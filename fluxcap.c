#include <errno.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <assert.h>
#include "shr.h"
#include "libut.h"

/* 
 * fluxcap: a network tap replication and aggregation tool
 *
 */

#define MAX_PKT 100000         /* max length of packet */
#define MAX_NIC 64             /* longest NIC name we accept */
#define BATCH_SIZE (1024*1024) /* bytes buffered before shr_writev */
#define BATCH_PKTS 10000       /* max pkts to read in one shr_readv */
struct bb {
  size_t n; /* batch buffer size */
  size_t u; /* batch buffer used */
  char  *d; /* batch buffer */
  UT_vector /* of struct iovec */ *iov; 
};

struct {
  int verbose;
  char *prog;
  enum {mode_none, mode_transmit, mode_receive, mode_create, 
        mode_tee, mode_funnel} mode;
  char *file;
  char dev[MAX_NIC];
  int dev_ifindex;
  int ticks;
  int vlan;
  int tail;
  int fd;
  int tx_fd;
  int signal_fd;
  int epoll_fd;
  char pkt[MAX_PKT];
  struct shr *ring;
  size_t size; /* ring create size (-cr), or snaplen (-rx/-tx) */
  /* auxilliary rings; for tee or funnel modes */
  UT_vector /* of ptr */ *aux_rings; 
  UT_vector /* of int */ *aux_fd; 
  UT_vector /* of utstring */ *aux_names; 
  UT_vector /* of struct bb */ *tee_bb; 
  UT_string *tmp;
  struct timeval now;
  struct bb bb; /* output batch buffer; accumulates output before shr_writev */
  struct bb rb; /* readv batch buffer; accepts many messages at once */
} cfg = {
  .bb.n = BATCH_SIZE,
  .rb.n = BATCH_SIZE,
  .fd = -1,
  .tx_fd = -1,
  .signal_fd = -1,
  .epoll_fd = -1,
};

/*
 * support to vectorize struct iovec and struct bb 
 */
UT_mm iov_mm = { . sz = sizeof(struct iovec) };
void bb_init(void *_b) {
  struct bb *b = (struct bb*)_b;
  memset(b,0,sizeof(*b));
  b->n = BATCH_SIZE;
  int mode = MAP_PRIVATE | MAP_ANONYMOUS /* | MAP_LOCKED */;
  b->d = mmap(0, b->n, PROT_READ|PROT_WRITE, mode, -1, 0);
  if (b->d == MAP_FAILED) {
    fprintf(stderr, "mmap: %s\n", strerror(errno));
    abort();
  }
  b->iov = utvector_new(&iov_mm);
  utvector_reserve(b->iov, BATCH_PKTS);
}

void bb_fini(void *_b) {
  struct bb *b = (struct bb*)_b;
  assert (b->d && (b->d != MAP_FAILED));
  munmap(b->d, b->n);
  utvector_free(b->iov);
}

void bb_clear(void *_b) {
  struct bb *b = (struct bb*)_b;
  b->u = 0;
  utvector_clear(b->iov);
}

UT_mm bb_mm = { 
  .sz = sizeof(struct bb),
  .init = bb_init,
  .fini = bb_fini,
  .clear = bb_clear,
};


UT_mm _utmm_ptr = {.sz = sizeof(void*)};
UT_mm* utmm_ptr = &_utmm_ptr;

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage() {
  fprintf(stderr,"usage: %s [-tx|-rx|-cr|-T|-F|-m] [options] <ring>\n"
                 "\n"
                 " transmit:       -tx -i <eth>  <ring>\n"
                 " receive:        -rx -i <eth>  <ring>\n"
                 " create ring:    -cr -s <size> <ring> ...\n"
                 " tee-out:        -T <src-ring> <dst-ring> ...\n"
                 " funnel-in:      -F <dst-ring> <src-ring> ...\n"
                 "\n"
                 "additional tx/rx options:\n"
                 "\n"
                 "           -V <vlan>    (inject VLAN tag)\n"
                 "           -s <size>    (snaplen)\n"
                 "           -D <n>       (trim n tail bytes)\n"
                 "           -v           (verbose)\n"
                 "\n"
                 "  <size> may have k/m/g/t suffix\n"
                 "\n",
          cfg.prog);
  exit(-1);
}

int new_epoll(int events, int fd) {
  int rc;
  struct epoll_event ev;
  memset(&ev,0,sizeof(ev)); // placate valgrind
  ev.events = events;
  ev.data.fd= fd;
  if (cfg.verbose) fprintf(stderr,"adding fd %d to epoll\n", fd);
  rc = epoll_ctl(cfg.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

int setup_rx(void) {
  int rc=-1, ec;

  /* any link layer protocol packets (linux/if_ether.h) */
  int protocol = htons(ETH_P_ALL);

  /* create the packet socket */
  cfg.fd = socket(AF_PACKET, SOCK_RAW, protocol);
  if (cfg.fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* convert interface name to index (in ifr.ifr_ifindex) */
  struct ifreq ifr; 
  strncpy(ifr.ifr_name, cfg.dev, sizeof(ifr.ifr_name));
  ec = ioctl(cfg.fd, SIOCGIFINDEX, &ifr);
  if (ec < 0) {
    fprintf(stderr,"failed to find interface %s\n", cfg.dev);
    goto done;
  }

  /* bind to receive the packets from just one interface */
  struct sockaddr_ll sl;
  memset(&sl, 0, sizeof(sl));
  sl.sll_family = AF_PACKET;
  sl.sll_protocol = protocol;
  sl.sll_ifindex = ifr.ifr_ifindex;
  ec = bind(cfg.fd, (struct sockaddr*)&sl, sizeof(sl));
  if (ec < 0) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* set promiscuous mode to get all packets. */
  struct packet_mreq m;
  memset(&m, 0, sizeof(m));
  m.mr_ifindex = ifr.ifr_ifindex;
  m.mr_type = PACKET_MR_PROMISC;
  ec = setsockopt(cfg.fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &m, sizeof(m));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_ADD_MEMBERSHIP: %s\n", strerror(errno));
    goto done;
  }

  
  /* enable ancillary data, providing packet length and snaplen, 802.1Q, etc */
  int on = 1;
  ec = setsockopt(cfg.fd, SOL_PACKET, PACKET_AUXDATA, &on, sizeof(on));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_AUXDATA: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int setup_tx(void) {
  int rc=-1, ec;

  int protocol = htons(ETH_P_ALL);

  /* create the packet socket */
  cfg.tx_fd = socket(AF_PACKET, SOCK_RAW, protocol);
  if (cfg.tx_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* convert interface name to index (in ifr.ifr_ifindex) */
  struct ifreq ifr;
  strncpy(ifr.ifr_name, cfg.dev, sizeof(ifr.ifr_name));
  ec = ioctl(cfg.tx_fd, SIOCGIFINDEX, &ifr);
  if (ec < 0) {
    fprintf(stderr,"failed to find interface %s\n", cfg.dev);
    goto done;
  }
  cfg.dev_ifindex = ifr.ifr_ifindex;

#if 0
  ec = ioctl(cfg.tx_fd, SIOCETHTOOL, &ifr);
  if (ec < 0) {
    fprintf(stderr,"failed to find interface %s\n", cfg.dev);
    goto done;
  }
#endif 

  /* bind interface. doing this to imitate tcpreplay(1) */
  /* using PACKET_HOST like tcpreplay; packet(7) says not needed */
  /* setsockopt SO_BROADCAST like tcpreplay. again, necessary? */
  struct sockaddr_ll sl;
  memset(&sl, 0, sizeof(sl));
  sl.sll_family = AF_PACKET;
  sl.sll_protocol = protocol;
  sl.sll_hatype = PACKET_HOST;
  sl.sll_ifindex = cfg.dev_ifindex;
  ec = bind(cfg.tx_fd, (struct sockaddr*)&sl, sizeof(sl));
  if (ec < 0) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }
  int one = 1;
  ec = setsockopt(cfg.tx_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
  if (ec < 0) {
    fprintf(stderr,"setsockopt SO_BROADCAST: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int bb_flush(struct shr *s, struct bb *b) {
  int rc = -1;
  struct iovec *iov;
  size_t n;
  ssize_t wr;

  n = utvector_len(b->iov);
  if (n == 0) { rc = 0; goto done; }
  iov = (struct iovec*)utvector_head(b->iov);

  wr = shr_writev(s, iov, n);
  if (wr < 0) {
    fprintf(stderr,"shr_write: error code %ld\n", (long)wr);
    goto done;
  }
  b->u = 0;
  utvector_clear(b->iov);

  rc = 0;

 done:
  return rc;
}

/* store the message into the batch buffer */
ssize_t bb_write(struct shr *s, struct bb *b, char *buf, size_t len) {
  struct iovec io;
  int rc = -1;

  if (b->n - b->u < len) {
    if (bb_flush(s,b) < 0) goto done;
  }

  assert((b->n - b->u) >= len);

  io.iov_base = &b->d[b->u];
  io.iov_len = len;
  memcpy(io.iov_base, buf, len);
  utvector_push(b->iov, &io);
  b->u += len;

  rc = 0;

 done:
  return (rc < 0) ? (ssize_t)-1 : len;
}

/* work we do on epoll timeout and also at 1hz.
 *  the modes that use the batch buffer to reduce shr_write get periodically
 *  flushed when they fill up or in this function which is a rainy day flush
 */
int periodic_work(void) {
  struct shr **r;
  struct bb *b;
  int rc = -1;

  switch(cfg.mode) {
    case mode_tee:
      r = NULL;
      b = NULL;
      while ( (r = (struct shr**)utvector_next(cfg.aux_rings, r)) != NULL) {
        b = (struct bb*)utvector_next(cfg.tee_bb, b); 
        assert(b);
        if (bb_flush(*r, b) < 0) goto done;
      }

      break;
    case mode_receive:
    case mode_funnel:
      if (bb_flush(cfg.ring, &cfg.bb) < 0) goto done;
      break;
  }

  rc = 0;

 done:
  return rc;
}

int handle_signal(void) {
  int rc=-1;
  struct signalfd_siginfo info;
  
  if (read(cfg.signal_fd, &info, sizeof(info)) != sizeof(info)) {
    fprintf(stderr,"failed to read signal fd buffer\n");
    goto done;
  }

  switch(info.ssi_signo) {
    case SIGALRM: 
      cfg.ticks++;
      gettimeofday(&cfg.now, NULL);
      if (periodic_work() < 0) goto done;
      alarm(1); 
      break;
    default: 
      fprintf(stderr,"got signal %d\n", info.ssi_signo);  
      goto done;
      break;
  }

 rc = 0;

 done:
  return rc;
}

/* inject four bytes to the ethernet frame with an 802.1q vlan tag.
 * note if this makes MTU exceeded it may result in sendto error */
#define VLAN_LEN 4
char buf[MAX_PKT];
char vlan_tag[VLAN_LEN] = {0x81, 0x00, 0x00, 0x00};
#define MACS_LEN (2*6)
char *inject_vlan(char *tx, ssize_t *nx) {
  if (((*nx) + 4) > MAX_PKT) return NULL;
  if ((*nx) <= MACS_LEN) return NULL;
  /* prepare 802.1q tag vlan portion in network order */
  uint16_t v = htons(cfg.vlan);
  memcpy(&vlan_tag[2], &v, sizeof(v));
  /* copy MAC's from original packet, inject 802.1q, copy packet */
  memcpy(buf,                   tx,            MACS_LEN);
  memcpy(buf+MACS_LEN,          vlan_tag,      VLAN_LEN);
  memcpy(buf+MACS_LEN+VLAN_LEN, tx + MACS_LEN, (*nx) - MACS_LEN);
  *nx += 4;
  return buf;
}

int tee_packet(void) {
  int rc=-1, n, nio;
  ssize_t nr,nt,nx;
  struct shr **r;
  struct bb *b;
  struct iovec *io;

  do {
    
    /* get pointers and lengths for the iov vector */
    utvector_clear(cfg.rb.iov);
    nio = cfg.rb.iov->n;
    io = (struct iovec*)cfg.rb.iov->d;

    /* read packets, up to BATCH_PKTS or BATCH_SIZE bytes */
    nr = shr_readv(cfg.ring, cfg.rb.d, cfg.rb.n, io, &nio);
    if (nr < 0) {
      fprintf(stderr, "shr_readv error: %ld\n", (long)nr);
      goto done;
    }

    /* record in vector number of used iov slots */
    if (cfg.verbose) fprintf(stderr,"readv: %d packets\n", nio);
    assert(nio <= cfg.rb.iov->n);
    cfg.rb.iov->i = nio;

    /* iterate over packets obtained in shr_readv */
    io = NULL;
    while ( (io = utvector_next(cfg.rb.iov, io))) {

      char *tx = io->iov_base; /* packet */
      nx = io->iov_len;        /* length */

      /* inject 802.1q tag if requested */
      if (cfg.vlan) tx = inject_vlan(tx,&nx);
      if (tx == NULL) {
        fprintf(stderr, "vlan tag injection failed\n");
        goto done;
      }

      /* truncate outgoing packet if requested */
      if (cfg.size && (nx > cfg.size)) nx = cfg.size;

      /* trim N bytes from frame end if requested. */
      if (cfg.tail && (nx > cfg.tail)) nx -= cfg.tail;

      r = NULL;
      b = NULL;
      while ( (r = (struct shr**)utvector_next(cfg.aux_rings, r)) != NULL) {
        b = (struct bb*)utvector_next(cfg.tee_bb, b); 
        assert(b);

        nt = bb_write(*r, b, tx, nx);
        if (nt < 0) {
          fprintf(stderr, "bb_write error %ld\n", (long)nt);
          goto done;
        }
      }

    }

  } while (nr > 0);  /* n == 0 --> would block */

  rc = 0;

 done:
  return rc;
}

int transmit_packet(void) {
  int rc=-1, n, nio;
  ssize_t nr,nt,nx;
  struct iovec *io;

  do {
    
    /* get pointers and lengths for the iov vector */
    utvector_clear(cfg.rb.iov);
    nio = cfg.rb.iov->n;
    io = (struct iovec*)cfg.rb.iov->d;

    /* read packets, up to BATCH_PKTS or BATCH_SIZE bytes */
    nr = shr_readv(cfg.ring, cfg.rb.d, cfg.rb.n, io, &nio);
    if (nr < 0) {
      fprintf(stderr, "shr_readv error: %ld\n", (long)nr);
      goto done;
    }

    /* record in vector number of used iov slots */
    if (cfg.verbose) fprintf(stderr,"readv: %d packets\n", nio);
    assert(nio <= cfg.rb.iov->n);
    cfg.rb.iov->i = nio;

    /* iterate over packets obtained in shr_readv */
    io = NULL;
    while ( (io = utvector_next(cfg.rb.iov, io))) {

      char *tx = io->iov_base; /* packet */
      nx = io->iov_len;        /* length */

      /* inject 802.1q tag if requested */
      if (cfg.vlan) tx = inject_vlan(tx,&nx);
      if (tx == NULL) {
        fprintf(stderr, "vlan tag injection failed\n");
        goto done;
      }

      /* truncate outgoing packet if requested */
      if (cfg.size && (nx > cfg.size)) nx = cfg.size;

      /* trim N bytes from frame end if requested. */
      if (cfg.tail && (nx > cfg.tail)) nx -= cfg.tail;

      nt = sendto(cfg.tx_fd, tx, nx, 0, NULL, 0);
      if (nt != nx) {
        fprintf(stderr,"sendto: %s\n", (nt < 0) ? strerror(errno) : "partial");
        goto done;
      }

      if (cfg.verbose) fprintf(stderr,"tx %ld byte packet\n", (long)nx);

    }

  } while (nr > 0);  /* n == 0 --> would block */

  rc = 0;

 done:
  return rc;
}

int receive_packet(void) {
  int rc=-1, sw;
  ssize_t nr,nt,nx;

  struct tpacket_auxdata *pa; /* for PACKET_AUXDATA; see packet(7) */
  struct cmsghdr *cmsg;
  struct {
    struct cmsghdr h;
    struct tpacket_auxdata a;
  } u;

  /* we get the packet and metadata via recvmsg */
  struct msghdr msgh;
  memset(&msgh, 0, sizeof(msgh));

  /* ancillary data; we requested packet metadata (PACKET_AUXDATA) */
  msgh.msg_control = &u;
  msgh.msg_controllen = sizeof(u);

  struct iovec iov;
  iov.iov_base = cfg.pkt;
  iov.iov_len = MAX_PKT;
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;

  nr = recvmsg(cfg.fd, &msgh, 0);
  if (nr <= 0) {
    fprintf(stderr,"recvmsg: %s\n", nr ? strerror(errno) : "eof");
    goto done;
  }

  if (cfg.verbose) fprintf(stderr,"received %lu bytes of message data\n", (long)nr);
  if (cfg.verbose) fprintf(stderr,"received %lu bytes of control data\n", (long)msgh.msg_controllen);
  cmsg = CMSG_FIRSTHDR(&msgh);
  if (cmsg == NULL) {
    fprintf(stderr,"ancillary data missing from packet\n");
    goto done;
  }
  pa = (struct tpacket_auxdata*)CMSG_DATA(cmsg);
  if (cfg.verbose) fprintf(stderr, " packet length  %u\n", pa->tp_len);
  if (cfg.verbose) fprintf(stderr, " packet snaplen %u\n", pa->tp_snaplen);
  int losing = (pa->tp_status & TP_STATUS_LOSING) ? 1 : 0; 
  if (losing) fprintf(stderr, " warning; losing\n");
  int has_vlan = (pa->tp_status & TP_STATUS_VLAN_VALID) ? 1 : 0; 
  if (cfg.verbose) fprintf(stderr, " packet has vlan %c\n", has_vlan ? 'Y' : 'N');
  if (has_vlan) {
    uint16_t vlan_tci = pa->tp_vlan_tci;
    uint16_t tci = vlan_tci;
    uint16_t vid = tci & 0xfff; // vlan VID is in the low 12 bits of the TCI
    if (cfg.verbose) fprintf(stderr, " packet vlan %d\n", vid);
    cfg.vlan = vid;
  }

  /* inject 802.1q tag if requested */
  char *tx = cfg.pkt;
  nx = nr;
  if (cfg.vlan) tx = inject_vlan(tx,&nx);
  if (tx == NULL) {
    fprintf(stderr, "vlan tag injection failed\n");
    goto done;
  }

  /* truncate outgoing packet if requested */
  if (cfg.size && (nx > cfg.size)) nx = cfg.size;

  /* trim N bytes from frame end if requested. */
  if (cfg.tail && (nx > cfg.tail)) nx -= cfg.tail;

  /* push into batch buffer */
  sw = bb_write(cfg.ring, &cfg.bb, tx, nx);
  if (sw < 0) {
    fprintf(stderr, "bb_write (%lu bytes): error code %d\n", (long)nx, sw);
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

/* 
 * funnel mode
 *
 * one of the rings funneling into the primary (output) ring is ready.
 * the index of the ready ring is pos. 
 * read elements from it, in batches, until wouldblock,
 * writing them to the primary
 */
int funnel(int pos) {
  ssize_t nr, wr;
  struct iovec *io;
  int rc = -1, nio;

  struct shr **r = (struct shr**)utvector_elt(cfg.aux_rings, pos);
  assert(r);

  do {
    
    /* get pointers and lengths for the iov vector */
    utvector_clear(cfg.rb.iov);
    nio = cfg.rb.iov->n;
    io = (struct iovec*)cfg.rb.iov->d;

    /* read packets, up to BATCH_PKTS or BATCH_SIZE bytes */
    nr = shr_readv(*r, cfg.rb.d, cfg.rb.n, io, &nio);
    if (nr < 0) {
      fprintf(stderr, "shr_readv error: %ld\n", (long)nr);
      goto done;
    }

    /* record in vector number of used iov slots */
    if (cfg.verbose) fprintf(stderr,"readv: %d packets\n", nio);
    assert(nio <= cfg.rb.iov->n);
    cfg.rb.iov->i = nio;

    /* iterate over packets obtained in shr_readv */
    io = NULL;
    while ( (io = utvector_next(cfg.rb.iov, io))) {

      char *pkt = io->iov_base; /* packet */
      size_t len = io->iov_len; /* length */

      /* funnel it into the output ring */
      wr = bb_write(cfg.ring, &cfg.bb, pkt, len);
      if (wr < 0) {
        fprintf(stderr, "bb_write: error code %ld\n", (long)wr);
        goto done;
      }
    }

  } while(nr > 0);

  rc = 0;

 done:
  return rc;
}

int handle_io(void) {
  int rc = -1;

  switch(cfg.mode) {
    case mode_receive:
      rc = receive_packet();
      break;
    case mode_transmit:
      rc = transmit_packet();
      break;
    case mode_tee:
      rc = tee_packet();
      break;
    default:
      assert(0);
      break;
  }

  return rc;
}

/* test if fd is a funnel source */
int is_funnel(int fd, int *opos) {
  int *p = NULL, pos=0;
  while ( (p = utvector_next(cfg.aux_fd, p)) != NULL) {
    if (*p == fd) {
      *opos = pos;
      return 1;
    }
    pos++;
  }
  return 0;
}

size_t kmgt(char *optarg) {
 size_t size=0;
 char unit;

 int n = sscanf(optarg, "%lu%c", &size, &unit);
 if (n == 0) usage();
 if (n == 2) {
    switch (unit) {
      case 't': case 'T': size *= 1024; /* fall through */
      case 'g': case 'G': size *= 1024; /* fall through */
      case 'm': case 'M': size *= 1024; /* fall through */
      case 'k': case 'K': size *= 1024; break;
      default: usage(); break;
    }
 }

 return size;
}

int main(int argc, char *argv[]) {
  struct epoll_event ev;
  cfg.prog = argv[0];
  int rc = -1, n, opt, ring_mode, init_mode, pos, ec;
  char *file;
  struct shr *r;
  struct bb *b;
  void **p;

  cfg.aux_rings = utvector_new(utmm_ptr);
  cfg.aux_names = utvector_new(utstring_mm);
  cfg.aux_fd = utvector_new(utmm_int);
  cfg.tee_bb = utvector_new(&bb_mm);
  utstring_new(cfg.tmp);

  while ( (opt=getopt(argc,argv,"t:r:c:vi:hV:s:D:TF")) != -1) {
    switch(opt) {
      case 't': cfg.mode = mode_transmit; if (*optarg != 'x') goto done; break;
      case 'r': cfg.mode = mode_receive;  if (*optarg != 'x') goto done; break;
      case 'c': cfg.mode = mode_create;   if (*optarg != 'r') goto done; break;
      case 'T': cfg.mode = mode_tee; break;
      case 'F': cfg.mode = mode_funnel; break;
      case 'v': cfg.verbose++; break;
      case 'V': cfg.vlan=atoi(optarg); break; 
      case 'D': cfg.tail=atoi(optarg); break; 
      case 's': cfg.size = kmgt(optarg); break;
      case 'h': default: usage(); break;
      case 'i': if (strlen(optarg) < MAX_NIC) strncpy(cfg.dev, optarg, MAX_NIC);
                break;
    }
  }

  sigset_t all;
  sigfillset(&all);
  sigprocmask(SIG_SETMASK,&all,NULL);

  /* a few signals we'll accept via our signalfd */
  sigset_t sw;
  sigemptyset(&sw);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++) sigaddset(&sw, sigs[n]);

  /* create the signalfd for receiving signals */
  cfg.signal_fd = signalfd(-1, &sw, 0);
  if (cfg.signal_fd == -1) {
    fprintf(stderr,"signalfd: %s\n", strerror(errno));
    goto done;
  }
  /* set up the epoll instance */
  cfg.epoll_fd = epoll_create(1); 
  if (cfg.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  /* add descriptors of interest */
  if (new_epoll(EPOLLIN, cfg.signal_fd)) goto done; // signals

  /* establish the batch buffers */
  utmm_init(&bb_mm, &cfg.bb, 1);
  utmm_init(&bb_mm, &cfg.rb, 1);

  /* in transmit mode, epoll on the ring descriptor.
   * in receive mode, epoll on the raw socket.
   */
  switch (cfg.mode) {
    case mode_receive:
      if (cfg.dev == NULL) usage();
      ring_mode = SHR_WRONLY;
      cfg.file = (optind < argc) ? argv[optind++] : NULL;
      cfg.ring = shr_open(cfg.file, ring_mode);
      if (cfg.ring == NULL) goto done;
      if (setup_rx() < 0) goto done;
      if (new_epoll(EPOLLIN, cfg.fd)) goto done;
      break;
    case mode_transmit:
      if (cfg.dev == NULL) usage();
      ring_mode = SHR_RDONLY|SHR_NONBLOCK|SHR_SELECTFD;
      cfg.file = (optind < argc) ? argv[optind++] : NULL;
      cfg.ring = shr_open(cfg.file, ring_mode);
      if (cfg.ring == NULL) goto done;
      cfg.fd = shr_get_selectable_fd(cfg.ring);
      if (cfg.fd < 0) goto done;
      if (new_epoll(EPOLLIN, cfg.fd)) goto done;
      if (setup_tx() < 0) goto done;
      break;
    case mode_funnel:
      ring_mode = SHR_WRONLY;
      cfg.file = (optind < argc) ? argv[optind++] : NULL;
      cfg.ring = shr_open(cfg.file, ring_mode);
      if (cfg.ring == NULL) goto done;
      while (optind < argc) {
        file = argv[optind++];
        r = shr_open(file, SHR_RDONLY|SHR_NONBLOCK|SHR_SELECTFD);
        if (r == NULL) goto done;
        utvector_push(cfg.aux_rings, &r);
        int fd = shr_get_selectable_fd(r);
        if (fd < 0) goto done;
        utvector_push(cfg.aux_fd, &fd);
        if (new_epoll(EPOLLIN, fd)) goto done;
      }
      break;
    case mode_tee:
      ring_mode = SHR_RDONLY|SHR_NONBLOCK|SHR_SELECTFD;
      cfg.file = (optind < argc) ? argv[optind++] : NULL;
      cfg.ring = shr_open(cfg.file, ring_mode);
      if (cfg.ring == NULL) goto done;
      cfg.fd = shr_get_selectable_fd(cfg.ring);
      if (cfg.fd < 0) goto done;
      if (new_epoll(EPOLLIN, cfg.fd)) goto done;
      while (optind < argc) {
        file = argv[optind++];
        r = shr_open(file, SHR_WRONLY);
        if (r == NULL) goto done;
        utvector_push(cfg.aux_rings, &r);
        b = (struct bb*)utvector_extend(cfg.tee_bb);
      }
      break;
    case mode_create:
      if (cfg.size == 0) usage();
      while (optind < argc) {
        file = argv[optind++];
        if (cfg.verbose) fprintf(stderr,"creating %s\n", file);
        init_mode = SHR_OVERWRITE|SHR_MESSAGES|SHR_LRU_DROP;
        if (shr_init(file, cfg.size, init_mode) < 0) goto done;
      }
      rc = 0;
      goto done;
      break;
    default:
      usage();
  }

  /* block all signals. we take signals synchronously via signalfd */
  alarm(1);

  while (1) {
    ec = epoll_wait(cfg.epoll_fd, &ev, 1, 100);
    if (ec < 0) { 
      fprintf(stderr, "epoll: %s\n", strerror(errno));
      goto done;
    }

    if (ec == 0)                          { if (periodic_work() < 0) goto done; }
    else if (ev.data.fd == cfg.signal_fd) { if (handle_signal()  < 0) goto done; }
    else if (ev.data.fd == cfg.fd)        { if (handle_io() < 0) goto done; }
    else if (is_funnel(ev.data.fd, &pos)) { if (funnel(pos) < 0) goto done; }

  }
  
  rc = 0;

done:
  /* in these modes, fd is internal to shr and closed by it */
  if ((cfg.mode != mode_transmit) && (cfg.mode != mode_tee)) {
    if (cfg.fd != -1) close(cfg.fd);
  }
  if (cfg.tx_fd != -1) close(cfg.tx_fd);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  utmm_fini(&bb_mm, &cfg.bb, 1);
  utmm_fini(&bb_mm, &cfg.rb, 1);
  if (cfg.ring) shr_close(cfg.ring);
  p = NULL; while ( (p = utvector_next(cfg.aux_rings, p)) != NULL) shr_close(*p);
  utvector_free(cfg.aux_rings);
  utvector_free(cfg.aux_names);
  utvector_free(cfg.aux_fd);
  utstring_free(cfg.tmp);
  utvector_free(cfg.tee_bb);
  return rc;
}
