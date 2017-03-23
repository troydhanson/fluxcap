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
#define FLUXCAP_VERSION "1.2"
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

struct encap { /* this is used in tx GRE/ERSPAN encapsulation mode */
  int enable;
  enum {mode_gre=0, mode_gretap, mode_erspan} mode;
  struct in_addr dst;
  int session;             /* TODO make configurable */
  uint32_t session_seqno;  /* TODO should be kept per-session */
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
  struct encap encap;
  /* auxilliary rings; for tee or funnel modes */
  UT_vector /* of ptr */ *aux_rings; 
  UT_vector /* of int */ *aux_fd; 
  UT_vector /* of utstring */ *aux_names; 
  UT_vector /* of struct bb */ *tee_bb; 
  UT_string *tmp;
  struct timeval now;
  struct bb bb; /* output batch buffer; accumulates output before shr_writev */
  struct bb rb; /* readv batch buffer; accepts many messages at once */
  /* fields below are for packet input from AF_PACKET socket */
  struct tpacket_req req; /* linux/if_packet.h */
  unsigned ring_block_sz; /* see comments in initialization below */
  unsigned ring_block_nr; /* number of blocks of sz above */
  unsigned ring_frame_sz; /* snaplen */
  unsigned ring_curr_idx; /* slot index in ring buffer */
  unsigned ring_frame_nr; /* redundant, total frame count */
  int losing;     /* packets loss since last reset (boolean) */
  int strip_vlan; /* strip VLAN on rx if present (boolean) */
  int drop_pct;   /* sampling % 0 (keep all)-100(drop all) */
} cfg = {
  .bb.n = BATCH_SIZE,
  .rb.n = BATCH_SIZE,
  .fd = -1,
  .tx_fd = -1,
  .signal_fd = -1,
  .epoll_fd = -1,
  .ring_block_sz = 1 << 22, /*4 mb; want powers of two due to kernel allocator*/
  .ring_block_nr = 64,
  .ring_frame_sz = 1 << 11, /* 2048 for MTU & header, divisor of ring_block_sz*/
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
  fprintf(stderr,
                 "fluxcap version " FLUXCAP_VERSION "\n"
                 "usage: %s [-tx|-rx|-cr|-T|-F|-m] [options] <ring>\n"
                 "\n"
                 " transmit:       -tx -i <eth>  <ring>\n"
                 " receive:        -rx -i <eth>  <ring>\n"
                 " create ring:    -cr -s <size> <ring> ...\n"
                 " tee-out:        -T <src-ring> <dst-ring> ...\n"
                 " funnel-in:      -F <dst-ring> <src-ring> ...\n"
                 "\n"
                 "  <size> may have k/m/g/t suffix\n"
                 "\n"
                 "encapsulation modes (tx-only):\n"
                 "\n"
                 "    -tx -E gre:<ip>    <ring>    (GRE encapsulation)\n"
                 "    -tx -E gretap:<ip> <ring>    (GRETAP encapsulation)\n"
                 "    -tx -E erspan:<ip> <ring>    (ERSPAN encapsulation)\n"
                 "\n"
                 "other options:\n"
                 "\n"
                 "    -V <vlan>    (inject VLAN tag) [rx/tee/tx]\n"
                 "    -Q           (strip VLAN tag) [rx]\n"
                 "    -s <size>    (snaplen- truncate at this size)\n"
                 "    -D <n>       (trim n tail bytes)\n"
                 "    -d <%%>       (downsample to %% (0=drop all,100=keep all) [rx]\n"
                 "    -v           (verbose)\n"
                 "\n"
                 " VLAN tags may be stripped (-Q) on rx,\n"
                 "  or replaced/inserted (-V <1-4095>) on rx,\n"
                 "  or inserted (-V <1-4095>) on tee/tx,\n"
                 "  or left intact (default).\n"
                 "\n"
                 " Kernel ring buffer options (PACKET_RX_RING TPACKET_V2)\n"
                 " -B <num-blocks>      -packet ring num-blocks e.g. 64\n"
                 " -S <log2-block-size> -log2 packet ring block size (e.g. 22 = 4mb)\n"
                 " -Z <frame-size>      -max frame (packet + header) size (e.g. 2048)\n"
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

/* 
 * Prepare to read packets using a AF_PACKET socket with PACKET_RX_RING
 * 
 * see packet(7)
 *
 * also see
 *  sudo apt-get install linux-doc
 *  zless /usr/share/doc/linux-doc/networking/packet_mmap.txt.gz
 *
 * With PACKET_RX_RING (in version TPACKET_V1 and TPACKET_V2)
 * the ring buffer consists of an array of packet slots.
 * Each slot is of size tp_snaplen.
 * Each packet is preceded by a metadata structure in the slot.
 * The application and kernel communicate the head and tail of
 * the ring through tp_status field (TP_STATUS_[USER|KERNEL]).
 *
 * the packet ring's mmap'd region is comprised of blocks filled with packets. 
 * in our memory space it's a regular mapped region; in kernel space
 * it is a number of discrete blocks. hence the description of the ring as 
 * blocks - see tpacket_req initialization in setup_rx
 *
 *
 */

int setup_rx(void) {
  int rc=-1, ec;

  /* sanity checks on allowable parameters. */
  if (cfg.ring_block_sz % cfg.ring_frame_sz) {
    fprintf(stderr,"-S block_sz must be multiple of -F frame_sz\n");
    goto done;
  }
  unsigned page_sz = (unsigned)sysconf(_SC_PAGESIZE);
  if (cfg.ring_block_sz % page_sz) {
    fprintf(stderr,"-S block_sz must be multiple of page_sz %u\n", page_sz);
    goto done;
  }
  if (cfg.ring_frame_sz <= TPACKET2_HDRLEN) {
    fprintf(stderr,"-Z frame_sz must exceed %lu\n", TPACKET2_HDRLEN);
    goto done;
  }
  if (cfg.ring_frame_sz % TPACKET_ALIGNMENT) {
    fprintf(stderr,"-Z frame_sz must be a mulitple of %u\n", TPACKET_ALIGNMENT);
    goto done;
  }

  cfg.ring_frame_nr = (cfg.ring_block_sz*cfg.ring_block_nr) / cfg.ring_frame_sz;

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

  /* PACKET_RX_RING comes in multiple versions. TPACKET_V2 is used here */
  int v = TPACKET_V2;
  ec = setsockopt(cfg.fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_VERSION: %s\n", strerror(errno));
    goto done;
  }

  /* fill out the struct tpacket_req describing the ring buffer */
  memset(&cfg.req, 0, sizeof(cfg.req));
  cfg.req.tp_block_size = cfg.ring_block_sz; /* Min sz of contig block */
  cfg.req.tp_frame_size = cfg.ring_frame_sz; /* Size of frame/snaplen */
  cfg.req.tp_block_nr = cfg.ring_block_nr;   /* Number of blocks */
  cfg.req.tp_frame_nr = cfg.ring_frame_nr;   /* Total number of frames */
  fprintf(stderr, "setting up PACKET_RX_RING:\n"
                  " RING: (%u blocks * %u bytes per block) = %u bytes (%u MB)\n"
                  " PACKETS: @(%u bytes/packet) = %u packets\n",
                 cfg.ring_block_nr, cfg.ring_block_sz,
                 cfg.ring_block_nr * cfg.ring_block_sz,
                 cfg.ring_block_nr * cfg.ring_block_sz / (1024 * 1024),
                 cfg.ring_frame_sz, cfg.ring_frame_nr);
  ec = setsockopt(cfg.fd, SOL_PACKET, PACKET_RX_RING, &cfg.req, sizeof(cfg.req));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_RX_RING: %s\n", strerror(errno));
    goto done;
  }

  /* now map the ring buffer we described above. lock in unswappable memory */
  cfg.rb.n = cfg.req.tp_block_size * cfg.req.tp_block_nr;
  cfg.rb.d = mmap(NULL, cfg.rb.n, PROT_READ|PROT_WRITE,
                      MAP_SHARED|MAP_LOCKED, cfg.fd, 0);
  if (cfg.rb.d == MAP_FAILED) {
    fprintf(stderr,"mmap: %s\n", strerror(errno));
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

  rc = 0;

 done:
  return rc;
}

int setup_tx(void) {
  int rc=-1, ec, one = 1;

  /* create the transmit socket;  see raw(7) and packet(7).
   * encap mode uses an IP "raw socket" (i.e. AF_INET, SOCK_RAW) [IP level]
   * NIC tx mode uses a "packet socket" (i.e. AF_PACKET, SOCK_RAW) [link level]
   */
  int domain = cfg.encap.enable ? AF_INET : AF_PACKET;
  int protocol = htons(ETH_P_ALL);
  cfg.tx_fd = socket(domain, SOCK_RAW, protocol);
  if (cfg.tx_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  if (cfg.encap.enable) { /* tell raw socket that we'll form IP headers */
    ec = setsockopt(cfg.tx_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (ec < 0) {
      fprintf(stderr,"setsockopt IP_HDRINCL: %s\n", strerror(errno));
      goto done;
    }

  } else { /* standard tx mode. lookup interface, bind to it. */
    struct ifreq ifr;
    strncpy(ifr.ifr_name, cfg.dev, sizeof(ifr.ifr_name));
    ec = ioctl(cfg.tx_fd, SIOCGIFINDEX, &ifr);
    if (ec < 0) {
      fprintf(stderr,"failed to find interface %s\n", cfg.dev);
      goto done;
    }
    cfg.dev_ifindex = ifr.ifr_ifindex;

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
    ec = setsockopt(cfg.tx_fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
    if (ec < 0) {
      fprintf(stderr,"setsockopt SO_BROADCAST: %s\n", strerror(errno));
      goto done;
    }
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
      if (cfg.losing) {
        fprintf(stderr,"packets lost\n");
        cfg.losing = 0;
      }
      struct tpacket_stats stats;  /* see /usr/include/linux/if_packet.h */
      socklen_t len = sizeof(stats);

      int ec = getsockopt(cfg.fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
      if (ec < 0) {
        fprintf(stderr,"getsockopt PACKET_STATISTICS: %s\n", strerror(errno));
        goto done;
      }

      if (cfg.verbose) {
        fprintf(stderr, "Received packets: %u\n", stats.tp_packets);
        fprintf(stderr, "Dropped packets:  %u\n", stats.tp_drops);
      }
      /* FALL THROUGH */
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

char gbuf[MAX_PKT];
char *encapsulate(char *tx, ssize_t *nx) {
  char *g = gbuf, *ethertype;
  if (*nx < 14) return NULL;
  uint32_t ip_src = 0;
  uint32_t ip_dst = cfg.encap.dst.s_addr;
  uint32_t seqno;
  uint16_t encap_ethertype;

  /* construct 20-byte IP header. 
   * NOTE: some zeroed header fields are filled out for us, when we send this
   * packet; particularly, checksum, src IP; ID and total length. see raw(7).
   */
  g[0] = 4 << 4;  /* IP version goes in MSB (upper 4 bits) of the first byte */
  g[0] |= 5;      /* IP header length (5 * 4 = 20 bytes) in lower 4 bits */
  g[1] = 0;       /* DSCP / ECN */
  g[2] = 0;       /* total length (upper byte) (see NOTE) */
  g[3] = 0;       /* total length (lower byte) (see NOTE) */
  g[4] = 0;       /* datagam id (upper byte); for frag reassembly (see NOTE) */
  g[5] = 0;       /* datagam id (lower byte); for frag reassembly (see NOTE) */
  g[6] = 0;       /* flags and upper bits of frag offset */
  g[7] = 0;       /* lower bits of frag offset */
  g[8] = 255;     /* TTL */
  g[9] = 47;      /* IP protocol GRE */
  g[10] = 0;      /* IP checksum (high byte) (see NOTE) */
  g[11] = 0;      /* IP checksum (low byte) (see NOTE) */
  memcpy(&g[12], &ip_src, sizeof(ip_src)); /* IP source (see NOTE) */
  memcpy(&g[16], &ip_dst, sizeof(ip_dst)); /* IP destination */

  g += 20;

  /* GRE header starts */

  switch(cfg.encap.mode) {
    case mode_gre:
      memset(g, 0, 2);     /* zero first two bytes of GRE header */
      g += 2;
      ethertype = &tx[12]; /* copy ethertype from packet into GRE header */
      memcpy(g, ethertype, sizeof(uint16_t));
      g += 2;
      *nx -= 14; tx += 14; // elide original MACs and ethertype!
      assert(*nx <= sizeof(gbuf)-(g-gbuf)); /* TODO skip not assert */
      memcpy(g, tx, *nx);
      g += *nx;
      *nx = g-gbuf;
      break;
    case mode_gretap:
      memset(g, 0, 2);     /* zero first two bytes of GRE header */
      g += 2;
      encap_ethertype = htons(0x6558); /* transparent ethernet bridging */
      memcpy(g, &encap_ethertype, sizeof(uint16_t));
      g += 2;
      assert(*nx <= sizeof(gbuf)-(g-gbuf)); /* TODO skip not assert */
      memcpy(g, tx, *nx);
      g += *nx;
      *nx = g-gbuf;
      break;
    case mode_erspan:
      g[0] = 1 << 4;  /* turn on GRE "S" bit to indicate sequence num option */
      g[1] = 0;       /* zero next full byte of GRE header */
      g += 2;
      encap_ethertype = htons(0x88BE); /* ERSPAN type II */
      memcpy(g, &encap_ethertype, sizeof(uint16_t));
      g += 2;
      seqno = htonl(cfg.encap.session_seqno++); /* GRE sequence number */
      memcpy(g, &seqno, sizeof(uint32_t));
      g += sizeof(uint32_t);
      /* start ERSPAN Type 2 header (8 bytes) */
      uint8_t cos = 0, t = 0;  /* TODO fill in with correct values */
      g[0] = 1 << 4;   /* ERSPAN  version, 0x1 = Type II */
      g[1] = 0;        /* lower 8 bits of the VLAN, we leave it in frame */
      g[2] = cos << 5; /* class of service from original frame; do later */
      g[2] |= 3 << 3;  /* trunk encap type 3 means preserved in frame */
      g[2] |= t << 2;  /* truncation bit */
      g[2] |= ((cfg.encap.session & 0x300) >> 8); /* MSB 2 bits of 10 */
      g[3] = cfg.encap.session & 0xff;           /* LSB 8 bits of 10 */
      g[4] = 0;        /* reserved MSB 8 of 12 bits */
      g[5] = 0;        /* reserved LSB 4 of 12 bits, index bits 19-16 */
      g[6] = 0;        /* index middle word; bits of 15-8 of index */
      g[7] = 0;        /* index LSB word; bits 7-0 of index */
      g += 8;
      /* packet */
      assert(*nx <= sizeof(gbuf)-(g-gbuf)); /* TODO truncate not assert */
      memcpy(g, tx, *nx);
      g += *nx;
      *nx = g-gbuf;
      break;
    default:
      assert(0);
      break;
  }

  return gbuf;
}

/* inject four bytes to the ethernet frame with an 802.1q vlan tag.
 * note if this makes MTU exceeded it may result in sendto error */
#define VLAN_LEN 4
char buf[MAX_PKT];
char vlan_tag[VLAN_LEN] = {0x81, 0x00, 0x00, 0x00};
#define MACS_LEN (2*6)
char *inject_vlan(char *tx, ssize_t *nx, uint16_t vlan) {
  if (((*nx) + 4) > MAX_PKT) return NULL;
  if ((*nx) <= MACS_LEN) return NULL;
  /* prepare 802.1q tag vlan portion in network order */
  uint16_t v = htons(vlan);
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
    if (cfg.vlan) tx = inject_vlan(tx,&nx,cfg.vlan);
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

  rc = 0;

 done:
  return rc;
}

int transmit_packet(void) {
  int rc=-1, n, nio;
  ssize_t nr,nt,nx;
  struct iovec *io;
  struct sockaddr *dst = NULL;
  socklen_t sz = 0;
  struct sockaddr_in sin;

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
    if (cfg.vlan) tx = inject_vlan(tx,&nx,cfg.vlan);
    if (tx == NULL) {
      fprintf(stderr, "vlan tag injection failed\n");
      goto done;
    }

    /* truncate outgoing packet if requested */
    if (cfg.size && (nx > cfg.size)) nx = cfg.size;

    /* trim N bytes from frame end if requested. */
    if (cfg.tail && (nx > cfg.tail)) nx -= cfg.tail;

    /* wrap encapsulation around it, if enabled */
    if (cfg.encap.enable) {
      tx = encapsulate(tx,&nx);
      if (tx == NULL) {
        fprintf(stderr, "encapsulation failed\n");
        goto done;
      }

      sin.sin_family = AF_INET;
      sin.sin_port = 0;
      sin.sin_addr = cfg.encap.dst;
      dst = (struct sockaddr*)&sin;
      sz = sizeof(sin);
    }

    nt = sendto(cfg.tx_fd, tx, nx, 0, dst, sz);
    if (nt != nx) {
      fprintf(stderr,"sendto: %s\n", (nt < 0) ? strerror(errno) : "partial");
      goto done;
    }

    if (cfg.verbose) fprintf(stderr,"tx %ld byte packet\n", (long)nx);

  }

  rc = 0;

 done:
  return rc;
}

/* right now sampling is the only way we elect to drop a packet */
int keep_packet(char *tx, size_t nx) {
  if (cfg.drop_pct == 0) return 1;
  int r = rand();
  if ((r * 100.0 / RAND_MAX) < cfg.drop_pct) return 0;
  return 1;
}

/* plow through the ready packets in the packet ring shared with kernel */
int receive_packets(void) {
  int rc=-1, sw, wire_vlan, form_vlan;
  ssize_t nr,nt,nx;
  struct iovec iov;
  char *tx;

  while (1) {

    /* get address of the current slot (metadata header, pad, packet) */
    uint8_t *cur = cfg.rb.d + cfg.ring_curr_idx * cfg.ring_frame_sz;

    /* struct tpacket2_hdr is defined in /usr/include/linux/if_packet.h */
    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)cur;

    /* check if the packet is ready. this is how we break the loop */
    if ((hdr->tp_status & TP_STATUS_USER) == 0) break;

    /* note packet drop condition */
    if (hdr->tp_status & TP_STATUS_LOSING) cfg.losing=1;

    tx = cur + hdr->tp_mac;
    nx = hdr->tp_snaplen;

    /* upon receipt the wire vlan (if any) has been pulled out for us */
    wire_vlan = (hdr->tp_status & TP_STATUS_VLAN_VALID) ? 
                (hdr->tp_vlan_tci & 0xfff) : 0;
    form_vlan = cfg.vlan ? cfg.vlan : wire_vlan;
    if (cfg.strip_vlan) form_vlan = 0;

    /* inject 802.1q tag if requested */
    if (form_vlan) tx = inject_vlan(tx,&nx,form_vlan);
    if (tx == NULL) {
      fprintf(stderr, "vlan tag injection failed\n");
      goto done;
    }

    /* truncate outgoing packet if requested */
    if (cfg.size && (nx > cfg.size)) nx = cfg.size;

    /* trim N bytes from frame end if requested. */
    if (cfg.tail && (nx > cfg.tail)) nx -= cfg.tail;

    int keep = keep_packet(tx,nx);

    /* push into batch buffer */
    sw = keep ? bb_write(cfg.ring, &cfg.bb, tx, nx) : 0;
    if (sw < 0) {
      fprintf(stderr, "bb_write (%lu bytes): error code %d\n", (long)nx, sw);
      goto done;
    }

    /* return the packet by assigning status word TP_STATUS_KERNEL (0) */
    hdr->tp_status = TP_STATUS_KERNEL;

    /* next packet */
    cfg.ring_curr_idx = (cfg.ring_curr_idx + 1) % cfg.ring_frame_nr;
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

  rc = 0;

 done:
  return rc;
}

int handle_io(void) {
  int rc = -1;

  switch(cfg.mode) {
    case mode_receive:
      rc = receive_packets();
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

int parse_encap(char *opt) {
  int rc = -1;
  char *mode=opt,*dst=opt, *colon;

  colon = strchr(mode,':');
  if (colon == NULL) {
    fprintf(stderr,"invalid encapsulation syntax\n");
    goto done;
  }
  *colon = '\0';

  if      (!strcmp(mode,"gre"))    cfg.encap.mode = mode_gre;
  else if (!strcmp(mode,"gretap")) cfg.encap.mode = mode_gretap;
  else if (!strcmp(mode,"erspan")) cfg.encap.mode = mode_erspan;
  else { 
    fprintf(stderr,"invalid encapsulation mode\n");
    goto done;
  }

  dst = colon+1;

  if (inet_aton(dst, &cfg.encap.dst) == 0) {
    fprintf(stderr,"invalid ip: %s\n", dst);
    goto done;
  }

  rc = 0;

 done:
  return rc;
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
  utmm_init(&bb_mm, &cfg.bb, 1);
  utmm_init(&bb_mm, &cfg.rb, 1);

  while ( (opt=getopt(argc,argv,"t:r:c:vi:hV:s:D:TFE:B:S:Z:Qd:")) != -1) {
    switch(opt) {
      case 't': cfg.mode = mode_transmit; if (*optarg != 'x') usage(); break;
      case 'r': cfg.mode = mode_receive;  if (*optarg != 'x') usage(); break;
      case 'c': cfg.mode = mode_create;   if (*optarg != 'r') usage(); break;
      case 'T': cfg.mode = mode_tee; break;
      case 'F': cfg.mode = mode_funnel; break;
      case 'E': cfg.encap.enable=1; if (parse_encap(optarg)) usage(); break;
      case 'v': cfg.verbose++; break;
      case 'V': cfg.vlan=atoi(optarg); break; 
      case 'D': cfg.tail=atoi(optarg); break; 
      case 's': cfg.size = kmgt(optarg); break;
      case 'i': if (strlen(optarg) < MAX_NIC) strncpy(cfg.dev, optarg, MAX_NIC);
                break;
      case 'B': cfg.ring_block_nr=atoi(optarg); break;
      case 'S': cfg.ring_block_sz = 1 << (unsigned)atoi(optarg); break;
      case 'Z': cfg.ring_frame_sz=atoi(optarg); break;
      case 'Q': cfg.strip_vlan = 1; break;
      case 'd': cfg.drop_pct=100-atoi(optarg); break;
      case 'h': default: usage(); break;
    }
  }

  if ((cfg.drop_pct < 0) || (cfg.drop_pct > 100)) usage();

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
      if ((cfg.dev == NULL) && (cfg.encap.enable == 0)) usage();
      ring_mode = SHR_RDONLY|SHR_NONBLOCK;
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
        r = shr_open(file, SHR_RDONLY|SHR_NONBLOCK);
        if (r == NULL) goto done;
        utvector_push(cfg.aux_rings, &r);
        int fd = shr_get_selectable_fd(r);
        if (fd < 0) goto done;
        utvector_push(cfg.aux_fd, &fd);
        if (new_epoll(EPOLLIN, fd)) goto done;
      }
      break;
    case mode_tee:
      ring_mode = SHR_RDONLY|SHR_NONBLOCK;
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
        init_mode = SHR_KEEPEXIST|SHR_MESSAGES|SHR_DROP;
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
