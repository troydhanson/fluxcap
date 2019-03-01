/* 
 * respan: a tool to receive or retransmit a network tap
 *
 * © 2019 The Johns Hopkins University Applied Physics Laboratory LLC.
 * All Rights Reserved. 
 *
 * AUTHOR: Troy D. Hanson
 * LICENSE: MIT
 * PACKAGE: fluxcap
 *
 */

#include <sys/signalfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include "respan.h"

struct {
  char *prog;
  int verbose;
  char *dir;
  time_t now;
  int rotate_sec;
  int maxsz_mb;
  int epoll_fd;
  int signal_fd;
  int rx_fd;
  io_mode from;
  io_mode to;
  char *file_pat;
  char pkt[MAX_PKT];
  /* savefile mapping */
  char *sv_addr;
  size_t sv_len;
  int    sv_fd;  
  time_t sv_ts;  /* time reflected in name of savefile */
  int    sv_seq; /* sequence number of save file within ts second */
  off_t  sv_cur; /* next write offset within save file */
} cfg = {
  .rx_fd = -1,
  .epoll_fd = -1,
  .signal_fd = -1,
  .rotate_sec = 5,
  .maxsz_mb = 10,
  .dir = ".",
  .file_pat = FILE_PATTERN,
};

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

#define x(a) #a,
char *mode_strings[] = { MODES NULL };
#undef x

struct option options[] = {
  {
    .name = "from",
    .has_arg = 1,
    .val = 'F',
  },
  {
    .name = "to",
    .has_arg = 1,
    .val = 'T',
  },
  {
    .name = "help",
    .has_arg = 0,
    .val = 'h',
  },
  {
    .name = NULL, /* terminal element */
  },
};

void usage() {
  fprintf(stderr,
       "usage: %s [-v] --from erspan --to pcap:<dir>\n"
       " pcap options\n"
       "     -G <rotate-sec>   (in sec)\n"
       "     -C <file-size>    (in mb)\n"
       "     -w <file-pat>     (eg. %s)\n"
       "\n",
       cfg.prog,
       FILE_PATTERN);
  exit(-1);
}

int new_epoll(int events, int fd) {
  int rc;
  struct epoll_event ev;
  memset(&ev,0,sizeof(ev)); // placate valgrind
  ev.events = events;
  ev.data.fd= fd;
  rc = epoll_ctl(cfg.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

const uint8_t pcap_glb_hdr[] = {
    0xd4, 0xc3, 0xb2, 0xa1,  /* magic number */
    0x02, 0x00, 0x04, 0x00,  /* version major, version minor */
    0x00, 0x00, 0x00, 0x00,  /* this zone */
    0x00, 0x00, 0x00, 0x00,  /* sigfigs  */
    0xff, 0xff, 0x00, 0x00,  /* snaplen  */
    0x01, 0x00, 0x00, 0x00   /* network  */
};

int close_savefile() {
  int rc=-1, sc;

  sc = munmap(cfg.sv_addr, cfg.sv_len);
  if (sc < 0) {
    fprintf(stderr,"munmap: %s\n", strerror(errno));
    goto done;
  }

  sc = ftruncate(cfg.sv_fd, cfg.sv_cur);
  if (sc < 0) {
    fprintf(stderr,"ftruncate: %s\n", strerror(errno));
    goto done;
  }

  sc = close(cfg.sv_fd);
  if (sc < 0) {
    fprintf(stderr,"close: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int reopen_savefile() {
  char base[FILE_MAX];
  char path[FILE_MAX];
  int rc=-1, sc;

  /* close out current savefile, if we have one */
  sc = cfg.sv_addr ? close_savefile() : 0;
  if (sc < 0) goto done;

  cfg.sv_addr= NULL;
  cfg.sv_len = 0;
  cfg.sv_cur = 0;
  cfg.sv_fd  =-1;
  if (cfg.sv_ts == cfg.now)
    cfg.sv_seq++;
  else
    cfg.sv_seq = 0;
  
  /* format filename with strftime */
  cfg.sv_ts = cfg.now;
  sc = strftime(base, sizeof(base), cfg.file_pat, localtime(&cfg.now));
  if (sc == 0) {
    fprintf(stderr,"strftime: error in file pattern\n");
    goto done; 
  }

  /* form full path to open */
  snprintf(path, sizeof(path), "%s/%s%.2u.pcap", cfg.dir, base, cfg.sv_seq);

  /* map file into memory */
  cfg.sv_fd = open(path, O_RDWR|O_CREAT|O_EXCL, 0644);
  if (cfg.sv_fd < 0) {
    fprintf(stderr, "open %s: %s\n", path, strerror(errno));
    goto done;
  }

  /* set its initial length; we fill it in memory to this size */
  cfg.sv_len = cfg.maxsz_mb*(1024*1024);
  sc = ftruncate(cfg.sv_fd, cfg.sv_len);
  if (sc < 0) {
    fprintf(stderr, "ftruncate %s: %s\n", path, strerror(errno));
    goto done;
  }

  int mode = PROT_READ|PROT_WRITE;
  cfg.sv_addr = mmap(0, cfg.sv_len, mode, MAP_SHARED, cfg.sv_fd, 0);
  if (cfg.sv_addr == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", path, strerror(errno));
    cfg.sv_addr = NULL;
    goto done;
  }

  /* set up global header. */
  memcpy(&cfg.sv_addr[cfg.sv_cur], pcap_glb_hdr, sizeof(pcap_glb_hdr));
  cfg.sv_cur += sizeof(pcap_glb_hdr);

  rc = 0;

 done: 
  return rc;
}


int periodic_work(void) {
  int rc = -1, sc;

  /* test rotation interval */
  if (cfg.sv_addr == NULL) {
    rc = 0;
    goto done;
  }

  if (cfg.sv_ts + cfg.rotate_sec > cfg.now) {
    rc = 0;
    goto done;
  }

  sc = reopen_savefile();
  if (sc < 0) goto done;

  rc = 0;

 done:
  return rc;
}

int handle_signal() {
  struct signalfd_siginfo info;
  int sc, rc=-1;
  ssize_t nr;
  char *s;
  
  nr = read(cfg.signal_fd, &info, sizeof(info));
  if (nr != sizeof(info)) {
    fprintf(stderr,"failed to read signal fd buffer\n");
    goto done;
  }

  switch(info.ssi_signo) {
    case SIGALRM: 
      cfg.now = time(NULL);
      sc = periodic_work();
      if (sc < 0) goto done;
      alarm(1); 
      break;
    default: 
      s = strsignal(info.ssi_signo);
      fprintf(stderr,"got signal %d (%s)\n", info.ssi_signo, s);
      goto done;
      break;
  }

 rc = 0;

 done:
  return rc;
}


int parse_mode(char *in) {
  char *colon, **m;
  int n, i=0;

  colon = strchr(in, ':');
  n = colon ? colon-in : strlen(in);

  m = mode_strings;
  while (*m) {
    if (!strncmp(*m, in, n)) {

      /* found match */

      /* parse dir from pcap:<dir> */
      if (colon && (i == mode_pcap))
        cfg.dir = strdup(colon+1);

      return i;
    }
    m++;
    i++;
  }

  return mode_none;

}

int record_packet(char *pkt, size_t len) {
  uint32_t sec, usec, caplen, origlen;
  int sc, rc = -1;
  size_t fl;

  if (cfg.sv_addr == NULL) {
    rc = 0;
    goto done;
  }

  /* does enough space remain in the output area? */
  fl = (sizeof(uint32_t) * 4) + len;
  if (cfg.sv_cur + fl >= cfg.maxsz_mb*(1024*1024)) {
    sc = reopen_savefile();
    if (sc < 0) goto done;
  }

  /* conjure timestamp from our clock */
  sec = (uint32_t)cfg.now;
  usec = 0;
  caplen = len;
  origlen = len;

  /* write packet header and packet. */
  memcpy(&cfg.sv_addr[cfg.sv_cur], &sec, sizeof(uint32_t));
  cfg.sv_cur += sizeof(uint32_t);
  memcpy(&cfg.sv_addr[cfg.sv_cur], &usec, sizeof(uint32_t));
  cfg.sv_cur += sizeof(uint32_t);
  memcpy(&cfg.sv_addr[cfg.sv_cur], &caplen, sizeof(uint32_t));
  cfg.sv_cur += sizeof(uint32_t);
  memcpy(&cfg.sv_addr[cfg.sv_cur], &origlen, sizeof(uint32_t));
  cfg.sv_cur += sizeof(uint32_t);
  memcpy(&cfg.sv_addr[cfg.sv_cur], pkt, len);
  cfg.sv_cur += len;

  rc = 0;

 done:
  return rc;
}

/* set up as a GRE receiver */
int setup_rx_encap(void) {
  struct sockaddr *sa;
  int i, sc, rc = -1;
  struct iovec *iov;
  socklen_t sz;

  cfg.rx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
  if (cfg.rx_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

/* decode the gre packet into its fields.
 * input pkt starts with outer IP header.
 * fields are returned in network order!
 * fields are zeroed if not present
 * on decoding failure, returns -1.
 * returns 0 on success
 */
#define GRE_MIN_HDR 4
#define GRE_CHECKSUM_LEN 2
#define GRE_RESERVED1_LEN 2
#define GRE_KEY_LEN 4
#define GRE_SEQNO_LEN 4
int decode_gre(char *pkt, ssize_t nr, uint16_t *type, uint16_t *csum,
     uint32_t *key, uint32_t *seqno, char **payload, size_t *plen) {
  int has_key, has_checksum, has_seqno, ko, co, so, po, ip_hdr_len;
  uint8_t ip_proto;

  *key = 0;
  *seqno = 0;
  *csum = 0;
  *payload = NULL;
  *plen = 0;
  *type = 0;

  assert(nr > 0);
  ip_hdr_len = (pkt[0] & 0x0f) * 4;

  if (nr < ip_hdr_len + GRE_MIN_HDR)
    return -1;

  ip_proto = pkt[9];
  if (ip_proto != IPPROTO_GRE)
    return -1;

  memcpy(type, &pkt[ip_hdr_len + 2], sizeof(uint16_t));

  has_key      = pkt[ip_hdr_len] & (1U << 5);
  has_checksum = pkt[ip_hdr_len] & (1U << 7);
  has_seqno    = pkt[ip_hdr_len] & (1U << 4);

  if (has_checksum) {
    co = ip_hdr_len + GRE_MIN_HDR;
    if (co + GRE_CHECKSUM_LEN > nr)
      return -1;
    memcpy(csum, pkt + co, GRE_CHECKSUM_LEN);
  }

  if (has_key) {
    ko = ip_hdr_len + GRE_MIN_HDR
         + (has_checksum ? GRE_CHECKSUM_LEN + GRE_RESERVED1_LEN : 0);
    if (ko + GRE_KEY_LEN > nr)
      return -1;
    memcpy(key, pkt + ko, GRE_KEY_LEN);
  }

  if (has_seqno) {
    so = ip_hdr_len + GRE_MIN_HDR +
         + (has_checksum ? GRE_CHECKSUM_LEN + GRE_RESERVED1_LEN : 0)
         + (has_key      ? GRE_KEY_LEN : 0);
    if (so + GRE_SEQNO_LEN > nr)
      return -1;
    memcpy(seqno, pkt + so, GRE_SEQNO_LEN);
  }

  po = ip_hdr_len + GRE_MIN_HDR +
       + (has_checksum ? GRE_CHECKSUM_LEN + GRE_RESERVED1_LEN : 0)
       + (has_key      ? GRE_KEY_LEN : 0)
       + (has_seqno    ? GRE_SEQNO_LEN : 0);

  *plen = nr - po;
  *payload = pkt + po;
  return 0;
}

/* see ovs-fields(7) */
#define ERSPAN_V1_GRETYPE 0x88be
#define ERSPAN_V1_HDR 8
#define ERSPAN_V2_GRETYPE 0x22eb
#define ERSPAN_V2_HDR 12
int decode_erspan(uint16_t gre_type, uint8_t *in, size_t in_len, 
  char **out, size_t *out_len) {
  int has_subhdr, rc = -1;

  gre_type = ntohs(gre_type);

  switch(gre_type) {
    case ERSPAN_V1_GRETYPE: /* erspan version 1 aka Type II */
      if (in_len < ERSPAN_V1_HDR) goto done;
      *out = in + ERSPAN_V1_HDR;
      *out_len = in_len - ERSPAN_V1_HDR;
      if (cfg.verbose) fprintf(stderr, " erspan v1\n");
      break;
    case ERSPAN_V2_GRETYPE: /* erspan version 2 aka Type III */
      if (in_len < ERSPAN_V2_HDR) goto done;
      /* test if ERSPAN "Optional subheader" flag is set */
      has_subhdr = (in[11] & 0x1) ? 1 : 0;
      *out = in + ERSPAN_V2_HDR + (has_subhdr ? 8 : 0);
      *out_len = in_len - ERSPAN_V2_HDR - (has_subhdr ? 8 : 0);
      if (cfg.verbose)
        fprintf(stderr, " erspan v2 (sub_hdr: %d)\n", has_subhdr);
      break;
    default:
      fprintf(stderr, "unknown gre erspan type 0x%x\n", gre_type);
      goto done;
  }

  rc = 0;

 done:
  return rc;
}

int handle_grerx(void) {
  uint32_t seqno, key;
  uint16_t csum, type;
  char *data, *out;
  size_t dlen, sz;
  int rc=-1, sc;
  ssize_t nr;

  nr = read(cfg.rx_fd, cfg.pkt, sizeof(cfg.pkt));
  if (nr < 0) {
    fprintf(stderr, "read: %s\n", strerror(errno));
    goto done;
  }

  if (cfg.verbose)
    fprintf(stderr, "received GRE packet of %zd bytes\n", nr);

  sc = decode_gre(cfg.pkt, nr, &type, &csum, &key, &seqno, &data, &dlen);
  if (sc < 0) {
    rc = 0;
    goto done;
  }

  /* decapsulate packet, advance over GRE header */
  if (dlen == 0) {
    rc = 0;
    goto done;
  }

  /* expect ERSPAN header at this point - discard */
  sc = decode_erspan(type, data, dlen, &out, &sz);
  if (sc < 0) {
    rc = 0;
    goto done;
  }

  /* save the packet */
  sc = record_packet(out, sz);
  if (sc < 0) goto done;

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  struct epoll_event ev;
  int opt, rc=-1, sc, n;

  cfg.now = time(NULL);
  cfg.prog = argv[0];

  do {
     opt = getopt_long_only(argc, argv, "vhF:T:G:C:w:", options, NULL);
     switch (opt) {
       case 'F': cfg.from = parse_mode(optarg); break;
       case 'T': cfg.to   = parse_mode(optarg); break;
       case 'G': cfg.rotate_sec = atoi(optarg); break;
       case 'C': cfg.maxsz_mb = atoi(optarg); break;
       case 'w': cfg.file_pat = strdup(optarg); break;
       case 'v': cfg.verbose++; break;
       case 'h': usage();
       case -1: break;
     }
  } while (opt > 0);

  if (cfg.from == mode_none) usage();
  if (cfg.to   == mode_none) usage();

  /* right now we only support this mode */
  assert(cfg.to == mode_pcap);
  assert(cfg.from == mode_erspan);

  /* block all signals. we take signals synchronously via signalfd */
  sigset_t all;
  sigfillset(&all);
  sigprocmask(SIG_SETMASK,&all,NULL);

  /* a few signals we'll accept via our signalfd */
  sigset_t sw;
  sigemptyset(&sw);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++)
	  sigaddset(&sw, sigs[n]);

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

  /* set up the encapsulation receiver */
  sc = setup_rx_encap();
  if (sc < 0) goto done;

  /* add descriptors of interest */
  sc = new_epoll(EPOLLIN, cfg.signal_fd);
  if (sc < 0) goto done;
  sc = new_epoll(EPOLLIN, cfg.rx_fd);
  if (sc < 0) goto done;

  /* open the initial savefile */
  sc = reopen_savefile();
  if (sc < 0) goto done;

  alarm(1);
  for (;;) {

    sc = epoll_wait(cfg.epoll_fd, &ev, 1, -1);
    if (sc < 0) {
      fprintf(stderr,"epoll: %s\n", strerror(errno));
      break;
    }

    if (ev.data.fd == cfg.signal_fd) {
      sc = handle_signal();
      if (sc < 0) goto done;
    } 
    else if (ev.data.fd == cfg.rx_fd) {
      sc = handle_grerx();
      if (sc < 0) goto done;
    } 
    else {
      fprintf(stderr, "unknown fd\n");
      assert(0);
    }

  }

  rc = 0;

 done:
  if (cfg.sv_addr) close_savefile();
  if (cfg.rx_fd != -1) close(cfg.rx_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  return rc;
}
