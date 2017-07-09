#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pcre.h>
#include "shr.h"

#define OVECSZ 30 /* must be multiple of 3 */

/* 
 * fluxcap file copy tool
 *
 * reads filenames from input shr ring
 * transforms file name via regex to dest path
 * copies to dest path, making directories as needed
 * writes output file to secondary shr ring optionally
 */

#define BATCH_FRAMES 10000
#define BATCH_MB     10
#define BATCH_BYTES  (BATCH_MB * 1024 * 1024)
char read_buffer[BATCH_BYTES];
struct iovec read_iov[BATCH_FRAMES];

struct {
  char *prog;
  int verbose;
  int epoll_fd;     /* epoll descriptor */
  int signal_fd;    /* to receive signals */
  int ring_fd;      /* ring readability fd */
  char *input_ring; /* ring file name */
  struct shr *ring; /* open ring handle */
  char *buf;        /* buf for shr_readv */
  struct iovec *iov;/* iov for shr_readv */
  char *pattern;    /* regex applied to input filenames */
  char *template;   /* basis of output filenames */
  pcre *re;         /* compiled pattern */
} cfg = {
  .buf = read_buffer,
  .iov = read_iov,
  .epoll_fd = -1,
  .signal_fd = -1,
  .ring_fd = -1,
  .pattern = "^.+$",   /* default regex matches any nonempty string */
  .template = "$0",    /* default output template is copy of input */
};

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage() {
  fprintf(stderr,"usage: %s [options] -i <filenames-ring>\n", cfg.prog);
  fprintf(stderr,"options:\n"
                 "   -v         (verbose)\n"
                 "   -p <regex> (pattern)\n"
                 "   -h         (this help)\n"
                 "\n");
  exit(-1);
}

int add_epoll(int events, int fd) {
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

int del_epoll(int fd) {
  int rc;
  struct epoll_event ev;
  rc = epoll_ctl(cfg.epoll_fd, EPOLL_CTL_DEL, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

/* work we do at 1hz  */
int periodic_work(void) {
  int rc = -1;

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

/* the heart of this program is here. we process one filename */
int process(char *file, size_t len) {
  int ovec[OVECSZ], rc = -1, pe, l, i;
  char *c;

  if (cfg.verbose) fprintf(stderr, "input: %.*s\n", len, file);

  pe = pcre_exec(cfg.re, NULL, file, len, 0, 0, ovec, OVECSZ);

  if (pe < 0) {
    if (pe == PCRE_ERROR_NOMATCH) {
      fprintf(stderr, "skipping %.*s: not a match for regex\n", len, file);
      rc = 0;
      goto done;
    }

    fprintf(stderr, "pcre_exec: error (%d) - see pcreapi(3)\n", pe);
    goto done;
  }

  
  if (pe == 0) {
    fprintf(stderr, "error: use fewer captures or increase OVECSZ\n");
    goto done;
  }

  /* pe is the number of substrings captured by pcre_exec including the
   * substring that matched the entire regular expression. see pcreapi(3) */
  assert(pe > 0);
  if (cfg.verbose) {
    for(i=0; i < pe*2; i+=2) {
      c = &file[ovec[i]];
      l = ovec[i+1]-ovec[i];
      fprintf(stderr, " $%u matched %.*s\n", i/2, l, c);
    }
  }

  rc = 0;

 done:
  return rc;
}

int handle_io(void) {
  int rc = -1, iovcnt, i;
  struct iovec *iov;
  ssize_t rv, wc;

  iovcnt = BATCH_FRAMES;
  rv = shr_readv(cfg.ring, cfg.buf, BATCH_BYTES, cfg.iov, &iovcnt);
  if (rv < 0) fprintf(stderr, "shr_readv: error\n");
  if (rv > 0) {
    /* iterate over filenames read in batch */
    for(i = 0; i < iovcnt; i++) {
      iov = &cfg.iov[i];
      if (process(iov->iov_base, iov->iov_len) < 0) goto done;
    }

  }

  rc = 0;

 done:
  return rc;
}

int parse_regex(void) {
  int rc = -1, off;
  const char *err;

  assert(cfg.pattern);

  cfg.re = pcre_compile(cfg.pattern, 0, &err, &off, NULL);
  if (cfg.re == NULL) {
    fprintf(stderr, "error in regex %s: %s (offset %u)\n", cfg.pattern, err, off);
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  int opt, rc=-1, n, ec;
  struct epoll_event ev;
  cfg.prog = argv[0];
  char unit, *c, buf[100];

  while ( (opt = getopt(argc,argv,"vhp:i:")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'h': default: usage(); break;
      case 'p': cfg.pattern = strdup(optarg); break;
      case 'i': cfg.input_ring = strdup(optarg); break;
    }
  }

  if (cfg.input_ring == NULL) usage();
  if (parse_regex() < 0) goto done;
  
  /* block all signals. we accept signals via signal_fd */
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

  /* open the ring */
  cfg.ring = shr_open(cfg.input_ring, SHR_RDONLY|SHR_NONBLOCK);
  if (cfg.ring == NULL) goto done;
  cfg.ring_fd = shr_get_selectable_fd(cfg.ring);
  if (cfg.ring_fd < 0) goto done;

  /* add descriptors of interest to epoll */
  if (add_epoll(EPOLLIN, cfg.signal_fd)) goto done;
  if (add_epoll(EPOLLIN, cfg.ring_fd)) goto done;

  alarm(1);

  while (1) {
    ec = epoll_wait(cfg.epoll_fd, &ev, 1, -1);
    if (ec < 0) { 
      fprintf(stderr, "epoll: %s\n", strerror(errno));
      goto done;
    }

    if (ec == 0)                          { assert(0); goto done; }
    else if (ev.data.fd == cfg.signal_fd) { if (handle_signal()  < 0) goto done; }
    else if (ev.data.fd == cfg.ring_fd)   { if (handle_io() < 0) goto done; }
    else                                  { assert(0); goto done; }
  }
  
  rc = 0;
 
 done:
  if (cfg.ring) shr_close(cfg.ring);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.input_ring) free(cfg.input_ring);
  return 0;
}
