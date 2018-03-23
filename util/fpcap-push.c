#include <sys/signalfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <zlib.h>
#include "shr.h"

/* 
 * fluxcap pcap-to-ring tool
 *
 * reads input shr ring of pcap filenames
 * (having optional gz/xz file extension)
 * write their packets to the output ring
 *
 */

#define BATCH_FRAMES 1000
#define BATCH_MB     1
#define BATCH_BYTES  (BATCH_MB * 1024 * 1024)
char read_buffer[BATCH_BYTES];
struct iovec read_iov[BATCH_FRAMES];
char tmp[PATH_MAX];

struct {
  char *prog;
  int verbose;
  int epoll_fd;     /* epoll descriptor */
  int signal_fd;    /* to receive signals */
  int fatal_signal_fd;/* fewer signals monitored in blocking i/o */
  int ring_fd;      /* ring readability fd */
  char *input_ring; /* R ring file name */
  char *output_ring;/* W ring file name */
  struct shr *ring; /* R ring handle */
  struct shr *oring;/* W ring handle */
  char *buf;        /* buf for shr_readv */
  struct iovec *iov;/* iov for shr_readv */
  char *tmp;
} cfg = {
  .buf = read_buffer,
  .iov = read_iov,
  .tmp = tmp,
  .epoll_fd = -1,
  .signal_fd = -1,
  .fatal_signal_fd = -1,
  .ring_fd = -1,
};

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage() {
  fprintf(stderr,"fluxcap pcap to ring utility\n\n");
  fprintf(stderr,"This tool continuously reads filenames from an input ring.\n"
                 "The filenames are those of PCAP files and may optionally\n"
                 "have a .gz or .xz file extension, decompressed in memory,\n"
                 "as this tool pushes their packets to the output ring.\n\n");
  fprintf(stderr,"usage: %s -i <input-ring> -o <output-ring>\n\n", cfg.prog);
  fprintf(stderr,"options:\n"
                 "   -i <input-ring>    [ring of input filenames]\n"
                 "   -o <output-ring>   [ring for output packets]\n"
                 "   -v                 [verbose; repeatable]\n"
                 "   -h                 [this help]\n"
                 "\n"
                 "\n"
                 "\n");
  exit(-1);
}

int add_epoll(int events, int fd) {
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
  ssize_t nr;
  
  nr = read(cfg.signal_fd, &info, sizeof(info));
  if (nr != sizeof(info)) {
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

#define want_gzip 16
#define def_windowbits (15 + want_gzip)
#define def_memlevel 8
int zip_copy(char *file, char *dest) {
  char suffixed_path[PATH_MAX];
  int fd=-1,dd=-1,rc=-1,ec;
  char *src=NULL,*dst=NULL;
  struct stat s;
  size_t zmax, len;

  /* source file */
  if ( (fd = open(file, O_RDONLY)) == -1) {
    if (errno == ENOENT) rc = 1;
    fprintf(stderr,"can't open %s: %s\n", file, strerror(errno));
    goto done;
  }
  if (fstat(fd, &s) == -1) {
    fprintf(stderr,"can't stat %s: %s\n", file, strerror(errno));
    goto done;
  }
  if (!S_ISREG(s.st_mode)) {
    fprintf(stderr,"not a regular file: %s\n", file);
    goto done;
  }

  /* dest file */
  if ( (dd = open(dest, O_RDWR|O_TRUNC|O_CREAT, 0644)) == -1) {
    fprintf(stderr,"can't open %s: %s\n", dest, strerror(errno));
    goto done;
  }

  /* map source */
  src = s.st_size ? mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0) : NULL;
  if (src == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", file, strerror(errno));
    goto done;
  }

  /* minimal required initialization of z_stream prior to deflateInit2 */
  z_stream zs = {.next_in = src, .zalloc=Z_NULL, .zfree=Z_NULL, .opaque=NULL};
  ec = deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, def_windowbits,
               def_memlevel, Z_DEFAULT_STRATEGY);
  if (ec != Z_OK) {
    fprintf(stderr, "deflateInit2 failed: %s\n", zs.msg);
    goto done;
  }

  /* calculate the max space needed to deflate this buffer in a single pass */
  zmax = deflateBound(&zs, s.st_size);

  /* map the output file at the max size we might need. */
  if (ftruncate(dd, zmax) == -1) {
    fprintf(stderr,"ftruncate: %s\n", strerror(errno));
    goto done;
  }
  dst = mmap(0, zmax, PROT_READ|PROT_WRITE, MAP_SHARED, dd, 0);
  if (dst == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", dest, strerror(errno));
    goto done;
  }

  /* prepare to deflate */
  zs.avail_in = s.st_size;
  zs.next_out = dst;
  zs.avail_out = zmax;

  /* deflate it in one fell swoop */
  ec = deflate(&zs, Z_FINISH);
  if (ec != Z_STREAM_END) {
    fprintf(stderr, "single-pass deflate failed: ");
    if (ec == Z_OK) fprintf(stderr, "additional passes needed\n");
    else if (ec == Z_STREAM_ERROR) fprintf(stderr,"stream error\n");
    else if (ec == Z_BUF_ERROR) fprintf(stderr,"buffer unavailable\n");
    else fprintf(stderr,"unknown error\n");
    goto done;
  }

  ec = deflateEnd(&zs);
  if (ec != Z_OK) {
    fprintf(stderr,"deflateEnd: %s\n", zs.msg);
    goto done;
  }

  /* unmap and truncate the output file to the compressed length */
  munmap(dst, zmax);
  dst = NULL;
  if (ftruncate(dd, zs.total_out) == -1) {
    fprintf(stderr,"ftruncate: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

done:
  if (src && (src != MAP_FAILED)) munmap(src, s.st_size);
  if (dst && (dst != MAP_FAILED)) munmap(dst, zmax);
  if (fd != -1) close(fd);
  if (dd != -1) close(dd);
  return rc;
}


/* the heart of this program is here. */
int push_file(char *file, size_t len) {
  int rc = -1, pe, l, i, ec;

  /* ensure a nul terminated string */
  if (len+1 > PATH_MAX) goto done;
  memcpy(cfg.tmp, file, len);
  cfg.tmp[len] = '\0';

  if (cfg.verbose) {
    fprintf(stderr, "-> %s\n", cfg.tmp);
  }

  /* TODO observe gz or xz suffix */
  /* map, parse, inject packets */


  rc = 0;

 done:
  return rc;
}

int handle_io(void) {
  struct iovec *iov;
  size_t i, iovcnt;
  int rc = -1, sc;
  ssize_t nr;

  iovcnt = BATCH_FRAMES;
  nr = shr_readv(cfg.ring, cfg.buf, BATCH_BYTES, cfg.iov, &iovcnt);
  if (nr <  0) fprintf(stderr, "shr_readv: error\n");
  if (nr == 0) iovcnt = 0;

  /* iterate over filenames */
  for(i = 0; i < iovcnt; i++) {
    iov = &cfg.iov[i];
    sc = push_file(iov->iov_base, iov->iov_len);
    if (sc < 0) goto done;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  int opt, rc=-1, n, ec, sc;
  struct epoll_event ev;
  cfg.prog = argv[0];

  while ( (opt = getopt(argc,argv,"vhi:o:")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'h': default: usage(); break;
      case 'i': cfg.input_ring = strdup(optarg); break;
      case 'o': cfg.output_ring = strdup(optarg); break;
    }
  }

  if (cfg.input_ring == NULL) usage();
  
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

  /* open the rings */
  cfg.ring = shr_open(cfg.input_ring, SHR_RDONLY|SHR_NONBLOCK);
  if (cfg.ring == NULL) goto done;

  cfg.ring_fd = shr_get_selectable_fd(cfg.ring);
  if (cfg.ring_fd < 0) goto done;

  cfg.oring = shr_open(cfg.output_ring, SHR_WRONLY);
  if (cfg.oring == NULL) goto done;

  /* fewer signals we'll allow to interrupt a blocking shr_write */
  sigset_t sf;
  sigemptyset(&sf);
  sigaddset(&sf, SIGTERM);
  sigaddset(&sf, SIGINT);

  /* create more selective signalfd for monitoring inside shr_write */
  cfg.fatal_signal_fd = signalfd(-1, &sf, 0);
  if (cfg.fatal_signal_fd == -1) {
    fprintf(stderr,"signalfd: %s\n", strerror(errno));
    goto done;
  }

  /* make shr_write monitor fatal signals */
  sc = shr_ctl(cfg.oring, SHR_POLLFD, cfg.fatal_signal_fd);
  if (sc < 0) {
    fprintf(stderr,"shr_ctl: error\n");
    goto done;
  }

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
  if (cfg.oring) shr_close(cfg.oring);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.fatal_signal_fd != -1) close(cfg.fatal_signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.input_ring) free(cfg.input_ring);
  if (cfg.output_ring) free(cfg.output_ring);
  return 0;
}
