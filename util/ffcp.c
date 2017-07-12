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
#include <pcre.h>
#include <time.h>
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
  int dry_run;
  int mkpath;
  int epoll_fd;     /* epoll descriptor */
  int signal_fd;    /* to receive signals */
  int ring_fd;      /* ring readability fd */
  char *input_ring; /* ring file name */
  char *output_ring;/* ring file name */
  struct shr *ring; /* open ring handle */
  struct shr *oring;/* output ring handle */
  char *buf;        /* buf for shr_readv */
  struct iovec *iov;/* iov for shr_readv */
  char *regex;    /* regex applied to input filenames */
  char *template;   /* basis of output filenames */
  pcre *re;         /* compiled regex */
  /* these are all work spaces for dealing with paths */
  char tmp[PATH_MAX];
  char dir[PATH_MAX];
  char rpath1[PATH_MAX];
  char rpath2[PATH_MAX];
  char opath[PATH_MAX];
} cfg = {
  .buf = read_buffer,
  .iov = read_iov,
  .epoll_fd = -1,
  .signal_fd = -1,
  .ring_fd = -1,
  .regex = "([^/]+)$", /* default: match any path, capture basename */
  .template = "$1",       /* default: output filename is input basename */
};

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage() {
  fprintf(stderr,"fluxcap file copy utility\n\n");
  fprintf(stderr,"This tool continuously copies files using a naming template.\n"
                 "The original filenames arrive in the input ring. They are\n"
                 "matched against the given regular expression. Matches are\n"
                 "made into a new filename according to the given template.\n"
                 "The template uses captures from the regular expression by\n"
                 "referring to $0 (whole matching expression), $1 (first\n"
                 "capture), etc. After $9 the captures are $A through $Z.\n\n");
  fprintf(stderr,"usage: %s <options>\n\n", cfg.prog);
  fprintf(stderr,"options:\n"
                 "   -i <input-ring>    [required; input filenames in ring]\n"
                 "   -p <regex>         [default: wildcard, capture basename]\n"
                 "   -t <template>      [default: basename of original]\n"
                 "   -o <output-ring>   [log output filenames to ring]\n"
                 "   -m                 [create directories in output path]\n"
                 "   -d                 [dry-run; show names, no copying]\n"
                 "   -h                 [this help]\n"
                 "   -v                 [verbose; repeatable]\n"
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

int map_copy(char *file, char *dest) {
  struct stat s;
  char *src=NULL,*dst=NULL;
  int fd=-1,dd=-1,rc=-1;

  if (cfg.dry_run) {
    rc = 0;
    goto done;
  }

  /* source file */
  if ( (fd = open(file, O_RDONLY)) == -1) {
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
  if (ftruncate(dd, s.st_size) == -1) {
    fprintf(stderr,"ftruncate: %s\n", strerror(errno));
    goto done;
  }

  /* copying a zero len file? we're done. don't attempt to map */
  if (s.st_size == 0) {
    rc = 0;
    goto done;
  }

  /* map both */
  src = mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (src == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", file, strerror(errno));
    goto done;
  }

  dst = mmap(0, s.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, dd, 0);
  if (dst == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", dest, strerror(errno));
    goto done;
  }
  memcpy(dst,src,s.st_size);

  rc = 0;

done:
  if (src && (src != MAP_FAILED)) munmap(src, s.st_size);
  if (dst && (dst != MAP_FAILED)) munmap(dst, s.st_size);
  if (fd != -1) close(fd);
  if (dd != -1) close(dd);
  return rc;
}

/* user probably did not intend to copy "file" to "./file" so we
 * error if src/dst pathnames resolve to the same file name.
 *
 * returns
 *  0 if files differ
 *  1 if files same
 * -1 on error (not file)
 *
 */
int same_file(char *newfile, char *srcfile) {
  int rc = -1;

  if (realpath(srcfile, cfg.rpath1) == NULL) {
    fprintf(stderr, "realpath: %s: %s\n", srcfile, strerror(errno));
    goto done;
  }

  if (realpath(newfile, cfg.rpath2) == NULL) {
    /* newfile doesn't exist, or path to it,
     * so it's not the same file as srcfile */
    rc = 0;
    goto done;
  }

  rc = strcmp(cfg.rpath1, cfg.rpath2) ? 0 : 1;
  if (rc == 1) {
    fprintf(stderr, "%s and %s are the same file\n", newfile, srcfile);
    goto done;
  }

 done:
  return rc;
}


#define append(c) do {               \
  if (olen == 0) {                   \
    fprintf(stderr,"buffer full\n"); \
    goto done;                       \
  }                                  \
  *o = c;                            \
  olen--;                            \
  o++;                               \
} while(0)

/* make a pathname from template applied to src. */
int pat2path(char *file, int *ovec, int pe) {
  char *p, *o, *c, opath[PATH_MAX];
  int i, rc = -1, ec; 
  unsigned char x;
  size_t olen, l;

  /* show captures for debugging */
  if (cfg.verbose > 1) {
    for(i=0; i < pe*2; i+=2) {
      c = &file[ovec[i]];
      l = ovec[i+1]-ovec[i];
      fprintf(stderr, " $%u matched %.*s\n", i/2, (int)l, c);
    }
  }

  p = cfg.template;
  o = cfg.opath;
  olen = sizeof(cfg.opath);

  while (*p != '\0') {
    if (*p == '$') {    /* translate next template character */
      p++;
      if (*p == '$') append(*p); /* special case: $$ */
      else {

        /* here if we had $x where x must be [0-9A-Z] */
        if      ((*p >= '0') && (*p <= '9')) x = *p - '0';
        else if ((*p >= 'A') && (*p <= 'Z')) x = *p - 'A' + 10;
        else {
          fprintf(stderr,"invalid capture syntax\n");
          goto done;
        }

        if (x > pe) {
          fprintf(stderr,"capture $%u exceeds $%d\n", x, pe);
          goto done;
        }

        /* copy capture $x */
        l = ovec[x*2+1] - ovec[x*2];
        if (l > olen) {
          fprintf(stderr, "capture too large for buffer\n");
          goto done;
        }
        assert(l >= 0);
        memcpy(o, &file[ovec[x*2]], l);
        olen -= l;
        o += l;
      }
    } else append(*p); /* copy literal character */
    p++;
  }

  append('\0');
  if (same_file(cfg.opath, file)) goto done;
  rc = 0;

  if (cfg.dry_run || cfg.verbose) {
    fprintf(stderr, "%s -> %s\n", file, cfg.opath);
  }

 done:
  return rc;
}

/* create the directory empty leading up to the basename */
int mkpath(char *path) {
  int rc  = -1, ec;
  struct stat s;
  char *b, *e;
  size_t l;

  b = path;
  e = path;
  while (1) {
    while ((*e != '/') && (*e != '\0')) e++;
    if (*e == '\0') break;
    l = e-b+1;
    if (l+1 > sizeof(cfg.dir)) goto done;
    memcpy(cfg.dir, b, l);
    cfg.dir[l] = '\0';
    ec = stat(cfg.dir, &s);
    if ((ec < 0) && (errno == ENOENT)) {
      if (cfg.verbose) fprintf(stderr, "creating %s\n", cfg.dir);
      if (mkdir(cfg.dir, 0777) < 0) {
        fprintf(stderr, "mkdir %s: %s\n", cfg.dir, strerror(errno));
        goto done;
      }
    }
    e++;
  }

  rc = 0;

 done:
  return rc;
}

/* the heart of this program is here. we process one filename */
int process(char *file, size_t len) {
  int ovec[OVECSZ], rc = -1, pe, l, i, ec;

  /* make a nul terminated string */
  if (len+1 > sizeof(cfg.tmp)) goto done;
  memcpy(cfg.tmp, file, len);
  cfg.tmp[len] = '\0';

  pe = pcre_exec(cfg.re, NULL, file, len, 0, 0, ovec, OVECSZ);
  if (pe < 0) {
    if (pe == PCRE_ERROR_NOMATCH) {
      fprintf(stderr, "skipping %s: not a match for regex\n", cfg.tmp);
      rc = 0;
      goto done;
    }
    fprintf(stderr, "pcre_exec: error (%d) - see pcreapi(3)\n", pe);
    goto done;
  }
  
  /* captures didn't fit in OVEC */
  if (pe == 0) {
    fprintf(stderr, "error: use fewer captures or increase OVECSZ\n");
    goto done;
  }

  /* pe is the number of substrings captured by pcre_exec including the
   * substring that matched the entire regular expression. see pcreapi(3) */
  assert(pe > 0);
  if (pat2path(cfg.tmp, ovec, pe) < 0) goto done;
  if (cfg.mkpath && (mkpath(cfg.opath) < 0)) goto done;
  if (map_copy(cfg.tmp, cfg.opath) < 0) goto done;
  if (cfg.oring) {
    ec = shr_write(cfg.oring, cfg.opath, strlen(cfg.opath));
    if (ec < 0) {
      fprintf(stderr, "shr_write: error (%d)\n", ec);
      goto done;
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

  assert(cfg.regex);

  cfg.re = pcre_compile(cfg.regex, 0, &err, &off, NULL);
  if (cfg.re == NULL) {
    fprintf(stderr, "error in regex %s: %s (offset %u)\n", cfg.regex, err, off);
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

  while ( (opt = getopt(argc,argv,"vmdht:r:i:o:")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'h': default: usage(); break;
      case 'd': cfg.dry_run=1; break;
      case 'm': cfg.mkpath=1; break;
      case 'r': cfg.regex = strdup(optarg); break;
      case 't': cfg.template = strdup(optarg); break;
      case 'i': cfg.input_ring = strdup(optarg); break;
      case 'o': cfg.output_ring = strdup(optarg); break;
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

  if (cfg.output_ring) {
    cfg.oring = shr_open(cfg.output_ring, SHR_WRONLY);
    if (cfg.oring == NULL) goto done;
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
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.input_ring) free(cfg.input_ring);
  if (cfg.output_ring) free(cfg.output_ring);
  return 0;
}
