#include <sys/signalfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pcre.h>
#include "libut.h"
#include "shr.h"


/*
 * fwalk: walk a directory tree,
 *        write leaf filenames to ring
 *
 * the leaf filenames are absolute paths
 * and are nul-terminated.
 *
 * this tool uses iteration (not recursion)
 * to walk the directory tree, and handles
 * signals and other epoll events during
 * the walk.
 *
 */

struct fe {
  char path[PATH_MAX];
  struct fe *next;
  struct fe *prev;
};

char dir[PATH_MAX];

struct {
  char *prog;
  int verbose;
  int epoll_fd;       /* epoll descriptor */
  int signal_fd;      /* to receive signals */
  int fatal_signal_fd;/* fewer signals monitored in blocking i/o */
  char *ring_name;    /* ring file name */
  struct shr *ring;   /* open ring handle */
  char *dir;          /* directory tree (realpath)  */
  struct fe *fentries;/* DL list current walk queue */
  char *regex;        /* string of regex, if any */
  pcre *re;           /* compiled regex, if any */
} cfg = {
  .dir = dir,
  .epoll_fd = -1,
  .signal_fd = -1,
  .fatal_signal_fd = -1,
};

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage() {
  fprintf(stderr,"directory walk tool\n"
                 "\n"
                 "walks directory tree and writes leaf filenames\n"
                 "to the given ring, as absolute, nul-terminated\n"
                 "strings"
                 "\n"
                 "\n");
  fprintf(stderr,"usage: %s [options] -r <ring> -d <dir>\n", cfg.prog);
  fprintf(stderr,"\n");
  fprintf(stderr,"options:\n"
                 "   -d <directory      [directory to prune; required]\n"
                 "   -r <ring-file>     [ring name for incoming files]\n"
                 "   -m                 [regex on file absolute path]\n"
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

int handle_signal(void) {
  struct signalfd_siginfo info;
  ssize_t nr;
  int rc=-1;
  
  nr = read(cfg.signal_fd, &info, sizeof(info));
  if (nr != sizeof(info)) {
    fprintf(stderr,"failed to read signal buffer\n");
    goto done;
  }

  switch(info.ssi_signo) {
    case SIGALRM: 
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

struct fe *make_fentry(char *path) {
  struct fe *fe = NULL;
  size_t len;

  len = path ? strlen(path) : 0;
  if (len+1 > sizeof(fe->path)) {
    fprintf(stderr, "path too long\n");
    goto done;
  }

  fe = calloc(1, sizeof(struct fe));
  if (fe == NULL) {
    fprintf(stderr, "out of memory\n");
    goto done;
  }

  if (path) memcpy(fe->path, path, len+1);

 done:
  return fe;
}

int fe_sort(const void *_a, const void *_b) {
	struct fe *a = (struct fe *)_a;
	struct fe *b = (struct fe *)_b;
  return strcmp(a->path, b->path);
}

/*
 * match_regex
 *
 * applies regex if one is defined
 *
 * returns
 *  0 not a match
 *  1 match (or no regex defined)
 * -1 error
 *
 */
#define OVECSZ 30 /* must be multiple of 3 */
int match_regex(char *file, size_t len) {
  int ovec[OVECSZ], pe;

  if (cfg.re == NULL) return 1;

  pe = pcre_exec(cfg.re, NULL, file, len, 0, 0, ovec, OVECSZ);

  if (pe >= 0)
    return 1;

  if (pe == PCRE_ERROR_NOMATCH)
    return 0;

  fprintf(stderr, "pcre_exec: error (%d) - see pcreapi(3)\n", pe);
  return -1;

}
/*
 * insert_dir
 *
 * places directory contents (immediate children)
 * of dir in sorted order at the front of the queue 
 *
 * returns:
 *   0 success
 *  -1 error
 */
int insert_dir(char *dir) {
  struct fe *fe, *fe_tmp, *fe_list = NULL;
  struct dirent *dent;
  int rc = -1, sc;
  DIR *d = NULL;
  size_t l, el;

  l = strlen(dir);
  d = opendir(dir);
  if (d == NULL) {
    fprintf(stderr, "opendir %s: %s\n", dir, strerror(errno));
    goto done;
  }

  while ( (dent = readdir(d)) != NULL) {

    if (!strcmp(dent->d_name, "."))  continue;
    if (!strcmp(dent->d_name, "..")) continue;

    el = strlen(dent->d_name);
    if (l+1+el+1 > sizeof(fe->path)) {
      fprintf(stderr, "path too long\n");
      goto done;
    }

    fe = make_fentry(NULL);
    if (fe == NULL) goto done;
    memcpy(fe->path, dir, l);
    fe->path[l] = '/';
    memcpy(&fe->path[l+1], dent->d_name, el+1);
    DL_APPEND(fe_list, fe);
  }

  /* sort directory contents */
  DL_SORT(fe_list, fe_sort);

  /* prepend to master list */
  DL_CONCAT(fe_list, cfg.fentries);
  cfg.fentries = fe_list;
  fe_list = NULL;
  rc = 0;

 done:
  if (d) closedir(d);
  if (rc && fe_list) {
    DL_FOREACH_SAFE(fe_list, fe, fe_tmp)
      free(fe);
  }
  return rc;
}

/*
 * keep_walking
 *
 * this is the heart of our iterative file walker
 * it pulls one element off the file queue
 * if its a file, it gets sent to the ring
 * if its a directory, its content replaces its own entry
 *
 * returns:
 *  0 (done, no more work to do)
 *  1 (did work, and more work remains)
 * -1 (error)
 *
 */
int keep_walking(void) {
  struct fe *fe = NULL;
  int sc, rc = -1;
  size_t len, nr;
  struct stat s;

  fe = cfg.fentries;
  assert(fe);

  DL_DELETE(cfg.fentries, fe);

  sc = lstat(fe->path, &s);
  if (sc < 0) {
    fprintf(stderr, "lstat: %s\n", strerror(errno));
    goto done;
  }

  if (S_ISDIR(s.st_mode)) {
    rc = insert_dir(fe->path);
    goto done;
  }

  if (cfg.verbose) 
    printf("%s\n", fe->path);

  len = strlen(fe->path);
 
  sc = match_regex(fe->path, len);
  if (sc < 0) goto done;

  nr = sc ? shr_write(cfg.ring, fe->path, len+1) : 0;
  if (nr < 0) {
    fprintf(stderr, "shr_write: %zd\n", nr);
    goto done;
  }

  rc = 0;

 done:
  if (fe) free(fe);
  if (rc < 0) return rc;
  return cfg.fentries ? 1 : 0;
}

int compile_regex(void) {
  int rc = -1, off;
  const char *err;

  if (cfg.regex == NULL) {
    rc = 0;
    goto done;
  }

  cfg.re = pcre_compile(cfg.regex, 0, &err, &off, NULL);
  if (cfg.re == NULL) {
    fprintf(stderr, "error in regex %s: %s (offset %u)\n",
      cfg.regex, err, off);
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  int opt, rc=-1, sc, shr_mode;
  struct fe *fe, *fe_tmp;
  struct epoll_event ev;
  cfg.prog = argv[0];
  char *dir=NULL;
  size_t n;

  while ( (opt = getopt(argc,argv,"vr:d:hm:")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'r': cfg.ring_name = strdup(optarg); break;
      case 'd': dir = strdup(optarg); break;
      case 'm': cfg.regex = strdup(optarg); break;
      case 'h': default: usage(); break;
    }
  }

  if (cfg.ring_name == NULL) usage();
  if (dir == NULL) usage();
  if (compile_regex() < 0) goto done;

  /* form absolute realpath of dir */
  if (realpath(dir, cfg.dir) == NULL) {
    fprintf(stderr, "realpath %s: %s\n", dir, strerror(errno));
    goto done;
  }

  /* open the ring */
  shr_mode = (SHR_WRONLY|SHR_BUFFERED);
  cfg.ring = shr_open(cfg.ring_name, shr_mode);
  if (cfg.ring == NULL) goto done;

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
  sc = shr_ctl(cfg.ring, SHR_POLLFD, cfg.fatal_signal_fd);
  if (sc < 0) {
    fprintf(stderr,"shr_ctl: error\n");
    goto done;
  }

  /* set up the epoll instance */
  cfg.epoll_fd = epoll_create(1); 
  if (cfg.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  /* add descriptors of interest to epoll */
  if (add_epoll(EPOLLIN, cfg.signal_fd)) goto done;

  /* set initial directory on work list */
  fe = make_fentry(cfg.dir);
  if (fe == NULL) goto done;
  DL_APPEND(cfg.fentries, fe);

  alarm(1);

  while (1) {
    sc = epoll_wait(cfg.epoll_fd, &ev, 1, 0);
    if (sc < 0) { 
      fprintf(stderr, "epoll: %s\n", strerror(errno));
      goto done;
    }

    if (sc == 0)                          { if (keep_walking() <= 0) goto done;}
    else if (ev.data.fd == cfg.signal_fd) { if (handle_signal() < 0) goto done;}
    else                                  { assert(0); goto done;}
  }
  
  rc = 0;
 
 done:
  DL_FOREACH_SAFE(cfg.fentries, fe, fe_tmp) free(fe);
  if (dir) free(dir);
  if (cfg.regex) free(cfg.regex);
  if (cfg.re) pcre_free(cfg.re);
  if (cfg.ring_name) free(cfg.ring_name);
  if (cfg.ring) shr_close(cfg.ring);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.fatal_signal_fd != -1) close(cfg.fatal_signal_fd);
  if (cfg.epoll_fd  != -1) close(cfg.epoll_fd);
  return 0;
}
