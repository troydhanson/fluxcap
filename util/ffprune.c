#include <sys/signalfd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/vfs.h>
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
#include "libut.h"
#include "shr.h"


/* 
 * fluxcap directory prune daemon
 *
 * scans a directory tree at startup, calculating size
 * thereafter deletes files (oldest) to keep directory 
 * size below the configured size. notification of new
 * files arriving in the directory hierarchy is via ring
 * buffer where the incoming file names are posted by
 * the application that writes them. this avoids all 
 * use of inotify.
 */

#define BATCH_FRAMES 10000
#define BATCH_MB     10
#define BATCH_BYTES  (BATCH_MB * 1024 * 1024)
char read_buffer[BATCH_BYTES];
struct iovec read_iov[BATCH_FRAMES];

#define FF_PATH_MAX 256
/* one of these for every node in the directory tree */
struct node {
  char name[FF_PATH_MAX];
  time_t mtime;
  off_t sz;
  struct node *fprev, *fnext; /* linked list of free nodes */
  UT_hash_handle hh;
};

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
  size_t sz;        /* byte size to prune to */
  char dir[PATH_MAX]; /* tree to prune (realpath) */
  char cur[PATH_MAX]; /* current file when ring */
  char tmp[PATH_MAX]; /* used in add and unlink_path */
  size_t tree_max_M; /* max nodes in tree, in millions */
  struct node *all_nodes;  /* malloc allocation of nodes */
  struct node *free_nodes; /* linked list of free nodes */
  struct node *tree_nodes; /* hash table of in-use nodes */
} cfg = {
  .buf = read_buffer,
  .iov = read_iov,
  .epoll_fd = -1,
  .signal_fd = -1,
  .ring_fd = -1,
  .tree_max_M = 1,
};

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage() {
  fprintf(stderr,"fluxcap directory pruning daemon\n"
                 "\n"
                 "This tool continuously attritions files in the directory\n"
                 "hierarchy specified, to maintain a total size under the\n"
                 "size specified in the -s argument. It attritions files,\n"
                 "by age, and prunes directories that it empties in doing so.\n"
                 "\n"
                 "An initial scan of the directory is done at start up time.\n"
                 "Thereafter, this daemon must be told about files placed into\n"
                 "the directory, from a compatible application (e.g. ffcp)\n"
                 "that writes the filenames into the ring buffer specified.\n"
                 "\n"
                 "If the ring buffer is not passed in, then this tool does\n"
                 "a single round of pruning and exits.\n"
                 "\n"
                 "An estimate of the maxinum number of files that may occupy\n"
                 "the directory hierarchy, rounded up to the nearest million,\n"
                 "is given to the -M argument (e.g. 1 = 1M files). This number\n"
                 "determines the size of the internal file tracking table.\n"
                 "\n");
  fprintf(stderr,"usage: %s -s <size> [options] <directory>\n\n", cfg.prog);
  fprintf(stderr,"options:\n"
                 "   -s <max-size>      [size to prune to, units k/m/g/t/%]\n"
                 "   -i <input-ring>    [ring of filenames incoming to tree]\n"
                 "   -M                 [max files, in millions; default: 1M]\n"
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

/* scan the struct nodes in active use, and 
 * calculate what attrition is needed to honor cfg.sz
 */
int do_attrition(void) {
  size_t tree_sz = 0, tree_count = 0;
  struct node *n, *tmp;
  int rc = -1;

  HASH_ITER(hh, cfg.tree_nodes, n, tmp) {
    tree_sz += n->sz;
    tree_count++;
  }

  if (cfg.verbose) {
    fprintf(stderr, "tree:\n");
    fprintf(stderr, " %ld items\n", (long)tree_count);
    fprintf(stderr, " %ld bytes\n", (long)tree_sz);
  }

  if (tree_sz < cfg.sz) {  /* sufficient free space? */
    rc = 0;
    goto done;
  }

  /* need to liberate space. sort by age and unlink */
  HASH_SORT(cfg.tree_nodes, mtime_sort);
  while(tree_sz > cfg.sz) {
    n = cfg.tree_nodes;
    assert(n && (tree_sz >= n->sz));
    if (unlink_path(n->name, 0) < 0) goto done;
    tree_sz -= n->sz;
    HASH_DEL(cfg.tree_nodes, n);   /* take structure off active hash */
    DL_APPEND2(cfg.free_nodes, n, fprev, fnext); /* put on free list */
  }

  rc = 0;

 done:
  return rc;
}

/* work we do at 1hz  */
int periodic_work(void) {
  int rc = -1;

  if (do_attrition() < 0) goto done;

  /* one-shot mode? induce program exit */
  if (cfg.input_ring == NULL) goto done;

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

/* lookup the size of the filesystem underlying cfg.dir and 
 * calculate pct% of that size */
long get_fs_pct(int pct) {
  assert(pct > 0 && pct < 100);
  struct statfs fb;

  if (statfs(cfg.dir, &fb) == -1) {
    fprintf(stderr,"statfs %s: %s\n", cfg.dir, strerror(errno));
    return -1;
  }

  long fsz = fb.f_bsize * fb.f_blocks; /* filesystem size */
  long cap = (fsz*pct) * 0.01;
  return cap;
}

/* convert something like "20%" or "20m" to bytes.
 * percentage means 'percent of filesystem size' */
int parse_sz(char *sz) {
  int rc = -1, l;
  char unit;
  long n;

  if (sscanf(sz, "%ld", &n) != 1) { /* e.g. 20 from "20m" */
    fprintf(stderr, "missing numeric size in %s\n", sz);
    goto done; 
  }
  l = strlen(sz);
  unit = sz[l-1];
  if (unit >= '0' && unit <= '9') { /* no unit suffix */ }
  else {
    switch(unit) {
      case '%': n = get_fs_pct(n); break;
      case 'T': case 't': n *= 1024; /* fall through */
      case 'G': case 'g': n *= 1024; /* fall through */
      case 'M': case 'm': n *= 1024; /* fall through */
      case 'K': case 'k': n *= 1024; break;
      default: 
        fprintf(stderr, "unknown unit in %s\n", sz);
        goto done;
        break;
    }
  }

  cfg.sz = n;
  rc = 0;

 done:
  return rc;
}

int keep_parent(char *name, char *ppath) {
  char tmp[FF_PATH_MAX], *p;
  struct dirent *dent;
  int rc = -1, i=0;
  DIR *d = NULL;
  size_t l, rl;

  l = strlen(name);
  if (l+1 > FF_PATH_MAX) {
    fprintf(stderr, "path too long: %s\n", name);
    goto done;
  }

  /* get dirname; it's destructive so use copy */
  memcpy(tmp, name, l+1);
  p = dirname(tmp);

  /* canonicalize to an absolute path */
  if (realpath(p, cfg.tmp) == NULL) {
    fprintf(stderr, "realpath %s: %s\n", p, strerror(errno));
    goto done;
  }

  /* store back into caller buffer */
  rl = strlen(cfg.tmp);
  if (rl+1 > FF_PATH_MAX) {
    fprintf(stderr, "path too long: %s\n", cfg.tmp);
    goto done;
  }
  memcpy(ppath, cfg.tmp, rl+1);

  /* limit upward empty directory removal to halt at cfg.dir.
   * strcmp ok; both args are canonicalized to realpath */
  if (!strcmp(cfg.tmp, cfg.dir)) {
    rc = 0;    /* parent is cfg.dir */
    i = 1;     /* always keep cfg.dir */
    goto done;
  }

  /* if we're here, count entries in parent; keep if non zero */
  d = opendir(cfg.tmp);
  if (d == NULL) {
    fprintf(stderr, "opendir %s: %s\n", cfg.tmp, strerror(errno));
    goto done;
  }

  while ( (dent = readdir(d)) != NULL) {
    if ((dent->d_type == DT_DIR) && (!strcmp(dent->d_name, ".")))  continue;
    if ((dent->d_type == DT_DIR) && (!strcmp(dent->d_name, ".."))) continue;
    i++;
  }

  rc = 0;

 done:
  if (d) closedir(d);
  return rc ? -1 : i;
}

int unlink_path(char *name, int is_dir) {
  char ppath[FF_PATH_MAX];
  int rc = -1, ec;

  if (cfg.verbose) fprintf(stderr, "unlinking %s\n", name);

  ec = is_dir ? rmdir(name) : unlink(name);
  if (ec < 0) {
    fprintf(stderr, "unlink: %s: %s\n", name, strerror(errno));
    goto done;
  }

  /* attrition empty parent directories, up to cfg.dir */
  ec = keep_parent(name, ppath);
  if (ec < 0) goto done;
  else if (ec > 0) { /* keep */ }
  else if (unlink_path(ppath, 1) < 0) goto done;

  rc = 0;

 done:
  return rc;
}

int mtime_sort(struct node *a, struct node *b) {
  if (a->mtime < b->mtime) return -1;
  if (a->mtime > b->mtime) return  1;
  return 0;
}

int add(char *file) {
  int rc = -1, ec;
  struct node *n;
  struct stat s;
  size_t l, d;

  /* canonicalize to an absolute path. only abs paths in hash */
  if (realpath(file, cfg.tmp) == NULL) {
    fprintf(stderr, "realpath %s: %s\n", file, strerror(errno));
    goto done;
  }

  /* verify that file is under the directory tree we monitor */
  d = strlen(cfg.dir);
  if ((memcmp(cfg.dir, cfg.tmp, d)) || (cfg.tmp[d] != '/')) {
    fprintf(stderr, "file %s not in directory %s\n", cfg.tmp, cfg.dir);
    goto done;
  }

  l = strlen(cfg.tmp);
  if (l+1 > FF_PATH_MAX) {
    fprintf(stderr, "path too long: %s\n", cfg.tmp);
    goto done;
  }

  ec = stat(cfg.tmp, &s);
  if (ec < 0) {
    fprintf(stderr, "stat: %s: %s\n", cfg.tmp, strerror(errno));
    goto done;
  }

  if (S_ISREG(s.st_mode) == 0) {
    fprintf(stderr, "not a regular file: %s\n", cfg.tmp);
    goto done;
  }

  /* if file is known already, update; otherwise create record */
  HASH_FIND_STR(cfg.tree_nodes, cfg.tmp, n);
  if (n == NULL) {

    if (cfg.free_nodes == NULL) {
      fprintf(stderr, "nodes exhausted, increase -M\n");
      goto done;
    }

    /* claim a free node. remove it from the free list */
    n = cfg.free_nodes;
    DL_DELETE2(cfg.free_nodes, n, fprev, fnext);
    memcpy(n->name, cfg.tmp, l+1);
    HASH_ADD_STR(cfg.tree_nodes, name, n);
  }

  /* update fields for nodes */
  n->mtime = s.st_mtim.tv_sec;
  n->sz = s.st_size;

  rc = 0;

 done:
  return rc;
}

/* add directory to tree , causing recursive addition of
 * directories and files inside it. */
int add_dir(char *dir) {
  char path[FF_PATH_MAX];
  struct dirent *dent;
  int rc = -1, ec;
  struct stat s;
  size_t l, el;
  DIR *d = NULL;

  l = strlen(dir);

  d = opendir(dir);
  if (d == NULL) {
    fprintf(stderr, "opendir %s: %s\n", dir, strerror(errno));
    goto done;
  }

  /* iterate over directory contents. use stat to distinguish regular files
   * from directories (etc). stat is more robust than using dent->d_type */
  while ( (dent = readdir(d)) != NULL) {

    /* skip the . and .. directories */
    if (!strcmp(dent->d_name, "."))  continue;
    if (!strcmp(dent->d_name, "..")) continue;

    /* formulate path to dir entry */
    el = strlen(dent->d_name);
    if (l+1+el+1 > FF_PATH_MAX) {
      fprintf(stderr, "path too long: %s/%s\n", dir, dent->d_name);
      goto done;
    }
    memcpy(path, dir, l);
    path[l] = '/';
    memcpy(&path[l+1], dent->d_name, el+1);

    /* lstat to determine its type */
    ec = lstat(path, &s);
    if (ec < 0) {
      fprintf(stderr, "lstat %s: %s\n", path, strerror(errno));
      goto done;
    }

    if (S_ISDIR(s.st_mode))  { if (add_dir(path) < 0) goto done; }
    else if (S_ISREG(s.st_mode)) { if (add(path) < 0) goto done; }
    else fprintf(stderr, "skipping special file: %s\n", path);
  }

  rc = 0;

 done:
  if (d) closedir(d);
  return rc;
}

/* the heart of this program is here. we process one filename */
int process(char *file, size_t len) {
  int rc = -1, ec;

  /* make a nul terminated string */
  if (len+1 > sizeof(cfg.cur)) goto done;
  memcpy(cfg.cur, file, len);
  cfg.cur[len] = '\0';

  ec = add(cfg.cur);
  if (ec < 0) goto done;

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  char unit, *c, *sz=NULL;
  int opt, rc=-1, n, ec;
  struct epoll_event ev;
  cfg.prog = argv[0];
  size_t l;
  off_t i;

  while ( (opt = getopt(argc,argv,"vhi:s:M:")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'i': cfg.input_ring = strdup(optarg); break;
      case 'M': cfg.tree_max_M = atoi(optarg); break;
      case 's': sz = optarg; break;
      case 'h': default: usage(); break;
    }
  }

  /* form canonical realpath of dir to monitor */
  if (optind < argc) {
    l = strlen( argv[optind] );
    if (l+1 > sizeof(cfg.tmp)) {
      fprintf(stderr, "path too long\n");
      goto done;
    }
    memcpy(cfg.tmp, argv[optind], l);
    cfg.tmp[l] = '\0';
    if (realpath(cfg.tmp, cfg.dir) == NULL) {
      fprintf(stderr, "realpath %s: %s\n", cfg.tmp, strerror(errno));
      goto done;
    }
    optind++;
  } else usage();

  if ((sz == NULL) || (parse_sz(sz) < 0)) usage();
  if (cfg.sz == 0) usage();

  size_t tree_sz = cfg.tree_max_M * 1000000 * sizeof(struct node);

  if (cfg.verbose) {
    fprintf(stderr, "tree  : %s\n", cfg.dir);
    fprintf(stderr, "max sz: %lu MB\n", (long)(cfg.sz >> 20));
    fprintf(stderr, "table : %luM nodes\n", cfg.tree_max_M);
    fprintf(stderr, "table : %lu MB\n", (long)(tree_sz >> 20));
  }

  /* allocate all the node slots up front */
  cfg.all_nodes = malloc( tree_sz );
  if (cfg.all_nodes == NULL) {
    fprintf(stderr, "memory request too large; reduce -M\n");
    goto done;
  }

  /* put all the nodes on the free list */
  for(i=0; i < cfg.tree_max_M * 1000000; i++) {
    DL_APPEND2(cfg.free_nodes, &cfg.all_nodes[i], fprev, fnext);
  }
  
  /* add directory root to the tree and initiate scan */
  if (add_dir(cfg.dir) < 0) goto done;
  if (cfg.verbose) fprintf(stderr, "initial scan complete\n");

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

  /* add descriptors of interest to epoll */
  if (add_epoll(EPOLLIN, cfg.signal_fd)) goto done;

  /* open the ring */
  if (cfg.input_ring) {
    cfg.ring = shr_open(cfg.input_ring, SHR_RDONLY|SHR_NONBLOCK);
    if (cfg.ring == NULL) goto done;
    cfg.ring_fd = shr_get_selectable_fd(cfg.ring);
    if (cfg.ring_fd < 0) goto done;
    if (add_epoll(EPOLLIN, cfg.ring_fd)) goto done;
  }

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
  HASH_CLEAR(hh, cfg.tree_nodes);
  if (cfg.all_nodes) free(cfg.all_nodes);
  if (cfg.ring) shr_close(cfg.ring);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.input_ring) free(cfg.input_ring);
  return 0;
}
