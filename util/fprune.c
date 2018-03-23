#include <sys/signalfd.h>
#include <sys/statvfs.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mman.h>
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
#include "libut.h"
#include "shr.h"


/* 
 * fprune: directory pruning daemon
 *
 * special purpose daemon to keep a filesystem
 * under a given percent full by attrition of old files
 *
 * notification of files (pre-existing or incoming during
 * runtime) in the monitored filesystem is via ring buffer
 * from a compatible application (including this program
 * in walk mode, or ffcp, or shr-tool). this program keeps
 * the directory under the given percent full, by unlinking
 * old files _that it knows about_ in the filesystem.
 *
 * the idea is that at startup, this program is run with
 * a second instance of itself, in walk mode, to post the
 * initial directory contents to the ring. thereafter and
 * concurrently, programs that generate new files in the
 * monitored filesystem post these file names to the ring.
 *
 * explicitly avoids use of inotify and its limitations
 */

#define FPRUNE_PATH_MAX 100
struct fs_ent {
  time_t mtime;
  char path[FPRUNE_PATH_MAX];
  UT_hash_handle hh;
  /* free list runs through these */
  struct fs_ent *next;
  struct fs_ent *prev;
};

#define BATCH_FRAMES 10000
#define BATCH_MB     10
#define BATCH_BYTES  (BATCH_MB * 1024 * 1024)
char read_buffer[BATCH_BYTES];
struct iovec read_iov[BATCH_FRAMES];

char dir[PATH_MAX];
char tmp[PATH_MAX];

struct {
  char *prog;
  int verbose;
  int walk;         /* walk (tree scan) mode */
  int fork_walker;  /* walk mode in sub process */
  int walk_prune;   /* prune empty dirs in walk */
  int unsorted;     /* whether to mtime-sort files */
  size_t count;     /* count of files read on ring */
  int pct;          /* percent to prune at */
  int epoll_fd;     /* epoll descriptor */
  int signal_fd;    /* to receive signals */
  int ring_fd;      /* ring readability fd */
  char *ring_name;  /* ring file name */
  struct shr *ring; /* open ring handle */
  char *buf;        /* buf for shr_readv */
  struct iovec *iov;/* iov for shr_readv */
  size_t niov;      /* number iov ready */
  struct statvfs vfs;
  char *dir;        /* tree to prune (realpath) */
  char *tmp;        /* temp in add and unlink_path */
  char *table_file;
  int table_fd;
  size_t tb;
  size_t table_sz;
  size_t table_slots;
  size_t nfile_per_tb;
  struct fs_ent *table;   /* all fs_ent */
  struct fs_ent *fe_tree; /* hash table in-use fs_ent */
  struct fs_ent *fe_free; /* DL of free fs_ent */
} cfg = {
  .dir = dir,
  .tmp = tmp,
  .buf = read_buffer,
  .iov = read_iov,
  .epoll_fd = -1,
  .signal_fd = -1,
  .ring_fd = -1,
  .table_file = "files.map",
  .table_fd = -1,
};

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage() {
  fprintf(stderr,"directory pruning daemon\n"
                 "\n"
                 "This tool continuously attritions files in a filesystem.\n"
                 "It keeps utilization under x%% full, given as -p <pct>.\n"
                 "It deletes files by age and removes empty subdirectories.\n"
                 "\n"
                 "Instead of directly monitoring the filesystem, this\n"
                 "daemon cooperates with other compatible applications\n"
                 "(e.g. ffcp) to get notified of files via ring buffer.\n"
                 "Typically the initial filesystem contents are posted\n"
                 "to the ring buffer by running a separate instance of\n"
                 "this program in -w (walk) mode; -W forks it implicitly.\n"
                 "Tools (e.g. ffcp) that put files into the filesystem post\n"
                 "their names to the ring buffer. This tool sorts them by age\n"
                 "(or simply by ring arrival order in -u mode) and unlinks\n"
                 "the oldest files as the filesystems utilization exceeds\n"
                 "the set value. Additionally, a maximum number of files\n"
                 "kept is the product of -t <tb> and -N <nfiles-per-tb>.\n"
                 "\n");
  fprintf(stderr,"usage: %s [options] -p <percent> -r <ring> -d <dir>\n", cfg.prog);
  fprintf(stderr,"\n");
  fprintf(stderr,"options:\n"
                 "   -d <directory      [directory to prune; required]\n"
                 "   -p <percent>       [percent full to prune directory]\n"
                 "   -r <ring-file>     [ring name for incoming files]\n"
                 "   -b <file-table>    [file name for state table]\n"
                 "   -t <tb>            [assume <tb> terabyte filesystem]\n"
                 "   -N <nfiles-per-tb> [assume <n> files per terabyte]\n"
                 "   -v                 [verbose; repeatable]\n"
                 "   -u                 [skip stat/sort; use ring order]\n"
                 "   -w                 [walk mode; walk tree rooted at dir]\n"
                 "   -W                 [fork subprocess in walk mode]\n"
                 "   -P                 [in walk mode, prune empty dirs]\n"
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

/*
 * keep_parent
 *
 * determine if parent directory (name/..) should
 * be kept based on whether it holds other files.
 * ppath must be a caller buffer of size PATH_MAX.
 * it gets populated by this function with parent
 * path.
 *
 * returns:
 *   0 (unlink parent)
 *   1 (keep parent)
 * < 0 error
 */
int keep_parent(const char *name, char *ppath) {
  struct dirent *dent;
  char dir[PATH_MAX], *dp;
  int rc = -1, i=0;
  DIR *d = NULL;
  size_t l, dl;

  l = strlen(name);
  if (l+1 > PATH_MAX) {
    fprintf(stderr, "path too long: %s\n", name);
    goto done;
  }

  /* dirname is destructive, use copy */
  memcpy(dir, name, l+1);
  dp = dirname(dir);
  assert(dp);

  /* copy realpath back to caller */
  if (realpath(dp, ppath) == NULL) {
    fprintf(stderr, "realpath %s: %s\n", dp, strerror(errno));
    goto done;
  }

  /* limit upward empty directory removal to halt at cfg.dir.
   * strcmp ok; both args are canonicalized to realpath */
  if (!strcmp(ppath, cfg.dir)) {
    rc = 0;    /* parent is cfg.dir */
    i = 1;     /* always keep cfg.dir */
    goto done;
  }

  /* if we're here, count entries in parent; keep if non zero */
  d = opendir(ppath);
  if (d == NULL) {
    fprintf(stderr, "opendir %s: %s\n", ppath, strerror(errno));
    goto done;
  }

  while ( (dent = readdir(d)) != NULL) {
    if (!strcmp(dent->d_name, ".")) continue;
    if (!strcmp(dent->d_name, "..")) continue;
    i++;
  }

  rc = 0;

 done:
  if (d) closedir(d);
  return rc ? -1 : i;
}

int unlink_path(const char *name, int is_dir) {
  char ppath[PATH_MAX];
  int rc = -1, ec;

  if (cfg.verbose)
    fprintf(stderr, "unlink: %s\n", name);

  ec = is_dir ? rmdir(name) : 
                unlink(name);
  /* skip and continue on unlink errors. either we have
   * a record of file that no longer exists, or we lack
   * permission, or it's not a regular file, etc. */
  if (ec < 0) {
    if (errno != ENOENT)
      fprintf(stderr, "unlink %s: %s\n", name, strerror(errno));
    rc = 0;
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

/*
 * maintain
 *
 * enforce filesystem utilization limit
 *
 */
int maintain(void) {
  struct fs_ent *fe;
  int rc = -1, sc;
  unsigned int used_blocks_pct;
  fsblkcnt_t   used_blocks, blocks;

  unsigned long used_slots;
  unsigned int used_slots_pct;

  do {

    sc = statvfs(cfg.dir, &cfg.vfs);
    if (sc < 0) {
      fprintf(stderr, "statvfs: %s\n", strerror(errno));
      goto done;
    }

    blocks = cfg.vfs.f_blocks;
    assert(blocks > 0);
    used_blocks = blocks - cfg.vfs.f_bfree;
    used_blocks_pct = used_blocks * 100.0 / blocks;

    used_slots = HASH_COUNT(cfg.fe_tree);
    used_slots_pct = used_slots * 100.0 / cfg.table_slots;

    if (cfg.verbose) {
      printf("blocks: %zu used: %zu (%u%% full)\n", 
        blocks, used_blocks, used_blocks_pct);
      printf("table: %zu files (%u%% slots)\n", 
        used_slots, used_slots_pct);
    }

    if (used_blocks_pct > cfg.pct) {

      fe = cfg.fe_tree;
      if (fe == NULL) {
        fprintf(stderr, "fs oversize but no files in table yet\n");
        break;
      }

      sc = unlink_path(fe->path,0);
      if (sc < 0) goto done;

      HASH_DEL(cfg.fe_tree, fe);
      DL_APPEND(cfg.fe_free, fe);
    }

  } while (used_blocks_pct > cfg.pct);

  rc = 0;

 done:
  return rc;
}

/*
 * is_mountpoint
 *
 * test if file is a mountpoint
 *
 * returns:
 *   -1 error
 *    0 no
 *    1 yes
 */
int is_mountpoint(char *file) {
  char parent[PATH_MAX];
  int rc = -1, sc;
  struct stat f, p;

  sc = stat(file, &f);
  if (sc < 0) {
    fprintf(stderr,"stat: %s\n", strerror(errno));
    goto done;
  }

  if (strlen(file) + 4 > PATH_MAX) {
    fprintf(stderr, "path too long\n");
    goto done;
  }

  snprintf(parent, PATH_MAX, "%s/..", file);
  sc = stat(parent, &p);
  if (sc < 0) {
    fprintf(stderr,"stat: %s\n", strerror(errno));
    goto done;
  }

  rc = (f.st_dev == p.st_dev) ? 0 : 1;

 done:
  return rc;
}

int age_sort(void *_a, void *_b) {
  struct fs_ent *a = (struct fs_ent*)_a;
  struct fs_ent *b = (struct fs_ent*)_b;
  return a->mtime - b->mtime;
}

int add(char *file) {
  struct fs_ent *fe;
  int rc = -1, sc;
  size_t l, d, sz;
  struct stat s;
  time_t mtime;

  if (cfg.verbose) printf("-> %s\n", file);

  /* canonicalize to an absolute path. */
  if (realpath(file, cfg.tmp) == NULL) {
    fprintf(stderr, "realpath %s: %s\n", file, strerror(errno));
    if (errno == ENOENT) rc = 0; /* skip missing file; continue on */
    goto done;
  }

  /* verify that file is under the directory tree we monitor */
  d = strlen(cfg.dir);
  if ((memcmp(cfg.dir, cfg.tmp, d)) || (cfg.tmp[d] != '/')) {
    fprintf(stderr, "file %s not in directory %s\n", cfg.tmp, cfg.dir);
    goto done;
  }

  l = strlen(cfg.tmp);
  if (l+1 > FPRUNE_PATH_MAX) {
    fprintf(stderr, "path too long: %s\n", cfg.tmp);
    goto done;
  }

  sc = cfg.unsorted ? 0 : stat(cfg.tmp, &s);
  if (sc < 0) {
    fprintf(stderr, "stat: %s: %s\n", cfg.tmp, strerror(errno));
    goto done;
  }

  mtime = cfg.unsorted ? (time_t)cfg.count : s.st_mtim.tv_sec;
  cfg.count++;

  /* is item already in hash table? */
  HASH_FIND_STR(cfg.fe_tree, cfg.tmp, fe);
  if (fe) {
    fe->mtime = mtime;
    rc = 0;
    goto done;
  }

  /* take an item from free list, or recycle oldest */
  assert(fe == NULL);
  if (cfg.fe_free) {
    fe = cfg.fe_free;
    DL_DELETE(cfg.fe_free, fe);
  } else {
    assert(cfg.fe_tree);
    fe = cfg.fe_tree;
    sc = unlink_path(fe->path,0);
    if (sc < 0) goto done;
    HASH_DEL(cfg.fe_tree, fe);
  }

  assert(fe);
  memcpy(fe->path, cfg.tmp, l+1);
  fe->mtime = mtime;
  if (cfg.unsorted) {
    HASH_ADD(hh, cfg.fe_tree, path, l, fe);
  } else {
    HASH_ADD_INORDER(hh, cfg.fe_tree, path, l, fe, age_sort);
  }

  rc = 0;

 done:
  return rc;
}

/*
 * handle_ring
 *
 * receive filenames via ring
 */
int handle_ring(void) {
  char *file, tmp[PATH_MAX];
  struct iovec *iov;
  int rc = -1, sc;
  ssize_t nr;
  size_t n, len;

  cfg.niov = BATCH_FRAMES;
  nr = shr_readv(cfg.ring, cfg.buf, BATCH_BYTES, cfg.iov, &cfg.niov);
  if (nr <  0) {
    fprintf(stderr, "shr_readv: error %zd\n", nr);
    goto done;
  }

  if (nr == 0) cfg.niov = 0;

  for(n=0; n < cfg.niov; n++) {
    iov = &cfg.iov[n];
    file = (char*)(iov->iov_base);
    len = iov->iov_len;
    if (file[len-1] != '\0') {
      if (len+1 > FPRUNE_PATH_MAX) {
        fprintf(stderr,"path too long\n");
        continue;
      }
      memcpy(tmp, file, len);
      tmp[len] = '\0';
      file = tmp;
    }
    sc = add(file);
    if (sc < 0) goto done;
  }

  sc = maintain();
  if (sc < 0) goto done;

  rc = 0;

 done:
  return rc;
}

#define BYTES_PER_TB (1024UL * 1024UL * 1024UL * 1024UL)
#define BYTES_PER_GB (1024UL * 1024UL * 1024UL)
int open_table(void) {
  int rc = -1, sc;

  assert(cfg.vfs.f_frsize > 0);

  if (cfg.tb == 0) {
    cfg.tb = cfg.vfs.f_frsize *
             cfg.vfs.f_blocks /
             BYTES_PER_TB;
    if (cfg.tb == 0) cfg.tb = 1;
  }

  if (cfg.nfile_per_tb == 0) {
    cfg.nfile_per_tb = 10 * 1024 * 1024;
  }

  cfg.table_slots = cfg.nfile_per_tb * cfg.tb;
  cfg.table_sz = sizeof(struct fs_ent) * 
                 cfg.table_slots;

  printf("%s: %zu slots (%zu GB)\n", cfg.table_file, 
       cfg.table_slots, cfg.table_sz / BYTES_PER_GB);


  cfg.table_fd = open(cfg.table_file, O_RDWR|O_TRUNC|O_CREAT, 0644);
  if (cfg.table_fd < 0) {
    fprintf(stderr, "open: %s\n", strerror(errno));
    goto done;
  }

  sc = ftruncate(cfg.table_fd, cfg.table_sz);
  if (sc < 0) {
    fprintf(stderr, "ftruncate: %s\n", strerror(errno));
    goto done;
  }

  cfg.table = mmap(NULL, cfg.table_sz, PROT_READ|PROT_WRITE, 
                   MAP_SHARED, cfg.table_fd, 0);
  if (cfg.table == MAP_FAILED) {
    fprintf(stderr, "mmap: %s\n", strerror(errno));
    cfg.table = NULL;
    goto done;
  }

  rc = 0;

 done:
  return rc;
}


int fstrcmp(const void *_a, const void *_b) {
	char *a = *(char **)_a;
	char *b = *(char **)_b;
  return strcmp(a,b);
}

/* add directory to tree, recursively. 
 * recursion depth bounded by fs depth
 *
 * returns
 *   < 0 on error
 *   >= 0 the number of files+directories in dir
 */
int walk_tree(char *dir) {
  int rc = -1, sc, n=0, f;
  char path[PATH_MAX];
  struct dirent *dent;
  struct stat s;
  size_t l, el;
  ssize_t nr;
  DIR *d = NULL;

  size_t num_slots=0, num_used=0, num_wanted, slotn;
  char **slots=NULL, **stmp, *dname;

  l = strlen(dir);
  d = opendir(dir);
  if (d == NULL) {
    fprintf(stderr, "opendir %s: %s\n", dir, strerror(errno));
    goto done;
  }

  /* accumulate directory entries into temp array to sort */
  while ( (dent = readdir(d)) != NULL) {
    /* skip the . and .. directories */
    if (!strcmp(dent->d_name, "."))  continue;
    if (!strcmp(dent->d_name, "..")) continue;
    if (num_slots - num_used == 0) {
      num_wanted = num_slots ? (num_slots * 2) : 100;
      stmp = realloc( slots, num_wanted * sizeof(char*));
      if (stmp == NULL) {
        fprintf(stderr, "out of memory\n");
        goto done;
      }
      slots = stmp;
      num_slots = num_wanted;
    }
    assert(num_slots > num_used);
    slots[num_used] = strdup(dent->d_name);
    if (slots[num_used] == NULL) {
      fprintf(stderr, "out of memory\n");
      goto done;
    }
    num_used++;
  }

  /* this is the heart of the sorted directory listing */
  qsort(slots, num_used, sizeof(char*), fstrcmp);

  /* iterate over sorted array */
  for(slotn = 0; slotn < num_used; slotn++) {

    dname = slots[ slotn ];

    /* formulate path to dir entry */
    el = strlen(dname);
    if (l+1+el+1 > PATH_MAX) {
      fprintf(stderr, "path too long: %s/%s\n", dir, dname);
      goto done;
    }
    memcpy(path, dir, l);
    path[l] = '/';
    memcpy(&path[l+1], dname, el+1);

    /* lstat to determine its type */
    sc = lstat(path, &s);
    if (sc < 0) {
      fprintf(stderr, "lstat %s: %s\n", path, strerror(errno));
      goto done;
    }

    if (S_ISDIR(s.st_mode))  { /* dir? recurse. if empty, prune. */
      f = walk_tree(path);
      if (f < 0) goto done;
      if (f == 0) {
        sc = cfg.walk_prune ? rmdir(path) : 0;
        if (sc < 0) {
          fprintf(stderr, "rmdir: %s\n", strerror(errno));
          goto done;
        }
      }
      if (f > 0) n++;
    } else if (S_ISREG(s.st_mode)) { /* regular file */
      if (cfg.verbose) printf("%s\n", path);
      nr = shr_write(cfg.ring, path, l+1+el+1);
      if (nr < 0) {
        fprintf(stderr, "shr_write: %zd\n", nr);
        goto done;
      }
      n++;
    } else {  /* a special file; ignore it- don't touch */
      fprintf(stderr, "special file: %s\n", path);
      n++;  /* prevent pruning of its parent */
    }
  }

  rc = 0;

 done:
  if (slots) {
    for(slotn=0; slotn < num_used; slotn++) free( slots[slotn] );
    free(slots);
  }
  if (d) closedir(d);
  return rc ? rc : n;
}


int main(int argc, char *argv[]) {
  int opt, rc=-1, sc, shr_mode;
  struct epoll_event ev;
  cfg.prog = argv[0];
  char *dir=NULL;
  size_t n;

  while ( (opt = getopt(argc,argv,"vwPr:p:d:hb:N:t:uW")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'r': cfg.ring_name = strdup(optarg); break;
      case 'p': cfg.pct = atoi(optarg); break;
      case 'd': dir = strdup(optarg); break;
      case 'b': cfg.table_file = strdup(optarg); break;
      case 't': cfg.tb = atoi(optarg); break;
      case 'N': cfg.nfile_per_tb = atoi(optarg); break;
      case 'w': cfg.walk = 1; break;
      case 'W': cfg.fork_walker = 1; break;
      case 'u': cfg.unsorted = 1; break;
      case 'P': cfg.walk_prune = 1; break;
      case 'h': default: usage(); break;
    }
  }

  if ((cfg.pct == 0) && (cfg.walk == 0)) usage();
  if (cfg.ring_name == NULL) usage();
  if (dir == NULL) usage();

  /* form absolute realpath of dir to monitor */
  if (realpath(dir, cfg.dir) == NULL) {
    fprintf(stderr, "realpath %s: %s\n", dir, strerror(errno));
    goto done;
  }

  if (is_mountpoint(cfg.dir) <= 0) {
    fprintf(stderr, "not mountpoint: %s\n", cfg.dir);
    goto done;
  }

  if (cfg.fork_walker) {
    pid_t pid = fork();
    if (pid < 0) {
      fprintf(stderr, "fork: %s\n", strerror(errno));
      goto done;
    }
    if (pid == 0) { /* child */
      cfg.walk = 1;
      cfg.walk_prune = 1;
      if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0) {
        fprintf(stderr, "prctl: %s\n", strerror(errno));
        goto done;
      }
    }
    /* child and parent continue */
  }

  /* open the ring */
  shr_mode = cfg.walk ? (SHR_WRONLY|SHR_BUFFERED) : 
                        (SHR_RDONLY|SHR_NONBLOCK);
  cfg.ring = shr_open(cfg.ring_name, shr_mode);
  if (cfg.ring == NULL) goto done;

  if (cfg.walk) {
    rc = walk_tree(cfg.dir);
    goto done;
  }

  sc = statvfs(cfg.dir, &cfg.vfs);
  if (sc < 0) {
    fprintf(stderr, "statvfs: %s\n", strerror(errno));
    goto done;
  }

  if (open_table() < 0) goto done;

  /* put all table slots on free list */
  for(n=0; n < cfg.table_slots; n++) {
    DL_APPEND(cfg.fe_free, &cfg.table[n]);
  }

  /* get the descriptor */
  cfg.ring_fd = shr_get_selectable_fd(cfg.ring);
  if (cfg.ring_fd < 0) goto done;

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
  if (add_epoll(EPOLLIN, cfg.ring_fd)) goto done;

  alarm(1);

  while (1) {
    sc = epoll_wait(cfg.epoll_fd, &ev, 1, -1);
    if (sc < 0) { 
      fprintf(stderr, "epoll: %s\n", strerror(errno));
      goto done;
    }

    if (sc == 0)                          { assert(0); goto done;}
    else if (ev.data.fd == cfg.signal_fd) { if (handle_signal() < 0) goto done;}
    else if (ev.data.fd == cfg.ring_fd)   { if (handle_ring()   < 0) goto done;}
    else                                  { assert(0); goto done;}
  }
  
  rc = 0;
 
 done:
  if (dir) free(dir);
  HASH_CLEAR(hh, cfg.fe_tree);
  if (cfg.ring_name) free(cfg.ring_name);
  if (cfg.ring) shr_close(cfg.ring);
  if (cfg.table) munmap(cfg.table, cfg.table_sz);
  if (cfg.table_fd  != -1) close(cfg.table_fd);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd  != -1) close(cfg.epoll_fd);
  return 0;
}
