#include <sys/signalfd.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/wait.h>
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
#include <sqlite3.h>
#include "libut.h"
#include "shr.h"
#include "tpl.h"


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

/* a pipe fd pair is ordered r=0,w=1 */
#define R 0
#define W 1

/* codes used in comms between parent and worker */
#define OP_INSERT   2
#define OP_PURGE    3
#define OP_ERR_UP   6
#define OP_DEBUG_UP 7
#define OP_SCAN_ADD 8
#define OP_SCAN_END 9

struct {
  char *prog;
  int verbose;
  int epoll_fd;     /* epoll descriptor */
  int signal_fd;    /* to receive signals */
  int ring_fd;      /* ring readability fd */
  char *ring_name;  /* ring file name */
  struct shr *ring; /* open ring handle */
  size_t ring_def_sz; /* ring buffer size if not extant */
  char *buf;        /* buf for shr_readv */
  struct iovec *iov;/* iov for shr_readv */
  size_t max;       /* byte size to prune to */
  char *db_name;    /* db file */
  char dir[PATH_MAX]; /* tree to prune (realpath) */
  char cur[PATH_MAX]; /* current file when reading ring */
  char tmp[PATH_MAX]; /* temp in add and unlink_path */
  int dn_work[2];   /* pipe for parent-to-worker comms */
  int up_work[2];   /* pipe for worker-to-parent comms */
  int dn_scan[2];   /* pipe for parent-to-scanner */
  int up_scan[2];   /* pipe for worker-to-scanner */
  time_t now;
  pid_t worker_pid;
  pid_t scanner_pid;
  struct timespec scanner_pause;
} cfg = {
  .buf = read_buffer,
  .iov = read_iov,
  .epoll_fd = -1,
  .signal_fd = -1,
  .ring_fd = -1,
  .db_name = "fprune.db",
  .dn_work = {-1,-1},
  .up_work = {-1,-1},
  .dn_scan = {-1,-1},
  .up_scan = {-1,-1},
  .scanner_pause = {.tv_nsec= 1000000}, /* 1/1000th second */
  .ring_def_sz = 1024*1024, /* 1mb */
};

int w_report_up(int op, const char *text);
int add(char *file);
int process(char *file, size_t len);

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage() {
  fprintf(stderr,"fluxcap directory pruning daemon\n"
                 "\n"
                 "This tool continuously attritions files in the directory\n"
                 "hierarchy specified, to maintain a total size under the\n"
                 "size specified in the -s argument. It attritions files,\n"
                 "by age, and deletes subdirectories once they are empty.\n"
                 "\n"
                 "Thereafter, this daemon must be told about files coming in\n"
                 "to the directory tree, from a compatible application (e.g.\n"
                 "ffcp) that writes the filenames into the ring buffer.\n"
                 "\n"
                 "A background scan of the directory is done at start up.\n"
                 "This brings the internal state into consistency with the\n"
                 "directory tree. Restart this daemon to induce this re-\n"
                 "scan whenever extraneous changes to the tree are made.\n"
                 "\n"
                 "\n");
  fprintf(stderr,"usage: %s [options] -s <sz> -r <ring> -d <dir>\n", cfg.prog);
  fprintf(stderr,"\n");
  fprintf(stderr,"options:\n"
                 "   -d <directory      [directory to prune; required]\n"
                 "   -s <max-size>      [size to prune to, units k/m/g/t/%%]\n"
                 "   -r <ring-file>     [name of ring of incoming files]\n"
                 "   -b                 [database file; def: fprune.db]\n"
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

/* helper for sql that has no bindings and returns no result */
int w_exec_sql(sqlite3 *db, char *sql) {
  sqlite3_stmt *stmt=NULL;
  int sc, rc = -1;

  sc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
  if( sc!=SQLITE_OK ){
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_step(stmt);
  if(sc != SQLITE_DONE) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_finalize(stmt);
  if (sc != SQLITE_OK) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

/* push purge down upon completion of fs scan */
int push_purge_down(uint64_t scan_start_ts) {
  int rc = -1, op, ec;
  tpl_node *tn=NULL;

  op = OP_PURGE;
  tn = tpl_map("iU", &op, &scan_start_ts);
  if (tn == NULL) goto done;
  tpl_pack(tn, 0);
  ec = tpl_dump(tn, TPL_FD, cfg.dn_work[W]);
  if (ec < 0) {
    fprintf(stderr,"tpl_dump: error %d\n", ec);
    goto done;
  }

  rc = 0;

 done:
  if (tn) tpl_free(tn);
  return rc;
}

/* push addition/update of file down to worker */
int push_update_down(char *name, time_t mtime, size_t sz) {
  uint64_t file_sz, file_mtime, file_stattime;
  int rc = -1, op, ec;
  tpl_node *tn=NULL;

  op = OP_INSERT;
  file_sz = sz;
  file_mtime = mtime;
  file_stattime = cfg.now ? cfg.now : time(NULL);;

  tn = tpl_map("isUUU", &op, &name, &file_sz, &file_mtime, &file_stattime);
  if (tn == NULL) goto done;
  tpl_pack(tn, 0);
  ec = tpl_dump(tn, TPL_FD, cfg.dn_work[W]);
  if (ec < 0) {
    fprintf(stderr,"tpl_dump: error %d\n", ec);
    goto done;
  }

  rc = 0;

 done:
  if (tn) tpl_free(tn);
  return rc;
}

/* work we do at 1hz  */
int periodic_work(void) {
  int rc = -1;

  cfg.now = time(NULL);
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

/* scanner has sent us a message up the pipe */
int handle_scanner(void) {
  tpl_node *tn=NULL;
  char *text = NULL;
  uint64_t timestamp;
  int rc = -1, op;

  tn = tpl_map("isU", &op, &text, &timestamp);
  if (tn == NULL) goto done;
  if (tpl_load(tn, TPL_FD, cfg.up_scan[R]) < 0) goto done;
  tpl_unpack(tn, 0);

  switch(op) {
    case OP_SCAN_ADD:
      if (cfg.verbose > 1) fprintf(stderr, "scanner: add %s\n", text);
      if (add(text) < 0) goto done;
      break;
    case OP_SCAN_END:
      /* close descriptors to scanner */
      close(cfg.up_scan[R]);
      close(cfg.dn_scan[W]);
      cfg.up_scan[R] = -1;
      cfg.dn_scan[W] = -1;

      /* collect scanner sub process */
      if (waitpid(cfg.scanner_pid, NULL, 0) < 0) {
        fprintf(stderr, "wait: %s\n", strerror(errno));
        goto done;
      }
      /* tell parent to tell db worker to purge OBE table entries */
      if (push_purge_down(timestamp) < 0) goto done;

      if (cfg.verbose) {
        time_t now = time(NULL);
        fprintf(stderr, "scanner: end (%lu sec)\n", now - timestamp);
      }
      break;
    default:
      fprintf(stderr, "scanner error: %s\n", text);
      goto done;
  }

  rc = 0;

 done:
  if (tn) tpl_free(tn);
  if (text) free(text);
  return rc;
}

/* worker has sent us a message up the pipe */
int handle_worker(void) {
  tpl_node *tn=NULL;
  char *text = NULL;
  int rc = -1, op;
  size_t len;

  tn = tpl_map("is", &op, &text);
  if (tn == NULL) goto done;
  if (tpl_load(tn, TPL_FD, cfg.up_work[R]) < 0) goto done;
  tpl_unpack(tn, 0);

  switch(op) {
    case OP_ERR_UP:
      fprintf(stderr, "worker error: %s\n", text);
      goto done;
      break;
    case OP_DEBUG_UP:
      if (cfg.verbose) fprintf(stderr, "worker: %s\n", text);
      break;
    default:
      fprintf(stderr, "invalid op %d from worker\n", op);
      goto done;
      break;
  }


  rc = 0;

 done:
  if (tn) tpl_free(tn);
  if (text) free(text);
  return rc;
}

int handle_io(void) {
  struct iovec *iov;
  int rc = -1, i;
  ssize_t rv, wc;
  size_t iovcnt;

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

  cfg.max = n;
  rc = 0;

 done:
  return rc;
}

int w_keep_parent(const char *name, char *ppath) {
  char tmp[PATH_MAX], *p;
  struct dirent *dent;
  int rc = -1, i=0;
  DIR *d = NULL;
  size_t l, rl;

  l = strlen(name);
  if (l+1 > PATH_MAX) {
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
  if (rl+1 > PATH_MAX) {
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

int w_unlink_path(const char *name, int is_dir) {
  char ppath[PATH_MAX];
  int rc = -1, ec;

  if (cfg.verbose) fprintf(stderr, "unlinking %s\n", name);

  /* do the unlink. tolerate a priori nonexistence */
  ec = is_dir ? rmdir(name) : unlink(name);
  if (ec < 0) {
    if (errno == ENOENT) {
      rc = 0;
      goto done;
    } else {
      fprintf(stderr, "unlink: %s: %s\n", name, strerror(errno));
      goto done;
    }
  }

  /* attrition empty parent directories, up to cfg.dir */
  ec = w_keep_parent(name, ppath);
  if (ec < 0) goto done;
  else if (ec > 0) { /* keep */ }
  else if (w_unlink_path(ppath, 1) < 0) goto done;

  rc = 0;

 done:
  return rc;
}

int add(char *file) {
  int rc = -1, ec;
  struct stat s;
  size_t l, d, sz;
  time_t mtime;

  /* canonicalize to an absolute path. only abs paths in db */
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
  if (l+1 > PATH_MAX) {
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

  mtime = s.st_mtim.tv_sec;
  sz = s.st_size;
  if (push_update_down(cfg.tmp, mtime, sz) < 0) goto done;

  rc = 0;

 done:
  return rc;
}

/* when scanner encounters each file in the tree during its scan,
 * it pushes the file name to its parent to insert/update/confirm
 * that it is in the table of known files. if the table is empty
 * or out of sync, the scan brings it into sync, when coupled with
 * the purge of any in-table files that were not found in the scan.
 */
int s_push_up(int op, char *text, uint64_t timestamp){
  int rc = -1, ec;
  tpl_node *tn=NULL;

  tn = tpl_map("isU", &op, &text, &timestamp);
  if (tn == NULL) goto done;
  tpl_pack(tn,0);
  ec = tpl_dump(tn, TPL_FD, cfg.up_scan[W]);
  if (ec < 0) goto done;

  rc = 0;

 done:
  if (tn) tpl_free(tn);
  return rc;
}

/* add directory to tree, recursively. 
 * recursion depth bounded by fs depth
 * runs in scanner process
 *
 * returns
 *   < 0 on error
 *   >= 0 the number of files+directories in dir
 */
int s_add_dir(char *dir) {
  int rc = -1, ec, n=0, f;
  char path[PATH_MAX];
  struct dirent *dent;
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
    if (l+1+el+1 > PATH_MAX) {
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

    if (S_ISDIR(s.st_mode))  { /* dir? recurse. if empty, prune. */
      f = s_add_dir(path);
      if (f < 0) goto done;
      if (f == 0) {
        ec = rmdir(path);
        if (ec < 0) {
          fprintf(stderr, "rmdir %s: %s\n", path, strerror(errno));
          goto done;
        }
      }
      if (f > 0) n++;
    } else if (S_ISREG(s.st_mode)) { /* regular file */
      if (s_push_up(OP_SCAN_ADD, path, 0) < 0) goto done;
      n++;
    } else {  /* a special file; ignore it- don't touch */
      fprintf(stderr, "special file: %s\n", path);
      n++;  /* prevent pruning of its parent */
    }
    nanosleep(&cfg.scanner_pause,0); /* reduce impact of scan */
  }

  rc = 0;

 done:
  if (d) closedir(d);
  return rc ? rc : n;
}

/* the heart of this program is here. we process one filename.
 * this means, the filename needs to be stat'd to determine its
 * size and modification time. store that, along with the
 * time we did the stat (that is, the current time).
 */
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

int w_report_up(int op, const char *text) {
  tpl_node *tn=NULL;
  int rc = -1, ec;

  tn = tpl_map("is", &op, &text);
  if (tn == NULL) goto done;
  tpl_pack(tn, 0);
  ec = tpl_dump(tn, TPL_FD, cfg.up_work[W]);
  if (ec < 0) goto done;

  rc = 0;

 done:
  if (tn) tpl_free(tn);
  return rc;
}

int w_reset(sqlite3_stmt *ps) {
  int sc, rc = -1;

  sc = sqlite3_reset(ps);
  if (sc != SQLITE_OK) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_clear_bindings(ps);
  if (sc != SQLITE_OK) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

/* query tree size from db. runs in worker. */
int w_maintain(sqlite3_stmt *ps_query, sqlite3_stmt *ps_delete) {
  int sc, rc = -1;
  sqlite3_int64 tree_sz, file_sz;
  const char *f;
  char file[PATH_MAX];
  size_t flen;

  do {
    /* query the table. due to SUM function in our query, even
     * an empty table returns one row, with sz==0 and f==NULL */
    if (w_reset(ps_query) < 0) goto done;
    sc = sqlite3_step(ps_query);
    if(sc != SQLITE_ROW) { 
      w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
      goto done;
    }
    tree_sz = sqlite3_column_int64(ps_query, 0);
    f = sqlite3_column_text(ps_query, 1);
    /* MIN(modts) is index 2 */
    file_sz = sqlite3_column_int64(ps_query, 3);

    /* copy filename from sqlite3's transient buffer */
    *file = '\0';
    flen = f ? strlen(f) : 0;
    if (flen+1 > sizeof(file)) goto done;
    if (f) memcpy(file, f, flen+1);
    
    /* allow query to complete so db unlocks/frees row space */
    sc = sqlite3_step(ps_query);
    if(sc != SQLITE_DONE) { 
      w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
      goto done;
    }

    if (tree_sz > cfg.max) {
      if (w_unlink_path(file, 0) < 0) goto done;
      assert(tree_sz >= file_sz);
      tree_sz -= file_sz;

      /* delete entry from db */
      if (cfg.verbose > 1) fprintf(stderr,"w_maintain: delete %s\n", file);
      if (w_reset(ps_delete) < 0) goto done;
      sc = sqlite3_bind_text(ps_delete, 1, file, -1, SQLITE_TRANSIENT);
      if (sc != SQLITE_OK) {
        w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
        goto done;
      }
      sc = sqlite3_step(ps_delete);
      if(sc != SQLITE_DONE) {
        w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
        goto done;
      }
    }

  } while (tree_sz > cfg.max);

  rc = 0;

 done:
  return rc;
}

/* purge all rows from db whose stattime is older than given */
int w_purge(sqlite3_stmt *ps_purge, uint64_t stattime) {
  int sc, rc = -1;

  if (w_reset(ps_purge) < 0) goto done;

  /* bind values */
  sc = sqlite3_bind_int64(ps_purge, 1, stattime);
  if (sc != SQLITE_OK) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  /* execute sql */
  sc = sqlite3_step(ps_purge);
  if(sc != SQLITE_DONE) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }


  rc = 0;

 done:
  return rc;
}

/* insert or replace a row in the db. runs in worker */
int w_insert(sqlite3_stmt *ps_insert, char *name, uint64_t sz, 
             uint64_t mtime, uint64_t stattime) {
  int sc, rc = -1;

  if (w_reset(ps_insert) < 0) goto done;

  /* bind values */
  sc = sqlite3_bind_text(ps_insert, 1, name, -1, SQLITE_TRANSIENT);
  if (sc != SQLITE_OK) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps_insert, 2, sz);
  if (sc != SQLITE_OK) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps_insert, 3, mtime);
  if (sc != SQLITE_OK) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps_insert, 4, stattime);
  if (sc != SQLITE_OK) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  /* execute sql */
  sc = sqlite3_step(ps_insert);
  if (sc != SQLITE_DONE) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}
/* decode opcode from parent. runs in worker */
int w_decode_op(char *img, size_t sz, sqlite3_stmt *ps_insert, 
                                      sqlite3_stmt *ps_purge) {
  int rc = -1, ec, op;
  tpl_node *tn=NULL;
  char *fmt=NULL, *name=NULL;
  uint64_t file_sz, file_mtime, file_stattime;

  fmt = tpl_peek(TPL_MEM | TPL_DATAPEEK, img, sz, "i", &op);
  if (fmt == NULL) {
    w_report_up(OP_ERR_UP, "tpl_peek: decoding error\n");
    goto done;
  }

  switch(op) {
    case OP_INSERT:
      tn = tpl_map("isUUU", &op, &name, &file_sz, &file_mtime, &file_stattime);
      if (tn == NULL) goto done;
      if (tpl_load(tn, TPL_MEM, img, sz) < 0) goto done;
      tpl_unpack(tn, 0);
      if (w_insert(ps_insert, name, file_sz, file_mtime, file_stattime) < 0) {
        goto done;
      }
      break;
    case OP_PURGE:
      tn = tpl_map("iU", &op, &file_stattime);
      if (tn == NULL) goto done;
      if (tpl_load(tn, TPL_MEM, img, sz) < 0) goto done;
      tpl_unpack(tn, 0);
      if (w_purge(ps_purge, file_stattime) < 0) {
        goto done;
      }
      break;
    default: 
      w_report_up(OP_ERR_UP, "decoding error: invalid op\n");
      goto done;
      break;
  }

  rc = 0;

 done:
  if (tn) tpl_free(tn);
  if (fmt) free(fmt);
  if (name) free(name);
  return rc;
}


int w_prepare_db(sqlite3 **db, sqlite3_stmt **ps_insert, 
                               sqlite3_stmt **ps_delete, 
                               sqlite3_stmt **ps_query,
                               sqlite3_stmt **ps_purge) {
  int rc = -1, sc;
  char *sql;

  sc = sqlite3_open(cfg.db_name, db);
  if(sc){
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  /* set 10 sec timeout for getting table lock */
  sc = sqlite3_busy_timeout(*db, 10000);
  if (sc != SQLITE_OK) {
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  /* establish database table if need be */
  sql = "CREATE TABLE IF NOT EXISTS files ("
        "name TEXT PRIMARY KEY, "
        "size INTEGER, "
        "modts INTEGER, "
        "statts INTEGER "
        ");";
  if (w_exec_sql(*db, sql) < 0) goto done;

  /* index so it's quick to find the min timestamp */
  sql = "CREATE INDEX IF NOT EXISTS byage ON files(modts);";
  if (w_exec_sql(*db, sql) < 0) goto done;

  /* prepared statements */
  sql = "INSERT OR REPLACE INTO files VALUES ($name, $size, $modts, $statts);";
  sc = sqlite3_prepare_v2(*db, sql, -1, ps_insert, NULL);
  if(sc != SQLITE_OK ){
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  sql = "DELETE FROM files WHERE name = $NAME;";
  sc = sqlite3_prepare_v2(*db, sql, -1, ps_delete, NULL);
  if(sc != SQLITE_OK ){
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  /* yields one row with the tree size summed over all rows, 
   * and filename of the oldest file, and its mod time. */
  sql = "SELECT SUM(size), name, MIN(modts), size FROM files;";
  sc = sqlite3_prepare_v2(*db, sql, -1, ps_query, NULL);
  if(sc != SQLITE_OK ){
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  sql = "DELETE FROM files WHERE statts < $STATTS;";
  sc = sqlite3_prepare_v2(*db, sql, -1, ps_purge, NULL);
  if(sc != SQLITE_OK ){
    w_report_up(OP_ERR_UP, sqlite3_errstr(sc));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

/* scanner process runs this function, never returns! */
void scanner(void) {
  char *img;
  size_t nr;
  int rc = -1;
  time_t start_ts;

  /* this is a background process- lower scheduling priority */
  setpriority(PRIO_PROCESS, 0, 10);

  /* scan the directory tree, recursing over all files in it.
   * each file gets added/updated in the table. afterward the 
   * parent culls any table entries older than our start_time. 
   * this cleans up file references that no longer exist in fs
   */
  start_ts = time(NULL);
  if (s_add_dir(cfg.dir) < 0) goto done;
  s_push_up(OP_SCAN_END, NULL, start_ts);

  rc = 0;

 done:
  exit(rc);
}
/* worker process runs this function, never returns! */
void worker(void) {
  sqlite3 *db=NULL;
  char *img;
  size_t nr;
  int sc;

  /* prepared statements */
  sqlite3_stmt *ps_insert=NULL,
               *ps_delete=NULL,
               *ps_query=NULL,
               *ps_purge=NULL;

  if (w_prepare_db(&db, &ps_insert, &ps_delete, &ps_query, &ps_purge) < 0) {
    w_report_up(OP_ERR_UP, "db setup failed\n");
    goto done;
  }

  while(1) {
    if (w_maintain(ps_query, ps_delete) < 0) goto done;

    /* block waiting for parent instruction */
    sc = tpl_gather(TPL_GATHER_BLOCKING, cfg.dn_work[R], &img, &nr);

    if (sc == 0) goto done; /* eof expected on parent exit */
    if (sc < 0) {
      w_report_up(OP_ERR_UP, "tpl_gather: error\n");
      goto done;
    }

    assert(sc > 0);
    assert(img);
    if (w_decode_op(img, nr, ps_insert, ps_purge) < 0) {
      goto done;
    }
    free(img);
  }

 done:
  sqlite3_finalize(ps_insert); // ok if NULL
  sqlite3_finalize(ps_delete); // ok if NULL
  sqlite3_finalize(ps_query); // ok if NULL
  sqlite3_finalize(ps_purge); // ok if NULL
  sqlite3_close(db); // ok if NULL
  exit(-1);
}

/* start process that scans file tree */
int start_scanner(void) {
  int rc = -1, sc;

  sc = pipe(cfg.dn_scan);
  if (sc < 0) {
    fprintf(stderr,"pipe: %s\n", strerror(errno));
    goto done;
  }

  sc = pipe(cfg.up_scan);
  if (sc < 0) {
    fprintf(stderr,"pipe: %s\n", strerror(errno));
    goto done;
  }

  sc = fork();
  if (sc < 0) {
    fprintf(stderr,"fork: %s\n", strerror(errno));
    goto done;
  } 
  
  if (sc == 0) { /* child */ 
    close(cfg.dn_work[W]);
    close(cfg.up_work[R]);
    close(cfg.dn_scan[W]);
    close(cfg.up_scan[R]);
    prctl(PR_SET_NAME, "fprune-fs");
    scanner();
    /* not reached */
    assert(0);
  }

  /* parent */
  cfg.scanner_pid = sc;
  close(cfg.dn_scan[R]);
  close(cfg.up_scan[W]);
  cfg.dn_scan[R] = -1;
  cfg.up_scan[W] = -1;

  rc = 0;

 done:
  return rc;
}

/* start process that works db */
int start_worker(void) {
  int rc = -1, sc;

  sc = pipe(cfg.dn_work);
  if (sc < 0) {
    fprintf(stderr,"pipe: %s\n", strerror(errno));
    goto done;
  }

  sc = pipe(cfg.up_work);
  if (sc < 0) {
    fprintf(stderr,"pipe: %s\n", strerror(errno));
    goto done;
  }

  sc = fork();
  if (sc < 0) {
    fprintf(stderr,"fork: %s\n", strerror(errno));
    goto done;
  } 
  
  if (sc == 0) { /* child */ 
    close(cfg.dn_work[W]);
    close(cfg.up_work[R]);
    prctl(PR_SET_NAME, "fprune-db");
    worker();
    /* not reached */
    assert(0);
  }

  /* parent */
  cfg.worker_pid = sc;
  close(cfg.dn_work[R]);
  close(cfg.up_work[W]);
  cfg.dn_work[R] = -1;
  cfg.up_work[W] = -1;

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  char unit, *c, *sz=NULL, *sql, *dir=NULL;
  int opt, rc=-1, n, ec;
  struct epoll_event ev;
  cfg.prog = argv[0];
  size_t l;
  off_t i;

  while ( (opt = getopt(argc,argv,"vr:b:s:d:h")) > 0) {
    switch(opt) {
      case 'v': cfg.verbose++; break;
      case 'r': cfg.ring_name = strdup(optarg); break;
      case 'b': cfg.db_name = strdup(optarg); break;
      case 's': sz = strdup(optarg); break;
      case 'd': dir = strdup(optarg); break;
      case 'h': default: usage(); break;
    }
  }

  if (dir == NULL) usage();
  if (cfg.ring_name == NULL) usage();

  /* form absolute realpath of dir to monitor */
  if (realpath(dir, cfg.dir) == NULL) {
    fprintf(stderr, "realpath %s: %s\n", dir, strerror(errno));
    goto done;
  }
  /* parse size here; it relies on cfg.dir being set for % mode */
  if ((sz == NULL) || (parse_sz(sz) < 0)) usage();

  /* start the db worker and the scanner */
  if (start_worker() < 0) goto done;
  if (start_scanner() < 0) goto done;

  /* open the ring */
  int init_mode = SHR_KEEPEXIST|SHR_DROP;
  if (shr_init(cfg.ring_name, cfg.ring_def_sz, init_mode) < 0) goto done;
  cfg.ring = shr_open(cfg.ring_name, SHR_RDONLY|SHR_NONBLOCK);
  if (cfg.ring == NULL) goto done;
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
  if (add_epoll(EPOLLIN, cfg.up_work[R])) goto done;
  if (add_epoll(EPOLLIN, cfg.up_scan[R])) goto done;
  if (add_epoll(EPOLLIN, cfg.ring_fd)) goto done;

  alarm(1);

  while (1) {
    ec = epoll_wait(cfg.epoll_fd, &ev, 1, -1);
    if (ec < 0) { 
      fprintf(stderr, "epoll: %s\n", strerror(errno));
      goto done;
    }

    if (ec == 0)                          { assert(0); goto done;}
    else if (ev.data.fd == cfg.signal_fd) { if (handle_signal()  < 0) goto done;}
    else if (ev.data.fd == cfg.ring_fd)   { if (handle_io() < 0) goto done;}
    else if (ev.data.fd == cfg.up_work[R]){ if (handle_worker() < 0) goto done;}
    else if (ev.data.fd == cfg.up_scan[R]){ if (handle_scanner() < 0) goto done;}
    else                                  { assert(0); goto done;}

  }
  
  rc = 0;
 
 done:
  if (cfg.ring) shr_close(cfg.ring);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.ring_name) free(cfg.ring_name);
  if (cfg.dn_work[R] != -1) close(cfg.dn_work[R]);
  if (cfg.dn_work[W] != -1) close(cfg.dn_work[W]);
  if (cfg.up_work[R] != -1) close(cfg.up_work[R]);
  if (cfg.up_work[W] != -1) close(cfg.up_work[W]);
  if (cfg.dn_scan[R] != -1) close(cfg.dn_scan[R]);
  if (cfg.dn_scan[W] != -1) close(cfg.dn_scan[W]);
  if (cfg.up_scan[R] != -1) close(cfg.up_scan[R]);
  if (cfg.up_scan[W] != -1) close(cfg.up_scan[W]);
  return 0;
}
