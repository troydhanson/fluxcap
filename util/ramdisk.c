#include <sys/mount.h>
#include <syslog.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "utarray.h"
#include <limits.h>

#define TMPFS_MAGIC           0x01021994
#define RAMFS_MAGIC           0x858458F6
 
/******************************************************************************
 * ramdisk
 *
 *   a utility with modes to: 
 *   - create a ramdisk,
 *   - query a ramdisk (see its size and percent full)
 *   - unmount a ramdisk 
 *
 * The ramdisk used here is the 'tmpfs' filesystem which is not strictly a 
 * pure RAM device; it can swap under the kernel's discretion. I have also
 * noticed that a large ramdisk (say, 6gb on a system with 8gb ram) might 
 * exhibit 'no space left on device' even when only 50% full. A better 
 * query mode would show the status (resident, paged, etc) of ramdisk pages.
 *****************************************************************************/

/* command line configuration parameters */
int verbose;
int ramfs;
enum {MODE_NONE,MODE_QUERY,MODE_CREATE,MODE_UNMOUNT} mode = MODE_NONE;
char *sz="50%";
char *ramdisk;
UT_array *dirs;
 
void usage(char *prog) {
  fprintf(stderr, "This utility creates a tmpfs ramdisk on a given mountpount.\n");
  fprintf(stderr, "It does nothing if a tmpfs is already mounted on that point.\n");
  fprintf(stderr, "\n");
  fprintf(stderr,"usage:\n\n");
  fprintf(stderr, "-c (create mode):\n");
  fprintf(stderr, "   %s -c [-s <size>] [-d <dir>] [-r] <mount-point>\n", prog);
  fprintf(stderr, "   -s <size> suffixed with k|m|g|%% [default: 50%%]\n");
  fprintf(stderr, "   -d <dir> directory to post-create inside ramdisk (repeatable)\n");
  fprintf(stderr, "   -r use ramfs instead of tmpfs (grows unbounded, no swap)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "-q (query mode):\n");
  fprintf(stderr, "   %s -q <ramdisk-mount-point>\n", prog);
  fprintf(stderr, "\n");
  fprintf(stderr, "-u (unmount mode):\n");
  fprintf(stderr, "   %s -u <ramdisk-mount-point>\n", prog);
  fprintf(stderr, "\n");
  fprintf(stderr, "Examples of creating a ramdisk:\n");
  fprintf(stderr, " %s -c -s 1g /mnt/ramdisk\n", prog);
  fprintf(stderr, " %s -c -s 1g -d /mnt/ramdisk/in -d /mnt/ramdisk/out /mnt/ramdisk\n", prog);
  fprintf(stderr, "\n");
  fprintf(stderr, "Note: 'cat /proc/mounts' to see mounted tmpfs ramdisks.\n");
  exit(-1);
}

/* Prevent a ramdisk from being mounted at the mount-point of an 
 * existing ramdisk. This prevents people from accidently stacking tmpfs.
 * However it is OK to mount a ramdisk on a subdirectory of another ramdisk. */
int suitable_mountpoint(char *dir, struct stat *sb, struct statfs *sf) {
  size_t dlen = strlen(dir);
  char pdir[PATH_MAX];
  struct stat psb;

  if (dlen+4 > PATH_MAX) {
    syslog(LOG_ERR, "path too long\n");
    return -1;
  }

  if (stat(ramdisk, sb) == -1) { /* does mount point exist? */
    syslog(LOG_ERR, "no mount point %s: %s\n", ramdisk, strerror(errno));
    return -1;
  }
  if (S_ISDIR(sb->st_mode) == 0) { /* has to be a directory */
    syslog(LOG_ERR, "mount point %s: not a directory\n", ramdisk);
    return -1;
  }
  if (statfs(ramdisk, sf) == -1) { /* what kinda filesystem is it on? */
    syslog(LOG_ERR, "can't statfs %s: %s\n", ramdisk, strerror(errno));
    return -1;
  }

  /* is it already a tmpfs mountpoint? */
  memcpy(pdir,dir,dlen+1); strcat(pdir,"/..");
  if (stat(pdir, &psb) == -1) {
    syslog(LOG_ERR, "can't stat %s: %s\n", pdir, strerror(errno));
    return -1;
  }
  int is_mountpoint = (psb.st_dev == sb->st_dev) ? 0 : 1;
  int is_tmpfs = (sf->f_type == TMPFS_MAGIC);
  int is_ramfs = (sf->f_type == RAMFS_MAGIC);
  if (is_mountpoint && (is_tmpfs || is_ramfs)) {
    //syslog(LOG_INFO, "already a tmpfs mountpoint: %s\n", dir, strerror(errno));
    return -2;
  }

  return 0;
}

#define KB 1024L
#define MB (1024*1024L)
#define GB (1024*1024*1024L)
int query_ramdisk(void) {
  struct stat sb; struct statfs sf;
  if (suitable_mountpoint(ramdisk, &sb, &sf) != -2) {
    printf("%s: not a ramdisk\n", ramdisk);
    return -1;
  }
  if (sf.f_type == RAMFS_MAGIC) {
    printf("%s: ramfs ramdisk (unbounded size)\n", ramdisk);
    return 0;
  }
  char szb[100];
  long bytes = sf.f_bsize*sf.f_blocks;
  if (bytes < KB) snprintf(szb, sizeof(szb), "%ld bytes", bytes);
  else if (bytes < MB) snprintf(szb, sizeof(szb), "%ld kb", bytes/KB);
  else if (bytes < GB) snprintf(szb, sizeof(szb), "%ld mb", bytes/MB);
  else                 snprintf(szb, sizeof(szb), "%ld gb", bytes/GB);
  int used_pct = 100 - (sf.f_bfree * 100.0 / sf.f_blocks);
  printf("%s: ramdisk of size %s (%d%% used)\n", ramdisk, szb, used_pct);
  return 0;
}

int unmount_ramdisk(void) {
  struct stat sb; struct statfs sf;
  if (suitable_mountpoint(ramdisk, &sb, &sf) != -2) {
    syslog(LOG_ERR,"%s: not a ramdisk\n", ramdisk);
    return -1;
  }
  if (umount(ramdisk) == -1) {
    syslog(LOG_ERR,"%s: cannot unmount\n", ramdisk);
    return -1;
  }
  return 0;
}

int create_ramdisk(void) {
  int rc;
  char opts[100], *kind;

  struct stat sb; struct statfs sf;
  rc = suitable_mountpoint(ramdisk, &sb, &sf);
  if (rc) return rc;

  kind = "tmpfs";
  if (ramfs) kind = "ramfs";

  /* ok, mount a ramdisk on this point */
  snprintf(opts,sizeof(opts),"size=%s",sz);
  rc=mount("none", ramdisk, kind, MS_NOATIME|MS_NODEV, opts);
  if (rc) syslog(LOG_ERR, "can't make ramdisk %s: %s\n", ramdisk, strerror(errno));
  return rc;
}

void make_dirs(UT_array *dirs) {
  char **d, *dir;
  d=NULL;
  while ( (d=(char**)utarray_next(dirs,d))) {
    dir = *d;
    /* fprintf(stderr,"dir is %s\n",dir); */
    if (mkdir(dir, 0777) == -1) {
      fprintf(stderr,"failed to make %s: %s\n",dir,strerror(errno));
    }
  }
}

int main(int argc, char * argv[]) {
  int opt, rc;
  utarray_new(dirs,&ut_str_icd);
 
  while ( (opt = getopt(argc, argv, "v+cqus:hd:r")) != -1) {
    switch (opt) {
      case 'v': verbose++; break;
      case 'r': ramfs=1; break;
      case 'q': if (mode) usage(argv[0]); mode=MODE_QUERY; break;
      case 'c': if (mode) usage(argv[0]); mode=MODE_CREATE; break;
      case 'u': if (mode) usage(argv[0]); mode=MODE_UNMOUNT; break;
      case 's': sz=strdup(optarg); break;
      case 'd': utarray_push_back(dirs,&optarg); break;
      case 'h': default: usage(argv[0]); break;
    }
  }
  if (optind < argc) ramdisk=argv[optind++];
  if (!ramdisk) usage(argv[0]);
  openlog("ramdisk", LOG_PID|LOG_PERROR, LOG_LOCAL0);

  switch(mode) {
    case MODE_CREATE: rc=create_ramdisk(); make_dirs(dirs); break;
    case MODE_UNMOUNT: rc=unmount_ramdisk(); break;
    case MODE_QUERY: rc=query_ramdisk(); break;
    default: usage(argv[0]); break;
  }
  utarray_free(dirs);
  return rc;
}
