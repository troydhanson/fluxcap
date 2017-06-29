#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

struct {
  int verbose;
  int pattern_mode;
  int mkdir_mode;
  char *prog;
} CF;

/* usage: watch_copy <watch-dir> <dest-pattern>
 *
 * whenever a file in watch-dir is closed (if it was open for writing),
 * it is copied to the dest-pattern. It does not recurse in watch-dir.
 *
 * This implementation mmaps the source and dest files.
 * 
 */

void usage() {
  fprintf(stderr,"usage: %s [-p] [-m] <watch-dir> <dest-pattern>\n", CF.prog);
  fprintf(stderr,"\n");
  fprintf(stderr," -v (verbose)\n");
  fprintf(stderr," -p (pattern mode)\n");
  fprintf(stderr," -m (mkdir mode; makes destination directory if needed,\n");
  fprintf(stderr,"     supports only one level of directory creation)\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"<dest-pattern> can be a directory, or a pattern (if -p)\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"pattern syntax: $1 = first character of file basename\n");
  fprintf(stderr,"                $2 = second character of file basename\n");
  fprintf(stderr,"                $3 = third character (likewise $4, ...)\n");
  fprintf(stderr,"                $A = tenth character (likewise $B, ...)\n");
  fprintf(stderr,"                $Z = 36th character\n");
  fprintf(stderr,"                $0 = entire original file basename\n");
  fprintf(stderr,"                $$ = literal $\n");
  fprintf(stderr,"                everything else is literal\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"note: quote pattern expressions to protect from shell!\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"examples:\n");
  fprintf(stderr,"  %s /tmp /data\n", CF.prog);
  fprintf(stderr,"  (/tmp/abc123.pcap -> /data/abc123.pcap)\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"  %s -p /tmp '/data/$1$2$3/$0'\n", CF.prog);
  fprintf(stderr,"  (/tmp/abc123.pcap -> /data/abc/abc123.pcap)\n");
  fprintf(stderr,"\n");
  fprintf(stderr,"  %s -mp /tmp '/data/$A$B/$0'\n", CF.prog);
  fprintf(stderr,"  (/tmp/fw-20170921.pcap -> /data/21/fw-20170921.pcap)\n");
  fprintf(stderr,"\n");

  exit(-1);
}

#define append(c) do {        \
  if (olen == 0) goto done;   \
  *(o++) = (c);               \
  olen--;                     \
} while(0)

/* make a pathname from pattern applied to src. literals are copied, $0 is src,
 * and $1 through $9 and $A through $Z refer to positions 1 through 36 in src */
int pat2path(char *out, size_t olen, char *src, char *pat) {
  char *p = pat;
  char *o = out;
  size_t l = strlen(src);
  int i, rc = -1; 
  unsigned char x;

  while (*p != '\0') {
    if (*p == '$') {    /* translate next pattern character */
      p++;
      if (*p == '$') append(*p); /* special case: $$ */
      else {

        /* here if we had $x where x must be [0-9A-Z] */
        if      ((*p >= '0') && (*p <= '9')) x = *p - '0';
        else if ((*p >= 'A') && (*p <= 'Z')) x = *p - 'A' + 10;
        else { 
          fprintf(stderr,"invalid position %c\n", *p); 
          goto done;
        }

        if (x == 0) { 
          /* $0 means whole src */
          if (olen < l) goto done;
          memcpy(o, src, l);
          o += l;
        } else { 
          /* copy from 1-based offset to 0-based */
          if (l < x)  {fprintf(stderr,"position %c > %s\n", *p, src); goto done;}
          append(src[x-1]);
        }
      }
    } else append(*p); /* copy literal character */
    p++;
  }

  append('\0');
  rc = 0;

 done:
  return rc;
}

int map_copy(char *file, char *dest) {
  struct stat s;
  char *src=NULL,*dst=NULL;
  int fd=-1,dd=-1,rc=-1;

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
  src = mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (src == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", file, strerror(errno));
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
  dst = mmap(0, s.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, dd, 0);
  if (dst == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", dest, strerror(errno));
    goto done;
  }
  memcpy(dst,src,s.st_size);

  rc = 0;

done:
  if (src && (src != MAP_FAILED)) {
    if (munmap(src, s.st_size)) fprintf(stderr,"munmap: %s\n",strerror(errno));
  }
  if (dst && (dst != MAP_FAILED)) {
    if (munmap(dst, s.st_size)) fprintf(stderr,"munmap: %s\n",strerror(errno));
  }
  if (fd != -1) close(fd);
  if (dd != -1) close(dd);
  return rc;
}

/* this implementation only supports making one level of directory */
int do_mkdir(char *path) {
  int rc = -1, sc;
  char dir[PATH_MAX], *d;
  size_t l = strlen(path);
  struct stat s;

  /* dirname may modify its input, so pass a copy in */
  if (l+1 > sizeof(dir)) goto done;
  memcpy(dir, path, l+1);
  d = dirname(dir);

  sc = stat(d, &s);
  if (sc < 0) {
    /* try to make the path */
    if (mkdir(d, 0755) == 0) { rc = 0; goto done; }
    fprintf(stderr, "mkdir failed: %s %s\n", d, strerror(errno));
    goto done;
  } else {
    /* path exists. is it a directory? */
    if (S_ISDIR(s.st_mode)) { rc = 0; goto done; } /* yes */
    fprintf(stderr, "path exists as non-directory: %s\n", d);
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  char *src=NULL, *dst=NULL, *name, oldpath[PATH_MAX],newpath[PATH_MAX];
  int fd=-1, wd, mask, opt, rc=-1, slen, dlen;
  struct inotify_event *eb=NULL, *ev, *nx;
  size_t eb_sz = sizeof(*eb) + PATH_MAX, sz;
  ssize_t nr;

  CF.prog = argv[0];

  while ( (opt = getopt(argc,argv,"pmvh")) > 0) {
    switch(opt) {
      case 'v': CF.verbose++; break;
      case 'p': CF.pattern_mode=1; break;
      case 'm': CF.mkdir_mode=1; break;
      case 'h': default: usage(); break;
    }
  }

  /* expect two more arguments - source and destination */
  if (argc > optind) src = argv[optind++];
  if (argc > optind) dst = argv[optind++];
  if ((src == NULL) || (dst == NULL)) usage();

  /* initialize source path buffer as /srcdir/... */
  slen = strlen(src);
  memcpy(oldpath, src, slen); oldpath[slen]='/';

  /* initialize dest path as /dstdir/... (regular mode) */
  dlen = strlen(dst);
  memcpy(newpath, dst, dlen); newpath[dlen]='/';

  /* setup inotify watch on src dir */
  if ( (fd = inotify_init()) == -1) {
    fprintf(stderr, "inotify_init failed: %s\n", strerror(errno));
    goto done;
  }

  mask = IN_CLOSE_WRITE;
  if ( (wd = inotify_add_watch(fd, src, mask)) == -1) {
    fprintf(stderr, "inotify_add_watch failed: %s\n", strerror(errno));
    goto done;
  }

  /* see inotify(7) as inotify_event has a trailing name
   * field allocated beyond the fixed structure; we must
   * allocate enough room for the kernel to populate it */
  if ( (eb = malloc(eb_sz)) == NULL) {
    fprintf(stderr, "out of memory\n");
    goto done;
  }

  /* one read will produce one or more event structures */
  while ( (nr=read(fd,eb,eb_sz)) > 0) {
    for(ev = eb; nr > 0; ev = nx) {

      sz = sizeof(*ev) + ev->len;
      nx = (struct inotify_event*)((char*)ev + sz);
      nr -= sz;

      name = (ev->len ? ev->name : src);
      memcpy(&oldpath[slen+1],name,strlen(name)+1);
      if (CF.pattern_mode == 0) memcpy(&newpath[dlen+1],name,strlen(name)+1);
      else if (pat2path(newpath, sizeof(newpath), name, dst) < 0) goto done;

      if (CF.mkdir_mode) {
        if (do_mkdir(newpath) < 0) goto done;
      }

      if (CF.verbose) fprintf(stderr, "%s --> %s\n", oldpath, newpath); 
      if (map_copy(oldpath, newpath)) goto done;
    }
  }

 done:
  if (fd != -1) close(fd);
  if (eb) free(eb);
  return rc;
}
