#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include "flatner.h"
#include "libut.h"
#include "shr.h"

/*
 *
 *
 * pcap replay tool
 *
 * utility to read a tree of pcap files,
 * index the packets found in those files by time,
 * inject the packets into an ring or nic in time order
 *
 *
 */

const uint8_t pcap_magic[] = { 0xd4, 0xc3, 0xb2, 0xa1 };
const int pcap_glb_hdrlen = 24;
const int pcap_pkt_hdrlen = (sizeof(uint32_t) * 4);
#define BATCH_MSGS 10000
struct {
  int verbose;
  char *prog;

  /* file structure to index */
  char dir[PATH_MAX];
  int recurse;
  char *suffix;

  /* ring */
  char *ring_name;
  struct shr *ring;

  struct flatner *f;
  int copy_pkt_hdr;
  char *mark;
  int mark_sz;
  char *time_range;      /* "a:b" */
  long start_ts, end_ts; /*  a,b */

  /* to batch iov writes */
  size_t niov;
  struct iovec iov[BATCH_MSGS];

} CF = {
  .recurse = 1,
  .copy_pkt_hdr = 0,
};

void usage() {
  fprintf(stderr, "usage: %s [options] [<pcap> ...]\n", CF.prog);
  fprintf(stderr, "\n");
  fprintf(stderr, "   -d <dir>      (directory to scan for pcap)\n");
  fprintf(stderr, "   -r [0|1]      (scan recursively; default: 1)\n");
  fprintf(stderr, "   -s <suffix>   (only files having suffix)\n");
  fprintf(stderr, "   -o <ring>     (inject packets to ring)\n");
  fprintf(stderr, "   -i <nic>      (inject packets to NIC)\n");
  fprintf(stderr, "   -u <a:b>      (only packets in epoch usec range)\n");
  fprintf(stderr, "   -H [0:1]      (include header on packets; def: 0)\n");
  fprintf(stderr, "   -W <hex>      (inject marker to ring when done)\n");
  fprintf(stderr, "   -v            (verbose, repeatable)\n");
  fprintf(stderr, "\n");
  exit(-1);
}

int is_suffix(char *file) {
  size_t file_len, suffix_len;
  char *file_suffix;

  /* not enforcing suffix match? */
  if (CF.suffix == NULL) return 1;

  file_len = strlen(file);
  suffix_len = strlen(CF.suffix);

  /* file too short for suffix match? */
  if (file_len < suffix_len) return 0;

  file_suffix = &file[ file_len - suffix_len ];
  return strcmp(file_suffix, CF.suffix) ? 0 : 1;
}

/* add directory to tree, recursively by option. 
 * function recursion depth bounded by fs depth
 *
 * returns
 *   < 0 on error
 *   0 success
 */
int add_dir(char *dir) {
  char path[PATH_MAX];
  struct dirent *dent;
  int rc = -1, ec;
  DIR *d = NULL;
  struct stat s;
  size_t l, el;

  if (CF.verbose) fprintf(stderr, "adding directory %s\n", dir);

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

    if (S_ISREG(s.st_mode) && is_suffix(path)) {
      if (CF.verbose) fprintf(stderr, "adding regular file %s\n", path);
      if (flatner_add(CF.f, path) < 0) goto done;
    } 

    if (CF.recurse && (S_ISDIR(s.st_mode)))  {
      if (add_dir(path) < 0) goto done;
    }
  }

  rc = 0;

 done:
  if (d) closedir(d);
  return rc;
}

/* unhexer, overwrites input space;
 * returns number of bytes or -1 */
int unhex(char *h) {
  char b;
  int rc = -1;
  unsigned u;
  size_t i, len = strlen(h);

  if (len == 0) goto done;
  if (len &  1) goto done; /* odd number of digits */
  for(i=0; i < len; i += 2) {
    if (sscanf( &h[i], "%2x", &u) < 1) goto done;
    assert(u <= 255);
    b = (unsigned char)u;
    h[i/2] = b;
  }

  rc = 0;

 done:
  if (rc < 0) {
    fprintf(stderr, "hex conversion failed\n");
    return -1;
  }

  return len/2;
}

/* flush when cache capacity reached or when
 * cache invalidation is pre announced. flatner 
 * sets mc when saved pointer validity ends next 
 * time we call flatner_next, meaning flush now. */
int flush_if_needed(int mc) {
  int rc = -1;
  ssize_t nr;

  if ((CF.niov < BATCH_MSGS) && (mc == 0)) 
    return 0;

  nr = shr_writev( CF.ring, CF.iov, CF.niov );
  if (nr < 0) {
    fprintf(stderr, "shr_writev: error %zd\n", nr);
    fprintf(stderr, "(ring buffer too small?)\n");
    goto done;
  }

  assert(nr > 0);
  CF.niov = 0;
  rc = 0;

 done:
  return rc;
}

int insert_terminator(void) {
  ssize_t nr;

  if (CF.mark_sz == 0) 
    return 0;

  if (CF.verbose)
    fprintf(stderr, "marking terminator\n");

  nr = shr_write(CF.ring, CF.mark, CF.mark_sz);
  if (nr < 0) {
    fprintf(stderr, "shr_write: %zd\n", nr);
    return -1;
  }

  return 0;
}

int populate_ring(void) {
  int rc = -1, sc, mc;
  struct iovec *iov;
  char *data;
  size_t sz;

  if (CF.ring == NULL) return 0;

  /* start iteration by zeroing */
  data = NULL;
  sz = 0;

  while(1) {
    sc = flatner_next(CF.f, &data, &sz, &mc);
    if (sc < 0)  goto done;
    if (sc ==0)  { 
      if (CF.verbose) fprintf(stderr, "end of data\n"); 
      assert(CF.niov == 0);
      break;
    }

    assert(sc > 0);
    data = CF.copy_pkt_hdr ? 
           data : 
           data + pcap_pkt_hdrlen;

    assert(CF.niov < BATCH_MSGS);
    iov = &CF.iov[ CF.niov ];
    iov->iov_base = data;
    iov->iov_len = sz;
    CF.niov++;

    sc = flush_if_needed(mc);
    if (sc < 0) goto done;
  }

  sc = insert_terminator();
  if (sc < 0) goto done;
  rc = 0;

 done:
  return rc;
}


/* callback to iterate through data items.
 * its purpose is to locate the next data
 * item in the buffer of length len. by
 * next data item, it means the one after
 * the "current" item at offset *off having
 * size *sz. (note *off and *sz may be zero
 * e.g. on the first invocation). the item's
 * timestamp should be placed into *ts. the
 * off and sz are input/output parameters.
 *
 * return
 *   0 if buffer is exhausted (no item found)
 *   1 if an item is available at offset off
 *  -1 if an error occurred e.g. bad input
 */
int cb(char *name, char *buf, size_t len, 
       uint64_t *off, size_t *sz, uint64_t *ts) {
  char *p;

  /* in initial state (sz==0) confirm pcap global header.
   * otherwise, skip over previously returned item. */
  if (*sz == 0) {
    assert(*off == 0);
    if (memcmp(buf, pcap_magic, sizeof(pcap_magic))) {
      fprintf(stderr, "%s: not pcap, skipping\n", name);
      return 0;
    }
		*sz = pcap_glb_hdrlen;
  }

  *off = (*off) + (*sz);
  if (buf + (*off) + pcap_pkt_hdrlen > buf+len) return 0;

  p = buf + *off;
  uint32_t *sec =      (uint32_t*)p;
  uint32_t *usec =     (uint32_t*)((char*)sec      + sizeof(*sec));
  uint32_t *incl_len = (uint32_t*)((char*)usec     + sizeof(*usec));
  uint32_t *orig_len = (uint32_t*)((char*)incl_len + sizeof(*incl_len));
  p += pcap_pkt_hdrlen;
  if (p + (*incl_len) > buf+len) {
    fprintf(stderr, "packet truncated\n");
    return 0;
  }
  *sz = pcap_pkt_hdrlen + (*incl_len);
  *ts = (*sec * 1000000UL) + *usec;
  return 1;
}

int main(int argc, char *argv[]) {
  int sc, opt, rc=-1;
  char *dir = NULL;

  CF.prog = argv[0];
  CF.f = flatner_new(cb);

  while ( (opt = getopt(argc,argv,"vhd:r:s:u:o:H:W:")) > 0) {
    switch(opt) {
      case 'v': CF.verbose++; break;
      case 'd': dir = strdup(optarg); break;
      case 'r': CF.recurse=atoi(optarg); break;
      case 'H': CF.copy_pkt_hdr=atoi(optarg); break;
      case 's': CF.suffix = strdup(optarg); break;
      case 'o': CF.ring_name = strdup(optarg); break;
      case 'u': CF.time_range = strdup(optarg); break;
      case 'W': CF.mark = strdup(optarg); break;
      case 'h': default: usage(argv[0]); break;
    }
  }

  if ((dir == NULL) && (optind >= argc)) usage();

  if (CF.ring_name) {
    CF.ring = shr_open(CF.ring_name, SHR_WRONLY);
    if (CF.ring == NULL) goto done;
  }

  if (CF.mark) {
    CF.mark_sz = unhex(CF.mark);
    if (CF.mark_sz == -1) goto done;
  }

  sc = CF.time_range ? 
       sscanf(CF.time_range, "%ld:%ld", &CF.start_ts, &CF.end_ts) : 2;
  if (sc != 2) {
    fprintf(stderr, "time range must be in START:STOP format\n");
    goto done;
  }

  if (dir) {
    if (realpath(dir, CF.dir) == NULL) {
      fprintf(stderr, "realpath %s: %s\n", dir, strerror(errno));
      goto done;
    }
    sc = add_dir(CF.dir);
    if (sc < 0) goto done;
  }

  while (optind < argc) {
    sc = flatner_add(CF.f, argv[optind++]);
    if (sc < 0) goto done;
  }

  if (CF.verbose) 
    flatner_describe(CF.f);

  /* TODO
   * sendto for bonus points
   * delay for bonus points
   */

  sc = populate_ring(); 
  if (sc < 0) goto done;

  rc = 0;
 
 done:
  if (dir) free(dir);
  if (CF.suffix) free(CF.suffix);
  if (CF.ring_name) free(CF.ring_name);
  if (CF.ring) shr_close(CF.ring);
  if (CF.time_range) free(CF.time_range);
  if (CF.mark) free(CF.mark);
  if (CF.f) flatner_free(CF.f);
  return rc;
}
