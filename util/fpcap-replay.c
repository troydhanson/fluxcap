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
#include <sqlite3.h>
#include "shr.h"

/*
 * fluxcap pcap to ring tool
 *
 * utility to read a tree of pcap files, and
 * index the packets found in those files by time, and
 * inject the packets into an shr ring in time sorted
 * order (packets interleaved from pcaps as necessary)
 *
 * this is a batch oriented tool 
 *
 *
 */

struct region {
  int64_t beg, st;
  int64_t end, et;
  int64_t npkts;
  int file_id;
  char name[PATH_MAX];
};

struct {
  int verbose;
  char *prog;
  enum {mode_build, mode_print, mode_output} mode;

  /* file structure to index */
  char dir[PATH_MAX];
  int recurse;
  char *suffix;
  int file_id;

  /* db info */
  char *db_name;
  sqlite3 *db;
  sqlite3_stmt *insert_stmt;
  sqlite3_stmt *delete_regn;
  sqlite3_stmt *select_stmt;
  sqlite3_stmt *insert_regn;
  int truncate;

  /* ring */
  char *ring_name;
  struct shr *ring;

  /* output mode state */
  char *map_buf;
  off_t map_len;
  int copy_pkt_hdr;
  char *mark;
  int mark_sz;
  char *time_range;      /* "a:b" */
  long start_ts, end_ts; /*  a,b */

  /* bisect work space */
  struct region region_a;
  struct region region_b;

} CF = {
  .mode = mode_build,
  .recurse = 1,
  .truncate = 1,
  .copy_pkt_hdr = 0,
};

void usage() {
  fprintf(stderr, "usage: %s [options] -b <dbfile> [<pcap> ...]\n", CF.prog);
  fprintf(stderr, "\n");
  fprintf(stderr, "   -d <dir>      (directory to scan for files)\n");
  fprintf(stderr, "   -r [0|1]      (scan recursively; default: 1)\n");
  fprintf(stderr, "   -s <suffix>   (only files matching suffix)\n");
  fprintf(stderr, "   -O            (output only, skip build phase)\n");
  fprintf(stderr, "   -o <ring>     (output sorted packets to ring)\n");
  fprintf(stderr, "   -u <a:b>      (select packets in epoch usec range)\n");
  fprintf(stderr, "   -H [0:1]      (output header on packets; def: 0)\n");
  fprintf(stderr, "   -W <hex>      (output marker to ring after packets)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "print mode:\n");
  fprintf(stderr, "   -p            (print db)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "general options:\n");
  fprintf(stderr, "   -v            (verbose, repeatable)\n");
  fprintf(stderr, "\n");
  exit(-1);
}

/* helper function for create statements that return no row */
int exec_sql(sqlite3 *db, char *sql) {
  sqlite3_stmt *ps=NULL;
  int sc, rc = -1;

  if (CF.verbose) fprintf(stderr, "executing SQL: %s\n", sql);

  sc = sqlite3_prepare_v2(db, sql, -1, &ps, NULL);
  if (sc != SQLITE_OK ){
    fprintf(stderr, "sqlite3_prepare: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_step(ps);
  if (sc != SQLITE_DONE) {
    fprintf(stderr, "sqlite3_step: result unexpected\n");
    goto done;
  }

  sc = sqlite3_finalize(ps);
  if (sc != SQLITE_OK) {
    fprintf(stderr,"sqlite3_finalize: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int prep_sql(sqlite3 *db, char *sql, sqlite3_stmt **ps) {
  int sc, rc = -1;

  if (CF.verbose) fprintf(stderr, "preparing SQL: %s\n", sql);

  sc = sqlite3_prepare_v2(db, sql, -1, ps, NULL);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_prepare: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int setup_db(void) {
  int sc, rc = -1;
  char *sql;

  sc = sqlite3_open(CF.db_name, &CF.db);
  if (sc) {
    fprintf(stderr, "sqlite3_open: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  /* files table */
  sql = "CREATE TABLE IF NOT EXISTS files (name TEXT PRIMARY KEY, id INTEGER);";
  if (exec_sql(CF.db, sql) < 0) goto done;

  /* prepare insert statement - we substitute values in later */
  sql = "INSERT INTO files VALUES ($NAME, $ID);";
  if (prep_sql(CF.db, sql, &CF.insert_stmt) < 0) goto done;

  /* regions table */
  sql = "CREATE TABLE IF NOT EXISTS regions "
        "(id INTEGER, beg INTEGER, st INTEGER, end INTEGER, et INTEGER, npkts INTEGER, "
        "CONSTRAINT pk PRIMARY KEY (id, beg, st));";
  if (exec_sql(CF.db, sql) < 0) goto done;

  /* truncate */
  if (CF.truncate && (CF.mode == mode_build)) {
    if (exec_sql(CF.db, "DELETE FROM files;")   < 0) goto done;
    if (exec_sql(CF.db, "DELETE FROM regions;") < 0) goto done;
  }

  /* index */
  sql = "CREATE INDEX IF NOT EXISTS by_ts ON regions(st);";
  if (exec_sql(CF.db, sql) < 0) goto done;

  /* prepare select statement */
  sql = "SELECT f.name, f.id, p.beg, p.st, p.end, p.et, p.npkts "
        "FROM files f, regions p "
        "WHERE p.id = f.id "
        "ORDER BY p.st;";
  if (prep_sql(CF.db, sql, &CF.select_stmt) < 0) goto done;

  /* prepare insert statement */
  sql = "INSERT INTO regions VALUES ($ID, $BEG, $ST, $END, $ET, $NPKTS);";
  if (prep_sql(CF.db, sql, &CF.insert_regn) < 0) goto done;

  /* prepare delete statement */
  sql = "DELETE FROM regions "
        "WHERE id = $ID "
        "  AND beg = $BEG "
        "  AND st  = $ST ";
  if (prep_sql(CF.db, sql, &CF.delete_regn) < 0) goto done;

  rc = 0;

 done:
  return rc;
}

int reset(sqlite3_stmt *ps) {
  int sc, rc = -1;

  sc = sqlite3_reset(ps);
  if (sc != SQLITE_OK) {
    fprintf(stderr,"sqlite3_reset: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_clear_bindings(ps);
  if (sc != SQLITE_OK) {
    fprintf(stderr,"sqlite3_clear_bindings: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

/* maps a file into memory. caller should clean up
 * by calling munmap(buf,len) when done with file */
char *map(const char *file, size_t *len) {
  int fd = -1, rc = -1;
  char *buf = NULL;
  struct stat s;

  *len = 0;

  if ( (fd = open(file, O_RDONLY)) == -1) {
    fprintf(stderr,"open %s: %s\n", file, strerror(errno));
    goto done;
  }

  if (fstat(fd, &s) == -1) {
    fprintf(stderr,"fstat %s: %s\n", file, strerror(errno));
    goto done;
  }

  buf = (s.st_size > 0) ?
        mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0) :
        NULL;
  if (buf == MAP_FAILED) {
    fprintf(stderr, "mmap %s: %s\n", file, strerror(errno));
    goto done;
  }

  rc = 0;
  *len = s.st_size;

 done:
  if (fd != -1) close(fd);
  if ((rc < 0) && (buf != NULL) && (buf != MAP_FAILED)) munmap(buf, s.st_size);
  return (rc < 0) ? NULL : buf;
}

int insert_region(sqlite3_stmt *ps, int id, size_t beg, int64_t st, 
                                            size_t end, int64_t et,
                                            int64_t npkts) {
  int sc, rc = -1;

  if (CF.verbose) fprintf(stderr, "inserting region id %d beg %ld st %ld "
                                  "end %ld et %ld npkts %ld\n",
     id, (long)beg, (long)st, (long)end, (long)et, (long)npkts);
  
  sc = sqlite3_bind_int( ps, 1, id);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps, 2, beg);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps, 3, st);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps, 4, end);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps, 5, et);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps, 6, npkts);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  /* insert */
  sc = sqlite3_step(ps);
  if (sc != SQLITE_DONE) {
    fprintf(stderr,"sqlite3_step: unexpected result\n");
    goto done;
  }

  if (reset(ps) < 0) goto done;

  rc = 0;

 done:
  return rc;
}

const uint8_t pcap_magic_number[] = { 0xd4, 0xc3, 0xb2, 0xa1 };
const int pcap_glb_hdrlen = 24;
const int pcap_pkt_hdrlen = (sizeof(uint32_t) * 4);

int get_extents(sqlite3_stmt *ps, char *file, int id) {
  int sc, rc = -1;
  size_t len, plen;
  char *p, *buf=NULL;
  int64_t beg=0, end=0;
  int64_t st,et,npkts=0;

  buf = map(file, &len);
  if (buf == NULL) goto done;
  if (len < pcap_glb_hdrlen) goto done;

  /* pcap global header */
  uint32_t *magic_number =  (uint32_t*)buf;
  uint16_t *version_major = (uint16_t*)((char*)magic_number  + sizeof(*magic_number));
  uint16_t *version_minor = (uint16_t*)((char*)version_major + sizeof(*version_major));
  uint32_t *thiszone =      (uint32_t*)((char*)version_minor + sizeof(*version_minor));
  uint32_t *sigfigs =       (uint32_t*)((char*)thiszone      + sizeof(*thiszone));
  uint32_t *snaplen =       (uint32_t*)((char*)sigfigs       + sizeof(*sigfigs));
  uint32_t *network =       (uint32_t*)((char*)snaplen       + sizeof(*snaplen));
  char *cur =               ((char*)network)                 + sizeof(*network);

  if (memcmp(magic_number, pcap_magic_number, sizeof(pcap_magic_number))) {
    fprintf(stderr, "%s: not pcap\n", file);
    goto done;
  }

  for(p = cur; p < buf + len; p += plen) {
    uint32_t *sec =      (uint32_t*)(p + sizeof(uint32_t)*0);
    uint32_t *usec =     (uint32_t*)(p + sizeof(uint32_t)*1);
    uint32_t *incl_len = (uint32_t*)(p + sizeof(uint32_t)*2);
    uint32_t *orig_len = (uint32_t*)(p + sizeof(uint32_t)*3);
    plen = pcap_pkt_hdrlen + *incl_len;
    if (p+plen > buf+len) goto done;
    /* record as if this is the last packet in the pcap (it might be) */
    end = p - buf;
    et = (*sec) * 1000000L + (*usec);
    /* if this is the first packet in the pcap, record its beg/st too */
    if (beg == 0) {
      beg = end;
      st = et;
    }
    npkts++;
  }

  sc = insert_region(ps, id, beg, st, end, et, npkts);
  if (sc < 0) goto done;

  rc = 0;

 done:
  if (buf) munmap(buf, len);
  return rc;
}


int insert_file(sqlite3_stmt *ps, char *name, int id) {
  int sc, rc = -1;
  
  sc = sqlite3_bind_text(ps, 1, name, -1, SQLITE_TRANSIENT);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_text: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int( ps, 2, id);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  /* insert */
  sc = sqlite3_step(ps);
  if (sc != SQLITE_DONE) {
    fprintf(stderr,"sqlite3_step: unexpected result\n");
    goto done;
  }

  if (reset(ps) < 0) goto done;

  /* insert min/max packets into regions table */
  if (get_extents(CF.insert_regn, name, id) < 0) goto done;

  rc = 0;

 done:
  return rc;
}


int add_file(char *file) {
  int rc = -1, sc;

  sc = insert_file(CF.insert_stmt, file, CF.file_id);
  if (sc < 0) goto done;

  CF.file_id++;
  
  rc = 0;

 done:
  return rc;
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
      if (add_file(path) < 0) goto done;
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

int release_db(void) {
  int sc, rc = -1;

  /* done with select statement */
  sc = sqlite3_finalize(CF.select_stmt);
  if (sc != SQLITE_OK) {
    fprintf(stderr,"sqlite3_finalize: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  /* done with insert statement */
  sc = sqlite3_finalize(CF.insert_stmt);
  if (sc != SQLITE_OK) {
    fprintf(stderr,"sqlite3_finalize: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  /* done with insert statement */
  sc = sqlite3_finalize(CF.insert_regn);
  if (sc != SQLITE_OK) {
    fprintf(stderr,"sqlite3_finalize: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  /* done with delete statement */
  sc = sqlite3_finalize(CF.delete_regn);
  if (sc != SQLITE_OK) {
    fprintf(stderr,"sqlite3_finalize: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sqlite3_close(CF.db); // NULL allowed

  rc = 0;

 done:
  return rc;
}


int print_db(void) {
  const unsigned char *name;
  sqlite3_stmt *ps;
  int64_t beg, st;
  int64_t end, et;
  int64_t id, npkts, n=0;
  int rc = -1;

  ps = CF.select_stmt;
  if (reset(ps) < 0) goto done;
  fprintf(stderr, "\n");

  while (sqlite3_step(ps) == SQLITE_ROW) {

    name =   sqlite3_column_text(ps, 0);
    id  =   sqlite3_column_int64(ps, 1);
    beg =   sqlite3_column_int64(ps, 2);
    st  =   sqlite3_column_int64(ps, 3);
    end =   sqlite3_column_int64(ps, 4);
    et  =   sqlite3_column_int64(ps, 5);
    npkts = sqlite3_column_int64(ps, 6);

    fprintf(stderr, " %ld> %s beg %ld st %ld end %ld et %ld npkts %ld\n", 
      ++n, name, (long)beg, (long)st, (long)end, (long)et, (long)npkts);

  }
  fprintf(stderr, "\n");
  reset(ps);

  rc = 0;

 done:
  return rc;
}

int get_region_packets(struct region *r) {
  int rc = -1, need_map, sc, skip;
  size_t len, plen, sz;
  char *p, *eob, *pkt;
  uint64_t ts;

  assert(CF.map_buf == NULL);

  CF.map_buf = map(r->name, &CF.map_len);
  if (CF.map_buf == NULL) goto done;

  eob = CF.map_buf + CF.map_len;
  for (p = CF.map_buf + r->beg; p < eob; p += plen) {

    /* find packet length. we want incl_len. */
    uint32_t *sec =      (uint32_t*)(p + sizeof(uint32_t)*0);
    uint32_t *usec =     (uint32_t*)(p + sizeof(uint32_t)*1);
    uint32_t *incl_len = (uint32_t*)(p + sizeof(uint32_t)*2);
    uint32_t *orig_len = (uint32_t*)(p + sizeof(uint32_t)*3);

    plen = pcap_pkt_hdrlen + *incl_len;
    if (p + plen > eob) {
      fprintf(stderr, "packet data out of bounds\n");
      goto done;
    }

    ts = (*sec) * 1000000L + (*usec);

    skip = 0;
    if (CF.start_ts && (ts < CF.start_ts)) skip=1;
    if (CF.end_ts   && (ts > CF.end_ts)) skip=1;

    if (CF.copy_pkt_hdr) {
      pkt = p;
      sz = plen;
    } else {
      pkt = p + pcap_pkt_hdrlen;
      sz = plen - pcap_pkt_hdrlen;
    }

    sc = skip ? 0 : shr_write(CF.ring, pkt, sz);
    if (sc < 0) {
      fprintf(stderr, "shr_write: %d\n", sc);
      goto done;
    }

    /* did we just enqueue the last packet in the region? */
    if ((p - CF.map_buf) == r->end) break;
  }

  rc = 0;

 done:
  if (CF.map_buf) {
    munmap(CF.map_buf, CF.map_len);
    CF.map_buf = NULL;
  }
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

int populate_ring(void) {
  int rc = -1, sc, sz, len;
  const unsigned char *name;
  int64_t id, pos, ts;
  sqlite3_stmt *ps;

  ps = CF.select_stmt;
  if (reset(ps) < 0) goto done;

  while (sqlite3_step(ps) == SQLITE_ROW) {

    name =                 sqlite3_column_text(ps, 0);
    CF.region_a.file_id = sqlite3_column_int64(ps, 1);
    CF.region_a.beg =     sqlite3_column_int64(ps, 2);
    CF.region_a.st  =     sqlite3_column_int64(ps, 3);
    CF.region_a.end =     sqlite3_column_int64(ps, 4);
    CF.region_a.et  =     sqlite3_column_int64(ps, 5);
    CF.region_a.npkts=    sqlite3_column_int64(ps, 6);

    len = strlen(name);
    assert(len < sizeof(CF.region_a.name));
    memcpy(CF.region_a.name, name, len+1);

    if (get_region_packets(&CF.region_a) < 0) goto done;
  }

  sc = CF.mark_sz ? shr_write(CF.ring, CF.mark, CF.mark_sz) : 0;
  if (sc < 0) {
    fprintf(stderr, "shr_write: %d\n", sc);
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int delete_region(struct region *r) {
  int sc, rc = -1;
  sqlite3_stmt *ps;

  if (CF.verbose) {
    fprintf(stderr, "deleting region id %ld beg %ld st %ld npkts %ld\n",
     (long)r->file_id, (long)r->beg, (long)r->st, (long)r->npkts);
  }

  ps = CF.delete_regn;
  if (reset(ps) < 0) goto done;

  sc = sqlite3_bind_int( ps, 1, r->file_id);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps, 2, r->beg);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps, 3, r->st);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_step(ps);
  if (sc != SQLITE_DONE) {
    fprintf(stderr,"sqlite3_step: unexpected result\n");
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int bisect_region(sqlite3_stmt *ps, struct region *r) {
  int64_t pn, end_region_1, beg_region_2, pos, ts;
  char *buf = NULL, *p, *eob;
  int sc, rc = -1;
  uint32_t plen;
  size_t len;

  if (r->npkts == 1) {   /* is the region already indivisible? */
    rc = 0;
    goto done;
  }

  if (delete_region(r) < 0) goto done;

  end_region_1 = r->npkts / 2;      /* pn where region 1 ends */
  beg_region_2 = end_region_1 + 1;  /* pn where region 2 starts */

  /* map in the file so we can find a packet boundary */
  buf = map(r->name, &len);
  if (buf == MAP_FAILED) {
    fprintf(stderr, "mmap: %s\n", strerror(errno));
    goto done;
  }

  /* find packet halfway between beg and end */
  pn = 0;
  eob = buf + len;
  for( p = buf + r->beg; p < eob; p += plen) {
    uint32_t *sec =      (uint32_t*)(p + sizeof(uint32_t)*0);
    uint32_t *usec =     (uint32_t*)(p + sizeof(uint32_t)*1);
    uint32_t *incl_len = (uint32_t*)(p + sizeof(uint32_t)*2);
    uint32_t *orig_len = (uint32_t*)(p + sizeof(uint32_t)*3);

    plen = pcap_pkt_hdrlen + *incl_len;
    if (p + plen > eob) {
      fprintf(stderr, "packet data out of bounds\n");
      goto done;
    }

    pos = p - buf;
    ts = (*sec) * 1000000L + (*usec);
    pn++;

    if (pn == end_region_1) {
      sc = insert_region(ps, r->file_id, r->beg, r->st, pos, ts, pn);
      if (sc < 0) goto done;
    }

    if (pn == beg_region_2) {
      sc = insert_region(ps, r->file_id, pos, ts, r->end, r->et, r->npkts-pn+1);
      if (sc < 0) goto done;
      break;
    }
  }

  rc = 0;
 
 done:
  if (buf && (buf != MAP_FAILED)) munmap(buf,len);
  return rc;
}

int bisect_sort(void) {
  const unsigned char *name;
  sqlite3_stmt *ps;
  int sc, rc = -1;
  size_t len;

  memset(&CF.region_a, 0, sizeof(CF.region_a));
  memset(&CF.region_b, 0, sizeof(CF.region_b));

  if (CF.verbose) print_db();
  ps = CF.select_stmt;
  if (reset(ps) < 0) goto done;

  while (sqlite3_step(ps) == SQLITE_ROW) {

    name =                 sqlite3_column_text(ps, 0);
    CF.region_a.file_id = sqlite3_column_int64(ps, 1);
    CF.region_a.beg =     sqlite3_column_int64(ps, 2);
    CF.region_a.st  =     sqlite3_column_int64(ps, 3);
    CF.region_a.end =     sqlite3_column_int64(ps, 4);
    CF.region_a.et  =     sqlite3_column_int64(ps, 5);
    CF.region_a.npkts=    sqlite3_column_int64(ps, 6);

    len = strlen(name);
    assert(len < sizeof(CF.region_a.name));
    memcpy(CF.region_a.name, name, len+1);

    /* is region disjoint from previous region? */
    if (CF.region_a.st >= CF.region_b.et) {
      CF.region_b = CF.region_a; /* struct copy */
      continue;
    }

    /* region_a overlaps region_b. bisect both. */
    if (CF.verbose) fprintf(stderr, "bisecting\n");
    if (bisect_region(CF.insert_regn, &CF.region_a) < 0) goto done;
    if (bisect_region(CF.insert_regn, &CF.region_b) < 0) goto done;

    if (CF.verbose) print_db();

    if (reset(ps) < 0) goto done;
    memset(&CF.region_a, 0, sizeof(CF.region_a));
    memset(&CF.region_b, 0, sizeof(CF.region_b));
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  char *dir = NULL;
  int sc, opt, rc=-1;

  CF.prog = argv[0];

  while ( (opt = getopt(argc,argv,"vphd:r:t:s:b:u:o:OH:W:")) > 0) {
    switch(opt) {
      case 'v': CF.verbose++; break;
      case 'd': dir = strdup(optarg); break;
      case 'r': CF.recurse=atoi(optarg); break;
      case 't': CF.truncate=atoi(optarg); break;
      case 'H': CF.copy_pkt_hdr=atoi(optarg); break;
      case 'p': CF.mode = mode_print; break;
      case 's': CF.suffix = strdup(optarg); break;
      case 'b': CF.db_name = strdup(optarg); break;
      case 'o': CF.ring_name = strdup(optarg); break;
      case 'O': CF.mode = mode_output; break;
      case 'u': CF.time_range = strdup(optarg); break;
      case 'W': CF.mark = strdup(optarg); break;
      case 'h': default: usage(argv[0]); break;
    }
  }

  if (CF.db_name == NULL) usage();
  if (CF.mark) {
    CF.mark_sz = unhex(CF.mark);
    if (CF.mark_sz == -1) goto done;
  }

  if (CF.time_range) {
    sc = sscanf(CF.time_range, "%ld:%ld", &CF.start_ts, &CF.end_ts);
    if (sc != 2) {
      fprintf(stderr, "time range must be in START:STOP format\n");
      goto done;
    }
  }

  if (setup_db() < 0) goto done;

  switch (CF.mode) {
    case mode_build:
     if ((dir == NULL) && (optind >= argc)) usage();
     if (dir) {
       if (realpath(dir, CF.dir) == NULL) {
         fprintf(stderr, "realpath %s: %s\n", dir, strerror(errno));
         goto done;
       }
       if (add_dir(CF.dir) < 0) goto done;
     }
     while ((optind < argc) && (add_file(argv[optind++]) < 0)) goto done;
     if (bisect_sort() < 0) goto done;
     if (CF.ring_name == NULL) break;
     else { /* FALL THRU */ }
    case mode_output:
     if (CF.ring_name == NULL) usage();
     CF.ring = shr_open(CF.ring_name, SHR_WRONLY);
     if (CF.ring == NULL) goto done;
     if (populate_ring() < 0) goto done;
     break;
    case mode_print:
     if (print_db() < 0) goto done;
     break;
    default:
     assert(0);
     goto done;
     break;
  }

  rc = 0;
 
 done:
  if (dir) free(dir);
  if (CF.suffix) free(CF.suffix);
  if (CF.db_name) free(CF.db_name);
  if (CF.ring_name) free(CF.ring_name);
  if (CF.ring) shr_close(CF.ring);
  if (CF.time_range) free(CF.time_range);
  if (CF.mark) free(CF.mark);
  if (CF.map_buf) munmap(CF.map_buf, CF.map_len);
  release_db();
  return rc;
}
