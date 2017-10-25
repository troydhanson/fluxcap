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
 * this is a batch oriented tool primarily for testing
 *
 *
 */

struct {
  int verbose;
  char *prog;
  enum {mode_build, mode_print, mode_flush} mode;

  /* file structure to index */
  char dir[PATH_MAX];
  int recurse;
  char *suffix;
  int file_id;

  /* db info */
  char *db_name;
  sqlite3 *db;
  sqlite3_stmt *insert_stmt;
  sqlite3_stmt *select_stmt;
  sqlite3_stmt *select_rnge;
  sqlite3_stmt *insert_rcrd;
  int truncate;

  /* ring */
  char *ring_name;
  struct shr *ring;

  /* output mode state */
  char  map_name[PATH_MAX];
  char *map_buf;
  off_t map_len;
  char *time_range;
  int copy_pkt_hdr;

} CF = {
  .mode = mode_build,
  .recurse = 1,
  .truncate = 1,
  .copy_pkt_hdr = 0,
};

void usage() {
  fprintf(stderr, "usage: %s [options] -b <dbfile>\n", CF.prog);
  fprintf(stderr, "\n");
  fprintf(stderr, "build mode (default):\n");
  fprintf(stderr, "   -d <dir>      (directory root to scan)\n");
  fprintf(stderr, "   -r [0|1]      (scan recursively; default: 1)\n");
  fprintf(stderr, "   -t [0|1]      (truncate db; default: 1)\n");
  fprintf(stderr, "   -s <suffix>   (only files matching suffix)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "print mode:\n");
  fprintf(stderr, "   -p            (print db)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "ring flush mode:\n");
  fprintf(stderr, "   -o <ring>     (output packet ring)\n");
  fprintf(stderr, "   -u <from:to>  (time range; epoch usec)\n");
  fprintf(stderr, "   -H [0:1]      (copy packet hdr; default: 0)\n");
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

  /* packets table */
  sql = "CREATE TABLE IF NOT EXISTS packets "
        "(id INTEGER, pos INTEGER, ts INTEGER);";
  if (exec_sql(CF.db, sql) < 0) goto done;

  /* truncate */
  if (CF.truncate && (CF.mode == mode_build)) {
    if (exec_sql(CF.db, "DELETE FROM files;")   < 0) goto done;
    if (exec_sql(CF.db, "DELETE FROM packets;") < 0) goto done;
  }

  /* index */
  sql = "CREATE INDEX IF NOT EXISTS by_ts ON packets(ts);";
  if (exec_sql(CF.db, sql) < 0) goto done;

  /* prepare select statement */
  sql = "SELECT f.name, p.pos, p.ts "
        "FROM files f, packets p "
        "WHERE p.id = f.id "
        "ORDER BY p.ts;";
  if (prep_sql(CF.db, sql, &CF.select_stmt) < 0) goto done;

  /* prepare select range statement */
  sql = "SELECT f.name, p.pos, p.ts "
        "FROM files f, packets p "
        "WHERE p.id = f.id "
        "  AND p.ts BETWEEN $A AND $B "
        "ORDER BY p.ts;";
  if (prep_sql(CF.db, sql, &CF.select_rnge) < 0) goto done;

  /* prepare insert statement - we substitute values in later */
  sql = "INSERT INTO packets VALUES ($ID, $POS, $TS);";
  if (prep_sql(CF.db, sql, &CF.insert_rcrd) < 0) goto done;

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

  rc = 0;

 done:
  return rc;
}

int insert_packet(sqlite3_stmt *ps, int id, size_t pos, int64_t ts) {
  int sc, rc = -1;
  
  sc = sqlite3_bind_int( ps, 1, id);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps, 2, pos);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( ps, 3, ts);
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


/* scan file and enter its packets into table */
int get_packets(sqlite3_stmt *ps, char *file, int id) {
  int sc, rc = -1;
  size_t len, plen;
  char *p, *buf=NULL;
  uint64_t ts;

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
    ts = (*sec) * 1000000L + (*usec);
    sc = insert_packet(ps, id, p-buf, ts);
    if (sc < 0) goto done;
  }

  rc = 0;

 done:
  if (buf) munmap(buf, len);
  return rc;
}

int add_file(char *file) {
  int rc = -1, sc;

  /* add file reference to file table */
  sc = insert_file(CF.insert_stmt, file, CF.file_id);
  if (sc < 0) goto done;

  /* open the file up, find packets, insert them */
  sc = get_packets(CF.insert_rcrd, file, CF.file_id);
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
      if (add_file(path) < 0) goto done;
      if (CF.verbose) fprintf(stderr, "adding regular file %s\n", path);
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

  /* done with select range statement */
  sc = sqlite3_finalize(CF.select_rnge);
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
  sc = sqlite3_finalize(CF.insert_rcrd);
  if (sc != SQLITE_OK) {
    fprintf(stderr,"sqlite3_finalize: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sqlite3_close(CF.db); // NULL allowed

  rc = 0;

 done:
  return rc;
}

int setup_query(sqlite3_stmt **ps) {
  long start_ts, end_ts;
  int rc = -1, sc;

  if (CF.time_range == NULL) { /* not range limited? */
    *ps = CF.select_stmt;
    rc = 0;
    goto done;
  }

  /* bind parameters to date range */
  *ps = CF.select_rnge;

  sc = sscanf(CF.time_range, "%ld:%ld", &start_ts, &end_ts);
  if (sc != 2) {
    fprintf(stderr, "time range must be in START:STOP format\n");
    goto done;
  }

  sc = sqlite3_bind_int64( *ps, 1, start_ts);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  sc = sqlite3_bind_int64( *ps, 2, end_ts);
  if (sc != SQLITE_OK) {
    fprintf(stderr, "sqlite3_bind_int: %s\n", sqlite3_errstr(sc));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int print_db(void) {
  const unsigned char *name;
  sqlite3_stmt *ps;
  int64_t pos, ts;
  int rc = -1;

  if (setup_query(&ps) < 0) goto done;

  while (sqlite3_step(ps) == SQLITE_ROW) {

    name = sqlite3_column_text(ps, 0);
    pos = sqlite3_column_int64(ps, 1);
    ts  = sqlite3_column_int64(ps, 2);

    printf("%s: pos %ld: usec: %ld\n", name, (long)pos, (long)ts);

  }

  rc = 0;

 done:
  return rc;
}

int put_packet(const char *name, int64_t pos) {
  int rc = -1, need_map, sc;
  size_t len, plen;
  char *p, *eob;

  /* is the right file already mapped into memory? */
  len = strlen(name);
  need_map = CF.map_buf ?  memcmp(name, CF.map_name, len+1) : 1;

  if (need_map && CF.map_buf) {
    sc = munmap(CF.map_buf, CF.map_len);
    if (sc < 0) {
      fprintf(stderr, "munmap: %s\n", strerror(errno));
      goto done;
    }
    CF.map_buf = NULL;
  }

  if (need_map) {
    CF.map_buf = map(name, &CF.map_len);
    if (CF.map_buf == NULL) goto done;
    memcpy(CF.map_name, name, len+1);
  }

  /* the right file is mapped into memory. */
  assert(CF.map_buf);
  assert(CF.map_len > pos);
  eob = CF.map_buf + CF.map_len;

  p = CF.map_buf + pos;
  if (p + pcap_pkt_hdrlen > eob) {
    fprintf(stderr, "packet header out of bounds\n");
    goto done;
  }

  /* find packet length. we want incl_len. */
  uint32_t *sec =      (uint32_t*)(p + sizeof(uint32_t)*0);
  uint32_t *usec =     (uint32_t*)(p + sizeof(uint32_t)*1);
  uint32_t *incl_len = (uint32_t*)(p + sizeof(uint32_t)*2);
  uint32_t *orig_len = (uint32_t*)(p + sizeof(uint32_t)*3);

  plen = *incl_len;
  if (p + pcap_pkt_hdrlen + plen > eob) {
    fprintf(stderr, "packet data out of bounds\n");
    goto done;
  }

  char *pkt = CF.copy_pkt_hdr ? p : (p + pcap_pkt_hdrlen);
  size_t sz = CF.copy_pkt_hdr ? (pcap_pkt_hdrlen + plen) : plen;

  sc = shr_write(CF.ring, pkt, sz);
  if (sc < 0) {
    fprintf(stderr, "shr_write: %d\n", sc);
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int populate_ring(void) {
  const unsigned char *name;
  int64_t pos, ts;
  sqlite3_stmt *ps;
  int rc = -1, sc;

  if (setup_query(&ps) < 0) goto done;

  while (sqlite3_step(ps) == SQLITE_ROW) {

    name = sqlite3_column_text(ps, 0);
    pos = sqlite3_column_int64(ps, 1);
    ts  = sqlite3_column_int64(ps, 2);

    if (put_packet(name, pos) < 0) goto done;

  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  char *dir = NULL;
  int opt, rc=-1;

  CF.prog = argv[0];

  while ( (opt = getopt(argc,argv,"vphd:r:t:s:b:u:o:H:")) > 0) {
    switch(opt) {
      case 'v': CF.verbose++; break;
      case 'd': dir = strdup(optarg); break;
      case 'r': CF.recurse=atoi(optarg); break;
      case 't': CF.truncate=atoi(optarg); break;
      case 'H': CF.copy_pkt_hdr=atoi(optarg); break;
      case 'p': CF.mode = mode_print; break;
      case 's': CF.suffix = strdup(optarg); break;
      case 'b': CF.db_name = strdup(optarg); break;
      case 'o': CF.ring_name = strdup(optarg); CF.mode = mode_flush; break;
      case 'u': CF.time_range = strdup(optarg); break;
      case 'h': default: usage(argv[0]); break;
    }
  }

  if (CF.db_name == NULL) usage();
  if (setup_db() < 0) goto done;

  switch (CF.mode) {
    case mode_build:
     if (dir == NULL) usage();
     if (realpath(dir, CF.dir) == NULL) {
       fprintf(stderr, "realpath %s: %s\n", dir, strerror(errno));
       goto done;
     }
     if (add_dir(CF.dir) < 0) goto done;
     break;
    case mode_print:
     if (print_db() < 0) goto done;
     break;
    case mode_flush:
     if (CF.ring_name == NULL) usage();
     CF.ring = shr_open(CF.ring_name, SHR_WRONLY);
     if (CF.ring == NULL) goto done;
     if (populate_ring() < 0) goto done;
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
  if (CF.map_buf) munmap(CF.map_buf, CF.map_len);
  release_db();
  return rc;
}
