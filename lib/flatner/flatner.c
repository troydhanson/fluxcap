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
#include "libut.h"
#include "flatner.h"

/*
 * flatner
 *
 * given files of timestamped events (such as PCAP)
 * flatner produces a region list without overlaps.
 * it exposes this via an iterator function that 
 * allows the caller to get sequential events from
 * the merged data set
 */

struct iteration_state {
  int ready;    /* is state valid */
  uint64_t pos; /* next item offset */
  size_t   len; /* next item length */
  uint64_t ts;  /* next item timestamp */
};

struct source {
  char name[PATH_MAX];
  char *buf;    /* mapped address   */
  size_t len;   /* mapped length    */
  uint64_t st;
  uint64_t et;
  size_t nr;    /* items in clamped range */
  size_t nc;    /* items iterated */
  struct iteration_state is;
  struct source *prev;
  struct source *next;
};

struct region {
  uint64_t st;
  uint64_t et;
  UT_vector *sources;
  struct region *prev;
  struct region *next;
};

static const UT_mm void_mm = {.sz = sizeof(void*) };

struct flatner {
  next_cb *next;
  struct source *sources; /* DL source list */
  struct region *regions; /* DL region list sorted by time */
  struct region *current; /* current region when iterating */
  uint64_t st;            /* min ts for flatner_clamp */
  uint64_t et;            /* max ts for flatner_clamp */
  int map_clean;          /* need to update mmaps when 0 */
};

struct flatner * flatner_new(next_cb *cb) {
  struct flatner *f;
  int rc = -1;

  f = calloc(1, sizeof(*f));
  if (f == NULL) {
    fprintf(stderr, "out of memory\n");
    goto done;
  }

  f->next = cb;

  rc = 0;

 done:
  return rc ? NULL : f;
}

/* sort by start time. if two regions start at the
 * same time, then sort shorter before longer */
static int64_t sort_by_time(struct region *a, 
                     struct region *b) {
  if (a->st != b->st)      return a->st - b->st;
  /*if (a->st == b->st)*/  return a->et - b->et;
}

/* absorb src into dst. then free src */
static void absorb_region(struct flatner *f,
                   struct region *dst,
                   struct region *src) {

  struct source *s, **v;

  assert(dst->st == src->st);
  assert(dst->et == src->et);

  v = NULL;
  while ( (v = utvector_next(src->sources, v))) {
    s = *v;
    utvector_push(dst->sources, &s);
  }

  DL_DELETE(f->regions, src);
  utvector_free(src->sources);
  free(src);
}

static struct region * dup_region(struct flatner *f,
                   struct region *s) {
  struct region *r = NULL;

  r = calloc(1, sizeof(*r));
  if (r == NULL) {
    fprintf(stderr, "out of memory\n");
    goto done;
  }
  r->st = s->st;
  r->et = s->et;
  r->sources = utvector_new(&void_mm);
  utvector_copy(r->sources, s->sources);
  DL_APPEND(f->regions, r);

 done:
  return r;
}

/* 
 * perform one step of region construction
 * this is the heart of the beast
 *
 * returns 
 *   0  if done
 *   1  if caller should call us again 
 *  -1  on error
 */
static int order_once(struct flatner *f) {
  struct region *r, *p;

  DL_SORT(f->regions, sort_by_time);

  for(r = f->regions; r; r = r->next) {
    if (r == f->regions) continue;
    if (r->st >= r->prev->et) continue;

    if (r->st != r->prev->st) {
      p = dup_region(f, r->prev);
      if (p == NULL) return -1;
      p->et = r->st;
      r->prev->st = r->st;
      return 1;
    }

    assert(r->st == r->prev->st);
    if (r->et == r->prev->et) {
      absorb_region(f, r->prev, r);
      return 1;
    }

    assert(r->et > r->prev->et);
    p = dup_region(f, r);
    if (p == NULL) return -1;
    p->st = r->prev->et;
    r->et = r->prev->et;
    return 1;
  }

  return 0;
}

/* maps a file into memory. caller should clean up
 * by calling munmap(buf,len) when done with file */
static char *map(const char *file, size_t *len) {
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
    buf = NULL;
    goto done;
  }

  rc = 0;
  *len = s.st_size;

 done:
  if (fd != -1) close(fd);
  if (rc && buf) munmap(buf, s.st_size);
  return (rc < 0) ? NULL : buf;
}

/* find the earliest and latest timestamps in file.
 * on return, *nr contains the number of data items
 * (within the min/max clamped range) in the source
 */
static int get_minmax(struct flatner *f, char *file, 
                      uint64_t *min, uint64_t *max, 
                      size_t *nr) {
  int sc, rc = -1;
  char *buf = NULL;
  size_t len;

  uint64_t pos=0, ts=0;
  size_t sz=0, i=0;
  *nr = 0;

  buf = map(file, &len);
  if (buf == NULL) goto done;

  while (1) {
    sc = f->next(file, buf, len, &pos, &sz, &ts);
    if (sc < 0) goto done;
    if (sc == 0) break;
    assert(sc > 0);
    if (f->st && (ts < f->st)) continue;
    if (f->et && (ts > f->et)) break;
    if ((i == 0) || (ts < *min)) *min = ts;
    if ((i == 0) || (ts > *max)) *max = ts;
    (*nr)++;
    i++;
  }
 
  rc = 0;

 done:
  if (buf) munmap(buf, len);
  return rc;
}

/*
 * flatner_add
 *
 * add a file to the region set. 
 * the ordered region list is then 
 * regenerated internally.
 *
 * returns
 *  0 on success
 * -1 on error
 * 
 */
#define MIN(x,y) ( ((x) < (y)) ? (x) : (y))
#define MAX(x,y) ( ((x) > (y)) ? (x) : (y))
int flatner_add(struct flatner *f, char *file) {
  struct source *s;
  struct region *r;
  int rc = -1, sc;
  size_t len, nr;
  uint64_t st, et;

  sc = get_minmax(f, file, &st, &et, &nr);
  if (sc < 0) goto done;
  if (nr == 0) {
    rc = 0;
    goto done;
  }

  s = calloc(1, sizeof(*s));
  if (s == NULL) {
    fprintf(stderr, "out of memory\n");
    goto done;
  }

  len = strlen(file);
  assert(len+1 <= sizeof(s->name));
  memcpy(s->name, file, len+1);
  s->st = st;
  s->et = et;
  s->nr = nr;
  DL_APPEND(f->sources, s);

  r = calloc(1, sizeof(*r));
  if (r == NULL) {
    fprintf(stderr, "out of memory\n");
    goto done;
  }

  r->st = st;
  r->et = et;
  r->sources = utvector_new(&void_mm);
  utvector_push(r->sources, &s);
  DL_APPEND(f->regions, r);

  do {
    rc = order_once(f);
  } while (rc > 0);
  
 done:
  return rc;
}

/* does region r have y as one of its sources? */
static int has_region_source(struct region *r, struct source *y) {
  struct source *s, **v;

  if (r == NULL) return 0;

  v = NULL;
  while ( (v = utvector_next(r->sources, v))) {
    s = *v;
    if (s == y) return 1;
  }

  return 0;
}


/*
 * map_current_region
 *
 * maps the current region's sources into memory,
 * leaving any intact if already mapped
 *
 * any other mappings are unmapped. 
 */
static int map_current_region(struct flatner *f) {
  struct source *s, *tmp;
  int rc = -1;

  if (f->map_clean) return 0;

  DL_FOREACH_SAFE(f->sources, s, tmp) {
    if (has_region_source(f->current,s)) {
      if (s->buf) continue;
      s->buf = map(s->name, &s->len);
      if (s->buf == NULL) goto done;
    } else if (s->buf) {
      munmap(s->buf, s->len);
      s->buf = NULL;
      s->len = 0;
    }
  }

  f->map_clean = 1;
  rc = 0;

 done:
  return rc;
}


/*
 *
 * position_source
 *
 * advances to next item in buffer, unless its already positioned.
 * the latter case is normal because when a multi-source region
 * finds the next item, it positions all its sources at their
 * candidate items and selects the one with the least-timestamp.
 * s->is.ready means the source is already positioned.
 *
 * returns
 *  1 positioned successfully
 *  0 if no items remain in source (current region)
 * -1 on error
 */
static int position_source(struct flatner *f, struct source *s) {
  struct region *r = f->current;
  int sc;

  if (s->is.ready) return 1;

  do {
    sc = f->next(s->name, s->buf, s->len, &s->is.pos, &s->is.len, &s->is.ts);
    if (sc < 0) return -1;
    if (sc == 0) return 0;
    if (s->is.ts > r->et) {  /* item belongs to subsequent region */
      s->is.ready = 1;
      return 0;
    }
  } while (s->is.ts < r->st);

  s->is.ready = 1;
  return 1;
}


static void reset_iteration(struct flatner *f) {
  struct source *s, *tmp;

  /* need region mmap update */
  f->map_clean = 0;

  /* set current region to head */
  f->current = f->regions;

  /* reset sources' iteration state */
  DL_FOREACH_SAFE(f->sources, s, tmp) {
    memset(&s->is, 0, sizeof(s->is));
    s->nc = 0;
  }
}

/*
 * flatner_next
 *
 * get the next data item from the flattened multiregion set
 * the pointer is valid until the next call to flatner_next 
 * or flatner_free.
 *
 * caller resets iteration to the beginning by  *pos = NULL:
 *
 *  char *pos = NULL;
 *  flatner_next(f, &pos, &len, &mc);
 *
 * mc is optional (may be NULL). if non-NULL, it receives
 * an integer (0 or 1) on positive return, indicating if 
 * a map change is imminent. 
 *
 * this is for callers that cache data pointers from
 * calls to flatner_next. the pointers are always valid
 * until the next call to flatner_next or flatner_free.
 * however, they actually remains valid longer-- until
 * the next munmap occurs internally. to utilize this,
 * the caller notes whenever *mc == 1 on positive return.
 * at that time the caller should flush any cached data
 * held as pointers to previous data, before the next 
 * call to flatner_next or flatner_free. 
 *
 * returns 
 *  0 on completion of iteration (no item is returned)
 *  1 if an item is returned
 * -1 on error
 *
 *
 */
int flatner_next(struct flatner *f, char **pos, size_t *len, int *mc) {
  struct source *s, **v, *m;
  int sc;

  if (f->regions == NULL) {
    return 0;
  }

  /* caller wants to restart iteration from beginning? */
  if (*pos == NULL) reset_iteration(f);

 again:

  /* map; leave intact if already mapped */
  if (map_current_region(f) < 0) return -1;

  /* choose the item having min timestamp among sources */
  m = NULL;
  v = NULL;
  while ( (v = utvector_next(f->current->sources, v))) {
    s = *v;
    sc = position_source(f,s);
    if (sc <  0) return -1;
    if (sc == 0) continue;
    if ((m == NULL) || (s->is.ts < m->is.ts)) m = s;
  }

  /* time to move to next region? */
  if (m == NULL) {
    f->map_clean = 0;
    f->current = f->current->next;
    if (f->current) goto again;
    return 0;
  }

  /* done. mark unready so next call gets new element */
  m->is.ready = 0;
  m->nc++;
  if (mc) *mc = (m->nc == m->nr) ? 1 : 0;
  *pos = m->buf + m->is.pos;
  *len = m->is.len;
  return 1;
}

void flatner_describe(struct flatner *f) {
  struct source *s, *stmp, **v;
  struct region *r, *rtmp;
  int ns=0, nr=0;

  DL_FOREACH_SAFE(f->sources, s, stmp) ns++;
  DL_FOREACH_SAFE(f->regions, r, rtmp) nr++;

  printf("%d sources, %d regions\n", ns, nr);

  nr = 0;
  DL_FOREACH_SAFE(f->regions, r, rtmp) {
    printf(" %d: [%lu,%lu]: ", nr, r->st, r->et);
    v = NULL;
    while ( (v = utvector_next(r->sources, v))) {
      s = *v;
      printf(" %s", s->name);
    }
    printf("\n");
    nr++;
  }
}

/*
 * flatner_clamp
 *
 * clamp the iteratable items (from flatner_next)
 * to those within the time bounds.  
 *
 * NOTE!!
 * this call is optional but must be called
 * BEFORE flatner_add if you do use it
 * 
 * if either bound is zero, it is ignored. 
 * e.g. (min=10,max=0) selects items of time 10 and up
 * 
 */
void flatner_clamp(struct flatner *f, uint64_t min, uint64_t max) {
  f->st = min;
  f->et = max;
}

void flatner_free(struct flatner *f) {
  struct source *s, *stmp;
  struct region *r, *rtmp;

  f->current = NULL;
  f->map_clean = 0;
  map_current_region(f);

  DL_FOREACH_SAFE(f->regions, r, rtmp) {
    utvector_free(r->sources);
    free(r);
  }
  DL_FOREACH_SAFE(f->sources, s, stmp) free(s);
  free(f);
}

