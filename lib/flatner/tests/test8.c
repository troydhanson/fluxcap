#include <assert.h>
#include <stdio.h>
#include "flatner.h"

#define file1 __FILE__ ".in1"
#define file2 __FILE__ ".in2"
#define file3 __FILE__ ".in3"

int cb(char *name, char *buf, size_t len, uint64_t *pos, size_t *sz, uint64_t *ts) {
  uint64_t end, i = 0;
  char c;

  *ts = 0;

  /* skip over previously returned item. 
   * works on initial state (sz==0) too.*/
  *pos = (*pos) + (*sz);
  end = *pos;

  while(buf + end < buf+len) {
    c = buf[end++];
    if ((c >= '0') && (c <= '9')) {
      *ts = (*ts * 10) + (c - '0');
      i++;
    }
    else if ((c == ' ') || (c == '\n')) {
      if (i == 0) continue; /* leading space */
      assert(i > 0);
      *sz = end - *pos;
      return 1;
    }
    else return -1;
  }

  return (i > 0) ? 1 : 0;
}

int main() {
  struct flatner *f = NULL;
  int sc, rc = -1;
  char *loc=NULL;
  size_t sz;

  f = flatner_new(cb);

  sc = flatner_add(f, file1);
  if (sc < 0) goto done;

  sc = flatner_add(f, file2);
  if (sc < 0) goto done;

  sc = flatner_add(f, file3);
  if (sc < 0) goto done;

  flatner_describe(f);

  do {
    sc = flatner_next(f, &loc, &sz, NULL);
    if (sc < 0)  printf("error\n");
    if (sc == 0) printf("eof\n");
    if (sc > 0)  printf(" -> %.*s", (int)sz, loc);
  } while (sc > 0);

  rc = 0;

 done:
  if (f) flatner_free(f);
  return rc;
}
