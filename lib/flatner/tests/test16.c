#include <assert.h>
#include <stdio.h>
#include "flatner.h"

#define file1 __FILE__ ".in"

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

void hexdump(char *buf, size_t len) {
  size_t i,n=0;
  unsigned char c;
  while(n < len) {
    fprintf(stdout,"%08x ", (int)n);
    for(i=0; i < 16; i++) {
      c = (n+i < len) ? buf[n+i] : 0;
      if (n+i < len) fprintf(stdout,"%.2x ", c);
      else fprintf(stdout, "   ");
    }
    for(i=0; i < 16; i++) {
      c = (n+i < len) ? buf[n+i] : ' ';
      if (c < 0x20 || c > 0x7e) c = '.';
      fprintf(stdout,"%c",c);
    }
    fprintf(stdout,"\n");
    n += 16;
  }
}

int main() {
  struct flatner *f = NULL;
  int sc, rc = -1;
  char *loc=NULL;
  size_t sz;

  f = flatner_new(cb);

  sc = flatner_add(f, file1);
  if (sc < 0) goto done;
  flatner_describe(f);

  do {
    sc = flatner_next(f, &loc, &sz, NULL);
    if (sc < 0)  printf("error\n");
    if (sc == 0) printf("eof\n");
    if (sc > 0)  hexdump(loc, sz);
  } while (sc > 0);

  rc = 0;

 done:
  if (f) flatner_free(f);
  return rc;
}
