#include <assert.h>
#include <stdio.h>
#include "flatner.h"

#define file1 "ping.pcap"

#define PCAP_GLOBAL_HDR_LEN 24

int cb(char *name, char *buf, size_t len, uint64_t *pos, size_t *sz, uint64_t *ts) {
  char *p;

  /* in initial state (sz==0) skip pcap global header.
   * otherwise, skip over previously returned item. */
  if (*sz == 0) *sz = PCAP_GLOBAL_HDR_LEN;
  *pos = (*pos) + (*sz);

  if (buf + (*pos) + (4*sizeof(uint32_t)) > buf+len) return 0;

  p = buf + *pos;
  uint32_t *sec =      (uint32_t*)p;
  uint32_t *usec =     (uint32_t*)((char*)sec      + sizeof(*sec));
  uint32_t *incl_len = (uint32_t*)((char*)usec     + sizeof(*usec));
  uint32_t *orig_len = (uint32_t*)((char*)incl_len + sizeof(*incl_len));
  p += 4*sizeof(uint32_t);
  if (p + (*incl_len) > buf+len) {
    fprintf(stderr, "packet truncated\n");
    return 0;
  }
  *sz = 4*sizeof(uint32_t) + (*incl_len);
  *ts = (*sec * 1000000UL) + *usec;
  return 1;
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

  uint64_t st = 1508741440440923;
  uint64_t et = st + 1000000; 

  flatner_clamp(f, st, et);

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
