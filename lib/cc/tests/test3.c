#include <stdio.h>
#include "cc.h"

char *conf = __FILE__ "fg";   /* test1.c becomes test1.cfg */
#define adim(x) (sizeof(x)/sizeof(*x))


int main() {
  int rc=-1;
  char *s;
  char *out;
  size_t len;

  struct cc_map map[] = {
    {"name", CC_str, &s},
  };

  struct cc *cc;
  cc = cc_open(conf, 0);
  if (cc == NULL) goto done;

  rc = cc_mapv(cc, map, adim(map));
  if (rc < 0) goto done;

  s = "hello";
  if (cc_dump(cc, &out, &len) < 0) 
    printf("error\n");

  cc_close(cc);

 done:
  return rc;
}
