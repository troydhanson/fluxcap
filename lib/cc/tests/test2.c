#include <stdio.h>
#include "cc.h"

char *conf = __FILE__ "fg";   /* test1.c becomes test1.cfg */
#define adim(x) (sizeof(x)/sizeof(*x))


int main() {
  int rc=-1;
  char *s;
  struct cc_map map[] = {
    {"name", CC_str, &s},
  };

  struct cc *cc;
  cc = cc_open(conf, 0);
  if (cc == NULL) goto done;

  rc = cc_mapv(cc, map, adim(map));
  if (rc < 0) goto done;
  cc_close(cc);

 done:
  return rc;
}
