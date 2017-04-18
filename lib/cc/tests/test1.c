#include <stdio.h>
#include "cc.h"

char *conf = __FILE__ "fg";   /* test1.c becomes test1.cfg */

int main() {
  int rc=-1;

  struct cc *cc;
  cc = cc_open(conf, 0);
  if (cc == NULL) goto done;
  cc_close(cc);

 done:
  return rc;
}
