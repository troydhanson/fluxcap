#include <stdio.h>
#include "flatner.h"
int main() {
  struct flatner *f = NULL;
  f = flatner_new(NULL);
  if (f) printf("flatner_new: ok\n");
  if (f) flatner_free(f);
  return 0;
}
