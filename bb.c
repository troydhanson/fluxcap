#include "fluxcap.h"

/*
 * support to vectorize struct iovec and struct bb
 */
UT_mm iov_mm = { . sz = sizeof(struct iovec) };

void bb_init(void *_b) {
  struct bb *b = (struct bb*)_b;
  memset(b,0,sizeof(*b));
  b->n = BATCH_SIZE;
  int mode = MAP_PRIVATE | MAP_ANONYMOUS /* | MAP_LOCKED */;
  b->d = mmap(0, b->n, PROT_READ|PROT_WRITE, mode, -1, 0);
  if (b->d == MAP_FAILED) {
    fprintf(stderr, "mmap: %s\n", strerror(errno));
    abort();
  }
  b->iov = utvector_new(&iov_mm);
  utvector_reserve(b->iov, BATCH_PKTS);
}

void bb_fini(void *_b) {
  struct bb *b = (struct bb*)_b;
  assert (b->d && (b->d != MAP_FAILED));
  munmap(b->d, b->n);
  utvector_free(b->iov);
}

void bb_clear(void *_b) {
  struct bb *b = (struct bb*)_b;
  b->u = 0;
  utvector_clear(b->iov);
}

UT_mm bb_mm = { 
  .sz = sizeof(struct bb),
  .init = bb_init,
  .fini = bb_fini,
  .clear = bb_clear,
};

