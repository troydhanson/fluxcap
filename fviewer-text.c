#include "fluxcap.h"

int init_watch_ui(struct watch_ui *ui) {
  return 0;
}

int fini_watch_ui(struct watch_ui *ui) {
  return 0;
}

int display_rates(struct watch_ui *ui, struct iovec *wiov, size_t niov) {
  int rc = -1;
  size_t i;
  struct ww *w;
  struct iovec *io;

  for(i=0; i < niov; i++) {
    io = &wiov[i];
    assert(io->iov_len == sizeof(struct ww));
    w = (struct ww*)io->iov_base;

    printf("name: %s\n",                  w->name);
    printf("packets per second: %s %s\n", w->ps.str.p, w->ps.str.P);
    printf("bytes per second: %s\n",      w->ps.str.B);
    printf("bits per second: %s %s\n",    w->ps.str.b, w->ps.str.E);
    printf("drops-rx: %s\n",              w->ps.str.rx);
    printf("drops-lag: %s\n",             w->ps.str.rd);
    printf("\n");

  }

  rc = 0;
  return rc;
}
