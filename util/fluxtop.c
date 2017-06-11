#include <errno.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <ncurses.h>
#include <assert.h>
#include "shr.h"
#include "libut.h"
#include "tpl.h"

/* 
 * fluxtop
 * 
 * displays in/out/loss rates for the given ring(s) in a "top"-like manner
 * 
 */

#define STAT_BUCKETS 10  /* number of samples over which rates are averaged */

struct {
  int verbose;
  char *prog;
  enum {mode_monitor, mode_notty} mode;
  enum {unit_bit, unit_pkt} unit; /* throughput in bits/s or pkts/s */
  char *file;
  int ticks;
  int signal_fd;
  int epoll_fd;
  struct shr *ring;
  int stat_bkt;
  size_t size;
  UT_vector /* of ptr */ *aux_rings; 
  UT_vector /* of utstring */ *aux_names; 
  UT_vector /* of struct shr_stat s[STAT_BUCKET] */ *stat; 
  struct shr_stat s[STAT_BUCKETS];
  UT_string *tmp;
  UT_string *rates;
  struct timeval now;
  tpl_node *tn;
  /* ncurses screen sz */
  unsigned rows;
  unsigned cols;
} cfg = {
  .signal_fd = -1,
  .epoll_fd = -1,
};

typedef struct shr_stat ring_trend[STAT_BUCKETS];
UT_mm _utmm_ptr = {.sz = sizeof(void*)};
UT_mm* utmm_ptr = &_utmm_ptr;
UT_mm _utmm_shr_stat = {.sz = sizeof(ring_trend)};
UT_mm* utmm_shr_stat = &_utmm_shr_stat;

void usage() {
  fprintf(stderr,"usage: %s [-m|-r] <ring> [<ring> ...]\n"
                 "\n"
                 " -m  (ncurses mode; default)\n"
                 " -r  (raw mode; print counters)\n"
                 "\n",
          cfg.prog);
  exit(-1);
}

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

int new_epoll(int events, int fd) {
  int rc;
  struct epoll_event ev;
  memset(&ev,0,sizeof(ev)); // placate valgrind
  ev.events = events;
  ev.data.fd= fd;
  if (cfg.verbose) fprintf(stderr,"adding fd %d to epoll\n", fd);
  rc = epoll_ctl(cfg.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

/* get b-a in usec */
#define MILLION 1000000
unsigned long subtract_timeval(struct timeval *b, struct timeval *a) {
  unsigned long au = a->tv_sec * MILLION + a->tv_usec;
  unsigned long bu = b->tv_sec * MILLION + b->tv_usec;
  return (bu > au) ? (bu - au) : 0;
}

/* returns volatile memory - use immediately or copy.
 * takes bits-per-second as input, returns like "20 Mbit/s"
 * where "bit" is the unit, can also be "pkt" etc.
 * using whatever SI unit is most readable (K,M,G,T) 
 */
char *format_rate(unsigned long bps, char *unit) {
  double b = bps;
  char c = ' ';
  if (b > 1024) { b /= 1024; c = 'K'; }
  if (b > 1024) { b /= 1024; c = 'M'; }
  if (b > 1024) { b /= 1024; c = 'G'; }
  if (b > 1024) { b /= 1024; c = 'T'; }
  utstring_clear(cfg.tmp);
  utstring_printf(cfg.tmp, "%10.2f %c%s/s", b, c, unit);
  return utstring_body(cfg.tmp);
}

int update_rates(int use_sample) {
  struct shr **r;
  struct shr_stat stat,sum,*sa,*ss;
  struct timeval ts;
  int rc = -1, sc, i, j;
  UT_string *n;
  char *s;
  unsigned long usec;
  double bps_r, bps_w, bps_l;
  double mps_r, mps_w, mps_l;
  struct timeval oldest;
  ring_trend *t;

  utstring_clear(cfg.rates);

  tpl_node *tn = NULL;
  tn = tpl_map("A(sffffffUUUUUUUUU)", &s, 
        &bps_r, &bps_w, &bps_l, 
        &mps_r, &mps_w, &mps_l, 
        &stat.bw, &stat.br, 
        &stat.mw, &stat.mr, 
        &stat.md, &stat.bd, 
        &stat.bn,
        &stat.bu, &stat.mu);
  if (tn == NULL) goto done;

  r = NULL;
  n = NULL;
  t = NULL;
  while ( (r = (struct shr**)utvector_next(cfg.aux_rings, r)) != NULL) {
    n = (UT_string*)utvector_next(cfg.aux_names, n); assert(n);
    t = (ring_trend*)utvector_next(cfg.stat, t); assert(t);
    sa = *t;
    sc = shr_stat(*r, &stat, &cfg.now);
    if ( sc < 0) { fprintf(stderr, "shr_stat: error\n"); goto done; }

    if (use_sample == 0) continue; 

    sa[cfg.stat_bkt] = stat; /* struct copy */

    /* loop over the stats buckets, calculate aggregate totals */
    memset(&sum,0,sizeof(sum));
    memset(&oldest,0,sizeof(oldest));

    /* advance through the slots, summing the counters */
    i = (cfg.stat_bkt + 1 ) % STAT_BUCKETS;

    for(j = 0; j < STAT_BUCKETS; j++) {
        ss = &sa[(i+j)%STAT_BUCKETS];

        /* when the ring is full, the oldest slot always follows the
         * current (new sample) slot. but during early execution, when
         * fewer than STAT_BUCKETS samples exist in the ring, we find
         * the oldest slot by advancing until we find a non-empty one. */
        if ((oldest.tv_sec == 0) && (ss->start.tv_sec != 0)) {
          oldest = ss->start;
        }

        sum.bw += ss->bw;
        sum.br += ss->br;
        sum.mw += ss->mw;
        sum.mr += ss->mr;
        sum.md += ss->md;
        sum.bd += ss->bd;
    }
    
    usec = subtract_timeval(&cfg.now, &oldest);

    /* calculate bit-per-second read and written, omitting frame headers */
    bps_r = (sum.br - sum.mr * sizeof(size_t)) * 8.0 * MILLION / usec;
    bps_w = (sum.bw - sum.mw * sizeof(size_t)) * 8.0 * MILLION / usec;
    bps_l = (sum.bd - sum.md * sizeof(size_t)) * 8.0 * MILLION / usec;
    /* calculate pkt-per-second read and written */
    mps_r = sum.mr * MILLION * 1.0 / usec;
    mps_w = sum.mw * MILLION * 1.0 / usec;
    mps_l = sum.md * MILLION * 1.0 / usec;
    s = utstring_body(n);
    tpl_pack(tn, 1);

    /*
    printf("bw %ld, br %ld, mw %ld, mr %ld, md %ld, bd %ld, bn %ld, bu %ld mu %ld\n",
        stat.bw, stat.br, stat.mw, stat.mr, stat.md, stat.bd, stat.bn, stat.bu, stat.mu);
    */
  }

  cfg.stat_bkt = (cfg.stat_bkt + 1) % STAT_BUCKETS;

  /* store a flat buffer encoding all the stats for all the rings */
  size_t needed;
  tpl_dump(tn, TPL_GETSIZE, &needed);
  utstring_reserve(cfg.rates, needed); 
  assert(cfg.rates->n >= needed);
  tpl_dump(tn, TPL_MEM|TPL_PREALLOCD, cfg.rates->d, cfg.rates->n);
  cfg.rates->i = needed;

  rc = 0;

 done:
  if (tn) tpl_free(tn);
  return rc;
}

int dump_rates_curses() {
  int rc = -1, x,y;
  tpl_node *tn = NULL;
  struct shr_stat stat;
  char *s;
  double bps_r, bps_w, bps_l;
  double mps_r, mps_w, mps_l;

  clear();

  if (cfg.rates->i == 0) goto done; // no data ready

  tn = tpl_map("A(sffffffUUUUUUUUU)", &s, 
        &bps_r, &bps_w, &bps_l, 
        &mps_r, &mps_w, &mps_l, 
        &stat.bw, &stat.br, 
        &stat.mw, &stat.mr, 
        &stat.md, &stat.bd, 
        &stat.bn,
        &stat.bu, &stat.mu);
  if (tn == NULL) goto done;
  if (tpl_load(tn, TPL_MEM, cfg.rates->d, cfg.rates->i) < 0) goto done;

  attron(A_BOLD);
  move(0, 0); printw("ring");
  move(0,30); printw("in");
  move(0,50); printw("out");
  move(0,70); printw("loss");
  attrset(A_NORMAL);
  //attron(COLOR_PAIR(1));
  //attroff(COLOR_PAIR(1));
  x = 1;
  y = 2;
  while (tpl_unpack(tn,1) > 0) {
    move(y, 0); printw(s);
    if (cfg.unit == unit_bit) {
      move(y,20); printw( format_rate(bps_w,"bit") );
      move(y,40); printw( format_rate(bps_r,"bit") );
      move(y,60); if (stat.bd) printw( format_rate(bps_l,"bit") );
    } else if (cfg.unit == unit_pkt) {
      move(y,20); printw( format_rate(mps_w,"pkt") );
      move(y,40); printw( format_rate(mps_r,"pkt") );
      move(y,60); if (stat.bd) printw( format_rate(mps_l,"pkt") );
    } else {
      assert(0);
      goto done;
    }
    y++;
    
    /*
    fprintf(stderr,"%s %f %f %f bw %ld, br %ld, mw %ld, mr %ld, md %ld, bd %ld, bn %ld, bu %ld mu %ld\n",
        s, bps_r, bps_w, bps_l,
        stat.bw, stat.br, stat.mw, stat.mr, stat.md, stat.bd, stat.bn, stat.bu, stat.mu);
    */
    
    free(s);
  }

  y++;
  attron(A_BOLD);
  move(y,30);
  printw("  q: quit, space: toggle units");
  attroff(A_BOLD);
  refresh();

  rc = 0;

 done:

  if (tn) tpl_free(tn);
  return rc;
}

int dump_rates_notty() {
  int rc = -1;
  tpl_node *tn = NULL;
  struct shr_stat stat;
  char *s;
  double bps_r, bps_w, bps_l;

  if (cfg.rates->i == 0) goto done; // no data ready

  tn = tpl_map("A(sfffUUUUUUUUU)", &s, &bps_r, &bps_w, &bps_l, 
        &stat.bw, &stat.br, &stat.mw, &stat.mr, &stat.md, &stat.bd, &stat.bn,
        &stat.bu, &stat.mu);
  if (tn == NULL) goto done;
  if (tpl_load(tn, TPL_MEM, cfg.rates->d, cfg.rates->i) < 0) goto done;
  while (tpl_unpack(tn,1) > 0) {
    printf("%s %f %f %f bw %ld, br %ld, mw %ld, mr %ld, md %ld, bd %ld, bn %ld, bu %ld mu %ld\n",
        s, bps_r, bps_w, bps_l,
        stat.bw, stat.br, stat.mw, stat.mr, stat.md, stat.bd, stat.bn, stat.bu, stat.mu);
    free(s);
  }

  rc = 0;

 done:

  if (tn) tpl_free(tn);
  return rc;
}

int update() {
  int rc = -1;

  gettimeofday(&cfg.now, NULL);
  if (update_rates(1) < 0) goto done;

  switch(cfg.mode) {
    case mode_notty:
      if (dump_rates_notty() < 0) goto done;
      break;
    case mode_monitor:
      if (dump_rates_curses() < 0) goto done;
      break;
  }

  rc = 0;

 done:
  return rc;
}

int handle_signal(void) {
  int rc=-1;
  struct signalfd_siginfo info;
  
  if (read(cfg.signal_fd, &info, sizeof(info)) != sizeof(info)) {
    fprintf(stderr,"failed to read signal fd buffer\n");
    goto done;
  }

  switch(info.ssi_signo) {
    case SIGALRM: 
      cfg.ticks++;
      gettimeofday(&cfg.now, NULL);
      alarm(1); 
      break;
    default: 
      fprintf(stderr,"got signal %d\n", info.ssi_signo);  
      goto done;
      break;
  }

 rc = 0;

 done:
  return rc;
}

int handle_keypress(void) {
  int rc= -1, bc;
  char c;

  bc = read(STDIN_FILENO, &c, sizeof(c));
  if (bc <= 0) goto done;
  if (c == 'q') goto done; /* quit program */
  if (c == ' ') {          /* toggle bit/s or msgs/s */
    cfg.unit = (cfg.unit == unit_pkt) ? unit_bit : unit_pkt;
  }
  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  struct epoll_event ev;
  cfg.prog = argv[0];
  int rc = -1, n, opt, ring_mode, ec;
  char *file, unit;
  struct shr *r;
  void **p;

  cfg.aux_rings = utvector_new(utmm_ptr);
  cfg.aux_names = utvector_new(utstring_mm);
  cfg.stat = utvector_new(utmm_shr_stat);
  utstring_new(cfg.tmp);
  utstring_new(cfg.rates);

  while ( (opt=getopt(argc,argv,"vhs:mr")) != -1) {
    switch(opt) {
      case 'm': cfg.mode = mode_monitor; break;
      case 'r': cfg.mode = mode_notty; break;
      case 'v': cfg.verbose++; break;
      case 'h': default: usage(); break;
      case 's':
         n = sscanf(optarg, "%ld%c", &cfg.size, &unit);
         if (n == 0) usage();
         if (n == 2) {
            switch (unit) {
              case 't': case 'T': cfg.size *= 1024; /* fall through */
              case 'g': case 'G': cfg.size *= 1024; /* fall through */
              case 'm': case 'M': cfg.size *= 1024; /* fall through */
              case 'k': case 'K': cfg.size *= 1024; break;
              default: usage(); break;
            }
         }
         break;
    }
  }

  /* not a terminal? use regular basic text */
  if ((isatty(STDOUT_FILENO) == 0) && (cfg.mode == mode_monitor)) {
    cfg.mode = mode_notty;
  }

  /* block all signals. we take signals synchronously via signalfd */
  sigset_t all;
  sigfillset(&all);
  sigprocmask(SIG_SETMASK,&all,NULL);

  /* a few signals we'll accept via our signalfd */
  sigset_t sw;
  sigemptyset(&sw);
  for(n=0; n < sizeof(sigs)/sizeof(*sigs); n++) sigaddset(&sw, sigs[n]);

  /* create the signalfd for receiving signals */
  cfg.signal_fd = signalfd(-1, &sw, 0);
  if (cfg.signal_fd == -1) {
    fprintf(stderr,"signalfd: %s\n", strerror(errno));
    goto done;
  }
  /* set up the epoll instance */
  cfg.epoll_fd = epoll_create(1); 
  if (cfg.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  /* add descriptors of interest */
  if (new_epoll(EPOLLIN, cfg.signal_fd)) goto done; // signals

  if (optind >= argc) usage();
  while (optind < argc) {
    file = argv[optind++];
    utstring_clear(cfg.tmp);
    utstring_printf(cfg.tmp, "%s", file);
    utvector_push(cfg.aux_names, cfg.tmp);
    utvector_extend(cfg.stat);
    r = shr_open(file, SHR_RDONLY);
    if (r == NULL) goto done;
    utvector_push(cfg.aux_rings, &r);
  }

  /* call once before initializing curses so errors are visible */
  if (update_rates(0) < 0) goto done;

  if (cfg.mode == mode_monitor) {
    initscr();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_GREEN);
    getmaxyx(stdscr, cfg.rows, cfg.cols);
    curs_set(0); // cursor visibilty (0=hide; 1=normal)
    clear();
    if (new_epoll(EPOLLIN, STDIN_FILENO)) goto done; /* keypress */
  }

  alarm(1);

  do { 
    ec = epoll_wait(cfg.epoll_fd, &ev, 1, 500);
    if      (ec < 0)  fprintf(stderr, "epoll: %s\n", strerror(errno));
    else if (ec == 0) update();
    else if (ev.data.fd == cfg.signal_fd) { if (handle_signal()  < 0) goto done; }
    else if (ev.data.fd == STDIN_FILENO)  { if (handle_keypress()  < 0) goto done; }
  } while (ec >= 0);

  rc = 0;

done:
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.ring) shr_close(cfg.ring);
  p = NULL; while ( (p = utvector_next(cfg.aux_rings, p)) != NULL) shr_close(*p);
  utvector_free(cfg.aux_rings);
  utvector_free(cfg.aux_names);
  utvector_free(cfg.stat);
  utstring_free(cfg.tmp);
  utstring_free(cfg.rates);
  if (cfg.mode == mode_monitor) endwin();
  return rc;
}
