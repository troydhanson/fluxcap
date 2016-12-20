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
 *
 * 
 */

struct {
  int verbose;
  char *prog;
  enum {mode_monitor, mode_notty} mode;
  char *file;
  int ticks;
  int signal_fd;
  int epoll_fd;
  struct shr *ring;
  size_t size;
  UT_vector /* of ptr */ *aux_rings; 
  UT_vector /* of utstring */ *aux_names; 
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

UT_mm _utmm_ptr = {.sz = sizeof(void*)};
UT_mm* utmm_ptr = &_utmm_ptr;

void usage() {
  fprintf(stderr,"usage: %s [-m|-n] [options] <ring> ...\n"
                 "\n"
                 " monitor:        -m <ring> ...\n"
                 " no tty:         -n <ring> ...\n"
                 "\n"
                 "additional options:\n"
                 "\n"
                 "           -v           (verbose)\n"
                 "\n"
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
 * using whatever SI unit is most readable (K,M,G,T) 
 */
char *format_rate(unsigned long bps) {
  double b = bps;
  char c = ' ';
  if (b > 1024) { b /= 1024; c = 'K'; }
  if (b > 1024) { b /= 1024; c = 'M'; }
  if (b > 1024) { b /= 1024; c = 'G'; }
  if (b > 1024) { b /= 1024; c = 'T'; }
  utstring_clear(cfg.tmp);
  utstring_printf(cfg.tmp, "%10.2f %cbit/s", b, c);
  return utstring_body(cfg.tmp);
}

int update_rates() {
  struct shr **r;
  struct shr_stat stat;
  struct timeval ts;
  int rc = -1, sc;
  UT_string *n;
  char *s;
  unsigned long age;
  double bps_r, bps_w, bps_l;

  utstring_clear(cfg.rates);

  tpl_node *tn = NULL;
  tn = tpl_map("A(sfffUUUUUUUUU)", &s, &bps_r, &bps_w, &bps_l, 
        &stat.bw, &stat.br, &stat.mw, &stat.mr, &stat.md, &stat.bd, &stat.bn,
        &stat.bu, &stat.mu);
  if (tn == NULL) goto done;

  r = NULL;
  n = NULL;
  while ( (r = (struct shr**)utvector_next(cfg.aux_rings, r)) != NULL) {
    n = (UT_string*)utvector_next(cfg.aux_names, n); assert(n);
    sc = shr_stat(*r, &stat, &cfg.now);
    if ( sc < 0) { fprintf(stderr, "shr_stat: error\n"); goto done; }
    
    age = subtract_timeval(&cfg.now, &stat.start);
    if (age < 0) continue;
    if (age > 10000000) continue; /* too long stats window */
    if (age < 10000) continue;    /* too short stats window */ 

    /* calculate bit-per-second read and written, omitting frame headers */
    bps_r = (stat.br - stat.mr * sizeof(size_t)) * 8.0 / age * MILLION;
    bps_w = (stat.bw - stat.mw * sizeof(size_t)) * 8.0 / age * MILLION;
    bps_l = (stat.bd - stat.md * sizeof(size_t)) * 8.0 / age * MILLION;
    s = utstring_body(n);
    tpl_pack(tn, 1);

    /*
    printf("bw %ld, br %ld, mw %ld, mr %ld, md %ld, bd %ld, bn %ld, bu %ld mu %ld\n",
        stat.bw, stat.br, stat.mw, stat.mr, stat.md, stat.bd, stat.bn, stat.bu, stat.mu);
    */
  }

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

  clear();

  if (cfg.rates->i == 0) goto done; // no data ready

  tn = tpl_map("A(sfffUUUUUUUUU)", &s, &bps_r, &bps_w, &bps_l, 
        &stat.bw, &stat.br, &stat.mw, &stat.mr, &stat.md, &stat.bd, &stat.bn,
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
    move(y,20); printw( format_rate(bps_w) );
    move(y,40); printw( format_rate(bps_r) );
    move(y,60); if (stat.bd) printw( format_rate(bps_l) );
    y++;
    
    /*
    fprintf(stderr,"%s %f %f %f bw %ld, br %ld, mw %ld, mr %ld, md %ld, bd %ld, bn %ld, bu %ld mu %ld\n",
        s, bps_r, bps_w, bps_l,
        stat.bw, stat.br, stat.mw, stat.mr, stat.md, stat.bd, stat.bn, stat.bu, stat.mu);
    */
    
    free(s);
  }
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
  if (update_rates() < 0) goto done;

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

int main(int argc, char *argv[]) {
  struct epoll_event ev;
  cfg.prog = argv[0];
  int rc = -1, n, opt, ring_mode, ec;
  char *file, unit;
  struct shr *r;
  void **p;

  cfg.aux_rings = utvector_new(utmm_ptr);
  cfg.aux_names = utvector_new(utstring_mm);
  utstring_new(cfg.tmp);
  utstring_new(cfg.rates);

  while ( (opt=getopt(argc,argv,"vhs:mn")) != -1) {
    switch(opt) {
      case 'm': cfg.mode = mode_monitor; break;
      case 'n': cfg.mode = mode_notty; break;
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
    r = shr_open(file, SHR_RDONLY);
    if (r == NULL) goto done;
    utvector_push(cfg.aux_rings, &r);
  }

  /* call once before initializing curses so errors are visible */
  if (update_rates() < 0) goto done;

  if (cfg.mode == mode_monitor) {
    initscr();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_GREEN);
    getmaxyx(stdscr, cfg.rows, cfg.cols);
    curs_set(0); // cursor visibilty (0=hide; 1=normal)
    if (new_epoll(EPOLLIN, STDIN_FILENO)) goto done; /* keypress */
  }

  /* block all signals. we take signals synchronously via signalfd */
  alarm(1);

  do { 
    ec = epoll_wait(cfg.epoll_fd, &ev, 1, 500);
    if      (ec < 0)  fprintf(stderr, "epoll: %s\n", strerror(errno));
    else if (ec == 0) update();
    else if (ev.data.fd == cfg.signal_fd) { if (handle_signal()  < 0) goto done; }
    else if (ev.data.fd == STDIN_FILENO) break; /* exit on keypress */
  } while (ec >= 0);

  rc = 0;

done:
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  if (cfg.ring) shr_close(cfg.ring);
  p = NULL; while ( (p = utvector_next(cfg.aux_rings, p)) != NULL) shr_close(*p);
  utvector_free(cfg.aux_rings);
  utvector_free(cfg.aux_names);
  utstring_free(cfg.tmp);
  utstring_free(cfg.rates);
  if (cfg.mode == mode_monitor) endwin();
  return rc;
}
