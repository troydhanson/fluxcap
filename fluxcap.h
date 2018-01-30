#ifndef _FLUXCAP_H_
#define _FLUXCAP_H_

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include "shr.h"
#include "libut.h"

#define FLUXCAP_VERSION "1.4"
#define MAX_PKT 100000         /* max length of packet */
#define MAX_NIC 64             /* longest NIC name we accept */
#define BATCH_SIZE (1024*1024) /* bytes buffered before shr_writev */
#define BATCH_PKTS 10000       /* max pkts to read in one shr_readv */
#define TIMER_HZ 10            /* rainy day flush/stats timer freq */

struct bb {
  size_t n; /* batch buffer size */
  size_t u; /* batch buffer used */
  char  *d; /* batch buffer */
  UT_vector /* of struct iovec */ *iov; 
};

struct encap { /* this is used in tx GRE/ERSPAN encapsulation mode */
  int enable;
  enum {mode_gre=0, mode_gretap, mode_erspan} mode;
  struct in_addr dst;
  int session;             /* TODO make configurable */
  uint32_t session_seqno;  /* TODO should be kept per-session */
};

struct fluxcap_stats {
  size_t rx_drops;  /* mode_receive drops in rx/pre-ring reported from kernel */
  size_t rd_drops;  /* mode_transmit/tee drops due to reader lag on shr ring */
};

struct watch_ui {  /* helper structure for ui state in mode_watch */
  char title[80];
  int rows;
  int cols;
  enum { rate_bps=0, rate_pps } unit;
  int acs;
};

/* watch window - for tracking rates over NWIN observations */
#define NWIN 100
#define RATE_MAX 20
#define NAME_MAX 80
struct ww {
  char name[NAME_MAX];

  struct {
    struct fluxcap_stats fs;
    struct shr_stat ss;
  } win[NWIN];

  /* resulting delta from newest to oldest window */
  unsigned long mw; /* packets in */
  unsigned long bw; /* bytes in */
  unsigned long rx; /* packet drops (tpacket rx) */
  unsigned long rd; /* packet drops (reader lag) */

  /* per second rates */
  struct {
    unsigned long p; /* packets in */
    unsigned long B; /* bytes in */
    unsigned long b; /* bits in */
    unsigned lg10_b; /* floor(base-10-log) of b */
    unsigned long rx; /* packet drops (tpacket rx) */
    unsigned long rd; /* packet drops (reader lag) */
    
    /* per second rates as strings */
    struct {
      char p[ RATE_MAX ]; /* packets per second */
      char B[ RATE_MAX ]; /* bytes   per second */
      char b[ RATE_MAX ]; /* bits    per second */
      char rx[RATE_MAX ]; /* drop-rx per second */
      char rd[RATE_MAX ]; /* drop-rd per second */
      char E[ RATE_MAX ]; /* bits    per second (human units e.g. Mbit/s) */
      char P[ RATE_MAX ]; /* packets per second (human units e.g. Mpkt/s) */
      char X[ RATE_MAX ]; /* drop-rx per second (human units e.g. Mbit/s) */
      char D[ RATE_MAX ]; /* drop-rd per second (human units e.g. Mbit/s) */
    } str;
  } ps;
};

/* prototypes called between files */
int display_rates(struct watch_ui *ui, struct iovec *wiov, size_t niov);
int init_watch_ui(struct watch_ui *ui);
int fini_watch_ui(struct watch_ui *ui);

#endif
