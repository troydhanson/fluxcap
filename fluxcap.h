#ifndef _FLUXCAP_H_
#define _FLUXCAP_H_

#define _GNU_SOURCE
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
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
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <math.h>
#include "shr.h"
#include "libut.h"

#define FLUXCAP_VERSION "3.2"
#define MAX_NIC 64             /* longest NIC name we accept */
#define MAX_PKT 10000          /* max length of packet */
#define BATCH_PKTS 10000       /* max pkts to read in one shr_readv */
#define BATCH_SIZE (BATCH_PKTS*MAX_PKT) /* bytes buffered before shr_writev */
#define TIMER_HZ 10            /* rainy day flush/stats timer freq */

#define VLAN_LEN 4
#define MACS_LEN (2*6)

struct bb {
  size_t n; /* batch buffer size */
  size_t u; /* batch buffer used */
  char  *d; /* batch buffer */
  UT_vector /* of struct iovec */ *iov; 
};

struct encap { /* this is used in GRE encapsulation mode */
  int enable;
  enum {mode_gre=0, mode_gretap, mode_vxlan} mode;
  struct in_addr dst; /* used as GRE TX dest IP, or GRE RX local IP */
  uint32_t key;       /* if non-zero, indicates RX/TX GRE key, or VXLAN VNI */
};

struct fluxcap_stats {
  size_t rx_drops;  /* mode_receive drops in rx/pre-ring reported from kernel */
  size_t rd_drops;  /* mode_transmit/tee drops due to reader lag on shr ring */
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
    unsigned long B; /* bytes in */
    unsigned long b; /* bits in */
    unsigned lg10_b; /* integer floor(base-10-log) of b */
    unsigned lg10_bf;/* fraction part of ^ scaled to [0-8) */
    unsigned long rx; /* packet drops (tpacket rx) */
    unsigned long rd; /* packet drops (reader lag) */
    
    /* per second rates as strings */
    struct {
      char b[ RATE_MAX ]; /* bits    per second */
      char rx[RATE_MAX ]; /* drop-rx per second */
      char rd[RATE_MAX ]; /* drop-rd per second */
      char E[ RATE_MAX ]; /* bits    per second (human units e.g. Mbit/s) */
      char X[ RATE_MAX ]; /* drop-rx per second (human units e.g. Mbit/s) */
      char D[ RATE_MAX ]; /* drop-rd per second (human units e.g. Mbit/s) */
    } str;
  } ps;
};


#endif
