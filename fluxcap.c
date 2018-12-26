#include "fluxcap.h"

/* 
 * fluxcap: a network tap replication and aggregation tool
 *
 */

struct mmsghdr bss_msgv[BATCH_PKTS];

struct {
  int verbose;
  char *prog;
  enum {mode_none, mode_transmit, mode_receive, mode_create, mode_watch} mode;
  char *file;
  char dev[MAX_NIC];
  unsigned long ticks;
  int vlan;
  int pass_vlan;
  int tail;
  int fd;
  int tx_fd;
  int rx_fd;
  int signal_fd;
  int timer_fd;
  int epoll_fd;
  char pkt[MAX_PKT];
  struct shr *ring;
  size_t size; /* ring create size (-cr), or snaplen (-rx/-tx) */
  struct encap encap;
  struct itimerspec timer;
  uint16_t ip_id; /* for implementing IP fragmentation when */
  int mtu;        /* using gre encapsulation */
  UT_vector /* of ptr */ *watch_rings;
  UT_vector /* of utstring */ *watch_names;
  UT_vector /* of struct ww */ *watch_win;
  UT_string *tmp;
  struct timeval now;
  struct bb bb; /* output shr ring batch buffer; accumulates til shr_writev */
  struct bb rb; /* input shr ring batch buffer; accepts many via shr_readv */
  struct bb pb; /* packet buffer (Special); faux bb wrapping kernel ring */
  /* fields below are for packet input from AF_PACKET socket */
  struct tpacket_req req; /* linux/if_packet.h */
  unsigned ring_block_sz; /* see comments in initialization below */
  unsigned ring_block_nr; /* number of blocks of sz above */
  unsigned ring_frame_sz; /* snaplen */
  unsigned ring_curr_idx; /* slot index in ring buffer */
  unsigned ring_frame_nr; /* redundant, total frame count */
  int strip_vlan; /* strip VLAN on rx if present (boolean) */
  int drop_pct;   /* sampling % 0 (keep all)-100(drop all) */
  int use_tx_ring; /* 0 = sendto-based tx; 1=packet mmap ring-based tx */
  int bypass_qdisc_on_tx; /* bypass kernel qdisc layer, more risk of loss */
  struct fluxcap_stats stats; /* used to periodically update rx/rd stats */
  int keep; /* in mode_create, keep existing ring if present */
  int losing;
  struct bb gb;         /* used in gre rx for recvmmsg */
  struct mmsghdr *msgv; /* used in gre rx for recvmmsg */
} cfg = {
  .fd = -1,
  .tx_fd = -1,
  .rx_fd = -1,
  .signal_fd = -1,
  .timer_fd = -1,
  .epoll_fd = -1,
  .ring_block_sz = 1 << 22, /*4 mb; want powers of two due to kernel allocator*/
  .ring_block_nr = 64,
  .ring_frame_sz = 1 << 11, /* 2048 for MTU & header, divisor of ring_block_sz*/
  .timer = {
    .it_value =    { .tv_sec = 0, .tv_nsec = 1 },
    .it_interval = { .tv_sec = 0, .tv_nsec = 1000000000UL / TIMER_HZ },
  },
  .msgv = bss_msgv,
};

extern UT_mm bb_mm;
UT_mm ww_mm = { .sz = sizeof(struct ww), };
UT_mm _utmm_ptr = {.sz = sizeof(void*)};
UT_mm* utmm_ptr = &_utmm_ptr;

/* signals that we'll accept via signalfd in epoll */
int sigs[] = {SIGHUP,SIGTERM,SIGINT,SIGQUIT,SIGALRM};

void usage() {
  fprintf(stderr,
       "usage: %s [-cr|-tx|-rx|-io] [options] <ring>\n"
       "\n"
       " create ring(s): -cr -s <size>[k|m|g|t] <ring> ...\n"
       " transmit:       -tx -i <eth>  <ring>\n"
       " receive:        -rx -i <eth>  <ring>\n"
       " i/o view:       -io <ring> ...\n"
       "\n"
       "GRE encapsulation modes:\n"
       "  -tx -E gretap:<host>  [-K <key>]            <ring>  (GRETAP send)\n"
       "  -rx -E gretap[:<ip>]> [-K <key>] [-i <eth>] <ring>  (GRETAP recv)\n"
       "  -tx -E gre:<host>     [-K <key>]            <ring>  (GRE send)\n"
       " where:\n"
       "    <key> GRE key/dotted quad (optional) [rx/tx]\n"
       "    <ip>  binds a local IP    (optional) [rx]\n"
       "    <eth> binds a local NIC   (optional) [rx]\n"
       "\n"
       "Other options:\n"
       "    -f 'vlan n'  (accept packets tagged VLAN n) [tx]\n"
       "    -V <vlan>    (inject VLAN tag) [rx/tx]\n"
       "    -Q           (remove VLAN tag) [rx]\n"
       "    -d <percent> (downsample to <0-99>%% [rx/tx]\n"
       "    -s <length>  (truncate at length) [rx/tx]\n"
       "    -D <n>       (trim n tail bytes) [rx/tx]\n"
       "    -R           (ring tx not sendto) [tx]\n"
       "    -q           (bypass qdisc layer) [tx]\n"
       "    -v           (verbose)\n"
       "\n"
       " Kernel ring buffer options (TPACKET_V2) [rx/tx]\n"
       "  Defaults apply if left unspecified. To use these options\n"
       "  the block size must be a multiple of the system page size,\n"
       "  and be small since it consumes physically contiguous pages.\n"
       "  The number of blocks can be large. Their product is the ring\n"
       "  capacity. The frame size must evenly divide the block size.\n"
       "  The ring parameters are checked to satisfy these constraints.\n"
       "  The frame size is for one packet (with overhead) so it should\n"
       "  exceed the MTU for full packet handling without truncation.\n"
       "    -Z <frame-size>  (max frame size)   [2048]\n"
       "    -B <num-blocks>  (number of blocks) [64])\n"
       "    -S <block-size>  (block size log2)  [22] (4mb)\n"
       "\n",
          cfg.prog);
  fprintf(stderr, "fluxcap version: %s\n", FLUXCAP_VERSION);
  exit(-1);
}

void hexdump(char *buf, size_t len) {
  size_t i,n=0;
  unsigned char c;
  while(n < len) {
    fprintf(stderr,"%08x ", (int)n);
    for(i=0; i < 16; i++) {
      c = (n+i < len) ? buf[n+i] : 0;
      if (n+i < len) fprintf(stderr,"%.2x ", c);
      else fprintf(stderr, "   ");
    }
    for(i=0; i < 16; i++) {
      c = (n+i < len) ? buf[n+i] : ' ';
      if (c < 0x20 || c > 0x7e) c = '.';
      fprintf(stderr,"%c",c);
    }
    fprintf(stderr,"\n");
    n += 16;
  }
}

int new_epoll(int events, int fd) {
  int rc;
  struct epoll_event ev;
  memset(&ev,0,sizeof(ev)); // placate valgrind
  ev.events = events;
  ev.data.fd= fd;
  rc = epoll_ctl(cfg.epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  if (rc == -1) {
    fprintf(stderr,"epoll_ctl: %s\n", strerror(errno));
  }
  return rc;
}

/*
 * read_proc
 *
 * read a complete file from the /proc filesystem
 * this is special because its size is not known a priori
 * so a read/realloc loop is needed
 *
 * size into len, returning buffer or NULL on error.
 * caller should free the buffer eventually.
 */
char *read_proc(char *file, size_t *len) {
  char *buf=NULL, *b, *tmp;
  int fd = -1, rc = -1, eof=0;
  size_t sz, br=0, l;
  ssize_t nr;

  /* initial guess at a sufficient buffer size */
  sz = 1000;

  fd = open(file, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr,"open: %s\n", strerror(errno));
    goto done;
  }

  while(!eof) {

    tmp = realloc(buf, sz);
    if (tmp == NULL) {
      fprintf(stderr, "out of memory\n");
      goto done;
    }

    buf = tmp;
    b = buf + br;
    l = sz - br;

    do {
      nr = read(fd, b, l);
      if (nr < 0) {
        fprintf(stderr,"read: %s\n", strerror(errno));
        goto done;
      }

      b += nr;
      l -= nr;
      br += nr;

      /* out of space? double buffer size */
      if (l == 0) { 
        sz *= 2;
        break;
      }

      if (nr == 0) eof = 1;

    } while (nr > 0);
  }

  *len = br;
  rc = 0;

 done:
  if (fd != -1) close(fd);
  if (rc && buf) { free(buf); buf = NULL; }
  return buf;
}

/*
 * find start and length of column N (one-based)
 * in input buffer buf of length buflen
 *
 * columns must be space-or-tab delimited
 * returns NULL if column not found
 *
 * the final column may end in newline or eob  
 *
 * col: column index (1-based)
 * len: OUTPUT parameter (column length)
 * buf: buffer to find columns in
 * buflen: length of buf
 *
 * returns:
 *   pointer to column N, or NULL
 */
#define ws(x) (((x) == ' ') || ((x) == '\t'))
char *get_col(int col, size_t *len, char *buf, size_t buflen) {
  char *b, *start=NULL, *eob;
  int num;

  eob = buf + buflen;

  b = buf;
  num = 0;  /* column number */
  *len = 0; /* column length */

  while (b < eob) {

    if (ws(*b) && (num == col)) break; /* end of sought column */
    if (*b == '\n') break;             /* end of line */

    if (ws(*b)) *len = 0;              /* skip over whitespace */
    if ((!ws(*b)) && (*len == 0)) {    /* record start of column */
      num++;
      start = b;
    }
    if (!ws(*b)) (*len)++;             /* increment column length */
    b++;
  }

  if ((*len) && (num == col)) return start;
  return NULL;
}

/*
 * find route for a given destination IP address
 *
 * parameters:
 *  dest_ip:   the destination IP address in network order
 *  interface: char[] to receive the output NIC interface name
 *             must be at least IF_NAMESIZE bytes long;
 *             see IF_NAMESIZE in /usr/include/net/if.h
 * returns:
 *   0 success
 *  -1 error parsing routing table
 *  -2 no route found
 *
 */
int find_route(uint32_t dest_ip, 
               char *interface) {

  int rc = -1, sc;
  char *buf=NULL, *line, *b, *iface, *s_dest, *s_gw, *s_mask;
  unsigned mask, dest, gw, best_mask=0, nroutes=0;
  size_t len, sz=0, to_eob, iface_len;

  buf = read_proc("/proc/net/route", &sz);
  if (buf == NULL) goto done;

  /* find initial newline; discard header row */
  b = buf;
  while ((b < buf+sz) && (*b != '\n')) b++;
  line = b+1;

  while (line < buf+sz) {

    to_eob = sz-(line-buf);

    s_dest = get_col(2, &len, line, to_eob);
    if (s_dest == NULL) goto done;
    sc = sscanf(s_dest, "%x", &dest);
    if (sc != 1) goto done;

    s_mask = get_col(8, &len, line, to_eob);
    if (s_mask == NULL) goto done;
    sc = sscanf(s_mask, "%x", &mask);
    if (sc != 1) goto done;

    iface = get_col(1, &iface_len, line, to_eob);
    if (iface == NULL) goto done;

    /* advance to next line */
    b = line;
    while ((b < buf+sz) && (*b != '\n')) b++;
    line = b+1;

    /* does the route apply? */
    if ((dest_ip & mask) != dest) continue;

    /* know a more specific route? */
    if (mask < best_mask) continue;

    /* this is the best route so far */
    best_mask = mask;

    /* copy details of this route */
    if (iface_len + 1 > IF_NAMESIZE) goto done;
    memcpy(interface, iface, iface_len);
    interface[iface_len] = '\0';
    nroutes++;
  }

  rc = nroutes ? 0 : -2;

 done:
  if (buf) free(buf);
  return rc;
}

/* get the MTU for the interface, or -1 on error */
int get_if_mtu(char *eth) {
  int fd = -1, sc, rc = -1;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    fprintf(stderr, "socket: %s\n", strerror(errno));
    goto done;
  }

  strncpy(ifr.ifr_name, eth, sizeof(ifr.ifr_name));
  sc = ioctl(fd, SIOCGIFMTU, &ifr);
  if (sc < 0) {
    fprintf(stderr, "ioctl: %s\n", strerror(errno));
    goto done;
  }

  rc = ifr.ifr_mtu;

 done:
  if (fd != -1) close(fd);
  return rc;
}

int check_ring_parameters(void) {
  int rc=-1;
  unsigned page_sz;

  if (cfg.ring_block_sz % cfg.ring_frame_sz) {
    fprintf(stderr,"-S block_sz must be multiple of -F frame_sz\n");
    goto done;
  }

  page_sz = (unsigned)sysconf(_SC_PAGESIZE);

  if (cfg.ring_block_sz % page_sz) {
    fprintf(stderr,"-S block_sz must be multiple of page_sz %u\n", page_sz);
    goto done;
  }

  if (cfg.ring_frame_sz <= TPACKET2_HDRLEN) {
    fprintf(stderr,"-Z frame_sz must exceed %lu\n", TPACKET2_HDRLEN);
    goto done;
  }

  if (cfg.ring_frame_sz % TPACKET_ALIGNMENT) {
    fprintf(stderr,"-Z frame_sz must be a multiple of %u\n", TPACKET_ALIGNMENT);
    goto done;
  }

  cfg.ring_frame_nr = (cfg.ring_block_sz / cfg.ring_frame_sz) * cfg.ring_block_nr;

  rc = 0;
 
 done:
  return rc;

}

/* print the ring capacity in MB and packets 
 *
 * here in userspace, the ring is nothing but a regular flat buffer.
 * it is comprised of contiguous slots - all of which have the same size.
 *
 * in kernel space, the ring is a set of blocks; each block is a number of
 * physically contiguous pages. since physically contiguous pages are
 * limited, the kernel only gets small allocations of them. it forms the
 * blocks into a virtually contiguous buffer for our benefit in user space.
 *
 * these kernel memory considerations are why the ring is specified as
 * a number of blocks (cfg.ring_block_nr) of a given size (cfg.ring_block_sz).
 * the other parameter (cfg.ring_frame_sz) is the max size of a packet structure
 * (struct tpacket_hdr, struct sockaddr_ll, packet itself, and padding). so
 * to deal with full packet data it needs to be the MTU plus all that overhead.
 *
 * we require block size to be a multiple of frame size, so there are no gaps
 * in the userspace view of the packet ring. it is a simple array of slots.
 *
 */
void describe_ring(char *label) {

  double block_size_mb = cfg.ring_block_sz / (1024.0 * 1024);
  double mb = cfg.ring_block_nr * block_size_mb;

  fprintf(stderr, "%s: %.1f megabytes (max %u packets)\n",
     label, mb, cfg.ring_frame_nr);

  if (cfg.verbose) {

    double bps = 10000000000.0; /* 10 gigabit/sec network */
    double mbytes_per_sec = bps / ( 8 * 1024 * 1024);
    double sec = mb / mbytes_per_sec;

    fprintf(stderr,
       " RING: (%u blocks * %u bytes per block) = %.1f megabytes\n"
       " PACKETS: @(%u bytes/packet) = %u packets\n"
       " TIME TO QUENCH @ 10Gigabit/s: %.1f seconds\n",
       cfg.ring_block_nr, cfg.ring_block_sz, mb,
       cfg.ring_frame_sz, cfg.ring_frame_nr, sec);
  }
}

/* set up as a GRE receiver */
int setup_rx_encap(void) {
  struct sockaddr *sa;
  int i, sc, rc = -1;
  struct iovec *iov;
  socklen_t sz;

  cfg.rx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
  if (cfg.rx_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* bind local IP; defaults to INADDR_ANY */
  struct sockaddr_in in;
  memset(&in, 0, sizeof(in));
  in.sin_addr = cfg.encap.dst;
  sa = (struct sockaddr*)&in;
  sz = sizeof(in);

  sc = bind(cfg.rx_fd, sa, sz);
  if (sc < 0) {
    fprintf(stderr, "bind: %s\n", strerror(errno));
    goto done;
  }

  /* bind specific RX NIC if requested */
  sz = strlen(cfg.dev);
  sc = sz ? setsockopt(cfg.rx_fd, SOL_SOCKET, SO_BINDTODEVICE, cfg.dev, sz) : 0;
  if (sc < 0) {
    fprintf(stderr, "setsockopt: %s\n", strerror(errno));
    goto done;
  }

  /* set up recvmmsg buffers */
  assert(BATCH_SIZE == BATCH_PKTS * MAX_PKT);
  assert(cfg.gb.n == BATCH_PKTS * MAX_PKT);
  assert(cfg.gb.iov && (cfg.gb.iov->n == BATCH_PKTS));
  cfg.gb.iov->i = cfg.gb.iov->n; /* mark slots used */
  iov = (struct iovec*)utvector_head(cfg.gb.iov);
  for(i=0; i < BATCH_PKTS; i++) {
    iov[i].iov_base = cfg.gb.d + i * MAX_PKT;
    iov[i].iov_len = MAX_PKT;
    cfg.msgv[i].msg_hdr.msg_iov = &iov[i];
    cfg.msgv[i].msg_hdr.msg_iovlen = 1;
  }

  rc = 0;

 done:
  return rc;
}

/* 
 * Prepare to read packets using a AF_PACKET socket with PACKET_RX_RING
 * 
 * see packet(7)
 *
 * also see
 *  sudo apt-get install linux-doc
 *  zless /usr/share/doc/linux-doc/networking/packet_mmap.txt.gz
 *
 * With PACKET_RX_RING (in TPACKET_V2)
 * the ring buffer consists of an array of packet slots.
 *
 * Each packet is preceded by a metadata structure in the slot.
 * The application and kernel communicate the head and tail of
 * the ring through tp_status field (TP_STATUS_[USER|KERNEL]).
 *
 */

int setup_rx(void) {
  int rc=-1, ec;

  if (check_ring_parameters() < 0) goto done;

  /* any link layer protocol packets (linux/if_ether.h) */
  int protocol = htons(ETH_P_ALL);

  /* create the packet socket */
  cfg.fd = socket(AF_PACKET, SOCK_RAW, protocol);
  if (cfg.fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* convert interface name to index (in ifr.ifr_ifindex) */
  struct ifreq ifr; 
  strncpy(ifr.ifr_name, cfg.dev, sizeof(ifr.ifr_name));
  ec = ioctl(cfg.fd, SIOCGIFINDEX, &ifr);
  if (ec < 0) {
    fprintf(stderr,"failed to find interface %s\n", cfg.dev);
    goto done;
  }

  /* PACKET_RX_RING comes in multiple versions. TPACKET_V2 is used here */
  int v = TPACKET_V2;
  ec = setsockopt(cfg.fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_VERSION: %s\n", strerror(errno));
    goto done;
  }

  /* fill out the struct tpacket_req describing the ring buffer */
  memset(&cfg.req, 0, sizeof(cfg.req));
  cfg.req.tp_block_size = cfg.ring_block_sz; /* Min sz of contig block */
  cfg.req.tp_frame_size = cfg.ring_frame_sz; /* Size of frame/snaplen */
  cfg.req.tp_block_nr = cfg.ring_block_nr;   /* Number of blocks */
  cfg.req.tp_frame_nr = cfg.ring_frame_nr;   /* Total number of frames */
  describe_ring("PACKET_RX_RING");
  ec = setsockopt(cfg.fd, SOL_PACKET, PACKET_RX_RING, &cfg.req, sizeof(cfg.req));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_RX_RING: %s\n", strerror(errno));
    goto done;
  }

  /* now map the ring buffer we described above. lock in unswappable memory */
  cfg.pb.n = cfg.req.tp_block_size * cfg.req.tp_block_nr;
  cfg.pb.d = mmap(NULL, cfg.pb.n, PROT_READ|PROT_WRITE,
                      MAP_SHARED|MAP_LOCKED, cfg.fd, 0);
  if (cfg.pb.d == MAP_FAILED) {
    fprintf(stderr,"mmap: %s\n", strerror(errno));
    goto done;
  }

  /* bind to receive the packets from just one interface */
  struct sockaddr_ll sl;
  memset(&sl, 0, sizeof(sl));
  sl.sll_family = AF_PACKET;
  sl.sll_protocol = protocol;
  sl.sll_ifindex = ifr.ifr_ifindex;
  ec = bind(cfg.fd, (struct sockaddr*)&sl, sizeof(sl));
  if (ec < 0) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* set promiscuous mode to get all packets. */
  struct packet_mreq m;
  memset(&m, 0, sizeof(m));
  m.mr_ifindex = ifr.ifr_ifindex;
  m.mr_type = PACKET_MR_PROMISC;
  ec = setsockopt(cfg.fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &m, sizeof(m));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_ADD_MEMBERSHIP: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

/* 
 * create the transmit socket 
 * 
 * There are two fundamentally different types of sockets here, only one
 * of which is created, based on whether we are doing *encapsulated* transmit
 * (of the packet into a GRE tunnel that then rides over regular IP); or
 * "regular" packet transmission where we inject the packet to the NIC.
 *
 *     MODE            SOCKET TYPE         SEE ALSO
 *     --------         ----------------    ---------------
 *     ENCAPSULATE     RAW IP              ip(7) and raw(7)
 *     REGULAR         RAW PACKET          packet(7) 
 *
 * Within REGULAR mode we further distinguish between sendto()-based
 * transmit, versus packet tx ring mode. The latter uses the kernel ring
 * buffer mechanism described in packet_mmap.txt.
 *
 */
int setup_tx(void) {
  char interface[IF_NAMESIZE], *ip;
  int rc=-1, ec, one = 1;

  if (cfg.encap.enable) {

    /* in encapsulation mode, use raw IP socket. */
    cfg.tx_fd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (cfg.tx_fd == -1) {
      fprintf(stderr,"socket: %s\n", strerror(errno));
      goto done;
    }

    /* IP_HDRINCL means WE form the IP headers.. with some help; see raw(7) */
    ec = setsockopt(cfg.tx_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (ec < 0) {
      fprintf(stderr,"setsockopt IP_HDRINCL: %s\n", strerror(errno));
      goto done;
    }

    /* we need the mtu of the egress NIC to implement IP fragmentation,
     * if needed, since raw sockets do not do that for us. to get the 
     * interface mtu, we need the egress interface, based on routing */
    ec = find_route( cfg.encap.dst.s_addr, interface);
    if (ec < 0) {
      ip = inet_ntoa(cfg.encap.dst);
      fprintf(stderr, "can't determine route to %s\n", ip);
      goto done;
    }

    cfg.mtu = get_if_mtu(interface);
    if (cfg.mtu < 0) {
      fprintf(stderr, "mtu lookup failed: %s\n", interface);
      goto done;
    }

    if (cfg.verbose) {
      ip = inet_ntoa(cfg.encap.dst);
      fprintf(stderr, "encapsulating to %s on interface %s mtu %d\n",
        ip, interface, cfg.mtu);
    }

    rc = 0;
    goto done;
  } 
  
  /* 
   * standard tx mode
   */

  /* use a raw PACKET (link-level) socket */
  cfg.tx_fd = socket(AF_PACKET, SOCK_RAW, 0 /* tx only */);
  if (cfg.tx_fd == -1) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* convert interface name to index (in ifr.ifr_ifindex) */
  struct ifreq ifr;
  strncpy(ifr.ifr_name, cfg.dev, sizeof(ifr.ifr_name));
  ec = ioctl(cfg.tx_fd, SIOCGIFINDEX, &ifr);
  if (ec < 0) {
    fprintf(stderr,"failed to find interface %s\n", cfg.dev);
    goto done;
  }

  /* bind interface for tx */
  struct sockaddr_ll sl;
  memset(&sl, 0, sizeof(sl));
  sl.sll_family = AF_PACKET;
  sl.sll_ifindex = ifr.ifr_ifindex;
  ec = bind(cfg.tx_fd, (struct sockaddr*)&sl, sizeof(sl));
  if (ec < 0) {
    fprintf(stderr,"socket: %s\n", strerror(errno));
    goto done;
  }

  /* when qdisc bypass is enabled, to quote packet_mmap.txt, "packets sent
   * through PF_PACKET will bypass the kernel's qdisc layer and are ...
   * pushed to the driver directly.  Meaning, packet are not buffered, tc
   * disciplines are ignored, increased loss can occur and such packets are 
   * not visible to other PF_PACKET sockets anymore."
   */
#ifdef PACKET_QDISC_BYPASS
  ec = cfg.bypass_qdisc_on_tx ?
      setsockopt(cfg.tx_fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one)) : 0;
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_QDISC_BYPASS: %s\n", strerror(errno));
    goto done;
  }
#else
  if (cfg.bypass_qdisc_on_tx) {
    fprintf(stderr,"setsockopt PACKET_QDISC_BYPASS: unsupported\n");
    goto done;
  }
#endif

  /* if we are using standard, sendto-based transmit, we are done */
  if (cfg.use_tx_ring == 0) {
    rc  = 0;
    goto done;
  }

  /*************************************************************
   * packet tx ring setup
   ************************************************************/
  if (check_ring_parameters() < 0) goto done;

  int v = TPACKET_V2;
  ec = setsockopt(cfg.tx_fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_VERSION: %s\n", strerror(errno));
    goto done;
  }

  /* fill out the struct tpacket_req describing the ring buffer */
  memset(&cfg.req, 0, sizeof(cfg.req));
  cfg.req.tp_block_size = cfg.ring_block_sz; /* Min sz of contig block */
  cfg.req.tp_frame_size = cfg.ring_frame_sz; /* Size of frame/snaplen */
  cfg.req.tp_block_nr = cfg.ring_block_nr;   /* Number of blocks */
  cfg.req.tp_frame_nr = cfg.ring_frame_nr;   /* Total number of frames */
  describe_ring("PACKET_TX_RING");
  ec = setsockopt(cfg.tx_fd, SOL_PACKET, PACKET_TX_RING, &cfg.req, sizeof(cfg.req));
  if (ec < 0) {
    fprintf(stderr,"setsockopt PACKET_TX_RING: %s\n", strerror(errno));
    goto done;
  }

  /* map the tx ring buffer into unswappable memory */
  cfg.pb.n = cfg.req.tp_block_size * cfg.req.tp_block_nr;
  cfg.pb.d = mmap(NULL, cfg.pb.n, PROT_READ|PROT_WRITE,
                      MAP_SHARED|MAP_LOCKED, cfg.tx_fd, 0);
  if (cfg.pb.d == MAP_FAILED) {
    fprintf(stderr,"mmap: %s\n", strerror(errno));
    goto done;
  }

  rc = 0;

 done:
  return rc;
}

int bb_flush(struct shr *s, struct bb *b) {
  int rc = -1;
  struct iovec *iov;
  size_t n;
  ssize_t wr;

  n = utvector_len(b->iov);
  if (n == 0) { rc = 0; goto done; }
  iov = (struct iovec*)utvector_head(b->iov);

  wr = shr_writev(s, iov, n);
  if (wr < 0) {
    fprintf(stderr,"shr_write: error code %ld\n", (long)wr);
    goto done;
  }
  b->u = 0;
  utvector_clear(b->iov);

  rc = 0;

 done:
  return rc;
}

/* store the message into the batch buffer */
ssize_t bb_write(struct shr *s, struct bb *b, char *buf, size_t len) {
  struct iovec io;
  int rc = -1;

  if (b->n - b->u < len) {
    if (bb_flush(s,b) < 0) goto done;
  }

  assert((b->n - b->u) >= len);

  io.iov_base = &b->d[b->u];
  io.iov_len = len;
  memcpy(io.iov_base, buf, len);
  utvector_push(b->iov, &io);
  b->u += len;

  rc = 0;

 done:
  return (rc < 0) ? (ssize_t)-1 : len;
}

/* add rx drops to the counter in the ring app data
 *
 * see /usr/include/linux/if_packet.h
 * see packet(7)
 * "Receiving statistics resets the internal counters."
 *
 */
int update_rx_drops(void) {
  struct tpacket_stats stats;
  struct fluxcap_stats st;
  size_t st_sz;
  void *stp;
  int sc, rc = -1;

  assert(cfg.mode == mode_receive);
  if (cfg.losing == 0) return 0;

  /* packet(7): "Receiving statistics resets the internal counters."  */
  socklen_t len = sizeof(stats);
  sc = getsockopt(cfg.fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len);
  if (sc < 0) {
    fprintf(stderr,"getsockopt: %s\n", strerror(errno));
    return -1;
  }

  if (cfg.verbose) {
    fprintf(stderr, "Received packets: %u\n", stats.tp_packets);
    fprintf(stderr, "Dropped packets:  %u\n", stats.tp_drops);
  }

  stp = &st;
  st_sz = sizeof(st);

  sc = shr_appdata(cfg.ring, &stp, NULL, &st_sz); /* "get" */
  if (sc < 0) {
    fprintf(stderr, "shr_appdata: error %d\n", sc);
    goto done;
  }

  st.rx_drops += stats.tp_drops;

  sc = shr_appdata(cfg.ring, NULL, stp, &st_sz); /* "set" */
  if (sc < 0) {
    fprintf(stderr, "shr_appdata: error %d\n", sc);
    goto done;
  }

  cfg.losing = 0;
  rc = 0;

 done:
  return rc;
}

/* add ring read drops to the counter in the ring app data */
int update_rd_drops(void) {
  struct fluxcap_stats st;
  size_t st_sz;
  void *stp;
  int sc, rc = -1;

  stp = &st;
  st_sz = sizeof(st);

  sc = shr_appdata(cfg.ring, &stp, NULL, &st_sz); /* "get" */
  if (sc < 0) {
    fprintf(stderr, "shr_appdata: error %d\n", sc);
    goto done;
  }

  st.rd_drops += shr_farm_stat(cfg.ring, 1);

  sc = shr_appdata(cfg.ring, NULL, stp, &st_sz); /* "set" */
  if (sc < 0) {
    fprintf(stderr, "shr_appdata: error %d\n", sc);
    goto done;
  }
 
  rc = 0;

 done:
  return rc;
}

/*
 * flux_log10
 * 
 * compute floor of the base-10 log of x
 * an integer approximation without -lm
 * 
 *
 */
unsigned flux_log10( unsigned x ) {
  if (x == 0) return 0;
  unsigned long n = 0;
  unsigned long m = 10;
  while(n <= 10) {
    if (x < m) return n;
    m *= 10;
    n++;
  }
  /* (2^32 > 10^9) && (2^32 < 10^10)
     thus log10 of 2^32 is between 9 and 10
     thus floor(log10(2^32)) is 9
   */
  assert(0); 
}

/* returns volatile memory - use immediately or copy.
 * takes bits-per-second as input, returns like "20 Mbit/s"
 * where "bit" is the unit, can also be "pkt" etc.
 * using whatever SI unit is most readable (K,M,G,T) 
 */
char *format_rate(unsigned long bps, char *unit) {
  double b = bps;
  char *c = "";
  if (b > 1024) { b /= 1024; c = "K"; }
  if (b > 1024) { b /= 1024; c = "M"; }
  if (b > 1024) { b /= 1024; c = "G"; }
  if (b > 1024) { b /= 1024; c = "T"; }
  utstring_clear(cfg.tmp);
  utstring_printf(cfg.tmp, "%.0f %s%s/s", b, c, unit);
  return utstring_body(cfg.tmp);
}

/*
 * status_rings
 *
 * update i/o metrics for each ring
 *
 */
int status_rings(void) {
  unsigned long start_tick, st, ct;
  struct shr_stat *ss;
  double elapsed_sec, lg10_b;
  size_t sz;
  int rc = -1, sc, i;
  char *name, *c;
  struct shr **r;
  struct ww *w;
  UT_string *s;
  ssize_t nr;
  void *fs;

  /* unicode 1/8 width box progression */
  char *blocks[] = {  "", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"};

  printf("\033[1;1H"); /* position at line 0, col 0 */
  printf("\033[1m"); /* bold */
  printf(" %-20s | %-12s | %-12s | %-12s \n\n", 
          "name", "rx-rate", "rx-drop", "tx-drop");
  printf("\033[m"); /* reset attributes */

  /* go through the rings to obtain their in/out counters */
  s = NULL;
  r = NULL;
  w = NULL;
  while ( (r = (struct shr**)utvector_next(cfg.watch_rings, r))) {
    s = (UT_string*)utvector_next(cfg.watch_names, s);
    w = (struct ww*)utvector_next(cfg.watch_win, w);
    assert(s);
    assert(w);

    name = utstring_body(s);

    ss = &w->win[ cfg.ticks % NWIN ].ss;
    sc = shr_stat(*r, ss, NULL);
    if (sc < 0) goto done;

    fs = &w->win[ cfg.ticks % NWIN ].fs;
    sz = sizeof(struct fluxcap_stats);
    sc = shr_appdata(*r, &fs, NULL, &sz);
    if (sc < 0) {
      fprintf(stderr, "shr_appdata: error %d\n", sc);
      goto done;
    }

    /* for this ring, compute intake & drops over the windows */
    start_tick = (cfg.ticks < NWIN) ? 0 : (cfg.ticks - (NWIN - 1));
    st = start_tick % NWIN;
    ct = cfg.ticks  % NWIN;
    w->bw = w->win[ ct ].ss.bw -
            w->win[ st ].ss.bw;
    w->mw = w->win[ ct ].ss.mw -
            w->win[ st ].ss.mw;
    w->rx = w->win[ ct ].fs.rx_drops -
            w->win[ st ].fs.rx_drops;
    w->rd = w->win[ ct ].fs.rd_drops -
            w->win[ st ].fs.rd_drops;

    /* compute per second rates, log and strings */
    elapsed_sec = (cfg.ticks - start_tick) * 1.0 / TIMER_HZ;
    memset( &w->ps, 0, sizeof(w->ps) );
    if (elapsed_sec > 0) {
      w->ps.B = w->bw / elapsed_sec;
      w->ps.b = w->ps.B * 8;
      lg10_b = w->ps.b ? log10(w->ps.b) : 0;
      w->ps.lg10_b = (unsigned)floor(lg10_b);      /* integer part */
      w->ps.lg10_bf = (lg10_b - w->ps.lg10_b) * 8; /* fraction n/8 */
      w->ps.rx = w->rx / elapsed_sec;
      w->ps.rd = w->rd / elapsed_sec;
    }

    /* render strings */
    strncpy(w->name, name, NAME_MAX);
    w->name[NAME_MAX - 1] = '\0';
    snprintf(w->ps.str.b,  RATE_MAX, "%lu", w->ps.b);
    snprintf(w->ps.str.rx, RATE_MAX, "%lu", w->ps.rx);
    snprintf(w->ps.str.rd, RATE_MAX, "%lu", w->ps.rd);

    /* bits/s in */
    c = format_rate(w->ps.b, "bit");
		assert(strlen(c)+1 <= RATE_MAX);
		strncpy(w->ps.str.E, c, RATE_MAX);

    /* rx (ingest) drops/s */
    c = format_rate(w->ps.rx, "bit");
		assert(strlen(c)+1 <= RATE_MAX);
		strncpy(w->ps.str.X, c, RATE_MAX);

    /* rd (reader) drops/s */
    c = format_rate(w->ps.rd, "bit");
		assert(strlen(c)+1 <= RATE_MAX);
		strncpy(w->ps.str.D, c, RATE_MAX);

    /* render to terminal */
    printf(" %-20.20s | %-12s | %-12s | %-12s ", 
      w->name, w->ps.str.E, w->ps.str.X, w->ps.str.D);
    for(i=0; i < w->ps.lg10_b; i++) printf("%s", blocks[8]);
    printf("%s", blocks[ w->ps.lg10_bf ]);
    printf("\033[0K"); /* erase to end of line */
    printf("\n");
  }

  rc = 0;

 done:
  return rc;
}

/*  work we do at 10hz
 *
 *  normally nexp (number of expirations) is 1.
 *  in a busy process expirations may coalesce.
 *
 *  we do "rainy day" cache flushes below
 *  so that time, like capacity, induce flush
 */
int timer_work(unsigned long nexp) {
  int rc = -1, sc;
  struct shr **r;
  struct bb *b;

  switch(cfg.mode) {

    case mode_transmit:
      sc = update_rd_drops();
      if (sc < 0) goto done;
      break;

    case mode_receive:
      sc = bb_flush(cfg.ring, &cfg.bb);
      if (sc < 0) goto done;
      sc = update_rx_drops();
      if (sc < 0) goto done;
      break;

    case mode_watch:
      sc = status_rings();
      if (sc < 0) goto done;
      break;

    default:
      break;
  }

  rc = 0;

 done:
  return rc;
}

int show_stats(void) {

  return 0;
}

int handle_signal(void) {
  struct signalfd_siginfo info;
  ssize_t nr;
  int rc=-1;
  
  nr = read(cfg.signal_fd, &info, sizeof(info));
  if (nr != sizeof(info)) {
    fprintf(stderr,"failed to read signal fd buffer\n");
    goto done;
  }

  switch(info.ssi_signo) {
    case SIGALRM: 
      gettimeofday(&cfg.now, NULL);
      if (cfg.verbose) show_stats();
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

/*
 * handle_timer
 *
 * triggered when our timerfd periodically expires.
 * number of expirations is usually 1, but in a very
 * busy process multiple expirations can coalesce.
 *
 */
int handle_timer(void) {
  unsigned long nexp;
  int rc=-1, sc;
 
  sc = read(cfg.timer_fd, &nexp, sizeof(nexp));
  if (sc < 0) {
    fprintf(stderr,"read: %s\n", strerror(errno));
    goto done;
  }

  sc = timer_work(nexp);
  if (sc < 0) goto done;

  cfg.ticks++;

 rc = 0;

 done:
  return rc;
}

/*
 * encapsulate_tx
 *
 * using a raw IP socket, transmit GRE-encapsulated packets.
 * if necessary, perform IP fragmentation ourselves, as this
 * is not done by the OS when using raw sockets.
 */
char gbuf[MAX_PKT];
int encapsulate_tx(char *tx, ssize_t nx) {
  uint16_t encap_ethertype, more_fragments=1, fo=0, fn=0;
  uint32_t ip_src, ip_dst, seqno, off;
  struct sockaddr_in sin;
  struct sockaddr *dst;
  char *g, *ethertype;
  ssize_t nr, fl;
  socklen_t sz;

  assert(nx >= 14);

  ip_src = 0;
  ip_dst = cfg.encap.dst.s_addr;

  sin.sin_family = AF_INET;
  sin.sin_port = 0;
  sin.sin_addr = cfg.encap.dst;
  dst = (struct sockaddr*)&sin;
  sz = sizeof(sin);

  cfg.ip_id++;
  g = gbuf;
  off = 0;

  /* construct 20-byte IP header. 
   * NOTE: some zeroed header fields are filled out for us, when we send this
   * packet; particularly, checksum, src IP; ID and total length. see raw(7).
   */
  g[0] = 4 << 4;  /* IP version goes in MSB (upper 4 bits) of the first byte */
  g[0] |= 5;      /* IP header length (5 * 4 = 20 bytes) in lower 4 bits */
  g[1] = 0;       /* DSCP / ECN */
  g[2] = 0;       /* total length (upper byte) (see NOTE) */
  g[3] = 0;       /* total length (lower byte) (see NOTE) */
  g[4] = (cfg.ip_id & 0xff00) >> 8; /* id (upper byte); for frag reassembly */
  g[5] = (cfg.ip_id & 0x00ff);      /* id (lower byte); for frag reassembly */
  g[6] = 0;       /* 0 DF MF flags and upper bits of frag offset */
  g[7] = 0;       /* lower bits of frag offset */
  g[8] = 255;     /* TTL */
  g[9] = IPPROTO_GRE; /* IP protocol GRE == 47 */
  g[10] = 0;      /* IP checksum (high byte) (see NOTE) */
  g[11] = 0;      /* IP checksum (low byte) (see NOTE) */
  memcpy(&g[12], &ip_src, sizeof(ip_src)); /* IP source (see NOTE) */
  memcpy(&g[16], &ip_dst, sizeof(ip_dst)); /* IP destination */

  g += 20;

  /* GRE header starts */

  switch(cfg.encap.mode) {
    case mode_gre:
      memset(g, 0, 2); /* zero first two bytes of GRE header */
      g[0] |= (cfg.encap.key ? (1U << 5) : 0); /* key bit */
      g += 2;
      ethertype = &tx[12]; /* copy ethertype from packet into GRE header */
      memcpy(g, ethertype, sizeof(uint16_t));
      g += 2;
      if (cfg.encap.key) {
        memcpy(g, &cfg.encap.key, 4);
        g += 4;
      }
      nx -= 14; tx += 14; // elide original MACs and ethertype!
      assert(nx <= sizeof(gbuf)-(g-gbuf));
      memcpy(g, tx, nx);
      g += nx;
      nx = g-gbuf;
      break;
    case mode_gretap:
      memset(g, 0, 2); /* zero first two bytes of GRE header */
      g[0] |= (cfg.encap.key ? (1U << 5) : 0); /* key bit */
      g += 2;
      encap_ethertype = htons(0x6558); /* transparent ethernet bridging */
      memcpy(g, &encap_ethertype, sizeof(uint16_t));
      g += 2;
      if (cfg.encap.key) {
        memcpy(g, &cfg.encap.key, 4);
        g += 4;
      }
      assert(nx <= sizeof(gbuf)-(g-gbuf));
      memcpy(g, tx, nx);
      g += nx;
      nx = g-gbuf;
      break;
    default:
      assert(0);
      break;
  }

  /*
   * send IP packet, performing fragmentation if greater than mtu
   */
  do {

    more_fragments = (nx > cfg.mtu) ? 1 : 0;
    assert((off & 0x7) == 0);
    fo = off / 8;

    gbuf[6]  = more_fragments ? (1 << 5) : 0; /* 0 DF [MF] flag */
    gbuf[6] |= (fo & 0x1f00) >> 8; /* upper bits of frag offset */
    gbuf[7] =  fo & 0x00ff;        /* lower bits of frag offset */

    /* choose fragment length so it's below MTU and so the payload 
     * length after 20 byte header is a multiple of 8 as required */
    if (more_fragments)
      fl = ((cfg.mtu - 20) & ~7U) + 20;
    else
      fl = nx;

    nr = sendto(cfg.tx_fd, gbuf, fl, 0, dst, sz);
    if (nr != fl) {
      fprintf(stderr,"sendto: %s\n", (nr<0) ? 
        strerror(errno) : "incomplete");
      return -1;
    }

    /* keeping 20-byte IP header, slide next fragment payload */
    if (more_fragments) {
      assert(fl > 20);
      memmove(&gbuf[20], &gbuf[fl], nx - fl);
      off += (fl - 20);
      nx  -= (fl - 20);
    }

  } while (more_fragments);

  return 0;
}

/* inject four bytes to the ethernet frame with an 802.1q vlan tag.
 * note if this makes MTU exceeded it may result in sendto error */
char buf[MAX_PKT];
char vlan_tag[VLAN_LEN] = {0x81, 0x00, 0x00, 0x00};
char *inject_vlan(char *tx, ssize_t *nx, uint16_t vlan) {
  if (((*nx) + 4) > MAX_PKT) return NULL;
  if ((*nx) <= MACS_LEN) return NULL;
  /* prepare 802.1q tag vlan portion in network order */
  uint16_t v = htons(vlan);
  memcpy(&vlan_tag[2], &v, sizeof(v));
  /* copy MAC's from original packet, inject 802.1q, copy packet */
  memcpy(buf,                   tx,            MACS_LEN);
  memcpy(buf+MACS_LEN,          vlan_tag,      VLAN_LEN);
  memcpy(buf+MACS_LEN+VLAN_LEN, tx + MACS_LEN, (*nx) - MACS_LEN);
  *nx += 4;
  return buf;
}

/* apply filtering to a rx or tx packet */
int keep_packet(char *tx, size_t nx) {
  uint16_t vlan;
  int r;

  /* apply vlan test, if enabled */
  if (cfg.pass_vlan) {

    if (nx < MACS_LEN + VLAN_LEN)
      return 0;

    if (memcmp(&tx[MACS_LEN], "\x81\x00", 2))
      return 0;

    memcpy(&vlan, &tx[MACS_LEN+2], sizeof(vlan));
    vlan = ntohs(vlan);
    vlan &= 0x0fff;

    if (vlan != cfg.pass_vlan)
      return 0;
  }

  /* apply random drop, if enabled */
  if (cfg.drop_pct != 0) {
    r = rand();
    if ((r * 100.0 / RAND_MAX) < cfg.drop_pct)
      return 0;
  }

  return 1;
}

/* tx-ring mode only: start transmission from the ring */
int initiate_transmit(void) {

  assert(cfg.use_tx_ring);

  /* initiate transmit, without waiting for completion */
  if (send(cfg.tx_fd, NULL, 0, MSG_DONTWAIT) < 0) {

    /* if tx is underway or the kernel can't sink any more data we can get
     * "resource temporarily unavailable". solution: start a blocking tx */
    if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {

      if (send(cfg.tx_fd, NULL, 0, 0) < 0) {
        fprintf(stderr,"blocking transmit failed: %s\n", strerror(errno));
        return -1;
      }

    } else {

      /* any other kind of send error is fatal */
      fprintf(stderr,"failed to initiate transmit: %s\n", strerror(errno));
      return -1;
    }
  }

  return 0;
}

/* tx-ring mode only: poll kernel for space availability in tx ring */
int wait_for_tx_space(void) {
  int rc, timeout = 1000; /* milliseconds */

  assert(cfg.use_tx_ring);

  struct pollfd pfd;
  pfd.fd = cfg.tx_fd;
  pfd.revents = 0;
  pfd.events = POLLOUT;

  rc = poll(&pfd, 1, timeout);
  if (rc <= 0) {
    fprintf(stderr, "poll for tx space: %s\n", rc ? strerror(errno) : "timeout");
    return -1;
  }

  return 0;
}

int transmit_packets(void) {
  int rc=-1, n, len, nq=0, failsafe=0;
  struct sockaddr *dst = NULL;
  struct sockaddr_in sin;
  ssize_t nr,nt,nx;
  struct iovec *io;
  socklen_t sz = 0;
  uint8_t *mac;
  size_t nio;

  /* get pointer to iov array to be populated */
  utvector_clear(cfg.rb.iov);
  nio = cfg.rb.iov->n;
  io = (struct iovec*)cfg.rb.iov->d;

  /* read packets, up to BATCH_PKTS or BATCH_SIZE bytes */
  nr = shr_readv(cfg.ring, cfg.rb.d, cfg.rb.n, io, &nio);
  if (nr < 0) {
    fprintf(stderr, "shr_readv error: %ld\n", (long)nr);
    goto done;
  }

  /* set number of used iov slots */
  assert(nio <= cfg.rb.iov->n);
  cfg.rb.iov->i = nio;

  /* iterate over packets obtained in shr_readv */
  io = NULL;
  while ( (io = utvector_next(cfg.rb.iov, io))) {

    char *tx = io->iov_base; /* packet */
    nx = io->iov_len;        /* length */
    if (keep_packet(tx, nx) == 0) continue;

    /* inject 802.1q tag if requested */
    if (cfg.vlan) tx = inject_vlan(tx,&nx,cfg.vlan);
    if (tx == NULL) {
      fprintf(stderr, "vlan tag injection failed\n");
      goto done;
    }

    /* truncate outgoing packet if requested */
    if (cfg.size && (nx > cfg.size)) nx = cfg.size;

    /* trim N bytes from frame end if requested. */
    if (cfg.tail && (nx > cfg.tail)) nx -= cfg.tail;

    /* wrap encapsulation around it, if enabled */
    if (cfg.encap.enable) {

      if (encapsulate_tx(tx, nx)) goto done;
      continue;

    } else if (cfg.use_tx_ring == 0) {

      nt = sendto(cfg.tx_fd, tx, nx, 0, dst, sz);
      if (nt != nx) {
        fprintf(stderr,"sendto: %s\n", (nt<0) ? 
          strerror(errno) : "incomplete");
        goto done;
      }

      continue;
    }

    /*************************************************************
     * packet tx ring mode below
     ************************************************************/

    assert(cfg.encap.enable == 0);
    assert(cfg.use_tx_ring);

    /* copy packet into kernel tx ring 
     *
     * each packet occupies a slot. a tpacket2_hdr precedes the packet.
     * once we initiate transmission from the ring, the tx progresses
     * in kernel space. later, when we come round to the slot again,
     * we can check its transmission status or outcome.
     *
     * a tx error, due to a malformed packet, causes the kernel to stop
     * transmitting from the ring. it sets TP_STATUS_WRONG_FORMAT on the
     * packet. normally, we treat this condition fatally. if the "keep 
     * going" option is enabled, tx errors are suppressed and ignored.

     * when we are about to write a packet into the slot, we may find
     * the slot is in this tx error state due to the previous packet.
     * or, we may find that the slot is still in-use. due to our
     * independence from the actual tranmission process, we only learn
     * of these states when we come round to the slot. it is normal to
     * encounter uninitiated or in-progress transmission, and we wait
     * for availability in the ring in that case.
     *
     * for all its sophistication, the ring-based transmitter had
     * lower performance in my tests than the sendto-based transmitter.
     * this may be due to the extra copying we do to populate the ring.
     * this is why the sendto-transmitter is used by default.
     *
     */

    /* get address of the current slot (metadata header, pad, packet) */
    uint8_t *cur = cfg.pb.d + cfg.ring_curr_idx * cfg.ring_frame_sz;

    /* struct tpacket2_hdr is defined in /usr/include/linux/if_packet.h */
    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)cur;

   retry_slot:

    if (failsafe++ > 1) {
      fprintf(stderr, "internal error awaiting tx ring availability\n");
      goto done;
    }

    /* did the slot have a previous error? */
    if (hdr->tp_status == TP_STATUS_WRONG_FORMAT) {
      fprintf(stderr,"tx error- frame dump follows; exiting.\n");
      hexdump(cur, cfg.ring_frame_sz);
      goto done;
    }

    /* is the slot in-use, in the midst of transmission? */
    if (hdr->tp_status == TP_STATUS_SENDING) {
      if (wait_for_tx_space() < 0) goto done;
      goto retry_slot;
    }

    /* is the slot in-use, awaiting transmit to begin? this can happen if
     * we loop around the ring, before initiating transmit (say, if the batch
     * size exceeds the ring size). it can also happen if we did initiate tx,
     * if the kernel has yet to get to this packet and flag it sending.
     */
    if (hdr->tp_status == TP_STATUS_SEND_REQUEST) {
      if (initiate_transmit() < 0) goto done;
      if (wait_for_tx_space() < 0) goto done;
      goto retry_slot;
    }

    /* if we got here, the slot _must_ be available. right? */
    if (hdr->tp_status != TP_STATUS_AVAILABLE) {
      fprintf(stderr,"tx slot: unexpected flag %d\n", hdr->tp_status);
      goto done;
    }

    failsafe = 0;  /* reset loop safegaurd */

    /* put packet's link level header (first MAC) after the tpacket2_hdr plus
     * alignment gap.  (struct sockaddr_ll is not in the slot during tx). */
    mac = (uint8_t*)TPACKET_ALIGN(((unsigned long)cur) +
          sizeof(struct tpacket2_hdr));
    len = cfg.ring_frame_sz - (mac - cur);
    if (nx > len) {
      fprintf(stderr, "packet length %ld exceeds effective frame_size %d\n",
        (long)nx, len);
      goto done;
    }

    /* populate packet proper */
    memcpy(mac, tx, nx);
    hdr->tp_len = nx;
    hdr->tp_status = TP_STATUS_SEND_REQUEST;
    nq++;

    /* point to next slot */
    cfg.ring_curr_idx = (cfg.ring_curr_idx + 1) % cfg.ring_frame_nr;
  }

  /* if packets were queued in to kernel tx ring, initiate transmit */
  if (nq && (initiate_transmit() < 0)) goto done;

  rc = 0;

 done:
  return rc;
}

int receive_packets(void) {
  int rc=-1, sw, wire_vlan, form_vlan, keep;
  ssize_t nr,nt,nx;
  struct iovec iov;
  char *tx;

  while (1) {

    /* get address of the current slot (metadata header, pad, packet) */
    uint8_t *cur = cfg.pb.d + cfg.ring_curr_idx * cfg.ring_frame_sz;

    /* these structs start the frame, see /usr/include/linux/if_packet.h */
    struct tpacket2_hdr *hdr = (struct tpacket2_hdr *)cur;
    struct sockaddr_ll *sll = (struct sockaddr_ll *)(cur + TPACKET2_HDRLEN);

    /* check if the packet is ready. this is how we break the loop */
    if ((hdr->tp_status & TP_STATUS_USER) == 0) break;

    /* note packet drop condition */
    if (hdr->tp_status & TP_STATUS_LOSING) cfg.losing = 1;

    tx = cur + hdr->tp_mac;
    nx = hdr->tp_snaplen;

    /* upon receipt the wire vlan (if any) has been pulled out for us */
    wire_vlan = (hdr->tp_status & TP_STATUS_VLAN_VALID) ? 
                (hdr->tp_vlan_tci & 0xfff) : 0;
    form_vlan = cfg.vlan ? cfg.vlan : wire_vlan;
    if (cfg.strip_vlan) form_vlan = 0;

    /* inject 802.1q tag if requested */
    if (form_vlan) tx = inject_vlan(tx,&nx,form_vlan);
    if (tx == NULL) {
      fprintf(stderr, "vlan tag injection failed\n");
      goto done;
    }

    /* truncate packet if requested */
    if (cfg.size && (nx > cfg.size)) nx = cfg.size;

    /* trim N bytes from frame end if requested. */
    if (cfg.tail && (nx > cfg.tail)) nx -= cfg.tail;

    keep = keep_packet(tx,nx);

    /* push into batch buffer */
    sw = keep ? bb_write(cfg.ring, &cfg.bb, tx, nx) : 0;
    if (sw < 0) {
      fprintf(stderr, "bb_write (%lu bytes): error code %d\n", (long)nx, sw);
      goto done;
    }

    /* return the packet by assigning status word TP_STATUS_KERNEL (0) */
    hdr->tp_status = TP_STATUS_KERNEL;

    /* next packet */
    cfg.ring_curr_idx = (cfg.ring_curr_idx + 1) % cfg.ring_frame_nr;
  }

  rc = 0;

 done:
  return rc;
}

/* decode the gre packet into its fields.
 * input pkt starts with outer IP header.
 * fields are returned in network order!
 * fields are zeroed if not present
 * on decoding failure, returns -1.
 * returns 0 on success
 */
#define GRE_MIN_HDR 4
#define GRE_CHECKSUM_LEN 2
#define GRE_RESERVED1_LEN 2
#define GRE_KEY_LEN 4
#define GRE_SEQNO_LEN 4
int decode_gre(char *pkt, ssize_t nr, uint16_t *csum, uint32_t *key, 
               uint32_t *seqno, char **payload, size_t *plen) {
  int has_key, has_checksum, has_seqno, ko, co, so, po, ip_hdr_len;
  uint8_t ip_proto;

  *key = 0;
  *seqno = 0;
  *csum = 0;
  *payload = NULL;
  *plen = 0;

  assert(nr > 0);
  ip_hdr_len = (pkt[0] & 0x0f) * 4;

  if (nr < ip_hdr_len + GRE_MIN_HDR)
    return -1;

  ip_proto = pkt[9];
  if (ip_proto != IPPROTO_GRE)
    return -1;

  has_key      = pkt[ip_hdr_len] & (1U << 5);
  has_checksum = pkt[ip_hdr_len] & (1U << 7);
  has_seqno    = pkt[ip_hdr_len] & (1U << 4);

  if (has_checksum) {
    co = ip_hdr_len + GRE_MIN_HDR;
    if (co + GRE_CHECKSUM_LEN > nr)
      return -1;
    memcpy(csum, pkt + co, GRE_CHECKSUM_LEN);
  }

  if (has_key) {
    ko = ip_hdr_len + GRE_MIN_HDR
         + (has_checksum ? GRE_CHECKSUM_LEN + GRE_RESERVED1_LEN : 0);
    if (ko + GRE_KEY_LEN > nr)
      return -1;
    memcpy(key, pkt + ko, GRE_KEY_LEN);
  }

  if (has_seqno) {
    so = ip_hdr_len + GRE_MIN_HDR +
         + (has_checksum ? GRE_CHECKSUM_LEN + GRE_RESERVED1_LEN : 0)
         + (has_key      ? GRE_KEY_LEN : 0);
    if (so + GRE_SEQNO_LEN > nr)
      return -1;
    memcpy(seqno, pkt + so, GRE_SEQNO_LEN);
  }

  po = ip_hdr_len + GRE_MIN_HDR +
       + (has_checksum ? GRE_CHECKSUM_LEN + GRE_RESERVED1_LEN : 0)
       + (has_key      ? GRE_KEY_LEN : 0)
       + (has_seqno    ? GRE_SEQNO_LEN : 0);

  *plen = nr - po;
  *payload = pkt + po;
  return 0;
}

int handle_grerx(void) {
  int i, rc=-1, sc, keep, nmsgs;
  char *data, *tx, *pkt;
  size_t dlen, nx, len;
  uint32_t seqno, key;
  uint16_t csum;
  ssize_t nr;

  nmsgs = recvmmsg(cfg.rx_fd, cfg.msgv, BATCH_PKTS, MSG_WAITFORONE, NULL);
  if (nmsgs < 0) {
    fprintf(stderr, "recvmmsg: %s\n", strerror(errno));
    goto done;
  }

  if (cfg.verbose)
    fprintf(stderr, "recvmmsg: %d messages received\n", nmsgs);

  for(i=0; i < nmsgs; i++) {

    pkt = cfg.msgv[i].msg_hdr.msg_iov[0].iov_base;
    len = cfg.msgv[i].msg_len;
    sc = decode_gre(pkt, len, &csum, &key, &seqno, &data, &dlen);
    if (sc < 0) {
      rc = 0;  /* ignore and drop bad packets */
      goto done;
    }

    /* test key matches desired key */
    if (cfg.encap.key != key) {
      rc = 0;
      goto done;
    }

    /* decapsulate packet, advance over GRE header */
    tx = data;
    nx = dlen;
    if (nx == 0) {
      rc = 0;
      goto done;
    }

    /* inject 802.1q tag if requested */
    if (cfg.vlan) tx = inject_vlan(tx,&nx,cfg.vlan);
    if (tx == NULL) {
      fprintf(stderr, "vlan tag injection failed\n");
      goto done;
    }

    /* truncate packet if requested */
    if (cfg.size && (nx > cfg.size)) nx = cfg.size;

    /* trim N bytes from frame end if requested. */
    if (cfg.tail && (nx > cfg.tail)) nx -= cfg.tail;

    keep = keep_packet(tx,nx);

    /* push into batch buffer */
    sc = keep ? bb_write(cfg.ring, &cfg.bb, tx, nx) : 0;
    if (sc < 0) {
      fprintf(stderr, "bb_write (%lu bytes): error code %d\n", (long)nx, sc);
      goto done;
    }
  }

  rc = 0;

 done:
  return rc;
}

int handle_io(void) {
  int rc = -1;

  switch(cfg.mode) {
    case mode_receive:
      rc = receive_packets();
      break;
    case mode_transmit:
      rc = transmit_packets();
      break;
    default:
      assert(0);
      break;
  }

  return rc;
}

size_t kmgt(char *optarg) {
 size_t size=0;
 char unit;

 int n = sscanf(optarg, "%lu%c", &size, &unit);
 if (n == 0) usage();
 if (n == 2) {
    switch (unit) {
      case 't': case 'T': size *= 1024; /* fall through */
      case 'g': case 'G': size *= 1024; /* fall through */
      case 'm': case 'M': size *= 1024; /* fall through */
      case 'k': case 'K': size *= 1024; break;
      default: usage(); break;
    }
 }

 return size;
}

int parse_encap(char *opt) {
  int rc = -1, len;
  char *mode=opt,*name=opt, *colon;
  struct hostent *e;

  colon = strchr(mode,':');
  if (colon) *colon = '\0';
  else if (cfg.mode == mode_transmit) {
    fprintf(stderr,"encapsulation syntax error\n");
    goto done;
  }

  if      (!strcmp(mode,"gre"))    cfg.encap.mode = mode_gre;
  else if (!strcmp(mode,"gretap")) cfg.encap.mode = mode_gretap;
  else { 
    fprintf(stderr,"invalid encapsulation mode\n");
    goto done;
  }

  /* name is destination hostname (GRE tx mode),
              or local IP to bind (GRE rx mode) */
  if (colon) {
    name = colon+1;
    e = gethostbyname(name);
    if (e == NULL) {
      fprintf(stderr, "gethostbyname: %s: %s\n", name, hstrerror(h_errno));
      goto done;
    }

    if (e->h_length != sizeof(cfg.encap.dst)) {
      fprintf(stderr, "DNS result size mismatch\n");
      goto done;
    }

    memcpy(&cfg.encap.dst.s_addr, e->h_addr, e->h_length);
  }

  rc = 0;

 done:
  return rc;
}

int main(int argc, char *argv[]) {
  int rc = -1, n, opt, ring_mode, init_mode, pos, sc;
  struct epoll_event ev;
  cfg.prog = argv[0];
  struct shr *r;
  struct bb *b;
  char *file;
  void **p;

  cfg.watch_rings = utvector_new(utmm_ptr);
  cfg.watch_names = utvector_new(utstring_mm);
  cfg.watch_win = utvector_new(&ww_mm);
  utstring_new(cfg.tmp);
  utmm_init(&bb_mm, &cfg.bb, 1);
  utmm_init(&bb_mm, &cfg.rb, 1);
  utmm_init(&bb_mm, &cfg.gb, 1);

  while ( (opt=getopt(argc,argv,"t:r:c:vi:hV:s:D:E:B:S:Z:Qd:K:Rqkf:")) != -1) {
    switch(opt) {
      case 't': cfg.mode = mode_transmit; if (*optarg != 'x') usage(); break;
      case 'r': cfg.mode = mode_receive;  if (*optarg != 'x') usage(); break;
      case 'c': cfg.mode = mode_create;   if (*optarg != 'r') usage(); break;
      case 'E': cfg.encap.enable=1; if (parse_encap(optarg)) usage(); break;
      case 'v': cfg.verbose++; break;
      case 'k': cfg.keep=1; break;
      case 'V': cfg.vlan=atoi(optarg); break; 
      case 'D': cfg.tail=atoi(optarg); break; 
      case 's': cfg.size = kmgt(optarg); break;
      case 'B': cfg.ring_block_nr=atoi(optarg); break;
      case 'S': cfg.ring_block_sz = 1 << (unsigned)atoi(optarg); break;
      case 'Z': cfg.ring_frame_sz=atoi(optarg); break;
      case 'q': cfg.bypass_qdisc_on_tx = 1; break;
      case 'Q': cfg.strip_vlan = 1; break;
      case 'd': cfg.drop_pct=100-atoi(optarg); break;
      case 'K': cfg.encap.key = strchr(optarg, '.') ? 
                inet_addr(optarg) : htonl(atoi(optarg));
                break;
      case 'R': cfg.use_tx_ring = 1; break;
      case 'i': if (!strcmp(optarg, "o")) cfg.mode = mode_watch; /* -io */
                else {                                           /* -i <nic> */
                  if (strlen(optarg)+1 > MAX_NIC) goto done;
                  strncpy(cfg.dev, optarg, MAX_NIC);
                }
                break;
      case 'f': sc = sscanf(optarg, "vlan %d", &cfg.pass_vlan);
                if (sc != 1) usage();
                break;
      case 'h': default: usage(); break;
    }
  }

  if ((cfg.drop_pct < 0) || (cfg.drop_pct > 100)) usage();

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

  /* create the timerfd for receiving clock events */
  cfg.timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (cfg.timer_fd == -1) {
    fprintf(stderr,"timerfd_create: %s\n", strerror(errno));
    goto done;
  }

  /* set up for periodic timer expiration */
  sc = timerfd_settime(cfg.timer_fd, 0, &cfg.timer, NULL);
  if (sc < 0) {
    fprintf(stderr, "timerfd_settime: %s\n", strerror(errno));
    goto done;
  }

  /* set up the epoll instance */
  cfg.epoll_fd = epoll_create(1); 
  if (cfg.epoll_fd == -1) {
    fprintf(stderr,"epoll: %s\n", strerror(errno));
    goto done;
  }

  /* add descriptors of interest */
  if (new_epoll(EPOLLIN, cfg.signal_fd)) goto done;
  if (new_epoll(EPOLLIN, cfg.timer_fd))  goto done;
  if (cfg.mode == mode_watch && isatty(STDIN_FILENO)) {
   if (new_epoll(EPOLLIN, STDIN_FILENO)) goto done;
  }

  /* in transmit mode, epoll on the ring descriptor.
   * in receive mode, epoll on the raw socket.
   */
  switch (cfg.mode) {
    case mode_receive:
      if (cfg.dev == NULL) usage();
      ring_mode = SHR_WRONLY;
      cfg.file = (optind < argc) ? argv[optind++] : NULL;
      cfg.ring = shr_open(cfg.file, ring_mode);
      if (cfg.ring == NULL) goto done;
      sc = cfg.encap.enable ? setup_rx_encap() : setup_rx();
      if (sc < 0) goto done;
      sc = cfg.encap.enable ? new_epoll(EPOLLIN, cfg.rx_fd) : 
                              new_epoll(EPOLLIN, cfg.fd);
      if (sc < 0) goto done;
      break;
    case mode_transmit:
      if ((cfg.dev == NULL) && (cfg.encap.enable == 0)) usage();
      ring_mode = SHR_RDONLY|SHR_NONBLOCK;
      cfg.file = (optind < argc) ? argv[optind++] : NULL;
      cfg.ring = shr_open(cfg.file, ring_mode);
      if (cfg.ring == NULL) goto done;
      cfg.fd = shr_get_selectable_fd(cfg.ring);
      if (cfg.fd < 0) goto done;
      if (new_epoll(EPOLLIN, cfg.fd)) goto done;
      if (setup_tx() < 0) goto done;
      break;
    case mode_create:
      if (cfg.size == 0) usage();
      while (optind < argc) {
        file = argv[optind++];
        init_mode = SHR_DROP|SHR_FARM|SHR_MLOCK|SHR_APPDATA;
        if (cfg.keep) init_mode |= SHR_KEEPEXIST;
        if (cfg.verbose) fprintf(stderr,"creating %s\n", file);
        sc = shr_init(file, cfg.size, init_mode, &cfg.stats, sizeof(cfg.stats));
        if (sc < 0) goto done;
      }
      rc = 0;
      goto done;
      break;
    case mode_watch:
      while (optind < argc) {
        file = argv[optind++];
        utstring_clear(cfg.tmp);
        utstring_printf(cfg.tmp, "%s", file);
        utvector_push(cfg.watch_names, cfg.tmp);
        r = shr_open(file, SHR_RDONLY);
        if (r == NULL) goto done;
        utvector_push(cfg.watch_rings, &r);
        utvector_extend(cfg.watch_win);
      }
      /* clear screen, move to 0,0 */
      printf("\033[2J\n");
      break;
    default:
      usage();
  }

  /* block all signals. we take signals synchronously via signalfd */
  alarm(1);

  while (1) {
    sc = epoll_wait(cfg.epoll_fd, &ev, 1, -1);
    if (sc < 0) {
      fprintf(stderr, "epoll: %s\n", strerror(errno));
      goto done;
    }

    if (sc == 0) { assert(0); goto done; }
    else if (ev.data.fd == cfg.signal_fd) { if (handle_signal() < 0) goto done;}
    else if (ev.data.fd == cfg.timer_fd)  { if (handle_timer()  < 0) goto done;}
    else if (ev.data.fd == cfg.rx_fd)     { if (handle_grerx()  < 0) goto done;}
    else if (ev.data.fd == cfg.fd)        { if (handle_io() < 0) goto done; }
    else if (ev.data.fd == STDIN_FILENO)  { goto done; }
    else {
      fprintf(stderr, "error: unknown descriptor\n");
      goto done;
    }
  }
  
  rc = 0;

done:
  /* in these modes, fd is internal to shr and closed by it */
  if (cfg.mode != mode_transmit) {
    if (cfg.fd != -1) close(cfg.fd);
  }
  if (cfg.tx_fd != -1) close(cfg.tx_fd);
  if (cfg.rx_fd != -1) close(cfg.rx_fd);
  if (cfg.signal_fd != -1) close(cfg.signal_fd);
  if (cfg.timer_fd != -1) close(cfg.timer_fd);
  if (cfg.epoll_fd != -1) close(cfg.epoll_fd);
  utmm_fini(&bb_mm, &cfg.bb, 1);
  utmm_fini(&bb_mm, &cfg.rb, 1);
  utmm_fini(&bb_mm, &cfg.gb, 1);
  if ((cfg.pb.n != 0) && (cfg.pb.d != MAP_FAILED)) {
    munmap(cfg.pb.d, cfg.pb.n); /* cfg.pb is mode specfic */
    assert(cfg.pb.iov == NULL); /* iov part of pb unused */
  }
  if (cfg.ring) shr_close(cfg.ring);
  p = NULL;
  while ( (p = utvector_next(cfg.watch_rings, p))) shr_close(*p);
  utvector_free(cfg.watch_rings);
  utvector_free(cfg.watch_names);
  utstring_free(cfg.tmp);
  utvector_free(cfg.watch_win);
  return rc;
}
