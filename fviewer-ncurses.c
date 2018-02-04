#include <ncurses.h>
#include <termios.h>
#include "fluxcap.h"

int init_ncurses(struct watch_ui *ui) {
  int rc= -1;

  initscr();
  start_color();
  getmaxyx(stdscr, ui->rows, ui->cols);

  init_pair(1, COLOR_WHITE,   COLOR_GREEN);
  init_pair(2, COLOR_RED,     COLOR_BLACK);
  init_pair(3, COLOR_GREEN,   COLOR_BLACK);
  init_pair(4, COLOR_MAGENTA, COLOR_BLACK);
  init_pair(5, COLOR_CYAN,    COLOR_BLACK);
  init_pair(6, COLOR_YELLOW,  COLOR_BLACK);
  init_pair(7, COLOR_BLUE,    COLOR_BLACK);
  init_pair(8, COLOR_WHITE,   COLOR_BLACK);

  curs_set(0); // cursor visibilty (0=hide; 1=normal)
  clear();
  rc = 0;
  return rc;
}

int want_keys(int want_keystrokes) {
  int rc = -1;
  struct termios t;

  if (isatty(STDIN_FILENO) == 0) return 0;

  if (tcgetattr(STDIN_FILENO, &t) < 0) {
    fprintf(stderr,"tcgetattr: %s\n", strerror(errno));
    goto done;
  }

  if (want_keystrokes) t.c_lflag &= ~(ICANON|ECHO);
  else                 t.c_lflag |=  (ICANON|ECHO);

  if (tcsetattr(STDIN_FILENO, TCSANOW, &t) < 0) {
    fprintf(stderr,"tcsetattr: %s\n", strerror(errno));
    goto done;
  }
  rc = 0;
 done:
  return rc;
}

int init_watch_ui(struct watch_ui *ui) {
  int rc  = -1;
  char *term;
  size_t l;

  if (want_keys(1) < 0) goto done;
  if (init_ncurses(ui) < 0) goto done;

  gethostname(ui->title, sizeof(ui->title));

  /* title is "<hostname> Intake Monitor" */
  l = strlen(ui->title);
  if (sizeof(ui->title) - l >= 20)
    strcat(ui->title, " Intake Monitor");

  /* acs characters for nice looking bars.
     putty often identifies as an xterm,
     render poorly, unless under screen */
  term = getenv("TERM");
  ui->acs = (term && strcmp(term, "xterm")) ? 1 : 0;
  ui->acs += getenv("STY") ? 1 : 0;

  rc = 0;

 done:
  return 0;
}

int fini_watch_ui(struct watch_ui *ui) {
  int rc = -1;

  /* restore terminal */
  endwin();
  want_keys(0);

  rc = 0;
  return 0;
}


/*
 * bar
 *
 * draw a boxed bar using ncurses symbols
 * whose height occupies three rows 
 * whose length occupies 16 columns
 * whose level ranges from 0 to 12 (bar length)
 *
 */
#define BARW 16
int bar(struct watch_ui *ui, unsigned row, unsigned col, unsigned level) {
  unsigned i, r,c;
  unsigned long b;
  int rc = -1;

  unsigned long ul, vl, ur, ll, lr, hl;
  ul = ui->acs ? ACS_ULCORNER : ' ';
  vl = ui->acs ? ACS_VLINE    : ' ';
  ur = ui->acs ? ACS_URCORNER : ' ';
  ll = ui->acs ? ACS_LLCORNER : ' ';
  lr = ui->acs ? ACS_LRCORNER : ' ';
  hl = ui->acs ? ACS_HLINE    : ' ';

  if (level > 12) level = 12;

  r = row;
  c = col;

  /* top border */
  mvaddch(r, c, ul);
  for(i=1; i < BARW; i++) mvaddch(r, c+i, hl);
  mvaddch(r, c+BARW, ur);

  /* central row */
  r++;
  mvaddch(r, c, vl);
  b = ' ';
  b |= A_STANDOUT;
  b |= COLOR_PAIR(3);
  for(i=1; i < level+1; i++) mvaddch(r, c+i, b);
  mvaddch(r, c+BARW, vl);

  /* bottom border */
  r++;
  mvaddch(r, c, ll);
  for(i=1; i < BARW; i++) mvaddch(r, c+i, hl);
  mvaddch(r, c+BARW, lr);

  rc = 0;

 done:
  return rc;
}
/*
 * display_rates
 *
 * this is the heart of the beast
 * go through each ring and render
 *
 */
int display_rates(struct watch_ui *ui, struct iovec *wiov, size_t niov) {
  int rc = -1, rx_loss, rd_loss;
  struct ww *w;
  size_t n, l;
  unsigned row, col, r;
  unsigned long c;

  clear();
  row=0;
  col=0;

  /* title text */
  l = strlen(ui->title);
  col = (80-l)/2;
  attrset( A_BOLD | COLOR_PAIR(3) );
  mvprintw(row, col, ui->title);
  attrset(0);
  row += 3;

  for(n=0; n < niov; n++) {

    if (row + 4 > ui->rows) break;

    w = (struct ww*)(wiov[n].iov_base);

    /* bar */
    attrset(A_BOLD | COLOR_PAIR(3) );
    col = 0;  bar(ui, row-1, col+1, w->ps.lg10_b);

    /* name */
    attrset( A_BOLD | COLOR_PAIR(5) );
    col = 20; mvprintw(row, col, w->name);

    /* rates */
    attrset(A_BOLD);
    col = 40; mvprintw(row, col, (ui->unit == rate_bps) ? 
                                  w->ps.str.E : 
                                  w->ps.str.P );
    /* drops */
    attrset(A_BOLD | COLOR_PAIR(2) );
    rx_loss = w->ps.rx;
    rd_loss = w->ps.rd;
    r = row;
    if (rx_loss) {
      r++;
      col = 20; mvprintw(r, col, "rx loss");
      col = 40; mvprintw(r, col, w->ps.str.X);
    }
    if (rd_loss) {
      r++;
      col = 20; mvprintw(r, col, "lag loss");
      col = 40; mvprintw(r, col, w->ps.str.D);
    }

    row += 4;
  }

  refresh();
  rc = 0;

  return rc;
}

