/* -*- mode:c; coding: koi8-r -*- */
/* $Id$ */

#include "userlist_clnt.h"
#include "userlist_proto.h"
#include "contests.h"
#include "userlist.h"
#include "userlist_cfg.h"

#include <reuse/osdeps.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <ncurses/ncurses.h>
#include <ncurses/menu.h>
#include <ncurses/panel.h>
#include <locale.h>

#define _(x) x
static char const * const member_string[] =
{
  _("Contestant"),
  _("Reserve"),
  _("Coach"),
  _("Advisor"),
  _("Guest")
};
static char const * const member_string_pl[] =
{
  _("Contestants"),
  _("Reserves"),
  _("Coaches"),
  _("Advisors"),
  _("Guests")
};
static char const * const member_status_string[] =
{
  _("Empty"),
  _("School student"),
  _("Student"),
  _("Magistrant"),
  _("PhD student"),
  _("School teacher"),
  _("Professor"),
  _("Scientist"),
  _("Other")
};
#undef _

#define XALLOCAZ(p,s) (XALLOCA((p),(s)),XMEMZERO((p),(s)))

static struct userlist_clnt *server_conn;
static struct contest_list *contests;
static struct userlist_cfg *config;
static WINDOW *root_window;

static int
display_user_menu(unsigned char *upper, int start_item, int only_choose);
static int
display_contests_menu(unsigned char *upper, int only_choose);

static void
print_help(char const *help)
{
  wattrset(stdscr, COLOR_PAIR(3));
  wbkgdset(stdscr, COLOR_PAIR(3));
  mvwaddstr(stdscr, LINES - 1, 0, help);
  wclrtoeol(stdscr);
  wattrset(stdscr, COLOR_PAIR(1));
  wbkgdset(stdscr, COLOR_PAIR(1));
}

static void
vis_err(unsigned char const *fmt, ...)
{
  unsigned char buf[1024];
  int buflen;
  va_list args;
  int req_cols, req_lines, first_line, first_col;
  WINDOW *out_win, *in_win;
  PANEL *out_pan, *in_pan;

  va_start(args, fmt);
  buflen = vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  if (buflen > COLS - 2) {
    req_lines = buflen / (COLS - 2) + 1;
    req_cols = COLS - 2;
  } else {
    req_lines = 1;
    req_cols = buflen;
  }
  first_line = (LINES - req_lines - 2) / 2;
  first_col = (COLS - req_cols - 2) / 2;
  out_win = newwin(req_lines + 2, req_cols + 2, first_line, first_col);
  in_win = newwin(req_lines, req_cols, first_line + 1, first_col + 1);
  wattrset(out_win, COLOR_PAIR(4));
  wbkgdset(out_win, COLOR_PAIR(4));
  wattrset(in_win, COLOR_PAIR(4));
  wbkgdset(in_win, COLOR_PAIR(4));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  waddstr(in_win, buf);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  update_panels();
  print_help("Press any key to continue");
  doupdate();
  (void) getch();
  del_panel(in_pan);
  del_panel(out_pan);
  delwin(out_win);
  delwin(in_win);
  update_panels();
  doupdate();
}

static int
okcancel(unsigned char const *fmt, ...)
{
  va_list args;
  unsigned char buf[1024];
  int buflen;
  WINDOW *in_win, *out_win, *txt_win;
  MENU *menu;
  ITEM *items[3];
  PANEL *in_pan, *out_pan, *txt_pan;
  int req_lines, req_cols, line0, col0;
  int answer = 0;               /* cancel */
  int c, cmd;

  va_start(args, fmt);
  buflen = vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  /* calculate size */
  if (buflen > COLS - 10) {
    req_lines = buflen / (COLS - 10) + 1;
    req_cols = COLS - 10;
  } else {
    req_lines = 1;
    req_cols = buflen;
  }
  if (req_cols < 10) req_cols = 10;
  line0 = (LINES - req_lines - 4) / 2;
  col0 = (COLS - req_cols - 2) / 2;

  items[0] = new_item("Cancel", 0);
  items[1] = new_item("Ok", 0);
  items[2] = 0;
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));

  out_win = newwin(req_lines + 4, req_cols + 2, line0, col0);
  txt_win = newwin(req_lines, req_cols, line0 + 1, col0 + 1);
  in_win = newwin(2, 8, line0 + req_lines + 1, col0 + 1 + (req_cols - 8) / 2);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wattrset(txt_win, COLOR_PAIR(1));
  wbkgdset(txt_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  wclear(txt_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  txt_pan = new_panel(txt_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  waddstr(txt_win, buf);

  post_menu(menu);
  print_help("Enter-select Y-Ok N-Cancel Q-Cancel");
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    switch (c) {
    case 'q': case 'Q': case 'й' & 255: case 'Й' & 255:
    case 'G' & 31:
      c = 'q';
      goto menu_done;
    case 'y': case 'Y': case 'н' & 255: case 'Н' & 255:
      c = 'y';
      goto menu_done;
    case 'n': case 'N': case 'т' & 255: case 'Т' & 255:
      c = 'n';
      goto menu_done;
    case '\n': case '\r': case ' ':
      c = '\n';
      goto menu_done;
    }
    cmd = -1;
    switch (c) {
    case KEY_UP:
    case KEY_LEFT:
      cmd = REQ_UP_ITEM;
      break;
    case KEY_DOWN:
    case KEY_RIGHT:
      cmd = REQ_DOWN_ITEM;
      break;
    }
    if (cmd != -1) {
      menu_driver(menu, cmd);
      update_panels();
      doupdate();
    }
  }
 menu_done:
  unpost_menu(menu);
  switch (c) {
  case '\n':
    answer = item_index(current_item(menu));
    if (answer < 0 || answer > 1) answer = 0;
    break;
  case 'y':
    answer = 1;
    break;
  }

  del_panel(in_pan);
  del_panel(out_pan);
  del_panel(txt_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(txt_win);
  delwin(in_win);
  free_item(items[0]);
  free_item(items[1]);
  update_panels();
  doupdate();
  return answer;
}

static int
yesno(int init_val, unsigned char const *fmt, ...)
{
  va_list args;
  unsigned char buf[1024];
  int buflen;
  WINDOW *in_win, *out_win, *txt_win;
  MENU *menu;
  ITEM *items[3];
  PANEL *in_pan, *out_pan, *txt_pan;
  int req_lines, req_cols, line0, col0;
  int answer = -1;               /* cancel */
  int c, cmd;

  va_start(args, fmt);
  buflen = vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  /* calculate size */
  if (buflen > COLS - 10) {
    req_lines = buflen / (COLS - 10) + 1;
    req_cols = COLS - 10;
  } else {
    req_lines = 1;
    req_cols = buflen;
  }
  if (req_cols < 10) req_cols = 10;
  line0 = (LINES - req_lines - 4) / 2;
  col0 = (COLS - req_cols - 2) / 2;

  items[0] = new_item("No", 0);
  items[1] = new_item("Yes", 0);
  items[2] = 0;
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));

  if (init_val < 0) init_val = 0;
  if (init_val > 1) init_val = 1;
  set_current_item(menu, items[init_val]);

  out_win = newwin(req_lines + 4, req_cols + 2, line0, col0);
  txt_win = newwin(req_lines, req_cols, line0 + 1, col0 + 1);
  in_win = newwin(2, 8, line0 + req_lines + 1, col0 + 1 + (req_cols - 8) / 2);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wattrset(txt_win, COLOR_PAIR(1));
  wbkgdset(txt_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  wclear(txt_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  txt_pan = new_panel(txt_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  waddstr(txt_win, buf);

  post_menu(menu);
  print_help("Enter-select Y-Yes N-No Q-Quit");
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    switch (c) {
    case 'q': case 'Q': case 'й' & 255: case 'Й' & 255:
    case 'G' & 31:
      c = 'q';
      goto menu_done;
    case 'y': case 'Y': case 'н' & 255: case 'Н' & 255:
      c = 'y';
      goto menu_done;
    case 'n': case 'N': case 'т' & 255: case 'Т' & 255:
      c = 'n';
      goto menu_done;
    case '\n': case '\r': case ' ':
      c = '\n';
      goto menu_done;
    }
    cmd = -1;
    switch (c) {
    case KEY_UP:
    case KEY_LEFT:
      cmd = REQ_UP_ITEM;
      break;
    case KEY_DOWN:
    case KEY_RIGHT:
      cmd = REQ_DOWN_ITEM;
      break;
    }
    if (cmd != -1) {
      menu_driver(menu, cmd);
      update_panels();
      doupdate();
    }
  }
 menu_done:
  unpost_menu(menu);
  switch (c) {
  case '\n':
    answer = item_index(current_item(menu));
    if (answer < 0 || answer > 1) answer = 0;
    break;
  case 'y':
    answer = 1;
    break;
  case 'n':
    answer = 0;
    break;
  }

  del_panel(in_pan);
  del_panel(out_pan);
  del_panel(txt_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(txt_win);
  delwin(in_win);
  free_item(items[0]);
  free_item(items[1]);
  update_panels();
  doupdate();
  return answer;
}

static int
display_reg_status_menu(int line, int init_val)
{
  int i;
  ITEM *items[USERLIST_REG_LAST + 1];
  int req_lines, req_cols, line0, col0;
  MENU *menu;
  WINDOW *out_win, *in_win;
  PANEL *out_pan, *in_pan;
  int selected_value = -1;
  int c, cmd;

  XMEMZERO(items, USERLIST_REG_LAST + 1);
  for (i = 0; i < USERLIST_REG_LAST; i++) {
    items[i] = new_item(userlist_unparse_reg_status(i), 0);
  }
  menu = new_menu(items);
  scale_menu(menu, &req_lines, &req_cols);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  line0 = line - req_lines/2 - 1;
  if (line0 + req_lines + 2 >= LINES)
    line0 = LINES - 1 - req_lines - 2;
  if (line0 < 1) line0 = 1;
  col0 = COLS - 1 - req_cols - 2;
  if (col0 < 0) col0 = 0;
  out_win = newwin(req_lines + 2, req_cols + 2, line0, col0);
  in_win = newwin(req_lines, req_cols, line0 + 1, col0 + 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);

  if (init_val < 0) init_val = 0;
  if (init_val >= USERLIST_REG_LAST) init_val = USERLIST_REG_LAST - 1;
  set_current_item(menu, items[init_val]);

  /*
    show_panel(out_pan);
    show_panel(in_pan);
  */
  post_menu(menu);
  print_help("Enter-select Q-quit");
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    switch (c) {
    case 'q': case 'Q': case 'й' & 255: case 'Й' & 255:
    case 'G' & 31:
      c = 'q';
      goto menu_done;
    case '\n': case '\r': case ' ':
      c = '\n';
      goto menu_done;
    }
    cmd = -1;
    switch (c) {
    case KEY_UP:
    case KEY_LEFT:
      cmd = REQ_UP_ITEM;
      break;
    case KEY_DOWN:
    case KEY_RIGHT:
      cmd = REQ_DOWN_ITEM;
      break;
    }
    if (cmd != -1) {
      menu_driver(menu, cmd);
      update_panels();
      doupdate();
    }
  }
 menu_done:
  unpost_menu(menu);
  /*
    hide_panel(out_pan);
    hide_panel(in_pan);
    update_panels();
    doupdate();
  */
  if (c == '\n') {
    selected_value = item_index(current_item(menu));
  }

  del_panel(in_pan);
  del_panel(out_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(in_win);
  update_panels();
  doupdate();
  for (i = 0; i < USERLIST_REG_LAST; i++) {
    free_item(items[i]);
  }
  return selected_value;
}

static int
display_role_menu(int line, int init_val)
{
  int i;
  ITEM *items[CONTEST_LAST_MEMBER + 1];
  int req_lines, req_cols, line0, col0;
  MENU *menu;
  WINDOW *out_win, *in_win;
  PANEL *out_pan, *in_pan;
  int selected_value = -1;
  int c, cmd;

  XMEMZERO(items, CONTEST_LAST_MEMBER + 1);
  for (i = 0; i < CONTEST_LAST_MEMBER; i++) {
    items[i] = new_item(member_string[i], 0);
  }
  menu = new_menu(items);
  scale_menu(menu, &req_lines, &req_cols);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  line0 = line - req_lines/2 - 1;
  if (line0 + req_lines + 2 >= LINES)
    line0 = LINES - 1 - req_lines - 2;
  if (line0 < 1) line0 = 1;
  col0 = COLS - 1 - req_cols - 2;
  if (col0 < 0) col0 = 0;
  out_win = newwin(req_lines + 2, req_cols + 2, line0, col0);
  in_win = newwin(req_lines, req_cols, line0 + 1, col0 + 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);

  if (init_val < 0) init_val = 0;
  if (init_val >= USERLIST_REG_LAST) init_val = CONTEST_LAST_MEMBER - 1;
  set_current_item(menu, items[init_val]);

  /*
    show_panel(out_pan);
    show_panel(in_pan);
  */
  post_menu(menu);
  print_help("Enter-select Q-quit");
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    switch (c) {
    case 'q': case 'Q': case 'й' & 255: case 'Й' & 255:
    case 'G' & 31:
      c = 'q';
      goto menu_done;
    case '\n': case '\r': case ' ':
      c = '\n';
      goto menu_done;
    }
    cmd = -1;
    switch (c) {
    case KEY_UP:
    case KEY_LEFT:
      cmd = REQ_UP_ITEM;
      break;
    case KEY_DOWN:
    case KEY_RIGHT:
      cmd = REQ_DOWN_ITEM;
      break;
    }
    if (cmd != -1) {
      menu_driver(menu, cmd);
      update_panels();
      doupdate();
    }
  }
 menu_done:
  unpost_menu(menu);
  /*
    hide_panel(out_pan);
    hide_panel(in_pan);
    update_panels();
    doupdate();
  */
  if (c == '\n') {
    selected_value = item_index(current_item(menu));
  }

  del_panel(in_pan);
  del_panel(out_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(in_win);
  update_panels();
  doupdate();
  for (i = 0; i < CONTEST_LAST_MEMBER; i++) {
    free_item(items[i]);
  }
  return selected_value;
}

static int
display_member_status_menu(int line, int init_val)
{
  int i;
  ITEM *items[USERLIST_ST_LAST + 1];
  int req_lines, req_cols, line0, col0;
  MENU *menu;
  WINDOW *out_win, *in_win;
  PANEL *out_pan, *in_pan;
  int selected_value = -1;
  int c, cmd;

  XMEMZERO(items, USERLIST_ST_LAST + 1);
  for (i = 0; i < USERLIST_ST_LAST; i++) {
    items[i] = new_item(member_status_string[i], 0);
  }
  menu = new_menu(items);
  scale_menu(menu, &req_lines, &req_cols);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  line0 = line - req_lines/2 - 1;
  if (line0 + req_lines + 2 >= LINES)
    line0 = LINES - 1 - req_lines - 2;
  if (line0 < 1) line0 = 1;
  col0 = COLS / 2;
  if (col0 + req_cols + 2 >= COLS)
    col0 =COLS - 1 - req_cols - 2;
  if (col0 < 0) col0 = 0;
  out_win = newwin(req_lines + 2, req_cols + 2, line0, col0);
  in_win = newwin(req_lines, req_cols, line0 + 1, col0 + 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);

  if (init_val < 0) init_val = 0;
  if (init_val >= USERLIST_ST_LAST) init_val = USERLIST_ST_LAST - 1;
  set_current_item(menu, items[init_val]);
  /*
    show_panel(out_pan);
    show_panel(in_pan);
  */
  post_menu(menu);
  print_help("Enter-select Q-quit");
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    switch (c) {
    case 'q': case 'Q': case 'й' & 255: case 'Й' & 255:
    case 'G' & 031:
      c = 'q';
      goto menu_done;
    case '\n': case '\r': case ' ':
      c = '\n';
      goto menu_done;
    }
    cmd = -1;
    switch (c) {
    case KEY_UP:
    case KEY_LEFT:
      cmd = REQ_UP_ITEM;
      break;
    case KEY_DOWN:
    case KEY_RIGHT:
      cmd = REQ_DOWN_ITEM;
      break;
    }
    if (cmd != -1) {
      menu_driver(menu, cmd);
      update_panels();
      doupdate();
    }
  }
 menu_done:
  unpost_menu(menu);
  /*
    hide_panel(out_pan);
    hide_panel(in_pan);
    update_panels();
    doupdate();
  */
  if (c == '\n') {
    i = item_index(current_item(menu));
    if (i >= 0 && i < USERLIST_ST_LAST) selected_value = i;
  }

  del_panel(in_pan);
  del_panel(out_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(in_win);
  update_panels();
  doupdate();
  for (i = 0; i < USERLIST_ST_LAST; i++) {
    free_item(items[i]);
  }
  return selected_value;
}

static int
edit_string(int line, int scr_wid,
            unsigned char const *head,
            unsigned char *buf, int length)
{
  WINDOW *out_win, *txt_win, *head_win;
  PANEL *out_pan, *txt_pan, *head_pan;
  int retval = -1;
  int req_lines, req_cols, line0, col0;
  int pos0, curpos, w, curlen;
  int c;
  char *mybuf;

  ASSERT(length > 0);
  mybuf = alloca(length + 10);
  memset(mybuf, 0, length + 10);
  strcpy(mybuf, buf);

  if (!head) head = "";
  if (scr_wid > COLS) scr_wid = COLS;
  req_lines = 4;
  req_cols = scr_wid;
  w = req_cols - 3;
  line0 = line - req_lines / 2;
  if (line0 + req_lines >= LINES)
    line0 = LINES - 1 - req_lines;
  if (line0 < 1) line0 = 1;
  col0 = (COLS - req_cols) / 2;
  if (col0 + req_cols >= COLS)
    col0 =COLS - 1 - req_cols;
  if (col0 < 0) col0 = 0;

  out_win = newwin(req_lines, req_cols, line0, col0);
  head_win = newwin(1, req_cols - 2, line0 + 1, col0 + 1);
  txt_win = newwin(1, req_cols - 2, line0 + 2, col0 + 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(head_win, COLOR_PAIR(1));
  wbkgdset(head_win, COLOR_PAIR(1));
  wattrset(txt_win, COLOR_PAIR(1));
  wbkgdset(txt_win, COLOR_PAIR(1));
  wclear(txt_win);
  wclear(out_win);
  wclear(head_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  head_pan = new_panel(head_win);
  txt_pan = new_panel(txt_win);
  waddstr(head_win, head);
  print_help("Enter-Ok ^G-Cancel");
  update_panels();
  doupdate();
  curlen = strlen(mybuf);
  curpos = curlen;
  pos0 = 0;

  while(1) {
    // recalculate pos0
    if (curpos < 0) curpos = 0;
    if (curpos > curlen) curpos = curlen;
    if (curpos - pos0 > w && curpos == curlen) {
      pos0 = curpos - w;
    } else if (curpos - pos0 >= w && curpos < curlen) {
      pos0 = curpos - w + 1;
    } else if (curpos < pos0) {
      pos0 = curpos;
    }
    if (pos0 < 0) pos0 = 0;
    mvwaddnstr(txt_win, 0, 0, mybuf + pos0, w);
    wclrtoeol(txt_win);
    wmove(txt_win, 0, curpos - pos0);
    wnoutrefresh(txt_win);
    doupdate();
    c = getch();
    if (c == ('G' & 31)) {
      break;
    }
    if (c == '\r' || c == '\n') {
      ASSERT(strlen(mybuf) <= length);
      strcpy(buf, mybuf);
      retval = strlen(buf);
      break;
    }
    if (c >= ' ' && c <= 255 && c != 127) {
      if (curlen == length) continue;
      memmove(mybuf + curpos + 1, mybuf + curpos, curlen - curpos + 1);
      mybuf[curpos] = c;
      curpos++;
      curlen++;
      continue;
    }
    switch (c) {
    case KEY_LEFT:
      if (!curpos) break;
      curpos--;
      break;
    case KEY_RIGHT:
      if (curpos > curlen) break;
      curpos++;
      break;
    case KEY_BACKSPACE: case 8:
      if (!curpos) break;
      curpos--;
    case KEY_DC: case 4: case 127:
      if (curpos >= curlen) break;
      memmove(mybuf + curpos, mybuf + curpos + 1, curlen - curpos);
      curlen--;
      break;
    case KEY_END: case 5:
      curpos = curlen;
      break;
    case KEY_HOME: case 1:
      curpos = 0;
      break;
    case 'K' & 31:
      curlen = curpos;
      mybuf[curlen] = 0;
      break;
    case 'U' & 31:
      if (curpos <= 0) break;
      memmove(mybuf, mybuf + curpos, curlen - curpos + 1);
      curlen -= curpos;
      curpos = 0;
      break;
    case 'Y' & 31:
      curlen = 0;
      curpos = 0;
      mybuf[curlen] = 0;
      break;
    }
  }

  del_panel(out_pan);
  del_panel(txt_pan);
  del_panel(head_pan);
  delwin(out_win);
  delwin(txt_win);
  delwin(head_win);
  update_panels();
  doupdate();
  return retval;
}

#define FIRST_COOKIE(u) ((struct userlist_cookie*) (u)->cookies->first_down)
#define NEXT_COOKIE(c)  ((struct userlist_cookie*) (c)->b.right)
#define FIRST_CONTEST(u) ((struct userlist_contest*)(u)->contests->first_down)
#define NEXT_CONTEST(c)  ((struct userlist_contest*)(c)->b.right)

static int
userlist_user_count_cookies(struct userlist_user *u)
{
  struct userlist_cookie *cookie;
  int tot = 0;

  if (!u) return 0;
  if (!u->cookies) return 0;
  for (cookie = FIRST_COOKIE(u); cookie; cookie = NEXT_COOKIE(cookie), tot++);
  return tot;
}
static int
userlist_user_count_contests(struct userlist_user *u)
{
  struct userlist_contest *c;
  int tot = 0;

  if (!u || !u->contests) return 0;
  for (c = FIRST_CONTEST(u); c; c = NEXT_CONTEST(c), tot++);
  return tot;
}

struct user_field_desc
{
  unsigned char const *name;
  char has_value;
  char is_editable;
};
static const struct user_field_desc user_descs[] =
{
  [USERLIST_NN_ID]                { "Id", 1, 0 },
  [USERLIST_NN_LOGIN]             { "Login", 1, 1 },
  [USERLIST_NN_EMAIL]             { "E-mail", 1, 1 },
  [USERLIST_NN_NAME]              { "Name", 1, 1 },
  [USERLIST_NN_IS_INVISIBLE]      { "Invisible?", 1, 1 },
  [USERLIST_NN_IS_BANNED]         { "Banned?", 1, 1 },
  [USERLIST_NN_SHOW_LOGIN]        { "Show login?", 1, 1 },
  [USERLIST_NN_SHOW_EMAIL]        { "Show email?", 1, 1 },
  [USERLIST_NN_USE_COOKIES]       { "Use cookies?", 1, 1 },
  [USERLIST_NN_READ_ONLY]         { "Read-only?", 1, 1 },
  [USERLIST_NN_TIMESTAMPS]        { "*Timestamps*", 0, 0 },
  [USERLIST_NN_REG_TIME]          { "Reg time", 1, 1 },
  [USERLIST_NN_LOGIN_TIME]        { "Login time", 1, 1 },
  [USERLIST_NN_ACCESS_TIME]       { "Access time", 1, 1 },
  [USERLIST_NN_CHANGE_TIME]       { "Change time", 1, 1 },
  [USERLIST_NN_PWD_CHANGE_TIME]   { "Pwd time", 1, 1 },
  [USERLIST_NN_MINOR_CHANGE_TIME] { "Minor time", 1, 1 },
  [USERLIST_NN_PASSWORDS]         { "*Passwords*", 0, 0 },
  [USERLIST_NN_REG_PASSWORD]      { "Reg password", 1, 1 },
  [USERLIST_NN_TEAM_PASSWORD]     { "Team password", 1, 1 },
  [USERLIST_NN_GENERAL_INFO]      { "*General info*", 0, 0 },
  [USERLIST_NN_INST]              { "Institution", 1, 1 },
  [USERLIST_NN_INSTSHORT]         { "Inst. (short)", 1, 1 },
  [USERLIST_NN_FAC]               { "Faculty", 1, 1 },
  [USERLIST_NN_FACSHORT]          { "Fac. (short)", 1, 1 },
  [USERLIST_NN_HOMEPAGE]          { "Homepage", 1, 1 },
  [USERLIST_NN_CITY]              { "City", 1, 1 },
  [USERLIST_NN_COUNTRY]           { "Country", 1, 1 },
};
static const struct user_field_desc member_descs[] =
{
  [USERLIST_NM_SERIAL]     { "Serial", 1, 1 },
  [USERLIST_NM_FIRSTNAME]  { "Firstname", 1, 1 },
  [USERLIST_NM_MIDDLENAME] { "Middlename", 1, 1 },
  [USERLIST_NM_SURNAME]    { "Surname", 1, 1 },
  [USERLIST_NM_STATUS]     { "Status", 1, 1 },
  [USERLIST_NM_GRADE]      { "Grade", 1, 1 },
  [USERLIST_NM_GROUP]      { "Group", 1, 1 },
  [USERLIST_NM_OCCUPATION] { "Occupation", 1, 1 },
  [USERLIST_NM_EMAIL]      { "E-mail", 1, 1 },
  [USERLIST_NM_HOMEPAGE]   { "Homepage", 1, 1 },
  [USERLIST_NM_INST]       { "Institution", 1, 1 },
  [USERLIST_NM_INSTSHORT]  { "Inst. (short)", 1, 1 },
  [USERLIST_NM_FAC]        { "Faculty", 1, 1 },
  [USERLIST_NM_FACSHORT]   { "Fac. (short)", 1, 1 },
};

static unsigned char *
unparse_ip(unsigned long ip)
{
  static char buf[64];

  snprintf(buf, sizeof(buf), "%lu.%lu.%lu.%lu",
           ip >> 24, (ip >> 16) & 0xff,
           (ip >> 8) & 0xff, ip & 0xff);
  return buf;
}

static int
get_cookie_str(unsigned char *buf, size_t len,
               const struct userlist_cookie *cookie)
{
  return snprintf(buf, len, "%016llx %16s %s %4d %4d",
                  cookie->cookie, unparse_ip(cookie->ip),
                  userlist_unparse_date(cookie->expire, 1),
                  cookie->locale_id,
                  cookie->contest_id);
}

static int
get_contest_str(unsigned char *buf, size_t len,
                const struct userlist_contest *reg)
{
  const struct contest_desc *d;
  const unsigned char *s = 0;
  if (reg->id >= 1 && reg->id < contests->id_map_size
      && (d = contests->id_map[reg->id])) {
    s = d->name;
  }
  if (!s) s = "???";
  return snprintf(buf, len,
                  "%6d  %c%c %-10.10s  %s",
                  reg->id, 
                  (reg->flags & USERLIST_UC_BANNED)?'B':' ',
                  (reg->flags & USERLIST_UC_INVISIBLE)?'I':' ',
                  userlist_unparse_reg_status(reg->status),
                  s);
}

struct field_ref
{
  int role;                     /* -1 - main */
  int pers;                     /*  */
  int field;
};

static void
user_menu_string(struct userlist_user *u, int f, unsigned char *out)
{
  unsigned char buf[128];

  if (!user_descs[f].has_value) {
    snprintf(out, 78, "%s", user_descs[f].name);
  } else {
    userlist_get_user_field_str(buf, sizeof(buf), u, f, 1);
    snprintf(out, 78, "%-16.16s:%-60.60s", user_descs[f].name, buf);
  }
}
static void
member_menu_string(struct userlist_member *m, int f, unsigned char *out)
{
  unsigned char buf[128];

  if (!member_descs[f].has_value) {
    snprintf(out, 78, "%s", member_descs[f].name);
  } else {
    userlist_get_member_field_str(buf, sizeof(buf), m, f, 1);
    snprintf(out, 78, "%-16.16s:%-60.60s", member_descs[f].name, buf);
  }
}

static int
display_user(unsigned char const *upper, int user_id, int start_item,
             int *p_needs_reload)
{
  int r, tot_items = 0;
  unsigned char *xml_text = 0;
  struct userlist_user *u = 0;
  int retcode = -1, i, j, role, pers;
  unsigned char **descs = 0;
  struct field_ref *info;
  void **refs;
  struct userlist_member *m = 0;
  struct userlist_contest *reg;
  struct userlist_cookie *cookie;
  ITEM **items;
  MENU *menu;
  PANEL *in_pan, *out_pan;
  WINDOW *in_win, *out_win;
  unsigned char current_level[512];
  int c, cmd;
  int cur_i, cur_line;
  unsigned char edit_buf[512];
  unsigned char edit_header[512];
  int new_status;
  char const *help_str = "";

  r = userlist_clnt_get_info(server_conn, user_id, &xml_text);
  if (r < 0) {
    vis_err("Cannot get user information: %s", userlist_strerror(-r));
    return -1;
  }
  if (!(u = userlist_parse_user_str(xml_text))) {
    vis_err("XML parse error");
    return -1;
  }

  snprintf(current_level, COLS + 1, "%s->%s %d", upper, "User", u->id);

  // count how much menu items we need
  tot_items = USERLIST_NN_LAST + 1;
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (!u->members[role] || !u->members[role]->total) continue;
    tot_items += 1 + (USERLIST_NM_LAST + 2) * u->members[role]->total;
  }
  if ((r = userlist_user_count_contests(u)) > 0) {
    tot_items += r + 1;
  }
  if ((r = userlist_user_count_cookies(u)) > 0) {
    tot_items += r + 1;
  }

  XALLOCAZ(descs, tot_items);
  XALLOCAZ(refs, tot_items);
  XALLOCAZ(info, tot_items);
  for (i = 0; i < tot_items; i++) {
    XALLOCAZ(descs[i], 80);
  }

  j = 0;
  for (i = 0; i <= USERLIST_NN_LAST; i++) {
    info[j].role = -1;
    info[j].pers = 0;
    info[j].field = i;
    user_menu_string(u, i, descs[j++]);
  }
  for (role = 0; role < CONTEST_LAST_MEMBER; role++) {
    if (!u->members[role] || !u->members[role]->total) continue;
    info[j].role = role;
    info[j].pers = -1;
    info[j].field = 0;
    snprintf(descs[j++], 78, "*%s*", member_string_pl[role]);

    for (pers = 0; pers < u->members[role]->total; pers++) {
      if (!(m = u->members[role]->members[pers])) continue;

      info[j].role = role;
      info[j].pers = pers;
      info[j].field = -1;
      refs[j] = m;
      snprintf(descs[j++], 78, "*%s %d*", member_string[role], pers + 1);

      for (i = 0; i <= USERLIST_NM_LAST; i++) {
        info[j].role = role;
        info[j].pers = pers;
        info[j].field = i;
        refs[j] = m;
        member_menu_string(m, i, descs[j++]);
      }
    }
  }
  if ((r = userlist_user_count_contests(u)) > 0) {
    info[j].role = -1;
    info[j].pers = 1;
    info[j].field = -1;
    snprintf(descs[j++], 78, "*%s*", "Registrations");

    for (reg = FIRST_CONTEST(u), i = 0; reg; reg = NEXT_CONTEST(reg), i++) {
      info[j].role = -1;
      info[j].pers = 1;
      info[j].field = i;
      refs[j] = reg;
      get_contest_str(descs[j], 78, reg);
      j++;
    }
  }
  if ((r = userlist_user_count_cookies(u)) > 0) {
    info[j].role = -1;
    info[j].pers = 2;
    info[j].field = -1;
    snprintf(descs[j++], 78, "*%s*", "Cookies");

    for (cookie=FIRST_COOKIE(u),i=0;cookie;cookie=NEXT_COOKIE(cookie),i++) {
      info[j].role = -1;
      info[j].pers = 2;
      info[j].field = i;
      refs[j] = cookie;
      get_cookie_str(descs[j], 78, cookie);
      j++;
    }
  }
  ASSERT(j == tot_items);

  XALLOCAZ(items, tot_items + 1);
  for (i = 0; i < tot_items; i++) {
    items[i] = new_item(descs[i], 0);
  }

  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  out_win = newwin(LINES - 2, COLS, 1, 0);
  in_win = newwin(LINES - 4, COLS - 2, 2, 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  mvwprintw(stdscr, 0, 0, "%s", current_level);
  wclrtoeol(stdscr);
  set_menu_format(menu, LINES - 4, 0);
  if (start_item < 0) start_item = 0;
  if (start_item >= tot_items) start_item = tot_items - 1;
  set_current_item(menu, items[start_item]);

  while (1) {
    show_panel(out_pan);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      help_str = "";
      i = item_index(current_item(menu));
      if (info[i].role == -1 && info[i].pers == 0) {
        switch (info[i].field) {
        case USERLIST_NN_ID:
        case USERLIST_NN_TIMESTAMPS:
        case USERLIST_NN_PASSWORDS:
        case USERLIST_NN_GENERAL_INFO:
          help_str = "C-contest A-new member Q-quit";
          break;
        case USERLIST_NN_LOGIN:
        case USERLIST_NN_EMAIL:
        case USERLIST_NN_REG_PASSWORD:
          help_str = "Enter-edit C-contest A-new member Q-quit";
          break;
        case USERLIST_NN_NAME:
        case USERLIST_NN_TEAM_PASSWORD:
        case USERLIST_NN_INST:
        case USERLIST_NN_INSTSHORT:
        case USERLIST_NN_FAC:
        case USERLIST_NN_FACSHORT:
        case USERLIST_NN_HOMEPAGE:
        case USERLIST_NN_CITY:
        case USERLIST_NN_COUNTRY:
          help_str = "Enter-edit D-clear C-contest A-new member Q-quit";
          break;
        case USERLIST_NN_IS_INVISIBLE:
        case USERLIST_NN_IS_BANNED:
        case USERLIST_NN_SHOW_LOGIN:
        case USERLIST_NN_SHOW_EMAIL:
        case USERLIST_NN_USE_COOKIES:
        case USERLIST_NN_READ_ONLY:
          help_str = "Enter-toggle D-reset C-contest A-new member Q-quit";
          break;
        case USERLIST_NN_REG_TIME:
        case USERLIST_NN_LOGIN_TIME:
        case USERLIST_NN_ACCESS_TIME:
        case USERLIST_NN_CHANGE_TIME:
        case USERLIST_NN_PWD_CHANGE_TIME:
        case USERLIST_NN_MINOR_CHANGE_TIME:
          help_str = "D-clear C-contest A-new member Q-quit";
          break;
        default:
          help_str = "Q-quit";
          break;
        }
      }
      if (info[i].role == -1 && info[i].pers == 1) {
        if (info[i].field == -1) {
          help_str = "C-contest A-new member Q-quit";
        } else {
          help_str = "R-register B-(un)ban I-(in)visible C-contest A-new member Q-quit";
        }
      }
      if (info[i].role == -1 && info[i].pers == 2) {
        if (info[i].field == -1) {
          help_str = "D-delete all C-contest A-new member Q-quit";
        } else {
          help_str = "D-delete C-contest A-new member Q-quit";
        }
      }
      if (info[i].role >= 0 && info[i].pers == -1) {
        help_str = "C-contest A-new member Q-quit";
      }
      if (info[i].role >= 0 && info[i].pers >= 0 && info[i].field == -1) {
        help_str = "D-delete C-contest A-new member Q-quit";
      }
      if (info[i].role >= 0 && info[i].pers >= 0 && info[i].field == 0) {
        help_str = "C-contest A-new member Q-quit";
      }
      if (info[i].role >= 0 && info[i].pers >= 0 && info[i].field > 0) {
        help_str = "Enter-edit D-clear C-contest A-new member Q-quit";
      }
      print_help(help_str);
      update_panels();
      doupdate();

      c = getch();
      // in the following may be duplicates
      if (c == KEY_BACKSPACE || c == KEY_DC || c == 127 || c == 8) {
        c = 'd';
        break;
      }
      switch (c) {
      case '\n': case '\r': case ' ':
        c = '\n';
        goto menu_done;
      case 'd': case 'D': case 'В' & 255: case 'в' & 255:
        c = 'd';
        goto menu_done;
      case 'q': case 'Q': case 'Й' & 255: case 'й' & 255:
      case 'G' & 31:
        c = 'q';
        goto menu_done;
      case 'r': case 'R': case 'к' & 255: case 'К' & 255:
        c = 'r';
        goto menu_done;
      case 'b': case 'B': case 'и' & 255: case 'И' & 255:
        c = 'b';
        goto menu_done;
      case 'i': case 'I': case 'ш' & 255: case 'Ш' & 255:
        c = 'i';
        goto menu_done;
      case 'a': case 'A': case 'ф' & 255: case 'Ф' & 255:
        c = 'a';
        goto menu_done;
      case 'c': case 'C': case 'с' & 255: case 'С' & 255:
        c = 'c';
        goto menu_done;
      }
      cmd = -1;
      switch (c) {
      case KEY_UP:
      case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN:
      case KEY_RIGHT:
        cmd = REQ_DOWN_ITEM;
        break;
      case KEY_HOME:
        cmd = REQ_FIRST_ITEM;
        break;
      case KEY_END:
        cmd = REQ_LAST_ITEM;
        break;
      case KEY_NPAGE:
        i = item_index(current_item(menu));
        if (i + LINES - 4 >= tot_items) cmd = REQ_LAST_ITEM;
        else cmd = REQ_SCR_DPAGE;
        break;
      case KEY_PPAGE:
        i = item_index(current_item(menu));
        if (i - (LINES - 4) < 0) cmd = REQ_FIRST_ITEM;
        else cmd = REQ_SCR_UPAGE;
        break;
      }
      if (cmd != -1) {
        menu_driver(menu, cmd);
        update_panels();
        doupdate();
      }
    }
  menu_done:
    if (c == 'r' || c == 'b' || c == 'i') {
      cur_i = item_index(current_item(menu));
      cur_line = i - top_row(menu) + 2;
      if (info[cur_i].role != -1) goto menu_continue;
      if (info[cur_i].pers != 1) goto menu_continue;
      if (info[cur_i].field < 0) goto menu_continue;
      reg = (struct userlist_contest*) refs[cur_i];
      switch (c) {
      case 'r':
        cur_line = i - top_row(menu) + 2;
        new_status = display_reg_status_menu(cur_line, reg->status);
        if (new_status < 0 || new_status >= USERLIST_REG_LAST)
          goto menu_continue;
        if (new_status == reg->status) goto menu_continue;
        r = userlist_clnt_change_registration(server_conn, u->id,
                                              reg->id, new_status, 0, 0);
        if (r >= 0) reg->status = new_status;
        break;
      case 'b':
        if (okcancel("Toggle BANNED status?") != 1) goto menu_continue;
        r = userlist_clnt_change_registration(server_conn, u->id,
                                              reg->id, -1, 3,
                                              USERLIST_UC_BANNED);
        if (r >= 0) reg->flags ^= USERLIST_UC_BANNED;
        break;
      case 'i':
        if (okcancel("Toggle INVISIBLE status?") != 1) goto menu_continue;
        r = userlist_clnt_change_registration(server_conn, u->id,
                                              reg->id, -1, 3,
                                              USERLIST_UC_INVISIBLE);
        if (r >= 0) reg->flags ^= USERLIST_UC_INVISIBLE;
        break;
      }
      if (r < 0) {
        vis_err("Operation failed: %s", userlist_strerror(-r));
        goto menu_continue;
      }
      get_contest_str(descs[cur_i], 78, reg);
    }
    if (c == 'd') {
      cur_i = item_index(current_item(menu));
      if (cur_i < 0 || cur_i >= tot_items) continue;
      cur_line = i - top_row(menu) + 2;
      r = 1;

      if (info[cur_i].role < -1 || info[cur_i].role > CONTEST_LAST_MEMBER)
        goto menu_continue;
      if (info[cur_i].role == -1) {
        if (info[cur_i].pers < 0) goto menu_continue;
        if (info[cur_i].pers == 0) {
          if (info[cur_i].field < 0 || info[cur_i].field > USERLIST_NN_LAST)
            goto menu_continue;
          if (info[cur_i].field == USERLIST_NN_ID) goto menu_continue;
          if (info[cur_i].field == USERLIST_NN_LOGIN) goto menu_continue;
          if (info[cur_i].field == USERLIST_NN_EMAIL) goto menu_continue;
          r = okcancel("Clear field %s?",
                       user_descs[info[cur_i].field].name);
        } else if (info[cur_i].pers == 1) {
          // registration
          if (info[cur_i].field < 0) goto menu_continue;
          reg = (struct userlist_contest*) refs[cur_i];
          r = okcancel("Delete registration for contest %d?", reg->id);
          if (r != 1) goto menu_continue;
          r = userlist_clnt_change_registration(server_conn, u->id,
                                                reg->id, -2, 0, 0);
          if (r < 0) {
            vis_err("Delete failed: %s", userlist_strerror(-r));
            goto menu_continue;
          }
          retcode = 0;
          c = 'q';
          goto menu_continue;
        } else if (info[cur_i].pers == 2) {
          // cookies
          if (info[cur_i].field == -1) {
            r = okcancel("Delete all cookies?");
          } else {
            cookie = (struct userlist_cookie*) refs[cur_i];
            r = okcancel("Delete cookie %016llx?", cookie->cookie);
          }
        }
      }
      if (info[cur_i].role >= 0) {
        if (info[cur_i].pers < 0) goto menu_continue;
        if (info[cur_i].pers >= u->members[info[cur_i].role]->total)
          goto menu_continue;
        m = u->members[info[cur_i].role]->members[info[cur_i].pers];
        if (info[cur_i].field < -1) goto menu_continue;
        if (info[cur_i].field > USERLIST_NM_LAST) goto menu_continue;
        if (info[cur_i].field == -1) {
          // delete the whole member
          r = okcancel("DELETE MEMBER %s_%d?",
                       member_string[info[cur_i].role],
                       info[cur_i].pers + 1);
        } else {
          r = okcancel("Reset field %s_%d::%s?",
                       member_string[info[cur_i].role],
                       info[cur_i].pers + 1,
                       member_descs[info[cur_i].field].name);
        }
      }
      if (r != 1) goto menu_continue;
      r = userlist_clnt_delete_field(server_conn, u->id,
                                     info[cur_i].role,
                                     info[cur_i].pers,
                                     info[cur_i].field);
      if (r < 0) {
        vis_err("Delete failed: %s", userlist_strerror(-r));
        goto menu_continue;
      }

      if (info[cur_i].role == -1 && info[cur_i].pers == 0) {
        if (info[cur_i].field == USERLIST_NN_NAME) {
          if (p_needs_reload) *p_needs_reload = 1;
        }
      }

      retcode = 0;
      c = 'q';
      goto menu_continue;
    }

    if (c == 'a') {
      r = display_role_menu(LINES / 2, 0);
      if (r < 0 || r >= CONTEST_LAST_MEMBER) goto menu_continue;

      r = userlist_clnt_add_field(server_conn, u->id, r, -1, -1);
      if (r < 0) {
        vis_err("Add failed: %s", userlist_strerror(-r));
        goto menu_continue;
      }

      retcode = 0;
      c = 'q';
      goto menu_continue;
    }

    if (c == 'c') {
      i = display_contests_menu(current_level, 1);
      if (i <= 0 || i >= contests->id_map_size || !contests->id_map[i])
        goto menu_continue;
      r = okcancel("Register for contest %d?", i);
      if (r != 1) goto menu_continue;
      r = userlist_clnt_register_contest(server_conn, u->id, i);
      if (r < 0) {
        vis_err("Registration failed: %s", userlist_strerror(-r));
        goto menu_continue;
      }
      retcode = 0;
      c = 'q';
      goto menu_continue;
    }

    if (c == '\n') {
      cur_i = item_index(current_item(menu));
      if (cur_i < 0 || cur_i >= tot_items) continue;
      cur_line = cur_i - top_row(menu) + 2;

      if (info[cur_i].role < -1) goto menu_continue;
      if (info[cur_i].role == -1) {
        if (info[cur_i].pers != 0) goto menu_continue;
        if (info[cur_i].field < 0
            || info[cur_i].field > USERLIST_NN_LAST)
          goto menu_continue;
        if (!user_descs[info[cur_i].field].is_editable
            || !user_descs[info[cur_i].field].has_value)
          goto menu_continue;

        switch (info[cur_i].field) {
        case USERLIST_NN_IS_INVISIBLE:
        case USERLIST_NN_IS_BANNED:
        case USERLIST_NN_SHOW_LOGIN:
        case USERLIST_NN_SHOW_EMAIL:
        case USERLIST_NN_USE_COOKIES:
        case USERLIST_NN_READ_ONLY:
          edit_buf[0] = 0;
          userlist_get_user_field_str(edit_buf, sizeof(edit_buf),
                                      u, info[cur_i].field, 0);
          r = userlist_parse_bool(edit_buf);
          r = yesno(r, "New value for \"%s\"",
                    user_descs[info[cur_i].field].name);
          if (r < 0 || r > 1) goto menu_continue;
          snprintf(edit_buf, sizeof(edit_buf), "%s", userlist_unparse_bool(r));
          r = userlist_set_user_field_str(u, info[cur_i].field, edit_buf);
          if (!r) goto menu_continue;
          if (r < 0) {
            vis_err("Invalid field value");
            goto menu_continue;
          }
          r = userlist_clnt_edit_field(server_conn, u->id, -1, 0,
                                       info[cur_i].field, edit_buf);
          if (r < 0) {
            vis_err("Server error: %s", userlist_strerror(-r));
            goto menu_continue;
          }
          user_menu_string(u, info[cur_i].field, descs[cur_i]);
          goto menu_continue;

        case USERLIST_NN_REG_TIME:
        case USERLIST_NN_LOGIN_TIME:
        case USERLIST_NN_ACCESS_TIME:
        case USERLIST_NN_CHANGE_TIME:
        case USERLIST_NN_PWD_CHANGE_TIME:
        case USERLIST_NN_MINOR_CHANGE_TIME:
          goto menu_continue;
        }

        userlist_get_user_field_str(edit_buf, sizeof(edit_buf),
                                    u, info[cur_i].field, 0);
        snprintf(edit_header, sizeof(edit_header),
                 "%s",
                 user_descs[info[cur_i].field].name);
        r = edit_string(cur_line, COLS, edit_header,
                        edit_buf, sizeof(edit_buf) - 1);
        if (r < 0) goto menu_continue;
        r = userlist_set_user_field_str(u, info[cur_i].field, edit_buf);
        if (!r) goto menu_continue;
        if (r < 0) {
          vis_err("Invalid field value");
          goto menu_continue;
        }
        r = userlist_clnt_edit_field(server_conn, u->id, -1, 0,
                                     info[cur_i].field, edit_buf);
        if (r < 0) {
          vis_err("Server error: %s", userlist_strerror(-r));
          goto menu_continue;
        }
        user_menu_string(u, info[cur_i].field, descs[cur_i]);
        if (info[cur_i].field == USERLIST_NN_LOGIN
            || info[cur_i].field == USERLIST_NN_NAME
            || info[cur_i].field == USERLIST_NN_EMAIL) {
          if (p_needs_reload) *p_needs_reload = 1;
        }
        goto menu_continue;
      }
      if (info[cur_i].role >= 0) {
        if (info[cur_i].role >= CONTEST_LAST_MEMBER) goto menu_continue;
        if (info[cur_i].pers < 0 ||
            info[cur_i].pers >= u->members[info[cur_i].role]->total)
          goto menu_continue;
        if (info[cur_i].field < 0
            || info[cur_i].field > USERLIST_NM_LAST)
          goto menu_continue;
        if (!member_descs[info[cur_i].field].is_editable
            || !member_descs[info[cur_i].field].has_value)
          goto menu_continue;

        m = (struct userlist_member*) refs[cur_i];
        if (info[cur_i].field == USERLIST_NM_SERIAL) goto menu_continue;
        if (info[cur_i].field == USERLIST_NM_STATUS) {
          int new_status;
          
          new_status = display_member_status_menu(cur_line, m->status);
          if (new_status < 0 || new_status >= USERLIST_ST_LAST
              || new_status == m->status)
            goto menu_continue;
          snprintf(edit_buf, sizeof(edit_buf), "%d", new_status);
          r = userlist_set_member_field_str(m, info[cur_i].field, edit_buf);
          if (!r) goto menu_continue;
          if (r < 0) {
            vis_err("Invalid field value");
            goto menu_continue;
          }
          r = userlist_clnt_edit_field(server_conn, u->id,
                                       info[cur_i].role, info[cur_i].pers,
                                       info[cur_i].field, edit_buf);
          if (r < 0) {
            vis_err("Server error: %s", userlist_strerror(-r));
            goto menu_continue;
          }
          member_menu_string(m, info[cur_i].field, descs[cur_i]);
          goto menu_continue;
        }
        if (info[cur_i].field >= 0) {
          userlist_get_member_field_str(edit_buf, sizeof(edit_buf),
                                        m, info[cur_i].field, 0);
          snprintf(edit_header, sizeof(edit_header),
                   "%s_%d::%s",
                   member_string[info[cur_i].role],
                   info[cur_i].pers + 1,
                   member_descs[info[cur_i].field].name);
          r = edit_string(cur_line, COLS, edit_header,
                          edit_buf, sizeof(edit_buf) - 1);
          if (r < 0) goto menu_continue;
          r = userlist_set_member_field_str(m, info[cur_i].field, edit_buf);
          if (!r) goto menu_continue;
          if (r < 0) {
            vis_err("Invalid field value");
            goto menu_continue;
          }
          r = userlist_clnt_edit_field(server_conn, u->id,
                                       info[cur_i].role, info[cur_i].pers,
                                       info[cur_i].field, edit_buf);
          if (r < 0) {
            vis_err("Server error: %s", userlist_strerror(-r));
            goto menu_continue;
          }
          member_menu_string(m, info[cur_i].field, descs[cur_i]);
          goto menu_continue;
        }
      }        
    }
  menu_continue:
    unpost_menu(menu);
    hide_panel(out_pan);
    hide_panel(in_pan);
    update_panels();
    doupdate();

    if (c == 'q') break;
  }

  free_menu(menu);
  del_panel(in_pan);
  del_panel(out_pan);
  delwin(out_win);
  delwin(in_win);
  for (i = 0; i < tot_items; i++) {
    free_item(items[i]);
  }
  return retcode;
}

static int
display_registered_users(unsigned char const *upper,
                         const struct contest_desc *cnts,
                         int init_val)
{
  unsigned char current_level[512];
  int r, nuser, i, j;
  unsigned char *xml_text = 0;
  struct userlist_list *users;
  struct userlist_user **uu = 0;
  struct userlist_contest **uc = 0, *cc;
  unsigned char **descs = 0;
  unsigned char buf[128];
  int buflen;
  ITEM **items;
  MENU *menu;
  WINDOW *in_win, *out_win;
  PANEL *in_pan, *out_pan;
  int c, cmd, cur_line, new_status;
  int first_row;
  int retcode = -1;

  snprintf(current_level, sizeof(current_level),
           "%s->%s %d", upper, "Registered users for",
           cnts->id);

  r = userlist_clnt_list_all_users(server_conn, cnts->id, &xml_text);
  if (r < 0) {
    vis_err("Cannot get the list of users: %s", userlist_strerror(-r));
    return 0;
  }
  users = userlist_parse_str(xml_text);
  xfree(xml_text);
  if (!users) {
    vis_err("XML parse error");
    return 0;
  }

  for (i = 1, nuser = 0; i < users->user_map_size; i++) {
    if (users->user_map[i]) nuser++;
  }
  if (!nuser) {
    vis_err("No users registered for this contest");
    return -1;
  }
  XALLOCAZ(uu,nuser);
  for (j = 0, i = 1; i < users->user_map_size; i++) {
    if (users->user_map[i]) uu[j++] = users->user_map[i];
  }
  XALLOCAZ(uc, nuser);
  for (i = 0; i < nuser; i++) {
    ASSERT(uu[i]->contests);
    for (cc = (struct userlist_contest*) uu[i]->contests->first_down;
         cc; cc = (struct userlist_contest*) cc->b.right) {
      if (cc->id == cnts->id) break;
    }
    ASSERT(cc);
    uc[i] = cc;
  }
  XALLOCAZ(descs, nuser);
  XALLOCAZ(items, nuser + 1);
  for (i = 0; i < nuser; i++) {
    // 77 - 6 - 16 - 10 - 6 = 77 - 38 = 39
    buflen = snprintf(buf, sizeof(buf),
                      "%6d  %-16.16s  %-36.36s  %c%c %-10.10s",
                      uu[i]->id, uu[i]->login, uu[i]->name,
                      (uc[i]->flags & USERLIST_UC_BANNED)?'B':' ',
                      (uc[i]->flags & USERLIST_UC_INVISIBLE)?'I':' ',
                      userlist_unparse_reg_status(uc[i]->status));
    ASSERT(buflen < 128);
    descs[i] = alloca(128);
    strcpy(descs[i], buf);
    items[i] = new_item(descs[i], 0);
  }

  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  out_win = newwin(LINES - 2, COLS, 1, 0);
  in_win = newwin(LINES - 4, COLS - 2, 2, 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  set_menu_format(menu, LINES - 4, 0);

  if (init_val >= nuser) init_val = nuser - 1;
  if (init_val < 0) init_val = 0;
  first_row = init_val - (LINES - 4) / 2;
  if (first_row + LINES - 4 > nuser) first_row = nuser - (LINES - 4);
  if (first_row < 0) first_row = 0;
  set_top_row(menu, first_row);
  set_current_item(menu, items[init_val]);

  while (1) {
    mvwprintw(stdscr, 0, 0, "%s", current_level);
    wclrtoeol(stdscr);
    print_help("A-add R-register D-delete B-(un)ban I-(in)visible Enter-edit Q-quit");
    show_panel(out_pan);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      c = getch();
      // in the following may be duplicates
      if (c == KEY_BACKSPACE || c == KEY_DC || c == 127 || c == 8) {
        c = 'd';
        break;
      }
      switch (c) {
      case 'q': case 'Q':
      case 'й' & 255: case 'Й' & 255: case 'G' & 31:
        c = 'q';
        goto menu_done;
      case 'r': case 'R': case 'к' & 255: case 'К' & 255:
        c = 'r';
        goto menu_done;
      case 'd': case 'D': case 'в' & 255: case 'В' & 255:
        c = 'd';
        goto menu_done;
      case 'i': case 'I': case 'ш' & 255: case 'Ш' & 255:
        c = 'i';
        goto menu_done;
      case 'b': case 'B': case 'и' & 255: case 'И' & 255:
        c = 'b';
        goto menu_done;
      case '\n': case '\r': case ' ':
        c = '\n';
        goto menu_done;
      case 'a': case 'A': case 'ф':case 'Ф':
        c = 'a';
        goto menu_done;
      }
      cmd = -1;
      switch (c) {
      case KEY_UP:
      case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN:
      case KEY_RIGHT:
        cmd = REQ_DOWN_ITEM;
        break;
      case KEY_HOME:
        cmd = REQ_FIRST_ITEM;
        break;
      case KEY_END:
        cmd = REQ_LAST_ITEM;
        break;
      case KEY_NPAGE:
        i = item_index(current_item(menu));
        if (i + LINES - 4 >= nuser) cmd = REQ_LAST_ITEM;
        else cmd = REQ_SCR_DPAGE;
        break;
      case KEY_PPAGE:
        i = item_index(current_item(menu));
        if (i - (LINES - 4) < 0) cmd = REQ_FIRST_ITEM;
        else cmd = REQ_SCR_UPAGE;
        break;
      }
      if (cmd != -1) {
        menu_driver(menu, cmd);
        update_panels();
        doupdate();
      }
    }
  menu_done:
    if (c == 'r') {
      i = item_index(current_item(menu));
      cur_line = i - top_row(menu) + 2;
      new_status = display_reg_status_menu(cur_line, uc[i]->status);
      if (new_status < 0 || new_status >= USERLIST_REG_LAST) continue;
      if (okcancel("Set registration status for %s to %s?",
                   uu[i]->login,
                   userlist_unparse_reg_status(new_status)) != 1) 
        continue;
      r = userlist_clnt_change_registration(server_conn, uu[i]->id,
                                            cnts->id, new_status, 0, 0);
      if (r < 0) {
        vis_err("Status change failed: %s", userlist_strerror(-r));
        continue;
      }
      uc[i]->status = new_status;
      snprintf(descs[i], 128,
               "%6d  %-16.16s  %-36.36s  %c%c %-10.10s",
               uu[i]->id, uu[i]->login, uu[i]->name,
               (uc[i]->flags & USERLIST_UC_BANNED)?'B':' ',
               (uc[i]->flags & USERLIST_UC_INVISIBLE)?'I':' ',
               userlist_unparse_reg_status(uc[i]->status));
    } else if (c == 'd') {
      i = item_index(current_item(menu));
      if (okcancel("Delete registration for %s?", uu[i]->login) != 1)
        continue;
      r = userlist_clnt_change_registration(server_conn, uu[i]->id,
                                            cnts->id, -2, 0, 0);
      if (r < 0) {
        vis_err("Delete failed: %s", userlist_strerror(-r));
        continue;
      }
      c = 'q';
      retcode = 0;
    } else if (c == 'b') {
      i = item_index(current_item(menu));
      if (okcancel("Toggle BANNED status for %s?", uu[i]->login) != 1)
        continue;
      r = userlist_clnt_change_registration(server_conn, uu[i]->id,
                                            cnts->id, -1, 3,
                                            USERLIST_UC_BANNED);
      if (r < 0) {
        vis_err("Toggle flags failed: %s", userlist_strerror(-r));
        continue;
      }
      uc[i]->flags ^= USERLIST_UC_BANNED;
      snprintf(descs[i], 128,
               "%6d  %-16.16s  %-36.36s  %c%c %-10.10s",
               uu[i]->id, uu[i]->login, uu[i]->name,
               (uc[i]->flags & USERLIST_UC_BANNED)?'B':' ',
               (uc[i]->flags & USERLIST_UC_INVISIBLE)?'I':' ',
               userlist_unparse_reg_status(uc[i]->status));
    } else if (c == 'i') {
      i = item_index(current_item(menu));
      if (okcancel("Toggle INVISIBLE status for %s?", uu[i]->login) != 1)
        continue;
      r = userlist_clnt_change_registration(server_conn, uu[i]->id,
                                            cnts->id, -1, 3,
                                            USERLIST_UC_INVISIBLE);
      if (r < 0) {
        vis_err("Toggle flags failed: %s", userlist_strerror(-r));
        continue;
      }
      uc[i]->flags ^= USERLIST_UC_INVISIBLE;
      snprintf(descs[i], 128,
               "%6d  %-16.16s  %-36.36s  %c%c %-10.10s",
               uu[i]->id, uu[i]->login, uu[i]->name,
               (uc[i]->flags & USERLIST_UC_BANNED)?'B':' ',
               (uc[i]->flags & USERLIST_UC_INVISIBLE)?'I':' ',
               userlist_unparse_reg_status(uc[i]->status));
    } else if (c == '\n') {
      i = item_index(current_item(menu));
      r = 0;
      while (r >= 0) {
        r = display_user(current_level, uu[i]->id, r, 0);
      }
      c = 'q';
      retcode = i;
    } else if (c == 'a') {
      i = display_user_menu(current_level, 0, 1);
      if (i > 0) {
        r = okcancel("Register user %d?", i);
        if (r == 1) {
          r = userlist_clnt_register_contest(server_conn, i, cnts->id);
          if (r < 0) {
            vis_err("Registration failed: %s", userlist_strerror(-r));
          } else {
            c = 'q';
            retcode = 0;
          }
        }
      }
    }

    unpost_menu(menu);
    hide_panel(out_pan);
    hide_panel(in_pan);
    update_panels();
    doupdate();

    if (c == 'q') break;
  }

  // cleanup
  wmove(stdscr, 0, 0);
  wclrtoeol(stdscr);
  wmove(stdscr, LINES - 1, 0);
  wclrtoeol(stdscr);
  del_panel(in_pan);
  del_panel(out_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(in_win);
  update_panels();
  doupdate();
  for (i = 0; i < nuser; i++) {
    free_item(items[i]);
  }
  return retcode;
}

static int
display_contests_menu(unsigned char *upper, int only_choose)
{
  int ncnts = 0, i, j;
  struct contest_desc **cntss, *cc;
  unsigned char **descs;
  unsigned char buf[128];
  int len;
  ITEM **items;
  MENU *menu;
  WINDOW *in_win, *out_win;
  PANEL *out_pan, *in_pan;
  int c, cmd;
  unsigned char current_level[512];
  int sel_num, r;
  int retval = -1;

  snprintf(current_level, sizeof(current_level),
           "%s->%s", upper, "Contest list");

  // count the total contests
  for (i = 1; i < contests->id_map_size; i++) {
    if (!contests->id_map[i]) continue;
    ncnts++;
  }
  if (!ncnts) return -1;

  cntss = alloca(ncnts * sizeof(cntss[0]));
  memset(cntss, 0, sizeof(cntss[0]) * ncnts);
  for (i = 1, j = 0; i < contests->id_map_size; i++) {
    if (!contests->id_map[i]) continue;
    cntss[j++] = contests->id_map[i];
  }
  ASSERT(j == ncnts);

  descs = alloca(ncnts * sizeof(descs[0]));
  memset(descs, 0, sizeof(descs[0]) * ncnts);
  for (i = 0; i < ncnts; i++) {
    cc = cntss[i];
    len = snprintf(buf, sizeof(buf), "%-8d  %-67.67s", cc->id, cc->name);
    descs[i] = alloca(len + 16);
    strcpy(descs[i], buf);
  }

  items = alloca((ncnts + 1) * sizeof(items[0]));
  memset(items, 0, sizeof(items[0]) * (ncnts + 1));
  for (i = 0; i < ncnts; i++) {
    items[i] = new_item(descs[i], 0);
  }
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  out_win = newwin(LINES - 2, COLS, 1, 0);
  in_win = newwin(LINES - 4, COLS - 2, 2, 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  set_menu_format(menu, LINES - 4, 0);

  while (1) {
    mvwprintw(stdscr, 0, 0, "%s", current_level);
    wclrtoeol(stdscr);
    print_help("Enter-view Q-quit");
    show_panel(out_pan);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      c = getch();
      switch (c) {
      case 'q': case 'Q':
      case 'й' & 255: case 'Й' & 255: case 'G' & 31:
        c = 'q';
        goto menu_done;
      case '\n': case '\r': case ' ':
        c = '\n';
        goto menu_done;
      }
      cmd = -1;
      switch (c) {
      case KEY_UP:
      case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN:
      case KEY_RIGHT:
        cmd = REQ_DOWN_ITEM;
        break;
      case KEY_HOME:
        cmd = REQ_FIRST_ITEM;
        break;
      case KEY_END:
        cmd = REQ_LAST_ITEM;
        break;
      case KEY_NPAGE:
        i = item_index(current_item(menu));
        if (i + LINES - 4 >= ncnts) cmd = REQ_LAST_ITEM;
        else cmd = REQ_SCR_DPAGE;
        break;
      case KEY_PPAGE:
        i = item_index(current_item(menu));
        if (i - (LINES - 4) < 0) cmd = REQ_FIRST_ITEM;
        else cmd = REQ_SCR_UPAGE;
        break;
      }
      if (cmd != -1) {
        menu_driver(menu, cmd);
        update_panels();
        doupdate();
      }
    }
  menu_done:
    unpost_menu(menu);
    hide_panel(out_pan);
    hide_panel(in_pan);
    update_panels();
    doupdate();

    if (c == 'q') break;
    if (c == '\n' && only_choose) {
      sel_num = item_index(current_item(menu));
      retval = cntss[sel_num]->id;
      break;
    }
    if (c == '\n') {
      sel_num = item_index(current_item(menu));
      r = 0;
      while (r >= 0) {
        r = display_registered_users(current_level, cntss[sel_num], r);
      }
    }
  }

  // cleanup
  wmove(stdscr, 0, 0);
  wclrtoeol(stdscr);
  del_panel(in_pan);
  del_panel(out_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(in_win);
  for (i = 0; i < ncnts; i++) {
    free_item(items[i]);
  }
  return retval;
}

static int
display_user_menu(unsigned char *upper, int start_item, int only_choose)
{
  int r;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  int nusers, i, j;
  struct userlist_user **uu = 0;
  unsigned char **descs = 0;
  unsigned char buf[128];
  int len;
  ITEM **items;
  MENU *menu;
  WINDOW *in_win, *out_win;
  PANEL *out_pan, *in_pan;
  int c, cmd;
  unsigned char current_level[512];
  int retval = -1;
  int needs_reload = 0, first_row;

  snprintf(current_level, sizeof(current_level),
           "%s->%s", upper, "User list");

  r = userlist_clnt_list_all_users(server_conn, 0, &xml_text);
  if (r < 0) {
    vis_err("Cannot get user list: %s", userlist_strerror(-r));
    return -1;
  }
  users = userlist_parse_str(xml_text);
  if (!users) {
    vis_err("XML parse error");
    xfree(xml_text);
    return -1;
  }

  // count all users
  nusers = 0;
  for (i = 1; i < users->user_map_size; i++) {
    if (!users->user_map[i]) continue;
    nusers++;
  }
  if (!nusers) {
    vis_err("No users in database");
    return -1;
  }

  uu = alloca(nusers * sizeof(uu[0]));
  memset(uu, 0, nusers * sizeof(uu[0]));
  for (i = 1, j = 0; i < users->user_map_size; i++) {
    if (!users->user_map[i]) continue;
    uu[j++] = users->user_map[i];
  }
  ASSERT(j == nusers);

  descs = alloca(nusers * sizeof(descs[0]));
  memset(descs, 0, nusers * sizeof(descs[0]));
  for (i = 0; i < nusers; i++) {
    len = snprintf(buf, sizeof(buf), "%6d  %-16.16s  %-51.51s",
                   uu[i]->id, uu[i]->login, uu[i]->name);
    descs[i] = alloca(len + 16);
    strcpy(descs[i], buf);
  }

  items = alloca((nusers + 1) * sizeof(items[0]));
  memset(items, 0, sizeof(items[0]) * (nusers + 1));
  for (i = 0; i < nusers; i++) {
    items[i] = new_item(descs[i], 0);
  }
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  out_win = newwin(LINES - 2, COLS, 1, 0);
  in_win = newwin(LINES - 4, COLS - 2, 2, 1);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  set_menu_format(menu, LINES - 4, 0);

  for (i = 0; i < nusers; i++)
    if (uu[i]->id == start_item) break;
  if (i < nusers) start_item = i;
  else start_item = 0;

  if (start_item < 0) start_item = 0;
  if (start_item >= nusers) start_item = nusers - 1;
  first_row = start_item - (LINES - 4)/2;
  if (first_row + LINES - 4 > nusers) first_row = nusers - (LINES - 4);
  if (first_row < 0) first_row = 0;
  set_top_row(menu, first_row);
  set_current_item(menu, items[start_item]);

  while (1) {
    mvwprintw(stdscr, 0, 0, "%s", current_level);
    wclrtoeol(stdscr);
    print_help("Enter-view A-add D-delete Q-quit");
    show_panel(out_pan);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      c = getch();
      if (c == KEY_BACKSPACE || c == KEY_DC || c == 127 || c == 8
          || c == 'd' || c == 'D' || c == 'В' || c == 'в') {
        c = 'd';
        goto menu_done;
      }
      switch (c) {
      case 'q': case 'Q':
      case 'й' & 255: case 'Й' & 255: case 'G' & 31:
        c = 'q';
        goto menu_done;
      case '\n': case '\r':
        c = '\n';
        goto menu_done;
      case 'a': case 'A': case 'ф' & 255: case 'Ф' & 255:
        c = 'a';
        goto menu_done;
      }
      cmd = -1;
      switch (c) {
      case KEY_UP:
      case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN:
      case KEY_RIGHT:
        cmd = REQ_DOWN_ITEM;
        break;
      case KEY_HOME:
        cmd = REQ_FIRST_ITEM;
        break;
      case KEY_END:
        cmd = REQ_LAST_ITEM;
        break;
      case KEY_NPAGE:
        i = item_index(current_item(menu));
        if (i + LINES - 4 >= nusers) cmd = REQ_LAST_ITEM;
        else cmd = REQ_SCR_DPAGE;
        break;
      case KEY_PPAGE:
        i = item_index(current_item(menu));
        if (i - (LINES - 4) < 0) cmd = REQ_FIRST_ITEM;
        else cmd = REQ_SCR_UPAGE;
        break;
      }
      if (cmd != -1) {
        menu_driver(menu, cmd);
        update_panels();
        doupdate();
      }
    }
  menu_done:
    if (c == 'd' && !only_choose) {
      i = item_index(current_item(menu));
      j = okcancel("REMOVE USER %d (%s)?", uu[i]->id, uu[i]->login);
      if (j != 1) goto menu_continue;
      j = userlist_clnt_delete_field(server_conn, uu[i]->id, -1, -1, 0);
      if (j < 0) {
        vis_err("Remove failed: %s", userlist_strerror(-j));
        goto menu_continue;
      }

      c = 'q';
      retval = 0;
    }
    if (c == 'a' && !only_choose) {
      j = okcancel("Add new user?");
      if (j != 1) goto menu_continue;
      j = userlist_clnt_add_field(server_conn, -1, -1, -1, -1);
      if (j < 0) {
        vis_err("Add failed: %s", userlist_strerror(-j));
        goto menu_continue;
      }

      c = 'q';
      retval = 0;
    }

  menu_continue:
    unpost_menu(menu);
    hide_panel(out_pan);
    hide_panel(in_pan);
    update_panels();
    doupdate();

    if (c == 'q') break;
    if (c == '\n' && only_choose) {
      i = item_index(current_item(menu));
      retval = uu[i]->id;
      break;
    }
    if (c == '\n' && !only_choose) {
      i = item_index(current_item(menu));
      j = 0;
      needs_reload = 0;
      while (j >= 0) {
        j = display_user(current_level, uu[i]->id, j, &needs_reload);
      }
      if (needs_reload) {
        retval = uu[i]->id;
        break;
      }
    }
  }

  // cleanup
  wmove(stdscr, 0, 0);
  wclrtoeol(stdscr);
  del_panel(in_pan);
  del_panel(out_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(in_win);
  for (i = 0; i < nusers; i++) {
    free_item(items[i]);
  }
  userlist_free(&users->b);
  return retval;
}

static void
display_main_menu(void)
{
  ITEM *items[5];
  MENU *menu;
  WINDOW *window, *in_win;
  PANEL *panel, *in_pan;
  int req_rows, req_cols;
  int c, cmd, start_col, r;
  unsigned char current_level[512];

  snprintf(current_level, sizeof(current_level), "%s", "Main menu");

  memset(items, 0, sizeof(items));
  items[0] = new_item("View contests", 0);
  items[1] = new_item("View users", 0);
  items[2] = new_item("Quit", 0);
  menu = new_menu(items);
  scale_menu(menu, &req_rows, &req_cols);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));

  start_col = (80 - req_cols - 2) / 2;
  window = newwin(req_rows + 2, req_cols + 2, 5, start_col);
  wattrset(window, COLOR_PAIR(1));
  wbkgdset(window, COLOR_PAIR(1));
  box(window, 0, 0);
  panel = new_panel(window);
  in_win = newwin(req_rows, req_cols, 6, start_col + 1);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);

  while (1) {
    mvwprintw(stdscr, 0, 0, "%s", current_level);
    wclrtoeol(stdscr);
    print_help("Enter-view C-contests U-users Q-quit");
    show_panel(panel);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      c = getch();
      switch (c) {
      case 'q': case 'Q':
      case 'й' & 255: case 'Й' & 255: case 'G' & 31:
        c = 'q';
        goto menu_done;
      case 'c': case 'C': case 'с' & 255: case 'С' & 255:
        c = 'c';
        goto menu_done;
      case 'u': case 'U': case 'г' & 255: case 'Г' & 255:
        c = 'u';
        goto menu_done;
      case '\n': case '\r': case ' ':
        c = '\n';
        goto menu_done;
      }
      cmd = -1;
      switch (c) {
      case KEY_UP:
      case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN:
      case KEY_RIGHT:
        cmd = REQ_DOWN_ITEM;
        break;
      case KEY_HOME:
        cmd = REQ_FIRST_ITEM;
        break;
      case KEY_END:
        cmd = REQ_LAST_ITEM;
        break;
      case KEY_NPAGE:
        cmd = REQ_SCR_UPAGE;
        break;
      case KEY_PPAGE:
        cmd = REQ_SCR_DPAGE;
        break;
      }
      if (cmd != -1) {
        menu_driver(menu, cmd);
        update_panels();
        doupdate();
      }
    }
  menu_done:
    unpost_menu(menu);
    hide_panel(panel);
    hide_panel(in_pan);
    update_panels();
    doupdate();
    
    // handle the requested action
    if (c == '\n') {
      ITEM *cur = current_item(menu);
      if (cur == items[0]) {
        c = 'c';
      } else if (cur == items[1]) {
        c = 'u';
      } else if (cur == items[2]) {
        c = 'q';
      }
    }
    if (c == 'q') break;
    if (c == 'c') {
      display_contests_menu(current_level, 0);
    } else if (c == 'u') {
      r = 0;
      while (r >= 0) {
        r = display_user_menu(current_level, r, 0);
      }
    }

    // perform other actions
  }
  
  // cleanup
  del_panel(in_pan);
  del_panel(panel);
  free_menu(menu);
  delwin(window);
  delwin(in_win);
  free_item(items[0]);
  free_item(items[1]);
  free_item(items[2]);
}

int
main(int argc, char **argv)
{
  int r;

  if (argc != 2) {
    fprintf(stderr, "%s: invalid number of arguments\n", argv[0]);
    return 1;
  }
  if (!(config = userlist_cfg_parse(argv[1]))) {
    fprintf(stderr, "%s: cannot parse configuration file\n", argv[0]);
    return 1;
  }
  if (!(contests = parse_contest_xml(config->contests_path))) {
    fprintf(stderr, "%s: cannot parse contests database",
            argv[0]);
    return 1;
  }
  if (!(server_conn = userlist_clnt_open(config->socket_path))) {
    fprintf(stderr, "%s: cannot open server connection: %s\n",
            argv[0], os_ErrorMsg());
    return 1;
  }
  if ((r = userlist_clnt_admin_process(server_conn)) < 0) {
    fprintf(stderr, "%s: cannot become admin process: %s\n",
            argv[0], userlist_strerror(-r));
    return 1;
  }

  setlocale(LC_ALL, "");

  if (!(root_window = initscr())) return 1;
  cbreak();
  noecho();
  nonl();
  meta(stdscr, TRUE);
  intrflush(stdscr, FALSE);
  keypad(stdscr, TRUE);

  if (has_colors()) {
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_BLUE);
    init_pair(2, COLOR_YELLOW, COLOR_BLUE);
    init_pair(3, COLOR_BLUE, COLOR_WHITE);
    init_pair(4, COLOR_YELLOW, COLOR_RED);
  }
  attrset(COLOR_PAIR(1));
  bkgdset(COLOR_PAIR(1));
  clear();

  display_main_menu();

  bkgdset(COLOR_PAIR(0));
  clear();
  refresh();
  endwin();
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "WINDOW" "ITEM" "PANEL" "MENU")
 * End:
 */
