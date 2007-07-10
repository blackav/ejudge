/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2004-2007 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ncurses_utils.h"
#include "tex_dom.h"
#include "misctext.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <limits.h>
#include <menu.h>
#include <panel.h>
#include <ncurses.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>

#ifndef XALLOCAZ
#define XALLOCAZ(p,s) ((p) = (typeof(p)) alloca((s) * sizeof((p)[0])), memset((p), 0, ((s) * sizeof((p)[0]))))
#endif

WINDOW *root_window = 0;

void
ncurses_print_help(char const *help)
{
  wattrset(stdscr, COLOR_PAIR(3));
  wbkgdset(stdscr, COLOR_PAIR(3));
  mvwaddstr(stdscr, LINES - 1, 0, help);
  wclrtoeol(stdscr);
  wattrset(stdscr, COLOR_PAIR(1));
  wbkgdset(stdscr, COLOR_PAIR(1));
}

// DUMB!!!
void
ncurses_render_tex_buffer(WINDOW *win, tex_buffer_t pbuf)
{
  int line, col;

  for (line = 0; line < pbuf->lines; line++) {
    if (!pbuf->buf[line]) continue;
    for (col = 0; col < pbuf->cols; col++) {
      if (!pbuf->buf[line][col]) continue;
      mvwaddch(win, line, col, pbuf->buf[line][col]->c);
    }
  }
}

const unsigned char tex_parse_err_msg[] =
"\\begin{center}\n"
"ERROR!\n"
"\\end{center}\n\n"
"Failed to parse tex string!\n";

int
ncurses_yesno(int init_val, unsigned char const *fmt, ...)
{
  va_list args;
  char *asbuf = 0;
  WINDOW *in_win, *out_win, *txt_win;
  MENU *menu;
  ITEM *items[3];
  PANEL *in_pan, *out_pan, *txt_pan;
  int req_lines, req_cols, line0, col0;
  int answer = -1;               /* cancel */
  int c, cmd;
  tex_dom_result_t tex_dom_res = 0;
  tex_doc_t tex_doc = 0;
  tex_buffer_t tex_buf = 0;

  va_start(args, fmt);
  vasprintf(&asbuf, fmt, args);
  va_end(args);
  tex_dom_res = tex_dom_parse(asbuf);
  if (tex_dom_res->errcnt > 0) {
    tex_dom_res = tex_dom_free_result(tex_dom_res);
    //fprintf(stderr, ">>%s<<\n", asbuf);
    xfree(asbuf); asbuf = 0;
    tex_dom_res = tex_dom_parse(tex_parse_err_msg);
    ASSERT(!tex_dom_res->errcnt);
  }
  tex_doc = tex_dom_build_doc(tex_dom_res->tree);
  tex_dom_res = tex_dom_free_result(tex_dom_res);
  req_cols = tex_dom_get_doc_width(tex_doc);
  if (req_cols < 10) req_cols = 10;
  if (req_cols > COLS - 10) req_cols = COLS - 10;
  tex_buf = tex_dom_render(req_cols, tex_doc);
  tex_doc = tex_dom_free_doc(tex_doc);
  req_lines = tex_dom_get_height(tex_buf);

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
  ncurses_render_tex_buffer(txt_win, tex_buf);
  tex_buf = tex_dom_free_buffer(tex_buf);

  post_menu(menu);
  ncurses_print_help("Enter-select Y-Yes N-No Q-Quit");
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    switch (c) {
    case 'q': case 'Q': case 'Ê' & 255: case 'ê' & 255:
    case 'G' & 31:
      c = 'q';
      goto menu_done;
    case 'y': case 'Y': case 'Î' & 255: case 'î' & 255:
      c = 'y';
      goto menu_done;
    case 'n': case 'N': case 'Ô' & 255: case 'ô' & 255:
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

void
ncurses_msgbox(unsigned char const *fmt, ...)
{
  va_list args;
  char *asbuf = 0;
  WINDOW *in_win, *out_win, *txt_win;
  MENU *menu;
  ITEM *items[2];
  PANEL *in_pan, *out_pan, *txt_pan;
  int req_lines, req_cols, line0, col0;
  int c;
  tex_dom_result_t tex_dom_res = 0;
  tex_doc_t tex_doc = 0;
  tex_buffer_t tex_buf = 0;

  va_start(args, fmt);
  vasprintf(&asbuf, fmt, args);
  va_end(args);
  tex_dom_res = tex_dom_parse(asbuf);
  if (tex_dom_res->errcnt > 0) {
    tex_dom_res = tex_dom_free_result(tex_dom_res);
    //fprintf(stderr, ">>%s<<\n", asbuf);
    xfree(asbuf); asbuf = 0;
    tex_dom_res = tex_dom_parse(tex_parse_err_msg);
    ASSERT(!tex_dom_res->errcnt);
  }
  tex_doc = tex_dom_build_doc(tex_dom_res->tree);
  tex_dom_res = tex_dom_free_result(tex_dom_res);
  req_cols = tex_dom_get_doc_width(tex_doc);
  if (req_cols < 10) req_cols = 10;
  if (req_cols > COLS - 10) req_cols = COLS - 10;
  tex_buf = tex_dom_render(req_cols, tex_doc);
  tex_doc = tex_dom_free_doc(tex_doc);
  req_lines = tex_dom_get_height(tex_buf);

  if (req_cols < 10) req_cols = 10;
  line0 = (LINES - req_lines - 4) / 2;
  col0 = (COLS - req_cols - 2) / 2;

  items[0] = new_item("OK", 0);
  items[1] = 0;
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  set_current_item(menu, items[0]);

  out_win = newwin(req_lines + 3, req_cols + 2, line0, col0);
  txt_win = newwin(req_lines, req_cols, line0 + 1, col0 + 1);
  in_win = newwin(1, 4, line0 + req_lines + 1, col0 + 1 + (req_cols - 4) / 2);
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
  ncurses_render_tex_buffer(txt_win, tex_buf);
  tex_buf = tex_dom_free_buffer(tex_buf);

  post_menu(menu);
  ncurses_print_help("Enter, Q - ok");
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    switch (c) {
    case 'q': case 'Q': case 'Ê' & 255: case 'ê' & 255:
    case 'G' & 31:
      c = 'q';
      goto menu_done;
    case '\n': case '\r': case ' ':
      c = '\n';
      goto menu_done;
    }
  }
 menu_done:
  unpost_menu(menu);
  del_panel(in_pan);
  del_panel(out_pan);
  del_panel(txt_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(txt_win);
  delwin(in_win);
  free_item(items[0]);
  update_panels();
  doupdate();
}

void
ncurses_errbox(unsigned char const *fmt, ...)
{
  va_list args;
  char *asbuf = 0;
  WINDOW *in_win, *out_win, *txt_win;
  MENU *menu;
  ITEM *items[2];
  PANEL *in_pan, *out_pan, *txt_pan;
  int req_lines, req_cols, line0, col0;
  int c;
  tex_dom_result_t tex_dom_res = 0;
  tex_doc_t tex_doc = 0;
  tex_buffer_t tex_buf = 0;

  va_start(args, fmt);
  vasprintf(&asbuf, fmt, args);
  va_end(args);
  tex_dom_res = tex_dom_parse(asbuf);
  if (tex_dom_res->errcnt > 0) {
    tex_dom_res = tex_dom_free_result(tex_dom_res);
    //fprintf(stderr, ">>%s<<\n", asbuf);
    xfree(asbuf); asbuf = 0;
    tex_dom_res = tex_dom_parse(tex_parse_err_msg);
    ASSERT(!tex_dom_res->errcnt);
  }
  tex_doc = tex_dom_build_doc(tex_dom_res->tree);
  tex_dom_res = tex_dom_free_result(tex_dom_res);
  req_cols = tex_dom_get_doc_width(tex_doc);
  if (req_cols < 10) req_cols = 10;
  if (req_cols > COLS - 10) req_cols = COLS - 10;
  tex_buf = tex_dom_render(req_cols, tex_doc);
  tex_doc = tex_dom_free_doc(tex_doc);
  req_lines = tex_dom_get_height(tex_buf);

  if (req_cols < 10) req_cols = 10;
  line0 = (LINES - req_lines - 4) / 2;
  col0 = (COLS - req_cols - 2) / 2;

  items[0] = new_item("OK", 0);
  items[1] = 0;
  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(4));
  set_menu_fore(menu, COLOR_PAIR(3));
  set_current_item(menu, items[0]);

  out_win = newwin(req_lines + 3, req_cols + 2, line0, col0);
  txt_win = newwin(req_lines, req_cols, line0 + 1, col0 + 1);
  in_win = newwin(1, 4, line0 + req_lines + 1, col0 + 1 + (req_cols - 4) / 2);
  wattrset(out_win, COLOR_PAIR(4));
  wbkgdset(out_win, COLOR_PAIR(4));
  wattrset(in_win, COLOR_PAIR(4));
  wbkgdset(in_win, COLOR_PAIR(4));
  wattrset(txt_win, COLOR_PAIR(4));
  wbkgdset(txt_win, COLOR_PAIR(4));
  wclear(in_win);
  wclear(out_win);
  wclear(txt_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  txt_pan = new_panel(txt_win);
  in_pan = new_panel(in_win);
  set_menu_win(menu, in_win);
  ncurses_render_tex_buffer(txt_win, tex_buf);
  tex_buf = tex_dom_free_buffer(tex_buf);

  post_menu(menu);
  ncurses_print_help("Enter, Q - ok");
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    switch (c) {
    case 'q': case 'Q': case 'Ê' & 255: case 'ê' & 255:
    case 'G' & 31:
      c = 'q';
      goto menu_done;
    case '\n': case '\r': case ' ':
      c = '\n';
      goto menu_done;
    }
  }
 menu_done:
  unpost_menu(menu);
  del_panel(in_pan);
  del_panel(out_pan);
  del_panel(txt_pan);
  free_menu(menu);
  delwin(out_win);
  delwin(txt_win);
  delwin(in_win);
  free_item(items[0]);
  update_panels();
  doupdate();
}

int
ncurses_generic_menu(int min_width, int max_width, /* incl. frame */
                     int min_height, int max_height, /* incl. frame */
                     int first_item, int nitems,
                     int rec_line, int rec_col,
                     unsigned char const * const *items,
                     unsigned char const * const *hotkeys,
                     unsigned char const *help_str,
                     unsigned char const *format, ...)
{
  unsigned char buf[1024];
  int buflen, i, itemlen, c, answer = -3, cmd;
  va_list args;
  int act_width, item_width, act_height, head_width;
  unsigned char **item_strs;
  unsigned char const *pc;
  ITEM **curs_items;
  MENU *curs_menu;
  WINDOW *in_win, *out_win, *txt_win;
  PANEL *in_pan, *out_pan, *txt_pan;

  ASSERT(items);
  ASSERT(nitems >= 1);
  for (i = 0; i < nitems; i++) {
    ASSERT(items[i]);
  }

  /* FIXME: we cannot scroll yet */
  ASSERT(nitems + 3 <= LINES - 2);

  if (max_width > COLS - 2 || max_width < 4) {
    max_width = COLS - 2;
  }
  if (min_width < 4 || min_width > max_width) {
    min_width = 4;
  }
  if (max_height > LINES - 2 || max_height < 4) {
    max_height = LINES - 2;
  }
  if (min_height < 4 || min_height > max_height) {
    min_height = 4;
  }

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  buflen = strlen(buf);
  if (buflen > max_width - 2) {
    buf[max_width - 2] = 0;
    buflen = max_width - 2;
    head_width = max_width - 2;
  } else if (buflen < min_height - 2) {
    head_width = min_height - 2;
  } else {
    head_width = buflen;
  }
  act_width = head_width;

  item_width = -1;
  for (i = 0; i < nitems; i++) {
    itemlen = strlen(items[i]);
    if (itemlen > max_width - 3) {
      itemlen = max_width - 3;
    }
    if (itemlen > item_width) {
      item_width = itemlen;
    }
  }
  ASSERT(item_width > 0);

  XALLOCAZ(item_strs, nitems);
  for (i = 0; i < nitems; i++) {
    item_strs[i] = (unsigned char*) alloca(item_width + 1);
    memset(item_strs[i], ' ', item_width);
    item_strs[i][item_width] = 0;
    itemlen = strlen(items[i]);
    if (itemlen > item_width) {
      itemlen = item_width;
    }
    memcpy(item_strs[i], items[i], itemlen);
  }

  /* FIXME: too dumb */
  act_height = nitems + 1;

  if (item_width + 1 > act_width) {
    act_width = item_width + 1;
  }
  if (rec_col < 0 || rec_col >= COLS) {
    rec_col = (COLS - 2 - act_width) / 2;
  }
  if (rec_col + act_width + 2 >= COLS) {
    rec_col = COLS - 3 - act_width;
  }
  if (rec_col < 0) {
    rec_col = 0;
  }
  if (rec_line < 1 || rec_line >= LINES - 1) {
    rec_line = (LINES - 4 - act_height) / 2 + 1;
  }
  if (rec_line + act_height + 2 >= LINES) {
    rec_line = LINES - 3 - act_height;
  }
  if (rec_line < 1) {
    rec_line = 1;
  }

  XALLOCAZ(curs_items, nitems + 1);
  for (i = 0; i < nitems; i++) {
    curs_items[i] = new_item(item_strs[i], 0);
  }
  curs_menu = new_menu(curs_items);
  set_menu_back(curs_menu, COLOR_PAIR(1));
  set_menu_fore(curs_menu, COLOR_PAIR(3));

  out_win = newwin(act_height + 2, act_width + 2, rec_line, rec_col);
  txt_win = newwin(1, act_width, rec_line + 1, rec_col + 1);
  in_win = newwin(act_height - 1, item_width + 1,
                  rec_line + 2, rec_col + 1 + (act_width - item_width-1) / 2);
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
  set_menu_win(curs_menu, in_win);
  mvwaddstr(txt_win, 0, (act_width - head_width) / 2, buf);

  if (first_item >= nitems) first_item = nitems - 1;
  if (first_item < 0) first_item = 0;
  set_current_item(curs_menu, curs_items[first_item]);

  post_menu(curs_menu);
  if (!help_str) help_str = "Enter-select ^G-cancel";
  ncurses_print_help(help_str);
  update_panels();
  doupdate();

  while (1) {
    c = getch();
    if (c < 0) c &= 255;
    cmd = -1;
    switch (c) {
    case '\r': case '\n': case ' ':
      /* OK */
      cmd = -2;
      break;
    case 'G' & 31:
      /* CANCEL */
      cmd = -3;
      break;
    case KEY_UP:
    case KEY_LEFT:
      cmd = REQ_UP_ITEM;
      break;
    case KEY_DOWN:
    case KEY_RIGHT:
      cmd = REQ_DOWN_ITEM;
      break;
    default:
      if (hotkeys && c <= 255) {
        for (i = 0; i < nitems; i++) {
          if (!hotkeys[i]) continue;
          pc = hotkeys[i];
          while (*pc && *pc != c) pc++;
          if (*pc == c) {
            set_current_item(curs_menu, curs_items[i]);
            cmd = -2;
            break;
          }
        }
      }
    }

    if (cmd < -1) break;
    if (cmd > -1) {
      menu_driver(curs_menu, cmd);
      update_panels();
      doupdate();
    }
  }

  unpost_menu(curs_menu);
  switch (cmd) {
  case -2:
    answer = item_index(current_item(curs_menu));
    if (answer < 0 || answer > nitems) answer = 0;
    break;
  case -3:
    answer = -1;
    break;
  }

  del_panel(in_pan);
  del_panel(out_pan);
  del_panel(txt_pan);
  delwin(out_win);
  delwin(txt_win);
  delwin(in_win);
  free_menu(curs_menu);
  for (i = 0; i < nitems; i++) {
    free_item(curs_items[i]);
  }
  update_panels();
  doupdate();
  return answer;
}

int
ncurses_edit_password(int line, int scr_wid,
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
  char *myastbuf;

  ASSERT(length > 0);
  mybuf = alloca(length + 10);
  memset(mybuf, 0, length + 10);
  strcpy(mybuf, buf);
  myastbuf = alloca(length + 10);
  memset(myastbuf, 0, length + 10);
  memset(myastbuf, '*', strlen(mybuf));

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
  ncurses_print_help("Enter-Ok ^G-Cancel");
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
    memset(myastbuf, '*', curlen);
    myastbuf[curlen] = 0;
    mvwaddnstr(txt_win, 0, 0, myastbuf + pos0, w);
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

int
ncurses_edit_string(
	int line,
        int scr_wid,
        unsigned char const *head,
        unsigned char *buf,
        int length,
        int utf8_mode)
{
  WINDOW *out_win, *txt_win, *head_win;
  PANEL *out_pan, *txt_pan, *head_pan;
  int retval = -1;
  int req_lines, req_cols, line0, col0;
  int pos0, curpos, w, curlen;
  int c, wc, wsz, i;
  char *mybuf;
  int *gl_ind = 0;
  unsigned char *pc;

  ASSERT(length > 0);
  mybuf = alloca(length + 10);
  memset(mybuf, 0, length + 10);
  snprintf(mybuf, length, "%s", buf);
  if (utf8_mode) {
    gl_ind = alloca((length + 10) * sizeof(gl_ind[0]));
    curlen = utf8_fix_string(mybuf, gl_ind);
  } else {
    gl_ind = alloca((length + 10) * sizeof(gl_ind[0]));
    curlen = strlen(mybuf);
    for (w = 0; w <= curlen; w++)
      gl_ind[w] = w;
  }

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
    col0 = COLS - 1 - req_cols;
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
  ncurses_print_help("Enter-Ok ^G-Cancel");
  update_panels();
  doupdate();
  curpos = curlen; // glyph position of the cursor
  pos0 = 0; // glyph position of the starting seq

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
    mvwaddnstr(txt_win, 0, 0, mybuf + gl_ind[pos0], -1 /*w*/);
    wclrtoeol(txt_win);
    wmove(txt_win, 0, curpos - pos0);
    wnoutrefresh(txt_win);
    doupdate();
    if (utf8_mode) {
      wc = 0;
      wsz = 0;
      c = getch();
      if (c < ' ' || c == 0x7f) {
        // do nothing
      } else if (c < 0x7f) {
        wc = c;
        wsz = 1;
      } else if (c <= 0xbf) {
        // invalid starting char
        continue;
      } else if (c <= 0xc1) {
        // reserved starting char
        continue;
      } else if (c <= 0xdf) {
        // two bytes: 0x80-0x7ff
        wc = c & 0x1f;
        wsz = 2;
      } else if (c <= 0xef) {
        // three bytes: 0x800-0xffff
        wc = c & 0x0f;
        wsz = 3;
      } else if (c <= 0xf7) {
        // four bytes: 0x10000-0x10ffff
        wc = c & 0x07;
        wsz = 4;
      } else if (c <= 0xff) {
        // reserved starting char
        continue;
      }
      if (wsz > 0) {
        for (i = 1; i < wsz; i++) {
          c = getch();
          if (c < 0x80 || c > 0xbf) break;
          wc = (wc << 6) | (c & 0x3f);
        }
        if (i < wsz) continue;
        if (wc <= 0x7f) wsz = 1;
        else if (wc <= 0x7ff) wsz = 2;
        else if (wc <= 0xffff) wsz = 3;
        else wsz = 4;
        if (gl_ind[curlen] + wsz > length) continue;
        memmove(mybuf + gl_ind[curpos] + wsz, mybuf + gl_ind[curpos],
                gl_ind[curlen] - gl_ind[curpos] + 1);
        memmove(&gl_ind[curpos + 1], &gl_ind[curpos],
                (curlen - curpos + 1) * sizeof(gl_ind[0]));
        for (i = curpos + 1; i <= curlen + 1; i++)
          gl_ind[i] += wsz;
        pc = mybuf + gl_ind[curpos];
        if (wsz == 1) {
          *pc = wc;
        } else if (wsz == 2) {
          *pc++ = ((wc >> 6) & 0x1f) | 0xc0;
          *pc = (wc & 0x3f) | 0x80;
        } else if (wsz == 3) {
          *pc++ = ((wc >> 12) & 0x0f) | 0xe0;
          *pc++ = ((wc >> 6) & 0x3f) | 0x80;
          *pc = (wc & 0x3f) | 0x80;
        } else if (wsz == 4) {
          *pc++ = ((wc >> 18) & 0x07) | 0xf0;
          *pc++ = ((wc >> 12) & 0x3f) | 0x80;
          *pc++ = ((wc >> 6) & 0x3f) | 0x80;
          *pc = (wc & 0x3f) | 0x80;
        }
        curpos++;
        curlen++;
        continue;
      }
    } else {
      c = getch();
      if (c >= ' ' && c <= 255 && c != 127) {
        if (curlen == length) continue;
        memmove(mybuf + curpos + 1, mybuf + curpos, curlen - curpos + 1);
        mybuf[curpos] = c;
        curpos++;
        curlen++;
        gl_ind[curlen] = curlen;
        continue;
      }
    }
    if (c == ('G' & 31) || c == '\033') {
      break;
    }
    if (c == '\r' || c == '\n') {
      ASSERT(strlen(mybuf) <= length);
      strcpy(buf, mybuf);
      retval = strlen(buf);
      break;
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
      if (utf8_mode) {
        wsz = gl_ind[curpos + 1] - gl_ind[curpos];
        memmove(mybuf + gl_ind[curpos], mybuf + gl_ind[curpos + 1],
                gl_ind[curlen] + 1 - gl_ind[curpos + 1]);
        memmove(&gl_ind[curpos], &gl_ind[curpos + 1],
                (curlen - curpos) * sizeof(gl_ind[0]));
        curlen--;
        for (i = curpos; i <= curlen; i++)
          gl_ind[i] -= wsz;
      } else {
        memmove(mybuf + curpos, mybuf + curpos + 1, curlen - curpos);
        curlen--;
      }
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
      if (utf8_mode) {
        wsz = gl_ind[curpos] - gl_ind[0];
        memmove(mybuf, mybuf + gl_ind[curpos],
                gl_ind[curlen] - gl_ind[curpos] + 1);
        memmove(gl_ind, &gl_ind[curpos],
                (curlen - curpos + 1) * sizeof(gl_ind[0]));
        curlen -= curpos;
        curpos = 0;
        for (i = 0; i <= curlen; i++)
          gl_ind[i] -= wsz;
      } else {
        memmove(mybuf, mybuf + curpos, curlen - curpos + 1);
        curlen -= curpos;
        curpos = 0;
      }
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

struct file_info
{
  unsigned char *name;
  struct stat stbuf;
  struct stat lstbuf;
};

static int
file_sort_func(const void *p1, const void *p2)
{
  const struct file_info *f1 = *(const struct file_info **) p1;
  const struct file_info *f2 = *(const struct file_info **) p2;

  if (p1 == p2) return 0;
  if (f1 == f2) return 0;

  // dangling links
  if (!f1->stbuf.st_mode && !f2->stbuf.st_mode)
    return strcmp(f1->name, f2->name);
  if (!f1->stbuf.st_mode) return 1;
  if (!f2->stbuf.st_mode) return -1;

  if (S_ISDIR(f1->stbuf.st_mode) && !S_ISDIR(f2->stbuf.st_mode)) return -1;
  if (!S_ISDIR(f1->stbuf.st_mode) && S_ISDIR(f2->stbuf.st_mode)) return 1;
  return strcmp(f1->name, f2->name);
}

static int
do_choose_file(
	const unsigned char *header,
        unsigned char *path_buf,
        int *p_view_hidden_flag,
        int utf8_mode)
{
  unsigned char dir_path[PATH_MAX], file_name[PATH_MAX];
  unsigned char tmp_path[PATH_MAX];
  unsigned char new_dir_name[PATH_MAX];
  size_t path_len, name_len, beg_len, end_len;
  struct file_info **files = 0;
  size_t files_u = 0, files_a = 0;
  DIR *d = 0;
  int retcode = -1, i, file_ind, first_row, cmd, c, j;
  struct dirent *dd;
  struct stat stbuf, lstbuf;
  char **descs = 0;
  const unsigned char *lnk_str = 0, *type_str = 0;
  unsigned char mode_str[10], time_str[32], size_str[32];
  unsigned char name_str[35];
  struct tm *ptm;
  ITEM **items = 0;
  MENU *menu = 0;
  WINDOW *in_win = 0, *out_win = 0, *path_win = 0;
  PANEL *out_pan = 0, *in_pan = 0, *path_pan = 0;

  //fprintf(stderr, "path_buf: %s\n", path_buf);

  ASSERT(path_buf[0] == '/');
  path_len = strlen(path_buf);
  if (path_buf[path_len - 1] == '/') {
    file_name[0] = 0;
    snprintf(dir_path, sizeof(dir_path), "%s", path_buf);
    path_len = strlen(dir_path);
    while (path_len > 0 && dir_path[path_len - 1] == '/')
      dir_path[--path_len] = 0;
    if (!path_len) {
      dir_path[path_len++] = '/';
      dir_path[path_len] = 0;
    }
  } else {
    while (path_buf[path_len - 1] != '/') path_len--;
    snprintf(file_name, sizeof(file_name), "%s", path_buf + path_len);
    while (path_len > 0 && path_buf[path_len - 1] == '/') path_len--;
    if (!path_len) path_len++;
    snprintf(dir_path, sizeof(dir_path), "%.*s", (int) path_len, path_buf);
  }

  //fprintf(stderr, "dir_path: %s\n", dir_path);
  //fprintf(stderr, "file_name: %s\n", file_name);

  // so far: dir_path: directory, file_name: file in it
  files_a = 16;
  XCALLOC(files, files_a);
  XCALLOC(files[0], 1);
  files[0]->name = xstrdup("..");
  files_u = 1;
  if (!strcmp(dir_path, "/")) {
    snprintf(tmp_path, sizeof(tmp_path), "/%s", files[0]->name);
  } else {
    snprintf(tmp_path, sizeof(tmp_path), "%s/%s", dir_path, files[0]->name);
  }
  if (stat(tmp_path, &files[0]->stbuf) < 0) {
    ncurses_errbox("\\begin{center}\nERROR!\n\nCannot stat  `%s'\n\\end{center}\n", tmp_path);
    goto cleanup;
  }
  memcpy(&files[0]->lstbuf, &files[0]->stbuf, sizeof(struct stat));

  if (!(d = opendir(dir_path))) {
    ncurses_errbox("\\begin{center}\nERROR!\n\nCannot open directory `%s'\n\\end{center}\n", dir_path);
    goto cleanup;
  }
  while ((dd = readdir(d))) {
    if (!dd->d_name[0]) continue;
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
    if (dd->d_name[0] == '.' && !*p_view_hidden_flag) continue;
    if (!strcmp(dir_path, "/")) {
      snprintf(tmp_path, sizeof(tmp_path), "/%s", dd->d_name);
    } else {
      snprintf(tmp_path, sizeof(tmp_path), "%s/%s", dir_path, dd->d_name);
    }
    if (lstat(tmp_path, &lstbuf) < 0) continue;
    if (!S_ISLNK(lstbuf.st_mode)) {
      memcpy(&stbuf, &lstbuf, sizeof(stbuf));
    } else if (stat(tmp_path, &stbuf) < 0) {
      // dangling link
      memset(&stbuf, 0, sizeof(stbuf));
    }
    if (files_u == files_a) {
      files_a *= 2;
      XREALLOC(files, files_a);
    }
    XCALLOC(files[files_u], 1);
    files[files_u]->name = xstrdup(dd->d_name);
    memcpy(&files[files_u]->stbuf, &stbuf, sizeof(stbuf));
    memcpy(&files[files_u]->lstbuf, &lstbuf, sizeof(lstbuf));
    files_u++;
  }
  if (closedir(d) < 0) {
    d = 0;
    ncurses_errbox("\\begin{center}\nERROR!\n\nRead error on directory `%s'\n\\end{center}\n", dir_path);
    goto cleanup;
  }
  d = 0;

  if (files_u > 1) {
    qsort(&files[1], files_u - 1, sizeof(files[0]), file_sort_func);
  }
  file_ind = 0;
  if (file_name[0]) {
    for (i = 1; i < files_u; i++)
      if (!strcmp(files[i]->name, file_name))
        break;
    if (i < files_u) file_ind = i;
  }
  XCALLOC(descs, files_u);

  for (i = 0; i < files_u; i++) {
    if (!files[i]->stbuf.st_mode) {
      lnk_str = "!";
    } else if (S_ISLNK(files[i]->lstbuf.st_mode)) {
      lnk_str = "@";
    } else {
      lnk_str = " ";
    }

    if (!files[i]->stbuf.st_mode) {
      type_str = " ";
    } else if (S_ISDIR(files[i]->stbuf.st_mode)) {
      type_str = "/";
    } else if (S_ISCHR(files[i]->stbuf.st_mode)) {
      type_str = "#";
    } else if (S_ISBLK(files[i]->stbuf.st_mode)) {
      type_str = "#";
    } else if (S_ISFIFO(files[i]->stbuf.st_mode)) {
      type_str = "|";
    } else if (S_ISSOCK(files[i]->stbuf.st_mode)) {
      type_str = "~";
    } else {
      type_str = " ";
    }

    strcpy(mode_str, "---------");
    if ((files[i]->lstbuf.st_mode & 0400)) mode_str[0] = 'r';
    if ((files[i]->lstbuf.st_mode & 0200)) mode_str[1] = 'w';
    if ((files[i]->lstbuf.st_mode & 0100)) mode_str[2] = 'x';
    if ((files[i]->lstbuf.st_mode & 0040)) mode_str[3] = 'r';
    if ((files[i]->lstbuf.st_mode & 0020)) mode_str[4] = 'w';
    if ((files[i]->lstbuf.st_mode & 0010)) mode_str[5] = 'x';
    if ((files[i]->lstbuf.st_mode & 0004)) mode_str[6] = 'r';
    if ((files[i]->lstbuf.st_mode & 0002)) mode_str[7] = 'w';
    if ((files[i]->lstbuf.st_mode & 0001)) mode_str[8] = 'x';

    ptm = localtime(&files[i]->lstbuf.st_mtime);
    snprintf(time_str, sizeof(time_str), "%04d/%02d/%02d %02d:%02d:%02d",
             ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
             ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
    
    if (files[i]->lstbuf.st_size > 1073741824) {
      snprintf(size_str, sizeof(size_str), ">1G");
    } else {
      snprintf(size_str, sizeof(size_str), "%lld",
               (long long) files[i]->lstbuf.st_size);
    }

    name_len = strlen(files[i]->name);
    if (name_len > sizeof(name_str) - 1) {
      beg_len = (sizeof(name_str) - 4) / 2;
      end_len = sizeof(name_str) - 4 - beg_len;
      snprintf(name_str, sizeof(name_str), "%.*s...%s",
               (int) beg_len, files[i]->name, files[i]->name + name_len - end_len);
    } else {
      snprintf(name_str, sizeof(name_str), "%s", files[i]->name);
    }

    asprintf(&descs[i], "%s%s%-*.*s %10s %s %s",
             lnk_str, type_str, (int) (sizeof(name_str) - 1),
             (int) (sizeof(name_str) - 1),
             name_str, size_str, time_str, mode_str);
  }

  XCALLOC(items, files_u + 1);
  for (i = 0; i < files_u; i++)
    items[i] = new_item(descs[i], 0);

  menu = new_menu(items);
  set_menu_back(menu, COLOR_PAIR(1));
  set_menu_fore(menu, COLOR_PAIR(3));
  out_win = newwin(LINES - 3, COLS, 2, 0);
  in_win = newwin(LINES - 5, COLS - 2, 3, 1);
  path_win = newwin(1, COLS, 1, 0);
  wattrset(out_win, COLOR_PAIR(1));
  wbkgdset(out_win, COLOR_PAIR(1));
  wattrset(in_win, COLOR_PAIR(1));
  wbkgdset(in_win, COLOR_PAIR(1));
  wattrset(path_win, COLOR_PAIR(1));
  wbkgdset(path_win, COLOR_PAIR(1));
  wclear(in_win);
  wclear(out_win);
  wclear(path_win);
  box(out_win, 0, 0);
  out_pan = new_panel(out_win);
  in_pan = new_panel(in_win);
  path_pan = new_panel(path_win);
  set_menu_win(menu, in_win);
  set_menu_format(menu, LINES - 5, 0);

  if (file_ind < 0) file_ind = 0;
  if (file_ind >= files_u) file_ind = files_u - 1;
  first_row = file_ind - (LINES - 5) / 2;
  if (first_row + LINES - 5 > files_u) first_row = files_u - (LINES - 5);
  if (first_row < 0) first_row = 0;
  set_top_row(menu, first_row);
  set_current_item(menu, items[file_ind]);

  while (1) {
    if (!header || !*header) {
      mvwprintw(stdscr, 0, 0, "Choose file or directory");
    } else {
      mvwprintw(stdscr, 0, 0, "%.*s", COLS - 1, header);
    }
    wclrtoeol(stdscr);
    mvwprintw(path_win, 0, 0, "%s", dir_path);
    wclrtoeol(path_win);
    ncurses_print_help("Enter - enter dir, Space - choose, Q - cancel, H - toggle hidden, M - mkdir");
    show_panel(path_pan);
    show_panel(out_pan);
    show_panel(in_pan);
    post_menu(menu);
    update_panels();
    doupdate();

    while (1) {
      c = getch();
      cmd = -1;
      switch (c) {
        /*
      case KEY_BACKSPACE: case KEY_DC: case 127: case 8:
      case 'd': case 'D': case '÷' & 255: case '×' & 255:
        c = 'd';
        goto menu_done;
        */
      case 'q': case 'Q': case 'Ê' & 255: case 'ê' & 255: case 'G' & 31:
        c = 'q';
        goto menu_done;
      case '\n': case '\r':
        c = '\n';
        goto menu_done;
      case 'h': case 'H': case 'Ò' & 255: case 'ò' & 255:
        c = 'h';
        goto menu_done;
      case 'm': case 'M': case 'Ø' & 255: case 'ø' & 255:
        c = 'm';
        goto menu_done;
      case ' ':
        goto menu_done;
      case KEY_UP: case KEY_LEFT:
        cmd = REQ_UP_ITEM;
        break;
      case KEY_DOWN: case KEY_RIGHT:
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
        if (i + LINES - 5 >= files_u) cmd = REQ_LAST_ITEM;
        else cmd = REQ_SCR_DPAGE;
        break;
      case KEY_PPAGE:
        i = item_index(current_item(menu));
        if (i - (LINES - 5) < 0) cmd = REQ_FIRST_ITEM;
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
    ;
    i = item_index(current_item(menu));
    if (c == 'q') break;
    if (c == ' ') {
      if (!i) continue;
      if (!strcmp(dir_path, "/")) {
        snprintf(path_buf, PATH_MAX, "/%s", files[i]->name);
      } else {
        snprintf(path_buf, PATH_MAX, "%s/%s", dir_path, files[i]->name);
      }
      retcode = 0;
      break;
    }
    if (c == '\n') {
      if (!i) {
        // cd ..
        snprintf(path_buf, PATH_MAX, "%s", dir_path);
        retcode = -2;
        break;
      }
      // dangling link
      if (!files[i]->stbuf.st_mode) continue;
      // not a dir
      if (!S_ISDIR(files[i]->stbuf.st_mode)) continue;
      // ok
      if (!strcmp(dir_path, "/")) {
        snprintf(path_buf, PATH_MAX, "/%s/", files[i]->name);
      } else {
        snprintf(path_buf, PATH_MAX, "%s/%s/", dir_path, files[i]->name);
      }
      retcode = -2;
      break;
    }
    if (c == 'h') {
      *p_view_hidden_flag = !*p_view_hidden_flag;
      retcode = -2;
      break;
    }
    if (c == 'm') {
      j = ncurses_edit_string(LINES/2, COLS, "New directory name",
                              new_dir_name, sizeof(new_dir_name), utf8_mode);
      if (j < 0) continue;
      if (strchr(new_dir_name, '/')) {
        ncurses_errbox("\\begin{center}\nERROR!\n\nInvalid directory name!\n\\end{center}\n", dir_path);
        continue;
      }
      if (!strcmp(dir_path, "/")) {
        snprintf(tmp_path, sizeof(tmp_path), "/%s", new_dir_name);
      } else {
        snprintf(tmp_path, sizeof(tmp_path), "%s/%s", dir_path, new_dir_name);
      }
      if (mkdir(tmp_path, 0777) < 0) {
        i = errno;
        //fprintf(stderr, ">>>%s<\n", strerror(i));
        ncurses_errbox("\\begin{center}\nERROR!\n\n%s!\n\\end{center}\n", strerror(i));
        continue;
      }
      snprintf(path_buf, PATH_MAX, tmp_path);
      retcode = -2;
      break;
    }
  }

 cleanup:
  wmove(stdscr, 0, 0);
  wclrtoeol(stdscr);
  if (path_pan) del_panel(path_pan);
  if (in_pan) del_panel(in_pan);
  if (out_pan) del_panel(out_pan);
  if (menu) free_menu(menu);
  if (out_win) delwin(out_win);
  if (in_win) delwin(in_win);
  if (path_win) delwin(path_win);
  if (d) closedir(d);
  if (items) {
    for (i = 0; i < files_u; i++) {
      if (items[i]) free_item(items[i]);
    }
    xfree(items);
  }
  if (files) {
    for (i = 0; i < files_u; i++) {
      if (files[i]->name) xfree(files[i]->name);
      xfree(files[i]);
    }
    xfree(files);
  }
  if (descs) {
    for (i = 0; i < files_u; i++)
      xfree(descs[i]);
    xfree(descs);
  }
  return retcode;
}

int
ncurses_choose_file(
	const unsigned char *header,
        unsigned char *buf,
        size_t buf_size,
        int utf8_mode)
{
  unsigned char tmp_buf[PATH_MAX], wdir[PATH_MAX];
  size_t si, di;
  struct stat stbuf;
  int res;
  int view_hidden_flag = 0;

  if (!buf[0]) {
    os_rGetWorkingDir(tmp_buf, sizeof(tmp_buf), 0);
  } else if (buf[0] != '/') {
    os_rGetWorkingDir(wdir, sizeof(wdir), 0);
    snprintf(tmp_buf, sizeof(tmp_buf), "%s/%s", wdir, buf);
  } else {
    snprintf(tmp_buf, sizeof(tmp_buf), "%s", buf);
  }

  os_normalize_path(tmp_buf);

  /* remove . and .. */
  si = di = 0;
  while (tmp_buf[si]) {
    if (tmp_buf[si] == '/' && tmp_buf[si + 1] == '.'
        && (!tmp_buf[si + 2] || tmp_buf[si + 2] == '/')) {
      si += 2;
    } else if (tmp_buf[si] == '/'
               && tmp_buf[si + 1] == '.' && tmp_buf[si + 2] == '.'
               && (!tmp_buf[si + 3] || tmp_buf[si + 3] == '/')) {
      if (!di || (di == 1 && tmp_buf[0] == '/')) {
        si += 3;
        di = 0;
      } else {
        while (di > 0 && tmp_buf[di - 1] == '/') di--;
        while (di > 0 && tmp_buf[di - 1] != '/') di--;
        if (di > 0) di--;
      }
    } else {
      if (si != di) tmp_buf[di] = tmp_buf[si];
      di++, si++;
    }
  }
  tmp_buf[di] = 0;

  while (1) {
    if (stat(tmp_buf, &stbuf) >= 0) break;
    // drop the last component of the path
    while (di > 0 && tmp_buf[di - 1] == '/') di--;
    while (di > 0 && tmp_buf[di - 1] != '/') di--;
    if (di > 0) di--;
    tmp_buf[di] = 0;
    if (!di) {
      ncurses_errbox("\\begin{center}\nERROR!\n\nCannot stat / directory!\n\\end{center}\n");
      return -1;
    }
  }

  while (di > 0 && tmp_buf[di - 1] == '/') di--;
  if (!di) tmp_buf[di++] = '/';
  tmp_buf[di] = 0;

  if (S_ISDIR(stbuf.st_mode)) {
    tmp_buf[di++] = '/';
    tmp_buf[di] = 0;
  }

  while (1) {
    res = do_choose_file(header, tmp_buf, &view_hidden_flag, utf8_mode);
    if (res >= -1) break;
  }

  if (res >= 0) {
    snprintf(buf, buf_size, "%s", tmp_buf);
  }
  return res;
}

struct line_info
{
  size_t len;
  unsigned char *txt;
};
struct txt_info
{
  int a, u, w;
  struct line_info *l;
};

void
ncurses_view_text(const unsigned char *header, const unsigned char *txt)
{
  const unsigned char *p, *q;
  struct txt_info fi;
  int i, j, first_line = 0, first_col = 0, height, width, c;
  WINDOW *in_win = 0, *out_win = 0;
  PANEL *in_pan = 0, *out_pan = 0;

  if (!header) header = "";
  if (!txt) txt = "";

  memset(&fi, 0, sizeof(fi));
  p = q = txt;
  while (1) {
    if (!*p || *p == '\n') {
      if (fi.u == fi.a) {
        if (!fi.a) fi.a = 8;
        fi.a *= 2;
        XREALLOC(fi.l, fi.a);
      }
      fi.l[fi.u].len = p - q;
      fi.l[fi.u].txt = xmemdup(q, p - q);
      fi.u++;
      if (!*p) break;
      p++; q = p;
    } else {
      p++;
    }
  }

  for (i = 0; i < fi.u; i++) {
    for (j = 0; j < fi.l[i].len; j++)
      if (fi.l[i].txt[j] < ' ')
        fi.l[i].txt[j] = ' ';
    while (fi.l[i].len > 0 && fi.l[i].txt[fi.l[i].len - 1] == ' ')
      fi.l[i].txt[--fi.l[i].len] = 0;
    if (fi.l[i].len > fi.w) fi.w = fi.l[i].len;
  }
  while (fi.u > 0 && !fi.l[fi.u - 1].len)
    xfree(fi.l[--fi.u].txt);

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

  mvwprintw(stdscr, 0, 0, "%.*s", COLS - 1, header);
  wclrtoeol(stdscr);
  ncurses_print_help("Q - quit");

  show_panel(out_pan);
  show_panel(in_pan);

  height = LINES - 4;
  width = COLS - 2;

  while (1) {
    // dumb!!!
    wclear(in_win);
    for (i = 0; i < LINES - 4 && first_line + i < fi.u; i++) {
      if (first_col >= fi.l[first_line + i].len) continue;
      mvwprintw(in_win, i, 0, "%.*s", COLS - 2,
                fi.l[first_line + i].txt + first_col);
      //fprintf(stderr, "[%d]>>%s\n", i, fi.l[first_line + i].txt + first_col);
    }

    update_panels();
    doupdate();

    while (1) {
      c = getch();
      switch (c) {
      case 'q': case 'Q': case 'Ê' & 255: case 'ê' & 255: case 'G' & 31:
        c = 'q';
        goto menu_done;
      case KEY_UP:
        if (!first_line) break;
        first_line--;
        wmove(in_win, 0, 0);
        winsertln(in_win);
        wprintw(in_win, "%.*s", COLS - 2, fi.l[first_line].txt + first_col);
        update_panels();
        doupdate();
        break;
      case KEY_DOWN:
        if (first_line + height >= fi.u) break;
        first_line++;
        wmove(in_win, 0, 0);
        wdeleteln(in_win);
        mvwprintw(in_win, height - 1, 0, "%.*s", COLS - 2,
                  fi.l[first_line + height - 1].txt + first_col);
        update_panels();
        doupdate();
        break;
      case KEY_LEFT:
        if (!first_col) break;
        first_col--;
        goto menu_done;
      case KEY_RIGHT:
        if (first_col + width >= fi.w) break;
        first_col++;
        goto menu_done;
      case KEY_HOME:
        first_col = 0;
        goto menu_done;
      case KEY_END:
        first_col = fi.w - width;
        if (first_col < 0) first_col = 0;
        goto menu_done;
      case KEY_NPAGE:
        first_line += height - 1;
        if (first_line + height > fi.u) first_line = fi.u - height;
        if (first_line < 0) first_line = 0;
        goto menu_done;
      case KEY_PPAGE:
        first_line -= height - 1;
        if (first_line < 0) first_line = 0;
        goto menu_done;
      }
    }
  menu_done:
    if (c == 'q') break;
  }

  if (in_pan) del_panel(in_pan);
  if (out_pan) del_panel(out_pan);
  if (out_win) delwin(out_win);
  if (in_win) delwin(in_win);
  for (i = 0; i < fi.u; i++)
    xfree(fi.l[i].txt);
  xfree(fi.l);
}

int
ncurses_init(void)
{
  if (!(root_window = initscr())) return -1;
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
    init_pair(5, COLOR_RED, COLOR_BLUE);
  }
  attrset(COLOR_PAIR(1));
  bkgdset(COLOR_PAIR(1));

  clear();
  return 0;
}

void
ncurses_shutdown(void)
{
  bkgdset(COLOR_PAIR(0));
  clear();
  refresh();
  endwin();
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "WINDOW" "ITEM" "PANEL" "MENU" "DIR")
 * End:
 */
