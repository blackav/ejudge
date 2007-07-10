/* -*- c -*- */
/* $Id$ */

#ifndef __NCURSES_UTILS_H__
#define __NCURSES_UTILS_H__

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

#include <menu.h>
#include <panel.h>
#include <ncurses.h>

extern WINDOW *root_window;

int ncurses_init(void);
void ncurses_shutdown(void);

void ncurses_print_help(const char *help);
int ncurses_yesno(int init_val, unsigned char const *fmt, ...);

int ncurses_generic_menu(int min_width, int max_width, /* incl. frame */
                         int min_height, int max_height, /* incl. frame */
                         int first_item, int nitems,
                         int rec_line, int rec_col,
                         unsigned char const * const *items,
                         unsigned char const * const *hotkeys,
                         unsigned char const *help_str,
                         unsigned char const *format, ...);

int ncurses_edit_string(int line, int scr_wid,
                        unsigned char const *head,
                        unsigned char *buf, int length, int utf8_mode);

int ncurses_edit_password(int line, int scr_wid,
                          unsigned char const *head,
                          unsigned char *buf, int length);

void ncurses_msgbox(unsigned char const *fmt, ...);
void ncurses_errbox(unsigned char const *fmt, ...);

int ncurses_choose_file(const unsigned char *header,
                        unsigned char *buf, size_t buf_size, int utf8_mode);

void ncurses_view_text(const unsigned char *header, const unsigned char *txt);

#endif /* __NCURSES_UTILS_H__ */

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "WINDOW" "ITEM" "PANEL" "MENU")
 * End:
 */
