/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2013 Alexander Chernov <cher@ejudge.ru> */

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

#include "checker_internal.h"

#include "l10n_impl.h"

int
checker_read_line(
        int ind,
        const char *name,
        int eof_error_flag,
        char **out_str)
{
  int c;
  unsigned char *buf = 0;
  size_t buf_a = 0, buf_u = 0;

  if (!name) name = "";
  c = getc_unlocked(f_arr[ind]);
  if (c == EOF) {
    if (ferror_unlocked(f_arr[ind])) {
      fatal_CF(_("%s: %s: input error"), gettext(f_arr_names[ind]), name);
    }
    if (!eof_error_flag) return -1;
    fatal_read(ind, _("%s: unexpected EOF"), name);
  }
  while (c != EOF) {
    if (!isspace(c) && c < ' ') {
      fatal_read(ind, _("%s: invalid control character with code %d"), name, c);
    }
    if (buf_u == buf_a) {
      if (!buf_a) buf_a = 128;
      buf_a *= 2;
      buf = xrealloc(buf, buf_a);
    }
    buf[buf_u++] = c;
    if (c == '\n') break;
    c = getc_unlocked(f_arr[ind]);
  }
  if (c == EOF && ferror_unlocked(f_arr[ind])) {
    fatal_CF(_("%s: %s: input error"), gettext(f_arr_names[ind]), name);
  }

  if (buf_u == buf_a) {
    if (!buf_a) buf_a = 128;
    buf_a *= 2;
    buf = xrealloc(buf, buf_a);
  }
  buf[buf_u] = 0;
  *out_str = buf;
  return buf_u;
}
