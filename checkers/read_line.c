/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ejudge.ru> */

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

int
checker_read_line(int ind, const char *name,
                  int eof_error_flag,
                  char **out_str)
{
  int c;
  unsigned char *buf = 0;
  size_t buf_a = 0, buf_u = 0;

  if (!name) name = "";
  c = getc(f_arr[ind]);
  if (c == EOF) {
    if (ferror(f_arr[ind]))
      fatal_CF("Input error while reading %s", name);
    if (!eof_error_flag) return -1;
    if (ind == 1)
      fatal_PE("Unexpected EOF while reading %s", name);
    else
      fatal_CF("Unexpected EOF while reading %s", name);
  }
  while (c != EOF) {
    if (buf_u == buf_a) {
      if (!buf_a) buf_a = 128;
      buf_a *= 2;
      buf = xrealloc(buf, buf_a);
    }
    buf[buf_u++] = c;
    if (c == '\n') break;
    c = getc(f_arr[ind]);
  }
  if (c == EOF && ferror(f_arr[ind]))
    fatal_CF("Input error while reading %s", name);

  if (buf_u == buf_a) {
    if (!buf_a) buf_a = 128;
    buf_a *= 2;
    buf = xrealloc(buf, buf_a);
  }
  buf[buf_u] = 0;
  *out_str = buf;
  return buf_u;
}
