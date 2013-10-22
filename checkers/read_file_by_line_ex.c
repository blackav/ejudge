/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2010-2013 Alexander Chernov <cher@ejudge.ru> */

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

void
checker_read_file_by_line_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        char ***out_lines,
        size_t *out_lines_num)
{
  unsigned char **lines = 0, **new_l = 0;
  size_t lines_u = 0, lines_a = 0, new_a = 0;
  unsigned char *buf = 0;
  size_t buf_u = 0, buf_a = 0;
  int c;

  *out_lines = 0;
  *out_lines_num = 0;
  if (!name) name = "";

  while ((c = getc_unlocked(f)) != EOF) {
    if (!isspace(c) && c < ' ') {
      error_func(_("%s: invalid control character with code %d"), name, c);
    }
    if (buf_u == buf_a) {
      if (!buf_a) buf_a = 16;
      buf = xrealloc(buf, buf_a *= 2);
    }
    buf[buf_u++] = c;
    if (c == '\n') {
      if (buf_u == buf_a) {
      if (!buf_a) buf_a = 16;
        buf = xrealloc(buf, buf_a *= 2);
      }
      buf[buf_u] = 0;
      if (lines_u == lines_a) {
        if(!(new_a = lines_a * 2)) new_a = 16;
        XCALLOC(new_l, new_a);
        if (lines_a > 0) {
          memcpy(new_l, lines, lines_a * sizeof(new_l[0]));
        }
        free(lines);
        lines_a = new_a;
        lines = new_l;
      }
      lines[lines_u++] = xstrdup(buf);
      buf_u = 0;
    }
  }

  if (ferror_unlocked(f)) {
    fatal_CF(_("%s: input error"), name);
  }
  if (buf_u > 0) {
    if (buf_u == buf_a) {
      buf = xrealloc(buf, buf_a *= 2);
    }
    buf[buf_u] = 0;

    if (lines_u == lines_a) {
      if(!(new_a = lines_a * 2)) new_a = 16;
      XCALLOC(new_l, new_a);
      if (lines_a > 0) {
        memcpy(new_l, lines, lines_a * sizeof(new_l[0]));
      }
      free(lines);
      lines_a = new_a;
      lines = new_l;
    }
    lines[lines_u++] = buf;
    buf = 0; buf_u = buf_a = 0;
  }

  *out_lines = (char**) lines;
  *out_lines_num = lines_u;
}
