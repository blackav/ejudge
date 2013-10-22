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

void
checker_read_file_by_line(int ind,
                          char ***out_lines,
                          size_t *out_lines_num)
{
  char **lb_v = 0;
  size_t lb_a = 0, lb_u = 0;
  unsigned char *b_v = 0;
  size_t b_a = 0, b_u = 0;
  int c;

  lb_a = 128;
  lb_v = (char **) xcalloc(lb_a, sizeof(lb_v[0]));
  lb_v[0] = NULL;

  b_a = 1024;
  b_v = (unsigned char *) xmalloc(b_a);
  b_v[0] = 0;

  while ((c = getc(f_arr[ind])) != EOF) {
    if (!c) fatal_read(ind, _("\\0 byte in file"));
    if (b_u + 1 >= b_a) {
      b_v = (unsigned char*) xrealloc(b_v, (b_a *= 2) * sizeof(b_v[0]));
    }
    b_v[b_u++] = c;
    b_v[b_u] = 0;
    if (c != '\n') continue;

    if (lb_u + 1 >= lb_a) {
      lb_a *= 2;
      lb_v = (char **) xrealloc(lb_v, lb_a * sizeof(lb_v[0]));
    }
    lb_v[lb_u++] = xstrdup(b_v);
    lb_v[lb_u] = NULL;
    b_u = 0;
    b_v[b_u] = 0;
  }
  if (ferror(f_arr[ind])) {
    fatal_CF(_("Input error from %s file"), gettext(f_arr_names[ind]));
  }
  if (b_u > 0) {
    if (lb_u + 1 >= lb_a) {
      lb_v = xrealloc(lb_v, (lb_a *= 2) * sizeof(lb_v[0]));
    }
    lb_v[lb_u++] = xstrdup(b_v);
    lb_v[lb_u] = NULL;
  }

  if (out_lines_num) *out_lines_num = lb_u;
  if (out_lines) *out_lines = lb_v;

  free(b_v);
}
