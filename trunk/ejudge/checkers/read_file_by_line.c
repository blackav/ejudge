/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003 Alexander Chernov <cher@ispras.ru> */

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

void
checker_read_file_by_line(int ind,
                          unsigned char ***out_lines,
                          size_t *out_lines_num)
{
  unsigned char **lb_v = 0;
  size_t lb_a = 0, lb_u = 0;
  unsigned char *b_v = 0;
  size_t b_a = 0, b_u = 0;
  unsigned char tv[512];
  size_t tl;
  unsigned char **bb;

  lb_a = 128;
  lb_v = (unsigned char **) alloca(lb_a * sizeof(lb_v[0]));
  memset(lb_v, 0, lb_a * sizeof(lb_v[0]));
  b_a = 1024;
  b_v = (unsigned char *) alloca(b_a);
  memset(b_v, 0, b_a);

  while (fgets(tv, sizeof(tv), f_arr[ind])) {
    tl = strlen(tv);
    if (tl + b_u >= b_a) {
      size_t new_b_a = b_a;
      unsigned char *new_b_v;

      while (tl + b_u >= new_b_a) new_b_a *= 2;
      new_b_v = (unsigned char*) alloca(new_b_a);
      memset(new_b_v, 0, new_b_a);
      memcpy(new_b_v, b_v, b_u + 1);
      b_v = new_b_v;
      b_a = new_b_a;
    }
    memcpy(b_v + b_u, tv, tl + 1);
    b_u += tl;

    if (tl < sizeof(tv) - 1 || feof(f_arr[ind])) {
      if (lb_u >= lb_a - 1) {
        size_t new_lb_a = lb_a * 2;
        unsigned char **new_lb_v;

        new_lb_v = (unsigned char **) alloca(new_lb_a * sizeof(new_lb_v[0]));
        memset(new_lb_v, 0, new_lb_a * sizeof(new_lb_v[0]));
        memcpy(new_lb_v, lb_v, lb_u * sizeof(lb_v[0]));
        lb_v = new_lb_v;
        lb_a = new_lb_a;
      }
      lb_v[lb_u] = xstrdup(b_v);
      lb_v[++lb_u] = 0;
      b_u = 0;
      b_v[0] = 0;
    }
  }
  if (ferror(f_arr[ind])) {
    fatal_CF("Input error from %s file", f_arr_names[ind]);
  }
  bb = (unsigned char**) xcalloc(lb_u + 1, sizeof(bb[0]));
  memcpy(bb, lb_v, lb_u * sizeof(bb[0]));

  if (out_lines_num) *out_lines_num = lb_u;
  if (out_lines) *out_lines = bb;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
