/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

static unsigned char *
read_atom(FILE *f)
{
  int c;
  unsigned char *buf = 0, *tmp;
  size_t buf_a = 0, buf_u = 0;

  c = getc(f);
  while (c != EOF && c <= ' ') c = getc(f);

  buf_a = 128;
  buf = alloca(buf_a);

  while (c != EOF && c != ')' && c != '(' && c > ' ') {
    if (buf_u + 1 >= buf_a) {
      buf_a *= 2;
      tmp = alloca(buf_a);
      memcpy(tmp, buf, buf_u);
      buf = tmp;
    }
    buf[buf_u++] = c;
    c = getc(f);
  }
  buf[buf_u] = 0;
  if (c != EOF) ungetc(c, f);
  return xstrdup(buf);
}

checker_sexpr_t
checker_read_sexpr(int ind)
{
  int c;
  checker_sexpr_t cur = 0, *plast = &cur, p, q;

  c = getc_unlocked(f_arr[ind]);
  while (c != EOF && c <= ' ') c = getc_unlocked(f_arr[ind]);

  if (c == '(') {
    while (1) {
      c = getc(f_arr[ind]);
      while (c != EOF && c <= ' ') c = getc(f_arr[ind]);
      if (c == EOF) {
        if (ind == 2) fatal_CF("Unexpected EOF");
        fatal_PE("Unexpected EOF");
      }
      if (c == ')') break;
      ungetc(c, f_arr[ind]);
      q = checker_read_sexpr(ind);
      p = xcalloc(1, sizeof(*p));
      p->p.kind = CHECKER_SEXPR_PAIR;
      p->p.head = q;
      *plast = p;
      plast = &p->p.tail;
    }
    return cur;
  }

  if (c == EOF) {
    if (ind == 2) fatal_CF("Unexpected EOF");
    fatal_PE("Unexpected EOF");
  }
  ungetc(c, f_arr[ind]);
  p = xcalloc(1, sizeof(*p));
  p->a.kind = CHECKER_SEXPR_ATOM;
  p->a.value = read_atom(f_arr[ind]);
  return p;
}
