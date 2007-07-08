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

#include "csv.h"

#include <reuse/xalloc.h>

#include <string.h>
#include <ctype.h>

struct csv_file *
csv_parse(const char *str, FILE *log_f, int fs)
{
  struct csv_file *p = 0;
  const unsigned char *s1 = (const unsigned char*) str, *s2, *s3;
  unsigned char *s4;
  struct csv_line *pp;

  XCALLOC(p, 1);

  while (1) {
    s2 = s1;
    while (*s2 && *s2 != '\n' && *s2 != fs) s2++;
    if (*s2 == '\n') {
      s3 = s2;
      while (s3 > s1 && isspace(s3[-1])) s3--;
    } else {
      s3 = s2;
    }
    if (s3 == (const unsigned char*) str) break;  /* empty file */
    s4 = (unsigned char*) xmalloc(s3 - s1 + 1);
    memcpy(s4, s1, s3 - s1);
    s4[s3 - s1] = 0;
    if (*s2) s1 = s2 + 1;

    if (p->u >= p->a) {
      if (!p->a) {
        p->a = 16;
        XCALLOC(p->v, p->a);
      } else {
        XREALLOC(p->v, p->a * 2);
        memset(p->v + p->a, 0, sizeof(p->v[0]) * p->a);
        p->a *= 2;
      }
    }
    pp = p->v + p->u;
    if (pp->u >= pp->a) {
      if (!pp->a) {
        pp->a = 16;
        XCALLOC(pp->v, pp->a);
      } else {
        XREALLOC(pp->v, pp->a * 2);
        memset(pp->v + pp->a, 0, sizeof(pp->v[0]) * pp->a);
        pp->a *= 2;
      }
    }
    pp->v[pp->u++] = s4;
    if (!*s2 || *s2 == '\n') p->u++;
    if (!*s2) break;
  }

  // strip off the last lines
  while (p->u > 0 && p->v[p->u - 1].u == 1 && !*p->v[p->u - 1].v[0]) {
    p->u--;
    xfree(p->v[p->u].v[0]); p->v[p->u].v[0] = 0;
    xfree(p->v[p->u].v); p->v[p->u].v = 0;
    p->v[p->u].u = p->v[p->u].a = 0;
  }

  if (!p->u) {
    // empty file
    xfree(p->v);
    xfree(p);
    p = 0;
  }

  return p;
}

struct csv_file *
csv_free(struct csv_file *p)
{
  size_t i, j;

  if (!p) return 0;
  for (i = 0; i < p->u; i++) {
    for (j = 0; j < p->v[i].u; j++)
      xfree(p->v[i].v[j]);
    xfree(p->v[i].v);
  }
  xfree(p->v);
  memset(p, 0, sizeof(*p));
  xfree(p);
  return 0;
}
