/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "stringset.h"

#include <reuse/xalloc.h>

#include <string.h>

struct stringset
{
  size_t a, u;
  unsigned char **v;
};

stringset_t
stringset_new(void)
{
  stringset_t p;

  XCALLOC(p, 1);
  return p;
}

stringset_t
stringset_free(stringset_t p)
{
  size_t i;

  if (!p) return 0;
  for (i = 0; i < p->u; i++) xfree(p->v[i]);
  xfree(p->v);
  xfree(p);
  return 0;
}

size_t
stringset_size(stringset_t p)
{
  if (!p) return 0;
  return p->u;
}

void
stringset_add(stringset_t p, const unsigned char *s)
{
  size_t i;

  if (!p || !s) return;
  for (i = 0; i < p->u; i++)
    if (!strcmp(p->v[i], s))
      return;
  if (p->u == p->a) {
    if (!p->a) p->a = 16;
    else p->a *= 2;
    XREALLOC(p->v, p->a);
  }
  p->v[p->u++] = xstrdup(s);
}

void
stringset_del(stringset_t p, const unsigned char *s)
{
  size_t i, j;

  if (!p || !s) return;
  for (i = 0; i < p->u; i++)
    if (!strcmp(p->v[i], s))
      break;
  if (i == p->u) return;
  if (i + 1 == p->u) {
    xfree(p->v[i]); p->v[i] = 0;
    p->u--;
    return;
  }
  xfree(p->v[i]);
  for (j = i + 1; j < p->u; j++)
    p->v[j - 1] = p->v[j];
  p->u--;
  p->v[p->u] = 0;
}

int
stringset_check(stringset_t p, const unsigned char * s)
{
  size_t i;

  if (!p || !s) return 0;
  for (i = 0; i < p->u; i++)
    if (!strcmp(p->v[i], s))
      return 1;
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
