/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "misctext.h"

#include <reuse/xalloc.h>

#include <stdlib.h>
#include <ctype.h>

void
allowed_list_parse(
        const unsigned char *str,
        unsigned char ***pv,
        size_t *pu)
{
  const unsigned char *s, *q;
  unsigned char *p;
  int i;
  size_t sz;
  unsigned char **v = 0;
  size_t u = 0;

  *pv = 0;
  *pu = 0;
  if (!str) return;

  for (s = str; *s; s++)
    if (*s == ',')
      u++;
  u++;

  XCALLOC(v, u);
  s = str;
  for (i = 0; i < u && *s;) {
    while (*s && isspace(*s)) s++;
    if (*s == ',') {
      s++;
      continue;
    }
    if (!*s) break;
    q = strchr(s, ',');
    if (!q) q = s + strlen(s);
    v[i] = p = xmemdup(s, q - s);
    sz = strlen(p);
    while (sz > 0 && isspace(p[sz - 1])) p[--sz] = 0;
    if (!sz) {
      xfree(p);
      v[i] = 0;
    } else {
      i++;
    }
    if (*s) s = q + 1;
  }
  u = i;
  if (!u) {
    xfree(v); v = 0;
  }
  *pv = v;
  *pu = u;
}

unsigned char **
allowed_list_free(unsigned char **pv, size_t u)
{
  size_t i;

  if (!pv || !u) return 0;
  for (i = 0; i < u; i++)
    xfree(pv[i]);
  xfree(pv);
  return 0;
}

void
allowed_list_map(
        const unsigned char *user_langs,
        unsigned char **pv,
        size_t pu,
        int **pmap)
{
  int *map = 0;
  unsigned char **langs = 0;
  size_t langs_u = 0;
  int i, j;

  *pmap = 0;
  if (!pv || !pu) return;
  XCALLOC(map, pu);
  *pmap = map;

  allowed_list_parse(user_langs, &langs, &langs_u);
  if (!langs || !langs_u) return;
  for (i = 0; i < pu; i++) {
    for (j = 0; j < langs_u; j++)
      if (!strcmp(pv[i], langs[j]))
        break;
    if (j < langs_u)
      map[i] = 1;
  }

  allowed_list_free(langs, langs_u);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
