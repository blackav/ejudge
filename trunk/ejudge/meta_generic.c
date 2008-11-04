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

#include "meta_generic.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <string.h>

struct meta_automaton *
meta_build_automaton(const struct meta_info_item *item, int item_num)
{
  int i, j, cur_st, c;
  unsigned char cmap[256];
  const unsigned char *s;
  unsigned char remap[256];
  struct meta_automaton *atm = 0;

  ASSERT(item);
  ASSERT(item_num);

  fprintf(stderr, "Building the automaton\n");
  memset(cmap, 0, sizeof(cmap));
  cmap[0] = 1;
  for (i = 0; i < item_num; ++i) {
    if (!item[i].tag) continue;
    s = (const unsigned char*) item[i].name;
    ASSERT(s);
    ASSERT(*s);
    for (; *s; ++s) {
      ASSERT(*s >= ' ' && *s < 127);
      cmap[*s] = 1;
    }
  }

  memset(remap, 1, sizeof(remap));
  remap[0] = 0;
  j = 2;
  for (i = ' '; i < 127; i++)
    if (cmap[i])
      remap[i] = j++;
  fprintf(stderr, "%d characters remapped\n", j);

  XCALLOC(atm, 1);
  memcpy(atm->remap, remap, sizeof(atm->remap));
  atm->char_num = j;

  atm->st_a = 16;
  XCALLOC(atm->st, atm->st_a);
  // 0 is the "no transition" indicator
  // 1 is the initial state
  XCALLOC(atm->st[1], atm->char_num);
  atm->st_u = 2;

  for (i = 0; i < item_num; ++i) {
    if (!item[i].tag) continue;
    s = (const unsigned char*) item[i].name;
    cur_st = 1;
    for (; *s; ++s) {
      c = atm->remap[*s];
      ASSERT(c > 1);
      if (atm->st[cur_st][c] > 0) {
        cur_st = atm->st[cur_st][c];
        continue;
      }

      // create a new state
      if (atm->st_u >= atm->st_a) {
        atm->st_a *= 2;
        XREALLOC(atm->st, atm->st_a);
      }
      XCALLOC(atm->st[atm->st_u], atm->char_num);
      atm->st[cur_st][c] = atm->st_u;
      cur_st = atm->st_u++;
    }
    if (atm->st[cur_st][0] < 0) {
      fprintf(stderr, "items %d and %d are the same\n", -atm->st[cur_st][0], i);
    }
    atm->st[cur_st][0] = -i;
  }
  fprintf(stderr, "The automaton has %d states\n", atm->st_u);

  /*
  fprintf(stderr, "automaton:\n");
  for (i = 1; i < atm->st_u; ++i) {
    fprintf(stderr, "%d:", i);
    for (j = 0; j < atm->char_num; ++j)
      fprintf(stderr, " %d", atm->st[i][j]);
    fprintf(stderr, "\n");
  }
  */

  return atm;
}

int
meta_lookup_string(const struct meta_automaton *atm, const char *str)
{
  const unsigned char *s = (const unsigned char *) str;
  int cur_st = 1;
  int c;

  ASSERT(atm);
  ASSERT(str);

  for (; *s; ++s) {
    if ((c = atm->remap[*s]) <= 1) return 0;
    if (!(cur_st = atm->st[cur_st][c])) return 0;
  }
  return -atm->st[cur_st][0];
}
