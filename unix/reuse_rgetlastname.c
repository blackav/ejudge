/* -*- mode:c -*- */

/* Copyright (C) 2004-2016 Alexander Chernov <cher@ejudge.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "ejudge/osdeps.h"

#include <string.h>

int
os_rGetLastname(char const *path, char *out, int maxlen)
{
  char const *dp;
  char const *sp;
  int   l;
  int   n;
  char *p;

  if (!path || !out || maxlen <= 0) return 0;
  l  = strlen(path);
  sp = strrchr(path, '/');

  if (!sp)
    sp = path;
  else
    sp++;

  dp = path + l;
  n = maxlen - 1;
  if (n > (dp - sp)) n = dp - sp;
  for (p = out; n; p++, sp++, n--) *p = *sp;
  *p = 0;
  return strlen(out);
}
