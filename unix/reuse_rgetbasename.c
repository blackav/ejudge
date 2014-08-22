/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

/**
 * NAME:    os_rGetBasename
 * PURPOSE: get basename of the file
 * ARGS:    path   - path of the file
 *          out    - the output buffer
 *          maxlen - size of the output buffer
 * RETURN:  strlen of the basename
 */
int
os_rGetBasename(char const *path, char *out, int maxlen)
{
  char const *dp;
  char const *sp;
  int   l;
  int   n;
  char *p;

  if (!path || !out || maxlen <= 0) return 0;
  l  = strlen(path);
  sp = strrchr(path, '/');
  dp = strrchr(path, '.');

  if (!sp)
    sp = path;
  else
    sp++;

  if (!dp || sp >= dp) dp = path + l;
  n = maxlen - 1;
  if (n > (dp - sp)) n = dp - sp;
  for (p = out; n; p++, sp++, n--) *p = *sp;
  *p = 0;
  return strlen(out);
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
