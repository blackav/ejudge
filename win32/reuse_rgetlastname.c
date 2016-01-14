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

/**
 * NAME:    os_rGetLastname
 * PURPOSE: get the last component of the file path
 * ARGS:    path   - path of the file
 *          out    - the output buffer
 *          maxlen - size of the output buffer
 * RETURN:  strlen of the lastname
 */
int
os_rGetLastname(char const *path, char *out, int maxlen)
{
  int len, i, cpsz;

  if (!path || !out || maxlen <= 0) return 0;

  len = strlen(path);
  for (i = len - 1;
       i >= 0 && path[i] && path[i] != '/' && path[i] != '\\' && path[i] != ':';
       --i);
  i++;
  cpsz = len - i;
  if (cpsz + 1 > maxlen) cpsz = maxlen - 1;
  memcpy(out, path + i, cpsz);
  out[cpsz] = 0;
  return cpsz;
}
