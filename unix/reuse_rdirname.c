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
 * NAME:    os_rDirName
 * PURPOSE: return dir name from file path
 * ARGS:    str - path to the file
 *          out - the output buffer
 *          size - the size of the output buffer
 * RETURN:  strlen of the directory name
 */
int
os_rDirName(char const *str, char *out, int size)
{
  char const *p = str + strlen(str) - 1;
  int         l = 0;

  if (!size) return 0;
  if (size == 1) return 0;

  /* skip trailing slashes */
  for (; p >= str && *p == '/'; p--);
  /* skip the last dir component */
  for (; p >= str && *p != '/'; p--);
  if (p < str) {
    strncpy(out, ".", size);
    return 1;
  }
  /* skip the trailing slashes */
  for (; p >= str && *p == '/'; p--);
  if (p < str) {
    strncpy(out, "/", size);
    return 1;
  }
  l = p - str + 1;
  if (l > size - 1) l = size - 1;
  strncpy(out, str, l);
  out[l] = 0;
  return l;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
