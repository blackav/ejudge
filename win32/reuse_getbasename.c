/* -*- mode:c -*- */

/* Copyright (C) 2002-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

/**
 * NAME:    os_GetBasename
 * PURPOSE: get basename of the file
 * ARGS:    path - path of the file
 * RETURN:  basename of the file, allocated in the heap
 */
char *
os_GetBasename(char const *path)
{
  int   l;
  char const *s;
  char const *sp = 0;

  if (!path) return xstrdup("");
  l = strlen(path);
  s = path + l - 1;
  for (s = path + l - 1; s >= path; s--) {
    if (*s == '/' || *s == '\\') {
      s++;
      break;
    } else if (*s == '.' && !sp) {
      sp = s;
    } else if (*s == ':') {
      s++;
      break;
    }
  }
  if (s < path) {
    s = path;
  }
  if (s == sp || !sp) {
    sp = path + l;
  }

  return xmemdup(s, sp - s);
}
