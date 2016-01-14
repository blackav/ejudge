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

#include <string.h>

/**
 * NAME:    os_GetBasename
 * PURPOSE: get basename of the file
 * ARGS:    path - path of the file
 * RETURN:  basename of the file, allocated in the heap
 */
char *
os_GetBasename(char const *path)
{
  char const *dp, *sp;
  int   l;

  if (!path) return xstrdup("");

  l  = strlen(path);
  sp = strrchr(path, '/');
  dp = strrchr(path, '.');

  if (!sp)
    sp = path;
  else
    sp++;

  if (!dp || sp >= dp) dp = path + l;

  return xmemdup(sp, dp - sp);
}
