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

char *os_GetSuffixPtr(char const *path);

/**
 * NAME:    os_SubstSuffix
 * PURPOSE: replace the suffix of the path with the given new suffix
 * ARGS:    path   - path of the file
 *          suffix - new suffix
 * RETURN:  new path allocated in the heap
 */
char *
os_SubstSuffix(char const *path, char const *suffix)
{
  char *s = os_GetSuffixPtr(path);
  char *r;

  if (!s) {
    return xstrmerge2(path, suffix);
  }

  XCALLOC(r, s - path + strlen(suffix) + 1);
  memcpy(r, path, s - path);
  strcat(r, suffix);

  return r;
}
