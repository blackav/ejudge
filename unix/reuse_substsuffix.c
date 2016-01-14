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
 * NAME:    os_SubstSuffix
 * PURPOSE: replace the suffix of the path with the given new suffix
 * ARGS:    path   - path of the file
 *          suffix - new suffix
 * RETURN:  new path allocated in the heap
 */
  char *
os_SubstSuffix(char const *path, char const *suffix)
{
  char *dp;
  char *sp;
  char *r;

  if (path == NULL)
    return NULL;

  sp = strrchr(path, '/');
  dp = strrchr(path, '.');

  if (dp == NULL || (sp != NULL && sp > dp))
    {
      return xstrmerge2(path, suffix);
    }

  r = xstrdup(path);
  r[dp - path] = 0;
  return xstrmerge1(r, suffix);
}
