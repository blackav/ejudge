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

#include <windows.h>

/**
 * NAME:    os_FindInPath
 * PURPOSE: find the given executable in the PATH
 * ARGS:    name - name of the executable
 * RETURN:  full path to the file, or NULL if file not found
 */
char *
os_FindInPath(char const *name)
{
  char buf1[1024];
  char *buf = buf1, *pext = 0;
  unsigned len = sizeof(buf1), new_len;

  new_len = SearchPath(NULL, name, NULL, len, buf, &pext);
  if (!new_len) return NULL;
  if (new_len < len) return xstrdup(buf);
  buf = 0;
  while (1) {
    len = (new_len + 16) & ~0xF;
    xfree(buf);
    buf = (char*) xmalloc(len);
    new_len = SearchPath(NULL, name, NULL, len, buf, &pext);
    if (!new_len) return NULL;
    if (new_len < len) return buf;
  }
}
