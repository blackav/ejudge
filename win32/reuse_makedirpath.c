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

#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/xalloc.h"

#include <windows.h>
#include <ctype.h>

/*
 * NAME:    os_MakeDirPath
 * PURPOSE: make directory hierarchy
 * ARGS:    path - path to the directory to be created
 *          mode - directory mode
 * RETURN:  <0 - error, >= 0 - ok
 */
int
os_MakeDirPath(char const *path, int mode)
{
  int pathlen, j = 0;
  unsigned char *buf = 0;
  int saved_char;

  pathlen = strlen(path);
  buf = (unsigned char *) xmalloc(pathlen + 1);
  strcpy(buf, path);
  if (isalpha(buf[j]) && buf[j + 1] == ':') {
    j += 2;
  }
  if (buf[j] == '/' || buf[j] == '\\') {
    j++;
  }
  do {
    while (buf[j] && buf[j] != '/' && buf[j] != '\\') {
      ++j;
    }
    saved_char = buf[j];
    buf[j] = 0;

    if (!CreateDirectory(buf, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
      xfree(buf); buf = 0;
      return -1;
    }

    buf[j++] = saved_char;
  } while (saved_char);
  xfree(buf); buf = 0;

  return 0;
}
