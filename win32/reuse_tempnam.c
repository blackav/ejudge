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

#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>

char *
os_tempnam(char const *dir, char const *pfx)
{
  char        buf[PATH_MAX];
  char        dirbuf[PATH_MAX];
  char const *pdir = dir;

  if (!dir) {
    GetTempPath(PATH_MAX, dirbuf);
    dirbuf[PATH_MAX - 1] = 0;
    pdir = dirbuf;
  }

  GetTempFileName(pdir, pfx, 0, buf);
  return xstrdup(buf);
}
