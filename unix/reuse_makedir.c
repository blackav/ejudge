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

#include "ejudge/osdeps.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * NAME:    os_MakeDir
 * PURPOSE: create directory
 * ARGS:    path - path to the directory
 *          mode - directory permissions mode
 * RETURN:  <0 - error, >0 - ok, 1 - directory already exists
 */
int
os_MakeDir(char const *path, int mode)
{
  struct stat buf;
  int         r;

  if (!path) return -1;

  errno = 0;
  r = stat(path, &buf);
  if (r < 0 && errno != ENOENT) return r;
  if (r >= 0 && !S_ISDIR(buf.st_mode)) return -1;
  if (r >= 0) return 1;

  return mkdir(path, mode);
}
