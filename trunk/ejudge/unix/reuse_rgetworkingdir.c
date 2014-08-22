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

#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>

/**
 * NAME:    os_rGetWorkingDir
 * PURPOSE: Get the current working directory
 *          path       - the buffer to store the path
 *          maxlen     - the size of the buffer
 *          abort_flag - if 1, failure of getcwd function will
 *                       lead to runtime error (abort)
 * RETURN:  strlen of the current working directory path
 */
int
os_rGetWorkingDir(char *path, unsigned int maxlen, int abort_flag)
{
  errno = 0;
  if (!getcwd(path, maxlen)) {
    if (errno == ERANGE && abort_flag) {
      SWERR(("os_rGetWorkingDir: buffer is too small (size = %d)", maxlen));
    }
    return -1;
  }
  return strlen(path);
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
