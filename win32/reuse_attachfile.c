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

#include <string.h>
#include <stdio.h>
#include <fcntl.h>

#ifdef _MSC_VER
_CRTIMP int __cdecl _open_osfhandle(long, int);
_CRTIMP FILE * __cdecl _fdopen(int, const char *);
#endif

void *
os_AttachFILE(int handle, char const *mode)
{
  int   fmode = 0;
  int   fd    = 0;
  FILE *f;

  if (!strcmp(mode, "r")) {
    fmode |= O_RDONLY;
  } else {
    SWERR(("os_AttachFILE: bad mode: %s", mode));
  }
  fd = _open_osfhandle(handle, fmode);
  if (fd < 0) {
    write_log(LOG_REUSE, LOG_ERROR,
	      "os_AttachFILE: _open_osfhandle(%u, %u) failed",
	      (unsigned int) handle, (unsigned int) fmode);
    return NULL;
  }
  write_log(LOG_REUSE, LOG_DEBUG, "os_AttachFILE: fd = %d", fd);
  f = _fdopen(fd, mode);
  if (!f) {
    write_log(LOG_REUSE, LOG_DEBUG, "_fdopen failed");
    return NULL;
  }
  return f;
}
