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

#include <io.h>

int
os_access(char const *s, int mode)
{
#ifdef _MSC_VER
  extern int _access(const char *, int);
  return _access(s, mode);
#else
  return access(s, mode);
#endif /* _MSC_VER */
}

int
os_CheckAccess(char const *path, int perms)
{
  int lflags = 0;

  //fprintf(stderr, "CheckAccess: %s\n", path);

  if ((perms & REUSE_R_OK)) {
    lflags |= 4;
  }
  if ((perms & REUSE_W_OK)) {
    lflags |= 2;
  }
  if (os_access(path, perms) < 0) {
    /* FIXME: analyze errno? */
    //fprintf(stderr, "access failed: %d\n", errno);
    return -1;
  }

  /*
  // FIXME: this does not work for batch scripts on Win2k

  if ((perms & REUSE_X_OK)) {
    DWORD exetype;
    int   err;

    if (!GetBinaryType(path, &exetype)) {
      err = GetLastError();
      if (err != ERROR_CALL_NOT_IMPLEMENTED) {
	//fprintf(stderr, "GetBinaryType failed: %d\n", GetLastError());
	return -1;
      }
    }
  }
  */

  return 0;
}
