/* $Id$ */

/* Copyright (C) 1998-2014 Alexander Chernov <cher@ejudge.ru> */
/* Created: <1998-04-22 22:11:30 cher> */

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

/**
 * FILE:    utils/xfile.c
 * PURPOSE: safer file open/close interface
 */

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/xfile.h"
#include "ejudge/logger.h"
#include "ejudge/errors.h"
#include "ejudge/osdeps.h"
#include "ejudge/getopt.h"

#include <errno.h>
#include <unistd.h>
#include <string.h>

/**
 * NAME:    xfopen
 * PURPOSE: wrapper over fopen function
 * NOTE:    if path is NULL, "", "-" - either stdout or stdin is
 *            duplicated depending on file opening mode:
 *            "r" - stdin
 *            "w", "a" - stdout
 *          if path is "/dev/stdin" - stdin is duplicated
 *          if path is "/dev/stdout" - stdout is duplicated
 *          if path is "/dev/stderr" - stderr is duplicated
 */
  FILE *
xfopen(char *path, char *mode)
{
  int   fd = 100000;
  char *s  = mode;
  FILE *f  = 0;

  ASSERT(mode);

  if (*s == 'b' || *s == 't') s++;
  if (!path || !*path || !strcmp(path, "-"))
    {
      switch (*s)
        {
        case 'r': fd = dup(0); break;
        case 'w': fd = dup(1); break;
        case 'a': fd = dup(1); break;
        default:
          SWERR(("Invalid mode '%s'", mode));
        }
    }
  else if (!strcmp(path, "/dev/stdin"))  fd = dup(0);
  else if (!strcmp(path, "/dev/stdout")) fd = dup(1);
  else if (!strcmp(path, "/dev/stderr")) fd = dup(2);

  if (fd < 0)
    err_Startup("dup() failed: %s", os_ErrorString());
  else if (fd != 100000 && !(f = fdopen(fd, mode)))
    err_Startup("fdopen() failed: %s", os_ErrorString());
  else if (fd == 100000 && !(f = fopen(path, mode)))
    err_Startup("cannot open file '%s': %s", path, os_ErrorString());

  return f;
}

/**
 * NAME:    xferror
 * PURPOSE: wrapper over ferror function
 * NOTE:    if error condition is true, error message is printed
 *          by err_Startup
 */
  int
xferror(FILE *f)
{
  ASSERT(f);

  if (ferror(f))
    {
      err_Startup("I/O error: %s", os_ErrorString());
      clearerr(f);
      errno = 0;
      return 1;
    }
  return 0;
}

/**
 * NAME:    xfclose
 * PURPOSE: wrapper over fclose function
 */
  int
xfclose(FILE *f)
{
  if (!f) return 0;

  clearerr(f);
  if (fclose(f) < 0)
    {
      err_Startup("cannot close file: %s", os_ErrorString());
      return -1;
    }
  return 0;
}

int
reuse_set_binary_stderr(void)
{
  return 0;
}

int
reuse_set_binary_stdout(void)
{
  return 0;
}
