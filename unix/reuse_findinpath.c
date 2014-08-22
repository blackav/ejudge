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

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * NAME:    os_FindInPath
 * PURPOSE: find the given executable in the PATH
 * ARGS:    name - name of the executable
 * RETURN:  full path to the file, or NULL if file not found
 */
char *
os_FindInPath(char const *name)
{
  char *path;
  int   trsize = 2048;
  char  trbuf[2048];
  char *s, *p;
  int   len;
  int   nlen;
  struct stat buf;

  if (name == NULL || *name == 0)
    return NULL;
  if ((path = getenv("PATH")) == NULL)
    return NULL;

  s = path;
  p = s;
  nlen = strlen(name);
  for (;*p != 0;s = p + 1)
    {
      p = strchr(s, ':');
      if (p == NULL)
        p = strchr(s, 0);
      if ((len = p - s) >= trsize - 2)
        {
          /* buffer is too small */
          continue;
        }
      memcpy(trbuf, s, len);
      trbuf[len++] = '/';
      trbuf[len] = 0;
      if (len + nlen >= trsize - 1)
        {
          /* buffer is too small */
          continue;
        }
      strcat(trbuf, name);

      if (stat(trbuf, &buf) < 0)
        {
          /* file not found */
          continue;
        }
      if (!S_ISREG(buf.st_mode))
        {
          /* not a regular file */
          continue;
        }
      if (!(buf.st_mode & 0111))
        {
          /* not an executable */
          continue;
        }

      /* found */
      return xstrdup(trbuf);
    }
  return NULL;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
