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
 * NAME:    os_DirName
 * PURPOSE: return dir name from file path
 * ARGS:    argpath - path to the file
 * RETURN:  the directory component of the path
 */
char *
os_DirName(char const *str)
{
  char *path = xstrdup(str);
  char *slash = strchr(path, 0) - 1;

  /* remove trailing slashes */
  while (slash >= path && *slash == '/')
    *slash-- = 0;

  slash = strrchr (path, '/');
  if (slash == NULL)
    path = xstrdup(".");
  else
    {
      /* Remove any trailing slashes and final element. */
      while (slash > path && *slash == '/')
        --slash;
      slash[1] = 0;
    }
  return (path);
}
