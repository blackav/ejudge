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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * NAME:    os_IsFile
 * PURPOSE: check whether the object given by the path is file
 * ARGS:    path - path to the object
 * RETURN:  <0 - error,
 *          OSPK_REG    - regular file
 *          OSPK_DIR    - directory
 *          OSPK_OBJECT - other object
 */
  int
os_IsFile(char const *path)
{
  struct stat buf;

  if (!path) return -1;

  if (stat(path, &buf) < 0)
    {
      /* file does not exist */
      return -1;
    }

  if (S_ISREG(buf.st_mode))
    return OSPK_REG;
  if (S_ISDIR(buf.st_mode))
    return OSPK_DIR;
  return OSPK_OTHER;
}
