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

#include <windows.h>
#include <limits.h>

/**
 * NAME:    os_GetWorkingDir
 * PURPOSE: Get the current working directory
 * RETURN:  the current working directory, located in the heap memory
 *          so it must be freed by xfree call
 */
char *
os_GetWorkingDir(void)
{
  char buf[PATH_MAX];

  GetCurrentDirectory(PATH_MAX, buf);
  buf[PATH_MAX - 1] = 0;
  return xstrdup(buf);
}
