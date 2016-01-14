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

#include <unistd.h>
#include <errno.h>

int
os_CheckAccess(char const *path, int perms)
{
  int r_perms = 0;
  int res     = 0;

  if ((perms & REUSE_X_OK)) r_perms |= X_OK;
  if ((perms & REUSE_W_OK)) r_perms |= W_OK;
  if ((perms & REUSE_R_OK)) r_perms |= R_OK;
  if ((perms & REUSE_F_OK)) r_perms |= F_OK;

  errno = 0;
  res = access(path, r_perms);
  return (res >= 0)?res:-errno;
}
