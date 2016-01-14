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

#define NOT_IMPLEMENTED() SWERR(("Not implemented"))

/**
 *  NAME:    os_SetLock
 *  PURPOSE: set the lockfile with the specified name
 *  ARGS:    path      - lock file path
 *           perms     - file permissions
 *           left_open - 1, if the function should return the open file
 *                       0, if the function should close the file
 *  RETURN:  >= 0 - ok, -1 - file is locked, -2 - other error
 *  NOTE:    function works reliably over NFS (Network Failure System)
 */
int
os_SetLock(char const *path, int perms, int left_open)
{
  NOT_IMPLEMENTED();
}
