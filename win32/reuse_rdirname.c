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
 * NAME:    os_rDirName
 * PURPOSE: return dir name from file path
 * ARGS:    str - path to the file
 *          out - the output buffer
 *          size - the size of the output buffer
 * RETURN:  strlen of the directory name
 */
int
os_rDirName(char const *str, char *out, int size)
{
  NOT_IMPLEMENTED();
}
