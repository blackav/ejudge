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

#define EXTBUFSIZE 32
static char extbuf[EXTBUFSIZE];

/**
 * NAME:    os_GetSuffix
 * PURPOSE: get file suffix
 * ARGS:    path - path of the file
 * RETURN:  file suffix in the static location
 */
char *
os_GetSuffix(char const *path)
{
  os_rGetSuffix(path, extbuf, EXTBUFSIZE);
  return extbuf;
}
