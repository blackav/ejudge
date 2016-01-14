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

#include <stdio.h>
#include <string.h>

char *
os_GetSuffixPtr(char const *path)
{
  char const *s;

  int   len;

  if (!path) {
    return NULL;
  }

  len = strlen(path);
  for (s = path + len - 1; s >= path; s--) {
    if (*s == '.' || *s == '/' || *s == '\\' || *s == ':') break;
  }
  if (s < path || *s == '/' || *s == '\\' || *s == ':' || s == path) {
    return NULL;
  }
  if (s[-1] == '/' || s[-1] == '\\' || s[-1] == ':') {
    return NULL;
  }

  return (char*) s;
}

/**
 * NAME:    os_rGetSuffix
 * PURPOSE: get the suffix of the file (reentrant version)
 * ARGS:    path - path of the file
 *          buf  - buffer to store suffix
 *          size - size of the buffer
 * RETURN:  length of the suffix string
 */
int
os_rGetSuffix(char const *path, char *buf, int size)
{
  char *s = os_GetSuffixPtr(path);
  if (!s) {
    buf[0] = 0;
    return 0;
  }
  strncpy(buf, s, size);
  return strlen(buf);
}
