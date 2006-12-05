/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "checker_internal.h"

void
checker_normalize_spaces_in_file(char **lines, size_t *lines_num)
{
  int i, j;
  int *new_ind;
  size_t len;
  unsigned char *p, *q;

  // remove trailing spaces in each line
  for (i = 0; i < *lines_num; i++) {
    if (!(p = lines[i])) fatal_CF("lines[%d] is NULL!", i);
    len = strlen(p);
    while (len > 0 && isspace(p[len - 1])) p[--len] = 0;
  }

  // remove trailing empty lines
  i = *lines_num;
  while (i > 0 && !lines[i - 1][0]) {
    i--;
    free(lines[i]);
    lines[i] = 0;
  }
  *lines_num = i;

  // remove empty lines
  XALLOCAZ(new_ind, *lines_num);
  for (i = 0, j = 0; i < *lines_num; i++) {
    if (lines[i][0]) {
      new_ind[i] = j++;
    }
  }
  for (i = 0; i < *lines_num; i++) {
    if (lines[i][0]) {
      lines[new_ind[i]] = lines[i];
    }
  }
  *lines_num = j;

  // remove spaces
  for (i = 0; i < *lines_num; i++) {
    p = lines[i];
    q = lines[i];
    while (*p && isspace(*p)) p++;
    while (*p) {
      while (*p && !isspace(*p)) *q++ = *p++;
      if (*p) {
        *q++ = ' ';
        p++;
      }
      while (*p && isspace(*p)) p++;
    }
    *q = 0;
  }
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
