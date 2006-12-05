/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ejudge.ru> */

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
checker_normalize_file(char **lines, size_t *lines_num)
{
  int i;
  size_t len;
  unsigned char *p;

  for (i = 0; i < *lines_num; i++) {
    if (!(p = lines[i])) fatal_CF("lines[%d] is NULL!", i);
    len = strlen(p);
    while (len > 0 && isspace(p[len - 1])) p[--len] = 0;
  }

  i = *lines_num;
  while (i > 0 && !lines[i - 1][0]) {
    i--;
    free(lines[i]);
    lines[i] = 0;
  }
  *lines_num = i;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
