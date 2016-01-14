/* -*- c -*- */

/* Copyright (C) 2004-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xml_utils.h"
#include "ejudge/errlog.h"

int
xml_parse_int(
        FILE *log_f,
        unsigned char const *path,
        int line,
        int column,
        unsigned char const *str,
        int *pval)
{
  int x = 0, n = 0;
  const char msg[] = "cannot parse integer value";

  if (!str || sscanf(str, "%d %n", &x, &n) != 1 || str[n]) {
    if (log_f) {
      if (path) {
        fprintf(log_f, "%s:%d:%d: %s\n", path, line, column, msg);
      } else {
        fprintf(log_f, "%d:%d: %s\n", line, column, msg);
      }
    } else {
      if (path) {
        err("%s:%d:%d: %s", path, line, column, msg);
      } else {
        err("%d:%d: %s", line, column, msg);
      }
    }
    return -1;
  }
  *pval = x;
  return 0;
}
