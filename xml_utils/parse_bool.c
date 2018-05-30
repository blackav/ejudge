/* -*- c -*- */

/* Copyright (C) 2006-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include <string.h>

int
xml_parse_bool(
        FILE *log_f,
        unsigned char const *path,
        int line,
        int column,
        unsigned char const *str,
        int *pv)
{
  static const char msg[] = "invalid boolean value";

  if (!str) goto failed;
  if (!strcasecmp(str, "true")
      || !strcasecmp(str, "yes")
      || !strcasecmp(str, "1")) {
    if (pv) *pv = 1;
    return 1;
  }

  if (!strcasecmp(str, "false")
      || !strcasecmp(str, "no")
      || !strcasecmp(str, "0")) {
    if (pv) *pv = 0;
    return 0;
  }

 failed:
  if (log_f) {
    if (path) {
      fprintf(log_f, "%s:%d:%d: %s\n", path, line, column, msg);
    } else if (line > 0) {
      fprintf(log_f, "%d:%d: %s\n", line, column, msg);
    }
  } else {
    if (path) {
      err("%s:%d:%d: %s", path, line, column, msg);
    } else if (line > 0) {
      err("%d:%d: %s", line, column, msg);
    }
  }
  return -1;
}
