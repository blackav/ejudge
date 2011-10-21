/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004-2011 Alexander Chernov <cher@ejudge.ru> */

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

#include "xml_utils.h"
#include "errlog.h"

int
xml_parse_ip(
        FILE *log_f,
        unsigned char const *path,
        int line,
        int column,
        unsigned char const *s,
        ej_ip_t *pip)
{
  unsigned int b1 = 0, b2 = 0, b3 = 0, b4 = 0;
  int n = 0;
  unsigned long ip;
  const char msg[] = "invalid IP-address";

  if (!s || sscanf(s, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || s[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
#if !defined PYTHON
    if (line > 0) {
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
    }
#endif
    return -1;
  }
  ip = b1 << 24 | b2 << 16 | b3 << 8 | b4;
  *pip = ip;
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
