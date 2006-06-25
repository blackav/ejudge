/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ispras.ru> */

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

#include <string.h>

int
xml_parse_date(unsigned char const *path, int line, int column,
               unsigned char const *s, time_t *pd)
{
  int year, month, day, hour, min, sec, n;
  time_t t;
  struct tm tt;

  memset(&tt, 0, sizeof(tt));
  tt.tm_isdst = -1;
  if (!s) goto failed;

  while (1) {
    if (sscanf(s, "%d/%d/%d %d:%d:%d%n", &year, &month, &day, &hour,
               &min, &sec, &n) == 6 && !s[n]) break;
    sec = 0;
    if (sscanf(s, "%d/%d/%d %d:%d%n", &year, &month, &day, &hour, &min, &n)
        == 5 && !s[n]) break;
    min = 0;
    if (sscanf(s, "%d/%d/%d %d%n", &year, &month, &day, &hour, &n) == 4
        && !s[n]) break;
    hour = 0;
    if (sscanf(s, "%d/%d/%d%n", &year, &month, &day, &n) == 3 && !s[n]) break;
    goto failed;
  }

  if (year < 1900 || year > 2100 || month < 1 || month > 12
      || day < 1 || day > 31 || hour < 0 || hour >= 24
      || min < 0 || min >= 60 || sec < 0 || sec >= 60) goto failed;
  tt.tm_sec = sec;
  tt.tm_min = min;
  tt.tm_hour = hour;
  tt.tm_mday = day;
  tt.tm_mon = month - 1;
  tt.tm_year = year - 1900;
  if ((t = mktime(&tt)) == (time_t) -1) goto failed;
  *pd = t;
  return 0;

 failed:
  if (path) {
    err("%s:%d:%d: invalid date", path, line, column);
  } else if (line > 0) {
    err("%d:%d: invalid date", line, column);
  }
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
