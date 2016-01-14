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

#include "ejudge/xalloc.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

// supported formats
// 2008/11/15 10:05:34 (default)
// 10:05:34 2008/11/15
// 15-11-2008 10:05:34
// and their variations (missing year, time, min, sec, etc)
// no space is allowed in date and time part

enum { MIN_YEAR = 1900, MAX_YEAR = 2100 };

int
xml_parse_date(
        FILE *log_f,
        unsigned char const *path,
        int line,
        int column,
        unsigned char const *s,
        time_t *pd)
{
  int year = 0, month, day, hour, min, sec, n, slen, i1, i2, i3;
  time_t t;
  struct tm tt, *ptt = 0;
  unsigned char *buf, *w1, *w2;
  unsigned char *dw = 0, *tw = 0;
  const char msg[] = "invalid date";

  memset(&tt, 0, sizeof(tt));
  tt.tm_isdst = -1;

  if (!s) goto failed;
  if ((slen = strlen(s)) > 1024) goto failed;
  buf = (unsigned char*) alloca(slen + 1);
  memcpy(buf, s, slen + 1);
  while (slen > 0 && isspace(buf[slen - 1])) --slen;
  buf[slen] = 0;
  if (!slen) goto failed;
  if (!strcmp(buf, "0")) {
    *pd = 0;
    return 0;
  }
  w1 = (unsigned char *) alloca(slen + 1);
  w2 = (unsigned char *) alloca(slen + 1);

  // split into two words
  if (sscanf(buf, "%s%s%n", w1, w2, &n) == 2) {
    if (buf[n]) goto failed;
  } else if (sscanf(buf, "%s%n", w1, &n) == 1) {
    if (buf[n]) goto failed;
    w2 = 0;
  } else {
    goto failed;
  }

  // classify w1 and w2
  if (strchr(w1, '-') || strchr(w1, '/')) {
    // this is probably date
    dw = w1;
  } else {
    tw = w1;
  }
  if (w2) {
    if (strchr(w2, '-') || strchr(w2, '/')) {
      if (dw) goto failed;
      dw = w2;
    } else {
      if (tw) goto failed;
      tw = w2;
    }
  }

  if (!dw) {
    // take today
    t = time(0);
    ptt = localtime(&t);
    tt.tm_year = ptt->tm_year;
    tt.tm_mon = ptt->tm_mon;
    tt.tm_mday = ptt->tm_mday;
  } else {
    if (strchr(dw, '/')) {
      if (sscanf(dw, "%d/%d/%d%n", &i1, &i2, &i3, &n) == 3) {
        if (dw[n]) goto failed;
        if (i1 >= MIN_YEAR && i1 <= MAX_YEAR && i2 >= 1 && i2 <= 12
            && i3 >= 1 && i3 <= 31) {
          // YYYY/MM/DD
          year = i1;
          month = i2;
          day = i3;
        } else if (i1 >= 1 && i1 <= 31 && i2 >= 1 && i2 <= 12
                   && i3 >= MIN_YEAR && i3 <= MAX_YEAR) {
          // DD/MM/YYYY
          year = i3;
          month = i2;
          day = i1;
        } else {
          goto failed;
        }
      } else if (sscanf(dw, "%d/%d%n", &i1, &i2, &n) == 2) {
        if (dw[n]) goto failed;
        if (i1 >= 1 && i1 <= 31 && i2 >= 1 && i2 <= 12) {
          // DD/MM
          day = i1;
          month = i2;
        } else if (i1 >= 1 && i1 <= 12 && i2 >= 1 && i2 <= 31) {
          // MM/DD
          day = i2;
          month = i1;
        } else {
          goto failed;
        }
      } else {
        goto failed;
      }
    } else {
      if (sscanf(dw, "%d-%d-%d%n", &i1, &i2, &i3, &n) == 3) {
        if (dw[n]) goto failed;
        if (i1 >= MIN_YEAR && i1 <= MAX_YEAR && i2 >= 1 && i2 <= 12
            && i3 >= 1 && i3 <= 31) {
          // YYYY/MM/DD
          year = i1;
          month = i2;
          day = i3;
        } else if (i1 >= 1 && i1 <= 31 && i2 >= 1 && i2 <= 12
                   && i3 >= MIN_YEAR && i3 <= MAX_YEAR) {
          // DD/MM/YYYY
          year = i3;
          month = i2;
          day = i1;
        } else {
          goto failed;
        }
      } else if (sscanf(dw, "%d-%d%n", &i1, &i2, &n) == 2) {
        if (dw[n]) goto failed;
        if (i1 >= 1 && i1 <= 31 && i2 >= 1 && i2 <= 12) {
          // DD/MM
          day = i1;
          month = i2;
        } else if (i1 >= 1 && i1 <= 12 && i2 >= 1 && i2 <= 31) {
          // MM/DD
          day = i2;
          month = i1;
        } else {
          goto failed;
        }
      } else {
        goto failed;
      }
    }

    if (!year) {
      t = time(0);
      ptt = localtime(&t);
      year = ptt->tm_year + 1900;
    }
    tt.tm_mday = day;
    tt.tm_mon = month - 1;
    tt.tm_year = year - 1900;
  }

  if (tw) {
    if (sscanf(tw, "%d:%d:%d%n", &hour, &min, &sec, &n) == 3) {
      if (tw[n]) goto failed;
    } else if (sscanf(tw, "%d:%d%n", &hour, &min, &n) == 2) {
      if (tw[n]) goto failed;
      sec = 0;
    } else if (sscanf(tw, "%d%n", &hour, &n) == 1) {
      if (tw[n]) goto failed;
      min = 0;
      sec = 0;
    }
    if (hour < 0 || hour >= 24 || min < 0 || min >= 60
        || sec < 0 || sec >= 60) goto failed;
    tt.tm_hour = hour;
    tt.tm_min = min;
    tt.tm_sec = sec;
  }

  if ((t = mktime(&tt)) == (time_t) -1) goto failed;
  *pd = t;
  return 0;

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
