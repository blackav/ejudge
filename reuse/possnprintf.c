/* -*- mode:c -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/positionsp.h"
#include "ejudge/logger.h"

extern posstate_t positions_state;
#define S positions_state

  int
possnPrintf(char *str, int n, char const *format, tPosition Pos)
{
#define SNPRINTF_BUFSIZE 64
  char       *ss = str;
  int         r;
  char        fbuf[SNPRINTF_BUFSIZE];
  char       *fptr;
  int         flen;
  char const *fstr;

  ASSERT(format != NULL);
  ASSERT(n >= 0);
  ASSERT(!n || str);
  if (!S.initialized) posInitModule();

  for (; *format; format++) {
    if (*format == '%' && format[1] != '%' && format[1] != 0) {
      fstr = format + 1;
      /* copy everything up to 'l', 'c', 'f' characters */
      fptr = fbuf; flen = SNPRINTF_BUFSIZE - 2;
      *fptr++ = '%';
      while (flen > 0 
             && *fstr != 0 && *fstr != 'f' && *fstr != 'l' && *fstr != 'c') {
        *fptr++ = *fstr++;
        flen--;
      }

      if (flen >= 0) {
        switch(*fstr) {
        case 'f':
          format = fstr;
          *fptr++ = 's'; *fptr = 0;
          r=snprintf(str,n,fbuf,ssString(S.fname_table,Pos.FName));
          str += r; n -= r;
          continue;

        case 'l':
          format = fstr;
          *fptr++ = 'u'; *fptr = 0;
          r = snprintf(str, n, fbuf, Pos.Line);
          str += r; n -= r;
          continue;

        case 'c':
          format = fstr;
          *fptr++ = 'u'; *fptr = 0;
          r = snprintf(str, n, fbuf, Pos.Column + 1);
          str += r; n -= r;
          continue;

        default:;
          /* do nothing, fall through to single character print */
        }
      }
    }

    /* put regular character */
    if (n > 1) {
      *str++ = *format;
      n--;
    }
  }

  if (n >= 1) {
    *str = 0;
  }
  return str - ss;
#undef SNPRINTF_BUFSIZE
}
