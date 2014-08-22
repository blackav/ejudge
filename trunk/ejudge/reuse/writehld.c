/* -*- mode: C -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/integral.h"
#include "ejudge/number_io.h"
#include "ejudge/fp_props.h"
#include "ejudge/str_utils.h"

#include <string.h>
#include <stdio.h>

extern const char _reuse_dig2charlower[];
extern const char _reuse_dig2charupper[];

#define PUT_TO_STRING(s,sz,i,v) do { if (sz > 0 && i < sz - 1) s[i]=(v); i++; } while (0)
#define LETTER(x) (digit_conv[x - 'a' + 10])

/* 80-bit long double IEEE 854 floating-point numbers */
/* FIXME: little-endian byte ordering is assumed */
int
reuse_writehld(char *str, size_t size, long double const *pval,
               int prec, int flags)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return reuse_writehd(str, size, (double const *) pval, prec, flags);
#else
#if CONF_PRINTF_LG_WORKS - 0 == 1 && CONF_PRINTF_A_WORKS - 0 == 1
  char format[32];
  int i = 0;

  format[i++] = '%';
  if ((flags & REUSE_FORMAT_PLUS)) format[i++] = '+';
  else if ((flags & REUSE_FORMAT_SPC)) format[i++] = ' ';
  if ((flags & REUSE_FORMAT_ALT)) format[i++] = '#';
  if (prec >= 0) {
    format[i++] = '.';
    format[i++] = '*';
  }
  format[i++] = 'L';
  if ((flags & REUSE_FORMAT_UP)) {
    format[i++] = 'A';
  } else {
    format[i++] = 'a';
  }
  format[i] = 0;
  if (prec >= 0) {
    return os_snprintf(str, size, format, prec, *pval);
  } else {
    return os_snprintf(str, size, format, *pval);
  }
#else
  size_t ol = 0;
  const unsigned long *pw = (const unsigned long *) pval;
  unsigned long ww[3];
  unsigned long long m;
  int d;
  int ed;
  char expbuf[32], *pexp;
  unsigned char const *digit_conv = _reuse_dig2charlower;

  if ((flags & REUSE_FORMAT_UP)) digit_conv = _reuse_dig2charupper;

  ww[0] = pw[0];
  ww[1] = pw[1];
  ww[2] = pw[2];
  ww[2] &= 0xFFFF;

  if (!ww[0] && ww[1] == 0xc0000000 && ww[2] == 0xFFFF) {
    PUT_TO_STRING(str, size, ol, LETTER('n'));
    PUT_TO_STRING(str, size, ol, LETTER('a'));
    PUT_TO_STRING(str, size, ol, LETTER('n'));
    return reuse_strnput0(str, size, ol);
  }

  if ((ww[2] & 0x8000)) {
    PUT_TO_STRING(str, size, ol, '-');
  } else if ((flags & REUSE_FORMAT_PLUS)) {
    PUT_TO_STRING(str, size, ol, '+');
  } else if ((flags & REUSE_FORMAT_SPC)) {
    PUT_TO_STRING(str, size, ol, ' ');
  }
  ww[2] &= 0x7fff;

  if (!ww[0] && !ww[1] && !ww[2]) {
    PUT_TO_STRING(str, size, ol, '0');
    PUT_TO_STRING(str, size, ol, LETTER('x'));
    PUT_TO_STRING(str, size, ol, '0');
    if (prec >= 1) {
      PUT_TO_STRING(str, size, ol, '.');
      for (; prec; prec--) {
        PUT_TO_STRING(str, size, ol, '0');
      }
    } else if ((flags & REUSE_FORMAT_ALT)) {
      PUT_TO_STRING(str, size, ol, '.');
    }
    PUT_TO_STRING(str, size, ol, LETTER('p'));
    PUT_TO_STRING(str, size, ol, '+');
    PUT_TO_STRING(str, size, ol, '0');
    return reuse_strnput0(str, size, ol);
  }
  if (!ww[0] && ww[1] == 0x80000000 && ww[2] == 0x7FFF) {
    PUT_TO_STRING(str, size, ol, LETTER('i'));
    PUT_TO_STRING(str, size, ol, LETTER('n'));
    PUT_TO_STRING(str, size, ol, LETTER('f'));
    return reuse_strnput0(str, size, ol);
  }

  if (prec < 0) prec = 15;
  PUT_TO_STRING(str, size, ol, '0');
  PUT_TO_STRING(str, size, ol, LETTER('x'));
  m = ((unsigned long long) ww[1] << 32) | ww[0];
  if (prec < 15) {
    rullong_t old_m = m;
    m += R_U64(0x0800000000000000) >> prec * 4;
    if (m < old_m) {
      PUT_TO_STRING(str, size, ol, '1');
    }
  }
  d = (m >> 60) & 0xF;
  PUT_TO_STRING(str, size, ol, digit_conv[d]);
  m <<= 4;
  if (prec > 0) {
    PUT_TO_STRING(str, size, ol, '.');
    while (prec) {
      d = (m >> 60) & 0xF;
      PUT_TO_STRING(str, size, ol, digit_conv[d]);
      m <<= 4;
      prec--;
    }
  } else if ((flags & REUSE_FORMAT_ALT)) {
    PUT_TO_STRING(str, size, ol, '.');    
  }
  ed = (int) (ww[2] & 0x7FFF) - 0x3FFF - 3;
  PUT_TO_STRING(str, size, ol, LETTER('p'));
  if (ed >= 0) {
    PUT_TO_STRING(str, size, ol, '+');
  } else if (ed < 0) {
    PUT_TO_STRING(str, size, ol, '-');
    ed = -ed;
  }
  sprintf(expbuf, "%d", ed);
  pexp = expbuf;
  while (*pexp) {
    PUT_TO_STRING(str, size, ol, *pexp);
    pexp++;
  }

  return reuse_strnput0(str, size, ol);
#endif
#endif /* R_LONG_DOUBLE_IS_DOUBLE */
}
