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

int
reuse_writehd(char *str, size_t size, double const *pval,
              int prec, int flags)
{
#if defined CONF_PRINTF_A_WORKS && CONF_PRINTF_A_WORKS - 0 == 1
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
  rullong_t lval = *(rullong_t const *) pval;
  rullong_t e, m;
  rullong_t d;
  int ed;
  char expbuf[32], *pexp;
  unsigned char const *digit_conv = _reuse_dig2charlower;

  if ((flags & REUSE_FORMAT_UP)) digit_conv = _reuse_dig2charupper;

  if (lval == R_I64(0x7ff8000000000000)) {
    pexp = "nan";
    if ((flags & REUSE_FORMAT_UP)) pexp = "NAN";
    return reuse_strncatx(str, size, 0, pexp);
  }

  if ((lval & R_I64(0x8000000000000000))) {
    PUT_TO_STRING(str, size, ol, '-');
  } else if ((flags & REUSE_FORMAT_PLUS)) {
    PUT_TO_STRING(str, size, ol, '+');
  } else if ((flags & REUSE_FORMAT_SPC)) {
    PUT_TO_STRING(str, size, ol, ' ');
  }
  lval &= R_I64(0x7fffffffffffffff);

  if (!lval) {
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
  if (lval == R_I64(0x7ff0000000000000)) {
    PUT_TO_STRING(str, size, ol, LETTER('i'));
    PUT_TO_STRING(str, size, ol, LETTER('n'));
    PUT_TO_STRING(str, size, ol, LETTER('f'));
    return reuse_strnput0(str, size, ol);
  }

  m = lval << 12;
  e = (lval >> 52) & 0x7FF;
  ed = (int) e - 0x3ff;

  PUT_TO_STRING(str, size, ol, '0');
  PUT_TO_STRING(str, size, ol, LETTER('x'));
  if (prec >= 0 && prec < 13) {
    m >>= 2;
    m += R_I64(0x4000000000000000) + (R_I64(0x2000000000000000) >> prec * 4);
    d = m >> 62;
    PUT_TO_STRING(str, size, ol, digit_conv[d]);
    m <<= 2;
  } else {
    PUT_TO_STRING(str, size, ol, '1');
  }
  if (prec > 0 || (m && prec < 0)) {
    if (prec < 0) prec = 13;
    PUT_TO_STRING(str, size, ol, '.');
    while (prec) {
      d = (m & R_U64(0xF000000000000000)) >> 60;
      PUT_TO_STRING(str, size, ol, digit_conv[d]);
      m <<= 4;
      prec--;
    }
  } else if ((flags & REUSE_FORMAT_ALT)) {
    PUT_TO_STRING(str, size, ol, '.');
  }
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
}
