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

#include <stdio.h>
#include <string.h>

extern const char _reuse_dig2charlower[];
extern const char _reuse_dig2charupper[];

#define PUT_TO_STRING(s,sz,i,v) do { if (sz > 0 && i < sz - 1) s[i]=(v); i++; } while (0)
#define LETTER(x) (digit_conv[x - 'a' + 10])

/* 32-bit IEEE 754 float value is assumed */
/* For big endian machines:
 *  31    - sign
 *  30-23 - exponent
 *  22-0  - mantissa
 */
int
reuse_writehf(char *str, size_t size, float const *pval,
              int prec, int flags)
{
  size_t ol = 0;
  unsigned long lval = *(unsigned long const *) pval;
  unsigned long e, m;
  unsigned long d;
  int ed;
  char expbuf[32], *pexp;
  unsigned char const *digit_conv = (const unsigned char*)_reuse_dig2charlower;

  if ((flags & REUSE_FORMAT_UP)) digit_conv = (const unsigned char*)_reuse_dig2charupper;
  if (lval == 0x7fc00000) {
    PUT_TO_STRING(str, size, ol, LETTER('n'));
    PUT_TO_STRING(str, size, ol, LETTER('a'));
    PUT_TO_STRING(str, size, ol, LETTER('n'));
    return reuse_strnput0(str, size, ol);
  }

  if ((lval & 0x80000000)) {
    PUT_TO_STRING(str, size, ol, '-');
  } else if ((flags & REUSE_FORMAT_PLUS)) {
    PUT_TO_STRING(str, size, ol, '+');
  } else if ((flags & REUSE_FORMAT_SPC)) {
    PUT_TO_STRING(str, size, ol, ' ');
  }
  lval &= 0x7fffffff;

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
  if (lval == 0x7f800000) {
    PUT_TO_STRING(str, size, ol, LETTER('i'));
    PUT_TO_STRING(str, size, ol, LETTER('n'));
    PUT_TO_STRING(str, size, ol, LETTER('f'));
    return reuse_strnput0(str, size, ol);
  }

  m = lval << 9;
  e = (lval >> 23) & 0xFF;
  ed = (int) e - 0x7f;

  PUT_TO_STRING(str, size, ol, '0');
  PUT_TO_STRING(str, size, ol, LETTER('x'));
  if (prec >= 0 && prec < 6) {
    m >>= 2;
    m += 0x40000000 + (0x20000000 >> prec * 4);
    d = m >> 30;
    PUT_TO_STRING(str, size, ol, digit_conv[d]);
    m <<= 2;
  } else {
    PUT_TO_STRING(str, size, ol, '1');
  }
  if (prec > 0 || (m && prec < 0)) {
    if (prec < 0) prec = 6;
    PUT_TO_STRING(str, size, ol, '.');
    while (prec) {
      d = (m & 0xF0000000) >> 28;
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
}
