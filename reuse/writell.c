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
#include "ejudge/str_utils.h"

#include <string.h>

extern const char _reuse_dig2charlower[];
extern const char _reuse_dig2charupper[];

#define PUT_TO_STRING(s,sz,i,v) do { if (sz > 0 && i < sz - 1) s[i]=(v); i++; } while (0)

int
reuse_writell(char *str, size_t size, void const *pval, int base,
              int prec, int flags)
{
  int sign = 0;
  rllong_t val = *(rllong_t const*) pval;
  rullong_t uval;
  char buf1[128];
  int  b1len = 0;
  int  outlen = 0, i;
  unsigned char const *digit_conv = (const unsigned char*) _reuse_dig2charlower;

  if ((flags & REUSE_FORMAT_UP)) {
    digit_conv = (const unsigned char*) _reuse_dig2charupper;
  }

  if (!pval) return -1;
  if (base < 2 || base > 36) return -1;

  uval = val;
  if (val < 0) {
    sign = -1;
    uval = -val;
  }
  if (!uval) {
    buf1[0] = digit_conv[0];
    b1len = 1;
  } else {
    while (uval) {
      buf1[b1len++] = digit_conv[uval % base];
      uval /= base;
    }
  }

  /* output characters */
  if ((flags & REUSE_FORMAT_PLUS) && sign >= 0) {
    PUT_TO_STRING(str, size, outlen, '+');
  } else if ((flags & REUSE_FORMAT_SPC) && sign >= 0) {
    PUT_TO_STRING(str, size, outlen, ' ');
  } else if (sign < 0) {
    PUT_TO_STRING(str, size, outlen, '-');
  }
  if ((flags & REUSE_FORMAT_ALT) && base == 16) {
    PUT_TO_STRING(str, size, outlen, '0');
    PUT_TO_STRING(str, size, outlen, digit_conv[33]); /* letter 'x' or 'X' */
  } else if ((flags & REUSE_FORMAT_ALT) && base == 8) {
    if (uval) PUT_TO_STRING(str, size, outlen, '0');
  }
  if (prec > b1len) {
    for (i = b1len; i < prec; i++) {
      PUT_TO_STRING(str, size, outlen, '0');
    }
  }
  for (b1len--; b1len >= 0; b1len--) {
    PUT_TO_STRING(str,size,outlen,buf1[b1len]);
  }

  return reuse_strnput0(str, size, outlen);
}
