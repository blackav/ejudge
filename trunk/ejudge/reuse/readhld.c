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

#include <string.h>
#include <ctype.h>

extern const signed char _reuse_letter_to_digit_table[];

int
reuse_readhld(char const *str, char **endptr, long double *pval)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return reuse_readhd(str, endptr, (double*) pval);
#else
  unsigned long long mant = 0;
  unsigned long w3 = 0;
  int ret_val = 0;
  int is_neg = 0, is_exp_neg = 0;
  int exp_add = 0;
  int shift_val = 60;
  int nz = 0;
  int d;
  long exp;

  if (!str) goto _format_error;
  while (isspace(*str)) str++;
  if (!*str) goto _format_error;
  if ((*str == 'n' || *str == 'N')
      && str[1] && (str[1] == 'a' || str[1] == 'A')
      && str[2] && (str[2] == 'n' || str[2] == 'N')) {
    mant = 0xc000000000000000LL;
    w3 = 0xFFFF;
    str += 3;
    goto _normal_exit;
  }
  if (*str == '+') {
    str++;
  } else if (*str == '-') {
    is_neg = 1;
    str++;
  }
  if ((*str == 'i' || *str == 'I')
      && str[1] && (str[1] == 'n' || str[1] == 'N')
      && str[2] && (str[2] == 'f' || str[2] == 'F')) {
    mant = 0x8000000000000000LL;
    w3 = 0x7fff;
    str += 3;
    goto _normal_exit;
  }
  if (*str != '0') goto _format_error;
  str++;
  if (*str != 'X' && *str != 'x') goto _format_error;
  str++;

  d = _reuse_letter_to_digit_table[*(unsigned char const*) str];
  if (d < 0 || d >= 16) goto _format_error;
  str++;
  while (1) {
    if (nz) {
      exp_add += 4;
      if (shift_val >= 0) mant |= (unsigned long long) d << shift_val;
      else if (shift_val > -4) mant |= (unsigned long long) d >> -shift_val;
      shift_val -= 4;
    } else if (d > 0) {
      if (d >= 8) {
        mant |= (unsigned long long) d << 60;
        shift_val = 56;
        exp_add = 3;
      } else if (d >= 4) {
        mant |= (unsigned long long) d << 61;
        shift_val = 57;
        exp_add = 2;
      } else if (d >= 2) {
        mant |= (unsigned long long) d << 62;
        shift_val = 58;
        exp_add = 1;
      } else {
        mant |= (unsigned long long) d << 63;
        shift_val = 59;
        exp_add = 0;
      }
      nz = 1;
    }
    d = _reuse_letter_to_digit_table[*(unsigned char const*) str];
    if (d < 0 || d >= 16) break;
    str++;
  }

  if (*str == '.') {
    str++;
    while (1) {
      d = _reuse_letter_to_digit_table[*(unsigned char const *) str];
      if (d < 0 || d >= 16) break;
      str++;
      if (nz) {
        if (shift_val >= 0) mant |= (unsigned long long) d << shift_val;
        else if (shift_val > -4) mant |= (unsigned long long) d >> -shift_val;
        shift_val -= 4;
      } else if (!d) {
        exp_add -= 4;
      } else {
        if (d >= 8) {
          mant |= (unsigned long long) d << 60;
          shift_val = 56;
          exp_add -= 1;
        } else if (d >= 4) {
          mant |= (unsigned long long) d << 61;
          shift_val = 57;
          exp_add -= 2;
        } else if (d >= 2) {
          mant |= (unsigned long long) d << 62;
          shift_val = 58;
          exp_add -= 3;
        } else {
          mant |= (unsigned long long) d << 63;
          shift_val = 59;
          exp_add -= 4;
        }
        nz = 1;
      }
    }
  }

  if (*str != 'p' && *str != 'P') goto _format_error;
  str++;
  if (*str == '+') {
    str++;
  } else if (*str == '-') {
    is_exp_neg = 1;
    str++;
  }
  d = _reuse_letter_to_digit_table[*(unsigned char const *) str];
  if (d < 0 || d >= 10) goto _format_error;
  exp = d;
  str++;
  while (1) {
    d = _reuse_letter_to_digit_table[*(unsigned char const *) str];
    if (d < 0 || d >= 10) break;
    str++;
    if (exp < 100000) exp = exp * 10 + d;
  }
  if (*str && endptr == (char**) 1) goto _format_error;
  if (is_exp_neg) exp = -exp;

  if (!mant) {
    w3 = 0;
    goto _normal_exit;
  }
  exp += 0x3FFF + exp_add;
  if (exp < 0) {
    /* underflow */
    w3 = 0;
    mant = 0;
    ret_val = 2;
    goto _normal_exit;
  }
  if (exp > 0x7FFF) {
    /* overflow */
    mant = 0x8000000000000000LL;
    w3 = 0x7fff;
    ret_val = 1;
    goto _normal_exit;
  }

  w3 = exp;

 _normal_exit:
  if (is_neg) w3 |= 0x8000;
  memmove(pval, &mant, 8);
  memmove((char*) pval + 8, &w3, 2);
  if (endptr && endptr != (char**) 1) *endptr = (char*) str;
  return ret_val;

 _format_error:
  if (pval) *pval = 0.0L;
  if (endptr && endptr != (char**) 1) *endptr = (char*) str;
  return -1;
#endif /* R_LONG_DOUBLE_IS_DOUBLE */
}
