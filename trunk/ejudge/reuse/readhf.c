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

/* if endptr == 0, we don't care about string termination */
/* if endptr == (char**) 1, string must end at the last character */
/* inf, -inf, nan literal values are supported */
/* returns:
 *  0  - ok,
 *  -1 - format error,
 *  1  - overflow ([-]INFINITY returned)
 *  2  - loss of precision ([-]0 returned)
 */
int
reuse_readhf(char const *str, char **endptr, float *pval)
{
  int is_neg = 0;
  int is_exp_neg = 0;
  int d;
  unsigned long im = 0;         /* integral part of mantissa */
  unsigned long fm = 0;         /* fractional part of mantissa */
  long exp = 0;
  int shift_val = 28;
  unsigned long lval = 0;
  int ret_val = 0;
  long exp_add = 0;

  if (!str) goto _format_error;
  while (isspace(*str)) str++;
  if (!*str) goto _format_error;
  if ((*str == 'n' || *str == 'N')
      && str[1] && (str[1] == 'a' || str[1] == 'A')
      && str[2] && (str[2] == 'n' || str[2] == 'N')) {
    lval = 0x7fc00000;
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
    lval = 0x7f800000;
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
  if (d && d != 1) {
    if (d >= 8) {
      fm = (unsigned long) d << 29;
      exp_add += 3;
      shift_val -= 3;
    } else if (d >= 4) {
      fm = (unsigned long) d << 30;
      exp_add += 2;
      shift_val -= 2;
    } else if (d >= 2) {
      fm = (unsigned long) d << 31;
      exp_add += 1;
      shift_val -= 1;
    }
    d = 1;
  }
  im |= d;
  while (1) {
    d = _reuse_letter_to_digit_table[*(unsigned char const *) str];
    if (d < 0 || d >= 16) break;
    str++;
    if (im) {
      if (shift_val >= 0) fm |= d << shift_val;
      else if (shift_val > -4) fm |= d >> -shift_val;
      exp_add += 4;
      shift_val -= 4;
    } else if (!im && d > 0) {
      if (d >= 8) {
        fm = (unsigned long) d << 29;
        exp_add += 3;
        shift_val -= 3;
      } else if (d >= 4) {
        fm = (unsigned long) d << 30;
        exp_add += 2;
        shift_val -= 2;
      } else if (d >= 2) {
        fm = (unsigned long) d << 31;
        exp_add += 1;
        shift_val -= 1;
      }
      im = 1;
    }
  }
  if (*str == '.') {
    str++;
    while (1) {
      d = _reuse_letter_to_digit_table[*(unsigned char const *) str];
      if (d < 0 || d >= 16) break;
      str++;
      if (im) {
        if (shift_val >= 0) fm |= d << shift_val;
        else if (shift_val > -4) fm |= d >> -shift_val;
        shift_val -= 4;
      } else if (!im && d > 0) {
        if (d >= 8) {
          fm = (unsigned long) d << 29;
          exp_add -= 1;
          shift_val -= 3;
        } else if (d >= 4) {
          fm = (unsigned long) d << 30;
          exp_add -= 2;
          shift_val -= 2;
        } else if (d >= 2) {
          fm = (unsigned long) d << 31;
          exp_add -= 3;
          shift_val -= 1;
        } else {
          exp_add -= 4;
        }
        im = 1;
      } else if (!im) {
        exp_add -= 4;
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

  if (!im && !fm) {
    lval = 0;
    goto _normal_exit;
  }
  if (im != 1) goto _format_error;

  exp += 0x7F + exp_add;
  if (exp < 0) {
    /* underflow */
    lval = 0;
    ret_val = 2;
    goto _normal_exit;
  }
  if (exp > 0xFF) {
    /* overflow */
    lval = 0x7f800000;
    ret_val = 1;
    goto _normal_exit;
  }

  lval = fm >> 9;
  lval |= exp << 23;

 _normal_exit:
  if (is_neg) lval |= 0x80000000;
  memmove(pval, &lval, 4);
  if (endptr && endptr != (char**) 1) *endptr = (char*) str;
  return ret_val;

 _format_error:
  if (pval) *pval = 0.0f;
  if (endptr && endptr != (char**) 1) *endptr = (char*) str;
  return -1;
}
