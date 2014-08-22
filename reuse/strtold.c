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
//#include "reuse_str_utils.h"

#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#if CONF_HAS_STRTOLD - 0 == 1
long double strtold();
#endif /* strtold is present */

extern const signed char _reuse_letter_to_digit_table[];

#if R_LONG_DOUBLE_IS_DOUBLE - 0 != 1
#if !defined CONF_HAS_STRTOLD || CONF_HAS_STRTOLD - 0 != 1
static long double
get10pow(int i_exp)
{
  long double pp = 1.0L;
  if (i_exp >= 0) {
    while (i_exp && !reuse_is_infinity_ld(&pp)) {
      i_exp--;
      pp *= 10.0L;
    }
    if (i_exp) errno = ERANGE;
  } else {
    while (i_exp && pp != 0.0L) {
      i_exp++;
      pp *= 0.1L;
    }
    if (i_exp) errno = ERANGE;
  }
  return pp;
}
static long double
do_strtold(char const *str, char **endptr)
{
  long double val = 0.0L;
  long double mant = 0.0L;
  long double ld_exp = 1.0L;
  long double frac_mult = 1.0L;
  unsigned char const *p = (unsigned char const *) str;
  int msign = 0;
  int esign = 0;
  int is_zero = 1;
  int i_exp = 0;
  int exp_shift = 0;
  int digits = 0;

  errno = 0;
  if (!str) {
    errno = EINVAL;
    goto _exit;
  }
  while (isspace(*p)) p++;
  if (!strncasecmp(p, "NAN", 3)) {
    /* FIXME: should skip (...) part of NAN */
    p += 3;
    reuse_set_nan_ld(&val);
    goto _exit;
  }
  if (*p == '-') {
    msign = -1;
    p++;
  } else if (*p == '+') {
    msign = +1;
    p++;
  }
  if (!strncasecmp(p, "INFINITY", 8)) {
    p += 8;
    reuse_set_infinity_ld(msign, &val);
    goto _exit;
  }
  if (!strncasecmp(p, "INF", 3)) {
    p += 3;
    reuse_set_infinity_ld(msign, &val);
    goto _exit;
  }
  if (!isdigit(*p) && *p != '.') {
    reuse_set_zero_ld(msign, &val);
    goto _exit;
  }
  if (isdigit(*p)) {
    while (*p == '0') p++;
    digits = 0;
    if (isdigit(*p)) is_zero = 0;
    while (isdigit(*p) && digits < 25) {
      mant = mant * 10.0L + _reuse_letter_to_digit_table[*p];
      digits++;
      p++;
    }
    while (isdigit(*p) && exp_shift < 100000) {
      exp_shift++;
      p++;
    }
    if (exp_shift >= 100000) {
      errno = ERANGE;
      reuse_set_infinity_ld(msign, &val);
      goto _skip_mantissa_integral;
    }
  }
  if (*p == '.') {
    p++;
    if (is_zero) {
      while (*p == '0' && exp_shift > -100000) {
        exp_shift--;
        p++;
      }
      if (exp_shift <= -100000) {
        errno = ERANGE;
        reuse_set_zero_ld(msign, &val);
        goto _skip_mantissa_fractional;
      }
    }
    if (isdigit(*p)) is_zero = 0;
    digits = 0;
    while (isdigit(*p) && digits < 25) {
      frac_mult *= 0.1L;
      mant += _reuse_letter_to_digit_table[*p] * frac_mult;
      p++;
      digits++;
    }
    while (isdigit(*p)) p++;
  }
  if (is_zero) {
    reuse_set_zero_ld(msign, &val);
    goto _skip_exponent;
  }
  if (*p == 'e' || *p == 'E') {
    p++;
    if (*p == '-') {
      esign = -1;
      p++;
    } else if (*p == '+') {
      esign = +1;
      p++;
    }
    while (isdigit(*p) && i_exp < 1000000) {
      i_exp = i_exp * 10 + _reuse_letter_to_digit_table[*p];
      p++;
    }
    if (esign < 0) i_exp = -i_exp;
    while (isdigit(*p)) p++;
  }

  i_exp += exp_shift;
  if (i_exp <= -1000000) {
    errno = ERANGE;
    reuse_set_zero_ld(msign, &val);
    goto _exit;
  }
  if (i_exp >= 1000000) {
    errno = ERANGE;
    reuse_set_infinity_ld(msign, &val);
    goto _exit;
  }
  ld_exp = get10pow(i_exp);
  if (errno == ERANGE) {
    if (ld_exp == 0.0L) reuse_set_zero_ld(msign, &val);
    else reuse_set_infinity_ld(msign, &val);
    goto _exit;
  }

  val = mant * ld_exp;
  if (msign < 0) val = -val;
  if (reuse_is_infinity_ld(&val)) errno = ERANGE;
  if (val == 0) errno = ERANGE;

 _exit:
  if (endptr) *endptr = (char*) p;
  return val;

 _skip_mantissa_integral:
  while (isdigit(*p)) p++;
  if (*p == '.') {
    p++;
  _skip_mantissa_fractional:
    while (isdigit(*p)) p++;
  }
 _skip_exponent:
  if (*p == 'e' || *p == 'E') {
    p++;
    if (*p == '+' || *p == '-') p++;
    while (isdigit(*p)) p++;
  }
  goto _exit;
}
#endif /* CONF_HAS_STRTOLD */
#endif /* R_LONG_DOUBLE_IS_DOUBLE */

long double
reuse_strtold(char const *str, char **endptr)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return reuse_strtod(str, endptr);
#else
# if defined CONF_HAS_STRTOLD && CONF_HAS_STRTOLD - 0 == 1
#  if CONF_STRTOD_ACCEPTS_HEX - 0 == 1
  return strtold(str, endptr);
#  else
  long double val;

  if (str && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
    if (reuse_readhld(str, endptr, &val) == 1) {
      errno = ERANGE;
    }
    return val;
  }
  return strtold(str, endptr);
#  endif /* strtold accepts hex literals */
# else
  long double val;

  if (str && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
    if (reuse_readhld(str, endptr, &val) == 1) {
      errno = ERANGE;
    }
    return val;
  }
  return do_strtold(str, endptr);
# endif /* CONF_HAS_STRTOLD */
#endif /* R_LONG_DOUBLE_IS_DOUBLE */
}
