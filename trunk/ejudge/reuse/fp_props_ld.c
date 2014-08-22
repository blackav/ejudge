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
#include "ejudge/fp_props.h"

#include <string.h>

int
reuse_is_infinity_ld(const long double *pv)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return reuse_is_infinity_d((const double*) pv);
#else
  unsigned long long mant;
  unsigned long w3;

  memmove(&mant, pv, 8);
  memmove(&w3, (char*) pv + 8, 2);
  if (mant == 0x8000000000000000LL && (w3 & 0x7fff) == 0x7fff)
    return 1;
  return 0;
#endif /* R_LONG_DOUBLE_IS_DOUBLE */
}

int
reuse_is_nan_ld(const long double *pv)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return reuse_is_nan_d((const double*) pv);
#else
  unsigned long long mant;
  unsigned long w3 = 0;

  memmove(&mant, pv, 8);
  memmove(&w3, (char*) pv + 8, 2);
  if (mant == 0xc000000000000000LL && w3 == 0xffff)
    return 1;
  return 0;
#endif /* R_LONG_DOUBLE_IS_DOUBLE */
}

int
reuse_get_sign_bit_ld(const long double *pv)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return reuse_get_sign_bit_d((const double*) pv);
#else
  unsigned long w3;

  memmove(&w3, (char*) pv + 8, 2);
  return (w3 & 0x8000) >> 15;
#endif /* R_LONG_DOUBLE_IS_DOUBLE */
}

void
reuse_set_zero_ld(int sgn, long double *pv)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return reuse_set_zero_d(sgn, (double*) pv);
#else
  unsigned long long mant;
  unsigned long w3;

  mant = 0LL;
  w3 = 0;
  if (sgn < 0) w3 |= 0x8000;
  memmove(pv, &mant, 8);
  memmove((char*) pv + 8, &w3, 2);
#endif /* R_LONG_DOUBLE_IS_DOUBLE */
}

void
reuse_set_infinity_ld(int sgn, long double *pv)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return reuse_set_infinity_d(sgn, (double*) pv);
#else
  unsigned long long mant;
  unsigned long w3;

  mant = 0x8000000000000000LL;
  w3 = 0x7fff;
  if (sgn < 0) w3 |= 0x8000;
  memmove(pv, &mant, 8);
  memmove((char*) pv + 8, &w3, 2);
#endif /* R_LONG_DOUBLE_IS_DOUBLE */
}

void
reuse_set_nan_ld(long double *pv)
{
#if R_LONG_DOUBLE_IS_DOUBLE - 0 == 1
  return reuse_set_nan_d((double*) pv);
#else
  unsigned long long mant;
  unsigned long w3;

  mant = 0xc000000000000000LL;
  w3 = 0xffff;
  memmove(pv, &mant, 8);
  memmove((char*) pv + 8, &w3, 2);
#endif /* R_LONG_DOUBLE_IS_DOUBLE */
}
