/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "checker_internal.h"

/*
 * 79 - sign bit
 * 63-78 - exponent
 * 0-62 - mantissa
 */
int
checker_eq_long_double_abs(long double v1, long double v2, long double eps)
{
#if defined __MINGW32__
  unsigned int *r1, *r2;
  int e1, e2, e, s1, s2;
  unsigned long long m1, m2;
  long double d;

  if (sizeof(long double) == sizeof(double))
    return checker_eq_double(v1, v2, eps);

  r1 = (unsigned int*) &v1;
  e1 = r1[2] & 0x7fff;
  m1 = r1[0] | (((unsigned long long) r1[1]) << 32);
  s1 = (r1[2] >> 15) & 1;

  r2 = (unsigned int*) &v2;
  e2 = r2[2] & 0x7fff;
  m2 = r2[0] | (((unsigned long long) r2[1]) << 32);
  s2 = (r2[2] >> 15) & 1;

  if (e1 == 0x7fff && m1 < 0 && e2 == 0x7fff && m2 < 0) {
    if ((m1 & 0x8000000000000000LL) != 0 && (m2 & 0x8000000000000000LL) != 0)
      return 1; /* both NaN */
    if ((m1 & 0x8000000000000000LL) != 0 || (m2 & 0x8000000000000000LL) != 0)
      return 0; /* only one NaN */
    /* both Inf */
    if ((s1 ^ s2) != 0) return 0;
    return 1;
  }
  if (e1 == 0xffff || e2 == 0xffff) return 0;
  d = v1 - v2;
  if (d <= 1.125*eps && d >= -1.125*eps) return 1;
  return 0;
#else
  if (fpclassify(v1) == FP_NAN && fpclassify(v2) == FP_NAN) return 1;
  if (fpclassify(v1) == FP_NAN || fpclassify(v2) == FP_NAN) return 0;
  if (fpclassify(v1) == FP_INFINITE && fpclassify(v2) == FP_INFINITE) {
    if (signbit(v1) == signbit(v2)) return 1;
    return 0;
  }
  if (fpclassify(v1) == FP_INFINITE || fpclassify(v2) == FP_INFINITE) return 0;
  if (fabsl(v1 - v2) <= 1.125*eps) return 1;
  return 0;
#endif
}
