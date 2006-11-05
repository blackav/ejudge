/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005, 2006 Alexander Chernov <cher@ejudge.ru> */

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
 * 63 - sign bit
 * 52-62 - exponent
 * 0-51 - mantissa
 */
int
checker_eq_double(double v1, double v2, double eps)
{
#if defined __MINGW32__
#define checker_is_nan(x) (((x) & 0x7ff0000000000000LL) == 0x7ff0000000000000LL && ((x) & 0x000fffffffffffffLL) != 0)
#define checker_is_inf(x) (((x) & 0x7ff0000000000000LL) == 0x7ff0000000000000LL && ((x) & 0x000fffffffffffffLL) == 0)
  long long vv1 = *(long long*) &v1;
  long long vv2 = *(long long*) &v2;
  long long p1, p2, p;

  if (checker_is_nan(vv1) && checker_is_nan(vv2)) return 1;
  if (checker_is_nan(vv1) || checker_is_nan(vv2)) return 0;
  if (checker_is_inf(vv1) && checker_is_inf(vv2)) {
    if ((vv1 ^ vv2) < 0) return 0;
    return 1;
  }
  if (checker_is_inf(vv1) || checker_is_inf(vv2)) return 0;
  if (fabs(v1) <= 1.0 && fabs(v2) <= 1.0) {
    if (fabs(v1 - v2) <= 1.125*eps) return 1;
    return 0;
  }
  if (!v1 || !v2) return 0;
  if ((vv1 ^ vv2) < 0) return 0;
  vv1 &= 0x7fffffffffffffffLL;
  vv2 &= 0x7fffffffffffffffLL;
  p = p1 = vv1 & 0x7ff0000000000000LL;
  if (p > (p2 = vv2 & 0x7ff0000000000000LL)) p = p2;
  if (p1 - p > 0x0010000000000000LL || p2 - p > 0x001000000000000LL)
    return 0;
  vv1 -= (p - 0x3ff0000000000000LL);
  vv2 -= (p - 0x3ff0000000000000LL);
  v1 = *(double*) &vv1;
  v2 = *(double*) &vv2;
  if (fabs(v1 - v2) <= 1.125*eps) return 1;
  return 0;
#else
  double m1, m2;
  int e1, e2, em;

  if (fpclassify(v1) == FP_NAN && fpclassify(v2) == FP_NAN) return 1;
  if (fpclassify(v1) == FP_NAN || fpclassify(v2) == FP_NAN) return 0;
  if (fpclassify(v1) == FP_INFINITE && fpclassify(v2) == FP_INFINITE) {
    if (signbit(v1) == signbit(v2)) return 1;
    return 0;
  }
  if (fpclassify(v1) == FP_INFINITE || fpclassify(v2) == FP_INFINITE) return 0;
  if (fabs(v1) <= 1.0 && fabs(v2) <= 1.0) {
    if (fabs(v1 - v2) <= 1.125*eps) return 1;
    return 0;
  }
  if (signbit(v1) != signbit(v2)) return 0;
  m1 = frexp(v1, &e1);
  m2 = frexp(v2, &e2);
  if (abs(e1 - e2) > 1) return 0;
  em = e1;
  if (e2 < em) em = e2;
  e1 -= em;
  e2 -= em;
  m1 = ldexp(m1, e1);
  m2 = ldexp(m2, e2);
  if (fabs(m1 - m2) <= 1.125*eps) return 1;
  return 0;
#endif
}
