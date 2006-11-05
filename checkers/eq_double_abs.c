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
 * 63 - sign bit
 * 52-62 - exponent
 * 0-51 - mantissa
 */
int
checker_eq_double_abs(double v1, double v2, double eps)
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
  if (fabs(v1 - v2) <= 1.125*eps) return 1;
  return 0;
#else
  if (fpclassify(v1) == FP_NAN && fpclassify(v2) == FP_NAN) return 1;
  if (fpclassify(v1) == FP_NAN || fpclassify(v2) == FP_NAN) return 0;
  if (fpclassify(v1) == FP_INFINITE && fpclassify(v2) == FP_INFINITE) {
    if (signbit(v1) == signbit(v2)) return 1;
    return 0;
  }
  if (fpclassify(v1) == FP_INFINITE || fpclassify(v2) == FP_INFINITE) return 0;
  if (fabs(v1 - v2) <= 1.125*eps) return 1;
  return 0;
#endif
}
