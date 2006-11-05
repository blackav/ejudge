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

int
checker_eq_float_abs(float v1, float v2, float eps)
{
#if defined __MINGW32__
#define checker_is_nan(x) (((x) & 0x7f800000) == 0x7f80000 && ((x) & 0x007fffff) != 0)
#define checker_is_inf(x) (((x) & 0x7f800000) == 0x7f80000 && ((x) & 0x007fffff) == 0)
  int vv1 = *(int*) &v1;
  int vv2 = *(int*) &v2;
  int p1, p2, p;

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
  if (fabsf(v1 - v2) <= 1.125*eps) return 1;
  return 0;
#endif
}
