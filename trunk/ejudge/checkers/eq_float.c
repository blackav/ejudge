/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005,2006 Alexander Chernov <cher@ispras.ru> */

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
checker_eq_float(float v1, float v2, float eps)
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
  if (fabs(v1) <= 1.0 && fabs(v2) <= 1.0) {
    if (fabs(v1 - v2) <= 2*eps) return 1;
    return 0;
  }
  if (!v1 || !v2) return 0;
  if ((vv1 ^ vv2) < 0) return 0;
  vv1 &= ~0x80000000;
  vv2 &= ~0x80000000;
  p = p1 = vv1 & 0x7f800000;
  if (p > (p2 = vv2 & 0x7f800000)) p = p2;
  if (abs(p1 - p2) > 0x00800000) return 0;
  vv1 -= (p - 0x3f800000);
  vv2 -= (p - 0x3f800000);
  v1 = *(float*) &vv1;
  v2 = *(float*) &vv2;
  if (fabs(v1 - v2) <= 2*eps) return 1;
  return 0;
#else
  float m1, m2;
  int e1, e2, em;

  if (fpclassify(v1) == FP_NAN && fpclassify(v2) == FP_NAN) return 1;
  if (fpclassify(v1) == FP_NAN || fpclassify(v2) == FP_NAN) return 0;
  if (fpclassify(v1) == FP_INFINITE && fpclassify(v2) == FP_INFINITE) {
    if (signbit(v1) == signbit(v2)) return 1;
    return 0;
  }
  if (fpclassify(v1) == FP_INFINITE || fpclassify(v2) == FP_INFINITE) return 0;
  if (fabsf(v1) <= 1.0 && fabsf(v2) <= 1.0) {
    if (fabsf(v1 - v2) <= 2*eps) return 1;
    return 0;
  }
  if (signbit(v1) != signbit(v2)) return 0;
  m1 = frexpf(v1, &e1);
  m2 = frexpf(v2, &e2);
  if (abs(e1 - e2) > 1) return 0;
  em = e1;
  if (e2 < em) em = e2;
  e1 -= em;
  e2 -= em;
  m1 = ldexpf(m1, e1);
  m2 = ldexpf(m2, e2);
  if (fabsf(m1 - m2) <= 2*eps) return 1;
  return 0;
#endif
}
