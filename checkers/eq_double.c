/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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
checker_eq_double(double v1, double v2, double eps)
{
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
    if (fabs(v1 - v2) <= 2*eps) return 1;
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
  if (fabs(m1 - m2) <= 2*eps) return 1;
  return 0;
}
