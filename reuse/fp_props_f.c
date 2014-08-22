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
reuse_is_infinity_f(const float *v)
{
  unsigned long const *lv = (unsigned long const *) v;

  return (*lv & 0x7fffffff) == 0x7f800000;
}

int
reuse_is_nan_f(const float *v)
{
  unsigned long const *lv = (unsigned long const *) v;

  return *lv == 0x7fc00000;
}

int
reuse_get_sign_bit_f(const float *v)
{
  unsigned long lv = *(unsigned long const *) v;

  return (lv & 0x80000000) >> 31;
}

void
reuse_set_infinity_f(int sgn, float *v)
{
  unsigned long *lv = (unsigned long *) v;

  *lv = 0x7f800000;
  if (sgn < 0) *lv |= 0x80000000;
}

void
reuse_set_nan_f(float *v)
{
  unsigned long *lv = (unsigned long *) v;

  *lv = 0x7fc00000;
}

void
reuse_set_zero_f(int sgn, float *v)
{
  unsigned long *lv = (unsigned long *) v;

  *lv = 0;
  if (sgn < 0) *lv |= 0x80000000;
}
