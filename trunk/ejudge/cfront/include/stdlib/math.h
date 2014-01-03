/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_MATH_H__
#define __RCC_MATH_H__

/* Copyright (C) 2001-2004 Alexander Chernov <cher@ispras.ru> */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <features.h>

double      sqrt(double);
float       sqrtf(float);
long double sqrtl(long double);

double      ceil(double);
float       ceilf(float);
long double ceill(long double);

double      floor(double);
float       floorf(float);
long double floorl(long double);

double      fabs(double);
float       fabsf(float);
long double fabsl(long double);

double      exp(double);
float       expf(float);
long double expl(long double);

double      exp2(double);
float       exp2f(float);
long double exp2l(long double);

double      exp10(double);
float       exp10f(float);
long double exp10l(long double);

double      pow10(double);
float       pow10f(float);
long double pow10l(long double);

double      log(double);
float       logf(float);
long double logl(long double);

double      log2(double);
float       log2f(float);
long double log2l(long double);

double      log10(double);
float       log10f(float);
long double log10l(long double);

double      pow(double, double);
float       powf(float, float);
long double powl(long double, long double);

double      asin(double);
float       asinf(float);
long double asinl(long double);

double      acos(double);
float       acosf(float);
long double acosl(long double);

double      atan(double);
float       atanf(float);
long double atanl(long double);

double      atan2(double, double);
float       atan2f(float, float);
long double atan2l(long double, long double);

double      sin(double);
float       sinf(float);
long double sinl(long double);

double      cos(double);
float       cosf(float);
long double cosl(long double);

double      tan(double);
float       tanf(float);
long double tanl(long double);

double      sinh(double);
float       sinhf(float);
long double sinhl(long double);

double      cosh(double);
float       coshf(float);
long double coshl(long double);

double      tanh(double);
float       tanhf(float);
long double tanhl(long double);

double      asinh(double);
float       asinhf(float);
long double asinhl(long double);

double      acosh(double);
float       acoshf(float);
long double acoshl(long double);

double      atanh(double);
float       atanhf(float);
long double atanhl(long double);

double enum
{
  M_E = 2.7182818284590452354,
#define M_E M_E
  M_LOG2E = 1.4426950408889634074,
#define M_LOG2E M_LOG2E
  M_LOG10E = 0.43429448190325182765,
#define M_LOG10E M_LOG10E
  M_LN2 = 0.69314718055994530942,
#define M_LN2 M_LN2
  M_LN10 = 2.30258509299404568402,
#define M_LN10 M_LN10
  M_PI = 3.14159265358979323846,
#define M_PI M_PI
  M_PI_2 = 1.57079632679489661923,
#define M_PI_2 M_PI_2
  M_PI_4 = 0.78539816339744830962,
#define M_PI_4 M_PI_4
  M_1_PI = 0.31830988618379067154,
#define M_1_PI M_1_PI
  M_2_PI = 0.63661977236758134308,
#define M_2_PI M_2_PI
  M_2_SQRTPI = 1.12837916709551257390,
#define M_2_SQRTPI M_2_SQRTPI
  M_SQRT2 = 1.41421356237309504880,
#define M_SQRT2 M_SQRT2
  M_SQRT1_2 = 0.70710678118654752440,
#define M_SQRT1_2 M_SQRT1_2
};

long double enum
{
  M_El = 2.7182818284590452353602874713526625L,
#define M_El M_El
  M_LOG2El = 1.4426950408889634073599246810018921L,
#define M_LOG2El M_LOG2El
  M_LOG10El = 0.4342944819032518276511289189166051L,
#define M_LOG10El M_LOG10El
  M_LN2l = 0.6931471805599453094172321214581766L,
#define M_LN2l M_LN2l
  M_LN10l = 2.3025850929940456840179914546843642L,
#define M_LN10l M_LN10l
  M_PIl = 3.1415926535897932384626433832795029L,
#define M_PIl M_PIl
  M_PI_2l = 1.5707963267948966192313216916397514L,
#define M_PI_2l M_PI_2l
  M_PI_4l = 0.7853981633974483096156608458198757L,
#define M_PI_4l M_PI_4l
  M_1_PIl = 0.3183098861837906715377675267450287L,
#define M_1_PIl M_1_PIl
  M_2_PIl = 0.6366197723675813430755350534900574L,
#define M_2_PIl M_2_PIl
  M_2_SQRTPIl = 1.1283791670955125738961589031215452L,
#define M_2_SQRTPIl M_2_SQRTPIl
  M_SQRT2l = 1.4142135623730950488016887242096981L,
#define M_SQRT2l M_SQRT2l
  M_SQRT1_2l = 0.7071067811865475244008443621048490L,
#define M_SQRT1_2l M_SQRT1_2l
};

#endif /* __RCC_MATH_H__ */
