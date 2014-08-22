/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `complex.h' of the GNU C Library,
   version 2.3.2. The original copyright follows. */

/* Copyright (C) 1997, 1998, 1999, 2000 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/*
 *      ISO C99:  7.3 Complex arithmetic        <complex.h>
 */

#ifndef __RCC_COMPLEX_H__
#define __RCC_COMPLEX_H__

#include <features.h>

#ifndef __RCC_FLOAT_T_DEFINED__
#define __RCC_FLOAT_T_DEFINED__
typedef long double float_t;
typedef long double double_t;
#endif /* __RCC_FLOAT_T_DEFINED__ */

/*
#define INFINITY    HUGE_VALF
#define FP_ILOGB0   (-2147483647 - 1)
#define FP_ILOGBNAN (-2147483647 - 1)
*/

#define complex         _Complex

float _Complex enum
{
#defconst _Complex_I ((float _Imaginary) 1.0f)
};

#undef I
#define I _Complex_I

/* float functions */
float _Complex cacosf(float _Complex z);
float _Complex casinf(float _Complex z);
float _Complex catanf(float _Complex z);
float _Complex ccosf(float _Complex z);
float _Complex csinf(float _Complex z);
float _Complex ctanf(float _Complex z);

float _Complex cacoshf(float _Complex z);
float _Complex casinhf(float _Complex z);
float _Complex catanhf(float _Complex z);
float _Complex ccoshf(float _Complex z);
float _Complex csinhf(float _Complex z);
float _Complex ctanhf(float _Complex z);

float _Complex cexpf(float _Complex z);
float _Complex clogf(float _Complex z);
float _Complex clog10f(float _Complex z);
float _Complex cpowf(float _Complex x, float _Complex y);
float _Complex csqrtf(float _Complex z);

float cabsf(float _Complex z);
float cargf(float _Complex z);
float _Complex conjf(float _Complex z);
float _Complex cprojf(float _Complex z);

float cimagf(float _Complex z);
float crealf(float _Complex z);

/* double functions */
double _Complex cacos(double _Complex z);
double _Complex casin(double _Complex z);
double _Complex catan(double _Complex z);
double _Complex ccos(double _Complex z);
double _Complex csin(double _Complex z);
double _Complex ctan(double _Complex z);

double _Complex cacosh(double _Complex z);
double _Complex casinh(double _Complex z);
double _Complex catanh(double _Complex z);
double _Complex ccosh(double _Complex z);
double _Complex csinh(double _Complex z);
double _Complex ctanh(double _Complex z);

double _Complex cexp(double _Complex z);
double _Complex clog(double _Complex z);
double _Complex clog10(double _Complex z);
double _Complex cpow(double _Complex x, double _Complex y);
double _Complex csqrt(double _Complex z);

double cabs(double _Complex z);
double carg(double _Complex z);
double _Complex conj(double _Complex z);
double _Complex cproj(double _Complex z);

double cimag(double _Complex z);
double creal(double _Complex z);

/* long double functions */
long double _Complex cacosl(long double _Complex z);
long double _Complex casinl(long double _Complex z);
long double _Complex catanl(long double _Complex z);
long double _Complex ccosl(long double _Complex z);
long double _Complex csinl(long double _Complex z);
long double _Complex ctanl(long double _Complex z);

long double _Complex cacoshl(long double _Complex z);
long double _Complex casinhl(long double _Complex z);
long double _Complex catanhl(long double _Complex z);
long double _Complex ccoshl(long double _Complex z);
long double _Complex csinhl(long double _Complex z);
long double _Complex ctanhl(long double _Complex z);

long double _Complex cexpl(long double _Complex z);
long double _Complex clogl(long double _Complex z);
long double _Complex clog10l(long double _Complex z);
long double _Complex cpowl(long double _Complex x, long double _Complex y);
long double _Complex csqrtl(long double _Complex z);

long double cabsl(long double _Complex z);
long double cargl(long double _Complex z);
long double _Complex conjl(long double _Complex z);
long double _Complex cprojl(long double _Complex z);

long double cimagl(long double _Complex z);
long double creall(long double _Complex z);

#endif /* __RCC_COMPLEX_H__ */

/*
 * Local variables:
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "_Complex" "_Imaginary")
 * End:
 */
