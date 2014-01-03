/* $Id$ */
/* Copyright (C) 2004 Alexander Chernov */

/* This file is derived from `float.h' of the GNU C Compiler,
   version 3.2.3. The original copyright follows. */

/* float.h for target with IEEE 32/64 bit and Intel 386 style 80 bit
   floating point formats */
#ifndef __RCC_FLOAT_H__
#define __RCC_FLOAT_H__
/* Produced by enquire version 4.3, CWI, Amsterdam */

#include <features.h>

   /* Radix of exponent representation */
int enum {
#defconst FLT_RADIX 2
};

   /* Number of base-FLT_RADIX digits in the significand of a float */
int enum {
#defconst FLT_MANT_DIG 24
};

   /* Number of decimal digits of precision in a float */
int enum {
#defconst FLT_DIG 6
};

   /* Addition rounds to 0: zero, 1: nearest, 2: +inf, 3: -inf, -1: unknown */
int enum {
#defconst FLT_ROUNDS 1
};

   /* Difference between 1.0 and the minimum float greater than 1.0 */
float enum {
#defconst FLT_EPSILON 1.19209290e-07F
};

   /* Minimum int x such that FLT_RADIX**(x-1) is a normalised float */
int enum {
#defconst FLT_MIN_EXP (-125)
};

   /* Minimum normalised float */
float enum {
#defconst FLT_MIN 1.17549435e-38F
};

   /* Minimum int x such that 10**x is a normalised float */
int enum {
#defconst FLT_MIN_10_EXP (-37)
};

   /* Maximum int x such that FLT_RADIX**(x-1) is a representable float */
int enum {
#defconst FLT_MAX_EXP 128
};

   /* Maximum float */
float enum {
#defconst FLT_MAX 3.40282347e+38F
};

   /* Maximum int x such that 10**x is a representable float */
int enum {
#defconst FLT_MAX_10_EXP 38
};

   /* Number of base-FLT_RADIX digits in the significand of a double */
int enum {
#defconst DBL_MANT_DIG 53
};

   /* Number of decimal digits of precision in a double */
int enum {
#defconst DBL_DIG 15
};

   /* Difference between 1.0 and the minimum double greater than 1.0 */
double enum {
#defconst DBL_EPSILON 2.2204460492503131e-16
};

   /* Minimum int x such that FLT_RADIX**(x-1) is a normalised double */
int enum {
#defconst DBL_MIN_EXP (-1021)
};

   /* Minimum normalised double */
double enum {
#defconst DBL_MIN 2.2250738585072014e-308
};

   /* Minimum int x such that 10**x is a normalised double */
int enum {
#defconst DBL_MIN_10_EXP (-307)
};

   /* Maximum int x such that FLT_RADIX**(x-1) is a representable double */
int enum {
#defconst DBL_MAX_EXP 1024
};

   /* Maximum double */
double enum {
#defconst DBL_MAX 1.7976931348623157e+308
};

   /* Maximum int x such that 10**x is a representable double */
int enum {
#defconst DBL_MAX_10_EXP 308
};

   /* Number of base-FLT_RADIX digits in the significand of a long double */
int enum {
#defconst LDBL_MANT_DIG 64
};

   /* Number of decimal digits of precision in a long double */
int enum {
#defconst LDBL_DIG 18
};

   /* Difference between 1.0 and the minimum long double greater than 1.0 */
long double enum {
#defconst LDBL_EPSILON 1.08420217248550443401e-19L
};

   /* Minimum int x such that FLT_RADIX**(x-1) is a normalised long double */
int enum {
#defconst LDBL_MIN_EXP (-16381)
};

   /* Minimum normalised long double */
long double enum {
#defconst LDBL_MIN 3.36210314311209350626e-4932L
};

   /* Minimum int x such that 10**x is a normalised long double */
int enum {
#defconst LDBL_MIN_10_EXP (-4931)
};

  /* Maximum int x such that FLT_RADIX**(x-1) is a representable long double */
int enum {
#defconst LDBL_MAX_EXP 16384
};

   /* Maximum long double */
long double enum {
#defconst LDBL_MAX 1.18973149535723176502e+4932L
};

   /* Maximum int x such that 10**x is a representable long double */
int enum {
#defconst LDBL_MAX_10_EXP 4932
};

   /* The floating-point expression evaluation method.
        -1  indeterminate
         0  evaluate all operations and constants just to the range and
            precision of the type
         1  evaluate operations and constants of type float and double
            to the range and precision of the double type, evaluate
            long double operations and constants to the range and
            precision of the long double type
         2  evaluate all operations and constants to the range and
            precision of the long double type
   */
int enum {
#defconst FLT_EVAL_METHOD        2
};

   /* Number of decimal digits to enable rounding to the given number of
      decimal digits without loss of precision.
         if FLT_RADIX == 10^n:  #mantissa * log10 (FLT_RADIX)
         else                :  ceil (1 + #mantissa * log10 (FLT_RADIX))
      where #mantissa is the number of bits in the mantissa of the widest
      supported floating-point type.
   */
int enum {
#defconst DECIMAL_DIG    21
};

#endif /*  __RCC_FLOAT_H__ */
