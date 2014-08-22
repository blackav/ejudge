/* -*- c -*- */
/* $Id$ */

#ifndef __REUSE_INTEGRAL_H__
#define __REUSE_INTEGRAL_H__

/* Copyright (C) 2011-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"

/* shorthands */
typedef signed char    rschar_t;
typedef unsigned char  ruchar_t;
typedef unsigned short rushort_t;
typedef unsigned int   ruint_t;
typedef unsigned long  rulong_t;

typedef signed char rint8_t;
typedef unsigned char ruint8_t;
typedef signed short rint16_t;
typedef unsigned short ruint16_t;
typedef signed int rint32_t;
typedef unsigned int ruint32_t;

#if defined R_HAS_LONGLONG
  #define R_HAS_INT64 1
  typedef long long rllong_t;
  typedef unsigned long long rullong_t;
  typedef signed long long rint64_t;
  typedef unsigned long long ruint64_t;
  #define R_LONG_LONG_MAX (9223372036854775807ll)
  #define R_LONG_LONG_MIN (-9223372036854775807ll-1ll)
  #define R_ULONG_LONG_MAX (18446744073709551615ull)
  #define R_I64(x) x##ll
  #define R_U64(x) x##ull
  #define R_F64 "ll"
#elif defined R_HAS___INT64
  #define R_HAS_INT64 1
  typedef __int64 rllong_t;
  typedef unsigned __int64 rullong_t;
  typedef signed __int64 rint64_t;
  typedef unsigned __int64 ruint64_t;
  #define R_LONG_LONG_MAX (9223372036854775807I64)
  #define R_LONG_LONG_MIN (-9223372036854775807I64-1I64)
  #define R_ULONG_LONG_MAX (18446744073709551615uI64)
  #define R_I64(x) x##I64
  #define R_U64(x) x##uI64
  #define R_F64 "I64"
#endif

#endif /* __REUSE_INTEGRAL_H__ */
