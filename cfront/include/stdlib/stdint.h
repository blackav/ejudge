/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_STDINT_H__
#define __RCC_STDINT_H__

/* Copyright (C) 2002-2004 Alexander Chernov <cher@ispras.ru> */

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

#if !defined __RCC_INTX_T_DEFINED__
#define __RCC_INTX_T_DEFINED__ 1
typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned           uint32_t;
typedef unsigned long long uint64_t;
#endif /* __RCC_INTX_T_DEFINED__ */

typedef signed char        int_least8_t;
typedef short int          int_least16_t;
typedef int                int_least32_t;
typedef long long          int_least64_t;
typedef unsigned char      uint_least8_t;
typedef unsigned short     uint_least16_t;
typedef unsigned           uint_least32_t;
typedef unsigned long long uint_least64_t;

typedef signed char        int_fast8_t;
typedef int                int_fast16_t;
typedef int                int_fast32_t;
typedef long long          int_fast64_t;
typedef unsigned char      uint_fast8_t;
typedef unsigned           uint_fast16_t;
typedef unsigned           uint_fast32_t;
typedef unsigned long long uint_fast64_t;

#ifndef __RCC_INTPTR_T_DEFINED__
#define __RCC_INTPTR_T_DEFINED__
typedef int          intptr_t;
#endif /* __RCC_INTPTR_T_DEFINED__ */

typedef unsigned int uintptr_t;

typedef long long          intmax_t;
typedef unsigned long long uintmax_t;

#if !defined __cplusplus || defined __STDC_LIMIT_MACROS

#  define __INT64_C(c)  c ## LL
#  define __UINT64_C(c) c ## ULL

# define INT8_MIN               (-128)
# define INT16_MIN              (-32767-1)
# define INT32_MIN              (-2147483647-1)
# define INT64_MIN              (-9223372036854775807LL-1)
# define INT8_MAX               (127)
# define INT16_MAX              (32767)
# define INT32_MAX              (2147483647)
# define INT64_MAX              (9223372036854775807LL)
# define UINT8_MAX              (255U)
# define UINT16_MAX             (65535U)
# define UINT32_MAX             (4294967295U)
# define UINT64_MAX             (18446744073709551615ULL)

# define INT_LEAST8_MIN         (-128)
# define INT_LEAST16_MIN        (-32767-1)
# define INT_LEAST32_MIN        (-2147483647-1)
# define INT_LEAST64_MIN        (-9223372036854775807LL-1)
# define INT_LEAST8_MAX         (127)
# define INT_LEAST16_MAX        (32767)
# define INT_LEAST32_MAX        (2147483647)
# define INT_LEAST64_MAX        (9223372036854775807ULL)
# define UINT_LEAST8_MAX        (255U)
# define UINT_LEAST16_MAX       (65535U)
# define UINT_LEAST32_MAX       (4294967295U)
# define UINT_LEAST64_MAX       (18446744073709551615ULL)

# define INT_FAST8_MIN   (-128)
# define INT_FAST16_MIN  (-2147483647-1)
# define INT_FAST32_MIN  (-2147483647-1)
# define INT_FAST64_MIN  (-9223372036854775807LL-1)
# define INT_FAST8_MAX   (127)
# define INT_FAST16_MAX  (2147483647)
# define INT_FAST32_MAX  (2147483647)
# define INT_FAST64_MAX  (9223372036854775807LL)
# define UINT_FAST8_MAX  (255U)
# define UINT_FAST16_MAX (4294967295U)
# define UINT_FAST32_MAX (4294967295U)
# define UINT_FAST64_MAX (18446744073709551615ULL)

# define INTPTR_MIN             (-2147483647-1)
# define INTPTR_MAX             (2147483647)
# define UINTPTR_MAX            (4294967295U)

# define INTMAX_MIN             (-9223372036854775807LL-1)
# define INTMAX_MAX             (9223372036854775807LL)
# define UINTMAX_MAX            (18446744073709551615ULL)

# define PTRDIFF_MIN            (-2147483647-1)
# define PTRDIFF_MAX            (2147483647)

# define SIG_ATOMIC_MIN         (-2147483647-1)
# define SIG_ATOMIC_MAX         (2147483647)

# define SIZE_MAX               (4294967295U)

# ifndef WCHAR_MIN
#  define WCHAR_MIN             (0)
#  define WCHAR_MAX             (2147483647)
# endif

# define WINT_MIN               (0)
# define WINT_MAX               (2147483647)

#endif  /* C++ && limit macros */

#if !defined __cplusplus || defined __STDC_CONSTANT_MACROS

# define INT8_C(c)      c
# define INT16_C(c)     c
# define INT32_C(c)     c
# define INT64_C(c)     c ## LL
# define UINT8_C(c)     c ## U
# define UINT16_C(c)    c ## U
# define UINT32_C(c)    c ## U
# define UINT64_C(c)    c ## ULL
# define INTMAX_C(c)    c ## LL
# define UINTMAX_C(c)   c ## ULL

#endif  /* C++ && constant macros */

#ifndef RCC_WCHAR_T_DEFINED
#define RCC_WCHAR_T_DEFINED 1
/* FIXME: wchar_t should be somehow built-in */
typedef long int wchar_t;
#endif /* RCC_WCHAR_T_DEFINED */

#endif /* __RCC_STDINT_H__ */
