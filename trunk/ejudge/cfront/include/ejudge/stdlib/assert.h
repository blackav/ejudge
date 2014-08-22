/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_ASSERT_H__
#define __RCC_ASSERT_H__

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

#ifndef RCC_SIZE_T_DEFINED
#define RCC_SIZE_T_DEFINED 1
typedef unsigned long size_t;
#endif /* RCC_SIZE_T_DEFINED */

#ifndef RCC_FILE_DEFINED
#define RCC_FILE_DEFINED 1
typedef struct
{
  int dummy;
} FILE;
#endif /* RCC_FILE_DEFINED */

#ifdef  NDEBUG

#define assert(expr)            ((void) 0)

#else /* Not NDEBUG.  */

extern int __assert_fail(const char *__assertion,
                         const char *__file,
                         unsigned int __line,
                         const char *__function)
     __attribute__((noreturn));

#define assert(expr) \
  ((void) ((expr) ? 0 : \
           (__assert_fail (#expr, \
                           __FILE__, __LINE__, __FUNCTION__), 0)))

#endif /* NDEBUG */

#endif /* __RCC_ASSERT_H__ */
