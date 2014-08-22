/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_STDARG_H__
#define __RCC_STDARG_H__

/* Copyright (C) 1999-2004 Alexander Chernov <cher@ispras.ru> */

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

#ifndef RCC_VA_LIST_DEFINED
#define RCC_VA_LIST_DEFINED
typedef __builtin_va_list va_list;
#endif /* RCC_VA_LIST_DEFINED */

#define va_start(a,b) __builtin_va_start(a,b)
#define va_arg(a,b)   __builtin_va_arg(a,b)
#define va_end(a)     __builtin_va_end(a)

struct __force_include_stdarg
{
  int pad[1];
};

#endif /* __RCC_STDARG_H__ */

