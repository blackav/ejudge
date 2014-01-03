/* -*- c -*- */
/* $Id$ */

#ifndef __RCC_STDDEF_H__
#define __RCC_STDDEF_H__

/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

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
#include <unistd.h>
#include <sys/types.h>

#ifndef RCC_WCHAR_T_DEFINED
#define RCC_WCHAR_T_DEFINED 1
/* FIXME: wchar_t should be somehow built-in */
typedef long int wchar_t;
#endif /* RCC_WCHAR_T_DEFINED */

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#endif /* __RCC_STDDEF_H__ */
