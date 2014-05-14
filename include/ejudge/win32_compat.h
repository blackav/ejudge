/* -*- c -*- */
/* $Id$ */

#ifndef __EJ_WIN32_COMPAT_H__
#define __EJ_WIN32_COMPAT_H__

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#define EJ_PRINTF_ZSPEC "l"
#define EJ_PRINTF_ZCAST(x) ((unsigned long) (x))
#define EJ_PRINTF_LLSPEC "I64"
#define EJ_PRINTF_TSPEC "l"
#define EJ_PRINTF_TCAST(x) ((long) (x))
#else
#define EJ_PRINTF_ZSPEC "z"
#define EJ_PRINTF_ZCAST(x) (x)
#define EJ_PRINTF_LLSPEC "ll"
#define EJ_PRINTF_TSPEC "t"
#define EJ_PRINTF_TCAST(x) (x)
#endif

#endif
