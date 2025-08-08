/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __SAFE_FORMAT_H__
#define __SAFE_FORMAT_H__

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdlib.h>
#include <stdarg.h>

typedef unsigned char safe_format_type_t;

enum
{
    SAFE_FORMAT_INT = 1,
};

int
safe_format_validate(
        const safe_format_type_t *types,
        const char *format);

int
safe_format_v(
        char *buf,
        size_t size,
        const safe_format_type_t *types,
        const char *format,
        va_list args);

int
safe_format(
        char *buf,
        size_t size,
        const safe_format_type_t *types,
        const char *format,
         ...);

#endif /* __SAFE_FORMAT_H__ */
