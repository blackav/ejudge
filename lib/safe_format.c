/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/safe_format.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

int
safe_format_validate(const safe_format_type_t *types, const char *format)
{
    size_t type_idx = 0;
    size_t i = 0;
    size_t len = strlen(format);
    while (i < len) {
        if (format[i] != '%') {
            ++i;
            continue;
        }
        // [-|+]?digits([.]digits)d
        ++i;
        if (i == len) return -1;
        if (format[i] == '%') {
            ++i;
            continue;
        }
        if (!types[type_idx]) return -1;
        if (format[i] == '+' || format[i] == '-') {
            ++i;
            if (i == len) return -1;
        }
        if (format[i] == '0') {
            ++i;
            if (i == len) return -1;
        }
        if (format[i] >= '0' && format[i] <= '9') {
            int val = 0;
            while (format[i] >= 0 && format[i] <= '9') {
                val = val * 10 + (format[i] - '0');
                if (val > 100) return -1;
                ++i;
            }
            if (i == len) return -1;
        }
        if (format[i] == '.') {
            ++i;
            if (i == len) return -1;
            if (format[i] < '0' || format[i] > '9') return -1;
            int val = 0;
            while (format[i] >= 0 && format[i] <= '9') {
                val = val * 10 + (format[i] - '0');
                if (val > 100) return -1;
                ++i;
            }
            if (i == len) return -1;
        }
        if (format[i] == 'd') {
            if (types[type_idx++] != SAFE_FORMAT_INT) return -1;
            ++i;
        } else {
            return -1;
        }
    }
    if (types[type_idx]) return -1;
    return 0;
}

int
safe_format_v(char *buf, size_t size, const safe_format_type_t *types, const char *format, va_list args)
{
    size_t j = 0;
    size_t type_idx = 0;
    size_t i = 0;
    size_t len = strlen(format);
    while (i < len) {
        if (format[i] != '%') {
            if (j < size) {
                buf[j] = format[i];
            }
            ++j;
            ++i;
            continue;
        }
        ++i;
        if (i == len) return -1;
        if (format[i] == '%') {
            if (j < size) {
                buf[j] = format[i];
            }
            ++j;
            ++i;
            continue;
        }
        if (!types[type_idx]) return -1;
        unsigned char plus_flag = 0;
        unsigned char minus_flag = 0;
        unsigned char zero_flag = 0;
        int width = -1;
        int precision = -1;
        if (format[i] == '+') {
            plus_flag = 1;
            ++i;
        } else if (format[i] == '-') {
            minus_flag = 1;
            ++i;
        }
        if (format[i] == '0') {
            zero_flag = 1;
            ++i;
        }
        if (format[i] >= '0' && format[i] <= '9') {
            int val = 0;
            while (format[i] >= 0 && format[i] <= '9') {
                val = val * 10 + (format[i] - '0');
                if (val > 100) return -1;
                ++i;
            }
            width = val;
        }
        if (format[i] == '.') {
            ++i;
            if (format[i] < '0' || format[i] > '9') return -1;
            int val = 0;
            while (format[i] >= 0 && format[i] <= '9') {
                val = val * 10 + (format[i] - '0');
                if (val > 100) return -1;
                ++i;
            }
            precision = val;
        }
        if (format[i] == 'd') {
            if (types[type_idx++] != SAFE_FORMAT_INT) return -1;
            ++i;
            int value = va_arg(args, int);
            (void) value;
            (void) precision;
            (void) width;
            (void) zero_flag;
            (void) minus_flag;
            (void) plus_flag;
            // TODO
            abort();
        } else {
            return -1;
        }
    }
    if (size > 0) buf[size-1] = 0;
    if (types[type_idx]) return -1;
    return (int) j;
}

int
safe_format(char *buf, size_t size, const safe_format_type_t *types, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int r = safe_format_v(buf, size, types, format, args);
    va_end(args);
    return r;
}
