/* -*- mode: c -*- */

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "checker_internal.h"

#include <errno.h>

int
checker_stoi(const char *str, int base, int *p_int)
{
    if (!str || !*str) return -1;
    errno = 0;
    char *eptr = NULL;
    long value = strtol(str, &eptr, base);
    if (errno || *eptr) return -1;
    if ((int) value != value) return -1;
    if (p_int) *p_int = value;
    return 1;
}
