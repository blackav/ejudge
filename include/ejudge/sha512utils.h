/* -*- mode: c; c-basic-offset: 4 -*- */

#ifndef __SHA512UTILS_H__
#define __SHA512UTILS_H__

/* Copyright (C) 2020 Alexander Chernov <cher@ejudge.ru> */

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
#include <stdio.h>

void
sha512b16buf(
        char *out,
        size_t out_size,
        const unsigned char *in,
        size_t in_size);

#endif
