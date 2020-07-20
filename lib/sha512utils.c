/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/sha512utils.h"
#include "ejudge/sha512.h"

#include <string.h>
#include <stdio.h>

void
sha512b16buf(
        char *out,
        size_t out_size,
        const unsigned char *in,
        size_t in_size)
{
    uint8_t raw_hash[SHA512_DIGEST_LENGTH];
    SHA512(in, in_size, raw_hash);
    unsigned char *p = out;
    unsigned char tbuf[256];
    if (out_size < (SHA512_DIGEST_LENGTH * 2 + 1)) {
        p = tbuf;
    }

    for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
        unsigned high = raw_hash[i] >> 4;
        unsigned low = raw_hash[i] & 0x0f;
        if (high <= 9) {
            *p++ = '0' + high;
        } else {
            *p++ = 'a' - 10 + high;
        }
        if (low <= 9) {
            *p++ = '0' + low;
        } else {
            *p++ = 'a' - 10 + low;
        }
    }
    *p = 0;

    if (out_size < (SHA512_DIGEST_LENGTH * 2 + 1)) {
        snprintf(out, out_size, "%s", tbuf);
    }
}
