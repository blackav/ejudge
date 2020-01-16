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

#include "ejudge/base32.h"

#include <stdlib.h>

void
base32_buf(unsigned char *outbuf, const unsigned char *inbuf, size_t insize, int upcase_flag)
{
    if (!inbuf || !insize) {
        *outbuf = 0;
        return;
    }

    size_t encsize = (insize * 8 + 4) / 5;
    outbuf += encsize;
    *outbuf-- = 0;

    // assume LE memory layout
    unsigned int work = 0;
    int freebits = 32;

    while (1) {
        if (freebits >= 8 && insize > 0) {
            work |= *inbuf++ << (32 - freebits);
            freebits -= 8;
            --insize;
        }
        if (freebits >= 32) break;
        unsigned val = work & 0x1f;
        work >>= 5;
        freebits += 5;
        if (val <= 9) {
            val += '0';
        } else if (upcase_flag) {
            val += 'A' - 10;
        } else {
            val += 'a' - 10;
        }
        *outbuf-- = val;
    }
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
