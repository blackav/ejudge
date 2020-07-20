/* -*- c -*- */

#ifndef __BASE32_H__
#define __BASE32_H__

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

#include <stdlib.h>

void
base32_buf(
        unsigned char *outbuf,
        const unsigned char *inbuf,
        size_t insize,
        int upcase_flag);

#endif /* __BASE32_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
