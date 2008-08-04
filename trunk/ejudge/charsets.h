/* -*- c -*- */
/* $Id$ */
#ifndef __CHARSETS_H__
#define __CHARSETS_H__

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

struct html_armor_buffer;

int charset_get_id(const unsigned char *charset_str);

const unsigned char *charset_decode_buf(int id, unsigned char *buf, size_t size);
const unsigned char *charset_decode_to_buf(int id, unsigned char *buf, size_t size,
                                     const unsigned char *str);
const unsigned char *charset_decode(int id, struct html_armor_buffer *ab,
                                    const unsigned char *str);
unsigned char *charset_decode_heap(int id, unsigned char *str);
unsigned char *charset_decode_to_heap(int id, const unsigned char *str);

const unsigned char *
charset_encode(
        int id,
        struct html_armor_buffer *ab,
        const unsigned char *str);
unsigned char *
charset_encode_heap(
        int id,
        unsigned char *str);
unsigned char *
charset_decode_to_heap(
        int id,
        const unsigned char *str);

#endif /* __CHARSETS_H__ */
