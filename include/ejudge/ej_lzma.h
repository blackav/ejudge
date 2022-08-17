/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __EJ_LZMA_H__
#define __EJ_LZMA_H__

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

int ej_lzma_is_supported(void);

int
ej_lzma_encode_buf(
        const unsigned char *in_buf,
        size_t in_size,
        unsigned char **p_out_buf,
        size_t *p_out_size);

int
ej_lzma_decode_buf(
        const unsigned char *in_buf,
        size_t in_size,
        size_t expected_out_size,
        unsigned char **p_out_buf,
        size_t *p_out_size);

#endif /* __EJ_LZMA_H__ */
