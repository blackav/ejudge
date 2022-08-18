/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/config.h"
#include "ejudge/ej_lzma.h"

#if CONF_HAS_LIBLZMA - 0 == 1
#include <lzma.h>
#endif

int
ej_lzma_is_supported(void)
{
#if CONF_HAS_LIBLZMA - 0 == 1
    return 1;
#else
    return 0;
#endif
}

int
ej_lzma_encode_buf(
        const unsigned char *in_buf,
        size_t in_size,
        unsigned char **p_out_buf,
        size_t *p_out_size)
{
#if CONF_HAS_LIBLZMA - 0 == 1
    // estimate compressed size as twice of the source size
    size_t out_size = 256 + 2 * in_size;
    uint8_t *out_buf = malloc(out_size);
    size_t out_pos = 0;
    lzma_ret ret = lzma_easy_buffer_encode(
        LZMA_PRESET_DEFAULT,
        LZMA_CHECK_NONE,
        NULL,
        in_buf, in_size,
        out_buf, &out_pos, out_size);
    if (ret != LZMA_OK) {
        free(out_buf);
        return -1;
    }
    out_buf[out_pos] = 0;
    out_buf = realloc(out_buf, out_pos + 1);
    *p_out_buf = out_buf;
    *p_out_size = out_pos;

    return 0;
#else
    return -1;
#endif
}

int
ej_lzma_decode_buf(
        const unsigned char *in_buf,
        size_t in_size,
        size_t expected_out_size,
        unsigned char **p_out_buf,
        size_t *p_out_size)
{
#if CONF_HAS_LIBLZMA - 0 == 1
    uint64_t mem_limit = UINT64_MAX;
    uint8_t *out_buf = malloc(expected_out_size + 1);
    size_t in_pos = 0;
    size_t out_pos = 0;
    lzma_ret ret = lzma_stream_buffer_decode(
        &mem_limit,
        0,
        NULL,
        in_buf, &in_pos, in_size,
        out_buf, &out_pos, expected_out_size);
    if (ret != LZMA_OK) {
        free(out_buf);
        return -1;
    }
    out_buf[out_pos] = 0;
    *p_out_buf = out_buf;
    *p_out_size = out_pos;

    return 0;
#else
    return -1;
#endif
}
