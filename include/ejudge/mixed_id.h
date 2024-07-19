/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __MIXED_ID_H__
#define __MIXED_ID_H__

/* Copyright (C) 2023-2024 Alexander Chernov <cher@ejudge.ru> */

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

#ifdef __GCC__
#define GCC_ATTRIB(x) __attribute__(x)
#else
#define GCC_ATTRIB(x)
#endif

typedef GCC_ATTRIB((aligned(16))) struct ej_mixed_id_t
{
  unsigned char data[16];
} ej_mixed_id_t;

// binary representation -> text representation
// dst_dst must be large enough (64 bytes)
unsigned char *
mixed_id_marshall(
        unsigned char dst_str[64],
        int mixed_id_kind,
        const ej_mixed_id_t *id);

// text representation -> binary representation
// returns 0 on success, -1 on failure
int
mixed_id_unmarshall(
        ej_mixed_id_t *id,
        int mixed_id_kind,
        const unsigned char *src_str);

int
mixed_id_parse_kind(const unsigned char *str);

int
mixed_it_parse_kind_2(const unsigned char *str, size_t *p_shift);

const unsigned char *
mixed_id_unparse_kind(int kind);

#endif /* __MIXED_ID_H__ */
