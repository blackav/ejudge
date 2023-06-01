/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __MIXED_ID_H__
#define __MIXED_ID_H__

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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

// binary representation -> text representation
// dst_dst must be large enough (64 bytes)
void
mixed_id_marshall(
        unsigned char dst_str[64],
        int mixed_id_kind,
        const unsigned char src_bin[16]);

// text representation -> binary representation
// returns 0 on success, -1 on failure
int
mixed_id_unmarshall(
        unsigned char *dst_bin[16],
        int mixed_id_kind,
        const unsigned char *src_str);

#endif /* __MIXED_ID_H__ */
