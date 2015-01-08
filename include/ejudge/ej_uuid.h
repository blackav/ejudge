/* -*- c -*- */
#ifndef __EJ_UUID_H__
#define __EJ_UUID_H__

/* Copyright (C) 2012-2015 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "ejudge/ej_types.h"

int ej_uuid_parse(const unsigned char *str, ej_uuid_t *puuid);
const unsigned char *ej_uuid_unparse(const ej_uuid_t *puuid, const unsigned char *default_value);
void ej_uuid_generate(ej_uuid_t *puuid);
int ej_uuid_supported(void);

const unsigned char *
ej_uuid_unparse_r(
        unsigned char *buf,
        size_t size,
        const ej_uuid_t *puuid,
        const unsigned char *default_value);

#define ej_uuid_is_nonempty(uuid) ((uuid).v[0] || (uuid).v[1] || (uuid).v[2] || (uuid).v[3])
#define ej_uuid_copy(dst, src) (memcpy((dst), (src), 16))
#define ej_uuid_bytes(puuid) (((const unsigned char *) (puuid)))

#endif /* __EJ_UUID_H__ */
