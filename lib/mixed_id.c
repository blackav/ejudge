/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/mixed_id.h"
#include "ejudge/ulid.h"

#include <uuid/uuid.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

unsigned char *
mixed_id_marshall(
        unsigned char dst_str[64],
        int mixed_id_kind,
        const ej_mixed_id_t *id)
{
    switch (mixed_id_kind) {
    case MIXED_ID_NONE:
        dst_str[0] = 0;
        break;
    case MIXED_ID_STRING:
        memcpy(dst_str, id->data, 16);
        dst_str[16] = 0;
        break;
    case MIXED_ID_U64:
        sprintf(dst_str, "%llu", *((const unsigned long long*) id->data));
        break;
    case MIXED_ID_UUID:
        uuid_unparse(id->data, dst_str);
        break;
    case MIXED_ID_ULID:
        ulid_marshall(dst_str, id->data);
        break;
    default:
        abort();
    }
    return dst_str;
}

int
mixed_id_unmarshall(
        ej_mixed_id_t *id,
        int mixed_id_kind,
        const unsigned char *src_str)
{
    switch (mixed_id_kind) {
    case MIXED_ID_NONE:
        memset(id, 0, sizeof(*id));
        break;
    case MIXED_ID_STRING: {
        if (!src_str) {
            return -1;
        }
        int len = strlen(src_str);
        if (len > (int) sizeof(*id)) {
            // string is too long
            return -1;
        }
        for (int i = 0; i < len; ++i) {
            if (!src_str[i]) break;
            if (src_str[i] < ' ' || src_str[i] == '\\' || src_str[i] == '\''
                || src_str[i] == '\"' || src_str[i] >= 0x7f) {
                return -1;
            }
        }
        strncpy(id->data, src_str, sizeof(*id));
        break;
    }
    case MIXED_ID_U64: {
        if (!src_str) {
            return -1;
        }
        errno = 0;
        char *eptr = NULL;
        unsigned long long value = strtoull(src_str, &eptr, 10);
        if (errno || *eptr || (char *) src_str == eptr) {
            return -1;
        }
        memcpy(id->data, &value, sizeof(value));
        memset(id->data + sizeof(value), 0, sizeof(value));
        break;
    }
    case MIXED_ID_UUID:
        if (!src_str) {
            return -1;
        }
        return uuid_parse(src_str, id->data);
    case MIXED_ID_ULID:
        if (!src_str) {
            return -1;
        }
        return ulid_unmarshall(id->data, src_str);
    default:
        abort();
    }
    return 0;
}

// "", "str", "u64", "uuid", "ulid"
int
mixed_id_parse_kind(const unsigned char *str)
{
    if (!str || !*str) return 0;
    if (str[0] == 's') {
        if (str[1] == 't' && str[2] == 'r' && str[3] == 0) {
            return MIXED_ID_STRING;
        } else {
            return -1;
        }
    } else if (str[0] == 'u') {
        if (str[1] == '6' && str[2] == '4' && str[3] == 0) {
            return MIXED_ID_U64;
        } else if (str[1] == 'u' && str[2] == 'i' && str[3] == 'd' && !str[4]){
            return MIXED_ID_UUID;
        } else if (str[1] == 'l' && str[2] == 'i' && str[3] == 'd' && !str[4]){
            return MIXED_ID_ULID;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}

const unsigned char *
mixed_id_unparse_kind(int kind)
{
    if (kind > 0 && kind < MIXED_ID_LAST) {
        static const unsigned char ids[][8] =
        {
            "", "str", "u64", "uuid", "ulid",
        };
        return ids[kind];
    }
    return "";
}
