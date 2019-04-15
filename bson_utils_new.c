/* -*- mode: c -*- */

/* Copyright (C) 2019 Alexander Chernov <cher@ejudge.ru> */

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

#if HAVE_LIBMONGOC - 0 > 0

#include "ejudge/bson_utils.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/errlog.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#else
#include <mongoc.h>
#endif

void
ej_bson_unparse_new(
        FILE *out,
        const bson_t *b,
        int is_array)
{
    char *json = bson_as_json(b, NULL);
    fprintf(out, "%s", json);
    bson_free(json);
}

int
ej_bson_parse_int_new(
        void *vbc,
        const unsigned char *field_name,
        int *p_value,
        int check_low,
        int low_value,
        int check_high,
        int high_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_INT32) {
        err("parse_bson_int: int32 field type expected for '%s'", field_name);
        return -1;
    }
    int value = bson_iter_int32(bc);
    if ((check_low > 0 && value < low_value) || (check_high > 0 && value >= high_value)) {
        err("parse_bson_int: invalid value of '%s': %d", field_name, value);
        return -1;
    }
    *p_value = value;
    return 1;
}

int
ej_bson_parse_int64_new(
        void *vbc,
        const unsigned char *field_name,
        long long *p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_INT64) {
        err("parse_bson_int: int64 field type expected for '%s'", field_name);
        return -1;
    }
    long long value = bson_iter_int64(bc);
    *p_value = value;
    return 1;
}

int
ej_bson_parse_boolean_new(
        void *vbc,
        const unsigned char *field_name,
        int *p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_BOOL) {
        err("parse_bson_int: boolean field type expected for '%s'", field_name);
        return -1;
    }
    int value = bson_iter_bool(bc);
    *p_value = !!value;
    return 1;
}

int
ej_bson_parse_boolean_uc_new(
        void *vbc,
        const unsigned char *field_name,
        unsigned char *p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_BOOL) {
        err("parse_bson_int: boolean field type expected for '%s'", field_name);
        return -1;
    }
    int value = bson_iter_bool(bc);
    *p_value = !!value;
    return 1;
}

int
ej_bson_parse_utc_datetime_new(
        void *vbc,
        const unsigned char *field_name,
        time_t *p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_DATE_TIME) {
        err("parse_bson_int: datetime field type expected for '%s'", field_name);
        return -1;
    }
    long long value = bson_iter_date_time(bc);
    if (p_value) {
        *p_value = (time_t) (value / 1000);
    }
    return 1;
}

int
ej_bson_parse_utc_datetime_64_new(
        void *vbc,
        const unsigned char *field_name,
        ej_time64_t *p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_DATE_TIME) {
        err("parse_bson_int: datetime field type expected for '%s'", field_name);
        return -1;
    }
    long long value = bson_iter_date_time(bc);
    if (p_value) {
        *p_value = value / 1000;
    }
    return 1;
}

int
ej_bson_parse_uuid_new(
        void *vbc,
        const unsigned char *field_name,
        ej_uuid_t *p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_BINARY) {
        err("parse_bson_uuid: UUID field type expected for '%s', actual type is %d", field_name, bson_iter_type(bc));
        return -1;
    }
    bson_subtype_t bt = 0;
    uint32_t bz = 0;
    const uint8_t *bd = NULL;
    bson_iter_binary(bc, &bt, &bz, &bd);
    if ((bt != BSON_SUBTYPE_UUID && bt != BSON_SUBTYPE_UUID_DEPRECATED) || bz != sizeof(ej_uuid_t)) {
        err("parse_bson_uuid: invalid binary data for in '%s'", field_name);
        return -1;
    }
    if (p_value) {
        memcpy(p_value, bd, sizeof(ej_uuid_t));
    }
    return 1;
}

int
ej_bson_parse_oid_new(
        void *vbc,
        const unsigned char *field_name,
        unsigned char *p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_OID) {
        err("parse_bson_int: OID field type expected for '%s'", field_name);
        return -1;
    }
    const bson_oid_t *p = bson_iter_oid(bc);
    memcpy(p_value, p, 12);
    return 1;
}

int
ej_bson_parse_ip_new(
        void *vbc,
        const unsigned char *field_name,
        ej_ip_t *p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_UTF8) {
        err("parse_bson_int: IP field type expected for '%s'", field_name);
        return -1;
    }
    uint32_t z = 0;
    const char *data = bson_iter_utf8(bc, &z);
    if (!data || strlen(data) != z) {
        err("parse_bson_ip: invalid string for in '%s'", field_name);
        return -1;
    }
    if (xml_parse_ipv6(NULL, 0, 0, 0, data, p_value) < 0) return -1;
    return 1;
}

int
ej_bson_parse_string_new(
        void *vbc,
        const unsigned char *field_name,
        unsigned char **p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_UTF8) {
        err("parse_bson_int: string field type expected for '%s'", field_name);
        return -1;
    }
    uint32_t z = 0;
    const char *data = bson_iter_utf8(bc, &z);
    if (!data || strlen(data) != z) {
        err("parse_bson_ip: invalid string for in '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = xstrdup(data);
    }
    return 1;
}

int
ej_bson_parse_array_new(
        void *vbc,
        const unsigned char *field_name,
        bson_t **p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_ARRAY) {
        err("parse_bson_int: array field type expected for '%s'", field_name);
        return -1;
    }
    const uint8_t *p = NULL;
    uint32_t z = 0;
    bson_iter_array(bc, &z, &p);
    if (p_value) {
        *p_value = bson_new_from_data(p, z);
    }
    return 1;
}

int
ej_bson_parse_sha1_new(
        void *vbc,
        const unsigned char *field_name,
        unsigned char *p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_BINARY) {
        err("ej_bson_parse_sha1: BINARY field type expected for '%s', actual type is %d", field_name, bson_iter_type(bc));
        return -1;
    }
    bson_subtype_t bt = 0;
    uint32_t bz = 0;
    const uint8_t *bd = NULL;
    bson_iter_binary(bc, &bt, &bz, &bd);
    if (bt != BSON_SUBTYPE_USER || bz != 20) {
        err("ej_bson_parse_sha1: invalid binary data for in '%s'", field_name);
        return -1;
    }
    if (p_value) {
        memcpy(p_value, bd, 20);
    }
    return 1;
}

int
ej_bson_parse_document_new(
        void *vbc,
        const unsigned char *field_name,
        bson_t **p_value)
{
    bson_iter_t *bc = vbc;
    if (bson_iter_type(bc) != BSON_TYPE_DOCUMENT) {
        err("parse_bson_int: document field type expected for '%s'", field_name);
        return -1;
    }
    const uint8_t *p = NULL;
    uint32_t z = 0;
    bson_iter_document(bc, &z, &p);
    if (p_value) {
        *p_value = bson_new_from_data(p, z);
    }
    return 1;
}

void
ej_bson_append_uuid_new(
        bson_t *b,
        const unsigned char *key,
        const ej_uuid_t *p_uuid)
{
    bson_append_binary(b, key, -1, BSON_SUBTYPE_UUID, (const uint8_t *) p_uuid, sizeof(*p_uuid));
}

void
ej_bson_append_ip_new(
        bson_t *b,
        const unsigned char *key,
        const ej_ip_t *p_ip)
{
    bson_append_utf8(b, key, -1, xml_unparse_ipv6(p_ip), -1);
}

bson_t *
ej_bson_unparse_array_int_new(const int *values, int count)
{
    bson_t *arr = bson_new();
    for (int i = 0; i < count; ++i) {
        unsigned char buf[32];
        sprintf(buf, "%d", i);
        bson_append_int32(arr, buf, -1, values[i]);
    }
    return arr;
}

bson_t *
ej_bson_unparse_array_uuid_new(
        ej_uuid_t *values,
        int count)
{
    bson_t *arr = bson_new();
    for (int i = 0; i < count; ++i) {
        unsigned char buf[32];
        sprintf(buf, "%d", i);
        ej_bson_append_uuid_new(arr, buf, &values[i]);
    }
    return arr;
}

#endif

int ej_bson_new_force_link_dummy = 0;

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
