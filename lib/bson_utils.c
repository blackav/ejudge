/* -*- mode: c -*- */

/* Copyright (C) 2015-2022 Alexander Chernov <cher@ejudge.ru> */

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

#if HAVE_LIBMONGO_CLIENT - 0 == 1

#include "ejudge/bson_utils.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/errlog.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"

#include <mongo.h>

void
ej_bson_unparse(
        FILE *out,
        const struct _bson *b,
        int is_array)
{
    if (!b) {
        fprintf(out, "NULL");
        return;
    }
    if (is_array) {
        fprintf(out, "[ ");
    } else {
        fprintf(out, "{ ");
    }
    bson_cursor *cursor = bson_cursor_new(b);
    int first = 1;
    while (bson_cursor_next(cursor)) {
        if (!first) fprintf(out, ", ");
        if (!is_array) {
            fprintf(out, "%s : ", bson_cursor_key(cursor));
        }
        bson_type t = bson_cursor_type(cursor);
        switch (t) {
        case BSON_TYPE_DOUBLE:
            break;
        case BSON_TYPE_STRING:
            {
                const char *value = NULL;
                if (bson_cursor_get_string(cursor, &value)) {
                    fprintf(out, "\"%s\"", value);
                }
            }
            break;
        case BSON_TYPE_DOCUMENT:
            {
                bson *doc = NULL;
                if (bson_cursor_get_document(cursor, &doc)) {
                    ej_bson_unparse(out, doc, 0);
                    bson_free(doc);
                }
            }
            break;
        case BSON_TYPE_ARRAY:
            {
                bson *doc = NULL;
                if (bson_cursor_get_array(cursor, &doc)) {
                    ej_bson_unparse(out, doc, 1);
                    bson_free(doc);
                }
            }
            break;
        case BSON_TYPE_BINARY:
            {
                bson_binary_subtype bt = 0;
                const unsigned char *bd = NULL;
                int bz = 0;
                if (bson_cursor_get_binary(cursor, &bt, &bd, &bz)
                    && bt == BSON_BINARY_SUBTYPE_UUID && bz == sizeof(ej_uuid_t)) {
                    ej_uuid_t value;
                    memcpy(&value, bd, sizeof(value));
                    fprintf(out, "\"%s\"", ej_uuid_unparse(&value, NULL));
                }
            }
            break;
        case BSON_TYPE_OID:
            break;
        case BSON_TYPE_BOOLEAN:
            {
                gboolean bb = 0;
                if (bson_cursor_get_boolean(cursor, &bb)) {
                    fprintf(out, "%s", bb?"true":"false");
                }
            }
            break;
        case BSON_TYPE_UTC_DATETIME:
            {
                gint64 ts = 0;
                if (bson_cursor_get_utc_datetime(cursor, &ts)) {
                    time_t tt = (time_t) (ts / 1000);
                    int ms = (int) (ts % 1000);
                    struct tm *ptm = gmtime(&tt);
                    fprintf(out, "\"%d-%02d-%02d %02d:%02d:%02d.%04d\"",
                            ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
                            ptm->tm_hour, ptm->tm_min, ptm->tm_sec, ms);
                }
            }
            break;
        case BSON_TYPE_NULL:
            break;
        case BSON_TYPE_INT32:
            {
                int value = 0;
                if (bson_cursor_get_int32(cursor, &value)) {
                    fprintf(out, "%d", value);
                }
            }
            break;
        case BSON_TYPE_INT64:
            {
                gint64 value = 0;
                if (bson_cursor_get_int64(cursor, &value)) {
                    fprintf(out, "%lld", (long long) value);
                }
            }
            break;
        default:
            break;
        }
        first = 0;
    }
    bson_cursor_free(cursor); cursor = NULL;
    if (is_array) {
        fprintf(out, " ]");
    } else {
        fprintf(out, " }");
    }
}

int
ej_bson_parse_int(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        int *p_value,
        int check_low,
        int low_value,
        int check_high,
        int high_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_INT32) {
        err("parse_bson_int: int32 field type expected for '%s'", field_name);
        return -1;
    }
    int value = 0;
    if (!bson_cursor_get_int32(bc, &value)) {
        err("parse_bson_int: failed to fetch int32 value of '%s'", field_name);
        return -1;
    }
    if ((check_low > 0 && value < low_value) || (check_high > 0 && value >= high_value)) {
        err("parse_bson_int: invalid value of '%s': %d", field_name, value);
        return -1;
    }
    *p_value = value;
    return 1;
}

int
ej_bson_parse_int64(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        long long *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_INT64) {
        err("parse_bson_int: int64 field type expected for '%s'", field_name);
        return -1;
    }
    gint64 value = 0;
    if (!bson_cursor_get_int64(bc, &value)) {
        err("parse_bson_int: failed to fetch int64 value of '%s'", field_name);
        return -1;
    }
    *p_value = value;
    return 1;
}

int
ej_bson_parse_boolean(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        int *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_BOOLEAN) {
        err("parse_bson_boolean: boolean field type expected for '%s'", field_name);
        return -1;
    }
    gboolean value = 0;
    if (!bson_cursor_get_boolean(bc, &value)) {
        err("parse_bson_boolean: failed to fetch boolean value of '%s'", field_name);
        return -1;
    }
    *p_value = !!value;
    return 1;
}

int
ej_bson_parse_boolean_uc(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        unsigned char *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_BOOLEAN) {
        err("parse_bson_boolean: boolean field type expected for '%s'", field_name);
        return -1;
    }
    gboolean value = 0;
    if (!bson_cursor_get_boolean(bc, &value)) {
        err("parse_bson_boolean: failed to fetch boolean value of '%s'", field_name);
        return -1;
    }
    *p_value = !!value;
    return 1;
}

int
ej_bson_parse_utc_datetime(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        time_t *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_UTC_DATETIME) {
        err("parse_bson_utc_datetime: utc_datetime field type expected for '%s'", field_name);
        return -1;
    }
    gint64 value = 0;
    if (!bson_cursor_get_utc_datetime(bc, &value)) {
        err("parse_bson_utc_datetime: failed to fetch utc_datetime value of '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = (time_t) (value / 1000);
    }
    return 1;
}

int
ej_bson_parse_utc_datetime_64(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        ej_time64_t *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_UTC_DATETIME) {
        err("parse_bson_utc_datetime: utc_datetime field type expected for '%s'", field_name);
        return -1;
    }
    gint64 value = 0;
    if (!bson_cursor_get_utc_datetime(bc, &value)) {
        err("parse_bson_utc_datetime: failed to fetch utc_datetime value of '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = value / 1000LL;
    }
    return 1;
}

int
ej_bson_parse_uuid(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        ej_uuid_t *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_BINARY) {
        err("parse_bson_uuid: uuid field type expected for '%s'", field_name);
        return -1;
    }

    bson_binary_subtype bt = 0;
    const unsigned char *bd = NULL;
    int bz = 0;
    if (!bson_cursor_get_binary(bc, &bt, &bd, &bz)) {
        err("parse_bson_uuid: failed to fetch binary data for '%s'", field_name);
        return -1;
    }
    if (bt != BSON_BINARY_SUBTYPE_UUID || bz != sizeof(ej_uuid_t)) {
        err("parse_bson_uuid: invalid binary data for in '%s'", field_name);
        return -1;
    }
    if (p_value) {
        memcpy(p_value, bd, sizeof(ej_uuid_t));
    }
    return 1;
}

int
ej_bson_parse_oid(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        unsigned char *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_OID) {
        err("parse_bson_oid: oid field type expected for '%s'", field_name);
        return -1;
    }

    const unsigned char *p = NULL;
    if (!bson_cursor_get_oid(bc, &p) || !p) {
        err("parse_bson_oid: failed to fetch oid for '%s'", field_name);
        return -1;
    }
    memcpy(p_value, p, 12);
    return 1;
}

int
ej_bson_parse_ip(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        ej_ip_t *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_STRING) {
        err("parse_bson_ip: string field type expected for '%s'", field_name);
        return -1;
    }
    const char *data = NULL;
    if (!bson_cursor_get_string(bc, &data)) {
        err("parse_bson_ip: failed to fetch string for '%s'", field_name);
        return -1;
    }
    if (!data) {
        err("parse_bson_ip: invalid string for in '%s'", field_name);
        return -1;
    }
    if (xml_parse_ipv6(NULL, 0, 0, 0, data, p_value) < 0) return -1;
    return 1;
}

int
ej_bson_parse_string(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        unsigned char **p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_STRING) {
        err("parse_bson_string: string field type expected for '%s'", field_name);
        return -1;
    }
    const char *data = NULL;
    if (!bson_cursor_get_string(bc, &data)) {
        err("parse_bson_string: failed to fetch string for '%s'", field_name);
        return -1;
    }
    if (!data) {
        err("parse_bson_string: invalid string for in '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = xstrdup(data);
    }
    return 1;
}

int
ej_bson_parse_array(
        bson_cursor *bc,
        const unsigned char *field_name,
        bson **p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_ARRAY) {
        err("parse_bson_array: array field type expected for '%s'", field_name);
        return -1;
    }
    bson *data = NULL;
    if (!bson_cursor_get_array(bc, &data) || !data) {
        err("parse_bson_array: failed to fetch array for '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = data;
    } else {
        bson_free(data);
    }
    return 1;
}

int
ej_bson_parse_document(
        bson_cursor *bc,
        const unsigned char *field_name,
        bson **p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_DOCUMENT) {
        err("parse_bson_document: document field type expected for '%s', got %s", field_name, bson_cursor_type_as_string(bc));
        return -1;
    }
    bson *data = NULL;
    if (!bson_cursor_get_document(bc, &data) || !data) {
        err("parse_bson_document: failed to fetch document for '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = data;
    } else {
        bson_free(data);
    }
    return 1;
}

void
ej_bson_append_uuid(
        struct _bson *b,
        const unsigned char *key,
        const ej_uuid_t *p_uuid)
{
    bson_append_binary(b, key, BSON_BINARY_SUBTYPE_UUID, (const unsigned char *) p_uuid, sizeof(*p_uuid));
}

void
ej_bson_append_ip(
        struct _bson *b,
        const unsigned char *key,
        const ej_ip_t *p_ip)
{
    bson_append_string(b, key, xml_unparse_ipv6(p_ip), -1);
}

bson *
ej_bson_unparse_array_int(const int *values, int count)
{
    bson *arr = bson_new();
    for (int i = 0; i < count; ++i) {
        unsigned char buf[32];
        sprintf(buf, "%d", i);
        bson_append_int32(arr, buf, values[i]);
    }
    bson_finish(arr);
    return arr;
}

bson *
ej_bson_unparse_array_uuid(
        ej_uuid_t *values,
        int count)
{
    bson *arr = bson_new();
    for (int i = 0; i < count; ++i) {
        unsigned char buf[32];
        sprintf(buf, "%d", i);
        ej_bson_append_uuid(arr, buf, &values[i]);
    }
    bson_finish(arr);
    return arr;

}

#endif

int ej_bson_force_link_dummy = 0;

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
