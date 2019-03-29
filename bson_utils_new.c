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

#if HAVE_LIBMONGOC - 0 == 1

#include "ejudge/bson_utils.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/errlog.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"

#include <mongoc/mongoc.h>

void
ej_bson_unparse_new(
        FILE *out,
        const bson_t *b,
        int is_array)
{
}

int
ej_bson_parse_int_new(
        void *bc,
        const unsigned char *field_name,
        int *p_value,
        int check_low,
        int low_value,
        int check_high,
        int high_value)
{
    return 0;
}

int
ej_bson_parse_int64_new(
        void *bc,
        const unsigned char *field_name,
        long long *p_value)
{
    return 0;
}

int
ej_bson_parse_boolean_new(
        void *bc,
        const unsigned char *field_name,
        int *p_value)
{
    return 0;
}

int
ej_bson_parse_boolean_uc_new(
        void *bc,
        const unsigned char *field_name,
        unsigned char *p_value)
{
    return 0;
}

int
ej_bson_parse_utc_datetime_new(
        void *bc,
        const unsigned char *field_name,
        time_t *p_value)
{
    return 0;
}

int
ej_bson_parse_utc_datetime_64_new(
        void *bc,
        const unsigned char *field_name,
        ej_time64_t *p_value)
{
    return 0;
}

int
ej_bson_parse_uuid_new(
        void *bc,
        const unsigned char *field_name,
        ej_uuid_t *p_value)
{
    return 0;
}

int
ej_bson_parse_oid_new(
        void *bc,
        const unsigned char *field_name,
        unsigned char *p_value)
{
    return 0;
}

int
ej_bson_parse_ip_new(
        void *bc,
        const unsigned char *field_name,
        ej_ip_t *p_value)
{
    return 0;
}

int
ej_bson_parse_string_new(
        void *bc,
        const unsigned char *field_name,
        unsigned char **p_value)
{
    return 0;
}

int
ej_bson_parse_array_new(
        void *bc,
        const unsigned char *field_name,
        bson_t **p_value)
{
    return 0;
}

int
ej_bson_parse_document_new(
        void *bc,
        const unsigned char *field_name,
        bson_t **p_value)
{
    return 0;
}

void
ej_bson_append_uuid_new(
        bson_t *b,
        const unsigned char *key,
        const ej_uuid_t *p_uuid)
{
}

void
ej_bson_append_ip_new(
        bson_t *b,
        const unsigned char *key,
        const ej_ip_t *p_ip)
{
}

bson_t *
ej_bson_unparse_array_int_new(const int *values, int count)
{
    return NULL;
}

bson_t *
ej_bson_unparse_array_uuid_new(
        ej_uuid_t *values,
        int count)
{
    return NULL;
}

#endif

int ej_bson_new_force_link_dummy = 0;

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
