/* -*- c -*- */

#ifndef __BSON_UTILS_H__
#define __BSON_UTILS_H__

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"

#include <stdio.h>
#include <time.h>

struct _bson;
struct _bson_cursor;

void
ej_bson_unparse(
        FILE *out,
        const struct _bson *,
        int is_array);

int
ej_bson_parse_int(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        int *p_value,
        int check_low,
        int low_value,
        int check_high,
        int high_value);
int
ej_bson_parse_utc_datetime(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        time_t *p_value);
int
ej_bson_parse_uuid(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        ej_uuid_t *p_value);
int
ej_bson_parse_ip(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        ej_ip_t *p_value);
int
ej_bson_parse_string(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        unsigned char **p_value);
int
ej_bson_parse_array(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        struct _bson **p_value);
int
ej_bson_parse_document(
        struct _bson_cursor *bc,
        const unsigned char *field_name,
        struct _bson **p_value);

void
ej_bson_append_uuid(
        struct _bson *b,
        const unsigned char *key,
        const ej_uuid_t *p_uuid);
void
ej_bson_append_ip(
        struct _bson *b,
        const unsigned char *key,
        const ej_ip_t *p_ip);

struct _bson *
ej_bson_unparse_array_int(
        const int *values,
        int count);
struct _bson *
ej_bson_unparse_array_uuid(
        ej_uuid_t *values,
        int count);

#endif /* __BSON_UTILS_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
