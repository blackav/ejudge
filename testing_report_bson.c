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

#include "ejudge/testing_report_xml.h"

#include "ejudge/xalloc.h"

#include <stdio.h>

#if HAVE_LIBMONGOC - 0 > 0

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#else
#include <mongoc.h>
#endif

static int
parse_testing_report_bson(bson_t *b, testing_report_xml_t r)
{
    return -1;
}

int testing_report_bson_available(void)
{
    return 1;
}
testing_report_xml_t
testing_report_parse_data(
        const unsigned char *data,
        unsigned int size)
{
    bson_t *b = bson_new_from_data(data, size);
    if (!b) return NULL;
    testing_report_xml_t r = NULL;
    XCALLOC(r, 1);
    if (parse_testing_report_bson(b, r) < 0) {
        bson_destroy(b);
        testing_report_free(r);
        return NULL;
    }
    bson_destroy(b);
    return r;
}
#else
// stubs when bson format is not available
int testing_report_bson_available(void)
{
    return 0;
}
testing_report_xml_t
testing_report_parse_data(
        const unsigned char *data,
        unsigned int size)
{
    return NULL;
}
#endif
