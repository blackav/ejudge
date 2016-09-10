/* -*- mode: c -*- */

/* Copyright (C) 2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/bson_utils.h"
#include "ejudge/xalloc.h"

#include "telegram_pbs.h"

#include <mongo.h>


struct telegram_pbs *
telegram_pbs_free(struct telegram_pbs *pbs)
{
    if (pbs) {
        xfree(pbs->_id);
        xfree(pbs);
    }
    return NULL;
}

struct telegram_pbs *
telegram_pbs_create(const unsigned char *_id)
{
    struct telegram_pbs *pbs = NULL;
    XCALLOC(pbs, 1);
    pbs->_id = xstrdup(_id);
    return pbs;
}

struct telegram_pbs *
telegram_pbs_parse_bson(struct _bson *bson)
{
    bson_cursor *bc = NULL;
    struct telegram_pbs *pbs = NULL;

    XCALLOC(pbs, 1);
    bc = bson_cursor_new(bson);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_string(bc, "_id", &pbs->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "update_id")) {
            if (ej_bson_parse_int64(bc, "update_id", &pbs->update_id) < 0) goto cleanup;
        }
    }
    bson_cursor_free(bc);
    return pbs;

cleanup:
    telegram_pbs_free(pbs);
    return NULL;
}

bson *
telegram_pbs_unparse_bson(const struct telegram_pbs *pbs)
{
    if (!pbs) return NULL;

    bson *bson = bson_new();
    if (pbs->_id && *pbs->_id) {
        bson_append_string(bson, "_id", pbs->_id, strlen(pbs->_id));
    }
    if (pbs->update_id != 0) {
        bson_append_int64(bson, "update_id", pbs->update_id);
    }
    bson_finish(bson);
    return bson;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
