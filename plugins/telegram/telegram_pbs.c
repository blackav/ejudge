/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2016-2022 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"
#include "ejudge/config.h"

#include "telegram_pbs.h"
#include "mongo_conn.h"

#if HAVE_LIBMONGOC - 0 > 0
struct _bson_t;
typedef struct _bson_t ej_bson_t;
#endif

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#endif

#include <errno.h>

#define TELEGRAM_BOTS_TABLE_NAME "telegram_bots"

static ej_bson_t *
telegram_pbs_unparse_bson(const struct telegram_pbs *pbs);
static struct telegram_pbs *
telegram_pbs_parse_bson(const ej_bson_t *bson);

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

static struct telegram_pbs *
telegram_pbs_parse_bson(const ej_bson_t *bson)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_iter_t iter, * const bc = &iter;
    struct telegram_pbs *pbs = NULL;

    if (!bson_iter_init(&iter, bson)) goto cleanup;

    XCALLOC(pbs, 1);
    while (bson_iter_next(&iter)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_string_new(bc, "_id", &pbs->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "update_id")) {
            if (ej_bson_parse_int64_new(bc, "update_id", &pbs->update_id) < 0) goto cleanup;
        }
    }

    return pbs;

cleanup:
    telegram_pbs_free(pbs);
    return NULL;
#else
    return NULL
#endif
}

static ej_bson_t *
telegram_pbs_unparse_bson(const struct telegram_pbs *pbs)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!pbs) return NULL;

    bson_t *bson = bson_new();
    if (pbs->_id && *pbs->_id) {
        bson_append_utf8(bson, "_id", -1, pbs->_id, strlen(pbs->_id));
    }
    if (pbs->update_id != 0) {
        bson_append_int64(bson, "update_id", -1, pbs->update_id);
    }
    return bson;
#else
    return NULL;
#endif
}

int
telegram_pbs_save(struct mongo_conn *conn, const struct telegram_pbs *pbs)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return -1;

    int retval = -1;
    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    bson_t *bson = NULL;
    bson_error_t error;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_BOTS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }
    query = bson_new();
    bson_append_utf8(query, "_id", -1, pbs->_id, -1);
    bson = telegram_pbs_unparse_bson(pbs);

    if (!mongoc_collection_update(coll, MONGOC_UPDATE_UPSERT, query, bson, NULL, &error)) {
        err("telegram_chat_save: failed: %s", error.message);
        goto cleanup;
    }

    retval = 0;

cleanup:
    if (coll) mongoc_collection_destroy(coll);
    if (query) bson_destroy(query);
    if (bson) bson_destroy(bson);
    return retval;
#else
    return 0;
#endif
}

struct telegram_pbs *
telegram_pbs_fetch(struct mongo_conn *conn, const unsigned char *bot_id)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return NULL;

    bson_t *query = NULL;
    mongoc_cursor_t *cursor = NULL;
    const bson_t *doc = NULL;
    struct telegram_pbs *retval = NULL;
    mongoc_collection_t *coll = NULL;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_BOTS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }
    query = bson_new();
    bson_append_utf8(query, "_id", -1, bot_id, -1);
    cursor = mongoc_collection_find_with_opts(coll, query, NULL, NULL);
    if (cursor && mongoc_cursor_next(cursor, &doc)) {
        retval = telegram_pbs_parse_bson(doc);
        goto cleanup;
    }

    if (cursor) mongoc_cursor_destroy(cursor);
    cursor = NULL;
    bson_destroy(query); query = NULL;
    mongoc_collection_destroy(coll); coll = NULL;
    retval = telegram_pbs_create(bot_id);
    telegram_pbs_save(conn, retval);

cleanup:
    if (cursor) mongoc_cursor_destroy(cursor);
    if (coll) mongoc_collection_destroy(coll);
    if (query) bson_destroy(query);
    return retval;
#else
    return NULL;
#endif
}
