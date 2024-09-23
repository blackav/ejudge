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

#include "telegram_chat.h"

#include "ejudge/bson_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"

#include "mongo_conn.h"

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#endif

#include <errno.h>
#include <string.h>

#if HAVE_LIBMONGOC - 0 > 0
struct _bson_t;
typedef struct _bson_t ej_bson_t;
#endif

#define TELEGRAM_CHATS_TABLE_NAME "telegram_chats"

static struct telegram_chat *
telegram_chat_parse_bson(const ej_bson_t *bson);
static ej_bson_t *
telegram_chat_unparse_bson(const struct telegram_chat *tc);

struct telegram_chat *
telegram_chat_free(struct telegram_chat *tc)
{
    if (tc) {
        xfree(tc->type);
        xfree(tc->title);
        xfree(tc->username);
        xfree(tc->first_name);
        xfree(tc->last_name);
        memset(tc, 0xff, sizeof(*tc));
        xfree(tc);
    }
    return NULL;
}

struct telegram_chat *
telegram_chat_create(void)
{
    struct telegram_chat *tc = NULL;
    XCALLOC(tc, 1);
    return tc;
}

static struct telegram_chat *
telegram_chat_parse_bson(const ej_bson_t *bson)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_iter_t iter, * const bc = &iter;
    struct telegram_chat *tc = NULL;

    if (!bson_iter_init(&iter, bson)) goto cleanup;

    XCALLOC(tc, 1);
    while (bson_iter_next(&iter)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_int64_new(bc, "_id", &tc->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "type")) {
            if (ej_bson_parse_string_new(bc, "type", &tc->type) < 0) goto cleanup;
        } else if (!strcmp(key, "title")) {
            if (ej_bson_parse_string_new(bc, "title", &tc->title) < 0) goto cleanup;
        } else if (!strcmp(key, "username")) {
            if (ej_bson_parse_string_new(bc, "username", &tc->username) < 0) goto cleanup;
        } else if (!strcmp(key, "first_name")) {
            if (ej_bson_parse_string_new(bc, "first_name", &tc->first_name) < 0) goto cleanup;
        } else if (!strcmp(key, "last_name")) {
            if (ej_bson_parse_string_new(bc, "last_name", &tc->last_name) < 0) goto cleanup;
        }
    }

    return tc;

cleanup:
    telegram_chat_free(tc);
    return NULL;

#else
    return NULL;
#endif
}

static ej_bson_t *
telegram_chat_unparse_bson(const struct telegram_chat *tc)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!tc) return NULL;

    bson_t *bson = bson_new();

    if (tc->_id) {
        bson_append_int64(bson, "_id", -1, tc->_id);
    }
    if (tc->type && *tc->type) {
        bson_append_utf8(bson, "type", -1, tc->type, strlen(tc->type));
    }
    if (tc->title && *tc->title) {
        bson_append_utf8(bson, "title", -1, tc->title, strlen(tc->title));
    }
    if (tc->username && *tc->username) {
        bson_append_utf8(bson, "username", -1, tc->username, strlen(tc->username));
    }
    if (tc->first_name && *tc->first_name) {
        bson_append_utf8(bson, "first_name", -1, tc->first_name, strlen(tc->first_name));
    }
    if (tc->last_name && *tc->last_name) {
        bson_append_utf8(bson, "last_name", -1, tc->last_name, strlen(tc->last_name));
    }

    return bson;
#else
    return NULL;
#endif
}

struct telegram_chat *
telegram_chat_fetch(struct mongo_conn *conn, long long _id)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return NULL;

    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    mongoc_cursor_t *cursor = NULL;
    const bson_t *doc = NULL;
    struct telegram_chat *retval = NULL;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_CHATS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }
    query = bson_new();
    bson_append_int64(query, "_id", -1, _id);
    cursor = mongoc_collection_find_with_opts(coll, query, NULL, NULL);
    if (!cursor) goto cleanup;

    if (mongoc_cursor_next(cursor, &doc)) {
        retval = telegram_chat_parse_bson(doc);
    }

cleanup:
    if (cursor) mongoc_cursor_destroy(cursor);
    if (coll) mongoc_collection_destroy(coll);
    if (query) bson_destroy(query);
    return retval;

#else
    return NULL;
#endif
}

int
telegram_chat_save(struct mongo_conn *conn, const struct telegram_chat *tc)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return -1;

    int retval = -1;
    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    bson_t *bson = NULL;
    bson_error_t error;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_CHATS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }
    query = bson_new();
    bson_append_int64(query, "_id", -1, tc->_id);
    bson = telegram_chat_unparse_bson(tc);

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
