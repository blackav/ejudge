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

#include "telegram_chat_state.h"

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

struct _bson_t;
typedef struct _bson_t ej_bson_t;

#define TELEGRAM_CHAT_STATES_TABLE_NAME "telegram_chat_states"

static struct telegram_chat_state *
telegram_chat_state_parse_bson(const ej_bson_t *bson);
static ej_bson_t *
telegram_chat_state_unparse_bson(const struct telegram_chat_state *tcs);

struct telegram_chat_state *
telegram_chat_state_free(struct telegram_chat_state *tcs)
{
    if (tcs) {
        memset(tcs, 0xff, sizeof(*tcs));
        xfree(tcs);
    }
    return NULL;
}

struct telegram_chat_state *
telegram_chat_state_create(void)
{
    struct telegram_chat_state *tcs = NULL;
    XCALLOC(tcs, 1);
    return tcs;
}

void
telegram_chat_state_reset(struct telegram_chat_state *tcs)
{
    xfree(tcs->command); tcs->command = NULL;
    xfree(tcs->token); tcs->token = NULL;
    tcs->state = 0;
    tcs->review_flag = 0;
    tcs->reply_flag = 0;
}

static struct telegram_chat_state *
telegram_chat_state_parse_bson(const ej_bson_t *bson)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_iter_t iter, * const bc = &iter;
    struct telegram_chat_state *tcs = NULL;

    if (!bson_iter_init(&iter, bson)) goto cleanup;
    XCALLOC(tcs, 1);

    while (bson_iter_next(bc)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_int64_new(bc, "_id", &tcs->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "command")) {
            if (ej_bson_parse_string_new(bc, "command", &tcs->command) < 0) goto cleanup;
        } else if (!strcmp(key, "token")) {
            if (ej_bson_parse_string_new(bc, "token", &tcs->token) < 0) goto cleanup;
        } else if (!strcmp(key, "state")) {
            if (ej_bson_parse_int_new(bc, "state", &tcs->state, 0, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "review_flag")) {
            if (ej_bson_parse_int_new(bc, "review_flag", &tcs->review_flag, 0, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "reply_flag")) {
            if (ej_bson_parse_int_new(bc, "reply_flag", &tcs->reply_flag, 0, 0, 0, 0) < 0) goto cleanup;
        }
    }

    return tcs;

cleanup:
    telegram_chat_state_free(tcs);
    return NULL;
#else
    return NULL;
#endif
}

static ej_bson_t *
telegram_chat_state_unparse_bson(const struct telegram_chat_state *tcs)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!tcs) return NULL;

    bson_t *bson = bson_new();

    if (tcs->_id) {
        bson_append_int64(bson, "_id", -1, tcs->_id);
    }
    if (tcs->command && *tcs->command) {
        bson_append_utf8(bson, "command", -1, tcs->command, strlen(tcs->command));
    }
    if (tcs->token && *tcs->token) {
        bson_append_utf8(bson, "token", -1, tcs->token, strlen(tcs->token));
    }
    if (tcs->state > 0) {
        bson_append_int32(bson, "state", -1, tcs->state);
    }
    if (tcs->review_flag > 0) {
        bson_append_int32(bson, "review_flag", -1, tcs->review_flag);
    }
    if (tcs->reply_flag > 0) {
        bson_append_int32(bson, "reply_flag", -1, tcs->reply_flag);
    }

    return bson;
#else
    return NULL;
#endif
}

struct telegram_chat_state *
telegram_chat_state_fetch(struct mongo_conn *conn, long long _id)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return NULL;

    mongoc_collection_t *coll = NULL;
    struct telegram_chat_state *retval = NULL;
    bson_t *query = NULL;
    mongoc_cursor_t *cursor = NULL;
    const bson_t *doc = NULL;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_CHAT_STATES_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }

    query = bson_new();
    bson_append_int64(query, "_id", -1, _id);
    cursor = mongoc_collection_find_with_opts(coll, query, NULL, NULL);
    if (!cursor) goto cleanup;

    if (mongoc_cursor_next(cursor, &doc)) {
        retval = telegram_chat_state_parse_bson(doc);
    }

cleanup:
    if (cursor) mongoc_cursor_destroy(cursor);
    if (query) bson_destroy(query);
    if (coll) mongoc_collection_destroy(coll);

    return retval;
#else
    return NULL;
#endif
}

int
telegram_chat_state_save(struct mongo_conn *conn, const struct telegram_chat_state *tcs)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return -1;

    int retval = -1;
    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    bson_t *bson = NULL;
    bson_error_t error;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_CHAT_STATES_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }
    query = bson_new();
    bson_append_int64(query, "_id", -1, tcs->_id);
    bson = telegram_chat_state_unparse_bson(tcs);

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
