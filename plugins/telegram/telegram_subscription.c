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

#include "telegram_subscription.h"
#include "mongo_conn.h"

#include "ejudge/bson_utils.h"
#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"
#include "ejudge/errlog.h"

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
#include <mongo.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

#if HAVE_LIBMONGOC - 0 > 0
struct _bson_t;
typedef struct _bson_t ej_bson_t;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
struct _bson;
typedef struct _bson ej_bson_t;
#endif

#define TELEGRAM_SUBSCRIPTIONS_TABLE_NAME "telegram_subscriptions"

static struct telegram_subscription *
telegram_subscription_parse_bson(const ej_bson_t *bson);
static ej_bson_t *
telegram_subscription_unparse_bson(const struct telegram_subscription *subscription);

struct telegram_subscription *
telegram_subscription_free(struct telegram_subscription *sub)
{
    if (sub) {
        xfree(sub->_id);
        xfree(sub->bot_id);
        memset(sub, 0xff, sizeof(*sub));
        xfree(sub);
    }
    return NULL;
}

struct telegram_subscription *
telegram_subscription_create(const unsigned char *bot_id, int user_id, int contest_id)
{
    struct telegram_subscription *sub = NULL;
    unsigned char buf[1024];

    if (!bot_id || !*bot_id || contest_id <= 0 || user_id <= 0) return NULL;
    snprintf(buf, sizeof(buf), "%s-%d-%d", bot_id, contest_id, user_id);

    XCALLOC(sub, 1);
    sub->_id = xstrdup(buf);
    sub->bot_id = xstrdup(bot_id);
    sub->user_id = user_id;
    sub->contest_id = contest_id;
    return sub;
}

static struct telegram_subscription *
telegram_subscription_parse_bson(const ej_bson_t *bson)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_iter_t iter, * const bc = &iter;
    struct telegram_subscription *sub = NULL;

    if (!bson_iter_init(&iter, bson)) goto cleanup;

    XCALLOC(sub, 1);
    while (bson_iter_next(&iter)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_string_new(bc, "_id", &sub->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "bot_id")) {
            if (ej_bson_parse_string_new(bc, "bot_id", &sub->bot_id) < 0) goto cleanup;
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int_new(bc, "user_id", &sub->user_id, 1, 1, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int_new(bc, "contest_id", &sub->contest_id, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "review_flag")) {
            if (ej_bson_parse_int_new(bc, "review_flag", &sub->review_flag, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "reply_flag")) {
            if (ej_bson_parse_int_new(bc, "reply_flag", &sub->reply_flag, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "chat_id")) {
            if (ej_bson_parse_int64_new(bc, "chat_id", &sub->chat_id) < 0) goto cleanup;
        }
    }
    return sub;

cleanup:
    telegram_subscription_free(sub);
    return NULL;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct telegram_subscription *sub = NULL;
    bson_cursor *bc = NULL;

    XCALLOC(sub, 1);
    bc = bson_cursor_new(bson);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_string(bc, "_id", &sub->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "bot_id")) {
            if (ej_bson_parse_string(bc, "bot_id", &sub->bot_id) < 0) goto cleanup;
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int(bc, "user_id", &sub->user_id, 1, 1, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int(bc, "contest_id", &sub->contest_id, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "review_flag")) {
            if (ej_bson_parse_int(bc, "review_flag", &sub->review_flag, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "reply_flag")) {
            if (ej_bson_parse_int(bc, "reply_flag", &sub->reply_flag, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "chat_id")) {
            if (ej_bson_parse_int64(bc, "chat_id", &sub->chat_id) < 0) goto cleanup;
        }
    }
    bson_cursor_free(bc);
    return sub;

cleanup:
    telegram_subscription_free(sub);
    return NULL;
#else
    return NULL;
#endif
}

static ej_bson_t *
telegram_subscription_unparse_bson(const struct telegram_subscription *sub)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!sub) return NULL;

    bson_t *bson = bson_new();
    if (sub->_id && *sub->_id) {
        bson_append_utf8(bson, "_id", -1, sub->_id, strlen(sub->_id));
    }
    if (sub->bot_id && *sub->bot_id) {
        bson_append_utf8(bson, "bot_id", -1, sub->bot_id, strlen(sub->bot_id));
    }
    if (sub->user_id > 0) {
        bson_append_int32(bson, "user_id", -1, sub->user_id);
    }
    if (sub->contest_id > 0) {
        bson_append_int32(bson, "contest_id", -1, sub->contest_id);
    }
    if (sub->review_flag > 0) {
        bson_append_int32(bson, "review_flag", -1, sub->review_flag);
    }
    if (sub->reply_flag > 0) {
        bson_append_int32(bson, "reply_flag", -1, sub->reply_flag);
    }
    if (sub->chat_id) {
        bson_append_int64(bson, "chat_id", -1, sub->chat_id);
    }
    return bson;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!sub) return NULL;

    bson *b = bson_new();
    if (sub->_id && *sub->_id) {
        bson_append_string(b, "_id", sub->_id, strlen(sub->_id));
    }
    if (sub->bot_id && *sub->bot_id) {
        bson_append_string(b, "bot_id", sub->bot_id, strlen(sub->bot_id));
    }
    if (sub->user_id > 0) {
        bson_append_int32(b, "user_id", sub->user_id);
    }
    if (sub->contest_id > 0) {
        bson_append_int32(b, "contest_id", sub->contest_id);
    }
    if (sub->review_flag > 0) {
        bson_append_int32(b, "review_flag", sub->review_flag);
    }
    if (sub->reply_flag > 0) {
        bson_append_int32(b, "reply_flag", sub->reply_flag);
    }
    if (sub->chat_id) {
        bson_append_int64(b, "chat_id", sub->chat_id);
    }
    bson_finish(b);
    return b;
#else
    return NULL;
#endif
}

struct telegram_subscription *
telegram_subscription_fetch(struct mongo_conn *conn, const unsigned char *bot_id, int user_id, int contest_id)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return NULL;

    unsigned char buf[1024];
    if (!bot_id || !*bot_id || contest_id <= 0 || user_id <= 0) return NULL;
    snprintf(buf, sizeof(buf), "%s-%d-%d", bot_id, contest_id, user_id);

    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    mongoc_cursor_t *cursor = NULL;
    const bson_t *doc = NULL;
    struct telegram_subscription *retval = NULL;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_SUBSCRIPTIONS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }

    query = bson_new();
    bson_append_utf8(query, "_id", -1, buf, strlen(buf));
    cursor = mongoc_collection_find_with_opts(coll, query, NULL, NULL);
    if (!cursor) goto cleanup;

    if (mongoc_cursor_next(cursor, &doc)) {
        retval = telegram_subscription_parse_bson(doc);
    }

cleanup:
    if (cursor) mongoc_cursor_destroy(cursor);
    if (coll) mongoc_collection_destroy(coll);
    if (query) bson_destroy(query);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return NULL;

    unsigned char buf[1024];
    if (!bot_id || !*bot_id || contest_id <= 0 || user_id <= 0) return NULL;
    snprintf(buf, sizeof(buf), "%s-%d-%d", bot_id, contest_id, user_id);

    bson *query = NULL;
    mongo_packet *pkt = NULL;
    mongo_sync_cursor *cursor = NULL;
    bson *result = NULL;
    struct telegram_subscription *retval = NULL;

    query = bson_new();
    bson_append_string(query, "_id", buf, strlen(buf));
    bson_finish(query);

    pkt = mongo_sync_cmd_query(conn->conn, mongo_conn_ns(conn, TELEGRAM_SUBSCRIPTIONS_TABLE_NAME), 0, 0, 1, query, NULL);
    if (!pkt && errno == ENOENT) {
        goto cleanup;
    }
    if (!pkt) {
        err("mongo query failed: %s", os_ErrorMsg());
        goto cleanup;
    }
    bson_free(query); query = NULL;

    cursor = mongo_sync_cursor_new(conn->conn, conn->ns, pkt);
    if (!cursor) {
        err("mongo query failed: cannot create cursor: %s", os_ErrorMsg());
        goto cleanup;
    }
    pkt = NULL;
    if (mongo_sync_cursor_next(cursor)) {
        result = mongo_sync_cursor_get_data(cursor);
        if (result) {
            retval = telegram_subscription_parse_bson(result);
        }
    }

cleanup:
    if (result) bson_free(result);
    if (cursor) mongo_sync_cursor_free(cursor);
    if (pkt) mongo_wire_packet_free(pkt);
    if (query) bson_free(query);
    return retval;
#else
    return NULL;
#endif
}

int
telegram_subscription_save(struct mongo_conn *conn, const struct telegram_subscription *sub)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return -1;

    int retval = -1;
    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    bson_t *bson = NULL;
    bson_error_t error;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_SUBSCRIPTIONS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }

    query = bson_new();
    bson_append_utf8(query, "_id", -1, sub->_id, strlen(sub->_id));
    bson = telegram_subscription_unparse_bson(sub);

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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return -1;
    int retval = -1;

    bson *b = telegram_subscription_unparse_bson(sub);
    bson *q = bson_new();
    bson_append_string(q, "_id", sub->_id, strlen(sub->_id));
    bson_finish(q);

    if (!mongo_sync_cmd_update(conn->conn, mongo_conn_ns(conn, TELEGRAM_SUBSCRIPTIONS_TABLE_NAME), MONGO_WIRE_FLAG_UPDATE_UPSERT, q, b)) {
        err("save_token: failed: %s", os_ErrorMsg());
        goto cleanup;
    }

    retval = 0;

cleanup:
    bson_free(q);
    bson_free(b);
    return retval;
#else
    return 0;
#endif
}
