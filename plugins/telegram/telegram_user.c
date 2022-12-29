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

#include "telegram_user.h"

#include "ejudge/bson_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"

#include "mongo_conn.h"

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
#include <mongo.h>
#endif

#include <errno.h>
#include <string.h>

#if HAVE_LIBMONGOC - 0 > 0
struct _bson_t;
typedef struct _bson_t ej_bson_t;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
struct _bson;
typedef struct _bson ej_bson_t;
#endif

#define TELEGRAM_USERS_TABLE_NAME "telegram_users"

static struct telegram_user *
telegram_user_parse_bson(const ej_bson_t *bson);
static ej_bson_t *
telegram_user_unparse_bson(const struct telegram_user *tu);

struct telegram_user *
telegram_user_free(struct telegram_user *tu)
{
    if (tu) {
        xfree(tu->username);
        xfree(tu->first_name);
        xfree(tu->last_name);
        memset(tu, 0xff, sizeof(*tu));
        xfree(tu);
    }
    return NULL;
}

struct telegram_user *
telegram_user_create(void)
{
    struct telegram_user *tu = NULL;
    XCALLOC(tu, 1);
    return tu;
}

static struct telegram_user *
telegram_user_parse_bson(const ej_bson_t *bson)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_iter_t iter, * const bc = &iter;
    struct telegram_user *tu = NULL;

    if (!bson_iter_init(&iter, bson)) goto cleanup;

    XCALLOC(tu, 1);
    while (bson_iter_next(&iter)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_int64_new(bc, "_id", &tu->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "username")) {
            if (ej_bson_parse_string_new(bc, "username", &tu->username) < 0) goto cleanup;
        } else if (!strcmp(key, "first_name")) {
            if (ej_bson_parse_string_new(bc, "first_name", &tu->first_name) < 0) goto cleanup;
        } else if (!strcmp(key, "last_name")) {
            if (ej_bson_parse_string_new(bc, "last_name", &tu->last_name) < 0) goto cleanup;
        }
    }

    return tu;

cleanup:
    telegram_user_free(tu);
    return NULL;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson_cursor *bc = NULL;
    struct telegram_user *tu = NULL;

    XCALLOC(tu, 1);
    bc = bson_cursor_new(bson);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_int64(bc, "_id", &tu->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "username")) {
            if (ej_bson_parse_string(bc, "username", &tu->username) < 0) goto cleanup;
        } else if (!strcmp(key, "first_name")) {
            if (ej_bson_parse_string(bc, "first_name", &tu->first_name) < 0) goto cleanup;
        } else if (!strcmp(key, "last_name")) {
            if (ej_bson_parse_string(bc, "last_name", &tu->last_name) < 0) goto cleanup;
        }
    }
    bson_cursor_free(bc);
    return tu;

cleanup:
    telegram_user_free(tu);
    return NULL;
#else
    return NULL;
#endif
}

static ej_bson_t *
telegram_user_unparse_bson(const struct telegram_user *tu)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!tu) return NULL;

    bson_t *bson = bson_new();

    if (tu->_id) {
        bson_append_int64(bson, "_id", -1, tu->_id);
    }
    if (tu->username && *tu->username) {
        bson_append_utf8(bson, "username", -1, tu->username, strlen(tu->username));
    }
    if (tu->first_name && *tu->first_name) {
        bson_append_utf8(bson, "first_name", -1, tu->first_name, strlen(tu->first_name));
    }
    if (tu->last_name && *tu->last_name) {
        bson_append_utf8(bson, "last_name", -1, tu->last_name, strlen(tu->last_name));
    }

    return bson;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!tu) return NULL;

    bson *bson = bson_new();
    if (tu->_id) {
        bson_append_int64(bson, "_id", tu->_id);
    }
    if (tu->username && *tu->username) {
        bson_append_string(bson, "username", tu->username, strlen(tu->username));
    }
    if (tu->first_name && *tu->first_name) {
        bson_append_string(bson, "first_name", tu->first_name, strlen(tu->first_name));
    }
    if (tu->last_name && *tu->last_name) {
        bson_append_string(bson, "last_name", tu->last_name, strlen(tu->last_name));
    }
    bson_finish(bson);
    return bson;
#else
    return NULL;
#endif
}

struct telegram_user *
telegram_user_fetch(struct mongo_conn *conn, long long _id)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return NULL;

    struct telegram_user *retval = NULL;
    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    mongoc_cursor_t *cursor = NULL;
    const bson_t *doc = NULL;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_USERS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }

    query = bson_new();
    bson_append_int64(query, "_id", -1, _id);

    cursor = mongoc_collection_find_with_opts(coll, query, NULL, NULL);
    if (!cursor) goto cleanup;

    if (mongoc_cursor_next(cursor, &doc)) {
        retval = telegram_user_parse_bson(doc);
    }

cleanup:
    if (cursor) mongoc_cursor_destroy(cursor);
    if (query) bson_destroy(query);
    if (coll) mongoc_collection_destroy(coll);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return NULL;

    bson *query = NULL;
    mongo_packet *pkt = NULL;
    mongo_sync_cursor *cursor = NULL;
    bson *result = NULL;
    struct telegram_user *retval = NULL;

    query = bson_new();
    bson_append_int64(query, "_id", _id);
    bson_finish(query);

    pkt = mongo_sync_cmd_query(conn->conn, mongo_conn_ns(conn, TELEGRAM_USERS_TABLE_NAME), 0, 0, 1, query, NULL);
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
            retval = telegram_user_parse_bson(result);
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
telegram_user_save(struct mongo_conn *conn, const struct telegram_user *tu)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return -1;

    int retval = -1;
    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    bson_t *bson = NULL;
    bson_error_t error;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_USERS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }

    bson = telegram_user_unparse_bson(tu);
    query = bson_new();
    bson_append_int64(query, "_id", -1, tu->_id);

    if (!mongoc_collection_update(coll, MONGOC_UPDATE_UPSERT, query, bson, NULL, &error)) {
        err("telegram_chat_save: failed: %s", error.message);
        goto cleanup;
    }

    retval = 0;

cleanup:
    if (query) bson_destroy(query);
    if (bson) bson_destroy(bson);
    if (coll) mongoc_collection_destroy(coll);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return -1;
    int retval = -1;

    bson *b = telegram_user_unparse_bson(tu);
    bson *q = bson_new();
    bson_append_int64(q, "_id", tu->_id);
    bson_finish(q);

    if (!mongo_sync_cmd_update(conn->conn, mongo_conn_ns(conn, TELEGRAM_USERS_TABLE_NAME), MONGO_WIRE_FLAG_UPDATE_UPSERT, q, b)) {
        err("save_token: failed: %s", os_ErrorMsg());
        goto cleanup;
    }

    retval = 0;

cleanup:
    bson_free(b);
    bson_free(q);
    return retval;
#else
    return 0;
#endif
}
