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
#include "ejudge/osdeps.h"
#include "ejudge/errlog.h"

#include "telegram_token.h"
#include "mongo_conn.h"

#if HAVE_LIBMONGOC - 0 > 0
struct _bson_t;
typedef struct _bson_t ej_bson_t;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
struct _bson;
typedef struct _bson ej_bson_t;
#endif

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
#include <mongo.h>
#endif

#include <errno.h>

#define TELEGRAM_TOKENS_TABLE_NAME "telegram_tokens"

static ej_bson_t *
telegram_token_unparse_bson(const struct telegram_token *token);
static struct telegram_token *
telegram_token_parse_bson(const ej_bson_t *bson);

struct telegram_token *
telegram_token_free(struct telegram_token *token)
{
    if (token) {
        xfree(token->bot_id);
        xfree(token->user_login);
        xfree(token->user_name);
        xfree(token->contest_name);
        xfree(token->token);
        xfree(token);
    }
    return NULL;
}

static struct telegram_token *
telegram_token_parse_bson(const ej_bson_t *bson)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_iter_t iter, * const bc = &iter;
    struct telegram_token *token = NULL;

    if (!bson_iter_init(&iter, bson)) goto cleanup;

    XCALLOC(token, 1);
    while (bson_iter_next(&iter)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_oid_new(bc, "_id", token->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "bot_id")) {
            if (ej_bson_parse_string_new(bc, "bot_id", &token->bot_id) < 0) goto cleanup;
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int_new(bc, "user_id", &token->user_id, 1, 1, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "user_login")) {
            if (ej_bson_parse_string_new(bc, "user_login", &token->user_login) < 0) goto cleanup;
        } else if (!strcmp(key, "user_name")) {
            if (ej_bson_parse_string_new(bc, "user_name", &token->user_name) < 0) goto cleanup;
        } else if (!strcmp(key, "token")) {
            if (ej_bson_parse_string_new(bc, "token", &token->token) < 0) goto cleanup;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int_new(bc, "contest_id", &token->contest_id, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "contest_name")) {
            if (ej_bson_parse_string_new(bc, "contest_name", &token->contest_name) < 0) goto cleanup;
        } else if (!strcmp(key, "locale_id")) {
            if (ej_bson_parse_int_new(bc, "locale_id", &token->locale_id, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "expiry_time")) {
            if (ej_bson_parse_utc_datetime_new(bc, "expiry_time", &token->expiry_time) < 0) goto cleanup;
        }
    }
    return token;
cleanup:
    telegram_token_free(token);
    return NULL;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct telegram_token *token = NULL;
    bson_cursor *bc = NULL;

    XCALLOC(token, 1);
    bc = bson_cursor_new(bson);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_oid(bc, "_id", token->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "bot_id")) {
            if (ej_bson_parse_string(bc, "bot_id", &token->bot_id) < 0) goto cleanup;
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int(bc, "user_id", &token->user_id, 1, 1, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "user_login")) {
            if (ej_bson_parse_string(bc, "user_login", &token->user_login) < 0) goto cleanup;
        } else if (!strcmp(key, "user_name")) {
            if (ej_bson_parse_string(bc, "user_name", &token->user_name) < 0) goto cleanup;
        } else if (!strcmp(key, "token")) {
            if (ej_bson_parse_string(bc, "token", &token->token) < 0) goto cleanup;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int(bc, "contest_id", &token->contest_id, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "contest_name")) {
            if (ej_bson_parse_string(bc, "contest_name", &token->contest_name) < 0) goto cleanup;
        } else if (!strcmp(key, "locale_id")) {
            if (ej_bson_parse_int(bc, "locale_id", &token->locale_id, 1, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "expiry_time")) {
            if (ej_bson_parse_utc_datetime(bc, "expiry_time", &token->expiry_time) < 0) goto cleanup;
        }
    }
    bson_cursor_free(bc);
    return token;

cleanup:
    telegram_token_free(token);
    return NULL;
#else
    return 0;
#endif
}

struct telegram_token *
telegram_token_create(void)
{
    struct telegram_token *token = NULL;
    XCALLOC(token, 1);
    return token;
}

static ej_bson_t *
telegram_token_unparse_bson(const struct telegram_token *token)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!token) return NULL;

    bson_t *bson = bson_new();
    int empty_id = 1;
    for (int i = 0; i < 12; ++i) {
        if (token->_id[i]) {
            empty_id = 0;
            break;
        }
    }

    if (!empty_id) {
        bson_append_oid(bson, "_id", -1, (bson_oid_t *) &token->_id);
    }
    if (token->bot_id && *token->bot_id) {
        bson_append_utf8(bson, "bot_id", -1, token->bot_id, strlen(token->bot_id));
    }
    if (token->user_id > 0) {
        bson_append_int32(bson, "user_id", -1, token->user_id);
    }
    if (token->user_login && *token->user_login) {
        bson_append_utf8(bson, "user_login", -1, token->user_login, strlen(token->user_login));
    }
    if (token->user_name && *token->user_name) {
        bson_append_utf8(bson, "user_name", -1, token->user_name, strlen(token->user_name));
    }
    if (token->token && *token->token) {
        bson_append_utf8(bson, "token", -1, token->token, strlen(token->token));
    }
    if (token->contest_id > 0) {
        bson_append_int32(bson, "contest_id", -1, token->contest_id);
    }
    if (token->contest_name && *token->contest_name) {
        bson_append_utf8(bson, "contest_name", -1, token->contest_name, strlen(token->contest_name));
    }
    if (token->locale_id > 0) {
        bson_append_int32(bson, "locale_id", -1, token->locale_id);
    }
    if (token->expiry_time > 0) {
        bson_append_date_time(bson, "expiry_time", -1, 1000LL * token->expiry_time);
    }
    return bson;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!token) return NULL;

    bson *b = bson_new();
    int empty_id = 1;
    for (int i = 0; i < 12; ++i) {
        if (token->_id[i]) {
            empty_id = 0;
            break;
        }
    }
    if (!empty_id) {
        bson_append_oid(b, "_id", token->_id);
    }
    if (token->bot_id && *token->bot_id) {
        bson_append_string(b, "bot_id", token->bot_id, strlen(token->bot_id));
    }
    if (token->user_id > 0) {
        bson_append_int32(b, "user_id", token->user_id);
    }
    if (token->user_login && *token->user_login) {
        bson_append_string(b, "user_login", token->user_login, strlen(token->user_login));
    }
    if (token->user_name && *token->user_name) {
        bson_append_string(b, "user_name", token->user_name, strlen(token->user_name));
    }
    if (token->token && *token->token) {
        bson_append_string(b, "token", token->token, strlen(token->token));
    }
    if (token->contest_id > 0) {
        bson_append_int32(b, "contest_id", token->contest_id);
    }
    if (token->contest_name && *token->contest_name) {
        bson_append_string(b, "contest_name", token->contest_name, strlen(token->contest_name));
    }
    if (token->locale_id > 0) {
        bson_append_int32(b, "locale_id", token->locale_id);
    }
    if (token->expiry_time > 0) {
        bson_append_utc_datetime(b, "expiry_time", 1000LL * token->expiry_time);
    }
    bson_finish(b);
    return b;
#else
    return NULL;
#endif
}

void
telegram_token_remove_expired(struct mongo_conn *conn, time_t current_time)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (current_time <= 0) current_time = time(NULL);

    if (!conn->b.vt->open(&conn->b)) return;

    mongoc_collection_t *coll = NULL;
    bson_t *qq = NULL;
    bson_t *q = NULL;
    bson_error_t error;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_TOKENS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }

    qq = bson_new();
    bson_append_date_time(qq, "$lt", -1, 1000LL * current_time);
    q = bson_new();
    bson_append_document(q, "expiry_time", -1, qq);
    bson_destroy(qq); qq = NULL;

    if (!mongoc_collection_delete_many(coll, q, NULL, NULL, &error)) {
        err("telegram_token_remove_expired: failed: %s", error.message);
        goto cleanup;
    }

cleanup:
    if (q) bson_destroy(q);
    if (qq) bson_destroy(qq);
    if (coll) mongoc_collection_destroy(coll);
    return;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (current_time <= 0) current_time = time(NULL);

    if (!mongo_conn_open(conn)) return;

    bson *qq = bson_new();
    bson_append_utc_datetime(qq, "$lt", 1000LL * current_time);
    bson_finish(qq);
    bson *q = bson_new();
    bson_append_document(q, "expiry_time", qq); qq = NULL;
    bson_finish(q);

    mongo_sync_cmd_delete(conn->conn, mongo_conn_ns(conn, TELEGRAM_TOKENS_TABLE_NAME), 0, q);

    bson_free(q);
#endif
}

void
telegram_token_remove(struct mongo_conn *conn, const unsigned char *token)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return;

    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    bson_error_t error;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_TOKENS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }

    query = bson_new();
    bson_append_utf8(query, "token", -1, token, strlen(token));

    if (!mongoc_collection_delete_one(coll, query, NULL, NULL, &error)) {
        err("telegram_token_remove_expired: failed: %s", error.message);
        goto cleanup;
    }

cleanup:
    if (query) bson_destroy(query);
    if (coll) mongoc_collection_destroy(coll);
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return;

    bson *q = bson_new();
    bson_append_string(q, "token", token, strlen(token));
    bson_finish(q);

    mongo_sync_cmd_delete(conn->conn, mongo_conn_ns(conn, TELEGRAM_TOKENS_TABLE_NAME), 0, q);

    bson_free(q);
#endif
}

int
telegram_token_fetch(struct mongo_conn *conn, const unsigned char *token_str, struct telegram_token **p_token)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return -1;

    int retval = -1;
    mongoc_collection_t *coll = NULL;
    bson_t *query = NULL;
    mongoc_cursor_t *cursor = NULL;
    const bson_t *doc = NULL;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_TOKENS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }

    query = bson_new();
    bson_append_utf8(query, "token", -1, token_str, strlen(token_str));

    cursor = mongoc_collection_find_with_opts(coll, query, NULL, NULL);
    if (!cursor) goto cleanup;

    if (mongoc_cursor_next(cursor, &doc)) {
        *p_token = telegram_token_parse_bson(doc);
        retval = 1;
    } else {
        retval = 0;
    }

cleanup:
    if (cursor) mongoc_cursor_destroy(cursor);
    if (query) bson_destroy(query);
    if (coll) mongoc_collection_destroy(coll);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    int retval = -1;

    if (!mongo_conn_open(conn)) return -1;

    bson *query = NULL;
    mongo_packet *pkt = NULL;
    mongo_sync_cursor *cursor = NULL;
    bson *result = NULL;

    query = bson_new();
    bson_append_string(query, "token", token_str, strlen(token_str));
    bson_finish(query);

    pkt = mongo_sync_cmd_query(conn->conn, mongo_conn_ns(conn, TELEGRAM_TOKENS_TABLE_NAME), 0, 0, 1, query, NULL);
    if (!pkt && errno == ENOENT) {
        retval = 0;
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
            struct telegram_token *t = telegram_token_parse_bson(result);
            if (t) {
                *p_token = t;
                retval = 1;
            }
        } else {
            retval = 0;
        }
    } else {
        retval = 0;
    }

cleanup:
    if (result) bson_free(result);
    if (cursor) mongo_sync_cursor_free(cursor);
    if (pkt) mongo_wire_packet_free(pkt);
    if (query) bson_free(query);
    return retval;
#else
    return 0;
#endif
}

int
telegram_token_save(struct mongo_conn *conn, const struct telegram_token *token)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (!conn->b.vt->open(&conn->b)) return -1;

    int retval = -1;
    mongoc_database_t *db = NULL;
    mongoc_collection_t *coll = NULL;
    bson_t *bson = NULL;
    bson_error_t error;
    bson_t *ind = NULL;
    char *ind_name = NULL;
    bson_t *create_bson = NULL;

    if (!(coll = mongoc_client_get_collection(conn->client, conn->b.database, TELEGRAM_TOKENS_TABLE_NAME))) {
        err("get_collection failed\n");
        goto cleanup;
    }

    bson = telegram_token_unparse_bson(token);

    if (!mongoc_collection_insert_one(coll, bson, NULL, NULL, &error)) {
        err("telegram_token_save: failed: %s", error.message);
        goto cleanup;
    }
    retval = 0;

    if (!conn->token_index_created) {
        conn->token_index_created = 1;

        ind = bson_new();
        bson_append_int32(ind, "token", -1, 1);
        ind_name = mongoc_collection_keys_to_index_string(ind);
        create_bson = BCON_NEW("createIndexes", BCON_UTF8(TELEGRAM_TOKENS_TABLE_NAME),
                               "indexes", "[", "{", "key", BCON_DOCUMENT(ind),
                               "name", BCON_UTF8(ind_name), "}", "]");

        if ((db = mongoc_client_get_database(conn->client, conn->b.database))) {
            mongoc_database_write_command_with_opts(db, create_bson, NULL, NULL, NULL);
        }
    }

cleanup:
    if (create_bson) bson_destroy(create_bson);
    if (ind_name) bson_free(ind_name);
    if (ind) bson_destroy(ind);
    if (bson) bson_destroy(bson);
    if (coll) mongoc_collection_destroy(coll);
    if (db) mongoc_database_destroy(db);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return -1;
    int retval = -1;

    bson *b = telegram_token_unparse_bson(token);
    bson *ind = NULL;

    if (!mongo_sync_cmd_insert(conn->conn, mongo_conn_ns(conn, TELEGRAM_TOKENS_TABLE_NAME), b, NULL)) {
        err("save_token: failed: %s", os_ErrorMsg());
        goto cleanup;
    }

    ind = bson_new();
    bson_append_int32(ind, "token", 1);
    bson_finish(ind);
    mongo_sync_cmd_index_create(conn->conn, conn->ns, ind, 0);

    retval = 0;
cleanup:
    if (ind) bson_free(ind);
    bson_free(b);
    return retval;
#else
    return 0;
#endif
}
