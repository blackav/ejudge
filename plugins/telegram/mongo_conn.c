/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2016-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "mongo_conn.h"

#if HAVE_LIBMONGOC - 0 > 0 || HAVE_LIBMONGO_CLIENT - 0 == 1

#include "telegram_pbs.h"
#include "telegram_token.h"
#include "telegram_chat.h"
#include "telegram_user.h"
#include "telegram_chat_state.h"
#include "telegram_subscription.h"

#include "ejudge/bson_utils.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"

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

#define MONGO_RETRY_TIMEOUT 60

static struct generic_conn *
free_func(struct generic_conn *gc);
static int
open_func(
        struct generic_conn *gc);
static const unsigned char *
ns_func(
        struct generic_conn *gc,
        const unsigned char *collection_name);

static struct telegram_pbs *
pbs_fetch_func(
        struct generic_conn *gc,
        const unsigned char *bot_id);
static int
pbs_save_func(
        struct generic_conn *gc,
        const struct telegram_pbs *pbs);

static int
token_fetch_func(
        struct generic_conn *gc,
        const unsigned char *token_str,
        struct telegram_token **p_token);
static int
token_save_func(
        struct generic_conn *gc,
        const struct telegram_token *token);
static void
token_remove_func(
        struct generic_conn *gc,
        const unsigned char *token);
static void
token_remove_expired_func(
        struct generic_conn *gc,
        time_t current_time);

static struct telegram_chat *
chat_fetch_func(
        struct generic_conn *gc,
        long long _id);
static int
chat_save_func(
        struct generic_conn *gc,
        const struct telegram_chat *tc);

static struct telegram_user *
user_fetch_func(
        struct generic_conn *gc,
        long long _id);
static int
user_save_func(
        struct generic_conn *gc,
        const struct telegram_user *tu);

static struct telegram_chat_state *
chat_state_fetch_func(
        struct generic_conn *gc,
        long long _id);
static int
chat_state_save_func(
        struct generic_conn *gc,
        const struct telegram_chat_state *tcs);

static struct telegram_subscription *
subscription_fetch_func(
        struct generic_conn *gc,
        const unsigned char *bot_id,
        int user_id,
        int contest_id);
static int
subscription_save_func(
        struct generic_conn *gc,
        const struct telegram_subscription *subscription);

static struct generic_conn_iface mongo_iface =
{
    free_func,
    NULL,                       /* prepare_func */
    open_func,
    ns_func,
    pbs_fetch_func,
    pbs_save_func,
    token_fetch_func,
    token_save_func,
    token_remove_func,
    token_remove_expired_func,
    chat_fetch_func,
    chat_save_func,
    user_fetch_func,
    user_save_func,
    chat_state_fetch_func,
    chat_state_save_func,
    subscription_fetch_func,
    subscription_save_func,
    NULL,                       /* password_get */
};

struct generic_conn *
mongo_conn_create(void)
{
    struct mongo_conn *conn = NULL;
    XCALLOC(conn, 1);
    conn->b.vt = &mongo_iface;
    return &conn->b;
}

static struct mongo_conn *
mongo_conn_free(struct mongo_conn *conn)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (conn) {
        xfree(conn->b.database);
        xfree(conn->b.host);
        xfree(conn->b.table_prefix);
        xfree(conn->b.user);
        xfree(conn->b.password);
        if (conn->client) {
            mongoc_client_destroy(conn->client);
        }
        memset(conn, 0xff, sizeof(*conn));
        xfree(conn);
    }
    return NULL;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (conn) {
        xfree(conn->database);
        xfree(conn->host);
        xfree(conn->table_prefix);
        xfree(conn->user);
        xfree(conn->password);
        if (conn->conn) {
            mongo_sync_disconnect(conn->conn);
        }
        memset(conn, 0xff, sizeof(*conn));
        xfree(conn);
    }
    return NULL;
#else
#error mongo packages are missing
#endif
}

static struct generic_conn *
free_func(struct generic_conn *gc)
{
    mongo_conn_free((struct mongo_conn *) gc);
    return NULL;
}

static int
mongo_conn_open(struct mongo_conn *state)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (state->client) return 1;

    time_t current_time = time(NULL);
    if (state->last_check_time > 0 && state->last_check_time + MONGO_RETRY_TIMEOUT > current_time) {
        return 0;
    }

    if (!state->b.database) {
        if (!state->b.database) state->b.database = xstrdup("ejudge");
        state->b.show_queries = 1;
    }
    if (!state->b.table_prefix) state->b.table_prefix = xstrdup("");
    if (!state->b.host) state->b.host = xstrdup("localhost");
    if (state->b.port <= 0) state->b.port = 27017;

    unsigned char uri[1024];
    if (state->b.user && state->b.password) {
        if (snprintf(uri, sizeof(uri), "mongodb://%s:%s@%s:%d", state->b.user, state->b.password, state->b.host, state->b.port) >= sizeof(uri)) {
            err("mongodb URI is too long");
            return 0;
        }
    } else {
        if (snprintf(uri, sizeof(uri), "mongodb://%s:%d", state->b.host, state->b.port) >= sizeof(uri)) {
            err("mongodb URI is too long");
            return 0;
        }
    }

    state->last_check_time = current_time;

    mongoc_init();

    state->client = mongoc_client_new(uri);
    if (!state->client) {
        err("cannot create mongoc client");
        return 0;
    }

    mongoc_client_set_appname(state->client, "ejudge-plugin-telegram");

    return 1;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (state->conn) return 1;

    time_t current_time = time(NULL);
    if (state->last_check_time > 0 && state->last_check_time + MONGO_RETRY_TIMEOUT > current_time) {
        return 0;
    }

    if (!state->database) {
        if (!state->database) state->database = xstrdup("ejudge");
        state->show_queries = 1;
    }
    if (!state->host) state->host = xstrdup("localhost");
    if (!state->table_prefix) state->table_prefix = xstrdup("");
    if (state->port <= 0) state->port = 27017;
    state->last_check_time = current_time;

    state->conn = mongo_sync_connect(state->host, state->port, 0);
    if (!state->conn) {
        err("cannot connect to mongodb: %s", os_ErrorMsg());
        return 0;
    }
    mongo_sync_conn_set_safe_mode(state->conn, 1);
    mongo_sync_conn_set_auto_reconnect(state->conn, 1);
    if (state->user && state->password) {
        if (!mongo_sync_cmd_authenticate(state->conn, state->database, state->user, state->password)) {
            err("mongodb authentification failed: %s", os_ErrorMsg());
            mongo_sync_disconnect(state->conn);
            state->conn = NULL;
            return 0;
        }
    }
    return 1;
#else
#error mongo packages are missing
#endif
}

static int
open_func(
        struct generic_conn *gc)
{
    return mongo_conn_open((struct mongo_conn *) gc);
}

static const unsigned char *
mongo_conn_ns(struct mongo_conn *conn, const unsigned char *collection_name)
{
    snprintf(conn->ns, sizeof(conn->ns), "%s.%s%s", conn->b.database, conn->b.table_prefix, collection_name);
    return conn->ns;
}

static const unsigned char *
ns_func(
        struct generic_conn *gc,
        const unsigned char *collection_name)
{
    return mongo_conn_ns((struct mongo_conn *) gc, collection_name);
}

#define TELEGRAM_BOTS_TABLE_NAME "telegram_bots"

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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
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
#else
#error mongo packages are missing
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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
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
#else
#error mongo packages are missing
#endif
}

static int
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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return -1;
    int retval = -1;

    bson *s = bson_new();
    bson_append_string(s, "_id", pbs->_id, strlen(pbs->_id));
    bson_finish(s);

    bson *b = telegram_pbs_unparse_bson(pbs);
    if (!mongo_sync_cmd_update(conn->conn, mongo_conn_ns(conn, TELEGRAM_BOTS_TABLE_NAME), MONGO_WIRE_FLAG_UPDATE_UPSERT, s, b)) {
        err("save_persistent_bot_state: failed: %s", os_ErrorMsg());
        goto done;
    }
    retval = 0;

done:
    bson_free(s);
    bson_free(b);
    return retval;
#else
#error mongo packages are missing
#endif
}

static struct telegram_pbs *
pbs_fetch_func(
        struct generic_conn *gc,
        const unsigned char *bot_id)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return NULL;

    mongo_packet *pkt = NULL;
    bson *query = NULL;
    mongo_sync_cursor *cursor = NULL;
    bson *result = NULL;
    struct telegram_pbs *pbs = NULL;

    query = bson_new();
    bson_append_string(query, "_id", bot_id, strlen(bot_id));
    bson_finish(query);
    pkt = mongo_sync_cmd_query(conn->conn, mongo_conn_ns(conn, TELEGRAM_BOTS_TABLE_NAME), 0, 0, 1, query, NULL);
    if (!pkt && errno == ENOENT) {
        bson_free(query); query = NULL;
        pbs = telegram_pbs_create(bot_id);
        telegram_pbs_save(conn, pbs);
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
        pbs = telegram_pbs_parse_bson(result);
    } else {
        mongo_sync_cursor_free(cursor); cursor = NULL;
        pbs = telegram_pbs_create(bot_id);
        telegram_pbs_save(conn, pbs);
    }

cleanup:
    if (result) bson_free(result);
    if (cursor) mongo_sync_cursor_free(cursor);
    if (pkt) mongo_wire_packet_free(pkt);
    if (query) bson_free(query);
    return pbs;
#else
#error mongo packages are missing
#endif
}

static int
pbs_save_func(
        struct generic_conn *gc,
        const struct telegram_pbs *pbs)
{
    return telegram_pbs_save((struct mongo_conn *) gc, pbs);
}

#undef TELEGRAM_BOTS_TABLE_NAME

#define TELEGRAM_TOKENS_TABLE_NAME "telegram_tokens"

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
#error mongo packages are missing
#endif
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
#error mongo packages are missing
#endif
}

static int
token_fetch_func(
        struct generic_conn *gc,
        const unsigned char *token_str,
        struct telegram_token **p_token)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#error mongo packages are missing
#endif
}

static int
token_save_func(
        struct generic_conn *gc,
        const struct telegram_token *token)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#error mongo packages are missing
#endif
}

static void
token_remove_func(
        struct generic_conn *gc,
        const unsigned char *token)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#else
#error mongo packages are missing
#endif
}

static void
token_remove_expired_func(
        struct generic_conn *gc,
        time_t current_time)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#else
#error mongo packages are missing
#endif
}

#undef TELEGRAM_TOKENS_TABLE_NAME

#define TELEGRAM_CHATS_TABLE_NAME "telegram_chats"

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

#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson_cursor *bc = NULL;
    struct telegram_chat *tc = NULL;

    XCALLOC(tc, 1);
    bc = bson_cursor_new(bson);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_int64(bc, "_id", &tc->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "type")) {
            if (ej_bson_parse_string(bc, "type", &tc->type) < 0) goto cleanup;
        } else if (!strcmp(key, "title")) {
            if (ej_bson_parse_string(bc, "title", &tc->title) < 0) goto cleanup;
        } else if (!strcmp(key, "username")) {
            if (ej_bson_parse_string(bc, "username", &tc->username) < 0) goto cleanup;
        } else if (!strcmp(key, "first_name")) {
            if (ej_bson_parse_string(bc, "first_name", &tc->first_name) < 0) goto cleanup;
        } else if (!strcmp(key, "last_name")) {
            if (ej_bson_parse_string(bc, "last_name", &tc->last_name) < 0) goto cleanup;
        }
    }
    bson_cursor_free(bc);
    return tc;

cleanup:
    telegram_chat_free(tc);
    return NULL;
#else
#error mongo packages are missing
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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!tc) return NULL;

    bson *bson = bson_new();
    if (tc->_id) {
        bson_append_int64(bson, "_id", tc->_id);
    }
    if (tc->type && *tc->type) {
        bson_append_string(bson, "type", tc->type, strlen(tc->type));
    }
    if (tc->title && *tc->title) {
        bson_append_string(bson, "title", tc->title, strlen(tc->title));
    }
    if (tc->username && *tc->username) {
        bson_append_string(bson, "username", tc->username, strlen(tc->username));
    }
    if (tc->first_name && *tc->first_name) {
        bson_append_string(bson, "first_name", tc->first_name, strlen(tc->first_name));
    }
    if (tc->last_name && *tc->last_name) {
        bson_append_string(bson, "last_name", tc->last_name, strlen(tc->last_name));
    }
    bson_finish(bson);
    return bson;
#else
#error mongo packages are missing
#endif
}

static struct telegram_chat *
chat_fetch_func(
        struct generic_conn *gc,
        long long _id)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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

#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return NULL;

    bson *query = NULL;
    mongo_packet *pkt = NULL;
    mongo_sync_cursor *cursor = NULL;
    bson *result = NULL;
    struct telegram_chat *retval = NULL;

    query = bson_new();
    bson_append_int64(query, "_id", _id);
    bson_finish(query);

    pkt = mongo_sync_cmd_query(conn->conn, mongo_conn_ns(conn, TELEGRAM_CHATS_TABLE_NAME), 0, 0, 1, query, NULL);
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
            retval = telegram_chat_parse_bson(result);
        }
    }

cleanup:
    if (result) bson_free(result);
    if (cursor) mongo_sync_cursor_free(cursor);
    if (pkt) mongo_wire_packet_free(pkt);
    if (query) bson_free(query);
    return retval;
#else
#error mongo packages are missing
#endif
}

static int
chat_save_func(
        struct generic_conn *gc,
        const struct telegram_chat *tc)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return -1;
    int retval = -1;

    bson *b = telegram_chat_unparse_bson(tc);
    bson *q = bson_new();
    bson_append_int64(q, "_id", tc->_id);
    bson_finish(q);

    if (!mongo_sync_cmd_update(conn->conn, mongo_conn_ns(conn, TELEGRAM_CHATS_TABLE_NAME), MONGO_WIRE_FLAG_UPDATE_UPSERT, q, b)) {
        err("save_token: failed: %s", os_ErrorMsg());
        goto cleanup;
    }

    retval = 0;

cleanup:
    bson_free(q);
    bson_free(b);
    return retval;
#else
#error mongo packages are missing
#endif
}

#undef TELEGRAM_CHATS_TABLE_NAME

#define TELEGRAM_USERS_TABLE_NAME "telegram_users"

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

static struct telegram_user *
user_fetch_func(
        struct generic_conn *gc,
        long long _id)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#error mongo packages are missing
#endif
}

static int
user_save_func(
        struct generic_conn *gc,
        const struct telegram_user *tu)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#error mongo packages are missing
#endif
}

#undef TELEGRAM_USERS_TABLE_NAME

#define TELEGRAM_CHAT_STATES_TABLE_NAME "telegram_chat_states"

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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson_cursor *bc = NULL;
    struct telegram_chat_state *tcs = NULL;

    XCALLOC(tcs, 1);
    bc = bson_cursor_new(bson);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_int64(bc, "_id", &tcs->_id) < 0) goto cleanup;
        } else if (!strcmp(key, "command")) {
            if (ej_bson_parse_string(bc, "command", &tcs->command) < 0) goto cleanup;
        } else if (!strcmp(key, "token")) {
            if (ej_bson_parse_string(bc, "token", &tcs->token) < 0) goto cleanup;
        } else if (!strcmp(key, "state")) {
            if (ej_bson_parse_int(bc, "state", &tcs->state, 0, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "review_flag")) {
            if (ej_bson_parse_int(bc, "review_flag", &tcs->review_flag, 0, 0, 0, 0) < 0) goto cleanup;
        } else if (!strcmp(key, "reply_flag")) {
            if (ej_bson_parse_int(bc, "reply_flag", &tcs->reply_flag, 0, 0, 0, 0) < 0) goto cleanup;
        }
    }
    bson_cursor_free(bc);
    return tcs;

cleanup:
    telegram_chat_state_free(tcs);
    return NULL;
#else
#error mongo packages are missing
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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!tcs) return NULL;

    bson *bson = bson_new();
    if (tcs->_id) {
        bson_append_int64(bson, "_id", tcs->_id);
    }
    if (tcs->command && *tcs->command) {
        bson_append_string(bson, "command", tcs->command, strlen(tcs->command));
    }
    if (tcs->token && *tcs->token) {
        bson_append_string(bson, "token", tcs->token, strlen(tcs->token));
    }
    if (tcs->state > 0) {
        bson_append_int32(bson, "state", tcs->state);
    }
    if (tcs->review_flag > 0) {
        bson_append_int32(bson, "review_flag", tcs->review_flag);
    }
    if (tcs->reply_flag > 0) {
        bson_append_int32(bson, "reply_flag", tcs->reply_flag);
    }
    bson_finish(bson);
    return bson;
#else
#error mongo packages are missing
#endif
}

static struct telegram_chat_state *
chat_state_fetch_func(
        struct generic_conn *gc,
        long long _id)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return NULL;

    bson *query = NULL;
    mongo_packet *pkt = NULL;
    mongo_sync_cursor *cursor = NULL;
    bson *result = NULL;
    struct telegram_chat_state *retval = NULL;

    query = bson_new();
    bson_append_int64(query, "_id", _id);
    bson_finish(query);

    pkt = mongo_sync_cmd_query(conn->conn, mongo_conn_ns(conn, TELEGRAM_CHAT_STATES_TABLE_NAME), 0, 0, 1, query, NULL);
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
            retval = telegram_chat_state_parse_bson(result);
        }
    }

cleanup:
    if (result) bson_free(result);
    if (cursor) mongo_sync_cursor_free(cursor);
    if (pkt) mongo_wire_packet_free(pkt);
    if (query) bson_free(query);
    return retval;
#else
#error mongo packages are missing
#endif
}

static int
chat_state_save_func(
        struct generic_conn *gc,
        const struct telegram_chat_state *tcs)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (!mongo_conn_open(conn)) return -1;
    int retval = -1;

    bson *b = telegram_chat_state_unparse_bson(tcs);
    bson *q = bson_new();
    bson_append_int64(q, "_id", tcs->_id);
    bson_finish(q);

    if (!mongo_sync_cmd_update(conn->conn, mongo_conn_ns(conn, TELEGRAM_CHAT_STATES_TABLE_NAME), MONGO_WIRE_FLAG_UPDATE_UPSERT, q, b)) {
        err("save_token: failed: %s", os_ErrorMsg());
        goto cleanup;
    }

    retval = 0;

cleanup:
    bson_free(q);
    bson_free(b);
    return retval;
#else
#error mongo packages are missing
#endif
}

#undef TELEGRAM_CHAT_STATES_TABLE_NAME

#define TELEGRAM_SUBSCRIPTIONS_TABLE_NAME "telegram_subscriptions"

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
#error mongo packages are missing
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
#error mongo packages are missing
#endif
}

static struct telegram_subscription *
subscription_fetch_func(
        struct generic_conn *gc,
        const unsigned char *bot_id,
        int user_id,
        int contest_id)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#error mongo packages are missing
#endif
}

static int
subscription_save_func(
        struct generic_conn *gc,
        const struct telegram_subscription *sub)
{
    struct mongo_conn *conn = (struct mongo_conn *) gc;
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
#error mongo packages are missing
#endif
}

#undef TELEGRAM_SUBSCRIPTIONS_TABLE_NAME

#else  // HAVE_LIBMONGOC - 0 > 0 || HAVE_LIBMONGO_CLIENT - 0 == 1

struct generic_conn *
mongo_conn_create(void)
{
    return NULL;
}

#endif
