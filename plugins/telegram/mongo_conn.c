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

#include <stdio.h>
#include <string.h>

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
    return NULL;
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
    return 0;
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

struct telegram_pbs;
struct telegram_pbs *
telegram_pbs_fetch(struct mongo_conn *conn, const unsigned char *bot_id);
int
telegram_pbs_save(struct mongo_conn *conn, const struct telegram_pbs *pbs);

static struct telegram_pbs *
pbs_fetch_func(
        struct generic_conn *gc,
        const unsigned char *bot_id)
{
    return telegram_pbs_fetch((struct mongo_conn *) gc, bot_id);
}

static int
pbs_save_func(
        struct generic_conn *gc,
        const struct telegram_pbs *pbs)
{
    return telegram_pbs_save((struct mongo_conn *) gc, pbs);
}

int
telegram_token_fetch(struct mongo_conn *conn, const unsigned char *token_str, struct telegram_token **p_token);

static int
token_fetch_func(
        struct generic_conn *gc,
        const unsigned char *token_str,
        struct telegram_token **p_token)
{
    return telegram_token_fetch((struct mongo_conn*) gc, token_str, p_token);
}

int
telegram_token_save(struct mongo_conn *conn, const struct telegram_token *token);

static int
token_save_func(
        struct generic_conn *gc,
        const struct telegram_token *token)
{
    return telegram_token_save((struct mongo_conn *) gc, token);
}

void
telegram_token_remove(struct mongo_conn *conn, const unsigned char *token);

static void
token_remove_func(
        struct generic_conn *gc,
        const unsigned char *token)
{
    telegram_token_remove((struct mongo_conn *) gc, token);
}

void
telegram_token_remove_expired(struct mongo_conn *conn, time_t current_time);

static void
token_remove_expired_func(
        struct generic_conn *gc,
        time_t current_time)
{
    telegram_token_remove_expired((struct mongo_conn *) gc, current_time);
}

struct telegram_chat *
telegram_chat_fetch(struct mongo_conn *conn, long long _id);

static struct telegram_chat *
chat_fetch_func(
        struct generic_conn *gc,
        long long _id)
{
    return telegram_chat_fetch((struct mongo_conn *) gc, _id);
}

int
telegram_chat_save(struct mongo_conn *conn, const struct telegram_chat *tc);

static int
chat_save_func(
        struct generic_conn *gc,
        const struct telegram_chat *tc)
{
    return telegram_chat_save((struct mongo_conn *) gc, tc);
}

struct telegram_user *
telegram_user_fetch(struct mongo_conn *conn, long long _id);

static struct telegram_user *
user_fetch_func(
        struct generic_conn *gc,
        long long _id)
{
    return telegram_user_fetch((struct mongo_conn *) gc, _id);
}

int
telegram_user_save(struct mongo_conn *conn, const struct telegram_user *tu);

static int
user_save_func(
        struct generic_conn *gc,
        const struct telegram_user *tu)
{
    return telegram_user_save((struct mongo_conn *) gc, tu);
}

struct telegram_chat_state *
telegram_chat_state_fetch(struct mongo_conn *conn, long long _id);

static struct telegram_chat_state *
chat_state_fetch_func(
        struct generic_conn *gc,
        long long _id)
{
    return telegram_chat_state_fetch((struct mongo_conn *) gc, _id);
}

int
telegram_chat_state_save(struct mongo_conn *conn, const struct telegram_chat_state *tcs);

static int
chat_state_save_func(
        struct generic_conn *gc,
        const struct telegram_chat_state *tcs)
{
    return telegram_chat_state_save((struct mongo_conn *) gc, tcs);
}

struct telegram_subscription *
telegram_subscription_fetch(struct mongo_conn *conn, const unsigned char *bot_id, int user_id, int contest_id);

static struct telegram_subscription *
subscription_fetch_func(
        struct generic_conn *gc,
        const unsigned char *bot_id,
        int user_id,
        int contest_id)
{
    return telegram_subscription_fetch((struct mongo_conn *) gc, bot_id, user_id, contest_id);
}

int
telegram_subscription_save(struct mongo_conn *conn, const struct telegram_subscription *subscription);

static int
subscription_save_func(
        struct generic_conn *gc,
        const struct telegram_subscription *subscription)
{
    return telegram_subscription_save((struct mongo_conn*) gc, subscription);
}
