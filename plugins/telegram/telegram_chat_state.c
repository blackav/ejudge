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
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"

#include "telegram_chat_state.h"
#include "mongo_conn.h"

#include <mongo.h>

#include <errno.h>

#define TELEGRAM_CHAT_STATES_TABLE_NAME "telegram_chat_states"

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

struct telegram_chat_state *
telegram_chat_state_parse_bson(struct _bson *bson)
{
    bson_cursor *bc = NULL;
    struct telegram_chat_state *tcs = NULL;

    XCALLOC(tcs, 1);
    bc = bson_cursor_new(bson);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (ej_bson_parse_int64(bc, "_id", &tcs->_id) < 0) goto cleanup;
        }
    }
    bson_cursor_free(bc);
    return tcs;

cleanup:
    telegram_chat_state_free(tcs);
    return NULL;
}

bson *
telegram_chat_state_unparse_bson(const struct telegram_chat_state *tcs)
{
    if (!tcs) return NULL;

    bson *bson = bson_new();
    if (tcs->_id) {
        bson_append_int64(bson, "_id", tcs->_id);
    }
    bson_finish(bson);
    return bson;
}

struct telegram_chat_state *
telegram_chat_state_fetch(struct mongo_conn *conn, long long _id)
{
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
}

int
telegram_chat_state_state_save(struct mongo_conn *conn, const struct telegram_chat_state *tcs)
{
    if (!mongo_conn_open(conn)) return -1;
    int retval = -1;

    bson *b = telegram_chat_state_unparse_bson(tcs);

    if (!mongo_sync_cmd_insert(conn->conn, mongo_conn_ns(conn, TELEGRAM_CHAT_STATES_TABLE_NAME), b, NULL)) {
        err("save_token: failed: %s", os_ErrorMsg());
        goto cleanup;
    }

    retval = 0;

cleanup:
    bson_free(b);
    return retval;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
