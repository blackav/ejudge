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

#include "telegram_pbs.h"
#include "mongo_conn.h"

#include <mongo.h>

#include <errno.h>

#define TELEGRAM_BOTS_TABLE_NAME "telegram_bots"

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

int
telegram_pbs_save(struct mongo_conn *conn, const struct telegram_pbs *pbs)
{
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
}

struct telegram_pbs *
telegram_pbs_fetch(struct mongo_conn *conn, const unsigned char *bot_id)
{
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
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
