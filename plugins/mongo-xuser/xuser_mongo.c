/* -*- mode: c -*- */

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/xml_utils.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/xuser_plugin.h"
#include "ejudge/contests.h"
#include "ejudge/team_extra.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <mongo.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

struct xuser_mongo_state
{
    int nref;

    unsigned char *host;
    int port;
    mongo_sync_connection *conn;
};

struct xuser_mongo_cnts_state
{
    struct xuser_cnts_state b;
    struct xuser_mongo_state *plugin_state;
    int contest_id;

    // entry cache
    int a, u;
    struct team_extra **v;
};

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);

static struct xuser_cnts_state *
open_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);
struct xuser_cnts_state *
close_func(
        struct xuser_cnts_state *data);

struct xuser_plugin_iface plugin_xuser_mongo =
{
    {
        {
            sizeof(struct xuser_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "xuser",
            "mongo",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    XUSER_PLUGIN_IFACE_VERSION,
    open_func,
    close_func,
};

static struct common_plugin_data *
init_func(void)
{
    struct xuser_mongo_state *state = NULL;
    XCALLOC(state, 1);
    return (struct common_plugin_data *) state;
}

static int
finish_func(struct common_plugin_data *data)
{
    struct xuser_mongo_state *state = (struct xuser_mongo_state *) data;

    if (state) {
        if (state->nref > 0) {
            err("xuser_mongo::finish: reference counter > 0");
            return -1;
        }

        xfree(state->host);
        memset(state, 0, sizeof(*state));
        xfree(state);
    }

    return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    struct xuser_mongo_state *state = (struct xuser_mongo_state *) data;

    // this plugin configuration subtree is pointed by 'tree'

    for (struct xml_tree *p = tree->first_down; p; p = p->right) {
        if (!strcmp(p->name[0], "host")) {
            if (xml_leaf_elem(p, &state->host, 1, 0) < 0) return -1;
        } else if (!strcmp(p->name[0], "port")) {
            if (xml_parse_int(NULL, "", p->line, p->column, p->text, &state->port) < 0) return -1;
            if (state->port < 0 || state->port > 65535) {
                xml_err_elem_invalid(p);
                return -1;
            }
        } else {
            return xml_err_elem_not_allowed(p);
        }
    }

    if (!state->host) state->host = xstrdup("localhost");
    if (state->port <= 0) state->port = 27027;

    state->conn = mongo_sync_connect(state->host, state->port, 0);
    if (!state->conn) {
        err("cannot connect to mongodb: %s", os_ErrorMsg());
        return -1;
    }

    return 0;
}

static struct xuser_cnts_state *
open_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    struct xuser_mongo_state *plugin_state = (struct xuser_mongo_state *) data;
    struct xuser_mongo_cnts_state *state = NULL;

    if (!plugin_state) return NULL;

    XCALLOC(state, 1);
    state->b.vt = &plugin_xuser_mongo;
    state->plugin_state = plugin_state;
    ++state->plugin_state->nref;
    state->contest_id = cnts->id;

    return (struct xuser_cnts_state *) state;
}

struct xuser_cnts_state *close_func(
        struct xuser_cnts_state *data)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    if (state) {
        --state->plugin_state->nref;
        // FIXME: close connection?
        xfree(state);
    }
    return NULL;
}

/*
struct team_extra
{
  // primary key
  ej_uuid_t uuid;

  int is_dirty;
  int user_id;

  int clar_map_size;
  int clar_map_alloc;
  unsigned long *clar_map;

  int clar_uuids_size;
  int clar_uuids_alloc;
  ej_uuid_t *clar_uuids;

  // disqualification reason
  unsigned char *disq_comment;

  // warnings
  int warn_u, warn_a;
  struct team_warning **warns;

  // status
  int status;

  // run table fields
  int run_fields;
};
 */

static struct team_extra *
parse_bson(bson *b)
{
    bson_cursor *bc = NULL;
    struct team_extra *res = NULL;

    if (!b) return NULL;

    XCALLOC(res, 1);
    bc = bson_cursor_new(b);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "uuid")) {
        } else if (!strcmp(key, "contest_id")) {
        } else if (!strcmp(key, "user_id")) {
        } else if (!strcmp(key, "viewed_clars")) {
        } else if (!strcmp(key, "clar_uuids")) {
        } else if (!strcmp(key, "disc_comment")) {
        } else if (!strcmp(key, "warnings")) {
        } else if (!strcmp(key, "status")) {
        } else if (!strcmp(key, "run_fields")) {
        }
    }
    bson_cursor_free(bc);
    return res;
}

const struct team_extra *
get_entry_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *res = NULL;

    if (user_id <= 0) return NULL;

    int low = 0, high = state->u, mid;
    while (low < high) {
        mid = (low + high) / 2;
        if (state->v[mid]->user_id == user_id) {
            return state->v[mid];
        } else if (state->v[mid]->user_id < user_id) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    mid = low;

    bson *query = bson_new();
    bson_append_int32(query, "contest_id", state->contest_id);
    bson_append_int32(query, "user_id", user_id);
    bson_finish(query);
    mongo_packet *pkt = mongo_sync_cmd_query(state->plugin_state->conn, "ejudge.xuser",
                                             0, 0, 1, query, NULL);
    bson_free(query); query = NULL;
    if (!pkt) {
        return NULL;
    }
    mongo_sync_cursor *cur = mongo_sync_cursor_new(state->plugin_state->conn, "ejudge.xuser", pkt);
    if (!cur) {
        mongo_wire_packet_free(pkt);
        return NULL;
    }
    while (mongo_sync_cursor_next(cur)) {
        bson *result = mongo_sync_cursor_get_data(cur);
        res = parse_bson(result);
        bson_free(result);
    }
    mongo_sync_cursor_free(cur);

    return res;
}


/*
 * Local variables:
 *  c-basic-offset: 4
 *  compile-command: "make"
 * End:
 */
