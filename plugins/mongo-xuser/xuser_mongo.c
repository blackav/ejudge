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
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <mongo.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define BPE (CHAR_BIT * sizeof(((struct team_extra*)0)->clar_map[0]))

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
static struct xuser_cnts_state *
close_func(
        struct xuser_cnts_state *data);
static const struct team_extra *
get_entry_func(
        struct xuser_cnts_state *data,
        int user_id);
static int
get_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid);
static int
set_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid);
static void
flush_func(
        struct xuser_cnts_state *data);
static int
append_warning_func(
        struct xuser_cnts_state *data,
        int user_id,
        int issuer_id,
        const ej_ip_t *issuer_ip,
        time_t issue_date,
        const unsigned char *txt,
        const unsigned char *cmt);
static int
set_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int status);
static int
set_disq_comment_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *disq_comment);
static int
get_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id);
static int
set_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id,
        int run_fields);
static int
count_read_clars_func(
        struct xuser_cnts_state *data,
        int user_id);
static struct xuser_team_extras *
get_entries_func(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids);

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
    get_entry_func,
    get_clar_status_func,
    set_clar_status_func,
    flush_func,
    append_warning_func,
    set_status_func,
    set_disq_comment_func,
    get_run_fields_func,
    set_run_fields_func,
    count_read_clars_func,
    get_entries_func,
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

static struct xuser_cnts_state *
close_func(
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

static int
parse_bson_int(
        bson_cursor *bc,
        const unsigned char *field_name,
        int *p_value,
        int check_low,
        int low_value,
        int check_high,
        int high_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_INT32) {
        err("parse_bson_int: int32 field type expected for '%s'", field_name);
        return -1;
    }
    int value = 0;
    if (!bson_cursor_get_int32(bc, &value)) {
        err("parse_bson_int: failed to fetch int32 value of '%s'", field_name);
        return -1;
    }
    if ((check_low > 0 && value < low_value) || (check_high > 0 && value >= high_value)) {
        err("parse_bson_int: invalid value of '%s': %d", field_name, value);
        return -1;
    }
    *p_value = value;
    return 1;
}

static int
parse_bson_utc_datetime(
        bson_cursor *bc,
        const unsigned char *field_name,
        time_t *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_UTC_DATETIME) {
        err("parse_bson_utc_datetime: utc_datetime field type expected for '%s'", field_name);
        return -1;
    }
    long long value = 0;
    if (!bson_cursor_get_utc_datetime(bc, &value)) {
        err("parse_bson_utc_datetime: failed to fetch utc_datetime value of '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = (time_t) (value / 1000);
    }
    return 1;
}

static int
parse_bson_uuid(
        bson_cursor *bc,
        const unsigned char *field_name,
        ej_uuid_t *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_BINARY) {
        err("parse_bson_uuid: uuid field type expected for '%s'", field_name);
        return -1;
    }

    bson_binary_subtype bt = 0;
    const unsigned char *bd = NULL;
    int bz = 0;
    if (!bson_cursor_get_binary(bc, &bt, &bd, &bz)) {
        err("parse_bson_uuid: failed to fetch binary data for '%s'", field_name);
        return -1;
    }
    if (bt != BSON_BINARY_SUBTYPE_UUID || bz != sizeof(ej_uuid_t)) {
        err("parse_bson_uuid: invalid binary data for in '%s'", field_name);
        return -1;
    }
    if (p_value) {
        memcpy(p_value, bd, sizeof(ej_uuid_t));
    }
    return 1;
}

static int
parse_bson_ip(
        bson_cursor *bc,
        const unsigned char *field_name,
        ej_ip_t *p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_STRING) {
        err("parse_bson_ip: string field type expected for '%s'", field_name);
        return -1;
    }
    const char *data = NULL;
    if (!bson_cursor_get_string(bc, &data)) {
        err("parse_bson_ip: failed to fetch string for '%s'", field_name);
        return -1;
    }
    if (!data) {
        err("parse_bson_ip: invalid string for in '%s'", field_name);
        return -1;
    }
    if (xml_parse_ipv6(NULL, 0, 0, 0, data, p_value) < 0) return -1;
    return 1;
}

static int
parse_bson_string(
        bson_cursor *bc,
        const unsigned char *field_name,
        unsigned char **p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_STRING) {
        err("parse_bson_string: string field type expected for '%s'", field_name);
        return -1;
    }
    const char *data = NULL;
    if (!bson_cursor_get_string(bc, &data)) {
        err("parse_bson_string: failed to fetch string for '%s'", field_name);
        return -1;
    }
    if (!data) {
        err("parse_bson_string: invalid string for in '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = xstrdup(data);
    }
    return 1;
}

static int
parse_bson_array(
        bson_cursor *bc,
        const unsigned char *field_name,
        bson **p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_ARRAY) {
        err("parse_bson_array: array field type expected for '%s'", field_name);
        return -1;
    }
    bson *data = NULL;
    if (!bson_cursor_get_array(bc, &data) || !data) {
        err("parse_bson_array: failed to fetch array for '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = data;
    } else {
        bson_free(data);
    }
    return 1;
}

static int
parse_bson_document(
        bson_cursor *bc,
        const unsigned char *field_name,
        bson **p_value)
{
    if (bson_cursor_type(bc) != BSON_TYPE_DOCUMENT) {
        err("parse_bson_document: array field type expected for '%s'", field_name);
        return -1;
    }
    bson *data = NULL;
    if (!bson_cursor_get_document(bc, &data) || !data) {
        err("parse_bson_document: failed to fetch document for '%s'", field_name);
        return -1;
    }
    if (p_value) {
        *p_value = data;
    } else {
        bson_free(data);
    }
    return 1;
}

static struct team_warning *
parse_bson_team_warning(bson *b)
{
    struct team_warning *res = NULL;
    bson_cursor *bc = NULL;

    if (!b) return NULL;

    XCALLOC(res, 1);
    bc = bson_cursor_new(b);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "date")) {
            if (parse_bson_utc_datetime(bc, "date", &res->date) < 0) goto fail;
        } else if (!strcmp(key, "issuer_id")) {
            if (parse_bson_int(bc, "issuer_id", &res->issuer_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "issuer_ip")) {
            if (parse_bson_ip(bc, "issuer_ip", &res->issuer_ip) < 0) goto fail;
        } else if (!strcmp(key, "text")) {
            if (parse_bson_string(bc, "text", &res->text) < 0) goto fail;
        } else if (!strcmp(key, "comment")) {
            if (parse_bson_string(bc, "comment", &res->comment) < 0) goto fail;
        }
    }
    bson_cursor_free(bc);

    return NULL;

fail:
    if (res) {
        xfree(res->text);
        xfree(res->comment);
        xfree(res);
    }
    if (bc) bson_cursor_free(bc);
    return NULL;
}

static struct team_extra *
parse_bson(bson *b)
{
    bson_cursor *bc = NULL;
    bson_cursor *bc2 = NULL;
    struct team_extra *res = NULL;
    bson *arr = NULL;
    bson *doc = NULL;
    struct team_warning *tw = NULL;

    if (!b) return NULL;

    XCALLOC(res, 1);
    bc = bson_cursor_new(b);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            if (parse_bson_uuid(bc, "_id", &res->uuid) < 0) goto fail;
        } else if (!strcmp(key, "contest_id")) {
            if (parse_bson_int(bc, "contest_id", &res->contest_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "user_id")) {
            if (parse_bson_int(bc, "user_id", &res->user_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "viewed_clars")) {
            if (parse_bson_array(bc, "viewed_clars", &arr) < 0) goto fail;
            bc2 = bson_cursor_new(arr);
            while (bson_cursor_next(bc2)) {
                int clar_id = 0;
                if (parse_bson_int(bc2, "viewed_clars/clar_id", &clar_id, 1, 0, 0, 0) < 0) goto fail;
                if (clar_id >= res->clar_map_size) team_extra_extend_clar_map(res, clar_id);
                res->clar_map[clar_id / BPE] |= (1UL << clar_id % BPE);
            }
            bson_cursor_free(bc2); bc2 = NULL;
            bson_free(arr); arr = NULL;
        } else if (!strcmp(key, "clar_uuids")) {
            if (parse_bson_array(bc, "clar_uuids", &arr) < 0) goto fail;
            bc2 = bson_cursor_new(arr);
            while (bson_cursor_next(bc2)) {
                ej_uuid_t uuid;
                if (parse_bson_uuid(bc2, "clar_uuids/uuid", &uuid) < 0) goto fail;
                team_extra_add_clar_uuid(res, &uuid);
            }
            bson_cursor_free(bc2); bc2 = NULL;
            bson_free(arr); arr = NULL;
        } else if (!strcmp(key, "disq_comment")) {
            if (parse_bson_string(bc, "disq_comment", &res->disq_comment) < 0) goto fail;
        } else if (!strcmp(key, "warnings")) {
            if (parse_bson_array(bc, "warnings", &arr) < 0) goto fail;
            bc2 = bson_cursor_new(arr);
            while (bson_cursor_next(bc2)) {
                if (parse_bson_document(bc, "warnings/warning", &doc) < 0) goto fail;
                if (!(tw = parse_bson_team_warning(doc))) goto fail;
                if (res->warn_u == res->warn_a) {
                    if (!(res->warn_a *= 2)) res->warn_a = 16;
                    XREALLOC(res->warns, res->warn_a);
                }
                res->warns[res->warn_u++] = tw; tw = NULL;
                bson_free(doc); doc = NULL;
            }
            bson_cursor_free(bc2); bc2 = NULL;
            bson_free(arr); arr = NULL;
        } else if (!strcmp(key, "status")) {
            if (parse_bson_int(bc, "status", &res->status, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "run_fields")) {
            if (parse_bson_int(bc, "run_fields", &res->run_fields, 1, 0, 0, 0) < 0) goto fail;
        }
    }
    bson_cursor_free(bc);
    return res;

fail:
    team_extra_free(res);
    if (doc) bson_free(doc);
    if (arr) bson_free(arr);
    if (bc2) bson_cursor_free(bc2);
    if (bc) bson_cursor_free(bc);
    return NULL;
}

static struct team_extra *
do_get_entry(
        struct xuser_mongo_cnts_state *state,
        int user_id)
{
    struct team_extra *extra = NULL;
    bson *query = NULL;
    mongo_packet *pkt = NULL;
    mongo_sync_cursor *cursor = NULL;
    bson *result = NULL;

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

    query = bson_new();
    bson_append_int32(query, "contest_id", state->contest_id);
    bson_append_int32(query, "user_id", user_id);
    bson_finish(query);
    if (!(pkt = mongo_sync_cmd_query(state->plugin_state->conn, "ejudge.xuser", 0, 0, 1, query, NULL))) {
        goto done;
    }
    if (!(cursor = mongo_sync_cursor_new(state->plugin_state->conn, "ejudge.xuser", pkt))) {
        goto done;
    }
    pkt = NULL; // ownership passed to 'cursor'
    while (mongo_sync_cursor_next(cursor)) {
        result = mongo_sync_cursor_get_data(cursor);
        if (!(extra = parse_bson(result))) {
            goto done;
        }
        bson_free(result); result = NULL;
    }
    if (!extra) {
        // query returned empty set
        XCALLOC(extra, 1);
        extra->user_id = user_id;
        extra->contest_id = state->contest_id;
    }
    if (state->u == state->a) {
        if (!(state->a *= 2)) state->a = 32;
        XREALLOC(state->v, state->a);
    }
    if (low < state->u) {
        memmove(&state->v[low + 1], &state->v, (state->u - low) * sizeof(state->v[0]));
    }
    state->v[low] = extra;
    ++state->u;

done:
    if (result) bson_free(result);
    if (cursor) mongo_sync_cursor_free(cursor);
    if (pkt) mongo_wire_packet_free(pkt);
    if (query) bson_free(query);
    return extra;
}

static const struct team_extra *
get_entry_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    return do_get_entry(state, user_id);
}

static int
get_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return 0;
    if (p_clar_uuid && team_extra_find_clar_uuid(extra, p_clar_uuid) >= 0) {
        return 1;
    }
    return 0;
}

static void
bson_append_uuid(bson *b, const unsigned char *key, const ej_uuid_t *p_uuid)
{
    bson_append_binary(b, key, BSON_BINARY_SUBTYPE_UUID, (const unsigned char *) p_uuid, sizeof(*p_uuid));
}

static bson *
unparse_clar_uuids(const struct team_extra *extra)
{
    bson *arr = bson_new();
    for (int i = 0; i < extra->clar_uuids_size; ++i) {
        unsigned char buf[32];
        sprintf(buf, "%d", i);
        bson_append_uuid(arr, buf, &extra->clar_uuids[i]);
    }
    bson_finish(arr);
    return arr;
 }

static bson *
unparse_bson(const struct team_extra *extra)
{
    bson *res = bson_new();
    bson_append_uuid(res, "_id", &extra->uuid);
    bson_append_int32(res, "user_id", extra->user_id);
    bson_append_int32(res, "contest_id", extra->contest_id);
    if (extra->disq_comment) {
        bson_append_string(res, "disq_comment", extra->disq_comment, strlen(extra->disq_comment));
    }
    bson_append_int32(res, "status", extra->status);
    bson_append_int32(res, "run_fields", extra->run_fields);
    if (extra->clar_map_size > 0) {
        bson *arr = bson_new();
        for (int i = 0, j = 0; i < extra->clar_map_size; ++i) {
            if (extra->clar_map[i / BPE] & (1UL << i % BPE)) {
                unsigned char buf[32];
                sprintf(buf, "%d", j++);
                bson_append_int32(arr, buf, i);
            }
        }
        bson_finish(arr);
        bson_append_document(res, "viewed_clars", arr);
        bson_free(arr); arr = NULL;
    }
    if (extra->clar_uuids_size > 0) {
        bson *arr = NULL;
        bson_append_document(res, "clar_uuids", (arr = unparse_clar_uuids(extra)));
        bson_free(arr); arr = NULL;
    }
    if (extra->warn_u > 0) {
    }
    /* FIXME: do warnings */
    bson_finish(res);
    return res;
}

/*
struct team_extra
{
  int clar_map_size;
  int clar_map_alloc;
  unsigned long *clar_map;

  int clar_uuids_size;
  int clar_uuids_alloc;
  ej_uuid_t *clar_uuids;

  // warnings
  int warn_u, warn_a;
  struct team_warning **warns;
};
*/

static int
do_insert(
        struct xuser_mongo_cnts_state *state,
        struct team_extra *extra)
{
    if (extra->contest_id <= 0) extra->contest_id = state->contest_id;
    if (!ej_uuid_is_nonempty(extra->uuid)) {
        ej_uuid_generate(&extra->uuid);
    }
    bson *b = unparse_bson(extra);
    if (!mongo_sync_cmd_insert(state->plugin_state->conn, "ejudge.xuser", b, NULL)) {
        err("do_insert: mongo query failed: %s", os_ErrorMsg());
        bson_free(b);
        return -1;
    }
    extra->is_dirty = 0;
    bson_free(b);
    return 0;
}

static int
set_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (!p_clar_uuid) return -1;
    int r = team_extra_add_clar_uuid(extra, p_clar_uuid);
    if (r <= 0) return r;
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson *filter = bson_new();
        bson_append_uuid(filter, "_id", &extra->uuid);
        bson_finish(filter);
        bson *update = bson_new();
        bson *arr = unparse_clar_uuids(extra);
        bson *doc = bson_new();
        bson_append_array(doc, "clar_uuids", arr);
        bson_free(arr); arr = NULL;
        bson_finish(doc);
        bson_append_document(update, "$set", doc);
        bson_free(doc); doc = NULL;
        bson_finish(update);

        int retval = 0;
        if (!mongo_sync_cmd_update(state->plugin_state->conn, "ejudge.xuser", 0, filter, update)) {
            err("set_clar_status: mongo update query failed: %s", os_ErrorMsg());
            retval = -1;
        }

        bson_free(update); update = NULL;
        bson_free(filter); filter = NULL;
        return retval;
    } else {
        return do_insert(state, extra);
    }
    return -1;
}

static void
flush_func(
        struct xuser_cnts_state *data)
{
}

static int
append_warning_func(
        struct xuser_cnts_state *data,
        int user_id,
        int issuer_id,
        const ej_ip_t *issuer_ip,
        time_t issue_date,
        const unsigned char *txt,
        const unsigned char *cmt)
{
    // TODO
    return -1;
}

static int
set_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int status)
{
    // TODO
    return -1;
}

static int
set_disq_comment_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *disq_comment)
{
    // TODO
    return -1;
}

static int
get_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return 0;
    return extra->run_fields;
}

static int
set_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id,
        int run_fields)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (extra->run_fields == run_fields) return 0;
    extra->run_fields = run_fields;
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson *filter = bson_new();
        bson_append_uuid(filter, "_id", &extra->uuid);
        bson_finish(filter);
        bson *update = bson_new();
        bson *doc = bson_new();
        bson_append_int32(doc, "run_fields", run_fields);
        bson_finish(doc);
        bson_append_document(update, "$set", doc);
        bson_free(doc); doc = NULL;
        bson_finish(update);

        int retval = 0;
        if (!mongo_sync_cmd_update(state->plugin_state->conn, "ejudge.xuser", 0, filter, update)) {
            err("set_clar_status: mongo update query failed: %s", os_ErrorMsg());
            retval = -1;
        }

        bson_free(update); update = NULL;
        bson_free(filter); filter = NULL;
        return retval;
    } else {
        return do_insert(state, extra);
    }
}

static int
count_read_clars_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return 0;
    return extra->clar_uuids_size;
}

static struct xuser_team_extras *
get_entries_func(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids)
{
    // TODO
    return NULL;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 *  compile-command: "make"
 * End:
 */
