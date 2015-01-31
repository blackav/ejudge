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
#include "ejudge/bson_utils.h"
#include "ejudge/common_mongo_plugin.h"

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
    struct common_mongo_state *common;
    int nref;
    unsigned char *xuser_table;
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
        xfree(state->xuser_table);
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

    const struct common_loaded_plugin *common_plugin = NULL;
    if (!(common_plugin = plugin_load_external(0, "common", "mongo", config))) {
        err("cannot load common_mongo plugin");
        return -1;
    }

    state->common = (struct common_mongo_state *) common_plugin->data;
    unsigned char buf[1024];
    snprintf(buf, sizeof(buf), "%s.%sxuser", state->common->database, state->common->table_prefix);
    state->xuser_table = xstrdup(buf);

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
            if (ej_bson_parse_utc_datetime(bc, "date", &res->date) < 0) goto fail;
        } else if (!strcmp(key, "issuer_id")) {
            if (ej_bson_parse_int(bc, "issuer_id", &res->issuer_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "issuer_ip")) {
            if (ej_bson_parse_ip(bc, "issuer_ip", &res->issuer_ip) < 0) goto fail;
        } else if (!strcmp(key, "text")) {
            if (ej_bson_parse_string(bc, "text", &res->text) < 0) goto fail;
        } else if (!strcmp(key, "comment")) {
            if (ej_bson_parse_string(bc, "comment", &res->comment) < 0) goto fail;
        }
    }
    bson_cursor_free(bc);

    return res;

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
            if (ej_bson_parse_uuid(bc, "_id", &res->uuid) < 0) goto fail;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int(bc, "contest_id", &res->contest_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int(bc, "user_id", &res->user_id, 1, 1, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "viewed_clars")) {
            if (ej_bson_parse_array(bc, "viewed_clars", &arr) < 0) goto fail;
            bc2 = bson_cursor_new(arr);
            while (bson_cursor_next(bc2)) {
                int clar_id = 0;
                if (ej_bson_parse_int(bc2, "viewed_clars/clar_id", &clar_id, 1, 0, 0, 0) < 0) goto fail;
                if (clar_id >= res->clar_map_size) team_extra_extend_clar_map(res, clar_id);
                res->clar_map[clar_id / BPE] |= (1UL << clar_id % BPE);
            }
            bson_cursor_free(bc2); bc2 = NULL;
            bson_free(arr); arr = NULL;
        } else if (!strcmp(key, "clar_uuids")) {
            if (ej_bson_parse_array(bc, "clar_uuids", &arr) < 0) goto fail;
            bc2 = bson_cursor_new(arr);
            while (bson_cursor_next(bc2)) {
                ej_uuid_t uuid;
                if (ej_bson_parse_uuid(bc2, "clar_uuids/uuid", &uuid) < 0) goto fail;
                team_extra_add_clar_uuid(res, &uuid);
            }
            bson_cursor_free(bc2); bc2 = NULL;
            bson_free(arr); arr = NULL;
        } else if (!strcmp(key, "disq_comment")) {
            if (ej_bson_parse_string(bc, "disq_comment", &res->disq_comment) < 0) goto fail;
        } else if (!strcmp(key, "warnings")) {
            if (ej_bson_parse_array(bc, "warnings", &arr) < 0) goto fail;
            bc2 = bson_cursor_new(arr);
            while (bson_cursor_next(bc2)) {
                if (ej_bson_parse_document(bc2, "warnings/warning", &doc) < 0) goto fail;
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
            if (ej_bson_parse_int(bc, "status", &res->status, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "run_fields")) {
            if (ej_bson_parse_int(bc, "run_fields", &res->run_fields, 1, 0, 0, 0) < 0) goto fail;
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
find_entry(
        struct xuser_mongo_cnts_state *state,
        int user_id,
        int *p_pos)
{
    if (user_id <= 0) return NULL;

    int low = 0, high = state->u, mid;
    while (low < high) {
        mid = (low + high) / 2;
        if (state->v[mid]->user_id == user_id) {
            if (p_pos) *p_pos = mid;
            return state->v[mid];
        } else if (state->v[mid]->user_id < user_id) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if (p_pos) *p_pos = low;
    return NULL;
}

static void
insert_entry(
        struct xuser_mongo_cnts_state *state,
        int user_id,
        struct team_extra *extra,
        int pos)
{
    ASSERT(user_id > 0);
    if (pos < 0) {
        int low = 0, high = state->u, mid;
        while (low < high) {
            mid = (low + high) / 2;
            if (state->v[mid]->user_id == user_id) {
                err("insert_entry: entry %d is already inserted", user_id);
                abort();
            } else if (state->v[mid]->user_id < user_id) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        pos = low;
    }
    if (state->u == state->a) {
        if (!(state->a *= 2)) state->a = 32;
        XREALLOC(state->v, state->a);
    }
    if (pos < state->u) {
        memmove(&state->v[pos + 1], &state->v[pos], (state->u - pos) * sizeof(state->v[0]));
    }
    state->v[pos] = extra;
    ++state->u;
}

static struct team_extra *
do_get_entry(
        struct xuser_mongo_cnts_state *state,
        int user_id)
{
    struct team_extra *extra = NULL;
    bson *query = NULL;
    int pos = 0, count = 0;
    bson **results = NULL;

    if (user_id <= 0) return NULL;

    if ((extra = find_entry(state, user_id, &pos)))
        return extra;

    query = bson_new();
    bson_append_int32(query, "contest_id", state->contest_id);
    bson_append_int32(query, "user_id", user_id);
    bson_finish(query);
    count = state->plugin_state->common->i->query(state->plugin_state->common, "xuser", 0, 1, query, NULL, &results);
    if (count < 0) goto done;
    if (count > 1) {
        err("do_get_entry: multiple entries returned: %d", count);
        goto done;
    }
    if (count == 1) {
        if (!(extra = parse_bson(results[0]))) {
            goto done;
        }
    }
    if (!extra) {
        XCALLOC(extra, 1);
        extra->user_id = user_id;
        extra->contest_id = state->contest_id;
    }
    insert_entry(state, user_id, extra, pos);

done:
    if (query) bson_free(query);
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_free(results[i]);
        }
        xfree(results);
    }
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

static bson *
unparse_clar_uuids(const struct team_extra *extra)
{
    bson *arr = bson_new();
    for (int i = 0; i < extra->clar_uuids_size; ++i) {
        unsigned char buf[32];
        sprintf(buf, "%d", i);
        ej_bson_append_uuid(arr, buf, &extra->clar_uuids[i]);
    }
    bson_finish(arr);
    return arr;
}

static bson *
unparse_team_warning(const struct team_warning *tw)
{
    bson *res = bson_new();
    long long utc_dt = (long long) tw->date * 1000;
    bson_append_utc_datetime(res, "date", utc_dt);
    bson_append_int32(res, "issuer_id", tw->issuer_id);
    ej_bson_append_ip(res, "issuer_ip", &tw->issuer_ip);
    if (tw->text) {
        bson_append_string(res, "text", tw->text, strlen(tw->text));
    }
    if (tw->comment) {
        bson_append_string(res, "comment", tw->comment, strlen(tw->comment));
    }
    bson_finish(res);
    return res;
}

static bson *
unparse_team_warnings(struct team_warning **tws, int count)
{
    bson *res = bson_new();
    if (tws && count > 0) {
        for (int i = 0; i < count; ++i) {
            unsigned char buf[32];
            bson *w;
            sprintf(buf, "%d", i);
            bson_append_document(res, buf, (w = unparse_team_warning(tws[i])));
            bson_free(w);
        }
    }
    bson_finish(res);
    return res;
}

static bson *
unparse_array_int(const int *values, int count)
{
    bson *arr = bson_new();
    for (int i = 0; i < count; ++i) {
        unsigned char buf[32];
        sprintf(buf, "%d", i);
        bson_append_int32(arr, buf, values[i]);
    }
    bson_finish(arr);
    return arr;
}

static bson *
unparse_bson(const struct team_extra *extra)
{
    bson *res = bson_new();
    ej_bson_append_uuid(res, "_id", &extra->uuid);
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
        bson_append_array(res, "clar_uuids", (arr = unparse_clar_uuids(extra)));
        bson_free(arr); arr = NULL;
    }
    if (extra->warn_u > 0) {
        bson *arr = unparse_team_warnings(extra->warns, extra->warn_u);
        bson_append_array(res, "warnings", arr);
        bson_free(arr); arr = NULL;
    }
    bson_finish(res);
    return res;
}

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
    if (state->plugin_state->common->i->insert_and_free(state->plugin_state->common, "xuser", &b) < 0) {
        return -1;
    }
    return 0;
}

static int
do_update(
        struct xuser_mongo_cnts_state *state,
        struct team_extra *extra,
        const unsigned char *op,
        bson *update_doc)
{
    bson *filter = bson_new();
    ej_bson_append_uuid(filter, "_id", &extra->uuid);
    bson_finish(filter);
    bson *update = bson_new();
    if (!op) op = "$set";
    bson_append_document(update, op, update_doc);
    bson_finish(update);

    int retval = state->plugin_state->common->i->update(state->plugin_state->common, "xuser", filter, update);
    bson_free(update); update = NULL;
    bson_free(filter); filter = NULL;
    bson_free(update_doc); update_doc = NULL;
    return retval;
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
        bson *arr = unparse_clar_uuids(extra);
        bson *doc = bson_new();
        bson_append_array(doc, "clar_uuids", arr);
        bson_free(arr); arr = NULL;
        bson_finish(doc);
        return do_update(state, extra, NULL, doc);
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
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;

    if (extra->warn_u == extra->warn_a) {
        extra->warn_a *= 2;
        if (!extra->warn_a) extra->warn_a = 8;
        XREALLOC(extra->warns, extra->warn_a);
    }
    struct team_warning *cur_warn = NULL;
    XCALLOC(cur_warn, 1);
    extra->warns[extra->warn_u++] = cur_warn;

    cur_warn->date = issue_date;
    cur_warn->issuer_id = issuer_id;
    cur_warn->issuer_ip = *issuer_ip;
    cur_warn->text = xstrdup(txt);
    cur_warn->comment = xstrdup(cmt);
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson *w = unparse_team_warning(cur_warn);
        bson *doc = bson_new();
        bson_append_document(doc, "warnings", w);
        bson_free(w); w = NULL;
        bson_finish(doc);
        return do_update(state, extra, "$push", doc);
    } else {
        return do_insert(state, extra);
    }
}

static int
set_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int status)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (extra->status == status) return 0;
    extra->status = status;
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson *doc = bson_new();
        bson_append_int32(doc, "status", status);
        bson_finish(doc);
        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
}

static int
set_disq_comment_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *disq_comment)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (!extra->disq_comment && !disq_comment) {
        return 0;
    }
    if (extra->disq_comment && !disq_comment) {
        ASSERT(ej_uuid_is_nonempty(extra->uuid));
        xfree(extra->disq_comment); extra->disq_comment = NULL;
        bson *doc = bson_new();
        bson_append_string(doc, "disq_comment", "", 0);
        bson_finish(doc);
        return do_update(state, extra, "$unset", doc);
    }
    if (extra->disq_comment && !strcmp(extra->disq_comment, disq_comment))
        return 0;
    xfree(extra->disq_comment);
    extra->disq_comment = xstrdup(disq_comment);
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson *doc = bson_new();
        bson_append_string(doc, "disq_comment", extra->disq_comment, strlen(extra->disq_comment));
        bson_finish(doc);
        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
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
        bson *doc = bson_new();
        bson_append_int32(doc, "run_fields", run_fields);
        bson_finish(doc);

        return do_update(state, extra, NULL, doc);
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

static int 
isort_func(const void *p1, const void *p2)
{
    const int *i1 = (const int *) p1;
    const int *i2 = (const int *) p2;
    if (*i1 < *i2) return -1;
    if (*i1 > *i2) return 1;
    return 0;
}

struct xuser_mongo_team_extras
{
    struct xuser_team_extras b;

    struct xuser_mongo_cnts_state *state;
};

static struct xuser_team_extras *
xuser_mongo_team_extras_free(struct xuser_team_extras *x)
{
    struct xuser_mongo_team_extras *xm = (struct xuser_mongo_team_extras *) x;
    if (xm) {
        xfree(xm);
    }
    return NULL;
}

static const struct team_extra *
xuser_mongo_team_extras_get(struct xuser_team_extras *x, int user_id)
{
    struct xuser_mongo_team_extras *xm = (struct xuser_mongo_team_extras*) x;
    return find_entry(xm->state, user_id, NULL);
}

static struct xuser_team_extras *
get_entries_func(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    int *loc_users = NULL;
    int loc_count = count, query_count = 0;
    struct xuser_mongo_team_extras *res = NULL;
    bson **query_results = NULL;
    struct team_extra *extra = NULL;

    if (count <= 0 || !user_ids) return NULL;

    XCALLOC(res, 1);
    res->b.free = xuser_mongo_team_extras_free;
    res->b.get = xuser_mongo_team_extras_get;
    res->state = state;

    /*
    fprintf(stderr, "[ ");
    for (int ii = 0; ii < count; ++ii)
        fprintf(stderr, " %d", user_ids[ii]);
    fprintf(stderr, " ]\n");
    */

    XCALLOC(loc_users, loc_count);
    memcpy(loc_users, user_ids, loc_count * sizeof(user_ids[0]));
    qsort(loc_users, loc_count, sizeof(loc_users[0]), isort_func);

    /*
    fprintf(stderr, "[ ");
    for (int ii = 0; ii < loc_count; ++ii)
        fprintf(stderr, " %d", loc_users[ii]);
    fprintf(stderr, " ]\n");
    */

    /*
    fprintf(stderr, "<");
    for (int ii = 0; ii < state->u; ++ii)
        fprintf(stderr, " %d", state->v[ii]->user_id);
    fprintf(stderr, " >\n");
    */

    // copy the existing users
    for (int i1 = 0, i2 = 0; i1 < state->u && i2 < loc_count; ) {
        if (state->v[i1]->user_id == loc_users[i2]) {
            // copy that user
            loc_users[i2++] = 0;
            ++i1;
        } else if (state->v[i1]->user_id < loc_users[i2]) {
            ++i1;
        } else {
            ++i2;
        }
    }

    /*
    fprintf(stderr, "[ ");
    for (int ii = 0; ii < loc_count; ++ii)
        fprintf(stderr, " %d", loc_users[ii]);
    fprintf(stderr, " ]\n");
    */

    // compress the user_ids
    int i1 = 0, i2 = 0;
    for (; i2 < loc_count; ++i2) {
        if (loc_users[i2] > 0) {
            if (i1 == i2) {
                ++i1;
            } else {
                loc_users[i1++] = loc_users[i2];
            }
        }
    }
    loc_count = i1;

    /*
    fprintf(stderr, "[ ");
    for (int ii = 0; ii < loc_count; ++ii)
        fprintf(stderr, " %d", loc_users[ii]);
    fprintf(stderr, " ]\n");
    */

    if (loc_count <= 0) goto done;

    bson *arr = unparse_array_int(loc_users, loc_count);
    bson *indoc = bson_new();
    bson_append_array(indoc, "$in", arr);
    bson_finish(indoc);
    bson_free(arr); arr = NULL;
    bson *query = bson_new();
    bson_append_int32(query, "contest_id", state->contest_id);
    bson_append_document(query, "user_id", indoc);
    bson_finish(query);
    bson_free(indoc); indoc = NULL;

    query_count = state->plugin_state->common->i->query(state->plugin_state->common, "xuser", 0, loc_count, query, NULL, &query_results);
    if (query_count > 0) {
        for (i1 = 0; i1 < query_count; ++i1) {
            if ((extra = parse_bson(query_results[i1]))) {
                insert_entry(state, extra->user_id, extra, -1);
            }
            bson_free(query_results[i1]); query_results[i1] = NULL;
        }
    }
    bson_free(query); query = NULL;
    xfree(query_results); query_results = NULL;

    // remove existing entries from loc_count
    for (i1 = 0, i2 = 0; i1 < state->u && i2 < loc_count; ) {
        if (state->v[i1]->user_id == loc_users[i2]) {
            // copy that user
            loc_users[i2++] = 0;
            ++i1;
        } else if (state->v[i1]->user_id < loc_users[i2]) {
            ++i1;
        } else {
            ++i2;
        }
    }
    i1 = 0; i2 = 0;
    for (; i2 < loc_count; ++i2) {
        if (loc_users[i2] > 0) {
            if (i1 == i2) {
                ++i1;
            } else {
                loc_users[i1++] = loc_users[i2];
            }
        }
    }
    loc_count = i1;

    /*
    fprintf(stderr, "[ ");
    for (int ii = 0; ii < loc_count; ++ii)
        fprintf(stderr, " %d", loc_users[ii]);
    fprintf(stderr, " ]\n");
    */

    for (i1 = 0; i1 < loc_count; ++i1) {
        struct team_extra *extra = NULL;
        XCALLOC(extra, 1);
        extra->user_id = loc_users[i1];
        extra->contest_id = state->contest_id;
        insert_entry(state, extra->user_id, extra, -1);
    }

    /*
    fprintf(stderr, "<");
    for (int ii = 0; ii < state->u; ++ii)
        fprintf(stderr, " %d", state->v[ii]->user_id);
    fprintf(stderr, " >\n");
    */

done:
    return &res->b;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 *  compile-command: "make"
 * End:
 */
