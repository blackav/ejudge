/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2015-2023 Alexander Chernov <cher@ejudge.ru> */

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

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
#include <mongo.h>
#endif

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

struct team_extra *
team_extra_bson_parse(ej_bson_t *b);
ej_bson_t *
team_warning_bson_unparse(const struct team_warning *tw);
ej_bson_t *
team_extra_bson_unparse(const struct team_extra *extra);

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
static long long
get_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id);
static int
set_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id,
        long long run_fields);
static int
count_read_clars_func(
        struct xuser_cnts_state *data,
        int user_id);
static struct xuser_team_extras *
get_entries_func(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids);
static int
set_problem_dir_prefix_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *problem_dir_prefix);
static int
get_user_ids_func(
        struct xuser_cnts_state *data,
        int *p_count,
        int **p_user_ids);

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
    set_problem_dir_prefix_func,
    get_user_ids_func,
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

        for (int i = 0; i < state->u; ++i) {
            team_extra_free(state->v[i]);
        }
        xfree(state->v);
        xfree(state);
    }
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

static void __attribute__((unused))
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
#if HAVE_LIBMONGOC - 0 > 0
    struct team_extra *extra = NULL;
    int pos = 0, count = 0;
    bson_t *query = NULL;
    bson_t **results = NULL;

    if (user_id <= 0) return NULL;

    if ((extra = find_entry(state, user_id, &pos)))
        return extra;

    query = bson_new();
    bson_append_int32(query, "contest_id", -1, state->contest_id);
    bson_append_int32(query, "user_id", -1, user_id);
    count = state->plugin_state->common->i->query(state->plugin_state->common, "xuser", 0, 1, query, NULL, &results);
    if (count < 0) goto done;
    if (count > 1) {
        err("do_get_entry: multiple entries returned: %d", count);
        goto done;
    }
    if (count == 1) {
        if (!(extra = team_extra_bson_parse(results[0]))) {
            goto done;
        }
    }
    if (!extra) {
        XCALLOC(extra, 1);
        extra->user_id = user_id;
        extra->contest_id = state->contest_id;
    }
    insert_entry(state, user_id, extra, pos);
done:;
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_destroy(results[i]);
        }
        xfree(results);
    }
    if (query) bson_destroy(query);
    return extra;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
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
        if (!(extra = team_extra_bson_parse(results[0]))) {
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
#else
    return NULL;
#endif
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

static int __attribute__((unused))
do_insert(
        struct xuser_mongo_cnts_state *state,
        struct team_extra *extra)
{
#if HAVE_LIBMONGOC - 0 > 0
    if (extra->contest_id <= 0) extra->contest_id = state->contest_id;
    if (!ej_uuid_is_nonempty(extra->uuid)) {
        ej_uuid_generate(&extra->uuid);
    }
    bson_t *b = team_extra_bson_unparse(extra);
    if (state->plugin_state->common->i->insert_and_free(state->plugin_state->common, "xuser", &b) < 0) {
        return -1;
    }
    return 0;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    if (extra->contest_id <= 0) extra->contest_id = state->contest_id;
    if (!ej_uuid_is_nonempty(extra->uuid)) {
        ej_uuid_generate(&extra->uuid);
    }
    bson *b = team_extra_bson_unparse(extra);
    if (state->plugin_state->common->i->insert_and_free(state->plugin_state->common, "xuser", &b) < 0) {
        return -1;
    }
    return 0;
#else
    return -1;
#endif
}

static int __attribute__((unused))
do_update(
        struct xuser_mongo_cnts_state *state,
        struct team_extra *extra,
        const unsigned char *op,
        ej_bson_t *update_doc)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_t *filter = bson_new();
    ej_bson_append_uuid_new(filter, "_id", &extra->uuid);
    bson_t *update = bson_new();
    if (!op) op = "$set";
    bson_append_document(update, op, -1, update_doc);
    bson_destroy(update_doc); update_doc = NULL;

    int retval = state->plugin_state->common->i->update_and_free(state->plugin_state->common, "xuser", &filter, &update);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
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
#else
    return -1;
#endif
}

static int
set_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (!p_clar_uuid) return -1;
    int r = team_extra_add_clar_uuid(extra, p_clar_uuid);
    if (r <= 0) return r;
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson_t *arr = ej_bson_unparse_array_uuid_new(extra->clar_uuids, extra->clar_uuids_size);
        bson_t *doc = bson_new();
        bson_append_array(doc, "clar_uuids", -1, arr);
        bson_destroy(arr); arr = NULL;
        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
    return -1;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (!p_clar_uuid) return -1;
    int r = team_extra_add_clar_uuid(extra, p_clar_uuid);
    if (r <= 0) return r;
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson *arr = ej_bson_unparse_array_uuid(extra->clar_uuids, extra->clar_uuids_size);
        bson *doc = bson_new();
        bson_append_array(doc, "clar_uuids", arr);
        bson_free(arr); arr = NULL;
        bson_finish(doc);
        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
    return -1;
#else
    return -1;
#endif
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
#if HAVE_LIBMONGOC - 0 > 0
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
        bson_t *w = team_warning_bson_unparse(cur_warn);
        bson_t *doc = bson_new();
        bson_append_document(doc, "warnings", -1, w);
        bson_destroy(w); w = NULL;
        return do_update(state, extra, "$push", doc);
    } else {
        return do_insert(state, extra);
    }
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
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
        bson *w = team_warning_bson_unparse(cur_warn);
        bson *doc = bson_new();
        bson_append_document(doc, "warnings", w);
        bson_free(w); w = NULL;
        bson_finish(doc);
        return do_update(state, extra, "$push", doc);
    } else {
        return do_insert(state, extra);
    }
#else
    return -1;
#endif
}

static int
set_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int status)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (extra->status == status) return 0;
    extra->status = status;
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson_t *doc = bson_new();
        bson_append_int32(doc, "status", -1, status);
        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
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
#else
    return -1;
#endif
}

static int
set_disq_comment_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *disq_comment)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (!extra->disq_comment && !disq_comment) {
        return 0;
    }
    if (extra->disq_comment && !disq_comment) {
        ASSERT(ej_uuid_is_nonempty(extra->uuid));
        xfree(extra->disq_comment); extra->disq_comment = NULL;
        bson_t *doc = bson_new();
        bson_append_utf8(doc, "disq_comment", -1, "", 0);
        return do_update(state, extra, "$unset", doc);
    }
    if (extra->disq_comment && !strcmp(extra->disq_comment, disq_comment))
        return 0;
    xfree(extra->disq_comment);
    extra->disq_comment = xstrdup(disq_comment);
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson_t *doc = bson_new();
        bson_append_utf8(doc, "disq_comment", -1, extra->disq_comment, -1);
        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
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
#else
    return -1;
#endif
}

static long long
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
        long long run_fields)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (extra->run_fields == run_fields) return 0;
    extra->run_fields = run_fields;
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson_t *doc = bson_new();
        bson_append_int64(doc, "run_fields", -1, run_fields);
        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (extra->run_fields == run_fields) return 0;
    extra->run_fields = run_fields;
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson *doc = bson_new();
        bson_append_int64(doc, "run_fields", run_fields);
        bson_finish(doc);

        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
#else
    return -1;
#endif
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

static int __attribute__((unused))
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

/*static*/ struct xuser_team_extras * __attribute__((unused))
xuser_mongo_team_extras_free(struct xuser_team_extras *x)
{
    struct xuser_mongo_team_extras *xm = (struct xuser_mongo_team_extras *) x;
    if (xm) {
        xfree(xm);
    }
    return NULL;
}

/*static*/ const struct team_extra * __attribute__((unused))
xuser_mongo_team_extras_get(struct xuser_team_extras *x, int user_id)
{
    struct xuser_mongo_team_extras *xm = (struct xuser_mongo_team_extras*) x;
    return find_entry(xm->state, user_id, NULL);
}

static struct xuser_team_extras * __attribute__((unused))
get_entries_func(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids)
{
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    int *loc_users = NULL;
    int loc_count = count;
    struct xuser_mongo_team_extras *res = NULL;

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

#if HAVE_LIBMONGOC - 0 > 0
    {
        int query_count = 0;
        struct team_extra *extra = NULL;
        bson_t **query_results = NULL;
        bson_t *arr = ej_bson_unparse_array_int_new(loc_users, loc_count);
        bson_t *indoc = bson_new();
        bson_append_array(indoc, "$in", -1, arr);
        bson_destroy(arr); arr = NULL;
        bson_t *query = bson_new();
        bson_append_int32(query, "contest_id", -1, state->contest_id);
        bson_append_document(query, "user_id", -1, indoc);
        bson_destroy(indoc); indoc = NULL;

        query_count = state->plugin_state->common->i->query(state->plugin_state->common, "xuser", 0, loc_count, query, NULL, &query_results);
        if (query_count > 0) {
            for (i1 = 0; i1 < query_count; ++i1) {
                if ((extra = team_extra_bson_parse(query_results[i1]))) {
                    insert_entry(state, extra->user_id, extra, -1);
                }
                bson_destroy(query_results[i1]); query_results[i1] = NULL;
            }
        }
        bson_destroy(query); query = NULL;
        xfree(query_results); query_results = NULL;
    }
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    {
        int query_count = 0;
        struct team_extra *extra = NULL;
        bson **query_results = NULL;
        bson *arr = ej_bson_unparse_array_int(loc_users, loc_count);
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
                if ((extra = team_extra_bson_parse(query_results[i1]))) {
                    insert_entry(state, extra->user_id, extra, -1);
                }
                bson_free(query_results[i1]); query_results[i1] = NULL;
            }
        }
        bson_free(query); query = NULL;
        xfree(query_results); query_results = NULL;
    }
#else
    return NULL;
#endif

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

static int
set_problem_dir_prefix_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *problem_dir_prefix)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (!extra->problem_dir_prefix && !problem_dir_prefix) {
        return 0;
    }
    if (extra->problem_dir_prefix && !problem_dir_prefix) {
        ASSERT(ej_uuid_is_nonempty(extra->uuid));
        xfree(extra->problem_dir_prefix); extra->problem_dir_prefix = NULL;
        bson_t *doc = bson_new();
        bson_append_utf8(doc, "problem_dir_prefix", -1, "", 0);
        return do_update(state, extra, "$unset", doc);
    }
    if (extra->problem_dir_prefix && !strcmp(extra->problem_dir_prefix, problem_dir_prefix))
        return 0;
    xfree(extra->problem_dir_prefix);
    extra->problem_dir_prefix = xstrdup(problem_dir_prefix);
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson_t *doc = bson_new();
        bson_append_utf8(doc, "problem_dir_prefix", -1, extra->problem_dir_prefix, -1);
        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    struct team_extra *extra = do_get_entry(state, user_id);
    if (!extra) return -1;
    if (!extra->problem_dir_prefix && !problem_dir_prefix) {
        return 0;
    }
    if (extra->problem_dir_prefix && !problem_dir_prefix) {
        ASSERT(ej_uuid_is_nonempty(extra->uuid));
        xfree(extra->problem_dir_prefix); extra->problem_dir_prefix = NULL;
        bson *doc = bson_new();
        bson_append_string(doc, "problem_dir_prefix", "", 0);
        bson_finish(doc);
        return do_update(state, extra, "$unset", doc);
    }
    if (extra->problem_dir_prefix && !strcmp(extra->problem_dir_prefix, problem_dir_prefix))
        return 0;
    xfree(extra->problem_dir_prefix);
    extra->problem_dir_prefix = xstrdup(problem_dir_prefix);
    if (ej_uuid_is_nonempty(extra->uuid)) {
        bson *doc = bson_new();
        bson_append_string(doc, "problem_dir_prefix", extra->problem_dir_prefix, strlen(extra->problem_dir_prefix));
        bson_finish(doc);
        return do_update(state, extra, NULL, doc);
    } else {
        return do_insert(state, extra);
    }
#else
    return -1;
#endif
}

static int
get_user_ids_func(
        struct xuser_cnts_state *data,
        int *p_count,
        int **p_user_ids)
{
    // db.xuser.find({"contest_id":ID},{"user_id":1}).sort({"user_id":1})
    struct xuser_mongo_cnts_state *state = (struct xuser_mongo_cnts_state *) data;
    *p_count = 0;
    int size = 0;
    int reserved = 0;
    int *user_ids = NULL;

#if HAVE_LIBMONGOC - 0 > 0
    bson_t *query = NULL;
    bson_t *sel = NULL;
    bson_t **results = NULL;
    bson_iter_t iter;
    int count = 0;
    query = bson_new();
    bson_append_int32(query, "contest_id", -1, state->contest_id);
    sel = bson_new();
    bson_append_int32(sel, "user_id", -1, 1);
    count = state->plugin_state->common->i->query(state->plugin_state->common, "xuser", 0, 1, query, NULL, &results);
    if (count > 0) {
        for (int i = 0; i < count; ++i) {
            bson_iter_init(&iter, results[i]);
            if (bson_iter_find(&iter, "user_id")) {
                if (bson_iter_type(&iter) == BSON_TYPE_INT32) {
                    int user_id = bson_iter_int32(&iter);
                    if (size == reserved) {
                        if (!(reserved *= 2)) reserved = 16;
                        XREALLOC(user_ids, reserved);
                    }
                    user_ids[size++] = user_id;
                }
            }
        }
    }
    if (size > 1) {
        qsort(user_ids, size, sizeof(user_ids[0]), isort_func);
    }
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_destroy(results[i]);
        }
        xfree(results);
    }
    if (query) bson_destroy(query);
    if (sel) bson_destroy(sel);
    *p_count = size;
    *p_user_ids = user_ids;
    return 0;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson *query = NULL;
    bson *sel = NULL;
    int count = 0;
    bson **results = NULL;
    bson_cursor *bc = NULL;

    query = bson_new();
    bson_append_int32(query, "contest_id", state->contest_id);
    bson_finish(query);
    sel = bson_new();
    bson_append_int32(sel, "user_id", 1);
    bson_finish(sel);
    count = state->plugin_state->common->i->query(state->plugin_state->common, "xuser", 0, 1, query, NULL, &results);
    if (count > 0) {
        for (int i = 0; i < count; ++i) {
            int user_id = 0;
            bc = bson_cursor_new(results[i]);
            if (bson_cursor_find(bc, "user_id")
                && bson_cursor_type(bc) == BSON_TYPE_INT32
                && bson_cursor_get_int32(bc, &user_id)) {
                if (size == reserved) {
                    if (!(reserved *= 2)) reserved = 16;
                    XREALLOC(user_ids, reserved);
                }
                user_ids[size++] = user_id;
            }
            bson_cursor_free(bc); bc = NULL;
        }
    }
    if (size > 1) {
        qsort(user_ids, size, sizeof(user_ids[0]), isort_func);
    }
    if (bc) bson_cursor_free(bc);
    if (query) bson_free(query);
    if (sel) bson_free(sel);
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_free(results[i]);
        }
        xfree(results);
    }
    *p_count = size;
    *p_user_ids = user_ids;
    return 0;
#else
    return 0;
#endif
}
