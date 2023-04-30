/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2019-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/status_plugin.h"
#include "ejudge/bson_utils.h"
#include "ejudge/statusdb.h"
#include "ejudge/errlog.h"
#include "ejudge/contests.h"
#include "ejudge/common_mongo_plugin.h"

#include "ejudge/xalloc.h"

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
#include <mongo.h>
#endif

#include <errno.h>

struct status_mongo_plugin_state
{
    struct status_common_plugin_state b;

    struct common_mongo_state *common;
    int nref;
    unsigned char *status_table;
    int contest_id_index_created;
};

struct status_mongo_state
{
    struct statusdb_state b;
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
static struct statusdb_state *
open_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);
static void
close_func(struct statusdb_state *sds);
static int
load_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        struct prot_serve_status *stat);
static int
save_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        const struct prot_serve_status *stat);
static void
remove_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global);
static int
has_status_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);

static int
serve_status_bson_parse(
        ej_bson_t *bson,
        struct prot_serve_status *status)
    __attribute__((unused));
static ej_bson_t *
serve_status_bson_unparse(
        const struct prot_serve_status *status)
    __attribute__((unused));


struct status_plugin_iface plugin_status_mongo =
{
    {
        {
            sizeof(struct status_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "status",
            "mongo"
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func
    },
    STATUS_PLUGIN_IFACE_VERSION,
    open_func,
    close_func,
    load_func,
    save_func,
    remove_func,
    has_status_func,
};

static struct common_plugin_data *
init_func(void)
{
    struct status_mongo_plugin_state *state = NULL;
    XCALLOC(state, 1);
    return &state->b.b;
}

static int
finish_func(struct common_plugin_data *data)
{
    struct status_mongo_plugin_state *state = (struct status_mongo_plugin_state *) data;

    if (state) {
        xfree(state->status_table);
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
    struct status_mongo_plugin_state *state = (struct status_mongo_plugin_state *) data;

    const struct common_loaded_plugin *common_plugin = NULL;
    if (!(common_plugin = plugin_load_external(0, "common", "mongo", config))) {
        err("cannot load common_mongo plugin");
        return -1;
    }

    state->common = (struct common_mongo_state *) common_plugin->data;
    char *tmp = NULL;
    __attribute__((unused)) int _;
    _ = asprintf(&tmp, "%s.%status", state->common->database, state->common->table_prefix);
    state->status_table = tmp;

    return 0;
}

static struct statusdb_state *
open_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    struct status_mongo_state *sms = NULL;
    XCALLOC(sms, 1);
    sms->b.plugin = self;
    return &sms->b;
}

static void
close_func(struct statusdb_state *sds)
{
    struct status_mongo_state *sms = (struct status_mongo_state *) sds;
    xfree(sms);
}

static int
load_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        struct prot_serve_status *stat)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct status_mongo_state *sms = (struct status_mongo_state *) sds;
    struct status_mongo_plugin_state *ps = (struct status_mongo_plugin_state *) sms->b.plugin->data;
    int retval = -1;
    bson_t *query = NULL;
    int count;
    bson_t **results = NULL;
    bson_iter_t iter;
    bson_t *doc = NULL;

    query = bson_new();
    bson_append_int32(query, "contest_id", -1, cnts->id);
    count = ps->common->i->query(ps->common, "status", 0, 1, query, NULL, &results);
    if (count < 0) goto cleanup;
    if (count > 1) {
        err("load_func: multiple entries returned: %d", count);
        goto cleanup;
    }
    if (count == 1 && results[0]) {
        if (!bson_iter_init(&iter, results[0])) goto cleanup;
        if (!bson_iter_find(&iter, "s")) goto cleanup;
        if (ej_bson_parse_document_new(&iter, "s", &doc) < 0) goto cleanup;
        if (serve_status_bson_parse(doc, stat) < 0) goto cleanup;
        retval = 1;
    } else {
        retval = 0;
    }

cleanup:;
    if (doc) bson_destroy(doc);
    if (query) bson_destroy(query);
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_destroy(results[i]);
        }
        xfree(results);
    }
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct status_mongo_state *sms = (struct status_mongo_state *) sds;
    struct status_mongo_plugin_state *ps = (struct status_mongo_plugin_state *) sms->b.plugin->data;
    bson *query = NULL;
    int count = 0;
    bson **results = NULL;
    bson *bs = NULL;
    int retval = -1;
    bson_cursor *bc = NULL;

    query = bson_new();
    bson_append_int32(query, "contest_id", cnts->id);
    bson_finish(query);

    count = ps->common->i->query(ps->common, "status", 0, 1, query, NULL, &results);
    if (count < 0) goto done;
    if (count > 1) {
        err("load_func: multiple entries returned: %d", count);
        goto done;
    }
    if (count == 1) {
        bc = bson_find(results[0], "s");
        if (bc) {
            if (bson_cursor_type(bc) != BSON_TYPE_DOCUMENT) {
                goto done;
            }
            if (!bson_cursor_get_document(bc, &bs)) {
                goto done;
            }
            if (serve_status_bson_parse(bs, stat) < 0) {
                goto done;
            }
            retval = 1;
        } else {
            retval = 0;
        }
    } else {
        retval = 0;
    }

done:
    if (bc) bson_cursor_free(bc);
    if (query) bson_free(query);
    if (bs) bson_free(bs);
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_free(results[i]);
        }
        xfree(results);
    }
    return retval;
#else
    return -1;
#endif
}

static int
save_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        const struct prot_serve_status *stat)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct status_mongo_state *sms = (struct status_mongo_state *) sds;
    struct status_mongo_plugin_state *ps = (struct status_mongo_plugin_state *) sms->b.plugin->data;
    int retval = -1;
    bson_t *filter = NULL;
    bson_t *bstat = NULL;
    bson_t *update = NULL;
    bson_t *index = NULL;

    filter = bson_new();
    bson_append_int32(filter, "contest_id", -1, cnts->id);
    bstat = serve_status_bson_unparse(stat);
    update = bson_new();
    bson_append_int32(update, "contest_id", -1, cnts->id);
    bson_append_document(update, "s", -1, bstat);

    retval = ps->common->i->upsert_and_free(ps->common, "status", &filter, &update);

    if (!ps->contest_id_index_created) {
        index = bson_new();
        bson_append_int32(index, "contest_id", -1, 1);
        ps->common->i->index_create(ps->common, "status", index);
        ps->contest_id_index_created = 1;
    }

    if (index) bson_destroy(index);
    if (update) bson_destroy(update);
    if (bstat) bson_destroy(bstat);
    if (filter) bson_destroy(filter);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct status_mongo_state *sms = (struct status_mongo_state *) sds;
    struct status_mongo_plugin_state *ps = (struct status_mongo_plugin_state *) sms->b.plugin->data;
    int retval = -1;
    bson *filter = bson_new();
    bson_append_int32(filter, "contest_id", cnts->id);
    bson_finish(filter);
    bson *bs = serve_status_bson_unparse(stat);
    bson *update = bson_new();
    bson_append_int32(update, "contest_id", cnts->id);
    bson_append_document(update, "s", bs);
    bson_finish(update);
    bson *index = NULL;

    retval = ps->common->i->upsert_and_free(ps->common, "status", &filter, &update);

    if (!ps->contest_id_index_created) {
        index = bson_new();
        bson_append_int32(index, "contest_id", 1);
        bson_finish(index);
        ps->common->i->index_create(ps->common, "status", index);
        ps->contest_id_index_created = 1;
    }

    if (index) bson_free(index);
    if (update) bson_free(update);
    if (filter) bson_free(filter);
    if (bs) bson_free(bs);
    return retval;
#else
    return -1;
#endif
}

static void
remove_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global)
{
    struct status_mongo_state *sms = (struct status_mongo_state *) sds;
    struct status_mongo_plugin_state *ps = (struct status_mongo_plugin_state *) sms->b.plugin->data;

#if HAVE_LIBMONGOC - 0 > 0
    bson_t *filter = NULL;
    filter = bson_new();
    bson_append_int32(filter, "contest_id", -1, cnts->id);
    ps->common->i->remove(ps->common, "status", filter);
    if (filter) bson_destroy(filter);
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson *filter = bson_new();
    bson_append_int32(filter, "contest_id", cnts->id);
    bson_finish(filter);
    ps->common->i->remove(ps->common, "status", filter);
    if (filter) bson_free(filter);
#endif
}

static int
has_status_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    struct status_mongo_plugin_state *ps = (struct status_mongo_plugin_state *) self->data;
#if HAVE_LIBMONGOC - 0 > 0
    int retval = -1;
    bson_t *query = NULL;
    int count;
    bson_t **results = NULL;

    query = bson_new();
    bson_append_int32(query, "contest_id", -1, cnts->id);
    count = ps->common->i->query(ps->common, "status", 0, 1, query, NULL, &results);
    if (count < 0) goto cleanup;
    if (count > 1) {
        err("load_func: multiple entries returned: %d", count);
        goto cleanup;
    }
    if (count == 1 && results[0]) {
        retval = 1;
    } else {
        retval = 0;
    }

cleanup:;
    if (query) bson_destroy(query);
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_destroy(results[i]);
        }
        xfree(results);
    }
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson *query = NULL;
    int count = 0;
    bson **results = NULL;
    int retval = -1;

    query = bson_new();
    bson_append_int32(query, "contest_id", cnts->id);
    bson_finish(query);

    count = ps->common->i->query(ps->common, "status", 0, 1, query, NULL, &results);
    if (count < 0) goto done;
    if (count > 1) {
        err("load_func: multiple entries returned: %d", count);
        goto done;
    }
    if (count == 1) {
        retval = 1;
    } else {
        retval = 0;
    }

done:
    if (query) bson_free(query);
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_free(results[i]);
        }
        xfree(results);
    }
    return retval;
#else
    return -1;
#endif
}

static ej_bson_t *
serve_status_bson_unparse(
        const struct prot_serve_status *status)
{
#if HAVE_LIBMONGOC - 0 > 0
#define UNPARSE_DATE_FIELD(f) do { if (status->f > 0) { bson_append_date_time(res, #f, -1, status->f * 1000LL); } } while (0)
#define UNPARSE_INT32NZ_FIELD(f) do { if (status->f != 0) { bson_append_int32(res, #f, -1, status->f); } } while (0)
#define UNPARSE_BOOLEAN_FIELD(f) do { if (status->f > 0) { bson_append_bool(res, #f, -1, status->f); } } while (0)

    bson_t *res = bson_new();

    UNPARSE_DATE_FIELD(cur_time);
    UNPARSE_DATE_FIELD(start_time);
    UNPARSE_DATE_FIELD(sched_time);
    UNPARSE_DATE_FIELD(stop_time);
    UNPARSE_DATE_FIELD(freeze_time);
    UNPARSE_DATE_FIELD(finish_time);
    UNPARSE_DATE_FIELD(stat_reported_before);
    UNPARSE_DATE_FIELD(stat_report_time);
    UNPARSE_DATE_FIELD(max_online_time);
    UNPARSE_DATE_FIELD(last_daily_reminder);

    UNPARSE_INT32NZ_FIELD(duration);
    UNPARSE_INT32NZ_FIELD(total_runs);
    UNPARSE_INT32NZ_FIELD(total_clars);
    UNPARSE_INT32NZ_FIELD(download_interval);
    UNPARSE_INT32NZ_FIELD(max_online_count);

    UNPARSE_BOOLEAN_FIELD(clars_disabled);
    UNPARSE_BOOLEAN_FIELD(team_clars_disabled);
    UNPARSE_BOOLEAN_FIELD(standings_frozen);
    UNPARSE_BOOLEAN_FIELD(clients_suspended);
    UNPARSE_BOOLEAN_FIELD(testing_suspended);
    UNPARSE_BOOLEAN_FIELD(is_virtual);
    UNPARSE_BOOLEAN_FIELD(continuation_enabled);
    UNPARSE_BOOLEAN_FIELD(printing_enabled);
    UNPARSE_BOOLEAN_FIELD(printing_suspended);
    UNPARSE_BOOLEAN_FIELD(always_show_problems);
    UNPARSE_BOOLEAN_FIELD(accepting_mode);
    UNPARSE_BOOLEAN_FIELD(upsolving_mode);
    UNPARSE_BOOLEAN_FIELD(upsolving_freeze_standings);
    UNPARSE_BOOLEAN_FIELD(upsolving_view_source);
    UNPARSE_BOOLEAN_FIELD(upsolving_view_protocol);
    UNPARSE_BOOLEAN_FIELD(upsolving_full_protocol);
    UNPARSE_BOOLEAN_FIELD(upsolving_disable_clars);
    UNPARSE_BOOLEAN_FIELD(testing_finished);
    UNPARSE_BOOLEAN_FIELD(online_view_judge_score);
    UNPARSE_BOOLEAN_FIELD(online_final_visibility);
    UNPARSE_BOOLEAN_FIELD(online_valuer_judge_comments);
    UNPARSE_BOOLEAN_FIELD(disable_virtual_start);

    bson_append_int32(res, "score_system", -1, status->score_system);

    if (status->online_view_source) {
        bson_append_int32(res, "online_view_source", -1, status->online_view_source);
    }
    if (status->online_view_report) {
        bson_append_int32(res, "online_view_report", -1, status->online_view_report);
    }

    {
        int nz_idx = (int)(sizeof(status->prob_prio) / sizeof(status->prob_prio[0])) - 1;
        for (; nz_idx >= 0 && !status->prob_prio[nz_idx]; --nz_idx) {}
        if (nz_idx >= 0) {
            bson_t *arr = bson_new();
            for (int i = 0; i <= nz_idx; ++i) {
                unsigned char buf[32];
                sprintf(buf, "%d", i);
                bson_append_int32(arr, buf, -1, status->prob_prio[i]);
            }
            bson_append_document(res, "prob_prio", -1, arr);
            bson_destroy(arr);
        }
    }

    return res;
#undef UNPARSE_DATE_FIELD
#undef UNPARSE_INT32NZ_FIELD
#undef UNPARSE_BOOLEAN_FIELD
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
#define UNPARSE_DATE_FIELD(f) do { if (status->f > 0) { bson_append_utc_datetime(res, #f, status->f * 1000LL); } } while (0)
#define UNPARSE_INT32NZ_FIELD(f) do { if (status->f != 0) { bson_append_int32(res, #f, status->f); } } while (0)
#define UNPARSE_BOOLEAN_FIELD(f) do { if (status->f > 0) { bson_append_boolean(res, #f, status->f); } } while (0)

    bson *res = bson_new();

    UNPARSE_DATE_FIELD(cur_time);
    UNPARSE_DATE_FIELD(start_time);
    UNPARSE_DATE_FIELD(sched_time);
    UNPARSE_DATE_FIELD(stop_time);
    UNPARSE_DATE_FIELD(freeze_time);
    UNPARSE_DATE_FIELD(finish_time);
    UNPARSE_DATE_FIELD(stat_reported_before);
    UNPARSE_DATE_FIELD(stat_report_time);
    UNPARSE_DATE_FIELD(max_online_time);
    UNPARSE_DATE_FIELD(last_daily_reminder);

    UNPARSE_INT32NZ_FIELD(duration);
    UNPARSE_INT32NZ_FIELD(total_runs);
    UNPARSE_INT32NZ_FIELD(total_clars);
    UNPARSE_INT32NZ_FIELD(download_interval);
    UNPARSE_INT32NZ_FIELD(max_online_count);

    UNPARSE_BOOLEAN_FIELD(clars_disabled);
    UNPARSE_BOOLEAN_FIELD(team_clars_disabled);
    UNPARSE_BOOLEAN_FIELD(standings_frozen);
    UNPARSE_BOOLEAN_FIELD(clients_suspended);
    UNPARSE_BOOLEAN_FIELD(testing_suspended);
    UNPARSE_BOOLEAN_FIELD(is_virtual);
    UNPARSE_BOOLEAN_FIELD(continuation_enabled);
    UNPARSE_BOOLEAN_FIELD(printing_enabled);
    UNPARSE_BOOLEAN_FIELD(printing_suspended);
    UNPARSE_BOOLEAN_FIELD(always_show_problems);
    UNPARSE_BOOLEAN_FIELD(accepting_mode);
    UNPARSE_BOOLEAN_FIELD(upsolving_mode);
    UNPARSE_BOOLEAN_FIELD(upsolving_freeze_standings);
    UNPARSE_BOOLEAN_FIELD(upsolving_view_source);
    UNPARSE_BOOLEAN_FIELD(upsolving_view_protocol);
    UNPARSE_BOOLEAN_FIELD(upsolving_full_protocol);
    UNPARSE_BOOLEAN_FIELD(upsolving_disable_clars);
    UNPARSE_BOOLEAN_FIELD(testing_finished);
    UNPARSE_BOOLEAN_FIELD(online_view_judge_score);
    UNPARSE_BOOLEAN_FIELD(online_final_visibility);
    UNPARSE_BOOLEAN_FIELD(online_valuer_judge_comments);
    UNPARSE_BOOLEAN_FIELD(disable_virtual_start);

    bson_append_int32(res, "score_system", status->score_system);

    if (status->online_view_source) {
        bson_append_int32(res, "online_view_source", status->online_view_source);
    }
    if (status->online_view_report) {
        bson_append_int32(res, "online_view_report", status->online_view_report);
    }

    {
        int nz_idx = (int)(sizeof(status->prob_prio) / sizeof(status->prob_prio[0])) - 1;
        for (; nz_idx >= 0 && !status->prob_prio[nz_idx]; --nz_idx) {}
        if (nz_idx >= 0) {
            bson *arr = bson_new();
            for (int i = 0; i <= nz_idx; ++i) {
                unsigned char buf[32];
                sprintf(buf, "%d", i);
                bson_append_int32(arr, buf, status->prob_prio[i]);
            }
            bson_finish(arr);
            bson_append_document(res, "prob_prio", arr);
            bson_free(arr);
        }
    }

    bson_finish(res);
    return res;
#undef UNPARSE_DATE_FIELD
#undef UNPARSE_INT32NZ_FIELD
#undef UNPARSE_BOOLEAN_FIELD
#else
    return -1;
#endif
}

static int
serve_status_bson_parse(
        ej_bson_t *b,
        struct prot_serve_status *status)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_iter_t iter, * const bc = &iter;
    bson_t *arr = NULL;

    if (!bson_iter_init(&iter, b)) goto fail;

    while (bson_iter_next(&iter)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "cur_time")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "cur_time", &status->cur_time) < 0) goto fail;
        } else if (!strcmp(key, "start_time")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "start_time", &status->start_time) < 0) goto fail;
        } else if (!strcmp(key, "sched_time")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "sched_time", &status->sched_time) < 0) goto fail;
        } else if (!strcmp(key, "stop_time")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "stop_time", &status->stop_time) < 0) goto fail;
        } else if (!strcmp(key, "freeze_time")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "freeze_time", &status->freeze_time) < 0) goto fail;
        } else if (!strcmp(key, "finish_time")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "finish_time", &status->finish_time) < 0) goto fail;
        } else if (!strcmp(key, "stat_reported_before")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "stat_reported_before", &status->stat_reported_before) < 0) goto fail;
        } else if (!strcmp(key, "stat_report_time")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "stat_report_time", &status->stat_report_time) < 0) goto fail;
        } else if (!strcmp(key, "max_online_time")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "max_online_time", &status->max_online_time) < 0) goto fail;
        } else if (!strcmp(key, "last_daily_reminder")) {
            if (ej_bson_parse_utc_datetime_64_new(bc, "last_daily_reminder", &status->last_daily_reminder) < 0) goto fail;
        } else if (!strcmp(key, "duration")) {
            if (ej_bson_parse_int_new(bc, "duration", &status->duration, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "total_runs")) {
            if (ej_bson_parse_int_new(bc, "total_runs", &status->total_runs, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "total_clars")) {
            if (ej_bson_parse_int_new(bc, "total_clars", &status->total_clars, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "download_interval")) {
            if (ej_bson_parse_int_new(bc, "download_interval", &status->download_interval, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "max_online_count")) {
            if (ej_bson_parse_int_new(bc, "max_online_count", &status->max_online_count, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "clars_disabled")) {
            if (ej_bson_parse_boolean_uc_new(bc, "clars_disabled", &status->clars_disabled) < 0) goto fail;
        } else if (!strcmp(key, "team_clars_disabled")) {
            if (ej_bson_parse_boolean_uc_new(bc, "team_clars_disabled", &status->team_clars_disabled) < 0) goto fail;
        } else if (!strcmp(key, "standings_frozen")) {
            if (ej_bson_parse_boolean_uc_new(bc, "standings_frozen", &status->standings_frozen) < 0) goto fail;
        } else if (!strcmp(key, "clients_suspended")) {
            if (ej_bson_parse_boolean_uc_new(bc, "clients_suspended", &status->clients_suspended) < 0) goto fail;
        } else if (!strcmp(key, "testing_suspended")) {
            if (ej_bson_parse_boolean_uc_new(bc, "testing_suspended", &status->testing_suspended) < 0) goto fail;
        } else if (!strcmp(key, "is_virtual")) {
            if (ej_bson_parse_boolean_uc_new(bc, "is_virtual", &status->is_virtual) < 0) goto fail;
        } else if (!strcmp(key, "continuation_enabled")) {
            if (ej_bson_parse_boolean_uc_new(bc, "continuation_enabled", &status->continuation_enabled) < 0) goto fail;
        } else if (!strcmp(key, "printing_enabled")) {
            if (ej_bson_parse_boolean_uc_new(bc, "printing_enabled", &status->printing_enabled) < 0) goto fail;
        } else if (!strcmp(key, "printing_suspended")) {
            if (ej_bson_parse_boolean_uc_new(bc, "printing_suspended", &status->printing_suspended) < 0) goto fail;
        } else if (!strcmp(key, "always_show_problems")) {
            if (ej_bson_parse_boolean_uc_new(bc, "always_show_problems", &status->always_show_problems) < 0) goto fail;
        } else if (!strcmp(key, "accepting_mode")) {
            if (ej_bson_parse_boolean_uc_new(bc, "accepting_mode", &status->accepting_mode) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_mode")) {
            if (ej_bson_parse_boolean_uc_new(bc, "upsolving_mode", &status->upsolving_mode) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_freeze_standings")) {
            if (ej_bson_parse_boolean_uc_new(bc, "upsolving_freeze_standings", &status->upsolving_freeze_standings) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_view_source")) {
            if (ej_bson_parse_boolean_uc_new(bc, "upsolving_view_source", &status->upsolving_view_source) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_view_protocol")) {
            if (ej_bson_parse_boolean_uc_new(bc, "upsolving_view_protocol", &status->upsolving_view_protocol) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_full_protocol")) {
            if (ej_bson_parse_boolean_uc_new(bc, "upsolving_full_protocol", &status->upsolving_full_protocol) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_disable_clars")) {
            if (ej_bson_parse_boolean_uc_new(bc, "upsolving_disable_clars", &status->upsolving_disable_clars) < 0) goto fail;
        } else if (!strcmp(key, "testing_finished")) {
            if (ej_bson_parse_boolean_uc_new(bc, "testing_finished", &status->testing_finished) < 0) goto fail;
        } else if (!strcmp(key, "online_view_judge_score")) {
            if (ej_bson_parse_boolean_uc_new(bc, "online_view_judge_score", &status->online_view_judge_score) < 0) goto fail;
        } else if (!strcmp(key, "online_final_visibility")) {
            if (ej_bson_parse_boolean_uc_new(bc, "online_final_visibility", &status->online_final_visibility) < 0) goto fail;
        } else if (!strcmp(key, "online_valuer_judge_comments")) {
            if (ej_bson_parse_boolean_uc_new(bc, "online_valuer_judge_comments", &status->online_valuer_judge_comments) < 0) goto fail;
        } else if (!strcmp(key, "disable_virtual_start")) {
            if (ej_bson_parse_boolean_uc_new(bc, "disable_virtual_start", &status->disable_virtual_start) < 0) goto fail;
        } else if (!strcmp(key, "score_system")) {
            int ss;
            if (ej_bson_parse_int_new(bc, "score_system", &ss, 1, 0, 1, 100) < 0) goto fail;
            status->score_system = ss;
        } else if (!strcmp(key, "online_view_source")) {
            int v;
            if (ej_bson_parse_int_new(bc, "online_view_source", &v, 0, 0, 0, 0) < 0) goto fail;
            if (v < 0) v = -1;
            if (v > 0) v = 1;
            status->online_view_source = v;
        } else if (!strcmp(key, "online_view_report")) {
            int v;
            if (ej_bson_parse_int_new(bc, "online_view_report", &v, 0, 0, 0, 0) < 0) goto fail;
            if (v < 0) v = -1;
            if (v > 0) v = 1;
            status->online_view_report = v;
        } else if (!strcmp(key, "prob_prio")) {
            if (ej_bson_parse_array_new(bc, "prob_prio", &arr) < 0) goto fail;
            bson_iter_t itera, * const bca = &itera;

            if (!bson_iter_init(&itera, arr)) goto fail;
            while (bson_iter_next(&itera)) {
                const unsigned char *key = bson_iter_key(bca);
                char *eptr = NULL;
                long val = 0;
                errno = 0;
                if (!key || (val = strtol(key, &eptr, 10)) < 0 || errno || *eptr || (const unsigned char *) eptr == key || (int) val != val) {
                    err("serve_status_bson_parse: invalid index in 'prob_prio': %s", key);
                    goto fail;
                }
                int prio = 0;
                if (ej_bson_parse_int_new(bca, "prob_prio/prio", &prio, 1, -128, 1, 127) < 0) goto fail;
                if (val >= 0 && val < EJ_SERVE_STATUS_TOTAL_PROBS_NEW) {
                    status->prob_prio[val] = prio;
                }
            }
            bson_destroy(arr); arr = NULL;
        } else {
            // do nothing: ignore unknown
        }
    }

    return 0;

fail:;
    if (arr) bson_destroy(arr);
    return -1;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson_cursor *bc = NULL;
    bson_cursor *bca = NULL;
    bson *arr = NULL;

    bc = bson_cursor_new(b);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "cur_time")) {
            if (ej_bson_parse_utc_datetime_64(bc, "cur_time", &status->cur_time) < 0) goto fail;
        } else if (!strcmp(key, "start_time")) {
            if (ej_bson_parse_utc_datetime_64(bc, "start_time", &status->start_time) < 0) goto fail;
        } else if (!strcmp(key, "sched_time")) {
            if (ej_bson_parse_utc_datetime_64(bc, "sched_time", &status->sched_time) < 0) goto fail;
        } else if (!strcmp(key, "stop_time")) {
            if (ej_bson_parse_utc_datetime_64(bc, "stop_time", &status->stop_time) < 0) goto fail;
        } else if (!strcmp(key, "freeze_time")) {
            if (ej_bson_parse_utc_datetime_64(bc, "freeze_time", &status->freeze_time) < 0) goto fail;
        } else if (!strcmp(key, "finish_time")) {
            if (ej_bson_parse_utc_datetime_64(bc, "finish_time", &status->finish_time) < 0) goto fail;
        } else if (!strcmp(key, "stat_reported_before")) {
            if (ej_bson_parse_utc_datetime_64(bc, "stat_reported_before", &status->stat_reported_before) < 0) goto fail;
        } else if (!strcmp(key, "stat_report_time")) {
            if (ej_bson_parse_utc_datetime_64(bc, "stat_report_time", &status->stat_report_time) < 0) goto fail;
        } else if (!strcmp(key, "max_online_time")) {
            if (ej_bson_parse_utc_datetime_64(bc, "max_online_time", &status->max_online_time) < 0) goto fail;
        } else if (!strcmp(key, "last_daily_reminder")) {
            if (ej_bson_parse_utc_datetime_64(bc, "last_daily_reminder", &status->last_daily_reminder) < 0) goto fail;
        } else if (!strcmp(key, "duration")) {
            if (ej_bson_parse_int(bc, "duration", &status->duration, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "total_runs")) {
            if (ej_bson_parse_int(bc, "total_runs", &status->total_runs, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "total_clars")) {
            if (ej_bson_parse_int(bc, "total_clars", &status->total_clars, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "download_interval")) {
            if (ej_bson_parse_int(bc, "download_interval", &status->download_interval, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "max_online_count")) {
            if (ej_bson_parse_int(bc, "max_online_count", &status->max_online_count, 1, 0, 0, 0) < 0) goto fail;
        } else if (!strcmp(key, "clars_disabled")) {
            if (ej_bson_parse_boolean_uc(bc, "clars_disabled", &status->clars_disabled) < 0) goto fail;
        } else if (!strcmp(key, "team_clars_disabled")) {
            if (ej_bson_parse_boolean_uc(bc, "team_clars_disabled", &status->team_clars_disabled) < 0) goto fail;
        } else if (!strcmp(key, "standings_frozen")) {
            if (ej_bson_parse_boolean_uc(bc, "standings_frozen", &status->standings_frozen) < 0) goto fail;
        } else if (!strcmp(key, "clients_suspended")) {
            if (ej_bson_parse_boolean_uc(bc, "clients_suspended", &status->clients_suspended) < 0) goto fail;
        } else if (!strcmp(key, "testing_suspended")) {
            if (ej_bson_parse_boolean_uc(bc, "testing_suspended", &status->testing_suspended) < 0) goto fail;
        } else if (!strcmp(key, "is_virtual")) {
            if (ej_bson_parse_boolean_uc(bc, "is_virtual", &status->is_virtual) < 0) goto fail;
        } else if (!strcmp(key, "continuation_enabled")) {
            if (ej_bson_parse_boolean_uc(bc, "continuation_enabled", &status->continuation_enabled) < 0) goto fail;
        } else if (!strcmp(key, "printing_enabled")) {
            if (ej_bson_parse_boolean_uc(bc, "printing_enabled", &status->printing_enabled) < 0) goto fail;
        } else if (!strcmp(key, "printing_suspended")) {
            if (ej_bson_parse_boolean_uc(bc, "printing_suspended", &status->printing_suspended) < 0) goto fail;
        } else if (!strcmp(key, "always_show_problems")) {
            if (ej_bson_parse_boolean_uc(bc, "always_show_problems", &status->always_show_problems) < 0) goto fail;
        } else if (!strcmp(key, "accepting_mode")) {
            if (ej_bson_parse_boolean_uc(bc, "accepting_mode", &status->accepting_mode) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_mode")) {
            if (ej_bson_parse_boolean_uc(bc, "upsolving_mode", &status->upsolving_mode) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_freeze_standings")) {
            if (ej_bson_parse_boolean_uc(bc, "upsolving_freeze_standings", &status->upsolving_freeze_standings) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_view_source")) {
            if (ej_bson_parse_boolean_uc(bc, "upsolving_view_source", &status->upsolving_view_source) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_view_protocol")) {
            if (ej_bson_parse_boolean_uc(bc, "upsolving_view_protocol", &status->upsolving_view_protocol) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_full_protocol")) {
            if (ej_bson_parse_boolean_uc(bc, "upsolving_full_protocol", &status->upsolving_full_protocol) < 0) goto fail;
        } else if (!strcmp(key, "upsolving_disable_clars")) {
            if (ej_bson_parse_boolean_uc(bc, "upsolving_disable_clars", &status->upsolving_disable_clars) < 0) goto fail;
        } else if (!strcmp(key, "testing_finished")) {
            if (ej_bson_parse_boolean_uc(bc, "testing_finished", &status->testing_finished) < 0) goto fail;
        } else if (!strcmp(key, "online_view_judge_score")) {
            if (ej_bson_parse_boolean_uc(bc, "online_view_judge_score", &status->online_view_judge_score) < 0) goto fail;
        } else if (!strcmp(key, "online_final_visibility")) {
            if (ej_bson_parse_boolean_uc(bc, "online_final_visibility", &status->online_final_visibility) < 0) goto fail;
        } else if (!strcmp(key, "online_valuer_judge_comments")) {
            if (ej_bson_parse_boolean_uc(bc, "online_valuer_judge_comments", &status->online_valuer_judge_comments) < 0) goto fail;
        } else if (!strcmp(key, "disable_virtual_start")) {
            if (ej_bson_parse_boolean_uc(bc, "disable_virtual_start", &status->disable_virtual_start) < 0) goto fail;
        } else if (!strcmp(key, "score_system")) {
            int ss;
            if (ej_bson_parse_int(bc, "score_system", &ss, 1, 0, 1, 100) < 0) goto fail;
            status->score_system = ss;
        } else if (!strcmp(key, "online_view_source")) {
            int v;
            if (ej_bson_parse_int(bc, "online_view_source", &v, 0, 0, 0, 0) < 0) goto fail;
            if (v < 0) v = -1;
            if (v > 0) v = 1;
            status->online_view_source = v;
        } else if (!strcmp(key, "online_view_report")) {
            int v;
            if (ej_bson_parse_int(bc, "online_view_report", &v, 0, 0, 0, 0) < 0) goto fail;
            if (v < 0) v = -1;
            if (v > 0) v = 1;
            status->online_view_report = v;
        } else if (!strcmp(key, "prob_prio")) {
            if (ej_bson_parse_array(bc, "prob_prio", &arr) < 0) goto fail;
            bca = bson_cursor_new(arr);
            while (bson_cursor_next(bca)) {
                const unsigned char *key = bson_cursor_key(bca);
                char *eptr = NULL;
                long val = 0;
                errno = 0;
                if (!key || (val = strtol(key, &eptr, 10)) < 0 || errno || *eptr || (const unsigned char *) eptr == key || (int) val != val) {
                    err("serve_status_bson_parse: invalid index in 'prob_prio': %s", key);
                    goto fail;
                }
                int prio = 0;
                if (ej_bson_parse_int(bca, "prob_prio/prio", &prio, 1, -128, 1, 127) < 0) goto fail;
                if (val >= 0 && val < EJ_SERVE_STATUS_TOTAL_PROBS_NEW) {
                    status->prob_prio[val] = prio;
                }
            }
            bson_cursor_free(bca); bca = NULL;
            bson_free(arr); arr = NULL;
        } else {
            // do nothing: ignore unknown
        }
    }
    bson_cursor_free(bc);
    return 0;

fail:
    if (bc) bson_cursor_free(bc);
    if (bca) bson_cursor_free(bca);
    if (arr) bson_free(arr);
    return -1;
#else
    return -1;
#endif
}
