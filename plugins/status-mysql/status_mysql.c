/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/status_plugin.h"
#include "ejudge/statusdb.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/contests.h"
#include "ejudge/errlog.h"
#include "ejudge/logger.h"
#include "ejudge/xalloc.h"

#include <errno.h>
#include <string.h>
#include <ctype.h>

#define STATUS_DB_VERSION 2

struct status_mysql_state
{
    int nref;

    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;

    int is_db_checked;
};

static struct common_plugin_data *
init_func(void)
{
    struct status_mysql_state *state = NULL;
    XCALLOC(state, 1);
    return (struct common_plugin_data *) state;
}

static int
finish_func(struct common_plugin_data *data)
{
    return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    struct status_mysql_state *state = (struct status_mysql_state *) data;
    const struct common_loaded_plugin *mplg;

    // load common_mysql plugin
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }
    state->mi = (struct common_mysql_iface*) mplg->iface;
    state->md = (struct common_mysql_state*) mplg->data;

    return 0;
}

struct status_internal
{
    int contest_id;
    time_t cur_time;
    time_t start_time;
    time_t sched_time;
    time_t stop_time;
    time_t freeze_time;
    time_t finish_time;
    time_t stat_reported_before;
    time_t stat_report_time;
    time_t max_online_time;
    time_t last_daily_reminder;
    int duration;
    int total_runs;
    int total_clars;
    int download_interval;
    int max_online_count;
    int clars_disabled;
    int team_clars_disabled;
    int standings_frozen;
    int score_system;
    int clients_suspended;
    int testing_suspended;
    int is_virtual;
    int continuation_enabled;
    int printing_enabled;
    int printing_suspended;
    int always_show_problems;
    int accepting_mode;
    int upsolving_mode;
    int upsolving_freeze_standings;
    int upsolving_view_source;
    int upsolving_view_protocol;
    int upsolving_full_protocol;
    int upsolving_disable_clars;
    int testing_finished;
    int online_view_source;
    int online_view_report;
    int online_view_judge_score;
    int online_final_visibility;
    int online_valuer_judge_comments;
    int disable_virtual_start;
    unsigned char *prob_prio_str;
    struct timeval last_update_time;
};

enum { STATUS_ROW_WIDTH = 43 };
#define STATUS_OFFSET(f) XOFFSET(struct status_internal, f)
static __attribute__((unused)) const struct common_mysql_parse_spec status_spec[STATUS_ROW_WIDTH] =
{
    { 0, 'd', "contest_id", STATUS_OFFSET(contest_id), 0 },
    { 1, 't', "cur_time", STATUS_OFFSET(cur_time), 0 },
    { 1, 't', "start_time", STATUS_OFFSET(start_time), 0 },
    { 1, 't', "sched_time", STATUS_OFFSET(sched_time), 0 },
    { 1, 't', "stop_time", STATUS_OFFSET(stop_time), 0 },
    { 1, 't', "freeze_time", STATUS_OFFSET(freeze_time), 0 },
    { 1, 't', "finish_time", STATUS_OFFSET(finish_time), 0 },
    { 1, 't', "stat_reported_before", STATUS_OFFSET(stat_reported_before), 0 },
    { 1, 't', "stat_report_time", STATUS_OFFSET(stat_report_time), 0 },
    { 1, 't', "max_online_time", STATUS_OFFSET(max_online_time), 0 },
    { 1, 't', "last_daily_reminder", STATUS_OFFSET(last_daily_reminder), 0 },
    { 0, 'd', "duration", STATUS_OFFSET(duration), 0 },
    { 0, 'd', "total_runs", STATUS_OFFSET(total_runs), 0 },
    { 0, 'd', "total_clars", STATUS_OFFSET(total_clars), 0 },
    { 0, 'd', "download_interval", STATUS_OFFSET(download_interval), 0 },
    { 0, 'd', "max_online_count", STATUS_OFFSET(max_online_count), 0 },
    { 0, 'd', "clars_disabled", STATUS_OFFSET(clars_disabled), 0 },
    { 0, 'd', "team_clars_disabled", STATUS_OFFSET(team_clars_disabled), 0 },
    { 0, 'd', "standings_frozen", STATUS_OFFSET(standings_frozen), 0 },
    { 0, 'd', "score_system", STATUS_OFFSET(score_system), 0 },
    { 0, 'd', "clients_suspended", STATUS_OFFSET(clients_suspended), 0 },
    { 0, 'd', "testing_suspended", STATUS_OFFSET(testing_suspended), 0 },
    { 0, 'd', "is_virtual", STATUS_OFFSET(is_virtual), 0 },
    { 0, 'd', "continuation_enabled", STATUS_OFFSET(continuation_enabled), 0 },
    { 0, 'd', "printing_enabled", STATUS_OFFSET(printing_enabled), 0 },
    { 0, 'd', "printing_suspended", STATUS_OFFSET(printing_suspended), 0 },
    { 0, 'd', "always_show_problems", STATUS_OFFSET(always_show_problems), 0 },
    { 0, 'd', "accepting_mode", STATUS_OFFSET(accepting_mode), 0 },
    { 0, 'd', "upsolving_mode", STATUS_OFFSET(upsolving_mode), 0 },
    { 0, 'd', "upsolving_freeze_standings", STATUS_OFFSET(upsolving_freeze_standings), 0 },
    { 0, 'd', "upsolving_view_source", STATUS_OFFSET(upsolving_view_source), 0 },
    { 0, 'd', "upsolving_view_protocol", STATUS_OFFSET(upsolving_view_protocol), 0 },
    { 0, 'd', "upsolving_full_protocol", STATUS_OFFSET(upsolving_full_protocol), 0 },
    { 0, 'd', "upsolving_disable_clars", STATUS_OFFSET(upsolving_disable_clars), 0 },
    { 0, 'd', "testing_finished", STATUS_OFFSET(testing_finished), 0 },
    { 0, 'd', "online_view_source", STATUS_OFFSET(online_view_source), 0 },
    { 0, 'd', "online_view_report", STATUS_OFFSET(online_view_report), 0 },
    { 0, 'd', "online_view_judge_score", STATUS_OFFSET(online_view_judge_score), 0 },
    { 0, 'd', "online_final_visibility", STATUS_OFFSET(online_final_visibility), 0 },
    { 0, 'd', "online_valuer_judge_comments", STATUS_OFFSET(online_valuer_judge_comments), 0 },
    { 0, 'd', "disable_virtual_start", STATUS_OFFSET(disable_virtual_start), 0 },
    { 1, 's', "prob_prio_str", STATUS_OFFSET(prob_prio_str), 0 },
    { 1, 'T', "last_update_time", STATUS_OFFSET(last_update_time), 0 },
};

struct statusdb_state_mysql
{
    struct statusdb_state b;
    int contest_id;
};

static const char create_query[] =
"CREATE TABLE %sstatuses("
"    contest_id INT NOT NULL PRIMARY KEY,"
"    cur_time DATETIME DEFAULT NULL,"
"    start_time DATETIME DEFAULT NULL,"
"    sched_time DATETIME DEFAULT NULL,"
"    stop_time DATETIME DEFAULT NULL,"
"    freeze_time DATETIME DEFAULT NULL,"
"    finish_time DATETIME DEFAULT NULL,"
"    stat_reported_before DATETIME DEFAULT NULL,"
"    stat_report_time DATETIME DEFAULT NULL,"
"    max_online_time DATETIME DEFAULT NULL,"
"    last_daily_reminder DATETIME DEFAULT NULL,"
"    duration INT NOT NULL DEFAULT 0,"
"    total_runs INT NOT NULL DEFAULT 0,"
"    total_clars INT NOT NULL DEFAULT 0,"
"    download_interval INT NOT NULL DEFAULT 0,"
"    max_online_count INT NOT NULL DEFAULT 0,"
"    clars_disabled TINYINT NOT NULL DEFAULT 0,"
"    team_clars_disabled TINYINT NOT NULL DEFAULT 0,"
"    standings_frozen TINYINT NOT NULL DEFAULT 0,"
"    score_system TINYINT NOT NULL DEFAULT 0,"
"    clients_suspended TINYINT NOT NULL DEFAULT 0,"
"    testing_suspended TINYINT NOT NULL DEFAULT 0,"
"    is_virtual TINYINT NOT NULL DEFAULT 0,"
"    continuation_enabled TINYINT NOT NULL DEFAULT 0,"
"    printing_enabled TINYINT NOT NULL DEFAULT 0,"
"    printing_suspended TINYINT NOT NULL DEFAULT 0,"
"    always_show_problems TINYINT NOT NULL DEFAULT 0,"
"    accepting_mode TINYINT NOT NULL DEFAULT 0,"
"    upsolving_mode TINYINT NOT NULL DEFAULT 0,"
"    upsolving_freeze_standings TINYINT NOT NULL DEFAULT 0,"
"    upsolving_view_source TINYINT NOT NULL DEFAULT 0,"
"    upsolving_view_protocol TINYINT NOT NULL DEFAULT 0,"
"    upsolving_full_protocol TINYINT NOT NULL DEFAULT 0,"
"    upsolving_disable_clars TINYINT NOT NULL DEFAULT 0,"
"    testing_finished TINYINT NOT NULL DEFAULT 0,"
"    online_view_source TINYINT NOT NULL DEFAULT 0,"
"    online_view_report TINYINT NOT NULL DEFAULT 0,"
"    online_view_judge_score TINYINT NOT NULL DEFAULT 0,"
"    online_final_visibility TINYINT NOT NULL DEFAULT 0,"
"    online_valuer_judge_comments TINYINT NOT NULL DEFAULT 0,"
"    disable_virtual_start TINYINT NOT NULL DEFAULT 0,"
"    prob_prio_str VARCHAR(512) DEFAULT NULL,"
"    last_update_time DATETIME(6) NOT NULL"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;";

static int
create_database(
        struct status_mysql_state *state)
{
    struct common_mysql_iface *mi = state->mi;
    struct common_mysql_state *md = state->md;

    if (mi->simple_fquery(md, create_query, md->table_prefix) < 0)
        db_error_fail(md);

    if (mi->simple_fquery(md, "INSERT INTO %sconfig VALUES ('status_version', '%d') ;", md->table_prefix, STATUS_DB_VERSION) < 0)
        db_error_fail(md);

    state->is_db_checked = 1;
    return 0;

fail:
    return -1;
}

static int
check_database(
        struct status_mysql_state *state)
{
    int status_version = 0;
    struct common_mysql_iface *mi = state->mi;
    struct common_mysql_state *md = state->md;

    if (mi->connect(md) < 0)
        return -1;

    if (mi->fquery(md, 1, "SELECT config_val FROM %sconfig WHERE config_key = 'status_version' ;", md->table_prefix) < 0) {
        err("probably the database is not created, please, create it");
        return -1;
    }
    if (md->row_count > 1) {
        err("status_version key is not unique");
        return -1;
    }
    if (!md->row_count) return create_database(state);
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (!md->row[0] || mi->parse_int(md, md->row[0], &status_version) < 0)
        db_error_inv_value_fail(md, "config_val");
    mi->free_res(md);

    if (status_version < 1 || status_version > STATUS_DB_VERSION) {
        err("status_version == %d is not supported", status_version);
        goto fail;
    }

    while (status_version >= 0) {
        switch (status_version) {
        case 1:
            if (mi->simple_fquery(md, "ALTER TABLE %sstatuses ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
                goto fail;
            if (mi->simple_fquery(md, "ALTER TABLE %sstatuses MODIFY COLUMN prob_prio_str VARCHAR(512) DEFAULT NULL ;", md->table_prefix) < 0)
                goto fail;
            break;
        case STATUS_DB_VERSION:
            status_version = -1;
            break;
        default:
            status_version = -1;
            break;
        }
        if (status_version >= 0) {
            ++status_version;
            if (mi->simple_fquery(state->md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'status_version' ;", state->md->table_prefix, status_version) < 0)
                return -1;
        }
    }

    state->is_db_checked = 1;
    return 0;

fail:
    return -1;
}

static struct statusdb_state *
open_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    __attribute__((unused)) struct status_plugin_iface *iface = (struct status_plugin_iface *) self->iface;
    struct status_mysql_state *data = (struct status_mysql_state *) self->data;

    if (!data->is_db_checked) {
        if (check_database(data) < 0) {
            return NULL;
        }
    }

    struct statusdb_state_mysql *cnts_state = NULL;
    XCALLOC(cnts_state, 1);
    cnts_state->b.plugin = self;
    ++data->nref;
    cnts_state->contest_id = cnts->id;

    return &cnts_state->b;
}

static void
close_func(struct statusdb_state *sds)
{
    if (sds) {
        struct statusdb_state_mysql *cnts_state = (struct statusdb_state_mysql *) sds;
        struct status_mysql_state *data = (struct status_mysql_state *) cnts_state->b.plugin->data;
        if (data->nref > 0) --data->nref;
        xfree(sds);
    }
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
    if (!sds) return -1;

    struct statusdb_state_mysql *sdsm = (struct statusdb_state_mysql *) sds;
    struct status_mysql_state *data = (struct status_mysql_state *) sdsm->b.plugin->data;
    struct common_mysql_iface *mi = data->mi;
    struct common_mysql_state *md = data->md;
    struct status_internal stint = {};

    if (mi->fquery(md, STATUS_ROW_WIDTH,
                   "SELECT * FROM %sstatuses WHERE contest_id=%d;",
                   md->table_prefix, sdsm->contest_id) < 0)
        db_error_fail(md);
    if (!md->row_count) {
        memset(stat, 0, sizeof(*stat));
        return 0;
    }
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (mi->parse_spec(md, -1, md->row, md->lengths, STATUS_ROW_WIDTH, status_spec, &stint) < 0) goto fail;

    memset(stat, 0, sizeof(*stat));
    stat->cur_time = stint.cur_time;
    stat->start_time = stint.start_time;
    stat->sched_time = stint.sched_time;
    stat->stop_time = stint.stop_time;
    stat->freeze_time = stint.freeze_time;
    stat->finish_time = stint.finish_time;
    stat->stat_reported_before = stint.stat_reported_before;
    stat->stat_report_time = stint.stat_report_time;
    stat->max_online_time = stint.max_online_time;
    stat->last_daily_reminder = stint.last_daily_reminder;
    stat->duration = stint.duration;
    stat->total_runs = stint.total_runs;
    stat->total_clars = stint.total_clars;
    stat->download_interval = stint.download_interval;
    stat->max_online_count = stint.max_online_count;
    stat->clars_disabled = !!stint.clars_disabled;
    stat->team_clars_disabled = !!stint.team_clars_disabled;
    stat->standings_frozen = !!stint.standings_frozen;
    stat->score_system = stint.score_system;
    stat->clients_suspended = !!stint.clients_suspended;
    stat->testing_suspended = !!stint.testing_suspended;
    stat->is_virtual = !!stint.is_virtual;
    stat->continuation_enabled = !!stint.continuation_enabled;
    stat->printing_enabled = !!stint.printing_enabled;
    stat->printing_suspended = !!stint.printing_suspended;
    stat->always_show_problems = !!stint.always_show_problems;
    stat->accepting_mode = !!stint.accepting_mode;
    stat->upsolving_mode = !!stint.upsolving_mode;
    stat->upsolving_freeze_standings = !!stint.upsolving_freeze_standings;
    stat->upsolving_view_source = !!stint.upsolving_view_source;
    stat->upsolving_view_protocol = !!stint.upsolving_view_protocol;
    stat->upsolving_full_protocol = !!stint.upsolving_full_protocol;
    stat->upsolving_disable_clars = !!stint.upsolving_disable_clars;
    stat->testing_finished = !!stint.testing_finished;
    stat->online_view_source = stint.online_view_source;
    stat->online_view_report = stint.online_view_report;
    stat->online_view_judge_score = !!stint.online_view_judge_score;
    stat->online_final_visibility = !!stint.online_final_visibility;
    stat->online_valuer_judge_comments = !!stint.online_valuer_judge_comments;
    stat->disable_virtual_start = !!stint.disable_virtual_start;

    if (stint.prob_prio_str && stint.prob_prio_str[0]) {
        char *s = (char *) stint.prob_prio_str;
        int i = 0;
        while (i < EJ_SERVE_STATUS_TOTAL_PROBS_NEW && *s) {
            char *eptr = NULL;
            errno = 0;
            long v = strtol(s, &eptr, 10);
            if (errno || v < -128 || v > 127) {
                // FIXME: report error?
                break;
            }
            if (eptr && !isspace((unsigned char) *eptr)) {
                // FIXME: report error?
                break;
            }
            if (eptr == s) {
                // trailing whitespace
                break;
            }
            stat->prob_prio[i++] = (signed char) v;
            s = eptr;
        }
    }
    free(stint.prob_prio_str);
    return 1;

fail:
    free(stint.prob_prio_str);
    return -1;
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
    struct statusdb_state_mysql *sdsm = (struct statusdb_state_mysql *) sds;
    struct status_mysql_state *data = (struct status_mysql_state *) sdsm->b.plugin->data;
    struct common_mysql_iface *mi = data->mi;
    struct common_mysql_state *md = data->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;

    struct status_internal stint = {};
    stint.contest_id = sdsm->contest_id;
    stint.cur_time = stat->cur_time;
    stint.start_time = stat->start_time;
    stint.sched_time = stat->sched_time;
    stint.stop_time = stat->stop_time;
    stint.freeze_time = stat->freeze_time;
    stint.finish_time = stat->finish_time;
    stint.stat_reported_before = stat->stat_reported_before;
    stint.stat_report_time = stat->stat_report_time;
    stint.max_online_time = stat->max_online_time;
    stint.last_daily_reminder = stat->last_daily_reminder;
    stint.duration = stat->duration;
    stint.total_runs = stat->total_runs;
    stint.total_clars = stat->total_clars;
    stint.download_interval = stat->download_interval;
    stint.max_online_count = stat->max_online_count;
    stint.clars_disabled = !!stat->clars_disabled;
    stint.team_clars_disabled = !!stat->team_clars_disabled;
    stint.standings_frozen = !!stat->standings_frozen;
    stint.score_system = stat->score_system;
    stint.clients_suspended = !!stat->clients_suspended;
    stint.testing_suspended = !!stat->testing_suspended;
    stint.is_virtual = !!stat->is_virtual;
    stint.continuation_enabled = !!stat->continuation_enabled;
    stint.printing_enabled = !!stat->printing_enabled;
    stint.printing_suspended = !!stat->printing_suspended;
    stint.always_show_problems = !!stat->always_show_problems;
    stint.accepting_mode = !!stat->accepting_mode;
    stint.upsolving_mode = !!stat->upsolving_mode;
    stint.upsolving_freeze_standings = !!stat->upsolving_freeze_standings;
    stint.upsolving_view_source = !!stat->upsolving_view_source;
    stint.upsolving_view_protocol = !!stat->upsolving_view_protocol;
    stint.upsolving_full_protocol = !!stat->upsolving_full_protocol;
    stint.upsolving_disable_clars = !!stat->upsolving_disable_clars;
    stint.testing_finished = !!stat->testing_finished;
    stint.online_view_source = stat->online_view_source;
    stint.online_view_report = stat->online_view_report;
    stint.online_view_judge_score = stat->online_view_judge_score;
    stint.online_final_visibility = stat->online_final_visibility;
    stint.online_valuer_judge_comments = stat->online_valuer_judge_comments;
    stint.disable_virtual_start = stat->disable_virtual_start;
    int prio_count = 0;
    for (; prio_count < EJ_SERVE_STATUS_TOTAL_PROBS_NEW; ++prio_count) {
        if (stat->prob_prio[prio_count] != 0) {
            break;
        }
    }
    if (prio_count < EJ_SERVE_STATUS_TOTAL_PROBS_NEW) {
        char *out_s = NULL;
        size_t out_z = 0;
        FILE *out_f = open_memstream(&out_s, &out_z);
        for (int i = 0; i <= prio_count; ++i) {
            if (i > 0) putc_unlocked(' ', out_f);
            fprintf(out_f, "%d", stat->prob_prio[i]);
        }
        fclose(out_f);
        stint.prob_prio_str = out_s;
    }

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %sstatuses VALUES ( ", md->table_prefix);
    // skip the last field 'last_update_time'
    mi->unparse_spec_2(md, cmd_f, STATUS_ROW_WIDTH, status_spec,
                       (1ULL << (STATUS_ROW_WIDTH - 1)), &stint);
    fprintf(cmd_f, ", last_update_time = NOW(6)) ON DUPLICATE KEY UPDATE ");
    // skip the first field 'contest_id' and the last field 'last_update_time'
    mi->unparse_spec_3(md, cmd_f, STATUS_ROW_WIDTH, status_spec,
                       (1ULL << (STATUS_ROW_WIDTH - 1)) | 1,
                       &stint);
    fprintf(cmd_f, ", last_update_time = NOW(6);");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;

    free(cmd_s);
    free(stint.prob_prio_str);
    return 1;

fail:
    free(stint.prob_prio_str);
    free(cmd_s);
    return -1;
}

static void
remove_func(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global)
{
    struct statusdb_state_mysql *sdsm = (struct statusdb_state_mysql *) sds;
    struct status_mysql_state *data = (struct status_mysql_state *) sdsm->b.plugin->data;
    struct common_mysql_iface *mi = data->mi;
    struct common_mysql_state *md = data->md;

    // errors ignored
    mi->simple_fquery(md, "DELETE FROM %sstatuses WHERE contest_id = %d ;", md->table_prefix, sdsm->contest_id);
}

static int
has_status_func(
        const struct common_loaded_plugin *self,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    struct status_mysql_state *data = (struct status_mysql_state *) self->data;
    struct common_mysql_iface *mi = data->mi;
    struct common_mysql_state *md = data->md;

    if (mi->fquery(md, 1, "SELECT contest_id FROM %sstatuses WHERE contest_id = %d ;", md->table_prefix, cnts->id) < 0) {
        return -1;
    }
    return md->row_count == 1;
}

struct status_plugin_iface plugin_status_mysql =
{
    {
        {
            sizeof (struct status_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "status",
            "mysql",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    STATUS_PLUGIN_IFACE_VERSION,
    open_func,
    close_func,
    load_func,
    save_func,
    remove_func,
    has_status_func,
};
