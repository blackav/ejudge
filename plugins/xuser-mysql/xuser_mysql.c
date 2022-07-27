/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/common_plugin.h"
#include "ejudge/xuser_plugin.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/contests.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

#include <stdint.h>

struct xuser_mysql_state
{
    struct common_plugin_data b;

    int nref;

    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;

    int is_db_checked;
};

static struct common_plugin_data *
init_func(void)
{
    struct xuser_mysql_state *state = NULL;
    XCALLOC(state, 1);
    return &state->b;
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
    struct xuser_mysql_state *xms = (struct xuser_mysql_state *) data;
    const struct common_loaded_plugin *mplg;

    // load common_mysql plugin
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }
    xms->mi = (struct common_mysql_iface*) mplg->iface;
    xms->md = (struct common_mysql_state*) mplg->data;

    return 0;
}

struct xuser_mysql_cnts_state
{
    struct xuser_cnts_state b;
    struct xuser_mysql_state *xms;
    int contest_id;
};

static const char create_query_1[] =
"CREATE TABLE %suserwarnings (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    user_extra_id INT NOT NULL\n"
"    issue_date DATETIME NOT NULL,\n"
"    issuer_id INT UNSIGNED NOT NULL,\n"
"    issuer_ip VARCHAR(128) DEFAULT NULL,\n"
"    user_text MEDIUMTEXT DEFAULT NULL,\n"
"    judge_text MEDIUMTEXT DEFAULT NULL,\n"
"    last_update_time DATETIME(6) DEFAULT NULL,\n"
"    KEY (contest_id, user_id),\n"
"    FOREIGN KEY uw_user_id_1_fk(user_id) REFERENCES %slogins(user_id),\n"
"    FOREIGN KEY uw_user_id_2_fk(issuer_id) REFERENCES %slogins(user_id),\n"
"    KEY uw_contest_id_idx(contest_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;\n";

static const char create_query_2[] =
"CREATE TABLE %sviewedclars (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    user_extra_id INT NOT NULL\n"
"    clar_uuid CHAR(40) CHARSET utf8 COLLATE utf8_bin NOT NULL,\n"
"    last_update_time DATETIME(6) DEFAULT NULL,\n"
"    KEY (contest_id, user_id),\n"
"    FOREIGN KEY vc_user_id_fk(user_id) REFERENCES %slogins(user_id),\n"
"    KEY uw_contest_id_idx(contest_id),\n"
"    KEY vc_clar_uuid_k(clar_uuid),\n"
"    UNIQUE KEY vc_clar_user_uuid_uk(user_id, clar_uuid)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;\n";
    
static const char create_query_3[] =
"ALTER TABLE %sviewedclars ADD FOREIGN KEY vc_clar_uuid_fk(clar_uuid) REFERENCES %sclars(uuid);\n";

static const char create_query_4[] =
"CREATE TABLE %suserextras (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    contest_id INT NOT NULL,\n"
"    user_id INT UNSIGNED NOT NULL,\n"
"    disq_comment TEXT(4096) DEFAULT NULL,\n"
"    status INT NOT NULL DEFAULT 0,\n"
"    run_fields BIGINT DEFAULT 0,\n"
"    problem_dir_prefix VARCHAR(1024) DEFAULT NULL,\n"
"    last_update_time DATETIME(6) DEFAULT NULL,\n"
"    UNIQUE KEY (contest_id, user_id),\n"
"    FOREIGN KEY ux_user_id_fk(user_id) REFERENCES %slogins(user_id),\n"
"    KEY ux_contest_id_idx(contest_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;\n";

static const char create_query_5[] =
"ALTER TABLE %sviewedclars ADD FOREIGN KEY vc_user_extra_id_fk(user_extra_id) REFERENCES %suserextras(serial_id);\n";

static const char create_query_6[] =
"ALTER TABLE %suserwarnings ADD FOREIGN KEY uw_user_extra_id_fk(user_extra_id) REFERENCES %suserextras(serial_id);\n";

static int
create_database(
        struct xuser_mysql_state *xms)
{
    struct common_mysql_iface *mi = xms->mi;
    struct common_mysql_state *md = xms->md;

    if (mi->simple_fquery(md, create_query_1,
                          md->table_prefix, md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_2,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_3,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_4,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_5,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_6,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);

    if (mi->simple_fquery(md, "INSERT INTO %sconfig VALUES ('xuser_version', '%d') ;", md->table_prefix, 1) < 0)
        db_error_fail(md);

    return 0;

fail:
    return -1;
}

static int
check_database(
        struct xuser_mysql_state *xms)
{
    int xuser_version = 0;
    struct common_mysql_iface *mi = xms->mi;
    struct common_mysql_state *md = xms->md;

    if (mi->connect(md) < 0)
        return -1;

    if (mi->fquery(md, 1, "SELECT config_val FROM %sconfig WHERE config_key = 'xuser_version' ;", md->table_prefix) < 0) {
        err("probably the database is not created, please, create it");
        return -1;
    }
    if (md->row_count > 1) {
        err("xuser_version key is not unique");
        return -1;
    }
    if (!md->row_count) return create_database(xms);
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (!md->row[0] || mi->parse_int(md, md->row[0], &xuser_version) < 0)
        db_error_inv_value_fail(md, "config_val");
    mi->free_res(md);

    if (xuser_version < 1) {
        err("xuser_version == %d is not supported", xuser_version);
        goto fail;
    }

    while (xuser_version >= 0) {
        switch (xuser_version) {
        default:
            xuser_version = -1;
            break;
        }
        if (xuser_version >= 0) {
            ++xuser_version;
            if (mi->simple_fquery(md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'xuser_version' ;", md->table_prefix, xuser_version) < 0)
                return -1;
        }
    }

    return 0;

fail:
    return -1;
}

extern struct xuser_plugin_iface plugin_xuser_mysql;

static struct xuser_cnts_state *
open_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    struct xuser_mysql_state *xms = (struct xuser_mysql_state *) data;

    if (!xms->is_db_checked) {
        if (check_database(xms) < 0) {
            return NULL;
        }
        xms->is_db_checked = 1;
    }

    struct xuser_mysql_cnts_state *xmcs = NULL;
    XCALLOC(xmcs, 1);
    xmcs->b.vt = &plugin_xuser_mysql;
    xmcs->xms = xms;
    xmcs->contest_id = cnts->id;
    ++xms->nref;
    
    return &xmcs->b;
}

static struct xuser_cnts_state *
close_func(
        struct xuser_cnts_state *data)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    if (xmcs) {
        if (xmcs->xms && xmcs->xms->nref > 0) {
            --xmcs->xms->nref;
        }
        xfree(xmcs);
    }
    return NULL;
}

struct user_warning_internal
{
    int serial_id;
    int user_extra_id;
    ej_time64_t issue_date;
    int isser_id;
    char *isser_ip;
    char *user_text;
    char *judge_text;
    struct timeval last_update_time;
};

struct viewed_clar_internal
{
    int serial_id;
    int user_extra_id;
    ej_uuid_t clar_uuid;
    struct timeval last_update_time;
};

enum { VIEWED_CLAR_ROW_WIDTH = 4 };
#define VIEWED_CLAR_OFFSET(f) XOFFSET(struct viewed_clar_internal, f)
static __attribute__((unused)) const struct common_mysql_parse_spec viewed_clar_spec[VIEWED_CLAR_ROW_WIDTH] =
{
    { 0, 'd', "serial_id", VIEWED_CLAR_OFFSET(serial_id), 0 },
    { 0, 'd', "user_extra_id", VIEWED_CLAR_OFFSET(user_extra_id), 0 },
    //{ 0, 'd', "user_id", USER_EXTRA_OFFSET(user_id), 0 },
    { 1, 'T', "last_update_time", VIEWED_CLAR_OFFSET(last_update_time), 0 },    
};

struct user_extra_internal
{
    int serial_id;
    int contest_id;
    int user_id;
    char *disq_comment;
    int status;
    uint64_t run_fields;
    char *problem_dir_prefix;
    struct timeval last_update_time;
};

enum { USER_EXTRA_ROW_WIDTH = 8 };
#define USER_EXTRA_OFFSET(f) XOFFSET(struct user_extra_internal, f)
static __attribute__((unused)) const struct common_mysql_parse_spec user_extra_spec[USER_EXTRA_ROW_WIDTH] =
{
    { 0, 'd', "serial_id", USER_EXTRA_OFFSET(serial_id), 0 },
    { 0, 'd', "contest_id", USER_EXTRA_OFFSET(contest_id), 0 },
    { 0, 'd', "user_id", USER_EXTRA_OFFSET(user_id), 0 },
    { 1, 's', "disq_comment", USER_EXTRA_OFFSET(disq_comment), 0 },
    { 0, 'd', "status", USER_EXTRA_OFFSET(status), 0 },
    { 0, 'q', "run_fields", USER_EXTRA_OFFSET(run_fields), 0 },
    { 1, 's', "problem_dir_prefix", USER_EXTRA_OFFSET(problem_dir_prefix), 0 },
    { 1, 'T', "last_update_time", USER_EXTRA_OFFSET(last_update_time), 0 },    
};

/*
enum { STATUS_ROW_WIDTH = 43 };
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
*/

static __attribute__((unused)) struct team_extra *
do_get_entry(
        struct xuser_mysql_cnts_state *xmcs,
        int user_id)
{
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;

    return NULL;
}

static const struct team_extra *
get_entry_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return NULL;
}

static int
get_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return 0;
}

static int
set_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return 0;
}

static void
flush_func(
        struct xuser_cnts_state *data)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
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
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return 0;
}

static int
set_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int status)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return 0;
}

static int
set_disq_comment_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *disq_comment)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return 0;
}

static int
get_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return 0;
}

static int
set_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id,
        int run_fields)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return 0;
}

static int
count_read_clars_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return 0;
}

static struct xuser_team_extras *
get_entries_func(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return NULL;
}

static int
set_problem_dir_prefix_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *problem_dir_prefix)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    /// TODO
    return 0;
}

struct xuser_plugin_iface plugin_xuser_mysql =
{
    {
        {
            sizeof (struct xuser_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "xuser",
            "mysql",
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
};
