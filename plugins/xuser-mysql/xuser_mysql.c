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
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

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
};

static __attribute__((unused)) const char create_query_1[] =
"CREATE TABLE %suserwarnings (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    contest_id INT NOT NULL,\n"
"    user_id INT UNSIGNED NOT NULL,\n"
"    issue_date DATETIME NOT NULL,\n"
"    issuer_id INT UNSIGNED NOT NULL,\n"
"    issuer_ip VARCHAR(128) DEFAULT NULL,\n"
"    user_text MEDIUMTEXT DEFAULT NULL,\n"
"    judge_text MEDIUMTEXT DEFAULT NULL,\n"
"    KEY (contest_id, user_id),\n"
"    FOREIGN KEY uw_user_id_1_fk(user_id) REFERENCES %slogins(user_id),\n"
"    FOREIGN KEY uw_user_id_2_fk(issuer_id) REFERENCES %slogins(user_id),\n"
"    KEY uw_contest_id_idx(contest_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;\n";

static __attribute__((unused)) const char create_query_2[] =
"CREATE TABLE %sviewedclars (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    contest_id INT NOT NULL,\n"
"    user_id INT UNSIGNED NOT NULL,\n"
"    clar_uuid CHAR(40) CHARSET utf8 COLLATE utf8_bin NOT NULL,\n"
"    KEY (contest_id, user_id),\n"
"    FOREIGN KEY vc_user_id_fk(user_id) REFERENCES %slogins(user_id),\n"
"    KEY uw_contest_id_idx(contest_id),\n"
"    KEY vc_clar_uuid_k(clar_uuid),\n"
"    UNIQUE KEY vc_clar_user_uuid_uk(user_id, clar_uuid)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;\n";
    
static __attribute__((unused)) const char create_query_3[] =
"ALTER TABLE %sviewedclars ADD FOREIGN KEY vc_clar_uuid_fk(clar_uuid) REFERENCES %sclars(uuid);\n";

static __attribute__((unused)) const char create_query_4[] =
"CREATE TABLE %suserextras (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    contest_id INT NOT NULL,\n"
"    user_id INT UNSIGNED NOT NULL,\n"
"    disq_comment TEXT(4096) DEFAULT NULL,\n"
"    status INT NOT NULL DEFAULT 0,\n"
"    run_fields BIGINT DEFAULT 0,\n"
"    problem_dir_prefix VARCHAR(1024) DEFAULT NULL,\n"
"    UNIQUE KEY (contest_id, user_id),\n"
"    FOREIGN KEY ux_user_id_fk(user_id) REFERENCES %slogins(user_id),\n"
"    KEY ux_contest_id_idx(contest_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;\n";

static struct xuser_cnts_state *
open_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    __attribute__((unused)) struct xuser_mysql_state *xms = (struct xuser_mysql_state *) data;

    /// TODO

    return NULL;
}

static struct xuser_cnts_state *
close_func(
        struct xuser_cnts_state *data)
{
    __attribute__((unused)) struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    if (xmcs) {
        /// TODO
    }
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
