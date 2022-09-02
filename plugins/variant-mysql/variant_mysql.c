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
#include "ejudge/variant_plugin.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/prepare.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

struct variant_mysql_data
{
    struct variant_plugin_data b;

    int nref;

    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;

    int is_db_checked;
};

static struct common_plugin_data *
init_func(void)
{
    struct variant_mysql_data *state = NULL;
    XCALLOC(state, 1);
    return &state->b.b;
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
    struct variant_mysql_data *vmd = (struct variant_mysql_data *) data;
    const struct common_loaded_plugin *mplg;

    // load common_mysql plugin
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }
    vmd->mi = (struct common_mysql_iface*) mplg->iface;
    vmd->md = (struct common_mysql_state*) mplg->data;

    return 0;
}

struct variant_cnts_mysql_data
{
    struct variant_cnts_plugin_data b;
    struct variant_mysql_data *vmd;
    int contest_id;
};

static const char create_query[] =
"CREATE TABLE %svariants (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    contest_id INT NOT NULL,\n"
"    user_id INT UNSIGNED NOT NULL,\n"
"    prob_id INT NOT NULL,\n"
"    variant INT,\n"
"    last_update_time DATETIME(6) DEFAULT NULL,\n"
"    FOREIGN KEY v_user_id_fk(user_id) REFERENCES %slogins(user_id),\n"
"    KEY v_contest_id_idx(contest_id),\n"
"    KEY v_cu_id_idx(contest_id,user_id),\n"
"    UNIQUE KEY v_cup_id_idx(contest_id,user_id,prob_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;\n";

static int
create_database(
        struct variant_mysql_data *vmd)
{
    struct common_mysql_iface *mi = vmd->mi;
    struct common_mysql_state *md = vmd->md;

    if (mi->simple_fquery(md, create_query,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);

    if (mi->simple_fquery(md, "INSERT INTO %sconfig VALUES ('variant_version', '%d') ;", md->table_prefix, 1) < 0)
        db_error_fail(md);

    return 0;

fail:
    return -1;
}

static int
check_database(
        struct variant_mysql_data *vms)
{
    int variant_version = 0;
    struct common_mysql_iface *mi = vms->mi;
    struct common_mysql_state *md = vms->md;

    if (mi->connect(md) < 0)
        goto fail;

    if (mi->fquery(md, 1, "SELECT config_val FROM %sconfig WHERE config_key = 'variant_version' ;", md->table_prefix) < 0) {
        err("probably the database is not created, please, create it");
        goto fail;
    }
    if (md->row_count > 1) {
        err("variant_version key is not unique");
        goto fail;
    }
    if (!md->row_count) return create_database(vms);
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (!md->row[0] || mi->parse_int(md, md->row[0], &variant_version) < 0)
        db_error_inv_value_fail(md, "config_val");
    mi->free_res(md);
    if (variant_version < 1) {
        err("variant_version == %d is not supported", variant_version);
        goto fail;
    }

    while (variant_version >= 0) {
        switch (variant_version) {
        default:
            variant_version = -1;
            break;
        }
        if (variant_version >= 0) {
            ++variant_version;
            if (mi->simple_fquery(md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'variant_version' ;", md->table_prefix, variant_version) < 0)
                return -1;
        }
    }

    return 0;

fail:
    return -1;
}

extern struct variant_plugin_iface plugin_variant_mysql;

static struct variant_cnts_plugin_data *
open_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    struct variant_mysql_data *vmd = (struct variant_mysql_data *) data;

    if (!vmd->is_db_checked) {
        if (check_database(vmd) < 0) {
            return NULL;
        }
        vmd->is_db_checked = 1;
    }

    struct variant_cnts_mysql_data *vcmd = NULL;
    XCALLOC(vcmd, 1);
    vcmd->b.vt = &plugin_variant_mysql;
    vcmd->vmd = vmd;
    vcmd->contest_id = cnts->id;
    ++vmd->nref;
    
    return &vcmd->b;
}

static struct variant_cnts_plugin_data *
close_func(
        struct variant_cnts_plugin_data *data)
{
    struct variant_cnts_mysql_data *vcmd = (struct variant_cnts_mysql_data *) data;
    if (vcmd) {
        if (vcmd->vmd && vcmd->vmd->nref > 0) {
            --vcmd->vmd->nref;
        }
        xfree(vcmd);
    }
    return NULL;
}

struct variant_plugin_iface plugin_variant_mysql =
{
    {
        {
            sizeof (struct variant_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "variant",
            "mysql",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    VARIANT_PLUGIN_IFACE_VERSION,
    open_func,
    close_func,
    /*
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
    */
};
