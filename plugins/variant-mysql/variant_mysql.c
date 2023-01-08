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
#include "ejudge/common_plugin.h"
#include "ejudge/variant_plugin.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/prepare.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/dyntrie.h"
#include "ejudge/random.h"

#include <string.h>

#define VARIANT_DB_VERSION 2

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

struct user_variant_info
{
    int64_t serial_id;
    int user_id;
    unsigned char *login;
    int variant;
    int virtual_variant;
    long long last_update_time_us;
    int *prob_variants;
};

struct variant_cnts_mysql_data
{
    struct variant_cnts_plugin_data b;
    struct variant_mysql_data *vmd;
    int contest_id;

    struct user_variant_info *uvis;
    size_t uviu;
    size_t uvia;
    struct dyntrie_node *login_idx;

    // user index: indexed by user_id
    int *uidxv;
    int uidxa;

    // problem index
    int *prob_idxv;
    int prob_idxa;
    int var_prob_count;
};

static const char create_query_1[] =
"CREATE TABLE %svariants (\n"
"    serial_id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    contest_id INT NOT NULL,\n"
"    user_id INT UNSIGNED NOT NULL,\n"
"    variant INT,\n"
"    virtual_variant INT,\n"
"    last_update_time DATETIME(6) DEFAULT NULL,\n"
"    FOREIGN KEY v_user_id_fk(user_id) REFERENCES %slogins(user_id),\n"
"    KEY v_contest_id_idx(contest_id),\n"
"    UNIQUE KEY v_cu_id_idx(contest_id,user_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static const char create_query_2[] =
"CREATE TABLE %svariantentries (\n"
"    serial_id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    entry_id BIGINT NOT NULL,\n"
"    prob_id INT NOT NULL,\n"
"    variant INT,\n"
"    last_update_time DATETIME(6) DEFAULT NULL,\n"
"    FOREIGN KEY ve_entry_id_fk(entry_id) REFERENCES %svariants(serial_id),\n"
"    UNIQUE KEY ve_ep_id_idx(entry_id, prob_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static int
create_database(
        struct variant_mysql_data *vmd)
{
    struct common_mysql_iface *mi = vmd->mi;
    struct common_mysql_state *md = vmd->md;

    if (mi->simple_fquery(md, create_query_1,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_2,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);

    if (mi->simple_fquery(md, "INSERT INTO %sconfig VALUES ('variant_version', '%d') ;", md->table_prefix, VARIANT_DB_VERSION) < 0)
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
        case 1:
            if (mi->simple_fquery(md, "ALTER TABLE %svariants ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
                goto fail;
            if (mi->simple_fquery(md, "ALTER TABLE %svariantentries ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
                goto fail;
            break;
        case VARIANT_DB_VERSION:
            variant_version = -1;
            break;
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

static void
load_all(
        struct variant_cnts_mysql_data *vcmd,
        const struct serve_state *state);

extern struct variant_plugin_iface plugin_variant_mysql;

static struct variant_cnts_plugin_data *
open_func(
        struct common_plugin_data *data,
        FILE *log_f,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct serve_state *state,
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
    load_all(vcmd, state);
    
    return &vcmd->b;
}

static struct variant_cnts_plugin_data *
close_func(
        struct variant_cnts_plugin_data *data)
{
    struct variant_cnts_mysql_data *vcmd = (struct variant_cnts_mysql_data *) data;
    if (vcmd) {
        dyntrie_free(&vcmd->login_idx, NULL, NULL);
        for (size_t i = 0; i < vcmd->uviu; ++i) {
            struct user_variant_info *vii = &vcmd->uvis[i];
            free(vii->login);
            free(vii->prob_variants);
        }
        free(vcmd->uidxv);
        free(vcmd->prob_idxv);
        if (vcmd->vmd && vcmd->vmd->nref > 0) {
            --vcmd->vmd->nref;
        }
        xfree(vcmd);
    }
    return NULL;
}

static int
append_user_variant_info(
        struct variant_cnts_mysql_data *vcmd,
        int user_id,
        const unsigned char *login)
{
    int uvii;

    if (!vcmd->uvia) {
        vcmd->uvia = 16;
        XCALLOC(vcmd->uvis, vcmd->uvia);
        vcmd->uviu = 1;
    }
    if (vcmd->uviu == vcmd->uvia) {
        vcmd->uvia *= 2;
        XREALLOC(vcmd->uvis, vcmd->uvia);
    }
    uvii = vcmd->uviu++;
    struct user_variant_info *uvi = &vcmd->uvis[uvii];
    memset(uvi, 0, sizeof(*uvi));
    dyntrie_insert(&vcmd->login_idx, login, (void *) (intptr_t) uvii, 0, NULL);
    if (user_id >= vcmd->uidxa) {
        size_t new_size = 64;
        while (new_size <= user_id) new_size *= 2;
        int *new_index = NULL;
        XCALLOC(new_index, new_size);
        if (vcmd->uidxa > 0) {
            memcpy(new_index, vcmd->uidxv, vcmd->uidxa * sizeof(new_index[0]));
        }
        free(vcmd->uidxv);
        vcmd->uidxv = new_index;
        vcmd->uidxa = new_size;
    }
    vcmd->uidxv[user_id] = uvii;

    return uvii;
}

struct variant_info_internal
{
    int64_t serial_id;
    int contest_id;
    int user_id;
    int variant;
    int virtual_variant;
    struct timeval last_update_time;
    unsigned char *login;
};

enum { VARIANT_INFO_ROW_WIDTH = 6 };
#define VARIANT_INFO_OFFSET(f) XOFFSET(struct variant_info_internal, f)
static const struct common_mysql_parse_spec variant_info_spec[VARIANT_INFO_ROW_WIDTH] =
{
    { 0, 'l', "serial_id", VARIANT_INFO_OFFSET(serial_id), 0 },
    { 0, 'd', "contest_id", VARIANT_INFO_OFFSET(contest_id), 0 },
    { 0, 'd', "user_id", VARIANT_INFO_OFFSET(user_id), 0 },
    { 1, 'd', "variant", VARIANT_INFO_OFFSET(variant), 0 },
    { 1, 'd', "virtual_variant", VARIANT_INFO_OFFSET(virtual_variant), 0 },
    { 1, 'T', "last_update_time", VARIANT_INFO_OFFSET(last_update_time), 0 },
};

enum { VARIANT_INFO_ROW_WIDTH_2 = 7 };
static const struct common_mysql_parse_spec variant_info_spec_2[VARIANT_INFO_ROW_WIDTH_2] =
{
    { 0, 'l', "serial_id", VARIANT_INFO_OFFSET(serial_id), 0 },
    { 0, 'd', "contest_id", VARIANT_INFO_OFFSET(contest_id), 0 },
    { 0, 'd', "user_id", VARIANT_INFO_OFFSET(user_id), 0 },
    { 1, 'd', "variant", VARIANT_INFO_OFFSET(variant), 0 },
    { 1, 'd', "virtual_variant", VARIANT_INFO_OFFSET(virtual_variant), 0 },
    { 1, 'T', "last_update_time", VARIANT_INFO_OFFSET(last_update_time), 0 },
    { 1, 's', "login", VARIANT_INFO_OFFSET(login), 0 },
};

struct variantentry_info_internal
{
    int64_t serial_id;
    int64_t entry_id;
    int prob_id;
    int variant;
    struct timeval last_update_time;
    int user_id;
};

enum { VARIANTENTRY_INFO_ROW_WIDTH = 5 };
#define VARIANTENTRY_INFO_OFFSET(f) XOFFSET(struct variantentry_info_internal, f)
static const struct common_mysql_parse_spec variantentry_info_spec[VARIANTENTRY_INFO_ROW_WIDTH] =
{
    { 0, 'l', "serial_id", VARIANTENTRY_INFO_OFFSET(serial_id), 0 },
    { 0, 'l', "entry_id", VARIANTENTRY_INFO_OFFSET(entry_id), 0 },
    { 0, 'd', "prob_id", VARIANTENTRY_INFO_OFFSET(prob_id), 0 },
    { 0, 'd', "variant", VARIANTENTRY_INFO_OFFSET(variant), 0 },
    { 1, 'T', "last_update_time", VARIANTENTRY_INFO_OFFSET(last_update_time), 0 },
};

enum { VARIANTENTRY_INFO_ROW_WIDTH_2 = 3 };
static const struct common_mysql_parse_spec variantentry_info_spec_2[VARIANTENTRY_INFO_ROW_WIDTH_2] =
{
    { 0, 'd', "prob_id", VARIANTENTRY_INFO_OFFSET(prob_id), 0 },
    { 0, 'd', "variant", VARIANTENTRY_INFO_OFFSET(variant), 0 },
    { 0, 'd', "user_id", VARIANTENTRY_INFO_OFFSET(user_id), 0 },
};

static struct user_variant_info *
get_user_variant_info(
        struct variant_cnts_mysql_data *vcmd,
        const unsigned char *login)
{
    struct variant_mysql_data *vmd = vcmd->vmd;
    struct common_mysql_iface *mi = vmd->mi;
    struct common_mysql_state *md = vmd->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct variant_info_internal vii = {};

    int uvii = (int)(intptr_t) dyntrie_get(&vcmd->login_idx, login);
    if (uvii > 0) {
        return &vcmd->uvis[uvii];
    }

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT IGNORE INTO %svariants SET contest_id = %d, user_id = (SELECT user_id FROM logins where login = '",
            md->table_prefix, vcmd->contest_id);
    mi->escape_string(md, cmd_f, login);
    fprintf(cmd_f, "'), last_update_time = NOW(6);");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * from %svariants WHERE contest_id = %d and user_id = (SELECT user_id FROM logins WHERE login = '",
            md->table_prefix, vcmd->contest_id);
    mi->escape_string(md, cmd_f, login);
    fprintf(cmd_f, "');");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, VARIANT_INFO_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    if (md->row_count == 1) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, VARIANT_INFO_ROW_WIDTH, variant_info_spec, &vii) < 0) goto fail;

        int uvii = (int)(intptr_t) dyntrie_get(&vcmd->login_idx, login);
        struct user_variant_info *uvi = NULL;
        if (!uvii) {
            uvii = append_user_variant_info(vcmd, vii.user_id, login);
            uvi = &vcmd->uvis[uvii];
        } else {
            uvi = &vcmd->uvis[uvii];
            free(uvi->login); uvi->login = NULL;
        }

        uvi->serial_id = vii.serial_id;
        uvi->user_id = vii.user_id;
        uvi->login = xstrdup(login);
        uvi->variant = vii.variant;
        uvi->virtual_variant = vii.virtual_variant;
        uvi->last_update_time_us = vii.last_update_time.tv_sec * 1000000LL + vii.last_update_time.tv_usec;
        return uvi;
    }

    return NULL;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    return NULL;
}

static struct user_variant_info *
get_user_variant_info_2(
        struct variant_cnts_mysql_data *vcmd,
        int user_id)
{
    struct variant_mysql_data *vmd = vcmd->vmd;
    struct common_mysql_iface *mi = vmd->mi;
    struct common_mysql_state *md = vmd->md;
    struct variant_info_internal vii = {};
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;

    if (user_id <= 0) return NULL;
    if (user_id < vcmd->uidxa && vcmd->uidxv[user_id] > 0) {
        return &vcmd->uvis[vcmd->uidxv[user_id]];
    }

    if (mi->simple_fquery(md, "INSERT IGNORE INTO %svariants SET contest_id = %d, user_id = %d, last_update_time = NOW(6);",
                          md->table_prefix, vcmd->contest_id, user_id) < 0)
        goto fail;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT %svariants.*, %slogins.login FROM %svariants, %slogins WHERE %svariants.contest_id = %d AND %svariants.user_id = %d AND %slogins.user_id = %d;",
            md->table_prefix, md->table_prefix,
            md->table_prefix, md->table_prefix,
            md->table_prefix, vcmd->contest_id,
            md->table_prefix, user_id,
            md->table_prefix, user_id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, VARIANT_INFO_ROW_WIDTH_2) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    if (md->row_count == 1) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, VARIANT_INFO_ROW_WIDTH_2, variant_info_spec_2, &vii) < 0) goto fail;

        int uvii = append_user_variant_info(vcmd, vii.user_id, vii.login);
        struct user_variant_info *uvi = &vcmd->uvis[uvii];
        uvi->serial_id = vii.serial_id;
        uvi->user_id = vii.user_id;
        uvi->login = vii.login; vii.login = NULL;
        uvi->variant = vii.variant;
        uvi->virtual_variant = vii.virtual_variant;
        uvi->last_update_time_us = vii.last_update_time.tv_sec * 1000000LL + vii.last_update_time.tv_usec;
        return uvi;
    }

    return NULL;

fail:
    free(vii.login);
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    return NULL;
}

static int
find_variant_func(
        struct variant_cnts_plugin_data *data,
        const struct serve_state *state,
        int user_id,
        int prob_id,
        int *p_virtual_variant)
{
    struct variant_cnts_mysql_data *vcmd = (struct variant_cnts_mysql_data *) data;
    struct variant_mysql_data *vmd = vcmd->vmd;
    struct common_mysql_iface *mi = vmd->mi;
    struct common_mysql_state *md = vmd->md;
    struct user_variant_info *uvi = get_user_variant_info_2(vcmd, user_id);
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct variantentry_info_internal veii = {};

    if (uvi->variant > 0) {
        if (p_virtual_variant) {
            if (uvi->virtual_variant > 0) {
                *p_virtual_variant = uvi->virtual_variant;
            } else {
                *p_virtual_variant = uvi->variant;
            }
        }
        return uvi->variant;
    }

    if (prob_id <= 0 || prob_id > state->max_prob) {
        return 0;
    }
    struct section_problem_data *prob = state->probs[prob_id];
    if (!prob) {
        return 0;
    }
    if (prob->variant_num <= 0) {
        return 0;
    }

    if (!vcmd->prob_idxv) {
        int max_prob_id = 0;
        int var_prob_count = 0;
        for (int i = 1; i <= state->max_prob; ++i) {
            struct section_problem_data *prob = state->probs[i];
            if (prob && prob->variant_num > 0) {
                max_prob_id = i;
                ++var_prob_count;
            }
        }
        if (max_prob_id > 0) {
            vcmd->prob_idxa = max_prob_id + 1;
            XCALLOC(vcmd->prob_idxv, vcmd->prob_idxa);
            vcmd->var_prob_count = var_prob_count;
            int j = 0;
            for (int i = 1; i <= state->max_prob; ++i) {
                struct section_problem_data *prob = state->probs[i];
                if (prob && prob->variant_num > 0) {
                    vcmd->prob_idxv[i] = j++;
                }
            }
        } else {
            return 0;
        }
    }

    if (!uvi->prob_variants) {
        XCALLOC(uvi->prob_variants, vcmd->var_prob_count);
    }

    int prob_variant = uvi->prob_variants[vcmd->prob_idxv[prob_id]];
    if (prob_variant > 0) {
        return prob_variant;
    }

    prob = state->probs[prob_id];
    prob_variant = random_range(1, prob->variant_num + 1);

    if (mi->simple_fquery(md, "INSERT IGNORE INTO %svariantentries SET entry_id = %lld, prob_id = %d, variant = %d, last_update_time = NOW(6);",
                          md->table_prefix,
                          (long long) uvi->serial_id,
                          prob_id,
                          prob_variant) < 0)
        goto fail;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %svariantentries WHERE entry_id = %lld AND prob_id = %d;",
            md->table_prefix,
            (long long) uvi->serial_id,
            prob_id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, VARIANTENTRY_INFO_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    if (md->row_count == 1) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, VARIANTENTRY_INFO_ROW_WIDTH, variantentry_info_spec, &veii) < 0) goto fail;
        prob_variant = veii.variant;
        uvi->prob_variants[vcmd->prob_idxv[prob_id]] = prob_variant;
        return prob_variant;
    }

    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    return 0;
}

static int
find_user_variant_func(
        struct variant_cnts_plugin_data *data,
        const struct serve_state *state,
        int user_id,
        int *p_virtual_variant)
{
    struct variant_cnts_mysql_data *vcmd = (struct variant_cnts_mysql_data *) data;
    struct user_variant_info *uvi = get_user_variant_info_2(vcmd, user_id);
    if (uvi->variant > 0) {
        if (p_virtual_variant) {
            if (uvi->virtual_variant > 0) {
                *p_virtual_variant = uvi->virtual_variant;
            } else {
                *p_virtual_variant = uvi->variant;
            }
        }
        return uvi->variant;
    }

    return 0;
}

static int
upsert_user_variant_func(
        struct variant_cnts_plugin_data *data,
        const unsigned char *login,
        int variant,
        int virtual_variant,
        int64_t *p_key)
{
    struct variant_cnts_mysql_data *vcmd = (struct variant_cnts_mysql_data *) data;
    struct variant_mysql_data *vmd = vcmd->vmd;
    struct common_mysql_iface *mi = vmd->mi;
    struct common_mysql_state *md = vmd->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct variant_info_internal vii = {};

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %svariants SET contest_id = %d, user_id = (SELECT user_id FROM logins where login = '",
            md->table_prefix, vcmd->contest_id);
    mi->escape_string(md, cmd_f, login);
    fprintf(cmd_f, "'), variant = ");
    if (variant > 0) {
        fprintf(cmd_f, "%d", variant);
    } else {
        fprintf(cmd_f, "null");
    }
    fprintf(cmd_f, ", virtual_variant = ");
    if (virtual_variant > 0) {
        fprintf(cmd_f, "%d", virtual_variant);
    } else {
        fprintf(cmd_f, "null");
    }
    fprintf(cmd_f, ", last_update_time = NOW(6) ON DUPLICATE KEY UPDATE variant = ");
    if (variant > 0) {
        fprintf(cmd_f, "%d", variant);
    } else {
        fprintf(cmd_f, "null");
    }
    fprintf(cmd_f, ", virtual_variant = ");
    if (virtual_variant > 0) {
        fprintf(cmd_f, "%d", virtual_variant);
    } else {
        fprintf(cmd_f, "null");
    }
    fprintf(cmd_f, ", last_update_time = NOW(6);");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * from %svariants WHERE contest_id = %d and user_id = (SELECT user_id FROM logins WHERE login = '",
            md->table_prefix, vcmd->contest_id);
    mi->escape_string(md, cmd_f, login);
    fprintf(cmd_f, "');");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, VARIANT_INFO_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    if (md->row_count == 1) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, VARIANT_INFO_ROW_WIDTH, variant_info_spec, &vii) < 0) goto fail;

        int uvii = (int)(intptr_t) dyntrie_get(&vcmd->login_idx, login);
        struct user_variant_info *uvi = NULL;
        if (!uvii) {
            uvii = append_user_variant_info(vcmd, vii.user_id, login);
            uvi = &vcmd->uvis[uvii];
        } else {
            uvi = &vcmd->uvis[uvii];
            free(uvi->login); uvi->login = NULL;
        }

        uvi->serial_id = vii.serial_id;
        uvi->user_id = vii.user_id;
        uvi->login = xstrdup(login);
        uvi->variant = vii.variant;
        uvi->virtual_variant = vii.virtual_variant;
        uvi->last_update_time_us = vii.last_update_time.tv_sec * 1000000LL + vii.last_update_time.tv_usec;
    }

    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    return -1;
}

static void
load_all(
        struct variant_cnts_mysql_data *vcmd,
        const struct serve_state *state)
{
    struct variant_mysql_data *vmd = vcmd->vmd;
    struct common_mysql_iface *mi = vmd->mi;
    struct common_mysql_state *md = vmd->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;

    int max_prob_id = 0;
    int var_prob_count = 0;
    for (int prob_id = 1; prob_id <= state->max_prob; ++prob_id) {
        const struct section_problem_data *prob = state->probs[prob_id];
        if (prob && prob->variant_num > 0) {
            max_prob_id = prob_id;
            ++var_prob_count;
        }
    }
    // no variant problems
    if (!max_prob_id) {
        return;
    }

    vcmd->prob_idxa = max_prob_id + 1;
    XCALLOC(vcmd->prob_idxv, vcmd->prob_idxa);
    vcmd->var_prob_count = var_prob_count;
    for (int prob_id = 1, j = 0; prob_id <= state->max_prob; ++prob_id) {
        const struct section_problem_data *prob = state->probs[prob_id];
        if (prob && prob->variant_num > 0) {
            vcmd->prob_idxv[prob_id] = j++;
        }
    }

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT %svariants.*, %slogins.login FROM %svariants LEFT JOIN %slogins ON %svariants.user_id = %slogins.user_id WHERE %svariants.contest_id = %d order by %svariants.user_id;",
            md->table_prefix, md->table_prefix,
            md->table_prefix, md->table_prefix,
            md->table_prefix, md->table_prefix,
            md->table_prefix, vcmd->contest_id, md->table_prefix);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, VARIANT_INFO_ROW_WIDTH_2) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    for (int row = 0; row < md->row_count; ++row) {
        struct variant_info_internal vii = {};
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, VARIANT_INFO_ROW_WIDTH_2, variant_info_spec_2, &vii) < 0) goto fail;

        int uvii = append_user_variant_info(vcmd, vii.user_id, vii.login);
        struct user_variant_info *uvi = &vcmd->uvis[uvii];
        uvi->serial_id = vii.serial_id;
        uvi->user_id = vii.user_id;
        uvi->login = vii.login; vii.login = NULL;
        uvi->variant = vii.variant;
        uvi->virtual_variant = vii.virtual_variant;
        uvi->last_update_time_us = vii.last_update_time.tv_sec * 1000000LL + vii.last_update_time.tv_usec;
    }

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT %svariantentries.prob_id, %svariantentries.variant , %svariants.user_id FROM %svariantentries LEFT JOIN %svariants ON %svariantentries.entry_id = %svariants.serial_id WHERE %svariants.contest_id = %d ORDER BY %svariants.user_id, %svariantentries.prob_id;",
            md->table_prefix, md->table_prefix, md->table_prefix,
            md->table_prefix, md->table_prefix,
            md->table_prefix, md->table_prefix,
            md->table_prefix, vcmd->contest_id,
            md->table_prefix, md->table_prefix);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, VARIANTENTRY_INFO_ROW_WIDTH_2) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    for (int row = 0; row < md->row_count; ++row) {
        struct variantentry_info_internal veii = {};
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, VARIANTENTRY_INFO_ROW_WIDTH_2, variantentry_info_spec_2, &veii) < 0) goto fail;

        if (veii.user_id > 0 && veii.user_id < vcmd->uidxa) {
            int index = vcmd->uidxv[veii.user_id];
            if (index > 0) {
                struct user_variant_info *uvi = &vcmd->uvis[index];
                if (veii.prob_id > 0 && veii.prob_id < vcmd->prob_idxa) {
                    int prob_index = vcmd->prob_idxv[veii.prob_id];
                    const struct section_problem_data *prob = state->probs[veii.prob_id];
                    if (prob && prob->variant_num > 0) {
                        if (veii.variant > 0 && veii.variant <= prob->variant_num) {
                            if (!uvi->prob_variants) {
                                XCALLOC(uvi->prob_variants, vcmd->var_prob_count);
                            }
                            uvi->prob_variants[prob_index] = veii.variant;
                        }
                    }
                }
            }
        }
    }

    return;

fail:;
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
}

static int
upsert_variant_func(
        struct variant_cnts_plugin_data *data,
        const unsigned char *login,
        int prob_id,
        int variant)
{
    struct variant_cnts_mysql_data *vcmd = (struct variant_cnts_mysql_data *) data;
    struct variant_mysql_data *vmd = vcmd->vmd;
    struct common_mysql_iface *mi = vmd->mi;
    struct common_mysql_state *md = vmd->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;

    struct user_variant_info *uvi = get_user_variant_info(vcmd, login);
    if (!uvi) goto fail;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %svariantentries SET entry_id = %lld, prob_id = %d, variant = %d, last_update_time = NOW(6) ON DUPLICATE KEY UPDATE variant = %d, last_update_time = NOW(6);",
            md->table_prefix, (long long) uvi->serial_id,
            prob_id, variant, variant);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    return 0;

fail:;
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    return -1;
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
    find_variant_func,
    find_user_variant_func,
    NULL, // get_entry_count
    NULL, // get_keys
    NULL, // get_login
    NULL, // get_user_variant
    NULL, // get_problem_ids
    NULL, // get_variant
    upsert_user_variant_func,
    upsert_variant_func,
};
