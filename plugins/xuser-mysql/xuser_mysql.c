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
#include "ejudge/xuser_plugin.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/team_extra.h"
#include "ejudge/contests.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

#include <stdint.h>
#include <string.h>

#define XUSER_DB_VERSION 5

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
    struct team_extra **extras;
    int extra_u, extra_a;
};

static const char create_query_1[] =
"CREATE TABLE %suserwarnings (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    user_extra_id INT NOT NULL,\n"
"    issue_date DATETIME NOT NULL,\n"
"    issuer_id INT UNSIGNED NOT NULL,\n"
"    issuer_ip VARCHAR(128) DEFAULT NULL,\n"
"    user_text MEDIUMTEXT DEFAULT NULL,\n"
"    judge_text MEDIUMTEXT DEFAULT NULL,\n"
"    last_update_time DATETIME(6) DEFAULT NULL,\n"
"    FOREIGN KEY uw_user_id_2_fk(issuer_id) REFERENCES %slogins(user_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static const char create_query_2[] =
"CREATE TABLE %sviewedclars (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    user_extra_id INT NOT NULL,\n"
"    clar_uuid CHAR(40) CHARSET utf8 COLLATE utf8_bin NOT NULL,\n"
"    last_update_time DATETIME(6) DEFAULT NULL,\n"
"    KEY vc_clar_uuid_k(clar_uuid),\n"
"    UNIQUE KEY vc_clar_user_uuid_uk(user_extra_id, clar_uuid)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";
    
static __attribute__((unused)) const char create_query_3[] =
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
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

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
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_2,
                          md->table_prefix) < 0)
        db_error_fail(md);
    /*
    if (mi->simple_fquery(md, create_query_3,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
*/
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

    if (mi->simple_fquery(md, "INSERT INTO %sconfig VALUES ('xuser_version', '%d') ;", md->table_prefix, XUSER_DB_VERSION) < 0)
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
        case 1:
            if (mi->simple_fquery(md, "ALTER TABLE %suserwarnings ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
                goto fail;
            if (mi->simple_fquery(md, "ALTER TABLE %sviewedclars ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
                goto fail;
            if (mi->simple_fquery(md, "ALTER TABLE %suserextras ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
                goto fail;
            break;
        case 2:
            if (mi->simple_fquery(md, "ALTER TABLE %suserwarnings MODIFY COLUMN issuer_ip VARCHAR(128) DEFAULT NULL, MODIFY COLUMN user_text MEDIUMTEXT DEFAULT NULL, MODIFY COLUMN judge_text MEDIUMTEXT DEFAULT NULL ;", md->table_prefix) < 0)
                goto fail;
            break;
        case 3:
            if (mi->simple_fquery(md, "ALTER TABLE %sviewedclars MODIFY COLUMN clar_uuid CHAR(40) NOT NULL ;", md->table_prefix) < 0)
                goto fail;
            break;
        case 4:
            if (mi->simple_fquery(md, "ALTER TABLE %suserextras MODIFY COLUMN disq_comment TEXT(4096) DEFAULT NULL, MODIFY COLUMN problem_dir_prefix VARCHAR(1024) DEFAULT NULL ;", md->table_prefix) < 0)
                goto fail;
            break;
        case XUSER_DB_VERSION:
            xuser_version = -1;
            break;
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
        if (xmcs->extra_u > 0) {
            for (int i = 0; i < xmcs->extra_u; ++i) {
                team_extra_free(xmcs->extras[i]);
            }
        }
        free(xmcs->extras);
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
    time_t issue_date;
    int issuer_id;
    ej_ip_t issuer_ip;
    char *user_text;
    char *judge_text;
    struct timeval last_update_time;
};

enum { USER_WARNING_ROW_WIDTH = 8 };
#define USER_WARNING_OFFSET(f) XOFFSET(struct user_warning_internal, f)
static const struct common_mysql_parse_spec user_warning_spec[USER_WARNING_ROW_WIDTH] =
{
    { 0, 'd', "serial_id", USER_WARNING_OFFSET(serial_id), 0 },
    { 0, 'd', "user_extra_id", USER_WARNING_OFFSET(user_extra_id), 0 },
    { 1, 't', "issue_date", USER_WARNING_OFFSET(issue_date), 0 },
    { 0, 'd', "issuer_id", USER_WARNING_OFFSET(issuer_id), 0 },
    { 1, 'I', "issuer_ip", USER_WARNING_OFFSET(issuer_ip), 0 },
    { 1, 's', "user_text", USER_WARNING_OFFSET(user_text), 0 },
    { 1, 's', "judge_text", USER_WARNING_OFFSET(judge_text), 0 },
    { 1, 'T', "last_update_time", USER_WARNING_OFFSET(last_update_time), 0 },
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
static const struct common_mysql_parse_spec viewed_clar_spec[VIEWED_CLAR_ROW_WIDTH] =
{
    { 0, 'd', "serial_id", VIEWED_CLAR_OFFSET(serial_id), 0 },
    { 0, 'd', "user_extra_id", VIEWED_CLAR_OFFSET(user_extra_id), 0 },
    { 1, 'g', "clar_uuid", VIEWED_CLAR_OFFSET(clar_uuid), 0 },
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
static const struct common_mysql_parse_spec user_extra_spec[USER_EXTRA_ROW_WIDTH] =
{
    { 0, 'd', "serial_id", USER_EXTRA_OFFSET(serial_id), 0 },
    { 0, 'd', "contest_id", USER_EXTRA_OFFSET(contest_id), 0 },
    { 0, 'd', "user_id", USER_EXTRA_OFFSET(user_id), 0 },
    { 1, 's', "disq_comment", USER_EXTRA_OFFSET(disq_comment), 0 },
    { 0, 'd', "status", USER_EXTRA_OFFSET(status), 0 },
    { 0, 'l', "run_fields", USER_EXTRA_OFFSET(run_fields), 0 },
    { 1, 's', "problem_dir_prefix", USER_EXTRA_OFFSET(problem_dir_prefix), 0 },
    { 1, 'T', "last_update_time", USER_EXTRA_OFFSET(last_update_time), 0 },
};

static int
uuid_sort_func(const void *p1, const void *p2)
{
    const ej_uuid_t *u1 = (const ej_uuid_t *) p1;
    const ej_uuid_t *u2 = (const ej_uuid_t *) p2;
    // reverse order, because of team_extra.c binary search!
    if (u1->v[0] < u2->v[0]) {
        return 1;
    } else if (u1->v[0] > u2->v[0]) {
        return -1;
    } else if (u1->v[1] < u2->v[1]) {
        return 1;
    } else if (u1->v[1] > u2->v[1]) {
        return -1;
    } else if (u1->v[2] < u2->v[2]) {
        return 1;
    } else if (u1->v[2] > u2->v[2]) {
        return -1;
    } else if (u1->v[3] < u2->v[3]) {
        return 1;
    } else if (u1->v[3] > u2->v[3]) {
        return -1;
    } else {
        return 0;
    }
}

static struct team_extra *
fetch_user(
        struct xuser_mysql_cnts_state *xmcs,
        int user_id)
{
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;
    struct team_extra *te = NULL;
    struct user_extra_internal uxi = {};

    XCALLOC(te, 1);
    if (mi->fquery(md, USER_EXTRA_ROW_WIDTH,
                   "SELECT * FROM %suserextras WHERE contest_id=%d AND user_id=%d;", md->table_prefix, xmcs->contest_id, user_id) < 0)
        db_error_fail(md);
    if (!md->row_count) {
        return NULL;
    }
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (mi->parse_spec(md, -1, md->row, md->lengths, USER_EXTRA_ROW_WIDTH, user_extra_spec, &uxi) < 0) goto fail;

    te->serial_id = uxi.serial_id;
    te->contest_id = uxi.contest_id;
    te->user_id = uxi.user_id;
    te->disq_comment = uxi.disq_comment; uxi.disq_comment = NULL;
    te->status = uxi.status;
    te->run_fields = uxi.run_fields;
    te->problem_dir_prefix = uxi.problem_dir_prefix; uxi.problem_dir_prefix = NULL;

    if (mi->fquery(md, VIEWED_CLAR_ROW_WIDTH,
                   "SELECT * FROM %sviewedclars WHERE user_extra_id=%d",
                   md->table_prefix, te->serial_id) < 0)
        db_error_fail(md);
    if (md->row_count > 0) {
        te->clar_uuids_alloc = 4;
        while (te->clar_uuids_alloc < md->row_count)
            te->clar_uuids_alloc *= 2;
        XCALLOC(te->clar_uuids, te->clar_uuids_alloc);
        te->clar_uuids_size = md->row_count;
        for (int i = 0; i < md->row_count; ++i) {
            struct viewed_clar_internal vci = {};
            if (mi->next_row(md) < 0) db_error_fail(md);
            if (mi->parse_spec(md, -1, md->row, md->lengths, VIEWED_CLAR_ROW_WIDTH, viewed_clar_spec, &vci) < 0) goto fail;
            te->clar_uuids[i] = vci.clar_uuid;
        }
        qsort(te->clar_uuids, md->row_count, sizeof(te->clar_uuids[0]), uuid_sort_func);
    }

    if (mi->fquery(md, USER_WARNING_ROW_WIDTH,
                   "SELECT * FROM %suserwarnings WHERE user_extra_id=%d",
                   md->table_prefix, te->serial_id) < 0)
        db_error_fail(md);
    if (md->row_count > 0) {
        te->warn_a = 4;
        while (te->warn_a < md->row_count)
            te->warn_a *= 2;
        XCALLOC(te->warns, te->warn_a);
        te->warn_u = md->row_count;
        for (int i = 0; i < md->row_count; ++i) {
            struct user_warning_internal uwi = {};
            if (mi->next_row(md) < 0) db_error_fail(md);
            if (mi->parse_spec(md, -1, md->row, md->lengths, USER_WARNING_ROW_WIDTH, user_warning_spec, &uwi) < 0) goto fail;
            struct team_warning *tw = NULL;
            XCALLOC(tw, 1);
            te->warns[i] = tw;
            tw->serial_id = uwi.serial_id;
            tw->date = uwi.issue_date;
            tw->issuer_id = uwi.issuer_id;
            tw->issuer_ip = uwi.issuer_ip;
            tw->text = uwi.user_text; uwi.user_text = NULL;
            tw->comment = uwi.judge_text; uwi.judge_text = NULL;
        }
    }

    return te;

fail:
    free(uxi.problem_dir_prefix);
    free(uxi.disq_comment);
    team_extra_free(te);
    return NULL;
}

static struct team_extra *
find_user(
        struct xuser_mysql_cnts_state *xmcs,
        int user_id,
        int *p_index)
{
    int low = 0, high = xmcs->extra_u, mid;
    while (low < high) {
        mid = (low + high) / 2;
        if (xmcs->extras[mid]->user_id == user_id) {
            if (p_index) *p_index = mid;
            return xmcs->extras[mid];
        } else if (xmcs->extras[mid]->user_id < user_id) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if (p_index) *p_index = low;
    return NULL;
}

static void
insert_user(
        struct xuser_mysql_cnts_state *xmcs,
        int index,
        struct team_extra *te)
{
    if (xmcs->extra_u == xmcs->extra_a) {
        if (!(xmcs->extra_a *= 2)) xmcs->extra_a = 16;
        xmcs->extras = xrealloc(xmcs->extras, xmcs->extra_a * sizeof(xmcs->extras[0]));
    }
    if (index < xmcs->extra_u) {
        memmove(&xmcs->extras[index + 1], &xmcs->extras[index],
                (xmcs->extra_u - index) * sizeof(xmcs->extras[0]));
    }
    ++xmcs->extra_u;
    xmcs->extras[index] = te;
}

static struct team_extra *
create_user(
        struct xuser_mysql_cnts_state *xmcs,
        int user_id)
{
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;

    if (mi->simple_fquery(md,
                          "INSERT IGNORE INTO %suserextras(contest_id,user_id,last_update_time) VALUES(%d,%d,NOW(6));",
                          md->table_prefix,
                          xmcs->contest_id, user_id) < 0)
        db_error_fail(md);
    return fetch_user(xmcs, user_id);

fail:
    return NULL;
}

static struct team_extra *
fetch_or_create_user(
        struct xuser_mysql_cnts_state *xmcs,
        int user_id)
{
    int index = 0;
    struct team_extra *te = find_user(xmcs, user_id, &index);
    if (te && te->serial_id <= 0) {
        te = create_user(xmcs, user_id);
        team_extra_free(xmcs->extras[index]);
        xmcs->extras[index] = te;
    } else if (!te) {
        te = fetch_user(xmcs, user_id);
        if (!te) {
            te = create_user(xmcs, user_id);
            if (!te) {
                return NULL;
            }
        }
        insert_user(xmcs, index, te);
    }
    return te;
}

static const struct team_extra *
get_entry_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    int index = 0;
    struct team_extra *te = find_user(xmcs, user_id, &index);
    if (te) {
        return te;
    }
    te = fetch_user(xmcs, user_id);
    if (!te) {
        XCALLOC(te, 1);
        te->serial_id = -1;
        te->contest_id = xmcs->contest_id;
        te->user_id = user_id;
    }
    insert_user(xmcs, index, te);
    return te;
}

static int
get_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid)
{
    const struct team_extra *te = get_entry_func(data, user_id);
    if (!te) return 0;
    return team_extra_find_clar_uuid(te, p_clar_uuid);
}

static int
set_clar_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;
    if (!p_clar_uuid) return -1;
    struct team_extra *te = fetch_or_create_user(xmcs, user_id);
    if (!te) goto fail;

    if (team_extra_find_clar_uuid(te, p_clar_uuid) >= 0) return 0;
    team_extra_add_clar_uuid(te, p_clar_uuid);
    char uuid_buf[64];
    ej_uuid_unparse_r(uuid_buf, sizeof(uuid_buf), p_clar_uuid, NULL);
    mi->simple_fquery(md,
                      "INSERT IGNORE INTO %sviewedclars(user_extra_id,clar_uuid,last_update_time) VALUES(%d,'%s',NOW(6));",
                      md->table_prefix, te->serial_id, uuid_buf);
    return 0;

fail:
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
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;
    struct team_extra *te = fetch_or_create_user(xmcs, user_id);
    FILE *cmd_f = NULL;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    if (!te) goto fail;

    struct user_warning_internal uwi = {};
    uwi.user_extra_id = te->serial_id;
    uwi.issue_date = issue_date;
    uwi.issuer_id = issuer_id;
    uwi.issuer_ip = *issuer_ip;
    uwi.user_text = (char*) txt;
    uwi.judge_text = (char*) cmt;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %suserwarnings VALUES (DEFAULT,", md->table_prefix);
    mi->unparse_spec_2(md, cmd_f, USER_WARNING_ROW_WIDTH,
                       user_warning_spec,
                       (1ULL << (USER_WARNING_ROW_WIDTH - 1)) | 1,
                       &uwi);
    fprintf(cmd_f, ",NOW(6))");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    if (te->warn_u == te->warn_a) {
        if (!(te->warn_a *= 2)) te->warn_a = 4;
        XREALLOC(te->warns, te->warn_a);
    }
    struct team_warning *tw = NULL;
    XCALLOC(tw, 1);
    te->warns[te->warn_u++] = tw;
    tw->serial_id = -1;
    tw->date = issue_date;
    tw->issuer_id = issuer_id;
    tw->issuer_ip = *issuer_ip;
    tw->text = xstrdup(txt);
    tw->comment = xstrdup(cmt);

    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    if (cmd_s) free(cmd_s);
    return -1;
}

static int
set_status_func(
        struct xuser_cnts_state *data,
        int user_id,
        int status)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;
    FILE *cmd_f = NULL;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    struct team_extra *te = fetch_or_create_user(xmcs, user_id);
    if (!te) goto fail;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "UPDATE %suserextras SET status = %d, last_update_time = NOW(6) WHERE serial_id = %d;",
            md->table_prefix,
            status, te->serial_id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    te->status = status;
    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    if (cmd_s) free(cmd_s);
    return -1;
}

static int
set_disq_comment_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *disq_comment)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;
    FILE *cmd_f = NULL;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    struct team_extra *te = fetch_or_create_user(xmcs, user_id);
    if (!te) goto fail;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "UPDATE %suserextras SET disq_comment = ", md->table_prefix);
    mi->write_escaped_string(md, cmd_f, NULL, disq_comment);
    fprintf(cmd_f, ", last_update_time = NOW(6) WHERE serial_id = %d;",
            te->serial_id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    xfree(te->disq_comment);
    te->disq_comment = xstrdup(disq_comment);

    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    if (cmd_s) free(cmd_s);
    return -1;
}

static long long
get_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    int index = 0;
    struct team_extra *te = find_user(xmcs, user_id, &index);
    if (te) {
        return te->run_fields;
    }
    te = fetch_user(xmcs, user_id);
    if (!te) {
        return 0;
    }
    insert_user(xmcs, index, te);
    return te->run_fields;
}

static int
set_run_fields_func(
        struct xuser_cnts_state *data,
        int user_id,
        long long run_fields)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;
    FILE *cmd_f = NULL;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    struct team_extra *te = fetch_or_create_user(xmcs, user_id);
    if (!te) goto fail;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "UPDATE %suserextras SET run_fields = %lld, last_update_time = NOW(6) WHERE serial_id = %d;",
            md->table_prefix,
            run_fields, te->serial_id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    te->run_fields = run_fields;
    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    if (cmd_s) free(cmd_s);
    return -1;
}

static int
count_read_clars_func(
        struct xuser_cnts_state *data,
        int user_id)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    int index = 0;
    struct team_extra *te = find_user(xmcs, user_id, &index);
    if (te) {
        return te->clar_uuids_size;
    }
    te = fetch_user(xmcs, user_id);
    if (!te) {
        return 0;
    }
    insert_user(xmcs, index, te);
    return te->clar_uuids_size;
}

struct xuser_mysql_team_extras
{
    struct xuser_team_extras b;
    struct xuser_mysql_cnts_state *xmcs;
};

static struct xuser_team_extras *
xuser_mysql_team_extras_free_func(struct xuser_team_extras *e)
{
    if (e) {
        struct xuser_mysql_team_extras *xmte = (struct xuser_mysql_team_extras *) e;
        free(xmte);
    }
    return NULL;
}
static const struct team_extra * 
xuser_mysql_team_extras_get_func(struct xuser_team_extras *e, int user_id)
{
    return NULL;
}

static int
sort_int_func(const void *p1, const void *p2)
{
    int v1 = *(const int *) p1;
    int v2 = *(const int *) p2;
    if (v1 < v2) return -1;
    return v1 > v2;
}

static int
team_extra_user_sort_func(const void *p1, const void *p2)
{
    const struct team_extra *te1 = *(const struct team_extra **) p1;
    const struct team_extra *te2 = *(const struct team_extra **) p2;
    // user_id > 0!
    return te1->user_id - te2->user_id;
}

static struct xuser_team_extras *
get_entries_func(
        struct xuser_cnts_state *data,
        int count,
        int *user_ids)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;
    struct xuser_mysql_team_extras *xmte = NULL;
    int *local_ids = NULL;
    int *fetch_ids = NULL;
    int fetch_count = 0;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct team_extra **new_te = NULL;
    int new_count = 0;

    if (count <= 0 || !user_ids) return NULL;

    local_ids = xmalloc(count * sizeof(local_ids[0]));
    memcpy(local_ids, user_ids, count * sizeof(local_ids[0]));
    qsort(local_ids, count, sizeof(local_ids[0]), sort_int_func);
    if (count > 1) {
        int i1, i2;
        for (i1 = i2 = 1; i1 < count; ++i1) {
            if (local_ids[i1] != local_ids[i1 - 1]) {
                if (i1 != i2) {
                    local_ids[i2] = local_ids[i1];
                }
                ++i2;
            }
        }
        count = i2;
    }
    fetch_ids = xmalloc(count * sizeof(fetch_ids[0]));

    {
        int i1 = 0, i2 = 0;
        while (i1 < count && i2 < xmcs->extra_u) {
            if (local_ids[i1] < xmcs->extras[i2]->user_id) {
                fetch_ids[fetch_count++] = local_ids[i1++];
            } else if (local_ids[i1] > xmcs->extras[i2]->user_id) {
                ++i2;
            } else {
                ++i1; ++i2;
            }
        }
        if (i1 < count) {
            for (; i1 < count; ++i1) {
                fetch_ids[fetch_count++] = local_ids[i1];
            }
        }
    }

    XCALLOC(xmte, 1);
    xmte->b.free = xuser_mysql_team_extras_free_func;
    xmte->b.get = xuser_mysql_team_extras_get_func;
    xmte->xmcs = xmcs;

    if (fetch_count > 0) {
        cmd_f = open_memstream(&cmd_s, &cmd_z);
        fprintf(cmd_f, "SELECT * FROM %suserextras WHERE contest_id=%d AND user_id IN (", md->table_prefix, xmcs->contest_id);
        for (int i = 0; i < fetch_count; ++i) {
            if (i > 0) fprintf(cmd_f, ",");
            fprintf(cmd_f, "%d", fetch_ids[i]);
        }
        fprintf(cmd_f, ") ORDER BY serial_id;");
        fclose(cmd_f); cmd_f = NULL;
        if (mi->query(md, cmd_s, cmd_z, USER_EXTRA_ROW_WIDTH) < 0)
            db_error_fail(md);
        free(cmd_s); cmd_s = NULL; cmd_z = 0;
        if (md->row_count > 0) {
            new_count = md->row_count;
            XCALLOC(new_te, new_count);
            for (int i = 0; i < new_count; ++i) {
                struct user_extra_internal uxi = {};
                if (mi->next_row(md) < 0) db_error_fail(md);
                if (mi->parse_spec(md, -1, md->row, md->lengths, USER_EXTRA_ROW_WIDTH, user_extra_spec, &uxi) < 0) goto fail;
                struct team_extra *te = NULL;
                XCALLOC(te, 1);
                new_te[i] = te;
                te->serial_id = uxi.serial_id;
                te->contest_id = uxi.contest_id;
                te->user_id = uxi.user_id;
                te->disq_comment = uxi.disq_comment; uxi.disq_comment = NULL;
                te->status = uxi.status;
                te->run_fields = uxi.run_fields;
                te->problem_dir_prefix = uxi.problem_dir_prefix; uxi.problem_dir_prefix = NULL;
            }
            cmd_f = open_memstream(&cmd_s, &cmd_z);
            fprintf(cmd_f, "SELECT * FROM %sviewedclars WHERE user_extra_id IN (",
                    md->table_prefix);
            for (int i = 0; i < new_count; ++i) {
                if (i > 0) fprintf(cmd_f, ",");
                fprintf(cmd_f, "%d", new_te[i]->serial_id);
            }
            fprintf(cmd_f, ") ORDER BY user_extra_id;");
            fclose(cmd_f); cmd_f = NULL;
            if (mi->query(md, cmd_s, cmd_z, VIEWED_CLAR_ROW_WIDTH) < 0)
                db_error_fail(md);
            free(cmd_s); cmd_s = NULL; cmd_z = 0;
            if (md->row_count > 0) {
                int i1 = 0;
                for (int i2 = 0; i2 < md->row_count; ++i2) {
                    struct viewed_clar_internal vci = {};
                    if (mi->next_row(md) < 0) db_error_fail(md);
                    if (mi->parse_spec(md, -1, md->row, md->lengths, VIEWED_CLAR_ROW_WIDTH, viewed_clar_spec, &vci) < 0) goto fail;
                    while (i1 < new_count && new_te[i1]->serial_id < vci.serial_id) {
                        ++i1;
                    }
                    if (i1 < new_count && new_te[i1]->serial_id == vci.serial_id) {
                        struct team_extra *te = new_te[i1];
                        if (te->clar_uuids_size == te->clar_uuids_alloc) {
                            if (!(te->clar_uuids_alloc *= 2)) te->clar_uuids_alloc = 4;
                            XREALLOC(te->clar_uuids, te->clar_uuids_alloc);
                        }
                        te->clar_uuids[te->clar_uuids_size++] = vci.clar_uuid;
                    }
                }
                for (i1 = 0; i1 < new_count; ++i1) {
                    struct team_extra *te = new_te[i1];
                    if (te->clar_uuids_size > 1) {
                        qsort(te->clar_uuids, te->clar_uuids_size, sizeof(te->clar_uuids[0]), uuid_sort_func);
                    }
                }
            }
            cmd_f = open_memstream(&cmd_s, &cmd_z);
            fprintf(cmd_f, "SELECT * FROM %suserwarnings WHERE user_extra_id IN (",
                    md->table_prefix);
            for (int i = 0; i < new_count; ++i) {
                if (i > 0) fprintf(cmd_f, ",");
                fprintf(cmd_f, "%d", new_te[i]->serial_id);
            }
            fprintf(cmd_f, ") ORDER BY user_extra_id, serial_id;");
            fclose(cmd_f); cmd_f = NULL;
            if (mi->query(md, cmd_s, cmd_z, USER_WARNING_ROW_WIDTH) < 0)
                db_error_fail(md);
            free(cmd_s); cmd_s = NULL; cmd_z = 0;
            if (md->row_count > 0) {
                int i1 = 0;
                for (int i2 = 0; i2 < md->row_count; ++i2) {
                    struct user_warning_internal uwi = {};
                    if (mi->next_row(md) < 0) db_error_fail(md);
                    if (mi->parse_spec(md, -1, md->row, md->lengths, USER_WARNING_ROW_WIDTH, user_warning_spec, &uwi) < 0) goto fail;
                    while (i1 < new_count && new_te[i1]->serial_id < uwi.serial_id) {
                        ++i1;
                    }
                    if (i1 < new_count && new_te[i1]->serial_id == uwi.serial_id) {
                        struct team_extra *te = new_te[i1];
                        if (te->warn_u == te->warn_a) {
                            if (!(te->warn_a *= 2)) te->warn_a = 4;
                            XREALLOC(te->warns, te->warn_a);
                        }
                        struct team_warning *tw = NULL;
                        XCALLOC(tw, 1);
                        te->warns[te->warn_u++] = tw;
                        tw->serial_id = uwi.serial_id;
                        tw->date = uwi.issue_date;
                        tw->issuer_id = uwi.issuer_id;
                        tw->issuer_ip = uwi.issuer_ip;
                        tw->text = uwi.user_text; uwi.user_text = NULL;
                        tw->comment = uwi.judge_text; uwi.judge_text = NULL;
                    }
                }
            }
            qsort(new_te, new_count, sizeof(new_te[0]), team_extra_user_sort_func);

            {
                int new_a = 1;
                while (new_a < xmcs->extra_u + new_count) {
                    new_a *= 2;
                }
                struct team_extra **new_x = xmalloc(new_a * sizeof(new_x[0]));
                int i1 = 0, i2 = 0, i3 = 0;
                while (i2 < xmcs->extra_u && i3 < new_count) {
                    if (xmcs->extras[i2]->user_id < new_te[i3]->user_id) {
                        new_x[i1++] = xmcs->extras[i2++];
                    } else if (xmcs->extras[i2]->user_id < new_te[i3]->user_id) {
                        new_x[i1++] = new_te[i3++];
                    } else {
                        abort();
                    }
                }
                while (i2 < xmcs->extra_u) {
                    new_x[i1++] = xmcs->extras[i2++];
                }
                while (i3 < new_count) {
                    new_x[i1++] = new_te[i3++];
                }
                free(xmcs->extras);
                xmcs->extras = new_x;
                xmcs->extra_a = new_a;
                xmcs->extra_u = i3;
            }
        }
    }

    free(new_te);
    free(fetch_ids);
    free(local_ids);
    return &xmte->b;

fail:
    if (new_te) {
        for (int i = 0; i < new_count; ++i) {
            team_extra_free(new_te[i]);
        }
        xfree(new_te);
    }
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    free(fetch_ids);
    free(local_ids);
    if (xmte) xmte->b.free(&xmte->b);
    return NULL;
}

static int
set_problem_dir_prefix_func(
        struct xuser_cnts_state *data,
        int user_id,
        const unsigned char *problem_dir_prefix)
{
    struct xuser_mysql_cnts_state *xmcs = (struct xuser_mysql_cnts_state *) data;
    struct common_mysql_iface *mi = xmcs->xms->mi;
    struct common_mysql_state *md = xmcs->xms->md;
    FILE *cmd_f = NULL;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    struct team_extra *te = fetch_or_create_user(xmcs, user_id);
    if (!te) goto fail;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "UPDATE %suserextras SET problem_dir_prefix = ", md->table_prefix);
    mi->write_escaped_string(md, cmd_f, NULL, problem_dir_prefix);
    fprintf(cmd_f, ", last_update_time = NOW(6) WHERE serial_id = %d;",
            te->serial_id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    xfree(te->problem_dir_prefix);
    te->problem_dir_prefix = xstrdup(problem_dir_prefix);

    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    if (cmd_s) free(cmd_s);
    return -1;
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
