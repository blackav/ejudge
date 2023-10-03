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

#include "mysql_conn.h"
#include "telegram_pbs.h"
#include "telegram_token.h"
#include "telegram_chat.h"
#include "telegram_user.h"
#include "telegram_chat_state.h"
#include "telegram_subscription.h"

#include "ejudge/common_plugin.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#include <stdio.h>

#define TELEGRAM_DB_VERSION 5

static struct generic_conn *
free_func(struct generic_conn *gc)
{
    if (gc) {
        struct mysql_conn *conn = (struct mysql_conn *) gc;
        free(conn->b.database);
        free(conn->b.host);
        free(conn->b.table_prefix);
        free(conn->b.user);
        free(conn->b.password);
        free(conn);
    }
    return NULL;
}

static int
prepare_func(
        struct generic_conn *gc,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    struct mysql_conn *conn = (struct mysql_conn *) gc;
    const struct common_loaded_plugin *mplg;

    // load common_mysql plugin
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }
    conn->mi = (struct common_mysql_iface*) mplg->iface;
    conn->md = (struct common_mysql_state*) mplg->data;

    return 0;
}

static const char create_query_1[] =
"CREATE TABLE %stelegram_bots (\n"
"    id CHAR(64) NOT NULL PRIMARY KEY,\n"
"    update_id BIGINT NOT NULL DEFAULT 0\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static const char create_query_2[] =
"CREATE TABLE %stelegram_tokens (\n"
"    id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    bot_id CHAR(64) NOT NULL,\n"
"    user_id INT UNSIGNED NOT NULL,\n"
"    user_login VARCHAR(64) DEFAULT NULL,\n"
"    user_name VARCHAR(512) DEFAULT NULL,\n"
"    token CHAR(64) NOT NULL,\n"
"    contest_id INT NOT NULL DEFAULT 0,\n"
"    contest_name VARCHAR(512) DEFAULT NULL,\n"
"    locale_id INT NOT NULL DEFAULT 0,\n"
"    expiry_time DATETIME NOT NULL,\n"
"    KEY tt_bot_id_k(bot_id),\n"
"    KEY tt_contest_id_k(contest_id),\n"
"    KEY tt_contest_user_k(contest_id,user_id),\n"
"    UNIQUE KEY tt_token_k(token),\n"
"    FOREIGN KEY tt_user_id_fk(user_id) REFERENCES %slogins(user_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static const char create_query_3[] =
"CREATE TABLE %stelegram_users (\n"
"    id BIGINT NOT NULL PRIMARY KEY,\n"
"    username VARCHAR(512) DEFAULT NULL,\n"
"    first_name VARCHAR(512) DEFAULT NULL,\n"
"    last_name VARCHAR(512) DEFAULT NULL\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static const char create_query_4[] =
"CREATE TABLE %stelegram_chats (\n"
"    id BIGINT NOT NULL PRIMARY KEY,\n"
"    chat_type VARCHAR(64) DEFAULT NULL,\n"
"    title VARCHAR(512) DEFAULT NULL,\n"
"    username VARCHAR(512) DEFAULT NULL,\n"
"    first_name VARCHAR(512) DEFAULT NULL,\n"
"    last_name VARCHAR(512) DEFAULT NULL\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static const char create_query_5[] =
"CREATE TABLE %stelegram_chat_states (\n"
"    id BIGINT NOT NULL PRIMARY KEY,\n"
"    command VARCHAR(64) DEFAULT NULL,\n"
"    token VARCHAR(64) DEFAULT NULL,\n"
"    state INT NOT NULL DEFAULT 0,\n"
"    review_flag INT NOT NULL DEFAULT 0,\n"
"    reply_flag INT NOT NULL DEFAULT 0\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static const char create_query_6[] =
"CREATE TABLE %stelegram_subscriptions (\n"
"    id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    bot_id CHAR(64) NOT NULL,\n"
"    user_id INT UNSIGNED NOT NULL,\n"
"    contest_id INT NOT NULL DEFAULT 0,\n"
"    review_flag INT NOT NULL DEFAULT 0,\n"
"    reply_flag INT NOT NULL DEFAULT 0,\n"
"    chat_id BIGINT NOT NULL DEFAULT 0,\n"
"    KEY ts_bot_id_k(bot_id),\n"
"    KEY ts_contest_id_k(contest_id),\n"
"    UNIQUE KEY ts_unique_k(bot_id,user_id,contest_id),\n"
"    FOREIGN KEY ts_user_id_fk(user_id) REFERENCES %slogins(user_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static const char create_query_7[] =
"CREATE TABLE %stelegram_registrations (\n"
"    reg_key CHAR(32) NOT NULL PRIMARY KEY,\n"
"    chat_id BIGINT NOT NULL,\n"
"    contest_id INT NOT NULL DEFAULT 0,\n"
"    create_time DATETIME(6) NOT NULL\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static int
create_database(
        struct mysql_conn *conn)
{
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;

    mi->lock(md);
    if (mi->simple_fquery(md, create_query_1,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_2,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_3,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_4,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_5,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_6,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, create_query_7,
                          md->table_prefix) < 0)
        db_error_fail(md);

    if (mi->simple_fquery(md, "INSERT INTO %sconfig VALUES ('telegram_version', '%d') ;", md->table_prefix, TELEGRAM_DB_VERSION) < 0)
        db_error_fail(md);

    mi->unlock(md);

    return 0;

fail:
    mi->unlock(md);
    return -1;
}

static int
check_database(
        struct mysql_conn *conn)
{
    int telegram_version = 0;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;

    mi->lock(md);

    if (mi->connect(md) < 0)
        goto fail;

    if (mi->fquery(md, 1, "SELECT config_val FROM %sconfig WHERE config_key = 'telegram_version' ;", md->table_prefix) < 0) {
        err("probably the database is not created, please, create it");
        goto fail;
    }
    if (md->row_count > 1) abort();
    if (!md->row_count) {
        mi->unlock(md);
        return create_database(conn);
    }
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (!md->row[0] || mi->parse_int(md, md->row[0], &telegram_version) < 0)
        db_error_inv_value_fail(md, "config_val");
    mi->free_res(md);

    if (telegram_version < 1) {
        err("telegram_version == %d is not supported", telegram_version);
        goto fail;
    }

    while (telegram_version >= 0) {
        switch (telegram_version) {
        case 1:
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_bots MODIFY COLUMN update_id BIGINT NOT NULL DEFAULT 0 ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_tokens MODIFY COLUMN id INT(18) NOT NULL ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_tokens DROP PRIMARY KEY ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_tokens MODIFY COLUMN id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_users DROP PRIMARY KEY ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_users MODIFY COLUMN id BIGINT NOT NULL PRIMARY KEY ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_chats DROP PRIMARY KEY ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_chats MODIFY COLUMN id BIGINT NOT NULL PRIMARY KEY ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_chat_states DROP PRIMARY KEY ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_chat_states MODIFY COLUMN id BIGINT NOT NULL PRIMARY KEY ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_subscriptions MODIFY COLUMN id INT(18) NOT NULL ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_subscriptions DROP PRIMARY KEY ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_subscriptions MODIFY COLUMN id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_subscriptions MODIFY COLUMN chat_id BIGINT NOT NULL DEFAULT 0 ;", md->table_prefix) < 0)
                return -1;
            break;
        case 2:
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_bots DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_tokens DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_users DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_chats DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_chat_states DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_subscriptions DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;", md->table_prefix) < 0)
                return -1;
            break;
        case 3:
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_bots MODIFY COLUMN  id CHAR(64) NOT NULL;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_tokens MODIFY COLUMN bot_id CHAR(64) NOT NULL, MODIFY COLUMN user_login VARCHAR(64) DEFAULT NULL, MODIFY COLUMN user_name VARCHAR(512) DEFAULT NULL, MODIFY COLUMN token CHAR(64) NOT NULL, MODIFY COLUMN contest_name VARCHAR(512) DEFAULT NULL ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_users MODIFY COLUMN username VARCHAR(512) DEFAULT NULL, MODIFY COLUMN first_name VARCHAR(512) DEFAULT NULL, MODIFY COLUMN last_name VARCHAR(512) DEFAULT NULL ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_chats MODIFY COLUMN chat_type VARCHAR(64) DEFAULT NULL, MODIFY COLUMN title VARCHAR(512) DEFAULT NULL, MODIFY COLUMN username VARCHAR(512) DEFAULT NULL, MODIFY COLUMN first_name VARCHAR(512) DEFAULT NULL, MODIFY COLUMN last_name VARCHAR(512) DEFAULT NULL ;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_chat_states MODIFY COLUMN  command VARCHAR(64) DEFAULT NULL, MODIFY COLUMN token VARCHAR(64) DEFAULT NULL;", md->table_prefix) < 0)
                return -1;
            if (mi->simple_fquery(md, "ALTER TABLE %stelegram_subscriptions MODIFY COLUMN bot_id CHAR(64) NOT NULL ;", md->table_prefix) < 0)
                return -1;
            break;
        case 4:
            if (mi->simple_fquery(md, create_query_7,
                                  md->table_prefix) < 0) {
                return -1;
            }
            break;
        default:
            telegram_version = -1;
            break;
        }
        if (telegram_version >= 0) {
            ++telegram_version;
            if (mi->simple_fquery(md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'telegram_version' ;", md->table_prefix, telegram_version) < 0)
                goto fail;
        }
    }

    mi->unlock(md);
    return 0;

fail:
    mi->unlock(md);
    return -1;
}

static int
open_func(struct generic_conn *gc)
{
    struct mysql_conn *conn = (struct mysql_conn *) gc;

    if (!conn->is_db_checked) {
        if (check_database(conn) < 0) {
            return -1;
        }
        conn->is_db_checked = 1;
    }

    return 0;
}

struct telegram_pbs_internal
{
    unsigned char *id;
    long long update_id;
};
enum { TELEGRAM_PBS_ROW_WIDTH = 2 };
#define TELEGRAM_PBS_OFFSET(f) XOFFSET(struct telegram_pbs_internal, f)
static const struct common_mysql_parse_spec telegram_pbs_spec[TELEGRAM_PBS_ROW_WIDTH] =
{
    { 1, 's', "id", TELEGRAM_PBS_OFFSET(id), 0 },
    { 0, 'l', "update_id", TELEGRAM_PBS_OFFSET(update_id), 0 },
};

static struct telegram_pbs *
pbs_fetch_func(
        struct generic_conn *gc,
        const unsigned char *bot_id)
{
    if (gc->vt->open(gc) < 0) return NULL;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_pbs_internal tpi = {};
    struct telegram_pbs *tp = NULL;

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %stelegram_bots WHERE id = ",
            md->table_prefix);
    mi->write_escaped_string(md, cmd_f, NULL, bot_id);
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, TELEGRAM_PBS_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count > 0) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, TELEGRAM_PBS_ROW_WIDTH, telegram_pbs_spec, &tpi) < 0) goto fail;
        XCALLOC(tp, 1);
        tp->_id = tpi.id; tpi.id = NULL;
        tp->update_id = tpi.update_id;
        mi->unlock(md);
        return tp;
    }

    tp = telegram_pbs_create(bot_id);
    mi->unlock(md);
    gc->vt->pbs_save(gc, tp);

    return tp;

fail:
    telegram_pbs_free(tp);
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    free(tpi.id);
    mi->unlock(md);
    return NULL;
}

static int
pbs_save_func(
        struct generic_conn *gc,
        const struct telegram_pbs *pbs)
{
    if (gc->vt->open(gc) < 0) return -1;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_pbs_internal tpi = {};

    mi->lock(md);
    tpi.id = pbs->_id;
    tpi.update_id = pbs->update_id;
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %stelegram_bots SET ", md->table_prefix);
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_PBS_ROW_WIDTH,
                       telegram_pbs_spec, 0, &tpi);
    fprintf(cmd_f, " ON DUPLICATE KEY UPDATE ");
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_PBS_ROW_WIDTH,
                       telegram_pbs_spec, 1ULL, &tpi);
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    mi->unlock(md);
    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return -1;
}

struct telegram_token_internal
{
    long long id;
    unsigned char *bot_id;
    int user_id;
    unsigned char *user_login;
    unsigned char *user_name;
    unsigned char *token;
    int contest_id;
    unsigned char *contest_name;
    int locale_id;
    time_t expiry_time;
};
enum { TELEGRAM_TOKEN_ROW_WIDTH = 10 };
#define TELEGRAM_TOKEN_OFFSET(f) XOFFSET(struct telegram_token_internal, f)
static const struct common_mysql_parse_spec telegram_token_spec[TELEGRAM_TOKEN_ROW_WIDTH] =
{
    { 0, 'l', "id", TELEGRAM_TOKEN_OFFSET(id), 0 },
    { 1, 's', "bot_id", TELEGRAM_TOKEN_OFFSET(bot_id), 0 },
    { 0, 'd', "user_id", TELEGRAM_TOKEN_OFFSET(user_id), 0 },
    { 1, 's', "user_login", TELEGRAM_TOKEN_OFFSET(user_login), 0 },
    { 1, 's', "user_name", TELEGRAM_TOKEN_OFFSET(user_name), 0 },
    { 1, 's', "token", TELEGRAM_TOKEN_OFFSET(token), 0 },
    { 0, 'd', "contest_id", TELEGRAM_TOKEN_OFFSET(contest_id), 0 },
    { 1, 's', "contest_name", TELEGRAM_TOKEN_OFFSET(contest_name), 0 },
    { 0, 'd', "locale_id", TELEGRAM_TOKEN_OFFSET(locale_id), 0 },
    { 1, 't', "expiry_time", TELEGRAM_TOKEN_OFFSET(expiry_time), 0 },
};

static int
token_fetch_func(
        struct generic_conn *gc,
        const unsigned char *token_str,
        struct telegram_token **p_token)
{
    if (gc->vt->open(gc) < 0) return -1;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_token_internal tti = {};
    struct telegram_token *tt = NULL;

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %stelegram_tokens WHERE token = ",
            md->table_prefix);
    mi->write_escaped_string(md, cmd_f, NULL, token_str);
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, TELEGRAM_TOKEN_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count == 1) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, TELEGRAM_TOKEN_ROW_WIDTH, telegram_token_spec, &tti) < 0) goto fail;
        XCALLOC(tt, 1);
        tt->bot_id = tti.bot_id; tti.bot_id = NULL;
        tt->user_id = tti.user_id;
        tt->user_login = tti.user_login; tti.user_login = NULL;
        tt->user_name = tti.user_name; tti.user_name = NULL;
        tt->token = tti.token; tti.token = NULL;
        tt->contest_id = tti.contest_id;
        tt->contest_name = tti.contest_name; tti.contest_name = NULL;
        tt->locale_id = tti.locale_id;
        tt->expiry_time = tti.expiry_time;
        *p_token = tt;
        mi->unlock(md);
        return 1;
    }

    mi->unlock(md);
    return 0;

fail:
    telegram_token_free(tt);
    free(tti.bot_id);
    free(tti.user_login);
    free(tti.user_name);
    free(tti.token);
    free(tti.contest_name);
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return -1;
}

static int
token_save_func(
        struct generic_conn *gc,
        const struct telegram_token *token)
{
    if (gc->vt->open(gc) < 0) return -1;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_token_internal tti = {};

    mi->lock(md);
    tti.bot_id = token->bot_id;
    tti.user_id = token->user_id;
    tti.user_login = token->user_login;
    tti.user_name = token->user_name;
    tti.token = token->token;
    tti.contest_id = token->contest_id;
    tti.contest_name = token->contest_name;
    tti.locale_id = token->locale_id;
    tti.expiry_time = token->expiry_time;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %stelegram_tokens VALUES (DEFAULT,",
            md->table_prefix);
    mi->unparse_spec_2(md, cmd_f, TELEGRAM_TOKEN_ROW_WIDTH,
                       telegram_token_spec, 1ULL, &tti);
    fprintf(cmd_f, ");");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    mi->unlock(md);
    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return -1;
}

static void
token_remove_func(
        struct generic_conn *gc,
        const unsigned char *token)
{
    if (gc->vt->open(gc) < 0) return;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "DELETE FROM %stelegram_tokens WHERE token = ",
            md->table_prefix);
    mi->write_escaped_string(md, cmd_f, NULL, token);
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    mi->unlock(md);
    return;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
}

static void
token_remove_expired_func(
        struct generic_conn *gc,
        time_t current_time)
{
    if (gc->vt->open(gc) < 0) return;

    if (current_time <= 0) current_time = time(NULL);

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "DELETE FROM %stelegram_tokens WHERE expiry_time < ",
            md->table_prefix);
    mi->write_timestamp(md, cmd_f, NULL, current_time);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    mi->unlock(md);
    return;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
}

struct telegram_chat_internal
{
    long long id;
    unsigned char *type;
    unsigned char *title;
    unsigned char *username;
    unsigned char *first_name;
    unsigned char *last_name;
};
enum { TELEGRAM_CHAT_ROW_WIDTH = 6 };
#define TELEGRAM_CHAT_OFFSET(f) XOFFSET(struct telegram_chat_internal, f)
static const struct common_mysql_parse_spec telegram_chat_spec[TELEGRAM_CHAT_ROW_WIDTH] =
{
    { 0, 'l', "id", TELEGRAM_CHAT_OFFSET(id), 0 },
    { 1, 's', "chat_type", TELEGRAM_CHAT_OFFSET(type), 0 },
    { 1, 's', "title", TELEGRAM_CHAT_OFFSET(title), 0 },
    { 1, 's', "username", TELEGRAM_CHAT_OFFSET(username), 0 },
    { 1, 's', "first_name", TELEGRAM_CHAT_OFFSET(first_name), 0 },
    { 1, 's', "last_name", TELEGRAM_CHAT_OFFSET(last_name), 0 },
};

static struct telegram_chat *
chat_fetch_func(
        struct generic_conn *gc,
        long long _id)
{
    if (gc->vt->open(gc) < 0) return NULL;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_chat_internal tci = {};
    struct telegram_chat *tc = NULL;

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %stelegram_chats WHERE id = %lld;",
            md->table_prefix, _id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, TELEGRAM_CHAT_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count > 0) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, TELEGRAM_CHAT_ROW_WIDTH, telegram_chat_spec, &tci) < 0) goto fail;
        XCALLOC(tc, 1);
        tc->_id = tci.id;
        tc->type = tci.type; tci.type = NULL;
        tc->title = tci.title; tci.title = NULL;
        tc->username = tci.username; tci.username = NULL;
        tc->first_name = tci.first_name; tci.first_name = NULL;
        tc->last_name = tci.last_name; tci.last_name = NULL;
        mi->unlock(md);
        return tc;
    }

    tc = telegram_chat_create();
    tc->_id = _id;
    mi->unlock(md);
    gc->vt->chat_save(gc, tc);
    return tc;

fail:
    free(tci.type);
    free(tci.title);
    free(tci.username);
    free(tci.first_name);
    free(tci.last_name);
    telegram_chat_free(tc);
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return NULL;
}

static int
chat_save_func(
        struct generic_conn *gc,
        const struct telegram_chat *tc)
{
    if (gc->vt->open(gc) < 0) return -1;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_chat_internal tci = {};

    mi->lock(md);
    tci.id = tc->_id;
    tci.type = tc->type;
    tci.title = tc->title;
    tci.username = tc->username;
    tci.first_name = tc->first_name;
    tci.last_name = tc->last_name;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %stelegram_chats SET ", md->table_prefix);
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_CHAT_ROW_WIDTH,
                       telegram_chat_spec, 0, &tci);
    fprintf(cmd_f, " ON DUPLICATE KEY UPDATE ");
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_CHAT_ROW_WIDTH,
                       telegram_chat_spec, 1ULL, &tci);
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    mi->unlock(md);
    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return -1;
}

struct telegram_user_internal
{
    long long id;
    unsigned char *username;
    unsigned char *first_name;
    unsigned char *last_name;
};
enum { TELEGRAM_USER_ROW_WIDTH = 4 };
#define TELEGRAM_USER_OFFSET(f) XOFFSET(struct telegram_user_internal, f)
static const struct common_mysql_parse_spec telegram_user_spec[TELEGRAM_USER_ROW_WIDTH] =
{
    { 0, 'l', "id", TELEGRAM_USER_OFFSET(id), 0 },
    { 1, 's', "username", TELEGRAM_USER_OFFSET(username), 0 },
    { 1, 's', "first_name", TELEGRAM_USER_OFFSET(first_name), 0 },
    { 1, 's', "last_name", TELEGRAM_USER_OFFSET(last_name), 0 },
};

static struct telegram_user *
user_fetch_func(
        struct generic_conn *gc,
        long long _id)
{
    if (gc->vt->open(gc) < 0) return NULL;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_user_internal tui = {};
    struct telegram_user *tu = NULL;

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %stelegram_users WHERE id = %lld;",
            md->table_prefix, _id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, TELEGRAM_USER_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count > 0) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, TELEGRAM_USER_ROW_WIDTH, telegram_user_spec, &tui) < 0) goto fail;
        XCALLOC(tu, 1);
        tu->_id = tui.id;
        tu->username = tui.username; tui.username = NULL;
        tu->first_name = tui.first_name; tui.first_name = NULL;
        tu->last_name = tui.last_name; tui.last_name = NULL;
        mi->unlock(md);
        return tu;
    }

    tu = telegram_user_create();
    tu->_id = _id;
    mi->unlock(md);
    gc->vt->user_save(gc, tu);
    return tu;

fail:
    free(tui.username);
    free(tui.first_name);
    free(tui.last_name);
    telegram_user_free(tu);
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return NULL;
}

static int
user_save_func(
        struct generic_conn *gc,
        const struct telegram_user *tu)
{
    if (gc->vt->open(gc) < 0) return -1;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_user_internal tui = {};

    mi->lock(md);
    tui.id = tu->_id;
    tui.username = tu->username;
    tui.first_name = tu->first_name;
    tui.last_name = tu->last_name;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %stelegram_users SET ", md->table_prefix);
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_USER_ROW_WIDTH,
                       telegram_user_spec, 0, &tui);
    fprintf(cmd_f, " ON DUPLICATE KEY UPDATE ");
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_USER_ROW_WIDTH,
                       telegram_user_spec, 1ULL, &tui);
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    mi->unlock(md);
    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return -1;
}

struct telegram_chat_state_internal
{
    long long id;
    unsigned char *command;
    unsigned char *token;
    int state;
    int review_flag;
    int reply_flag;
};
enum { TELEGRAM_CHAT_STATE_ROW_WIDTH = 6 };
#define TELEGRAM_CHAT_STATE_OFFSET(f) XOFFSET(struct telegram_chat_state_internal, f)
static const struct common_mysql_parse_spec telegram_chat_state_spec[TELEGRAM_CHAT_STATE_ROW_WIDTH] =
{
    { 0, 'l', "id", TELEGRAM_CHAT_STATE_OFFSET(id), 0 },
    { 1, 's', "command", TELEGRAM_CHAT_STATE_OFFSET(command), 0 },
    { 1, 's', "token", TELEGRAM_CHAT_STATE_OFFSET(token), 0 },
    { 0, 'd', "state", TELEGRAM_CHAT_STATE_OFFSET(state), 0 },
    { 0, 'd', "review_flag", TELEGRAM_CHAT_STATE_OFFSET(review_flag), 0 },
    { 0, 'd', "reply_flag", TELEGRAM_CHAT_STATE_OFFSET(reply_flag), 0 },
};

static struct telegram_chat_state *
chat_state_fetch_func(
        struct generic_conn *gc,
        long long _id)
{
    if (gc->vt->open(gc) < 0) return NULL;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_chat_state_internal tcsi = {};
    struct telegram_chat_state *tcs = NULL;

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %stelegram_chat_states WHERE id = %lld;",
            md->table_prefix, _id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, TELEGRAM_CHAT_STATE_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count > 0) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, TELEGRAM_CHAT_STATE_ROW_WIDTH, telegram_chat_state_spec, &tcsi) < 0) goto fail;
        XCALLOC(tcs, 1);
        tcs->_id = tcsi.id;
        tcs->command = tcsi.command; tcsi.command = NULL;
        tcs->token = tcsi.token; tcsi.token = NULL;
        tcs->state = tcsi.state;
        tcs->review_flag = tcsi.review_flag;
        tcs->reply_flag = tcsi.reply_flag;
        mi->unlock(md);
        return tcs;
    }

    tcs = telegram_chat_state_create();
    tcs->_id = _id;
    mi->unlock(md);
    gc->vt->chat_state_save(gc, tcs);
    return tcs;

fail:
    free(tcsi.command);
    free(tcsi.token);
    telegram_chat_state_free(tcs);
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return NULL;
}

static int
chat_state_save_func(
        struct generic_conn *gc,
        const struct telegram_chat_state *tcs)
{
    if (gc->vt->open(gc) < 0) return -1;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_chat_state_internal tcsi = {};

    mi->lock(md);
    tcsi.id = tcs->_id;
    tcsi.command = tcs->command;
    tcsi.token = tcs->token;
    tcsi.state = tcs->state;
    tcsi.review_flag = tcs->review_flag;
    tcsi.reply_flag = tcs->reply_flag;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %stelegram_chat_states SET ", md->table_prefix);
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_CHAT_STATE_ROW_WIDTH,
                       telegram_chat_state_spec, 0, &tcsi);
    fprintf(cmd_f, " ON DUPLICATE KEY UPDATE ");
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_CHAT_STATE_ROW_WIDTH,
                       telegram_chat_state_spec, 1ULL, &tcsi);
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    mi->unlock(md);
    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return -1;
}

struct telegram_subscription_internal
{
    long long id;
    unsigned char *bot_id;
    int user_id;
    int contest_id;
    int review_flag;
    int reply_flag;
    long long chat_id;
};
enum { TELEGRAM_SUBSCRIPTION_ROW_WIDTH = 7 };
#define TELEGRAM_SUBSCRIPTION_OFFSET(f) XOFFSET(struct telegram_subscription_internal, f)
static const struct common_mysql_parse_spec telegram_subscription_spec[TELEGRAM_SUBSCRIPTION_ROW_WIDTH] =
{
    { 0, 'l', "id", TELEGRAM_SUBSCRIPTION_OFFSET(id), 0 },
    { 1, 's', "bot_id", TELEGRAM_SUBSCRIPTION_OFFSET(bot_id), 0 },
    { 0, 'd', "user_id", TELEGRAM_SUBSCRIPTION_OFFSET(user_id), 0 },
    { 0, 'd', "contest_id", TELEGRAM_SUBSCRIPTION_OFFSET(contest_id), 0 },
    { 0, 'd', "review_flag", TELEGRAM_SUBSCRIPTION_OFFSET(review_flag), 0 },
    { 0, 'd', "reply_flag", TELEGRAM_SUBSCRIPTION_OFFSET(reply_flag), 0 },
    { 0, 'l', "chat_id", TELEGRAM_SUBSCRIPTION_OFFSET(chat_id), 0 },
};

static struct telegram_subscription *
subscription_fetch_func(
        struct generic_conn *gc,
        const unsigned char *bot_id,
        int user_id,
        int contest_id)
{
    if (gc->vt->open(gc) < 0) return NULL;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_subscription_internal tsi = {};
    struct telegram_subscription *ts = NULL;

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %stelegram_subscriptions WHERE bot_id = ",
            md->table_prefix);
    mi->write_escaped_string(md, cmd_f, NULL, bot_id);
    fprintf(cmd_f, " AND user_id = %d AND contest_id = %d;",
            user_id, contest_id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, TELEGRAM_SUBSCRIPTION_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    if (md->row_count > 0) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, TELEGRAM_SUBSCRIPTION_ROW_WIDTH, telegram_subscription_spec, &tsi) < 0) goto fail;
        XCALLOC(ts, 1);
        ts->bot_id = tsi.bot_id; tsi.bot_id = NULL;
        ts->user_id = tsi.user_id;
        ts->contest_id = tsi.contest_id;
        ts->review_flag = tsi.review_flag;
        ts->reply_flag = tsi.reply_flag;
        ts->chat_id = tsi.chat_id;
        mi->unlock(md);
        return ts;
    }

    ts = telegram_subscription_create(bot_id, user_id, contest_id);
    mi->unlock(md);
    gc->vt->subscription_save(gc, ts);
    return ts;

fail:
    free(tsi.bot_id);
    telegram_subscription_free(ts);
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return NULL;
}

static int
subscription_save_func(
        struct generic_conn *gc,
        const struct telegram_subscription *ts)
{
    if (gc->vt->open(gc) < 0) return -1;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct telegram_subscription_internal tsi = {};

    mi->lock(md);
    tsi.bot_id = ts->bot_id;
    tsi.user_id = ts->user_id;
    tsi.contest_id = ts->contest_id;
    tsi.review_flag = ts->review_flag;
    tsi.reply_flag = ts->reply_flag;
    tsi.chat_id = ts->chat_id;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %stelegram_subscriptions SET ", md->table_prefix);
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_SUBSCRIPTION_ROW_WIDTH,
                       telegram_subscription_spec, 1ULL, &tsi);
    fprintf(cmd_f, " ON DUPLICATE KEY UPDATE ");
    mi->unparse_spec_3(md, cmd_f, TELEGRAM_SUBSCRIPTION_ROW_WIDTH,
                       telegram_subscription_spec, 15ULL, &tsi);
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    mi->unlock(md);
    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return -1;
}

struct grouptocontest_internal
{
    unsigned char *group_id;
    int contest_id;
};
enum { GROUPTOCONTEST_ROW_WIDTH = 2 };
#define GROUPTOCONTEST_OFFSET(f) XOFFSET(struct grouptocontest_internal, f)
static const struct common_mysql_parse_spec grouptocontest_spec[GROUPTOCONTEST_ROW_WIDTH] =
{
    { 1, 's', "group_id", GROUPTOCONTEST_OFFSET(group_id), 0 },
    { 0, 'd', "contest_id", GROUPTOCONTEST_OFFSET(contest_id), 0 },
};

struct userpassword_internal
{
    int user_id;
    unsigned char *login;
    int pwdmethod;
    unsigned char *password;
    int contest_id;
    int status;
    int banned;
    int invisible;
    int locked;
    int disqualified;
    int privileged;
};
enum { USERPASSWORD_ROW_WIDTH = 11 };
#define USERPASSWORD_OFFSET(f) XOFFSET(struct userpassword_internal, f)
static const struct common_mysql_parse_spec userpassword_spec[USERPASSWORD_ROW_WIDTH] =
{
    { 0, 'd', "user_id", USERPASSWORD_OFFSET(user_id), 0 },
    { 1, 's', "login", USERPASSWORD_OFFSET(login), 0 },
    { 0, 'd', "pwdmethod", USERPASSWORD_OFFSET(pwdmethod), 0 },
    { 1, 's', "password", USERPASSWORD_OFFSET(password), 0 },
    { 0, 'd', "contest_id", USERPASSWORD_OFFSET(contest_id), 0 },
    { 0, 'd', "status", USERPASSWORD_OFFSET(status), 0 },
    { 0, 'd', "banned", USERPASSWORD_OFFSET(banned), 0 },
    { 0, 'd', "invisible", USERPASSWORD_OFFSET(invisible), 0 },
    { 0, 'd', "locked", USERPASSWORD_OFFSET(locked), 0 },
    { 0, 'd', "disqualified", USERPASSWORD_OFFSET(disqualified), 0 },
    { 0, 'd', "privileged", USERPASSWORD_OFFSET(privileged), 0 },
};

static int
password_get_func(
        struct generic_conn *gc,
        const unsigned char *group_id,
        const unsigned char *student_id,
        unsigned char **login,
        unsigned char **password)
{
    if (gc->vt->open(gc) < 0) return -1;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct grouptocontest_internal gtci = {};
    unsigned char *in_login = NULL;
    struct userpassword_internal upi = {};

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %sgrouptocontests WHERE group_id = ", md->table_prefix);
    mi->write_escaped_string(md, cmd_f, NULL, group_id);
    fprintf(cmd_f, " ;");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, GROUPTOCONTEST_ROW_WIDTH) < 0) {
        db_error_fail(md);
    }
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count <= 0) {
        mi->unlock(md);
        return 0;
    }
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (mi->parse_spec(md, -1, md->row, md->lengths, GROUPTOCONTEST_ROW_WIDTH, grouptocontest_spec, &gtci) < 0) {
        goto fail;
    }
    free(gtci.group_id); gtci.group_id = NULL;
    mi->free_res(md);

    {
        char *s = NULL;
        asprintf(&s, "s%s", student_id);
        in_login = s;
    }

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT logins.user_id, logins.login, logins.pwdmethod, logins.password, cntsregs.contest_id, cntsregs.status, cntsregs.banned, cntsregs.invisible, cntsregs.locked, cntsregs.disqualified, cntsregs.privileged FROM logins LEFT JOIN cntsregs ON logins.user_id = cntsregs.user_id WHERE logins.login = ");
    mi->write_escaped_string(md, cmd_f, NULL, in_login);
    fprintf(cmd_f, " AND cntsregs.contest_id = %d;", gtci.contest_id);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, USERPASSWORD_ROW_WIDTH) < 0) {
        db_error_fail(md);
    }
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count <= 0) {
        free(in_login);
        mi->unlock(md);
        return 0;
    }
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (mi->parse_spec(md, -1, md->row, md->lengths, USERPASSWORD_ROW_WIDTH, userpassword_spec, &upi) < 0) {
        goto fail;
    }
    mi->free_res(md);
    free(in_login); in_login = NULL;

    if (upi.pwdmethod != 0 || upi.status != 0 || upi.banned != 0 || upi.invisible != 0 || upi.locked != 0 || upi.disqualified != 0 || upi.privileged != 0) {
        free(upi.login);
        free(upi.password);
        mi->unlock(md);
        return 0;
    }

    *login = upi.login; upi.login = NULL;
    *password = upi.password; upi.password = NULL;
    mi->unlock(md);
    return 1;

fail:;
    free(cmd_s);
    free(gtci.group_id);
    free(in_login);
    free(upi.login);
    free(upi.password);
    mi->unlock(md);
    return -1;
}

static int
registration_save_func(
        struct generic_conn *gc,
        const unsigned char *reg_key,
        long long chat_id,
        int contest_id)
{
    if (gc->vt->open(gc) < 0) return -1;

    struct mysql_conn *conn = (struct mysql_conn *) gc;
    struct common_mysql_iface *mi = conn->mi;
    struct common_mysql_state *md = conn->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;

    mi->lock(md);
    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %stelegram_registrations VALUES ( ",
            md->table_prefix);
    fprintf(cmd_f, "'%s', %lld, %d, NOW(6)", reg_key, chat_id, contest_id);
    fprintf(cmd_f, "); ");
    fclose(cmd_f); cmd_f = NULL;

    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "DELETE FROM %stelegram_registrations WHERE ADDDATE(create_time, INTERVAL 5 MINUTE) <= NOW(6);", md->table_prefix);
    fclose(cmd_f); cmd_f = NULL;

    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    mi->unlock(md);
    return 0;

fail:;
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    mi->unlock(md);
    return -1;
}

static struct generic_conn_iface mysql_iface =
{
    free_func,
    prepare_func,
    open_func,
    NULL,
    pbs_fetch_func,
    pbs_save_func,
    token_fetch_func,
    token_save_func,
    token_remove_func,
    token_remove_expired_func,
    chat_fetch_func,
    chat_save_func,
    user_fetch_func,
    user_save_func,
    chat_state_fetch_func,
    chat_state_save_func,
    subscription_fetch_func,
    subscription_save_func,
    password_get_func,
    registration_save_func,
};

struct generic_conn *
mysql_conn_create(void)
{
    struct mysql_conn *conn = NULL;
    XCALLOC(conn, 1);
    conn->b.vt = &mysql_iface;
    return &conn->b;
}
