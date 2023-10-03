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
#include "ejudge/avatar_plugin.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#define AVATAR_DB_VERSION 2

struct avatar_mysql_state
{
    struct avatar_plugin_data b;

    int nref;

    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;

    int is_db_checked;
};

static struct common_plugin_data *
init_func(void)
{
    struct avatar_mysql_state *state = NULL;
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
    struct avatar_mysql_state *xms = (struct avatar_mysql_state *) data;
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

static const char create_query[] =
"CREATE TABLE %savatarinfos (\n"
"    serial_id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    contest_id INT NOT NULL,\n"
"    user_id INT UNSIGNED NOT NULL,\n"
"    is_cropped TINYINT NOT NULL DEFAULT 0,\n"
"    is_temporary TINYINT NOT NULL DEFAULT 0,\n"
"    is_public TINYINT NOT NULL DEFAULT 0,\n"
"    mime_type INT NOT NULL DEFAULT 0,\n"
"    width INT NOT NULL DEFAULT 0,\n"
"    height INT NOT NULL DEFAULT 0,\n"
"    random_key CHAR(32) NOT NULL,\n"
"    create_time DATETIME NOT NULL,\n"
"    img_size INT NOT NULL DEFAULT 0,\n"
"    img_data MEDIUMBLOB DEFAULT NULL,\n"
"    FOREIGN KEY av_user_id_fk(user_id) REFERENCES %slogins(user_id),\n"
"    KEY av_contest_id_k(contest_id),\n"
"    UNIQUE KEY av_random_k(random_key),\n"
"    KEY av_avatar_k(contest_id,user_id)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n";

static int
create_database(struct avatar_mysql_state *ams)
{
    struct common_mysql_iface *mi = ams->mi;
    struct common_mysql_state *md = ams->md;

    if (mi->simple_fquery(md, create_query,
                          md->table_prefix,
                          md->table_prefix) < 0)
        db_error_fail(md);
    if (mi->simple_fquery(md, "INSERT INTO %sconfig VALUES ('avatar_version', '%d') ;", md->table_prefix, AVATAR_DB_VERSION) < 0)
        db_error_fail(md);
    return 0;

fail:
    return -1;
}

static int
check_database(struct avatar_mysql_state *ams)
{
    int avatar_version = 0;
    struct common_mysql_iface *mi = ams->mi;
    struct common_mysql_state *md = ams->md;

    if (mi->connect(md) < 0)
        return -1;

    if (mi->fquery(md, 1, "SELECT config_val FROM %sconfig WHERE config_key = 'avatar_version' ;", md->table_prefix) < 0) {
        err("probably the database is not created, please, create it");
        return -1;
    }
    if (md->row_count > 1) abort();
    if (!md->row_count) return create_database(ams);
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (!md->row[0] || mi->parse_int(md, md->row[0], &avatar_version) < 0)
        db_error_inv_value_fail(md, "config_val");
    mi->free_res(md);

    if (avatar_version < 1 || avatar_version > AVATAR_DB_VERSION) {
        err("avatar_version == %d is not supported", avatar_version);
        goto fail;
    }

    while (avatar_version >= 0) {
        switch (avatar_version) {
        case 1:
            if (mi->simple_fquery(md, "ALTER TABLE %savatarinfos ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ;", md->table_prefix) < 0)
                goto fail;
            if (mi->simple_fquery(md, "ALTER TABLE %savatarinfos MODIFY COLUMN random_key CHAR(32) NOT NULL ;", md->table_prefix) < 0)
                goto fail;
            break;
        case AVATAR_DB_VERSION:
            avatar_version = -1;
            break;
        }
        if (avatar_version >= 0) {
            ++avatar_version;
            if (mi->simple_fquery(md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'avatar_version' ;", md->table_prefix, avatar_version) < 0)
                return -1;
        }
    }

    return 0;

fail:
    return -1;
}

struct avatar_info_internal
{
    int serial_id;
    int contest_id;
    int user_id;
    int is_cropped;
    int is_temporary;
    int is_public;
    int mime_type;
    int width;
    int height;
    unsigned char *random_key;
    time_t create_time;
    int img_size;
    struct common_mysql_binary img_data;
};

enum { AVATAR_INFO_ROW_WIDTH = 13 };
#define AVATAR_INFO_OFFSET(f) XOFFSET(struct avatar_info_internal, f)
static const struct common_mysql_parse_spec avatar_info_spec[AVATAR_INFO_ROW_WIDTH] =
{
    { 0, 'd', "serial_id", AVATAR_INFO_OFFSET(serial_id), 0 },
    { 0, 'd', "contest_id", AVATAR_INFO_OFFSET(contest_id), 0 },
    { 0, 'd', "user_id", AVATAR_INFO_OFFSET(user_id), 0 },
    { 0, 'd', "is_cropped", AVATAR_INFO_OFFSET(is_cropped), 0 },
    { 0, 'd', "is_temporary", AVATAR_INFO_OFFSET(is_temporary), 0 },
    { 0, 'd', "is_public", AVATAR_INFO_OFFSET(is_public), 0 },
    { 0, 'd', "mime_type", AVATAR_INFO_OFFSET(mime_type), 0 },
    { 0, 'd', "width", AVATAR_INFO_OFFSET(width), 0 },
    { 0, 'd', "height", AVATAR_INFO_OFFSET(height), 0 },
    { 1, 's', "random_key", AVATAR_INFO_OFFSET(random_key), 0 },
    { 1, 't', "create_time", AVATAR_INFO_OFFSET(create_time), 0 },
    { 0, 'd', "img_size", AVATAR_INFO_OFFSET(img_size), 0 },
    { 1, 'x', "img_data", AVATAR_INFO_OFFSET(img_data), 0 },
};

static int
insert_func(
        struct avatar_plugin_data *data,
        int user_id,
        int contest_id,
        int is_cropped,
        int is_temporary,
        int is_public,
        int mime_type,
        int width,
        int height,
        const unsigned char *random_key,
        time_t create_time,
        const unsigned char *img_data,
        size_t img_size,
        unsigned char **p_id)
{
    struct avatar_mysql_state *ams = (struct avatar_mysql_state *) data;
    struct common_mysql_iface *mi = ams->mi;
    struct common_mysql_state *md = ams->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    int serial_id = 0;

    if (!ams->is_db_checked) {
        if (check_database(ams) < 0) {
            return -1;
        }
        ams->is_db_checked = 1;
    }

    struct avatar_info_internal aii = {};
    aii.user_id = user_id;
    aii.contest_id = contest_id;
    aii.is_cropped = is_cropped;
    aii.is_temporary = is_temporary;
    aii.is_public = is_public;
    aii.mime_type = mime_type;
    aii.width = width;
    aii.height = height;
    aii.random_key = (unsigned char *) random_key;
    aii.create_time = create_time;
    aii.img_size = img_size;
    aii.img_data.size = img_size;
    aii.img_data.data = (unsigned char *) img_data;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO %savatarinfos SET ",
            md->table_prefix);
    mi->unparse_spec_3(md, cmd_f, AVATAR_INFO_ROW_WIDTH,
                       avatar_info_spec, 1ULL,
                       &aii);
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query_bin(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    if (mi->fquery(md, 1, "SELECT LAST_INSERT_ID();") < 0) {
        goto fail;
    }
    if (md->row_count <= 0) {
        goto fail;
    }
    if (mi->next_row(md) < 0) {
        goto fail;
    }
    if (mi->parse_int(md, md->row[0], &serial_id) < 0) {
        goto fail;
    }
    mi->free_res(md);

    return 0;

fail:
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    return -1;
}

static int
fetch_by_key_func(
        struct avatar_plugin_data *data,
        const unsigned char *random_key,
        int omit_image,
        struct avatar_info_vector *result)
{
    struct avatar_mysql_state *ams = (struct avatar_mysql_state *) data;
    struct common_mysql_iface *mi = ams->mi;
    struct common_mysql_state *md = ams->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct avatar_info_internal aii = {};

    if (!ams->is_db_checked) {
        if (check_database(ams) < 0) {
            return -1;
        }
        ams->is_db_checked = 1;
    }

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %savatarinfos WHERE random_key = '",
            md->table_prefix);
    mi->escape_string(md, cmd_f, random_key);
    fprintf(cmd_f, "'");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, AVATAR_INFO_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count == 1) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, AVATAR_INFO_ROW_WIDTH, avatar_info_spec, &aii) < 0) goto fail;
        if (result->u >= result->a) {
            avatar_vector_expand(result);
        }
        struct avatar_info *ai = &result->v[result->u++];
        ai->user_id = aii.user_id;
        ai->contest_id = aii.contest_id;
        ai->is_cropped = aii.is_cropped;
        ai->is_temporary = aii.is_temporary;
        ai->is_public = aii.is_public;
        ai->mime_type = aii.mime_type;
        ai->width = aii.width;
        ai->height = aii.height;
        ai->random_key = aii.random_key; aii.random_key = NULL;
        ai->create_time = aii.create_time;
        ai->img_size = aii.img_size;
        ai->img_data = aii.img_data.data;
    }

    return 1;

fail:
    free(aii.random_key);
    free(aii.img_data.data);
    free(cmd_s);
    return -1;
}

static int
delete_by_key_func(
        struct avatar_plugin_data *data,
        const unsigned char *random_key)
{
    struct avatar_mysql_state *ams = (struct avatar_mysql_state *) data;
    struct common_mysql_iface *mi = ams->mi;
    struct common_mysql_state *md = ams->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;

    if (!ams->is_db_checked) {
        if (check_database(ams) < 0) {
            return -1;
        }
        ams->is_db_checked = 1;
    }

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "DELETE FROM %savatarinfos WHERE random_key = '",
            md->table_prefix);
    mi->escape_string(md, cmd_f, random_key);
    fprintf(cmd_f, "'");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    return 0;

fail:
    free(cmd_s);
    return -1;
}

struct av_telegram_registration_internal
{
    unsigned char *key;
    long long chat_id;
    int contest_id;
    struct timeval create_time;
};

enum { TELEGRAM_REGISTRATION_ROW_WIDTH = 4 };
#define TELEGRAM_REGISTRATION_OFFSET(f) XOFFSET(struct av_telegram_registration_internal, f)
static const struct common_mysql_parse_spec telegram_registration_spec[TELEGRAM_REGISTRATION_ROW_WIDTH] =
{
    { 1, 's', "reg_key", TELEGRAM_REGISTRATION_OFFSET(key), 0 },
    { 0, 'l', "chat_id", TELEGRAM_REGISTRATION_OFFSET(chat_id), 0 },
    { 0, 'd', "contest_id", TELEGRAM_REGISTRATION_OFFSET(contest_id), 0 },
    { 1, 'T', "create_time", TELEGRAM_REGISTRATION_OFFSET(create_time), 0 },
};

static int
get_telegram_registration_func(
        struct avatar_plugin_data *data,
        const unsigned char *key,
        struct av_telegram_registration *p_reg)
{
    struct avatar_mysql_state *ams = (struct avatar_mysql_state *) data;
    struct common_mysql_iface *mi = ams->mi;
    struct common_mysql_state *md = ams->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct av_telegram_registration_internal tri = {};

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %stelegram_registrations WHERE reg_key = '",
            md->table_prefix);
    mi->escape_string(md, cmd_f, key);
    fprintf(cmd_f, "'");
    fclose(cmd_f); cmd_f = NULL;

    if (mi->query(md, cmd_s, cmd_z, TELEGRAM_REGISTRATION_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    if (md->row_count <= 0) {
        return 0;
    }

    if (mi->next_row(md) < 0) db_error_fail(md);
    if (mi->parse_spec(md, -1, md->row, md->lengths, TELEGRAM_REGISTRATION_ROW_WIDTH, telegram_registration_spec, &tri) < 0) goto fail;

    p_reg->key = tri.key; tri.key = NULL;
    p_reg->chat_id = tri.chat_id;
    p_reg->contest_id = tri.contest_id;
    p_reg->create_time = tri.create_time;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "DELETE FROM %stelegram_registrations WHERE ADDDATE(create_time, INTERVAL 5 MINUTE) <= NOW(6) OR reg_key = '", md->table_prefix);
    mi->escape_string(md, cmd_f, key);
    fprintf(cmd_f, "'");
    fclose(cmd_f); cmd_f = NULL;

    __attribute__((unused)) int _;
    _ = mi->simple_query(md, cmd_s, cmd_z);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    return 1;

fail:;
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    free(tri.key);
    return -1;
}

struct av_telegram_chat_internal
{
    long long id;
    unsigned char *type;
    unsigned char *title;
    unsigned char *username;
    unsigned char *first_name;
    unsigned char *last_name;
};

enum { TELEGRAM_CHAT_ROW_WIDTH = 6 };
#define TELEGRAM_CHAT_OFFSET(f) XOFFSET(struct av_telegram_chat_internal, f)
static const struct common_mysql_parse_spec telegram_chat_spec[TELEGRAM_CHAT_ROW_WIDTH] =
{
    { 0, 'l', "id", TELEGRAM_CHAT_OFFSET(id), 0 },
    { 1, 's', "type", TELEGRAM_CHAT_OFFSET(type), 0 },
    { 1, 's', "title", TELEGRAM_CHAT_OFFSET(title), 0 },
    { 1, 's', "username", TELEGRAM_CHAT_OFFSET(username), 0 },
    { 1, 's', "first_name", TELEGRAM_CHAT_OFFSET(first_name), 0 },
    { 1, 's', "last_name", TELEGRAM_CHAT_OFFSET(last_name), 0 },
};

static int
get_telegram_chat_func(
        struct avatar_plugin_data *data,
        long long chat_id,
        struct av_telegram_chat *p_chat)
{
    struct avatar_mysql_state *ams = (struct avatar_mysql_state *) data;
    struct common_mysql_iface *mi = ams->mi;
    struct common_mysql_state *md = ams->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct av_telegram_chat_internal tci = {};

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM %stelegram_chats WHERE id = %lld ;",
            md->table_prefix, chat_id);
    fclose(cmd_f); cmd_f = NULL;

    if (mi->query(md, cmd_s, cmd_z, TELEGRAM_CHAT_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    if (md->row_count <= 0) {
        return 0;
    }

    if (mi->next_row(md) < 0) db_error_fail(md);
    if (mi->parse_spec(md, -1, md->row, md->lengths, TELEGRAM_CHAT_ROW_WIDTH, telegram_chat_spec, &tci) < 0) goto fail;

    p_chat->id = tci.id;
    p_chat->type = tci.type; tci.type = NULL;
    p_chat->title = tci.title; tci.title = NULL;
    p_chat->username = tci.username; tci.username = NULL;
    p_chat->first_name = tci.first_name; tci.first_name = NULL;
    p_chat->last_name = tci.last_name; tci.last_name = NULL;

    return 1;

fail:;
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    free(tci.type);
    free(tci.title);
    free(tci.username);
    free(tci.first_name);
    free(tci.last_name);
    return -1;
}

struct avatar_plugin_iface plugin_avatar_mysql =
{
    {
        {
            sizeof (struct avatar_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "avatar",
            "mysql",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    AVATAR_PLUGIN_IFACE_VERSION,
    insert_func,
    fetch_by_key_func,
    delete_by_key_func,
    get_telegram_registration_func,
    get_telegram_chat_func,
};
