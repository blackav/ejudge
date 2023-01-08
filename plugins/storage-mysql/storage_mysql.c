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
#include "ejudge/storage_plugin.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/random.h"
#include "ejudge/base64.h"
#include "ejudge/sha256utils.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#define STORAGE_DB_VERSION 1

struct storage_mysql_data
{
    struct storage_plugin_data b;

    int nref;

    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;

    int is_db_checked;
};

extern struct storage_plugin_iface plugin_storage_mysql;

static struct common_plugin_data *
init_func(void)
{
    struct storage_mysql_data *state = NULL;
    XCALLOC(state, 1);
    state->b.vt = &plugin_storage_mysql;
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
    struct storage_mysql_data *smd = (struct storage_mysql_data *) data;
    const struct common_loaded_plugin *mplg;

    // load common_mysql plugin
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }
    smd->mi = (struct common_mysql_iface*) mplg->iface;
    smd->md = (struct common_mysql_state*) mplg->data;

    return 0;
}

static const char create_query[] =
"CREATE TABLE `%sstorage` (\n"
"    serial_id BIGINT NOT NULL PRIMARY KEY AUTO_INCREMENT,\n"
"    size INT UNSIGNED NOT NULL DEFAULT 0,\n"
"    is_temporary TINYINT NOT NULL DEFAULT 0,\n"
"    mime_type INT NOT NULL DEFAULT 0,\n"
"    random_key CHAR(64) NOT NULL,\n"
"    sha256 CHAR(64) NOT NULL,\n"
"    create_time DATETIME(6) NOT NULL,\n"
"    last_access_time DATETIME(6) DEFAULT NULL,\n"
"    content MEDIUMBLOB DEFAULT NULL,\n"
"    UNIQUE KEY st_random_k(random_key),\n"
"    UNIQUE KEY st_sha256_k(sha256)\n"
") ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;\n";

static int
create_database(
        struct storage_mysql_data *smd)
{
    struct common_mysql_iface *mi = smd->mi;
    struct common_mysql_state *md = smd->md;

    if (mi->simple_fquery(md, create_query,
                          md->table_prefix) < 0)
        db_error_fail(md);

    if (mi->simple_fquery(md, "INSERT INTO %sconfig VALUES ('storage_version', '%d') ;", md->table_prefix, STORAGE_DB_VERSION) < 0)
        db_error_fail(md);

    smd->is_db_checked = 1;
    return 0;

fail:
    return -1;
}

static int
check_database(
        struct storage_mysql_data *smd)
{
    int storage_version = 0;
    struct common_mysql_iface *mi = smd->mi;
    struct common_mysql_state *md = smd->md;

    if (mi->connect(md) < 0)
        goto fail;

    if (mi->fquery(md, 1, "SELECT config_val FROM %sconfig WHERE config_key = 'storage_version' ;", md->table_prefix) < 0) {
        err("probably the database is not created, please, create it");
        goto fail;
    }
    if (md->row_count > 1) {
        err("storage_version key is not unique");
        goto fail;
    }
    if (!md->row_count) return create_database(smd);
    if (mi->next_row(md) < 0) db_error_fail(md);
    if (!md->row[0] || mi->parse_int(md, md->row[0], &storage_version) < 0)
        db_error_inv_value_fail(md, "config_val");
    mi->free_res(md);
    if (storage_version < 1 || storage_version > STORAGE_DB_VERSION) {
        err("storage_version == %d is not supported", storage_version);
        goto fail;
    }

    while (storage_version >= 0) {
        switch (storage_version) {
        case STORAGE_DB_VERSION:
            storage_version = -1;
            break;
        }
        if (storage_version >= 0) {
            ++storage_version;
            if (mi->simple_fquery(md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'storage_version' ;", md->table_prefix, storage_version) < 0)
                return -1;
        }
    }

    smd->is_db_checked = 1;
    return 0;

fail:
    return -1;
}

static int
open_func(
        struct storage_plugin_data *data)
{
    struct storage_mysql_data *smd = (struct storage_mysql_data *) data;

    if (!smd->is_db_checked) {
        check_database(smd);
    }

    return 0;
}

struct storage_info_internal
{
    int64_t serial_id;
    int64_t size;
    int is_temporary;
    int mime_type;
    unsigned char *random_key;
    unsigned char *sha256;
    struct timeval create_time;
    struct timeval last_access_time;
    struct common_mysql_binary content;
};

enum { STORAGE_INFO_ROW_WIDTH = 9 };
#define STORAGE_INFO_OFFSET(f) XOFFSET(struct storage_info_internal, f)
static const struct common_mysql_parse_spec storage_info_spec[STORAGE_INFO_ROW_WIDTH] =
{
    { 0, 'l', "serial_id", STORAGE_INFO_OFFSET(serial_id), 0 },
    { 0, 'l', "size", STORAGE_INFO_OFFSET(size), 0 },
    { 0, 'd', "is_temporary", STORAGE_INFO_OFFSET(is_temporary), 0 },
    { 0, 'd', "mime_type", STORAGE_INFO_OFFSET(mime_type), 0 },
    { 0, 's', "random_key", STORAGE_INFO_OFFSET(random_key), 0 },
    { 0, 's', "sha256", STORAGE_INFO_OFFSET(sha256), 0 },
    { 1, 'T', "create_time", STORAGE_INFO_OFFSET(create_time), 0 },
    { 1, 'T', "last_access_time", STORAGE_INFO_OFFSET(last_access_time), 0 },
    { 1, 'x', "content", STORAGE_INFO_OFFSET(content) },
};

static int
insert_func(
        struct storage_plugin_data *data,
        int is_temporary,
        int mime_type,
        size_t content_size,
        const unsigned char *content,
        struct storage_entry *p_se)
{
    struct storage_mysql_data *smd = (struct storage_mysql_data *) data;
    struct common_mysql_iface *mi = smd->mi;
    struct common_mysql_state *md = smd->md;
    unsigned char random_id_bytes[16];
    unsigned char random_id_str[32];
    unsigned char sha256_str[64];
    int len;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct storage_info_internal sii = {};
    struct common_mysql_binary bin = {};

    if (!smd->is_db_checked) {
        check_database(smd);
    }

    random_init();
    random_bytes(random_id_bytes, sizeof(random_id_bytes));
    len = base64u_encode(random_id_bytes,
                         sizeof(random_id_bytes),
                         random_id_str);
    random_id_str[len] = 0;

    if (!content) {
        content_size = 0;
        content = "";
    }
    sha256b64ubuf(sha256_str, sizeof(sha256_str), content, content_size);

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "INSERT INTO `%sstorage` VALUES (DEFAULT",
            md->table_prefix);
    fprintf(cmd_f, ", %zu", content_size);
    fprintf(cmd_f, ", %d", !!is_temporary);
    fprintf(cmd_f, ", %d", mime_type);
    fprintf(cmd_f, ", '");
    mi->escape_string(md, cmd_f, random_id_str);
    fprintf(cmd_f, "', '");
    mi->escape_string(md, cmd_f, sha256_str);
    fprintf(cmd_f, "', NOW(6), NOW(6), ");
    bin.size = content_size;
    bin.data = (unsigned char *) content;
    mi->write_escaped_bin(md, cmd_f, "", &bin);
    fprintf(cmd_f, ") ON DUPLICATE KEY UPDATE last_access_time = NOW(6)");
    if (!is_temporary) {
        fprintf(cmd_f, ", is_temporary = 0");
    }
    fprintf(cmd_f, ";");
    fclose(cmd_f); cmd_f = NULL;
    //if (mi->simple_query(md, cmd_s, cmd_z) < 0) goto fail;
    if (mi->simple_query_bin(md, cmd_s, cmd_z) < 0) goto fail;
    free(cmd_s); cmd_s = NULL; cmd_z = 0;

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT serial_id, size, is_temporary, mime_type, random_key, sha256, create_time, last_access_time, NULL FROM %sstorage WHERE sha256 = '",
            md->table_prefix);
    mi->escape_string(md, cmd_f, sha256_str);
    fprintf(cmd_f, "';");
    fclose(cmd_f); cmd_f = NULL;
    if (mi->query(md, cmd_s, cmd_z, STORAGE_INFO_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count == 1) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, STORAGE_INFO_ROW_WIDTH, storage_info_spec, &sii) < 0) goto fail;

        p_se->serial_id = sii.serial_id;
        p_se->size = sii.size;
        p_se->is_temporary = sii.is_temporary;
        p_se->mime_type = sii.mime_type;
        p_se->random_key[0] = 0;
        if (sii.random_key) {
            snprintf(p_se->random_key, sizeof(p_se->random_key), "%s",
                     sii.random_key);
        }
        free(sii.random_key); sii.random_key = NULL;
        p_se->sha256[0] = 0;
        if (sii.sha256) {
            snprintf(p_se->sha256, sizeof(p_se->sha256), "%s",
                     sii.sha256);
        }
        free(sii.sha256); sii.sha256 = NULL;
        p_se->create_time_us = sii.create_time.tv_sec * 1000000LL + sii.create_time.tv_usec;
        p_se->last_access_time_us = sii.last_access_time.tv_sec * 1000000LL + sii.last_access_time.tv_usec;
        free(sii.content.data); sii.content.data = NULL;
    }

    return 0;

fail:
    free(sii.random_key);
    free(sii.sha256);
    free(sii.content.data);
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    return -1;
}

static int
get_by_serial_id_func(
        struct storage_plugin_data *data,
        int64_t serial_id,
        struct storage_entry *p_se)
{
    struct storage_mysql_data *smd = (struct storage_mysql_data *) data;
    struct common_mysql_iface *mi = smd->mi;
    struct common_mysql_state *md = smd->md;
    char *cmd_s = NULL;
    size_t cmd_z = 0;
    FILE *cmd_f = NULL;
    struct storage_info_internal sii = {};

    cmd_f = open_memstream(&cmd_s, &cmd_z);
    fprintf(cmd_f, "SELECT * FROM `%sstorage` WHERE serial_id = %lld;",
            md->table_prefix, (long long) serial_id);
    fclose(cmd_f); cmd_f = NULL;

    if (mi->query(md, cmd_s, cmd_z, STORAGE_INFO_ROW_WIDTH) < 0)
        db_error_fail(md);
    free(cmd_s); cmd_s = NULL; cmd_z = 0;
    if (md->row_count == 1) {
        if (mi->next_row(md) < 0) db_error_fail(md);
        if (mi->parse_spec(md, -1, md->row, md->lengths, STORAGE_INFO_ROW_WIDTH, storage_info_spec, &sii) < 0) goto fail;
        p_se->serial_id = sii.serial_id;
        p_se->size = sii.size;
        p_se->is_temporary = sii.is_temporary;
        p_se->mime_type = sii.mime_type;
        p_se->random_key[0] = 0;
        if (sii.random_key) {
            snprintf(p_se->random_key, sizeof(p_se->random_key), "%s",
                     sii.random_key);
        }
        free(sii.random_key); sii.random_key = NULL;
        p_se->sha256[0] = 0;
        if (sii.sha256) {
            snprintf(p_se->sha256, sizeof(p_se->sha256), "%s",
                     sii.sha256);
        }
        free(sii.sha256); sii.sha256 = NULL;
        p_se->create_time_us = sii.create_time.tv_sec * 1000000LL + sii.create_time.tv_usec;
        p_se->last_access_time_us = sii.last_access_time.tv_sec * 1000000LL + sii.last_access_time.tv_usec;
        p_se->content = sii.content.data; sii.content.data = NULL;
        return 1;
    }
    return 0;

fail:
    free(sii.random_key);
    free(sii.sha256);
    free(sii.content.data);
    if (cmd_f) fclose(cmd_f);
    free(cmd_s);
    return -1;
}

struct storage_plugin_iface plugin_storage_mysql =
{
    {
        {
            sizeof (struct storage_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "storage",
            "mysql",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    STORAGE_PLUGIN_IFACE_VERSION,
    open_func,
    insert_func,
    get_by_serial_id_func,
};
