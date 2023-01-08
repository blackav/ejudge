/* -*- mode: c -*- */

/* Copyright (C) 2008-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/cldb_plugin.h"
#include "ejudge/clarlog.h"
#include "ejudge/clarlog_state.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/xml_utils.h"
#include "ejudge/errlog.h"
#include "ejudge/contests.h"
#include "ejudge/prepare.h"
#include "ejudge/compat.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <mysql.h>

#include <string.h>
#include <errno.h>

struct cldb_mysql_state
{
  int nref;

  // mysql access
  struct common_mysql_iface *mi;
  struct common_mysql_state *md;
};

struct cldb_mysql_cnts
{
  struct cldb_mysql_state *plugin_state;
  struct clarlog_state *cl_state;
  int contest_id;
};

static struct common_plugin_data *init_func(void);
static int finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);
static struct cldb_plugin_cnts *
open_func(
        struct cldb_plugin_data *data,
        struct clarlog_state *cl_state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags);
static struct cldb_plugin_cnts *
close_func(struct cldb_plugin_cnts *cdata);
static int
reset_func(struct cldb_plugin_cnts *cdata);
static int
add_entry_func(struct cldb_plugin_cnts *, int);
static int
set_flags_func(struct cldb_plugin_cnts *, int);
static int
set_charset_func(struct cldb_plugin_cnts *, int);
static int
get_raw_text_func(struct cldb_plugin_cnts *, int, unsigned char **,size_t*);
static int
add_text_func(struct cldb_plugin_cnts *, int, const ej_uuid_t *, const unsigned char *, size_t);
static int
modify_text_func(struct cldb_plugin_cnts *, int, const unsigned char *, size_t);
static int
modify_record_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        int mask,
        const struct clar_entry_v2 *pe);
static int
fetch_run_messages_func(
        struct cldb_plugin_cnts *cdata,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry **pp);
static int
fetch_run_messages_2_func(
        struct cldb_plugin_cnts *cdata,
        int uuid_count,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry **pp);
static int
fetch_total(
        struct cldb_plugin_cnts *cdata);

/* plugin entry point */
struct cldb_plugin_iface plugin_cldb_mysql =
{
  {
    {
      sizeof (struct cldb_plugin_iface),
      EJUDGE_PLUGIN_IFACE_VERSION,
      "cldb",
      "mysql",
    },
    COMMON_PLUGIN_IFACE_VERSION,
    init_func,
    finish_func,
    prepare_func,
  },
  CLDB_PLUGIN_IFACE_VERSION,

  open_func,
  close_func,
  reset_func,
  add_entry_func,
  set_flags_func,
  set_charset_func,
  get_raw_text_func,
  add_text_func,
  modify_text_func,
  modify_record_func,
  fetch_run_messages_func,
  fetch_run_messages_2_func,
  fetch_total
};

static struct common_plugin_data *
init_func(void)
{
  struct cldb_mysql_state *state = 0;
  XCALLOC(state, 1);
  return (struct common_plugin_data*) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  struct cldb_mysql_state *state = (struct cldb_mysql_state*) data;

  if (state->nref > 0) {
    err("cldb_mysql::finish: reference counter > 0");
    return -1;
  }

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
  struct cldb_mysql_state *state = (struct cldb_mysql_state*) data;
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

struct clar_entry_internal
{
  int clar_id;
  unsigned char *uuid;
  int contest_id;
  int size;
  time_t create_time;
  int nsec;
  int user_from;
  int user_to;
  int j_from;
  int flags;
  int ip_version;
  int hide_flag;
  int ssl_flag;
  int appeal_flag;
  ej_ip_t ip;
  int locale_id;
  int in_reply_to;
  unsigned char *in_reply_uuid;
  int run_id;
  unsigned char *run_uuid;
  int old_run_status;
  int new_run_status;
  unsigned char *clar_charset;
  unsigned char *subj;
};

#define CLAR_VERSION 13

enum { CLARS_ROW_WIDTH = 24 };

#define CLARS_OFFSET(f) XOFFSET(struct clar_entry_internal, f)
static const struct common_mysql_parse_spec clars_spec[CLARS_ROW_WIDTH] =
{
  { 0, 'd', "clar_id", CLARS_OFFSET(clar_id), 0 },
  { 1, 's', "uuid", CLARS_OFFSET(uuid), 0 },
  { 0, 'd', "contest_id", CLARS_OFFSET(contest_id), 0 },
  { 0, 'd', "size", CLARS_OFFSET(size), 0 },
  { 0, 't', "create_time", CLARS_OFFSET(create_time), 0 },
  { 0, 'd', "nsec", CLARS_OFFSET(nsec), 0 },
  { 0, 'd', "user_from", CLARS_OFFSET(user_from), 0 },
  { 0, 'd', "user_to", CLARS_OFFSET(user_to), 0 },
  { 0, 'd', "j_from", CLARS_OFFSET(j_from), 0 },
  { 0, 'd', "flags", CLARS_OFFSET(flags), 0 },
  { 0, 'd', "ip_version", CLARS_OFFSET(ip_version), 0 },
  { 0, 'b', "hide_flag", CLARS_OFFSET(hide_flag), 0 },
  { 0, 'b', "ssl_flag", CLARS_OFFSET(ssl_flag), 0 },
  { 0, 'b', "appeal_flag", CLARS_OFFSET(appeal_flag), 0 },
  { 0, 'I', "ip", CLARS_OFFSET(ip), 0 },
  { 0, 'd', "locale_id", CLARS_OFFSET(locale_id), 0 },
  { 0, 'd', "in_reply_to", CLARS_OFFSET(in_reply_to), 0 },
  { 1, 's', "in_reply_uuid", CLARS_OFFSET(in_reply_uuid), 0 },
  { 0, 'd', "run_id", CLARS_OFFSET(run_id), 0 },
  { 1, 's', "run_uuid", CLARS_OFFSET(run_uuid), 0 },
  { 0, 'd', "old_run_status", CLARS_OFFSET(old_run_status), 0 },
  { 0, 'd', "new_run_status", CLARS_OFFSET(new_run_status), 0 },
  { 0, 's', "clar_charset", CLARS_OFFSET(clar_charset), 0 },
  { 0, 's', "subj", CLARS_OFFSET(subj), 0 },
};

static const char create_clars_query[] =
"CREATE TABLE %sclars("
"        clar_id INT UNSIGNED NOT NULL,"
"        uuid CHAR(40) NOT NULL,"
"        contest_id INT UNSIGNED NOT NULL,"
"        size INT UNSIGNED NOT NULL DEFAULT 0,"
"        create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
"        nsec INT UNSIGNED NOT NULL DEFAULT 0,"
"        user_from INT UNSIGNED NOT NULL DEFAULT 0,"
"        user_to INT UNSIGNED NOT NULL DEFAULT 0,"
"        j_from INT UNSIGNED NOT NULL DEFAULT 0,"
"        flags TINYINT NOT NULL DEFAULT 0,"
"        ip_version TINYINT NOT NULL DEFAULT 4,"
"        hide_flag TINYINT NOT NULL DEFAULT 0,"
"        ssl_flag TINYINT NOT NULL DEFAULT 0,"
"        appeal_flag TINYINT NOT NULL DEFAULT 0,"
"        ip VARCHAR(64) NOT NULL,"
"        locale_id INT NOT NULL DEFAULT 0,"
"        in_reply_to INT NOT NULL DEFAULT 0,"
"        in_reply_uuid CHAR(40),"
"        run_id INT NOT NULL DEFAULT 0,"
"        run_uuid CHAR(40),"
"        old_run_status TINYINT NOT NULL DEFAULT 0,"
"        new_run_status TINYINT NOT NULL DEFAULT 0,"
"        clar_charset VARCHAR(32),"
"        subj VARCHAR(256) DEFAULT NULL,"
"        PRIMARY KEY (clar_id, contest_id),"
"        UNIQUE KEY clars_uuid_uk (uuid),"
"        KEY clars_contest_id_k (contest_id),"
"        KEY clars_run_uuid_k (run_uuid),"
"        KEY clars_user_from_k (user_from),"
"        KEY clars_user_to_k (user_to)"
"        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;";

struct clartext_entry_internal
{
  int clar_id;
  int contest_id;
  unsigned char *uuid;
  unsigned char *clar_text;
};

enum { CLARTEXTS_ROW_WIDTH = 4 };

#define CLARTEXTS_OFFSET(f) XOFFSET(struct clartext_entry_internal, f)
static const struct common_mysql_parse_spec clartexts_spec[CLARTEXTS_ROW_WIDTH]=
{
  { 0, 'd', "clar_id", CLARTEXTS_OFFSET(clar_id), 0 },
  { 0, 'd', "contest_id", CLARTEXTS_OFFSET(contest_id), 0 },
  { 0, 's', "uuid", CLARTEXTS_OFFSET(uuid), 0 },
  { 0, 's', "clar_text", CLARTEXTS_OFFSET(clar_text), 0 },
};

static const char create_texts_query[] =
"CREATE TABLE %sclartexts("
"        clar_id INT UNSIGNED NOT NULL,"
"        contest_id INT UNSIGNED NOT NULL,"
"        uuid CHAR(40) NOT NULL,"
"        clar_text VARBINARY(4096),"
"        PRIMARY KEY (clar_id, contest_id),"
"        UNIQUE KEY clartexts_uuid_uk (uuid)"
"        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;";

static int
do_create(struct cldb_mysql_state *state)
{
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  mi->free_res(md);
  if (mi->simple_fquery(md, create_clars_query, md->table_prefix) < 0)
    db_error_fail(md);
  if (mi->simple_fquery(md, create_texts_query, md->table_prefix) < 0)
    db_error_fail(md);
  if (mi->simple_fquery(md, "ALTER TABLE %sclartexts ADD INDEX clartexts_contest_id_idx (contest_id);", md->table_prefix) < 0)
    return -1;
  if (mi->simple_fquery(md, "INSERT INTO %sconfig VALUES ('clar_version', '%d') ;", md->table_prefix, CLAR_VERSION) < 0)
    db_error_fail(md);
  return 0;

 fail:
  return -1;
}

static int
do_open(struct cldb_mysql_state *state)
{
  int clar_version = 0;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  if (mi->connect(md) < 0)
    return -1;

  if (mi->fquery(md, 1, "SELECT config_val FROM %sconfig WHERE config_key = 'clar_version' ;", md->table_prefix) < 0) {
    err("probably the database is not created, please, create it");
    return -1;
  }
  if (md->row_count > 1) {
    err("clar_version key is not unique");
    return -1;
  }
  if (!md->row_count) return do_create(state);
  if (mi->next_row(md) < 0) db_error_fail(md);
  if (!md->row[0] || mi->parse_int(md, md->row[0], &clar_version) < 0)
    db_error_inv_value_fail(md, "config_val");
  mi->free_res(md);

  if (clar_version < 1 || clar_version > CLAR_VERSION) {
    err("clar_version == %d is not supported", clar_version);
    goto fail;
  }

  while (clar_version > 0) {
    switch (clar_version) {
    case 1:
      if (mi->simple_fquery(md, "ALTER TABLE %sclars ADD COLUMN run_id INT NOT NULL DEFAULT 0 AFTER in_reply_to", md->table_prefix) < 0)
        return -1;
      break;
    case 2:
      if (mi->simple_fquery(md, "ALTER TABLE %sclars ADD COLUMN uuid CHAR(40) DEFAULT NULL AFTER clar_id, ADD COLUMN in_reply_uuid CHAR(40) DEFAULT NULL AFTER in_reply_to, ADD COLUMN run_uuid CHAR(40) DEFAULT NULL AFTER run_id ;", md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "UPDATE %sclars SET uuid = UUID() WHERE uuid IS NULL ;", md->table_prefix) < 0)
        return -1;
      // update uuid indices
      if (mi->simple_fquery(md, "UPDATE %sclars AS t1, %sclars AS t2 SET t1.in_reply_uuid = t2.uuid WHERE t1.in_reply_to > 0 AND t1.contest_id = t2.contest_id AND t1.in_reply_to - 1 = t2.clar_id;", md->table_prefix, md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "UPDATE %sclars AS t1, %sruns AS t2 SET t1.run_uuid = t2.run_uuid WHERE t1.run_id > 0 AND t1.contest_id = t2.contest_id AND t1.run_id - 1 = t2.run_id;", md->table_prefix, md->table_prefix) < 0)
        return -1;
      break;
    case 3:
      if (mi->simple_fquery(md,
                            "ALTER TABLE %sclars "
                            " ADD COLUMN old_run_status TINYINT NOT NULL DEFAULT 0 AFTER run_uuid, "
                            " ADD COLUMN new_run_status TINYINT NOT NULL DEFAULT 0 AFTER old_run_status, "
                            " ADD UNIQUE KEY clars_uuid_uk (uuid), "
                            " ADD KEY clars_contest_id_k (contest_id), "
                            " ADD KEY clars_run_uuid_k (run_uuid), "
                            " ADD KEY clars_user_from_k (user_from), "
                            " ADD KEY clars_user_key_k (user_to) ; ",
                            md->table_prefix) < 0)
        return -1;
      break;
    case 4:
      if (mi->simple_fquery(md,
                            "ALTER TABLE %sclars "
                            " MODIFY clar_charset VARCHAR(32),"
                            " MODIFY subj VARCHAR(128); ",
                            md->table_prefix) < 0)
        return -1;
      break;
    case 5:
      if (mi->simple_fquery(md,
                            "ALTER TABLE %sclars "
                            " MODIFY uuid CHAR(40) NOT NULL ;",
                            md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md,
                            "ALTER TABLE %sclartexts "
                            " ADD COLUMN uuid CHAR(40) DEFAULT NULL AFTER contest_id;",
                            md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "UPDATE %sclartexts AS t1, %sclars AS t2 SET t1.uuid = t2.uuid WHERE t1.contest_id = t2.contest_id AND t1.clar_id = t2.clar_id;", md->table_prefix, md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md,
                            "ALTER TABLE %sclartexts "
                            " MODIFY uuid CHAR(40) NOT NULL,"
                            " ADD UNIQUE KEY clartexts_uuid_uk (uuid) ;",
                            md->table_prefix) < 0)
        return -1;
      break;
    case 6:
      if (mi->simple_fquery(md, "ALTER TABLE %sclartexts ADD INDEX clartexts_contest_id_idx (contest_id);", md->table_prefix) < 0)
        return -1;
      break;
    case 7:
      if (mi->simple_fquery(md, "ALTER TABLE %sclartexts ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;", md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sclars ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;", md->table_prefix) < 0)
        return -1;
      break;
    case 8:
      if (mi->simple_fquery(md, "ALTER TABLE %sclars MODIFY uuid CHAR(40) CHARSET utf8 COLLATE utf8_bin NOT NULL;", md->table_prefix) < 0)
        return -1;
      break;
    case 9:
      if (mi->simple_fquery(md, "ALTER TABLE %sclars ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;", md->table_prefix) < 0)
        return -1;
      if (mi->simple_fquery(md, "ALTER TABLE %sclartexts ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;", md->table_prefix) < 0)
        return -1;
      break;
    case 10:
      if (mi->simple_fquery(md, "ALTER TABLE %sclars MODIFY COLUMN uuid CHAR(40) NOT NULL, MODIFY COLUMN ip VARCHAR(64) NOT NULL, MODIFY COLUMN in_reply_uuid CHAR(40), MODIFY COLUMN run_uuid CHAR(40), MODIFY COLUMN clar_charset VARCHAR(32) ;", md->table_prefix) < 0)
        return -1;
      break;
    case 11:
      if (mi->simple_fquery(md, "ALTER TABLE %sclartexts MODIFY COLUMN uuid CHAR(40) NOT NULL ;", md->table_prefix) < 0)
        return -1;
      break;
    case 12:
      if (mi->simple_fquery(md, "ALTER TABLE %sclars MODIFY COLUMN subj VARCHAR(256) DEFAULT NULL ;", md->table_prefix) < 0)
        return -1;
      break;
    case CLAR_VERSION:
      clar_version = -1;
      break;
    }
    if (clar_version > 0) {
      ++clar_version;
      if (mi->simple_fquery(md, "UPDATE %sconfig SET config_val = '%d' WHERE config_key = 'clar_version' ;", md->table_prefix, clar_version) < 0)
        return -1;
    }
  }

  return 0;

 fail:
  mi->free_res(md);
  return -1;
}

static void
expand_clar_array(struct clar_array *arr, int clar_id)
{
  int new_a;
  struct clar_entry_v2 *new_v;
  int i;

  if (clar_id < arr->a) return;
  new_a = arr->a;
  if (!new_a) new_a = 128;
  while (clar_id >= new_a) new_a *= 2;
  XCALLOC(new_v, new_a);
  if (arr->a > 0) memcpy(new_v, arr->v, sizeof(new_v[0]) * arr->a);
  for (i = arr->a; i < new_a; new_v[i++].id = -1);
  xfree(arr->v);
  arr->a = new_a;
  arr->v = new_v;
}

static int
is_valid_charset(const unsigned char *charset)
{
  const unsigned char *p;

  if (!charset) return 1;
  if (strlen(charset) >= CLAR_ENTRY_V2_CHARSET_SIZE) return 0;
  for (p = charset; *p; ++p)
    if (*p <= ' ' || *p >= 127)
      return 0;
  return 1;
}

static int
make_clarlog_entry(
        struct cldb_mysql_state *state,
        int contest_id,
        int extra_columns,
        struct clar_entry_v2 *ce)
{
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  int retval = -1;

  struct clar_entry_internal cl = {};
  ej_uuid_t uuid = {};
  ej_uuid_t in_reply_uuid = {};
  ej_uuid_t run_uuid = {};
  unsigned char subj2[CLAR_ENTRY_V2_SUBJ_SIZE] = {};

  memset(ce, 0, sizeof(*ce));

  if (md->field_count != CLARS_ROW_WIDTH + extra_columns) {
    err("wrong field_count (%d instead of %d). invalid table format?", md->field_count, CLARS_ROW_WIDTH + extra_columns);
    goto fail;
  }
  if (mi->parse_spec(md, -1, md->row, md->lengths, CLARS_ROW_WIDTH, clars_spec, &cl) < 0)
    goto fail;

  if (cl.clar_id < 0) db_error_inv_value_fail(md, "clar_id");
  if (cl.uuid && ej_uuid_parse(cl.uuid, &uuid) < 0) db_error_inv_value_fail(md, "uuid");
  if (cl.contest_id != contest_id)
    db_error_inv_value_fail(md, "contest_id");
  if (cl.size < 0 || cl.size >= 65536) db_error_inv_value_fail(md, "size");
  if (cl.create_time <= 0) db_error_inv_value_fail(md, "create_time");
  if (cl.nsec < 0 || cl.nsec >= 1000000000)
    db_error_inv_value_fail(md, "nsec");
  if (cl.user_from < 0) db_error_inv_value_fail(md, "user_from");
  if (cl.user_to < 0) db_error_inv_value_fail(md, "user_to");
  if (cl.j_from < 0) db_error_inv_value_fail(md, "j_from");
  if (cl.flags < 0 || cl.flags > 2) db_error_inv_value_fail(md, "flags");
  if (cl.locale_id < 0 || cl.locale_id > 255)
    db_error_inv_value_fail(md, "locale_id");
  if (cl.in_reply_to < 0) db_error_inv_value_fail(md, "in_reply_to");
  if (cl.in_reply_uuid && ej_uuid_parse(cl.in_reply_uuid, &in_reply_uuid)) db_error_inv_value_fail(md, "in_reply_uuid");
  if (cl.run_id < 0) db_error_inv_value_fail(md, "run_id");
  if (cl.run_uuid && ej_uuid_parse(cl.run_uuid, &run_uuid) < 0) db_error_inv_value_fail(md, "run_uuid");
  if (!is_valid_charset(cl.clar_charset)) db_error_inv_value_fail(md, "clar_charset");
  int subj_len = 0;
  if (cl.subj) subj_len = strlen(cl.subj);
  if (subj_len < CLAR_ENTRY_V2_SUBJ_SIZE) {
    if (cl.subj) strcpy(subj2, cl.subj);
  } else {
    memcpy(subj2, cl.subj, CLAR_ENTRY_V2_SUBJ_SIZE);
    int j = CLAR_ENTRY_V2_SUBJ_SIZE - 4;
    if (cl.clar_charset && !strcasecmp(cl.clar_charset, "utf-8")) {
      while (j >= 0 && subj2[j] >= 0x80 && subj2[j] <= 0xbf) j--;
      if (j < 0) j = 0;
    }
    subj2[j++] = '.';
    subj2[j++] = '.';
    subj2[j++] = '.';
    subj2[j++] = 0;
    for (; j < CLAR_ENTRY_V2_SUBJ_SIZE; subj2[j++] = 0);
  }

  ce->id = cl.clar_id;
  ej_uuid_copy(&ce->uuid, &uuid);
  ce->size = cl.size;
  ce->time = cl.create_time;
  ce->nsec = cl.nsec;
  ce->from = cl.user_from;
  ce->to = cl.user_to;
  ce->j_from = cl.j_from;
  ce->flags = cl.flags;
  ce->ssl_flag = cl.ssl_flag;
  ce->appeal_flag = cl.appeal_flag;
  ipv6_to_clar_entry(&cl.ip, ce);
  ce->ipv6_flag = cl.ip.ipv6_flag;
  ce->locale_id = cl.locale_id;
  ce->in_reply_to = cl.in_reply_to;
  ej_uuid_copy(&ce->in_reply_uuid, &in_reply_uuid);
  ce->run_id = cl.run_id;
  ej_uuid_copy(&ce->run_uuid, &run_uuid);
  ce->old_run_status = cl.old_run_status;
  ce->new_run_status = cl.new_run_status;
  strcpy(ce->charset, cl.clar_charset);
  strcpy(ce->subj, subj2);
  retval = 0;

  //done:;
fail:;
  xfree(cl.uuid);
  xfree(cl.in_reply_uuid);
  xfree(cl.run_uuid);
  xfree(cl.clar_charset);
  xfree(cl.subj);
  return retval;
}

static struct cldb_plugin_cnts *
open_func(
        struct cldb_plugin_data *data,
        struct clarlog_state *cl_state,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
  struct cldb_mysql_state *state = (struct cldb_mysql_state*) data;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct cldb_mysql_cnts *cs = 0;
  int i;
  struct clar_entry_v2 ce;

  XCALLOC(cs, 1);
  cs->plugin_state = state;
  if (state) state->nref++;
  cs->cl_state = cl_state;
  if (cnts) cs->contest_id = cnts->id;
  if (!cs->contest_id) {
    err("undefined contest_id");
    goto fail;
  }
  if (do_open(state) < 0) goto fail;

  if (mi->fquery(md, CLARS_ROW_WIDTH,
                 "SELECT * FROM %sclars WHERE contest_id=%d ORDER BY clar_id;",
                md->table_prefix, cs->contest_id) < 0)
    db_error_fail(md);
  for (i = 0; i < md->row_count; i++) {
    if (mi->next_row(md) < 0) goto fail;
    if (make_clarlog_entry(state, cs->contest_id, 0, &ce) < 0)
      goto fail;

    expand_clar_array(&cl_state->clars, ce.id);
    cl_state->clars.v[ce.id] = ce;
    if (ce.id >= cl_state->clars.u) cl_state->clars.u = ce.id + 1;
  }
  state->mi->free_res(state->md);

  return (struct cldb_plugin_cnts*) cs;

 fail:
  state->mi->free_res(state->md);
  close_func((struct cldb_plugin_cnts*) cs);
  return 0;
}

static struct cldb_plugin_cnts *
close_func(struct cldb_plugin_cnts *cdata)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;

  if (!cs) return 0;
  if (cs->plugin_state) cs->plugin_state->nref--;
  memset(cs, 0, sizeof(*cs));
  xfree(cs);
  return 0;
}

static int
reset_func(struct cldb_plugin_cnts *cdata)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct clarlog_state *cl = cs->cl_state;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  int i;

  cl->clars.u = 0;
  xfree(cl->clars.v);
  cl->clars.a = 128;
  XCALLOC(cl->clars.v, cl->clars.a);
  for (i = 0; i < cl->clars.a; cl->clars.v[i++].id = -1);

  mi->simple_fquery(md, "DELETE FROM %sclars WHERE contest_id = %d ;",
                   md->table_prefix, cs->contest_id);
  mi->simple_fquery(md, "DELETE FROM %sclartexts WHERE contest_id = %d ;",
                   md->table_prefix, cs->contest_id);
  return 0;
}

static int
add_entry_func(struct cldb_plugin_cnts *cdata, int clar_id)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct clarlog_state *cl = cs->cl_state;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct clar_entry_internal cc;
  struct clar_entry_v2 *ce;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  unsigned char uuid_str[40];
  unsigned char in_reply_uuid_str[40];
  unsigned char run_uuid_str[40];

  if (clar_id < 0 || clar_id >= cl->clars.u) return -1;
  ce = &cl->clars.v[clar_id];
  if (ce->id != clar_id) return -1;

  memset(&cc, 0, sizeof(cc));
  cc.clar_id = ce->id;
  if (ej_uuid_is_nonempty(ce->uuid)) {
    ej_uuid_unparse_r(uuid_str, sizeof(uuid_str), &ce->uuid, NULL);
    cc.uuid = uuid_str;
  }
  cc.contest_id = cs->contest_id;
  cc.size = ce->size;
  cc.create_time = ce->time;
  cc.nsec = ce->nsec;
  cc.user_from = ce->from;
  cc.user_to = ce->to;
  cc.j_from = ce->j_from;
  cc.flags = ce->flags;
  cc.hide_flag = ce->hide_flag;
  cc.ssl_flag = ce->ssl_flag;
  cc.appeal_flag = ce->appeal_flag;
  cc.ip_version = 4;
  clar_entry_to_ipv6(ce, &cc.ip);
  if (cc.ip.ipv6_flag) cc.ip_version = 6;
  cc.locale_id = ce->locale_id;
  cc.in_reply_to = ce->in_reply_to;
  if (ej_uuid_is_nonempty(ce->in_reply_uuid)) {
    ej_uuid_unparse_r(in_reply_uuid_str, sizeof(in_reply_uuid_str), &ce->in_reply_uuid, NULL);
    cc.in_reply_uuid = in_reply_uuid_str;
  }
  cc.run_id = ce->run_id;
  if (ej_uuid_is_nonempty(ce->run_uuid)) {
    ej_uuid_unparse_r(run_uuid_str, sizeof(run_uuid_str), &ce->run_uuid, NULL);
    cc.run_uuid = run_uuid_str;
  }
  cc.old_run_status = ce->old_run_status;
  cc.new_run_status = ce->new_run_status;
  cc.clar_charset = ce->charset;
  cc.subj = ce->subj;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %sclars VALUES ( ", md->table_prefix);
  mi->unparse_spec(md, cmd_f, CLARS_ROW_WIDTH, clars_spec, &cc);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (mi->simple_query(md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
set_flags_func(struct cldb_plugin_cnts *cdata, int clar_id)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct clarlog_state *cl = cs->cl_state;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct clar_entry_v2 *ce;

  if (clar_id < 0 || clar_id >= cl->clars.u) return -1;
  ce = &cl->clars.v[clar_id];
  if (ce->id != clar_id) return -1;
  return mi->simple_fquery(md, "UPDATE %sclars SET flags = %d WHERE clar_id = %d AND contest_id = %d ;", md->table_prefix, ce->flags, clar_id, cs->contest_id);
}

static int
set_charset_func(struct cldb_plugin_cnts *cdata, int clar_id)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct clarlog_state *cl = cs->cl_state;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct clar_entry_v2 *ce;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;

  if (clar_id < 0 || clar_id >= cl->clars.u) return -1;
  ce = &cl->clars.v[clar_id];
  if (ce->id != clar_id) return -1;
  if (!is_valid_charset(ce->charset)) return -1;
  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %sclars SET clar_charset = ", md->table_prefix);
  mi->write_escaped_string(md, cmd_f, 0, ce->charset);
  fprintf(cmd_f, " WHERE clar_id = %d AND contest_id = %d ;",
          clar_id, cs->contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (mi->simple_query(md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
get_raw_text_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        unsigned char **p_text,
        size_t *p_size)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  if (mi->fquery(md, 1, "SELECT clar_text FROM %sclartexts WHERE clar_id = %d AND contest_id = %d ;", md->table_prefix, clar_id, cs->contest_id) < 0)
    return -1;
  if (md->row_count <= 0) {
    *p_text = xstrdup("");
    *p_size = 0;
    mi->free_res(md);
    return 0;
  }
  if (mi->next_row(md) < 0) goto fail;
  if (strlen(md->row[0]) != md->lengths[0]) {
    err("clar text is binary: clar_id = %d, contest_id = %d",
        clar_id, cs->contest_id);
    goto fail;
  }
  *p_size = md->lengths[0];
  *p_text = xmalloc(md->lengths[0] + 1);
  memcpy(*p_text, md->row[0], md->lengths[0]);
  (*p_text)[*p_size] = 0;
  mi->free_res(md);
  return 0;

 fail:
  mi->free_res(md);
  return -1;
}

static int
add_text_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        const ej_uuid_t *puuid,
        const unsigned char *text,
        size_t size)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  struct clartext_entry_internal ct;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  unsigned char uuid_str[40];

  if (!text) {
    text = "";
    size = 0;
  }
  if (strlen(text) != size) {
    err("clar text is binary: clar_id = %d, contest_id = %d",
        clar_id, cs->contest_id);
    goto fail;
  }

  memset(&ct, 0, sizeof(ct));
  ct.clar_id = clar_id;
  ct.contest_id = cs->contest_id;
  uuid_str[0] = 0;
  ej_uuid_unparse_r(uuid_str, sizeof(uuid_str), puuid, NULL);
  ct.uuid = uuid_str;
  ct.clar_text = (unsigned char*) text;
  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %sclartexts VALUES ( ", md->table_prefix);
  mi->unparse_spec(md, cmd_f, CLARTEXTS_ROW_WIDTH, clartexts_spec, &ct);
  fprintf(cmd_f, " ) ;");
  close_memstream(cmd_f); cmd_f = 0;
  if (mi->simple_query(md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
modify_text_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        const unsigned char *text,
        size_t size)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;

  if (!text) {
    text = "";
    size = 0;
  }
  if (strlen(text) != size) {
    err("clar text is binary: clar_id = %d, contest_id = %d",
        clar_id, cs->contest_id);
    goto fail;
  }

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %sclartexts SET clar_text = ", md->table_prefix);
  mi->write_escaped_string(md, cmd_f, NULL, text);
  fprintf(cmd_f, " WHERE clar_id = %d AND contest_id = %d", clar_id, cs->contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (mi->simple_query(md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
modify_record_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        int mask,
        const struct clar_entry_v2 *pe)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;
  const unsigned char *sep = "";
  const unsigned char *sep1 = ", ";

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %sclars SET ", md->table_prefix);

  if (mask & (1 << CLAR_FIELD_SIZE)) {
    fprintf(cmd_f, "%ssize = %d", sep, pe->size);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_FROM)) {
    fprintf(cmd_f, "%suser_from = %d", sep, pe->from);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_TO)) {
    fprintf(cmd_f, "%suser_to = %d", sep, pe->to);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_J_FROM)) {
    fprintf(cmd_f, "%sj_from = %d", sep, pe->j_from);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_FLAGS)) {
    fprintf(cmd_f, "%sflags = %d", sep, pe->flags);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_HIDE_FLAG)) {
    fprintf(cmd_f, "%shide_flag = %d", sep, pe->hide_flag);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_SSL_FLAG)) {
    fprintf(cmd_f, "%sssl_flag = %d", sep, pe->ssl_flag);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_APPEAL_FLAG)) {
    fprintf(cmd_f, "%sappeal_flag = %d", sep, pe->appeal_flag);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_IP)) {
    int ip_version  = 4;
    if (pe->ipv6_flag) ip_version = 6;
    fprintf(cmd_f, "%sip_version = %d", sep, ip_version);
    sep = sep1;
    ej_ip_t ipv6;
    clar_entry_to_ipv6(pe, &ipv6);
    mi->write_escaped_string(md, cmd_f, sep, xml_unparse_ipv6(&ipv6));
  }
  if (mask & (1 << CLAR_FIELD_LOCALE_ID)) {
    fprintf(cmd_f, "%slocale_id = %d", sep, pe->locale_id);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_IN_REPLY_TO)) {
    fprintf(cmd_f, "%sin_reply_to = %d", sep, pe->in_reply_to);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_IN_REPLY_UUID)) {
    fprintf(cmd_f, "%sin_reply_uuid = ", sep);
    if (ej_uuid_is_nonempty(pe->in_reply_uuid)) {
      fprintf(cmd_f, "'%s'", ej_uuid_unparse(&pe->in_reply_uuid, NULL));
    } else {
      fprintf(cmd_f, "NULL");
    }
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_RUN_ID)) {
    fprintf(cmd_f, "%srun_id = %d", sep, pe->run_id);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_RUN_UUID)) {
    fprintf(cmd_f, "%srun_uuid = ", sep);
    if (ej_uuid_is_nonempty(pe->run_uuid)) {
      fprintf(cmd_f, "'%s'", ej_uuid_unparse(&pe->run_uuid, NULL));
    } else {
      fprintf(cmd_f, "NULL");
    }
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_OLD_RUN_STATUS)) {
    fprintf(cmd_f, "%sold_run_status = %d", sep, pe->old_run_status);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_NEW_RUN_STATUS)) {
    fprintf(cmd_f, "%snew_run_status = %d", sep, pe->new_run_status);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_CHARSET)) {
    fprintf(cmd_f, "%s", sep);
    mi->write_escaped_string(md, cmd_f, sep, pe->charset);
    sep = sep1;
  }
  if (mask & (1 << CLAR_FIELD_SUBJECT)) {
    fprintf(cmd_f, "%s", sep);
    mi->write_escaped_string(md, cmd_f, sep, pe->subj);
    sep = sep1;
  }

  fprintf(cmd_f, " WHERE clar_id = %d AND contest_id = %d", clar_id, cs->contest_id);
  close_memstream(cmd_f); cmd_f = 0;
  if (mi->simple_query(md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

static int
fetch_run_messages_func(
        struct cldb_plugin_cnts *cdata,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry **pp)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  int count = 0;
  struct full_clar_entry *fce = NULL;
  int i;

  if (mi->fquery(md, CLARS_ROW_WIDTH + 1,
                 "SELECT t1.*, t2.clar_text FROM %sclars AS t1, %sclartexts AS t2 WHERE t1.contest_id=%d AND t1.run_uuid = '%s' AND t1.uuid = t2.uuid ORDER BY t1.clar_id;",
                 md->table_prefix, md->table_prefix,
                 cs->contest_id, ej_uuid_unparse(p_run_uuid, "")) < 0)
    db_error_fail(md);

  if (md->row_count <= 0) {
    state->mi->free_res(state->md);
    return 0;
  }

  count = md->row_count;
  XCALLOC(fce, count);

  for (i = 0; i < md->row_count; i++) {
    if (mi->next_row(md) < 0) goto fail;
    if (make_clarlog_entry(state, cs->contest_id, 1, &fce[i].e) < 0)
      goto fail;
    if (!md->row[CLARS_ROW_WIDTH]) {
      fce[i].text = NULL;
      fce[i].size = 0;
    } else {
      fce[i].size = md->lengths[CLARS_ROW_WIDTH];
      fce[i].text = xmalloc(fce[i].size + 1);
      memcpy(fce[i].text, md->row[CLARS_ROW_WIDTH], md->lengths[CLARS_ROW_WIDTH]);
      fce[i].text[fce[i].size] = 0;
    }
  }
  state->mi->free_res(state->md);

  *pp = fce;
  return count;

fail:
  if (fce) {
    for (i = 0; i < count; ++i) {
      xfree(fce[i].text);
    }
    xfree(fce);
  }
  state->mi->free_res(state->md);
  return -1;
}

static int
fetch_run_messages_2_func(
        struct cldb_plugin_cnts *cdata,
        int uuid_count,
        const ej_uuid_t *p_run_uuid,
        struct full_clar_entry **pp)
{
  char *uuid_s = NULL;
  size_t uuid_z = 0;
  FILE *uuid_f = NULL;
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;
  int count = 0;
  struct full_clar_entry *fce = NULL;
  int i, j;

  if (uuid_count <= 0) {
    return 0;
  }

  uuid_f = open_memstream(&uuid_s, &uuid_z);
  fprintf(uuid_f, "'%s'", ej_uuid_unparse(&p_run_uuid[0], ""));
  for (j = 1; j < uuid_count; ++j) {
    fprintf(uuid_f, ", '%s'", ej_uuid_unparse(&p_run_uuid[j], ""));
  }
  fclose(uuid_f); uuid_f = NULL;

  if (mi->fquery(md, CLARS_ROW_WIDTH + 1,
                 "SELECT t1.*, t2.clar_text FROM %sclars AS t1, %sclartexts AS t2 WHERE t1.contest_id=%d AND t1.run_uuid IN (%s) AND t1.uuid = t2.uuid ORDER BY t1.clar_id;",
                 md->table_prefix, md->table_prefix,
                 cs->contest_id, uuid_s) < 0)
    db_error_fail(md);
  xfree(uuid_s); uuid_s = NULL;

  if (md->row_count <= 0) {
    state->mi->free_res(state->md);
    return 0;
  }

  count = md->row_count;
  XCALLOC(fce, count);

  for (i = 0; i < md->row_count; i++) {
    if (mi->next_row(md) < 0) goto fail;
    if (make_clarlog_entry(state, cs->contest_id, 1, &fce[i].e) < 0)
      goto fail;
    if (!md->row[CLARS_ROW_WIDTH]) {
      fce[i].text = NULL;
      fce[i].size = 0;
    } else {
      fce[i].size = md->lengths[CLARS_ROW_WIDTH];
      fce[i].text = xmalloc(fce[i].size + 1);
      memcpy(fce[i].text, md->row[CLARS_ROW_WIDTH], md->lengths[CLARS_ROW_WIDTH]);
      fce[i].text[fce[i].size] = 0;
    }
  }
  state->mi->free_res(state->md);

  *pp = fce;
  return count;

fail:
  if (fce) {
    for (i = 0; i < count; ++i) {
      xfree(fce[i].text);
    }
    xfree(fce);
  }
  state->mi->free_res(state->md);
  xfree(uuid_s);
  return -1;
}

static int
fetch_total(
        struct cldb_plugin_cnts *cdata)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct common_mysql_iface *mi = state->mi;
  struct common_mysql_state *md = state->md;

  if (mi->fquery(md, 1, "SELECT max(clar_id) FROM %sclars WHERE contest_id = %d ;", md->table_prefix, cs->contest_id) < 0)
    return -1;
  if (md->row_count <= 0) {
    return -1;
  }
  if (mi->next_row(md) < 0) goto fail;
  if (!md->row[0]) {
    mi->free_res(md);
    return 0;
  }
  if (strlen(md->row[0]) != md->lengths[0]) goto fail;

  errno = 0;
  char *eptr = NULL;
  long val = strtol(md->row[0], &eptr, 10);
  if (errno || *eptr || eptr == md->row[0] || (int) val != val || val < 0)
    goto fail;

  int res = val + 1;
  mi->free_res(md);
  return res;

 fail:
  mi->free_res(md);
  return -1;
}

/*
 * Local variables:
 * End:
 */
