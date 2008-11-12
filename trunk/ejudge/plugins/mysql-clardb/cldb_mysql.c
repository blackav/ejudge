/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "ej_limits.h"
#include "cldb_plugin.h"
#include "clarlog.h"
#include "clarlog_state.h"
#include "../mysql-common/common_mysql.h"

#include "xml_utils.h"
#include "errlog.h"
#include "contests.h"
#include "prepare.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

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
        struct ejudge_cfg *config,
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
add_text_func(struct cldb_plugin_cnts *, int, const unsigned char *, size_t);

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
        struct ejudge_cfg *config,
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
  unsigned char *clar_charset;
  unsigned char *subj;
};

enum { CLARS_ROW_WIDTH = 18 };

#define CLARS_OFFSET(f) XOFFSET(struct clar_entry_internal, f)
static const struct common_mysql_parse_spec clars_spec[CLARS_ROW_WIDTH] =
{
  { 0, 'd', "clar_id", CLARS_OFFSET(clar_id), 0 },
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
  { 0, 'i', "ip", CLARS_OFFSET(ip), 0 },
  { 0, 'd', "locale_id", CLARS_OFFSET(locale_id), 0 },
  { 0, 'd', "in_reply_to", CLARS_OFFSET(in_reply_to), 0 },
  { 0, 's', "clar_charset", CLARS_OFFSET(clar_charset), 0 },
  { 0, 's', "subj", CLARS_OFFSET(subj), 0 },
};

static const char create_clars_query[] =
"CREATE TABLE %sclars("
"        clar_id INT UNSIGNED NOT NULL,"
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
"        clar_charset VARCHAR(64),"
"        subj VARBINARY(64),"
"        PRIMARY KEY (clar_id, contest_id)"
"        );";

struct clartext_entry_internal
{
  int clar_id;
  int contest_id;
  unsigned char *clar_text;
};

enum { CLARTEXTS_ROW_WIDTH = 3 };

#define CLARTEXTS_OFFSET(f) XOFFSET(struct clartext_entry_internal, f)
static const struct common_mysql_parse_spec clartexts_spec[CLARTEXTS_ROW_WIDTH]=
{
  { 0, 'd', "clar_id", CLARTEXTS_OFFSET(clar_id), 0 },
  { 0, 'd', "contest_id", CLARTEXTS_OFFSET(contest_id), 0 },
  { 0, 's', "clar_text", CLARTEXTS_OFFSET(clar_text), 0 },
};

static const char create_texts_query[] =
"CREATE TABLE %sclartexts("
"        clar_id INT UNSIGNED NOT NULL,"
"        contest_id INT UNSIGNED NOT NULL,"
"        clar_text VARBINARY(4096),"
"        PRIMARY KEY (clar_id, contest_id)"
"        );";

static int
do_create(struct cldb_mysql_state *state)
{
  state->mi->free_res(state->md);
  if (state->mi->simple_fquery(state->md, create_clars_query, state->md->table_prefix) < 0)
    db_error_fail(state->md);
  if (state->mi->simple_fquery(state->md, create_texts_query, state->md->table_prefix) < 0)
    db_error_fail(state->md);
  if (state->mi->simple_fquery(state->md, "INSERT INTO %sconfig VALUES ('clar_version', '1') ;", state->md->table_prefix) < 0)
    db_error_fail(state->md);
  return 0;

 fail:
  return -1;
}

static int
do_open(struct cldb_mysql_state *state)
{
  int clar_version = 0;

  if (state->mi->connect(state->md) < 0)
    return -1;

  if (state->mi->fquery(state->md, 1, "SELECT config_val FROM %sconfig WHERE config_key = 'clar_version' ;", state->md->table_prefix) < 0) {
    err("probably the database is not created, please, create it");
    return -1;
  }
  if (state->md->row_count > 1) {
    err("clar_version key is not unique");
    return -1;
  }
  if (!state->md->row_count) return do_create(state);
  if (state->mi->next_row(state->md) < 0) db_error_fail(state->md);
  if (!state->md->row[0]
      || state->mi->parse_int(state->md, state->md->row[0], &clar_version) < 0)
    db_error_inv_value_fail(state->md, "config_val");
  state->mi->free_res(state->md);
  if (clar_version != 1) {
    err("clar_version == %d is not supported", clar_version);
    goto fail;
  }
  return 0;

 fail:
  state->mi->free_res(state->md);
  return -1;
}

static void
expand_clar_array(struct clar_array *arr, int clar_id)
{
  int new_a;
  struct clar_entry_v1 *new_v;
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
  if (strlen(charset) >= CLAR_ENTRY_CHARSET_SIZE) return 0;
  for (p = charset; *p; ++p)
    if (*p <= ' ' || *p >= 127)
      return 0;
  return 1;
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
  struct cldb_mysql_cnts *cs = 0;
  int i, j;
  struct clar_entry_internal cl;
  struct clar_entry_v1 *ce;
  unsigned char subj2[CLAR_ENTRY_SUBJ_SIZE];
  int subj_len;

  memset(&cl, 0, sizeof(cl));
  XCALLOC(cs, 1);
  cs->plugin_state = state;
  if (state) state->nref++;
  cs->cl_state = cl_state;
  if (cnts) cs->contest_id = cnts->id;
  if (!cs->contest_id && global) cs->contest_id = global->contest_id;
  if (!cs->contest_id) {
    err("undefined contest_id");
    goto fail;
  }
  if (do_open(state) < 0) goto fail;

  if (state->mi->fquery(state->md, CLARS_ROW_WIDTH,
                "SELECT * FROM %sclars WHERE contest_id = %d ORDER BY clar_id;",
                state->md->table_prefix, cs->contest_id) < 0)
    db_error_fail(state->md);
  for (i = 0; i < state->md->row_count; i++) {
    if (state->mi->next_row(state->md) < 0) goto fail;
    memset(&cl, 0, sizeof(cl));
    if (state->mi->parse_spec(state->md, state->md->field_count, state->md->row,
                              state->md->lengths, CLARS_ROW_WIDTH,
                              clars_spec, &cl) < 0)
      goto fail;
    if (cl.clar_id < 0) db_error_inv_value_fail(state->md, "clar_id");
    if (cl.contest_id != cs->contest_id) db_error_inv_value_fail(state->md, "contest_id");
    if (cl.size < 0 || cl.size >= 65536) db_error_inv_value_fail(state->md, "size");
    if (cl.create_time <= 0) db_error_inv_value_fail(state->md, "create_time");
    if (cl.nsec < 0 || cl.nsec >= 1000000000) db_error_inv_value_fail(state->md, "nsec");
    if (cl.user_from < 0) db_error_inv_value_fail(state->md, "user_from");
    if (cl.user_to < 0) db_error_inv_value_fail(state->md, "user_to");
    if (cl.j_from < 0) db_error_inv_value_fail(state->md, "j_from");
    if (cl.flags < 0 || cl.flags > 2) db_error_inv_value_fail(state->md, "flags");
    if (cl.ip_version != 4) db_error_inv_value_fail(state->md, "ip_version");
    if (cl.locale_id < 0 || cl.locale_id > 255) db_error_inv_value_fail(state->md, "locale_id");
    if (cl.in_reply_to < 0) db_error_inv_value_fail(state->md, "in_reply_to");
    if (!is_valid_charset(cl.clar_charset)) db_error_inv_value_fail(state->md, "clar_charset");
    memset(subj2, 0, sizeof(subj2));
    subj_len = 0;
    if (cl.subj) subj_len = strlen(cl.subj);
    if (subj_len < CLAR_ENTRY_SUBJ_SIZE) {
      if (cl.subj) strcpy(subj2, cl.subj);
    } else {
      memcpy(subj2, cl.subj, CLAR_ENTRY_SUBJ_SIZE);
      j = CLAR_ENTRY_SUBJ_SIZE - 4;
      if (cl.clar_charset && !strcasecmp(cl.clar_charset, "utf-8")) {
        while (j >= 0 && subj2[j] >= 0x80 && subj2[j] <= 0xbf) j--;
        if (j < 0) j = 0;
      }
      subj2[j++] = '.';
      subj2[j++] = '.';
      subj2[j++] = '.';
      subj2[j++] = 0;
      for (; j < CLAR_ENTRY_SUBJ_SIZE; subj2[j++] = 0);
    }

    expand_clar_array(&cl_state->clars, cl.clar_id);
    ce = &cl_state->clars.v[cl.clar_id];

    ce->id = cl.clar_id;
    ce->size = cl.size;
    ce->time = cl.create_time;
    ce->nsec = cl.nsec;
    ce->from = cl.user_from;
    ce->to = cl.user_to;
    ce->j_from = cl.j_from;
    ce->flags = cl.flags;
    ce->ip6_flag = 0;
    ce->ssl_flag = cl.ssl_flag;
    ce->appeal_flag = cl.appeal_flag;
    ce->a.ip = cl.ip;
    ce->locale_id = cl.locale_id;
    ce->in_reply_to = cl.in_reply_to;
    strcpy(ce->charset, cl.clar_charset);
    strcpy(ce->subj, subj2);
    if (cl.clar_id >= cl_state->clars.u) cl_state->clars.u = cl.clar_id + 1;

    xfree(cl.clar_charset); cl.clar_charset = 0;
    xfree(cl.subj); cl.subj = 0;
  }
  state->mi->free_res(state->md);

  return (struct cldb_plugin_cnts*) cs;

 fail:
  xfree(cl.clar_charset);
  xfree(cl.subj);
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
  int i;

  cl->clars.u = 0;
  xfree(cl->clars.v);
  cl->clars.a = 128;
  XCALLOC(cl->clars.v, cl->clars.a);
  for (i = 0; i < cl->clars.a; cl->clars.v[i++].id = -1);

  state->mi->simple_fquery(state->md, "DELETE FROM %sclars WHERE contest_id = %d ;",
                   state->md->table_prefix, cs->contest_id);
  state->mi->simple_fquery(state->md, "DELETE FROM %sclartexts WHERE contest_id = %d ;",
                   state->md->table_prefix, cs->contest_id);
  return 0;
}

static int
add_entry_func(struct cldb_plugin_cnts *cdata, int clar_id)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct clarlog_state *cl = cs->cl_state;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct clar_entry_internal cc;
  struct clar_entry_v1 *ce;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;

  if (clar_id < 0 || clar_id >= cl->clars.u) return -1;
  ce = &cl->clars.v[clar_id];
  if (ce->id != clar_id) return -1;

  memset(&cc, 0, sizeof(cc));
  cc.clar_id = ce->id;
  cc.contest_id = cs->contest_id;
  cc.size = ce->size;
  cc.create_time = ce->time;
  cc.nsec = ce->nsec;
  cc.user_from = ce->from;
  cc.user_to = ce->to;
  cc.j_from = ce->j_from;
  cc.flags = ce->flags;
  cc.ip_version = 4;
  cc.hide_flag = ce->hide_flag;
  cc.ssl_flag = ce->ssl_flag;
  cc.appeal_flag = ce->appeal_flag;
  cc.ip = ce->a.ip;
  cc.locale_id = ce->locale_id;
  cc.in_reply_to = ce->in_reply_to;
  cc.clar_charset = ce->charset;
  cc.subj = ce->subj;

  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %sclars VALUES ( ", state->md->table_prefix);
  state->mi->unparse_spec(state->md, cmd_f, CLARS_ROW_WIDTH, clars_spec, &cc);
  fprintf(cmd_f, " ) ;");
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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
  struct clar_entry_v1 *ce;

  if (clar_id < 0 || clar_id >= cl->clars.u) return -1;
  ce = &cl->clars.v[clar_id];
  if (ce->id != clar_id) return -1;
  return state->mi->simple_fquery(state->md, "UPDATE %sclars SET flags = %d WHERE clar_id = %d AND contest_id = %d ;", state->md->table_prefix, ce->flags, clar_id, cs->contest_id);
}

static int
set_charset_func(struct cldb_plugin_cnts *cdata, int clar_id)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct clarlog_state *cl = cs->cl_state;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct clar_entry_v1 *ce;
  FILE *cmd_f = 0;
  char *cmd_t = 0;
  size_t cmd_z = 0;

  if (clar_id < 0 || clar_id >= cl->clars.u) return -1;
  ce = &cl->clars.v[clar_id];
  if (ce->id != clar_id) return -1;
  if (!is_valid_charset(ce->charset)) return -1;
  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "UPDATE %sclars SET clar_charset = ", state->md->table_prefix);
  state->mi->write_escaped_string(state->md, cmd_f, 0, ce->charset);
  fprintf(cmd_f, " WHERE clar_id = %d AND contest_id = %d ;",
          clar_id, cs->contest_id);
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
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

  if (state->mi->fquery(state->md, 1, "SELECT clar_text FROM %sclartexts WHERE clar_id = %d AND contest_id = %d ;", state->md->table_prefix, clar_id, cs->contest_id) < 0)
    return -1;
  if (state->md->row_count <= 0) {
    *p_text = xstrdup("");
    *p_size = 0;
    return 0;
  }
  if (state->mi->next_row(state->md) < 0) goto fail;
  if (strlen(state->md->row[0]) != state->md->lengths[0]) {
    err("clar text is binary: clar_id = %d, contest_id = %d",
        clar_id, cs->contest_id);
    goto fail;
  }
  *p_size = state->md->lengths[0];
  *p_text = xmalloc(state->md->lengths[0] + 1);
  memcpy(*p_text, state->md->row[0], state->md->lengths[0]);
  (*p_text)[*p_size] = 0;
  state->mi->free_res(state->md);
  return 0;

 fail:
  state->mi->free_res(state->md);
  return -1;
}

static int
add_text_func(
        struct cldb_plugin_cnts *cdata,
        int clar_id,
        const unsigned char *text,
        size_t size)
{
  struct cldb_mysql_cnts *cs = (struct cldb_mysql_cnts*) cdata;
  struct cldb_mysql_state *state = cs->plugin_state;
  struct clartext_entry_internal ct;
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

  memset(&ct, 0, sizeof(ct));
  ct.clar_id = clar_id;
  ct.contest_id = cs->contest_id;
  ct.clar_text = (unsigned char*) text;
  cmd_f = open_memstream(&cmd_t, &cmd_z);
  fprintf(cmd_f, "INSERT INTO %sclartexts VALUES ( ", state->md->table_prefix);
  state->mi->unparse_spec(state->md, cmd_f, CLARTEXTS_ROW_WIDTH, clartexts_spec, &ct);
  fprintf(cmd_f, " ) ;");
  fclose(cmd_f); cmd_f = 0;
  if (state->mi->simple_query(state->md, cmd_t, cmd_z) < 0) goto fail;
  xfree(cmd_t); cmd_t = 0;
  return 0;

 fail:
  if (cmd_f) fclose(cmd_f);
  xfree(cmd_t);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
