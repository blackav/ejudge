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
#include "rldb_plugin.h"
#include "runlog.h"
#include "teamdb.h"
#include "runlog_state.h"

#include "errlog.h"
#include "xml_utils.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <mysql.h>

#include <stdarg.h>
#include <errno.h>

struct rldb_mysql_state
{
  int nref;

  // configuration settings
  int port;
  int show_queries;

  unsigned char *user;
  unsigned char *password;
  unsigned char *database;
  unsigned char *host;
  unsigned char *socket;
  unsigned char *table_prefix;
  unsigned char *charset;

  // MYSQL connection
  MYSQL *conn;
  MYSQL_RES *res;
  MYSQL_ROW row;
  unsigned long *lengths;
  int row_count;
  int field_count;
};

struct rldb_mysql_cnts
{
  struct rldb_mysql_state *plugin_state;
  struct runlog_state *cl_state;
  int contest_id;
};

#include "methods.inc.c"

/* plugin entry point */
struct rldb_plugin_iface plugin_rldb_mysql =
{
  {
    sizeof (struct rldb_plugin_iface),
    EJUDGE_PLUGIN_IFACE_VERSION,
    "rldb",
    "mysql",
  },
  RLDB_PLUGIN_IFACE_VERSION,

  init_func,
  finish_func,
  prepare_func,
};

#include "mysql_utils.inc.c"
#include "mysql_values.inc.c"

static struct rldb_plugin_data *
init_func(void)
{
  struct rldb_mysql_state *state = 0;
  XCALLOC(state, 1);
  state->show_queries = 1;
  return (struct rldb_plugin_data*) state;
}

static int
finish_func(struct rldb_plugin_data *data)
{
  struct rldb_mysql_state *state = (struct rldb_mysql_state*) data;

  if (state->nref > 0) {
    err("rldb_mysql::finish: reference counter > 0");
    return -1;
  }

  my_free_res(state);
  if (state->conn) mysql_close(state->conn);
  xfree(state->user);
  xfree(state->password);
  xfree(state->database);
  xfree(state->host);
  xfree(state->socket);
  xfree(state->table_prefix);
  xfree(state->charset);

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

static const unsigned char *charset_mappings[][2] =
{
  { "utf-8", "utf8" },
  { "koi8-r", "koi8r" },

  { 0, 0 },
};

static int
prepare_func(
        struct rldb_plugin_data *data,
        struct ejudge_cfg *config,
        struct xml_tree *tree)
{
  struct rldb_mysql_state *state = (struct rldb_mysql_state*) data;
  const struct xml_parse_spec *spec = ejudge_cfg_get_spec();
  const struct xml_attr *a = 0;
  struct xml_tree *p = 0;
  const unsigned char *cs = 0;
  int i;

  ASSERT(tree->tag == spec->default_elem);
  ASSERT(!strcmp(tree->name[0], "config"));

  if (xml_empty_text_c(tree) < 0) return -1;

  for (a = tree->first; a; a = a->next) {
    ASSERT(a->tag == spec->default_attr);
    if (!strcmp(a->name[0], "show_queries")) {
      if (xml_attr_bool(a, &state->show_queries) < 0) return -1;
    } else {
      return xml_err_attr_not_allowed(p, a);
    }
  }

  for (p = tree->first_down; p; p = p->right) {
    ASSERT(p->tag == spec->default_elem);
    if (!strcmp(p->name[0], "user")) {
      if (xml_leaf_elem(p, &state->user, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "password")) {
      if (xml_leaf_elem(p, &state->password, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "database")) {
      if (xml_leaf_elem(p, &state->database, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "host")) {
      if (xml_leaf_elem(p, &state->host, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "socket")) {
      if (xml_leaf_elem(p, &state->socket, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "table_prefix")) {
      if (xml_leaf_elem(p, &state->table_prefix, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "port")) {
      if (p->first) return xml_err_attrs(p);
      if (p->first_down) return xml_err_nested_elems(p);
      if (state->port > 0) return xml_err_elem_redefined(p);
      if (xml_parse_int("", p->line, p->column, p->text,
                        &state->port) < 0) return -1;
    } else if (!strcmp(p->name[0], "charset")) {
      if (xml_leaf_elem(p, &state->charset, 1, 0) < 0) return -1;
    } else {
      return xml_err_elem_not_allowed(p);
    }
  }

  if (!state->user) return xml_err_elem_undefined_s(tree, "user");
  if (!state->password) return xml_err_elem_undefined_s(tree, "password");
  if (!state->database) return xml_err_elem_undefined_s(tree, "database");
  if (!state->table_prefix) state->table_prefix = xstrdup("");
  if (!state->charset) {
    if (config) cs = config->charset;
#if defined EJUDGE_CHARSET
    if (!cs) cs = EJUDGE_CHARSET;
#endif /* EJUDGE_CHARSET */
    // remap charset, since mysql has different charset names
    if (cs) {
      for (i = 0; charset_mappings[i][0]; i++) {
        if (!strcasecmp(charset_mappings[i][0], cs))
          state->charset = xstrdup(charset_mappings[i][1]);
      }
    }
  }

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
