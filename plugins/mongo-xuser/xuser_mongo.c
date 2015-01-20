/* -*- mode: c -*- */

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/xml_utils.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/xuser_plugin.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <mongo.h>

struct xuser_mongo_state
{
  int nref;

  unsigned char *host;
  int port;
  mongo_sync_connection *conn;
};

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);

struct xuser_plugin_iface plugin_xuser_mongo =
{
  {
    {
      sizeof(struct xuser_plugin_iface),
      EJUDGE_PLUGIN_IFACE_VERSION,
      "xuser",
      "mongo",
    },
    COMMON_PLUGIN_IFACE_VERSION,
    init_func,
    finish_func,
    prepare_func,
  },
  XUSER_PLUGIN_IFACE_VERSION,
};

static struct common_plugin_data *
init_func(void)
{
  struct xuser_mongo_state *state = NULL;
  XCALLOC(state, 1);
  return (struct common_plugin_data *) state;
}

static int
finish_func(struct common_plugin_data *data)
{
  struct xuser_mongo_state *state = (struct xuser_mongo_state *) data;

  if (state) {
    if (state->nref > 0) {
      err("xuser_mongo::finish: reference counter > 0");
      return -1;
    }

    xfree(state->host);
    memset(state, 0, sizeof(*state));
    xfree(state);
  }

  return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
  struct xuser_mongo_state *state = (struct xuser_mongo_state *) data;

  // this plugin configuration subtree is pointed by 'tree'

  for (struct xml_tree *p = tree->first_down; p; p = p->right) {
    if (!strcmp(p->name[0], "host")) {
      if (xml_leaf_elem(p, &state->host, 1, 0) < 0) return -1;
    } else if (!strcmp(p->name[0], "port")) {
      if (xml_parse_int(NULL, "", p->line, p->column, p->text, &state->port) < 0) return -1;
      if (state->port < 0 || state->port > 65535) {
        xml_err_elem_invalid(p);
        return -1;
      }
    } else {
      return xml_err_elem_not_allowed(p);
    }
  }

  if (!state->host) state->host = xstrdup("localhost");
  if (state->port <= 0) state->port = 27027;

  state->conn = mongo_sync_connect(state->host, state->port, 0);
  if (!state->conn) {
    err("cannot connect to mongodb: %s", os_ErrorMsg());
    return -1;
  }

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
