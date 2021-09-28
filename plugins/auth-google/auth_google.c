/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2021 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/auth_plugin.h"
#include "ejudge/xml_utils.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"
#include "ejudge/logger.h"
#include "../common-mysql/common_mysql.h"

#include <string.h>

static struct common_plugin_data*
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);
static int
open_func(void *data);
static int
check_func(void *data);

struct auth_plugin_iface plugin_auth_google =
{
    {
        {
            sizeof (struct auth_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "auth",
            "google",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    AUTH_PLUGIN_IFACE_VERSION,
    open_func,
    check_func,
};

struct auth_google_state
{
    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;
};

static struct common_plugin_data*
init_func(void)
{
    struct auth_google_state *state;

    XCALLOC(state, 1);
    return (struct common_plugin_data*) state;
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
    // load common_mysql plugin
    const struct common_loaded_plugin *mplg;
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }

    struct auth_google_state *state = (struct auth_google_state*) data;
    state->mi = (struct common_mysql_iface*) mplg->iface;
    state->md = (struct common_mysql_state*) mplg->data;

    // handle config section
    ASSERT(tree->tag == xml_err_spec->default_elem);
    ASSERT(!strcmp(tree->name[0], "config"));
  /*
  struct xml_attr *a;



  if (xml_empty_text(tree) < 0) return -1;

  for (a = tree->first; a; a = a->next) {
    ASSERT(a->tag == xml_err_spec->default_attr);
    if (!strcmp(a->name[0], "cache_queries")) {
      if (xml_attr_bool(a, &state->cache_queries) < 0) return -1;
    } else {
      return xml_err_attr_not_allowed(tree, a);
    }
  }
     */
    return 0;
}

static int
open_func(void *data)
{
  struct auth_google_state *state = (struct auth_google_state*) data;

  if (state->mi->connect(state->md) < 0)
    return -1;

  return 0;
}

static int
check_func(void *data)
{
    struct auth_google_state *state = (struct auth_google_state*) data;

    if (!state->md->conn) return -1;

    return 0;
}
