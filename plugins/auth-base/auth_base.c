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
#include "ejudge/auth_base_plugin.h"
#include "../common-mysql/common_mysql.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

struct auth_base_queue_item
{
    void (*handler)(int uid, int argc, char **argv, void *user);
    int uid;
    int argc;
    char **argv;
    void *user;
};

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

struct auth_base_plugin_iface plugin_auth_base =
{
    {
        {
            sizeof (struct auth_base_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "auth",
            "base",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    AUTH_BASE_PLUGIN_IFACE_VERSION,
    open_func,
    NULL, // check_func
};

struct auth_base_plugin_state
{
    // mysql access
    struct common_mysql_iface *mi;
    struct common_mysql_state *md;
};

static struct common_plugin_data*
init_func(void)
{
    struct auth_base_plugin_state *state;

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
    const struct common_loaded_plugin *mplg;
    if (!(mplg = plugin_load_external(0, "common", "mysql", config))) {
        err("cannot load common_mysql plugin");
        return -1;
    }

    struct auth_base_plugin_state *state = (struct auth_base_plugin_state*) data;
    state->mi = (struct common_mysql_iface*) mplg->iface;
    state->md = (struct common_mysql_state*) mplg->data;

    return 0;
}

static int
open_func(void *data)
{
  struct auth_base_plugin_state *state = (struct auth_base_plugin_state*) data;

  if (state->mi->connect(state->md) < 0)
    return -1;

  return 0;
}
