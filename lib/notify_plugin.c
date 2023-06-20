/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/notify_plugin.h"
#include "ejudge/errlog.h"

#include <string.h>

enum { PLUGIN_NUM_LIMIT = 128 };

struct notify_plugin_info
{
    struct notify_plugin_data *data;
    unsigned char failed;
};

static struct notify_plugin_info plugins[PLUGIN_NUM_LIMIT];

static void
load_registered_plugins(
        const struct ejudge_cfg *config)
{
    for (const struct xml_tree *p = config->plugin_list; p; p = p->right) {
        const struct ejudge_plugin *plg = (const struct ejudge_plugin*) p;
        if (!plg->load_flag || strcmp(plg->type, "notify") != 0) {
            continue;
        }

        const struct common_loaded_plugin *lp = plugin_load_external(plg->path, plg->type, plg->name, config);
        if (!lp) {
            err("cannot load plugin %s, %s", plg->type, plg->name);
            continue;
        }
        int serial = ((struct notify_plugin_iface *) lp->iface)->get_registered_number((struct notify_plugin_data *)lp->data);
        if (serial <= 0 || serial >= PLUGIN_NUM_LIMIT) {
            err("invalid reg num %d of plugin %s, %s", serial, plg->type, plg->name);
            continue;
        }
        if (plugins[serial].data) {
            err("reg num %d of plugin %s, %s already taken", serial, plg->type, plg->name);
            continue;
        }
        plugins[serial].data = (struct notify_plugin_data *)lp->data;
    }

    for (int i = 0; i < PLUGIN_NUM_LIMIT; ++i) {
        if (!plugins[i].data) {
            plugins[i].failed = 1;
        }
    }
}

struct notify_plugin_data *
notify_plugin_get(
        const struct ejudge_cfg *config,
        int serial)
{
    if (serial <= 0 || serial >= PLUGIN_NUM_LIMIT) {
        return NULL;
    }
    struct notify_plugin_info *pi = &plugins[serial];
    if (pi->failed) {
        return NULL;
    }
    if (!pi->data) {
        load_registered_plugins(config);
    }
    if (pi->failed) {
        return NULL;
    }

    return pi->data;
}
