/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/storage_plugin.h"
#include "ejudge/errlog.h"

#include <string.h>

struct storage_plugin_data *
storage_plugin_get(
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config,
        const unsigned char *plugin_name)
{
    const struct common_loaded_plugin *loaded_plugin = NULL;

    if (!plugin_name) plugin_name = "mysql";

    if ((loaded_plugin = plugin_get("storage", plugin_name))) {
        ((struct storage_plugin_iface *) loaded_plugin->iface)->open((struct storage_plugin_data *)loaded_plugin->data);
        return (struct storage_plugin_data *) loaded_plugin->data;
    }

    if (!config) {
        err("cannot load any plugin");
        return NULL;
    }

    const struct xml_tree *p = NULL;
    const struct ejudge_plugin *plg = NULL;
    for (p = config->plugin_list; p; p = p->right) {
        plg = (const struct ejudge_plugin*) p;
        if (plg->load_flag && !strcmp(plg->type, "storage")
            && !strcmp(plg->name, plugin_name))
            break;
    }
    if (!p || !plg) {
        err("storage plugin '%s' is not registered", plugin_name);
        return NULL;
    }

    loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
    if (!loaded_plugin) {
        err("cannot load plugin %s, %s", plg->type, plg->name);
        return NULL;
    }
    ((struct storage_plugin_iface *) loaded_plugin->iface)->open((struct storage_plugin_data *)loaded_plugin->data);
    return (struct storage_plugin_data *) loaded_plugin->data;
}
