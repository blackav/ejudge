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

#include "ejudge/config.h"
#include "ejudge/variant_plugin.h"
#include "ejudge/prepare.h"
#include "ejudge/errlog.h"

#include <string.h>

extern struct variant_plugin_iface plugin_variant_file;

struct variant_cnts_plugin_data *
variant_plugin_open(
        FILE *log_f,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct serve_state *state,
        const unsigned char *plugin_name,
        int flags)
{
    const struct common_loaded_plugin *loaded_plugin = NULL;
    const struct variant_plugin_iface *iface = NULL;

    if (!plugin_register_builtin(&plugin_variant_file.b, config)) {
        err("cannot register default plugin");
        return NULL;
    }

    if (!plugin_name) {
        if (state->global) plugin_name = state->global->variant_plugin;
    }
    if (!plugin_name) plugin_name = "";
    if (!log_f) log_f = stderr;

    if (!*plugin_name || !strcmp(plugin_name, "file")) {
        if (!(loaded_plugin = plugin_get("variant", "file"))) {
            err("cannot load default plugin");
            return NULL;
        }
        iface = (struct variant_plugin_iface *) loaded_plugin->iface;
        return iface->open(loaded_plugin->data, log_f, config, cnts, state, flags);
    }

    if ((loaded_plugin = plugin_get("variant", plugin_name))) {
        iface = (struct variant_plugin_iface*) loaded_plugin->iface;
        return iface->open(loaded_plugin->data, log_f, config, cnts, state, flags);
    }

    if (!config) {
        err("cannot load any plugin");
        return NULL;
    }

    const struct xml_tree *p = NULL;
    const struct ejudge_plugin *plg = NULL;
    for (p = config->plugin_list; p; p = p->right) {
        plg = (const struct ejudge_plugin*) p;
        if (plg->load_flag && !strcmp(plg->type, "variant")
            && !strcmp(plg->name, plugin_name))
            break;
    }
    if (!p || !plg) {
        err("variant plugin '%s' is not registered", plugin_name);
        return NULL;
    }

    loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
    if (!loaded_plugin) {
        err("cannot load plugin %s, %s", plg->type, plg->name);
        return NULL;
    }

    iface = (struct variant_plugin_iface*) loaded_plugin->iface;
    return iface->open(loaded_plugin->data, log_f, config, cnts, state, flags);
}
