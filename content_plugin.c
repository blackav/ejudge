/* -*- mode: c -*- */

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/content_plugin.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/contests.h"
#include "ejudge/new-server.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"

#include <string.h>

#define DEFAULT_CONTENT_PLUGIN "none"

#define CONTENT_PLUGIN_TYPE "content"

struct common_plugin_iface *
plugin_content_none_get_iface(void);
struct common_plugin_iface *
plugin_content_file_get_iface(void);

struct content_loaded_plugin *
content_plugin_get(
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config,
        const unsigned char *plugin_name)
{
    if (!plugin_name && cnts) plugin_name = cnts->content_plugin;
    if (!plugin_name && config) plugin_name = config->default_content_plugin;
    if (!plugin_name) plugin_name = DEFAULT_CONTENT_PLUGIN;

    if (extra->main_content_plugin) {
        if (!strcmp(extra->main_content_plugin->name, plugin_name)) {
            return extra->main_content_plugin;
        }
        err("default content plugin is '%s', but plugin '%s' requested", extra->main_content_plugin->name, plugin_name);
        return NULL;
    }

    const struct ejudge_plugin *plg = NULL;
    for (const struct xml_tree *p = config->plugin_list; p; p = p->right) {
        plg = (const struct ejudge_plugin*) p;
        if (plg->load_flag && !strcmp(plg->type, CONTENT_PLUGIN_TYPE) && !strcmp(plg->name, plugin_name))
            break;
        plg = NULL;
    }

    const struct common_loaded_plugin *loaded_plugin = NULL;
    if (!strcmp(plugin_name, "none")) {
        loaded_plugin = plugin_register_builtin(plugin_content_none_get_iface(), config);
    } else if (!strcmp(plugin_name, "file")) {
        loaded_plugin = plugin_register_builtin(plugin_content_file_get_iface(), config);
    } else {
        if (!plg) {
            err("content plugin '%s' is not registered", plugin_name);
            return NULL;
        }
        loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
    }
    if (!loaded_plugin) {
        err("cannot load plugin %s, %s", CONTENT_PLUGIN_TYPE, plugin_name);
        return NULL;
    }

    struct content_loaded_plugin *cp = NULL;
    XCALLOC(cp, 1);
    cp->common = loaded_plugin;
    cp->name = xstrdup(plugin_name);
    cp->iface = (struct content_plugin_iface *) loaded_plugin->iface;
    cp->data = (struct content_plugin_data *) loaded_plugin->data;

    extra->main_content_plugin = cp;
    return cp;
}

struct content_loaded_plugin *
content_plugin_destroy(struct content_loaded_plugin *plugin)
{
    if (plugin) {
        xfree(plugin->name);
        xfree(plugin);
    }
    return NULL;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
