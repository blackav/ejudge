/* -*- c -*- */

/* Copyright (C) 2019-2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/statusdb.h"
#include "ejudge/status_plugin.h"
#include "ejudge/common_plugin.h"
#include "ejudge/errlog.h"
#include "ejudge/prepare.h"

#include <string.h>

extern struct status_plugin_iface plugin_status_file;
static int plugin_registered;

struct statusdb_state *
statusdb_open(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const unsigned char *plugin_name,
        int flags,
        int enable_migrate)
{
    if (!plugin_registered) {
        if (!plugin_register_builtin(&plugin_status_file.b, config)) {
            err("cannot register default plugin plugin_status_file");
            return NULL;
        }
        plugin_registered = 1;
    }

    if (!plugin_name) {
        if (global) plugin_name = global->status_plugin;
    }
    if (!plugin_name) plugin_name = "";

    const struct common_loaded_plugin *loaded_plugin = NULL;
    if (!plugin_name[0] || !strcmp(plugin_name, "file")) {
        if (!(loaded_plugin = plugin_get("status", "file"))) {
            err("cannot load default plugin_status_file");
            return NULL;
        }
        const struct status_plugin_iface *iface = (struct status_plugin_iface*) loaded_plugin->iface;
        return iface->open(loaded_plugin, config, cnts, global, flags);
    }

    // need file plugin for migration anyway
    const struct common_loaded_plugin *file_plugin = plugin_get("status", "file");
    if (!file_plugin) {
        err("cannot load plugin_status_file");
        return NULL;
    }

    loaded_plugin = plugin_get("status", plugin_name);
    if (!loaded_plugin) {
        if (!config) {
            err("cannot load any plugin");
            return NULL;
        }

        const struct xml_tree *p = NULL;
        const struct ejudge_plugin *plg = NULL;
        for (p = config->plugin_list; p; p = p->right) {
            plg = (const struct ejudge_plugin*) p;
            if (plg->load_flag && !strcmp(plg->type, "status")
                && !strcmp(plg->name, plugin_name))
                break;
        }
        if (!p || !plg) {
            err("status plugin '%s' is not registered", plugin_name);
            return NULL;
        }

        loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
        if (!loaded_plugin) {
            err("cannot load plugin %s, %s", plg->type, plg->name);
            return NULL;
        }
    }

    const struct status_plugin_iface *iface = (struct status_plugin_iface*) loaded_plugin->iface;
    struct statusdb_state *sds = iface->open(loaded_plugin, config, cnts, global, flags);
    if (!sds) return NULL;

    if (enable_migrate <= 0) return sds;

    // check if we need to upgrade from the file plugin
    const struct status_plugin_iface *fif = (struct status_plugin_iface*) file_plugin->iface;
    if (fif->has_status(file_plugin, config, cnts, global, flags) <= 0) {
        return sds;
    }

    // do need upgrade
    struct statusdb_state *sfs = fif->open(file_plugin, config, cnts, global, flags);
    if (!sfs) {
        err("cannot open contest %d with status_file plugin", cnts->id);
        return NULL;
    }

    struct prot_serve_status stat = {};
    int lr = fif->load(sfs, config, cnts, global, flags, &stat);
    if (lr > 0) {
        if (iface->save(sds, config, cnts, global, flags, &stat) < 0) {
            err("failed to save the contest state by plugin %s", plugin_name);
            return NULL;
        }
        info("contest %d status upgrade: %s -> %s successful", cnts->id, "file", plugin_name);
        fif->remove(sfs, config, cnts, global);
    } else if (lr < 0) {
        err("failed to load existing contest state for contest %d", cnts->id);
        // FIXME: ignore this error?
        return NULL;
    }
    fif->close(sfs); sfs = NULL;
    return sds;
}

void
statusdb_close(
        struct statusdb_state *sds)
{
    if (sds) {
        if (sds->plugin) {
            const struct status_plugin_iface *iface = (struct status_plugin_iface*) sds->plugin->iface;
            iface->close(sds);
        } else {
            free(sds);
        }
    }
}

int
statusdb_load(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        struct prot_serve_status *stat)
{
    const struct status_plugin_iface *iface = (struct status_plugin_iface*) sds->plugin->iface;
    return iface->load(sds, config, cnts, global, flags, stat);
}

int
statusdb_save(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        const struct prot_serve_status *stat)
{
    const struct status_plugin_iface *iface = (struct status_plugin_iface*) sds->plugin->iface;
    return iface->save(sds, config, cnts, global, flags, stat);
}

void
statusdb_remove(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global)
{
    const struct status_plugin_iface *iface = (struct status_plugin_iface*) sds->plugin->iface;
    iface->remove(sds, config, cnts, global);
}

int
statusdb_has_status(
        struct statusdb_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    const struct status_plugin_iface *iface = (struct status_plugin_iface*) sds->plugin->iface;
    return iface->has_status(sds->plugin, config, cnts, global, flags);
}
