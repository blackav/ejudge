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
#include "ejudge/userprob_plugin.h"
#include "ejudge/errlog.h"

#include <string.h>

struct userprob_entry *
userprob_entry_free(struct userprob_entry *ue)
{
    if (ue) {
        free(ue->lang_name);
        free(ue->hook_id);
        free(ue->gitlab_token);
        free(ue->vcs_type);
        free(ue->vcs_url);
        free(ue->vcs_subdir);
        free(ue->vcs_branch_spec);
        free(ue->ssh_private_key);
        free(ue->last_event);
        free(ue->last_revision);
        free(ue->message);
        memset(ue, 0xff, sizeof(*ue));
        free(ue);
    }
    return NULL;
}

struct userprob_plugin_data *
userprob_plugin_get(
        const struct ejudge_cfg *config,
        const unsigned char *plugin_name,
        int flags)
{
    const struct common_loaded_plugin *loaded_plugin = NULL;

    if (!plugin_name) plugin_name = "mysql";

    if ((loaded_plugin = plugin_get("userprob", plugin_name))) {
        ((struct userprob_plugin_iface *) loaded_plugin->iface)->open((struct userprob_plugin_data *)loaded_plugin->data);
        return (struct userprob_plugin_data *) loaded_plugin->data;
    }

    if (!config) {
        err("cannot load any plugin");
        return NULL;
    }

    const struct xml_tree *p = NULL;
    const struct ejudge_plugin *plg = NULL;
    for (p = config->plugin_list; p; p = p->right) {
        plg = (const struct ejudge_plugin*) p;
        if (plg->load_flag && !strcmp(plg->type, "userprob")
            && !strcmp(plg->name, plugin_name))
            break;
    }
    if (!p || !plg) {
        err("userprob plugin '%s' is not registered", plugin_name);
        return NULL;
    }

    loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
    if (!loaded_plugin) {
        err("cannot load plugin %s, %s", plg->type, plg->name);
        return NULL;
    }
    ((struct userprob_plugin_iface *) loaded_plugin->iface)->open((struct userprob_plugin_data *)loaded_plugin->data);
    return (struct userprob_plugin_data *) loaded_plugin->data;
}
