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

#include "ejudge/avatar_plugin.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/contests.h"
#include "ejudge/new-server.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#include <string.h>

static void
avatar_info_free(struct avatar_info *av)
{
    xfree(av->random_key);
    xfree(av->img_data);
}

void
avatar_vector_free(struct avatar_info_vector *vec)
{
    for (size_t i = 0; i < vec->u; ++i) {
        avatar_info_free(&vec->v[i]);
    }
    xfree(vec->v);
    memset(vec, 0, sizeof(*vec));
}

void
avatar_vector_clear(struct avatar_info_vector *vec)
{
    for (size_t i = 0; i < vec->u; ++i) {
        avatar_info_free(&vec->v[i]);
    }
    vec->u = 0;
}

void
avatar_vector_init(struct avatar_info_vector *vec, size_t init_a)
{
    memset(vec, 0, sizeof(*vec));
    if (init_a > 0) {
        vec->a = init_a;
        vec->v = xmalloc(init_a * sizeof(vec->v[0]));
    }
}

void avatar_vector_reserve(struct avatar_info_vector *vec, size_t new_a)
{
    if (!new_a) {
        avatar_vector_free(vec);
    } else if (new_a < vec->u) {
        for (size_t i = new_a; i < vec->u; ++i) {
            avatar_info_free(&vec->v[i]);
        }
        vec->v = xrealloc(vec->v, new_a * sizeof(vec->v[0]));
        vec->u = new_a;
        vec->a = new_a;
    } else {
        vec->v = xrealloc(vec->v, new_a * sizeof(vec->v[0]));
        vec->a = new_a;
    }
}

void avatar_vector_expand(struct avatar_info_vector *vec)
{
    if (!vec->a) {
        vec->a = 1;
    } else {
        vec->a *= 2;
    }
    vec->v = xrealloc(vec->v, vec->a * sizeof(vec->v[0]));
}


#define DEFAULT_AVATAR_PLUGIN "mongo"

#define AVATAR_PLUGIN_TYPE "avatar"

struct avatar_loaded_plugin *
avatar_plugin_get(
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config,
        const unsigned char *plugin_name)
{
    if (!plugin_name && cnts) plugin_name = cnts->avatar_plugin;
    if (!plugin_name && config) plugin_name = config->default_avatar_plugin;
    if (!plugin_name) plugin_name = DEFAULT_AVATAR_PLUGIN;

    if (extra->main_avatar_plugin) {
        if (!strcmp(extra->main_avatar_plugin->name, plugin_name)) {
            return extra->main_avatar_plugin;
        }
        // FIXME: support multiple plugins per contest
        err("default avatar plugin is '%s', but plugin '%s' requested for load", extra->main_avatar_plugin->name, plugin_name);
        return NULL;
    }

    const struct ejudge_plugin *plg = NULL;
    for (const struct xml_tree *p = config->plugin_list; p; p = p->right) {
        plg = (const struct ejudge_plugin*) p;
        if (plg->load_flag && !strcmp(plg->type, AVATAR_PLUGIN_TYPE) && !strcmp(plg->name, plugin_name))
            break;
        plg = NULL;
    }
    if (!plg) {
        err("avatar plugin '%s' is not registered", plugin_name);
        return NULL;
    }

    const struct common_loaded_plugin *loaded_plugin = plugin_load_external(plg->path, plg->type, plg->name, config);
    if (!loaded_plugin) {
        err("cannot load plugin %s, %s", plg->type, plg->name);
        return NULL;
    }

    struct avatar_loaded_plugin *avt = NULL;
    XCALLOC(avt, 1);
    avt->common = loaded_plugin;
    avt->name = xstrdup(plugin_name);
    avt->iface = (struct avatar_plugin_iface*) loaded_plugin->iface;
    avt->data = (struct avatar_plugin_data*) loaded_plugin->data;

    extra->main_avatar_plugin = avt;
    return avt;
}

struct avatar_loaded_plugin *
avatar_plugin_destroy(struct avatar_loaded_plugin *plugin)
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
