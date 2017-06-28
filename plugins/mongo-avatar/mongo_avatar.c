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
#include "ejudge/common_mongo_plugin.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#include <string.h>

struct avatar_mongo_state
{
    struct common_mongo_state *common;
    int nref;
    unsigned char *avatar_table;
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

struct avatar_plugin_iface plugin_avatar_mongo =
{
    {
        {
            sizeof(struct avatar_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "avatar",
            "mongo",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    AVATAR_PLUGIN_IFACE_VERSION,
};

static struct common_plugin_data *
init_func(void)
{
    struct avatar_mongo_state *state = NULL;
    XCALLOC(state, 1);
    return (struct common_plugin_data *) state;
}

static int
finish_func(struct common_plugin_data *data)
{
    struct avatar_mongo_state *state = (struct avatar_mongo_state *) data;

    if (state) {
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
    struct avatar_mongo_state *state = (struct avatar_mongo_state *) data;

    const struct common_loaded_plugin *common_plugin = NULL;
    if (!(common_plugin = plugin_load_external(0, "common", "mongo", config))) {
        err("cannot load common_mongo plugin");
        return -1;
    }

    state->common = (struct common_mongo_state *) common_plugin->data;
    unsigned char buf[1024];
    snprintf(buf, sizeof(buf), "%s.%savatar", state->common->database, state->common->table_prefix);
    state->avatar_table = xstrdup(buf);

    return 0;
}


