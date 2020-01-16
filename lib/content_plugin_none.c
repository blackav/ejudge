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
#include "ejudge/xalloc.h"

#include <string.h>

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *data);
static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree);

static int
is_enabled_func(struct content_plugin_data *data, const struct contest_desc *cnts);

static struct content_plugin_iface plugin_content_none =
{
    {
        {
            sizeof(struct content_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "content",
            "none",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    CONTENT_PLUGIN_IFACE_VERSION,
    is_enabled_func,
    NULL, // generate_url_generator
    NULL, // save_content
    NULL, // get_url
};

struct common_plugin_iface *
plugin_content_none_get_iface(void)
{
    return &plugin_content_none.b;
}

static struct common_plugin_data *
init_func(void)
{
    struct content_plugin_data *state = NULL;
    XCALLOC(state, 1);
    return &state->b;
}

static int
finish_func(struct common_plugin_data *data)
{
    struct content_plugin_data *state = (struct content_plugin_data*) data;
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
    return 0;
}

static int
is_enabled_func(struct content_plugin_data *data, const struct contest_desc *cnts)
{
    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
