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
#include "ejudge/bson_utils.h"
#include "ejudge/mime_type.h"

#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#include <string.h>
#include <mongo.h>

struct avatar_mongo_state
{
    struct avatar_plugin_data b;
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
static int
insert_func(
        struct avatar_plugin_data *data,
        int user_id,
        int contest_id,
        int is_cropped,
        int is_temporary,
        int is_public,
        int mime_type,
        int width,
        int height,
        const unsigned char *random_key,
        time_t create_time,
        const unsigned char *img_data,
        size_t img_size,
        unsigned char **p_id);

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
    insert_func,
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
    snprintf(buf, sizeof(buf), "%savatars", state->common->table_prefix);
    state->avatar_table = xstrdup(buf);

    return 0;
}

static int
insert_func(
        struct avatar_plugin_data *data,
        int user_id,
        int contest_id,
        int is_cropped,
        int is_temporary,
        int is_public,
        int mime_type,
        int width,
        int height,
        const unsigned char *random_key,
        time_t create_time,
        const unsigned char *img_data,
        size_t img_size,
        unsigned char **p_id)
{
    struct avatar_mongo_state *state = (struct avatar_mongo_state *) data;

    bson *res = bson_new();
    bson_append_int32(res, "user_id", user_id);
    bson_append_int32(res, "contest_id", contest_id);
    bson_append_boolean(res, "is_cropped", is_cropped);
    bson_append_boolean(res, "is_temporary", is_temporary);
    bson_append_boolean(res, "is_public", is_public);
    const unsigned char *mime_type_str = mime_type_get_type(mime_type);
    bson_append_string(res, "mime_type", mime_type_str, strlen(mime_type_str));
    bson_append_int32(res, "width", width);
    bson_append_int32(res, "height", height);
    bson_append_string(res, "random_key", random_key, strlen(random_key));
    bson_append_utc_datetime(res, "create_time", create_time * 1000LL);
    bson_append_int64(res, "size", (long long) img_size);
    bson_append_binary(res, "image", BSON_BINARY_SUBTYPE_USER_DEFINED, img_data, img_size);
    bson_finish(res);

    // FIXME: handle errors
    state->common->i->insert_and_free(state->common, state->avatar_table, &res);
    /*
    if (state->plugin_state->common->i->insert_and_free(state->plugin_state->common, "xuser", &b) < 0) {
        return -1;
    }
     */

    res = bson_new();
    bson_append_int32(res, "random_key", 1);
    bson_finish(res);
    state->common->i->index_create(state->common, state->avatar_table, res);
    bson_free(res);

    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
