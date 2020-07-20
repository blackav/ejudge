/* -*- mode: c -*- */

/* Copyright (C) 2017-2019 Alexander Chernov <cher@ejudge.ru> */

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

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
#include <mongo.h>
#endif

#include <string.h>

static int __attribute__((unused))
avatar_info_bson_parse(ej_bson_t *b, struct avatar_info *av)
{
#if HAVE_LIBMONGOC - 0 > 0
    bson_iter_t iter, * const bc = &iter;
    unsigned char *mt_str = NULL;
    int retval = -1;

    if (!bson_iter_init(&iter, b)) goto fail;

    while (bson_iter_next(&iter)) {
        const unsigned char *key = bson_iter_key(bc);
        if (!strcmp(key, "_id")) {
            // what to do with mongo's _id?
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int_new(bc, "user_id", &av->user_id, 1, 1, 0, 0) < 0)
                goto fail;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int_new(bc, "contest_id", &av->contest_id, 1, 0, 0, 0) < 0)
                goto fail;
        } else if (!strcmp(key, "is_cropped")) {
            if (ej_bson_parse_boolean_new(bc, "is_cropped", &av->is_cropped) < 0)
                goto fail;
        } else if (!strcmp(key, "is_temporary")) {
            if (ej_bson_parse_boolean_new(bc, "is_temporary", &av->is_temporary) < 0)
                goto fail;
        } else if (!strcmp(key, "is_public")) {
            if (ej_bson_parse_boolean_new(bc, "is_public", &av->is_public) < 0)
                goto fail;
        } else if (!strcmp(key, "mime_type")) {
            if (ej_bson_parse_string_new(bc, "mime_type", &mt_str) < 0)
                goto fail;
            int mt = mime_type_parse(mt_str);
            if (mt < 0) {
                err("avatar_info_bson_parse: invalid mime type '%s'", mt_str);
                goto fail;
            }
            if (mt < MIME_TYPE_IMAGE_FIRST || mt > MIME_TYPE_IMAGE_LAST) {
                err("avatar_info_bson_parse: mime type '%s' is not image mime type", mime_type_get_type(mt));
                goto fail;
            }
            av->mime_type = mt;
        } else if (!strcmp(key, "width")) {
            if (ej_bson_parse_int_new(bc, "width", &av->width, 1, 0, 0, 0) < 0)
                goto fail;
        } else if (!strcmp(key, "height")) {
            if (ej_bson_parse_int_new(bc, "height", &av->height, 1, 0, 0, 0) < 0)
                goto fail;
        } else if (!strcmp(key, "random_key")) {
            if (ej_bson_parse_string_new(bc, "random_key", &av->random_key) < 0)
                goto fail;
        } else if (!strcmp(key, "create_time")) {
            if (ej_bson_parse_utc_datetime_new(bc, "create_time", &av->create_time) < 0)
                goto fail;
        } else if (!strcmp(key, "size")) {
            long long llsz = 0;
            if (ej_bson_parse_int64_new(bc, "size", &llsz) < 0)
                goto fail;
            if (llsz < 0) {
                err("avatar_info_bson_parse: size < 0");
                goto fail;
            }
            if ((size_t) llsz != llsz) {
                err("avatar_info_bson_parse: size overflow");
                goto fail;
            }
            av->img_size = llsz;
        } else if (!strcmp(key, "image")) {
            //bson_append_binary(res, "image", BSON_BINARY_SUBTYPE_USER_DEFINED, img_data, img_size);
            if (bson_iter_type(bc) != BSON_TYPE_BINARY) {
                err("avatar_info_bson_parse: binary field type expected for '%s'", "image");
                goto fail;
            }
            bson_subtype_t subtype = 0;
            const uint8_t *bson_data = NULL;
            uint32_t bson_size = 0;
            bson_iter_binary(bc, &subtype, &bson_size, &bson_data);
            if (subtype != BSON_SUBTYPE_USER) {
                err("avatar_info_bson_parse: user-defined binary subtype expected for '%s'", "image");
                goto fail;
            }
            av->img_data = xmalloc(bson_size);
            memcpy(av->img_data, bson_data, bson_size);
        }
    }
    retval = 1;

fail:
    free(mt_str);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    bson_cursor *bc = NULL;
    unsigned char *mt_str = NULL;

    bc = bson_cursor_new(b);
    while (bson_cursor_next(bc)) {
        const unsigned char *key = bson_cursor_key(bc);
        if (!strcmp(key, "_id")) {
            // what to do with mongo's _id?
        } else if (!strcmp(key, "user_id")) {
            if (ej_bson_parse_int(bc, "user_id", &av->user_id, 1, 1, 0, 0) < 0)
                goto fail;
        } else if (!strcmp(key, "contest_id")) {
            if (ej_bson_parse_int(bc, "contest_id", &av->contest_id, 1, 0, 0, 0) < 0)
                goto fail;
        } else if (!strcmp(key, "is_cropped")) {
            if (ej_bson_parse_boolean(bc, "is_cropped", &av->is_cropped) < 0)
                goto fail;
        } else if (!strcmp(key, "is_temporary")) {
            if (ej_bson_parse_boolean(bc, "is_temporary", &av->is_temporary) < 0)
                goto fail;
        } else if (!strcmp(key, "is_public")) {
            if (ej_bson_parse_boolean(bc, "is_public", &av->is_public) < 0)
                goto fail;
        } else if (!strcmp(key, "mime_type")) {
            if (ej_bson_parse_string(bc, "mime_type", &mt_str) < 0)
                goto fail;
            int mt = mime_type_parse(mt_str);
            if (mt < 0) {
                err("avatar_info_bson_parse: invalid mime type '%s'", mt_str);
                goto fail;
            }
            if (mt < MIME_TYPE_IMAGE_FIRST || mt > MIME_TYPE_IMAGE_LAST) {
                err("avatar_info_bson_parse: mime type '%s' is not image mime type", mime_type_get_type(mt));
                goto fail;
            }
            av->mime_type = mt;
        } else if (!strcmp(key, "width")) {
            if (ej_bson_parse_int(bc, "width", &av->width, 1, 0, 0, 0) < 0)
                goto fail;
        } else if (!strcmp(key, "height")) {
            if (ej_bson_parse_int(bc, "height", &av->height, 1, 0, 0, 0) < 0)
                goto fail;
        } else if (!strcmp(key, "random_key")) {
            if (ej_bson_parse_string(bc, "random_key", &av->random_key) < 0)
                goto fail;
        } else if (!strcmp(key, "create_time")) {
            if (ej_bson_parse_utc_datetime(bc, "create_time", &av->create_time) < 0)
                goto fail;
        } else if (!strcmp(key, "size")) {
            long long llsz = 0;
            if (ej_bson_parse_int64(bc, "size", &llsz) < 0)
                goto fail;
            if (llsz < 0) {
                err("avatar_info_bson_parse: size < 0");
                goto fail;
            }
            if ((size_t) llsz != llsz) {
                err("avatar_info_bson_parse: size overflow");
                goto fail;
            }
            av->img_size = llsz;
        } else if (!strcmp(key, "image")) {
            //bson_append_binary(res, "image", BSON_BINARY_SUBTYPE_USER_DEFINED, img_data, img_size);
            if (bson_cursor_type(bc) != BSON_TYPE_BINARY) {
                err("avatar_info_bson_parse: binary field type expected for '%s'", "image");
                goto fail;
            }
            bson_binary_subtype subtype = 0;
            const guint8 *bson_data = NULL;
            gint32 bson_size = 0;
            if (!bson_cursor_get_binary(bc, &subtype, &bson_data, &bson_size)) {
                err("avatar_info_bson_parse: failed to fetch binary data for '%s'", "image");
                goto fail;
            }
            if (subtype != BSON_BINARY_SUBTYPE_USER_DEFINED) {
                err("avatar_info_bson_parse: user-defined binary subtype expected for '%s'", "image");
                goto fail;
            }
            av->img_data = xmalloc(bson_size);
            memcpy(av->img_data, bson_data, bson_size);
        }
    }
    bson_cursor_free(bc);
    return 1;

fail:;
    if (bc) bson_cursor_free(bc);
    xfree(mt_str);
    return -1;
#else
    return -1;
#endif
}

struct avatar_mongo_state
{
    struct avatar_plugin_data b;
    struct common_mongo_state *common;
    int nref;
    unsigned char *avatar_table;
    int avatar_table_index_created;
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
static int
fetch_by_key_func(
        struct avatar_plugin_data *data,
        const unsigned char *random_key,
        int need_image,
        struct avatar_info_vector *result);
static int
delete_by_key_func(
        struct avatar_plugin_data *data,
        const unsigned char *random_key);

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
    fetch_by_key_func,
    delete_by_key_func,
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
#if HAVE_LIBMONGOC - 0 > 0
    struct avatar_mongo_state *state = (struct avatar_mongo_state *) data;

    bson_t *res = bson_new();
    bson_append_int32(res, "user_id", -1, user_id);
    bson_append_int32(res, "contest_id", -1, contest_id);
    bson_append_bool(res, "is_cropped", -1, is_cropped);
    bson_append_bool(res, "is_temporary", -1, is_temporary);
    bson_append_bool(res, "is_public", -1, is_public);
    const unsigned char *mime_type_str = mime_type_get_type(mime_type);
    bson_append_utf8(res, "mime_type", -1, mime_type_str, -1);
    bson_append_int32(res, "width", -1, width);
    bson_append_int32(res, "height", -1, height);
    bson_append_utf8(res, "random_key", -1, random_key, -1);
    bson_append_date_time(res, "create_time", -1, create_time * 1000LL);
    bson_append_int64(res, "size", -1, (int64_t) img_size);
    bson_append_binary(res, "image", -1, BSON_SUBTYPE_USER, img_data, img_size);

    state->common->i->insert_and_free(state->common, state->avatar_table, &res);

    if (!state->avatar_table_index_created) {
        res = bson_new();
        bson_append_int32(res, "random_key", -1, 1);
        state->common->i->index_create(state->common, state->avatar_table, res);
        bson_destroy(res); res = NULL;
        state->avatar_table_index_created = 1;
    }

    return 0;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
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
#else
    return 0;
#endif
}

static int
fetch_by_key_func(
        struct avatar_plugin_data *data,
        const unsigned char *random_key,
        int omit_image,
        struct avatar_info_vector *result)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct avatar_mongo_state *state = (struct avatar_mongo_state *) data;
    bson_t *query = NULL;
    bson_t **results = NULL;
    int count = 0;
    int retval = -1;
    struct avatar_info avatar = {};

    query = bson_new();
    bson_append_utf8(query, "random_key", -1, random_key, -1);
    count = state->common->i->query(state->common, state->avatar_table, 0, 100, query, NULL, &results);
    if (count < 0) goto cleanup;
    if (count > 1) {
        err("fetch_by_key_func: multiple entries returned");
        goto cleanup;
    }
    if (!count) {
        retval = 0;
        goto cleanup;
    }
    if (avatar_info_bson_parse(results[0], &avatar) < 0) goto cleanup;
    if (result->u >= result->a) {
        avatar_vector_expand(result);
    }
    memcpy(&result->v[result->u++], &avatar, sizeof(avatar));
    retval = 1;

cleanup:;
    if (query) bson_destroy(query);
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_destroy(results[i]);
        }
        xfree(results);
    }
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct avatar_mongo_state *state = (struct avatar_mongo_state *) data;
    bson *query = NULL;
    bson **results = NULL;
    int count = 0;
    int retval = -1;
    struct avatar_info avatar;

    query = bson_new();
    bson_append_string(query, "random_key", random_key, strlen(random_key));
    bson_finish(query);

    // FIXME: also specify selector in case of omit_image != 0

    count = state->common->i->query(state->common, state->avatar_table, 0, 100, query, NULL, &results);
    if (count < 0) goto cleanup;
    if (count > 1) {
        err("fetch_by_key_func: multiple entries returned");
        goto cleanup;
    }
    if (!count) {
        retval = 0;
        goto cleanup;
    }
    memset(&avatar, 0, sizeof(avatar));
    if (avatar_info_bson_parse(results[0], &avatar) < 0) goto cleanup;
    if (result->u >= result->a) {
        avatar_vector_expand(result);
    }
    memcpy(&result->v[result->u++], &avatar, sizeof(avatar));
    retval = 1;

cleanup:;
    if (query) bson_free(query);
    if (results) {
        for (int i = 0; i < count; ++i) {
            bson_free(results[i]);
        }
        xfree(results);
    }
    return retval;
#else
    return -1;
#endif
}

static int
delete_by_key_func(
        struct avatar_plugin_data *data,
        const unsigned char *random_key)
{
#if HAVE_LIBMONGOC - 0 > 0
    struct avatar_mongo_state *state = (struct avatar_mongo_state *) data;
    int retval = -1;
    bson_t *query = NULL;
    int r;

    query = bson_new();
    bson_append_utf8(query, "random_key", -1, random_key, -1);

    r = state->common->i->remove(state->common, state->avatar_table, query);
    if (r < 0) goto cleanup;
    retval = 0;

cleanup:;
    if (query) bson_destroy(query);
    return retval;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    int retval = -1;
    struct avatar_mongo_state *state = (struct avatar_mongo_state *) data;
    bson *query = NULL;
    int r;

    query = bson_new();
    bson_append_string(query, "random_key", random_key, strlen(random_key));
    bson_finish(query);

    r = state->common->i->remove(state->common, state->avatar_table, query);
    if (r < 0) goto cleanup;
    retval = 0;

cleanup:;
    if (query) bson_free(query);
    return retval;
#else
    return -1;
#endif
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
