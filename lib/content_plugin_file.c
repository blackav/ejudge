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

#include "ejudge/config.h"

#include "ejudge/content_plugin.h"
#include "ejudge/contests.h"
#include "ejudge/fileutl.h"
#include "ejudge/xml_utils.h"
#include "ejudge/errlog.h"
#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"
#include "ejudge/logger.h"

#include <string.h>
#include <limits.h>

struct content_plugin_file_data
{
    struct content_plugin_data b;
    unsigned char *content_dir;
    unsigned char *content_url_prefix;
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
save_content_func(
        struct content_plugin_data *data,
        FILE *log_f,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const unsigned char *key,
        const unsigned char *suffix,
        const unsigned char *content_data,
        size_t content_size);
static int
get_url_func(
        struct content_plugin_data *data,
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const unsigned char *key,
        const unsigned char *suffix);

static int
is_enabled_func(struct content_plugin_data *data, const struct contest_desc *cnts);
static void
generate_url_generator_func(
        struct content_plugin_data *,
        const struct contest_desc *,
        FILE *fout,
        const unsigned char *fun_name);

static struct content_plugin_iface plugin_content_file =
{
    {
        {
            sizeof(struct content_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "content",
            "file",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    CONTENT_PLUGIN_IFACE_VERSION,
    is_enabled_func,
    generate_url_generator_func,
    save_content_func,
    get_url_func,
};

struct common_plugin_iface *
plugin_content_file_get_iface(void)
{
    return &plugin_content_file.b;
}

static struct common_plugin_data *
init_func(void)
{
    struct content_plugin_file_data *state = NULL;
    XCALLOC(state, 1);
    return &state->b.b;
}

static int
finish_func(struct common_plugin_data *data)
{
    struct content_plugin_file_data *state = (struct content_plugin_file_data*) data;
    if (state) {
        xfree(state->content_dir);
        xfree(state->content_url_prefix);
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
    struct content_plugin_file_data *state = (struct content_plugin_file_data*) data;

    if (tree) {
        for (struct xml_tree *p = tree->first_down; p; p = p->right) {
            if (!strcmp(p->name[0], "content_dir")) {
                if (xml_leaf_elem(p, &state->content_dir, 1, 0) < 0) return -1;
            } else if (!strcmp(p->name[0], "content_url_prefix")) {
                if (xml_leaf_elem(p, &state->content_url_prefix, 1, 0) < 0) return -1;
            }
        }
    }

    if (config->default_content_url_prefix && config->default_content_url_prefix[0]) {
        xfree(state->content_url_prefix);
        state->content_url_prefix = xstrdup(config->default_content_url_prefix);
    }

    return 0;
}

static int
is_enabled_func(struct content_plugin_data *data, const struct contest_desc *cnts)
{
    return 1;
}

static void
generate_url_generator_func(
        struct content_plugin_data *data,
        const struct contest_desc *cnts,
        FILE *fout,
        const unsigned char *fun_name)
{
    struct content_plugin_file_data *state = (struct content_plugin_file_data*) data;

    // FIXME: javascript escape chars
    const unsigned char *prefix = NULL;
    if (cnts) {
        prefix = cnts->content_url_prefix;
    }
    if (state->content_url_prefix) {
        prefix = state->content_url_prefix;
    }
    if (!prefix) prefix = "/";
    fprintf(fout,
            "function %s(avatar_id, avatar_suffix)\n"
            "{\n"
            "    if (avatar_suffix == null) avatar_suffix = \"\";\n"
            "    return \"%s\" + avatar_id + avatar_suffix;\n"
            "}\n\n",
            fun_name, prefix);
}

static int
save_content_func(
        struct content_plugin_data *data,
        FILE *log_f,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const unsigned char *key,
        const unsigned char *suffix,
        const unsigned char *content_data,
        size_t content_size)
{
    struct content_plugin_file_data *state = (struct content_plugin_file_data*) data;

    unsigned char var_dir[PATH_MAX];

    var_dir[0] = 0;
    if (!var_dir[0] && state->content_dir) {
        snprintf(var_dir, sizeof(var_dir), "%s", state->content_dir);
    }
    if (!var_dir[0] && config->var_dir) {
        snprintf(var_dir, sizeof(var_dir), "%s/content", config->var_dir);
    }
    if (!var_dir[0] && config->contests_home_dir) {
        snprintf(var_dir, sizeof(var_dir), "%s/var/content", config->contests_home_dir);
    }
#if defined EJUDGE_LOCAL_DIR
    if (!var_dir[0]) {
        snprintf(var_dir, sizeof(var_dir), "%s/content", EJUDGE_LOCAL_DIR);
    }
#endif
#if defined EJUDGE_CONTESTS_HOME_DIR
    if (!var_dir[0]) {
        snprintf(var_dir, sizeof(var_dir), "%s/var/content", EJUDGE_CONTESTS_HOME_DIR);
    }
#endif

    if (os_MakeDirPath(var_dir, 0771) < 0) {
        if (log_f) {
            fprintf(log_f, "failed to create directory '%s'", var_dir);
        }
        err("failed to create directory '%s'", var_dir);
        return -1;
    }

    if (!suffix) suffix = "";
    unsigned char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s%s", var_dir, key, suffix);
    FILE *f = fopen(path, "w");
    if (!f) {
        if (log_f) {
            fprintf(log_f, "cannot open output file '%s'", path);
        }
        err("cannot open output file '%s'", path);
        return -1;
    }
    for (size_t i = 0; i < content_size; ++i) {
        putc_unlocked(content_data[i], f);
    }
    if (ferror(f)) {
        if (log_f) {
            fprintf(log_f, "write error to '%s'", path);
        }
        err("write error to '%s'", path);
        fclose(f);
        return -1;
    }
    fclose(f); f = NULL;
    return 0;
}

static int
get_url_func(
        struct content_plugin_data *data,
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const unsigned char *key,
        const unsigned char *suffix)
{
    struct content_plugin_file_data *state = (struct content_plugin_file_data*) data;
    const unsigned char *prefix = NULL;

    if (cnts) {
        prefix = cnts->content_url_prefix;
    }
    if (state->content_url_prefix) {
        prefix = state->content_url_prefix;
    }
    if (!prefix) prefix = "/";
    if (!suffix) suffix = "";
    return snprintf(buf, size, "%s%s%s", prefix, key, suffix);
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
