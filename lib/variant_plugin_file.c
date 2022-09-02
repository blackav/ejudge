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
#include "ejudge/common_plugin.h"
#include "ejudge/variant_plugin.h"
#include "ejudge/contests.h"
#include "ejudge/xalloc.h"

struct variant_file_data
{
    struct variant_plugin_data b;
    int nref;
};

static struct common_plugin_data *
init_func(void)
{
    struct variant_file_data *state = NULL;
    XCALLOC(state, 1);
    return &state->b.b;
}

static int
finish_func(struct common_plugin_data *data)
{
    return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    [[gnu::unused]]
    struct variant_file_data *vmd = (struct variant_file_data *) data;

    return 0;
}

struct variant_cnts_file_data
{
    struct variant_cnts_plugin_data b;
    struct variant_file_data *vfd;
    int contest_id;
};

extern struct variant_plugin_iface plugin_variant_file;

static struct variant_cnts_plugin_data *
open_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags)
{
    struct variant_file_data *vfd = (struct variant_file_data *) data;

    struct variant_cnts_file_data *vcfd = NULL;
    XCALLOC(vcfd, 1);
    vcfd->b.vt = &plugin_variant_file;
    vcfd->vfd = vfd;
    vcfd->contest_id = cnts->id;
    ++vfd->nref;
    
    return &vcfd->b;
}

static struct variant_cnts_plugin_data *
close_func(
        struct variant_cnts_plugin_data *data)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;
    if (vcfd) {
        if (vcfd->vfd && vcfd->vfd->nref > 0) {
            --vcfd->vfd->nref;
        }
        xfree(vcfd);
    }
    return NULL;
}

struct variant_plugin_iface plugin_variant_file =
{
    {
        {
            sizeof (struct variant_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "variant",
            "file",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    VARIANT_PLUGIN_IFACE_VERSION,
    open_func,
    close_func,
};
