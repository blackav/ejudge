/* -*- c -*- */

#ifndef __CONTENT_PLUGIN_H__
#define __CONTENT_PLUGIN_H__

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

#include "ejudge/ejudge_plugin.h"
#include "ejudge/common_plugin.h"

/* version of the plugin interface structure */
#define CONTENT_PLUGIN_IFACE_VERSION 1

struct content_plugin_data
{
    struct common_plugin_data b;
};

struct contest_desc;

struct content_plugin_iface
{
    struct common_plugin_iface b;
    int content_version;

    int (*is_enabled)(struct content_plugin_data *, const struct contest_desc *);
    void (*generate_url_generator)(
        struct content_plugin_data *,
        const struct contest_desc *,
        FILE *fout,
        const unsigned char *fun_name);
    int (*save_content)(
        struct content_plugin_data *,
        FILE *log_f,
        const struct ejudge_cfg *,
        const struct contest_desc *,
        const unsigned char *key,
        const unsigned char *suffix,
        const unsigned char *content_data,
        size_t content_size);
    int (*get_url)(
        struct content_plugin_data *,
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const unsigned char *key,
        const unsigned char *suffix);
};

struct content_loaded_plugin
{
    const struct common_loaded_plugin *common;
    unsigned char *name;
    struct content_plugin_iface *iface;
    struct content_plugin_data *data;
};

struct contest_extra;
struct contest_desc;
struct ejudge_cfg;

struct content_loaded_plugin *
content_plugin_get(
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config,
        const unsigned char *plugin_name);

struct content_loaded_plugin *
content_plugin_destroy(struct content_loaded_plugin *);

#endif /* __CONTENT_PLUGIN_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
