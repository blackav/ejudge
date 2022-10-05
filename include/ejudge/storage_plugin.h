/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __STORAGE_PLUGIN_H__
#define __STORAGE_PLUGIN_H__

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

#include "ejudge/common_plugin.h"

#define STORAGE_PLUGIN_IFACE_VERSION 1

struct storage_plugin_iface;

struct storage_plugin_data
{
    struct common_plugin_data b;
    struct storage_plugin_iface *vt;
};

struct storage_entry
{
    int64_t serial_id;
    size_t size;
    int is_temporary;
    unsigned char random_key[64];
    unsigned char sha256[64];
    int64_t create_time_us;
    int64_t last_access_time_us;
    unsigned char *content;
};

struct storage_plugin_iface
{
    struct common_plugin_iface b;
    int storage_version;

    int (*insert)(
        struct storage_plugin_data *data,
        int is_temporary,
        size_t content_size,
        const unsigned char *content,
        struct storage_entry *p_se);

    int (*get_by_serial_id)(
        struct storage_plugin_data *data,
        int64_t serial_id,
        struct storage_entry *p_se);
};

struct contest_extra;
struct contest_desc;
struct ejudge_cfg;

struct storage_plugin_data *
storage_plugin_get(
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config,
        const unsigned char *plugin_name);

#endif /* __STORAGE_PLUGIN_H__ */
