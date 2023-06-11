/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __NOTIFY_PLUGIN_H__
#define __NOTIFY_PLUGIN_H__

/* Copyright (C) 2023 Alexander Chernov <cher@ejudge.ru> */

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

#define NOTIFY_PLUGIN_IFACE_VERSION 1

struct notify_plugin_iface;

struct notify_plugin_data
{
    struct common_plugin_data b;
    struct notify_plugin_iface *vt;
};

struct notify_plugin_iface
{
    struct common_plugin_iface b;
    int notify_version;

    int (*open)(
        struct notify_plugin_data *data);
};

struct contest_extra;
struct contest_desc;
struct ejudge_cfg;

struct notify_plugin_data *
notify_plugin_get(
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config,
        const unsigned char *plugin_name);

#endif /* __NOTIFY_PLUGIN_H__ */
