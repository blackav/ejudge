/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __USERPROB_PLUGIN_H__
#define __USERPROB_PLUGIN_H__

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

#define USERPROB_PLUGIN_IFACE_VERSION 1

struct userprob_plugin_data
{
    struct common_plugin_data b;
};

struct userprob_plugin_iface;

struct userprob_cnts_plugin_data
{
    struct userprob_plugin_iface *vt;
};

struct userprob_plugin_iface
{
    struct common_plugin_iface b;
    int userprob_version;
};

struct ejudge_cfg;
struct contest_desc;
struct serve_state;

struct userprob_cnts_plugin_data *
userprob_plugin_open(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct serve_state *state,
        const unsigned char *plugin_name,
        int flags);

#endif /* __SUBMIT_PLUGIN_H__ */
