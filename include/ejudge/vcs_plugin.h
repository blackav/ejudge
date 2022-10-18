/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __VCS_PLUGIN_H__
#define __VCS_PLUGIN_H__

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

typedef void (*vcs_command_handler_t)(
        int uid,
        int argc,
        char **argv,
        void *self);

typedef void (*vcs_set_command_handler_t)(
        void *set_self,
        const unsigned char *cmd,
        vcs_command_handler_t handler,
        void *vcs_self);

#define VCS_PLUGIN_IFACE_VERSION 1

struct vcs_plugin_iface;

// the plugin state
struct vcs_plugin_data
{
    struct common_plugin_data b;
    struct vcs_plugin_iface *vt;
};

struct vcs_plugin_iface
{
    struct common_plugin_iface b;
    int vcs_version;

    int (*open)(
        struct vcs_plugin_data *data,
        const struct ejudge_cfg *config);
    void (*set_set_command_handler)(
        struct vcs_plugin_data *data,
        vcs_set_command_handler_t setter,
        void *setter_self);
    void (*set_work_dir)(
        struct vcs_plugin_data *data,
        const unsigned char *work_dir);
};

#endif /* __VCS_PLUGIN_H__ */
