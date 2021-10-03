/* -*- mode: c; c-basic-offset: 4 -*- */

#ifndef __AUTH_PLUGIN_H__
#define __AUTH_PLUGIN_H__

/* Copyright (C) 2021 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/oauth.h"

#define AUTH_PLUGIN_IFACE_VERSION 1

struct auth_plugin_iface
{
    struct common_plugin_iface b;
    int auth_version;

    // open the database
    int (*open)(void *);
    int (*check)(void *);

    void (*set_register_fd_func)(
        void *data,
        oauth_register_fd_func_t func);
    unsigned char * (*get_redirect_url)(
        void *data,
        const unsigned char *cookie,
        const unsigned char *provider,
        int contest_id,
        const unsigned char *extra_data);
    unsigned char * (*process_auth_callback)(
        void *data,
        const unsigned char *state_id,
        const unsigned char *code,
        void (*fd_register_func)(int fd, void (*callback)(int fd, void *), void *data));
};

#endif /* __AUTH_PLUGIN_H__ */
