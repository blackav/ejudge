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

typedef void (*auth_command_handler_t)(int uid, int argc, char **argv, void *self);
typedef void (*auth_set_command_handler_t)(void *set_self, const unsigned char *cmd, auth_command_handler_t handler, void *auth_self);

typedef int (*auth_send_job_handler_t)(void *self, unsigned char **args);

struct auth_plugin_iface
{
    struct common_plugin_iface b;
    int auth_version;

    // open the database
    int (*open)(void *);
    int (*check)(void *);
    int (*start_thread)(void *);

    void (*set_set_command_handler)(
        void *data,
        auth_set_command_handler_t setter,
        void *setter_self);
    void (*set_send_job_handler)(
        void *data,
        auth_send_job_handler_t handler,
        void *handler_self);
    unsigned char * (*get_redirect_url)(
        void *data,
        const unsigned char *cookie,
        const unsigned char *provider,
        const unsigned char *role,
        int contest_id,
        const unsigned char *extra_data);
    unsigned char * (*process_auth_callback)(
        void *data,
        const unsigned char *state_id,
        const unsigned char *code);
    struct OAuthLoginResult (*get_result)(
        void *data,
        const unsigned char *job_id);
};

#endif /* __AUTH_PLUGIN_H__ */
