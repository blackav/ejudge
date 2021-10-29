/* -*- mode: c; c-basic-offset: 4 -*- */

#ifndef __AUTH_BASE_PLUGIN_H__
#define __AUTH_BASE_PLUGIN_H__

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

#include "ejudge/common_plugin.h"
#include "ejudge/ej_types.h"

#define AUTH_BASE_PLUGIN_IFACE_VERSION 1

struct oauth_stage1_internal;
struct oauth_stage2_internal;

struct auth_base_plugin_iface
{
    struct common_plugin_iface b;
    int auth_base_version;

    int (*open)(void *);
    int (*check)(void *);
    int (*start_thread)(void *);
    void (*enqueue_action)(
        void *data,
        void (*handler)(int uid, int argc, char **argv, void *user),
        int uid,
        int argc,
        char **argv,
        void *user);
    int (*insert_stage1)(
        void *data,
        const unsigned char *state_id,
        const unsigned char *provider,
        const unsigned char *role,
        const unsigned char *cookie,
        int contest_id,
        const unsigned char *extra_data,
        time_t create_time,
        time_t expiry_time);
    int (*extract_stage1)(
        void *data,
        const unsigned char *state_id,
        struct oauth_stage1_internal *poas1);
    void (*free_stage1)(
        void *data,
        struct oauth_stage1_internal *poas1);
    int (*insert_stage2)(
        void *data,
        struct oauth_stage2_internal *poas2);
    int (*extract_stage2)(
        void *data,
        const unsigned char *request_id,
        struct oauth_stage2_internal *poas2);
    int (*update_stage2)(
        void *data,
        const unsigned char *request_id,
        int request_status,
        const unsigned char *error_message,
        const unsigned char *response_name,
        const unsigned char *response_email,
        const unsigned char *access_token,
        const unsigned char *id_token);
    void (*free_stage2)(
        void *data,
        struct oauth_stage2_internal *poas2);
};

struct oauth_stage1_internal
{
    unsigned char *state_id;
    unsigned char *provider;
    unsigned char *role;
    unsigned char *cookie;
    int contest_id;
    unsigned char *extra_data;
    time_t create_time;
    time_t expiry_time;
};

struct oauth_stage2_internal
{
    unsigned char *request_id;
    unsigned char *provider;
    unsigned char *role;
    int request_state;
    unsigned char *request_code;
    unsigned char *cookie;
    int contest_id;
    unsigned char *extra_data;
    time_t create_time;
    time_t update_time;
    unsigned char *response_email;
    unsigned char *response_name;
    unsigned char *access_token;
    unsigned char *id_token;
    unsigned char *error_message;
};

#endif /* __AUTH_BASE_PLUGIN_H__ */
