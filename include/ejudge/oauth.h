/* -*- mode: c; c-basic-offset: 4 -*- */

#ifndef __OAUTH_H__
#define __OAUTH_H__

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

unsigned char *
oauth_get_redirect_url(
        const struct ejudge_cfg *config,
        const unsigned char *provider,
        const unsigned char *role,
        const unsigned char *cookie,
        int contest_id,
        const unsigned char *extra_data);

// function for command handling
typedef void (*oauth_command_handler_t)(int uid, int argc, char **argv, void *self);

// function for registering command handler
typedef void (*oauth_set_command_handler_t)(void *set_self, const unsigned char *cmd, oauth_command_handler_t handler, void *auth_self);

unsigned char *
oauth_server_callback(
        const struct ejudge_cfg *config,
        const unsigned char *provider,
        const unsigned char *state_id,
        const unsigned char *code);

unsigned char *
oauth_server_callback_num(
        const struct ejudge_cfg *config,
        unsigned long long provider_id,
        const unsigned char *state_id,
        const unsigned char *code);

const unsigned char *
oauth_get_provider(
        const struct ejudge_cfg *config,
        unsigned long long provider_id);

struct OAuthLoginResult
{
    int status; // 0, 1 - progress; 2 - fail, 3 - success
    unsigned char *provider;
    unsigned char *role;
    unsigned char *cookie;
    unsigned char *extra_data;
    unsigned char *email;
    unsigned char *name;
    unsigned char *access_token;
    unsigned char *id_token;
    unsigned char *error_message;
    int contest_id;
};

struct OAuthLoginResult
oauth_get_result(
        const struct ejudge_cfg *config,
        const unsigned char *provider,
        const unsigned char *request_id);

void
oauth_free_result(struct OAuthLoginResult *res);

void
oauth_set_set_command_handler(
        oauth_set_command_handler_t handler,
        void *data);

int
oauth_start_thread(
        const struct ejudge_cfg *config,
        const unsigned char *provider);

int
oauth_is_available_num(
        const struct ejudge_cfg *config,
        unsigned long long provider_id);

#endif /* __OAUTH_H__ */
