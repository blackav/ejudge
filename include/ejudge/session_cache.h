/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __SESSION_CACHE_H__
#define __SESSION_CACHE_H__

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

#include "ejudge/config.h"
#include "ejudge/ej_types.h"

#include <time.h>

/* session cache to reduce ej-users request ratio */
struct new_session_info
{
    ej_cookie_t session_id;
    ej_cookie_t client_key;

    ej_ip_t origin_ip;          // access address
    time_t access_time;         // time of the last access
    time_t refresh_time;        // time to refresh the values
    time_t expire_time;         // cookie expiration time

    unsigned char *login;
    unsigned char *name;
    struct userlist_user *user_info;

    int cmd;     // command (PRIV_GET_COOKIE or TEAM_GET_COOKIE)
    int user_id;
    int contest_id;
    unsigned int reg_flags;

    unsigned char ssl_flag;
    signed char   locale_id;
    unsigned char priv_level;
    unsigned char role;
    unsigned char is_ws;
    unsigned char is_job;
    unsigned char team_login;
    unsigned char reg_status;
    unsigned char passwd_method;

    // these fields are from 'session_info'
    int user_view_all_runs;
    int user_view_all_clars;
    int user_viewed_section;
};

struct new_session_cache
{
    struct new_session_info *info;
    int    reserved;
    int    res_index;
    int    rehash_threshold;
    int    used;
};

struct cached_token_info
{
    unsigned char token[32];
    unsigned char used;       // 1 if this entry is used
    // whatever
};

struct token_cache
{
    struct cached_token_info *info;
    int reserved;
    int res_index;
    int rehash_threshold;
    int used;
};

struct id_cache
{
    struct new_session_cache s;
    struct token_cache t;
};

#ifdef __cplusplus
extern "C" {
#endif

void idc_init(struct id_cache *idc);

struct new_session_info * nsc_insert(struct new_session_cache *nsc, ej_cookie_t session_id, ej_cookie_t client_key);
struct new_session_info * nsc_find(struct new_session_cache *nsc, ej_cookie_t session_id, ej_cookie_t client_key);
int nsc_remove(struct new_session_cache *nsc, ej_cookie_t session_id, ej_cookie_t client_key, struct new_session_info *out);

struct cached_token_info *tc_insert(struct token_cache *tc, const unsigned char *token);
struct cached_token_info *tc_find(struct token_cache *tc, const unsigned char *token);
int tc_remove(struct token_cache *tc, const unsigned char *token, struct cached_token_info *out);

#ifdef __cplusplus
}
#endif

#endif /* __SESSION_CACHE_H__ */
