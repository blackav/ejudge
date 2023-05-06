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

    unsigned char pad[8];
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
    ej_ip_t origin_ip;          // access address
    time_t access_time;         // time of the last access
    time_t expiry_time;
    time_t refresh_time;

    unsigned char *login;
    unsigned char *name;

    int cmd;
    int user_id;
    int contest_id;
    unsigned int reg_flags;
    unsigned int key_contest_id;

    unsigned char ssl_flag;
    unsigned char role;
    unsigned char reg_status;
    unsigned char all_contests;
    unsigned char used;       // 1 if this entry is used
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

    time_t last_check_time;
};

#ifdef __cplusplus
extern "C" {
#endif

void idc_init(struct id_cache *idc);

struct new_session_info * nsc_insert(struct new_session_cache *nsc, ej_cookie_t session_id, ej_cookie_t client_key);
struct new_session_info * nsc_find(struct new_session_cache *nsc, ej_cookie_t session_id, ej_cookie_t client_key);
int nsc_remove(struct new_session_cache *nsc, ej_cookie_t session_id, ej_cookie_t client_key, struct new_session_info *out);
void nsc_clear(struct new_session_cache *nsc);
void nsc_remove_expired(struct new_session_cache *nsc, time_t cur_time);

struct cached_token_info *tc_insert(struct token_cache *tc, const unsigned char *token, unsigned int key_contest_id);
struct cached_token_info *tc_find(struct token_cache *tc, const unsigned char *token, unsigned int key_contest_id);
int tc_remove(struct token_cache *tc, const unsigned char *token, unsigned int key_contest_id, struct cached_token_info *out);
void tc_clear(struct token_cache *tc);
void tc_remove_expired(struct token_cache *tc, time_t cur_time);

#ifdef __cplusplus
}
#endif

#endif /* __SESSION_CACHE_H__ */
