/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __GENERIC_CONN_H__
#define __GENERIC_CONN_H__

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

#include <time.h>

struct ejudge_cfg;
struct generic_conn;
struct telegram_pbs;
struct telegram_token;
struct telegram_chat;
struct telegram_chat_state;
struct telegram_subscription;

struct generic_conn_iface
{
    struct generic_conn *(*free)(
        struct generic_conn *gc);
    int (*open)(
        struct generic_conn *gc);
    const unsigned char *(*ns)(
        struct generic_conn *gc,
        const unsigned char *collection_name);

    struct telegram_pbs *(*pbs_fetch)(
        struct generic_conn *gc,
        const unsigned char *bot_id);
    int (*pbs_save)(
        struct generic_conn *gc,
        const struct telegram_pbs *pbs);

    int (*token_fetch)(
        struct generic_conn *gc,
        const unsigned char *token_str,
        struct telegram_token **p_token);
    int (*token_save)(
        struct generic_conn *gc,
        const struct telegram_token *token);
    void (*token_remove)(
        struct generic_conn *gc,
        const unsigned char *token);
    void (*token_remove_expired)(
        struct generic_conn *gc,
        time_t current_time);

    struct telegram_chat *(*chat_fetch)(
        struct generic_conn *gc,
        long long _id);
    int (*chat_save)(
        struct generic_conn *gc,
        const struct telegram_chat *tc);

    struct telegram_user *(*user_fetch)(
        struct generic_conn *gc,
        long long _id);
    int (*user_save)(
        struct generic_conn *gc,
        const struct telegram_user *tu);

    struct telegram_chat_state *(*chat_state_fetch)(
        struct generic_conn *gc,
        long long _id);
    int (*chat_state_save)(
        struct generic_conn *gc,
        const struct telegram_chat_state *tcs);

    struct telegram_subscription * (*subscription_fetch)(
        struct generic_conn *gc,
        const unsigned char *bot_id,
        int user_id,
        int contest_id);
    int (*subscription_save)(
        struct generic_conn *gc,
        const struct telegram_subscription *subscription);
};

struct generic_conn
{
    struct generic_conn_iface *vt;

    unsigned char *database;
    unsigned char *host;
    unsigned char *table_prefix;
    unsigned char *user;
    unsigned char *password;
    int port;
    int show_queries;
    const struct ejudge_cfg *ejudge_config;
};

struct generic_conn *
mongo_conn_create(void);

struct generic_conn *
mysql_conn_create(void);

#endif
