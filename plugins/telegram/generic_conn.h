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

struct generic_conn;
struct telegram_pbs;
struct telegram_token;

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
};

struct generic_conn *
mongo_conn_create(void);

#endif
