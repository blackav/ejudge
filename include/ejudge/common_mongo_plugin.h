/* -*- c -*- */

#ifndef __COMMON_MONGO_PLUGIN_H__
#define __COMMON_MONGO_PLUGIN_H__

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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

#define COMMON_MONGO_PLUGIN_IFACE_VERSION 1

struct _mongo_sync_connection;
struct _bson;

struct common_mongo_iface;

struct common_mongo_state
{
    struct common_mongo_iface *i;
    int nref;

    unsigned char *host;
    int port;
    unsigned char *database;
    unsigned char *table_prefix;
    unsigned char *password_file;
    unsigned char *user;
    unsigned char *password;
    int show_queries;

    struct _mongo_sync_connection *conn;
};

struct common_mongo_iface
{
    struct common_plugin_iface b;
    int common_mongo_version;

    int (*query)(
        struct common_mongo_state *state,
        const unsigned char *table,
        int skip,
        int count,
        const struct _bson *query,
        const struct _bson *sel,
        struct _bson ***p_res);
    int (*insert)(
        struct common_mongo_state *state,
        const unsigned char *table,
        const struct _bson *b);
    int (*insert_and_free)(
        struct common_mongo_state *state,
        const unsigned char *table,
        struct _bson **b);
    int (*update)(
        struct common_mongo_state *state,
        const unsigned char *table,
        const struct _bson *selector,
        const struct _bson *update);
    int (*update_and_free)(
        struct common_mongo_state *state,
        const unsigned char *table,
        struct _bson **selector,
        struct _bson **update);
};

#endif /* __COMMON_MONGO_PLUGIN_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
