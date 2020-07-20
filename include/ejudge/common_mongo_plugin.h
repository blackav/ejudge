/* -*- c -*- */

#ifndef __COMMON_MONGO_PLUGIN_H__
#define __COMMON_MONGO_PLUGIN_H__

/* Copyright (C) 2015-2019 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"

#include "ejudge/ejudge_plugin.h"
#include "ejudge/common_plugin.h"

#define COMMON_MONGO_PLUGIN_IFACE_VERSION 2

#if HAVE_LIBMONGOC - 0 > 0
struct _mongoc_client_t;
struct _bson_t;

typedef struct _mongoc_client_t ej_mongo_conn_t;
typedef struct _bson_t ej_bson_t;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
struct _mongo_sync_connection;
struct _bson;

typedef struct _mongo_sync_connection ej_mongo_conn_t;
typedef struct _bson ej_bson_t;
#else
struct mongo_connection_missing;
struct bson_definition_missing;

typedef struct mongo_connection_missing ej_mongo_conn_t;
typedef struct bson_definition_missing ej_bson_t;
#endif

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

    ej_mongo_conn_t *conn;
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
        const ej_bson_t *query,
        const ej_bson_t *sel,
        ej_bson_t ***p_res);
    int (*insert)(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *b);
    int (*insert_and_free)(
        struct common_mongo_state *state,
        const unsigned char *table,
        ej_bson_t **b);
    int (*update)(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *selector,
        const ej_bson_t *update);
    int (*update_and_free)(
        struct common_mongo_state *state,
        const unsigned char *table,
        ej_bson_t **selector,
        ej_bson_t **update);
    int (*index_create)(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *b);
    int (*remove)(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *selector);
    int (*upsert)(
        struct common_mongo_state *state,
        const unsigned char *table,
        const ej_bson_t *selector,
        const ej_bson_t *update);
    int (*upsert_and_free)(
        struct common_mongo_state *state,
        const unsigned char *table,
        ej_bson_t **selector,
        ej_bson_t **update);
};

#endif /* __COMMON_MONGO_PLUGIN_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
