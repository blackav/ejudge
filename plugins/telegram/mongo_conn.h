/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __MONGO_CONN_H__
#define __MONGO_CONN_H__

/* Copyright (C) 2016-2022 Alexander Chernov <cher@ejudge.ru> */

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
#include "generic_conn.h"

#include <time.h>

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#elif HAVE_LIBMONGOC - 0 > 0
#include <mongoc.h>
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
struct _mongo_sync_connection;
#endif

// mongo connectivity
struct mongo_conn
{
    struct generic_conn b;
#if HAVE_LIBMONGOC - 0 > 0
    mongoc_client_t *client;
#elif HAVE_LIBMONGO_CLIENT - 0 == 1
    struct _mongo_sync_connection *conn;
#endif
    time_t last_check_time;
    int token_index_created;
    unsigned char ns[128];
};

struct generic_conn *
mongo_conn_create(void);

#endif
