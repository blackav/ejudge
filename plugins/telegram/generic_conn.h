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

struct generic_conn;

struct generic_conn_iface
{
    struct generic_conn *(*free)(
        struct generic_conn *gc);
    int (*open)(
        struct generic_conn *gc);
    const unsigned char *(*ns)(
        struct generic_conn *gc,
        const unsigned char *collection_name);
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

#endif
