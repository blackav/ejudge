/* -*- mode: c; c-basic-offset: 4 -*- */
#ifndef __MYSQL_CONN_H__
#define __MYSQL_CONN_H__

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

#include "ejudge/config.h"
#include "generic_conn.h"

#include <time.h>

struct common_mysql_iface;
struct common_mysql_state;

struct mysql_conn
{
    struct generic_conn b;

    struct common_mysql_iface *mi;
    struct common_mysql_state *md;

    int is_db_checked;
};

#endif
