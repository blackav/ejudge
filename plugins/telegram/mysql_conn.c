/* -*- mode: c; c-basic-offset: 4 -*- */

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

#include "mysql_conn.h"

#include "ejudge/xalloc.h"

static struct generic_conn_iface mysql_iface =
{
};

struct generic_conn *
mysql_conn_create(void)
{
    struct mysql_conn *conn = NULL;
    XCALLOC(conn, 1);
    conn->b.vt = &mysql_iface;
    return &conn->b;
}

