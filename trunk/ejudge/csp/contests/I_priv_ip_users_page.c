/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "new_server_pi.h"
#include "new-server.h"
#include "contests.h"
#include "userlist_clnt.h"

#include "reuse/xalloc.h"
#include "reuse/logger.h"

extern int
csp_view_priv_ip_users_page(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);

static void
destroy_func(
        PageInterface *ps)
{
}

static int
execute_func(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    return 0;
}

static struct PageInterfaceOps ops =
{
    destroy_func,
    execute_func,
    csp_view_priv_ip_users_page,
};

PageInterface *
csp_get_priv_ip_users_page(void)
{
    PrivViewIPUsersPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
