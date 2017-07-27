/* -*- c -*- */

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/new-server.h"
#include "ejudge/new_server_pi.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/external_action.h"

extern int
csp_view_int_public_log(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);
static int
csp_execute_int_public_log(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr);
static void
csp_destroy_int_public_log(
        PageInterface *ps);

static struct PageInterfaceOps ops __attribute__((unused)) =
{
    csp_destroy_int_public_log,
    csp_execute_int_public_log,
    csp_view_int_public_log,
};

PageInterface *
csp_get_int_public_log(void)
{
  /*
    PrivViewUsersPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
  */
  return NULL;
}

static void
csp_destroy_int_public_log(
        PageInterface *ps)
{
  /*
    PrivViewUsersPage *pg = (PrivViewUsersPage*) ps;
    xfree(pg->message);
    free_users_array(pg->users);
    xfree(pg);
  */
}

static int
csp_execute_int_public_log(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    return 0;
}


/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
