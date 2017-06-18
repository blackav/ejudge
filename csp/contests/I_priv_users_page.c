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

#include "ejudge/new_server_pi.h"
#include "ejudge/new-server.h"
#include "ejudge/contests.h"
#include "ejudge/userlist.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/clarlog.h"
#include "ejudge/runlog.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

extern int
csp_view_priv_users_page(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);
static int
csp_execute_priv_users_page(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr);
static void
csp_destroy_priv_users_page(
        PageInterface *ps);

static struct PageInterfaceOps ops =
{
    csp_destroy_priv_users_page,
    csp_execute_priv_users_page,
    csp_view_priv_users_page,
};

PageInterface *
csp_get_priv_users_page(void)
{
    PrivViewPrivUsersPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
}

static void
csp_destroy_priv_users_page(
        PageInterface *ps)
{
    PrivViewUsersPage *pg = (PrivViewUsersPage*) ps;
    xfree(pg->message);
    xfree(pg);
}

static int
csp_execute_priv_users_page(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    PrivViewUsersPage *pg = (PrivViewUsersPage*) ps;
    struct contest_extra *extra = phr->extra;
    unsigned char *xml_text = NULL;
    struct userlist_list *users = NULL;
    int *run_counts = NULL;
    size_t *run_sizes = NULL;
    int *clar_counts = NULL;

    if (ns_open_ul_connection(phr->fw_state) < 0) {
        asprintf(&pg->message, "Failed to open userlist server connection");
        goto cleanup;
    }

    int err = userlist_clnt_list_all_users(ul_conn, ULS_LIST_ALL_USERS, phr->contest_id, &xml_text);
    if (err < 0) {
        asprintf(&pg->message, "Failed to get data from server");
        goto cleanup;
    }

    if (!(users = userlist_parse_str(xml_text))) {
        asprintf(&pg->message, "Failed to get data from server");
        goto cleanup;
    }

    xfree(xml_text); xml_text = NULL;

    if (users->user_map_size > 0) {
        XCALLOC(run_counts, users->user_map_size);
        XCALLOC(run_sizes, users->user_map_size);
        XCALLOC(clar_counts, users->user_map_size);
        run_get_all_statistics(extra->serve_state->runlog_state, users->user_map_size, run_counts, run_sizes);
        clar_get_all_users_usage(extra->serve_state->clarlog_state, users->user_map_size, clar_counts, NULL);
    }

cleanup:;
    xfree(xml_text);
    if (users) userlist_free(&users->b);
    xfree(run_counts);
    xfree(run_sizes);
    xfree(clar_counts);
    return 0;
}


/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
