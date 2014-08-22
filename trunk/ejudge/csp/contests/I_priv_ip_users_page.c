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

#include "ejudge/new_server_pi.h"
#include "ejudge/new-server.h"
#include "ejudge/contests.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/runlog.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

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
    PrivViewIPUsersPage *pp = (PrivViewIPUsersPage *) ps;
    for (int i = 0; i < pp->ips.u; ++i) {
        xfree(pp->ips.v[i].ip_str);
        xfree(pp->ips.v[i].uids);
    }
    xfree(pp->ips.v);
    xfree(pp);
}

static int
execute_func(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    PrivViewIPUsersPage *pp = (PrivViewIPUsersPage *) ps;
    struct contest_extra *extra = phr->extra;
    serve_state_t cs = extra->serve_state;
    int total_runs = run_get_total(cs->runlog_state);

    for (int run_id = 0; run_id < total_runs; ++run_id) {
        struct run_entry re;
        run_get_entry(cs->runlog_state, run_id, &re);
        if (!run_is_valid_status(re.status)) continue;
        if (re.status == RUN_EMPTY) continue;
        if (re.user_id <= 0 || re.user_id > EJ_MAX_USER_ID) continue;
        //if (!re.a.ip) continue;
        int i;
        ej_ip_t ipv6;
        run_entry_to_ipv6(&re, &ipv6);
        for (i = 0; i < pp->ips.u; ++i) {
            if (!ipv6cmp(&pp->ips.v[i].ip, &ipv6))
                break;
        }
        if (i == pp->ips.u) {
            if (pp->ips.u == pp->ips.a) {
                if (!pp->ips.a) pp->ips.a = 16;
                pp->ips.a *= 2;
                XREALLOC(pp->ips.v, pp->ips.a);
            }
            memset(&pp->ips.v[i], 0, sizeof(pp->ips.v[i]));
            pp->ips.v[i].ip = ipv6;
            pp->ips.v[i].ip_str = xstrdup(xml_unparse_ipv6(&ipv6));
            pp->ips.u++;
        }
        int j;
        for (j = 0; j < pp->ips.v[i].uid_u; ++j)
            if (pp->ips.v[i].uids[j] == re.user_id)
                break;
        if (j == pp->ips.v[i].uid_u) {
            if (pp->ips.v[i].uid_u == pp->ips.v[i].uid_a) {
                if (!pp->ips.v[i].uid_a) pp->ips.v[i].uid_a = 16;
                pp->ips.v[i].uid_a *= 2;
                XREALLOC(pp->ips.v[i].uids, pp->ips.v[i].uid_a);
            }
            pp->ips.v[i].uids[j] = re.user_id;
            pp->ips.v[i].uid_u++;
        }
    }

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
