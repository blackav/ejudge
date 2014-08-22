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

#include "ejudge/ej_types.h"
#include "ejudge/new-server.h"
#include "ejudge/new_server_pi.h"
#include "ejudge/contests.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/runlog.h"
#include "ejudge/xml_utils.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

extern int
csp_view_priv_user_ips_page(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);

static void
destroy_func(
        PageInterface *ps)
{
    PrivViewUserIPsPage *pp = (PrivViewUserIPsPage*) ps;

    for (int i = 0; i < pp->users.u; ++i) {
        if (pp->users.v[i]) {
            xfree(pp->users.v[i]->ips);
            xfree(pp->users.v[i]);
        }
    }
    xfree(pp->users.v);
    xfree(pp);
}

static int
execute_func(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    PrivViewUserIPsPage *pp = (PrivViewUserIPsPage*) ps;
    struct contest_extra *extra = phr->extra;
    serve_state_t cs = extra->serve_state;
    int total_runs = run_get_total(cs->runlog_state);

    pp->users.a = pp->users.u = 64;
    XCALLOC(pp->users.v, pp->users.u);

    for (int run_id = 0; run_id < total_runs; ++run_id) {
        struct run_entry re;

        run_get_entry(cs->runlog_state, run_id, &re);
        if (!run_is_valid_status(re.status)) continue;
        if (re.status == RUN_EMPTY) continue;
        if (re.user_id <= 0 || re.user_id > EJ_MAX_USER_ID) continue;
        if (re.user_id >= pp->users.a) {
            int new_a = pp->users.a;
            PrivUserIPItem **new_u;
            while (new_a <= re.user_id) new_a *= 2;
            XCALLOC(new_u, new_a);
            memcpy(new_u, pp->users.v, pp->users.u * sizeof(new_u[0]));
            xfree(pp->users.v);
            pp->users.v = new_u;
            pp->users.a = new_a;
            pp->users.u = new_a;
        }
        if (!pp->users.v[re.user_id]) {
            XCALLOC(pp->users.v[re.user_id], 1);
        }
        PrivUserIPItem *ui = pp->users.v[re.user_id];
        int i = 0;
        ej_ip_t ipv6;
        run_entry_to_ipv6(&re, &ipv6);
        for (i = 0; i < ui->ip_u; ++i) {
            if (!ipv6cmp(&ui->ips[i], &ipv6))
                break;
        }
        if (i < ui->ip_u) continue;
        if (ui->ip_u >= ui->ip_a) {
            if (!ui->ip_a) ui->ip_a = 8;
            ui->ip_a *= 2;
            XREALLOC(ui->ips, ui->ip_a);
        }
        ui->ips[ui->ip_u++] = ipv6;
    }

    return 0;
}

static struct PageInterfaceOps ops =
{
    destroy_func,
    execute_func,
    csp_view_priv_user_ips_page,
};

PageInterface *
csp_get_priv_user_ips_page(void)
{
    PrivViewUserIPsPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
