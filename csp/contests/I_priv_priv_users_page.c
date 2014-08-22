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

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

extern int
csp_view_priv_priv_users_page(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);
static int
csp_execute_priv_priv_users_page(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr);
static void
csp_destroy_priv_priv_users_page(
        PageInterface *ps);

static struct PageInterfaceOps ops =
{
    csp_destroy_priv_priv_users_page,
    csp_execute_priv_priv_users_page,
    csp_view_priv_priv_users_page,
};

PageInterface *
csp_get_priv_priv_users_page(void)
{
    PrivViewPrivUsersPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
}

static void
csp_destroy_priv_priv_users_page(
        PageInterface *ps)
{
    PrivViewPrivUsersPage *pg = (PrivViewPrivUsersPage*) ps;
    for (int i = 0; i < pg->users.u; i++) {
        if (pg->users.v[i]) {
            xfree(pg->users.v[i]->login);
            xfree(pg->users.v[i]->name);
        }
        xfree(pg->users.v[i]);
    }
    xfree(pg->users.v);
    xfree(pg);
}

static int
priv_user_info_sort_func(const void *v1, const void *v2)
{
    const struct PrivUserInfo *p1 = *(const struct PrivUserInfo**) v1;
    const struct PrivUserInfo *p2 = *(const struct PrivUserInfo**) v2;

    if (v1 == v2) return 0;
    ASSERT(p1 != p2);
    if (p1->user_id < p2->user_id) return -1;
    if (p1->user_id > p2->user_id) return 1;
    abort();
}

static int
csp_execute_priv_priv_users_page(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    PrivViewPrivUsersPage *pg = (PrivViewPrivUsersPage*) ps;

    const struct opcap_list_item *op;
    const struct contest_desc *cnts = phr->cnts;
    unsigned int role_mask;
    int user_id, i;
    unsigned char *name = 0, *login = 0;
    PrivUserInfo *pp;
    int_iterator_t iter;

    if (ns_open_ul_connection(phr->fw_state) < 0) {
        //ns_html_err_ul_server_down(fout, phr, 1, 0);
        // FIXME: report error
        return -1;
    }

  // collect all information about allowed MASTER and JUDGE logins
    for (op = CNTS_FIRST_PERM(cnts); op; op = CNTS_NEXT_PERM(op)) {
        role_mask = 0;
        if (opcaps_check(op->caps, OPCAP_MASTER_LOGIN) >= 0) {
            role_mask |= (1 << USER_ROLE_ADMIN);
        }
        if (opcaps_check(op->caps, OPCAP_JUDGE_LOGIN) >= 0) {
            role_mask |= (1 << USER_ROLE_JUDGE);
        }
        if (!role_mask) continue;
        if (userlist_clnt_lookup_user(ul_conn, op->login, 0, &user_id, &name) < 0)
            continue;
        for (i = 0; i < pg->users.u; i++)
            if (pg->users.v[i]->user_id == user_id)
                break;
        if (i < pg->users.u) {
            xfree(name);
            continue;
        }
        XEXPAND2(pg->users);
        XCALLOC(pg->users.v[pg->users.u], 1);
        pp = pg->users.v[pg->users.u++];
        pp->user_id = user_id;
        pp->login = xstrdup(op->login);
        pp->name = name;
        pp->role_mask |= role_mask;
    }

    // collect information about other roles
    for (iter = nsdb_get_contest_user_id_iterator(phr->contest_id);
         iter->has_next(iter);
         iter->next(iter)) {
        user_id = iter->get(iter);
        if (nsdb_get_priv_role_mask_by_iter(iter, &role_mask) < 0) continue;
        if (userlist_clnt_lookup_user_id(ul_conn, user_id, phr->contest_id,
                                         &login, &name) < 0)
            continue;
        for (i = 0; i < pg->users.u; i++)
            if (pg->users.v[i]->user_id == user_id)
                break;
        if (i < pg->users.u) {
            xfree(login);
            xfree(name);
            pg->users.v[i]->role_mask |= role_mask;
            continue;
        }
        XEXPAND2(pg->users);
        XCALLOC(pg->users.v[pg->users.u], 1);
        pp = pg->users.v[pg->users.u++];
        pp->user_id = user_id;
        pp->login = login;
        pp->name = name;
        pp->role_mask |= role_mask;
    }
    iter->destroy(iter); iter = 0;

    qsort(pg->users.v, pg->users.u, sizeof(pg->users.v[0]), priv_user_info_sort_func);

    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
