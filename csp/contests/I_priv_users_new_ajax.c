/* -*- c -*- */

/* Copyright (C) 2017-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/xml_utils.h"
#include "ejudge/prepare.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

extern int
csp_view_priv_users_new_ajax(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);
static int
csp_execute_priv_users_new_ajax(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr);
static void
csp_destroy_priv_users_new_ajax(
        PageInterface *ps);

static struct PageInterfaceOps ops =
{
    csp_destroy_priv_users_new_ajax,
    csp_execute_priv_users_new_ajax,
    csp_view_priv_users_new_ajax,
};

PageInterface *
csp_get_priv_users_new_ajax(void)
{
    PrivViewUsersPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
}

static UserInfoPage *
free_user(UserInfoPage *user)
{
    xfree(user->user_login);
    xfree(user->user_name);
    xfree(user->status_str);
    xfree(user->create_time_str);
    xfree(user->last_login_time_str);
    xfree(user->avatar_store);
    xfree(user->avatar_id);
    xfree(user->avatar_suffix);
    xfree(user);
    return NULL;
}

static UserInfoPageArray *
free_users_array(UserInfoPageArray *users)
{
    if (users) {
        for (int i = 0; i < users->u; ++i) {
            free_user(users->v[i]);
        }
        xfree(users->v);
        xfree(users);
    }
    return NULL;
}

static void
csp_destroy_priv_users_new_ajax(
        PageInterface *ps)
{
    PrivViewUsersPage *pg = (PrivViewUsersPage*) ps;
    xfree(pg->message);
    free_users_array(pg->users);
    xfree(pg);
}

static int
csp_execute_priv_users_new_ajax(
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
    const struct contest_desc *cnts = phr->cnts;
    const struct section_global_data *global = extra->serve_state->global;
    int new_contest_id = cnts->id;
    if (cnts->user_contest_num > 0) new_contest_id = cnts->user_contest_num;
    int show_not_ok = 0;
    int show_invisible = 0;
    int show_banned = 0;
    int show_only_pending = 0;
    __attribute__((unused)) int _;

    if (ns_open_ul_connection(phr->fw_state) < 0) {
        _ = asprintf(&pg->message, "Failed to open userlist server connection");
        goto cleanup;
    }

    int err = userlist_clnt_list_all_users(ul_conn, ULS_LIST_ALL_USERS, phr->contest_id, &xml_text);
    if (err < 0) {
        _ = asprintf(&pg->message, "Failed to get data from server");
        goto cleanup;
    }

    if (!(users = userlist_parse_str(xml_text))) {
        _ = asprintf(&pg->message, "Failed to get data from server");
        goto cleanup;
    }

    xfree(xml_text); xml_text = NULL;

    if (users->user_map_size <= 0) {
        pg->result = 1;
        goto cleanup;
    }

    hr_cgi_param_jsbool_opt(phr, "show_not_ok", &show_not_ok, 0);
    hr_cgi_param_jsbool_opt(phr, "show_invisible", &show_invisible, 0);
    hr_cgi_param_jsbool_opt(phr, "show_banned", &show_banned, 0);
    hr_cgi_param_jsbool_opt(phr, "show_only_pending", &show_only_pending, 0);

    XCALLOC(run_counts, users->user_map_size);
    XCALLOC(run_sizes, users->user_map_size);
    XCALLOC(clar_counts, users->user_map_size);
    run_get_all_statistics(extra->serve_state->runlog_state, users->user_map_size, run_counts, run_sizes);
    clar_get_all_users_usage(extra->serve_state->clarlog_state, users->user_map_size, clar_counts, NULL);

    XCALLOC(pg->users, 1);
    pg->users->a = users->user_map_size;
    XCALLOC(pg->users->v, users->user_map_size);

    for (int user_id = 1; user_id < users->user_map_size; ++user_id) {
        struct userlist_user *u = users->user_map[user_id];
        if (!u) continue;
        const struct userlist_contest *uc = userlist_get_user_contest(u, new_contest_id);
        if (!uc) continue;

        if (show_only_pending) {
            if (uc->status != USERLIST_REG_PENDING)
                continue;
        } else {
            if (uc->status != USERLIST_REG_OK && show_not_ok <= 0) {
                continue;
            }
            int need_show = 0;
            if ((uc->flags & (USERLIST_UC_BANNED | USERLIST_UC_DISQUALIFIED | USERLIST_UC_LOCKED)) && show_banned) {
                need_show = 1;
            }
            if ((uc->flags & USERLIST_UC_INVISIBLE) && show_invisible) {
                need_show = 1;
            }
            if (!(uc->flags & (USERLIST_UC_INVISIBLE | USERLIST_UC_BANNED | USERLIST_UC_DISQUALIFIED | USERLIST_UC_LOCKED))) {
                need_show = 1;
            }
            if (!need_show) continue;
        }

        UserInfoPage *up = NULL;
        XCALLOC(up, 1);
        pg->users->v[pg->users->u++] = up;
        up->user_id = user_id;
        up->user_login = xstrdup(u->login);

        if (u->cnts0 && u->cnts0->name) {
            up->user_name = xstrdup(u->cnts0->name);
        } else {
            up->user_name = xstrdup("");
        }
        up->status = uc->status;
        up->status_str = xstrdup(userlist_unparse_reg_status(uc->status));

        if ((uc->flags & USERLIST_UC_BANNED))
            up->is_banned = 1;
        if ((uc->flags & USERLIST_UC_INVISIBLE))
            up->is_invisible = 1;
        if ((uc->flags & USERLIST_UC_LOCKED))
            up->is_locked = 1;
        if ((uc->flags & USERLIST_UC_INCOMPLETE))
            up->is_incomplete = 1;
        if ((uc->flags & USERLIST_UC_DISQUALIFIED))
            up->is_disqualified = 1;
        if ((uc->flags & USERLIST_UC_PRIVILEGED))
            up->is_privileged = 1;
        if ((uc->flags & USERLIST_UC_REG_READONLY))
            up->is_reg_readonly = 1;

        if (uc->create_time > 0) {
            up->create_time_str = xstrdup(xml_unparse_date(uc->create_time));
        } else {
            up->create_time_str = xstrdup("");
        }
        if (u->cnts0 && u->cnts0->last_login_time) {
            up->last_login_time_str = xstrdup(xml_unparse_date(u->cnts0->last_login_time));
        } else {
            up->last_login_time_str = xstrdup("");
        }

        if (u->cnts0 && u->cnts0->avatar_store && u->cnts0->avatar_store[0]) {
            up->avatar_store = xstrdup(u->cnts0->avatar_store);
        }
        if (u->cnts0 && u->cnts0->avatar_id && u->cnts0->avatar_id[0]) {
            up->avatar_id = xstrdup(u->cnts0->avatar_id);
        }
        if (u->cnts0 && u->cnts0->avatar_suffix && u->cnts0->avatar_suffix[0]) {
            up->avatar_suffix = xstrdup(u->cnts0->avatar_suffix);
        }

        up->run_count = run_counts[user_id];
        up->run_size = run_sizes[user_id];
        up->clar_count = clar_counts[user_id];

        if (global->memoize_user_results > 0) {
            up->result_score = serve_get_user_result_score(extra->serve_state, user_id);
        }
    }

    // additional sorting

    pg->result = 1;

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
