/* -*- c -*- */

/* Copyright (C) 2014-2020 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/super_serve_pi.h"
#include "ejudge/contests.h"
#include "ejudge/http_request.h"
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"

#include "ejudge/xalloc.h"

#include <string.h>

extern int
csp_view_main_page(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);

static void
destroy_func(
        PageInterface *ps)
{
    CspNewMainPage *pp = (CspNewMainPage *) ps;
    if (!pp) return;
    for (int i = 0; i < pp->contests.u; ++i) {
        CspContestInfo *ci = pp->contests.v[i];
        if (ci) {
            xfree(ci->name);
            xfree(ci->comment);
            xfree(ci);
        }
        pp->contests.v[i] = 0;
    }
    xfree(pp->contests.v);
    memset(pp, 0, sizeof(*pp));
    xfree(pp);
}

static const unsigned char * access_type_styles[] =
{
    "AccessStyleRed",
    "AccessStyleYellow",
    "AccessStyleGreen"
};

static int
execute_func(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    CspNewMainPage *pp = (CspNewMainPage *) ps;
    if (!pp) return 0;

    const unsigned char *contests_map = 0;
    int contest_max_id = contests_get_set(&contests_map);
    if (contest_max_id <= 0 || !contests_map) return 0;

    for (int contest_id = 1, serial = 0; contest_id < contest_max_id; ++contest_id) {
        if (!contests_map[contest_id]) {
            // FIXME: removed from map?
            continue;
        }
        int errcode = 0;
        const struct contest_desc *cnts = 0;
        if ((errcode = contests_get(contest_id, &cnts)) < 0) {
            // FIXME: display errors
            continue;
        }
        opcap_t caps = 0;
        int has_caps = opcaps_find(&cnts->capabilities, phr->login, &caps);
        if (phr->priv_level < PRIV_LEVEL_ADMIN && !(phr->ss->flags & SID_STATE_SHOW_UNMNG)) {
            // skip contests, where nor ADMIN neither JUDGE permissions are set
            if (has_caps < 0) continue;
            if (opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0 && opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0) continue;
        }
        if (has_caps < 0) caps = 0;

        if (!(phr->ss->flags & SID_STATE_SHOW_HIDDEN) && cnts->invisible) continue;
        if (!(phr->ss->flags & SID_STATE_SHOW_CLOSED) && cnts->closed) continue;

        //struct ss_contest_extra *extra = get_existing_contest_extra(contest_id);
        CspContestInfo *ci = 0;
        XCALLOC(ci, 1);
        if (pp->contests.a == pp->contests.u) {
            if (!(pp->contests.a *= 2)) pp->contests.a = 32;
            XREALLOC(pp->contests.v, pp->contests.a);
        }
        pp->contests.v[pp->contests.u++] = ci;

        ci->serial = ++serial;
        ci->id = cnts->id;
        // FIXME: choose between name and name_en
        ci->name = xstrdup(cnts->name);
        ci->closed = cnts->closed;
        ci->invisible = cnts->invisible;

        if (phr->priv_level >= PRIV_LEVEL_ADMIN && opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0
            && contests_check_serve_control_ip_2(cnts, &phr->ip, phr->ssl_flag)) {
            ci->details_enabled = 1;
            ci->edit_settings_enabled = 1;
            ci->edit_tests_enabled = 1;
        }

        if (phr->priv_level >= PRIV_LEVEL_JUDGE && opcaps_check(caps, OPCAP_LIST_USERS) >= 0
            && contests_check_serve_control_ip_2(cnts, &phr->ip, phr->ssl_flag)) {
            ci->edit_users_enabled = 1;
        }

        if (opcaps_check(caps, OPCAP_JUDGE_LOGIN) >= 0 && contests_check_judge_ip_2(cnts, &phr->ip, phr->ssl_flag)) {
            ci->judge_enabled = 1;
        }

        if (opcaps_check(caps, OPCAP_MASTER_LOGIN) >= 0 && contests_check_master_ip_2(cnts, &phr->ip, phr->ssl_flag)) {
            ci->master_enabled = 1;
        }

        if (contests_check_team_ip_2(cnts, &phr->ip, phr->ssl_flag)) {
            ci->user_enabled = 1;
        }

        ci->register_access_style = "AccessStyleGreen";
        int as = contests_get_register_access_type(cnts);
        if (as >= 0 && as <= 2) ci->register_access_style = access_type_styles[as];

        ci->users_access_style = "AccessStyleGreen";
        as = contests_get_users_access_type(cnts);
        if (as >= 0 && as <= 2) ci->users_access_style = access_type_styles[as];

        ci->client_access_style = "AccessStyleGreen";
        as = contests_get_participant_access_type(cnts);
        if (as >= 0 && as <= 2) ci->client_access_style = access_type_styles[as];

        char *addi_t = 0;
        size_t addi_z = 0;
        FILE *addi_f = open_memstream(&addi_t, &addi_z);
        if (cnts->comment) {
            fprintf(addi_f, "%s", cnts->comment);
        }
    /*

    // report "closed" flag
    fprintf(f, "<td>%s</td>", cnts->closed?"closed":"&nbsp;");

    // report run mastering status
    if (priv_level >= PRIV_LEVEL_ADMIN) {
      if (!cnts->old_run_managed && (!extra || !extra->run_used)) {
        cnt = 0;
        if (cnts && cnts->slave_rules) {
          for (p = cnts->slave_rules->first_down; p; p = p->right)
            if (p->tag == CONTEST_RUN_MANAGED_ON)
              cnt++;
        }
        if (cnt > 0) {
          fprintf(f, "<td><i>Managed on:");
          for (p = cnts->slave_rules->first_down; p; p = p->right)
            if (p->tag == CONTEST_RUN_MANAGED_ON)
              fprintf(f, " %s", p->text);
          fprintf(f, "</i></td>\n");
        } else if (cnts && cnts->run_managed) {
          fprintf(f, "<td><i>Super-run</i></td>\n");
        } else {
          fprintf(f, "<td><i>Not managed</i></td>\n");
        }
      } else if (!extra || !extra->run_used) {
        fprintf(f, "<td bgcolor=\"#ffff88\">Not yet managed</td>\n");
      } else if (!cnts->old_run_managed) {
        // still managed, but not necessary
        if (extra->run_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed, not managed</td>\n");
        } else if (extra->run_pid > 0) {
          fprintf(f, "<td bgcolor=\"#ffff88\">Running, %d, not managed</td>\n",
                  extra->run_pid);
        } else {
          fprintf(f, "<td bgcolor=\"#ffff88\">Waiting, not managed</td>\n");
        }
      } else {
        // managed as need to
        if (extra->run_suspended) {
          fprintf(f, "<td bgcolor=\"#ff8888\">Failed</td>\n");
        } else if (extra->run_pid > 0) {
          fprintf(f, "<td>Running, %d</td>\n", extra->run_pid);
        } else {
          fprintf(f, "<td>Waiting</td>\n");
        }
      }
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }

    if (priv_level >= PRIV_LEVEL_JUDGE
        && opcaps_check(caps, OPCAP_LIST_USERS) >= 0
        && contests_check_serve_control_ip_2(cnts, ip_address, ssl)) {
      fprintf(f, "<td>%sEdit users</a></td>\n", html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args, "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST, SSERV_CMD_USER_BROWSE_PAGE, contest_id));
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }

    if (priv_level >= PRIV_LEVEL_ADMIN
        && opcaps_check(caps, OPCAP_CONTROL_CONTEST) >= 0
        && contests_check_serve_control_ip_2(cnts, ip_address, ssl)) {
      fprintf(f, "<td>%sEdit settings</a></td>",
              html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                            "contest_id=%d&action=%d", contest_id,
                            SSERV_CMD_EDIT_CONTEST_XML));
      fprintf(f, "<td>%sEdit tests</a></td>\n",
              html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                            "action=%d&op=%d&contest_id=%d", SSERV_CMD_HTTP_REQUEST,
                            SSERV_CMD_TESTS_MAIN_PAGE, contest_id));
      fprintf(f, "<td>%sView details</a></td>\n",
              html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                            "contest_id=%d&action=%d", contest_id,
                            SSERV_CMD_CONTEST_PAGE));
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
      fprintf(f, "<td>&nbsp;</td>\n");
      fprintf(f, "<td>&nbsp;</td>\n");
    }

    // report judge URL
    if (opcaps_check(caps, OPCAP_JUDGE_LOGIN) >= 0 && judge_url[0]
        && contests_check_judge_ip_2(cnts, ip_address, ssl)) {
      if (cnts->managed) {
        fprintf(f, "<td><a href=\"%s?SID=%016llx&contest_id=%d&action=3\" target=\"_blank\">Judge</a></td>\n",
                new_judge_url, session_id, contest_id);
      } else {
        fprintf(f, "<td><a href=\"%s?SID=%016llx&contest_id=%d\" target=\"_blank\">Judge</a></td>\n",
                judge_url, session_id, contest_id);
      }
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }
    // report master URL
    if (opcaps_check(caps, OPCAP_MASTER_LOGIN) >= 0 && master_url[0]
        && contests_check_master_ip_2(cnts, ip_address, ssl)) {
      if (cnts->managed) {
        fprintf(f, "<td><a href=\"%s?SID=%016llx&contest_id=%d&action=3\" target=\"_blank\">Master</a></td>\n",
                new_master_url, session_id, contest_id);
      } else {
        fprintf(f, "<td><a href=\"%s?SID=%016llx&contest_id=%d\" target=\"_blank\">Master</a></td>\n",
                master_url, session_id, contest_id);
      }
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }
    // report user URL
    if (client_url[0] && contests_check_team_ip_2(cnts, ip_address, ssl)) {
      if (cnts->managed) {
        fprintf(f, "<td><a href=\"%s?contest_id=%d\" target=\"_blank\">User</a></td>\n",
                new_client_url, contest_id);
      } else {
        fprintf(f, "<td><a href=\"%s?contest_id=%d\" target=\"_blank\">User</a></td>\n",
                client_url, contest_id);
      }
    } else {
      fprintf(f, "<td>&nbsp;</td>\n");
    }
     */
        fclose(addi_f); addi_f = 0;
        ci->comment = addi_t;
        addi_t = 0; addi_z = 0;
    }

    return 0;
}

static struct PageInterfaceOps ops =
{
    destroy_func,
    execute_func,
    csp_view_main_page,
};

PageInterface *
csp_get_main_page(void)
{
    CspNewMainPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    return (PageInterface*) pg;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
