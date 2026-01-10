/* -*- mode: c -*- */

/* Copyright (C) 2025-2026 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/expat_iface.h"
#include "ejudge/json_serializers.h"
#include "ejudge/l10n.h"
#include "ejudge/meta/contests_meta.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/misctext.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/opcaps.h"
#include "ejudge/parsecfg.h"
#include "ejudge/prepare.h"
#include "ejudge/super-serve.h"
#include "ejudge/super_html.h"
#include "ejudge/super_proto.h"
#include "ejudge/type_info.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/http_request.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/contests.h"
#include "ejudge/random.h"
#include "ejudge/logger.h"
#include "ejudge/cJSON.h"
#include "ejudge/xalloc.h"
#include "ejudge/xml_utils.h"
#include "ejudge/userlist.h"
#include "ejudge/problem_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <strings.h>
#include <time.h>

int
ss_get_contest_caps(
        const struct http_request_info *phr,
        const struct contest_desc *cnts,
        opcap_t *pcap);

void
super_html_json_result(
        FILE *fout,
        struct http_request_info *phr,
        int ok,
        int err_num,
        unsigned err_id,
        const unsigned char *err_msg,
        cJSON *jr)
{
    phr->json_reply = 1;
    if (!ok) {
        if (err_num < 0)
            err_num = -err_num;
        if (!err_id) {
            random_init();
            err_id = random_u32();
        }
        if (!err_msg || !*err_msg) {
            err_msg = NULL;
            if (err_num > 0 && err_num < SSERV_ERR_LAST) {
                err_msg = super_proto_error_messages[err_num];
                if (err_msg && !*err_msg) {
                    err_msg = NULL;
                }
            }
        }
        cJSON_AddFalseToObject(jr, "ok");
        cJSON *jerr = cJSON_CreateObject();
        if (err_num > 0) {
            cJSON_AddNumberToObject(jerr, "num", err_num);
        }
        if (err_id) {
            char xbuf[64];
            sprintf(xbuf, "%08x", err_id);
            cJSON_AddStringToObject(jerr, "log_id", xbuf);
        }
        if (err_msg) {
            cJSON_AddStringToObject(jerr, "message", err_msg);
        }
        cJSON_AddItemToObject(jr, "error", jerr);
        // FIXME: log event
    } else {
        cJSON_AddTrueToObject(jr, "ok");
    }
    cJSON_AddNumberToObject(jr, "server_time", (double)phr->current_time);
    if (phr->request_id > 0) {
        cJSON_AddNumberToObject(jr, "request_id", (double)phr->request_id);
    }
    if (phr->action_str) {
        cJSON_AddStringToObject(jr, "action", phr->action_str);
    } else if (phr->action > 0 && phr->action < SSERV_CMD_LAST && super_proto_cmd_names[phr->action]) {
        cJSON_AddStringToObject(jr, "action", super_proto_cmd_names[phr->action]);
    }
    /*
    if (phr->client_state && phr->client_state->ops->get_reply_id) {
      int reply_id = phr->client_state->ops->get_reply_id(phr->client_state);
      cJSON_AddNumberToObject(jr, "reply_id", (double) reply_id);
    }
    */
    char *jrstr = cJSON_PrintUnformatted(jr);
    fprintf(fout, "%s\n", jrstr);
    free(jrstr);
}

void
super_serve_api_LOGIN_ACTION_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    const unsigned char *user_login = NULL;
    const unsigned char *user_password = NULL;
    unsigned char *user_name = NULL;
    unsigned char buf[128];
    __attribute__((unused)) int _;

    if (hr_cgi_param(phr, "login", &user_login) <= 0 || hr_cgi_param(phr, "password", &user_password) <= 0 ||
        !user_login || !user_password || !user_login[0] || !user_password[0]) {
        phr->err_num = SSERV_ERR_PERM_DENIED;
        phr->status_code = 401;
        goto done;
    }

    int user_id = 0;
    ej_cookie_t session_id = 0;
    ej_cookie_t client_key = 0;
    int priv_level = 0;
    int r;

    r = userlist_clnt_priv_login(phr->userlist_clnt, ULS_PRIV_CHECK_USER_2, &phr->ip, 0, phr->ssl_flag, 0, 0,
                                 USER_ROLE_ADMIN, user_login, user_password, &user_id, &session_id, &client_key,
                                 &priv_level, &user_name);
    if (r < 0) {
        switch (-r) {
        case ULS_ERR_INVALID_LOGIN:
        case ULS_ERR_INVALID_PASSWORD:
        case ULS_ERR_BAD_CONTEST_ID:
        case ULS_ERR_IP_NOT_ALLOWED:
        case ULS_ERR_NO_PERMS:
        case ULS_ERR_NOT_REGISTERED:
        case ULS_ERR_CANNOT_PARTICIPATE:
        case ULS_ERR_NO_COOKIE:
            phr->err_num = SSERV_ERR_PERM_DENIED;
            phr->status_code = 401;
            goto done;
        default:
            phr->err_num = SSERV_ERR_USERLIST_DOWN;
            phr->status_code = 500;
            goto done;
        }
    }
    if (priv_level != PRIV_LEVEL_ADMIN || user_id <= 0) {
        phr->err_num = SSERV_ERR_PERM_DENIED;
        phr->status_code = 401;
        goto done;
    }
    opcap_t caps = 0;
    if (ejudge_cfg_opcaps_find(phr->config, user_login, &caps) < 0) {
        phr->err_num = SSERV_ERR_PERM_DENIED;
        phr->status_code = 401;
        goto done;
    }
    if (opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0) {
        phr->err_num = SSERV_ERR_PERM_DENIED;
        phr->status_code = 401;
        goto done;
    }

    cJSON *jrr = cJSON_CreateObject();
    cJSON_AddNumberToObject(jrr, "user_id", user_id);
    cJSON_AddStringToObject(jrr, "user_login", user_login);
    if (user_name && user_name[0]) {
        cJSON_AddStringToObject(jrr, "user_name", user_name);
    }
    _ = snprintf(buf, sizeof(buf), "%016llx-%016llx", session_id, client_key);
    cJSON_AddStringToObject(jrr, "session", buf);
    _ = snprintf(buf, sizeof(buf), "%016llx", session_id);
    cJSON_AddStringToObject(jrr, "SID", buf);
    _ = snprintf(buf, sizeof(buf), "%016llx", client_key);
    cJSON_AddStringToObject(jrr, "EJSID", buf);
    cJSON_AddItemToObject(phr->json_result, "result", jrr);

done:;
    free(user_name);
}

void
super_serve_api_CNTS_START_EDIT_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    int contest_id = 0;
    unsigned char buf[128];

    int xml_only = 0;
    hr_cgi_param_bool_opt(phr, "xml_only", &xml_only, 0);

    if (hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0) < 0) {
        phr->err_num = SSERV_ERR_INV_CONTEST;
        phr->status_code = 400;
        return;
    }
    phr->contest_id = contest_id;
    const struct contest_desc *cnts = NULL;
    if (contests_get(contest_id, &cnts) < 0 || !cnts) {
        phr->err_num = SSERV_ERR_INV_CONTEST;
        phr->status_code = 400;
        return;
    }
    if (phr->priv_level != PRIV_LEVEL_ADMIN) {
        phr->err_num = SSERV_ERR_PERM_DENIED;
        phr->status_code = 401;
        return;
    }
    opcap_t caps = 0;
    ss_get_contest_caps(phr, cnts, &caps);
    if (opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
        phr->err_num = SSERV_ERR_PERM_DENIED;
        phr->status_code = 401;
        return;
    }

    const struct sid_state *other_ss = super_serve_sid_state_get_cnts_editor(phr->contest_id);
    if (other_ss && other_ss->user_id != phr->user_id) {
        phr->err_num = SSERV_ERR_CONTEST_ALREADY_EDITED;
        phr->status_code = 423;
        return;
    }

    if (other_ss) {
        // { "session": "SID-CK", "init_time": TS, "is_created": false }
        cJSON *jrr = cJSON_CreateObject();
        snprintf(buf, sizeof(buf), "%016llx-%016llx", other_ss->sid, other_ss->client_key);
        cJSON_AddStringToObject(jrr, "session", buf);
        cJSON_AddNumberToObject(jrr, "init_time", (double)other_ss->init_time);
        cJSON_AddFalseToObject(jrr, "is_created");
        cJSON_AddItemToObject(phr->json_result, "result", jrr);
        phr->status_code = 200;
        return;
    }

    random_init();
    ej_cookie_t sid = random_u64();
    ej_cookie_t client_key = random_u64();
    while (sid_state_find(sid, client_key)) {
        sid = random_u64();
        client_key = random_u64();
    }
    phr->ss = sid_state_add(sid, client_key, &phr->ip, phr->user_id, phr->login, phr->name);
    ASSERT(!phr->ss->edited_cnts);

    struct contest_desc *rw_cnts = 0;
    if (contests_load(phr->contest_id, &rw_cnts) < 0 || !rw_cnts) {
        phr->err_num = SSERV_ERR_INV_CONTEST;
        phr->status_code = 400;
        sid_state_delete(phr->config, phr->ss);
        phr->ss = NULL;
        return;
    }

    phr->ss->edited_cnts = rw_cnts;
    if (!xml_only) {
        super_html_load_serve_cfg(rw_cnts, phr->config, phr->ss);
    }

    // { "session": "SID-CK", "init_time": TS, "is_created": false }
    cJSON *jrr = cJSON_CreateObject();
    snprintf(buf, sizeof(buf), "%016llx-%016llx", phr->ss->sid, phr->ss->client_key);
    cJSON_AddStringToObject(jrr, "session", buf);
    cJSON_AddNumberToObject(jrr, "init_time", (double)phr->ss->init_time);
    cJSON_AddTrueToObject(jrr, "is_created");
    cJSON_AddItemToObject(phr->json_result, "result", jrr);
    phr->status_code = 200;
}

static int
parse_session(struct http_request_info *phr, const unsigned char *var_name, ej_cookie_t *p_sid, ej_cookie_t *p_client_key)
{
    const unsigned char *s = NULL;
    int r = hr_cgi_param(phr, var_name, &s);
    if (r <= 0) {
        return r;
    }
    if (!*s) {
        return 0;
    }
    if (!isxdigit(*s)) {
        return -1;
    }
    errno = 0;
    char *eptr = NULL;
    ej_cookie_t sid = strtoull(s, &eptr, 16);
    if (errno || *eptr != '-') {
        return -1;
    }
    s = (const unsigned char *)eptr + 1;
    if (!isxdigit(*s)) {
        return -1;
    }
    errno = 0;
    ej_cookie_t client_key = strtoull(s, &eptr, 16);
    if (errno || *eptr) {
        return -1;
    }
    *p_sid = sid;
    *p_client_key = client_key;
    return 1;
}

void
super_serve_api_CNTS_FORGET_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    // method: POST
    // parameters: session
    // parameters: other_contest_id
    // parameters: allow_other_user [true|false] - remove another user's session
    int other_contest_id = 0;
    if (hr_cgi_param_int_opt(phr, "other_contest_id", &other_contest_id, 0) < 0) {
        phr->err_num = SSERV_ERR_INV_CONTEST;
        phr->status_code = 400;
        return;
    }
    const struct contest_desc *other_cnts = NULL;
    if (other_contest_id > 0 && (contests_get(other_contest_id, &other_cnts) < 0 || !other_cnts)) {
        phr->err_num = SSERV_ERR_INV_CONTEST;
        phr->status_code = 400;
        return;
    }
    if (other_cnts) {
        struct sid_state *ss = super_serve_sid_state_get_cnts_editor_nc(other_contest_id);
        if (!ss) {
            cJSON_AddTrueToObject(phr->json_result, "result");
            phr->status_code = 200;
            return;
        }
        if (ss->user_id == phr->user_id) {
            super_serve_clear_edited_contest(ss);
            cJSON_AddTrueToObject(phr->json_result, "result");
            phr->status_code = 200;
            return;
        }
        ASSERT(ss->edited_cnts);
        opcap_t caps = 0;
        if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
            phr->err_num = SSERV_ERR_PERM_DENIED;
            phr->status_code = 401;
            return;
        }
        caps = 0;
        ss_get_contest_caps(phr, other_cnts, &caps);
        if (opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
            phr->err_num = SSERV_ERR_PERM_DENIED;
            phr->status_code = 401;
            return;
        }
        super_serve_clear_edited_contest(ss);
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    ej_cookie_t sid = 0;
    ej_cookie_t client_key = 0;
    if (parse_session(phr, "session", &sid, &client_key) <= 0) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    struct sid_state *ss = sid_state_find(sid, client_key);
    if (!ss) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    if (!ss->edited_cnts) {
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    if (ss->user_id != phr->user_id) {
        int allow_other_user = 0;
        if (hr_cgi_param_bool_opt(phr, "allow_other_user", &allow_other_user, 0) < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (allow_other_user <= 0) {
            phr->err_num = SSERV_ERR_INV_SESSION;
            phr->status_code = 400;
            return;
        }
        opcap_t caps = 0;
        if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
            phr->err_num = SSERV_ERR_INV_SESSION;
            phr->status_code = 400;
            return;
        }
    }

    super_serve_clear_edited_contest(ss);
    cJSON_AddTrueToObject(phr->json_result, "result");
    phr->status_code = 200;
}

void
super_serve_api_CNTS_LIST_SESSION_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    cJSON *jr = cJSON_CreateObject();
    cJSON *jsa = cJSON_CreateArray();
    struct sid_state *ss = super_serve_sid_state_get_first();
    opcap_t gcaps = 0;
    int has_global_edit_contest = ss_get_global_caps(phr, &gcaps) >= 0 && opcaps_check(gcaps, OPCAP_EDIT_CONTEST) >= 0;

    for (; ss; ss = ss->next) {
        if (!ss->edited_cnts) continue;
        const struct contest_desc *cnts = NULL;
        opcap_t caps = 0;
        if (ss->user_id == phr->user_id || has_global_edit_contest > 0 ||
            (contests_get(ss->edited_cnts->id, &cnts) >= 0 && cnts
             && ss_get_contest_caps(phr, ss->edited_cnts, &caps) >= 0
             && opcaps_check(caps, OPCAP_EDIT_CONTEST) >= 0)) {
            cJSON *jsai = cJSON_CreateObject();
            cJSON_AddNumberToObject(jsai, "contest_id", ss->edited_cnts->id);
            cJSON_AddNumberToObject(jsai, "user_id", ss->user_id);
            cJSON_AddStringToObject(jsai, "user_login", ss->user_login);
            if (phr->user_id == ss->user_id) {
                char sbuf[64];
                snprintf(sbuf, sizeof(sbuf), "%016llx-%016llx", ss->sid, ss->client_key);
                cJSON_AddStringToObject(jsai, "session", sbuf);
            }
            cJSON_AddItemToArray(jsa, jsai);
        }
    }

    cJSON_AddItemToObject(jr, "sessions", jsa);
    cJSON_AddItemToObject(phr->json_result, "result", jr);
    phr->status_code = 200;
}

void
super_serve_api_CNTS_COMMIT_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    ej_cookie_t sid = 0;
    ej_cookie_t client_key = 0;
    if (parse_session(phr, "session", &sid, &client_key) <= 0) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    struct sid_state *ss = sid_state_find(sid, client_key);
    if (!ss) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    phr->ss = ss;
    if (!ss->edited_cnts) {
        phr->err_num = SSERV_ERR_NO_EDITED_CNTS;
        phr->status_code = 400;
        return;
    }
    const struct contest_desc *cur_cnts = NULL;
    if (contests_get(ss->edited_cnts->id, &cur_cnts) >= 0 && cur_cnts) {
        opcap_t caps = 0;
        if (ss_get_contest_caps(phr, cur_cnts, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
            phr->err_num = SSERV_ERR_PERM_DENIED;
            phr->status_code = 401;
            return;
        }
    } else {
        opcap_t caps = 0;
        if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
            phr->err_num = SSERV_ERR_PERM_DENIED;
            phr->status_code = 401;
            return;
        }
    }
    // add editing caps for this user anyway
    opcap_t newcaps = 0;
    opcaps_find(&ss->edited_cnts->capabilities, phr->login, &newcaps);
    newcaps |= 1ULL << OPCAP_EDIT_CONTEST;
    contests_upsert_permission(ss->edited_cnts, phr->login, newcaps);

    char *comm_s = NULL;
    size_t comm_z = 0;
    FILE *comm_f = NULL;
    int r = 0;

    comm_f = open_memstream(&comm_s, &comm_z);
    r = super_html_commit_contest_2(comm_f, phr->user_id, phr->login, &phr->ip, phr->config, phr->userlist_clnt, phr->ss, 0, NULL);
    fclose(comm_f); comm_f = NULL;

    cJSON *jr = cJSON_CreateObject();
    if (r < 0) {
        cJSON_AddFalseToObject(jr, "success");
    } else {
        cJSON_AddTrueToObject(jr, "success");
    }
    cJSON_AddStringToObject(jr, "messages", comm_s);
    free(comm_s); comm_s = NULL;

    if (r >= 0) {
        super_serve_clear_edited_contest(phr->ss);
    }

    cJSON_AddItemToObject(phr->json_result, "result", jr);
    phr->status_code = 200;
}

void
super_serve_api_CNTS_DRY_COMMIT_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    ej_cookie_t sid = 0;
    ej_cookie_t client_key = 0;
    if (parse_session(phr, "session", &sid, &client_key) <= 0) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    struct sid_state *ss = sid_state_find(sid, client_key);
    if (!ss) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    phr->ss = ss;
    if (!ss->edited_cnts) {
        phr->err_num = SSERV_ERR_NO_EDITED_CNTS;
        phr->status_code = 400;
        return;
    }
    const struct contest_desc *cur_cnts = NULL;
    if (contests_get(ss->edited_cnts->id, &cur_cnts) >= 0 && cur_cnts) {
        opcap_t caps = 0;
        if (ss_get_contest_caps(phr, cur_cnts, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
            phr->err_num = SSERV_ERR_PERM_DENIED;
            phr->status_code = 401;
            return;
        }
    } else {
        opcap_t caps = 0;
        if (ss_get_global_caps(phr, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
            phr->err_num = SSERV_ERR_PERM_DENIED;
            phr->status_code = 401;
            return;
        }
    }
    // add editing caps for this user anyway
    opcap_t newcaps = 0;
    opcaps_find(&ss->edited_cnts->capabilities, phr->login, &newcaps);
    newcaps |= 1ULL << OPCAP_EDIT_CONTEST;
    contests_upsert_permission(ss->edited_cnts, phr->login, newcaps);

    char *comm_s = NULL;
    size_t comm_z = 0;
    FILE *comm_f = NULL;
    int r = 0;

    comm_f = open_memstream(&comm_s, &comm_z);
    r = super_html_commit_contest_2(comm_f, phr->user_id, phr->login, &phr->ip, phr->config, phr->userlist_clnt, phr->ss, 1, NULL);
    fclose(comm_f); comm_f = NULL;

    cJSON *jr = cJSON_CreateObject();
    if (r < 0) {
        cJSON_AddFalseToObject(jr, "success");
    } else {
        cJSON_AddTrueToObject(jr, "success");
    }
    cJSON_AddStringToObject(jr, "messages", comm_s);
    free(comm_s); comm_s = NULL;

    if (r >= 0) {
        super_serve_clear_edited_contest(phr->ss);
    }

    cJSON_AddItemToObject(phr->json_result, "result", jr);
    phr->status_code = 200;
}

void
super_serve_api_CHECK_TESTS_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    int contest_id = 0;
    if (hr_cgi_param_int(phr, "contest_id", &contest_id) <= 0) {
        phr->err_num = SSERV_ERR_INV_CONTEST;
        phr->status_code = 400;
        return;
    }
    const struct contest_desc *cnts = NULL;
    if (contests_get(contest_id, &cnts) < 0 || !cnts) {
        phr->err_num = SSERV_ERR_INV_CONTEST;
        phr->status_code = 400;
        return;
    }
    phr->contest_id = contest_id;
    phr->cnts = cnts;
    opcap_t caps = 0;
    if (ss_get_contest_caps(phr, cnts, &caps) < 0 || opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
        phr->err_num = SSERV_ERR_PERM_DENIED;
        phr->status_code = 401;
        return;
    }
    const struct sid_state *other_ss = super_serve_sid_state_get_cnts_editor(phr->contest_id);
    if (other_ss) {
        phr->err_num = SSERV_ERR_CONTEST_ALREADY_EDITED;
        phr->status_code = 423;
        return;
    }

    random_init();
    ej_cookie_t sid = random_u64();
    ej_cookie_t client_key = random_u64();
    while (sid_state_find(sid, client_key)) {
        sid = random_u64();
        client_key = random_u64();
    }
    phr->ss = sid_state_add(sid, client_key, &phr->ip, phr->user_id, phr->login, phr->name);
    ASSERT(!phr->ss->edited_cnts);

    struct contest_desc *rw_cnts = 0;
    if (contests_load(phr->contest_id, &rw_cnts) < 0 || !rw_cnts) {
        // FIXME: memleak on rw_cnts
        phr->err_num = SSERV_ERR_INV_CONTEST;
        phr->status_code = 400;
        return;
    }
    phr->ss->edited_cnts = rw_cnts;
    super_html_load_serve_cfg(rw_cnts, phr->config, phr->ss);

    char *log_t = 0;
    size_t log_z = 0;
    FILE *log_f = open_memstream(&log_t, &log_z);
    int r = super_html_new_check_tests(log_f, phr->config, phr->ss);
    fclose(log_f); log_f = NULL;
    super_serve_clear_edited_contest(phr->ss);

    cJSON *jr = cJSON_CreateObject();
    if (r < 0) {
        cJSON_AddFalseToObject(jr, "success");
    } else {
        cJSON_AddTrueToObject(jr, "success");
    }
    cJSON_AddStringToObject(jr, "messages", log_t);
    free(log_t); log_t = NULL;

    if (r >= 0) {
        super_serve_clear_edited_contest(phr->ss);
    }

    cJSON_AddItemToObject(phr->json_result, "result", jr);
    phr->status_code = 200;
}

enum
{
    FILE_USERS_HEADER = 1,
    FILE_USERS_FOOTER,
    FILE_REGISTER_HEADER,
    FILE_REGISTER_FOOTER,
    FILE_TEAM_HEADER,
    FILE_TEAM_MENU_1,
    FILE_TEAM_MENU_2,
    FILE_TEAM_MENU_3,
    FILE_TEAM_SEPARATOR,
    FILE_TEAM_FOOTER,
    FILE_PRIV_HEADER,
    FILE_PRIV_FOOTER,
    FILE_COPYRIGHT,
    FILE_REGISTER_EMAIL,
    FILE_WELCOME,
    FILE_REG_WELCOME,
};

static const unsigned char * const file_names[] =
{
    [FILE_USERS_HEADER] = "users_header",
    [FILE_USERS_FOOTER] = "users_footer",
    [FILE_REGISTER_HEADER] = "register_header",
    [FILE_REGISTER_FOOTER] = "register_footer",
    [FILE_TEAM_HEADER] = "team_header",
    [FILE_TEAM_MENU_1] = "team_menu_1",
    [FILE_TEAM_MENU_2] = "team_menu_2",
    [FILE_TEAM_MENU_3] = "team_menu_3",
    [FILE_TEAM_SEPARATOR] = "team_separator",
    [FILE_TEAM_FOOTER] = "team_footer",
    [FILE_PRIV_HEADER] = "priv_header",
    [FILE_PRIV_FOOTER] = "priv_footer",
    [FILE_COPYRIGHT] = "copyright",
    [FILE_REGISTER_EMAIL] = "register_email",
    [FILE_WELCOME] = "welcome",
    [FILE_REG_WELCOME] = "reg_welcome",
};

static int
parse_file_field_name(const unsigned char *s)
{
    if (!s) return -1;
    for (int i = 1; i < sizeof(file_names)/sizeof(file_names[0]); ++i) {
        if (!strcmp(s, file_names[i])) {
            return i;
        }
    }
    return -1;
}

static void
get_state_file_pointers(
        struct sid_state *ss,
        struct contest_desc *cnts,
        int field,
        const unsigned char **p_name,
        unsigned char ***p_text,
        ejintbool_t **p_loaded)
{
    switch (field) {
    case FILE_USERS_HEADER:
        *p_name = cnts->users_header_file;
        *p_text = &ss->users_header_text;
        *p_loaded = &ss->users_header_loaded;
        break;
    case FILE_USERS_FOOTER:
        *p_name = cnts->users_footer_file;
        *p_text = &ss->users_footer_text;
        *p_loaded = &ss->users_footer_loaded;
        break;
    case FILE_REGISTER_HEADER:
        *p_name = cnts->register_header_file;
        *p_text = &ss->register_header_text;
        *p_loaded = &ss->register_header_loaded;
        break;
    case FILE_REGISTER_FOOTER:
        *p_name = cnts->register_footer_file;
        *p_text = &ss->register_footer_text;
        *p_loaded = &ss->register_footer_loaded;
        break;
    case FILE_TEAM_HEADER:
        *p_name = cnts->team_header_file;
        *p_text = &ss->team_header_text;
        *p_loaded = &ss->team_header_loaded;
        break;
    case FILE_TEAM_MENU_1:
        *p_name = cnts->team_menu_1_file;
        *p_text = &ss->team_menu_1_text;
        *p_loaded = &ss->team_menu_1_loaded;
        break;
    case FILE_TEAM_MENU_2:
        *p_name = cnts->team_menu_2_file;
        *p_text = &ss->team_menu_2_text;
        *p_loaded = &ss->team_menu_2_loaded;
        break;
    case FILE_TEAM_MENU_3:
        *p_name = cnts->team_menu_3_file;
        *p_text = &ss->team_menu_3_text;
        *p_loaded = &ss->team_menu_3_loaded;
        break;
    case FILE_TEAM_SEPARATOR:
        *p_name = cnts->team_separator_file;
        *p_text = &ss->team_separator_text;
        *p_loaded = &ss->team_separator_loaded;
        break;
    case FILE_TEAM_FOOTER:
        *p_name = cnts->team_footer_file;
        *p_text = &ss->team_footer_text;
        *p_loaded = &ss->team_footer_loaded;
        break;
    case FILE_PRIV_HEADER:
        *p_name = cnts->priv_header_file;
        *p_text = &ss->priv_header_text;
        *p_loaded = &ss->priv_header_loaded;
        break;
    case FILE_PRIV_FOOTER:
        *p_name = cnts->priv_footer_file;
        *p_text = &ss->priv_footer_text;
        *p_loaded = &ss->priv_footer_loaded;
        break;
    case FILE_COPYRIGHT:
        *p_name = cnts->copyright_file;
        *p_text = &ss->copyright_text;
        *p_loaded = &ss->copyright_loaded;
        break;
    case FILE_REGISTER_EMAIL:
        *p_name = cnts->register_email_file;
        *p_text = &ss->register_email_text;
        *p_loaded = &ss->register_email_loaded;
        break;
    case FILE_WELCOME:
        *p_name = cnts->welcome_file;
        *p_text = &ss->welcome_text;
        *p_loaded = &ss->welcome_loaded;
        break;
    case FILE_REG_WELCOME:
        *p_name = cnts->reg_welcome_file;
        *p_text = &ss->reg_welcome_text;
        *p_loaded = &ss->reg_welcome_loaded;
        break;
    default:
        *p_name = NULL;
        *p_text = NULL;
        *p_loaded = NULL;
        break;
    }
}

static void
get_state_file_pointers_by_field_id(
        struct sid_state *ss,
        int field_id,
        unsigned char ***p_text,
        ejintbool_t **p_loaded)
{
    switch (field_id) {
    case CNTS_users_header_file:
        *p_text = &ss->users_header_text;
        *p_loaded = &ss->users_header_loaded;
        break;
    case CNTS_users_footer_file:
        *p_text = &ss->users_footer_text;
        *p_loaded = &ss->users_footer_loaded;
        break;
    case CNTS_register_header_file:
        *p_text = &ss->register_header_text;
        *p_loaded = &ss->register_header_loaded;
        break;
    case CNTS_register_footer_file:
        *p_text = &ss->register_footer_text;
        *p_loaded = &ss->register_footer_loaded;
        break;
    case CNTS_team_header_file:
        *p_text = &ss->team_header_text;
        *p_loaded = &ss->team_header_loaded;
        break;
    case CNTS_team_menu_1_file:
        *p_text = &ss->team_menu_1_text;
        *p_loaded = &ss->team_menu_1_loaded;
        break;
    case CNTS_team_menu_2_file:
        *p_text = &ss->team_menu_2_text;
        *p_loaded = &ss->team_menu_2_loaded;
        break;
    case CNTS_team_menu_3_file:
        *p_text = &ss->team_menu_3_text;
        *p_loaded = &ss->team_menu_3_loaded;
        break;
    case CNTS_team_separator_file:
        *p_text = &ss->team_separator_text;
        *p_loaded = &ss->team_separator_loaded;
        break;
    case CNTS_team_footer_file:
        *p_text = &ss->team_footer_text;
        *p_loaded = &ss->team_footer_loaded;
        break;
    case CNTS_priv_header_file:
        *p_text = &ss->priv_header_text;
        *p_loaded = &ss->priv_header_loaded;
        break;
    case CNTS_priv_footer_file:
        *p_text = &ss->priv_footer_text;
        *p_loaded = &ss->priv_footer_loaded;
        break;
    case CNTS_copyright_file:
        *p_text = &ss->copyright_text;
        *p_loaded = &ss->copyright_loaded;
        break;
    case CNTS_register_email_file:
        *p_text = &ss->register_email_text;
        *p_loaded = &ss->register_email_loaded;
        break;
    case CNTS_welcome_file:
        *p_text = &ss->welcome_text;
        *p_loaded = &ss->welcome_loaded;
        break;
    case CNTS_reg_welcome_file:
        *p_text = &ss->reg_welcome_text;
        *p_loaded = &ss->reg_welcome_loaded;
        break;
    default:
        *p_text = NULL;
        *p_loaded = NULL;
        break;
    }
}

static const unsigned char global_ignored_fields[CNTSGLOB_LAST_FIELD] =
{
    [CNTSGLOB_name] = 1,
    [CNTSGLOB_root_dir] = 1,
    [CNTSGLOB_serve_socket] = 1,
    [CNTSGLOB_l10n_dir] = 1,
    [CNTSGLOB_standings_locale_id] = 1,
    [CNTSGLOB_contest_id] = 1,
    [CNTSGLOB_socket_path] = 1,
    [CNTSGLOB_contests_dir] = 1,
    [CNTSGLOB_lang_config_dir] = 1,
    [CNTSGLOB_conf_dir] = 1,
    [CNTSGLOB_problems_dir] = 1,
    [CNTSGLOB_super_run_dir] = 1,
    [CNTSGLOB_virtual_end_info] = 1,
    [CNTSGLOB_var_dir] = 1,
    [CNTSGLOB_run_log_file] = 1,
    [CNTSGLOB_clar_log_file] = 1,
    [CNTSGLOB_archive_dir] = 1,
    [CNTSGLOB_clar_archive_dir] = 1,
    [CNTSGLOB_run_archive_dir] = 1,
    [CNTSGLOB_report_archive_dir] = 1,
    [CNTSGLOB_team_report_archive_dir] = 1,
    [CNTSGLOB_xml_report_archive_dir] = 1,
    [CNTSGLOB_full_archive_dir] = 1,
    [CNTSGLOB_audit_log_dir] = 1,
    [CNTSGLOB_uuid_archive_dir] = 1,
    [CNTSGLOB_team_extra_dir] = 1,
    [CNTSGLOB_legacy_status_dir] = 1,
    [CNTSGLOB_work_dir] = 1,
    [CNTSGLOB_print_work_dir] = 1,
    [CNTSGLOB_diff_work_dir] = 1,
    [CNTSGLOB_compile_queue_dir] = 1,
    [CNTSGLOB_compile_src_dir] = 1,
    [CNTSGLOB_compile_out_dir] = 1,
    [CNTSGLOB_compile_status_dir] = 1,
    [CNTSGLOB_compile_report_dir] = 1,
    [CNTSGLOB_compile_work_dir] = 1,
    [CNTSGLOB_run_queue_dir] = 1,
    [CNTSGLOB_run_exe_dir] = 1,
    [CNTSGLOB_run_out_dir] = 1,
    [CNTSGLOB_run_status_dir] = 1,
    [CNTSGLOB_run_report_dir] = 1,
    [CNTSGLOB_run_team_report_dir] = 1,
    [CNTSGLOB_run_full_archive_dir] = 1,
    [CNTSGLOB_run_work_dir] = 1,
    [CNTSGLOB_run_check_dir] = 1,
    [CNTSGLOB_stand_header_txt] = 1,
    [CNTSGLOB_stand_footer_txt] = 1,
    [CNTSGLOB_stand2_header_txt] = 1,
    [CNTSGLOB_stand2_footer_txt] = 1,
    [CNTSGLOB_plog_header_txt] = 1,
    [CNTSGLOB_plog_footer_txt] = 1,
    [CNTSGLOB_user_exam_protocol_header_txt] = 1,
    [CNTSGLOB_user_exam_protocol_footer_txt] = 1,
    [CNTSGLOB_prob_exam_protocol_header_txt] = 1,
    [CNTSGLOB_prob_exam_protocol_footer_txt] = 1,
    [CNTSGLOB_full_exam_protocol_header_txt] = 1,
    [CNTSGLOB_full_exam_protocol_footer_txt] = 1,
    [CNTSGLOB_unhandled_vars] = 1,
    [CNTSGLOB_language_import] = 1,
};

static void
get_contest_xml_json(struct http_request_info *phr)
{
    int date_mode = 0;
    hr_cgi_param_int_opt(phr, "date_mode", &date_mode, 0);
    cJSON_AddItemToObject(phr->json_result, "result", json_serialize_contest_xml_full(phr->ss->edited_cnts, date_mode));
    phr->status_code = 200;
}

static void
get_contest_file_json(struct http_request_info *phr)
{
    const unsigned char *field_name = NULL;
    if (hr_cgi_param(phr, "field_name", &field_name) <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    int field_id = parse_file_field_name(field_name);
    if (field_id <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    const unsigned char *file_name = NULL;
    unsigned char **p_text = NULL;
    ejintbool_t *p_loaded = 0;
    get_state_file_pointers(phr->ss, phr->ss->edited_cnts, field_id, &file_name, &p_text, &p_loaded);
    if (!p_text) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    cJSON *jr = cJSON_CreateObject();
    cJSON_AddStringToObject(jr, "field_name", field_name);
    if (file_name) {
        cJSON_AddStringToObject(jr, "file_name", file_name);
        if (*p_text) {
            cJSON_AddStringToObject(jr, "text", *p_text);
        }
        if (*p_loaded > 0) {
            cJSON_AddTrueToObject(jr, "loaded");
        }
    }
    cJSON_AddItemToObject(phr->json_result, "result", jr);
    phr->status_code = 200;
}

static void
get_contest_global_json(struct http_request_info *phr)
{
    int date_mode = 0, size_mode = 0;
    hr_cgi_param_int_opt(phr, "date_mode", &date_mode, 0);
    hr_cgi_param_int_opt(phr, "size_mode", &size_mode, 0);
    if (phr->ss->global) {
        cJSON_AddItemToObject(phr->json_result, "result", json_serialize_global(phr->ss->global, date_mode, size_mode, global_ignored_fields));
    } else {
        cJSON_AddNullToObject(phr->json_result, "result");
    }
    phr->status_code = 200;
}

static void
get_contest_problems_json(struct http_request_info *phr)
{
    cJSON *jps = cJSON_CreateArray();
    for (int i = 0; i < phr->ss->aprob_u; ++i) {
        if (phr->ss->aprobs[i]) {
            cJSON_AddItemToArray(jps, json_serialize_problem_id(phr->ss->aprobs[i]));
        }
    }
    for (int i = 0; i < phr->ss->prob_a; ++i) {
        if (phr->ss->probs[i]) {
            cJSON_AddItemToArray(jps, json_serialize_problem_id(phr->ss->probs[i]));
        }
    }
    cJSON_AddItemToObject(phr->json_result, "result", jps);
    phr->status_code = 200;
}

static const unsigned char problem_ignored_fields[CNTSPROB_LAST_FIELD] =
{
    [CNTSPROB_ntests] = 1,
    [CNTSPROB_tscores] = 1,
    [CNTSPROB_x_score_tests] = 1,
    [CNTSPROB_ts_total] = 1,
    [CNTSPROB_ts_infos] = 1,
    [CNTSPROB_normalization_val] = 1,
    [CNTSPROB_dp_total] = 1,
    [CNTSPROB_dp_infos] = 1,
    [CNTSPROB_gsd] = 1,
    [CNTSPROB_gdl] = 1,
    [CNTSPROB_pd_total] = 1,
    [CNTSPROB_pd_infos] = 1,
    [CNTSPROB_score_bonus_total] = 1,
    [CNTSPROB_score_bonus_val] = 1,
    [CNTSPROB_open_tests_count] = 1,
    [CNTSPROB_open_tests_val] = 1,
    [CNTSPROB_open_tests_group] = 1,
    [CNTSPROB_final_open_tests_count] = 1,
    [CNTSPROB_final_open_tests_val] = 1,
    [CNTSPROB_final_open_tests_group] = 1,
    [CNTSPROB_token_open_tests_count] = 1,
    [CNTSPROB_token_open_tests_val] = 1,
    [CNTSPROB_token_open_tests_group] = 1,
    [CNTSPROB_score_view_score] = 1,
    [CNTSPROB_score_view_text] = 1,
    [CNTSPROB_xml_file_path] = 1,
    [CNTSPROB_var_xml_file_paths] = 1,
};

static int
does_problem_match(
        const struct section_problem_data *prob,
        const unsigned char *short_name,
        const unsigned char *long_name,
        const unsigned char *internal_name,
        const unsigned char *uuid,
        const unsigned char *extid)
{
    if (!prob) return 0;
    if (short_name && !strcmp(prob->short_name, short_name)) return 1;
    if (uuid && prob->uuid && !strcmp(prob->uuid, uuid)) return 1;
    if (internal_name && prob->internal_name && !strcmp(prob->internal_name, internal_name)) return 1;
    if (extid && prob->extid && !strcmp(prob->extid, extid)) return 1;
    if (long_name && prob->long_name && !strcmp(prob->long_name, long_name)) return 1;
    return 0;
}

static int
lookup_contest_problem(
        const struct sid_state *ss,
        int abstract,
        int prob_id,
        const unsigned char *short_name,
        const unsigned char *long_name,
        const unsigned char *internal_name,
        const unsigned char *uuid,
        const unsigned char *extid,
        int *p_abstract,
        int *p_prob_id,
        struct section_problem_data **p_prob)
{
    if (!ss) return 404;
    int found_abstract = -1;
    int found_prob_id = -1;
    struct section_problem_data *prob = NULL;
    if (abstract != 0) { // true or undefined
        if (abstract > 0 && prob_id >= 0) {
            if (prob_id >= ss->aprob_u) return -404;
            prob = ss->aprobs[prob_id];
            if (!prob) return -404;
            if (p_abstract) *p_abstract = 1;
            if (p_prob_id) *p_prob_id = prob_id;
            if (p_prob) *p_prob = prob;
            return 0;
        }
        for (int i = 0; i < ss->aprob_u; ++i) {
            if (does_problem_match(ss->aprobs[i], short_name, long_name, internal_name, uuid, extid)) {
                if (prob) return -429;
                found_abstract = 1;
                found_prob_id = i;
                prob = ss->aprobs[i];
            }
        }
    }
    if (abstract <= 0) { // false or undefined
        if (abstract == 0 && prob_id >= 0) {
            if (prob_id >= ss->prob_a) return -404;
            prob = ss->probs[prob_id];
            if (!prob) return -404;
            if (p_abstract) *p_abstract = 0;
            if (p_prob_id) *p_prob_id = prob_id;
            if (p_prob) *p_prob = prob;
            return 0;
        }
        for (int i = 0; i < ss->prob_a; ++i) {
            if (does_problem_match(ss->probs[i], short_name, long_name, internal_name, uuid, extid)) {
                if (prob) return -429;
                found_abstract = 0;
                found_prob_id = i;
                prob = ss->probs[i];
            }
        }
    }
    if (!prob) {
        return -404;
    }
    if (p_abstract) *p_abstract = found_abstract;
    if (p_prob_id) *p_prob_id = found_prob_id;
    if (p_prob) *p_prob = prob;
    return 0;
}

static void
get_contest_problem_json(struct http_request_info *phr)
{
    int date_mode = 0, size_mode = 0;
    hr_cgi_param_int_opt(phr, "date_mode", &date_mode, 0);
    hr_cgi_param_int_opt(phr, "size_mode", &size_mode, 0);
    int abstract = -1;
    hr_cgi_param_bool_opt(phr, "abstract", &abstract, -1);
    int prob_id = -1;
    hr_cgi_param_int_opt(phr, "prob_id", &prob_id, -1);
    const unsigned char *short_name = NULL;
    hr_cgi_param(phr, "short_name", &short_name);
    const unsigned char *long_name = NULL;
    hr_cgi_param(phr, "long_name", &long_name);
    const unsigned char *internal_name = NULL;
    hr_cgi_param(phr, "internal_name", &internal_name);
    const unsigned char *uuid = NULL;
    hr_cgi_param(phr, "uuid", &uuid);
    const unsigned char *extid = NULL;
    hr_cgi_param(phr, "extid", &extid);
    struct section_problem_data *prob = NULL;
    int r = lookup_contest_problem(phr->ss, abstract, prob_id, short_name, long_name, internal_name, uuid, extid, NULL, NULL, &prob);
    if (r < 0) {
        phr->status_code = -r;
        return;
    }
    if (!prob) {
        phr->status_code = 404;
        return;
    }
    cJSON_AddItemToObject(phr->json_result, "result", json_serialize_problem(prob, date_mode, size_mode, problem_ignored_fields));
    phr->status_code = 200;
}

static void
get_contest_compile_servers(struct http_request_info *phr)
{
    cJSON *jr = cJSON_CreateObject();
    cJSON *jcs = cJSON_CreateArray();
    if (phr->ss->cscs && phr->ss->cscs->u > 0) {
        for (int serv_i = 0; serv_i < phr->ss->cscs->u; ++serv_i) {
            struct compile_server_config *csc = &phr->ss->cscs->v[serv_i];
            cJSON *jc = cJSON_CreateObject();
            cJSON_AddStringToObject(jc, "id", csc->id);
            if (serv_i == 0) {
                cJSON_AddTrueToObject(jc, "default");
            }
            if (!csc->errors) {
                cJSON_AddTrueToObject(jc, "available");
            }
            if (csc->errors) {
                cJSON_AddStringToObject(jc, "errors", csc->errors);
            }
            cJSON_AddItemToArray(jcs, jc);
        }
    }
    cJSON_AddItemToObject(jr, "compile_servers", jcs);
    cJSON_AddItemToObject(phr->json_result, "result", jr);
    phr->status_code = 200;
}

static void
get_contest_compile_server(struct http_request_info *phr)
{
    const unsigned char *compile_server_id = NULL;
    int date_mode = 0, size_mode = 0;
    if (hr_cgi_param(phr, "compile_server_id", &compile_server_id) < 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    hr_cgi_param_int_opt(phr, "date_mode", &date_mode, 0);
    hr_cgi_param_int_opt(phr, "size_mode", &size_mode, 0);
    if (!*compile_server_id) compile_server_id = NULL;
    if (!phr->ss->cscs || !phr->ss->cscs->u) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 404;
        return;
    }

    const struct compile_server_config *csc = NULL;
    if (!compile_server_id) {
        csc = &phr->ss->cscs->v[0];
    } else {
        for (int i = 0; i < phr->ss->cscs->u; ++i) {
            const struct compile_server_config *cc = &phr->ss->cscs->v[i];
            if (cc->id && !strcmp(compile_server_id, cc->id)) {
                csc = cc;
                break;
            }
        }
    }
    if (!csc) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 404;
        return;
    }

    cJSON *jr = cJSON_CreateObject();
    cJSON_AddStringToObject(jr, "compile_server_id", csc->id);
    if (csc->global) {
        cJSON_AddItemToObject(jr, "global", json_serialize_global(phr->ss->global, date_mode, size_mode, global_ignored_fields));
    }
    cJSON *jls = cJSON_CreateArray();
    if (csc->langs) {
        for (int lang_id = 0; lang_id <= csc->max_lang; ++lang_id) {
            const struct section_language_data *lang = csc->langs[lang_id];
            if (!lang) continue;
            cJSON_AddItemToArray(jls, json_serialize_language(lang, 1));
        }
    }
    cJSON_AddItemToObject(jr, "languages", jls);
    cJSON_AddItemToObject(phr->json_result, "result", jr);
    phr->status_code = 200;
}

static void
add_ejsize64_to_object(
        cJSON *j,
        const unsigned char *name,
        ej_size64_t value,
        int size_mode)
{
    if (value > 0) {
        if (size_mode == 1) {
            cJSON_AddNumberToObject(j, name, value);
        } else {
            unsigned char buf[128];
            ll_to_size_str(buf, sizeof(buf), value);
            cJSON_AddStringToObject(j, name, buf);
        }
    }
}

static void
get_contest_languages(struct http_request_info *phr)
{
    int date_mode = 0, size_mode = 0;
    hr_cgi_param_int_opt(phr, "date_mode", &date_mode, 0);
    hr_cgi_param_int_opt(phr, "size_mode", &size_mode, 0);

    cJSON *jr = cJSON_CreateObject();
    cJSON *jg = cJSON_CreateObject();
    const struct section_global_data *global = phr->ss->global;
    if (phr->config->enable_compile_container > 0) {
        if (global && global->compile_max_vm_size) {
            add_ejsize64_to_object(jg, "compile_max_vm_size", global->compile_max_vm_size, size_mode);
        }
        if (global && global->compile_max_rss_size) {
            add_ejsize64_to_object(jg, "compile_max_rss_size", global->compile_max_rss_size, size_mode);
        }
        if (global && global->compile_max_stack_size) {
            add_ejsize64_to_object(jg, "compile_max_stack_size", global->compile_max_stack_size, size_mode);
        }
    }
    if (global && global->compile_max_file_size) {
        add_ejsize64_to_object(jg, "compile_max_file_size", global->compile_max_file_size, size_mode);
    }
    if (global && global->compile_server_id && global->compile_server_id[0]) {
        cJSON_AddStringToObject(jg, "compile_server_id", global->compile_server_id);
    }
    cJSON_AddItemToObject(jr, "global", jg);
    cJSON *jls = cJSON_CreateArray();
    for (int lang_id = 0; lang_id < phr->ss->lang_a; ++lang_id) {
        const struct section_language_data *lang = phr->ss->langs[lang_id];
        const struct section_language_data *serv_lang = phr->ss->serv_langs[lang_id];
        struct section_language_data *work_lang = NULL;
        struct section_language_data *act_lang = NULL;
        struct language_extra *lang_extra = &phr->ss->lang_extra[lang_id];
        if (lang) {
            act_lang = prepare_alloc_language();
            prepare_merge_language(act_lang, serv_lang, lang);
            prepare_language_set_defaults(act_lang);
        } else if (serv_lang) {
            // !lang
            act_lang = prepare_alloc_language();
            prepare_copy_language(act_lang, serv_lang);
            prepare_language_set_defaults(act_lang);
            work_lang = prepare_alloc_language();
            work_lang->id = lang_id;
            lang = work_lang;
        }

        if (!act_lang) continue;

        cJSON *jl = cJSON_CreateObject();
        if (lang_extra->enabled == 2) {
            cJSON_AddTrueToObject(jl, "force_disabled");
        } else if (lang_extra->enabled < 0) {
            cJSON_AddTrueToObject(jl, "invalid");
        } else if (lang_extra->enabled == 0) {
            cJSON_AddTrueToObject(jl, "disabled");
        } else {
            /*
        if (enable_container > 0) {
        } else {
            if (lang && lang->insecure > 0 && global && global->secure_run > 0) {
            td_attr = " bgcolor=\"#ffffdd\"";
            } else if (lang) {
            td_attr = " bgcolor=\"#ddffdd\"";
            }
        }
            */
        }
        if (lang_extra->enabled == 1) {
            cJSON_AddTrueToObject(jl, "enabled");
        }

        cJSON_AddItemToObject(jl, "config", json_serialize_language(lang, 0));
        cJSON *je = cJSON_CreateObject();
        if (lang_extra->ejudge_flags) {
            cJSON_AddStringToObject(je, "ejudge_flags", lang_extra->ejudge_flags);
        }
        if (lang_extra->ejudge_libs) {
            cJSON_AddStringToObject(je, "ejudge_libs", lang_extra->ejudge_libs);
        }
        if (lang_extra->compiler_env) {
            cJSON_AddStringToObject(je, "compiler_env", lang_extra->compiler_env);
        }
        cJSON_AddItemToObject(jl, "extra", je);

        cJSON_AddItemToObject(jl, "expanded", json_serialize_language(act_lang, 0));
        cJSON_AddItemToArray(jls, jl);
        if (act_lang) {
            prepare_free_config(&act_lang->g);
        }
        if (work_lang) {
            prepare_free_config(&work_lang->g);
        }
    }
    cJSON_AddItemToObject(jr, "languages", jls);
    cJSON_AddItemToObject(phr->json_result, "result", jr);
    phr->status_code = 200;
}

void
super_serve_api_CNTS_GET_VALUE_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    ej_cookie_t sid = 0;
    ej_cookie_t client_key = 0;
    if (parse_session(phr, "session", &sid, &client_key) <= 0) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    struct sid_state *ss = sid_state_find(sid, client_key);
    if (!ss) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    phr->ss = ss;
    if (!ss->edited_cnts) {
        phr->err_num = SSERV_ERR_NO_EDITED_CNTS;
        phr->status_code = 400;
        return;
    }
    const unsigned char *section = NULL;
    if (hr_cgi_param(phr, "section", &section) <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    if (!strcmp(section, "contest.xml")) {
        get_contest_xml_json(phr);
        return;
    } else if (!strcmp(section, "file")) {
        get_contest_file_json(phr);
        return;
    } else if (!strcmp(section, "global")) {
        get_contest_global_json(phr);
        return;
    } else if (!strcmp(section, "problems")) {
        get_contest_problems_json(phr);
        return;
    } else if (!strcmp(section, "problem")) {
        get_contest_problem_json(phr);
        return;
    } else if (!strcmp(section, "compile-servers")) {
        get_contest_compile_servers(phr);
        return;
    } else if (!strcmp(section, "compile-server")) {
        get_contest_compile_server(phr);
        return;
    } else if (!strcmp(section, "languages")) {
        get_contest_languages(phr);
        return;
    } else {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
}

static void
delete_contest_xml_json(struct http_request_info *phr)
{
    const unsigned char *field_name = NULL;
    if (hr_cgi_param(phr, "field_name", &field_name) <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    int field_id = contest_desc_lookup_field(field_name);
    if (field_id <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    void *field_ptr = contest_desc_get_ptr_nc(phr->ss->edited_cnts, field_id);
    if (!field_ptr) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    int field_type = contest_desc_get_type(field_id);
    if (field_type == 'b') {
        ejbytebool_t *ptr = (ejbytebool_t*) field_ptr;
        *ptr = 0;
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    if (field_type == 't') {
        time_t *ptr = (time_t *) field_ptr;
        *ptr = 0;
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }

    unsigned char **field_text_ptr = NULL;
    ejintbool_t *field_text_loaded_ptr = NULL;
    get_state_file_pointers_by_field_id(phr->ss, field_id, &field_text_ptr, &field_text_loaded_ptr);
    if (field_text_ptr && field_text_loaded_ptr) {
        xfree(*field_text_ptr); *field_text_ptr = NULL;
        *field_text_loaded_ptr = 0;
        xfree(field_ptr); field_ptr = NULL;
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }

    switch (field_id) {
    case CNTS_id:
    case CNTS_root_dir:
    case CNTS_conf_dir:
    case CNTS_serve_user:
    case CNTS_serve_group:
    case CNTS_run_user:
    case CNTS_run_group:
    case CNTS_slave_rules:
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    case CNTS_name: {
        unsigned char **ptr = (unsigned char **) field_ptr;
        xfree(*ptr); *ptr = xstrdup("");
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_user_contest:
    case CNTS_user_contest_num:
        xfree(phr->ss->edited_cnts->user_contest); phr->ss->edited_cnts->user_contest = NULL;
        phr->ss->edited_cnts->user_contest_num = 0;
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    case CNTS_default_locale:
    case CNTS_default_locale_num:
        xfree(phr->ss->edited_cnts->default_locale); phr->ss->edited_cnts->default_locale = NULL;
        phr->ss->edited_cnts->default_locale_num = -1;
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    case CNTS_file_mode:
    case CNTS_dir_mode: {
        unsigned char **ptr = (unsigned char **) field_ptr;
        xfree(*ptr); *ptr = NULL;
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_capabilities:
    case CNTS_caps_node: {
        const unsigned char *other_login = NULL;
        if (hr_cgi_param(phr, "login", &other_login) <= 0) {
            contest_remove_all_permissions(phr->ss->edited_cnts);
        } else {
            contests_remove_login_permission(phr->ss->edited_cnts, other_login);
        }
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_register_access:
    case CNTS_users_access:
    case CNTS_master_access:
    case CNTS_judge_access:
    case CNTS_team_access:
    case CNTS_serve_control_access: {
        struct contest_access **p_acc = (struct contest_access**) field_ptr;
        const unsigned char *mask_str = NULL;
        if (hr_cgi_param(phr, "mask", &mask_str) <= 0) {
            contests_delete_all_rules(p_acc);
        } else {
            ej_ip_t addr, mask;
            if (xml_parse_ipv6_mask(NULL, NULL, 0, 0, mask_str, &addr, &mask) < 0) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
            int ssl_flag = 0;
            hr_cgi_param_int_opt(phr, "ssl", &ssl_flag, -1);
            ssl_flag = EJ_SIGN(ssl_flag);
            contests_delete_ip_rule_by_mask(p_acc, &addr, &mask, ssl_flag);
        }
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_fields: {
        const unsigned char *user_field_name = NULL;
        if (hr_cgi_param(phr, "user_field_name", &user_field_name) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        int user_field = contests_parse_user_field_name(user_field_name);
        if (user_field < CONTEST_FIRST_FIELD || user_field >= CONTEST_LAST_FIELD) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        // should not be a memory leak
        phr->ss->edited_cnts->fields[user_field] = NULL;
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_members: {
        const unsigned char *member = NULL;
        if (hr_cgi_param(phr, "member", &member) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        int member_id = contests_parse_member(member);
        if (member_id < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        const unsigned char *member_field_name = NULL;
        if (hr_cgi_param(phr, "member_field_name", &member_field_name) > 0) {
            int member_field = contests_parse_member_field_name(member_field_name);
            if (member_field <= 0 || member_field >= CONTEST_LAST_MEMBER_FIELD) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
            if (phr->ss->edited_cnts->members[member_id]) {
                phr->ss->edited_cnts->members[member_id]->fields[member_field] = NULL;
            }
        } else {
            phr->ss->edited_cnts->members[member_id] = NULL;
        }
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_oauth_rules: {
        const unsigned char *domain = NULL;
        if (hr_cgi_param(phr, "domain", &domain) > 0) {
            contests_delete_oauth_rule(phr->ss->edited_cnts, domain);
        } else {
            phr->ss->edited_cnts->oauth_rules = NULL;
        }
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    default:
        break;
    }
    if (field_type == 's') {
        unsigned char **ptr = (unsigned char **) field_ptr;
        xfree(*ptr); *ptr = NULL;
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    phr->err_num = SSERV_ERR_INV_PARAM;
    phr->status_code = 400;
}

static void
delete_contest_file_json(struct http_request_info *phr)
{
    const unsigned char *field_name = NULL;
    if (hr_cgi_param(phr, "field_name", &field_name) <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    int field_id = parse_file_field_name(field_name);
    if (field_id <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }

    const unsigned char *file_name = NULL;
    unsigned char **p_text = NULL;
    ejintbool_t *p_loaded = 0;
    get_state_file_pointers(phr->ss, phr->ss->edited_cnts, field_id, &file_name, &p_text, &p_loaded);
    if (!p_text) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    xfree(*p_text);
    *p_text = NULL;
    *p_loaded = 0;
    cJSON_AddTrueToObject(phr->json_result, "result");
    phr->status_code = 200;
}

static void
delete_contest_global_json(struct http_request_info *phr)
{
    if (!phr->ss->global) goto status_400;
    const unsigned char *field_name = NULL;
    if (hr_cgi_param(phr, "field_name", &field_name) <= 0) goto status_400;
    int field_id = cntsglob_lookup_field(field_name);
    if (field_id <= 0) goto status_400;
    if (global_ignored_fields[field_id]) goto status_400;
    void *field_ptr = cntsglob_get_ptr_nc(phr->ss->global, field_id);
    if (!field_ptr) goto status_400;

    switch (field_id) {
    case CNTSGLOB_priority_adjustment:
        phr->ss->global->priority_adjustment = 0;
        goto status_200_default;
    case CNTSGLOB_score_system:
        phr->ss->global->score_system = SCORE_ACM;
        goto status_200_default;
    case CNTSGLOB_rounding_mode:
        phr->ss->global->rounding_mode = 0;
        goto status_200_default;
    default:
        break;
    }

    int field_type = cntsglob_get_type(field_id);
    switch (field_type) {
    case 'i': {
        int *ptr = (int*) field_ptr;
        *ptr = -1;
        goto status_200_default;
    }
    case 'z': {
        ejintsize_t *ptr = (ejintsize_t*) field_ptr;
        *ptr = 0;
        goto status_200_default;
    }
    case 'B': {
        ejintbool_t *ptr = (ejintbool_t*) field_ptr;
        *ptr = 0;
        goto status_200_default;
    }
    case 't': {
        time_t *ptr = (time_t*) field_ptr;
        *ptr = 0;
        goto status_200_default;
    }
    case 's': {
        unsigned char **ptr = (unsigned char **) field_ptr;
        if (*ptr) xfree(*ptr);
        *ptr = NULL;
        goto status_200_default;
    }
    case 'E': {
        ej_size64_t *ptr = (ej_size64_t *) field_ptr;
        *ptr = 0;
        goto status_200_default;
    }
    case 'x': {
        char ***ptr = (char***) field_ptr;
        const unsigned char *s = NULL;
        int r = hr_cgi_param(phr, "old_item", &s);
        if (r < 0) goto status_400;
        if (r == 0) {
            sarray_free(*ptr);
            *ptr = NULL;
        } else {
            int i = 0;
            for (; (*ptr)[i] && strcmp((*ptr)[i], s) != 0; ++i) {}
            if ((*ptr)[i]) {
                xfree((*ptr)[i]);
                while (((*ptr)[i] = (*ptr)[i+1])) {
                    ++i;
                }
            }
        }
        goto status_200_default;
    }
    }

status_400:;
    phr->err_num = SSERV_ERR_INV_PARAM;
    phr->status_code = 400;
    return;

status_200_default:;
    cJSON_AddTrueToObject(phr->json_result, "result");
    phr->status_code = 200;
    return;
}

extern const unsigned char problem_typically_ignored_fields[CNTSPROB_LAST_FIELD];

static void
delete_contest_problem_json(struct http_request_info *phr)
{
    int is_changed = 0;
    int abstract = -1;
    hr_cgi_param_bool_opt(phr, "abstract", &abstract, -1);
    int prob_id = -1;
    hr_cgi_param_int_opt(phr, "prob_id", &prob_id, -1);
    const unsigned char *short_name = NULL;
    hr_cgi_param(phr, "short_name", &short_name);
    const unsigned char *long_name = NULL;
    hr_cgi_param(phr, "long_name", &long_name);
    const unsigned char *internal_name = NULL;
    hr_cgi_param(phr, "internal_name", &internal_name);
    const unsigned char *uuid = NULL;
    hr_cgi_param(phr, "uuid", &uuid);
    const unsigned char *extid = NULL;
    hr_cgi_param(phr, "extid", &extid);
    struct section_problem_data *prob = NULL;
    int r = lookup_contest_problem(phr->ss, abstract, prob_id, short_name, long_name, internal_name, uuid, extid, &abstract, &prob_id, &prob);
    if (r < 0) {
        cJSON_AddFalseToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }

    const unsigned char *field_name = NULL;
    r = hr_cgi_param(phr, "field_name", &field_name);
    if (r < 0) goto status_400;
    if (r == 0) {
        if (abstract) {
            for (int i = prob_id + 1; i < phr->ss->aprob_u; ++i) {
                phr->ss->aprobs[i-1] = phr->ss->aprobs[i];
                phr->ss->aprob_flags[i-1] = phr->ss->aprob_flags[i];
            }
            --phr->ss->aprob_u;
            phr->ss->aprobs[phr->ss->aprob_u] = NULL;
            phr->ss->aprob_flags[phr->ss->aprob_u] = 0;
        } else {
            phr->ss->probs[prob_id] = NULL;
            phr->ss->prob_flags[prob_id] = 0;
        }
    } else {
        int field_id = cntsprob_lookup_field(field_name);
        if (field_id <= 0) goto status_400;
        if (problem_delete_field(prob, field_id, &is_changed) < 0) goto status_400;
    }
    cJSON_AddTrueToObject(phr->json_result, "result");
    phr->status_code = 200;
    return;

status_400:;
    phr->err_num = SSERV_ERR_INV_PARAM;
    phr->status_code = 400;
    return;
}

void
super_serve_api_CNTS_DELETE_VALUE_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    ej_cookie_t sid = 0;
    ej_cookie_t client_key = 0;
    if (parse_session(phr, "session", &sid, &client_key) <= 0) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    struct sid_state *ss = sid_state_find(sid, client_key);
    if (!ss) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    phr->ss = ss;
    if (!ss->edited_cnts) {
        phr->err_num = SSERV_ERR_NO_EDITED_CNTS;
        phr->status_code = 400;
        return;
    }
    const unsigned char *section = NULL;
    if (hr_cgi_param(phr, "section", &section) <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    if (!strcmp(section, "contest.xml")) {
        delete_contest_xml_json(phr);
        return;
    } else if (!strcmp(section, "file")) {
        delete_contest_file_json(phr);
        return;
    } else if (!strcmp(section, "global")) {
        delete_contest_global_json(phr);
        return;
    } else if (!strcmp(section, "problem")) {
        delete_contest_problem_json(phr);
        return;
    } else {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
}

static void
set_capability(
        struct contest_desc *cnts,
        const unsigned char *login,
        opcap_t caps,
        int atfront,
        int atback,
        const unsigned char *before)
{
    struct opcap_list_item *cur;
    for (cur = cnts->capabilities.first; cur; cur = (struct opcap_list_item *) cur->b.right) {
        if (!strcmp(cur->login, login))
            break;
    }
    if (cur) {
        cur->caps = caps;
        if (atfront <= 0 && atback <= 0 && !before) {
            return;
        }
        if (atfront && !cur->b.left) {
            return;
        }
        if (atback && !cur->b.right) {
            return;
        }
        if (before) {
            struct opcap_list_item *next = (struct opcap_list_item *) cur->b.right;
            if (next && !strcmp(next->login, before)) {
                return;
            }
        }
        xml_unlink_node(&cur->b);
    } else {
        cur = (struct opcap_list_item *) contests_new_node(CONTEST_CAP);
        cur->login = xstrdup(login);
        cur->caps = caps;
    }
    if (!cnts->caps_node) {
        cnts->caps_node = contests_new_node(CONTEST_CAPS);
        xml_link_node_last(&cnts->b, cnts->caps_node);
    }
    if (atfront > 0) {
        xml_link_node_first(cnts->caps_node, &cur->b);
    } else if (before) {
        struct opcap_list_item *bn;
        for (bn = cnts->capabilities.first; bn; bn = (struct opcap_list_item* ) bn->b.right) {
            if (!strcmp(bn->login, before)) {
                break;
            }
        }
        ASSERT(bn);
        xml_link_node_before(&bn->b, &cur->b);
    } else {
        xml_link_node_last(cnts->caps_node, &cur->b);
    }
    cnts->capabilities.first = (struct opcap_list_item *) cnts->caps_node->first_down;
}

static void
set_ip_restriction(
        struct contest_desc *cnts,
        struct contest_access **p_acc,
        int tag,
        const ej_ip_t *p_addr,
        const ej_ip_t *p_mask,
        int ssl_flag,
        int allow,
        int atfront,
        int atback,
        int has_before,
        const ej_ip_t *before_addr,
        const ej_ip_t *before_mask,
        int before_ssl)
{
    struct contest_ip *cur = contests_find_ip_rule_nc(*p_acc, p_addr, p_mask, ssl_flag);
    if (cur) {
        cur->allow = !!allow;
        if (atfront <= 0 && atback <= 0 && has_before <= 0) {
            return;
        }
        if (atfront > 0 && !cur->b.left) {
            return;
        }
        if (atback > 0 && !cur->b.right) {
            return;
        }
        if (has_before > 0) {
            struct contest_ip *next = (struct contest_ip *) cur->b.right;
            if (!next) return;
            if (!ipv6cmp(&next->addr, before_addr) && !ipv6cmp(&next->mask, before_mask)) {
                if (before_ssl < 0 || before_ssl == next->ssl) {
                    return;
                }
            }
        }
        xml_unlink_node(&cur->b);
    } else {
        cur = (struct contest_ip *) contests_new_node(CONTEST_IP);
        cur->addr = *p_addr;
        cur->mask = *p_mask;
        cur->ssl = ssl_flag;
        cur->allow = allow;
    }
    struct contest_access *acc = *p_acc;
    if (!acc) {
        acc = (struct contest_access *) contests_new_node(tag);
        xml_link_node_last(&cnts->b, &acc->b);
        *p_acc = acc;
    }
    if (atfront > 0) {
        xml_link_node_first(&acc->b, &cur->b);
    } else if (has_before > 0) {
        struct contest_ip *before = contests_find_ip_rule_nc(acc, before_addr, before_mask, before_ssl);
        if (before) {
            xml_link_node_before(&before->b, &cur->b);
        } else {
            xml_link_node_last(&acc->b, &cur->b);
        }
    } else {
        xml_link_node_last(&acc->b, &cur->b);
    }
}

static void
set_oauth_rule(
        struct contest_desc *cnts,
        const unsigned char *domain,
        int allow,
        int deny,
        int strip_domain,
        int disable_email_check,
        int atfront,
        int atback,
        const unsigned char *before)
{
    struct xml_tree *cur = contests_find_oauth_rule_nc(cnts, domain);
    int found = 0;
    if (cur) {
        contests_free_attrs(cur);
        found = 1;
    } else {
        cur = contests_new_node(CONTEST_OAUTH_RULE);
    }
    xml_link_attr_last(cur, contests_new_attr(CONTEST_A_DOMAIN, domain));
    if (allow >= 0) {
        xml_link_attr_last(cur, contests_new_attr(CONTEST_A_ALLOW, xml_unparse_bool(allow)));
    } else if (deny >= 0) {
        xml_link_attr_last(cur, contests_new_attr(CONTEST_A_DENY, xml_unparse_bool(deny)));
    }
    if (strip_domain >= 0) {
        xml_link_attr_last(cur, contests_new_attr(CONTEST_A_STRIP_DOMAIN, xml_unparse_bool(strip_domain)));
    }
    if (disable_email_check >= 0) {
        xml_link_attr_last(cur, contests_new_attr(CONTEST_A_DISABLE_EMAIL_CHECK, xml_unparse_bool(disable_email_check)));
    }
    struct xml_tree *before_node = NULL;
    if (before) {
        before_node = contests_find_oauth_rule_nc(cnts, before);
    }
    if (found) {
        if (atfront <= 0 && atback <= 0 && !before_node) {
            return;
        }
        if (atfront > 0 && !cur->left) {
            return;
        }
        if (atback > 0 && !cur->right) {
            return;
        }
        if (before_node && cur->right == before_node) {
            return;
        }
        xml_unlink_node(cur);
    }
    if (!cnts->oauth_rules) {
        cnts->oauth_rules = contests_new_node(CONTEST_OAUTH_RULES);
        xml_link_node_last(&cnts->b, cnts->oauth_rules);
    }
    if (atfront > 0) {
        xml_link_node_first(cnts->oauth_rules, cur);
    } else if (before_node) {
        xml_link_node_before(before_node, cur);
    } else {
        xml_link_node_last(cnts->oauth_rules, cur);
    }
}

static const int access_tags_map[] =
{   
  CONTEST_REGISTER_ACCESS,
  CONTEST_USERS_ACCESS,
  CONTEST_MASTER_ACCESS,
  CONTEST_JUDGE_ACCESS,
  CONTEST_TEAM_ACCESS,
  CONTEST_SERVE_CONTROL_ACCESS,
};

static void
set_contest_xml_json(struct http_request_info *phr)
{
    const unsigned char *field_name = NULL;
    if (hr_cgi_param(phr, "field_name", &field_name) <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    int field_id = contest_desc_lookup_field(field_name);
    if (field_id <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    void *field_ptr = contest_desc_get_ptr_nc(phr->ss->edited_cnts, field_id);
    if (!field_ptr) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    int field_type = contest_desc_get_type(field_id);
    if (field_type == 'b') {
        ejbytebool_t *ptr = (ejbytebool_t*) field_ptr;
        int value = 0;
        if (hr_cgi_param_bool_opt(phr, "value", &value, 0) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        *ptr = !!value;
        if (*ptr) {
            cJSON_AddTrueToObject(phr->json_result, "result");
        } else {
            cJSON_AddFalseToObject(phr->json_result, "result");
        }
        phr->status_code = 200;
        return;
    }
    if (field_type == 't') {
        time_t *ptr = (time_t *) field_ptr;
        const unsigned char *value_str = NULL;
        if (hr_cgi_param(phr, "value", &value_str) <= 0 || !value_str || !*value_str) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        time_t tvalue = 0;
        char *eptr = NULL;
        errno = 0;
        long value = strtol(value_str, &eptr, 10);
        if (errno || *eptr || value_str == (const unsigned char *) eptr || value < 0 || (time_t) value != value) {
            if (xml_parse_date(NULL, NULL, 0, 0, value_str, &tvalue) < 0 || tvalue < 0) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
        } else {
            tvalue = value;
        }
        *ptr = tvalue;
        cJSON_AddNumberToObject(phr->json_result, "result", tvalue);
        phr->status_code = 200;
        return;
    }
    unsigned char **field_text_ptr = NULL;
    ejintbool_t *field_text_loaded_ptr = NULL;
    get_state_file_pointers_by_field_id(phr->ss, field_id, &field_text_ptr, &field_text_loaded_ptr);
    if (field_text_ptr && field_text_loaded_ptr) {
        const unsigned char *value = NULL;
        if (hr_cgi_param(phr, "value", &value) <= 0 || !value) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (!*value) {
            xfree(*field_text_ptr); *field_text_ptr = NULL;
            *field_text_loaded_ptr = 0;
            xfree(field_ptr); field_ptr = NULL;
            cJSON_AddNullToObject(phr->json_result, "result");
            phr->status_code = 200;
            return;
        }
        // FIXME: validate file name
        unsigned char **ptr = (unsigned char **) field_ptr;
        xfree(*ptr);
        *ptr = xstrdup(value);
        cJSON_AddStringToObject(phr->json_result, "result", value);
        phr->status_code = 200;
        return;
    }

    switch (field_id) {
    case CNTS_id:
    case CNTS_root_dir:
    case CNTS_conf_dir:
    case CNTS_serve_user:
    case CNTS_serve_group:
    case CNTS_run_user:
    case CNTS_run_group:
    case CNTS_slave_rules:
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    case CNTS_name: {
        unsigned char **ptr = (unsigned char **) field_ptr;
        const unsigned char *value = NULL;
        if (hr_cgi_param(phr, "value", &value) <= 0 || !value) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        xfree(*ptr); *ptr = xstrdup(value);
        cJSON_AddStringToObject(phr->json_result, "result", value);
        phr->status_code = 200;
        return;
    }
    case CNTS_user_contest:
    case CNTS_user_contest_num: {
        int value = 0;
        if (hr_cgi_param_int_opt(phr, "value", &value, 0) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (value == 0) {
            xfree(phr->ss->edited_cnts->user_contest); phr->ss->edited_cnts->user_contest = NULL;
            phr->ss->edited_cnts->user_contest_num = 0;
            cJSON_AddNumberToObject(phr->json_result, "result", 0);
            phr->status_code = 200;
            return;
        }
        if (value < 0 || value == phr->ss->edited_cnts->id) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        const struct contest_desc *other_cnts = NULL;
        if (contests_get(value, &other_cnts) < 0 || !other_cnts) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (other_cnts->user_contest_num > 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        char *user_contest_str = NULL;
        asprintf(&user_contest_str, "%d", value);
        xfree(phr->ss->edited_cnts->user_contest);
        phr->ss->edited_cnts->user_contest = user_contest_str;
        phr->ss->edited_cnts->user_contest_num = value;
        cJSON_AddNumberToObject(phr->json_result, "result", value);
        phr->status_code = 200;
        return;
    }
    case CNTS_default_locale:
    case CNTS_default_locale_num: {
        const unsigned char *value_str = NULL;
        if (hr_cgi_param(phr, "value", &value_str) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (!value_str || !*value_str) {
            xfree(phr->ss->edited_cnts->default_locale); phr->ss->edited_cnts->default_locale = NULL;
            phr->ss->edited_cnts->default_locale_num = -1;
            cJSON_AddNullToObject(phr->json_result, "result");
            phr->status_code = 200;
            return;
        }
        int locale_id = l10n_parse_locale(value_str);
        if (locale_id < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        xfree(phr->ss->edited_cnts->default_locale);
        phr->ss->edited_cnts->default_locale = xstrdup(l10n_unparse_locale(locale_id));
        phr->ss->edited_cnts->default_locale_num = locale_id;
        cJSON_AddNumberToObject(phr->json_result, "result", locale_id);
        phr->status_code = 200;
        return;
    }
    case CNTS_file_mode:
    case CNTS_dir_mode: {
        unsigned char **ptr = (unsigned char **) field_ptr;
        const unsigned char *value_str = NULL;
        if (hr_cgi_param(phr, "value", &value_str) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (!value_str || !*value_str) {
            xfree(*ptr); *ptr = NULL;
            cJSON_AddNullToObject(phr->json_result, "result");
            phr->status_code = 200;
            return;
        }
        errno = 0;
        char *eptr = NULL;
        unsigned long val = strtoul(value_str, &eptr, 8);
        if (errno || *eptr || value_str == (unsigned char *) eptr || val == 0 || val > 07777) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        char *sval = 0;
        asprintf(&sval, "%04lo", val);
        xfree(*ptr); *ptr = sval;
        cJSON_AddStringToObject(phr->json_result, "result", sval);
        phr->status_code = 200;
        return;
    }
    case CNTS_capabilities:
    case CNTS_caps_node: {
        const unsigned char *other_login = NULL;
        if (hr_cgi_param(phr, "login", &other_login) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        const unsigned char *caps_str = NULL;
        if (hr_cgi_param(phr, "caps", &caps_str) <= 0 || !caps_str) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        opcap_t caps = 0;
        if (opcaps_parse(caps_str, &caps) < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        int atfront = 0, atback = 0;
        const unsigned char *before = NULL;
        hr_cgi_param_bool_opt(phr, "atfront", &atfront, 0);
        hr_cgi_param_bool_opt(phr, "atback", &atback, 0);
        if (hr_cgi_param(phr, "before", &before) < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (before && !strcmp(other_login, before)) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (before) {
            opcap_t ocap = 0;
            if (opcaps_find(&phr->ss->edited_cnts->capabilities, other_login, &ocap) < 0) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
        }
        set_capability(phr->ss->edited_cnts, other_login, caps, atfront, atback, before);
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_register_access:
    case CNTS_users_access:
    case CNTS_master_access:
    case CNTS_judge_access:
    case CNTS_team_access:
    case CNTS_serve_control_access: {
        struct contest_access **p_acc = (struct contest_access**) field_ptr;
        // default [allow|deny]
        const unsigned char *default_str = NULL;
        int r = hr_cgi_param(phr, "default", &default_str);
        if (r < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (r > 0) {
            int default_access = 0;
            if (!strcasecmp(default_str, "allow")) {
                contests_set_default(phr->ss->edited_cnts, p_acc, access_tags_map[field_id-CNTS_register_access], 1);
                default_access = 1;
            } else if (!strcasecmp(default_str, "deny")) {
                contests_set_default(phr->ss->edited_cnts, p_acc, access_tags_map[field_id-CNTS_register_access], 0);
            } else {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
            cJSON_AddNumberToObject(phr->json_result, "result", default_access);
            phr->status_code = 200;
            return;
        }
        const unsigned char *mask_str = NULL;
        ej_ip_t addr, mask;
        if (hr_cgi_param(phr, "mask", &mask_str) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (xml_parse_ipv6_mask(NULL, NULL, 0, 0, mask_str, &addr, &mask) < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        int ssl_flag = 0, allow = 0;
        hr_cgi_param_int_opt(phr, "ssl", &ssl_flag, -1);
        ssl_flag = EJ_SIGN(ssl_flag);
        hr_cgi_param_bool_opt(phr, "allow", &allow, 0);
        if (allow > 0) allow = 1;
        else allow = 0;
        int atfront = 0, atback = 0;
        const unsigned char *before_str = NULL;
        hr_cgi_param_bool_opt(phr, "atfront", &atfront, 0);
        hr_cgi_param_bool_opt(phr, "atback", &atback, 0);
        if (hr_cgi_param(phr, "before", &before_str) < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        int has_before = 0;
        ej_ip_t before_addr = {}, before_mask = {};
        int before_ssl = -1;
        if (before_str) {
            if (xml_parse_ipv6_mask(NULL, NULL, 0, 0, before_str, &before_addr, &before_mask) < 0) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
            hr_cgi_param_int_opt(phr, "before_ssl", &before_ssl, -1);
            before_ssl = EJ_SIGN(before_ssl);
            if (!contests_find_ip_rule_nc(*p_acc, &before_addr, &before_mask, -1)) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
            has_before = 1;
        }
        set_ip_restriction(phr->ss->edited_cnts, p_acc, access_tags_map[field_id-CNTS_register_access],
                           &addr, &mask, ssl_flag, allow, atfront, atback,
                           has_before, &before_addr, &before_mask, before_ssl);
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_fields: {
        const unsigned char *user_field_name = NULL;
        if (hr_cgi_param(phr, "user_field_name", &user_field_name) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        int user_field = contests_parse_user_field_name(user_field_name);
        if (user_field < CONTEST_FIRST_FIELD || user_field >= CONTEST_LAST_FIELD) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        int mandatory = -1, checkbox = -1, is_password = -1;
        const unsigned char *legend = NULL, *separator = NULL, *options = NULL;
        hr_cgi_param_bool_opt(phr, "mandatory", &mandatory, 0);
        hr_cgi_param_bool_opt(phr, "checkbox", &checkbox, 0);
        hr_cgi_param_bool_opt(phr, "is_password", &is_password, 0);
        hr_cgi_param(phr, "legend", &legend);
        hr_cgi_param(phr, "separator", &separator);
        hr_cgi_param(phr, "options", &options);
        struct contest_field *f = phr->ss->edited_cnts->fields[user_field];
        if (f) {
            f->mandatory = 0;
            f->checkbox = 0;
            f->is_password = 0;
            xfree(f->legend); f->legend = NULL;
            xfree(f->separator); f->separator = NULL;
            xfree(f->options); f->options = NULL;
        } else {
            f = (struct contest_field *) contests_new_node(CONTEST_FIELD);
            xml_link_node_last(&phr->ss->edited_cnts->b, &f->b);
            phr->ss->edited_cnts->fields[user_field] = f;
            f->id = user_field;
        }
        f->mandatory = mandatory;
        f->checkbox = checkbox;
        f->is_password = is_password;
        if (legend) {
            f->legend = xstrdup(legend);
        }
        if (separator) {
            f->separator = xstrdup(separator);
        }
        if (options) {
            f->options = xstrdup(options);
        }
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_members: {
        const unsigned char *member = NULL;
        if (hr_cgi_param(phr, "member", &member) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        int member_id = contests_parse_member(member);
        if (member_id < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        const unsigned char *member_field_name = NULL;
        int r = hr_cgi_param(phr, "member_field_name", &member_field_name);
        if (r < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (!r || !member_field_name || !*member_field_name) {
            int min_count = 0, max_count = 0, init_count = 0;
            if (hr_cgi_param_int(phr, "min_count", &min_count) < 0 || min_count < 0 || min_count > 100) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
            if (hr_cgi_param_int(phr, "max_count", &max_count) < 0 || max_count < min_count || max_count > 100) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
            if (hr_cgi_param_int(phr, "init_count", &init_count) < 0 || init_count < min_count || init_count > max_count) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
            struct contest_member *m = phr->ss->edited_cnts->members[member_id];
            if (!m) {
                m = (struct contest_member *) contests_new_node(CONTEST_CONTESTANTS + member_id);
                xml_link_node_last(&phr->ss->edited_cnts->b, &m->b);
                phr->ss->edited_cnts->members[member_id] = m;
            }
            m->min_count = min_count;
            m->max_count = max_count;
            m->init_count = init_count;
            cJSON_AddTrueToObject(phr->json_result, "result");
            phr->status_code = 200;
            return;
        }
        int member_field = contests_parse_member_field_name(member_field_name);
        if (member_field <= 0 || member_field >= CONTEST_LAST_MEMBER_FIELD) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        struct contest_member *m = phr->ss->edited_cnts->members[member_id];
        if (!m) {
            m = (struct contest_member *) contests_new_node(CONTEST_CONTESTANTS + member_id);
            xml_link_node_last(&phr->ss->edited_cnts->b, &m->b);
            phr->ss->edited_cnts->members[member_id] = m;
        }
        int mandatory = -1, checkbox = -1, is_password = -1;
        const unsigned char *legend = NULL, *separator = NULL, *options = NULL;
        hr_cgi_param_bool_opt(phr, "mandatory", &mandatory, 0);
        hr_cgi_param_bool_opt(phr, "checkbox", &checkbox, 0);
        hr_cgi_param_bool_opt(phr, "is_password", &is_password, 0);
        hr_cgi_param(phr, "legend", &legend);
        hr_cgi_param(phr, "separator", &separator);
        hr_cgi_param(phr, "options", &options);
        struct contest_field *f = m->fields[member_field];
        if (f) {
            f->mandatory = 0;
            f->checkbox = 0;
            f->is_password = 0;
            xfree(f->legend); f->legend = NULL;
            xfree(f->separator); f->separator = NULL;
            xfree(f->options); f->options = NULL;
        } else {
            f = (struct contest_field *) contests_new_node(CONTEST_FIELD);
            xml_link_node_last(&m->b, &f->b);
            m->fields[member_field] = f;
            f->id = member_field;
        }
        f->mandatory = mandatory;
        f->checkbox = checkbox;
        f->is_password = is_password;
        if (legend) {
            f->legend = xstrdup(legend);
        }
        if (separator) {
            f->separator = xstrdup(separator);
        }
        if (options) {
            f->options = xstrdup(options);
        }
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    case CNTS_oauth_rules: {
        const unsigned char *domain = NULL;
        if (hr_cgi_param(phr, "domain", &domain) <= 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        int allow = -1, deny = -1, strip_domain = -1, disable_email_check = -1;
        hr_cgi_param_bool_opt(phr, "allow", &allow, -1);
        hr_cgi_param_bool_opt(phr, "deny", &deny, -1);
        hr_cgi_param_bool_opt(phr, "strip_domain", &strip_domain, -1);
        hr_cgi_param_bool_opt(phr, "disable_email_check", &disable_email_check, -1);
        int atfront = 0, atback = 0;
        const unsigned char *before = NULL;
        hr_cgi_param_bool_opt(phr, "atfront", &atfront, 0);
        hr_cgi_param_bool_opt(phr, "atback", &atback, 0);
        if (hr_cgi_param(phr, "before", &before) < 0) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        if (before) {
            if (!strcmp(before, domain)) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
            if (!contests_find_oauth_rule_nc(phr->ss->edited_cnts, before)) {
                phr->err_num = SSERV_ERR_INV_PARAM;
                phr->status_code = 400;
                return;
            }
        }
        set_oauth_rule(phr->ss->edited_cnts, domain, allow, deny, strip_domain, disable_email_check, atfront, atback, before);
        cJSON_AddTrueToObject(phr->json_result, "result");
        phr->status_code = 200;
        return;
    }
    default:
        break;
    }
    if (field_type == 's') {
        unsigned char **ptr = (unsigned char **) field_ptr;
        const unsigned char *value = NULL;
        if (hr_cgi_param(phr, "value", &value) <= 0 || !value) {
            phr->err_num = SSERV_ERR_INV_PARAM;
            phr->status_code = 400;
            return;
        }
        xfree(*ptr); *ptr = xstrdup(value);
        cJSON_AddStringToObject(phr->json_result, "result", value);
        phr->status_code = 200;
        return;
    }
    phr->err_num = SSERV_ERR_INV_PARAM;
    phr->status_code = 400;
}

static void
set_contest_file_json(struct http_request_info *phr)
{
    const unsigned char *field_name = NULL;
    if (hr_cgi_param(phr, "field_name", &field_name) <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    int field_id = parse_file_field_name(field_name);
    if (field_id <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    const unsigned char *value = NULL;
    if (hr_cgi_param(phr, "value", &value) <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    const unsigned char *file_name = NULL;
    unsigned char **p_text = NULL;
    ejintbool_t *p_loaded = 0;
    get_state_file_pointers(phr->ss, phr->ss->edited_cnts, field_id, &file_name, &p_text, &p_loaded);
    if (!p_text) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    xfree(*p_text);
    *p_text = xstrdup(value);
    *p_loaded = 1;
    cJSON_AddTrueToObject(phr->json_result, "result");
    phr->status_code = 200;
}

static char **
split_by_sep(const unsigned char *str, const unsigned char *sep)
{
    int seplen = strlen(sep);
    int cnt = 0;
    char **res = NULL;
    char *cur = strstr(str, sep);
    if (!cur) {
        XCALLOC(res, 2);
        res[0] = xstrdup(str);
        return res;
    }
    ++cnt;
    do {
        cur += seplen;
        ++cnt;
        cur = strstr(str, sep);
    } while (cur);
    XCALLOC(res, cnt + 1);
    cur = (char*) str;
    int i = 0;
    for (; i < cnt - 1; ++i){
        char *next = strstr(cur, sep);
        res[i] = xmemdup(cur, next - cur);
        cur += seplen;
    }
    res[i] = xstrdup(cur);
    return res;
}

static int
parse_and_set_xarray(struct http_request_info *phr, char ***ptr)
{
    // atfront, atback, before, old_value, separator, value, index
    const unsigned char *value = NULL;
    if (hr_cgi_param(phr, "value", &value) <= 0 || !value) return -1;
    const unsigned char *sep = NULL;
    int r = hr_cgi_param(phr, "separator", &sep);
    if (r < 0) return -1;
    if (r > 0 && sep) {
        sarray_free(*ptr);
        *ptr = split_by_sep(value, sep);
        return 0;
    }
    int index = -1;
    if (hr_cgi_param_int_opt(phr, "index", &index, -1) < 0) return -1;
    if (index >= 0) {
        int slen = sarray_len(*ptr);
        if (index >= slen) return -1;
        xfree((*ptr)[index]);
        (*ptr)[index] = xstrdup(value);
        return 0;
    }
    return -1;
}

static int
parse_and_set_time(struct http_request_info *phr, time_t *ptr)
{
    const unsigned char *s = NULL;
    if (hr_cgi_param(phr, "value", &s) <= 0) return -1;
    // try time in time_t format
    char *eptr = NULL;
    errno = 0;
    long long llv = strtoll(s, &eptr, 10);
    if (!errno && !*eptr && eptr != (char*) s) {
        if (llv < 0) return -1;
        if ((time_t) llv != llv) return -1;
        *ptr = (time_t) llv;
        return 0;
    }
    time_t tv = 0;
    if (xml_parse_date(NULL, NULL, 0, 0, s, &tv) < 0) return -1;
    if (tv < 0) tv = 0;
    *ptr = tv;
    return 0;
}

static void
set_contest_global_json(struct http_request_info *phr)
{
    if (!phr->ss->global) goto status_400;
    const unsigned char *field_name = NULL;
    if (hr_cgi_param(phr, "field_name", &field_name) <= 0) goto status_400;
    int field_id = cntsglob_lookup_field(field_name);
    if (field_id <= 0) goto status_400;
    if (global_ignored_fields[field_id]) goto status_400;
    void *field_ptr = cntsglob_get_ptr_nc(phr->ss->global, field_id);
    if (!field_ptr) goto status_400;

    switch (field_id) {
    case CNTSGLOB_priority_adjustment: {
        int value = 0;
        if (hr_cgi_param_int(phr, "value", &value) <= 0 || value < -16 || value > 15) goto status_400;
        phr->ss->global->priority_adjustment = value;
        goto status_200_default;
    }
    case CNTSGLOB_score_system: {
        const unsigned char *s = NULL;
        if (hr_cgi_param(phr, "value", &s) <= 0) goto status_400;
        int value = prepare_parse_score_system(s);
        if (value < SCORE_ACM || value > SCORE_MOSCOW) goto status_400;
        phr->ss->global->score_system = value;
        goto status_200_default;
    }
    case CNTSGLOB_rounding_mode: {
        const unsigned char *s = NULL;
        if (hr_cgi_param(phr, "value", &s) <= 0) goto status_400;
        int value = prepare_parse_rounding_mode(s);
        if (value < SEC_CEIL || value > SEC_ROUND) goto status_400;
        phr->ss->global->rounding_mode = value;
        goto status_200_default;
    }
    default:
        break;
    }

    int field_type = cntsglob_get_type(field_id);
    switch (field_type) {
    case 'i': {
        int *ptr = (int*) field_ptr;
        int iv = -1;
        if (hr_cgi_param_int(phr, "value", &iv) < 0) goto status_400;
        if (iv < 0) iv = -1;
        *ptr = iv;
        goto status_200_default;
    }
    case 'z': {
        ejintsize_t *ptr = (ejintsize_t*) field_ptr;
        const unsigned char *s = NULL;
        if (hr_cgi_param(phr, "value", &s) <= 0 || !s) goto status_400;
        int iv = 0;
        if (size_str_to_num(s, &iv) < 0) goto status_400;
        if (iv < 0) iv = -1;
        *ptr = iv;
        goto status_200_default;
    }
    case 'B': {
        ejintbool_t *ptr = (ejintbool_t*) field_ptr;
        int value = -1;
        if (hr_cgi_param_bool_opt(phr, "value", &value, -1) < 0) goto status_400;
        *ptr = value;
        goto status_200_default;
    }
    case 't': {
        time_t *ptr = (time_t*) field_ptr;
        if (parse_and_set_time(phr, ptr) < 0) goto status_400;
        goto status_200_default;
    }
    case 's': {
        unsigned char **ptr = (unsigned char **) field_ptr;
        const unsigned char *s = NULL;
        if (hr_cgi_param(phr, "value", &s) <= 0 || !s) goto status_400;
        if (*ptr) xfree(*ptr);
        *ptr = xstrdup(s);
        goto status_200_default;
    }
    case 'E': {
        ej_size64_t *ptr = (ej_size64_t *) field_ptr;
        const unsigned char *s = NULL;
        if (hr_cgi_param(phr, "value", &s) <= 0 || !s) goto status_400;
        long long llv = 0;
        if (size_str_to_size64_t(s, &llv) < 0) goto status_400;
        if (llv < 0) llv = -1;
        *ptr = llv;
        goto status_200_default;
    }
    case 'x': {
        char ***ptr = (char***) field_ptr;
        if (parse_and_set_xarray(phr, ptr) < 0) goto status_400;
        goto status_200_default;
    }
    }

status_400:;
    phr->err_num = SSERV_ERR_INV_PARAM;
    phr->status_code = 400;
    return;

status_200_default:;
    cJSON_AddTrueToObject(phr->json_result, "result");
    phr->status_code = 200;
    return;
}

static int
create_abstract_problem(
        struct sid_state *ss,
        const unsigned char *short_name,
        int *p_abstract,
        int *p_prob_id,
        struct section_problem_data **p_prob)
{
    int prob_id = ss->aprob_u;
    if (ss->aprob_u == ss->aprob_a) {
        if (!ss->aprob_a) ss->aprob_a = 4;
        ss->aprob_a *= 2;
        XREALLOC(ss->aprobs, ss->aprob_a);
        XREALLOC(ss->aprob_flags, ss->aprob_a);
    }
    struct section_problem_data *prob = prepare_alloc_problem();
    prepare_problem_init_func(&prob->g);
    ss->cfg = param_merge(&prob->g, ss->cfg);
    ss->aprobs[prob_id] = prob;
    ss->aprob_flags[prob_id] = 0;
    ss->aprob_u++;
    snprintf(prob->short_name, sizeof(prob->short_name), "%s", short_name);
    prob->abstract = 1;
    prob->id = prob_id;
    *p_abstract = 1;
    *p_prob_id = prob_id;
    *p_prob = prob;
    return 1;
}

static int
create_contest_problem(
        struct sid_state *ss,
        int abstract,
        int prob_id,
        const unsigned char *short_name,
        const unsigned char *long_name,
        const unsigned char *internal_name,
        const unsigned char *uuid,
        const unsigned char *extid,
        int *p_abstract,
        int *p_prob_id,
        struct section_problem_data **p_prob)
{
    if (abstract > 0) {
        // only short name is used
        if (!short_name || !*short_name) {
            return -1;
        }
        if (strlen(short_name) >= 32) {
            return -1;
        }
        if (check_str(short_name, login_accept_chars) < 0) {
            return -1;
        }
        for (int i = 0; i < ss->aprob_a; ++i) {
            if (!strcmp(ss->aprobs[i]->short_name, short_name)) {
                return -1;
            }
        }
        for (int i = 0; i < ss->prob_a; ++i) {
            const struct section_problem_data *pp = ss->probs[i];
            if (pp && !strcmp(pp->short_name, short_name)) {
                return -1;
            }
        }
        return create_abstract_problem(ss, short_name, p_abstract, p_prob_id, p_prob);
    }

    if (prob_id > 0) {
        if (prob_id > EJ_MAX_PROB_ID) {
            return -1;
        }
        if (prob_id < ss->prob_a && ss->probs[prob_id]) {
            return -1;
        }
    } else {
        for (prob_id = 1; prob_id < ss->prob_a; ++prob_id) {
            if (!ss->probs[prob_id]) {
                break;
            }
        }
    }

    if (prob_id >= ss->prob_a) {
        int new_prob_a = ss->prob_a;
        if (!new_prob_a) new_prob_a = 16;
        while (prob_id >= new_prob_a) new_prob_a *= 2;
        struct section_problem_data **new_probs;
        int *new_prob_flags;
        XCALLOC(new_probs, new_prob_a);
        XCALLOC(new_prob_flags, new_prob_a);
        if (ss->prob_a > 0) {
            XMEMCPY(new_probs, ss->probs, ss->prob_a);
            XMEMCPY(new_prob_flags, ss->prob_flags, ss->prob_a);
        }
        xfree(ss->probs);
        xfree(ss->prob_flags);
        ss->probs = new_probs;
        ss->prob_flags = new_prob_flags;
        ss->prob_a = new_prob_a;
    }

    unsigned char short_name_buf[32];
    if (!short_name || !*short_name) {
        snprintf(short_name_buf, sizeof(short_name_buf), "prob_%d", prob_id);
        short_name = short_name_buf;
    } else {
        if (strlen(short_name) >= 32) {
            return -1;
        }
        if (check_str(short_name, login_accept_chars) < 0) {
            return -1;
        }
    }
    for (int aprob_id = 0; aprob_id < ss->aprob_u; ++aprob_id) {
        if (!strcmp(short_name, ss->aprobs[aprob_id]->short_name)) {
            return -1;
        }
    }
    for (int id = 0; id < ss->prob_a; ++id) {
        const struct section_problem_data *pp = ss->probs[id];
        if (!strcmp(pp->short_name, short_name)) {
            return -1;
        }
        if (pp->internal_name && !strcmp(pp->internal_name, short_name)) {
            return -1;
        }
    }
    if (long_name && !*long_name) {
        long_name = NULL;
    }
    if (internal_name && !*internal_name) {
        internal_name = NULL;
    }
    if (internal_name) {
        for (int aprob_id = 0; aprob_id < ss->aprob_u; ++aprob_id) {
            if (!strcmp(internal_name, ss->aprobs[aprob_id]->short_name)) {
                return -1;
            }
        }
        for (int id = 0; id < ss->prob_a; ++id) {
            const struct section_problem_data *pp = ss->probs[id];
            if (!strcmp(pp->short_name, internal_name)) {
                return -1;
            }
            if (pp->internal_name && !strcmp(pp->internal_name, internal_name)) {
                return -1;
            }
        }
    }
    if (uuid && !*uuid) {
        uuid = NULL;
    }
    if (extid && !*extid) {
        extid = NULL;
    }

    struct section_problem_data *prob = prepare_alloc_problem();
    prepare_problem_init_func(&prob->g);
    ss->cfg = param_merge(&prob->g, ss->cfg);
    ss->probs[prob_id] = prob;
    ss->prob_flags[prob_id] = 0;
    snprintf(prob->short_name, sizeof(prob->short_name), "%s", short_name);
    prob->abstract = 0;
    prob->id = prob_id;
    if (long_name) {
        prob->long_name = xstrdup(long_name);
    }
    if (internal_name) {
        prob->internal_name = xstrdup(internal_name);
    }
    if (uuid) {
        prob->uuid = xstrdup(uuid);
    }
    if (extid) {
        prob->extid = xstrdup(extid);
    }

    *p_abstract = 0;
    *p_prob_id = prob_id;
    *p_prob = prob;
    return 1;
}

static void
set_contest_problem_json_json(struct http_request_info *phr)
{
    int is_changed = 0;
    cJSON *jpf = NULL, *jaf = NULL, *jp = NULL;
    unsigned char *cfg_str = NULL;
    struct problem_config_section *cfg = NULL;
    ///////////////////////
    char *msg_s = NULL;
    size_t msg_z = 0;
    FILE *msg_f = NULL;
    int abstract = -1;
    hr_cgi_param_bool_opt(phr, "abstract", &abstract, -1);
    int prob_id = -1;
    hr_cgi_param_int_opt(phr, "prob_id", &prob_id, -1);
    const unsigned char *short_name = NULL;
    hr_cgi_param(phr, "short_name", &short_name);
    const unsigned char *long_name = NULL;
    hr_cgi_param(phr, "long_name", &long_name);
    const unsigned char *internal_name = NULL;
    hr_cgi_param(phr, "internal_name", &internal_name);
    const unsigned char *uuid = NULL;
    hr_cgi_param(phr, "uuid", &uuid);
    const unsigned char *extid = NULL;
    hr_cgi_param(phr, "extid", &extid);
    int create_mode = 0, exclusive_mode = 0;
    hr_cgi_param_bool_opt(phr, "create", &create_mode, 0);
    hr_cgi_param_bool_opt(phr, "exclusive", &exclusive_mode, 0);
    struct section_problem_data *prob = NULL;
    int out_abstract = -1, out_prob_id = -1;
    int r = lookup_contest_problem(phr->ss, abstract, prob_id, short_name, long_name, internal_name, uuid, extid, &out_abstract, &out_prob_id, &prob);
    if (r < 0) {
        if (create_mode <= 0) goto status_404;
        r = create_contest_problem(phr->ss, abstract, prob_id, short_name, long_name, internal_name, uuid, extid, &out_abstract, &out_prob_id, &prob);
        if (r < 0) {
            goto status_400;
        }
        prob_id = out_prob_id;
        abstract = out_abstract;
        is_changed = 1;
    } else {
        if (create_mode > 0 && exclusive_mode > 0) {
            goto status_429;
        }
        prob_id = out_prob_id;
        abstract = out_abstract;
    }

    // protected_fields, allowed_fields, problem
    const unsigned char *s = NULL;
    r = hr_cgi_param(phr, "protected_fields", &s);
    if (r < 0) goto status_400;
    if (r > 0 && !(jpf = cJSON_Parse(s))) goto status_400;
    r = hr_cgi_param(phr, "allowed_fields", &s);
    if (r < 0) goto status_400;
    if (r > 0 && !(jaf = cJSON_Parse(s))) goto status_400;
    if (hr_cgi_param(phr, "problem_cfg", &s) > 0 && s) {
        cfg_str = xstrdup(s);
        cfg = problem_config_section_parse_cfg_str("problem_cfg", cfg_str, strlen(cfg_str));
        if (!cfg) goto status_400;
    } else {
        r = hr_cgi_param(phr, "problem", &s);
        if (r <= 0) goto status_400;
        if (!(jp = cJSON_Parse(s))) goto status_400;
    }

    msg_f = open_memstream(&msg_s, &msg_z);
    if (cfg) {
        r = problem_assign_cfg(prob, jpf, jaf, cfg, msg_f, &is_changed);
    } else {
        r = problem_assign_json(prob, jpf, jaf, jp, msg_f, &is_changed);
    }
    fclose(msg_f); msg_f = NULL;

    cJSON *jr = cJSON_CreateObject();
    if (abstract) {
        cJSON_AddTrueToObject(jr, "abstract");
    } else {
        cJSON_AddFalseToObject(jr, "abstract");
    }
    if (is_changed) {
        cJSON_AddTrueToObject(jr, "changed");
    }
    cJSON_AddNumberToObject(jr, "prob_id", prob_id);
    cJSON_AddNumberToObject(jr, "result", r);
    cJSON_AddStringToObject(jr, "messages", msg_s);
    cJSON_AddItemToObject(phr->json_result, "result", jr);
    phr->status_code = 200;

cleanup:;
    if (msg_f) fclose(msg_f);
    free(msg_s);
    if (jpf) cJSON_Delete(jpf);
    if (jaf) cJSON_Delete(jaf);
    if (jp) cJSON_Delete(jp);
    if (cfg) problem_config_section_free(&cfg->g);
    free(cfg_str);
    return;

status_400:;
    phr->err_num = SSERV_ERR_INV_PARAM;
    phr->status_code = 400;
    goto cleanup;

status_404:;
    phr->err_num = SSERV_ERR_INV_PARAM;
    phr->status_code = 404;
    goto cleanup;

status_429:;
    phr->err_num = SSERV_ERR_INV_PARAM;
    phr->status_code = 429;
    goto cleanup;
}

void
super_serve_api_CNTS_SET_VALUE_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    ej_cookie_t sid = 0;
    ej_cookie_t client_key = 0;
    if (parse_session(phr, "session", &sid, &client_key) <= 0) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    struct sid_state *ss = sid_state_find(sid, client_key);
    if (!ss) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    phr->ss = ss;
    if (!ss->edited_cnts) {
        phr->err_num = SSERV_ERR_NO_EDITED_CNTS;
        phr->status_code = 400;
        return;
    }
    const unsigned char *section = NULL;
    if (hr_cgi_param(phr, "section", &section) <= 0) {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
    if (!strcmp(section, "contest.xml")) {
        set_contest_xml_json(phr);
        return;
    } else if (!strcmp(section, "file")) {
        set_contest_file_json(phr);
        return;
    } else if (!strcmp(section, "global")) {
        set_contest_global_json(phr);
        return;
    } else if (!strcmp(section, "problem.json")) {
        set_contest_problem_json_json(phr);
        return;
    } else {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
}

void
super_serve_api_CNTS_MINIMIZE_PROBLEM_JSON(
        FILE *out_f,
        struct http_request_info *phr)
{
    ej_cookie_t sid = 0;
    ej_cookie_t client_key = 0;
    if (parse_session(phr, "session", &sid, &client_key) <= 0) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    struct sid_state *ss = sid_state_find(sid, client_key);
    if (!ss) {
        phr->err_num = SSERV_ERR_INV_SESSION;
        phr->status_code = 400;
        return;
    }
    phr->ss = ss;
    if (!ss->edited_cnts) {
        phr->err_num = SSERV_ERR_NO_EDITED_CNTS;
        phr->status_code = 400;
        return;
    }

    int abstract = -1;
    hr_cgi_param_bool_opt(phr, "abstract", &abstract, -1);
    int prob_id = -1;
    hr_cgi_param_int_opt(phr, "prob_id", &prob_id, -1);
    const unsigned char *short_name = NULL;
    hr_cgi_param(phr, "short_name", &short_name);
    const unsigned char *long_name = NULL;
    hr_cgi_param(phr, "long_name", &long_name);
    const unsigned char *internal_name = NULL;
    hr_cgi_param(phr, "internal_name", &internal_name);
    const unsigned char *uuid = NULL;
    hr_cgi_param(phr, "uuid", &uuid);
    const unsigned char *extid = NULL;
    hr_cgi_param(phr, "extid", &extid);
    struct section_problem_data *prob = NULL;
    int r = lookup_contest_problem(phr->ss, abstract, prob_id, short_name, long_name, internal_name, uuid, extid, NULL, NULL, &prob);
    if (r < 0) {
        phr->status_code = -r;
        return;
    }
    if (!prob) {
        phr->status_code = 404;
        return;
    }
    const struct section_problem_data *aprob = NULL;
    if (prob->abstract <= 0 && prob->super[0]) {
        for (int i = 0; i < phr->ss->aprob_u; ++i) {
            const struct section_problem_data *p = phr->ss->aprobs[i];
            if (p && !strcmp(p->short_name, prob->super)) {
                aprob = p;
                break;
            }
        }
    }

    problem_minimize(prob, aprob);
    cJSON_AddTrueToObject(phr->json_result, "result");
    phr->status_code = 200;
    return;
}
