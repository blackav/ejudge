/* -*- mode: c -*- */

/* Copyright (C) 2011-2025 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/new_server_proto.h"
#include "ejudge/opcaps.h"
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
    } else {
        phr->err_num = SSERV_ERR_INV_PARAM;
        phr->status_code = 400;
        return;
    }
}
