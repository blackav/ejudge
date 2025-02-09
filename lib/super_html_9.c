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
#include "ejudge/opcaps.h"
#include "ejudge/super-serve.h"
#include "ejudge/super_html.h"
#include "ejudge/super_proto.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/http_request.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/contests.h"
#include "ejudge/random.h"
#include "ejudge/logger.h"
#include "ejudge/cJSON.h"

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

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
    super_html_load_serve_cfg(rw_cnts, phr->config, phr->ss);

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
    if (contests_get(other_contest_id, &other_cnts) < 0 || !other_cnts) {
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
super_serve_api_CNTS_LIST_SESSIONS_JSON(
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
    r = super_html_commit_contest_2(comm_f, phr->user_id, phr->login, &phr->ip, phr->config, phr->userlist_clnt, phr->ss);
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
