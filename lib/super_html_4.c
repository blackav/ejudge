/* -*- mode: c -*- */

/* Copyright (C) 2008-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/version.h"
#include "ejudge/ej_limits.h"
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"
#include "ejudge/meta/super-serve_meta.h"
#include "ejudge/super_proto.h"
#include "ejudge/copyright.h"
#include "ejudge/misctext.h"
#include "ejudge/contests.h"
#include "ejudge/meta/contests_meta.h"
#include "ejudge/l10n.h"
#include "ejudge/charsets.h"
#include "ejudge/fileutl.h"
#include "ejudge/xml_utils.h"
#include "ejudge/userlist.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/mischtml.h"
#include "ejudge/prepare.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/meta_generic.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/cpu.h"
#include "ejudge/compat.h"
#include "ejudge/errlog.h"
#include "ejudge/external_action.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <dlfcn.h>

#if !defined CONF_STYLE_PREFIX
#define CONF_STYLE_PREFIX "/ejudge/"
#endif

#define ARMOR(s)  html_armor_buf(&ab, s)
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

static const char fancy_priv_header[] =
"Content-Type: %s; charset=%s\n"
"Cache-Control: no-cache\n"
"Pragma: no-cache\n\n"
"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
"<html><head>\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=%s\"/>\n"
"<link rel=\"stylesheet\" href=\"%spriv.css\" type=\"text/css\">\n"
  //"<link rel=\"shortcut icon\" type=\"image/x-icon\" href=\"/favicon.ico\">\n"
"<title>%s</title></head>\n"
"<body>\n";

void
ss_write_html_header(
        FILE *out_f,
        struct http_request_info *phr,
        const unsigned char *title)
{
  fprintf(out_f, fancy_priv_header,
          "text/html", EJUDGE_CHARSET, EJUDGE_CHARSET, CONF_STYLE_PREFIX,
          title);

  fprintf(out_f, "</head>");
  fprintf(out_f, "<body>");
}

static const char fancy_priv_footer[] =
"<hr/>%s</body></html>\n";
void
ss_write_html_footer(FILE *out_f)
{
  fprintf(out_f, fancy_priv_footer, get_copyright(0));
}

static void
write_json_header(FILE *out_f)
{
  fprintf(out_f, "Content-type: text/plain; charset=%s\n\n",
          EJUDGE_CHARSET);
}

static void
refresh_page(
        FILE *out_f,
        struct http_request_info *phr,
        const char *format,
        ...)
  __attribute__((format(printf, 3, 4)));
static void
refresh_page(
        FILE *out_f,
        struct http_request_info *phr,
        const char *format,
        ...)
{
  va_list args;
  char buf[1024];
  char url[1024];

  buf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
  }

  if (!buf[0] && !phr->session_id) {
    snprintf(url, sizeof(url), "%s", phr->self_url);
  } else if (!buf[0]) {
    snprintf(url, sizeof(url), "%s?SID=%016llx", phr->self_url,
             phr->session_id);
  } else if (!phr->session_id) {
    snprintf(url, sizeof(url), "%s?%s", phr->self_url, buf);
  } else {
    snprintf(url, sizeof(url), "%s?SID=%016llx&%s", phr->self_url,
             phr->session_id, buf);
  }

  fprintf(out_f, "Location: %s\n", url);
  if (phr->client_key) {
    fprintf(out_f, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", phr->client_key);
  }
  putc('\n', out_f);
}

typedef int (*handler_func_t)(FILE *log_f, FILE *out_f, struct http_request_info *phr);

static int
cmd_edited_cnts_back(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  refresh_page(out_f, phr, NULL);
  return 0;
}

static int
cmd_edited_cnts_continue(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  refresh_page(out_f, phr, "action=%d", SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE);
  return 0;
}

static int
cmd_edited_cnts_start_new(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  int contest_id = 0;

  if (hr_cgi_param_int_opt(phr, "contest_id", &contest_id, 0) < 0
      || contest_id < 0) contest_id = 0;
  super_serve_clear_edited_contest(phr->ss);
  if (!contest_id) {
    refresh_page(out_f, phr, "action=%d", SSERV_CMD_CREATE_CONTEST_PAGE);
  } else {
    refresh_page(out_f, phr, "action=%d&contest_id=%d", SSERV_CMD_CNTS_START_EDIT_ACTION, contest_id);
  }

  return 0;
}

// forget the contest editing from the other session and return
// to the main page
// all errors are silently ignored
static int
cmd_locked_cnts_forget(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  struct sid_state *ss;
  int contest_id = -1;

  if (phr->ss->edited_cnts)
    goto done;
  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0 || contest_id <= 0)
    goto done;
  if (!(ss = super_serve_sid_state_get_cnts_editor_nc(contest_id)))
    goto done;
  if (ss->user_id != phr->user_id)
    goto done;
  super_serve_clear_edited_contest(ss);

 done:;
  refresh_page(out_f, phr, NULL);
  return 0;
}

// move the editing information to this session and continue editing
// all errors are silently ignored
static int
cmd_locked_cnts_continue(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  struct sid_state *ss;
  int contest_id = 0;

  if (phr->ss->edited_cnts)
    goto top_level;
  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0 || contest_id <= 0)
    goto top_level;
  if (!(ss = super_serve_sid_state_get_cnts_editor_nc(contest_id)))
    goto top_level;
  if (ss->user_id != phr->user_id)
    goto top_level;

  super_serve_move_edited_contest(phr->ss, ss);
  refresh_page(out_f, phr, "action=%d", SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE);
  return 0;

 top_level:;
  refresh_page(out_f, phr, NULL);
  return 0;
}

static int
cmd_logout(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  if (phr->userlist_clnt) {
    userlist_clnt_delete_cookie(phr->userlist_clnt, phr->user_id,
                                0,
                                phr->client_key,
                                phr->session_id);
  }
  // FIXME: release other session-related resources
  phr->session_id = 0;
  refresh_page(out_f, phr, NULL);
  return 0;
}

static int
cmd_clear_session(
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr)
{
  const unsigned char *s = NULL;
  if (hr_cgi_param(phr, "other_session_id", &s) <= 0 || !s) {
    goto done;
  }
  char *eptr = NULL;
  errno = 0;
  unsigned long long other_session_id = strtoull(s, &eptr, 16);
  if (errno || *eptr || eptr == (char*) s || !other_session_id) {
    goto done;
  }

  if (phr->priv_level != PRIV_LEVEL_ADMIN) {
    goto done;
  }
  opcap_t caps = 0;
  if (ejudge_cfg_opcaps_find(phr->config, phr->login, &caps) < 0) {
    goto done;
  }
  if (opcaps_check(caps, OPCAP_EDIT_CONTEST) < 0) {
    goto done;
  }

  super_serve_sid_state_clear(other_session_id);
  info("session %016llx cleared by %s", other_session_id, phr->login);

done:;
  refresh_page(out_f, phr, "action=%d", SSERV_CMD_MAIN_PAGE);
  return 0;
}

static handler_func_t op_handlers[SSERV_CMD_LAST] =
{
  [SSERV_CMD_LOGOUT] = cmd_logout,
  [SSERV_CMD_EDITED_CNTS_BACK] = cmd_edited_cnts_back,
  [SSERV_CMD_EDITED_CNTS_CONTINUE] = cmd_edited_cnts_continue,
  [SSERV_CMD_EDITED_CNTS_START_NEW] = cmd_edited_cnts_start_new,
  [SSERV_CMD_LOCKED_CNTS_FORGET] = cmd_locked_cnts_forget,
  [SSERV_CMD_LOCKED_CNTS_CONTINUE] = cmd_locked_cnts_continue,
  [SSERV_CMD_CLEAR_SESSION] = cmd_clear_session,

  /* Note: operations SSERV_CMD_USER_*, SSERV_CMD_GROUP_* are loaded using dlsym */
};

extern void super_html_6_force_link(void);
void *super_html_6_force_link_ptr = super_html_6_force_link;
extern void super_html_7_force_link(void);
void *super_html_7_force_link_ptr = super_html_7_force_link;

static int
parse_opcode(struct http_request_info *phr, int *p_opcode)
{
  const unsigned char *s = NULL;
  if (hr_cgi_param(phr, "op", &s) <= 0 || !s || !*s) {
    *p_opcode = 0;
    return 0;
  }
  const unsigned char *q;
  for (q = s; isdigit(*q); ++q) {}
  if (!*q) {
    char *eptr = NULL;
    errno = 0;
    long val = strtol(s, &eptr, 10);
    if (errno || *eptr) return SSERV_ERR_INV_OPER;
    if (val < 0 || val >= SSERV_CMD_LAST) return SSERV_ERR_INV_OPER;
    *p_opcode = val;
    return 0;
  }

  for (int i = 1; i < SSERV_CMD_LAST; ++i) {
    if (!strcasecmp(super_proto_cmd_names[i], s)) {
      *p_opcode = i;
      return 0;
    }
  }
  *p_opcode = 0;
  return 0;
}

static int
parse_action(struct http_request_info *phr)
{
  int action = 0;
  int n = 0, r = 0;
  const unsigned char *s = 0;

  if ((s = hr_cgi_nname(phr, "action_", 7))) {
    if (sscanf(s, "action_%d%n", &action, &n) != 1 || s[n] || action < 0 || action >= SSERV_CMD_LAST) {
      return -1;
    }
  } else if ((r = hr_cgi_param(phr, "action", &s)) < 0 || !s || !*s) {
    phr->action = 0;
    return 0;
  } else {
    if (sscanf(s, "%d%n", &action, &n) != 1 || s[n] || action < 0 || action >= SSERV_CMD_LAST) {
      return -1;
    }
  }

  if (action == SSERV_CMD_HTTP_REQUEST) {
    // compatibility option: parse op
    if ((s = hr_cgi_nname(phr, "op_", 3))) {
      if (sscanf(s, "op_%d%n", &action, &n) != 1 || s[n] || action < 0 || action >= SSERV_CMD_LAST)
        return -1;
    } else if (parse_opcode(phr, &action) < 0) {
      return -1;
    }
  }
  phr->action = action;
  return action;
}

static void *self_dl_handle = 0;
static int
do_http_request(FILE *log_f, FILE *out_f, struct http_request_info *phr)
{
  int action = 0;
  int retval = 0;

  if ((action = parse_action(phr)) < 0) {
    FAIL(SSERV_ERR_INV_OPER);
  }

  if (!super_proto_cmd_names[action]) FAIL(SSERV_ERR_INV_OPER);
  if (op_handlers[action] == (handler_func_t) 1) FAIL(SSERV_ERR_NOT_IMPLEMENTED);

  if (!op_handlers[action]) {
    if (self_dl_handle == (void*) 1) FAIL(SSERV_ERR_NOT_IMPLEMENTED);
    self_dl_handle = dlopen(NULL, RTLD_NOW);
    if (!self_dl_handle) {
      err("do_http_request: dlopen failed: %s", dlerror());
      self_dl_handle = (void*) 1;
      FAIL(SSERV_ERR_NOT_IMPLEMENTED);
    }

    int redir_action = action;
    if (super_proto_op_redirect[action] > 0) {
      redir_action = super_proto_op_redirect[action];
      if (redir_action <= 0 || redir_action >= SSERV_CMD_LAST || !super_proto_cmd_names[redir_action]) {
        err("do_http_request: invalid action redirect %d->%d", action, redir_action);
        op_handlers[action] = (handler_func_t) 1;
        FAIL(SSERV_ERR_NOT_IMPLEMENTED);
      }
      if (op_handlers[redir_action] == (handler_func_t) 1) {
        err("do_http_request: not implemented action redirect %d->%d", action, redir_action);
        op_handlers[action] = (handler_func_t) 1;
        FAIL(SSERV_ERR_NOT_IMPLEMENTED);
      }
    }

    if (op_handlers[redir_action]) {
      op_handlers[action] = op_handlers[redir_action];
    } else {
      unsigned char func_name[512];
      snprintf(func_name, sizeof(func_name), "super_serve_op_%s", super_proto_cmd_names[redir_action]);
      void *void_func = dlsym(self_dl_handle, func_name);
      if (!void_func) {
        err("do_http_request: function %s is not found", func_name);
        op_handlers[action] = (handler_func_t) 1;
        FAIL(SSERV_ERR_NOT_IMPLEMENTED);
      }
      op_handlers[action] = (handler_func_t) void_func;
    }
  }

  retval = (*op_handlers[action])(log_f, out_f, phr);

 cleanup:
  return retval;
}

static void
parse_cookie(struct http_request_info *phr)
{
  const unsigned char *cookies = hr_getenv(phr, "HTTP_COOKIE");
  if (!cookies) return;
  const unsigned char *s = cookies;
  ej_cookie_t client_key = 0;
  while (1) {
    while (isspace(*s)) ++s;
    if (strncmp(s, "EJSID=", 6) != 0) {
      while (*s && *s != ';') ++s;
      if (!*s) return;
      ++s;
      continue;
    }
    int n = 0;
    if (sscanf(s + 6, "%llx%n", &client_key, &n) == 1) {
      s += 6 + n;
      if (!*s || isspace(*s) || *s == ';') {
        phr->client_key = client_key;
        return;
      }
    }
    phr->client_key = 0;
    return;
  }
}

static const int external_action_aliases[SSERV_CMD_LAST] =
{
  [SSERV_CMD_SERVE_CFG_PAGE] = SSERV_CMD_CONTEST_XML_PAGE,
  [SSERV_CMD_CNTS_EDIT_USERS_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_MASTER_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_JUDGE_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_TEAM_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_SERVE_CONTROL_ACCESS_PAGE] = SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  [SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS_PAGE] = SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE,
  [SSERV_CMD_CNTS_EDIT_COACH_FIELDS_PAGE] = SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE,
  [SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS_PAGE] = SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE,
  [SSERV_CMD_CNTS_EDIT_GUEST_FIELDS_PAGE] = SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE,
  [SSERV_CMD_GLOB_EDIT_CONTEST_STOP_CMD_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_USERS_HEADER_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_USERS_FOOTER_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_COPYRIGHT_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_WELCOME_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_REG_WELCOME_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE_PAGE] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE,
  [SSERV_CMD_CNTS_START_EDIT_VARIANT_ACTION] = SSERV_CMD_CNTS_EDIT_CUR_VARIANT_PAGE,
  [SSERV_CMD_USER_SEL_VIEW_CNTS_PASSWD_PAGE] = SSERV_CMD_USER_SEL_VIEW_PASSWD_PAGE,
  [SSERV_CMD_USER_SEL_CLEAR_CNTS_PASSWD_PAGE] = SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE,
  [SSERV_CMD_USER_SEL_RANDOM_CNTS_PASSWD_PAGE] = SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE,
  [SSERV_CMD_USER_SEL_DELETE_REG_PAGE] = SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE,
  [SSERV_CMD_USER_SEL_CHANGE_REG_STATUS_PAGE] = SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE,
  [SSERV_CMD_USER_SEL_CHANGE_REG_FLAGS_PAGE] = SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE,
  [SSERV_CMD_USER_SEL_CREATE_REG_PAGE] = SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE,
  [SSERV_CMD_USER_SEL_CREATE_REG_AND_COPY_PAGE] = SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE,
};
static const unsigned char * const external_action_names[SSERV_CMD_LAST] =
{
  [SSERV_CMD_LOGIN_PAGE] = "login_page",
  [SSERV_CMD_MAIN_PAGE] = "main_page",
  [SSERV_CMD_CONTEST_PAGE] = "contest_page",
  [SSERV_CMD_CONTEST_XML_PAGE] = "contest_xml_page",
  [SSERV_CMD_CREATE_CONTEST_PAGE] = "create_contest_page",
  [SSERV_CMD_CREATE_CONTEST_2_ACTION] = "create_contest_2_action",
  [SSERV_CMD_CONTEST_ALREADY_EDITED_PAGE] = "contest_already_edited_page",
  [SSERV_CMD_CONTEST_LOCKED_PAGE] = "contest_locked_page",
  [SSERV_CMD_CHECK_TESTS_PAGE] = "check_tests_page",
  [SSERV_CMD_CNTS_EDIT_PERMISSIONS_PAGE] = "cnts_edit_permissions_page",
  [SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE] = "cnts_edit_access_page",
  [SSERV_CMD_CNTS_EDIT_USER_FIELDS_PAGE] = "cnts_edit_user_fields_page",
  [SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS_PAGE] = "cnts_edit_member_fields_page",
  [SSERV_CMD_CNTS_START_EDIT_ACTION] = "cnts_start_edit_action",
  [SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE] = "cnts_edit_cur_contest_page",
  [SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD_PAGE] = "cnts_edit_file_page",
  [SSERV_CMD_CNTS_RELOAD_FILE_ACTION] = "cnts_reload_file_action",
  [SSERV_CMD_CNTS_CLEAR_FILE_ACTION] = "cnts_clear_file_action",
  [SSERV_CMD_CNTS_SAVE_FILE_ACTION] = "cnts_save_file_action",
  [SSERV_CMD_CNTS_EDIT_CUR_GLOBAL_PAGE] = "cnts_edit_cur_global_page",
  [SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE] = "cnts_edit_cur_languages_page",
  [SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE] = "cnts_edit_cur_problems_page",
  [SSERV_CMD_CNTS_EDIT_CUR_PROBLEM_PAGE] = "cnts_edit_cur_problem_page",
  [SSERV_CMD_CNTS_START_EDIT_PROBLEM_ACTION] = "cnts_start_edit_problem_action",
  [SSERV_CMD_CNTS_EDIT_CUR_VARIANT_PAGE] = "cnts_edit_cur_variant_page",
  [SSERV_CMD_CNTS_NEW_SERVE_CFG_PAGE] = "cnts_new_serve_cfg_page",
  [SSERV_CMD_CNTS_COMMIT_PAGE] = "cnts_commit_page",
  [SSERV_CMD_USER_BROWSE_PAGE] = "user_browse_page",
  [SSERV_CMD_USER_BROWSE_DATA] = "user_browse_data",
  [SSERV_CMD_GET_CONTEST_LIST] = "get_contest_list",
  [SSERV_CMD_CNTS_SAVE_BASIC_FORM] = "cnts_save_basic_form",
  [SSERV_CMD_CNTS_SAVE_FLAGS_FORM] = "cnts_save_flags_form",
  [SSERV_CMD_CNTS_SAVE_REGISTRATION_FORM] = "cnts_save_registration_form",
  [SSERV_CMD_CNTS_SAVE_TIMING_FORM] = "cnts_save_timing_form",
  [SSERV_CMD_CNTS_SAVE_URLS_FORM] = "cnts_save_urls_form",
  [SSERV_CMD_CNTS_SAVE_HEADERS_FORM] = "cnts_save_headers_form",
  [SSERV_CMD_CNTS_SAVE_ATTRS_FORM] = "cnts_save_attrs_form",
  [SSERV_CMD_CNTS_SAVE_NOTIFICATIONS_FORM] = "cnts_save_notifications_form",
  [SSERV_CMD_CNTS_SAVE_ADVANCED_FORM] = "cnts_save_advanced_form",
  [SSERV_CMD_GLOB_SAVE_MAIN_FORM] = "glob_save_main_form",
  [SSERV_CMD_GLOB_SAVE_CAPABILITIES_FORM] = "glob_save_capabilities_form",
  [SSERV_CMD_GLOB_SAVE_FILES_FORM] = "glob_save_files_form",
  [SSERV_CMD_GLOB_SAVE_QUOTAS_FORM] = "glob_save_quotas_form",
  [SSERV_CMD_GLOB_SAVE_URLS_FORM] = "glob_save_urls_form",
  [SSERV_CMD_GLOB_SAVE_ATTRS_FORM] = "glob_save_attrs_form",
  [SSERV_CMD_GLOB_SAVE_ADVANCED_FORM] = "glob_save_advanced_form",
  [SSERV_CMD_GLOB_SAVE_LIMITS_FORM] = "glob_save_limits_form",
  [SSERV_CMD_LANG_SAVE_MAIN_FORM] = "lang_save_main_form",
  [SSERV_CMD_PROB_SAVE_ID_FORM] = "prob_save_id_form",
  [SSERV_CMD_PROB_SAVE_FILES_FORM] = "prob_save_files_form",
  [SSERV_CMD_PROB_SAVE_VALIDATION_FORM] = "prob_save_validation_form",
  [SSERV_CMD_PROB_SAVE_VIEW_FORM] = "prob_save_view_form",
  [SSERV_CMD_PROB_SAVE_SUBMISSION_FORM] = "prob_save_submission_form",
  [SSERV_CMD_PROB_SAVE_COMPILING_FORM] = "prob_save_compiling_form",
  [SSERV_CMD_PROB_SAVE_RUNNING_FORM] = "prob_save_running_form",
  [SSERV_CMD_PROB_SAVE_LIMITS_FORM] = "prob_save_limits_form",
  [SSERV_CMD_PROB_SAVE_CHECKING_FORM] = "prob_save_checking_form",
  [SSERV_CMD_PROB_SAVE_SCORING_FORM] = "prob_save_scoring_form",
  [SSERV_CMD_PROB_SAVE_FEEDBACK_FORM] = "prob_save_feedback_form",
  [SSERV_CMD_PROB_SAVE_STANDING_FORM] = "prob_save_standing_form",
  [SSERV_CMD_MAIN_PAGE_BUTTON] = "main_page_button",
  [SSERV_CMD_IMPORT_FROM_POLYGON_PAGE] = "import_from_polygon_page",
  [SSERV_CMD_IMPORT_CONTEST_FROM_POLYGON_PAGE] = "import_contest_from_polygon_page",
  [SSERV_CMD_UPDATE_FROM_POLYGON_PAGE] = "update_from_polygon_page",
  [SSERV_CMD_DOWNLOAD_PROGRESS_PAGE] = "download_progress_page",
  [SSERV_CMD_GROUP_CREATE_PAGE] = "group_create_page",
  [SSERV_CMD_GROUP_BROWSE_PAGE] = "group_browse_page",
  [SSERV_CMD_USER_IMPORT_CSV_PAGE] = "user_import_csv_page",
  [SSERV_CMD_USER_CREATE_FROM_CSV_PAGE] = "user_create_from_csv_page",
  [SSERV_CMD_USER_CREATE_MANY_PAGE] = "user_create_many_page",
  [SSERV_CMD_USER_CREATE_ONE_PAGE] = "user_create_one_page",
  [SSERV_CMD_CAPS_EDIT_PAGE] = "caps_edit_page",
  [SSERV_CMD_CAPS_MAIN_PAGE] = "caps_main_page",
  [SSERV_CMD_MIGRATION_PAGE] = "migration_page",
  [SSERV_CMD_EJUDGE_XML_MUST_RESTART] = "ejudge_xml_must_restart",
  [SSERV_CMD_USER_MAP_MAIN_PAGE] = "user_map_main_page",
  [SSERV_CMD_EJUDGE_XML_UPDATE_ACTION] = "ejudge_xml_update_action",
  [SSERV_CMD_GROUP_DELETE_PAGE] = "group_delete_page",
  [SSERV_CMD_GROUP_MODIFY_PAGE] = "group_modify_page",
  [SSERV_CMD_USER_CREATE_REG_PAGE] = "user_create_reg_page",
  [SSERV_CMD_USER_EDIT_REG_PAGE] = "user_edit_reg_page",
  [SSERV_CMD_USER_SEL_VIEW_PASSWD_PAGE] = "user_sel_view_passwd_page",
  [SSERV_CMD_USER_DELETE_MEMBER_PAGE] = "user_delete_member_page",
  [SSERV_CMD_USER_DELETE_REG_PAGE] = "user_delete_reg_page",
  [SSERV_CMD_USER_CNTS_PASSWORD_PAGE] = "user_cnts_password_page",
  [SSERV_CMD_USER_PASSWORD_PAGE] = "user_password_page",
  [SSERV_CMD_USER_DETAIL_PAGE] = "user_detail_page",
  [SSERV_CMD_USER_SEL_RANDOM_PASSWD_PAGE] = "user_sel_random_passwd_page",
  [SSERV_CMD_EDIT_SESSIONS_PAGE] = "edit_sessions_page",
};

static const unsigned char * const external_error_names[SSERV_ERR_LAST] =
{
  [1] = "error_unknown_page", // here comes the default error handler
};

static ExternalActionState *external_action_states[SSERV_CMD_LAST];
static ExternalActionState *external_error_states[SSERV_ERR_LAST];

static void
default_error_page(
        char **p_out_t,
        size_t *p_out_z,
        struct http_request_info *phr)
{
  if (phr->log_f) {
    fclose(phr->log_f); phr->log_f = NULL;
  }
  FILE *out_f = open_memstream(p_out_t, p_out_z);

  if (phr->error_code < 0) phr->error_code = -phr->error_code;
  unsigned char buf[32];
  const unsigned char *errmsg = 0;
  if (phr->error_code > 0 && phr->error_code < SSERV_ERR_LAST) {
    errmsg = super_proto_error_messages[phr->error_code];
  }
  if (!errmsg) {
    snprintf(buf, sizeof(buf), "%d", phr->error_code);
    errmsg = buf;
  }

  fprintf(out_f, "Content-type: text/html; charset=%s\n\n", EJUDGE_CHARSET);
  fprintf(out_f,
          "<html>\n"
          "<head>\n"
          "<title>Error: %s</title>\n"
          "</head>\n"
          "<body>\n"
          "<h1>Error: %s</h1>\n",
          errmsg, errmsg);
  if (phr->log_t && *phr->log_t) {
    fprintf(out_f, "<p>Additional messages:</p>\n");
    unsigned char *s = html_armor_string_dup(phr->log_t);
    fprintf(out_f, "<pre><font color=\"red\">%s</font></pre>\n", s);
    xfree(s); s = NULL;
    xfree(phr->log_t); phr->log_t = NULL;
    phr->log_z = 0;
  }
  fprintf(out_f, "</body>\n</html>\n");
  fclose(out_f); out_f = NULL;
}

typedef PageInterface *(*external_action_handler_t)(void);

static void
external_error_page(
        char **p_out_t,
        size_t *p_out_z,
        struct http_request_info *phr,
        int error_code)
{
  if (error_code < 0) error_code = -error_code;
  if (error_code <= 0 || error_code >= SSERV_ERR_LAST) error_code = 1;
  phr->error_code = error_code;

  if (!external_error_names[error_code]) error_code = 1;
  if (!external_error_names[error_code]) {
    default_error_page(p_out_t, p_out_z, phr);
    return;
  }

  external_error_states[error_code] = external_action_load(external_error_states[error_code],
                                                           "csp/super-server",
                                                           external_error_names[error_code],
                                                           "csp_get_",
                                                           NULL /* fixed_src_dir */,
                                                           phr->current_time,
                                                           0 /* contest_id */,
                                                           0 /* allow_fail */);
  if (!external_error_states[error_code] || !external_error_states[error_code]->action_handler) {
    default_error_page(p_out_t, p_out_z, phr);
    return;
  }
  PageInterface *pg = ((external_action_handler_t) external_error_states[error_code]->action_handler)();
  if (!pg) {
    default_error_page(p_out_t, p_out_z, phr);
    return;
  }

  phr->out_f = open_memstream(p_out_t, p_out_z);
  fprintf(phr->out_f, "Content-type: text/html; charset=%s\n\n", EJUDGE_CHARSET);
  pg->ops->render(pg, NULL, phr->out_f, phr);
  xfree(phr->log_t); phr->log_t = NULL;
  phr->log_z = 0;
  fclose(phr->out_f); phr->out_f = NULL;
}

void
super_html_http_request(
        char **p_out_t,
        size_t *p_out_z,
        struct http_request_info *phr)
{
  int r = 0, n;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *script_name = 0;
  const unsigned char *protocol = "http";
  const unsigned char *s = 0;
  unsigned char self_url_buf[4096];
  unsigned char context_url[4096];
  unsigned char hid_buf[4096];
  int ext_action = 0;

  if (hr_getenv(phr, "SSL_PROTOCOL") || hr_getenv(phr, "HTTPS")) {
    phr->ssl_flag = 1;
    protocol = "https";
  }
  if (!(phr->http_host = hr_getenv(phr, "HTTP_HOST"))) phr->http_host = "localhost";
  if (!(script_name = hr_getenv(phr, "SCRIPT_NAME")))
    script_name = "/cgi-bin/serve-control";
  snprintf(self_url_buf, sizeof(self_url_buf), "%s://%s%s", protocol, phr->http_host, script_name);
  phr->self_url = self_url_buf;
  phr->script_name = script_name;

  snprintf(context_url, sizeof(context_url), "%s", phr->self_url);
  unsigned char *rs = strrchr(context_url, '/');
  if (rs) *rs = 0;
  phr->context_url = context_url;

  if (phr->anonymous_mode) {
    phr->action = SSERV_CMD_LOGIN_PAGE;
  } else {
    parse_cookie(phr);
    if (parse_action(phr) < 0) {
      r = -SSERV_ERR_INV_OPER;
    } else {
      r = 0;
    }

    if (!r) {
      if ((r = hr_cgi_param(phr, "SID", &s)) < 0) {
        r = -SSERV_ERR_INV_SID;
      }
      if (r > 0) {
        r = 0;
        if (sscanf(s, "%llx%n", &phr->session_id, &n) != 1
            || s[n] || !phr->session_id) {
          r = -SSERV_ERR_INV_SID;
        }
      }
    }
  }

  hr_cgi_param_int_opt(phr, "contest_id", &phr->contest_id, 0);

  if (!r) {
    // try external actions
    ext_action = phr->action;

redo_action:
    // main_page by default
    if (!super_proto_cmd_names[ext_action]) ext_action = SSERV_CMD_MAIN_PAGE;

    if (ext_action < 0 || ext_action >= SSERV_CMD_LAST) ext_action = 0;
    if (external_action_aliases[ext_action] > 0) ext_action = external_action_aliases[ext_action];
    if (external_action_names[ext_action]) {
      if (phr->current_time <= 0) phr->current_time = time(NULL);
      external_action_states[ext_action] = external_action_load(external_action_states[ext_action],
                                                                "csp/super-server",
                                                                external_action_names[ext_action],
                                                                "csp_get_",
                                                                NULL /* fixed_src_dir */,
                                                                phr->current_time,
                                                                0 /* contest_id */,
                                                                0 /* allow_fail */);
      if (!external_action_states[ext_action] || !external_action_states[ext_action]->action_handler) {
        external_error_page(p_out_t, p_out_z, phr, SSERV_ERR_INV_OPER);
        return;
      }

      snprintf(hid_buf, sizeof(hid_buf),
               "<input type=\"hidden\" name=\"SID\" value=\"%016llx\"/>",
               phr->session_id);
      phr->hidden_vars = hid_buf;

      phr->log_f = open_memstream(&phr->log_t, &phr->log_z);
      phr->out_f = open_memstream(&phr->out_t, &phr->out_z);
      PageInterface *pg = ((external_action_handler_t) external_action_states[ext_action]->action_handler)();
      if (pg->ops->execute) {
        r = pg->ops->execute(pg, phr->log_f, phr);
        if (r < 0) {
          fclose(phr->out_f); phr->out_f = NULL;
          xfree(phr->out_t); phr->out_t = NULL;
          phr->out_z = 0;
          external_error_page(p_out_t, p_out_z, phr, -r);
          return;
        }
      }
      if (pg->ops->render) {
        snprintf(phr->content_type, sizeof(phr->content_type), "text/html; charset=%s", EJUDGE_CHARSET);
        r = pg->ops->render(pg, phr->log_f, phr->out_f, phr);
        if (r < 0) {
          fclose(phr->out_f); phr->out_f = NULL;
          xfree(phr->out_t); phr->out_t = NULL;
          phr->out_z = 0;
          external_error_page(p_out_t, p_out_z, phr, -r);
          return;
        }
        if (r > 0) {
          ext_action = r;
          if (pg->ops->destroy) pg->ops->destroy(pg);
          pg = NULL;
          fclose(phr->out_f); phr->out_f = NULL;
          xfree(phr->out_t); phr->out_t = NULL;
          fclose(phr->log_f); phr->log_f = NULL;
          xfree(phr->log_t); phr->log_t = NULL;
          goto redo_action;
        }
      }
      if (pg->ops->destroy) {
        pg->ops->destroy(pg);
      }
      pg = NULL;

      fclose(phr->log_f); phr->log_f = NULL;
      xfree(phr->log_t); phr->log_t = NULL;
      phr->log_z = 0;
      fclose(phr->out_f); phr->out_f = NULL;

      if (phr->redirect) {
        xfree(phr->out_t); phr->out_t = NULL;
        phr->out_z = 0;

        FILE *tmp_f = open_memstream(p_out_t, p_out_z);
        if (phr->client_key) {
          fprintf(tmp_f, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", phr->client_key);
        }
        fprintf(tmp_f, "Location: %s\n\n", phr->redirect);
        fclose(tmp_f); tmp_f = NULL;

        xfree(phr->redirect); phr->redirect = NULL;
      } else {
        FILE *tmp_f = open_memstream(p_out_t, p_out_z);
        fprintf(tmp_f, "Content-type: %s\n\n", phr->content_type);
        fwrite(phr->out_t, 1, phr->out_z, tmp_f);
        fclose(tmp_f); tmp_f = NULL;

        xfree(phr->out_t); phr->out_t = NULL;
        phr->out_z = 0;
      }
      return;
    }
  }

  if (!r) {
    phr->out_f = open_memstream(&phr->out_t, &phr->out_z);
    phr->log_f = open_memstream(&phr->log_t, &phr->log_z);
    r = do_http_request(phr->log_f, phr->out_f, phr);
    if (r >= 0 && phr->suspend_reply) {
      html_armor_free(&ab);
      return;
    }
    close_memstream(phr->out_f); phr->out_f = 0;
    close_memstream(phr->log_f); phr->log_f = 0;
  }

  if (r < 0) {
    xfree(phr->out_t); phr->out_t = 0; phr->out_z = 0;
    phr->out_f = open_memstream(&phr->out_t, &phr->out_z);
    if (phr->json_reply) {
      write_json_header(phr->out_f);
      fprintf(phr->out_f, "{ \"status\": %d, \"text\": \"%s\" }",
              r, super_proto_error_messages[-r]);
    } else {
      ss_write_html_header(phr->out_f, phr, "Request failed");
      if (r < -1 && r > -SSERV_ERR_LAST) {
        fprintf(phr->out_f, "<h1>Request failed: error %d</h1>\n", -r);
        fprintf(phr->out_f, "<h2>%s</h2>\n", super_proto_error_messages[-r]);
      } else {
        fprintf(phr->out_f, "<h1>Request failed</h1>\n");
      }
      fprintf(phr->out_f, "<pre><font color=\"red\">%s</font></pre>\n",
              ARMOR(phr->log_t));
      ss_write_html_footer(phr->out_f);
    }
    close_memstream(phr->out_f); phr->out_f = 0;
  }
  xfree(phr->log_t); phr->log_t = 0; phr->log_z = 0;

  if (!phr->out_t || !*phr->out_t) {
    xfree(phr->out_t); phr->out_t = 0; phr->out_z = 0;
    phr->out_f = open_memstream(&phr->out_t, &phr->out_z);
    if (phr->json_reply) {
      write_json_header(phr->out_f);
      fprintf(phr->out_f, "{ \"status\": %d }", r);
    } else {
      ss_write_html_header(phr->out_f, phr, "Empty output");
      fprintf(phr->out_f, "<h1>Empty output</h1>\n");
      fprintf(phr->out_f, "<p>The output page is empty!</p>\n");
      ss_write_html_footer(phr->out_f);
    }
    close_memstream(phr->out_f); phr->out_f = 0;
  }

  /*
  if (phr->json_reply) {
    fprintf(stderr, "json: %s\n", out_t);
  }
  */

  *p_out_t = phr->out_t;
  *p_out_z = phr->out_z;
  html_armor_free(&ab);
}

void *super_html_forced_link[] =
{
  html_date_select, sarray_unparse_2, contest_tmpl_new
};
