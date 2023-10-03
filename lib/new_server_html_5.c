/* -*- mode: c -*- */

/* Copyright (C) 2007-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/new-server.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/userlist.h"
#include "ejudge/contests.h"
#include "ejudge/misctext.h"
#include "ejudge/mischtml.h"
#include "ejudge/xml_utils.h"
#include "ejudge/l10n.h"
#include "ejudge/compat.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/external_action.h"
#include "ejudge/mime_type.h"
#include "ejudge/imagemagick.h"
#include "ejudge/random.h"
#include "ejudge/base32.h"
#include "ejudge/avatar_plugin.h"
#include "ejudge/content_plugin.h"
#include "ejudge/errlog.h"
#include "ejudge/session_cache.h"
#include "ejudge/base64.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

#define ARMOR(s)  html_armor_buf(&ab, s)
#define URLARMOR(s)  url_armor_buf(&ab, s)
#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)
#define FAIL2(c) do { retval = -(c); goto failed; } while (0)

static int
reg_external_action(
        FILE *out_f,
        struct http_request_info *phr,
        int action,
        ContestExternalActions *cnts_actions);
static void
error_page(
        FILE *out_f,
        struct http_request_info *phr,
        int error_code);

static const unsigned char *
get_client_url(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const struct http_request_info *phr)
{
  if (phr->rest_mode > 0) {
    snprintf(buf, size, "%s/user", phr->context_url);
  } else if (cnts->team_url) {
    snprintf(buf, size, "%s", cnts->team_url);
  } else {
#if defined CGI_PROG_SUFFIX
    snprintf(buf, size, "%s/new-client%s", phr->context_url, CGI_PROG_SUFFIX);
#else
    snprintf(buf, size, "%s/new-client", phr->contest_url);
#endif
  }
  return buf;
}

/*
static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};
*/

extern const unsigned char * const ns_symbolic_action_table[];

static unsigned char *
curl(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const struct http_request_info *phr,
        int need_sid,
        const unsigned char *sep,
        int action,
        const char *format,
        ...)
  __attribute__((format(printf, 8, 9)));
static unsigned char *
curl(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const struct http_request_info *phr,
        int need_sid,
        const unsigned char *sep,
        int action,
        const char *format,
        ...)
{
  unsigned char tbuf[1024];
  unsigned char fbuf[1024];
  unsigned char lbuf[64];
  unsigned char abuf[64];
  unsigned char nbuf[64];
  unsigned char sbuf[64];
  const unsigned char *fsep = "";
  va_list args;

  if (sep == NULL) sep = "&";
  fbuf[0] = 0;
  if (format) {
    va_start(args, format);
    vsnprintf(fbuf, sizeof(fbuf), format, args);
    va_end(args);
  }
  if (fbuf[0]) fsep = sep;

  lbuf[0] = 0;
  if (phr->locale_id > 0) {
    snprintf(lbuf, sizeof(lbuf), "%slocale_id=%d", sep, phr->locale_id);
  }
  nbuf[0] = 0;
  if (phr->contest_id > 0) {
    snprintf(nbuf, sizeof(nbuf), "%scontest_id=%d", sep, phr->contest_id);
  }

  if (phr->rest_mode > 0) {
    if (action < 0 || action >= NEW_SRV_ACTION_LAST) action = 0;
    sbuf[0] = 0;
    if (need_sid > 0 && phr->session_id) {
      snprintf(sbuf, sizeof(sbuf), "/S%016llx", phr->session_id);
    }
    snprintf(buf, size, "%s/%s%s?%s%s%s%s",
             get_client_url(tbuf, sizeof(tbuf), cnts, phr),
             ns_symbolic_action_table[action], sbuf, nbuf, lbuf, fsep, fbuf);
  } else {
    abuf[0] = 0;
    if (action > 0) {
      snprintf(abuf, sizeof(abuf), "%saction=%d", sep, action);
    }
    sbuf[0] = 0;
    if (need_sid > 0 && phr->session_id) {
      snprintf(sbuf, sizeof(sbuf), "%sSID=%016llx", sep, phr->session_id);
    }
    snprintf(buf, size, "%s?%s%s%s%s%s%s",
             get_client_url(tbuf, sizeof(tbuf), cnts, phr),
             sbuf, abuf, nbuf, lbuf, fsep, fbuf);
  }

  return buf;
}

static void
create_account(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *login = 0;
  const unsigned char *email = 0;
  int retval = 0, r, ul_error = 0, next_action;
  unsigned char urlbuf[1024];
  unsigned char *new_login = 0;
  unsigned char *new_password = 0;
  int regular_flag = 0;

  if (ejudge_config->disable_new_users > 0 || cnts->disable_standalone_reg > 0) {
    fprintf(phr->log_f, "registration is not available");
    return error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
  }

  if (!cnts->assign_logins) {
    r = hr_cgi_param(phr, "login", &login);
    if (r < 0) FAIL2(NEW_SRV_ERR_LOGIN_BINARY);
    if (!r || !login) FAIL2(NEW_SRV_ERR_LOGIN_UNSPECIFIED);
    if (!is_valid_login(login))
      FAIL2(NEW_SRV_ERR_LOGIN_INV_CHARS);
  } else {
    login = "";
  }

  r = hr_cgi_param(phr, "email", &email);
  if (r < 0) FAIL2(NEW_SRV_ERR_EMAIL_BINARY);
  if (!r || !email) FAIL2(NEW_SRV_ERR_EMAIL_UNSPECIFIED);
  if (check_str(email, email_accept_chars) < 0)
    FAIL2(NEW_SRV_ERR_EMAIL_INV_CHARS);
  if (!is_valid_email_address(email))
    FAIL2(NEW_SRV_ERR_EMAIL_INV_CHARS);

  hr_cgi_param_int_opt(phr, "regular", &regular_flag, 0);

  // if neither login nor email are specified, just change the locale
  if (!*login && !*email) {
    snprintf(urlbuf, sizeof(urlbuf), "%s?contest_id=%d&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, phr->locale_id,
             NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
    ns_refresh_page_2(fout, phr->client_key, urlbuf);
    return;
  }

  if (!cnts->assign_logins) {
    if (!*login) FAIL2(NEW_SRV_ERR_LOGIN_UNSPECIFIED);
  }
  if (!*email) FAIL2(NEW_SRV_ERR_EMAIL_UNSPECIFIED);

  if (ns_open_ul_connection(phr->fw_state) < 0)
    FAIL2(NEW_SRV_ERR_UL_CONNECT_FAILED);

  next_action = NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE;

  if (cnts->simple_registration && regular_flag <= 0) {
    ul_error = userlist_clnt_register_new_2(ul_conn, &phr->ip, phr->ssl_flag,
                                            phr->contest_id, phr->locale_id,
                                            next_action,
                                            login, email, phr->self_url,
                                            0, &new_login, &new_password);


  } else {
    ul_error = userlist_clnt_register_new(ul_conn, ULS_REGISTER_NEW,
                                          &phr->ip, phr->ssl_flag,
                                          phr->contest_id, phr->locale_id,
                                          next_action,
                                          login, email, phr->self_url);
  }

  if (ul_error < 0) goto failed;
  fprintf(fout, "Location: %s?contest_id=%d&action=%d", phr->self_url, phr->contest_id, next_action);
  if (phr->locale_id > 0) fprintf(fout, "&locale_id=%d", phr->locale_id);
  if (cnts->simple_registration) {
    if (new_login && *new_login) fprintf(fout,"&login=%s",URLARMOR(new_login));
    if (new_password && *new_password)
      fprintf(fout, "&password=%s", URLARMOR(new_password));
  } else {
    if (login && *login) fprintf(fout, "&login=%s", URLARMOR(login));
  }
  if (email && *email) fprintf(fout, "&email=%s", URLARMOR(email));
  fprintf(fout, "\n\n");
  goto cleanup;

 failed:
  fprintf(fout, "Location: %s?contest_id=%d&action=%d", phr->self_url, phr->contest_id, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE);
  if (phr->locale_id > 0) fprintf(fout, "&locale_id=%d", phr->locale_id);
  if (login && *login) fprintf(fout, "&login=%s", URLARMOR(login));
  if (email && *email) fprintf(fout, "&email=%s", URLARMOR(email));
  if (retval) fprintf(fout, "&retval=%d", retval);
  if (ul_error) fprintf(fout, "&ul_error=%d", ul_error);
  fprintf(fout, "\n\n");

 cleanup:
  html_armor_free(&ab);
  xfree(new_login);
  xfree(new_password);
}

static void
cmd_login(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  const unsigned char *login = 0;
  const unsigned char *password = 0;
  int r, i;
  unsigned char urlbuf[1024];
  int need_regform = 0;

  if (hr_cgi_param(phr, "login", &login) <= 0) {
    fprintf(phr->log_f, "login is invalid");
    return error_page(fout, phr, NEW_SRV_ERR_INV_PARAM);
  }
  phr->login = xstrdup(login);
  if (hr_cgi_param(phr, "password", &password) <= 0) {
    fprintf(phr->log_f, "password is invalid");
    return error_page(fout, phr, NEW_SRV_ERR_INV_PARAM);
  }

  // if neither login, nor password is not specified, just change the locale
  if ((!login || !*login) && (!password || !*password)) {
    snprintf(urlbuf, sizeof(urlbuf), "%s?contest_id=%d&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, phr->locale_id,
             NEW_SRV_ACTION_REG_LOGIN_PAGE);
    ns_refresh_page_2(fout, phr->client_key, urlbuf);
    return;
  }

  /* check password action is here */
  if (ns_open_ul_connection(phr->fw_state) < 0)
    return error_page(fout, phr, NEW_SRV_ERR_USERLIST_SERVER_DOWN);

  if ((r = userlist_clnt_login(ul_conn, ULS_CHECK_USER,
                               &phr->ip,
                               0, /* cookie */
                               phr->client_key,
                               0, /* expire */
                               phr->ssl_flag, phr->contest_id,
                               phr->locale_id,
                               0, /* pwd_special */
                               0, /* is_ws */
                               0, /* is_job */
                               phr->login, password,
                               &phr->user_id,
                               &phr->session_id,
                               &phr->client_key,
                               &phr->name,
                               NULL /* expire */,
                               &phr->priv_level,
                               &phr->reg_status,
                               &phr->reg_flags)) < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      fprintf(phr->log_f, "user_login failed: %s", userlist_strerror(-r));
      return error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
    case ULS_ERR_DISCONNECT:
      return error_page(fout, phr, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    case ULS_ERR_SIMPLE_REGISTERED:
      return error_page(fout, phr, NEW_SRV_ERR_SIMPLE_REGISTERED);
    default:
      fprintf(phr->log_f, "user_login failed: %s", userlist_strerror(-r));
      return error_page(fout, phr, NEW_SRV_ERR_INTERNAL);
    }
  }

  if (!cnts->disable_name) need_regform = 1;
  if (!cnts->disable_team_password) need_regform = 1;
  for (i = CONTEST_FIRST_FIELD; i < CONTEST_LAST_FIELD; i++)
    if (cnts->fields[i])
      need_regform = 1;
  for (i = 0; i < CONTEST_LAST_MEMBER; i++)
    if (cnts->members[i] && cnts->members[i]->max_count > 0)
      need_regform = 1;

  // if there is no editable fields and autoregister flag is set,
  // then register immediately for the contest and redirect there
  if (cnts->force_registration && cnts->autoregister && !need_regform) {
    r = userlist_clnt_register_contest(ul_conn, ULS_REGISTER_CONTEST_2,
                                       phr->user_id, phr->contest_id,
                                       &phr->ip, phr->ssl_flag);
    if (r < 0) {
      fprintf(phr->log_f, "register_contest failed: %s", userlist_strerror(-r));
      return error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
    }

    curl(urlbuf, sizeof(urlbuf), cnts, phr, 1, "&", 0, NULL);
    ns_refresh_page_2(fout, phr->client_key, urlbuf);
  } else if (cnts->force_registration) {
    // register for the contest anyway, but do not redirect to new-client
    // since we're not allowed to login unless the registration form
    // is complete, we may relax registration procedure
    r = userlist_clnt_register_contest(ul_conn, ULS_REGISTER_CONTEST_2,
                                       phr->user_id, phr->contest_id,
                                       &phr->ip, phr->ssl_flag);
    if (r < 0) {
      fprintf(phr->log_f, "register_contest failed: %s", userlist_strerror(-r));
      return error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
    }
  }

  snprintf(urlbuf, sizeof(urlbuf), "%s?SID=%llx", phr->self_url,
           phr->session_id);
  ns_refresh_page_2(fout, phr->client_key, urlbuf);
}

typedef void (*reg_action_handler_func_t)(FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time);
static reg_action_handler_func_t action_handlers[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_REG_CREATE_ACCOUNT] = create_account,
  [NEW_SRV_ACTION_REG_LOGIN] = cmd_login,
};

static void
anon_register_pages(FILE *fout, struct http_request_info *phr)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = 0;
  int create_flag = 0;

  hr_cgi_param_int(phr, "create_account", &create_flag);

  // contest_id is required
  if (phr->contest_id <= 0 || contests_get(phr->contest_id,&cnts) < 0 || !cnts){
    if (reg_external_action(fout, phr, NEW_SRV_ACTION_CONTESTS_PAGE, NULL) > 0) return;
    error_page(fout, phr, NEW_SRV_ERR_INV_ACTION);
    return;
  }
  phr->cnts = cnts;

  if (phr->locale_id < 0) phr->locale_id = cnts->default_locale_num;
  if (phr->locale_id < 0) phr->locale_id = 0;

  // check permissions
  if (cnts->closed || !contests_check_register_ip_2(cnts, &phr->ip, phr->ssl_flag)) {
    fprintf(phr->log_f, "registration is not available for this IP or protocol\n");
    error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
    return;
  }

  cur_time = time(0);

  // load style stuff
  extra = ns_get_contest_extra(cnts, phr->config);
  if (cnts->enable_local_pages > 0 && !extra->cnts_actions) {
    extra->cnts_actions = ns_get_contest_external_actions(phr->contest_id, cur_time);
  }
  phr->extra = extra;
  watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
  extra->separator_txt = "";
  extra->copyright_txt = extra->copyright.text;
  if (!extra->header_txt || !extra->footer_txt) {
    extra->header_txt = ns_fancy_header;
    extra->separator_txt = ns_fancy_separator;
    if (extra->copyright_txt) extra->footer_txt = ns_fancy_footer_2;
    else extra->footer_txt = ns_fancy_footer;
  }

  if (extra->contest_arm) xfree(extra->contest_arm);
  if (phr->locale_id == 0 && cnts->name_en) {
    extra->contest_arm = html_armor_string_dup(cnts->name_en);
  } else {
    extra->contest_arm = html_armor_string_dup(cnts->name);
  }

  if (create_flag) {
    phr->action = NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE;
  }

  if (phr->action < 0 || phr->action >= NEW_SRV_ACTION_LAST) phr->action = 0;
  if (reg_external_action(fout, phr, -1, extra->cnts_actions) > 0) return;

  if (phr->action == NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE ||
      phr->action == NEW_SRV_ACTION_REG_LOGIN_PAGE) {
    if (reg_external_action(fout, phr, NEW_SRV_ACTION_REG_LOGIN_PAGE, extra->cnts_actions) > 0) return;
    error_page(fout, phr, NEW_SRV_ERR_INV_ACTION);
  }

  if (action_handlers[phr->action])
    return (*action_handlers[phr->action])(fout, phr, cnts, extra, cur_time);

  if (cnts->assign_logins) {
    if (reg_external_action(fout, phr, NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE, extra->cnts_actions) > 0) return;
    error_page(fout, phr, NEW_SRV_ERR_INV_ACTION);
  } else {
    if (reg_external_action(fout, phr, NEW_SRV_ACTION_REG_LOGIN_PAGE, extra->cnts_actions) > 0) return;
    error_page(fout, phr, NEW_SRV_ERR_INV_ACTION);
  }
}

static void
change_locale(FILE *fout, struct http_request_info *phr)
{
  int next_action = 0;
  const unsigned char *sep = "?";
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *s = 0;

  hr_cgi_param_int(phr, "next_action", &next_action);
  if (next_action < 0 || next_action >= NEW_SRV_ACTION_LAST) next_action = 0;

  // SID, contest_id, login are passed "as is"
  // next_action is passed as action
  if (phr->session_id) {
    // FIXME: report errors?
    if (ns_open_ul_connection(phr->fw_state) >= 0) {
      userlist_clnt_set_cookie(ul_conn, ULS_SET_COOKIE_LOCALE,
                               phr->session_id,
                               phr->client_key,
                               phr->locale_id);
    }

    fprintf(fout, "Location: %s?SID=%016llx", phr->self_url, phr->session_id);
    if (next_action > 0) fprintf(fout, "&action=%d", next_action);
    fprintf(fout, "\n");
    if (phr->client_key) {
      fprintf(fout, "Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", phr->client_key);
    }
    fprintf(fout, "\n");
    return;
  }

  fprintf(fout, "Location: %s", phr->self_url);
  if (phr->contest_id > 0) {
    fprintf(fout, "%scontest_id=%d", sep, phr->contest_id);
    sep = "&";
  }
  s = 0;
  if (hr_cgi_param(phr, "login", &s) > 0 && s && *s) {
    fprintf(fout, "%slogin=%s", sep, URLARMOR(s));
    sep = "&";
  }
  s = 0;
  if (hr_cgi_param(phr, "email", &s) > 0 && s && *s) {
    fprintf(fout, "%semail=%s", sep, URLARMOR(s));
    sep = "&";
  }
  if (phr->locale_id > 0) {
    fprintf(fout, "%slocale_id=%d", sep, phr->locale_id);
    sep = "&";
  }
  if (next_action > 0) {
    fprintf(fout, "%saction=%d", sep, next_action);
    sep = "&";
  }
  fprintf(fout, "\n\n");

  html_armor_free(&ab);
}

static void
info_table_row(
        FILE *fout,
        const unsigned char *s1,
        const unsigned char *s2,
        int is_empty,
        int is_mandatory,
        int is_password,
        const unsigned char *valid_chars,
        struct html_armor_buffer *pb,
        int is_href,
        const unsigned char *login)
{
  const unsigned char *red_beg = "", *red_end = "", *s;
  unsigned char invstr[512];
  int strres = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if ((is_empty || !s2 || !*s2) && is_mandatory) {
    red_beg = "<font color=\"red\">";
    red_end = "</font>";
  } else if (s2 && valid_chars
             && (strres = check_str_2(s2, valid_chars, invstr,
                                      sizeof(invstr), utf8_mode)) < 0) {
    red_beg = "<font color=\"red\">";
    red_end = "</font>";
  }

  fprintf(fout, "<tr><td class=\"b0\">%s%s%s:</td><td class=\"b0\">", red_beg, s1, red_end);
  if (is_empty || !s2 || !*s2) {
    fprintf(fout, "&nbsp;");
  } else if (is_href) {
    s = html_armor_buf(pb, s2);
    fprintf(fout, "<a href=\"%s\" target=\"_blank\"><tt>%s</tt></a>", s, s);
  } else if (is_password) {
    fprintf(fout, "<tt>***</tt>");
  } else {
    fprintf(fout, "<tt>%s</tt>", html_armor_buf(pb, s2));
  }
  fprintf(fout, "</td><td class=\"b0\">");
  if ((is_empty || !s2 || !*s2) && login && *login) {
    fprintf(fout, "<i>%s:</i> <tt>%s</tt>", _("Default value"), ARMOR(login));
  } else if ((is_empty || !s2 || !*s2) && is_mandatory) {
    fprintf(fout, "%s<i>%s</i>%s", red_beg, _("Not set"), red_end);
  } else if (s2 && valid_chars && strres) {
    fprintf(fout, "%s<i>%s:</i> <tt>%s</tt>%s",
            red_beg, _("Invalid characters"), ARMOR(invstr), red_end);
  } else {
    fprintf(fout, "&nbsp;");
  }
  fprintf(fout, "</td></tr>\n");

  html_armor_free(&ab);
}

static int
contest_fields_order[] =
{
  CONTEST_F_INST,
  CONTEST_F_INST_EN,
  CONTEST_F_INSTSHORT,
  CONTEST_F_INSTSHORT_EN,
  CONTEST_F_INSTNUM,
  CONTEST_F_FAC,
  CONTEST_F_FAC_EN,
  CONTEST_F_FACSHORT,
  CONTEST_F_FACSHORT_EN,
  CONTEST_F_COUNTRY,
  CONTEST_F_COUNTRY_EN,
  CONTEST_F_CITY,
  CONTEST_F_CITY_EN,
  CONTEST_F_REGION,
  CONTEST_F_AREA,
  CONTEST_F_ZIP,
  CONTEST_F_STREET,
  CONTEST_F_LANGUAGES,
  CONTEST_F_HOMEPAGE,
  CONTEST_F_PHONE,
  CONTEST_F_FIELD0,
  CONTEST_F_FIELD1,
  CONTEST_F_FIELD2,
  CONTEST_F_FIELD3,
  CONTEST_F_FIELD4,
  CONTEST_F_FIELD5,
  CONTEST_F_FIELD6,
  CONTEST_F_FIELD7,
  CONTEST_F_FIELD8,
  CONTEST_F_FIELD9,
  0,
};

static int
member_fields_order[] =
{
  CONTEST_MF_GENDER,
  CONTEST_MF_FIRSTNAME,
  CONTEST_MF_FIRSTNAME_EN,
  CONTEST_MF_MIDDLENAME,
  CONTEST_MF_MIDDLENAME_EN,
  CONTEST_MF_SURNAME,
  CONTEST_MF_SURNAME_EN,
  CONTEST_MF_STATUS,
  CONTEST_MF_GRADE,
  CONTEST_MF_GROUP,
  CONTEST_MF_GROUP_EN,
  CONTEST_MF_EMAIL,
  CONTEST_MF_HOMEPAGE,
  CONTEST_MF_PHONE,
  CONTEST_MF_INST,
  CONTEST_MF_INST_EN,
  CONTEST_MF_INSTSHORT,
  CONTEST_MF_INSTSHORT_EN,
  CONTEST_MF_FAC,
  CONTEST_MF_FAC_EN,
  CONTEST_MF_FACSHORT,
  CONTEST_MF_FACSHORT_EN,
  CONTEST_MF_OCCUPATION,
  CONTEST_MF_OCCUPATION_EN,
  CONTEST_MF_DISCIPLINE,
  CONTEST_MF_BIRTH_DATE,
  CONTEST_MF_ENTRY_DATE,
  CONTEST_MF_GRADUATION_DATE,
  0,
};

static int
member_fields_order_1[] =
{
  CONTEST_MF_SURNAME,
  CONTEST_MF_SURNAME_EN,
  CONTEST_MF_FIRSTNAME,
  CONTEST_MF_FIRSTNAME_EN,
  CONTEST_MF_MIDDLENAME,
  CONTEST_MF_MIDDLENAME_EN,
  CONTEST_MF_GENDER,
  CONTEST_MF_BIRTH_DATE,
  CONTEST_MF_STATUS,
  CONTEST_MF_GRADE,
  CONTEST_MF_GROUP,
  CONTEST_MF_GROUP_EN,
  0,
};

static int
member_fields_order_2[] =
{
  CONTEST_MF_PHONE,
  CONTEST_MF_EMAIL,
  CONTEST_MF_HOMEPAGE,
  CONTEST_MF_INST,
  CONTEST_MF_INST_EN,
  CONTEST_MF_INSTSHORT,
  CONTEST_MF_INSTSHORT_EN,
  CONTEST_MF_FAC,
  CONTEST_MF_FAC_EN,
  CONTEST_MF_FACSHORT,
  CONTEST_MF_FACSHORT_EN,
  CONTEST_MF_OCCUPATION,
  CONTEST_MF_OCCUPATION_EN,
  CONTEST_MF_DISCIPLINE,
  CONTEST_MF_ENTRY_DATE,
  CONTEST_MF_GRADUATION_DATE,
  0,
};

struct field_desc_s
{
  char *description;
  int repl_char;
  int maxlength;
  int size;
  int is_href;
};

static struct field_desc_s contest_field_desc[CONTEST_LAST_FIELD] =
{
  [CONTEST_F_HOMEPAGE] = { __("Homepage"), '?', 128, 64, 1 },
  [CONTEST_F_PHONE] = { __("Phone"), '?', 128, 64, 0 },
  [CONTEST_F_INST] = { __("Institution"), '?', 256, 64, 0 },
  [CONTEST_F_INST_EN] = { __("Institution (En)"), '?', 256, 64, 0 },
  [CONTEST_F_INSTSHORT] = { __("Institution (abbreviated)"), '?', 128, 32, 0 },
  [CONTEST_F_INSTSHORT_EN] = { __("Institution (abbreviated) (En)"), '?', 128, 32, 0 },
  [CONTEST_F_INSTNUM] = { __("Institution number"), '?', 32, 32, 0 },
  [CONTEST_F_FAC] = { __("Faculty"), '?', 256, 64, 0 },
  [CONTEST_F_FAC_EN] = { __("Faculty (En)"), '?', 256, 64, 0 },
  [CONTEST_F_FACSHORT] = { __("Faculty (abbreviated)"), '?', 128, 32, 0 },
  [CONTEST_F_FACSHORT_EN] = { __("Faculty (abbreviated) (En)"), '?', 128, 32, 0 },
  [CONTEST_F_CITY] = { __("City"), '?', 256, 64, 0 },
  [CONTEST_F_CITY_EN] = { __("City (En)"), '?', 256, 64, 0 },
  [CONTEST_F_COUNTRY] = { __("Country"), '?', 256, 64, 0 },
  [CONTEST_F_COUNTRY_EN] = { __("Country (En)"),  '?', 256, 64, 0 },
  [CONTEST_F_REGION] = { __("Region"), '?', 256, 64, 0 },
  [CONTEST_F_AREA] = { __("Area"), '?', 256, 64, 0 },
  [CONTEST_F_ZIP] = { __("Zip code"), '?', 128, 64, 0 },
  [CONTEST_F_STREET] = { __("Street address"), '?', 256, 64, 0 },
  [CONTEST_F_LANGUAGES] = { __("Programming languages"), '?', 256, 64, 0 },
  [CONTEST_F_FIELD0] = { __("Field 0"), '?', 512, 64, 0 },
  [CONTEST_F_FIELD1] = { __("Field 1"), '?', 512, 64, 0 },
  [CONTEST_F_FIELD2] = { __("Field 2"), '?', 512, 64, 0 },
  [CONTEST_F_FIELD3] = { __("Field 3"), '?', 512, 64, 0 },
  [CONTEST_F_FIELD4] = { __("Field 4"), '?', 512, 64, 0 },
  [CONTEST_F_FIELD5] = { __("Field 5"), '?', 512, 64, 0 },
  [CONTEST_F_FIELD6] = { __("Field 6"), '?', 512, 64, 0 },
  [CONTEST_F_FIELD7] = { __("Field 7"), '?', 512, 64, 0 },
  [CONTEST_F_FIELD8] = { __("Field 8"), '?', 512, 64, 0 },
  [CONTEST_F_FIELD9] = { __("Field 9"), '?', 512, 64, 0 },
};

static struct field_desc_s member_field_desc[CONTEST_LAST_MEMBER_FIELD] =
{
  [CONTEST_MF_FIRSTNAME] = { __("First name"), '?', 256, 64, 0 },
  [CONTEST_MF_FIRSTNAME_EN] = { __("First name (En)"), '?', 256, 64, 0 },
  [CONTEST_MF_MIDDLENAME] = { __("Middle name"), '?', 256, 64, 0 },
  [CONTEST_MF_MIDDLENAME_EN] = { __("Middle name (En)"), '?', 256, 64, 0 },
  [CONTEST_MF_SURNAME] = { __("Family name"), '?', 256, 64, 0 },
  [CONTEST_MF_SURNAME_EN] = { __("Family name (En)"), '?', 256, 64, 0 },
  [CONTEST_MF_STATUS] = { __("Status"), '?', 64, 64, 0 },
  [CONTEST_MF_GENDER] = { __("Gender"), '?', 64, 64, 0 },
  [CONTEST_MF_GRADE] = { __("Grade"), '?', 16, 16, 0 },
  [CONTEST_MF_GROUP] = { __("Group"), '?', 64, 16, 0 },
  [CONTEST_MF_GROUP_EN] = { __("Group (En)"), '?', 64, 16, 0 },
  [CONTEST_MF_EMAIL] = { __("E-mail"), '?', 128, 64, 0 },
  [CONTEST_MF_HOMEPAGE] = { __("Homepage"), '?', 256, 64, 1 },
  [CONTEST_MF_PHONE] = { __("Phone"), '?', 128, 64, 0 },
  [CONTEST_MF_INST] = { __("Institution"), '?', 256, 64, 0 },
  [CONTEST_MF_INST_EN] = { __("Institution (En)"), '?', 256, 64, 0 },
  [CONTEST_MF_INSTSHORT] = { __("Institution (abbreviated)"), '?', 128, 32, 0 },
  [CONTEST_MF_INSTSHORT_EN] = { __("Institution (abbreviated) (En)"), '?', 128, 32, 0 },
  [CONTEST_MF_FAC] = { __("Faculty"), '?', 256, 64, 0 },
  [CONTEST_MF_FAC_EN] = { __("Faculty (En)"), '?', 256, 64, 0 },
  [CONTEST_MF_FACSHORT] = { __("Faculty (abbreviated)"), '?', 128, 32, 0 },
  [CONTEST_MF_FACSHORT_EN] = { __("Faculty (abbreviated) (En)"), '?', 128, 32, 0 },
  [CONTEST_MF_OCCUPATION] = { __("Occupation"), '?', 256, 64, 0 },
  [CONTEST_MF_OCCUPATION_EN] = { __("Occupation (En)"), '?', 256, 64, 0 },
  [CONTEST_MF_DISCIPLINE] = { __("Discipline"), '?', 256, 64, 0 },
  [CONTEST_MF_BIRTH_DATE] = { __("Birth Date"), '?', 128, 64, 0 },
  [CONTEST_MF_ENTRY_DATE] = { __("Institution entry date"), '?', 128, 64, 0 },
  [CONTEST_MF_GRADUATION_DATE] = { __("Institution graduation date"), '?', 128, 64, 0 },
};

static int
tab_actions[] =
{
  NEW_SRV_ACTION_REG_VIEW_GENERAL,
  NEW_SRV_ACTION_REG_VIEW_CONTESTANTS,
  NEW_SRV_ACTION_REG_VIEW_RESERVES,
  NEW_SRV_ACTION_REG_VIEW_COACHES,
  NEW_SRV_ACTION_REG_VIEW_ADVISORS,
  NEW_SRV_ACTION_REG_VIEW_GUESTS,
  0,
};
static const unsigned char *tab_labels[] =
{
  __("General info"),
  __("Contestants"),
  __("Reserves"),
  __("Coaches"),
  __("Advisors"),
  __("Guests"),
};

static const unsigned char *no_role_allowed_str[] =
{
  __("No contestants are allowed in this contest"),
  __("No reserves are allowed in this contest"),
  __("No coaches are allowed in this contest"),
  __("No advisors are allowed in this contest"),
  __("No guests are allowed in this contest"),
};

const unsigned char *ns_role_labels[] =
{
  __("Contestant"),
  __("Reserve"),
  __("Coach"),
  __("Advisor"),
  __("Guest"),
};

static const unsigned char *role_move_direction[] =
{
  __("Move to reserves"),
  __("Move to contestants"),
  __("Move to advisors"),
  __("Move to coaches"),
  0
};

static const int role_move_dir_code[] =
{
  CONTEST_M_RESERVE,
  CONTEST_M_CONTESTANT,
  CONTEST_M_ADVISOR,
  CONTEST_M_COACH,
  -1,
};

void
ns_reg_main_page_view_info(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  unsigned char ub[1024];
  unsigned char bb[1024];
  int i, ff, nr, j;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct userlist_user *u = 0;
  const unsigned char *s, *hh = 0, *cc = 0, *legend;
  unsigned char fbuf[1024];
  int tab_count, err_count, role_err_count[CONTEST_LAST_MEMBER + 1];
  int rr, mm, mmbound, main_area_span;
  const struct userlist_member *m;
  const struct userlist_user_info *ui = 0;
  const struct userlist_members *mmm = 0;

  u = phr->user_info;
  if (u) ui = userlist_get_cnts0(u);
  if (ui) mmm = ui->members;

  if (phr->action < NEW_SRV_ACTION_REG_VIEW_GENERAL
      || phr->action > NEW_SRV_ACTION_REG_VIEW_GUESTS) {
    phr->action = NEW_SRV_ACTION_REG_VIEW_GENERAL;
  }

  // check that we need tabs and how many
  tab_count = 1;
  for (i = 0; i < CONTEST_LAST_MEMBER; i++) {
    if (cnts->members[i] && cnts->members[i]->max_count > 0
        && (!cnts->personal ||
            (cnts->personal && i != CONTEST_M_CONTESTANT
             && i != CONTEST_M_RESERVE)))
      tab_count++;
    else if (phr->action == NEW_SRV_ACTION_REG_VIEW_CONTESTANTS + i)
      phr->action = NEW_SRV_ACTION_REG_VIEW_GENERAL;
  }

  err_count = userlist_count_info_errors(cnts, u, ui, mmm, role_err_count);
  (void) err_count;

  //fprintf(fout, "<br/>\n");
  if (phr->reg_status < 0) {
    fprintf(fout, "<p>%s</p>\n", _("In order to complete the registration procedure, hit the \"Confirm registration\" link."));
  }

  // generate upper tabs
  main_area_span = 1;
  if (tab_count > 1) {
    fprintf(fout, "<table cellpadding=\"0\" cellspacing=\"0\">\n");
    main_area_span = 0;
    fprintf(fout, "<tr id=\"probNavTopList\">\n");
    for (i = 0; tab_actions[i]; i++) {
      if (i > 0 && (!cnts->members[i - 1]
                    || cnts->members[i - 1]->max_count <= 0))
        continue;
      if (cnts->personal &&
          (i == CONTEST_M_CONTESTANT || i == CONTEST_M_RESERVE))
        continue;

      if (main_area_span > 0) {
        fprintf(fout, "<td class=\"probNavSpaceTop\">&nbsp;</td>");
        main_area_span++;
      }

      hh = "probNavHidden";
      if (phr->action == tab_actions[i]) hh = "probNavActiveTop";
      cc = "probOk";
      if (phr->action == tab_actions[i]) {
        cc = "probCurrent";
      } else if (role_err_count[i] > 0) {
        cc = "probBad";
      }
      fprintf(fout, "<td class=\"%s\" onclick=\"displayRoleInfo(%d)\"><div class=\"%s\">", hh, tab_actions[i], cc);
      fprintf(fout, "%s%s</a>",
              ns_aref_2(bb, sizeof(bb), phr, "tab", tab_actions[i], 0),
              gettext(tab_labels[i]));
      fprintf(fout, "</div></td>\n");
      main_area_span++;
    }
    fprintf(fout, "</tr>\n");
    fprintf(fout, "<tr><td colspan=\"%d\" id=\"memberNavArea\"><div id=\"probNavTaskArea\">\n", main_area_span);
  }

  if (phr->action == NEW_SRV_ACTION_REG_VIEW_GENERAL) {
    fprintf(fout, "<h2>%s", _("General information"));
    if (u && !u->read_only && (!ui || !ui->cnts_read_only) && !(phr->reg_flags & USERLIST_UC_REG_READONLY)) {
      fprintf(fout, " [%s%s</a>]",
              ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE, 0), _("Edit"));
    }
    fprintf(fout, "</h2>\n");
    fprintf(fout, "<table class=\"b0 table-userinfo\">\n");
    s = 0;
    if (u && u->login && *u->login) {
      s = u->login;
    }
    info_table_row(fout,  _("Login"), s, 0, 0, 0, 0, &ab, 0, 0);
    s = 0;
    if (u && u->email && *u->email) {
      s = u->email;
    }
    info_table_row(fout,  _("E-mail"), s, 0, 0, 0, 0, &ab, 0, 0);
    if (!cnts->disable_name) {
      s = 0;
      if (ui && ui->name && *ui->name) {
        s = ui->name;
      }
      if (cnts->read_only_name) {
        info_table_row(fout, cnts->personal?_("User name (for standings)"):_("Team name"), s, 0, 0, 0, 0, &ab, 0, 0);
      } else {
        info_table_row(fout, cnts->personal?_("User name (for standings)"):_("Team name"), s, 0, 0, 0, name_accept_chars, &ab, 0, u->login);
      }
    }
    if (ui && cnts->personal && cnts->members[(rr = CONTEST_M_CONTESTANT)]
        && cnts->members[rr]->max_count > 0) {
      if ((m = userlist_members_get_first(ui->members))) {
        for (i = 0; (ff = member_fields_order_1[i]); i++) {
          if (!cnts->members[rr]->fields[ff]) continue;
          userlist_get_member_field_str(fbuf, sizeof(fbuf), m,
                                        userlist_member_field_ids[ff], 0, 1);
          legend = cnts->members[rr]->fields[ff]->legend;
          if (!legend || !*legend)
            legend = gettext(member_field_desc[ff].description);
          info_table_row(fout, legend, fbuf,
                         userlist_is_empty_member_field(m, userlist_member_field_ids[ff]),
                         cnts->members[rr]->fields[ff]->mandatory,
                         cnts->members[rr]->fields[ff]->is_password,
                         userlist_get_member_accepting_chars(ff),
                         &ab, member_field_desc[ff].is_href, 0);
        }
      } else {
        fbuf[0] = 0;
        for (i = 0; (ff = member_fields_order_1[i]); i++) {
          if (!cnts->members[rr]->fields[ff]) continue;
          legend = cnts->members[rr]->fields[ff]->legend;
          if (!legend || !*legend)
            legend = gettext(member_field_desc[ff].description);
          info_table_row(fout, legend, fbuf, 1,
                         cnts->members[rr]->fields[ff]->mandatory,
                         cnts->members[rr]->fields[ff]->is_password,
                         userlist_get_member_accepting_chars(ff),
                         &ab, member_field_desc[ff].is_href, 0);
        }
      }
    }
    for (i = 0; (ff = contest_fields_order[i]); i++) {
      if (!cnts->fields[ff]) continue;
      userlist_get_user_info_field_str(fbuf, sizeof(fbuf), ui,
                                       userlist_contest_field_ids[ff], 0);

      legend = cnts->fields[ff]->legend;
      if (!legend || !*legend)
        legend = gettext(contest_field_desc[ff].description);
      info_table_row(fout, legend, fbuf,
                     userlist_is_empty_user_info_field(ui, userlist_contest_field_ids[ff]),
                     cnts->fields[ff]->mandatory,
                     0 /* is_password */,
                     userlist_get_contest_accepting_chars(ff),
                     &ab, contest_field_desc[ff].is_href, 0);
    }
    if (ui && cnts->personal && cnts->members[(rr = CONTEST_M_CONTESTANT)]
        && cnts->members[rr]->max_count > 0) {
      if ((m = userlist_members_get_first(ui->members))) {
        for (i = 0; (ff = member_fields_order_2[i]); i++) {
          if (!cnts->members[rr]->fields[ff]) continue;
          userlist_get_member_field_str(fbuf, sizeof(fbuf), m,
                                        userlist_member_field_ids[ff], 0, 1);
          legend = cnts->members[rr]->fields[ff]->legend;
          if (!legend || !*legend)
            legend = gettext(member_field_desc[ff].description);
          info_table_row(fout, legend, fbuf,
                         userlist_is_empty_member_field(m, userlist_member_field_ids[ff]),
                         cnts->members[rr]->fields[ff]->mandatory,
                         cnts->members[rr]->fields[ff]->is_password,
                         userlist_get_member_accepting_chars(ff),
                         &ab, member_field_desc[ff].is_href, 0);
        }
      } else {
        fbuf[0] = 0;
        for (i = 0; (ff = member_fields_order_2[i]); i++) {
          if (!cnts->members[rr]->fields[ff]) continue;
          legend = cnts->members[rr]->fields[ff]->legend;
          if (!legend || !*legend)
            legend = gettext(member_field_desc[ff].description);
          info_table_row(fout, legend, fbuf, 1,
                         cnts->members[rr]->fields[ff]->mandatory,
                         cnts->members[rr]->fields[ff]->is_password,
                         userlist_get_member_accepting_chars(ff),
                         &ab, member_field_desc[ff].is_href, 0);
        }
      }
    }
    fprintf(fout, "</table>\n");

    if (cnts->enable_avatar > 0) {
      fprintf(fout, "<div class=\"userinfo-avatar-cont\">\n");
      if (ui && ui->avatar_id && ui->avatar_id[0]) {
        struct content_loaded_plugin *cp = NULL;
        int content_enabled = 0;
        unsigned char url_buf[1024];

        cp = content_plugin_get(phr->extra, phr->cnts, phr->config, NULL);
        if (cp) {
          content_enabled = cp->iface->is_enabled(cp->data, phr->cnts);
        }
        if (content_enabled > 0) {
          cp->iface->get_url(cp->data, url_buf, sizeof(url_buf),
                             phr->cnts, ui->avatar_id, ui->avatar_suffix);
        } else {
          snprintf(url_buf, sizeof(url_buf), "%s?SID=%llx&key=%s&action=%d",
                   phr->self_url, phr->session_id, ui->avatar_id, NEW_SRV_ACTION_GET_AVATAR);
        }
        fprintf(fout, "<img class=\"avatar-img\" src=\"%s\" alt=\"avatar\" />", url_buf);
      }
      if (!(phr->reg_flags & USERLIST_UC_REG_READONLY)) {
        html_start_form(fout, 2, phr->self_url, "");
        html_hidden(fout, "SID", "%llx", phr->session_id);
        fprintf(fout, "<input class=\"avatar-file\" type=\"file\" name=\"img_file\" /><br/>");
        fprintf(fout, "%s",
                ns_submit_button_2(bb, sizeof(bb), "avatar-button", NULL,
                                   NEW_SRV_ACTION_UPLOAD_AVATAR, 0));
        fprintf(fout, "</form>\n");
      }
      fprintf(fout, "</div>\n");
    }
  } else if (phr->action >= NEW_SRV_ACTION_REG_VIEW_CONTESTANTS
             && phr->action <= NEW_SRV_ACTION_REG_VIEW_GUESTS) {
    rr = phr->action - NEW_SRV_ACTION_REG_VIEW_CONTESTANTS;
    if (!cnts->members[rr] || cnts->members[rr]->max_count <= 0) {
      fprintf(fout, "<h2><font color=\"red\">%s</font></h2>\n", gettext(no_role_allowed_str[rr]));
    } else if (ui) {
      mmbound = 0;
      // count the total of the specified role
      if ((mmm = ui->members) && mmm->u > 0) {
        for (j = 0; j < mmm->u; j++)
          if ((m = mmm->m[j]) && m->team_role == rr)
            mmbound++;
      }

      fprintf(fout, "<h2>%s", gettext(tab_labels[rr + 1]));
      if (!u->read_only && !ui->cnts_read_only
          && mmbound < cnts->members[rr]->max_count) {
        fprintf(fout, " [%s%s</a>]",
                ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_ADD_MEMBER_PAGE, "role=%d", rr), _("Add new"));
      }
      fprintf(fout, "</h2>\n");

      if (mmbound < cnts->members[rr]->min_count) {
        fprintf(fout, _("<p><font color=\"red\">Minimal number for this contest is %d, but only %d are defined.</font></p>\n"),
                cnts->members[rr]->min_count,
                mmbound);
      }
      if (mmbound > cnts->members[rr]->max_count) {
        fprintf(fout, _("<p><font color=\"red\">Maximal number for this contest is %d, but already %d are defined.</font></p>\n"),
                cnts->members[rr]->max_count,
                mmbound);
      }

      if (mmbound < cnts->members[rr]->max_count) {
        fprintf(fout, _("<p>You may define up to %d members.</p>"),
                cnts->members[rr]->max_count);
      }

      /*
      if (cnts->members[rr]->max_count < mmbound)
        mmbound = cnts->members[rr]->max_count;
      */
      for (mm = 0; mm < mmbound; mm++) {
        fprintf(fout, "<h3>%s %d", gettext(ns_role_labels[rr]), mm + 1);
        if (!u->read_only && !ui->cnts_read_only) {
          fprintf(fout, " [%s%s</a>]",
                  ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE, "role=%d&amp;member=%d", rr, mm), _("Edit"));
        }
        if (!u->read_only && !ui->cnts_read_only
            && !cnts->disable_member_delete) {
          fprintf(fout, " [%s%s</a>]",
                  ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_REMOVE_MEMBER, "role=%d&amp;member=%d", rr, mm), _("Remove"));
        }
        if (!u->read_only && !ui->cnts_read_only
            && role_move_direction[rr]
            && (nr = role_move_dir_code[rr]) >= 0
            && cnts->members[nr] && cnts->members[nr]->max_count
            && userlist_members_count(ui->members, nr) <= cnts->members[nr]->max_count) {
          fprintf(fout, " [%s%s</a>]",
                  ns_aref(ub, sizeof(ub), phr, NEW_SRV_ACTION_REG_MOVE_MEMBER, "role=%d&amp;member=%d", rr, mm), gettext(role_move_direction[rr]));
        }
        fprintf(fout, "</h3>\n");
        if (!(m = userlist_members_get_nth(ui->members, rr, mm)))
          continue;
        fprintf(fout, "<table class=\"b0\">\n");

        for (i = 0; (ff = member_fields_order[i]); i++) {
          if (!cnts->members[rr]->fields[ff]) continue;
          userlist_get_member_field_str(fbuf, sizeof(fbuf), m,
                                        userlist_member_field_ids[ff], 0, 1);
          legend = cnts->members[rr]->fields[ff]->legend;
          if (!legend || !*legend)
            legend = gettext(member_field_desc[ff].description);
          info_table_row(fout, legend, fbuf,
                         userlist_is_empty_member_field(m, userlist_member_field_ids[ff]),
                         cnts->members[rr]->fields[ff]->mandatory,
                         cnts->members[rr]->fields[ff]->is_password,
                         userlist_get_member_accepting_chars(ff),
                         &ab, member_field_desc[ff].is_href, 0);
        }

        fprintf(fout, "</table>\n");
      }
    }
  }

  // generate tabs bottom
  if (tab_count > 1) {
    fprintf(fout, "</div></td></tr></table>\n");
  }

  html_armor_free(&ab);
}

void
ns_edit_member_form(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        const struct userlist_member *m,
        int role,
        int member,
        int skip_header,
        const unsigned char *var_prefix,
        int fields_order[]);

void
ns_edit_general_form(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        const struct userlist_user *u)
{
  unsigned char bb[1024];
  unsigned char buf[1024];
  unsigned char varname[1024];
  int i, ff, j, rr;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *comment = 0, *s = 0, *ac, *legend;
  size_t allowed_languages_u = 0, allowed_regions_u = 0;
  unsigned char **allowed_languages = 0, **allowed_regions = 0;
  int *user_lang_map = 0;
  const struct userlist_member *m = 0;
  const struct userlist_user_info *ui = 0;
  int is_checked = 0;

  if (u) ui = u->cnts0;

  if (cnts->fields[CONTEST_F_LANGUAGES]) {
    allowed_list_parse(cnts->allowed_languages, 0,
                       &allowed_languages, &allowed_languages_u);
  }
  if (cnts->fields[CONTEST_F_REGION]) {
    allowed_list_parse(cnts->allowed_regions, 0,
                       &allowed_regions, &allowed_regions_u);
  }

  html_start_form(fout, 1, phr->self_url, "");
  html_hidden(fout, "SID", "%llx", phr->session_id);
  fprintf(fout, "<table class=\"b0\">");

  if (!cnts->disable_name) {
    bb[0] = 0;
    if (cnts->user_name_comment)
      snprintf(bb, sizeof(bb), "%s", cnts->user_name_comment);
    fprintf(fout, "<tr><td class=\"b0\"><b>%s</b>%s:</td>",
            cnts->personal?_("User name (for standings)"):_("Team name"), bb);
    bb[0] = 0;
    if (ui && ui->name) snprintf(bb, sizeof(bb), "%s", ui->name);
    comment = 0;
    if (check_str(bb, name_accept_chars) < 0) {
      comment = __("contains invalid characters");
    }
    fprintf(fout, "<td class=\"b0\">%s</td>",
            html_input_text(bb, sizeof(bb), "name", 64, 0, "%s", ARMOR(bb)));

    if (!comment) comment = "&nbsp;";
    fprintf(fout, "<td class=\"b0\"><font color=\"red\"><i>%s</i></font></td>", comment);
    fprintf(fout, "</tr>\n");
  }

  // for personal contest put the member form here
  if (ui && cnts->personal && cnts->members[(rr = CONTEST_M_CONTESTANT)]
      && cnts->members[rr]->max_count > 0) {
    m = userlist_members_get_first(ui->members);
    ns_edit_member_form(fout, phr, cnts, m, rr, 0, 1, "m", member_fields_order_1);
  }

  for (i = 0; (ff = contest_fields_order[i]); i++) {
    if (!cnts->fields[ff]) continue;
    fprintf(fout, "<tr>");
    fprintf(fout, "<td class=\"b0\" valign=\"top\">");
    if (cnts->fields[ff]->mandatory) fprintf(fout, "<b>");
    legend = cnts->fields[ff]->legend;
    if (!legend || !*legend)
      legend = gettext(contest_field_desc[ff].description);
    fprintf(fout, "%s:", legend);
    if (cnts->fields[ff]->mandatory) fprintf(fout, "</b>");
    fprintf(fout, "</td>");
    userlist_get_user_info_field_str(bb, sizeof(bb), ui,
                                     userlist_contest_field_ids[ff], 0);
    comment = 0;
    if (cnts->fields[ff]->mandatory
        && (userlist_is_empty_user_info_field(ui,userlist_contest_field_ids[ff])
            || !bb[0])) {
      comment = _("must be specified");
    } else if ((ac = userlist_get_contest_accepting_chars(ff))
               && check_str(bb, ac) < 0) {
      comment = _("contains invalid characters");
    }

    if (cnts->fields[ff]->options) {
      int separator = 0;
      if (cnts->fields[ff]->separator)
        separator = cnts->fields[ff]->separator[0];
      if (separator <= 0) separator = ',';
      unsigned char **options = 0;
      size_t options_u = 0;
      allowed_list_parse(cnts->fields[ff]->options, separator,
                         &options, &options_u);

      fprintf(fout, "<td class=\"b0\"><select name=\"param_%d\"><option></option>", ff);
      for (j = 0; j < options_u; j++) {
        s = "";
        if (!strcmp(bb, options[j]))
          s = " selected=\"yes\"";
        fprintf(fout, "<option%s>%s</option>", s, ARMOR(options[j]));
      }
      fprintf(fout, "</select></td>\n");

      allowed_list_free(options, options_u);
    } else if (ff == CONTEST_F_LANGUAGES && allowed_languages_u > 0) {
      allowed_list_map(bb, 0, allowed_languages, allowed_languages_u,
                       &user_lang_map);

      fprintf(fout, "<td class=\"b0\"><table class=\"b0\">\n");
      for (j = 0; j < allowed_languages_u; j++) {
        fprintf(fout, "<tr><td class=\"b0\"><input type=\"checkbox\" name=\"proglang_%d\"%s/></td>"
               "<td class=\"b0\">%s</td></tr>\n",
               j, user_lang_map[j]?" checked=\"yes\"":"",
               ARMOR(allowed_languages[j]));
      }
      fprintf(fout, "</table></td>\n");
    } else if (ff == CONTEST_F_REGION && allowed_regions_u > 0) {
      fprintf(fout, "<td class=\"b0\"><select name=\"param_%d\"><option></option>", ff);
      for (j = 0; j < allowed_regions_u; j++) {
        s = "";
        if (!strcmp(bb, allowed_regions[j]))
          s = " selected=\"yes\"";
        fprintf(fout, "<option%s>%s</option>", s, ARMOR(allowed_regions[j]));
      }
      fprintf(fout, "</select></td>\n");
    } else if (cnts->fields[ff]->checkbox) {
      xml_parse_bool(NULL, NULL, 0, 0, bb, &is_checked);
      snprintf(varname, sizeof(varname), "param_%d", ff);
      fprintf(fout, "<td class=\"b0\">%s</td>",
              html_checkbox(buf, sizeof(buf), varname, "yes", is_checked, 0));
    } else {
      snprintf(varname, sizeof(varname), "param_%d", ff);
      fprintf(fout, "<td class=\"b0\">%s</td>",
              html_input_text(buf, sizeof(buf), varname,
                              contest_field_desc[ff].size, 0,
                              "%s", ARMOR(bb)));
    }

    if (!comment) comment = "&nbsp;";
    fprintf(fout, "<td class=\"b0\" valign=\"top\"><font color=\"red\"><i>%s</i></font></td>", comment);
    fprintf(fout, "</tr>\n");
  }

  // for personal contest put the member form here
  if (ui && cnts->personal && cnts->members[(rr = CONTEST_M_CONTESTANT)]
      && cnts->members[rr]->max_count > 0) {
    m = userlist_members_get_first(ui->members);
    ns_edit_member_form(fout, phr, cnts, m, rr, 0, 1, "m", member_fields_order_2);
  }

  fprintf(fout, "</table>\n");
  fprintf(fout, "<table class=\"b0\"><tr>");
  fprintf(fout, "<td class=\"b0\">%s</td>",
          ns_submit_button(bb, sizeof(bb), 0,
                           NEW_SRV_ACTION_REG_SUBMIT_GENERAL_EDITING, 0));
  fprintf(fout, "<td class=\"b0\">%s</td>",
          ns_submit_button(bb, sizeof(bb), 0,
                           NEW_SRV_ACTION_REG_CANCEL_GENERAL_EDITING, 0));
  fprintf(fout, "</tr></table>");
  fprintf(fout, "</form>\n");

  html_armor_free(&ab);
  allowed_list_free(allowed_languages, allowed_languages_u);
  allowed_list_free(allowed_regions, allowed_regions_u);
  xfree(user_lang_map);
}

static const unsigned char * const month_names[] =
{
  "",
  __("Jan"), __("Feb"), __("Mar"), __("Apr"), __("May"), __("Jun"),
  __("Jul"), __("Aug"), __("Sep"), __("Oct"), __("Nov"), __("Dec"),
};

static void
display_date_change_dialog(FILE *fout, int field, const unsigned char *val,
                           const unsigned char *beg_str,
                           const unsigned char *end_str,
                           const unsigned char *var_prefix)
{
  int day = 0, month = 0, year = 0, n;
  unsigned char vbuf[128];
  const unsigned char *sstr = " selected=\"selected\"";
  const unsigned char *s = "";

  if (!var_prefix) var_prefix = "";

  fprintf(fout, "%s", beg_str);
  if (sscanf(val, "%d/%d/%d%n", &year, &month, &day, &n) != 3 || val[n]
      || year <= 1900 || year >= 10000 || month < 0 || month > 12
      || day < 0 || day > 31) {
    day = month = year = 0;
  }
  if (day == 1 && month == 1 && year == 1970) {
    day = month = year = 0;
  }

  // day selection
  s = "";
  if (!day) s = sstr;
  fprintf(fout, "<select name=\"%sday_%d\"><option%s></option>",
          var_prefix, field, s);
  for (n = 1; n <= 31; n++) {
    s = "";
    if (day == n) s = sstr;
    fprintf(fout, "<option%s>%d</option>", s, n);
  }
  fprintf(fout, "</select>\n");

  // month selection
  s = "";
  if (!month) s = sstr;
  fprintf(fout, "<select name=\"%smonth_%d\"><option value=\"0\"%s></option>",
          var_prefix, field, s);
  for (n = 1; n <= 12; n++) {
    s = "";
    if (month == n) s = sstr;
    fprintf(fout, "<option value=\"%d\"%s>%s</option>", n, s,
            gettext(month_names[n]));
  }
  fprintf(fout, "</select>\n");

  vbuf[0] = 0;
  if (year > 0) snprintf(vbuf, sizeof(vbuf), "%d", year);
  fprintf(fout, "<input type=\"text\" name=\"%syear_%d\" value=\"%s\" maxlength=\"4\" size=\"4\"/></p>", var_prefix, field, vbuf);
  fprintf(fout, "%s", end_str);
}

static unsigned char const * const member_status_string[] =
{
  0,
  __("School student"),
  __("Student"),
  __("Magistrant"),
  __("PhD student"),
  __("School teacher"),
  __("Professor"),
  __("Scientist"),
  __("Other")
};

static void
display_status_changing_dialog(
        FILE *fout,
        int field,
        int val,
        const unsigned char *beg_str,
        const unsigned char *end_str,
        const unsigned char *var_prefix)
{
  int n = 0;

  if (!beg_str) beg_str = "";
  if (!end_str) end_str = "";
  if (!var_prefix) var_prefix = "";

  fprintf(fout, "%s<select name=\"%sparam_%d\"><option value=\"\"></option>",
          beg_str, var_prefix, field);

  if (val < 0 || val >= USERLIST_ST_LAST) val = 0;

  for (n = 1; n < USERLIST_ST_LAST; n++) {
    fprintf(fout, "<option value=\"%d\"%s>%s</option>",
           n, n == val?" selected=\"selected\"":"",
           gettext(member_status_string[n]));
  }
  fprintf(fout, "</select>%s", end_str);
}

static unsigned char const * const member_gender_string[] =
{
  0,
  __("Male"),
  __("Female"),
};

static void
display_gender_changing_dialog(
        FILE *fout,
        int field,
        int val,
        const unsigned char *beg_str,
        const unsigned char *end_str,
        const unsigned char *var_prefix)
{
  int n = 0;

  if (!beg_str) beg_str = "";
  if (!end_str) end_str = "";
  if (!var_prefix) var_prefix = "";

  fprintf(fout, "%s<select name=\"%sparam_%d\"><option value=\"\"></option>",
          beg_str, var_prefix, field);

  if (val < 0 || val >= USERLIST_SX_LAST) val = 0;

  for (n = 1; n < USERLIST_SX_LAST; n++) {
    fprintf(fout, "<option value=\"%d\"%s>%s</option>",
           n, n == val?" selected=\"selected\"":"",
           gettext(member_gender_string[n]));
  }
  fprintf(fout, "</select>%s", end_str);
}

static void
display_grade_changing_dialog(
        FILE *fout,
        int field,
        int val,
        const unsigned char *beg_str,
        const unsigned char *end_str,
        const unsigned char *var_prefix)
{
  int n = 0;
  const unsigned char *sel, *s1, *s2;
  unsigned char buf[64];

  if (!beg_str) beg_str = "";
  if (!end_str) end_str = "";
  if (!var_prefix) var_prefix = "";

  fprintf(fout, "%s<select name=\"%sparam_%d\">",
          beg_str, var_prefix, field);

  if (val < -1 || val >= 12) val = -1;

  for (n = -1; n < 12; n++) {
    sel = "";
    if (n == val) sel = " selected=\"selected\"";
    if (n == -1) {
      s1 = s2 = "";
    } else if (!n) {
      s1 = "0";
      s2 = _("Other");
    } else {
      snprintf(buf, sizeof(buf), "%d", n);
      s1 = s2 = buf;
    }
    fprintf(fout, "<option value=\"%s\"%s>%s</option>", s1, sel, s2);
  }
  fprintf(fout, "</select>%s", end_str);
}

void
ns_edit_member_form(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        const struct userlist_member *m,
        int role,
        int member,
        int skip_header,
        const unsigned char *var_prefix,
        int fields_order[])
{
  const struct contest_member *cm = cnts->members[role];
  unsigned char bb[1024];
  unsigned char varname[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int i, ff, val;
  const unsigned char *comment = 0, *ac, *legend;

  if (!var_prefix) var_prefix = "";
  if (!fields_order) fields_order = member_fields_order;

  if (!skip_header) {
    html_start_form(fout, 1, phr->self_url, "");
    html_hidden(fout, "SID", "%llx", phr->session_id);
    html_hidden(fout, "role", "%d", role);
    html_hidden(fout, "member", "%d", member);

    fprintf(fout, "<table class=\"b0\">");
  }
  for (i = 0; (ff = fields_order[i]); i++) {
    if (!cm->fields[ff]) continue;
    fprintf(fout, "<tr>");
    fprintf(fout, "<td class=\"b0\" valign=\"top\">");
    if (cm->fields[ff]->mandatory) fprintf(fout, "<b>");
    legend = cm->fields[ff]->legend;
    if (!legend || !*legend)
      legend = gettext(member_field_desc[ff].description);
    fprintf(fout, "%s:", legend);
    if (cm->fields[ff]->mandatory) fprintf(fout, "</b>");
    fprintf(fout, "</td>");
    bb[0] = 0;
    if (m)
      userlist_get_member_field_str(bb, sizeof(bb), m,
                                    userlist_member_field_ids[ff], 0, 1);
    comment = 0;
    if (cm->fields[ff]->mandatory
        && ((m && userlist_is_empty_member_field(m, userlist_member_field_ids[ff]))
            || !bb[0])) {
      comment = __("must be specified");
    } else if ((ac = userlist_get_member_accepting_chars(ff))
               && check_str(bb, ac) < 0) {
      comment = __("contains invalid characters");
    }

    switch (ff) {
    case CONTEST_MF_STATUS:
      val = 0;
      if (m) val = m->status;
      display_status_changing_dialog(fout, ff, val, "<td class=\"b0\">",
                                     "</td>", var_prefix);
      break;
    case CONTEST_MF_GENDER:
      val = 0;
      if (m) val = m->gender;
      display_gender_changing_dialog(fout, ff, val, "<td class=\"b0\">",
                                     "</td>", var_prefix);
      break;

    case CONTEST_MF_GRADE:
      val = 0;
      if (m) val = m->grade;
      display_grade_changing_dialog(fout, ff, val, "<td class=\"b0\">",
                                     "</td>", var_prefix);
      break;

    case CONTEST_MF_BIRTH_DATE:
    case CONTEST_MF_ENTRY_DATE:
    case CONTEST_MF_GRADUATION_DATE:
      display_date_change_dialog(fout, ff, bb, "<td class=\"b0\">",
                                 "</td>", var_prefix);
      break;

    default:
      snprintf(varname, sizeof(varname), "%sparam_%d", var_prefix, ff);
      if (cm->fields[ff]->is_password) {
        fprintf(fout, "<td class=\"b0\">%s</td>",
                html_input_password(bb, sizeof(bb), varname,
                                    member_field_desc[ff].size,
                                    "%s", ARMOR(bb)));
      } else {
        fprintf(fout, "<td class=\"b0\">%s</td>",
                html_input_text(bb, sizeof(bb), varname,
                                member_field_desc[ff].size, 0,
                                "%s", ARMOR(bb)));
      }
      break;
    }

    if (!comment || !*comment) comment = "&nbsp;";
    else comment = gettext(comment);
    fprintf(fout, "<td class=\"b0\" valign=\"top\"><font color=\"red\"><i>%s</i></font></td>", comment);
    fprintf(fout, "</tr>\n");
  }

  if (!skip_header) {
    fprintf(fout, "</table>\n");

    fprintf(fout, "<table class=\"b0\"><tr>");
    fprintf(fout, "<td class=\"b0\">%s</td>",
            ns_submit_button(bb, sizeof(bb), 0,
                             NEW_SRV_ACTION_REG_SUBMIT_MEMBER_EDITING, 0));
    fprintf(fout, "<td class=\"b0\">%s</td>",
            ns_submit_button(bb, sizeof(bb), 0,
                             NEW_SRV_ACTION_REG_CANCEL_MEMBER_EDITING, 0));
    fprintf(fout, "</table>");
    fprintf(fout, "</form>\n");
  }

  html_armor_free(&ab);
}

static void
cancel_editing(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  int next_action = NEW_SRV_ACTION_REG_VIEW_GENERAL;
  int role;

  if (phr->action == NEW_SRV_ACTION_REG_CANCEL_MEMBER_EDITING
      && hr_cgi_param_int(phr, "role", &role) >= 0
      && role >= CONTEST_M_CONTESTANT && role < CONTEST_LAST_MEMBER)
    next_action = NEW_SRV_ACTION_REG_VIEW_CONTESTANTS + role;

  ns_refresh_page(fout, phr, next_action, 0);
}

static void
action_error_page(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const unsigned char *text)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *n, *s;

  if (phr->locale_id < 0) phr->locale_id = 0;
  l10n_setlocale(phr->locale_id);

  s = _("Operation errors");
  n = phr->name;
  if (!n || !*n) n = phr->login;
  ns_header(fout, extra->header_txt, 0, 0, 0, 0, phr->locale_id, cnts,
            NULL_CLIENT_KEY,
            "%s [%s, %s]", s, ARMOR(n), extra->contest_arm);

  fprintf(fout, "<div class=\"user_actions\"><table class=\"menu\"><tr>");
  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  fprintf(fout, "</tr></table></div>\n");

  fprintf(fout, "<div class=\"white_empty_block\">&nbsp;</div>\n");

  fprintf(fout, "<div class=\"contest_actions\"><table class=\"menu\"><tr>\n");
  fprintf(fout, "<td class=\"menu\"><div class=\"contest_actions_item\">&nbsp;</div></td>");
  fprintf(fout, "</tr></table></div>\n");
  if (extra->separator_txt && *extra->separator_txt) {
    ns_separator(fout, extra->separator_txt, cnts);
  }

  fprintf(fout, "<br><font color=\"red\"><pre>%s</pre></font><br>\n",
          ARMOR(text));

  ns_footer(fout, extra->footer_txt, extra->copyright_txt, phr->locale_id);
  l10n_resetlocale();

  html_armor_free(&ab);
}

static unsigned char *
preprocess_string(unsigned char *buf, size_t size, const unsigned char *str)
{
  const unsigned char *s = str;
  size_t len, i;

  ASSERT(size > 0);

  for (;*s > 0 && *s <= ' '; s++);
  snprintf(buf, size, "%s", s);
  len = strlen(buf);

  for (i = 0; i < len; i++)
    if (buf[i] < ' ') buf[i] = ' ';
  while (len > 0 && buf[len - 1] == ' ') len--;
  buf[len] = 0;
  return buf;
}

static unsigned char *
assemble_programming_languages(
        unsigned char *buf,
        size_t size,
        struct http_request_info *phr,
        const unsigned char *cnts_allowed_languages)
{
  unsigned char **allowed_languages;
  size_t allowed_languages_u, i;
  int is_first = 1;
  unsigned char varname[64];
  FILE *f;
  char *t = 0;
  size_t z = 0;
  const unsigned char *s = 0;

  allowed_list_parse(cnts_allowed_languages, 0,
                     &allowed_languages, &allowed_languages_u);
  f = open_memstream(&t, &z);

  for (i = 0; i < allowed_languages_u; i++) {
    snprintf(varname, sizeof(varname), "proglang_%zu", i);
    if (hr_cgi_param(phr, varname, &s) > 0) {
      if (!is_first) fputs(", ", f);
      is_first = 0;
      fputs(allowed_languages[i], f);
    }
  }
  close_memstream(f); f = 0;

  snprintf(buf, size, "%s", t);
  allowed_list_free(allowed_languages, allowed_languages_u);
  xfree(t);
  return buf;
}

static unsigned char *
get_member_field(
        unsigned char *buf,
        size_t size,
        struct http_request_info *phr,
        int field,
        const unsigned char *var_prefix,
        FILE *log_f,
        const unsigned char *legend)
{
  unsigned char varname[128];
  int r, n, dd, mm, yy;
  const unsigned char *v;
  struct tm stm, *ptm;
  time_t ttm;

  if (!var_prefix) var_prefix = "";

  switch (field) {
  case CONTEST_MF_STATUS:
    snprintf(varname, sizeof(varname), "%sparam_%d", var_prefix, field);
    if ((r = hr_cgi_param(phr, varname, &v)) < 0)
      goto non_printable;
    else if (!r || !v)
      v = "";

    r = 0;
    if (*v) {
      if (sscanf(v, "%d%n", &r, &n) != 1 || v[n] || r < 0
          || r >= USERLIST_ST_LAST)
        goto invalid_field;
    }
    buf[0] = 0;
    if (r > 0) snprintf(buf, size, "%d", r);
    break;

  case CONTEST_MF_GENDER:
    snprintf(varname, sizeof(varname), "%sparam_%d", var_prefix, field);
    if ((r = hr_cgi_param(phr, varname, &v)) < 0)
      goto non_printable;
    else if (!r || !v)
      v = "";

    r = 0;
    if (*v) {
      if (sscanf(v, "%d%n", &r, &n) != 1 || v[n] || r < 0
          || r >= USERLIST_SX_LAST)
        goto invalid_field;
    }
    buf[0] = 0;
    if (r > 0) snprintf(buf, size, "%d", r);
    break;

  case CONTEST_MF_GRADE:
    snprintf(varname, sizeof(varname), "%sparam_%d", var_prefix, field);
    if ((r = hr_cgi_param(phr, varname, &v)) < 0)
      goto non_printable;
    else if (!r || !v)
      v = "";

    r = 0;
    buf[0] = 0;
    if (*v) {
      if (sscanf(v, "%d%n", &r, &n) != 1 || v[n] || r < -1 || r >= 100000)
        goto invalid_field;
      if (r >= 0) snprintf(buf, size, "%d", r);
    }
    break;

  case CONTEST_MF_BIRTH_DATE:
  case CONTEST_MF_ENTRY_DATE:
  case CONTEST_MF_GRADUATION_DATE:
    // <prefix>day_<field>, <prefix>month_<field>, <prefix>year_<field>

    snprintf(varname, sizeof(varname), "%sday_%d", var_prefix, field);
    if ((r = hr_cgi_param(phr, varname, &v)) < 0)
      goto non_printable;
    else if (!r || !v)
      v = "";
    dd = 0;
    if (*v) {
      if (sscanf(v, "%d%n", &dd, &n) != 1 || v[n] || dd < 0 || dd >= 32)
        goto invalid_field;
    }

    snprintf(varname, sizeof(varname), "%smonth_%d", var_prefix, field);
    if ((r = hr_cgi_param(phr, varname, &v)) < 0)
      goto non_printable;
    else if (!r || !v)
      v = "";
    mm = 0;
    if (*v) {
      if (sscanf(v, "%d%n", &mm, &n) != 1 || v[n] || mm < 0 || mm > 12)
        goto invalid_field;
    }

    snprintf(varname, sizeof(varname), "%syear_%d", var_prefix, field);
    if ((r = hr_cgi_param(phr, varname, &v)) < 0)
      goto non_printable;
    else if (!r || !v)
      v = "";
    yy = 0;
    if (*v) {
      if (sscanf(v, "%d%n", &yy, &n) != 1 || v[n] || yy < 0 || yy >= 10000)
        goto invalid_field;
    }

    if ((!dd && !mm && !yy) || (dd == 1 && mm == 1 && yy == 1970)) {
      buf[0] = 0;
      return buf;
    }
    if (!dd || !mm || yy < 1970) goto invalid_field;

    memset(&stm, 0, sizeof(stm));
    stm.tm_mday = dd;
    stm.tm_mon = mm - 1;
    stm.tm_year = yy - 1900;
    stm.tm_isdst = -1;
    if ((ttm = mktime(&stm)) == (time_t) -1) goto invalid_field;
    if (!ttm) {
      buf[0] = 0;
      return buf;
    }
    ptm = localtime(&ttm);
    snprintf(buf, size, "%04d-%02d-%02d", ptm->tm_year + 1900,
             ptm->tm_mon + 1, ptm->tm_mday);
    //fprintf(stderr, ">>%s<<\n", buf);
    break;

  default:
    snprintf(varname, sizeof(varname), "%sparam_%d", var_prefix, field);
    if ((r = hr_cgi_param(phr, varname, &v)) < 0) {
      goto non_printable;
    } else if (!r || !v) {
      v = "";
    }
    preprocess_string(buf, size, v);
    break;
  }

  return buf;

 non_printable:
  fprintf(log_f, _("Field \"%s\" contains non-printable characters.\n"),
          gettext(member_field_desc[field].description));
  return 0;

 invalid_field:
  fprintf(log_f, _("Value of field \"%s\" is invalid.\n"),
          gettext(member_field_desc[field].description));
  return 0;
}

static void
submit_member_editing(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  int r, ff;
  int role = 0, member = 0;
  const struct userlist_user *u = NULL;
  const struct userlist_member *m = 0;
  unsigned char vbuf[1024];
  int deleted_ids[USERLIST_NM_LAST], edited_ids[USERLIST_NM_LAST];
  unsigned char *edited_strs[USERLIST_NM_LAST];
  int deleted_num = 0, edited_num = 0;
  const unsigned char *legend;

  if (cnts->personal) {
    // they kidding us...
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
    return;
  }

  u = phr->user_info;

  // role, member, param_%d
  if (hr_cgi_param_int(phr, "role", &role) < 0
      || role < CONTEST_M_CONTESTANT || role >= CONTEST_LAST_MEMBER
      || !cnts->members[role] || cnts->members[role]->max_count <= 0) {
    // invalid role, or such role is not enabled on this contest...
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
    return;
  }

  if (hr_cgi_param_int(phr, "member", &member) < 0
      || !u || !u->cnts0 || u->read_only || u->cnts0->cnts_read_only
      || !(m = userlist_members_get_nth(u->cnts0->members, role, member)))
    goto done;

  log_f = open_memstream(&log_t, &log_z);

  if ((phr->reg_flags & USERLIST_UC_REG_READONLY)) {
    fprintf(log_f, "permission denied\n");
    goto done;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    fprintf(log_f, "%s.\n", _("User database server is down"));
    goto done;
  }

  for (ff = CONTEST_MF_FIRSTNAME; ff < CONTEST_LAST_MEMBER_FIELD; ff++) {
    if (!cnts->members[role]->fields[ff]) continue;

    legend = cnts->members[role]->fields[ff]->legend;
    if (!legend || !*legend)
      legend = gettext(member_field_desc[ff].description);

    if (!get_member_field(vbuf, sizeof(vbuf), phr, ff, "", log_f, legend))
      goto done;

    if (vbuf[0]) {
      edited_ids[edited_num] = userlist_member_field_ids[ff];
      edited_strs[edited_num] = alloca(strlen(vbuf) + 1);
      strcpy(edited_strs[edited_num], vbuf);
      edited_num++;
    } else {
      deleted_ids[deleted_num++] = userlist_member_field_ids[ff];
    }
  }

  r = userlist_clnt_edit_field_seq(ul_conn, ULS_EDIT_FIELD_SEQ,
                                   phr->user_id, phr->contest_id, m->serial,
                                   deleted_num, edited_num, deleted_ids,
                                   edited_ids,
                                   (const unsigned char**) edited_strs);
  if (r < 0) {
    fprintf(log_f, "%s.\n", userlist_strerror(-r));
    goto done;
  }

  // force reloading the user info
  ns_invalidate_session(phr->session_id, phr->client_key);
  phr->nsi = NULL;

 done:;
  if (log_f) close_memstream(log_f);
  log_f = 0;

  if (log_t && *log_t) {
    action_error_page(fout, phr, cnts, extra, log_t);
  } else {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_CONTESTANTS + role - CONTEST_M_CONTESTANT, 0);
  }

  xfree(log_t);
}

static void
submit_general_editing(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  int r, ff;
  const unsigned char *v = 0;
  unsigned char varname[128];
  unsigned char vbuf[1024];
  int deleted_ids[USERLIST_NM_LAST], edited_ids[USERLIST_NM_LAST];
  unsigned char *edited_strs[USERLIST_NM_LAST];
  int deleted_num = 0, edited_num = 0;
  const unsigned char *legend;
  char *eptr;

  l10n_setlocale(phr->locale_id);
  log_f = open_memstream(&log_t, &log_z);

  if ((phr->reg_flags & USERLIST_UC_REG_READONLY)) {
    fprintf(log_f, "permission denied\n");
    goto done;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    fprintf(log_f, "%s.\n", _("User database server is down"));
    goto done;
  }

  // name, param_%d
  // for personal contests, also set the first member

  if (!cnts->disable_name && !cnts->read_only_name) {
    if ((r = hr_cgi_param(phr, "name", &v)) < 0) {
      fprintf(log_f, "%s.\n",
              _("Field \"Name\" contains non-printable characters"));
      goto done;
    } else if (!r || !v) {
      v = "";
    }
    preprocess_string(vbuf, sizeof(vbuf), v);
    if (vbuf[0]) {
      edited_ids[edited_num] = USERLIST_NC_NAME;
      edited_strs[edited_num] = alloca(strlen(vbuf) + 1);
      strcpy(edited_strs[edited_num], vbuf);
      edited_num++;
    } else {
      deleted_ids[deleted_num++] = USERLIST_NC_NAME;
    }
  }

  for (ff = CONTEST_FIRST_FIELD; ff < CONTEST_LAST_FIELD; ff++) {
    if (!cnts->fields[ff]) continue;

    legend = cnts->fields[ff]->legend;
    if (!legend || !*legend)
      legend = gettext(contest_field_desc[ff].description);

    if (ff == CONTEST_F_LANGUAGES && cnts->allowed_languages) {
      assemble_programming_languages(vbuf, sizeof(vbuf), phr,
                                     cnts->allowed_languages);
    } else {
      snprintf(varname, sizeof(varname), "param_%d", ff);
      if ((r = hr_cgi_param(phr, varname, &v)) < 0) {
        fprintf(log_f, _("Field \"%s\" contains non-printable characters.\n"),
                legend);
        goto done;
      } else if (!r || !v) {
        v = "";
      }
      preprocess_string(vbuf, sizeof(vbuf), v);
      if (ff == CONTEST_F_INSTNUM) {
        errno = 0;
        r = strtol(vbuf, &eptr, 10);
        if (errno || *eptr || r < -1) {
          fprintf(log_f, _("Value of field \"%s\" is invalid.\n"),
                  gettext(contest_field_desc[ff].description));
          goto done;
        }
      }
    }

    if (vbuf[0]) {
      edited_ids[edited_num] = userlist_contest_field_ids[ff];
      edited_strs[edited_num] = alloca(strlen(vbuf) + 1);
      strcpy(edited_strs[edited_num], vbuf);
      edited_num++;
    } else {
      deleted_ids[deleted_num++] = userlist_contest_field_ids[ff];
    }
  }

  if (cnts->personal && cnts->members[CONTEST_M_CONTESTANT]) {
    for (ff = CONTEST_MF_FIRSTNAME; ff < CONTEST_LAST_MEMBER_FIELD; ff++) {
      if (!cnts->members[CONTEST_M_CONTESTANT]->fields[ff]) continue;

      legend = cnts->members[CONTEST_M_CONTESTANT]->fields[ff]->legend;
      if (!legend || !*legend)
        legend = gettext(member_field_desc[ff].description);

      if (!get_member_field(vbuf, sizeof(vbuf), phr, ff, "m", log_f, legend))
        goto done;

      if (vbuf[0]) {
        edited_ids[edited_num] = userlist_member_field_ids[ff];
        edited_strs[edited_num] = alloca(strlen(vbuf) + 1);
        strcpy(edited_strs[edited_num], vbuf);
        edited_num++;
      } else {
        deleted_ids[deleted_num++] = userlist_member_field_ids[ff];
      }
    }
  }

  r = userlist_clnt_edit_field_seq(ul_conn, ULS_EDIT_FIELD_SEQ,
                                   phr->user_id, phr->contest_id, 0,
                                   deleted_num, edited_num, deleted_ids,
                                   edited_ids,
                                   (const unsigned char**) edited_strs);
  if (r < 0) {
    fprintf(log_f, "%s.\n", gettext(userlist_strerror(-r)));
    goto done;
  }

  // force reloading the user info
  ns_invalidate_session(phr->session_id, phr->client_key);
  phr->nsi = NULL;

 done:;
  if (log_f) close_memstream(log_f);
  log_f = 0;

  if (log_t && *log_t) {
    action_error_page(fout, phr, cnts, extra, log_t);
  } else {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
  }

  l10n_resetlocale();
  xfree(log_t);
}

static void
add_member(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  int r, role = 0;
  struct userlist_user *u = NULL;

  if (cnts->personal) {
    // they kidding us...
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
    return;
  }

  u = phr->user_info;

  // role
  if (hr_cgi_param_int(phr, "role", &role) < 0
      || role < CONTEST_M_CONTESTANT || role >= CONTEST_LAST_MEMBER
      || !cnts->members[role] || cnts->members[role]->max_count <= 0) {
    // invalid role, or such role is not enabled on this contest...
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
    return;
  }

  userlist_get_cnts0(u);
  if (u && (u->read_only || (u->cnts0 && u->cnts0->cnts_read_only)))
    goto done;
  if (u && u->cnts0 && userlist_members_count(u->cnts0->members, role) >= cnts->members[role]->max_count)
    goto done;

  log_f = open_memstream(&log_t, &log_z);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    fprintf(log_f, "%s.\n", _("User database server is down"));
    goto done;
  }

  r = userlist_clnt_create_member(ul_conn, phr->user_id, phr->contest_id, role);
  if (r < 0) {
    fprintf(log_f, "%s.\n", userlist_strerror(-r));
    goto done;
  }

  // force reloading the user info
  ns_invalidate_session(phr->session_id, phr->client_key);
  phr->nsi = NULL;

 done:;
  if (log_f) close_memstream(log_f);
  log_f = 0;

  if (log_t && *log_t) {
    action_error_page(fout, phr, cnts, extra, log_t);
  } else {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_CONTESTANTS + role - CONTEST_M_CONTESTANT, 0);
  }

  xfree(log_t);
}

static void
remove_member(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  int r, role = 0, member = 0;
  const struct userlist_user *u = NULL;
  const struct userlist_member *m = 0;

  if (cnts->personal) {
    // they kidding us...
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
    return;
  }

  u = phr->user_info;

  // role
  if (hr_cgi_param_int(phr, "role", &role) < 0
      || role < CONTEST_M_CONTESTANT || role >= CONTEST_LAST_MEMBER
      || !cnts->members[role] || cnts->members[role]->max_count <= 0) {
    // invalid role, or such role is not enabled on this contest...
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
    return;
  }

  if (!u || !u->cnts0 || u->read_only || u->cnts0->cnts_read_only
      || cnts->disable_member_delete)
    goto done;

  // member
  if (hr_cgi_param_int(phr, "member", &member) < 0 || member < 0
      || !(m = userlist_members_get_nth(u->cnts0->members, role, member)))
    goto done;

  log_f = open_memstream(&log_t, &log_z);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    fprintf(log_f, "%s.\n", _("User database server is down"));
    goto done;
  }
  r = userlist_clnt_delete_info(ul_conn, ULS_PRIV_DELETE_MEMBER,
                                phr->user_id, phr->contest_id, m->serial);
  if (r < 0) {
    fprintf(log_f, "%s.\n", userlist_strerror(-r));
    goto done;
  }

  // force reloading the user info
  ns_invalidate_session(phr->session_id, phr->client_key);
  phr->nsi = NULL;

 done:;
  if (log_f) close_memstream(log_f);
  log_f = 0;

  if (log_t && *log_t) {
    action_error_page(fout, phr, cnts, extra, log_t);
  } else {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_CONTESTANTS + role - CONTEST_M_CONTESTANT, 0);
  }

  xfree(log_t);
}

static void
move_member(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  int r, role = 0, member = 0, new_role = 0;;
  const struct userlist_user *u = NULL;
  const struct userlist_member *m = 0;

  if (cnts->personal) {
    // they kidding us...
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
    return;
  }

  u = phr->user_info;

  // role
  if (hr_cgi_param_int(phr, "role", &role) < 0
      || role < CONTEST_M_CONTESTANT || role >= CONTEST_LAST_MEMBER
      || !cnts->members[role] || cnts->members[role]->max_count <= 0) {
    // invalid role, or such role is not enabled on this contest...
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
    return;
  }

  // member
  if (!u || !u->cnts0 || u->read_only || u->cnts0->cnts_read_only)
    goto done;
  if (hr_cgi_param_int(phr, "member", &member) < 0)
    goto done;
  if (!userlist_members_get_nth(u->cnts0->members, role, member))
    goto done;

  switch (role) {
  case CONTEST_M_CONTESTANT:
    new_role = CONTEST_M_RESERVE;
    break;
  case CONTEST_M_RESERVE:
    new_role = CONTEST_M_CONTESTANT;
    break;
  case CONTEST_M_COACH:
    new_role = CONTEST_M_ADVISOR;
    break;
  case CONTEST_M_ADVISOR:
    new_role = CONTEST_M_COACH;
    break;
  default:
    goto done;
  }

  if (!cnts->members[new_role] || cnts->members[new_role]->max_count <= 0)
    goto done;
  if (userlist_members_count(u->cnts0->members, new_role) > cnts->members[new_role]->max_count)
    goto done;

  m = userlist_members_get_nth(u->cnts0->members, role, member);
  log_f = open_memstream(&log_t, &log_z);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    fprintf(log_f, "%s.\n", _("User database server is down"));
    goto done;
  }
  r = userlist_clnt_move_member(ul_conn, ULS_MOVE_MEMBER,
                                phr->user_id, phr->contest_id, m->serial,
                                new_role);
  if (r < 0) {
    fprintf(log_f, "%s.\n", userlist_strerror(-r));
    goto done;
  }

  // force reloading the user info
  ns_invalidate_session(phr->session_id, phr->client_key);
  phr->nsi = NULL;

 done:;
  if (log_f) close_memstream(log_f);
  log_f = 0;

  if (log_t && *log_t) {
    action_error_page(fout, phr, cnts, extra, log_t);
  } else {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_CONTESTANTS + role - CONTEST_M_CONTESTANT, 0);
  }

  xfree(log_t);
}

static void
logout(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  unsigned char urlbuf[1024];

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return error_page(fout, phr, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  userlist_clnt_delete_cookie(ul_conn, phr->user_id, phr->contest_id,
                              phr->session_id,
                              phr->client_key);
  if (phr->json_reply) {
    fprintf(fout, "{\n  \"ok\": true\n}\n");
  } else {
    snprintf(urlbuf, sizeof(urlbuf),
             "%s?contest_id=%d&locale_id=%d",
             phr->self_url, phr->contest_id, phr->locale_id);
    ns_refresh_page_2(fout, phr->client_key, urlbuf);
  }
}

static void
change_password(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  const unsigned char *p0 = 0, *p1 = 0, *p2 = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char url[1024];
  int r;

  log_f = open_memstream(&log_t, &log_z);

  if (hr_cgi_param(phr, "oldpasswd", &p0) <= 0) {
    fprintf(log_f, "%s.\n", _("Old password is invalid"));
    goto done;
  }
  if (hr_cgi_param(phr, "newpasswd1", &p1) <= 0) {
    fprintf(log_f, "%s.\n", _("New password (1) is invalid"));
    goto done;
  }
  if (hr_cgi_param(phr, "newpasswd2", &p2) <= 0) {
    fprintf(log_f, "%s.\n", _("New password (2) is invalid"));
    goto done;
  }
  if (strlen(p0) >= 256) {
    ns_error(log_f, NEW_SRV_ERR_OLD_PWD_TOO_LONG);
    goto done;
  }
  if (strcmp(p1, p2)) {
    ns_error(log_f, NEW_SRV_ERR_NEW_PWD_MISMATCH);
    goto done;
  }
  if (strlen(p1) >= 256) {
    ns_error(log_f, NEW_SRV_ERR_NEW_PWD_TOO_LONG);
    goto done;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    fprintf(log_f, "%s.\n", _("User database server is down"));
    goto done;
  }
  r = userlist_clnt_set_passwd(ul_conn, ULS_PRIV_SET_REG_PASSWD,
                               phr->user_id, phr->contest_id, 0, p0, p1, NULL);
  if (r < 0) {
    ns_error(log_f, NEW_SRV_ERR_PWD_UPDATE_FAILED, userlist_strerror(-r));
    goto done;
  }

 done:;
  if (log_f) close_memstream(log_f);
  log_f = 0;

  if (log_t && *log_t) {
    action_error_page(fout, phr, cnts, extra, log_t);
  } else {
    snprintf(url, sizeof(url),
             "%s?contest_id=%d&login=%s&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, URLARMOR(phr->login),
             phr->locale_id, NEW_SRV_ACTION_REG_LOGIN_PAGE);
    ns_refresh_page_2(fout, phr->client_key, url);
  }

  xfree(log_t);
  html_armor_free(&ab);
}

static void
register_for_contest(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  int r;

  log_f = open_memstream(&log_t, &log_z);

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    fprintf(log_f, "%s.\n", _("User database server is down"));
    goto done;
  }
  r = userlist_clnt_register_contest(ul_conn, ULS_REGISTER_CONTEST_2,
                                     phr->user_id, phr->contest_id,
                                     &phr->ip, phr->ssl_flag);
  if (r < 0) {
    fprintf(log_f, "%s: %s.\n", _("Registration for contest failed"),
            userlist_strerror(-r));
    goto done;
  }

 done:;
  if (log_f) close_memstream(log_f);
  log_f = 0;

  if (log_t && *log_t) {
    action_error_page(fout, phr, cnts, extra, log_t);
  } else {
    ns_refresh_page(fout, phr, NEW_SRV_ACTION_REG_VIEW_GENERAL, 0);
  }

  xfree(log_t);
}

enum { MAX_IMAGE_SIZE = 16 * 1024 * 1024, MAX_IMAGE_WIDTH = 10000, MAX_IMAGE_HEIGHT = 10000 };

static void
upload_avatar(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        time_t cur_time)
{
  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;
  const unsigned char *img_data = NULL;
  size_t img_size = 0;
  int mime_type = 0, width = 0, height = 0;
  unsigned char random_key_bin[AVATAR_RANDOM_KEY_SIZE];
  unsigned char random_key[AVATAR_RANDOM_KEY_SIZE * 2];
  unsigned char urlbuf[1024];

  urlbuf[0] = 0;
  log_f = open_memstream(&log_t, &log_z);

  if (phr->reg_status != USERLIST_REG_PENDING && phr->reg_status != USERLIST_REG_OK) {
    fprintf(log_f, "permission denied\n");
    goto done;
  }
  if ((phr->reg_flags & USERLIST_UC_REG_READONLY)) {
    fprintf(log_f, "permission denied\n");
    goto done;
  }

  if (hr_cgi_param_bin(phr, "img_file", &img_data, &img_size) <= 0) {
    fprintf(log_f, "image is not attached\n");
    goto done;
  }
  if (img_size > MAX_IMAGE_SIZE) {
    fprintf(log_f, "image file size (%zu) exceeds maximum allowed (%d)", img_size, (int) MAX_IMAGE_SIZE);
    goto done;
  }

  mime_type = image_identify(log_f, NULL, img_data, img_size, &width, &height);
  if (mime_type < 0) {
    goto done;
  }
  if (mime_type < MIME_TYPE_IMAGE_FIRST || mime_type > MIME_TYPE_IMAGE_LAST) {
    goto done;
  }
  if (width < 0 || height < 0) {
    fprintf(log_f, "invalid image dimensions (%dx%d)", width, height);
    goto done;
  }
  if (width > MAX_IMAGE_WIDTH || height > MAX_IMAGE_HEIGHT) {
    fprintf(log_f, "image is too large (%dx%d), max %dx%d is allowed", width, height, MAX_IMAGE_WIDTH, MAX_IMAGE_HEIGHT);
    goto done;
  }
  if (width < AVATAR_WIDTH || height < AVATAR_HEIGHT) {
    fprintf(log_f, "image is too small (%dx%d), min %dx%d is required", width, height, AVATAR_WIDTH, AVATAR_HEIGHT);
    goto done;
  }

  // generate 128-bit random key
  if (random_init() < 0) {
    fprintf(log_f, "failed to initialize random number generator");
    goto done;
  }
  random_bytes(random_key_bin, AVATAR_RANDOM_KEY_SIZE);
  base32_buf(random_key, random_key_bin, AVATAR_RANDOM_KEY_SIZE, 0);

  struct avatar_loaded_plugin *avt = avatar_plugin_get(extra, cnts, phr->config, NULL);
  if (!avt) {
    fprintf(log_f, "failed to load avatar plugin");
    goto done;
  }

  int r = avt->iface->insert(avt->data, phr->user_id, phr->contest_id,
                             0 /* is_cropped */,
                             1 /* is_temporary */,
                             0 /* is_public */,
                             mime_type, width, height, random_key,
                             cur_time,
                             img_data,
                             img_size,
                             NULL);
  if (r < 0) {
    fprintf(log_f, "failed to store avatar image");
    goto done;
  }

  snprintf(urlbuf, sizeof(urlbuf), "%s?SID=%llx&action=%d&key=%s",
           phr->self_url, phr->session_id, NEW_SRV_ACTION_CROP_AVATAR_PAGE,
           random_key);

done:;
  if (log_f) close_memstream(log_f);
  log_f = NULL;

  if (log_t && *log_t) {
    action_error_page(fout, phr, cnts, extra, log_t);
  } else {
    ns_refresh_page_2(fout, phr->client_key, urlbuf);
  }
}

static reg_action_handler_func_t reg_handlers[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_LOGOUT] = logout,
  [NEW_SRV_ACTION_CHANGE_PASSWORD] = change_password,
  [NEW_SRV_ACTION_REG_SUBMIT_GENERAL_EDITING] = submit_general_editing,
  [NEW_SRV_ACTION_REG_CANCEL_GENERAL_EDITING] = cancel_editing,
  [NEW_SRV_ACTION_REG_SUBMIT_MEMBER_EDITING] = submit_member_editing,
  [NEW_SRV_ACTION_REG_CANCEL_MEMBER_EDITING] = cancel_editing,
  [NEW_SRV_ACTION_REG_REGISTER] = register_for_contest,
  [NEW_SRV_ACTION_REG_ADD_MEMBER_PAGE] = add_member,
  [NEW_SRV_ACTION_REG_REMOVE_MEMBER] = remove_member,
  [NEW_SRV_ACTION_REG_MOVE_MEMBER] = move_member,
  [NEW_SRV_ACTION_UPLOAD_AVATAR] = upload_avatar,
};

typedef PageInterface *(*external_action_handler_t)(void);

static const unsigned char * const external_reg_action_names[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_MAIN_PAGE] = "reg_main_page",
  [NEW_SRV_ACTION_REG_LOGIN_PAGE] = "reg_login_page",
  [NEW_SRV_ACTION_CONTESTS_PAGE] = "reg_contests_page",
  [NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE] = "reg_create_page",
  [NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE] = "reg_edit_page",
  [NEW_SRV_ACTION_CROP_AVATAR_PAGE] = "reg_crop_avatar_page",
  [NEW_SRV_ACTION_SAVE_CROPPED_AVATAR_AJAX] = "reg_save_cropped_avatar_ajax",
};
static const int external_reg_action_aliases[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_REG_VIEW_GENERAL] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_REG_VIEW_CONTESTANTS] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_REG_VIEW_RESERVES] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_REG_VIEW_COACHES] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_REG_VIEW_ADVISORS] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_REG_VIEW_GUESTS] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_VIEW_SETTINGS] = NEW_SRV_ACTION_MAIN_PAGE,
  [NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE] = NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE,
};
static const unsigned char * const external_reg_error_names[NEW_SRV_ERR_LAST] =
{
  [NEW_SRV_ERR_UNKNOWN_ERROR] = "reg_error_unknown",
  [NEW_SRV_ERR_SIMPLE_REGISTERED] = "reg_error_simple_registered",
  [NEW_SRV_ERR_USERLIST_SERVER_DOWN] = "reg_error_userlist_server_down",
  [NEW_SRV_ERR_INV_SESSION] = "reg_error_inv_session",
  [NEW_SRV_ERR_INTERNAL] = "reg_error_internal",
  [NEW_SRV_ERR_INV_PARAM] = "reg_error_inv_param",
  [NEW_SRV_ERR_PERMISSION_DENIED] = "reg_error_no_perm",
};
static ExternalActionState *external_reg_action_states[NEW_SRV_ACTION_LAST];
static ExternalActionState *external_reg_error_states[NEW_SRV_ERR_LAST];

static void
error_page(
        FILE *out_f,
        struct http_request_info *phr,
        int error_code)
{
  const unsigned char * const * error_names = external_reg_error_names;
  ExternalActionState **error_states = external_reg_error_states;

  if (phr->json_reply) {
    struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
    fprintf(out_f, "{\n");
    fprintf(out_f, "  \"ok\": false");
    fprintf(out_f, ",\n  \"error\": {\n");
    fprintf(out_f, "    \"num\": %d", error_code);
    fprintf(out_f, ",\n    \"symbol\": \"%s\"", ns_error_symbol(error_code));
    const unsigned char *msg = ns_error_title_2(error_code);
    if (msg) {
      fprintf(out_f, ",\n    \"message\": \"%s\"", json_armor_buf(&ab, msg));
    }
    fprintf(out_f, "\n  }");
    fprintf(out_f, "\n}\n");
    html_armor_free(&ab);
    return;
  }

  if (phr->log_t && !*phr->log_t) {
    xfree(phr->log_t); phr->log_t = NULL; phr->log_z = 0;
  }

  if (error_code < 0) error_code = -error_code;
  if (error_code <= 0 || error_code >= NEW_SRV_ERR_LAST) error_code = NEW_SRV_ERR_UNKNOWN_ERROR;
  phr->error_code = error_code;

  const unsigned char *error_name = error_names[error_code];
  if (!error_name) error_name = error_names[NEW_SRV_ERR_UNKNOWN_ERROR];
  if (!error_name) {
    return ns_html_error(out_f, phr, 0, error_code);
  }
  error_states[error_code] = external_action_load(error_states[error_code],
                                                  "csp/contests",
                                                  error_name,
                                                  "csp_get_",
                                                  NULL /* fixed_src_dir */,
                                                  phr->current_time,
                                                  0 /* contest_id */,
                                                  0 /* allow_fail */);
  if (!error_states[error_code] || !error_states[error_code]->action_handler) {
    return ns_html_error(out_f, phr, 0, error_code);
  }
  PageInterface *pg = ((external_action_handler_t) error_states[error_code]->action_handler)();
  if (!pg) {
    return ns_html_error(out_f, phr, 0, error_code);
  }

  snprintf(phr->content_type, sizeof(phr->content_type), "text/html; charset=%s", EJUDGE_CHARSET);
  pg->ops->render(pg, NULL, out_f, phr);
  xfree(phr->log_t); phr->log_t = NULL;
  phr->log_z = 0;
}

static int
reg_external_action(
        FILE *out_f,
        struct http_request_info *phr,
        int action,
        ContestExternalActions *cnts_actions)
{
  if (action < 0) action = phr->action;
  if (external_reg_action_aliases[action] > 0) action = external_reg_action_aliases[action];

  ExternalActionState *action_state = NULL;
  if (external_reg_action_names[action]) {
    if (cnts_actions && cnts_actions->reg_actions && action >= 0 && action < cnts_actions->actions_size) {
      ExternalActionState *st = cnts_actions->reg_actions[action];
      const unsigned char *root_dir = NULL;
      if (phr->cnts) root_dir = phr->cnts->root_dir;
      if (st != EXTERNAL_ACTION_NONE) {
        st = external_action_load(st,
                                  "csp/contests",
                                  external_reg_action_names[action],
                                  "csp_get_",
                                  root_dir,
                                  phr->current_time,
                                  phr->contest_id,
                                  1 /* allow_fail */);
        if (!st) {
          cnts_actions->reg_actions[action] = EXTERNAL_ACTION_NONE;
        } else {
          cnts_actions->reg_actions[action] = st;
          action_state = st;
        }
      }
    }
    if (!action_state) {
      external_reg_action_states[action] = external_action_load(external_reg_action_states[action],
                                                                "csp/contests",
                                                                external_reg_action_names[action],
                                                                "csp_get_",
                                                                NULL /* fixed_src_dir */,
                                                                phr->current_time,
                                                                0 /* contest_id */,
                                                                0 /* allow_fail */);
      action_state = external_reg_action_states[action];
    }
  }

  if (action_state && action_state->action_handler) {
    PageInterface *pg = ((external_action_handler_t) action_state->action_handler)();

    if (pg->ops->execute) {
      int r = pg->ops->execute(pg, phr->log_f, phr);
      if (r < 0) {
        error_page(out_f, phr, -r);
        goto cleanup;
      }
    }

    if (pg->ops->render) {
      snprintf(phr->content_type, sizeof(phr->content_type), "text/html; charset=%s", EJUDGE_CHARSET);
      int r = pg->ops->render(pg, phr->log_f, out_f, phr);
      if (r < 0) {
        error_page(out_f, phr, -r);
        goto cleanup;
      }
    }

    if (pg->ops->destroy) {
      pg->ops->destroy(pg);
      pg = NULL;
    }

    goto cleanup;
  }

  return 0;

cleanup:
  return 1;
}

static void
reg_get_avatar(FILE *fout, struct http_request_info *phr)
{
  const unsigned char *key = NULL;
  int cookie_locale_id = 0;
  int is_team = 0;
  int cur_user_id = 0;
  struct avatar_info_vector avatars;

  avatar_vector_init(&avatars, 1);
  if (hr_cgi_param(phr, "key", &key) <= 0) {
    error_page(fout, phr, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }
  if (phr->session_id) {
    if (ns_open_ul_connection(phr->fw_state) >= 0) {
      if (userlist_clnt_get_cookie(ul_conn, ULS_GET_COOKIE,
                                   &phr->ip, phr->ssl_flag,
                                   phr->session_id,
                                   phr->client_key,
                                   &phr->user_id, &phr->contest_id,
                                   &cookie_locale_id, 0, &phr->role, &is_team,
                                   &phr->reg_status, &phr->reg_flags, &phr->passwd_method,
                                   NULL /* p_is_ws */,
                                   NULL /* p_is_job */,
                                   NULL /* p_expire */,
                                   &phr->login, &phr->name) >= 0) {
        // this is an authentificated user
        cur_user_id = phr->user_id;
        if (contests_get(phr->contest_id, &phr->cnts) < 0 || !phr->cnts) {
          fprintf(phr->log_f, "invalid contest_id %d", phr->contest_id);
          error_page(fout, phr, NEW_SRV_ERR_INV_PARAM);
          goto cleanup;
        }
        if (!(phr->extra = ns_get_contest_extra(phr->cnts, phr->config))) {
          fprintf(phr->log_f, "invalid contest_id %d", phr->contest_id);
          error_page(fout, phr, NEW_SRV_ERR_INV_PARAM);
          goto cleanup;
        }
      }
    }
  }

  if (!phr->extra) {
    if (contests_get(phr->contest_id, &phr->cnts) < 0 || !phr->cnts) {
      fprintf(phr->log_f, "invalid contest_id %d", phr->contest_id);
      error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }
    if (!(phr->extra = ns_get_contest_extra(phr->cnts, phr->config))) {
      fprintf(phr->log_f, "invalid contest_id %d", phr->contest_id);
      error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }
  }

  struct avatar_loaded_plugin *avt = avatar_plugin_get(phr->extra, phr->cnts, phr->config, NULL);
  if (!avt) {
    error_page(fout, phr, NEW_SRV_ERR_INV_PARAM);
    goto cleanup;
  }

  if (avt->iface->fetch_by_key(avt->data, key, 0, &avatars) < 0) {
    error_page(fout, phr, NEW_SRV_ERR_DATABASE_FAILED);
    goto cleanup;
  }
  if (avatars.u > 1) {
    err("AVATAR_INTERNAL: multiple avatars with random key %s!", key);
    error_page(fout, phr, NEW_SRV_ERR_INTERNAL);
    goto cleanup;
  }
  if (avatars.u < 1) {
    error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
    goto cleanup;
  }

  struct avatar_info *av = &avatars.v[0];
  if (!av->is_public) {
    if (!cur_user_id || cur_user_id != av->user_id) {
      error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
      goto cleanup;
    }
  }

  fprintf(fout, "Content-type: %s\n", mime_type_get_type(av->mime_type));
  fprintf(fout, "Content-Disposition: attachment; filename=\"%s%s\"\n", key, mime_type_get_suffix(av->mime_type));
  fprintf(fout, "\n");
  fwrite(av->img_data, 1, av->img_size, fout);

cleanup:;
  avatar_vector_free(&avatars);
}

extern const unsigned char login_accept_chars[257];
static int
check_login(const unsigned char *login_str)
{
  if (!login_str || !*login_str) return -1;
  return check_str(login_str, login_accept_chars);
}

struct RegLoginJsonResponse
{
  unsigned error_id;
  unsigned char log_msg[256];
  time_t expire;
};

static int
do_reg_login_json(FILE *fout, struct http_request_info *phr, struct RegLoginJsonResponse *resp)
{
  const unsigned char *login = NULL;
  if (hr_cgi_param(phr, "login", &login) <= 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "login is not specified");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (!login || !*login) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "login is empty");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (check_login(login) < 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "login is invalid");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  const unsigned char *password = NULL;
  if (hr_cgi_param(phr, "password", &password) <= 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "password is not specified");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (!password || !*password) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "password is empty");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (ns_open_ul_connection(phr->fw_state) < 0) {
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }

  int r = userlist_clnt_login(ul_conn, ULS_CHECK_USER_2,
                              &phr->ip,
                              0, /* cookie */
                              0ULL /* client_key */,
                              0, /* expire */
                              phr->ssl_flag,
                              0 /* contest_id */,
                              0 /* locale_id */,
                              0 /* pwd_special */,
                              0, /* is_ws */
                              0, /* is_job */
                              login, password,
                              &phr->user_id,
                              &phr->session_id,
                              &phr->client_key,
                              &phr->name,
                              &resp->expire,
                              &phr->priv_level,
                              &phr->reg_status,
                              &phr->reg_flags);
  if (r < 0) {
    r = -r;
    switch (r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "CHECK_USER_2 failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_PERMISSION_DENIED;
    case ULS_ERR_DISCONNECT:
      return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
    case ULS_ERR_SIMPLE_REGISTERED:
      return -NEW_SRV_ERR_SIMPLE_REGISTERED;
    default:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "CHECK_USER_2 failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_INTERNAL;
    }
  }

  phr->login = xstrdup(login);
  return 0;
}

static void
json_error(
        FILE *fout,
        struct http_request_info *phr,
        struct html_armor_buffer *pab,
        int num,
        const unsigned char *log_msg)
{
  if (num < 0) num = -num;
  random_init();
  unsigned error_id = random_u32();

  fprintf(fout, ",\n  \"error\": {\n");
  fprintf(fout, "    \"num\": %d", num);
  fprintf(fout, ",\n    \"symbol\": \"%s\"", ns_error_symbol(num));
  const unsigned char *msg = ns_error_title_2(num);
  if (msg) {
    fprintf(fout, ",\n    \"message\": \"%s\"", json_armor_buf(pab, msg));
  }
  if (error_id) {
    fprintf(fout, ",\n    \"log_id\": \"%08x\"", error_id);
  }
  fprintf(fout, "\n  }");
  if (!msg) msg = "unknown error";
  err("%d: %s: error_id = %08x: %s", phr->id, msg, error_id, log_msg);
}

static void
reg_login_json(FILE *fout, struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct RegLoginJsonResponse resp = {};

  int res = do_reg_login_json(fout, phr, &resp);

  phr->json_reply = 1;
  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\": %s", (res?"false":"true"));
  if (res) {
    json_error(fout, phr, &ab, res, resp.log_msg);
  } else {
    fprintf(fout, ",\n  \"result\": {");
    fprintf(fout, "\n    \"user_id\": %d", phr->user_id);
    fprintf(fout, ",\n    \"user_login\": \"%s\"", json_armor_buf(&ab, phr->login));
    if (phr->name && *phr->name) {
      fprintf(fout, ",\n    \"user_name\": \"%s\"", json_armor_buf(&ab, phr->name));
    }
    fprintf(fout, ",\n    \"session\": \"%016llx-%016llx\"", phr->session_id, phr->client_key);
    fprintf(fout, ",\n    \"SID\": \"%016llx\"", phr->session_id);
    fprintf(fout, ",\n    \"EJSID\": \"%016llx\"", phr->client_key);
    if (resp.expire > 0) {
      fprintf(fout, ",\n    \"expire\": %lld", (long long) resp.expire);
    }
    fprintf(fout, "\n  }");
  }
  fprintf(fout, "\n}\n");
  html_armor_free(&ab);
}

struct RegUserContestsJsonContest
{
  // owned somewhere else
  int id;
  const struct contest_desc *cnts;
  const struct userlist_contest *uc;
  const struct userlist_user_info *ui;
};

struct RegUserContestsJson
{
  unsigned char log_msg[256];
  struct userlist_user *u;

  int r_a, r_u;
  struct RegUserContestsJsonContest *r_p;
};

static int
do_reg_user_contests_json(FILE *fout, struct http_request_info *phr, struct RegUserContestsJson *resp)
{
  // session_id, client_key as params
  if (hr_cgi_param_h64(phr, "SID", &phr->session_id) < 0 || !phr->session_id) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "session_id is invalid");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (hr_cgi_param_h64(phr, "EJSID", &phr->client_key) < 0 || !phr->client_key) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "client_key is invalid");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  // filtering options

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }
  int priv_level = 0;
  int is_team = 0;
  int r = userlist_clnt_get_cookie(ul_conn,
                                   ULS_GET_COOKIE,
                                   &phr->ip,
                                   phr->ssl_flag,
                                   phr->session_id,
                                   phr->client_key,
                                   &phr->user_id,
                                   &phr->contest_id,
                                   NULL /* p_locale_id */,
                                   &priv_level,
                                   &phr->role,
                                   &is_team,
                                   NULL /* p_reg_status */,
                                   NULL /* p_reg_flags */,
                                   NULL /* p_passwd_method */,
                                   NULL /* p_is_ws */,
                                   NULL /* p_is_job */,
                                   NULL /* p_expire */,
                                   &phr->login,
                                   &phr->name);
  if (r < 0) {
    r = -r;
    switch (r) {
    case ULS_ERR_NO_COOKIE:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NOT_REGISTERED:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "GET_COOKIE failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_INV_SESSION;
    case ULS_ERR_DISCONNECT:
      return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
    default:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "GET_COOKIE failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_INTERNAL;
    }
  }
  if (phr->contest_id > 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "cookie is bound to contest %d", phr->contest_id);
    return -NEW_SRV_ERR_INV_SESSION;
  }
  if (priv_level > 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "cookie has privilege level %d", priv_level);
    return -NEW_SRV_ERR_INV_SESSION;
  }
  if (is_team) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "cookie is participation-bound");
    return -NEW_SRV_ERR_INV_SESSION;
  }
  unsigned char *xml_text = NULL;
  r = userlist_clnt_get_info(ul_conn, ULS_PRIV_GET_USER_INFO,
                             phr->user_id, 0, &xml_text);
  if (r < 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "PRIV_GET_USER_INFO failed: %s", userlist_strerror(-r));
    return -NEW_SRV_ERR_DATABASE_FAILED;
  }
  resp->u = userlist_parse_user_str(xml_text);
  if (!resp->u) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "XML parse error");
    xfree(xml_text);
    return -NEW_SRV_ERR_DATABASE_FAILED;
  }
  xfree(xml_text);

  const int *contest_ids = NULL;
  int contest_count = contests_get_list(&contest_ids);
  if (contest_count <= 0 || !contest_ids) return 0;

  for (int i = 0; i < contest_count; ++i) {
    int cnts_id = contest_ids[i];
    const struct contest_desc *cnts = NULL;
    if (contests_get(cnts_id, &cnts) < 0 || !cnts) continue;

    const struct userlist_contest *uc = userlist_get_user_contest(resp->u, cnts_id);
    if (!uc) continue;
    const struct userlist_user_info *ui = userlist_get_user_info(resp->u, cnts_id);

    // FIXME: implement filtering

    if (uc->status != USERLIST_REG_OK) continue;
    if ((uc->flags & (USERLIST_UC_BANNED | USERLIST_UC_LOCKED | USERLIST_UC_DISQUALIFIED)) != 0) continue;
    if ((uc->flags & (USERLIST_UC_INCOMPLETE | USERLIST_UC_PRIVILEGED)) == USERLIST_UC_INCOMPLETE) continue;

    if (!cnts->disable_team_password) continue;
    if (cnts->closed) continue;
    if (cnts->open_time > 0 && phr->current_time < cnts->open_time) continue;
    if (cnts->close_time > 0 && phr->current_time >= cnts->close_time) continue;
    if (!contests_check_team_ip_2(cnts, &phr->ip, phr->ssl_flag)) continue;

    if (resp->r_u == resp->r_a) {
      if (!(resp->r_a *= 2)) resp->r_a = 16;
      XREALLOC(resp->r_p, resp->r_a);
    }
    struct RegUserContestsJsonContest *cur = &resp->r_p[resp->r_u++];
    memset(cur, 0, sizeof(*cur));
    cur->id = cnts_id;
    cur->cnts = cnts;
    cur->uc = uc;
    cur->ui = ui;
  }

  return 0;
}

static void
reg_user_contests_json(FILE *fout, struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct RegUserContestsJson resp = {};

  int res = do_reg_user_contests_json(fout, phr, &resp);
  phr->json_reply = 1;
  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\": %s", (res?"false":"true"));
  if (res) {
    json_error(fout, phr, &ab, res, resp.log_msg);
  } else {
    fprintf(fout, ",\n  \"result\": {");
    if (resp.r_u > 0) {
      fprintf(fout, "\n    \"contests\": [\n");
      for (int i = 0; i < resp.r_u; ++i) {
        struct RegUserContestsJsonContest *cur = &resp.r_p[i];
        if (i > 0) {
          fprintf(fout, ",\n");
        }
        fprintf(fout, "      {\n");
        fprintf(fout, "        \"id\": %d,\n", cur->id);
        fprintf(fout, "        \"name\": \"%s\"\n", json_armor_buf(&ab, cur->cnts->name));
        fprintf(fout, "      }");
      }
      fprintf(fout, "\n    ]");
      fprintf(fout, "\n  }");
    }
  }
  fprintf(fout, "\n}\n");
  html_armor_free(&ab);
  if (resp.u) {
    userlist_free(&resp.u->b);
  }
  if (resp.r_p) {
    free(resp.r_p);
  }
}

struct RegEnterContestJson
{
  unsigned char log_msg[256];
  struct userlist_user *u;
  const struct userlist_contest *uc;
  const struct userlist_user_info *ui;
  int contest_id;
  ej_cookie_t session_id;
  ej_cookie_t client_key;
  time_t expire;
};

static int
do_reg_enter_contest_json(FILE *fout, struct http_request_info *phr, struct RegEnterContestJson *resp)
{
  // session_id, client_key as params
  if (hr_cgi_param_h64(phr, "SID", &phr->session_id) < 0 || !phr->session_id) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "session_id is invalid");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (hr_cgi_param_h64(phr, "EJSID", &phr->client_key) < 0 || !phr->client_key) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "client_key is invalid");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  int contest_id = 0;
  if (hr_cgi_param_int(phr, "contest_id", &contest_id) < 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "contest_id is invalid");
    return -NEW_SRV_ERR_INV_CONTEST_ID;
  }
  if (contest_id <= 0 || contests_get(contest_id, &phr->cnts) < 0 || !phr->cnts){
    snprintf(resp->log_msg, sizeof(resp->log_msg), "contest_id is invalid");
    return -NEW_SRV_ERR_INV_CONTEST_ID;
  }

  // filtering options

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }
  int priv_level = 0;
  int is_team = 0;
  int r = userlist_clnt_get_cookie(ul_conn,
                                   ULS_GET_COOKIE,
                                   &phr->ip,
                                   phr->ssl_flag,
                                   phr->session_id,
                                   phr->client_key,
                                   &phr->user_id,
                                   &phr->contest_id,
                                   NULL /* p_locale_id */,
                                   &priv_level,
                                   &phr->role,
                                   &is_team,
                                   NULL /* p_reg_status */,
                                   NULL /* p_reg_flags */,
                                   NULL /* p_passwd_method */,
                                   NULL /* p_is_ws */,
                                   NULL /* p_is_job */,
                                   NULL /* p_expire */,
                                   &phr->login,
                                   &phr->name);
  if (r < 0) {
    r = -r;
    switch (r) {
    case ULS_ERR_NO_COOKIE:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NOT_REGISTERED:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "GET_COOKIE failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_INV_SESSION;
    case ULS_ERR_DISCONNECT:
      return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
    default:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "GET_COOKIE failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_INTERNAL;
    }
  }
  if (phr->contest_id > 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "cookie is bound to contest %d", phr->contest_id);
    return -NEW_SRV_ERR_INV_SESSION;
  }
  if (priv_level > 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "cookie has privilege level %d", priv_level);
    return -NEW_SRV_ERR_INV_SESSION;
  }
  if (is_team) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "cookie is participation-bound");
    return -NEW_SRV_ERR_INV_SESSION;
  }

  if (!phr->cnts->disable_team_password) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "contest %d is contest-password-enabled", contest_id);
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (phr->cnts->closed) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "contest %d is closed", contest_id);
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (phr->cnts->open_time > 0 && phr->current_time < phr->cnts->open_time){
    snprintf(resp->log_msg, sizeof(resp->log_msg), "contest %d is not opened", contest_id);
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  // FIXME: handle close time
  if (!contests_check_team_ip_2(phr->cnts, &phr->ip, phr->ssl_flag)) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "contest %d IP is not allowed", contest_id);
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  unsigned char *xml_text = NULL;
  r = userlist_clnt_get_info(ul_conn, ULS_PRIV_GET_USER_INFO, phr->user_id, contest_id, &xml_text);
  if (r < 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "PRIV_GET_USER_INFO failed: %s", userlist_strerror(-r));
    return -NEW_SRV_ERR_DATABASE_FAILED;
  }
  resp->u = userlist_parse_user_str(xml_text);
  if (!resp->u) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "XML parse error");
    xfree(xml_text);
    return -NEW_SRV_ERR_DATABASE_FAILED;
  }
  xfree(xml_text);

  resp->uc = userlist_get_user_contest(resp->u, contest_id);
  resp->ui = userlist_get_user_info(resp->u, contest_id);
  if (!resp->uc) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "user is not registered");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if (resp->uc->status != USERLIST_REG_OK) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "user registration status is not OK");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if ((resp->uc->flags & USERLIST_UC_BANNED)) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "user is BANNED");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if ((resp->uc->flags & USERLIST_UC_DISQUALIFIED)) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "user is DISQUALIFIED");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if ((resp->uc->flags & USERLIST_UC_LOCKED)) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "user is LOCKED");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }
  if ((resp->uc->flags & (USERLIST_UC_INCOMPLETE | USERLIST_UC_PRIVILEGED)) == USERLIST_UC_INCOMPLETE) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "user registration is INCOMPLETE");
    return -NEW_SRV_ERR_PERMISSION_DENIED;
  }

  struct userlist_cookie in_c;
  struct userlist_cookie out_c;

  memset(&in_c, 0, sizeof(in_c));
  memcpy(&in_c.ip, &phr->ip, sizeof(in_c.ip));
  in_c.ssl = phr->ssl_flag;
  in_c.user_id = phr->user_id;
  in_c.contest_id = contest_id;
  in_c.locale_id = 0;
  in_c.priv_level = 0;
  in_c.role = USER_ROLE_CONTESTANT;
  in_c.recovery = 0;
  in_c.team_login = 0;

  r = userlist_clnt_create_cookie(ul_conn, ULS_CREATE_COOKIE, &in_c, &out_c);
  if (r < 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "CREATE_COOKIE failed: %s", userlist_strerror(-r));
    return -NEW_SRV_ERR_DATABASE_FAILED;
  }

  resp->contest_id = contest_id;
  resp->session_id = out_c.cookie;
  resp->client_key = out_c.client_key;
  resp->expire = out_c.expire;

  return 0;
}

static void
unparse_userlist_contest_json(
        FILE *fout,
        struct html_armor_buffer *pab,
        const struct userlist_contest *uc,
        const unsigned char *name,
        const unsigned char *prefix,
        const unsigned char *postfix,
        const unsigned char *indent)
{
  if (!uc) return;
  if (!prefix) prefix = "";
  if (!indent) indent = "";
  if (!postfix) postfix = "";
  fprintf(fout, "%s%s\"%s\": {\n", prefix, indent, name);
  fprintf(fout, "%s  \"status\": \"%s\"",
          indent, userlist_unparse_reg_status(uc->status));
  if ((uc->flags & USERLIST_UC_INVISIBLE)) {
    fprintf(fout, ",\n%s  \"invisible\" : true", indent);
  }
  if ((uc->flags & USERLIST_UC_BANNED)) {
    fprintf(fout, ",\n%s  \"banned\" : true", indent);
  }
  if ((uc->flags & USERLIST_UC_LOCKED)) {
    fprintf(fout, ",\n%s  \"locked\" : true", indent);
  }
  if ((uc->flags & USERLIST_UC_INCOMPLETE)) {
    fprintf(fout, ",\n%s  \"incomplete\" : true", indent);
  }
  if ((uc->flags & USERLIST_UC_DISQUALIFIED)) {
    fprintf(fout, ",\n%s  \"disqualified\" : true", indent);
  }
  if ((uc->flags & USERLIST_UC_PRIVILEGED)) {
    fprintf(fout, ",\n%s  \"privileged\" : true", indent);
  }
  if ((uc->flags & USERLIST_UC_REG_READONLY)) {
    fprintf(fout, ",\n%s  \"reg_readonly\" : true", indent);
  }
  fprintf(fout, "\n%s}%s", indent, postfix);
}

static void
reg_enter_contest_json(FILE *fout, struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct RegEnterContestJson resp = {};
  int res = do_reg_enter_contest_json(fout, phr, &resp);
  phr->json_reply = 1;
  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\": %s", (res?"false":"true"));
  if (res) {
    json_error(fout, phr, &ab, res, resp.log_msg);
  } else {
    fprintf(fout, ",\n  \"result\": {");
    fprintf(fout, "\n    \"session\": \"%016llx-%016llx\"", resp.session_id, resp.client_key);
    fprintf(fout, ",\n    \"SID\": \"%016llx\"", resp.session_id);
    fprintf(fout, ",\n    \"EJSID\": \"%016llx\"", resp.client_key);
    if (resp.contest_id > 0) {
      fprintf(fout, ",\n    \"contest_id\": %d", resp.contest_id);
    }
    if (resp.expire > 0) {
      fprintf(fout, ",\n    \"expire\": %lld", (long long) resp.expire);
    }
    fprintf(fout, ",\n    \"user_id\": %d", resp.u->id);
    fprintf(fout, ",\n    \"user_login\": \"%s\"", json_armor_buf(&ab, resp.u->login));
    const unsigned char *name = resp.u->login;
    if (resp.ui && resp.ui->name) {
      name = resp.ui->name;
    }
    fprintf(fout, ",\n    \"user_name\": \"%s\"", json_armor_buf(&ab, name));
    unparse_userlist_contest_json(fout, &ab, resp.uc,
                                  "cntsreg",
                                  ",\n",
                                  "",
                                  "    ");
    fprintf(fout, "\n  }");
  }
  fprintf(fout, "\n}\n");
  html_armor_free(&ab);
  if (resp.u) {
    userlist_free(&resp.u->b);
  }
}

struct RegPingJson
{
  unsigned char log_msg[256];
  time_t expire;
};

static int
do_reg_ping_json(FILE *fout, struct http_request_info *phr, struct RegPingJson *resp)
{
  // session_id, client_key as params
  if (hr_cgi_param_h64(phr, "SID", &phr->session_id) < 0 || !phr->session_id) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "session_id is invalid");
    return -NEW_SRV_ERR_INV_PARAM;
  }
  if (hr_cgi_param_h64(phr, "EJSID", &phr->client_key) < 0 || !phr->client_key) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "client_key is invalid");
    return -NEW_SRV_ERR_INV_PARAM;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
  }
  int priv_level = 0;
  int is_team = 0;
  int r = userlist_clnt_get_cookie(ul_conn,
                                   ULS_GET_COOKIE,
                                   &phr->ip,
                                   phr->ssl_flag,
                                   phr->session_id,
                                   phr->client_key,
                                   &phr->user_id,
                                   &phr->contest_id,
                                   NULL /* p_locale_id */,
                                   &priv_level,
                                   &phr->role,
                                   &is_team,
                                   NULL /* p_reg_status */,
                                   NULL /* p_reg_flags */,
                                   NULL /* p_passwd_method */,
                                   NULL /* p_is_ws */,
                                   NULL /* p_is_job */,
                                   NULL /* p_expire */,
                                   &phr->login,
                                   &phr->name);
  if (r < 0) {
    r = -r;
    switch (r) {
    case ULS_ERR_NO_COOKIE:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NOT_REGISTERED:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "GET_COOKIE failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_INV_SESSION;
    case ULS_ERR_DISCONNECT:
      return -NEW_SRV_ERR_USERLIST_SERVER_DOWN;
    default:
      snprintf(resp->log_msg, sizeof(resp->log_msg), "GET_COOKIE failed: %s", userlist_strerror(r));
      return -NEW_SRV_ERR_INTERNAL;
    }
  }
  if (phr->contest_id > 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "cookie is bound to contest %d", phr->contest_id);
    return -NEW_SRV_ERR_INV_SESSION;
  }
  if (priv_level > 0) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "cookie has privilege level %d", priv_level);
    return -NEW_SRV_ERR_INV_SESSION;
  }
  if (is_team) {
    snprintf(resp->log_msg, sizeof(resp->log_msg), "cookie is participation-bound");
    return -NEW_SRV_ERR_INV_SESSION;
  }

  return 0;
}

static void
reg_ping_json(FILE *fout, struct http_request_info *phr)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct RegPingJson resp = {};
  int res = do_reg_ping_json(fout, phr, &resp);
  phr->json_reply = 1;
  fprintf(fout, "{\n");
  fprintf(fout, "  \"ok\": %s", (res?"false":"true"));
  if (res) {
    json_error(fout, phr, &ab, res, resp.log_msg);
  } else {
    fprintf(fout, ",\n  \"result\": {");
    if (resp.expire > 0) {
      fprintf(fout, "\n    \"expire\": %lld", (long long) resp.expire);
    }
    fprintf(fout, "\n  }");
  }
  fprintf(fout, "\n}\n");
  html_armor_free(&ab);
}

#define FIRST_CONTEST(u) ((struct userlist_contest*)(u)->contests->first_down)
#define NEXT_CONTEST(c)  ((struct userlist_contest*)(c)->b.right)

static void
reg_telegram_register(FILE *fout, struct http_request_info *phr)
{
  const unsigned char *reg_key = NULL;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct av_telegram_registration treg = {};
  struct av_telegram_chat tchat = {};
  unsigned char login_str[64];
  unsigned char password_str[64];
  unsigned char *xml_text = NULL;
  struct userlist_user *u = NULL;
  unsigned char error_message[1024];

  error_message[0] = 0;
  if (phr->config->enable_telegram_registration <= 0) {
    err("%s: not enabled globally", __FUNCTION__);
    goto fail;
  }

  int r = hr_cgi_param(phr, "key", &reg_key);
  if (r < 0) {
    err("%s: key param is binary", __FUNCTION__);
    goto fail;
  }
  if (!r) {
    err("%s: key param is undefined", __FUNCTION__);
    goto fail;
  }

  const struct contest_desc *cnts = NULL;
  if (contests_get(phr->contest_id, &cnts) < 0 || !cnts) {
    err("%s: contest %d is invalid", __FUNCTION__, phr->contest_id);
    goto fail;
  }
  if (cnts->enable_telegram_registration <= 0) {
    err("%s: not enabled for contest %d", __FUNCTION__, phr->contest_id);
    goto fail;
  }
  if (cnts->closed > 0) {
    err("%s: contest %d closed", __FUNCTION__, phr->contest_id);
    goto fail;
  }

  struct contest_extra *extra = ns_get_contest_extra(cnts, phr->config);

  // TODO: we need a separate plugin here, obviously
  struct avatar_loaded_plugin *avt = avatar_plugin_get(extra, cnts, phr->config, NULL);
  if (!avt) {
    err("%s: failed to load avatar plugin", __FUNCTION__);
    goto fail;
  }

  if (!avt->iface->get_telegram_registration
      || !avt->iface->get_telegram_chat) {
    err("%s: telegram registration not supported by plugin", __FUNCTION__);
    goto fail;
  }

  r = avt->iface->get_telegram_registration(avt->data, reg_key, &treg);
  if (r < 0) {
    err("%s: failed to get telegram registration", __FUNCTION__);
    goto fail;
  }
  if (!r) {
    err("%s: telegram registration '%s' does not exist", __FUNCTION__, reg_key);
    goto fail;
  }
  if (treg.contest_id != phr->contest_id) {
    err("%s: contest_id mismatch: %d, %d", __FUNCTION__,
        phr->contest_id, treg.contest_id);
    goto fail;
  }

  long long current_time_us;
  long long current_time;
  {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    current_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;
    current_time = tv.tv_sec;
  }
  long long create_time_us = treg.create_time.tv_sec * 1000000LL + treg.create_time.tv_usec;
  if (create_time_us + 5 * 60 * 1000000LL < current_time_us) {
    err("%s: key '%s' is expired", __FUNCTION__, reg_key);
    goto fail;
  }
  if (cnts->reg_deadline > 0 && current_time >= cnts->reg_deadline) {
    err("%s: registration deadline exceeded", __FUNCTION__);
    goto fail;
  }

  r = avt->iface->get_telegram_chat(avt->data, treg.chat_id, &tchat);
  if (r < 0) {
    err("%s: failed to get telegram chat", __FUNCTION__);
    goto fail;
  }
  if (!r) {
    err("%s: telegram chat %lld does not exist", __FUNCTION__, treg.chat_id);
    goto fail;
  }
  if (!tchat.type || strcmp(tchat.type, "private") != 0) {
    err("%s: invalid type for telegram chat %lld", __FUNCTION__, treg.chat_id);
    goto fail;
  }

  r = snprintf(login_str, sizeof(login_str), "u%lld@tl", treg.chat_id);
  if (r >= (int) sizeof(login_str)) {
    err("%s: login u%lld@tl is too long", __FUNCTION__, treg.chat_id);
    goto fail;
  }

  if (ns_open_ul_connection(phr->fw_state) < 0) {
    err("%s: failed to open userlist connection", __FUNCTION__);
    goto fail;
  }

  int user_id = 0;
  password_str[0] = 0;
  r = userlist_clnt_lookup_user(ul_conn, login_str, 0, &user_id, NULL);
  if (r < 0) {
    if (r != -ULS_ERR_INVALID_LOGIN) {
      err("%s: lookup user '%s' failed %d", __FUNCTION__, login_str, r);
      goto fail;
    }

    unsigned char rbuf[16];
    random_init();
    random_bytes(rbuf, sizeof(rbuf));
    int len = base64u_encode(rbuf, sizeof(rbuf), password_str);
    password_str[len] = 0;

    struct userlist_pk_create_user_2 up = {};
    up.confirm_email_flag = 1;
    up.use_sha1_flag = 1;

    r = userlist_clnt_create_user_2(ul_conn, ULS_CREATE_USER_2, &up,
                                    login_str, login_str,
                                    password_str, password_str, "",
                                    &user_id);
    if (r < 0) {
      err("%s: create_user failed: %d", __FUNCTION__, r);
      goto fail;
    }
  }
  if (user_id <= 0) {
    err("%s: user_id is invalid: %d", __FUNCTION__, user_id);
    goto fail;
  }
  r = userlist_clnt_get_info(ul_conn, ULS_PRIV_GET_USER_INFO,
                             user_id, 0, &xml_text);
  if (r < 0) {
    err("%s: get_info failed: %d", __FUNCTION__, r);
    goto fail;
  }
  u = userlist_parse_user_str(xml_text);
  if (!u) {
    err("%s: failed to parse get_info XML", __FUNCTION__);
    goto fail;
  }
  free(xml_text); xml_text = NULL;

  if (!u->login || !u->email
      || u->is_privileged > 0 || u->is_invisible > 0
      || u->is_banned > 0 || u->is_locked > 0
      || u->read_only > 0 || u->simple_registration > 0) {
    err("%s: operation is not available for user '%s' and contest %d",
        __FUNCTION__, login_str, phr->contest_id);
    snprintf(error_message, sizeof(error_message),
             "Operation is not available for this user '%s'.",
             login_str);
    goto done;
  }
  userlist_free(&u->b); u = NULL;

  r = userlist_clnt_register_contest(ul_conn,
                                     ULS_PRIV_REGISTER_CONTEST,
                                     user_id,
                                     phr->contest_id,
                                     &phr->ip,
                                     phr->ssl_flag);
  if (r < 0) {
    err("%s: registration failed for user '%s' and contest %d: %d",
        __FUNCTION__, login_str, phr->contest_id, r);
    snprintf(error_message, sizeof(error_message),
             "Registration failed for this user '%s' and contest %d.",
             login_str, phr->contest_id);
    goto done;
  }

  r = userlist_clnt_get_info(ul_conn, ULS_PRIV_GET_USER_INFO,
                             user_id, phr->contest_id, &xml_text);
  if (r < 0) {
    err("%s: get_info failed: %d", __FUNCTION__, r);
    goto fail;
  }
  u = userlist_parse_user_str(xml_text);
  if (!u) {
    err("%s: failed to parse get_info XML", __FUNCTION__);
    goto fail;
  }
  free(xml_text); xml_text = NULL;

  __attribute__((unused)) const struct userlist_user_info *ui = u->cnts0;
  const struct userlist_contest *reg = NULL;
  for (struct userlist_contest *rr = FIRST_CONTEST(u); rr; reg = NEXT_CONTEST(reg)) {
    if (rr->id == phr->contest_id) {
      reg = rr;
      break;
    }
  }
  if (!reg) {
    err("%s: registration failed for user '%s' and contest %d: reg == NULL",
        __FUNCTION__, login_str, phr->contest_id);
    snprintf(error_message, sizeof(error_message),
             "Registration failed for this user '%s' and contest %d.",
             login_str, phr->contest_id);
    goto done;
  }
  if (reg->status == USERLIST_REG_REJECTED) {
    snprintf(error_message, sizeof(error_message),
             "Registration for this user '%s' and contest %d rejected.",
             login_str, phr->contest_id);
    goto done;
  }
  if ((reg->flags & USERLIST_UC_LOCKED)) {
    snprintf(error_message, sizeof(error_message),
             "This user '%s' is locked in contest %d.",
             login_str, phr->contest_id);
    goto done;
  }
  if ((reg->flags & USERLIST_UC_BANNED)) {
    snprintf(error_message, sizeof(error_message),
             "This user '%s' is banned in contest %d.",
             login_str, phr->contest_id);
    goto done;
  }
  if ((reg->flags & USERLIST_UC_DISQUALIFIED)) {
    snprintf(error_message, sizeof(error_message),
             "This user '%s' is disqualified in contest %d.",
             login_str, phr->contest_id);
    goto done;
  }

  if (!ui || !ui->name) {
    if (tchat.username || tchat.first_name || tchat.last_name) {
      char *name_s = NULL;
      size_t name_z = 0;
      FILE *name_f = open_memstream(&name_s, &name_z);
      if (tchat.username) {
        fprintf(name_f, "%s", tchat.username);
      }
      if (tchat.first_name || tchat.last_name) {
        fprintf(name_f, " (");
        if (tchat.first_name) {
          fprintf(name_f, "%s", tchat.first_name);
        }
        if (tchat.last_name) {
          fprintf(name_f, " %s", tchat.last_name);
        }
        fprintf(name_f, ")");
      }
      fclose(name_f); name_f = NULL;
      userlist_clnt_edit_field(ul_conn, ULS_EDIT_FIELD,
                               user_id, phr->contest_id, 0,
                               USERLIST_NC_NAME, name_s);
      free(name_s);
    }
  }

  if (!password_str[0]) {
    snprintf(error_message, sizeof(error_message),
             "This user '%s' already exists and registered to contest %d.",
             login_str, phr->contest_id);
    goto done;
  }

done:;
  if (error_message[0]) {
    login_str[0] = 0;
    password_str[0] = 0;
  }
  serve_telegram_registered(phr->config, cnts, treg.chat_id,
                            login_str, password_str, error_message);

  phr->json_reply = 1;
  fprintf(fout, "{ \"ok\": true }");
  goto cleanup;

fail:;
  ns_refresh_page(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, 0);

cleanup:;
  html_armor_free(&ab);
  free(treg.key);
  free(tchat.type);
  free(tchat.title);
  free(tchat.username);
  free(tchat.first_name);
  free(tchat.last_name);
  free(xml_text);
  if (u) {
    userlist_free(&u->b);
  }
}

void
ns_register_pages(FILE *fout, struct http_request_info *phr)
{
  int is_team = 0, r;
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = 0;
  unsigned char *user_info_xml = 0;
  unsigned char hid_buf[1024];
  int cookie_locale_id = -1;

  phr->log_f = open_memstream(&phr->log_t, &phr->log_z);

  if (phr->action == NEW_SRV_ACTION_CHANGE_LANGUAGE)
    return change_locale(fout, phr);

  if (phr->action == NEW_SRV_ACTION_GET_AVATAR) {
    return reg_get_avatar(fout, phr);
  }
  if (phr->action == NEW_SRV_ACTION_LOGIN_JSON) {
    return reg_login_json(fout, phr);
  }
  if (phr->action == NEW_SRV_ACTION_USER_CONTESTS_JSON) {
    return reg_user_contests_json(fout, phr);
  }
  if (phr->action == NEW_SRV_ACTION_ENTER_CONTEST_JSON) {
    return reg_enter_contest_json(fout, phr);
  }
  if (phr->action == NEW_SRV_ACTION_PING) {
    return reg_ping_json(fout, phr);
  }
  if (phr->action == NEW_SRV_ACTION_TELEGRAM_REGISTER) {
    return reg_telegram_register(fout, phr);
  }

  if (!phr->session_id) return anon_register_pages(fout, phr);

  snprintf(hid_buf, sizeof(hid_buf),
           "<input type=\"hidden\" name=\"SID\" value=\"%016llx\"/>",
           phr->session_id);
  phr->hidden_vars = hid_buf;

  if (ns_open_ul_connection(phr->fw_state) < 0)
    return error_page(fout, phr, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
  if ((r = userlist_clnt_get_cookie(ul_conn, ULS_GET_COOKIE,
                                    &phr->ip, phr->ssl_flag,
                                    phr->session_id,
                                    phr->client_key,
                                    &phr->user_id, &phr->contest_id,
                                    &cookie_locale_id, 0, &phr->role, &is_team,
                                    &phr->reg_status, &phr->reg_flags, &phr->passwd_method,
                                    NULL /* p_is_ws */,
                                    NULL /* p_is_job */,
                                    NULL /* p_expire */,
                                    &phr->login, &phr->name)) < 0) {
    if (phr->locale_id < 0 && cookie_locale_id >= 0) phr->locale_id = cookie_locale_id;
    if (phr->locale_id < 0) phr->locale_id = 0;
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
    case ULS_ERR_CANNOT_PARTICIPATE:
    case ULS_ERR_NOT_REGISTERED:
      return error_page(fout, phr, NEW_SRV_ERR_INV_SESSION);
    case ULS_ERR_DISCONNECT:
      return error_page(fout, phr, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    default:
      fprintf(phr->log_f, "get_cookie failed: %s", userlist_strerror(-r));
      return error_page(fout, phr, NEW_SRV_ERR_INTERNAL);
    }
  }
  if (phr->locale_id < 0 && cookie_locale_id >= 0) phr->locale_id = cookie_locale_id;
  if (phr->locale_id < 0) phr->locale_id = 0;

  // allow logout
  if (phr->contest_id <= 0 && phr->action == NEW_SRV_ACTION_LOGOUT) {
    return logout(fout, phr, NULL, NULL, time(NULL));
  }

  if (phr->role > 0) {
    fprintf(phr->log_f, "role %d > 0", phr->role);
    return error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
  }
  if (contests_get(phr->contest_id, &cnts) < 0 || !cnts) {
    fprintf(phr->log_f, "invalid contest_id %d", phr->contest_id);
    return error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
  }
  phr->cnts = cnts;
  if (!cnts->disable_team_password && is_team) {
    fprintf(phr->log_f, "participation cookie");
    return error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
  }

  // check permissions
  if (cnts->closed || !contests_check_register_ip_2(cnts, &phr->ip, phr->ssl_flag)) {
    fprintf(phr->log_f, "registration is not available");
    return error_page(fout, phr, NEW_SRV_ERR_PERMISSION_DENIED);
  }

  if (!phr->user_info) {
    if (userlist_clnt_get_info(ul_conn, ULS_PRIV_GET_USER_INFO,
                               phr->user_id, phr->contest_id,
                               &user_info_xml) < 0) {
      // FIXME: need better error reporting
      return error_page(fout, phr, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    }
    phr->user_info = userlist_parse_user_str(user_info_xml);
    if (!phr->user_info) {
      // FIXME: need better error reporting
      return error_page(fout, phr, NEW_SRV_ERR_USERLIST_SERVER_DOWN);
    }
    xfree(user_info_xml); user_info_xml = 0;
  }

  cur_time = time(0);

  extra = ns_get_contest_extra(cnts, phr->config);
  phr->extra = extra;
  watched_file_update(&extra->copyright, cnts->copyright_file, cur_time);
  extra->separator_txt = "";
  extra->copyright_txt = extra->copyright.text;
  if (!extra->header_txt || !extra->footer_txt) {
    extra->header_txt = ns_fancy_header;
    extra->separator_txt = ns_fancy_separator;
    if (extra->copyright_txt) extra->footer_txt = ns_fancy_footer_2;
    else extra->footer_txt = ns_fancy_footer;
  }

  if (extra->contest_arm) xfree(extra->contest_arm);
  if (phr->locale_id == 0 && cnts->name_en) {
    extra->contest_arm = html_armor_string_dup(cnts->name_en);
  } else {
    extra->contest_arm = html_armor_string_dup(cnts->name);
  }

  if (phr->action <= 0 || phr->action >= NEW_SRV_ACTION_LAST) phr->action = NEW_SRV_ACTION_MAIN_PAGE;
  if (reg_external_action(fout, phr, -1, extra->cnts_actions) > 0) return;

  if (reg_handlers[phr->action])
    return (*reg_handlers[phr->action])(fout, phr, cnts, extra, cur_time);

  if (reg_external_action(fout, phr, NEW_SRV_ACTION_MAIN_PAGE, extra->cnts_actions) > 0) return;
  error_page(fout, phr, NEW_SRV_ERR_INV_ACTION);
  //return main_page(fout, phr, cnts, extra, cur_time);
}
