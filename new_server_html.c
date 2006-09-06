/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "settings.h"
#include "ej_types.h"
#include "ej_limits.h"

#include "new-server.h"
#include "pathutl.h"
#include "xml_utils.h"
#include "misctext.h"
#include "copyright.h"
#include "userlist_clnt.h"
#include "ejudge_cfg.h"
#include "errlog.h"
#include "userlist_proto.h"
#include "contests.h"
#include "nsdb_plugin.h"
#include "l10n.h"
#include "fileutl.h"
#include "userlist.h"
#include "mischtml.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

enum
{
  NEW_SRV_ACTION_LOGIN_PAGE = 1,
  NEW_SRV_ACTION_MAIN_PAGE,
  NEW_SRV_ACTION_VIEW_USERS,
  NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS,
  NEW_SRV_ACTION_USERS_SET_PENDING,
  NEW_SRV_ACTION_USERS_SET_OK,
  NEW_SRV_ACTION_USERS_SET_REJECTED,
  NEW_SRV_ACTION_USERS_SET_INVISIBLE,
  NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE,
  NEW_SRV_ACTION_USERS_SET_BANNED,
  NEW_SRV_ACTION_USERS_CLEAR_BANNED,
  NEW_SRV_ACTION_USERS_SET_LOCKED,
  NEW_SRV_ACTION_USERS_CLEAR_LOCKED,
  NEW_SRV_ACTION_USERS_ADD_BY_LOGIN,
  NEW_SRV_ACTION_USERS_ADD_BY_USER_ID,
  NEW_SRV_ACTION_PRIV_USERS_VIEW,
  NEW_SRV_ACTION_PRIV_USERS_REMOVE,
  NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER,
  NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER,
  NEW_SRV_ACTION_PRIV_USERS_ADD_JUDGE,
  NEW_SRV_ACTION_PRIV_USERS_DEL_JUDGE,
  NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_JUDGE,
  NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_JUDGE,
  NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR,
  NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR,
  NEW_SRV_ACTION_PRIV_USERS_ADD_BY_LOGIN,
  NEW_SRV_ACTION_PRIV_USERS_ADD_BY_USER_ID,

  NEW_SRV_ACTION_LAST,
};

struct watched_file
{
  unsigned char *path;
  time_t last_check;
  time_t last_mtime;
  size_t size;
  unsigned char *text;
};
struct contest_extra
{
  struct watched_file header;
  struct watched_file footer;
  struct watched_file priv_header;
  struct watched_file priv_footer;

  const unsigned char *header_txt;
  const unsigned char *footer_txt;
  unsigned char *contest_arm;
};
static struct contest_extra **extras = 0;
static size_t extra_a = 0;

static struct contest_extra *
get_contest_extra(int contest_id)
{
  size_t new_extra_a = 0;
  struct contest_extra **new_extras = 0, *p;

  ASSERT(contest_id > 0 && contest_id <= MAX_CONTEST_ID);

  if (contest_id >= extra_a) {
    if (!(new_extra_a = extra_a)) new_extra_a = 8;
    while (contest_id >= new_extra_a) new_extra_a *= 2;
    XCALLOC(new_extras, new_extra_a);
    if (extra_a > 0) memcpy(new_extras, extras, extra_a * sizeof(extras[0]));
    xfree(extras);
    extra_a = new_extra_a;
    extras = new_extras;
  }
  if (!(p = extras[contest_id])) {
    XCALLOC(p, 1);
    extras[contest_id] = p;
  }
  return p;
}

static void
update_watched_file(struct watched_file *pw, const unsigned char *path,
                    time_t cur_time)
{
  struct stat stb;
  char *tmpc = 0;

  if (!path) {
    if (!pw->path) return;
    xfree(pw->path);
    xfree(pw->text);
    memset(pw, 0, sizeof(*pw));
    return;
  }

  if (!cur_time) cur_time = time(0);
  if (pw->path && strcmp(path, pw->path) != 0) {
    xfree(pw->path);
    xfree(pw->text);
    memset(pw, 0, sizeof(*pw));
  }
  if (!pw->path) {
    pw->path = xstrdup(path);
    pw->last_check = cur_time;
    if (stat(pw->path, &stb) < 0) return;
    pw->last_mtime = stb.st_mtime;
    generic_read_file(&tmpc, 0, &pw->size, 0, 0, pw->path, "");
    pw->text = tmpc;
    return;
  }
  if (pw->last_check + 10 > cur_time) return;
  if (stat(pw->path, &stb) < 0) {
    xfree(pw->text); pw->text = 0;
    pw->size = 0;
    pw->last_check = cur_time;
    return;
  }
  if (pw->last_mtime == stb.st_mtime) return;
  pw->last_mtime = stb.st_mtime;
  pw->last_check = cur_time;
  xfree(pw->text); pw->text = 0;
  pw->size = 0;
  generic_read_file(&tmpc, 0, &pw->size, 0, 0, pw->path, "");
  pw->text = tmpc;  
}

static const unsigned char*
ns_getenv(const struct http_request_info *phr, const unsigned char *var)
{
  int i;
  size_t var_len;

  if (!var) return 0;
  var_len = strlen(var);
  for (i = 0; i < phr->env_num; i++)
    if (!strncmp(phr->envs[i], var, var_len) && phr->envs[i][var_len] == '=')
      break;
  if (i < phr->env_num)
    return phr->envs[i] + var_len + 1;
  return 0;
}

static int
ns_cgi_param(const struct http_request_info *phr, const unsigned char *param,
             const unsigned char **p_value)
{
  int i;

  if (!param) return -1;
  for (i = 0; i < phr->param_num; i++)
    if (!strcmp(phr->param_names[i], param))
      break;
  if (i >= phr->param_num) return 0;
  if (strlen(phr->params[i]) != phr->param_sizes[i]) return -1;
  *p_value = phr->params[i];
  return 1;
}

static const unsigned char *
ns_cgi_nname(const struct http_request_info *phr,
             const unsigned char *prefix, size_t pflen)
{
  int i;

  if (!prefix || !pflen) return 0;
  for (i = 0; i < phr->param_num; i++)
    if (!strncmp(phr->param_names[i], prefix, pflen))
      return phr->param_names[i];
  return 0;
}

static void
close_ul_connection(struct server_framework_state *state)
{
  if (!ul_conn) return;

  nsf_remove_watch(state, userlist_clnt_get_fd(ul_conn));
  ul_conn = userlist_clnt_close(ul_conn);
}

static void
ul_conn_callback(struct server_framework_state *state,
                 struct server_framework_watch *pw,
                 int events)
{
  info("userlist-server fd ready: disconnect?");
  close_ul_connection(state);
}

static int
open_ul_connection(struct server_framework_state *state)
{
  struct server_framework_watch w;
  int r;

  if (ul_conn) return 0;

  if (!(ul_conn = userlist_clnt_open(config->socket_path))) {
    err("open_ul_connection: connect to server failed");
    return -1;
  }

  memset(&w, 0, sizeof(w));
  w.fd = userlist_clnt_get_fd(ul_conn);
  w.mode = NSF_READ;
  w.callback = ul_conn_callback;
  nsf_add_watch(state, &w);

  xfree(ul_login); ul_login = 0;
  if ((r = userlist_clnt_admin_process(ul_conn, &ul_uid, &ul_login, 0)) < 0) {
    err("open_connection: cannot became an admin process: %s",
        userlist_strerror(-r));
    close_ul_connection(state);
    return -1;
  }

  info("running as %s (%d)", ul_login, ul_uid);
  return 0;
}

static const unsigned char * const ssl_flag_str[] =
{
  "http", "https",
};

static unsigned char default_header_template[] =
"<html><head>"
"<meta http-equiv=\"Content-Type\" content=\"%T; charset=%C\">\n"
"<title>%H</title>\n"
"</head>\n"
"<body><h1>%H</h1>\n";
static unsigned char default_footer_template[] =
"<hr>%R</body></html>\n";

static void
process_template(FILE *out,
                 unsigned char const *template,
                 unsigned char const *content_type,
                 unsigned char const *charset,
                 unsigned char const *title,
                 unsigned char const *copyright,
                 int locale_id)
{
  unsigned char const *s = template;

  while (*s) {
    if (*s != '%') {
      putc(*s++, out);
      continue;
    }
    switch (*++s) {
    case 'L':
      fprintf(out, "%d", locale_id);
      break;
    case 'C':
      fputs(charset, out);
      break;
    case 'T':
      fputs(content_type, out);
      break;
    case 'H':
      fputs(title, out);
      break;
    case 'R':
      fputs(copyright, out);
      break;
    default:
      putc('%', out);
      continue;
    }
    s++;
  }
}

static void
html_put_header(FILE *out, unsigned char const *template,
                unsigned char const *content_type,
                unsigned char const *charset,
                int locale_id,
                char const *format, ...)
{
  va_list args;
  unsigned char title[1024];

  title[0] = 0;
  if (format) {
    va_start(args, format);
    vsnprintf(title, sizeof(title), format, args);
    va_end(args);
  }

  if (!charset) charset = EJUDGE_CHARSET;
  if (!content_type) content_type = "text/html";
  if (!template) template = default_header_template;

  fprintf(out, "Content-Type: %s; charset=%s\n"
          "Cache-Control: no-cache\n"
          "Pragma: no-cache\n\n", content_type, charset);

  process_template(out, template, content_type, charset, title, 0, locale_id);
}

static void
html_put_footer(FILE *out, unsigned char const *template)
{
  if (!template) template = default_footer_template;
  process_template(out, template, 0, 0, 0, get_copyright(), 0);
}

static const unsigned char *role_strs[] =
  {
    __("Contestant"),
    __("Observer"),
    __("Judge"),
    __("Chief judge"),
    __("Coordinator"),
    __("Administrator"),
    0,
  };
static const unsigned char *
unparse_role(int role)
{
  static unsigned char buf[32];
  if (role < 0 || role >= USER_ROLE_LAST) {
    snprintf(buf, sizeof(buf), "role_%d", role);
    return buf;
  }
  return gettext(role_strs[role]);
}

static void
html_role_select(FILE *fout, int role, int allow_admin,
                 const unsigned char *var_name)
{
  int i;
  const unsigned char *ss;
  int last_role = USER_ROLE_ADMIN;

  if (!var_name) var_name = "role";
  if (!allow_admin) last_role = USER_ROLE_COORDINATOR;
  if (role <= 0 || role > last_role) role = USER_ROLE_OBSERVER;
  fprintf(fout, "<select name=\"%s\">", var_name);
  for (i = 1; i <= last_role; i++) {
    ss = "";
    if (i == role) ss = " selected=\"1\"";
    fprintf(fout, "<option value=\"%d\"%s>%s</option>",
            i, ss, gettext(role_strs[i]));
  }
  fprintf(fout, "</select>\n");
}

static unsigned char *
html_url(unsigned char *buf, size_t size,
         struct http_request_info *phr,
         int action)
{
  if (action > 0) {
    snprintf(buf, size, "%s?SID=%016llx&action=%d", phr->self_url,
             phr->session_id, action);
  } else {
    snprintf(buf, size, "%s?SID=%016llx", phr->self_url, phr->session_id);
  }
  return buf;
}

static void
html_refresh_page(struct server_framework_state *state,
                  FILE *fout,
                  struct http_request_info *phr,
                  int new_action)
{
  unsigned char url[1024];

  html_url(url, sizeof(url), phr, new_action);

  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\n\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><meta http-equiv=\"Refresh\" content=\"%d; url=%s\"><title>%s</title></head><body><h1>%s</h1><p>If autorefresh does not work, follow <a href=\"%s\">this</a> link.</p></body></html>\n", EJUDGE_CHARSET, EJUDGE_CHARSET, 1, url, "Operation successful", "Operation successful", url);
}

static void
privileged_page_login_page(struct server_framework_state *state,
                           struct client_state *p,
                           FILE *fout,
                           struct http_request_info *phr)
{
  const unsigned char *s;
  unsigned char *as;
  int r, n;

  html_put_header(fout, 0, 0, 0, phr->locale_id, "Login page");
  html_start_form(fout, 1, phr->self_url, "");
  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td>%s:</td><td><input type=\"text\" size=\"32\" name=\"login\"", _("Login"));
  if (ns_cgi_param(phr, "login", &s) > 0) {
    as = html_armor_string_dup(s);
    fprintf(fout, " value=\"%s\"", as);
    xfree(as);
  }
  fprintf(fout, "></td></tr>\n");
  fprintf(fout, "<tr><td>%s:</td><td><input type=\"password\" size=\"32\" name=\"password\"", _("Password"));
  if (ns_cgi_param(phr, "password", &s) > 0) {
    as = html_armor_string_dup(s);
    fprintf(fout, " value=\"%s\"", as);
    xfree(as);
  }
  fprintf(fout, "></td></tr>\n");
  fprintf(fout, "<tr><td>%s:</td><td><input type=\"text\" size=\"32\" name=\"contest_id\"", _("Contest"));
  if (phr->contest_id > 0) {
    fprintf(fout, " value=\"%d\"", phr->contest_id);
  }
  fprintf(fout, "></td></tr>\n");
  phr->role = USER_ROLE_OBSERVER;
  if (ns_cgi_param(phr, "role", &s) > 0) {
    if (sscanf(s, "%d%n", &r, &n) == 1 && !s[n]
        && r >= USER_ROLE_CONTESTANT && r < USER_ROLE_LAST)
      phr->role = r;
  }
  fprintf(fout, "<tr><td>%s:</td><td>", _("Role"));
  html_role_select(fout, phr->role, 1, 0);
  fprintf(fout, "</td></tr>\n");
  fprintf(fout, "<tr><td>%s:</td><td>", _("Language"));
  l10n_html_locale_select(fout, phr->locale_id);
  fprintf(fout, "</td></tr>\n");
  fprintf(fout, "<tr><td>&nbsp;</td><td><input type=\"submit\" value=\"%s\"></td></tr>\n", _("Submit"));
  fprintf(fout, "</table></form>\n");
  html_put_footer(fout, 0);
}

static void
html_err_permission_denied(struct server_framework_state *state,
                           struct client_state *p,
                           FILE *fout,
                           struct http_request_info *phr,
                           int priv_mode,
                           const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0;
  time_t cur_time = time(0);
  unsigned char *s;
  unsigned char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  err("%d: permission denied: %s", p->id, buf);

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    update_watched_file(&extra->header, cnts->team_header_file, cur_time);
    update_watched_file(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    update_watched_file(&extra->priv_header, cnts->priv_header_file, cur_time);
    update_watched_file(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id, _("Permission denied"));
  fprintf(fout, "<p>%s</p>\n",
          _("Permission denied. The possible reasons are as follows."));
  fprintf(fout, "<ul>\n");
  s = html_armor_string_dup(phr->login);
  fprintf(fout, _("<li>You have typed an invalid login (<tt>%s</tt>).</li>\n"),
          s);
  xfree(s);
  fprintf(fout, _("<li>You have typed an invalid password.</li>\n"));
  if (!priv_mode) {
    if (cnts) {
      s = html_armor_string_dup(cnts->name);
      fprintf(fout, _("<li>You are not registered for contest %s.</li>\n"), s);
      xfree(s);
    } else {
      fprintf(fout, _("<li>You are not registered for contest %d.</li>\n"),
              phr->contest_id);
    }
    fprintf(fout, _("<li>Your registration was not confirmed.</li>\n"));
    fprintf(fout, _("<li>You were banned by the administrator.</li>\n"));
    fprintf(fout, _("<li>Your IP-address (<tt>%s</tt>) or protocol (<tt>%s</tt>) is banned for participation.</li>"), xml_unparse_ip(phr->ip),
            ssl_flag_str[phr->ssl_flag]);
    fprintf(fout, _("<li>The contest is closed for participation.</li>\n"));
  } else {
    fprintf(fout, _("<li>Your IP-address (<tt>%s</tt>) or protocol (<tt>%s</tt>) is banned for participation.</li>"), xml_unparse_ip(phr->ip), ssl_flag_str[phr->ssl_flag]);
    fprintf(fout, _("<li>You do not have permissions to login using the specified role.</li>"));
  }
  fprintf(fout, "</ul>\n");
  fprintf(fout, _("<p>Note, that the exact reason is not reported due to security reasons.</p>"));
  html_put_footer(fout, footer);
  l10n_setlocale(0);
}

static void
html_err_invalid_param(struct server_framework_state *state,
                       struct client_state *p,
                       FILE *fout,
                       struct http_request_info *phr,
                       int priv_mode,
                       const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  err("%d: invalid parameter: %s", p->id, buf);

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    update_watched_file(&extra->header, cnts->team_header_file, cur_time);
    update_watched_file(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    update_watched_file(&extra->priv_header, cnts->priv_header_file, cur_time);
    update_watched_file(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id, _("Invalid parameter"));
  fprintf(fout, "<p>%s</p>\n",
          _("A request parameter is invalid. Please, contact the site administrator."));
  html_put_footer(fout, footer);
  l10n_setlocale(0);
}

static void
html_err_userlist_server_down(struct server_framework_state *state,
                              struct client_state *p,
                              FILE *fout,
                              struct http_request_info *phr,
                              int priv_mode)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0;
  time_t cur_time = time(0);

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    update_watched_file(&extra->header, cnts->team_header_file, cur_time);
    update_watched_file(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    update_watched_file(&extra->priv_header, cnts->priv_header_file, cur_time);
    update_watched_file(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id, _("User database server is down"));
  fprintf(fout, "<p>%s</p>\n",
          _("The user database server is currently not available. Please, retry the request later."));
  html_put_footer(fout, footer);
  l10n_setlocale(0);
}

static void
html_err_internal_error(struct server_framework_state *state,
                        struct client_state *p,
                        FILE *fout,
                        struct http_request_info *phr,
                        int priv_mode,
                        const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  err("%d: internal error: %s", p->id, buf);

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    update_watched_file(&extra->header, cnts->team_header_file, cur_time);
    update_watched_file(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    update_watched_file(&extra->priv_header, cnts->priv_header_file, cur_time);
    update_watched_file(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id, _("Internal error"));
  fprintf(fout, "<p>%s</p>\n",
          _("Your request has caused an internal server error. Please, report it as a bug."));
  html_put_footer(fout, footer);
  l10n_setlocale(0);
}

static void
html_err_invalid_session(struct server_framework_state *state,
                         struct client_state *p,
                         FILE *fout,
                         struct http_request_info *phr,
                         int priv_mode,
                         const char *format, ...)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0;
  time_t cur_time = time(0);
  unsigned char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);
  err("%d: invalid session: %s", p->id, buf);

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = get_contest_extra(phr->contest_id);
  if (extra && !priv_mode) {
    update_watched_file(&extra->header, cnts->team_header_file, cur_time);
    update_watched_file(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    update_watched_file(&extra->priv_header, cnts->priv_header_file, cur_time);
    update_watched_file(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id, _("Invalid session"));
  fprintf(fout, "<p>%s</p>\n",
          _("Invalid session identifier. The possible reasons are as follows."));
  fprintf(fout, "<ul>\n");
  fprintf(fout, _("<li>The specified session does not exist.</li>"));
  fprintf(fout, _("<li>The specified has expired.</li>\n"));
  fprintf(fout, _("<li>The session was created from a different IP-address or protocol, that yours (%s,%s).</li>\n"), xml_unparse_ip(phr->ip), ssl_flag_str[phr->ssl_flag]);
  fprintf(fout, _("<li>The session was removed by an administrator.</li>"));
  fprintf(fout, "</ul>\n");
  fprintf(fout, _("<p>Note, that the exact reason is not reported due to security reasons.</p>"));
  html_put_footer(fout, footer);
  l10n_setlocale(0);
}

static void
html_error_status_page(struct server_framework_state *state,
                       struct client_state *p,
                       FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra,
                       const unsigned char *log_txt,
                       int back_action)
{
  unsigned char *s;
  unsigned char url[1024];

  l10n_setlocale(phr->locale_id);
  html_put_header(fout, extra->header_txt, 0, 0, phr->locale_id,
                  _("Operation competed with errors"));
  s = html_armor_string_dup(log_txt);
  fprintf(fout, "<font color=\"red\"><pre>%s</pre></font>\n",
          s);
  xfree(s);
  fprintf(fout, "<hr><a href=\"%s\">Back</a>\n",
          html_url(url, sizeof(url), phr, back_action));
  html_put_footer(fout, extra->footer_txt);
  l10n_setlocale(0);
}
                       
static void
privileged_page_login(struct server_framework_state *state,
                      struct client_state *p,
                      FILE *fout,
                      struct http_request_info *phr)
{
  const unsigned char *login, *password, *s;
  int r, n;
  const struct contest_desc *cnts = 0;
  opcap_t caps;

  if ((r = ns_cgi_param(phr, "login", &login)) < 0)
    return html_err_invalid_param(state, p, fout, phr, 1, "cannot parse login");
  if (!r || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return privileged_page_login_page(state, p, fout, phr);

  phr->login = xstrdup(login);
  if ((r = ns_cgi_param(phr, "password", &password)) <= 0)
    return html_err_invalid_param(state, p, fout, phr, 1,
                                  "cannot parse password");
  if (phr->contest_id<=0 || contests_get(phr->contest_id, &cnts)<0 || !cnts)
    return html_err_invalid_param(state, p, fout, phr, 1,
                                  "invalid contest_id");

  phr->role = USER_ROLE_OBSERVER;
  if (ns_cgi_param(phr, "role", &s) > 0) {
    if (sscanf(s, "%d%n", &r, &n) == 1 && !s[n]
        && r >= USER_ROLE_CONTESTANT && r < USER_ROLE_LAST)
      phr->role = r;
  }
  if (phr->role == USER_ROLE_CONTESTANT) {
    // FIXME: go to the unprvileged login
    abort();
  }

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (!contests_check_master_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "IP %s://%s is not allowed for MASTER for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "IP %s://%s is not allowed for MASTER for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  }

  if (open_ul_connection(state) < 0)
    return html_err_userlist_server_down(state, p, fout, phr, 1);
  if ((r = userlist_clnt_priv_login(ul_conn, ULS_PRIV_CHECK_USER,
                                    phr->ip, phr->ssl_flag, phr->contest_id,
                                    phr->locale_id, 0, phr->role, login,
                                    password, &phr->user_id, &phr->session_id,
                                    0, 0, &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "priv_login failed: %s",
                                        userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return html_err_userlist_server_down(state, p, fout, phr, 1);
    default:
      return html_err_internal_error(state, p, fout, phr, 1,
                                     "priv_login failed: %s",
                                     userlist_strerror(-r));
    }
  }

  // analyze permissions
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0)
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "user %s does not have MASTER_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "user %s has no permission to login as role %d for contest %d", phr->login, phr->role, phr->contest_id);
  }

  // TODO: store a cookie
  html_refresh_page(state, fout, phr, NEW_SRV_ACTION_MAIN_PAGE);
}

static void
priv_registration_operation(struct server_framework_state *state,
                            struct client_state *p,
                            FILE *fout,
                            struct http_request_info *phr,
                            const struct contest_desc *cnts,
                            struct contest_extra *extra)
{
  int i, x, n, new_status, cmd, flag;
  intarray_t uset;
  const unsigned char *s;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;

  // extract the selected set of users
  memset(&uset, 0, sizeof(uset));
  for (i = 0; i < phr->param_num; i++) {
    if (strncmp(phr->param_names[i], "user_", 5) != 0) continue;
    if (sscanf((s = phr->param_names[i] + 5), "%d%n", &x, &n) != 1
        || s[n] || x <= 0) {
      html_err_invalid_param(state, p, fout, phr, 1,
                             "invalid parameter name %s", phr->param_names[i]);
      goto cleanup;
    }
    XEXPAND2(uset);
    uset.v[uset.u++] = x;
  }

  // FIXME: probably we need to sort user_ids and remove duplicates

  if (open_ul_connection(state) < 0) {
    html_err_userlist_server_down(state, p, fout, phr, 1);
    goto cleanup;
  }

  log_f = open_memstream(&log_txt, &log_len);

  for (i = 0; i < uset.u; i++) {
    switch (phr->action) {
    case NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS:
      n = userlist_clnt_change_registration(ul_conn, uset.v[i],
                                            phr->contest_id, -2, 0, 0);
      if (n < 0) {
        fprintf(log_f, "Removal of user %d from contest %d failed: %s",
                uset.v[i], phr->contest_id, userlist_strerror(-n));
      }
      break;
    case NEW_SRV_ACTION_USERS_SET_PENDING:
    case NEW_SRV_ACTION_USERS_SET_OK:
    case NEW_SRV_ACTION_USERS_SET_REJECTED:
      switch (phr->action) {
      case NEW_SRV_ACTION_USERS_SET_PENDING: 
        new_status = USERLIST_REG_PENDING;
        break;
      case NEW_SRV_ACTION_USERS_SET_OK:
        new_status = USERLIST_REG_OK;
        break;
      case NEW_SRV_ACTION_USERS_SET_REJECTED:
        new_status = USERLIST_REG_REJECTED;
        break;
      default:
        abort();
      }
      n = userlist_clnt_change_registration(ul_conn, uset.v[i],
                                            phr->contest_id, new_status, 0, 0);
      if (n < 0) {
        fprintf(log_f, "Changing status of user %d in contest %d failed: %s",
                uset.v[i], phr->contest_id, userlist_strerror(-n));
      }
      break;

    case NEW_SRV_ACTION_USERS_SET_INVISIBLE:
    case NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE:
    case NEW_SRV_ACTION_USERS_SET_BANNED:
    case NEW_SRV_ACTION_USERS_CLEAR_BANNED:
    case NEW_SRV_ACTION_USERS_SET_LOCKED:
    case NEW_SRV_ACTION_USERS_CLEAR_LOCKED:
      switch (phr->action) {
      case NEW_SRV_ACTION_USERS_SET_INVISIBLE:
        cmd = 1;
        flag = USERLIST_UC_INVISIBLE;
        break;
      case NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE:
        cmd = 2;
        flag = USERLIST_UC_INVISIBLE;
        break;
      case NEW_SRV_ACTION_USERS_SET_BANNED:
        cmd = 1;
        flag = USERLIST_UC_BANNED;
        break;
      case NEW_SRV_ACTION_USERS_CLEAR_BANNED:
        cmd = 2;
        flag = USERLIST_UC_BANNED;
        break;
      case NEW_SRV_ACTION_USERS_SET_LOCKED:
        cmd = 1;
        flag = USERLIST_UC_LOCKED;
        break;
      case NEW_SRV_ACTION_USERS_CLEAR_LOCKED:
        cmd = 2;
        flag = USERLIST_UC_LOCKED;
        break;
      default:
        abort();
      }
      n = userlist_clnt_change_registration(ul_conn, uset.v[i],
                                            phr->contest_id, -1, cmd,
                                            flag);
      if (n < 0) {
        fprintf(log_f, "Changing flags of user %d in contest %d failed: %s",
                uset.v[i], phr->contest_id, userlist_strerror(-n));
      }
      break;

    default:
      html_err_invalid_param(state, p, fout, phr, 1,
                             "invalid action %d", phr->action);
      goto cleanup;
    }
  }

  fclose(log_f); log_f = 0;

  if (!log_txt || !*log_txt) {
    html_refresh_page(state, fout, phr, NEW_SRV_ACTION_VIEW_USERS);
  } else {
    html_error_status_page(state, p, fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_VIEW_USERS);
  }

 cleanup:
  xfree(uset.v);
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
priv_add_user_by_user_id(struct server_framework_state *state,
                         struct client_state *p,
                         FILE *fout,
                         struct http_request_info *phr,
                         const struct contest_desc *cnts,
                         struct contest_extra *extra)
{
  const unsigned char *s;
  int x, n, r;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;

  log_f = open_memstream(&log_txt, &log_len);

  if ((r = ns_cgi_param(phr, "add_user_id", &s)) < 0 || !s
      || sscanf(s, "%d%n", &x, &n) != 1 || s[n] || x <= 0) {
    fprintf(log_f, "Invalid user Id");
    goto done;
  }

  if (open_ul_connection(state) < 0) {
    html_err_userlist_server_down(state, p, fout, phr, 1);
    goto cleanup;
  }
  
  r = userlist_clnt_register_contest(ul_conn, ULS_PRIV_REGISTER_CONTEST,
                                     x, phr->contest_id);
  if (r < 0) {
    fprintf(log_f, "Registration failed: %s", userlist_strerror(-r));
    goto done;
  }

 done:
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    html_refresh_page(state, fout, phr, NEW_SRV_ACTION_VIEW_USERS);
  } else {
    html_error_status_page(state, p, fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_VIEW_USERS);
  }

 cleanup:
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
priv_add_user_by_login(struct server_framework_state *state,
                       struct client_state *p,
                       FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  const unsigned char *s;
  int r, user_id;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  unsigned char *ss;

  log_f = open_memstream(&log_txt, &log_len);

  if ((r = ns_cgi_param(phr, "add_login", &s)) < 0 || !s) {
    fprintf(log_f, "Invalid User Login");
    goto done;
  }
  if (open_ul_connection(state) < 0) {
    html_err_userlist_server_down(state, p, fout, phr, 1);
    goto cleanup;
  }
  if ((r = userlist_clnt_lookup_user(ul_conn, s, &user_id, 0)) < 0) {
    ss = html_armor_string_dup(s);
    fprintf(log_f, "User <tt>%s</tt> does not exist", ss);
    xfree(ss);
    goto done;
  }
  if ((r = userlist_clnt_register_contest(ul_conn, ULS_PRIV_REGISTER_CONTEST,
                                          user_id, phr->contest_id)) < 0) {
    fprintf(log_f, "Registration failed: %s", userlist_strerror(-r));
    goto done;
  }

 done:
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    html_refresh_page(state, fout, phr, NEW_SRV_ACTION_VIEW_USERS);
  } else {
    html_error_status_page(state, p, fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_VIEW_USERS);
  }

 cleanup:
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
priv_priv_user_operation(struct server_framework_state *state,
                         struct client_state *p,
                         FILE *fout,
                         struct http_request_info *phr,
                         const struct contest_desc *cnts,
                         struct contest_extra *extra)
{
  int i, x, n, role;
  intarray_t uset;
  const unsigned char *s;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;

  // extract the selected set of users
  memset(&uset, 0, sizeof(uset));
  for (i = 0; i < phr->param_num; i++) {
    if (strncmp(phr->param_names[i], "user_", 5) != 0) continue;
    if (sscanf((s = phr->param_names[i] + 5), "%d%n", &x, &n) != 1
        || s[n] || x <= 0) {
      html_err_invalid_param(state, p, fout, phr, 1,
                             "invalid parameter name %s", phr->param_names[i]);
      goto cleanup;
    }
    XEXPAND2(uset);
    uset.v[uset.u++] = x;
  }

  // FIXME: probably we need to sort user_ids and remove duplicates

  log_f = open_memstream(&log_txt, &log_len);

  switch (phr->action) {
  case NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER:
    role = USER_ROLE_OBSERVER;
    break;
  case NEW_SRV_ACTION_PRIV_USERS_ADD_JUDGE:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_JUDGE:
    role = USER_ROLE_JUDGE;
    break;
  case NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_JUDGE:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_JUDGE:
    role = USER_ROLE_CHIEF_JUDGE;
    break;
  case NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR:
    role = USER_ROLE_COORDINATOR;
    break;
  }

  for (i = 0; i < uset.u; i++) {
    switch (phr->action) {
    case NEW_SRV_ACTION_PRIV_USERS_REMOVE:
      if (nsdb_priv_remove_user(uset.v[i], phr->contest_id) < 0) {
        fprintf(log_f, "Remove (%d,%d) failed\n", uset.v[i], phr->contest_id);
      }
      break;

    case NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER:
    case NEW_SRV_ACTION_PRIV_USERS_ADD_JUDGE:
    case NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_JUDGE:
    case NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR:
      if (nsdb_add_role(uset.v[i], phr->contest_id, role) < 0) {
        fprintf(log_f, "add_role (%d,%d,%d) failed\n",
                uset.v[i], phr->contest_id, role);
      }
      break;

    case NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER:
    case NEW_SRV_ACTION_PRIV_USERS_DEL_JUDGE:
    case NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_JUDGE:
    case NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR:
      if (nsdb_del_role(uset.v[i], phr->contest_id, role) < 0) {
        fprintf(log_f, "del_role (%d,%d,%d) failed\n",
                uset.v[i], phr->contest_id, role);
      }
      break;

    default:
      html_err_invalid_param(state, p, fout, phr, 1,
                             "invalid action %d", phr->action);
      goto cleanup;
    }
  }

  fclose(log_f); log_f = 0;

  if (!log_txt || !*log_txt) {
    html_refresh_page(state, fout, phr, NEW_SRV_ACTION_PRIV_USERS_VIEW);
  } else {
    html_error_status_page(state, p, fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_PRIV_USERS_VIEW);
  }

 cleanup:
  xfree(uset.v);
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
priv_add_priv_user_by_user_id(struct server_framework_state *state,
                              struct client_state *p,
                              FILE *fout,
                              struct http_request_info *phr,
                              const struct contest_desc *cnts,
                              struct contest_extra *extra)
{
  const unsigned char *s;
  int user_id, n, r, add_role;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;

  log_f = open_memstream(&log_txt, &log_len);

  if ((r = ns_cgi_param(phr, "add_user_id", &s)) < 0 || !s
      || sscanf(s, "%d%n", &user_id, &n) != 1 || s[n] || user_id <= 0) {
    fprintf(log_f, "Invalid user Id");
    goto done;
  }
  if ((r = ns_cgi_param(phr, "add_role_2", &s)) < 0 || !s
      || sscanf(s, "%d%n", &add_role, &n) != 1 || s[n]
      || add_role < USER_ROLE_OBSERVER || add_role > USER_ROLE_COORDINATOR) {
    fprintf(log_f, "Invalid User Role");
    goto done;
  }

  if (nsdb_add_role(user_id, phr->contest_id, add_role) < 0) {
    fprintf(log_f, "Adding role (%d,%d,%d) failed", user_id, phr->contest_id,
            add_role);
    goto done;
  }

 done:
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    html_refresh_page(state, fout, phr, NEW_SRV_ACTION_PRIV_USERS_VIEW);
  } else {
    html_error_status_page(state, p, fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_PRIV_USERS_VIEW);
  }

  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
priv_add_priv_user_by_login(struct server_framework_state *state,
                            struct client_state *p,
                            FILE *fout,
                            struct http_request_info *phr,
                            const struct contest_desc *cnts,
                            struct contest_extra *extra)
{
  const unsigned char *s, *login;
  int r, user_id, add_role, n;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  unsigned char *ss;

  log_f = open_memstream(&log_txt, &log_len);

  if ((r = ns_cgi_param(phr, "add_login", &login)) < 0 || !s) {
    fprintf(log_f, "Invalid User Login");
    goto done;
  }
  if ((r = ns_cgi_param(phr, "add_role_1", &s)) < 0 || !s
      || sscanf(s, "%d%n", &add_role, &n) != 1 || s[n]
      || add_role < USER_ROLE_OBSERVER || add_role > USER_ROLE_COORDINATOR) {
    fprintf(log_f, "Invalid User Role");
    goto done;
  }
  if (open_ul_connection(state) < 0) {
    html_err_userlist_server_down(state, p, fout, phr, 1);
    goto cleanup;
  }
  if ((r = userlist_clnt_lookup_user(ul_conn, login, &user_id, 0)) < 0) {
    ss = html_armor_string_dup(s);
    fprintf(log_f, "User <tt>%s</tt> does not exist", ss);
    xfree(ss);
    goto done;
  }
  if (nsdb_add_role(user_id, phr->contest_id, add_role) < 0) {
    fprintf(log_f, "Adding role (%d,%d,%d) failed", user_id, phr->contest_id,
            add_role);
    goto done;
  }

 done:
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    html_refresh_page(state, fout, phr, NEW_SRV_ACTION_PRIV_USERS_VIEW);
  } else {
    html_error_status_page(state, p, fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_PRIV_USERS_VIEW);
  }

 cleanup:
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

static void
priv_view_users_page(struct server_framework_state *state,
                     struct client_state *p,
                     FILE *fout,
                     struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra)
{
  int r;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  const struct userlist_user *u = 0;
  const struct userlist_contest *uc = 0;
  unsigned char *s;
  int uid;
  int row = 1, serial = 1;
  char url[1024];

  if (open_ul_connection(state) < 0)
    return html_err_userlist_server_down(state, p, fout, phr, 1);
  if ((r = userlist_clnt_list_all_users(ul_conn, ULS_LIST_ALL_USERS,
                                        phr->contest_id, &xml_text)) < 0)
    return html_err_internal_error(state, p, fout, phr, 1,
                                   "list_all_users failed: %s",
                                   userlist_strerror(-r));
  users = userlist_parse_str(xml_text);
  xfree(xml_text); xml_text = 0;
  if (!users)
    return html_err_internal_error(state, p, fout, phr, 1,
                                   "XML parsing failed");

  l10n_setlocale(phr->locale_id);
  html_put_header(fout, extra->header_txt, 0, 0, phr->locale_id,
                  "%s [%s, %s]: %s", unparse_role(phr->role),
                  phr->name_arm, extra->contest_arm, _("Users page"));

  fprintf(fout, "<h2>Registered users</h2>");

  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table><tr><th>NN</th><th>Id</th><th>Login</th><th>Name</th><th>Status</th><th>Flags</th><th>Reg. date</th><th>Login date</th><th>Select</th></tr>\n");
  for (uid = 1; uid < users->user_map_size; uid++) {
    if (!(u = users->user_map[uid])) continue;
    if (!(uc = userlist_get_user_contest(u, phr->contest_id))) continue;

    fprintf(fout, "<tr%s>", form_row_attrs[row ^= 1]);
    fprintf(fout, "<td>%d</td><td>%d</td>", serial++, uid);
    s = html_armor_string_dup(u->login);
    fprintf(fout, "<td>%s</td>", s);
    xfree(s);
    if (u->i.name && *u->i.name) {
      s = html_armor_string_dup(u->i.name);
      fprintf(fout, "<td>%s</td>", s);
      xfree(s);
    } else {
      fprintf(fout, "<td>&nbsp;</td>");
    }
    fprintf(fout, "<td>%s</td>", userlist_unparse_reg_status(uc->status));
    if ((uc->flags & (USERLIST_UC_BANNED | USERLIST_UC_INVISIBLE | USERLIST_UC_LOCKED))) {
      r = 0;
      fprintf(fout, "<td>");
      if ((uc->flags & USERLIST_UC_BANNED))
        fprintf(fout, "%s%s", r++?",":"", "banned");
      if ((uc->flags & USERLIST_UC_INVISIBLE))
        fprintf(fout, "%s%s", r++?",":"", "invisible");
      if ((uc->flags & USERLIST_UC_LOCKED))
        fprintf(fout, "%s%s", r++?",":"", "locked");
      fprintf(fout, "</td>");
    } else {
      fprintf(fout, "<td>&nbsp;</td>");
    }
    if (uc->date > 0) {
      fprintf(fout, "<td>%s</td>", xml_unparse_date(uc->date));
    } else {
      fprintf(fout, "<td>&nbsp;</td>");
    }
    if (u->i.last_login_time > 0) {
      fprintf(fout, "<td>%s</td>", xml_unparse_date(u->i.last_login_time));
    } else {
      fprintf(fout, "<td>&nbsp;</td>");
    }
    fprintf(fout, "<td><input type=\"checkbox\" name=\"user_%d\"></td>", uid);
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>Available actions</h2>\n");

  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td><a href=\"%s\">Back</a></td><td>Return to the main page</td></tr>\n", html_url(url, sizeof(url), phr, 0));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS, _("Remove registrations"), _("Remove the selected users from the list"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_SET_PENDING, _("Mark PENDING"), _("Set the registration status of the selected users to PENDING"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_SET_OK, _("Mark OK"), _("Set the registration status of the selected users to OK"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_SET_REJECTED, _("Mark REJECTED"), _("Set the registration status of the selected users to REJECTED"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_SET_INVISIBLE, _("Mark INVISIBLE"), _("Set the INVISIBLE flag for the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE, _("Clear INVISIBLE"), _("Clear the INVISIBLE flag for the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_SET_BANNED, _("Mark BANNED"), _("Set the BANNED flag for the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_CLEAR_BANNED, _("Clear BANNED"), _("Clear the BANNED flag for the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_SET_LOCKED, _("Mark LOCKED"), _("Set the LOCKED flag for the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_CLEAR_LOCKED, _("Clear LOCKED"), _("Clear the LOCKED flag for the selected users"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>%s</h2>\n", _("Add new user"));
  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td><input type=\"text\" size=\"32\" name=\"add_login\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_ADD_BY_LOGIN, _("Add by login"), _("Add a new user specifying his/her login"));
  fprintf(fout, "<tr><td><input type=\"text\" size=\"32\" name=\"add_user_id\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_USERS_ADD_BY_USER_ID, _("Add by ID"), _("Add a new user specifying his/her User Id"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "</form>\n");

  html_put_footer(fout, extra->footer_txt);
  l10n_setlocale(0);

  if (users) userlist_free(&users->b);
}

struct priv_user_info
{
  int user_id;
  unsigned char *login;
  unsigned char *name;
  unsigned int role_mask;
};
static int
priv_user_info_sort_func(const void *v1, const void *v2)
{
  const struct priv_user_info *p1 = *(const struct priv_user_info**) v1;
  const struct priv_user_info *p2 = *(const struct priv_user_info**) v2;

  if (v1 == v2) return 0;
  ASSERT(p1 != p2);
  if (p1->user_id < p2->user_id) return -1;
  if (p1->user_id > p2->user_id) return 1;
  abort();
}

static void
priv_view_priv_users_page(struct server_framework_state *state,
                          struct client_state *p,
                          FILE *fout,
                          struct http_request_info *phr,
                          const struct contest_desc *cnts,
                          struct contest_extra *extra)
{
  struct ptrarray_t
  {
    int a, u;
    struct priv_user_info **v;
  };
  struct ptrarray_t users;
  struct opcap_list_item *op;
  int user_id, i;
  unsigned char *name = 0, *login = 0, *s;
  struct priv_user_info *pp;
  int_iterator_t iter;
  unsigned int role_mask;
  int row = 1, cnt, r;
  unsigned char url[1024];

  XMEMZERO(&users, 1);

  if (open_ul_connection(state) < 0) {
    html_err_userlist_server_down(state, p, fout, phr, 1);
    goto cleanup;
  }

  // collect all information about allowed MASTER logins
  for (op = cnts->capabilities.first; op;
       op = (struct opcap_list_item*) op->b.right) {
    if (opcaps_check(op->caps, OPCAP_MASTER_LOGIN) < 0) continue;
    if (userlist_clnt_lookup_user(ul_conn, op->login, &user_id, &name) < 0)
      continue;
    for (i = 0; i < users.u; i++)
      if (users.v[i]->user_id == user_id)
        break;
    if (i < users.u) {
      xfree(name);
      continue;
    }
    XEXPAND2(users);
    XCALLOC(users.v[users.u], 1);
    pp = users.v[users.u++];
    pp->user_id = user_id;
    pp->login = xstrdup(op->login);
    pp->name = name;
    pp->role_mask |= (1 << USER_ROLE_ADMIN);
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
    for (i = 0; i < users.u; i++)
      if (users.v[i]->user_id == user_id)
        break;
    if (i < users.u) {
      xfree(login);
      xfree(name);
      users.v[i]->role_mask |= role_mask;
      continue;
    }
    XEXPAND2(users);
    XCALLOC(users.v[users.u], 1);
    pp = users.v[users.u++];
    pp->user_id = user_id;
    pp->login = login;
    pp->name = name;
    pp->role_mask |= role_mask;
  }
  iter->destroy(iter); iter = 0;

  qsort(users.v, users.u, sizeof(users.v[0]), priv_user_info_sort_func);

  l10n_setlocale(phr->locale_id);
  html_put_header(fout, extra->header_txt, 0, 0, phr->locale_id,
                  "%s [%s, %s]: %s", unparse_role(phr->role),
                  phr->name_arm, extra->contest_arm, _("Privileged users page"));

  fprintf(fout, "<h2>Privileged users</h2>");

  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table><tr><th>NN</th><th>Id</th><th>Login</th><th>Name</th><th>Roles</th><th>Select</th></tr>\n");
  for (i = 0; i < users.u; i++) {
    fprintf(fout, "<tr%s><td>%d</td>", form_row_attrs[row ^= 1], i + 1);
    fprintf(fout, "<td>%d</td>", users.v[i]->user_id);
    s = html_armor_string_dup(users.v[i]->login);
    fprintf(fout, "<td>%s</td>", s);
    xfree(s);
    s = html_armor_string_dup(users.v[i]->name);
    fprintf(fout, "<td>%s</td>", s);
    xfree(s);
    if ((role_mask = users.v[i]->role_mask)) {
      fprintf(fout, "<td>");
      for (cnt = 0, r = USER_ROLE_OBSERVER; r <= USER_ROLE_ADMIN; r++)
        if ((role_mask & (1 << r)))
          fprintf(fout, "%s%s", cnt++?",":"", unparse_role(r));
      fprintf(fout, "</td>");
    } else {
      fprintf(fout, "<td>&nbsp;</td>");
    }
    fprintf(fout, "<td><input type=\"checkbox\" name=\"user_%d\"></td>",
            users.v[i]->user_id);
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>Available actions</h2>\n");

  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td><a href=\"%s\">Back</a></td><td>Return to the main page</td></tr>\n", html_url(url, sizeof(url), phr, 0));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_REMOVE, _("Remove"), _("Remove the selected users from the list (ADMINISTRATORs cannot be removed)"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER, _("Add OBSERVER"), _("Add the OBSERVER role to the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER, _("Del OBSERVER"), _("Remove the OBSERVER role from the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_ADD_JUDGE, _("Add JUDGE"), _("Add the JUDGE role to the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_DEL_JUDGE, _("Del JUDGE"), _("Remove the JUDGE role from the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_JUDGE, _("Add CHIEF JUDGE"), _("Add the CHIEF JUDGE role to the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_JUDGE, _("Del CHIEF JUDGE"), _("Remove the CHIEF JUDGE role from the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR, _("Add COORDINATOR"), _("Add the COORDINATOR role to the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR, _("Del COORDINATOR"), _("Remove the COORDINATOR role from the selected users"));
  fprintf(fout, "</table>\n");

  fprintf(fout, "<h2>%s</h2>\n", _("Add new user"));
  fprintf(fout, "<table>\n");
  fprintf(fout, "<tr><td><input type=\"text\" size=\"32\" name=\"add_login\"></td><td>");
  html_role_select(fout, USER_ROLE_OBSERVER, 0, "add_role_1");
  fprintf(fout, "</td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_ADD_BY_LOGIN, _("Add by login"), _("Add a new user specifying his/her login"));
  fprintf(fout, "<tr><td><input type=\"text\" size=\"32\" name=\"add_user_id\"></td><td>");
  html_role_select(fout, USER_ROLE_OBSERVER, 0, "add_role_2");
  fprintf(fout, "</td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_ADD_BY_USER_ID, _("Add by ID"), _("Add a new user specifying his/her User Id"));
  fprintf(fout, "</table>\n");

  html_put_footer(fout, extra->footer_txt);
  l10n_setlocale(0);

 cleanup:
  for (i = 0; i < users.u; i++) {
    if (users.v[i]) {
      xfree(users.v[i]->login);
      xfree(users.v[i]->name);
    }
    xfree(users.v[i]);
  }
  xfree(users.v);
  if (iter) iter->destroy(iter);
}

static void
priv_main_page(struct server_framework_state *state,
               struct client_state *p,
               FILE *fout,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  unsigned char hbuf[1024];

  l10n_setlocale(phr->locale_id);
  html_put_header(fout, extra->header_txt, 0, 0, phr->locale_id,
                  "%s [%s, %s]: %s", unparse_role(phr->role),
                  phr->name_arm, extra->contest_arm, _("Main page"));
  fprintf(fout, "<ul>\n");
  fprintf(fout, "<li><a href=\"%s\">View regular users</a></li>\n",
          html_url(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_USERS));
  fprintf(fout, "<li><a href=\"%s\">View privileged users</a></li>\n",
          html_url(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_PRIV_USERS_VIEW));
  fprintf(fout, "</ul>\n");
  html_put_footer(fout, extra->footer_txt);
  l10n_setlocale(0);
}

static void (*actions_table[])(struct server_framework_state *state,
                               struct client_state *p,
                               FILE *fout,
                               struct http_request_info *phr,
                               const struct contest_desc *cnts,
                               struct contest_extra *extra) =
{
  [NEW_SRV_ACTION_VIEW_USERS] = priv_view_users_page,
  [NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_PENDING] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_OK] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_REJECTED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_INVISIBLE] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_BANNED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_BANNED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_SET_LOCKED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_CLEAR_LOCKED] = priv_registration_operation,
  [NEW_SRV_ACTION_USERS_ADD_BY_LOGIN] = priv_add_user_by_login,
  [NEW_SRV_ACTION_USERS_ADD_BY_USER_ID] = priv_add_user_by_user_id,
  [NEW_SRV_ACTION_PRIV_USERS_VIEW] = priv_view_priv_users_page,
  [NEW_SRV_ACTION_PRIV_USERS_REMOVE] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_JUDGE] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_JUDGE] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_JUDGE] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_JUDGE] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_BY_LOGIN] = priv_add_priv_user_by_login,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_BY_USER_ID] = priv_add_priv_user_by_user_id,
};


static void
privileged_page(struct server_framework_state *state,
                struct client_state *p,
                FILE *fout,
                struct http_request_info *phr)
{
  int r;
  opcap_t caps;
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = time(0);
  unsigned char hid_buf[1024];

  if (!phr->session_id || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return privileged_page_login(state, p, fout, phr);

  // validate cookie
  if (open_ul_connection(state) < 0)
    return html_err_userlist_server_down(state, p, fout, phr, 1);
  if ((r = userlist_clnt_get_cookie(ul_conn, phr->ip, phr->ssl_flag,
                                    phr->session_id,
                                    &phr->user_id, &phr->contest_id,
                                    &phr->locale_id, 0, &phr->role,
                                    &phr->login, &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
      return html_err_invalid_session(state, p, fout, phr, 1,
                                     "priv_login failed: %s",
                                     userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return html_err_userlist_server_down(state, p, fout, phr, 1);
    default:
      return html_err_internal_error(state, p, fout, phr, 1,
                                     "priv_login failed: %s",
                                     userlist_strerror(-r));
    }
  }

  if (phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return html_err_permission_denied(state, p, fout, phr, 1,
                                      "invalid contest_id %d", phr->contest_id);
  extra = get_contest_extra(phr->contest_id);
  ASSERT(extra);

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (!contests_check_master_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "IP %s://%s is not allowed for MASTER for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "IP %s://%s is not allowed for MASTER for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  }

  // analyze permissions
  if (phr->role <= 0 || phr->role >= USER_ROLE_LAST)
    return html_err_permission_denied(state, p, fout, phr, 1,
                                      "invalid role %d", phr->role);
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0)
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "user %s does not have MASTER_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "user %s has no permission to login as role %d for contest %d", phr->login, phr->role, phr->contest_id);
  }

  update_watched_file(&extra->priv_header, cnts->priv_header_file, cur_time);
  update_watched_file(&extra->priv_footer, cnts->priv_footer_file, cur_time);
  extra->header_txt = extra->priv_header.text;
  extra->footer_txt = extra->priv_footer.text;

  if (phr->name && *phr->name) {
    phr->name_arm = html_armor_string_dup(phr->name);
  } else {
    phr->name_arm = html_armor_string_dup(phr->login);
  }
  if (extra->contest_arm) xfree(extra->contest_arm);
  if (phr->locale_id == 0 && cnts->name_en) {
    extra->contest_arm = html_armor_string_dup(cnts->name_en);
  } else {
    extra->contest_arm = html_armor_string_dup(cnts->name);
  }

  snprintf(hid_buf, sizeof(hid_buf),
           "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">",
           phr->session_id);
  phr->hidden_vars = hid_buf;

  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST
      && actions_table[phr->action]) {
    actions_table[phr->action](state, p, fout, phr, cnts, extra);
  } else {
    priv_main_page(state, p, fout, phr, cnts, extra);
  }
}

void
new_server_handle_http_request(struct server_framework_state *state,
                               struct client_state *p,
                               FILE *fout,
                               struct http_request_info *phr)
{
  const unsigned char *script_filename = 0;
  path_t last_name;
  const unsigned char *http_host;
  const unsigned char *script_name;
  const unsigned char *protocol = "http";
  const unsigned char *remote_addr;
  const unsigned char *s;
  path_t self_url;
  int r, n;

  // make a self-referencing URL
  if (ns_getenv(phr, "SSL_PROTOCOL")) {
    phr->ssl_flag = 1;
    protocol = "https";
  }
  if (!(http_host = ns_getenv(phr, "HTTP_HOST"))) http_host = "localhost";
  if (!(script_name = ns_getenv(phr, "SCRIPT_NAME")))
    script_name = "/cgi-bin/new-client";
  snprintf(self_url, sizeof(self_url), "%s://%s%s", protocol,
           http_host, script_name);
  phr->self_url = self_url;

  // parse the client IP address
  if (!(remote_addr = ns_getenv(phr, "REMOTE_ADDR")))
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "REMOTE_ADDR does not exist");
  if (!strcmp(remote_addr, "::1")) remote_addr = "127.0.0.1";
  if (xml_parse_ip(0, 0, 0, remote_addr, &phr->ip) < 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse REMOTE_ADDR");

  // parse the contest_id
  if ((r = ns_cgi_param(phr, "contest_id", &s)) < 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse contest_id");
  if (r > 0) {
    if (sscanf(s, "%d%n", &phr->contest_id, &n) != 1
        || s[n] || phr->contest_id <= 0)
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "cannot parse contest_id");
  }

  // parse the session_id
  if ((r = ns_cgi_param(phr, "SID", &s)) < 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse SID");
  if (r > 0) {
    if (sscanf(s, "%llx%n", &phr->session_id, &n) != 1
        || s[n] || !phr->session_id)
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "cannot parse SID");
  }

  // parse the locale_id
  if ((r = ns_cgi_param(phr, "locale_id", &s)) < 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse locale_id");
  if (r > 0) {
    if (sscanf(s, "%d%n", &phr->locale_id, &n) != 1 || s[n]
        || phr->locale_id < 0)
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "cannot parse locale_id");
  }

  // parse the action
  if ((s = ns_cgi_nname(phr, "action_", 7))) {
    if (sscanf(s, "action_%d%n", &phr->action, &n) != 1 || s[n]
        || phr->action <= 0)
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "cannot parse action");
  } else if ((r = ns_cgi_param(phr, "action", &s)) < 0) {
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse action");
  } else if (r > 0) {
    if (sscanf(s, "%d%n", &phr->action, &n) != 1 || s[n]
        || phr->action <= 0)
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "cannot parse action");
  }

  // check how we've been called
  script_filename = ns_getenv(phr, "SCRIPT_FILENAME");
  if (!script_filename && phr->arg_num > 0) script_filename = phr->args[0];
  if (!script_filename)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot get script filename");

  os_rGetLastname(script_filename, last_name, sizeof(last_name));
  // FIXME: call either non-privileged, or privileged page generator

  privileged_page(state, p, fout, phr);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
