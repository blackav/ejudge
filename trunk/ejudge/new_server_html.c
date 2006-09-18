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
#include "serve_state.h"
#include "teamdb.h"
#include "prepare.h"
#include "runlog.h"
#include "html.h"
#include "watched_file.h"
#include "mime_type.h"
#include "sha.h"
#include "archive_paths.h"

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
  USER_SECTION_FIRST = 0,
  USER_SECTION_GENERAL = USER_SECTION_FIRST,
  USER_SECTION_PROBLEM_STATUS,
  USER_SECTION_PROBLEM,
  USER_SECTION_CLAR,
  USER_SECTION_SETTINGS,

  USER_SECTION_LAST,
};

static struct contest_extra **extras = 0;
static size_t extra_a = 0;

static const unsigned char * const user_section_names[] =
{
  [USER_SECTION_GENERAL] = __("General information"),
  [USER_SECTION_PROBLEM_STATUS] = __("Problem statistics"),
  [USER_SECTION_PROBLEM] = __("Problems"),
  [USER_SECTION_CLAR] = __("Clarifications"),
  [USER_SECTION_SETTINGS] = __("Settings"),
};

static void unprivileged_page_login(struct server_framework_state *state,
                                    struct client_state *p,
                                    FILE *fout,
                                    struct http_request_info *phr);

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

static struct contest_extra *
try_contest_extra(int contest_id)
{
  if (contest_id <= 0 || contest_id > MAX_CONTEST_ID) return 0;
  if (contest_id >= extra_a) return 0;
  return extras[contest_id];
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

static int
ns_cgi_param_bin(const struct http_request_info *phr,
                 const unsigned char *param,
                 const unsigned char **p_value,
                 size_t *p_size)
{
  int i;

  if (!param) return -1;
  for (i = 0; i < phr->param_num; i++)
    if (!strcmp(phr->param_names[i], param))
      break;
  if (i >= phr->param_num) return 0;
  *p_value = phr->params[i];
  *p_size = phr->param_sizes[i];
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
  int r, contest_id = 0;
  struct contest_extra *e;

  info("userlist-server fd ready");
  while (1) {
    r = userlist_clnt_read_notification(ul_conn, &contest_id);
    if (r == ULS_ERR_UNEXPECTED_EOF) {
      info("userlist-server disconnect");
      close_ul_connection(state);
      break;
    } else if (r < 0) {
      err("userlist-server error: %s", userlist_strerror(-r));
      close_ul_connection(state);
      break;
    } else {
      e = try_contest_extra(contest_id);
      if (!e) {
        err("userlist-server notification: %d - no such contest", contest_id);
        break;
      } else {
        info("userlist-server notification: %d", contest_id);
        if (e->serve_state && e->serve_state->teamdb_state)
          teamdb_set_update_flag(e->serve_state->teamdb_state);
        if (userlist_clnt_bytes_available(ul_conn) <= 0) break;
      }
    }
    info("userlist-server fd has more data");
  }
}

static void
ul_notification_callback(void *user_data, int contest_id)
{
  struct contest_extra *e;

  e = try_contest_extra(contest_id);
  if (!e) {
    err("userlist-server notification: %d - no such contest", contest_id);
  } else {
    info("userlist-server notification: %d", contest_id);
    if (e->serve_state && e->serve_state->teamdb_state)
      teamdb_set_update_flag(e->serve_state->teamdb_state);
  }
}

static int
open_ul_connection(struct server_framework_state *state)
{
  struct server_framework_watch w;
  int r, contest_id;
  struct contest_extra *e;

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

  userlist_clnt_set_notification_callback(ul_conn, ul_notification_callback, 0);

  // add notifications for all the active contests
  for (contest_id = 1; contest_id < extra_a; contest_id++) {
    if (!(e = extras[contest_id]) || !e->serve_state) continue;
    if ((r = userlist_clnt_notify(ul_conn, ULS_ADD_NOTIFY, contest_id)) < 0) {
      err("open_connection: cannot add notification: %s",
          userlist_strerror(-r));
      close_ul_connection(state);
      return -1;
    }
  }

  info("running as %s (%d)", ul_login, ul_uid);
  return 0;
}

static int
list_all_users_callback(void *user_data, int contest_id, unsigned char **p_xml)
{
  struct server_framework_state *state = (struct server_framework_state *) user_data;
  if (open_ul_connection(state) < 0) return -1;

  if (userlist_clnt_list_all_users(ul_conn, ULS_LIST_STANDINGS_USERS,
                                   contest_id, p_xml) < 0) return -1;
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

static unsigned char fancy_header[] =
"<html><head><meta charset=\"%C\">"
"<link rel=\"stylesheet\" href=\"/ejudge/unpriv.css\" type=\"text/css\">"
"<title>%H</title></head>"
"<body topmargin=\"0\" leftmargin=\"0\" bottommargin=\"0\" scroll=\"auto\" valign=\"top\">"
"<div id=\"container\"><div id=\"left-block\">"
"<img src=\"/ejudge/logo.gif\" align=\"left\" height=\"100\"></div>"
"<div id=\"center-block\">"
"<div class=\"main\">%H</div><div class=\"search_actions\">&nbsp;</div>\n";
static unsigned char fancy_footer[] =
"</div>"
"<div id=\"footer\">%R</div>"
"</div>"
"</BODY>"
"</HTML>";

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
html_put_footer(FILE *out, unsigned char const *template, int locale_id)
{
  if (!template) template = default_footer_template;
  process_template(out, template, 0, 0, 0, get_copyright(locale_id), 0);
}

static const unsigned char *role_strs[] =
  {
    __("Contestant"),
    __("Observer"),
    __("Examiner"),
    __("Chief examiner"),
    __("Coordinator"),
    __("Judge"),
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

unsigned char *
new_serve_url(unsigned char *buf, size_t size,
              const struct http_request_info *phr,
              int action, const char *format, ...)
{
  unsigned char fbuf[1024];
  unsigned char abuf[64];
  const unsigned char *sep = "";
  va_list args;

  fbuf[0] = 0;
  if (format && *format) {
    va_start(args, format);
    vsnprintf(fbuf, sizeof(fbuf), format, args);
    va_end(args);
  }
  if (fbuf[0]) sep = "&";

  abuf[0] = 0;
  if (action > 0) snprintf(abuf, sizeof(abuf), "&action=%d", action);

  snprintf(buf, size, "%s?SID=%016llx%s%s%s", phr->self_url,
           phr->session_id, abuf, sep, fbuf);
  return buf;
}

static const unsigned char * const submit_button_labels[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_UPDATE_STANDINGS_1] = __("Update public standings"),
  [NEW_SRV_ACTION_RESET_1] = __("Reset the contest!"),
  [NEW_SRV_ACTION_SUSPEND] = __("Suspend clients"),
  [NEW_SRV_ACTION_RESUME] = __("Resume clients"),
  [NEW_SRV_ACTION_TEST_SUSPEND] = __("Suspend testing"),
  [NEW_SRV_ACTION_TEST_RESUME] = __("Resume testing"),
  [NEW_SRV_ACTION_PRINT_SUSPEND] = __("Suspend printing"),
  [NEW_SRV_ACTION_PRINT_RESUME] = __("Resume printing"),
  [NEW_SRV_ACTION_SET_JUDGING_MODE] = __("Set judging mode"),
  [NEW_SRV_ACTION_SET_ACCEPTING_MODE] = __("Set accepting mode"),
  [NEW_SRV_ACTION_GENERATE_PASSWORDS_1] = __("Regenerate contest passwords!"),
  [NEW_SRV_ACTION_CLEAR_PASSWORDS_1] = __("Clear contest passwords!"),
  [NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1] = __("Regenerate registration passwords!"),
  [NEW_SRV_ACTION_RELOAD_SERVER_1] = __("Reload config files"),
  [NEW_SRV_ACTION_PRIV_SUBMIT_CLAR] = __("Send clarification"),
  [NEW_SRV_ACTION_CHANGE_PASSWORD] = __("Change password"),
  [NEW_SRV_ACTION_CHANGE_LANGUAGE] = __("Switch language"),
  [NEW_SRV_ACTION_RESET_FILTER] = __("Reset filter"),
  [NEW_SRV_ACTION_CLEAR_RUN] = __("Clear"),
  [NEW_SRV_ACTION_CHANGE_STATUS] = __("Change"),
  [NEW_SRV_ACTION_REJUDGE_ALL_1] = __("Rejudge all"),
  [NEW_SRV_ACTION_REJUDGE_SUSPENDED_1] = __("Judge suspended runs"),
  [NEW_SRV_ACTION_REJUDGE_DISPLAYED_1] = __("Rejudge displayed runs"),
  [NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1] = __("Full rejudge displayed runs"),
  [NEW_SRV_ACTION_SQUEEZE_RUNS] = __("Squeeze runs"),
  [NEW_SRV_ACTION_RESET_CLAR_FILTER] = __("Reset filter"),
};

unsigned char *
new_serve_submit_button(unsigned char *buf, size_t size,
                        const unsigned char *var_name, int action,
                        const unsigned char *label)
{
  if (!var_name) var_name = "action";
  if (!label && action > 0 && action < NEW_SRV_ACTION_LAST)
    label = gettext(submit_button_labels[action]);
  if (!label) label = "Submit";
  snprintf(buf, size,
           "<button type=\"submit\" name=\"%s\" value=\"%d\">%s</button>",
           var_name, action, label);
  return buf;
}

static void
html_refresh_page(struct server_framework_state *state,
                  FILE *fout,
                  struct http_request_info *phr,
                  int new_action)
{
  unsigned char url[1024];

  new_serve_url(url, sizeof(url), phr, new_action, 0);

  fprintf(fout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\n\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><meta http-equiv=\"Refresh\" content=\"%d; url=%s\"><title>%s</title></head><body><h1>%s</h1><p>If autorefresh does not work, follow <a href=\"%s\">this</a> link.</p></body></html>\n", EJUDGE_CHARSET, EJUDGE_CHARSET, 1, url, "Operation successful", "Operation successful", url);
}

static void
html_refresh_page_2(struct server_framework_state *state,
                    FILE *fout,
                    const unsigned char *url)
{
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

  l10n_setlocale(phr->locale_id);
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
  html_put_footer(fout, 0, phr->locale_id);
  l10n_setlocale(0);
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
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header) header = fancy_header;
    if (!footer) footer = fancy_footer;
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
  html_put_footer(fout, footer, phr->locale_id);
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
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header) header = fancy_header;
    if (!footer) footer = fancy_footer;
  }
  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id, _("Invalid parameter"));
  fprintf(fout, "<p>%s</p>\n",
          _("A request parameter is invalid. Please, contact the site administrator."));
  html_put_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
}

static void
html_err_service_not_available(struct server_framework_state *state,
                               struct client_state *p,
                               FILE *fout,
                               struct http_request_info *phr,
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
  err("%d: service not available: %s", p->id, buf);

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = get_contest_extra(phr->contest_id);
  if (extra) {
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  }

  // try fancy headers
  if (!header) header = fancy_header;
  if (!footer) footer = fancy_footer;

  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id,
                  _("Service not available"));
  fprintf(fout, "<p>%s</p>\n",
          _("Service that you requested is not available."));
  html_put_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
}

static void
html_err_contest_not_available(struct server_framework_state *state,
                               struct client_state *p,
                               FILE *fout,
                               struct http_request_info *phr,
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
  err("%d: contest not available: %s", p->id, buf);

  if (phr->contest_id > 0) contests_get(phr->contest_id, &cnts);
  if (cnts) extra = get_contest_extra(phr->contest_id);
  if (extra) {
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  }

  // try fancy headers
  if (!header) header = fancy_header;
  if (!footer) footer = fancy_footer;

  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id,
                  _("Contest not available"));
  fprintf(fout, "<p>%s</p>\n",
          _("The contest is temporarily not available. Please, retry the request a bit later."));
  html_put_footer(fout, footer, phr->locale_id);
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
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header) header = fancy_header;
    if (!footer) footer = fancy_footer;
  }
  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id, _("User database server is down"));
  fprintf(fout, "<p>%s</p>\n",
          _("The user database server is currently not available. Please, retry the request later."));
  html_put_footer(fout, footer, phr->locale_id);
  l10n_setlocale(0);
}

void
new_server_html_err_internal_error(struct server_framework_state *state,
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
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header) header = fancy_header;
    if (!footer) footer = fancy_footer;
  }
  l10n_setlocale(phr->locale_id);
  html_put_header(fout, header, 0, 0, phr->locale_id, _("Internal error"));
  fprintf(fout, "<p>%s</p>\n",
          _("Your request has caused an internal server error. Please, report it as a bug."));
  html_put_footer(fout, footer, phr->locale_id);
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
    watched_file_update(&extra->header, cnts->team_header_file, cur_time);
    watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
    header = extra->header.text;
    footer = extra->footer.text;
  } else if (extra && priv_mode) {
    watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
    watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
    header = extra->priv_header.text;
    footer = extra->priv_footer.text;
  }
  if (!priv_mode) {
    if (!header) header = fancy_header;
    if (!footer) footer = fancy_footer;
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
  html_put_footer(fout, footer, phr->locale_id);
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
          new_serve_url(url, sizeof(url), phr, back_action, 0));
  html_put_footer(fout, extra->footer_txt, phr->locale_id);
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
  if (phr->role == USER_ROLE_CONTESTANT)
    return unprivileged_page_login(state, p, fout, phr);

  // analyze IP limitations
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (!contests_check_master_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "%s://%s is not allowed for MASTER for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "%s://%s is not allowed for MASTER for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
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
      return new_server_html_err_internal_error(state, p, fout, phr, 1,
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
  } else if (phr->role == USER_ROLE_ADMIN) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0)
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "user %s does not have JUDGE_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "user %s has no permission to login as role %d for contest %d", phr->login, phr->role, phr->contest_id);
  }

  new_server_get_session(phr->session_id, 0);
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
  case NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER:
    role = USER_ROLE_EXAMINER;
    break;
  case NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER:
  case NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER:
    role = USER_ROLE_CHIEF_EXAMINER;
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
    case NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER:
    case NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER:
    case NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR:
      if (nsdb_add_role(uset.v[i], phr->contest_id, role) < 0) {
        fprintf(log_f, "add_role (%d,%d,%d) failed\n",
                uset.v[i], phr->contest_id, role);
      }
      break;

    case NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER:
    case NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER:
    case NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER:
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
    return new_server_html_err_internal_error(state, p, fout, phr, 1,
                                              "list_all_users failed: %s",
                                              userlist_strerror(-r));
  users = userlist_parse_str(xml_text);
  xfree(xml_text); xml_text = 0;
  if (!users)
    return new_server_html_err_internal_error(state, p, fout, phr, 1,
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
  fprintf(fout, "<tr><td><a href=\"%s\">Back</a></td><td>Return to the main page</td></tr>\n", new_serve_url(url, sizeof(url), phr, 0, 0));
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

  html_put_footer(fout, extra->footer_txt, phr->locale_id);
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

  // collect all information about allowed MASTER and JUDGE logins
  for (op = cnts->capabilities.first; op;
       op = (struct opcap_list_item*) op->b.right) {
    role_mask = 0;
    if (opcaps_check(op->caps, OPCAP_MASTER_LOGIN) >= 0) {
      role_mask |= (1 << USER_ROLE_ADMIN);
    }
    if (opcaps_check(op->caps, OPCAP_JUDGE_LOGIN) >= 0) {
      role_mask |= (1 << USER_ROLE_JUDGE);
    }
    if (!role_mask) continue;
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
  fprintf(fout, "<tr><td><a href=\"%s\">Back</a></td><td>Return to the main page</td></tr>\n", new_serve_url(url, sizeof(url), phr, 0, 0));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_REMOVE, _("Remove"), _("Remove the selected users from the list (ADMINISTRATORs cannot be removed)"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER, _("Add OBSERVER"), _("Add the OBSERVER role to the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER, _("Del OBSERVER"), _("Remove the OBSERVER role from the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER, _("Add EXAMINER"), _("Add the EXAMINER role to the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER, _("Del EXAMINER"), _("Remove the EXAMINER role from the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER, _("Add CHIEF EXAMINER"), _("Add the CHIEF EXAMINER role to the selected users"));
  fprintf(fout, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td><td>%s</td></tr>\n", NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER, _("Del CHIEF EXAMINER"), _("Remove the CHIEF EXAMINER role from the selected users"));
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

  html_put_footer(fout, extra->footer_txt, phr->locale_id);
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

void
unpriv_print_status(struct server_framework_state *state,
                    struct client_state *p,
                    FILE *fout,
                    struct http_request_info *phr,
                    const struct contest_desc *cnts,
                    struct contest_extra *extra,
                    time_t start_time, time_t stop_time, time_t duration,
                    time_t sched_time,
                    time_t fog_start_time)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const unsigned char *s = 0;
  unsigned char duration_buf[128];
  time_t tmpt;

  fprintf(fout, "<hr><a name=\"status\"></a><%s>%s</%s>\n",
          cnts->team_head_style, _("Server status"),
          cnts->team_head_style);
  if (stop_time > 0) {
    if (duration > 0 && global->board_fog_time > 0
        && global->board_unfog_time > 0
        && cs->current_time < stop_time + global->board_unfog_time
        && !cs->standings_updated) {
      s = _("The contest is over (standings are frozen)");
    } else {
      s = _("The contest is over");
    }
  } else if (start_time > 0) {
    if (fog_start_time > 0 && cs->current_time >= fog_start_time)
      s = _("The contest is in progress (standings are frozen)");
    else
      s = _("The contest is in progress");
  } else {
    s = _("The contest is not started");
  }
  fprintf(fout, "<p><big><b>%s</b></big></p>\n", s);

  if (start_time > 0) {
    if (global->score_system_val == SCORE_OLYMPIAD) {
      if (cs->accepting_mode)
        s = _("Participants' solutions are being accepted");
      else
        s = _("Participants' solutions are being judges");
      fprintf(fout, "<p><big><b>%s</b></big></p>\n", s);
    }
  }

  if (cs->clients_suspended) {
    fprintf(fout, "<p><big><b>%s</b></big></p>\n",
            _("Team requests are suspended"));
  }

  if (start_time > 0) {
    if (cs->testing_suspended) {
      fprintf(fout, "<p><big><b>%s</b></big></p>\n",
             _("Testing of team's submits is suspended"));
    }
    if (cs->printing_suspended) {
      fprintf(fout, "<p><big><b>%s</b></big></p>\n",
             _("Print requests are suspended"));
    }
  }

  fprintf(fout, "<table border=\"0\">");
  fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
          _("Server time"), ctime(&cs->current_time));
  if (start_time > 0) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Contest start time"), ctime(&start_time));
  }
  if (!global->virtual && start_time <= 0 && sched_time > 0) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Planned start time"), ctime(&sched_time));
  }
  if (stop_time <= 0 && (duration > 0 || global->contest_finish_time_d <= 0)) {
    if (duration > 0) {
      duration_str(0, duration, 0, duration_buf, 0);
    } else {
      snprintf(duration_buf, sizeof(duration_buf), "%s", _("Unlimited"));
    }
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Duration"), duration_buf);
  }
  if (start_time > 0 && stop_time <= 0 && duration > 0) {
    tmpt = start_time + duration;
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Scheduled end time"), ctime(&tmpt));
  } else if (start_time > 0 && stop_time <= 0 && duration <= 0
             && global->contest_finish_time_d > 0) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Scheduled end time"), ctime(&global->contest_finish_time_d));
  } else if (stop_time) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("End time"), ctime(&stop_time));
  }

  if (start_time > 0 && stop_time <= 0 && fog_start_time > 0) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Standings freeze time"), ctime(&fog_start_time));
  } else if (stop_time > 0 && duration > 0 && global->board_fog_time > 0
             && global->board_unfog_time > 0 && !cs->standings_updated
             && cs->current_time < stop_time + global->board_unfog_time) {
    tmpt = stop_time + global->board_unfog_time;
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Standings unfreeze time"), ctime(&tmpt));
  }

  if (start_time > 0 && stop_time <= 0 && duration > 0) {
    duration_str(0, cs->current_time, start_time, duration_buf, 0);
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Elapsed time"), duration_buf);
    duration_str(0, start_time + duration - cs->current_time, 0,
                 duration_buf, 0);
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Remaining time"), duration_buf);
  }
  fprintf(fout, "</table>\n");
}

static void
priv_main_page(struct server_framework_state *state,
               struct client_state *p,
               FILE *fout,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  time_t start_time, sched_time, duration, stop_time, fog_start_time = 0, tmpt;
  unsigned char hbuf[1024];
  unsigned char duration_buf[128];
  const unsigned char *s;
  unsigned char bbuf[1024];
  int action;
  long long tdiff;

  run_get_times(cs->runlog_state, &start_time, &sched_time, &duration,
                &stop_time);
  if (duration > 0 && start_time && !stop_time && global->board_fog_time > 0)
    fog_start_time = start_time + duration - global->board_fog_time;
  if (fog_start_time < 0) fog_start_time = 0;

  l10n_setlocale(phr->locale_id);
  html_put_header(fout, extra->header_txt, 0, 0, phr->locale_id,
                  "%s [%s, %s]: %s", unparse_role(phr->role),
                  phr->name_arm, extra->contest_arm, _("Main page"));
  fprintf(fout, "<ul>\n");
  fprintf(fout, "<li><a href=\"%s\">View regular users</a></li>\n",
          new_serve_url(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_USERS, 0));
  fprintf(fout, "<li><a href=\"%s\">View privileged users</a></li>\n",
          new_serve_url(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_PRIV_USERS_VIEW, 0));
  fprintf(fout, "</ul>\n");

  /* if role == ADMIN and capability CONTROL_CONTEST */

  fprintf(fout, "<hr><a name=\"status\"></a><%s>%s</%s>\n",
          /*cnts->priv_head_style*/ "h2", _("Server status"),
          /*cnts->priv_head_style*/ "h2");
  if (stop_time > 0) {
    if (duration > 0 && global->board_fog_time > 0
        && global->board_unfog_time > 0
        && cs->current_time < stop_time + global->board_unfog_time
        && !cs->standings_updated) {
      s = _("The contest is over (standings are frozen)");
    } else {
      s = _("The contest is over");
    }
  } else if (start_time > 0) {
    if (fog_start_time > 0 && cs->current_time >= fog_start_time)
      s = _("The contest is in progress (standings are frozen)");
    else
      s = _("The contest is in progress");
  } else {
    s = _("The contest is not started");
  }
  fprintf(fout, "<p><big><b>%s</b></big></p>\n", s);

  if (global->score_system_val == SCORE_OLYMPIAD) {
    if (cs->accepting_mode)
      s = _("Participants' solutions are being accepted");
    else
      s = _("Participants' solutions are being judges");
    fprintf(fout, "<p><big><b>%s</b></big></p>\n", s);
  }

  if (cs->clients_suspended) {
    fprintf(fout, "<p><big><b>%s</b></big></p>\n",
            _("Team requests are suspended"));
  }

  if (cs->testing_suspended) {
    fprintf(fout, "<p><big><b>%s</b></big></p>\n",
            _("Testing of team's submits is suspended"));
  }
  if (cs->printing_suspended) {
    fprintf(fout, "<p><big><b>%s</b></big></p>\n",
            _("Print requests are suspended"));
  }

  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table border=\"0\">");

  fprintf(fout,
          "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
          _("Server time"), ctime(&cs->current_time));

  if (start_time <= 0) {
    fprintf(fout, "<tr><td colspan=\"2\"><b>%s</b></td><td>&nbsp;</td><td><button type=\"submit\" name=\"action\" value=\"%d\">%s</button></td></tr>\n",
            _("Contest is not started"), NEW_SRV_ACTION_START_CONTEST,
            _("Start"));
  } else {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td>",
            _("Contest start time"), ctime(&start_time));
    if (stop_time <= 0) {
      fprintf(fout, "<td><button type=\"submit\" name=\"action\" value=\"%d\">%s</button></td></tr>\n", NEW_SRV_ACTION_STOP_CONTEST, _("Stop"));
    } else if (global->enable_continue
               && (!duration || stop_time < start_time + duration)) {
      fprintf(fout, "<td><button type=\"submit\" name=\"action\" value=\"%d\">%s</button></td></tr>\n", NEW_SRV_ACTION_CONTINUE_CONTEST, _("Continue"));
    }
  }

  if (!global->virtual && start_time <= 0) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td>"
            "<td><input type=\"text\" name=\"sched_time\" size=\"16\"></td>"
            "<td><button type=\"submit\" name=\"action\" value=\"%d\">%s"
            "</button></td></tr>\n",
            _("Planned start time"),
            sched_time <= 0?_("Not set"):ctime(&sched_time),
            NEW_SRV_ACTION_SCHEDULE, _("Reschedule"));
  }

  if (global->contest_finish_time_d <= 0) {
    if (duration > 0) {
      duration_str(0, duration, 0, duration_buf, 0);
    } else {
      snprintf(duration_buf, sizeof(duration_buf), "%s", _("Unlimited"));
    }

    fprintf(fout, "<tr><td>%s:</td><td>%s</td>",_("Duration"), duration_buf);
    if (stop_time <= 0 || global->enable_continue) {
      fprintf(fout, "<td><input type=\"text\" name=\"dur\" size=\"16\"></td>"
              "<td><button type=\"submit\" name=\"action\" value=\"%d\">%s"
              "</button></td></tr>\n",
              NEW_SRV_ACTION_CHANGE_DURATION, _("Change duration"));
    } else {
      fprintf(fout, "<td>nbsp;</td><td>&nbsp;</td></tr>\n");
    }
  }

  if (start_time > 0 && stop_time <= 0 && duration > 0) {
    tmpt = start_time + duration;
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Scheduled end time"), ctime(&tmpt));
  } else if (start_time > 0 && stop_time <= 0 && duration <= 0
             && global->contest_finish_time_d > 0) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Scheduled end time"), ctime(&global->contest_finish_time_d));
  } else if (stop_time) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("End time"), ctime(&stop_time));
  }


  if (start_time > 0 && stop_time <= 0 && fog_start_time > 0) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Standings freeze time"), ctime(&fog_start_time));
  } else if (stop_time > 0 && duration > 0 && global->board_fog_time > 0
             && global->board_unfog_time > 0 && !cs->standings_updated
             && cs->current_time < stop_time + global->board_unfog_time) {
    tmpt = stop_time + global->board_unfog_time;
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Standings unfreeze time"), ctime(&tmpt));
  }

  if (start_time > 0 && stop_time <= 0 && duration > 0) {
    duration_str(0, cs->current_time, start_time, duration_buf, 0);
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Elapsed time"), duration_buf);
    duration_str(0, start_time + duration - cs->current_time, 0,
                 duration_buf, 0);
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Remaining time"), duration_buf);
  }
  fprintf(fout, "</table></form>\n");

  fprintf(fout, "<hr>\n");

  // role == ADMIN && CONTROL_CONTEST
  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "%s\n", 
          new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                  NEW_SRV_ACTION_UPDATE_STANDINGS_1, 0));
  fprintf(fout, "%s\n",
          new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                  NEW_SRV_ACTION_RESET_1, 0));
  action = NEW_SRV_ACTION_SUSPEND;
  if (cs->clients_suspended) action = NEW_SRV_ACTION_RESUME;
  fprintf(fout, "%s\n",
          new_serve_submit_button(bbuf, sizeof(bbuf), 0, action, 0));
  action = NEW_SRV_ACTION_TEST_SUSPEND;
  if (cs->testing_suspended) action = NEW_SRV_ACTION_TEST_RESUME;
  fprintf(fout, "%s\n",
          new_serve_submit_button(bbuf, sizeof(bbuf), 0, action, 0));
  if (global->enable_printing) {
    action = NEW_SRV_ACTION_PRINT_SUSPEND;
    if (cs->printing_suspended) action = NEW_SRV_ACTION_PRINT_RESUME;
    fprintf(fout, "%s\n",
            new_serve_submit_button(bbuf, sizeof(bbuf), 0, action, 0));
  }
  if (global->score_system_val == SCORE_OLYMPIAD) {
    action = NEW_SRV_ACTION_SET_JUDGING_MODE;
    if (!cs->accepting_mode) action = NEW_SRV_ACTION_SET_ACCEPTING_MODE;
    fprintf(fout, "%s\n",
            new_serve_submit_button(bbuf, sizeof(bbuf), 0, action, 0));
  }
  if (!cnts->disable_team_password) {
    fprintf(fout, "%s\n",
            new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                    NEW_SRV_ACTION_GENERATE_PASSWORDS_1, 0));
    fprintf(fout, "%s\n",
            new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                    NEW_SRV_ACTION_CLEAR_PASSWORDS_1, 0));
  }
  fprintf(fout, "%s\n",
          new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                  NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1, 0));
  fprintf(fout, "%s\n",
          new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                  NEW_SRV_ACTION_RELOAD_SERVER_1, 0));

  new_serve_write_priv_all_runs(fout, phr, cnts, extra, -1, -1, 0);

  new_serve_write_all_clars(fout, phr, cnts, extra, 0, -1, -1);

  fprintf(fout, "<hr><h2>%s</h2>", _("Compose a message to all participants"));
  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table>\n"
          "<tr>"
          "<td>%s:</td>"
          "<td><input type=\"text\" size=\"16\" name=\"msg_dest_id\"></td>"
          "</tr>\n"
          "<tr>"
          "<td>%s:</td>"
          "<td><input type=\"text\" size=\"32\" name=\"msg_dest_login\"></td>"
          "</tr>\n"
          "<tr>"
          "<td>%s:</td>"
          "<td><input type=\"text\" size=\"64\" name=\"msg_subj\"></td>"
          "</tr>\n",
          _("To user id"),
          _("To user login"),
          _("Subject"));
  if (start_time <= 0) {
    fprintf(fout, "<tr><td>%s</td><td><select name=\"msg_hide_flag\"><option value=\"0\">NO</option><option value=\"1\">YES</option></select></td></tr>\n",
            _("Do not show before the contest starts?"));
  }
  fprintf(fout, "</table>\n"
          "<p><textarea name=\"msg_text\" rows=\"20\" cols=\"60\">"
          "</textarea></p>"
          "<p>%s\n</form>\n",
          new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                  NEW_SRV_ACTION_PRIV_SUBMIT_CLAR, 0));

  /* change the password */
  fprintf(fout, "<hr><a name=\"chgpasswd\"></a>\n<%s>%s</%s>\n",
          /*cnts->priv_head_style*/ "h2",
          _("Change password"),
          /*cnts->team_head_style*/ "h2");
  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);

  fprintf(fout, "<table>\n"
          "<tr><td>%s:</td><td><input type=\"password\" name=\"oldpasswd\" size=\"16\"></td></tr>\n"
          "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd1\" size=\"16\"></td></tr>\n"
          "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd2\" size=\"16\"></td></tr>\n"
          "<tr><td colspan=\"2\">%s</td></tr>\n"
          "</table></form>",
          _("Old password"),
          _("New password"), _("Retype new password"),
          new_serve_submit_button(bbuf, sizeof(bbuf), 0, 
                                  NEW_SRV_ACTION_CHANGE_PASSWORD, 0));

#if CONF_HAS_LIBINTL - 0 == 1
  if (cs->global->enable_l10n) {
    fprintf(fout, "<hr><a name=\"chglanguage\"></a><%s>%s</%s>\n",
            cnts->team_head_style, _("Change language"),
            cnts->team_head_style);
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    fprintf(fout, "<table><tr><td>%s</td><td>", _("Change language"));
    l10n_html_locale_select(fout, phr->locale_id);
    fprintf(fout, "</td><td>%s</td></tr></table></form>\n",
            new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                    NEW_SRV_ACTION_CHANGE_LANGUAGE, 0));
  }
#endif /* CONF_HAS_LIBINTL */

  if (1 /*cs->global->show_generation_time*/) {
  gettimeofday(&phr->timestamp2, 0);
  tdiff = ((long long) phr->timestamp2.tv_sec) * 1000000;
  tdiff += phr->timestamp2.tv_usec;
  tdiff -= ((long long) phr->timestamp1.tv_sec) * 1000000;
  tdiff -= phr->timestamp1.tv_usec;
  fprintf(fout, "<hr><p%s>%s: %lld %s\n", cnts->team_par_style,
          _("Page generation time"), tdiff / 1000,
          _("msec"));
  }

  html_put_footer(fout, extra->footer_txt, phr->locale_id);
  l10n_setlocale(0);
}

typedef void (*action_handler_t)(struct server_framework_state *state,
                                 struct client_state *p,
                                 FILE *fout,
                                 struct http_request_info *phr,
                                 const struct contest_desc *cnts,
                                 struct contest_extra *extra);

static action_handler_t actions_table[NEW_SRV_ACTION_LAST] =
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
  [NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER] = priv_priv_user_operation,
  [NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER] = priv_priv_user_operation,
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
  struct teamdb_db_callbacks callbacks;

  if (!phr->session_id || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return privileged_page_login(state, p, fout, phr);

  // validate cookie
  if (open_ul_connection(state) < 0)
    return html_err_userlist_server_down(state, p, fout, phr, 1);
  if ((r = userlist_clnt_get_cookie(ul_conn, ULS_PRIV_GET_COOKIE,
                                    phr->ip, phr->ssl_flag,
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
      return new_server_html_err_internal_error(state, p, fout, phr, 1,
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
                                        "%s://%s is not allowed for MASTER for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "%s://%s is not allowed for MASTER for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
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
  } else if (phr->role == USER_ROLE_JUDGE) {
    // as for the judge program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_JUDGE_LOGIN) < 0)
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "user %s does not have JUDGE_LOGIN bit for contest %d", phr->login, phr->contest_id);
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      return html_err_permission_denied(state, p, fout, phr, 1,
                                        "user %s has no permission to login as role %d for contest %d", phr->login, phr->role, phr->contest_id);
  }

  watched_file_update(&extra->priv_header, cnts->priv_header_file, cur_time);
  watched_file_update(&extra->priv_footer, cnts->priv_footer_file, cur_time);
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
  phr->session_extra = new_server_get_session(phr->session_id, cur_time);

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.user_data = (void*) state;
  callbacks.list_all_users = list_all_users_callback;

  // invoke the contest
  if (serve_state_load_contest(phr->contest_id,
                               ul_conn,
                               &callbacks,
                               &extra->serve_state) < 0) {
    return html_err_contest_not_available(state, p, fout, phr, "");
  }

  extra->serve_state->current_time = time(0);
  
  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST
      && actions_table[phr->action]) {
    actions_table[phr->action](state, p, fout, phr, cnts, extra);
  } else {
    priv_main_page(state, p, fout, phr, cnts, extra);
  }
}

void
unprivileged_page_login_page(struct server_framework_state *state,
                             struct client_state *p,
                             FILE *fout,
                             struct http_request_info *phr)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time;
  const unsigned char *s;
  unsigned char *as;

  if (phr->contest_id <= 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return html_err_service_not_available(state, p, fout, phr,
                                          "contest_id is invalid");
  if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
    return html_err_service_not_available(state, p, fout, phr,
                                        "%s://%s is not allowed for TEAM for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  if (cnts->closed)
    return html_err_service_not_available(state, p, fout, phr,
                                          "contest %d is closed");
  if (cnts->client_disable_team)
    return html_err_service_not_available(state, p, fout, phr,
                                          "contest %d team is disabled");

  extra = get_contest_extra(phr->contest_id);
  ASSERT(extra);

  cur_time = time(0);
  watched_file_update(&extra->header, cnts->team_header_file, cur_time);
  watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
  extra->header_txt = extra->header.text;
  extra->footer_txt = extra->footer.text;
  if (!extra->header_txt) extra->header_txt = fancy_header;
  if (!extra->footer_txt) extra->footer_txt = fancy_footer;

  if (extra->contest_arm) xfree(extra->contest_arm);
  if (phr->locale_id == 0 && cnts->name_en) {
    extra->contest_arm = html_armor_string_dup(cnts->name_en);
  } else {
    extra->contest_arm = html_armor_string_dup(cnts->name);
  }

  l10n_setlocale(phr->locale_id);
  html_put_header(fout, extra->header_txt, 0, 0, phr->locale_id,
                  _("User login [%s]"), extra->contest_arm);


  html_start_form(fout, 1, phr->self_url, "");
  fprintf(fout, "<div class=\"login_actions\">\n");
  fprintf(fout, "<input type=\"hidden\" name=\"contest_id\" value=\"%d\">",
          phr->contest_id);
  fprintf(fout, "<input type=\"hidden\" name=\"role\" value=\"0\">");
  fprintf(fout, "%s:&nbsp;<input type=\"text\" size=\"8\" name=\"login\"", _("login"));
  if (ns_cgi_param(phr, "login", &s) > 0) {
    as = html_armor_string_dup(s);
    fprintf(fout, " value=\"%s\"", as);
    xfree(as);
  }
  fprintf(fout, ">&nbsp;&nbsp;\n");
  fprintf(fout, "%s:&nbsp;<input type=\"password\" size=\"8\" name=\"password\"", _("password"));
  if (ns_cgi_param(phr, "password", &s) > 0) {
    as = html_armor_string_dup(s);
    fprintf(fout, " value=\"%s\"", as);
    xfree(as);
  }
  fprintf(fout, ">&nbsp;&nbsp;\n");
  fprintf(fout, "%s:&nbsp;", _("language"));
  l10n_html_locale_select(fout, phr->locale_id);
  fprintf(fout, "&nbsp;&nbsp;\n");
  fprintf(fout, "<input type=\"submit\" value=\"%s\">\n", _("Submit"));
  fprintf(fout, "</form></div>\n");
  fprintf(fout, "<div class=\"search_actions\"><a href=\"\">%s</a>&nbsp;&nbsp;<a href=\"\">%s</a></div>", _("Registration"), _("Forgot the password?"));
  html_put_footer(fout, extra->footer_txt, phr->locale_id);
  l10n_setlocale(0);
}

static void
unprivileged_page_login(struct server_framework_state *state,
                        struct client_state *p,
                        FILE *fout,
                        struct http_request_info *phr)
{
  const unsigned char *login = 0;
  const unsigned char *password = 0;
  int r;
  const struct contest_desc *cnts = 0;

  if ((r = ns_cgi_param(phr, "login", &login)) < 0)
    return html_err_invalid_param(state, p, fout, phr, 0, "cannot parse login");
  if (!r || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return unprivileged_page_login_page(state, p, fout, phr);

  phr->login = xstrdup(login);
  if ((r = ns_cgi_param(phr, "password", &password)) <= 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse password");
  if (phr->contest_id<=0 || contests_get(phr->contest_id, &cnts)<0 || !cnts)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "invalid contest_id");
  if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
    return html_err_permission_denied(state, p, fout, phr, 0,
                                      "%s://%s is not allowed for TEAM for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  if (cnts->closed)
    return html_err_service_not_available(state, p, fout, phr,
                                          "contest %d is closed");
  if (cnts->client_disable_team)
    return html_err_service_not_available(state, p, fout, phr,
                                          "contest %d team is disabled");

  if (open_ul_connection(state) < 0)
    return html_err_userlist_server_down(state, p, fout, phr, 0);

  if ((r = userlist_clnt_team_login(ul_conn, ULS_CHECK_USER,
                                    phr->ip, phr->ssl_flag, phr->contest_id,
                                    phr->locale_id, login, password,
                                    &phr->user_id, &phr->session_id,
                                    0, &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
    case ULS_ERR_NOT_REGISTERED:
    case ULS_ERR_CANNOT_PARTICIPATE:
      return html_err_permission_denied(state, p, fout, phr, 0,
                                        "team_login failed: %s",
                                        userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return html_err_userlist_server_down(state, p, fout, phr, 0);
    default:
      return new_server_html_err_internal_error(state, p, fout, phr, 0,
                                                "team_login failed: %s",
                                                userlist_strerror(-r));
    }
  }

  new_server_get_session(phr->session_id, 0);
  html_refresh_page(state, fout, phr, NEW_SRV_ACTION_MAIN_PAGE);
}

static void
unpriv_change_language(struct server_framework_state *state,
                       struct client_state *p,
                       FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  const unsigned char *s;
  int r, n;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  int new_locale_id;

  if ((r = ns_cgi_param(phr, "locale_id", &s)) < 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse locale_id");
  if (r > 0) {
    if (sscanf(s, "%d%n", &new_locale_id, &n) != 1 || s[n] || new_locale_id < 0)
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "cannot parse locale_id");
  }

  log_f = open_memstream(&log_txt, &log_len);

  if (open_ul_connection(state) < 0) {
    html_err_userlist_server_down(state, p, fout, phr, 0);
    goto cleanup;
  }
  if ((r = userlist_clnt_set_cookie(ul_conn, ULS_SET_COOKIE_LOCALE,
                                    phr->session_id,
                                    new_locale_id)) < 0) {
    fprintf(log_f, "set_cookie failed: %s", userlist_strerror(-r));
  }

  //done:
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    html_refresh_page(state, fout, phr, NEW_SRV_ACTION_MAIN_PAGE);
  } else {
    html_error_status_page(state, p, fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE);
  }

 cleanup:
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
unpriv_change_password(struct server_framework_state *state,
                       struct client_state *p,
                       FILE *fout,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra)
{
  const unsigned char *p0 = 0, *p1 = 0, *p2 = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  int cmd, r;
  unsigned char url[1024];
  unsigned char login_buf[256];

  if (ns_cgi_param(phr, "oldpasswd", &p0) <= 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse oldpasswd");
  if (ns_cgi_param(phr, "newpasswd1", &p1) <= 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse newpasswd1");
  if (ns_cgi_param(phr, "newpasswd2", &p2) <= 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse newpasswd2");

  log_f = open_memstream(&log_txt, &log_len);

  if (strlen(p0) >= 256) {
    fprintf(log_f, _("Old password is too long"));
    goto done;
  }
  if (strcmp(p1, p2)) {
    fprintf(log_f, _("New passwords do not match"));
    goto done;
  }
  if (strlen(p1) >= 256) {
    fprintf(log_f, _("New password is too long"));
    goto done;
  }

  cmd = ULS_PRIV_SET_TEAM_PASSWD;
  if (cnts->disable_team_password) cmd = ULS_PRIV_SET_REG_PASSWD;

  if (open_ul_connection(state) < 0) {
    html_err_userlist_server_down(state, p, fout, phr, 0);
    goto cleanup;
  }
  r = userlist_clnt_set_passwd(ul_conn, cmd, phr->user_id, phr->contest_id,
                               p0, p1);
  if (r < 0) {
    fprintf(log_f, "set_passwd failed: %s", userlist_strerror(-r));
    goto done;
  }

 done:;
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    url_armor_string(login_buf, sizeof(login_buf), phr->login);
    snprintf(url, sizeof(url),
             "%s?contest_id=%d&login=%s&locale_id=%d&action=%d",
             phr->self_url, phr->contest_id, login_buf, phr->locale_id,
             NEW_SRV_ACTION_LOGIN_PAGE);
    html_refresh_page_2(state, fout, url);
  } else {
    html_error_status_page(state, p, fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE);
  }

 cleanup:;
  if (log_f) fclose(log_f);
  xfree(log_txt);
}

static void
unpriv_submit_run(struct server_framework_state *state,
                  struct client_state *p,
                  FILE *fout,
                  struct http_request_info *phr,
                  const struct contest_desc *cnts,
                  struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  const struct section_language_data *lang = 0;
  char *log_txt = 0;
  size_t log_len = 0;
  FILE *log_f = 0;
  int prob_id, n, lang_id = 0, i, ans, max_ans, j;
  const unsigned char *s, *run_text = 0;
  size_t run_size = 0, ans_size;
  unsigned char *ans_buf, *ans_map;
  time_t start_time, stop_time, user_deadline = 0;
  const unsigned char *login, *mime_type_str = 0;
  char **lang_list;
  int mime_type = 0;
  ruint32_t shaval[5];
  int variant = 0, run_id, arch_flags = 0;
  unsigned char *acc_probs = 0;
  struct timeval precise_time;
  path_t run_path;

  if (ns_cgi_param(phr, "prob_id", &s) <= 0)
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "prob_id is not set or binary");
  if (sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n])
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "cannot parse prob_id");
  if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id]))
    return html_err_invalid_param(state, p, fout, phr, 0,
                                  "prob_id is invalid");

  // "STANDARD" problems need programming language identifier
  if (prob->type_val == PROB_TYPE_STANDARD) {
    if (ns_cgi_param(phr, "lang_id", &s) <= 0)
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "lang_id is not set or binary");
    if (sscanf(s, "%d%n", &lang_id, &n) != 1 || s[n])
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "cannot parse lang_id");
    if (lang_id <= 0 || lang_id > cs->max_lang || !(lang = cs->langs[lang_id]))
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "lang_id is invalid");
  }

  switch (prob->type_val) {
  case PROB_TYPE_STANDARD:      // "file"
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
    if (!ns_cgi_param_bin(phr, "file", &run_text, &run_size))
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "\"file\" parameter is not set");
    break;
  case PROB_TYPE_SELECT_MANY:   // "ans_*"
    for (i = 0, max_ans = -1, ans_size = 0; i < phr->param_num; i++)
      if (!strncmp(phr->param_names[i], "ans_", 4)) {
        if (sscanf(phr->param_names[i] + 4, "%d%n", &ans, &n) != 1
            || phr->param_names[i][4 + n])
          return html_err_invalid_param(state, p, fout, phr, 0,
                                        "\"ans_*\" parameter is invalid");
        if (ans < 0 || ans > 65535)
          return html_err_invalid_param(state, p, fout, phr, 0,
                                        "\"ans_*\" parameter is out of range");
        if (ans > max_ans) max_ans = ans;
        ans_size += 7;
      }
    if (max_ans < 0) {
      run_text = "";
      run_size = 0;
      break;
    }
    XALLOCAZ(ans_map, max_ans + 1);
    for (i = 0; i < phr->param_num; i++)
      if (!strncmp(phr->param_names[i], "ans_", 4)) {
        sscanf(phr->param_names[i] + 4, "%d", &ans);
        ans_map[ans] = 1;
      }
    XALLOCA(ans_buf, ans_size);
    run_text = ans_buf;
    for (i = 0, run_size = 0; i <= max_ans; i++)
      if (ans_map[i]) {
        if (run_size > 0) ans_buf[run_size++] = ' ';
        run_size += sprintf(ans_buf + run_size, "%d", i);
      }
    ans_map[run_size] = 0;
    break;
  default:
    abort();
  }

  switch (prob->type_val) {
  case PROB_TYPE_STANDARD:
    if (!lang->binary && strlen(run_text) != run_size) 
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "binary submission");
    break;

  case PROB_TYPE_OUTPUT_ONLY:
    if (!prob->binary_input && strlen(run_text) != run_size) 
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "binary submission");
    break;

  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
  case PROB_TYPE_SELECT_MANY:
    if (strlen(run_text) != run_size) 
      return html_err_invalid_param(state, p, fout, phr, 0,
                                    "binary submission");
    break;
  }

  if (global->virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }

  log_f = open_memstream(&log_txt, &log_len);

  if (cs->clients_suspended) {
    fprintf(log_f, _("Client's requests are suspended.\nPlease wait until the contest administrator resumes the contest."));
    goto done;
  }
  if (!start_time) {
    fprintf(log_f, _("The contest is not started."));
    goto done;
  }
  if (stop_time) {
    fprintf(log_f, _("The contest is finished."));
    goto done;
  }
  if (serve_check_user_quota(cs, phr->user_id, run_size) < 0) {
    fprintf(log_f, _("User quota exceeded.\nThis submit is too large, you already have too many submits,\nor the total size of your submits is too big."));
    goto done;
  }
  // problem submit start time
  if (prob->t_start_date >= 0 && cs->current_time < prob->t_start_date) {
    fprintf(log_f, _("This problem is not yet available."));
    goto done;
  }
  // personal deadline
  if (prob->pd_total > 0) {
    login = teamdb_get_login(cs->teamdb_state, phr->user_id);
    for (i = 0; i < prob->pd_total; i++) {
      if (!strcmp(login, prob->pd_infos[i].login)) {
        user_deadline = prob->pd_infos[i].deadline;
        break;
      }
    }
  }
  // common problem deadline
  if (user_deadline <= 0) user_deadline = prob->t_deadline;
  if (user_deadline > 0 && cs->current_time >= user_deadline) {
    fprintf(log_f, _("Deadline for this problem is expired."));
    goto done;
  }
  /* check for disabled languages */
  if (lang_id > 0) {
    if (lang->disabled) {
      fprintf(log_f, _("This language is disabled for use."));
      goto done;
    }

    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (!lang_list[i]) {
        fprintf(log_f, _("The language %s is not available for this problem."),
                lang->short_name);
        goto done;
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], lang->short_name))
          break;
      if (lang_list[i]) {
        fprintf(log_f, _("The language %s is disabled for this problem."),
                lang->short_name);
        goto done;
      }
    }
  } else {
    // guess the content-type and check it against the list
    if ((mime_type = mime_type_guess(cs->global->diff_work_dir,
                                     run_text, run_size)) < 0) {
      fprintf(log_f, _("Cannot guess the content type."));
      goto done;
    }
    mime_type_str = mime_type_get_type(mime_type);
    if (prob->enable_language) {
      lang_list = prob->enable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (!lang_list[i]) {
        fprintf(log_f,
                _("The content type %s is not available for this problem."),
                mime_type_str);
        goto done;
      }
    } else if (prob->disable_language) {
      lang_list = prob->disable_language;
      for (i = 0; lang_list[i]; i++)
        if (!strcmp(lang_list[i], mime_type_str))
          break;
      if (lang_list[i]) {
        fprintf(log_f, _("The content type %s is disabled for this problem."),
                mime_type_str);
        goto done;
      }
    }
  }

  if (prob->variant_num > 0) {
    if ((variant = find_variant(cs, phr->user_id, prob_id)) <= 0) {
      fprintf(log_f, _("No assigned variant."));
      goto done;
    }
  }

  sha_buffer(run_text, run_size, shaval);
  if ((run_id = run_find_duplicate(cs->runlog_state, phr->user_id, prob_id,
                                   lang_id, variant, run_size, shaval)) >= 0) {
    fprintf(log_f, _("This submit is duplicate of the run %d."), run_id);
    goto done;
  }

  if (global->disable_submit_after_ok
      && global->score_system_val != SCORE_OLYMPIAD && !cs->accepting_mode) {
    XALLOCAZ(acc_probs, cs->max_prob + 1);
    run_get_accepted_set(cs->runlog_state, phr->user_id,
                         cs->accepting_mode, cs->max_prob, acc_probs);
    if (acc_probs[prob_id]) {
      fprintf(log_f, _("This problem is already solved."));
      goto done;
    }
  }

  if (prob->require) {
    if (!acc_probs) {
      XALLOCAZ(acc_probs, cs->max_prob + 1);
      run_get_accepted_set(cs->runlog_state, phr->user_id,
                           cs->accepting_mode, cs->max_prob, acc_probs);
    }
    for (i = 0; prob->require[i]; i++) {
      for (j = 1; j <= cs->max_prob; j++)
        if (cs->probs[j] && !strcmp(cs->probs[j]->short_name, prob->require[i]))
          break;
      if (j > cs->max_prob || !acc_probs[j]) break;
    }
    if (prob->require[i]) {
      fprintf(log_f, _("Not all pre-required problems are solved."));
      goto done;
    }
  }

  // OK, so all checks are done, now we add this submit to the database
  gettimeofday(&precise_time, 0);

  run_id = run_add_record(cs->runlog_state, 
                          precise_time.tv_sec, precise_time.tv_usec,
                          run_size, shaval,
                          phr->ip, phr->ssl_flag,
                          phr->locale_id, phr->user_id,
                          prob_id, lang_id, 0, 0, mime_type);
  if (run_id < 0) {
    fprintf(log_f, _("Cannot add the record to the database."));
    goto done;
  }
  serve_move_files_to_insert_run(cs, run_id);
                          
  arch_flags = archive_make_write_path(cs, run_path, sizeof(run_path),
                                       global->run_archive_dir, run_id,
                                       run_size, 0);
  if (arch_flags < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    fprintf(log_f, _("Cannot allocate disk space."));
    goto done;
  }
  if (archive_dir_prepare(cs, global->run_archive_dir, run_id, 0, 0) < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    fprintf(log_f, _("Cannot allocate disk space."));
    goto done;
  }
  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    fprintf(log_f, _("Cannot write to the disk."));
    goto done;
  }

  if (prob->type == PROB_TYPE_STANDARD) {
    if (prob->disable_auto_testing > 0
        || (prob->disable_testing > 0 && prob->enable_compilation <= 0)
        || lang->disable_auto_testing || lang->disable_testing) {
      run_change_status(cs->runlog_state, run_id, RUN_PENDING, 0, -1, 0);
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: pending\n"
                      "Run-id: %d\n"
                      "  Testing disabled for this problem or language\n",
                      run_id);
    } else {
      if (serve_compile_request(cs, run_text, run_size, run_id,
                                lang->compile_id, phr->locale_id, 0,
                                lang->src_sfx,
                                lang->compiler_env, -1, 0) < 0) {
        fprintf(log_f, _("Cannot put the run to the compilation queue."));
        goto done;
      }
      serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                      "Command: submit\n"
                      "Status: ok\n"
                      "Run-id: %d\n", run_id);
    }
  } else {
  }

 done:;
  fclose(log_f); log_f = 0;
  if (!log_txt || !*log_txt) {
    html_refresh_page(state, fout, phr, NEW_SRV_ACTION_MAIN_PAGE);
  } else {
    html_error_status_page(state, p, fout, phr, cnts, extra, log_txt,
                           NEW_SRV_ACTION_MAIN_PAGE);
  }

  //cleanup:;
  if (log_f) fclose(log_f);
  xfree(log_txt);

}

static int
is_problem_deadlined(serve_state_t cs,
                     int problem_id,
                     const unsigned char *user_login,
                     time_t *p_deadline)
{
  time_t user_deadline = 0;
  int pdi;
  struct pers_dead_info *pdinfo;

  if (problem_id <= 0 || problem_id > cs->max_prob) return 1;
  if (!cs->probs[problem_id]) return 1;

  user_deadline = 0;
  for (pdi = 0, pdinfo = cs->probs[problem_id]->pd_infos;
       pdi < cs->probs[problem_id]->pd_total;
       pdi++, pdinfo++) {
    if (!strcmp(user_login, pdinfo->login)) {
      user_deadline = pdinfo->deadline;
      break;
    }
  }
  if (!user_deadline) user_deadline = cs->probs[problem_id]->t_deadline;
  if (p_deadline) *p_deadline = user_deadline;

  if (!user_deadline) return 0;
  return (cs->current_time >= user_deadline);
}

static void
html_problem_selection(serve_state_t cs,
                       FILE *fout,
                       struct http_request_info *phr,
                       const unsigned char *solved_flag,
                       const unsigned char *accepted_flag,
                       const unsigned char *var_name,
                       int light_mode,
                       time_t start_time)
{
  int i, pdi, dpi, j, k;
  time_t user_deadline = 0;
  int user_penalty = 0, variant = 0;
  struct pers_dead_info *pdinfo;
  unsigned char deadline_str[64];
  unsigned char penalty_str[64];
  unsigned char problem_str[128];
  const unsigned char *problem_ptr = 0;
  const struct section_problem_data *prob;

  if (!var_name) var_name = "prob_id";

  fprintf(fout, "<select name=\"%s\"><option value=\"\"></option>\n", var_name);

  for (i = 1; i <= cs->max_prob; i++) {
    if (!(prob = cs->probs[i])) continue;
    if (!light_mode && cs->global->disable_submit_after_ok>0 && solved_flag[i])
      continue;
    if (prob->t_start_date > 0 && cs->current_time < prob->t_start_date)
      continue;
    if (start_time <= 0) continue;

    penalty_str[0] = 0;
    deadline_str[0] = 0;
    if (!light_mode) {
      // try to find personal rules
      user_deadline = 0;
      user_penalty = 0;
      for (pdi = 0, pdinfo = prob->pd_infos;
           pdi < prob->pd_total;
           pdi++, pdinfo++) {
        if (!strcmp(phr->login, pdinfo->login)) {
          user_deadline = pdinfo->deadline;
          break;
        }
      }
      // if no user-specific deadline, try the problem deadline
      if (!user_deadline) user_deadline = prob->t_deadline;
      // if deadline is over, go to the next problem
      if (user_deadline && cs->current_time >= user_deadline) continue;

      // check `require' variable
      if (prob->require) {
        for (j = 0; prob->require[j]; j++) {
          for (k = 1; k <= cs->max_prob; k++) {
            if (cs->probs[k]
                && !strcmp(cs->probs[k]->short_name, prob->require[j]))
              break;
          }
          // no such problem :(
          if (k > cs->max_prob) break;
          // this problem is not yet accepted or solved
          if (!solved_flag[k] && !accepted_flag[k]) break;
        }
        if (prob->require[j]) continue;
      }

      // find date penalty
      for (dpi = 0; dpi < prob->dp_total; dpi++)
        if (cs->current_time < prob->dp_infos[dpi].deadline)
          break;
      if (dpi < prob->dp_total)
        user_penalty = prob->dp_infos[dpi].penalty;

      if (user_deadline > 0 && cs->global->show_deadline)
        snprintf(deadline_str, sizeof(deadline_str),
                 " (%s)", xml_unparse_date(user_deadline));
      if (user_penalty && cs->global->show_deadline)
        snprintf(penalty_str, sizeof(penalty_str), " [%d]", user_penalty);
    }

    if (prob->variant_num > 0) {
      if ((variant = find_variant(cs, phr->user_id, i)) <= 0) continue;
      snprintf(problem_str, sizeof(problem_str),
               "%s-%d", prob->short_name, variant);
      problem_ptr = problem_str;
    } else {
      problem_ptr = prob->short_name;
    }

    fprintf(fout, "<option value=\"%d\">%s - %s%s%s</option>\n",
            i, problem_ptr, prob->long_name, penalty_str,
            deadline_str);
  }

  fprintf(fout, "</select>");
}

static int
insert_variant_num(unsigned char *buf, size_t size,
                   const unsigned char *file, int variant)
{
  int flen, pos;

  ASSERT(file);
  flen = strlen(file);
  ASSERT(flen > 0);
  pos = flen - 1;
  while (pos >= 0 && file[pos] != '/' && file[pos] != '.') pos--;
  if (pos <= 0 || file[pos] == '/')
    return snprintf(buf, size, "%s-%d", file, variant);
  // pos > 0 && file[pos] == '.'
  return snprintf(buf, size, "%.*s-%d.%s", pos - 1, file, variant, file + pos);
}

static void
user_main_page(struct server_framework_state *state,
               struct client_state *p,
               FILE *fout,
               struct http_request_info *phr,
               const struct contest_desc *cnts,
               struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  struct section_global_data *global = cs->global;
  long long tdiff;
  time_t start_time, stop_time, duration, sched_time, fog_start_time = 0;
  const unsigned char *s;
  int unread_clars, all_runs = 0, all_clars = 0, viewed_section = 0;
  unsigned char *solved_flag = 0;
  unsigned char *accepted_flag = 0;
  int n, v, prob_id = 0, i, j, variant = 0;
  char **lang_list;
  path_t variant_stmt_file;
  struct watched_file *pw = 0;
  const unsigned char *pw_path;
  const struct section_problem_data *prob = 0;

  if (ns_cgi_param(phr, "all_runs", &s) > 0
      && sscanf(s, "%d%n", &v, &n) == 1 && !s[n] && v >= 0 && v <= 1) {
    phr->session_extra->user_view_all_runs = v;
  }
  all_runs = phr->session_extra->user_view_all_runs;
  if (ns_cgi_param(phr, "all_clars", &s) > 0
      && sscanf(s, "%d%n", &v, &n) == 1 && !s[n] && v >= 0 && v <= 1) {
    phr->session_extra->user_view_all_clars = v;
  }
  all_clars = phr->session_extra->user_view_all_clars;
  if (ns_cgi_param(phr, "section", &s) > 0
      && sscanf(s, "%d%n", &v, &n) == 1 && !s[n]
      && v >= USER_SECTION_FIRST && v < USER_SECTION_LAST) {
    phr->session_extra->user_viewed_section = v;
  }
  viewed_section = phr->session_extra->user_viewed_section;
  if (ns_cgi_param(phr, "prob_id", &s) > 0
      && sscanf(s, "%d%n", &v, &n) == 1 && !s[n] && v > 0)
    prob_id = v;
  

  XALLOCAZ(solved_flag, cs->max_prob + 1);
  XALLOCAZ(accepted_flag, cs->max_prob + 1);

  if (global->virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, phr->user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, phr->user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }
  run_get_times(cs->runlog_state, 0, &sched_time, &duration, 0);
  if (duration > 0 && start_time && !stop_time && global->board_fog_time > 0)
    fog_start_time = start_time + duration - global->board_fog_time;
  if (fog_start_time < 0) fog_start_time = 0;

  l10n_setlocale(phr->locale_id);
  html_put_header(fout, extra->header_txt, 0, 0, phr->locale_id,
                  "%s [%s]: %s",
                  phr->name_arm, extra->contest_arm, _("Main page"));

#if 0
  fprintf(fout, "<%s>%s</%s>\n", cnts->team_head_style,
          _("Quick navigation"), cnts->team_head_style);
  fprintf(fout, "<ul>\n");
  fprintf(fout, "<li><a href=\"#status\">%s</a></li>\n", _("Contest status"));
  /*
  if (error_log)
    printf("<li><a href=\"#lastcmd\">%s</a>\n",
           _("The last command completion status"));
  */
  if (cs->contest_start_time && cs->clients_suspended) {
    fprintf(fout, "<li><a href=\"#probstat\">%s</a>\n",
            _("Problem status summary"));
  }
  if (cs->contest_start_time && !cs->contest_stop_time
      && !cs->clients_suspended) {
    fprintf(fout, "<li><a href=\"#submit\">%s</a>\n",
            _("Send a submission"));
  }
  if (cs->contest_start_time && !cs->contest_stop_time) {
    fprintf(fout, "<li><a href=\"#runstat\">%s</a>\n",
            _("Submission log"));
  }
  if (!global->disable_team_clars && !global->disable_clars
      && !cs->clients_suspended) {
    fprintf(fout, "<li><a href=\"#clar\">%s</a>\n",
            _("Send a message to judges"));
  }
  if (!global->disable_clars) {
    fprintf(fout, "<li><a href=\"#clarstat\">%s</a>\n",
            _("Messages from judges"));
  }
  if (!cs->clients_suspended) {
    fprintf(fout, "<li><a href=\"#chgpasswd\">%s</a>\n",
            _("Change password"));
  }
#if CONF_HAS_LIBINTL - 0 == 1
  if (global->enable_l10n) {
    fprintf(fout, "<li><a href=\"#chglanguage\">%s</a>\n",
            _("Change language"));
  }
#endif /* CONF_HAS_LIBINTL */
  if (cnts->standings_url && cs->contest_start_time) {
    fprintf(fout, "<li><a href=\"%s\" target=\"_blank\">%s</a>\n",
            cnts->standings_url, _("Team standings"));
  }
  if (cnts->problems_url) {
    if (global->always_show_problems || start_time) {
      fprintf(fout, "<li><a href=\"%s\" target=\"_blank\">%s</a>\n",
              cnts->problems_url, _("Problems"));
    }
  }
  fprintf(fout, "</ul>\n");
#endif

  // new navigation
  fprintf(fout, "<table border=\"0\" width=\"100%%\" bgcolor=\"#eeeeee\"><tr>");
  for (i = USER_SECTION_FIRST; i < USER_SECTION_LAST; i++) {
    if (i == viewed_section) {
      fprintf(fout, "<td bgcolor=\"#ffffff\">%s</td>",
              gettext(user_section_names[i]));
    } else {
      fprintf(fout, "<td><a href=\"%s?SID=%016llx&section=%d\">%s</a></td>",
              phr->self_url, phr->session_id, i,
              gettext(user_section_names[i]));
    }
  }
  fprintf(fout, "</tr></table>\n");

  unpriv_print_status(state, p, fout, phr, cnts, extra,
                      start_time, stop_time, duration, sched_time,
                      fog_start_time);

  if (!cs->global->disable_clars || !cs->global->disable_team_clars){
    unread_clars = serve_count_unread_clars(cs, phr->user_id, start_time);
    if (unread_clars > 0) {
      fprintf(fout, _("<hr><big><b>You have %d unread message(s)!</b></big>\n"),
              unread_clars);
    }
  }

  if (start_time && viewed_section == USER_SECTION_PROBLEM_STATUS) {
    fprintf(fout, "<hr><a name=\"probstat\"></a><%s>%s</%s>\n",
            cnts->team_head_style,
            _("Problem status summary"),
            cnts->team_head_style);
    html_write_user_problems_summary(cs, fout, phr->user_id, solved_flag,
                                     accepted_flag, 0);
  } else if (start_time && viewed_section == USER_SECTION_PROBLEM) {
    html_write_user_problems_summary(cs, fout, phr->user_id, solved_flag,
                                     accepted_flag, 1);
  }

  if (viewed_section == USER_SECTION_PROBLEM) {
    if (prob_id > cs->max_prob) prob_id = 0;
    if (prob_id > 0 && !(prob = cs->probs[prob_id])) prob_id = 0;
    if (prob_id > 0 && is_problem_deadlined(cs, prob_id, phr->login, 0))
      prob_id = 0;
    if (prob_id > 0 && prob->t_start_date > 0
        && cs->current_time < prob->t_start_date)
      prob_id = 0;
    if (prob_id > 0 && prob->variant_num > 0
        && (variant = find_variant(cs, phr->user_id, prob_id)) <= 0)
      prob_id = 0;

    if (start_time > 0 && stop_time <= 0 && !prob_id) {
      fprintf(fout, "<hr><a name=\"submit\"></a><%s>%s</%s>\n",
              cnts->team_head_style, _("Send a submission"),
              cnts->team_head_style);
      html_start_form(fout, 0, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table>\n");
      fprintf(fout, "<tr><td>%s:</td><td>", _("Problem"));

      html_problem_selection(cs, fout, phr, solved_flag, accepted_flag, 0, 0,
                             start_time);

      fprintf(fout, "</td><td><button type=\"submit\" name=\"action\" value=\"%d\">%s</button></td></tr></table></form>\n", NEW_SRV_ACTION_MAIN_PAGE, _("Select problem"));
    } else if (start_time > 0 && stop_time <= 0 && prob_id > 0) {
      prob = cs->probs[prob_id];

      if (variant > 0) {
        fprintf(fout, "<hr><a name=\"submit\"></a><%s>%s %s-%s (%s %d)</%s>\n",
                cnts->team_head_style, _("Submit a solution for"),
                prob->short_name, prob->long_name, _("Variant"), variant,
                cnts->team_head_style);
      } else {
        fprintf(fout, "<hr><a name=\"submit\"></a><%s>%s %s-%s</%s>\n",
                cnts->team_head_style, _("Submit a solution for"),
                prob->short_name, prob->long_name, cnts->team_head_style);
      }

      /* put problem statement */
      if (prob->statement_file[0]) {
        if (variant > 0) {
          insert_variant_num(variant_stmt_file, sizeof(variant_stmt_file),
                             prob->statement_file, variant);
          pw = &cs->prob_extras[prob_id].v_stmts[variant];
          pw_path = variant_stmt_file;
        } else {
          pw = &cs->prob_extras[prob_id].stmt;
          pw_path = prob->statement_file;
        }
        watched_file_update(pw, pw_path, cs->current_time);
        if (!pw->text) {
          fprintf(fout, "<big><font color=\"red\"><p>%s</p></font></big>\n",
                  _("The problem statement is not available"));
        } else {
          fprintf(fout, "%s", pw->text);
        }
      }

      html_start_form(fout, 2, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<input type=\"hidden\" name=\"prob_id\" value=\"%d\">\n",
              prob_id);
      fprintf(fout, "<table>\n");
      if (!prob->type_val) {
        fprintf(fout, "<tr><td>%s:</td><td>", _("Language"));
        fprintf(fout, "<select name=\"lang_id\"><option value=\"\">\n");
        for (i = 1; i <= cs->max_lang; i++) {
          if (!cs->langs[i] || cs->langs[i]->disabled) continue;
          if ((lang_list = prob->enable_language)) {
            for (j = 0; lang_list[j]; j++)
              if (!strcmp(lang_list[j], cs->langs[i]->short_name))
                break;
            if (!lang_list[j]) continue;
          } else if ((lang_list = prob->disable_language)) {
            for (j = 0; lang_list[j]; j++)
              if (!strcmp(lang_list[j], cs->langs[i]->short_name))
                break;
            if (lang_list[j]) continue;
          }
          fprintf(fout, "<option value=\"%d\">%s - %s</option>\n",
                  i, cs->langs[i]->short_name, cs->langs[i]->long_name);
        }
        fprintf(fout, "</select></td></tr>\n");
      }
      switch (prob->type_val) {
      case PROB_TYPE_STANDARD:
      case PROB_TYPE_OUTPUT_ONLY:
        fprintf(fout, "<tr><td>%s</td><td><input type=\"file\" name=\"file\"></td></tr>\n", _("File"));
        break;
      case PROB_TYPE_SHORT_ANSWER:
        fprintf(fout, "<tr><td>%s</td><td><input type=\"text\" name=\"file\"></td></tr>\n", _("Answer"));
        break;
      case PROB_TYPE_TEXT_ANSWER:
        fprintf(fout, "<tr><td colspan=\"2\"><textarea name=\"file\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n");
        break;
      case PROB_TYPE_SELECT_ONE:
        for (i = 0; prob->alternative[i]; i++) {
          fprintf(fout, "<tr><td>%d</td><td><input type=\"radio\" name=\"file\"></td><td>%s</td></tr>\n", i + 1, prob->alternative[i]);
        }
        break;
      case PROB_TYPE_SELECT_MANY:
        for (i = 0; prob->alternative[i]; i++) {
          fprintf(fout, "<tr><td>%d</td><td><input type=\"checkbox\" name=\"ans_%d\"></td><td>%s</td></tr>\n", i + 1, i + 1, prob->alternative[i]);
        }
        break;
      }
      fprintf(fout, "<tr><td>%s</td><td><button type=\"submit\" name=\"action\" value=\"%d\">%s</button></td></tr></table></form>\n", _("Send!"),
              NEW_SRV_ACTION_SUBMIT_RUN, _("Send!"));

      fprintf(fout, "<hr><a name=\"submit\"></a><%s>%s</%s>\n",
              cnts->team_head_style, _("Select another problem"),
              cnts->team_head_style);
      html_start_form(fout, 0, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table>\n");
      fprintf(fout, "<tr><td>%s:</td><td>", _("Problem"));

      html_problem_selection(cs, fout, phr, solved_flag, accepted_flag, 0, 0,
                             start_time);

      fprintf(fout, "</td><td><button type=\"submit\" name=\"action\" value=\"%d\">%s</button></td></tr></table></form>\n", NEW_SRV_ACTION_MAIN_PAGE, _("Select problem"));
    }

    if (start_time) {
      fprintf(fout, "<hr><a name=\"runstat\"></a><%s>%s (%s)</%s>\n",
              cnts->team_head_style,
              _("Sent submissions"),
              all_runs?_("all"):_("last 15"),
              cnts->team_head_style);
      new_write_user_runs(cs, fout, phr->user_id, all_runs,
                          NEW_SRV_ACTION_VIEW_SOURCE,
                          NEW_SRV_ACTION_VIEW_REPORT,
                          NEW_SRV_ACTION_PRINT_RUN,
                          phr->session_id, phr->self_url,
                          phr->hidden_vars, "");
      if (all_runs) s = _("View last 15");
      else s = _("View all");
      fprintf(fout, "<p><a href=\"%s?SID=%016llx&all_runs=%d&action=%d\">%s</a></p>\n", phr->self_url, phr->session_id, !all_runs, NEW_SRV_ACTION_MAIN_PAGE, s);
    }
  }

  if (viewed_section == USER_SECTION_CLAR) {
    if (!global->disable_clars && !global->disable_team_clars) {
      fprintf(fout, "<hr><a name=\"clar\"></a><%s>%s</%s>\n",
              cnts->team_head_style, _("Send a message to judges"),
              cnts->team_head_style);
      html_start_form(fout, 2, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table><tr><td>%s:</td><td>", _("Problem"));
      html_problem_selection(cs, fout, phr, solved_flag, accepted_flag, 0, 1,
                             start_time);
      fprintf(fout, "</td></tr>\n<tr><td>%s:</td>"
              "<td><input type=\"text\" name=\"subject\"></td></tr>\n"
              "<tr><td colspan=\"2\"><textarea name=\"text\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n"
              "<tr><td colspan=\"2\"><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr>\n"
              "</table></form>\n",
              _("Subject"), NEW_SRV_ACTION_SUBMIT_CLAR, _("Send!"));
    }

    if (!global->disable_clars) {
      fprintf(fout, "<hr><a name=\"clarstat\"></a><%s>%s (%s)</%s>\n",
              cnts->team_head_style, _("Messages"),
              all_clars?_("all"):_("last 15"), cnts->team_head_style);

      new_write_user_clars(cs, fout, phr->user_id, all_clars,
                           NEW_SRV_ACTION_VIEW_CLAR,
                           phr->session_id,
                           phr->self_url, phr->hidden_vars, "");

      if (all_clars) s = _("View last 15");
      else s = _("View all");
      fprintf(fout, "<p><a href=\"%s?SID=%016llx&all_clars=%d&action=%d\">%s</a></p>\n", phr->self_url, phr->session_id, !all_clars, NEW_SRV_ACTION_MAIN_PAGE, s);
    }
  }

  if (viewed_section == USER_SECTION_SETTINGS) {
    /* change the password */
    if (!cs->clients_suspended) {
      fprintf(fout, "<hr><a name=\"chgpasswd\"></a>\n<%s>%s</%s>\n",
              cnts->team_head_style,
              _("Change password"),
              cnts->team_head_style);
      html_start_form(fout, 1, phr->self_url, phr->hidden_vars);

      fprintf(fout, "<table>\n"
              "<tr><td>%s:</td><td><input type=\"password\" name=\"oldpasswd\" size=\"16\"></td></tr>\n"
              "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd1\" size=\"16\"></td></tr>\n"
              "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd2\" size=\"16\"></td></tr>\n"
              "<tr><td colspan=\"2\"><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr>\n"
              "</table></form>",
              _("Old password"),
              _("New password"), _("Retype new password"),
              NEW_SRV_ACTION_CHANGE_PASSWORD, _("Change!"));
    }

#if CONF_HAS_LIBINTL - 0 == 1
    if (cs->global->enable_l10n) {
      fprintf(fout, "<hr><a name=\"chglanguage\"></a><%s>%s</%s>\n",
              cnts->team_head_style, _("Change language"),
              cnts->team_head_style);
      html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
      fprintf(fout, "<table><tr><td>%s</td><td>", _("Change language"));
      l10n_html_locale_select(fout, phr->locale_id);
      fprintf(fout, "</td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr></table></form>\n",
              NEW_SRV_ACTION_CHANGE_LANGUAGE, _("Change"));
    }
#endif /* CONF_HAS_LIBINTL */
  }

  if (1 /*cs->global->show_generation_time*/) {
  gettimeofday(&phr->timestamp2, 0);
  tdiff = ((long long) phr->timestamp2.tv_sec) * 1000000;
  tdiff += phr->timestamp2.tv_usec;
  tdiff -= ((long long) phr->timestamp1.tv_sec) * 1000000;
  tdiff -= phr->timestamp1.tv_usec;
  fprintf(fout, "<hr><p%s>%s: %lld %s\n", cnts->team_par_style,
          _("Page generation time"), tdiff / 1000,
          _("msec"));
  }

  html_put_footer(fout, extra->footer_txt, phr->locale_id);
  l10n_setlocale(0);
}

static action_handler_t user_actions_table[NEW_SRV_ACTION_LAST] =
{
  [NEW_SRV_ACTION_CHANGE_LANGUAGE] = unpriv_change_language,
  [NEW_SRV_ACTION_CHANGE_PASSWORD] = unpriv_change_password,
  [NEW_SRV_ACTION_SUBMIT_RUN] = unpriv_submit_run,
};

static void
unprivileged_page(struct server_framework_state *state,
                  struct client_state *p,
                  FILE *fout,
                  struct http_request_info *phr)
{
  int r;
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  time_t cur_time = time(0);
  unsigned char hid_buf[1024];
  struct teamdb_db_callbacks callbacks;

  if (!phr->session_id || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return unprivileged_page_login(state, p, fout, phr);

  // validate cookie
  if (open_ul_connection(state) < 0)
    return html_err_userlist_server_down(state, p, fout, phr, 0);
  if ((r = userlist_clnt_get_cookie(ul_conn, ULS_GET_COOKIE,
                                    phr->ip, phr->ssl_flag,
                                    phr->session_id,
                                    &phr->user_id, &phr->contest_id,
                                    &phr->locale_id, 0, &phr->role,
                                    &phr->login, &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
      return html_err_invalid_session(state, p, fout, phr, 0,
                                     "get_cookie failed: %s",
                                     userlist_strerror(-r));
    case ULS_ERR_DISCONNECT:
      return html_err_userlist_server_down(state, p, fout, phr, 0);
    default:
      return new_server_html_err_internal_error(state, p, fout, phr, 0,
                                                "get_cookie failed: %s",
                                                userlist_strerror(-r));
    }
  }

  if (phr->contest_id < 0 || contests_get(phr->contest_id, &cnts) < 0 || !cnts)
    return html_err_permission_denied(state, p, fout, phr, 1,
                                      "invalid contest_id %d", phr->contest_id);
  extra = get_contest_extra(phr->contest_id);
  ASSERT(extra);

  if (!contests_check_team_ip(phr->contest_id, phr->ip, phr->ssl_flag))
    return html_err_permission_denied(state, p, fout, phr, 0,
                                      "%s://%s is not allowed for TEAM for contest %d", ssl_flag_str[phr->ssl_flag], xml_unparse_ip(phr->ip), phr->contest_id);
  if (cnts->closed)
    return html_err_service_not_available(state, p, fout, phr,
                                          "contest %d is closed");
  if (cnts->client_disable_team)
    return html_err_service_not_available(state, p, fout, phr,
                                          "contest %d team is disabled");

  watched_file_update(&extra->header, cnts->team_header_file, cur_time);
  watched_file_update(&extra->footer, cnts->team_footer_file, cur_time);
  extra->header_txt = extra->header.text;
  extra->footer_txt = extra->footer.text;
  //if (!extra->header_txt) extra->header_txt = fancy_header;
  //if (!extra->footer_txt) extra->footer_txt = fancy_footer;

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
  phr->session_extra = new_server_get_session(phr->session_id, cur_time);

  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.user_data = (void*) state;
  callbacks.list_all_users = list_all_users_callback;

  // invoke the contest
  if (serve_state_load_contest(phr->contest_id,
                               ul_conn,
                               &callbacks,
                               &extra->serve_state) < 0) {
    return html_err_contest_not_available(state, p, fout, phr, "");
  }

  extra->serve_state->current_time = time(0);

  if (phr->action > 0 && phr->action < NEW_SRV_ACTION_LAST
      && user_actions_table[phr->action]) {
    user_actions_table[phr->action](state, p, fout, phr, cnts, extra);
  } else {
    user_main_page(state, p, fout, phr, cnts, extra);
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
  if (!strcmp(last_name, "priv-client"))
    privileged_page(state, p, fout, phr);
  else
    unprivileged_page(state, p, fout, phr);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
