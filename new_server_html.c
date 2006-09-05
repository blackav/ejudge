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

static void
html_role_select(FILE *fout, int role)
{
  static const unsigned char *roles[] =
    {
      "Contestant",
      "Observer",
      "Judge",
      "Chief judge",
      "Coordinator",
      "Administrator (Master)",
      0,
    };
  int i;
  const unsigned char *ss;

  if (role < 0 || role >= USER_ROLE_LAST) role = USER_ROLE_OBSERVER;
  fprintf(fout, "<select name=\"role\">");
  for (i = 0; roles[i]; i++) {
    ss = "";
    if (i == role) ss = " selected=\"1\"";
    fprintf(fout, "<option value=\"%d\"%s>%s</option>",
            i, ss, gettext(roles[i]));
  }
  fprintf(fout, "</select>\n");
}

static void
html_start_form(FILE *fout, const unsigned char *url)
{
  fprintf(fout, "<form method=\"POST\" action=\"%s\" "
          "ENCTYPE=\"application/x-www-form-urlencoded\">\n",
          url);
}

static void
html_refresh_page(struct server_framework_state *state,
                  FILE *fout,
                  struct http_request_info *phr,
                  int new_action)
{
  unsigned char url[1024];

  if (new_action > 0) {
    snprintf(url, sizeof(url), "%s?SID=%016llx&action=%d",
             phr->self_url, phr->session_id, new_action);
  } else {
    snprintf(url, sizeof(url), "%s?SID=%016llx",
             phr->self_url, phr->session_id);
  }

  fprintf(stdout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\n\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><meta http-equiv=\"Refresh\" content=\"%d; url=%s\"><title>%s</title></head><body><h1>%s</h1><p>If autorefresh does not work, follow <a href=\"%s\">this</a> link.</p></body></html>\n", EJUDGE_CHARSET, EJUDGE_CHARSET, 1, url, "Operation successful", "Operation successful", url);
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
  html_start_form(fout, phr->self_url);
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
  html_role_select(fout, phr->role);
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
                           FILE *fout,
                           struct http_request_info *phr,
                           int priv_mode)
{
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  const unsigned char *header = 0, *footer = 0;
  time_t cur_time = time(0);
  unsigned char *s;

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
            phr->ssl_flag?"https":"http");
    fprintf(fout, _("<li>The contest is closed for participation.</li>\n"));
  } else {
    fprintf(fout, _("<li>Your IP-address (<tt>%s</tt>) or protocol (<tt>%s</tt>) is banned for participation.</li>"), xml_unparse_ip(phr->ip),
            phr->ssl_flag?"https":"http");
    fprintf(fout, _("<li>You do not have permissions to login using the specified role.</li>"));
  }
  fprintf(fout, "</ul>\n");
  fprintf(fout, _("<p>Note, that the exact reason is not reported due to security reasons.</p>"));
  html_put_footer(fout, footer);
  l10n_setlocale(0);
}

static void
html_err_invalid_param(struct server_framework_state *state,
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
  html_put_header(fout, header, 0, 0, phr->locale_id, _("Invalid parameter"));
  fprintf(fout, "<p>%s</p>\n",
          _("A request parameter is invalid. Please, contact the site administrator."));
  html_put_footer(fout, footer);
  l10n_setlocale(0);
}

static void
html_err_userlist_server_down(struct server_framework_state *state,
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
  html_put_header(fout, header, 0, 0, phr->locale_id, _("Internal error"));
  fprintf(fout, "<p>%s</p>\n",
          _("Your request has caused an internal server error. Please, report it as a bug."));
  html_put_footer(fout, footer);
  l10n_setlocale(0);
}

static void
html_err_invalid_session(struct server_framework_state *state,
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
  html_put_header(fout, header, 0, 0, phr->locale_id, _("Invalid session"));
  fprintf(fout, "<p>%s</p>\n",
          _("Invalid session identifier. The possible reasons are as follows."));
  fprintf(fout, "<ul>\n");
  fprintf(fout, _("<li>The specified session does not exist.</li>"));
  fprintf(fout, _("<li>The specified has expired.</li>\n"));
  fprintf(fout, _("<li>The session was created from a different IP-address or protocol, that yours (%s,%s).</li>\n"), xml_unparse_ip(phr->ip), phr->ssl_flag?"https":"http");;
  fprintf(fout, _("<li>The session was removed by an administrator.</li>"));
  fprintf(fout, "</ul>\n");
  fprintf(fout, _("<p>Note, that the exact reason is not reported due to security reasons.</p>"));
  html_put_footer(fout, footer);
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
    return html_err_invalid_param(state, fout, phr, 1);
  if (!r || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return privileged_page_login_page(state, p, fout, phr);

  if ((r = ns_cgi_param(phr, "password", &password)) <= 0)
    return html_err_invalid_param(state, fout, phr, 1);
  if (phr->contest_id<=0 || contests_get(phr->contest_id, &cnts)<0 || !cnts)
    return html_err_invalid_param(state, fout, phr, 1);

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
      return html_err_permission_denied(state, fout, phr, 1);
  } else {
    // as for judge program
    if (!contests_check_judge_ip(phr->contest_id, phr->ip, phr->ssl_flag))
      return html_err_permission_denied(state, fout, phr, 1);
  }

  if (open_ul_connection(state) < 0)
    return html_err_userlist_server_down(state, fout, phr, 1);
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
      return html_err_permission_denied(state, fout, phr, 1);
    case ULS_ERR_DISCONNECT:
      return html_err_userlist_server_down(state, fout, phr, 1);
    default:
      return html_err_internal_error(state, fout, phr, 1);
    }
  }
  phr->login = xstrdup(login);

  // analyze permissions
  if (phr->role == USER_ROLE_ADMIN) {
    // as for the master program
    if (opcaps_find(&cnts->capabilities, phr->login, &caps) < 0
        || opcaps_check(caps, OPCAP_MASTER_LOGIN) < 0)
      return html_err_permission_denied(state, fout, phr, 1);
  } else {
    // user privileges checked locally
    if (nsdb_check_role(phr->user_id, phr->contest_id, phr->role) < 0)
      return html_err_permission_denied(state, fout, phr, 1);
  }

  // TODO: store a cookie
  html_refresh_page(state, fout, phr, NEW_SRV_ACTION_MAIN_PAGE);
}

static void
privileged_page(struct server_framework_state *state,
                struct client_state *p,
                FILE *fout,
                struct http_request_info *phr)
{
  int r;

  if (!phr->session_id || phr->action == NEW_SRV_ACTION_LOGIN_PAGE)
    return privileged_page_login(state, p, fout, phr);

  // validate cookie
  if (open_ul_connection(state) < 0)
    return html_err_userlist_server_down(state, fout, phr, 1);
  if ((r = userlist_clnt_get_cookie(ul_conn, phr->ip, phr->ssl_flag,
                                    phr->contest_id, phr->session_id,
                                    &phr->user_id, 0, &phr->locale_id,
                                    0, &phr->role, &phr->login,
                                    &phr->name)) < 0) {
    switch (-r) {
    case ULS_ERR_NO_COOKIE:
      return html_err_invalid_session(state, fout, phr, 1);
    case ULS_ERR_DISCONNECT:
      return html_err_userlist_server_down(state, fout, phr, 1);
    default:
      return html_err_internal_error(state, fout, phr, 1);
    }
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
    return html_err_invalid_param(state, fout, phr, 0);
  if (!strcmp(remote_addr, "::1")) remote_addr = "127.0.0.1";
  if (xml_parse_ip(0, 0, 0, remote_addr, &phr->ip) < 0)
    return html_err_invalid_param(state, fout, phr, 0);

  // parse the contest_id
  if ((r = ns_cgi_param(phr, "contest_id", &s)) < 0)
    return html_err_invalid_param(state, fout, phr, 0);
  if (r > 0) {
    if (sscanf(s, "%d%n", &phr->contest_id, &n) != 1
        || s[n] || phr->contest_id <= 0)
      return html_err_invalid_param(state, fout, phr, 0);
  }

  // parse the session_id
  if ((r = ns_cgi_param(phr, "SID", &s)) < 0)
    return html_err_invalid_param(state, fout, phr, 0);
  if (r > 0) {
    if (sscanf(s, "%llx%n", &phr->session_id, &n) != 1
        || s[n] || !phr->session_id)
      return html_err_invalid_param(state, fout, phr, 0);
  }

  // parse the locale_id
  if ((r = ns_cgi_param(phr, "locale_id", &s)) < 0)
    return html_err_invalid_param(state, fout, phr, 0);
  if (r > 0) {
    if (sscanf(s, "%d%n", &phr->locale_id, &n) != 1 || s[n]
        || phr->locale_id <= 0)
    return html_err_invalid_param(state, fout, phr, 0);
  }

  // parse the action
  if ((s = ns_cgi_nname(phr, "action_", 7))) {
    if (sscanf(s, "action_%d%n", &phr->action, &n) != 1 || s[n]
        || phr->action <= 0)
    return html_err_invalid_param(state, fout, phr, 0);
  } else if ((r = ns_cgi_param(phr, "action", &s)) < 0) {
    return html_err_invalid_param(state, fout, phr, 0);
  } else if (r > 0) {
    if (sscanf(s, "%d%n", &phr->action, &n) != 1 || s[n]
        || phr->action <= 0)
      return html_err_invalid_param(state, fout, phr, 0);
  }

  // check how we've been called
  script_filename = ns_getenv(phr, "SCRIPT_FILENAME");
  if (!script_filename && phr->arg_num > 0) script_filename = phr->args[0];
  if (!script_filename)
    return html_err_invalid_param(state, fout, phr, 0);

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
