/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2000-2004 Alexander Chernov <cher@ispras.ru> */

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

#include "cgi.h"
#include "fileutl.h"
#include "pathutl.h"
#include "clarlog.h"
#include "base64.h"
#include "parsecfg.h"
#include "clntutil.h"
#include "misctext.h"
#include "serve_clnt.h"
#include "contests.h"
#include "protocol.h"
#include "userlist_proto.h"
#include "userlist_clnt.h"
#include "client_actions.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

/*
 * The default path to data directory
 */
#if !defined CGI_DATA_PATH
#define CGI_DATA_PATH "../cgi-data"
#endif

/* defaults */
#define DEFAULT_VAR_DIR        "var"
#define DEFAULT_STATUS_FILE    "status/dir/status"
#define DEFAULT_RUN_PAGE_SIZE  10
#define DEFAULT_CLAR_PAGE_SIZE 10
#define DEFAULT_CHARSET        "iso8859-1"
#define DEFAULT_SERVE_SOCKET   "serve"

struct section_global_data
{
  struct generic_section_config g;

  int    run_page_size;
  int    clar_page_size;
  int    allow_deny;
  path_t root_dir;
  path_t var_dir;
  path_t status_file;
  path_t allow_from;
  path_t deny_from;
  path_t charset;

  /* locallization stuff */
  int    enable_l10n;
  path_t l10n_dir;

  /* userlist-server stuff */
  int contest_id;
  path_t socket_path;
  path_t contests_dir;
  path_t serve_socket;
};

static void print_nav_buttons(void);

static struct generic_section_config *config;
static struct section_global_data    *global;

#define GLOBAL_OFFSET(x)   XOFFSET(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(run_page_size, "d"),
  GLOBAL_PARAM(clar_page_size, "d"),
  GLOBAL_PARAM(allow_deny, "d"),
  GLOBAL_PARAM(root_dir, "s"),
  GLOBAL_PARAM(var_dir, "s"),
  GLOBAL_PARAM(status_file, "s"),
  GLOBAL_PARAM(allow_from, "s"),
  GLOBAL_PARAM(deny_from, "s"),
  GLOBAL_PARAM(charset, "s"),
  GLOBAL_PARAM(enable_l10n, "d"),
  GLOBAL_PARAM(l10n_dir, "s"),

  GLOBAL_PARAM(contest_id, "d"),
  GLOBAL_PARAM(socket_path, "s"),
  GLOBAL_PARAM(contests_dir, "s"),
  GLOBAL_PARAM(serve_socket, "s"),

  { 0, 0, 0, 0 }
};

static struct config_section_info params[] =
{
  { "global" ,sizeof(struct section_global_data), section_global_params },
  { NULL, 0, NULL }
};

/* new userlist-server related variables */
static struct contest_desc *cur_contest;
static struct userlist_clnt *userlist_conn;
static unsigned long client_ip;
static int serve_socket_fd = -1;
static unsigned char *self_url = 0;
static unsigned char hidden_vars[1024];
static unsigned char *filter_expr;
static int filter_first_run;
static int filter_last_run;
static int filter_first_clar;
static int filter_last_clar;
static int priv_level;
static int client_action = 0;
static int cgi_contest_id = 0;
static unsigned char contest_id_str[64];

enum
  {
    SID_DISABLED = 0,
    SID_EMBED,
    SID_URL,
    SID_COOKIE
  };

static int client_sid_mode;
static int need_set_cookie;
static unsigned long long client_cookie;
static unsigned long long client_sid;
static unsigned char *client_login;
static unsigned char *client_password;
static unsigned char *client_name;
static unsigned int client_user_id;

/* form headers */
static char    form_start_simple[1024];
static char    form_start_multipart[1024];

static void open_serve(void);

static void
read_state_params(void)
{
  unsigned char *a_passwd;
  unsigned char *s;
  int passwd_len, x, n;
  unsigned char form_contest_id[1024];

  client_action = 0;
  if ((s = cgi_param("action"))) {
    n = 0; x = 0;
    if (sscanf(s, "%d%n", &x, &n) == 1 && !s[n]
        && x > 0 && x < ACTION_LAST)
      client_action = x;
  }
  if (!client_action && (s = cgi_nname("action_", 7))) {
    n = 0; x = 0;
    if (sscanf(s, "action_%d%n", &x, &n) == 1 && !s[n]
        && x > 0 && x < ACTION_LAST)
      client_action = x;
  }

  passwd_len = html_armored_strlen(client_password);
  a_passwd = alloca(passwd_len + 10);
  html_armor_string(client_password, a_passwd);

  form_contest_id[0] = 0;
  if (cgi_contest_id > 0) {
    snprintf(form_contest_id, sizeof(form_contest_id),
             "<input type=\"hidden\" name=\"contest_id\" value=\"%d\">",
             global->contest_id);
  }

  switch (client_sid_mode) {
  case SID_DISABLED:
    sprintf(form_start_simple,
            "%s"
            "<input type=\"hidden\" name=\"sid_mode\" value=\"0\">"
            "<input type=\"hidden\" name=\"login\" value=\"%s\">"
            "<input type=\"hidden\" name=\"password\" value=\"%s\">%s",
            form_header_simple, client_login, a_passwd, form_contest_id);
    sprintf(form_start_multipart,
            "%s"
            "<input type=\"hidden\" name=\"sid_mode\" value=\"0\">"
            "<input type=\"hidden\" name=\"login\" value=\"%s\">"
            "<input type=\"hidden\" name=\"password\" value=\"%s\">%s",
            form_header_multipart, client_login, a_passwd, form_contest_id);
    snprintf(hidden_vars, sizeof(hidden_vars),
             "<input type=\"hidden\" name=\"sid_mode\" value=\"0\">"
             "<input type=\"hidden\" name=\"login\" value=\"%s\">"
             "<input type=\"hidden\" name=\"password\" value=\"%s\">%s",
             client_login, a_passwd, form_contest_id);
    break;
  case SID_EMBED:
    snprintf(form_start_simple, sizeof(form_start_simple),
             "%s<input type=\"hidden\" name=\"SID\" value=\"%016llx\">"
             "<input type=\"hidden\" name=\"sid_mode\" value=\"1\">%s",
             form_header_simple, client_sid, form_contest_id);
    snprintf(form_start_multipart, sizeof(form_start_multipart),
             "%s<input type=\"hidden\" name=\"SID\" value=\"%016llx\">"
             "<input type=\"hidden\" name=\"sid_mode\" value=\"1\">%s",
             form_header_multipart, client_sid, form_contest_id);
    snprintf(hidden_vars, sizeof(hidden_vars),
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">"
             "<input type=\"hidden\" name=\"sid_mode\" value=\"1\">%s",
             client_sid, form_contest_id);
    break;
  case SID_URL:
    snprintf(form_start_simple, sizeof(form_start_simple),
             "%s"
             "<input type=\"hidden\" name=\"sid_mode\" value=\"2\">"
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">%s",
             form_header_simple, client_sid, form_contest_id);
    snprintf(form_start_multipart, sizeof(form_start_multipart),
             "%s"
             "<input type=\"hidden\" name=\"sid_mode\" value=\"2\">"
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">%s",
             form_header_multipart, client_sid, form_contest_id);
    snprintf(hidden_vars, sizeof(hidden_vars),
             "<input type=\"hidden\" name=\"sid_mode\" value=\"2\">"
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">%s",
             client_sid, form_contest_id);
    break;
  case SID_COOKIE:
    snprintf(form_start_simple, sizeof(form_start_simple),
             "%s%s", form_header_simple, form_contest_id);
    snprintf(form_start_multipart, sizeof(form_start_multipart),
             "%s%s", form_header_multipart, form_contest_id);
    snprintf(hidden_vars, sizeof(hidden_vars), "%s", form_contest_id);
    break;
  default:
    SWERR(("Unhandled sid mode %d", client_sid_mode));
  }
}

static void
make_self_url(void)
{
  unsigned char *http_host = getenv("HTTP_HOST");
  unsigned char *script_name = getenv("SCRIPT_NAME");
  unsigned char fullname[1024];

  if (!http_host) http_host = "localhost";
  if (!script_name) script_name = "/cgi-bin/master";
  snprintf(fullname, sizeof(fullname), "http://%s%s",
           http_host, script_name);
  self_url = xstrdup(fullname);
}

static unsigned char *
hyperref(unsigned char *buf, int size,
         int sid_mode, unsigned long long sid,
         unsigned char const *contest_id_str,
         unsigned char const *self_url,
         unsigned char const *format, ...)
{
  va_list args;
  unsigned char *out = buf;
  int left = size, n;

  ASSERT(sid_mode == SID_URL || sid_mode == SID_COOKIE);
  if (sid_mode == SID_COOKIE) {
    n = snprintf(out, left, "%s?sid_mode=%d%s",
                 self_url, SID_COOKIE, contest_id_str);
  } else {
    n = snprintf(out, left, "%s?sid_mode=%d&SID=%016llx%s",
                 self_url, SID_URL, sid, contest_id_str);
  }
  if (n >= left) n = left;
  left -= n; out += n;
  if (format && *format) {
    n = snprintf(out, left, "&");
    if (n >= left) n = left;
    left -= n; out += n;
    va_start(args, format);
    n = vsnprintf(out, left, format, args);
    va_end(args);
  }
  return buf;
}

static void
set_cookie_if_needed(void)
{
  time_t t;
  struct tm gt;
  char buf[128];

  if (!need_set_cookie) return;
  need_set_cookie = 0;
  if (!client_cookie) {
    printf("Set-cookie: MID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
    return;
  }
  t = time(0);
  t += 24 * 60 * 60;
  gmtime_r(&t, &gt);
  strftime(buf, sizeof(buf), "%A, %d-%b-%Y %H:%M:%S GMT", &gt);
  printf("Set-cookie: MID=%llx; expires=%s\n", client_cookie, buf);
}

/* this function is called, if the contest_id is not known */
static int
display_enter_password_2(void)
{
  make_self_url();
  client_put_header(stdout, 0, 0, "iso8859-1", 1, 0,
                    "Enter password - %s",
                    protocol_priv_level_str(priv_level));
  printf("<form method=\"POST\" action=\"%s\" "
         "ENCTYPE=\"application/x-www-form-urlencoded\">",
         self_url);
  printf("<input type=\"hidden\" name=\"sid_mode\" value=\"2\">\n");
  printf("<table>"
         "<tr>"
         "<td>%s:</td>"
         "<td><input type=\"text\" size=16 name=\"login\"></td>"
         "</tr>"
         "<tr>"
         "<td>%s:</td>"
         "<td><input type=\"password\" size=16 name=\"password\"></td>"
         "</tr>"
         "<tr>"
         "<td>%s:</td>"
         "<td><input type=\"text\" size=\"16\" name=\"contest_id\"></td>"
         "</tr>"
         "<tr>"
         "<td>&nbsp;</td>"
         "<td><input type=\"submit\" value=\"%s\"></td>"
         "</tr>"
         "</table>"
         "</form>",
         _("Login"), _("Password"), _("Contest ID"), _("Submit"));
  client_put_footer(stdout, 0);
  return 0;
}

static int
display_enter_password(void)
{
  unsigned char *a_name = 0;
  int a_len;

  if (cur_contest->name) {
    a_len = html_armored_strlen(cur_contest->name);
    a_name = alloca(a_len + 10);
    html_armor_string(cur_contest->name, a_name);
  }
  set_cookie_if_needed();
  if (a_name) {
    client_put_header(stdout, 0, 0, global->charset, 1, 0,
                      "Enter password - %s - &quot;%s&quot;",
                      protocol_priv_level_str(priv_level), a_name);
  } else {
    client_put_header(stdout, 0, 0, global->charset, 1, 0,
                      "Enter password - %s",
                      protocol_priv_level_str(priv_level));
  }

  puts(form_header_simple);
  if (cgi_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n", 
           cgi_contest_id);
  }
  printf("<input type=\"hidden\" name=\"sid_mode\" value=\"2\">\n");
  printf("<table>"
         "<tr>"
         "<td>%s:</td>"
         "<td><input type=\"text\" size=16 name=\"login\"></td>"
         "</tr>"
         "<tr>"
         "<td>%s:</td>"
         "<td><input type=\"password\" size=16 name=\"password\"></td>"
         "</tr>"
         "<tr>"
         "<td>&nbsp;</td>"
         "<td><input type=\"submit\" value=\"%s\"></td>"
         "</tr>"
         "</table>"
         "</form>",
         _("Login"), _("Password"), _("Submit"));
  client_put_footer(stdout, 0);
  return 0;
}

static int
get_cookie(unsigned char const *var, unsigned long long *p_val)
{
  unsigned char const *cookie_str, *s, *p;
  unsigned char *nstr, *vstr;
  size_t cookie_len;
  int n;
  unsigned long long val;

  if (!(cookie_str = getenv("HTTP_COOKIE"))) return 0;
  cookie_len = strlen(cookie_str);
  nstr = alloca(cookie_len + 10);
  vstr = alloca(cookie_len + 10);
  s = cookie_str;
  while (1) {
    while (isspace(*s)) s++;
    if (!*s || *s == '=') return 0;
    memset(nstr, 0, cookie_len + 10);
    memset(vstr, 0, cookie_len + 10);
    p = s;
    while (*s && !isspace(*s) && *s != ';' && *s != '=') s++;
    if (!*s || *s == ';') return 0;
    memcpy(nstr, p, s - p);
    while (*s && isspace(*s)) s++;
    if (!*s || *s != '=') return 0;
    s++;
    while (*s && isspace(*s)) s++;
    p = s;
    while (*s && !isspace(*s) && *s != ';' && *s != '=') s++;
    if (*s == '=') return 0;
    memcpy(vstr, p, s - p);
    while (*s && isspace(*s)) s++;
    if (*s == ';') s++;

    // nstr - name of the cookie, vstr - value
    if (strcmp(nstr, var) != 0) continue;
    if (sscanf(vstr, "%llx%n", &val, &n) != 1 || vstr[n]) continue;
    if (!val) continue;

    if (p_val) *p_val = val;
    return 1;
  }
}

static void
open_userlist_server(void)
{
  if (!userlist_conn) {
    if (!(userlist_conn = userlist_clnt_open(global->socket_path))) {
      set_cookie_if_needed();
      client_put_header(stdout, 0, 0, global->charset, 1, 0, _("Server is down"));
      printf("<p>%s</p>",
             _("The server is down. Try again later."));
      client_put_footer(stdout, 0);
      exit(0);
    }
  }
}

static void
permission_denied(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0, _("Permission denied"));
  printf("<p>%s</p>",
         "Permission denied. You have typed invalid login, invalid password,"
         " or do not have enough privileges.");
  client_put_footer(stdout, 0);
  exit(0);
}
static void
fatal_server_error(int r)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0, _("Server error"));
  printf("<p>Server error: %s</p>", userlist_strerror(-r));
  client_put_footer(stdout, 0);
  exit(0);
}
static int
is_auth_error(int r)
{
  return r == -ULS_ERR_INVALID_LOGIN
    || r == -ULS_ERR_INVALID_PASSWORD
    || r == -ULS_ERR_NO_PERMS
    || r == -ULS_ERR_NO_COOKIE
    || r == -ULS_ERR_BAD_CONTEST_ID;
}

static int
get_session_id(unsigned char const *var, unsigned long long *p_val)
{
  unsigned char const *str;
  unsigned long long val;
  int n;

  if (!var) return 0;
  if (!(str = cgi_param(var))) return 0;
  if (sscanf(str, "%llx%n", &val, &n) != 1 || str[n]) return 0;
  if (!val) return 0;

  if (p_val) *p_val = val;
  return 1;
}

static void
client_put_refresh_header(unsigned char const *coding,
                          unsigned char const *url,
                          int interval,
                          unsigned char const *format, ...)
{
  va_list args;

  if (!coding) coding = "iso8859-1";

  va_start(args, format);
  fprintf(stdout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\n\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><meta http-equiv=\"Refresh\" content=\"%d; url=%s\"><title>\n", coding, coding, interval, url);
  vfprintf(stdout, format, args);
  fputs("\n</title></head><body><h1>\n", stdout);
  vfprintf(stdout, format, args);
  fputs("\n</h1>\n", stdout);
}

static int
authentificate(void)
{
  unsigned long long session_id;
  unsigned char const *sid_mode_str;
  int r;

  /* read and parse session mode */
  sid_mode_str = cgi_param("sid_mode");
  client_sid_mode = -1;
  if (sid_mode_str) {
    int x, n = 0;
    if (sscanf(sid_mode_str, "%d%n", &x, &n) == 1 && !sid_mode_str[n]
        && x >= SID_DISABLED && x <= SID_COOKIE) {
      client_sid_mode = x;
    }
  }

  if ((client_sid_mode == -1 || client_sid_mode == SID_COOKIE)
      && get_cookie("MID", &session_id)) {
    client_cookie = session_id;
    open_userlist_server();
    r = userlist_clnt_priv_cookie(userlist_conn, client_ip, global->contest_id,
                                  session_id,
                                  0 /* locale_id */,
                                  priv_level, &client_user_id,
                                  0, /* p_contest_id */
                                  0 /* p_locale_id */,
                                  &priv_level, &client_login, &client_name);
    if (r >= 0) {
      client_sid_mode = SID_COOKIE;
      client_sid = client_cookie;
      client_password = "";
      return 1;
    }
    if (!is_auth_error(r)) fatal_server_error(r);
    client_cookie = 0;
    need_set_cookie = 1;
  }

  if ((client_sid_mode == -1 || client_sid_mode == SID_EMBED
      || client_sid_mode == SID_URL)
      && get_session_id("SID", &session_id)) {
    open_userlist_server();
    r = userlist_clnt_priv_cookie(userlist_conn, client_ip, global->contest_id,
                                  session_id,
                                  0 /* locale_id */,
                                  priv_level, &client_user_id,
                                  0 /* p_contest_id */,
                                  0 /* p_locale_id */,
                                  &priv_level, &client_login, &client_name);
    if (r >= 0) {
      if (client_sid_mode == -1) client_sid_mode = SID_URL;
      client_sid = session_id;
      client_password = "";
      return 1;
    }
    if (!is_auth_error(r)) fatal_server_error(r);
  }

  client_login = cgi_param("login");
  client_password = cgi_param("password");
  if (!client_login || !client_password) {
    display_enter_password();
    exit(0);
  }

  // set default behavior
  if (client_sid_mode == -1) {
    client_sid_mode = SID_COOKIE;
  }

  open_userlist_server();
  r = userlist_clnt_priv_login(userlist_conn, client_ip, global->contest_id,
                               0, /* locale_id */
                               client_sid_mode != SID_DISABLED,
                               priv_level, client_login, client_password,
                               &client_user_id,
                               &client_sid,
                               0, /* p_locale_id */
                               &priv_level,
                               &client_name);
  if (r < 0 && is_auth_error(r)) permission_denied();
  if (r < 0) fatal_server_error(r);
  if (client_sid_mode == SID_COOKIE) {
    client_cookie = client_sid;
    need_set_cookie = 1;
  }

  if (client_sid_mode == SID_URL || client_sid_mode == SID_COOKIE) {
    unsigned char hbuf[128];

    hyperref(hbuf, sizeof(hbuf), client_sid_mode, client_sid,
             contest_id_str,
             self_url, 0);
    set_cookie_if_needed();
    client_put_refresh_header(global->charset, hbuf, 0,
                              "Login successful");
    printf("<p>%s</p>", _("Login successfull. Now entering the main page."));
    printf("<p>If automatic updating does not work, click on <a href=\"%s\">this</a> link.</p>", hbuf);
           
    //client_put_footer();
    exit(0);
  }

  return 1;
}

static void
print_refresh_button(char const *str)
{
  if (!str) str = _("Refresh");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s\">%s</a>",
           self_url, SID_URL, client_sid, contest_id_str, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s\">%s</a>", self_url, SID_COOKIE,
           contest_id_str, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"refresh\" value=\"%s\">", str);
    puts("</form>");
  }
}

static void
print_standings_button(char const *str)
{
  if (!str) str = _("Standings");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s&stand=1\">%s</a>",
           self_url, SID_URL, client_sid, contest_id_str, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s&stand=1\">%s</a>", self_url,
           SID_COOKIE, contest_id_str, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"stand\" value=\"%s\">", str);
    puts("</form>");
  }
}

static void
print_update_button(char const *str)
{
  if (!str) str = _("Update public standings");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
         ACTION_UPDATE_STANDINGS_1, str);
  puts("</form>");
}

static void
print_teamview_button(char const *str)
{
  if (!str) str = _("View teams");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s&viewteams=1\">%s</a>",
           self_url, SID_URL, client_sid, contest_id_str, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s&viewteams=1\">%s</a>", self_url,
           SID_COOKIE, contest_id_str, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"viewteams\" value=\"%s\">", str);
    puts("</form>");
  }
}

static void
print_logout_button(unsigned char const *str)
{
  if (!str) str = _("Log out");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s&logout=1\">%s</a>",
           self_url, SID_URL, client_sid, contest_id_str, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s&logout=1\">%s</a>", self_url,
           SID_COOKIE, contest_id_str, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"logout\" value=\"%s\"></form>", str);
  }
}

static void
print_dump_runs_button(unsigned char const *str)
{
  if (!str) str = _("Dump runs database");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s&action=%d\">%s</a>",
           self_url, SID_URL, client_sid,
           contest_id_str, ACTION_DUMP_RUNS, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s&action=%d\">%s</a>", self_url,
           SID_COOKIE, contest_id_str, ACTION_DUMP_RUNS, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
           ACTION_DUMP_RUNS, str);
  }
}

static void
print_write_xml_runs_button(unsigned char const *str)
{
  if (!str) str = _("Write XML runs (internal format)");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s&action=%d\">%s</a>",
           self_url, SID_URL, client_sid,
           contest_id_str, ACTION_WRITE_XML_RUNS, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s&action=%d\">%s</a>", self_url,
           SID_COOKIE, contest_id_str, ACTION_WRITE_XML_RUNS, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
           ACTION_WRITE_XML_RUNS, str);
  }
}

static void
print_export_xml_runs_button(unsigned char const *str)
{
  if (!str) str = _("Export XML runs (external format)");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s&action=%d\">%s</a>",
           self_url, SID_URL, client_sid,
           contest_id_str, ACTION_EXPORT_XML_RUNS, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s&action=%d\">%s</a>", self_url,
           SID_COOKIE, contest_id_str, ACTION_EXPORT_XML_RUNS, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
           ACTION_EXPORT_XML_RUNS, str);
  }
}

static void
print_dump_users_button(unsigned char const *str)
{
  if (!str) str = _("Dump users database");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s&action=%d\">%s</a>",
           self_url, SID_URL, client_sid,
           contest_id_str, ACTION_DUMP_USERS, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s&action=%d\">%s</a>", self_url,
           SID_COOKIE, contest_id_str, ACTION_DUMP_USERS, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
           ACTION_DUMP_USERS, str);
  }
}

static void
print_dump_standings_button(unsigned char const *str)
{
  if (!str) str = _("Dump standings database");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s&action=%d\">%s</a>",
           self_url, SID_URL, client_sid,
           contest_id_str, ACTION_DUMP_STANDINGS, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s&action=%d\">%s</a>", self_url,
           SID_COOKIE, contest_id_str, ACTION_DUMP_STANDINGS, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
           ACTION_DUMP_STANDINGS, str);
  }
}

static void
print_reset_button(char const *str)
{
  if (!str) str = _("Reset the contest!");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         ACTION_RESET_1, str);
}

static void
print_regenerate_button(unsigned char const *str)
{
  if (!str) str = _("Regenerate user passwords!");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         ACTION_GENERATE_PASSWORDS_1, str);
}

static void
print_regenerate_reg_button(unsigned char const *str)
{
  if (!str) str = _("Regenerate register user passwords!");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         ACTION_GENERATE_REG_PASSWORDS_1, str);
}

static void
print_clear_team_passwords_button(unsigned char const *str)
{
  if (!str) str = _("Clear team passwords!");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         ACTION_CLEAR_TEAM_PASSWORDS_1, str);
}

static void
print_suspend_button(char const *str)
{
  if (!str) str = _("Suspend clients");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         ACTION_SUSPEND, str);
}

static void
print_resume_button(char const *str)
{
  if (!str) str = _("Resume clients");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         ACTION_RESUME, str);
}

static void
print_testing_suspend_button(void)
{
  const unsigned char *str;
  int action;

  str = _("Suspend testing");
  action = ACTION_TEST_SUSPEND;
  if (server_testing_suspended) {
    str = _("Resume testing");
    action = ACTION_TEST_RESUME;
  }
  printf("%s<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         form_start_simple, action, str);
}

static void
print_printing_suspend_button(void)
{
  const unsigned char *str;
  int action;

  str = _("Suspend printing");
  action = ACTION_PRINT_SUSPEND;
  if (server_printing_suspended) {
    str = _("Resume printing");
    action = ACTION_PRINT_RESUME;
  }
  printf("%s<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         form_start_simple, action, str);
}

static void
print_judging_mode_button(int judging_mode)
{
  int a = 0;
  unsigned char *str = 0;

  if (!judging_mode) {
    str = _("Set judging mode");
    a = ACTION_SET_JUDGING_MODE;
  } else {
    str = _("Set accepting mode");
    a = ACTION_SET_ACCEPTING_MODE;
  }
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         a, str);
}

static void
print_reload_server_button(const unsigned char *str)
{
  if (!str) str = _("Reload server");
  puts(form_start_simple);
  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
         ACTION_RELOAD_SERVER, str);
}

static void
read_view_params(void)
{
  unsigned char *s;
  int x, n;

  if (cgi_param("view_all_runs")) {
    filter_first_run = -1;
    filter_last_run = 1;
  }
  if (cgi_param("view_all_clars")) {
    filter_first_clar = -1;
    filter_last_clar = 1;
  }
  if (cgi_param("filter_view_clars")) {
    s = cgi_param("filter_first_clar");
    n = 0;
    if (s && sscanf(s, "%d %n", &x, &n) == 1 && !s[n]) {
      if (x >= 0) x++;
      filter_first_clar = x;
    }
    s = cgi_param("filter_last_clar");
    n = 0;
    if (s && sscanf(s, "%d %n", &x, &n) == 1 && !s[n]) {
      if (x >= 0) x++;
      filter_last_clar = x;
    }
  }
  if (cgi_param("filter_view")) {
    s = cgi_param("filter_first_run");
    n = 0;
    if (s && sscanf(s, "%d %n", &x, &n) == 1 && !s[n]) {
      if (x >= 0) x++;
      filter_first_run = x;
    }
    s = cgi_param("filter_last_run");
    n = 0;
    if (s && sscanf(s, "%d %n", &x, &n) == 1 && !s[n]) {
      if (x >= 0) x++;
      filter_last_run = x;
    }
    filter_expr = cgi_param("filter_expr");
  }
}

static void
operation_status_page(int code, unsigned char const *msg, int run_id)
{
  unsigned char href[256];
  unsigned char src_view_str[128];

  src_view_str[0] = 0;
  if (run_id >= 0) {
    snprintf(src_view_str, sizeof(src_view_str), "&source_%d=1", run_id);
  }

  if (client_sid_mode != SID_URL && client_sid_mode != SID_COOKIE) return;
  set_cookie_if_needed();
  if (code < 0) {
    client_put_header(stdout, 0, 0, global->charset, 1, 0, "Operation failed");
    if (code != -1 || !msg) msg = protocol_strerror(-code);
    printf("<h2><font color=\"red\">%s</font></h2>\n", msg);
  } else {
    hyperref(href, sizeof(href), client_sid_mode, client_sid,
             contest_id_str,
             self_url, "%s", src_view_str);
    client_put_refresh_header(global->charset, href, 0,
                              "Operation successfull");
    printf("<h2>Operation completed successfully</h2>");
  }
  print_refresh_button(_("Back"));
  client_put_footer(stdout, 0);
  exit(0);
}

static void
start_if_asked(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_START, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
stop_if_asked(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_STOP, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_reload_server(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_QUIT, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
update_standings_if_asked(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_UPDATE_STAND, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
changedur_if_asked(void)
{
  unsigned char *s;
  int dh, dm, n, r;
  time_t d;

  if (!(s = cgi_param("dur"))) goto invalid_dur;
  if (sscanf(s, "%d:%d%n", &dh, &dm, &n) != 2 || s[n]) {
    dm = 0;
    if (sscanf(s, "%d%n", &dh, &n) != 1 || s[n]) goto invalid_dur;
  }
  d = dh * 60 + dm;
  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_DURATION,
                            &d, sizeof(d));
  operation_status_page(r, 0, -1);
  return;

 invalid_dur:
  operation_status_page(-1, "Invalid duration specification", -1);
}

static void
sched_if_asked(void)
{
  int   h = 0, m = 0, n, r;
  time_t     tloc;
  time_t     sloc;
  struct tm *ploc;
  unsigned char *s;

  if (!(s = cgi_param("sched_time"))) goto invalid_time;
  if (sscanf(s, "%d:%d%n", &h, &m, &n) != 2 || s[n]) {
    if (sscanf(s, "%d%n", &h, &n) != 1 || s[n]) goto invalid_time;
    m = 0;
  }

  time(&tloc);
  ploc = localtime(&tloc);
  ploc->tm_hour = h;
  ploc->tm_min = m;
  ploc->tm_sec = 0;
  sloc = mktime(ploc);
  if (sloc == (time_t) -1) goto invalid_time;
  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_SCHEDULE,
                            &sloc, sizeof(sloc));
  operation_status_page(r, 0, -1);
  return;

 invalid_time:
  operation_status_page(-1, "Invalid time specification", -1);
}

static void
change_status_if_asked()
{
  unsigned char *s;
  unsigned char var_name[64];
  int run_id, n, status, r;

  if (!(s = cgi_nname("change_", 7))) return;

  if (sscanf(s, "change_%d%n", &run_id, &n) != 1 || s[n])
    goto invalid_operation;
  if (run_id < 0 || run_id >= server_total_runs)
    goto invalid_operation;
  snprintf(var_name, sizeof(var_name), "stat_%d", run_id);
  if (!(s = cgi_param(var_name)))
    goto invalid_operation;
  if (sscanf(s, "%d%n", &status, &n) != 1 || s[n])
    goto invalid_operation;
  /* FIXME: symbolic constants should be used */
  /* We don't have information about scoring mode, so allow any */
  if (status < 0 || status > 99 || (status > 9 && status < 99) || status == 6)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_STATUS_SET,
                          0, 0, 0, status, 0, 0, 0, 0, 0, 0, 0, 0);
  operation_status_page(r, 0, -1);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_status()
{
  unsigned char *s;
  int run_id, n, status, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("status")))
    goto invalid_operation;
  if (sscanf(s, "%d%n", &status, &n) != 1 || s[n])
    goto invalid_operation;
  /* FIXME: symbolic constants should be used */
  /* We don't have information about scoring mode, so allow any */
  if (status < 0 || status > 99 || (status > 9 && status < 99) || status == 6)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_STATUS_SET,
                          0, 0, 0, status, 0, 0, 0, 0, 0, 0, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_problem()
{
  unsigned char *s;
  int run_id, n, prob_id, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("problem")))
    goto invalid_operation;
  if (sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n])
    goto invalid_operation;
  if (prob_id <= 0)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_PROB_SET,
                          0, prob_id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_language()
{
  unsigned char *s;
  int run_id, n, lang_id, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("language")))
    goto invalid_operation;
  if (sscanf(s, "%d%n", &lang_id, &n) != 1 || s[n])
    goto invalid_operation;
  if (lang_id <= 0 || lang_id > 255)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_LANG_SET,
                          0, 0, lang_id, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_variant()
{
  unsigned char *s;
  int run_id, n, variant, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("variant")))
    goto invalid_operation;
  if (sscanf(s, "%d%n", &variant, &n) != 1 || s[n])
    goto invalid_operation;
  if (variant < 0 || variant > 255)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_VARIANT_SET,
                          0, 0, 0, 0, 0, variant, 0, 0, 0, 0, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
action_run_change_pages()
{
  unsigned char *s;
  int run_id, n, pages, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("pages")))
    goto invalid_operation;
  if (sscanf(s, "%d%n", &pages, &n) != 1 || s[n])
    goto invalid_operation;
  if (pages < 0 || pages > 255)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_PAGES_SET,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, pages, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_user_id()
{
  unsigned char *s;
  int run_id, n, user_id, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("run_user_id")))
    goto invalid_operation;
  if (sscanf(s, "%d%n", &user_id, &n) != 1 || s[n])
    goto invalid_operation;
  if (user_id <= 0)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_UID_SET,
                          user_id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_user_login()
{
  unsigned char *user_login, *s;
  int run_id, r, n;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(user_login = cgi_param("run_user_login")))
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_LOGIN_SET,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, user_login);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_imported(void)
{
  unsigned char *s;
  int n = 0, v, run_id, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("is_imported"))
      || sscanf(s, "%d%n", &v, &n) != 1
      || s[n]
      || v < 0 || v > 1)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_IMPORTED_SET,
                          0, 0, 0, 0, v, 0, 0, 0, 0, 0, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_hidden(void)
{
  unsigned char *s;
  int n = 0, v, run_id, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("is_hidden"))
      || sscanf(s, "%d%n", &v, &n) != 1
      || s[n]
      || v < 0 || v > 1)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_HIDDEN_SET,
                          0, 0, 0, 0, 0, 0, v, 0, 0, 0, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_tests(void)
{
  unsigned char *s;
  int n = 0, v, run_id, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("tests"))
      || sscanf(s, "%d%n", &v, &n) != 1
      || s[n]
      || v < -1 || v > 127)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_TESTS_SET,
                          0, 0, 0, 0, 0, 0, 0, v, 0, 0, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_score(void)
{
  unsigned char *s;
  int n = 0, v, run_id, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("score"))
      || sscanf(s, "%d%n", &v, &n) != 1
      || s[n]
      || v < -1 || v > 100000)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_SCORE_SET,
                          0, 0, 0, 0, 0, 0, 0, 0, v, 0, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
change_readonly(void)
{
  unsigned char *s;
  int n = 0, v, run_id, r;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs)
    goto invalid_operation;
  if (!(s = cgi_param("is_readonly"))
      || sscanf(s, "%d%n", &v, &n) != 1
      || s[n]
      || v < 0 || v > 1)
    goto invalid_operation;

  open_serve();
  r = serve_clnt_edit_run(serve_socket_fd, run_id,
                          PROT_SERVE_RUN_READONLY_SET,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, v, 0, 0);
  operation_status_page(r, 0, run_id);
  return;

 invalid_operation:
  operation_status_page(-1, "Invalid operation", -1);
}

static void
view_source_if_asked()
{
  char *s = cgi_nname("source_", 7);
  int   runid, n, r;

  if (!s) return;
  if (sscanf(s, "source_%d%n", &runid, &n) != 1
      || (s[n] && s[n] != '.')) return;
  if (runid < 0 || runid >= server_total_runs) return;

  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Source for run %d", runid);
  fflush(stdout);
  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_VIEW_SOURCE, runid, 0, 0,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
  }
  client_put_footer(stdout, 0);
  exit(0);
}

static void
view_report_if_asked()
{
  char *s = cgi_nname("report_", 7);
  int   runid, n, r;
  unsigned int flags = 0;

  if (!s) return;
  if (sscanf(s, "report_%d%n", &runid, &n) != 1
      || (s[n] && s[n] != '.')) return;
  if (runid < 0 || runid >= server_total_runs) return;
  if (cgi_param("t")) flags = 1;

  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Report for run %d", runid);
  fflush(stdout);
  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_VIEW_REPORT, runid, 0, flags,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
  }
  client_put_footer(stdout, 0);
  exit(0);
}

static void
view_teams_if_asked(int forced_flag)
{
  int r;

  if (!forced_flag && !cgi_param("viewteams")) return;

  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0, "Users list");
  fflush(stdout);
  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_VIEW_USERS, 0, 0, 0,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
  }
  client_put_footer(stdout, 0);
  exit(0);
}

static void
action_dump_runs(void)
{
  int r;

  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_DUMP_RUNS, 0, 0, 0,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    set_cookie_if_needed();
    client_put_header(stdout, 0, 0, global->charset, 1, 0, "Runs database error");
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
    client_put_footer(stdout, 0);
  }
  exit(0);
}

static void
action_write_xml_runs(void)
{
  int r;

  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_WRITE_XML_RUNS, 0, 0, 0,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    set_cookie_if_needed();
    client_put_header(stdout, 0, 0, global->charset, 1, 0, "Runs database error");
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
    client_put_footer(stdout, 0);
  }
  exit(0);
}

static void
action_export_xml_runs(void)
{
  int r;

  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_EXPORT_XML_RUNS, 0, 0, 0,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    set_cookie_if_needed();
    client_put_header(stdout, 0, 0, global->charset, 1, 0, "Runs database error");
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
    client_put_footer(stdout, 0);
  }
  exit(0);
}

static void
action_dump_users(void)
{
  int r;

  ASSERT(userlist_conn);
  fflush(stdout);
  r = userlist_clnt_dump_database(userlist_conn, global->contest_id, 1);
  if (r < 0) {
    set_cookie_if_needed();
    client_put_header(stdout, 0, 0, global->charset, 1, 0, "Users database error");
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           userlist_strerror(-r));
    client_put_footer(stdout, 0);
  }
  exit(0);
}

static void
action_dump_standings(void)
{
  int r;

  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_DUMP_STANDINGS, 0, 0, 0,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    set_cookie_if_needed();
    client_put_header(stdout, 0, 0, global->charset, 1, 0,
                      "Standings database error");
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
    client_put_footer(stdout, 0);
  }
  exit(0);
}

static void
action_submit_run(void)
{
  const unsigned char *p, *l, *prog_data;
  int prob_id, lang_id, variant, n;
  size_t prog_size;

  if (!(p = cgi_param("problem"))) p = "";
  if (!(l = cgi_param("language"))) l = "";
  if (cgi_param_bin("file", &prog_size, &prog_data) < 0) {
    operation_status_page(-1, _("Submission data is empty"), -1);
    return;
  }

  if (sscanf(p, "%d%n", &prob_id, &n) == 1 && !p[n]) {
    variant = 0;
  } else if (sscanf(p, "%d,%d%n", &prob_id, &variant, &n) != 2 || p[n]) {
    operation_status_page(-1, _("Invalid problem specification"), -1);
  }
  if (sscanf(l, "%d%n", &lang_id, &n) != 1 || l[n]) {
    operation_status_page(-1, _("Invalid language specification"), -1);
  }

  open_serve();
  n = serve_clnt_submit_run(serve_socket_fd, SRV_CMD_PRIV_SUBMIT_RUN,
                            client_user_id,
                            global->contest_id, 0,
                            client_ip, prob_id, lang_id, variant,
                            prog_size, prog_data);
  operation_status_page(n, 0, -1);
}

static void
action_upload_report(void)
{
  int run_id, n = 0;
  const unsigned char *s, *report_data = 0, *jr, *ur;
  size_t report_size = 0;
  unsigned int flags = 0;

  if (!(s = cgi_param("run_id")) || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]) {
    operation_status_page(-1, _("Invalid run_id"), -1);
    return;
  }
  if (cgi_param_bin("file", &report_size, &report_data) < 0) {
    operation_status_page(-1, _("Submission data is empty"), -1);
    return;
  }
  if ((jr = cgi_param("judge_report"))) flags |= 1;
  if ((ur = cgi_param("user_report"))) flags |= 2;

  open_serve();
  n = serve_clnt_upload_report(serve_socket_fd, SRV_CMD_UPLOAD_REPORT,
                               client_user_id, global->contest_id,
                               run_id, flags, report_size, report_data);
  operation_status_page(n, 0, -1);
}

static void
confirm_reset_if_asked(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0, "Confirm contest reset");
  print_refresh_button(_("No"));
  printf("<p>%s<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form>", form_start_simple,
         ACTION_RESET_2, _("Yes, reset the contest!"));
  client_put_footer(stdout, 0);
  exit(0);
}

static void
confirm_update_standings(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm update public standings");
  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, ACTION_UPDATE_STANDINGS_2,
         _("Yes, update standings!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

static void
confirm_clear_team_passwords(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm clear team passwords");
  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, ACTION_CLEAR_TEAM_PASSWORDS_2,
         _("Yes, clear passwords!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

static void
confirm_regenerate_register_if_asked(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm register user password generation");
  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, ACTION_GENERATE_REG_PASSWORDS_2,
         _("Yes, generate passwords!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

static void
confirm_regenerate_if_asked(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm user password generation");
  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, ACTION_GENERATE_PASSWORDS_2,
         _("Yes, generate passwords!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

static void
confirm_rejudge_all(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm rejudge all runs");
  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, ACTION_REJUDGE_ALL_2,
         _("Yes, rejudge!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

static void
confirm_judge_suspended(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm judge suspended runs");
  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, ACTION_JUDGE_SUSPENDED_2,
         _("Yes, judge!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

#define BITS_PER_LONG (8*sizeof(unsigned long)) 

static void
confirm_rejudge_displayed(void)
{
  unsigned char *run_mask_size_str;
  unsigned char *run_mask_str, *p;
  int run_mask_size, n = 0, i;
  unsigned long *run_mask;

  if (!(run_mask_size_str = cgi_param("run_mask_size")))
    goto invalid_parameters;
  if (sscanf(run_mask_size_str, "%d%n", &run_mask_size, &n) != 1
      || run_mask_size_str[n])
    goto invalid_parameters;
  if (run_mask_size <= 0
      || run_mask_size > server_total_runs / BITS_PER_LONG + 1)
    goto invalid_parameters;

  run_mask = (unsigned long *) alloca(run_mask_size * sizeof(run_mask[0]));
  memset(run_mask, 0, run_mask_size * sizeof(run_mask[0]));
  if (!(run_mask_str = cgi_param("run_mask")))
    goto invalid_parameters;
  for (i = 0, p = run_mask_str; i < run_mask_size; i++) {
    n = 0;
    if (sscanf(p, "%lx%n", &run_mask[i], &n) != 1) goto invalid_parameters;
    p += n;
  }
  if (*p) goto invalid_parameters;

  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm rejudge displayed runs");
  printf("<p>%s:\n", _("The following runs will be rejudged"));
  for (i = 0, n = 0; i < server_total_runs; i++) {
    if ((run_mask[i / BITS_PER_LONG] & (1 << (i % BITS_PER_LONG)))) {
      if (n) printf(", ");
      printf("%d", i);
      n++;
    }
  }
  printf(".\n<p>");
  print_refresh_button(_("No"));
  printf("<p>%s\n", form_start_simple);

  printf("<input type=\"hidden\" name=\"run_mask_size\" value=\"%d\">\n",
         run_mask_size);
  printf("<input type=\"hidden\" name=\"run_mask\" value=\"");
  for (i = 0; i < run_mask_size; i++) {
    if (i > 0) printf(" ");
    printf("%lx", run_mask[i]);
  }
  printf("\">\n");

  printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", ACTION_REJUDGE_DISPLAYED_2,
         _("Yes, rejudge!"));
  client_put_footer(stdout, 0);
  exit(0);

 invalid_parameters:
  operation_status_page(-1, "Invalid parameter", -1);
}

static void
confirm_squeeze(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm squeeze run log");
  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, ACTION_SQUEEZE_RUNS_2,
         _("Yes, squeeze!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

static void
confirm_continue(void)
{
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm continue contest");
  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, ACTION_CONTINUE_2,
         _("Yes, continue!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

static void
confirm_clear_run(void)
{
  unsigned char *s;
  int r, n;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &r, &n) != 1
      || s[n]
      || r < 0
      || r >= server_total_runs) {
    operation_status_page(-1, "Invalid parameter", -1);
    return;
  }

  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Confirm clear run %d", r);
  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s"
         "<input type=\"hidden\" name=\"run_id\" value=\"%d\">"
         "<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, r, ACTION_CLEAR_RUN_2,
         _("Yes, clear!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

static void
do_contest_reset_if_asked(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_RESET, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
do_clear_team_passwords(void)
{
  int r;

  r = userlist_clnt_clear_team_passwords(userlist_conn, global->contest_id);
  operation_status_page(r<0?-1:0, userlist_strerror(-r), -1);

}

static void
do_generate_register_passwords_if_asked(void)
{
  int r;

  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "New register passwords");
  print_nav_buttons();
  printf("<hr>");
  fflush(stdout);

  r = userlist_clnt_generate_team_passwd(userlist_conn,
                                         ULS_GENERATE_PASSWORDS,
                                         global->contest_id, 1);
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           userlist_strerror(-r));
  }

  printf("<hr>");
  print_nav_buttons();
  client_put_footer(stdout, 0);
  exit(0);
}

static void
do_generate_passwords_if_asked(void)
{
  int r;

  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0, "New passwords");
  print_nav_buttons();
  printf("<hr>");
  fflush(stdout);

  r = userlist_clnt_generate_team_passwd(userlist_conn,
                                         ULS_GENERATE_TEAM_PASSWORDS,
                                         global->contest_id, 1);
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           userlist_strerror(-r));
  }

  printf("<hr>");
  print_nav_buttons();
  client_put_footer(stdout, 0);
  exit(0);
}

static void
action_merge_runs(void)
{
  int r;
  unsigned char *xml;

  open_serve();
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0, "Run merge results");
  print_nav_buttons();
  printf("<hr>");
  fflush(stdout);

  xml = cgi_param("file");
  if (!xml) xml = "";
  r = serve_clnt_import_xml_runs(serve_socket_fd, 1, xml);
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           protocol_strerror(-r));
  }

  printf("<hr>");
  print_nav_buttons();
  client_put_footer(stdout, 0);
  exit(0);
}

static void
do_suspend_if_asked(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_SUSPEND, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
do_resume_if_asked(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_RESUME, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_test_suspend(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_TEST_SUSPEND, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_test_resume(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_TEST_RESUME, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_print_suspend(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_PRINT_SUSPEND, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_print_resume(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_PRINT_RESUME, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_set_judgind_mode(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_SET_JUDGING_MODE, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_set_accepting_mode(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_SET_ACCEPTING_MODE, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
do_rejudge_all_if_asked(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_REJUDGE_ALL, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_judge_suspended(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_JUDGE_SUSPENDED, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_rejudge_displayed(void)
{
  unsigned char *run_mask_size_str;
  unsigned char *run_mask_str, *p;
  int run_mask_size, n = 0, i, r;
  unsigned long *run_mask;

  if (!(run_mask_size_str = cgi_param("run_mask_size")))
    goto invalid_parameters;
  if (sscanf(run_mask_size_str, "%d%n", &run_mask_size, &n) != 1
      || run_mask_size_str[n])
    goto invalid_parameters;
  if (run_mask_size <= 0
      || run_mask_size > server_total_runs / BITS_PER_LONG + 1)
    goto invalid_parameters;

  run_mask = (unsigned long *) alloca(run_mask_size * sizeof(run_mask[0]));
  memset(run_mask, 0, run_mask_size * sizeof(run_mask[0]));
  if (!(run_mask_str = cgi_param("run_mask")))
    goto invalid_parameters;
  for (i = 0, p = run_mask_str; i < run_mask_size; i++) {
    n = 0;
    if (sscanf(p, "%lx%n", &run_mask[i], &n) != 1) goto invalid_parameters;
    p += n;
  }
  if (*p) goto invalid_parameters;

  open_serve();
  r = serve_clnt_rejudge_by_mask(serve_socket_fd, SRV_CMD_REJUDGE_BY_MASK,
                                 run_mask_size, run_mask);
  operation_status_page(r, 0, -1);
  return;

 invalid_parameters:
  operation_status_page(-1, "Invalid parameter", -1);
}

static void
action_squeeze_runs(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_SQUEEZE_RUNS, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_continue(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_CONTINUE, 0, 0);
  operation_status_page(r, 0, -1);
}

static void
action_clear_run(void)
{
  unsigned char *s;
  int r, n;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &r, &n) != 1
      || s[n]
      || r < 0
      || r >= server_total_runs) {
    operation_status_page(-1, "Invalid parameter", -1);
    return;
  }

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_CLEAR_RUN, &r, sizeof(r));
  operation_status_page(r, 0, -1);
}

static void
action_priv_print_run(void)
{
  unsigned char *s;
  int r, n;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &r, &n) != 1
      || s[n]
      || r < 0
      || r >= server_total_runs) {
    operation_status_page(-1, "Invalid parameter", -1);
    return;
  }

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_PRIV_PRINT_RUN,
                            &r, sizeof(r));
  operation_status_page(r, 0, -1);
}

static void
action_priv_download_run(void)
{
  unsigned char *s;
  int r, n;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &r, &n) != 1
      || s[n]
      || r < 0
      || r >= server_total_runs) {
    operation_status_page(-1, "Invalid parameter", -1);
    return;
  }

  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_PRIV_DOWNLOAD_RUN, r, 0, 0,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    set_cookie_if_needed();
    client_put_header(stdout, 0, 0, global->charset, 1, 0, "Download error");
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
    client_put_footer(stdout, 0);
  }
  exit(0);
}

static void
action_compare_runs(void)
{
  unsigned char *s;
  int r, n, r2;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &r, &n) != 1
      || s[n]
      || r < 0
      || r >= server_total_runs) {
    operation_status_page(-1, "Invalid parameter", -1);
    return;
  }
  if (!(s = cgi_param("run_id2"))
      || sscanf(s, "%d%n", &r2, &n) != 1
      || s[n]
      || r2 < 0
      || r2 >= server_total_runs) {
    operation_status_page(-1, "Invalid parameter", -1);
    return;
  }

  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_COMPARE_RUNS, r, r2, 0,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    set_cookie_if_needed();
    client_put_header(stdout, 0, 0, global->charset, 1, 0, "Compare error");
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
    client_put_footer(stdout, 0);
  }
  exit(0);
}

static void
action_reset_filter(void)
{
  int r;

  open_serve();
  r = serve_clnt_reset_filter(serve_socket_fd, SRV_CMD_RESET_FILTER,
                              client_sid, client_user_id, global->contest_id);
  operation_status_page(r, 0, -1);
}

static void
action_toggle_visibility(void)
{
  unsigned char const *p;
  int user_id, n, r;

  if (!(p = cgi_param("user_id"))
      || sscanf(p, "%d%n", &user_id, &n) != 1
      || p[n]
      || user_id <= 0) {
    operation_status_page(-1, "Invalid parameter", -1);
    return;
  }

  r = userlist_clnt_change_registration(userlist_conn, user_id,
                                        global->contest_id,
                                        -1, 3, USERLIST_UC_INVISIBLE);
  operation_status_page(r<0?-1:0, userlist_strerror(-r), -1);
}

static void
action_toggle_ban(void)
{
  unsigned char const *p;
  int user_id, n, r;

  if (!(p = cgi_param("user_id"))
      || sscanf(p, "%d%n", &user_id, &n) != 1
      || p[n]
      || user_id <= 0) {
    operation_status_page(-1, "Invalid parameter", -1);
    return;
  }

  r = userlist_clnt_change_registration(userlist_conn, user_id,
                                        global->contest_id,
                                        -1, 3, USERLIST_UC_BANNED);
  operation_status_page(r<0?-1:0, userlist_strerror(-r), -1);
}

static void
action_toggle_lock(void)
{
  unsigned char const *p;
  int user_id, n, r;

  if (!(p = cgi_param("user_id"))
      || sscanf(p, "%d%n", &user_id, &n) != 1
      || p[n]
      || user_id <= 0) {
    operation_status_page(-1, "Invalid parameter", -1);
    return;
  }

  r = userlist_clnt_change_registration(userlist_conn, user_id,
                                        global->contest_id,
                                        -1, 3, USERLIST_UC_LOCKED);
  operation_status_page(r<0?-1:0, userlist_strerror(-r), -1);
}

static void
do_rejudge_problem_if_asked(void)
{
  unsigned char *p;
  int prob, n, r;

  if (!(p = cgi_param("problem")) ||
      sscanf(p, "%d %n", &prob, &n) != 1 || p[n] || prob <= 0) {
    operation_status_page(-1, "Problem to rejudge is not set", -1);
    return;
  }
  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_REJUDGE_PROBLEM,
                            &prob, sizeof(prob));
  operation_status_page(r, 0, -1);
}

static void
view_clar_if_asked()
{
  char *s = cgi_nname("clar_", 5);
  int   clarid, n;
  int r;

  if (!s) return;
  if (sscanf(s, "clar_%d%n", &clarid, &n) != 1 || (s[n] && s[n]!='.')) return;
  if (clarid < 0 || clarid >= server_total_clars) return;

  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0,
                    "Clarification %d", clarid);
  fflush(stdout);
  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_VIEW_CLAR, clarid, 0, 0,
                      client_sid_mode, self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
  }

  client_put_footer(stdout, 0);
  exit(0);
}

static void
send_msg_if_asked(void)
{
  unsigned char const *subj, *text, *dest_id_str, *dest_login;
  int dest_id = -1, x, n = 0, r;

  if (!cgi_param("msg_send")) return;

  subj = cgi_param("msg_subj");
  text = cgi_param("msg_text");
  if ((dest_id_str = cgi_param("msg_dest_id"))
      && sscanf(dest_id_str, "%d%n", &x, &n) == 1
      && !dest_id_str[n])
    dest_id = x;
  dest_login = cgi_param("msg_dest_login");
  if (!subj) subj = "";
  if (!dest_login || !*dest_login) dest_login = "all";
  if (!*text) {
    if (client_sid_mode != SID_URL && client_sid_mode != SID_COOKIE) return;
    operation_status_page(-1, "Empty message body", -1);
  }
  if (!*subj) subj = _("(no subject)");

  open_serve();
  r = serve_clnt_message(serve_socket_fd, SRV_CMD_PRIV_MSG,
                         dest_id, -1, dest_login,
                         subj, text);
  if (client_sid_mode != SID_URL && client_sid_mode != SID_COOKIE) return;
  operation_status_page(r, 0, -1);
}

static void
send_reply_if_asked(void)
{
  int dest_uid = 1, ref, n, r;
  unsigned char *txt = 0, *s;

  if (cgi_param("answ_all")) {
    dest_uid = 0;
    txt = cgi_param("reply");
    if (!txt) return;
  } else if (cgi_param("answ_text")) {
    txt = cgi_param("reply");
    if (!txt) return;
  } else if (cgi_param("answ_read")) {
    txt = xstrdup(_("Read the problem.\n"));
  } else if (cgi_param("answ_no_comments")) {
    txt = xstrdup(_("No comments.\n"));
  } else if (cgi_param("answ_yes")) {
    txt = xstrdup(_("YES."));
  } else if (cgi_param("answ_no")) {
    txt = xstrdup(_("NO."));
  } else {
    return;
  }
  if (!txt) {
    operation_status_page(-1, "Message body is empty", -1);
    return;
  }

  s = cgi_param("in_reply_to");
  if (!s || sscanf(s, "%d%n", &ref, &n) != 1 || s[n]
      || ref < 0 || ref >= server_total_clars) {
    operation_status_page(-1, "Invalid reference id", -1);
    return;
  }

  open_serve();
  r = serve_clnt_message(serve_socket_fd, SRV_CMD_PRIV_REPLY,
                         dest_uid, ref, 0, 0, txt);
  operation_status_page(r, 0, -1);
}

static void
log_out_if_asked(void)
{
  if (!cgi_param("logout")) return;
  if (client_sid) {
    open_userlist_server();
    userlist_clnt_logout(userlist_conn, client_ip, client_sid);
  }
  if (client_sid_mode == SID_COOKIE) {
    client_cookie = 0;
    need_set_cookie = 1;
  }
  set_cookie_if_needed();
  client_put_header(stdout, 0, 0, global->charset, 1, 0, "%s", _("Good-bye"));
  printf("<p>%s</p>\n",
         _("Good-bye!"));
  client_put_footer(stdout, 0);
  exit(0);
}

static int
set_defaults(void)
{
  if (global->run_page_size <= 0 || global->run_page_size > 25) {
    global->run_page_size = DEFAULT_RUN_PAGE_SIZE;
  }
  if (global->clar_page_size <= 0 || global->clar_page_size > 25) {
    global->clar_page_size = DEFAULT_CLAR_PAGE_SIZE;
  }

  if (!global->root_dir[0]) {
    err("root_dir must be set");
    return -1;
  }
  path_init(global->var_dir, global->root_dir, DEFAULT_VAR_DIR);
  path_init(global->status_file, global->var_dir, DEFAULT_STATUS_FILE);
  if (!global->charset[0]) {
    pathcpy(global->charset, DEFAULT_CHARSET);
  }

  if (global->contest_id <= 0) {
    err("contest_id must be set");
    return -1;
  }
  path_init(global->serve_socket, global->var_dir, DEFAULT_SERVE_SOCKET);

  /* FIXME: should we support localization */
  /*
  if (!global->l10n_dir[0] || !global->enable_l10n) {
    global->enable_l10n = 0;
    global->l10n_dir[0] = 0;
  }
  */
  return 0;
}

static void
parse_client_ip(void)
{
  unsigned int b1, b2, b3, b4;
  int n;
  unsigned char *s = getenv("REMOTE_ADDR");

  client_ip = 0;
  if (!s) return;
  n = 0;
  if (sscanf(s, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || s[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
    client_ip = 0xffffffff;
    return;
  }
  client_ip = b1 << 24 | b2 << 16 | b3 << 8 | b4;
}

static int
parse_contest_id(void)
{
  unsigned char *s = cgi_param("contest_id");
  int v = 0, n = 0;

  if (!s) return 0;
  if (sscanf(s, "%d %n", &v, &n) != 1 || s[n] || v < 0) return 0;
  return v;
}

static int
parse_name_contest_id(unsigned char *basename)
{
  int v, n;

  if (!basename) return 0;
  if (sscanf(basename, "-%d %n", &v, &n)!=1 || basename[n] || v < 0) return 0;
  return v;
}

static int
check_config_exist(unsigned char const *path)
{
  struct stat sb;

  if (stat(path, &sb) >= 0 && S_ISREG(sb.st_mode) && access(path, R_OK) >= 0) {
    return 1;
  }
  return 0;
}

static void
initialize(int argc, char *argv[])
{
  path_t  fullname;
  path_t  dirname;
  path_t  basename;
  path_t  cfgname;
  path_t  cfgdir;
  path_t  progname;
  path_t  cfgname2;
  struct generic_section_config *p;
  char   *s = getenv("SCRIPT_FILENAME");
  int namelen;
  int name_contest_id;
  int name_ok = 0, errcode;
  
  pathcpy(fullname, argv[0]);
  if (s) pathcpy(fullname, s);
  os_rDirName(fullname, dirname, PATH_MAX);
  os_rGetBasename(fullname, basename, PATH_MAX);
  if (!strncmp(basename, "master", 6)) {
    priv_level = PRIV_LEVEL_ADMIN;
    namelen = 6;
  } else if (!strncmp(basename, "judge", 5)) {
    priv_level = PRIV_LEVEL_JUDGE;
    namelen = 5;
  } else {
    client_not_configured(0, "bad program name", 0);
    /* never get here */
  }
  memset(progname, 0, sizeof(progname));
  strncpy(progname, basename, namelen);

  /* we need CGI parameters relatively early because of contest_id */
  cgi_read(0);
  cgi_contest_id = parse_contest_id();
  name_contest_id = parse_name_contest_id(basename + namelen);

  /*
   * if CGI_DATA_PATH is absolute, do not append the program start dir
   */
  /* FIXME: we need to perform "/" translation */
  if (CGI_DATA_PATH[0] == '/') {
    pathmake(cfgdir, CGI_DATA_PATH, "/", NULL);
  } else {
    pathmake(cfgdir, dirname, "/",CGI_DATA_PATH, "/", NULL);
  }

  /*
    Try different variants:
      o If basename has the form <prog>-<number>, then consider
        <number> as contest_id, ignoring the contest_id from
        CGI arguments. Try config file <prog>-<number>.cfg
        first, and then try <prog>.cfg.
      o If basename has the bare form <prog>, then read contest_id
        from CGI parameters. Try config file <prog>-<contest_id>.cfg
        first, and then try <prog>.cfg. If contest_id in CGI is not set,
        refuse to run.
      o If basename has any other form, ignore contest_id from
        CGI parameters. Always use config file <prog>.cfg.
  */
  if (name_contest_id > 0) {
    // first case
    cgi_contest_id = 0;
    snprintf(cfgname, sizeof(cfgname), "%s%s.cfg", cfgdir, basename);
    name_ok = check_config_exist(cfgname);
    if (!name_ok) {
      snprintf(cfgname2, sizeof(cfgname2), "%s%s-%d.cfg", cfgdir, progname,
               name_contest_id);
      if (strcmp(cfgname2, cfgname) != 0 && check_config_exist(cfgname2)) {
        name_ok = 1;
        strcpy(cfgname, cfgname2);
      }
    }
    if (!name_ok) {
      snprintf(cfgname2, sizeof(cfgname2), "%s%s-%06d.cfg", cfgdir, progname,
               name_contest_id);
      if (strcmp(cfgname2, cfgname) != 0 && check_config_exist(cfgname2)) {
        name_ok = 1;
        strcpy(cfgname, cfgname2);
      }
    }
    if (!name_ok) {
      snprintf(cfgname, sizeof(cfgname), "%s%s.cfg", cfgdir, progname);
      name_ok = check_config_exist(cfgname);
    }
  } else if (strlen(basename) == namelen) {
    // second case
    if (!cgi_param("contest_id") && !cgi_param("sid_mode")
        && !cgi_param("SID")) {
      display_enter_password_2();
      exit(0);
    }

    if (cgi_contest_id <= 0) {
      client_not_configured(0, "Contest ID is unknown", 0);
      /* never get here */
    }
    snprintf(cfgname, sizeof(cfgname), "%s%s-%d.cfg", cfgdir, progname,
             cgi_contest_id);
    name_ok = check_config_exist(cfgname);
    if (!name_ok) {
      snprintf(cfgname, sizeof(cfgname), "%s%s-%06d.cfg", cfgdir, progname,
               cgi_contest_id);
      name_ok = check_config_exist(cfgname);
    }
    if (!name_ok) {
      snprintf(cfgname, sizeof(cfgname), "%s%s.cfg", cfgdir, progname);
      name_ok = check_config_exist(cfgname);
    }
  } else {
    // third case
    cgi_contest_id = 0;
    snprintf(cfgname, sizeof(cfgname), "%s%s.cfg", cfgdir, basename);
    name_ok = check_config_exist(cfgname);
  }

  config = parse_param(cfgname, 0, params, 1);
  if (!config)
    client_not_configured(0, "config file not parsed", 0);

  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  }
  if (!p)
    client_not_configured(0, "no global section", 0);
  global = (struct section_global_data *) p;

  if (!global->contests_dir[0]) {
    client_not_configured(0, "contests are not defined", 0);
    /* never get here */
  }
  contests_set_directory(global->contests_dir);

  /* verify contest_id from the configuration file */
  if (name_contest_id > 0) {
    if (global->contest_id > 0 && name_contest_id != global->contest_id) {
      client_not_configured(0, "contest_id's do not match", 0);
      /* never get here */
    }
    global->contest_id = name_contest_id;
  } else if (cgi_contest_id > 0) {
    if (global->contest_id > 0 && cgi_contest_id != global->contest_id) {
      client_not_configured(0, "contest_id's do not match", 0);
      /* never get here */
    }
    global->contest_id = cgi_contest_id;
  } else {
    if (global->contest_id <= 0) {
      client_not_configured(0, "contest_id is not set", 0);
      /* never get here */
    }
  }

  if (cgi_contest_id > 0) {
    snprintf(contest_id_str, sizeof(contest_id_str), "&contest_id=%d",
             cgi_contest_id);
  }

  if ((errcode = contests_get(global->contest_id, &cur_contest)) < 0) {
    err("contests_get failed: %d: %s", global->contest_id,
        contests_strerror(-errcode));
    client_not_configured(0, "invalid contest", 0);
    /* never get here */
  }

  // FIXME: maybe it's better to eliminate root_dir, var_dir, etc?
  if (cur_contest->root_dir) {
    pathcpy(global->root_dir, cur_contest->root_dir);
  }

  if (set_defaults() < 0)
    client_not_configured(global->charset, "bad configuration", 0);
  logger_set_level(-1, LOG_WARNING);
  parse_client_ip();

  make_self_url();
  client_make_form_headers(self_url);
}

static void
open_serve(void)
{
  if (serve_socket_fd >= 0) return;
  serve_socket_fd = serve_clnt_open(global->serve_socket);
  if (serve_socket_fd < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           "Cannot connect to the contest server");
    printf("<p>Error: %s</p>\n", protocol_strerror(-serve_socket_fd));
    client_put_footer(stdout, 0);
    exit(0);
  }
}

static void
view_standings_if_asked()
{
  int r;

  if (!cgi_param("stand")) return;

  fflush(stdout);
  open_serve();
  r = serve_clnt_standings(serve_socket_fd, 1,
                           client_user_id,
                           global->contest_id, 0,
                           priv_level,
                           client_sid_mode,
                           self_url,
                           hidden_vars,
                           contest_id_str);

  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           protocol_strerror(-r));
  }

  client_put_footer(stdout, 0);
  exit(0);
}

static void
display_master_page(void)
{
  int r;

  open_serve();
  r = serve_clnt_master_page(serve_socket_fd, 1,
                             client_sid,
                             client_user_id,
                             global->contest_id, 0,
                             client_ip,
                             priv_level,
                             client_sid_mode,
                             filter_first_run,
                             filter_last_run,
                             filter_first_clar,
                             filter_last_clar,
                             self_url,
                             filter_expr,
                             hidden_vars, contest_id_str);
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           protocol_strerror(-r));
    return;
  }
}

static void
print_nav_buttons(void)
{
  printf("<table><tr><td>");
  print_refresh_button(0);
  printf("</td><td>");
  print_standings_button(0);
  printf("</td><td>");
  print_teamview_button(0);
  printf("</td><td>");
  print_logout_button(0);
  printf("</td></tr></table>\n");
}

static void
print_dump_buttons(void)
{
  printf("<table><tr><td>");
  print_dump_runs_button(0);
  printf("</td><td>");
  print_dump_users_button(0);
  printf("</td><td>");
  print_dump_standings_button(0);
  printf("</td></tr><tr><td>");
  print_export_xml_runs_button(0);
  printf("</td><td>");
  print_write_xml_runs_button(0);
  printf("</td></tr></table>\n");
}

int
main(int argc, char *argv[])
{
  int server_lag = 3;
  int access_flag = 0;

  initialize(argc, argv);

  if (!client_check_source_ip(global->allow_deny,
                              global->allow_from,
                              global->deny_from))
    client_access_denied(global->charset, 0);

  switch(priv_level) {
  case PRIV_LEVEL_ADMIN:
    access_flag = contests_check_master_ip(global->contest_id, client_ip);
    break;
  case PRIV_LEVEL_JUDGE:
    access_flag = contests_check_judge_ip(global->contest_id, client_ip);
    break;
  }
  if (!access_flag) {
    client_access_denied(global->charset, 0);
  }

  // done in initialize
  //cgi_read(global->charset);

  if (authentificate() != 1) client_access_denied(global->charset, 0);
  read_state_params();
  read_view_params();

  if (cur_contest->client_ignore_time_skew) {
    server_lag = 0;
  }
  if (!client_check_server_status(global->charset, global->status_file,
                                  server_lag, 0)) {
    return 0;
  }

  if (priv_level == PRIV_LEVEL_ADMIN) {
    //fprintf(stderr, ">>%d\n", client_action);

    switch (client_action) {
    case ACTION_GENERATE_PASSWORDS_1:
      confirm_regenerate_if_asked();
      break;
    case ACTION_GENERATE_PASSWORDS_2:
      do_generate_passwords_if_asked();
      break;
    case ACTION_GENERATE_REG_PASSWORDS_1:
      confirm_regenerate_register_if_asked();
      break;
    case ACTION_GENERATE_REG_PASSWORDS_2:
      do_generate_register_passwords_if_asked();
      break;
    case ACTION_CLEAR_TEAM_PASSWORDS_1:
      confirm_clear_team_passwords();
      break;
    case ACTION_CLEAR_TEAM_PASSWORDS_2:
      do_clear_team_passwords();
      break;
    case ACTION_SUSPEND:
      do_suspend_if_asked();
      break;
    case ACTION_RESUME:
      do_resume_if_asked();
      break;
    case ACTION_TEST_SUSPEND:
      action_test_suspend();
      break;
    case ACTION_TEST_RESUME:
      action_test_resume();
      break;
    case ACTION_PRINT_SUSPEND:
      action_print_suspend();
      break;
    case ACTION_PRINT_RESUME:
      action_print_resume();
      break;
    case ACTION_UPDATE_STANDINGS_1:
      confirm_update_standings();
      break;
    case ACTION_UPDATE_STANDINGS_2:
      update_standings_if_asked();
      break;
    case ACTION_RESET_1:
      confirm_reset_if_asked();
      break;
    case ACTION_RESET_2:
      do_contest_reset_if_asked();
      break;
    case ACTION_START:
      start_if_asked();
      break;
    case ACTION_STOP:
      stop_if_asked();
      break;
    case ACTION_REJUDGE_ALL_1:
      confirm_rejudge_all();
      break;
    case ACTION_REJUDGE_ALL_2:
      do_rejudge_all_if_asked();
      break;
    case ACTION_JUDGE_SUSPENDED_1:
      confirm_judge_suspended();
      break;
    case ACTION_JUDGE_SUSPENDED_2:
      action_judge_suspended();
      break;
    case ACTION_REJUDGE_DISPLAYED_1:
      confirm_rejudge_displayed();
      break;
    case ACTION_REJUDGE_DISPLAYED_2:
      action_rejudge_displayed();
      break;
    case ACTION_REJUDGE_PROBLEM:
      do_rejudge_problem_if_asked();
      break;
    case ACTION_SCHEDULE:
      sched_if_asked();
      break;
    case ACTION_DURATION:
      changedur_if_asked();
      break;
    case ACTION_RUN_CHANGE_USER_ID:
      change_user_id();
      break;
    case ACTION_RUN_CHANGE_USER_LOGIN:
      change_user_login();
      break;
    case ACTION_RUN_CHANGE_LANG:
      change_language();
      break;
    case ACTION_RUN_CHANGE_PROB:
      change_problem();
      break;
    case ACTION_RUN_CHANGE_STATUS:
      change_status();
      break;
    case ACTION_RUN_CHANGE_IMPORTED:
      change_imported();
      break;
    case ACTION_RUN_CHANGE_HIDDEN:
      change_hidden();
      break;
    case ACTION_RUN_CHANGE_READONLY:
      change_readonly();
      break;
    case ACTION_RUN_CHANGE_TESTS:
      change_tests();
      break;
    case ACTION_RUN_CHANGE_SCORE:
      change_score();
      break;
    case ACTION_USER_TOGGLE_BAN:
      action_toggle_ban();
      break;
    case ACTION_USER_TOGGLE_LOCK:
      action_toggle_lock();
      break;
    case ACTION_USER_TOGGLE_VISIBILITY:
      action_toggle_visibility();
      break;
    case ACTION_SQUEEZE_RUNS:
      confirm_squeeze();
      break;
    case ACTION_CLEAR_RUN:
      confirm_clear_run();
      break;
    case ACTION_SQUEEZE_RUNS_2:
      action_squeeze_runs();
      break;
    case ACTION_CLEAR_RUN_2:
      action_clear_run();
      break;
    case ACTION_DUMP_RUNS:
      action_dump_runs();
      break;
    case ACTION_EXPORT_XML_RUNS:
      action_export_xml_runs();
      break;
    case ACTION_WRITE_XML_RUNS:
      action_write_xml_runs();
      break;
    case ACTION_DUMP_USERS:
      action_dump_users();
      break;
    case ACTION_DUMP_STANDINGS:
      action_dump_standings();
      break;
    case ACTION_SET_JUDGING_MODE:
      action_set_judgind_mode();
      break;
    case ACTION_SET_ACCEPTING_MODE:
      action_set_accepting_mode();
      break;
    case ACTION_CONTINUE:
      confirm_continue();
      break;
    case ACTION_CONTINUE_2:
      action_continue();
      break;
    case ACTION_MERGE_RUNS:
      action_merge_runs();
      break;
    case ACTION_RELOAD_SERVER:
      action_reload_server();
      break;
    case ACTION_RUN_CHANGE_VARIANT:
      change_variant();
      break;
    case ACTION_RUN_CHANGE_PAGES:
      action_run_change_pages();
      break;
    default:
      change_status_if_asked();
      break;
    }
  }
  switch (client_action) {
  case ACTION_SUBMIT_RUN:
    action_submit_run();
    break;
  case ACTION_RESET_FILTER:
    action_reset_filter();
    break;
  case ACTION_PRINT_PRIV_RUN:
    action_priv_print_run();
    break;
  case ACTION_PRIV_DOWNLOAD_RUN:
    action_priv_download_run();
    break;
  case ACTION_COMPARE_RUNS:
    action_compare_runs();
    break;
  case ACTION_UPLOAD_REPORT:
    action_upload_report();
    break;
  }
  log_out_if_asked();
  view_source_if_asked();
  view_report_if_asked();
  view_clar_if_asked();
  view_teams_if_asked(0);
  send_reply_if_asked();
  send_msg_if_asked();

  set_cookie_if_needed();
  if (cur_contest->name) {
    client_put_header(stdout, 0, 0, global->charset, 1, 0,
                      "%s: %s - &quot;%s&quot;",
                      _("Monitor"),
                      protocol_priv_level_str(priv_level),
                      cur_contest->name);
  } else {
    client_put_header(stdout, 0, 0, global->charset, 1, 0, "%s: %s",
                      _("Monitor"),
                      protocol_priv_level_str(priv_level));
  }

  view_standings_if_asked();

  print_nav_buttons();
  print_dump_buttons();
  client_print_server_status(priv_level, form_start_simple, 0);

  print_nav_buttons();

  if (priv_level == PRIV_LEVEL_ADMIN) {
    printf("<table><tr><td>");
    print_update_button(0);
    printf("</td><td>");
    print_reset_button(0);
    printf("</td><td>");
    if (!server_clients_suspended) {
      printf("</td><td>");
      print_suspend_button(0);
    } else {
      printf("</td><td>");
      print_resume_button(0);
    }
    printf("</td><td>");
    print_testing_suspend_button();
    if (server_printing_enabled) {
      printf("</td><td>");
      print_printing_suspend_button();
    }
    if (server_score_system == SCORE_OLYMPIAD) {
      printf("</td><td>");
      print_judging_mode_button(server_olympiad_judging_mode);
    }
    printf("</td></tr></table>\n");
    printf("<table><tr><td>");
    print_regenerate_button(0);
    printf("</td><td>");
    print_regenerate_reg_button(0);
    printf("</td><td>");
    print_clear_team_passwords_button(0);
    printf("</td></tr></table>\n");
    printf("<table><tr><td>");
    print_reload_server_button(0);
    printf("</td></tr></table>\n");
  }

  fflush(stdout);
  display_master_page();

  if (priv_level >= PRIV_LEVEL_JUDGE) {
    printf("<hr><h2>%s</h2>", _("Compose a message to all the teams"));
    puts(form_start_multipart);
    printf("<table>\n");
    printf("<tr>"
           "<td>%s:</td>"
           "<td><input type=\"text\" size=\"16\" name=\"msg_dest_id\"></td>"
           "</tr>\n", _("To user id"));
    printf("<tr>"
           "<td>%s:</td>"
           "<td><input type=\"text\" size=\"32\" name=\"msg_dest_login\"></td>"
           "</tr>\n", _("To user login"));
    printf("<tr>"
           "<td>%s:</td>"
           "<td><input type=\"text\" size=\"64\" name=\"msg_subj\"></td>"
           "</tr>\n",
           _("Subject"));
    printf("</table>\n");
    printf("<p><textarea name=\"msg_text\" rows=\"20\" cols=\"60\">"
           "</textarea></p>");
    printf("<p><input type=\"submit\" name=\"msg_send\" value=\"%s\">",
           _("Send"));
    printf("</form>\n");
  }

  print_nav_buttons();

#if 0
  puts("<hr><pre>");
  //fflush(0);
  //system("printenv");
  puts("");
  for (i = 0; i < argc; i++) {
    printf("argv[%d] = '%s'\n", i, argv[i]);
  }
  puts("");
  cgi_print_param();
#endif
  client_put_footer(stdout, 0);

  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */

