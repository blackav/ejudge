/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2000-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_types.h"

#include "cgi.h"
#include "parsecfg.h"
#include "pathutl.h"
#include "errlog.h"
#include "fileutl.h"
#include "clntutil.h"
#include "clarlog.h"
#include "base64.h"
#include "contests.h"
#include "userlist_proto.h"
#include "userlist_clnt.h"
#include "protocol.h"
#include "serve_clnt.h"
#include "misctext.h"
#include "client_actions.h"
#include "l10n.h"

#include <reuse/osdeps.h>
#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#define _(x) gettext(x)
#else
#define _(x) x
#define gettext(x) x
#endif

/*
 * The default path to data directory
 */
#if !defined CGI_DATA_PATH
#define CGI_DATA_PATH "../cgi-data"
#endif

static char const password_accept_chars[] =
" !#$%\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"`abcdefghijklmnopqrstuvwxyz{|}~ ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿"
"ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";

/* configuration defaults */
#define DEFAULT_VAR_DIR              "var"
#define DEFAULT_STATUS_FILE          "status/dir/status"
#define DEFAULT_SERVER_LAG           10
#define DEFAULT_SERVE_SOCKET         "serve"

#if defined EJUDGE_CHARSET
#define DEFAULT_CHARSET              EJUDGE_CHARSET
#else
#define DEFAULT_CHARSET              "iso8859-1"
#endif /* EJUDGE_CHARSET */

/* global configuration settings */
struct section_global_data
{
  struct generic_section_config g;

  int    allow_deny;
  int    show_generation_time;
  path_t root_dir;
  path_t var_dir;
  path_t allow_from;
  path_t deny_from;
  path_t status_file;
  path_t charset;
  path_t serve_socket;

  /* locallization stuff */
  int    enable_l10n;
  path_t l10n_dir;

  /* userlist-server stuff */
  int contest_id;
  path_t socket_path;
  path_t contests_dir;
};

/* configuration information */
static struct generic_section_config *config;
static struct section_global_data *global;

/* new userlist-server related variables */
static const struct contest_desc *cur_contest;
static struct userlist_clnt *server_conn;
static ej_ip_t client_ip;
static unsigned char *self_url;
static int ssl_flag = 0;
static unsigned char *head_style = "h2";
static unsigned char *par_style = "";

static int cgi_contest_id;
static unsigned char contest_id_str[128];

/* client state variables */
static unsigned char *client_login;
static unsigned char *client_password;
static unsigned char *client_team_name;
static int     client_locale_id = -1;
static int     client_team_id;
static int     client_action;

static int     client_view_all_runs;
static int     client_view_all_clars;

static int     force_recheck_status = 0;

static char   *error_log;

static char *header_txt, *footer_txt;
static size_t header_len, footer_len;

static int serve_socket_fd = -1;

static ej_cookie_t client_sid;

static unsigned char form_start_simple[1024];
static unsigned char form_start_multipart[1024];
static unsigned char hidden_vars[1024];

static void global_init_func(struct generic_section_config *);

/* description of configuration parameters */
#define GLOBAL_OFFSET(x) XOFFSET(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(allow_deny, "d"),
  GLOBAL_PARAM(show_generation_time, "d"),
  GLOBAL_PARAM(root_dir, "s"),
  GLOBAL_PARAM(var_dir, "s"),
  GLOBAL_PARAM(allow_from, "s"),
  GLOBAL_PARAM(deny_from, "s"),
  GLOBAL_PARAM(status_file, "s"),
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
  { "global" ,sizeof(struct section_global_data), section_global_params,
    0, global_init_func },
  { NULL, 0, NULL }
};

static void
global_init_func(struct generic_section_config *gp)
{
  struct section_global_data *p = (struct section_global_data *) gp;

  p->enable_l10n = -1;
  p->allow_deny = -1;
}

static void print_refresh_button(unsigned char const *);
static void print_logout_button(unsigned char const *);
static void print_nav_buttons(unsigned char const *,
                              unsigned char const *,
                              unsigned char const *);
static void
error(char const *format, ...)
{
  va_list args;
  unsigned char buf[1024];
  int len;

  va_start(args, format);
  len = vsnprintf(buf, 1000, format, args);
  va_end(args);
  strcpy(buf + len, "\n");
  error_log = xstrmerge1(error_log, buf);
}


static int
fix_string(unsigned char *buf, unsigned char const *accept_str, int c)
{
  unsigned char *s;
  unsigned char const *q;
  unsigned char flags[256];
  int cnt = 0;

  memset(flags, 0, sizeof(flags));
  for (q = accept_str; *q; q++)
    flags[*q] = 1;

  for (s = buf; *s; s++)
    if (!flags[*s]) {
      cnt++;
      *s = c;
    }
  return cnt;
}

static void
make_self_url(void)
{
  unsigned char *http_host = getenv("HTTP_HOST");
  unsigned char *script_name = getenv("REDIRECT_URL");
  unsigned char fullname[1024];
  unsigned char *protocol = "http";

  if (getenv("SSL_PROTOCOL") || getenv("HTTPS")) {
    ssl_flag = 1;
    protocol = "https";
  }
  if (!script_name) script_name = getenv("SCRIPT_NAME");
  if (!http_host) http_host = "localhost";
  if (!script_name) script_name = "/cgi-bin/team";
  snprintf(fullname, sizeof(fullname), "%s://%s%s", protocol, http_host, script_name);
  self_url = xstrdup(fullname);
}

static unsigned char *
hyperref(unsigned char *buf, int size,
         ej_cookie_t sid,
         unsigned char const *self_url,
         unsigned char const *extra_args,
         unsigned char const *format, ...)
{
  va_list args;
  unsigned char *out = buf;
  int left = size, n;

  n = snprintf(out, left, "%s?SID=%016llx%s", self_url, sid, extra_args);
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
open_serve(void)
{
  if (serve_socket_fd >= 0) return;
  serve_socket_fd = serve_clnt_open(global->serve_socket);
  if (serve_socket_fd < 0) {
    printf("<%s><font color=\"red\">%s</font></%s>\n",
           head_style, "Cannot connect to the contest server", head_style);
    printf("<p%s>Error: %s</p>\n",
           par_style, protocol_strerror(-serve_socket_fd));
    client_put_footer(stdout, footer_txt);
    exit(0);
  }
}

static int
set_defaults(void)
{
  if (!global->root_dir[0]) {
    err("root_dir must be set");
    return -1;
  }
  path_init(global->var_dir, global->root_dir, DEFAULT_VAR_DIR);
  if (global->contest_id <= 0) {
    err("contest_id must be set");
    return -1;
  }
  path_init(global->status_file, global->var_dir, DEFAULT_STATUS_FILE);
  path_init(global->serve_socket, global->var_dir, DEFAULT_SERVE_SOCKET);
  if (!global->charset[0]) {
    pathcpy(global->charset, DEFAULT_CHARSET);
  }

#if CONF_HAS_LIBINTL - 0 == 1
  if (global->enable_l10n < 0) global->enable_l10n = 1;
  if (global->enable_l10n && !global->l10n_dir[0]) {
    strcpy(global->l10n_dir, EJUDGE_LOCALE_DIR);
  }
  if (global->enable_l10n && !global->l10n_dir[0]) global->enable_l10n = 0;
#else
  global->enable_l10n = 0;
#endif /* CONF_HAS_LIBINTL */
  return 0;
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
client_put_refresh_header(unsigned char const *coding,
                          unsigned char const *url,
                          int interval,
                          unsigned char const *format, ...);

static void
redirect_to_new_client(void)
{
  const unsigned char *s;
  unsigned char url_buf[1024];
  unsigned char lbuf[1024] = { 0 };
  int x, n;

  client_locale_id = 0;
  if ((s = cgi_param("locale_id")) && sscanf(s, "%d%n", &x, &n) == 1
      && !s[n] && x >= 0 && x < 100000)
    client_locale_id = x;
  if (client_locale_id > 0) {
    snprintf(lbuf, sizeof(lbuf), "&locale_id=%d", client_locale_id);
  }

  // just replace `team' with `new-client' in self_url
  if (!(s = strstr(self_url, "team"))) return;
  snprintf(url_buf, sizeof(url_buf), "%.*snew-client%s?contest_id=%d%s",
           (int) (s - self_url), self_url, s + 4, global->contest_id, lbuf);
  client_put_refresh_header(global->charset, url_buf, 0,
                            "redirecting to the new-client...");
  exit(0);
}

static void
initialize(int argc, char *argv[])
{
  path_t  fullname;
  path_t  dirname;
  path_t  basename;
  path_t  cfgname;
  path_t  progname;
  path_t  cfgdir;
  path_t  cfgname2;
  char   *s = getenv("SCRIPT_FILENAME");
  int namelen;
  int name_contest_id;
  int name_ok = 0, errcode;
  
  struct generic_section_config *p;

  pathcpy(fullname, argv[0]);
  if (s) pathcpy(fullname, s);
  os_rDirName(fullname, dirname, PATH_MAX);
  os_rGetBasename(fullname, basename, PATH_MAX);
#if defined CGI_PROG_SUFFIX
 {
   size_t baselen = strlen(basename);
   size_t sufflen = strlen(CGI_PROG_SUFFIX);
   if (baselen>sufflen && !strcmp(basename+baselen-sufflen,CGI_PROG_SUFFIX)) {
     basename[baselen - sufflen] = 0;
   }
 }
#endif /* CGI_PROG_SUFFIX */
  if (strncmp(basename, "team", 4))
    client_not_configured(0, "bad program name", 0);
  memset(progname, 0, sizeof(progname));
  strncpy(progname, basename, 4);
  namelen = 4;

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

  if (!check_config_exist(cfgname)) {
    config = param_make_global_section(params);
  } else {
    config = parse_param(cfgname, 0, params, 1, 0, 0, 0);
  }
  if (!config)
    client_not_configured(0, "config file not parsed", 0);

  /* find global section */
  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  }
  if (!p) client_not_configured(0, "no global section", 0);
  global = (struct section_global_data *) p;

#if defined EJUDGE_SOCKET_PATH
  if (!global->socket_path[0]) {
    snprintf(global->socket_path, sizeof(global->socket_path),
             "%s", EJUDGE_SOCKET_PATH);
  }
#endif /* EJUDGE_SOCKET_PATH */
#if defined EJUDGE_CONTESTS_DIR
  if (!global->contests_dir[0]) {
    snprintf(global->contests_dir, sizeof(global->contests_dir),
             "%s", EJUDGE_CONTESTS_DIR);
  }
#endif /* EJUDGE_CONTESTS_DIR */

  if (!global->contests_dir[0]) {
    client_not_configured(0, "contests are not defined", 0);
    /* never get here */
  }
  contests_set_directory(global->contests_dir);

  if (global->allow_deny < 0) global->allow_deny = 1;

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

  if (cur_contest->root_dir) {
    pathcpy(global->root_dir, cur_contest->root_dir);
  }

  logger_set_level(-1, LOG_WARNING);
  if (cur_contest->team_header_file) {
    generic_read_file(&header_txt, 0, &header_len, 0,
                      0, cur_contest->team_header_file, "");
  }
  if (cur_contest->team_footer_file) {
    generic_read_file(&footer_txt, 0, &footer_len, 0,
                      0, cur_contest->team_footer_file, "");
  }

  if (!(head_style = cur_contest->team_head_style))
    head_style = "h2";
  if (!(par_style = cur_contest->team_par_style))
    par_style = "";

  if (set_defaults() < 0)
    client_not_configured(global->charset, "bad defaults", 0);

  client_ip = parse_client_ip();

  make_self_url();
  client_make_form_headers(self_url);

  if (cur_contest->new_managed) redirect_to_new_client();
}

static void
read_state_params(void)
{
  int x, n;
  unsigned char *s;
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

  form_contest_id[0] = 0;
  if (cgi_contest_id > 0) {
    snprintf(form_contest_id, sizeof(form_contest_id),
             "<input type=\"hidden\" name=\"contest_id\" value=\"%d\">",
             global->contest_id);
  }

  snprintf(form_start_simple, sizeof(form_start_simple),
           "%s"
           "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">%s",
           form_header_simple, client_sid, form_contest_id);
  snprintf(form_start_multipart, sizeof(form_start_multipart),
           "%s"
           "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">%s",
           form_header_multipart, client_sid, form_contest_id);
  snprintf(hidden_vars, sizeof(hidden_vars),
           "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">%s",
           client_sid, form_contest_id);

  client_view_all_runs = 0;
  client_view_all_clars = 0;
  if (cgi_param("all_runs"))  client_view_all_runs = 1;
  if (cgi_param("all_clars")) client_view_all_clars = 1;
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
  if (a_name) {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id,
                      "%s - &quot;%s&quot;", _("Enter password"), a_name);
  } else {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id,
                      "%s", _("Enter password"));
  }

  puts(form_header_simple);
  if (cgi_contest_id > 0) {
    printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">\n", 
           cgi_contest_id);
  }
  printf("<table>"
         "<tr>"
         "<td>%s:</td>"
         "<td><input type=\"text\" size=16 name=\"login\"></td>"
         "</tr>"
         "<tr>"
         "<td>%s:</td>"
         "<td><input type=\"password\" size=16 name=\"password\"></td>"
         "</tr>",
         _("Login"), _("Password"));

  if (global->enable_l10n) {
    printf("<tr valign=\"top\">"
           "<td>%s:</td>"
           "<td>"
           "<select name=\"locale_id\">"
           "<option value=\"0\"%s>%s</option>"
           "<option value=\"1\"%s>%s</option>"
           "</select>"
           "</td>",
           _("Choose language"),
           client_locale_id==0?" selected=\"1\"":"", _("English"),
           client_locale_id==1?" selected=\"1\"":"", _("Russian"));
  }

  printf("<tr>"
         "<td>&nbsp;</td>"
         "<td><input type=\"submit\" value=\"%s\"></td>"
         "</tr>"
         "</table></form>",
         _("Submit"));

  client_put_footer(stdout, footer_txt);
  return 0;
}

static void
open_userlist_server(void)
{
  if (!server_conn) {
    if (!(server_conn = userlist_clnt_open(global->socket_path))) {
      client_put_header(stdout, header_txt, 0, global->charset, 1,
                        client_locale_id, _("Server is down"));
      printf("<p%s>%s</p>",
             par_style, _("The server is down. Try again later."));
      client_put_footer(stdout, footer_txt);
      exit(0);
    }
  }
}

static void
permission_denied(void)
{
  client_put_header(stdout, header_txt, 0, global->charset, 1,
                    client_locale_id, _("Permission denied"));
  printf("<p%s>%s</p>",
         par_style,
         _("Permission denied. You have typed invalid login, invalid password,"
           " invalid contest, or your host is banned."));
  client_put_footer(stdout, footer_txt);
  exit(0);
}

static void
error_not_registered(void)
{
  client_put_header(stdout, header_txt, 0, global->charset, 1,
                    client_locale_id, _("Not registered"));
  printf("<p%s>%s</p>", par_style,
         _("You are not registered for this contest."));
  client_put_footer(stdout, footer_txt);
  exit(0);
}

static void
error_cannot_participate(void)
{
  client_put_header(stdout, header_txt, 0, global->charset, 1,
                    client_locale_id, _("Cannot participate"));
  printf("<p%s>%s</p>", par_style,
         _("You cannot participate in this contest. Your registration is not confirmed, or you have been banned."));
  client_put_footer(stdout, footer_txt);
  exit(0);
}

static void
fatal_server_error(int r)
{
  client_put_header(stdout, header_txt, 0, global->charset, 1,
                    client_locale_id, _("Server error"));
  printf("<p%s>%s: %s</p>", par_style, _("Server error"),
         gettext(userlist_strerror(-r)));
  client_put_footer(stdout, footer_txt);
  exit(0);
}

static int
get_session_id(unsigned char const *var, ej_cookie_t *p_val)
{
  unsigned char const *str;
  ej_cookie_t val;
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

  if (!coding) coding = DEFAULT_CHARSET;

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
  ej_cookie_t session_id;
  int new_locale_id = client_locale_id;
  int r;
  unsigned char hbuf[128];

  /* read and parse session mode */
  if (get_session_id("SID", &session_id)) {
    open_userlist_server();
    r = userlist_clnt_team_cookie(server_conn, client_ip, ssl_flag, global->contest_id,
                                  session_id,
                                  client_locale_id,
                                  &client_team_id,
                                  0 /* p_contest_id */,
                                  &new_locale_id,
                                  &client_login, &client_team_name);
    if (r >= 0) {
      client_sid = session_id;
      client_password = "";
      if (new_locale_id != client_locale_id) {
        l10n_setlocale(new_locale_id);
        client_locale_id = new_locale_id;
      }
      return 1;
    }
    if (r != -ULS_ERR_NO_COOKIE) {
      switch (-r) {
      case ULS_ERR_NOT_REGISTERED:
        error_cannot_participate();
      case ULS_ERR_CANNOT_PARTICIPATE:
        error_not_registered();
      default:
        fatal_server_error(r);
      }
    }
  }

  client_login = cgi_param("login");
  client_password = cgi_param("password");
  if (!client_login || !client_password) {
    display_enter_password();
    exit(0);
  }

  open_userlist_server();
  r = userlist_clnt_team_login(server_conn, ULS_TEAM_LOGIN,
                               client_ip, ssl_flag, global->contest_id,
                               client_locale_id,
                               client_login, client_password,
                               &client_team_id,
                               &client_sid,
                               &new_locale_id,
                               &client_team_name);
  if (r < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_BAD_CONTEST_ID:
    case ULS_ERR_IP_NOT_ALLOWED:
    case ULS_ERR_NO_PERMS:
      permission_denied();
    case ULS_ERR_NOT_REGISTERED:
      error_not_registered();
    case ULS_ERR_CANNOT_PARTICIPATE:
      error_cannot_participate();
    default:
      fatal_server_error(r);
    }
  }
  if (new_locale_id != client_locale_id) {
    l10n_setlocale(new_locale_id);
    client_locale_id = new_locale_id;
  }

  hyperref(hbuf, sizeof(hbuf), client_sid, self_url, contest_id_str, 0);
  client_put_refresh_header(global->charset, hbuf, 0, _("Login successful"));
  printf("<p%s>%s</p>", par_style,
         _("Login successfull. Now entering the main page."));
  printf(_("<p%s>If automatic updating does not work, click on <a href=\"%s\">this</a> link.</p>"), par_style, hbuf);
  exit(0);
}

static void
operation_status_page(int code, unsigned char const *msg)
{
  unsigned char href[128];

  if (code < 0) {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id, _("Operation failed"));
    if (code != -1 || !msg) msg = protocol_strerror(-code);
    printf("<%s><font color=\"red\">%s</font></%s>\n", head_style, 
           msg, head_style);
    print_refresh_button(_("Back"));
    client_put_footer(stdout, footer_txt);
  } else {
    hyperref(href, sizeof(href), client_sid, self_url, contest_id_str, 0);
    client_put_refresh_header(global->charset, href, 0,
                              _("Operation successfull"));
    printf("<%s>%s</%s>", head_style,
           _("Operation completed successfully"), head_style);
    print_refresh_button(_("Back"));
  }
  exit(0);
}

static void
print_refresh_button(unsigned char const *str)
{
  if (!str) str = _("Refresh");

  printf("<a href=\"%s?SID=%016llx%s\">%s</a>",
         self_url, client_sid, contest_id_str, str);
}

static void
print_standings_button(unsigned char const *str)
{
  if (!str) str = _("Virtual standings");

  printf("<a href=\"%s?SID=%016llx&action=%d%s\">%s</a>",
         self_url, client_sid, ACTION_STANDINGS, contest_id_str, str);
}

static void
print_logout_button(unsigned char const *str)
{
  if (!str) str = _("Log out");

  printf("<a href=\"%s?SID=%016llx&action=%d%s\">%s</a>",
         self_url, client_sid, ACTION_LOGOUT, contest_id_str, str);
}

static void
send_clar_if_asked(void)
{
  char *s, *p, *t, *full_subj;
  int   n;

  if (!server_is_virtual) {
    if (!server_start_time) {
      operation_status_page(-1, _("The message cannot be sent. The contest is not started."));
      return;
    }
    if (server_stop_time) {
      operation_status_page(-1, _("The message cannot be sent. The contest is over."));
      return;
    }
  }
  if (server_team_clars_disabled) {
    operation_status_page(-1, _("The message cannot be sent. Messages are disabled."));
    return;
  }

  p = cgi_param("problem");  if (!p) p = "";
  s = cgi_param("subject");  if (!s) s = "";
  t = cgi_param("text");     if (!t) t = "";

  /* process subject */
  full_subj = alloca(strlen(p) + strlen(s) + 16);
  full_subj[0] = 0;
  if (p[0]) {
    strcat(full_subj, p);
    strcat(full_subj, ": ");
  }
  if (s[0]) strcat(full_subj, s);
  if (!full_subj[0]) strcpy(full_subj, _("(no subject)"));

  open_serve();
  n = serve_clnt_submit_clar(serve_socket_fd, client_team_id,
                             global->contest_id, client_locale_id,
                             client_ip, ssl_flag, full_subj, t);
  operation_status_page(n, 0);
  force_recheck_status = 1;
}

static void
submit_if_asked(void)
{
  char *p, *l;
  int prob, lang, n;
  const unsigned char *prog_data = 0;
  size_t prog_size = 0;

  if (!server_is_virtual) {
    if (!server_start_time) {
      operation_status_page(-1, _("The submission cannot be sent. The contest is not started."));
      return;
    }
    if (server_stop_time) {
      operation_status_page(-1, _("The submission cannot be sent. The contest is over."));
      return;
    }
  }

  p = cgi_param("problem");  if (!p) p = "";
  l = cgi_param("language"); if (!l) l = "";
  if (cgi_param_bin("file", &prog_size, &prog_data) < 0) {
    operation_status_page(-1, _("Submission data is empty"));
    return;
  }

  if (sscanf(p, "%d%n", &prob, &n) != 1
      || p[n]
      || sscanf(l, "%d%n", &lang, &n) != 1
      || l[n]) {
    operation_status_page(-1, _("Invalid parameters"));
    return;
  }

  open_serve();
  n = serve_clnt_submit_run(serve_socket_fd, SRV_CMD_SUBMIT_RUN,
                            client_team_id,
                            global->contest_id, client_locale_id,
                            client_ip, ssl_flag, prob, lang, 0,
                            prog_size, prog_data);
  if (n == -SRV_ERR_DATA_FORMAT)
    operation_status_page(-1, _("File sending error. Maybe the file you've sent is not a text file (or is not saved as a text file)."));
  else
    operation_status_page(n, 0);
  force_recheck_status = 1;
}

static void
action_change_password(void)
{
  char *p0, *p1, *p2;
  int r;

  p0 = cgi_param("oldpasswd");
  p1 = cgi_param("newpasswd1");
  p2 = cgi_param("newpasswd2");
  if (!p0 || !p1 || !p2 || !*p0 || !*p1 || !*p2) {
    operation_status_page(-1, _("Invalid parameters"));
    return;
  }

  if (strlen(p0) > 16) {
    operation_status_page(-1, _("Old password is too long"));
    return;
  }
  if (fix_string(p0, password_accept_chars, '?') > 0) {
    operation_status_page(-1, _("Old password contain invalid characters"));
    return;
  }
  if (strcmp(p1, p2)) {
    operation_status_page(-1, _("New passwords do not match"));
    return;
  }
  if (strlen(p1) > 16) {
    operation_status_page(-1, _("New password is too long"));
    return;
  }
  if (fix_string(p1, password_accept_chars, '?') > 0) {
    operation_status_page(-1, _("New password contain invalid characters."));
    return;
  }

  open_userlist_server();
  if (cur_contest && cur_contest->disable_team_password) {
    r = userlist_clnt_set_passwd(server_conn, ULS_SET_PASSWD,
                                 client_team_id, 0, p0, p1);
  } else {
    r = userlist_clnt_set_passwd(server_conn, ULS_TEAM_SET_PASSWD,
                                 client_team_id, global->contest_id, p0, p1);
  }
  if (r < 0) {
    operation_status_page(-1, gettext(userlist_strerror(-r)));
    return;
  }

  operation_status_page(0, 0);

  client_password = p1;
  read_state_params();
  force_recheck_status = 1;
}

static void
show_clar_if_asked(void)
{
  char *s;
  int   n, clar_id, r;

  if (server_clars_disabled) {
    error("%s", _("Messages are disabled."));
    return;
  }

  if (!(s = cgi_nname("clar_", 5))) return;
  if (sscanf(s, "clar_%d%n", &clar_id, &n) != 1
      || (s[n] && s[n] != '.'))
    return;
  if (clar_id < 0 || clar_id >= server_total_clars) return;

  client_put_header(stdout, header_txt, 0, global->charset, 1,
                    client_locale_id, _("Message view"));
  print_nav_buttons(_("Main page"), 0, 0);
  printf("<hr>\n");
  fflush(stdout);
  open_serve();
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_SHOW_CLAR,
                           client_team_id, global->contest_id,
                           client_locale_id, clar_id);
  if (r < 0) {
    printf("<p%s><pre><font color=\"red\">%s</font></pre></p>\n",
           par_style, gettext(protocol_strerror(-r)));
  }
  printf("<hr>\n");
  print_nav_buttons(_("Main page"), 0, 0);
  client_put_footer(stdout, footer_txt);
  exit(0);
}

static void
request_source_if_asked(void)
{
  char *s;
  int   n, run_id, r;
  int   is_binary = 0;
  int   cmd = SRV_CMD_SHOW_SOURCE;

  if (!(s = cgi_nname("source_", 7))) return;
  if (sscanf(s, "source_%d%n", &run_id, &n) != 1
      || (s[n] && s[n] != '.'))
    return;
  if (run_id < 0 || run_id >= server_total_runs) return;
  if (cgi_param("binary")) is_binary = 1;

  if (is_binary) cmd = SRV_CMD_DUMP_SOURCE_2;
  if (!is_binary) {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id, _("Source view"));
    print_nav_buttons(_("Main page"), 0, 0);
    printf("<hr>");
    fflush(stdout);
  }
  open_serve();
  r = serve_clnt_show_item(serve_socket_fd, 1, cmd,
                           client_team_id, global->contest_id,
                           client_locale_id, run_id);
  if (r < 0) {
    if (is_binary) {
      client_put_header(stdout, header_txt, 0, global->charset, 1,
                        client_locale_id, _("Source view"));
      print_nav_buttons(_("Main page"), 0, 0);
      printf("<hr>");
    }
    printf("<p%s><pre><font color=\"red\">%s</font></pre></p>\n",
           par_style, gettext(protocol_strerror(-r)));
    if (is_binary) {
      printf("<hr>");
      print_nav_buttons(_("Main page"), 0, 0);
      client_put_footer(stdout, footer_txt);
    }
  }
  if (!is_binary) {
    printf("<hr>");
    print_nav_buttons(_("Main page"), 0, 0);
    client_put_footer(stdout, footer_txt);
  }
  exit(0);
}

static void
action_standings(void)
{
  int r;

  client_put_header(stdout, header_txt, 0, global->charset, 1,
                    client_locale_id, _("Current virtual standings"));
  print_nav_buttons(_("Main page"), 0, 0);
  printf("<hr>");
  fflush(stdout);
  open_serve();
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_VIRTUAL_STANDINGS,
                           client_team_id, global->contest_id,
                           client_locale_id, 0);
  r = 0;
  if (r < 0) {
    printf("<p%s><pre><font color=\"red\">%s</font></pre></p>\n",
           par_style, gettext(protocol_strerror(-r)));
  }
  printf("<hr>");
  print_nav_buttons(_("Main page"), 0, 0);
  client_put_footer(stdout, footer_txt);
  exit(0);
}

static void
request_report_if_asked(void)
{
  char *s;
  int   n, run_id, r;

  if (!(s = cgi_nname("report_", 7))) return;
  if (sscanf(s, "report_%d%n", &run_id, &n) != 1
      || (s[n] && s[n] != '.'))
    return;
  if (run_id < 0 || run_id >= server_total_runs) return;

  client_put_header(stdout, header_txt, 0, global->charset, 1,
                    client_locale_id, _("Report view"));
  print_nav_buttons(_("Main page"), 0, 0);
  printf("<hr>");
  fflush(stdout);
  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, SRV_CMD_SHOW_REPORT, run_id, 
                      client_locale_id, 0, self_url, hidden_vars, contest_id_str);
  /*
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_SHOW_REPORT,
                           client_team_id, global->contest_id,
                           client_locale_id, run_id);
  */
  if (r < 0) {
    printf("<p%s><pre><font color=\"red\">%s</font></pre></p>\n",
           par_style, gettext(protocol_strerror(-r)));
  }
  printf("<hr>");
  print_nav_buttons(_("Main page"), 0, 0);
  client_put_footer(stdout, footer_txt);
  exit(0);
}

static void
request_printing_if_asked(void)
{
  char *s;
  int   n, run_id;

  if (!(s = cgi_nname("print_", 6))) return;
  if (sscanf(s, "print_%d%n", &run_id, &n) != 1 || (s[n] && s[n] != '.'))
    return;
  if (run_id < 0 || run_id >= server_total_runs) return;

  client_put_header(stdout, header_txt, 0, global->charset, 1,
                    client_locale_id, "%s %d", _("Confirm printing run"), run_id);

  printf("<p>");
  print_refresh_button(_("No"));
  printf("<p>%s"
         "<input type=\"hidden\" name=\"run_id\" value=\"%d\">"
         "<input type=\"submit\" name=\"action_%d\" value=\"%s\">"
         "</form></p>", form_start_simple, run_id, ACTION_PRINT_RUN,
         _("Yes, print!"));
  client_put_footer(stdout, 0);
  exit(0);  
}

static void
request_archive_if_asked(void)
{
  char *s;
  unsigned char *dirpath = 0, *basename, *lastdir;
  char *args[10];
  int r, token;

  if (!(s = cgi_param("archive"))) return;

  open_serve();
  if ((r = serve_clnt_get_archive(serve_socket_fd, client_team_id,
                                  global->contest_id, client_locale_id,
                                  &token, &dirpath)) < 0) {
    operation_status_page(r, 0);
    return;
  }
  basename = os_GetBasename(dirpath);
  lastdir = os_DirName(dirpath);
  printf("Content-type: application/octet-stream; name=\"%s.tgz\"\n\n", basename);
  fprintf(stderr, "Content-type: application/octet-stream; name=\"%s.tgz\"\n", basename);
  //printf("Content-location: %s.tar.gz\n\n", basename);
  fflush(0);
  args[0] = "/bin/tar";         /* FIXME! */
  args[1] = "cfz";
  args[2] = "-";
  args[3] = "-C";
  args[4] = lastdir;
  args[5] = basename;
  args[6] = 0;
  execv("/bin/tar", args);
  fprintf(stderr, "execv failed: %s\n", os_ErrorMsg());
  exit(1);
}

static void
action_virtual_start(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_VIRTUAL_START, 0, 0);
  operation_status_page(r, 0);
}

static void
action_virtual_stop(void)
{
  int r;

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_VIRTUAL_STOP, 0, 0);
  operation_status_page(r, 0);
}

static void
action_print_run(void)
{
  int r;
  int run_id, n;
  unsigned char *s;

  if (!(s = cgi_param("run_id"))
      || sscanf(s, "%d%n", &run_id, &n) != 1
      || s[n]
      || run_id < 0
      || run_id >= server_total_runs) {
    operation_status_page(-SRV_ERR_PROTOCOL, 0);
    return;
  }

  open_serve();
  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_PRINT_RUN,
                            &run_id, sizeof(run_id));
  operation_status_page(r, 0);
}

static void
action_view_test(int cmd)
{
  unsigned char *s;
  int run_id, test_num, n, r;

  if (!(s = cgi_param("run_id"))) goto invalid_operation;
  if (sscanf(s, "%d%n", &run_id, &n) != 1 || s[n]) goto invalid_operation;
  if (run_id < 0 || run_id > 999999) goto invalid_operation;

  if (!(s = cgi_param("test_num"))) goto invalid_operation;
  if (sscanf(s, "%d%n", &test_num, &n) != 1 || s[n]) goto invalid_operation;
  if (test_num < 1 || test_num > 255) goto invalid_operation;

  open_serve();
  r = serve_clnt_view(serve_socket_fd, 1, cmd, run_id, test_num, 0,
                      self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    client_put_header(stdout, 0, 0, global->charset, 1, 0,
                      _("Details about run %d, test %d"), run_id, test_num);
    printf("<h2><font color=\"red\">%s</font></h2>\n", protocol_strerror(-r));
    client_put_footer(stdout, 0);
  }
  exit(0);

 invalid_operation:
  operation_status_page(-1, "Invalid operation");
}

static void
action_change_language(void)
{
  // if we are here, no further operations are required
  operation_status_page(0, 0);
}

static void
action_logout(void)
{
  unsigned char s1[32];

  if (client_sid) {
    open_userlist_server();
    userlist_clnt_logout(server_conn, ULS_DO_LOGOUT,
                         client_ip, ssl_flag, client_sid);
  }
  client_put_header(stdout, header_txt, 0, global->charset, 1,
                    client_locale_id, "%s", _("Good-bye"));

  s1[0] = 0;
  if (client_locale_id >= 0) {
    snprintf(s1, sizeof(s1), "&locale_id=%d", client_locale_id);
  }

  printf("<p%s>%s</p>\n", par_style,
         _("Good-bye!"));
  printf(_("<p%s>Follow this <a href=\"%s?contest_id=%d%s\">link</a> to login again.</p>"),
         par_style, self_url, global->contest_id, s1);
  client_put_footer(stdout, footer_txt);
  exit(0);
}

static void
display_team_page(void)
{
  int r;

  fflush(stdout);
  open_serve();
  r = serve_clnt_team_page(serve_socket_fd, 1, client_locale_id,
                           ((client_view_all_clars?1:0)<<1)|(client_view_all_runs?1:0),
                           self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    printf("<p%s>%s: %s\n", par_style, _("Server error"),
           gettext(protocol_strerror(-r)));
  }
}

static void
print_nav_buttons(unsigned char const *p1, unsigned char const *p2,
                  unsigned char const *p3)
{
  printf("<table><tr><td>");
  print_refresh_button(p1);
  if (server_is_virtual) {
    printf("</td><td>");
    print_standings_button(p3);
  }
  printf("</td><td>");
  print_logout_button(p3);
  printf("</td></tr></table>\n");
}

static void
read_locale_id(void)
{
  unsigned char *e;
  int x = 0, n = 0;

  if (!(e = cgi_param("locale_id"))) return;
  if (sscanf(e, "%d%n", &x, &n) == 1 && !e[n] && x >= 0 && x <= 1) {
    client_locale_id = x;
  }
}

static void
client_contest_closed(void)
{
  unsigned char *a_name = 0;
  int a_len;

  if (cur_contest->name) {
    a_len = html_armored_strlen(cur_contest->name);
    a_name = alloca(a_len + 10);
    html_armor_string(cur_contest->name, a_name);
  }

  if (a_name) {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id,
                      "%s - &quot;%s&quot;", _("Contest is closed"), a_name);
  } else {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id,
                      "%s", _("Contest is closed"));
  }

  printf("<p>%s</p>", _("The contest is closed."));
  client_put_footer(stdout, footer_txt);
  exit(0);
}

static void
client_server_down(void)
{
  unsigned char *a_name = 0;
  int a_len;

  if (cur_contest->name) {
    a_len = html_armored_strlen(cur_contest->name);
    a_name = alloca(a_len + 10);
    html_armor_string(cur_contest->name, a_name);
  }

  if (a_name) {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id,
                      "%s - &quot;%s&quot;", _("Server is down"), a_name);
  } else {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id,
                      "%s", _("Server is down"));
  }

  printf("<p>%s</p>", _("Server is down."));
  client_put_footer(stdout, footer_txt);
  exit(0);
}

int
main(int argc, char *argv[])
{
  int need_show_submit = 0;
  int need_show_clar = 0;
  struct timeval begin_time, end_time;
  int server_lag = DEFAULT_SERVER_LAG;

  gettimeofday(&begin_time, 0);
  initialize(argc, argv);

  if (!client_check_source_ip(global->allow_deny,
                              global->allow_from,
                              global->deny_from))
    client_access_denied(global->charset, 0);

  if (!contests_check_team_ip(global->contest_id, client_ip, ssl_flag)) {
    client_access_denied(global->charset, 0);
  }

  /*
  if (cur_contest) {
    if (!contests_check_ip(cur_contest, client_ip))
      client_access_denied(global->charset);
  }
  */

  read_locale_id();

  l10n_prepare(global->enable_l10n, global->l10n_dir);
  l10n_setlocale(client_locale_id);

  if (cur_contest->closed) {
    client_contest_closed();
  }

  if (authentificate() != 1)
    client_access_denied(global->charset, client_locale_id);

  read_state_params();

  // FIXME: is server_lag necessary?
  if (cur_contest->client_ignore_time_skew) {
    server_lag = 0;
  }
  if (!client_check_server_status(global->charset,
                                  global->status_file, server_lag,
                                  client_locale_id)) {
    return 0;
  }

  if (!server_clients_suspended && serve_socket_fd < 0) {
    serve_socket_fd = serve_clnt_open(global->serve_socket);
    if (serve_socket_fd < 0) client_server_down();
  }

  switch (client_action) {
  case ACTION_LOGOUT:
    action_logout();
    break;
  case ACTION_CHANGE_LANGUAGE:
    action_change_language();
    break;
  case ACTION_CHANGE_PASSWORD:
    action_change_password();
    break;
  }

  if (!server_clients_suspended) {
    switch (client_action) {
    case ACTION_SUBMIT_CLAR:
      send_clar_if_asked();
      break;
    case ACTION_SUBMIT_RUN:
      submit_if_asked();
      break;
    case ACTION_START_VIRTUAL:
      action_virtual_start();
      break;
    case ACTION_STOP_VIRTUAL:
      action_virtual_stop();
      break;
    case ACTION_STANDINGS:
      action_standings();
      break;
    case ACTION_PRINT_RUN:
      action_print_run();
      break;
    case ACTION_VIEW_TEST_INPUT:
      action_view_test(SRV_CMD_VIEW_TEST_INPUT);
      break;
    case ACTION_VIEW_TEST_OUTPUT:
      action_view_test(SRV_CMD_VIEW_TEST_OUTPUT);
      break;
    case ACTION_VIEW_TEST_ANSWER:
      action_view_test(SRV_CMD_VIEW_TEST_ANSWER);
      break;
    case ACTION_VIEW_TEST_ERROR:
      action_view_test(SRV_CMD_VIEW_TEST_ERROR);
      break;
    case ACTION_VIEW_TEST_CHECKER:
      action_view_test(SRV_CMD_VIEW_TEST_CHECKER);
      break;
    case ACTION_VIEW_TEST_INFO:
      action_view_test(SRV_CMD_VIEW_TEST_INFO);
      break;
    default:
      show_clar_if_asked();
      request_source_if_asked();
      request_report_if_asked();
      request_printing_if_asked();
      request_archive_if_asked();
    }
  }

  if (force_recheck_status) {
    client_check_server_status(global->charset,
                               global->status_file, server_lag,
                               client_locale_id);
    force_recheck_status = 0;
  }

  if (cur_contest->name) {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id,
                      "%s: &quot;%s&quot - &quot;%s&quot;",
                      _("Monitor"), client_team_name, cur_contest->name);
  } else {
    client_put_header(stdout, header_txt, 0, global->charset, 1,
                      client_locale_id,
                      "%s: &quot;%s&quot", _("Monitor"), client_team_name);
  }

  need_show_submit = server_start_time && !server_stop_time && !server_clients_suspended;
  need_show_clar = server_start_time && !server_stop_time && !server_team_clars_disabled && !server_clars_disabled && !server_clients_suspended;

  /* print quick navigation */
  puts("<ul>");
  printf("<li><a href=\"#status\">%s</a></li>\n", _("Contest status"));
  if (error_log)
    printf("<li><a href=\"#lastcmd\">%s</a>\n",
           _("The last command completion status"));
  if (server_start_time && !server_clients_suspended)
    printf("<li><a href=\"#probstat\">%s</a>\n", _("Problem status summary"));
  if (need_show_submit)
    printf("<li><a href=\"#submit\">%s</a>\n", _("Send a submission"));
  if (server_start_time && !server_clients_suspended)
    printf("<li><a href=\"#runstat\">%s</a>\n", _("Submission log"));
  if (need_show_clar)
    printf("<li><a href=\"#clar\">%s</a>\n", _("Send a message to judges"));
  if (!server_clars_disabled && !server_clients_suspended)
    printf("<li><a href=\"#clarstat\">%s</a>\n", _("Messages from judges"));
  if (!server_clients_suspended /*&& !cur_contest->disable_team_password*/) {
    printf("<li><a href=\"#chgpasswd\">%s</a>\n", _("Change password"));
  }
#if CONF_HAS_LIBINTL - 0 == 1
  if (global->enable_l10n) {
    printf("<li><a href=\"#chglanguage\">%s</a>\n", _("Change language"));
  }
#endif /* CONF_HAS_LIBINTL */
  if (cur_contest->standings_url && server_start_time) {
    printf("<li><a href=\"%s\" target=_blank>%s</a>\n",
           cur_contest->standings_url, _("Team standings"));
  }
  if (server_always_show_problems ||
      (!server_is_virtual && cur_contest->problems_url && server_start_time)) {
    printf("<li><a href=\"%s\" target=_blank>%s</a>\n",
           cur_contest->problems_url, _("Problems"));
  }
  puts("</ul>");
  print_nav_buttons(0, 0, 0);

  if (error_log) {
    printf("<hr><a name=\"lastcmd\"></a><%s>%s</%s>\n",
           head_style, _("The last command completion status"), head_style);
    printf("<pre><font color=\"red\">%s</font></pre>\n", error_log);
    print_nav_buttons(0, 0, 0);
  }

  client_print_server_status(0, "", "status");
  if (!server_is_virtual || server_clients_suspended) {
    print_nav_buttons(0, 0, 0);
  }

  if (!server_clients_suspended) {
    display_team_page();
  }

  if (!server_clients_suspended /*&& !cur_contest->disable_team_password*/) {
    printf("<hr><a name=\"chgpasswd\"></a><%s>%s</%s>\n"
           "%s<table>\n"
           "<tr><td>%s:</td><td><input type=\"password\" name=\"oldpasswd\" size=\"16\"></td></tr>\n"
           "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd1\" size=\"16\"></td></tr>\n"
           "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd2\" size=\"16\"></td></tr>\n"
           "<tr><td colspan=\"2\"><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr>\n"
           "</table></form>",
           head_style, _("Change password"), head_style, form_start_simple,
           _("Old password"),
           _("New password"), _("Retype new password"),
           ACTION_CHANGE_PASSWORD, _("Change!"));
    print_nav_buttons(0, 0, 0);
  }

#if CONF_HAS_LIBINTL - 0 == 1
  if (global->enable_l10n) {
    printf("<hr><a name=\"chglanguage\"></a><%s>%s</%s>\n",
           head_style, _("Change language"), head_style);
    printf("%s", form_start_simple);
    if (cgi_contest_id > 0) {
      printf("<input type=\"hidden\" name=\"contest_id\" value=\"%d\">",
             global->contest_id);
    }

    printf("%s: <select name=\"locale_id\">"
           "<option value=\"0\"%s>%s</option>"
           "<option value=\"1\"%s>%s</option>"
           "</select>"
           "<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>\n",
           _("Change language"),
           client_locale_id==0?" selected=\"1\"":"", _("English"),
           client_locale_id==1?" selected=\"1\"":"", _("Russian"),
           ACTION_CHANGE_LANGUAGE, _("Change!"));
    print_nav_buttons(0, 0, 0);
  }
#endif /* CONF_HAS_LIBINTL */

  if (global->show_generation_time) {
    gettimeofday(&end_time, 0);
    end_time.tv_sec -= begin_time.tv_sec;
    if ((end_time.tv_usec -= begin_time.tv_usec) < 0) {
      end_time.tv_usec += 1000000;
      end_time.tv_sec--;
    }
    printf("<hr><p%s>%s: %ld %s\n", par_style,
           _("Page generation time"),
           end_time.tv_usec / 1000 + end_time.tv_sec * 1000,
           _("msec"));
  }

#if 0
  {
    int i;

    puts("<hr><pre>");
    puts("");
    for (i = 0; i < argc; i++) {
      printf("argv[%d] = '%s'\n", i, argv[i]);
    }
    puts("");
    cgi_print_param();
    fflush(0);
    system("printenv");
  }
#endif

  client_put_footer(stdout, footer_txt);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
