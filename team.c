/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2000-2003 Alexander Chernov <cher@ispras.ru> */

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

#include "cgi.h"
#include "parsecfg.h"
#include "pathutl.h"
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
#endif

/*
 * The default path to data directory
 */
#if !defined CGI_DATA_PATH
#define CGI_DATA_PATH "../cgi-data"
#endif

static char const password_accept_chars[] =
" !#$%\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_"
"`abcdefghijklmnopqrstuvwxyz{|}~═║╒ё╓╔╕╖╗╘╙╚╛╜╝╞╟╠╡Ё╢╣╤╥╦╧╨╩╪╫╬©"
"юабцдефгхийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ";

/* configuration defaults */
#define DEFAULT_VAR_DIR              "var"
#define DEFAULT_STATUS_FILE          "status/dir/status"
#define DEFAULT_SERVER_LAG           10
#define DEFAULT_MAX_RUN_SIZE         65536
#define DEFAULT_MAX_CLAR_SIZE        1024
#define DEFAULT_CHARSET              "iso8859-1"
#define DEFAULT_SERVE_SOCKET         "serve"

/* global configuration settings */
struct section_global_data
{
  struct generic_section_config g;

  int    allow_deny;
  int    max_run_size;
  int    max_clar_size;
  int    show_generation_time;
  int    enable_session_mode;
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
static struct contest_desc *cur_contest;
static struct userlist_clnt *server_conn;
static unsigned long client_ip;
static unsigned char *self_url;

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

static int serve_socket_fd = -1;

enum
  {
    SID_DISABLED = 0,
    SID_EMBED,
    SID_URL,
    SID_COOKIE
  };

static int client_sid_mode;
static int need_set_cookie;
static unsigned long long client_sid;
static unsigned long long client_cookie;

static unsigned char form_start_simple[1024];
static unsigned char form_start_multipart[1024];
static unsigned char hidden_vars[1024];

/* description of configuration parameters */
#define GLOBAL_OFFSET(x) XOFFSET(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(allow_deny, "d"),
  GLOBAL_PARAM(max_run_size, "d"),
  GLOBAL_PARAM(max_clar_size, "d"),
  GLOBAL_PARAM(show_generation_time, "d"),
  GLOBAL_PARAM(enable_session_mode, "d"),
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
  { "global" ,sizeof(struct section_global_data), section_global_params },
  { NULL, 0, NULL }
};

static void print_refresh_button(unsigned char const *);
static void print_logout_button(unsigned char const *);
static void print_nav_buttons(unsigned char const *,
                              unsigned char const *,
                              unsigned char const *);

static int
setup_locale(int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  char *e = 0;
  char env_buf[128];

  if (!global->enable_l10n) return 0;

  switch (locale_id) {
  case 1:
    e = "ru_RU.KOI8-R";
    break;
  case 0:
  default:
    locale_id = 0;
    e = "C";
    break;
  }

  sprintf(env_buf, "LC_ALL=%s", e);
  putenv(env_buf);
  setlocale(LC_ALL, "");
  return locale_id;
#else
  return 0;
#endif /* CONF_HAS_LIBINTL */
}

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
  
  if (!script_name) script_name = getenv("SCRIPT_NAME");
  if (!http_host) http_host = "localhost";
  if (!script_name) script_name = "/cgi-bin/team";
  snprintf(fullname, sizeof(fullname), "http://%s%s", http_host, script_name);
  self_url = xstrdup(fullname);
}

static unsigned char *
hyperref(unsigned char *buf, int size,
         int sid_mode, unsigned long long sid,
         unsigned char const *self_url,
         unsigned char const *extra_args,
         unsigned char const *format, ...)
{
  va_list args;
  unsigned char *out = buf;
  int left = size, n;

  ASSERT(sid_mode == SID_URL || sid_mode == SID_COOKIE);
  if (sid_mode == SID_COOKIE) {
    n = snprintf(out, left, "%s?sid_mode=%d%s",
                 self_url, SID_COOKIE, extra_args);
  } else {
    n = snprintf(out, left, "%s?sid_mode=%d&SID=%016llx%s",
                 self_url, SID_URL, sid, extra_args);
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
open_serve(void)
{
  if (serve_socket_fd >= 0) return;
  serve_socket_fd = serve_clnt_open(global->serve_socket);
  if (serve_socket_fd < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           "Cannot connect to the contest server");
    printf("<p>Error: %s</p>\n", protocol_strerror(-serve_socket_fd));
    client_put_footer();
    exit(0);
  }
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
    printf("Set-cookie: UID=0; expires=Thu, 01-Jan-70 00:00:01 GMT\n");
    return;
  }
  t = time(0);
  t += 24 * 60 * 60;
  gmtime_r(&t, &gt);
  strftime(buf, sizeof(buf), "%A, %d-%b-%Y %H:%M:%S GMT", &gt);
  printf("Set-cookie: UID=%llx; expires=%s\n", client_cookie, buf);
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
  if (global->max_run_size < 0 || global->max_run_size > 128 * 1024) {
    err("invalid max_run_size");
    return -1;
  }
  if (!global->max_run_size) global->max_run_size = DEFAULT_MAX_RUN_SIZE;
  if (global->max_clar_size < 0 || global->max_clar_size > 16 * 1024) {
    err("invalid max_clar_size");
    return -1;
  }
  if (!global->max_clar_size) global->max_clar_size = DEFAULT_MAX_CLAR_SIZE;
  if (!global->charset[0]) {
    pathcpy(global->charset, DEFAULT_CHARSET);
  }

  if (!global->l10n_dir[0] || !global->enable_l10n) {
    global->enable_l10n = 0;
    global->l10n_dir[0] = 0;
  }
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
  if (strncmp(basename, "team", 4))
    client_not_configured(0, "bad program name");
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
      client_not_configured(0, "Contest ID is unknown");
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
    client_not_configured(0, "config file not parsed");

  /* find global section */
  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  }
  if (!p) client_not_configured(0, "no global section");
  global = (struct section_global_data *) p;

  if (!global->contests_dir[0]) {
    client_not_configured(0, "contests are not defined");
    /* never get here */
  }
  contests_set_directory(global->contests_dir);

  /* verify contest_id from the configuration file */
  if (name_contest_id > 0) {
    if (global->contest_id > 0 && name_contest_id != global->contest_id) {
      client_not_configured(0, "contest_id's do not match");
      /* never get here */
    }
    global->contest_id = name_contest_id;
  } else if (cgi_contest_id > 0) {
    if (global->contest_id > 0 && cgi_contest_id != global->contest_id) {
      client_not_configured(0, "contest_id's do not match");
      /* never get here */
    }
    global->contest_id = cgi_contest_id;
  } else {
    if (global->contest_id <= 0) {
      client_not_configured(0, "contest_id is not set");
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
    client_not_configured(0, "invalid contest");
    /* never get here */
  }

  if (cur_contest->root_dir) {
    pathcpy(global->root_dir, cur_contest->root_dir);
  }

  if (set_defaults() < 0)
    client_not_configured(global->charset, "bad defaults");
  logger_set_level(-1, LOG_WARNING);

  parse_client_ip();

  make_self_url();
  client_make_form_headers(self_url);
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

  switch (client_sid_mode) {
  case SID_DISABLED:
    snprintf(form_start_simple, sizeof(form_start_simple),
             "%s"
             "<input type=\"hidden\" name=\"sid_mode\" value=\"0\">"
             "<input type=\"hidden\" name=\"login\" value=\"%s\">"
             "<input type=\"hidden\" name=\"password\" value=\"%s\">"
             "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">%s",
             form_header_simple, client_login, client_password,
             client_locale_id, form_contest_id);
    snprintf(form_start_multipart, sizeof(form_start_multipart),
             "%s"
             "<input type=\"hidden\" name=\"sid_mode\" value=\"0\">"
             "<input type=\"hidden\" name=\"login\" value=\"%s\">"
             "<input type=\"hidden\" name=\"password\" value=\"%s\">"
             "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">%s",
             form_header_multipart, client_login, client_password,
             client_locale_id, form_contest_id);
    snprintf(hidden_vars, sizeof(hidden_vars),
             "<input type=\"hidden\" name=\"sid_mode\" value=\"0\">"
             "<input type=\"hidden\" name=\"login\" value=\"%s\">"
             "<input type=\"hidden\" name=\"password\" value=\"%s\">"
             "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">%s",
             client_login, client_password, client_locale_id,
             form_contest_id);
    break;
  case SID_EMBED:
    snprintf(form_start_simple, sizeof(form_start_simple),
             "%s"
             "<input type=\"hidden\" name=\"sid_mode\" value=\"1\">"
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">%s",
             form_header_simple, client_sid, form_contest_id);
    snprintf(form_start_multipart, sizeof(form_start_multipart),
             "%s"
             "<input type=\"hidden\" name=\"sid_mode\" value=\"1\">"
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">%s",
             form_header_multipart, client_sid, form_contest_id);
    snprintf(hidden_vars, sizeof(hidden_vars),
             "<input type=\"hidden\" name=\"sid_mode\" value=\"1\">"
             "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">%s",
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
  set_cookie_if_needed();
  if (a_name) {
    client_put_header(global->charset, "%s - &quot;%s&quot;",
                      _("Enter password"), a_name);
  } else {
    client_put_header(global->charset, "%s", _("Enter password"));
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

  if (global->enable_session_mode) {
    printf("<tr valign=\"top\">"
           "<td>%s:</td>"
           "<td>"
           "<input type=\"radio\" name=\"sid_mode\" value=\"0\">%s<br>"
           "<input type=\"radio\" name=\"sid_mode\" value=\"1\">%s<br>"
           "<input type=\"radio\" name=\"sid_mode\" value=\"2\">%s<br>"
           "<input type=\"radio\" name=\"sid_mode\" value=\"3\" checked=\"yes\">%s"
           "</td>"
           "</tr>",
           _("Session support"), _("No session"),
           _("In forms"), _("In URL"), _("In cookies"));
  } else {
    printf("<input type=\"hidden\" name=\"sid_mode\" value=\"2\">");
  }

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

  client_put_footer();
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
  if (!server_conn) {
    if (!(server_conn = userlist_clnt_open(global->socket_path))) {
      set_cookie_if_needed();
      client_put_header(global->charset, _("Server is down"));
      printf("<p>%s</p>",
             _("The server is down. Try again later."));
      client_put_footer();
      exit(0);
    }
  }
}

static void
permission_denied(void)
{
  set_cookie_if_needed();
  client_put_header(global->charset, _("Permission denied"));
  printf("<p>%s</p>",
         _("Permission denied. You have typed invalid login, invalid password,"
           " or do not have enough privileges."));
  client_put_footer();
  exit(0);
}

static void
fatal_server_error(int r)
{
  set_cookie_if_needed();
  client_put_header(global->charset, _("Server error"));
  printf("<p>%s: %s</p>", _("Server error"),
         gettext(userlist_strerror(-r)));
  client_put_footer();
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
  int new_locale_id = client_locale_id;
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
      && get_cookie("UID", &session_id)) {
    client_cookie = session_id;
    open_userlist_server();
    r = userlist_clnt_team_cookie(server_conn, client_ip, global->contest_id,
                                  session_id,
                                  client_locale_id,
                                  &client_team_id,
                                  0, /* p_contest_id */
                                  &new_locale_id,
                                  &client_login, &client_team_name);
    if (r >= 0) {
      client_sid_mode = SID_COOKIE;
      client_sid = client_cookie;
      client_password = "";
      if (new_locale_id != client_locale_id) {
        setup_locale(new_locale_id);
        client_locale_id = new_locale_id;
      }
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
    r = userlist_clnt_team_cookie(server_conn, client_ip, global->contest_id,
                                  session_id,
                                  client_locale_id,
                                  &client_team_id,
                                  0 /* p_contest_id */,
                                  &new_locale_id,
                                  &client_login, &client_team_name);
    if (r >= 0) {
      if (client_sid_mode == -1) client_sid_mode = SID_URL;
      client_sid = session_id;
      client_password = "";
      if (new_locale_id != client_locale_id) {
        setup_locale(new_locale_id);
        client_locale_id = new_locale_id;
      }
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
  r = userlist_clnt_team_login(server_conn, client_ip, global->contest_id,
                               client_locale_id,
                               client_sid_mode != SID_DISABLED,
                               client_login, client_password,
                               &client_team_id,
                               &client_sid,
                               &new_locale_id,
                               &client_team_name);
  if (r < 0 && is_auth_error(r)) permission_denied();
  if (r < 0) fatal_server_error(r);
  if (client_sid_mode == SID_COOKIE) {
    client_cookie = client_sid;
    need_set_cookie = 1;
  }
  if (new_locale_id != client_locale_id) {
    setup_locale(new_locale_id);
    client_locale_id = new_locale_id;
  }

  if (client_sid_mode == SID_URL || client_sid_mode == SID_COOKIE) {
    unsigned char hbuf[128];

    hyperref(hbuf, sizeof(hbuf), client_sid_mode, client_sid, self_url,
             contest_id_str, 0);
    set_cookie_if_needed();
    client_put_refresh_header(global->charset, hbuf, 0,
                              _("Login successful"));
    printf("<p>%s</p>", _("Login successfull. Now entering the main page."));
    printf(_("<p>If automatic updating does not work, click on <a href=\"%s\">this</a> link.</p>"), hbuf);
           
    //client_put_footer();
    exit(0);
  }

  return 1;
}

static void
operation_status_page(int code, unsigned char const *msg)
{
  unsigned char href[128];

  if (client_sid_mode != SID_URL && client_sid_mode != SID_COOKIE) {
    if (code == -1 && msg) {
      error("%s", msg);
    } else if (code < 0) {
      error("%s", gettext(protocol_strerror(-code)));
    }
    return;
  }
  set_cookie_if_needed();
  if (code < 0) {
    client_put_header(global->charset, _("Operation failed"));
    if (code != -1 || !msg) msg = protocol_strerror(-code);
    printf("<h2><font color=\"red\">%s</font></h2>\n", msg);
  } else {
    hyperref(href, sizeof(href), client_sid_mode, client_sid, self_url,
             contest_id_str, 0);
    client_put_refresh_header(global->charset, href, 0,
                              _("Operation successfull"));
    printf("<h2>%s</h2>", _("Operation completed successfully"));
  }
  print_refresh_button(_("Back"));
  client_put_footer();
  exit(0);
}

static void
print_refresh_button(unsigned char const *str)
{
  if (!str) str = _("Refresh");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx%s\">%s</a>",
           self_url, SID_URL, client_sid, contest_id_str, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d%s\">%s</a>",
           self_url, SID_COOKIE, contest_id_str, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"refresh\" value=\"%s\">", str);
    puts("</form>");
  }
}

static void
print_standings_button(unsigned char const *str)
{
  if (!str) str = _("Virtual standings");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx&action=%d%s\">%s</a>",
           self_url, SID_URL, client_sid, ACTION_STANDINGS,
           contest_id_str, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d&action=%d%s\">%s</a>",
           self_url, SID_COOKIE, ACTION_STANDINGS, contest_id_str, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
           ACTION_STANDINGS, str);
  }
}

static void
print_logout_button(unsigned char const *str)
{
  if (!str) str = _("Log out");

  if (client_sid_mode == SID_URL) {
    printf("<a href=\"%s?sid_mode=%d&SID=%016llx&action=%d%s\">%s</a>",
           self_url, SID_URL, client_sid, ACTION_LOGOUT,
           contest_id_str, str);
  } else if (client_sid_mode == SID_COOKIE) {
    printf("<a href=\"%s?sid_mode=%d&action=%d%s\">%s</a>",
           self_url, SID_COOKIE, ACTION_LOGOUT, contest_id_str, str);
  } else {
    puts(form_start_simple);
    printf("<input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>",
           ACTION_LOGOUT, str);
  }
}

static void
send_clar_if_asked(void)
{
  char *s, *p, *t, *r, *full_subj;
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
  r = getenv("REMOTE_ADDR"); if (!r || !*r) r = "N/A";

  /* process subject */
  full_subj = alloca(strlen(p) + strlen(s) + 16);
  full_subj[0] = 0;
  if (p[0]) {
    strcat(full_subj, p);
    strcat(full_subj, ": ");
  }
  if (s[0]) strcat(full_subj, s);
  if (!full_subj[0]) strcpy(full_subj, _("(no subject)"));

  if (strlen(t) + strlen(full_subj) > global->max_clar_size) {
    operation_status_page(-1, _("The message cannot be sent because its size exceeds maximal allowed."));
    return;
  }

  open_serve();
  n = serve_clnt_submit_clar(serve_socket_fd, client_team_id,
                             global->contest_id, client_locale_id,
                             client_ip, full_subj, t);
  operation_status_page(n, 0);
  force_recheck_status = 1;
}

static void
submit_if_asked(void)
{
  char *p, *l, *t;
  int prob, lang, n;

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
  t = cgi_param("file");     if (!t) t = "";

  if (sscanf(p, "%d%n", &prob, &n) != 1
      || p[n]
      || sscanf(l, "%d%n", &lang, &n) != 1
      || l[n]) {
    operation_status_page(-1, _("Invalid parameters"));
    return;
  }

  if (strlen(t) > global->max_run_size) {
    operation_status_page(-1, _("The submission cannot be sent because its size exceeds maximal allowed."));
    return;
  }

  open_serve();
  n = serve_clnt_submit_run(serve_socket_fd, client_team_id,
                            global->contest_id, client_locale_id,
                            client_ip, prob, lang, t);
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
  r = userlist_clnt_team_set_passwd(server_conn, client_team_id,
                                    global->contest_id,
                                    p0, p1);
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

  set_cookie_if_needed();
  client_put_header(global->charset, _("Message view"));
  print_nav_buttons(_("Main page"), 0, 0);
  printf("<hr>\n");
  fflush(stdout);
  open_serve();
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_SHOW_CLAR,
                           client_team_id, global->contest_id,
                           client_locale_id, clar_id);
  if (r < 0) {
    printf("<p><pre><font color=\"red\">%s</font></pre></p>\n",
           gettext(protocol_strerror(-r)));
  }
  printf("<hr>\n");
  print_nav_buttons(_("Main page"), 0, 0);
  client_put_footer();
  exit(0);
}

static void
request_source_if_asked(void)
{
  char *s;
  int   n, run_id, r;

  if (!(s = cgi_nname("source_", 7))) return;
  if (sscanf(s, "source_%d%n", &run_id, &n) != 1
      || (s[n] && s[n] != '.'))
    return;
  if (run_id < 0 || run_id >= server_total_runs) return;

  set_cookie_if_needed();
  client_put_header(global->charset, _("Source view"));
  print_nav_buttons(_("Main page"), 0, 0);
  printf("<hr>");
  fflush(stdout);
  open_serve();
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_SHOW_SOURCE,
                           client_team_id, global->contest_id,
                           client_locale_id, run_id);
  if (r < 0) {
    printf("<p><pre><font color=\"red\">%s</font></pre></p>\n",
           gettext(protocol_strerror(-r)));
  }
  printf("<hr>");
  print_nav_buttons(_("Main page"), 0, 0);
  client_put_footer();
  exit(0);
}

static void
action_standings(void)
{
  int r;

  set_cookie_if_needed();
  client_put_header(global->charset, _("Current virtual standings"));
  print_nav_buttons(_("Main page"), 0, 0);
  printf("<hr>");
  fflush(stdout);
  open_serve();
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_VIRTUAL_STANDINGS,
                           client_team_id, global->contest_id,
                           client_locale_id, 0);
  r = 0;
  if (r < 0) {
    printf("<p><pre><font color=\"red\">%s</font></pre></p>\n",
           gettext(protocol_strerror(-r)));
  }
  printf("<hr>");
  print_nav_buttons(_("Main page"), 0, 0);
  client_put_footer();
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

  set_cookie_if_needed();
  client_put_header(global->charset, _("Report view"));
  print_nav_buttons(_("Main page"), 0, 0);
  printf("<hr>");
  fflush(stdout);
  open_serve();
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_SHOW_REPORT,
                           client_team_id, global->contest_id,
                           client_locale_id, run_id);
  if (r < 0) {
    printf("<p><pre><font color=\"red\">%s</font></pre></p>\n",
           gettext(protocol_strerror(-r)));
  }
  printf("<hr>");
  print_nav_buttons(_("Main page"), 0, 0);
  client_put_footer();
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
action_change_language(void)
{
  // if we are here, no further operations are required
  operation_status_page(0, 0);
}

static void
action_logout(void)
{
  if (client_sid) {
    open_userlist_server();
    userlist_clnt_logout(server_conn, client_ip, client_sid);
  }
  if (client_sid_mode == SID_COOKIE) {
    client_cookie = 0;
    need_set_cookie = 1;
  }
  set_cookie_if_needed();
  client_put_header(global->charset, "%s", _("Good-bye"));
  printf("<p>%s</p>\n",
         _("Good-bye!"));
  printf(_("<p>Follow this <a href=\"%s\">link</a> to login again.</p>"),
         self_url);
  client_put_footer();
  exit(0);
}

static void
display_team_page(void)
{
  int r;

  fflush(stdout);
  open_serve();
  r = serve_clnt_team_page(serve_socket_fd, 1,
                           client_sid_mode, client_locale_id,
                           ((client_view_all_clars?1:0)<<1)|(client_view_all_runs?1:0),
                           self_url, hidden_vars, contest_id_str);
  if (r < 0) {
    printf("<p>%s: %s\n", _("Server error"),
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
    client_access_denied(global->charset);

  if (!contests_check_team_ip(global->contest_id, client_ip)) {
    client_access_denied(global->charset);
  }

  /*
  if (cur_contest) {
    if (!contests_check_ip(cur_contest, client_ip))
      client_access_denied(global->charset);
  }
  */

  read_locale_id();

#if CONF_HAS_LIBINTL - 0 == 1
  /* load the language used */
  if (global->enable_l10n) {
    bindtextdomain("ejudge", global->l10n_dir);
    textdomain("ejudge");
  }
  if (client_locale_id >= 0 && client_locale_id <= 1) {
    setup_locale(client_locale_id);
  }
#endif /* CONF_HAS_LIBINTL */

  if (authentificate() != 1) client_access_denied(global->charset);

  read_state_params();

  // FIXME: is server_lag necessary?
  if (cur_contest->client_ignore_time_skew) {
    server_lag = 0;
  }
  if (!client_check_server_status(global->charset,
                                  global->status_file, server_lag)) {
    return 0;
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
    default:
      show_clar_if_asked();
      request_source_if_asked();
      request_report_if_asked();
      request_archive_if_asked();
    }
  }

  if (force_recheck_status) {
    client_check_server_status(global->charset,
                               global->status_file, server_lag);
    force_recheck_status = 0;
  }

  set_cookie_if_needed();
  if (cur_contest->name) {
    client_put_header(global->charset,
                       "%s: &quot;%s&quot - &quot;%s&quot;",
                      _("Monitor"),
                      client_team_name, cur_contest->name);
  } else {
    client_put_header(global->charset, "%s: &quot;%s&quot",
                      _("Monitor"),
                      client_team_name);
  }

  need_show_submit = server_start_time && !server_stop_time && !server_clients_suspended;
  need_show_clar = server_start_time && !server_stop_time && !server_team_clars_disabled && !server_clars_disabled && !server_clients_suspended;

  /* print quick navigation */
  puts("<ul>");
  printf("<li><a href=\"#status\">%s</a></li>\n", _("Contest status"));
  if (error_log)
    printf("<li><a href=\"#lastcmd\">%s</a>\n",
           _("The last command completion status"));
  if (need_show_submit)
    printf("<li><a href=\"#submit\">%s</a>\n", _("Send a submission"));
  if (server_start_time && !server_clients_suspended)
    printf("<li><a href=\"#runstat\">%s</a>\n", _("Submission log"));
  if (need_show_clar)
    printf("<li><a href=\"#clar\">%s</a>\n", _("Send a message to judges"));
  if (!server_clars_disabled && !server_clients_suspended)
    printf("<li><a href=\"#clarstat\">%s</a>\n", _("Messages from judges"));
  if (!server_clients_suspended && !cur_contest->disable_team_password) {
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
  if (cur_contest->problems_url && server_start_time) {
    printf("<li><a href=\"%s\" target=_blank>%s</a>\n",
           cur_contest->problems_url, _("Problems"));
  }
  puts("</ul>");
  print_nav_buttons(0, 0, 0);

  if (error_log) {
    printf("<hr><a name=\"lastcmd\"><h2>%s</h2>\n",
           _("The last command completion status"));
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

  if (!server_clients_suspended && !cur_contest->disable_team_password) {
    printf("<hr><a name=\"chgpasswd\"><h2>%s</h2>\n"
           "%s<table>\n"
           "<tr><td>%s:</td><td><input type=\"password\" name=\"oldpasswd\" size=\"16\"></td></tr>\n"
           "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd1\" size=\"16\"></td></tr>\n"
           "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd2\" size=\"16\"></td></tr>\n"
           "<tr><td colspan=\"2\"><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr>\n"
           "</table></form>",
           _("Change password"), form_start_simple,
           _("Old password"),
           _("New password"), _("Retype new password"),
           ACTION_CHANGE_PASSWORD, _("Change!"));
    print_nav_buttons(0, 0, 0);
  }

#if CONF_HAS_LIBINTL - 0 == 1
  if (global->enable_l10n) {
    printf("<hr><a name=\"chglanguage\"><h2>%s</h2>\n",
           _("Change language"));
    if (!client_sid_mode) {
      printf("%s<input type=\"hidden\" name=\"login\" value=\"%s\">"
             "<input type=\"hidden\" name=\"password\" value=\"%s\">",
             form_header_simple, client_login, client_password);
    } else {
      printf("%s", form_start_simple);
    }
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
    printf("<hr><p>%s: %ld %s\n",
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

  client_put_footer();
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
