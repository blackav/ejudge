/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
  int    server_lag;
  int    max_run_size;
  int    max_clar_size;
  int    show_generation_time;
  path_t root_dir;
  path_t var_dir;
  path_t allow_from;
  path_t deny_from;
  path_t status_file;
  path_t standings_url;
  path_t problems_url;
  path_t charset;
  path_t serve_socket;

  /* locallization stuff */
  int    enable_l10n;
  path_t l10n_dir;

  /* userlist-server stuff */
  int contest_id;
  path_t socket_path;
  path_t contests_path;
};

/* configuration information */
static struct generic_section_config *config;
static struct section_global_data *global;

/* new userlist-server related variables */
static struct contest_list *contests;
static struct contest_desc *cur_contest;
static struct userlist_clnt *server_conn;
static unsigned long client_ip;

/* client state variables */
static char   *client_login;
static char   *client_password;
static int     client_locale_id;
static char   *client_team_name;
static int     client_team_id;

static int     client_view_all_runs;
static int     client_view_all_clars;

static int     force_recheck_status = 0;

static char   *error_log;

static int serve_socket_fd = -1;

/* for general use */
static char    form_start_simple[1024];
static char    form_start_multipart[1024];
static char    form_start_simple_ext[1024];
static char    form_start_multipart_ext[1024];

/* description of configuration parameters */
#define GLOBAL_OFFSET(x) XOFFSET(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(allow_deny, "d"),
  GLOBAL_PARAM(server_lag, "d"),
  GLOBAL_PARAM(max_run_size, "d"),
  GLOBAL_PARAM(max_clar_size, "d"),
  GLOBAL_PARAM(show_generation_time, "d"),
  GLOBAL_PARAM(root_dir, "s"),
  GLOBAL_PARAM(var_dir, "s"),
  GLOBAL_PARAM(allow_from, "s"),
  GLOBAL_PARAM(deny_from, "s"),
  GLOBAL_PARAM(status_file, "s"),
  GLOBAL_PARAM(standings_url, "s"),
  GLOBAL_PARAM(problems_url, "s"),
  GLOBAL_PARAM(charset, "s"),
  GLOBAL_PARAM(enable_l10n, "d"),
  GLOBAL_PARAM(l10n_dir, "s"),

  GLOBAL_PARAM(contest_id, "d"),
  GLOBAL_PARAM(socket_path, "s"),
  GLOBAL_PARAM(contests_path, "s"),
  GLOBAL_PARAM(serve_socket, "s"),

  { 0, 0, 0, 0 }
};
static struct config_section_info params[] =
{
  { "global" ,sizeof(struct section_global_data), section_global_params },
  { NULL, 0, NULL }
};

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
  if (global->server_lag < 0 || global->server_lag > 30) {
    err("invalid server_lag");
    return -1;
  }
  if (!global->server_lag) global->server_lag = DEFAULT_SERVER_LAG;
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

static void
initialize(int argc, char *argv[])
{
  path_t  fullname;
  path_t  dirname;
  path_t  basename;
  path_t  cfgname;
  char   *s = getenv("SCRIPT_FILENAME");
  
  struct generic_section_config *p;

  pathcpy(fullname, argv[0]);
  if (s) pathcpy(fullname, s);
  os_rDirName(fullname, dirname, PATH_MAX);
  os_rGetBasename(fullname, basename, PATH_MAX);
  strcpy(program_name, basename);
  if (strncmp(basename, "team", 4))
    client_not_configured(0, "bad program_name");

  /*
   * if CGI_DATA_PATH is absolute, do not append the program start dir
   */
  /* FIXME: we need to perform "/" translation */
  if (CGI_DATA_PATH[0] == '/') {
    pathmake(cfgname, CGI_DATA_PATH, "/", basename, ".cfg", NULL);
  } else {
    pathmake(cfgname, dirname, "/",CGI_DATA_PATH, "/", basename, ".cfg", NULL);
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

  if (set_defaults() < 0)
    client_not_configured(global->charset, "bad defaults");
  logger_set_level(-1, LOG_WARNING);

  if (!(contests = parse_contest_xml(global->contests_path))) {
    client_not_configured(global->charset, "no contests are defined");
  }
  if (global->contest_id <= 0
      || global->contest_id >= contests->id_map_size
      || !(cur_contest = contests->id_map[global->contest_id])) {
    client_not_configured(global->charset, "invalid contest");
  }
  parse_client_ip();

  serve_socket_fd = serve_clnt_open(global->serve_socket);
  if (serve_socket_fd < 0) {
    client_not_configured(global->charset, "server is down");
  }

  /* check directory structure */
  client_make_form_headers();
}

static void
read_state_params(void)
{
  sprintf(form_start_simple,
          "%s<input type=\"hidden\" name=\"login\" value=\"%s\">"
          "<input type=\"hidden\" name=\"password\" value=\"%s\">"
          "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">",
          form_header_simple, client_login, client_password,
          client_locale_id);
  sprintf(form_start_multipart,
          "%s<input type=\"hidden\" name=\"login\" value=\"%s\">"
          "<input type=\"hidden\" name=\"password\" value=\"%s\">"
          "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">",
          form_header_multipart, client_login, client_password,
          client_locale_id);
  sprintf(form_start_simple_ext,
          "%s<input type=\"hidden\" name=\"login\" value=\"%s\">"
          "<input type=\"hidden\" name=\"password\" value=\"%s\">"
          "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">",
          form_header_simple_ext, client_login, client_password,
          client_locale_id);
  sprintf(form_start_multipart_ext,
          "%s<input type=\"hidden\" name=\"login\" value=\"%s\">"
          "<input type=\"hidden\" name=\"password\" value=\"%s\">"
          "<input type=\"hidden\" name=\"locale_id\" value=\"%d\">",
          form_header_multipart_ext, client_login, client_password,
          client_locale_id);

  client_view_all_runs = 0;
  client_view_all_clars = 0;
  if (cgi_param("view_all_runs"))  client_view_all_runs = 1;
  if (cgi_param("view_all_clars")) client_view_all_clars = 1;
}

static int
ask_passwd(void)
{
  char *l = cgi_param("login");
  char *p = cgi_param("password");
  if (!l || !p) return 1;
  return 0;
}

static int
check_passwd(void)
{
  int r, new_uid, new_locale_id;
  unsigned char *new_name;
  unsigned long long new_cookie;
  char *l, *p;

  l = cgi_param("login");
  p = cgi_param("password");
  if (!l || !p) return 0;
  client_login = l;
  client_password = p;

  if (!server_conn) {
    server_conn = userlist_clnt_open(global->socket_path);
    if (!server_conn) {
      client_not_configured(global->charset, "server is not available");
    }
  }
  r = userlist_clnt_team_login(server_conn, client_ip, cur_contest->id,
                               client_locale_id, 0,
                               client_login, client_password,
                               &new_uid, &new_cookie, &new_locale_id,
                               &new_name);
  if (r != ULS_LOGIN_OK) return 0;
  client_team_id = new_uid;
  client_team_name = new_name;
  client_locale_id = new_locale_id;
  return 1;
}

static int
display_enter_password(void)
{
  client_put_header(global->charset, _("Enter password"));
  puts(form_header_simple);
  printf("<p>%s: <input type=\"text\" size=\"16\" name=\"login\">\n",
         _("Login"));
  printf("<p>%s: <input type=\"password\" size=\"16\" name=\"password\">\n",
       _("Password"));
  if (global->enable_l10n) {
    printf("<p>%s: <select name=\"locale_id\">"
           "<option value=\"0\"%s>%s</option>"
           "<option value=\"1\"%s>%s</option>"
           "</select>",
           _("Choose language"),
           client_locale_id==0?" selected=\"1\"":"", _("English"),
           client_locale_id==1?" selected=\"1\"":"", _("Russian"));
  }
  printf("<p><input type=\"submit\" value=\"%s\">", _("submit"));
  puts("</form>");
  client_put_footer();
  return 0;
}

static void
print_refresh_button(char const *anchor)
{
  printf(form_start_simple_ext, anchor);
  printf("<input type=\"submit\" name=\"refresh\" value=\"%s\">\n",
         _("Refresh"));
  puts("</form>");
}

static void
send_clar_if_asked(void)
{
  char *s, *p, *t, *r, *full_subj;
  int n;

  if (!cgi_param("msg")) return;

  if (!server_start_time) {
    error("%s", _("The message cannot be sent. The contest is not started."));
    return;
  }
  if (server_stop_time) {
    error("%s", _("The message cannot be sent. The contest is over."));
    return;
  }
  if (server_team_clars_disabled) {
    error("%s", _("The message cannot be sent. Messages are disabled."));
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
    error("%s", _("The message cannot be sent because its size exceeds maximal allowed."));
    return;
  }

  n = serve_clnt_submit_clar(serve_socket_fd, client_team_id,
                             global->contest_id, client_locale_id,
                             client_ip, full_subj, t);
  if (n < 0) {
    error("%s", gettext(protocol_strerror(-n)));
  } else {
    error("%s", _("clarification is sent successfully"));
  }

  force_recheck_status = 1;
}

static void
submit_if_asked(void)
{
  char *p, *l, *t;
  int prob, lang, n;

  if (!cgi_param("send")) return;

  if (!server_start_time) {
    error("%s", _("The submission cannot be sent. The contest is not started."));
    return;
  }
  if (server_stop_time) {
    error("%s", _("The submission cannot be sent. The contest is over."));
    return;
  }

  p = cgi_param("problem");  if (!p) p = "";
  l = cgi_param("language"); if (!l) l = "";
  t = cgi_param("file");     if (!t) t = "";

  if (sscanf(p, "%d%n", &prob, &n) != 1
      || p[n]
      || sscanf(l, "%d%n", &lang, &n) != 1
      || l[n]) {
    return;
  }

  if (strlen(t) > global->max_run_size) {
    error("%s", _("The submission cannot be sent because its size exceeds maximal allowed."));
    return;
  }

  n = serve_clnt_submit_run(serve_socket_fd, client_team_id,
                            global->contest_id, client_locale_id,
                            client_ip, prob, lang, t);
  if (n < 0) {
    error("%s", gettext(protocol_strerror(-n)));
  } else {
    error("%s", _("submission is sent successfully"));
  }

  force_recheck_status = 1;
}

static void
change_passwd_if_asked(void)
{
  char *p1, *p2;
  int r;

  if (!cgi_param("change_passwd")) return;
  p1 = cgi_param("newpasswd1");
  p2 = cgi_param("newpasswd2");
  if (!p1 || !p2 || !*p1 || !*p2) return;

  if (strcmp(p1, p2)) {
    error("%s", _("Passwords do not match."));
    return;
  }
  if (strlen(p1) > 16) {
    error("%s", _("Password is too long (>16 characters)."));
    return;
  }
  if (fix_string(p1, password_accept_chars, '?') > 0) {
    error("%s", _("Password contain invalid characters."));
    return;
  }

  if (!server_conn) {
    error("%s", _("No connection to server."));
    return;
  }
  // FIXME: if we are in cookie mode, we need to know the old password!
  r = userlist_clnt_team_set_passwd(server_conn, client_team_id,
                                    client_password, p1);
  if (r < 0) {
    error("%s", gettext(userlist_strerror(-r)));
    return;
  }

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

  client_put_header(global->charset, _("Message view"));
  fflush(stdout);
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_SHOW_CLAR,
                           client_team_id, global->contest_id,
                           client_locale_id, clar_id);
  if (r < 0) {
    printf("<p><pre><font color=\"red\">%s</font></pre></p>\n",
           gettext(protocol_strerror(-r)));
  }
  printf("<hr>%s<input type=\"submit\" name=\"refresh\" value=\"%s\"></form>",
         form_start_simple, _("Back"));
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

  client_put_header(global->charset, _("Source view"));
  printf("<hr>");
  fflush(stdout);
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_SHOW_SOURCE,
                           client_team_id, global->contest_id,
                           client_locale_id, run_id);
  if (r < 0) {
    printf("<p><pre><font color=\"red\">%s</font></pre></p>\n",
           gettext(protocol_strerror(-r)));
  }
  printf("<hr>%s<input type=\"submit\" name=\"refresh\" value=\"%s\"></form>",
         form_start_simple, _("Back"));

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

  client_put_header(global->charset, _("Report view"));
  printf("<hr>");
  fflush(stdout);
  r = serve_clnt_show_item(serve_socket_fd, 1, SRV_CMD_SHOW_REPORT,
                           client_team_id, global->contest_id,
                           client_locale_id, run_id);
  if (r < 0) {
    printf("<p><pre><font color=\"red\">%s</font></pre></p>\n",
           gettext(protocol_strerror(-r)));
  }
  printf("<hr>%s<input type=\"submit\" name=\"refresh\" value=\"%s\"></form>",
         form_start_simple, _("Back"));

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

  if (!global->serve_socket[0] || global->contest_id <= 0) {
    error("%s", _("Operation is not supported"));
    return;
  }

  if ((r = serve_clnt_get_archive(serve_socket_fd, client_team_id,
                                  global->contest_id, client_locale_id,
                                  &token, &dirpath)) < 0) {
    error("%s", gettext(protocol_strerror(-r)));
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
display_team_page(void)
{
  int r;

  fflush(stdout);
  r = serve_clnt_team_page(serve_socket_fd, 1,
                           client_team_id, global->contest_id,
                           client_locale_id, client_ip,
                           ((client_view_all_clars?1:0)<<1)|(client_view_all_runs?1:0),
                           form_start_simple,
                           form_start_multipart);
  if (r < 0) {
    printf("<p>%s: %s\n", _("Server error"),
           gettext(protocol_strerror(-r)));
  }
}

int
main(int argc, char *argv[])
{
  int need_show_submit = 0;
  int need_show_clar = 0;
  struct timeval begin_time, end_time;

  gettimeofday(&begin_time, 0);
  initialize(argc, argv);

  if (!client_check_source_ip(global->allow_deny,
                              global->allow_from,
                              global->deny_from))
    client_access_denied(global->charset);

  if (cur_contest) {
    if (!contests_check_ip(cur_contest, client_ip))
      client_access_denied(global->charset);
  }

  cgi_read(global->charset);

#if CONF_HAS_LIBINTL - 0 == 1
  /* load the language used */
  if (global->enable_l10n) {
    char *e = cgi_param("locale_id");
    int n = 0;
    char env_buf[1024];

    if (e) {
      if (sscanf(e, "%d%n", &client_locale_id, &n) != 1 || e[n])
        client_locale_id = 0;
      if (client_locale_id < 0 || client_locale_id > 1)
        client_locale_id = 0;
    }

    switch (client_locale_id) {
    case 1:
      e = "ru_RU.KOI8-R";
      break;
    case 0:
    default:
      client_locale_id = 0;
      e = "C";
      break;
    }

    sprintf(env_buf, "LC_ALL=%s", e);
    putenv(env_buf);
    setlocale(LC_ALL, "");
    bindtextdomain("ejudge", global->l10n_dir);
    textdomain("ejudge");
  }
#endif /* CONF_HAS_LIBINTL */
  
  if (ask_passwd()) {
    display_enter_password();
    return 0;
  }

  ASSERT(!server_conn);
  if (!(server_conn = userlist_clnt_open(global->socket_path))) {
    client_not_configured(global->charset, _("no connection to server"));
  }
  if (!check_passwd()) client_access_denied(global->charset);

  read_state_params();

  if (!client_check_server_status(global->charset,
                                  global->status_file, global->server_lag)) {
    return 0;
  }

  if (!server_clients_suspended) {
    send_clar_if_asked();
    show_clar_if_asked();
    request_source_if_asked();
    request_report_if_asked();
    request_archive_if_asked();
    submit_if_asked();
    change_passwd_if_asked();

    if (force_recheck_status) {
      client_check_server_status(global->charset,
                                 global->status_file, global->server_lag);
      force_recheck_status = 0;
    }
  }

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
    printf("<li><a href=\"#clarstat\">%s</a>\n", _("Messages log"));
  if (!server_clients_suspended) {
    printf("<li><a href=\"#chgpasswd\">%s</a>\n", _("Change password"));
  }
#if CONF_HAS_LIBINTL - 0 == 1
  if (global->enable_l10n) {
    printf("<li><a href=\"#chglanguage\">%s</a>\n", _("Change language"));
  }
#endif /* CONF_HAS_LIBINTL */
  if (global->standings_url[0] && need_show_submit) {
    printf("<li><a href=\"%s\" target=_blank>%s</a>\n",
           global->standings_url, _("Team standings"));
  }
  if (global->problems_url[0] && need_show_submit) {
    printf("<li><a href=\"%s\" target=_blank>%s</a>\n",
           global->problems_url, _("Problems"));
  }
  puts("</ul>");
  print_refresh_button("");

  client_print_server_status(1, "", "status");
  print_refresh_button("#status");

  if (error_log) {
    printf("<hr><a name=\"lastcmd\"><h2>%s</h2>\n",
           _("The last command completion status"));
    printf("<pre><font color=\"red\">%s</font></pre>\n", error_log);
    print_refresh_button("");
  }

  if (!server_clients_suspended) {
    display_team_page();
  }

  if (!server_clients_suspended) {
    printf("<hr><a name=\"chgpasswd\"><h2>%s</h2>\n"
           "%s<table>\n"
           "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd1\" size=\"16\"></td></tr>\n"
           "<tr><td>%s:</td><td><input type=\"password\" name=\"newpasswd2\" size=\"16\"></td></tr>\n"
           "<tr><td colspan=\"2\"><input type=\"submit\" name=\"change_passwd\" value=\"%s\"></td></tr>\n"
           "</table></form>",
           _("Change password"), form_start_simple,
           _("New password"), _("Retype new password"), _("Change!"));
    print_refresh_button("");
  }

#if CONF_HAS_LIBINTL - 0 == 1
  if (global->enable_l10n) {
    printf("<hr><a name=\"chglanguage\"><h2>%s</h2>\n"
           "%s<input type=\"hidden\" name=\"login\" value=\"%s\">"
           "<input type=\"hidden\" name=\"password\" value=\"%s\">"
           "%s: <select name=\"locale_id\">"
           "<option value=\"0\"%s>%s</option>"
           "<option value=\"1\"%s>%s</option>"
           "</select>"
           "<input type=\"submit\" name=\"refresh\" value=\"%s\"></form>\n",
           _("Change language"),
           form_header_simple, client_login, client_password,
           _("Change language"),
           client_locale_id==0?" selected=\"1\"":"", _("English"),
           client_locale_id==1?" selected=\"1\"":"", _("Russian"),
           _("Change!"));
    print_refresh_button("");
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
  }
#endif

  client_put_footer();
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
