/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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

#include "expat_iface.h"
#include "xml_utils.h"
#include "pathutl.h"
#include "clntutil.h"
#include "contests.h"
#include "userlist_clnt.h"
#include "cgi.h"
#include "userlist.h"
#include "userlist_proto.h"
#include "super_clnt.h"
#include "super_proto.h"
#include "super_actions.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
*/
#define _(x) x

#if defined EJUDGE_CHARSET
#define DEFAULT_CHARSET              EJUDGE_CHARSET
#else
#define DEFAULT_CHARSET              "iso8859-1"
#endif /* EJUDGE_CHARSET */

/* configuration file:
 * <serve_control_config>
 *   <charset>CHARSET</charset>
 *   <super_serve_socket>PATH</super_serve_socket>
 *   <socket_path>PATH</socket_path>
 *   <contests_dir>PATH</contests_dir>
 *   <serve_control_access default="allow|deny">
 *     <ip allow="YES|NO">IP</ip>
 *   </serve_control_access>
 * </serve_control_config>
 */
enum
{
  TG_CONFIG = 1,
  TG_SUPER_SERVE_SOCKET,
  TG_SOCKET_PATH,
  TG_CONTESTS_DIR,
  TG_SERVE_CONTROL_ACCESS,
  TG_IP,
  TG_CHARSET,

  TG_LAST_TAG,
};
enum
{
  AT_DEFAULT = 1,
  AT_ALLOW,
};

struct ip_node
{
  struct xml_tree b;
  int allow;
  unsigned int addr;
  unsigned int mask;
};
struct access_node
{
  struct xml_tree b;
  int default_is_allow;
};
struct config_node
{
  struct xml_tree b;

  unsigned char *charset;
  unsigned char *super_serve_socket;
  unsigned char *socket_path;
  unsigned char *contests_dir;
  struct access_node *access;
};

static const char * const elem_map[] =
{
  0,
  "serve_control_config",
  "super_serve_socket",
  "socket_path",
  "contests_dir",
  "serve_control_access",
  "ip",
  "charset",
  0,
};
static const char * const attr_map[] =
{
  0,
  "default",
  "allow",
  0,
};
static size_t elem_size[TG_LAST_TAG] =
{
  [TG_CONFIG] sizeof(struct config_node),
  [TG_SERVE_CONTROL_ACCESS] sizeof(struct access_node),
  [TG_IP] sizeof(struct ip_node),
};
static void *
elem_alloc(int tag)
{
  size_t sz = sizeof(struct xml_tree);

  ASSERT(tag > 0 && tag < TG_LAST_TAG);
  if (elem_size[tag]) sz = elem_size[tag];
  return xcalloc(1, sz);
}
static void *
attr_alloc(int tag)
{
  return xcalloc(1, sizeof(struct xml_attn));
}

static struct config_node *
parse_config(const unsigned char *path, const unsigned char *default_config)
{
  struct xml_tree *tree = 0, *t1, *t2;
  struct xml_attn *attr;
  struct config_node *cfg = 0;
  struct ip_node *pip;
  unsigned char **leaf_elem_addr = 0;

  if (default_config) {
    tree = xml_build_tree_str(default_config, elem_map, attr_map,
                              elem_alloc, attr_alloc);
  } else {
    tree = xml_build_tree_str(path, elem_map, attr_map,
                              elem_alloc, attr_alloc);
  }
  if (!tree) goto failed;

  xml_err_path = path;
  xml_err_elem_names = elem_map;
  xml_err_attr_names = attr_map;

  if (tree->tag != TG_CONFIG) {
    xml_err_top_level(tree, TG_CONFIG);
    goto failed;
  }
  cfg = (struct config_node *) tree;
  tree = 0;

  if (cfg->b.first) {
    xml_err_attrs(tree);
    goto failed;
  }
  if (xml_empty_text(&cfg->b) < 0) goto failed;

  for (t1 = cfg->b.first_down; t1; t1 = t1->left) {
    switch (t1->tag) {
    case TG_SUPER_SERVE_SOCKET:
      leaf_elem_addr = &cfg->super_serve_socket; goto parse_final_tag;
    case TG_SOCKET_PATH:
      leaf_elem_addr = &cfg->socket_path; goto parse_final_tag;
    case TG_CONTESTS_DIR:
      leaf_elem_addr = &cfg->contests_dir; goto parse_final_tag;
    case TG_CHARSET:
      leaf_elem_addr = &cfg->charset; goto parse_final_tag;
    parse_final_tag:
      if (xml_leaf_elem(t1, leaf_elem_addr, 1, 0) < 0)
        goto failed;
      break;
    case TG_SERVE_CONTROL_ACCESS:
      if (xml_empty_text(t1) < 0) goto failed;
      if (cfg->access) {
        xml_err_elem_redefined(t1);
        goto failed;
      }
      cfg->access = (struct access_node*) t1;
      for (attr = t1->first; attr; attr = attr->next) {
        switch (attr->tag) {
        case AT_DEFAULT:
          if (!strcasecmp(attr->text, "ALLOW")) {
            cfg->access->default_is_allow = 1;
          } else if (!strcasecmp(attr->text, "DENY")) {
          } else {
            xml_err_attr_invalid(attr);
            goto failed;
          }
          break;
        default:
          xml_err_attr_not_allowed(t1, attr);
          goto failed;
        }
      }
      for (t2 = t1->first_down; t2; t2 = t2->left) {
        if (t2->tag != TG_IP) {
          xml_err_elem_not_allowed(t2);
          goto failed;
        }
        pip = (struct ip_node*) t2;
        for (attr = t2->first; attr; attr = attr->next) {
          if (attr->tag != AT_ALLOW) {
            xml_err_attr_not_allowed(t2, attr);
            goto failed;
          }
          if (xml_attr_bool(attr, &pip->allow) < 0) goto failed;
        }
        if (xml_elem_ip_mask(t2, &pip->addr, &pip->mask) < 0) goto failed;
      }
      break;
      
    default:
      xml_err_elem_not_allowed(t1);
      goto failed;
    }
  }

#if defined EJUDGE_CHARSET
  if (!cfg->charset) cfg->charset = xstrdup(EJUDGE_CHARSET);
#endif /* EJUDGE_CHARSET */
  if (!cfg->charset) cfg->charset = "iso8859-1";

#if defined EJUDGE_SOCKET_PATH
  if (!cfg->socket_path) cfg->socket_path = xstrdup(EJUDGE_SOCKET_PATH);
#endif
  if (!cfg->socket_path) {
    xml_err_elem_undefined(&cfg->b, TG_SOCKET_PATH);
    goto failed;
  }

#if defined EJUDGE_SUPER_SERVE_SOCKET
  if (!cfg->super_serve_socket)
    cfg->super_serve_socket = xstrdup(EJUDGE_SUPER_SERVE_SOCKET);
#endif
  if (!cfg->super_serve_socket) {
    xml_err_elem_undefined(&cfg->b, TG_SUPER_SERVE_SOCKET);
    goto failed;
  }

#if defined EJUDGE_CONTESTS_DIR
  if (!cfg->contests_dir) cfg->contests_dir = xstrdup(EJUDGE_CONTESTS_DIR);
#endif
  if (!cfg->contests_dir) {
    xml_err_elem_undefined(&cfg->b, TG_CONTESTS_DIR);
    goto failed;
  }
  return cfg;

 failed:
  /* FIXME: release resources... */
  return 0;
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
static const unsigned char default_config[] =
"<?xml version=\"1.0\" ?>\n"
"<serve_control_config>\n"
"  <serve_control_access default=\"allow\"/>\n"
"</serve_control_config>\n";

static struct config_node *config;
static unsigned long user_ip;
static userlist_clnt_t userlist_conn;
static unsigned long long session_id;
static unsigned int user_id;
static unsigned char *user_login;
static unsigned char *user_name;
static unsigned char *user_password;
static unsigned char *self_url;
static int super_serve_fd = -1;
static int priv_level;
static int client_action;
static unsigned char hidden_vars[1024];

static void
make_self_url(void)
{
  unsigned char *http_host = getenv("HTTP_HOST");
  unsigned char *script_name = getenv("SCRIPT_NAME");
  unsigned char fullname[1024];

  if (!http_host) http_host = "localhost";
  if (!script_name) script_name = "/cgi-bin/serve-control";
  snprintf(fullname, sizeof(fullname), "http://%s%s",
           http_host, script_name);
  self_url = xstrdup(fullname);
}

static void
initialize(int argc, char *argv[])
{
  path_t full_path;
  path_t dir_path;
  path_t base_name;
  path_t exp_base;
  path_t cfg_dir;
  path_t cfg_path;
  unsigned char *s;

  s = getenv("SCRIPT_FILENAME");
  if (!s) s = argv[0];
  if (!s) s = "";
  snprintf(full_path, sizeof(full_path), "%s", s);
  os_rDirName(full_path, dir_path, PATH_MAX);
  os_rGetBasename(full_path, base_name, PATH_MAX);

#if defined CGI_PROG_SUFFIX
  snprintf(exp_base, sizeof(exp_base),"%s%s","serve-control", CGI_PROG_SUFFIX);
#else
  snprintf(exp_base, sizeof(exp_base), "%s", "serve_control");
#endif
  if (strcmp(exp_base, base_name) != 0) {
    client_not_configured(0, "bad program name", 0);
  }

#if defined CGI_DATA_PATH
  if (CGI_DATA_PATH[0] == '/') {
    snprintf(cfg_dir, sizeof(cfg_dir), "%s/", CGI_DATA_PATH);
  } else {
    snprintf(cfg_dir, sizeof(cfg_dir), "%s/%s/", dir_path, CGI_DATA_PATH);
  }
#else
  snprintf(cfg_dir, sizeof(cfg_dir), "%s/../cgi-data/", dir_path);
#endif

  snprintf(cfg_path, sizeof(cfg_path), "%s%s.xml", cfg_dir, base_name);
  if (check_config_exist(cfg_path)) {
    config = parse_config(cfg_path, 0);
  } else {
    config = parse_config(0, default_config);
  }
  if (!config) {
    client_not_configured(0, "config file not parsed", 0);
  }

  if (contests_set_directory(config->contests_dir) < 0) {
    client_not_configured(0, "contests directory is invalid", 0);
  }
  logger_set_level(-1, LOG_WARNING);

  cgi_read(0);
  user_ip = parse_client_ip();

  make_self_url();
  client_make_form_headers(self_url);
}

static int
check_source_ip(void)
{
  struct ip_node *p;

  if (!config) return 0;
  if (!config->access) return 0;
  if (!user_ip) return config->access->default_is_allow;

  for (p = (struct ip_node*) config->access->b.first_down;
       p; p = (struct ip_node*) p->b.right) {
    if ((user_ip & p->mask) == p->addr) return p->allow;
  }
  return config->access->default_is_allow;
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
open_userlist_server(void)
{
  if (userlist_conn) return;
  if (!(userlist_conn = userlist_clnt_open(config->socket_path))) {
    client_put_header(stdout, 0, 0, config->charset, 1, 0,
                      _("Server is down"));
    printf("<p>%s</p>",
           _("The server is down. Try again later."));
    client_put_footer(stdout, 0);
    exit(0);
  }
}
static void
open_super_server(void)
{
  if (super_serve_fd >= 0) return;
  if ((super_serve_fd = super_clnt_open(config->super_serve_socket)) < 0) {
    client_put_header(stdout, 0, 0, config->charset, 1, 0,
                      _("Server is down"));
    printf("<p>%s</p>",
           _("The server is down. Try again later."));
    client_put_footer(stdout, 0);
    exit(0);
  }
}

static void fatal_server_error(int r) __attribute__((noreturn));
static void
fatal_server_error(int r)
{
  client_put_header(stdout, 0, 0, config->charset, 1, 0, _("Server error"));
  printf("<p>Server error: %s</p>", userlist_strerror(-r));
  client_put_footer(stdout, 0);
  exit(0);
}

static void permission_denied(void) __attribute__((noreturn));
static void
permission_denied(void)
{
  client_put_header(stdout,0,0,config->charset,1,0,_("Permission denied"));
  printf("<p>%s</p>", _("You do not have permissions to use this service"));
  client_put_footer(stdout, 0);
  exit(0);
}

static void invalid_login(void) __attribute__((noreturn));
static void
invalid_login(void)
{
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    _("Invalid login"));
  printf("<p>%s</p>",
         "Invalid login. You have typed invalid login, invalid password,"
         " or have a banned IP-address.");
  client_put_footer(stdout, 0);
  exit(0);
}

static void display_login_page(void) __attribute__((noreturn));
static void
display_login_page(void)
{
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    "Enter password - serve-control");

  puts(form_header_simple);
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
  exit(0);
}

static unsigned char * hyperref(unsigned char *, size_t,
                                unsigned long long,
                                const unsigned char *,
                                const char *, ...)
     __attribute__((format(printf, 5, 6)));
static unsigned char *
hyperref(unsigned char *buf, size_t size,
         unsigned long long sid,
         unsigned char const *self_url,
         char const *format, ...)
{
  va_list args;
  unsigned char buf1[512];
  unsigned char buf2[1024];

  if (format && *format) {
    snprintf(buf1, sizeof(buf1), "%s?SID=%016llx", self_url, sid);
    va_start(args, format);
    vsnprintf(buf2, sizeof(buf2), format, args);
    va_end(args);
    snprintf(buf, size, "%s&%s", buf1, buf2);
  } else {
    snprintf(buf, size, "%s?SID=%016llx", self_url, sid);
  }
  return buf;
}
static unsigned char *
vhyperref(unsigned char *buf, size_t size,
          unsigned long long sid,
          unsigned char const *self_url,
          const unsigned char *format,
          va_list args)
{
  unsigned char buf1[512];
  unsigned char buf2[1024];

  if (format && *format) {
    snprintf(buf1, sizeof(buf1), "%s?SID=%016llx", self_url, sid);
    vsnprintf(buf2, sizeof(buf2), format, args);
    snprintf(buf, size, "%s&%s", buf1, buf2);
  } else {
    snprintf(buf, size, "%s?SID=%016llx", self_url, sid);
  }
  return buf;
}

static void
read_state_params(void)
{
  unsigned char *s;
  int x, n;

  client_action = 0;
  if ((s = cgi_param("action"))) {
    n = 0; x = 0;
    if (sscanf(s, "%d%n", &x, &n) == 1 && !s[n]
        && x > 0 && x < SUPER_ACTION_LAST)
      client_action = x;
  }
  if (!client_action && (s = cgi_nname("action_", 7))) {
    n = 0; x = 0;
    if (sscanf(s, "action_%d%n", &x, &n) == 1 && !s[n]
        && x > 0 && x < SUPER_ACTION_LAST)
      client_action = x;
  }

  snprintf(hidden_vars, sizeof(hidden_vars),
           "<input type=\"hidden\" name=\"SID\" value=\"%016llx\">",
           session_id);
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
parse_contest_id(void)
{
  unsigned char *s = cgi_param("contest_id");
  int v = 0, n = 0;

  if (!s) return 0;
  if (sscanf(s, "%d %n", &v, &n) != 1 || s[n] || v < 0) return 0;
  return v;
}

static void operation_status_page(int userlist_code,
                                  int super_code,
                                  const unsigned char *format,
                                  ...) __attribute__((noreturn));
static void
operation_status_page(int userlist_code,
                      int super_code,
                      const unsigned char *format,
                      ...)
{
  unsigned char msg[1024];
  unsigned char href[1024];
  va_list args;

  if (userlist_code == -1 && super_code == -1) {
    client_put_header(stdout, 0, 0, config->charset, 1, 0, "Operation failed");
    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);
    printf("<h2><font color=\"red\">%s</font></h2>\n", msg);
    client_put_footer(stdout, 0);
    exit(0);
  }
  if (userlist_code == -1 && super_code < -1) {
    client_put_header(stdout, 0, 0, config->charset, 1, 0, "Operation failed");
    printf("<h2><font color=\"red\">super-serve error: %s</font></h2>\n",
           super_proto_strerror(-super_code));
    client_put_footer(stdout, 0);
    exit(0);
  }
  if (userlist_code < -1 && super_code == -1) {
    client_put_header(stdout, 0, 0, config->charset, 1, 0, "Operation failed");
    printf("<h2><font color=\"red\">userlist-server error: %s</font></h2>\n",
           userlist_strerror(-userlist_code));
    client_put_footer(stdout, 0);
    exit(0);
  }
  if (userlist_code < -1 && super_code < -1) {
    client_put_header(stdout, 0, 0, config->charset, 1, 0, "Operation failed");
    printf("<h2><font color=\"red\">Unknown error: %d, %d</font></h2>\n",
           userlist_code, super_code);
    client_put_footer(stdout, 0);
    exit(0);
  }

  va_start(args, format);
  vhyperref(href, sizeof(href), session_id, self_url, format, args);
  va_end(args);
  client_put_refresh_header(config->charset, href, 0,
                            "Operation successfull");
  printf("<h2>Operation completed successfully</h2>");
  exit(0);
}

static void
authentificate(void)
{
  int r;
  unsigned char buf[512];

  if (get_session_id("SID", &session_id)) {
    open_userlist_server();
    r = userlist_clnt_priv_cookie(userlist_conn, user_ip,
                                  0, /* contest_id */
                                  session_id,
                                  0, /* locale_id */
                                  PRIV_LEVEL_ADMIN,
                                  &user_id,
                                  0, /* p_contest_id */
                                  0, /* p_locale_id */
                                  &priv_level,
                                  &user_login,
                                  &user_name);
    if (r >= 0) {
      user_password = "";
      return;
    }
    if (r != -ULS_ERR_NO_COOKIE) {
      if (r == -ULS_ERR_NO_PERMS) permission_denied();
      fatal_server_error(r);
    }
    session_id = 0;
  }

  user_login = cgi_param("login");
  user_password = cgi_param("password");
  if (!user_login || !user_password) display_login_page();

  fprintf(stderr, "%s, %s\n", user_login, user_password);

  open_userlist_server();
  r = userlist_clnt_priv_login(userlist_conn, user_ip,
                               0, /* contest_id */
                               0, /* locale_id */
                               1, /* session_id is enabled */
                               PRIV_LEVEL_ADMIN,
                               user_login,
                               user_password,
                               &user_id,
                               &session_id,
                               0, /* p_locale_id */
                               &priv_level,
                               &user_name);
  if (r < 0) {
    switch (-r) {
    case ULS_ERR_INVALID_LOGIN:
    case ULS_ERR_INVALID_PASSWORD:
    case ULS_ERR_IP_NOT_ALLOWED:
      invalid_login();
    case ULS_ERR_NO_PERMS:
      permission_denied();
    default:
      fatal_server_error(r);
    }
  }

  hyperref(buf, sizeof(buf), session_id, self_url, 0);
  client_put_refresh_header(config->charset, buf, 0, "Login successfull");
  printf("<p>%s</p>", _("Login successfull. Now entering the main page."));
  printf("<p>If automatic updating does not work, click on <a href=\"%s\">this</a> link.</p>", buf);
  exit(0);
}

static void action_view_contest(int cmd) __attribute__((noreturn));
static void
action_view_contest(int cmd)
{
  int contest_id, r;
  unsigned char *extra_str = "";

  if ((contest_id = parse_contest_id()) <= 0) goto invalid_parameter;

  switch (cmd) {
  case SSERV_CMD_VIEW_SERVE_LOG:
    extra_str = ", serve log";
    break;
  case SSERV_CMD_VIEW_RUN_LOG:
    extra_str = ", run log";
    break;
  case SSERV_CMD_VIEW_CONTEST_XML:
    extra_str = ", contest.xml";
    break;
  case SSERV_CMD_VIEW_SERVE_CFG:
    extra_str = ", serve.cfg";
    break;
  }

  open_super_server();
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    "%s: %s, %d%s", "serve-control", user_name, contest_id,
                    extra_str);
  fflush(stdout);
  r = super_clnt_main_page(super_serve_fd, 1, cmd,
                           contest_id, 0, 0, self_url, hidden_vars, "");
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           super_proto_strerror(-r));
  }
  client_put_footer(stdout, 0);
  exit(0);

 invalid_parameter:
  operation_status_page(-1, -1, "Contest view parameters are invalid");
}

static void action_simple_command(int cmd) __attribute__((noreturn));
static void
action_simple_command(int cmd)
{
  int contest_id, r;

  if ((contest_id = parse_contest_id()) <= 0) goto invalid_parameter;

  open_super_server();
  r = super_clnt_simple_cmd(super_serve_fd, cmd, contest_id);
  operation_status_page(-1, r, "contest_id=%d&action=%d", contest_id, 1);

 invalid_parameter:
  operation_status_page(-1, -1, "Contest control parameters are invalid");
}

int
main(int argc, char *argv[])
{
  int r;

  initialize(argc, argv);

  // check ip limitations from the configuration file
  if (!check_source_ip()) {
    client_access_denied(config->charset, 0);
  }

  authentificate();
  read_state_params();

  switch (client_action) {
  case SUPER_ACTION_VIEW_CONTEST:
    action_view_contest(SSERV_CMD_CONTEST_PAGE);
    break;
  case SUPER_ACTION_SERVE_LOG_VIEW:
    action_view_contest(SSERV_CMD_VIEW_SERVE_LOG);
    break;
  case SUPER_ACTION_RUN_LOG_VIEW:
    action_view_contest(SSERV_CMD_VIEW_RUN_LOG);
    break;
  case SUPER_ACTION_VIEW_CONTEST_XML:
    action_view_contest(SSERV_CMD_VIEW_CONTEST_XML);
    break;
  case SUPER_ACTION_VIEW_SERVE_CFG:
    action_view_contest(SSERV_CMD_VIEW_SERVE_CFG);
    break;
  case SUPER_ACTION_OPEN_CONTEST:
    action_simple_command(SSERV_CMD_OPEN_CONTEST);
    break;
  case SUPER_ACTION_CLOSE_CONTEST:
    action_simple_command(SSERV_CMD_CLOSE_CONTEST);
    break;
  case SUPER_ACTION_CONTEST_VISIBLE:
    action_simple_command(SSERV_CMD_VISIBLE_CONTEST);
    break;
  case SUPER_ACTION_CONTEST_INVISIBLE:
    action_simple_command(SSERV_CMD_INVISIBLE_CONTEST);
    break;
  }

  /* default (main) screen */
  open_super_server();
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    "%s: %s", "serve-control", user_name);
  fflush(stdout);
  r = super_clnt_main_page(super_serve_fd, 1, SSERV_CMD_MAIN_PAGE, 0,
                           0, 0, self_url, hidden_vars, "");
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           super_proto_strerror(-r));
  }
  client_put_footer(stdout, 0);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
