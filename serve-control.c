/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

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
 *     <ip allow="YES|NO" [ssl="YES|NO|ANY"]>IP</ip>
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
  AT_SSL,
};

struct ip_node
{
  struct xml_tree b;
  int allow;
  int ssl;
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
  "ssl",
  0,
};
static size_t elem_sizes[TG_LAST_TAG] =
{
  [TG_CONFIG] sizeof(struct config_node),
  [TG_SERVE_CONTROL_ACCESS] sizeof(struct access_node),
  [TG_IP] sizeof(struct ip_node),
};

static struct xml_parse_spec serve_control_config_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = elem_sizes,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = NULL,
  .attr_free = NULL,
};

static struct config_node *
parse_config(const unsigned char *path, const unsigned char *default_config)
{
  struct xml_tree *tree = 0, *t1, *t2;
  struct xml_attr *attr;
  struct config_node *cfg = 0;
  struct ip_node *pip;
  unsigned char **leaf_elem_addr = 0;

  if (default_config) {
    tree = xml_build_tree_str(default_config, &serve_control_config_parse_spec);
  } else {
    tree = xml_build_tree(path, &serve_control_config_parse_spec);
  }
  if (!tree) goto failed;

  xml_err_path = path;
  xml_err_spec = &serve_control_config_parse_spec;

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
      for (t2 = t1->first_down; t2; t2 = t2->right) {
        if (t2->tag != TG_IP) {
          xml_err_elem_not_allowed(t2);
          goto failed;
        }
        pip = (struct ip_node*) t2;
        pip->ssl = -1;
        for (attr = t2->first; attr; attr = attr->next) {
          if (attr->tag != AT_ALLOW && attr->tag != AT_SSL) {
            xml_err_attr_not_allowed(t2, attr);
            goto failed;
          }
          if (attr->tag == AT_SSL) {
            if (!strcasecmp(attr->text, "yes")) {
              pip->ssl = 1;
            } else if (!strcasecmp(attr->text, "no")) {
              pip->ssl = 0;
            } else if (!strcasecmp(attr->text, "any")) {
              pip->ssl = -1;
            } else {
              xml_err_attr_invalid(attr);
              goto failed;
            }
          } else {
            if (xml_attr_bool(attr, &pip->allow) < 0) goto failed;
          }
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
static ej_ip_t user_ip;
static userlist_clnt_t userlist_conn;
static ej_cookie_t session_id;
static unsigned int user_id;
static unsigned char *user_login;
static unsigned char *user_name;
static unsigned char *user_password;
static unsigned char *self_url;
static int ssl_flag;
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
  unsigned char *protocol = "http";

  if (getenv("SSL_PROTOCOL") || getenv("HTTPS")) {
    ssl_flag = 1;
    protocol = "https";
  }
  if (!http_host) http_host = "localhost";
  if (!script_name) script_name = "/cgi-bin/serve-control";
  snprintf(fullname, sizeof(fullname), "%s://%s%s", protocol, http_host, script_name);
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
    if ((user_ip & p->mask) == p->addr
        && (p->ssl == -1 || p->ssl == ssl_flag)) return p->allow;
  }
  return config->access->default_is_allow;
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
         "<td><input type=\"text\" size=16 name=\"login\"/></td>"
         "</tr>"
         "<tr>"
         "<td>%s:</td>"
         "<td><input type=\"password\" size=16 name=\"password\"/></td>"
         "</tr>"
         "<tr>"
         "<td>&nbsp;</td>"
         "<td><input type=\"submit\" value=\"%s\"/></td>"
         "</tr>"
         "</table>"
         "</form>",
         _("Login"), _("Password"), _("Submit"));
  client_put_footer(stdout, 0);
  exit(0);
}

static unsigned char * hyperref(unsigned char *, size_t,
                                ej_cookie_t,
                                const unsigned char *,
                                const char *, ...)
     __attribute__((format(printf, 5, 6)));
static unsigned char *
hyperref(unsigned char *buf, size_t size,
         ej_cookie_t sid,
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
          ej_cookie_t sid,
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
        && x > 0 && x < SSERV_CMD_LAST)
      client_action = x;
  }
  if (!client_action && (s = cgi_nname("action_", 7))) {
    n = 0; x = 0;
    if (sscanf(s, "action_%d%n", &x, &n) == 1 && !s[n]
        && x > 0 && x < SSERV_CMD_LAST)
      client_action = x;
  }

  snprintf(hidden_vars, sizeof(hidden_vars),
           "<input type=\"hidden\" name=\"SID\" value=\"%016llx\"/>",
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
    r = userlist_clnt_priv_cookie(userlist_conn, user_ip, ssl_flag,
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
  r = userlist_clnt_priv_login(userlist_conn, ULS_PRIV_LOGIN, user_ip, ssl_flag,
                               0, /* contest_id */
                               0, /* locale_id */
                               PRIV_LEVEL_ADMIN, 0,
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
  case SSERV_CMD_SERVE_MNG_PROBE_RUN:
    extra_str = ", serve probe run";
    break;
  case SSERV_CMD_VIEW_RUN_LOG:
    extra_str = ", run log";
    break;
  case SSERV_CMD_VIEW_CONTEST_XML:
    extra_str = ", contest.xml";
    break;
  case SSERV_CMD_EDIT_CONTEST_XML:
    extra_str = ", editing contest.xml";
    break;
  case SSERV_CMD_VIEW_SERVE_CFG:
    extra_str = ", serve.cfg";
    break;
  case SSERV_CMD_CHECK_TESTS:
    extra_str = ", checking contest settings";
    break;
  case SSERV_CMD_PROB_EDIT_VARIANTS:
  case SSERV_CMD_PROB_EDIT_VARIANTS_2:
    extra_str = ", editing variant map";
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

static void
action_contest_command(int cmd, int next_state)
{
  int contest_id, r;

  if ((contest_id = parse_contest_id()) <= 0) goto invalid_parameter;

  open_super_server();
  r = super_clnt_simple_cmd(super_serve_fd, cmd, contest_id);
  if (next_state) {
    operation_status_page(-1, r, "action=%d&contest_id=%d", next_state, contest_id);
  } else {
    operation_status_page(-1, r, "contest_id=%d", contest_id);
  }

 invalid_parameter:
  operation_status_page(-1, -1, "Contest view parameters are invalid");
}

static void action_create_contest(void) __attribute__((noreturn));
static void
action_create_contest(void)
{
  int r;

  open_super_server();
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    "%s: %s, creating new contest", "serve-control", user_name);
  fflush(stdout);

  r = super_clnt_main_page(super_serve_fd, 1, SSERV_CMD_CREATE_CONTEST,
                           0, 0, 0, self_url, hidden_vars, "");
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           super_proto_strerror(-r));
  }
  client_put_footer(stdout, 0);
  exit(0);
}

static void action_edit_current_contest(int cmd) __attribute__((noreturn));
static void
action_edit_current_contest(int cmd)
{
  int r;

  open_super_server();
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    "%s: %s, editing contest", "serve-control", user_name);
  fflush(stdout);

  r = super_clnt_main_page(super_serve_fd, 1, cmd,
                           0, 0, 0, self_url, hidden_vars, "");
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           super_proto_strerror(-r));
  }
  client_put_footer(stdout, 0);
  exit(0);
}

static void action_edit_permissions(void) __attribute__((noreturn));
static void
action_edit_permissions(void)
{
  char *s;
  int num, n, r;

  if (!(s = cgi_param("num"))
      || sscanf(s, "%d%n", &num, &n) != 1
      || s[n]
      || num < 0 || num >= 100000)
    goto invalid_parameter;

  open_super_server();
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    "%s: %s, editing permissions for contest", "serve-control",
                    user_name);
  fflush(stdout);

  r = super_clnt_main_page(super_serve_fd, 1, SSERV_CMD_CNTS_EDIT_PERMISSION,
                           0, 0, num, self_url, hidden_vars, "");
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           super_proto_strerror(-r));
  }
  client_put_footer(stdout, 0);
  exit(0);

 invalid_parameter:
  operation_status_page(-1, -1, "Contest view parameters are invalid");
}

static void action_create_contest_2(void) __attribute__((noreturn));
static void
action_create_contest_2(void)
{
  int r, n;
  unsigned char *s;
  int num_mode, templ_mode, contest_id = 0, templ_id = 0;

  if (!(s = cgi_param("num_mode"))
      || sscanf(s, "%d%n", &num_mode, &n) != 1
      || s[n]
      || num_mode < 0 || num_mode > 1)
    goto invalid_parameter;
  if (!(s = cgi_param("templ_mode"))
      || sscanf(s, "%d%n", &templ_mode, &n) != 1
      || s[n]
      || templ_mode < 0 || templ_mode > 1)
    goto invalid_parameter;
  if (num_mode) {
    if (!(s = cgi_param("contest_id"))
        || sscanf(s, "%d%n", &contest_id, &n) != 1
        || s[n]
        || contest_id <= 0 || contest_id > 999999)
      goto invalid_parameter;
  }
  if (templ_mode) {
    if (!(s = cgi_param("templ_id"))
        || sscanf(s, "%d%n", &templ_id, &n) != 1
        || s[n]
        || templ_id <= 0 || templ_id > 999999)
      goto invalid_parameter;
  }

  open_super_server();
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    "%s: %s, editing new contest", "serve-control", user_name);
  fflush(stdout);

  r = super_clnt_create_contest(super_serve_fd, 1, SSERV_CMD_CREATE_CONTEST_2,
                                num_mode, templ_mode, contest_id, templ_id,
                                self_url, hidden_vars, "");
  if (r < 0) {
    printf("<h2><font color=\"red\">%s</font></h2>\n",
           super_proto_strerror(-r));
  }

  client_put_footer(stdout, 0);
  exit(0);

 invalid_parameter:
  operation_status_page(-1, -1, "Contest creation parameters are invalid");
}

static void action_simple_top_command(int cmd) __attribute__((noreturn));
static void
action_simple_top_command(int cmd)
{
  int r;

  open_super_server();
  r = super_clnt_simple_cmd(super_serve_fd, cmd, 0);
  operation_status_page(-1, r, "");
}

static void action_simple_edit_command(int, int) __attribute__((noreturn));
static void action_simple_edit_command(int cmd, int next_state)
{
  int r;

  open_super_server();
  r = super_clnt_simple_cmd(super_serve_fd, cmd, 0);
  if (next_state) {
    operation_status_page(-1, r, "action=%d", next_state);
  } else {
    operation_status_page(-1, r, "");
  }
}

static void action_set_param(int, int) __attribute__((noreturn));
static void
action_set_param(int cmd, int next_state)
{
  int r;
  unsigned char *param = cgi_param("param");

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, 0, param, 0, 0, 0);
  if (next_state) {
    operation_status_page(-1, r, "action=%d", next_state);
  } else {
    operation_status_page(-1, r, "");
  }
}

static void action_set_date_param(int cmd, int nextstate) __attribute__((noreturn));
static void
action_set_date_param(int cmd, int nextstate)
{
  int r;
  unsigned char *d_hour = cgi_param("d_hour");
  unsigned char *d_min = cgi_param("d_min");
  unsigned char *d_sec = cgi_param("d_sec");
  unsigned char *d_mday = cgi_param("d_mday");
  unsigned char *d_mon = cgi_param("d_mon");
  unsigned char *d_year = cgi_param("d_year");
  unsigned char buf[182];

  if (!d_hour) d_hour = "0";
  if (!d_min) d_min = "0";
  if (!d_sec) d_sec = "0";
  if (!d_mday) d_mday = "1";
  if (!d_mon) d_mon = "1";
  if (!d_year) d_year = "2001";
  snprintf(buf, sizeof(buf), "%s/%s/%s %s:%s:%s",
           d_year, d_mon, d_mday, d_hour, d_min, d_sec);

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, 0, buf, 0, 0, 0);
  if (nextstate) {
    operation_status_page(-1, r, "action=%d", nextstate);
  } else {
    operation_status_page(-1, r, "");
  }
}

static const int ip_param_next_state[] =
{
  SSERV_CMD_EDIT_REGISTER_ACCESS,
  SSERV_CMD_EDIT_USERS_ACCESS,
  SSERV_CMD_EDIT_MASTER_ACCESS,
  SSERV_CMD_EDIT_JUDGE_ACCESS,
  SSERV_CMD_EDIT_TEAM_ACCESS,
  SSERV_CMD_EDIT_SERVE_CONTROL_ACCESS,
};

static void action_set_ip_param(int cmd) __attribute__((noreturn));
static void
action_set_ip_param(int cmd)
{
  unsigned char *s;
  int r = 0, n;
  int acc_mode;
  int access = -1;
  int rule_num = -1;
  int ssl = -1;
  unsigned char *ip_str = cgi_param("ip");

  if (!(s = cgi_param("acc_mode")) || sscanf(s, "%d%n", &acc_mode, &n) != 1
      || s[n] || acc_mode < 0 || acc_mode > 5)
    goto invalid_parameter;
  if ((s = cgi_param("access"))) {
    if (sscanf(s, "%d%n", &access, &n) != 1 || s[n] || access < 0 || access > 1)
      goto invalid_parameter;
  }
  if ((s = cgi_param("ssl"))) {
    if (sscanf(s, "%d%n", &ssl, &n) != 1 || s[n] || ssl < -1 || ssl > 1)
      goto invalid_parameter;
  }
  if ((s = cgi_param("rule_num"))) {
    if (sscanf(s, "%d%n", &rule_num, &n) != 1 || s[n] || rule_num < 0)
      goto invalid_parameter;
  }
  if (!ip_str) ip_str = "";

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, acc_mode, ip_str, access, rule_num,ssl);
  operation_status_page(-1, r, "action=%d", ip_param_next_state[acc_mode]);

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void action_copy_ip_param(int cmd) __attribute__((noreturn));
static void
action_copy_ip_param(int cmd)
{
  unsigned char *s;
  int acc_mode, templ_id, acc_from, n, r;

  if (!(s = cgi_param("acc_mode")) || sscanf(s, "%d%n", &acc_mode, &n) != 1
      || s[n] || acc_mode < 0 || acc_mode > 5)
    goto invalid_parameter;
  if (!(s = cgi_param("templ_id")) || sscanf(s, "%d%n", &templ_id, &n) != 1
      || s[n] || templ_id < 0 || templ_id >= 1000000)
    goto invalid_parameter;
  if (!(s = cgi_param("acc_from")) || sscanf(s, "%d%n", &acc_from, &n) != 1
      || s[n] || acc_from < 0 || acc_from > 5)
    goto invalid_parameter;

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, acc_mode, 0, templ_id, acc_from, 0);
  operation_status_page(-1, r, "action=%d", ip_param_next_state[acc_mode]);

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static const unsigned char * const predef_sets[4] =
{
// 0000000000111111111122222222223333333333444444444455555555556666
// 0123456789012345678901234567890123456789012345678901234567890123
  "0000000000000000000000000000000000000000000000000000000000000000", // none
  "0100100100000000000111111000000000000000000000000000000000000000", // observ
  "0110100110000000001111111001100100000000000000000000000000000000", // judge
  "1111111111111111111111111111111110000000000000000000000000000000", // master
};

static void action_perform_permission_op(int, int) __attribute__((noreturn));
static void
action_perform_permission_op(int cmd, int next_state)
{
  int num = -1, n, r, setnum;
  unsigned char *s;
  unsigned char *param = 0;
  unsigned char varbuf[64];

  if (cmd == SSERV_CMD_CNTS_ADD_PERMISSION) {
    if (!(param = cgi_param("param")) || !*param)
      goto invalid_parameter;
  } else {
    if (!(s = cgi_param("num")) || sscanf(s, "%d%n", &num, &n) != 1 || s[n] || num < 0)
      goto invalid_parameter;
  }
  if (cmd == SSERV_CMD_CNTS_SET_PREDEF_PERMISSIONS) {
    if (!(param = cgi_param("param")) || !*param
        || sscanf(param, "%d%n", &setnum, &n) != 1
        || param[n] || setnum < 0 || setnum > 3)
      goto invalid_parameter;
    cmd = SSERV_CMD_CNTS_SAVE_PERMISSIONS;
    param = (unsigned char*) predef_sets[setnum];
  } else if (cmd == SSERV_CMD_CNTS_SAVE_PERMISSIONS) {
    param = alloca(65);
    memset(param, '0', 64);
    param[64] = 0;
    for (n = 0; n < 64; n++) {
      snprintf(varbuf, sizeof(varbuf), "cap_%d", n);
      if (cgi_param(varbuf)) param[n] = '1';
    }
  }

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, num, param, 0, 0, 0);
  operation_status_page(-1, r, "action=%d", next_state);

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void action_save_form_fields(int, int) __attribute__((noreturn));
static void
action_save_form_fields(int cmd, int next_state)
{
  unsigned char *s;
  int min_count = -1, max_count = -1, init_count = -1, n, i, total_fields, f, r;
  unsigned char varname[64];
  unsigned char *fields_str = 0;

  if ((s = cgi_param("min_count"))) {
    if (sscanf(s, "%d%n", &min_count, &n) != 1 || s[n]
        || min_count < 0 || min_count > 5)
      goto invalid_parameter;
  }
  if ((s = cgi_param("max_count"))) {
    if (sscanf(s, "%d%n", &max_count, &n) != 1 || s[n]
        || max_count < 0 || max_count > 5)
      goto invalid_parameter;
  }
  if ((s = cgi_param("init_count"))) {
    if (sscanf(s, "%d%n", &init_count, &n) != 1 || s[n]
        || max_count < 0 || init_count > 5)
      goto invalid_parameter;
  }

  for (total_fields = 1; ;total_fields++) {
    snprintf(varname, sizeof(varname), "field_%d", total_fields);
    if (!cgi_param(varname)) break;
  }
  fields_str = alloca(total_fields + 1);
  memset(fields_str, '0', total_fields);
  fields_str[total_fields] = 0;
  for (i = 1; i < total_fields; i++) {
    snprintf(varname, sizeof(varname), "field_%d", i);
    if (!(s = cgi_param(varname)) || sscanf(s, "%d%n", &f, &n) != 1 || s[n]
        || f < 0 || f > 2)
      goto invalid_parameter;
    fields_str[i] = '0' + f;
  }

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, init_count, fields_str,
                           min_count, max_count, 0);
  operation_status_page(-1, r, "action=%d", next_state);

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void
action_lang_cmd(int cmd, int next_state)
{
  int lang_id, n, r;
  unsigned char *s;
  unsigned char *param = cgi_param("param");

  if (!(s = cgi_param("lang_id")) || sscanf(s, "%d%n", &lang_id, &n) != 1
      || s[n] || lang_id <= 0 || lang_id > 999999) goto invalid_parameter;

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, lang_id, param, 0, 0, 0);
  if (next_state) {
    operation_status_page(-1, r, "action=%d", next_state);
  } else {
    operation_status_page(-1, r, "");
  }

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void
action_prob_cmd(int cmd, int next_state)
{
  int prob_id, n, r;
  unsigned char *s;

  if (!(s = cgi_param("prob_id")) || sscanf(s, "%d%n", &prob_id, &n) != 1
      || s[n] || prob_id < -999999 || prob_id > 999999)
    goto invalid_parameter;

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, prob_id, 0, 0, 0, 0);
  if (next_state) {
    operation_status_page(-1, r, "action=%d", next_state);
  } else {
    operation_status_page(-1, r, "");
  }

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void
action_prob_param(int cmd, int next_state)
{
  int prob_id, n, r;
  unsigned char *s;
  unsigned char *param = cgi_param("param");

  if (!(s = cgi_param("prob_id")) || sscanf(s, "%d%n", &prob_id, &n) != 1
      || s[n] || prob_id < -999999 || prob_id > 999999)
    goto invalid_parameter;

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, prob_id, param, 0, 0, 0);
  if (next_state) {
    operation_status_page(-1, r, "action=%d", next_state);
  } else {
    operation_status_page(-1, r, "");
  }

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void
action_variant_param(int cmd, int next_state) __attribute__((noreturn));
static void
action_variant_param(int cmd, int next_state)
{
  int row, n, r, total = 0, i;
  unsigned char *s;
  unsigned char nbuf[64];
  char *param_txt = 0;
  FILE *param_f = 0;
  size_t param_len = 0;

  if (!(s = cgi_param("row")) || sscanf(s, "%d%n", &row, &n) != 1
      || s[n] || row < 0 || row > 999999)
    goto invalid_parameter;

  // collect all param_<NUM> into a single string
  total = -1;
  do {
    total++;
    snprintf(nbuf, sizeof(nbuf), "param_%d", total);
  } while (cgi_param(nbuf));

  param_f = open_memstream(&param_txt, &param_len);
  fprintf(param_f, "%d", total);
  for (i = 0; i < total; i++) {
    snprintf(nbuf, sizeof(nbuf), "param_%d", i);
    if (!(s = cgi_param(nbuf)) || sscanf(s, "%d%n", &r, &n) != 1
        || s[n] || r < 0 || r > 999999)
      goto invalid_parameter;
    fprintf(param_f, " %d", r);
  }
  fclose(param_f);
  while (param_len > 0 && isspace(param_txt[param_len - 1])) param_txt[--param_len]=0;

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, row, param_txt, 0, 0, 0);
  xfree(param_txt);
  if (next_state) {
    operation_status_page(-1, r, "action=%d", next_state);
  } else {
    operation_status_page(-1, r, "");
  }

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void
action_prob_date_param(int cmd, int next_state) __attribute__((noreturn));
static void
action_prob_date_param(int cmd, int next_state)
{
  int prob_id, n, r;
  unsigned char *s;
  unsigned char *d_hour = cgi_param("d_hour");
  unsigned char *d_min = cgi_param("d_min");
  unsigned char *d_sec = cgi_param("d_sec");
  unsigned char *d_mday = cgi_param("d_mday");
  unsigned char *d_mon = cgi_param("d_mon");
  unsigned char *d_year = cgi_param("d_year");
  unsigned char buf[256];

  if (!(s = cgi_param("prob_id")) || sscanf(s, "%d%n", &prob_id, &n) != 1
      || s[n] || prob_id < -999999 || prob_id > 999999)
    goto invalid_parameter;

  if (!d_hour) d_hour = "0";
  if (!d_min) d_min = "0";
  if (!d_sec) d_sec = "0";
  if (!d_mday) d_mday = "1";
  if (!d_mon) d_mon = "1";
  if (!d_year) d_year = "2001";
  snprintf(buf, sizeof(buf), "%s/%s/%s %s:%s:%s",
           d_year, d_mon, d_mday, d_hour, d_min, d_sec);

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, prob_id, buf, 0, 0, 0);
  if (next_state) {
    operation_status_page(-1, r, "action=%d", next_state);
  } else {
    operation_status_page(-1, r, "");
  }

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void
action_prob_add_abstract(int cmd, int next_state)
{
  unsigned char *s;
  int r;

  if (!(s = cgi_param("prob_name"))) goto invalid_parameter;

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, 0, s, 0, 0, 0);
  operation_status_page(-1, r, "action=%d", next_state);

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void
action_prob_add(int cmd, int next_state)
{
  unsigned char *s;
  int prob_id = 0, n;
  int r;

  if ((s = cgi_param("prob_id")) && *s) {
    if (sscanf(s, "%d%n", &prob_id, &n) != 1 || s[n]
        || prob_id < 0 || prob_id > 999999)
      goto invalid_parameter;
  }

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, prob_id, 0, 0, 0, 0);
  operation_status_page(-1, r, "action=%d", next_state);

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static const int next_action_map[SSERV_CMD_LAST] =
{
  [SSERV_CMD_OPEN_CONTEST] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_CLOSE_CONTEST] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_CLEAR_MESSAGES] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_VISIBLE_CONTEST] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_INVISIBLE_CONTEST] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_SERVE_LOG_TRUNC] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_SERVE_LOG_DEV_NULL] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_SERVE_LOG_FILE] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_LOG_TRUNC] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_LOG_DEV_NULL] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_LOG_FILE] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_SERVE_MNG_TERM] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_MNG_TERM] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_CONTEST_RESTART] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_SERVE_MNG_RESET_ERROR] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_MNG_RESET_ERROR] = SSERV_CMD_CONTEST_PAGE,

  [SSERV_CMD_CNTS_BASIC_VIEW] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_ADVANCED_VIEW] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_HIDE_HTML_HEADERS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SHOW_HTML_HEADERS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_HIDE_HTML_ATTRS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SHOW_HTML_ATTRS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_HIDE_PATHS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SHOW_PATHS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_HIDE_NOTIFICATIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SHOW_NOTIFICATIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_HIDE_ACCESS_RULES] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SHOW_ACCESS_RULES] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_HIDE_PERMISSIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SHOW_PERMISSIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_HIDE_FORM_FIELDS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SHOW_FORM_FIELDS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_NAME] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_NAME_EN] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_MAIN_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_DEADLINE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_TEAM_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_PRIV_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_COPYRIGHT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_HEAD_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_PAR_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_VERB_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT_EN] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND_EN] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_HEAD_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_PAR_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_TABLE_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_NAME_COMMENT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_ALLOWED_LANGUAGES] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_ALLOWED_REGIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_CF_NOTIFY_EMAIL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_CLAR_NOTIFY_EMAIL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_DAILY_STAT_EMAIL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_TEAM_HEAD_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_TEAM_PAR_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE_OPTIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_TEAM_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_STANDINGS_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_PROBLEMS_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_ROOT_DIR] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_CONF_DIR] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_PRIV_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_COPYRIGHT_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_NAME] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_NAME_EN] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_MAIN_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_AUTOREGISTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_SIMPLE_REGISTRATION] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_ASSIGN_LOGINS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_FORCE_REGISTRATION] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_DISABLE_NAME] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_ENABLE_FORGOT_PASSWORD] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_EXAM_MODE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_DISABLE_LOCALE_CHANGE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_PERSONAL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_SEND_PASSWD_EMAIL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_MANAGED] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_NEW_MANAGED] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_RUN_MANAGED] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_CLEAN_USERS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_CLOSED] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_INVISIBLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_TIME_SKEW] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_TEAM_LOGIN] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_DEADLINE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_REGISTER_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_REGISTER_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_TEAM_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_TEAM_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_PRIV_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_PRIV_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_COPYRIGHT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_HEAD_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_PAR_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_VERB_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT_EN] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND_EN] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_REGISTER_HEAD_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_REGISTER_PAR_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_REGISTER_TABLE_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_REGISTER_NAME_COMMENT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_ALLOWED_LANGUAGES] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_ALLOWED_REGIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_CF_NOTIFY_EMAIL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_CLAR_NOTIFY_EMAIL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_DAILY_STAT_EMAIL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_TEAM_HEAD_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_TEAM_PAR_STYLE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_REGISTER_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE_OPTIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL_FILE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_TEAM_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_STANDINGS_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_PROBLEMS_URL] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_ROOT_DIR] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_CONF_DIR] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_DIR_MODE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_DIR_GROUP] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_FILE_MODE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CHANGE_FILE_GROUP] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_DIR_MODE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_DIR_GROUP] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_FILE_MODE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_FILE_GROUP] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_DELETE_PERMISSION] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_ADD_PERMISSION] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_PERMISSIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SET_PREDEF_PERMISSIONS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_FORM_FIELDS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_COACH_FIELDS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_GUEST_FIELDS] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_USERS_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_USERS_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_REGISTER_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_REGISTER_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_TEAM_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_TEAM_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_PRIV_HEADER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_PRIV_FOOTER] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_COPYRIGHT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_SAVE_REGISTER_EMAIL_FILE] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_PRIV_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_COPYRIGHT_TEXT] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT] =SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT] = SSERV_CMD_CNTS_EDIT_USERS_HEADER,
  [SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT] = SSERV_CMD_CNTS_EDIT_USERS_FOOTER,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT] = SSERV_CMD_CNTS_EDIT_REGISTER_HEADER,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT] = SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER,
  [SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT] = SSERV_CMD_CNTS_EDIT_TEAM_HEADER,
  [SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT] = SSERV_CMD_CNTS_EDIT_TEAM_FOOTER,
  [SSERV_CMD_CNTS_CLEAR_PRIV_HEADER_TEXT] = SSERV_CMD_CNTS_EDIT_TEAM_HEADER,
  [SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER_TEXT] = SSERV_CMD_CNTS_EDIT_TEAM_FOOTER,
  [SSERV_CMD_CNTS_CLEAR_COPYRIGHT_TEXT] = SSERV_CMD_CNTS_EDIT_COPYRIGHT,
  [SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT] = SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE,
  [SSERV_CMD_GLOB_SHOW_1] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_HIDE_1] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SHOW_2] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_HIDE_2] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SHOW_3] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_HIDE_3] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SHOW_4] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_HIDE_4] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SHOW_5] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_HIDE_5] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SHOW_6] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_HIDE_6] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SHOW_7] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_HIDE_7] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_LANG_SHOW_DETAILS] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_HIDE_DETAILS] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_DEACTIVATE] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_ACTIVATE] = SSERV_CMD_EDIT_CURRENT_LANG,

  [SSERV_CMD_LANG_CHANGE_DISABLED] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_CHANGE_LONG_NAME] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_CLEAR_LONG_NAME] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_CHANGE_CONTENT_TYPE] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_CLEAR_CONTENT_TYPE] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_CHANGE_DISABLE_AUTO_TESTING] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_CHANGE_DISABLE_TESTING] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_CHANGE_BINARY] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_CHANGE_OPTS] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SSERV_CMD_LANG_CLEAR_OPTS] = SSERV_CMD_EDIT_CURRENT_LANG,

  [SSERV_CMD_PROB_ADD] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_ADD_ABSTRACT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_SHOW_DETAILS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_HIDE_DETAILS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_SHOW_ADVANCED] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_HIDE_ADVANCED] = SSERV_CMD_EDIT_CURRENT_PROB,

  [SSERV_CMD_PROB_DELETE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_SHORT_NAME] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_SHORT_NAME] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_LONG_NAME] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_LONG_NAME] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_SUPER] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TYPE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_SCORING_CHECKER] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_MANUAL_CHECKING] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_EXAMINATOR_NUM] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_CHECK_PRESENTATION] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_USE_STDIN] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_USE_STDOUT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_BINARY_INPUT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_IGNORE_EXIT_CODE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TIME_LIMIT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TIME_LIMIT_MILLIS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_REAL_TIME_LIMIT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_REP_VIEW] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_CE_VIEW] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_DISABLE_USER_SUBMIT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_DISABLE_SUBMIT_AFTER_OK] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_DISABLE_TESTING] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_DISABLE_AUTO_TESTING] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_ENABLE_COMPILATION] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_FULL_SCORE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TEST_SCORE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_RUN_PENALTY] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_ACM_RUN_PENALTY] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_DISQUALIFIED_PENALTY] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_VARIABLE_FULL_SCORE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TEST_SCORE_LIST] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_TEST_SCORE_LIST] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_SCORE_TESTS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_SCORE_TESTS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TESTS_TO_ACCEPT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_ACCEPT_PARTIAL] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_MIN_TESTS_TO_ACCEPT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_HIDDEN] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_STAND_HIDE_TIME] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_ADVANCE_TO_NEXT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_MAX_VM_SIZE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_MAX_STACK_SIZE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_INPUT_FILE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_INPUT_FILE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_OUTPUT_FILE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_OUTPUT_FILE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_USE_CORR] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_USE_INFO] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TEST_DIR] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_TEST_DIR] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_CORR_DIR] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_CORR_DIR] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_INFO_DIR] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_INFO_DIR] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TEST_SFX] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_TEST_SFX] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TEST_PAT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_TEST_PAT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_CORR_SFX] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_CORR_SFX] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_CORR_PAT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_CORR_PAT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_INFO_SFX] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_INFO_SFX] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_INFO_PAT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_INFO_PAT] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_STANDARD_CHECKER] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_SCORE_BONUS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_SCORE_BONUS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_CHECK_CMD] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_CHECK_CMD] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_CHECKER_ENV] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_CHECKER_ENV] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ_MILLIS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ_MILLIS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_DISABLE_LANGUAGE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_DISABLE_LANGUAGE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_ENABLE_LANGUAGE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_ENABLE_LANGUAGE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_REQUIRE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_REQUIRE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_TEST_SETS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_TEST_SETS] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_START_DATE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_START_DATE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_DEADLINE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_DEADLINE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_VARIANT_NUM] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_EDIT_VARIANTS] = SSERV_CMD_PROB_EDIT_VARIANTS,
  [SSERV_CMD_PROB_EDIT_VARIANTS_2] = SSERV_CMD_PROB_EDIT_VARIANTS_2,
  [SSERV_CMD_PROB_CHANGE_VARIANTS] = SSERV_CMD_PROB_EDIT_VARIANTS_2,
  [SSERV_CMD_PROB_DELETE_VARIANTS] = SSERV_CMD_PROB_EDIT_VARIANTS_2,
  [SSERV_CMD_PROB_CLEAR_VARIANTS] = SSERV_CMD_PROB_EDIT_VARIANTS_2,
  [SSERV_CMD_PROB_RANDOM_VARIANTS] = SSERV_CMD_PROB_EDIT_VARIANTS_2,
  [SSERV_CMD_PROB_CHANGE_STATEMENT_FILE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_STATEMENT_FILE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_ALTERNATIVES_FILE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_ALTERNATIVES_FILE] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CHANGE_STAND_ATTR] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SSERV_CMD_PROB_CLEAR_STAND_ATTR] = SSERV_CMD_EDIT_CURRENT_PROB,

  [SSERV_CMD_GLOB_CHANGE_DURATION] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_UNLIMITED_DURATION] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_TYPE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_FOG_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_UNFOG_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_DISABLE_FOG] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_LOCALE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_SRC_VIEW] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_REP_VIEW] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_CE_VIEW] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_JUDGE_REPORT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_DISABLE_CLARS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_DISABLE_TEAM_CLARS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_IGNORE_COMPILE_ERRORS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_IGNORE_DUPICATED_RUNS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_REPORT_ERROR_CODE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_SHOW_DEADLINE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_PRINTING] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_DISABLE_BANNER_PAGE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_PRUNE_EMPTY_USERS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_FULL_ARCHIVE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ALWAYS_SHOW_PROBLEMS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_DISABLE_USER_STANDINGS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_PROBLEM_NAVIGATION] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_TEST_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_TEST_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_CORR_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_CORR_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_INFO_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_INFO_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_TGZ_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_TGZ_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_CHECKER_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_CHECKER_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STATEMENT_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STATEMENT_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_DESCRIPTION_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_DESCRIPTION_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_CONTEST_START_CMD] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_MAX_RUN_SIZE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_MAX_RUN_TOTAL] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_MAX_RUN_NUM] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_MAX_CLAR_SIZE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_MAX_CLAR_TOTAL] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_MAX_CLAR_NUM] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_TEAM_PAGE_QUOTA] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_TEAM_INFO_URL] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_TEAM_INFO_URL] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_PROB_INFO_URL] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_PROB_INFO_URL] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_FILE_NAME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_FILE_NAME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_USERS_ON_PAGE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_HEADER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_HEADER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_FOOTER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_SYMLINK_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_SYMLINK_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_IGNORE_AFTER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_IGNORE_AFTER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_APPEAL_DEADLINE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_APPEAL_DEADLINE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_CONTEST_FINISH_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_CONTEST_FINISH_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_STAND2] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND2_FILE_NAME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND2_FILE_NAME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND2_HEADER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND2_FOOTER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND2_SYMLINK_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND2_SYMLINK_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_PLOG] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_PLOG_FILE_NAME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_PLOG_FILE_NAME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_PLOG_HEADER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_PLOG_FOOTER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_FILE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_PLOG_SYMLINK_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_PLOG_SYMLINK_DIR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_PLOG_UPDATE_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_EXTERNAL_XML_UPDATE_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_INTERNAL_XML_UPDATE_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_TABLE_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_TABLE_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_PLACE_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_PLACE_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_TEAM_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_TEAM_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_PROB_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_PROB_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_SOLVED_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_SOLVED_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_SCORE_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_SCORE_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_PENALTY_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_PENALTY_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_SHOW_OK_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_SHOW_ATT_NUM] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_SORT_BY_SOLVED] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_IGNORE_SUCCESS_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_TIME_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_TIME_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_SUCCESS_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_SUCCESS_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_FAIL_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_FAIL_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_TRANS_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_TRANS_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_SELF_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_SELF_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_V_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_V_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_R_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_R_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_U_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_U_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_EXTRA_COL] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_FORMAT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_FORMAT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_LEGEND] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_LEGEND] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_SLEEP_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_SERVE_SLEEP_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_AUTOUPDATE_STANDINGS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ROUNDING_MODE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_MAX_FILE_LENGTH] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_MAX_LINE_LENGTH] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_INACTIVITY_TIMEOUT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_TESTING] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_DISABLE_TESTING] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_CR_SERIALIZATION_KEY] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_SHOW_ASTR_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_CONTINUE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_REPORT_UPLOAD] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_RUNLOG_MERGE] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_USE_COMPILATION_SERVER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_SECURE_RUN] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_CUR_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_PAGE_CUR_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_PAGE_ROW_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_COL_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_PAGE_COL_ATTR] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_ENABLE_L10N] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_CHARSET] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_CHARSET] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_DISABLE_TEAM_DOWNLOAD_TIME] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CHANGE_CPU_BOGOMIPS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_DETECT_CPU_BOGOMIPS] = SSERV_CMD_EDIT_CURRENT_GLOBAL,

  [SSERV_CMD_GLOB_SAVE_CONTEST_START_CMD] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD,
  [SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SAVE_STAND_HEADER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT] = SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE,
  [SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SAVE_STAND_FOOTER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT] = SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE,
  [SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SAVE_STAND2_HEADER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT] = SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE,
  [SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SAVE_STAND2_FOOTER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT] = SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE,
  [SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SAVE_PLOG_HEADER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT] = SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE,
  [SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_SAVE_PLOG_FOOTER] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT] = SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE,
  [SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SSERV_CMD_LANG_UPDATE_VERSIONS] = SSERV_CMD_EDIT_CURRENT_LANG,
};

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
  case SSERV_CMD_CONTEST_PAGE:
    action_view_contest(SSERV_CMD_CONTEST_PAGE);
    break;
  case SSERV_CMD_SERVE_MNG_PROBE_RUN:
    action_view_contest(SSERV_CMD_SERVE_MNG_PROBE_RUN);
    break;
  case SSERV_CMD_VIEW_SERVE_LOG:
    action_view_contest(SSERV_CMD_VIEW_SERVE_LOG);
    break;
  case SSERV_CMD_VIEW_RUN_LOG:
    action_view_contest(SSERV_CMD_VIEW_RUN_LOG);
    break;
  case SSERV_CMD_VIEW_CONTEST_XML:
    action_view_contest(SSERV_CMD_VIEW_CONTEST_XML);
    break;
  case SSERV_CMD_VIEW_SERVE_CFG:
    action_view_contest(SSERV_CMD_VIEW_SERVE_CFG);
    break;

  case SSERV_CMD_OPEN_CONTEST:
  case SSERV_CMD_CLOSE_CONTEST:
  case SSERV_CMD_CLEAR_MESSAGES:
  case SSERV_CMD_VISIBLE_CONTEST:
  case SSERV_CMD_INVISIBLE_CONTEST:
  case SSERV_CMD_SERVE_LOG_TRUNC:
  case SSERV_CMD_SERVE_LOG_DEV_NULL:
  case SSERV_CMD_SERVE_LOG_FILE:
  case SSERV_CMD_RUN_LOG_TRUNC:
  case SSERV_CMD_RUN_LOG_DEV_NULL:
  case SSERV_CMD_RUN_LOG_FILE:
  case SSERV_CMD_SERVE_MNG_TERM:
  case SSERV_CMD_RUN_MNG_TERM:
  case SSERV_CMD_CONTEST_RESTART:
  case SSERV_CMD_SERVE_MNG_RESET_ERROR:
  case SSERV_CMD_RUN_MNG_RESET_ERROR:
    action_contest_command(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_HIDE_HIDDEN:
    action_simple_top_command(SSERV_CMD_HIDE_HIDDEN);
    break;
  case SSERV_CMD_SHOW_HIDDEN:
    action_simple_top_command(SSERV_CMD_SHOW_HIDDEN);
    break;
  case SSERV_CMD_HIDE_CLOSED:
    action_simple_top_command(SSERV_CMD_HIDE_CLOSED);
    break;
  case SSERV_CMD_SHOW_CLOSED:
    action_simple_top_command(SSERV_CMD_SHOW_CLOSED);
    break;
  case SSERV_CMD_HIDE_UNMNG:
    action_simple_top_command(SSERV_CMD_HIDE_UNMNG);
    break;
  case SSERV_CMD_SHOW_UNMNG:
    action_simple_top_command(SSERV_CMD_SHOW_UNMNG);
    break;
  case SSERV_CMD_CREATE_CONTEST:
    action_create_contest();
    break;
  case SSERV_CMD_CREATE_CONTEST_2:
    action_create_contest_2();
    break;

  case SSERV_CMD_EDIT_CURRENT_CONTEST:
  case SSERV_CMD_EDIT_REGISTER_ACCESS:
  case SSERV_CMD_EDIT_USERS_ACCESS:
  case SSERV_CMD_EDIT_MASTER_ACCESS:
  case SSERV_CMD_EDIT_JUDGE_ACCESS:
  case SSERV_CMD_EDIT_TEAM_ACCESS:
  case SSERV_CMD_EDIT_SERVE_CONTROL_ACCESS:
  case SSERV_CMD_CNTS_EDIT_FORM_FIELDS:
  case SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS:
  case SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS:
  case SSERV_CMD_CNTS_EDIT_COACH_FIELDS:
  case SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS:
  case SSERV_CMD_CNTS_EDIT_GUEST_FIELDS:
  case SSERV_CMD_CNTS_EDIT_USERS_HEADER:
  case SSERV_CMD_CNTS_EDIT_USERS_FOOTER:
  case SSERV_CMD_CNTS_EDIT_REGISTER_HEADER:
  case SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER:
  case SSERV_CMD_CNTS_EDIT_TEAM_HEADER:
  case SSERV_CMD_CNTS_EDIT_TEAM_FOOTER:
  case SSERV_CMD_CNTS_EDIT_PRIV_HEADER:
  case SSERV_CMD_CNTS_EDIT_PRIV_FOOTER:
  case SSERV_CMD_CNTS_EDIT_COPYRIGHT:
  case SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE:
  case SSERV_CMD_CNTS_COMMIT:
  case SSERV_CMD_EDIT_CURRENT_GLOBAL:
  case SSERV_CMD_EDIT_CURRENT_LANG:
  case SSERV_CMD_EDIT_CURRENT_PROB:
  case SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD:
  case SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE:
  case SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE:
  case SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE:
  case SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE:
  case SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE:
  case SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE:
  case SSERV_CMD_VIEW_NEW_SERVE_CFG:
  case SSERV_CMD_PROB_EDIT_VARIANTS:
  case SSERV_CMD_PROB_EDIT_VARIANTS_2:
    action_edit_current_contest(client_action);
    break;
  case SSERV_CMD_CNTS_FORGET:
    action_simple_top_command(client_action);
    break;
  case SSERV_CMD_CHECK_TESTS:
  case SSERV_CMD_EDIT_CONTEST_XML:
    action_view_contest(client_action);
    break;
  case SSERV_CMD_CNTS_EDIT_PERMISSION:
    action_edit_permissions();
    break;

  case SSERV_CMD_CNTS_CHANGE_NAME:
  case SSERV_CMD_CNTS_CHANGE_NAME_EN:
  case SSERV_CMD_CNTS_CHANGE_MAIN_URL:
  case SSERV_CMD_CNTS_CHANGE_AUTOREGISTER:
  case SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD:
  case SSERV_CMD_CNTS_CHANGE_SIMPLE_REGISTRATION:
  case SSERV_CMD_CNTS_CHANGE_ASSIGN_LOGINS:
  case SSERV_CMD_CNTS_CHANGE_FORCE_REGISTRATION:
  case SSERV_CMD_CNTS_CHANGE_DISABLE_NAME:
  case SSERV_CMD_CNTS_CHANGE_ENABLE_FORGOT_PASSWORD:
  case SSERV_CMD_CNTS_CHANGE_EXAM_MODE:
  case SSERV_CMD_CNTS_CHANGE_DISABLE_LOCALE_CHANGE:
  case SSERV_CMD_CNTS_CHANGE_PERSONAL:
  case SSERV_CMD_CNTS_CHANGE_SEND_PASSWD_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_MANAGED:
  case SSERV_CMD_CNTS_CHANGE_NEW_MANAGED:
  case SSERV_CMD_CNTS_CHANGE_RUN_MANAGED:
  case SSERV_CMD_CNTS_CHANGE_CLEAN_USERS:
  case SSERV_CMD_CNTS_CHANGE_CLOSED:
  case SSERV_CMD_CNTS_CHANGE_INVISIBLE:
  case SSERV_CMD_CNTS_CHANGE_TIME_SKEW:
  case SSERV_CMD_CNTS_CHANGE_TEAM_LOGIN:
  case SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE:
  case SSERV_CMD_CNTS_CHANGE_USERS_HEADER:
  case SSERV_CMD_CNTS_CHANGE_USERS_FOOTER:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_HEADER:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_FOOTER:
  case SSERV_CMD_CNTS_CHANGE_TEAM_HEADER:
  case SSERV_CMD_CNTS_CHANGE_TEAM_FOOTER:
  case SSERV_CMD_CNTS_CHANGE_PRIV_HEADER:
  case SSERV_CMD_CNTS_CHANGE_PRIV_FOOTER:
  case SSERV_CMD_CNTS_CHANGE_COPYRIGHT:
  case SSERV_CMD_CNTS_CHANGE_USERS_HEAD_STYLE:
  case SSERV_CMD_CNTS_CHANGE_USERS_PAR_STYLE:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_STYLE:
  case SSERV_CMD_CNTS_CHANGE_USERS_VERB_STYLE:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT_EN:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND:
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND_EN:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_HEAD_STYLE:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_PAR_STYLE:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_TABLE_STYLE:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_NAME_COMMENT:
  case SSERV_CMD_CNTS_CHANGE_ALLOWED_LANGUAGES:
  case SSERV_CMD_CNTS_CHANGE_ALLOWED_REGIONS:
  case SSERV_CMD_CNTS_CHANGE_CF_NOTIFY_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_CLAR_NOTIFY_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_DAILY_STAT_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_TEAM_HEAD_STYLE:
  case SSERV_CMD_CNTS_CHANGE_TEAM_PAR_STYLE:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_URL:
  case SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE:
  case SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE_OPTIONS:
  case SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL_FILE:
  case SSERV_CMD_CNTS_CHANGE_TEAM_URL:
  case SSERV_CMD_CNTS_CHANGE_STANDINGS_URL:
  case SSERV_CMD_CNTS_CHANGE_PROBLEMS_URL:
  case SSERV_CMD_CNTS_CHANGE_ROOT_DIR:
  case SSERV_CMD_CNTS_CHANGE_CONF_DIR:
  case SSERV_CMD_CNTS_CHANGE_DIR_MODE:
  case SSERV_CMD_CNTS_CHANGE_DIR_GROUP:
  case SSERV_CMD_CNTS_CHANGE_FILE_MODE:
  case SSERV_CMD_CNTS_CHANGE_FILE_GROUP:
  case SSERV_CMD_CNTS_SAVE_USERS_HEADER:
  case SSERV_CMD_CNTS_SAVE_USERS_FOOTER:
  case SSERV_CMD_CNTS_SAVE_REGISTER_HEADER:
  case SSERV_CMD_CNTS_SAVE_REGISTER_FOOTER:
  case SSERV_CMD_CNTS_SAVE_TEAM_HEADER:
  case SSERV_CMD_CNTS_SAVE_TEAM_FOOTER:
  case SSERV_CMD_CNTS_SAVE_PRIV_HEADER:
  case SSERV_CMD_CNTS_SAVE_PRIV_FOOTER:
  case SSERV_CMD_CNTS_SAVE_COPYRIGHT:
  case SSERV_CMD_CNTS_SAVE_REGISTER_EMAIL_FILE:
    action_set_param(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_CNTS_CHANGE_DEADLINE:
  case SSERV_CMD_GLOB_CHANGE_STAND_IGNORE_AFTER:
  case SSERV_CMD_GLOB_CHANGE_APPEAL_DEADLINE:
  case SSERV_CMD_GLOB_CHANGE_CONTEST_FINISH_TIME:
    action_set_date_param(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_CNTS_DEFAULT_ACCESS:
  case SSERV_CMD_CNTS_ADD_RULE:
  case SSERV_CMD_CNTS_CHANGE_RULE:
  case SSERV_CMD_CNTS_DELETE_RULE:
  case SSERV_CMD_CNTS_UP_RULE:
  case SSERV_CMD_CNTS_DOWN_RULE:
    action_set_ip_param(client_action);
    break;

  case SSERV_CMD_CNTS_COPY_ACCESS:
    action_copy_ip_param(client_action);
    break;

  case SSERV_CMD_CNTS_DELETE_PERMISSION:
  case SSERV_CMD_CNTS_ADD_PERMISSION:
  case SSERV_CMD_CNTS_SAVE_PERMISSIONS:
  case SSERV_CMD_CNTS_SET_PREDEF_PERMISSIONS:
    action_perform_permission_op(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_CNTS_SAVE_FORM_FIELDS:
  case SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS:
  case SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS:
  case SSERV_CMD_CNTS_SAVE_COACH_FIELDS:
  case SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS:
  case SSERV_CMD_CNTS_SAVE_GUEST_FIELDS:
    action_save_form_fields(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_CNTS_BASIC_VIEW:
  case SSERV_CMD_CNTS_ADVANCED_VIEW:
  case SSERV_CMD_CNTS_HIDE_HTML_HEADERS:
  case SSERV_CMD_CNTS_SHOW_HTML_HEADERS:
  case SSERV_CMD_CNTS_HIDE_HTML_ATTRS:
  case SSERV_CMD_CNTS_SHOW_HTML_ATTRS:
  case SSERV_CMD_CNTS_HIDE_PATHS:
  case SSERV_CMD_CNTS_SHOW_PATHS:
  case SSERV_CMD_CNTS_HIDE_NOTIFICATIONS:
  case SSERV_CMD_CNTS_SHOW_NOTIFICATIONS:
  case SSERV_CMD_CNTS_HIDE_ACCESS_RULES:
  case SSERV_CMD_CNTS_SHOW_ACCESS_RULES:
  case SSERV_CMD_CNTS_HIDE_PERMISSIONS:
  case SSERV_CMD_CNTS_SHOW_PERMISSIONS:
  case SSERV_CMD_CNTS_HIDE_FORM_FIELDS:
  case SSERV_CMD_CNTS_SHOW_FORM_FIELDS:
  case SSERV_CMD_CNTS_CLEAR_NAME:
  case SSERV_CMD_CNTS_CLEAR_NAME_EN:
  case SSERV_CMD_CNTS_CLEAR_MAIN_URL:
  case SSERV_CMD_CNTS_CLEAR_DEADLINE:
  case SSERV_CMD_CNTS_CLEAR_USERS_HEADER:
  case SSERV_CMD_CNTS_CLEAR_USERS_FOOTER:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER:
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEADER:
  case SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER:
  case SSERV_CMD_CNTS_CLEAR_PRIV_HEADER:
  case SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER:
  case SSERV_CMD_CNTS_CLEAR_COPYRIGHT:
  case SSERV_CMD_CNTS_CLEAR_USERS_HEAD_STYLE:
  case SSERV_CMD_CNTS_CLEAR_USERS_PAR_STYLE:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_STYLE:
  case SSERV_CMD_CNTS_CLEAR_USERS_VERB_STYLE:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT_EN:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND:
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND_EN:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEAD_STYLE:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_PAR_STYLE:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_TABLE_STYLE:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_NAME_COMMENT:
  case SSERV_CMD_CNTS_CLEAR_ALLOWED_LANGUAGES:
  case SSERV_CMD_CNTS_CLEAR_ALLOWED_REGIONS:
  case SSERV_CMD_CNTS_CLEAR_CF_NOTIFY_EMAIL:
  case SSERV_CMD_CNTS_CLEAR_CLAR_NOTIFY_EMAIL:
  case SSERV_CMD_CNTS_CLEAR_DAILY_STAT_EMAIL:
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEAD_STYLE:
  case SSERV_CMD_CNTS_CLEAR_TEAM_PAR_STYLE:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_URL:
  case SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE:
  case SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE_OPTIONS:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE:
  case SSERV_CMD_CNTS_CLEAR_TEAM_URL:
  case SSERV_CMD_CNTS_CLEAR_STANDINGS_URL:
  case SSERV_CMD_CNTS_CLEAR_PROBLEMS_URL:
  case SSERV_CMD_CNTS_CLEAR_ROOT_DIR:
  case SSERV_CMD_CNTS_CLEAR_CONF_DIR:
  case SSERV_CMD_CNTS_CLEAR_DIR_MODE:
  case SSERV_CMD_CNTS_CLEAR_DIR_GROUP:
  case SSERV_CMD_CNTS_CLEAR_FILE_MODE:
  case SSERV_CMD_CNTS_CLEAR_FILE_GROUP:
  case SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_PRIV_HEADER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER_TEXT:
  case SSERV_CMD_CNTS_CLEAR_COPYRIGHT_TEXT:
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT:
  case SSERV_CMD_GLOB_SHOW_1:
  case SSERV_CMD_GLOB_HIDE_1:
  case SSERV_CMD_GLOB_SHOW_2:
  case SSERV_CMD_GLOB_HIDE_2:
  case SSERV_CMD_GLOB_SHOW_3:
  case SSERV_CMD_GLOB_HIDE_3:
  case SSERV_CMD_GLOB_SHOW_4:
  case SSERV_CMD_GLOB_HIDE_4:
  case SSERV_CMD_GLOB_SHOW_5:
  case SSERV_CMD_GLOB_HIDE_5:
  case SSERV_CMD_GLOB_SHOW_6:
  case SSERV_CMD_GLOB_HIDE_6:
  case SSERV_CMD_GLOB_SHOW_7:
  case SSERV_CMD_GLOB_HIDE_7:
  case SSERV_CMD_LANG_UPDATE_VERSIONS:
    action_simple_edit_command(client_action, next_action_map[client_action]);
    break;
  case SSERV_CMD_LANG_SHOW_DETAILS:
  case SSERV_CMD_LANG_HIDE_DETAILS:
  case SSERV_CMD_LANG_DEACTIVATE:
  case SSERV_CMD_LANG_ACTIVATE:
  case SSERV_CMD_LANG_CHANGE_DISABLED:
  case SSERV_CMD_LANG_CHANGE_LONG_NAME:
  case SSERV_CMD_LANG_CLEAR_LONG_NAME:
  case SSERV_CMD_LANG_CHANGE_CONTENT_TYPE:
  case SSERV_CMD_LANG_CLEAR_CONTENT_TYPE:
  case SSERV_CMD_LANG_CHANGE_DISABLE_AUTO_TESTING:
  case SSERV_CMD_LANG_CHANGE_DISABLE_TESTING:
  case SSERV_CMD_LANG_CHANGE_BINARY:
  case SSERV_CMD_LANG_CHANGE_OPTS:
  case SSERV_CMD_LANG_CLEAR_OPTS:
    action_lang_cmd(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_PROB_ADD:
    action_prob_add(client_action, next_action_map[client_action]);
    break;
  case SSERV_CMD_PROB_ADD_ABSTRACT:
    action_prob_add_abstract(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_PROB_SHOW_DETAILS:
  case SSERV_CMD_PROB_HIDE_DETAILS:
  case SSERV_CMD_PROB_SHOW_ADVANCED:
  case SSERV_CMD_PROB_HIDE_ADVANCED:
    action_prob_cmd(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_PROB_DELETE:
  case SSERV_CMD_PROB_CHANGE_SHORT_NAME:
  case SSERV_CMD_PROB_CLEAR_SHORT_NAME:
  case SSERV_CMD_PROB_CHANGE_LONG_NAME:
  case SSERV_CMD_PROB_CLEAR_LONG_NAME:
  case SSERV_CMD_PROB_CHANGE_SUPER:
  case SSERV_CMD_PROB_CHANGE_TYPE:
  case SSERV_CMD_PROB_CHANGE_SCORING_CHECKER:
  case SSERV_CMD_PROB_CHANGE_MANUAL_CHECKING:
  case SSERV_CMD_PROB_CHANGE_EXAMINATOR_NUM:
  case SSERV_CMD_PROB_CHANGE_CHECK_PRESENTATION:
  case SSERV_CMD_PROB_CHANGE_USE_STDIN:
  case SSERV_CMD_PROB_CHANGE_USE_STDOUT:
  case SSERV_CMD_PROB_CHANGE_BINARY_INPUT:
  case SSERV_CMD_PROB_CHANGE_IGNORE_EXIT_CODE:
  case SSERV_CMD_PROB_CHANGE_TIME_LIMIT:
  case SSERV_CMD_PROB_CHANGE_TIME_LIMIT_MILLIS:
  case SSERV_CMD_PROB_CHANGE_REAL_TIME_LIMIT:
  case SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_REP_VIEW:
  case SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_CE_VIEW:
  case SSERV_CMD_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT:
  case SSERV_CMD_PROB_CHANGE_DISABLE_USER_SUBMIT:
  case SSERV_CMD_PROB_CHANGE_DISABLE_SUBMIT_AFTER_OK:
  case SSERV_CMD_PROB_CHANGE_DISABLE_TESTING:
  case SSERV_CMD_PROB_CHANGE_DISABLE_AUTO_TESTING:
  case SSERV_CMD_PROB_CHANGE_ENABLE_COMPILATION:
  case SSERV_CMD_PROB_CHANGE_FULL_SCORE:
  case SSERV_CMD_PROB_CHANGE_TEST_SCORE:
  case SSERV_CMD_PROB_CHANGE_RUN_PENALTY:
  case SSERV_CMD_PROB_CHANGE_ACM_RUN_PENALTY:
  case SSERV_CMD_PROB_CHANGE_DISQUALIFIED_PENALTY:
  case SSERV_CMD_PROB_CHANGE_VARIABLE_FULL_SCORE:
  case SSERV_CMD_PROB_CHANGE_TEST_SCORE_LIST:
  case SSERV_CMD_PROB_CLEAR_TEST_SCORE_LIST:
  case SSERV_CMD_PROB_CHANGE_SCORE_TESTS:
  case SSERV_CMD_PROB_CLEAR_SCORE_TESTS:
  case SSERV_CMD_PROB_CHANGE_TESTS_TO_ACCEPT:
  case SSERV_CMD_PROB_CHANGE_ACCEPT_PARTIAL:
  case SSERV_CMD_PROB_CHANGE_MIN_TESTS_TO_ACCEPT:
  case SSERV_CMD_PROB_CHANGE_HIDDEN:
  case SSERV_CMD_PROB_CHANGE_STAND_HIDE_TIME:
  case SSERV_CMD_PROB_CHANGE_ADVANCE_TO_NEXT:
  case SSERV_CMD_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT:
  case SSERV_CMD_PROB_CHANGE_MAX_VM_SIZE:
  case SSERV_CMD_PROB_CHANGE_MAX_STACK_SIZE:
  case SSERV_CMD_PROB_CHANGE_INPUT_FILE:
  case SSERV_CMD_PROB_CLEAR_INPUT_FILE:
  case SSERV_CMD_PROB_CHANGE_OUTPUT_FILE:
  case SSERV_CMD_PROB_CLEAR_OUTPUT_FILE:
  case SSERV_CMD_PROB_CHANGE_USE_CORR:
  case SSERV_CMD_PROB_CHANGE_USE_INFO:
  case SSERV_CMD_PROB_CHANGE_TEST_DIR:
  case SSERV_CMD_PROB_CLEAR_TEST_DIR:
  case SSERV_CMD_PROB_CHANGE_CORR_DIR:
  case SSERV_CMD_PROB_CLEAR_CORR_DIR:
  case SSERV_CMD_PROB_CHANGE_INFO_DIR:
  case SSERV_CMD_PROB_CLEAR_INFO_DIR:
  case SSERV_CMD_PROB_CHANGE_TEST_SFX:
  case SSERV_CMD_PROB_CLEAR_TEST_SFX:
  case SSERV_CMD_PROB_CHANGE_TEST_PAT:
  case SSERV_CMD_PROB_CLEAR_TEST_PAT:
  case SSERV_CMD_PROB_CHANGE_CORR_SFX:
  case SSERV_CMD_PROB_CLEAR_CORR_SFX:
  case SSERV_CMD_PROB_CHANGE_CORR_PAT:
  case SSERV_CMD_PROB_CLEAR_CORR_PAT:
  case SSERV_CMD_PROB_CHANGE_INFO_SFX:
  case SSERV_CMD_PROB_CLEAR_INFO_SFX:
  case SSERV_CMD_PROB_CHANGE_INFO_PAT:
  case SSERV_CMD_PROB_CLEAR_INFO_PAT:
  case SSERV_CMD_PROB_CHANGE_STANDARD_CHECKER:
  case SSERV_CMD_PROB_CHANGE_SCORE_BONUS:
  case SSERV_CMD_PROB_CLEAR_SCORE_BONUS:
  case SSERV_CMD_PROB_CHANGE_CHECK_CMD:
  case SSERV_CMD_PROB_CLEAR_CHECK_CMD:
  case SSERV_CMD_PROB_CHANGE_CHECKER_ENV:
  case SSERV_CMD_PROB_CLEAR_CHECKER_ENV:
  case SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ:
  case SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ:
  case SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ_MILLIS:
  case SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ_MILLIS:
  case SSERV_CMD_PROB_CHANGE_DISABLE_LANGUAGE:
  case SSERV_CMD_PROB_CLEAR_DISABLE_LANGUAGE:
  case SSERV_CMD_PROB_CHANGE_ENABLE_LANGUAGE:
  case SSERV_CMD_PROB_CLEAR_ENABLE_LANGUAGE:
  case SSERV_CMD_PROB_CHANGE_REQUIRE:
  case SSERV_CMD_PROB_CLEAR_REQUIRE:
  case SSERV_CMD_PROB_CHANGE_TEST_SETS:
  case SSERV_CMD_PROB_CLEAR_TEST_SETS:
  case SSERV_CMD_PROB_CLEAR_START_DATE:
  case SSERV_CMD_PROB_CLEAR_DEADLINE:
  case SSERV_CMD_PROB_CHANGE_VARIANT_NUM:
  case SSERV_CMD_PROB_CHANGE_STATEMENT_FILE:
  case SSERV_CMD_PROB_CLEAR_STATEMENT_FILE:
  case SSERV_CMD_PROB_CHANGE_ALTERNATIVES_FILE:
  case SSERV_CMD_PROB_CLEAR_ALTERNATIVES_FILE:
  case SSERV_CMD_PROB_CLEAR_VARIANTS:
  case SSERV_CMD_PROB_RANDOM_VARIANTS:
  case SSERV_CMD_PROB_CHANGE_STAND_ATTR:
  case SSERV_CMD_PROB_CLEAR_STAND_ATTR:
    action_prob_param(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_PROB_CHANGE_START_DATE:
  case SSERV_CMD_PROB_CHANGE_DEADLINE:
    action_prob_date_param(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_GLOB_CHANGE_DURATION:
  case SSERV_CMD_GLOB_UNLIMITED_DURATION:
  case SSERV_CMD_GLOB_CHANGE_TYPE:
  case SSERV_CMD_GLOB_CHANGE_FOG_TIME:
  case SSERV_CMD_GLOB_CHANGE_UNFOG_TIME:
  case SSERV_CMD_GLOB_DISABLE_FOG:
  case SSERV_CMD_GLOB_CHANGE_STAND_LOCALE:
  case SSERV_CMD_GLOB_CHANGE_SRC_VIEW:
  case SSERV_CMD_GLOB_CHANGE_REP_VIEW:
  case SSERV_CMD_GLOB_CHANGE_CE_VIEW:
  case SSERV_CMD_GLOB_CHANGE_JUDGE_REPORT:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_CLARS:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_TEAM_CLARS:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK:
  case SSERV_CMD_GLOB_CHANGE_IGNORE_COMPILE_ERRORS:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW:
  case SSERV_CMD_GLOB_CHANGE_IGNORE_DUPICATED_RUNS:
  case SSERV_CMD_GLOB_CHANGE_REPORT_ERROR_CODE:
  case SSERV_CMD_GLOB_CHANGE_SHOW_DEADLINE:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_PRINTING:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_BANNER_PAGE:
  case SSERV_CMD_GLOB_CHANGE_PRUNE_EMPTY_USERS:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_FULL_ARCHIVE:
  case SSERV_CMD_GLOB_CHANGE_ALWAYS_SHOW_PROBLEMS:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_USER_STANDINGS:
  case SSERV_CMD_GLOB_CHANGE_PROBLEM_NAVIGATION:
  case SSERV_CMD_GLOB_CHANGE_TEST_DIR:
  case SSERV_CMD_GLOB_CLEAR_TEST_DIR:
  case SSERV_CMD_GLOB_CHANGE_CORR_DIR:
  case SSERV_CMD_GLOB_CLEAR_CORR_DIR:
  case SSERV_CMD_GLOB_CHANGE_INFO_DIR:
  case SSERV_CMD_GLOB_CLEAR_INFO_DIR:
  case SSERV_CMD_GLOB_CHANGE_TGZ_DIR:
  case SSERV_CMD_GLOB_CLEAR_TGZ_DIR:
  case SSERV_CMD_GLOB_CHANGE_CHECKER_DIR:
  case SSERV_CMD_GLOB_CLEAR_CHECKER_DIR:
  case SSERV_CMD_GLOB_CHANGE_STATEMENT_DIR:
  case SSERV_CMD_GLOB_CLEAR_STATEMENT_DIR:
  case SSERV_CMD_GLOB_CHANGE_DESCRIPTION_FILE:
  case SSERV_CMD_GLOB_CLEAR_DESCRIPTION_FILE:
  case SSERV_CMD_GLOB_CHANGE_CONTEST_START_CMD:
  case SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD:
  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_SIZE:
  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_TOTAL:
  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_NUM:
  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_SIZE:
  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_TOTAL:
  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_NUM:
  case SSERV_CMD_GLOB_CHANGE_TEAM_PAGE_QUOTA:
  case SSERV_CMD_GLOB_CHANGE_TEAM_INFO_URL:
  case SSERV_CMD_GLOB_CLEAR_TEAM_INFO_URL:
  case SSERV_CMD_GLOB_CHANGE_PROB_INFO_URL:
  case SSERV_CMD_GLOB_CLEAR_PROB_INFO_URL:
  case SSERV_CMD_GLOB_CHANGE_STAND_FILE_NAME:
  case SSERV_CMD_GLOB_CLEAR_STAND_FILE_NAME:
  case SSERV_CMD_GLOB_CHANGE_USERS_ON_PAGE:
  case SSERV_CMD_GLOB_CHANGE_STAND_HEADER_FILE:
  case SSERV_CMD_GLOB_CLEAR_STAND_HEADER_FILE:
  case SSERV_CMD_GLOB_CHANGE_STAND_FOOTER_FILE:
  case SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_FILE:
  case SSERV_CMD_GLOB_CHANGE_STAND_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CLEAR_STAND_IGNORE_AFTER:
  case SSERV_CMD_GLOB_CLEAR_APPEAL_DEADLINE:
  case SSERV_CMD_GLOB_CLEAR_CONTEST_FINISH_TIME:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_STAND2:
  case SSERV_CMD_GLOB_CHANGE_STAND2_FILE_NAME:
  case SSERV_CMD_GLOB_CLEAR_STAND2_FILE_NAME:
  case SSERV_CMD_GLOB_CHANGE_STAND2_HEADER_FILE:
  case SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_FILE:
  case SSERV_CMD_GLOB_CHANGE_STAND2_FOOTER_FILE:
  case SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_FILE:
  case SSERV_CMD_GLOB_CHANGE_STAND2_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CLEAR_STAND2_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_PLOG:
  case SSERV_CMD_GLOB_CHANGE_PLOG_FILE_NAME:
  case SSERV_CMD_GLOB_CLEAR_PLOG_FILE_NAME:
  case SSERV_CMD_GLOB_CHANGE_PLOG_HEADER_FILE:
  case SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_FILE:
  case SSERV_CMD_GLOB_CHANGE_PLOG_FOOTER_FILE:
  case SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_FILE:
  case SSERV_CMD_GLOB_CHANGE_PLOG_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CLEAR_PLOG_SYMLINK_DIR:
  case SSERV_CMD_GLOB_CHANGE_PLOG_UPDATE_TIME:
  case SSERV_CMD_GLOB_CHANGE_EXTERNAL_XML_UPDATE_TIME:
  case SSERV_CMD_GLOB_CHANGE_INTERNAL_XML_UPDATE_TIME:
  case SSERV_CMD_GLOB_CHANGE_STAND_TABLE_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_TABLE_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PLACE_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PLACE_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_TEAM_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_TEAM_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PROB_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PROB_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SOLVED_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SOLVED_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SCORE_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SCORE_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PENALTY_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PENALTY_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_OK_TIME:
  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_ATT_NUM:
  case SSERV_CMD_GLOB_CHANGE_STAND_SORT_BY_SOLVED:
  case SSERV_CMD_GLOB_CHANGE_IGNORE_SUCCESS_TIME:
  case SSERV_CMD_GLOB_CHANGE_STAND_TIME_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_TIME_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SUCCESS_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SUCCESS_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_FAIL_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_FAIL_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_TRANS_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_TRANS_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SELF_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_SELF_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_V_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_V_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_R_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_R_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_U_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_U_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_EXTRA_COL:
  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_FORMAT:
  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_FORMAT:
  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_LEGEND:
  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_LEGEND:
  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER:
  case SSERV_CMD_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR:
  case SSERV_CMD_GLOB_CHANGE_SLEEP_TIME:
  case SSERV_CMD_GLOB_CHANGE_SERVE_SLEEP_TIME:
  case SSERV_CMD_GLOB_CHANGE_AUTOUPDATE_STANDINGS:
  case SSERV_CMD_GLOB_CHANGE_ROUNDING_MODE:
  case SSERV_CMD_GLOB_CHANGE_MAX_FILE_LENGTH:
  case SSERV_CMD_GLOB_CHANGE_MAX_LINE_LENGTH:
  case SSERV_CMD_GLOB_CHANGE_INACTIVITY_TIMEOUT:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_TESTING:
  case SSERV_CMD_GLOB_CHANGE_DISABLE_TESTING:
  case SSERV_CMD_GLOB_CHANGE_CR_SERIALIZATION_KEY:
  case SSERV_CMD_GLOB_CHANGE_SHOW_ASTR_TIME:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_CONTINUE:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_REPORT_UPLOAD:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_RUNLOG_MERGE:
  case SSERV_CMD_GLOB_CHANGE_USE_COMPILATION_SERVER:
  case SSERV_CMD_GLOB_CHANGE_SECURE_RUN:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR:
  case SSERV_CMD_GLOB_CHANGE_STAND_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_CUR_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_CUR_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_ROW_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_ROW_ATTR:
  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_COL_ATTR:
  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_COL_ATTR:
  case SSERV_CMD_GLOB_CHANGE_ENABLE_L10N:
  case SSERV_CMD_GLOB_CHANGE_CHARSET:
  case SSERV_CMD_GLOB_CLEAR_CHARSET:
  case SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME:
  case SSERV_CMD_GLOB_DISABLE_TEAM_DOWNLOAD_TIME:
  case SSERV_CMD_GLOB_CHANGE_CPU_BOGOMIPS:
  case SSERV_CMD_GLOB_DETECT_CPU_BOGOMIPS:

  case SSERV_CMD_GLOB_SAVE_CONTEST_START_CMD:
  case SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT:
  case SSERV_CMD_GLOB_SAVE_STAND_HEADER:
  case SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT:
  case SSERV_CMD_GLOB_SAVE_STAND_FOOTER:
  case SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT:
  case SSERV_CMD_GLOB_SAVE_STAND2_HEADER:
  case SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT:
  case SSERV_CMD_GLOB_SAVE_STAND2_FOOTER:
  case SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT:
  case SSERV_CMD_GLOB_SAVE_PLOG_HEADER:
  case SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT:
  case SSERV_CMD_GLOB_SAVE_PLOG_FOOTER:
  case SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT:
    action_set_param(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_PROB_CHANGE_VARIANTS:
  case SSERV_CMD_PROB_DELETE_VARIANTS:
    action_variant_param(client_action, next_action_map[client_action]);
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

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
