/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ispras.ru> */

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
#include "super_actions.h"

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
    tree = xml_build_tree(path, elem_map, attr_map, elem_alloc, attr_alloc);
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

  if (getenv("SSL_PROTOCOL")) {
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
  r = userlist_clnt_priv_login(userlist_conn, user_ip, ssl_flag,
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
  SUPER_ACTION_CNTS_EDIT_REGISTER_ACCESS,
  SUPER_ACTION_CNTS_EDIT_USERS_ACCESS,
  SUPER_ACTION_CNTS_EDIT_MASTER_ACCESS,
  SUPER_ACTION_CNTS_EDIT_JUDGE_ACCESS,
  SUPER_ACTION_CNTS_EDIT_TEAM_ACCESS,
  SUPER_ACTION_CNTS_EDIT_SERVE_CONTROL_ACCESS,
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

static void action_perform_permission_op(int, int) __attribute__((noreturn));
static void
action_perform_permission_op(int cmd, int next_state)
{
  int num = -1, n, r;
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
  if (cmd == SSERV_CMD_CNTS_SAVE_PERMISSIONS) {
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

static const int action_to_cmd_map[SUPER_ACTION_LAST] =
{
  [SUPER_ACTION_OPEN_CONTEST] = SSERV_CMD_OPEN_CONTEST,
  [SUPER_ACTION_CLOSE_CONTEST] = SSERV_CMD_CLOSE_CONTEST,
  [SUPER_ACTION_CLEAR_MESSAGES] = SSERV_CMD_CLEAR_MESSAGES,
  [SUPER_ACTION_CONTEST_VISIBLE] = SSERV_CMD_VISIBLE_CONTEST,
  [SUPER_ACTION_CONTEST_INVISIBLE] = SSERV_CMD_INVISIBLE_CONTEST,
  [SUPER_ACTION_SERVE_LOG_TRUNC] = SSERV_CMD_SERVE_LOG_TRUNC,
  [SUPER_ACTION_SERVE_LOG_DEV_NULL] = SSERV_CMD_SERVE_LOG_DEV_NULL,
  [SUPER_ACTION_SERVE_LOG_FILE] = SSERV_CMD_SERVE_LOG_FILE,
  [SUPER_ACTION_RUN_LOG_TRUNC] = SSERV_CMD_RUN_LOG_TRUNC,
  [SUPER_ACTION_RUN_LOG_DEV_NULL] = SSERV_CMD_RUN_LOG_DEV_NULL,
  [SUPER_ACTION_RUN_LOG_FILE] = SSERV_CMD_RUN_LOG_FILE,
  [SUPER_ACTION_SERVE_MNG_TERM] = SSERV_CMD_SERVE_MNG_TERM,
  [SUPER_ACTION_RUN_MNG_TERM] = SSERV_CMD_RUN_MNG_TERM,
  [SUPER_ACTION_CONTEST_RESTART] = SSERV_CMD_CONTEST_RESTART,
  [SUPER_ACTION_SERVE_MNG_RESET_ERROR] = SSERV_CMD_SERVE_MNG_RESET_ERROR,
  [SUPER_ACTION_RUN_MNG_RESET_ERROR] = SSERV_CMD_RUN_MNG_RESET_ERROR,

  [SUPER_ACTION_CNTS_BASIC_VIEW] = SSERV_CMD_CNTS_BASIC_VIEW,
  [SUPER_ACTION_CNTS_ADVANCED_VIEW] = SSERV_CMD_CNTS_ADVANCED_VIEW,
  [SUPER_ACTION_CNTS_HIDE_HTML_HEADERS] = SSERV_CMD_CNTS_HIDE_HTML_HEADERS,
  [SUPER_ACTION_CNTS_SHOW_HTML_HEADERS] = SSERV_CMD_CNTS_SHOW_HTML_HEADERS,
  [SUPER_ACTION_CNTS_HIDE_HTML_ATTRS] = SSERV_CMD_CNTS_HIDE_HTML_ATTRS,
  [SUPER_ACTION_CNTS_SHOW_HTML_ATTRS] = SSERV_CMD_CNTS_SHOW_HTML_ATTRS,
  [SUPER_ACTION_CNTS_FORGET] = SSERV_CMD_CNTS_FORGET,
  [SUPER_ACTION_CNTS_HIDE_PATHS] = SSERV_CMD_CNTS_HIDE_PATHS,
  [SUPER_ACTION_CNTS_SHOW_PATHS] = SSERV_CMD_CNTS_SHOW_PATHS,
  [SUPER_ACTION_CNTS_HIDE_NOTIFICATIONS] = SSERV_CMD_CNTS_HIDE_NOTIFICATIONS,
  [SUPER_ACTION_CNTS_SHOW_NOTIFICATIONS] = SSERV_CMD_CNTS_SHOW_NOTIFICATIONS,
  [SUPER_ACTION_CNTS_HIDE_ACCESS_RULES] = SSERV_CMD_CNTS_HIDE_ACCESS_RULES,
  [SUPER_ACTION_CNTS_SHOW_ACCESS_RULES] = SSERV_CMD_CNTS_SHOW_ACCESS_RULES,
  [SUPER_ACTION_EDIT_CURRENT_CONTEST] = SSERV_CMD_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_EDIT_REGISTER_ACCESS] = SSERV_CMD_EDIT_REGISTER_ACCESS,
  [SUPER_ACTION_CNTS_EDIT_USERS_ACCESS] = SSERV_CMD_EDIT_USERS_ACCESS,
  [SUPER_ACTION_CNTS_EDIT_MASTER_ACCESS] = SSERV_CMD_EDIT_MASTER_ACCESS,
  [SUPER_ACTION_CNTS_EDIT_JUDGE_ACCESS] = SSERV_CMD_EDIT_JUDGE_ACCESS,
  [SUPER_ACTION_CNTS_EDIT_TEAM_ACCESS] = SSERV_CMD_EDIT_TEAM_ACCESS,
  [SUPER_ACTION_CNTS_EDIT_SERVE_CONTROL_ACCESS] = SSERV_CMD_EDIT_SERVE_CONTROL_ACCESS,
  [SUPER_ACTION_CNTS_HIDE_PERMISSIONS] = SSERV_CMD_CNTS_HIDE_PERMISSIONS,
  [SUPER_ACTION_CNTS_SHOW_PERMISSIONS] = SSERV_CMD_CNTS_SHOW_PERMISSIONS,
  [SUPER_ACTION_EDIT_CONTEST_XML] = SSERV_CMD_EDIT_CONTEST_XML,
  [SUPER_ACTION_CHECK_TESTS] = SSERV_CMD_CHECK_TESTS,
  [SUPER_ACTION_CNTS_HIDE_FORM_FIELDS] = SSERV_CMD_CNTS_HIDE_FORM_FIELDS,
  [SUPER_ACTION_CNTS_SHOW_FORM_FIELDS] = SSERV_CMD_CNTS_SHOW_FORM_FIELDS,
  [SUPER_ACTION_CNTS_EDIT_FORM_FIELDS] = SSERV_CMD_CNTS_EDIT_FORM_FIELDS,
  [SUPER_ACTION_CNTS_EDIT_CONTESTANT_FIELDS] = SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS,
  [SUPER_ACTION_CNTS_EDIT_RESERVE_FIELDS] = SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS,
  [SUPER_ACTION_CNTS_EDIT_COACH_FIELDS] = SSERV_CMD_CNTS_EDIT_COACH_FIELDS,
  [SUPER_ACTION_CNTS_EDIT_ADVISOR_FIELDS] = SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS,
  [SUPER_ACTION_CNTS_EDIT_GUEST_FIELDS] = SSERV_CMD_CNTS_EDIT_GUEST_FIELDS,
  [SUPER_ACTION_CNTS_EDIT_USERS_HEADER] = SSERV_CMD_CNTS_EDIT_USERS_HEADER,
  [SUPER_ACTION_CNTS_EDIT_USERS_FOOTER] = SSERV_CMD_CNTS_EDIT_USERS_FOOTER,
  [SUPER_ACTION_CNTS_EDIT_REGISTER_HEADER] = SSERV_CMD_CNTS_EDIT_REGISTER_HEADER,
  [SUPER_ACTION_CNTS_EDIT_REGISTER_FOOTER] = SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER,
  [SUPER_ACTION_CNTS_EDIT_TEAM_HEADER] = SSERV_CMD_CNTS_EDIT_TEAM_HEADER,
  [SUPER_ACTION_CNTS_EDIT_TEAM_FOOTER] = SSERV_CMD_CNTS_EDIT_TEAM_FOOTER,
  [SUPER_ACTION_CNTS_EDIT_REGISTER_EMAIL_FILE] = SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE,
  [SUPER_ACTION_CNTS_CLEAR_NAME] = SSERV_CMD_CNTS_CLEAR_NAME,
  [SUPER_ACTION_CNTS_CLEAR_NAME_EN] = SSERV_CMD_CNTS_CLEAR_NAME_EN,
  [SUPER_ACTION_CNTS_CLEAR_DEADLINE] = SSERV_CMD_CNTS_CLEAR_DEADLINE,
  [SUPER_ACTION_CNTS_CLEAR_USERS_HEADER] = SSERV_CMD_CNTS_CLEAR_USERS_HEADER,
  [SUPER_ACTION_CNTS_CLEAR_USERS_FOOTER] = SSERV_CMD_CNTS_CLEAR_USERS_FOOTER,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_HEADER] = SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_FOOTER] = SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_HEADER] = SSERV_CMD_CNTS_CLEAR_TEAM_HEADER,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_FOOTER] = SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER,
  [SUPER_ACTION_CNTS_CLEAR_USERS_HEAD_STYLE] = SSERV_CMD_CNTS_CLEAR_USERS_HEAD_STYLE,
  [SUPER_ACTION_CNTS_CLEAR_USERS_PAR_STYLE] = SSERV_CMD_CNTS_CLEAR_USERS_PAR_STYLE,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_STYLE] = SSERV_CMD_CNTS_CLEAR_USERS_TABLE_STYLE,
  [SUPER_ACTION_CNTS_CLEAR_USERS_VERB_STYLE] = SSERV_CMD_CNTS_CLEAR_USERS_VERB_STYLE,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_FORMAT] = SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_FORMAT_EN] = SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT_EN,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_LEGEND] = SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_LEGEND_EN] = SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND_EN,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_HEAD_STYLE] = SSERV_CMD_CNTS_CLEAR_REGISTER_HEAD_STYLE,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_PAR_STYLE] = SSERV_CMD_CNTS_CLEAR_REGISTER_PAR_STYLE,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_TABLE_STYLE] = SSERV_CMD_CNTS_CLEAR_REGISTER_TABLE_STYLE,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_NAME_COMMENT] = SSERV_CMD_CNTS_CLEAR_REGISTER_NAME_COMMENT,
  [SUPER_ACTION_CNTS_CLEAR_ALLOWED_LANGUAGES] = SSERV_CMD_CNTS_CLEAR_ALLOWED_LANGUAGES,
  [SUPER_ACTION_CNTS_CLEAR_CF_NOTIFY_EMAIL] = SSERV_CMD_CNTS_CLEAR_CF_NOTIFY_EMAIL,
  [SUPER_ACTION_CNTS_CLEAR_CLAR_NOTIFY_EMAIL] = SSERV_CMD_CNTS_CLEAR_CLAR_NOTIFY_EMAIL,
  [SUPER_ACTION_CNTS_CLEAR_DAILY_STAT_EMAIL] = SSERV_CMD_CNTS_CLEAR_DAILY_STAT_EMAIL,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_HEAD_STYLE] = SSERV_CMD_CNTS_CLEAR_TEAM_HEAD_STYLE,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_PAR_STYLE] = SSERV_CMD_CNTS_CLEAR_TEAM_PAR_STYLE,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL] = SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_URL] = SSERV_CMD_CNTS_CLEAR_REGISTER_URL,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL_FILE] = SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_URL] = SSERV_CMD_CNTS_CLEAR_TEAM_URL,
  [SUPER_ACTION_CNTS_CLEAR_STANDINGS_URL] = SSERV_CMD_CNTS_CLEAR_STANDINGS_URL,
  [SUPER_ACTION_CNTS_CLEAR_PROBLEMS_URL] = SSERV_CMD_CNTS_CLEAR_PROBLEMS_URL,
  [SUPER_ACTION_CNTS_CLEAR_ROOT_DIR] = SSERV_CMD_CNTS_CLEAR_ROOT_DIR,
  [SUPER_ACTION_CNTS_CLEAR_CONF_DIR] = SSERV_CMD_CNTS_CLEAR_CONF_DIR,
  [SUPER_ACTION_CNTS_CHANGE_NAME] = SSERV_CMD_CNTS_CHANGE_NAME,
  [SUPER_ACTION_CNTS_CHANGE_NAME_EN] = SSERV_CMD_CNTS_CHANGE_NAME_EN,
  [SUPER_ACTION_CNTS_CHANGE_AUTOREGISTER] = SSERV_CMD_CNTS_CHANGE_AUTOREGISTER,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_PASSWD] = SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD,
  [SUPER_ACTION_CNTS_CHANGE_MANAGED] = SSERV_CMD_CNTS_CHANGE_MANAGED,
  [SUPER_ACTION_CNTS_CHANGE_RUN_MANAGED] = SSERV_CMD_CNTS_CHANGE_RUN_MANAGED,
  [SUPER_ACTION_CNTS_CHANGE_CLEAN_USERS] = SSERV_CMD_CNTS_CHANGE_CLEAN_USERS,
  [SUPER_ACTION_CNTS_CHANGE_CLOSED] = SSERV_CMD_CNTS_CHANGE_CLOSED,
  [SUPER_ACTION_CNTS_CHANGE_INVISIBLE] = SSERV_CMD_CNTS_CHANGE_INVISIBLE,
  [SUPER_ACTION_CNTS_CHANGE_TIME_SKEW] = SSERV_CMD_CNTS_CHANGE_TIME_SKEW,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_LOGIN] = SSERV_CMD_CNTS_CHANGE_TEAM_LOGIN,
  [SUPER_ACTION_CNTS_CHANGE_MEMBER_DELETE] = SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE,
  [SUPER_ACTION_CNTS_CHANGE_DEADLINE] = SSERV_CMD_CNTS_CHANGE_DEADLINE,
  [SUPER_ACTION_CNTS_CHANGE_USERS_HEADER] = SSERV_CMD_CNTS_CHANGE_USERS_HEADER,
  [SUPER_ACTION_CNTS_CHANGE_USERS_FOOTER] = SSERV_CMD_CNTS_CHANGE_USERS_FOOTER,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_HEADER] = SSERV_CMD_CNTS_CHANGE_REGISTER_HEADER,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_FOOTER] = SSERV_CMD_CNTS_CHANGE_REGISTER_FOOTER,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_HEADER] = SSERV_CMD_CNTS_CHANGE_TEAM_HEADER,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_FOOTER] = SSERV_CMD_CNTS_CHANGE_TEAM_FOOTER,
  [SUPER_ACTION_CNTS_CHANGE_USERS_HEAD_STYLE] = SSERV_CMD_CNTS_CHANGE_USERS_HEAD_STYLE,
  [SUPER_ACTION_CNTS_CHANGE_USERS_PAR_STYLE] = SSERV_CMD_CNTS_CHANGE_USERS_PAR_STYLE,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_STYLE] = SSERV_CMD_CNTS_CHANGE_USERS_TABLE_STYLE,
  [SUPER_ACTION_CNTS_CHANGE_USERS_VERB_STYLE] = SSERV_CMD_CNTS_CHANGE_USERS_VERB_STYLE,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_FORMAT] = SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_FORMAT_EN] = SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT_EN,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_LEGEND] = SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_LEGEND_EN] = SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND_EN,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_HEAD_STYLE] = SSERV_CMD_CNTS_CHANGE_REGISTER_HEAD_STYLE,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_PAR_STYLE] = SSERV_CMD_CNTS_CHANGE_REGISTER_PAR_STYLE,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_TABLE_STYLE] = SSERV_CMD_CNTS_CHANGE_REGISTER_TABLE_STYLE,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_NAME_COMMENT] = SSERV_CMD_CNTS_CHANGE_REGISTER_NAME_COMMENT,
  [SUPER_ACTION_CNTS_CHANGE_ALLOWED_LANGUAGES] = SSERV_CMD_CNTS_CHANGE_ALLOWED_LANGUAGES,
  [SUPER_ACTION_CNTS_CHANGE_CF_NOTIFY_EMAIL] = SSERV_CMD_CNTS_CHANGE_CF_NOTIFY_EMAIL,
  [SUPER_ACTION_CNTS_CHANGE_CLAR_NOTIFY_EMAIL] = SSERV_CMD_CNTS_CHANGE_CLAR_NOTIFY_EMAIL,
  [SUPER_ACTION_CNTS_CHANGE_DAILY_STAT_EMAIL] = SSERV_CMD_CNTS_CHANGE_DAILY_STAT_EMAIL,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_HEAD_STYLE] = SSERV_CMD_CNTS_CHANGE_TEAM_HEAD_STYLE,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_PAR_STYLE] = SSERV_CMD_CNTS_CHANGE_TEAM_PAR_STYLE,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_EMAIL] = SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_URL] = SSERV_CMD_CNTS_CHANGE_REGISTER_URL,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_EMAIL_FILE] = SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL_FILE,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_URL] = SSERV_CMD_CNTS_CHANGE_TEAM_URL,
  [SUPER_ACTION_CNTS_CHANGE_STANDINGS_URL] = SSERV_CMD_CNTS_CHANGE_STANDINGS_URL,
  [SUPER_ACTION_CNTS_CHANGE_PROBLEMS_URL] = SSERV_CMD_CNTS_CHANGE_PROBLEMS_URL,
  [SUPER_ACTION_CNTS_CHANGE_ROOT_DIR] = SSERV_CMD_CNTS_CHANGE_ROOT_DIR,
  [SUPER_ACTION_CNTS_CHANGE_CONF_DIR] = SSERV_CMD_CNTS_CHANGE_CONF_DIR,
  [SUPER_ACTION_CNTS_DEFAULT_ACCESS] = SSERV_CMD_CNTS_DEFAULT_ACCESS,
  [SUPER_ACTION_CNTS_ADD_RULE] = SSERV_CMD_CNTS_ADD_RULE,
  [SUPER_ACTION_CNTS_CHANGE_RULE] = SSERV_CMD_CNTS_CHANGE_RULE,
  [SUPER_ACTION_CNTS_DELETE_RULE] = SSERV_CMD_CNTS_DELETE_RULE,
  [SUPER_ACTION_CNTS_UP_RULE] = SSERV_CMD_CNTS_UP_RULE,
  [SUPER_ACTION_CNTS_DOWN_RULE] = SSERV_CMD_CNTS_DOWN_RULE,
  [SUPER_ACTION_CNTS_COPY_ACCESS] = SSERV_CMD_CNTS_COPY_ACCESS,
  [SUPER_ACTION_CNTS_DELETE_PERMISSION] = SSERV_CMD_CNTS_DELETE_PERMISSION,
  [SUPER_ACTION_CNTS_ADD_PERMISSION] = SSERV_CMD_CNTS_ADD_PERMISSION,
  [SUPER_ACTION_CNTS_SAVE_PERMISSIONS] = SSERV_CMD_CNTS_SAVE_PERMISSIONS,
  [SUPER_ACTION_CNTS_SAVE_FORM_FIELDS] = SSERV_CMD_CNTS_SAVE_FORM_FIELDS,
  [SUPER_ACTION_CNTS_SAVE_CONTESTANT_FIELDS] = SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS,
  [SUPER_ACTION_CNTS_SAVE_RESERVE_FIELDS] = SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS,
  [SUPER_ACTION_CNTS_SAVE_COACH_FIELDS] = SSERV_CMD_CNTS_SAVE_COACH_FIELDS,
  [SUPER_ACTION_CNTS_SAVE_ADVISOR_FIELDS] = SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS,
  [SUPER_ACTION_CNTS_SAVE_GUEST_FIELDS] = SSERV_CMD_CNTS_SAVE_GUEST_FIELDS,
  [SUPER_ACTION_CNTS_SAVE_USERS_HEADER] = SSERV_CMD_CNTS_SAVE_USERS_HEADER,
  [SUPER_ACTION_CNTS_SAVE_USERS_FOOTER] = SSERV_CMD_CNTS_SAVE_USERS_FOOTER,
  [SUPER_ACTION_CNTS_SAVE_REGISTER_HEADER] = SSERV_CMD_CNTS_SAVE_REGISTER_HEADER,
  [SUPER_ACTION_CNTS_SAVE_REGISTER_FOOTER] = SSERV_CMD_CNTS_SAVE_REGISTER_FOOTER,
  [SUPER_ACTION_CNTS_SAVE_TEAM_HEADER] = SSERV_CMD_CNTS_SAVE_TEAM_HEADER,
  [SUPER_ACTION_CNTS_SAVE_TEAM_FOOTER] = SSERV_CMD_CNTS_SAVE_TEAM_FOOTER,
  [SUPER_ACTION_CNTS_SAVE_REGISTER_EMAIL_FILE] =SSERV_CMD_CNTS_SAVE_REGISTER_EMAIL_FILE,
  [SUPER_ACTION_CNTS_CLEAR_USERS_HEADER_TEXT] = SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT,
  [SUPER_ACTION_CNTS_CLEAR_USERS_FOOTER_TEXT] = SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_HEADER_TEXT] = SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_FOOTER_TEXT] = SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_HEADER_TEXT] = SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_FOOTER_TEXT] = SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT] = SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT,
  [SUPER_ACTION_CNTS_READ_USERS_HEADER] = SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT,
  [SUPER_ACTION_CNTS_READ_USERS_FOOTER] = SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT,
  [SUPER_ACTION_CNTS_READ_REGISTER_HEADER] = SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT,
  [SUPER_ACTION_CNTS_READ_REGISTER_FOOTER] = SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT,
  [SUPER_ACTION_CNTS_READ_TEAM_HEADER] = SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT,
  [SUPER_ACTION_CNTS_READ_TEAM_FOOTER] = SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT,
  [SUPER_ACTION_CNTS_READ_REGISTER_EMAIL_FILE] = SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT,
  [SUPER_ACTION_CNTS_COMMIT] = SSERV_CMD_CNTS_COMMIT,
  [SUPER_ACTION_EDIT_CURRENT_GLOBAL] = SSERV_CMD_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SHOW_1] = SSERV_CMD_GLOB_SHOW_1,
  [SUPER_ACTION_GLOB_HIDE_1] = SSERV_CMD_GLOB_HIDE_1,
  [SUPER_ACTION_GLOB_SHOW_2] = SSERV_CMD_GLOB_SHOW_2,
  [SUPER_ACTION_GLOB_HIDE_2] = SSERV_CMD_GLOB_HIDE_2,
  [SUPER_ACTION_GLOB_SHOW_3] = SSERV_CMD_GLOB_SHOW_3,
  [SUPER_ACTION_GLOB_HIDE_3] = SSERV_CMD_GLOB_HIDE_3,
  [SUPER_ACTION_GLOB_SHOW_4] = SSERV_CMD_GLOB_SHOW_4,
  [SUPER_ACTION_GLOB_HIDE_4] = SSERV_CMD_GLOB_HIDE_4,
  [SUPER_ACTION_GLOB_SHOW_5] = SSERV_CMD_GLOB_SHOW_5,
  [SUPER_ACTION_GLOB_HIDE_5] = SSERV_CMD_GLOB_HIDE_5,
  [SUPER_ACTION_GLOB_SHOW_6] = SSERV_CMD_GLOB_SHOW_6,
  [SUPER_ACTION_GLOB_HIDE_6] = SSERV_CMD_GLOB_HIDE_6,
  [SUPER_ACTION_GLOB_SHOW_7] = SSERV_CMD_GLOB_SHOW_7,
  [SUPER_ACTION_GLOB_HIDE_7] = SSERV_CMD_GLOB_HIDE_7,
  [SUPER_ACTION_EDIT_CURRENT_LANG] = SSERV_CMD_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_SHOW_DETAILS] = SSERV_CMD_LANG_SHOW_DETAILS,
  [SUPER_ACTION_LANG_HIDE_DETAILS] = SSERV_CMD_LANG_HIDE_DETAILS,
  [SUPER_ACTION_LANG_DEACTIVATE] = SSERV_CMD_LANG_DEACTIVATE,
  [SUPER_ACTION_LANG_ACTIVATE] = SSERV_CMD_LANG_ACTIVATE,

  [SUPER_ACTION_LANG_CHANGE_DISABLED] = SSERV_CMD_LANG_CHANGE_DISABLED,
  [SUPER_ACTION_LANG_CHANGE_LONG_NAME] = SSERV_CMD_LANG_CHANGE_LONG_NAME,
  [SUPER_ACTION_LANG_CLEAR_LONG_NAME] = SSERV_CMD_LANG_CLEAR_LONG_NAME,
  [SUPER_ACTION_LANG_CHANGE_DISABLE_AUTO_TESTING] = SSERV_CMD_LANG_CHANGE_DISABLE_AUTO_TESTING,
  [SUPER_ACTION_LANG_CHANGE_DISABLE_TESTING] = SSERV_CMD_LANG_CHANGE_DISABLE_TESTING,
  [SUPER_ACTION_LANG_CHANGE_OPTS] = SSERV_CMD_LANG_CHANGE_OPTS,
  [SUPER_ACTION_LANG_CLEAR_OPTS] = SSERV_CMD_LANG_CLEAR_OPTS,

  [SUPER_ACTION_EDIT_CURRENT_PROB] = SSERV_CMD_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_ADD] = SSERV_CMD_PROB_ADD,
  [SUPER_ACTION_PROB_ADD_ABSTRACT] = SSERV_CMD_PROB_ADD_ABSTRACT,
  [SUPER_ACTION_PROB_SHOW_DETAILS] = SSERV_CMD_PROB_SHOW_DETAILS,
  [SUPER_ACTION_PROB_HIDE_DETAILS] = SSERV_CMD_PROB_HIDE_DETAILS,
  [SUPER_ACTION_PROB_SHOW_ADVANCED] = SSERV_CMD_PROB_SHOW_ADVANCED,
  [SUPER_ACTION_PROB_HIDE_ADVANCED] = SSERV_CMD_PROB_HIDE_ADVANCED,

  [SUPER_ACTION_PROB_DELETE] = SSERV_CMD_PROB_DELETE,
  [SUPER_ACTION_PROB_CHANGE_SHORT_NAME] = SSERV_CMD_PROB_CHANGE_SHORT_NAME,
  [SUPER_ACTION_PROB_CLEAR_SHORT_NAME] = SSERV_CMD_PROB_CLEAR_SHORT_NAME,
  [SUPER_ACTION_PROB_CHANGE_LONG_NAME] = SSERV_CMD_PROB_CHANGE_LONG_NAME,
  [SUPER_ACTION_PROB_CLEAR_LONG_NAME] = SSERV_CMD_PROB_CLEAR_LONG_NAME,
  [SUPER_ACTION_PROB_CHANGE_SUPER] = SSERV_CMD_PROB_CHANGE_SUPER,
  [SUPER_ACTION_PROB_CHANGE_USE_STDIN] = SSERV_CMD_PROB_CHANGE_USE_STDIN,
  [SUPER_ACTION_PROB_CHANGE_USE_STDOUT] = SSERV_CMD_PROB_CHANGE_USE_STDOUT,
  [SUPER_ACTION_PROB_CHANGE_BINARY_INPUT] = SSERV_CMD_PROB_CHANGE_BINARY_INPUT,
  [SUPER_ACTION_PROB_CHANGE_TIME_LIMIT] = SSERV_CMD_PROB_CHANGE_TIME_LIMIT,
  [SUPER_ACTION_PROB_CHANGE_TIME_LIMIT_MILLIS] = SSERV_CMD_PROB_CHANGE_TIME_LIMIT_MILLIS,
  [SUPER_ACTION_PROB_CHANGE_REAL_TIME_LIMIT] = SSERV_CMD_PROB_CHANGE_REAL_TIME_LIMIT,
  [SUPER_ACTION_PROB_CHANGE_TEAM_ENABLE_REP_VIEW] = SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_REP_VIEW,
  [SUPER_ACTION_PROB_CHANGE_TEAM_ENABLE_CE_VIEW] = SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_CE_VIEW,
  [SUPER_ACTION_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT] = SSERV_CMD_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT,
  [SUPER_ACTION_PROB_CHANGE_DISABLE_TESTING] = SSERV_CMD_PROB_CHANGE_DISABLE_TESTING,
  [SUPER_ACTION_PROB_CHANGE_DISABLE_AUTO_TESTING] = SSERV_CMD_PROB_CHANGE_DISABLE_AUTO_TESTING,
  [SUPER_ACTION_PROB_CHANGE_ENABLE_COMPILATION] = SSERV_CMD_PROB_CHANGE_ENABLE_COMPILATION,
  [SUPER_ACTION_PROB_CHANGE_FULL_SCORE] = SSERV_CMD_PROB_CHANGE_FULL_SCORE,
  [SUPER_ACTION_PROB_CHANGE_TEST_SCORE] = SSERV_CMD_PROB_CHANGE_TEST_SCORE,
  [SUPER_ACTION_PROB_CHANGE_RUN_PENALTY] = SSERV_CMD_PROB_CHANGE_RUN_PENALTY,
  [SUPER_ACTION_PROB_CHANGE_DISQUALIFIED_PENALTY] = SSERV_CMD_PROB_CHANGE_DISQUALIFIED_PENALTY,
  [SUPER_ACTION_PROB_CHANGE_VARIABLE_FULL_SCORE] = SSERV_CMD_PROB_CHANGE_VARIABLE_FULL_SCORE,
  [SUPER_ACTION_PROB_CHANGE_TEST_SCORE_LIST] = SSERV_CMD_PROB_CHANGE_TEST_SCORE_LIST,
  [SUPER_ACTION_PROB_CLEAR_TEST_SCORE_LIST] = SSERV_CMD_PROB_CLEAR_TEST_SCORE_LIST,
  [SUPER_ACTION_PROB_CHANGE_SCORE_TESTS] = SSERV_CMD_PROB_CHANGE_SCORE_TESTS,
  [SUPER_ACTION_PROB_CLEAR_SCORE_TESTS] = SSERV_CMD_PROB_CLEAR_SCORE_TESTS,
  [SUPER_ACTION_PROB_CHANGE_TESTS_TO_ACCEPT] = SSERV_CMD_PROB_CHANGE_TESTS_TO_ACCEPT,
  [SUPER_ACTION_PROB_CHANGE_ACCEPT_PARTIAL] = SSERV_CMD_PROB_CHANGE_ACCEPT_PARTIAL,
  [SUPER_ACTION_PROB_CHANGE_HIDDEN] = SSERV_CMD_PROB_CHANGE_HIDDEN,
  [SUPER_ACTION_PROB_CHANGE_STAND_HIDE_TIME] = SSERV_CMD_PROB_CHANGE_STAND_HIDE_TIME,
  [SUPER_ACTION_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT] = SSERV_CMD_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT,
  [SUPER_ACTION_PROB_CHANGE_MAX_VM_SIZE] = SSERV_CMD_PROB_CHANGE_MAX_VM_SIZE,
  [SUPER_ACTION_PROB_CHANGE_MAX_STACK_SIZE] = SSERV_CMD_PROB_CHANGE_MAX_STACK_SIZE,
  [SUPER_ACTION_PROB_CHANGE_INPUT_FILE] = SSERV_CMD_PROB_CHANGE_INPUT_FILE,
  [SUPER_ACTION_PROB_CLEAR_INPUT_FILE] = SSERV_CMD_PROB_CLEAR_INPUT_FILE,
  [SUPER_ACTION_PROB_CHANGE_OUTPUT_FILE] = SSERV_CMD_PROB_CHANGE_OUTPUT_FILE,
  [SUPER_ACTION_PROB_CLEAR_OUTPUT_FILE] = SSERV_CMD_PROB_CLEAR_OUTPUT_FILE,
  [SUPER_ACTION_PROB_CHANGE_USE_CORR] = SSERV_CMD_PROB_CHANGE_USE_CORR,
  [SUPER_ACTION_PROB_CHANGE_USE_INFO] = SSERV_CMD_PROB_CHANGE_USE_INFO,
  [SUPER_ACTION_PROB_CHANGE_TEST_DIR] = SSERV_CMD_PROB_CHANGE_TEST_DIR,
  [SUPER_ACTION_PROB_CLEAR_TEST_DIR] = SSERV_CMD_PROB_CLEAR_TEST_DIR,
  [SUPER_ACTION_PROB_CHANGE_CORR_DIR] = SSERV_CMD_PROB_CHANGE_CORR_DIR,
  [SUPER_ACTION_PROB_CLEAR_CORR_DIR] = SSERV_CMD_PROB_CLEAR_CORR_DIR,
  [SUPER_ACTION_PROB_CHANGE_INFO_DIR] = SSERV_CMD_PROB_CHANGE_INFO_DIR,
  [SUPER_ACTION_PROB_CLEAR_INFO_DIR] = SSERV_CMD_PROB_CLEAR_INFO_DIR,
  [SUPER_ACTION_PROB_CHANGE_TEST_SFX] = SSERV_CMD_PROB_CHANGE_TEST_SFX,
  [SUPER_ACTION_PROB_CLEAR_TEST_SFX] = SSERV_CMD_PROB_CLEAR_TEST_SFX,
  [SUPER_ACTION_PROB_CHANGE_TEST_PAT] = SSERV_CMD_PROB_CHANGE_TEST_PAT,
  [SUPER_ACTION_PROB_CLEAR_TEST_PAT] = SSERV_CMD_PROB_CLEAR_TEST_PAT,
  [SUPER_ACTION_PROB_CHANGE_CORR_SFX] = SSERV_CMD_PROB_CHANGE_CORR_SFX,
  [SUPER_ACTION_PROB_CLEAR_CORR_SFX] = SSERV_CMD_PROB_CLEAR_CORR_SFX,
  [SUPER_ACTION_PROB_CHANGE_CORR_PAT] = SSERV_CMD_PROB_CHANGE_CORR_PAT,
  [SUPER_ACTION_PROB_CLEAR_CORR_PAT] = SSERV_CMD_PROB_CLEAR_CORR_PAT,
  [SUPER_ACTION_PROB_CHANGE_INFO_SFX] = SSERV_CMD_PROB_CHANGE_INFO_SFX,
  [SUPER_ACTION_PROB_CLEAR_INFO_SFX] = SSERV_CMD_PROB_CLEAR_INFO_SFX,
  [SUPER_ACTION_PROB_CHANGE_INFO_PAT] = SSERV_CMD_PROB_CHANGE_INFO_PAT,
  [SUPER_ACTION_PROB_CLEAR_INFO_PAT] = SSERV_CMD_PROB_CLEAR_INFO_PAT,
  [SUPER_ACTION_PROB_CHANGE_STANDARD_CHECKER] = SSERV_CMD_PROB_CHANGE_STANDARD_CHECKER,
  [SUPER_ACTION_PROB_CHANGE_SCORE_BONUS] = SSERV_CMD_PROB_CHANGE_SCORE_BONUS,
  [SUPER_ACTION_PROB_CLEAR_SCORE_BONUS] = SSERV_CMD_PROB_CLEAR_SCORE_BONUS,
  [SUPER_ACTION_PROB_CHANGE_CHECK_CMD] = SSERV_CMD_PROB_CHANGE_CHECK_CMD,
  [SUPER_ACTION_PROB_CLEAR_CHECK_CMD] = SSERV_CMD_PROB_CLEAR_CHECK_CMD,
  [SUPER_ACTION_PROB_CHANGE_CHECKER_ENV] = SSERV_CMD_PROB_CHANGE_CHECKER_ENV,
  [SUPER_ACTION_PROB_CLEAR_CHECKER_ENV] = SSERV_CMD_PROB_CLEAR_CHECKER_ENV,
  [SUPER_ACTION_PROB_CHANGE_LANG_TIME_ADJ] = SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ,
  [SUPER_ACTION_PROB_CLEAR_LANG_TIME_ADJ] = SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ,
  [SUPER_ACTION_PROB_CHANGE_TEST_SETS] = SSERV_CMD_PROB_CHANGE_TEST_SETS,
  [SUPER_ACTION_PROB_CLEAR_TEST_SETS] = SSERV_CMD_PROB_CLEAR_TEST_SETS,
  [SUPER_ACTION_PROB_CHANGE_START_DATE] = SSERV_CMD_PROB_CHANGE_START_DATE,
  [SUPER_ACTION_PROB_CLEAR_START_DATE] = SSERV_CMD_PROB_CLEAR_START_DATE,
  [SUPER_ACTION_PROB_CHANGE_DEADLINE] = SSERV_CMD_PROB_CHANGE_DEADLINE,
  [SUPER_ACTION_PROB_CLEAR_DEADLINE] = SSERV_CMD_PROB_CLEAR_DEADLINE,
  [SUPER_ACTION_PROB_CHANGE_VARIANT_NUM] = SSERV_CMD_PROB_CHANGE_VARIANT_NUM,
  [SUPER_ACTION_PROB_EDIT_VARIANTS] = SSERV_CMD_PROB_EDIT_VARIANTS,
  [SUPER_ACTION_PROB_EDIT_VARIANTS_2] = SSERV_CMD_PROB_EDIT_VARIANTS_2,
  [SUPER_ACTION_PROB_CHANGE_VARIANTS] = SSERV_CMD_PROB_CHANGE_VARIANTS,
  [SUPER_ACTION_PROB_DELETE_VARIANTS] = SSERV_CMD_PROB_DELETE_VARIANTS,

  [SUPER_ACTION_GLOB_CHANGE_DURATION] = SSERV_CMD_GLOB_CHANGE_DURATION,
  [SUPER_ACTION_GLOB_UNLIMITED_DURATION] = SSERV_CMD_GLOB_UNLIMITED_DURATION,
  [SUPER_ACTION_GLOB_CHANGE_TYPE] = SSERV_CMD_GLOB_CHANGE_TYPE,
  [SUPER_ACTION_GLOB_CHANGE_FOG_TIME] = SSERV_CMD_GLOB_CHANGE_FOG_TIME,
  [SUPER_ACTION_GLOB_CHANGE_UNFOG_TIME] = SSERV_CMD_GLOB_CHANGE_UNFOG_TIME,
  [SUPER_ACTION_GLOB_DISABLE_FOG] = SSERV_CMD_GLOB_DISABLE_FOG,
  [SUPER_ACTION_GLOB_CHANGE_STAND_LOCALE] = SSERV_CMD_GLOB_CHANGE_STAND_LOCALE,
  [SUPER_ACTION_GLOB_CHANGE_SRC_VIEW] = SSERV_CMD_GLOB_CHANGE_SRC_VIEW,
  [SUPER_ACTION_GLOB_CHANGE_REP_VIEW] = SSERV_CMD_GLOB_CHANGE_REP_VIEW,
  [SUPER_ACTION_GLOB_CHANGE_CE_VIEW] = SSERV_CMD_GLOB_CHANGE_CE_VIEW,
  [SUPER_ACTION_GLOB_CHANGE_JUDGE_REPORT] = SSERV_CMD_GLOB_CHANGE_JUDGE_REPORT,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_CLARS] = SSERV_CMD_GLOB_CHANGE_DISABLE_CLARS,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_TEAM_CLARS] = SSERV_CMD_GLOB_CHANGE_DISABLE_TEAM_CLARS,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK] = SSERV_CMD_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK,
  [SUPER_ACTION_GLOB_CHANGE_IGNORE_COMPILE_ERRORS] = SSERV_CMD_GLOB_CHANGE_IGNORE_COMPILE_ERRORS,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW] = SSERV_CMD_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW,
  [SUPER_ACTION_GLOB_CHANGE_IGNORE_DUPICATED_RUNS] = SSERV_CMD_GLOB_CHANGE_IGNORE_DUPICATED_RUNS,
  [SUPER_ACTION_GLOB_CHANGE_REPORT_ERROR_CODE] = SSERV_CMD_GLOB_CHANGE_REPORT_ERROR_CODE,
  [SUPER_ACTION_GLOB_CHANGE_SHOW_DEADLINE] = SSERV_CMD_GLOB_CHANGE_SHOW_DEADLINE,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_PRINTING] = SSERV_CMD_GLOB_CHANGE_ENABLE_PRINTING,
  [SUPER_ACTION_GLOB_CHANGE_PRUNE_EMPTY_USERS] = SSERV_CMD_GLOB_CHANGE_PRUNE_EMPTY_USERS,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_FULL_ARCHIVE] = SSERV_CMD_GLOB_CHANGE_ENABLE_FULL_ARCHIVE,
  [SUPER_ACTION_GLOB_CHANGE_TEST_DIR] = SSERV_CMD_GLOB_CHANGE_TEST_DIR,
  [SUPER_ACTION_GLOB_CLEAR_TEST_DIR] = SSERV_CMD_GLOB_CLEAR_TEST_DIR,
  [SUPER_ACTION_GLOB_CHANGE_CORR_DIR] = SSERV_CMD_GLOB_CHANGE_CORR_DIR,
  [SUPER_ACTION_GLOB_CLEAR_CORR_DIR] = SSERV_CMD_GLOB_CLEAR_CORR_DIR,
  [SUPER_ACTION_GLOB_CHANGE_INFO_DIR] = SSERV_CMD_GLOB_CHANGE_INFO_DIR,
  [SUPER_ACTION_GLOB_CLEAR_INFO_DIR] = SSERV_CMD_GLOB_CLEAR_INFO_DIR,
  [SUPER_ACTION_GLOB_CHANGE_TGZ_DIR] = SSERV_CMD_GLOB_CHANGE_TGZ_DIR,
  [SUPER_ACTION_GLOB_CLEAR_TGZ_DIR] = SSERV_CMD_GLOB_CLEAR_TGZ_DIR,
  [SUPER_ACTION_GLOB_CHANGE_CHECKER_DIR] = SSERV_CMD_GLOB_CHANGE_CHECKER_DIR,
  [SUPER_ACTION_GLOB_CLEAR_CHECKER_DIR] = SSERV_CMD_GLOB_CLEAR_CHECKER_DIR,
  [SUPER_ACTION_GLOB_CHANGE_CONTEST_START_CMD] = SSERV_CMD_GLOB_CHANGE_CONTEST_START_CMD,
  [SUPER_ACTION_GLOB_CLEAR_CONTEST_START_CMD] = SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD,
  [SUPER_ACTION_GLOB_EDIT_CONTEST_START_CMD] = SSERV_CMD_GLOB_EDIT_CONTEST_START_CMD,
  [SUPER_ACTION_GLOB_CHANGE_MAX_RUN_SIZE] = SSERV_CMD_GLOB_CHANGE_MAX_RUN_SIZE,
  [SUPER_ACTION_GLOB_CHANGE_MAX_RUN_TOTAL] = SSERV_CMD_GLOB_CHANGE_MAX_RUN_TOTAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_RUN_NUM] = SSERV_CMD_GLOB_CHANGE_MAX_RUN_NUM,
  [SUPER_ACTION_GLOB_CHANGE_MAX_CLAR_SIZE] = SSERV_CMD_GLOB_CHANGE_MAX_CLAR_SIZE,
  [SUPER_ACTION_GLOB_CHANGE_MAX_CLAR_TOTAL] = SSERV_CMD_GLOB_CHANGE_MAX_CLAR_TOTAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_CLAR_NUM] = SSERV_CMD_GLOB_CHANGE_MAX_CLAR_NUM,
  [SUPER_ACTION_GLOB_CHANGE_TEAM_PAGE_QUOTA] = SSERV_CMD_GLOB_CHANGE_TEAM_PAGE_QUOTA,
  [SUPER_ACTION_GLOB_CHANGE_TEAM_INFO_URL] = SSERV_CMD_GLOB_CHANGE_TEAM_INFO_URL,
  [SUPER_ACTION_GLOB_CLEAR_TEAM_INFO_URL] = SSERV_CMD_GLOB_CLEAR_TEAM_INFO_URL,
  [SUPER_ACTION_GLOB_CHANGE_PROB_INFO_URL] = SSERV_CMD_GLOB_CHANGE_PROB_INFO_URL,
  [SUPER_ACTION_GLOB_CLEAR_PROB_INFO_URL] = SSERV_CMD_GLOB_CLEAR_PROB_INFO_URL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_FILE_NAME] = SSERV_CMD_GLOB_CHANGE_STAND_FILE_NAME,
  [SUPER_ACTION_GLOB_CLEAR_STAND_FILE_NAME] = SSERV_CMD_GLOB_CLEAR_STAND_FILE_NAME,
  [SUPER_ACTION_GLOB_CHANGE_USERS_ON_PAGE] = SSERV_CMD_GLOB_CHANGE_USERS_ON_PAGE,
  [SUPER_ACTION_GLOB_CHANGE_STAND_HEADER_FILE] = SSERV_CMD_GLOB_CHANGE_STAND_HEADER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_STAND_HEADER_FILE] = SSERV_CMD_GLOB_CLEAR_STAND_HEADER_FILE,
  [SUPER_ACTION_GLOB_EDIT_STAND_HEADER_FILE] = SSERV_CMD_GLOB_EDIT_STAND_HEADER_FILE,
  [SUPER_ACTION_GLOB_CHANGE_STAND_FOOTER_FILE] = SSERV_CMD_GLOB_CHANGE_STAND_FOOTER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_STAND_FOOTER_FILE] = SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_FILE,
  [SUPER_ACTION_GLOB_EDIT_STAND_FOOTER_FILE] = SSERV_CMD_GLOB_EDIT_STAND_FOOTER_FILE,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SYMLINK_DIR] = SSERV_CMD_GLOB_CHANGE_STAND_SYMLINK_DIR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SYMLINK_DIR] = SSERV_CMD_GLOB_CLEAR_STAND_SYMLINK_DIR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_IGNORE_AFTER] = SSERV_CMD_GLOB_CHANGE_STAND_IGNORE_AFTER,
  [SUPER_ACTION_GLOB_CLEAR_STAND_IGNORE_AFTER] = SSERV_CMD_GLOB_CLEAR_STAND_IGNORE_AFTER,
  [SUPER_ACTION_GLOB_CHANGE_CONTEST_FINISH_TIME] = SSERV_CMD_GLOB_CHANGE_CONTEST_FINISH_TIME,
  [SUPER_ACTION_GLOB_CLEAR_CONTEST_FINISH_TIME] = SSERV_CMD_GLOB_CLEAR_CONTEST_FINISH_TIME,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_STAND2] = SSERV_CMD_GLOB_CHANGE_ENABLE_STAND2,
  [SUPER_ACTION_GLOB_CHANGE_STAND2_FILE_NAME] = SSERV_CMD_GLOB_CHANGE_STAND2_FILE_NAME,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_FILE_NAME] = SSERV_CMD_GLOB_CLEAR_STAND2_FILE_NAME,
  [SUPER_ACTION_GLOB_CHANGE_STAND2_HEADER_FILE] = SSERV_CMD_GLOB_CHANGE_STAND2_HEADER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_HEADER_FILE] = SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_FILE,
  [SUPER_ACTION_GLOB_EDIT_STAND2_HEADER_FILE] = SSERV_CMD_GLOB_EDIT_STAND2_HEADER_FILE,
  [SUPER_ACTION_GLOB_CHANGE_STAND2_FOOTER_FILE] = SSERV_CMD_GLOB_CHANGE_STAND2_FOOTER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_FOOTER_FILE] = SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_FILE,
  [SUPER_ACTION_GLOB_EDIT_STAND2_FOOTER_FILE] = SSERV_CMD_GLOB_EDIT_STAND2_FOOTER_FILE,
  [SUPER_ACTION_GLOB_CHANGE_STAND2_SYMLINK_DIR] = SSERV_CMD_GLOB_CHANGE_STAND2_SYMLINK_DIR,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_SYMLINK_DIR] = SSERV_CMD_GLOB_CLEAR_STAND2_SYMLINK_DIR,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_PLOG] = SSERV_CMD_GLOB_CHANGE_ENABLE_PLOG,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_FILE_NAME] = SSERV_CMD_GLOB_CHANGE_PLOG_FILE_NAME,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_FILE_NAME] = SSERV_CMD_GLOB_CLEAR_PLOG_FILE_NAME,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_HEADER_FILE] = SSERV_CMD_GLOB_CHANGE_PLOG_HEADER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_HEADER_FILE] = SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_FILE,
  [SUPER_ACTION_GLOB_EDIT_PLOG_HEADER_FILE] = SSERV_CMD_GLOB_EDIT_PLOG_HEADER_FILE,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_FOOTER_FILE] = SSERV_CMD_GLOB_CHANGE_PLOG_FOOTER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_FOOTER_FILE] = SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_FILE,
  [SUPER_ACTION_GLOB_EDIT_PLOG_FOOTER_FILE] = SSERV_CMD_GLOB_EDIT_PLOG_FOOTER_FILE,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_SYMLINK_DIR] = SSERV_CMD_GLOB_CHANGE_PLOG_SYMLINK_DIR,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_SYMLINK_DIR] = SSERV_CMD_GLOB_CLEAR_PLOG_SYMLINK_DIR,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_UPDATE_TIME] = SSERV_CMD_GLOB_CHANGE_PLOG_UPDATE_TIME,
  [SUPER_ACTION_GLOB_CHANGE_STAND_TABLE_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_TABLE_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_TABLE_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_TABLE_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PLACE_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_PLACE_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PLACE_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_PLACE_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_TEAM_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_TEAM_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_TEAM_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_TEAM_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PROB_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_PROB_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PROB_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_PROB_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SOLVED_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_SOLVED_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SOLVED_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_SOLVED_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SCORE_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_SCORE_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SCORE_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_SCORE_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PENALTY_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_PENALTY_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PENALTY_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_PENALTY_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SHOW_OK_TIME] = SSERV_CMD_GLOB_CHANGE_STAND_SHOW_OK_TIME,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SHOW_ATT_NUM] = SSERV_CMD_GLOB_CHANGE_STAND_SHOW_ATT_NUM,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SORT_BY_SOLVED] = SSERV_CMD_GLOB_CHANGE_STAND_SORT_BY_SOLVED,
  [SUPER_ACTION_GLOB_CHANGE_IGNORE_SUCCESS_TIME] = SSERV_CMD_GLOB_CHANGE_IGNORE_SUCCESS_TIME,
  [SUPER_ACTION_GLOB_CHANGE_STAND_TIME_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_TIME_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_TIME_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_TIME_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SUCCESS_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_SUCCESS_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SUCCESS_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_SUCCESS_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_FAIL_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_FAIL_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_FAIL_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_FAIL_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_TRANS_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_TRANS_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_TRANS_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_TRANS_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SELF_ROW_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_SELF_ROW_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SELF_ROW_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_SELF_ROW_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_V_ROW_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_V_ROW_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_V_ROW_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_V_ROW_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_R_ROW_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_R_ROW_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_R_ROW_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_R_ROW_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_U_ROW_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_U_ROW_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_U_ROW_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_U_ROW_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_EXTRA_COL] = SSERV_CMD_GLOB_CHANGE_ENABLE_EXTRA_COL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_EXTRA_FORMAT] = SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_FORMAT,
  [SUPER_ACTION_GLOB_CLEAR_STAND_EXTRA_FORMAT] = SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_FORMAT,
  [SUPER_ACTION_GLOB_CHANGE_STAND_EXTRA_LEGEND] = SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_LEGEND,
  [SUPER_ACTION_GLOB_CLEAR_STAND_EXTRA_LEGEND] = SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_LEGEND,
  [SUPER_ACTION_GLOB_CHANGE_STAND_EXTRA_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_EXTRA_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER] = SSERV_CMD_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER,
  [SUPER_ACTION_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_SLEEP_TIME] = SSERV_CMD_GLOB_CHANGE_SLEEP_TIME,
  [SUPER_ACTION_GLOB_CHANGE_SERVE_SLEEP_TIME] = SSERV_CMD_GLOB_CHANGE_SERVE_SLEEP_TIME,
  [SUPER_ACTION_GLOB_CHANGE_AUTOUPDATE_STANDINGS] = SSERV_CMD_GLOB_CHANGE_AUTOUPDATE_STANDINGS,
  [SUPER_ACTION_GLOB_CHANGE_ROUNDING_MODE] = SSERV_CMD_GLOB_CHANGE_ROUNDING_MODE,
  [SUPER_ACTION_GLOB_CHANGE_MAX_FILE_LENGTH] = SSERV_CMD_GLOB_CHANGE_MAX_FILE_LENGTH,
  [SUPER_ACTION_GLOB_CHANGE_MAX_LINE_LENGTH] = SSERV_CMD_GLOB_CHANGE_MAX_LINE_LENGTH,
  [SUPER_ACTION_GLOB_CHANGE_INACTIVITY_TIMEOUT] = SSERV_CMD_GLOB_CHANGE_INACTIVITY_TIMEOUT,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_AUTO_TESTING] = SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_TESTING,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_TESTING] = SSERV_CMD_GLOB_CHANGE_DISABLE_TESTING,
  [SUPER_ACTION_GLOB_CHANGE_CR_SERIALIZATION_KEY] = SSERV_CMD_GLOB_CHANGE_CR_SERIALIZATION_KEY,
  [SUPER_ACTION_GLOB_CHANGE_SHOW_ASTR_TIME] = SSERV_CMD_GLOB_CHANGE_SHOW_ASTR_TIME,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_CONTINUE] = SSERV_CMD_GLOB_CHANGE_ENABLE_CONTINUE,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_REPORT_UPLOAD] = SSERV_CMD_GLOB_CHANGE_ENABLE_REPORT_UPLOAD,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_RUNLOG_MERGE] = SSERV_CMD_GLOB_CHANGE_ENABLE_RUNLOG_MERGE,
  [SUPER_ACTION_GLOB_CHANGE_USE_COMPILATION_SERVER] = SSERV_CMD_GLOB_CHANGE_USE_COMPILATION_SERVER,
  [SUPER_ACTION_GLOB_CHANGE_SECURE_RUN] = SSERV_CMD_GLOB_CHANGE_SECURE_RUN,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR] = SSERV_CMD_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_ROW_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_ROW_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_ROW_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_ROW_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_CUR_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_PAGE_CUR_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_CUR_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_PAGE_CUR_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_ROW_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_PAGE_ROW_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_ROW_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_PAGE_ROW_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_COL_ATTR] = SSERV_CMD_GLOB_CHANGE_STAND_PAGE_COL_ATTR,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_COL_ATTR] = SSERV_CMD_GLOB_CLEAR_STAND_PAGE_COL_ATTR,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_L10N] = SSERV_CMD_GLOB_CHANGE_ENABLE_L10N,
  [SUPER_ACTION_GLOB_CHANGE_CHARSET] = SSERV_CMD_GLOB_CHANGE_CHARSET,
  [SUPER_ACTION_GLOB_CLEAR_CHARSET] = SSERV_CMD_GLOB_CLEAR_CHARSET,
  [SUPER_ACTION_GLOB_CHANGE_TEAM_DOWNLOAD_TIME] = SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME,
  [SUPER_ACTION_GLOB_DISABLE_TEAM_DOWNLOAD_TIME] = SSERV_CMD_GLOB_DISABLE_TEAM_DOWNLOAD_TIME,
  [SUPER_ACTION_GLOB_CHANGE_CPU_BOGOMIPS] = SSERV_CMD_GLOB_CHANGE_CPU_BOGOMIPS,
  [SUPER_ACTION_GLOB_DETECT_CPU_BOGOMIPS] = SSERV_CMD_GLOB_DETECT_CPU_BOGOMIPS,

  [SUPER_ACTION_GLOB_SAVE_CONTEST_START_CMD] = SSERV_CMD_GLOB_SAVE_CONTEST_START_CMD,
  [SUPER_ACTION_GLOB_READ_CONTEST_START_CMD] = SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT,
  [SUPER_ACTION_GLOB_CLEAR_CONTEST_START_CMD_TEXT] = SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD_TEXT,
  [SUPER_ACTION_GLOB_SAVE_STAND_HEADER] = SSERV_CMD_GLOB_SAVE_STAND_HEADER,
  [SUPER_ACTION_GLOB_READ_STAND_HEADER] = SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT,
  [SUPER_ACTION_GLOB_CLEAR_STAND_HEADER_TEXT] = SSERV_CMD_GLOB_CLEAR_STAND_HEADER_TEXT,
  [SUPER_ACTION_GLOB_SAVE_STAND_FOOTER] = SSERV_CMD_GLOB_SAVE_STAND_FOOTER,
  [SUPER_ACTION_GLOB_READ_STAND_FOOTER] = SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT,
  [SUPER_ACTION_GLOB_CLEAR_STAND_FOOTER_TEXT] = SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_TEXT,
  [SUPER_ACTION_GLOB_SAVE_STAND2_HEADER] = SSERV_CMD_GLOB_SAVE_STAND2_HEADER,
  [SUPER_ACTION_GLOB_READ_STAND2_HEADER] = SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_HEADER_TEXT] = SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_TEXT,
  [SUPER_ACTION_GLOB_SAVE_STAND2_FOOTER] = SSERV_CMD_GLOB_SAVE_STAND2_FOOTER,
  [SUPER_ACTION_GLOB_READ_STAND2_FOOTER] = SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_FOOTER_TEXT] = SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_TEXT,
  [SUPER_ACTION_GLOB_SAVE_PLOG_HEADER] = SSERV_CMD_GLOB_SAVE_PLOG_HEADER,
  [SUPER_ACTION_GLOB_READ_PLOG_HEADER] = SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_HEADER_TEXT] = SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_TEXT,
  [SUPER_ACTION_GLOB_SAVE_PLOG_FOOTER] = SSERV_CMD_GLOB_SAVE_PLOG_FOOTER,
  [SUPER_ACTION_GLOB_READ_PLOG_FOOTER] = SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_FOOTER_TEXT] = SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_TEXT,

  [SUPER_ACTION_VIEW_NEW_SERVE_CFG] = SSERV_CMD_VIEW_NEW_SERVE_CFG,
  [SUPER_ACTION_LANG_UPDATE_VERSIONS] = SSERV_CMD_LANG_UPDATE_VERSIONS,
};

static const int next_action_map[SUPER_ACTION_LAST] =
{
  [SUPER_ACTION_OPEN_CONTEST] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_CLOSE_CONTEST] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_CLEAR_MESSAGES] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_CONTEST_VISIBLE] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_CONTEST_INVISIBLE] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_SERVE_LOG_TRUNC] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_SERVE_LOG_DEV_NULL] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_SERVE_LOG_FILE] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_RUN_LOG_TRUNC] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_RUN_LOG_DEV_NULL] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_RUN_LOG_FILE] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_SERVE_MNG_TERM] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_RUN_MNG_TERM] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_CONTEST_RESTART] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_SERVE_MNG_RESET_ERROR] = SUPER_ACTION_VIEW_CONTEST,
  [SUPER_ACTION_RUN_MNG_RESET_ERROR] = SUPER_ACTION_VIEW_CONTEST,

  [SUPER_ACTION_CNTS_BASIC_VIEW] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_ADVANCED_VIEW] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_HIDE_HTML_HEADERS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SHOW_HTML_HEADERS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_HIDE_HTML_ATTRS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SHOW_HTML_ATTRS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_HIDE_PATHS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SHOW_PATHS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_HIDE_NOTIFICATIONS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SHOW_NOTIFICATIONS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_HIDE_ACCESS_RULES] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SHOW_ACCESS_RULES] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_HIDE_PERMISSIONS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SHOW_PERMISSIONS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_HIDE_FORM_FIELDS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SHOW_FORM_FIELDS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_NAME] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_NAME_EN] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_DEADLINE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_HEADER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_FOOTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_HEADER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_FOOTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_HEADER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_FOOTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_HEAD_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_PAR_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_VERB_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_FORMAT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_FORMAT_EN] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_LEGEND] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_LEGEND_EN] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_HEAD_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_PAR_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_TABLE_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_NAME_COMMENT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_ALLOWED_LANGUAGES] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_CF_NOTIFY_EMAIL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_CLAR_NOTIFY_EMAIL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_DAILY_STAT_EMAIL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_HEAD_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_PAR_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_URL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL_FILE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_URL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_STANDINGS_URL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_PROBLEMS_URL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_ROOT_DIR] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_CONF_DIR] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_HEADER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_FOOTER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_HEADER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_FOOTER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_HEADER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_FOOTER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_NAME] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_NAME_EN] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_AUTOREGISTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_PASSWD] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_MANAGED] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_RUN_MANAGED] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_CLEAN_USERS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_CLOSED] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_INVISIBLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_TIME_SKEW] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_LOGIN] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_MEMBER_DELETE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_DEADLINE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_HEADER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_FOOTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_HEADER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_FOOTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_HEADER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_FOOTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_HEAD_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_PAR_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_VERB_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_FORMAT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_FORMAT_EN] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_LEGEND] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_LEGEND_EN] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_HEAD_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_PAR_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_TABLE_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_NAME_COMMENT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_ALLOWED_LANGUAGES] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_CF_NOTIFY_EMAIL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_CLAR_NOTIFY_EMAIL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_DAILY_STAT_EMAIL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_HEAD_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_PAR_STYLE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_EMAIL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_URL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_REGISTER_EMAIL_FILE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_TEAM_URL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_STANDINGS_URL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_PROBLEMS_URL] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_ROOT_DIR] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CHANGE_CONF_DIR] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_DELETE_PERMISSION] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_ADD_PERMISSION] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_PERMISSIONS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_FORM_FIELDS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_CONTESTANT_FIELDS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_RESERVE_FIELDS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_COACH_FIELDS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_ADVISOR_FIELDS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_GUEST_FIELDS] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_USERS_HEADER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_USERS_FOOTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_REGISTER_HEADER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_REGISTER_FOOTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_TEAM_HEADER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_TEAM_FOOTER] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_SAVE_REGISTER_EMAIL_FILE] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_HEADER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_USERS_FOOTER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_HEADER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_FOOTER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_HEADER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_TEAM_FOOTER_TEXT] = SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT] =SUPER_ACTION_EDIT_CURRENT_CONTEST,
  [SUPER_ACTION_CNTS_READ_USERS_HEADER] = SUPER_ACTION_CNTS_EDIT_USERS_HEADER,
  [SUPER_ACTION_CNTS_READ_USERS_FOOTER] = SUPER_ACTION_CNTS_EDIT_USERS_FOOTER,
  [SUPER_ACTION_CNTS_READ_REGISTER_HEADER] = SUPER_ACTION_CNTS_EDIT_REGISTER_HEADER,
  [SUPER_ACTION_CNTS_READ_REGISTER_FOOTER] = SUPER_ACTION_CNTS_EDIT_REGISTER_FOOTER,
  [SUPER_ACTION_CNTS_READ_TEAM_HEADER] = SUPER_ACTION_CNTS_EDIT_TEAM_HEADER,
  [SUPER_ACTION_CNTS_READ_TEAM_FOOTER] = SUPER_ACTION_CNTS_EDIT_TEAM_FOOTER,
  [SUPER_ACTION_CNTS_READ_REGISTER_EMAIL_FILE] = SUPER_ACTION_CNTS_EDIT_REGISTER_EMAIL_FILE,
  [SUPER_ACTION_GLOB_SHOW_1] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_HIDE_1] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SHOW_2] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_HIDE_2] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SHOW_3] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_HIDE_3] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SHOW_4] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_HIDE_4] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SHOW_5] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_HIDE_5] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SHOW_6] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_HIDE_6] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SHOW_7] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_HIDE_7] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_LANG_SHOW_DETAILS] = SUPER_ACTION_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_HIDE_DETAILS] = SUPER_ACTION_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_DEACTIVATE] = SUPER_ACTION_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_ACTIVATE] = SUPER_ACTION_EDIT_CURRENT_LANG,

  [SUPER_ACTION_LANG_CHANGE_DISABLED] = SUPER_ACTION_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_CHANGE_LONG_NAME] = SUPER_ACTION_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_CLEAR_LONG_NAME] = SUPER_ACTION_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_CHANGE_DISABLE_AUTO_TESTING] = SUPER_ACTION_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_CHANGE_DISABLE_TESTING] = SUPER_ACTION_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_CHANGE_OPTS] = SUPER_ACTION_EDIT_CURRENT_LANG,
  [SUPER_ACTION_LANG_CLEAR_OPTS] = SUPER_ACTION_EDIT_CURRENT_LANG,

  [SUPER_ACTION_PROB_ADD] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_ADD_ABSTRACT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_SHOW_DETAILS] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_HIDE_DETAILS] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_SHOW_ADVANCED] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_HIDE_ADVANCED] = SUPER_ACTION_EDIT_CURRENT_PROB,

  [SUPER_ACTION_PROB_DELETE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_SHORT_NAME] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_SHORT_NAME] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_LONG_NAME] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_LONG_NAME] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_SUPER] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_USE_STDIN] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_USE_STDOUT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_BINARY_INPUT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TIME_LIMIT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TIME_LIMIT_MILLIS] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_REAL_TIME_LIMIT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TEAM_ENABLE_REP_VIEW] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TEAM_ENABLE_CE_VIEW] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_DISABLE_TESTING] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_DISABLE_AUTO_TESTING] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_ENABLE_COMPILATION] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_FULL_SCORE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TEST_SCORE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_RUN_PENALTY] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_DISQUALIFIED_PENALTY] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_VARIABLE_FULL_SCORE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TEST_SCORE_LIST] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_TEST_SCORE_LIST] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_SCORE_TESTS] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_SCORE_TESTS] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TESTS_TO_ACCEPT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_ACCEPT_PARTIAL] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_HIDDEN] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_STAND_HIDE_TIME] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_MAX_VM_SIZE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_MAX_STACK_SIZE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_INPUT_FILE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_INPUT_FILE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_OUTPUT_FILE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_OUTPUT_FILE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_USE_CORR] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_USE_INFO] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TEST_DIR] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_TEST_DIR] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_CORR_DIR] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_CORR_DIR] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_INFO_DIR] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_INFO_DIR] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TEST_SFX] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_TEST_SFX] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TEST_PAT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_TEST_PAT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_CORR_SFX] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_CORR_SFX] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_CORR_PAT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_CORR_PAT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_INFO_SFX] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_INFO_SFX] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_INFO_PAT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_INFO_PAT] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_STANDARD_CHECKER] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_SCORE_BONUS] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_SCORE_BONUS] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_CHECK_CMD] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_CHECK_CMD] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_CHECKER_ENV] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_CHECKER_ENV] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_LANG_TIME_ADJ] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_LANG_TIME_ADJ] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_TEST_SETS] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_TEST_SETS] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_START_DATE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_START_DATE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_DEADLINE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CLEAR_DEADLINE] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_CHANGE_VARIANT_NUM] = SUPER_ACTION_EDIT_CURRENT_PROB,
  [SUPER_ACTION_PROB_EDIT_VARIANTS] = SUPER_ACTION_PROB_EDIT_VARIANTS,
  [SUPER_ACTION_PROB_EDIT_VARIANTS_2] = SUPER_ACTION_PROB_EDIT_VARIANTS_2,
  [SUPER_ACTION_PROB_CHANGE_VARIANTS] = SUPER_ACTION_PROB_EDIT_VARIANTS_2,
  [SUPER_ACTION_PROB_DELETE_VARIANTS] = SUPER_ACTION_PROB_EDIT_VARIANTS_2,

  [SUPER_ACTION_GLOB_CHANGE_DURATION] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_UNLIMITED_DURATION] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_TYPE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_FOG_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_UNFOG_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_DISABLE_FOG] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_LOCALE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_SRC_VIEW] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_REP_VIEW] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_CE_VIEW] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_JUDGE_REPORT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_CLARS] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_TEAM_CLARS] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_IGNORE_COMPILE_ERRORS] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_IGNORE_DUPICATED_RUNS] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_REPORT_ERROR_CODE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_SHOW_DEADLINE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_PRINTING] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_PRUNE_EMPTY_USERS] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_FULL_ARCHIVE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_TEST_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_TEST_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_CORR_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_CORR_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_INFO_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_INFO_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_TGZ_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_TGZ_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_CHECKER_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_CHECKER_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_CONTEST_START_CMD] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_CONTEST_START_CMD] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_RUN_SIZE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_RUN_TOTAL] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_RUN_NUM] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_CLAR_SIZE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_CLAR_TOTAL] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_CLAR_NUM] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_TEAM_PAGE_QUOTA] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_TEAM_INFO_URL] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_TEAM_INFO_URL] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_PROB_INFO_URL] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_PROB_INFO_URL] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_FILE_NAME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_FILE_NAME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_USERS_ON_PAGE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_HEADER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_HEADER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_FOOTER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_FOOTER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SYMLINK_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SYMLINK_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_IGNORE_AFTER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_IGNORE_AFTER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_CONTEST_FINISH_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_CONTEST_FINISH_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_STAND2] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND2_FILE_NAME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_FILE_NAME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND2_HEADER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_HEADER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND2_FOOTER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_FOOTER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND2_SYMLINK_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_SYMLINK_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_PLOG] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_FILE_NAME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_FILE_NAME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_HEADER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_HEADER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_FOOTER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_FOOTER_FILE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_SYMLINK_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_SYMLINK_DIR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_PLOG_UPDATE_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_TABLE_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_TABLE_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PLACE_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PLACE_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_TEAM_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_TEAM_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PROB_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PROB_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SOLVED_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SOLVED_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SCORE_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SCORE_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PENALTY_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PENALTY_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SHOW_OK_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SHOW_ATT_NUM] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SORT_BY_SOLVED] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_IGNORE_SUCCESS_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_TIME_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_TIME_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SUCCESS_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SUCCESS_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_FAIL_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_FAIL_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_TRANS_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_TRANS_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SELF_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_SELF_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_V_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_V_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_R_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_R_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_U_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_U_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_EXTRA_COL] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_EXTRA_FORMAT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_EXTRA_FORMAT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_EXTRA_LEGEND] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_EXTRA_LEGEND] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_EXTRA_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_EXTRA_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_SLEEP_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_SERVE_SLEEP_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_AUTOUPDATE_STANDINGS] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ROUNDING_MODE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_FILE_LENGTH] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_MAX_LINE_LENGTH] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_INACTIVITY_TIMEOUT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_AUTO_TESTING] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_DISABLE_TESTING] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_CR_SERIALIZATION_KEY] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_SHOW_ASTR_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_CONTINUE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_REPORT_UPLOAD] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_RUNLOG_MERGE] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_USE_COMPILATION_SERVER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_SECURE_RUN] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_CUR_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_CUR_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_ROW_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_COL_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_COL_ATTR] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_ENABLE_L10N] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_CHARSET] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CLEAR_CHARSET] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_TEAM_DOWNLOAD_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_DISABLE_TEAM_DOWNLOAD_TIME] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_CHANGE_CPU_BOGOMIPS] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_DETECT_CPU_BOGOMIPS] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,

  [SUPER_ACTION_GLOB_SAVE_CONTEST_START_CMD] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_READ_CONTEST_START_CMD] = SUPER_ACTION_GLOB_EDIT_CONTEST_START_CMD,
  [SUPER_ACTION_GLOB_CLEAR_CONTEST_START_CMD_TEXT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SAVE_STAND_HEADER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_READ_STAND_HEADER] = SUPER_ACTION_GLOB_EDIT_STAND_HEADER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_STAND_HEADER_TEXT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SAVE_STAND_FOOTER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_READ_STAND_FOOTER] = SUPER_ACTION_GLOB_EDIT_STAND_FOOTER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_STAND_FOOTER_TEXT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SAVE_STAND2_HEADER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_READ_STAND2_HEADER] = SUPER_ACTION_GLOB_EDIT_STAND2_HEADER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_HEADER_TEXT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SAVE_STAND2_FOOTER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_READ_STAND2_FOOTER] = SUPER_ACTION_GLOB_EDIT_STAND2_FOOTER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_STAND2_FOOTER_TEXT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SAVE_PLOG_HEADER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_READ_PLOG_HEADER] = SUPER_ACTION_GLOB_EDIT_PLOG_HEADER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_HEADER_TEXT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_SAVE_PLOG_FOOTER] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_GLOB_READ_PLOG_FOOTER] = SUPER_ACTION_GLOB_EDIT_PLOG_FOOTER_FILE,
  [SUPER_ACTION_GLOB_CLEAR_PLOG_FOOTER_TEXT] = SUPER_ACTION_EDIT_CURRENT_GLOBAL,
  [SUPER_ACTION_LANG_UPDATE_VERSIONS] = SUPER_ACTION_EDIT_CURRENT_LANG,
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
  case SUPER_ACTION_VIEW_CONTEST:
    action_view_contest(SSERV_CMD_CONTEST_PAGE);
    break;
  case SUPER_ACTION_SERVE_MNG_PROBE_RUN:
    action_view_contest(SSERV_CMD_SERVE_MNG_PROBE_RUN);
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
  case SUPER_ACTION_CLOSE_CONTEST:
  case SUPER_ACTION_CLEAR_MESSAGES:
  case SUPER_ACTION_CONTEST_VISIBLE:
  case SUPER_ACTION_CONTEST_INVISIBLE:
  case SUPER_ACTION_SERVE_LOG_TRUNC:
  case SUPER_ACTION_SERVE_LOG_DEV_NULL:
  case SUPER_ACTION_SERVE_LOG_FILE:
  case SUPER_ACTION_RUN_LOG_TRUNC:
  case SUPER_ACTION_RUN_LOG_DEV_NULL:
  case SUPER_ACTION_RUN_LOG_FILE:
  case SUPER_ACTION_SERVE_MNG_TERM:
  case SUPER_ACTION_RUN_MNG_TERM:
  case SUPER_ACTION_CONTEST_RESTART:
  case SUPER_ACTION_SERVE_MNG_RESET_ERROR:
  case SUPER_ACTION_RUN_MNG_RESET_ERROR:
    action_contest_command(action_to_cmd_map[client_action],
                           next_action_map[client_action]);
    break;

  case SUPER_ACTION_HIDE_HIDDEN:
    action_simple_top_command(SSERV_CMD_HIDE_HIDDEN);
    break;
  case SUPER_ACTION_SHOW_HIDDEN:
    action_simple_top_command(SSERV_CMD_SHOW_HIDDEN);
    break;
  case SUPER_ACTION_HIDE_CLOSED:
    action_simple_top_command(SSERV_CMD_HIDE_CLOSED);
    break;
  case SUPER_ACTION_SHOW_CLOSED:
    action_simple_top_command(SSERV_CMD_SHOW_CLOSED);
    break;
  case SUPER_ACTION_HIDE_UNMNG:
    action_simple_top_command(SSERV_CMD_HIDE_UNMNG);
    break;
  case SUPER_ACTION_SHOW_UNMNG:
    action_simple_top_command(SSERV_CMD_SHOW_UNMNG);
    break;
  case SUPER_ACTION_CREATE_CONTEST:
    action_create_contest();
    break;
  case SUPER_ACTION_CREATE_CONTEST_2:
    action_create_contest_2();
    break;

  case SUPER_ACTION_EDIT_CURRENT_CONTEST:
  case SUPER_ACTION_CNTS_EDIT_REGISTER_ACCESS:
  case SUPER_ACTION_CNTS_EDIT_USERS_ACCESS:
  case SUPER_ACTION_CNTS_EDIT_MASTER_ACCESS:
  case SUPER_ACTION_CNTS_EDIT_JUDGE_ACCESS:
  case SUPER_ACTION_CNTS_EDIT_TEAM_ACCESS:
  case SUPER_ACTION_CNTS_EDIT_SERVE_CONTROL_ACCESS:
  case SUPER_ACTION_CNTS_EDIT_FORM_FIELDS:
  case SUPER_ACTION_CNTS_EDIT_CONTESTANT_FIELDS:
  case SUPER_ACTION_CNTS_EDIT_RESERVE_FIELDS:
  case SUPER_ACTION_CNTS_EDIT_COACH_FIELDS:
  case SUPER_ACTION_CNTS_EDIT_ADVISOR_FIELDS:
  case SUPER_ACTION_CNTS_EDIT_GUEST_FIELDS:
  case SUPER_ACTION_CNTS_EDIT_USERS_HEADER:
  case SUPER_ACTION_CNTS_EDIT_USERS_FOOTER:
  case SUPER_ACTION_CNTS_EDIT_REGISTER_HEADER:
  case SUPER_ACTION_CNTS_EDIT_REGISTER_FOOTER:
  case SUPER_ACTION_CNTS_EDIT_TEAM_HEADER:
  case SUPER_ACTION_CNTS_EDIT_TEAM_FOOTER:
  case SUPER_ACTION_CNTS_EDIT_REGISTER_EMAIL_FILE:
  case SUPER_ACTION_CNTS_COMMIT:
  case SUPER_ACTION_EDIT_CURRENT_GLOBAL:
  case SUPER_ACTION_EDIT_CURRENT_LANG:
  case SUPER_ACTION_EDIT_CURRENT_PROB:
  case SUPER_ACTION_GLOB_EDIT_CONTEST_START_CMD:
  case SUPER_ACTION_GLOB_EDIT_STAND_HEADER_FILE:
  case SUPER_ACTION_GLOB_EDIT_STAND_FOOTER_FILE:
  case SUPER_ACTION_GLOB_EDIT_STAND2_HEADER_FILE:
  case SUPER_ACTION_GLOB_EDIT_STAND2_FOOTER_FILE:
  case SUPER_ACTION_GLOB_EDIT_PLOG_HEADER_FILE:
  case SUPER_ACTION_GLOB_EDIT_PLOG_FOOTER_FILE:
  case SUPER_ACTION_VIEW_NEW_SERVE_CFG:
  case SUPER_ACTION_PROB_EDIT_VARIANTS:
  case SUPER_ACTION_PROB_EDIT_VARIANTS_2:
    action_edit_current_contest(action_to_cmd_map[client_action]);
    break;
  case SUPER_ACTION_CNTS_FORGET:
    action_simple_top_command(action_to_cmd_map[client_action]);
    break;
  case SUPER_ACTION_CHECK_TESTS:
  case SUPER_ACTION_EDIT_CONTEST_XML:
    action_view_contest(action_to_cmd_map[client_action]);
    break;
  case SUPER_ACTION_CNTS_EDIT_PERMISSION:
    action_edit_permissions();
    break;

  case SUPER_ACTION_CNTS_CHANGE_NAME:
  case SUPER_ACTION_CNTS_CHANGE_NAME_EN:
  case SUPER_ACTION_CNTS_CHANGE_AUTOREGISTER:
  case SUPER_ACTION_CNTS_CHANGE_TEAM_PASSWD:
  case SUPER_ACTION_CNTS_CHANGE_MANAGED:
  case SUPER_ACTION_CNTS_CHANGE_RUN_MANAGED:
  case SUPER_ACTION_CNTS_CHANGE_CLEAN_USERS:
  case SUPER_ACTION_CNTS_CHANGE_CLOSED:
  case SUPER_ACTION_CNTS_CHANGE_INVISIBLE:
  case SUPER_ACTION_CNTS_CHANGE_TIME_SKEW:
  case SUPER_ACTION_CNTS_CHANGE_TEAM_LOGIN:
  case SUPER_ACTION_CNTS_CHANGE_MEMBER_DELETE:
  case SUPER_ACTION_CNTS_CHANGE_USERS_HEADER:
  case SUPER_ACTION_CNTS_CHANGE_USERS_FOOTER:
  case SUPER_ACTION_CNTS_CHANGE_REGISTER_HEADER:
  case SUPER_ACTION_CNTS_CHANGE_REGISTER_FOOTER:
  case SUPER_ACTION_CNTS_CHANGE_TEAM_HEADER:
  case SUPER_ACTION_CNTS_CHANGE_TEAM_FOOTER:
  case SUPER_ACTION_CNTS_CHANGE_USERS_HEAD_STYLE:
  case SUPER_ACTION_CNTS_CHANGE_USERS_PAR_STYLE:
  case SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_STYLE:
  case SUPER_ACTION_CNTS_CHANGE_USERS_VERB_STYLE:
  case SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_FORMAT:
  case SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_FORMAT_EN:
  case SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_LEGEND:
  case SUPER_ACTION_CNTS_CHANGE_USERS_TABLE_LEGEND_EN:
  case SUPER_ACTION_CNTS_CHANGE_REGISTER_HEAD_STYLE:
  case SUPER_ACTION_CNTS_CHANGE_REGISTER_PAR_STYLE:
  case SUPER_ACTION_CNTS_CHANGE_REGISTER_TABLE_STYLE:
  case SUPER_ACTION_CNTS_CHANGE_REGISTER_NAME_COMMENT:
  case SUPER_ACTION_CNTS_CHANGE_ALLOWED_LANGUAGES:
  case SUPER_ACTION_CNTS_CHANGE_CF_NOTIFY_EMAIL:
  case SUPER_ACTION_CNTS_CHANGE_CLAR_NOTIFY_EMAIL:
  case SUPER_ACTION_CNTS_CHANGE_DAILY_STAT_EMAIL:
  case SUPER_ACTION_CNTS_CHANGE_TEAM_HEAD_STYLE:
  case SUPER_ACTION_CNTS_CHANGE_TEAM_PAR_STYLE:
  case SUPER_ACTION_CNTS_CHANGE_REGISTER_EMAIL:
  case SUPER_ACTION_CNTS_CHANGE_REGISTER_URL:
  case SUPER_ACTION_CNTS_CHANGE_REGISTER_EMAIL_FILE:
  case SUPER_ACTION_CNTS_CHANGE_TEAM_URL:
  case SUPER_ACTION_CNTS_CHANGE_STANDINGS_URL:
  case SUPER_ACTION_CNTS_CHANGE_PROBLEMS_URL:
  case SUPER_ACTION_CNTS_CHANGE_ROOT_DIR:
  case SUPER_ACTION_CNTS_CHANGE_CONF_DIR:
  case SUPER_ACTION_CNTS_SAVE_USERS_HEADER:
  case SUPER_ACTION_CNTS_SAVE_USERS_FOOTER:
  case SUPER_ACTION_CNTS_SAVE_REGISTER_HEADER:
  case SUPER_ACTION_CNTS_SAVE_REGISTER_FOOTER:
  case SUPER_ACTION_CNTS_SAVE_TEAM_HEADER:
  case SUPER_ACTION_CNTS_SAVE_TEAM_FOOTER:
  case SUPER_ACTION_CNTS_SAVE_REGISTER_EMAIL_FILE:
    action_set_param(action_to_cmd_map[client_action], next_action_map[client_action]);
    break;

  case SUPER_ACTION_CNTS_CHANGE_DEADLINE:
  case SUPER_ACTION_GLOB_CHANGE_STAND_IGNORE_AFTER:
  case SUPER_ACTION_GLOB_CHANGE_CONTEST_FINISH_TIME:
    action_set_date_param(action_to_cmd_map[client_action],
                          next_action_map[client_action]);
    break;

  case SUPER_ACTION_CNTS_DEFAULT_ACCESS:
  case SUPER_ACTION_CNTS_ADD_RULE:
  case SUPER_ACTION_CNTS_CHANGE_RULE:
  case SUPER_ACTION_CNTS_DELETE_RULE:
  case SUPER_ACTION_CNTS_UP_RULE:
  case SUPER_ACTION_CNTS_DOWN_RULE:
    action_set_ip_param(action_to_cmd_map[client_action]);
    break;

  case SUPER_ACTION_CNTS_COPY_ACCESS:
    action_copy_ip_param(action_to_cmd_map[client_action]);
    break;

  case SUPER_ACTION_CNTS_DELETE_PERMISSION:
  case SUPER_ACTION_CNTS_ADD_PERMISSION:
  case SUPER_ACTION_CNTS_SAVE_PERMISSIONS:
    action_perform_permission_op(action_to_cmd_map[client_action],
                                 next_action_map[client_action]);
    break;

  case SUPER_ACTION_CNTS_SAVE_FORM_FIELDS:
  case SUPER_ACTION_CNTS_SAVE_CONTESTANT_FIELDS:
  case SUPER_ACTION_CNTS_SAVE_RESERVE_FIELDS:
  case SUPER_ACTION_CNTS_SAVE_COACH_FIELDS:
  case SUPER_ACTION_CNTS_SAVE_ADVISOR_FIELDS:
  case SUPER_ACTION_CNTS_SAVE_GUEST_FIELDS:
    action_save_form_fields(action_to_cmd_map[client_action],
                            next_action_map[client_action]);
    break;

  case SUPER_ACTION_CNTS_BASIC_VIEW:
  case SUPER_ACTION_CNTS_ADVANCED_VIEW:
  case SUPER_ACTION_CNTS_HIDE_HTML_HEADERS:
  case SUPER_ACTION_CNTS_SHOW_HTML_HEADERS:
  case SUPER_ACTION_CNTS_HIDE_HTML_ATTRS:
  case SUPER_ACTION_CNTS_SHOW_HTML_ATTRS:
  case SUPER_ACTION_CNTS_HIDE_PATHS:
  case SUPER_ACTION_CNTS_SHOW_PATHS:
  case SUPER_ACTION_CNTS_HIDE_NOTIFICATIONS:
  case SUPER_ACTION_CNTS_SHOW_NOTIFICATIONS:
  case SUPER_ACTION_CNTS_HIDE_ACCESS_RULES:
  case SUPER_ACTION_CNTS_SHOW_ACCESS_RULES:
  case SUPER_ACTION_CNTS_HIDE_PERMISSIONS:
  case SUPER_ACTION_CNTS_SHOW_PERMISSIONS:
  case SUPER_ACTION_CNTS_HIDE_FORM_FIELDS:
  case SUPER_ACTION_CNTS_SHOW_FORM_FIELDS:
  case SUPER_ACTION_CNTS_CLEAR_NAME:
  case SUPER_ACTION_CNTS_CLEAR_NAME_EN:
  case SUPER_ACTION_CNTS_CLEAR_DEADLINE:
  case SUPER_ACTION_CNTS_CLEAR_USERS_HEADER:
  case SUPER_ACTION_CNTS_CLEAR_USERS_FOOTER:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_HEADER:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_FOOTER:
  case SUPER_ACTION_CNTS_CLEAR_TEAM_HEADER:
  case SUPER_ACTION_CNTS_CLEAR_TEAM_FOOTER:
  case SUPER_ACTION_CNTS_CLEAR_USERS_HEAD_STYLE:
  case SUPER_ACTION_CNTS_CLEAR_USERS_PAR_STYLE:
  case SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_STYLE:
  case SUPER_ACTION_CNTS_CLEAR_USERS_VERB_STYLE:
  case SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_FORMAT:
  case SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_FORMAT_EN:
  case SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_LEGEND:
  case SUPER_ACTION_CNTS_CLEAR_USERS_TABLE_LEGEND_EN:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_HEAD_STYLE:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_PAR_STYLE:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_TABLE_STYLE:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_NAME_COMMENT:
  case SUPER_ACTION_CNTS_CLEAR_ALLOWED_LANGUAGES:
  case SUPER_ACTION_CNTS_CLEAR_CF_NOTIFY_EMAIL:
  case SUPER_ACTION_CNTS_CLEAR_CLAR_NOTIFY_EMAIL:
  case SUPER_ACTION_CNTS_CLEAR_DAILY_STAT_EMAIL:
  case SUPER_ACTION_CNTS_CLEAR_TEAM_HEAD_STYLE:
  case SUPER_ACTION_CNTS_CLEAR_TEAM_PAR_STYLE:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_URL:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL_FILE:
  case SUPER_ACTION_CNTS_CLEAR_TEAM_URL:
  case SUPER_ACTION_CNTS_CLEAR_STANDINGS_URL:
  case SUPER_ACTION_CNTS_CLEAR_PROBLEMS_URL:
  case SUPER_ACTION_CNTS_CLEAR_ROOT_DIR:
  case SUPER_ACTION_CNTS_CLEAR_CONF_DIR:
  case SUPER_ACTION_CNTS_CLEAR_USERS_HEADER_TEXT:
  case SUPER_ACTION_CNTS_CLEAR_USERS_FOOTER_TEXT:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_HEADER_TEXT:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_FOOTER_TEXT:
  case SUPER_ACTION_CNTS_CLEAR_TEAM_HEADER_TEXT:
  case SUPER_ACTION_CNTS_CLEAR_TEAM_FOOTER_TEXT:
  case SUPER_ACTION_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT:
  case SUPER_ACTION_CNTS_READ_USERS_HEADER:
  case SUPER_ACTION_CNTS_READ_USERS_FOOTER:
  case SUPER_ACTION_CNTS_READ_REGISTER_HEADER:
  case SUPER_ACTION_CNTS_READ_REGISTER_FOOTER:
  case SUPER_ACTION_CNTS_READ_TEAM_HEADER:
  case SUPER_ACTION_CNTS_READ_TEAM_FOOTER:
  case SUPER_ACTION_CNTS_READ_REGISTER_EMAIL_FILE:
  case SUPER_ACTION_GLOB_SHOW_1:
  case SUPER_ACTION_GLOB_HIDE_1:
  case SUPER_ACTION_GLOB_SHOW_2:
  case SUPER_ACTION_GLOB_HIDE_2:
  case SUPER_ACTION_GLOB_SHOW_3:
  case SUPER_ACTION_GLOB_HIDE_3:
  case SUPER_ACTION_GLOB_SHOW_4:
  case SUPER_ACTION_GLOB_HIDE_4:
  case SUPER_ACTION_GLOB_SHOW_5:
  case SUPER_ACTION_GLOB_HIDE_5:
  case SUPER_ACTION_GLOB_SHOW_6:
  case SUPER_ACTION_GLOB_HIDE_6:
  case SUPER_ACTION_GLOB_SHOW_7:
  case SUPER_ACTION_GLOB_HIDE_7:
  case SUPER_ACTION_LANG_UPDATE_VERSIONS:
    action_simple_edit_command(action_to_cmd_map[client_action],
                               next_action_map[client_action]);
    break;
  case SUPER_ACTION_LANG_SHOW_DETAILS:
  case SUPER_ACTION_LANG_HIDE_DETAILS:
  case SUPER_ACTION_LANG_DEACTIVATE:
  case SUPER_ACTION_LANG_ACTIVATE:
  case SUPER_ACTION_LANG_CHANGE_DISABLED:
  case SUPER_ACTION_LANG_CHANGE_LONG_NAME:
  case SUPER_ACTION_LANG_CLEAR_LONG_NAME:
  case SUPER_ACTION_LANG_CHANGE_DISABLE_AUTO_TESTING:
  case SUPER_ACTION_LANG_CHANGE_DISABLE_TESTING:
  case SUPER_ACTION_LANG_CHANGE_OPTS:
  case SUPER_ACTION_LANG_CLEAR_OPTS:
    action_lang_cmd(action_to_cmd_map[client_action],
                    next_action_map[client_action]);
    break;

  case SUPER_ACTION_PROB_ADD:
    action_prob_add(action_to_cmd_map[client_action],
                    next_action_map[client_action]);
    break;
  case SUPER_ACTION_PROB_ADD_ABSTRACT:
    action_prob_add_abstract(action_to_cmd_map[client_action],
                             next_action_map[client_action]);
    break;

  case SUPER_ACTION_PROB_SHOW_DETAILS:
  case SUPER_ACTION_PROB_HIDE_DETAILS:
  case SUPER_ACTION_PROB_SHOW_ADVANCED:
  case SUPER_ACTION_PROB_HIDE_ADVANCED:
    action_prob_cmd(action_to_cmd_map[client_action],
                    next_action_map[client_action]);
    break;

  case SUPER_ACTION_PROB_DELETE:
  case SUPER_ACTION_PROB_CHANGE_SHORT_NAME:
  case SUPER_ACTION_PROB_CLEAR_SHORT_NAME:
  case SUPER_ACTION_PROB_CHANGE_LONG_NAME:
  case SUPER_ACTION_PROB_CLEAR_LONG_NAME:
  case SUPER_ACTION_PROB_CHANGE_SUPER:
  case SUPER_ACTION_PROB_CHANGE_USE_STDIN:
  case SUPER_ACTION_PROB_CHANGE_USE_STDOUT:
  case SUPER_ACTION_PROB_CHANGE_BINARY_INPUT:
  case SUPER_ACTION_PROB_CHANGE_TIME_LIMIT:
  case SUPER_ACTION_PROB_CHANGE_TIME_LIMIT_MILLIS:
  case SUPER_ACTION_PROB_CHANGE_REAL_TIME_LIMIT:
  case SUPER_ACTION_PROB_CHANGE_TEAM_ENABLE_REP_VIEW:
  case SUPER_ACTION_PROB_CHANGE_TEAM_ENABLE_CE_VIEW:
  case SUPER_ACTION_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT:
  case SUPER_ACTION_PROB_CHANGE_DISABLE_TESTING:
  case SUPER_ACTION_PROB_CHANGE_DISABLE_AUTO_TESTING:
  case SUPER_ACTION_PROB_CHANGE_ENABLE_COMPILATION:
  case SUPER_ACTION_PROB_CHANGE_FULL_SCORE:
  case SUPER_ACTION_PROB_CHANGE_TEST_SCORE:
  case SUPER_ACTION_PROB_CHANGE_RUN_PENALTY:
  case SUPER_ACTION_PROB_CHANGE_DISQUALIFIED_PENALTY:
  case SUPER_ACTION_PROB_CHANGE_VARIABLE_FULL_SCORE:
  case SUPER_ACTION_PROB_CHANGE_TEST_SCORE_LIST:
  case SUPER_ACTION_PROB_CLEAR_TEST_SCORE_LIST:
  case SUPER_ACTION_PROB_CHANGE_SCORE_TESTS:
  case SUPER_ACTION_PROB_CLEAR_SCORE_TESTS:
  case SUPER_ACTION_PROB_CHANGE_TESTS_TO_ACCEPT:
  case SUPER_ACTION_PROB_CHANGE_ACCEPT_PARTIAL:
  case SUPER_ACTION_PROB_CHANGE_HIDDEN:
  case SUPER_ACTION_PROB_CHANGE_STAND_HIDE_TIME:
  case SUPER_ACTION_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT:
  case SUPER_ACTION_PROB_CHANGE_MAX_VM_SIZE:
  case SUPER_ACTION_PROB_CHANGE_MAX_STACK_SIZE:
  case SUPER_ACTION_PROB_CHANGE_INPUT_FILE:
  case SUPER_ACTION_PROB_CLEAR_INPUT_FILE:
  case SUPER_ACTION_PROB_CHANGE_OUTPUT_FILE:
  case SUPER_ACTION_PROB_CLEAR_OUTPUT_FILE:
  case SUPER_ACTION_PROB_CHANGE_USE_CORR:
  case SUPER_ACTION_PROB_CHANGE_USE_INFO:
  case SUPER_ACTION_PROB_CHANGE_TEST_DIR:
  case SUPER_ACTION_PROB_CLEAR_TEST_DIR:
  case SUPER_ACTION_PROB_CHANGE_CORR_DIR:
  case SUPER_ACTION_PROB_CLEAR_CORR_DIR:
  case SUPER_ACTION_PROB_CHANGE_INFO_DIR:
  case SUPER_ACTION_PROB_CLEAR_INFO_DIR:
  case SUPER_ACTION_PROB_CHANGE_TEST_SFX:
  case SUPER_ACTION_PROB_CLEAR_TEST_SFX:
  case SUPER_ACTION_PROB_CHANGE_TEST_PAT:
  case SUPER_ACTION_PROB_CLEAR_TEST_PAT:
  case SUPER_ACTION_PROB_CHANGE_CORR_SFX:
  case SUPER_ACTION_PROB_CLEAR_CORR_SFX:
  case SUPER_ACTION_PROB_CHANGE_CORR_PAT:
  case SUPER_ACTION_PROB_CLEAR_CORR_PAT:
  case SUPER_ACTION_PROB_CHANGE_INFO_SFX:
  case SUPER_ACTION_PROB_CLEAR_INFO_SFX:
  case SUPER_ACTION_PROB_CHANGE_INFO_PAT:
  case SUPER_ACTION_PROB_CLEAR_INFO_PAT:
  case SUPER_ACTION_PROB_CHANGE_STANDARD_CHECKER:
  case SUPER_ACTION_PROB_CHANGE_SCORE_BONUS:
  case SUPER_ACTION_PROB_CLEAR_SCORE_BONUS:
  case SUPER_ACTION_PROB_CHANGE_CHECK_CMD:
  case SUPER_ACTION_PROB_CLEAR_CHECK_CMD:
  case SUPER_ACTION_PROB_CHANGE_CHECKER_ENV:
  case SUPER_ACTION_PROB_CLEAR_CHECKER_ENV:
  case SUPER_ACTION_PROB_CHANGE_LANG_TIME_ADJ:
  case SUPER_ACTION_PROB_CLEAR_LANG_TIME_ADJ:
  case SUPER_ACTION_PROB_CHANGE_TEST_SETS:
  case SUPER_ACTION_PROB_CLEAR_TEST_SETS:
  case SUPER_ACTION_PROB_CLEAR_START_DATE:
  case SUPER_ACTION_PROB_CLEAR_DEADLINE:
  case SUPER_ACTION_PROB_CHANGE_VARIANT_NUM:
    action_prob_param(action_to_cmd_map[client_action],
                      next_action_map[client_action]);
    break;

  case SUPER_ACTION_PROB_CHANGE_START_DATE:
  case SUPER_ACTION_PROB_CHANGE_DEADLINE:
    action_prob_date_param(action_to_cmd_map[client_action],
                           next_action_map[client_action]);
    break;

  case SUPER_ACTION_GLOB_CHANGE_DURATION:
  case SUPER_ACTION_GLOB_UNLIMITED_DURATION:
  case SUPER_ACTION_GLOB_CHANGE_TYPE:
  case SUPER_ACTION_GLOB_CHANGE_FOG_TIME:
  case SUPER_ACTION_GLOB_CHANGE_UNFOG_TIME:
  case SUPER_ACTION_GLOB_DISABLE_FOG:
  case SUPER_ACTION_GLOB_CHANGE_STAND_LOCALE:
  case SUPER_ACTION_GLOB_CHANGE_SRC_VIEW:
  case SUPER_ACTION_GLOB_CHANGE_REP_VIEW:
  case SUPER_ACTION_GLOB_CHANGE_CE_VIEW:
  case SUPER_ACTION_GLOB_CHANGE_JUDGE_REPORT:
  case SUPER_ACTION_GLOB_CHANGE_DISABLE_CLARS:
  case SUPER_ACTION_GLOB_CHANGE_DISABLE_TEAM_CLARS:
  case SUPER_ACTION_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK:
  case SUPER_ACTION_GLOB_CHANGE_IGNORE_COMPILE_ERRORS:
  case SUPER_ACTION_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW:
  case SUPER_ACTION_GLOB_CHANGE_IGNORE_DUPICATED_RUNS:
  case SUPER_ACTION_GLOB_CHANGE_REPORT_ERROR_CODE:
  case SUPER_ACTION_GLOB_CHANGE_SHOW_DEADLINE:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_PRINTING:
  case SUPER_ACTION_GLOB_CHANGE_PRUNE_EMPTY_USERS:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_FULL_ARCHIVE:
  case SUPER_ACTION_GLOB_CHANGE_TEST_DIR:
  case SUPER_ACTION_GLOB_CLEAR_TEST_DIR:
  case SUPER_ACTION_GLOB_CHANGE_CORR_DIR:
  case SUPER_ACTION_GLOB_CLEAR_CORR_DIR:
  case SUPER_ACTION_GLOB_CHANGE_INFO_DIR:
  case SUPER_ACTION_GLOB_CLEAR_INFO_DIR:
  case SUPER_ACTION_GLOB_CHANGE_TGZ_DIR:
  case SUPER_ACTION_GLOB_CLEAR_TGZ_DIR:
  case SUPER_ACTION_GLOB_CHANGE_CHECKER_DIR:
  case SUPER_ACTION_GLOB_CLEAR_CHECKER_DIR:
  case SUPER_ACTION_GLOB_CHANGE_CONTEST_START_CMD:
  case SUPER_ACTION_GLOB_CLEAR_CONTEST_START_CMD:
  case SUPER_ACTION_GLOB_CHANGE_MAX_RUN_SIZE:
  case SUPER_ACTION_GLOB_CHANGE_MAX_RUN_TOTAL:
  case SUPER_ACTION_GLOB_CHANGE_MAX_RUN_NUM:
  case SUPER_ACTION_GLOB_CHANGE_MAX_CLAR_SIZE:
  case SUPER_ACTION_GLOB_CHANGE_MAX_CLAR_TOTAL:
  case SUPER_ACTION_GLOB_CHANGE_MAX_CLAR_NUM:
  case SUPER_ACTION_GLOB_CHANGE_TEAM_PAGE_QUOTA:
  case SUPER_ACTION_GLOB_CHANGE_TEAM_INFO_URL:
  case SUPER_ACTION_GLOB_CLEAR_TEAM_INFO_URL:
  case SUPER_ACTION_GLOB_CHANGE_PROB_INFO_URL:
  case SUPER_ACTION_GLOB_CLEAR_PROB_INFO_URL:
  case SUPER_ACTION_GLOB_CHANGE_STAND_FILE_NAME:
  case SUPER_ACTION_GLOB_CLEAR_STAND_FILE_NAME:
  case SUPER_ACTION_GLOB_CHANGE_USERS_ON_PAGE:
  case SUPER_ACTION_GLOB_CHANGE_STAND_HEADER_FILE:
  case SUPER_ACTION_GLOB_CLEAR_STAND_HEADER_FILE:
  case SUPER_ACTION_GLOB_CHANGE_STAND_FOOTER_FILE:
  case SUPER_ACTION_GLOB_CLEAR_STAND_FOOTER_FILE:
  case SUPER_ACTION_GLOB_CHANGE_STAND_SYMLINK_DIR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_SYMLINK_DIR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_IGNORE_AFTER:
  case SUPER_ACTION_GLOB_CLEAR_CONTEST_FINISH_TIME:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_STAND2:
  case SUPER_ACTION_GLOB_CHANGE_STAND2_FILE_NAME:
  case SUPER_ACTION_GLOB_CLEAR_STAND2_FILE_NAME:
  case SUPER_ACTION_GLOB_CHANGE_STAND2_HEADER_FILE:
  case SUPER_ACTION_GLOB_CLEAR_STAND2_HEADER_FILE:
  case SUPER_ACTION_GLOB_CHANGE_STAND2_FOOTER_FILE:
  case SUPER_ACTION_GLOB_CLEAR_STAND2_FOOTER_FILE:
  case SUPER_ACTION_GLOB_CHANGE_STAND2_SYMLINK_DIR:
  case SUPER_ACTION_GLOB_CLEAR_STAND2_SYMLINK_DIR:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_PLOG:
  case SUPER_ACTION_GLOB_CHANGE_PLOG_FILE_NAME:
  case SUPER_ACTION_GLOB_CLEAR_PLOG_FILE_NAME:
  case SUPER_ACTION_GLOB_CHANGE_PLOG_HEADER_FILE:
  case SUPER_ACTION_GLOB_CLEAR_PLOG_HEADER_FILE:
  case SUPER_ACTION_GLOB_CHANGE_PLOG_FOOTER_FILE:
  case SUPER_ACTION_GLOB_CLEAR_PLOG_FOOTER_FILE:
  case SUPER_ACTION_GLOB_CHANGE_PLOG_SYMLINK_DIR:
  case SUPER_ACTION_GLOB_CLEAR_PLOG_SYMLINK_DIR:
  case SUPER_ACTION_GLOB_CHANGE_PLOG_UPDATE_TIME:
  case SUPER_ACTION_GLOB_CHANGE_STAND_TABLE_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_TABLE_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_PLACE_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_PLACE_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_TEAM_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_TEAM_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_PROB_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_PROB_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_SOLVED_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_SOLVED_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_SCORE_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_SCORE_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_PENALTY_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_PENALTY_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_SHOW_OK_TIME:
  case SUPER_ACTION_GLOB_CHANGE_STAND_SHOW_ATT_NUM:
  case SUPER_ACTION_GLOB_CHANGE_STAND_SORT_BY_SOLVED:
  case SUPER_ACTION_GLOB_CHANGE_IGNORE_SUCCESS_TIME:
  case SUPER_ACTION_GLOB_CHANGE_STAND_TIME_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_TIME_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_SUCCESS_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_SUCCESS_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_FAIL_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_FAIL_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_TRANS_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_TRANS_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_SELF_ROW_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_SELF_ROW_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_V_ROW_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_V_ROW_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_R_ROW_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_R_ROW_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_U_ROW_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_U_ROW_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_EXTRA_COL:
  case SUPER_ACTION_GLOB_CHANGE_STAND_EXTRA_FORMAT:
  case SUPER_ACTION_GLOB_CLEAR_STAND_EXTRA_FORMAT:
  case SUPER_ACTION_GLOB_CHANGE_STAND_EXTRA_LEGEND:
  case SUPER_ACTION_GLOB_CLEAR_STAND_EXTRA_LEGEND:
  case SUPER_ACTION_GLOB_CHANGE_STAND_EXTRA_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_EXTRA_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER:
  case SUPER_ACTION_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_SLEEP_TIME:
  case SUPER_ACTION_GLOB_CHANGE_SERVE_SLEEP_TIME:
  case SUPER_ACTION_GLOB_CHANGE_AUTOUPDATE_STANDINGS:
  case SUPER_ACTION_GLOB_CHANGE_ROUNDING_MODE:
  case SUPER_ACTION_GLOB_CHANGE_MAX_FILE_LENGTH:
  case SUPER_ACTION_GLOB_CHANGE_MAX_LINE_LENGTH:
  case SUPER_ACTION_GLOB_CHANGE_INACTIVITY_TIMEOUT:
  case SUPER_ACTION_GLOB_CHANGE_DISABLE_AUTO_TESTING:
  case SUPER_ACTION_GLOB_CHANGE_DISABLE_TESTING:
  case SUPER_ACTION_GLOB_CHANGE_CR_SERIALIZATION_KEY:
  case SUPER_ACTION_GLOB_CHANGE_SHOW_ASTR_TIME:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_CONTINUE:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_REPORT_UPLOAD:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_RUNLOG_MERGE:
  case SUPER_ACTION_GLOB_CHANGE_USE_COMPILATION_SERVER:
  case SUPER_ACTION_GLOB_CHANGE_SECURE_RUN:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_ROW_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_ROW_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_CUR_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_CUR_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_ROW_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_ROW_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_STAND_PAGE_COL_ATTR:
  case SUPER_ACTION_GLOB_CLEAR_STAND_PAGE_COL_ATTR:
  case SUPER_ACTION_GLOB_CHANGE_ENABLE_L10N:
  case SUPER_ACTION_GLOB_CHANGE_CHARSET:
  case SUPER_ACTION_GLOB_CLEAR_CHARSET:
  case SUPER_ACTION_GLOB_CHANGE_TEAM_DOWNLOAD_TIME:
  case SUPER_ACTION_GLOB_DISABLE_TEAM_DOWNLOAD_TIME:
  case SUPER_ACTION_GLOB_CHANGE_CPU_BOGOMIPS:
  case SUPER_ACTION_GLOB_DETECT_CPU_BOGOMIPS:

  case SUPER_ACTION_GLOB_SAVE_CONTEST_START_CMD:
  case SUPER_ACTION_GLOB_READ_CONTEST_START_CMD:
  case SUPER_ACTION_GLOB_CLEAR_CONTEST_START_CMD_TEXT:
  case SUPER_ACTION_GLOB_SAVE_STAND_HEADER:
  case SUPER_ACTION_GLOB_READ_STAND_HEADER:
  case SUPER_ACTION_GLOB_CLEAR_STAND_HEADER_TEXT:
  case SUPER_ACTION_GLOB_SAVE_STAND_FOOTER:
  case SUPER_ACTION_GLOB_READ_STAND_FOOTER:
  case SUPER_ACTION_GLOB_CLEAR_STAND_FOOTER_TEXT:
  case SUPER_ACTION_GLOB_SAVE_STAND2_HEADER:
  case SUPER_ACTION_GLOB_READ_STAND2_HEADER:
  case SUPER_ACTION_GLOB_CLEAR_STAND2_HEADER_TEXT:
  case SUPER_ACTION_GLOB_SAVE_STAND2_FOOTER:
  case SUPER_ACTION_GLOB_READ_STAND2_FOOTER:
  case SUPER_ACTION_GLOB_CLEAR_STAND2_FOOTER_TEXT:
  case SUPER_ACTION_GLOB_SAVE_PLOG_HEADER:
  case SUPER_ACTION_GLOB_READ_PLOG_HEADER:
  case SUPER_ACTION_GLOB_CLEAR_PLOG_HEADER_TEXT:
  case SUPER_ACTION_GLOB_SAVE_PLOG_FOOTER:
  case SUPER_ACTION_GLOB_READ_PLOG_FOOTER:
  case SUPER_ACTION_GLOB_CLEAR_PLOG_FOOTER_TEXT:
    action_set_param(action_to_cmd_map[client_action],
                     next_action_map[client_action]);
    break;

  case SUPER_ACTION_PROB_CHANGE_VARIANTS:
  case SUPER_ACTION_PROB_DELETE_VARIANTS:
    action_variant_param(action_to_cmd_map[client_action],
                         next_action_map[client_action]);
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
