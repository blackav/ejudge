/* -*- mode: c -*- */

/* Copyright (C) 2004-2021 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/expat_iface.h"
#include "ejudge/xml_utils.h"
#include "ejudge/pathutl.h"
#include "ejudge/clntutil.h"
#include "ejudge/contests.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/cgi.h"
#include "ejudge/userlist.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/super_clnt.h"
#include "ejudge/super_proto.h"
#include "ejudge/compat.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>

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
#define DEFAULT_CHARSET              "utf-8"
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
  ej_ip_t addr;
  ej_ip_t mask;
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
  [TG_CONFIG] = sizeof(struct config_node),
  [TG_SERVE_CONTROL_ACCESS] = sizeof(struct access_node),
  [TG_IP] = sizeof(struct ip_node),
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
    tree = xml_build_tree_str(NULL, default_config, &serve_control_config_parse_spec);
  } else {
    tree = xml_build_tree(NULL, path, &serve_control_config_parse_spec);
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
        if (xml_elem_ipv6_mask(t2, &pip->addr, &pip->mask) < 0) goto failed;
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
  if (!cfg->charset) cfg->charset = "utf-8";

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
static unsigned char *http_host;
static unsigned char *self_url;
static int ssl_flag;
static int super_serve_fd = -1;
static int priv_level;
static int client_action;
static unsigned char hidden_vars[1024];
static ej_cookie_t client_key;

static void operation_status_page(int userlist_code,
                                  int super_code,
                                  const unsigned char *format,
                                  ...) __attribute__((noreturn));

static void
make_self_url(void)
{
  unsigned char *script_name = getenv("SCRIPT_NAME");
  unsigned char fullname[1024];
  unsigned char *protocol = "http";

  http_host = getenv("HTTP_HOST");
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
parse_cookie(void)
{
  const unsigned char *cookies = getenv("HTTP_COOKIE");
  if (!cookies) return;
  const unsigned char *s = cookies;
  while (1) {
    while (isspace(*s)) ++s;
    if (strncmp(s, "EJSID=", 6) != 0) {
      while (*s && *s != ';') ++s;
      if (!*s) return;
      ++s;
      continue;
    }
    int n = 0;
    if (sscanf(s + 6, "%llx%n", &client_key, &n) == 1) {
      s += 6 + n;
      if (!*s || isspace(*s) || *s == ';') {
        // debug
        //fprintf(stderr, "client_key = %016llx\n", client_key);
        return;
      }
    }
    client_key = 0;
    return;
  }
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
  os_rGetLastname(full_path, base_name, PATH_MAX);

#if defined CGI_PROG_SUFFIX
  snprintf(exp_base, sizeof(exp_base),"%s%s","serve-control", CGI_PROG_SUFFIX);
#else
  snprintf(exp_base, sizeof(exp_base), "%s", "serve-control");
#endif
  if (strcmp(exp_base, base_name) != 0) {
    client_not_configured(0, "bad program name", 0, 0);
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
    client_not_configured(0, "config file not parsed", 0, 0);
  }

  if (contests_set_directory(config->contests_dir) < 0) {
    client_not_configured(0, "contests directory is invalid", 0, 0);
  }
  logger_set_level(-1, LOG_WARNING);

  cgi_read(0);
  parse_client_ip(&user_ip);
  parse_cookie();

  make_self_url();
  client_make_form_headers(self_url);
}

static int
check_source_ip(void)
{
  struct ip_node *p;

  if (!config) return 0;
  if (!config->access) return 0;
  //if (!user_ip) return config->access->default_is_allow;

  for (p = (struct ip_node*) config->access->b.first_down;
       p; p = (struct ip_node*) p->b.right) {
    if (ipv6_match_mask(&p->addr, &p->mask, &user_ip)
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
                      NULL_CLIENT_KEY,
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
                      NULL_CLIENT_KEY,
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
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    NULL_CLIENT_KEY, _("Server error"));
  printf("<p>Server error: %s</p>", userlist_strerror(-r));
  client_put_footer(stdout, 0);
  exit(0);
}

static void permission_denied(void) __attribute__((noreturn));
static void
permission_denied(void)
{
  client_put_header(stdout,0,0,config->charset,1,0,
                    NULL_CLIENT_KEY, _("Permission denied"));
  printf("<p>%s</p>", _("You do not have permissions to use this service"));
  client_put_footer(stdout, 0);
  exit(0);
}

static void invalid_login(void) __attribute__((noreturn));
static void
invalid_login(void)
{
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    NULL_CLIENT_KEY,
                    _("Invalid login"));
  printf("<p>%s</p>",
         "Invalid login. You have typed invalid login, invalid password,"
         " or have a banned IP-address.");
  client_put_footer(stdout, 0);
  exit(0);
}

static void read_state_params(void);
static void display_login_page(char *argv[]) __attribute__((noreturn));
static void
display_login_page(char *argv[])
{
  int param_num, i, r;
  unsigned char **param_names, **params;
  size_t *param_sizes;

  read_state_params();
  open_super_server();

  param_num = cgi_get_param_num();
  XALLOCAZ(param_names, param_num + 1);
  XALLOCAZ(param_sizes, param_num + 1);
  XALLOCAZ(params, param_num + 1);
  for (i = 0; i < param_num; i++) {
    cgi_get_nth_param_bin(i, &param_names[i], &param_sizes[i], &params[i]);
  }

  ++param_num;
  param_names[i] = "login_page";
  param_sizes[i] = 1;
  params[i] = "1";

  r = super_clnt_http_request(super_serve_fd, 1, (unsigned char**) argv,
                              (unsigned char **) environ,
                              param_num, param_names,
                              param_sizes, params, 0, 0);
  if (r < 0) {
    operation_status_page(-1, -1, "Invalid request");
  }

  exit(0);

  /*
  client_put_header(stdout, 0, 0, config->charset, 1, 0,
                    NULL_CLIENT_KEY, "serve-control: %s", http_host);

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
  */
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
parse_action(void)
{
  unsigned char *s = cgi_param("action");
  if (!s || !*s) return;
  unsigned char *q;
  for (q = s; isdigit(*q); ++q) {}
  if (!*q) {
    char *eptr = NULL;
    errno = 0;
    long val = strtol(s, &eptr, 10);
    if (!errno && !*eptr && val > 0 && val < SSERV_CMD_LAST) {
      client_action = val;
    }
    return;
  }
  for (int i = 1; i < SSERV_CMD_LAST; ++i) {
    if (super_proto_cmd_names[i] && !strcasecmp(super_proto_cmd_names[i], s)) {
      client_action = i;
      return;
    }
  }
}

static void
read_state_params(void)
{
  unsigned char *s;
  int x, n;

  client_action = 0;
  parse_action();
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
client_put_refresh_header(
        unsigned char const *coding,
        unsigned char const *url,
        int interval,
        unsigned char const *format, ...)
{
  /*
  va_list args;

  if (!coding) coding = DEFAULT_CHARSET;

  va_start(args, format);
  fprintf(stdout, "Content-Type: text/html; charset=%s\nCache-Control: no-cache\nPragma: no-cache\n\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><meta http-equiv=\"Refresh\" content=\"%d; url=%s\"><title>\n", coding, coding, interval, url);
  vfprintf(stdout, format, args);
  fputs("\n</title></head><body><h1>\n", stdout);
  vfprintf(stdout, format, args);
  fputs("\n</h1>\n", stdout);
  */
  if (client_key) {
    printf("Set-Cookie: EJSID=%016llx; Path=/; SameSite=Lax\n", client_key);
  }
  printf("Location: %s\n\n", url);
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
    client_put_header(stdout, 0, 0, config->charset, 1, 0, NULL_CLIENT_KEY, "Operation failed");
    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);
    printf("<h2><font color=\"red\">%s</font></h2>\n", msg);
    client_put_footer(stdout, 0);
    exit(0);
  }
  if (userlist_code == -1 && super_code < -1) {
    client_put_header(stdout, 0, 0, config->charset, 1, 0, NULL_CLIENT_KEY, "Operation failed");
    printf("<h2><font color=\"red\">super-serve error: %s</font></h2>\n",
           super_proto_strerror(-super_code));
    client_put_footer(stdout, 0);
    exit(0);
  }
  if (userlist_code < -1 && super_code == -1) {
    client_put_header(stdout, 0, 0, config->charset, 1, 0, NULL_CLIENT_KEY, "Operation failed");
    printf("<h2><font color=\"red\">userlist-server error: %s</font></h2>\n",
           userlist_strerror(-userlist_code));
    client_put_footer(stdout, 0);
    exit(0);
  }
  if (userlist_code < -1 && super_code < -1) {
    client_put_header(stdout, 0, 0, config->charset, 1, 0, NULL_CLIENT_KEY, "Operation failed");
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
authentificate(char *argv[])
{
  int r;
  unsigned char buf[512];

  if (get_session_id("SID", &session_id) && client_key) {
    open_userlist_server();
    r = userlist_clnt_priv_cookie(userlist_conn, &user_ip, ssl_flag,
                                  0, /* contest_id */
                                  session_id,
                                  client_key,
                                  -1,
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
  if (!user_login || !user_password) display_login_page(argv);

  open_userlist_server();
  r = userlist_clnt_priv_login(userlist_conn, ULS_PRIV_LOGIN, &user_ip,
                               client_key,
                               ssl_flag,
                               0, /* contest_id */
                               0, /* locale_id */
                               USER_ROLE_ADMIN,
                               user_login,
                               user_password,
                               &user_id,
                               &session_id,
                               &client_key,
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

static const int ip_param_next_state[] =
{
  SSERV_CMD_CNTS_EDIT_REGISTER_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_USERS_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_MASTER_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_JUDGE_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_TEAM_ACCESS_PAGE,
  SSERV_CMD_CNTS_EDIT_SERVE_CONTROL_ACCESS_PAGE,
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
  "0110100110000000001111111001100100010000000000000000000000000000", // judge
  "1111111111111111111111111111111111110000000000000000000000000000", // master
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
      || s[n] || lang_id <= 0 || lang_id > EJ_MAX_LANG_ID)
    goto invalid_parameter;

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
      || s[n] || prob_id < -EJ_MAX_PROB_ID || prob_id > EJ_MAX_PROB_ID)
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
      || s[n] || prob_id < -EJ_MAX_PROB_ID || prob_id > EJ_MAX_PROB_ID)
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
      || s[n] || row < 0 || row > EJ_MAX_USER_ID)
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
        || s[n] || r < 0 || r > EJ_MAX_USER_ID)
      goto invalid_parameter;
    fprintf(param_f, " %d", r);
  }
  close_memstream(param_f); param_f = 0;
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
        || prob_id < 0 || prob_id > EJ_MAX_PROB_ID)
      goto invalid_parameter;
  }

  open_super_server();
  r = super_clnt_set_param(super_serve_fd, cmd, prob_id, 0, 0, 0, 0);
  operation_status_page(-1, r, "action=%d", next_state);

 invalid_parameter:
  operation_status_page(-1, -1, "Invalid parameter");
}

static void action_http_request(char **argv)
  __attribute__((noreturn));
static void
action_http_request(char **argv)
{
  int param_num, i, r;
  unsigned char **param_names, **params;
  size_t *param_sizes;

  open_super_server();

  param_num = cgi_get_param_num();
  XALLOCAZ(param_names, param_num);
  XALLOCAZ(param_sizes, param_num);
  XALLOCAZ(params, param_num);
  for (i = 0; i < param_num; i++) {
    cgi_get_nth_param_bin(i, &param_names[i], &param_sizes[i], &params[i]);
  }

  r = super_clnt_http_request(super_serve_fd, 1, (unsigned char**) argv,
                              (unsigned char **) environ,
                              param_num, param_names,
                              param_sizes, params, 0, 0);
  if (r < 0) {
    operation_status_page(-1, -1, "Invalid request");
  }

  exit(0);
}

static const int next_action_map[SSERV_CMD_LAST] =
{
  [SSERV_CMD_OPEN_CONTEST] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_CLOSE_CONTEST] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_CLEAR_MESSAGES] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_VISIBLE_CONTEST] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_INVISIBLE_CONTEST] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_LOG_TRUNC] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_LOG_DEV_NULL] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_LOG_FILE] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_MNG_TERM] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_CONTEST_RESTART] = SSERV_CMD_CONTEST_PAGE,
  [SSERV_CMD_RUN_MNG_RESET_ERROR] = SSERV_CMD_CONTEST_PAGE,

  [SSERV_CMD_CNTS_DELETE_PERMISSION] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_CNTS_ADD_PERMISSION] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_CNTS_SAVE_PERMISSIONS] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_CNTS_SET_PREDEF_PERMISSIONS] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_CNTS_SAVE_FORM_FIELDS] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_CNTS_SAVE_COACH_FIELDS] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_CNTS_SAVE_GUEST_FIELDS] = SSERV_CMD_CNTS_EDIT_CUR_CONTEST_PAGE,
  [SSERV_CMD_LANG_SHOW_DETAILS] = SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE,
  [SSERV_CMD_LANG_HIDE_DETAILS] = SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE,
  [SSERV_CMD_LANG_DEACTIVATE] = SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE,
  [SSERV_CMD_LANG_ACTIVATE] = SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE,

  [SSERV_CMD_PROB_ADD] = SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE,
  [SSERV_CMD_PROB_ADD_ABSTRACT] = SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE,
  [SSERV_CMD_PROB_SHOW_DETAILS] = SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE,
  [SSERV_CMD_PROB_HIDE_DETAILS] = SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE,
  [SSERV_CMD_PROB_SHOW_ADVANCED] = SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE,
  [SSERV_CMD_PROB_HIDE_ADVANCED] = SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE,

  [SSERV_CMD_PROB_DELETE] = SSERV_CMD_CNTS_EDIT_CUR_PROBLEMS_PAGE,
  [SSERV_CMD_PROB_CHANGE_VARIANTS] = SSERV_CMD_CNTS_EDIT_CUR_VARIANT_PAGE,
  [SSERV_CMD_PROB_DELETE_VARIANTS] = SSERV_CMD_CNTS_EDIT_CUR_VARIANT_PAGE,
  [SSERV_CMD_PROB_CLEAR_VARIANTS] = SSERV_CMD_CNTS_EDIT_CUR_VARIANT_PAGE,
  [SSERV_CMD_PROB_RANDOM_VARIANTS] = SSERV_CMD_CNTS_EDIT_CUR_VARIANT_PAGE,

  [SSERV_CMD_LANG_UPDATE_VERSIONS] = SSERV_CMD_CNTS_EDIT_CUR_LANGUAGES_PAGE,
};

int
main(int argc, char *argv[])
{
  initialize(argc, argv);

  // check ip limitations from the configuration file
  if (!check_source_ip()) {
    client_access_denied(config->charset, 0);
  }

  authentificate(argv);
  read_state_params();

  if (client_action >= 0 && client_action < SSERV_CMD_LAST && super_proto_is_http_request[client_action]) {
    client_action = SSERV_CMD_HTTP_REQUEST;
  }
  switch (client_action) {
  case SSERV_CMD_OPEN_CONTEST:
  case SSERV_CMD_CLOSE_CONTEST:
  case SSERV_CMD_CLEAR_MESSAGES:
  case SSERV_CMD_VISIBLE_CONTEST:
  case SSERV_CMD_INVISIBLE_CONTEST:
  case SSERV_CMD_RUN_LOG_TRUNC:
  case SSERV_CMD_RUN_LOG_DEV_NULL:
  case SSERV_CMD_RUN_LOG_FILE:
  case SSERV_CMD_RUN_MNG_TERM:
  case SSERV_CMD_CONTEST_RESTART:
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

  case SSERV_CMD_CNTS_FORGET:
    action_simple_top_command(client_action);
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

  case SSERV_CMD_LANG_UPDATE_VERSIONS:
    action_simple_edit_command(client_action, next_action_map[client_action]);
    break;
  case SSERV_CMD_LANG_SHOW_DETAILS:
  case SSERV_CMD_LANG_HIDE_DETAILS:
  case SSERV_CMD_LANG_DEACTIVATE:
  case SSERV_CMD_LANG_ACTIVATE:
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
  case SSERV_CMD_PROB_CLEAR_VARIANTS:
  case SSERV_CMD_PROB_RANDOM_VARIANTS:
    action_prob_param(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_PROB_CHANGE_VARIANTS:
  case SSERV_CMD_PROB_DELETE_VARIANTS:
    action_variant_param(client_action, next_action_map[client_action]);
    break;

  case SSERV_CMD_HTTP_REQUEST:
    action_http_request(argv);
    break;
  }

  /* default (main) screen */
  action_http_request(argv);
  return 0;
}
