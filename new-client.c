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

#include "new_server_proto.h"
#include "new_server_clnt.h"
#include "pathutl.h"
#include "cgi.h"
#include "clntutil.h"
#include "errlog.h"
#include "parsecfg.h"
#include "xml_utils.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

enum { MAX_ATTEMPT = 10 };

struct section_global_data
{
  struct generic_section_config g;

  int enable_l10n;
  int connect_attempts;

  path_t l10n_dir;
  path_t charset;
  path_t new_server_socket;
  char **access;
};

static void global_init_func(struct generic_section_config *gp);

#define GLOBAL_OFFSET(x)   XOFFSET(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(charset, "s"),
  GLOBAL_PARAM(new_server_socket, "s"),
  GLOBAL_PARAM(access, "x"),

  { 0, 0, 0, 0 }
};

static struct config_section_info params[] =
{
  { "global" ,sizeof(struct section_global_data), section_global_params,
    0, global_init_func },
  { NULL, 0, NULL }
};

static struct generic_section_config *config;
static struct section_global_data    *global;
static unsigned char *client_charset = 0;
static int ssl_flag = 0;
static ej_ip_t client_ip;

static void
global_init_func(struct generic_section_config *gp)
{
  struct section_global_data *p = (struct section_global_data *) gp;

  p->enable_l10n = -1;
  p->connect_attempts = -1;
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

static int
check_access_rules(char **rules, ej_ip_t ip, int ssl_flag)
{
  int i, r, n, mode, ssl_mode;
  unsigned char *s;
  unsigned char b1[1024];
  unsigned char b2[1024];
  unsigned char b3[1024];
  ej_ip_t cur_ip, cur_mask;

  if (!rules) return 0;
  for (i = 0; rules[i]; i++) {
    s = (unsigned char*) rules[i];
    r = sscanf(s, "%1000s%1000s%1000s%n", b1, b2, b3, &n);
    while (isspace(s[n])) n++;
    if (s[n] || r < 2) goto failed;
    if (!strcasecmp(b1, "allow")) {
      mode = 0;
    } else if (!strcasecmp(b1, "deny")) {
      mode = -1;
    } else goto failed;
    if (xml_parse_ip_mask(0, -1, 0, b2, &cur_ip, &cur_mask) < 0) goto failed;
    ssl_mode = -1;
    if (r == 3) {
      if (!strcasecmp(b3, "ssl")) {
        ssl_mode = 1;
      } else if (!strcasecmp(b3, "nossl")) {
        ssl_mode = 0;
      } else goto failed;
    }

    if ((ip & cur_mask) == cur_ip && (ssl_mode < 0 || ssl_flag == ssl_mode))
      return mode;
  }
  return 0;

 failed:
  client_not_configured(client_charset, "invalid access rules", 0);
  return -1;
}

static void
initialize(int argc, char *argv[])
{
  path_t full_path;
  path_t dir_path;
  path_t base_name;
  path_t cfg_dir;
  path_t cfg_path;
  unsigned char *s;
  struct generic_section_config *p;

  if (getenv("SSL_PROTOCOL") || getenv("HTTPS")) {
    ssl_flag = 1;
  }
  client_ip = parse_client_ip();

  s = getenv("SCRIPT_FILENAME");
  if (!s) s = argv[0];
  if (!s) s = "";
  snprintf(full_path, sizeof(full_path), "%s", s);
  os_rDirName(full_path, dir_path, PATH_MAX);
  os_rGetBasename(full_path, base_name, PATH_MAX);

#if defined CGI_DATA_PATH
  if (CGI_DATA_PATH[0] == '/') {
    snprintf(cfg_dir, sizeof(cfg_dir), "%s/", CGI_DATA_PATH);
  } else {
    snprintf(cfg_dir, sizeof(cfg_dir), "%s/%s/", dir_path, CGI_DATA_PATH);
  }
#else
  snprintf(cfg_dir, sizeof(cfg_dir), "%s/../cgi-data/", dir_path);
#endif

  snprintf(cfg_path, sizeof(cfg_path), "%s%s.cfg", cfg_dir, base_name);

  if (!check_config_exist(cfg_path)) {
    config = param_make_global_section(params);
  } else {
    config = parse_param(cfg_path, 0, params, 1, 0, 0, 0);
  }
  if (!config) client_not_configured(0, "config file not parsed", 0);

  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  }
  if (!p) client_not_configured(0, "no global section", 0);
  global = (struct section_global_data *) p;

#if defined EJUDGE_NEW_SERVER_SOCKET
  if (!global->new_server_socket[0]) {
    snprintf(global->new_server_socket, sizeof(global->new_server_socket),
             "%s", EJUDGE_NEW_SERVER_SOCKET);
  }
#endif
  if (!global->new_server_socket[0]) {
    snprintf(global->new_server_socket, sizeof(global->new_server_socket),
             "%s", EJUDGE_NEW_SERVER_SOCKET_DEFAULT);
  }
#if defined EJUDGE_CHARSET
  if (!global->charset[0]) {
    snprintf(global->charset, sizeof(global->charset),
             "%s", EJUDGE_CHARSET);
  }
#endif
  if (global->charset) client_charset = global->charset;
  if (global->connect_attempts <= 0)
    global->connect_attempts = MAX_ATTEMPT;

  if (global->access) {
    if (check_access_rules(global->access, client_ip, ssl_flag) < 0)
      client_access_denied(client_charset, 0);
  }

  cgi_read(client_charset);
}

int
main(int argc, char *argv[])
{
  new_server_conn_t conn = 0;
  int r, param_num, i, attempt;
  unsigned char **param_names, **params;
  size_t *param_sizes;

  logger_set_level(-1, LOG_WARNING);
  initialize(argc, argv);

  for (attempt = 0; attempt < global->connect_attempts; attempt++) {
    r = new_server_clnt_open(global->new_server_socket, &conn);
    if (r >= 0 || r != -NEW_SRV_ERR_CONNECT_FAILED) break;
    sleep(1);
  }

  if (r < 0) {
    err("new-client: cannot connect to the server: %d", -r);
    client_not_configured(client_charset, "cannot connect to the server", 0);
  }

  param_num = cgi_get_param_num();
  XALLOCAZ(param_names, param_num);
  XALLOCAZ(param_sizes, param_num);
  XALLOCAZ(params, param_num);
  for (i = 0; i < param_num; i++) {
    cgi_get_nth_param_bin(i, &param_names[i], &param_sizes[i], &params[i]);
  }

  r = new_server_clnt_http_request(conn, 1, (unsigned char**) argv,
                                   (unsigned char **) environ,
                                   param_num, param_names,
                                   param_sizes, params, 0, 0);
  if (r < 0) {
    err("new-client: http_request failed: %d", -r);
    client_not_configured(client_charset, "request failed", 0);
  }

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
