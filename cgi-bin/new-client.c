/* -*- mode: c -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/new_server_proto.h"
#include "ejudge/new_server_clnt.h"
#include "ejudge/pathutl.h"
#include "ejudge/cgi.h"
#include "ejudge/clntutil.h"
#include "ejudge/errlog.h"
#include "ejudge/parsecfg.h"
#include "ejudge/xml_utils.h"
#include "ejudge/misctext.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

enum { MAX_ATTEMPT = 10 };

struct client_section_global_data
{
  struct generic_section_config g;

  int enable_l10n;

  path_t l10n_dir;
  path_t new_server_socket;
  char **access;
};

static void global_init_func(struct generic_section_config *gp);

#define GLOBAL_OFFSET(x)   XOFFSET(struct client_section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x) }
static struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(new_server_socket, "s"),
  GLOBAL_PARAM(access, "x"),

  { 0, 0, 0, 0 }
};

static struct config_section_info params[] =
{
  { "global" ,sizeof(struct client_section_global_data), section_global_params,
    0, global_init_func },
  { NULL, 0, NULL }
};

static struct generic_section_config *config;
static struct client_section_global_data    *global;
static unsigned char *client_charset = "UTF-8";
static int connect_attempts = MAX_ATTEMPT;

static void
global_init_func(struct generic_section_config *gp)
{
  struct client_section_global_data *p = (struct client_section_global_data *) gp;

  p->enable_l10n = -1;
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
  path_t full_path;
  path_t dir_path;
  path_t base_name;
  path_t cfg_dir;
  path_t cfg_path;
  unsigned char *s;
  struct generic_section_config *p;

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
  if (!config) client_not_configured(0, "config file not parsed", 0, 0);

  for (p = config; p; p = p->next) {
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  }
  if (!p) client_not_configured(0, "no global section", 0, 0);
  global = (struct client_section_global_data *) p;

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
  client_charset = EJUDGE_CHARSET;
#endif

  cgi_read(client_charset);
}

static void
json_error_reply(FILE *out_f, int error_code)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  fprintf(out_f, "Content-Type: text/json; charset=UTF-8\n"
          "Cache-Control: no-cache\n"
          "Pragma: no-cache\n\n");
  fprintf(out_f, "{\n");
  fprintf(out_f, "  \"ok\": false");
  fprintf(out_f, ",\n  \"error\": {\n");
  fprintf(out_f, "    \"num\": %d", error_code);
  fprintf(out_f, ",\n    \"symbol\": \"%s\"", ns_error_symbol(error_code));
  const unsigned char *msg = ns_error_title_2(error_code);
  if (msg) {
    fprintf(out_f, ",\n    \"message\": \"%s\"", json_armor_buf(&ab, msg));
  }
  fprintf(out_f, "\n  }");
  fprintf(out_f, "\n}\n");
  html_armor_free(&ab);
}

int
main(int argc, char *argv[])
{
  new_server_conn_t conn = 0;
  int r = 0, param_num, i, attempt;
  unsigned char **param_names, **params;
  size_t *param_sizes;
  int json_mode = 0;

  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;

  logger_set_level(-1, LOG_WARNING);
  initialize(argc, argv);

  param_num = cgi_get_param_num();
  XALLOCAZ(param_names, param_num);
  XALLOCAZ(param_sizes, param_num);
  XALLOCAZ(params, param_num);
  for (i = 0; i < param_num; i++) {
    cgi_get_nth_param_bin(i, &param_names[i], &param_sizes[i], &params[i]);
    if (!strcmp(param_names[i], "json") && !strcmp(params[i], "1")) {
      json_mode = 1;
    }
  }

  for (attempt = 0; attempt < connect_attempts; attempt++) {
    r = new_server_clnt_open(global->new_server_socket, &conn);
    if (r >= 0 || r != -NEW_SRV_ERR_CONNECT_FAILED) break;
    sleep(1);
  }

  if (r < 0) {
    err("new-client: cannot connect to the server: %d", -r);
    if (json_mode) {
      json_error_reply(stdout, -r);
      return 0;
    } else {
      client_not_configured(client_charset, "cannot connect to the server", 0,0);
    }
  }

  log_f = open_memstream(&log_t, &log_z);

  r = new_server_clnt_http_request(conn, log_f, 1, (unsigned char**) argv,
                                   (unsigned char **) environ,
                                   param_num, param_names,
                                   param_sizes, params, 0, 0);
  if (log_f) {
    fclose(log_f);
    log_f = 0;
  }
  if (r < 0) {
    err("new-client: http_request failed: %d", -r);
    if (json_mode) {
      json_error_reply(stdout, -r);
    } else {
      client_not_configured(client_charset, "request failed", 0, log_t);
    }
  }

  return 0;
}
