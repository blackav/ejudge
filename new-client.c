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

#include "new_serve_proto.h"
#include "new_serve_clnt.h"
#include "pathutl.h"
#include "cgi.h"
#include "clntutil.h"
#include "errlog.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>

#include <stdio.h>

static const unsigned char *socket_path = "/tmp/new-serve-socket";

static void
initialize(int argc, char *argv[])
{
  path_t full_path;
  path_t dir_path;
  path_t base_name;
  path_t cfg_dir;
  path_t cfg_path;
  unsigned char *s;

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

  /*
  if (check_config_exist(cfg_path)) {
    config = parse_config(cfg_path, 0);
  } else {
    config = parse_config(0, default_config);
  }
  if (!config) {
    client_not_configured(0, "config file not parsed", 0);
  }
  */

  cgi_read(0);
}

extern unsigned char **environ;

int
main(int argc, char *argv[])
{
  new_serve_conn_t conn = 0;
  int r, param_num, i;
  unsigned char **param_names, **params;
  size_t *param_sizes;

  initialize(argc, argv);

  if ((r = new_serve_clnt_open(socket_path, &conn)) < 0) {
    err("new-client: cannot connect to the server: %d", -r);
    client_not_configured(0, "cannot connect to the server", 0);
  }

  param_num = cgi_get_param_num();
  XALLOCAZ(param_names, param_num);
  XALLOCAZ(param_sizes, param_num);
  XALLOCAZ(params, param_num);
  for (i = 0; i < param_num; i++) {
    cgi_get_nth_param_bin(i, &param_names[i], &param_sizes[i], &params[i]);
  }

  r = new_serve_clnt_http_request(conn, 1, (unsigned char**) argv, environ,
                                  param_num, param_names,
                                  param_sizes, params);
  if (r < 0) {
    err("new-client: http_request failed: %d", -r);
    client_not_configured(0, "request failed", 0);
  }

  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
