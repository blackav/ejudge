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

static unsigned char *client_charset = "UTF-8";
static int connect_attempts = MAX_ATTEMPT;
static const unsigned char *new_server_socket;

static void
initialize(int argc, char *argv[])
{
#if defined EJUDGE_NEW_SERVER_SOCKET
  new_server_socket = EJUDGE_NEW_SERVER_SOCKET;
#endif
  if (!new_server_socket || !*new_server_socket) {
    new_server_socket = EJUDGE_NEW_SERVER_SOCKET_DEFAULT;
  }

#if defined EJUDGE_CHARSET
  client_charset = EJUDGE_CHARSET;
#endif

  cgi_read(client_charset);
}

/*
static void
json_error_reply(FILE *out_f, int http_status, int error_code)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  fprintf(out_f, "Content-Type: text/json; charset=UTF-8\n"
          "Cache-Control: no-cache\n"
          "Status: %d\n"
          "Pragma: no-cache\n\n", http_status);
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
*/

static void
text_error_reply(FILE *out_f, int http_status, int error_code)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  fprintf(out_f, "Content-Type: text/plain; charset=UTF-8\n"
          "Cache-Control: no-cache\n"
          "Status: %d\n"
          "Pragma: no-cache\n\n", http_status);
  fprintf(out_f, "Error %d\n", error_code);
  html_armor_free(&ab);
}

int
main(int argc, char *argv[])
{
  new_server_conn_t conn = 0;
  int r = 0, param_num, attempt;
  unsigned char **param_names, **params;
  size_t *param_sizes;

  FILE *log_f = 0;
  char *log_t = 0;
  size_t log_z = 0;

  logger_set_level(-1, LOG_WARNING);
  initialize(argc, argv);

  param_num = cgi_get_param_num();
  XALLOCAZ(param_names, param_num);
  XALLOCAZ(param_sizes, param_num);
  XALLOCAZ(params, param_num);

  for (int i = 0; i < param_num; i++) {
    cgi_get_nth_param_bin(i, &param_names[i], &param_sizes[i], &params[i]);
  }
  for (attempt = 0; attempt < connect_attempts; attempt++) {
    r = new_server_clnt_open(new_server_socket, &conn);
    if (r >= 0 || r != -NEW_SRV_ERR_CONNECT_FAILED) break;
    sleep(1);
  }

  if (r < 0) {
    err("new-client: cannot connect to the server: %d", -r);
    text_error_reply(stdout, 503, -r);
    return 0;
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
    text_error_reply(stdout, 500, -r);
    return 0;
  }

  return 0;
}
