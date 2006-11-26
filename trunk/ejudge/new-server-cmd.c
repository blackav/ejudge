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
#include "version.h"

#include "ejudge_cfg.h"
#include "contests.h"
#include "pathutl.h"
#include "xml_utils.h"
#include "new_server_clnt.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

static const unsigned char *program_name = "";
static const unsigned char *program_path = "";

static void startup_error(const char *format, ...)
  __attribute__((format(printf, 1, 2), noreturn));
static void
startup_error(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n  Use --help option for help.\n", program_name,
          buf);
  exit(1);
}

static void op_error(const char *format, ...)
  __attribute__((format(printf, 1, 2), noreturn));
static void
op_error(const char *format, ...)
{
  va_list args;
  char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", program_name, buf);
  exit(1);
}

static void write_help(void) __attribute__((noreturn));
static void
write_help(void)
{
  printf("%s: new-server command line client\n"
         "Usage: %s [OPTIONS] CNTS-ID COMMAND CMD-ARGS\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "    -f CFG    specify the ejudge configuration file\n"
         "  COMMAND:\n"
         /*"    status    report the new-server status\n"*/,
         program_name, program_name);
  exit(0);
}
static void write_version(void) __attribute__((noreturn));
static void
write_version(void)
{
  printf("%s %s, compiled %s\n", program_name, compile_version, compile_date);
  exit(0);
}

static void invoke_serve_cmd(int argc, char *argv[])
  __attribute__((noreturn));
static void
invoke_serve_cmd(int argc, char *argv[])
{
  char *dn;
  path_t serve_cmd_path;
  char **args;
  int i;

  // substitute argv[0]
  if (!strchr(argv[0], '/')) {
    snprintf(serve_cmd_path, sizeof(serve_cmd_path), "serve-cmd");
  } else {
    dn = os_DirName(argv[0]);
    snprintf(serve_cmd_path, sizeof(serve_cmd_path), "%s/serve-cmd",
             dn);
  }

  XCALLOC(args, argc + 1);
  args[0] = serve_cmd_path;
  for (i = 1; i < argc; i++)
    args[i] = argv[i];
  args[i] = 0;
  execve(args[0], args, environ);
  startup_error("cannot execute serve-cmd: %s", os_ErrorMsg());
}

static struct ejudge_cfg *config;
static int contest_id;
static const struct contest_desc *cnts;
static ej_ip_t ip_address;
static int ssl_flag;
static int session_mode;
static const unsigned char *script_name = 0;
static const unsigned char *http_host = 0;
static const unsigned char *socket_path = 0;
static int use_reply_buf = 0;
static unsigned char *reply_buf;
static size_t reply_size;

static unsigned char **cgi_environ = 0;
static int cgi_environ_a = 0;
static int cgi_environ_u = 0;

static int cgi_param_u = 0, cgi_param_a = 0;
static unsigned char **cgi_param_names = 0;
static size_t *cgi_param_sizes = 0;
static unsigned char **cgi_param_values = 0;

static void
put_cgi_environ(const unsigned char *name, const unsigned char *value)
{
  size_t slen, nlen;
  int ind = 0, r, j;

  ASSERT(name && *name);
  nlen = strlen(name);

  if (!cgi_environ) {
    if (!value) return;
    cgi_environ_a = 16;
    cgi_environ_u = 0;
    XCALLOC(cgi_environ, cgi_environ_a);
  } else {
    for (ind = 0; ind < cgi_environ_u; ind++) {
      if (!(r = strncmp(name, cgi_environ[ind], nlen))) {
        if (cgi_environ[ind][nlen] != '=') break;
        // exact match
        xfree(cgi_environ[ind]); cgi_environ[ind] = 0;
        if (!value) {
          // remove
          for (j = ind; j < cgi_environ_u; j++)
            cgi_environ[j] = cgi_environ[j + 1];
          cgi_environ_u--;
          return;
        }
        slen = nlen + strlen(value) + 2;
        cgi_environ[ind] = xmalloc(slen);
        sprintf(cgi_environ[ind], "%s=%s", name, value);
        return;
      } else if (r > 0) {
        break;
      }
    }
    // ind - place to insert
    if (!value) return;
  }
  if (cgi_environ_u + 1 >= cgi_environ_a) {
    if (!cgi_environ_a) cgi_environ_a = 8;
    cgi_environ_a *= 2;
    cgi_environ = xrealloc(cgi_environ, cgi_environ_a * sizeof(cgi_environ[0]));
  }
  for (j = cgi_environ_u; j >= ind; j--)
    cgi_environ[j + 1] = cgi_environ[j];
  cgi_environ_u++;
  slen = nlen + strlen(value) + 2;
  cgi_environ[ind] = xmalloc(slen);
  sprintf(cgi_environ[ind], "%s=%s", name, value);
}

static void
put_cgi_param_bin(const unsigned char *name, size_t size,
                  const unsigned char *value)
{
  int ind = 0, r, j;

  ASSERT(name && *name);

  if (!cgi_param_a) {
    if (!value) return;
    cgi_param_a = 16;
    XCALLOC(cgi_param_names, cgi_param_a);
    XCALLOC(cgi_param_sizes, cgi_param_a);
    XCALLOC(cgi_param_values, cgi_param_a);
  } else {
    for (ind = 0; ind < cgi_param_u; ind++) {
      if (!(r = strcmp(name, cgi_param_names[ind]))) {
        if (!value) {
          xfree(cgi_param_names[ind]);
          xfree(cgi_param_values[ind]);
          for (j = ind; j < cgi_param_u; j++) {
            cgi_param_names[j] = cgi_param_names[j + 1];
            cgi_param_sizes[j] = cgi_param_sizes[j + 1];
            cgi_param_values[j] = cgi_param_values[j + 1];
          }
          cgi_param_u--;
          return;
        }
        xfree(cgi_param_values[ind]);
        cgi_param_sizes[ind] = size;
        cgi_param_values[ind] = xmemdup(value, size);
        return;
      } else if (r < 0) {
        break;
      }
    }
    if (!value) return;
  }
  if (cgi_param_u + 1 >= cgi_param_a) {
    cgi_param_a *= 2;
    XREALLOC(cgi_param_names, cgi_param_a);
    XREALLOC(cgi_param_sizes, cgi_param_a);
    XREALLOC(cgi_param_values, cgi_param_a);
  }
  for (j = cgi_param_u; j >= ind; j--) {
    cgi_param_names[j + 1] = cgi_param_names[j];
    cgi_param_sizes[j + 1] = cgi_param_sizes[j];
    cgi_param_values[j + 1] = cgi_param_values[j];
  }
  cgi_param_u++;
  cgi_param_names[ind] = xstrdup(name);
  cgi_param_sizes[ind] = size;
  cgi_param_values[ind] = xmemdup(value, size);
}

static void
create_cgi_environ(void)
{
  /* create CGI environment:
   *   HTTP_HOST
   *   REMOTE_ADDR
   *   SCRIPT_FILENAME - cannot be forged, always new-server-cmd
   *   SCRIPT_NAME
   *   SSL_PROTOCOL
   */

  if (!http_host || !*http_host) http_host = "localhost";
  put_cgi_environ("HTTP_HOST", http_host);
  if (!ip_address)
    put_cgi_environ("REMOTE_ADDR", "127.0.0.1");
  else
    put_cgi_environ("REMOTE_ADDR", xml_unparse_ip(ip_address));
  put_cgi_environ("SCRIPT_FILENAME", program_path);
  if (!script_name) script_name = program_path;
  put_cgi_environ("SCRIPT_NAME", script_name);
  if (ssl_flag)
    put_cgi_environ("SSL_PROTOCOL", "1");
}

static void
put_cgi_param(const unsigned char *name, const unsigned char *str)
{
  put_cgi_param_bin(name, strlen(str), str);
}

static void
put_cgi_param_f(const unsigned char *name, const char *format, ...)
  __attribute__((format(printf, 2, 3), unused));
static void
put_cgi_param_f(const unsigned char *name, const char *format, ...)
{
  va_list args;
  unsigned char buf[8192];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  put_cgi_param(name, buf);
}

int
main(int argc, char *argv[])
{
  int i, n, r;
  const unsigned char *ejudge_xml_path = 0;
  const unsigned char *command = 0;
  new_server_conn_t conn = 0;
  unsigned char **p1 = 0;
  size_t *p2 = 0;
  int fd = 1;

  program_path = argv[0];
  program_name = os_GetBasename(argv[0]);

  if (argc <= 1) startup_error("not enough parameters");

  if (!strcmp(argv[1], "--help")) {
    write_help();
  } else if (!strcmp(argv[1], "--version")) {
    write_version();
  }

  // pre-command options
  i = 1;
  while (i < argc) {
    if (!strcmp(argv[i], "-f")) {
      if (i + 1 >= argc) startup_error("argument expected for `-f'");
      ejudge_xml_path = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (argv[i][0] == '-') {
      startup_error("invalid option `%s'", argv[i]);
    } else {
      break;
    }
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) startup_error("ejudge.xml path is not specified");
  if (!(config = ejudge_cfg_parse(ejudge_xml_path))) return 1;
  if (!config->contests_dir) startup_error("<contests_dir> tag is not set!");
  if (contests_set_directory(config->contests_dir) < 0)
    startup_error("contests directory is invalid");

  // contest-id
  if (i >= argc) startup_error("contest-id is expected");
  if (sscanf(argv[i], "%d%n", &contest_id, &n) != 1 || argv[i][n])
    startup_error("invalid contest-id `%s'", argv[i]);
  if (contest_id <= 0 || contest_id >= 1000000)
    startup_error("invalid contest-id %d", contest_id);
  if ((n = contests_get(contest_id, &cnts)) < 0)
    startup_error("cannot load contest %d: %s",
                  contest_id, contests_strerror(-n));
  i++;

  // if the contest is not new-managed, invoke serve-cmd
  if (!cnts->new_managed) invoke_serve_cmd(argc, argv);

#if defined EJUDGE_NEW_SERVER_SOCKET
  if (!socket_path) socket_path = EJUDGE_NEW_SERVER_SOCKET;
#endif
  if (!socket_path) startup_error("socket path is undefined");

  if (i >= argc) startup_error("command expected");
  command = argv[i++];

  /* parse generic options */
  while (i < argc) {
    if (!strcmp(argv[i], "--ip")) {
      if (i + 1 >= argc) startup_error("argument expected for --ip");
      if (xml_parse_ip(NULL, 0, 0, argv[i + 1], &ip_address) < 0)
        return 1;
      i += 2;
    } else if (!strncmp(argv[i], "--ip=", 5)) {
      if (xml_parse_ip(NULL, 0, 0, argv[i] + 5, &ip_address) < 0)
        return 1;
      i++;      
    } else if (!strcmp(argv[i], "--ssl")) {
      ssl_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "--no-ssl")) {
      ssl_flag = 0;
      i++;
    } else if (!strcmp(argv[i], "--session")) {
      session_mode = 1;
      i++;
    } else if (!strcmp(argv[i], "--script-name")) {
      if (i + 1>= argc) startup_error("argument expected for --script-name");
      script_name = argv[i + 1];
      i += 2;
    } else if (!strncmp(argv[i], "--script-name=", 14)) {
      script_name = argv[i] + 14;
      i++;
    } else if (!strcmp(argv[i], "--http-host")) {
      if (i + 1>= argc) startup_error("argument expected for --http-host");
      http_host = argv[i + 1];
      i += 2;
    } else if (!strncmp(argv[i], "--http-host=", 12)) {
      http_host = argv[i] + 12;
      i++;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (argv[i][0] == '-') {
      startup_error("invalid option `%s'", argv[i]);
    } else {
      break;
    }
  }

  /* call request preparer */

  /* invoke request */
  create_cgi_environ();
  if ((r = new_server_clnt_open(socket_path, &conn)) < 0)
    op_error("cannot connect to the server: %d", -r);
  if (use_reply_buf) {
    fd = -1;
    p1 = &reply_buf;
    p2 = &reply_size;
  }
  r = new_server_clnt_http_request(conn, fd, (unsigned char**) argv,
                                   cgi_environ,
                                   cgi_param_u, cgi_param_names,
                                   cgi_param_sizes, cgi_param_values,
                                   p1, p2);
  if (r < 0)
    op_error("request failed: %d", -r);

  /* call request post-processor */

  return 0;
}
