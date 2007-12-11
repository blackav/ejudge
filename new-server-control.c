/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_types.h"
#include "version.h"

#include "ejudge_cfg.h"
#include "new_server_proto.h"
#include "new_server_clnt.h"
#include "new_server_proto.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

/*
 * usage: new-server-control COMMAND CONFIG
 *   COMMAND is one of `stop', `restart', `status'
 */

static const unsigned char *program_name = "";

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
  printf("%s: new-server control utility\n"
         "Usage: %s [OPTIONS] COMMAND [EJUDGE-XML-PATH]\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "  COMMAND:\n"
         "    stop      stop the new-server\n"
         "    restart   restart the new-server\n"
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

int
main(int argc, char *argv[])
{
  int i = 1, r = 0;
  const char *command = 0;
  const char *ejudge_xml_path = 0;
  struct ejudge_cfg *config = 0;
  int cmd = 0;
  new_server_conn_t conn = 0;

  program_name = os_GetBasename(argv[0]);
  if (argc < 2) startup_error("not enough parameters");

  if (!strcmp(argv[i], "--help")) {
    write_help();
  } else if (!strcmp(argv[i], "--version")) {
    write_version();
  }

  command = argv[i];
  i++;

  if (i < argc) {
    ejudge_xml_path = argv[i];
    i++;
  }

  if (i < argc) startup_error("too many parameters");

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */

  if (!ejudge_xml_path) startup_error("ejudge.xml path is not specified");

  if (!(config = ejudge_cfg_parse(ejudge_xml_path))) return 1;

#if defined EJUDGE_NEW_SERVER_SOCKET
  if (!config->new_server_socket)
    config->new_server_socket = xstrdup(EJUDGE_NEW_SERVER_SOCKET);
#endif
  if (!config->new_server_socket)
    config->new_server_socket = xstrdup(EJUDGE_NEW_SERVER_SOCKET_DEFAULT);

  if (!strcmp(command, "stop")) {
    cmd = NEW_SRV_CMD_STOP;
  } else if (!strcmp(command, "restart")) {
    cmd = NEW_SRV_CMD_RESTART;
  } else {
    startup_error("invalid command");
  }

  r = new_server_clnt_open(config->new_server_socket, &conn);
  if (r == -NEW_SRV_ERR_CONNECT_FAILED) op_error("new-server is not running");
  if (r < 0) op_error("%s", ns_strerror(-r));

  r = new_server_clnt_control(conn, cmd);
  if (r < 0) op_error("%s", ns_strerror(-r));

  return 0;
}
