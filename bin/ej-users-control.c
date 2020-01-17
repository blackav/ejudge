/* -*- mode: c -*- */

/* Copyright (C) 2006-2015 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/version.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/startstop.h"

#include "ejudge/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

/*
 * usage: ej-users-control COMMAND CONFIG
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
  printf("%s: ej-users control utility\n"
         "Usage: %s [OPTIONS] COMMAND [EJUDGE-XML-PATH]\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "  COMMAND:\n"
         "    stop      stop the ej-users\n"
         "    restart   restart the ej-users\n"
         /*"    status    report the ej-users status\n"*/,
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
  userlist_clnt_t userlist_clnt = 0;
  int cmd = 0;
  const unsigned char *signame = "";
  int signum = 0;
  int pid;

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

  if (!(config = ejudge_cfg_parse(ejudge_xml_path, 0))) return 1;

  if (!strcmp(command, "stop")) {
    cmd = ULS_STOP;
    signame = "TERM";
    signum = START_STOP;
  } else if (!strcmp(command, "restart")) {
    cmd = ULS_RESTART;
    signame = "HUP";
    signum = START_RESTART;
  } else {
    startup_error("invalid command");
  }

  (void) signum;
  (void) signame;

  if (!(pid = start_find_process("ej-users", 0))) {
    op_error("ej-users is not running");
  } else if (pid > 0) {
    /*
    fprintf(stderr, "%s: ej-users is running as pid %d\n", program_name, pid);
    fprintf(stderr, "%s: sending it the %s signal\n", program_name, signame);
    if (start_kill(pid, signum) < 0) op_error("failed: %s", os_ErrorMsg());
    return 0;
    */
  }

  if (!(userlist_clnt = userlist_clnt_open(config->socket_path)))
    op_error("ej-users is not running");
  r = userlist_clnt_control(userlist_clnt, cmd);
  if (r < 0) op_error("%s", userlist_strerror(-r));

  return 0;
}
