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
#include "job_packet.h"

#include <reuse/osdeps.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

/*
 * usage: job-server-control COMMAND CONFIG
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
  printf("%s: job-server control utility\n"
         "Usage: %s [OPTIONS] COMMAND [EJUDGE-XML-PATH]\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "  COMMAND:\n"
         "    stop      stop the job-server\n"
         "    restart   restart the job-server\n"
         /*"    status    report the job-server status\n"*/,
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
  int i = 1;
  const char *command = 0;
  const char *ejudge_xml_path = 0;
  struct ejudge_cfg *config = 0;
  unsigned char *job_args[2] = { "", 0 };
  unsigned char *check_args[2] = { "nop", 0 };
  unsigned char *pkt_path = 0;
  int tot_wait = 0, cur_wait = 0;

  logger_set_level(-1, LOG_WARNING);
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

  if (!strcmp(command, "stop")) {
    job_args[0] = "stop";
  } else if (!strcmp(command, "restart")) {
    job_args[0] = "restart";
  } else {
    startup_error("invalid command");
  }

  // check, that job-server is running
  if (send_job_packet(NULL, check_args, &pkt_path) < 0)
    op_error("packet write error");
  cur_wait = 100000;
  tot_wait = 0;
  while (1) {
    usleep(cur_wait);
    tot_wait += cur_wait;
    cur_wait += 100000;
    if (access(pkt_path, F_OK) < 0) break;
    if (tot_wait >= 5000000) {
      unlink(pkt_path);
      op_error("job-server seems to not running");
    }
  }

  if (send_job_packet(NULL, job_args, &pkt_path) < 0)
    op_error("packet write error");
  cur_wait = 100000;
  while (1) {
    usleep(cur_wait);
    cur_wait += 100000;
    if (cur_wait > 1000000) cur_wait = 1000000;
    if (access(pkt_path, F_OK) < 0) break;
  }

  return 0;
}
