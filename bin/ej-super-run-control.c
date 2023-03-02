/* -*- mode: c -*- */

/* Copyright (C) 2012-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/startstop.h"
#include "ejudge/logrotate.h"

#include "ejudge/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#define WAIT_TIMEOUT_US 300000000LL // 300s

/*
 * usage: ej-super-run-control COMMAND CONFIG
 *   COMMAND is one of 'stop', 'restart', 'rotate'
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
  printf("%s: ej-super-run control utility\n"
         "Usage: %s [OPTIONS] COMMAND [EJUDGE-XML-PATH]\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "  COMMAND:\n"
         "    stop      stop the ej-super-run\n"
         "    restart   restart the ej-super-run\n"
         "    rotate    rotate the log file\n"
         /*"    status    report the ej-super-run status\n"*/,
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
  int signum = 0;
  const unsigned char *signame = "";
  int pid_count;
  int *pids = NULL;
  int date_suffix_flag = 0;

  program_name = os_GetBasename(argv[0]);
  if (argc < 2) startup_error("not enough parameters");

  while (1) {
    if (!strcmp(argv[i], "--help")) {
      write_help();
    } else if (!strcmp(argv[i], "--version")) {
      write_version();
    } else if (!strcmp(argv[i], "--date-suffix")) {
      ++i;
      date_suffix_flag = 1;
    } else {
      break;
    }
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

  if (!(config = ejudge_cfg_parse(ejudge_xml_path, 1))) return 1;

  if (!strcmp(command, "stop")) {
    signum = START_STOP;
    signame = "TERM";
    return (start_stop_and_wait(program_name, "ej-super-run", NULL, signame, signum, WAIT_TIMEOUT_US) < 0);
  } else if (!strcmp(command, "restart")) {
    signum = START_RESTART;
    signame = "HUP";
  } else if (!strcmp(command, "rotate")) {
    unsigned char lpd[PATH_MAX];
    unsigned char lpf[PATH_MAX];
    if (rotate_get_log_dir_and_file(lpd, sizeof(lpd),
                                    lpf, sizeof(lpf),
                                    config,
                                    NULL,
                                    "ej-super-run.log") < 0) {
      startup_error("log file is not defined or invalid");
    }

    unsigned char *log_group = NULL;
#if defined EJUDGE_PRIMARY_USER
    log_group = EJUDGE_PRIMARY_USER;
#endif

    rotate_log_files(lpd, lpf, NULL, NULL, log_group, 0620, date_suffix_flag);

    signum = START_ROTATE;
    signame = "USR1";
  } else {
    startup_error("invalid command");
  }

  if ((pid_count = start_find_all_processes("ej-super-run", NULL, &pids)) < 0) {
    op_error("cannot get the list of processes from /proc");
  } else if (!pid_count) {
    op_error("ej-super-run is not running");
  } else {
    fprintf(stderr, "%s: ej-super-run is running as pids", program_name);
    for (i = 0; i < pid_count; ++i) {
      fprintf(stderr, " %d", pids[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "%s: sending them the %s signal\n", program_name, signame);
    for (i = 0; i < pid_count; ++i) {
      if (start_kill(pids[i], signum) < 0) op_error("failed: %s", os_ErrorMsg());
    }
  }

  return 0;
}
