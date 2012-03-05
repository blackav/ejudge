/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2012 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_limits.h"
#include "version.h"

#include "startstop.h"
#include "ejudge_cfg.h"
#include "fileutl.h"

#include "reuse_xalloc.h"
#include "reuse_osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

#define SUPER_RUN_DIRECTORY "super-run"

static const unsigned char *program_name = 0;
static struct ejudge_cfg *ejudge_config;
static unsigned char super_run_path[PATH_MAX];
static unsigned char super_run_spool_path[PATH_MAX];
static unsigned char super_run_exe_path[PATH_MAX];
static unsigned char super_run_conf_path[PATH_MAX];

static void
fatal(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void
fatal(const char *format, ...)
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
  printf("%s: ejudge testing super server\n"
         "Usage: %s [OPTIONS]\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "    -u USER   specify the user to run under\n"
         "    -g GROUP  specify the group to run under\n"
         "    -D        daemon mode\n",
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

static void
create_directories(void)
{
  snprintf(super_run_spool_path, sizeof(super_run_spool_path), "%s/%s",
           super_run_path, "queue");
  snprintf(super_run_exe_path, sizeof(super_run_exe_path), "%s/%s",
           super_run_path, "exe");
  make_dir(super_run_path, 0755);
  make_all_dir(super_run_spool_path, 0777);
  make_dir(super_run_exe_path, 0777);
}

int
main(int argc, char *argv[])
{
  char **argv_restart = 0;
  int argc_restart = 0;
  int cur_arg = 1;
  int pid;
  unsigned char *contests_home_dir = NULL;
  unsigned char ejudge_xml_path[PATH_MAX];

  program_name = os_GetBasename(argv[0]);
  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 1);
  argv_restart[argc_restart++] = argv[0];
  ejudge_xml_path[0] = 0;

  while (cur_arg < argc) {
    if (!strcmp(argv[cur_arg], "--help")) {
      write_help();
    } else if (!strcmp(argv[cur_arg], "--version")) {
      write_version();
    }
  }

  argv_restart[argc_restart] = NULL;
  start_set_args(argv_restart);

  if ((pid = start_find_process("ej-super-server", 0)) > 0) {
    fatal("is already running as pid %d", pid);
  }

  if (!ejudge_xml_path[0]) {
#if defined EJUDGE_CONTESTS_HOME_DIR
    contests_home_dir = EJUDGE_CONTESTS_HOME_DIR;
#endif
    if (!contests_home_dir) {
      fatal("CONTESTS_HOME_DIR is undefined");
    }
#if defined EJUDGE_XML_PATH
    snprintf(ejudge_xml_path, sizeof(ejudge_xml_path), "%s", EJUDGE_XML_PATH);
#endif
    if (!ejudge_xml_path[0]) {
      snprintf(ejudge_xml_path, sizeof(ejudge_xml_path), "%s/conf/ejudge.xml", contests_home_dir);
    }
  }

  ejudge_config = ejudge_cfg_parse(ejudge_xml_path);
  if (!ejudge_config) return 1;

  if (!contests_home_dir && ejudge_config->contests_home_dir) {
    contests_home_dir = ejudge_config->contests_home_dir;
  }

  if (!os_IsAbsolutePath(contests_home_dir)) {
    fatal("contests home directory is not an absolute path");
  }
  if (os_IsFile(contests_home_dir) != OSPK_DIR) {
    fatal("contests home directory is not a directory");
  }
  snprintf(super_run_path, sizeof(super_run_path), "%s/%s", contests_home_dir, SUPER_RUN_DIRECTORY);
  snprintf(super_run_conf_path, sizeof(super_run_conf_path), "%s/conf/super-run.cfg", super_run_path);
  create_directories();

  return 0;
}

