/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/pathutl.h"
#include "ejudge/ej_process.h"

#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#define EJ_USERS_MASK 1
#define EJ_SUPER_SERVER_MASK 2
#define EJ_COMPILE_MASK 4
#define EJ_SUPER_RUN_MASK 8
#define EJ_JOBS_MASK 16
#define EJ_CONTESTS_MASK 32
#define EJ_LAST_MASK 64
#define EJ_ALL_MASK (EJ_LAST_MASK - 1)

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
  __attribute__((format(printf, 1, 2), noreturn, unused));
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
  printf("%s: ejudge control utility\n"
         "Usage: %s [OPTIONS] COMMAND [EJUDGE-XML-PATH]\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "    -u USER   specify the user to run under\n"
         "    -g GROUP  specify the group to run under\n"
         "    -f        forced start mode\n"
         "    -s        slave mode (ej-compile and ej-super-server)\n"
         "    -r        serve all contests in run mode\n"
         "    -m        master mode (all except ej-compile)\n"
         "    -nu       skip start of ej-users\n"
         "    -ns       skip start of ej-super-server\n"
         "    -no       skip start of ej-compile\n"
         "    -nr       skip start of ej-super-run\n"
         "    -nj       skip start of ej-jobs\n"
         "    -nc       skip start of ej-contests\n"
         "  COMMAND:\n"
         "    start     start the ejudge daemons\n"
         "    stop      stop the ejudge daemons\n"
         "    restart   restart the ejudge daemons\n"
         /*"    status    report the ejudge daemon status\n"*/,
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
invoke_stopper(const char *prog, const char *ejudge_xml_path)
{
  path_t path;
  tTask *tsk = 0;

  snprintf(path, sizeof(path), "%s/%s-control", EJUDGE_SERVER_BIN_PATH, prog);
  tsk = task_New();
  task_AddArg(tsk, path);
  task_AddArg(tsk, "stop");
  if (ejudge_xml_path) task_AddArg(tsk, ejudge_xml_path);
  task_Start(tsk);
  task_Wait(tsk);
  task_Delete(tsk);
}

static int
command_start(
        const struct ejudge_cfg *config,
        const char *user,
        const char *group,
        const char *ejudge_xml_path,
        int force_mode,
        int slave_mode,
        int all_run_serve,
        int master_mode,
        int super_run_parallelism,
        int skip_mask)
{
  tTask *tsk = 0;
  path_t path;
  const unsigned char *workdir = 0;
  int userlist_server_started = 0;
  int super_serve_started = 0;
  int compile_started = 0;
  int super_run_started = 0;
  int job_server_started = 0;
  int new_server_started = 0;

  if (config->contests_home_dir) workdir = config->contests_home_dir;
#if defined EJUDGE_CONTESTS_HOME_DIR
  workdir = EJUDGE_CONTESTS_HOME_DIR;
#endif

  // start ej-users
  if (!slave_mode && !(skip_mask & EJ_USERS_MASK)) {
    snprintf(path, sizeof(path), "%s/ej-users", EJUDGE_SERVER_BIN_PATH);
    tsk = task_New();
    task_AddArg(tsk, path);
    task_AddArg(tsk, "-D");
    if (user) {
      task_AddArg(tsk, "-u");
      task_AddArg(tsk, user);
    }
    if (group) {
      task_AddArg(tsk, "-g");
      task_AddArg(tsk, group);
    }
    if (workdir) {
      task_AddArg(tsk, "-C");
      task_AddArg(tsk, workdir);
    }
    if (force_mode) {
      task_AddArg(tsk, "-f");
    }
    task_AddArg(tsk, ejudge_xml_path);
    task_SetPathAsArg0(tsk);
    task_Start(tsk);
    task_Wait(tsk);
    if (task_IsAbnormal(tsk)) goto failed;
    task_Delete(tsk); tsk = 0;
    userlist_server_started = 1;
  }

  // start ej-super-server
  if (!(skip_mask & EJ_SUPER_SERVER_MASK)) {
    snprintf(path, sizeof(path), "%s/ej-super-server", EJUDGE_SERVER_BIN_PATH);
    tsk = task_New();
    task_AddArg(tsk, path);
    task_AddArg(tsk, "-D");
    if (user) {
      task_AddArg(tsk, "-u");
      task_AddArg(tsk, user);
    }
    if (group) {
      task_AddArg(tsk, "-g");
      task_AddArg(tsk, group);
    }
    if (workdir) {
      task_AddArg(tsk, "-C");
      task_AddArg(tsk, workdir);
    }
    if (force_mode) {
    task_AddArg(tsk, "-f");
    }
    if (slave_mode) {
      task_AddArg(tsk, "-s");
    }
    if (all_run_serve) {
      task_AddArg(tsk, "-r");
    }
    if (master_mode) {
      task_AddArg(tsk, "-m");
    }
    task_AddArg(tsk, ejudge_xml_path);
    task_SetPathAsArg0(tsk);
    task_Start(tsk);
    task_Wait(tsk);
    if (task_IsAbnormal(tsk)) goto failed;
    task_Delete(tsk); tsk = 0;
    super_serve_started = 1;
  }

  // start ej-compile
  if (!master_mode && !(skip_mask & EJ_COMPILE_MASK)) {
    snprintf(path, sizeof(path), "%s/ej-compile", EJUDGE_SERVER_BIN_PATH);
    tsk = task_New();
    task_AddArg(tsk, path);
    task_AddArg(tsk, "-D");
    if (user) {
      task_AddArg(tsk, "-u");
      task_AddArg(tsk, user);
    }
    if (group) {
      task_AddArg(tsk, "-g");
      task_AddArg(tsk, group);
    }
    if (workdir) {
      snprintf(path, sizeof(path), "%s/compile", workdir);
      task_AddArg(tsk, "-C");
      task_AddArg(tsk, path);
    }
    task_AddArg(tsk, "conf/compile.cfg");
    task_SetPathAsArg0(tsk);
    task_Start(tsk);
    task_Wait(tsk);
    if (task_IsAbnormal(tsk)) goto failed;
    task_Delete(tsk); tsk = 0;
    compile_started = 1;
  }

  // start ej-super-run
  if (!master_mode && !(skip_mask & EJ_SUPER_RUN_MASK)) {
    for (int i = 0; i < super_run_parallelism; ++i) {
      snprintf(path, sizeof(path), "%s/ej-super-run", EJUDGE_SERVER_BIN_PATH);
      tsk = task_New();
      task_AddArg(tsk, path);
      task_AddArg(tsk, "-D");
      if (user) {
        task_AddArg(tsk, "-u");
        task_AddArg(tsk, user);
      }
      if (group) {
        task_AddArg(tsk, "-g");
        task_AddArg(tsk, group);
      }
      if (workdir) {
        task_AddArg(tsk, "-C");
        task_AddArg(tsk, workdir);
      }
      task_SetPathAsArg0(tsk);
      task_Start(tsk);
      task_Wait(tsk);
      if (task_IsAbnormal(tsk)) goto failed;
      task_Delete(tsk); tsk = 0;
    }
    super_run_started = 1;
  }

  // start ej-jobs
  if (!slave_mode && !(skip_mask & EJ_JOBS_MASK)) {
    snprintf(path, sizeof(path), "%s/ej-jobs", EJUDGE_SERVER_BIN_PATH);
    tsk = task_New();
    task_AddArg(tsk, path);
    task_AddArg(tsk, "-D");
    if (user) {
      task_AddArg(tsk, "-u");
      task_AddArg(tsk, user);
    }
    if (group) {
      task_AddArg(tsk, "-g");
      task_AddArg(tsk, group);
    }
    if (workdir) {
      task_AddArg(tsk, "-C");
      task_AddArg(tsk, workdir);
    }
    task_AddArg(tsk, ejudge_xml_path);
    task_SetPathAsArg0(tsk);
    task_Start(tsk);
    task_Wait(tsk);
    if (task_IsAbnormal(tsk)) goto failed;
    task_Delete(tsk); tsk = 0;
    job_server_started = 1;
  }

  // start ej-contests
  if (!slave_mode && !(skip_mask & EJ_CONTESTS_MASK)) {
    snprintf(path, sizeof(path), "%s/ej-contests", EJUDGE_SERVER_BIN_PATH);
    tsk = task_New();
    task_AddArg(tsk, path);
    task_AddArg(tsk, "-D");
    if (user) {
      task_AddArg(tsk, "-u");
      task_AddArg(tsk, user);
    }
    if (group) {
      task_AddArg(tsk, "-g");
      task_AddArg(tsk, group);
    }
    if (workdir) {
      task_AddArg(tsk, "-C");
      task_AddArg(tsk, workdir);
    }
    if (force_mode) {
      task_AddArg(tsk, "-f");
    }
    task_AddArg(tsk, ejudge_xml_path);
    task_SetPathAsArg0(tsk);
    task_Start(tsk);
    task_Wait(tsk);
    if (task_IsAbnormal(tsk)) goto failed;
    task_Delete(tsk); tsk = 0;
    new_server_started = 1;
  }

  return 0;

 failed:
  task_Delete(tsk); tsk = 0;

  if (userlist_server_started) {
    invoke_stopper("ej-users", ejudge_xml_path);
  }
  if (super_serve_started) {
    invoke_stopper("ej-super-server", ejudge_xml_path);
  }
  if (compile_started) {
    invoke_stopper("ej-compile", ejudge_xml_path);
  }
  if (super_run_started) {
    invoke_stopper("ej-super-run", ejudge_xml_path);
  }
  if (job_server_started) {
    invoke_stopper("ej-jobs", ejudge_xml_path);
  }
  if (new_server_started) {
    invoke_stopper("ej-contests", ejudge_xml_path);
  }

  return -1;
}

static int
command_stop(
        const struct ejudge_cfg *config,
        const char *ejudge_xml_path,
        int slave_mode,
        int master_mode)
{
  if (!slave_mode) {
    invoke_stopper("ej-contests", ejudge_xml_path);
  }
  if (!master_mode) {
    invoke_stopper("ej-compile", ejudge_xml_path);
  }
  if (!master_mode) {
    invoke_stopper("ej-super-run", ejudge_xml_path);
  }
  invoke_stopper("ej-super-server", ejudge_xml_path);
  if (!slave_mode) {
    invoke_stopper("ej-users", ejudge_xml_path);
    invoke_stopper("ej-jobs", ejudge_xml_path);
  }

  return 0;
}

int
main(int argc, char *argv[])
{
  int i = 1, r = 0;
  const char *command = 0;
  struct ejudge_cfg *config = 0;
  const char *ejudge_xml_path = 0;
  const char *user = 0, *group = 0;
  int force_mode = 0;
  int slave_mode = 0;
  int all_run_serve = 0;
  int master_mode = 0;
  int parallelism = 1;
  int skip_mask = 0;
  unsigned char **host_names = NULL;

  logger_set_level(-1, LOG_WARNING);
  program_name = os_GetBasename(argv[0]);
  if (argc < 2) startup_error("not enough parameters");

  if (!(host_names = ejudge_get_host_names())) {
    startup_error("cannot obtain the list of host names");
  }
  if (!host_names[0]) {
    startup_error("cannot determine the name of the host");
  }

  while (i < argc) {
    if (!strcmp(argv[i], "--help")) {
      write_help();
    } else if (!strcmp(argv[i], "--version")) {
      write_version();
    } else if (!strcmp(argv[i], "-u")) {
      if (i + 1 >= argc) startup_error("argument expected for `-u'");
      user = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-g")) {
      if (i + 1 >= argc) startup_error("argument expected for `-g'");
      group = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-f")) {
      force_mode = 1;
      i++;
    } else if (!strcmp(argv[i], "-s")) {
      slave_mode = 1;
      i++;
    } else if (!strcmp(argv[i], "-r")) {
      all_run_serve = 1;
      i++;
    } else if (!strcmp(argv[i], "-m")) {
      master_mode = 1;
      i++;
    } else if (!strcmp(argv[i], "-nu")) {
      skip_mask |= EJ_USERS_MASK;
      i++;
    } else if (!strcmp(argv[i], "-ns")) {
      skip_mask |= EJ_SUPER_SERVER_MASK;
      i++;
    } else if (!strcmp(argv[i], "-no")) {
      skip_mask |= EJ_COMPILE_MASK;
      i++;
    } else if (!strcmp(argv[i], "-nr")) {
      skip_mask |= EJ_SUPER_RUN_MASK;
      i++;
    } else if (!strcmp(argv[i], "-nj")) {
      skip_mask |= EJ_JOBS_MASK;
      i++;
    } else if (!strcmp(argv[i], "-nc")) {
      skip_mask |= EJ_CONTESTS_MASK;
      i++;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (!strncmp(argv[i], "-", 1)) {
      startup_error("invalid option `%s'", argv[i]);
    } else
      break;
  }

  if (i >= argc) startup_error("command expected");
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

  parallelism = ejudge_cfg_get_host_option_int(config, host_names, "parallelism", 1, 0);
  if (parallelism <= 0 || parallelism > 128) {
    startup_error("invalid value of parallelism host option");
  }

  if (!strcmp(command, "start")) {
    if (command_start(config, user, group, ejudge_xml_path, force_mode,
                      slave_mode, all_run_serve, master_mode, parallelism,
                      skip_mask) < 0) 
      r = 1;
  } else if (!strcmp(command, "stop")) {
    if (command_stop(config, ejudge_xml_path, slave_mode, master_mode) < 0)
      r = 1;
  } else if (!strcmp(command, "restart")) {
    startup_error("`restart' command is not yet implemented");
  } else {
    startup_error("invalid command `%s'", command);
  }

  return r;
}
