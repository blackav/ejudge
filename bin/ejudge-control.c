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
#include "ejudge/version.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/pathutl.h"
#include "ejudge/ej_process.h"
#include "ejudge/startstop.h"
#include "ejudge/logrotate.h"

#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>

#define EJ_USERS_MASK 1
#define EJ_SUPER_SERVER_MASK 2
#define EJ_COMPILE_MASK 4
#define EJ_SUPER_RUN_MASK 8
#define EJ_JOBS_MASK 16
#define EJ_CONTESTS_MASK 32
#define EJ_AGENT_MASK 64
#define EJ_LAST_MASK 128
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
         "    rotate    rotate log files\n"
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

static int
invoke_stopper(const char *prog, const char *ejudge_xml_path)
{
  path_t path;
  tTask *tsk = 0;

  snprintf(path, sizeof(path), "%s/%s-control", EJUDGE_SERVER_BIN_PATH, prog);
  tsk = task_New();
  task_AddArg(tsk, path);
  task_AddArg(tsk, "stop");
  if (strcmp(prog, "ej-compile") != 0) {
    if (ejudge_xml_path) task_AddArg(tsk, ejudge_xml_path);
  }
  if (task_Start(tsk) < 0) {
    fprintf(stderr, "%s: failed to start %s\n", program_name, path);
    task_Delete(tsk);
    return -1;
  }
  task_Wait(tsk);
  if (task_IsAbnormal(tsk)) {
    fprintf(stderr, "%s: subcommand %s failed\n", program_name, path);
    task_Delete(tsk);
    return -1;
  }
  task_Delete(tsk);
  return 0;
}

static void
invoke_rotate(
        const char *prog,
        const char *ejudge_xml_path,
        int date_suffix_flag)
{
  path_t path;
  tTask *tsk = 0;

  snprintf(path, sizeof(path), "%s/%s-control", EJUDGE_SERVER_BIN_PATH, prog);
  tsk = task_New();
  task_AddArg(tsk, path);
  if (date_suffix_flag > 0) {
    task_AddArg(tsk, "--date-suffix");
  }
  task_AddArg(tsk, "rotate");
  if (strcmp(prog, "ej-compile") != 0) {
    if (ejudge_xml_path) task_AddArg(tsk, ejudge_xml_path);
  }
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
        int compile_parallelism,
        int skip_mask,
        const char *agent,
        const char *instance_id,
        const char *queue,
        int verbose_mode,
        const char *mirror,
        int enable_heartbeat,
        int disable_heartbeat,
        const char *timeout_str,
        const char *shutdown_script,
        const char *ip_address,
        const char *reboot_script,
        const char *lang_id_map,
        const char *local_cache)
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
  char tool_instance_id[128];

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
  if (!slave_mode && !(skip_mask & EJ_SUPER_SERVER_MASK)) {
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
    snprintf(path, sizeof(path), "%s/ej-compile-control", EJUDGE_SERVER_BIN_PATH);
    tsk = task_New();
    task_AddArg(tsk, path);
    if (agent && *agent) {
      task_AddArg(tsk, "--agent");
      task_AddArg(tsk, agent);
    }
    if (instance_id && *instance_id) {
      snprintf(tool_instance_id, sizeof(tool_instance_id),
               "%s-compile", instance_id);
      task_AddArg(tsk, "--instance-id");
      task_AddArg(tsk, tool_instance_id);
      task_AddArg(tsk, "-hi");
      task_AddArg(tsk, instance_id);
    }
    if (queue && *queue) {
      task_AddArg(tsk, "--queue");
      task_AddArg(tsk, queue);
    }
    if (ip_address && *ip_address) {
      task_AddArg(tsk, "--ip");
      task_AddArg(tsk, ip_address);
    }
    if (shutdown_script && *shutdown_script) {
      task_AddArg(tsk, "-hc");
      task_AddArg(tsk, shutdown_script);
    }
    if (reboot_script && *reboot_script) {
      task_AddArg(tsk, "-rc");
      task_AddArg(tsk, reboot_script);
    }
    if (lang_id_map && *lang_id_map) {
      task_AddArg(tsk, "--lang-id-map");
      task_AddArg(tsk, lang_id_map);
    }
    if (local_cache && *local_cache) {
      task_AddArg(tsk, "--local-cache");
      task_AddArg(tsk, local_cache);
    }
    if (verbose_mode) {
      task_AddArg(tsk, "-v");
    }
    task_AddArg(tsk, "start");
    task_SetPathAsArg0(tsk);
    task_Start(tsk);
    task_Wait(tsk);
    if (task_IsAbnormal(tsk)) goto failed;
    task_Delete(tsk); tsk = 0;
    compile_started = 1;
  }

  // start ej-super-run
  if (!master_mode && !(skip_mask & EJ_SUPER_RUN_MASK)) {
    if (mirror && *mirror) {
      os_MakeDirPath(mirror, 0700);
    }

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
      if (agent && *agent) {
        task_AddArg(tsk, "--agent");
        task_AddArg(tsk, agent);
      }
      if (ip_address && *ip_address) {
        task_AddArg(tsk, "--ip");
        task_AddArg(tsk, ip_address);
      }
      if (instance_id && *instance_id) {
        snprintf(tool_instance_id, sizeof(tool_instance_id),
                 "%s-run", instance_id);
        task_AddArg(tsk, "--instance-id");
        task_AddArg(tsk, tool_instance_id);
        task_AddArg(tsk, "-hi");
        task_AddArg(tsk, instance_id);
      }
      if (queue && *queue) {
        task_AddArg(tsk, "-p");
        task_AddArg(tsk, queue);
      }
      if (verbose_mode) {
        task_AddArg(tsk, "-v");
      }
      if (mirror && *mirror) {
        task_AddArg(tsk, "-m");
        task_AddArg(tsk, mirror);
      }
      if (local_cache && *local_cache) {
        task_AddArg(tsk, "--local-cache");
        task_AddArg(tsk, local_cache);
      }
      if (enable_heartbeat > 0) {
        task_AddArg(tsk, "-hb");
      }
      if (disable_heartbeat > 0) {
        task_AddArg(tsk, "-nhb");
      }
      if (timeout_str && *timeout_str) {
        task_AddArg(tsk, "-ht");
        task_AddArg(tsk, timeout_str);
      }
      if (shutdown_script && *shutdown_script) {
        task_AddArg(tsk, "-hc");
        task_AddArg(tsk, shutdown_script);
      }
      if (reboot_script && *reboot_script) {
        task_AddArg(tsk, "-rc");
        task_AddArg(tsk, reboot_script);
      }
      if (i > 0) {
        char buf[64];
        sprintf(buf, "%d", i);
        task_AddArg(tsk, "-x");
        task_AddArg(tsk, buf);
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

  if (compile_started) {
    invoke_stopper("ej-compile", ejudge_xml_path);
  }
  if (super_run_started) {
    invoke_stopper("ej-super-run", ejudge_xml_path);
  }
  if (super_serve_started) {
    invoke_stopper("ej-super-server", ejudge_xml_path);
  }
  if (new_server_started) {
    invoke_stopper("ej-contests", ejudge_xml_path);
  }
  if (job_server_started) {
    invoke_stopper("ej-jobs", ejudge_xml_path);
  }
  if (userlist_server_started) {
    invoke_stopper("ej-users", ejudge_xml_path);
  }

  return -1;
}

static int
command_stop(
        const struct ejudge_cfg *config,
        const char *ejudge_xml_path,
        int skip_mask,
        int slave_mode,
        int master_mode)
{
  if (!master_mode && !(skip_mask & EJ_COMPILE_MASK)) {
    if (invoke_stopper("ej-compile", ejudge_xml_path) < 0)
      return -1;
  }
  if (!master_mode && !(skip_mask & EJ_SUPER_RUN_MASK)) {
    if (invoke_stopper("ej-super-run", ejudge_xml_path) < 0)
      return -1;
  }
  if (!slave_mode && !(skip_mask & EJ_SUPER_SERVER_MASK)) {
    if (invoke_stopper("ej-super-server", ejudge_xml_path) < 0)
      return -1;
  }
  if (!slave_mode && !(skip_mask & EJ_CONTESTS_MASK)) {
    if (invoke_stopper("ej-contests", ejudge_xml_path) < 0)
      return -1;
  }
  if (!slave_mode) {
    if (!(skip_mask & EJ_JOBS_MASK)) {
      if (invoke_stopper("ej-jobs", ejudge_xml_path) < 0)
        return -1;
    }
    if (!(skip_mask & EJ_USERS_MASK)) {
      if (invoke_stopper("ej-users", ejudge_xml_path) < 0)
        return -1;
    }
  }

  return 0;
}

static void
rotate_agent_log(
        const struct ejudge_cfg *config,
        const char *ejudge_xml_path,
        int date_suffix_flag)
{
  unsigned char lpd[PATH_MAX];
  unsigned char lpf[PATH_MAX];
  if (rotate_get_log_dir_and_file(lpd, sizeof(lpd),
                                  lpf, sizeof(lpf),
                                  config,
                                  NULL,
                                  "ej-agent.log") < 0) {
    return;
  }

  unsigned char *log_group = NULL;
#if defined EJUDGE_PRIMARY_USER
  log_group = EJUDGE_PRIMARY_USER;
#endif

  rotate_log_files(lpd, lpf, NULL, NULL, log_group, 0620, date_suffix_flag);

  int *pids = NULL;
  int pid_count = start_find_all_processes("ej-agent", NULL, &pids);
  for (int i = 0; i < pid_count; ++i) {
    start_kill(pids[i], SIGUSR1);
  }
}

static int
command_rotate(
        const struct ejudge_cfg *config,
        const char *ejudge_xml_path,
        int skip_mask,
        int slave_mode,
        int master_mode,
        int date_suffix_flag)
{
  if (!slave_mode && !(skip_mask & EJ_CONTESTS_MASK)) {
    invoke_rotate("ej-contests", ejudge_xml_path, date_suffix_flag);
  }
  if (!master_mode && !(skip_mask & EJ_COMPILE_MASK)) {
    invoke_rotate("ej-compile", ejudge_xml_path, date_suffix_flag);
  }
  if (!master_mode && !(skip_mask & EJ_SUPER_RUN_MASK)) {
    invoke_rotate("ej-super-run", ejudge_xml_path, date_suffix_flag);
  }
  if (!slave_mode && !(skip_mask & EJ_SUPER_SERVER_MASK)) {
    invoke_rotate("ej-super-server", ejudge_xml_path, date_suffix_flag);
  }
  if (!slave_mode) {
    if (!(skip_mask & EJ_USERS_MASK)) {
      invoke_rotate("ej-users", ejudge_xml_path, date_suffix_flag);
    }
    if (!(skip_mask & EJ_JOBS_MASK)) {
      invoke_rotate("ej-jobs", ejudge_xml_path, date_suffix_flag);
    }
  }
  if (!slave_mode && !(skip_mask & EJ_AGENT_MASK)) {
    rotate_agent_log(config, ejudge_xml_path, date_suffix_flag);
  }

  return 0;
}

struct tool_names_s
{
  int mask;
  const char ** names;
};

static const struct tool_names_s tool_names[] =
{
  { EJ_USERS_MASK, (const char *[]) { "ej-users", "users", "user", NULL } },
  { EJ_SUPER_SERVER_MASK, (const char *[]) { "ej-super-server", "super-server", "server", NULL } },
  { EJ_COMPILE_MASK, (const char *[]) { "ej-compile", "compile", "comp", NULL } },
  { EJ_SUPER_RUN_MASK, (const char *[]) { "ej-super-run", "super-run", "run", NULL } },
  { EJ_JOBS_MASK, (const char *[]) { "ej-jobs", "jobs", "job", NULL } },
  { EJ_CONTESTS_MASK, (const char *[]) { "ej-contests", "contests", "contest", "cont", NULL } },
  { EJ_AGENT_MASK, (const char *[]) { "ej-agent", "agents", "agent", NULL } },
  { 0, NULL },
};

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
  int compile_parallelism = 1;
  int skip_mask = 0;
  int tool_mask = 0;
  unsigned char **host_names = NULL;
  const char *agent = NULL;
  const char *instance_id = NULL;
  const char *queue = NULL;
  int verbose_mode = 0;
  const char *mirror = NULL;
  int enable_heartbeat = 0;
  int disable_heartbeat = 0;
  const char *timeout_str = NULL;
  const char *shutdown_script = NULL;
  const char *reboot_script = NULL;
  int date_suffix_flag = 0;
  const char *ip_address = NULL;
  const char *lang_id_map = NULL;
  const char *local_cache = NULL;

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
    } else if (!strcmp(argv[i], "--agent")) {
      if (i + 1 >= argc) startup_error("argument expected for `--agent'");
      agent = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--instance-id")) {
      if (i + 1 >= argc) startup_error("argument expected for `--instance-id'");
      instance_id = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--queue")) {
      if (i + 1 >= argc) startup_error("argument expected for `--queue'");
      queue = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--mirror")) {
      if (i + 1 >= argc) startup_error("argument expected for `--mirror'");
      mirror = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--ip")) {
      if (i + 1 >= argc) startup_error("argument expected for --ip");
      ip_address = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-ht")) {
      if (i + 1 >= argc) startup_error("argument expected for `-ht'");
      timeout_str = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-hc")) {
      if (i + 1 >= argc) startup_error("argument expected for `-hc'");
      shutdown_script = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-rc")) {
      if (i + 1 >= argc) startup_error("argument expected for `-rc'");
      reboot_script = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--lang-id-map")) {
      if (i + 1 >= argc) startup_error("argument expected for `--lang-id-map'");
      lang_id_map = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--local-cache")) {
      if (i + 1 >= argc) startup_error("argument expected for `--local-cache'");
      local_cache = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-v")) {
      verbose_mode = 1;
      i++;
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
    } else if (!strcmp(argv[i], "-hb")) {
      enable_heartbeat = 1;
      i++;
    } else if (!strcmp(argv[i], "-nhb")) {
      disable_heartbeat = 1;
      i++;
    } else if (!strcmp(argv[i], "--date-suffix")) {
      date_suffix_flag = 1;
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

  while (i < argc) {
    int j;
    for (j = 0; tool_names[j].mask; ++j) {
      int k;
      for (k = 0; tool_names[j].names[k]; ++k) {
        if (!strcasecmp(tool_names[j].names[k], argv[i])) {
          break;
        }
      }
      if (tool_names[j].names[k]) {
        tool_mask |= tool_names[j].mask;
        break;
      }
    }
    if (!tool_names[j].mask) {
      break;
    }
    ++i;
  }

  if (i < argc) {
    ejudge_xml_path = argv[i];
    i++;
  }

  if (i < argc) startup_error("too many parameters");

  if (tool_mask != 0) skip_mask = EJ_ALL_MASK ^ tool_mask;

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */

  if (!ejudge_xml_path) startup_error("ejudge.xml path is not specified");

  if (!(config = ejudge_cfg_parse(ejudge_xml_path, 0))) return 1;

  parallelism = ejudge_cfg_get_host_option_int(config, host_names, "parallelism", 1, 0);
  if (parallelism <= 0 || parallelism > 128) {
    startup_error("invalid value of parallelism host option");
  }

  compile_parallelism = ejudge_cfg_get_host_option_int(config, host_names, "compile_parallelism", 1, 0);
  if (compile_parallelism <= 0 || compile_parallelism > 128) {
    startup_error("invalid value of compile_parallelism host option");
  }

  if (!strcmp(command, "start")) {
    if (command_start(config, user, group, ejudge_xml_path, force_mode,
                      slave_mode, all_run_serve, master_mode, parallelism,
                      compile_parallelism, skip_mask,
                      agent, instance_id, queue, verbose_mode,
                      mirror, enable_heartbeat, disable_heartbeat,
                      timeout_str, shutdown_script, ip_address,
                      reboot_script, lang_id_map, local_cache) < 0)
      r = 1;
  } else if (!strcmp(command, "stop")) {
    // ej-agents are not stopped if not asked explicitly
    if (!(tool_mask & EJ_AGENT_MASK)) skip_mask |= EJ_AGENT_MASK;
    if (command_stop(config, ejudge_xml_path,
                     skip_mask, slave_mode, master_mode) < 0)
      r = 1;
  } else if (!strcmp(command, "rotate")) {
    if (command_rotate(config, ejudge_xml_path,
                       skip_mask, slave_mode, master_mode,
                       date_suffix_flag) < 0)
      r = 1;
  } else if (!strcmp(command, "restart")) {
    startup_error("`restart' command is not yet implemented");
  } else {
    startup_error("invalid command `%s'", command);
  }

  return r;
}
