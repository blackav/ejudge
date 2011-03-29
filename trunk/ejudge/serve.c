/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2000-2011 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_limits.h"

#include "runlog.h"
#include "parsecfg.h"
#include "teamdb.h"
#include "prepare.h"
#include "html.h"
#include "clarlog.h"
#include "protocol.h"
#include "userlist.h"
#include "sha.h"
#include "l10n.h"
#include "archive_paths.h"
#include "team_extra.h"
#include "printing.h"
#include "diff.h"
#include "compile_packet.h"
#include "run_packet.h"
#include "curtime.h"
#include "xml_utils.h"
#include "job_packet.h"
#include "serve_state.h"
#include "startstop.h"
#include "ejudge_cfg.h"

#include "misctext.h"
#include "base64.h"
#include "pathutl.h"
#include "errlog.h"
#include "fileutl.h"

#include "reuse_xalloc.h"
#include "reuse_logger.h"
#include "reuse_osdeps.h"
#include "reuse_exec.h"

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/types.h>
#include <pwd.h>

static int cmdline_socket_fd = -1;
static struct serve_state serve_state;
static const struct contest_desc *cur_contest = 0;
static int forced_mode = 0;
static int initialize_mode = 0;
static const unsigned char *ejudge_xml_path = 0;
static struct ejudge_cfg *config = 0;

int
main(int argc, char *argv[])
{
  path_t  cpp_opts = { 0 };
  int     p_flags = 0;
  int     i = 1;
  unsigned char *user = 0, *group = 0, *workdir = 0;
  const struct section_global_data *global = 0;
  time_t contest_finish_time = 0;

  start_set_self_args(argc, argv);

  if (argc == 1) goto print_usage;

  while (i < argc) {
    if (!strncmp(argv[i], "-D", 2)) {
      if (cpp_opts[0]) pathcat(cpp_opts, " ");
      pathcat(cpp_opts, argv[i++]);
    } else if (!strcmp(argv[i], "-f")) {
      i++;
      forced_mode = 1;
    } else if (!strcmp(argv[i], "-i")) {
      i++;
      initialize_mode = 1;
    } else if (!strncmp(argv[i], "-S", 2)) {
      int x = 0, n = 0;

      if (sscanf(argv[i] + 2, "%d%n", &x, &n) != 1
          || argv[i][n+2] || x < 0 || x > 10000) {
        err("invalid parameter for -S");
        return 1;
      }
      i++;
      cmdline_socket_fd = x;
    } else if (!strcmp(argv[i], "-u")) {
      if (++i >= argc) goto print_usage;
      user = argv[i++];
    } else if (!strcmp(argv[i], "-g")) {
      if (++i >= argc) goto print_usage;
      group = argv[i++];
    } else if (!strcmp(argv[i], "-C")) {
      if (++i >= argc) goto print_usage;
      workdir = argv[i++];
    } else break;
  }
  if (i >= argc) goto print_usage;

  if (!initialize_mode) {
    err("this program now supports only initialize mode");
    return 1;
  }

  if (start_prepare(user, group, workdir) < 0) return 1;

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) {
    err("configuration file is not specified");
    return 1;
  }

  config = ejudge_cfg_parse(ejudge_xml_path);
  if (!config) return 1;
  if (contests_set_directory(config->contests_dir) < 0) return 1;

  // initialize the current time to avoid some asserts
  serve_state.current_time = time(0);

  if (prepare(&serve_state, argv[i], p_flags, PREPARE_SERVE, cpp_opts,
              (cmdline_socket_fd >= 0), 0, 0) < 0) return 1;
  if (prepare_serve_defaults(&serve_state, &cur_contest) < 0) return 1;

  global = serve_state.global;
  l10n_prepare(global->enable_l10n, global->l10n_dir);

  if (create_dirs(&serve_state, PREPARE_SERVE) < 0) return 1;
  if (global->contest_id <= 0) {
    err("contest_id is not defined");
    return 1;
  }
  serve_state.teamdb_state = teamdb_init();
  serve_state.team_extra_state = team_extra_init();
  team_extra_set_dir(serve_state.team_extra_state, global->team_extra_dir);
  if (!initialize_mode) {
    if (teamdb_open_client(serve_state.teamdb_state, global->socket_path,
                           global->contest_id) < 0)
      return 1;
  }
  serve_state.runlog_state = run_init(serve_state.teamdb_state);
  if (global->contest_finish_time > 0) {
    contest_finish_time = global->contest_finish_time;
  }
  if (contest_finish_time > 0
      && contest_finish_time <= serve_state.current_time) {
    contest_finish_time = 0;
  }
  if (run_open(serve_state.runlog_state, config, cur_contest, global, 0, 0,
               global->contest_time, cur_contest->sched_time,
               contest_finish_time) < 0) return 1;
  if (global->is_virtual
      && global->score_system != SCORE_ACM) {
    err("invalid score system for virtual contest");
    return 1;
  }
  serve_state.clarlog_state = clar_init();
  if (clar_open(serve_state.clarlog_state,
                config, cur_contest, global, 0, 0) < 0)
    return 1;
  serve_load_status_file(&serve_state);
  serve_build_compile_dirs(&serve_state);
  serve_build_run_dirs(&serve_state);
  if (serve_create_symlinks(&serve_state) < 0) return 1;
  serve_state.current_time = time(0);
  serve_update_status_file(&serve_state, 1);
  team_extra_flush(serve_state.team_extra_state);
  return 0;

 print_usage:
  printf("Usage: %s [ OPTS ] config-file\n", argv[0]);
  printf("  -T     - print configuration and exit\n");
  printf("  -SSOCK - set a socket fd\n");
  printf("  -DDEF  - define a symbol for preprocessor\n");
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "fd_set" "tpTask")
 * End:
 */
