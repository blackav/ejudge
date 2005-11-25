/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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

#include "userlist_cfg.h"
#include "pathutl.h"
#include "errlog.h"
#include "contests.h"
#include "userlist_proto.h"
#include "userlist_clnt.h"
#include "serve_clnt.h"
#include "protocol.h"
#include "fileutl.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/time.h>

static const unsigned char *program_path;
static const unsigned char *program_name;
static const unsigned char *ejudge_xml_path;
static const unsigned char *contest_root_dir;
static struct userlist_cfg *config;
static int contest_id;
static struct contest_desc *cnts;
static userlist_clnt_t userlist_conn;
static unsigned char serve_socket_path[PATH_MAX];
static int serve_socket_fd = -1;
static ej_ip_t local_ip;  /* 127.0.0.1 */
static ej_cookie_t session_id;
static int user_id;

static int
too_many_params(const unsigned char *cmd)
{
  err("too many parameters for `%s'", cmd);
  return 1;
}
static int
too_few_params(const unsigned char *cmd)
{
  err("too few parameters for `%s'", cmd);
  return 1;
}

static void
open_server(void)
{
  if (serve_socket_fd >= 0) return;
  if ((serve_socket_fd = serve_clnt_open(serve_socket_path)) < 0) {
    err("cannot connect to the contest server: %s",
        protocol_strerror(-serve_socket_fd));
    exit(1);
  }
}

static void
authentificate(const unsigned char *pwdfile)
{
  FILE *f;
  int r;
  unsigned char *user_login, *user_name;

  if (!(f = fopen(pwdfile, "r"))) {
    err("cannot open %s: %s", pwdfile, os_ErrorMsg());
    exit(1);
  }
  if (fscanf(f, "%llx", &session_id) != 1) {
    err("cannot parse session_id");
    exit(1);
  }
  fscanf(f, " ");
  if (!feof(f)) {
    err("garbage in the session_id file");
    exit(1);
  }
  fclose(f);

  r = userlist_clnt_priv_cookie(userlist_conn, local_ip, 1, contest_id,
                                session_id,
                                0 /* locale_id */,
                                PRIV_LEVEL_ADMIN,
                                &user_id,
                                0, /* p_contest_id */
                                0 /* p_locale_id */,
                                0, &user_login, &user_name);
  if (r < 0) {
    err("server error: %s", userlist_strerror(-r));
    exit(1);
  }
  info("logged in as uid %d, login %s, name %s",
       user_id, user_login, user_name);
}

/*
 * argv[0] - session_id_file
 * argv[1] - login
 * argv[2] - password
 */
static int
handle_login(const unsigned char *cmd,
             int srv_cmd, int argc, char *argv[])
{
  int r, user_id;
  unsigned char *user_name;
  FILE *f;

  if (argc < 3) return too_few_params(cmd);
  if (argc > 3) return too_many_params(cmd);

  r = userlist_clnt_priv_login(userlist_conn, local_ip, 1, contest_id,
                               0, 1, PRIV_LEVEL_ADMIN,
                               argv[1], argv[2],
                               &user_id, &session_id, 0, 0, &user_name);
  if (r < 0) {
    err("server error: %s", userlist_strerror(-r));
    return 1;
  }
  info("logged in as uid %d, name %s, sid %016llx",
       user_id, user_name, session_id);

  if (!(f = fopen(argv[0], "w"))) {
    err("cannot open %s for writing: %s", argv[0], os_ErrorMsg());
    return 1;
  }
  fprintf(f, "%016llx\n", session_id);
  if (fclose(f) < 0) {
    err("output error: %s", os_ErrorMsg());
    unlink(argv[0]);
    return 1;
  }

  return 0;
}

/*
 * argv[0] - session_id_file
 */
static int
handle_dump_runs(const unsigned char *cmd,
                 int srv_cmd, int argc, char *argv[])
{
  int r;

  if (argc < 1) return too_few_params(cmd);
  if (argc > 1) return too_many_params(cmd);

  authentificate(argv[0]);
  open_server();

  r = serve_clnt_view(serve_socket_fd, 1, srv_cmd, 0, 0, 0, "", "", "");
  if (r < 0) {
    err("server error: %s", protocol_strerror(-r));
    return 1;
  }
  return 0;
}

/*
 * argv[0] - session_id_file
 */
static int
handle_dump_all_users(const unsigned char *cmd,
                      int srv_cmd, int argc, char *argv[])
{
  int r;

  if (argc < 1) return too_few_params(cmd);
  if (argc > 1) return too_many_params(cmd);

  authentificate(argv[0]);
  r = userlist_clnt_dump_database(userlist_conn, ULS_DUMP_WHOLE_DATABASE, 0, 1, 0);
  if (r < 0) {
    err("userlist-server error: %s", userlist_strerror(-r));
    return 1;
  }

  return 0;
}

/*
 * argv[0] - session_id_file
 */
static int
handle_userlist_server_param(const unsigned char *cmd,
                             int srv_cmd, int argc, char *argv[])
{
  int r;
  unsigned char *out_str = 0;

  if (argc < 1) return too_few_params(cmd);
  if (argc > 1) return too_many_params(cmd);

  authentificate(argv[0]);
  r = userlist_clnt_get_param(userlist_conn, srv_cmd, contest_id, &out_str);
  if (r < 0) {
    err("userlist-server error: %s", userlist_strerror(-r));
    return 1;
  }

  printf("%s\n", out_str);
  return 0;
}

/*
 * argv[0] - session_id_file
 */
static int
handle_priv_command_0(const unsigned char *cmd,
                      int srv_cmd, int argc, char *argv[])
{
  int r;

  if (argc < 1) return too_few_params(cmd);
  if (argc > 1) return too_many_params(cmd);

  authentificate(argv[0]);
  open_server();

  r = serve_clnt_simple_cmd(serve_socket_fd, srv_cmd, 0, 0);
  if (r < 0) {
    err("server error: %s", protocol_strerror(-r));
    return 1;
  }
  return 0;
}

/*
 * argv[0] - session_id_file
 */
static int
handle_serve_get_param(const unsigned char *cmd,
                       int srv_cmd, int argc, char *argv[])
{
  int r;
  unsigned char *str = 0;

  if (argc < 1) return too_few_params(cmd);
  if (argc > 1) return too_many_params(cmd);

  authentificate(argv[0]);
  open_server();

  r = serve_clnt_get_param(serve_socket_fd, srv_cmd, &str);
  if (r < 0) {
    err("server error: %s", protocol_strerror(-r));
    return 1;
  }
  printf("%s\n", str);
  xfree(str);
  return 0;
}

/*
 * argv[0] - session_id_file
 */
static int
handle_priv_transient_runs(const unsigned char *cmd,
                           int srv_cmd, int argc, char *argv[])
{
  int r;

  if (argc < 1) return too_few_params(cmd);
  if (argc > 1) return too_many_params(cmd);

  authentificate(argv[0]);
  open_server();

  r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_HAS_TRANSIENT_RUNS, 0, 0);
  if (r == -SRV_ERR_TRANSIENT_RUNS) {
    printf("There are transient runs\n");
    return 2;
  }
  if (r < 0) {
    err("server error: %s", protocol_strerror(-r));
    return 1;
  }
  printf("There is no transient runs\n");
  return 0;
}

/*
 * argv[0] - session_id_file
 */
static int
handle_logout(const unsigned char *cmd,
              int srv_cmd, int argc, char *argv[])
{
  if (argc < 1) return too_few_params(cmd);
  if (argc > 1) return too_many_params(cmd);

  authentificate(argv[0]);
  userlist_clnt_logout(userlist_conn, ULS_DO_LOGOUT, local_ip, 1, session_id);
  unlink(argv[0]);
  return 0;
}

/*
 * argv[0] - session_id_file
 * argv[1] - XML runlog file
 */
static int
handle_import_xml(const unsigned char *cmd,
                  int srv_cmd, int argc, char *argv[])
{
  char *xml_txt = 0;
  size_t xml_txt_size;
  int r;

  if (argc < 2) return too_few_params(cmd);
  if (argc > 2) return too_many_params(cmd);

  authentificate(argv[0]);
  open_server();

  if (generic_read_file(&xml_txt, 0, &xml_txt_size, 0, 0, argv[1], 0) < 0) {
    err("reading %s failed", argv[1]);
    return 1;
  }

  if ((r = serve_clnt_import_xml_runs(serve_socket_fd, 2, 1, xml_txt)) < 0) {
    err("server error: %s", protocol_strerror(-r));
    return 1;
  }
  xfree(xml_txt);
  return 0;
}

/*
 * argv[0] - session_id_file
 * argv[1] - run Id
 */
static int
handle_dump_source(const unsigned char *cmd,
                   int srv_cmd, int argc, char *argv[])
{
  int run_id, r;

  if (argc < 2) return too_few_params(cmd);
  if (argc > 2) return too_many_params(cmd);

  if (sscanf(argv[1], "%d%n", &run_id, &r) != 1 || argv[1][r]
      || run_id < 0 || run_id >= 1000000) {
    err("value of run_id is invalid");
    return 1;
  }

  authentificate(argv[0]);
  open_server();

  r = serve_clnt_view(serve_socket_fd, 1, srv_cmd, run_id, 0, 0, 0, 0, 0);
  if (r < 0) {
    err("server error: %s", protocol_strerror(-r));
    return 1;
  }

  return 0;
}

/*
 * argv[0] - session_id_file
 * argv[1] - filter_expr
 * argv[2] - first_run
 * argv[3] - last_run
 */
static int
handle_dump_master_runs(const unsigned char *cmd,
                        int srv_cmd, int argc, char *argv[])
{
  int n, first_run = 0, last_run = 0, r;

  if (argc < 4) return too_few_params(cmd);
  if (argc > 4) return too_many_params(cmd);

  if (argv[2] && argv[2][0]) {
    if (sscanf(argv[2], "%d%n", &first_run, &n) != 1 || argv[2][n]) {
      err("value of first_run is invalid");
      return 1;
    }
    if (first_run >= 0) first_run++;
  }
  if (argv[3] && argv[3][0]) {
    if (sscanf(argv[3], "%d%n", &last_run, &n) != 1 || argv[3][n]) {
      err("value of last_run is invalid");
      return 1;
    }
    if (last_run >= 0) last_run++;
  }

  authentificate(argv[0]);
  open_server();

  r = serve_clnt_master_page(serve_socket_fd, 1,
                             SRV_CMD_DUMP_MASTER_RUNS,
                             session_id, 0,
                             contest_id, 0, local_ip, 1,
                             PRIV_LEVEL_ADMIN,
                             first_run, last_run, 0, 0, 0, "", argv[1], "", "");
  if (r < 0) {
    err("server error: %s", protocol_strerror(-r));
    return 1;
  }

  return 0;
}

static volatile int was_interrupt = 0;
static volatile int was_alarm = 0;

static void
interrupt_handler(int signo)
{
  was_interrupt = 1;
}
static void
alarm_handler(int signo)
{
  was_alarm = 1;
}

/*
 * argv[0] - session_id_file
 * argv[1] - XML runlog file
 * argv[2] - XML runlog file
 * argv[3] - ...
 * note, that arbitrary number of XML run logs may be imported at a time
 */
static int
handle_full_import_xml(const unsigned char *cmd,
                       int srv_cmd, int argc, char *argv[])
{
  char **xml_txts;
  size_t *xml_txt_sizes;
  int r, i, retcode = 1, prev_state = 0;
  sigset_t blkmask, origmask;
  struct itimerval tmval;

  if (argc < 2) return too_few_params(cmd);

  XALLOCAZ(xml_txts, argc);
  XALLOCAZ(xml_txt_sizes, argc);
  for (i = 1; i < argc; i++) {
    if (generic_read_file(xml_txts+i, 0, xml_txt_sizes+i, 0, 0, argv[i], 0)<0){
      err("reading %s failed", argv[i]);
      return 1;
    }
  }

  authentificate(argv[0]);
  open_server();

  sigemptyset(&blkmask);
  sigaddset(&blkmask, SIGHUP);
  sigaddset(&blkmask, SIGALRM);
  sigaddset(&blkmask, SIGINT);
  sigaddset(&blkmask, SIGTERM);
  sigprocmask(SIG_BLOCK, &blkmask, &origmask);
  signal(SIGHUP, interrupt_handler);
  signal(SIGINT, interrupt_handler);
  signal(SIGTERM, interrupt_handler);
  signal(SIGALRM, alarm_handler);

  // get previous testing status
  prev_state = serve_clnt_simple_cmd(serve_socket_fd,
                                     SRV_CMD_GET_TEST_SUSPEND, 0, 0);
  if (prev_state < 0) {
    err("server error: %s", protocol_strerror(prev_state));
    return 1;
  }

  // disable testing
  if (!prev_state) {
    r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_TEST_SUSPEND, 0, 0);
    if (r < 0) {
      err("server error: %s", protocol_strerror(-r));
      return 1;
    }
  }

  sigprocmask(SIG_UNBLOCK, &blkmask, 0);
  sigprocmask(SIG_BLOCK, &blkmask, 0);
  if (was_interrupt) {
    retcode = 2;
    goto recover_and_exit;
  }

  while (1) {
    // try to get transient run status
    r = serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_HAS_TRANSIENT_RUNS,0,0);
    if (!r) break;
    if (r != -SRV_ERR_TRANSIENT_RUNS) {
      err("server error: %s", protocol_strerror(-r));
      goto recover_and_exit;
    }
    // sleep for 1 second
    was_alarm = 0;
    memset(&tmval, 0, sizeof(tmval));
    tmval.it_value.tv_sec = 1;
    tmval.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &tmval, 0);
    fprintf(stderr, "Waiting 1 second...\n");
    while (!was_interrupt && !was_alarm) sigsuspend(&origmask);
    if (was_interrupt) {
      retcode = 2;
      fprintf(stderr, "Interrupted\n");
      goto recover_and_exit;
    }
  }

  // import all logs one by one
  retcode = 0;
  for (i = 1; i < argc; i++) {
    fprintf(stderr, "Importing %s...\n", argv[i]);
    r = serve_clnt_import_xml_runs(serve_socket_fd, 2, 1, xml_txts[i]);
    if (r < 0) {
      err("server error: %s", protocol_strerror(-r));
      retcode = 3;
    }
  }

 recover_and_exit:
  if (!prev_state) {
    serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_TEST_RESUME, 0, 0);
    serve_clnt_simple_cmd(serve_socket_fd, SRV_CMD_JUDGE_SUSPENDED, 0, 0);
  }
  return retcode;
}

struct cmdinfo
{
  const unsigned char *cmdname;
  int (*cmdfunc)(const unsigned char *cmd, int, int argnum, char *argptr[]);
  int srvcmd;
};
static struct cmdinfo cmds[] =
{
  { "login", handle_login, 0 },
  { "logout", handle_logout, 0 },
  { "write-xml-runs", handle_dump_runs, SRV_CMD_WRITE_XML_RUNS },
  { "export-xml-runs", handle_dump_runs, SRV_CMD_EXPORT_XML_RUNS },
  { "dump-runs", handle_dump_runs, SRV_CMD_DUMP_RUNS },
  { "dump-problems", handle_dump_runs, SRV_CMD_DUMP_PROBLEMS },
  { "soft-update-stand", handle_priv_command_0, SRV_CMD_SOFT_UPDATE_STAND },
  { "import-xml-runs", handle_import_xml, 0 },
  { "dump-source", handle_dump_source, SRV_CMD_PRIV_DOWNLOAD_RUN },
  { "dump-report", handle_dump_source, SRV_CMD_PRIV_DOWNLOAD_REPORT },
  { "dump-team-report", handle_dump_source, SRV_CMD_PRIV_DOWNLOAD_TEAM_REPORT },
  { "dump-standings", handle_dump_runs, SRV_CMD_DUMP_STANDINGS },
  { "dump-master-runs", handle_dump_master_runs, 0 },
  { "suspend-testing", handle_priv_command_0, SRV_CMD_TEST_SUSPEND },
  { "resume-testing", handle_priv_command_0, SRV_CMD_TEST_RESUME },
  { "judge-suspended-runs", handle_priv_command_0, SRV_CMD_JUDGE_SUSPENDED },
  { "has-transient-runs", handle_priv_transient_runs, 0 },
  { "full-import-xml-runs", handle_full_import_xml, 0 },
  { "dump-all-users", handle_dump_all_users, 0 },
  { "get-contest-name", handle_userlist_server_param, ULS_GET_CONTEST_NAME },
  { "get-contest-type", handle_serve_get_param, SRV_CMD_GET_CONTEST_TYPE },

  { 0, 0 },
};

int
main(int argc, char *argv[])
{
  int i = 1, n;

  program_path = argv[0];
  program_name = os_GetBasename(program_path);
  logger_set_level(-1, LOG_WARNING);

  // parse global options
  while (i < argc) {
    if (!strcmp(argv[i], "-e")) {
      if (i + 1 >= argc) goto option_value_expected;
      ejudge_xml_path = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "-r")) {
      if (i + 1 >= argc) goto option_value_expected;
      contest_root_dir = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (argv[i][0] == '-') {
      fprintf(stderr, "%s: unhandled option %s\n", program_name, argv[i]);
      return 1;
    } else {
      break;
    }
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) {
    ejudge_xml_path = EJUDGE_XML_PATH;
  }
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) {
    fprintf(stderr, "%s: configuration file is not specified\n", program_name);
    return 1;
  }

  config = userlist_cfg_parse(ejudge_xml_path);
  if (!config) return 1;
  if (!config->contests_dir) {
    err("<contests_dir> tag is not set!");
    return 1;
  }
  if (contests_set_directory(config->contests_dir) < 0) {
    err("contests directory is invalid");
    return 1;
  }

  // first mandatory parameter: contest_id
  if (i >= argc) goto too_few_arguments;
  if (sscanf(argv[i], "%d%n", &contest_id, &n) != 1 || argv[i][n]) {
    err("failed to parse %s as contest id", argv[i]);
    return 1;
  }
  i++;
  if (contest_id <= 0 || contest_id >= 1000000) {
    err("invalid contest_id %d", contest_id);
    return 1;
  }
  if ((n = contests_get(contest_id, &cnts)) < 0) {
    err("cannot load contest %d: %s", contest_id, contests_strerror(-n));
    return 1;
  }

  if (!contest_root_dir && cnts->root_dir) {
    contest_root_dir = xstrdup(cnts->root_dir);
  }
  if (!contest_root_dir) {
    err("contest root dir is not set");
    return 1;
  }

  if (!(userlist_conn = userlist_clnt_open(config->socket_path))) {
    err("cannot open userlist-server connection: %s", os_ErrorMsg());
    return 1;
  }
  /*
  if ((n = userlist_clnt_admin_process(userlist_conn)) < 0) {
    err("cannot became an admin process: %s", userlist_strerror(-n));
    return 1;
  }
  */

  snprintf(serve_socket_path, sizeof(serve_socket_path),
           "%s/var/serve", contest_root_dir);

  // set the IP address
  local_ip = (127 << 24) | 1;

  if (i >= argc) goto too_few_arguments;
  for (n = 0; cmds[n].cmdname; n++) {
    if (!strcmp(cmds[n].cmdname, argv[i]))
      return (*cmds[n].cmdfunc)(argv[i], cmds[n].srvcmd,
                                argc - i - 1, argv + i + 1);
  }
  err("invalid command %s", argv[i]);
  return 1;

 option_value_expected:
  fprintf(stderr, "%s: option value expected for %s\n", program_name, argv[i]);
  return 1;

 too_few_arguments:
  fprintf(stderr, "%s: too few arguments specified\n", program_name);
  return 1;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
