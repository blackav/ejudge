/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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
#include "contests.h"
#include "userlist_proto.h"
#include "userlist_clnt.h"
#include "serve_clnt.h"
#include "protocol.h"
#include "fileutl.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

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
static unsigned long local_ip;  /* 127.0.0.1 */
static unsigned long long session_id;

enum
  {
    SID_DISABLED = 0,
    SID_EMBED,
    SID_URL,
    SID_COOKIE
  };

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
  int r, user_id;
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

  r = userlist_clnt_priv_cookie(userlist_conn, local_ip, contest_id,
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

  r = userlist_clnt_priv_login(userlist_conn, local_ip, contest_id,
                               0, SID_URL, PRIV_LEVEL_ADMIN,
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

  r = serve_clnt_view(serve_socket_fd, 1, srv_cmd, 0, 0, 0,
                      0, "", "", "");
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
handle_logout(const unsigned char *cmd,
              int srv_cmd, int argc, char *argv[])
{
  if (argc < 1) return too_few_params(cmd);
  if (argc > 1) return too_many_params(cmd);

  authentificate(argv[0]);
  userlist_clnt_logout(userlist_conn, local_ip, session_id);
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
  { "soft-update-stand", handle_priv_command_0, SRV_CMD_SOFT_UPDATE_STAND },
  { "import-xml-runs", handle_import_xml, 0 },

  { 0, 0 },
};

int
main(int argc, char *argv[])
{
  int i = 1, n;

  program_path = argv[0];
  program_name = os_GetBasename(program_path);

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
