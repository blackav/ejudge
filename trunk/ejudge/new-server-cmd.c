/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_types.h"
#include "version.h"

#include "ejudge_cfg.h"
#include "contests.h"
#include "pathutl.h"
#include "xml_utils.h"
#include "new_server_clnt.h"
#include "new-server.h"
#include "new_server_proto.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

static const unsigned char *program_name = "";
static const unsigned char *program_path = "";

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
  printf("%s: new-server command line client\n"
         "Usage: %s [OPTIONS] CNTS-ID COMMAND CMD-ARGS\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "    -f CFG    specify the ejudge configuration file\n"
         "  COMMAND:\n"
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

static void invoke_serve_cmd(int argc, char *argv[])
  __attribute__((noreturn));
static void
invoke_serve_cmd(int argc, char *argv[])
{
  char *dn;
  path_t serve_cmd_path;
  char **args;
  int i;

  // substitute argv[0]
  if (!strchr(argv[0], '/')) {
    snprintf(serve_cmd_path, sizeof(serve_cmd_path), "serve-cmd");
  } else {
    dn = os_DirName(argv[0]);
    snprintf(serve_cmd_path, sizeof(serve_cmd_path), "%s/serve-cmd",
             dn);
  }

  XCALLOC(args, argc + 1);
  args[0] = serve_cmd_path;
  for (i = 1; i < argc; i++)
    args[i] = argv[i];
  args[i] = 0;
  execve(args[0], args, environ);
  startup_error("cannot execute serve-cmd: %s", os_ErrorMsg());
}

struct ejudge_cfg *config;
static int contest_id;
static const struct contest_desc *cnts;
static ej_ip_t ip_address;
static int ssl_flag;
static int session_mode;
static const unsigned char *script_name = 0;
static const unsigned char *http_host = 0;
static const unsigned char *socket_path = 0;
static int use_reply_buf = 0;
static unsigned char *reply_buf;
static size_t reply_size;
static const unsigned char *session_id_file;
static ej_cookie_t session_id;

static unsigned char **cgi_environ = 0;
static int cgi_environ_a = 0;
static int cgi_environ_u = 0;

static int cgi_param_u = 0, cgi_param_a = 0;
static unsigned char **cgi_param_names = 0;
static size_t *cgi_param_sizes = 0;
static unsigned char **cgi_param_values = 0;

static void
put_cgi_environ(const unsigned char *name, const unsigned char *value)
{
  size_t slen, nlen;
  int ind = 0, r, j;

  ASSERT(name && *name);
  nlen = strlen(name);

  if (!cgi_environ) {
    if (!value) return;
    cgi_environ_a = 16;
    cgi_environ_u = 0;
    XCALLOC(cgi_environ, cgi_environ_a);
  } else {
    for (ind = 0; ind < cgi_environ_u; ind++) {
      if (!(r = strncmp(name, cgi_environ[ind], nlen))) {
        if (cgi_environ[ind][nlen] != '=') break;
        // exact match
        xfree(cgi_environ[ind]); cgi_environ[ind] = 0;
        if (!value) {
          // remove
          for (j = ind; j < cgi_environ_u; j++)
            cgi_environ[j] = cgi_environ[j + 1];
          cgi_environ_u--;
          return;
        }
        slen = nlen + strlen(value) + 2;
        cgi_environ[ind] = xmalloc(slen);
        sprintf(cgi_environ[ind], "%s=%s", name, value);
        return;
      } else if (r > 0) {
        break;
      }
    }
    // ind - place to insert
    if (!value) return;
  }
  if (cgi_environ_u + 1 >= cgi_environ_a) {
    if (!cgi_environ_a) cgi_environ_a = 8;
    cgi_environ_a *= 2;
    cgi_environ = xrealloc(cgi_environ, cgi_environ_a * sizeof(cgi_environ[0]));
  }
  for (j = cgi_environ_u; j >= ind; j--)
    cgi_environ[j + 1] = cgi_environ[j];
  cgi_environ_u++;
  slen = nlen + strlen(value) + 2;
  cgi_environ[ind] = xmalloc(slen);
  sprintf(cgi_environ[ind], "%s=%s", name, value);
}

static void
put_cgi_param_bin(const unsigned char *name, size_t size,
                  const unsigned char *value)
{
  int ind = 0, r, j;

  ASSERT(name && *name);

  if (!cgi_param_a) {
    if (!value) return;
    cgi_param_a = 16;
    XCALLOC(cgi_param_names, cgi_param_a);
    XCALLOC(cgi_param_sizes, cgi_param_a);
    XCALLOC(cgi_param_values, cgi_param_a);
  } else {
    for (ind = 0; ind < cgi_param_u; ind++) {
      if (!(r = strcmp(name, cgi_param_names[ind]))) {
        if (!value) {
          xfree(cgi_param_names[ind]);
          xfree(cgi_param_values[ind]);
          for (j = ind; j < cgi_param_u; j++) {
            cgi_param_names[j] = cgi_param_names[j + 1];
            cgi_param_sizes[j] = cgi_param_sizes[j + 1];
            cgi_param_values[j] = cgi_param_values[j + 1];
          }
          cgi_param_u--;
          return;
        }
        xfree(cgi_param_values[ind]);
        cgi_param_sizes[ind] = size;
        cgi_param_values[ind] = xmemdup(value, size);
        return;
      } else if (r < 0) {
        break;
      }
    }
    if (!value) return;
  }
  if (cgi_param_u + 1 >= cgi_param_a) {
    cgi_param_a *= 2;
    XREALLOC(cgi_param_names, cgi_param_a);
    XREALLOC(cgi_param_sizes, cgi_param_a);
    XREALLOC(cgi_param_values, cgi_param_a);
  }
  for (j = cgi_param_u; j >= ind; j--) {
    cgi_param_names[j + 1] = cgi_param_names[j];
    cgi_param_sizes[j + 1] = cgi_param_sizes[j];
    cgi_param_values[j + 1] = cgi_param_values[j];
  }
  cgi_param_u++;
  cgi_param_names[ind] = xstrdup(name);
  cgi_param_sizes[ind] = size;
  cgi_param_values[ind] = xmemdup(value, size);
}

static void
create_cgi_environ(void)
{
  /* create CGI environment:
   *   HTTP_HOST
   *   REMOTE_ADDR
   *   SCRIPT_FILENAME - cannot be forged, always new-server-cmd
   *   SCRIPT_NAME
   *   SSL_PROTOCOL
   */

  if (!http_host || !*http_host) http_host = "localhost";
  put_cgi_environ("HTTP_HOST", http_host);
  if (!ip_address)
    put_cgi_environ("REMOTE_ADDR", "127.0.0.1");
  else
    put_cgi_environ("REMOTE_ADDR", xml_unparse_ip(ip_address));
  put_cgi_environ("SCRIPT_FILENAME", program_path);
  if (!script_name) script_name = program_path;
  put_cgi_environ("SCRIPT_NAME", script_name);
  if (ssl_flag)
    put_cgi_environ("SSL_PROTOCOL", "1");
}

static void
put_cgi_param(const unsigned char *name, const unsigned char *str)
{
  put_cgi_param_bin(name, strlen(str), str);
}

static void
put_cgi_param_f(const unsigned char *name, const char *format, ...)
  __attribute__((format(printf, 2, 3), unused));
static void
put_cgi_param_f(const unsigned char *name, const char *format, ...)
{
  va_list args;
  unsigned char buf[8192];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  put_cgi_param(name, buf);
}

static int
parse_int(const char *str, int *p_val)
{
  int v;
  char *eptr = 0;

  errno = 0;
  v = strtol(str, &eptr, 10);
  if (errno || *eptr) return -1;
  return 0;
}

struct role_str_map
{
  const char *str;
  int val;
};
static const struct role_str_map role_str_tab[] =
{
  { "CONTESTANT", USER_ROLE_CONTESTANT },
  { "USER", USER_ROLE_CONTESTANT },
  { "OBSERVER", USER_ROLE_OBSERVER },
  { "EXAMINER", USER_ROLE_EXAMINER },
  { "CHIEF_EXAMINER", USER_ROLE_CHIEF_EXAMINER },
  { "COORDINATOR", USER_ROLE_COORDINATOR },
  { "JUDGE", USER_ROLE_JUDGE },
  { "ADMIN", USER_ROLE_ADMIN },
  { "MASTER", USER_ROLE_ADMIN },

  { 0, 0 },
};
static int
parse_role(const unsigned char *str)
{
  int i;

  for (i = 0; role_str_tab[i].str; i++)
    if (!strcasecmp(role_str_tab[i].str, str))
      return role_str_tab[i].val;

  if (parse_int(str, &i) < 0 || i < 0 || i >= USER_ROLE_LAST)
    startup_error("invalid role `%s'", str);
  return i;
}

static void
shift_args(int *p_argc, char **argv, int i, int n)
{
  int j;
  
  if (i >= *p_argc || i + n > *p_argc) return;
  for (j = i + n; j < *p_argc; j++)
    argv[j - n] = argv[j];
  *p_argc -= n;
}

static void
parse_session_id(int *p_argc, char **argv)
{
  char *endp = 0;
  unsigned char buf[1024];
  int c, blen;
  FILE *f = 0;

  if (!*p_argc) startup_error("session_id is not specified");
  if (session_mode) {
    errno = 0;
    session_id = strtoull(argv[0], &endp, 16);
    if (errno || *endp || !session_id) startup_error("invalid session_id");
  } else if (!strcmp(argv[0], "-") || !strcmp(argv[0], "STDIN")) {
    if (!fgets(buf, sizeof(buf), stdin))
      startup_error("session_id is not specified on STDIN");
    if ((blen = strlen(buf)) > sizeof(buf) - 2)
      startup_error("line is too long on STDIN");
    while (blen > 0 && isspace(buf[blen - 1])) blen--;
    buf[blen] = 0;
    errno = 0;
    session_id = strtoull(buf, &endp, 16);
    if (errno || *endp || !session_id)
      startup_error("invalid session_id on STDIN");
  } else {
    if (!(f = fopen(argv[0], "r")))
      startup_error("cannot open session file `%s'", argv[0]);
    if (!fgets(buf, sizeof(buf), f))
      startup_error("session file `%s' is empty", argv[0]);
    while ((c = getc_unlocked(f)) != EOF && isspace(c));
    if (c != EOF) startup_error("garbage in session file `%s'", argv[0]);
    fclose(f); f = 0;
    if ((blen = strlen(buf)) > sizeof(buf) - 2)
      startup_error("line is too long in session file `%s'", argv[0]);
    while (blen > 0 && isspace(buf[blen - 1])) blen--;
    buf[blen] = 0;
    errno = 0;
    session_id = strtoull(buf, &endp, 16);
    if (errno || *endp || !session_id)
      startup_error("invalid session_id int file `%s'", argv[0]);
  }
  shift_args(p_argc, argv, 0, 1);
  put_cgi_param_f("SID", "%016llx", session_id);
}

/*
 * OPTIONS:
 *  -p      - read password from terminal (no echo)
 *  -f      - read password from file
 *  -r ROLE - specify role
 * argv[0] - session_id_file
 * argv[1] - login
 * argv[2] - password or password file
 */

static void
prepare_login(const unsigned char *cmd, int argc, char *argv[], int role,
              int action)
{
  int i = 0;
  int passwd_flag = 0, passwd_file = 0;
  const unsigned char *login = 0;
  const unsigned char *password = 0;
  unsigned char buf[1024];
  FILE *fpwd = 0;
  int blen;

  if (session_mode)
    op_error("--session is not supported for this command");

  while (i < argc) {
    if (!strcmp(argv[i], "-f")) {
      if (passwd_flag)
        startup_error("-f and -p options cannot be used together in `%s'",
                      cmd);
      passwd_file = 1;
      i++;
    } else if (!strcmp(argv[i], "-p")) {
      if (passwd_file)
        startup_error("-f and -p options cannot be used together in `%s'",
                      cmd);
      passwd_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "-r")) {
      if (i + 1 >= argc)
        startup_error("parameter expected for -r option");
      role = parse_role(argv[i + 1]);
      i += 2;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (argv[i][0] == '-') {
      startup_error("invalid option `%s' for command `%s'",
                    argv[i], cmd);
    } else
      break;
  }
  if (passwd_file) {
    if (i + 3 != argc) startup_error("invalid number of arguments for `%s'",
                                     cmd);
    session_id_file = argv[i++];
    login = argv[i++];
    if (!(fpwd = fopen(argv[i], "r")))
      startup_error("cannot open password file `%s'", argv[i]);
    if (!fgets(buf, sizeof(buf), fpwd))
      startup_error("password file is empty");
    fclose(fpwd); fpwd = 0;
    blen = strlen(buf);
    while (blen > 0 && isspace(buf[blen - 1])) blen--;
    buf[blen] = 0;
    if (!blen) startup_error("password is empty");
    password = buf;
  } else if (passwd_flag) {
    if (i + 2 != argc) startup_error("invalid number of arguments for `%s'",
                                     cmd);
    session_id_file = argv[i++];
    login = argv[i++];
    password = getpass("Password:");
  } else {
    if (i + 3 != argc) startup_error("invalid number of arguments for `%s'",
                                     cmd);
    session_id_file = argv[i++];
    login = argv[i++];
    password = argv[i++];
  }

  put_cgi_param_f("contest_id", "%d", contest_id);
  put_cgi_param("login", login);
  put_cgi_param("password", password);
  put_cgi_param_f("role", "%d", role);
  use_reply_buf = 1;
  put_cgi_param_f("action", "%d", NEW_SRV_ACTION_LOGIN);
}

static int
post_login(void)
{
  char *eptr = 0;
  FILE *fout = 0;

  while (reply_size > 0 && isspace(reply_buf[reply_size - 1])) reply_size--;
  reply_buf[reply_size] = 0;
  if (!reply_size) op_error("reply is empty");

  errno = 0;
  session_id = strtoull(reply_buf, &eptr, 16);
  if (errno || *eptr || reply_buf + reply_size != (unsigned char*) eptr
      || !session_id)
    op_error("invalid session_id");

  if (!strcmp(session_id_file, "-") || !strcmp(session_id_file, "STDOUT")) {
    printf("%016llx\n", session_id);
  } else {
    if (!(fout = fopen(session_id_file, "w")))
      op_error("cannot open output file `%s'", session_id_file);
    fprintf(fout, "%016llx\n", session_id);
    if (ferror(fout) || fclose(fout) < 0)
      op_error("write error");
  }
  
  return 0;
}

static void
prepare_logout(const unsigned char *cmd, int argc, char *argv[], int role,
               int action)
{
  parse_session_id(&argc, argv);
  if (argc != 0) startup_error("invalid number of arguments for logout");
  put_cgi_param_f("action", "%d", NEW_SRV_ACTION_LOGOUT);
}

static void
prepare_simple(const unsigned char *cmd, int argc, char *argv[], int role,
               int action)
{
  parse_session_id(&argc, argv);
  if (argc != 0) startup_error("invalid number of arguments for `%s'", cmd);
  put_cgi_param_f("action", "%d", action);
}

static void
prepare_run_id(const unsigned char *cmd, int argc, char *argv[], int role,
               int action)
{
  int run_id = -1;

  parse_session_id(&argc, argv);
  if (argc != 1) startup_error("invalid number of arguments for `%s'", cmd);
  if (parse_int(argv[0], &run_id) < 0) startup_error("invalid parameter");
  put_cgi_param_f("run_id", "%d", run_id);
  put_cgi_param_f("action", "%d", action);
}

static void
prepare_clar_id(const unsigned char *cmd, int argc, char *argv[], int role,
                int action)
{
  int clar_id = -1;

  parse_session_id(&argc, argv);
  if (argc != 1) startup_error("invalid number of arguments for `%s'", cmd);
  if (parse_int(argv[0], &clar_id) < 0) startup_error("invalid parameter");
  put_cgi_param_f("clar_id", "%d", clar_id);
  put_cgi_param_f("action", "%d", action);
}

static void
read_file(FILE *f, char **out, size_t *out_len)
{
  unsigned char read_buf[4096];
  unsigned char *buf = 0;
  size_t buf_len = 0, read_len = 0;

  while (1) {
    read_len = fread(read_buf, 1, sizeof(read_buf), f);
    if (!read_len) break;
    if (!buf_len) {
      buf = (unsigned char*) xcalloc(read_len + 1, 1);
      memcpy(buf, read_buf, read_len);
      buf_len = read_len;
    } else {
      buf = (unsigned char*) xrealloc(buf, buf_len + read_len);
      memcpy(buf + buf_len, read_buf, read_len);
      buf_len += read_len;
      buf[buf_len] = 0;
    }
  }
  if (ferror(f))
    startup_error("input error");
  if (!buf_len) {
    buf = (unsigned char*) xmalloc(1);
    buf[0] = 0;
    buf_len = 0;
  }
  if (out) *out = buf;
  if (out_len) *out_len = buf_len;
}

/*
 * argv[0] - problem short name
 * argv[1] - language short name
 * argv[2] - source file name (or stdin)
 * argv[3] - variant (optionally, for privileged submits)
 */
static void
prepare_submit_run(const unsigned char *cmd, int argc, char *argv[], int role,
                   int action)
{
  FILE *fin = 0;
  char *run_txt = 0;
  size_t run_len = 0;
  int variant = -1;

  parse_session_id(&argc, argv);

  if (argc < 2 || argc > 4)
    startup_error("invalid number of arguments for `%s'", cmd);

  if (argc == 2 || !strcmp(argv[2], "-") || !strcmp(argv[2], "STDIN")) {
    fin = stdin;
  } else {
    if (!(fin = fopen(argv[2], "r")))
      startup_error("cannot open file `%s'", argv[2]);
  }
  read_file(fin, &run_txt, &run_len);
  if (fin != stdin) fclose(fin);
  if (argc == 4) {
    if (parse_int(argv[3], &variant) < 0 || variant < 0)
      startup_error("invalid variant");
  }

  put_cgi_param("prob", argv[0]);
  put_cgi_param("lang", argv[1]);
  put_cgi_param_bin("file", run_len, run_txt);
  if (variant >= 0) {
    put_cgi_param_f("variant", "%d", variant);
  }
  put_cgi_param_f("action", "%d", NEW_SRV_ACTION_SUBMIT_RUN);
}

struct command_handler
{
  const char *cmd;
  void (*pre_func)(const unsigned char *, int, char **, int, int);
  int (*post_func)(void);
  int role;
  int action;
};
static const struct command_handler handler_table[] =
{
  { "login", prepare_login, post_login, USER_ROLE_ADMIN, 0 },
  { "team-login", prepare_login, post_login, USER_ROLE_CONTESTANT, 0 },
  { "user-login", prepare_login, post_login, USER_ROLE_CONTESTANT, 0 },
  { "observer-login", prepare_login, post_login, USER_ROLE_OBSERVER, 0 },
  { "examiner-login", prepare_login, post_login, USER_ROLE_EXAMINER, 0 },
  { "chief-examiner-login",prepare_login,post_login,USER_ROLE_CHIEF_EXAMINER,0},
  { "coordinator-login", prepare_login, post_login, USER_ROLE_COORDINATOR, 0 },
  { "judge-login", prepare_login, post_login, USER_ROLE_JUDGE, 0 },
  { "admin-login", prepare_login, post_login, USER_ROLE_ADMIN, 0 },
  { "master-login", prepare_login, post_login, USER_ROLE_ADMIN, 0 },
  { "logout", prepare_logout, 0, 0, 0 },
  { "write-xml-runs", prepare_simple, 0, 0, NEW_SRV_ACTION_WRITE_XML_RUNS },
  { "export-xml-runs", prepare_simple, 0, 0, NEW_SRV_ACTION_EXPORT_XML_RUNS},
  { "dump-runs", prepare_simple, 0, 0, NEW_SRV_ACTION_VIEW_RUNS_DUMP },
  { "dump-problems", prepare_simple, 0, 0, NEW_SRV_ACTION_DUMP_PROBLEMS },
  { "soft-update-stand", prepare_simple, 0, 0, NEW_SRV_ACTION_SOFT_UPDATE_STANDINGS },
  { "suspend-testing", prepare_simple, 0, 0, NEW_SRV_ACTION_TEST_SUSPEND },
  { "resume-testing", prepare_simple, 0, 0, NEW_SRV_ACTION_TEST_RESUME },
  { "judge-suspended-runs", prepare_simple, 0, 0, NEW_SRV_ACTION_REJUDGE_SUSPENDED_2 },
  { "has-transient-runs", prepare_simple, 0, 0, NEW_SRV_ACTION_HAS_TRANSIENT_RUNS },
  { "team-run-status", prepare_run_id, 0, 0, NEW_SRV_ACTION_DUMP_RUN_STATUS },
  { "run-status", prepare_run_id, 0, 0, NEW_SRV_ACTION_DUMP_RUN_STATUS },
  { "dump-source", prepare_run_id, 0, 0, NEW_SRV_ACTION_DUMP_SOURCE },
  { "team-dump-source", prepare_run_id, 0, 0, NEW_SRV_ACTION_DUMP_SOURCE },
  { "dump-clar", prepare_clar_id, 0, 0, NEW_SRV_ACTION_DUMP_CLAR },
  { "team-dump-clar", prepare_clar_id, 0, 0, NEW_SRV_ACTION_DUMP_CLAR },
  { "get-contest-name", prepare_simple, 0, 0, NEW_SRV_ACTION_GET_CONTEST_NAME },
  { "get-contest-type", prepare_simple, 0, 0, NEW_SRV_ACTION_GET_CONTEST_TYPE },
  { "submit-run", prepare_submit_run, 0, 0, 0 },
  { "team-submit-run", prepare_submit_run, 0, 0, 0 },

  { 0, 0 },
};

/*
static struct cmdinfo cmds[] =
{
  { "import-xml-runs", handle_import_xml, 0 },
  { "dump-report", handle_dump_source, SRV_CMD_PRIV_DOWNLOAD_REPORT },
  { "dump-team-report", handle_dump_source, SRV_CMD_PRIV_DOWNLOAD_TEAM_REPORT },
  { "dump-standings", handle_dump_runs, SRV_CMD_DUMP_STANDINGS },
  { "dump-master-runs", handle_dump_master_runs, 0 },
  { "full-import-xml-runs", handle_full_import_xml, 0 },
  { "dump-all-users", handle_dump_all_users, 0 },

  { 0, 0 },
};
*/

int
main(int argc, char *argv[])
{
  int i, n, r, j, arg_start;
  const unsigned char *ejudge_xml_path = 0;
  const unsigned char *command = 0;
  new_server_conn_t conn = 0;
  unsigned char **p1 = 0;
  size_t *p2 = 0;
  int fd = 1;

  program_path = argv[0];
  program_name = os_GetBasename(argv[0]);

  if (argc <= 1) startup_error("not enough parameters");

  if (!strcmp(argv[1], "--help")) {
    write_help();
  } else if (!strcmp(argv[1], "--version")) {
    write_version();
  }

  // pre-command options
  i = 1;
  while (i < argc) {
    if (!strcmp(argv[i], "-f")) {
      if (i + 1 >= argc) startup_error("argument expected for `-f'");
      ejudge_xml_path = argv[i + 1];
      i += 2;
    } else if (!strcmp(argv[i], "--")) {
      i++;
      break;
    } else if (argv[i][0] == '-') {
      startup_error("invalid option `%s'", argv[i]);
    } else {
      break;
    }
  }

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) startup_error("ejudge.xml path is not specified");
  if (!(config = ejudge_cfg_parse(ejudge_xml_path))) return 1;
  if (!config->contests_dir) startup_error("<contests_dir> tag is not set!");
  if (contests_set_directory(config->contests_dir) < 0)
    startup_error("contests directory is invalid");

  // contest-id
  if (i >= argc) startup_error("contest-id is expected");
  if (sscanf(argv[i], "%d%n", &contest_id, &n) != 1 || argv[i][n])
    startup_error("invalid contest-id `%s'", argv[i]);
  if (contest_id <= 0 || contest_id >= 1000000)
    startup_error("invalid contest-id %d", contest_id);
  if ((n = contests_get(contest_id, &cnts)) < 0)
    startup_error("cannot load contest %d: %s",
                  contest_id, contests_strerror(-n));
  i++;
  
  if (i >= argc) startup_error("command expected");
  command = argv[i++];

  // if the contest is not new-managed, invoke serve-cmd
  if (!cnts->new_managed) invoke_serve_cmd(argc, argv);

#if defined EJUDGE_NEW_SERVER_SOCKET
  if (!socket_path) socket_path = EJUDGE_NEW_SERVER_SOCKET;
#endif
  if (!socket_path) socket_path = EJUDGE_NEW_SERVER_SOCKET_DEFAULT;

  /* parse generic options */
  arg_start = i;
  while (i < argc) {
    if (!strcmp(argv[i], "--ip")) {
      if (i + 1 >= argc) startup_error("argument expected for --ip");
      if (xml_parse_ip(NULL, 0, 0, argv[i + 1], &ip_address) < 0)
        return 1;
      shift_args(&argc, argv, i, 2);
    } else if (!strncmp(argv[i], "--ip=", 5)) {
      if (xml_parse_ip(NULL, 0, 0, argv[i] + 5, &ip_address) < 0)
        return 1;
      shift_args(&argc, argv, i, 1);
    } else if (!strcmp(argv[i], "--ssl")) {
      ssl_flag = 1;
      shift_args(&argc, argv, i, 1);
    } else if (!strcmp(argv[i], "--no-ssl")) {
      ssl_flag = 0;
      shift_args(&argc, argv, i, 1);
    } else if (!strcmp(argv[i], "--session")) {
      session_mode = 1;
      shift_args(&argc, argv, i, 1);
    } else if (!strcmp(argv[i], "--script-name")) {
      if (i + 1>= argc) startup_error("argument expected for --script-name");
      script_name = argv[i + 1];
      shift_args(&argc, argv, i, 2);
    } else if (!strncmp(argv[i], "--script-name=", 14)) {
      script_name = argv[i] + 14;
      shift_args(&argc, argv, i, 1);
    } else if (!strcmp(argv[i], "--http-host")) {
      if (i + 1>= argc) startup_error("argument expected for --http-host");
      http_host = argv[i + 1];
      shift_args(&argc, argv, i, 2);
    } else if (!strncmp(argv[i], "--http-host=", 12)) {
      http_host = argv[i] + 12;
      shift_args(&argc, argv, i, 1);
    } else if (!strcmp(argv[i], "--")) {
      break;
    } else if (argv[i][0] == '-') {
      i++;
    } else {
      break;
    }
  }

  /* call request preparer */
  for (j = 0; handler_table[j].cmd; j++)
    if (!strcasecmp(handler_table[j].cmd, command)) {
      (*handler_table[j].pre_func)(command, argc - arg_start,
                                   argv + arg_start,
                                   handler_table[j].role,
                                   handler_table[j].action);
      break;
    }
  if (!handler_table[j].cmd)
    startup_error("invalid command `%s'", command);

  /* invoke request */
  create_cgi_environ();
  if ((r = new_server_clnt_open(socket_path, &conn)) < 0)
    op_error("cannot connect to the server: %d", -r);
  if (use_reply_buf) {
    fd = -1;
    p1 = &reply_buf;
    p2 = &reply_size;
  }
  r = new_server_clnt_http_request(conn, fd, (unsigned char**) argv,
                                   cgi_environ,
                                   cgi_param_u, cgi_param_names,
                                   cgi_param_sizes, cgi_param_values,
                                   p1, p2);
  if (r < 0)
    op_error("request failed: %d, %s", -r, ns_strerror_2(r));

  /* call request post-processor */
  r = 0;
  if (handler_table[j].post_func) {
    r = (*handler_table[j].post_func)();
  }
  if (r < 0) r = 1;
  else if (r == -NEW_SRV_ERR_TRANSIENT_RUNS || r == -NEW_SRV_ERR_TRY_AGAIN)r=2;
  else r = 0;

  return r;
}
