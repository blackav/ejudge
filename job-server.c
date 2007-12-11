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

#include "errlog.h"
#include "ejudge_cfg.h"
#include "pathutl.h"
#include "fileutl.h"
#include "startstop.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <time.h>

static struct ejudge_cfg *config;
static path_t job_server_log_path;
static path_t job_server_spool_path;
static path_t job_server_work_path;
static path_t job_server_dir_path;
static volatile int term_signal_flag;
static volatile int hup_signal_flag;
static volatile int notify_signal_flag;
static volatile int child_signal_flag;
static sigset_t blkmask, waitmask;
static int job_server_dir_fd = -1;

static int
make_path_in_var_dir(unsigned char *buf, const unsigned char *file)
{
  if (!config->var_dir || !os_IsAbsolutePath(config->var_dir)) {
    err("<var_dir> is not set or not an absolute path");
    return -1;
  }
  snprintf(buf, sizeof(path_t), "%s/%s", config->var_dir, file);
  return 0;
}

static int
prepare_config_vars(void)
{
  if (config->job_server_log) {
    if (os_IsAbsolutePath(config->job_server_log)) {
      snprintf(job_server_log_path, sizeof(job_server_log_path),
               "%s", config->job_server_log);
    } else {
      if (make_path_in_var_dir(job_server_log_path,
                               config->job_server_log) < 0)
        return -1;
    }
  } else {
    if (make_path_in_var_dir(job_server_log_path, "job_server.log") < 0)
      return -1;
  }

  if (config->job_server_spool) {
    if (os_IsAbsolutePath(config->job_server_spool)) {
      snprintf(job_server_spool_path, sizeof(job_server_spool_path),
               "%s", config->job_server_spool);
    } else {
      if (make_path_in_var_dir(job_server_spool_path,
                               config->job_server_spool) < 0)
        return -1;
    }
  } else {
    if (make_path_in_var_dir(job_server_spool_path, "jspool") < 0)
      return -1;
  }

  if (config->job_server_work) {
    if (os_IsAbsolutePath(config->job_server_work)) {
      snprintf(job_server_work_path, sizeof(job_server_work_path),
               "%s", config->job_server_work);
    } else {
      if (make_path_in_var_dir(job_server_work_path,
                               config->job_server_work) < 0)
        return -1;
    }
  } else {
    if (make_path_in_var_dir(job_server_work_path, "jwork") < 0)
      return -1;
  }

  if (make_dir(job_server_work_path, 0) < 0) return -1;
  if (make_all_dir(job_server_spool_path, 0) < 0) return -1;

  return 0;
}

static void
term_signal_handler(int sig)
{
  term_signal_flag = 1;
}
static void
hup_signal_handler(int sig)
{
  term_signal_flag = 1;
  hup_signal_flag = 1;
}
static void
notify_signal_handler(int sig)
{
  notify_signal_flag = 1;
}
static void
child_signal_handler(int sig)
{
  child_signal_flag = 1;
}

static void
prepare_sinals(void)
{

  sigemptyset(&waitmask);
  sigemptyset(&blkmask);
  sigaddset(&blkmask, SIGINT);
  sigaddset(&blkmask, SIGTERM);
  sigaddset(&blkmask, SIGHUP);
  sigaddset(&blkmask, SIGRTMIN);
  sigaddset(&blkmask, SIGCHLD);
  sigprocmask(SIG_BLOCK, &blkmask, 0);
  signal(SIGINT, term_signal_handler);
  signal(SIGTERM, term_signal_handler);
  signal(SIGHUP, hup_signal_handler);
  signal(SIGRTMIN, notify_signal_handler);
  signal(SIGCHLD, child_signal_handler);
  signal(SIGPIPE, SIG_IGN);
}

static int
prepare_directory_notify(void)
{
  snprintf(job_server_dir_path, sizeof(job_server_dir_path),
           "%s/dir", job_server_spool_path);
  if ((job_server_dir_fd = open(job_server_dir_path, O_RDONLY, 0)) < 0) {
    err("cannot open directory `%s'", job_server_dir_path);
    return -1;
  }
  if (fcntl(job_server_dir_fd, F_SETSIG, SIGRTMIN) < 0) {
    err("fcntl failed on `%s'", job_server_dir_path);
    return -1;
  }
  if (fcntl(job_server_dir_fd, F_NOTIFY,
            DN_CREATE | DN_DELETE | DN_RENAME | DN_MULTISHOT) < 0) {
    err("fcntl failed on `%s'", job_server_dir_path);
    return -1;
  }

  return 0;
}

static int
parse_incoming_packet(const char *data, size_t length,
                      int *p_argc, char ***p_argv)
{
  int argc = 0, i;
  char **argv = 0;
  int *argl;
  int arglength;

  if (length < sizeof(argc)) {
    err("packet is too small");
    return -1;
  }
  memcpy(&argc, data, sizeof(argc));
  data += sizeof(argc); length -= sizeof(argc);
  if (argc <= 0 || argc > 100) {
    err("bad number of arguments");
    return -1;
  }

  XCALLOC(argv, argc + 1);
  XALLOCAZ(argl, argc);

  if (argc * sizeof(argl[0]) > length) {
    err("packet is too small");
    goto failure;
  }
  memcpy(argl, data, argc * sizeof(argl[0]));
  data += argc * sizeof(argl[0]);
  length -= argc * sizeof(argl[0]);
  for (i = 0, arglength = 0; i < argc; i++) {
    if (argl[i] < 0 || argl[i] > 65535) {
      err("invalid argument length");
      goto failure;
    }
    arglength += argl[i];
    argv[i] = xmalloc(argl[i] + 1);
  }
  if (arglength != length) {
    err("invalid argument length");
    goto failure;
  }
  for (i = 0; i < argc; i++) {
    memcpy(argv[i], data, argl[i]);
    argv[i][argl[i]] = 0;
    data += argl[i]; length -= argl[i];
  }
  *p_argc = argc;
  *p_argv = argv;
  return 0;

 failure:
  if (argv) {
    for (i = 0; i < argc; i++)
      xfree(argv[i]);
    xfree(argv);
  }
  return -1;
}

static int
run_process(char * const *args, const char *stdin_buf)
{
  int inp[2] = { -1, -1 }, outp[2] = { -1, -1 };
  int pid, nfd, r;
  sigset_t chldmask, wmask, prevmask;
  fd_set rset, wset, *prset, *pwset;
  struct timeval tout;
  const char *outbuf = 0;
  int outbuf_len = 0, pstat, retval = -1;
  char *inbuf = 0;
  size_t inbuf_len = 0;
  FILE *in = 0;
  char pbuf[4096];
  char *coredumped = "";

  if (stdin_buf && !*stdin_buf) stdin_buf = 0;
  if (stdin_buf) {
    if (pipe(inp) < 0) {
      err("pipe() failed: %s", os_ErrorMsg());
      goto cleanup;
    }
    outbuf = stdin_buf;
    outbuf_len = strlen(outbuf);
  }
  if (pipe(outp) < 0) {
    err("pipe() failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  if ((pid = fork()) < 0) {
    err("fork() failed: %s", os_ErrorMsg());
    goto cleanup;
  }
  if (!pid) {
    sigemptyset(&chldmask);
    sigprocmask(SIG_SETMASK, &chldmask, 0);
    close(0);
    if (stdin_buf) {
      dup(inp[0]);
      close(inp[0]);
      close(inp[1]);
    } else {
      if (open("/dev/null", O_RDONLY, 0) < 0) {
        err("open() of /dev/null failed: %s", os_ErrorMsg());
        _exit(1);
      }
    }
    close(1); dup(outp[1]);
    close(2); dup(outp[1]);
    close(outp[0]); close(outp[1]);
    execv(args[0], args);
    err("execv() failed: %s", os_ErrorMsg());
    _exit(1);
  }

  // parent
  info("process %d started", pid);
  if (stdin_buf) close(inp[0]);
  inp[0] = -1;
  close(outp[1]);
  outp[1] = -1;
  if (stdin_buf) fcntl(inp[1], F_SETFL, fcntl(inp[1], F_GETFL) | O_NONBLOCK);
  fcntl(outp[0], F_SETFL, fcntl(outp[0], F_GETFL) | O_NONBLOCK);
  sigemptyset(&wmask);
  sigprocmask(SIG_SETMASK, 0, &prevmask);
  child_signal_flag = 0;
  in = open_memstream(&inbuf, &inbuf_len);

  while (1) {
    FD_ZERO(&rset); prset = 0;
    FD_ZERO(&wset); pwset = 0;
    nfd = -1;
    if (inp[1] >= 0) {
      FD_SET(inp[1], &wset);
      if (inp[1] > nfd) nfd = inp[1];
      pwset = &wset;
    }
    if (outp[0] >= 0) {
      FD_SET(outp[0], &rset);
      if (outp[0] > nfd) nfd = outp[0];
      prset = &rset;
    }
    if (!prset && !pwset) {
      while (!child_signal_flag) sigsuspend(&wmask);
      break;
    }
    tout.tv_sec = 10;
    tout.tv_usec = 0;

    sigprocmask(SIG_SETMASK, &wmask, 0);
    if (child_signal_flag) break;
    nfd = select(nfd, prset, pwset, 0, &tout);
    sigprocmask(SIG_SETMASK, &prevmask, 0);
    if (child_signal_flag) break;

    if (nfd < 0 && errno == EINTR) continue;
    if (nfd < 0) {
      err("select() failed: %s", os_ErrorMsg());
      break;
    }
    if (!nfd) continue;

    if (outp[0] >= 0 && FD_ISSET(outp[0], &rset)) {
      while (1) {
        r = read(outp[0], pbuf, sizeof(pbuf));
        if (r < 0 && errno == EAGAIN) break;
        if (r < 0) {
          err("read() failed: %s", os_ErrorMsg());
          close(outp[0]); outp[0] = -1;
          break;
        }
        if (!r) {
          close(outp[0]); outp[0] = -1;
          break;
        }
        fwrite(pbuf, 1, r, in); // assuming that no errors possible...
      }
    }
    if (inp[1] >= 0 && FD_ISSET(inp[1], &wset)) {
      while (1) {
        r = write(inp[1], outbuf, outbuf_len);
        if (r < 0 && errno == EAGAIN) break;
        if (r < 0 && errno == EPIPE) {
          close(inp[1]); inp[1] = -1;
          break;
        }
        if (r < 0) {
          err("write() failed: %s", os_ErrorMsg());
          close(inp[1]); inp[1] = -1;
          break;
        }
        if (!r) {
          err("write() returned 0");
          continue;
        }
        outbuf += r; outbuf_len -= r;
        if (!outbuf_len) {
          close(inp[1]); inp[1] = -1;
          break;
        }
      }
    }
  }

  if (outp[0]) {
    close(outp[0]); outp[0] = -1;
  }
  if (inp[1]) {
    close(inp[1]); inp[1] = -1;
  }
  fclose(in); in = 0;
  waitpid(pid, &pstat, 0);
  if (WIFEXITED(pstat)) {
    if (!(retval = WEXITSTATUS(pstat))) {
      info("process %d exited normally", pid);
    } else {
      err("process %d exited with code %d", pid, retval);
    }
  } else if (WIFSIGNALED(pstat)) {
    if (WCOREDUMP(pstat)) coredumped = " (core dumped)";
    r = WTERMSIG(pstat);
    err("process %d terminated by signal %d%s", pid, r, coredumped);
    retval = 128 + r;
  } else {
    err("process %d got unexpected exit status 0x%08x", pid, pstat);
    retval = 256;
  }
  if (inbuf && *inbuf) {
    info("process %d output follows:\n%s", pid, inbuf);
  }

 cleanup:
  if (in) fclose(in);
  if (inbuf) xfree(inbuf);
  if (inp[0] >= 0) close(inp[0]);
  if (inp[1] >= 0) close(inp[1]);
  if (outp[0] >= 0) close(outp[0]);
  if (outp[1] >= 0) close(outp[1]);
  return retval;
}

/*
 * [0] - "mail"
 * [1] - charset
 * [2] - subject
 * [3] - from
 * [4] - to
 * [5] - text
 */
static void
handle_mail_packet(int uid, int argc, char **argv)
{
  FILE *f = 0;
  char *full_txt = 0;
  size_t full_len = 0;
  char *charset = 0, r;
  char *prc_args[10];
  unsigned char date_buf[128];
  time_t cur_time;
  struct tm *ptm;

  ASSERT(config->email_program);

  if (argc != 6) {
    err("mail: invalid number of arguments");
    goto cleanup;
  }
  if (argv[1][0]) charset = argv[1];
  if (!charset) charset = EJUDGE_CHARSET;

  cur_time = time(0);
  ptm = localtime(&cur_time);
  strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S %z", ptm);

  f = open_memstream(&full_txt, &full_len);
  fprintf(f,
          "Date: %s\n"
          "Content-type: text/plain; charset=\"%s\"\n"
          "To: %s\n"
          "From: %s\n"
          "Subject: %s\n"
          "\n"
          "%s\n",
          date_buf, charset, argv[4], argv[3], argv[2], argv[5]);
  fclose(f); f = 0;
  if (strstr(config->email_program, "sendmail")) {
    prc_args[0] = config->email_program;
    prc_args[1] = "-B8BITMIME";
    //    prc_args[2] = "-ba";
    prc_args[2] = "-t";
    prc_args[3] = 0;
  } else {
    prc_args[0] = config->email_program;
    prc_args[1] = 0;
  }

  while (1) {
    r = run_process(prc_args, full_txt);
    if (!r) break;
    sleep(10);
  }

 cleanup:
  if (f) fclose(f);
  xfree(full_txt);
}

static void
handle_stop_packet(int uid, int argc, char **argv)
{
  if (uid != 0 && uid != getuid()) {
    // no feedback :(
    err("stop: permission denied for user %d", uid);
    return;
  }
  raise(SIGTERM);
}

static void
handle_restart_packet(int uid, int argc, char **argv)
{
  if (uid != 0 && uid != getuid()) {
    // no feedback :(
    err("stop: permission denied for user %d", uid);
    return;
  }
  raise(SIGHUP);
}

static void
handle_nop_packet(int uid, int argc, char **argv)
{
}

struct cmd_handler_info
{
  char *cmd;
  void (*handler)(int, int, char**);
};
static struct cmd_handler_info handlers[] =
{
  { "mail", handle_mail_packet },
  { "stop", handle_stop_packet },
  { "restart", handle_restart_packet },
  { "nop", handle_nop_packet },

  { NULL, NULL },
};

static void
do_work(void)
{
  int r, argc = 0, i;
  path_t pkt_name;
  path_t pkt_path;
  char *req_buf = 0;
  size_t req_buf_size = 0;
  char **argv = 0;
  struct stat stbuf;

  while (!term_signal_flag) {
    if ((r = scan_dir(job_server_spool_path, pkt_name, sizeof(pkt_name))) < 0) {
      // error
      break;
    }
    if (!r) {
      notify_signal_flag = 0;
      while (!term_signal_flag && !notify_signal_flag)
        sigsuspend(&waitmask);
      continue;
    }

    snprintf(pkt_path, sizeof(pkt_path), "%s/dir/%s", job_server_spool_path,
             pkt_name);
    if (stat(pkt_path, &stbuf) < 0) continue;

    xfree(req_buf); req_buf = 0; req_buf_size = 0;
    r = generic_read_file(&req_buf, 0, &req_buf_size, SAFE | REMOVE,
                          job_server_spool_path, pkt_name, "");
    if (!r) continue;
    if (r < 0) return;

    if (argv) {
      for (i = 0; i < argc; i++)
        xfree(argv[i]);
      xfree(argv);
    }
    argc = 0; argv = 0;
    if (parse_incoming_packet(req_buf, req_buf_size, &argc, &argv) < 0) {
      err("packet parsing error");
      continue;
    }
    if (!argc || !argv || !argv[0]) {
      err("empty packet");
      continue;
    }

    for (i = 0; handlers[i].cmd; i++)
      if (!strcmp(handlers[i].cmd, argv[0]))
        break;
    if (!handlers[i].cmd) {
      err("invalid command `%s'", argv[0]);
      continue;
    }
    (*handlers[i].handler)(stbuf.st_uid, argc, argv);
  }
}

int
main(int argc, char *argv[])
{
  int cur_arg = 1, j = 0;
  int daemon_mode = 0;
  unsigned char *ejudge_xml_path = 0;
  int log_fd = -1;
  int pid;
  const unsigned char *user = 0, *group = 0, *workdir = 0;
  char **argv_restart = 0;

  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 1);
  argv_restart[j++] = argv[0];

  while (cur_arg < argc) {
    if (!strcmp(argv[cur_arg], "-D")) {
      daemon_mode = 1;
      cur_arg++;
    } else if (!strcmp(argv[cur_arg], "-u")) {
      if (cur_arg + 1 >= argc) { 
        err("argument expected for `-u' option");
        return 1;
      }
      user = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-g")) {
      if (cur_arg + 1 >= argc) { 
        err("argument expected for `-g' option");
        return 1;
      }
      group = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-C")) {
      if (cur_arg + 1 >= argc) { 
        err("argument expected for `-C' option");
        return 1;
      }
      workdir = argv[cur_arg + 1];
      cur_arg += 2;
    } else
      break;
  }
  if (cur_arg < argc) {
    argv_restart[j++] = argv[cur_arg];
    ejudge_xml_path = argv[cur_arg++];
  }
  if (cur_arg != argc) {
    err("invalid number of arguments");
    return 1;
  }
  argv_restart[j] = 0;
  start_set_args(argv_restart);

#if defined EJUDGE_XML_PATH
  if (!ejudge_xml_path) {
    ejudge_xml_path = EJUDGE_XML_PATH;
  }
#endif /* EJUDGE_XML_PATH */
  if (!ejudge_xml_path) {
    err("configuration file is not specified");
    return 1;
  }

  if (start_prepare(user, group, workdir) < 0) return 1;

  info("job-server %s, compiled %s", compile_version, compile_date);

  config = ejudge_cfg_parse(ejudge_xml_path);
  if (!config) return 1;
  if (prepare_config_vars() < 0) return 1;
  prepare_sinals();
  notify_signal_flag = 1;
  if (chdir(job_server_work_path) < 0) {
    err("cannot change directory to %s", job_server_work_path);
    return 1;
  }

  if (daemon_mode) {
    log_fd = open(job_server_log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (log_fd < 0) {
      err("cannot open log file `%s'", job_server_log_path);
      return 1;
    }
    close(0);
    if (open("/dev/null", O_RDONLY) < 0) return 1;
    close(1);
    if (open("/dev/null", O_WRONLY) < 0) return 1;
    close(2); dup(log_fd); close(log_fd);
    if ((pid = fork()) < 0) return 1;
    if (pid > 0) _exit(0);
    setsid();
  }

  if (prepare_directory_notify() < 0) return 1;
  do_work();
  if (job_server_dir_fd >= 0) close(job_server_dir_fd);

  if (hup_signal_flag) start_restart();

  return 0;
}
