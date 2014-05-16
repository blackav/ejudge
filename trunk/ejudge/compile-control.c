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
#include "ejudge/serve_state.h"
#include "ejudge/prepare.h"
#include "ejudge/compile_packet.h"
#include "ejudge/fileutl.h"
#include "ejudge/startstop.h"

#include "reuse/xalloc.h"
#include "reuse/logger.h"
#include "reuse/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

/*
 * usage: ej-compile-control COMMAND CONFIG
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
  printf("%s: ej-compile control utility\n"
         "Usage: %s [OPTIONS] COMMAND [EJUDGE-XML-PATH]\n"
         "  OPTIONS:\n"
         "    --help    write message and exit\n"
         "    --version report version and exit\n"
         "  COMMAND:\n"
         "    stop      stop the ej-compile\n"
         "    restart   restart the ej-compile\n"
         /*"    status    report the ej-compile status\n"*/,
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

struct serve_state serve_state;

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";
static void
b32_number(unsigned long long num, unsigned char buf[])
{
  int i;

  memset(buf, '0', EJ_SERVE_PACKET_NAME_SIZE - 1);
  buf[EJ_SERVE_PACKET_NAME_SIZE - 1] = 0;
  i = EJ_SERVE_PACKET_NAME_SIZE - 2;
  while (num > 0 && i >= 0) {
    buf[i] = b32_digits[num & 0x1f];
    i--;
    num >>= 5;
  }
  ASSERT(!num);
}

void
serve_packet_name(int run_id, int prio, unsigned char buf[])
{
  unsigned long long num = 0;
  struct timeval ts;

  // generate "random" number, that would include the
  // pid of "serve", the current time (with microseconds)
  // and some small random component.
  // pid is 2 byte (15 bit)
  // run_id is 2 byte
  // time_t component - 4 byte
  // nanosec component - 4 byte

  num = (getpid() & 0x7fffLLU) << 25LLU;
  num |= (run_id & 0x7fffLLU) << 40LLU;
  gettimeofday(&ts, 0);
  num |= (ts.tv_sec ^ ts.tv_usec) & 0x1ffffff;
  b32_number(num, buf);
  if (prio < -16) prio = -16;
  if (prio > 15) prio = 15;
  buf[0] = b32_digits[prio + 16];
}

int
main(int argc, char *argv[])
{
  int i = 1;
  const char *command = 0;
  const char *ejudge_xml_path = 0;
  struct ejudge_cfg *config = 0;
  path_t pkt_path;
  int tot_wait = 0, cur_wait = 0;
  const char *config_path = 0;
  const char *conf_suffix = 0;
  const unsigned char *compile_home_dir = 0;
  path_t config_path_buf;
  path_t  cpp_opts = {0};
  int cmd = 0, signum = 0, pid;
  struct compile_request_packet cp;
  void *pkt_buf = 0;
  size_t pkt_len = 0;
  unsigned char pkt_name[EJ_SERVE_PACKET_NAME_SIZE];
  const unsigned char *signame = 0;
  unsigned char cmdstr[1024];

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
    config_path = argv[i];
    i++;
  }

  if (i < argc) startup_error("too many parameters");

  if (config_path) {
    conf_suffix = os_GetSuffix(config_path);
    if (strcmp(conf_suffix, ".cfg") != 0) {
      ejudge_xml_path = config_path;
      config_path = 0;
    }
  }

  if (!config_path) {
#if defined EJUDGE_XML_PATH
    if (!ejudge_xml_path) ejudge_xml_path = EJUDGE_XML_PATH;
#endif /* EJUDGE_XML_PATH */
    if (!ejudge_xml_path) startup_error("ejudge.xml path is not specified");
    if (!(config = ejudge_cfg_parse(ejudge_xml_path))) return 1;
    compile_home_dir = config->compile_home_dir;
#if defined EJUDGE_CONTESTS_HOME_DIR
    if (!compile_home_dir) {
      snprintf(config_path_buf, sizeof(config_path_buf), "%s/compile",
               EJUDGE_CONTESTS_HOME_DIR);
      compile_home_dir = xstrdup(config_path_buf);
    }
#endif
    snprintf(config_path_buf, sizeof(config_path_buf),
             "%s/conf/compile.cfg", compile_home_dir);
    config_path = xstrdup(config_path_buf);
  }

  if (prepare(&serve_state, config_path, 0, PREPARE_COMPILE,cpp_opts,0,0,0) < 0)
    return 1;

  if (!strcmp(command, "stop")) {
    cmd = 1;
    signame = "TERM";
    signum = START_STOP;
  } else if (!strcmp(command, "restart")) {
    cmd = 2;
    signame = "HUP";
    signum = START_RESTART;
  } else {
    startup_error("invalid command");
  }
  (void) cmd;

  if (!(pid = start_find_process("ej-compile", 0))) {
    op_error("ej-compile is not running");
  } else if (pid > 0) {
    // FIXME: also analyze the uid
    fprintf(stderr, "%s: ej-compile is running as pid %d\n", program_name, pid);
    fprintf(stderr, "%s: sending it the %s signal\n", program_name, signame);
    if (start_kill(pid, signum) < 0) op_error("failed: %s", os_ErrorMsg());
    return 0;
  }

  /* check, that compile is running */
  memset(&cp, 0, sizeof(cp));
  if (compile_request_packet_write(&cp, &pkt_len, &pkt_buf) < 0)
    op_error("compile packet error");
  serve_packet_name(0, 0, pkt_name);
  if (generic_write_file(pkt_buf, pkt_len, SAFE,
                         serve_state.global->compile_queue_dir,
                         pkt_name, "") < 0)
    op_error("compile packet write error");
  snprintf(pkt_path, sizeof(pkt_path), "%s/dir/%s",
           serve_state.global->compile_queue_dir, pkt_name);
  cur_wait = 100000;
  tot_wait = 0;
  while (1) {
    usleep(cur_wait);
    tot_wait += cur_wait;
    cur_wait += 100000;
    if (access(pkt_path, F_OK) < 0) break;
    if (tot_wait >= 5000000) {
      unlink(pkt_path);
      op_error("ej-compile seems to not running");
    }
  }

  /* FIXME: reimplement it normally */
  snprintf(cmdstr, sizeof(cmdstr), "killall -%s ej-compile", signame);
  if (system(cmdstr) < 0)
    op_error("killall failed");
#if 0
  memset(&cp, 0, sizeof(cp));
  cp.lang_id = cmd;
  if (compile_request_packet_write(&cp, &pkt_len, &pkt_buf) < 0)
    op_error("compile packet error");
  serve_packet_name(0, 0, pkt_name);
  if (generic_write_file(pkt_buf, pkt_len, SAFE,
                         serve_state.global->compile_queue_dir,
                         pkt_name, "") < 0)
    op_error("compile packet write error");
  snprintf(pkt_path, sizeof(pkt_path), "%s/dir/%s",
           serve_state.global->compile_queue_dir, pkt_name);
  cur_wait = 100000;
  while (1) {
    usleep(cur_wait);
    cur_wait += 100000;
    if (cur_wait > 1000000) cur_wait = 1000000;
    if (access(pkt_path, F_OK) < 0) break;
  }
#endif

  return 0;
}
