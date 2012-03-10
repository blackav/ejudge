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
#include "errlog.h"
#include "prepare.h"
#include "cr_serialize.h"
#include "interrupt.h"
#include "super_run_packet.h"
#include "run_packet.h"

#include "reuse_xalloc.h"
#include "reuse_osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>

#define SUPER_RUN_DIRECTORY "super-run"

static const unsigned char *program_name = 0;
struct ejudge_cfg *ejudge_config = NULL;
static unsigned char super_run_path[PATH_MAX];
static unsigned char super_run_spool_path[PATH_MAX];
static unsigned char super_run_exe_path[PATH_MAX];
static unsigned char super_run_conf_path[PATH_MAX];
static int utf8_mode = 0;
static struct serve_state serve_state;
static int restart_flag = 0;
static unsigned char *contests_home_dir = NULL;

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

static void
handle_packet(serve_state_t state, const unsigned char *pkt_name)
{
  int r;
  char *srp_b = 0;
  size_t srp_z = 0;
  struct super_run_in_packet *srp = NULL;
  struct super_run_in_global_packet *srgp = NULL;
  struct super_run_in_problem_packet *srpp = NULL;
  unsigned char run_base[PATH_MAX];
  unsigned char report_path[PATH_MAX];
  unsigned char full_report_path[PATH_MAX];

  unsigned char full_report_dir[PATH_MAX];
  unsigned char full_status_dir[PATH_MAX];
  unsigned char full_full_dir[PATH_MAX];

  struct run_reply_packet reply_pkt;
  void *reply_pkt_buf = 0;
  size_t reply_pkt_buf_size = 0;

  memset(&reply_pkt, 0, sizeof(reply_pkt));

  r = generic_read_file(&srp_b, 0, &srp_z, SAFE | REMOVE, super_run_spool_path, pkt_name, "");
  if (r == 0) goto cleanup;
  if (r < 0) {
    err("generic_read_file failed for packet %s in %s", pkt_name, super_run_spool_path);
    goto cleanup;
  }

  fprintf(stderr, "packet: <<%.*s>>\n", (int) srp_z, srp_b);

  srp = super_run_in_packet_parse_cfg_str(pkt_name, srp_b, srp_z);
  if (!srp) {
    err("failed to parse packet %s", pkt_name);
    goto cleanup;
  }
  if (!(srgp = srp->global)) {
    err("packet %s has no global section", pkt_name);
    goto cleanup;
  }
  if (srgp->contest_id <= 0) {
    err("packet %s: undefined contest_id", pkt_name);
    goto cleanup;
  }
  if (srgp->restart > 0) {
    info("ignoring force quit packet %s", pkt_name);
    goto cleanup;
  }

  if (!(srpp = srp->problem)) {
    err("packet %s: no [problem] section", pkt_name);
    goto cleanup;
  }

  snprintf(run_base, sizeof(run_base), "%06d", srgp->run_id);
  report_path[0] = 0;
  full_report_path[0] = 0;

  // FIXME: do actions

  if (srgp->reply_report_dir && srgp->reply_report_dir[0]) {
    snprintf(full_report_dir, sizeof(full_report_dir), "%s", srgp->reply_report_dir);
  } else {
    snprintf(full_report_dir, sizeof(full_report_dir), "%s/%06d/var/run/%06d/report",
             contests_home_dir, srgp->contest_id, srgp->contest_id);
  }
  if (srgp->reply_spool_dir && srgp->reply_spool_dir[0]) {
    snprintf(full_status_dir, sizeof(full_status_dir), "%s", srgp->reply_spool_dir);
  } else {
    snprintf(full_status_dir, sizeof(full_status_dir), "%s/%06d/var/run/%06d/status",
             contests_home_dir, srgp->contest_id, srgp->contest_id);
  }
  if (srgp->reply_full_archive_dir && srgp->reply_full_archive_dir[0]) {
    snprintf(full_full_dir, sizeof(full_full_dir), "%s", srgp->reply_full_archive_dir);
  } else {
    snprintf(full_full_dir, sizeof(full_full_dir), "%s/%06d/var/run/%06d/output",
             contests_home_dir, srgp->contest_id, srgp->contest_id);
  }

  // copy full report from temporary location
  if (generic_copy_file(0, NULL, report_path, "", 0, full_report_dir, run_base, "") < 0) {
    // FIXME: handle
    goto cleanup;
  }

  if (full_report_path[0] && generic_copy_file(0, NULL, full_report_path, "", 0, full_full_dir, run_base, "") < 0) {
    // FIXME: handle
    goto cleanup;
  }

  if (run_reply_packet_write(&reply_pkt, &reply_pkt_buf_size, &reply_pkt_buf) < 0) {
    /* FIXME: do something, if this is possible.
     * However, unability to generate a reply packet only
     * means that invalid data passed, which should be reported
     * immediately as internal error!
     */
    goto cleanup;
  }

  if (generic_write_file(reply_pkt_buf, reply_pkt_buf_size, SAFE, full_status_dir, run_base, "") < 0) {
    // FIXME:
    goto cleanup;
  }

#if 0
    
    xfree(reply_pkt_buf);
    reply_pkt_buf = 0;
    clear_directory(global->run_work_dir);
    last_activity_time = time(0);
    continue;

#endif




cleanup:
  xfree(srp_b); srp_b = NULL; srp_z = 0;
  srp = super_run_in_packet_free(srp);
  xfree(reply_pkt_buf); reply_pkt_buf = NULL;
}

static int
do_loop(serve_state_t state)
{
  struct section_global_data *global = state->global;
  unsigned char pkt_name[PATH_MAX];
  int r;

  if (global->sleep_time <= 0) global->sleep_time = 1000;

  if (state->global->cr_serialization_key > 0) {
    if (cr_serialize_init(state) < 0) {
      err("cr_serialize_init() failed");
      return -1;
    }
  }
  interrupt_init();
  interrupt_disable();

  while (1) {
    interrupt_enable();
    /* time window for immediate signal delivery */
    interrupt_disable();

    // terminate, if signaled
    if (interrupt_get_status()) break;
    if (interrupt_restart_requested()) {
      restart_flag = 1;
    }
    if (restart_flag) break;

    r = scan_dir(super_run_spool_path, pkt_name, sizeof(pkt_name));
    if (r < 0) {
      err("scan_dir failed for %s, waiting...", super_run_spool_path);

      interrupt_enable();
      os_Sleep(global->sleep_time);
      interrupt_disable();
      continue;
    }

    if (!r) {
      interrupt_enable();
      os_Sleep(global->sleep_time);
      interrupt_disable();
      continue;
    }

    handle_packet(state, pkt_name);
  }

  return 0;
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

static void
collect_sections(serve_state_t state)
{
  struct generic_section_config *p;
  struct section_tester_data    *t;
  int abstr_tester_count = 0, i;

  for (p = state->config; p; p = p->next) {
    if (!strcmp(p->name, "") || !strcmp(p->name, "global")) {
      if (state->global != NULL) {
        fatal("duplicate global section");
      }
      state->global = (struct section_global_data*) p;
    } else if (!strcmp(p->name, "problem")) {
      fatal("section [problem] is not supported");
    } else if (!strcmp(p->name, "language")) {
      fatal("section [language] is not supported");
    } else if (!strcmp(p->name, "tester")) {
      t = (struct section_tester_data *) p;
      if (t->abstract <= 0 && t->any <= 0) {
        fatal("problem-specific [tester] section is not supported");
      }
      if (t->abstract > 0) {
        ++abstr_tester_count;
      }
    }
  }

  if (abstr_tester_count <= 0) {
    fatal("no abstract testers");
  }

  state->max_abstr_tester = abstr_tester_count;
  XCALLOC(state->abstr_testers, abstr_tester_count);

  for (p = state->config, i = 0; p; p = p->next) {
    if (!strcmp(p->name, "tester")) {
      t = (struct section_tester_data *) p;
      if (t->abstract > 0) {
        state->abstr_testers[i++] = t;
      }
    }
  }
}

int
main(int argc, char *argv[])
{
  char **argv_restart = 0;
  int argc_restart = 0;
  int cur_arg = 1;
  int pid;
  unsigned char ejudge_xml_path[PATH_MAX];
  serve_state_t state = &serve_state;

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

#if defined __unix__
  if (getuid() == 0) {
    fatal("will not run as the root");
  }
#endif

  if (!strcasecmp(EJUDGE_CHARSET, "UTF-8")) utf8_mode = 1;

  state->config = prepare_parse_config_file(super_run_conf_path, NULL);
  if (state->config == NULL) {
    fatal("config file parsing failed");
  }
  collect_sections(state);

  // run_work_dir, run_check_dir, cr_serialization_key

  if (do_loop(state) < 0) {
    return 1;
  }

  return 0;
}

