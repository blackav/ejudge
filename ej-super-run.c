/* -*- c -*- */

/* Copyright (C) 2012-2015 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/version.h"
#include "ejudge/startstop.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/fileutl.h"
#include "ejudge/errlog.h"
#include "ejudge/prepare.h"
#include "ejudge/interrupt.h"
#include "ejudge/super_run_packet.h"
#include "ejudge/run_packet.h"
#include "ejudge/run.h"
#include "ejudge/curtime.h"
#include "ejudge/ej_process.h"
#include "ejudge/xml_utils.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>

struct ignored_problem_info
{
  int contest_id;
  unsigned char *short_name;
};

#define SUPER_RUN_DIRECTORY "super-run"
static unsigned char *super_run_dir = NULL;

static const unsigned char *program_name = 0;
struct ejudge_cfg *ejudge_config = NULL;
static unsigned char super_run_path[PATH_MAX];
static unsigned char super_run_spool_path[PATH_MAX];
static unsigned char super_run_exe_path[PATH_MAX];
static unsigned char super_run_conf_path[PATH_MAX];
static unsigned char super_run_log_path[PATH_MAX];
static int utf8_mode = 0;
static struct serve_state serve_state;
static int restart_flag = 0;
static unsigned char *contests_home_dir = NULL;

static int ignored_archs_count = 0;
static int ignored_problems_count = 0;
static unsigned char **ignored_archs = NULL;
static struct ignored_problem_info *ignored_problems = NULL;
static int ignore_rejudge = 0;

static unsigned char **host_names = NULL;
static unsigned char *mirror_dir = NULL;

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

static int
is_packet_to_ignore(
        const unsigned char *pkt_name,
        int contest_id,
        int rejudge_flag,
        const unsigned char *short_name,
        const unsigned char *arch)
{
  int i;

  if (ignore_rejudge > 0 && rejudge_flag > 0) return 1;

  if (ignored_archs_count > 0) {
    for (i = 0; i < ignored_archs_count; ++i) {
      if (!strcmp(ignored_archs[i], arch))
        break;
    }
    if (i < ignored_archs_count) {
      info("packet %s: ignored because of arch == '%s'", pkt_name, arch);
      return 1;
    }
  }
  if (ignored_problems_count > 0) {
    for (i = 0; i < ignored_problems_count; ++i) {
      if (ignored_problems[i].contest_id > 0 && ignored_problems[i].short_name) {
        if (contest_id == ignored_problems[i].contest_id
            && !strcmp(short_name, ignored_problems[i].short_name))
          break;
      } else if (ignored_problems[i].contest_id > 0) {
        if (contest_id == ignored_problems[i].contest_id)
          break;
      } else if (ignored_problems[i].short_name) {
        if (!strcmp(short_name, ignored_problems[i].short_name))
          break;
      }
    }
    if (i < ignored_problems_count) {
      info("packet %s: ignored because of contest_id == %d, short_name == '%s'",
           pkt_name, contest_id, short_name);
      return 1;
    }
  }
  return 0;
}

static const struct section_tester_data *
find_abstract_tester(serve_state_t state, const unsigned char *arch)
{
  if (!state || !arch || state->max_abstr_tester <= 0) return NULL;
  for (int i = 0; i < state->max_abstr_tester; ++i) {
    if (!strcmp(arch, state->abstr_testers[i]->arch)) {
      return state->abstr_testers[i];
    }
  }
  return NULL;
}

static int
handle_packet(
        serve_state_t state,
        const unsigned char *pkt_name)
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

  unsigned char exe_pkt_name[PATH_MAX];
  unsigned char exe_name[PATH_MAX];
  unsigned char reply_packet_name[PATH_MAX];

  struct section_global_data *global = state->global;

  struct run_reply_packet reply_pkt;
  void *reply_pkt_buf = 0;
  size_t reply_pkt_buf_size = 0;
  int retval = 1;
  unsigned char *arch = NULL;
  unsigned char *short_name = NULL;
  const struct section_tester_data *tst = NULL;

  memset(&reply_pkt, 0, sizeof(reply_pkt));

  r = generic_read_file(&srp_b, 0, &srp_z, SAFE | REMOVE, super_run_spool_path, pkt_name, "");
  if (r == 0) {
    // ignore this packet
    retval = 0;
    goto cleanup;
  }
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

  arch = srgp->arch;
  if (!arch) arch = "";
  short_name = srpp->short_name;
  if (!short_name) short_name = "";

  if (is_packet_to_ignore(pkt_name, srgp->contest_id, srgp->rejudge_flag, short_name, arch)) {
    retval = 0;
    generic_write_file(srp_b, srp_z, SAFE, super_run_spool_path, pkt_name, "");
    goto cleanup;
  }

  snprintf(run_base, sizeof(run_base), "%06d", srgp->run_id);
  report_path[0] = 0;
  full_report_path[0] = 0;

  if (srpp->type_val == PROB_TYPE_TESTS) {
    //cr_serialize_lock(state);
    run_inverse_testing(state, srp, &reply_pkt,
                        pkt_name, super_run_exe_path,
                        report_path, sizeof(report_path),
                        utf8_mode);
    //cr_serialize_unlock(state);
  } else {
    if (!srpp->type_val) {
      tst = find_abstract_tester(state, arch);
      if (!tst) {
        err("no support for architecture %s here", arch);
        retval = 0;
        generic_write_file(srp_b, srp_z, SAFE, super_run_spool_path, pkt_name, "");
        goto cleanup;
      }
    }

    snprintf(exe_pkt_name, sizeof(exe_pkt_name), "%s%s", pkt_name, srgp->exe_sfx);
    snprintf(exe_name, sizeof(exe_name), "%s%s", run_base, srgp->exe_sfx);

    r = generic_copy_file(REMOVE, super_run_exe_path, exe_pkt_name, "",
                          0, global->run_work_dir, exe_name, "");
    if (r <= 0) {
      // FIXME: handle this differently?
      retval = 0;
      generic_write_file(srp_b, srp_z, SAFE, super_run_spool_path, pkt_name, "");
      goto cleanup;
    }

    reply_pkt.judge_id = srgp->judge_id;
    reply_pkt.contest_id = srgp->contest_id;
    reply_pkt.run_id = srgp->run_id;
    reply_pkt.notify_flag = srgp->notify_flag;
    reply_pkt.user_status = -1;
    reply_pkt.user_tests_passed = -1;
    reply_pkt.user_score = -1;
    reply_pkt.ts1 = srgp->ts1;
    reply_pkt.ts1_us = srgp->ts1_us;
    reply_pkt.ts2 = srgp->ts2;
    reply_pkt.ts2_us = srgp->ts2_us;
    reply_pkt.ts3 = srgp->ts3;
    reply_pkt.ts3_us = srgp->ts3_us;
    reply_pkt.ts4 = srgp->ts4;
    reply_pkt.ts4_us = srgp->ts4_us;
    get_current_time(&reply_pkt.ts5, &reply_pkt.ts5_us);
    if (srgp->run_uuid && srgp->run_uuid[0]) {
      ej_uuid_parse(srgp->run_uuid, &reply_pkt.uuid);
    }

    //if (cr_serialize_lock(state) < 0) return -1;
    run_tests(ejudge_config, state, tst, srp, &reply_pkt,
              srgp->accepting_mode,
              srpp->accept_partial, srgp->variant,
              exe_name, run_base,
              report_path, full_report_path,
              srgp->user_spelling,
              srpp->spelling, mirror_dir, utf8_mode);
    //if (cr_serialize_unlock(state) < 0) return -1;
  }

  if (srgp->reply_report_dir && srgp->reply_report_dir[0]) {
    if (os_IsAbsolutePath(srgp->reply_report_dir)) {
      snprintf(full_report_dir, sizeof(full_report_dir), "%s", srgp->reply_report_dir);
    } else {
      snprintf(full_report_dir, sizeof(full_report_dir), "%s/%s/%s",
               EJUDGE_CONTESTS_HOME_DIR, super_run_dir, srgp->reply_report_dir);
    }
  } else {
    snprintf(full_report_dir, sizeof(full_report_dir), "%s/%06d/var/run/%06d/report",
             contests_home_dir, srgp->contest_id, srgp->contest_id);
  }
  if (srgp->reply_spool_dir && srgp->reply_spool_dir[0]) {
    if (os_IsAbsolutePath(srgp->reply_spool_dir)) {
      snprintf(full_status_dir, sizeof(full_status_dir), "%s", srgp->reply_spool_dir);
    } else {
      snprintf(full_status_dir, sizeof(full_status_dir), "%s/%s/%s",
               EJUDGE_CONTESTS_HOME_DIR, super_run_dir, srgp->reply_spool_dir);
    }
  } else {
    snprintf(full_status_dir, sizeof(full_status_dir), "%s/%06d/var/run/%06d/status",
             contests_home_dir, srgp->contest_id, srgp->contest_id);
  }
  if (srgp->reply_full_archive_dir && srgp->reply_full_archive_dir[0]) {
    if (os_IsAbsolutePath(srgp->reply_full_archive_dir)) {
      snprintf(full_full_dir, sizeof(full_full_dir), "%s", srgp->reply_full_archive_dir);
    } else {
      snprintf(full_status_dir, sizeof(full_status_dir), "%s/%s/%s",
               EJUDGE_CONTESTS_HOME_DIR, super_run_dir,
               srgp->reply_full_archive_dir);
    }
  } else {
    snprintf(full_full_dir, sizeof(full_full_dir), "%s/%06d/var/run/%06d/output",
             contests_home_dir, srgp->contest_id, srgp->contest_id);
  }

  if (full_report_dir[0]) {
    os_MakeDirPath(full_report_dir, 0777);
  }
  if (full_full_dir[0]) {
    os_MakeDirPath(full_full_dir, 0777);
  }
  if (full_status_dir[0]) {
    os_MakeDirPath(full_status_dir, 0777);
    make_all_dir(full_status_dir, 0777);
  }

  if (srgp->reply_packet_name && srgp->reply_packet_name[0]) {
    snprintf(reply_packet_name, sizeof(reply_packet_name), "%s", srgp->reply_packet_name);
  } else {
    snprintf(reply_packet_name, sizeof(reply_packet_name), "%s", run_base);
  }

  // copy full report from temporary location
  if (generic_copy_file(0, NULL, report_path, "", 0, full_report_dir, reply_packet_name, "") < 0) {
    goto cleanup;
  }

#if defined CONF_HAS_LIBZIP
  if (full_report_path[0] && generic_copy_file(0, NULL, full_report_path, "", 0, full_full_dir, reply_packet_name, ".zip") < 0) {
    goto cleanup;
  }
#else
  if (full_report_path[0] && generic_copy_file(0, NULL, full_report_path, "", 0, full_full_dir, reply_packet_name, "") < 0) {
    goto cleanup;
  }
#endif

  //run_reply_packet_dump(&reply_pkt);

  if (run_reply_packet_write(&reply_pkt, &reply_pkt_buf_size, &reply_pkt_buf) < 0) {
    goto cleanup;
  }

  if (generic_write_file(reply_pkt_buf, reply_pkt_buf_size, SAFE, full_status_dir, reply_packet_name, "") < 0) {
    goto cleanup;
  }

cleanup:
  xfree(srp_b); srp_b = NULL; srp_z = 0;
  srp = super_run_in_packet_free(srp);
  xfree(reply_pkt_buf); reply_pkt_buf = NULL;
  clear_directory(global->run_work_dir);
  return retval;
}

int
do_loop(
        serve_state_t state)
{
  struct section_global_data *global = state->global;
  unsigned char pkt_name[PATH_MAX];
  int r;

  if (global->sleep_time <= 0) global->sleep_time = 1000;

  /*
  if (state->global->cr_serialization_key > 0) {
    if (cr_serialize_init(state) < 0) {
      err("cr_serialize_init() failed");
      return -1;
    }
  }
  */
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

    pkt_name[0] = 0;
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

    r = handle_packet(state, pkt_name);
    if (!r) {
      scan_dir_add_ignored(super_run_spool_path, pkt_name);
    }
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
         "    --help       write this message and exit\n"
         "    --version    report version and exit\n"
         "    -u USER      specify the user to run under\n"
         "    -g GROUP     specify the group to run under\n"
         "    -C DIR       specify the working directory\n"
         "    -D           daemon mode\n"
         "    -s ARCH      ignore specified architecture\n"
         "    -i CNTS:PROB ignore specified problem\n"
         "    -r           ignore rejudging\n"
         "    -p DIR       specify alternate name for super-run directory\n"
         "    -a           write log file to an alternate location\n"
         "    -m DIR       specify a directory for file mirroring",
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
  snprintf(super_run_spool_path, sizeof(super_run_spool_path), "%s/var/%s",
           super_run_path, "queue");
  snprintf(super_run_exe_path, sizeof(super_run_exe_path), "%s/var/%s",
           super_run_path, "exe");
  os_MakeDirPath(super_run_spool_path, 0777);
  os_MakeDirPath(super_run_exe_path, 0777);
  make_all_dir(super_run_spool_path, 0777);
}

static int
create_working_directories(serve_state_t state)
{
  struct section_global_data *global = state->global;
  const unsigned char *hostname = os_NodeName();
  int pid = getpid();
  unsigned char work_dir[PATH_MAX];
  unsigned char check_dir[PATH_MAX];
  int retval = 0;

#if defined EJUDGE_LOCAL_DIR
  if (!global->run_work_dir || !global->run_work_dir[0]) {
    snprintf(global->run_work_dir, sizeof(global->run_work_dir),
             "%s/%s/work", EJUDGE_LOCAL_DIR, super_run_dir);
  }
  if (!global->run_check_dir || !global->run_check_dir[0]) {
    snprintf(global->run_check_dir, sizeof(global->run_check_dir),
             "%s/%s/check", EJUDGE_LOCAL_DIR, super_run_dir);
  }
#endif
  if (!global->run_work_dir || !global->run_work_dir[0]) {
    snprintf(global->run_work_dir, sizeof(global->run_work_dir), 
             "%s/var/work", super_run_path);
  }
  if (!global->run_check_dir || !global->run_check_dir[0]) {
    snprintf(global->run_check_dir, sizeof(global->run_check_dir),
             "%s/var/check", super_run_path);
  }

  snprintf(work_dir, sizeof(work_dir), "%s/%s_%d", global->run_work_dir, hostname, pid);
  snprintf(check_dir, sizeof(check_dir), "%s/%s_%d", global->run_check_dir, hostname, pid);
  snprintf(global->run_work_dir, sizeof(global->run_work_dir), "%s", work_dir);
  snprintf(global->run_check_dir, sizeof(global->run_check_dir), "%s", check_dir);

  if (os_MakeDirPath(global->run_work_dir, 0755) < 0) {
    err("failed to create working directory '%s'", global->run_work_dir);
    retval = -1;
  }
  if (os_MakeDirPath(global->run_check_dir, 0755) < 0) {
    err("failed to create check directory '%s'", global->run_check_dir);
    retval = -1;
  }

  return retval;
}

static void
remove_working_directory(serve_state_t state)
{
  struct section_global_data *global = state->global;

  if (!global) return;
  if (global->run_work_dir && global->run_work_dir[0]) {
    remove_directory_recursively(global->run_work_dir, 0);
  }
  if (global->run_check_dir && global->run_check_dir[0]) {
    remove_directory_recursively(global->run_check_dir, 0);
  }
}

static void
collect_sections(serve_state_t state)
{
  struct generic_section_config *p;
  struct section_global_data *global = NULL;
  struct section_tester_data    *t;
  int abstr_tester_count = 0, i;
  unsigned char start_path[PATH_MAX];

  for (p = state->config; p; p = p->next) {
    if (!strcmp(p->name, "") || !strcmp(p->name, "global")) {
      if (state->global != NULL) {
        fatal("duplicate global section");
      }
      global = state->global = (struct section_global_data*) p;
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

  if (!global) {
    fatal("no global section");
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

#if defined EJUDGE_SCRIPT_DIR
  if (!global->script_dir[0]) {
    snprintf(global->script_dir, sizeof(global->script_dir), "%s", EJUDGE_SCRIPT_DIR);
  }
  if (!global->ejudge_checkers_dir[0]) {
    snprintf(global->ejudge_checkers_dir, sizeof(global->ejudge_checkers_dir),
             "%s/checkers", EJUDGE_SCRIPT_DIR);
  }
#endif

  if (!global->ejudge_checkers_dir[0]) {
    fatal("ejudge_checkers_dir parameter is undefined");
  }

  for (i = 0; i < state->max_abstr_tester; ++i) {
    if (!(t = state->abstr_testers[i])) continue;

    if (t->memory_limit_type[0] >= ' ') {
      t->memory_limit_type_val = prepare_parse_memory_limit_type(t->memory_limit_type);
      if (t->memory_limit_type_val < 0) {
        fatal("invalid memory_limit_type `%s'", t->memory_limit_type);
      }
    }

    if (t->secure_exec_type[0] >= ' ') {
      t->secure_exec_type_val = prepare_parse_secure_exec_type(t->secure_exec_type);
      if (t->secure_exec_type_val < 0) {
        fatal("invalid secure_exec_type `%s'", t->secure_exec_type);
      }
    }

    if (t->start_cmd && t->start_cmd[0]) {
      if (!os_IsAbsolutePath(t->start_cmd)) {
        snprintf(start_path, sizeof(start_path), "%s", t->start_cmd);
        if (ejudge_config && ejudge_config->compile_home_dir) {
          pathmake2(start_path, ejudge_config->compile_home_dir,
                    "/", "scripts", "/", start_path, NULL);
        } else if (ejudge_config && ejudge_config->contests_home_dir) {
          pathmake2(start_path, ejudge_config->contests_home_dir,
                    "/", "compile", "/", "scripts", "/", start_path, NULL);
        }
#if defined EJUDGE_CONTESTS_HOME_DIR
        else {
          pathmake2(start_path, EJUDGE_CONTESTS_HOME_DIR,
                    "/", "compile", "/", "scripts", "/", start_path, NULL);
        }
#endif
        if (access(start_path, X_OK) >= 0) {
          snprintf(t->start_cmd, sizeof(t->start_cmd), "%s", start_path);
        } else {
          pathmake2(t->start_cmd, global->script_dir, "/", "lang", "/", t->start_cmd, NULL);
        }
      }
    }
  }
}

static int
parse_ignored_problem(
        const unsigned char *arg,
        struct ignored_problem_info *info)
{
  // [ CONTEST-ID : PROBLEM-SHORT-NAME ]
  const unsigned char *c = arg;
  int x, n;
  unsigned char *s = NULL;

  info->contest_id = 0;

  if (!arg) return -1;
  while (isspace(*c)) ++c;
  if (!*c) return -1;
  if (isdigit(*c)) {
    if (sscanf(c, "%d%n", &x, &n) != 1) return -1;
    if (x < 0 || x > 1000000) return -1;
    info->contest_id = x;
    c += n;
    while (isspace(*c)) ++c;
  }
  if (*c != ':') return -1;
  ++c;
  while (isspace(*c)) ++c;
  if (!*c) return 0;
  s = (unsigned char*) xmalloc((strlen(arg) + 1) * sizeof(*s));
  info->short_name = s;
  while (*c && !isspace(*c)) *s++ = *c++;
  *s = 0;
  while (isspace(*c)) ++c;
  if (*c) return -1;
  return 0;
}

static void
create_configs(
        const unsigned char *super_run_path,
        const unsigned char *super_run_conf_path)
{
  unsigned char dir_path[PATH_MAX];
  FILE *f = NULL;

  if (os_MakeDirPath(super_run_path, 0775) < 0)
    fatal("cannot create directory '%s'", super_run_path);
  snprintf(dir_path, sizeof(dir_path), "%s/var", super_run_path);
  if (os_MakeDir(dir_path, 0775) < 0)
    fatal("cannot create directory '%s'", dir_path);
  snprintf(dir_path, sizeof(dir_path), "%s/conf", super_run_path);
  if (os_MakeDir(dir_path, 0775) < 0)
    fatal("cannot create directory '%s'", dir_path);

  if (!(f = fopen(super_run_conf_path, "w")))
    fatal("cannot open file '%s' for writing", super_run_conf_path);
  fprintf(f, "sleep_time = 1000\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Generic\n"
          "arch = \"\"\n"
          "abstract\n"
          "no_core_dump\n"
          "enable_memory_limit_error\n"
          "kill_signal = KILL\n"
          "memory_limit_type = \"default\"\n"
          "secure_exec_type = \"static\"\n"
          "clear_env\n"
          "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
          "start_env = \"LANG=C\"\n"
          "start_env = \"LC_CTYPE=C\"\n"
          "start_env = \"HOME\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Linux-shared\n"
          "arch = \"linux-shared\"\n"
          "abstract\n"
          "no_core_dump\n"
          "enable_memory_limit_error\n"
          "kill_signal = KILL\n"
          "memory_limit_type = \"default\"\n"
          "secure_exec_type = \"dll\"\n"
          "clear_env\n"
          "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
          "start_env = \"LANG=C\"\n"
          "start_env = \"LC_CTYPE=C\"\n"
          "start_env = \"HOME\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Linux-shared-32\n"
          "arch = \"linux-shared-32\"\n"
          "abstract\n"
          "no_core_dump\n"
          "enable_memory_limit_error\n"
          "kill_signal = KILL\n"
          "memory_limit_type = \"default\"\n"
          "secure_exec_type = \"dll32\"\n"
          "clear_env\n"
          "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
          "start_env = \"LANG=C\"\n"
          "start_env = \"LC_CTYPE=C\"\n"
          "start_env = \"HOME\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Linux-java\n"
          "arch = \"java\"\n"
          "abstract\n"
          "no_core_dump\n"
          "kill_signal = TERM\n"
          "memory_limit_type = \"java\"\n"
          "secure_exec_type = \"java\"\n"
          "start_cmd = \"runjava\"\n"
          "start_env = \"LANG=C\"\n"
          "start_env = \"LC_CTYPE=C\"\n"
          "start_env = \"EJUDGE_PREFIX_DIR\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Linux-msil\n"
          "arch = \"msil\"\n"
          "abstract\n"
          "no_core_dump\n"
          "kill_signal = TERM\n"
          "memory_limit_type = \"mono\"\n"
          "secure_exec_type = \"mono\"\n"
          "start_cmd = \"runmono\"\n"
          "start_env = \"LANG=C\"\n"
          "start_env = \"LC_CTYPE=C\"\n"
          "start_env = \"EJUDGE_PREFIX_DIR\"\n\n");

  fprintf(f, "[tester]\n"
          "name = DOSTester\n"
          "arch = dos\n"
          "abstract\n"
          "no_core_dump\n"
          "no_redirect\n"
          "ignore_stderr\n"
          "time_limit_adjustment\n"
          "is_dos\n"
          "kill_signal = KILL\n"
          "memory_limit_type = \"dos\"\n"
          "errorcode_file = \"retcode.txt\"\n"
          "start_cmd = \"dosrun3\"\n\n");

  fprintf(f, "[tester]\n"
          "name = Win32\n"
          "arch = win32\n"
          "abstract\n"
          "nwrun_spool_dir = \"win32_nwrun\"\n\n");

  fprintf(f,
          "[tester]\n"
          "name = Valgrind\n"
          "arch = \"valgrind\"\n"
          "abstract\n"
          "no_core_dump\n"
          "kill_signal = TERM\n"
          "memory_limit_type = \"valgrind\"\n"
          "secure_exec_type = \"valgrind\"\n"
          "clear_env\n"
          "start_cmd = \"runvg\"\n"
          "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
          "start_env = \"LANG=C\"\n"
          "start_env = \"LC_CTYPE=C\"\n"
          "start_env = \"HOME\"\n\n");

  fclose(f); f = NULL;
}

const unsigned char * const
upgrade_times[] =
{
  "2012/05/01 00:00:00",
  "2012/05/26 00:00:00",
  "2012/06/21 00:00:00",
  "2012/11/05 00:00:00",

  NULL
};

static void
remove_if_upgrade_needed(const unsigned char *path)
{
  struct stat stb;

  if (!path || !*path) return;
  if (stat(path, &stb) < 0) return;
  if (!S_ISREG(stb.st_mode)) return;
  for (int i = 0; upgrade_times[i]; ++i) {
    time_t t = 0;
    if (xml_parse_date(NULL, 0, 0, 0, upgrade_times[i], &t) < 0) continue;
    if (t <= 0) continue;
    if (stb.st_mtime < t) {
      struct tm *tt = localtime(&t);
      unsigned char bak_path[PATH_MAX];
      snprintf(bak_path, sizeof(bak_path), "%s.%04d%02d%02d", path,
               tt->tm_year + 1900, tt->tm_mon + 1, tt->tm_mday);
      rename(path, bak_path);
      return;
    }
  }
}

int
main(int argc, char *argv[])
{
  char **argv_restart = 0;
  int argc_restart = 0;
  int cur_arg = 1;
  int pid_count;
  int *pids = NULL;
  unsigned char ejudge_xml_path[PATH_MAX];
  serve_state_t state = &serve_state;
  int retval = 0;
  int daemon_mode = 0, restart_mode = 0, alternate_log_mode = 0;
  const unsigned char *user = NULL, *group = NULL, *workdir = NULL;

  signal(SIGPIPE, SIG_IGN);

  program_name = os_GetBasename(argv[0]);
  start_set_self_args(argc, argv);
  XCALLOC(argv_restart, argc + 2);
  argv_restart[argc_restart++] = argv[0];
  ejudge_xml_path[0] = 0;

  XCALLOC(ignored_archs, argc);
  XCALLOC(ignored_problems, argc);

  while (cur_arg < argc) {
    if (!strcmp(argv[cur_arg], "--help")) {
      write_help();
    } else if (!strcmp(argv[cur_arg], "--version")) {
      write_version();
    } else if (!strcmp(argv[cur_arg], "-u")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -u");
      user = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-g")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -g");
      group = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-C")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -C");
      workdir = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-D")) {
      daemon_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-R")) {
      restart_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-s")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -s");
      ignored_archs[ignored_archs_count++] = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-a")) {
      argv_restart[argc_restart++] = argv[cur_arg];
      alternate_log_mode = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-r")) {
      argv_restart[argc_restart++] = argv[cur_arg];
      ignore_rejudge = 1;
      ++cur_arg;
    } else if (!strcmp(argv[cur_arg], "-p")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -p");
      xfree(super_run_dir); super_run_dir = NULL;
      super_run_dir = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-m")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -m");
      xfree(mirror_dir); mirror_dir = NULL;
      mirror_dir = xstrdup(argv[cur_arg + 1]);
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else if (!strcmp(argv[cur_arg], "-i")) {
      if (cur_arg + 1 >= argc) fatal("argument expected for -i");
      if (parse_ignored_problem(argv[cur_arg + 1], &ignored_problems[ignored_problems_count++]) < 0) {
        fatal("invalid argument for -i: '%s'", argv[cur_arg + 1]);
      }
      argv_restart[argc_restart++] = argv[cur_arg];
      argv_restart[argc_restart++] = argv[cur_arg + 1];
      cur_arg += 2;
    } else {
      fatal("invalid command line parameter");
    }
  }

  argv_restart[argc_restart++] = "-R";

  argv_restart[argc_restart] = NULL;
  start_set_args(argv_restart);

  if (!(host_names = ejudge_get_host_names())) {
    fatal("cannot obtain the list of host names");
  }
  if (!host_names[0]) {
    fatal("cannot determine the name of the host");
  }
  if (!super_run_dir) {
    super_run_dir = xstrdup(SUPER_RUN_DIRECTORY);
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

  int parallelism = ejudge_cfg_get_host_option_int(ejudge_config, host_names, "parallelism", 1, 0);
  if (parallelism <= 0 || parallelism > 128) {
    fatal("invalid value of parallelism host option");
  }

  if ((pid_count = start_find_all_processes("ej-super-run", &pids)) < 0) {
    fatal("cannot get the list of processes");
  }
  if (pid_count >= parallelism) {
    fprintf(stderr, "%d", pids[0]);
    for (int i = 1; i < pid_count; ++i) {
      fprintf(stderr, " %d", pids[i]);
    }
    fprintf(stderr, "\n");
    fatal("%d processes are already running", pid_count);
  }

  if (!contests_home_dir && ejudge_config->contests_home_dir) {
    contests_home_dir = ejudge_config->contests_home_dir;
  }

  if (!os_IsAbsolutePath(contests_home_dir)) {
    fatal("contests home directory is not an absolute path");
  }
  if (os_IsFile(contests_home_dir) != OSPK_DIR) {
    fatal("contests home directory is not a directory");
  }
  snprintf(super_run_path, sizeof(super_run_path), "%s/%s", contests_home_dir, super_run_dir);
  snprintf(super_run_conf_path, sizeof(super_run_conf_path), "%s/conf/super-run.cfg", super_run_path);

  super_run_log_path[0] = 0;
  if (alternate_log_mode) {
#if defined EJUDGE_LOCAL_DIR
    snprintf(super_run_log_path, sizeof(super_run_log_path),
      "%s/%s/ej-super-run.log", EJUDGE_LOCAL_DIR, super_run_dir);
#endif
    if (!super_run_log_path[0]) {
      snprintf(super_run_log_path, sizeof(super_run_log_path), 
               "%s/var/ej-super-run.log", super_run_path);
    }
  } else {
    snprintf(super_run_log_path, sizeof(super_run_log_path), "%s/var/ej-super-run.log", contests_home_dir);
  }

  remove_if_upgrade_needed(super_run_conf_path);

  if (os_IsFile(super_run_conf_path) < 0) {
    create_configs(super_run_path, super_run_conf_path);
    if (os_IsFile(super_run_path) != OSPK_DIR) {
      fatal("path '%s' must be a directory", super_run_path);
    }
  }

  if (!workdir || *workdir) {
    workdir = super_run_path;
  }
  if (start_prepare(user, group, workdir) < 0) return 1;

  create_directories();

  if (!strcasecmp(EJUDGE_CHARSET, "UTF-8")) utf8_mode = 1;

  state->config = prepare_parse_config_file(super_run_conf_path, NULL);
  if (state->config == NULL) {
    fatal("config file parsing failed");
  }
  collect_sections(state);

  if (daemon_mode) {
    if (start_daemon(super_run_log_path) < 0) {
      retval = 1;
      goto cleanup;
    }
  } else if (restart_mode) {
    if (start_open_log(super_run_log_path) < 0) {
      retval = 1;
      goto cleanup;
    }
  }

  if (create_working_directories(state) < 0) {
    retval = 1;
    goto cleanup;
  }

  fprintf(stderr, "%s %s, compiled %s\n", program_name, compile_version, compile_date);

  if (do_loop(state) < 0) {
    retval = 1;
  }

  if (interrupt_restart_requested()) start_restart();

cleanup:
  remove_working_directory(state);
  return retval;
}

