/* -*- c -*- */

/* Copyright (C) 2000-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/prepare.h"
#include "ejudge/runlog.h"
#include "ejudge/testinfo.h"
#include "ejudge/interrupt.h"
#include "ejudge/run_packet.h"
#include "ejudge/curtime.h"
#include "ejudge/full_archive.h"
#include "ejudge/digest_io.h"
#include "ejudge/serve_state.h"
#include "ejudge/startstop.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/nwrun_packet.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/fileutl.h"
#include "ejudge/errlog.h"
#include "ejudge/misctext.h"
#include "ejudge/run.h"
#include "ejudge/super_run_packet.h"
#include "ejudge/win32_compat.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/integral.h"
#include "ejudge/exec.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#ifndef __MINGW32__
#include <sys/vfs.h>
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJ_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

static int managed_mode_flag = 0;
static time_t last_activity_time;
static struct serve_state serve_state;
static int restart_flag = 0;
static int utf8_mode = 0;
static unsigned char **skip_archs;
static int skip_arch_count;

static int tests_a = 0;
static struct run_test_info *tests = 0;

static int
filter_testers(char *key)
{
  int i, total = 0;

  for (i = 1; i <= serve_state.max_tester; i++) {
    if (key && !serve_state.testers[i]->key) {
      serve_state.testers[i] = 0;
      continue;
    }
    if (key && strcmp(serve_state.testers[i]->key, key)) {
      serve_state.testers[i] = 0;
      continue;
    }
    if (serve_state.testers[i]) total++;
  }

  return 0;
}

static int
do_loop(void)
{
  int r;

  path_t report_path;
  path_t full_report_path;

  path_t pkt_name;
  unsigned char exe_pkt_name[64];
  unsigned char run_base[64];
  path_t full_report_dir;
  path_t full_status_dir;
  path_t full_full_dir;

  char   exe_name[64];
  int    tester_id;
  struct section_tester_data tn, *tst;
  int got_quit_packet = 0;

  struct run_reply_packet reply_pkt;
  void *reply_pkt_buf = 0;
  size_t reply_pkt_buf_size = 0;
  unsigned char errmsg[512];
  const struct section_global_data *global = serve_state.global;
  const unsigned char *arch = 0;

  char *srp_b = 0;
  size_t srp_z = 0;
  struct super_run_in_packet *srp = NULL;
  struct super_run_in_global_packet *srgp = NULL;
  struct super_run_in_problem_packet *srpp = NULL;

  memset(&tn, 0, sizeof(tn));

  //if (cr_serialize_init(&serve_state) < 0) return -1;
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

    r = scan_dir(global->run_queue_dir, pkt_name, sizeof(pkt_name), 0);
    if (r < 0) return -1;
    if (!r) {
      if (got_quit_packet && managed_mode_flag) {
        return 0;
      }
      if (managed_mode_flag && global->inactivity_timeout > 0 &&
          last_activity_time + global->inactivity_timeout < time(0)) {
        info("no activity for %d seconds, exiting",global->inactivity_timeout);
        return 0;
      }
      interrupt_enable();
      os_Sleep(global->sleep_time);
      interrupt_disable();
      continue;
    }

    last_activity_time = time(0);

    srp = super_run_in_packet_free(srp);
    xfree(srp_b); srp_b = NULL;
    srp_z = 0;

    r = generic_read_file(&srp_b, 0, &srp_z, SAFE | REMOVE, global->run_queue_dir, pkt_name, "");
    if (r == 0) continue;
    if (r < 0) return -1;

    if (!strcmp(pkt_name, "QUIT")) {
      if (managed_mode_flag) {
        got_quit_packet = 1;
        info("got force quit run packet");
      } else {
        restart_flag = 1;
      }
      xfree(srp_b); srp_b = NULL; srp_z = 0;
      continue;
    }

    fprintf(stderr, "packet: <<%.*s>>\n", (int) srp_z, srp_b);

    srp = super_run_in_packet_parse_cfg_str(pkt_name, srp_b, srp_z);
    //xfree(srp_b); srp_b = NULL; srp_z = 0;
    if (!srp) {
      err("failed to parse file %s", pkt_name);
      continue;
    }
    if (!(srgp = srp->global)) {
      err("packet %s has no global section", pkt_name);
      continue;
    }
    if (srgp->contest_id <= 0) {
      err("packet %s: undefined contest_id", pkt_name);
      continue;
    }

    if (managed_mode_flag && srgp->restart > 0) {
      got_quit_packet = 1;
      info("got force quit run packet");
      continue;
    }
    if (srgp->restart > 0) {
      restart_flag = 1;
      continue;
    }
    /*
    if (req_pkt->contest_id == -1) {
      r = generic_write_file(req_buf, req_buf_size, SAFE,
                             serve_state.global->run_queue_dir, pkt_name, "");
      if (r < 0) return -1;
      info("force quit packet is ignored in unmanaged mode");
      scan_dir_add_ignored(serve_state.global->run_queue_dir, pkt_name);
      continue;
    }
    */

    if (!(srpp = srp->problem)) {
      err("packet %s: no [problem] section", pkt_name);
      continue;
    }

    /* if we are asked to do full testing, but don't want */
    if ((global->skip_full_testing > 0 && !srgp->accepting_mode)
        || (global->skip_accept_testing > 0 && srgp->accepting_mode)) {
      r = generic_write_file(srp_b, srp_z, SAFE,
                             global->run_queue_dir, pkt_name, "");
      if (r < 0) return -1;
      info("skipping problem %s", srpp->short_name);
      scan_dir_add_ignored(global->run_queue_dir, pkt_name);
      continue;
    }

    /* if this problem is marked as "skip_testing" put the
     * packet back to the spool directory
     */
#if 0
    if (cur_prob->skip_testing > 0) {
      r = generic_write_file(srp_b, srp_z, SAFE, global->run_queue_dir, pkt_name, "");
      if (r < 0) return -1;
      info("skipping problem %s", cur_prob->short_name);
      scan_dir_add_ignored(global->run_queue_dir, pkt_name);
      continue;
    }
#endif

    snprintf(run_base, sizeof(run_base), "%06d", srgp->run_id);
    report_path[0] = 0;
    full_report_path[0] = 0;

    if (srpp->type_val == PROB_TYPE_TESTS) {
      //cr_serialize_lock(&serve_state);
      run_inverse_testing(&serve_state, srp, &reply_pkt,
                          pkt_name, global->run_exe_dir,
                          report_path, sizeof(report_path),
                          utf8_mode);
      //cr_serialize_unlock(&serve_state);
    } else {
      arch = srgp->arch;
      if (!arch) arch = "";
      if (srpp->type_val > 0 && arch && !*arch) {
        // any tester will work for output-only problems
        arch = 0;
      }

      /* regular problem */
      if (!(tester_id = find_tester(&serve_state, srpp->id, arch))){
        snprintf(errmsg, sizeof(errmsg),
                 "no tester found for %d, %s\n",
                 srpp->id, srgp->arch);
        goto report_check_failed_and_continue;
      }

      info("fount tester %d for pair %d,%s", tester_id, srpp->id,
           srgp->arch);
      tst = serve_state.testers[tester_id];

      if (tst->any) {
        info("tester %d is a default tester", tester_id);
        r = prepare_tester_refinement(&serve_state, &tn, tester_id,
                                      srpp->id);
        ASSERT(r >= 0);
        tst = &tn;
      }

      /* if this tester is marked as "skip_testing" put the
       * packet back to the spool directory
       */
      if (tst->skip_testing > 0) {
        r = generic_write_file(srp_b, srp_z, SAFE,
                               global->run_queue_dir, pkt_name, "");
        if (r < 0) return -1;
        info("skipping tester <%s,%s>", srpp->short_name, tst->arch);
        scan_dir_add_ignored(global->run_queue_dir, pkt_name);
        if (tst == &tn) {
          sarray_free(tst->start_env); tst->start_env = 0;
          sarray_free(tst->super); tst->super = 0;
        }
        continue;
      }

      snprintf(exe_pkt_name, sizeof(exe_pkt_name), "%s%s", pkt_name,
               srgp->exe_sfx);
      snprintf(exe_name, sizeof(exe_name), "%s%s", run_base, srgp->exe_sfx);

      r = generic_copy_file(REMOVE, global->run_exe_dir, exe_pkt_name, "",
                            0, global->run_work_dir, exe_name, "");
      if (r <= 0) {
        snprintf(errmsg, sizeof(errmsg),
                 "failed to copy executable file %s/%s\n",
                 global->run_exe_dir, exe_pkt_name);
        goto report_check_failed_and_continue;
      }

      /* start filling run_reply_packet */
      memset(&reply_pkt, 0, sizeof(reply_pkt));
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

      //if (cr_serialize_lock(&serve_state) < 0) return -1;
      run_tests(ejudge_config, &serve_state, tst, srp, &reply_pkt,
                NULL /* agent_client */,
                exe_name, run_base,
                report_path, full_report_path,
                NULL /* mirror_dir */, utf8_mode, NULL, NULL, NULL /* remaps */,
                0 /* user_input_mode*/,
                NULL /* inp_data */,
                0 /* inp_size*/,
                NULL /* src_path */);
      //if (cr_serialize_unlock(&serve_state) < 0) return -1;

      if (tst == &tn) {
        sarray_free(tst->start_env); tst->start_env = 0;
        sarray_free(tst->super); tst->super = 0;
      }
    }

    if (srgp->reply_report_dir && srgp->reply_report_dir[0]) {
      snprintf(full_report_dir, sizeof(full_report_dir),
               "%s", srgp->reply_report_dir);
    } else {
      snprintf(full_report_dir, sizeof(full_report_dir),
               "%s/%06d/report", global->run_dir, srgp->contest_id);
    }
    if (srgp->reply_spool_dir && srgp->reply_spool_dir[0]) {
      snprintf(full_status_dir, sizeof(full_status_dir),
               "%s", srgp->reply_spool_dir);
    } else {
      snprintf(full_status_dir, sizeof(full_status_dir),
               "%s/%06d/status", global->run_dir, srgp->contest_id);
    }
    if (srgp->reply_full_archive_dir && srgp->reply_full_archive_dir[0]) {
      snprintf(full_full_dir, sizeof(full_full_dir),
               "%s", srgp->reply_full_archive_dir);
    } else {
      snprintf(full_full_dir, sizeof(full_full_dir),
               "%s/%06d/output", global->run_dir, srgp->contest_id);
    }

    if (generic_copy_file(0, NULL, report_path, "",
                          0, full_report_dir, run_base, "") < 0)
      return -1;
#if defined CONF_HAS_LIBZIP
    if (full_report_path[0]
        && generic_copy_file(0, NULL, full_report_path, "",
                             0, full_full_dir,
                             run_base, ".zip") < 0)
      return -1;
#else
    if (full_report_path[0]
        && generic_copy_file(0, NULL, full_report_path, "",
                             0, full_full_dir,
                             run_base, "") < 0)
      return -1;
#endif

    //run_reply_packet_dump(&reply_pkt);

    if (run_reply_packet_write(&reply_pkt, &reply_pkt_buf_size,
                               &reply_pkt_buf) < 0) {
      /* FIXME: do something, if this is possible.
       * However, unability to generate a reply packet only
       * means that invalid data passed, which should be reported
       * immediately as internal error!
       */
      abort();
    }
    if (generic_write_file(reply_pkt_buf, reply_pkt_buf_size, SAFE,
                           full_status_dir, run_base, "") < 0) {
      xfree(reply_pkt_buf);
      reply_pkt_buf = 0;
      return -1;
    }
    xfree(reply_pkt_buf);
    reply_pkt_buf = 0;
    clear_directory(global->run_work_dir);
    last_activity_time = time(0);
    continue;

  report_check_failed_and_continue:;
    memset(&reply_pkt, 0, sizeof(reply_pkt));
    reply_pkt.judge_id = srgp->judge_id;
    reply_pkt.contest_id = srgp->contest_id;
    reply_pkt.run_id = srgp->run_id;
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
    reply_pkt.ts6 = reply_pkt.ts5;
    reply_pkt.ts6_us = reply_pkt.ts5_us;
    reply_pkt.ts7 = reply_pkt.ts5;
    reply_pkt.ts7_us = reply_pkt.ts5_us;
    reply_pkt.status = RUN_CHECK_FAILED;
    reply_pkt.failed_test = 0;
    reply_pkt.score = -1;

    if (run_reply_packet_write(&reply_pkt, &reply_pkt_buf_size,
                               &reply_pkt_buf) < 0) {
      // oops :(
      abort();
    }

    if (generic_write_file(errmsg, strlen(errmsg), 0,
                           full_report_dir, run_base, "") < 0
        || generic_write_file(reply_pkt_buf, reply_pkt_buf_size, SAFE,
                              full_status_dir, run_base, "") < 0) {
      err("error writing check failed packet");
    }

    clear_directory(global->run_work_dir);
  }

  srp = super_run_in_packet_free(srp);
  xfree(srp_b); srp_b = NULL;
  srp_z = 0;

  return 0;
}

static int
count_files(char const *dir, char const *sfx, const char *pat)
{
  path_t path;
  int    n = 1;
  int    s;

  while (1) {
    if (pat && pat[0]) {
      unsigned char file_base[64];
      snprintf(file_base, sizeof(file_base), pat, n);
      snprintf(path, PATH_MAX, "%s%s%s", dir, PATH_SEP, file_base);
    } else {
      snprintf(path, PATH_MAX, "%s%s%03d%s", dir, PATH_SEP, n, sfx);
    }
    s = os_IsFile(path);
    if (s < 0) break;
    if (s != OSPK_REG) {
      err("'%s' is not a regular file", path);
      return -1;
    }
    n++;
  }

  return n - 1;
}

static int
process_default_testers(void)
{
  int total = 0;
  int i, j, k;
  unsigned char *prob_flags = 0;
  struct section_tester_data *tp, *tq;
  struct section_problem_data *ts;

  struct section_tester_data tn; //temporary entry

  prob_flags = (unsigned char *) alloca(serve_state.max_prob + 1);

  /* scan all the 'any' testers */
  for (i = 1; i <= serve_state.max_tester; i++) {
    tp = serve_state.testers[i];
    if (!tp || !tp->any) continue;

    // check architecture uniqueness
    for (j = 1; j <= serve_state.max_tester; j++) {
      tq = serve_state.testers[j];
      if (i == j || !tq || !tq->any) continue;
      if (strcmp(serve_state.testers[j]->arch, tp->arch) != 0) continue;
      err("default testers %d and %d has the same architecture '%s'",
          i, j, tp->arch);
      return -1;
    }

    // mark the problems with explicit testers for this architecture
    memset(prob_flags, 0, serve_state.max_prob + 1);
    for (j = 1; j <= serve_state.max_tester; j++) {
      tq = serve_state.testers[j];
      if (!tq || tq->any) continue;
      if (strcmp(tp->arch, tq->arch) != 0) continue;

      // tq is specific tester with the same architecture
      ASSERT(tq->problem > 0 && tq->problem <= serve_state.max_prob);
      ASSERT(serve_state.probs[tq->problem]);
      prob_flags[tq->problem] = 1;
    }

    // scan all problems, which have no default tester
    for (k = 1; k <= serve_state.max_prob; k++) {
      ts = serve_state.probs[k];
      if (!ts || prob_flags[k]) continue;
      if (ts->disable_testing) continue;
      if (ts->manual_checking) continue;

      // so at this point: tp - pointer to the default tester,
      // k is the problem number
      // ts - pointer to the problem which should be handled by the
      // default tester
      if (prepare_tester_refinement(&serve_state, &tn, i, k) < 0) return -1;
      if (create_tester_dirs(&tn) < 0) return -1;

      /* check working dirs */
      if (make_writable(tn.check_dir) < 0) return -1;
      if (check_writable_dir(tn.check_dir) < 0) return -1;
      if (tn.prepare_cmd && tn.prepare_cmd[0] && check_executable(tn.prepare_cmd) < 0) return -1;
      if (tn.start_cmd && tn.start_cmd[0] && check_executable(tn.start_cmd) < 0) return -1;
      total++;

      sarray_free(tn.start_env);
      sarray_free(tn.super);
    }
  }

  return total;
}

static int
check_config(void)
{
  int     i, n1 = 0, n2, j, k;
  int     total = 0;

  struct section_problem_data *prb = 0;
  struct section_tester_data *tst = 0;
  unsigned char *var_test_dir;
  unsigned char *var_corr_dir;
  unsigned char *var_info_dir;
  unsigned char *var_tgz_dir;
  problem_xml_t px;
  const struct section_global_data *global = serve_state.global;

  if (skip_arch_count > 0) {
    for (i = 0; i < serve_state.max_abstr_tester; ++i) {
      tst = serve_state.abstr_testers[i];
      if (!tst) continue;
      tst->skip_testing = -1;
      for (j = 0; j < skip_arch_count; ++j) {
        if (!strcmp(skip_archs[j], tst->arch)) {
          break;
        }
      }
      if (j < skip_arch_count) {
        tst->skip_testing = 1;
      }
    }
  }

  /* check spooler dirs */
  if (check_writable_spool(global->run_queue_dir, SPOOL_OUT) < 0) return -1;
  if (check_writable_dir(global->run_exe_dir) < 0) return -1;

  /* check working dirs */
  if (make_writable(global->run_work_dir) < 0) return -1;
  if (check_writable_dir(global->run_work_dir) < 0) return -1;

  for (i = 1; i <= serve_state.max_prob; i++) {
    prb = serve_state.probs[i];
    if (!prb) continue;
    if (prb->disable_testing) continue;
    if (prb->manual_checking) continue;

    /* ignore output-only problems with XML and answer variants */
    px = 0;
    if (prb->variant_num > 0 && prb->xml.a) {
      px = prb->xml.a[0];
    } else {
      px = prb->xml.p;
    }
    if (px && px->answers) {
      prb->disable_testing = 1;
      continue;
    }

    // check if there exists a tester for this problem
    for (j = 1; j <= serve_state.max_tester; j++) {
      if (!serve_state.testers[j]) continue;
      if (serve_state.testers[j]->any) break;
      if (serve_state.testers[j]->problem == i) break;
    }
    if (j > serve_state.max_tester) {
      // no checker for the problem :-(
      info("no checker found for problem %d", i);
      continue;
    }

    if (prb->type > 0 && prb->type != PROB_TYPE_TESTS) {
      // output-only problems have no input file
      if (prb->variant_num <= 0) {
        if (prb->use_corr) {
          if (!prb->corr_dir) {
            err("directory with answers is not defined");
            return -1;
          }
          if (global->advanced_layout > 0) {
            var_corr_dir = (unsigned char*) alloca(sizeof(path_t));
            get_advanced_layout_path(var_corr_dir, sizeof(path_t), global,
                                     prb, DFLT_P_CORR_DIR, -1);
          } else {
            var_corr_dir = prb->corr_dir;
          }
          if (check_readable_dir(var_corr_dir) < 0) return -1;
          if ((n2 = count_files(var_corr_dir, prb->corr_sfx, prb->corr_pat)) < 0)
            return -1;
          n1 = n2;
          info("found %d answers for problem %s", n2, prb->short_name);
          if (n2 != 1) {
            err("output-only problem must define only one answer file");
            return -1;
          }
        }
        if (prb->use_info) {
          if (!prb->info_dir) {
            err("directory with test information is not defined");
            return -1;
          }
          if (global->advanced_layout > 0) {
            var_info_dir = (unsigned char*) alloca(sizeof(path_t));
            get_advanced_layout_path(var_info_dir, sizeof(path_t), global,
                                     prb, DFLT_P_INFO_DIR, -1);
          } else {
            var_info_dir = prb->info_dir;
          }
          if (check_readable_dir(var_info_dir) < 0) return -1;
          if ((n2 = count_files(var_info_dir,prb->info_sfx, prb->info_pat)) < 0)
            return -1;
          info("found %d info files for problem %s", n2, prb->short_name);
          if (n2 != 1) {
            err("output-only problem must define only one info file");
            return -1;
          }
        }
        if (prb->use_tgz) {
          if (!prb->tgz_dir) {
            err("directory with tgz information is not defined");
            return -1;
          }
          if (global->advanced_layout > 0) {
            var_tgz_dir = (unsigned char*) alloca(sizeof(path_t));
            get_advanced_layout_path(var_tgz_dir, sizeof(path_t), global,
                                     prb, DFLT_P_TGZ_DIR, -1);
          } else {
            var_tgz_dir = prb->tgz_dir;
          }
          if (check_readable_dir(var_tgz_dir) < 0) return -1;
          if ((n2 = count_files(var_tgz_dir, prb->tgz_sfx, 0)) < 0) return -1;
          info("found %d tgz files for problem %s", n2, prb->short_name);
          if (n2 != 1) {
            err("output-only problem must define only one tgz file");
            return -1;
          }
        }
      } else {
        var_test_dir = (unsigned char *) alloca(sizeof(path_t));
        var_corr_dir = (unsigned char *) alloca(sizeof(path_t));
        var_info_dir = (unsigned char *) alloca(sizeof(path_t));
        var_tgz_dir = (unsigned char *) alloca(sizeof(path_t));

        for (k = 1; k <= prb->variant_num; k++) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(var_test_dir, sizeof(path_t), global,
                                     prb, DFLT_P_TEST_DIR, k);
            get_advanced_layout_path(var_corr_dir, sizeof(path_t), global,
                                     prb, DFLT_P_CORR_DIR, k);
            get_advanced_layout_path(var_info_dir, sizeof(path_t), global,
                                     prb, DFLT_P_INFO_DIR, k);
            get_advanced_layout_path(var_tgz_dir, sizeof(path_t), global,
                                     prb, DFLT_P_TGZ_DIR, k);
          } else {
            snprintf(var_test_dir, sizeof(path_t), "%s-%d", prb->test_dir, k);
            snprintf(var_corr_dir, sizeof(path_t), "%s-%d", prb->corr_dir, k);
            snprintf(var_info_dir, sizeof(path_t), "%s-%d", prb->info_dir, k);
            snprintf(var_tgz_dir, sizeof(path_t), "%s-%d", prb->tgz_dir, k);
          }
          if (prb->use_corr) {
            if (!prb->corr_dir) {
              err("directory with answers is not defined");
              return -1;
            }
            if (check_readable_dir(var_corr_dir) < 0) return -1;
            if ((j = count_files(var_corr_dir, prb->corr_sfx, prb->corr_pat)) < 0)
              return -1;
            if (j != 1) {
              err("output-only problem must define only one answer file");
              return -1;
            }
          }
          if (prb->use_info) {
            if (!prb->info_dir) {
              err("directory with test infos is not defined");
              return -1;
            }
            if (check_readable_dir(var_info_dir) < 0) return -1;
            if ((j = count_files(var_info_dir,prb->info_sfx,prb->info_pat)) < 0)
              return -1;
            if (j != 1) {
              err("output-only problem must define only one info file");
              return -1;
            }
          }
          if (prb->use_tgz) {
            if (!prb->tgz_dir) {
              err("directory with tgz is not defined");
              return -1;
            }
            if (check_readable_dir(var_tgz_dir) < 0) return -1;
            if ((j = count_files(var_tgz_dir, prb->tgz_sfx, 0)) < 0) return -1;
            if (j != 1) {
              err("output-only problem must define only one info file");
              return -1;
            }
          }
        }
        n1 = n2 = 1;
      }
    } else if (!prb->type) {
      /* check existence of tests */
      if (prb->variant_num <= 0) {
        if (global->advanced_layout > 0) {
          var_test_dir = (unsigned char *) alloca(sizeof(path_t));
          get_advanced_layout_path(var_test_dir, sizeof(path_t), global,
                                   prb, DFLT_P_TEST_DIR, -1);
        } else {
          var_test_dir = prb->test_dir;
        }
        if (check_readable_dir(var_test_dir) < 0) return -1;
        if ((n1 = count_files(var_test_dir, prb->test_sfx, prb->test_pat)) < 0)
          return -1;
        if (!n1) {
          err("'%s' does not contain any tests", var_test_dir);
          return -1;
        }
        /*
        if (prb->type_val > 0 && n1 != 1) {
          err("`%s' must have only one test (as output-only problem)",
              prb->short_name);
          return -1;
        }
        */
        info("found %d tests for problem %s", n1, prb->short_name);
        if (n1 < prb->tests_to_accept) {
          err("%d tests required for problem acceptance!",prb->tests_to_accept);
          return -1;
        }
        if (prb->use_corr) {
          if (!prb->corr_dir) {
            err("directory with answers is not defined");
            return -1;
          }
          if (global->advanced_layout > 0) {
            var_corr_dir = (unsigned char *) alloca(sizeof(path_t));
            get_advanced_layout_path(var_corr_dir, sizeof(path_t), global,
                                     prb, DFLT_P_CORR_DIR, -1);
          } else {
            var_corr_dir = prb->corr_dir;
          }
          if (check_readable_dir(var_corr_dir) < 0) return -1;
          if ((n2 = count_files(var_corr_dir, prb->corr_sfx, prb->corr_pat)) < 0)
            return -1;
          info("found %d answers for problem %s", n2, prb->short_name);
          if (n1 != n2) {
            err("number of test does not match number of answers");
            return -1;
          }
        }
        if (prb->use_info) {
          if (!prb->info_dir) {
            err("directory with test information is not defined");
            return -1;
          }
          if (global->advanced_layout > 0) {
            var_info_dir = (unsigned char *) alloca(sizeof(path_t));
            get_advanced_layout_path(var_info_dir, sizeof(path_t), global,
                                     prb, DFLT_P_INFO_DIR, -1);
          } else {
            var_info_dir = prb->info_dir;
          }
          if (check_readable_dir(var_info_dir) < 0) return -1;
          if ((n2 = count_files(var_info_dir,prb->info_sfx,prb->info_pat)) < 0)
            return -1;
          info("found %d info files for problem %s", n2, prb->short_name);
          if (n1 != n2) {
            err("number of test does not match number of info files");
            return -1;
          }
        }
        if (prb->use_tgz) {
          if (!prb->tgz_dir) {
            err("directory with tgz information is not defined");
            return -1;
          }
          if (global->advanced_layout > 0) {
            var_tgz_dir = (unsigned char *) alloca(sizeof(path_t));
            get_advanced_layout_path(var_tgz_dir, sizeof(path_t), global,
                                     prb, DFLT_P_TGZ_DIR, -1);
          } else {
            var_tgz_dir = prb->tgz_dir;
          }
          if (check_readable_dir(var_tgz_dir) < 0) return -1;
          if ((n2 = count_files(var_tgz_dir, prb->tgz_sfx, 0)) < 0) return -1;
          info("found %d tgz files for problem %s", n2, prb->short_name);
          if (n1 != n2) {
            err("number of test does not match number of tgz files");
            return -1;
          }
        }
      } else {
        n1 = n2 = -1;
        var_test_dir = (unsigned char *) alloca(sizeof(path_t));
        var_corr_dir = (unsigned char *) alloca(sizeof(path_t));
        var_info_dir = (unsigned char *) alloca(sizeof(path_t));
        var_tgz_dir = (unsigned char *) alloca(sizeof(path_t));

        for (k = 1; k <= prb->variant_num; k++) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(var_test_dir, sizeof(path_t), global,
                                     prb, DFLT_P_TEST_DIR, k);
            get_advanced_layout_path(var_corr_dir, sizeof(path_t), global,
                                     prb, DFLT_P_CORR_DIR, k);
            get_advanced_layout_path(var_info_dir, sizeof(path_t), global,
                                     prb, DFLT_P_INFO_DIR, k);
            get_advanced_layout_path(var_tgz_dir, sizeof(path_t), global,
                                     prb, DFLT_P_TGZ_DIR, k);
          } else {
            snprintf(var_test_dir, sizeof(path_t), "%s-%d", prb->test_dir, k);
            snprintf(var_corr_dir, sizeof(path_t), "%s-%d", prb->corr_dir, k);
            snprintf(var_info_dir, sizeof(path_t), "%s-%d", prb->info_dir, k);
            snprintf(var_tgz_dir, sizeof(path_t), "%s-%d", prb->tgz_dir, k);
          }
          if (check_readable_dir(var_test_dir) < 0) return -1;
          if ((j = count_files(var_test_dir, prb->test_sfx, prb->test_pat)) < 0)
            return -1;
          if (!j) {
            err("'%s' does not contain any tests", var_test_dir);
            return -1;
          }
          /*
          if (prb->type_val > 0 && n1 != 1) {
            err("`%s', variant %d must have only one test (as output-only problem)",
                prb->short_name, j);
            return -1;
          }
          */
          if (n1 < 0) n1 = j;
          if (n1 != j) {
            err("number of tests %d for variant %d does not equal %d",
                j, k, n1);
            return -1;
          }
          info("found %d tests for problem %s, variant %d",
               n1, prb->short_name, k);
          if (n1 < prb->tests_to_accept) {
            err("%d tests required for problem acceptance!",
                prb->tests_to_accept);
            return -1;
          }
          if (prb->use_corr) {
            if (!prb->corr_dir) {
              err("directory with answers is not defined");
              return -1;
            }
            if (check_readable_dir(var_corr_dir) < 0) return -1;
            if ((j = count_files(var_corr_dir, prb->corr_sfx, prb->corr_pat)) < 0)
              return -1;
            info("found %d answers for problem %s, variant %d",
                 j, prb->short_name, k);
            if (n1 != j) {
              err("number of tests %d does not match number of answers %d",
                  n1, j);
              return -1;
            }
          }
          if (prb->use_info) {
            if (!prb->info_dir) {
              err("directory with test infos is not defined");
              return -1;
            }
            if (check_readable_dir(var_info_dir) < 0) return -1;
            if ((j = count_files(var_info_dir,prb->info_sfx,prb->info_pat)) < 0)
              return -1;
            info("found %d test infos for problem %s, variant %d",
                 j, prb->short_name, k);
            if (n1 != j) {
              err("number of tests %d does not match number of test infos %d",
                  n1, j);
              return -1;
            }
          }
          if (prb->use_tgz) {
            if (!prb->tgz_dir) {
              err("directory with tgz is not defined");
              return -1;
            }
            if (check_readable_dir(var_tgz_dir) < 0) return -1;
            if ((j = count_files(var_tgz_dir, prb->tgz_sfx, 0)) < 0) return -1;
            info("found %d tgzs for problem %s, variant %d",
                 j, prb->short_name, k);
            if (n1 != j) {
              err("number of tests %d does not match number of tgz %d",
                  n1, j);
              return -1;
            }
          }
          n2 = n1;
        }
      }
    }

    if (n1 >= tests_a - 1) {
      if (!tests_a) tests_a = 128;
      while (n1 >= tests_a - 1)
        tests_a *= 2;
      xfree(tests);
      XCALLOC(tests, tests_a);
    }

    ASSERT(prb->test_score >= 0);
    if (global->score_system == SCORE_MOSCOW) {
      if (prb->full_score <= 0) {
        err("problem %s: problem full_score is not set", prb->short_name);
        return -1;
      }
      prb->ntests = n1;
      if (!prb->scoring_checker) {
        if (!(prb->x_score_tests = prepare_parse_score_tests(prb->score_tests,
                                                             prb->full_score))){
          err("problem %s: parsing of score_tests failed", prb->short_name);
          return -1;
        }
        prb->x_score_tests[prb->full_score - 1] = n1 + 1;
        if (prb->full_score > 1
            && prb->x_score_tests[prb->full_score - 2] > n1 + 1) {
          err("problem %s: score_tests[%d] > score_tests[%d]",
              prb->short_name,
              prb->full_score - 2, prb->full_score - 1);
          return -1;
        }
      }
    } else if (prb->test_score >= 0 && global->score_system != SCORE_ACM) {
      int score_summ = 0;

      prb->ntests = n1;
      XCALLOC(prb->tscores, prb->ntests + 1);

      for (j = 1; j <= prb->ntests; j++)
        prb->tscores[j] = prb->test_score;

      // test_score_list overrides test_score
      if (prb->test_score_list && prb->test_score_list[0]) {
        char const *s = prb->test_score_list;
        int tn = 1;
        int was_indices = 0;
        int n;
        int index, score;

        while (1) {
          while (*s > 0 && *s <= ' ') s++;
          if (!*s) break;

          if (*s == '[') {
            if (sscanf(s, "[ %d ] %d%n", &index, &score, &n) != 2) {
              err("cannot parse test_score_list for problem %s",
                  prb->short_name);
              return -1;
            }
            if (index < 1 || index > prb->ntests) {
              err("problem %s: test_score_list: index out of range",
                  prb->short_name);
              return -1;
            }
            if (score < 0) {
              err("problem %s: test_score_list: invalid score",
                  prb->short_name);
              return -1;
            }
            tn = index;
            was_indices = 1;
            prb->tscores[tn++] = score;
            s += n;
          } else {
            if (sscanf(s, "%d%n", &score, &n) != 1) {
              err("cannot parse test_score_list for problem %s",
                  prb->short_name);
              return -1;
            }
            if (score < 0) {
              err("problem %s: test_score_list: invalid score",
                  prb->short_name);
              return -1;
            }
            if (tn > prb->ntests) {
              err("problem %s: too many scores specified", prb->short_name);
              return -1;
            }
            prb->tscores[tn++] = score;
            s += n;
          }
        }

        if (!was_indices && tn <= prb->ntests) {
          info("test_score_list for problem %s defines only %d tests",
               prb->short_name, tn - 1);
        }
      }

      for (j = 1; j <= prb->ntests; j++) score_summ += prb->tscores[j];
      if (score_summ > prb->full_score && (!prb->valuer_cmd || !prb->valuer_cmd[0])) {
        err("total score (%d) > full score (%d) for problem %s",
            score_summ, prb->full_score, prb->short_name);
        return -1;
      }
    }
  }

  for (i = 1; i <= serve_state.max_tester; i++) {
    if (!serve_state.testers[i]) continue;
    if (serve_state.testers[i]->any) continue;
    prb = serve_state.probs[serve_state.testers[i]->problem];
    total++;

    /* check working dirs */
    if (make_writable(serve_state.testers[i]->check_dir) < 0) return -1;
    if (check_writable_dir(serve_state.testers[i]->check_dir) < 0) return -1;
    if (serve_state.testers[i]->prepare_cmd && serve_state.testers[i]->prepare_cmd[0]
        && check_executable(serve_state.testers[i]->prepare_cmd) < 0) return -1;
    if (serve_state.testers[i]->start_cmd && serve_state.testers[i]->start_cmd[0]
        && check_executable(serve_state.testers[i]->start_cmd) < 0) return -1;
  }

  info("checking default testers...");
  if ((i = process_default_testers()) < 0) return -1;
  info("checking default testers done");
  total += i;

  if (!total) info("no testers");

#if CONF_HAS_LIBINTL - 0 == 1
  // bind message catalogs, if specified
  if (global->enable_l10n && global->l10n_dir && global->l10n_dir[0]) {
    bindtextdomain("ejudge", global->l10n_dir);
    textdomain("ejudge");
  }
#endif

  return 0;
}

int
main(int argc, char *argv[])
{
  int   i = 1;
  char *key = 0;
  int   p_flags = 0, code = 0;
  path_t cpp_opts = { 0 };

  start_set_self_args(argc, argv);

  if (argc == 1) goto print_usage;
  code = 1;

  if (argc > 0) {
    XCALLOC(skip_archs, argc);
  }

  while (i < argc) {
    if (!strcmp(argv[i], "-k")) {
      if (++i >= argc) goto print_usage;
      key = argv[i++];
    } else if (!strcmp(argv[i], "-S")) {
      managed_mode_flag = 1;
      i++;
    } else if (!strncmp(argv[i], "-D", 2)) {
      if (cpp_opts[0]) pathcat(cpp_opts, " ");
      pathcat(cpp_opts, argv[i++]);
    } else if (!strcmp(argv[i], "-s")) {
        if (++i >= argc) goto print_usage;
        skip_archs[skip_arch_count++] = argv[i++];
    } else break;
  }
  if (i >= argc) goto print_usage;

#if defined __unix__
  if (getuid() == 0) {
    err("sorry, will not run as the root");
    return 1;
  }
#endif

  if (!strcasecmp(EJUDGE_CHARSET, "UTF-8")) utf8_mode = 1;

  if (prepare(NULL, NULL, &serve_state, argv[i], p_flags, PREPARE_RUN,
              cpp_opts, managed_mode_flag, 0, 0) < 0)
    return 1;
  if (filter_testers(key) < 0) return 1;
  if (create_dirs(NULL, &serve_state, PREPARE_RUN) < 0) return 1;
  if (check_config() < 0) return 1;
  if (do_loop() < 0) return 1;
  if (restart_flag) {
    start_restart();
  }
  return 0;

 print_usage:
  printf("Usage: %s [ OPTS ] config-file\n", argv[0]);
  printf("  -k key  - specify tester key\n");
  printf("  -DDEF   - define a symbol for preprocessor\n");
  printf("  -s arch - specify architecture to skip testing\n");
  return code;
}
