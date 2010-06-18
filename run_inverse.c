/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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

#include "run.h"
#include "serve_state.h"
#include "fileutl.h"
#include "pathutl.h"
#include "mime_type.h"
#include "prepare.h"
#include "run_packet.h"
#include "prepare_dflt.h"
#include "misctext.h"
#include "curtime.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>

#include <ctype.h>

#define GOOD_DIR_NAME "good"
#define FAIL_DIR_NAME "fail"

/*
static void
generate_xml_report(
        const unsigned char *report_path,
        const struct run_request_packet *req_pkt)
{
}
*/

static void
make_patterns(
        const struct section_problem_data *prob,
        unsigned char *test_pat,
        size_t test_pat_size,
        unsigned char *corr_pat,
        size_t corr_pat_size)
{
  if (prob->test_pat[0]) {
    snprintf(test_pat, test_pat_size, "%s", prob->test_pat);
  } else if (prob->test_sfx[0]) {
    snprintf(test_pat, test_pat_size, "%%03d%s", prob->test_sfx);
  } else {
    snprintf(test_pat, test_pat_size, "%%03d.dat");
  }

  if (prob->use_corr > 0) {
    if (prob->corr_pat[0]) {
      snprintf(corr_pat, corr_pat_size, "%s", prob->corr_pat);
    } else if (prob->corr_sfx[0]) {
      snprintf(corr_pat, corr_pat_size, "%%03d%s", prob->corr_sfx);
    } else {
      snprintf(corr_pat, corr_pat_size, "%%03d.ans");
    }
  }
}

static int
invoke_tar(const unsigned char *arch_path, const unsigned char *work_dir)
{
  return 0;
}

static int
count_tests(
        FILE *log_f,
        const struct section_problem_data *prob,
        const unsigned char *tests_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat)
{
  path_t test_path;
  path_t corr_path;
  path_t test_name;
  path_t corr_name;
  int serial = 0;
  int r1, r2;

  while (1) {
    ++serial;
    snprintf(test_name, sizeof(test_name), test_pat, serial);
    snprintf(corr_name, sizeof(corr_name), corr_pat, serial);
    snprintf(test_path, sizeof(test_path), "%s/%s", tests_dir, test_name);
    snprintf(corr_path, sizeof(corr_path), "%s/%s", tests_dir, corr_name);

    r1 = os_IsFile(test_path);
    r2 = os_IsFile(corr_path);

    if (r1 < 0 && r2 < 0) {
      return serial - 1;
    }
    if (r1 < 0 && r2 >= 0) {
      fprintf(log_f, "Test file %s does not exist, but answer file %s does exist\n", test_name, corr_name);
      return -1;
    }
    if (r1 >= 0 && r2 < 0) {
      fprintf(log_f, "Test file %s does exist, but answer file %s does not exist\n", test_name, corr_name);
      return -1;
    }
    if (r1 != OSPK_REG) {
      fprintf(log_f, "Test file %s is not a regular file\n", test_name);
      return -1;
    }
    if (r2 != OSPK_REG) {
      fprintf(log_f, "Answer file %s is not a regular file\n", corr_name);
      return -1;
    }
  }
}

static int
normalize_file(
        FILE *log_f,
        const unsigned char *path,
        const unsigned char *name)
{
  path_t out_path = { 0 };
  unsigned char *in_text = 0;
  size_t in_size = 0, out_size = 0, out_count = 0;
  int out_mask = 0;
  FILE *out_f = 0;

  if (text_read_file(path, 2, &in_text, &in_size) < 0) {
    fprintf(log_f, "Failed to read %s\n", name);
    goto fail;
  }
  if (text_is_binary(in_text, in_size)) {
    fprintf(log_f, "File %s is not a text file\n", name);
    goto fail;
  }
  out_size = text_normalize_buf(in_text, in_size,
                                TEXT_FIX_CR | TEXT_FIX_TR_SP
                                | TEXT_FIX_FINAL_NL | TEXT_FIX_TR_NL,
                                &out_count, &out_mask);
  if (out_count) {
    snprintf(out_path, sizeof(out_path), "%s.tmp", path);
    if (!(out_f = fopen(out_path, "w"))) {
      fprintf(log_f, "Cannot open %s for writing\n", out_path);
      goto fail;
    }
    fprintf(out_f, "%s", in_text);
    if (fflush(out_f) < 0) {
      fprintf(log_f, "Write error to %s\n", out_path);
      goto fail;
    }
    fclose(log_f); log_f = 0;

    if (rename(out_path, path) < 0) {
      fprintf(log_f, "Rename %s -> %s failed\n", out_path, path);
      goto fail;
    }
    out_path[0] = 0;
  }
  xfree(in_text); in_text = 0;
  return 0;

fail:
  if (out_f) fclose(out_f);
  if (out_path[0]) remove(out_path);
  xfree(in_text);
  return -1;
}

static int
normalize_tests(
        FILE *log_f,
        const struct section_problem_data *prob,
        int test_count,
        const unsigned char *tests_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat)
{
  int num;
  path_t test_path;
  path_t corr_path;
  path_t test_name;
  path_t corr_name;

  if (prob->binary_input > 0) return 0;

  for (num = 1; num <= test_count; ++num) {
    snprintf(test_name, sizeof(test_name), test_pat, num);
    snprintf(corr_name, sizeof(corr_name), corr_pat, num);
    snprintf(test_path, sizeof(test_path), "%s/%s", tests_dir, test_name);
    snprintf(corr_path, sizeof(corr_path), "%s/%s", tests_dir, corr_name);

    if (normalize_file(log_f, test_path, test_name) < 0) goto fail;
    if (normalize_file(log_f, corr_path, corr_name) < 0) goto fail;
  }

  return 0;

fail:
  return -1;
}

static int
invoke_test_checkers(
        const struct section_problem_data *prob,
        int test_count,
        const unsigned char *tests_dir)
{
  return 0;
}

static int
invoke_sample_program(
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        const unsigned char *exe_path,
        int test_count,
        const unsigned char *tests_dir,
        int expect_fail)
{
  return 0;
}

void
run_inverse_testing(
        struct serve_state *state,
        struct run_request_packet *req_pkt,
        struct run_reply_packet *reply_pkt,
        struct section_problem_data *prob,
        const unsigned char *pkt_name,
        unsigned char *report_path,
        size_t report_path_size,
        int utf8_mode)
{
  struct section_global_data *global = state->global;
  int r, i;
  path_t arch_dir;
  path_t arch_path;
  path_t tests_dir;
  int test_count;
  path_t sample_dir;
  path_t good_dir;
  path_t fail_dir;
  int good_count = 0, fail_count = 0;
  unsigned char **good_files = 0, **fail_files = 0;
  path_t exe_path;
  path_t log_path;
  FILE *log_f = 0;
  unsigned char *log_text = 0;
  size_t log_size = 0;
  path_t test_pat = { 0 };
  path_t corr_pat = { 0 };

  make_patterns(prob, test_pat, sizeof(test_pat), corr_pat, sizeof(corr_pat));

  snprintf(log_path, sizeof(log_path), "%s/%s.txt",
           pkt_name, global->run_work_dir);
  if (!(log_f = fopen(log_path, "w"))) {
    // FIXME: fail miserable
    abort();
  }

  /* fill the reply packet with initial values */
  memset(&reply_pkt, 0, sizeof(reply_pkt));
  reply_pkt->judge_id = req_pkt->judge_id;
  reply_pkt->contest_id = req_pkt->contest_id;
  reply_pkt->run_id = req_pkt->run_id;
  reply_pkt->notify_flag = req_pkt->notify_flag;
  reply_pkt->ts1 = req_pkt->ts1;
  reply_pkt->ts1_us = req_pkt->ts1_us;
  reply_pkt->ts2 = req_pkt->ts2;
  reply_pkt->ts2_us = req_pkt->ts2_us;
  reply_pkt->ts3 = req_pkt->ts3;
  reply_pkt->ts3_us = req_pkt->ts3_us;
  reply_pkt->ts4 = req_pkt->ts4;
  reply_pkt->ts4_us = req_pkt->ts4_us;
  get_current_time(&reply_pkt->ts5, &reply_pkt->ts5_us);

  /*
Remaining fields:
  int status;      -- OK, WRONG_ANSWER, CHECK_FAILED
  int failed_test; -- always 0?
  int score;       -- 0 or full score?
  int marked_flag; -- always 0
  */

  snprintf(report_path, report_path_size, "%s/%s.xml",
           global->run_work_dir, pkt_name);
  
  if (req_pkt->mime_type != MIME_TYPE_APPL_GZIP) {
    // FIXME: handle error
  }

  r = generic_copy_file(REMOVE, global->run_exe_dir, pkt_name,req_pkt->exe_sfx,
                        0, global->run_work_dir, pkt_name,
                        mime_type_get_suffix(req_pkt->mime_type));
  if (r <= 0) {
    // FIXME: handle error
  }

  snprintf(arch_path, sizeof(arch_path), "%s%s%s",
           global->run_work_dir, pkt_name,
           mime_type_get_suffix(req_pkt->mime_type));

  snprintf(arch_dir,sizeof(arch_dir), "%s/%s", global->run_work_dir, pkt_name);
  if (make_dir(arch_dir, 0) < 0) {
    // FIXME: handle error
  }

  // invoke tar
  if (invoke_tar(arch_path, arch_dir) < 0) {
    // FIXME: handle error
  }

  snprintf(tests_dir, sizeof(tests_dir), "%s/%s", arch_dir, "tests");
  r = os_IsFile(tests_dir);
  if (r < 0) {
    // FIXME: report error
  } else if (r != OSPK_DIR) {
    // FIXME: report error
  }

  // count tests
  test_count = count_tests(log_f, prob, tests_dir, test_pat, corr_pat);
  if (test_count < 0) {
    // FIXME: report error
  }
  if (!test_count) {
  }

  // normalize test contents
  if (normalize_tests(log_f, prob, test_count, tests_dir, test_pat,
                      corr_pat) < 0) {
    // FIXME: report error
  }

  // invoke test checkers on each test
  if (invoke_test_checkers(prob, test_count, tests_dir) < 0) {
    // FIXME: report error
  }

  // now we're ready to run our programs on the given tests
  if (global->advanced_layout > 0) {
    if (prob->variant_num > 0 && req_pkt->variant > 0) {
      get_advanced_layout_path(sample_dir, sizeof(sample_dir), global, prob,
                               DFLT_P_TEST_DIR, req_pkt->variant);
    } else {
      get_advanced_layout_path(sample_dir, sizeof(sample_dir), global, prob,
                               DFLT_P_TEST_DIR, -1);
    }
  } else {
    if (prob->variant_num > 0 && req_pkt->variant > 0) {
      snprintf(sample_dir, sizeof(sample_dir), "%s-%d", prob->test_dir,
               req_pkt->variant);
    } else {
      snprintf(sample_dir, sizeof(sample_dir), "%s", prob->test_dir);
    }
  }

  snprintf(good_dir, sizeof(good_dir), "%s/%s", sample_dir, GOOD_DIR_NAME);
  snprintf(fail_dir, sizeof(fail_dir), "%s/%s", sample_dir, FAIL_DIR_NAME);

  if (scan_executable_files(good_dir, &good_count, &good_files) < 0) {
    // FIXME: report error
  }
  if (scan_executable_files(fail_dir, &fail_count, &fail_files) < 0) {
    // FIXME: report error
  }

  for (i = 0; i < good_count; ++i) {
    snprintf(exe_path, sizeof(exe_path), "%s/%s", good_dir, good_files[i]);
    r = invoke_sample_program(global, prob, exe_path, test_count, tests_dir,0);
  }
  for (i = 0; i < fail_count; ++i) {
    snprintf(exe_path, sizeof(exe_path), "%s/%s", fail_dir, fail_files[i]);
    r = invoke_sample_program(global, prob, exe_path, test_count, tests_dir,1);
  }

  /* process the log file */
  fclose(log_f); log_f = 0;
  if (text_read_file(log_path, 1, &log_text, &log_size) < 0) {
    log_text = xstrdup("Error: failed to read the log file\n");
    log_size = strlen(log_text);
  } else if (strlen(log_text) != log_size) {
    log_text = xstrdup("Error: log file is binary\n");
    log_size = strlen(log_text);
  }
  if (log_size > 0 && isspace(log_text[log_size - 1])) --log_size;
  log_text[log_size] = 0;
  if (!log_size) {
    xfree(log_text); log_text = 0; log_size = 0;
  }
  if (utf8_mode && log_text) {
    utf8_fix_string(log_text, NULL);
  }

  /* fill the remaining fields of the reply packet */
  get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);
  reply_pkt->ts7 = reply_pkt->ts6;
  reply_pkt->ts7_us = reply_pkt->ts6_us;

  /* FIXME: save the XML report log */

  if (log_f) {
    fclose(log_f); log_f = 0;
  }
  xfree(log_text);
  if (good_files) {
    for (i = 0; i < good_count; ++i)
      xfree(good_files[i]);
    xfree(good_files);
    good_files = 0; good_count = 0;
  }
  if (fail_files) {
    for (i = 0; i < fail_count; ++i)
      xfree(fail_files[i]);
    xfree(fail_files);
    fail_files = 0; fail_count = 0;
  }

  clear_directory(global->run_work_dir);
  return;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
