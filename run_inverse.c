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
#include "runlog.h"
#include "testing_report_xml.h"

#include <reuse/osdeps.h>
#include <reuse/xalloc.h>
#include <reuse/exec.h>
#include <reuse/logger.h>

#include <ctype.h>

#define GOOD_DIR_NAME "good"
#define FAIL_DIR_NAME "fail"

struct run_info
{
  int status;
  long cpu_time_ms;
  long real_time_ms;
};

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
invoke_tar(
        FILE *log_f,
        const unsigned char *log_path,
        const unsigned char *arch_path,
        const unsigned char *work_dir)
{
  tpTask tsk = 0;

  tsk = task_New();
  task_AddArg(tsk, "/bin/tar");
  task_AddArg(tsk, "xf");
  task_AddArg(tsk, arch_path);
  task_AddArg(tsk, "-C");
  task_AddArg(tsk, work_dir);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  if (work_dir) task_SetWorkingDir(tsk, work_dir);
  task_SetPathAsArg0(tsk);
  task_EnableAllSignals(tsk);

  fflush(log_f);
  if (task_Start(tsk) < 0) {
    fprintf(log_f, "invoke_tar: failed to start /bin/tar\n");
    task_Delete(tsk);
    return -1;
  }
  task_Wait(tsk);
  if (task_IsAbnormal(tsk)) {
    fprintf(log_f, "invoke_tar: /bin/tar failed\n");
    task_Delete(tsk);
    return -1;
  }
  task_Delete(tsk); tsk = 0;

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
    fprintf(log_f, "File %s is modified (%d bytes changed): ", name,
            (int) out_count);
    if ((out_mask & TEXT_FIX_CR)) {
      fprintf(log_f, "(CR removed) ");
    }
    if ((out_mask & TEXT_FIX_TR_SP)) {
      fprintf(log_f, "(trailing whitespace removed) ");
    }
    if ((out_mask & TEXT_FIX_FINAL_NL)) {
      fprintf(log_f, "(final NL appended) ");
    }
    if ((out_mask & TEXT_FIX_TR_NL)) {
      fprintf(log_f, "(trailing empty lines removed) ");
    }
    fprintf(log_f, "\n");
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
invoke_test_checker(
        FILE *log_f,
        const unsigned char *log_path,
        const unsigned char *test_checker_cmd,
        const struct section_problem_data *prob,
        int num,
        const unsigned char *work_dir,
        const unsigned char *input_file,
        const unsigned char *output_file)
{
  tpTask tsk = 0;
  int i, r;

  tsk = task_New();
  task_AddArg(tsk, test_checker_cmd);
  task_AddArg(tsk, input_file);
  task_AddArg(tsk, output_file);
  task_SetPathAsArg0(tsk);
  task_EnableAllSignals(tsk);
  if (work_dir) task_SetWorkingDir(tsk, work_dir);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  if (prob->test_checker_env) {
    for (i = 0; prob->test_checker_env[i]; ++i)
      task_PutEnv(tsk, prob->test_checker_env[i]);
  }
  if (prob->checker_real_time_limit > 0) {
    task_SetMaxRealTime(tsk, prob->checker_real_time_limit);
  }

  fflush(log_f);

  if (task_Start(tsk) < 0) {
    fprintf(log_f, "Error: failed to start %s\n", test_checker_cmd);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  task_Wait(tsk);
  if (task_IsTimeout(tsk)) {
    fprintf(log_f, "Error: test checker %s time-out on test %d\n",
            test_checker_cmd, num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  r = task_Status(tsk);
  if (r != TSK_EXITED && r != TSK_SIGNALED) {
    fprintf(log_f, "Error: test checker %s invalid status on test %d\n",
            test_checker_cmd, num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  if (r == TSK_SIGNALED) {
    fprintf(log_f,
            "Error: test checker %s is terminated by signal %d on test %d\n",
            test_checker_cmd, task_TermSignal(tsk), num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  r = task_ExitCode(tsk);
  if (r != RUN_OK && r != RUN_COMPILE_ERR && r != RUN_PRESENTATION_ERR
      && r != RUN_WRONG_ANSWER_ERR && r != RUN_CHECK_FAILED) {
    fprintf(log_f, "Error: test checker %s exit code %d invalid on test %d\n",
            test_checker_cmd, r, num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  if (r == RUN_CHECK_FAILED) {
    fprintf(log_f, "Error: test checker %s reported CHECK_FAILED on test %d\n",
            test_checker_cmd, num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  if (r == RUN_COMPILE_ERR || r == RUN_PRESENTATION_ERR) {
    fprintf(log_f, "Test checker reports PRESENTATION ERROR on test %d\n",
            num);
    task_Delete(tsk);
    return RUN_PRESENTATION_ERR;
  }
  if (r == RUN_WRONG_ANSWER_ERR) {
    fprintf(log_f, "Test checker report WRONG ANSWER ERROR on test %d\n",
            num);
    task_Delete(tsk);
    return RUN_PRESENTATION_ERR;
  }
  task_Delete(tsk);
  return RUN_OK;
}

static int
invoke_test_checker_on_tests(
        FILE *log_f,
        const unsigned char *log_path,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant,
        int test_count,
        const unsigned char *tests_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat)
{
  path_t test_path;
  path_t corr_path;
  path_t test_name;
  path_t corr_name;
  path_t test_checker_cmd;
  int retval = RUN_OK, r, num;

  if (!prob->test_checker_cmd || !prob->test_checker_cmd[0])
    return 0;

  if (prob->variant_num > 0 && variant > 0) {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(test_checker_cmd, sizeof(test_checker_cmd),
                               global, prob, prob->test_checker_cmd, variant);
    } else if (os_IsAbsolutePath(prob->test_checker_cmd)) {
      snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s-%d",
               prob->test_checker_cmd, variant);
    } else {
      snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s/%s-%d",
               global->checker_dir, prob->test_checker_cmd, variant);
    }
  } else {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(test_checker_cmd, sizeof(test_checker_cmd),
                               global, prob, prob->test_checker_cmd, -1);
    } else if (os_IsAbsolutePath(prob->test_checker_cmd)) {
      snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s",
               prob->test_checker_cmd);
    } else {
      snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s/%s",
               global->checker_dir, prob->test_checker_cmd);
    }
  }

  if ((r = os_IsFile(test_checker_cmd)) < 0) {
    fprintf(log_f, "Error: test checker %s does not exist\n",
            test_checker_cmd);
    return RUN_CHECK_FAILED;
  }
  if (r != OSPK_REG) {
    fprintf(log_f, "Error: test checker %s is not a regular file\n",
            test_checker_cmd);
    return RUN_CHECK_FAILED;
  }
  if (os_CheckAccess(test_checker_cmd, REUSE_X_OK) < 0) {
    fprintf(log_f, "Error: test checker %s is not an executable file\n",
            test_checker_cmd);
    return RUN_CHECK_FAILED;
  }

  for (num = 1; num <= test_count; ++num) {
    snprintf(test_name, sizeof(test_name), test_pat, num);
    snprintf(corr_name, sizeof(corr_name), corr_pat, num);
    snprintf(test_path, sizeof(test_path), "%s/%s", tests_dir, test_name);
    snprintf(corr_path, sizeof(corr_path), "%s/%s", tests_dir, corr_name);

    r = invoke_test_checker(log_f, log_path, test_checker_cmd, prob,
                            num, tests_dir, test_path, corr_path);
    ASSERT(r == RUN_OK || r == RUN_PRESENTATION_ERR || r == RUN_CHECK_FAILED);
    if (r == RUN_CHECK_FAILED) {
      retval = r;
    } else if (r == RUN_PRESENTATION_ERR && retval == RUN_OK) {
      retval = r;
    }
  }

  return retval;
}

static int
touch_file(const unsigned char *path)
{
  FILE *f = fopen(path, "w");
  if (!f) return -1;
  if (fclose(f) < 0) return -1;
  return 0;
}

static int
invoke_test_program(
        FILE *log_f,
        const unsigned char *log_path,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int num,
        const unsigned char *check_dir,
        const unsigned char *exe_path,
        const unsigned char *exe_name,
        const unsigned char *input_file,
        struct testing_report_cell *tt_cell)
{
  path_t check_exe;
  path_t input_path;
  path_t output_path;
  tpTask tsk = 0;
  long time_limit_ms = 0;
  int clear_check_dir = 0;
  int retval = RUN_CHECK_FAILED;
  int r;

  snprintf(check_exe, sizeof(check_exe), "%s/%s", check_dir, exe_name);
  snprintf(input_path, sizeof(input_path), "%s/%s", check_dir,
           prob->input_file);
  snprintf(output_path, sizeof(output_path), "%s/%s", check_dir,
           prob->output_file);

  if (prob->time_limit_millis > 0) {
    time_limit_ms = prob->time_limit_millis;
  } else if (prob->time_limit > 0) {
    time_limit_ms = prob->time_limit * 1000;
  }

  clear_check_dir = 1;
  if (generic_copy_file(0, 0, exe_path, 0, 0, check_dir, exe_name, 0) < 0) {
    fprintf(log_f, "Error: failed to copy %s to %s\n",
            exe_path, check_exe);
    goto cleanup;
  }
  if (make_executable(check_exe) < 0) {
    fprintf(log_f, "Error: failed to set executable bit on %s\n",
            check_exe);
    goto cleanup;
  }
  if (generic_copy_file(0, 0, input_file, 0, 0, check_dir,
                        prob->input_file, 0) < 0) {
    fprintf(log_f, "Error: failed to copy %s to %s\n", input_file, input_path);
    goto cleanup;
  }
  if (touch_file(output_path) < 0) {
    fprintf(log_f, "Error: failed to create %s\n", output_path);
    goto cleanup;
  }

  tsk = task_New();
  task_AddArg(tsk, check_exe);
  task_SetPathAsArg0(tsk);
  task_SetWorkingDir(tsk, check_dir);
  if (prob->combined_stdin > 0 || prob->use_stdin > 0) {
    task_SetRedir(tsk, 0, TSR_FILE, input_path, TSK_READ, 0);
  } else {
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  }
  if (prob->combined_stdout > 0 || prob->use_stdout > 0) {
    task_SetRedir(tsk, 1, TSR_FILE, output_path, TSK_REWRITE, TSK_FULL_RW);
  } else {
    task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
  }
  task_SetRedir(tsk, 2, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
  task_EnableAllSignals(tsk);
  if (time_limit_ms > 0 && time_limit_ms % 1000 == 0) {
    task_SetMaxTime(tsk, time_limit_ms / 1000);
  } else if (time_limit_ms > 0) {
    task_SetMaxTimeMillis(tsk, time_limit_ms);
  }
  if (prob->real_time_limit > 0) {
    task_SetMaxRealTime(tsk, prob->real_time_limit);
  }
  if (prob->max_stack_size && prob->max_stack_size != -1L) {
    task_SetStackSize(tsk, prob->max_stack_size);
  }
  if (prob->max_data_size && prob->max_data_size != -1L) {
    task_SetDataSize(tsk, prob->max_data_size);
  }
  if (prob->max_vm_size && prob->max_vm_size != -1L) {
    task_SetVMSize(tsk, prob->max_vm_size);
  }
  /* no security restrictions and memory limits */
  if (task_Start(tsk) < 0) {
    fprintf(log_f, "Error: failed to start %s on test %d\n",
            check_exe, num);
    goto cleanup;
  }

  task_Wait(tsk);
  tt_cell->time = task_GetRunningTime(tsk);
  tt_cell->real_time = task_GetRealTime(tsk);

  if (task_IsTimeout(tsk)) {
    fprintf(log_f, "Program %s time-limit exceeded on test %d\n",
            exe_name, num);
    retval = RUN_TIME_LIMIT_ERR;
    goto cleanup;
  }
  r = task_Status(tsk);
  if (r != TSK_EXITED && r != TSK_SIGNALED) {
    fprintf(log_f, "Error: program %s invalid status %d on test %d\n",
            exe_name, r, num);
    goto cleanup;
  }
  if (r == TSK_SIGNALED) {
    fprintf(log_f, "Program %s terminated with signal %d on test %d\n",
            exe_name, task_TermSignal(tsk), num);
    retval = RUN_RUN_TIME_ERR;
    goto cleanup;
  }
  r = task_ExitCode(tsk);
  if (r != 0) {
    fprintf(log_f, "Program %s exited with code %d on test %d\n",
            exe_name, r, num);
    retval = RUN_RUN_TIME_ERR;
    goto cleanup;
  }
  clear_check_dir = 0;
  retval = RUN_OK;

cleanup:
  if (tsk) task_Delete(tsk);
  if (clear_check_dir) clear_directory(check_dir);
  tt_cell->status = retval;
  return retval;
} 

static int
invoke_checker(
        FILE *log_f,
        const unsigned char *log_path,
        const struct section_problem_data *prob,
        const unsigned char *check_dir,
        const unsigned char *check_cmd,
        const unsigned char *exe_name,
        int num,
        const unsigned char *input_path,
        const unsigned char *output_path,
        const unsigned char *correct_path,
        struct testing_report_cell *tt_cell)
{
  tpTask tsk = 0;
  int r, i;
  int retval = RUN_CHECK_FAILED;

  tsk = task_New();
  task_AddArg(tsk, check_cmd);
  task_SetPathAsArg0(tsk);
  task_SetWorkingDir(tsk, check_dir);
  task_AddArg(tsk, input_path);
  task_AddArg(tsk, output_path);
  task_AddArg(tsk, correct_path);
  if (prob->checker_real_time_limit > 0) {
    task_SetMaxRealTime(tsk, prob->checker_real_time_limit);
  }
  if (prob->checker_env) {
    for (i = 0; prob->checker_env[i]; ++i)
      task_PutEnv(tsk, prob->checker_env[i]);
  }
  task_EnableAllSignals(tsk);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_WRITE, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, log_path, TSK_WRITE, TSK_FULL_RW);

  fflush(log_f);

  if (task_Start(tsk) < 0) {
    fprintf(log_f, "Error: failed to start checker %s for %s on test %d\n",
            check_cmd, exe_name, num);
    goto cleanup;
  }
  task_Wait(tsk);
  r = task_Status(tsk);
  if (r != TSK_EXITED && r != TSK_SIGNALED) {
    fprintf(log_f, "Error: invalid status of %s for %s on test %d\n",
            check_cmd, exe_name, num);
    goto cleanup;
  }
  if (task_IsTimeout(tsk)) {
    fprintf(log_f, "Error: checker %s for %s timeout on test %d\n",
            check_cmd, exe_name, num);
    goto cleanup;
  }
  if (r == TSK_SIGNALED) {
    fprintf(log_f,
            "Error: checker %s for %s terminated by signal %d on test %d\n",
            check_cmd, exe_name, task_TermSignal(tsk), num);
    goto cleanup;
  }
  r = task_ExitCode(tsk);
  if (r != RUN_OK && r != RUN_CHECK_FAILED && r != RUN_WRONG_ANSWER_ERR
      && r != RUN_PRESENTATION_ERR) {
    fprintf(log_f, "Error: checker %s for %s invalid exit code %d on test %d\n",
            check_cmd, exe_name, r, num);
    goto cleanup;
  }
  if (r == RUN_CHECK_FAILED) {
    fprintf(log_f, "Error: checker %s for %s status CHECK_FAILED on test %d\n",
            check_cmd, exe_name, num);
    goto cleanup;
  }
  retval = r;

cleanup:
  if (tsk) task_Delete(tsk);
  tt_cell->status = retval;
  return retval;
}

static int
invoke_sample_program(
        FILE *log_f,
        const unsigned char *log_path,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        const unsigned char *check_dir,
        const unsigned char *exe_path,
        const unsigned char *exe_name,
        const unsigned char *check_cmd,
        int test_count,
        const unsigned char *tests_dir,
        const unsigned char *test_pat,
        const unsigned char *corr_pat,
        struct testing_report_row *tt_row,
        struct testing_report_cell **tt_cell_row)
{
  int num, r, i;
  path_t test_name;
  path_t corr_name;
  path_t test_path;
  path_t corr_path;
  path_t out_path;

  /* no sense to continue if operation on the check_dir failed */
  if (make_writable(check_dir) < 0) {
    fprintf(log_f, "Error: cannot make writable directory %s\n", check_dir);
    tt_row->status = RUN_CHECK_FAILED;
    return RUN_CHECK_FAILED;
  }
  if (clear_directory(check_dir) < 0) {
    fprintf(log_f, "Error: failed to clean directory %s\n", check_dir);
    tt_row->status = RUN_CHECK_FAILED;
    return RUN_CHECK_FAILED;
  }

  snprintf(out_path, sizeof(out_path), "%s/%s", check_dir, prob->output_file);

  for (num = 1; num <= test_count; ++num) {
    snprintf(test_name, sizeof(test_name), test_pat, num);
    snprintf(corr_name, sizeof(corr_name), corr_pat, num);
    snprintf(test_path, sizeof(test_path), "%s/%s", tests_dir, test_name);
    snprintf(corr_path, sizeof(corr_path), "%s/%s", tests_dir, corr_name);

    r = invoke_test_program(log_f, log_path, global, prob, num, check_dir,
                            exe_path, exe_name, test_path,
                            tt_cell_row[num - 1]);
    if (r == RUN_OK) {
      invoke_checker(log_f, log_path, prob, check_dir, check_cmd,
                     exe_name, num, test_path, out_path, corr_path,
                     tt_cell_row[num - 1]);
    }

    if (clear_directory(check_dir) < 0) {
      fprintf(log_f, "Error: failed to clean directory %s\n", check_dir);
    }
  }

  tt_row->status = RUN_OK;
  for (i = 0; i < test_count; ++i) {
    if (tt_cell_row[i]->status == RUN_CHECK_FAILED) {
      tt_row->status = RUN_CHECK_FAILED;
      break;
    }
    if (tt_cell_row[i]->status != RUN_OK) {
      tt_row->status = RUN_PARTIAL;
    }
  }

  return 0;
}

static void
analyze_results(
        FILE *log_f,
        const unsigned char *log_path,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        struct run_request_packet *req_pkt,
        struct run_reply_packet *reply_pkt,
        testing_report_xml_t report_xml)
{
  int i, j, score = 0;

  if (!report_xml->tt_rows) {
    fprintf(stderr, "Error: tt_rows == NULL\n");
    goto check_failed;
  }
  if (!report_xml->tt_cells) {
    fprintf(stderr, "Error: tt_cells == NULL\n");
    goto check_failed;
  }

  for (i = 0; i < report_xml->tt_row_count; ++i) {
    if (!report_xml->tt_rows[i]) {
      fprintf(stderr, "Error: tt_rows[%d] == NULL\n", i);
      goto check_failed;
    }
    if (!report_xml->tt_cells[i]) {
      fprintf(stderr, "Error: tt_cells[%d] == NULL\n", i);
      goto check_failed;
    }
    if (report_xml->tt_rows[i]->status == RUN_CHECK_FAILED) {
      goto check_failed;
    }
    for (j = 0; j < report_xml->tt_column_count; ++j) {
      if (!report_xml->tt_cells[i][j]) {
        fprintf(stderr, "Error: tt_cells[%d][%d] == NULL\n", i, j);
        goto check_failed;
      }
      if (report_xml->tt_cells[i][j]->status == RUN_CHECK_FAILED) {
        goto check_failed;
      }
    }
  }

  for (i = 0; i < report_xml->tt_row_count; ++i) {
    if (report_xml->tt_rows[i]->must_fail <= 0) {
      // this sample program must be OK
      if (report_xml->tt_rows[i]->status != RUN_OK)
        goto wrong_answer;
    } else {
      // this sample program must fail
      if (report_xml->tt_rows[i]->status == RUN_OK)
        goto wrong_answer;
    }
  }

  score = report_xml->max_score;
  report_xml->status = RUN_OK;
  reply_pkt->status = RUN_OK;
  report_xml->score = score;
  reply_pkt->score = score;
  return;

wrong_answer:
  report_xml->status = RUN_WRONG_ANSWER_ERR;
  reply_pkt->status = RUN_WRONG_ANSWER_ERR;
  return;

check_failed:
  report_xml->status = RUN_CHECK_FAILED;
  reply_pkt->status = RUN_CHECK_FAILED;
  return;
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
  int r, i, j;
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
  FILE *log_f = 0, *rep_f = 0;
  unsigned char *log_text = 0;
  size_t log_size = 0;
  path_t test_pat = { 0 };
  path_t corr_pat = { 0 };
  struct testing_report_cell ***tt_cells = 0, *tt_cell = 0;
  struct testing_report_row **tt_rows = 0, *tt_row = 0;
  int tt_row_count = 0;
  path_t check_cmd = { 0 };
  path_t check_dir = { 0 };
  testing_report_xml_t report_xml = 0;
  long time_limit_ms = 0;

  make_patterns(prob, test_pat, sizeof(test_pat), corr_pat, sizeof(corr_pat));

  snprintf(log_path, sizeof(log_path), "%s/%s.txt",
           global->run_work_dir, pkt_name);
  if (!(log_f = fopen(log_path, "w"))) {
    // FIXME: fail miserably
    abort();
  }
  fclose(log_f); log_f = 0;
  if (!(log_f = fopen(log_path, "a"))) {
    abort();
  }

  /* fill the reply packet with initial values */
  memset(reply_pkt, 0, sizeof(*reply_pkt));
  reply_pkt->judge_id = req_pkt->judge_id;
  reply_pkt->contest_id = req_pkt->contest_id;
  reply_pkt->run_id = req_pkt->run_id;
  reply_pkt->notify_flag = req_pkt->notify_flag;
  reply_pkt->failed_test = 0;
  reply_pkt->marked_flag = 0;
  reply_pkt->status = RUN_CHECK_FAILED;
  reply_pkt->score = 0;
  reply_pkt->ts1 = req_pkt->ts1;
  reply_pkt->ts1_us = req_pkt->ts1_us;
  reply_pkt->ts2 = req_pkt->ts2;
  reply_pkt->ts2_us = req_pkt->ts2_us;
  reply_pkt->ts3 = req_pkt->ts3;
  reply_pkt->ts3_us = req_pkt->ts3_us;
  reply_pkt->ts4 = req_pkt->ts4;
  reply_pkt->ts4_us = req_pkt->ts4_us;
  get_current_time(&reply_pkt->ts5, &reply_pkt->ts5_us);

  /* create the testing report */
  report_xml = testing_report_alloc(reply_pkt->run_id, reply_pkt->judge_id);
  report_xml->status = RUN_CHECK_FAILED;
  report_xml->scoring_system = req_pkt->scoring_system;
  report_xml->archive_available = 0;
  report_xml->correct_available = 1;
  report_xml->info_available = 0;
  report_xml->real_time_available = 1;
  report_xml->max_memory_used_available = 0;
  report_xml->run_tests = 0;
  report_xml->variant = req_pkt->variant;
  report_xml->accepting_mode = 0;
  report_xml->failed_test = -1;
  report_xml->tests_passed = 0;
  report_xml->score = 0;
  report_xml->max_score = prob->full_score;
  report_xml->marked_flag = 0;
  report_xml->tests_mode = 1;

  if (prob->time_limit_millis > 0) {
    time_limit_ms = prob->time_limit_millis;
  } else if (prob->time_limit > 0) {
    time_limit_ms = prob->time_limit * 1000;
  }
  if (time_limit_ms > 0) {
    report_xml->time_limit_ms = time_limit_ms;
  }
  if (prob->real_time_limit > 0) {
    report_xml->real_time_limit_ms = prob->real_time_limit * 1000;
  }
  if ((log_text = os_NodeName())) {
    report_xml->host = xstrdup(log_text);
  }
  log_text = 0;

  /*
Remaining field to fill:
  int status;      -- OK, WRONG_ANSWER, CHECK_FAILED
  int score;       -- 0 or full score
  */

  snprintf(report_path, report_path_size, "%s/%s.xml",
           global->run_work_dir, pkt_name);
  
  if (req_pkt->mime_type != MIME_TYPE_APPL_GZIP) {
    fprintf(log_f, "Error: archive of type %d (%s) is not supported\n",
            req_pkt->mime_type, mime_type_get_type(req_pkt->mime_type));
    goto cleanup;
  }

  r = generic_copy_file(REMOVE, global->run_exe_dir, pkt_name,req_pkt->exe_sfx,
                        0, global->run_work_dir, pkt_name,
                        mime_type_get_suffix(req_pkt->mime_type));
  if (r <= 0) {
    fprintf(log_f, "Error: failed to read archive file %s/%s%s\n",
            global->run_work_dir, pkt_name,
            mime_type_get_suffix(req_pkt->mime_type));
    goto cleanup;
  }

  snprintf(arch_path, sizeof(arch_path), "%s/%s%s",
           global->run_work_dir, pkt_name,
           mime_type_get_suffix(req_pkt->mime_type));

  snprintf(arch_dir,sizeof(arch_dir), "%s/%s", global->run_work_dir, pkt_name);
  if (make_dir(arch_dir, 0) < 0) {
    fprintf(log_f, "Error: failed to create directory %s/%s\n",
            global->run_work_dir, pkt_name);
    goto cleanup;
  }

  // invoke tar
  if (invoke_tar(log_f, log_path, arch_path, arch_dir) < 0) {
    fprintf(log_f, "Error: tar extraction failed on file %s in dir %s\n",
            arch_path, arch_dir);
    goto cleanup;
  }

  snprintf(tests_dir, sizeof(tests_dir), "%s/%s", arch_dir, "tests");
  r = os_IsFile(tests_dir);
  if (r < 0) {
    fprintf(log_f, "Error: directory %s does not exist\n", tests_dir);
    goto cleanup;
  } else if (r != OSPK_DIR) {
    fprintf(log_f, "Error: %s is not a directory\n", tests_dir);
    goto cleanup;
  }

  // count tests
  test_count = count_tests(log_f, prob, tests_dir, test_pat, corr_pat);
  if (test_count < 0) {
    fprintf(log_f, "Error: failed to count tests in %s\n", tests_dir);
    goto cleanup;
  }
  if (!test_count) {
    fprintf(log_f, "Error: no tests in the archive\n");
    goto cleanup;
  }

  // normalize test contents
  if (normalize_tests(log_f, prob, test_count, tests_dir, test_pat,
                      corr_pat) < 0) {
    fprintf(log_f, "Error: failed to normalize tests\n");
    goto cleanup;
  }

  // invoke test checkers on each test
  r = invoke_test_checker_on_tests(log_f, log_path, global,
                                   prob, req_pkt->variant,
                                   test_count, tests_dir,
                                   test_pat, corr_pat);
  if (r != RUN_OK) {
    reply_pkt->status = r;
    report_xml->status = r;
    goto cleanup;
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
    fprintf(log_f, "Error: scan of %s failed\n", good_dir);
    goto cleanup;
  }
  if (scan_executable_files(fail_dir, &fail_count, &fail_files) < 0) {
    fprintf(log_f, "Error: scan of %s failed\n", good_dir);
    goto cleanup;
  }
  if (good_count <= 0 && fail_count <= 0) {
    fprintf(log_f, "Error: no sample programs are found\n");
    goto cleanup;
  }

  // get checker path
  if (prob->standard_checker[0]) {
    snprintf(check_cmd, sizeof(check_cmd), "%s/%s",
             global->ejudge_checkers_dir, prob->standard_checker);
  } else if (global->advanced_layout > 0) {
    if (prob->variant_num > 0 && req_pkt->variant > 0) {
      get_advanced_layout_path(check_cmd, sizeof(check_cmd),
                               global, prob, prob->check_cmd, req_pkt->variant);
    } else {
      get_advanced_layout_path(check_cmd, sizeof(check_cmd),
                               global, prob, prob->check_cmd, -1);
    }
  } else if (os_IsAbsolutePath(prob->check_cmd)) {
    if (prob->variant_num > 0 && req_pkt->variant > 0) {
      snprintf(check_cmd, sizeof(check_cmd), "%s-%d", prob->check_cmd,
               req_pkt->variant);
    } else {
      snprintf(check_cmd, sizeof(check_cmd), "%s", prob->check_cmd);
    }
  } else {
    if (prob->variant_num > 0 && req_pkt->variant > 0) {
      snprintf(check_cmd, sizeof(check_cmd), "%s/%s-%d",
               global->checker_dir, prob->check_cmd, req_pkt->variant);
    } else {
      snprintf(check_cmd, sizeof(check_cmd), "%s/%s",
               global->checker_dir, prob->check_cmd);
    }
  }
  r = os_IsFile(check_cmd);
  if (r < 0) {
    fprintf(log_f, "Error: checker %s does not exist\n", check_cmd);
    goto cleanup;
  }
  if (r != OSPK_REG) {
    fprintf(log_f, "Error: checker %s is not a regular file\n", check_cmd);
    goto cleanup;
  }
  if (os_CheckAccess(check_cmd, REUSE_X_OK) < 0) {
    fprintf(log_f, "Error: checker %s is not an executable file\n", check_cmd);
    goto cleanup;
  }

  snprintf(check_dir, sizeof(check_dir), "%s", global->run_check_dir);
#if defined EJUDGE_LOCAL_DIR
  pathmake2(check_dir, EJUDGE_LOCAL_DIR, "/", check_dir, NULL);
#endif
  pathmake2(check_dir, EJUDGE_CONTESTS_HOME_DIR, "/", check_dir, NULL);
  if (make_dir(check_dir, 0) < 0) {
    fprintf(log_f, "Error: failed to create directory %s\n", check_dir);
    goto cleanup;
  }

  ASSERT(good_count >= 0 && fail_count >= 0);
  tt_row_count = good_count + fail_count;
  report_xml->tt_row_count = tt_row_count;
  report_xml->tt_column_count = test_count;

  XCALLOC(tt_rows, tt_row_count);
  for (i = 0; i < tt_row_count; ++i) {
    XCALLOC(tt_row, 1);
    tt_rows[i] = tt_row;
    tt_row->row = i;
    tt_row->status = RUN_CHECK_FAILED;
    if (i >= good_count) {
      tt_row->name = xstrdup(fail_files[i - good_count]);
      tt_row->must_fail = 1;
    } else {
      tt_row->name = xstrdup(good_files[i]);
      tt_row->must_fail = 0;
    }
    tt_row->nominal_score = -1;
    tt_row->score = -1;
  }
  report_xml->tt_rows = tt_rows; tt_rows = 0;

  XCALLOC(tt_cells, tt_row_count);
  for (i = 0; i < tt_row_count; ++i) {
    XCALLOC(tt_cells[i], test_count);
    for (j = 0; j < test_count; ++j) {
      XCALLOC(tt_cell, 1);
      tt_cells[i][j] = tt_cell;
      tt_cell->row = i;
      tt_cell->column = j;
      tt_cell->status = RUN_CHECK_FAILED;
      tt_cell->time = -1;
      tt_cell->real_time = -1;
    }
  }
  report_xml->tt_cells = tt_cells; tt_cells = 0;

  for (i = 0; i < good_count; ++i) {
    snprintf(exe_path, sizeof(exe_path), "%s/%s", good_dir, good_files[i]);
    r = invoke_sample_program(log_f, log_path, global, prob, check_dir,
                              exe_path, good_files[i], check_cmd, test_count,
                              tests_dir, test_pat, corr_pat,
                              report_xml->tt_rows[i], report_xml->tt_cells[i]);
  }
  for (i = 0; i < fail_count; ++i) {
    snprintf(exe_path, sizeof(exe_path), "%s/%s", fail_dir, fail_files[i]);
    r = invoke_sample_program(log_f, log_path, global, prob, check_dir,
                              exe_path, fail_files[i], check_cmd, test_count,
                              tests_dir, test_pat, corr_pat,
                              report_xml->tt_rows[i + good_count],
                              report_xml->tt_cells[i + good_count]);
  }

  analyze_results(log_f, log_path, global, prob, req_pkt, reply_pkt,
                  report_xml);

cleanup:
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
  if (log_text) {
    report_xml->errors = log_text; log_text = 0;
  }

  /* fill the remaining fields of the reply packet */
  get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);
  reply_pkt->ts7 = reply_pkt->ts6;
  reply_pkt->ts7_us = reply_pkt->ts6_us;

  if ((rep_f = fopen(report_path, "w"))) {
    testing_report_unparse_xml(rep_f, utf8_mode,
                               global->max_file_length, global->max_line_length,
                               report_xml);
    fclose(rep_f); rep_f = 0;
  }

  report_xml = testing_report_free(report_xml);

  if (log_f) {
    fclose(log_f); log_f = 0;
  }
  if (tt_cells) {
    for (i = 0; i < tt_row_count; ++i) {
      if (tt_cells[i]) {
        for (j = 0; j < test_count; ++j) {
          xfree(tt_cells[i][j]);
        }
        xfree(tt_cells[i]);
      }
    }
    xfree(tt_cells);
    tt_cells = 0;
  }
  if (tt_rows) {
    for (i = 0; i < tt_row_count; ++i) {
      if (tt_rows[i]) {
        xfree(tt_rows[i]->name);
        xfree(tt_rows);
      }
    }
    xfree(tt_rows); tt_rows = 0;
  }
  tt_row_count = 0;
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

  //clear_directory(global->run_work_dir);
  return;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
