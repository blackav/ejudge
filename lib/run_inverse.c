/* -*- c -*- */

/* Copyright (C) 2010-2022 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/run.h"
#include "ejudge/serve_state.h"
#include "ejudge/fileutl.h"
#include "ejudge/pathutl.h"
#include "ejudge/mime_type.h"
#include "ejudge/prepare.h"
#include "ejudge/run_packet.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/misctext.h"
#include "ejudge/curtime.h"
#include "ejudge/runlog.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/super_run_packet.h"
#include "ejudge/cpu.h"
#include "ejudge/ej_uuid.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>

#define GOOD_DIR_NAME "good"
#define FAIL_DIR_NAME "fail"

#define MAX_LOG_FILE_SIZE (1 * 1024 * 1024)

struct run_info
{
  int status;
  long cpu_time_ms;
  long real_time_ms;
};

static void plog(FILE *f, const char *pfx, const char *format, ...)
  __attribute__((format(printf, 3, 4)));
static void plog(FILE *f, const char *pfx, const char *format, ...)
{
  char buf[1024];
  va_list args;

  if (!f) return;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (pfx) {
    fprintf(f, "%s: %s\n", pfx, buf);
  } else {
    fprintf(f, "%s\n", buf);
  }
}

static void perr(FILE *f, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
static void perr(FILE *f, const char *format, ...)
{
  char buf[1024];
  va_list args;

  if (!f) return;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(f, "Error: %s\n", buf);
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
    plog(log_f, "invoke_tar", "failed to start /bin/tar");
    task_Delete(tsk);
    return -1;
  }
  task_Wait(tsk);
  if (task_IsAbnormal(tsk)) {
    plog(log_f, "invoke_tar", "/bin/tar failed");
    task_Delete(tsk);
    return -1;
  }
  task_Delete(tsk); tsk = 0;

  return 0;
}

static int
invoke_zip(
        FILE *log_f,
        const unsigned char *log_path,
        const unsigned char *arch_path,
        const unsigned char *work_dir)
{
  tpTask tsk = 0;

  tsk = task_New();
  task_AddArg(tsk, "/usr/bin/7z");
  task_AddArg(tsk, "x");
  task_AddArg(tsk, arch_path);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  if (work_dir) task_SetWorkingDir(tsk, work_dir);
  task_SetPathAsArg0(tsk);
  task_EnableAllSignals(tsk);
  task_SetWorkingDir(tsk, work_dir);

  fflush(log_f);
  if (task_Start(tsk) < 0) {
    plog(log_f, "invoke_zip", "failed to start /usr/bin/7z");
    task_Delete(tsk);
    return -1;
  }
  task_Wait(tsk);
  if (task_IsAbnormal(tsk)) {
    plog(log_f, "invoke_zip", "/usr/bin/7z failed");
    task_Delete(tsk);
    return -1;
  }
  task_Delete(tsk); tsk = 0;

  return 0;
}

static int
count_tests(
        FILE *log_f,
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
      plog(log_f, 0, "Test file %s does not exist, but answer file %s does exist", test_name, corr_name);
      return -1;
    }
    if (r1 >= 0 && r2 < 0) {
      plog(log_f, 0, "Test file %s does exist, but answer file %s does not exist", test_name, corr_name);
      return -1;
    }
    if (r1 != OSPK_REG) {
      plog(log_f, 0, "Test file %s is not a regular file", test_name);
      return -1;
    }
    if (r2 != OSPK_REG) {
      plog(log_f, 0, "Answer file %s is not a regular file", corr_name);
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
    perr(log_f, "Failed to read %s", name);
    goto fail;
  }
  if (text_is_binary(in_text, in_size)) {
    perr(log_f, "File %s is not a text file", name);
    goto fail;
  }
  out_size = text_normalize_buf(in_text, in_size,
                                TEXT_FIX_CR | TEXT_FIX_TR_SP
                                | TEXT_FIX_FINAL_NL | TEXT_FIX_TR_NL,
                                &out_count, &out_mask);
  (void) out_size;
  if (out_count) {
    snprintf(out_path, sizeof(out_path), "%s.tmp", path);
    if (!(out_f = fopen(out_path, "w"))) {
      perr(log_f, "Cannot open %s for writing", out_path);
      goto fail;
    }
    fprintf(out_f, "%s", in_text);
    if (fflush(out_f) < 0) {
      perr(log_f, "Write error to %s", out_path);
      goto fail;
    }
    fclose(out_f); out_f = 0;

    if (rename(out_path, path) < 0) {
      perr(log_f, "Rename %s -> %s failed", out_path, path);
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
    fflush(log_f);
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
        const struct super_run_in_packet *srp,
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

  if (srp->problem->binary_input > 0) return 0;

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
        const struct super_run_in_packet *srp,
        int num,
        const unsigned char *work_dir,
        const unsigned char *input_file,
        const unsigned char *output_file)
{
  tpTask tsk = 0;
  int i, r;

  const struct super_run_in_problem_packet *srpp = srp->problem;

  tsk = task_New();
  task_AddArg(tsk, test_checker_cmd);
  task_AddArg(tsk, input_file);
  task_AddArg(tsk, output_file);
  task_SetPathAsArg0(tsk);
  task_EnableAllSignals(tsk);
  if (work_dir) task_SetWorkingDir(tsk, work_dir);
  task_SetRedir(tsk, 0, TSR_FILE, input_file, TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  if (srpp->test_checker_env) {
    for (i = 0; srpp->test_checker_env[i]; ++i)
      task_PutEnv(tsk, srpp->test_checker_env[i]);
  }
  if (srpp->checker_real_time_limit_ms > 0) {
    task_SetMaxRealTimeMillis(tsk, srpp->checker_real_time_limit_ms);
  }
  if (srpp->checker_time_limit_ms > 0) {
    task_SetMaxTimeMillis(tsk, srpp->checker_time_limit_ms);
  }
  if (srpp->checker_max_stack_size > 0) {
    task_SetStackSize(tsk, srpp->checker_max_stack_size);
  }
  if (srpp->checker_max_vm_size > 0) {
    task_SetVMSize(tsk, srpp->checker_max_vm_size);
  }

  fflush(log_f);

  if (task_Start(tsk) < 0) {
    perr(log_f, "failed to start %s", test_checker_cmd);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  task_Wait(tsk);
  if (task_IsTimeout(tsk)) {
    perr(log_f, "test checker %s time-out on test %d", test_checker_cmd, num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  r = task_Status(tsk);
  if (r != TSK_EXITED && r != TSK_SIGNALED) {
    perr(log_f, "test checker %s invalid status on test %d",
         test_checker_cmd, num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  if (r == TSK_SIGNALED) {
    perr(log_f, "test checker %s is terminated by signal %d on test %d",
         test_checker_cmd, task_TermSignal(tsk), num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  r = task_ExitCode(tsk);
  if (r == 1) r = RUN_WRONG_ANSWER_ERR;
  if (r == 2) r = RUN_PRESENTATION_ERR;
  if (r != RUN_OK && r != RUN_COMPILE_ERR && r != RUN_PRESENTATION_ERR
      && r != RUN_WRONG_ANSWER_ERR && r != RUN_CHECK_FAILED) {
    perr(log_f, "test checker %s exit code %d invalid on test %d",
         test_checker_cmd, r, num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  if (r == RUN_CHECK_FAILED) {
    perr(log_f, "test checker %s reported CHECK_FAILED on test %d",
         test_checker_cmd, num);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  if (r == RUN_COMPILE_ERR || r == RUN_PRESENTATION_ERR) {
    plog(log_f, 0, "Test checker reports PRESENTATION ERROR on test %d", num);
    task_Delete(tsk);
    return RUN_PRESENTATION_ERR;
  }
  if (r == RUN_WRONG_ANSWER_ERR) {
    plog(log_f, 0, "Test checker report WRONG ANSWER ERROR on test %d", num);
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
        const struct super_run_in_packet *srp,
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

  const struct super_run_in_problem_packet *srpp = srp->problem;

  if (!srpp->test_checker_cmd || !srpp->test_checker_cmd[0])
    return 0;

  snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s", srpp->test_checker_cmd);

  if ((r = os_IsFile(test_checker_cmd)) < 0) {
    perr(log_f, "test checker %s does not exist", test_checker_cmd);
    return RUN_CHECK_FAILED;
  }
  if (r != OSPK_REG) {
    perr(log_f, "test checker %s is not a regular file", test_checker_cmd);
    return RUN_CHECK_FAILED;
  }
  if (os_CheckAccess(test_checker_cmd, REUSE_X_OK) < 0) {
    perr(log_f, "test checker %s is not an executable file", test_checker_cmd);
    return RUN_CHECK_FAILED;
  }

  for (num = 1; num <= test_count; ++num) {
    snprintf(test_name, sizeof(test_name), test_pat, num);
    snprintf(corr_name, sizeof(corr_name), corr_pat, num);
    snprintf(test_path, sizeof(test_path), "%s/%s", tests_dir, test_name);
    snprintf(corr_path, sizeof(corr_path), "%s/%s", tests_dir, corr_name);

    r = invoke_test_checker(log_f, log_path, test_checker_cmd, srp,
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
        const struct super_run_in_packet *srp,
        int num,
        const unsigned char *check_dir,
        const unsigned char *exe_path,
        const unsigned char *exe_name,
        const unsigned char *extra_suffix, // if some extra file to be copied, like .jar file
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

  const struct super_run_in_problem_packet *srpp = srp->problem;

  snprintf(check_exe, sizeof(check_exe), "%s/%s", check_dir, exe_name);
  snprintf(input_path, sizeof(input_path), "%s/%s", check_dir, srpp->input_file);
  snprintf(output_path, sizeof(output_path), "%s/%s", check_dir, srpp->output_file);

  time_limit_ms = srpp->time_limit_ms;

  clear_check_dir = 1;
  if (generic_copy_file(0, 0, exe_path, 0, 0, check_dir, exe_name, 0) < 0) {
    perr(log_f, "failed to copy %s to %s", exe_path, check_exe);
    goto cleanup;
  }
  if (extra_suffix) {
    if (generic_copy_file(0, 0, exe_path, extra_suffix, 0, check_dir, exe_name, extra_suffix) < 0) {
      perr(log_f, "failed to copy %s%s to %s", exe_path, extra_suffix, check_exe);
      goto cleanup;
    }
  }
  if (make_executable(check_exe) < 0) {
    perr(log_f, "failed to set executable bit on %s", check_exe);
    goto cleanup;
  }
  if (generic_copy_file(0, 0, input_file, 0, 0, check_dir,
                        srpp->input_file, 0) < 0) {
    perr(log_f, "failed to copy %s to %s", input_file, input_path);
    goto cleanup;
  }
  if (touch_file(output_path) < 0) {
    perr(log_f, "failed to create %s", output_path);
    goto cleanup;
  }

  tsk = task_New();
  task_AddArg(tsk, check_exe);
  task_SetPathAsArg0(tsk);
  task_SetWorkingDir(tsk, check_dir);
  if (srpp->combined_stdin > 0 || srpp->use_stdin > 0) {
    task_SetRedir(tsk, 0, TSR_FILE, input_path, TSK_READ, 0);
  } else {
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  }
  if (srpp->combined_stdout > 0 || srpp->use_stdout > 0) {
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
  if (srpp->real_time_limit_ms > 0) {
    task_SetMaxRealTimeMillis(tsk, srpp->real_time_limit_ms);
  }
  if (srpp->max_stack_size > 0) {
    task_SetStackSize(tsk, srpp->max_stack_size);
  }
  if (srpp->max_data_size > 0) {
    task_SetDataSize(tsk, srpp->max_data_size);
  }
  if (srpp->max_vm_size > 0) {
    task_SetVMSize(tsk, srpp->max_vm_size);
  }
  if (srpp->max_rss_size > 0) {
    task_SetRSSSize(tsk, srpp->max_rss_size);
  }
  /* no security restrictions and memory limits */
  if (task_Start(tsk) < 0) {
    perr(log_f, "failed to start %s on test %d", check_exe, num);
    goto cleanup;
  }

  task_Wait(tsk);
  tt_cell->time = task_GetRunningTime(tsk);
  tt_cell->real_time = task_GetRealTime(tsk);

  if (task_IsTimeout(tsk)) {
    plog(log_f, 0, "Program %s time-limit exceeded on test %d", exe_name, num);
    retval = RUN_TIME_LIMIT_ERR;
    goto cleanup;
  }
  r = task_Status(tsk);
  if (r != TSK_EXITED && r != TSK_SIGNALED) {
    perr(log_f, "program %s invalid status %d on test %d", exe_name, r, num);
    goto cleanup;
  }
  if (r == TSK_SIGNALED) {
    plog(log_f, 0, "Program %s terminated with signal %d on test %d",
         exe_name, task_TermSignal(tsk), num);
    retval = RUN_RUN_TIME_ERR;
    goto cleanup;
  }
  r = task_ExitCode(tsk);
  if (r != 0) {
    plog(log_f, 0, "Program %s exited with code %d on test %d",
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
        const struct super_run_in_packet *srp,
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

  const struct super_run_in_problem_packet *srpp = srp->problem;

  tsk = task_New();
  task_AddArg(tsk, check_cmd);
  task_SetPathAsArg0(tsk);
  task_SetWorkingDir(tsk, check_dir);
  task_AddArg(tsk, input_path);
  task_AddArg(tsk, output_path);
  task_AddArg(tsk, correct_path);
  if (srpp->checker_real_time_limit_ms > 0) {
    task_SetMaxRealTimeMillis(tsk, srpp->checker_real_time_limit_ms);
  }
  if (srpp->checker_time_limit_ms > 0) {
    task_SetMaxTimeMillis(tsk, srpp->checker_time_limit_ms);
  }
  if (srpp->checker_max_stack_size > 0) {
    task_SetStackSize(tsk, srpp->checker_max_stack_size);
  }
  if (srpp->checker_max_vm_size > 0) {
    task_SetVMSize(tsk, srpp->checker_max_vm_size);
  }
  if (srpp->checker_env) {
    for (i = 0; srpp->checker_env[i]; ++i)
      task_PutEnv(tsk, srpp->checker_env[i]);
  }
  task_EnableAllSignals(tsk);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);

  fflush(log_f);

  if (task_Start(tsk) < 0) {
    perr(log_f, "failed to start checker %s for %s on test %d",
         check_cmd, exe_name, num);
    goto cleanup;
  }
  task_Wait(tsk);
  r = task_Status(tsk);
  if (r != TSK_EXITED && r != TSK_SIGNALED) {
    perr(log_f, "invalid status of %s for %s on test %d",
         check_cmd, exe_name, num);
    goto cleanup;
  }
  if (task_IsTimeout(tsk)) {
    perr(log_f, "checker %s for %s timeout on test %d",
         check_cmd, exe_name, num);
    goto cleanup;
  }
  if (r == TSK_SIGNALED) {
    perr(log_f, "checker %s for %s terminated by signal %d on test %d",
         check_cmd, exe_name, task_TermSignal(tsk), num);
    goto cleanup;
  }
  r = task_ExitCode(tsk);
  if (r != RUN_OK && r != RUN_CHECK_FAILED && r != RUN_WRONG_ANSWER_ERR
      && r != RUN_PRESENTATION_ERR) {
    perr(log_f, "checker %s for %s invalid exit code %d on test %d",
         check_cmd, exe_name, r, num);
    goto cleanup;
  }
  if (r == RUN_CHECK_FAILED) {
    perr(log_f, "checker %s for %s status CHECK_FAILED on test %d",
         check_cmd, exe_name, num);
    r = RUN_PRESENTATION_ERR;
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
        const struct super_run_in_packet *srp,
        const unsigned char *check_dir,
        const unsigned char *exe_path,
        const unsigned char *exe_name,
        const unsigned char *extra_suffix,
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

  const struct super_run_in_problem_packet *srpp = srp->problem;

  /* no sense to continue if operation on the check_dir failed */
  if (make_writable(check_dir) < 0) {
    perr(log_f, "cannot make writable directory %s", check_dir);
    tt_row->status = RUN_CHECK_FAILED;
    return RUN_CHECK_FAILED;
  }
  if (clear_directory(check_dir) < 0) {
    perr(log_f, "failed to clean directory %s", check_dir);
    tt_row->status = RUN_CHECK_FAILED;
    return RUN_CHECK_FAILED;
  }

  snprintf(out_path, sizeof(out_path), "%s/%s", check_dir, srpp->output_file);

  for (num = 1; num <= test_count; ++num) {
    snprintf(test_name, sizeof(test_name), test_pat, num);
    snprintf(corr_name, sizeof(corr_name), corr_pat, num);
    snprintf(test_path, sizeof(test_path), "%s/%s", tests_dir, test_name);
    snprintf(corr_path, sizeof(corr_path), "%s/%s", tests_dir, corr_name);

    fprintf(log_f, "Starting %s on test %d\n", exe_name, num);
    fflush(log_f);

    r = invoke_test_program(log_f, log_path, srp, num, check_dir,
                            exe_path, exe_name, extra_suffix, test_path,
                            tt_cell_row[num - 1]);
    if (r == RUN_OK) {
      fprintf(log_f, "Starting checker %s\n", check_cmd);
      fflush(log_f);

      invoke_checker(log_f, log_path, srp, check_dir, check_cmd,
                     exe_name, num, test_path, out_path, corr_path,
                     tt_cell_row[num - 1]);
    }

    if (clear_directory(check_dir) < 0) {
      perr(log_f, "failed to clean directory %s", check_dir);
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

/* FIXME: move to a separate file? */
static int
parse_test_score_list(
        FILE *log_f,
        const unsigned char *pfx,
        const struct super_run_in_packet *srp,
        int test_count,
        int *test_scores)
{
  int i, j, v;
  char *eptr;
  const unsigned char *list_txt;

  const struct super_run_in_problem_packet *srpp = srp->problem;

  if (srpp->test_score < 0) {
    plog(log_f, pfx, "test_score %d < 0", srpp->test_score);
    return -1;
  }
  if (srpp->full_score < 0) {
    plog(log_f, pfx, "full_score %d < 0", srpp->full_score);
    return -1;
  }

  for (i = 0; i < test_count; ++i)
    test_scores[i] = srpp->test_score;

  if (!srpp->test_score_list || !srpp->test_score_list[0]) return 0;
  list_txt = srpp->test_score_list;

  j = 0; i = 0;
  while (1) {
    while (list_txt[j] && isspace(list_txt[j])) ++j;
    if (!list_txt[j]) {
      return 0;
    }
    if (list_txt[j] == '[') {
      ++j;
      while (list_txt[j] && isspace(list_txt[j])) ++j;
      if (!list_txt[j]) {
        plog(log_f, pfx, "index expected after '['");
        return -1;
      }
      errno = 0;
      v = strtol(list_txt + j, &eptr, 10);
      if (*eptr && !isspace(*eptr) && *eptr != ']') {
        plog(log_f, pfx, "garbage after index in \"%s\"", list_txt + j);
        return -1;
      }
      if (errno) {
        plog(log_f, pfx, "index is too big in \"%s\"", list_txt + j);
        return -1;
      }
      if (v < 1 || v > test_count) {
        plog(log_f, pfx, "index is out of range \"%s\"", list_txt + j);
        return -1;
      }
      i = v - 1;
      list_txt = (const unsigned char*) eptr;
      while (list_txt[j] && isspace(list_txt[j])) ++j;
      if (list_txt[j] != ']') {
        plog(log_f, pfx, "']' expected after index");
        return -1;
      }
      ++j;
      while (list_txt[j] && isspace(list_txt[j])) ++j;
    }

    errno = 0;
    v = strtol(list_txt + j, &eptr, 10);
    if (*eptr && !isspace(*eptr)) {
      plog(log_f, pfx, "garbage after score in \"%s\"", list_txt + j);
      return -1;
    }
    if (errno) {
      plog(log_f, pfx, "score is too big in \"%s\"", list_txt + j);
      return -1;
    }
    if (v < 0) {
      plog(log_f, pfx, "score < 0 in \"%s\"", list_txt + j);
      return -1;
    }
    if (v > srpp->full_score) {
      plog(log_f, pfx, "score > full_score in \"%s\"", list_txt + j);
      return -1;
    }
    list_txt = (const unsigned char*) eptr;
    test_scores[i++] = v;
  }

  for (i = 0, j = 0; i < test_count; ++i)
    j += test_scores[i];

  if (j > srpp->full_score) {
    plog(log_f, pfx, "summ of test scores > full_score");
    return -1;
  }
}

static void
analyze_results(
        FILE *log_f,
        const unsigned char *log_path,
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        testing_report_xml_t report_xml)
{
  int i, j, score = 0;
  int status = RUN_CHECK_FAILED;
  int failed_test = 0;
  int *test_scores = 0;
  int passed_count = 0;

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  if (!report_xml->tt_rows) {
    perr(log_f, "tt_rows == NULL");
    goto done;
  }
  if (!report_xml->tt_cells) {
    perr(log_f, "tt_cells == NULL");
    goto done;
  }

  for (i = 0; i < report_xml->tt_row_count; ++i) {
    if (!report_xml->tt_rows[i]) {
      perr(log_f, "tt_rows[%d] == NULL", i);
      goto done;
    }
    if (!report_xml->tt_cells[i]) {
      perr(log_f, "tt_cells[%d] == NULL", i);
      goto done;
    }
    if (report_xml->tt_rows[i]->status == RUN_CHECK_FAILED) {
      goto done;
    }
    for (j = 0; j < report_xml->tt_column_count; ++j) {
      if (!report_xml->tt_cells[i][j]) {
        perr(log_f, "tt_cells[%d][%d] == NULL", i, j);
        goto done;
      }
      if (report_xml->tt_cells[i][j]->status == RUN_CHECK_FAILED) {
        goto done;
      }
    }
  }

  if (srgp->scoring_system_val == SCORE_OLYMPIAD && srgp->accepting_mode) {
    perr(log_f, "OLYMPIAD accepting mode is not supported");
    goto done;
  } else if (srgp->scoring_system_val == SCORE_KIROV
             || srgp->scoring_system_val == SCORE_OLYMPIAD) {
    XCALLOC(test_scores, report_xml->tt_row_count);
    if (parse_test_score_list(log_f, NULL, srp, report_xml->tt_row_count,
                              test_scores) < 0) {
      goto done;
    }

    /* FIXME: support test_sets and valuer_cmd */
    status = RUN_OK;
    for (i = 0; i < report_xml->tt_row_count; ++i) {
      if (report_xml->tt_rows[i]->must_fail <= 0) {
        // this sample program must be OK
        if (report_xml->tt_rows[i]->status != RUN_OK) {
          status = RUN_PARTIAL;
        } else {
          passed_count++;
          score += test_scores[i];
        }
      } else {
        // this sample program must fail
        if (report_xml->tt_rows[i]->status == RUN_OK) {
          status = RUN_PARTIAL;
        } else {
          passed_count++;
          score += test_scores[i];
        }
      }
    }
    if (status == RUN_OK && srpp->variable_full_score <= 0) {
      score = srpp->full_score;
    }
    failed_test = passed_count + 1;
  } else if (srgp->scoring_system_val == SCORE_MOSCOW) {
    if (srpp->full_score <= 0) {
      perr(log_f, "full_score must be > 0 in MOSCOW mode");
      goto done;
    }
    test_scores = prepare_parse_score_tests(srpp->score_tests, srpp->full_score);
    if (!test_scores) {
      perr(log_f, "invalid score_tests");
      goto done;
    }
    test_scores[srpp->full_score - 1] = report_xml->tt_row_count + 1;
    for (i = 0; i < report_xml->tt_row_count; ++i) {
      if (report_xml->tt_rows[i]->must_fail <= 0) {
        // this sample program must be OK
        if (report_xml->tt_rows[i]->status != RUN_OK) {
          status = RUN_WRONG_ANSWER_ERR;
          failed_test = i + 1;
          break;
        }
      } else {
        // this sample program must fail
        if (report_xml->tt_rows[i]->status == RUN_OK) {
          status = RUN_WRONG_ANSWER_ERR;
          failed_test = i + 1;
          break;
        }
      }
    }
    if (failed_test <= 0) {
      status = RUN_OK;
      score = srpp->full_score;
    } else {
      for (i = 0; failed_test > test_scores[i]; i++);
      score = i;
    }
  } else if (srgp->scoring_system_val == SCORE_ACM) {
    // just check that all the tests are passed
    for (i = 0; i < report_xml->tt_row_count; ++i) {
      if (report_xml->tt_rows[i]->must_fail <= 0) {
        // this sample program must be OK
        if (report_xml->tt_rows[i]->status != RUN_OK) {
          status = RUN_WRONG_ANSWER_ERR;
          failed_test = i + 1;
          goto done;
        }
      } else {
        // this sample program must fail
        if (report_xml->tt_rows[i]->status == RUN_OK) {
          status = RUN_WRONG_ANSWER_ERR;
          failed_test = i + 1;
          goto done;
        }
      }
    }
    status = RUN_OK;
  } else {
    abort();
  }

done:
  report_xml->failed_test = failed_test;
  reply_pkt->failed_test = failed_test;
  report_xml->score = score;
  reply_pkt->score = score;
  report_xml->status = status;
  reply_pkt->status = status;

  xfree(test_scores);
  return;
}

void
run_inverse_testing(
        struct serve_state *state,
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        const unsigned char *pkt_name,
        const unsigned char *run_exe_dir,
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
  path_t extra_path;
  path_t log_path;
  FILE *log_f = 0;
  unsigned char *log_text = 0;
  size_t log_size = 0;
  struct testing_report_cell ***tt_cells = 0, *tt_cell = 0;
  struct testing_report_row **tt_rows = 0, *tt_row = 0;
  int tt_row_count = 0;
  path_t check_cmd = { 0 };
  path_t check_dir = { 0 };
  testing_report_xml_t report_xml = 0;
  long time_limit_ms = 0;
  int (*unpack_func)(
        FILE *log_f,
        const unsigned char *log_path,
        const unsigned char *arch_path,
        const unsigned char *work_dir) = 0;
  ssize_t ssize;
  const unsigned char *arch_sfx = NULL;
  const unsigned char *extra_suffix = NULL;

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  unsigned char *cpu_model = NULL;
  unsigned char *cpu_mhz = NULL;

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
  reply_pkt->judge_id = srgp->judge_id;
  reply_pkt->contest_id = srgp->contest_id;
  reply_pkt->run_id = srgp->run_id;
  reply_pkt->notify_flag = srgp->notify_flag;
  reply_pkt->failed_test = 0;
  reply_pkt->marked_flag = 0;
  reply_pkt->status = RUN_CHECK_FAILED;
  reply_pkt->score = 0;
  reply_pkt->user_status = -1;
  reply_pkt->user_tests_passed = -1;
  reply_pkt->user_score = -1;
  reply_pkt->ts1 = srgp->ts1;
  reply_pkt->ts1_us = srgp->ts1_us;
  reply_pkt->ts2 = srgp->ts2;
  reply_pkt->ts2_us = srgp->ts2_us;
  reply_pkt->ts3 = srgp->ts3;
  reply_pkt->ts3_us = srgp->ts3_us;
  reply_pkt->ts4 = srgp->ts4;
  reply_pkt->ts4_us = srgp->ts4_us;
  if (srgp->run_uuid && srgp->run_uuid[0]) {
    ej_uuid_parse(srgp->run_uuid, &reply_pkt->uuid);
  }
  if (srgp->judge_uuid && srgp->judge_uuid[0]) {
    ej_uuid_parse(srgp->judge_uuid, &reply_pkt->judge_uuid);
  }
  get_current_time(&reply_pkt->ts5, &reply_pkt->ts5_us);

  /* create the testing report */
  report_xml = testing_report_alloc(srgp->contest_id, reply_pkt->run_id, reply_pkt->judge_id, &reply_pkt->judge_uuid);
  report_xml->status = RUN_CHECK_FAILED;
  report_xml->scoring_system = srgp->scoring_system_val;
  report_xml->archive_available = 0;
  report_xml->correct_available = 1;
  report_xml->info_available = 0;
  report_xml->real_time_available = 1;
  report_xml->max_memory_used_available = 0;
  report_xml->run_tests = 0;
  report_xml->variant = srgp->variant;
  report_xml->accepting_mode = 0;
  report_xml->failed_test = -1;
  report_xml->tests_passed = 0;
  report_xml->score = 0;
  report_xml->max_score = srpp->full_score;
  report_xml->marked_flag = 0;
  report_xml->tests_mode = 1;

  time_limit_ms = srpp->time_limit_ms;
  if (time_limit_ms > 0) {
    report_xml->time_limit_ms = time_limit_ms;
  }
  if (srpp->real_time_limit_ms > 0) {
    report_xml->real_time_limit_ms = srpp->real_time_limit_ms;
  }
  if ((log_text = os_NodeName())) {
    report_xml->host = xstrdup(log_text);
  }
  log_text = 0;
  cpu_get_performance_info(&cpu_model, &cpu_mhz);
  report_xml->cpu_model = cpu_model; cpu_model = NULL;
  report_xml->cpu_mhz = cpu_mhz; cpu_mhz = NULL;

  snprintf(report_path, report_path_size, "%s/%s.xml",
           global->run_work_dir, pkt_name);

  switch (srgp->mime_type) {
  case MIME_TYPE_APPL_GZIP:
    unpack_func = invoke_tar;
    arch_sfx = ".tar.gz";
    break;
  case MIME_TYPE_APPL_BZIP2:
    unpack_func = invoke_tar;
    arch_sfx = ".tar.bz2";
    break;
  case MIME_TYPE_APPL_COMPRESS:
    unpack_func = invoke_tar;
    arch_sfx = ".tar.Z";
    break;
  case MIME_TYPE_APPL_TAR:
    unpack_func = invoke_tar;
    arch_sfx = ".tar";
    break;

  case MIME_TYPE_APPL_ZIP:
    unpack_func = invoke_zip;
    arch_sfx = ".zip";
    break;

  default:
    perr(log_f, "archive of type %d (%s) is not supported",
         srgp->mime_type, mime_type_get_type(srgp->mime_type));
    goto cleanup;
  }

  r = generic_copy_file(REMOVE, run_exe_dir, pkt_name, srgp->exe_sfx,
                        0, global->run_work_dir, pkt_name, arch_sfx);
  if (r <= 0) {
    perr(log_f, "failed to read archive file %s/%s%s",
         global->run_work_dir, pkt_name, arch_sfx);
    goto cleanup;
  }

  snprintf(arch_path, sizeof(arch_path), "%s/%s%s",
           global->run_work_dir, pkt_name, arch_sfx);

  snprintf(arch_dir,sizeof(arch_dir), "%s/%s", global->run_work_dir, pkt_name);
  if (make_dir(arch_dir, 0) < 0) {
    perr(log_f, "failed to create directory %s/%s",
         global->run_work_dir, pkt_name);
    goto cleanup;
  }

  // invoke tar
  if (unpack_func(log_f, log_path, arch_path, arch_dir) < 0) {
    perr(log_f, "archive extraction failed on file %s in dir %s",
         arch_path, arch_dir);
    goto cleanup;
  }

  snprintf(tests_dir, sizeof(tests_dir), "%s/%s", arch_dir, "tests");
  r = os_IsFile(tests_dir);
  if (r < 0) {
    perr(log_f, "directory %s does not exist", tests_dir);
    goto presentation_error;
  } else if (r != OSPK_DIR) {
    perr(log_f, "%s is not a directory", tests_dir);
    goto presentation_error;
  }

  // count tests
  test_count = count_tests(log_f, tests_dir, srpp->test_pat, srpp->corr_pat);
  if (test_count < 0) {
    perr(log_f, "failed to count tests in %s", tests_dir);
    goto cleanup;
  }
  if (!test_count) {
    perr(log_f, "no tests in the archive");
    goto presentation_error;
  }

  // normalize test contents
  if (normalize_tests(log_f, srp, test_count, tests_dir, srpp->test_pat,
                      srpp->corr_pat) < 0) {
    perr(log_f, "failed to normalize tests");
    goto presentation_error;
  }

  // invoke test checkers on each test
  r = invoke_test_checker_on_tests(log_f, log_path, srp, srgp->variant,
                                   test_count, tests_dir,
                                   srpp->test_pat, srpp->corr_pat);
  if (r != RUN_OK) {
    reply_pkt->status = r;
    report_xml->status = r;
    goto cleanup;
  }

  snprintf(sample_dir, sizeof(sample_dir), "%s", srpp->test_dir);
  snprintf(good_dir, sizeof(good_dir), "%s/%s", sample_dir, GOOD_DIR_NAME);
  snprintf(fail_dir, sizeof(fail_dir), "%s/%s", sample_dir, FAIL_DIR_NAME);

  if (scan_executable_files(good_dir, &good_count, &good_files) < 0) {
    perr(log_f, "scan of %s failed", good_dir);
    goto cleanup;
  }
  if (scan_executable_files(fail_dir, &fail_count, &fail_files) < 0) {
    perr(log_f, "scan of %s failed", good_dir);
    goto cleanup;
  }
  if (good_count <= 0 && fail_count <= 0) {
    perr(log_f, "no sample programs are found");
    goto cleanup;
  }

  if (srpp->standard_checker && srpp->standard_checker[0]) {
    snprintf(check_cmd, sizeof(check_cmd), "%s/%s",
             global->ejudge_checkers_dir, srpp->standard_checker);
  } else {
    snprintf(check_cmd, sizeof(check_cmd), "%s", srpp->check_cmd);
  }

  r = os_IsFile(check_cmd);
  if (r < 0) {
    perr(log_f, "checker %s does not exist", check_cmd);
    goto cleanup;
  }
  if (r != OSPK_REG) {
    perr(log_f, "checker %s is not a regular file", check_cmd);
    goto cleanup;
  }
  if (os_CheckAccess(check_cmd, REUSE_X_OK) < 0) {
    perr(log_f, "checker %s is not an executable file", check_cmd);
    goto cleanup;
  }

  snprintf(check_dir, sizeof(check_dir), "%s", global->run_check_dir);
#if defined EJUDGE_LOCAL_DIR
  pathmake2(check_dir, EJUDGE_LOCAL_DIR, "/", check_dir, NULL);
#endif
  pathmake2(check_dir, EJUDGE_CONTESTS_HOME_DIR, "/", check_dir, NULL);
  if (make_dir(check_dir, 0) < 0) {
    perr(log_f, "failed to create directory %s", check_dir);
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
    extra_suffix = NULL;
    snprintf(exe_path, sizeof(exe_path), "%s/%s", good_dir, good_files[i]);
    // check for .jar addition
    snprintf(extra_path, sizeof(extra_path), "%s.jar", exe_path);
    if (os_CheckAccess(extra_path, REUSE_R_OK) >= 0) {
      extra_suffix = ".jar";
    }
    r = invoke_sample_program(log_f, log_path, srp, check_dir,
                              exe_path, good_files[i], extra_suffix, check_cmd, test_count,
                              tests_dir, srpp->test_pat, srpp->corr_pat,
                              report_xml->tt_rows[i], report_xml->tt_cells[i]);
  }
  for (i = 0; i < fail_count; ++i) {
    extra_suffix = NULL;
    snprintf(exe_path, sizeof(exe_path), "%s/%s", fail_dir, fail_files[i]);
    // check for .jar addition
    snprintf(extra_path, sizeof(extra_path), "%s.jar", exe_path);
    if (os_CheckAccess(extra_path, REUSE_R_OK) >= 0) {
      extra_suffix = ".jar";
    }
    r = invoke_sample_program(log_f, log_path, srp, check_dir,
                              exe_path, fail_files[i], extra_suffix, check_cmd, test_count,
                              tests_dir, srpp->test_pat, srpp->corr_pat,
                              report_xml->tt_rows[i + good_count],
                              report_xml->tt_cells[i + good_count]);
  }

  analyze_results(log_f, log_path, srp, reply_pkt, report_xml);

cleanup:
  /* process the log file */
  fclose(log_f); log_f = 0;

  ssize = generic_file_size(NULL, log_path, NULL);
  if (ssize < 0) {
    log_text = xstrdup("Error: log file does not exist\n");
    log_size = strlen(log_text);
  } else if (ssize > MAX_LOG_FILE_SIZE) {
    log_text = xstrdup("Error: log file is too large\n");
    log_size = strlen(log_text);
  } else if (text_read_file(log_path, 1, &log_text, &log_size) < 0) {
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

  if (srgp->bson_available && testing_report_bson_available()) {
    if (testing_report_to_file_bson(report_path, report_xml) < 0) {
    }
  } else {
    if (testing_report_to_file(report_path, utf8_mode, report_xml) < 0) {
      // too late to report error
      //perr("run_inverse_testing: failed to save file '%s'", report_path);
    }
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
  xfree(cpu_model);
  xfree(cpu_mhz);

  //clear_directory(global->run_work_dir);
  return;

presentation_error:
  report_xml->status = RUN_PRESENTATION_ERR;
  reply_pkt->status = RUN_PRESENTATION_ERR;
  goto cleanup;
}
