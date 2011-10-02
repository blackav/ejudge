/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2006-2011 Alexander Chernov <cher@ejudge.ru> */

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
#include "version.h"

#include "testinfo.h"

#include "reuse_xalloc.h"
#include "reuse_exec.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <grp.h>

#define DEFAULT_INPUT_FILE_NAME  "input.txt"
#define DEFAULT_OUTPUT_FILE_NAME "output.txt"
#define DEFAULT_ERROR_FILE_NAME  "error.txt"

enum
{
  RUN_OK               = 0,
  RUN_COMPILE_ERR      = 1,
  RUN_RUN_TIME_ERR     = 2,
  RUN_TIME_LIMIT_ERR   = 3,
  RUN_PRESENTATION_ERR = 4,
  RUN_WRONG_ANSWER_ERR = 5,
  RUN_CHECK_FAILED     = 6,
  RUN_PARTIAL          = 7,
  RUN_ACCEPTED         = 8,
  RUN_IGNORED          = 9,
  RUN_DISQUALIFIED     = 10,
  RUN_PENDING          = 11,
  RUN_MEM_LIMIT_ERR    = 12,
  RUN_SECURITY_ERR     = 13,
  RUN_STYLE_ERR        = 14,
};

static const unsigned char *progname;

static void
fatal(const char *format, ...)
{
  unsigned char buf[512];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", progname, buf);
  exit(2);
}

static const unsigned char *stdin_file = 0;
static const unsigned char *stdout_file = 0;
static const unsigned char *stderr_file = 0;
static const unsigned char *working_dir = 0;
static const unsigned char *kill_signal = 0;
static const unsigned char *test_file = 0;
static const unsigned char *corr_file = 0;
static const unsigned char *info_file = 0;
static const unsigned char *input_file = 0;
static const unsigned char *output_file = 0;
static const unsigned char *error_file = 0;
static const unsigned char *test_pattern = 0;
static const unsigned char *corr_pattern = 0;
static const unsigned char *info_pattern = 0;

static strarray_t env_vars;

static int clear_env_flag = 0;
static int no_core_dump = 0;
static int memory_limit = 0;
static int secure_exec = 0;
static int security_violation = 0;
static int use_stdin = 0;
static int use_stdout = 0;
static int group = -1;
static int mode = -1;
static int test_num = 0;
static int quiet_flag = 0;

static int time_limit = 0;
static int time_limit_millis = 0;
static int real_time_limit = 0;

static long long max_vm_size = 0;
static long long max_stack_size = 0;
static long long max_data_size = 0;

static void
parse_int(const unsigned char *name, const unsigned char *opt, int *pval,
          int minval, int maxval)
{
  int n, v;

  if (sscanf(opt, "%d%n", &v, &n) != 1 || opt[n]
      || v < minval || v > maxval)
    fatal("invalid value for option %s", name);
  *pval = v;
}

static void
parse_size(const unsigned char *name, const unsigned char *opt,
           long long *pval, long long minval, long long maxval)
{
  int n;
  long long v;

  if (sscanf(opt, "%lld%n", &v, &n) != 1 || v < 0) goto invalid_value;
  if (toupper(opt[n]) == 'K') {
    if ((v & 0xffe0000000000000LL)) goto invalid_value;
    v <<= 10;
    n++;
  } else if (toupper(opt[n]) == 'M') {
    if ((v & 0xfffff80000000000LL)) goto invalid_value;
    v <<= 20;
    n++;
  } else if (toupper(opt[n]) == 'G') {
    if ((v & 0xfffffffe00000000LL)) goto invalid_value;
    v <<= 30;
    n++;
  }
  if (opt[n]) goto invalid_value;
  if (v < minval || v > maxval) goto invalid_value;
  *pval = v;
  return;

 invalid_value:
  fatal("invalid value for option %s", name);
}

static void
parse_mode(const unsigned char *name, const unsigned char *opt, int *pval)
{
  char *eptr = NULL;
  int val = 0;

  errno = 0;
  val = strtol(opt, &eptr, 8);
  if (errno || val <= 0 || val > 07777) fatal("invalid value for option %s", name);
  *pval = val;
}

static void
parse_group(const unsigned char *name, const unsigned char *opt, int *pval)
{
  struct group *grp = getgrnam(opt);
  if (!grp || grp->gr_gid <= 0) fatal("invalid group for option %s", name);
  *pval = grp->gr_gid;
}

static void
report_version(void)
{
  printf("%s: ejudge version %s compiled %s\n",
         progname, compile_version, compile_date);
  exit(0);
}

static const unsigned char help_str[] =
"--version                print the version and exit\n"
"--help                   print this help and exit\n"
"--                       stop option processing\n"
"--stdin=FILE             redirect standard input stream from FILE\n"
"--stdout=FILE            redirect standard output stream to FILE\n"
"--stderr=FILE            redirect standard error stream to FILE\n"
"--use-stdin              redirect standard input\n"
"--use-stdout             redirect standard output\n"
"--test-file=FILE         get the input from FILE\n"
"--corr-file=FILE         move the output to FILE\n"
"--info-file=FILE         get the command line parameters from FILE\n"
"--input-file=FILE        move the input file to FILE\n"
"--output-file=FILE       expect the output to be in FILE\n"
"--workdir=DIR            set the working directory to DIR\n"
"--clear-env              clear all environment\n"
"--env=VAR=VALUE          set the environment VAR to VALUE\n"
"--time-limit=SEC         set the time limit to SEC seconds\n"
"--time-limit-millis=MSEC set the time limit to MSEC milliseconds\n"
"--real-time-limit=SEC    set the real time limit to SEC seconds\n"
"--no-core-dump           disable core dump\n"
"--kill-signal=SIGNAL     specify the termination signal (kill, term, intr)\n"
"--memory-limit           enable memory limit error detection\n"
"--secure-exec            enable secure execution\n"
"--security-violation     enable security violation error detection\n"
"--max-vm-size=SIZE       specify the virtual memory size limit\n"
"--max-stack-size=SIZE    specify the stack size limit\n"
"--max-data-size=SIZE     specify the heap size limit\n"
"--mode=MODE              file mode for output file\n"
"--group=GROUP            file group for output file\n"
"--test-num=NUM           test number\n"
"--test-pattern=PATTERN   printf-style patter for test files\n"
"--corr-pattern=PATTERN   printf-style patter for corr files\n"
"--info-pattern=PATTERN   printf-style patter for info files\n"
"--quiet                  be quiet\n"
  ;

static void
report_help(void)
{
  printf("%s usage: execute [OPTIONS]... program [ARGUMENTS]...\n", progname);
  fputs(help_str, stdout);
  exit(0);
}

static int
copy_file(
        const unsigned char *src_dir,
        const unsigned char *src_file,
        const unsigned char *dst_dir,
        const unsigned char *dst_file,
        int group,
        int mode)
{
  unsigned char src_path[PATH_MAX];
  unsigned char dst_path[PATH_MAX];
  int fdr = -1;
  int fdw = -1;
  unsigned char buf[4096], *p;
  int unlink_dst_flag = 0, r, w;

  if (src_dir && src_dir[0]) {
    snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, src_file);
  } else {
    snprintf(src_path, sizeof(src_path), "%s", src_file);
  }

  if (dst_dir && dst_dir[0]) {
    snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, dst_file);
  } else {
    snprintf(dst_path, sizeof(dst_path), "%s", dst_file);
  }

  if ((fdr = open(src_path, O_RDONLY, 0)) < 0) {
    fprintf(stderr, "read open failed for %s: %s\n", src_path, strerror(errno));
    goto fail;
  }
  if ((fdw = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
    if (errno != EACCES) {
      fprintf(stderr, "write open failed for %s: %s\n", dst_path, strerror(errno));
      goto fail;
    }
    unlink(dst_path);
    if ((fdw = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0666)) < 0) {
      fprintf(stderr, "write open failed for %s: %s\n", dst_path, strerror(errno));
      goto fail;
    }
  }

  unlink_dst_flag = 1;

  while ((r = read(fdr, buf, sizeof(buf))) > 0) {
    p = buf;
    while (r > 0) {
      if ((w = write(fdw, p, r)) <= 0) {
        fprintf(stderr, "write error for %s: %s\n", dst_path, strerror(errno));
        goto fail;
      }
      p += w; r -= w;
    }
  }
  if (r < 0) {
    fprintf(stderr, "read error for %s: %s\n", src_path, strerror(errno));
    goto fail;
  }

  if (group > 0) fchown(fdw, -1, group);
  if (mode > 0) fchmod(fdw, mode);

  close(fdw); fdw = -1;
  close(fdr); fdr = -1;
  return 0;

fail:
  if (unlink_dst_flag) unlink(dst_path);
  if (fdw >= 0) close(fdw);
  if (fdr >= 0) close(fdr);
  return -1;
}

const unsigned char *
check_option(const unsigned char *opt_name, const unsigned char *opt)
{
  int opt_len = strlen(opt_name);
  if (strncmp(opt_name, opt, opt_len) != 0) return NULL;
  if (opt[opt_len] != '=') return NULL;
  return opt + opt_len + 1;
}

static int
handle_options(const unsigned char *opt)
{
  const unsigned char *n = NULL, *p;

  if (!strcmp("--version", opt)) {
    report_version();
  } else if (!strcmp("--help", opt)) {
    report_help();
  } else if ((p = check_option("--stdin", opt))) {
    stdin_file = p;
  } else if ((p = check_option("--stdout", opt))) {
    stdout_file = p;
  } else if ((p = check_option("--stderr", opt))) {
    stderr_file = p;
  } else if ((p = check_option("--workdir", opt))) {
    working_dir = p;
  } else if ((p = check_option("--test-file", opt))) {
    test_file = p;
  } else if ((p = check_option("--corr-file", opt))) {
    corr_file = p;
  } else if ((p = check_option("--info-file", opt))) {
    info_file = p;
  } else if ((p = check_option("--input_file", opt))) {
    input_file = p;
  } else if ((p = check_option("--output-file", opt))) {
    output_file = p;
  } else if (!strcmp("--clear-env", opt)) {
    clear_env_flag = 1;
  } else if ((p = check_option("--env", opt))) {
    xexpand(&env_vars);
    env_vars.v[env_vars.u++] = xstrdup(p);
  } else if ((p = check_option((n = "--time-limit"), opt))) {
    parse_int(n, p, &time_limit, 1, 99999);
  } else if ((p = check_option((n = "--time-limit-millis"), opt))) {
    parse_int(n, p, &time_limit_millis, 1, 999999999);
  } else if ((p = check_option((n = "--real-time-limit"), opt))) {
    parse_int(n, p, &real_time_limit, 1, 99999);
  } else if (!strcmp("--no-core-dump", opt)) {
    no_core_dump = 1;
  } else if ((p = check_option("--kill-signal", opt))) {
    kill_signal = p;
  } else if (!strcmp("--memory-limit", opt)) {
    memory_limit = 1;
  } else if (!strcmp("--secure-exec", opt)) {
    secure_exec = 1;
  } else if (!strcmp("--security-violation", opt)) {
    security_violation = 1;
  } else if (!strcmp("--use-stdin", opt)) {
    use_stdin = 1;
  } else if (!strcmp("--use-stdout", opt)) {
    use_stdout = 1;
  } else if ((p = check_option((n = "--max-vm-size"), opt))) {
    parse_size(n, p, &max_vm_size, 4096, 1 << 30);
  } else if ((p = check_option((n = "--max-stack-size"), opt))) {
    parse_size(n, p, &max_stack_size, 4096, 1 << 30);
  } else if ((p = check_option((n = "--max-data-size"), opt))) {
    parse_size(n, p, &max_data_size, 4096, 1 << 30);
  } else if ((p = check_option((n = "--mode"), opt))) {
    parse_mode(n, p, &mode);
  } else if ((p = check_option((n = "--group"), opt))) {
    parse_group(n, p, &group);
  } else if ((p = check_option((n = "--test-num"), opt))) {
    parse_int(n, p, &test_num, 1, 99999);
  } else if ((p = check_option("--test-pattern", opt))) {
    test_pattern = p;
  } else if ((p = check_option("--corr-pattern", opt))) {
    corr_pattern = p;
  } else if ((p = check_option("--info-pattern", opt))) {
    info_pattern = p;
  } else if (!strcmp("--quiet", opt)) {
    quiet_flag = 1;
  } else if (!strcmp("--", opt)) {
    return 1;
  } else if (!strncmp("--", opt, 2)) {
    fatal("invalid option %s");
  } else {
    return 2;
  }
  return 0;
}

static int
run_program(int argc, char *argv[])
{
  tTask *tsk = 0;
  int i;
  int retcode = RUN_CHECK_FAILED;
  struct testinfo_struct tinfo;
  unsigned char input_path[PATH_MAX];
  unsigned char output_path[PATH_MAX];
  unsigned char error_path[PATH_MAX];
  unsigned char buf[1024];

  memset(&tinfo, 0, sizeof(tinfo));
  input_path[0] = 0;
  output_path[0] = 0;
  error_path[0] = 0;

  if (test_num > 0) {
    if (test_pattern && test_pattern[0]) {
      snprintf(buf, sizeof(buf), test_pattern, test_num);
      test_file = strdup(buf);
    }
    if (corr_pattern && corr_pattern[0]) {
      snprintf(buf, sizeof(buf), corr_pattern, test_num);
      corr_file = strdup(buf);
    }
    if (info_pattern && info_pattern[0]) {
      snprintf(buf, sizeof(buf), info_pattern, test_num);
      info_file = strdup(buf);
    }
  }

  if (info_file && (i = testinfo_parse(info_file, &tinfo)) < 0) {
    fatal("testinfo file parse error: %s", testinfo_strerror(-i));
  }

  if (test_file) {
    if (!input_file || !input_file[0]) input_file = DEFAULT_INPUT_FILE_NAME;
    if (working_dir && working_dir[0]) {
      snprintf(input_path, sizeof(input_path), "%s/%s", working_dir, input_file);
    } else {
      snprintf(input_path, sizeof(input_path), "%s", input_file);
    }
  }

  if (corr_file) {
    if (!output_file || !output_file[0]) output_file = DEFAULT_OUTPUT_FILE_NAME;
    if (working_dir && working_dir[0]) {
      snprintf(output_path, sizeof(output_path), "%s/%s", working_dir, output_file);
    } else {
      snprintf(output_path, sizeof(output_path), "%s", output_file);
    }
  }

  if (info_file && tinfo.check_stderr > 0) {
    error_file = DEFAULT_ERROR_FILE_NAME;
    if (working_dir && working_dir[0]) {
      snprintf(error_path, sizeof(error_path), "%s/%s", working_dir, error_file);
    } else {
      snprintf(error_path, sizeof(error_path), "%s", error_file);
    }
  }

  if (!(tsk = task_New())) fatal("cannot create task");
  task_SetQuietFlag(tsk);
  task_pnAddArgs(tsk, argc, argv);
  task_pnAddArgs(tsk, tinfo.cmd_argc, tinfo.cmd_argv);
  task_SetPathAsArg0(tsk);
  if (working_dir) task_SetWorkingDir(tsk, working_dir);
  if (test_file) {
    if (copy_file(NULL, test_file, working_dir, input_file, -1, -1) < 0)
      fatal("copy failed");
    if (use_stdin) task_SetRedir(tsk, 0, TSR_FILE, input_path, TSK_READ);
  } else {
    if (stdin_file) task_SetRedir(tsk, 0, TSR_FILE, stdin_file, TSK_READ);
  }
  if (corr_file) {
    if (use_stdout) task_SetRedir(tsk, 1, TSR_FILE, output_path, TSK_REWRITE, TSK_FULL_RW);
  } else {
    if (stdout_file)
      task_SetRedir(tsk, 1, TSR_FILE, stdout_file, TSK_REWRITE, TSK_FULL_RW);
  }
  if (info_file && tinfo.check_stderr > 0) {
    task_SetRedir(tsk, 2, TSR_FILE, error_path, TSK_REWRITE, TSK_FULL_RW);
  } else {
    if (stderr_file)
      task_SetRedir(tsk, 2, TSR_FILE, stderr_file, TSK_REWRITE, TSK_FULL_RW);
  }
  if (clear_env_flag) task_ClearEnv(tsk);
  for (i = 0; i < env_vars.u; i++)
    task_PutEnv(tsk, env_vars.v[i]);
  for (i = 0; i < tinfo.env_u; ++i) {
    task_PutEnv(tsk, tinfo.env_v[i]);
  }
  if (time_limit_millis > 0)
    if (task_SetMaxTimeMillis(tsk, time_limit_millis) < 0)
      fatal("--time-limit-millis is not supported");
  if (time_limit > 0) task_SetMaxTime(tsk, time_limit);
  if (real_time_limit > 0) task_SetMaxRealTime(tsk, real_time_limit);
  if (kill_signal)
    if (task_SetKillSignal(tsk, kill_signal) < 0)
      fatal("invalid value for --kill-signal option");
  if (no_core_dump) task_DisableCoreDump(tsk);
  if (max_vm_size) task_SetVMSize(tsk, max_vm_size);
  if (max_stack_size) task_SetStackSize(tsk, max_stack_size);
  if (max_data_size) task_SetDataSize(tsk, max_data_size);
  if (memory_limit)
    if (task_EnableMemoryLimitError(tsk) < 0)
      fatal("--memory-limit is not supported");
  if (secure_exec)
    if (task_EnableSecureExec(tsk) < 0)
      fatal("--secure-exec is not supported");
  if (security_violation)
    if (task_EnableSecurityViolationError(tsk) < 0)
      fatal("--security-violation is not supported");

  if (task_Start(tsk) < 0) {
    fprintf(stderr, "Status: CF\n"
            "Description: cannot start task: %s\n", task_GetErrorMessage(tsk));
    retcode = RUN_CHECK_FAILED;
    goto cleanup;
  }
  task_Wait(tsk);
  if (memory_limit && task_IsMemoryLimit(tsk)) {
    fprintf(stderr, "Status: ML\n"
            "Description: memory limit exceeded\n");
    retcode = RUN_MEM_LIMIT_ERR;
  } else if (security_violation && task_IsSecurityViolation(tsk)) {
    fprintf(stderr, "Status: SV\n"
            "Description: security violation\n");
    retcode = RUN_SECURITY_ERR;
  } else if (task_IsTimeout(tsk)) {
    fprintf(stderr, "Status: TL\n"
            "Description: time limit exceeded\n");
    retcode = RUN_TIME_LIMIT_ERR;
  } else if (task_IsAbnormal(tsk)
             && (!info_file || tinfo.exit_code <= 0 || task_Status(tsk) != TSK_EXITED
                 || task_ExitCode(tsk) != tinfo.exit_code)) {
    fprintf(stderr, "Status: RT\n");
    if (task_Status(tsk) == TSK_SIGNALED) {
      fprintf(stderr, "Signal: %d\n", task_TermSignal(tsk));
    } else {
      fprintf(stderr, "Exitcode: %d\n", task_ExitCode(tsk));
    }
    fprintf(stderr, "Description: run-time error\n");
    retcode = RUN_RUN_TIME_ERR;
  } else {
    if (info_file && tinfo.check_stderr > 0) {
      if (copy_file(working_dir, error_file, NULL, corr_file, group, mode) < 0) {
        fprintf(stderr, "Status: PE\n");
      } else {
        if (quiet_flag <= 0) fprintf(stderr, "Status: OK\n");
        retcode = 0;
      }
    } else if (corr_file) {
      if (copy_file(working_dir, output_file, NULL, corr_file, group, mode) < 0) {
        fprintf(stderr, "Status: PE\n");
      } else {
        if (quiet_flag <= 0) fprintf(stderr, "Status: OK\n");
        retcode = 0;
      }
    } else {
      if (quiet_flag <= 0) fprintf(stderr, "Status: OK\n");
      retcode = 0;
    }
  }
  if (quiet_flag <= 0) {
    fprintf(stderr, "CPUTime: %ld\n", task_GetRunningTime(tsk));
    fprintf(stderr, "RealTime: %ld\n", task_GetRealTime(tsk));
  }

cleanup:
  task_Delete(tsk); tsk = NULL;
  if (input_path[0]) unlink(input_path);
  if (output_path[0]) unlink(output_path);
  if (error_path[0]) unlink(error_path);

  return retcode;
}

int
main(int argc, char *argv[])
{
  int i, r;

  progname = argv[0];
  for (i = 1; i < argc; i++) {
    r = handle_options(argv[i]);
    if (r == 1) i++;
    if (r > 0) break;
  }
  if (i == argc) fatal("no program to execute");

  return run_program(argc - i, argv + i);
}
