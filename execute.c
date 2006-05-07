/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

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

#include <reuse/xalloc.h>
#include <reuse/exec.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

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

static const unsigned char *input_file = 0;
static const unsigned char *output_file = 0;
static const unsigned char *error_file = 0;
static const unsigned char *working_dir = 0;
static const unsigned char *kill_signal = 0;

static strarray_t env_vars;

static int clear_env_flag = 0;
static int no_core_dump = 0;
static int memory_limit = 0;
static int secure_exec = 0;

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
"--input=FILE             redirect standard input stream from FILE\n"
"--output=FILE            redirect standard output stream to FILE\n"
"--error=FILE             redirect standard error stream to FILE\n"
"--workdir=DIR            set the working directory to DIR\n"
"--clear-env              clear all environment\n"
"--env=VAR=VALUE          set the environment VAR to VALUE\n"
"--time-limit=SEC         set the time limit to SEC seconds\n"
#if defined HAVE_TASK_SETMAXTIMEMILLIS
"--time-limit-millis=MSEC set the time limit to MSEC milliseconds\n"
#endif
"--real-time-limit=SEC    set the real time limit to SEC seconds\n"
"--no-core-dump           disable core dump\n"
"--kill-signal=SIGNAL     specify the termination signal (kill, term, intr)\n"
#if defined HAVE_TASK_ENABLEMEMORYLIMITERROR
"--memory-limit           enable memory limit error detection\n"
#endif
#if !defined HAVE_TASK_ENABLESECUREEXEC
"--secure-exec            enable secure execution\n"
#endif
"--max-vm-size=SIZE       specify the virtual memory size limit\n"
"--max-stack-size=SIZE    specify the stack size limit\n"
"--max-data-size=SIZE     specify the heap size limit\n"
  ;

static void
report_help(void)
{
  printf("%s usage: execute [OPTIONS]... program [ARGUMENTS]...\n", progname);
  fputs(help_str, stdout);
  exit(0);
}

static int
handle_options(const unsigned char *opt)
{
  if (!strcmp("--version", opt)) {
    report_version();
  } else if (!strcmp("--help", opt)) {
    report_help();
  } else if (!strncmp("--input=", opt, 8)) {
    input_file = opt + 8;
  } else if (!strncmp("--output=", opt, 9)) {
    output_file = opt + 9;
  } else if (!strncmp("--error=", opt, 8)) {
    error_file = opt + 8;
  } else if (!strncmp("--workdir=", opt, 10)) {
    working_dir = opt + 10;
  } else if (!strcmp("--clear-env", opt)) {
    clear_env_flag = 1;
  } else if (!strncmp("--env=", opt, 6)) {
    xexpand(&env_vars);
    env_vars.v[env_vars.u++] = xstrdup(opt + 6);
  } else if (!strncmp("--time-limit=", opt, 13)) {
    parse_int("--time-limit", opt + 13, &time_limit, 1, 99999);
  } else if (!strncmp("--time-limit-millis=", opt, 20)) {
#if !defined HAVE_TASK_SETMAXTIMEMILLIS
    fatal("option --time-limit-millis is not supported");
#else
    parse_int("--time-limit-millis", opt + 20, &time_limit_millis,
              1, 999999999);
#endif
  } else if (!strncmp("--real-time-limit=", opt, 18)) {
    parse_int("--real-time-limit", opt + 18, &real_time_limit, 1, 99999);
  } else if (!strcmp("--no-core-dump", opt)) {
    no_core_dump = 1;
  } else if (!strncmp("--kill-signal=", opt, 14)) {
    kill_signal = opt + 14;
  } else if (!strcmp("--memory-limit", opt)) {
#if !defined HAVE_TASK_ENABLEMEMORYLIMITERROR
    fatal("option --memory-limit is not supported");
#else
    memory_limit = 1;
#endif
  } else if (!strcmp("--secure-exec", opt)) {
#if !defined HAVE_TASK_ENABLESECUREEXEC
    fatal("option --secure-exec is not supported");
#else
    secure_exec = 1;
#endif
  } else if (!strncmp("--max-vm-size=", opt, 14)) {
    parse_size("--max-vm-size", opt + 14, &max_vm_size, 4096, 1 << 30);
  } else if (!strncmp("--max-stack-size=", opt, 17)) {
    parse_size("--max-stack-size", opt + 17, &max_stack_size, 4096, 1 << 30);
  } else if (!strncmp("--max-data-size=", opt, 16)) {
    parse_size("--max-data-size", opt + 16, &max_data_size, 4096, 1 << 30);
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
  int retcode = 1;

  if (!(tsk = task_New())) fatal("cannot create task");
#if defined HAVE_TASK_SETQUIETFLAG
  task_SetQuietFlag(tsk);
#endif
  task_pnAddArgs(tsk, argc, argv);
  task_SetPathAsArg0(tsk);
  if (working_dir) task_SetWorkingDir(tsk, working_dir);
  if (input_file) task_SetRedir(tsk, 0, TSR_FILE, input_file, TSK_READ);
  if (output_file)
    task_SetRedir(tsk, 0, TSR_FILE, output_file, TSK_WRITE, TSK_FULL_RW);
  if (error_file)
    task_SetRedir(tsk, 0, TSR_FILE, error_file, TSK_WRITE, TSK_FULL_RW);
  if (clear_env_flag) task_ClearEnv(tsk);
  for (i = 0; i < env_vars.u; i++)
    task_PutEnv(tsk, env_vars.v[i]);
#if defined HAVE_TASK_SETMAXTIMEMILLIS
  if (time_limit_millis > 0)
    if (task_SetMaxTimeMillis(tsk, time_limit_millis) < 0)
      fatal("--time-limit-millis is not supported");
#endif
  if (time_limit > 0) task_SetMaxTime(tsk, time_limit);
  if (real_time_limit > 0) task_SetMaxRealTime(tsk, real_time_limit);
  if (kill_signal)
    if (task_SetKillSignal(tsk, kill_signal) < 0)
      fatal("invalid value for --kill-signal option");
  if (no_core_dump) task_DisableCoreDump(tsk);
  if (max_vm_size) task_SetVMSize(tsk, max_vm_size);
  if (max_stack_size) task_SetStackSize(tsk, max_stack_size);
  if (max_data_size) task_SetDataSize(tsk, max_data_size);
#if defined HAVE_TASK_ENABLEMEMORYLIMITERROR
  if (memory_limit)
    if (task_EnableMemoryLimitError(tsk) < 0)
      fatal("--memory-limit is not supported");
#endif
#if defined HAVE_TASK_ENABLESECUREEXEC
  if (secure_exec)
    if (task_EnableSecureExec(tsk) < 0)
      fatal("--secure-exec is not supported");
#endif

  if (task_Start(tsk) < 0) {
#if defined HAVE_TASK_GETERRORMESSAGE
    fprintf(stderr, "Status: CF\n"
            "Description: cannot start task: %s\n", task_GetErrorMessage(tsk));
#else
    fprintf(stderr, "Status: CF\n"
            "Description: cannot start task\n");
#endif
    task_Delete(tsk);
    return 2;
  }
  task_Wait(tsk);
#if defined HAVE_TASK_ISMEMORYLIMIT
  if (memory_limit && task_IsMemoryLimit(tsk)) {
    fprintf(stderr, "Status: ML\n"
            "Description: memory limit exceeded\n");
  } else
#endif
  if (task_IsTimeout(tsk)) {
    fprintf(stderr, "Status: TL\n"
            "Description: time limit exceeded\n");
  } else if (task_IsAbnormal(tsk)) {
    fprintf(stderr, "Status: RT\n");
    if (task_Status(tsk) == TSK_SIGNALED) {
      fprintf(stderr, "Signal: %d\n", task_TermSignal(tsk));
    } else {
      fprintf(stderr, "Exitcode: %d\n", task_ExitCode(tsk));
    }
    fprintf(stderr, "Description: run-time error\n");
  } else {
    fprintf(stderr, "Status: OK\n");
    retcode = 0;
  }
  fprintf(stderr, "CPUTime: %ld\n", task_GetRunningTime(tsk));
#if defined HAVE_TASK_GETREALTIME
  fprintf(stderr, "RealTime: %ld\n", task_GetRealTime(tsk));
#endif
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

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "tTask")
 * End:
 */
