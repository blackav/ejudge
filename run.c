/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000,2001 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "prepare.h"
#include "runlog.h"

#include "fileutl.h"
#include "osdeps.h"
#include "logger.h"
#include "exec.h"
#include "xalloc.h"

#include <stdio.h>
#include <string.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define MAX_TEST    255

struct testinfo
{
  int            status;	/* the execution status */
  int            code;		/* the process exit code */
  unsigned long  times;		/* execution time */
  char          *input;		/* the input */
  char          *output;	/* the output */
  char          *error;		/* the error */
  char          *correct;	/* the correct result */
  char          *chk_out;       /* checker's output */
};

int total_tests;
struct testinfo tests[MAX_TEST + 1];

static int
filter_testers(char *key)
{
  int i, total = 0;

  for (i = 1; i <= max_tester; i++) {
    if (key && strcmp(testers[i]->key, key)) {
      testers[i] = 0;
      continue;
    }
    if (testers[i]) total++;
  }

  if (!total) {
    err(_("no testers"));
    return -1;
  }
  return 0;
}

char *
result2str(int s)
{
  static char result2str_buf[1024];

  switch (s) {
  case 0:
    return _("OK");
  case 2:
    return _("Runtime error");
  case 3:
    return _("Time-limit exceeded");
  case 4:
    return _("Presentation error");
  case 5:
    return _("Wrong answer");
  case 6:
    return _("Manual check required");
  default:
    sprintf(result2str_buf, _("Unknown result (%d)"), s);
    return result2str_buf;
  }
}

static int
generate_report(char *report_path)
{
  FILE *f;
  int   i;
  int   status = 0;
  int   first_failed = 0;
  int   passed_tests = 0;
  int   failed_tests = 0;
  int   addition = -1;

  if (!(f = fopen(report_path, "w"))) {
    err(_("generate_report: cannot open protocol file %s"), report_path);
    return -1;
  }

  for (i = 1; i < total_tests; i++) {
    if (status == 0 && tests[i].status != 0) {
      status = tests[i].status;
      first_failed = i;
    }
    if (tests[i].status == 0) passed_tests++;
    else failed_tests++;
  }

  if (status == 0) {
    fprintf(f, "OK\n\n");
  } else {
    fprintf(f, _("%s, test #%d\n\n"), result2str(status), first_failed);
  }
  fprintf(f, _("%d total tests runs, %d passed, %d failed\n\n"),
	  total_tests - 1, passed_tests, failed_tests);

  fprintf(f, _("Test #  Status  Time (sec)  Result\n"));
  for (i = 1; i < total_tests; i++) {
    fprintf(f, "%-8d%-8d%-12.3f%s\n",
	    i, tests[i].code, (double) tests[i].times / 1000,
	    result2str(tests[i].status));
  }
  fprintf(f, "\n");

  i = total_tests - 1;
  for (; i >= 1 && i < total_tests; i += addition) {
    fprintf(f, _("====== Test #%d =======\n"), i);
    fprintf(f, _("Judgement: %s\n"), result2str(tests[i].status));
    if (tests[i].output != NULL) {
      fprintf(f, _("--- Output ---\n"));
      if (strlen(tests[i].output) > 65536) {
        fprintf(f, _("Program output is too long\n"));
      } else {
        fprintf(f, "%s\n", tests[i].output);
      }
    }
    if (tests[i].correct != NULL) {
      fprintf(f, _("--- Correct ---\n"));
      fprintf(f, "%s\n", tests[i].correct);
    }
    if (tests[i].input != NULL) {
      fprintf(f, _("--- Input ---\n"));
      fprintf(f, "%s\n", tests[i].input);
    }
    if (tests[i].error != NULL) {
      fprintf(f, _("--- Stderr ---\n"));
      fprintf(f, "%s\n", tests[i].error);
    }
    if (tests[i].chk_out != NULL) {
      fprintf(f, _("--- Checker output ---\n"));
      fprintf(f, "%s\n", tests[i].chk_out);
    }
  }


  fclose(f);
  return 0;
}

static int
read_error_code(char const *path)
{
  FILE *f;
  int   n;

  if (!(f = fopen(path, "r"))) {
    return 100;
  }
  if (fscanf(f, "%d", &n) != 1) {
    fclose(f);
    return 101;
  }
  fscanf(f, " ");
  if (getc(f) != EOF) {
    fclose(f);
    return 102;
  }
  fclose(f);
  return n;
}

static int
run_tests(struct section_tester_data *tst,
          char const *new_name,
          char const *new_base,
          char *reply_string,               /* buffer where reply is formed */
          char *report_path)                /* path to the report */
{
  tTask *tsk = 0;
  int    cur_test;
  int    copy_flag = 0;
  path_t exe_path;
  path_t test_base;
  path_t test_src;
  path_t corr_path;
  path_t corr_base;
  path_t input_path;
  path_t output_path;
  path_t error_path;
  path_t check_out_path;
  path_t error_code;
  int    status = 0;
  int    failed_test = 0;
  int    ec = -100;            /* FIXME: magic */
  struct section_problem_data *prb;

  ASSERT(tst->problem > 0);
  ASSERT(tst->problem <= max_prob);
  ASSERT(probs[tst->problem]);
  prb = probs[tst->problem];

  pathmake(report_path, tst->tmp_dir, "/", "report", NULL);
  memset(tests, 0, sizeof(tests));
  total_tests = 1;
  cur_test = 1;

  /* at this point the executable is copied into the working dir */
  if (tst->prepare_cmd[0]) {
    info(_("starting: %s %s"), tst->prepare_cmd, new_name);
    tsk = task_New();
    task_AddArg(tsk, tst->prepare_cmd);
    task_AddArg(tsk, new_name);
    task_SetPathAsArg0(tsk);
    task_SetWorkingDir(tsk, tst->tmp_dir);
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
    task_SetRedir(tsk, 1, TSR_FILE, report_path, TSK_REWRITE, TSK_FULL_RW);
    task_SetRedir(tsk, 2, TSR_DUP, 1);
    task_Start(tsk);
    task_Wait(tsk);
    if (task_IsAbnormal(tsk)) goto _internal_execution_error;
    task_Delete(tsk); tsk = 0;
  }

  pathmake3(exe_path, tst->work_dir, "/", new_name, NULL);
  if (tst->is_dos) copy_flag = CONVERT;

  error_code[0] = 0;
  if (tst->errorcode_file[0]) {
    pathmake(error_code, tst->work_dir, "/", tst->errorcode_file, 0);
  }

  while (1) {
    sprintf(test_base, "%03d%s", cur_test, prb->test_sfx);
    sprintf(corr_base, "%03d%s", cur_test, prb->corr_sfx);
    pathmake(test_src, prb->test_dir, "/", test_base, NULL);
    if (os_CheckAccess(test_src, REUSE_R_OK) < 0) break;

    make_writable(tst->work_dir);
    clear_directory(tst->work_dir);

    /* copy the executable */
    generic_copy_file(0, tst->tmp_dir, new_name, "",
                      0, tst->work_dir, new_name, "");
    make_executable(exe_path);

    /* copy the test */
    generic_copy_file(0, NULL, test_src, "",
                      copy_flag, tst->work_dir, prb->input_file, "");

    pathmake(input_path, tst->work_dir, "/", prb->input_file, 0);
    pathmake(output_path, tst->work_dir, "/", prb->output_file, 0);
    pathmake(error_path, tst->work_dir, "/", tst->error_file, 0);
    pathmake(check_out_path, tst->tmp_dir, "/", "checkout", 0);

    /* run the tested program */
    tsk = task_New();
    if (tst->start_cmd[0]) {
      info(_("starting: %s %s"), tst->start_cmd, exe_path);
      task_AddArg(tsk, tst->start_cmd);
    } else {
      info(_("starting: %s"), exe_path);
    }
    task_AddArg(tsk, exe_path);
    task_SetPathAsArg0(tsk);
    task_SetWorkingDir(tsk, tst->work_dir);
    if (!tst->no_redirect) {
      if (prb->use_stdin) {
        task_SetRedir(tsk, 0, TSR_FILE, input_path, TSK_READ);
      } else {
        task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
      }
      if (prb->use_stdout) {
        task_SetRedir(tsk, 1, TSR_FILE, output_path, TSK_REWRITE, TSK_FULL_RW);
      } else {
        task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
      }
      task_SetRedir(tsk, 2, TSR_FILE, error_path, TSK_REWRITE, TSK_FULL_RW);
    }

    if (prb->time_limit > 0) task_SetMaxTime(tsk, prb->time_limit);
    if (task_Start(tsk) < 0) {
      /* failed to start task */
      status = RUN_CHECK_FAILED;
      tests[cur_test].code = task_ErrorCode(tsk, 0, 0);
      task_Delete(tsk); tsk = 0;
    } else {
      /* task hopefully started */
      task_Wait(tsk);

      if (error_code[0]) {
        ec = read_error_code(error_code);
      }

      /* set normal permissions for the working directory */
      make_writable(tst->work_dir);

      /* fill test report structure */
      tests[cur_test].times = task_GetRunningTime(tsk);
      generic_read_file(&tests[cur_test].input, 0, 0, 0,
                        0, input_path, "");
      generic_read_file(&tests[cur_test].output, 0, 0, 0,
                        0, output_path, "");
      generic_read_file(&tests[cur_test].error, 0, 0, 0,
                        0, error_path, "");

      task_Log(tsk, 0, LOG_INFO);

      if (task_IsTimeout(tsk)) {
        failed_test = cur_test;
        status = RUN_TIME_LIMIT_ERR;
        task_Delete(tsk); tsk = 0;
      } else if ((error_code[0] && ec != 0) || task_IsAbnormal(tsk)) {
        /* runtime error */
        if (error_code[0]) {
          tests[cur_test].code = ec;
        } else {
          tests[cur_test].code = task_ExitCode(tsk);
        }
        failed_test = cur_test;
        status = RUN_RUN_TIME_ERR;
        task_Delete(tsk); tsk = 0;
      } else {
        task_Delete(tsk); tsk = 0;

        /* now start checker */
        /* checker <input data> <output result> <corr answer> */
        tsk = task_New();
        task_AddArg(tsk, tst->check_cmd);
        task_AddArg(tsk, prb->input_file);
        task_AddArg(tsk, prb->output_file);
        if (prb->corr_dir[0]) {
          pathmake3(corr_path, prb->corr_dir, "/", corr_base, NULL);
          task_AddArg(tsk, corr_path);
          generic_read_file(&tests[cur_test].correct, 0, 0, 0,
                            0, corr_path, "");
        }
        task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
        task_SetRedir(tsk, 1, TSR_FILE, check_out_path,
                      TSK_REWRITE, TSK_FULL_RW);
        task_SetRedir(tsk, 2, TSR_DUP, 1);
        task_SetWorkingDir(tsk, tst->work_dir);
        task_SetPathAsArg0(tsk);
        task_Start(tsk);
        task_Wait(tsk);

        generic_read_file(&tests[cur_test].chk_out, 0, 0, 0,
                          0, check_out_path, "");
        /* analyze error codes */
        if (task_Status(tsk) == TSK_SIGNALED) {
          /* crashed */
          status = RUN_CHECK_FAILED;
          failed_test = cur_test;
        } else if (task_Status(tsk) == TSK_EXITED) {
          status = task_ExitCode(tsk);
          switch (status) {
          case RUN_OK:
          case RUN_PRESENTATION_ERR:
          case RUN_WRONG_ANSWER_ERR:
          case RUN_CHECK_FAILED:
            /* this might be expected from the checker */
            break;
          default:
            status = RUN_CHECK_FAILED;
            break;
          }
          if (status > 0) failed_test = cur_test;
        } else {
          /* something strange */
          status = RUN_CHECK_FAILED;
          failed_test = cur_test;
        }
        task_Delete(tsk); tsk = 0;
      }
    }

    tests[cur_test].status = status;
    cur_test++;
    total_tests++;
    if (status > 0) break;
    clear_directory(tst->work_dir);
  }

  /* TESTING COMPLETED (SOMEHOW) */

  generate_report(report_path);
  sprintf(reply_string, "%d %d\n", status, failed_test);
  /*
  if (status == 0) { 
    putchar(7);
    usleep(500000);
    putchar(7);
  }
  */
  goto _cleanup;

 _internal_execution_error:
  sprintf(reply_string, "%d 0\n", RUN_CHECK_FAILED);
  goto _cleanup;

 _cleanup:
  if (tsk) task_Delete(tsk);
  tsk = 0;
  clear_directory(tst->work_dir);
  for (cur_test = 1; cur_test < total_tests; cur_test++) {
    xfree(tests[cur_test].input);
    xfree(tests[cur_test].output);
    xfree(tests[cur_test].error);
    xfree(tests[cur_test].chk_out);
    xfree(tests[cur_test].correct);
    memset(&tests[cur_test], 0, sizeof(tests[cur_test]));
  }
  return 0;
}

static int
do_loop(void)
{
  int i, r;

  path_t new_name;
  path_t new_base;
  path_t report_path;

  char   status_string[64];

  while (1) {
    for (i = 1; i <= max_tester; i++) {
      if (!testers[i]) continue;
      r = scan_dir(testers[i]->exe_dir, new_name);
      if (r < 0) return -1;
      if (r > 0) break;
    }

    if (i <= max_tester) {
      r = generic_copy_file(REMOVE|SAFE, testers[i]->exe_dir, new_name, "",
                            0, testers[i]->tmp_dir, new_name, "");
      if (r < 0) return -1;
      if (r == 0) continue;

      os_rGetBasename(new_name, new_base, PATH_MAX);
      if (run_tests(testers[i], new_name, new_base,
                    status_string, report_path) < 0) return -1;
      if (generic_copy_file(0, NULL, report_path, "",
                            0, testers[i]->run_report_dir, new_base, "") < 0)
        return -1;
      if (generic_write_file(status_string, strlen(status_string), SAFE,
                             testers[i]->run_status_dir, new_base, "") < 0)
        return -1;
      clear_directory(testers[i]->tmp_dir);
      continue;
    }

    os_Sleep(global->sleep_time);
  }
}

static int
count_files(char const *dir, char const *sfx)
{
  path_t path;
  int    n = 1;
  int    s;

  while (1) {
    os_snprintf(path, PATH_MAX, "%s%s%03d%s", dir, PATH_SEP, n, sfx);
    s = os_IsFile(path);
    if (s < 0) break;
    if (s != OSPK_REG) {
      err(_("'%s' is not a regular file"), path);
      return -1;
    }
    n++;
  }

  return n - 1;
}

int
check_config(void)
{
  int     i, n1, n2;
  int     total = 0;

  struct section_problem_data *prb = 0;

  for (i = 1; i <= max_tester; i++) {
    if (!testers[i]) continue;

    total++;
    prb = probs[testers[i]->problem];

    /* check existence of tests */
    if (check_readable_dir(prb->test_dir) < 0) return -1;
    if ((n1 = count_files(prb->test_dir, prb->test_sfx)) < 0) return -1;
    if (!n1) {
      err(_("'%s' does not contain any tests"), prb->test_dir);
      return -1;
    }
    info(_("found %d tests for problem %s"), n1, prb->short_name);
    if (prb->corr_dir[0]) {
      if (check_readable_dir(prb->corr_dir) < 0) return -1;
      if ((n2 = count_files(prb->corr_dir, prb->corr_sfx)) < 0) return -1;
      info(_("found %d answers for problem %s"), n2, prb->short_name);
      if (n1 != n2) {
        err(_("number of test does not match number of answers"));
        return -1;
      }
    }

    /* check spooler dirs */
    if (check_writable_spool(testers[i]->exe_dir, SPOOL_OUT) < 0) return -1;
    if (check_writable_spool(testers[i]->run_status_dir,SPOOL_IN)<0) return -1;
    if (check_writable_dir(testers[i]->run_report_dir) < 0) return -1;

    /* check working dirs */
    if (make_writable(testers[i]->tmp_dir) < 0) return -1;
    if (make_writable(testers[i]->work_dir) < 0) return -1;
    if (check_writable_dir(testers[i]->tmp_dir) < 0) return -1;
    if (check_writable_dir(testers[i]->work_dir) < 0) return -1;

    if (check_executable(testers[i]->check_cmd) < 0) return -1;
    if (testers[i]->prepare_cmd[0]
        && check_executable(testers[i]->prepare_cmd) < 0) return -1;
    if (testers[i]->start_cmd[0]
        && check_executable(testers[i]->start_cmd) < 0) return -1;
  }

  if (!total) {
    err(_("no testers"));
    return -1;
  }
  return 0;
}

int
main(int argc, char *argv[])
{
  int   i = 1;
  char *key = 0;
  int   p_flags = 0, code = 0;
  path_t cpp_opts;

  if (argc == 1) goto print_usage;
  code = 1;

  while (i < argc) {
    if (!strcmp(argv[i], "-k")) {
      if (++i >= argc) goto print_usage;
      key = argv[i++];
    } else if (!strncmp(argv[i], "-D", 2)) {
      if (cpp_opts[0]) pathcat(cpp_opts, " ");
      pathcat(cpp_opts, argv[i++]);
    } else if (!strcmp(argv[i], "-E")) {
      i++;
      p_flags |= PREPARE_USE_CPP;
    } else break;
  }
  if (i >= argc) goto print_usage;

  if (prepare(argv[i], p_flags, PREPARE_RUN, cpp_opts) < 0) return 1;
  if (filter_testers(key) < 0) return 1;
  if (create_dirs(PREPARE_RUN) < 0) return 1;
  if (check_config() < 0) return 1;
  if (do_loop() < 0) return 1;
  return 0;

 print_usage:
  printf(_("Usage: %s [ OPTS ] config-file\n"), argv[0]);
  printf(_("  -k key - specify tester key\n"));
  printf(_("  -E     - enable C preprocessor\n"));
  printf(_("  -DDEF  - define a symbol for preprocessor\n"));
  return code;
}


/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "tTask")
 * End:
 */

