/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2003 Alexander Chernov <cher@ispras.ru> */

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

#include "prepare.h"
#include "runlog.h"
#include "cr_serialize.h"

#include "fileutl.h"

#include <reuse/osdeps.h>
#include <reuse/logger.h>
#include <reuse/exec.h>
#include <reuse/xalloc.h>
#include <reuse/number_io.h>
#include <reuse/format_io.h>

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#include <locale.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define MAX_TEST    255

struct testinfo
{
  int            status;	/* the execution status */
  int            code;		/* the process exit code */
  int            termsig;       /* the termination signal */
  int            score;         /* score gained for this test */
  int            max_score;     /* maximal score for this test */
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
setup_locale(int locale_id)
{
#if CONF_HAS_LIBINTL - 0 == 1
  char *e = 0;
  char env_buf[128];

  if (!global->enable_l10n) return 0;

  switch (locale_id) {
  case 1:
    e = "ru_RU.KOI8-R";
    break;
  case 0:
  default:
    locale_id = 0;
    e = "C";
    break;
  }

  sprintf(env_buf, "LC_ALL=%s", e);
  putenv(env_buf);
  setlocale(LC_ALL, "");
  return locale_id;
#else
  return 0;
#endif /* CONF_HAS_LIBINTL */
}

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

  return 0;
}

char *
result2str(int s, int st, int sig)
{
  static char result2str_buf[1024];

  switch (s) {
  case 0:
    return _("OK");
  case 2:
    if (st == 256) {
      sprintf(result2str_buf, "%s (%s)", _("Runtime error"),
              os_GetSignalString(sig));
      return result2str_buf;
    }
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

static void
print_by_line(FILE *f, char const *s)
{
  char const *p = s;

  if (global->max_file_length >  0 && strlen(s) > global->max_file_length) {
    fprintf(f, "<%s>\n", _("file is too long"));
    return;
  }

  while (*s) {
    while (*s && *s != '\r' && *s != '\n') s++;
    if (global->max_line_length > 0 && s - p > global->max_line_length) {
      fprintf(f, "<%s>\n", _("line is too long"));
    } else {
      while (p != s)
        putc(*p++, f);
    }
    while (*s == '\r' || *s == '\n')
      putc(*s++, f);
    p = s;
  }
  putc('\n', f);
}

static int
generate_report(int score_system_val,
                int accept_testing,
                char *report_path, int scores, int max_score)
{
  FILE *f;
  int   i;
  int   status = 0;
  int   first_failed = 0;
  int   passed_tests = 0;
  int   failed_tests = 0;
  int   addition = -1;
  char  score_buf[32];
  char  score_buf2[32];

  if (!(f = fopen(report_path, "w"))) {
    err("generate_report: cannot open protocol file %s", report_path);
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

  if (score_system_val == SCORE_OLYMPIAD && accept_testing) {
    if (status == 0) {
      fprintf(f, "%s\n\n", _("ACCEPTED"));
    } else {
      fprintf(f, _("%s, test #%d\n\n"),
              result2str(status,0,0), first_failed);
    }
    fprintf(f, _("%d total tests runs, %d passed, %d failed\n"),
            total_tests - 1, passed_tests, failed_tests);
    fprintf(f, "\n");
  } else {
    if (status == 0) {
      fprintf(f, "%s\n\n", _("OK"));
    } else {
      if (score_system_val == SCORE_KIROV) {
        fprintf(f, _("PARTIAL SOLUTION\n\n"));
      } else {
        fprintf(f, _("%s, test #%d\n\n"),
                result2str(status,0,0), first_failed);
      }
    }
    fprintf(f, _("%d total tests runs, %d passed, %d failed\n"),
            total_tests - 1, passed_tests, failed_tests);
    if (score_system_val == SCORE_KIROV) {
      fprintf(f, _("Scores gained: %d (out of %d)\n"), scores, max_score);
    }
    fprintf(f, "\n");
  }

  fprintf(f, _("Test #  Status  Time (sec)  %sResult\n"),
          (score_system_val == SCORE_KIROV)?_("Score   "):"");
  for (i = 1; i < total_tests; i++) {
    score_buf[0] = 0;
    if (score_system_val == SCORE_KIROV) {
      sprintf(score_buf2, "%d (%d)", tests[i].score, tests[i].max_score);
      sprintf(score_buf, "%-8s", score_buf2);
    }
    fprintf(f, "%-8d%-8d%-12.3f%s%s\n",
	    i, tests[i].code, (double) tests[i].times / 1000,
            score_buf,
	    result2str(tests[i].status, tests[i].code, tests[i].termsig));
  }
  fprintf(f, "\n");

  i = total_tests - 1;
  for (; i >= 1 && i < total_tests; i += addition) {
    fprintf(f, _("====== Test #%d =======\n"), i);
    fprintf(f, _("Judgement: %s\n"), result2str(tests[i].status, 0, 0));
    if (tests[i].output != NULL) {
      fprintf(f, _("--- Output ---\n"));
      print_by_line(f, tests[i].output);
    }
    if (tests[i].correct != NULL) {
      fprintf(f, _("--- Correct ---\n"));
      print_by_line(f, tests[i].correct);
    }
    if (tests[i].input != NULL) {
      fprintf(f, _("--- Input ---\n"));
      print_by_line(f, tests[i].input);
    }
    if (tests[i].error != NULL) {
      fprintf(f, _("--- Stderr ---\n"));
      print_by_line(f, tests[i].error);
    }
    if (tests[i].chk_out != NULL) {
      fprintf(f, _("--- Checker output ---\n"));
      print_by_line(f, tests[i].chk_out);
    }
  }


  fclose(f);
  return 0;
}

static int
generate_team_report(int score_system_val,
                     int accept_testing,
                     int report_error_code,
                     char const *report_path, int scores, int max_score)
{
  FILE *f;
  int   i;
  int   status = 0;
  int   first_failed = 0;
  int   passed_tests = 0;
  int   failed_tests = 0;
  int   retcode;

  char  score_buf[32];
  char  score_buf2[32];

  if (!(f = fopen(report_path, "w"))) {
    err("generate_report: cannot open protocol file %s", report_path);
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

  if (score_system_val == SCORE_OLYMPIAD && accept_testing) {
    if (status == 0) {
      fprintf(f, "%s\n\n", _("ACCEPTED"));
    } else {
      fprintf(f, _("%s, test #%d\n\n"),
              result2str(status,0,0), first_failed);
    }
    fprintf(f, _("%d total tests runs, %d passed, %d failed\n"),
            total_tests - 1, passed_tests, failed_tests);
    fprintf(f, "\n");
  } else {
    if (status == 0) {
      fprintf(f, "%s\n\n", _("OK"));
    } else {
      if (score_system_val == SCORE_KIROV) {
        fprintf(f, _("PARTIAL SOLUTION\n\n"));
      } else {
        fprintf(f, _("%s, test #%d\n\n"),
                result2str(status,0,0), first_failed);
      }
    }
    fprintf(f, _("%d total tests runs, %d passed, %d failed\n"),
            total_tests - 1, passed_tests, failed_tests);
    if (score_system_val == SCORE_KIROV) {
      fprintf(f, _("Scores gained: %d (out of %d)\n"), scores, max_score);
    }
    fprintf(f, "\n");
  }

  fprintf(f, _("Test #  Status  Time (sec)  %sResult\n"),
          (score_system_val == SCORE_KIROV)?_("Score   "):"");
  for (i = 1; i < total_tests; i++) {
    score_buf[0] = 0;
    if (score_system_val == SCORE_KIROV) {
      sprintf(score_buf2, "%d (%d)", tests[i].score, tests[i].max_score);
      sprintf(score_buf, "%-8s", score_buf2);
    }
    retcode = tests[i].code;
    if (tests[i].code != 0 && !report_error_code) {
      retcode = 1;
    }
    fprintf(f, "%-8d%-8d%-12.3f%s%s\n",
	    i, retcode, (double) tests[i].times / 1000,
            score_buf,
	    result2str(tests[i].status,0,0));
  }
  fprintf(f, "\n");

  if (!report_error_code) {
    fprintf(f, "\n%s\n", _("Note: non-zero return code is always reported as 1"));
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
          int locale_id,
          int team_enable_rep_view,
          int report_error_code,
          int score_system_val,
          int accept_testing,
          char const *new_name,
          char const *new_base,
          char *reply_string,               /* buffer where reply is formed */
          char *report_path,                /* path to the report */
          char *team_report_path) /* path to the team report */
{
  tTask *tsk = 0;
  int    cur_test;
  int    copy_flag = 0;
  path_t exe_path;
  path_t arg0_path;
  path_t test_base;
  path_t test_src;
  path_t corr_path;
  path_t corr_base;
  path_t input_path;
  path_t output_path;
  path_t error_path;
  path_t check_out_path;
  path_t error_code;
  int    score = 0;
  int    status = 0;
  int    failed_test = 0;
  int    total_failed_tests = 0;
  int    ec = -100;            /* FIXME: magic */
  struct section_problem_data *prb;
  char *sound;
  struct termios term_attrs;

  ASSERT(tst->problem > 0);
  ASSERT(tst->problem <= max_prob);
  ASSERT(probs[tst->problem]);
  prb = probs[tst->problem];

  pathmake(report_path, global->run_work_dir, "/", "report", NULL);
  team_report_path[0] = 0;
  if (team_enable_rep_view) {
    pathmake(team_report_path, global->run_work_dir, "/", "team_report", NULL);
  }
  memset(tests, 0, sizeof(tests));
  total_tests = 1;
  cur_test = 1;

  /* at this point the executable is copied into the working dir */
  if (tst->prepare_cmd[0]) {
    info("starting: %s %s", tst->prepare_cmd, new_name);
    tsk = task_New();
    task_AddArg(tsk, tst->prepare_cmd);
    task_AddArg(tsk, new_name);
    task_SetPathAsArg0(tsk);
    task_SetWorkingDir(tsk, global->run_work_dir);
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
    task_SetRedir(tsk, 1, TSR_FILE, report_path, TSK_REWRITE, TSK_FULL_RW);
    task_SetRedir(tsk, 2, TSR_DUP, 1);
    task_Start(tsk);
    task_Wait(tsk);
    if (task_IsAbnormal(tsk)) goto _internal_execution_error;
    task_Delete(tsk); tsk = 0;
  }

  pathmake3(exe_path, tst->check_dir, "/", new_name, NULL);
  snprintf(arg0_path, sizeof(arg0_path), "./%s", new_name);
  
  if (tst->is_dos) copy_flag = CONVERT;

  error_code[0] = 0;
  if (tst->errorcode_file[0]) {
    pathmake(error_code, tst->check_dir, "/", tst->errorcode_file, 0);
  }

  while (1) {
    if (score_system_val == SCORE_OLYMPIAD
        && accept_testing
        && cur_test > prb->tests_to_accept) break;

    sprintf(test_base, "%03d%s", cur_test, prb->test_sfx);
    sprintf(corr_base, "%03d%s", cur_test, prb->corr_sfx);
    pathmake(test_src, prb->test_dir, "/", test_base, NULL);
    if (os_CheckAccess(test_src, REUSE_R_OK) < 0) break;

    make_writable(tst->check_dir);
    clear_directory(tst->check_dir);

    /* copy the executable */
    generic_copy_file(0, global->run_work_dir, new_name, "",
                      0, tst->check_dir, new_name, "");
    make_executable(exe_path);

    /* copy the test */
    generic_copy_file(0, NULL, test_src, "",
                      copy_flag, tst->check_dir, prb->input_file, "");

    pathmake(input_path, tst->check_dir, "/", prb->input_file, 0);
    pathmake(output_path, tst->check_dir, "/", prb->output_file, 0);
    pathmake(error_path, tst->check_dir, "/", tst->error_file, 0);
    pathmake(check_out_path, global->run_work_dir, "/", "checkout", 0);

    /* run the tested program */
    tsk = task_New();
    if (tst->start_cmd[0]) {
      info("starting: %s %s", tst->start_cmd, arg0_path);
      task_AddArg(tsk, tst->start_cmd);
    } else {
      info("starting: %s", arg0_path);
    }
    //task_AddArg(tsk, exe_path);
    task_AddArg(tsk, arg0_path);
    task_SetPathAsArg0(tsk);
    task_SetWorkingDir(tsk, tst->check_dir);
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
        // create empty output file
        {
          int fd = open(output_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
          if (fd >= 0) close(fd);
        }
      }
      task_SetRedir(tsk, 2, TSR_FILE, error_path, TSK_REWRITE, TSK_FULL_RW);
    }  else {
      // create empty output file
      {
        int fd = open(output_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
        if (fd >= 0) close(fd);
      }
    }

    if (tst->clear_env) task_ClearEnv(tsk);
    if (tst->start_env) {
      int jj;
      for (jj = 0; tst->start_env[jj]; jj++)
        task_PutEnv(tsk, tst->start_env[jj]);
    }
    if (prb->time_limit > 0 && tst->time_limit_adjustment > 0) {
      task_SetMaxTime(tsk, prb->time_limit + tst->time_limit_adjustment);
    } else if (prb->time_limit > 0) {
      task_SetMaxTime(tsk, prb->time_limit);
    }
    if (prb->real_time_limit>0) task_SetMaxRealTime(tsk,prb->real_time_limit);
    if (tst->kill_signal[0]) task_SetKillSignal(tsk, tst->kill_signal);
    if (tst->no_core_dump) task_DisableCoreDump(tsk);
    if (tst->max_stack_size) task_SetStackSize(tsk, tst->max_stack_size);
    if (tst->max_data_size) task_SetDataSize(tsk, tst->max_data_size);
    if (tst->max_vm_size) task_SetVMSize(tsk, tst->max_vm_size);

    memset(&term_attrs, 0, sizeof(term_attrs));
    if (tst->no_redirect && isatty(0)) {
      /* we need to save terminal state since if the program
       * is killed with SIGKILL, the terminal left in random state
       */
      if (tcgetattr(0, &term_attrs) < 0) {
        err("tcgetattr failed: %s", os_ErrorMsg());
      }
    }

    if (task_Start(tsk) < 0) {
      /* failed to start task */
      status = RUN_CHECK_FAILED;
      tests[cur_test].code = task_ErrorCode(tsk, 0, 0);
      task_Delete(tsk); tsk = 0;
      total_failed_tests++;
    } else {
      /* task hopefully started */
      task_Wait(tsk);

      if (error_code[0]) {
        ec = read_error_code(error_code);
      }

      /* restore the terminal state */
      if (tst->no_redirect && isatty(0)) {
        if (tcsetattr(0, TCSADRAIN, &term_attrs) < 0)
          err("tcsetattr failed: %s", os_ErrorMsg());
      }

      /* set normal permissions for the working directory */
      make_writable(tst->check_dir);
      /* make the output file readable */
      if (chmod(output_path, 0600) < 0) {
        err("chmod failed: %s", os_ErrorMsg());
      }

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
        total_failed_tests++;
        task_Delete(tsk); tsk = 0;
      } else if ((error_code[0] && ec != 0)
                 || (!error_code[0] && task_IsAbnormal(tsk))) {
        /* runtime error */
        if (error_code[0]) {
          tests[cur_test].code = ec;
        } else {
          if (task_Status(tsk) == TSK_SIGNALED) {
            tests[cur_test].code = 256; /* FIXME: magic */
            tests[cur_test].termsig = task_TermSignal(tsk);
          } else {
            tests[cur_test].code = task_ExitCode(tsk);
          }
        }
        failed_test = cur_test;
        status = RUN_RUN_TIME_ERR;
        total_failed_tests++;
        task_Delete(tsk); tsk = 0;

      } else {
        task_Delete(tsk); tsk = 0;

        /* now start checker */
        /* checker <input data> <output result> <corr answer> */
        tsk = task_New();
        task_AddArg(tsk, tst->check_cmd);
        task_AddArg(tsk, prb->input_file);
        task_AddArg(tsk, prb->output_file);
        if (prb->use_corr && prb->corr_dir[0]) {
          pathmake3(corr_path, prb->corr_dir, "/", corr_base, NULL);
          task_AddArg(tsk, corr_path);
          generic_read_file(&tests[cur_test].correct, 0, 0, 0,
                            0, corr_path, "");
        }
        task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
        task_SetRedir(tsk, 1, TSR_FILE, check_out_path,
                      TSK_REWRITE, TSK_FULL_RW);
        task_SetRedir(tsk, 2, TSR_DUP, 1);
        task_SetWorkingDir(tsk, tst->check_dir);
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
          if (status > 0) { 
            failed_test = cur_test;
            total_failed_tests++;
          }
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
    if (status > 0) {
      // test failed, how to react on this
      if (score_system_val == SCORE_ACM) break;
      if (score_system_val == SCORE_OLYMPIAD
          && accept_testing) break;
    }
    clear_directory(tst->check_dir);
  }

  /* TESTING COMPLETED (SOMEHOW) */

  if (score_system_val == SCORE_OLYMPIAD
      && accept_testing) {
    if (!failed_test) { 
      status = RUN_ACCEPTED;
      failed_test = cur_test;
    }
    sprintf(reply_string, "%d %d -1\n", status, failed_test);
  } else if (score_system_val == SCORE_KIROV
             || score_system_val == SCORE_OLYMPIAD) {
    int jj, retcode = RUN_OK;

    for (jj = 1; jj <= prb->ntests; jj++) {
      tests[jj].score = 0;
      tests[jj].max_score = prb->tscores[jj];
      if (tests[jj].status == RUN_OK) {
        score += prb->tscores[jj];
        tests[jj].score = prb->tscores[jj];
      }
      if (tests[jj].status == RUN_CHECK_FAILED) {
        retcode = RUN_CHECK_FAILED;
      } else if (tests[jj].status != RUN_OK && retcode != RUN_CHECK_FAILED) {
        retcode = RUN_PARTIAL;
      }
    }

    if (retcode == RUN_PARTIAL && prb->ts_total > 0) {
      int ts;

      /* FIXME: check testsets */
      for (ts = 0; ts < prb->ts_total; ts++) {
        struct testset_info *ti = &prb->ts_infos[ts];

        if (ti->total > prb->ntests) continue;
        // check, that any RUN_OK test is in set
        for (jj = 1; jj <= prb->ntests; jj++) {
          if (tests[jj].status != RUN_OK) continue;
          if (jj > ti->total) break;
          if (!ti->nums[jj - 1]) break;
        }
        // no
        if (jj <= prb->ntests) continue;
        // check, that any test in set is RUN_OK
        for (jj = 0; jj < ti->total; jj++) {
          if (!ti->nums[jj]) continue;
          if (jj >= prb->ntests) break;
          if (tests[jj + 1].status != RUN_OK) break;
        }
        // no
        if (jj < ti->total) continue;
        // set the score
        score = ti->score;
      }
    }

    if (!total_failed_tests) score = prb->full_score;

    /* ATTENTION: number of passed test returned is greater than actual by 1 */
    sprintf(reply_string, "%d %d %d\n",
            retcode,
            total_tests - total_failed_tests,
            score);
  } else {
    sprintf(reply_string, "%d %d -1\n", status, failed_test);

    // play funny sound
    sound = 0;
    if (status == RUN_TIME_LIMIT_ERR
        && global->sound_player[0] && global->timelimit_sound[0]) {
      sound = global->timelimit_sound;
    } else if (status == RUN_RUN_TIME_ERR
               && global->sound_player[0] && global->runtime_sound[0]) {
      sound = global->runtime_sound;
    } else if (status == RUN_CHECK_FAILED && global->sound_player[0]
               && global->internal_sound[0]) {
      sound = global->internal_sound;
    } else if (status == RUN_PRESENTATION_ERR
               && global->sound_player[0] && global->presentation_sound[0]) {
      sound = global->presentation_sound;
    } else if (status == RUN_WRONG_ANSWER_ERR
               && global->sound_player[0] && global->wrong_sound[0]) {
      sound = global->wrong_sound;
    } else if (status == RUN_OK
               && global->sound_player[0] && global->accept_sound[0]) {
      sound = global->accept_sound;
    }

    if (sound) {
      tsk = task_New();
      task_AddArg(tsk, global->sound_player);
      task_AddArg(tsk, sound);
      task_SetPathAsArg0(tsk);
      task_Start(tsk);
      task_Wait(tsk);
      task_Delete(tsk);
      tsk = 0;
    }
  }

  if (team_enable_rep_view) {
    setup_locale(locale_id);
    generate_team_report(score_system_val, accept_testing,
                         report_error_code,
                         team_report_path, score, prb->full_score);
    setup_locale(0);
  }
  generate_report(score_system_val, accept_testing,
                  report_path, score, prb->full_score);

  goto _cleanup;

 _internal_execution_error:
  sprintf(reply_string, "%d 0 -1\n", RUN_CHECK_FAILED);
  goto _cleanup;

 _cleanup:
  if (tsk) task_Delete(tsk);
  tsk = 0;
  clear_directory(tst->check_dir);
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
  int r;

  path_t report_path;
  path_t team_report_path;

  unsigned char pkt_name[64];
  unsigned char exe_pkt_name[64];
  unsigned char run_base[64];
  path_t full_report_dir;
  path_t full_team_report_dir;
  path_t full_status_dir;

  char   status_string[64];

  char   pkt_buf[128];
  char  *pkt_ptr;
  int    rsize;

  char   exe_name[64];
  int    contest_id;
  int    run_id;
  int    tester_id;
  int    prob_id;
  int    locale_id;
  int    accept_testing;
  int    n;
  unsigned char exe_sfx[64];
  unsigned char arch[64];
  int exe_sfx_len, arch_len;
  int score_system_val;
  int team_enable_rep_view;
  int report_error_code;
  struct section_tester_data tn, *tst;

  memset(&tn, 0, sizeof(tn));

  if (cr_serialize_init() < 0) return -1;

  while (1) {
    r = scan_dir(global->run_queue_dir, pkt_name);
    if (r < 0) return -1;
    if (!r) {
      os_Sleep(global->sleep_time);
      continue;
    }

    memset(pkt_buf, 0, sizeof(pkt_buf));
    pkt_ptr = pkt_buf;
    r = generic_read_file(&pkt_ptr, sizeof(pkt_buf), &rsize, SAFE | REMOVE,
                          global->run_queue_dir, pkt_name, "");
    if (r == 0) continue;
    if (r < 0) return -1;
 
    chop(pkt_buf);
    info("run packet: <%s>", pkt_buf);
    n = 0;
    memset(exe_sfx, 0, sizeof(exe_sfx));
    if ((r = sscanf(pkt_buf, "%d %d %d %d %d %d %d %d %63s %63s %n",
                    &contest_id, &run_id,
                    &prob_id, &accept_testing, &locale_id,
                    &score_system_val, &team_enable_rep_view,
                    &report_error_code,
                    exe_sfx, arch,
               &n)) != 10
        || pkt_buf[n]
        || contest_id <= 0
        || run_id < 0
        || (exe_sfx_len = strlen(exe_sfx)) < 2
        || exe_sfx[0] != '\"'
        || exe_sfx[exe_sfx_len - 1] != '\"'
        || (arch_len = strlen(arch)) < 2
        || arch[0] != '\"'
        || arch[arch_len - 1] != '\"'
        || prob_id <= 0
        || prob_id > max_prob
        || !probs[prob_id]
        || accept_testing < 0
        || accept_testing > 1
        || score_system_val < SCORE_ACM
        || score_system_val > SCORE_OLYMPIAD
        || team_enable_rep_view < 0
        || team_enable_rep_view > 1
        || report_error_code < 0
        || report_error_code > 1
        || locale_id < 0
        || locale_id > 1024) {
      err("bad packet");
      continue;
    }

    exe_sfx[0] = 0;
    exe_sfx[exe_sfx_len - 1] = 0;
    arch[0] = 0;
    arch[arch_len - 1] = 0;

    if (!(tester_id = find_tester(prob_id, arch + 1))) {
      err("no tester for pair %d,%s", prob_id, arch);
      continue;
    }
    info("fount tester %d for pair %d,%s", tester_id, prob_id, arch);
    tst = testers[tester_id];
    if (tst->any) {
      info("tester %d is a default tester", tester_id);
      r = prepare_tester_refinement(&tn, tester_id, prob_id);
      ASSERT(r >= 0);
      tst = &tn;
    }

    snprintf(exe_pkt_name, sizeof(exe_pkt_name), "%s%s",
             pkt_name,  exe_sfx + 1);
    snprintf(run_base, sizeof(run_base), "%06d", run_id);
    snprintf(exe_name, sizeof(exe_name), "%s%s",
             run_base, exe_sfx + 1);

    r = generic_copy_file(REMOVE, global->run_exe_dir, exe_pkt_name, "",
                          0, global->run_work_dir, exe_name, "");
    if (r <= 0) continue;

    report_path[0] = 0;
    /* team report might be not produced */
    team_report_path[0] = 0;

    if (cr_serialize_lock() < 0) return -1;
    if (run_tests(tst, locale_id,
                  team_enable_rep_view, report_error_code,
                  score_system_val, accept_testing,
                  exe_name, run_base,
                  status_string, report_path,
                  team_report_path) < 0) {
      cr_serialize_unlock();
      return -1;
    }
    if (cr_serialize_unlock() < 0) return -1;

    if (tst == &tn) {
      sarray_free(tst->start_env);
    }

    snprintf(full_report_dir, sizeof(full_report_dir),
             "%s/%04d/report", global->run_dir, contest_id);
    snprintf(full_team_report_dir, sizeof(full_team_report_dir),
             "%s/%04d/teamreport", global->run_dir, contest_id);
    snprintf(full_status_dir, sizeof(full_status_dir),
             "%s/%04d/status", global->run_dir, contest_id);
             
    if (generic_copy_file(0, NULL, report_path, "",
                          0, full_report_dir, run_base, "") < 0)
      return -1;
    if (team_report_path[0]
        && generic_copy_file(0, NULL, team_report_path, "",
                             0, full_team_report_dir,
                             run_base, "") < 0)
      return -1;
    if (generic_write_file(status_string, strlen(status_string), SAFE,
                           full_status_dir, run_base, "") < 0)
      return -1;
    clear_directory(global->run_work_dir);
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

  prob_flags = (unsigned char *) alloca(max_prob + 1);

  /* scan all the 'any' testers */
  for (i = 1; i <= max_tester; i++) {
    tp = testers[i];
    if (!tp || !tp->any) continue;

    // check architecture uniqueness
    for (j = 1; j <= max_tester; j++) {
      tq = testers[j];
      if (i == j || !tq || !tq->any) continue;
      if (strcmp(testers[j]->arch, tp->arch) != 0) continue;
      err("default testers %d and %d has the same architecture '%s'",
          i, j, tp->arch);
      return -1;
    }

    // mark the problems with explicit testers for this architecture
    memset(prob_flags, 0, max_prob + 1);
    for (j = 1; j <= max_tester; j++) {
      tq = testers[j];
      if (!tq || tq->any) continue;
      if (strcmp(tp->arch, tq->arch) != 0) continue;

      // tq is specific tester with the same architecture
      ASSERT(tq->problem > 0 && tq->problem <= max_prob);
      ASSERT(probs[tq->problem]);
      prob_flags[tq->problem] = 1;
    }

    // scan all problems, which have no default tester
    for (k = 1; k <= max_prob; k++) {
      ts = probs[k];
      if (!ts || prob_flags[k]) continue;

      // so at this point: tp - pointer to the default tester,
      // k is the problem number
      // ts - pointer to the problem which should be handled by the
      // default tester
      if (prepare_tester_refinement(&tn, i, k) < 0) return -1;
      if (create_tester_dirs(&tn) < 0) return -1;

      /* check working dirs */
      if (make_writable(tn.check_dir) < 0) return -1;
      if (check_writable_dir(tn.check_dir) < 0) return -1;
      if (check_executable(tn.check_cmd) < 0) return -1;
      if (tn.prepare_cmd[0] && check_executable(tn.prepare_cmd) < 0) return -1;
      if (tn.start_cmd[0] && check_executable(tn.start_cmd) < 0) return -1;
      total++;
    }
  }

  return total;
}

int
check_config(void)
{
  int     i, n1, n2, j;
  int     total = 0;

  struct section_problem_data *prb = 0;

  /* check spooler dirs */
  if (check_writable_spool(global->run_queue_dir, SPOOL_OUT) < 0) return -1;
  if (check_writable_dir(global->run_exe_dir) < 0) return -1;

  /* check working dirs */
  if (make_writable(global->run_work_dir) < 0) return -1;
  if (check_writable_dir(global->run_work_dir) < 0) return -1;

  for (i = 1; i <= max_prob; i++) {
    prb = probs[i];
    if (!prb) continue;

    // check if there exists a tester for this problem
    for (j = 1; j <= max_tester; j++) {
      if (!testers[j]) continue;
      if (testers[j]->any) break;
      if (testers[j]->problem == i) break;
    }
    if (j > max_tester) {
      // no checker for the problem :-(
      info("no checker found for problem %d", i);
      continue;
    }

    /* check existence of tests */
    if (check_readable_dir(prb->test_dir) < 0) return -1;
    if ((n1 = count_files(prb->test_dir, prb->test_sfx)) < 0) return -1;
    if (!n1) {
      err("'%s' does not contain any tests", prb->test_dir);
      return -1;
    }
    info("found %d tests for problem %s", n1, prb->short_name);
    if (n1 <= prb->tests_to_accept) {
      err("%d tests required for problem acceptance!", prb->tests_to_accept);
      return -1;
    }
    if (prb->use_corr) {
      if (!prb->corr_dir[0]) {
        err("directory with answers is not defined");
        return -1;
      }
      if (check_readable_dir(prb->corr_dir) < 0) return -1;
      if ((n2 = count_files(prb->corr_dir, prb->corr_sfx)) < 0) return -1;
      info("found %d answers for problem %s", n2, prb->short_name);
      if (n1 != n2) {
        err("number of test does not match number of answers");
        return -1;
      }
    }

    if (prb->test_score > 0) {
      int score_summ = 0;

      prb->ntests = n1;
      XCALLOC(prb->tscores, prb->ntests + 1);

      for (j = 1; j <= prb->ntests; j++)
        prb->tscores[j] = prb->test_score;

      // test_score_list overrides test_score
      if (prb->test_score_list[0]) {
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
            if (score <= 0) {
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
            if (score <= 0) {
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
      if (score_summ > prb->full_score) {
        err("total score (%d) > full score (%d) for problem %s",
            score_summ, prb->full_score, prb->short_name);
        return -1;
      }
    }
  }

  for (i = 1; i <= max_tester; i++) {
    if (!testers[i]) continue;
    if (testers[i]->any) continue;

    total++;

    /* check working dirs */
    if (make_writable(testers[i]->check_dir) < 0) return -1;
    if (check_writable_dir(testers[i]->check_dir) < 0) return -1;

    if (check_executable(testers[i]->check_cmd) < 0) return -1;
    if (testers[i]->prepare_cmd[0]
        && check_executable(testers[i]->prepare_cmd) < 0) return -1;
    if (testers[i]->start_cmd[0]
        && check_executable(testers[i]->start_cmd) < 0) return -1;
  }

  info("checking default testers...");
  if ((i = process_default_testers()) < 0) return -1;
  info("checking default testers done");
  total += i;

  if (!total) {
    err("no testers");
    return -1;
  }

#if CONF_HAS_LIBINTL - 0 == 1
  // bind message catalogs, if specified
  if (global->enable_l10n && global->l10n_dir[0]) {
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
  int   p_flags = 0, code = 0, T_flag = 0;
  path_t cpp_opts = { 0 };

  if (argc == 1) goto print_usage;
  code = 1;

  while (i < argc) {
    if (!strcmp(argv[i], "-T")) {
      T_flag = 1;
      i++;
    } else if (!strcmp(argv[i], "-k")) {
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
  if (T_flag) {
    print_configuration(stdout);
    return 0;
  }
  if (filter_testers(key) < 0) return 1;
  if (create_dirs(PREPARE_RUN) < 0) return 1;
  if (check_config() < 0) return 1;
  if (do_loop() < 0) return 1;
  return 0;

 print_usage:
  printf("Usage: %s [ OPTS ] config-file\n", argv[0]);
  printf("  -T     - print configuration and exit");
  printf("  -k key - specify tester key\n");
  printf("  -E     - enable C preprocessor\n");
  printf("  -DDEF  - define a symbol for preprocessor\n");
  return code;
}


/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "tTask")
 * End:
 */

