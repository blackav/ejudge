/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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

  if (!total) {
    err("no testers");
    return -1;
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
generate_report(int accept_testing,
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

  if (global->score_system_val == SCORE_OLYMPIAD && accept_testing) {
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
      if (global->score_system_val == SCORE_KIROV) {
        fprintf(f, _("PARTIAL SOLUTION\n\n"));
      } else {
        fprintf(f, _("%s, test #%d\n\n"),
                result2str(status,0,0), first_failed);
      }
    }
    fprintf(f, _("%d total tests runs, %d passed, %d failed\n"),
            total_tests - 1, passed_tests, failed_tests);
    if (global->score_system_val == SCORE_KIROV) {
      fprintf(f, _("Scores gained: %d (out of %d)\n"), scores, max_score);
    }
    fprintf(f, "\n");
  }

  fprintf(f, _("Test #  Status  Time (sec)  %sResult\n"),
          (global->score_system_val == SCORE_KIROV)?_("Score   "):"");
  for (i = 1; i < total_tests; i++) {
    score_buf[0] = 0;
    if (global->score_system_val == SCORE_KIROV) {
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
generate_team_report(int accept_testing,
                     char const *report_path, int scores, int max_score)
{
  FILE *f;
  int   i;
  int   status = 0;
  int   first_failed = 0;
  int   passed_tests = 0;
  int   failed_tests = 0;

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

  if (global->score_system_val == SCORE_OLYMPIAD && accept_testing) {
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
      if (global->score_system_val == SCORE_KIROV) {
        fprintf(f, _("PARTIAL SOLUTION\n\n"));
      } else {
        fprintf(f, _("%s, test #%d\n\n"),
                result2str(status,0,0), first_failed);
      }
    }
    fprintf(f, _("%d total tests runs, %d passed, %d failed\n"),
            total_tests - 1, passed_tests, failed_tests);
    if (global->score_system_val == SCORE_KIROV) {
      fprintf(f, _("Scores gained: %d (out of %d)\n"), scores, max_score);
    }
    fprintf(f, "\n");
  }

  fprintf(f, _("Test #  Status  Time (sec)  %sResult\n"),
          (global->score_system_val == SCORE_KIROV)?_("Score   "):"");
  for (i = 1; i < total_tests; i++) {
    score_buf[0] = 0;
    if (global->score_system_val == SCORE_KIROV) {
      sprintf(score_buf2, "%d (%d)", tests[i].score, tests[i].max_score);
      sprintf(score_buf, "%-8s", score_buf2);
    }
    fprintf(f, "%-8d%-8d%-12.3f%s%s\n",
	    i, tests[i].code, (double) tests[i].times / 1000,
            score_buf,
	    result2str(tests[i].status,0,0));
  }
  fprintf(f, "\n");

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

  ASSERT(tst->problem > 0);
  ASSERT(tst->problem <= max_prob);
  ASSERT(probs[tst->problem]);
  prb = probs[tst->problem];

  pathmake(report_path, tst->tmp_dir, "/", "report", NULL);
  team_report_path[0] = 0;
  if (global->team_enable_rep_view) {
    pathmake(team_report_path, tst->tmp_dir, "/", "team_report", NULL);
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
    if (global->score_system_val == SCORE_OLYMPIAD
        && accept_testing
        && cur_test > prb->tests_to_accept) break;

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
      info("starting: %s %s", tst->start_cmd, exe_path);
      task_AddArg(tsk, tst->start_cmd);
    } else {
      info("starting: %s", exe_path);
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
        total_failed_tests++;
        task_Delete(tsk); tsk = 0;
      } else if ((error_code[0] && ec != 0) || task_IsAbnormal(tsk)) {
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
      if (global->score_system_val == SCORE_ACM) break;
      if (global->score_system_val == SCORE_OLYMPIAD
          && accept_testing) break;
    }
    clear_directory(tst->work_dir);
  }

  /* TESTING COMPLETED (SOMEHOW) */

  if (global->score_system_val == SCORE_OLYMPIAD
      && accept_testing) {
    if (!failed_test) { 
      status = RUN_ACCEPTED;
      failed_test = cur_test;
    }
    sprintf(reply_string, "%d %d -1\n", status, failed_test);
  } else if (global->score_system_val == SCORE_KIROV
             || global->score_system_val == SCORE_OLYMPIAD) {
    int jj;

    for (jj = 1; jj <= prb->ntests; jj++) {
      tests[jj].score = 0;
      tests[jj].max_score = prb->tscores[jj];
      if (tests[jj].status == RUN_OK) {
        score += prb->tscores[jj];
        tests[jj].score = prb->tscores[jj];
      }
    }

    if (!total_failed_tests) score = prb->full_score;

    /* ATTENTION: number of passed test returned is greater than actual by 1 */
    sprintf(reply_string, "%d %d %d\n",
            total_failed_tests > 0?RUN_PARTIAL:RUN_OK,
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

  if (global->team_enable_rep_view) {
    setup_locale(locale_id);
    generate_team_report(accept_testing,
                         team_report_path, score, prb->full_score);
    setup_locale(0);
  }
  generate_report(accept_testing, report_path, score, prb->full_score);

  goto _cleanup;

 _internal_execution_error:
  sprintf(reply_string, "%d 0 -1\n", RUN_CHECK_FAILED);
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
  path_t team_report_path;

  char   status_string[64];

  char   pkt_buf[128];
  char  *pkt_ptr;
  int    rsize;

  char   exe_name[64];
  int    locale_id;
  int    accept_testing;
  int    n;

  if (cr_serialize_init() < 0) return -1;

  while (1) {
    for (i = 1; i <= max_tester; i++) {
      if (!testers[i]) continue;
      r = scan_dir(testers[i]->queue_dir, new_name);
      if (r < 0) return -1;
      if (r > 0) break;
    }

    if (i > max_tester) {
      os_Sleep(global->sleep_time);
      continue;
    }

    memset(pkt_buf, 0, sizeof(pkt_buf));
    pkt_ptr = pkt_buf;
    r = generic_read_file(&pkt_ptr, sizeof(pkt_buf), &rsize, SAFE | REMOVE,
                          testers[i]->queue_dir, new_name, "");
    if (r == 0) continue;
    if (r < 0) return -1;
 
    chop(pkt_buf);
    info("run packet: <%s>", pkt_buf);
    n = 0;
    memset(exe_name, 0, sizeof(exe_name));
    if (sscanf(pkt_buf, "%63s %d %d %n", exe_name, &locale_id,
               &accept_testing, &n) != 3
        || pkt_buf[n]
        || accept_testing < 0
        || accept_testing > 1
        || locale_id < 0
        || locale_id > 1024) {
      err("bad packet");
      continue;
    }

    r = generic_copy_file(REMOVE, testers[i]->server_exe_dir, exe_name, "",
                          0, testers[i]->tmp_dir, exe_name, "");
    if (r <= 0) continue;

    /* team report might be not produced */
    team_report_path[0] = 0;

    os_rGetBasename(exe_name, new_base, PATH_MAX);
    if (cr_serialize_lock() < 0) return -1;
    if (run_tests(testers[i], locale_id, accept_testing, exe_name, new_base,
                  status_string, report_path,
                  team_report_path) < 0) {
      cr_serialize_unlock();
      return -1;
    }
    if (cr_serialize_unlock() < 0) return -1;
    if (generic_copy_file(0, NULL, report_path, "",
                          0, testers[i]->run_report_dir, new_base, "") < 0)
      return -1;
    if (team_report_path[0]
        && generic_copy_file(0, NULL, team_report_path, "",
                             0, testers[i]->run_team_report_dir,
                             new_base, "") < 0)
      return -1;
    if (generic_write_file(status_string, strlen(status_string), SAFE,
                           testers[i]->run_status_dir, new_base, "") < 0)
      return -1;
    clear_directory(testers[i]->tmp_dir);
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

int
check_config(void)
{
  int     i, n1, n2, j;
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

    if (global->score_system_val == SCORE_KIROV) {
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

    /* check spooler dirs */
    if (check_writable_spool(testers[i]->queue_dir, SPOOL_OUT) < 0) return -1;
    if (check_writable_spool(testers[i]->run_status_dir,SPOOL_IN)<0) return -1;
    if (check_writable_dir(testers[i]->run_report_dir) < 0) return -1;
    if (global->team_enable_rep_view) {
      if (check_writable_dir(testers[i]->run_team_report_dir) < 0) return -1;
    }

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

