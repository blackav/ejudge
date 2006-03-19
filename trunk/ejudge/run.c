/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2006 Alexander Chernov <cher@ispras.ru> */

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

#include "prepare.h"
#include "prepare_vars.h"
#include "runlog.h"
#include "cr_serialize.h"
#include "testinfo.h"
#include "interrupt.h"
#include "run_packet.h"
#include "curtime.h"
#include "full_archive.h"
#include "digest_io.h"
#include "filehash.h"

#include "fileutl.h"
#include "errlog.h"
#include "misctext.h"

#include <reuse/osdeps.h>
#include <reuse/logger.h>
#include <reuse/exec.h>
#include <reuse/xalloc.h>
#include <reuse/number_io.h>
#include <reuse/format_io.h>
#include <reuse/integral.h>

#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
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
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

//#define MAX_TEST    514

static int managed_mode_flag = 0;
static time_t last_activity_time;

struct testinfo
{
  int            status;        /* the execution status */
  int            code;          /* the process exit code */
  int            termsig;       /* the termination signal */
  int            score;         /* score gained for this test */
  int            max_score;     /* maximal score for this test */
  long           times;         /* execution time */
  long           real_time;     /* execution real time */
  char          *input;         /* the input */
  long           input_size;
  int            has_input_digest;
  unsigned char  input_digest[32];
  char          *output;        /* the output */
  long           output_size;
  char          *error;         /* the error */
  long           error_size;
  char          *correct;       /* the correct result */
  long           correct_size;
  int            has_correct_digest;
  unsigned char  correct_digest[32];
  int            has_info_digest;
  unsigned char  info_digest[32];
  char          *chk_out;       /* checker's output */
  long           chk_out_size;
  unsigned char *args;          /* command-line arguments */
  unsigned char *comment;       /* judge's comment */
  unsigned char *team_comment;  /* team's comment */
};

int total_tests;
static int tests_a = 0;
static struct testinfo *tests = 0; //[MAX_TEST + 1];

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

static void
html_print_by_line(FILE *f, unsigned char const *s, size_t size)
{
  const unsigned char *p = s;
  const unsigned char * const * trans_table;

  if (global->max_file_length > 0 && size > global->max_file_length) {
    fprintf(f, "(%s, %s = %zu)\n",
            "file is too long", "size", size);
    return;
  }

  if (!s) {
    fprintf(f, "(%s)\n", "file is missing");
    return;
  }

  trans_table = html_get_armor_table();

  while (*s) {
    while (*s && *s != '\r' && *s != '\n') s++;
    if (global->max_line_length > 0 && s - p > global->max_line_length) {
      fprintf(f, "(%s, %s = %td)\n",
              "line is too long", "size", s - p);
    } else {
      while (p != s)
        if (trans_table[*p]) {
          fputs(trans_table[*p], f);
          p++;
        } else {
          putc(*p++, f);
        }
    }
    while (*s == '\r' || *s == '\n')
      putc(*s++, f);
    p = s;
  }
  putc('\n', f);
}

unsigned char *
prepare_checker_comment(const unsigned char *str)
{
  size_t len = strlen(str);
  unsigned char *wstr = alloca(len + 1), *p;

  strcpy(wstr, str);
  for (p = wstr; *p; p++)
    if (*p < ' ') *p = ' ';
  for (--p; p >= wstr && *p == ' '; *p-- = 0);
  if (p - wstr > 64) {
    p = wstr + 60;
    *p++ = '.';
    *p++ = '.';
    *p++ = '.';
    *p = 0;
  }

  return html_armor_string_dup(wstr);
}

static const char * const scoring_system_strs[] =
{
  [SCORE_ACM] "ACM",
  [SCORE_KIROV] "KIROV",
  [SCORE_OLYMPIAD] "OLYMPIAD",
  [SCORE_MOSCOW] "MOSCOW",
};
static const unsigned char *
unparse_scoring_system(unsigned char *buf, size_t size, int val)
{
  if (val >= SCORE_ACM && val < SCORE_TOTAL) return scoring_system_strs[val];
  snprintf(buf, size, "scoring_%d", val);
  return buf;
}

static int
generate_xml_report(struct run_request_packet *req_pkt,
                    struct run_reply_packet *reply_pkt,
                    const unsigned char *report_path,
                    int variant, int scores, int max_score,
                    int correct_available_flag,
                    int info_available_flag,
                    const unsigned char *additional_comment)
{
  FILE *f = 0;
  unsigned char buf1[32], buf2[32], buf3[128];
  int i;
  unsigned char *msg = 0;

  if (!(f = fopen(report_path, "w"))) {
    err("generate_xml_report: cannot open protocol file %s", report_path);
    return -1;
  }

  fprintf(f, "Content-type: text/xml\n\n");
  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\"?>\n", EJUDGE_CHARSET);

  run_status_to_str_short(buf1, sizeof(buf1), reply_pkt->status);
  fprintf(f, "<testing-report run-id=\"%d\" judge-id=\"%d\" status=\"%s\" scoring=\"%s\" archive-available=\"%s\" run-tests=\"%d\"",
          req_pkt->run_id, req_pkt->judge_id, buf1,
          unparse_scoring_system(buf2, sizeof(buf2), req_pkt->scoring_system),
          (req_pkt->full_archive)?"yes":"no", total_tests - 1);
  if (correct_available_flag) {
    fprintf(f, " correct-available=\"yes\"");
  }
  if (info_available_flag) {
    fprintf(f, " info-available=\"yes\"");
  }
  if (variant > 0) {
    fprintf(f, " variant=\"%d\"", variant);
  }
  if (req_pkt->scoring_system == SCORE_OLYMPIAD) {
    fprintf(f, " accepting-mode=\"%s\"", req_pkt->accepting_mode?"yes":"no");
  }
  if (req_pkt->scoring_system == SCORE_OLYMPIAD && req_pkt->accepting_mode
      && reply_pkt->status != RUN_ACCEPTED) {
    fprintf(f, " failed-test=\"%d\"", total_tests - 1);
  } else if (req_pkt->scoring_system == SCORE_ACM && reply_pkt->status != RUN_OK) {
    fprintf(f, " failed-test=\"%d\"", total_tests - 1);
  } else if (req_pkt->scoring_system == SCORE_OLYMPIAD && !req_pkt->accepting_mode) {
    fprintf(f, " tests-passed=\"%d\" score=\"%d\" max-score=\"%d\"",
            reply_pkt->failed_test - 1, reply_pkt->score, max_score);
  } else if (req_pkt->scoring_system == SCORE_KIROV) {
    fprintf(f, " tests-passed=\"%d\" score=\"%d\" max-score=\"%d\"",
            reply_pkt->failed_test - 1, reply_pkt->score, max_score);
  } else if (req_pkt->scoring_system == SCORE_MOSCOW) {
    if (reply_pkt->status != RUN_OK) {
      fprintf(f, " failed-test=\"%d\"", total_tests - 1);
    }
    fprintf(f, " score=\"%d\" max-score=\"%d\"", reply_pkt->score, max_score);
  }
  fprintf(f, " >\n");

  if (additional_comment) {
    msg = html_armor_string_dup(additional_comment);
    fprintf(f, "  <comment>%s</comment>", msg);
    xfree(msg);
  }

  fprintf(f, "  <tests>\n");

  for (i = 1; i < total_tests; i++) {
    run_status_to_str_short(buf1, sizeof(buf1), tests[i].status);
    fprintf(f, "    <test num=\"%d\" status=\"%s\"", i, buf1);
    if (tests[i].status == RUN_RUN_TIME_ERR) {
      if (tests[i].code == 256) {
        fprintf(f, " term-signal=\"%d\"", tests[i].termsig);
      } else {
        fprintf(f, " exit-code=\"%d\"", tests[i].code);
      }
    }
    fprintf(f, " time=\"%lu\"", tests[i].times);
    if (tests[i].real_time > 0) {
      fprintf(f, " real-time=\"%ld\"", tests[i].real_time);
    }
    if (req_pkt->scoring_system == SCORE_OLYMPIAD && !req_pkt->accepting_mode) {
      fprintf(f, " nominal-score=\"%d\" score=\"%d\"",
              tests[i].max_score, tests[i].score);
    } else if (req_pkt->scoring_system == SCORE_KIROV) {
      fprintf(f, " nominal-score=\"%d\" score=\"%d\"",
              tests[i].max_score, tests[i].score);
    }
    if (tests[i].comment && tests[i].comment[0]) {
      msg = html_armor_string_dup(tests[i].comment);
      fprintf(f, " comment=\"%s\"", msg);
      xfree(msg);
    }
    if (tests[i].team_comment && tests[i].team_comment[0]) {
      msg = html_armor_string_dup(tests[i].team_comment);
      fprintf(f, " team-comment=\"%s\"", msg);
      xfree(msg);
    }
    if ((tests[i].status == RUN_WRONG_ANSWER_ERR 
         || tests[i].status == RUN_PRESENTATION_ERR || tests[i].status == RUN_OK)
        && tests[i].chk_out_size > 0 && tests[i].chk_out && tests[i].chk_out[0]) {
      msg = prepare_checker_comment(tests[i].chk_out);
      fprintf(f, " checker-comment=\"%s\"", msg);
      xfree(msg);
    }
    if (req_pkt->full_archive) {
      if (tests[i].has_input_digest) {
        digest_to_ascii(DIGEST_SHA1, tests[i].input_digest, buf3);
        fprintf(f, " input-digest=\"%s\"", buf3);
      }
      if (tests[i].has_correct_digest) {
        digest_to_ascii(DIGEST_SHA1, tests[i].correct_digest, buf3);
        fprintf(f, " correct-digest=\"%s\"", buf3);
      }
      if (tests[i].has_info_digest) {
        digest_to_ascii(DIGEST_SHA1, tests[i].info_digest, buf3);
        fprintf(f, " info-digest=\"%s\"", buf3);
      }
    }
    if (tests[i].output_size >= 0 && req_pkt->full_archive) {
      fprintf(f, " output-available=\"yes\"");
    }
    if (tests[i].error_size >= 0 && req_pkt->full_archive) {
      fprintf(f, " stderr-available=\"yes\"");
    }
    if (tests[i].chk_out_size >= 0 && req_pkt->full_archive) {
      fprintf(f, " checker-output-available=\"yes\"");
    }
    if (tests[i].args && strlen(tests[i].args) >= global->max_cmd_length) {
      fprintf(f, " args-too-long=\"yes\"");
    }
    fprintf(f, " >\n");

    if (tests[i].args && strlen(tests[i].args) < global->max_cmd_length) {
      msg = html_armor_string_dup(tests[i].args);
      fprintf(f, "      <args>%s</args>\n", msg);
      xfree(msg);
    }

    if (tests[i].input_size >= 0 && !req_pkt->full_archive) {
      fprintf(f, "      <input>");
      html_print_by_line(f, tests[i].input, tests[i].input_size);
      fprintf(f, "</input>\n");
    }

    if (tests[i].output_size >= 0 && !req_pkt->full_archive) {
      fprintf(f, "      <output>");
      html_print_by_line(f, tests[i].output, tests[i].output_size);
      fprintf(f, "</output>\n");
    }

    if (tests[i].correct_size >= 0 && !req_pkt->full_archive) {
      fprintf(f, "      <correct>");
      html_print_by_line(f, tests[i].correct, tests[i].correct_size);
      fprintf(f, "</correct>\n");
    }

    if (tests[i].error_size >= 0 && !req_pkt->full_archive) {
      fprintf(f, "      <stderr>");
      html_print_by_line(f, tests[i].error, tests[i].error_size);
      fprintf(f, "</stderr>\n");
    }

    if (tests[i].chk_out_size >= 0 && !req_pkt->full_archive) {
      fprintf(f, "      <checker>");
      html_print_by_line(f, tests[i].chk_out, tests[i].chk_out_size);
      fprintf(f, "</checker>\n");
    }

    fprintf(f, "    </test>\n");
  }

  fprintf(f, "  </tests>\n");

  fprintf(f, "</testing-report>\n");
  fclose(f); f = 0;
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

static void
append_msg_to_log(const unsigned char *path, char *format, ...)
  __attribute__((format(printf, 2, 3)));
static void
append_msg_to_log(const unsigned char *path, char *format, ...)
{
  va_list args;
  unsigned char buf[1024];
  FILE *f;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (!(f = fopen(path, "a"))) {
    err("append_msg_to_log: cannot open %s for appending", path);
    return;
  }
  fprintf(f, "\n\nrun: %s\n", buf);
  if (ferror(f)) {
    err("append_msg_to_log: write error to %s", path);
    fclose(f);
    return;
  }
  if (fclose(f) < 0) {
    err("append_msg_to_log: write error to %s", path);
    return;
  }
}

static int
run_tests(struct section_tester_data *tst,
          struct run_request_packet *req_pkt,
          struct run_reply_packet *reply_pkt,
          int score_system_val,
          int accept_testing,
          int accept_partial,
          int cur_variant,
          char const *new_name,
          char const *new_base,
          char *report_path,                /* path to the report */
          char *full_report_path,           /* path to the full output dir */
          const unsigned char *user_spelling,
          const unsigned char *problem_spelling)
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
  path_t info_src;
  path_t tgz_src;
  path_t tgz_src_dir;
  path_t input_path;
  path_t output_path;
  path_t error_path;
  path_t check_out_path;
  path_t error_code;
  path_t prog_working_dir;
  int    score = 0;
  int    status = 0;
  int    failed_test = 0;
  int    total_failed_tests = 0;
  int    ec = -100;            /* FIXME: magic */
  struct section_problem_data *prb;
  char *sound;
  unsigned char *var_test_dir;
  unsigned char *var_corr_dir;
  unsigned char *var_info_dir = 0;
  unsigned char *var_tgz_dir = 0;
  unsigned char *var_check_cmd;
  testinfo_t tstinfo;
  int errcode;
  int time_limit_value;
  unsigned char ejudge_prefix_dir_env[1024] = { 0 };
  ssize_t file_size;
  unsigned char arch_entry_name[64];
  full_archive_t far = 0;
  unsigned char *additional_comment = 0;
  int jj;

#ifdef HAVE_TERMIOS_H
  struct termios term_attrs;
#endif

  ASSERT(tst->problem > 0);
  ASSERT(tst->problem <= max_prob);
  ASSERT(probs[tst->problem]);
  prb = probs[tst->problem];

#ifdef EJUDGE_PREFIX_DIR
  snprintf(ejudge_prefix_dir_env, sizeof(ejudge_prefix_dir_env),
           "EJUDGE_PREFIX_DIR=%s", EJUDGE_PREFIX_DIR);
#endif /* EJUDGE_PREFIX_DIR */

  if (cur_variant > 0) {
    var_test_dir = (unsigned char*) alloca(sizeof(path_t));
    var_corr_dir = (unsigned char*) alloca(sizeof(path_t));
    snprintf(var_test_dir, sizeof(path_t), "%s-%d", prb->test_dir,cur_variant);
    snprintf(var_corr_dir, sizeof(path_t), "%s-%d", prb->corr_dir,cur_variant);
    if (prb->use_info) {
      var_info_dir = (unsigned char*) alloca(sizeof(path_t));
      snprintf(var_info_dir,sizeof(path_t),"%s-%d",prb->info_dir,cur_variant);
    }
    if (prb->use_tgz) {
      var_tgz_dir = (unsigned char*) alloca(sizeof(path_t));
      snprintf(var_tgz_dir, sizeof(path_t), "%s-%d", prb->tgz_dir,cur_variant);
    }
  } else {
    var_test_dir = prb->test_dir;
    var_corr_dir = prb->corr_dir;
    if (prb->use_info) {
      var_info_dir = prb->info_dir;
    }
    if (prb->use_tgz) {
      var_tgz_dir = prb->tgz_dir;
    }
  }

  pathmake(report_path, global->run_work_dir, "/", "report", NULL);
  full_report_path[0] = 0;
  if (req_pkt->full_archive) {
    pathmake(full_report_path, global->run_work_dir, "/", "full_output", NULL);
    far = full_archive_open_write(full_report_path);
  }

  memset(tests, 0, sizeof(tests[0]) * tests_a);
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
  if (prb->use_tgz) {
#ifdef __WIN32__
    snprintf(arg0_path, sizeof(arg0_path), "%s%s..%s%s", tst->check_dir,
             CONF_DIRSEP, CONF_DIRSEP, new_name);
#else
    snprintf(arg0_path, sizeof(arg0_path), "../%s", new_name);
#endif
  } else {
#ifdef __WIN32__
    snprintf(arg0_path, sizeof(arg0_path), "%s", exe_path);
#else
    snprintf(arg0_path, sizeof(arg0_path), "./%s", new_name);
#endif
  }
  
  if (tst->is_dos && !prb->binary_input) copy_flag = CONVERT;

  error_code[0] = 0;
  if (tst->errorcode_file[0]) {
    pathmake(error_code, tst->check_dir, "/", tst->errorcode_file, 0);
  }

  while (1) {
    if (score_system_val == SCORE_OLYMPIAD
        && accept_testing
        && cur_test > prb->tests_to_accept) break;

    if (prb->test_pat[0]) {
      sprintf(test_base, prb->test_pat, cur_test);
    } else {
      sprintf(test_base, "%03d%s", cur_test, prb->test_sfx);
    }
    if (prb->corr_pat[0]) {
      sprintf(corr_base, prb->corr_pat, cur_test);
    } else {
      sprintf(corr_base, "%03d%s", cur_test, prb->corr_sfx);
    }
    pathmake(test_src, var_test_dir, "/", test_base, NULL);
    if (os_CheckAccess(test_src, REUSE_R_OK) < 0) {
      // testing is done as no tests left in the testing directory
      break;
    }

    tests[cur_test].input_size = -1;
    tests[cur_test].output_size = -1;
    tests[cur_test].error_size = -1;
    tests[cur_test].correct_size = -1;
    tests[cur_test].chk_out_size = -1;

    /* Load test information file */
    if (prb->use_info) {
      if (prb->info_pat[0]) {
        unsigned char info_base[64];
        snprintf(info_base, sizeof(info_base), prb->info_pat, cur_test);
        snprintf(info_src, sizeof(path_t), "%s/%s", var_info_dir, info_base);
      } else {
        snprintf(info_src, sizeof(path_t), "%s/%03d%s",
                 var_info_dir, cur_test, prb->info_sfx);
      }
      if ((errcode = testinfo_parse(info_src, &tstinfo)) < 0) {
        err("Cannot parse test info file '%s': %s", info_src,
            testinfo_strerror(-errcode));
        failed_test = cur_test;
        status = RUN_CHECK_FAILED;
        total_failed_tests++;
        goto done_this_test;
      }
    }

    make_writable(tst->check_dir);
    clear_directory(tst->check_dir);

    /* copy the executable */
    generic_copy_file(0, global->run_work_dir, new_name, "",
                      0, tst->check_dir, new_name, "");
    make_executable(exe_path);

    if (!prb->use_tgz) {
      snprintf(prog_working_dir, sizeof(path_t), "%s", tst->check_dir);
    }
    if (prb->use_tgz) {
      snprintf(tgz_src, sizeof(path_t), "%s/%03d%s",
               var_tgz_dir, cur_test, prb->tgz_sfx);
      snprintf(tgz_src_dir, sizeof(path_t), "%s/%03d",
               var_tgz_dir, cur_test);
      snprintf(prog_working_dir, sizeof(path_t), "%s/%03d",
               tst->check_dir, cur_test);
      info("starting: %s", "/bin/tar");
      tsk = task_New();
      task_AddArg(tsk, "/bin/tar");
      task_AddArg(tsk, "xfz");
      task_AddArg(tsk, tgz_src);
      task_SetPathAsArg0(tsk);
      task_SetWorkingDir(tsk, tst->check_dir);
      task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
      task_SetRedir(tsk, 1, TSR_FILE, report_path, TSK_REWRITE, TSK_FULL_RW);
      task_SetRedir(tsk, 2, TSR_DUP, 1);
      task_Start(tsk);
      task_Wait(tsk);
      if (task_IsAbnormal(tsk)) {
        failed_test = cur_test;
        status = RUN_CHECK_FAILED;
        total_failed_tests++;
        goto done_this_test;
      }
      task_Delete(tsk); tsk = 0;
    }

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
    if (prb->use_info && tstinfo.cmd_argc >= 1) {
      task_pnAddArgs(tsk, tstinfo.cmd_argc, (char**) tstinfo.cmd_argv);
    }
    task_SetPathAsArg0(tsk);
    task_SetWorkingDir(tsk, prog_working_dir);
    if (!tst->no_redirect || managed_mode_flag) {
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
      for (jj = 0; tst->start_env[jj]; jj++) {
        if (!strcmp(tst->start_env[jj], "EJUDGE_PREFIX_DIR")) {
          task_PutEnv(tsk, ejudge_prefix_dir_env);
        } else {
          task_PutEnv(tsk, tst->start_env[jj]);
        }
      }
    }
    if (prb->time_limit_millis > 0) {
#if defined HAVE_TASK_SETMAXTIMEMILLIS
      time_limit_value = prb->time_limit_millis;
      if (tst->time_limit_adjustment > 0)
        time_limit_value += tst->time_limit_adjustment * 1000;
      if (req_pkt->time_limit_adj > 0)
        time_limit_value += req_pkt->time_limit_adj * 1000;
      task_SetMaxTimeMillis(tsk, time_limit_value);
#else
      time_limit_value = (prb->time_limit_millis + 999) / 1000;;
      if (tst->time_limit_adjustment > 0)
        time_limit_value += tst->time_limit_adjustment;
      if (req_pkt->time_limit_adj > 0)
        time_limit_value += req_pkt->time_limit_adj;
      task_SetMaxTime(tsk, time_limit_value);
#endif
    } else if (prb->time_limit > 0) {
      time_limit_value = prb->time_limit;
      if (tst->time_limit_adjustment > 0)
        time_limit_value += tst->time_limit_adjustment;
      if (req_pkt->time_limit_adj > 0)
        time_limit_value += req_pkt->time_limit_adj;
      task_SetMaxTime(tsk, time_limit_value);
    }
    if (prb->real_time_limit>0) task_SetMaxRealTime(tsk,prb->real_time_limit);
    if (tst->kill_signal[0]) task_SetKillSignal(tsk, tst->kill_signal);
    if (tst->no_core_dump) task_DisableCoreDump(tsk);
    // debugging
#if 0
    if (tst->max_vm_size == -1L)
      fprintf(stderr,">>max_vm_size == -1\n");
    else
      fprintf(stderr, ">>max_vm_size == %zu\n", tst->max_vm_size);
    if (tst->max_stack_size == -1L)
      fprintf(stderr, ">>max_stack_size == -1\n");
    else
      fprintf(stderr, ">>max_stack_size == %zu\n", tst->max_stack_size);
#endif
    if (tst->max_stack_size && tst->max_stack_size != -1L)
      task_SetStackSize(tsk, tst->max_stack_size);
    if (tst->max_data_size && tst->max_data_size != -1L)
      task_SetDataSize(tsk, tst->max_data_size);
    if (tst->max_vm_size && tst->max_vm_size != -1L)
      task_SetVMSize(tsk, tst->max_vm_size);
#if defined HAVE_TASK_ENABLEMEMORYLIMITERROR
    if (tst->enable_memory_limit_error && req_pkt->memory_limit) {
      task_EnableMemoryLimitError(tsk);
    }
#endif

#ifdef HAVE_TERMIOS_H
    memset(&term_attrs, 0, sizeof(term_attrs));
    if (tst->no_redirect && isatty(0) && !managed_mode_flag) {
      /* we need to save terminal state since if the program
       * is killed with SIGKILL, the terminal left in random state
       */
      if (tcgetattr(0, &term_attrs) < 0) {
        err("tcgetattr failed: %s", os_ErrorMsg());
      }
    }
#endif

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
#ifdef HAVE_TERMIOS_H
      if (tst->no_redirect && isatty(0) && !managed_mode_flag) {
        if (tcsetattr(0, TCSADRAIN, &term_attrs) < 0)
          err("tcsetattr failed: %s", os_ErrorMsg());
      }
#endif

      /* set normal permissions for the working directory */
      make_writable(tst->check_dir);
      /* make the output file readable */
      if (chmod(output_path, 0600) < 0) {
        err("chmod failed: %s", os_ErrorMsg());
      }

      /* fill test report structure */
      tests[cur_test].times = task_GetRunningTime(tsk);
#if defined HAVE_TASK_GETREALTIME
      tests[cur_test].real_time = task_GetRealTime(tsk);
#endif
      if (req_pkt->full_archive) {
        filehash_get(test_src, tests[cur_test].input_digest);
        tests[cur_test].has_input_digest = 1;
      } else {
        file_size = generic_file_size(0, test_src, 0);
        if (file_size >= 0) {
          tests[cur_test].input_size = file_size;
          if (global->max_file_length > 0
              && file_size <= global->max_file_length) {
            generic_read_file(&tests[cur_test].input, 0, 0, 0,
                              0, test_src, "");
          }
        }
      }
      file_size = generic_file_size(0, output_path, 0);
      if (file_size >= 0) {
        tests[cur_test].output_size = file_size;
        if (global->max_file_length > 0 && !req_pkt->full_archive
            && file_size <= global->max_file_length) {
          generic_read_file(&tests[cur_test].output, 0, 0, 0,
                            0, output_path, "");
        }
        if (far) {
          snprintf(arch_entry_name, sizeof(arch_entry_name),
                   "%06d.o", cur_test);
          //info("appending program output to archive");
          full_archive_append_file(far, arch_entry_name, 0, output_path);
        }
      }
      file_size = generic_file_size(0, error_path, 0);
      if (file_size >= 0) {
        tests[cur_test].error_size = file_size;
        if (global->max_file_length > 0 && !req_pkt->full_archive
            && file_size <= global->max_file_length) {
          generic_read_file(&tests[cur_test].error, 0, 0, 0,
                            0, error_path, "");
        }
        if (far) {
          snprintf(arch_entry_name, sizeof(arch_entry_name),
                   "%06d.e", cur_test);
          //info("appending program error stream to archive");
          full_archive_append_file(far, arch_entry_name, 0, error_path);
        }
      }
      if (prb->use_info) {
        size_t cmd_args_len = 0;
        int i;
        unsigned char *args = 0, *s;

        if (req_pkt->full_archive) {
          filehash_get(info_src, tests[cur_test].info_digest);
          tests[cur_test].has_info_digest = 1;
        }

        for (i = 0; i < tstinfo.cmd_argc; i++) {
          cmd_args_len += 16;
          if (tstinfo.cmd_argv[i]) {
            cmd_args_len += strlen(tstinfo.cmd_argv[i]);
          }
        }
        if (cmd_args_len > 0) {
          s = args = (unsigned char *) xmalloc(cmd_args_len + 16);
          for (i = 0; i < tstinfo.cmd_argc; i++) {
            if (tstinfo.cmd_argv[i]) {
              s += sprintf(s, "[%3d]: >%s<\n", i + 1, tstinfo.cmd_argv[i]);
            } else {
              s += sprintf(s, "[%3d]: NULL\n", i + 1);
            }
          }
        }
        tests[cur_test].args = args;
        if (tstinfo.comment) {
          tests[cur_test].comment = xstrdup(tstinfo.comment);
        }
        if (tstinfo.team_comment) {
          tests[cur_test].team_comment = xstrdup(tstinfo.team_comment);
        }
      }

      task_Log(tsk, 0, LOG_INFO);

#if defined HAVE_TASK_ISMEMORYLIMIT
      if (tst->enable_memory_limit_error && req_pkt->memory_limit
          && task_IsMemoryLimit(tsk)) {
        failed_test = cur_test;
        status = RUN_MEM_LIMIT_ERR;
        total_failed_tests++;
        task_Delete(tsk); tsk = 0;
      } else
#endif
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

        if (prb->variant_num > 0 && !tst->standard_checker_used) {
          var_check_cmd = (unsigned char*) alloca(sizeof(path_t));
          snprintf(var_check_cmd, sizeof(path_t),
                   "%s-%d", tst->check_cmd, cur_variant);
        } else {
          var_check_cmd = tst->check_cmd;
        }

        /* now start checker */
        /* checker <input data> <output result> <corr answer> <info file> */
        info("starting checker: %s %s %s", var_check_cmd, test_src,
             prb->output_file);

        tsk = task_New();
        task_AddArg(tsk, var_check_cmd);
        task_AddArg(tsk, test_src);
        task_AddArg(tsk, prb->output_file);
        if (prb->use_corr && prb->corr_dir[0]) {
          pathmake3(corr_path, var_corr_dir, "/", corr_base, NULL);
          task_AddArg(tsk, corr_path);
          if (req_pkt->full_archive) {
            filehash_get(corr_path, tests[cur_test].correct_digest);
            tests[cur_test].has_correct_digest = 1;
          } else {
            file_size = generic_file_size(0, corr_path, 0);
            if (file_size >= 0) {
              tests[cur_test].correct_size = file_size;
              if (global->max_file_length > 0
                  && file_size <= global->max_file_length) {
                generic_read_file(&tests[cur_test].correct, 0, 0, 0,
                                  0, corr_path, "");
              }
            }
          }
        }
        if (prb->use_info) {
          task_AddArg(tsk, info_src);
        }
        if (prb->use_tgz) {
          task_AddArg(tsk, tgz_src_dir);
          task_AddArg(tsk, prog_working_dir);
        }
        task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
        task_SetRedir(tsk, 1, TSR_FILE, check_out_path,
                      TSK_REWRITE, TSK_FULL_RW);
        task_SetRedir(tsk, 2, TSR_DUP, 1);
        task_SetWorkingDir(tsk, tst->check_dir);
        task_SetPathAsArg0(tsk);
        if (prb->checker_real_time_limit > 0) {
          task_SetMaxRealTime(tsk, prb->checker_real_time_limit);
        }
        if (prb->checker_env) {
          for (jj = 0; prb->checker_env[jj]; jj++)
            task_PutEnv(tsk, prb->checker_env[jj]);
        }
        if (tst->checker_env) {
          for (jj = 0; tst->checker_env[jj]; jj++)
            task_PutEnv(tsk, tst->checker_env[jj]);
        }

        task_Start(tsk);
        task_Wait(tsk);
        if (task_IsTimeout(tsk)) {
          append_msg_to_log(check_out_path, "checker timeout");
          err("checker timeout");
        } else {
          task_Log(tsk, 0, LOG_INFO);
          if (task_Status(tsk) == TSK_SIGNALED) {
            jj = task_TermSignal(tsk);
            append_msg_to_log(check_out_path,
                              "checker terminated with signal %d (%s)",
                              jj, os_GetSignalString(jj));
          } else {
            jj = task_ExitCode(tsk);
            if (jj != RUN_OK && jj != RUN_PRESENTATION_ERR
                && jj != RUN_WRONG_ANSWER_ERR) {
              append_msg_to_log(check_out_path,
                                "checker exited with code %d", jj);
            }
          }
        }

        file_size = generic_file_size(0, check_out_path, 0);
        if (file_size >= 0) {
          tests[cur_test].chk_out_size = file_size;
          if (!req_pkt->full_archive) {
            generic_read_file(&tests[cur_test].chk_out, 0, 0, 0, 0, check_out_path, "");
          }
          if (far) {
            snprintf(arch_entry_name, sizeof(arch_entry_name),
                     "%06d.c", cur_test);
            //info("appending checker output to archive");
            full_archive_append_file(far, arch_entry_name, 0, check_out_path);
          }
        }

        /* analyze error codes */
        if (task_IsTimeout(tsk)) {
          status = RUN_CHECK_FAILED;
          failed_test = cur_test;
        } else if (task_Status(tsk) == TSK_SIGNALED) {
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

  done_this_test:
    if (prb->use_info) {
      testinfo_free(&tstinfo);
    }
    tests[cur_test].status = status;
    cur_test++;
    total_tests++;
    if (status > 0) {
      // test failed, how to react on this
      if (score_system_val == SCORE_ACM) break;
      if (score_system_val == SCORE_MOSCOW) break;
      if (score_system_val == SCORE_OLYMPIAD
          && accept_testing && !accept_partial) break;
    }
    clear_directory(tst->check_dir);
  }

  /* TESTING COMPLETED (SOMEHOW) */

  if (score_system_val == SCORE_OLYMPIAD && accept_testing) {
    if (accept_partial) {
      status = RUN_ACCEPTED;
      failed_test = 1;
      for (jj = 1; jj <= prb->tests_to_accept; jj++) {
        if (tests[jj].status == RUN_OK)
          failed_test++;
        else if (tests[jj].status == RUN_CHECK_FAILED)
          status = RUN_CHECK_FAILED;
      }
    } else {
      if (!failed_test) { 
        status = RUN_ACCEPTED;
        failed_test = cur_test;
      }
    }
    reply_pkt->status = status;
    reply_pkt->failed_test = failed_test;
    reply_pkt->score = -1;
    get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);
  } else if (score_system_val == SCORE_KIROV
             || score_system_val == SCORE_OLYMPIAD) {
    int retcode = RUN_OK;

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

      /* check testsets */
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
        // set additional judging comment
        {
          unsigned char *outp, first_item = 1;
          outp = additional_comment = alloca(ti->total * 64 + 128);

          outp += sprintf(outp, "Test set {");
          for (jj = 0; jj < ti->total; jj++) {
            if (!ti->nums[jj]) continue;
            if (!first_item) {
              outp += sprintf(outp, ",");
              first_item = 0;
            }
            outp += sprintf(outp, " %d", jj + 1);
          }
          outp += sprintf(outp, " } is scored as %d\n", ti->score);
        }
      }
    }

    if (!total_failed_tests) score = prb->full_score;

    /* ATTENTION: number of passed test returned is greater than actual by 1,
     * and it is returned in the `failed_test' field
     */
    reply_pkt->status = retcode;
    reply_pkt->failed_test = total_tests - total_failed_tests;
    reply_pkt->score = score;
    get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);

    if (global->sound_player[0] && global->extended_sound && !req_pkt->disable_sound) {
      unsigned char b1[64], b2[64], b3[64];

      snprintf(b1, sizeof(b1), "%d", retcode);
      snprintf(b2, sizeof(b2), "%d", total_tests - total_failed_tests - 1);
      snprintf(b3, sizeof(b3), "%d", score);

      tsk = task_New();
      task_AddArg(tsk, global->sound_player);
      task_AddArg(tsk, b1);
      task_AddArg(tsk, b2);
      task_AddArg(tsk, user_spelling);
      task_AddArg(tsk, problem_spelling);
      task_AddArg(tsk, b3);
      task_SetPathAsArg0(tsk);
      task_Start(tsk);
      task_Wait(tsk);
      task_Delete(tsk);
      tsk = 0;
    }
  } else {
    // ACM, MOSCOW scoring system
    reply_pkt->status = status;
    reply_pkt->failed_test = failed_test;
    reply_pkt->score = -1;
    if (score_system_val == SCORE_MOSCOW) {
      reply_pkt->score = prb->full_score;
      if (status != RUN_OK) {
        int s;

        ASSERT(failed_test <= prb->ntests && failed_test > 0);
        for (s = 0; failed_test > prb->x_score_tests[s]; s++);
        reply_pkt->score = s;
      }
    }
    get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);

    if (global->sound_player[0] && global->extended_sound && !req_pkt->disable_sound) {
      unsigned char b1[64], b2[64];

      snprintf(b1, sizeof(b1), "%d", status);
      snprintf(b2, sizeof(b2), "%d", failed_test);

      tsk = task_New();
      task_AddArg(tsk, global->sound_player);
      task_AddArg(tsk, b1);
      task_AddArg(tsk, b2);
      task_AddArg(tsk, user_spelling);
      task_AddArg(tsk, problem_spelling);
      task_SetPathAsArg0(tsk);
      task_Start(tsk);
      task_Wait(tsk);
      task_Delete(tsk);
      tsk = 0;
    } else if (global->sound_player[0] && !req_pkt->disable_sound) {
      // play funny sound
      sound = 0;
      switch (status) {
      case RUN_TIME_LIMIT_ERR:   sound = global->timelimit_sound;    break;
      case RUN_RUN_TIME_ERR:     sound = global->runtime_sound;      break;
      case RUN_CHECK_FAILED:     sound = global->internal_sound;     break;
      case RUN_PRESENTATION_ERR: sound = global->presentation_sound; break;
      case RUN_WRONG_ANSWER_ERR: sound = global->wrong_sound;        break;
      case RUN_OK:               sound = global->accept_sound;       break;
      }
      if (sound && !*sound) sound = 0;

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
  }

  get_current_time(&reply_pkt->ts7, &reply_pkt->ts7_us);

  generate_xml_report(req_pkt, reply_pkt, report_path, cur_variant,
                      score, prb->full_score,
                      (prb->use_corr && prb->corr_dir[0]), prb->use_info,
                      additional_comment);

  goto _cleanup;

 _internal_execution_error:
  reply_pkt->status = RUN_CHECK_FAILED;
  reply_pkt->failed_test = 0;
  reply_pkt->score = -1;
  get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);
  reply_pkt->ts7 = reply_pkt->ts6;
  reply_pkt->ts7_us = reply_pkt->ts6_us;
  goto _cleanup;

 _cleanup:
  if (far) full_archive_close(far);
  if (tsk) task_Delete(tsk);
  tsk = 0;
  clear_directory(tst->check_dir);
  for (cur_test = 1; cur_test < total_tests; cur_test++) {
    xfree(tests[cur_test].input);
    xfree(tests[cur_test].output);
    xfree(tests[cur_test].error);
    xfree(tests[cur_test].chk_out);
    xfree(tests[cur_test].correct);
    xfree(tests[cur_test].args);
    xfree(tests[cur_test].comment);
    xfree(tests[cur_test].team_comment);
    memset(&tests[cur_test], 0, sizeof(tests[cur_test]));
  }
  return 0;
}

static int
do_loop(void)
{
  int r;

  path_t report_path;
  path_t full_report_path;

  unsigned char pkt_name[64];
  unsigned char exe_pkt_name[64];
  unsigned char run_base[64];
  path_t full_report_dir;
  path_t full_status_dir;
  path_t full_full_dir;

  char   exe_name[64];
  int    tester_id;
  struct section_tester_data tn, *tst;
  int got_quit_packet = 0;

  char *req_buf = 0;            /* char* is needed for generic_read_file */
  size_t req_buf_size = 0;
  struct run_request_packet *req_pkt = 0;
  struct section_problem_data *cur_prob = 0;
  struct run_reply_packet reply_pkt;
  void *reply_pkt_buf = 0;
  size_t reply_pkt_buf_size = 0;
  unsigned char errmsg[512];

  memset(&tn, 0, sizeof(tn));

  if (cr_serialize_init() < 0) return -1;
  interrupt_init();
  interrupt_disable();

  while (1) {
    interrupt_enable();
    /* time window for immediate signal delivery */
    interrupt_disable();

    // terminate, if signaled
    if (interrupt_get_status()) break;

    r = scan_dir(global->run_queue_dir, pkt_name);
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

    req_pkt = run_request_packet_free(req_pkt);
    xfree(req_buf), req_buf = 0;
    req_buf_size = 0;

    r = generic_read_file(&req_buf, 0, &req_buf_size, SAFE | REMOVE,
                          global->run_queue_dir, pkt_name, "");
    if (r == 0) continue;
    if (r < 0) return -1;

    if (run_request_packet_read(req_buf_size, req_buf, &req_pkt) < 0) {
      /* the request packet is broken. ignore it */
      continue;
    }
    if (managed_mode_flag && req_pkt->contest_id == -1) {
      got_quit_packet = 1;
      info("got force quit run packet");
      continue;
    }
    if (req_pkt->contest_id == -1) {
      r = generic_write_file(req_buf, req_buf_size, SAFE,
                             global->run_queue_dir, pkt_name, "");
      if (r < 0) return -1;
      info("force quit packet is ignored in unmanaged mode");
      scan_dir_add_ignored(global->run_queue_dir, pkt_name);
      continue;
    }

    if (req_pkt->problem_id > max_prob || !probs[req_pkt->problem_id]) {
      snprintf(errmsg, sizeof(errmsg),
               "problem %d is unknown to the run program\n",
               req_pkt->problem_id);
      goto report_check_failed_and_continue;
    }
    cur_prob = probs[req_pkt->problem_id];

    /* if we are asked to do full testing, but don't want */
    if ((global->skip_full_testing > 0 && !req_pkt->accepting_mode)
        || (global->skip_accept_testing > 0 && req_pkt->accepting_mode)) {
      r = generic_write_file(req_buf, req_buf_size, SAFE,
                             global->run_queue_dir, pkt_name, "");
      if (r < 0) return -1;
      info("skipping problem %s", cur_prob->short_name);
      scan_dir_add_ignored(global->run_queue_dir, pkt_name);
      continue;
    }

    /* if this problem is marked as "skip_testing" put the
     * packet back to the spool directory
     */
    if (cur_prob->skip_testing > 0) {
      r = generic_write_file(req_buf, req_buf_size, SAFE,
                             global->run_queue_dir, pkt_name, "");
      if (r < 0) return -1;
      info("skipping problem %s", cur_prob->short_name);
      scan_dir_add_ignored(global->run_queue_dir, pkt_name);
      continue;
    }

    if (cur_prob->variant_num <= 0 && req_pkt->variant != 0) {
      snprintf(errmsg, sizeof(errmsg),
               "problem %d has no variants, but one was specified\n",
               req_pkt->problem_id);
      goto report_check_failed_and_continue;
    }
    if (cur_prob->variant_num > 0
        &&(req_pkt->variant <= 0 || req_pkt->variant > cur_prob->variant_num)) {
      snprintf(errmsg, sizeof(errmsg),
               "problem %d has variants, but no variant was specified\n",
               req_pkt->problem_id);
      goto report_check_failed_and_continue;
    }
    if (!(tester_id = find_tester(req_pkt->problem_id, req_pkt->arch))) {
      snprintf(errmsg, sizeof(errmsg),
               "no tester found for %d, %s\n",
               req_pkt->problem_id, req_pkt->arch);
      goto report_check_failed_and_continue;
    }

    info("fount tester %d for pair %d,%s", tester_id,req_pkt->problem_id,req_pkt->arch);
    tst = testers[tester_id];

    /* if this tester is marked as "skip_testing" put the
     * packet back to the spool directory
     */
    if (tst->skip_testing > 0) {
      r = generic_write_file(req_buf, req_buf_size, SAFE,
                             global->run_queue_dir, pkt_name, "");
      if (r < 0) return -1;
      info("skipping tester <%s,%s>", cur_prob->short_name, tst->arch);
      scan_dir_add_ignored(global->run_queue_dir, pkt_name);
      continue;
    }

    if (tst->any) {
      info("tester %d is a default tester", tester_id);
      r = prepare_tester_refinement(&tn, tester_id, req_pkt->problem_id);
      ASSERT(r >= 0);
      tst = &tn;
    }

    snprintf(exe_pkt_name, sizeof(exe_pkt_name), "%s%s", pkt_name, req_pkt->exe_sfx);
    snprintf(run_base, sizeof(run_base), "%06d", req_pkt->run_id);
    snprintf(exe_name, sizeof(exe_name), "%s%s", run_base, req_pkt->exe_sfx);

    r = generic_copy_file(REMOVE, global->run_exe_dir, exe_pkt_name, "",
                          0, global->run_work_dir, exe_name, "");
    if (r <= 0) {
      snprintf(errmsg, sizeof(errmsg),
               "failed to copy executable file %s/%s\n",
               global->run_exe_dir, exe_pkt_name);
      goto report_check_failed_and_continue;
    }

    report_path[0] = 0;
    full_report_path[0] = 0;

    /* start filling run_reply_packet */
    memset(&reply_pkt, 0, sizeof(reply_pkt));
    reply_pkt.judge_id = req_pkt->judge_id;
    reply_pkt.contest_id = req_pkt->contest_id;
    reply_pkt.run_id = req_pkt->run_id;
    reply_pkt.ts1 = req_pkt->ts1;
    reply_pkt.ts1_us = req_pkt->ts1_us;
    reply_pkt.ts2 = req_pkt->ts2;
    reply_pkt.ts2_us = req_pkt->ts2_us;
    reply_pkt.ts3 = req_pkt->ts3;
    reply_pkt.ts3_us = req_pkt->ts3_us;
    reply_pkt.ts4 = req_pkt->ts4;
    reply_pkt.ts4_us = req_pkt->ts4_us;
    get_current_time(&reply_pkt.ts5, &reply_pkt.ts5_us);

    if (cr_serialize_lock() < 0) return -1;
    if (run_tests(tst, req_pkt, &reply_pkt,
                  req_pkt->scoring_system, req_pkt->accepting_mode,
                  req_pkt->accept_partial, req_pkt->variant,
                  exe_name, run_base,
                  report_path, full_report_path,
                  req_pkt->user_spelling, req_pkt->prob_spelling) < 0) {
      cr_serialize_unlock();
      return -1;
    }
    if (cr_serialize_unlock() < 0) return -1;

    if (tst == &tn) {
      sarray_free(tst->start_env);
    }

    snprintf(full_report_dir, sizeof(full_report_dir),
             "%s/%06d/report", global->run_dir, req_pkt->contest_id);
    snprintf(full_status_dir, sizeof(full_status_dir),
             "%s/%06d/status", global->run_dir, req_pkt->contest_id);
    snprintf(full_full_dir, sizeof(full_full_dir),
             "%s/%06d/output", global->run_dir, req_pkt->contest_id);
             
    if (generic_copy_file(0, NULL, report_path, "",
                          0, full_report_dir, run_base, "") < 0)
      return -1;
    if (full_report_path[0]
        && generic_copy_file(0, NULL, full_report_path, "",
                             0, full_full_dir,
                             run_base, "") < 0)
      return -1;
    
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
    reply_pkt.judge_id = req_pkt->judge_id;
    reply_pkt.contest_id = req_pkt->contest_id;
    reply_pkt.run_id = req_pkt->run_id;
    reply_pkt.ts1 = req_pkt->ts1;
    reply_pkt.ts1_us = req_pkt->ts1_us;
    reply_pkt.ts2 = req_pkt->ts2;
    reply_pkt.ts2_us = req_pkt->ts2_us;
    reply_pkt.ts3 = req_pkt->ts3;
    reply_pkt.ts3_us = req_pkt->ts3_us;
    reply_pkt.ts4 = req_pkt->ts4;
    reply_pkt.ts4_us = req_pkt->ts4_us;
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
      os_snprintf(path, PATH_MAX, "%s%s%s", dir, PATH_SEP, file_base);
    } else {
      os_snprintf(path, PATH_MAX, "%s%s%03d%s", dir, PATH_SEP, n, sfx);
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
  int i, j, k, n;
  unsigned char *prob_flags = 0;
  unsigned char *var_check_cmd = 0;
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
      if (ts->disable_testing) continue;

      // so at this point: tp - pointer to the default tester,
      // k is the problem number
      // ts - pointer to the problem which should be handled by the
      // default tester
      if (prepare_tester_refinement(&tn, i, k) < 0) return -1;
      if (create_tester_dirs(&tn) < 0) return -1;

      if (ts->variant_num > 0 && !tn.standard_checker_used) {
        if (!var_check_cmd)
          var_check_cmd = (unsigned char*) alloca(sizeof(path_t));
        for (n = 1; n <= ts->variant_num; n++) {
          snprintf(var_check_cmd, sizeof(path_t), "%s-%d", tn.check_cmd, n);
          if (check_executable(var_check_cmd) < 0) return -1;
        }
      } else {
        if (check_executable(tn.check_cmd) < 0) return -1;
      }

      /* check working dirs */
      if (make_writable(tn.check_dir) < 0) return -1;
      if (check_writable_dir(tn.check_dir) < 0) return -1;
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
  int     i, n1, n2, j, n, k;
  int     total = 0;

  struct section_problem_data *prb = 0;
  unsigned char *var_test_dir;
  unsigned char *var_corr_dir;
  unsigned char *var_info_dir;
  unsigned char *var_tgz_dir;
  unsigned char *var_check_cmd = 0;

  /* check spooler dirs */
  if (check_writable_spool(global->run_queue_dir, SPOOL_OUT) < 0) return -1;
  if (check_writable_dir(global->run_exe_dir) < 0) return -1;

  /* check working dirs */
  if (make_writable(global->run_work_dir) < 0) return -1;
  if (check_writable_dir(global->run_work_dir) < 0) return -1;

  for (i = 1; i <= max_prob; i++) {
    prb = probs[i];
    if (!prb) continue;
    if (prb->disable_testing) continue;

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
    if (prb->variant_num <= 0) {
      if (check_readable_dir(prb->test_dir) < 0) return -1;
      if ((n1 = count_files(prb->test_dir, prb->test_sfx, prb->test_pat)) < 0)
        return -1;
      if (!n1) {
        err("'%s' does not contain any tests", prb->test_dir);
        return -1;
      }
      info("found %d tests for problem %s", n1, prb->short_name);
      if (n1 < prb->tests_to_accept) {
        err("%d tests required for problem acceptance!", prb->tests_to_accept);
        return -1;
      }
      if (prb->use_corr) {
        if (!prb->corr_dir[0]) {
          err("directory with answers is not defined");
          return -1;
        }
        if (check_readable_dir(prb->corr_dir) < 0) return -1;
        if ((n2 = count_files(prb->corr_dir,prb->corr_sfx,prb->corr_pat)) < 0)
          return -1;
        info("found %d answers for problem %s", n2, prb->short_name);
        if (n1 != n2) {
          err("number of test does not match number of answers");
          return -1;
        }
      }
      if (prb->use_info) {
        if (!prb->info_dir[0]) {
          err("directory with test information is not defined");
          return -1;
        }
        if (check_readable_dir(prb->info_dir) < 0) return -1;
        if ((n2 = count_files(prb->info_dir,prb->info_sfx,prb->info_pat)) < 0)
          return -1;
        info("found %d info files for problem %s", n2, prb->short_name);
        if (n1 != n2) {
          err("number of test does not match number of info files");
          return -1;
        }
      }
      if (prb->use_tgz) {
        if (!prb->tgz_dir[0]) {
          err("directory with tgz information is not defined");
          return -1;
        }
        if (check_readable_dir(prb->tgz_dir) < 0) return -1;
        if ((n2 = count_files(prb->tgz_dir, prb->tgz_sfx, 0)) < 0) return -1;
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
        snprintf(var_test_dir, sizeof(path_t), "%s-%d", prb->test_dir, k);
        snprintf(var_corr_dir, sizeof(path_t), "%s-%d", prb->corr_dir, k);
        snprintf(var_info_dir, sizeof(path_t), "%s-%d", prb->info_dir, k);
        snprintf(var_tgz_dir, sizeof(path_t), "%s-%d", prb->tgz_dir, k);
        if (check_readable_dir(var_test_dir) < 0) return -1;
        if ((j = count_files(var_test_dir, prb->test_sfx, prb->test_pat)) < 0)
          return -1;
        if (!j) {
          err("'%s' does not contain any tests", var_test_dir);
          return -1;
        }
        if (n1 < 0) n1 = j;
        if (n1 != j) {
          err("number of tests %d for variant %d does not equal %d", j, k, n1);
          return -1;
        }
        info("found %d tests for problem %s, variant %d",n1,prb->short_name,k);
        if (n1 < prb->tests_to_accept) {
          err("%d tests required for problem acceptance!",
              prb->tests_to_accept);
          return -1;
        }
        if (prb->use_corr) {
          if (!prb->corr_dir[0]) {
            err("directory with answers is not defined");
            return -1;
          }
          if (check_readable_dir(var_corr_dir) < 0) return -1;
          if ((j = count_files(var_corr_dir,prb->corr_sfx,prb->corr_pat)) < 0)
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
          if (!prb->info_dir[0]) {
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
          if (!prb->tgz_dir[0]) {
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

    if (n1 >= tests_a - 1) {
      if (!tests_a) tests_a = 128;
      while (n1 >= tests_a - 1)
        tests_a *= 2;
      xfree(tests);
      XCALLOC(tests, tests_a);
    }

    ASSERT(prb->test_score >= 0);
    if (global->score_system_val == SCORE_MOSCOW) {
      if (prb->full_score <= 0) {
        err("problem %s: problem full_score is not set", prb->short_name);
        return -1;
      }
      if (!(prb->x_score_tests = prepare_parse_score_tests(prb->score_tests,
                                                           prb->full_score))) {
        err("problem %s: parsing of score_tests failed", prb->short_name);
        return -1;
      }
      prb->x_score_tests[prb->full_score - 1] = n1;
      prb->ntests = n1;
      if (prb->full_score > 1
          && prb->x_score_tests[prb->full_score - 2] >= n1) {
        err("problem %s: score_tests[%d] >= score_tests[%d]",
            prb->short_name,
            prb->full_score - 2, prb->full_score - 1);
        return -1;
      }
    } else if (prb->test_score >= 0 && global->score_system_val != SCORE_ACM) {
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
    prb = probs[testers[i]->problem];
    total++;

    if (prb->variant_num > 0 && !testers[i]->standard_checker_used) {
      if (!var_check_cmd)
        var_check_cmd = (unsigned char*) alloca(sizeof(path_t));
      for (n = 1; n <= prb->variant_num; n++) {
        snprintf(var_check_cmd, sizeof(path_t),
                 "%s-%d", testers[i]->check_cmd, n);
        if (check_executable(var_check_cmd) < 0) return -1;
      }
    } else {
      if (check_executable(testers[i]->check_cmd) < 0) return -1;
    }

    /* check working dirs */
    if (make_writable(testers[i]->check_dir) < 0) return -1;
    if (check_writable_dir(testers[i]->check_dir) < 0) return -1;
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
    } else if (!strcmp(argv[i], "-S")) {
      managed_mode_flag = 1;
      i++;
    } else if (!strncmp(argv[i], "-D", 2)) {
      if (cpp_opts[0]) pathcat(cpp_opts, " ");
      pathcat(cpp_opts, argv[i++]);
    } else break;
  }
  if (i >= argc) goto print_usage;

#if defined __unix__
  if (getuid() == 0) {
    err("sorry, will not run as the root");
    return 1;
  }
#endif

  if (prepare(argv[i], p_flags, PREPARE_RUN, cpp_opts, managed_mode_flag) < 0)
    return 1;
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
  printf("  -DDEF  - define a symbol for preprocessor\n");
  return code;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "tTask")
 * End:
 */
