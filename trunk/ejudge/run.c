/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2012 Alexander Chernov <cher@ejudge.ru> */

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

#include "prepare.h"
#include "runlog.h"
#include "cr_serialize.h"
#include "testinfo.h"
#include "interrupt.h"
#include "run_packet.h"
#include "curtime.h"
#include "full_archive.h"
#include "digest_io.h"
#include "filehash.h"
#include "serve_state.h"
#include "startstop.h"
#include "ejudge_cfg.h"
#include "nwrun_packet.h"
#include "prepare_dflt.h"
#include "fileutl.h"
#include "errlog.h"
#include "misctext.h"
#include "run.h"
#include "super_run_packet.h"

#include "reuse_xalloc.h"
#include "reuse_logger.h"
#include "reuse_osdeps.h"
#include "reuse_integral.h"
#include "reuse_exec.h"

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

#include "win32_compat.h"

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

struct testinfo
{
  int            status;        /* the execution status */
  int            code;          /* the process exit code */
  int            termsig;       /* the termination signal */
  int            score;         /* score gained for this test */
  int            max_score;     /* maximal score for this test */
  long           times;         /* execution time */
  long           real_time;     /* execution real time */
  int            max_memory_used;
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
  unsigned char *exit_comment;  /* comment on exit status */
  int            checker_score;
  int            visibility;    /* test visibility */
};

static int total_tests;
static int tests_a = 0;
static struct testinfo *tests = 0;

#define SIZE_G (1024 * 1024 * 1024)
#define SIZE_M (1024 * 1024)
#define SIZE_K (1024)

static unsigned char*
size_t_to_size(unsigned char *buf, size_t buf_size, size_t num)
{
  if (!num) snprintf(buf, buf_size, "0");
  else if (!(num % SIZE_G)) snprintf(buf, buf_size, "%" EJ_PRINTF_ZSPEC "uG", EJ_PRINTF_ZCAST(num / SIZE_G));
  else if (!(num % SIZE_M)) snprintf(buf, buf_size, "%" EJ_PRINTF_ZSPEC "uM", EJ_PRINTF_ZCAST(num / SIZE_M));
  else if (!(num % SIZE_K)) snprintf(buf, buf_size, "%" EJ_PRINTF_ZSPEC "uK", EJ_PRINTF_ZCAST(num / SIZE_K));
  else snprintf(buf, buf_size, "%" EJ_PRINTF_ZSPEC "u", EJ_PRINTF_ZCAST(num));
  return buf;
}

static int
filter_testers(char *key)
{
  int i, total = 0;

  for (i = 1; i <= serve_state.max_tester; i++) {
    if (key && strcmp(serve_state.testers[i]->key, key)) {
      serve_state.testers[i] = 0;
      continue;
    }
    if (serve_state.testers[i]) total++;
  }

  return 0;
}

static unsigned char *
prepare_checker_comment(const unsigned char *str)
{
  size_t len = strlen(str);
  unsigned char *wstr = 0, *p;
  unsigned char *cmt = 0;

  wstr = (unsigned char*) xmalloc(len + 1);
  strcpy(wstr, str);
  for (p = wstr; *p; p++)
    if (*p < ' ') *p = ' ';
  for (--p; p >= wstr && *p == ' '; *p-- = 0);
  for (p = wstr; *p; p++) {
    switch (*p) {
    case '"': case '&': case '<': case '>':
      *p = '?';
    }
  }
  if (utf8_mode) {
    utf8_fix_string(wstr, 0);
    len = strlen(wstr);
    if (len > 128) {
      p = wstr + 120;
      while (*p >= 0x80 && *p <= 0xbf) p--; 
      *p++ = '.';
      *p++ = '.';
      *p++ = '.';
      *p = 0;
    }
  } else {
    if (p - wstr > 64) {
      p = wstr + 60;
      *p++ = '.';
      *p++ = '.';
      *p++ = '.';
      *p = 0;
    }
  }

  cmt = html_armor_string_dup(wstr);
  xfree(wstr);
  return cmt;
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

#define ARMOR(s)  html_armor_buf(&ab, s)

static int
generate_xml_report(
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        const unsigned char *report_path,
        int variant,
        int scores,
        int max_score,
        int user_max_score,
        int correct_available_flag,
        int info_available_flag,
        int report_time_limit_ms,
        int report_real_time_limit_ms,
        int has_real_time,
        int has_max_memory_used,
        int marked_flag,
        int user_run_tests,
        const unsigned char *additional_comment,
        const unsigned char *valuer_comment,
        const unsigned char *valuer_judge_comment,
        const unsigned char *valuer_errors)
{
  FILE *f = 0;
  unsigned char buf1[32], buf2[32], buf3[128];
  int i;
  unsigned char *msg = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct section_global_data *global = serve_state.global;
  const struct super_run_in_global_packet *srgp = srp->global;

  if (!(f = fopen(report_path, "w"))) {
    err("generate_xml_report: cannot open protocol file %s", report_path);
    return -1;
  }

  fprintf(f, "Content-type: text/xml\n\n");
  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\"?>\n", EJUDGE_CHARSET);

  run_status_to_str_short(buf1, sizeof(buf1), reply_pkt->status);
  fprintf(f, "<testing-report run-id=\"%d\" judge-id=\"%d\" status=\"%s\" scoring=\"%s\" archive-available=\"%s\" run-tests=\"%d\"",
          srgp->run_id, srgp->judge_id, buf1,
          unparse_scoring_system(buf2, sizeof(buf2), srgp->scoring_system_val),
          (srgp->enable_full_archive)?"yes":"no", total_tests - 1);
  if (has_real_time) {
    fprintf(f, " real-time-available=\"yes\"");
  }
  if (has_max_memory_used) {
    fprintf(f, " max-memory-used-available=\"yes\"");
  }
  if (correct_available_flag) {
    fprintf(f, " correct-available=\"yes\"");
  }
  if (info_available_flag) {
    fprintf(f, " info-available=\"yes\"");
  }
  if (variant > 0) {
    fprintf(f, " variant=\"%d\"", variant);
  }
  if (srgp->scoring_system_val == SCORE_OLYMPIAD) {
    fprintf(f, " accepting-mode=\"%s\"", srgp->accepting_mode?"yes":"no");
  }
  if (srgp->scoring_system_val == SCORE_OLYMPIAD && srgp->accepting_mode
      && reply_pkt->status != RUN_ACCEPTED) {
    fprintf(f, " failed-test=\"%d\"", total_tests - 1);
  } else if (srgp->scoring_system_val == SCORE_ACM && reply_pkt->status != RUN_OK) {
    fprintf(f, " failed-test=\"%d\"", total_tests - 1);
  } else if (srgp->scoring_system_val == SCORE_OLYMPIAD && !srgp->accepting_mode) {
    fprintf(f, " tests-passed=\"%d\" score=\"%d\" max-score=\"%d\"",
            reply_pkt->failed_test - 1, reply_pkt->score, max_score);
  } else if (srgp->scoring_system_val == SCORE_KIROV) {
    fprintf(f, " tests-passed=\"%d\" score=\"%d\" max-score=\"%d\"",
            reply_pkt->failed_test - 1, reply_pkt->score, max_score);
  } else if (srgp->scoring_system_val == SCORE_MOSCOW) {
    if (reply_pkt->status != RUN_OK) {
      fprintf(f, " failed-test=\"%d\"", total_tests - 1);
    }
    fprintf(f, " score=\"%d\" max-score=\"%d\"", reply_pkt->score, max_score);
  }
  if (report_time_limit_ms > 0) {
    fprintf(f, " time-limit-ms=\"%d\"", report_time_limit_ms);
  }
  if (report_real_time_limit_ms > 0) {
    fprintf(f, " real-time-limit-ms=\"%d\"", report_real_time_limit_ms);
  }
  if (marked_flag >= 0) {
    fprintf(f, " marked-flag=\"%s\"", marked_flag?"yes":"no");
  }
  if (srgp->separate_user_score > 0 && reply_pkt->user_status >= 0) {
    run_status_to_str_short(buf1, sizeof(buf1), reply_pkt->user_status);
    fprintf(f, " user-status=\"%s\"", buf1);
  }
  if (srgp->separate_user_score > 0 && reply_pkt->user_score >= 0) {
    fprintf(f, " user-score=\"%d\"", reply_pkt->user_score);
  }
  if (srgp->separate_user_score > 0) {
    if (user_max_score < 0) user_max_score = max_score;
    fprintf(f, " user-max-score=\"%d\"", user_max_score);
  }
  if (srgp->separate_user_score > 0 && reply_pkt->user_tests_passed >= 0) {
    fprintf(f, " user-tests-passed=\"%d\"", reply_pkt->user_tests_passed);
  }
  if (srgp->separate_user_score > 0 && user_run_tests >= 0) {
    fprintf(f, " user-run-tests=\"%d\"", user_run_tests);
  }
  fprintf(f, " >\n");

  if (additional_comment) {
    fprintf(f, "  <comment>%s</comment>\n", ARMOR(additional_comment));
  }
  if (valuer_comment) {
    fprintf(f, "  <valuer-comment>%s</valuer-comment>\n",
            ARMOR(valuer_comment));
  }
  if (valuer_judge_comment) {
    fprintf(f, "  <valuer-judge-comment>%s</valuer-judge-comment>\n",
            ARMOR(valuer_judge_comment));
  }
  if (valuer_errors) {
    fprintf(f, "  <valuer-errors>%s</valuer-errors>\n",
            ARMOR(valuer_errors));
  }
  if ((msg = os_NodeName())) {
    fprintf(f, "  <host>%s</host>\n", msg);
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
    if (tests[i].real_time >= 0 && has_real_time) {
      fprintf(f, " real-time=\"%ld\"", tests[i].real_time);
    }
    if (tests[i].max_memory_used > 0) {
      fprintf(f, " max-memory-used=\"%d\"", tests[i].max_memory_used);
    }
    if (srgp->scoring_system_val == SCORE_OLYMPIAD && !srgp->accepting_mode) {
      fprintf(f, " nominal-score=\"%d\" score=\"%d\"",
              tests[i].max_score, tests[i].score);
    } else if (srgp->scoring_system_val == SCORE_KIROV) {
      fprintf(f, " nominal-score=\"%d\" score=\"%d\"",
              tests[i].max_score, tests[i].score);
    }
    if (tests[i].comment && tests[i].comment[0]) {
      fprintf(f, " comment=\"%s\"", ARMOR(tests[i].comment));
    }
    if (tests[i].team_comment && tests[i].team_comment[0]) {
      fprintf(f, " team-comment=\"%s\"", ARMOR(tests[i].team_comment));
    }
    if (tests[i].exit_comment && tests[i].exit_comment[0]) {
      fprintf(f, " exit-comment=\"%s\"", ARMOR(tests[i].exit_comment));
    }
    if ((tests[i].status == RUN_WRONG_ANSWER_ERR 
         || tests[i].status == RUN_PRESENTATION_ERR || tests[i].status == RUN_OK)
        && tests[i].chk_out_size > 0 && tests[i].chk_out && tests[i].chk_out[0]) {
      msg = prepare_checker_comment(tests[i].chk_out);
      fprintf(f, " checker-comment=\"%s\"", msg);
      xfree(msg);
    }
    if (srgp->enable_full_archive) {
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
    if (tests[i].output_size >= 0 && srgp->enable_full_archive) {
      fprintf(f, " output-available=\"yes\"");
    }
    if (tests[i].error_size >= 0 && srgp->enable_full_archive) {
      fprintf(f, " stderr-available=\"yes\"");
    }
    if (tests[i].chk_out_size >= 0 && srgp->enable_full_archive) {
      fprintf(f, " checker-output-available=\"yes\"");
    }
    if (tests[i].args && strlen(tests[i].args) >= global->max_cmd_length) {
      fprintf(f, " args-too-long=\"yes\"");
    }
    if (tests[i].visibility > 0) {
      fprintf(f, " visibility=\"%s\"", test_visibility_unparse(tests[i].visibility));
    }
    fprintf(f, " >\n");

    if (tests[i].args && strlen(tests[i].args) < global->max_cmd_length) {
      fprintf(f, "      <args>%s</args>\n", ARMOR(tests[i].args));
    }

    if (tests[i].input_size >= 0 && !srgp->enable_full_archive) {
      fprintf(f, "      <input>");
      html_print_by_line(f, utf8_mode, global->max_file_length,
                         global->max_line_length,
                         tests[i].input, tests[i].input_size);
      fprintf(f, "</input>\n");
    }

    if (tests[i].output_size >= 0 && !srgp->enable_full_archive) {
      fprintf(f, "      <output>");
      html_print_by_line(f, utf8_mode, global->max_file_length,
                         global->max_line_length,
                         tests[i].output, tests[i].output_size);
      fprintf(f, "</output>\n");
    }

    if (tests[i].correct_size >= 0 && !srgp->enable_full_archive) {
      fprintf(f, "      <correct>");
      html_print_by_line(f, utf8_mode, global->max_file_length,
                         global->max_line_length,
                         tests[i].correct, tests[i].correct_size);
      fprintf(f, "</correct>\n");
    }

    if (tests[i].error_size >= 0 && !srgp->enable_full_archive) {
      fprintf(f, "      <stderr>");
      html_print_by_line(f, utf8_mode, global->max_file_length,
                         global->max_line_length,
                         tests[i].error, tests[i].error_size);
      fprintf(f, "</stderr>\n");
    }

    if (tests[i].chk_out_size >= 0 && !srgp->enable_full_archive) {
      fprintf(f, "      <checker>");
      html_print_by_line(f, utf8_mode, global->max_file_length,
                         global->max_line_length,
                         tests[i].chk_out, tests[i].chk_out_size);
      fprintf(f, "</checker>\n");
    }

    fprintf(f, "    </test>\n");
  }

  fprintf(f, "  </tests>\n");

  fprintf(f, "</testing-report>\n");
  fclose(f); f = 0;
  html_armor_free(&ab);
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
append_msg_to_log(const unsigned char *path, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
static void
append_msg_to_log(const unsigned char *path, const char *format, ...)
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

static void
chk_printf(struct testinfo *result, const char *format, ...)
  __attribute__((format(printf, 2, 3)));
static void
chk_printf(struct testinfo *result, const char *format, ...)
{
  va_list args;
  unsigned char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (!result->chk_out) {
    result->chk_out = xstrdup(buf);
    result->chk_out_size = strlen(result->chk_out);
  } else {
    int len1 = strlen(result->chk_out);
    int len2 = strlen(buf);
    int len3 = len1 + len2;
    unsigned char *str = (unsigned char*) xmalloc(len3 + 1);
    memcpy(str, result->chk_out, len1);
    memcpy(str + len1, buf, len2);
    str[len3] = 0;
    xfree(result->chk_out);
    result->chk_out = str;
    result->chk_out_size = len3;
  }
}

static int
read_checker_score(const unsigned char *path,
                   const unsigned char *log_path,
                   const unsigned char *what,
                   int max_score,
                   int *p_score)
{
  char *score_buf = 0;
  size_t score_buf_size = 0;
  int x, n, r;

  r = generic_read_file(&score_buf, 0, &score_buf_size, 0,
                        0, path, "");
  if (r < 0) {
    append_msg_to_log(log_path, "Cannot read the %s score output", what);
    return -1;
  }
  if (strlen(score_buf) != score_buf_size) {
    append_msg_to_log(log_path, "The %s score output is binary", what);
    xfree(score_buf);
    return -1;
  }

  while (score_buf_size > 0 && isspace(score_buf[score_buf_size - 1]))
    score_buf[--score_buf_size] = 0;
  if (!score_buf_size) {
    append_msg_to_log(log_path, "The %s score output is empty", what);
    xfree(score_buf);
    return -1;
  }

  if (sscanf(score_buf, "%d%n", &x, &n) != 1 || score_buf[n]) {
    append_msg_to_log(log_path, "The %s score output (%s) is invalid",
                      what, score_buf);
    xfree(score_buf);
    return -1;
  }
  if (x < 0 || x > max_score) {
    append_msg_to_log(log_path, "The %s score (%d) is invalid", what, x);
    xfree(score_buf);
    return -1;
  }

  *p_score = x;
  xfree(score_buf);
  return 0;
}

static int
read_valuer_score(
        const unsigned char *path,
        const unsigned char *log_path,
        const unsigned char *what,
        int max_score,
        int valuer_sets_marked,
        int separate_user_score,
        int *p_score,
        int *p_marked,
        int *p_user_status,
        int *p_user_score,
        int *p_user_tests_passed)
{
  char *score_buf = 0, *p;
  size_t score_buf_size = 0;
  int x, y, n, r, user_status = -1, user_score = -1, user_tests_passed = -1;

  if (p_marked) *p_marked = -1;

  r = generic_read_file(&score_buf, 0, &score_buf_size, 0,
                        0, path, "");
  if (r < 0) {
    append_msg_to_log(log_path, "Cannot read the %s score output", what);
    return -1;
  }
  if (strlen(score_buf) != score_buf_size) {
    append_msg_to_log(log_path, "The %s score output is binary", what);
    goto fail;
  }

  while (score_buf_size > 0 && isspace(score_buf[score_buf_size - 1]))
    score_buf[--score_buf_size] = 0;
  if (!score_buf_size) {
    append_msg_to_log(log_path, "The %s score output is empty", what);
    goto fail;
  }

  p = score_buf;
  if (sscanf(p, "%d%n", &x, &n) != 1) {
    append_msg_to_log(log_path, "The %s score output (%s) is invalid",
                      what, score_buf);
    goto fail;
  }
  if (x < 0 || x > max_score) {
    append_msg_to_log(log_path, "The %s score (%d) is invalid", what, x);
    goto fail;
  }
  p += n;

  if (valuer_sets_marked > 0) {
    if (sscanf(p, "%d%n", &y, &n) != 1) {
      append_msg_to_log(log_path, "The %s marked_flag output (%s) is invalid",
                        what, score_buf);
      goto fail;
    }
    if (y < 0 || y > 1) {
      append_msg_to_log(log_path, "The %s marked_flag (%d) is invalid", what,y);
      goto fail;
    }
    p += n;
  }

  if (separate_user_score > 0) {
    while (isspace(*p)) ++p;
    if (*p) {
      if (sscanf(p, "%d%n", &user_status, &n) != 1) {
        append_msg_to_log(log_path, "The %s user_status output (%s) is invalid",
                          what, score_buf);
        goto fail;
      }
      p += n;
      if (user_status >= 0) {
        if (user_status != RUN_OK && user_status != RUN_PARTIAL) {
          append_msg_to_log(log_path, "The %s user_status output (%d) is invalid",
                            what, user_status);
          goto fail;
        }
      } else {
        user_status = -1;
      }
    }
    while (isspace(*p)) ++p;
    if (*p) {
      if (sscanf(p, "%d%n", &user_score, &n) != 1) {
        append_msg_to_log(log_path, "The %s user_score output (%s) is invalid",
                          what, score_buf);
        goto fail;
      }
      p += n;
      if (user_score >= 0) {
        // do some more checking...
      } else {
        user_score = -1;
      }
    }
    while (isspace(*p)) ++p;
    if (*p) {
      if (sscanf(p, "%d%n", &user_tests_passed, &n) != 1) {
        append_msg_to_log(log_path, "The %s user_tests_passed output (%s) is invalid",
                          what, score_buf);
        goto fail;
      }
      p += n;
      if (user_tests_passed >= 0) {
        // do some more checking
      } else {
        user_tests_passed = -1;
      }
    }
  }

  if (*p) {
    append_msg_to_log(log_path, "The %s output is invalid", what);
    goto fail;
  }

  *p_score = x;
  if (valuer_sets_marked > 0 && p_marked) *p_marked = y;
  if (separate_user_score > 0) {
    if (p_user_status && user_status >= 0) *p_user_status = user_status;
    if (p_user_score && user_score >= 0) *p_user_score = user_score;
    if (p_user_tests_passed && user_tests_passed >= 0) *p_user_tests_passed = user_tests_passed;
  }

  xfree(score_buf);
  return 0;

fail:
  xfree(score_buf);
  return -1;
}

static void
setup_environment(
        tpTask tsk,
        char **envs,
        const unsigned char *ejudge_prefix_dir_env,
        const struct testinfo_struct *pt)
{
  int jj;
  unsigned char env_buf[1024];
  const unsigned char *envval = NULL;
  
  if (envs) {
    for (jj = 0; envs[jj]; jj++) {
      if (!strcmp(envs[jj], "EJUDGE_PREFIX_DIR")) {
        task_PutEnv(tsk, ejudge_prefix_dir_env);
      } else if (!strchr(envs[jj], '=')) {
        envval = getenv(envs[jj]);
        if (envval) {
          snprintf(env_buf, sizeof(env_buf), "%s=%s", envs[jj], envval);
          task_PutEnv(tsk, env_buf);
        }
      } else {
        task_PutEnv(tsk, envs[jj]);
      }
    }
  }

  if (pt && pt->env_u && pt->env_v) {
    for (jj = 0; jj < pt->env_u; ++jj) {
      if (pt->env_v[jj]) {
        task_PutEnv(tsk, pt->env_v[jj]);
      }
    }
  }
}

static int
invoke_valuer(
        const struct section_global_data *global,
        const struct super_run_in_packet *srp,
        int cur_variant,
        int max_score,
        int *p_score,
        int *p_marked,
        int *p_user_status,
        int *p_user_score,
        int *p_user_tests_passed,
        char **p_err_txt,
        char **p_cmt_txt,
        char **p_jcmt_txt)
{
  path_t ejudge_prefix_dir_env;
  path_t score_list;
  path_t score_res;
  path_t score_err;
  path_t score_cmt;
  path_t score_jcmt;
  path_t valuer_cmd;
  FILE *f = 0;
  int i, retval = -1;
  tpTask tsk = 0;
  char *err_txt = 0, *cmt_txt = 0, *jcmt_txt = 0;
  size_t err_len = 0, cmt_len = 0, jcmt_len = 0;
  unsigned char strbuf[1024];

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

#ifdef EJUDGE_PREFIX_DIR
  snprintf(ejudge_prefix_dir_env, sizeof(ejudge_prefix_dir_env),
           "EJUDGE_PREFIX_DIR=%s", EJUDGE_PREFIX_DIR);
#endif /* EJUDGE_PREFIX_DIR */

  pathmake(score_list, global->run_work_dir, "/", "score_list", NULL);
  pathmake(score_res, global->run_work_dir, "/", "score_res", NULL);
  pathmake(score_err, global->run_work_dir, "/", "score_err", NULL);
  pathmake(score_cmt, global->run_work_dir, "/", "score_cmt", NULL);
  pathmake(score_jcmt, global->run_work_dir, "/", "score_jcmt", NULL);

  // write down the score list
  if (!(f = fopen(score_list, "w"))) {
    append_msg_to_log(score_err, "cannot open %s for writing", score_list);
    goto cleanup;
  }
  fprintf(f, "%d\n", total_tests - 1);
  for (i = 1; i < total_tests; i++) {
    fprintf(f, "%d", tests[i].status);
    if (srpp->scoring_checker > 0) {
      fprintf(f, " %d", tests[i].checker_score);
    } else {
      fprintf(f, " %d", tests[i].score);
    }
    fprintf(f, " %ld", tests[i].times);
    fprintf(f, "\n");
  }
  if (ferror(f)) {
    append_msg_to_log(score_err, "failed to write to %s", score_list);
    goto cleanup;
  }
  if (fclose(f) < 0) {
    append_msg_to_log(score_err, "failed to write to %s", score_list);
    f = 0;
    goto cleanup;
  }
  f = 0;

  snprintf(valuer_cmd, sizeof(valuer_cmd), srpp->valuer_cmd);

  info("starting valuer: %s %s %s", valuer_cmd, score_cmt, score_jcmt);

  tsk = task_New();
  task_AddArg(tsk, valuer_cmd);
  task_AddArg(tsk, score_cmt);
  task_AddArg(tsk, score_jcmt);
  task_SetRedir(tsk, 0, TSR_FILE, score_list, TSK_READ);
  task_SetRedir(tsk, 1, TSR_FILE, score_res, TSK_REWRITE, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, score_err, TSK_REWRITE, TSK_FULL_RW);
  task_SetWorkingDir(tsk, global->run_work_dir);
  task_SetPathAsArg0(tsk);
  if (srpp->checker_real_time_limit_ms > 0) {
    task_SetMaxRealTimeMillis(tsk, srpp->checker_real_time_limit_ms);
  }
  setup_environment(tsk, srpp->valuer_env, ejudge_prefix_dir_env, NULL);
  if (srgp->separate_user_score > 0) {
    snprintf(strbuf, sizeof(strbuf), "EJUDGE_USER_SCORE=1");
    task_PutEnv(tsk, strbuf);
  }
  task_EnableAllSignals(tsk);

  if (task_Start(tsk) < 0) {
    append_msg_to_log(score_err, "valuer failed to start");
    goto cleanup;
  }
  task_Wait(tsk);
  if (task_IsTimeout(tsk)) {
    append_msg_to_log(score_err, "valuer time-out");
    goto cleanup;
  } else if (task_IsAbnormal(tsk)) {
    if (task_Status(tsk) == TSK_SIGNALED) {
      i = task_TermSignal(tsk);
      append_msg_to_log(score_err, "valuer exited by signal %d (%s)",
                        i, os_GetSignalString(i));
    } else {
      append_msg_to_log(score_err, "valuer exited with code %d",
                        task_ExitCode(tsk));
    }
    goto cleanup;
  }

  task_Delete(tsk); tsk = 0;

  if (read_valuer_score(score_res, score_err, "valuer", max_score,
                        srpp->valuer_sets_marked, srgp->separate_user_score,
                        p_score, p_marked, p_user_status, p_user_score, p_user_tests_passed) < 0) {
    goto cleanup;
  }
  generic_read_file(&cmt_txt, 0, &cmt_len, 0, 0, score_cmt, "");
  if (cmt_txt) {
    while (cmt_len > 0 && isspace(cmt_txt[cmt_len - 1])) cmt_len--;
    cmt_txt[cmt_len] = 0;
    if (!cmt_len) {
      xfree(cmt_txt);
      cmt_txt = 0;
    }
  }
  generic_read_file(&jcmt_txt, 0, &jcmt_len, 0, 0, score_jcmt, "");
  if (jcmt_txt) {
    while (jcmt_len > 0 && isspace(jcmt_txt[jcmt_len - 1])) jcmt_len--;
    jcmt_txt[jcmt_len] = 0;
    if (!jcmt_len) {
      xfree(jcmt_txt);
      jcmt_txt = 0;
    }
  }

  if (p_cmt_txt) {
    *p_cmt_txt = cmt_txt;
    cmt_txt = 0;
  }
  if (p_jcmt_txt) {
    *p_jcmt_txt = jcmt_txt;
    jcmt_txt = 0;
  }
  retval = 0;

 cleanup:
  generic_read_file(&err_txt, 0, &err_len, 0, 0, score_err, "");
  if (err_txt) {
    while (err_len > 0 && isspace(err_txt[err_len - 1])) err_len--;
    err_txt[err_len] = 0;
    if (!err_len) {
      xfree(err_txt); err_txt = 0;
    }
  }

  if (tsk) {
    task_Delete(tsk);
    tsk = 0;
  }

  xfree(cmt_txt); cmt_txt = 0;
  xfree(jcmt_txt); jcmt_txt = 0;
  if (p_err_txt) {
    *p_err_txt = err_txt; err_txt = 0;
  } else {
    xfree(err_txt); err_txt = 0;
  }

  unlink(score_list);
  unlink(score_res);
  unlink(score_err);
  unlink(score_cmt);
  unlink(score_jcmt);
  return retval;
}

static long
get_expected_free_space(const unsigned char *path)
{
#ifdef __MINGW32__
  return -1;
#else
  struct statfs sb;
  if (statfs(path, &sb) < 0) return -1;
  return sb.f_bfree;
#endif
}

static void
check_free_space(const unsigned char *path, long expected_space)
{
#ifndef __MINGW32__
  struct statfs sb;
  int wait_count = 0;

  if (expected_space <= 0) return;

  while (1) {
    if (statfs(path, &sb) < 0) {
      err("statfs failed: %s", os_ErrorMsg());
      return;
    }
    if (sb.f_bfree * 2 >= expected_space) return;
    if (++wait_count == 10) {
      err("check_free_space: waiting for free space aborted after ten attempts!");
      return;
    }
    info("not enough free space in the working directory, waiting");
    os_Sleep(500);
  }
#endif
}

static int
get_num_prefix(int num)
{
  if (num < 0) return '-';
  if (num < 10) return '0';
  if (num < 100) return '1';
  if (num < 1000) return '2';
  if (num < 10000) return '3';
  if (num < 100000) return '4';
  if (num < 1000000) return '5';
  return '6';
}

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";

static int
invoke_nwrun(
        struct section_tester_data *tst,
        const struct super_run_in_packet *srp,
        full_archive_t far,
        int test_num,
        int priority,
        int *p_has_real_time,
        const unsigned char *exe_src_dir,
        const unsigned char *exe_basename,
        const unsigned char *test_src_path,
        const unsigned char *test_basename,
        long time_limit_millis,
        struct testinfo *result)
{
  path_t full_spool_dir;
  path_t pkt_name;
  path_t full_in_path;
  path_t full_dir_path;
  path_t queue_path;
  path_t tmp_in_path;
  path_t exe_src_path;
  path_t result_path;
  path_t result_pkt_name;
  path_t out_entry_packet = { 0 };
  path_t dir_entry_packet;
  path_t check_output_path;
  path_t packet_output_path;
  path_t packet_error_path;
  path_t arch_entry_name;
  FILE *f = 0;
  int r;
  struct generic_section_config *generic_out_packet = 0;
  struct nwrun_out_packet *out_packet = 0;
  long file_size;
  int remove_out_packet_flag = 0;
  int timeout;
  int wait_time;

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  if (!tst->nwrun_spool_dir[0]) abort();

  priority += 16;
  if (priority < 0) priority = 0;
  if (priority > 31) priority = 31;

  result->status = RUN_CHECK_FAILED;

  if (os_IsAbsolutePath(tst->nwrun_spool_dir)) {
    snprintf(full_spool_dir, sizeof(full_spool_dir), "%s",
             tst->nwrun_spool_dir);
  } else {
    if (ejudge_config && ejudge_config->contests_home_dir) {
      snprintf(full_spool_dir, sizeof(full_spool_dir), "%s/%s",
               ejudge_config->contests_home_dir, tst->nwrun_spool_dir);
    } else {
#if defined EJUDGE_CONTESTS_HOME_DIR
      snprintf(full_spool_dir, sizeof(full_spool_dir), "%s/%s",
               EJUDGE_CONTESTS_HOME_DIR, tst->nwrun_spool_dir);
#else
      err("cannot initialize full_spool_dir");
      chk_printf(result, "full_spool_dir is invalid\n");
      goto fail;
#endif
    }
  }

  snprintf(queue_path, sizeof(queue_path), "%s/queue",
           full_spool_dir);
  if (make_all_dir(queue_path, 0777) < 0) {
    chk_printf(result, "make_all_dir(%s) failed\n", queue_path);
    goto fail;
  }

  snprintf(pkt_name, sizeof(pkt_name), "%c%c%d%c%d%c%d%c%d%c%d",
           b32_digits[priority],
           get_num_prefix(srgp->contest_id), srgp->contest_id,
           get_num_prefix(srgp->run_id), srgp->run_id,
           get_num_prefix(srpp->id), srpp->id,
           get_num_prefix(test_num), test_num,
           get_num_prefix(srgp->judge_id), srgp->judge_id);
  snprintf(full_in_path, sizeof(full_in_path),
           "%s/in/%s_%s", queue_path, os_NodeName(), pkt_name);
  if (make_dir(full_in_path, 0777) < 0) {
    chk_printf(result, "make_dir(%s) failed\n", full_in_path);
    goto fail;
  }

  // copy (or link) the executable
  snprintf(exe_src_path, sizeof(exe_src_path), "%s/%s",
           exe_src_dir, exe_basename);
  snprintf(tmp_in_path, sizeof(tmp_in_path), "%s/%s",
           full_in_path, exe_basename);
  if (make_hardlink(exe_src_path, tmp_in_path) < 0) {
    chk_printf(result, "copy(%s, %s) failed\n", exe_src_path, tmp_in_path);
    goto fail;
  }

  // copy (or link) the test file
  snprintf(tmp_in_path, sizeof(tmp_in_path), "%s/%s",
           full_in_path, test_basename);
  if (make_hardlink(test_src_path, tmp_in_path) < 0) {
    chk_printf(result, "copy(%s, %s) failed\n", test_src_path, tmp_in_path);
    goto fail;
  }

  // make the description file
  snprintf(tmp_in_path, sizeof(tmp_in_path), "%s/packet.cfg", full_in_path);
  f = fopen(tmp_in_path, "w");
  if (!f) {
    chk_printf(result, "fopen(%s) failed\n", tmp_in_path);
    goto fail;
  }

  fprintf(f, "priority = %d\n", priority + 1);
  fprintf(f, "contest_id = %d\n", srgp->contest_id);
  fprintf(f, "run_id = %d\n", srgp->run_id + 1);
  fprintf(f, "prob_id = %d\n", srpp->id);
  fprintf(f, "test_num = %d\n", test_num);
  fprintf(f, "judge_id = %d\n", srgp->judge_id);
  fprintf(f, "use_contest_id_in_reply = %d\n", 1);
  fprintf(f, "enable_unix2dos = %d\n", 1);
  if (srpp->use_stdin > 0 || srpp->combined_stdin > 0) {
    fprintf(f, "redirect_stdin = %d\n", 1);
  } else {
    fprintf(f, "disable_stdin = %d\n", 1);
  }
  if (srpp->combined_stdin > 0) {
    fprintf(f, "combined_stdin = %d\n", 1);
  }
  if (srpp->use_stdout > 0 || srpp->combined_stdout > 0) {
    fprintf(f, "redirect_stdout = %d\n", 1);
  } else {
    fprintf(f, "ignore_stdout = %d\n", 1);
  }
  if (srpp->combined_stdout > 0) {
    fprintf(f, "combined_stdout = %d\n", 1);
  }
  fprintf(f, "redirect_stderr = %d\n", 1);
  fprintf(f, "time_limit_millis = %ld\n", time_limit_millis);
  if (srpp->real_time_limit_ms > 0) {
    fprintf(f, "real_time_limit_millis = %d\n", srpp->real_time_limit_ms);
  }
  if (srpp->max_stack_size != 0 && srpp->max_stack_size != (size_t) -1L) {
    fprintf(f, "max_stack_size = %" EJ_PRINTF_ZSPEC "u\n",
            EJ_PRINTF_ZCAST(srpp->max_stack_size));
  }
  if (srpp->max_data_size != 0 && srpp->max_data_size != (size_t) -1L) {
    fprintf(f, "max_data_size = %" EJ_PRINTF_ZSPEC "u\n",
            EJ_PRINTF_ZCAST(srpp->max_data_size));
  }
  if (srpp->max_vm_size != 0 && srpp->max_vm_size != (size_t) -1L) {
    fprintf(f, "max_vm_size = %" EJ_PRINTF_ZSPEC "u\n",
            EJ_PRINTF_ZCAST(srpp->max_vm_size));
  }
  fprintf(f, "max_output_file_size = 60M\n");
  fprintf(f, "max_error_file_size = 16M\n");
  if (srgp->secure_run) {
    fprintf(f, "enable_secure_run = 1\n");
  }
  if (srgp->enable_memory_limit_error && srgp->secure_run) {
    fprintf(f, "enable_memory_limit_error = 1\n");
  }
  if (srgp->detect_violations && srgp->secure_run) {
    fprintf(f, "enable_security_violation_error = 1\n");
  }
  fprintf(f, "prob_short_name = \"%s\"\n", srpp->short_name);
  fprintf(f, "program_name = \"%s\"\n", exe_basename);
  fprintf(f, "test_file_name = \"%s\"\n", test_basename);
  fprintf(f, "input_file_name = \"%s\"\n", srpp->input_file);
  fprintf(f, "output_file_name = \"%s\"\n", srpp->output_file);
  fprintf(f, "result_file_name = \"%s\"\n", srpp->output_file);
  fprintf(f, "error_file_name = \"%s\"\n", tst->error_file);
  fprintf(f, "log_file_name = \"%s\"\n", tst->error_file);

  fflush(f);
  if (ferror(f)) {
    chk_printf(result, "output error to %s\n", tmp_in_path);
    goto fail;
  }
  fclose(f); f = 0;

  // wait for the result package
  snprintf(result_path, sizeof(result_path), "%s/result/%06d",
           full_spool_dir, srgp->contest_id);
  make_all_dir(result_path, 0777);

  snprintf(full_dir_path, sizeof(full_dir_path),
           "%s/dir/%s", queue_path, pkt_name);
  if (rename(full_in_path, full_dir_path) < 0) {
    chk_printf(result, "rename(%s, %s) failed\n", full_in_path, full_dir_path);
    goto fail;
  }

 restart_waiting:;

  // wait for the result package
  // timeout is 2 * real_time_limit
  timeout = 0;
  if (srpp->real_time_limit_ms > 0) timeout = 3 * srpp->real_time_limit_ms;
  if (timeout <= 0) timeout = 3 * time_limit_millis;
  wait_time = 0;

  while (1) {
    r = scan_dir(result_path, result_pkt_name, sizeof(result_pkt_name));
    if (r < 0) {
      chk_printf(result, "scan_dir(%s) failed\n", result_path);
      goto fail;
    }

    if (r > 0) break;

    if (wait_time >= timeout) {
      chk_printf(result, "invoke_nwrun: timeout!\n");
      goto fail;
    }

    cr_serialize_unlock(&serve_state);
    interrupt_enable();
    os_Sleep(100);
    interrupt_disable();
    cr_serialize_lock(&serve_state);

    // more appropriate interval?
    wait_time += 100;
  }

  snprintf(dir_entry_packet, sizeof(dir_entry_packet), "%s/dir/%s",
           result_path, result_pkt_name);
  snprintf(out_entry_packet, sizeof(out_entry_packet), "%s/out/%s_%s",
           result_path, os_NodeName(), result_pkt_name);
  if (rename(dir_entry_packet, out_entry_packet) < 0) {
    err("rename(%s, %s) failed: %s", dir_entry_packet, out_entry_packet,
        os_ErrorMsg());
    chk_printf(result, "rename(%s, %s) failed", dir_entry_packet,
               out_entry_packet);
    goto fail;
  }

  // parse the resulting packet
  remove_out_packet_flag = 1;
  snprintf(tmp_in_path, sizeof(tmp_in_path), "%s/packet.cfg",
           out_entry_packet);
  generic_out_packet = nwrun_out_packet_parse(tmp_in_path, &out_packet);
  if (!generic_out_packet) {
    chk_printf(result, "out_packet parse failed for %s\n", tmp_in_path);
    goto fail;
  }

  // match output and input data
  if (out_packet->contest_id != srgp->contest_id) {
    chk_printf(result, "contest_id mismatch: %d, %d\n",
               out_packet->contest_id, srgp->contest_id);
    goto restart_waiting;
  }
  if (out_packet->run_id - 1 != srgp->run_id) {
    chk_printf(result, "run_id mismatch: %d, %d\n",
               out_packet->run_id, srgp->run_id);
    goto restart_waiting;
  }
  if (out_packet->prob_id != srpp->id) {
    chk_printf(result, "prob_id mismatch: %d, %d\n",
               out_packet->prob_id, srpp->id);
    goto restart_waiting;
  }
  if (out_packet->test_num != test_num) {
    chk_printf(result, "test_num mismatch: %d, %d\n",
               out_packet->test_num, test_num);
    goto restart_waiting;
  }
  if (out_packet->judge_id != srgp->judge_id) {
    chk_printf(result, "judge_id mismatch: %d, %d\n",
               out_packet->judge_id, srgp->judge_id);
    goto restart_waiting;
  }

  result->status = out_packet->status;
  if (result->status != RUN_OK
      && result->status != RUN_PRESENTATION_ERR
      && result->status != RUN_RUN_TIME_ERR
      && result->status != RUN_TIME_LIMIT_ERR
      && result->status != RUN_CHECK_FAILED
      && result->status != RUN_MEM_LIMIT_ERR
      && result->status != RUN_SECURITY_ERR) {
    chk_printf(result, "invalid status %d\n", result->status);
    goto fail;
  }

  if (result->status != RUN_OK && out_packet->comment[0]) {
    chk_printf(result, "nwrun: %s\n", out_packet->comment);
  }

  if (out_packet->is_signaled) {
    result->code = 256;
    result->termsig = out_packet->signal_num & 0x7f;
  } else {
    result->code = out_packet->exit_code & 0x7f;
  }

  result->times = out_packet->cpu_time_millis;
  if (out_packet->real_time_available) {
    *p_has_real_time = 1;
    result->real_time = out_packet->real_time_millis;
  }
  if (out_packet->exit_comment[0]) {
    result->exit_comment = xstrdup(out_packet->exit_comment);
  }
  if (out_packet->max_memory_used > 0) {
    result->max_memory_used = out_packet->max_memory_used;
  }

  /* handle the input test data */
  if (srgp->enable_full_archive) {
    filehash_get(test_src_path, result->input_digest);
    result->has_input_digest = 1;
  } else if (srpp->binary_input <= 0) {
    file_size = generic_file_size(0, test_src_path, 0);
    if (file_size >= 0) {
      result->input_size = file_size;
      if (srgp->max_file_length > 0 && file_size <= srgp->max_file_length) {
        if (generic_read_file(&result->input, 0, 0, 0, 0, test_src_path, "")<0){
          chk_printf(result, "generic_read_file(%s) failed\n", test_src_path);
          goto fail;
        }
      }
    }
  }

  /* handle the program output */
  if (out_packet->output_file_existed > 0
      && out_packet->output_file_too_big <= 0) {
    snprintf(packet_output_path, sizeof(packet_output_path),
             "%s/%s", out_entry_packet, srpp->output_file);
    if (result->status == RUN_OK) {
      // copy file into the working directory for further checking
      snprintf(check_output_path, sizeof(check_output_path),
               "%s/%s", tst->check_dir, srpp->output_file);
      if (fast_copy_file(packet_output_path, check_output_path) < 0) {
        chk_printf(result, "copy_file(%s, %s) failed\n",
                   packet_output_path, check_output_path);
        goto fail;
      }
    }

    result->output_size = out_packet->output_file_orig_size;
    if (!srgp->enable_full_archive
        && srpp->binary_input <= 0
        && srgp->max_file_length > 0
        && result->output_size <= srgp->max_file_length) {
      if (generic_read_file(&result->output,0,0,0,0,packet_output_path,"")<0) {
        chk_printf(result, "generic_read_file(%s) failed\n",
                   packet_output_path);
        goto fail;
      }
    }

    if (far) {
      snprintf(arch_entry_name, sizeof(arch_entry_name), "%06d.o", test_num);
      full_archive_append_file(far, arch_entry_name, 0, packet_output_path);
    }
  } else if (out_packet->output_file_existed > 0) {
    chk_printf(result, "output file is too big\n");
  }

  /* handle the program error file */
  if (out_packet->error_file_existed > 0) {
    snprintf(packet_error_path, sizeof(packet_error_path),
             "%s/%s", out_entry_packet, tst->error_file);
    result->error_size = out_packet->error_file_size;
    if (!srgp->enable_full_archive
        && srgp->max_file_length > 0
        && result->error_size <= srgp->max_file_length) {
      if (generic_read_file(&result->error,0,0,0,0,packet_error_path,"") < 0) {
        chk_printf(result, "generic_read_file(%s) failed\n",
                   packet_error_path);
        goto fail;
      }
    }
    if (far) {
      snprintf(arch_entry_name, sizeof(arch_entry_name), "%06d.e", test_num);
      full_archive_append_file(far, arch_entry_name, 0, packet_error_path);
    }
  }

 cleanup:
  if (out_entry_packet[0]) {
    remove_directory_recursively(out_entry_packet, 0);
  }
  if (f) fclose(f);
  generic_out_packet = nwrun_out_packet_free(generic_out_packet);
  return result->status;

 fail:
  result->status = RUN_CHECK_FAILED;
  goto cleanup;
}

static int
run_tests(
        struct section_tester_data *tst,
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
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
  path_t score_out_path;
  path_t error_code;
  path_t prog_working_dir;
  int    score = 0;
  int    status = 0;
  int    failed_test = 0;
  int    total_failed_tests = 0;
  int    ec = -100;            /* FIXME: magic */
  int    marked_flag = -1;
  const char *sound;
  unsigned char *var_test_dir = 0;
  unsigned char *var_corr_dir = 0;
  unsigned char *var_info_dir = 0;
  unsigned char *var_tgz_dir = 0;
  unsigned char *var_interactor_cmd = 0;
  testinfo_t tstinfo;
  int errcode;
  int time_limit_value;
  unsigned char ejudge_prefix_dir_env[1024] = { 0 };
  ssize_t file_size;
  unsigned char arch_entry_name[64];
  full_archive_t far = 0;
  unsigned char *additional_comment = 0;
  int jj, tmpfd, test_max_score, force_check_failed;
  unsigned char flags_buf[128], bb[128];
  unsigned char *java_flags_ptr = flags_buf;
  char *valuer_comment = 0;
  char *valuer_judge_comment = 0;
  char *valuer_errors = 0;
  int report_time_limit_ms = -1;
  int report_real_time_limit_ms = -1;
  int has_real_time = 0;
  int has_max_memory_used = 0;
  int has_user_score, user_status, user_score, user_tests_passed, user_run_tests;
  unsigned char bname[64];
  unsigned char check_cmd[PATH_MAX];

  int pfd1[2], pfd2[2];
  tpTask tsk_int = 0;

  int *open_tests_val = NULL;
  int open_tests_count = 0;

  int *test_score_val = NULL;
  int test_score_count = 0;

#ifdef HAVE_TERMIOS_H
  struct termios term_attrs;
#endif

  long expected_free_space = 0;
  const struct section_global_data *global = serve_state.global;
  int disable_stderr;

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  memset(&tstinfo, 0, sizeof(tstinfo));
  if (srpp->open_tests && srpp->open_tests[0]) {
    // FIXME: handle errors
    prepare_parse_open_tests(stderr, srpp->open_tests, &open_tests_val, &open_tests_count);
  }

  if (srpp->test_score_list && srpp->test_score_list[0]) {
    // FIXME: handle errors
    prepare_parse_test_score_list(stderr, srpp->test_score_list, &test_score_val, &test_score_count);
  }

#ifdef EJUDGE_PREFIX_DIR
  snprintf(ejudge_prefix_dir_env, sizeof(ejudge_prefix_dir_env),
           "EJUDGE_PREFIX_DIR=%s", EJUDGE_PREFIX_DIR);
#endif /* EJUDGE_PREFIX_DIR */

  var_test_dir = srpp->test_dir;
  var_corr_dir = srpp->corr_dir;
  var_info_dir = srpp->info_dir;
  var_tgz_dir = srpp->tgz_dir;
  var_interactor_cmd = srpp->interactor_cmd;

  pathmake(report_path, global->run_work_dir, "/", "report", NULL);
  full_report_path[0] = 0;
  if (srgp->enable_full_archive) {
    pathmake(full_report_path, global->run_work_dir, "/", "full_output", NULL);
    far = full_archive_open_write(full_report_path);
  }

  memset(tests, 0, sizeof(tests[0]) * tests_a);
  total_tests = 1;
  cur_test = 1;

  /* at this point the executable is copied into the working dir */
  if (!srpp->type_val && tst->prepare_cmd[0]) {
    info("starting: %s %s", tst->prepare_cmd, new_name);
    tsk = task_New();
    task_AddArg(tsk, tst->prepare_cmd);
    task_AddArg(tsk, new_name);
    task_SetPathAsArg0(tsk);
    task_SetWorkingDir(tsk, global->run_work_dir);
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
    task_SetRedir(tsk, 1, TSR_FILE, report_path, TSK_REWRITE, TSK_FULL_RW);
    task_SetRedir(tsk, 2, TSR_DUP, 1);
    task_EnableAllSignals(tsk);
    task_Start(tsk);
    task_Wait(tsk);
    if (task_IsAbnormal(tsk)) goto _internal_execution_error;
    task_Delete(tsk); tsk = 0;
  }

  /* calculate the expected free space in check_dir */
  expected_free_space = get_expected_free_space(tst->check_dir);

  pathmake3(exe_path, tst->check_dir, "/", new_name, NULL);
  if (srpp->use_tgz > 0) {
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
  
  if (tst->is_dos && !srpp->binary_input) copy_flag = CONVERT;

  error_code[0] = 0;
  if (tst->errorcode_file[0]) {
    pathmake(error_code, tst->check_dir, "/", tst->errorcode_file, NULL);
  }

  while (1) {
    if (srgp->scoring_system_val == SCORE_OLYMPIAD
        && accept_testing
        && cur_test > srpp->tests_to_accept) break;

    sprintf(test_base, srpp->test_pat, cur_test);
    sprintf(corr_base, srpp->corr_pat, cur_test);
    pathmake(test_src, var_test_dir, "/", test_base, NULL);
    if (os_CheckAccess(test_src, REUSE_R_OK) < 0) {
      // testing is done as no tests left in the testing directory
      break;
    }

    pfd1[0] = -1;
    pfd1[1] = -1;
    pfd2[0] = -1;
    pfd2[1] = -1;
    tsk_int = 0;

    memset(&tests[cur_test], 0, sizeof(tests[0]));
    tests[cur_test].input_size = -1;
    tests[cur_test].output_size = -1;
    tests[cur_test].error_size = -1;
    tests[cur_test].correct_size = -1;
    tests[cur_test].chk_out_size = -1;
    if (open_tests_val && cur_test > 0 && cur_test < open_tests_count) {
      tests[cur_test].visibility = open_tests_val[cur_test];
    } else {
      tests[cur_test].visibility = TV_NORMAL;
    }

    time_limit_value = 0;
    if (srpp->time_limit_ms > 0) {
      time_limit_value += srpp->time_limit_ms;
    }
    if (time_limit_value > 0) {
      // adjustment works only for limited time
      if (tst->time_limit_adj_millis > 0)
        time_limit_value += tst->time_limit_adj_millis;
      else if (tst->time_limit_adjustment > 0)
        time_limit_value += tst->time_limit_adjustment * 1000;
      if (srgp->lang_time_limit_adj_ms > 0)
        time_limit_value += srgp->lang_time_limit_adj_ms;
    }

    pathmake(check_out_path, global->run_work_dir, "/", "checkout", NULL);
    pathmake(score_out_path, global->run_work_dir, "/", "scoreout", NULL);

    unlink(check_out_path);
    unlink(score_out_path);

    if (tst->nwrun_spool_dir[0]) {
      status = invoke_nwrun(tst, srp, far,
                            cur_test, 0, &has_real_time,
                            global->run_work_dir,
                            new_name, test_src, test_base, time_limit_value,
                            &tests[cur_test]);

      if (tests[cur_test].max_memory_used > 0) {
        has_max_memory_used = 1;
      }
      if (status) {
        failed_test = cur_test;
        total_failed_tests++;
        goto done_this_test;
      }
      goto run_checker;
    }

    /* Load test information file */
    if (srpp->use_info > 0) {
      snprintf(bname, sizeof(bname), srpp->info_pat, cur_test);
      snprintf(info_src, sizeof(path_t), "%s/%s", var_info_dir, bname);
      if ((errcode = testinfo_parse(info_src, &tstinfo)) < 0) {
        err("Cannot parse test info file '%s': %s", info_src,
            testinfo_strerror(-errcode));
        failed_test = cur_test;
        status = RUN_CHECK_FAILED;
        total_failed_tests++;
        goto done_this_test;
      }
    }

    disable_stderr = -1;
    if (srpp->use_info > 0 && tstinfo.disable_stderr >= 0) {
      disable_stderr = tstinfo.disable_stderr;
    }
    if (disable_stderr < 0) {
      disable_stderr = srpp->disable_stderr;
    }
    if (disable_stderr < 0) {
      disable_stderr = 0;
    }

    make_writable(tst->check_dir);
    clear_directory(tst->check_dir);
    check_free_space(tst->check_dir, expected_free_space);

    /* copy the executable */
    generic_copy_file(0, global->run_work_dir, new_name, "",
                      0, tst->check_dir, new_name, "");
    make_executable(exe_path);

    if (!srpp->use_tgz) {
      snprintf(prog_working_dir, sizeof(path_t), "%s", tst->check_dir);
    }
    if (srpp->use_tgz > 0) {
      snprintf(bname, sizeof(bname), srpp->tgz_pat, cur_test);
      snprintf(tgz_src, sizeof(tgz_src), "%s/%s", var_tgz_dir, bname);
      snprintf(bname, sizeof(bname), srpp->tgzdir_pat, cur_test);
      snprintf(tgz_src_dir, sizeof(tgz_src_dir), "%s/%s", var_tgz_dir, bname);
      snprintf(prog_working_dir, sizeof(prog_working_dir), "%s/%s", tst->check_dir, bname);
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
                      copy_flag, tst->check_dir, srpp->input_file, "");

    pathmake(input_path, tst->check_dir, "/", srpp->input_file, NULL);
    pathmake(output_path, tst->check_dir, "/", srpp->output_file, NULL);
    pathmake(error_path, tst->check_dir, "/", tst->error_file, NULL);

    if (var_interactor_cmd) {
      pathmake(output_path, global->run_work_dir, "/", srpp->output_file, NULL);
    }

    if (srpp->type_val > 0) {
      /* output-only problem */
      // copy exe_path -> output_path
      generic_copy_file(0, NULL, exe_path, "", 0, NULL, output_path, "");
    } else {
#ifndef __WIN32__
      // will not support interactive problems for now...
      /* run the interactor */
      if (var_interactor_cmd) {
        // the input file is opened from the test directory
        // the output file is in the run_work_dir
        if (pipe(pfd1) < 0) {
          // FIXME: report error
        }
        if (pipe(pfd2) < 0) {
          // FIXME: report error
        }
        // pfd1: prog -> interactor
        // pfd2: interactor -> prog
        tsk_int = task_New();
        task_AddArg(tsk_int, var_interactor_cmd);
        task_AddArg(tsk_int, test_src);
        task_AddArg(tsk_int, output_path);
        if (srpp->use_corr > 0) {
          snprintf(corr_path, sizeof(corr_path), "%s/%s", var_corr_dir, corr_base);
          task_AddArg(tsk_int, corr_path);
        }
        task_SetPathAsArg0(tsk_int);
        task_SetWorkingDir(tsk_int, prog_working_dir);
        setup_environment(tsk_int, srpp->interactor_env, ejudge_prefix_dir_env, NULL);
        task_SetRedir(tsk_int, 0, TSR_DUP, pfd1[0]);
        task_SetRedir(tsk_int, 1, TSR_DUP, pfd2[1]);
        task_SetRedir(tsk_int, pfd1[0], TSR_CLOSE);
        task_SetRedir(tsk_int, pfd1[1], TSR_CLOSE);
        task_SetRedir(tsk_int, pfd2[0], TSR_CLOSE);
        task_SetRedir(tsk_int, pfd2[1], TSR_CLOSE);
        task_SetRedir(tsk_int, 2, TSR_FILE, check_out_path, TSK_REWRITE, 
                      TSK_FULL_RW);
        task_EnableAllSignals(tsk_int);
        if (srpp->interactor_time_limit_ms > 0) {
          task_SetMaxTimeMillis(tsk_int, srpp->interactor_time_limit_ms);
        }

        if (task_Start(tsk_int) < 0) {
          /* failed to start task */
          status = RUN_CHECK_FAILED;
          tests[cur_test].code = task_ErrorCode(tsk_int, 0, 0);
          task_Delete(tsk_int); tsk_int = 0;
          total_failed_tests++;
          goto done_this_test;
        }
      }
#endif

      /* run the tested program */
      tsk = task_New();
      if (tst->start_cmd[0]) {
        unsigned char env_buf[1024];
        info("starting: %s %s", tst->start_cmd, arg0_path);
        task_AddArg(tsk, tst->start_cmd);
        if (srpp->input_file && srpp->input_file[0]) {
          snprintf(env_buf, sizeof(env_buf), "INPUT_FILE=%s", srpp->input_file);
          task_PutEnv(tsk, env_buf);
        }
        if (srpp->output_file && srpp->output_file[0]) {
          snprintf(env_buf, sizeof(env_buf),"OUTPUT_FILE=%s", srpp->output_file);
          task_PutEnv(tsk, env_buf);
        }
      } else {
        info("starting: %s", arg0_path);
      }
      //task_AddArg(tsk, exe_path);
      task_AddArg(tsk, arg0_path);
      if (srpp->use_info > 0 && tstinfo.cmd_argc >= 1) {
        task_pnAddArgs(tsk, tstinfo.cmd_argc, (char**) tstinfo.cmd_argv);
      }
      task_SetPathAsArg0(tsk);
      task_SetWorkingDir(tsk, prog_working_dir);
      if (var_interactor_cmd) {
        task_SetRedir(tsk, 0, TSR_DUP, pfd2[0]);
        task_SetRedir(tsk, 1, TSR_DUP, pfd1[1]);
        if (tst->ignore_stderr > 0) {
          task_SetRedir(tsk, 2,TSR_FILE, "/dev/null",TSK_WRITE,TSK_FULL_RW);
        } else {
          task_SetRedir(tsk, 2,TSR_FILE,error_path,TSK_REWRITE,TSK_FULL_RW);
        }
        task_SetRedir(tsk, pfd1[0], TSR_CLOSE);
        task_SetRedir(tsk, pfd1[1], TSR_CLOSE);
        task_SetRedir(tsk, pfd2[0], TSR_CLOSE);
        task_SetRedir(tsk, pfd2[1], TSR_CLOSE);
      } else {
        if (!tst->no_redirect || managed_mode_flag) {
          if (srpp->use_stdin && !tst->no_redirect) {
            task_SetRedir(tsk, 0, TSR_FILE, input_path, TSK_READ);
          } else {
            task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
          }
          if (srpp->use_stdout && srpp->use_info && tstinfo.check_stderr) {
            task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", TSK_WRITE,TSK_FULL_RW);
            task_SetRedir(tsk, 2, TSR_FILE,output_path,TSK_REWRITE,TSK_FULL_RW);
          } else if (srpp->use_stdout && !tst->no_redirect) {
            task_SetRedir(tsk, 1,TSR_FILE,output_path,TSK_REWRITE,TSK_FULL_RW);
            if (tst->ignore_stderr > 0 && disable_stderr <= 0) {
              task_SetRedir(tsk, 2,TSR_FILE, "/dev/null",TSK_WRITE,TSK_FULL_RW);
            } else {
              task_SetRedir(tsk, 2,TSR_FILE,error_path,TSK_REWRITE,TSK_FULL_RW);
            }
          } else {
            task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", TSK_WRITE,TSK_FULL_RW);
            // create empty output file
            tmpfd = open(output_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
            if (tmpfd >= 0) close(tmpfd);
            if (tst->ignore_stderr > 0 && disable_stderr <= 0) {
              task_SetRedir(tsk, 2, TSR_FILE,"/dev/null",TSK_WRITE,TSK_FULL_RW);
            } else {
              task_SetRedir(tsk, 2,TSR_FILE,error_path,TSK_REWRITE,TSK_FULL_RW);
            }
          }
        } else {
          // create empty output file
          tmpfd = open(output_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
          if (tmpfd >= 0) close(tmpfd);
          if (tst->ignore_stderr > 0 && disable_stderr <= 0) {
            task_SetRedir(tsk, 2, TSR_FILE, "/dev/null",TSK_WRITE,TSK_FULL_RW);
          } else {
            task_SetRedir(tsk, 2,TSR_FILE,error_path,TSK_REWRITE,TSK_FULL_RW);
          }
        }
      }

      if (tst->clear_env) task_ClearEnv(tsk);
      setup_environment(tsk, tst->start_env, ejudge_prefix_dir_env, &tstinfo);

      if (time_limit_value > 0) {
        if ((time_limit_value % 1000)) {
          task_SetMaxTimeMillis(tsk, time_limit_value);
        } else {
          task_SetMaxTime(tsk, time_limit_value / 1000);
        }
      }
      if (time_limit_value > 0 && report_time_limit_ms < 0) {
        report_time_limit_ms = time_limit_value;
      }

      if (srpp->real_time_limit_ms > 0) {
        task_SetMaxRealTimeMillis(tsk, srpp->real_time_limit_ms);
      }
      if (report_real_time_limit_ms < 0 && srpp->real_time_limit_ms > 0) {
        report_real_time_limit_ms = srpp->real_time_limit_ms;
      }
      if (tst->kill_signal[0]) task_SetKillSignal(tsk, tst->kill_signal);
      if (tst->no_core_dump) task_DisableCoreDump(tsk);
      if (tst->memory_limit_type_val < 0) {
        // compatibility stuff
        // debug
#if 0
        fprintf(stderr,
                "memory limit type: legacy\n"
                "max_vm_size:       %zu\n"
                "max_stack_size:    %zu\n"
                "max_data_size:     %zu\n",
                tst->max_vm_size,
                tst->max_stack_size,
                tst->max_data_size);
#endif
        if (tst->max_stack_size && tst->max_stack_size != -1L)
          task_SetStackSize(tsk, tst->max_stack_size);
        if (tst->max_data_size && tst->max_data_size != -1L)
          task_SetDataSize(tsk, tst->max_data_size);
        if (tst->max_vm_size && tst->max_vm_size != -1L)
          task_SetVMSize(tsk, tst->max_vm_size);
        if (tst->enable_memory_limit_error && srgp->enable_memory_limit_error
            && srgp->secure_run) {
          task_EnableMemoryLimitError(tsk);
        }
        if (tst->enable_memory_limit_error && srgp->secure_run
            && srgp->detect_violations) {
          task_EnableSecurityViolationError(tsk);
        }
      } else {
        switch (tst->memory_limit_type_val) {
        case MEMLIMIT_TYPE_DEFAULT:
          // debug
#if 0
          fprintf(stderr,
                  "memory limit type: default\n"
                  "max_vm_size:       %zu\n"
                  "max_stack_size:    %zu\n"
                  "max_data_size:     %zu\n",
                  prb->max_vm_size,
                  prb->max_stack_size,
                  prb->max_data_size);
#endif
          if (srpp->max_stack_size && srpp->max_stack_size != (size_t) -1L)
            task_SetStackSize(tsk, srpp->max_stack_size);
          if (srpp->max_data_size && srpp->max_data_size != (size_t) -1L)
            task_SetDataSize(tsk, srpp->max_data_size);
          if (srpp->max_vm_size && srpp->max_vm_size != (size_t) -1L)
            task_SetVMSize(tsk, srpp->max_vm_size);
          if (tst->enable_memory_limit_error && srgp->enable_memory_limit_error
              && srgp->secure_run) {
            task_EnableMemoryLimitError(tsk);
          }
          if (tst->enable_memory_limit_error
              && srgp->secure_run && srgp->detect_violations) {
            task_EnableSecurityViolationError(tsk);
          }
          break;
        case MEMLIMIT_TYPE_JAVA:
          java_flags_ptr = flags_buf;
          java_flags_ptr += sprintf(java_flags_ptr, "EJUDGE_JAVA_FLAGS=");
          if (srpp->max_vm_size && srpp->max_vm_size != (size_t) -1L) {
            java_flags_ptr += sprintf(java_flags_ptr, "-Xmx%s",
                                      size_t_to_size(bb, sizeof(bb),
                                                     srpp->max_vm_size));
          }
          if (srpp->max_stack_size && srpp->max_stack_size != (size_t) -1L) {
            if (java_flags_ptr[-1] != '=') *java_flags_ptr++ = ' ';
            *java_flags_ptr = 0;
            java_flags_ptr += sprintf(java_flags_ptr, "-Xss%s",
                                      size_t_to_size(bb, sizeof(bb),
                                                     srpp->max_stack_size));
                                                     
          }
          if (java_flags_ptr[-1] != '=') {
            task_PutEnv(tsk, flags_buf);
          }
          // debug
#if 0
          fprintf(stderr,
                  "memory limit type: java\n"
                  "max_vm_size:       %zu\n"
                  "max_stack_size:    %zu\n"
                  "max_data_size:     %zu\n"
                  "environment:       %s\n",
                  prb->max_vm_size,
                  prb->max_stack_size,
                  prb->max_data_size,
                  flags_buf);
#endif
          break;

        case MEMLIMIT_TYPE_DOS:
          // debug
#if 0
          fprintf(stderr,
                  "memory limit type: dos\n");
#endif
          // dosbox has natural memory limit :)
          break;
        default:
          abort();
        }
      }
      if (tst->secure_exec_type_val > 0) {
        switch (tst->secure_exec_type_val) {
        case SEXEC_TYPE_STATIC:
          if (srgp->secure_run) {
            if (task_EnableSecureExec(tsk) < 0) {
              // FIXME: also report this condition
              err("task_EnableSecureExec() failed");
              status = RUN_CHECK_FAILED;
              tests[cur_test].code = 0;
              task_Delete(tsk); tsk = 0;
              if (tsk_int) task_Delete(tsk_int);
              tsk_int = 0;
              if (pfd1[0] >= 0) close(pfd1[0]);
              if (pfd1[1] >= 0) close(pfd1[1]);
              if (pfd2[0] >= 0) close(pfd2[0]);
              if (pfd2[1] >= 0) close(pfd2[1]);
              pfd1[0] = pfd1[1] = pfd2[0] = pfd2[1] = -1;
              total_failed_tests++;
              goto done_this_test;
            }
          }
          break;
        case SEXEC_TYPE_DLL:
          if (srgp->secure_run) {
            task_PutEnv(tsk, "LD_BIND_NOW=1");
            snprintf(flags_buf, sizeof(flags_buf),
                     "LD_PRELOAD=%s/lang/libdropcaps.so", EJUDGE_SCRIPT_DIR);
            task_PutEnv(tsk, flags_buf);
          }
          break;
        case SEXEC_TYPE_DLL32:
          if (srgp->secure_run) {
            task_PutEnv(tsk, "LD_BIND_NOW=1");
            snprintf(flags_buf, sizeof(flags_buf),
                     "LD_PRELOAD=%s/lang/libdropcaps32.so", EJUDGE_SCRIPT_DIR);
            task_PutEnv(tsk, flags_buf);
          }
          break;
        case SEXEC_TYPE_JAVA:
          if (srgp->secure_run) {
            task_PutEnv(tsk, "EJUDGE_JAVA_POLICY=fileio.policy");
            /*
            if (!prb->use_stdin || !prb->use_stdout) {
              task_PutEnv(tsk, "EJUDGE_JAVA_POLICY=fileio.policy");
            }
            */
          } else {
            task_PutEnv(tsk, "EJUDGE_JAVA_POLICY=none");
          }
          break;
        default:
          abort();
        }
      }

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
      task_EnableAllSignals(tsk);

      if (srpp->max_core_size && srpp->max_core_size != (size_t) -1L) {
        task_SetMaxCoreSize(tsk, srpp->max_core_size);
      }
      if (srpp->max_file_size && srpp->max_file_size != (size_t) -1L) {
        task_SetMaxFileSize(tsk, srpp->max_file_size);
      }
      if (srpp->max_open_file_count > 0) {
        task_SetMaxOpenFileCount(tsk, srpp->max_open_file_count);
      }
      if (srpp->max_process_count > 0) {
        task_SetMaxProcessCount(tsk, srpp->max_process_count);
      }

      if (task_Start(tsk) < 0) {
        /* failed to start task */
        status = RUN_CHECK_FAILED;
        tests[cur_test].code = task_ErrorCode(tsk, 0, 0);
        task_Delete(tsk); tsk = 0;
        if (tsk_int) task_Delete(tsk_int);
        tsk_int = 0;
        if (pfd1[0] >= 0) close(pfd1[0]);
        if (pfd1[1] >= 0) close(pfd1[1]);
        if (pfd2[0] >= 0) close(pfd2[0]);
        if (pfd2[1] >= 0) close(pfd2[1]);
        pfd1[0] = pfd1[1] = pfd2[0] = pfd2[1] = -1;
        total_failed_tests++;
        goto done_this_test;
      }

      if (pfd1[0] >= 0) close(pfd1[0]);
      if (pfd1[1] >= 0) close(pfd1[1]);
      if (pfd2[0] >= 0) close(pfd2[0]);
      if (pfd2[1] >= 0) close(pfd2[1]);
      pfd1[0] = pfd1[1] = pfd2[0] = pfd2[1] = -1;

      /* task hopefully started */
      task_Wait(tsk);

      if (tsk) task_Log(tsk, 0, LOG_INFO);

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

      if (tsk_int) task_Wait(tsk_int);
      //task_Delete(tsk_int); tsk_int = 0;
    } /* if (!prb->output_only) */

    /* set normal permissions for the working directory */
    make_writable(tst->check_dir);
    /* make the output file readable */
    if (chmod(output_path, 0600) < 0) {
      err("chmod failed: %s", os_ErrorMsg());
    }

    /* fill test report structure */
    if (tsk) {
      tests[cur_test].times = task_GetRunningTime(tsk);
      has_real_time = 1;
      tests[cur_test].real_time = task_GetRealTime(tsk);
    }
    if (srgp->enable_full_archive) {
      filehash_get(test_src, tests[cur_test].input_digest);
      tests[cur_test].has_input_digest = 1;
    } else {
      // ignore file if binary_input
      file_size = -1;
      if (srpp->binary_input <= 0)
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
    file_size = -1;
    if (srpp->binary_input <= 0)
      file_size = generic_file_size(0, output_path, 0);
    if (file_size >= 0) {
      tests[cur_test].output_size = file_size;
      if (global->max_file_length > 0 && !srgp->enable_full_archive
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
      if (global->max_file_length > 0 && !srgp->enable_full_archive
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
    if (srpp->use_info) {
      size_t cmd_args_len = 0;
      int i;
      unsigned char *args = 0, *s;

      if (srgp->enable_full_archive) {
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

    if (tsk && tst->enable_memory_limit_error && srgp->enable_memory_limit_error
        && srgp->secure_run && task_IsMemoryLimit(tsk)) {
      failed_test = cur_test;
      status = RUN_MEM_LIMIT_ERR;
      total_failed_tests++;
      task_Delete(tsk); tsk = 0;
      if (tsk_int) task_Delete(tsk_int);
      tsk_int = 0;
      goto done_this_test;
    }

    if (tsk && tst->enable_memory_limit_error && srgp->detect_violations
        && srgp->secure_run && task_IsSecurityViolation(tsk)) {
      failed_test = cur_test;
      status = RUN_SECURITY_ERR;
      total_failed_tests++;
      task_Delete(tsk); tsk = 0;
      if (tsk_int) task_Delete(tsk_int);
      tsk_int = 0;
      goto done_this_test;
    }

    if (tsk && task_IsTimeout(tsk)) {
      failed_test = cur_test;
      status = RUN_TIME_LIMIT_ERR;
      total_failed_tests++;
      task_Delete(tsk); tsk = 0;
      if (tsk_int) task_Delete(tsk_int);
      tsk_int = 0;
      goto done_this_test;
    }

    if (tsk && srpp->use_info && tstinfo.exit_code > 0) {
      if (task_Status(tsk) == TSK_SIGNALED) {
        tests[cur_test].code = 256; /* FIXME: magic */
        tests[cur_test].termsig = task_TermSignal(tsk);
        failed_test = cur_test;
        status = RUN_RUN_TIME_ERR;
        total_failed_tests++;
        task_Delete(tsk); tsk = 0;
        if (tsk_int) task_Delete(tsk_int);
        tsk_int = 0;
        goto done_this_test;
      }
      tests[cur_test].code = task_ExitCode(tsk);
      if (tests[cur_test].code != tstinfo.exit_code) {
        failed_test = cur_test;
        status = RUN_WRONG_ANSWER_ERR;
        total_failed_tests++;
        task_Delete(tsk); tsk = 0;
        if (tsk_int) task_Delete(tsk_int);
        tsk_int = 0;
        goto done_this_test;
      }
    } else if (tsk && ((error_code[0] && !srpp->ignore_exit_code && ec != 0)
                       || (!error_code[0]
                           && ((!srpp->ignore_exit_code
                                && task_IsAbnormal(tsk))
                               || (srpp->ignore_exit_code
                                   && task_Status(tsk) == TSK_SIGNALED))))) {
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
      if (tsk_int) task_Delete(tsk_int);
      tsk_int = 0;
      goto done_this_test;
    }

    task_Delete(tsk); tsk = 0;

    if (var_interactor_cmd) {
      if (task_IsTimeout(tsk_int)) {
        append_msg_to_log(check_out_path, "interactor timeout");
        err("interactor timeout");
        status = RUN_CHECK_FAILED;
        failed_test = cur_test;
        goto read_checker_output;
      } else {
        task_Log(tsk_int, 0, LOG_INFO);
        if (task_Status(tsk_int) == TSK_SIGNALED) {
          jj = task_TermSignal(tsk_int);
          append_msg_to_log(check_out_path,
                            "interactor terminated with signal %d (%s)",
                            jj, os_GetSignalString(jj));
          status = RUN_CHECK_FAILED;
          failed_test = cur_test;
          goto read_checker_output;
        } else {
          jj = task_ExitCode(tsk_int);
          if (jj == RUN_OK) {
            // do nothing
          } else if (jj == RUN_PRESENTATION_ERR || jj == RUN_WRONG_ANSWER_ERR) {
            status = jj;
            failed_test = cur_test;
            total_failed_tests++;
            goto read_checker_output;
          } else {
            append_msg_to_log(check_out_path,
                              "checker exited with code %d", jj);
            status = RUN_CHECK_FAILED;
            failed_test = cur_test;
            goto read_checker_output;
          }
        }
      }
    }

  run_checker:;
    if (disable_stderr > 0 && tests[cur_test].error_size > 0) {
      append_msg_to_log(check_out_path, "non-empty output to stderr");
      status = RUN_PRESENTATION_ERR;
      failed_test = cur_test;
      total_failed_tests++;
      goto read_checker_output;
    }

    if (srpp->standard_checker && srpp->standard_checker[0]) {
      snprintf(check_cmd, sizeof(check_cmd), "%s/%s",
               global->ejudge_checkers_dir, srpp->standard_checker);
    } else {
      snprintf(check_cmd, sizeof(check_cmd), "%s", srpp->check_cmd);
    }

    /* now start checker */
    /* checker <input data> <output result> <corr answer> <info file> */
    info("starting checker: %s %s %s", check_cmd, test_src,
         srpp->output_file);

    tsk = task_New();
    task_AddArg(tsk, check_cmd);
    task_AddArg(tsk, test_src);
    if (var_interactor_cmd) {
      task_AddArg(tsk, output_path);
    } else {
      task_AddArg(tsk, srpp->output_file);
    }
    if (srpp->use_corr) {
      snprintf(corr_path, sizeof(corr_path), "%s/%s", var_corr_dir, corr_base);
      task_AddArg(tsk, corr_path);
      if (srgp->enable_full_archive) {
        filehash_get(corr_path, tests[cur_test].correct_digest);
        tests[cur_test].has_correct_digest = 1;
      } else {
        file_size = -1;
        if (srpp->binary_input <= 0)
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
    if (srpp->use_info) {
      task_AddArg(tsk, info_src);
    }
    if (srpp->use_tgz) {
      task_AddArg(tsk, tgz_src_dir);
      task_AddArg(tsk, prog_working_dir);
    }
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
    if (srpp->scoring_checker > 0) {
      task_SetRedir(tsk, 1, TSR_FILE, score_out_path,
                    TSK_REWRITE, TSK_FULL_RW);
      if (var_interactor_cmd) {
        task_SetRedir(tsk, 2, TSR_FILE, check_out_path,
                      TSK_APPEND, TSK_FULL_RW);
      } else {
        task_SetRedir(tsk, 2, TSR_FILE, check_out_path,
                      TSK_REWRITE, TSK_FULL_RW);
      }
    } else {
      if (var_interactor_cmd) {
        task_SetRedir(tsk, 1, TSR_FILE, check_out_path,
                      TSK_APPEND, TSK_FULL_RW);
      } else {
        task_SetRedir(tsk, 1, TSR_FILE, check_out_path,
                      TSK_REWRITE, TSK_FULL_RW);
      }
      task_SetRedir(tsk, 2, TSR_DUP, 1);
    }
    task_SetWorkingDir(tsk, tst->check_dir);
    task_SetPathAsArg0(tsk);
    if (srpp->checker_real_time_limit_ms > 0) {
      task_SetMaxRealTimeMillis(tsk, srpp->checker_real_time_limit_ms);
    }
    setup_environment(tsk, srpp->checker_env, ejudge_prefix_dir_env, NULL);
    task_EnableAllSignals(tsk);

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

    force_check_failed = 0;
    if (srpp->scoring_checker && !task_IsTimeout(tsk)
        && task_Status(tsk) == TSK_EXITED
        && (task_ExitCode(tsk) == RUN_WRONG_ANSWER_ERR
            || task_ExitCode(tsk) == RUN_OK)) {
      switch (srgp->scoring_system_val) {
      case SCORE_KIROV:
      case SCORE_OLYMPIAD:
        test_max_score = -1;
        if (test_score_val && cur_test > 0 && cur_test < test_score_count) {
          test_max_score = test_score_val[cur_test];
        }
        if (test_max_score < 0) {
          test_max_score = srpp->test_score;
        }
        if (test_max_score < 0) test_max_score = 0;
        break;
      case SCORE_MOSCOW:
        test_max_score = srpp->full_score - 1;
        break;
      case SCORE_ACM:
        test_max_score = 0;
        break;
      default:
        abort();
      }
      if (read_checker_score(score_out_path, check_out_path, "checker",
                             test_max_score,
                             &tests[cur_test].checker_score) < 0) {
        force_check_failed = 1;
      }
    }

    /* analyze error codes */
    if (force_check_failed) {
      status = RUN_CHECK_FAILED;
      failed_test = cur_test;
    } else if (task_IsTimeout(tsk)) {
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
      case RUN_CHECK_FAILED:
        /* this might be expected from the checker */
        break;
      case RUN_WRONG_ANSWER_ERR:
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

    // read the checker output
  read_checker_output:;
    file_size = generic_file_size(0, check_out_path, 0);
    if (file_size >= 0) {
      tests[cur_test].chk_out_size = file_size;
      if (!srgp->enable_full_archive) {
        generic_read_file(&tests[cur_test].chk_out, 0, 0, 0, 0, check_out_path, "");
      }
      if (far) {
        snprintf(arch_entry_name, sizeof(arch_entry_name),
                 "%06d.c", cur_test);
        //info("appending checker output to archive");
        full_archive_append_file(far, arch_entry_name, 0, check_out_path);
      }
    }

  done_this_test:
    if (srpp->use_info) {
      testinfo_free(&tstinfo);
    }
    tests[cur_test].status = status;
    cur_test++;
    total_tests++;
    if (status > 0) {
      // test failed, how to react on this
      if (srgp->scoring_system_val == SCORE_ACM) break;
      if (srgp->scoring_system_val == SCORE_MOSCOW) break;
      if (srgp->scoring_system_val == SCORE_OLYMPIAD
          && accept_testing && !accept_partial) break;
    }
    clear_directory(tst->check_dir);
  }

  /* TESTING COMPLETED (SOMEHOW) */

  /* look for RUN_CHECK_FAILED status */
  for (jj = 1; jj < total_tests; ++jj) {
    if (tests[jj].status == RUN_CHECK_FAILED) break;
  }
  if (jj < total_tests) {
    reply_pkt->status = RUN_CHECK_FAILED;
    get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);
    goto done2;
  }

  if (srgp->scoring_system_val == SCORE_OLYMPIAD && accept_testing) {
    if (accept_partial) {
      status = RUN_ACCEPTED;
      failed_test = 1;
      // FIXME: this seems broken?
      for (jj = 1; jj <= srpp->tests_to_accept; jj++) {
        if (tests[jj].status == RUN_OK)
          failed_test++;
      }
    } else if (srpp->min_tests_to_accept >= 0) {
      if (!failed_test) {
        status = RUN_ACCEPTED;
        failed_test = cur_test;
      } else if (failed_test > srpp->min_tests_to_accept)
        status = RUN_ACCEPTED;
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
  } else if (srgp->scoring_system_val == SCORE_KIROV
             || srgp->scoring_system_val == SCORE_OLYMPIAD) {
    int retcode = RUN_OK;

    for (jj = 1; jj < total_tests; jj++) {
      int this_score = -1;
      if (jj < test_score_count) {
        this_score = test_score_val[jj];
      }
      if (this_score < 0) {
        this_score = srpp->test_score;
      }
      if (this_score < 0) {
        this_score = 0;
      }
      tests[jj].score = 0;
      tests[jj].max_score = this_score;
      if (srpp->scoring_checker
          && (tests[jj].status == RUN_OK
              || tests[jj].status == RUN_PRESENTATION_ERR
              || tests[jj].status == RUN_WRONG_ANSWER_ERR)) {
      } else if (tests[jj].status == RUN_OK) {
        score += this_score;
        tests[jj].score = this_score;
      }
      if (tests[jj].status != RUN_OK) {
        retcode = RUN_PARTIAL;
      }
    }

#if 0
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
#endif

    if (!total_failed_tests) score = srpp->full_score;

    /* ATTENTION: number of passed test returned is greater than actual by 1,
     * and it is returned in the `failed_test' field
     */
    reply_pkt->status = retcode;
    reply_pkt->failed_test = total_tests - total_failed_tests;
    reply_pkt->score = score;
    get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);

    if (global->sound_player[0] && global->extended_sound && !srgp->disable_sound) {
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
#if 0
    // FIXME!
    if (srgp->scoring_system_val == SCORE_MOSCOW) {
      reply_pkt->score = srpp->full_score;
      if (status != RUN_OK) {
        int s;

        ASSERT(failed_test <= prb->ntests && failed_test > 0);
        if (prb->scoring_checker) {
          reply_pkt->score = tests[failed_test].checker_score;
        } else {
          for (s = 0; failed_test > prb->x_score_tests[s]; s++);
          reply_pkt->score = s;
        }
      }
    }
#endif
    get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);

    if (global->sound_player[0] && global->extended_sound && !srgp->disable_sound) {
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
    } else if (global->sound_player[0] && !srgp->disable_sound) {
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

done2:

  get_current_time(&reply_pkt->ts7, &reply_pkt->ts7_us);

  has_user_score = 0;
  user_status = -1;
  user_score = -1;
  user_tests_passed = -1;
  user_run_tests = -1;
  if (srpp->valuer_cmd && srpp->valuer_cmd[0] && !srgp->accepting_mode
      && !reply_pkt->status != RUN_CHECK_FAILED) {
    if (invoke_valuer(global, srp, cur_variant, srpp->full_score,
                      &score, &marked_flag,
                      &user_status, &user_score, &user_tests_passed,
                      &valuer_errors, &valuer_comment,
                      &valuer_judge_comment) < 0) {
      reply_pkt->status = RUN_CHECK_FAILED;
    } else {
      reply_pkt->score = score;
      reply_pkt->marked_flag = marked_flag;
    }
  }

  if (reply_pkt->status == RUN_CHECK_FAILED) {
    user_status = -1;
    user_score = -1;
    user_tests_passed = -1;
    user_run_tests = -1;
  } else if (global->separate_user_score <= 0) {
    user_status = -1;
    user_score = -1;
    user_tests_passed = -1;
    user_run_tests = -1;
  } else {
    has_user_score = 1;
    user_run_tests = 0;
    for (cur_test = 1; cur_test < total_tests; ++cur_test) {
      if (tests[cur_test].visibility != TV_HIDDEN)
        ++user_run_tests;
    }
    if (user_status < 0) {
      user_status = RUN_OK;
      for (cur_test = 1; cur_test < total_tests; ++cur_test) {
        if (tests[cur_test].visibility != TV_HIDDEN
            && tests[cur_test].status != RUN_OK) {
          user_status = RUN_PARTIAL;
          break;
        }
      }
    }
    if (srgp->scoring_system_val == SCORE_KIROV
        || (srgp->scoring_system_val == SCORE_OLYMPIAD && !srgp->accepting_mode)) {
      if (user_score < 0) {
        if (srpp->variable_full_score <= 0 && user_status == RUN_OK) {
          if (srpp->full_user_score >= 0) {
            user_score = srpp->full_user_score;
          } else {
            user_score = srpp->full_score;
          }
        } else {
          user_score = 0;
          for (cur_test = 1; cur_test < total_tests; ++cur_test) {
            if (tests[cur_test].visibility != TV_HIDDEN
                && tests[cur_test].score >= 0) {
              user_score += tests[cur_test].score;
            }
          }
          if (srpp->variable_full_score <= 0) {
            if (srpp->full_user_score >= 0 && user_score > srpp->full_user_score) {
              user_score = srpp->full_user_score;
            } else if (user_score > srpp->full_score) {
              user_score = srpp->full_score;
            }
          }
        }
      }
      if (user_tests_passed < 0) {
        user_tests_passed = 0;
        for (cur_test = 1; cur_test < total_tests; ++cur_test) {
          if (tests[cur_test].visibility != TV_HIDDEN
              && tests[cur_test].status == RUN_OK)
            ++user_tests_passed;
        }
      }
    }
  }

  reply_pkt->has_user_score = has_user_score;
  reply_pkt->user_status = user_status;
  reply_pkt->user_score = user_score;
  reply_pkt->user_tests_passed = user_tests_passed;

  generate_xml_report(srp, reply_pkt, report_path, cur_variant,
                      score, srpp->full_score, srpp->full_user_score,
                      srpp->use_corr, srpp->use_info,
                      report_time_limit_ms, report_real_time_limit_ms,
                      has_real_time, has_max_memory_used, marked_flag,
                      user_run_tests,
                      additional_comment, valuer_comment,
                      valuer_judge_comment, valuer_errors);

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
  xfree(valuer_comment);
  xfree(valuer_judge_comment);
  xfree(valuer_errors);
  xfree(open_tests_val);
  xfree(test_score_val);
  for (cur_test = 1; cur_test < total_tests; cur_test++) {
    xfree(tests[cur_test].input);
    xfree(tests[cur_test].output);
    xfree(tests[cur_test].error);
    xfree(tests[cur_test].chk_out);
    xfree(tests[cur_test].correct);
    xfree(tests[cur_test].args);
    xfree(tests[cur_test].comment);
    xfree(tests[cur_test].team_comment);
    xfree(tests[cur_test].exit_comment);
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

  if (cr_serialize_init(&serve_state) < 0) return -1;
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

    r = scan_dir(global->run_queue_dir, pkt_name, sizeof(pkt_name));
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
    xfree(srp_b); srp_b = NULL; srp_z = 0;
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
      cr_serialize_lock(&serve_state);
      run_inverse_testing(&serve_state, srp, &reply_pkt,
                          pkt_name, report_path, sizeof(report_path),
                          utf8_mode);
      cr_serialize_unlock(&serve_state);
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

      if (cr_serialize_lock(&serve_state) < 0) return -1;
      if (run_tests(tst, srp, &reply_pkt,
                    srgp->accepting_mode,
                    srpp->accept_partial, srgp->variant,
                    exe_name, run_base,
                    report_path, full_report_path,
                    srgp->user_spelling,
                    srpp->spelling) < 0) {
        cr_serialize_unlock(&serve_state);
        return -1;
      }
      if (cr_serialize_unlock(&serve_state) < 0) return -1;

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
      if (tn.prepare_cmd[0] && check_executable(tn.prepare_cmd) < 0) return -1;
      if (tn.start_cmd[0] && check_executable(tn.start_cmd) < 0) return -1;
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
          if (!prb->corr_dir[0]) {
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
          if ((n2 = count_files(var_corr_dir,prb->corr_sfx,prb->corr_pat)) < 0)
            return -1;
          n1 = n2;
          info("found %d answers for problem %s", n2, prb->short_name);
          if (n2 != 1) {
            err("output-only problem must define only one answer file");
            return -1;
          }
        }
        if (prb->use_info) {
          if (!prb->info_dir[0]) {
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
          if ((n2 = count_files(var_info_dir,prb->info_sfx,prb->info_pat)) < 0)
            return -1;
          info("found %d info files for problem %s", n2, prb->short_name);
          if (n2 != 1) {
            err("output-only problem must define only one info file");
            return -1;
          }
        }
        if (prb->use_tgz) {
          if (!prb->tgz_dir[0]) {
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
            if (!prb->corr_dir[0]) {
              err("directory with answers is not defined");
              return -1;
            }
            if (check_readable_dir(var_corr_dir) < 0) return -1;
            if ((j = count_files(var_corr_dir,prb->corr_sfx,prb->corr_pat)) < 0)
              return -1;
            if (j != 1) {
              err("output-only problem must define only one answer file");
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
            if (j != 1) {
              err("output-only problem must define only one info file");
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
          if (!prb->corr_dir[0]) {
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
          if ((n2 = count_files(var_corr_dir,prb->corr_sfx,prb->corr_pat)) < 0)
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
          if (!prb->tgz_dir[0]) {
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
      if (score_summ > prb->full_score && !prb->valuer_cmd[0]) {
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
    if (serve_state.testers[i]->prepare_cmd[0]
        && check_executable(serve_state.testers[i]->prepare_cmd) < 0) return -1;
    if (serve_state.testers[i]->start_cmd[0]
        && check_executable(serve_state.testers[i]->start_cmd) < 0) return -1;
  }

  info("checking default testers...");
  if ((i = process_default_testers()) < 0) return -1;
  info("checking default testers done");
  total += i;

  if (!total) info("no testers");

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

  if (prepare(&serve_state, argv[i], p_flags, PREPARE_RUN,
              cpp_opts, managed_mode_flag, 0, 0) < 0)
    return 1;
  if (filter_testers(key) < 0) return 1;
  if (create_dirs(&serve_state, PREPARE_RUN) < 0) return 1;
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

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "tTask")
 * End:
 */
