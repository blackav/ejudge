/* -*- c -*- */

/* Copyright (C) 2012-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/misctext.h"
#include "ejudge/prepare.h"
#include "ejudge/run_packet.h"
#include "ejudge/super_run_packet.h"
#include "ejudge/run.h"
#include "ejudge/errlog.h"
#include "ejudge/runlog.h"
#include "ejudge/digest_io.h"
#include "ejudge/fileutl.h"
#include "ejudge/testinfo.h"
#include "ejudge/full_archive.h"
#include "ejudge/win32_compat.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/interrupt.h"
#include "ejudge/nwrun_packet.h"
#include "ejudge/filehash.h"
#include "ejudge/curtime.h"
#include "ejudge/cpu.h"
#include "ejudge/ej_process.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/base64.h"
#include "ejudge/ej_libzip.h"
#include "ejudge/agent_client.h"
#include "ejudge/random.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"
#include "ejudge/exec.h"
#include "ejudge/logger.h"
#include "ejudge/process_stats.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <utime.h>
#include <sys/mman.h>
#ifndef __MINGW32__
#include <sys/vfs.h>
#endif
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#define SIZE_G (1024 * 1024 * 1024)
#define SIZE_M (1024 * 1024)
#define SIZE_K (1024)

static void
mirror_file(
        struct AgentClient *agent,
        unsigned char *buf,
        int size,
        const unsigned char *mirror_dir);
static void
read_run_test_file(
        const struct super_run_in_global_packet *srgp,
        struct run_test_file *rtf,
        const unsigned char *path,
        int utf8_mode);

static unsigned char*
ej_size64_t_to_size(unsigned char *buf, size_t buf_size, ej_size64_t num)
{
  if (!num) snprintf(buf, buf_size, "0");
  else if (!(num % SIZE_G)) snprintf(buf, buf_size, "%lldG", num / SIZE_G);
  else if (!(num % SIZE_M)) snprintf(buf, buf_size, "%lldM", num / SIZE_M);
  else if (!(num % SIZE_K)) snprintf(buf, buf_size, "%lldK", num / SIZE_K);
  else snprintf(buf, buf_size, "%lld", num);
  return buf;
}

static unsigned char *
prepare_checker_comment(int utf8_mode, const unsigned char *str)
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

static int
need_base64(unsigned char *data, long long size)
{
  if (!data) return 0;
  if (size > 1000000000) return 1;
  long sz = size;
  for (int i = 0; i < sz; ++i) {
    unsigned char c = data[i];
    if (c == 127) {
      return 1;
    } else if (c >= ' ' || c == '\t' || c == '\n' || c == '\r') {
    } else {
      return 1;
    }
  }
  return 0;
}

static void
make_file_content_2(
        struct testing_report_file_content *fc,
        const struct super_run_in_global_packet *srgp,
        const struct run_test_file *rtf)
{
  if (!rtf->is_here) {
    fc->size = -1;
    fc->orig_size = -1;
    fc->data = NULL;
    fc->is_too_big = 0;
    fc->is_base64 = 0;
  } else if (rtf->is_too_long || rtf->is_too_wide) {
    fc->size = rtf->stored_size;
    fc->orig_size = rtf->orig_size;
    fc->is_too_big = 1;
    fc->is_base64 = rtf->is_base64;
    if (rtf->data) {
      fc->data = xmalloc(rtf->stored_size + 1);
      memcpy(fc->data, rtf->data, rtf->stored_size);
      fc->data[fc->size] = 0;
    }
  } else {
    fc->size = rtf->stored_size;
    fc->orig_size = rtf->orig_size;
    fc->is_too_big = 0;
    fc->is_base64 = rtf->is_base64;
    if (rtf->data) {
      fc->data = xmalloc(rtf->stored_size + 1);
      memcpy(fc->data, rtf->data, rtf->stored_size);
      fc->data[fc->size] = 0;
    }
  }
}

static __attribute__((unused))  void
make_file_content(
        struct testing_report_file_content *fc,
        const struct super_run_in_global_packet *srgp,
        unsigned char *data,
        long long size,
        int utf8_mode)
{
  if (size < 0) {
    fc->size = -1;
    fc->orig_size = -1;
    fc->data = NULL;
    fc->is_too_big = 0;
    fc->is_base64 = 0;
  } else if (size > srgp->max_file_length) {
    fc->is_too_big = 1;
    fc->size = 0;
    fc->orig_size = size;
    fc->data = NULL;
    fc->is_base64 = 0;
  } else if (need_base64(data, size)) {
    fc->is_too_big = 0;
    fc->is_base64 = 1;
    fc->orig_size = -1;
    fc->size = size;
    fc->data = xmalloc(size * 4 / 3 + 64);
    int len = base64_encode(data, size, fc->data);
    fc->data[len] = 0;
  } else {
    fc->is_too_big = 0;
    fc->is_base64 = 0;
    fc->size = size;
    fc->orig_size = -1;
    fc->data = xmemdup(data, size);
    if (utf8_mode) {
      utf8_fix_string(fc->data, NULL);
    }
  }
}

static const unsigned int status_to_bit_map[] =
{
  [RUN_OK]                  = RUN_OK_BIT,
  [RUN_RUN_TIME_ERR]        = RUN_RUN_TIME_ERR_BIT,
  [RUN_TIME_LIMIT_ERR]      = RUN_TIME_LIMIT_ERR_BIT,
  [RUN_PRESENTATION_ERR]    = RUN_PRESENTATION_ERR_BIT,
  [RUN_WRONG_ANSWER_ERR]    = RUN_WRONG_ANSWER_ERR_BIT,
  [RUN_CHECK_FAILED]        = RUN_CHECK_FAILED_BIT,
  [RUN_MEM_LIMIT_ERR]       = RUN_MEM_LIMIT_ERR_BIT,
  [RUN_SECURITY_ERR]        = RUN_SECURITY_ERR_BIT,
  [RUN_WALL_TIME_LIMIT_ERR] = RUN_WALL_TIME_LIMIT_ERR_BIT,
  [RUN_SKIPPED]             = RUN_SKIPPED_BIT,
  [RUN_SYNC_ERR]            = RUN_SYNC_ERR_BIT,
};

static __attribute__((unused)) void
print_run_test_file(
        FILE *fout,
        const unsigned char *title,
        const struct run_test_file *rtf)
{
  fprintf(fout, "%s: { "
          "\"orig_size\": %zd,"
          "\"stored_size\": %zd,"
          "\"is_here\":%d,"
          "\"is_binary\":%d,"
          "\"is_too_long\":%d,"
          "\"is_too_wide\":%d,"
          "\"is_fixed\":%d,"
          "\"is_base64\":%d,"
          "\"is_archived\":%d,"
          "}\n",
          title, rtf->orig_size, rtf->stored_size,
          rtf->is_here, rtf->is_binary, rtf->is_too_long,
          rtf->is_too_wide, rtf->is_fixed,
          rtf->is_base64, rtf->is_archived);
}

static int
generate_xml_report(
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        const unsigned char *report_path,
        int total_tests,
        const struct run_test_info *tests,
        int utf8_mode,
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
        int has_max_rss,
        int marked_flag,
        int user_run_tests,
        const unsigned char *additional_comment,
        const unsigned char *valuer_comment,
        const unsigned char *valuer_judge_comment,
        const unsigned char *valuer_errors,
        const unsigned char *cpu_model,
        const unsigned char *cpu_mhz,
        const unsigned char *hostname)
{
  int i;
  unsigned char *msg = 0;
  const struct super_run_in_global_packet *srgp = srp->global;

  ej_uuid_t judge_uuid = {};
  if (srgp->judge_uuid && srgp->judge_uuid[0]) {
    ej_uuid_parse(srgp->judge_uuid, &judge_uuid);
  }

  testing_report_xml_t tr = testing_report_alloc(srgp->contest_id, srgp->run_id, srgp->judge_id, &judge_uuid);
  tr->submit_id = srgp->submit_id;
  tr->status = reply_pkt->status;
  tr->scoring_system = srgp->scoring_system_val;
  tr->archive_available = (srgp->enable_full_archive > 0);
  tr->correct_available = correct_available_flag;
  tr->info_available = info_available_flag;
  tr->real_time_available = has_real_time;
  tr->max_memory_used_available = has_max_memory_used;
  tr->max_rss_available = has_max_rss;
  tr->run_tests = total_tests - 1;
  tr->variant = variant;
  if (srgp->scoring_system_val == SCORE_OLYMPIAD) {
    tr->accepting_mode = (srgp->accepting_mode > 0);
  }
  tr->tests_passed = reply_pkt->tests_passed;

  if (srgp->scoring_system_val == SCORE_OLYMPIAD && srgp->accepting_mode > 0 && reply_pkt->status != RUN_ACCEPTED) {
    tr->failed_test = total_tests - 1;
  } else if (srgp->scoring_system_val == SCORE_ACM && reply_pkt->status != RUN_OK) {
    tr->failed_test = total_tests - 1;
  } else if (srgp->scoring_system_val == SCORE_OLYMPIAD && srgp->accepting_mode <= 0) {
    tr->score = reply_pkt->score;
    tr->max_score = max_score;
  } else if (srgp->scoring_system_val == SCORE_KIROV) {
    tr->score = reply_pkt->score;
    tr->max_score = max_score;
  } else if (srgp->scoring_system_val == SCORE_MOSCOW) {
    if (reply_pkt->status != RUN_OK) {
      tr->failed_test = total_tests - 1;
    }
    tr->score = reply_pkt->score;
    tr->max_score = max_score;
  } else {
  }
  if (report_time_limit_ms > 0) {
    tr->time_limit_ms = report_time_limit_ms;
  }
  if (report_real_time_limit_ms > 0) {
    tr->real_time_limit_ms = report_real_time_limit_ms;
  }
  if (marked_flag >= 0) {
    tr->marked_flag = (marked_flag > 0);
  }
  tr->tests_mode = 0;
  if (srgp->separate_user_score > 0) {
    tr->separate_user_score = 1;
    if (reply_pkt->user_status >= 0) {
      tr->user_status = reply_pkt->user_status;
    }
    if (reply_pkt->user_score >= 0) {
      tr->user_score = reply_pkt->user_score;
    }
    if (user_max_score < 0) user_max_score = max_score;
    tr->user_max_score = user_max_score;
    if (reply_pkt->user_tests_passed >= 0) {
      tr->user_tests_passed = reply_pkt->user_tests_passed;
    }
    if (user_run_tests >= 0) {
      tr->user_run_tests = user_run_tests;
    }
  }
  tr->compile_error = 0;
  if (additional_comment) {
    tr->comment = xstrdup(additional_comment);
  }
  if (valuer_comment) {
    tr->valuer_comment = xstrdup(valuer_comment);
  }
  if (valuer_judge_comment) {
    tr->valuer_judge_comment = xstrdup(valuer_judge_comment);
  }
  if (valuer_errors) {
    tr->valuer_errors = xstrdup(valuer_errors);
  }
  if (hostname) {
    tr->host = xstrdup(hostname);
  } else if ((msg = os_NodeName())) {
    tr->host = xstrdup(msg);
  }
  if (cpu_model) {
    tr->cpu_model = xstrdup(cpu_model);
  }
  if (cpu_mhz) {
    tr->cpu_mhz = xstrdup(cpu_mhz);
  }
  if (srgp->run_uuid) {
    ej_uuid_parse(srgp->run_uuid, &tr->uuid);
  }

  unsigned int verdict_bits = 0;
  if (total_tests > 1) {
    XCALLOC(tr->tests, total_tests - 1);
    for (i = 1; i < total_tests; ++i) {
      struct testing_report_test *trt = testing_report_test_alloc(i, tests[i].status);
      tr->tests[i - 1] = trt;
      const struct run_test_info *ti = &tests[i];
      if (ti->status >= 0 && ti->status < (int) (sizeof(status_to_bit_map) / sizeof(status_to_bit_map[0]))) {
        verdict_bits |= status_to_bit_map[ti->status];
      }
      if (ti->status == RUN_RUN_TIME_ERR) {
        if (ti->code == 256) {
          trt->term_signal = ti->termsig;
        } else {
          trt->exit_code = ti->code;
        }
      } else {
        trt->exit_code = ti->code;
      }
      trt->time = ti->times;
      if (ti->real_time >= 0 && has_real_time) {
        trt->real_time = ti->real_time;
      }
      if (ti->max_memory_used > 0) {
        trt->max_memory_used = ti->max_memory_used;
      }
      if (ti->max_rss > 0) {
        trt->max_rss = ti->max_rss;
      }
      if (ti->program_stats_str) {
        trt->program_stats_str = xstrdup(ti->program_stats_str);
      }
      if (ti->interactor_stats_str) {
        trt->interactor_stats_str = xstrdup(ti->interactor_stats_str);
      }
      if (ti->checker_stats_str) {
        trt->checker_stats_str = xstrdup(ti->checker_stats_str);
      }
      if (srgp->scoring_system_val == SCORE_OLYMPIAD && srgp->accepting_mode <= 0) {
        trt->nominal_score = ti->max_score;
        trt->score = ti->score;
      } else if (srgp->scoring_system_val == SCORE_KIROV) {
        trt->nominal_score = ti->max_score;
        trt->score = ti->score;
      }
      if (ti->comment && ti->comment[0]) {
        trt->comment = xstrdup(ti->comment);
      }
      if (ti->team_comment && ti->team_comment[0]) {
        trt->team_comment = xstrdup(ti->team_comment);
      }
      if (ti->exit_comment && ti->exit_comment[0]) {
        trt->exit_comment = xstrdup(ti->exit_comment);
      }
      if (ti->checker_token && ti->checker_token[0]) {
        trt->checker_token = xstrdup(ti->checker_token);
      }
      if ((ti->status == RUN_WRONG_ANSWER_ERR || ti->status == RUN_PRESENTATION_ERR || ti->status == RUN_OK)
          && ti->chk_out.data && ti->chk_out.data[0]) {
        trt->checker_comment = prepare_checker_comment(utf8_mode, ti->chk_out.data);
      }
      if (srgp->enable_full_archive > 0) {
        if (ti->has_input_digest) {
          trt->has_input_digest = 1;
          filehash_copy(trt->input_digest, ti->input_digest);
        }
        if (ti->has_correct_digest) {
          trt->has_correct_digest = 1;
          filehash_copy(trt->correct_digest, ti->correct_digest);
        }
        if (ti->has_info_digest) {
          trt->has_info_digest = 1;
          filehash_copy(trt->info_digest, ti->info_digest);
        }
      }
      if (srgp->enable_full_archive > 0) {
        trt->output_available = ti->output.is_archived;
        trt->stderr_available = ti->error.is_archived;
        trt->checker_output_available = ti->chk_out.is_archived;
      }
      if (ti->args && strlen(ti->args) >= srgp->max_cmd_length) {
        trt->args_too_long = 1;
      }
      if (ti->visibility > 0) {
        trt->visibility = ti->visibility;
      }
      if (ti->user_status >= 0) {
        trt->has_user = 1;
        trt->user_status = ti->user_status;
        if (ti->user_score >= 0) {
          trt->user_score = ti->user_score;
        }
        if (ti->user_nominal_score >= 0) {
          trt->user_nominal_score = ti->user_nominal_score;
        }
      }
      if (ti->args && strlen(ti->args) < srgp->max_cmd_length) {
        trt->args = xstrdup(ti->args);
      }
      if (srgp->enable_full_archive <= 0) {
        make_file_content_2(&trt->input, srgp, &ti->input);
        make_file_content_2(&trt->output, srgp, &ti->output);
        make_file_content_2(&trt->correct, srgp, &ti->correct);
        make_file_content_2(&trt->error, srgp, &ti->error);
        make_file_content_2(&trt->checker, srgp, &ti->chk_out);
        make_file_content_2(&trt->test_checker, srgp, &ti->test_checker);

        /*
        char buf[64];
        snprintf(buf, sizeof(buf), "RTF %d: ", i);
        print_run_test_file(stderr, buf, &ti->output);
        */
      }
    }
  }
  tr->verdict_bits = verdict_bits;
  reply_pkt->verdict_bits = verdict_bits;

  if (srgp->bson_available && testing_report_bson_available()) {
    if (testing_report_to_file_bson(report_path, tr) < 0) {
      err("generate_xml_report: failed to save BSON file '%s'", report_path);
    }
    reply_pkt->bson_flag = 1;
  } else {
    if (testing_report_to_file(report_path, utf8_mode, tr) < 0) {
      err("generate_xml_report: failed to save file '%s'", report_path);
      return -1;
    }
  }
  testing_report_free(tr);
  return 0;
}

static unsigned char *
get_process_stats_str(tpTask tsk)
{
  char *str_s = NULL;
  size_t str_z = 0;
  FILE *str_f = open_memstream(&str_s, &str_z);
  struct ej_process_stats stats;
  process_stats_init(&stats);
  if (task_GetProcessStats(tsk, &stats) >= 0) {
    process_stats_serialize(str_f, &stats);
    fclose(str_f);
    return str_s;
  } else {
    fclose(str_f);
    free(str_s);
    return NULL;
  }
}

static int
read_error_code(char const *path)
{
  FILE *f;
  int   n;
  __attribute__((unused)) int _;

  if (!(f = fopen(path, "r"))) {
    return 100;
  }
  if (fscanf(f, "%d", &n) != 1) {
    fclose(f);
    return 101;
  }
  _ = fscanf(f, " ");
  if (getc(f) != EOF) {
    fclose(f);
    return 102;
  }
  fclose(f);
  return n;
}

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

static __attribute__((format(printf, 2, 3))) void
rtf_printf(struct run_test_file *rtf, const char *format, ...)
{
  va_list args;
  char *text_s = NULL;
  size_t text_z = 0;
  FILE *text_f = NULL;

  text_f = open_memstream(&text_s, &text_z);
  if (rtf->stored_size > 0 && rtf->data) {
    fwrite_unlocked(rtf->data, 1, rtf->stored_size, text_f);
  }
  va_start(args, format);
  vfprintf(text_f, format, args);
  va_end(args);
  fclose(text_f); text_f = NULL;

  free(rtf->data);
  rtf->data = text_s; text_s = NULL;
  rtf->stored_size = text_z;
  rtf->orig_size = text_z;
  rtf->is_here = 1;
  rtf->is_binary = 0;
  rtf->is_too_long = 0;
  rtf->is_too_wide = 0;
  rtf->is_fixed = 0;
  rtf->is_base64 = 0;
}

static int
parse_checker_score(
        const unsigned char *path,
        const unsigned char *log_path,
        const unsigned char *what,
        int user_score_mode,
        int max_score,
        int default_score, // if >= 0, allow failure
        int testlib_mode,
        int checker_token_mode,
        int verdict,
        int *p_score,
        int *p_user_score,
        int *p_user_verdict,
        unsigned char **p_checker_token)
{
  char *score_buf = 0;
  size_t score_buf_size = 0;
  int x, n, r;

  if (testlib_mode > 0) {
    r = generic_read_file(&score_buf, 0, &score_buf_size, 0, 0, log_path, "");
  } else {
    r = generic_read_file(&score_buf, 0, &score_buf_size, 0, 0, path, "");
  }
  if (r < 0) {
    append_msg_to_log(log_path, "Cannot read the %s score output", what);
    goto fail;
  }
  if (strlen(score_buf) != score_buf_size) {
    append_msg_to_log(log_path, "The %s score output is binary", what);
    goto fail;
  }

  while (score_buf_size > 0 && isspace(score_buf[score_buf_size - 1]))
    score_buf[--score_buf_size] = 0;
  if (!score_buf_size) {
    if (testlib_mode > 0) {
      *p_score = 0;
      *p_user_score = 0;
      *p_user_verdict = RUN_WRONG_ANSWER_ERR;
      goto done;
    }
    append_msg_to_log(log_path, "The %s score output is empty", what);
    goto fail;
  }

  if (testlib_mode > 0) {
    fprintf(stderr, ">>%s<<\n", score_buf);
    if (strncasecmp(score_buf, "points ", 7) != 0) {
      //append_msg_to_log(log_path, "The %s output does not start with 'points'",
      //                  what);
      if (verdict == RUN_OK) {
        *p_score = max_score;
      } else {
        *p_score = 0;
      }
      if (user_score_mode > 0) {
        *p_user_score = *p_score;
        *p_user_verdict = verdict;
      }
      goto done;
    }
    char *ptr = score_buf + 7;
    char *eptr = NULL;
    errno = 0;
    long lx = strtol(ptr, &eptr, 10);
    if (errno || eptr == ptr || (*eptr && !isspace((unsigned char) *eptr)) || (int) lx != lx || lx < 0) {
      append_msg_to_log(log_path, "The %s score is invalid", what);
      goto fail;
    }
    if (lx > max_score) lx = max_score;
    *p_score = lx;
    if (user_score_mode > 0) {
      *p_user_score = lx;
      *p_user_verdict = RUN_WRONG_ANSWER_ERR;
      if (lx == max_score) *p_user_verdict = RUN_OK;
    }
  } else if (user_score_mode) {
    // valid score file variants:
    //   score user_score user_verdict
    //   score user_score
    //   score
    if (p_score) *p_score = -1;
    if (p_user_score) *p_user_score = -1;
    if (p_user_verdict) *p_user_verdict = -1;

    char *ptr = score_buf;
    char *eptr;
    errno = 0;
    long lx = strtol(ptr, &eptr, 10);
    if (errno || eptr == ptr || (int) lx != lx || lx < 0 || lx > max_score || (*eptr && !isspace(*eptr))) {
      append_msg_to_log(log_path, "The %s score is invalid", what);
      goto fail;
    }
    if (p_score) *p_score = lx;
    ptr = eptr;
    while (isspace(*ptr)) ++ptr;
    if (*ptr) {
      errno = 0;
      long lx = strtol(ptr, &eptr, 10);
      if (errno || eptr == ptr || (int) lx != lx || lx < 0 || lx > max_score || (*eptr && !isspace(*eptr))) {
        append_msg_to_log(log_path, "The %s user score is invalid", what);
        goto fail;
      }
      if (p_user_score) *p_user_score = lx;
      ptr = eptr;
      while (isspace(*ptr)) ++ptr;
      if (ptr) {
        errno = 0;
        long lx = strtol(ptr, &eptr, 10);
        if (errno || eptr == ptr || (int) lx != lx || lx < 0 || (*eptr && !isspace(*eptr))) {
          append_msg_to_log(log_path, "The %s user verdict is invalid", what);
          goto fail;
        }
        // what is valid here:
        switch (lx) {
        case RUN_OK:
        case RUN_ACCEPTED:
        case RUN_PENDING_REVIEW:
          break;
        case RUN_PRESENTATION_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_PARTIAL:
          break;
        default:
          append_msg_to_log(log_path, "The %s user verdict (%d) is invalid", what, lx);
          goto fail;
        }
        if (p_user_verdict) *p_user_verdict = lx;
        ptr = eptr;
        while (isspace(*ptr)) ++ptr;
        if (*ptr) {
          append_msg_to_log(log_path, "The %s garbage after scoring information", what);
          goto fail;
        }
      }
    }
  } else if (checker_token_mode) {
    char *eptr = NULL;
    errno = 0;
    long xx = strtol(score_buf, &eptr, 10);
    if (errno || (*eptr && !isspace((unsigned char) *eptr))) {
      append_msg_to_log(log_path, "The %s score output (%s) is invalid", what, score_buf);
      goto fail;
    }
    if (xx < 0 || xx > max_score) {
      append_msg_to_log(log_path, "The %s score (%ld) is invalid", what, xx);
      goto fail;
    }
    if (p_score) *p_score = xx;
    if (*eptr) {
      char *ptr = eptr;
      while (isspace((unsigned char) *ptr)) ++ptr;
      if (*ptr && p_checker_token) {
        if (*p_checker_token) free(*p_checker_token);
        *p_checker_token = xstrdup(ptr);
      }
    }
  } else {
    if (sscanf(score_buf, "%d%n", &x, &n) != 1 || score_buf[n]) {
      append_msg_to_log(log_path, "The %s score output (%s) is invalid", what, score_buf);
      goto fail;
    }
    if (x < 0 || x > max_score) {
      append_msg_to_log(log_path, "The %s score (%d) is invalid", what, x);
      goto fail;
    }
    if (p_score) *p_score = x;
  }

done:
  xfree(score_buf);
  return 0;

fail:
  xfree(score_buf);
  if (default_score >= 0) {
    if (p_score) *p_score = default_score;
    return 0;
  }
  return -1;
}

static int
parse_valuer_score(
        const unsigned char *log_path,
        const unsigned char *in_buf,
        ssize_t in_buf_size,
        int enable_reply_next_num, // enable < 0 as score (next test num)
        int max_score,
        int valuer_sets_marked,
        int separate_user_score,
        int *p_reply_next_num,
        int *p_score,
        int *p_marked,
        int *p_user_status,
        int *p_user_score,
        int *p_user_tests_passed)
{
  if (p_marked) *p_marked = -1;

  if (in_buf_size < 0 || in_buf_size > 1024) {
    append_msg_to_log(log_path, "valuer reply too long (%lld)", (long long) in_buf_size);
    goto fail;
  }
  unsigned char *buf = alloca(in_buf_size + 1);
  memcpy(buf, in_buf, in_buf_size);
  buf[in_buf_size] = 0;
  int buflen = strlen(buf);
  if (buflen != in_buf_size) {
    append_msg_to_log(log_path, "valuer reply contains '\0' byte");
    goto fail;
  }
  for (unsigned char *s = buf; *s; ++s) {
    if (*s == '\n' || *s == '\r' || *s == '\r') *s = ' ';
  }
  for (unsigned char *s = buf; *s; ++s) {
    if (*s < ' ' || *s == 0x7f) {
      append_msg_to_log(log_path, "valuer reply contains control chars");
      goto fail;
    }
  }
  while (buflen > 0 && buf[buflen - 1] == ' ') --buflen;
  buf[buflen] = 0;
  if (buflen <= 0) {
    append_msg_to_log(log_path, "valuer reply is empty");
    goto fail;
  }
  int idx = 0, n, v_score = -2;
  int lineno = 0;

  if (sscanf(buf + idx, "%d%n", &v_score, &n) != 1) {
    lineno = __LINE__;
    goto invalid_reply;
  }
  idx += n;
  if (buf[idx] != ' ' && buf[idx] != 0) {
    lineno = __LINE__;
    goto invalid_reply;
  }
  if (enable_reply_next_num > 0 && v_score < 0) {
    if (buf[idx]) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    if (p_reply_next_num) *p_reply_next_num = -v_score;
    return 0;
  }
  if (v_score < 0 || v_score > max_score) {
    lineno = __LINE__;
    goto invalid_reply;
  }
  int v_marked = 0;
  if (valuer_sets_marked > 0) {
    if (sscanf(buf + idx, "%d%n", &v_marked, &n) != 1) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    idx += n;
    if (buf[idx] != ' ' && buf[idx] != 0) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    if (v_marked < 0 || v_marked > 1) {
      lineno = __LINE__;
      goto invalid_reply;
    }
  }
  int v_user_status = -1, v_user_score = -1, v_user_tests_passed = -1;
  if (separate_user_score > 0) {
    if (sscanf(buf + idx, "%d%n", &v_user_status, &n) != 1) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    idx += n;
    if (buf[idx] != ' ' && buf[idx] != 0) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    if (!run_is_normal_status(v_user_status) && v_user_status != -1) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    if (sscanf(buf + idx, "%d%n", &v_user_score, &n) != 1) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    idx += n;
    if (buf[idx] != ' ' && buf[idx] != 0) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    if (v_user_score < -1 || v_user_score > max_score) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    if (sscanf(buf + idx, "%d%n", &v_user_tests_passed, &n) != 1) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    idx += n;
    if (buf[idx] != ' ' && buf[idx] != 0) {
      lineno = __LINE__;
      goto invalid_reply;
    }
    if (v_user_tests_passed < -1 || v_user_tests_passed > EJ_MAX_TEST_NUM) {
      lineno = __LINE__;
      goto invalid_reply;
    }
  }
  if (buf[idx]) {
    lineno = __LINE__;
    goto invalid_reply;
  }

  if (p_reply_next_num) *p_reply_next_num = 0;
  if (p_score) *p_score = v_score;
  if (p_marked) *p_marked = v_marked;
  if (p_user_status) *p_user_status = v_user_status;
  if (p_user_score) *p_user_score = v_user_score;
  if (p_user_tests_passed) *p_user_tests_passed = v_user_tests_passed;
  return 0;

invalid_reply:
  append_msg_to_log(log_path, "valuer reply '%s' is invalid (code %d)", buf,
                    lineno);

fail:
  return -1;
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
  char *score_buf = 0;
  size_t score_buf_size = 0;
  int r;

  if (p_marked) *p_marked = -1;

  r = generic_read_file(&score_buf, 0, &score_buf_size, 0,
                        0, path, "");
  if (r < 0) {
    append_msg_to_log(log_path, "Cannot read the %s score output", what);
    return -1;
  }

  r = parse_valuer_score(log_path, score_buf, score_buf_size,
                         0, max_score, valuer_sets_marked, separate_user_score,
                         NULL, p_score, p_marked,
                         p_user_status, p_user_score, p_user_tests_passed);

  xfree(score_buf);
  return r;
}

static int
read_env_file(tpTask tsk, const unsigned char *env_file)
{
  char *str = NULL;
  size_t size = 0;
  ssize_t r;
  FILE *f = fopen(env_file, "r");
  if (!f) {
    err("read_env_file: open '%s' failed: %s", env_file, os_ErrorMsg());
    return -1;
  }
  while ((r = getline(&str, &size, f)) >= 0) {
    int len = strlen(str);
    if (len != r) {
      err("read_env_file: binary file '%s'", env_file);
      continue;
    }
    while (len > 0 && isspace((unsigned char) str[len - 1])) --len;
    str[len] = 0;
    if (!len) continue;
    char *eq = strchr(str, '=');
    if (!eq) {
      err("read_env_file: missing '=' in '%s'", env_file);
      continue;
    }
    *eq = 0;
    task_SetEnv(tsk, str, eq + 1);
  }
  free(str);
  fclose(f);
  return 0;
}

static void
setup_environment(
        tpTask tsk,
        char **envs,
        //const struct testinfo_struct *pt,
        int ti_env_u,
        char **ti_env_v,
        int force_ejudge_env)
{
  int jj;
  unsigned char env_buf[1024];
  const unsigned char *envval = NULL;

  if (force_ejudge_env > 0) {
#if defined EJUDGE_PREFIX_DIR
    task_SetEnv(tsk, "EJUDGE_PREFIX_DIR", EJUDGE_PREFIX_DIR);
#endif
#if defined EJUDGE_CONTESTS_HOME_DIR
    task_SetEnv(tsk, "EJUDGE_CONTESTS_HOME_DIR", EJUDGE_CONTESTS_HOME_DIR);
#endif
#if defined EJUDGE_LOCAL_DIR
    task_SetEnv(tsk, "EJUDGE_LOCAL_DIR", EJUDGE_LOCAL_DIR);
#endif
#if defined EJUDGE_SERVER_BIN_PATH
    task_SetEnv(tsk, "EJUDGE_SERVER_BIN_PATH", EJUDGE_SERVER_BIN_PATH);
#endif
  }

  if (envs) {
    for (jj = 0; envs[jj]; jj++) {
      if (force_ejudge_env <= 0 && !strcmp(envs[jj], "EJUDGE_PREFIX_DIR")) {
#if defined EJUDGE_PREFIX_DIR
        task_SetEnv(tsk, "EJUDGE_PREFIX_DIR", EJUDGE_PREFIX_DIR);
#endif
      } else if (force_ejudge_env <= 0 && !strcmp(envs[jj], "EJUDGE_CONTESTS_HOME_DIR")) {
#if defined EJUDGE_CONTESTS_HOME_DIR
        task_SetEnv(tsk, "EJUDGE_CONTESTS_HOME_DIR", EJUDGE_CONTESTS_HOME_DIR);
#endif
      } else if (force_ejudge_env <= 0 && !strcmp(envs[jj], "EJUDGE_LOCAL_DIR")) {
#if defined EJUDGE_LOCAL_DIR
        task_SetEnv(tsk, "EJUDGE_LOCAL_DIR", EJUDGE_LOCAL_DIR);
#endif
      } else if (force_ejudge_env <= 0 && !strcmp(envs[jj], "EJUDGE_SERVER_BIN_PATH")) {
#if defined EJUDGE_SERVER_BIN_PATH
        task_SetEnv(tsk, "EJUDGE_SERVER_BIN_PATH", EJUDGE_SERVER_BIN_PATH);
#endif
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

  if (ti_env_v && ti_env_u) {
    for (jj = 0; jj < ti_env_u; ++jj) {
      if (ti_env_v[jj]) {
        task_PutEnv(tsk, ti_env_v[jj]);
      }
    }
  }
  /*
  if (pt && pt->env_u && pt->env_v) {
    for (jj = 0; jj < pt->env_u; ++jj) {
      if (pt->env_v[jj]) {
        task_PutEnv(tsk, pt->env_v[jj]);
      }
    }
  }
  */
}

static void
setup_ejudge_environment(
        tpTask tsk,
        const struct super_run_in_packet *srp,
        int cur_test,
        int test_max_score,
        int output_only,
        const unsigned char *src_path,
        int exec_user_serial,
        uint64_t test_random_value)
{
  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;
  unsigned char buf[64];

  task_SetEnv(tsk, "EJUDGE", "1");
  if (srpp->scoring_checker > 0) {
    task_SetEnv(tsk, "EJUDGE_SCORING_CHECKER", "1");
    if (srpp->enable_checker_token > 0) {
      task_SetEnv(tsk, "EJUDGE_CHECKER_TOKEN", "1");
    }
    if (test_max_score >= 0) {
      snprintf(buf, sizeof(buf), "%d", test_max_score);
      task_SetEnv(tsk, "EJUDGE_MAX_SCORE", buf);
    }
  }
  if (srgp->checker_locale && srgp->checker_locale[0]) {
    task_SetEnv(tsk, "EJUDGE_LOCALE", srgp->checker_locale);
  }
  if (srgp->separate_user_score > 0 || output_only > 0) {
    task_SetEnv(tsk, "EJUDGE_USER_SCORE", "1");
  }
  if (srpp->valuer_sets_marked > 0) {
    task_SetEnv(tsk, "EJUDGE_MARKED", "1");
  }
  if (srpp->interactive_valuer > 0) {
    task_SetEnv(tsk, "EJUDGE_INTERACTIVE", "1");
  }
  if (srgp->rejudge_flag > 0) {
    task_SetEnv(tsk, "EJUDGE_REJUDGE", "1");
  }
  if (exec_user_serial > 0) {
    sprintf(buf, "%d", exec_user_serial);
    task_SetEnv(tsk, "EJUDGE_SUPER_RUN_SERIAL", buf);
  }
  if (test_random_value > 0) {
    sprintf(buf, "%llx", (unsigned long long) test_random_value);
    task_SetEnv(tsk, "EJUDGE_TEST_RANDOM_VALUE", buf);
  }
  if (srgp->testlib_mode > 0) {
    task_SetEnv(tsk, "EJUDGE_TESTLIB_MODE", "1");
  }
  if (srgp->enable_container > 0) {
    task_SetEnv(tsk, "EJUDGE_CONTAINER", "1");
  } else if (srgp->suid_run > 0) {
    task_SetEnv(tsk, "EJUDGE_SUID_RUN", "1");
  }
  if (srpp->enable_extended_info > 0) {
    snprintf(buf, sizeof(buf), "%d", srgp->user_id);
    task_SetEnv(tsk, "EJUDGE_USER_ID", buf);
    snprintf(buf, sizeof(buf), "%d", srgp->contest_id);
    task_SetEnv(tsk, "EJUDGE_CONTEST_ID", buf);
    snprintf(buf, sizeof(buf), "%d", srgp->run_id);
    task_SetEnv(tsk, "EJUDGE_RUN_ID", buf);
    if (cur_test > 0) {
      snprintf(buf, sizeof(buf), "%d", cur_test);
      task_SetEnv(tsk, "EJUDGE_TEST_NUM", buf);
    }
    if (srgp->user_login) {
      task_SetEnv(tsk, "EJUDGE_USER_LOGIN", srgp->user_login);
    }
    if (srgp->user_name) {
      task_SetEnv(tsk, "EJUDGE_USER_NAME", srgp->user_name);
    }
    if (srpp->test_count > 0) {
      snprintf(buf, sizeof(buf), "%d", srpp->test_count);
      task_SetEnv(tsk, "EJUDGE_TEST_COUNT", buf);
    }
  }
  if (src_path) {
    task_SetEnv(tsk, "EJUDGE_SOURCE_PATH", src_path);
  }
}

static void
read_log_file(const unsigned char *path, char **p_text)
{
  char *stext = NULL;
  size_t size = 0;

  if (p_text) *p_text = NULL;
  if (generic_read_file(&stext, 0, &size, 0, 0, path, "") < 0) {
    return;
  }
  unsigned char *text = (unsigned char*) stext;
  if (text) {
    while (size > 0 && isspace(text[size - 1])) --size;
    text[size] = 0;
    if (!size) {
      xfree(text);
      text = NULL;
    }
  }
  if (text) {
    for (int i = 0; i < size; ++i) {
      if (text[i] == 0x7f) {
        text[i] = ' ';
      } else if (text[i] < ' ' && text[i] != '\n') {
        text[i] = ' ';
      }
    }
  }
  if (p_text) {
    *p_text = text;
  } else {
    xfree(text);
  }
}

static int
invoke_valuer(
        const struct section_global_data *global,
        const struct super_run_in_packet *srp,
        struct AgentClient *agent,
        const unsigned char *mirror_dir,
        int total_tests,
        const struct run_test_info *tests,
        int cur_variant,
        int max_score,
        int exec_user_serial,
        int *p_score,
        int *p_marked,
        int *p_user_status,
        int *p_user_score,
        int *p_user_tests_passed,
        char **p_err_txt,
        char **p_cmt_txt,
        char **p_jcmt_txt,
        const unsigned char *src_path)
{
  path_t score_list;
  path_t score_res;
  path_t score_err;
  path_t score_cmt;
  path_t score_jcmt;
  path_t valuer_cmd;
  FILE *f = 0;
  int i, retval = -1;
  tpTask tsk = 0;

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

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
    fprintf(f, " %d", tests[i].score);
    fprintf(f, " %ld", tests[i].times);
    if (srpp->enable_checker_token > 0) {
      if (tests[i].checker_token && tests[i].checker_token[0]) {
        fprintf(f, " %s", tests[i].checker_token);
      }
      // FIXME: what to do if no checker_token?
    }
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

  snprintf(valuer_cmd, sizeof(valuer_cmd), "%s", srpp->valuer_cmd);
  mirror_file(agent, valuer_cmd, sizeof(valuer_cmd), mirror_dir);

  info("starting valuer: %s %s %s", valuer_cmd, score_cmt, score_jcmt);

  tsk = task_New();
  task_AddArg(tsk, valuer_cmd);
  task_AddArg(tsk, score_cmt);
  task_AddArg(tsk, score_jcmt);
  if (srpp->problem_dir && srpp->problem_dir[0]) {
    task_AddArg(tsk, srpp->problem_dir);
  }
  task_SetRedir(tsk, 0, TSR_FILE, score_list, TSK_READ);
  task_SetRedir(tsk, 1, TSR_FILE, score_res, TSK_REWRITE, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, score_err, TSK_REWRITE, TSK_FULL_RW);
  task_SetWorkingDir(tsk, global->run_work_dir);
  task_SetPathAsArg0(tsk);
  /*
  if (srpp->checker_real_time_limit_ms > 0) {
    task_SetMaxRealTimeMillis(tsk, srpp->checker_real_time_limit_ms);
  }
  */
  if (srpp->checker_time_limit_ms > 0) {
    task_SetMaxTimeMillis(tsk, srpp->checker_time_limit_ms);
  }
  if (srpp->checker_max_stack_size > 0) {
    task_SetStackSize(tsk, srpp->checker_max_stack_size);
  }
  if (srpp->checker_max_vm_size > 0) {
    task_SetVMSize(tsk, srpp->checker_max_vm_size);
  }
  if (srpp->checker_max_rss_size > 0) {
    task_SetRSSSize(tsk, srpp->checker_max_rss_size);
  }
  setup_environment(tsk, srpp->valuer_env, 0, NULL, 1);
  setup_ejudge_environment(tsk, srp,
                           0 /* cur_test*/,
                           -1 /* test_max_score */,
                           0 /* output_only */,
                           src_path, exec_user_serial,
                           0 /* test_random_value */);
  task_EnableAllSignals(tsk);

  task_PrintArgs(tsk);

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
  read_log_file(score_cmt, p_cmt_txt);
  read_log_file(score_jcmt, p_jcmt_txt);
  retval = 0;

 cleanup:
  read_log_file(score_err, p_err_txt);

  if (tsk) {
    task_Delete(tsk);
    tsk = 0;
  }

  unlink(score_list);
  unlink(score_res);
  unlink(score_err);
  unlink(score_cmt);
  unlink(score_jcmt);
  return retval;
}

#ifndef __WIN32__
static tpTask
start_interactive_valuer(
        const struct section_global_data *global,
        const struct super_run_in_packet *srp,
        struct AgentClient *agent,
        const unsigned char *mirror_dir,
        const unsigned char *valuer_err_file,
        const unsigned char *valuer_cmt_file,
        const unsigned char *valuer_jcmt_file,
        int stdin_fd,
        int stdout_fd,
        const unsigned char *src_path,
        int exec_user_serial)
{
  const struct super_run_in_problem_packet *srpp = srp->problem;
  path_t valuer_cmd;
  tpTask tsk = NULL;

  snprintf(valuer_cmd, sizeof(valuer_cmd), "%s", srpp->valuer_cmd);
  mirror_file(agent, valuer_cmd, sizeof(valuer_cmd), mirror_dir);

  info("starting interactive valuer: %s %s %s",
       valuer_cmd, valuer_cmt_file, valuer_jcmt_file);

  tsk = task_New();
  task_AddArg(tsk, valuer_cmd);
  task_AddArg(tsk, valuer_cmt_file);
  task_AddArg(tsk, valuer_jcmt_file);
  if (srpp->problem_dir && srpp->problem_dir[0]) {
    if (agent && mirror_dir) {
      // need to mirror 'valuer'cfg'
      unsigned char valuer_cfg_path[PATH_MAX];
      snprintf(valuer_cfg_path, sizeof(valuer_cfg_path),
               "%s/valuer.cfg", srpp->problem_dir);
      mirror_file(agent, valuer_cfg_path, sizeof(valuer_cfg_path), mirror_dir);
      char *p = strrchr(valuer_cfg_path, '/');
      if (p) *p = 0;
      task_AddArg(tsk, valuer_cfg_path);
    } else {
      task_AddArg(tsk, srpp->problem_dir);
    }
  }
  task_SetRedir(tsk, 0, TSR_DUP, stdin_fd);
  task_SetRedir(tsk, 1, TSR_DUP, stdout_fd);
  task_SetRedir(tsk, 2, TSR_FILE, valuer_err_file, TSK_APPEND, TSK_FULL_RW);
  task_SetWorkingDir(tsk, global->run_work_dir);
  task_SetPathAsArg0(tsk);
  /*
  if (srpp->checker_real_time_limit_ms > 0) {
    task_SetMaxRealTimeMillis(tsk, srpp->checker_real_time_limit_ms);
  }
  */
  if (srpp->checker_time_limit_ms > 0) {
    task_SetMaxTimeMillis(tsk, srpp->checker_time_limit_ms);
  }
  if (srpp->checker_max_stack_size > 0) {
    task_SetStackSize(tsk, srpp->checker_max_stack_size);
  }
  if (srpp->checker_max_vm_size > 0) {
    task_SetVMSize(tsk, srpp->checker_max_vm_size);
  }
  if (srpp->checker_max_rss_size > 0) {
    task_SetRSSSize(tsk, srpp->checker_max_rss_size);
  }
  setup_environment(tsk, srpp->valuer_env, 0, NULL, 1);
  setup_ejudge_environment(tsk, srp,
                           0 /* cur_test */,
                           -1 /* test_max_score */,
                           0 /* output_only */,
                           src_path,
                           exec_user_serial,
                           0 /* test_random_value */);
  //task_EnableAllSignals(tsk);

  task_PrintArgs(tsk);

  if (task_Start(tsk) < 0) {
    append_msg_to_log(valuer_err_file, "valuer failed to start");
    task_Delete(tsk);
    return NULL;
  }

  return tsk;
}
#endif

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

static void
agent_mirror_file(
        struct AgentClient *agent,
        unsigned char *buf,
        int size,
        const unsigned char *mirror_dir)
{
  char *pkt_ptr = NULL;
  size_t pkt_len = 0;
  int fd = -1;
  char *out_ptr = MAP_FAILED;

  if (!strncmp(buf, EJUDGE_PREFIX_DIR, sizeof(EJUDGE_PREFIX_DIR) - 1)) {
    // do not mirror these files
    return;
  }

  const unsigned char *sep = "";
  int md_len = strlen(mirror_dir);
  if (md_len > 0 && mirror_dir[md_len - 1] != '/' && buf[0] != '/') {
    sep = "/";
  }
  unsigned char mirror_path[PATH_MAX];
  snprintf(mirror_path, sizeof(mirror_path), "%s%s%s", mirror_dir, sep, buf);

  long long fsize = -1;
  time_t mtime = 0;
  int mode = -1;

  struct stat stb;
  if (stat(mirror_path, &stb) >= 0) {
    if (!S_ISREG(stb.st_mode)) {
      err("mirror file '%s' is not regular", mirror_path);
      return;
    }

    fsize = stb.st_size;
    mtime = stb.st_mtime;
    mode = stb.st_mode & 07777;
  }

  time_t new_mtime = 0;
  int new_mode = -1;
  int new_uid = -1;
  int new_gid = -1;
  int r = agent->ops->mirror_file(agent, buf, mtime, fsize, mode,
                                  &pkt_ptr, &pkt_len, &new_mtime,
                                  &new_mode, &new_uid, &new_gid);
  if (r < 0) {
    err("mirror_file failed on '%s'", buf);
    return;
  }
  if (!r) {
    info("using mirrored file '%s'", mirror_path);
    snprintf(buf, size, "%s", mirror_path);
    return;
  }

  unsigned char dirname[PATH_MAX];
  os_rDirName(mirror_path, dirname, sizeof(dirname));
  if (stat(dirname, &stb) < 0) {
    if (os_MakeDirPath(dirname, 0700) < 0) {
      err("cannot create mirror directory '%s'", dirname);
      goto done;
    }
  }
  if (stat(dirname, &stb) < 0) {
    err("mirror directory '%s' does not exist", dirname);
    goto done;
  }
  if (!S_ISDIR(stb.st_mode)) {
    err("mirror directory '%s' is not a directory", dirname);
    goto done;
  }
  fd = open(mirror_path, O_RDWR | O_CLOEXEC | O_CREAT | O_TRUNC | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW, 0600);
  if (fd < 0) {
    err("failed to create mirrored file '%s': %s", mirror_path, os_ErrorMsg());
    goto done;
  }
  if (fstat(fd, &stb) < 0) {
    err("fstat failed: %s", os_ErrorMsg());
    goto done;
  }
  if (!S_ISREG(stb.st_mode)) {
    err("mirrored file '%s' is not regular", mirror_path);
    goto done;
  }
  if (pkt_len > 0) {
    if (ftruncate(fd, pkt_len) < 0) {
      err("ftruncate failed on mirrored '%s': %s", mirror_path, os_ErrorMsg());
      goto done;
    }
    out_ptr = mmap(NULL, pkt_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (out_ptr == MAP_FAILED) {
      err("mmap failed on mirrored '%s': %s", mirror_path, os_ErrorMsg());
      goto done;
    }
    memcpy(out_ptr, pkt_ptr, pkt_len);
    munmap(out_ptr, pkt_len); out_ptr = MAP_FAILED;
  }

  if (new_mtime > 0) {
    struct timespec ub[2] = {};
    ub[0].tv_sec = new_mtime;
    ub[1].tv_sec = new_mtime;
    if (futimens(fd, ub) < 0) {
      err("failed to change times of '%s': %s", mirror_path, os_ErrorMsg());
      // ignore this error
    }
  }

  if (new_mode >= 0) {
    if (fchmod(fd, new_mode & 07777) < 0) {
      err("failed to change perms of '%s': %s", mirror_path, os_ErrorMsg());
      // ignore this error
    }
  }

  info("using mirrored file '%s'", mirror_path);
  snprintf(buf, size, "%s", mirror_path);

done:;
  if (out_ptr != MAP_FAILED) munmap(out_ptr, pkt_len);
  if (fd >= 0) close(fd);
  free(pkt_ptr);
}

static int
copy_mirrored_file(unsigned char *buf, int size, const unsigned char *mirror_path, const struct stat *psrcstat)
{
  unsigned char dirname[PATH_MAX];
  os_rDirName(mirror_path, dirname, sizeof(dirname));

  struct stat dbuf;
  if (stat(dirname, &dbuf) < 0) {
    // create directory
    if (os_MakeDirPath(dirname, 0700) < 0) {
      err("cannot create mirror directory '%s'", dirname);
      return -1;
    }
  }
  if (stat(dirname, &dbuf) < 0) {
    err("mirror directory '%s' does not exist", dirname);
    return -1;
  }
  if (!S_ISDIR(dbuf.st_mode)) {
    err("mirror directory '%s' is not a directory", dirname);
    return -1;
  }
  if (generic_copy_file(0, NULL, buf, NULL, 0, NULL, mirror_path, NULL) < 0) {
    return -1;
  }
  // update mtime
  struct utimbuf ub = {};
  ub.actime = psrcstat->st_atime;
  ub.modtime = psrcstat->st_mtime;
  if (utime(mirror_path, &ub) < 0) {
    err("failed to change modification time of '%s': %s", mirror_path, os_ErrorMsg());
    // ignore this error
  }
  if (chmod(mirror_path, psrcstat->st_mode & 0777) < 0) {
    err("failed to change permissions of '%s': %s", mirror_path, os_ErrorMsg());
    // ignore this error
  }

  info("using mirrored file '%s'", mirror_path);
  snprintf(buf, size, "%s", mirror_path);
  return 0;
}

static void
mirror_file(
        struct AgentClient *agent,
        unsigned char *buf,
        int size,
        const unsigned char *mirror_dir)
{
  if (!mirror_dir || !*mirror_dir) return;

  if (agent) {
    agent_mirror_file(agent, buf, size, mirror_dir);
    return;
  }

  // handle only existing regular files
  struct stat src_stbuf;
  if (stat(buf, &src_stbuf) < 0) return;
  if (!S_ISREG(src_stbuf.st_mode)) return;

  unsigned char mirror_path[PATH_MAX];
  const unsigned char *sep = "/";
  if (mirror_dir[strlen(mirror_dir) - 1] == '/' || buf[0] == '/') sep = "";
  snprintf(mirror_path, sizeof(mirror_path), "%s%s%s", mirror_dir, sep, buf);

  struct stat dst_stbuf;
  if (stat(mirror_path, &dst_stbuf) < 0 || dst_stbuf.st_size != src_stbuf.st_size || dst_stbuf.st_mtime < src_stbuf.st_mtime) {
    copy_mirrored_file(buf, size, mirror_path, &src_stbuf);
    return;
  }
  info("using mirrored copy of '%s' in '%s'", buf, mirror_path);
  snprintf(buf, size, "%s", mirror_path);
}

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";

static int
invoke_nwrun(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct section_tester_data *tst,
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
        struct run_test_info *result,
        const unsigned char *check_dir)
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
  path_t error_file_name;
  path_t log_file_name;
  FILE *f = 0;
  int r;
  struct generic_section_config *generic_out_packet = 0;
  struct nwrun_out_packet *out_packet = 0;
  long file_size;
  int timeout;

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  if (!tst->nwrun_spool_dir || !tst->nwrun_spool_dir[0]) abort();

  priority += 16;
  if (priority < 0) priority = 0;
  if (priority > 31) priority = 31;

  result->status = RUN_CHECK_FAILED;

  if (os_IsAbsolutePath(tst->nwrun_spool_dir)) {
    snprintf(full_spool_dir, sizeof(full_spool_dir), "%s", tst->nwrun_spool_dir);
  } else {
    if (config && config->contests_home_dir) {
      snprintf(full_spool_dir, sizeof(full_spool_dir), "%s/%s", config->contests_home_dir, tst->nwrun_spool_dir);
    } else {
#if defined EJUDGE_CONTESTS_HOME_DIR
      snprintf(full_spool_dir, sizeof(full_spool_dir), "%s/%s", EJUDGE_CONTESTS_HOME_DIR, tst->nwrun_spool_dir);
#else
      err("cannot initialize full_spool_dir");
      rtf_printf(&result->chk_out, "full_spool_dir is invalid\n");
      goto fail;
#endif
    }
  }

  snprintf(queue_path, sizeof(queue_path), "%s/queue",
           full_spool_dir);
  if (make_all_dir(queue_path, 0777) < 0) {
    rtf_printf(&result->chk_out, "make_all_dir(%s) failed\n", queue_path);
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
    rtf_printf(&result->chk_out, "make_dir(%s) failed\n", full_in_path);
    goto fail;
  }

  // copy (or link) the executable
  snprintf(exe_src_path, sizeof(exe_src_path), "%s/%s",
           exe_src_dir, exe_basename);
  snprintf(tmp_in_path, sizeof(tmp_in_path), "%s/%s",
           full_in_path, exe_basename);
  if (make_hardlink(exe_src_path, tmp_in_path) < 0) {
    rtf_printf(&result->chk_out, "copy(%s, %s) failed\n", exe_src_path, tmp_in_path);
    goto fail;
  }

  // copy (or link) the test file
  snprintf(tmp_in_path, sizeof(tmp_in_path), "%s/%s",
           full_in_path, test_basename);
  if (make_hardlink(test_src_path, tmp_in_path) < 0) {
    rtf_printf(&result->chk_out, "copy(%s, %s) failed\n", test_src_path, tmp_in_path);
    goto fail;
  }

  error_file_name[0] = 0;
  if (tst && tst->error_file && tst->error_file[0]) {
    snprintf(error_file_name, sizeof(error_file_name), "%s", tst->error_file);
  } else {
    snprintf(error_file_name, sizeof(error_file_name), "%s", "errors.txt");
  }

  log_file_name[0] = 0;
  snprintf(log_file_name, sizeof(log_file_name), "%s", "log.txt");

  // make the description file
  snprintf(tmp_in_path, sizeof(tmp_in_path), "%s/packet.cfg", full_in_path);
  f = fopen(tmp_in_path, "w");
  if (!f) {
    rtf_printf(&result->chk_out, "fopen(%s) failed\n", tmp_in_path);
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
  if (srpp->max_stack_size > 0) {
    fprintf(f, "max_stack_size = %lld\n", srpp->max_stack_size);
  }
  if (srpp->max_data_size > 0) {
    fprintf(f, "max_data_size = %lld\n", srpp->max_data_size);
  }
  if (srpp->max_vm_size > 0) {
    fprintf(f, "max_vm_size = %lld\n", srpp->max_vm_size);
  }
  fprintf(f, "max_output_file_size = 60M\n");
  fprintf(f, "max_error_file_size = 16M\n");
  if (srgp->secure_run > 0) {
    fprintf(f, "enable_secure_run = 1\n");
  }
  if (srgp->enable_memory_limit_error > 0 && srgp->secure_run > 0) {
    fprintf(f, "enable_memory_limit_error = 1\n");
  }
  if (srgp->detect_violations > 0 && srgp->secure_run > 0) {
    fprintf(f, "enable_security_violation_error = 1\n");
  }
  fprintf(f, "prob_short_name = \"%s\"\n", srpp->short_name);
  fprintf(f, "program_name = \"%s\"\n", exe_basename);
  fprintf(f, "test_file_name = \"%s\"\n", test_basename);
  fprintf(f, "input_file_name = \"%s\"\n", srpp->input_file);
  fprintf(f, "output_file_name = \"%s\"\n", srpp->output_file);
  fprintf(f, "result_file_name = \"%s\"\n", srpp->output_file);
  fprintf(f, "error_file_name = \"%s\"\n", error_file_name);
  fprintf(f, "log_file_name = \"%s\"\n", log_file_name);

  fflush(f);
  if (ferror(f)) {
    rtf_printf(&result->chk_out, "output error to %s\n", tmp_in_path);
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
    rtf_printf(&result->chk_out, "rename(%s, %s) failed\n", full_in_path, full_dir_path);
    goto fail;
  }

 restart_waiting:;

  // wait for the result package
  // timeout is 2 * real_time_limit
  timeout = 0;
  if (srpp->real_time_limit_ms > 0) timeout = 3 * srpp->real_time_limit_ms;
  if (timeout <= 0) timeout = 3 * time_limit_millis;

  long long wait_end_time = get_current_time_ms();
  wait_end_time += timeout;
  //fprintf(stderr, "end time: %lld\n", wait_end_time);

  while (1) {
    r = scan_dir(result_path, result_pkt_name, sizeof(result_pkt_name), 0);
    if (r < 0) {
      rtf_printf(&result->chk_out, "scan_dir(%s) failed\n", result_path);
      goto fail;
    }

    if (r > 0) break;

    long long cur_time_ms = get_current_time_ms();
    //fprintf(stderr, "time: %lld\n", cur_time_ms);

    if (cur_time_ms >= wait_end_time) {
      rtf_printf(&result->chk_out, "invoke_nwrun: timeout!\n");
      goto fail;
    }

    //cr_serialize_unlock(state);
    interrupt_enable();
    os_Sleep(100);
    interrupt_disable();
    //cr_serialize_lock(state);
  }

  snprintf(dir_entry_packet, sizeof(dir_entry_packet), "%s/dir/%s",
           result_path, result_pkt_name);
  snprintf(out_entry_packet, sizeof(out_entry_packet), "%s/out/%s_%s",
           result_path, os_NodeName(), result_pkt_name);
  if (rename(dir_entry_packet, out_entry_packet) < 0) {
    err("rename(%s, %s) failed: %s", dir_entry_packet, out_entry_packet,
        os_ErrorMsg());
    rtf_printf(&result->chk_out, "rename(%s, %s) failed", dir_entry_packet,
               out_entry_packet);
    goto fail;
  }

  // parse the resulting packet
  snprintf(tmp_in_path, sizeof(tmp_in_path), "%s/packet.cfg",
           out_entry_packet);
  generic_out_packet = nwrun_out_packet_parse(tmp_in_path, &out_packet);
  if (!generic_out_packet) {
    rtf_printf(&result->chk_out, "out_packet parse failed for %s\n", tmp_in_path);
    goto fail;
  }

  // match output and input data
  if (out_packet->contest_id != srgp->contest_id) {
    rtf_printf(&result->chk_out, "contest_id mismatch: %d, %d\n",
               out_packet->contest_id, srgp->contest_id);
    goto restart_waiting;
  }
  if (out_packet->run_id - 1 != srgp->run_id) {
    rtf_printf(&result->chk_out, "run_id mismatch: %d, %d\n",
               out_packet->run_id, srgp->run_id);
    goto restart_waiting;
  }
  if (out_packet->prob_id != srpp->id) {
    rtf_printf(&result->chk_out, "prob_id mismatch: %d, %d\n",
               out_packet->prob_id, srpp->id);
    goto restart_waiting;
  }
  if (out_packet->test_num != test_num) {
    rtf_printf(&result->chk_out, "test_num mismatch: %d, %d\n",
               out_packet->test_num, test_num);
    goto restart_waiting;
  }
  if (out_packet->judge_id != srgp->judge_id) {
    rtf_printf(&result->chk_out, "judge_id mismatch: %d, %d\n",
               out_packet->judge_id, srgp->judge_id);
    goto restart_waiting;
  }

  result->status = out_packet->status;
  if (result->status != RUN_OK
      && result->status != RUN_PRESENTATION_ERR
      && result->status != RUN_RUN_TIME_ERR
      && result->status != RUN_TIME_LIMIT_ERR
      && result->status != RUN_WALL_TIME_LIMIT_ERR
      && result->status != RUN_CHECK_FAILED
      && result->status != RUN_MEM_LIMIT_ERR
      && result->status != RUN_SECURITY_ERR
      && result->status != RUN_SYNC_ERR) {
    rtf_printf(&result->chk_out, "invalid status %d\n", result->status);
    goto fail;
  }

  if (result->status != RUN_OK && out_packet->comment[0]) {
    rtf_printf(&result->chk_out, "nwrun: %s\n", out_packet->comment);
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
  if (srgp->enable_full_archive > 0) {
    filehash_get(test_src_path, result->input_digest);
    result->has_input_digest = 1;
  } else {
    read_run_test_file(srgp, &result->input, test_src_path, 0);
  }

  /* handle the program output */
  if (out_packet->output_file_existed > 0
      && out_packet->output_file_too_big <= 0) {
    snprintf(packet_output_path, sizeof(packet_output_path),
             "%s/%s", out_entry_packet, srpp->output_file);
    if (result->status == RUN_OK) {
      // copy file into the working directory for further checking
      snprintf(check_output_path, sizeof(check_output_path),
               "%s/%s", check_dir, srpp->output_file);
      if (fast_copy_file(packet_output_path, check_output_path) < 0) {
        rtf_printf(&result->chk_out, "copy_file(%s, %s) failed\n",
                   packet_output_path, check_output_path);
        goto fail;
      }
    }

    read_run_test_file(srgp, &result->output, packet_output_path, 0);
    if (far) {
      snprintf(arch_entry_name, sizeof(arch_entry_name), "%06d.o", test_num);
      full_archive_append_file(far, arch_entry_name, 0, packet_output_path);
    }
  } else if (out_packet->output_file_existed > 0) {
    rtf_printf(&result->chk_out, "output file is too big\n");
  }

  /* handle the program error file */
  if (out_packet->error_file_existed > 0) {
    snprintf(packet_error_path, sizeof(packet_error_path),
             "%s/%s", out_entry_packet, error_file_name);
    if (far) {
      file_size = generic_file_size(0, packet_error_path, 0);
      if (file_size >= 0) {
        result->error.is_archived = 1;
        snprintf(arch_entry_name, sizeof(arch_entry_name), "%06d.e", test_num);
        full_archive_append_file(far, arch_entry_name, 0, packet_error_path);
      }
    } else {
      read_run_test_file(srgp, &result->error, packet_error_path, 0);
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
invoke_tar(
        const unsigned char *tar_path,
        const unsigned char *archive_path,
        const unsigned char *working_dir,
        const unsigned char *report_path)
{
  tpTask tsk = NULL;
  int retval = -1;

  info("starting: %s", tar_path);
  tsk = task_New();
  task_AddArg(tsk, tar_path);
  task_AddArg(tsk, "xpfv");
  task_AddArg(tsk, archive_path);
  task_SetPathAsArg0(tsk);
  task_SetWorkingDir(tsk, working_dir);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, report_path, TSK_REWRITE, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_DUP, 1);
  task_Start(tsk);
  task_Wait(tsk);
  if (task_IsAbnormal(tsk)) {
    goto cleanup;
  }

  retval = 0;

cleanup:
  task_Delete(tsk); tsk = 0;
  return retval;
}

static int
invoke_test_checker_cmd(
        const struct super_run_in_packet *srp,
        const unsigned char *work_dir,
        const unsigned char *input_file,
        const unsigned char *log_path,
        int exec_user_serial)
{
  const struct super_run_in_problem_packet *srpp = srp->problem;
  tpTask tsk = NULL;

  tsk = task_New();
  task_AddArg(tsk, srpp->test_checker_cmd);
  task_AddArg(tsk, input_file);
  task_SetPathAsArg0(tsk);
  task_EnableAllSignals(tsk);
  if (work_dir) task_SetWorkingDir(tsk, work_dir);
  task_SetRedir(tsk, 0, TSR_FILE, input_file, TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  if (srpp->test_checker_env) {
    for (int i = 0; srpp->test_checker_env[i]; ++i)
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
  if (srpp->checker_max_rss_size > 0) {
    task_SetRSSSize(tsk, srpp->checker_max_rss_size);
  }
  if (exec_user_serial > 0) {
    char buf[32];
    sprintf(buf, "%d", exec_user_serial);
    task_SetEnv(tsk, "EJUDGE_SUPER_RUN_SERIAL", buf);
  }

  if (task_Start(tsk) < 0) {
    append_msg_to_log(log_path, "failed to start test checker %s", srpp->test_checker_cmd);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  task_Wait(tsk);
  if (task_IsTimeout(tsk)) {
    append_msg_to_log(log_path, "test checker %s time-out", srpp->test_checker_cmd);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  if (task_Status(tsk) == TSK_SIGNALED) {
    append_msg_to_log(log_path, "test checker %s is terminated by signal %d", srpp->test_checker_cmd, task_TermSignal(tsk));
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  int r = task_ExitCode(tsk);
  if (r == 1 || r == 2 || r == RUN_WRONG_ANSWER_ERR || r == RUN_PRESENTATION_ERR) {
    r = RUN_PRESENTATION_ERR;
  } else if (r != 0) {
    append_msg_to_log(log_path, "test checker %s exit code %d is invalid", srpp->test_checker_cmd, r);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }
  task_Delete(tsk);
  return r;
}

static int
invoke_test_generator_cmd(
        const struct super_run_in_packet *srp,
        const unsigned char *test_generator_cmd,
        const unsigned char *work_dir,
        const unsigned char *src_path,
        const unsigned char *log_path,
        int exec_user_serial)
{
  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;
  tpTask tsk = NULL;

  tsk = task_New();
  task_AddArg(tsk, test_generator_cmd);
  task_SetPathAsArg0(tsk);
  task_EnableAllSignals(tsk);
  if (work_dir) task_SetWorkingDir(tsk, work_dir);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_FILE, log_path, TSK_APPEND, TSK_FULL_RW);
  if (srpp->test_generator_env) {
    for (int i = 0; srpp->test_generator_env[i]; ++i)
      task_PutEnv(tsk, srpp->test_generator_env[i]);
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
  if (srpp->checker_max_rss_size > 0) {
    task_SetRSSSize(tsk, srpp->checker_max_rss_size);
  }
  task_SetEnv(tsk, "EJUDGE", "1");
  if (srgp->checker_locale && srgp->checker_locale[0]) {
    task_SetEnv(tsk, "EJUDGE_LOCALE", srgp->checker_locale);
  }
  if (srgp->testlib_mode > 0) {
    task_SetEnv(tsk, "EJUDGE_TESTLIB_MODE", "1");
  }
  if (exec_user_serial > 0) {
    char buf[32];
    sprintf(buf, "%d", exec_user_serial);
    task_SetEnv(tsk, "EJUDGE_SUPER_RUN_SERIAL", buf);
  }
  if (srpp->enable_extended_info > 0) {
    unsigned char buf[64];
    snprintf(buf, sizeof(buf), "%d", srgp->user_id);
    task_SetEnv(tsk, "EJUDGE_USER_ID", buf);
    snprintf(buf, sizeof(buf), "%d", srgp->contest_id);
    task_SetEnv(tsk, "EJUDGE_CONTEST_ID", buf);
    snprintf(buf, sizeof(buf), "%d", srgp->run_id);
    task_SetEnv(tsk, "EJUDGE_RUN_ID", buf);
    task_SetEnv(tsk, "EJUDGE_USER_LOGIN", srgp->user_login);
    task_SetEnv(tsk, "EJUDGE_USER_NAME", srgp->user_name);
  }
  if (src_path) {
    task_SetEnv(tsk, "EJUDGE_SOURCE_PATH", src_path);
  }

  if (task_Start(tsk) < 0) {
    append_msg_to_log(log_path, "failed to start test generator %s", srpp->test_generator_cmd);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  task_Wait(tsk);
  if (task_IsTimeout(tsk)) {
    append_msg_to_log(log_path, "test generator %s time-out", srpp->test_generator_cmd);
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  if (task_Status(tsk) == TSK_SIGNALED) {
    append_msg_to_log(log_path, "test generator %s is terminated by signal %d", srpp->test_generator_cmd, task_TermSignal(tsk));
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  if (task_ExitCode(tsk) != 0) {
    append_msg_to_log(log_path, "test generator %s failed with code %d", srpp->test_generator_cmd, task_ExitCode(tsk));
    task_Delete(tsk);
    return RUN_CHECK_FAILED;
  }

  task_Delete(tsk);
  return 0;
}

static int
invoke_init_cmd(
        const struct super_run_in_packet *srp,
        const unsigned char *subcommand,
        const unsigned char *test_src_path,
        const unsigned char *corr_src_path,
        const unsigned char *info_src_path,
        const unsigned char *working_dir,
        const unsigned char *check_out_path,
        testinfo_t *ti,
        const unsigned char *src_path,
        int cur_test,
        int exec_user_serial,
        uint64_t test_random_value)
{
  tpTask tsk = NULL;
  int status = 0;
  int env_u = 0;
  char **env_v = NULL;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  if (ti) {
    env_u = ti->init_env.u;
    env_v = ti->init_env.v;
  }

  tsk = task_New();
  task_AddArg(tsk, srpp->init_cmd);
  if (subcommand && *subcommand) {
    task_AddArg(tsk, subcommand);
  }
  if (test_src_path && *test_src_path) {
    task_AddArg(tsk, test_src_path);
  }
  if (corr_src_path && *corr_src_path) {
    task_AddArg(tsk, corr_src_path);
  }
  if (info_src_path && *info_src_path) {
    task_AddArg(tsk, info_src_path);
  }
  task_SetPathAsArg0(tsk);
  if (working_dir && *working_dir) {
    task_SetWorkingDir(tsk, working_dir);
  }
  setup_environment(tsk, srpp->init_env, env_u, env_v, 1);
  setup_ejudge_environment(tsk,
                           srp,
                           cur_test,
                           -1, /* test_max_score */
                           0, /* output_only */
                           src_path,
                           exec_user_serial,
                           test_random_value);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
  task_SetRedir(tsk, 1, TSR_FILE, check_out_path, TSK_APPEND, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_DUP, 1);
  task_EnableAllSignals(tsk);
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
  if (srpp->checker_max_rss_size > 0) {
    task_SetRSSSize(tsk, srpp->checker_max_rss_size);
  }

  if (task_Start(tsk) < 0) {
    append_msg_to_log(check_out_path, "failed to start init_cmd %s", srpp->init_cmd);
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  task_Wait(tsk);

  if (task_IsTimeout(tsk)) {
    append_msg_to_log(check_out_path, "init_cmd timeout (%ld ms)", task_GetRunningTime(tsk));
    err("init_cmd timeout (%ld ms)", task_GetRunningTime(tsk));
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  if (task_Status(tsk) == TSK_SIGNALED) {
    int signo = task_TermSignal(tsk);
    append_msg_to_log(check_out_path, "init_cmd terminated with signal %d (%s)",
                      signo, os_GetSignalString(signo));
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  int exitcode = task_ExitCode(tsk);
  switch (exitcode) {
  case RUN_OK:
  case RUN_RUN_TIME_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_MEM_LIMIT_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_SECURITY_ERR:
  case RUN_WALL_TIME_LIMIT_ERR:
  case RUN_SYNC_ERR:
    break;

  case RUN_PRESENTATION_ERR:
    if (srpp->disable_pe > 0) {
      exitcode = RUN_WRONG_ANSWER_ERR;
    }
    break;

  case RUN_CHECK_FAILED:
  default:
    append_msg_to_log(check_out_path, "init_cmd exited with code %d", exitcode);
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  status = exitcode;

cleanup:
  task_Delete(tsk);
  return status;
}

static __attribute__((unused)) tpTask
invoke_interactor(
        const unsigned char *interactor_cmd,
        const unsigned char *test_src_path,
        const unsigned char *output_path,
        const unsigned char *corr_src_path,
        const unsigned char *info_src_path,
        const unsigned char *working_dir,
        const unsigned char *check_out_path,
        struct testinfo_struct *ti,
        int stdin_fd,
        int stdout_fd,
        int control_fd,
        int program_pid,
        const struct super_run_in_packet *srp,
        int cur_test,
        const unsigned char *src_path,
        int exec_user_serial,
        uint64_t test_random_value)
{
  tpTask tsk_int = NULL;
  int env_u = 0;
  char **env_v = NULL;

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  if (ti) {
    env_u = ti->interactor_env.u;
    env_v = ti->interactor_env.v;
  }

  tsk_int = task_New();
  task_AddArg(tsk_int, interactor_cmd);
  task_AddArg(tsk_int, test_src_path);
  task_AddArg(tsk_int, output_path);
  if (corr_src_path && corr_src_path[0]) {
    task_AddArg(tsk_int, corr_src_path);
  }
  if (program_pid > 0 && srgp->testlib_mode <= 0) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d", program_pid);
    task_AddArg(tsk_int, buf);
  }
  if (srpp->use_info > 0) {
    task_AddArg(tsk_int, info_src_path);
  }
  task_SetPathAsArg0(tsk_int);
  task_SetWorkingDir(tsk_int, working_dir);
  setup_environment(tsk_int, srpp->interactor_env, env_u, env_v, 1);
  setup_ejudge_environment(tsk_int,
                           srp,
                           cur_test,
                           -1, /* test_max_score */
                           0, /* output_only */
                           src_path,
                           exec_user_serial,
                           test_random_value);
  if (control_fd >= 0) {
    unsigned char buf[64];
    snprintf(buf, sizeof(buf), "%d", control_fd);
    task_SetEnv(tsk_int, "EJUDGE_CONTROL_FD", buf);
  }
  task_SetRedir(tsk_int, 0, TSR_DUP, stdin_fd);
  task_SetRedir(tsk_int, 1, TSR_DUP, stdout_fd);
  task_SetRedir(tsk_int, 2, TSR_FILE, check_out_path, TSK_APPEND, TSK_FULL_RW);
  task_EnableAllSignals(tsk_int);
  task_IgnoreSIGPIPE(tsk_int);
  if (srpp->interactor_time_limit_ms > 0) {
    task_SetMaxTimeMillis(tsk_int, srpp->interactor_time_limit_ms);
  }
  if (srpp->interactor_real_time_limit_ms > 0) {
    task_SetMaxRealTimeMillis(tsk_int, srpp->interactor_real_time_limit_ms);
  }
  if (srpp->checker_max_stack_size > 0) {
    task_SetStackSize(tsk_int, srpp->checker_max_stack_size);
  }
  if (srpp->checker_max_vm_size > 0) {
    task_SetVMSize(tsk_int, srpp->checker_max_vm_size);
  }
  if (srpp->checker_max_rss_size > 0) {
    task_SetRSSSize(tsk_int, srpp->checker_max_rss_size);
  }

  task_PrintArgs(tsk_int);

  if (task_Start(tsk_int) < 0) {
    task_Delete(tsk_int);
    tsk_int = NULL;
  }

  return tsk_int;
}

static int
touch_file(const unsigned char *path)
{
  int tmpfd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
  if (tmpfd < 0) return -1;
  close(tmpfd);
  return 0;
}

static void
make_java_limits(unsigned char *buf, int blen, ej_size64_t max_vm_size, ej_size64_t max_stack_size)
{
  unsigned char bv[1024], bs[1024];

  buf[0] = 0;
  if (max_vm_size > 0 && max_stack_size > 0) {
    snprintf(buf, blen, "EJUDGE_JAVA_FLAGS=-Xmx%s -Xss%s",
             ej_size64_t_to_size(bv, sizeof(bv), max_vm_size),
             ej_size64_t_to_size(bs, sizeof(bs), max_stack_size));
  } else if (max_vm_size > 0) {
    snprintf(buf, blen, "EJUDGE_JAVA_FLAGS=-Xmx%s",
             ej_size64_t_to_size(bv, sizeof(bv), max_vm_size));
  } else if (max_stack_size > 0) {
    snprintf(buf, blen, "EJUDGE_JAVA_FLAGS=-Xss%s",
             ej_size64_t_to_size(bs, sizeof(bs), max_stack_size));
  } else {
  }
}

static void __attribute__((unused))
make_mono_limits(unsigned char *buf, int blen, ej_size64_t max_vm_size, ej_size64_t max_stack_size)
{
  unsigned char bv[1024];
  // stack limit is not supported
  buf[0] = 0;
  if (max_vm_size > 0) {
    snprintf(buf, blen, "MONO_GC_PARAMS=max-heap-size=%s",
             ej_size64_t_to_size(bv, sizeof(bv), max_vm_size));
  }
}

static unsigned char *
report_args_and_env(testinfo_t *ti)
{
  int i;
  int cmd_args_len = 0;
  unsigned char *s, *args = NULL;

  if (!ti || ti->cmd.u <= 0) return NULL;

  for (i = 0; i < ti->cmd.u; i++) {
    cmd_args_len += 16;
    if (ti->cmd.v[i]) {
      cmd_args_len += strlen(ti->cmd.v[i]) + 16;
    }
  }
  if (cmd_args_len > 0) {
    s = args = (unsigned char *) xmalloc(cmd_args_len + 1);
    for (i = 0; i < ti->cmd.u; i++) {
      if (ti->cmd.v[i]) {
        s += sprintf(s, "[%3d]: >%s<\n", i + 1, ti->cmd.v[i]);
      } else {
        s += sprintf(s, "[%3d]: NULL\n", i + 1);
      }
    }
  }
  return args;
}

static int
invoke_checker(
        const struct super_run_in_packet *srp,
        int cur_test,
        struct run_test_info *cur_info,
        const unsigned char *check_cmd,
        const unsigned char *test_src,
        const unsigned char *output_path,
        const unsigned char *corr_src,
        const unsigned char *info_src,
        const unsigned char *tgzdir_src,
        const unsigned char *working_dir,
        const unsigned char *score_out_path,
        const unsigned char *check_out_path,
        const unsigned char *check_dir,
        testinfo_t *ti,
        int test_score_count,
        const int *test_score_val,
        int output_only,
        const unsigned char *src_path,
        int exec_user_serial,
        uint64_t test_random_value)
{
  tpTask tsk = NULL;
  int status = RUN_CHECK_FAILED;
  int test_max_score = -1;
  int default_score = -1;
  int env_u = 0;
  char **env_v = 0;
  int user_score_mode = 0;
  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  if (ti) {
    env_u = ti->checker_env.u;
    env_v = ti->checker_env.v;
  }

  tsk = task_New();
  task_AddArg(tsk, check_cmd);
  task_SetPathAsArg0(tsk);

  task_AddArg(tsk, test_src);
  task_AddArg(tsk, output_path);
  if (srpp->use_corr > 0) {
    task_AddArg(tsk, corr_src);
  }
  if (srpp->use_info > 0) {
    task_AddArg(tsk, info_src);
  }
  if (srpp->use_tgz > 0) {
    task_AddArg(tsk, tgzdir_src);
    task_AddArg(tsk, working_dir);
  }

  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
  if (srpp->scoring_checker > 0) {
    task_SetRedir(tsk, 1, TSR_FILE, score_out_path, TSK_REWRITE, TSK_FULL_RW);
    task_SetRedir(tsk, 2, TSR_FILE, check_out_path, TSK_APPEND, TSK_FULL_RW);
  } else {
    task_SetRedir(tsk, 1, TSR_FILE, check_out_path, TSK_APPEND, TSK_FULL_RW);
    task_SetRedir(tsk, 2, TSR_DUP, 1);
  }

  task_SetWorkingDir(tsk, check_dir);
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
  if (srpp->checker_max_rss_size > 0) {
    task_SetRSSSize(tsk, srpp->checker_max_rss_size);
  }
	
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
  setup_environment(tsk, srpp->checker_env, env_u, env_v, 1);
  setup_ejudge_environment(tsk,
                           srp,
                           cur_test,
                           test_max_score,
                           output_only,
                           src_path,
                           exec_user_serial,
                           test_random_value);
  if (srgp->separate_user_score > 0 && output_only > 0) {
    user_score_mode = 1;
  }
  task_EnableAllSignals(tsk);

  task_PrintArgs(tsk);

  if (task_Start(tsk) < 0) {
    append_msg_to_log(check_out_path, "failed to start checker %s", check_cmd);
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  task_Wait(tsk);
  task_Log(tsk, 0, LOG_INFO);

  cur_info->checker_stats_str = get_process_stats_str(tsk);

  if (task_IsTimeout(tsk)) {
    append_msg_to_log(check_out_path, "checker timeout (%ld ms)", task_GetRunningTime(tsk));
    err("checker timeout (%ld ms)", task_GetRunningTime(tsk));
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  if (task_Status(tsk) == TSK_SIGNALED) {
    int signo = task_TermSignal(tsk);
    append_msg_to_log(check_out_path, "checker terminated with signal %d (%s)",
                      signo, os_GetSignalString(signo));
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  int exitcode = task_ExitCode(tsk);
  if (exitcode == 1) exitcode = RUN_WRONG_ANSWER_ERR;
  if (exitcode == 2) exitcode = RUN_PRESENTATION_ERR;
  if (exitcode == RUN_PRESENTATION_ERR && srpp->disable_pe > 0) {
    exitcode = RUN_WRONG_ANSWER_ERR;
  }
  if (exitcode == 7 && srgp->testlib_mode > 0) {
    exitcode = RUN_WRONG_ANSWER_ERR;
  }
  if (exitcode != RUN_OK && srgp->not_ok_is_cf > 0) {
    append_msg_to_log(check_out_path, "checker exited with code %d", exitcode);
    append_msg_to_log(check_out_path, "Check failed on non-OK result mode enabled");
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }
  if (exitcode != RUN_OK && exitcode != RUN_PRESENTATION_ERR
      && exitcode != RUN_WRONG_ANSWER_ERR && exitcode != RUN_CHECK_FAILED) {
    append_msg_to_log(check_out_path, "checker exited with code %d", exitcode);
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }

  status = exitcode;
  if (status == RUN_CHECK_FAILED) {
    goto cleanup;
  }
  if (status == RUN_PRESENTATION_ERR) {
    if (user_score_mode) {
      cur_info->user_score = 0;
      cur_info->user_status = status;
      cur_info->user_tests_passed = 0;
    }
    goto cleanup;
  }
	
  if (srpp->scoring_checker > 0) {
    int user_score = -1;
    int user_status = -1;
    int user_tests_passed = -1;
    if (status == RUN_OK) default_score = test_max_score;
    if (parse_checker_score(score_out_path, check_out_path, "checker",
                            user_score_mode,
                            test_max_score, default_score,
                            srgp->testlib_mode,
                            srpp->enable_checker_token,
                            status,
                            &cur_info->score,
                            &user_score,
                            &user_status,
                            &cur_info->checker_token) < 0) {
      status = RUN_CHECK_FAILED;
      goto cleanup;
    }
    if (cur_info->score == test_max_score) {
      status = RUN_OK;
    }
    if (user_score_mode) {
      if (user_score < 0) user_score = cur_info->score;
      if (user_status < 0) user_status = status;
      switch (user_status) {
      case RUN_OK:
      case RUN_ACCEPTED:
      case RUN_PENDING_REVIEW:
        user_tests_passed = 1;
        break;
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_PARTIAL:
        user_tests_passed = 0;
        break;
      }
      if (user_tests_passed < 0) user_tests_passed = 0;

      cur_info->user_score = user_score;
      cur_info->user_status = user_status;
      cur_info->user_tests_passed = user_tests_passed;
    }
  } else {
    if (status == RUN_OK) cur_info->score = test_max_score;
  }

cleanup:
  task_Delete(tsk); tsk = NULL;
  return status;
}

static int
invoke_clean_up_cmd(
        const struct super_run_in_packet *srp,
        const unsigned char *working_dir,
        const unsigned char *check_out_path,
        const unsigned char *src_path,
        int cur_test,
        int exec_user_serial,
        uint64_t test_random_value)
{
  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;
  tpTask tsk = NULL;
  unsigned char start_path[PATH_MAX];
  __attribute__((unused)) int _;
  unsigned char *start_ptr = NULL;
  int status = 0;

  if (!srgp->clean_up_cmd || !srgp->clean_up_cmd[0]) {
    return 0;
  }

  if (os_IsAbsolutePath(srgp->clean_up_cmd)) {
    start_ptr = srgp->clean_up_cmd;
  } else {
    _ = snprintf(start_path, sizeof(start_path), "%s/lang/%s",
                 EJUDGE_SCRIPT_DIR, srgp->clean_up_cmd);
    start_ptr = start_path;
  }

  tsk = task_New();
  task_AddArg(tsk, start_ptr);
  task_SetPathAsArg0(tsk);
  if (working_dir && *working_dir) {
    task_SetWorkingDir(tsk, working_dir);
  }
  setup_environment(tsk, srpp->init_env, 0, NULL, 1);
  setup_ejudge_environment(tsk,
                           srp,
                           cur_test,
                           -1,
                           0,
                           src_path,
                           exec_user_serial,
                           test_random_value);
  if (srgp->clean_up_env_file && *srgp->clean_up_env_file) {
    read_env_file(tsk, srgp->clean_up_env_file);
  }
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
  task_SetRedir(tsk, 1, TSR_FILE, check_out_path, TSK_APPEND, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_DUP, 1);
  task_EnableAllSignals(tsk);
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
  if (srpp->checker_max_rss_size > 0) {
    task_SetRSSSize(tsk, srpp->checker_max_rss_size);
  }

  if (task_Start(tsk) < 0) {
    append_msg_to_log(check_out_path, "failed to start clean_up_cmd %s",
                      start_ptr);
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }
  task_Wait(tsk);
  if (task_IsTimeout(tsk)) {
    append_msg_to_log(check_out_path, "clean_up_cmd timeout (%ld ms)",
                      task_GetRunningTime(tsk));
    err("clean_up_cmd timeout (%ld ms)",
        task_GetRunningTime(tsk));
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }
  if (task_Status(tsk) == TSK_SIGNALED) {
    int signo = task_TermSignal(tsk);
    append_msg_to_log(check_out_path,
                      "clean_up_cmd terminated with signal %d (%s)",
                      signo, os_GetSignalString(signo));
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }
  int exitcode = task_ExitCode(tsk);
  if (exitcode != 0) {
    append_msg_to_log(check_out_path, "clean_up_cmd exited with code %d",
                      exitcode);
    status = RUN_CHECK_FAILED;
    goto cleanup;
  }

cleanup:
  task_Delete(tsk);
  return status;
}

static const char *
remap_start_cmd_for_container(const char *start_cmd)
{
  if (!start_cmd || !*start_cmd) return NULL;
  char *last = strrchr(start_cmd, '/');
  if (!last) return start_cmd;
  ++last;

  static const char * const remaps[][2] =
  {
    { "runmono", "runmono2" },
    { "runjava", "runjava2" },
    { "rundotnet", "rundotnet2" },
    { "runvg", "runvg2" },
    { NULL, NULL },
  };

  for (int i = 0; remaps[i][0]; ++i) {
    if (!strcmp(last, remaps[i][0])) {
      static char remap_buf[PATH_MAX];
      snprintf(remap_buf, sizeof(remap_buf), "%s/ejudge/lang/%s", EJUDGE_LIBEXEC_DIR, remaps[i][1]);
      return remap_buf;
    }
  }

  return start_cmd;
}

static int
is_java_memory_limit(const unsigned char *text, ssize_t size)
{
  static const char AT_STR[] = "at ";
  static const char EX_STR_1[] = "Exception in thread \"";
  static const char EX_STR_2[] = "\" java.lang.OutOfMemoryError: Java heap space";
  static const char EX_STR_3[] = "\" java.lang.StackOverflowError";

  if (size <= 0 || !text || strlen(text) != size) return 0;

  char **lines = NULL;
  split_to_lines(text, &lines, 2);
  int i = 0;
  for (; lines[i]; ++i) {}
  --i;
  for (; i >= 0 && !strncmp(AT_STR, lines[i], sizeof(AT_STR) - 1); --i) {}
  if (i < 0) return 0;
  int len = strlen(lines[i]);
  if (len <= sizeof(EX_STR_1) - 1) return 0;
  if (strncmp(lines[i], EX_STR_1, sizeof(EX_STR_1) - 1)) return 0;
  if (len > sizeof(EX_STR_2) && !strcmp(lines[i] + len - sizeof(EX_STR_2) + 1, EX_STR_2)) return 1;
  if (len > sizeof(EX_STR_3) && !strcmp(lines[i] + len - sizeof(EX_STR_3) + 1, EX_STR_3)) return 1;

  return 0;
}

struct testinfo_subst_handler_super_run
{
  struct testinfo_subst_handler b;
  const struct super_run_in_packet *srp;
  char *eff_s; // effective .inf file text
  size_t eff_z;
  FILE *eff_f;
};

static unsigned char *testinfo_subst_handler_substitute(struct testinfo_subst_handler *bp, const unsigned char *str)
{
  struct testinfo_subst_handler_super_run *srh = (struct testinfo_subst_handler_super_run *) bp;
  unsigned char *s = text_substitute(srh->srp, str, super_run_in_packet_get_variable);
  if (srh->eff_f) {
    fprintf(srh->eff_f, "%s\n", s);
  }
  return s;
}

static unsigned char *
remap_command(const unsigned char *cmd, const struct remap_spec *specs)
{
  if (!specs) return xstrdup(cmd);
  for (const struct remap_spec *spec = specs; spec->src_dir; ++spec) {
    if (!strncmp(cmd, spec->src_dir, spec->src_len)) {
      unsigned char *out = malloc(spec->dst_len + strlen(cmd + spec->src_len) + 1);
      sprintf(out, "%s%s", spec->dst_dir, cmd + spec->src_len);
      return out;
    }
  }
  return xstrdup(cmd);
}

static int
does_test_exist(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct super_run_in_packet *srp,
        const unsigned char *test_dir,
        int cur_test)
{
  unsigned char test_base[PATH_MAX];
  unsigned char test_src[PATH_MAX];
  const struct super_run_in_problem_packet *srpp = srp->problem;

  test_src[0] = 0;
  if (srpp->test_pat && srpp->test_pat[0]) {
    snprintf(test_base, sizeof(test_base), srpp->test_pat, cur_test);
    snprintf(test_src, sizeof(test_src), "%s/%s", test_dir, test_base);
  }
  return os_CheckAccess(test_src, REUSE_R_OK) >= 0;
}

static int
copy_exe_file_and_extract_args(
        const unsigned char *src_dir,
        const unsigned char *src_name,
        const unsigned char *src_sfx,
        const unsigned char *src_b,
        ssize_t src_z,
        ssize_t prepended_size,
        unsigned char **p_interpreter_str,
        const unsigned char *dst_dir,
        const unsigned char *dst_name,
        const unsigned char *dst_sfx,
        unsigned char **interpreter_args,
        int *p_interpreter_cnt)
{
  int retval = -1;
  unsigned char src_path[PATH_MAX];
  unsigned char dst_path[PATH_MAX];
  int src_fd = -1;
  int r;
  unsigned char *src_mem = MAP_FAILED;
  size_t src_mem_z = 0;
  size_t start_offset = 0;
  size_t dst_z = 0;
  int dst_fd = -1;
  unsigned char *dst_mem = MAP_FAILED;
  unsigned char *interpreter_str = NULL;

  if (!src_b) {
    if (!src_sfx) src_sfx = "";
    if (src_dir && *src_dir) {
      r = snprintf(src_path, sizeof(src_path), "%s/%s%s", src_dir, src_name, src_sfx);
    } else {
      r = snprintf(src_path, sizeof(src_path), "%s%s", src_name, src_sfx);
    }
    if (r >= (int) sizeof(src_path)) {
      err("%s: src_path is too long", __FUNCTION__);
      goto cleanup;
    }
    src_fd = open(src_path, O_RDONLY | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0);
    if (src_fd < 0) {
      err("%s: failed to open '%s': %s", __FUNCTION__, src_path, os_ErrorMsg());
      goto cleanup;
    }
    struct stat stb;
    if (fstat(src_fd, &stb) < 0) {
      err("%s: failed to fstat: %s", __FUNCTION__, os_ErrorMsg());
      goto cleanup;
    }
    if (!S_ISREG(stb.st_mode)) {
      err("%s: '%s' not regular", __FUNCTION__, src_path);
      goto cleanup;
    }
    if (stb.st_size > 0) {
      if (stb.st_size > 1024 * 1024 * 1024) {
        err("%s: '%s' is too big", __FUNCTION__, src_path);
        goto cleanup;
      }
      src_mem_z = stb.st_size;
      src_mem = mmap(NULL, src_mem_z, PROT_READ, MAP_PRIVATE, src_fd, 0);
      if (src_mem == MAP_FAILED) {
        err("%s: mmap '%s' failed: %s", __FUNCTION__, src_path, os_ErrorMsg());
        goto cleanup;
      }
    } else {
      src_mem = NULL;
      src_mem_z = 0;
    }
    close(src_fd); src_fd = -1;
    src_b = src_mem;
    src_z = src_mem_z;
  }

  while (1) {
    if (prepended_size <= 0) {
      break;
    }
    if (prepended_size >= src_z) {
      break;
    }
    interpreter_str = malloc(prepended_size + 1);
    memcpy(interpreter_str, src_b, prepended_size);
    interpreter_str[prepended_size] = 0;
    unsigned char *ep = strchr(interpreter_str, '\n');
    if (!ep) {
      break;
    }
    int ei = ep - interpreter_str;
    while (ei > 0 && isspace(interpreter_str[ei - 1])) --ei;
    interpreter_str[ei] = 0;
    if (interpreter_str[0] != '#' || interpreter_str[1] != '!') {
      break;
    }
    int bi = 2;
    if (bi == ei) {
      break;
    }
    while (isspace(interpreter_str[bi])) ++bi;
    int cnt = 0;
    // extract interpreter name
    int eei = bi;
    while (interpreter_str[eei] && !isspace(interpreter_str[eei])) ++eei;
    if (interpreter_str[eei]) {
      interpreter_str[eei] = 0;
      interpreter_args[cnt++] = &interpreter_str[bi];
      bi = eei + 1;
      while (isspace(interpreter_str[bi])) ++bi;
      interpreter_args[cnt++] = &interpreter_str[bi];
      interpreter_args[cnt] = NULL;
    } else {
      interpreter_args[cnt++] = &interpreter_str[bi];
      interpreter_args[cnt] = NULL;
    }
    *p_interpreter_cnt = cnt;
    start_offset = prepended_size;
    *p_interpreter_str = interpreter_str; interpreter_str = NULL;
    break;
  }

  dst_z = src_z - start_offset;
  if (!dst_sfx) dst_sfx = "";
  if (dst_dir && *dst_dir) {
    r = snprintf(dst_path, sizeof(dst_path), "%s/%s%s", dst_dir, dst_name, dst_sfx);
  } else {
    r = snprintf(dst_path, sizeof(dst_path), "%s%s", dst_name, dst_sfx);
  }
  if (r >= (int) sizeof(dst_path)) {
    err("%s: dst_path is too long", __FUNCTION__);
    goto cleanup;
  }
  dst_fd = open(dst_path, O_RDWR | O_CREAT | O_TRUNC | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK, 0666);
  if (dst_fd < 0) {
    err("%s: open '%s' failed: %s", __FUNCTION__, dst_path, os_ErrorMsg());
    goto cleanup;
  }
  struct stat stb;
  if (fstat(dst_fd, &stb) < 0) {
    err("%s: fstat failed: %s", __FUNCTION__, os_ErrorMsg());
    goto cleanup;
  }
  if (ftruncate(dst_fd, dst_z) < 0) {
    err("%s: ftruncate failed: %s", __FUNCTION__, os_ErrorMsg());
    goto cleanup;
  }
  if (dst_z > 0) {
    dst_mem = mmap(NULL, dst_z, PROT_READ | PROT_WRITE, MAP_SHARED, dst_fd, 0);
    if (dst_mem == MAP_FAILED) {
      err("%s: mmap failed: %s", __FUNCTION__, os_ErrorMsg());
      goto cleanup;
    }
    close(dst_fd); dst_fd = -1;
    memcpy(dst_mem, src_b + start_offset, dst_z);
  }

  retval = 0;

cleanup:;
  if (dst_mem != MAP_FAILED) munmap(dst_mem, dst_z);
  if (src_mem && src_mem != MAP_FAILED) munmap(src_mem, src_mem_z);
  if (src_fd >= 0) close(src_fd);
  if (dst_fd >= 0) close(dst_fd);
  xfree(interpreter_str);
  return retval;
}

static ssize_t
get_max_line_length(const unsigned char *data, ssize_t size)
{
  ssize_t max_len = 0;
  ssize_t prev_ind = -1;
  for (ssize_t i = 0; i < size; ++i) {
    if (data[i] == '\n') {
      if (i - prev_ind > max_len) {
        max_len = i - prev_ind;
      }
      prev_ind = i;
    }
  }
  if (size - prev_ind > max_len) {
    max_len = size - prev_ind;
  }
  return max_len;
}

static void
trim_long_lines(
        const unsigned char *data,
        ssize_t size,
        int utf8_mode,
        int max_line_length,
        unsigned char **p_out_data,
        ssize_t *p_out_size)
{
  char *out_s = NULL;
  size_t out_z = 0;
  FILE *out_f = open_memstream(&out_s, &out_z);
  ssize_t beg_ind = 0;
  ssize_t ind;

  for (ind = 0; ind < size; ++ind) {
    if (data[ind] == '\n') {
      if (ind - beg_ind > max_line_length) {
        if (utf8_mode) {
          ssize_t trimmed = utf8_trim_last_codepoint(&data[beg_ind], max_line_length);
          fwrite_unlocked(&data[beg_ind], 1, trimmed, out_f);
          fputs_unlocked("…\n", out_f);
        } else {
          fwrite_unlocked(&data[beg_ind], 1, max_line_length, out_f);
          fputs_unlocked("...\n", out_f);
        }
      } else {
        fwrite_unlocked(&data[beg_ind], 1, ind - beg_ind + 1, out_f);
      }
      beg_ind = ind + 1;
    } else if (ind == size - 1) {
      if (ind - beg_ind + 1 > max_line_length) {
        if (utf8_mode) {
          ssize_t trimmed = utf8_trim_last_codepoint(&data[beg_ind], max_line_length);
          fwrite_unlocked(&data[beg_ind], 1, trimmed, out_f);
          fputs_unlocked("…", out_f);
        } else {
          fwrite_unlocked(&data[beg_ind], 1, max_line_length, out_f);
          fputs_unlocked("...", out_f);
        }
      } else {
        fwrite_unlocked(&data[beg_ind], 1, ind - beg_ind + 1, out_f);
      }
    }
  }

  fclose(out_f);
  *p_out_data = out_s;
  *p_out_size = out_z;
}

static void
read_run_test_file(
        const struct super_run_in_global_packet *srgp,
        struct run_test_file *rtf,
        const unsigned char *path,
        int utf8_mode)
{
  int fd = -1;
  unsigned char *proc_data = NULL;
  long long proc_size = 0;

  memset(rtf, 0, sizeof(*rtf));

  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK, 0);
  if (fd < 0) {
    err("%s: cannot open on '%s': %s", __FUNCTION__, path, os_ErrorMsg());
    return;
  }

  struct stat stb;
  if (fstat(fd, &stb) < 0) {
    err("%s: stat failed on '%s': %s", __FUNCTION__, path, os_ErrorMsg());
    goto done;
  }
  if (stb.st_size < 0) {
    err("%s: invalid size of '%s': %lld", __FUNCTION__, path,
        (long long) stb.st_size);
    goto done;
  }
  if (!S_ISREG(stb.st_mode)) {
    err("%s: not a regular file: '%s'", __FUNCTION__, path);
    goto done;
  }
  if (!stb.st_size) {
    // empty file
    rtf->data = xmalloc(1);
    rtf->data[0] = 0;
    rtf->is_here = 1;
    goto done;
  }

  proc_size = stb.st_size;
  if (stb.st_size > srgp->max_file_length) {
    proc_size = srgp->max_file_length;
  }
  proc_data = xmalloc(proc_size + 1024);

  {
    long long rem_size = proc_size;
    unsigned char *p = proc_data;
    while (rem_size > 0) {
      ssize_t r = read(fd, p, rem_size);
      if (r < 0) {
        err("%s: read error from '%s': %s", __FUNCTION__, path, os_ErrorMsg());
        goto done;
      }
      if (!r) {
        err("%s: file truncated '%s'", __FUNCTION__, path);
        proc_size -= rem_size;
        break;
      }
      rem_size -= r;
      p += r;
    }
    proc_data[proc_size] = 0;
  }
  close(fd); fd = -1;

  if (need_base64(proc_data, proc_size)) {
    // binary file
    rtf->orig_size = stb.st_size;
    rtf->is_here = 1;
    rtf->is_binary = 1;
    rtf->is_too_long = (stb.st_size > proc_size);
    rtf->is_base64 = 1;
    rtf->data = xmalloc(proc_size * 4 / 3 + 64);
    int len = base64_encode(proc_data, proc_size, rtf->data);
    rtf->data[len] = 0;
    rtf->stored_size = len;
    goto done;
  }

  if (proc_size != stb.st_size && utf8_mode) {
    proc_size = utf8_trim_last_codepoint(proc_data, proc_size);
  }

  ssize_t max_len = get_max_line_length(proc_data, proc_size);
  if (max_len > srgp->max_line_length) {
    unsigned char *out_data = NULL;
    ssize_t out_size = 0;
    rtf->is_too_long = proc_size != stb.st_size;
    trim_long_lines(proc_data, proc_size, utf8_mode, srgp->max_line_length,
                    &out_data, &out_size);
    xfree(proc_data); proc_data = out_data; out_data = NULL;
    proc_size = out_size; out_size = 0;
    rtf->is_too_wide = 1;
  } else {
    rtf->is_too_long = proc_size != stb.st_size;
  }
  if (rtf->is_too_long) {
    if (utf8_mode) {
      static const char append_str[] = "\n…\n";
      proc_data = xrealloc(proc_data, proc_size + 64);
      strcpy(proc_data + proc_size, append_str);
      proc_size += sizeof(append_str) - 1;
    } else {
      static const char append_str[] = "\n...\n";
      proc_data = xrealloc(proc_data, proc_size + 64);
      strcpy(proc_data + proc_size, append_str);
      proc_size += sizeof(append_str) - 1;
    }
  }
  if (utf8_mode) {
    utf8_fix_string(proc_data, NULL);
    // FIXME: set is_fixed depending on the number of utf8 fixes
  }
  rtf->data = proc_data; proc_data = NULL;
  rtf->orig_size = stb.st_size;
  rtf->stored_size = proc_size;
  rtf->is_here = 1;

done:;
  xfree(proc_data);
  if (fd >= 0) close(fd);
}

static int
run_one_test(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct super_run_in_packet *srp,
        const struct section_tester_data *tst,
        struct AgentClient *agent,
        int cur_test,
        struct run_test_info_vector *tests,
        full_archive_t far,
        const unsigned char *exe_name,
        const unsigned char *report_path,
        const unsigned char *check_cmd,
        const unsigned char *interactor_cmd,
        char **start_env,
        int open_tests_count,
        const int *open_tests_val,
        int test_score_count,
        const int *test_score_val,
        long long expected_free_space,
        int *p_has_real_time,
        int *p_has_max_memory_used,
        int *p_has_max_rss,
        long *p_report_time_limit_ms,
        long *p_report_real_time_limit_ms,
        int utf8_mode,
        const unsigned char *mirror_dir,
        const struct remap_spec *remaps,
        int user_input_mode,
        const unsigned char *inp_data,
        size_t inp_size,
        const unsigned char *src_path,
        const unsigned char *test_dir,
        const unsigned char *corr_dir,
        const unsigned char *info_dir,
        const unsigned char *tgz_dir)
{
  const struct section_global_data *global = state->global;

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  unsigned char test_base[PATH_MAX];
  unsigned char corr_base[PATH_MAX];
  unsigned char info_base[PATH_MAX];
  unsigned char tgz_base[PATH_MAX];
  unsigned char tgzdir_base[PATH_MAX];

  unsigned char test_src[PATH_MAX];
  unsigned char corr_src[PATH_MAX];
  unsigned char info_src[PATH_MAX];
  unsigned char tgz_src[PATH_MAX];
  unsigned char tgzdir_src[PATH_MAX];

  unsigned char check_out_path[PATH_MAX];
  unsigned char score_out_path[PATH_MAX];
  const unsigned char *output_path_to_check = NULL;
  unsigned char test_checker_out_path[PATH_MAX];

  unsigned char check_dir[PATH_MAX];
  unsigned char exe_path[PATH_MAX];
  unsigned char working_dir[PATH_MAX];
  unsigned char input_path[PATH_MAX];
  unsigned char output_path[PATH_MAX];
  unsigned char error_path[PATH_MAX];
  unsigned char arg0_path[PATH_MAX];
  unsigned char error_file[PATH_MAX];
  unsigned char error_code[PATH_MAX];
  unsigned char arch_entry_name[PATH_MAX];
  unsigned char local_check_cmd[PATH_MAX];
  unsigned char exe_dir[PATH_MAX];

  unsigned char mem_limit_buf[PATH_MAX];

  struct run_test_info *cur_info = NULL;
  int time_limit_value_ms = 0;
  int status = RUN_CHECK_FAILED;
  int errcode = 0;
  int disable_stderr = -1;
  int copy_flag = 0;
  int error_code_value = 0;
  long long file_size;
  int init_cmd_started = 0;
  int pg_not_empty = 0;

  int pfd1[2] = { -1, -1 };
  int pfd2[2] = { -1, -1 };
  int cfd[2] = { -1, -1 }; // control socket for container
  testinfo_t tstinfo;
  tpTask tsk_int = NULL;
  tpTask tsk = NULL;

  unsigned char start_cmd_name[PATH_MAX];
  unsigned char start_cmd_arg[PATH_MAX];
  unsigned char start_cmd_path[PATH_MAX];

  FILE *start_msg_f = NULL;
  char *start_msg_s = NULL;
  size_t start_msg_z = 0;
  int start_msg_need_env = 0;

  char *eff_inf_text = NULL;

#ifdef HAVE_TERMIOS_H
  struct termios term_attrs;
#endif

  unsigned char *interpreter_args[4];
  int interpreter_cnt = 0;
  unsigned char *interpreter_str = NULL;

  uint64_t test_random_value;
  int clean_up_executed = 0;

  test_checker_out_path[0] = 0;
  memset(&tstinfo, 0, sizeof(tstinfo));

#ifdef HAVE_TERMIOS_H
  memset(&term_attrs, 0, sizeof(term_attrs));
#endif

  if (srgp->scoring_system_val == SCORE_OLYMPIAD
      && srgp->accepting_mode > 0
      && cur_test > srpp->tests_to_accept) {
    return -1;
  }

  if (srpp->test_count > 0 && cur_test > srpp->test_count) {
    return -1;
  }

  random_init();
  test_random_value = random_u64();

  test_base[0] = 0;
  test_src[0] = 0;
  if (srpp->test_pat && srpp->test_pat[0]) {
    snprintf(test_base, sizeof(test_base), srpp->test_pat, cur_test);
    snprintf(test_src, sizeof(test_src), "%s/%s", test_dir, test_base);
  }
  corr_base[0] = 0;
  corr_src[0] = 0;
  if (srpp->corr_pat && srpp->corr_pat[0]) {
    snprintf(corr_base, sizeof(corr_base), srpp->corr_pat, cur_test);
    snprintf(corr_src, sizeof(corr_src), "%s/%s", corr_dir, corr_base);
  }
  if (srpp->use_corr > 0 && corr_src[0]) {
    mirror_file(agent, corr_src, sizeof(corr_src), mirror_dir);
  }
  info_base[0] = 0;
  info_src[0] = 0;
  if (srpp->use_info > 0) {
    snprintf(info_base, sizeof(info_base), srpp->info_pat, cur_test);
    snprintf(info_src, sizeof(info_src), "%s/%s", info_dir, info_base);
  }
  tgz_base[0] = 0;
  tgzdir_base[0] = 0;
  tgz_src[0] = 0;
  tgzdir_src[0] = 0;
  if (srpp->use_tgz > 0) {
    snprintf(tgz_base, sizeof(tgz_base), srpp->tgz_pat, cur_test);
    snprintf(tgz_src, sizeof(tgz_src), "%s/%s", tgz_dir, tgz_base);
    snprintf(tgzdir_base, sizeof(tgzdir_base), srpp->tgzdir_pat, cur_test);
    snprintf(tgzdir_src, sizeof(tgzdir_src), "%s/%s", tgz_dir, tgzdir_base);
  }

  // avoid check access operation if the test count is known
  if (srpp->test_count <= 0 && os_CheckAccess(test_src, REUSE_R_OK) < 0) {
    return -1;
  }

  if (tst && tst->check_dir && tst->check_dir[0]) {
    snprintf(check_dir, sizeof(check_dir), "%s", tst->check_dir);
  } else {
    snprintf(check_dir, sizeof(check_dir), "%s", global->run_check_dir);
  }

  ASSERT(cur_test == tests->size);

  if (tests->size >= tests->reserved) {
    tests->reserved *= 2;
    if (!tests->reserved) tests->reserved = 32;
    tests->data = (typeof(tests->data)) xrealloc(tests->data, tests->reserved * sizeof(tests->data[0]));
  }
  memset(&tests->data[cur_test], 0, sizeof(tests->data[0]));
  cur_info = &tests->data[cur_test];
  ++tests->size;

  cur_info->visibility = TV_NORMAL;
  if (open_tests_val && cur_test > 0 && cur_test < open_tests_count) {
    cur_info->visibility = open_tests_val[cur_test];
  }
  cur_info->user_status = -1;
  cur_info->user_score = -1;
  cur_info->user_nominal_score = -1;

  time_limit_value_ms = 0;
  if (srpp->time_limit_ms > 0) {
    time_limit_value_ms += srpp->time_limit_ms;
  }
  if (time_limit_value_ms > 0) {
    // adjustment works only for limited time
    if (tst && tst->time_limit_adj_millis > 0)
      time_limit_value_ms += tst->time_limit_adj_millis;
    else if (tst && tst->time_limit_adjustment > 0)
      time_limit_value_ms += tst->time_limit_adjustment * 1000;
    if (srgp->lang_time_limit_adj_ms > 0)
      time_limit_value_ms += srgp->lang_time_limit_adj_ms;
  }

  snprintf(check_out_path, sizeof(check_out_path), "%s/checkout_%d.txt",
           global->run_work_dir, cur_test);
  snprintf(score_out_path, sizeof(score_out_path), "%s/scoreout_%d.txt",
           global->run_work_dir, cur_test);

  error_code[0] = 0;
  if (tst && tst->errorcode_file && tst->errorcode_file[0]) {
    snprintf(error_code, sizeof(error_code), "%s/%s", check_dir, tst->errorcode_file);
  }

  if (tst && tst->nwrun_spool_dir && tst->nwrun_spool_dir[0]) {
    status = invoke_nwrun(config, state,
                          tst, srp, far,
                          cur_test, 0, p_has_real_time,
                          global->run_work_dir,
                          exe_name, test_src, test_base, time_limit_value_ms,
                          cur_info, check_dir);
    if (cur_info->max_memory_used > 0) {
      *p_has_max_memory_used = 1;
    }
    if (status > 0) {
      goto cleanup;
    }
    goto run_checker;
  }

  /* Load test information file */
  if (srpp->use_info > 0) {
    struct testinfo_subst_handler_super_run sr;
    memset(&sr, 0, sizeof(sr));
    sr.b.substitute = testinfo_subst_handler_substitute;
    sr.srp = srp;
    sr.eff_f = open_memstream(&sr.eff_s, &sr.eff_z);
    if ((errcode = testinfo_parse(info_src, &tstinfo, &sr.b)) < 0) {
      fclose(sr.eff_f); xfree(sr.eff_s);
      err("Cannot parse test info file '%s': %s", info_src, testinfo_strerror(-errcode));
      append_msg_to_log(check_out_path, "failed to parse testinfo file '%s': %s\n",
                        info_src, testinfo_strerror(-errcode));
      goto check_failed;
    }
    fclose(sr.eff_f);
    eff_inf_text = sr.eff_s;

    // if 'enable_subst' is enabled, save the effective .inf file into the working directory
    // and further use it instead of the original file
    if (tstinfo.enable_subst > 0) {
      snprintf(info_src, sizeof(info_src), "%s/eff_%s", global->run_work_dir, info_base);
      if (generic_write_file(sr.eff_s, sr.eff_z, 0, NULL, info_src, NULL) < 0) {
        append_msg_to_log(check_out_path, "failed to save effective testinfo file '%s': %s\n",
                          info_src, testinfo_strerror(-errcode));
        goto check_failed;
      }
    }
    xfree(eff_inf_text); eff_inf_text = NULL;

    if (srgp->lang_short_name && srgp->lang_short_name[0] && tstinfo.ok_language.u > 0) {
      int i;
      for (i = 0; i < tstinfo.ok_language.u; ++i) {
        if (tstinfo.ok_language.v[i] && !strcmp(tstinfo.ok_language.v[i], srgp->lang_short_name))
          break;
      }
      if (i < tstinfo.ok_language.u) {
        // mark this test as successfully passed
        status = RUN_OK; // FIXME: RUN_SKIPPED?
        rtf_printf(&cur_info->chk_out, "auto-OK for language %s", srgp->lang_short_name);
        //cur_info->comment = xstrdup(cur_info->chk_out);
        // FIXME: set comment or team_comment
        goto cleanup;
      }
    }


    if (sizeof(tstinfo.max_vm_size) != sizeof(size_t)) {
      if (tstinfo.max_vm_size > 0 && (size_t) tstinfo.max_vm_size != tstinfo.max_vm_size) {
        append_msg_to_log(check_out_path, "max_vm_size %lld cannot be represented by size_t\n", tstinfo.max_vm_size);
        goto check_failed;
      }
      if (tstinfo.max_stack_size > 0 && (size_t) tstinfo.max_stack_size != tstinfo.max_stack_size) {
        append_msg_to_log(check_out_path, "max_stack_size %lld cannot be represented by size_t\n", tstinfo.max_stack_size);
        goto check_failed;
      }
      if (tstinfo.max_rss_size > 0 && (size_t) tstinfo.max_rss_size != tstinfo.max_rss_size) {
        append_msg_to_log(check_out_path, "max_rss_size %lld cannot be represented by size_t\n", tstinfo.max_rss_size);
        goto check_failed;
      }
      if (tstinfo.max_file_size > 0 && (size_t) tstinfo.max_file_size != tstinfo.max_file_size) {
        append_msg_to_log(check_out_path, "max_file_size %lld cannot be represented by size_t\n", tstinfo.max_file_size);
        goto check_failed;
      }
    }
  }

  if (srpp->use_info > 0 && tstinfo.disable_stderr >= 0) {
    disable_stderr = tstinfo.disable_stderr;
  }
  if (disable_stderr < 0) {
    disable_stderr = srpp->disable_stderr;
  }
  if (disable_stderr < 0) {
    disable_stderr = 0;
  }

  if (tstinfo.disable_valgrind && tst && !strcmp(tst->arch, "valgrind")) {
    struct section_tester_data *newtst = NULL;
    for (int i = 0; i < state->max_abstr_tester; ++i) {
      if (state->abstr_testers[i] && !state->abstr_testers[i]->arch[0]) {
        newtst = state->abstr_testers[i];
      }
    }
    if (!newtst) {
      err("failed to find replacement testing settings for disable_valgrind mode");
    } else {
      tst = newtst;
    }
  }

  make_writable(check_dir);
  clear_directory(check_dir);
  check_free_space(check_dir, expected_free_space);

  if (srpp->use_tgz > 0 && srpp->copy_exe_to_tgzdir > 0) {
    snprintf(exe_dir, sizeof(exe_dir), "%s/%s", check_dir, tgzdir_base);
    if (mkdir(exe_dir, 0700) < 0 && errno != EEXIST) {
      append_msg_to_log(check_out_path, "failed to create directory '%s': %s", exe_dir, os_ErrorMsg());
      goto check_failed;
    }
  } else {
    snprintf(exe_dir, sizeof(exe_dir), "%s", check_dir);
  }

  if (srgp->zip_mode > 0) {
    unsigned char zip_path[PATH_MAX];
    snprintf(zip_path, sizeof(zip_path), "%s/%s", global->run_work_dir, exe_name);
    FILE *log_f = fopen(check_out_path, "a");
    struct ZipData *zf = ej_libzip_open(log_f, zip_path, O_RDONLY);
    if (!zf) {
      if (log_f) {
        fprintf(log_f, "cannot open zip '%s' file for reading\n", check_out_path);
        fclose(log_f);
      }
      goto check_failed;
    }
    unsigned char entry_name[PATH_MAX];
    if (srgp->exe_sfx) {
      snprintf(entry_name, sizeof(entry_name), "%06d_%03d%s", srgp->run_id, cur_test, srgp->exe_sfx);
    } else {
      snprintf(entry_name, sizeof(entry_name), "%06d_%03d", srgp->run_id, cur_test);
    }
    unsigned char *bytes_s = NULL;
    ssize_t bytes_z = 0;
    if (zf->ops->read_file(zf, entry_name, &bytes_s, &bytes_z) < 0 || !bytes_s) {
      if (log_f) {
        fprintf(log_f, "cannot extract entry '%s' from zip archive\n", entry_name);
        fclose(log_f);
      }
      zf->ops->close(zf);
      goto check_failed;
    }
    zf->ops->close(zf); zf = NULL;
    unsigned char target_path[PATH_MAX];
    snprintf(target_path, sizeof(target_path), "%s/%s", exe_dir, exe_name);
    if (srgp->prepended_size > 0) {
      if (copy_exe_file_and_extract_args(NULL, NULL, NULL,
                                         bytes_s, bytes_z, srgp->prepended_size,
                                         &interpreter_str,
                                         exe_dir, exe_name, NULL,
                                         interpreter_args, &interpreter_cnt) < 0) {
        if (log_f) {
          fprintf(log_f, "cannot save file '%s'\n", target_path);
          fclose(log_f);
        }
        xfree(bytes_s);
        goto check_failed;
      }
    } else {
      if (generic_write_file(bytes_s, bytes_z, 0, NULL, target_path, NULL) < 0) {
        if (log_f) {
          fprintf(log_f, "cannot save file '%s'\n", target_path);
          fclose(log_f);
        }
        xfree(bytes_s);
        goto check_failed;
      }
    }
    xfree(bytes_s);
    if (log_f) fclose(log_f);
  } else {
    if (srgp->prepended_size > 0) {
      if (copy_exe_file_and_extract_args(global->run_work_dir,
                                         exe_name, NULL,
                                         NULL, 0,
                                         srgp->prepended_size,
                                         &interpreter_str,
                                         exe_dir, exe_name, NULL,
                                         interpreter_args, &interpreter_cnt) < 0) {
        append_msg_to_log(check_out_path, "failed to copy %s/%s -> %s/%s", global->run_work_dir, exe_name,
                          exe_dir, exe_name);
        goto check_failed;
      }
    } else {
      if (generic_copy_file(0, global->run_work_dir, exe_name, "", 0, exe_dir, exe_name, "") < 0) {
        append_msg_to_log(check_out_path, "failed to copy %s/%s -> %s/%s", global->run_work_dir, exe_name,
                          exe_dir, exe_name);
        goto check_failed;
      }
    }
  }

  snprintf(exe_path, sizeof(exe_path), "%s/%s", exe_dir, exe_name);
  make_executable(exe_path);

  start_cmd_name[0] = 0;
  start_cmd_arg[0] = 0;
  start_cmd_path[0] = 0;
  if (srpp->start_cmd && srpp->start_cmd[0]) {
    os_rGetLastname(srpp->start_cmd, start_cmd_name, sizeof(start_cmd_name));
    if (srpp->use_tgz > 0) {
      snprintf(start_cmd_arg, sizeof(start_cmd_arg), "../%s", start_cmd_name);
    } else {
      snprintf(start_cmd_arg, sizeof(start_cmd_arg), "./%s", start_cmd_name);
    }
    snprintf(start_cmd_path, sizeof(start_cmd_path), "%s/%s", check_dir, start_cmd_name);
    if (generic_copy_file(0, NULL, srpp->start_cmd, NULL, 0, NULL, start_cmd_path, NULL) < 0) {
      append_msg_to_log(check_out_path, "failed to copy %s -> %s", srpp->start_cmd, start_cmd_path);
      goto check_failed;
    }
    make_executable(start_cmd_path);
  }

  if (srpp->use_tgz > 0 && srpp->copy_exe_to_tgzdir <= 0) {
#ifdef __WIN32__
    snprintf(arg0_path, sizeof(arg0_path), "%s%s..%s%s", check_dir, CONF_DIRSEP, CONF_DIRSEP, exe_name);
#else
    snprintf(arg0_path, sizeof(arg0_path), "../%s", exe_name);
#endif
  } else {
#ifdef __WIN32__
    snprintf(arg0_path, sizeof(arg0_path), "%s", exe_path);
#else
    snprintf(arg0_path, sizeof(arg0_path), "./%s", exe_name);
#endif
  }

  if (srpp->use_tgz > 0) {
    snprintf(working_dir, sizeof(working_dir), "%s/%s", check_dir, tgzdir_base);
  } else {
    snprintf(working_dir, sizeof(working_dir), "%s", check_dir);
  }

  if (srpp->use_tgz > 0) {
    if (invoke_tar("/bin/tar", tgz_src, check_dir, report_path) < 0) {
      goto check_failed;
    }
  }

  int is_dos = srgp->is_dos;
  if (tst && tst->is_dos > 0) is_dos = tst->is_dos;
  if (is_dos > 0 && srpp->binary_input <= 0) copy_flag = CONVERT;

  if (user_input_mode) {
    /* write the provided data as input */
    if (generic_write_file(inp_data, inp_size, 0, check_dir, srpp->input_file, "") < 0) {
      append_msg_to_log(check_out_path, "failed to write test file to %s/%s",
                        check_dir, srpp->input_file);
      goto check_failed;
    }

    snprintf(input_path, sizeof(input_path), "%s/%s",
             check_dir, srpp->input_file);

    if (srpp->test_checker_cmd && *srpp->test_checker_cmd) {
      snprintf(test_checker_out_path, sizeof(test_checker_out_path),
               "%s/testcheckout_%d.txt",
               global->run_work_dir, cur_test);

      int r = invoke_test_checker_cmd(srp, check_dir, input_path, test_checker_out_path, state->exec_user_serial);
      if (r == RUN_CHECK_FAILED) {
        status = RUN_CHECK_FAILED;
        goto check_failed;
      }
      read_run_test_file(srgp, &cur_info->test_checker, test_checker_out_path, utf8_mode);
      if (r != 0) {
        status = r;
        goto cleanup;
      }
    }
  } else {
    /* copy the test */
    mirror_file(agent, test_src, sizeof(test_src), mirror_dir);
    if (generic_copy_file(0, NULL, test_src, "", copy_flag, check_dir, srpp->input_file, "") < 0) {
      append_msg_to_log(check_out_path, "failed to copy test file %s -> %s/%s",
                        test_src, check_dir, srpp->input_file);
      goto check_failed;
    }
  }

  if (tst && tst->error_file && tst->error_file[0]) {
    snprintf(error_file, sizeof(error_file), "%s", tst->error_file);
  } else {
    snprintf(error_file, sizeof(error_file), "%s", "error");
  }

  snprintf(input_path, sizeof(input_path), "%s/%s", check_dir, srpp->input_file);
  snprintf(output_path, sizeof(output_path), "%s/%s", check_dir, srpp->output_file);
  snprintf(error_path, sizeof(error_path), "%s/%s", check_dir, error_file);

  if (srpp->init_cmd && srpp->init_cmd[0]) {
    status = invoke_init_cmd(srp, "start", test_src, corr_src,
                             info_src, working_dir, check_out_path,
                             &tstinfo, src_path, cur_test,
                             state->exec_user_serial,
                             test_random_value);
    if (status != 0) {
      append_msg_to_log(check_out_path, "init_cmd failed to start with code 0");
      status = RUN_CHECK_FAILED;
      goto check_failed;
    }
    init_cmd_started = 1;
  }

  if (interactor_cmd) {
    snprintf(output_path, sizeof(output_path), "%s/%s", global->run_work_dir, srpp->output_file);
    if (srpp->enable_control_socket > 0) {
      if (socketpair(PF_UNIX, SOCK_STREAM, 0, cfd) < 0) {
        append_msg_to_log(check_out_path, "socketpair failed: %s", os_ErrorMsg());
        status = RUN_CHECK_FAILED;
        goto check_failed;
      }
    }
  }

#ifndef __WIN32__
  if (interactor_cmd) {
    if (pipe(pfd1) < 0) {
      append_msg_to_log(check_out_path, "pipe() failed: %s", os_ErrorMsg());
      goto check_failed;
    }
    fcntl(pfd1[0], F_SETFD, FD_CLOEXEC);
    fcntl(pfd1[1], F_SETFD, FD_CLOEXEC);
    if (pipe(pfd2) < 0) {
      append_msg_to_log(check_out_path, "pipe() failed: %s", os_ErrorMsg());
      goto check_failed;
    }
    fcntl(pfd2[0], F_SETFD, FD_CLOEXEC);
    fcntl(pfd2[1], F_SETFD, FD_CLOEXEC);
  }
#endif

  tsk = task_New();
  start_msg_f = open_memstream(&start_msg_s, &start_msg_z);
  fprintf(start_msg_f, "starting:");
  if (start_cmd_arg[0]) {
    fprintf(start_msg_f, " %s", start_cmd_arg);
    start_msg_need_env = 1;
    task_AddArg(tsk, start_cmd_arg);
  }
  if (tst && tst->start_cmd && tst->start_cmd[0]) {
    if (srgp->enable_container > 0) {
      const char *remapped_path = remap_start_cmd_for_container(tst->start_cmd);
      fprintf(start_msg_f, " %s", remapped_path);
      task_AddArg(tsk, remapped_path);
    } else if (remaps) {
      unsigned char *new_cmd = remap_command(tst->start_cmd, remaps);
      fprintf(start_msg_f, " %s", new_cmd);
      task_AddArg(tsk, new_cmd);
      free(new_cmd);
    } else {
      fprintf(start_msg_f, " %s", tst->start_cmd);
      task_AddArg(tsk, tst->start_cmd);
    }
    start_msg_need_env = 1;
  }
  fprintf(start_msg_f, " %s", arg0_path);
  fclose(start_msg_f); start_msg_f = NULL;
  info("%s", start_msg_s);
  xfree(start_msg_s); start_msg_s = NULL; start_msg_z = 0;
  if (start_msg_need_env) {
    if (srpp->input_file && srpp->input_file[0]) {
      task_SetEnv(tsk, "INPUT_FILE", srpp->input_file);
    }
    if (srpp->output_file && srpp->output_file[0]) {
      task_SetEnv(tsk, "OUTPUT_FILE", srpp->output_file);
    }
  }

  /*
  if (tst && tst->start_cmd && tst->start_cmd[0]) {
    info("starting: %s %s", tst->start_cmd, arg0_path);
    task_AddArg(tsk, tst->start_cmd);
    if (srpp->input_file && srpp->input_file[0]) {
      task_SetEnv(tsk, "INPUT_FILE", srpp->input_file);
    }
    if (srpp->output_file && srpp->output_file[0]) {
      task_SetEnv(tsk, "OUTPUT_FILE", srpp->output_file);
    }
  } else if (start_cmd_arg[0]) {
    info("starting: %s %s", start_cmd_arg, arg0_path);
    task_AddArg(tsk, start_cmd_arg);
    if (srpp->input_file && srpp->input_file[0]) {
      task_SetEnv(tsk, "INPUT_FILE", srpp->input_file);
    }
    if (srpp->output_file && srpp->output_file[0]) {
      task_SetEnv(tsk, "OUTPUT_FILE", srpp->output_file);
    }
  } else {
    info("starting: %s", arg0_path);
  }
  */

  if (interpreter_cnt > 0) {
    task_pnAddArgs(tsk, interpreter_cnt, (char**) interpreter_args);
  }

  if (tstinfo.program_name && *tstinfo.program_name) {
    task_AddArg(tsk, tstinfo.program_name);
    task_SetPath(tsk, arg0_path);
  } else {
    task_AddArg(tsk, arg0_path);
    task_SetPathAsArg0(tsk);
  }

  if (srpp->use_info > 0 && tstinfo.cmd.u >= 1) {
    task_pnAddArgs(tsk, tstinfo.cmd.u, (char**) tstinfo.cmd.v);
  }
  /*
  if (tstinfo.working_dir) {
    task_SetWorkingDir(tsk, tstinfo.working_dir);
  } else {
    task_SetWorkingDir(tsk, working_dir);
  }
  */
  task_SetWorkingDir(tsk, working_dir);
  if (srgp->suid_run > 0 && srpp->enable_kill_all > 0) {
    task_EnableKillAll(tsk);
  }
  if (srpp->enable_process_group > 0) {
    task_EnableProcessGroup(tsk);
#ifndef __WIN32__
    snprintf(mem_limit_buf, sizeof(mem_limit_buf), "%d", getpid());
    task_SetEnv(tsk, "EJ_SUPER_RUN_PID", mem_limit_buf);
#endif
  }
  if (srpp->use_tgz) {
    task_EnableSubdirMode(tsk);
  }

  if (interactor_cmd) {
    task_SetRedir(tsk, 0, TSR_DUP, pfd2[0]);
    task_SetRedir(tsk, 1, TSR_DUP, pfd1[1]);
    if (tst->ignore_stderr > 0) {
      task_SetRedir(tsk, 2, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
    } else {
      task_SetRedir(tsk, 2, TSR_FILE, error_path, TSK_REWRITE, TSK_FULL_RW);
    }
  } else if (tst && tst->no_redirect > 0) {
    task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
    task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
    task_SetRedir(tsk, 2, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
    touch_file(output_path);
  } else {
    if (srpp->use_stdin > 0) {
      task_SetRedir(tsk, 0, TSR_FILE, input_path, TSK_READ);
    } else {
      task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ);
    }
    if (srpp->use_stdout > 0 && srpp->use_info > 0 && tstinfo.check_stderr) {
      task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
      task_SetRedir(tsk, 2, TSR_FILE, output_path, TSK_REWRITE, TSK_FULL_RW);
      touch_file(output_path);
    } else {
      if (srpp->use_stdout > 0) {
        task_SetRedir(tsk, 1, TSR_FILE, output_path, TSK_REWRITE, TSK_FULL_RW);
        touch_file(output_path);
      } else {
        task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
        if (srgp->secure_run > 0 || srpp->use_tgz > 0) {
          touch_file(output_path);
        }
      }
      if (tst && tst->ignore_stderr > 0 && disable_stderr <= 0) {
        task_SetRedir(tsk, 2, TSR_FILE, "/dev/null", TSK_WRITE, TSK_FULL_RW);
      } else {
        task_SetRedir(tsk, 2, TSR_FILE, error_path, TSK_REWRITE, TSK_FULL_RW);
        touch_file(error_path);
      }
    }
  }

  int ejudge_env_flag = (tst && tst->enable_ejudge_env > 0) || (srgp->enable_ejudge_env > 0);

  if (tst && tst->clear_env > 0) task_ClearEnv(tsk);
  setup_environment(tsk, start_env, tstinfo.env.u, tstinfo.env.v, ejudge_env_flag);
  if (ejudge_env_flag) {
    setup_ejudge_environment(tsk, srp, cur_test,
                             -1 /* test_max_score */,
                             0 /* output_only */,
                             src_path,
                             state->exec_user_serial,
                             test_random_value);
    if (srpp->input_file && srpp->input_file[0]) {
      task_SetEnv(tsk, "INPUT_FILE", srpp->input_file);
    }
    if (srpp->output_file && srpp->output_file[0]) {
      task_SetEnv(tsk, "OUTPUT_FILE", srpp->output_file);
    }
  }
  if (srgp->run_env_file) {
    read_env_file(tsk, srgp->run_env_file);
  }

  if (tstinfo.time_limit_ms > 0) {
    task_SetMaxTimeMillis(tsk, tstinfo.time_limit_ms);
    *p_report_time_limit_ms = tstinfo.time_limit_ms;
  } else if (time_limit_value_ms > 0) {
    if ((time_limit_value_ms % 1000)) {
      task_SetMaxTimeMillis(tsk, time_limit_value_ms);
    } else {
      task_SetMaxTime(tsk, time_limit_value_ms / 1000);
    }
    *p_report_time_limit_ms = time_limit_value_ms;
  }

  if (tstinfo.real_time_limit_ms > 0) {
    task_SetMaxRealTimeMillis(tsk, tstinfo.real_time_limit_ms);
    *p_report_real_time_limit_ms = tstinfo.real_time_limit_ms;
  } else if (srpp->real_time_limit_ms > 0) {
    task_SetMaxRealTimeMillis(tsk, srpp->real_time_limit_ms);
    *p_report_real_time_limit_ms = srpp->real_time_limit_ms;
  }

  if (tst && tst->kill_signal && tst->kill_signal[0]) task_SetKillSignal(tsk, tst->kill_signal);
  if (tst && tst->no_core_dump > 0) task_DisableCoreDump(tsk);

  long long max_vm_size = -1LL;
  long long max_stack_size = -1LL;
  long long max_rss_size = -1LL;
  long long max_file_size = -1LL;
  if (srpp->use_info > 0) {
    if (tstinfo.max_vm_size >= 0) max_vm_size = tstinfo.max_vm_size;
    if (tstinfo.max_stack_size >= 0) max_stack_size = tstinfo.max_stack_size;
    if (tstinfo.max_rss_size >= 0) max_rss_size = tstinfo.max_rss_size;
    if (tstinfo.max_file_size >= 0) max_file_size = tstinfo.max_file_size;
  }
  if (max_vm_size < 0 && srpp->max_vm_size > 0) max_vm_size = srpp->max_vm_size;
  if (max_stack_size < 0 && srpp->max_stack_size > 0) max_stack_size = srpp->max_stack_size;
  if (max_rss_size < 0 && srpp->max_rss_size > 0) max_rss_size = srpp->max_rss_size;
  if (max_file_size < 0 && srpp->max_file_size > 0) max_file_size = srpp->max_file_size;

  if (!tst || tst->memory_limit_type_val < 0) {
    if (max_stack_size > 0) {
      task_SetStackSize(tsk, max_stack_size);
    } else if (srgp->enable_max_stack_size > 0 && max_vm_size > 0) {
      task_SetStackSize(tsk, max_vm_size);
    }
    if (srpp->max_data_size > 0)
      task_SetDataSize(tsk, srpp->max_data_size);
    if (max_vm_size > 0)
      task_SetVMSize(tsk, max_vm_size);
    if (max_rss_size > 0)
      task_SetRSSSize(tsk, max_rss_size);
    if (srpp->disable_vm_size_limit > 0)
      task_DisableVMSizeLimit(tsk);
  } else {
    switch (tst->memory_limit_type_val) {
    case MEMLIMIT_TYPE_DEFAULT:
    case MEMLIMIT_TYPE_DOTNET:  // don't know how to setup limits
    case MEMLIMIT_TYPE_MONO:    // no reasonable limit support
      if (max_stack_size > 0) {
        task_SetStackSize(tsk, max_stack_size);
      } else if (srgp->enable_max_stack_size > 0 && max_vm_size > 0) {
        task_SetStackSize(tsk, max_vm_size);
      }
      if (srpp->max_data_size > 0)
        task_SetDataSize(tsk, srpp->max_data_size);
      if (max_vm_size > 0)
        task_SetVMSize(tsk, max_vm_size);
      if (max_rss_size > 0)
        task_SetRSSSize(tsk, max_rss_size);
      if (tst->enable_memory_limit_error > 0 && srgp->enable_memory_limit_error > 0 && srgp->secure_run > 0) {
        task_EnableMemoryLimitError(tsk);
      }
      if (srpp->disable_vm_size_limit > 0)
        task_DisableVMSizeLimit(tsk);
      break;
    case MEMLIMIT_TYPE_JAVA:
      make_java_limits(mem_limit_buf, sizeof(mem_limit_buf), max_vm_size, max_stack_size);
      if (mem_limit_buf[0]) {
        task_PutEnv(tsk, mem_limit_buf);
      }
      break;
    case MEMLIMIT_TYPE_DOS:
      break;
      /*
    case MEMLIMIT_TYPE_MONO:
      make_mono_limits(mem_limit_buf, sizeof(mem_limit_buf), max_vm_size, max_stack_size);
      if (mem_limit_buf[0]) {
        task_PutEnv(tsk, mem_limit_buf);
      }
      break;
      */
    case MEMLIMIT_TYPE_VALGRIND:
      //???
      break;
    default:
      abort();
    }
  }

  if (tst && srgp->enable_container > 0) {
    task_SetSuidHelperDir(tsk, EJUDGE_SERVER_BIN_PATH);
    task_EnableContainer(tsk);
    if (srpp->container_options && srpp->container_options[0])
      task_AppendContainerOptions(tsk, srpp->container_options);
    if (srgp->lang_container_options && srgp->lang_container_options[0])
      task_AppendContainerOptions(tsk, srgp->lang_container_options);
    if (srgp->lang_short_name && *srgp->lang_short_name)
      task_SetLanguageName(tsk, srgp->lang_short_name);
    if (tst->secure_exec_type_val == SEXEC_TYPE_JAVA) {
      task_PutEnv(tsk, "EJUDGE_JAVA_POLICY=fileio.policy");
    }
  } else if (tst && srgp->suid_run > 0) {
    task_SetSuidHelperDir(tsk, EJUDGE_SERVER_BIN_PATH);
    task_EnableSuidExec(tsk);
    switch (tst->secure_exec_type_val) {
    case SEXEC_TYPE_JAVA:
      task_PutEnv(tsk, "EJUDGE_JAVA_POLICY=fileio.policy");
      break;
    }
  }

  if (tst && tst->secure_exec_type_val > 0 && srgp->secure_run > 0 && srgp->enable_container <= 0) {
    switch (tst->secure_exec_type_val) {
    case SEXEC_TYPE_STATIC:
      if (task_EnableSecureExec(tsk) < 0) {
        err("task_EnableSecureExec() failed");
        append_msg_to_log(check_out_path, "task_EnableSecureExec() failed");
        goto check_failed;
      }
      break;
    case SEXEC_TYPE_DLL:
      task_PutEnv(tsk, "LD_BIND_NOW=1");
      task_FormatEnv(tsk, "LD_PRELOAD", "%s/lang/libdropcaps.so", EJUDGE_SCRIPT_DIR);
      break;
    case SEXEC_TYPE_DLL32:
      task_PutEnv(tsk, "LD_BIND_NOW=1");
      task_FormatEnv(tsk, "LD_PRELOAD", "%s/lang/libdropcaps32.so", EJUDGE_SCRIPT_DIR);
      break;
    case SEXEC_TYPE_JAVA:
      task_PutEnv(tsk, "EJUDGE_JAVA_POLICY=fileio.policy");
      break;
    case SEXEC_TYPE_MONO:
      // nothing secure
      break;
    case SEXEC_TYPE_VALGRIND:
      // nothing secure
      break;
    case SEXEC_TYPE_DOTNET:
      // nothing secure
      break;
    default:
      abort();
    }
  }

  if (tst && tst->secure_exec_type_val == SEXEC_TYPE_JAVA && srgp->secure_run <= 0 && srgp->enable_container <= 0) {
    task_PutEnv(tsk, "EJUDGE_JAVA_POLICY=none");
  }

  if (tst && tst->secure_exec_type_val == SEXEC_TYPE_JAVA && srgp->lang_short_name) {
    task_FormatEnv(tsk, "EJUDGE_JAVA_COMPILER", "%s", srgp->lang_short_name);
  }

  if (tst && tst->enable_memory_limit_error > 0 && srgp->secure_run > 0 && srgp->detect_violations > 0 && srgp->enable_container <= 0) {
    switch (tst->secure_exec_type_val) {
    case SEXEC_TYPE_STATIC:
    case SEXEC_TYPE_DLL:
    case SEXEC_TYPE_DLL32:
      task_EnableSecurityViolationError(tsk);
      break;
    }
  }

#ifdef HAVE_TERMIOS_H
  if (tst && tst->no_redirect > 0 && isatty(0)) {
    /* we need to save terminal state since if the program
     * is killed with SIGKILL, the terminal left in random state
     */
    if (tcgetattr(0, &term_attrs) < 0) {
      err("tcgetattr failed: %s", os_ErrorMsg());
    }
  }
#endif

  task_EnableAllSignals(tsk);

  if (srpp->max_core_size > 0) {
    task_SetMaxCoreSize(tsk, srpp->max_core_size);
  }
  if (max_file_size > 0) {
    task_SetMaxFileSize(tsk, max_file_size);
  }
  if (srpp->use_info > 0 && tstinfo.max_open_file_count >= 0) {
    task_SetMaxOpenFileCount(tsk, tstinfo.max_open_file_count);
  } else if (srpp->max_open_file_count > 0) {
    task_SetMaxOpenFileCount(tsk, srpp->max_open_file_count);
  }
  if (srpp->use_info > 0 && tstinfo.max_process_count >= 0) {
    task_SetMaxProcessCount(tsk, tstinfo.max_process_count);
  } else if (srpp->max_process_count > 0) {
    task_SetMaxProcessCount(tsk, srpp->max_process_count);
  }
  if (srpp->umask && srpp->umask[0]) {
    // FIXME: handle errors
    int umask = strtol(srpp->umask, NULL, 8);
    if (umask >= 0 && umask <= 0777) {
      task_SetUmask(tsk, umask);
    }
  }
  if (srpp->enable_control_socket) {
    task_SetControlSocket(tsk, cfd[0], cfd[1]);
  }
  if (state->exec_user_serial > 0) {
    task_SetUserSerial(tsk, state->exec_user_serial);
  }

  //task_PrintArgs(tsk);

  if (task_Start(tsk) < 0) {
    /* failed to start task */
    cur_info->code = task_ErrorCode(tsk, 0, 0);
    append_msg_to_log(check_out_path, "failed to start %s", exe_path);
    goto check_failed;
  }

  if (cfd[0] >= 0) {
    close(cfd[0]); cfd[0] = -1;
  }

#ifndef __WIN32__
  if (interactor_cmd) {
    tsk_int = invoke_interactor(interactor_cmd, test_src, output_path, corr_src, info_src,
                                working_dir, check_out_path,
                                &tstinfo, pfd1[0], pfd2[1], cfd[1], task_GetPid(tsk), srp, cur_test, src_path,
                                state->exec_user_serial,
                                test_random_value);
    if (!tsk_int) {
      append_msg_to_log(check_out_path, "interactor failed to start");
    }
  }
#endif

  if (pfd1[0] >= 0) close(pfd1[0]);
  if (pfd1[1] >= 0) close(pfd1[1]);
  if (pfd2[0] >= 0) close(pfd2[0]);
  if (pfd2[1] >= 0) close(pfd2[1]);
  pfd1[0] = pfd1[1] = pfd2[0] = pfd2[1] = -1;

  if (cfd[1] >= 0) {
    close(cfd[1]); cfd[1] = -1;
  }

  task_NewWait(tsk);

  info("CPU time = %ld, real time = %ld, used_vm_size = %ld",
       (long) task_GetRunningTime(tsk), (long) task_GetRealTime(tsk),
       (long) task_GetMemoryUsed(tsk));

  if (error_code[0]) {
    error_code_value = read_error_code(error_code);
  }

  /* restore the terminal state */
#ifdef HAVE_TERMIOS_H
  if (tst && tst->no_redirect > 0 && isatty(0)) {
    if (tcsetattr(0, TCSADRAIN, &term_attrs) < 0)
      err("tcsetattr failed: %s", os_ErrorMsg());
  }
#endif

  // postpone "Check failed" failure on interactor start up
#ifndef __WIN32__
  if (interactor_cmd && !tsk_int) {
    goto check_failed;
  }
#endif

  if (task_WasCheckFailed(tsk)) {
    append_msg_to_log(check_out_path, "%s", task_GetErrorMessage(tsk));
    goto check_failed;
  } else if (srgp->enable_container > 0) {
    if (task_GetOrphanProcessCount(tsk) > 0) {
      append_msg_to_log(check_out_path, "There exist processes belonging to the 'ejexec' user\n");
      pg_not_empty = 1;
    }
  } else if (srgp->suid_run > 0 && srpp->enable_kill_all > 0 && task_TryAnyProcess(tsk) > 0) {
    append_msg_to_log(check_out_path,
                      "There exist processes belonging to the 'ejexec' user\n");
    pg_not_empty = 1;
    task_KillAllProcesses(tsk);
  } else if (srpp->enable_process_group > 0 && task_TryProcessGroup(tsk) >= 0) {
    // there exist some processes beloging to the process group
    append_msg_to_log(check_out_path,
                      "There exist processes belonging to the process group of the program being tested\n");
    pg_not_empty = 1;
    task_KillProcessGroup(tsk);
  }

  if (tsk_int) task_Wait(tsk_int);

  /* set normal permissions for the working directory */
  make_writable(check_dir);
  /* make the output file readable */
  if (chmod(output_path, 0600) < 0) {
    err("chmod failed: %s", os_ErrorMsg());
  }

  /* fill test report structure */
  cur_info->times = task_GetRunningTime(tsk);
  *p_has_real_time = 1;
  cur_info->real_time = task_GetRealTime(tsk);
  cur_info->max_memory_used = task_GetMemoryUsed(tsk);
  if (cur_info->max_memory_used > 0) *p_has_max_memory_used = 1;
  cur_info->program_stats_str = get_process_stats_str(tsk);
  cur_info->max_rss = task_GetMaxRSS(tsk);
  if (cur_info->max_rss > 0) *p_has_max_rss = 1;

  // input file
  if (user_input_mode) {
    struct run_test_file *rtf = &cur_info->input;
    rtf->data = xmalloc(inp_size + 1);
    memcpy(rtf->data, inp_data, inp_size);
    rtf->data[inp_size] = 0;
    rtf->orig_size = inp_size;
    rtf->stored_size = inp_size;
    rtf->is_here = 1;
  } else {
    if (srgp->enable_full_archive > 0) {
      filehash_get(test_src, cur_info->input_digest);
      cur_info->has_input_digest = 1;
    } else {
      read_run_test_file(srgp, &cur_info->input, test_src, utf8_mode);
    }
  }

  // output file
  if (far) {
    file_size = generic_file_size(0, output_path, 0);
    if (file_size >= 0) {
      cur_info->output.is_archived = 1;
      snprintf(arch_entry_name, sizeof(arch_entry_name), "%06d.o", cur_test);
      full_archive_append_file(far, arch_entry_name, 0, output_path);
    }
  } else {
    read_run_test_file(srgp, &cur_info->output, output_path, utf8_mode);
  }

  // error file
  if (error_path[0]) {
    if (far) {
      file_size = generic_file_size(0, error_path, 0);
      if (file_size >= 0) {
        cur_info->error.is_archived = 1;
        snprintf(arch_entry_name, sizeof(arch_entry_name), "%06d.e", cur_test);
        full_archive_append_file(far, arch_entry_name, 0, error_path);
      }
    } else {
      read_run_test_file(srgp, &cur_info->error, error_path, utf8_mode);
    }
  }

  // command-line arguments and environment
  if (srpp->use_info > 0) {
    if (srgp->enable_full_archive > 0) {
      filehash_get(info_src, cur_info->info_digest);
      cur_info->has_info_digest = 1;
    }
    cur_info->args = report_args_and_env(&tstinfo);
    if (tstinfo.comment) {
      cur_info->comment = xstrdup(tstinfo.comment);
    }
    if (tstinfo.team_comment) {
      cur_info->team_comment = xstrdup(tstinfo.team_comment);
    }
  }

  if (tsk_int) {
    info("interactor CPU time = %ld, real time = %ld, used_vm_size = %ld",
         (long) task_GetRunningTime(tsk_int), (long) task_GetRealTime(tsk_int),
         (long) task_GetMemoryUsed(tsk_int));
    cur_info->interactor_stats_str = get_process_stats_str(tsk_int);
    if (task_IsTimeout(tsk_int)) {
      append_msg_to_log(check_out_path, "interactor timeout");
      err("interactor timeout");
      goto check_failed;
    }
    if (task_Status(tsk_int) == TSK_SIGNALED) {
      int signo = task_TermSignal(tsk_int);
      task_Log(tsk_int, 0, LOG_INFO);
      append_msg_to_log(check_out_path, "interactor terminated with signal %d (%s)", signo, os_GetSignalString(signo));
      goto check_failed;
    }
    int exitcode = task_ExitCode(tsk_int);
    if (exitcode == 1) exitcode = RUN_WRONG_ANSWER_ERR;
    if (exitcode == 2) exitcode = RUN_PRESENTATION_ERR;
    if (exitcode == RUN_PRESENTATION_ERR && srpp->disable_pe > 0) {
      exitcode = RUN_WRONG_ANSWER_ERR;
    }
    if (exitcode != RUN_OK && exitcode != RUN_PRESENTATION_ERR && exitcode != RUN_WRONG_ANSWER_ERR) {
      append_msg_to_log(check_out_path, "interactor exited with code %d", exitcode);
      goto check_failed;
    }
  }

  // debug
  if (cur_info->times > 1000000 || cur_info->times < 0) {
    append_msg_to_log(check_out_path, "bogus running time %ld", cur_info->times);
    goto check_failed;
  }

  if (task_IsRealTimeout(tsk)) {
    if (srpp->wtl_is_cf > 0) {
      goto check_failed;
    } else if (srpp->disable_wtl > 0) {
      status = RUN_TIME_LIMIT_ERR;
    } else {
      status = RUN_WALL_TIME_LIMIT_ERR;
    }
    if (tsk_int) goto read_checker_output;
    goto cleanup;
  }
  if (task_IsTimeout(tsk)) {
    status = RUN_TIME_LIMIT_ERR;
    if (tsk_int) goto read_checker_output;
    goto cleanup;
  }

  if (tst && tst->enable_memory_limit_error > 0 && srgp->enable_memory_limit_error > 0
      && srgp->secure_run > 0 && task_IsMemoryLimit(tsk)) {
    status = RUN_MEM_LIMIT_ERR;
    if (tsk_int) goto read_checker_output;
    goto cleanup;
  }

  if (tst && tst->memory_limit_type_val == MEMLIMIT_TYPE_JAVA && srgp->enable_memory_limit_error > 0
      && task_IsAbnormal(tsk) && is_java_memory_limit(cur_info->error.data, cur_info->error.orig_size)) {
    status = RUN_MEM_LIMIT_ERR;
    if (tsk_int) goto read_checker_output;
    goto cleanup;
  }

  if (tst && tst->enable_memory_limit_error > 0 && srgp->detect_violations > 0
      && srgp->secure_run > 0 && task_IsSecurityViolation(tsk)) {
    status = RUN_SECURITY_ERR;
    if (tsk_int) goto read_checker_output;
    goto cleanup;
  }

  if (task_GetIPCObjectCount(tsk) > 0) {
    status = RUN_SECURITY_ERR;
    append_msg_to_log(check_out_path, "%s", task_GetErrorMessage(tsk));
    goto read_checker_output;
  }

  // terminated with a signal
  if (task_Status(tsk) == TSK_SIGNALED) {
    int ignore_term_signal = 0;
    if (srpp->use_info > 0 && tstinfo.ignore_term_signal > 0) {
      ignore_term_signal = 1;
    } else {
      ignore_term_signal = srpp->ignore_term_signal;
    }
    if (ignore_term_signal <= 0) {
      cur_info->code = 256; /* FIXME: magic */
      cur_info->termsig = task_TermSignal(tsk);
      status = RUN_RUN_TIME_ERR;
      if (tsk_int) goto read_checker_output;
      goto cleanup;
    } else {
      // save info, but proceed with testing
      cur_info->code = 256;
      cur_info->termsig = task_TermSignal(tsk);
    }
  }

  if (error_code[0]) {
    cur_info->code = error_code_value;
  } else {
    cur_info->code = task_ExitCode(tsk);
  }

  if (srpp->use_info > 0 && tstinfo.exit_code > 0) {
    if (cur_info->code != tstinfo.exit_code) {
      status = RUN_WRONG_ANSWER_ERR;
      if (tsk_int) goto read_checker_output;
      goto cleanup;
    }
  } else {
    int ignore_exit_code = -1;
    if (srpp->use_info > 0 && tstinfo.ignore_exit_code >= 0) {
      ignore_exit_code = tstinfo.ignore_exit_code;
    } else {
      ignore_exit_code = srpp->ignore_exit_code;
    }
    if (ignore_exit_code <= 0 && cur_info->code != 0) {
      status = RUN_RUN_TIME_ERR;
      if (tsk_int) goto read_checker_output;
      goto cleanup;
    }
  }

  if (pg_not_empty) {
    status = RUN_SYNC_ERR;
    goto read_checker_output;
  }

  task_Delete(tsk); tsk = NULL;

  if (tsk_int) {
    int exitcode = task_ExitCode(tsk_int);
    if (exitcode == 1) exitcode = RUN_WRONG_ANSWER_ERR;
    if (exitcode == 2) exitcode = RUN_PRESENTATION_ERR;
    if (!exitcode) {
    } else if (exitcode == RUN_PRESENTATION_ERR || exitcode == RUN_WRONG_ANSWER_ERR) {
      if (exitcode == RUN_PRESENTATION_ERR && srpp->disable_pe > 0) {
        exitcode = RUN_WRONG_ANSWER_ERR;
      }
      status = exitcode;
      goto read_checker_output;
    } else {
      goto check_failed;
    }

    task_Delete(tsk_int); tsk_int = NULL;
  }

run_checker:;
  if (user_input_mode) {
    status = RUN_OK;
    goto cleanup;
  }

  if (disable_stderr > 0 && cur_info->error.orig_size > 0) {
    append_msg_to_log(check_out_path, "non-empty output to stderr");
    if (srpp->disable_pe > 0) {
      status = RUN_WRONG_ANSWER_ERR;
    } else {
      status = RUN_PRESENTATION_ERR;
    }
    goto read_checker_output;
  }

  file_size = -1;
  if (srpp->use_corr > 0) {
    if (srgp->enable_full_archive > 0) {
      filehash_get(corr_src, cur_info->correct_digest);
      cur_info->has_correct_digest = 1;
    } else {
      read_run_test_file(srgp, &cur_info->correct, corr_src, utf8_mode);
    }
  }

  if (!output_path_to_check) {
    output_path_to_check = srpp->output_file;
    if (interactor_cmd) {
      output_path_to_check = output_path;
    }
  }

  if (tstinfo.check_cmd && tstinfo.check_cmd[0]) {
    if (os_IsAbsolutePath(tstinfo.check_cmd)) {
      snprintf(local_check_cmd, sizeof(local_check_cmd), "%s", tstinfo.check_cmd);
    } else {
      snprintf(local_check_cmd, sizeof(local_check_cmd), "%s/%s", srpp->problem_dir, tstinfo.check_cmd);
    }
    mirror_file(agent, local_check_cmd, sizeof(local_check_cmd), mirror_dir);
    check_cmd = local_check_cmd;
  }

  status = invoke_checker(srp, cur_test, cur_info,
                          check_cmd, test_src, output_path_to_check,
                          corr_src, info_src, tgzdir_src,
                          working_dir, score_out_path, check_out_path,
                          check_dir, &tstinfo, test_score_count, test_score_val,
                          0, src_path,
                          state->exec_user_serial,
                          test_random_value);

  // read the checker output
read_checker_output:;
  if (init_cmd_started) {
    int new_status = invoke_init_cmd(srp, "stop", test_src,
                                     corr_src, info_src, working_dir, check_out_path,
                                     &tstinfo, src_path, cur_test,
                                     state->exec_user_serial,
                                     test_random_value);
    if (!status) status = new_status;
    init_cmd_started = 0;
  }
  if (srgp->clean_up_cmd && srgp->clean_up_cmd[0] && !clean_up_executed) {
    invoke_clean_up_cmd(srp, working_dir, check_out_path,
                        src_path, cur_test, state->exec_user_serial,
                        test_random_value);
    clean_up_executed = 1;
  }

  if (far) {
    file_size = generic_file_size(0, check_out_path, 0);
    if (file_size >= 0) {
      cur_info->chk_out.is_archived = 1;
      snprintf(arch_entry_name, sizeof(arch_entry_name), "%06d.c", cur_test);
      full_archive_append_file(far, arch_entry_name, 0, check_out_path);
    }
  } else {
    read_run_test_file(srgp, &cur_info->chk_out, check_out_path, utf8_mode);
  }

cleanup:;
  if (status != RUN_OK && status != RUN_CHECK_FAILED && srgp->not_ok_is_cf > 0) {
    append_msg_to_log(check_out_path, "Check failed on non-OK result mode enabled");
    status = RUN_CHECK_FAILED;
  }

  if (init_cmd_started) {
    int new_status = invoke_init_cmd(srp, "stop", test_src, corr_src,  info_src, working_dir, check_out_path,
                                     &tstinfo, src_path, cur_test,
                                     state->exec_user_serial,
                                     test_random_value);
    if (!status) status = new_status;
    init_cmd_started = 0;
  }
  if (srgp->clean_up_cmd && srgp->clean_up_cmd[0] && !clean_up_executed) {
    invoke_clean_up_cmd(srp, working_dir, check_out_path,
                        src_path, cur_test, state->exec_user_serial,
                        test_random_value);
    clean_up_executed = 1;
  }

  cur_info->status = status;
  if (pfd1[0] >= 0) close(pfd1[0]);
  if (pfd1[1] >= 0) close(pfd1[1]);
  if (pfd2[0] >= 0) close(pfd2[0]);
  if (pfd2[1] >= 0) close(pfd2[1]);
  if (cfd[0] >= 0) close(cfd[0]);
  if (cfd[1] >= 0) close(cfd[1]);

  if (check_out_path[0]) unlink(check_out_path);
  if (score_out_path[0]) unlink(score_out_path);

  testinfo_free(&tstinfo);
  xfree(eff_inf_text);
  task_Delete(tsk_int);
  task_Delete(tsk);
  if (check_dir[0]) {
    clear_directory(check_dir);
  }
  xfree(interpreter_str);

  return status;

check_failed:
  status = RUN_CHECK_FAILED;
  goto read_checker_output;
}

static void
init_testinfo_vector(struct run_test_info_vector *tv)
{
  if (!tv) return;

  memset(tv, 0, sizeof(*tv));
  tv->reserved = 16;
  XCALLOC(tv->data, tv->reserved);
  tv->size = 1;
}

static void
free_testinfo_vector(struct run_test_info_vector *tv)
{
  if (tv == NULL || tv->size <= 0 || tv->data == NULL) return;

  for (int i = 0; i < tv->size; ++i) {
    struct run_test_info *ti = &tv->data[i];
    xfree(ti->args);
    xfree(ti->comment);
    xfree(ti->team_comment);
    xfree(ti->exit_comment);
    xfree(ti->program_stats_str);
    xfree(ti->interactor_stats_str);
    xfree(ti->checker_stats_str);
    xfree(ti->checker_token);
    xfree(ti->input.data);
    xfree(ti->output.data);
    xfree(ti->correct.data);
    xfree(ti->error.data);
    xfree(ti->chk_out.data);
    xfree(ti->test_checker.data);
  }
  memset(tv->data, 0, sizeof(tv->data[0]) * tv->size);
  xfree(tv->data);
  memset(tv, 0, sizeof(*tv));
}

static int
invoke_prepare_cmd(
        const unsigned char *prepare_cmd,
        const unsigned char *working_dir,
        const unsigned char *exe_name,
        const unsigned char *messages_path,
        const unsigned char *src_path,
        int exec_user_serial)
{
  tpTask tsk = task_New();
  int retval = -1;

  task_AddArg(tsk, prepare_cmd);
  task_SetPathAsArg0(tsk);

  task_AddArg(tsk, exe_name);
  task_SetWorkingDir(tsk, working_dir);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", TSK_READ, 0);
  task_SetRedir(tsk, 1, TSR_FILE, messages_path, TSK_REWRITE, TSK_FULL_RW);
  task_SetRedir(tsk, 2, TSR_DUP, 1);
  task_EnableAllSignals(tsk);

  if (src_path) {
    task_SetEnv(tsk, "EJUDGE_SOURCE_PATH", src_path);
  }
  if (exec_user_serial > 0) {
    char buf[32];
    sprintf(buf, "%d", exec_user_serial);
    task_SetEnv(tsk, "EJUDGE_SUPER_RUN_SERIAL", buf);
  }

  if (task_Start(tsk) < 0) {
    append_msg_to_log(messages_path, "failed to start prepare_cmd %s", prepare_cmd);
    goto cleanup;
  }

  task_Wait(tsk);
  task_Log(tsk, 0, LOG_INFO);
  if (task_IsAbnormal(tsk)) {
    append_msg_to_log(messages_path, "prepare_cmd %s failed", prepare_cmd);
    goto cleanup;
  }

  retval = 0;

cleanup:
  task_Delete(tsk);
  return retval;
}

static int
handle_test_sets(
        const unsigned char *messages_path,
        struct run_test_info_vector *tv,
        int score,
        int test_sets_count,
        struct testset_info *test_sets_val)
{
  int ts, i;
  FILE *msgf = NULL;

  if (test_sets_count <= 0) return score;

  for (ts = 0; ts < test_sets_count; ++ts) {
    struct testset_info *ti = &test_sets_val[ts];

    for (i = 1; i < tv->size; ++i) {
      if (tv->data[i].status == RUN_OK
          && (i > ti->total || !ti->nums[i - 1]))
        break;
    }
    if (i < tv->size) continue;
    for (i = 0; i < ti->total; ++i) {
      if (ti->nums[i]
          && (i >= tv->size - 1 || tv->data[i + 1].status != RUN_OK))
        break;
    }
    if (i < ti->total) continue;

    // set the score
    score = ti->score;
    msgf = fopen(messages_path, "a");
    if (msgf) {
      const unsigned char *sep = "";
      fprintf(msgf, "Test set {");
      for (i = 0; i < ti->total; ++i) {
        if (ti->nums[i]) {
          fprintf(msgf, "%s%d", sep, i + 1);
          sep = ", ";
        }
      }
      fprintf(msgf, " } is scored as %d\n", ti->score);
      fclose(msgf); msgf = NULL;
    }
  }
  return score;
}

static void
play_sound(
        const struct section_global_data *global,
        const unsigned char *messages_path,
        int disable_sound,
        int status,
        int passed_tests,
        int score,
        const unsigned char *user_spelling,
        const unsigned char *problem_spelling)
{
  unsigned char b1[64], b2[64], b3[64];
  tpTask tsk = NULL;

  if (!global->sound_player || !global->sound_player[0] || disable_sound > 0) return;

  if (global->extended_sound > 0) {
    tsk = task_New();
    task_AddArg(tsk, global->sound_player);
    snprintf(b1, sizeof(b1), "%d", status);
    snprintf(b2, sizeof(b2), "%d", passed_tests);
    snprintf(b3, sizeof(b3), "%d", score);
    task_AddArg(tsk, b1);
    task_AddArg(tsk, b2);
    task_AddArg(tsk, user_spelling);
    task_AddArg(tsk, problem_spelling);
    task_AddArg(tsk, b3);
  } else {
    const unsigned char *sound = NULL;
    switch (status) {
    case RUN_TIME_LIMIT_ERR:   sound = global->timelimit_sound;    break;
    case RUN_WALL_TIME_LIMIT_ERR: sound = global->timelimit_sound; break;
    case RUN_RUN_TIME_ERR:     sound = global->runtime_sound;      break;
    case RUN_CHECK_FAILED:     sound = global->internal_sound;     break;
    case RUN_PRESENTATION_ERR: sound = global->presentation_sound; break;
    case RUN_WRONG_ANSWER_ERR: sound = global->wrong_sound;        break;
    case RUN_OK:               sound = global->accept_sound;       break;
    }
    if (sound) {
      tsk = task_New();
      task_AddArg(tsk, global->sound_player);
      task_AddArg(tsk, sound);
    }
  }

  if (!tsk) return;

  task_SetPathAsArg0(tsk);
  if (task_Start(tsk) < 0) {
    append_msg_to_log(messages_path, "failed to start sound player %s", global->sound_player);
    goto cleanup;
  }

  task_Wait(tsk);

cleanup:
  task_Delete(tsk);
  return;
}

static int
check_output_only(
        const struct section_global_data *global,
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        struct AgentClient *agent,
        full_archive_t far,
        const unsigned char *exe_name,
        struct run_test_info_vector *tests,
        const unsigned char *check_cmd,
        const unsigned char *mirror_dir,
        int utf8_mode,
        int exec_user_serial)
{
  int cur_test = 1;
  struct run_test_info *cur_info = NULL;
  int status = RUN_CHECK_FAILED;
  long long file_size = 0;

  unsigned char output_path[PATH_MAX];
  unsigned char score_out_path[PATH_MAX];
  unsigned char check_out_path[PATH_MAX];
  unsigned char arch_entry_name[PATH_MAX];

  unsigned char test_base[PATH_MAX];
  unsigned char corr_base[PATH_MAX];
  unsigned char test_src[PATH_MAX];
  unsigned char corr_src[PATH_MAX];

  const struct super_run_in_global_packet *srgp = srp->global;
  const struct super_run_in_problem_packet *srpp = srp->problem;

  // check_cmd, check_dir, global->run_work_dir
  ASSERT(cur_test == tests->size);

  if (tests->size >= tests->reserved) {
    tests->reserved *= 2;
    if (!tests->reserved) tests->reserved = 32;
    tests->data = (typeof(tests->data)) xrealloc(tests->data, tests->reserved * sizeof(tests->data[0]));
  }
  memset(&tests->data[cur_test], 0, sizeof(tests->data[0]));
  cur_info = &tests->data[cur_test];
  ++tests->size;

  test_base[0] = 0;
  test_src[0] = 0;
  if (srpp->test_pat && srpp->test_pat[0]) {
    snprintf(test_base, sizeof(test_base), srpp->test_pat, cur_test);
    snprintf(test_src, sizeof(test_src), "%s/%s", srpp->test_dir, test_base);
  }
  corr_base[0] = 0;
  corr_src[0] = 0;
  if (srpp->corr_pat && srpp->corr_pat[0]) {
    snprintf(corr_base, sizeof(corr_base), srpp->corr_pat, cur_test);
    snprintf(corr_src, sizeof(corr_src), "%s/%s", srpp->corr_dir, corr_base);
  }
  if (test_src[0]) {
    mirror_file(agent, test_src, sizeof(test_src), mirror_dir);
  }
  if (srpp->use_corr > 0 && corr_src[0]) {
    mirror_file(agent, corr_src, sizeof(corr_src), mirror_dir);
  }

  snprintf(check_out_path, sizeof(check_out_path), "%s/checkout_%d.txt",
           global->run_work_dir, cur_test);
  snprintf(score_out_path, sizeof(score_out_path), "%s/scoreout_%d.txt",
           global->run_work_dir, cur_test);

  // do we need it?
  unlink(check_out_path);
  unlink(score_out_path);

  cur_info->visibility = TV_NORMAL;
  cur_info->user_status = -1;
  cur_info->user_nominal_score = -1;
  cur_info->user_score = -1;

  snprintf(output_path, sizeof(output_path), "%s/%s", global->run_work_dir, exe_name);
  status = invoke_checker(srp, cur_test, cur_info,
                          check_cmd, test_src, output_path,
                          corr_src, NULL, NULL,
                          global->run_work_dir, score_out_path, check_out_path,
                          global->run_work_dir, NULL, 0, NULL, 1, NULL,
                          exec_user_serial, 0);

  cur_info->status = status;
  cur_info->max_score = srpp->full_score;
  if (srgp->separate_user_score > 0) {
    if (srpp->full_user_score >= 0) {
      cur_info->user_nominal_score = srpp->full_user_score;
    } else {
      cur_info->user_nominal_score = srpp->full_score;
    }
  }

  if ((status == RUN_PRESENTATION_ERR || status == RUN_WRONG_ANSWER_ERR)
      && (srgp->scoring_system_val == SCORE_KIROV
          || (srgp->scoring_system_val == SCORE_OLYMPIAD && srgp->accepting_mode <= 0))) {
    status = RUN_PARTIAL;
  }

  // FIXME: scoring checker
  if (status == RUN_OK) {
    if (srpp->variable_full_score > 0) {
      reply_pkt->score = cur_info->score;
    } else {
      reply_pkt->score = srpp->full_score;
    }
    reply_pkt->failed_test = 2;
    reply_pkt->tests_passed = 1;
  } else {
    reply_pkt->score = cur_info->score;
    reply_pkt->failed_test = 1;
    reply_pkt->tests_passed = 0;
  }
  if (srgp->separate_user_score > 0 && cur_info->user_status >= 0) {
    reply_pkt->has_user_score = 1;
    reply_pkt->user_status = cur_info->user_status;
    reply_pkt->user_score = cur_info->user_score;
    reply_pkt->user_tests_passed = cur_info->user_tests_passed;
    if (reply_pkt->user_status == RUN_OK && srpp->variable_full_score <= 0) {
      if (srpp->full_user_score >= 0) {
        reply_pkt->user_score = srpp->full_user_score;
      } else if (srpp->full_score >= 0) {
        reply_pkt->user_score = srpp->full_score;
      }
    }
  } else {
    reply_pkt->has_user_score = 0;
    reply_pkt->user_status = 0;
    reply_pkt->user_score = 0;
    reply_pkt->user_tests_passed = 0;
  }

  // output file
  if (far) {
    file_size = generic_file_size(0, output_path, 0);
    if (file_size >= 0) {
      cur_info->output.is_archived = 1;
      snprintf(arch_entry_name, sizeof(arch_entry_name), "%06d.o", cur_test);
      full_archive_append_file(far, arch_entry_name, 0, output_path);
    }
  } else {
    read_run_test_file(srgp, &cur_info->output, output_path, utf8_mode);
  }

  file_size = -1;
  if (srpp->use_corr > 0) {
    if (srgp->enable_full_archive > 0) {
      filehash_get(corr_src, cur_info->correct_digest);
      cur_info->has_correct_digest = 1;
    } else {
      read_run_test_file(srgp, &cur_info->correct, corr_src, utf8_mode);
    }
  }

  if (far) {
    file_size = generic_file_size(0, check_out_path, 0);
    if (file_size >= 0) {
      cur_info->chk_out.is_archived = 1;
      snprintf(arch_entry_name, sizeof(arch_entry_name), "%06d.c", cur_test);
      full_archive_append_file(far, arch_entry_name, 0, check_out_path);
    }
  } else {
    read_run_test_file(srgp, &cur_info->chk_out, check_out_path, utf8_mode);
  }

  return status;
}

static char **
merge_env(char **env1, char **env2)
{
  if ((!env1 || !env1[0]) && (!env2 || !env2[0])) return NULL;
  if (!env1 || !env1[0]) return sarray_copy(env2);
  if (!env2 || !env2[0]) return sarray_copy(env1);

  int len1 = sarray_len(env1);
  int len2 = sarray_len(env2);
  char **res = NULL;
  XCALLOC(res, len1 + len2 + 1);
  int j = 0;
  for (int i = 0; i < len2; ++i) {
    res[j++] = xstrdup(env2[i]);
  }
  for (int k = 0; k < len1; ++k) {
    unsigned char env_name[1024];
    char *s = strchr(env1[k], '=');
    if (!s) {
      snprintf(env_name, sizeof(env_name), "%s", env1[k]);
    } else {
      snprintf(env_name, sizeof(env_name), "%.*s", (int) (s - env1[k]), env1[k]);
    }
    int envlen = strlen(env_name);
    int i;
    for (i = 0; i < j; ++i) {
      if (!strncmp(env_name, res[i], envlen) && (res[i][envlen] == '=' || res[i][envlen] == '\0'))
        break;
    }
    if (i >= j) {
      res[j++] = xstrdup(env1[k]);
    }
  }

  return res;
}

static char **
merge_env_2(char **env1, char **env2)
{
  if ((!env1 || !env1[0]) && (!env2 || !env2[0])) return NULL;
  if (!env1 || !env1[0]) return sarray_copy(env2);
  if (!env2 || !env2[0]) return env1;

  char **res = merge_env(env1, env2);
  sarray_free(env1);
  return res;
}

static int
is_piped_core_dump(void)
{
  int fd = open("/proc/sys/kernel/core_pattern", O_RDONLY, 0);
  if (fd < 0) return 0;
  char c = 0;
  if (read(fd, &c, sizeof(c)) == sizeof(c) && c == '|') {
    close(fd);
    return 1;
  }
  close(fd);
  return 0;
}

static void
append_skipped_test(
        const struct super_run_in_problem_packet *srpp,
        int cur_test,
        struct run_test_info_vector *tests,
        int open_tests_count,
        const int *open_tests_val,
        int test_score_count,
        const int *test_score_val)
{
  if (tests->size >= tests->reserved) {
    tests->reserved *= 2;
    if (!tests->reserved) tests->reserved = 32;
    tests->data = (typeof(tests->data)) xrealloc(tests->data, tests->reserved * sizeof(tests->data[0]));
  }
  struct run_test_info *cur_info = &tests->data[cur_test];
  memset(cur_info, 0, sizeof(*cur_info));
  ++tests->size;

  cur_info->status = RUN_SKIPPED;
  cur_info->user_status = -1;

  cur_info->visibility = TV_NORMAL;
  if (open_tests_val && cur_test > 0 && cur_test < open_tests_count) {
    cur_info->visibility = open_tests_val[cur_test];
  }

  int test_max_score = -1;
  if (test_score_val && cur_test > 0 && cur_test < test_score_count) {
    test_max_score = test_score_val[cur_test];
  }
  if (test_max_score < 0) {
    test_max_score = srpp->test_score;
  }
  if (test_max_score < 0) test_max_score = 0;
  cur_info->max_score = test_max_score;
}

void
run_tests(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct section_tester_data *tst,
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        struct AgentClient *agent,
        char const *exe_name,
        char const *new_base,
        char *report_path,                /* path to the report */
        char *full_report_path,           /* path to the full output dir */
        const unsigned char *mirror_dir,
        int utf8_mode,
        struct run_listener *listener,
        const unsigned char *hostname,
        const struct remap_spec *remaps,
        int user_input_mode,
        const unsigned char *inp_data,
        size_t inp_size,
        const unsigned char *src_path)
{
  const struct section_global_data *global = state->global;
  const struct super_run_in_global_packet *srgp = srp->global;
  /*const*/ struct super_run_in_problem_packet *srpp = srp->problem;
  const struct super_run_in_tester_packet *srtp = srp->tester;

  full_archive_t far = NULL;

  struct run_test_info_vector tests;
  int cur_test = 0;
  int has_real_time = 0;
  int has_max_memory_used = 0;
  int has_max_rss = 0;
  int status = RUN_CHECK_FAILED;
  int failed_test;
  int total_score = 0;
  int total_max_score = 0;
  int failed_test_count = 0;
  int has_user_score = 0;
  int user_status = -1;
  int user_score = -1;
  int user_tests_passed = -1;
  int user_run_tests = -1;
  int marked_flag = 0;
  int tests_passed = 0;

  unsigned char messages_path[PATH_MAX];
  unsigned char check_dir[PATH_MAX];
  unsigned char check_cmd[PATH_MAX];
  unsigned char b_interactor_cmd[PATH_MAX];
  const unsigned char *interactor_cmd = NULL;
  unsigned char b_test_generator_cmd[PATH_MAX];
  const unsigned char *test_generator_cmd = NULL;

  int *open_tests_val = NULL;
  int open_tests_count = 0;

  int *test_score_val = NULL;
  int test_score_count = 0;

  int *score_tests_val = NULL;

  struct testset_info *test_sets_val = NULL;
  int test_sets_count = 0;

  long long expected_free_space = 0;

  char *valuer_errors = NULL;
  char *valuer_comment = NULL;
  char *valuer_judge_comment = NULL;
  char *additional_comment = NULL;

  long report_time_limit_ms = -1;
  long report_real_time_limit_ms = -1;

  char **merged_start_env = NULL;
  char **start_env = NULL;

  unsigned char *cpu_model = NULL;
  unsigned char *cpu_mhz = NULL;

  // ejudge->valuer pipe
  int evfds[2] = { -1, -1 };
  // valuer->ejudge pipe
  int vefds[2] = { -1, -1 };
  tpTask valuer_tsk = NULL;
  unsigned char valuer_cmt_file[PATH_MAX];
  unsigned char valuer_jcmt_file[PATH_MAX];

  int valuer_score = -1;
  int valuer_marked = -1;
  int valuer_user_status = -1;
  int valuer_user_score = -1;
  int valuer_user_tests_passed = -1;

  const unsigned char *test_dir = srpp->test_dir;
  const unsigned char *corr_dir = srpp->corr_dir;
  const unsigned char *info_dir = srpp->info_dir;
  const unsigned char *tgz_dir = srpp->tgz_dir;
  unsigned char b_test_dir[PATH_MAX];

  valuer_cmt_file[0] = 0;
  valuer_jcmt_file[0] = 0;

  cpu_get_performance_info(&cpu_model, &cpu_mhz);

  init_testinfo_vector(&tests);
  messages_path[0] = 0;

  /*
  if (srpp->max_vm_size == (size_t) -1L) srpp->max_vm_size = 0;
  if (srpp->max_data_size == (size_t) -1L) srpp->max_data_size = 0;
  if (srpp->max_stack_size == (size_t) -1L) srpp->max_stack_size = 0;
  */

  snprintf(messages_path, sizeof(messages_path), "%s/%s", global->run_work_dir, "messages");

  if (is_piped_core_dump()) {
    append_msg_to_log(messages_path,
                      "ATTENTION: core file pattern in /proc/sys/kernel/core_pattern\n"
                      "is set to pipe the core file to a helper program.\n"
                      "This is NOT RECOMMENDED for correct judging.\n"
                      "Please, modify the core_pattern file.\n"
                      "For example, consider disabling abrtd.\n");
  }

  if (tst) {
    merged_start_env = merge_env_2(merged_start_env, tst->start_env);
  }
  if (srtp) {
    merged_start_env = merge_env_2(merged_start_env, srtp->start_env);
  }
  if (srpp) {
    merged_start_env = merge_env_2(merged_start_env, srpp->start_env);
  }
  start_env = merged_start_env;

  report_path[0] = 0;
  pathmake(report_path, global->run_work_dir, "/", "report", NULL);
  full_report_path[0] = 0;
  if (srgp->enable_full_archive > 0) {
#if defined CONF_HAS_LIBZIP
    pathmake(full_report_path, global->run_work_dir, "/", "full_output", ".zip", NULL);
#else
    pathmake(full_report_path, global->run_work_dir, "/", "full_output", NULL);
#endif
    far = full_archive_open_write(full_report_path);
  }

  if (tst && tst->check_dir && tst->check_dir[0]) {
    snprintf(check_dir, sizeof(check_dir), "%s", tst->check_dir);
  } else {
    snprintf(check_dir, sizeof(check_dir), "%s", global->run_check_dir);
  }

  if (srpp->standard_checker && srpp->standard_checker[0]) {
    snprintf(check_cmd, sizeof(check_cmd), "%s/%s",
             global->ejudge_checkers_dir, srpp->standard_checker);
  } else {
    snprintf(check_cmd, sizeof(check_cmd), "%s", srpp->check_cmd);
  }
  if (srpp->checker_extra_files) {
    for (int i = 0; srpp->checker_extra_files[i]; ++i) {
      const char *cef = srpp->checker_extra_files[i];
      unsigned char extra_file[PATH_MAX];
      if (os_IsAbsolutePath(cef)) {
        snprintf(extra_file, sizeof(extra_file), "%s", cef);
      } else {
        unsigned char dirname[PATH_MAX];
        os_rDirName(srpp->check_cmd, dirname, sizeof(dirname));
        snprintf(extra_file, sizeof(extra_file), "%s/%s", dirname, cef);
      }
      mirror_file(agent, extra_file, sizeof(extra_file), mirror_dir);
    }
  }
  mirror_file(agent, check_cmd, sizeof(check_cmd), mirror_dir);

  if ((!srpp->standard_checker || !srpp->standard_checker[0])
      && (!srpp->check_cmd || !srpp->check_cmd[0])) {
    append_msg_to_log(messages_path, "neither 'check_cmd' nor 'standard_checker' is defined");
    goto check_failed;
  }

  if (srpp->interactor_cmd && srpp->interactor_cmd[0]) {
    snprintf(b_interactor_cmd, sizeof(b_interactor_cmd), "%s",
             srpp->interactor_cmd);
    interactor_cmd = b_interactor_cmd;
    mirror_file(agent, b_interactor_cmd, sizeof(b_interactor_cmd), mirror_dir);
  }

  if (srpp->test_generator_cmd && srpp->test_generator_cmd[0]) {
    snprintf(b_test_generator_cmd, sizeof(b_test_generator_cmd), "%s",
             srpp->test_generator_cmd);
    test_generator_cmd = b_test_generator_cmd;
    mirror_file(agent, b_test_generator_cmd, sizeof(b_test_generator_cmd),
                mirror_dir);
  }

  if (srpp->type_val) {
    status = check_output_only(global, srp, reply_pkt,
                               agent,
                               far, exe_name, &tests, check_cmd,
                               mirror_dir,
                               utf8_mode,
                               state->exec_user_serial);
    has_user_score = reply_pkt->has_user_score;
    if (has_user_score) {
      user_status = reply_pkt->user_status;
      user_score = reply_pkt->user_score;
      user_tests_passed = reply_pkt->user_tests_passed;
    }
    goto done;
  }

  if (srpp->open_tests && srpp->open_tests[0]) {
    if (prepare_parse_open_tests(stderr, srpp->open_tests, &open_tests_val, &open_tests_count) < 0) {
      append_msg_to_log(messages_path, "failed to parse open_tests = '%s'", srpp->open_tests);
      goto check_failed;
    }
  }

  if (srpp->test_score_list && srpp->test_score_list[0]) {
    if (prepare_parse_test_score_list(stderr, srpp->test_score_list, &test_score_val, &test_score_count) < 0) {
      append_msg_to_log(messages_path, "failed to parse test_score_list = '%s'", srpp->test_score_list);
      goto check_failed;
    }
  }

  if (srpp->test_sets && srpp->test_sets[0]) {
    if (prepare_parse_testsets(srpp->test_sets, &test_sets_count, &test_sets_val) < 0) {
      append_msg_to_log(messages_path, "failed to parse test_sets");
      goto check_failed;
    }
  }

  if (srpp->score_tests && srpp->score_tests[0]) {
    if (!(score_tests_val = prepare_parse_score_tests(srpp->score_tests, srpp->full_score))) {
      append_msg_to_log(messages_path, "failed to parse score_tests = '%s'", srpp->score_tests);
      goto check_failed;
    }
  }

  if (srpp->max_vm_size > 0 && srpp->max_vm_size != (size_t) srpp->max_vm_size) {
    unsigned char sz_buf[64];
    append_msg_to_log(messages_path, "max_vm_size = %s is too big for this platform",
                      ej_size64_t_to_size(sz_buf, sizeof(sz_buf), srpp->max_vm_size));
    goto check_failed;
  }
  if (srpp->max_stack_size > 0 && srpp->max_stack_size != (size_t) srpp->max_stack_size) {
    unsigned char sz_buf[64];
    append_msg_to_log(messages_path, "max_stack_size = %s is too big for this platform",
                      ej_size64_t_to_size(sz_buf, sizeof(sz_buf), srpp->max_stack_size));
    goto check_failed;
  }
  if (srpp->max_rss_size > 0 && srpp->max_rss_size != (size_t) srpp->max_rss_size) {
    unsigned char sz_buf[64];
    append_msg_to_log(messages_path, "max_rss_size = %s is too big for this platform",
                      ej_size64_t_to_size(sz_buf, sizeof(sz_buf), srpp->max_rss_size));
    goto check_failed;
  }
  if (srpp->max_file_size > 0 && srpp->max_file_size != (size_t) srpp->max_file_size) {
    unsigned char sz_buf[64];
    append_msg_to_log(messages_path, "max_file_size = %s is too big for this platform",
                      ej_size64_t_to_size(sz_buf, sizeof(sz_buf), srpp->max_file_size));
    goto check_failed;
  }

  if (test_generator_cmd && test_generator_cmd[0]) {
    int r = snprintf(b_test_dir, sizeof(b_test_dir), "%s/tests",
                     global->run_work_dir);
    if (r >= (int) sizeof(b_test_dir)) {
      append_msg_to_log(messages_path, "test_dir path too long");
      goto check_failed;
    }
    if (mkdir(b_test_dir, 0700) < 0) {
      append_msg_to_log(messages_path, "mkdir '%s' failed: %s",
                        b_test_dir, strerror(errno));
      goto check_failed;
    }
    r = invoke_test_generator_cmd(srp, test_generator_cmd,
                                  b_test_dir, src_path, messages_path,
                                  state->exec_user_serial);
    if (r != 0) {
      append_msg_to_log(messages_path, "test generator failed");
      goto check_failed;
    }
    test_dir = b_test_dir;
    corr_dir = b_test_dir;
    info_dir = b_test_dir;
    tgz_dir = b_test_dir;
  }

  if (!srpp->type_val && tst && tst->prepare_cmd && tst->prepare_cmd[0]) {
    if (invoke_prepare_cmd(tst->prepare_cmd, global->run_work_dir, exe_name,
                           messages_path, src_path,
                           state->exec_user_serial) < 0) {
      goto check_failed;
    }
  }

  /* calculate the expected free space in check_dir */
  expected_free_space = get_expected_free_space(check_dir);

#ifndef __WIN32__
  if (!user_input_mode &&
      srpp->interactive_valuer > 0 && srpp->valuer_cmd && srpp->valuer_cmd[0]
      && srgp->accepting_mode <= 0) {
    if (pipe(evfds) < 0
        || fcntl(evfds[0], F_SETFD, FD_CLOEXEC) < 0
        || fcntl(evfds[1], F_SETFD, FD_CLOEXEC) < 0
        || pipe(vefds) < 0
        || fcntl(vefds[0], F_SETFD, FD_CLOEXEC) < 0
        || fcntl(vefds[1], F_SETFD, FD_CLOEXEC) < 0) {
      append_msg_to_log(messages_path, "pipe() failed: %s", os_ErrorMsg());
      goto check_failed;
    }
    snprintf(valuer_cmt_file, sizeof(valuer_cmt_file), "%s/score_cmt", global->run_work_dir);
    snprintf(valuer_jcmt_file, sizeof(valuer_jcmt_file), "%s/score_jcmt", global->run_work_dir);
    valuer_tsk = start_interactive_valuer(global, srp, agent, mirror_dir,
                                          messages_path,
                                          valuer_cmt_file,
                                          valuer_jcmt_file,
                                          evfds[0], vefds[1],
                                          src_path,
                                          state->exec_user_serial);
    if (!valuer_tsk) {
      append_msg_to_log(messages_path, "failed to start interactive valuer");
      goto check_failed;
    }
    close(evfds[0]); evfds[0] = -1;
    close(vefds[1]); vefds[1] = -1;
    if (ejudge_timed_write(messages_path, evfds[1], "-1\n", 3, 100) < 0) {
      append_msg_to_log(messages_path, "interactive valuer write failed");
      goto check_failed;
    }
  }
#endif

  while (1) {
    ++cur_test;
    if (srgp->scoring_system_val == SCORE_OLYMPIAD
        && srgp->accepting_mode
        && cur_test > srpp->tests_to_accept) break;

    int tl_retry = 0;
    int tl_retry_count = srgp->time_limit_retry_count;
    if (tl_retry_count <= 0) tl_retry_count = 1;

    if (listener && listener->ops && listener->ops->before_test) {
      listener->ops->before_test(listener, cur_test);
    }

    while (1) {
      status = run_one_test(config, state, srp, tst,
                            agent,
                            cur_test, &tests,
                            far, exe_name, report_path, check_cmd,
                            interactor_cmd, start_env,
                            open_tests_count, open_tests_val,
                            test_score_count, test_score_val,
                            expected_free_space,
                            &has_real_time, &has_max_memory_used,
                            &has_max_rss,
                            &report_time_limit_ms, &report_real_time_limit_ms,
                            utf8_mode,
                            mirror_dir, remaps,
                            user_input_mode,
                            inp_data,
                            inp_size,
                            src_path,
                            test_dir,
                            corr_dir,
                            info_dir,
                            tgz_dir);
      if (status != RUN_TIME_LIMIT_ERR && status != RUN_WALL_TIME_LIMIT_ERR)
        break;
      if (++tl_retry >= tl_retry_count) break;
      info("test failed due to TL, do it again");
      --tests.size;
    }

    if (status < 0) {
      status = RUN_OK;
      break;
    }
    if (status == RUN_OK) ++tests_passed;
    if (user_input_mode) {
      break;
    }
    if (status > 0) {
      if (srgp->scoring_system_val == SCORE_ACM) break;
      if (srgp->scoring_system_val == SCORE_MOSCOW) break;
      if (srgp->scoring_system_val == SCORE_OLYMPIAD
          && srgp->accepting_mode && !srpp->accept_partial) break;
      if (srgp->scoring_system_val == SCORE_KIROV && srpp->stop_on_first_fail > 0) {
        while (1) {
          ++cur_test;
          if (!does_test_exist(config, state, srp, srpp->test_dir, cur_test)) break;
          append_skipped_test(srpp, cur_test, &tests,
                              open_tests_count, open_tests_val,
                              test_score_count, test_score_val);
        }
        break;
      }
    }
    if (valuer_tsk) {
      unsigned char buf[1024];
      snprintf(buf, sizeof(buf), "%d %d %ld\n",
               tests.data[cur_test].status, tests.data[cur_test].score,
               tests.data[cur_test].times);
      ssize_t buflen = strlen(buf);
      if (ejudge_timed_write(messages_path, evfds[1], buf, buflen, 100) < 0) {
        append_msg_to_log(messages_path, "interactive valuer write failed");
        goto check_failed;
      }
      buflen = ejudge_timed_fdgets(messages_path, vefds[0], buf, sizeof(buf), 500);
      if (buflen < 0) {
        append_msg_to_log(messages_path, "interactive valuer read failed");
        goto check_failed;
      }
      if (!buflen) {
        append_msg_to_log(messages_path, "interactive valuer unexpected EOF");
        goto check_failed;
      }

      int reply_next_num = 0;
      if (parse_valuer_score(messages_path, buf, buflen, 1, srpp->full_score,
                             srpp->valuer_sets_marked,
                             srgp->separate_user_score,
                             &reply_next_num,
                             &valuer_score,
                             &valuer_marked,
                             &valuer_user_status,
                             &valuer_user_score,
                             &valuer_user_tests_passed) < 0) {
        append_msg_to_log(messages_path, "interactive valuer protocol error");
        goto check_failed;
      }

      if (reply_next_num > 0) {
        if (reply_next_num == 1) continue;
        if (reply_next_num <= cur_test) {
          append_msg_to_log(messages_path, "interactive valuer returned invalid next test number %d", reply_next_num);
          goto check_failed;
        }

        for (++cur_test; cur_test < reply_next_num; ++cur_test) {
          append_skipped_test(srpp, cur_test, &tests,
                              open_tests_count, open_tests_val,
                              test_score_count, test_score_val);
        }
        --cur_test;
        continue;
      }

      close(evfds[1]); evfds[1] = -1;
      task_Wait(valuer_tsk);
      if (task_IsAbnormal(valuer_tsk)) {
        append_msg_to_log(messages_path, "interactive valuer terminated abnormally");
        goto check_failed;
      }
      task_Delete(valuer_tsk); valuer_tsk = NULL;
      close(vefds[0]); vefds[0] = -1;
      append_msg_to_log(messages_path, "testing was completed prematurely because of interactive valuer");
      break;
    }
  }

  if (valuer_tsk) {
    unsigned char buf[1024];
    close(evfds[1]); evfds[1] = -1;
    ssize_t buflen = ejudge_timed_fdgets(messages_path, vefds[0], buf, sizeof(buf), 500);
    if (buflen < 0) {
      append_msg_to_log(messages_path, "interactive valuer read failed");
      goto check_failed;
    }
    if (!buflen) {
      append_msg_to_log(messages_path, "interactive valuer unexpected EOF");
      goto check_failed;
    }
    if (parse_valuer_score(messages_path, buf, buflen, 0, srpp->full_score,
                           srpp->valuer_sets_marked,
                           srgp->separate_user_score,
                           NULL,
                           &valuer_score,
                           &valuer_marked,
                           &valuer_user_status,
                           &valuer_user_score,
                           &valuer_user_tests_passed) < 0) {
      append_msg_to_log(messages_path, "interactive valuer protocol error");
      goto check_failed;
    }
    task_Wait(valuer_tsk);
    if (task_IsAbnormal(valuer_tsk)) {
      append_msg_to_log(messages_path, "interactive valuer terminated abnormally");
      goto check_failed;
    }
    task_Delete(valuer_tsk); valuer_tsk = NULL;
    close(vefds[0]); vefds[0] = -1;
  }

  /* TESTING COMPLETED */
  get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);

  // no tests?
  if (srgp->scoring_system_val == SCORE_OLYMPIAD
      && srgp->accepting_mode > 0 && srpp->tests_to_accept <= 0) {
    // no tests is ok
  } else if (tests.size <= 1) {
    append_msg_to_log(messages_path, "No tests found");
    goto check_failed;
  }

  reply_pkt->tests_passed = tests_passed;

  // check failed?
  for (cur_test = 1; cur_test < tests.size; ++cur_test) {
    if (tests.data[cur_test].status == RUN_CHECK_FAILED) break;
  }
  if (cur_test < tests.size) {
    goto check_failed;
  }

  if (user_input_mode) {
    has_user_score = 0;
    user_status = status;
    user_score = 0;
    user_tests_passed = 0;
    goto done;
  }

  if (srgp->scoring_system_val == SCORE_OLYMPIAD && srgp->accepting_mode) {
    status = RUN_ACCEPTED;
    failed_test = 0;
    for (cur_test = 1; cur_test <= srpp->tests_to_accept; ++cur_test) {
      if (tests.data[cur_test].status != RUN_OK) {
        status = tests.data[cur_test].status;
        failed_test = cur_test;
        break;
      }
    }
    if (srpp->accept_partial) {
      status = RUN_ACCEPTED;
    } else if (srpp->min_tests_to_accept >= 0 && failed_test > srpp->min_tests_to_accept) {
      status = RUN_ACCEPTED;
    }

    reply_pkt->failed_test = failed_test;
    reply_pkt->score = -1;
  } else if (srgp->scoring_system_val == SCORE_KIROV || srgp->scoring_system_val == SCORE_OLYMPIAD) {
    status = RUN_OK;
    total_score = 0;
    failed_test_count = 0;
    for (cur_test = 1; cur_test < tests.size; ++cur_test) {
      if (tests.data[cur_test].status != RUN_OK) {
        status = RUN_PARTIAL;
        ++failed_test_count;
      }
      int this_score = -1;
      if (cur_test < test_score_count) {
        this_score = test_score_val[cur_test];
      }
      if (this_score < 0) {
        this_score = srpp->test_score;
      }
      if (this_score < 0) {
        this_score = 0;
      }
      tests.data[cur_test].max_score = this_score;
      total_max_score += this_score;

      if (srpp->scoring_checker > 0) {
        total_score += tests.data[cur_test].score;
      } else if (tests.data[cur_test].status == RUN_OK) {
        tests.data[cur_test].score = this_score;
        total_score += this_score;
      }
    }

    if (total_max_score > srpp->full_score && (!srpp->valuer_cmd || !srpp->valuer_cmd[0])) {
      append_msg_to_log(messages_path, "Max total score (%d) is greater than full_score",
                        total_max_score, srpp->full_score);
      goto check_failed;
    }

    if (status == RUN_PARTIAL && test_sets_count > 0) {
      total_score = handle_test_sets(messages_path, &tests, total_score,
                                     test_sets_count, test_sets_val);
    }

    if (srpp->variable_full_score <= 0) {
      if (status == RUN_OK) {
        total_score = srpp->full_score;
      } else if (total_score > srpp->full_score) {
        total_score = srpp->full_score;
      }
    } else {
      if (total_score > srpp->full_score) {
        total_score = srpp->full_score;
      }
    }

    // ATTENTION: number of passed test returned is greater than actual by 1,
    // and it is returned in the `failed_test' field
    reply_pkt->failed_test = tests.size - failed_test_count;
    reply_pkt->score = total_score;

    play_sound(global, messages_path, srgp->disable_sound, status,
               tests.size - failed_test_count, total_score,
               srgp->user_spelling, srpp->spelling);
  } else {
    reply_pkt->failed_test = tests.size - 1;
    reply_pkt->score = -1;
    if (srgp->scoring_system_val == SCORE_MOSCOW) {
      reply_pkt->score = srpp->full_score;
      if (status != RUN_OK) {
        if (srpp->scoring_checker > 0) {
          reply_pkt->score = tests.data[tests.size - 1].score;
        } else if (!srpp->valuer_cmd || !srpp->valuer_cmd[0]) {
          if (!score_tests_val) {
            append_msg_to_log(messages_path, "score_tests parameter is undefined");
            goto check_failed;
          }

          int s;
          for (s = 0; score_tests_val[s] && tests.size - 1 > score_tests_val[s]; ++s);
          reply_pkt->score = s;
        }
      }
    }
  }

  if (!user_input_mode && srpp->valuer_cmd && srpp->valuer_cmd[0] && srgp->accepting_mode <= 0) {
    if (srpp->interactive_valuer <= 0
        && reply_pkt->status != RUN_CHECK_FAILED) {
      if (invoke_valuer(global, srp, agent, mirror_dir,
                        tests.size, tests.data,
                        srgp->variant, srpp->full_score,
                        state->exec_user_serial,
                        &total_score, &marked_flag,
                        &user_status, &user_score, &user_tests_passed,
                        &valuer_errors, &valuer_comment,
                        &valuer_judge_comment, src_path) < 0) {
        goto check_failed;
      } else {
        reply_pkt->score = total_score;
        reply_pkt->marked_flag = marked_flag;
      }
    } else if (srpp->interactive_valuer > 0) {
      total_score = valuer_score;
      marked_flag = valuer_marked;
      user_status = valuer_user_status;
      user_score = valuer_user_score;
      user_tests_passed = valuer_user_tests_passed;
      read_log_file(valuer_cmt_file, &valuer_comment);
      read_log_file(valuer_jcmt_file, &valuer_judge_comment);
      unlink(valuer_cmt_file);
      unlink(valuer_jcmt_file);
      reply_pkt->score = total_score;
      reply_pkt->marked_flag = marked_flag;
    }
  }

  if (srgp->separate_user_score <= 0) {
    user_status = -1;
    user_score = -1;
    user_tests_passed = -1;
    user_run_tests = -1;
  } else {
    has_user_score = 1;
    user_run_tests = 0;
    for (cur_test = 1; cur_test < tests.size; ++cur_test) {
      if (tests.data[cur_test].visibility != TV_HIDDEN)
        ++user_run_tests;
    }
    if (user_tests_passed < 0) {
      user_tests_passed = 0;
      for (cur_test = 1; cur_test < tests.size; ++cur_test) {
        if (tests.data[cur_test].visibility != TV_HIDDEN
            && tests.data[cur_test].status == RUN_OK)
          ++user_tests_passed;
      }
    }
    if (user_status < 0) {
      user_status = RUN_OK;
      for (cur_test = 1; cur_test < tests.size; ++cur_test) {
        if (tests.data[cur_test].visibility != TV_HIDDEN
            && tests.data[cur_test].status != RUN_OK) {
          user_status = RUN_PARTIAL;
          break;
        }
      }
    }
    if (user_score < 0) {
      user_score = 0;
      for (cur_test = 1; cur_test < tests.size; ++cur_test) {
        if (tests.data[cur_test].visibility != TV_HIDDEN) {
          if (tests.data[cur_test].user_score >= 0) {
            user_score += tests.data[cur_test].user_score;
          } else if (tests.data[cur_test].score >= 0) {
            user_score += tests.data[cur_test].score;
          }
        }
      }
    }
    // user_run_tests, user_status, user_score computed
    if (srgp->scoring_system_val == SCORE_KIROV || (srgp->scoring_system_val == SCORE_OLYMPIAD && srgp->accepting_mode <= 0)) {
      if (srpp->variable_full_score <= 0 && user_status == RUN_OK) {
        if (srpp->full_user_score >= 0) {
          user_score = srpp->full_user_score;
        } else {
          user_score = srpp->full_score;
        }
      }
    }
  }

done:;

  long long file_size = -1;
  if (messages_path[0]) {
    file_size = generic_file_size(0, messages_path, 0);
  }
  if (file_size > 0) {
    generic_read_file(&additional_comment, 0, 0, 0, 0, messages_path, "");
  }

  reply_pkt->status = status;
  reply_pkt->has_user_score = has_user_score;
  reply_pkt->user_status = user_status;
  reply_pkt->user_score = user_score;
  reply_pkt->user_tests_passed = user_tests_passed;

  generate_xml_report(srp, reply_pkt, report_path,
                      tests.size, tests.data, utf8_mode,
                      srgp->variant, total_score,
                      srpp->full_score, srpp->full_user_score,
                      srpp->use_corr, srpp->use_info,
                      report_time_limit_ms, report_real_time_limit_ms,
                      has_real_time, has_max_memory_used,
                      has_max_rss,
                      marked_flag,
                      user_run_tests,
                      additional_comment, valuer_comment,
                      valuer_judge_comment, valuer_errors,
                      cpu_model, cpu_mhz, hostname);

  get_current_time(&reply_pkt->ts7, &reply_pkt->ts7_us);

  if (evfds[0] >= 0) close(evfds[0]);
  if (evfds[1] >= 0) close(evfds[1]);
  if (vefds[0] >= 0) close(vefds[0]);
  if (vefds[1] >= 0) close(vefds[1]);
  if (valuer_tsk) {
    task_Kill(valuer_tsk);
    task_Wait(valuer_tsk);
    task_Delete(valuer_tsk);
  }

  if (far) full_archive_close(far);
  free_testinfo_vector(&tests);
  xfree(open_tests_val);
  xfree(test_score_val);
  prepare_free_testsets(test_sets_count, test_sets_val);
  xfree(score_tests_val);
  xfree(valuer_errors);
  xfree(valuer_comment);
  xfree(valuer_judge_comment);
  xfree(additional_comment);
  merged_start_env = sarray_free(merged_start_env);
  xfree(cpu_model);
  xfree(cpu_mhz);
  return;

check_failed:
  if (reply_pkt->ts6 <= 0) {
    get_current_time(&reply_pkt->ts6, &reply_pkt->ts6_us);
  }

  status = RUN_CHECK_FAILED;
  has_user_score = 0;
  user_status = -1;
  user_score = -1;
  user_tests_passed = -1;
  user_run_tests = -1;
  goto done;
}
