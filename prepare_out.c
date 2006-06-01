/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005,2006 Alexander Chernov <cher@unicorn.cmc.msu.ru> */

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
#include "prepare_dflt.h"
#include "xml_utils.h"
#include "prepare_serve.h"
#include "errlog.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <string.h>

struct str_buf
{
  unsigned char *s;
  size_t a;
};

static const unsigned char *
c_armor(struct str_buf *pb, const unsigned char *s)
{
  const unsigned char *ps;
  unsigned char *pq;
  size_t outlen, inlen;
  int c;

  if (!s) s = "";
  inlen = strlen(s);
  for (outlen = 0, ps = s; *ps; ps++) {
    switch (*ps) {
    case '\'':
    case '\"':
    case '\\':
    case '\a':
    case '\b':
    case '\f':
    case '\n':
    case '\r':
    case '\t':
    case '\v':
      outlen += 2;
      break;
    default:
      if (*ps >= ' ') {
        outlen++;
      } else {
        outlen += 4;
      }
      break;
    }
  }

  if (outlen == inlen) return s;
  if (outlen >= pb->a) {
    if (!pb->a) pb->a = 64;
    while (outlen >= pb->a) pb->a *= 2;
    XREALLOC(pb->s, pb->a);
  }
  for (pq = pb->s, ps = s; *ps; ps++) {
    switch (*ps) {
    case '\'':
    case '\"':
    case '\\':
      c = *ps;
      goto handle_escape;
    case '\a': c = 'a'; goto handle_escape;
    case '\b': c = 'b'; goto handle_escape;
    case '\f': c = 'f'; goto handle_escape;
    case '\n': c = 'n'; goto handle_escape;
    case '\r': c = 'r'; goto handle_escape;
    case '\t': c = 't'; goto handle_escape;
    case '\v': c = 'v'; goto handle_escape;
    handle_escape:
      *pq++ = '\\';
      *pq++ = c;
      break;
    default:
      if (*ps >= ' ') {
        *pq++ = *ps;
      } else {
        *pq++ = '\\';
        *pq++ = (*ps >> 6) + '0';
        *pq++ = ((*ps >> 3) & 07) + '0';
        *pq++ = (*ps & 07) + '0';
      }
      break;
    }
  }
  *pq = 0;
  return pb->s;
}

static void
unparse_bool(FILE *f, const unsigned char *name, int value)
{
  fprintf(f, "%s%s\n", name, value?"":" = 0");
}

#define SIZE_G (1024 * 1024 * 1024)
#define SIZE_M (1024 * 1024)
#define SIZE_K (1024)

static unsigned char*
num_to_size(unsigned char *buf, size_t buf_size, int num)
{
  if (!num) snprintf(buf, buf_size, "0");
  else if (!(num % SIZE_G)) snprintf(buf, buf_size, "%uG", num / SIZE_G);
  else if (!(num % SIZE_M)) snprintf(buf, buf_size, "%uM", num / SIZE_M);
  else if (!(num % SIZE_K)) snprintf(buf, buf_size, "%uK", num / SIZE_K);
  else snprintf(buf, buf_size, "%u", num);
  return buf;
}
static unsigned char*
size_t_to_size(unsigned char *buf, size_t buf_size, size_t num)
{
  if (!num) snprintf(buf, buf_size, "0");
  else if (!(num % SIZE_G)) snprintf(buf, buf_size, "%zuG", num / SIZE_G);
  else if (!(num % SIZE_M)) snprintf(buf, buf_size, "%zuM", num / SIZE_M);
  else if (!(num % SIZE_K)) snprintf(buf, buf_size, "%zuK", num / SIZE_K);
  else snprintf(buf, buf_size, "%zu", num);
  return buf;
}

static void
do_str(FILE *f, struct str_buf *pb, const unsigned char *name, const unsigned char *val)
{
  if (!val || !*val) return;
  fprintf(f, "%s = \"%s\"\n", name, c_armor(pb, val));
}

/*
static void
do_str_mb_empty(FILE *f, struct str_buf *pb, const unsigned char *name,
                const unsigned char *val)
{
  if (!val) val = "";
  fprintf(f, "%s = \"%s\"\n", name, c_armor(pb, val));
}
*/

static void
do_xstr(FILE *f, struct str_buf *pb, const unsigned char *name, char **val)
{
  int i;

  if (!val) return;
  for (i = 0; val[i]; i++) {
    fprintf(f, "%s = \"%s\"\n", name, c_armor(pb, val[i]));
  }
}

void
prepare_unparse_global(FILE *f, struct section_global_data *global,
                       const unsigned char *compile_dir,
                       int need_variant_map)
{
  struct str_buf sbuf = { 0, 0};
  path_t compile_spool_dir;
  static const unsigned char * const contest_types[] =
  {
    "acm",
    "kirov",
    "olympiad",
    "moscow",
    0,
  };
  static const unsigned char * const rounding_modes[] =
  {
    "ceil",
    "floor",
    "round",
    0,
  };
  unsigned char nbuf[64];

  fprintf(f, "contest_id = %d\n", global->contest_id);
  fprintf(f, "root_dir = \"%s\"\n", c_armor(&sbuf, global->root_dir));
  if (global->conf_dir[0] && strcmp(global->conf_dir, DFLT_G_CONF_DIR))
    fprintf(f, "conf_dir = \"%s\"\n", c_armor(&sbuf, global->conf_dir));
  fprintf(f, "\n");

  fprintf(f, "contest_time = %d\n", global->contest_time);
  if (global->contest_finish_time_d > 0) {
    fprintf(f, "contest_finish_time = \"%s\"\n",
            xml_unparse_date(global->contest_finish_time_d));
  }
  ASSERT(global->score_system_val >= 0 && global->score_system_val < SCORE_TOTAL);
  fprintf(f, "score_system = %s\n", contest_types[global->score_system_val]);
  if (global->virtual)
    fprintf(f, "virtual\n");
  if (global->board_fog_time != DFLT_G_BOARD_FOG_TIME)
    fprintf(f, "board_fog_time = %d\n", global->board_fog_time);
  if (global->board_unfog_time != DFLT_G_BOARD_UNFOG_TIME)
    fprintf(f, "board_unfog_time = %d\n", global->board_unfog_time);
  if (global->standings_locale[0])
    fprintf(f, "standings_locale = \"%s\"\n",
            c_armor(&sbuf, global->standings_locale));
  fprintf(f, "\n");

  if (compile_dir) {
    snprintf(compile_spool_dir, sizeof(compile_spool_dir),
             "%s/var/compile", compile_dir);
    fprintf(f, "compile_dir = \"%s\"\n\n", c_armor(&sbuf, compile_spool_dir));
  }

  if (global->team_enable_src_view != DFLT_G_TEAM_ENABLE_SRC_VIEW)
    unparse_bool(f, "team_enable_src_view", global->team_enable_src_view);
  if (global->team_enable_rep_view != DFLT_G_TEAM_ENABLE_REP_VIEW)
    unparse_bool(f, "team_enable_rep_view", global->team_enable_rep_view);
  if (global->team_enable_ce_view != DFLT_G_TEAM_ENABLE_CE_VIEW)
    unparse_bool(f, "team_enable_ce_view", global->team_enable_ce_view);
  if (global->team_show_judge_report != DFLT_G_TEAM_SHOW_JUDGE_REPORT)
    unparse_bool(f, "team_show_judge_report", global->team_show_judge_report);
  if (global->report_error_code != DFLT_G_REPORT_ERROR_CODE)
    unparse_bool(f, "report_error_code", global->report_error_code);
  if (global->disable_clars != DFLT_G_DISABLE_CLARS)
    unparse_bool(f, "disable_clars", global->disable_clars);
  if (global->disable_team_clars != DFLT_G_DISABLE_TEAM_CLARS)
    unparse_bool(f, "disable_team_clars", global->disable_team_clars);
  if (global->disable_submit_after_ok)
    unparse_bool(f, "disable_submit_after_ok", global->disable_submit_after_ok);
  if (global->ignore_compile_errors != DFLT_G_IGNORE_COMPILE_ERRORS)
    unparse_bool(f, "ignore_compile_errors", global->ignore_compile_errors);
  if (global->disable_failed_test_view > 0)
    unparse_bool(f,"disable_failed_test_view",global->disable_failed_test_view);
  if (global->ignore_duplicated_runs != DFLT_G_IGNORE_DUPLICATED_RUNS)
    unparse_bool(f, "ignore_duplicated_runs", global->ignore_duplicated_runs);
  if (global->show_deadline != DFLT_G_SHOW_DEADLINE)
    unparse_bool(f, "show_deadline", global->show_deadline);
  if (global->enable_printing != DFLT_G_ENABLE_PRINTING)
    unparse_bool(f, "enable_printing", global->enable_printing);
  if (global->prune_empty_users != DFLT_G_PRUNE_EMPTY_USERS)
    unparse_bool(f, "prune_empty_users", global->prune_empty_users);
  if (global->enable_full_archive != DFLT_G_ENABLE_FULL_ARCHIVE)
    unparse_bool(f, "enable_full_archive", global->enable_full_archive);
  if (global->always_show_problems != DFLT_G_ALWAYS_SHOW_PROBLEMS)
    unparse_bool(f, "always_show_problems", global->always_show_problems);
  fprintf(f, "\n");

  if (global->test_dir[0] && strcmp(global->test_dir, DFLT_G_TEST_DIR))
    fprintf(f, "test_dir = \"%s\"\n", c_armor(&sbuf, global->test_dir));
  if (global->corr_dir[0] && strcmp(global->corr_dir, DFLT_G_CORR_DIR))
    fprintf(f, "corr_dir = \"%s\"\n", c_armor(&sbuf, global->corr_dir));
  if (global->info_dir[0] && strcmp(global->info_dir, DFLT_G_INFO_DIR))
    fprintf(f, "info_dir = \"%s\"\n", c_armor(&sbuf, global->info_dir));
  if (global->tgz_dir[0] && strcmp(global->tgz_dir, DFLT_G_TGZ_DIR))
    fprintf(f, "tgz_dir = \"%s\"\n", c_armor(&sbuf, global->tgz_dir));
  if (global->checker_dir[0] && strcmp(global->checker_dir, DFLT_G_CHECKER_DIR))
    fprintf(f, "checker_dir = \"%s\"\n", c_armor(&sbuf, global->checker_dir));
  if (global->contest_start_cmd[0])
    fprintf(f, "contest_start_cmd = \"%s\"\n",
            c_armor(&sbuf, global->contest_start_cmd));
  fprintf(f, "\n");

  if (global->max_run_size != DFLT_G_MAX_RUN_SIZE)
    fprintf(f, "max_run_size = %s\n",
            num_to_size(nbuf, sizeof(nbuf), global->max_run_size));
  if (global->max_run_total != DFLT_G_MAX_RUN_TOTAL)
    fprintf(f, "max_run_total = %s\n",
            num_to_size(nbuf, sizeof(nbuf), global->max_run_total));
  if (global->max_run_num != DFLT_G_MAX_RUN_NUM)
    fprintf(f, "max_run_num = %d\n", global->max_run_num);
  if (global->max_clar_size != DFLT_G_MAX_CLAR_SIZE)
    fprintf(f, "max_clar_size = %s\n",
            num_to_size(nbuf, sizeof(nbuf), global->max_clar_size));
  if (global->max_clar_total != DFLT_G_MAX_CLAR_TOTAL)
    fprintf(f, "max_clar_total = %s\n",
            num_to_size(nbuf, sizeof(nbuf), global->max_clar_total));
  if (global->max_clar_num != DFLT_G_MAX_CLAR_NUM)
    fprintf(f, "max_clar_num = %d\n", global->max_clar_num);
  if (global->team_page_quota != DFLT_G_TEAM_PAGE_QUOTA)
    fprintf(f, "team_page_quota = %d\n", global->team_page_quota);
  fprintf(f, "\n");

  if (global->team_info_url[0])
    fprintf(f, "team_info_url = \"%s\"\n",
            c_armor(&sbuf, global->team_info_url));
  if (global->prob_info_url[0])
    fprintf(f, "prob_info_url = \"%s\"\n",
            c_armor(&sbuf, global->prob_info_url));
  if (global->standings_file_name[0] &&
      strcmp(global->standings_file_name, DFLT_G_STANDINGS_FILE_NAME))
    fprintf(f, "standings_file_name = \"%s\"\n",
            c_armor(&sbuf, global->standings_file_name));
  if (global->users_on_page > 0)
    fprintf(f, "users_on_page = %d\n", global->users_on_page);
  if (global->stand_header_file[0])
    fprintf(f, "stand_header_file = \"%s\"\n",
            c_armor(&sbuf, global->stand_header_file));
  if (global->stand_footer_file[0])
    fprintf(f, "stand_footer_file = \"%s\"\n",
            c_armor(&sbuf, global->stand_footer_file));
  if (global->stand_symlink_dir[0])
    fprintf(f, "stand_symlink_dir = \"%s\"\n",
            c_armor(&sbuf, global->stand_symlink_dir));
  if (global->stand_ignore_after_d > 0) {
    fprintf(f, "stand_ignore_after = \"%s\"\n",
            xml_unparse_date(global->stand_ignore_after_d));
  }
  if (global->ignore_success_time != DFLT_G_IGNORE_SUCCESS_TIME)
    unparse_bool(f, "ignore_success_time", global->ignore_success_time);
  if (global->stand2_file_name[0]) {
    fprintf(f, "stand2_file_name = \"%s\"\n",
            c_armor(&sbuf, global->stand2_file_name));
    if (global->stand2_header_file[0])
      fprintf(f, "stand2_header_file = \"%s\"\n",
              c_armor(&sbuf, global->stand2_header_file));
    if (global->stand2_footer_file[0])
      fprintf(f, "stand2_footer_file = \"%s\"\n",
              c_armor(&sbuf, global->stand2_footer_file));
    if (global->stand2_symlink_dir[0])
      fprintf(f, "stand2_symlink_dir = \"%s\"\n",
              c_armor(&sbuf, global->stand2_symlink_dir));
  }
  if (global->plog_file_name[0]) {
    fprintf(f, "plog_file_name = \"%s\"\n",
            c_armor(&sbuf, global->plog_file_name));
    if (global->plog_header_file[0])
      fprintf(f, "plog_header_file = \"%s\"\n",
              c_armor(&sbuf, global->plog_header_file));
    if (global->plog_footer_file[0])
      fprintf(f, "plog_footer_file = \"%s\"\n",
              c_armor(&sbuf, global->plog_footer_file));
    if (global->plog_symlink_dir[0])
      fprintf(f, "plog_symlink_dir = \"%s\"\n",
              c_armor(&sbuf, global->plog_symlink_dir));
    if (global->plog_update_time != DFLT_G_PLOG_UPDATE_TIME)
      fprintf(f, "plog_update_time = %d\n", global->plog_update_time);
  }
  fprintf(f, "\n");

  if (global->stand_success_attr[0])
    fprintf(f, "stand_success_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_success_attr));
  if (global->stand_table_attr[0])
    fprintf(f, "stand_table_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_table_attr));
  if (global->stand_place_attr[0])
    fprintf(f, "stand_place_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_place_attr));
  if (global->stand_team_attr[0])
    fprintf(f, "stand_team_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_team_attr));
  if (global->stand_prob_attr[0])
    fprintf(f, "stand_prob_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_prob_attr));
  if (global->stand_solved_attr[0])
    fprintf(f, "stand_solved_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_solved_attr));
  if (global->stand_score_attr[0])
    fprintf(f, "stand_score_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_score_attr));
  if (global->stand_penalty_attr[0])
    fprintf(f, "stand_penalty_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_penalty_attr));
  if (global->stand_fail_attr[0])
    fprintf(f, "stand_fail_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_fail_attr));
  if (global->stand_trans_attr[0])
    fprintf(f, "stand_trans_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_trans_attr));
  if (global->stand_show_ok_time != DFLT_G_STAND_SHOW_OK_TIME)
    unparse_bool(f, "stand_show_ok_time", global->stand_show_ok_time);
  if (global->stand_show_att_num)
    unparse_bool(f, "stand_show_att_num", global->stand_show_att_num);
  if (global->stand_sort_by_solved)
    unparse_bool(f, "stand_sort_by_solved", global->stand_sort_by_solved);
  if (global->stand_show_ok_time && global->stand_time_attr[0])
    fprintf(f, "stand_time_attr = \"%s\"\n",
            c_armor(&sbuf, global->stand_time_attr));
  if (global->virtual) {
    if (global->stand_self_row_attr[0])
      fprintf(f, "stand_self_row_attr = \"%s\"\n",
              c_armor(&sbuf, global->stand_self_row_attr));
    if (global->stand_r_row_attr[0])
      fprintf(f, "stand_r_row_attr = \"%s\"\n",
              c_armor(&sbuf, global->stand_r_row_attr));
    if (global->stand_v_row_attr[0])
      fprintf(f, "stand_v_row_attr = \"%s\"\n",
              c_armor(&sbuf, global->stand_v_row_attr));
    if (global->stand_u_row_attr[0])
      fprintf(f, "stand_u_row_attr = \"%s\"\n",
              c_armor(&sbuf, global->stand_u_row_attr));
  }
  if (global->stand_extra_format[0]) {
    fprintf(f, "stand_extra_format = \"%s\"\n",
            c_armor(&sbuf, global->stand_extra_format));
    if (global->stand_extra_legend[0])
      fprintf(f, "stand_extra_legend = \"%s\"\n",
              c_armor(&sbuf, global->stand_extra_legend));
    if (global->stand_extra_attr[0])
      fprintf(f, "stand_extra_attr = \"%s\"\n",
              c_armor(&sbuf, global->stand_extra_attr));
  }
  if (global->stand_show_warn_number != DFLT_G_STAND_SHOW_WARN_NUMBER)
    unparse_bool(f, "stand_show_warn_number", global->stand_show_warn_number);
  if (global->stand_show_warn_number) {
    if (global->stand_warn_number_attr[0])
      fprintf(f, "stand_warn_number_attr = \"%s\"\n",
              c_armor(&sbuf, global->stand_warn_number_attr));
  }
  //GLOBAL_PARAM(stand_row_attr, "x"),
  do_xstr(f, &sbuf, "stand_row_attr", global->stand_row_attr);
  //GLOBAL_PARAM(stand_page_table_attr, "s"),
  do_str(f, &sbuf, "stand_page_table_attr", global->stand_page_table_attr);
  //GLOBAL_PARAM(stand_page_cur_attr, "s"),
  do_str(f, &sbuf, "stand_page_cur_attr", global->stand_page_cur_attr);
  //GLOBAL_PARAM(stand_page_row_attr, "x"),
  do_xstr(f, &sbuf, "stand_page_row_attr", global->stand_page_row_attr);
  //GLOBAL_PARAM(stand_page_col_attr, "x"),  
  do_xstr(f, &sbuf, "stand_page_col_attr", global->stand_page_col_attr);
  fprintf(f, "\n");

  if (global->sleep_time != DFLT_G_SLEEP_TIME)
    fprintf(f, "sleep_time = %d\n", global->sleep_time);
  if (global->serve_sleep_time != DFLT_G_SERVE_SLEEP_TIME)
    fprintf(f, "serve_sleep_time = %d\n", global->serve_sleep_time);
  if (global->autoupdate_standings != DFLT_G_AUTOUPDATE_STANDINGS)
    unparse_bool(f, "autoupdate_standings", global->autoupdate_standings);
  if (global->inactivity_timeout
      && global->inactivity_timeout != DFLT_G_INACTIVITY_TIMEOUT)
    fprintf(f, "inactivity_timeout = %d\n", global->inactivity_timeout);
  ASSERT(global->rounding_mode_val >= 0 && global->rounding_mode_val <= 2);
  if (global->rounding_mode_val)
    fprintf(f, "rounding_mode = %s\n", rounding_modes[global->rounding_mode_val]);
  if (global->max_file_length && global->max_file_length != DFLT_G_MAX_FILE_LENGTH)
    fprintf(f, "max_file_length = %s\n",
            num_to_size(nbuf, sizeof(nbuf), global->max_file_length));
  if (global->max_line_length && global->max_line_length != DFLT_G_MAX_LINE_LENGTH)
    fprintf(f, "max_line_length = %s\n",
            num_to_size(nbuf, sizeof(nbuf), global->max_line_length));
  if (global->disable_auto_testing != DFLT_G_DISABLE_AUTO_TESTING)
    unparse_bool(f, "disable_auto_testing", global->disable_auto_testing);
  if (global->disable_testing != DFLT_G_DISABLE_TESTING)
    unparse_bool(f, "disable_testing", global->disable_testing);
  fprintf(f, "cr_serialization_key = %d\n", global->cr_serialization_key);
  if (global->show_astr_time != DFLT_G_SHOW_ASTR_TIME)
    unparse_bool(f, "show_astr_time", global->show_astr_time);
  if (global->enable_continue != DFLT_G_ENABLE_CONTINUE)
    unparse_bool(f, "enable_continue", global->enable_continue);
  if (global->enable_report_upload != DFLT_G_ENABLE_REPORT_UPLOAD)
    unparse_bool(f, "enable_report_upload", global->enable_report_upload);
  if (global->enable_runlog_merge != DFLT_G_ENABLE_RUNLOG_MERGE)
    unparse_bool(f, "enable_runlog_merge", global->enable_runlog_merge);
  if (global->secure_run != DFLT_G_SECURE_RUN)
    unparse_bool(f, "secure_run", global->secure_run);
  if (global->enable_memory_limit_error != DFLT_G_ENABLE_MEMORY_LIMIT_ERROR)
    unparse_bool(f, "enable_memory_limit_error", global->enable_memory_limit_error);
  //???
  unparse_bool(f, "enable_l10n", global->enable_l10n);
  if (global->charset[0] && strcmp(global->charset, DFLT_G_CHARSET))
    fprintf(f, "charset = \"%s\"\n", c_armor(&sbuf, global->charset));
  if (global->team_download_time != DFLT_G_TEAM_DOWNLOAD_TIME)
    fprintf(f, "team_download_time = %d\n", global->team_download_time);
  if (global->cpu_bogomips > 0)
    fprintf(f, "cpu_bogomips = %d\n", global->cpu_bogomips);
  if (global->variant_map_file[0] && need_variant_map)
    fprintf(f, "variant_map_file = \"%s\"\n", c_armor(&sbuf, global->variant_map_file));
  fprintf(f, "\n");

  if (global->unhandled_vars) fprintf(f, "%s\n", global->unhandled_vars);
    
  xfree(sbuf.s); sbuf.s = 0; sbuf.a = 0;
}

  /*
   * Unhandled global variables:
   *
  GLOBAL_PARAM(tests_to_accept, "d"),
  GLOBAL_PARAM(script_dir, "s"),
  GLOBAL_PARAM(test_sfx, "s"),
  GLOBAL_PARAM(corr_sfx, "s"),
  GLOBAL_PARAM(info_sfx, "s"),
  GLOBAL_PARAM(tgz_sfx, "s"),
  GLOBAL_PARAM(ejudge_checkers_dir, "s"),
  GLOBAL_PARAM(test_pat, "s"),
  GLOBAL_PARAM(corr_pat, "s"),
  GLOBAL_PARAM(info_pat, "s"),
  GLOBAL_PARAM(tgz_pat, "s"),
  GLOBAL_PARAM(var_dir, "s"),
  GLOBAL_PARAM(socket_path, "s"),
  GLOBAL_PARAM(contests_dir, "s"),
  GLOBAL_PARAM(serve_socket, "s"),
  GLOBAL_PARAM(run_log_file, "s"),
  GLOBAL_PARAM(clar_log_file, "s"),
  GLOBAL_PARAM(archive_dir, "s"),
  GLOBAL_PARAM(clar_archive_dir, "s"),
  GLOBAL_PARAM(run_archive_dir, "s"),
  GLOBAL_PARAM(report_archive_dir, "s"),
  GLOBAL_PARAM(team_report_archive_dir, "s"),
  GLOBAL_PARAM(team_extra_dir, "s"),
  GLOBAL_PARAM(status_dir, "s"),
  GLOBAL_PARAM(work_dir, "s"),
  GLOBAL_PARAM(print_work_dir, "s"),
  GLOBAL_PARAM(diff_work_dir, "s"),
  GLOBAL_PARAM(a2ps_path, "s"),
  GLOBAL_PARAM(a2ps_args, "x"),
  GLOBAL_PARAM(lpr_path, "s"),
  GLOBAL_PARAM(lpr_args, "x"),
  GLOBAL_PARAM(diff_path, "s"),
  GLOBAL_PARAM(compile_dir, "s"),
  GLOBAL_PARAM(compile_work_dir, "s"),
  GLOBAL_PARAM(run_dir, "s"),
  GLOBAL_PARAM(run_work_dir, "s"),
  GLOBAL_PARAM(run_check_dir, "s"),
  GLOBAL_PARAM(htdocs_dir, "s"),
  GLOBAL_PARAM(extended_sound, "d"),
  GLOBAL_PARAM(disable_sound, "d"),
  GLOBAL_PARAM(sound_player, "s"),
  GLOBAL_PARAM(accept_sound, "s"),
  GLOBAL_PARAM(runtime_sound, "s"),
  GLOBAL_PARAM(timelimit_sound, "s"),
  GLOBAL_PARAM(wrong_sound, "s"),
  GLOBAL_PARAM(presentation_sound, "s"),
  GLOBAL_PARAM(internal_sound, "s"),
  GLOBAL_PARAM(start_sound, "s"),
  GLOBAL_PARAM(l10n_dir, "s"),
  GLOBAL_PARAM(auto_short_problem_name, "d"),
  GLOBAL_PARAM(checker_real_time_limit, "d"),
  GLOBAL_PARAM(compile_real_time_limit, "d"),
  GLOBAL_PARAM(use_gzip, "d"),
  GLOBAL_PARAM(min_gzip_size, "d"),
  GLOBAL_PARAM(use_dir_hierarchy, "d"),
  GLOBAL_PARAM(priority_adjustment, "d"),
  GLOBAL_PARAM(user_priority_adjustments, "x"),
  GLOBAL_PARAM(contestant_status_num, "d"),
  GLOBAL_PARAM(contestant_status_legend, "x"),
  GLOBAL_PARAM(contestant_status_row_attr, "x"),
  GLOBAL_PARAM(stand_show_contestant_status, "d"),
  GLOBAL_PARAM(stand_contestant_status_attr, "s"),
  */
void
prepare_unparse_unhandled_global(FILE *f, const struct section_global_data *global)
{
  struct str_buf sbuf = { 0, 0};

  //GLOBAL_PARAM(tests_to_accept, "d"),
  if (global->tests_to_accept >= 0
      && global->tests_to_accept != DFLT_G_TESTS_TO_ACCEPT)
    fprintf(f, "tests_to_accept = %d\n", global->tests_to_accept);
  //GLOBAL_PARAM(script_dir, "s"),
  do_str(f, &sbuf, "script_dir", global->script_dir);
  //GLOBAL_PARAM(test_sfx, "s"),
  do_str(f, &sbuf, "test_sfx", global->test_sfx);
  //GLOBAL_PARAM(corr_sfx, "s"),
  do_str(f, &sbuf, "corr_sfx", global->corr_sfx);
  //GLOBAL_PARAM(info_sfx, "s"),
  if (global->info_sfx[0] && strcmp(global->info_sfx, DFLT_G_INFO_SFX))
      do_str(f, &sbuf, "info_sfx", global->info_sfx);
  //GLOBAL_PARAM(tgz_sfx, "s"),
  if (global->tgz_sfx[0] && strcmp(global->tgz_sfx, DFLT_G_TGZ_SFX))
    do_str(f, &sbuf, "tgz_sfx", global->tgz_sfx);
  //GLOBAL_PARAM(ejudge_checkers_dir, "s"),
  do_str(f, &sbuf, "ejudge_checkers_dir", global->ejudge_checkers_dir);
  //GLOBAL_PARAM(test_pat, "s"),
  do_str(f, &sbuf, "test_pat", global->test_pat);
  //GLOBAL_PARAM(corr_pat, "s"),
  do_str(f, &sbuf, "corr_pat", global->corr_pat);
  //GLOBAL_PARAM(info_pat, "s"),
  do_str(f, &sbuf, "info_pat", global->info_pat);
  //GLOBAL_PARAM(tgz_pat, "s"),
  do_str(f, &sbuf, "tgz_pat", global->tgz_pat);

  //GLOBAL_PARAM(socket_path, "s"),
  do_str(f, &sbuf, "socket_path", global->socket_path);
  //GLOBAL_PARAM(contests_dir, "s"),
  do_str(f, &sbuf, "contests_dir", global->contests_dir);
  //GLOBAL_PARAM(run_log_file, "s"),
  do_str(f, &sbuf, "run_log_file", global->run_log_file);
  //GLOBAL_PARAM(clar_log_file, "s"),
  do_str(f, &sbuf, "clar_log_file", global->clar_log_file);
  //GLOBAL_PARAM(archive_dir, "s"),
  do_str(f, &sbuf, "archive_dir", global->archive_dir);
  //GLOBAL_PARAM(clar_archive_dir, "s"),
  do_str(f, &sbuf, "clar_archive_dir", global->clar_archive_dir);
  //GLOBAL_PARAM(run_archive_dir, "s"),
  do_str(f, &sbuf, "run_archive_dir", global->run_archive_dir);
  //GLOBAL_PARAM(report_archive_dir, "s"),
  do_str(f, &sbuf, "report_archive_dir", global->report_archive_dir);
  //GLOBAL_PARAM(team_report_archive_dir, "s"),
  do_str(f, &sbuf, "team_report_archive_dir", global->team_report_archive_dir);
  //GLOBAL_PARAM(team_extra_dir, "s"),
  do_str(f, &sbuf, "team_extra_dir", global->team_extra_dir);
  //GLOBAL_PARAM(l10n_dir, "s"),
  do_str(f, &sbuf, "l10n_dir", global->l10n_dir);

  //GLOBAL_PARAM(status_dir, "s"),
  do_str(f, &sbuf, "status_dir", global->status_dir);
  //GLOBAL_PARAM(work_dir, "s"),
  do_str(f, &sbuf, "work_dir", global->work_dir);
  //GLOBAL_PARAM(print_work_dir, "s"),
  do_str(f, &sbuf, "print_work_dir", global->print_work_dir);
  //GLOBAL_PARAM(diff_work_dir, "s"),
  do_str(f, &sbuf, "diff_work_dir", global->diff_work_dir);
  //GLOBAL_PARAM(compile_work_dir, "s"),
  do_str(f, &sbuf, "compile_work_dir", global->compile_work_dir);
  //GLOBAL_PARAM(run_work_dir, "s"),
  do_str(f, &sbuf, "run_work_dir", global->run_work_dir);

  //GLOBAL_PARAM(a2ps_path, "s"),
  do_str(f, &sbuf, "a2ps_path", global->a2ps_path);
  //GLOBAL_PARAM(a2ps_args, "x"),
  do_xstr(f, &sbuf, "a2ps_args", global->a2ps_args);
  //GLOBAL_PARAM(lpr_path, "s"),
  do_str(f, &sbuf, "lpr_path", global->lpr_path);
  //GLOBAL_PARAM(lpr_args, "x"),
  do_xstr(f, &sbuf, "lpr_args", global->lpr_args);
  //GLOBAL_PARAM(diff_path, "s"),
  do_str(f, &sbuf, "diff_path", global->diff_path);

  //GLOBAL_PARAM(run_dir, "s"),
  do_str(f, &sbuf, "run_dir", global->run_dir);
  //GLOBAL_PARAM(run_check_dir, "s"),
  do_str(f, &sbuf, "run_check_dir", global->run_check_dir);
  //GLOBAL_PARAM(htdocs_dir, "s"),
  do_str(f, &sbuf, "htdocs_dir", global->htdocs_dir);

  //GLOBAL_PARAM(extended_sound, "d"),
  if (global->extended_sound)
    unparse_bool(f, "extended_sound", global->extended_sound);
  //GLOBAL_PARAM(disable_sound, "d"),
  if (global->disable_sound)
    unparse_bool(f, "disable_sound", global->disable_sound);
  //GLOBAL_PARAM(sound_player, "s"),
  do_str(f, &sbuf, "sound_player", global->sound_player);
  //GLOBAL_PARAM(accept_sound, "s"),
  do_str(f, &sbuf, "accept_sound", global->accept_sound);
  //GLOBAL_PARAM(runtime_sound, "s"),
  do_str(f, &sbuf, "runtime_sound", global->runtime_sound);
  //GLOBAL_PARAM(timelimit_sound, "s"),
  do_str(f, &sbuf, "timelimit_sound", global->timelimit_sound);
  //GLOBAL_PARAM(wrong_sound, "s"),
  do_str(f, &sbuf, "wrong_sound", global->wrong_sound);
  //GLOBAL_PARAM(presentation_sound, "s"),
  do_str(f, &sbuf, "presentation_sound", global->presentation_sound);
  //GLOBAL_PARAM(internal_sound, "s"),
  do_str(f, &sbuf, "internal_sound", global->internal_sound);
  //GLOBAL_PARAM(start_sound, "s"),
  do_str(f, &sbuf, "start_sound", global->start_sound);

  //GLOBAL_PARAM(auto_short_problem_name, "d"),
  if (global->auto_short_problem_name)
    unparse_bool(f, "auto_short_problem_name", global->auto_short_problem_name);
  //GLOBAL_PARAM(checker_real_time_limit, "d"),
  if (global->checker_real_time_limit >= 0
      && global->checker_real_time_limit != DFLT_G_CHECKER_REAL_TIME_LIMIT)
    fprintf(f, "checker_real_time_limit = %d\n", global->checker_real_time_limit);
  //GLOBAL_PARAM(compile_real_time_limit, "d"),
  if (global->compile_real_time_limit >= 0
      && global->compile_real_time_limit != DFLT_G_COMPILE_REAL_TIME_LIMIT)
    fprintf(f, "compile_real_time_limit = %d\n", global->compile_real_time_limit);
  //GLOBAL_PARAM(use_gzip, "d"),
  if (global->use_gzip >= 0 && global->use_gzip != DFLT_G_USE_GZIP)
    unparse_bool(f, "use_gzip", global->use_gzip);
  //GLOBAL_PARAM(min_gzip_size, "d"),
  if (global->min_gzip_size >= 0 && global->min_gzip_size != DFLT_G_MIN_GZIP_SIZE)
    fprintf(f, "min_gzip_size = %d\n", global->min_gzip_size);
  //GLOBAL_PARAM(use_dir_hierarchy, "d"),
  if (global->use_dir_hierarchy >= 0
      && global->use_dir_hierarchy != DFLT_G_USE_DIR_HIERARCHY)
    unparse_bool(f, "use_dir_hierarchy", global->use_dir_hierarchy);

  //GLOBAL_PARAM(priority_adjustment, "d"),
  if (global->priority_adjustment)
    fprintf(f, "priority_adjustment = %d\n", global->priority_adjustment);
  //GLOBAL_PARAM(user_priority_adjustments, "x"),
  do_xstr(f, &sbuf, "user_priority_adjustments", global->user_priority_adjustments);
  //GLOBAL_PARAM(skip_full_testing, "d"),
  if (global->skip_full_testing)
    fprintf(f, "skip_full_testing = %d\n", global->skip_full_testing);
  //GLOBAL_PARAM(skip_accept_testing, "d"),
  if (global->skip_accept_testing)
    fprintf(f, "skip_accept_testing = %d\n", global->skip_accept_testing);

  //GLOBAL_PARAM(contestant_status_num, "d"),
  if (global->contestant_status_num > 0)
    fprintf(f, "contestant_status_num = %d\n", global->contestant_status_num);
  //GLOBAL_PARAM(contestant_status_legend, "x"),
  do_xstr(f, &sbuf, "contestant_status_legend", global->contestant_status_legend);
  //GLOBAL_PARAM(contestant_status_row_attr, "x"),
  do_xstr(f, &sbuf, "contestant_status_row_attr", global->contestant_status_row_attr);
  //GLOBAL_PARAM(stand_show_contestant_status, "d"),
  if (global->stand_show_contestant_status)
    unparse_bool(f,"stand_show_contestant_status",global->stand_show_contestant_status);
  //GLOBAL_PARAM(stand_contestant_status_attr, "s"),
  do_str(f,&sbuf,"stand_contestant_status_attr",global->stand_contestant_status_attr);

  xfree(sbuf.s); sbuf.s = 0; sbuf.a = 0;
}

/*
 * Forbidden global variables:
 *
  GLOBAL_PARAM(name, "s"),
  GLOBAL_PARAM(var_dir, "s"),
  GLOBAL_PARAM(serve_socket, "s"),
 */
int
prepare_check_forbidden_global(FILE *f, const struct section_global_data *global)
{
  if (global->name[0]) {
    fprintf(f, "Cannot handle contests with `name' global variable set\n");
    return -1;
  }
  if (global->var_dir[0]) {
    fprintf(f, "Cannot handle contests with `var_dir' global variable set\n");
    return -1;
  }
  if (global->serve_socket[0]) {
    fprintf(f, "Cannot handle contests with `serve_socket' global variable set\n");
    return -1;
  }
  return 0;
}

void
prepare_unparse_lang(FILE *f, const struct section_language_data *lang,
                     const unsigned char *long_name,
                     const unsigned char *options)
{
  struct str_buf sbuf = { 0, 0};
  int i, flag = 0;

  fprintf(f, "[language]\n");
  fprintf(f, "id = %d\n", lang->id);
  if (lang->compile_id && lang->compile_id != lang->id)
    fprintf(f, "compile_id = %d\n", lang->compile_id);
  fprintf(f, "short_name = \"%s\"\n", c_armor(&sbuf, lang->short_name));
  if (long_name && *long_name)
    fprintf(f, "long_name = \"%s\"\n", c_armor(&sbuf, long_name));
  else if (lang->long_name[0])
    fprintf(f, "long_name = \"%s\"\n", c_armor(&sbuf, lang->long_name));
  fprintf(f, "arch = \"%s\"\n", c_armor(&sbuf, lang->arch));
  fprintf(f, "src_sfx = \"%s\"\n", c_armor(&sbuf, lang->src_sfx));
  fprintf(f, "exe_sfx = \"%s\"\n", c_armor(&sbuf, lang->exe_sfx));
  /*
  if (lang->key[0])
    fprintf(f, "key = \"%s\"\n", c_armor(&sbuf, lang->key));
  if (lang->cmd[0])
    fprintf(f, "cmd = \"%s\"\n", c_armor(&sbuf, lang->cmd));
  */
  if (lang->disabled)
    unparse_bool(f, "disabled", lang->disabled);
  if (lang->binary)
    unparse_bool(f, "binary", lang->binary);
  if (lang->disable_auto_testing)
    unparse_bool(f, "disable_auto_testing", lang->disable_auto_testing);
  if (lang->disable_testing)
    unparse_bool(f, "disable_testing", lang->disable_testing);
  if (lang->content_type[0]) {
    fprintf(f, "content_type = \"%s\"\n", c_armor(&sbuf, lang->content_type));
  }

  if (lang->compiler_env) {
    for (i = 0; lang->compiler_env[i]; i++) {
      if (!strncmp(lang->compiler_env[i], "EJUDGE_FLAGS=", 13)
          && options && *options) {
        fprintf(f, "compiler_env = \"EJUDGE_FLAGS=%s\"\n", c_armor(&sbuf, options));
        flag = 1;
      } else {
        fprintf(f, "compiler_env = \"%s\"\n", lang->compiler_env[i]);
      }
    }
  }
  if (!flag && options && *options) {
    fprintf(f, "compiler_env = \"EJUDGE_FLAGS=%s\"\n",
            c_armor(&sbuf, options));
  }
  fprintf(f, "\n");

  if (lang->unhandled_vars) fprintf(f, "%s\n", lang->unhandled_vars);

  xfree(sbuf.s); sbuf.s = 0; sbuf.a = 0;
}

/*
 * Unhandled language variables:
 *
  LANGUAGE_PARAM(priority_adjustment, "d"),
  LANGUAGE_PARAM(key, "s"),
  LANGUAGE_PARAM(compile_real_time_limit, "d"),
*/
void
prepare_unparse_unhandled_lang(FILE *f, const struct section_language_data *lang)
{
  struct str_buf sbuf = { 0, 0};

  //LANGUAGE_PARAM(priority_adjustment, "d"),
  if (lang->priority_adjustment)
    fprintf(f, "priority_adjustment = %d\n", lang->priority_adjustment);
  //LANGUAGE_PARAM(compile_real_time_limit, "d"),
  if (lang->compile_real_time_limit >= 0)
    fprintf(f, "compile_real_time_limit = %d\n", lang->compile_real_time_limit);
  //LANGUAGE_PARAM(key, "s"),
  do_str(f, &sbuf, "key", lang->key);

  xfree(sbuf.s); sbuf.s = 0; sbuf.a = 0;
}

/*
 * Forbidden language variables:
 *
  LANGUAGE_PARAM(cmd, "s"),
  LANGUAGE_PARAM(compile_dir, "s"),
*/
int
prepare_check_forbidden_lang(FILE *f, const struct section_language_data *lang)
{
  if (lang->cmd[0]) {
    fprintf(f, "Cannot handle contests with `cmd' language variable set\n");
    return -1;
  }
  if (lang->compile_dir[0]) {
    fprintf(f, "Cannot handle contests with `compile_dir' language variable set\n");
    return -1;
  }
  return 0;
}

void
prepare_unparse_prob(FILE *f, const struct section_problem_data *prob,
                     const struct section_global_data *global,
                     int score_system_val)
{
  struct str_buf sbuf = { 0, 0};

  fprintf(f, "[problem]\n");
  if (!prob->abstract) {
    fprintf(f, "id = %d\n", prob->id);
    /*
    if (prob->tester_id && prob->tester_id != prob->id)
      fprintf(f, "tester_id = %d\n", prob->tester_id);
    */
  }
  if (prob->abstract)
    unparse_bool(f, "abstract", prob->abstract);
  if (!prob->abstract) {
    if (prob->super[0])
      fprintf(f, "super = \"%s\"\n", c_armor(&sbuf, prob->super));
  }
  fprintf(f, "short_name = \"%s\"\n", c_armor(&sbuf, prob->short_name));
  if (!prob->abstract) {
    fprintf(f, "long_name = \"%s\"\n", c_armor(&sbuf, prob->long_name));
  }

  if ((prob->abstract && prob->output_only == 1)
      || (!prob->abstract && prob->output_only >= 0))
    unparse_bool(f, "output_only", prob->output_only);
  if ((prob->abstract && prob->use_stdin == 1)
      || (!prob->abstract && prob->use_stdin >= 0))
    unparse_bool(f, "use_stdin", prob->use_stdin);
  if (prob->input_file[0])
    fprintf(f, "input_file = \"%s\"\n", c_armor(&sbuf, prob->input_file));
  if ((prob->abstract && prob->use_stdout == 1)
      || (!prob->abstract && prob->use_stdout >= 0))
    unparse_bool(f, "use_stdout", prob->use_stdout);
  if (prob->output_file[0])
    fprintf(f, "output_file = \"%s\"\n", c_armor(&sbuf, prob->output_file));
  if ((prob->abstract && prob->binary_input == 1)
      || (!prob->abstract && prob->binary_input >= 0))
    unparse_bool(f, "binary_input", prob->binary_input);
  if (prob->test_dir[0])
    fprintf(f, "test_dir = \"%s\"\n", c_armor(&sbuf, prob->test_dir));
  if (prob->test_sfx[0] != 1) {
    if ((prob->abstract && strcmp(prob->test_sfx, global->test_sfx))
        || !prob->abstract)
      fprintf(f, "test_sfx = \"%s\"\n", c_armor(&sbuf, prob->test_sfx));
  }
  if (prob->test_pat[0] != 1) {
    if ((prob->abstract && strcmp(prob->test_pat, global->test_pat))
        || !prob->abstract)
      fprintf(f, "test_pat = \"%s\"\n", c_armor(&sbuf, prob->test_pat));
  }
  if ((prob->abstract && prob->use_corr == 1)
      || (!prob->abstract && prob->use_corr >= 0))
    unparse_bool(f, "use_corr", prob->use_corr);
  if (prob->corr_dir[0])
    fprintf(f, "corr_dir = \"%s\"\n", c_armor(&sbuf, prob->corr_dir));
  if (prob->corr_sfx[0] != 1) {
    if ((prob->abstract && strcmp(prob->corr_sfx, global->corr_sfx))
        || !prob->abstract)
      fprintf(f, "corr_sfx = \"%s\"\n", c_armor(&sbuf, prob->corr_sfx));
  }
  if (prob->corr_pat[0] != 1) {
    if ((prob->abstract && strcmp(prob->corr_pat, global->corr_pat))
        || !prob->abstract)
      fprintf(f, "corr_pat = \"%s\"\n", c_armor(&sbuf, prob->corr_pat));
  }
  if ((prob->abstract && prob->use_info == 1)
      || (!prob->abstract && prob->use_info >= 0))
    unparse_bool(f, "use_info", prob->use_info);
  if (prob->info_dir[0])
    fprintf(f, "info_dir = \"%s\"\n", c_armor(&sbuf, prob->info_dir));
  if (prob->info_sfx[0] != 1) {
    if ((prob->abstract
         && ((global->info_sfx[0] && strcmp(prob->info_sfx, global->info_sfx))
             || (!global->info_sfx[0] && strcmp(prob->info_sfx, DFLT_G_INFO_SFX))))
        || !prob->abstract)
      fprintf(f, "info_sfx = \"%s\"\n", c_armor(&sbuf, prob->info_sfx));
  }
  if (prob->info_pat[0] != 1) {
    if ((prob->abstract && strcmp(prob->info_pat, global->info_pat))
        || !prob->abstract)
      fprintf(f, "info_pat = \"%s\"\n", c_armor(&sbuf, prob->info_pat));
  }
  if ((prob->abstract && prob->use_tgz == 1)
      || (!prob->abstract && prob->use_tgz >= 0))
    unparse_bool(f, "use_tgz", prob->use_tgz);
  if (prob->tgz_dir[0])
    fprintf(f, "tgz_dir = \"%s\"\n", c_armor(&sbuf, prob->tgz_dir));
  if (prob->tgz_sfx[0] != 1) {
    if ((prob->abstract
         && ((global->tgz_sfx[0] && strcmp(prob->tgz_sfx, global->tgz_sfx))
             || (!global->tgz_sfx[0] && strcmp(prob->tgz_sfx, DFLT_G_TGZ_SFX))))
        || !prob->abstract)
      fprintf(f, "tgz_sfx = \"%s\"\n", c_armor(&sbuf, prob->tgz_sfx));
  }
  if (prob->tgz_pat[0] != 1) {
    if ((prob->abstract && strcmp(prob->tgz_pat, global->tgz_pat))
        || !prob->abstract)
      fprintf(f, "tgz_pat = \"%s\"\n", c_armor(&sbuf, prob->tgz_pat));
  }
  /*
  if (prob->use_tgz != -1) unparse_bool(f, "use_tgz", prob->use_tgz);
  if (prob->tgz_dir[0])
    fprintf(f, "tgz_dir = \"%s\"\n", c_armor(&sbuf, prob->tgz_dir));
  if (prob->tgz_sfx[0] != 1)
    fprintf(f, "tgz_sfx = \"%s\"\n", c_armor(&sbuf, prob->tgz_sfx));
  if (prob->tgz_pat[0] != 1)
    fprintf(f, "tgz_pat = \"%s\"\n", c_armor(&sbuf, prob->tgz_pat));
  */

  if ((prob->abstract && prob->time_limit > 0)
      || (!prob->abstract && prob->time_limit >= 0))
    fprintf(f, "time_limit = %d\n", prob->time_limit);
  if ((prob->abstract && prob->time_limit_millis > 0)
      || (!prob->abstract && prob->time_limit_millis >= 0))
    fprintf(f, "time_limit_millis = %d\n", prob->time_limit_millis);
  if ((prob->abstract && prob->real_time_limit > 0)
      || (!prob->abstract && prob->real_time_limit >= 0))
    fprintf(f, "real_time_limit = %d\n", prob->real_time_limit);
  if (prob->checker_real_time_limit >= 0)
    fprintf(f, "checker_real_time_limit = %d\n", prob->checker_real_time_limit);

  if (score_system_val == SCORE_KIROV || score_system_val == SCORE_OLYMPIAD) {
    if (prob->full_score >= 0) {
      if ((prob->abstract && prob->full_score != DFLT_P_FULL_SCORE)
          || !prob->abstract)
        fprintf(f, "full_score = %d\n", prob->full_score);
    }
    if (prob->test_score >= 0) {
      if ((prob->abstract && prob->test_score != DFLT_P_TEST_SCORE)
          || !prob->abstract)
        fprintf(f, "test_score = %d\n", prob->test_score);
    }
    if (prob->variable_full_score >= 0) {
      if ((prob->abstract && prob->variable_full_score != DFLT_P_VARIABLE_FULL_SCORE)
          || !prob->abstract)
        unparse_bool(f, "variable_full_score", prob->variable_full_score);
    }
    if (prob->run_penalty >= 0) {
      if ((prob->abstract && prob->run_penalty != DFLT_P_RUN_PENALTY)
          || !prob->abstract)
        fprintf(f, "run_penalty = %d\n", prob->run_penalty);
    }
    if (prob->disqualified_penalty >= 0) {
      // FIXME: better condition
      if ((prob->abstract && prob->disqualified_penalty != prob->run_penalty)
          || !prob->abstract)
        fprintf(f, "disqualified_penalty = %d\n", prob->disqualified_penalty);
    }
    if (prob->test_score_list[0])
      fprintf(f, "test_score_list = \"%s\"\n", c_armor(&sbuf, prob->test_score_list));
    if (prob->score_bonus[0])
      fprintf(f, "score_bonus = \"%s\"\n", c_armor(&sbuf, prob->score_bonus));
  }
  if (score_system_val == SCORE_MOSCOW || score_system_val == SCORE_ACM) {
    if (prob->acm_run_penalty >= 0) {
      if ((prob->abstract && prob->acm_run_penalty != DFLT_P_ACM_RUN_PENALTY)
          || !prob->abstract)
        fprintf(f, "acm_run_penalty = %d\n", prob->acm_run_penalty);
    }
  }
  if (score_system_val == SCORE_MOSCOW) {
    if (prob->full_score >= 0) {
      if ((prob->abstract && prob->full_score != DFLT_P_FULL_SCORE)
          || !prob->abstract)
        fprintf(f, "full_score = %d\n", prob->full_score);
    }
    if (prob->score_tests[0])
      fprintf(f, "score_tests = \"%s\"\n", c_armor(&sbuf, prob->score_tests));
  }
  if (score_system_val == SCORE_OLYMPIAD) {
    if (prob->tests_to_accept >= 0) {
      if ((prob->abstract
           && ((global->tests_to_accept >= 0
                && prob->tests_to_accept != global->tests_to_accept)
               || (global->tests_to_accept < 0
                   && prob->tests_to_accept != DFLT_G_TESTS_TO_ACCEPT)))
          || !prob->abstract)
        fprintf(f, "tests_to_accept = %d\n", prob->tests_to_accept);
    }
    if (prob->accept_partial >= 0) {
      if ((prob->abstract && prob->accept_partial)
          || !prob->abstract)
        unparse_bool(f, "accept_partial", prob->accept_partial);
    }
  }
  if (prob->standard_checker[0])
    fprintf(f, "standard_checker = \"%s\"\n", c_armor(&sbuf, prob->standard_checker));
  if (prob->check_cmd[0])
    fprintf(f, "check_cmd = \"%s\"\n", c_armor(&sbuf, prob->check_cmd));
  do_xstr(f, &sbuf, "checker_env", prob->checker_env);
  do_xstr(f, &sbuf, "lang_time_adj", prob->lang_time_adj);
  do_xstr(f, &sbuf, "test_sets", prob->test_sets);

  if (!prob->abstract && prob->variant_num > 0) {
    fprintf(f, "variant_num = %d\n", prob->variant_num);
  }
 
  if (prob->team_enable_rep_view >= 0)
    unparse_bool(f, "team_enable_rep_view", prob->team_enable_rep_view);
  if (prob->team_enable_ce_view >= 0)
    unparse_bool(f, "team_enable_ce_view", prob->team_enable_ce_view);
  if (prob->team_show_judge_report >= 0)
    unparse_bool(f, "team_show_judge_report", prob->team_show_judge_report);
  if (prob->disable_auto_testing >= 0)
    unparse_bool(f, "disable_auto_testing", prob->disable_auto_testing);
  if (prob->disable_testing >= 0)
    unparse_bool(f, "disable_testing", prob->disable_testing);
  if (prob->enable_compilation >= 0)
    unparse_bool(f, "enable_compilation", prob->enable_compilation);
  if (prob->hidden >= 0) {
    if ((prob->abstract && prob->hidden)
        || !prob->abstract)
      unparse_bool(f, "hidden", prob->hidden);
  }
  if (prob->stand_hide_time)
    unparse_bool(f, "stand_hide_time", prob->stand_hide_time);
  if (!prob->abstract && prob->start_date[0])
    fprintf(f, "start_date = \"%s\"\n", c_armor(&sbuf, prob->start_date));
  if (!prob->abstract && prob->deadline[0])
    fprintf(f, "deadline = \"%s\"\n", c_armor(&sbuf, prob->deadline));

  fprintf(f, "\n");
  if (prob->unhandled_vars) fprintf(f, "%s\n", prob->unhandled_vars);

  xfree(sbuf.s); sbuf.s = 0; sbuf.a = 0;
}

/*
 * Unhandled problem variables:
 *
  PROBLEM_PARAM(use_tgz, "d"),
  PROBLEM_PARAM(priority_adjustment, "d"),
  PROBLEM_PARAM(spelling, "s"),
  PROBLEM_PARAM(score_multiplier, "d"),
  PROBLEM_PARAM(date_penalty, "x"),
  PROBLEM_PARAM(disable_language, "x"),
  PROBLEM_PARAM(tgz_pat, "s"),
  PROBLEM_PARAM(personal_deadline, "x"),
  PROBLEM_PARAM(skip_testing, "d"),
*/
void
prepare_unparse_unhandled_prob(FILE *f, const struct section_problem_data *prob,
                               const struct section_global_data *global)
{
  struct str_buf sbuf = { 0, 0};

  //PROBLEM_PARAM(use_tgz, "d"),
  if (prob->use_tgz >= 0) {
    if (prob->use_tgz || !prob->abstract)
      unparse_bool(f, "use_tgz", prob->use_tgz);
  }
  /*
  //PROBLEM_PARAM(tgz_dir, "s"),
  do_str(f, &sbuf, "tgz_dir", prob->tgz_dir);
  //PROBLEM_PARAM(tgz_sfx, "s"),
  if (prob->tgz_sfx[0] != 1) {
    if ((prob->abstract
         && ((global->tgz_sfx[0] && strcmp(prob->tgz_sfx, global->tgz_sfx))
             || (!global->tgz_sfx[0] && strcmp(prob->tgz_sfx, DFLT_G_TGZ_SFX))))
        || !prob->abstract)
      do_str_mb_empty(f, &sbuf, "tgz_sfx", prob->tgz_sfx);
  }
  //PROBLEM_PARAM(tgz_pat, "s"),
  if (prob->tgz_pat[0] != 1) {
    if (strcmp(prob->tgz_pat, global->tgz_pat) || !prob->abstract)
      do_str_mb_empty(f, &sbuf, "tgz_pat", prob->tgz_pat);
  }
  */
  //PROBLEM_PARAM(skip_testing, "d"),
  if (prob->skip_testing > 0) {
    fprintf(f, "skip_testing = %d\n", prob->skip_testing);
  }
  //PROBLEM_PARAM(priority_adjustment, "d"),
  if (prob->priority_adjustment != -1000) {
    if (prob->priority_adjustment || !prob->abstract)
      fprintf(f, "priority_adjustment = %d\n", prob->priority_adjustment);
  }
  //PROBLEM_PARAM(spelling, "s"),
  do_str(f, &sbuf, "spelling", prob->spelling);
  //PROBLEM_PARAM(score_multiplier, "d"),
  if (prob->score_multiplier)
    fprintf(f, "score_multiplier = %d\n", prob->score_multiplier);
  //PROBLEM_PARAM(date_penalty, "x"),
  do_xstr(f, &sbuf, "date_penalty", prob->date_penalty);
  //PROBLEM_PARAM(disable_language, "x"),
  do_xstr(f, &sbuf, "disable_language", prob->disable_language);
  //PROBLEM_PARAM(personal_deadline, "x"),
  do_xstr(f, &sbuf, "personal_deadline", prob->personal_deadline);

  xfree(sbuf.s); sbuf.s = 0; sbuf.a = 0;
}

/*
 * Forbidden problem variables:
 *
  PROBLEM_PARAM(tester_id, "d"),
*/
int
prepare_check_forbidden_prob(FILE *f, const struct section_problem_data *prob)
{
  if (prob->tester_id > 0) {
    fprintf(f, "Cannot handle contests with `tester_id' problem variable set\n");
    return -1;
  }
  return 0;
}

enum
{
  ARCH_LINUX,
  ARCH_LINUX_SHARED,
  ARCH_DOS,
  ARCH_JAVA,
  ARCH_JAVA14,
  ARCH_PERL,
  ARCH_MSIL,

  ARCH_LAST,
};

static const unsigned char * const supported_archs[] =
{
  "",                           /* default - Linux static */
  "linux-shared",
  "dos",
  "java",
  "java14",
  "perl",
  "msil",
  0,
};
static const unsigned char * const arch_abstract_names [] =
{
  "Generic",
  "Linux-shared",
  "DOSTester",
  "Linux-java",
  "Linux-java14",
  "Perl",
  "Linux-msil",
  0,
};

int
prepare_unparse_is_supported_arch(const unsigned char *arch)
{
  int i;

  for (i = 0; supported_archs[i]; i++)
    if (!strcmp(arch, supported_archs[i]))
      return i;
  return -1;
}

int
prepare_unparse_is_supported_tester(const unsigned char *tester_name)
{
  int i;

  for (i = 0; arch_abstract_names[i]; i++)
    if (!strcmp(tester_name, arch_abstract_names[i]))
      return i;
  return -1;
}

static void
generate_abstract_tester(FILE *f, int arch, int secure_run,
                         size_t max_vm_size,
                         size_t max_stack_size,
                         int use_files,
                         int total_abstr_testers,
                         struct section_tester_data **abstr_testers,
                         const unsigned char *testing_work_dir)
{
  unsigned char nbuf[256], nbuf2[256];
  struct str_buf sbuf = { 0, 0};
  int i;
  struct section_tester_data *atst = 0;

  for (i = 0; i < total_abstr_testers; i++) {
    if (abstr_testers[i] && !strcmp(abstr_testers[i]->name, arch_abstract_names[arch]))
      break;
  }
  if (i < total_abstr_testers) atst = abstr_testers[i];

  switch (arch) {
  case ARCH_LINUX:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "no_core_dump\n"
            "enable_memory_limit_error\n"
            "kill_signal = KILL\n"
            "clear_env\n",
            arch_abstract_names[arch], supported_archs[arch]);
    if (max_vm_size != -1L)
      fprintf(f, "max_vm_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    if (max_stack_size != -1L)
      fprintf(f, "max_stack_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
#if CONF_HAS_LIBCAP - 0 == 1
    if (secure_run)
      fprintf(f, "start_cmd = \"capexec\"\n");
#endif /* CONF_HAS_LIBCAP */
    break;

  case ARCH_LINUX_SHARED:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "no_core_dump\n"
            "enable_memory_limit_error\n"
            "kill_signal = KILL\n"
            "clear_env\n",
            arch_abstract_names[arch], supported_archs[arch]);
    if (max_vm_size != -1L)
      fprintf(f, "max_vm_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    if (max_stack_size != -1L)
      fprintf(f, "max_stack_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
#if CONF_HAS_LIBCAP - 0 == 1
    if (secure_run)
      fprintf(f, "start_env = \"LD_BIND_NOW=1\"\n"
              "start_env = \"LD_PRELOAD=${script_dir}/libdropcaps.so\"\n");
#endif /* CONF_HAS_LIBCAP */
    break;

  case ARCH_JAVA:
  case ARCH_JAVA14:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "no_core_dump\n"
            "kill_signal = TERM\n"
            "start_cmd = \"runjava%s\"\n"
            "start_env = \"LANG=C\"\n"
            "start_env = \"EJUDGE_PREFIX_DIR\"\n",
            arch_abstract_names[arch], supported_archs[arch],
            arch == ARCH_JAVA14?"14":"");
    if (max_vm_size != -1L && max_stack_size != -1L) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_FLAGS=-Xmx%s -Xss%s\"\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size),
              size_t_to_size(nbuf2, sizeof(nbuf2), max_stack_size));
    } else if (max_vm_size != -1L) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_FLAGS=-Xmx%s\"\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    } else if (max_stack_size != -1L) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_FLAGS=-Xss%s\"\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
    }
    if (!secure_run) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_POLICY=none\"\n");
    } else if (use_files) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_POLICY=fileio.policy\"\n");
    }
    break;

  case ARCH_DOS:
    fprintf(f, "[tester]\n"
            "name = DOSTester\n"
            "arch = dos\n"
            "abstract\n"
            "no_core_dump\n"
            "no_redirect\n"
            "time_limit_adjustment\n"
            "is_dos\n"
            "kill_signal = KILL\n"
            "errorcode_file = \"retcode.txt\"\n"
            "start_cmd = \"dosrun3\"\n");
    break;

  case ARCH_PERL:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "no_core_dump\n"
            "kill_signal = TERM\n",
            arch_abstract_names[arch], supported_archs[arch]);
    if (max_vm_size != -1L)
      fprintf(f, "max_vm_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    if (max_stack_size != -1L)
      fprintf(f, "max_stack_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
    if (secure_run)
      fprintf(f, "start_cmd = \"runperl\"\n");
    break;

  case ARCH_MSIL:
  default:
    abort();
  }

  if (atst && atst->check_dir[0]) {
    fprintf(f, "check_dir = \"%s\"\n",
            c_armor(&sbuf, atst->check_dir));
  } else if (arch == ARCH_DOS) {
    fprintf(f, "check_dir = \"%s\"\n", "/home/judges/dosemu/run");
  } else if(testing_work_dir) {
    fprintf(f, "check_dir = \"%s\"\n",
            c_armor(&sbuf, testing_work_dir));
  }
  fprintf(f, "\n");

  xfree(sbuf.s); sbuf.s = 0; sbuf.a = 0;
}

static void
generate_concrete_tester(FILE *f, int arch,
                         struct section_problem_data *prob,
                         size_t max_vm_size,
                         size_t max_stack_size,
                         int use_files)
{
  unsigned char nbuf[256], nbuf2[256];
  struct str_buf sbuf = { 0, 0};

  fprintf(f, "[tester]\n"
          "problem_name = \"%s\"\n"
          "super = %s\n", c_armor(&sbuf, prob->short_name),
          arch_abstract_names[arch]);
  if (supported_archs[arch][0])
    fprintf(f, "arch = %s\n", supported_archs[arch]);

  switch (arch) {
  case ARCH_LINUX:
  case ARCH_LINUX_SHARED:
    if (max_vm_size != -1L) {
      fprintf(f, "max_vm_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    }
    if (max_stack_size != -1L) {
      fprintf(f, "max_stack_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
    }
    break;

  case ARCH_DOS:
    break;

  case ARCH_JAVA:
  case ARCH_JAVA14:
    if (use_files) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_POLICY=fileio.policy\"\n");
    } else {
      fprintf(f, "start_env = \"EJUDGE_JAVA_POLICY=default.policy\"\n");
    }
    if (max_vm_size != -1L && max_stack_size != -1L) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_FLAGS=-Xmx%s -Xss%s\"\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size),
              size_t_to_size(nbuf2, sizeof(nbuf2), max_stack_size));
    } else if (max_vm_size != -1L) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_FLAGS=-Xmx%s\"\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    } else if (max_stack_size != -1L) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_FLAGS=-Xss%s\"\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
    }
    break;

  case ARCH_PERL:
    break;

  case ARCH_MSIL:
  default:
    abort();
  }
  fprintf(f, "\n");
  xfree(sbuf.s); sbuf.s = 0; sbuf.a = 0;
}

int
prepare_unparse_testers(FILE *f,
                        int secure_run,
                        const struct section_global_data *global,
                        int total_langs,
                        struct section_language_data **langs,
                        int total_aprobs,
                        struct section_problem_data **aprobs,
                        int total_probs,
                        struct section_problem_data **probs,
                        int total_atesters,
                        struct section_tester_data **atesters,
                        const unsigned char *testing_work_dir)
{
  unsigned char **archs = 0;
  size_t *vm_sizes = 0, *stack_sizes = 0, *vm_ind = 0, *stack_ind = 0;
  int *vm_count = 0, *stack_count = 0, vm_total = 0, stack_total = 0;
  int *file_ios = 0, *need_sep_tester = 0;
  int total_archs = 0, i, j;
  int retcode = 0;
  int use_stdio = 0, use_files = 0, max_vm_ind, max_stack_ind;
  struct section_problem_data *abstr;
  struct section_problem_data tmp_prob;
  unsigned long def_vm_size, def_stack_size;
  int def_use_files;
  int def_tester_total = 0;
  int *arch_codes = 0;
  struct str_buf sbuf = { 0, 0};
  int arch_flags[ARCH_LAST];

  // how many languages
  for (i = 1, j = 0; i < total_langs; i++)
    if (langs[i]) j++;
  if (!j) {
    err("prepare_unparse_testers: no languages defined");
    retcode = -1;
    goto cleanup;
  }

  // how many problems
  for (i = 1, j = 0; i < total_probs; i++)
    if (probs[i] && probs[i]->disable_testing <= 0) j++;
  if (!j) {
    err("prepare_unparse_testers: no problems defined");
    retcode = -1;
    goto cleanup;
  }

  // collect architectures
  XCALLOC(archs, total_langs);
  XCALLOC(arch_codes, total_langs);
  for (i = 1; i < total_langs; i++) {
    if (!langs[i]) continue;
    for (j = 0; j < total_archs; j++)
      if (!strcmp(archs[j], langs[i]->arch))
        break;
    if (j == total_archs)
      archs[total_archs++] = xstrdup(langs[i]->arch);
  }

  // check for unsupported archs
  memset(arch_flags, 0, sizeof(arch_flags));
  for (i = 0; i < total_archs; i++) {
    if ((j = prepare_unparse_is_supported_arch(archs[i])) < 0) {
      err("prepare_unparse_testers: unsupported arch: `%s'", archs[i]);
      retcode = -1;
      goto cleanup;
    }
    ASSERT(j >= 0 && j < ARCH_LAST);
    arch_flags[j] = 1;
  }
  for (i = 0, j = 0; i < ARCH_LAST; i++)
    if (arch_flags[i])
      arch_codes[j++] = i;

  // collect memory limits, stack sizes, and file io flags
  XCALLOC(vm_sizes, total_probs);
  XCALLOC(stack_sizes, total_probs);
  XCALLOC(file_ios, total_probs);
  XCALLOC(vm_ind, total_probs);
  XCALLOC(stack_ind, total_probs);
  XCALLOC(vm_count, total_probs);
  XCALLOC(stack_count, total_probs);
  for (i = 0; i < total_probs; i++) {
    if (!probs[i] || probs[i]->disable_testing > 0) continue;
    abstr = 0;
    if (probs[i]->super[0]) {
      for (j = 0; j < total_aprobs; j++)
        if (!strcmp(probs[i]->super, aprobs[j]->short_name))
          break;
      if (j == total_aprobs) {
        err("prepare_unparse_testers: abstract problem `%s' not found",
            probs[i]->super);
        retcode = -1;
        goto cleanup;
      }
      abstr = aprobs[j];
    }
    prepare_copy_problem(&tmp_prob, probs[i]);
    prepare_set_prob_value(PREPARE_FIELD_PROB_OUTPUT_ONLY,
                           &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_STDIN,
                           &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_STDOUT,
                           &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_BINARY_INPUT,
                           &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_MAX_VM_SIZE,
                           &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_MAX_STACK_SIZE,
                           &tmp_prob, abstr, global);
    vm_sizes[i] = tmp_prob.max_vm_size;
    stack_sizes[i] = tmp_prob.max_stack_size;
    file_ios[i] = !tmp_prob.output_only && (!tmp_prob.use_stdin || !tmp_prob.use_stdout);
  }

  // collect memory and stack limits for the default tester
  for (i = 0; i < total_probs; i++) {
    if (!probs[i] || probs[i]->disable_testing > 0) continue;

    for (j = 0; j < vm_total; j++)
      if (vm_ind[j] == vm_sizes[i])
        break;
    if (j == vm_total) vm_total++;
    vm_ind[j] = vm_sizes[i];
    vm_count[j]++;

    for (j = 0; j < stack_total; j++)
      if (stack_ind[j] == stack_sizes[i])
        break;
    if (j == stack_total) stack_total++;
    stack_ind[j] = stack_sizes[i];
    stack_count[j]++;

    if (file_ios[i]) use_files++;
    else use_stdio++;
  }

  // find mostly used memory and stack limit
  max_vm_ind = 0;
  for (i = 1; i < vm_total; i++) {
    if (vm_count[i] > vm_count[max_vm_ind]) max_vm_ind = i;
  }
  max_stack_ind = 0;
  for (i = 1; i < stack_total; i++) {
    if (stack_count[i] > stack_count[max_stack_ind]) max_stack_ind = i;
  }
  def_vm_size = vm_ind[max_vm_ind];
  def_stack_size = stack_ind[max_stack_ind];
  def_use_files = 0;
  if (use_files > use_stdio) def_use_files = 1;

  // which problems require specific testers
  XCALLOC(need_sep_tester, total_probs);
  for (i = 0; i < total_probs; i++) {
    if (!probs[i] || probs[i]->disable_testing > 0) continue;
    if (vm_sizes[i] != def_vm_size 
        || stack_sizes[i] != def_stack_size
        || file_ios[i] != def_use_files)
      need_sep_tester[i] = 1;
  }

  // how many default testers do we need
  def_tester_total = 0;
  for (i = 0; i < total_probs; i++) {
    if (probs[i] && probs[i]->disable_testing <= 0 && !need_sep_tester[i])
      def_tester_total++;
  }

  for (i = 0; i < total_archs; i++) {
    generate_abstract_tester(f, arch_codes[i], secure_run,
                             def_vm_size, def_stack_size, def_use_files,
                             total_atesters, atesters, testing_work_dir);
  }

  if (def_tester_total) {
    for (i = 0; i < total_archs; i++) {
      fprintf(f, "[tester]\n"
              "any\n"
              "super = %s\n", arch_abstract_names[arch_codes[i]]);
      if (supported_archs[arch_codes[i]][0])
        fprintf(f, "arch = %s\n", supported_archs[arch_codes[i]]);
      fprintf(f, "\n");
    }
  }

  for (i = 0; i < total_probs; i++) {
    if (!probs[i] || probs[i]->disable_testing > 0 || !need_sep_tester[i]) continue;
    for (j = 0; j < total_archs; j++) {
      generate_concrete_tester(f, arch_codes[j], probs[i],
                               vm_sizes[i], stack_sizes[i], file_ios[i]);
    }
  }

 cleanup:
  for (i = 0; i < total_archs; i++)
    xfree(archs[i]);
  xfree(archs);
  xfree(vm_sizes);
  xfree(stack_sizes);
  xfree(file_ios);
  xfree(vm_ind);
  xfree(stack_ind);
  xfree(vm_count);
  xfree(stack_count);
  xfree(need_sep_tester);
  xfree(arch_codes);
  xfree(sbuf.s);
  return retcode;
}

static void
mkpath(unsigned char *out, const unsigned char *d, const unsigned char *n,
       const unsigned char *i)
{
  if (!n || !*n) {
    snprintf(out, sizeof(path_t), "%s/%s", d, i);
  } else if (!os_IsAbsolutePath(n)) {
    snprintf(out, sizeof(path_t), "%s/%s", d, n);
  } else {
    snprintf(out, sizeof(path_t), "%s", n);
  }
}
static void
print_files(FILE *f, const unsigned char *desc, const unsigned char *sfx,
            const unsigned char *pat)
{
  int i;

  fprintf(f, "%s: ", desc);
  if (pat && *pat) {
    for (i = 1; i < 5; i++) {
      fprintf(f, pat, i);
      fprintf(f, ", ");
    }
  } else {
    for (i = 1; i < 5; i++) {
      fprintf(f, "%03d%s, ", i, sfx);
    }
  }
  fprintf(f, "etc...\n");
}

static void
prob_instr(FILE *f, const unsigned char *root_dir,
           const unsigned char *conf_dir,
           const struct section_global_data *global,
           const struct section_problem_data *prob,
           const struct section_problem_data *abstr)
{
  struct section_problem_data tmp_prob;
  path_t checker_path;
  path_t conf_path;
  path_t g_path;
  path_t l_path;

  prepare_copy_problem(&tmp_prob, prob);
  mkpath(conf_path, root_dir, conf_dir, "conf");

  fprintf(f, "Problem %s: %s\n", prob->short_name, prob->long_name);
  if (!prob->standard_checker[0]) {
    mkpath(checker_path, conf_path, global->checker_dir, DFLT_G_CHECKER_DIR);
    prepare_set_prob_value(PREPARE_FIELD_PROB_CHECK_CMD, &tmp_prob, abstr, global);
    if (os_IsAbsolutePath(tmp_prob.check_cmd)) {
      fprintf(f, "Checker command: %s\n", tmp_prob.check_cmd);
    } else {
      fprintf(f, "Checker directory: %s\n", checker_path);
      fprintf(f, "Checker file name: %s\n", tmp_prob.check_cmd);
    }
  }

  mkpath(g_path, conf_path, global->test_dir, DFLT_G_TEST_DIR);
  prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_DIR, &tmp_prob, abstr, 0);
  mkpath(l_path, g_path, tmp_prob.test_dir, "");
  fprintf(f, "Directory with tests: %s\n", l_path);
  prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_SFX, &tmp_prob, abstr, global);
  prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_PAT, &tmp_prob, abstr, global);
  print_files(f, "Test file names", tmp_prob.test_sfx, tmp_prob.test_pat);

  prepare_set_prob_value(PREPARE_FIELD_PROB_USE_CORR, &tmp_prob, abstr, global);
  if (tmp_prob.use_corr) {
    mkpath(g_path, conf_path, global->corr_dir, DFLT_G_CORR_DIR);
    prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_DIR, &tmp_prob, abstr, 0);
    mkpath(l_path, g_path, tmp_prob.corr_dir, "");
    fprintf(f, "Directory with correct answers: %s\n", l_path);
    prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_SFX, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_PAT, &tmp_prob, abstr, global);
    print_files(f, "Correct answer file names", tmp_prob.corr_sfx, tmp_prob.corr_pat);
  }

  prepare_set_prob_value(PREPARE_FIELD_PROB_USE_INFO, &tmp_prob, abstr, global);
  if (tmp_prob.use_info) {
    mkpath(g_path, conf_path, global->info_dir, DFLT_G_INFO_DIR);
    prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_DIR, &tmp_prob, abstr, 0);
    mkpath(l_path, g_path, tmp_prob.info_dir, "");
    fprintf(f, "Directory with test info files: %s\n", l_path);
    prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_SFX, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_PAT, &tmp_prob, abstr, global);
    print_files(f, "Test info file names", tmp_prob.info_sfx, tmp_prob.info_pat);
  }

  prepare_set_prob_value(PREPARE_FIELD_PROB_USE_TGZ, &tmp_prob, abstr, global);
  if (tmp_prob.use_tgz) {
    mkpath(g_path, conf_path, global->tgz_dir, DFLT_G_TGZ_DIR);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TGZ_DIR, &tmp_prob, abstr, 0);
    mkpath(l_path, g_path, tmp_prob.tgz_dir, "");
    fprintf(f, "Directory with test tgz files: %s\n", l_path);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TGZ_SFX, &tmp_prob, abstr, global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TGZ_PAT, &tmp_prob, abstr, global);
    print_files(f, "Test tgz file names", tmp_prob.tgz_sfx, tmp_prob.tgz_pat);
  }

  fprintf(f, "\n");
}

void
prepare_further_instructions(FILE *f,
                             const unsigned char *root_dir,
                             const unsigned char *conf_dir,
                             const struct section_global_data *global,
                             int aprob_a, struct section_problem_data **aprobs,
                             int prob_a, struct section_problem_data **probs)
{
  int i, j;
  const struct section_problem_data *abstr;

  if (!global) return;

  for (i = 1; i < prob_a; i++) {
    if (!probs[i] || probs[i]->disable_testing > 0) continue;
    abstr = 0;
    if (probs[i]->super[0]) {
      for (j = 0; j < aprob_a; j++)
        if (!strcmp(probs[i]->super, aprobs[j]->short_name))
          break;
      if (j < aprob_a) abstr = aprobs[j];
    }
    prob_instr(f, root_dir, conf_dir, global, probs[i], abstr);
  }

  fprintf(f, "\n"
          "Make sure, that checker executables are placed in the specified directory\n"
          "and has the specified names!\n\n"
          "Copy test files, correct answer files (if needed), test info files (if needed)\n"
          "to the specified directories and name them as specified!\n\n"
          "Make sure, that all input files are in UNIX text format!\n");
}

void
prepare_unparse_variants(FILE *f, const struct variant_map *vmap,
                         const unsigned char *header,
                         const unsigned char *footer)
{
  int i, j;

  fprintf(f, "<variant_map version=\"1\">\n");
  if (header) fprintf(f, "%s", header);
  for (i = 0; i < vmap->u; i++) {
    fprintf(f, "%s", vmap->v[i].login);
    for (j = 0; j < vmap->prob_rev_map_size; j++)
      fprintf(f, " %d", vmap->v[i].variants[j]);
    fprintf(f, "\n");
  }
  fprintf(f, "</variant_map>\n");
  if (footer) fprintf(f, "%s", footer);
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
