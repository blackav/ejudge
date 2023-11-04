/* -*- mode: c -*- */

/* Copyright (C) 2005-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/prepare.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/xml_utils.h"
#include "ejudge/prepare_serve.h"
#include "ejudge/errlog.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/misctext.h"
#include "ejudge/sformat.h"
#include "ejudge/varsubst.h"
#include "ejudge/variant_map.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>

static const unsigned char *
c_armor_2(
        struct html_armor_buffer *pb,
        const unsigned char *str,
        const unsigned char *pfx)
{
  int plen;
  const unsigned char *s;

  if (!os_IsAbsolutePath(str) || !pfx || !os_IsAbsolutePath(pfx))
    return c_armor_buf(pb, str);
  plen = strlen(pfx);
  if (strncmp(str, pfx, plen) != 0) return c_armor_buf(pb, str);
  s = str + plen;
  while (*s == '/') s++;
  return c_armor_buf(pb, s);
}

#define CARMOR(s) c_armor_buf(&ab, (s))

static void
unparse_bool(FILE *f, const unsigned char *name, int value)
{
  fprintf(f, "%s%s\n", name, value?"":" = 0");
}

static void
do_str(
        FILE *f,
        struct html_armor_buffer *pb,
        const unsigned char *name,
        const unsigned char *val)
{
  if (!val || !*val || val[0] == 1) return;
  fprintf(f, "%s = \"%s\"\n", name, c_armor_buf(pb, val));
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
do_xstr(
        FILE *f,
        struct html_armor_buffer *pb,
        const unsigned char *name,
        char **val)
{
  int i;

  if (!val) return;
  for (i = 0; val[i]; i++) {
    fprintf(f, "%s = \"%s\"\n", name, c_armor_buf(pb, val[i]));
  }
}

void
prepare_unparse_global(
        FILE *f,
        const struct contest_desc *cnts,
        struct section_global_data *global,
        const unsigned char *compile_dir,
        int need_variant_map)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  path_t compile_spool_dir, tmp1, tmp2, contests_home_dir;
  int skip_elem, len;
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
  unsigned char size_buf[256];

  /*
  fprintf(f, "contest_id = %d\n", global->contest_id);
  */

  // make the contests_home_dir path for future use
  contests_home_dir[0] = 0;
  if (ejudge_config && ejudge_config->contests_home_dir) {
    snprintf(contests_home_dir, sizeof(contests_home_dir), "%s",
             ejudge_config->contests_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!contests_home_dir[0]) {
    snprintf(contests_home_dir, sizeof(contests_home_dir), "%s",
             EJUDGE_CONTESTS_HOME_DIR);
  }
#endif

  // avoid generating root_dir and conf_dir if their values are default
  skip_elem = 0;
  if (contests_home_dir[0] && global->root_dir && global->root_dir[0]) {
    len = strlen(contests_home_dir);
    snprintf(tmp1, sizeof(tmp1), "%s/%06d", contests_home_dir, cnts->id);
    if (!strcmp(tmp1, global->root_dir)) {
      // do nothing, <root_dir> has the default value
      skip_elem = 1;
    } else if (!strncmp(contests_home_dir, global->root_dir, len)
               && global->root_dir[len] == '/') {
      while (global->root_dir[len] == '/') len++;
      fprintf(f, "root_dir = \"%s\"\n", CARMOR(global->root_dir + len));
      skip_elem = 1;
    }
  }
  if (!skip_elem)
    fprintf(f, "root_dir = \"%s\"\n", CARMOR(global->root_dir));

  skip_elem = 0;
  if (global->root_dir && global->root_dir[0] && global->conf_dir && global->conf_dir[0]) {
    snprintf(tmp1, sizeof(tmp1), "%s/conf", global->root_dir);
    if (!strcmp(tmp1, global->conf_dir)
        || !strcmp(global->conf_dir, DFLT_G_CONF_DIR)) skip_elem = 1;
  }
  if (!skip_elem && global->conf_dir && global->conf_dir[0])
    fprintf(f, "conf_dir = \"%s\"\n", CARMOR(global->conf_dir));
  fprintf(f, "\n");

  fprintf(f, "contest_time = %d\n", global->contest_time);
  if (global->contest_finish_time > 0) {
    fprintf(f, "contest_finish_time = \"%s\"\n",
            xml_unparse_date(global->contest_finish_time));
  }
  ASSERT(global->score_system >= 0 && global->score_system < SCORE_TOTAL);
  fprintf(f, "score_system = %s\n", contest_types[global->score_system]);
  if (global->is_virtual)
    fprintf(f, "virtual\n");
  if (global->board_fog_time != DFLT_G_BOARD_FOG_TIME)
    fprintf(f, "board_fog_time = %d\n", global->board_fog_time);
  if (global->board_unfog_time != DFLT_G_BOARD_UNFOG_TIME)
    fprintf(f, "board_unfog_time = %d\n", global->board_unfog_time);
  do_str(f, &ab, "standings_locale", global->standings_locale);
  if (global->checker_locale && global->checker_locale[0]) {
    do_str(f, &ab, "checker_locale", global->checker_locale);
  }
  fprintf(f, "\n");

  // if the `compile_dir' and the `var_dir' has the common prefix,
  // prefer relative path to absolute
  if (compile_dir) {
    snprintf(compile_spool_dir, sizeof(compile_spool_dir),
             "%s/var/compile", compile_dir);
    snprintf(tmp1, sizeof(tmp1), "%s/var", global->root_dir);
    path_make_relative(tmp2, sizeof(tmp2), compile_spool_dir,
                       tmp1, contests_home_dir);
    fprintf(f, "compile_dir = \"%s\"\n", CARMOR(tmp2));
  }
  // for extra_compile_dirs we do not add `var/compile' suffix
  // also, extra_compile_dirs are relative to the contests_home_dir
  if (global->extra_compile_dirs) {
    for (int i = 0; global->extra_compile_dirs[i]; ++i) {
      path_make_relative(tmp2, sizeof(tmp2), global->extra_compile_dirs[i],
                         contests_home_dir, contests_home_dir);
      fprintf(f, "extra_compile_dirs = \"%s\"\n", CARMOR(tmp2));
    }
  }
  fprintf(f, "\n");

  if (global->separate_user_score > 0)
    unparse_bool(f, "separate_user_score", global->separate_user_score);
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
  if (global->enable_eoln_select > 0)
    unparse_bool(f, "enable_eoln_select", global->enable_eoln_select);
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
  if (global->show_sha1 > 0)
    unparse_bool(f, "show_sha1", global->show_sha1);
  if (global->show_judge_identity > 0)
    unparse_bool(f, "show_judge_identity", global->show_judge_identity);
  if (global->enable_printing != DFLT_G_ENABLE_PRINTING)
    unparse_bool(f, "enable_printing", global->enable_printing);
  if (global->disable_banner_page != DFLT_G_DISABLE_BANNER_PAGE)
    unparse_bool(f, "disable_banner_page", global->disable_banner_page);
  if (global->printout_uses_login > 0)
    unparse_bool(f, "printout_uses_login", global->printout_uses_login);
  if (global->print_just_copy > 0)
    unparse_bool(f, "print_just_copy", global->print_just_copy);
  if (global->prune_empty_users != DFLT_G_PRUNE_EMPTY_USERS)
    unparse_bool(f, "prune_empty_users", global->prune_empty_users);
  if (global->enable_full_archive != DFLT_G_ENABLE_FULL_ARCHIVE)
    unparse_bool(f, "enable_full_archive", global->enable_full_archive);
  if (global->enable_problem_history)
    unparse_bool(f, "enable_problem_history", global->enable_problem_history);
  if (global->always_show_problems != DFLT_G_ALWAYS_SHOW_PROBLEMS)
    unparse_bool(f, "always_show_problems", global->always_show_problems);
  if (global->disable_user_standings != DFLT_G_DISABLE_USER_STANDINGS)
    unparse_bool(f, "disable_user_standings", global->disable_user_standings);
  if (global->disable_language != DFLT_G_DISABLE_LANGUAGE)
    unparse_bool(f, "disable_language", global->disable_language);
  if (global->problem_navigation != DFLT_G_PROBLEM_NAVIGATION)
    unparse_bool(f, "problem_navigation", global->problem_navigation);
  if (global->vertical_navigation != DFLT_G_VERTICAL_NAVIGATION)
    unparse_bool(f, "vertical_navigation", global->vertical_navigation);
  if (global->disable_virtual_start != DFLT_G_DISABLE_VIRTUAL_START)
    unparse_bool(f, "disable_virtual_start", global->disable_virtual_start);
  if (global->disable_virtual_auto_judge != DFLT_G_DISABLE_VIRTUAL_AUTO_JUDGE)
    unparse_bool(f, "disable_virtual_auto_judge", global->disable_virtual_auto_judge);
  if (global->enable_auto_print_protocol != DFLT_G_ENABLE_AUTO_PRINT_PROTOCOL)
    unparse_bool(f, "enable_auto_print_protocol", global->enable_auto_print_protocol);
  if (global->notify_clar_reply > 0)
    unparse_bool(f, "notify_clar_reply", global->notify_clar_reply);
  if (global->notify_status_change > 0)
    unparse_bool(f, "notify_status_change", global->notify_status_change);
  if (global->appeal_deadline > 0) {
    fprintf(f, "appeal_deadline = \"%s\"\n",
            xml_unparse_date(global->appeal_deadline));
  }
  if (global->start_on_first_login > 0)
    unparse_bool(f, "start_on_first_login", global->start_on_first_login);
  if (global->enable_virtual_restart > 0)
    unparse_bool(f, "enable_virtual_restart", global->enable_virtual_restart);
  if (global->preserve_line_numbers > 0)
    unparse_bool(f, "preserve_line_numbers", global->preserve_line_numbers);
  if (global->enable_remote_cache > 0)
    unparse_bool(f, "enable_remote_cache", global->enable_remote_cache);
  if (global->virtual_end_options && global->virtual_end_options[0])
    fprintf(f, "virtual_end_options = \"%s\"\n", CARMOR(global->virtual_end_options));
  fprintf(f, "\n");

  if (global->test_dir && strcmp(global->test_dir, DFLT_G_TEST_DIR))
    fprintf(f, "test_dir = \"%s\"\n", CARMOR(global->test_dir));
  if (global->corr_dir && strcmp(global->corr_dir, DFLT_G_CORR_DIR))
    fprintf(f, "corr_dir = \"%s\"\n", CARMOR(global->corr_dir));
  if (global->info_dir && strcmp(global->info_dir, DFLT_G_INFO_DIR))
    fprintf(f, "info_dir = \"%s\"\n", CARMOR(global->info_dir));
  if (global->tgz_dir && strcmp(global->tgz_dir, DFLT_G_TGZ_DIR))
    fprintf(f, "tgz_dir = \"%s\"\n", CARMOR(global->tgz_dir));
  if (global->checker_dir && global->checker_dir[0] && strcmp(global->checker_dir, DFLT_G_CHECKER_DIR))
    fprintf(f, "checker_dir = \"%s\"\n", CARMOR(global->checker_dir));
  if (global->statement_dir && global->statement_dir[0] && strcmp(global->statement_dir, DFLT_G_STATEMENT_DIR))
    fprintf(f, "statement_dir = \"%s\"\n", CARMOR(global->statement_dir));
  if (global->plugin_dir && global->plugin_dir[0] && strcmp(global->plugin_dir, DFLT_G_PLUGIN_DIR))
    fprintf(f, "plugin_dir = \"%s\"\n", CARMOR(global->plugin_dir));
  do_str(f, &ab, "contest_start_cmd", global->contest_start_cmd);
  if (global->contest_stop_cmd && global->contest_stop_cmd[0])
    fprintf(f, "contest_stop_cmd = \"%s\"\n",
            CARMOR(global->contest_stop_cmd));
  do_str(f, &ab, "description_file", global->description_file);
  fprintf(f, "\n");

  if (global->max_run_size != DFLT_G_MAX_RUN_SIZE)
    fprintf(f, "max_run_size = %s\n",
            num_to_size_str(nbuf, sizeof(nbuf), global->max_run_size));
  if (global->max_run_total != DFLT_G_MAX_RUN_TOTAL)
    fprintf(f, "max_run_total = %s\n",
            num_to_size_str(nbuf, sizeof(nbuf), global->max_run_total));
  if (global->max_run_num != DFLT_G_MAX_RUN_NUM)
    fprintf(f, "max_run_num = %d\n", global->max_run_num);
  if (global->max_clar_size != DFLT_G_MAX_CLAR_SIZE)
    fprintf(f, "max_clar_size = %s\n",
            num_to_size_str(nbuf, sizeof(nbuf), global->max_clar_size));
  if (global->max_clar_total != DFLT_G_MAX_CLAR_TOTAL)
    fprintf(f, "max_clar_total = %s\n",
            num_to_size_str(nbuf, sizeof(nbuf), global->max_clar_total));
  if (global->max_clar_num != DFLT_G_MAX_CLAR_NUM)
    fprintf(f, "max_clar_num = %d\n", global->max_clar_num);
  if (global->team_page_quota != DFLT_G_TEAM_PAGE_QUOTA)
    fprintf(f, "team_page_quota = %d\n", global->team_page_quota);
  if (global->time_between_submits >= 0)
    fprintf(f, "time_between_submits = %d\n", global->time_between_submits);
  if (global->max_input_size > 0)
    fprintf(f, "max_input_size = %s\n",
            num_to_size_str(nbuf, sizeof(nbuf), global->max_input_size));
  if (global->max_submit_num > 0)
    fprintf(f, "max_submit_num = %d\n", global->max_submit_num);
  if (global->max_submit_total > 0)
    fprintf(f, "max_submit_total = %s\n",
            num_to_size_str(nbuf, sizeof(nbuf), global->max_submit_total));

  if (global->compile_max_vm_size > 0) {
    fprintf(f, "compile_max_vm_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), global->compile_max_vm_size));
  }
  if (global->compile_max_stack_size > 0) {
    fprintf(f, "compile_max_stack_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), global->compile_max_stack_size));
  }
  if (global->compile_max_file_size > 0) {
    fprintf(f, "compile_max_file_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), global->compile_max_file_size));
  }
  if (global->compile_max_rss_size > 0) {
    fprintf(f, "compile_max_rss_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), global->compile_max_rss_size));
  }

  fprintf(f, "\n");

  if (global->team_info_url && global->team_info_url[0])
    fprintf(f, "team_info_url = \"%s\"\n", CARMOR(global->team_info_url));
  if (global->prob_info_url && global->prob_info_url[0])
    fprintf(f, "prob_info_url = \"%s\"\n", CARMOR(global->prob_info_url));
  if (global->standings_file_name && global->standings_file_name[0] &&
      strcmp(global->standings_file_name, DFLT_G_STANDINGS_FILE_NAME))
    fprintf(f, "standings_file_name = \"%s\"\n", CARMOR(global->standings_file_name));
  if (global->users_on_page > 0)
    fprintf(f, "users_on_page = %d\n", global->users_on_page);
  if (global->stand_header_file && global->stand_header_file[0])
    fprintf(f, "stand_header_file = \"%s\"\n", CARMOR(global->stand_header_file));
  if (global->stand_footer_file && global->stand_footer_file[0])
    fprintf(f, "stand_footer_file = \"%s\"\n", CARMOR(global->stand_footer_file));
  if (global->stand_symlink_dir && global->stand_symlink_dir[0])
    fprintf(f, "stand_symlink_dir = \"%s\"\n", CARMOR(global->stand_symlink_dir));
  if (global->stand_ignore_after > 0) {
    fprintf(f, "stand_ignore_after = \"%s\"\n",
            xml_unparse_date(global->stand_ignore_after));
  }
  if (global->ignore_success_time != DFLT_G_IGNORE_SUCCESS_TIME)
    unparse_bool(f, "ignore_success_time", global->ignore_success_time);
  if (global->stand2_file_name && global->stand2_file_name[0]) {
    fprintf(f, "stand2_file_name = \"%s\"\n", CARMOR(global->stand2_file_name));
    if (global->stand2_header_file && global->stand2_header_file[0])
      fprintf(f, "stand2_header_file = \"%s\"\n", CARMOR(global->stand2_header_file));
    if (global->stand2_footer_file && global->stand2_footer_file[0])
      fprintf(f, "stand2_footer_file = \"%s\"\n", CARMOR(global->stand2_footer_file));
    if (global->stand2_symlink_dir && global->stand2_symlink_dir[0])
      fprintf(f, "stand2_symlink_dir = \"%s\"\n", CARMOR(global->stand2_symlink_dir));
  }
  if (global->plog_file_name && global->plog_file_name[0]) {
    fprintf(f, "plog_file_name = \"%s\"\n", CARMOR(global->plog_file_name));
    if (global->plog_header_file && global->plog_header_file[0])
      fprintf(f, "plog_header_file = \"%s\"\n", CARMOR(global->plog_header_file));
    if (global->plog_footer_file && global->plog_footer_file[0])
      fprintf(f, "plog_footer_file = \"%s\"\n", CARMOR(global->plog_footer_file));
    if (global->plog_symlink_dir && global->plog_symlink_dir[0])
      fprintf(f, "plog_symlink_dir = \"%s\"\n", CARMOR(global->plog_symlink_dir));
    if (global->plog_update_time != DFLT_G_PLOG_UPDATE_TIME)
      fprintf(f, "plog_update_time = %d\n", global->plog_update_time);
  }
  if (global->external_xml_update_time > 0)
    fprintf(f, "external_xml_update_time = %d\n", global->external_xml_update_time);
  if (global->internal_xml_update_time > 0)
    fprintf(f, "internal_xml_update_time = %d\n", global->internal_xml_update_time);
  fprintf(f, "\n");

  if (global->stand_fancy_style > 0)
    unparse_bool(f, "stand_fancy_style", global->stand_fancy_style);
  do_str(f, &ab, "stand_success_attr", global->stand_success_attr);
  do_str(f, &ab, "stand_table_attr", global->stand_table_attr);
  do_str(f, &ab, "stand_place_attr", global->stand_place_attr);
  do_str(f, &ab, "stand_team_attr", global->stand_team_attr);
  do_str(f, &ab, "stand_prob_attr", global->stand_prob_attr);
  do_str(f, &ab, "stand_solved_attr", global->stand_solved_attr);
  do_str(f, &ab, "stand_score_attr", global->stand_score_attr);
  do_str(f, &ab, "stand_penalty_attr", global->stand_penalty_attr);
  do_str(f, &ab, "stand_fail_attr", global->stand_fail_attr);
  do_str(f, &ab, "stand_trans_attr", global->stand_trans_attr);
  do_str(f, &ab, "stand_disq_attr", global->stand_disq_attr);
  if (global->stand_use_login != DFLT_G_STAND_USE_LOGIN)
    unparse_bool(f, "stand_use_login", global->stand_use_login);
  if (global->stand_show_avatar > 0)
    unparse_bool(f, "stand_show_avatar", global->stand_show_avatar);
  if (global->stand_show_first_solver > 0)
    unparse_bool(f, "stand_show_first_solver", global->stand_show_first_solver);
  if (global->stand_show_ok_time != DFLT_G_STAND_SHOW_OK_TIME)
    unparse_bool(f, "stand_show_ok_time", global->stand_show_ok_time);
  if (global->stand_show_att_num)
    unparse_bool(f, "stand_show_att_num", global->stand_show_att_num);
  if (global->stand_sort_by_solved)
    unparse_bool(f, "stand_sort_by_solved", global->stand_sort_by_solved);
  if (global->stand_collate_name)
    unparse_bool(f, "stand_collate_name", global->stand_collate_name);
  if (global->stand_enable_penalty)
    unparse_bool(f, "stand_enable_penalty", global->stand_enable_penalty);
  if (global->stand_show_ok_time) {
    do_str(f, &ab, "stand_time_attr", global->stand_time_attr);
  }
  if (global->is_virtual) {
    do_str(f, &ab, "stand_self_row_attr", global->stand_self_row_attr);
    do_str(f, &ab, "stand_r_row_attr", global->stand_r_row_attr);
    do_str(f, &ab, "stand_v_row_attr", global->stand_v_row_attr);
    do_str(f, &ab, "stand_u_row_attr", global->stand_u_row_attr);
  }
  if (global->stand_extra_format && global->stand_extra_format[0]) {
    do_str(f, &ab, "stand_extra_format", global->stand_extra_format);
    do_str(f, &ab, "stand_extra_legend", global->stand_extra_legend);
    do_str(f, &ab, "stand_extra_attr", global->stand_extra_attr);
  }
  if (global->stand_show_warn_number != DFLT_G_STAND_SHOW_WARN_NUMBER)
    unparse_bool(f, "stand_show_warn_number", global->stand_show_warn_number);
  if (global->stand_show_warn_number) {
    do_str(f, &ab, "stand_warn_number_attr", global->stand_warn_number_attr);
  }
  //GLOBAL_PARAM(stand_row_attr, "x"),
  do_xstr(f, &ab, "stand_row_attr", global->stand_row_attr);
  //GLOBAL_PARAM(stand_page_table_attr, "s"),
  do_str(f, &ab, "stand_page_table_attr", global->stand_page_table_attr);
  //GLOBAL_PARAM(stand_page_cur_attr, "s"),
  do_str(f, &ab, "stand_page_cur_attr", global->stand_page_cur_attr);
  //GLOBAL_PARAM(stand_page_row_attr, "x"),
  do_xstr(f, &ab, "stand_page_row_attr", global->stand_page_row_attr);
  //GLOBAL_PARAM(stand_page_col_attr, "x"),
  do_xstr(f, &ab, "stand_page_col_attr", global->stand_page_col_attr);
  fprintf(f, "\n");

  if (global->sleep_time != DFLT_G_SLEEP_TIME)
    fprintf(f, "sleep_time = %d\n", global->sleep_time);
  if (global->serve_sleep_time != DFLT_G_SERVE_SLEEP_TIME)
    fprintf(f, "serve_sleep_time = %d\n", global->serve_sleep_time);
  if (ejudge_config && ejudge_config->disable_autoupdate_standings > 0) {
    if (global->autoupdate_standings > 0)
      unparse_bool(f, "autoupdate_standings", global->autoupdate_standings);
  } else {
    if (global->autoupdate_standings != DFLT_G_AUTOUPDATE_STANDINGS)
      unparse_bool(f, "autoupdate_standings", global->autoupdate_standings);
  }
  if (global->use_ac_not_ok != DFLT_G_USE_AC_NOT_OK)
    unparse_bool(f, "use_ac_not_ok", global->use_ac_not_ok);
  if (global->inactivity_timeout
      && global->inactivity_timeout != DFLT_G_INACTIVITY_TIMEOUT)
    fprintf(f, "inactivity_timeout = %d\n", global->inactivity_timeout);
  ASSERT(global->rounding_mode >= 0 && global->rounding_mode <= 2);
  if (global->rounding_mode)
    fprintf(f, "rounding_mode = %s\n", rounding_modes[global->rounding_mode]);
  if (global->max_file_length && global->max_file_length != DFLT_G_MAX_FILE_LENGTH)
    fprintf(f, "max_file_length = %s\n",
            num_to_size_str(nbuf, sizeof(nbuf), global->max_file_length));
  if (global->max_line_length && global->max_line_length != DFLT_G_MAX_LINE_LENGTH)
    fprintf(f, "max_line_length = %s\n",
            num_to_size_str(nbuf, sizeof(nbuf), global->max_line_length));
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
  if (global->detect_violations > 0)
    unparse_bool(f, "detect_violations", global->detect_violations);
  if (global->enable_memory_limit_error != DFLT_G_ENABLE_MEMORY_LIMIT_ERROR)
    unparse_bool(f, "enable_memory_limit_error", global->enable_memory_limit_error);
  if (global->advanced_layout > 0)
    unparse_bool(f, "advanced_layout", global->advanced_layout);
  if (global->uuid_run_store > 0)
    unparse_bool(f, "uuid_run_store", global->uuid_run_store);
  if (global->enable_32bit_checkers > 0)
    unparse_bool(f, "enable_32bit_checkers", global->enable_32bit_checkers);
  if (global->ignore_bom > 0)
    unparse_bool(f, "ignore_bom", global->ignore_bom);
  if (global->disable_auto_refresh > 0)
    unparse_bool(f, "disable_auto_refresh", global->disable_auto_refresh);
  if (global->disable_user_database > 0)
    unparse_bool(f, "disable_user_database", global->disable_user_database);
  if (global->enable_max_stack_size > 0)
    unparse_bool(f, "enable_max_stack_size", global->enable_max_stack_size);
  if (global->time_limit_retry_count > 1)
    fprintf(f, "time_limit_retry_count = %d\n", global->time_limit_retry_count);
  if (global->score_n_best_problems > 0)
    fprintf(f, "score_n_best_problems = %d\n", global->score_n_best_problems);
  if (global->require_problem_uuid > 0)
    unparse_bool(f, "require_problem_uuid", global->require_problem_uuid);

  //???
  unparse_bool(f, "enable_l10n", global->enable_l10n);
  if (global->charset && global->charset[0] && strcmp(global->charset, DFLT_G_CHARSET))
    fprintf(f, "charset = \"%s\"\n", CARMOR(global->charset));
  do_str(f, &ab, "standings_charset", global->standings_charset);
  do_str(f, &ab, "stand2_charset", global->stand2_charset);
  do_str(f, &ab, "plog_charset", global->plog_charset);

  if (global->team_download_time != DFLT_G_TEAM_DOWNLOAD_TIME)
    fprintf(f, "team_download_time = %d\n", global->team_download_time);
  if (global->cpu_bogomips > 0)
    fprintf(f, "cpu_bogomips = %d\n", global->cpu_bogomips);
  if (global->variant_map_file && need_variant_map)
    fprintf(f, "variant_map_file = \"%s\"\n", CARMOR(global->variant_map_file));
  if (global->clardb_plugin && global->clardb_plugin[0] && strcmp(global->clardb_plugin, "file"))
    fprintf(f, "clardb_plugin = \"%s\"\n", CARMOR(global->clardb_plugin));
  if (global->rundb_plugin && global->rundb_plugin[0] && strcmp(global->rundb_plugin, "file"))
    fprintf(f, "rundb_plugin = \"%s\"\n", CARMOR(global->rundb_plugin));
  if (global->xuser_plugin && global->xuser_plugin[0] && strcmp(global->xuser_plugin, "file"))
    fprintf(f, "xuser_plugin = \"%s\"\n", CARMOR(global->xuser_plugin));
  if (global->status_plugin && global->status_plugin[0] && strcmp(global->status_plugin, "file"))
    fprintf(f, "status_plugin = \"%s\"\n", CARMOR(global->status_plugin));
  if (global->variant_plugin && global->variant_plugin[0] && strcmp(global->variant_plugin, "file"))
    fprintf(f, "variant_plugin = \"%s\"\n", CARMOR(global->variant_plugin));
  do_xstr(f, &ab, "load_user_group", global->load_user_group);
  fprintf(f, "\n");

  if (global->tokens && global->tokens[0]) {
    do_str(f, &ab, "tokens", global->tokens);
    fprintf(f, "\n");
  }

  if (global->dates_config_file && global->dates_config_file[0]) {
    do_str(f, &ab, "dates_config_file", global->dates_config_file);
    fprintf(f, "\n");
  }

  if (global->unhandled_vars) fprintf(f, "%s\n", global->unhandled_vars);

  html_armor_free(&ab);
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
  GLOBAL_PARAM(problem_tab_size, "d"),
  GLOBAL_PARAM(user_exam_protocol_header_file, "s"),
  GLOBAL_PARAM(user_exam_protocol_footer_file, "s"),
  GLOBAL_PARAM(prob_exam_protocol_header_file, "s"),
  GLOBAL_PARAM(prob_exam_protocol_footer_file, "s"),
  GLOBAL_PARAM(full_exam_protocol_header_file, "s"),
  GLOBAL_PARAM(full_exam_protocol_footer_file, "s"),
  GLOBAL_PARAM(contest_plugin_file, "s"),
  */
void
prepare_unparse_unhandled_global(FILE *f, const struct section_global_data *global)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  //GLOBAL_PARAM(super_run_dir, "S"),
  do_str(f, &ab, "super_run_dir", global->super_run_dir);

  //GLOBAL_PARAM(compile_server_id, "S"),
  do_str(f, &ab, "compile_server_id", global->compile_server_id);

  //GLOBAL_PARAM(tests_to_accept, "d"),
  if (global->tests_to_accept >= 0
      && global->tests_to_accept != DFLT_G_TESTS_TO_ACCEPT)
    fprintf(f, "tests_to_accept = %d\n", global->tests_to_accept);
  //GLOBAL_PARAM(script_dir, "s"),
  do_str(f, &ab, "script_dir", global->script_dir);
  //GLOBAL_PARAM(test_sfx, "s"),
  do_str(f, &ab, "test_sfx", global->test_sfx);
  //GLOBAL_PARAM(corr_sfx, "s"),
  do_str(f, &ab, "corr_sfx", global->corr_sfx);
  //GLOBAL_PARAM(info_sfx, "s"),
  if (global->info_sfx && strcmp(global->info_sfx, DFLT_G_INFO_SFX))
    do_str(f, &ab, "info_sfx", global->info_sfx);
  //GLOBAL_PARAM(tgz_sfx, "s"),
  if (global->tgz_sfx && strcmp(global->tgz_sfx, DFLT_G_TGZ_SFX))
    do_str(f, &ab, "tgz_sfx", global->tgz_sfx);
  //GLOBAL_PARAM(tgzdir_sfx, "s"),
  if (global->tgzdir_sfx && strcmp(global->tgzdir_sfx, DFLT_G_TGZDIR_SFX))
    do_str(f, &ab, "tgzdir_sfx", global->tgzdir_sfx);
  //GLOBAL_PARAM(ejudge_checkers_dir, "s"),
  do_str(f, &ab, "ejudge_checkers_dir", global->ejudge_checkers_dir);
  //GLOBAL_PARAM(test_pat, "s"),
  do_str(f, &ab, "test_pat", global->test_pat);
  //GLOBAL_PARAM(corr_pat, "s"),
  do_str(f, &ab, "corr_pat", global->corr_pat);
  //GLOBAL_PARAM(info_pat, "s"),
  do_str(f, &ab, "info_pat", global->info_pat);
  //GLOBAL_PARAM(tgz_pat, "s"),
  do_str(f, &ab, "tgz_pat", global->tgz_pat);
  //GLOBAL_PARAM(tgzdir_pat, "s"),
  do_str(f, &ab, "tgzdir_pat", global->tgzdir_pat);

  //GLOBAL_PARAM(socket_path, "s"),
  do_str(f, &ab, "socket_path", global->socket_path);
  //GLOBAL_PARAM(contests_dir, "s"),
  do_str(f, &ab, "contests_dir", global->contests_dir);
  //GLOBAL_PARAM(run_log_file, "s"),
  do_str(f, &ab, "run_log_file", global->run_log_file);
  //GLOBAL_PARAM(clar_log_file, "s"),
  do_str(f, &ab, "clar_log_file", global->clar_log_file);
  //GLOBAL_PARAM(archive_dir, "s"),
  do_str(f, &ab, "archive_dir", global->archive_dir);
  //GLOBAL_PARAM(clar_archive_dir, "s"),
  do_str(f, &ab, "clar_archive_dir", global->clar_archive_dir);
  //GLOBAL_PARAM(run_archive_dir, "s"),
  do_str(f, &ab, "run_archive_dir", global->run_archive_dir);
  //GLOBAL_PARAM(report_archive_dir, "s"),
  do_str(f, &ab, "report_archive_dir", global->report_archive_dir);
  //GLOBAL_PARAM(team_report_archive_dir, "s"),
  do_str(f, &ab, "team_report_archive_dir", global->team_report_archive_dir);
  //GLOBAL_PARAM(team_extra_dir, "s"),
  do_str(f, &ab, "team_extra_dir", global->team_extra_dir);
  //GLOBAL_PARAM(l10n_dir, "s"),
  do_str(f, &ab, "l10n_dir", global->l10n_dir);

  //GLOBAL_PARAM(status_dir, "s"),
  do_str(f, &ab, "legacy_status_dir", global->legacy_status_dir);
  //GLOBAL_PARAM(work_dir, "s"),
  //do_str(f, &ab, "work_dir", global->work_dir);
  //GLOBAL_PARAM(print_work_dir, "s"),
  //do_str(f, &ab, "print_work_dir", global->print_work_dir);
  //GLOBAL_PARAM(diff_work_dir, "s"),
  //do_str(f, &ab, "diff_work_dir", global->diff_work_dir);
  //GLOBAL_PARAM(compile_work_dir, "s"),
  do_str(f, &ab, "compile_work_dir", global->compile_work_dir);
  //GLOBAL_PARAM(run_work_dir, "s"),
  do_str(f, &ab, "run_work_dir", global->run_work_dir);

  //GLOBAL_PARAM(a2ps_path, "s"),
  do_str(f, &ab, "a2ps_path", global->a2ps_path);
  //GLOBAL_PARAM(a2ps_args, "x"),
  do_xstr(f, &ab, "a2ps_args", global->a2ps_args);
  //GLOBAL_PARAM(lpr_path, "s"),
  do_str(f, &ab, "lpr_path", global->lpr_path);
  //GLOBAL_PARAM(lpr_args, "x"),
  do_xstr(f, &ab, "lpr_args", global->lpr_args);
  //GLOBAL_PARAM(diff_path, "s"),
  do_str(f, &ab, "diff_path", global->diff_path);
  //GLOBAL_PARAM(contest_plugin_file, "s"),
  do_str(f, &ab, "contest_plugin_file", global->contest_plugin_file);

  //GLOBAL_PARAM(run_dir, "s"),
  do_str(f, &ab, "run_dir", global->run_dir);
  //GLOBAL_PARAM(run_check_dir, "s"),
  do_str(f, &ab, "run_check_dir", global->run_check_dir);
  //GLOBAL_PARAM(htdocs_dir, "s"),
  do_str(f, &ab, "htdocs_dir", global->htdocs_dir);

  //GLOBAL_PARAM(extended_sound, "d"),
  if (global->extended_sound)
    unparse_bool(f, "extended_sound", global->extended_sound);
  //GLOBAL_PARAM(disable_sound, "d"),
  if (global->disable_sound)
    unparse_bool(f, "disable_sound", global->disable_sound);
  //GLOBAL_PARAM(sound_player, "s"),
  do_str(f, &ab, "sound_player", global->sound_player);
  //GLOBAL_PARAM(accept_sound, "s"),
  do_str(f, &ab, "accept_sound", global->accept_sound);
  //GLOBAL_PARAM(runtime_sound, "s"),
  do_str(f, &ab, "runtime_sound", global->runtime_sound);
  //GLOBAL_PARAM(timelimit_sound, "s"),
  do_str(f, &ab, "timelimit_sound", global->timelimit_sound);
  //GLOBAL_PARAM(wrong_sound, "s"),
  do_str(f, &ab, "wrong_sound", global->wrong_sound);
  //GLOBAL_PARAM(presentation_sound, "s"),
  do_str(f, &ab, "presentation_sound", global->presentation_sound);
  //GLOBAL_PARAM(internal_sound, "s"),
  do_str(f, &ab, "internal_sound", global->internal_sound);
  //GLOBAL_PARAM(start_sound, "s"),
  do_str(f, &ab, "start_sound", global->start_sound);

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
  do_xstr(f, &ab, "user_priority_adjustments", global->user_priority_adjustments);
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
  do_xstr(f, &ab, "contestant_status_legend", global->contestant_status_legend);
  //GLOBAL_PARAM(contestant_status_row_attr, "x"),
  do_xstr(f, &ab, "contestant_status_row_attr", global->contestant_status_row_attr);
  //GLOBAL_PARAM(stand_show_contestant_status, "d"),
  if (global->stand_show_contestant_status)
    unparse_bool(f,"stand_show_contestant_status",global->stand_show_contestant_status);
  //GLOBAL_PARAM(stand_contestant_status_attr, "s"),
  do_str(f,&ab,"stand_contestant_status_attr",global->stand_contestant_status_attr);

  //GLOBAL_PARAM(problem_tab_size, "d"),
  if (global->problem_tab_size > 0)
    fprintf(f, "problem_tab_size = %d\n", global->problem_tab_size);

  //GLOBAL_PARAM(user_exam_protocol_header_file, "s"),
  do_str(f, &ab, "user_exam_protocol_header_file", global->user_exam_protocol_header_file);
  //GLOBAL_PARAM(user_exam_protocol_footer_file, "s"),
  do_str(f, &ab, "user_exam_protocol_footer_file", global->user_exam_protocol_footer_file);
  //GLOBAL_PARAM(prob_exam_protocol_header_file, "s"),
  do_str(f, &ab, "prob_exam_protocol_header_file", global->prob_exam_protocol_header_file);
  //GLOBAL_PARAM(prob_exam_protocol_footer_file, "s"),
  do_str(f, &ab, "prob_exam_protocol_footer_file", global->prob_exam_protocol_footer_file);
  //GLOBAL_PARAM(full_exam_protocol_header_file, "s"),
  do_str(f, &ab, "full_exam_protocol_header_file", global->full_exam_protocol_header_file);
  //GLOBAL_PARAM(full_exam_protocol_footer_file, "s"),
  do_str(f, &ab, "full_exam_protocol_footer_file", global->full_exam_protocol_footer_file);

  html_armor_free(&ab);
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
  if (global->name && global->name[0]) {
    fprintf(f, "Cannot handle contests with `name' global variable set\n");
    return -1;
  }
  if (global->var_dir && global->var_dir[0]) {
    fprintf(f, "Cannot handle contests with `var_dir' global variable set\n");
    return -1;
  }
  if (global->serve_socket && global->serve_socket[0]) {
    fprintf(f, "Cannot handle contests with `serve_socket' global variable set\n");
    return -1;
  }
  return 0;
}

void
prepare_unparse_lang(
        FILE *f,
        const struct section_language_data *lang,
        const unsigned char *long_name,
        const unsigned char *options,
        const unsigned char *libs)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int i, flag = 0, lib_flag = 0;
  unsigned char size_buf[256];

  fprintf(f, "[language]\n");
  fprintf(f, "id = %d\n", lang->id);
  if (lang->compile_id && lang->compile_id != lang->id)
    fprintf(f, "compile_id = %d\n", lang->compile_id);
  if (lang->compile_dir_index > 0) {
    fprintf(f, "compile_dir_index = %d\n", lang->compile_dir_index);
  }
  fprintf(f, "short_name = \"%s\"\n", CARMOR(lang->short_name));
  if (long_name && *long_name)
    fprintf(f, "long_name = \"%s\"\n", CARMOR(long_name));
  else if (lang->long_name && lang->long_name[0])
    fprintf(f, "long_name = \"%s\"\n", CARMOR(lang->long_name));
  if (lang->extid && lang->extid[0]) {
    fprintf(f, "extid = \"%s\"\n", CARMOR(lang->extid));
  }
  if (lang->super_run_dir && lang->super_run_dir[0]) {
    fprintf(f, "super_run_dir = \"%s\"\n", CARMOR(lang->super_run_dir));
  }
  if (lang->compile_server_id && lang->compile_server_id[0]) {
    fprintf(f, "compile_server_id = \"%s\"\n", CARMOR(lang->compile_server_id));
  }
  if (lang->arch && lang->arch[0])
    fprintf(f, "arch = \"%s\"\n", CARMOR(lang->arch));
  fprintf(f, "src_sfx = \"%s\"\n", CARMOR(lang->src_sfx));
  if (lang->exe_sfx[0])
    fprintf(f, "exe_sfx = \"%s\"\n", CARMOR(lang->exe_sfx));
  /*
  if (lang->key[0])
    fprintf(f, "key = \"%s\"\n", CARMOR(lang->key));
  if (lang->cmd[0])
    fprintf(f, "cmd = \"%s\"\n", CARMOR(lang->cmd));
  */
  if (lang->disabled)
    unparse_bool(f, "disabled", lang->disabled);
  if (lang->insecure)
    unparse_bool(f, "insecure", lang->insecure);
  if (lang->disable_security)
    unparse_bool(f, "disable_security", lang->disable_security);
  if (lang->enable_suid_run)
    unparse_bool(f, "enable_suid_run", lang->enable_suid_run);
  if (lang->is_dos > 0)
    unparse_bool(f, "is_dos", lang->is_dos);
  if (lang->binary)
    unparse_bool(f, "binary", lang->binary);
  if (lang->disable_auto_testing)
    unparse_bool(f, "disable_auto_testing", lang->disable_auto_testing);
  if (lang->disable_testing)
    unparse_bool(f, "disable_testing", lang->disable_testing);
  if (lang->enable_custom > 0)
    unparse_bool(f, "enable_custom", lang->enable_custom);
  if (lang->enable_ejudge_env > 0)
    unparse_bool(f, "enable_ejudge_env", lang->enable_ejudge_env);
  if (lang->preserve_line_numbers > 0)
    unparse_bool(f, "preserve_line_numbers", lang->preserve_line_numbers);
  if (lang->content_type && lang->content_type[0]) {
    fprintf(f, "content_type = \"%s\"\n", CARMOR(lang->content_type));
  }
  if (lang->style_checker_cmd && lang->style_checker_cmd[0]) {
    fprintf(f, "style_checker_cmd = \"%s\"\n",CARMOR(lang->style_checker_cmd));
  }

  if (lang->max_vm_size > 0) {
    fprintf(f, "max_vm_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), lang->max_vm_size));
  }
  if (lang->max_stack_size > 0) {
    fprintf(f, "max_stack_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), lang->max_stack_size));
  }
  if (lang->max_file_size > 0) {
    fprintf(f, "max_file_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), lang->max_file_size));
  }
  if (lang->max_rss_size > 0) {
    fprintf(f, "max_rss_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), lang->max_rss_size));
  }
  if (lang->run_max_stack_size > 0) {
    fprintf(f, "run_max_stack_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), lang->run_max_stack_size));
  }
  if (lang->run_max_vm_size > 0) {
    fprintf(f, "run_max_vm_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), lang->run_max_vm_size));
  }
  if (lang->run_max_rss_size > 0) {
    fprintf(f, "run_max_rss_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), lang->run_max_rss_size));
  }

  if (lang->compiler_env) {
    for (i = 0; lang->compiler_env[i]; i++) {
      if (!strncmp(lang->compiler_env[i], "EJUDGE_FLAGS=", 13)
          && options && *options) {
        fprintf(f, "compiler_env = \"EJUDGE_FLAGS=%s\"\n", CARMOR(options));
        flag = 1;
      } else if (!strncmp(lang->compiler_env[i], "EJUDGE_LIBS=", 12) && libs && *libs) {
        fprintf(f, "compiler_env = \"EJUDGE_LIBS=%s\"\n", CARMOR(libs));
        lib_flag = 1;
      } else {
        fprintf(f, "compiler_env = \"%s\"\n", lang->compiler_env[i]);
      }
    }
  }
  if (!flag && options && *options) {
    fprintf(f, "compiler_env = \"EJUDGE_FLAGS=%s\"\n", CARMOR(options));
  }
  if (!lib_flag && libs && *libs) {
    fprintf(f, "compiler_env = \"EJUDGE_LIBS=%s\"\n", CARMOR(libs));
  }
  do_xstr(f, &ab, "style_checker_env", lang->style_checker_env);
  if (lang->container_options && *lang->container_options) {
    fprintf(f, "container_options = \"%s\"\n", CARMOR(lang->container_options));
  }
  if (lang->clean_up_cmd && *lang->clean_up_cmd) {
    fprintf(f, "clean_up_cmd = \"%s\"\n", CARMOR(lang->clean_up_cmd));
  }
  if (lang->run_env_file && *lang->run_env_file) {
    fprintf(f, "run_env_file = \"%s\"\n", CARMOR(lang->run_env_file));
  }
  if (lang->clean_up_env_file && *lang->clean_up_env_file) {
    fprintf(f, "clean_up_env_file = \"%s\"\n", CARMOR(lang->clean_up_env_file));
  }
  fprintf(f, "\n");

  if (lang->unhandled_vars) fprintf(f, "%s\n", lang->unhandled_vars);

  html_armor_free(&ab);
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
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  //LANGUAGE_PARAM(priority_adjustment, "d"),
  if (lang->priority_adjustment)
    fprintf(f, "priority_adjustment = %d\n", lang->priority_adjustment);
  //LANGUAGE_PARAM(compile_real_time_limit, "d"),
  if (lang->compile_real_time_limit >= 0)
    fprintf(f, "compile_real_time_limit = %d\n", lang->compile_real_time_limit);
  //LANGUAGE_PARAM(key, "s"),
  do_str(f, &ab, "key", lang->key);

  html_armor_free(&ab);
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
  if (lang->cmd && lang->cmd[0]) {
    fprintf(f, "Cannot handle contests with `cmd' language variable set\n");
    return -1;
  }
  if (lang->compile_dir && lang->compile_dir[0]) {
    fprintf(f, "Cannot handle contests with `compile_dir' language variable set\n");
    return -1;
  }
  return 0;
}

void
prepare_unparse_prob(
        FILE *f,
        const struct section_problem_data *prob,
        const struct section_problem_data *aprob,
        const struct section_global_data *global,
        int score_system)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char size_buf[256];

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
      fprintf(f, "super = \"%s\"\n", CARMOR(prob->super));
  }
  fprintf(f, "short_name = \"%s\"\n", CARMOR(prob->short_name));
  if (!prob->abstract && prob->long_name) {
    fprintf(f, "long_name = \"%s\"\n", CARMOR(prob->long_name));
  }
  if (!prob->abstract && prob->internal_name) {
    fprintf(f, "internal_name = \"%s\"\n", CARMOR(prob->internal_name));
  }
  if (!prob->abstract && prob->plugin_entry_name) {
    fprintf(f, "plugin_entry_name = \"%s\"\n", CARMOR(prob->plugin_entry_name));
  }
  if (!prob->abstract && prob->uuid && prob->uuid[0]) {
    fprintf(f, "uuid = \"%s\"\n", CARMOR(prob->uuid));
  }
  if (prob->problem_dir && prob->problem_dir[0]) {
    fprintf(f, "problem_dir = \"%s\"\n", CARMOR(prob->problem_dir));
  }

  if (prob->extid && prob->extid[0])
    fprintf(f, "extid = \"%s\"\n", CARMOR(prob->extid));

  if ((prob->abstract && prob->type > 0)
      || (!prob->abstract && prob->type >= 0))
    fprintf(f, "type = \"%s\"\n", problem_unparse_type(prob->type));
  /*
  if ((prob->abstract && prob->output_only == 1)
      || (!prob->abstract && prob->output_only >= 0))
    unparse_bool(f, "output_only", prob->output_only);
  */
  if ((prob->abstract && prob->scoring_checker == 1)
      || (!prob->abstract && prob->scoring_checker >= 0))
    unparse_bool(f, "scoring_checker", prob->scoring_checker);
  if ((prob->abstract && prob->enable_checker_token == 1)
      || (!prob->abstract && prob->enable_checker_token >= 0))
    unparse_bool(f, "enable_checker_token", prob->enable_checker_token);
  if ((prob->abstract && prob->interactive_valuer == 1)
      || (!prob->abstract && prob->interactive_valuer >= 0))
    unparse_bool(f, "interactive_valuer", prob->interactive_valuer);
  if ((prob->abstract && prob->disable_pe == 1)
      || (!prob->abstract && prob->disable_pe >= 0))
    unparse_bool(f, "disable_pe", prob->disable_pe);
  if ((prob->abstract && prob->disable_wtl == 1)
      || (!prob->abstract && prob->disable_wtl >= 0))
    unparse_bool(f, "disable_wtl", prob->disable_wtl);
  if ((prob->abstract && prob->wtl_is_cf == 1)
      || (!prob->abstract && prob->wtl_is_cf >= 0))
    unparse_bool(f, "wtl_is_cf", prob->wtl_is_cf);
  if ((prob->abstract && prob->manual_checking == 1)
      || (!prob->abstract && prob->manual_checking >= 0))
    unparse_bool(f, "manual_checking", prob->manual_checking);
  if ((prob->abstract && prob->examinator_num > 0)
      || (!prob->abstract && prob->examinator_num > 0))
    fprintf(f, "examinator_num = %d\n", prob->examinator_num);
  if ((prob->abstract && prob->check_presentation == 1)
      || (!prob->abstract && prob->check_presentation >= 0))
    unparse_bool(f, "check_presentation", prob->check_presentation);
  if ((prob->abstract && prob->use_stdin == 1)
      || (!prob->abstract && prob->use_stdin >= 0))
    unparse_bool(f, "use_stdin", prob->use_stdin);
  if (prob->input_file)
    fprintf(f, "input_file = \"%s\"\n", CARMOR(prob->input_file));
  if ((prob->abstract && prob->combined_stdin == 1)
      || (!prob->abstract && prob->combined_stdin >= 0))
    unparse_bool(f, "combined_stdin", prob->combined_stdin);
  if ((prob->abstract && prob->use_stdout == 1)
      || (!prob->abstract && prob->use_stdout >= 0))
    unparse_bool(f, "use_stdout", prob->use_stdout);
  if (prob->output_file)
    fprintf(f, "output_file = \"%s\"\n", CARMOR(prob->output_file));
  if ((prob->abstract && prob->combined_stdout == 1)
      || (!prob->abstract && prob->combined_stdout >= 0))
    unparse_bool(f, "combined_stdout", prob->combined_stdout);
  if ((prob->abstract && prob->binary_input == 1)
      || (!prob->abstract && prob->binary_input >= 0))
    unparse_bool(f, "binary_input", prob->binary_input);
  if ((prob->abstract && prob->binary > 0)
      || (!prob->abstract && prob->binary >= 0))
    unparse_bool(f, "binary", prob->binary);
  if ((prob->abstract && prob->ignore_exit_code == 1)
      || (!prob->abstract && prob->ignore_exit_code >= 0))
    unparse_bool(f, "ignore_exit_code", prob->ignore_exit_code);
  if ((prob->abstract && prob->ignore_term_signal == 1)
      || (!prob->abstract && prob->ignore_term_signal >= 0))
    unparse_bool(f, "ignore_term_signal", prob->ignore_term_signal);
  if ((prob->abstract && prob->olympiad_mode == 1)
      || (!prob->abstract && prob->olympiad_mode >= 0))
    unparse_bool(f, "olympiad_mode", prob->olympiad_mode);
  if ((prob->abstract && prob->score_latest == 1)
      || (!prob->abstract && prob->score_latest >= 0))
    unparse_bool(f, "score_latest", prob->score_latest);
  if ((prob->abstract && prob->score_latest_or_unmarked == 1)
      || (!prob->abstract && prob->score_latest_or_unmarked >= 0))
    unparse_bool(f, "score_latest_or_unmarked", prob->score_latest_or_unmarked);
  if ((prob->abstract && prob->score_latest_marked == 1)
      || (!prob->abstract && prob->score_latest_marked >= 0))
    unparse_bool(f, "score_latest_marked", prob->score_latest_marked);
  if ((prob->abstract && prob->score_tokenized > 0)
      || (!prob->abstract && prob->score_tokenized >= 0))
    unparse_bool(f, "score_tokenized", prob->score_tokenized);
  if (prob->xml_file)
    fprintf(f, "xml_file = \"%s\"\n", CARMOR(prob->xml_file));
  if (prob->alternatives_file)
    fprintf(f, "alternatives_file = \"%s\"\n", CARMOR(prob->alternatives_file));
  if (prob->plugin_file)
    fprintf(f, "plugin_file = \"%s\"\n", CARMOR(prob->plugin_file));
  if (prob->test_dir)
    fprintf(f, "test_dir = \"%s\"\n", CARMOR(prob->test_dir));

  if (prob->test_sfx) {
    int need = 0;
    if (aprob && aprob->test_sfx) {
      need = (strcmp(prob->test_sfx, aprob->test_sfx) != 0);
    } else if (global && global->test_sfx) {
      need = (strcmp(prob->test_sfx, global->test_sfx) != 0);
    } else {
      need = 1;
    }
    if (need) {
      fprintf(f, "test_sfx = \"%s\"\n", CARMOR(prob->test_sfx));
    }
  }
  if (prob->test_pat) {
    int need = 0;
    if (aprob && aprob->test_pat) {
      need = (strcmp(prob->test_pat, aprob->test_pat) != 0);
    } else if (global && global->test_pat) {
      need = (strcmp(prob->test_pat, global->test_pat) != 0);
    } else {
      need = 1;
    }
    if (need) {
      fprintf(f, "test_pat = \"%s\"\n", CARMOR(prob->test_pat));
    }
  }
  if ((prob->abstract && prob->use_corr == 1)
      || (!prob->abstract && prob->use_corr >= 0))
    unparse_bool(f, "use_corr", prob->use_corr);
  if (prob->corr_dir)
    fprintf(f, "corr_dir = \"%s\"\n", CARMOR(prob->corr_dir));
  if (prob->corr_sfx) {
    int need = 0;
    if (aprob && aprob->corr_sfx) {
      need = (strcmp(prob->corr_sfx, aprob->corr_sfx) != 0);
    } else if (global && global->corr_sfx) {
      need = (strcmp(prob->corr_sfx, global->corr_sfx) != 0);
    } else {
      need = 1;
    }
    if (need) {
      fprintf(f, "corr_sfx = \"%s\"\n", CARMOR(prob->corr_sfx));
    }
  }
  if (prob->corr_pat) {
    int need = 0;
    if (aprob && aprob->corr_pat) {
      need = (strcmp(prob->corr_pat, aprob->corr_pat) != 0);
    } else if (global && global->corr_pat) {
      need = (strcmp(prob->corr_pat, global->corr_pat) != 0);
    } else {
      need = 1;
    }
    if (need) {
      fprintf(f, "corr_pat = \"%s\"\n", CARMOR(prob->corr_pat));
    }
  }
  if ((prob->abstract && prob->use_info == 1)
      || (!prob->abstract && prob->use_info >= 0))
    unparse_bool(f, "use_info", prob->use_info);
  if (prob->info_dir)
    fprintf(f, "info_dir = \"%s\"\n", CARMOR(prob->info_dir));

  if (prob->info_sfx) {
    int need = 0;
    if (aprob && aprob->info_sfx) {
      need = (strcmp(prob->info_sfx, aprob->info_sfx) != 0);
    } else if (global && global->info_sfx) {
      need = (strcmp(prob->info_sfx, global->info_sfx) != 0);
    } else {
      need = (strcmp(prob->info_sfx, DFLT_G_INFO_SFX) != 0);
    }
    if (need) {
      fprintf(f, "info_sfx = \"%s\"\n", CARMOR(prob->info_sfx));
    }
  }
  if (prob->info_pat) {
    int need = 0;
    if (aprob && aprob->info_pat) {
      need = (strcmp(prob->info_pat, aprob->info_pat) != 0);
    } else {
      need = 1;
    }
    if (need) {
      fprintf(f, "info_pat = \"%s\"\n", CARMOR(prob->info_pat));
    }
  }
  if ((prob->abstract && prob->use_tgz == 1)
      || (!prob->abstract && prob->use_tgz >= 0))
    unparse_bool(f, "use_tgz", prob->use_tgz);
  if (prob->tgz_dir)
    fprintf(f, "tgz_dir = \"%s\"\n", CARMOR(prob->tgz_dir));
  if (prob->tgz_sfx) {
    int need = 0;
    if (aprob && aprob->tgz_sfx) {
      need = (strcmp(prob->tgz_sfx, aprob->tgz_sfx) != 0);
    } else if (global && global->tgz_sfx) {
      need = (strcmp(prob->tgz_sfx, global->tgz_sfx) != 0);
    } else {
      need = (strcmp(prob->tgz_sfx, DFLT_G_TGZ_SFX) != 0);
    }
    if (need) {
      fprintf(f, "tgz_sfx = \"%s\"\n", CARMOR(prob->tgz_sfx));
    }
  }
  if (prob->tgz_pat) {
    int need = 0;
    if (aprob && aprob->tgz_pat) {
      need = (strcmp(prob->tgz_pat, aprob->tgz_pat) != 0);
    } else {
      need = 1;
    }
    if (need) {
      fprintf(f, "tgz_pat = \"%s\"\n", CARMOR(prob->tgz_pat));
    }
  }
  if (prob->tgzdir_sfx) {
    int need = 0;
    if (aprob && aprob->tgzdir_sfx) {
      need = (strcmp(prob->tgzdir_sfx, aprob->tgzdir_sfx) != 0);
    } else if (global && global->tgzdir_sfx) {
      need = (strcmp(prob->tgzdir_sfx, global->tgzdir_sfx) != 0);
    } else {
      need = (strcmp(prob->tgzdir_sfx, DFLT_G_TGZDIR_SFX) != 0);
    }
    if (need) {
      fprintf(f, "tgzdir_sfx = \"%s\"\n", CARMOR(prob->tgzdir_sfx));
    }
  }
  if (prob->tgzdir_pat) {
    int need = 0;
    if (aprob && aprob->tgzdir_pat) {
      need = (strcmp(prob->tgzdir_pat, aprob->tgzdir_pat) != 0);
    } else {
      need = 1;
    }
    if (need) {
      fprintf(f, "tgzdir_pat = \"%s\"\n", CARMOR(prob->tgzdir_pat));
    }
  }
  /*
  if (prob->use_tgz != -1) unparse_bool(f, "use_tgz", prob->use_tgz);
  if (prob->tgz_dir[0])
    fprintf(f, "tgz_dir = \"%s\"\n", CARMOR(prob->tgz_dir));
  if (prob->tgz_sfx[0] != 1)
    fprintf(f, "tgz_sfx = \"%s\"\n", CARMOR(prob->tgz_sfx));
  if (prob->tgz_pat[0] != 1)
    fprintf(f, "tgz_pat = \"%s\"\n", CARMOR(prob->tgz_pat));
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
  if (prob->checker_time_limit_ms >= 0)
    fprintf(f, "checker_time_limit_ms = %d\n", prob->checker_time_limit_ms);
  if (prob->checker_max_vm_size >= 0)
    fprintf(f, "checker_max_vm_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->checker_max_vm_size));
  if (prob->checker_max_stack_size >= 0)
    fprintf(f, "checker_max_stack_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->checker_max_stack_size));
  if (prob->checker_max_rss_size >= 0)
    fprintf(f, "checker_max_rss_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->checker_max_rss_size));

  if (prob->max_vm_size >= 0)
    fprintf(f, "max_vm_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_vm_size));
  if (prob->max_stack_size >= 0)
    fprintf(f, "max_stack_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_stack_size));
  if (prob->max_rss_size >= 0)
    fprintf(f, "max_rss_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_rss_size));
  if (prob->max_data_size >= 0)
    fprintf(f, "max_data_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_data_size));
  if (prob->max_core_size >= 0)
    fprintf(f, "max_core_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_core_size));
  if (prob->max_file_size >= 0)
    fprintf(f, "max_file_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_file_size));
  if (prob->max_open_file_count >= 0) {
    fprintf(f, "max_open_file_count = %d\n", prob->max_open_file_count);
  }
  if (prob->max_process_count >= 0) {
    fprintf(f, "max_process_count = %d\n", prob->max_process_count);
  }
  if (prob->umask && prob->umask[0])
    fprintf(f, "umask = \"%s\"\n", CARMOR(prob->umask));

  if (score_system == SCORE_KIROV || score_system == SCORE_OLYMPIAD) {
    if (prob->full_score >= 0) {
      if ((prob->abstract && prob->full_score != DFLT_P_FULL_SCORE)
          || !prob->abstract)
        fprintf(f, "full_score = %d\n", prob->full_score);
    }
    if (prob->full_user_score >= 0 && global) {
      fprintf(f, "full_user_score = %d\n", prob->full_user_score);
    }
    if (prob->min_score_1 >= 0) {
      fprintf(f, "min_score_1 = %d\n", prob->min_score_1);
    }
    if (prob->min_score_2 >= 0) {
      fprintf(f, "min_score_2 = %d\n", prob->min_score_2);
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
    if (prob->compile_error_penalty != -1) {
        fprintf(f, "compile_error_penalty = %d\n", prob->compile_error_penalty);
    }
    if (prob->disqualified_penalty >= 0) {
      // FIXME: better condition
      if ((prob->abstract && prob->disqualified_penalty != prob->run_penalty)
          || !prob->abstract)
        fprintf(f, "disqualified_penalty = %d\n", prob->disqualified_penalty);
    }
    if (prob->test_score_list && prob->test_score_list[0])
      fprintf(f, "test_score_list = \"%s\"\n", CARMOR(prob->test_score_list));
    if (prob->score_bonus)
      fprintf(f, "score_bonus = \"%s\"\n", CARMOR(prob->score_bonus));
  }
  if (prob->open_tests && prob->open_tests[0]) {
    fprintf(f, "open_tests = \"%s\"\n", CARMOR(prob->open_tests));
  }
  if (prob->final_open_tests && prob->final_open_tests[0]) {
    fprintf(f, "final_open_tests = \"%s\"\n", CARMOR(prob->final_open_tests));
  }
  if (prob->token_open_tests && prob->token_open_tests[0]) {
    fprintf(f, "token_open_tests = \"%s\"\n", CARMOR(prob->token_open_tests));
  }
  if (prob->tokens && prob->tokens[0])
    fprintf(f, "tokens = \"%s\"\n", CARMOR(prob->tokens));
  if (score_system == SCORE_MOSCOW || score_system == SCORE_ACM) {
    if (prob->acm_run_penalty >= 0) {
      if ((prob->abstract && prob->acm_run_penalty != DFLT_P_ACM_RUN_PENALTY)
          || !prob->abstract)
        fprintf(f, "acm_run_penalty = %d\n", prob->acm_run_penalty);
    }
  }
  if (score_system == SCORE_MOSCOW) {
    if (prob->full_score >= 0) {
      if ((prob->abstract && prob->full_score != DFLT_P_FULL_SCORE)
          || !prob->abstract)
        fprintf(f, "full_score = %d\n", prob->full_score);
    }
    if (prob->full_user_score >= 0) {
      fprintf(f, "full_user_score = %d\n", prob->full_user_score);
    }
    if (prob->score_tests)
      fprintf(f, "score_tests = \"%s\"\n", CARMOR(prob->score_tests));
  }
  if (score_system == SCORE_OLYMPIAD) {
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
    if (prob->min_tests_to_accept >= 0) {
      fprintf(f, "min_tests_to_accept = %d\n", prob->min_tests_to_accept);
    }
  }
  if (prob->standard_checker)
    fprintf(f, "standard_checker = \"%s\"\n", CARMOR(prob->standard_checker));
  if (prob->check_cmd && prob->check_cmd[0])
    fprintf(f, "check_cmd = \"%s\"\n", CARMOR(prob->check_cmd));
  do_xstr(f, &ab, "checker_env", prob->checker_env);
  if (prob->valuer_cmd)
    fprintf(f, "valuer_cmd = \"%s\"\n", CARMOR(prob->valuer_cmd));
  do_xstr(f, &ab, "valuer_env", prob->valuer_env);
  if (prob->interactor_cmd && prob->interactor_cmd[0])
    fprintf(f,"interactor_cmd = \"%s\"\n",CARMOR(prob->interactor_cmd));
  do_xstr(f, &ab, "interactor_env", prob->interactor_env);
  if (prob->interactor_time_limit > 0) {
    fprintf(f, "interactor_time_limit = %d\n", prob->interactor_time_limit);
  }
  if (prob->interactor_real_time_limit > 0) {
    fprintf(f, "interactor_real_time_limit = %d\n", prob->interactor_real_time_limit);
  }
  if (prob->style_checker_cmd && prob->style_checker_cmd[0])
    fprintf(f,"style_checker_cmd = \"%s\"\n",CARMOR(prob->style_checker_cmd));
  do_xstr(f, &ab, "style_checker_env", prob->style_checker_env);
  do_xstr(f, &ab, "lang_compiler_env", prob->lang_compiler_env);
  do_xstr(f, &ab, "lang_compiler_container_options", prob->lang_compiler_container_options);
  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    fprintf(f,"test_checker_cmd = \"%s\"\n", CARMOR(prob->test_checker_cmd));
  }
  if (prob->test_generator_cmd && prob->test_generator_cmd[0]) {
    fprintf(f,"test_generator_cmd = \"%s\"\n", CARMOR(prob->test_generator_cmd));
  }
  if (prob->init_cmd && prob->init_cmd[0]) {
    fprintf(f,"init_cmd = \"%s\"\n", CARMOR(prob->init_cmd));
  }
  if (prob->start_cmd && prob->start_cmd[0]) {
    fprintf(f,"start_cmd = \"%s\"\n", CARMOR(prob->start_cmd));
  }
  if (prob->solution_src && prob->solution_src[0]) {
    fprintf(f,"solution_src = \"%s\"\n", CARMOR(prob->solution_src));
  }
  if (prob->solution_cmd && prob->solution_cmd[0]) {
    fprintf(f,"solution_cmd = \"%s\"\n", CARMOR(prob->solution_cmd));
  }
  if (prob->post_pull_cmd && prob->post_pull_cmd[0]) {
    fprintf(f,"post_pull_cmd = \"%s\"\n", CARMOR(prob->post_pull_cmd));
  }
  if (prob->vcs_compile_cmd && prob->vcs_compile_cmd[0]) {
    fprintf(f,"vcs_compile_cmd = \"%s\"\n", CARMOR(prob->vcs_compile_cmd));
  }
  do_xstr(f, &ab, "test_checker_env", prob->test_checker_env);
  do_xstr(f, &ab, "test_generator_env", prob->test_generator_env);
  do_xstr(f, &ab, "init_env", prob->init_env);
  do_xstr(f, &ab, "start_env", prob->start_env);
  do_xstr(f, &ab, "lang_time_adj", prob->lang_time_adj);
  do_xstr(f, &ab, "lang_time_adj_millis", prob->lang_time_adj_millis);
  do_xstr(f, &ab, "lang_max_vm_size", prob->lang_max_vm_size);
  do_xstr(f, &ab, "lang_max_stack_size", prob->lang_max_stack_size);
  do_xstr(f, &ab, "lang_max_rss_size", prob->lang_max_rss_size);
  do_xstr(f, &ab, "checker_extra_files", prob->checker_extra_files);
  do_xstr(f, &ab, "test_sets", prob->test_sets);
  do_xstr(f, &ab, "disable_language", prob->disable_language);
  do_xstr(f, &ab, "enable_language", prob->enable_language);
  do_xstr(f, &ab, "require", prob->require);
  do_xstr(f, &ab, "provide_ok", prob->provide_ok);
  do_xstr(f, &ab, "allow_ip", prob->allow_ip);
  do_xstr(f, &ab, "score_view", prob->score_view);
  do_xstr(f, &ab, "statement_env", prob->statement_env);

  if (!prob->abstract && prob->variant_num > 0) {
    fprintf(f, "variant_num = %d\n", prob->variant_num);
  }
  if ((prob->abstract > 0 && prob->autoassign_variants > 0)
      || (!prob->abstract && prob->autoassign_variants >= 0)) {
    unparse_bool(f, "autoassign_variants", prob->autoassign_variants);
  }

  if (prob->max_user_run_count > 0) {
    fprintf(f, "max_user_run_count = %d\n", prob->max_user_run_count);
  }

  if (prob->use_ac_not_ok >= 0)
    unparse_bool(f, "use_ac_not_ok", prob->use_ac_not_ok);
  if (prob->ok_status && prob->ok_status[0])
    fprintf(f, "ok_status = \"%s\"\n", CARMOR(prob->ok_status));
  if (prob->header_pat && prob->header_pat[0])
    fprintf(f, "header_pat = \"%s\"\n", CARMOR(prob->header_pat));
  if (prob->footer_pat && prob->footer_pat[0])
    fprintf(f, "footer_pat = \"%s\"\n", CARMOR(prob->footer_pat));
  if (prob->compiler_env_pat && prob->compiler_env_pat[0])
    fprintf(f, "compiler_env_pat = \"%s\"\n", CARMOR(prob->compiler_env_pat));
  if (prob->container_options && prob->container_options[0])
    fprintf(f, "container_options = \"%s\"\n", CARMOR(prob->container_options));
  if (prob->ignore_prev_ac >= 0)
    unparse_bool(f, "ignore_prev_ac", prob->ignore_prev_ac);
  if (prob->team_enable_rep_view >= 0)
    unparse_bool(f, "team_enable_rep_view", prob->team_enable_rep_view);
  if (prob->team_enable_ce_view >= 0)
    unparse_bool(f, "team_enable_ce_view", prob->team_enable_ce_view);
  if (prob->team_show_judge_report >= 0)
    unparse_bool(f, "team_show_judge_report", prob->team_show_judge_report);
  if (prob->show_checker_comment >= 0)
    unparse_bool(f, "show_checker_comment", prob->show_checker_comment);
  if (prob->ignore_compile_errors >= 0)
    unparse_bool(f, "ignore_compile_errors", prob->ignore_compile_errors);
  if (prob->disable_auto_testing >= 0)
    unparse_bool(f, "disable_auto_testing", prob->disable_auto_testing);
  if (prob->disable_user_submit >= 0)
    unparse_bool(f, "disable_user_submit", prob->disable_user_submit);
  if (prob->notify_on_submit >= 0)
    unparse_bool(f, "notify_on_submit", prob->notify_on_submit);
  if (prob->disable_tab >= 0)
    unparse_bool(f, "disable_tab", prob->disable_tab);
  if (prob->unrestricted_statement >= 0)
    unparse_bool(f, "unrestricted_statement", prob->unrestricted_statement);
  if (prob->statement_ignore_ip >= 0)
    unparse_bool(f, "statement_ignore_ip", prob->statement_ignore_ip);
  if (prob->enable_submit_after_reject >= 0)
    unparse_bool(f, "enable_submit_after_reject", prob->enable_submit_after_reject);
  if (prob->hide_file_names >= 0)
    unparse_bool(f, "hide_file_names", prob->hide_file_names);
  if (prob->hide_real_time_limit >= 0)
    unparse_bool(f, "hide_real_time_limit", prob->hide_real_time_limit);
  if (prob->enable_tokens >= 0)
    unparse_bool(f, "enable_tokens", prob->enable_tokens);
  if (prob->tokens_for_user_ac >= 0)
    unparse_bool(f, "tokens_for_user_ac", prob->tokens_for_user_ac);
  if (prob->disable_submit_after_ok >= 0)
    unparse_bool(f, "disable_submit_after_ok", prob->disable_submit_after_ok);
  if (prob->disable_security >= 0)
    unparse_bool(f, "disable_security", prob->disable_security);
  if (prob->enable_suid_run >= 0)
    unparse_bool(f, "enable_suid_run", prob->enable_suid_run);
  if (prob->enable_container >= 0)
    unparse_bool(f, "enable_container", prob->enable_container);
  if (prob->enable_dynamic_priority >= 0)
    unparse_bool(f, "enable_dynamic_priority", prob->enable_dynamic_priority);
  if (prob->enable_multi_header >= 0)
    unparse_bool(f, "enable_multi_header", prob->enable_multi_header);
  if (prob->use_lang_multi_header >= 0)
    unparse_bool(f, "use_lang_multi_header", prob->use_lang_multi_header);
  if (prob->require_any >= 0)
    unparse_bool(f, "require_any", prob->require_any);
  if (prob->disable_testing >= 0)
    unparse_bool(f, "disable_testing", prob->disable_testing);
  if (prob->enable_compilation >= 0)
    unparse_bool(f, "enable_compilation", prob->enable_compilation);
  if (prob->hidden >= 0) {
    if ((prob->abstract && prob->hidden)
        || !prob->abstract)
      unparse_bool(f, "hidden", prob->hidden);
  }
  if (prob->stand_hide_time >= 0
      && ((prob->abstract && prob->stand_hide_time) || !prob->abstract))
      unparse_bool(f, "stand_hide_time", prob->stand_hide_time);
  if (prob->advance_to_next >= 0
      && ((prob->abstract && prob->advance_to_next) || !prob->abstract))
      unparse_bool(f, "advance_to_next", prob->advance_to_next);
  if (prob->disable_ctrl_chars >= 0
      && ((prob->abstract && prob->disable_ctrl_chars) || !prob->abstract))
      unparse_bool(f, "disable_ctrl_chars", prob->disable_ctrl_chars);
  if (prob->valuer_sets_marked >= 0
      && ((prob->abstract && prob->valuer_sets_marked) || !prob->abstract))
      unparse_bool(f, "valuer_sets_marked", prob->valuer_sets_marked);
  if (prob->ignore_unmarked >= 0
      && ((prob->abstract && prob->ignore_unmarked) || !prob->abstract))
      unparse_bool(f, "ignore_unmarked", prob->ignore_unmarked);
  if (prob->disable_stderr >= 0
      && ((prob->abstract && prob->disable_stderr) || !prob->abstract))
      unparse_bool(f, "disable_stderr", prob->disable_stderr);
  if ((prob->abstract > 0 && prob->enable_process_group > 0)
      || (!prob->abstract && prob->enable_process_group >= 0)) {
    unparse_bool(f, "enable_process_group", prob->enable_process_group);
  }
  if ((prob->abstract > 0 && prob->enable_kill_all > 0)
      || (!prob->abstract && prob->enable_kill_all >= 0)) {
    unparse_bool(f, "enable_kill_all", prob->enable_kill_all);
  }
  if ((prob->abstract > 0 && prob->enable_testlib_mode > 0)
      || (!prob->abstract && prob->enable_testlib_mode >= 0)) {
    unparse_bool(f, "enable_testlib_mode", prob->enable_testlib_mode);
  }
  if ((prob->abstract > 0 && prob->enable_extended_info > 0)
      || (!prob->abstract && prob->enable_extended_info >= 0)) {
    unparse_bool(f, "enable_extended_info", prob->enable_extended_info);
  }
  if ((prob->abstract > 0 && prob->stop_on_first_fail > 0)
      || (!prob->abstract && prob->stop_on_first_fail >= 0)) {
    unparse_bool(f, "stop_on_first_fail", prob->stop_on_first_fail);
  }
  if ((prob->abstract > 0 && prob->enable_control_socket > 0)
      || (!prob->abstract && prob->enable_control_socket >= 0)) {
    unparse_bool(f, "enable_control_socket", prob->enable_control_socket);
  }
  if ((prob->abstract > 0 && prob->copy_exe_to_tgzdir > 0)
      || (!prob->abstract && prob->copy_exe_to_tgzdir >= 0)) {
    unparse_bool(f, "copy_exe_to_tgzdir", prob->copy_exe_to_tgzdir);
  }
  if ((prob->abstract > 0 && prob->hide_variant > 0)
      || (!prob->abstract && prob->hide_variant >= 0)) {
    unparse_bool(f, "hide_variant", prob->hide_variant);
  }
  if (prob->enable_text_form >= 0
      && ((prob->abstract && prob->enable_text_form) || !prob->abstract))
      unparse_bool(f, "enable_text_form", prob->enable_text_form);
  if ((prob->abstract > 0 && prob->enable_user_input > 0)
      || (!prob->abstract && prob->enable_user_input >= 0)) {
    unparse_bool(f, "enable_user_input", prob->enable_user_input);
  }
  if ((prob->abstract > 0 && prob->enable_vcs > 0)
      || (!prob->abstract && prob->enable_vcs >= 0)) {
    unparse_bool(f, "enable_vcs", prob->enable_vcs);
  }
  if ((prob->abstract > 0 && prob->enable_iframe_statement > 0)
      || (!prob->abstract && prob->enable_iframe_statement >= 0)) {
    unparse_bool(f, "enable_iframe_statement", prob->enable_iframe_statement);
  }
  if ((prob->abstract > 0 && prob->enable_src_for_testing > 0)
      || (!prob->abstract && prob->enable_src_for_testing >= 0)) {
    unparse_bool(f, "enable_src_for_testing", prob->enable_src_for_testing);
  }
  if ((prob->abstract > 0 && prob->disable_vm_size_limit > 0)
      || (!prob->abstract && prob->disable_vm_size_limit >= 0)) {
    unparse_bool(f, "disable_vm_size_limit", prob->disable_vm_size_limit);
  }
  if (prob->stand_ignore_score >= 0
      && ((prob->abstract && prob->stand_ignore_score) || !prob->abstract))
      unparse_bool(f, "stand_ignore_score", prob->stand_ignore_score);
  if (prob->stand_last_column >= 0
      && ((prob->abstract && prob->stand_last_column) || !prob->abstract))
      unparse_bool(f, "stand_last_column", prob->stand_last_column);
  if (!prob->abstract && prob->stand_column) {
    fprintf(f, "stand_column = \"%s\"\n", CARMOR(prob->stand_column));
  }
  if (prob->stand_name)
    fprintf(f, "stand_name = \"%s\"\n", CARMOR(prob->stand_name));

  if (!prob->abstract && prob->start_date > 0)
    fprintf(f, "start_date = \"%s\"\n", xml_unparse_date(prob->start_date));
  if (!prob->abstract && prob->deadline > 0)
    fprintf(f, "deadline = \"%s\"\n", xml_unparse_date(prob->deadline));
  if (prob->stand_attr)
    fprintf(f, "stand_attr = \"%s\"\n", CARMOR(prob->stand_attr));
  if (prob->source_header)
    fprintf(f, "source_header = \"%s\"\n", CARMOR(prob->source_header));
  if (prob->source_footer)
    fprintf(f, "source_footer = \"%s\"\n", CARMOR(prob->source_footer));
  if (prob->custom_compile_cmd)
    fprintf(f, "custom_compile_cmd = \"%s\"\n", CARMOR(prob->custom_compile_cmd));
  if (prob->custom_lang_name)
    fprintf(f, "custom_lang_name = \"%s\"\n", CARMOR(prob->custom_lang_name));
  if (prob->extra_src_dir)
    fprintf(f, "extra_src_dir = \"%s\"\n", CARMOR(prob->extra_src_dir));
  if (prob->normalization)
    fprintf(f, "normalization = \"%s\"\n", CARMOR(prob->normalization));
  if (prob->super_run_dir && prob->super_run_dir[0]) {
    fprintf(f,"super_run_dir = \"%s\"\n", CARMOR(prob->super_run_dir));
  }

  fprintf(f, "\n");
  if (prob->unhandled_vars) fprintf(f, "%s\n", prob->unhandled_vars);

  html_armor_free(&ab);
}

void
prepare_unparse_actual_prob(
        FILE *f,
        const struct section_problem_data *prob,
        const struct section_global_data *global,
        int show_paths)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char size_buf[64];

  fprintf(f, "[problem]\n");
  fprintf(f, "id = %d\n", prob->id);
  if (prob->abstract > 0) fprintf(f, "abstract\n");
  if (prob->super[0]) fprintf(f, "super = \"%s\"\n", CARMOR(prob->super));
  fprintf(f, "short_name = \"%s\"\n", CARMOR(prob->short_name));
  if (prob->long_name) {
    fprintf(f, "long_name = \"%s\"\n", CARMOR(prob->long_name));
  }
  if (prob->internal_name) fprintf(f, "internal_name = \"%s\"\n", CARMOR(prob->internal_name));
  if (prob->plugin_entry_name) {
    fprintf(f, "plugin_entry_name = \"%s\"\n", CARMOR(prob->plugin_entry_name));
  }
  if (prob->uuid && prob->uuid[0]) fprintf(f, "uuid = \"%s\"\n", CARMOR(prob->uuid));
  if (prob->problem_dir && prob->problem_dir[0]) fprintf(f, "problem_dir = \"%s\"\n", CARMOR(prob->problem_dir));
  fprintf(f, "type = \"%s\"\n", problem_unparse_type(prob->type));

  if (prob->scoring_checker > 0)
    unparse_bool(f, "scoring_checker", prob->scoring_checker);
  if (prob->enable_checker_token > 0)
    unparse_bool(f, "enable_checker_token", prob->enable_checker_token);
  if (prob->interactive_valuer > 0)
    unparse_bool(f, "interactive_valuer", prob->interactive_valuer);
  if (prob->disable_pe > 0)
    unparse_bool(f, "disable_pe", prob->disable_pe);
  if (prob->disable_wtl > 0)
    unparse_bool(f, "disable_wtl", prob->disable_wtl);
  if (prob->wtl_is_cf > 0)
    unparse_bool(f, "wtl_is_cf", prob->wtl_is_cf);
  if (prob->manual_checking > 0)
    unparse_bool(f, "manual_checking", prob->manual_checking);
  if (prob->examinator_num > 0)
    fprintf(f, "examinator_num = %d\n", prob->examinator_num);
  if (prob->check_presentation > 0)
    unparse_bool(f, "check_presentation", prob->check_presentation);
  if (prob->use_stdin > 0)
    unparse_bool(f, "use_stdin", prob->use_stdin);
  if (prob->input_file)
    fprintf(f, "input_file = \"%s\"\n", CARMOR(prob->input_file));
  if (prob->combined_stdin > 0)
    unparse_bool(f, "combined_stdin", prob->combined_stdin);
  if (prob->use_stdout > 0)
    unparse_bool(f, "use_stdout", prob->use_stdout);
  if (prob->output_file)
    fprintf(f, "output_file = \"%s\"\n", CARMOR(prob->output_file));
  if (prob->combined_stdout > 0)
    unparse_bool(f, "combined_stdout", prob->combined_stdout);
  if (prob->binary_input > 0)
    unparse_bool(f, "binary_input", prob->binary_input);
  if (prob->binary > 0)
    unparse_bool(f, "binary", prob->binary);
  if (prob->ignore_exit_code > 0)
    unparse_bool(f, "ignore_exit_code", prob->ignore_exit_code);
  if (prob->ignore_term_signal > 0)
    unparse_bool(f, "ignore_term_signal", prob->ignore_term_signal);
  if (prob->olympiad_mode > 0)
    unparse_bool(f, "olympiad_mode", prob->olympiad_mode);
  if (prob->score_latest > 0)
    unparse_bool(f, "score_latest", prob->score_latest);
  if (prob->score_latest_or_unmarked > 0)
    unparse_bool(f, "score_latest_or_unmarked", prob->score_latest_or_unmarked);
  if (prob->score_latest_marked > 0)
    unparse_bool(f, "score_latest_marked", prob->score_latest_marked);
  if (prob->score_tokenized > 0)
    unparse_bool(f, "score_tokenized", prob->score_tokenized);
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->xml_file)
    fprintf(f, "xml_file = \"%s\"\n", CARMOR(prob->xml_file));
  if (show_paths && prob->alternatives_file)
    fprintf(f, "alternatives_file = \"%s\"\n", CARMOR(prob->alternatives_file));
  if (show_paths && prob->statement_file)
    fprintf(f, "statement_file = \"%s\"\n", CARMOR(prob->statement_file));
  if (show_paths && prob->plugin_file)
    fprintf(f, "plugin_file = \"%s\"\n", CARMOR(prob->plugin_file));

  if (show_paths && prob->test_dir)
    fprintf(f, "test_dir = \"%s\"\n", CARMOR(prob->test_dir));
  if (prob->test_pat) {
    fprintf(f, "test_pat = \"%s\"\n", CARMOR(prob->test_pat));
  } else if (prob->test_sfx) {
    fprintf(f, "test_sfx = \"%s\"\n", CARMOR(prob->test_sfx));
  }

  if (prob->use_corr > 0) {
    unparse_bool(f, "use_corr", prob->use_corr);
    if (show_paths && prob->corr_dir)
      fprintf(f, "corr_dir = \"%s\"\n", CARMOR(prob->corr_dir));
    if (prob->corr_pat) {
      fprintf(f, "corr_pat = \"%s\"\n", CARMOR(prob->corr_pat));
    } else if (prob->corr_sfx) {
      fprintf(f, "corr_sfx = \"%s\"\n", CARMOR(prob->corr_sfx));
    }
  }

  if (prob->use_info > 0) {
    unparse_bool(f, "use_info", prob->use_info);
    if (show_paths && prob->info_dir)
      fprintf(f, "info_dir = \"%s\"\n", CARMOR(prob->info_dir));
    if (prob->info_pat) {
      fprintf(f, "info_pat = \"%s\"\n", CARMOR(prob->info_pat));
    } else if (prob->info_sfx) {
      fprintf(f, "info_sfx = \"%s\"\n", CARMOR(prob->info_sfx));
    }
  }

  if (prob->use_tgz > 0) {
    unparse_bool(f, "use_tgz", prob->use_tgz);
    if (show_paths && prob->tgz_dir)
      fprintf(f, "tgz_dir = \"%s\"\n", CARMOR(prob->tgz_dir));
    if (prob->tgz_pat) {
      fprintf(f, "tgz_pat = \"%s\"\n", CARMOR(prob->tgz_pat));
    } else if (prob->tgz_sfx) {
      fprintf(f, "tgz_sfx = \"%s\"\n", CARMOR(prob->tgz_sfx));
    }
    if (prob->tgzdir_pat) {
      fprintf(f, "tgzdir_pat = \"%s\"\n", CARMOR(prob->tgzdir_pat));
    } else if (prob->tgzdir_sfx) {
      fprintf(f, "tgzdir_sfx = \"%s\"\n", CARMOR(prob->tgzdir_sfx));
    }
  }

  if (prob->time_limit_millis > 0) {
    fprintf(f, "time_limit_millis = %d\n", prob->time_limit_millis);
  } else if (prob->time_limit > 0) {
    fprintf(f, "time_limit = %d\n", prob->time_limit);
  }
  if (prob->real_time_limit > 0)
    fprintf(f, "real_time_limit = %d\n", prob->real_time_limit);
  if (prob->checker_real_time_limit > 0)
    fprintf(f, "checker_real_time_limit = %d\n", prob->checker_real_time_limit);
  if (prob->checker_time_limit_ms > 0)
    fprintf(f, "checker_time_limit_ms = %d\n", prob->checker_time_limit_ms);
  if (prob->checker_max_vm_size >= 0)
    fprintf(f, "checker_max_vm_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->checker_max_vm_size));
  if (prob->checker_max_stack_size >= 0)
    fprintf(f, "checker_max_stack_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->checker_max_stack_size));
  if (prob->checker_max_rss_size >= 0)
    fprintf(f, "checker_max_rss_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->checker_max_rss_size));

  if (prob->max_vm_size >= 0)
    fprintf(f, "max_vm_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_vm_size));
  if (prob->max_stack_size >= 0)
    fprintf(f, "max_stack_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_stack_size));
  if (prob->max_rss_size >= 0)
    fprintf(f, "max_rss_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_rss_size));
  if (prob->max_data_size >= 0)
    fprintf(f, "max_data_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_data_size));
  if (prob->max_core_size >= 0)
    fprintf(f, "max_core_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_core_size));
  if (prob->max_file_size >= 0)
    fprintf(f, "max_file_size = %s\n", ll_to_size_str(size_buf, sizeof(size_buf), prob->max_file_size));
  if (prob->max_open_file_count > 0) {
    fprintf(f, "max_open_file_count = %d\n", prob->max_open_file_count);
  }
  if (prob->max_process_count > 0) {
    fprintf(f, "max_process_count = %d\n", prob->max_process_count);
  }
  if (prob->umask && prob->umask[0])
    fprintf(f, "umask = \"%s\"\n", CARMOR(prob->umask));

  if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD) {
    if (prob->full_score >= 0)
      fprintf(f, "full_score = %d\n", prob->full_score);
    if (prob->full_user_score >= 0)
      fprintf(f, "full_user_score = %d\n", prob->full_user_score);
    if (prob->min_score_1 >= 0) {
      fprintf(f, "min_score_1 = %d\n", prob->min_score_1);
    }
    if (prob->min_score_2 >= 0) {
      fprintf(f, "min_score_2 = %d\n", prob->min_score_2);
    }
    if (prob->test_score >= 0)
      fprintf(f, "test_score = %d\n", prob->test_score);
    if (prob->variable_full_score > 0)
      unparse_bool(f, "variable_full_score", prob->variable_full_score);
    if (prob->run_penalty >= 0)
      fprintf(f, "run_penalty = %d\n", prob->run_penalty);
    if (prob->compile_error_penalty != -1)
      fprintf(f, "compile_error_penalty = %d\n", prob->compile_error_penalty);
    if (prob->disqualified_penalty >= 0)
      fprintf(f, "disqualified_penalty = %d\n", prob->disqualified_penalty);
    if (prob->test_score_list && prob->test_score_list[0])
      fprintf(f, "test_score_list = \"%s\"\n", CARMOR(prob->test_score_list));
    if (prob->score_bonus)
      fprintf(f, "score_bonus = \"%s\"\n", CARMOR(prob->score_bonus));
    if (prob->score_multiplier > 0)
      fprintf(f, "score_multiplier = %d\n", prob->score_multiplier);
  }
  if (global->score_system == SCORE_MOSCOW || global->score_system == SCORE_ACM) {
    if (prob->acm_run_penalty >= 0)
      fprintf(f, "acm_run_penalty = %d\n", prob->acm_run_penalty);
    if (prob->ignore_penalty > 0)
      unparse_bool(f, "ignore_penalty", prob->ignore_penalty);
  }
  if (global->score_system == SCORE_MOSCOW) {
    if (prob->full_score >= 0)
      fprintf(f, "full_score = %d\n", prob->full_score);
    if (prob->full_user_score >= 0)
      fprintf(f, "full_user_score = %d\n", prob->full_user_score);
    if (prob->score_tests)
      fprintf(f, "score_tests = \"%s\"\n", CARMOR(prob->score_tests));
  }
  if (global->score_system == SCORE_OLYMPIAD) {
    if (prob->tests_to_accept > 0)
      fprintf(f, "tests_to_accept = %d\n", prob->tests_to_accept);
    if (prob->accept_partial > 0)
      unparse_bool(f, "accept_partial", prob->accept_partial);
    if (prob->min_tests_to_accept >= 0)
      fprintf(f, "min_tests_to_accept = %d\n", prob->min_tests_to_accept);
  }

  if (prob->open_tests && prob->open_tests[0])
    fprintf(f, "open_tests = \"%s\"\n", CARMOR(prob->open_tests));
  if (prob->final_open_tests && prob->final_open_tests[0])
    fprintf(f, "final_open_tests = \"%s\"\n", CARMOR(prob->final_open_tests));
  if (prob->token_open_tests && prob->token_open_tests[0])
    fprintf(f, "token_open_tests = \"%s\"\n", CARMOR(prob->token_open_tests));
  if (prob->tokens && prob->tokens[0])
    fprintf(f, "tokens = \"%s\"\n", CARMOR(prob->tokens));

  if (prob->standard_checker)
    fprintf(f, "standard_checker = \"%s\"\n", CARMOR(prob->standard_checker));
  if (!prob->standard_checker && (show_paths || (global && global->advanced_layout > 0)) && prob->check_cmd)
    fprintf(f, "check_cmd = \"%s\"\n", CARMOR(prob->check_cmd));
  do_xstr(f, &ab, "checker_env", prob->checker_env);
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->valuer_cmd)
    fprintf(f, "valuer_cmd = \"%s\"\n", CARMOR(prob->valuer_cmd));
  do_xstr(f, &ab, "valuer_env", prob->valuer_env);
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->interactor_cmd && prob->interactor_cmd[0])
    fprintf(f,"interactor_cmd = \"%s\"\n",CARMOR(prob->interactor_cmd));
  do_xstr(f, &ab, "interactor_env", prob->interactor_env);
  if (prob->interactor_time_limit > 0)
    fprintf(f, "interactor_time_limit = %d\n", prob->interactor_time_limit);
  if (prob->interactor_real_time_limit > 0)
    fprintf(f, "interactor_real_time_limit = %d\n", prob->interactor_real_time_limit);
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->style_checker_cmd && prob->style_checker_cmd[0])
    fprintf(f,"style_checker_cmd = \"%s\"\n",CARMOR(prob->style_checker_cmd));
  do_xstr(f, &ab, "style_checker_env", prob->style_checker_env);
  do_xstr(f, &ab, "lang_compiler_container_options", prob->lang_compiler_container_options);
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    fprintf(f,"test_checker_cmd = \"%s\"\n", CARMOR(prob->test_checker_cmd));
  }
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->test_generator_cmd && prob->test_generator_cmd[0]) {
    fprintf(f,"test_generator_cmd = \"%s\"\n", CARMOR(prob->test_generator_cmd));
  }
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->init_cmd && prob->init_cmd[0]) {
    fprintf(f,"init_cmd = \"%s\"\n", CARMOR(prob->init_cmd));
  }
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->start_cmd && prob->start_cmd[0]) {
    fprintf(f,"start_cmd = \"%s\"\n", CARMOR(prob->start_cmd));
  }
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->solution_src && prob->solution_src[0]) {
    fprintf(f,"solution_src = \"%s\"\n", CARMOR(prob->solution_src));
  }
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->solution_cmd && prob->solution_cmd[0]) {
    fprintf(f,"solution_cmd = \"%s\"\n", CARMOR(prob->solution_cmd));
  }
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->post_pull_cmd && prob->post_pull_cmd[0]) {
    fprintf(f,"post_pull_cmd = \"%s\"\n", CARMOR(prob->post_pull_cmd));
  }
  if ((show_paths || (global && global->advanced_layout > 0)) && prob->vcs_compile_cmd && prob->vcs_compile_cmd[0]) {
    fprintf(f,"vcs_compile_cmd = \"%s\"\n", CARMOR(prob->vcs_compile_cmd));
  }
  do_xstr(f, &ab, "test_checker_env", prob->test_checker_env);
  do_xstr(f, &ab, "test_generator_env", prob->test_generator_env);
  do_xstr(f, &ab, "init_env", prob->init_env);
  do_xstr(f, &ab, "start_env", prob->start_env);
  do_xstr(f, &ab, "lang_time_adj", prob->lang_time_adj);
  do_xstr(f, &ab, "lang_time_adj_millis", prob->lang_time_adj_millis);
  do_xstr(f, &ab, "lang_max_vm_size", prob->lang_max_vm_size);
  do_xstr(f, &ab, "lang_max_stack_size", prob->lang_max_stack_size);
  do_xstr(f, &ab, "lang_max_rss_size", prob->lang_max_rss_size);
  do_xstr(f, &ab, "checker_extra_files", prob->checker_extra_files);
  do_xstr(f, &ab, "test_sets", prob->test_sets);
  do_xstr(f, &ab, "disable_language", prob->disable_language);
  do_xstr(f, &ab, "enable_language", prob->enable_language);
  do_xstr(f, &ab, "require", prob->require);
  do_xstr(f, &ab, "provide_ok", prob->provide_ok);
  do_xstr(f, &ab, "allow_ip", prob->allow_ip);
  do_xstr(f, &ab, "score_view", prob->score_view);
  do_xstr(f, &ab, "date_penalty", prob->date_penalty);
  do_xstr(f, &ab, "group_start_date", prob->group_start_date);
  do_xstr(f, &ab, "group_deadline", prob->group_deadline);
  do_xstr(f, &ab, "personal_deadline", prob->personal_deadline);
  do_xstr(f, &ab, "score_view", prob->score_view);
  do_xstr(f, &ab, "score_view_text", prob->score_view_text);
  do_xstr(f, &ab, "statement_env", prob->statement_env);

  if (prob->variant_num > 0)
    fprintf(f, "variant_num = %d\n", prob->variant_num);
   if (prob->autoassign_variants > 0)
    unparse_bool(f, "autoassign_variants", prob->autoassign_variants);

  if (prob->use_ac_not_ok > 0)
    unparse_bool(f, "use_ac_not_ok", prob->use_ac_not_ok);
  if (prob->ok_status && prob->ok_status[0])
    fprintf(f, "ok_status = \"%s\"\n", CARMOR(prob->ok_status));
  if (prob->header_pat && prob->header_pat[0])
    fprintf(f, "header_pat = \"%s\"\n", CARMOR(prob->header_pat));
  if (prob->footer_pat && prob->footer_pat[0])
    fprintf(f, "footer_pat = \"%s\"\n", CARMOR(prob->footer_pat));
  if (prob->compiler_env_pat && prob->compiler_env_pat[0])
    fprintf(f, "compiler_env_pat = \"%s\"\n", CARMOR(prob->compiler_env_pat));
  if (prob->container_options && prob->container_options[0])
    fprintf(f, "container_options = \"%s\"\n", CARMOR(prob->container_options));
  if (prob->ignore_prev_ac > 0)
    unparse_bool(f, "ignore_prev_ac", prob->ignore_prev_ac);
  if (prob->team_enable_rep_view > 0)
    unparse_bool(f, "team_enable_rep_view", prob->team_enable_rep_view);
  if (prob->team_enable_ce_view > 0)
    unparse_bool(f, "team_enable_ce_view", prob->team_enable_ce_view);
  if (prob->team_show_judge_report > 0)
    unparse_bool(f, "team_show_judge_report", prob->team_show_judge_report);
  if (prob->show_checker_comment > 0)
    unparse_bool(f, "show_checker_comment", prob->show_checker_comment);
  if (prob->ignore_compile_errors > 0)
    unparse_bool(f, "ignore_compile_errors", prob->ignore_compile_errors);
  if (prob->disable_auto_testing > 0)
    unparse_bool(f, "disable_auto_testing", prob->disable_auto_testing);
  if (prob->disable_user_submit > 0)
    unparse_bool(f, "disable_user_submit", prob->disable_user_submit);
  if (prob->notify_on_submit > 0)
    unparse_bool(f, "notify_on_submit", prob->notify_on_submit);
  if (prob->disable_tab > 0)
    unparse_bool(f, "disable_tab", prob->disable_tab);
  if (prob->unrestricted_statement > 0)
    unparse_bool(f, "unrestricted_statement", prob->unrestricted_statement);
  if (prob->statement_ignore_ip > 0)
    unparse_bool(f, "statement_ignore_ip", prob->statement_ignore_ip);
  if (prob->enable_submit_after_reject > 0)
    unparse_bool(f, "enable_submit_after_reject", prob->enable_submit_after_reject);
  if (prob->hide_file_names > 0)
    unparse_bool(f, "hide_file_names", prob->hide_file_names);
  if (prob->hide_real_time_limit > 0)
    unparse_bool(f, "hide_real_time_limit", prob->hide_real_time_limit);
  if (prob->enable_tokens > 0)
    unparse_bool(f, "enable_tokens", prob->enable_tokens);
  if (prob->tokens_for_user_ac > 0)
    unparse_bool(f, "tokens_for_user_ac", prob->tokens_for_user_ac);
  if (prob->disable_submit_after_ok > 0)
    unparse_bool(f, "disable_submit_after_ok", prob->disable_submit_after_ok);
  if (prob->disable_security > 0)
    unparse_bool(f, "disable_security", prob->disable_security);
  if (prob->enable_suid_run > 0)
    unparse_bool(f, "enable_suid_run", prob->enable_suid_run);
  if (prob->enable_container > 0)
    unparse_bool(f, "enable_container", prob->enable_container);
  if (prob->enable_dynamic_priority > 0)
    unparse_bool(f, "enable_dynamic_priority", prob->enable_dynamic_priority);
  if (prob->enable_multi_header > 0)
    unparse_bool(f, "enable_multi_header", prob->enable_multi_header);
  if (prob->use_lang_multi_header > 0)
    unparse_bool(f, "use_lang_multi_header", prob->use_lang_multi_header);
  if (prob->require_any > 0)
    unparse_bool(f, "require_any", prob->require_any);
  if (prob->disable_testing > 0)
    unparse_bool(f, "disable_testing", prob->disable_testing);
  if (prob->skip_testing  > 0)
    unparse_bool(f, "skip_testing", prob->skip_testing);
  if (prob->priority_adjustment > 0)
    fprintf(f, "priority_adjustment = %d\n", prob->priority_adjustment);
  if (prob->enable_compilation > 0)
    unparse_bool(f, "enable_compilation", prob->enable_compilation);
  if (prob->hidden > 0)
    unparse_bool(f, "hidden", prob->hidden);
  if (prob->stand_hide_time > 0)
    unparse_bool(f, "stand_hide_time", prob->stand_hide_time);
  if (prob->advance_to_next > 0)
    unparse_bool(f, "advance_to_next", prob->advance_to_next);
  if (prob->prev_runs_to_show > 0)
    fprintf(f, "prev_runs_to_show = %d\n", prob->prev_runs_to_show);
  if (prob->max_user_run_count > 0)
    fprintf(f, "max_user_run_count = %d\n", prob->max_user_run_count);
  if (prob->disable_ctrl_chars > 0)
    unparse_bool(f, "disable_ctrl_chars", prob->disable_ctrl_chars);
  if (prob->valuer_sets_marked > 0)
    unparse_bool(f, "valuer_sets_marked", prob->valuer_sets_marked);
  if (prob->ignore_unmarked > 0)
    unparse_bool(f, "ignore_unmarked", prob->ignore_unmarked);
  if (prob->disable_stderr > 0)
    unparse_bool(f, "disable_stderr", prob->disable_stderr);
  if (prob->enable_process_group > 0)
    unparse_bool(f, "enable_process_group", prob->enable_process_group);
  if (prob->enable_kill_all > 0)
    unparse_bool(f, "enable_kill_all", prob->enable_kill_all);
  if (prob->enable_testlib_mode > 0)
    unparse_bool(f, "enable_testlib_mode", prob->enable_testlib_mode);
  if (prob->enable_extended_info > 0)
    unparse_bool(f, "enable_extended_info", prob->enable_extended_info);
  if (prob->stop_on_first_fail > 0)
    unparse_bool(f, "stop_on_first_fail", prob->stop_on_first_fail);
  if (prob->enable_control_socket > 0)
    unparse_bool(f, "enable_control_socket", prob->enable_control_socket);
  if (prob->copy_exe_to_tgzdir > 0)
    unparse_bool(f, "copy_exe_to_tgzdir", prob->copy_exe_to_tgzdir);
  if (prob->hide_variant > 0)
    unparse_bool(f, "hide_variant", prob->hide_variant);
  if (prob->enable_text_form > 0)
    unparse_bool(f, "enable_text_form", prob->enable_text_form);
  if (prob->enable_user_input > 0)
    unparse_bool(f, "enable_user_input", prob->enable_user_input);
  if (prob->enable_vcs > 0)
    unparse_bool(f, "enable_vcs", prob->enable_vcs);
  if (prob->enable_iframe_statement > 0)
    unparse_bool(f, "enable_iframe_statement", prob->enable_iframe_statement);
  if (prob->enable_src_for_testing > 0)
    unparse_bool(f, "enable_src_for_testing", prob->enable_src_for_testing);
  if (prob->disable_vm_size_limit > 0)
    unparse_bool(f, "disable_vm_size_limit", prob->disable_vm_size_limit);
  if (prob->disable_vm_size_limit > 0)
    unparse_bool(f, "disable_vm_size_limit", prob->disable_vm_size_limit);
  if (prob->stand_ignore_score > 0)
    unparse_bool(f, "stand_ignore_score", prob->stand_ignore_score);
  if (prob->stand_last_column > 0)
    unparse_bool(f, "stand_last_column", prob->stand_last_column);
  if (prob->stand_column)
    fprintf(f, "stand_column = \"%s\"\n", CARMOR(prob->stand_column));
  if (prob->stand_name)
    fprintf(f, "stand_name = \"%s\"\n", CARMOR(prob->stand_name));
  if (prob->group_name)
    fprintf(f, "group_name = \"%s\"\n", CARMOR(prob->group_name));
  if (prob->spelling)
    fprintf(f, "spelling = \"%s\"\n", CARMOR(prob->spelling));

  if (prob->start_date > 0)
    fprintf(f, "start_date = \"%s\"\n", xml_unparse_date(prob->start_date));
  if (prob->deadline > 0)
    fprintf(f, "deadline = \"%s\"\n", xml_unparse_date(prob->deadline));
  if (prob->stand_attr)
    fprintf(f, "stand_attr = \"%s\"\n", CARMOR(prob->stand_attr));
  if (prob->source_header)
    fprintf(f, "source_header = \"%s\"\n", CARMOR(prob->source_header));
  if (prob->source_footer)
    fprintf(f, "source_footer = \"%s\"\n", CARMOR(prob->source_footer));
  if (prob->custom_compile_cmd)
    fprintf(f, "custom_compile_cmd = \"%s\"\n", CARMOR(prob->custom_compile_cmd));
  if (prob->custom_lang_name)
    fprintf(f, "custom_lang_name = \"%s\"\n", CARMOR(prob->custom_lang_name));
  if (prob->extra_src_dir)
    fprintf(f, "extra_src_dir = \"%s\"\n", CARMOR(prob->extra_src_dir));
  if (prob->normalization)
    fprintf(f, "normalization = \"%s\"\n", CARMOR(prob->normalization));
  if (prob->extid && prob->extid[0])
    fprintf(f, "extid = \"%s\"\n", CARMOR(prob->extid));

  html_armor_free(&ab);
}

/*
 * Unhandled problem variables:
 *
  PROBLEM_PARAM(use_tgz, "d"),
  PROBLEM_PARAM(priority_adjustment, "d"),
  PROBLEM_PARAM(spelling, "s"),
  PROBLEM_PARAM(score_multiplier, "d"),
  PROBLEM_PARAM(prev_runs_to_show, "d"),
  PROBLEM_PARAM(ignore_penalty, "d"),
  PROBLEM_PARAM(date_penalty, "x"),
  PROBLEM_PARAM(group_start_date, "x"),
  PROBLEM_PARAM(group_deadline, "x"),
  PROBLEM_PARAM(tgz_pat, "s"),
  PROBLEM_PARAM(personal_deadline, "x"),
  PROBLEM_PARAM(skip_testing, "d"),
  PROBLEM_PARAM(statement_file, "s"),
  PROBLEM_PARAM(group_name, "s"),
*/
void
prepare_unparse_unhandled_prob(
        FILE *f,
        const struct section_problem_data *prob,
        const struct section_global_data *global)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  /*
  //PROBLEM_PARAM(use_tgz, "d"),
  if (prob->use_tgz >= 0) {
    if (prob->use_tgz || !prob->abstract)
      unparse_bool(f, "use_tgz", prob->use_tgz);
  }
  */
  /*
  //PROBLEM_PARAM(tgz_dir, "s"),
  do_str(f, &ab, "tgz_dir", prob->tgz_dir);
  //PROBLEM_PARAM(tgz_sfx, "s"),
  if (prob->tgz_sfx[0] != 1) {
    if ((prob->abstract
         && ((global->tgz_sfx[0] && strcmp(prob->tgz_sfx, global->tgz_sfx))
             || (!global->tgz_sfx[0] && strcmp(prob->tgz_sfx, DFLT_G_TGZ_SFX))))
        || !prob->abstract)
      do_str_mb_empty(f, &ab, "tgz_sfx", prob->tgz_sfx);
  }
  //PROBLEM_PARAM(tgz_pat, "s"),
  if (prob->tgz_pat[0] != 1) {
    if (strcmp(prob->tgz_pat, global->tgz_pat) || !prob->abstract)
      do_str_mb_empty(f, &ab, "tgz_pat", prob->tgz_pat);
  }
  */
  //PROBLEM_PARAM(skip_testing, "d"),
  if (prob->skip_testing > 0) {
    fprintf(f, "skip_testing = %d\n", prob->skip_testing);
  }
  if (prob->ignore_penalty > 0) {
    fprintf(f, "ignore_penalty\n");
  }
  //PROBLEM_PARAM(priority_adjustment, "d"),
  if (prob->priority_adjustment != -1000) {
    if (prob->priority_adjustment || !prob->abstract)
      fprintf(f, "priority_adjustment = %d\n", prob->priority_adjustment);
  }
  //PROBLEM_PARAM(group_name, "s"),
  do_str(f, &ab, "group_name", prob->group_name);
  //PROBLEM_PARAM(spelling, "s"),
  do_str(f, &ab, "spelling", prob->spelling);
  //PROBLEM_PARAM(score_multiplier, "d"),
  if (prob->score_multiplier)
    fprintf(f, "score_multiplier = %d\n", prob->score_multiplier);
  if (prob->prev_runs_to_show > 0)
    fprintf(f, "prev_runs_to_show = %d\n", prob->prev_runs_to_show);
  //PROBLEM_PARAM(date_penalty, "x"),
  do_xstr(f, &ab, "date_penalty", prob->date_penalty);
  //PROBLEM_PARAM(group_start_date, "x"),
  do_xstr(f, &ab, "group_start_date", prob->group_start_date);
  //PROBLEM_PARAM(group_deadline, "x"),
  do_xstr(f, &ab, "group_deadline", prob->group_deadline);
  //PROBLEM_PARAM(personal_deadline, "x"),
  do_xstr(f, &ab, "personal_deadline", prob->personal_deadline);
  //PROBLEM_PARAM(statement_file, "s"),
  do_str(f, &ab, "statement_file", prob->statement_file);
  //PROBLEM_PARAM(alternative, "x"),
  do_xstr(f, &ab, "alternative", prob->alternative);

  html_armor_free(&ab);
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
  ARCH_LINUX_SHARED_32,
  ARCH_DOS,
  ARCH_JAVA,
  ARCH_JAVA14,
  ARCH_PERL,
  ARCH_MSIL,
  ARCH_WIN32,
  ARCH_VALGRIND,
  ARCH_DOTNET,

  ARCH_LAST,
};

static const unsigned char * const supported_archs[] =
{
  "",                           /* default - Linux static */
  "linux-shared",
  "linux-shared-32",
  "dos",
  "java",
  "java14",
  "perl",
  "msil",
  "win32",
  "valgrind",
  "dotnet",

  0,
};
static const unsigned char * const arch_abstract_names [] =
{
  "Generic",
  "Linux-shared",
  "Linux-shared-32",
  "DOSTester",
  "Linux-java",
  "Linux-java14",
  "Perl",
  "Linux-msil",
  "Win32",
  "Valgrind",
  "Dotnet",

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
generate_abstract_tester(
        FILE *f,
        int arch,
        int secure_run,
        int use_files,
        int total_abstr_testers,
        struct section_tester_data **abstr_testers,
        const unsigned char *testing_work_dir,
        const unsigned char *contests_home_dir)
{
  //unsigned char nbuf[256], nbuf2[256];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int i;
  struct section_tester_data *atst = 0;

#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!contests_home_dir) contests_home_dir = EJUDGE_CONTESTS_HOME_DIR;
#endif

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
            "memory_limit_type = \"default\"\n"
            "secure_exec_type = \"static\"\n",
            arch_abstract_names[arch], supported_archs[arch]);
    if (!atst) {
      fprintf(f, "clear_env\n"
              "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
              "start_env = \"HOME\"\n");
    }
    /*
    if (max_vm_size != -1L)
      fprintf(f, "max_vm_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    if (max_stack_size != -1L)
      fprintf(f, "max_stack_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
    */
    /*
#if CONF_HAS_LIBCAP - 0 == 1
    if (secure_run)
      fprintf(f, "start_cmd = \"capexec\"\n");
#endif
    */
    break;

  case ARCH_LINUX_SHARED:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "no_core_dump\n"
            "enable_memory_limit_error\n"
            "kill_signal = KILL\n"
            "memory_limit_type = \"default\"\n"
            "secure_exec_type = \"dll\"\n",
            arch_abstract_names[arch], supported_archs[arch]);
    /*
    if (max_vm_size != -1L)
      fprintf(f, "max_vm_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    if (max_stack_size != -1L)
      fprintf(f, "max_stack_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
    */
    /*
#if CONF_HAS_LIBCAP - 0 == 1
    if (secure_run)
      fprintf(f, "start_env = \"LD_BIND_NOW=1\"\n"
              "start_env = \"LD_PRELOAD=${script_dir}/lang/libdropcaps.so\"\n");
#endif
    */
    if (!atst) {
      fprintf(f, "clear_env\n"
              "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
              "start_env = \"HOME\"\n");
    }
    break;

  case ARCH_LINUX_SHARED_32:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "no_core_dump\n"
            "enable_memory_limit_error\n"
            "kill_signal = KILL\n"
            "memory_limit_type = \"default\"\n"
            "secure_exec_type = \"dll32\"\n",
            arch_abstract_names[arch], supported_archs[arch]);
    if (!atst) {
      fprintf(f, "clear_env\n"
              "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
              "start_env = \"HOME\"\n");
    }
    break;

  case ARCH_JAVA:
  case ARCH_JAVA14:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "no_core_dump\n"
            "kill_signal = TERM\n"
            "memory_limit_type = \"java\"\n"
            "secure_exec_type = \"java\"\n"
            "start_cmd = \"runjava%s\"\n",
            arch_abstract_names[arch], supported_archs[arch],
            arch == ARCH_JAVA14?"14":"");
    /* FIXME: add special java parameter
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
    */
    /*
    if (!secure_run) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_POLICY=none\"\n");
    } else if (use_files) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_POLICY=fileio.policy\"\n");
    }
    */
    if (!atst) {
      fprintf(f, "start_env = \"LANG=C\"\n"
              "start_env = \"EJUDGE_PREFIX_DIR\"\n");
    }
    break;

  case ARCH_DOS:
    fprintf(f, "[tester]\n"
            "name = DOSTester\n"
            "arch = dos\n"
            "abstract\n"
            "no_core_dump\n"
            "no_redirect\n"
            "ignore_stderr\n"
            "time_limit_adjustment\n"
            "is_dos\n"
            "kill_signal = KILL\n"
            "memory_limit_type = \"dos\"\n"
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
    /*
    if (max_vm_size != -1L)
      fprintf(f, "max_vm_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    if (max_stack_size != -1L)
      fprintf(f, "max_stack_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
    */
    if (secure_run)
      fprintf(f, "start_cmd = \"runperl\"\n");
    break;

  case ARCH_MSIL:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "no_core_dump\n"
            "kill_signal = TERM\n"
            //            "memory_limit_type = \"java\"\n"
            //            "secure_exec_type = \"java\"\n"
            "start_cmd = \"runmono\"\n",
            arch_abstract_names[arch], supported_archs[arch]);
    if (!atst) {
      fprintf(f, "start_env = \"LANG=C\"\n"
              "start_env = \"EJUDGE_PREFIX_DIR\"\n");
    }
    break;

  case ARCH_WIN32:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "nwrun_spool_dir = \"win32_nwrun\"\n",
            arch_abstract_names[arch], supported_archs[arch]);
    break;

  case ARCH_VALGRIND:
    fprintf(f,
            "[tester]\n"
            "name = Valgrind\n"
            "arch = \"valgrind\"\n"
            "abstract\n"
            "no_core_dump\n"
            "kill_signal = TERM\n"
            "memory_limit_type = \"valgrind\"\n"
            "secure_exec_type = \"valgrind\"\n"
            "start_cmd = \"runvg\"\n");
    if (!atst) {
      fprintf(f, "clear_env\n"
              "start_env = \"PATH=/usr/local/bin:/usr/bin:/bin\"\n"
              "start_env = \"LANG=C\"\n"
              "start_env = \"HOME\"\n");
    }
    break;

  case ARCH_DOTNET:
    fprintf(f, "[tester]\n"
            "name = %s\n"
            "arch = \"%s\"\n"
            "abstract\n"
            "no_core_dump\n"
            "kill_signal = TERM\n"
            "memory_limit_type = \"dotnet\"\n"
            "secure_exec_type = \"dotnet\"\n"
            "start_cmd = \"rundotnet\"\n",
            arch_abstract_names[arch], supported_archs[arch]);
    if (!atst) {
      fprintf(f, "start_env = \"LANG=C\"\n"
              "start_env = \"EJUDGE_PREFIX_DIR\"\n");
    }
    break;

  default:
    abort();
  }

  if (atst) {
    if (atst->clear_env > 0) {
      unparse_bool(f, "clear_env", atst->clear_env);
    }
    if (atst->enable_ejudge_env > 0) {
      unparse_bool(f, "enable_ejudge_env", atst->enable_ejudge_env);
    }
    do_xstr(f, &ab, "start_env", atst->start_env);
  }

  if (atst && atst->check_dir && atst->check_dir[0]) {
    fprintf(f, "check_dir = \"%s\"\n", c_armor_2(&ab, atst->check_dir, contests_home_dir));
  } else if (arch == ARCH_DOS) {
    fprintf(f, "check_dir = \"%s\"\n",
            c_armor_2(&ab, "/home/judges/dosemu/run", contests_home_dir));
  } else if(testing_work_dir) {
    fprintf(f, "check_dir = \"%s\"\n",
            c_armor_2(&ab, testing_work_dir, contests_home_dir));
  }
  if (atst && atst->skip_testing > 0) {
    fprintf(f, "skip_testing\n");
  }
  fprintf(f, "\n");

  html_armor_free(&ab);
}

static void
generate_concrete_tester(FILE *f, int arch,
                         struct section_problem_data *prob,
                         /*size_t max_vm_size,
                           size_t max_stack_size,*/
                         int use_files)
{
  //unsigned char nbuf[256], nbuf2[256];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  fprintf(f, "[tester]\n"
          "problem_name = \"%s\"\n"
          "super = %s\n", CARMOR(prob->short_name),
          arch_abstract_names[arch]);
  if (supported_archs[arch][0])
    fprintf(f, "arch = %s\n", supported_archs[arch]);

  switch (arch) {
  case ARCH_LINUX:
  case ARCH_LINUX_SHARED:
  case ARCH_LINUX_SHARED_32:
    /*
    if (max_vm_size != -1L) {
      fprintf(f, "max_vm_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_vm_size));
    }
    if (max_stack_size != -1L) {
      fprintf(f, "max_stack_size = %s\n",
              size_t_to_size(nbuf, sizeof(nbuf), max_stack_size));
    }
    */
    break;

  case ARCH_DOS:
    break;

  case ARCH_JAVA:
  case ARCH_JAVA14:
    fprintf(f, "start_env = \"EJUDGE_JAVA_POLICY=fileio.policy\"\n");
    /*
    if (use_files) {
      fprintf(f, "start_env = \"EJUDGE_JAVA_POLICY=fileio.policy\"\n");
    } else {
      fprintf(f, "start_env = \"EJUDGE_JAVA_POLICY=default.policy\"\n");
    }
    */
    /*
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
    */
    break;

  case ARCH_PERL:
    break;

  case ARCH_MSIL:
    break;

  case ARCH_WIN32:
    break;

  case ARCH_VALGRIND:
    break;

  case ARCH_DOTNET:
    break;

  default:
    abort();
  }
  fprintf(f, "\n");

  html_armor_free(&ab);
}

int
prepare_unparse_testers(
        FILE *f,
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
        const unsigned char *testing_work_dir,
        const unsigned char *contests_home_dir)
{
  unsigned char **archs = 0;
  //size_t *vm_sizes = 0, *stack_sizes = 0, *vm_ind = 0, *stack_ind = 0;
  //int *vm_count = 0, *stack_count = 0, vm_total = 0, stack_total = 0;
  int *file_ios = 0, *need_sep_tester = 0;
  int total_archs = 0, i, j;
  int retcode = 0;
  int use_stdio = 0, use_files = 0/*, max_vm_ind, max_stack_ind*/;
  struct section_problem_data *abstr;
  struct section_problem_data *tmp_prob = 0;
  //unsigned long def_vm_size, def_stack_size;
  int def_use_files;
  int def_tester_total = 0;
  int *arch_codes = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
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
    const unsigned char *arch = langs[i]->arch;
    if (!arch) arch = "";
    for (j = 0; j < total_archs; j++) {
      if (!strcmp(archs[j], arch))
        break;
    }
    if (j == total_archs)
      archs[total_archs++] = xstrdup(arch);
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
  //XCALLOC(vm_sizes, total_probs);
  //XCALLOC(stack_sizes, total_probs);
  XCALLOC(file_ios, total_probs);
  //XCALLOC(vm_ind, total_probs);
  //XCALLOC(stack_ind, total_probs);
  //XCALLOC(vm_count, total_probs);
  //XCALLOC(stack_count, total_probs);
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
    tmp_prob = prepare_copy_problem(probs[i]);
    prepare_set_prob_value(CNTSPROB_type, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_scoring_checker, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_enable_checker_token, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_interactive_valuer, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_disable_pe, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_disable_wtl, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_wtl_is_cf, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_manual_checking, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_examinator_num, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_check_presentation,tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_stdin, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_stdout, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_combined_stdin, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_combined_stdout, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_binary_input, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_binary, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_ignore_exit_code, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_ignore_term_signal, tmp_prob, abstr, global);
    /*
    prepare_set_prob_value(CNTSPROB_MAX_VM_SIZE, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_MAX_STACK_SIZE, tmp_prob, abstr, global);
    */
    //vm_sizes[i] = tmp_prob->max_vm_size;
    //stack_sizes[i] = tmp_prob->max_stack_size;
    file_ios[i] = !tmp_prob->type && (!tmp_prob->use_stdin || !tmp_prob->use_stdout);
    tmp_prob = prepare_problem_free(tmp_prob);
  }

  // collect memory and stack limits for the default tester
  for (i = 0; i < total_probs; i++) {
    if (!probs[i] || probs[i]->disable_testing > 0) continue;

  /*
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
  */

    if (file_ios[i]) use_files++;
    else use_stdio++;
  }

  // find mostly used memory and stack limit
  /*
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
  */
  def_use_files = 0;
  if (use_files > use_stdio) def_use_files = 1;

  // which problems require specific testers
  XCALLOC(need_sep_tester, total_probs);
  for (i = 0; i < total_probs; i++) {
    if (!probs[i] || probs[i]->disable_testing > 0) continue;
    if (/*vm_sizes[i] != def_vm_size
        || stack_sizes[i] != def_stack_size
        || file_ios[i] != def_use_files*/ 0)
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
                             /*def_vm_size, def_stack_size, */def_use_files,
                             total_atesters, atesters, testing_work_dir,
                             contests_home_dir);
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
                               /*vm_sizes[i], stack_sizes[i], */file_ios[i]);
    }
  }

 cleanup:
  tmp_prob = prepare_problem_free(tmp_prob);
  for (i = 0; i < total_archs; i++)
    xfree(archs[i]);
  xfree(archs);
  //xfree(vm_sizes);
  //xfree(stack_sizes);
  xfree(file_ios);
  //xfree(vm_ind);
  //xfree(stack_ind);
  //xfree(vm_count);
  //xfree(stack_count);
  xfree(need_sep_tester);
  xfree(arch_codes);
  html_armor_free(&ab);
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

#define ARMOR(s)  html_armor_buf(&ab, (s))

static void
print_files(FILE *f, const unsigned char *desc, const unsigned char *sfx,
            const unsigned char *pat)
{
  int i;

  fprintf(f, "<p><b>%s</b>: ", desc);
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
  fprintf(f, "etc...</p>\n");
}

static void
report_directory(
        FILE *f,
        const unsigned char *path,
        int variant)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int r;

  fprintf(f, "<tr>");
  if (variant > 0) {
    fprintf(f, "<td>%d<td>", variant);
  }
  fprintf(f, "<td><tt>%s</tt></td>", ARMOR(path));
  r = os_IsFile(path);
  if (r < 0) {
    fprintf(f, "<td><font color=\"red\">Does not exist!</font></td>");
  } else if (r != OSPK_DIR) {
    fprintf(f, "<td><font color=\"red\">Not a directory!</font></td>");
  } else {
    fprintf(f, "<td><font color=\"green\">OK</font></td>");
  }
  fprintf(f, "</tr>");

  html_armor_free(&ab);
}

static void
report_file(
        FILE *f,
        const unsigned char *path,
        int is_executable,
        int variant)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int r;

  fprintf(f, "<tr>");
  if (variant > 0) {
    fprintf(f, "<td>%d<td>", variant);
  }
  fprintf(f, "<td><tt>%s</tt></td>", ARMOR(path));
  r = os_IsFile(path);
  if (r < 0) {
    fprintf(f, "<td><font color=\"red\">Does not exist!</font></td>");
  } else if (r != OSPK_REG) {
    fprintf(f, "<td><font color=\"red\">Not a file!</font></td>");
  } else {
    fprintf(f, "<td><font color=\"green\">OK</font></td>");
  }
  fprintf(f, "</tr>");

  html_armor_free(&ab);
}

static void
handle_file(
        FILE *f,
        const struct section_global_data *global,
        struct section_problem_data *prob,
        const unsigned char *file,
        int is_executable)
{
  path_t path = { 0 };
  int variant;

  fprintf(f, "<table border=\"1\">\n");
  if (prob->variant_num > 0) {
    for (variant = 0; variant <= prob->variant_num; ++variant) {
      if (global->advanced_layout > 0) {
        get_advanced_layout_path(path, sizeof(path), global, prob, file,
                                 variant);
      } else {
        prepare_insert_variant_num(path, sizeof(path), file, variant);
      }
      report_file(f, path, is_executable, variant);
    }
  } else {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(path, sizeof(path), global, prob, file, -1);
      report_file(f, path, is_executable, -1);
    } else {
      report_file(f, file, is_executable, -1);
    }
  }
  fprintf(f, "</table>\n");
}

static void
handle_directory(
        FILE *f,
        const struct section_global_data *global,
        struct section_problem_data *prob,
        const unsigned char *conf_path,
        const unsigned char *gdir, /* global dir for standard layout */
        const unsigned char *gdefdir, /* default global dir for std. layout */
        const unsigned char *dir1, /* for standard layout */
        const unsigned char *dir2) /* for advanced layout */
{
  path_t path1 = { 0 };
  path_t path2 = { 0 };
  path_t path;
  int variant;

  if (global->advanced_layout <= 0) {
    mkpath(path1, conf_path, gdir, gdefdir);
    mkpath(path2, path1, dir1, "");
  }

  fprintf(f, "<table border=\"1\">\n");
  if (prob->variant_num > 0) {
    for (variant = 1; variant <= prob->variant_num; ++variant) {
      if (global->advanced_layout > 0) {
        get_advanced_layout_path(path, sizeof(path), global, prob, dir2,
                                 variant);
      } else {
        snprintf(path, sizeof(path), "%s-%d", path2, variant);
      }
      report_directory(f, path, -1);
    }
  } else {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(path2, sizeof(path2), global, prob, dir2, -1);
    }
    report_directory(f, path2, -1);
  }
  fprintf(f, "</table>\n");
}

static void
prob_instr(
        FILE *f,
        const unsigned char *root_dir,
        const unsigned char *conf_dir,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        const struct section_problem_data *abstr)
{
  struct section_problem_data *tmp_prob = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  path_t conf_path;
  path_t prob_path;
  path_t sc_path;
  int variant;

  fprintf(f, "<h3>Problem %s: %s</h3>\n", prob->short_name, ARMOR(prob->long_name));
  if (prob->variant_num > 0) {
    fprintf(f, "<p>This is a variant problem with <b>%d variants</b> (1-%d).</p>\n",
            prob->variant_num, prob->variant_num);
  }

  tmp_prob = prepare_copy_problem(prob);
  mkpath(conf_path, root_dir, conf_dir, "conf");

  if (global->advanced_layout > 0) {
    fprintf(f, "<p><b>Problem directory:</b></p>\n");
    fprintf(f, "<table border=\"1\">\n");
    if (prob->variant_num > 0) {
      for (variant = 1; variant <= prob->variant_num; ++variant) {
        get_advanced_layout_path(prob_path, sizeof(prob_path),
                                 global, tmp_prob, NULL, variant);
        report_directory(f, prob_path, variant);
      }
    } else {
      get_advanced_layout_path(prob_path, sizeof(prob_path),
                               global, tmp_prob, NULL, -1);
      report_directory(f, prob_path, -1);
    }
    fprintf(f, "</table>\n");

    fprintf(f, "<p><b>Makefile (optional):</b></p>\n");
    handle_file(f, global, tmp_prob, "Makefile", 0);
  }
  prepare_set_prob_value(CNTSPROB_xml_file, tmp_prob, abstr, global);
  if (tmp_prob->xml_file && tmp_prob->xml_file[0]) {
    if (global->advanced_layout <= 0 && !os_IsAbsolutePath(tmp_prob->xml_file)) {
      usprintf(&tmp_prob->xml_file, "%s/%s", conf_path, tmp_prob->xml_file);
    }
    fprintf(f, "<p><b>Problem statement file:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->xml_file, 0);
  }

  prepare_set_prob_value(CNTSPROB_plugin_file, tmp_prob, abstr, global);
  if (tmp_prob->plugin_file && tmp_prob->plugin_file[0]) {
    fprintf(f, "<p><b>Problem plugin file:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->plugin_file, 0);
  }

  if (!tmp_prob->standard_checker) {
    if (!tmp_prob->check_cmd) {
      fprintf(f, "<p><b><font color=\"red\">Neither standard, nor custom checker is defined!</font></b></p>\n");
    } else {
      prepare_set_prob_value(CNTSPROB_check_cmd, tmp_prob, abstr, global);
      fprintf(f, "<p><b>Output file checker:</b></p>\n");
      handle_file(f, global, tmp_prob, tmp_prob->check_cmd, 1);
    }
  }

  prepare_set_prob_value(CNTSPROB_test_checker_cmd, tmp_prob, abstr, global);
  if (tmp_prob->test_checker_cmd && tmp_prob->test_checker_cmd[0]) {
    fprintf(f, "<p><b>Tests checker:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->test_checker_cmd, 1);
  }

  prepare_set_prob_value(CNTSPROB_test_generator_cmd, tmp_prob, abstr, global);
  if (tmp_prob->test_generator_cmd && tmp_prob->test_generator_cmd[0]) {
    fprintf(f, "<p><b>Tests generator:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->test_generator_cmd, 1);
  }

  prepare_set_prob_value(CNTSPROB_init_cmd, tmp_prob, abstr, global);
  if (tmp_prob->init_cmd && tmp_prob->init_cmd[0]) {
    fprintf(f, "<p><b>Init-style interactor:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->init_cmd, 1);
  }

  prepare_set_prob_value(CNTSPROB_start_cmd, tmp_prob, abstr, global);
  if (tmp_prob->start_cmd && tmp_prob->start_cmd[0]) {
    fprintf(f, "<p><b>Start proxy program:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->start_cmd, 1);
  }

  prepare_set_prob_value(CNTSPROB_solution_src, tmp_prob, abstr, global);
  if (tmp_prob->solution_src && tmp_prob->solution_src[0]) {
    fprintf(f, "<p><b>Solution source code:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->solution_src, 1);
  }

  prepare_set_prob_value(CNTSPROB_solution_cmd, tmp_prob, abstr, global);
  if (tmp_prob->solution_cmd && tmp_prob->solution_cmd[0]) {
    fprintf(f, "<p><b>Solution command:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->solution_cmd, 1);
  }

  /*
  prepare_set_prob_value(CNTSPROB_post_pull_cmd, tmp_prob, abstr, global);
  if (tmp_prob->post_pull_cmd && tmp_prob->post_pull_cmd[0]) {
    fprintf(f, "<p><b>Tests checker:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->post_pull_cmd, 1);
  }
   */

  prepare_set_prob_value(CNTSPROB_valuer_cmd, tmp_prob, abstr, global);
  if (tmp_prob->valuer_cmd && tmp_prob->valuer_cmd[0]) {
    fprintf(f, "<p><b>Score evaluator:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->valuer_cmd, 1);
  }

  prepare_set_prob_value(CNTSPROB_interactor_cmd, tmp_prob, abstr, global);
  if (tmp_prob->interactor_cmd && tmp_prob->interactor_cmd[0]) {
    fprintf(f, "<p><b>Interactor:</b></p>\n");
    handle_file(f, global, tmp_prob, tmp_prob->interactor_cmd, 1);
  }

  prepare_set_prob_value(CNTSPROB_style_checker_cmd, tmp_prob, abstr, global);
  if (tmp_prob->style_checker_cmd && tmp_prob->style_checker_cmd[0]) {
    fprintf(f, "<p><b>Style checker:</b></p>\n");

    sformat_message(prob_path, sizeof(prob_path), 0,
                    tmp_prob->style_checker_cmd, global, tmp_prob,
                    0, 0, 0, 0, 0, 0);
    config_var_substitute_buf(prob_path, sizeof(prob_path));
    if (os_IsAbsolutePath(prob_path)) {
      snprintf(sc_path, sizeof(sc_path), "%s", prob_path);
    } else if (global->advanced_layout > 0) {
      get_advanced_layout_path(sc_path, sizeof(sc_path),
                               global, prob, prob_path, -1);
    } else {
      snprintf(sc_path, sizeof(sc_path), "%s/%s", global->checker_dir,
               prob_path);
    }

    fprintf(f, "<table border=\"1\">\n");
    report_file(f, prob_path, 0, -1);
    fprintf(f, "</table>\n");
  }

  /*
  if (!prob->standard_checker[0]) {
    if (global->advanced_layout > 0) {
      get_advanced_layout_path(checker_path, sizeof(checker_path),
                               global, tmp_prob, NULL, -1);
    } else {
      mkpath(checker_path, conf_path, global->checker_dir, DFLT_G_CHECKER_DIR);
    }
    prepare_set_prob_value(CNTSPROB_check_cmd, tmp_prob, abstr, global);
    if (os_IsAbsolutePath(tmp_prob->check_cmd)) {
      fprintf(f, "Checker command: %s\n", tmp_prob->check_cmd);
    } else {
      fprintf(f, "Checker directory: %s\n", checker_path);
      fprintf(f, "Checker file name: %s\n", tmp_prob->check_cmd);
    }
  }
  */

  fprintf(f, "<p><b>Tests directory:</b></p>\n");
  prepare_set_prob_value(CNTSPROB_test_dir, tmp_prob, abstr, 0);
  handle_directory(f, global, tmp_prob, conf_path,
                   global->test_dir, DFLT_G_TEST_DIR,
                   tmp_prob->test_dir, DFLT_P_TEST_DIR);

  prepare_set_prob_value(CNTSPROB_test_sfx, tmp_prob, abstr, global);
  prepare_set_prob_value(CNTSPROB_test_pat, tmp_prob, abstr, global);
  print_files(f, "Test file names", tmp_prob->test_sfx, tmp_prob->test_pat);

  prepare_set_prob_value(CNTSPROB_use_corr, tmp_prob, abstr, global);
  if (tmp_prob->use_corr) {
    fprintf(f, "<p><b>Correct answer directory:</b></p>\n");
    prepare_set_prob_value(CNTSPROB_corr_dir, tmp_prob, abstr, 0);
    handle_directory(f, global, tmp_prob, conf_path,
                     global->corr_dir, DFLT_G_CORR_DIR,
                     tmp_prob->corr_dir, DFLT_P_CORR_DIR);

    prepare_set_prob_value(CNTSPROB_corr_sfx, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_corr_pat, tmp_prob, abstr, global);
    print_files(f, "Correct answer file names", tmp_prob->corr_sfx, tmp_prob->corr_pat);
  }

  prepare_set_prob_value(CNTSPROB_use_info, tmp_prob, abstr, global);
  if (tmp_prob->use_info) {
    fprintf(f, "<p><b>Info files directory:</b></p>\n");
    prepare_set_prob_value(CNTSPROB_info_dir, tmp_prob, abstr, 0);
    handle_directory(f, global, tmp_prob, conf_path,
                     global->info_dir, DFLT_G_INFO_DIR,
                     tmp_prob->info_dir, DFLT_P_INFO_DIR);

    prepare_set_prob_value(CNTSPROB_info_sfx, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_info_pat, tmp_prob, abstr, global);
    print_files(f, "Info file names", tmp_prob->info_sfx, tmp_prob->info_pat);
  }

  prepare_set_prob_value(CNTSPROB_use_tgz, tmp_prob, abstr, global);
  if (tmp_prob->use_tgz) {
    fprintf(f, "<p><b>TGZ files directory:</b></p>\n");
    prepare_set_prob_value(CNTSPROB_tgz_dir, tmp_prob, abstr, 0);
    handle_directory(f, global, tmp_prob, conf_path,
                     global->tgz_dir, DFLT_G_TGZ_DIR,
                     tmp_prob->tgz_dir, DFLT_P_TGZ_DIR);

    prepare_set_prob_value(CNTSPROB_tgz_sfx, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_tgz_pat, tmp_prob, abstr, global);
    print_files(f, "TGZ file names", tmp_prob->tgz_sfx, tmp_prob->tgz_pat);
    prepare_set_prob_value(CNTSPROB_tgzdir_sfx, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_tgzdir_pat, tmp_prob, abstr, global);
    print_files(f, "master working directories", tmp_prob->tgzdir_sfx, tmp_prob->tgzdir_pat);
  }

  fprintf(f, "\n");

  tmp_prob = prepare_problem_free(tmp_prob);
  html_armor_free(&ab);
}

void
prepare_further_instructions(
        FILE *f,
        const unsigned char *root_dir,
        const unsigned char *conf_dir,
        const struct section_global_data *global,
        int aprob_a,
        struct section_problem_data **aprobs,
        int prob_a,
        struct section_problem_data **probs)
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

  fprintf(f, "<p>Make sure, that checker, valuer, and other executables are placed in the specified directory and have the specified names!</p>"
          "<p>Copy test files, correct answer files (if needed), test info files (if needed), etc to the specified directories and name them as specified!</p>"
          "<p>Make sure, that all input text files are in UNIX text format!</p>"
          "<p>When done with the files, perform &quot;Check contests settings&quot; operation.</p>");
}
