/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2000-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "settings.h"
#include "varsubst.h"
#include "version.h"

#include "fileutl.h"
#include "sformat.h"
#include "teamdb.h"
#include "prepare_serve.h"
#include "prepare_dflt.h"
#include "ejudge_cfg.h"
#include "cpu.h"
#include "errlog.h"
#include "serve_state.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define GLOBAL_OFFSET(x)   XOFFSET(struct section_global_data, x)
#define GLOBAL_SIZE(x)     XFSIZE(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x), GLOBAL_SIZE(x) }
#define GLOBAL_ALIAS(a, x, t) { #a, t, GLOBAL_OFFSET(x), GLOBAL_SIZE(x) }
static const struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(name, "s"),
  GLOBAL_PARAM(sleep_time, "d"),
  GLOBAL_PARAM(serve_sleep_time, "d"),
  GLOBAL_PARAM(contest_time, "d"),
  GLOBAL_PARAM(max_run_size, "d"),
  GLOBAL_PARAM(max_run_total, "d"),
  GLOBAL_PARAM(max_run_num, "d"),
  GLOBAL_PARAM(max_clar_size, "d"),
  GLOBAL_PARAM(max_clar_total, "d"),
  GLOBAL_PARAM(max_clar_num, "d"),

  GLOBAL_PARAM(board_fog_time, "d"),
  GLOBAL_PARAM(board_unfog_time, "d"),

  // aliases for the existing configuration variables
  GLOBAL_ALIAS(stand_freeze_time, board_fog_time, "d"),
  GLOBAL_ALIAS(stand_melt_time, board_unfog_time, "d"),

  GLOBAL_PARAM(autoupdate_standings, "d"),
  GLOBAL_PARAM(team_enable_src_view, "d"),
  GLOBAL_PARAM(team_enable_rep_view, "d"),
  GLOBAL_PARAM(team_enable_ce_view, "d"),
  GLOBAL_PARAM(team_show_judge_report, "d"),
  GLOBAL_PARAM(disable_clars, "d"),
  GLOBAL_PARAM(disable_team_clars, "d"),
  GLOBAL_PARAM(disable_submit_after_ok, "d"),
  GLOBAL_PARAM(max_file_length, "d"),
  GLOBAL_PARAM(max_line_length, "d"),
  GLOBAL_PARAM(tests_to_accept, "d"),
  GLOBAL_PARAM(ignore_compile_errors, "d"),
  GLOBAL_PARAM(disable_failed_test_view, "d"),
  GLOBAL_PARAM(inactivity_timeout, "d"),
  GLOBAL_PARAM(disable_auto_testing, "d"),
  GLOBAL_PARAM(disable_testing, "d"),
  GLOBAL_PARAM(secure_run, "d"),
  GLOBAL_PARAM(enable_memory_limit_error, "d"),
  GLOBAL_PARAM(always_show_problems, "d"),
  GLOBAL_PARAM(disable_user_standings, "d"),

  GLOBAL_PARAM(stand_ignore_after, "s"),
  GLOBAL_PARAM(appeal_deadline, "s"),
  GLOBAL_PARAM(charset, "s"),
  GLOBAL_PARAM(contest_finish_time, "s"),
  //GLOBAL_PARAM(standings_charset, "s"),

  GLOBAL_PARAM(root_dir, "s"),
  GLOBAL_PARAM(conf_dir, "s"),
  GLOBAL_PARAM(script_dir, "s"),
  GLOBAL_PARAM(test_dir, "s"),
  GLOBAL_PARAM(corr_dir, "s"),
  GLOBAL_PARAM(info_dir, "s"),
  GLOBAL_PARAM(tgz_dir, "s"),
  GLOBAL_PARAM(checker_dir, "s"),
  GLOBAL_PARAM(statement_dir, "s"),
  GLOBAL_PARAM(test_sfx, "s"),
  GLOBAL_PARAM(corr_sfx, "s"),
  GLOBAL_PARAM(info_sfx, "s"),
  GLOBAL_PARAM(tgz_sfx, "s"),
  GLOBAL_PARAM(ejudge_checkers_dir, "s"),
  GLOBAL_PARAM(test_pat, "s"),
  GLOBAL_PARAM(corr_pat, "s"),
  GLOBAL_PARAM(info_pat, "s"),
  GLOBAL_PARAM(tgz_pat, "s"),
  GLOBAL_PARAM(contest_start_cmd, "s"),

  GLOBAL_PARAM(var_dir, "s"),

  GLOBAL_PARAM(contest_id, "d"),
  GLOBAL_PARAM(socket_path, "s"),
  GLOBAL_PARAM(contests_dir, "s"),
  GLOBAL_PARAM(serve_socket, "s"),

  //GLOBAL_PARAM(log_file, "s"),
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

  GLOBAL_PARAM(score_system, "s"),
  GLOBAL_PARAM(rounding_mode, "s"),
  GLOBAL_PARAM(is_virtual, "d"),
  GLOBAL_ALIAS(virtual, is_virtual, "d"),

  GLOBAL_PARAM(htdocs_dir, "s"),

  GLOBAL_PARAM(team_info_url, "s"),
  GLOBAL_PARAM(prob_info_url, "s"),
  GLOBAL_PARAM(standings_file_name, "s"),
  GLOBAL_PARAM(stand_header_file, "s"),
  GLOBAL_PARAM(stand_footer_file, "s"),
  GLOBAL_PARAM(stand_symlink_dir, "s"),
  GLOBAL_PARAM(users_on_page, "d"),
  GLOBAL_PARAM(stand2_file_name, "s"),
  GLOBAL_PARAM(stand2_header_file, "s"),
  GLOBAL_PARAM(stand2_footer_file, "s"),
  GLOBAL_PARAM(stand2_symlink_dir, "s"),
  GLOBAL_PARAM(plog_file_name, "s"),
  GLOBAL_PARAM(plog_header_file, "s"),
  GLOBAL_PARAM(plog_footer_file, "s"),
  GLOBAL_PARAM(plog_update_time, "d"),
  GLOBAL_PARAM(plog_symlink_dir, "s"),

  GLOBAL_PARAM(external_xml_update_time, "d"),
  GLOBAL_PARAM(internal_xml_update_time, "d"),

  // standings table attributes
  GLOBAL_PARAM(stand_extra_format, "s"),
  GLOBAL_PARAM(stand_extra_legend, "s"),
  GLOBAL_PARAM(stand_extra_attr, "s"),
  GLOBAL_PARAM(stand_table_attr, "s"),
  GLOBAL_PARAM(stand_place_attr, "s"),
  GLOBAL_PARAM(stand_team_attr, "s"),
  GLOBAL_PARAM(stand_prob_attr, "s"),
  GLOBAL_PARAM(stand_solved_attr, "s"),
  GLOBAL_PARAM(stand_score_attr, "s"),
  GLOBAL_PARAM(stand_penalty_attr, "s"),
  GLOBAL_PARAM(stand_time_attr, "s"),
  GLOBAL_PARAM(stand_self_row_attr, "s"),
  GLOBAL_PARAM(stand_v_row_attr, "s"),
  GLOBAL_PARAM(stand_r_row_attr, "s"),
  GLOBAL_PARAM(stand_u_row_attr, "s"),
  GLOBAL_PARAM(stand_success_attr, "s"),
  GLOBAL_PARAM(stand_fail_attr, "s"),
  GLOBAL_PARAM(stand_trans_attr, "s"),
  GLOBAL_PARAM(stand_show_ok_time, "d"),
  GLOBAL_PARAM(stand_show_att_num, "d"),
  GLOBAL_PARAM(stand_sort_by_solved, "d"),
  GLOBAL_PARAM(stand_row_attr, "x"),
  GLOBAL_PARAM(stand_page_table_attr, "s"),
  GLOBAL_PARAM(stand_page_row_attr, "x"),
  GLOBAL_PARAM(stand_page_col_attr, "x"),
  GLOBAL_PARAM(stand_page_cur_attr, "s"),

  // just for fun
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

  GLOBAL_PARAM(enable_l10n, "d"),
  GLOBAL_PARAM(l10n_dir, "s"),
  GLOBAL_PARAM(standings_locale, "s"),

  GLOBAL_PARAM(team_download_time, "d"),

  GLOBAL_PARAM(cr_serialization_key, "d"),
  GLOBAL_PARAM(show_astr_time, "d"),
  GLOBAL_PARAM(ignore_duplicated_runs, "d"),
  GLOBAL_PARAM(report_error_code, "d"),
  GLOBAL_PARAM(auto_short_problem_name, "d"),
  GLOBAL_PARAM(enable_continue, "d"),
  GLOBAL_PARAM(checker_real_time_limit, "d"),
  GLOBAL_PARAM(compile_real_time_limit, "d"),
  GLOBAL_PARAM(show_deadline, "d"),
  GLOBAL_PARAM(enable_runlog_merge, "d"),
  GLOBAL_PARAM(prune_empty_users, "d"),
  GLOBAL_PARAM(enable_report_upload, "d"),
  GLOBAL_PARAM(ignore_success_time, "d"),

  GLOBAL_PARAM(use_gzip, "d"),
  GLOBAL_PARAM(min_gzip_size, "d"),
  GLOBAL_PARAM(use_dir_hierarchy, "d"),
  GLOBAL_PARAM(html_report, "d"),
  GLOBAL_PARAM(xml_report, "d"),
  GLOBAL_PARAM(enable_full_archive, "d"),
  GLOBAL_PARAM(cpu_bogomips, "d"),
  GLOBAL_PARAM(skip_full_testing, "d"),
  GLOBAL_PARAM(skip_accept_testing, "d"),

  GLOBAL_PARAM(variant_map_file, "s"),

  GLOBAL_PARAM(enable_printing, "d"),
  GLOBAL_PARAM(disable_banner_page, "d"),
  GLOBAL_PARAM(team_page_quota, "d"),

  GLOBAL_PARAM(priority_adjustment, "d"),
  GLOBAL_PARAM(user_priority_adjustments, "x"),

  GLOBAL_PARAM(contestant_status_num, "d"),
  GLOBAL_PARAM(contestant_status_legend, "x"),
  GLOBAL_PARAM(contestant_status_row_attr, "x"),
  GLOBAL_PARAM(stand_show_contestant_status, "d"),
  GLOBAL_PARAM(stand_show_warn_number, "d"),
  GLOBAL_PARAM(stand_contestant_status_attr, "s"),
  GLOBAL_PARAM(stand_warn_number_attr, "s"),

  { 0, 0, 0, 0 }
};

#define PROBLEM_OFFSET(x)   XOFFSET(struct section_problem_data, x)
#define PROBLEM_SIZE(x)     XFSIZE(struct section_problem_data, x)
#define PROBLEM_PARAM(x, t) { #x, t, PROBLEM_OFFSET(x), PROBLEM_SIZE(x) }
#define PROBLEM_ALIAS(a, x, t) { #a, t, PROBLEM_OFFSET(x), PROBLEM_SIZE(x) }
static const struct config_parse_info section_problem_params[] =
{
  PROBLEM_PARAM(id, "d"),
  PROBLEM_PARAM(tester_id, "d"),
  PROBLEM_PARAM(abstract, "d"),
  PROBLEM_PARAM(scoring_checker, "d"),  
  PROBLEM_PARAM(manual_checking, "d"),  
  PROBLEM_PARAM(examinator_num, "d"),  
  PROBLEM_PARAM(check_presentation, "d"),  
  PROBLEM_PARAM(use_stdin, "d"),
  PROBLEM_PARAM(use_stdout, "d"),
  PROBLEM_PARAM(binary_input, "d"),
  PROBLEM_PARAM(ignore_exit_code, "d"),
  PROBLEM_PARAM(time_limit, "d"),
  PROBLEM_PARAM(time_limit_millis, "d"),
  PROBLEM_PARAM(real_time_limit, "d"),
  PROBLEM_PARAM(team_enable_rep_view, "d"),
  PROBLEM_PARAM(team_enable_ce_view, "d"),
  PROBLEM_PARAM(team_show_judge_report, "d"),
  PROBLEM_PARAM(full_score, "d"),
  PROBLEM_PARAM(test_score, "d"),
  PROBLEM_PARAM(run_penalty, "d"),
  PROBLEM_PARAM(acm_run_penalty, "d"),
  PROBLEM_PARAM(disqualified_penalty, "d"),
  PROBLEM_PARAM(use_corr, "d"),
  PROBLEM_PARAM(use_info, "d"),
  PROBLEM_PARAM(use_tgz, "d"),
  PROBLEM_PARAM(tests_to_accept, "d"),
  PROBLEM_PARAM(accept_partial, "d"),
  PROBLEM_PARAM(checker_real_time_limit, "d"),
  PROBLEM_PARAM(disable_auto_testing, "d"),
  PROBLEM_PARAM(disable_testing, "d"),
  PROBLEM_PARAM(disable_user_submit, "d"),
  PROBLEM_PARAM(disable_submit_after_ok, "d"),
  PROBLEM_PARAM(enable_compilation, "d"),
  PROBLEM_PARAM(skip_testing, "d"),
  PROBLEM_PARAM(variable_full_score, "d"),
  PROBLEM_PARAM(hidden, "d"),
  PROBLEM_PARAM(priority_adjustment, "d"),
  PROBLEM_PARAM(spelling, "s"),
  PROBLEM_PARAM(stand_hide_time, "d"),
  PROBLEM_PARAM(score_multiplier, "d"),
  PROBLEM_ALIAS(output_only, type_val, "d"),
  PROBLEM_PARAM(max_vm_size, "z"),
  PROBLEM_PARAM(max_stack_size, "z"),
  PROBLEM_PARAM(max_data_size, "z"),

  PROBLEM_PARAM(super, "s"),
  PROBLEM_PARAM(short_name, "s"),
  PROBLEM_PARAM(long_name, "s"),
  PROBLEM_PARAM(test_dir, "s"),
  PROBLEM_PARAM(test_sfx, "s"),
  PROBLEM_PARAM(corr_dir, "s"),
  PROBLEM_PARAM(corr_sfx, "s"),
  PROBLEM_PARAM(info_dir, "s"),
  PROBLEM_PARAM(info_sfx, "s"),
  PROBLEM_PARAM(tgz_dir, "s"),
  PROBLEM_PARAM(tgz_sfx, "s"),
  PROBLEM_PARAM(input_file, "s"),
  PROBLEM_PARAM(output_file, "s"),
  PROBLEM_PARAM(test_score_list, "s"),
  PROBLEM_PARAM(score_tests, "s"),
  PROBLEM_PARAM(test_sets, "x"),
  PROBLEM_PARAM(deadline, "s"),
  PROBLEM_PARAM(start_date, "s"),
  PROBLEM_PARAM(variant_num, "d"),
  PROBLEM_PARAM(date_penalty, "x"),
  PROBLEM_PARAM(disable_language, "x"),
  PROBLEM_PARAM(enable_language, "x"),
  PROBLEM_PARAM(require, "x"),
  PROBLEM_PARAM(standard_checker, "s"),
  PROBLEM_PARAM(checker_env, "x"),
  PROBLEM_PARAM(lang_time_adj, "x"),
  PROBLEM_PARAM(check_cmd, "s"),
  PROBLEM_PARAM(test_pat, "s"),
  PROBLEM_PARAM(corr_pat, "s"),
  PROBLEM_PARAM(info_pat, "s"),
  PROBLEM_PARAM(tgz_pat, "s"),
  PROBLEM_PARAM(personal_deadline, "x"),
  PROBLEM_PARAM(score_bonus, "s"),
  PROBLEM_PARAM(statement_file, "s"),
  PROBLEM_PARAM(alternatives_file, "s"),
  PROBLEM_PARAM(type, "s"),
  PROBLEM_PARAM(alternative, "x"),
  PROBLEM_PARAM(stand_attr, "s"),

  { 0, 0, 0, 0 }
};

#define LANGUAGE_OFFSET(x)   XOFFSET(struct section_language_data, x)
#define LANGUAGE_SIZE(x)     XFSIZE(struct section_language_data, x)
#define LANGUAGE_PARAM(x, t) { #x, t, LANGUAGE_OFFSET(x), LANGUAGE_SIZE(x) }
static const struct config_parse_info section_language_params[] =
{
  LANGUAGE_PARAM(id, "d"),
  LANGUAGE_PARAM(compile_id, "d"),
  LANGUAGE_PARAM(disabled, "d"),
  LANGUAGE_PARAM(binary, "d"),
  LANGUAGE_PARAM(priority_adjustment, "d"),
  LANGUAGE_PARAM(short_name, "s"),
  LANGUAGE_PARAM(long_name, "s"),
  LANGUAGE_PARAM(key, "s"),
  LANGUAGE_PARAM(arch, "s"),
  LANGUAGE_PARAM(src_sfx, "s"),
  LANGUAGE_PARAM(exe_sfx, "s"),
  LANGUAGE_PARAM(cmd, "s"),
  LANGUAGE_PARAM(content_type, "s"),

  LANGUAGE_PARAM(disable_auto_testing, "d"),
  LANGUAGE_PARAM(disable_testing, "d"),

  LANGUAGE_PARAM(compile_dir, "s"),
  LANGUAGE_PARAM(compile_real_time_limit, "d"),
  LANGUAGE_PARAM(compiler_env, "x"),

  { 0, 0, 0, 0 }
};

#define TESTER_OFFSET(x) XOFFSET(struct section_tester_data, x)
#define TESTER_SIZE(x)   XFSIZE(struct section_tester_data, x)
#define TESTER_PARAM(x, t) { #x, t, TESTER_OFFSET(x), TESTER_SIZE(x) }
static const struct config_parse_info section_tester_params[] =
{
  TESTER_PARAM(id, "d"),
  TESTER_PARAM(name, "s"),
  TESTER_PARAM(problem, "d"),
  TESTER_PARAM(problem_name, "s"),
  TESTER_PARAM(no_redirect, "d"),
  TESTER_PARAM(is_dos, "d"),
  TESTER_PARAM(skip_testing, "d"),
  TESTER_PARAM(arch, "s"),
  TESTER_PARAM(key, "s"),
  TESTER_PARAM(any, "d"),
  TESTER_PARAM(priority_adjustment, "d"),
  TESTER_PARAM(memory_limit_type, "s"),

  TESTER_PARAM(abstract, "d"),
  TESTER_PARAM(super, "x"),

  TESTER_PARAM(no_core_dump, "d"),
  TESTER_PARAM(enable_memory_limit_error, "d"),
  TESTER_PARAM(kill_signal, "s"),
  TESTER_PARAM(max_stack_size, "z"),
  TESTER_PARAM(max_data_size, "z"),
  TESTER_PARAM(max_vm_size, "z"),
  TESTER_PARAM(clear_env, "d"),
  TESTER_PARAM(time_limit_adjustment, "d"),

  TESTER_PARAM(run_dir, "s"),
  TESTER_PARAM(check_dir, "s"),
  TESTER_PARAM(errorcode_file, "s"),
  TESTER_PARAM(error_file, "s"),

  TESTER_PARAM(prepare_cmd, "s"),
  TESTER_PARAM(check_cmd, "s"),
  TESTER_PARAM(start_cmd, "s"),

  TESTER_PARAM(start_env, "x"),
  TESTER_PARAM(checker_env, "x"),

  { 0, 0, 0, 0 }
};

void prepare_problem_init_func(struct generic_section_config *);
static void tester_init_func(struct generic_section_config *);
static void global_init_func(struct generic_section_config *);
static void language_init_func(struct generic_section_config *);

static const struct config_section_info params[] =
{
  { "global", sizeof(struct section_global_data), section_global_params,
    0, global_init_func, prepare_global_free_func },
  { "problem", sizeof(struct section_problem_data), section_problem_params,
    0, prepare_problem_init_func, prepare_problem_free_func },
  { "language",sizeof(struct section_language_data),section_language_params,
    0, language_init_func, prepare_language_free_func },
  { "tester", sizeof(struct section_tester_data), section_tester_params,
    0, tester_init_func, prepare_tester_free_func },
  { NULL, 0, NULL }
};

int
find_tester(const serve_state_t state,int problem, char const *arch)
{
  int i;

  for (i = 1; i <= state->max_tester; i++) {
    if (!state->testers[i]) continue;
    if (state->testers[i]->any) continue;
    if (problem == state->testers[i]->problem
        && !strcmp(arch, state->testers[i]->arch))
      return i;
  }
  for (i = 1; i <= state->max_tester; i++) {
    if (!state->testers[i]) continue;
    if (state->testers[i]->any && !strcmp(arch, state->testers[i]->arch))
      return i;
  }
  
  return 0;
}

static void
global_init_func(struct generic_section_config *gp)
{
  struct section_global_data *p = (struct section_global_data *) gp;

  p->team_enable_src_view = -1;
  p->team_enable_rep_view = -1;
  p->team_enable_ce_view = -1;
  p->team_show_judge_report = -1;
  p->report_error_code = -1;
  p->disable_clars = -1;
  p->disable_team_clars = -1;
  p->ignore_compile_errors = -1;
  p->disable_failed_test_view = -1;
  p->enable_printing = -1;
  p->disable_banner_page = -1;
  p->prune_empty_users = -1;
  p->enable_full_archive = -1;
  p->always_show_problems = -1;
  p->disable_user_standings = -1;
  p->stand_show_ok_time = -1;
  p->stand_show_warn_number = -1;
  p->disable_auto_testing = -1;
  p->disable_testing = -1;
  p->show_astr_time = -1;
  p->enable_report_upload = -1;
  p->enable_runlog_merge = -1;
  p->secure_run = -1;
  p->enable_memory_limit_error = -1;
  p->ignore_success_time = -1;

  p->autoupdate_standings = -1;
  p->board_fog_time = -1;
  p->board_unfog_time = -1;
  p->contest_time = -1;
  p->tests_to_accept = -1;
  p->team_download_time = -1;
  p->ignore_duplicated_runs = -1;
  p->show_deadline = -1;
  p->inactivity_timeout = -1;
  p->checker_real_time_limit = -1;
  p->compile_real_time_limit = -1;
  p->use_gzip = -1;
  p->use_dir_hierarchy = -1;
  p->min_gzip_size = -1;
  p->team_page_quota = -1;
  p->enable_l10n = -1;
  p->enable_continue = -1;
  p->html_report = -1;
  p->xml_report = -1;
}

static void free_user_adjustment_info(struct user_adjustment_info*);
static void free_user_adjustment_map(struct user_adjustment_map*);

void
prepare_global_free_func(struct generic_section_config *gp)
{
  struct section_global_data *p = (struct section_global_data *) gp;

  sarray_free(p->a2ps_args);
  sarray_free(p->lpr_args);
  xfree(p->stand_header_txt);
  xfree(p->stand_footer_txt);
  xfree(p->stand2_header_txt);
  xfree(p->stand2_footer_txt);
  xfree(p->plog_header_txt);
  xfree(p->plog_footer_txt);
  sarray_free(p->user_priority_adjustments);
  sarray_free(p->contestant_status_legend);
  sarray_free(p->contestant_status_row_attr);
  sarray_free(p->stand_row_attr);
  sarray_free(p->stand_page_row_attr);
  sarray_free(p->stand_page_col_attr);
  prepare_free_variant_map(p->variant_map);
  free_user_adjustment_info(p->user_adjustment_info);
  free_user_adjustment_map(p->user_adjustment_map);
  xfree(p->unhandled_vars);

  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

static void
language_init_func(struct generic_section_config *gp)
{
  struct section_language_data *p = (struct section_language_data*) gp;

  p->compile_real_time_limit = -1;
}

void
prepare_language_free_func(struct generic_section_config *gp)
{
  struct section_language_data *p = (struct section_language_data*) gp;

  p->compiler_env = sarray_free(p->compiler_env);
  xfree(p->unhandled_vars);
  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

void
prepare_problem_init_func(struct generic_section_config *gp)
{
  struct section_problem_data *p = (struct section_problem_data*) gp;

  p->type_val = -1;
  p->scoring_checker = -1;
  p->manual_checking = -1;
  p->check_presentation = -1;
  p->use_stdin = -1;
  p->use_stdout = -1;
  p->binary_input = -1;
  p->ignore_exit_code = -1;
  p->time_limit = -1;
  p->time_limit_millis = -1;
  p->real_time_limit = -1;
  p->team_enable_rep_view = -1;
  p->team_enable_ce_view = -1;
  p->team_show_judge_report = -1;
  p->use_corr = -1;
  p->use_info = -1;
  p->use_tgz = -1;
  p->tests_to_accept = -1;
  p->accept_partial = -1;
  p->test_sfx[0] = 1;
  p->corr_sfx[0] = 1;
  p->info_sfx[0] = 1;
  p->tgz_sfx[0] = 1;
  p->run_penalty = -1;
  p->acm_run_penalty = -1;
  p->disqualified_penalty = -1;
  p->checker_real_time_limit = -1;
  p->variant_num = -1;
  p->disable_auto_testing = -1;
  p->disable_testing = -1;
  p->disable_user_submit = -1;
  p->disable_submit_after_ok = -1;
  p->enable_compilation = -1;
  p->skip_testing = -1;
  p->test_score = -1;
  p->full_score = -1;
  p->variable_full_score = -1;
  p->hidden = -1;
  p->priority_adjustment = -1000;
  p->test_pat[0] = 1;
  p->corr_pat[0] = 1;
  p->info_pat[0] = 1;
  p->tgz_pat[0] = 1;
  p->max_vm_size = -1L;
  p->max_stack_size = -1L;
  p->max_data_size = -1L;
}

static void free_testsets(int t, struct testset_info *p);
static void free_deadline_penalties(int t, struct penalty_info *p);
static void free_personal_deadlines(int t, struct pers_dead_info *p);

void
prepare_problem_free_func(struct generic_section_config *gp)
{
  struct section_problem_data *p = (struct section_problem_data*) gp;

  xfree(p->tscores);
  xfree(p->x_score_tests);
  sarray_free(p->test_sets);
  sarray_free(p->date_penalty);
  sarray_free(p->disable_language);
  sarray_free(p->enable_language);
  sarray_free(p->require);
  sarray_free(p->checker_env);
  sarray_free(p->lang_time_adj);
  sarray_free(p->personal_deadline);
  sarray_free(p->alternative);
  xfree(p->score_bonus_val);
  free_testsets(p->ts_total, p->ts_infos);
  free_deadline_penalties(p->dp_total, p->dp_infos);
  free_personal_deadlines(p->pd_total, p->pd_infos);
  xfree(p->unhandled_vars);

  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

static void
tester_init_func(struct generic_section_config *gp)
{
  struct section_tester_data *p = (struct section_tester_data*) gp;

  p->is_dos = -1;
  p->skip_testing = -1;
  p->no_redirect = -1;
  p->no_core_dump = -1;
  p->enable_memory_limit_error = -1;
  p->clear_env = -1;
  p->time_limit_adjustment = -1;
  p->priority_adjustment = -1000;
  p->max_vm_size = -1L;
  p->max_stack_size = -1L;
  p->max_data_size = -1L;
  p->memory_limit_type[0] = 1;
  p->memory_limit_type_val = -1;
}

void
prepare_tester_free_func(struct generic_section_config *gp)
{
  struct section_tester_data *p = (struct section_tester_data*) gp;

  sarray_free(p->super);
  sarray_free(p->start_env);
  sarray_free(p->checker_env);
  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

static char*
tester_get_name(void const *vpt)
{
  struct section_tester_data *pt = (struct section_tester_data *) vpt;
  return pt->name;
}

struct inheritance_info
{
  unsigned long  offset;        /* offset of this field */
  char          *name;          /* name of this field */

  int (*isdef_func)(void *);    /* checks, whether field is defined */
  void (*copy_func)(void *d, void *s); /* copies s to d */
};

int
inherit_fields(const struct inheritance_info *iinfo,
               void *obj, char *name, int stot, void **sups,
               char *(*get_name_func)(void const *))
{
  int   ii, j, defnum, defpos;
  void *objf, *sobjf;

  for (ii = 0; iinfo[ii].name; ii++) {
    objf = XPDEREF(void, obj, iinfo[ii].offset);
    if (iinfo[ii].isdef_func(objf)) continue;
    for (j = 0, defpos = -1, defnum = 0; j < stot; j++) {
      sobjf = XPDEREF(void, sups[j], iinfo[ii].offset);
      if (iinfo[ii].isdef_func(sobjf)) {
        defnum++;
        defpos = j;
      }
    }
    if (defnum > 1) {
      err("several supertesters define %s for %s",
          iinfo[ii].name, name);
      return -1;
    }
    if (defnum == 0) continue;
    sobjf = XPDEREF(void, sups[defpos], iinfo[ii].offset);
    info("%s.%s inherited from %s",
         name, iinfo[ii].name, get_name_func(sups[defpos]));
    iinfo[ii].copy_func(objf, sobjf);
  }

  return 0;
}

static int inh_isdef_int(void *vpint)
{
  int *pint = (int*) vpint;
  if (*pint != -1) return 1;
  return 0;
}
static int inh_isdef_int3(void *vpint)
{
  int *pint = (int*) vpint;
  if (*pint != -1000) return 1;
  return 0;
}
static int inh_isdef_size(void *vpsize)
{
  size_t *psize = (size_t*) vpsize;
  if (*psize != -1L) return 1;
  return 0;
}
static void inh_copy_int(void *dst, void *src)
{
  memcpy(dst, src, sizeof(int));
}
static void inh_copy_size(void *dst, void *src)
{
  memcpy(dst, src, sizeof(size_t));
}

static int inh_isdef_path(void *vppath)
{
  char *pc = (char *) vppath;
  if (*pc) return 1;
  return 0;
}
static int inh_isdef_path2(void *vppath)
{
  char *pc = (char *) vppath;

  if (*pc == 1) return 0;
  return 1;
}
static void inh_copy_path(void *dst, void *src)
{
  memcpy(dst, src, sizeof(path_t));
}

#define TESTER_INH(f,d,c) {TESTER_OFFSET(f),#f,inh_isdef_##d,inh_copy_##c }
static const struct inheritance_info tester_inheritance_info[] =
{
  TESTER_INH(arch, path, path),
  TESTER_INH(key, path, path),
  TESTER_INH(run_dir, path, path),
  TESTER_INH(no_core_dump, int, int),
  TESTER_INH(enable_memory_limit_error, int, int),
  TESTER_INH(clear_env, int, int),
  TESTER_INH(time_limit_adjustment, int, int),
  TESTER_INH(kill_signal, path, path),
  TESTER_INH(max_stack_size, size, size),
  TESTER_INH(max_data_size, size, size),
  TESTER_INH(max_vm_size, size, size),
  TESTER_INH(is_dos, int, int),
  TESTER_INH(skip_testing, int, int),
  TESTER_INH(no_redirect, int, int),
  TESTER_INH(priority_adjustment, int3, int),
  TESTER_INH(check_dir, path, path),
  TESTER_INH(errorcode_file, path, path),
  TESTER_INH(error_file, path, path),
  TESTER_INH(check_cmd, path, path),
  TESTER_INH(start_cmd, path, path),
  TESTER_INH(prepare_cmd, path, path),
  TESTER_INH(memory_limit_type, path2, path),

  { 0, 0, 0, 0 }
};

static int
process_abstract_tester(serve_state_t state, int i)
{
  struct section_tester_data *atp = state->abstr_testers[i], *katp;
  struct section_tester_data **sups;
  char ***envs;
  char *ish;
  char **nenv;
  int   stot, j, k;

  if (!atp->name[0]) {
    err("abstract tester must define tester name");
    return -1;
  }
  if (atp->any) {
    err("abstract tester cannot be default");
    return -1;
  }
  ish = atp->name;
  if (atp->id) {
    err("abstract tester %s must not have id", ish);
    return -1;
  }
  if (atp->problem || atp->problem_name[0]) {
    err("abstract tester %s cannot reference a problem", ish);
    return -1;
  }

  // no inheritance
  if (!atp->super || !atp->super[0]) {
    atp->is_processed = 1;
    return 0;
  }

  // count the number of supertesters and create array of references
  for (stot = 0; atp->super[stot]; stot++);
  sups = (struct section_tester_data**) alloca(stot * sizeof(sups[0]));
  envs = (char***) alloca((stot + 1) * sizeof(envs[0]));
  memset(sups, 0, stot * sizeof(sups[0]));
  memset(envs, 0, stot * sizeof(envs[0]));
  envs[stot] = atp->start_env;

  for (j = 0; j < stot; j++) {
    katp = 0;
    for (k = 0; k < state->max_abstr_tester; k++) {
      katp = state->abstr_testers[k];
      if (!katp || !katp->name[0]) continue;
      if (!strcmp(atp->super[j], katp->name)) break;
    }
    if (k >= state->max_abstr_tester || !katp) {
      err("abstract tester %s not found", atp->super[j]);
      return -1;
    }
    if (!katp->is_processed) {
      err("abstract tester %s must be defined before use", atp->super[j]);
      return -1;
    }
    sups[j] = katp;
    envs[j] = katp->start_env;
  }

  for (j = 0; j < stot; j++)
    fprintf(stderr, ">>%s\n", sups[j]->name);

  if (inherit_fields(tester_inheritance_info,
                     atp, ish, stot, (void**) sups,
                     tester_get_name) < 0)
    return -1;

  // merge all the start_env fields
  nenv = sarray_merge_arr(stot + 1, envs);
  sarray_free(atp->start_env);
  atp->start_env = nenv;

  if (atp->memory_limit_type[0] != 1) {
    atp->memory_limit_type_val = prepare_parse_memory_limit_type(atp->memory_limit_type);
    if (atp->memory_limit_type_val < 0) {
      err("invalid memory_limit_type `%s'", atp->memory_limit_type);
      return -1;
    }
  }

  atp->is_processed = 1;
  return 0;
}

static void
free_testsets(int t, struct testset_info *p)
{
  int i;

  if (!p) return;
  for (i = 0; i < t; i++)
    xfree(p[i].nums);
  memset(p, 0xab, t * sizeof(p[0]));
  xfree(p);
}

int *
prepare_parse_score_tests(const unsigned char *str,
                          int score)
{
  const unsigned char *p = str;
  int n, s, i, r;
  int *ps = 0;

  for (i = 0; i < score - 1; i++) {
    if ((r = sscanf(p, "%d%n", &s, &n)) != 1) {
      if (r == -1) {
        err("not enogh score specified");
      } else {
        err("cannot parse score_tests");
      }
      return 0;
    }
    if (s <= 0) {
      err("score test %d is invalid at position %d", s, i + 1);
      return 0;
    }
    p += n;
  }
  while (*p && isspace(*p)) p++;
  if (*p) {
    err("garbage after test specification");
    return 0;
  }
  XCALLOC(ps, score);
  for (i = 0, p = str; i < score - 1; i++) {
    sscanf(p, "%d%n", &s, &n);
    ps[i] = s;
    p += n;
    if (i > 0 && ps[i] < ps[i - 1]) {
      err("score_tests[%d] < score_tests[%d]", i + 1, i);
      xfree(ps);
      return 0;
    }
  }
  return ps;
}

static int
parse_testsets(char **set_in, int *p_total, struct testset_info **p_info)
{
  int total = 0;
  struct testset_info *info = 0;
  int i, n, x, t, score;
  unsigned char *s;

  if (!set_in || !set_in[0]) return 0;

  *p_total = 0;
  *p_info = 0;

  for (total = 0; set_in[total]; total++);
  info = (struct testset_info*) xcalloc(total, sizeof(info[0]));

  for (i = 0; i < total; i++) {
    s = set_in[i];
    t = -1;
    while (1) {
      n = 0;
      if (sscanf(s, "%d%n", &x, &n) != 1) break;
      if (x <= 0 || x >= 1000) {
        err("invalid test number in testset specification");
        return -1;
      }
      if (x > t) t = x;
      s += n;
    }

    if (t == -1) {
      err("no test defined in testset");
      return -1;
    }

    while (isspace(*s)) s++;
    if (*s != '=') {
      err("`=' expected in the testset specification");
      return -1;
    }
    s++;

    n = 0;
    if (sscanf(s, "%d %n", &score, &n) != 1) {
      err("score expected in the testset specification");
      return -1;
    }
    if (s[n]) {
      err("garbage after testset specification");
      return -1;
    }
    if (score < 0) {
      err("invalid score in testset specification");
      return -1;
    }

    info[i].total = t;
    info[i].score = score;
    info[i].testop = 0;
    info[i].scoreop = 0;
    info[i].nums = (unsigned char*) xcalloc(t, sizeof(info[i].nums[0]));

    s = set_in[i];
    while (1) {
      n = 0;
      if (sscanf(s, "%d%n", &x, &n) != 1) break;
      ASSERT(x > 0 && x < 1000);
      s += n;
      info[i].nums[x - 1] = 1;
    }
    /*
    fprintf(stderr, ">>%d\n", t);
    for (n = 0; n < t; n++)
      fprintf(stderr, " %d", info[i].nums[n]);
    fprintf(stderr, "\n");
    */
  }

  *p_info = info;
  *p_total = total;
  return 0;
}

static int
parse_date(const unsigned char *s, time_t *pd)
{
  int year, month, day, hour, min, sec, n;
  time_t t;
  struct tm tt;

  if (!s) goto failed;

  memset(&tt, 0, sizeof(tt));
  tt.tm_isdst = -1;
  while (1) {
    year = month = day = hour = min = sec = 0;
    if (sscanf(s, "%d/%d/%d %d:%d:%d %n", &year, &month, &day, &hour,
               &min, &sec, &n) == 6 && !s[n]) break;
    sec = 0;
    if (sscanf(s, "%d/%d/%d %d:%d %n", &year, &month, &day, &hour, &min, &n)
        == 5 && !s[n]) break;
    min = sec = 0;
    if (sscanf(s, "%d/%d/%d %d %n", &year, &month, &day, &hour, &n) == 4
        && !s[n]) break;
    hour = min = sec = 0;
    if (sscanf(s, "%d/%d/%d %n", &year, &month, &day, &n) == 3 && !s[n]) break;
    goto failed;
  }

  if (year < 1900 || year > 2100 || month < 1 || month > 12
      || day < 1 || day > 31 || hour < 0 || hour >= 24
      || min < 0 || min >= 60 || sec < 0 || sec >= 60) goto failed;
  tt.tm_sec = sec;
  tt.tm_min = min;
  tt.tm_hour = hour;
  tt.tm_mday = day;
  tt.tm_mon = month - 1;
  tt.tm_year = year - 1900;
  if ((t = mktime(&tt)) == (time_t) -1) goto failed;
  *pd = t;
  return 0;

 failed:
  return -1;
}

static void
free_deadline_penalties(int t, struct penalty_info *p)
{
  if (!p) return;
  memset(p, 0xab, t * sizeof(p[0]));
  xfree(p);
}

static int
parse_deadline_penalties(char **dpstr, int *p_total,
                         struct penalty_info **p_pens)
{
  int total = 0, i, n, x;
  struct penalty_info *v = 0;
  const char *s;
  size_t maxlen = 0, curlen;
  unsigned char *b1, *b2, *b3;
  time_t tt;

  *p_total = 0;
  *p_pens = 0;
  if (!dpstr || !*dpstr) return 0;

  for (i = 0; dpstr[i]; i++) {
    curlen = strlen(dpstr[i]);
    if (curlen > maxlen) maxlen = curlen;
    total++;
  }
  if (!total) return 0;
  XCALLOC(v, total);
  b1 = (unsigned char*) alloca(maxlen + 10);
  b2 = (unsigned char*) alloca(maxlen + 10);
  b3 = (unsigned char*) alloca(maxlen + 10);

  for (i = 0; (s = dpstr[i]); i++) {
    if (sscanf(s, "%s%s%s%n", b1, b3, b2, &n) == 3 && !s[n]) {
      strcat(b1, " ");
      strcat(b1, b3);
    } else if (sscanf(s, "%s%s%n", b1, b2, &n) == 2 && !s[n]) {
      // do nothing
    } else if (sscanf(s, "%s%n", b2, &n) == 1 && !s[n]) {
      if (maxlen + 10 < 64) b1 = (unsigned char*) alloca(64);
      strcpy(b1, "2038/01/19");
    }  else {
      err("%d: invalid date penalty specification %s", i + 1, s);
      goto failure;
    }
    n = x = 0;
    if (sscanf(b2, "%d%n", &x, &n) != 1 || b2[n]) {
      err("%d: invalid penalty specification %s", i + 1, b2);
      goto failure;
    }
    if (parse_date(b1, &tt) < 0) {
      err("%d: invalid date specification %s", i + 1, b1);
      goto failure;
    }
    v[i].deadline = tt;
    v[i].penalty = x;
  }

  /*
  fprintf(stderr, ">>Total %d\n", total);
  for (i = 0; i < total; i++)
    fprintf(stderr, ">>[%d]: %ld,%d\n", i + 1, v[i].deadline, v[i].penalty);
  */

  *p_total = total;
  *p_pens = v;
  return 0;

 failure:
  xfree(v);
  return -1;
}

static void
free_personal_deadlines(int t, struct pers_dead_info *p)
{
  int i;

  if (!p) return;
  for (i = 0; i < t; i++)
    xfree(p[i].login);
  memset(p, 0xab, t * sizeof(p[0]));
  xfree(p);
}

/* login deadline */
static int
parse_personal_deadlines(char **pdstr, int *p_total,
                         struct pers_dead_info **p_dl)
{
  int total, i, maxlen = 0, n;
  struct pers_dead_info *dinfo;
  unsigned char *s1, *s2, *s3;

  for (total = 0; pdstr[total]; total++) {
    if ((i = strlen(pdstr[total])) > maxlen) maxlen = i;
  }

  if (!total) {
    *p_dl = 0;
    *p_total = 0;
    return 0;
  }

  XCALLOC(dinfo, total);
  s1 = alloca(maxlen + 16);
  s2 = alloca(maxlen + 16);
  s3 = alloca(maxlen + 16);

  for (i = 0; i < total; i++) {
    if (sscanf(pdstr[i], "%s%s%s%n", s1, s2, s3, &n) == 3 && !pdstr[i][n]) {
      strcat(s2, " ");
      strcat(s2, s3);
    } else if (!sscanf(pdstr[i], "%s%s%n", s1, s2, &n) == 2 && !pdstr[i][n]) {
    } else if (!sscanf(pdstr[i], "%s%n", s1, &n) == 1 && !pdstr[i][n]) {
      strcpy(s2, "2038/01/19");
    }

    if (parse_date(s2, &dinfo[i].deadline) < 0) {
      err("%d: invalid date specification %s", i + 1, s2);
      return -1;
    }
    dinfo[i].login = xstrdup(s1);
  }

  // debug
  /*
  fprintf(stderr, "personal deadlines:\n");
  for (i = 0; i < total; i++) {
    fprintf(stderr, "[%d] %s %ld\n", i, dinfo[i].login, dinfo[i].deadline);
  }
  */

  *p_dl = dinfo;
  *p_total = total;
  return i;
}

void
prepare_free_variant_map(struct variant_map *p)
{
  int i;

  if (!p) return;

  for (i = 0; i < p->u; i++) {
    xfree(p->v[i].login);
    xfree(p->v[i].name);
    xfree(p->v[i].variants);
  }
  xfree(p->prob_map);
  xfree(p->prob_rev_map);
  xfree(p->v);
  xfree(p->user_map);
  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

static struct variant_map *
parse_variant_map(serve_state_t state, const unsigned char *path)
{
  unsigned char buf[1200];
  unsigned char login_buf[sizeof(buf)];
  unsigned char *p;
  int vintage, n, len, i, j, v;
  FILE *f = 0;
  struct variant_map *pmap = 0;

  XCALLOC(pmap, 1);
  XCALLOC(pmap->prob_map, state->max_prob + 1);
  XCALLOC(pmap->prob_rev_map, state->max_prob + 1);
  pmap->var_prob_num = 0;
  for (i = 1; i <= state->max_prob; i++) {
    if (!state->probs[i] || state->probs[i]->variant_num <= 0) continue;
    pmap->prob_map[i] = ++pmap->var_prob_num;
    pmap->prob_rev_map[pmap->var_prob_num] = i;
  }
  pmap->a = 16;
  XCALLOC(pmap->v, pmap->a);

  if (!(f = fopen(path, "r"))) {
    err("Cannot open variant map file '%s'", path);
    goto failed;
  }
  if (!fgets(buf, sizeof(buf), f)) {
    err("Unexpected EOF in variant map file '%s'", path);
    goto failed;
  }
  len = strlen(buf);
  if (len > 1024) {
    err("Line is too long in '%s'", path);
    goto failed;
  }
  while (len > 0 && isspace(buf[len - 1])) buf[--len] = 0;
  if (sscanf(buf, " < variant_map version = \"%d\" >%n",
             &vintage, &n) != 1 || buf[n]) {
    err("Invalid header of the variant map file '%s'", path);
    goto failed;
  }
  if (vintage != 1) {
    err("Cannot handle variant map file '%s' version %d", path, vintage);
    goto failed;
  }

  while (fgets(buf, sizeof(buf), f)) {
    if ((p = strchr(buf, '#'))) *p = 0;
    len = strlen(buf);
    if (len > 1024) {
      err("Line is too long in '%s'", path);
      goto failed;
    }
    while (len > 0 && isspace(buf[len - 1])) buf[--len] = 0;
    if (!len) continue;
    if (!strcmp(buf, "</variant_map>")) break;

    if (pmap->u >= pmap->a) {
      pmap->a *= 2;
      pmap->v = (typeof(pmap->v)) xrealloc(pmap->v,
                                           pmap->a * sizeof(pmap->v[0]));
    }
    memset(&pmap->v[pmap->u], 0, sizeof(pmap->v[0]));
    XCALLOC(pmap->v[pmap->u].variants, pmap->var_prob_num + 1);

    p = buf;
    if (sscanf(p, "%s%n", login_buf, &n) != 1) {
      err("Cannot read team login");
      goto failed;
    }
    p += n;
    pmap->v[pmap->u].login = xstrdup(login_buf);

    for (j = 1; j <= pmap->var_prob_num; j++) {
      i = pmap->prob_rev_map[j];
      ASSERT(i > 0 && i <= state->max_prob);
      ASSERT(state->probs[i]);
      ASSERT(state->probs[i]->variant_num > 0);
      if (sscanf(p, "%d%n", &v, &n) != 1) {
        err("Cannot read variant for team %s and problem %s",
            login_buf, state->probs[i]->short_name);
        goto failed;
      }
      if (v < 0 || v > state->probs[i]->variant_num) {
        err("Invalid variant %d for team %s and problem %s",
            v, login_buf, state->probs[i]->short_name);
        goto failed;
      }
      p += n;
      pmap->v[pmap->u].variants[j] = v;
    }
    pmap->u++;
  }

  if (ferror(f)) {
    err("Input error from '%s'", path);
    goto failed;
  }

#if 0
  fprintf(stderr, "Parsed variant map version %d\n", vintage);
  for (i = 0; i < pmap->u; i++) {
    fprintf(stderr, "%s: ", pmap->v[i].login);
    for (j = 1; j <= pmap->var_prob_num; j++)
      fprintf(stderr, "%s(%d) ",
              state->probs[pmap->prob_rev_map[j]]->short_name,
              pmap->v[i].variants[j]);
    fprintf(stderr, "\n");
  }
#endif

  fclose(f);
  return pmap;

 failed:
  if (pmap) {
    for (i = 0; i < pmap->u; i++) {
      xfree(pmap->v[i].login);
      xfree(pmap->v[i].name);
      xfree(pmap->v[i].variants);
    }
    xfree(pmap->user_map);
    xfree(pmap->v);
    xfree(pmap->prob_map);
    xfree(pmap->prob_rev_map);
    xfree(pmap);
  }
  fclose(f);
  return 0;
}

static void
free_user_adjustment_map(struct user_adjustment_map *p)
{
  if (!p) return;

  xfree(p->user_map);
  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

static void
free_user_adjustment_info(struct user_adjustment_info *p)
{
  int i;

  if (!p) return;

  for (i = 0; p[i].login; i++)
    xfree(p[i].login);
  xfree(p);
}

static struct user_adjustment_info *
parse_user_adjustment(char **strs)
{
  int count = 0, i, x, n;
  struct user_adjustment_info *pinfo = 0;

  if (!strs) return 0;
  for (; strs[count]; count++);
  XCALLOC(pinfo, count + 1);
  for (i = 0; i < count; i++) {
    pinfo[i].login = xmalloc(strlen(strs[i]) + 1);
    n = 0;
    if (sscanf("%s %d %n", pinfo[i].login, &x, &n) != 2 || strs[i][n]) {
      err("invalid user adjustment line %d", i + 1);
      return 0;
    }
    if (x <= -1000 || x >= 1000) {
      err("user priority adjustment %d at line %d is invalid", x, i + 1);
      return 0;
    }
    pinfo[i].adjustment = x;
  }
  return pinfo;
}

static int
parse_score_bonus(const unsigned char *str, int *p_total, int **p_values)
{
  int total = 0, p, n, r, x, i;
  int *values = 0;

  p = 0;
  while (1) {
    if ((r = sscanf(str + p, "%d%n", &x, &n)) < 0) break;
    if (r != 1 || (str[p + n] && !isspace(str[p + n]))) {
      err("invalid score_bonus specification `%s'", str);
      goto failed;
    }
    if (x < -100000 || x > 100000) {
      err("score_bonus value %d is out of range", x);
      goto failed;
    }
    total++;
    p += n;
  }

  XCALLOC(values, total);
  for (i = 0, p = 0; i < total; i++, p += n) {
    if (sscanf(str + p, "%d%n", &x, &n) != 1) {
      err("oops, something strange during score_bonus parsing");
      goto failed;
    }
    values[i] = x;
  }

  if (p_total) *p_total = total;
  if (p_values) *p_values = values;
  return 0;

 failed:
  xfree(values);
  return -1;
}

const unsigned char * const problem_type_str[] =
{
  [PROB_TYPE_STANDARD] = "standard",
  [PROB_TYPE_OUTPUT_ONLY] = "output-only",
  [PROB_TYPE_SHORT_ANSWER] = "short-answer",
  [PROB_TYPE_TEXT_ANSWER] = "text-answer",
  [PROB_TYPE_SELECT_ONE] = "select-one",
  [PROB_TYPE_SELECT_MANY] = "select-many",

  [PROB_TYPE_LAST] = 0,
};

static int
parse_problem_type(const unsigned char *str)
{
  int i;

  if (!str) return 0;
  for (i = 0; i < PROB_TYPE_LAST; i++)
    if (problem_type_str[i] && !strcasecmp(str, problem_type_str[i]))
      return i;
  return -1;
}
const unsigned char *
prepare_unparse_problem_type(int val)
{
  ASSERT(val >= 0 && val < PROB_TYPE_LAST);
  ASSERT(problem_type_str[val]);
  return problem_type_str[val];
}

const unsigned char * const memory_limit_type_str[] =
{
  [MEMLIMIT_TYPE_DEFAULT] = "default",
  [MEMLIMIT_TYPE_DOS] = "dos",
  [MEMLIMIT_TYPE_JAVA] = "java",

  [MEMLIMIT_TYPE_LAST] = 0,
};
int
prepare_parse_memory_limit_type(const unsigned char *str)
{
  int i;

  if (!str || !*str) return 0;
  for (i = 0; i < MEMLIMIT_TYPE_LAST; i++)
    if (memory_limit_type_str[i] && !strcasecmp(str, memory_limit_type_str[i]))
      return i;
  return -1;
}

static void
make_stand_file_name_2(serve_state_t state)
{
  path_t b1, b2;
  unsigned char *s = state->global->standings_file_name;
  int i;

  if (state->global->users_on_page <= 0) return;
  i = strlen(s);
  ASSERT(i > 0);

  snprintf(b1, sizeof(b1), s, 1);
  snprintf(b2, sizeof(b2), s, 2);
  if (strcmp(b1, b2) != 0) {
    snprintf(state->global->stand_file_name_2,
             sizeof(state->global->stand_file_name_2), "%s", s);
    return;
  }

  i--;
  while (i >= 0 && s[i] != '.' && s[i] != '/') i--;
  if (i < 0 || s[i] == '/') i++;
  snprintf(state->global->stand_file_name_2,
           sizeof(state->global->stand_file_name_2),
           "%.*s%s%s", i, s, "%d", s + i);
}

static int
set_defaults(serve_state_t state, int mode)
{
  struct generic_section_config *p;
  struct section_problem_data *aprob;

  int i, j, si;
  char *ish;
  char *sish;
  void *vptr;

  size_t tmp_len = 0;
  int r;

  /* find global section */
  for (p = state->config; p; p = p->next)
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  if (!p) {
    err("Global configuration settings not found");
    return -1;
  }
  state->global = (struct section_global_data*) p;

  /* userlist-server interaction */
  if (mode == PREPARE_SERVE) {
#if defined EJUDGE_SOCKET_PATH
    if (!state->global->socket_path[0]) {
      snprintf(state->global->socket_path, sizeof(state->global->socket_path),
               "%s", EJUDGE_SOCKET_PATH);
    }
#endif /* EJUDGE_SOCKET_PATH */
    if (!state->global->socket_path[0]) {
      err("global.socket_path must be set");
      return -1;
    }
  }

  /* directory poll intervals */
  if (state->global->sleep_time < 0 || state->global->sleep_time > 10000) {
    err("Invalid global.sleep_time value");
    return -1;
  }
  if (mode == PREPARE_SERVE) {
    if (state->global->serve_sleep_time < 0 || state->global->serve_sleep_time > 10000) {
      err("Invalid global.serve_sleep_time value");
      return -1;
    }
  }
  if (!state->global->sleep_time && !state->global->serve_sleep_time) {
    info("global.sleep_time set to %d", DFLT_G_SLEEP_TIME);
    state->global->sleep_time = DFLT_G_SLEEP_TIME;
    if (mode == PREPARE_SERVE) {
      info("global.serve_sleep_time set to %d", DFLT_G_SERVE_SLEEP_TIME);
      state->global->serve_sleep_time = DFLT_G_SERVE_SLEEP_TIME;
    }
  } else if (!state->global->sleep_time) {
    info("global.sleep_time set to %d", DFLT_G_SLEEP_TIME);
    state->global->sleep_time = DFLT_G_SLEEP_TIME;
  } else if (mode == PREPARE_SERVE && !state->global->serve_sleep_time) {
    info("global.serve_sleep_time set to global.sleep_time");
    state->global->serve_sleep_time = state->global->sleep_time;
  }

  if (state->global->team_enable_src_view == -1)
    state->global->team_enable_src_view = DFLT_G_TEAM_ENABLE_SRC_VIEW;
  if (state->global->team_enable_rep_view == -1)
    state->global->team_enable_rep_view = DFLT_G_TEAM_ENABLE_REP_VIEW;
  if (state->global->team_enable_ce_view == -1)
    state->global->team_enable_ce_view = DFLT_G_TEAM_ENABLE_CE_VIEW;
  if (state->global->team_show_judge_report == -1)
    state->global->team_show_judge_report = DFLT_G_TEAM_SHOW_JUDGE_REPORT;
  if (state->global->report_error_code == -1)
    state->global->report_error_code = DFLT_G_REPORT_ERROR_CODE;
  if (state->global->disable_clars == -1)
    state->global->disable_clars = DFLT_G_DISABLE_CLARS;
  if (state->global->disable_team_clars == -1)
    state->global->disable_team_clars = DFLT_G_DISABLE_TEAM_CLARS;
  if (state->global->ignore_compile_errors == -1)
    state->global->ignore_compile_errors = DFLT_G_IGNORE_COMPILE_ERRORS;
  if (state->global->disable_failed_test_view == -1)
    state->global->disable_failed_test_view = DFLT_G_DISABLE_FAILED_TEST_VIEW;
  if (state->global->ignore_duplicated_runs == -1)
    state->global->ignore_duplicated_runs = DFLT_G_IGNORE_DUPLICATED_RUNS;
  if (state->global->show_deadline == -1)
    state->global->show_deadline = DFLT_G_SHOW_DEADLINE;
  if (state->global->enable_printing == -1)
    state->global->enable_printing = DFLT_G_ENABLE_PRINTING;
  if (state->global->disable_banner_page == -1)
    state->global->disable_banner_page = DFLT_G_DISABLE_BANNER_PAGE;
  if (state->global->prune_empty_users == -1)
    state->global->prune_empty_users = DFLT_G_PRUNE_EMPTY_USERS;
  if (state->global->enable_full_archive == -1)
    state->global->enable_full_archive = DFLT_G_ENABLE_FULL_ARCHIVE;
  if (state->global->always_show_problems == -1)
    state->global->always_show_problems = DFLT_G_ALWAYS_SHOW_PROBLEMS;
  if (state->global->disable_user_standings == -1)
    state->global->disable_user_standings = DFLT_G_DISABLE_USER_STANDINGS;
  if (state->global->stand_show_ok_time == -1)
    state->global->stand_show_ok_time = DFLT_G_STAND_SHOW_OK_TIME;
  if (state->global->stand_show_warn_number == -1)
    state->global->stand_show_warn_number = DFLT_G_STAND_SHOW_WARN_NUMBER;
  if (state->global->autoupdate_standings == -1)
    state->global->autoupdate_standings = DFLT_G_AUTOUPDATE_STANDINGS;
  if (state->global->disable_auto_testing == -1)
    state->global->disable_auto_testing = DFLT_G_DISABLE_AUTO_TESTING;
  if (state->global->disable_testing == -1)
    state->global->disable_testing = DFLT_G_DISABLE_TESTING;
  if (state->global->show_astr_time == -1)
    state->global->show_astr_time = DFLT_G_SHOW_ASTR_TIME;
  if (state->global->enable_report_upload == -1)
    state->global->enable_report_upload = DFLT_G_ENABLE_REPORT_UPLOAD;
  if (state->global->enable_runlog_merge == -1)
    state->global->enable_runlog_merge = DFLT_G_ENABLE_RUNLOG_MERGE;
  if (state->global->ignore_success_time == -1)
    state->global->ignore_success_time = DFLT_G_IGNORE_SUCCESS_TIME;
  if (state->global->secure_run == -1)
    state->global->secure_run = DFLT_G_SECURE_RUN;
  if (state->global->enable_memory_limit_error == -1)
    state->global->enable_memory_limit_error = DFLT_G_ENABLE_MEMORY_LIMIT_ERROR;

#if defined EJUDGE_HTTPD_HTDOCS_DIR
  if (!state->global->htdocs_dir[0]) {
    snprintf(state->global->htdocs_dir, sizeof(state->global->htdocs_dir),
             "%s", EJUDGE_HTTPD_HTDOCS_DIR);
  }
#endif

  if (state->global->stand_ignore_after[0] &&
      parse_date(state->global->stand_ignore_after, &state->global->stand_ignore_after_d) < 0) {
    err("cannot parse stand_ignore_after parameter");
    return -1;
  }
  if (state->global->appeal_deadline[0] &&
      parse_date(state->global->appeal_deadline, &state->global->appeal_deadline_d) < 0) {
    err("cannot parse appeal_deadline parameter");
    return -1;
  }
  if (state->global->contest_finish_time[0] &&
      parse_date(state->global->contest_finish_time,
                 &state->global->contest_finish_time_d) < 0) {
    err("cannot parse contest_finish_time parameter");
    return -1;
  }

#define GLOBAL_INIT_NUM_FIELD(f,v) do { if (!state->global->f) { info("global.%s set to %d", #f, v); state->global->f = v; } } while (0)
  /* limits (serve) */
  if (mode == PREPARE_SERVE) {
    GLOBAL_INIT_NUM_FIELD(max_run_size, DFLT_G_MAX_RUN_SIZE);
    GLOBAL_INIT_NUM_FIELD(max_run_num, DFLT_G_MAX_RUN_NUM);
    GLOBAL_INIT_NUM_FIELD(max_run_total, DFLT_G_MAX_RUN_TOTAL);
    GLOBAL_INIT_NUM_FIELD(max_clar_size, DFLT_G_MAX_CLAR_SIZE);
    GLOBAL_INIT_NUM_FIELD(max_clar_num, DFLT_G_MAX_CLAR_NUM);
    GLOBAL_INIT_NUM_FIELD(max_clar_total, DFLT_G_MAX_CLAR_TOTAL);
  }

  /* timings */
  if (state->global->board_fog_time < 0) {
    info("global.board_fog_time set to %d", DFLT_G_BOARD_FOG_TIME);
    state->global->board_fog_time = DFLT_G_BOARD_FOG_TIME;
  }
  state->global->board_fog_time *= 60;
  if (state->global->board_unfog_time == -1) {
    info("global.board_unfog_time set to %d", DFLT_G_BOARD_UNFOG_TIME);
    state->global->board_unfog_time = DFLT_G_BOARD_UNFOG_TIME;
  }
  state->global->board_unfog_time *= 60;
  if (state->global->contest_time < -1) {
    err("bad value of global.contest_time: %d", state->global->contest_time);
    return -1;
  }
  if (state->global->contest_time == -1) {
    info("global.contest_time set to %d", DFLT_G_CONTEST_TIME);
    state->global->contest_time = DFLT_G_CONTEST_TIME;
  }
  state->global->contest_time *= 60;

  if (mode == PREPARE_SERVE || mode == PREPARE_RUN) {
    if (state->global->inactivity_timeout == -1) {
      info("global.inactivity_timeout set to %d", DFLT_G_INACTIVITY_TIMEOUT);
      state->global->inactivity_timeout = DFLT_G_INACTIVITY_TIMEOUT;
    }
  }

  if (!state->global->root_dir[0]) {
    err("global.root_dir must be set!");
    return -1;
  }

  /* root_dir, conf_dir, var_dir */
  if (!state->global->root_dir[0] && !state->global->var_dir[0] && !state->global->conf_dir[0]) {
    info("global.root_dir set to %s", DFLT_G_ROOT_DIR);
    info("global.conf_dir set to %s", DFLT_G_CONF_DIR);
    info("global.var_dir set to %s", DFLT_G_VAR_DIR);
    snprintf(state->global->root_dir, sizeof(state->global->root_dir),
             "%s", DFLT_G_ROOT_DIR);
    path_init(state->global->conf_dir, state->global->root_dir, DFLT_G_CONF_DIR);
    path_init(state->global->var_dir, state->global->root_dir, DFLT_G_VAR_DIR);
  } else if (state->global->root_dir[0]) {
    if (!state->global->conf_dir[0]) {
      info("global.conf_dir set to %s", DFLT_G_CONF_DIR);
    }
    if (!state->global->var_dir[0]) {
      info("global.var_dir set to %s", DFLT_G_VAR_DIR);
    }
    path_init(state->global->conf_dir, state->global->root_dir, DFLT_G_CONF_DIR);
    path_init(state->global->var_dir, state->global->root_dir, DFLT_G_VAR_DIR);
  } else if (!state->global->var_dir[0]) {
    err("global.var_dir must be set!");
    return -1;
  } else if (!state->global->conf_dir[0]) {
    err("global.conf_dir must be set!");
    return -1;
  }

  /* CONFIGURATION FILES DEFAULTS */
#define GLOBAL_INIT_FIELD(f,d,c) do { if (!state->global->f[0]) { info("global." #f " set to %s", d); snprintf(state->global->f, sizeof(state->global->f), "%s", d); } pathmake2(state->global->f,state->global->c, "/", state->global->f, NULL); } while (0)

#if defined EJUDGE_SCRIPT_DIR
  if (!state->global->script_dir[0]) {
    snprintf(state->global->script_dir, sizeof(state->global->script_dir), "%s",
             EJUDGE_SCRIPT_DIR);
    info("global.script_dir is set to %s", state->global->script_dir);
  }
  if (!state->global->ejudge_checkers_dir[0]) {
    snprintf(state->global->ejudge_checkers_dir, sizeof(state->global->ejudge_checkers_dir),
             "%s", EJUDGE_SCRIPT_DIR);
    info("global.ejudge_checkers_dir is set to %s",
         state->global->ejudge_checkers_dir);
  }
#endif /* EJUDGE_SCRIPT_DIR */

  if (mode == PREPARE_RUN || mode == PREPARE_SERVE) {
    GLOBAL_INIT_FIELD(test_dir, DFLT_G_TEST_DIR, conf_dir);
    GLOBAL_INIT_FIELD(corr_dir, DFLT_G_CORR_DIR, conf_dir);
    GLOBAL_INIT_FIELD(info_dir, DFLT_G_INFO_DIR, conf_dir);
    GLOBAL_INIT_FIELD(tgz_dir, DFLT_G_TGZ_DIR, conf_dir);
  }

  if (mode == PREPARE_RUN) {
    GLOBAL_INIT_FIELD(checker_dir, DFLT_G_CHECKER_DIR, conf_dir);
  }
  if (mode == PREPARE_SERVE) {
    GLOBAL_INIT_FIELD(statement_dir, DFLT_G_STATEMENT_DIR, conf_dir);
  }

  if (mode != PREPARE_COMPILE) {
    if (!state->global->info_sfx[0]) {
      snprintf(state->global->info_sfx, sizeof(state->global->info_sfx),
               "%s", DFLT_G_INFO_SFX);
      info("global.info_sfx set to %s", state->global->info_sfx);
    }
    if (!state->global->tgz_sfx[0]) {
      snprintf(state->global->tgz_sfx, sizeof(state->global->tgz_sfx),
               "%s", DFLT_G_TGZ_SFX);
      info("global.tgz_sfx set to %s", state->global->tgz_sfx);
    }
  }

  if (mode == PREPARE_SERVE) {
    GLOBAL_INIT_FIELD(run_log_file, DFLT_G_RUN_LOG_FILE, var_dir);
    GLOBAL_INIT_FIELD(clar_log_file, DFLT_G_CLAR_LOG_FILE, var_dir);
    GLOBAL_INIT_FIELD(archive_dir, DFLT_G_ARCHIVE_DIR, var_dir);
    GLOBAL_INIT_FIELD(clar_archive_dir, DFLT_G_CLAR_ARCHIVE_DIR, archive_dir);
    GLOBAL_INIT_FIELD(run_archive_dir, DFLT_G_RUN_ARCHIVE_DIR, archive_dir);
    GLOBAL_INIT_FIELD(report_archive_dir,DFLT_G_REPORT_ARCHIVE_DIR,archive_dir);
    GLOBAL_INIT_FIELD(xml_report_archive_dir,DFLT_G_XML_REPORT_ARCHIVE_DIR,archive_dir);
    GLOBAL_INIT_FIELD(full_archive_dir, DFLT_G_FULL_ARCHIVE_DIR, archive_dir);
    GLOBAL_INIT_FIELD(audit_log_dir, DFLT_G_AUDIT_LOG_DIR, archive_dir);
    GLOBAL_INIT_FIELD(team_report_archive_dir,DFLT_G_TEAM_REPORT_ARCHIVE_DIR,archive_dir);
    GLOBAL_INIT_FIELD(team_extra_dir, DFLT_G_TEAM_EXTRA_DIR, var_dir);

    GLOBAL_INIT_FIELD(status_dir, DFLT_G_STATUS_DIR, var_dir);
    GLOBAL_INIT_FIELD(serve_socket, DFLT_G_SERVE_SOCKET, var_dir);
    if (state->global->variant_map_file) {
      GLOBAL_INIT_FIELD(variant_map_file, "", conf_dir);
    }
  }

  if (mode == PREPARE_COMPILE || mode == PREPARE_SERVE) {
    GLOBAL_INIT_FIELD(compile_dir, DFLT_G_COMPILE_DIR, var_dir);
    pathmake(state->global->compile_queue_dir, state->global->compile_dir, "/",
             DFLT_G_COMPILE_QUEUE_DIR, 0);
    info("global.compile_queue_dir is %s", state->global->compile_queue_dir);
    pathmake(state->global->compile_src_dir, state->global->compile_dir, "/",
             DFLT_G_COMPILE_SRC_DIR, 0);
    info("global.compile_src_dir is %s", state->global->compile_src_dir);
  }

  if (mode == PREPARE_SERVE) {
    /* compile_out_dir is no longer parametrized, also it uses compile_dir */
    snprintf(state->global->compile_out_dir, sizeof(state->global->compile_out_dir),
             "%s/%06d", state->global->compile_dir, state->global->contest_id);
    info("global.compile_out_dir is %s", state->global->compile_out_dir);
    pathmake(state->global->compile_status_dir, state->global->compile_out_dir, "/",
             DFLT_G_COMPILE_STATUS_DIR, 0);
    info("global.compile_status_dir is %s", state->global->compile_status_dir);
    pathmake(state->global->compile_report_dir, state->global->compile_out_dir, "/",
             DFLT_G_COMPILE_REPORT_DIR, 0);
    info("global.compile_report_dir is %s", state->global->compile_report_dir);
  }

  GLOBAL_INIT_FIELD(work_dir, DFLT_G_WORK_DIR, var_dir);
  GLOBAL_INIT_FIELD(print_work_dir, DFLT_G_PRINT_WORK_DIR, work_dir);
  GLOBAL_INIT_FIELD(diff_work_dir, DFLT_G_DIFF_WORK_DIR, work_dir);

  if (!state->global->a2ps_path[0]) {
    strcpy(state->global->a2ps_path, DFLT_G_A2PS_PATH);
  }
  if (!state->global->lpr_path[0]) {
    strcpy(state->global->lpr_path, DFLT_G_LPR_PATH);
  }
  if (!state->global->diff_path[0]) {
    strcpy(state->global->diff_path, DFLT_G_DIFF_PATH);
  }

  if (state->global->team_page_quota < 0) {
    state->global->team_page_quota = DFLT_G_TEAM_PAGE_QUOTA;
  }

  if (mode == PREPARE_COMPILE) {
    GLOBAL_INIT_FIELD(compile_work_dir, DFLT_G_COMPILE_WORK_DIR, work_dir);
  }

  if (mode == PREPARE_RUN || mode == PREPARE_SERVE) {
    GLOBAL_INIT_FIELD(run_dir, DFLT_G_RUN_DIR, var_dir);
    pathmake(state->global->run_queue_dir, state->global->run_dir, "/",
             DFLT_G_RUN_QUEUE_DIR, 0);
    info("global.run_queue_dir is %s", state->global->run_queue_dir);
    pathmake(state->global->run_exe_dir, state->global->run_dir, "/",
             DFLT_G_RUN_EXE_DIR, 0);
    info("global.run_exe_dir is %s", state->global->run_exe_dir);
  }
  if (mode == PREPARE_SERVE) {
    snprintf(state->global->run_out_dir, sizeof(state->global->run_out_dir),
             "%s/%06d", state->global->run_dir, state->global->contest_id);
    info("global.run_out_dir is %s", state->global->run_out_dir);
    pathmake(state->global->run_status_dir, state->global->run_out_dir, "/",
             DFLT_G_RUN_STATUS_DIR, 0);
    info("global.run_status_dir is %s", state->global->run_status_dir);
    pathmake(state->global->run_report_dir, state->global->run_out_dir, "/",
             DFLT_G_RUN_REPORT_DIR, 0);
    info("global.run_report_dir is %s", state->global->run_report_dir);
    if (state->global->team_enable_rep_view) {
      pathmake(state->global->run_team_report_dir, state->global->run_out_dir, "/",
               DFLT_G_RUN_TEAM_REPORT_DIR, 0);
      info("global.run_team_report_dir is %s", state->global->run_team_report_dir);
    }
    if (state->global->enable_full_archive) {
      pathmake(state->global->run_full_archive_dir, state->global->run_out_dir, "/",
               DFLT_G_RUN_FULL_ARCHIVE_DIR, 0);
      info("global.run_full_archive_dir is %s", state->global->run_full_archive_dir);
    }
  }

  if (mode == PREPARE_RUN) {
    GLOBAL_INIT_FIELD(run_work_dir, DFLT_G_RUN_WORK_DIR, work_dir);
    GLOBAL_INIT_FIELD(run_check_dir, DFLT_G_RUN_CHECK_DIR, work_dir);
  }

  /* score_system must be either "acm", either "kirov"
   * "acm" is the default
   */
  if (!state->global->score_system[0]) {
    state->global->score_system_val = SCORE_ACM;
  } else if (!strcasecmp(state->global->score_system, "acm")) {
    state->global->score_system_val = SCORE_ACM;
  } else if (!strcasecmp(state->global->score_system, "kirov")) {
    state->global->score_system_val = SCORE_KIROV;
  } else if (!strcasecmp(state->global->score_system, "olympiad")) {
    state->global->score_system_val = SCORE_OLYMPIAD;
  } else if (!strcasecmp(state->global->score_system, "moscow")) {
    state->global->score_system_val = SCORE_MOSCOW;
  } else {
    err("Invalid scoring system: %s", state->global->score_system);
    return -1;
  }

  /*
   * Seconds rounding mode.
   */
  if (!state->global->rounding_mode[0]) {
    state->global->rounding_mode_val = SEC_CEIL;
  } else if (!strcmp(state->global->rounding_mode, "ceil")) {
    state->global->rounding_mode_val = SEC_CEIL;
  } else if (!strcmp(state->global->rounding_mode, "floor")) {
    state->global->rounding_mode_val = SEC_FLOOR;
  } else if (!strcmp(state->global->rounding_mode, "round")) {
    state->global->rounding_mode_val = SEC_ROUND;
  } else {
    err("Invalid rounding mode: %s", state->global->rounding_mode);
    return -1;
  }

  if (state->global->enable_continue == -1) state->global->enable_continue = DFLT_G_ENABLE_CONTINUE;
  if (state->global->html_report == -1) state->global->html_report = 1;
  if (state->global->xml_report == -1) state->global->xml_report = 0;
  if (state->global->xml_report) state->global->html_report = 0;

  if (state->global->tests_to_accept == -1) {
    state->global->tests_to_accept = DFLT_G_TESTS_TO_ACCEPT;
  }

  if (mode == PREPARE_COMPILE) {
    if (state->global->compile_real_time_limit == -1) {
      state->global->compile_real_time_limit = DFLT_G_COMPILE_REAL_TIME_LIMIT;
      info("global.compile_real_time_limit set to %d",
           state->global->compile_real_time_limit);
    }
  }

  if (mode == PREPARE_RUN) {
    if (state->global->checker_real_time_limit == -1) {
      state->global->checker_real_time_limit = DFLT_G_CHECKER_REAL_TIME_LIMIT;
      info("global.checker_real_time_limit set to %d",
           state->global->checker_real_time_limit);
    }
  }

  if (mode == PREPARE_SERVE) {
    if (!state->global->charset[0]) {
      snprintf(state->global->charset, sizeof(state->global->charset),
               "%s", DFLT_G_CHARSET);
      info("global.charset set to %s", state->global->charset);
    }
    /*
    if (!(state->global->charset_ptr = nls_lookup_table(state->global->charset))) {
      err("global.charset `%s' is invalid", state->global->charset);
      return -1;
    }
    */
    /*
    if (!state->global->standings_charset[0]) {
      snprintf(state->global->standings_charset, sizeof(state->global->standings_charset),
               "%s", state->global->charset);
      info("global.standings_charset set to %s", state->global->standings_charset);
    }
    if (!(state->global->standings_charset_ptr = nls_lookup_table(state->global->standings_charset))) {
      err("global.standings_charset `%s' is invalid", state->global->standings_charset);
      return -1;
    }
    */
    if (!state->global->standings_file_name[0]) {
      snprintf(state->global->standings_file_name,sizeof(state->global->standings_file_name),
               "%s", DFLT_G_STANDINGS_FILE_NAME);
    }
    make_stand_file_name_2(state);

    if (state->global->contest_start_cmd[0]) {
      pathmake2(state->global->contest_start_cmd, state->global->conf_dir, "/",
                state->global->contest_start_cmd, 0);
      if (check_executable(state->global->contest_start_cmd) < 0) {
        err("contest start command %s is not executable or does not exist",
            state->global->contest_start_cmd);
        return -1;
      }
    }

    if (state->global->stand_header_file[0]) {
      pathmake2(state->global->stand_header_file, state->global->conf_dir, "/",
                state->global->stand_header_file, 0);
      vptr = &state->global->stand_header_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0,
                            0, state->global->stand_header_file, "");
      if (r < 0) return -1;
    }

    if (state->global->stand_footer_file[0]) {
      pathmake2(state->global->stand_footer_file, state->global->conf_dir, "/",
                state->global->stand_footer_file, 0);
      vptr = &state->global->stand_footer_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0,
                            0, state->global->stand_footer_file, "");
      if (r < 0) return -1;
    }

    if (state->global->stand2_file_name[0]) {
      if (state->global->stand2_header_file[0]) {
        pathmake2(state->global->stand2_header_file, state->global->conf_dir, "/",
                  state->global->stand2_header_file, 0);
        vptr = &state->global->stand2_header_txt;
        r = generic_read_file(vptr, 0, &tmp_len,
                              0, 0, state->global->stand2_header_file, "");
        if (r < 0) return -1;
      }
      if (state->global->stand2_footer_file[0]) {
        pathmake2(state->global->stand2_footer_file, state->global->conf_dir, "/",
                  state->global->stand2_footer_file, 0);
        vptr = &state->global->stand2_footer_txt;
        r = generic_read_file(vptr, 0, &tmp_len,
                              0, 0, state->global->stand2_footer_file, "");
        if (r < 0) return -1;
      } 
    }

    if (state->global->plog_file_name[0]) {
      if (state->global->plog_header_file[0]) {
        pathmake2(state->global->plog_header_file, state->global->conf_dir, "/",
                  state->global->plog_header_file, 0);
        vptr = &state->global->plog_header_txt;
        r = generic_read_file(vptr, 0, &tmp_len,
                              0, 0, state->global->plog_header_file, "");
        if (r < 0) return -1;
      }
      if (state->global->plog_footer_file[0]) {
        pathmake2(state->global->plog_footer_file, state->global->conf_dir, "/",
                  state->global->plog_footer_file, 0);
        vptr = &state->global->plog_footer_txt;
        r = generic_read_file(vptr, 0, &tmp_len,
                              0, 0, state->global->plog_footer_file, "");
        if (r < 0) return -1;
      }
      if (!state->global->plog_update_time) {
        state->global->plog_update_time = DFLT_G_PLOG_UPDATE_TIME;
      }
    } else {
      state->global->plog_update_time = 0;
    }

    if (state->global->use_gzip < 0 || state->global->use_gzip > 1) {
      state->global->use_gzip = DFLT_G_USE_GZIP;
    }
    if (state->global->use_dir_hierarchy < 0 || state->global->use_dir_hierarchy > 1) {
      state->global->use_dir_hierarchy = DFLT_G_USE_DIR_HIERARCHY;
    }
    if (state->global->min_gzip_size < 0) {
      state->global->min_gzip_size = DFLT_G_MIN_GZIP_SIZE;
    }
  }

#if CONF_HAS_LIBINTL - 0 == 1
  if (state->global->enable_l10n < 0) state->global->enable_l10n = 1;
#if defined EJUDGE_LOCALE_DIR
  if (state->global->enable_l10n && !state->global->l10n_dir[0]) {
    strcpy(state->global->l10n_dir, EJUDGE_LOCALE_DIR);
  }
#endif /* EJUDGE_LOCALE_DIR */
  if (state->global->enable_l10n && !state->global->l10n_dir[0]) {
    state->global->enable_l10n = 0;
  }
#else
  state->global->enable_l10n = 0;
#endif /* CONF_HAS_LIBINTL */

#if CONF_HAS_LIBINTL - 0 == 1
  if (mode == PREPARE_SERVE && state->global->enable_l10n) {
    /* convert locale string into locale id */
    if (!strcmp(state->global->standings_locale, "ru_RU.KOI8-R")
        || !strcmp(state->global->standings_locale, "ru")) {
      state->global->standings_locale_id = 1;
    } else {
      state->global->standings_locale_id = 0;
    }
    info("standings_locale_id is %d", state->global->standings_locale_id);
  }
#endif /* CONF_HAS_LIBINTL */

  if (state->global->team_download_time == -1) {
    state->global->team_download_time = DFLT_G_TEAM_DOWNLOAD_TIME;
  }
  state->global->team_download_time *= 60;

  /* only run needs these parameters */
  if (mode == PREPARE_RUN) {
    if (!state->global->max_file_length) {
      state->global->max_file_length = DFLT_G_MAX_FILE_LENGTH;
      info("global.max_file_length set to %d", state->global->max_file_length);
    }
    if (!state->global->max_line_length) {
      state->global->max_line_length = DFLT_G_MAX_LINE_LENGTH;
      info("global.max_line_length set to %d", state->global->max_line_length);
    }
    if (!state->global->max_cmd_length) {
      state->global->max_cmd_length = DFLT_G_MAX_CMD_LENGTH;
      info("global.max_cmd_length set to %d", state->global->max_cmd_length);
    }

    if (state->global->sound_player[0]) {
      char *tmps;

      tmps = varsubst_heap(state, state->global->sound_player, 0,
                           section_global_params, section_problem_params,
                           section_language_params, section_tester_params);
      if (tmps != state->global->sound_player) {
        snprintf(state->global->sound_player, sizeof(state->global->sound_player),"%s",tmps);
        xfree(tmps);
      }
    }
  }

  if (mode == PREPARE_SERVE && state->global->user_priority_adjustments) {
    state->global->user_adjustment_info = parse_user_adjustment(state->global->user_priority_adjustments);
    if (!state->global->user_adjustment_info) return -1;
  }

  if (mode == PREPARE_SERVE) {
    if (state->global->contestant_status_num<0 || state->global->contestant_status_num>100) {
      err("global.contestant_status_num is invalid");
      return -1;
    }
  }
  if (mode == PREPARE_SERVE && state->global->contestant_status_num > 0) {
    // there must be exact number of legend entries
    if (!state->global->contestant_status_legend) {
      err("global.contestant_status_legend is not set");
      return -1;
    }
    for (i = 0; state->global->contestant_status_legend[i]; i++);
    if (i != state->global->contestant_status_num) {
      err("global.contestant_status_legend has different number of entries, than global.contestant_status_num");
      return -1;
    }
    if (state->global->contestant_status_row_attr) {
      for (i = 0; state->global->contestant_status_row_attr[i]; i++);
      if (i != state->global->contestant_status_num) {
        err("global.contestant_status_row_attr has different number of entries, than global.contestant_status_num");
        return -1;
      }
    }
  }

  for (i = 1; i <= state->max_lang && mode != PREPARE_RUN; i++) {
    if (!state->langs[i]) continue;
    if (!state->langs[i]->short_name[0]) {
      info("language.%d.short_name set to \"lang%d\"", i, i);
      sprintf(state->langs[i]->short_name, "lang%d", i);
    }
    if (!state->langs[i]->long_name[0]) {
      info("language.%d.long_name set to \"Language %d\"", i, i);
      sprintf(state->langs[i]->long_name, "Language %d", i);
    }
    
    if (mode == PREPARE_SERVE) {
      if (!state->langs[i]->compile_dir[0]) {
        // use the global compile queue settings
        pathcpy(state->langs[i]->compile_dir, state->global->compile_dir);
        pathcpy(state->langs[i]->compile_queue_dir, state->global->compile_queue_dir);
        pathcpy(state->langs[i]->compile_src_dir, state->global->compile_src_dir);
        pathcpy(state->langs[i]->compile_out_dir, state->global->compile_out_dir);
        pathcpy(state->langs[i]->compile_status_dir, state->global->compile_status_dir);
        pathcpy(state->langs[i]->compile_report_dir, state->global->compile_report_dir);
      } else {
        // prepare language-specific compile queue settings
        pathmake(state->langs[i]->compile_queue_dir, state->langs[i]->compile_dir, "/",
                 DFLT_G_COMPILE_QUEUE_DIR, 0);
        info("language.%d.compile_queue_dir is %s",
             i, state->langs[i]->compile_queue_dir);
        pathmake(state->langs[i]->compile_src_dir, state->langs[i]->compile_dir, "/",
                 DFLT_G_COMPILE_SRC_DIR, 0);
        info("language.%d.compile_src_dir is %s",
             i, state->langs[i]->compile_src_dir);
        snprintf(state->langs[i]->compile_out_dir, sizeof(state->langs[i]->compile_out_dir),
                 "%s/%06d", state->langs[i]->compile_dir, state->global->contest_id);
        info("language.%d.compile_out_dir is %s", i, state->langs[i]->compile_out_dir);
        pathmake(state->langs[i]->compile_status_dir, state->langs[i]->compile_out_dir, "/",
                 DFLT_G_COMPILE_STATUS_DIR, 0);
        info("language.%d.compile_status_dir is %s", i, state->langs[i]->compile_status_dir);
        pathmake(state->langs[i]->compile_report_dir, state->langs[i]->compile_out_dir, "/",
                 DFLT_G_COMPILE_REPORT_DIR, 0);
        info("language.%d.compile_report_dir is %s", i, state->langs[i]->compile_report_dir);
      }
    }

    if (!state->langs[i]->src_sfx[0]) {
      err("language.%d.src_sfx must be set", i);
      return -1;
    }

    if (mode == PREPARE_COMPILE) {
      if (!state->langs[i]->cmd[0]) {
        err("language.%d.cmd must be set", i);
        return -1;
      }
      pathmake4(state->langs[i]->cmd,state->global->script_dir, "/", state->langs[i]->cmd, NULL);
      info("language.%d.cmd is %s", i, state->langs[i]->cmd);
      if (state->langs[i]->compile_real_time_limit == -1) {
        state->langs[i]->compile_real_time_limit = state->global->compile_real_time_limit;
        info("language.%d.compile_real_time_limit is inherited from global (%d)", i, state->langs[i]->compile_real_time_limit);
      }
      ASSERT(state->langs[i]->compile_real_time_limit >= 0);
    }

    if (state->langs[i]->compiler_env) {
      for (j = 0; state->langs[i]->compiler_env[j]; j++) {
        state->langs[i]->compiler_env[j] = varsubst_heap(state, state->langs[i]->compiler_env[j], 1,
                                                  section_global_params,
                                                  section_problem_params,
                                                  section_language_params,
                                                  section_tester_params);
        if (!state->langs[i]->compiler_env[j]) return -1;
      }
    }
  }

  for (i = 0; i < state->max_abstr_prob && mode != PREPARE_COMPILE; i++) {
    aprob = state->abstr_probs[i];
    if (!aprob->short_name[0]) {
      err("abstract problem must define problem short name");
      return -1;
    }
    ish = aprob->short_name;
    if (aprob->id) {
      err("abstract problem %s must not define problem id", ish);
      return -1;
    }
    if (aprob->long_name[0]) {
      err("abstract problem %s must not define problem long name", ish);
      return -1;
    }
    if (aprob->super[0]) {
      err("abstract problem %s cannot have a superproblem", ish);
      return -1;
    }
    if (aprob->type[0]) {
      aprob->type_val = parse_problem_type(aprob->type);
      if (aprob->type_val < 0 || aprob->type_val >= PROB_TYPE_LAST) {
        err("abstract problem %s has invalid type %s", ish, aprob->type);
        return -1;
      }
    }
  }

  for (i = 1; i <= state->max_prob && mode != PREPARE_COMPILE; i++) {
    if (!state->probs[i]) continue;
    si = -1;
    sish = 0;
    aprob = 0;
    if (state->probs[i]->super[0]) {
      for (si = 0; si < state->max_abstr_prob; si++)
        if (!strcmp(state->abstr_probs[si]->short_name, state->probs[i]->super))
          break;
      if (si >= state->max_abstr_prob) {
        err("abstract problem `%s' is not defined", state->probs[i]->super);
        return -1;
      }
      aprob = state->abstr_probs[si];
      sish = aprob->short_name;
    }
    if (!state->probs[i]->short_name[0] && state->global->auto_short_problem_name) {
      snprintf(state->probs[i]->short_name, sizeof(state->probs[i]->short_name),
               "%06d", state->probs[i]->id);
      info("problem %d short name is set to %s", i, state->probs[i]->short_name);
    }
    if (!state->probs[i]->short_name[0]) {
      err("problem %d short name must be set", i);
      return -1;
    }
    ish = state->probs[i]->short_name;
    if (!state->probs[i]->long_name[0]) {
      info("problem.%s.long_name set to \"Problem %s\"", ish, ish);
      sprintf(state->probs[i]->long_name, "Problem %s", ish);
    }

    if (state->probs[i]->type[0]) {
      state->probs[i]->type_val = parse_problem_type(state->probs[i]->type);
      if (state->probs[i]->type_val < 0 || state->probs[i]->type_val > PROB_TYPE_LAST) {
        err("problem %s type %s is invalid", state->probs[i]->short_name, state->probs[i]->type);
        return -1;
      }
    }

    prepare_set_prob_value(PREPARE_FIELD_PROB_TYPE,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEAM_ENABLE_REP_VIEW,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEAM_ENABLE_CE_VIEW,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEAM_SHOW_JUDGE_REPORT,
                           state->probs[i], aprob, state->global);

    prepare_set_prob_value(PREPARE_FIELD_PROB_TESTS_TO_ACCEPT,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_ACCEPT_PARTIAL,
                           state->probs[i], aprob, state->global);

    prepare_set_prob_value(PREPARE_FIELD_PROB_DISABLE_USER_SUBMIT,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_DISABLE_SUBMIT_AFTER_OK,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_DISABLE_AUTO_TESTING,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_DISABLE_TESTING,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_ENABLE_COMPILATION,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_SKIP_TESTING,
                           state->probs[i], aprob, state->global);

    prepare_set_prob_value(PREPARE_FIELD_PROB_FULL_SCORE,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_VARIABLE_FULL_SCORE,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_SCORE,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_RUN_PENALTY,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_ACM_RUN_PENALTY,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_DISQUALIFIED_PENALTY,
                           state->probs[i], aprob, state->global);

    prepare_set_prob_value(PREPARE_FIELD_PROB_HIDDEN,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_SCORING_CHECKER,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_MANUAL_CHECKING,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_EXAMINATOR_NUM,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_CHECK_PRESENTATION,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_STDIN,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_USE_STDOUT,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_BINARY_INPUT,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_IGNORE_EXIT_CODE,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TIME_LIMIT,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TIME_LIMIT_MILLIS,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_REAL_TIME_LIMIT,
                           state->probs[i], aprob, state->global);

    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_SFX,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_SFX,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_SFX,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TGZ_SFX,
                           state->probs[i], aprob, state->global);

    prepare_set_prob_value(PREPARE_FIELD_PROB_TEST_PAT,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_CORR_PAT,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_INFO_PAT,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_TGZ_PAT,
                           state->probs[i], aprob, state->global);

    prepare_set_prob_value(PREPARE_FIELD_PROB_CHECK_CMD,
                           state->probs[i], aprob, state->global);

    prepare_set_prob_value(PREPARE_FIELD_PROB_MAX_VM_SIZE,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_MAX_STACK_SIZE,
                           state->probs[i], aprob, state->global);
    prepare_set_prob_value(PREPARE_FIELD_PROB_MAX_DATA_SIZE,
                           state->probs[i], aprob, state->global);

    prepare_set_prob_value(PREPARE_FIELD_PROB_CHECK_CMD,
                           state->probs[i], aprob, state->global);

    if (state->probs[i]->priority_adjustment == -1000 && si != -1 &&
        state->abstr_probs[si]->priority_adjustment != -1000) {
      state->probs[i]->priority_adjustment = state->abstr_probs[si]->priority_adjustment;
    }
    if (state->probs[i]->priority_adjustment == -1000) {
      state->probs[i]->priority_adjustment = 0;
    }

    if (!state->probs[i]->score_multiplier && si != -1 &&
        state->abstr_probs[si]->score_multiplier >= 1) {
      state->probs[i]->score_multiplier = state->abstr_probs[si]->score_multiplier;
    }

    if (mode == PREPARE_SERVE) {
      if (state->probs[i]->deadline[0]) {
        if (parse_date(state->probs[i]->deadline, &state->probs[i]->t_deadline) < 0) {
          err("invalid deadline specified for problem `%s'",
              state->probs[i]->short_name);
          return -1;
        }
        info("problem.%s.deadline is %ld", ish, state->probs[i]->t_deadline);
      }
      if (state->probs[i]->personal_deadline) {
        if (parse_personal_deadlines(state->probs[i]->personal_deadline,
                                     &state->probs[i]->pd_total,
                                     &state->probs[i]->pd_infos) < 0) {
          return -1;
        }
      }
      if (state->probs[i]->start_date[0]) {
        if (parse_date(state->probs[i]->start_date, &state->probs[i]->t_start_date) < 0) {
          err("invalid start_date specified for problem `%s'",
              state->probs[i]->short_name);
          return -1;
        }
        info("problem.%s.start_date is %ld", ish, state->probs[i]->t_start_date);
      }

      if (parse_deadline_penalties(state->probs[i]->date_penalty,
                                   &state->probs[i]->dp_total,
                                   &state->probs[i]->dp_infos) < 0) return -1;

      if (si != -1 && state->abstr_probs[si]->disable_language) {
        state->probs[i]->disable_language = sarray_merge_pf(state->abstr_probs[si]->disable_language, state->probs[i]->disable_language);
      }
      if (si != -1 && state->abstr_probs[si]->enable_language) {
        state->probs[i]->enable_language = sarray_merge_pf(state->abstr_probs[si]->enable_language, state->probs[i]->enable_language);
      }
      if (si != -1 && state->abstr_probs[si]->require) {
        state->probs[i]->require = sarray_merge_pf(state->abstr_probs[si]->require, state->probs[i]->require);
      }
      if (si != -1 && state->abstr_probs[si]->checker_env) {
        state->probs[i]->checker_env = sarray_merge_pf(state->abstr_probs[si]->checker_env,
                                                state->probs[i]->checker_env);
      }
      if (state->probs[i]->checker_env) {
        for (j = 0; state->probs[i]->checker_env[j]; j++) {
          state->probs[i]->checker_env[j] = varsubst_heap(state, state->probs[i]->checker_env[j], 1,
                                                   section_global_params,
                                                   section_problem_params,
                                                   section_language_params,
                                                   section_tester_params);
          if (!state->probs[i]->checker_env[j]) return -1;
        }
      }

      /* score bonus */
      prepare_set_prob_value(PREPARE_FIELD_PROB_SCORE_BONUS,
                             state->probs[i], aprob, state->global);
      if (state->probs[i]->score_bonus[0]) {
        if (parse_score_bonus(state->probs[i]->score_bonus, &state->probs[i]->score_bonus_total,
                              &state->probs[i]->score_bonus_val) < 0) return -1;
      }
    }

    if (mode == PREPARE_SERVE) {
      if (!state->probs[i]->statement_file[0] && si != -1
          && state->abstr_probs[si]->statement_file[0]) {
        sformat_message(state->probs[i]->statement_file, PATH_MAX,
                        state->abstr_probs[si]->statement_file,
                        NULL, state->probs[i], NULL, NULL, NULL, 0, 0, 0);
      }
      if (state->probs[i]->statement_file[0]) {
        path_add_dir(state->probs[i]->statement_file,
                     state->global->statement_dir);
      }

      if (!state->probs[i]->alternatives_file[0] && si != -1
          && state->abstr_probs[si]->alternatives_file[0]) {
        sformat_message(state->probs[i]->alternatives_file, PATH_MAX,
                        state->abstr_probs[si]->alternatives_file,
                        NULL, state->probs[i], NULL, NULL, NULL, 0, 0, 0);
      }
      if (state->probs[i]->alternatives_file[0]) {
        path_add_dir(state->probs[i]->alternatives_file,
                     state->global->statement_dir);
      }
      prepare_set_prob_value(PREPARE_FIELD_PROB_STAND_ATTR,
                             state->probs[i], state->abstr_probs[si],
                             state->global);
    }

    if (mode == PREPARE_RUN || mode == PREPARE_SERVE) {
      if (!state->probs[i]->test_dir[0] && si != -1
          && state->abstr_probs[si]->test_dir[0]) {
        sformat_message(state->probs[i]->test_dir, PATH_MAX,
                        state->abstr_probs[si]->test_dir,
                        NULL, state->probs[i], NULL, NULL, NULL, 0, 0, 0);
        info("problem.%s.test_dir taken from problem.%s ('%s')",
             ish, sish, state->probs[i]->test_dir);
      }
      if (!state->probs[i]->test_dir[0]) {
        info("problem.%s.test_dir set to %s", ish, state->probs[i]->short_name);
        pathcpy(state->probs[i]->test_dir, state->probs[i]->short_name);
      }
      path_add_dir(state->probs[i]->test_dir, state->global->test_dir);
      info("problem.%s.test_dir is '%s'", 
           ish, state->probs[i]->test_dir);

      if (!state->probs[i]->corr_dir[0] && si != -1
          && state->abstr_probs[si]->corr_dir[0]) {
        sformat_message(state->probs[i]->corr_dir, PATH_MAX,
                        state->abstr_probs[si]->corr_dir,
                        NULL, state->probs[i], NULL, NULL, NULL, 0, 0, 0);
        info("problem.%s.corr_dir taken from problem.%s ('%s')",
             ish, sish, state->probs[i]->corr_dir);
      }
      if (state->probs[i]->corr_dir[0]) {
        path_add_dir(state->probs[i]->corr_dir, state->global->corr_dir);
        info("problem.%s.corr_dir is '%s'", ish, state->probs[i]->corr_dir);
      }

      prepare_set_prob_value(PREPARE_FIELD_PROB_USE_INFO,
                             state->probs[i], aprob, state->global);

      if (!state->probs[i]->info_dir[0] && si != -1 && state->probs[i]->use_info
          && state->abstr_probs[si]->info_dir[0]) {
        sformat_message(state->probs[i]->info_dir, PATH_MAX,
                        state->abstr_probs[si]->info_dir,
                        NULL, state->probs[i], NULL, NULL, NULL, 0, 0, 0);
        info("problem.%s.info_dir taken from problem.%s ('%s')",
             ish, sish, state->probs[i]->info_dir);
      }
      if (!state->probs[i]->info_dir[0] && state->probs[i]->use_info) {
        pathcpy(state->probs[i]->info_dir, state->probs[i]->short_name);
        info("problem.%s.info_dir is set to '%s'", ish, state->probs[i]->info_dir);
      }
      if (state->probs[i]->use_info) {
        path_add_dir(state->probs[i]->info_dir, state->global->info_dir);
        info("problem.%s.info_dir is '%s'", ish, state->probs[i]->info_dir);
      }

      if (state->probs[i]->use_tgz == -1 && si != -1
          && state->abstr_probs[si]->use_tgz != -1) {
        state->probs[i]->use_tgz = state->abstr_probs[si]->use_tgz;
        info("problem.%s.use_tgz taken from problem.%s (%d)",
             ish, sish, state->probs[i]->use_tgz);
      }
      if (state->probs[i]->use_tgz == -1) {
        state->probs[i]->use_tgz = 0;
      }

      if (!state->probs[i]->tgz_dir[0] && si != -1 && state->probs[i]->use_tgz
          && state->abstr_probs[si]->tgz_dir[0]) {
        sformat_message(state->probs[i]->tgz_dir, PATH_MAX,
                        state->abstr_probs[si]->tgz_dir,
                        NULL, state->probs[i], NULL, NULL, NULL, 0, 0, 0);
        info("problem.%s.tgz_dir taken from problem.%s ('%s')",
             ish, sish, state->probs[i]->tgz_dir);
      }
      if (!state->probs[i]->tgz_dir[0] && state->probs[i]->use_tgz) {
        pathcpy(state->probs[i]->tgz_dir, state->probs[i]->short_name);
        info("problem.%s.tgz_dir is set to '%s'", ish, state->probs[i]->tgz_dir);
      }
      if (state->probs[i]->use_tgz) {
        path_add_dir(state->probs[i]->tgz_dir, state->global->tgz_dir);
        info("problem.%s.tgz_dir is '%s'", ish, state->probs[i]->tgz_dir);
      }
    }

    if (mode == PREPARE_RUN) {
      if (!state->probs[i]->input_file[0] && si != -1
          && state->abstr_probs[si]->input_file[0]) {
        sformat_message(state->probs[i]->input_file, PATH_MAX,
                        state->abstr_probs[si]->input_file,
                        NULL, state->probs[i], NULL, NULL, NULL, 0, 0, 0);
        info("problem.%s.input_file inherited from problem.%s ('%s')",
             ish, sish, state->probs[i]->input_file);
      }
      if (!state->probs[i]->input_file[0]) {
        info("problem.%s.input_file set to %s", ish, DFLT_P_INPUT_FILE);
        snprintf(state->probs[i]->input_file, sizeof(state->probs[i]->input_file),
                 "%s", DFLT_P_INPUT_FILE);
      }
      if (!state->probs[i]->output_file[0] && si != -1
          && state->abstr_probs[si]->output_file[0]) {
        sformat_message(state->probs[i]->output_file, PATH_MAX,
                        state->abstr_probs[si]->output_file,
                        NULL, state->probs[i], NULL, NULL, NULL, 0, 0, 0);
        info("problem.%s.output_file inherited from problem.%s ('%s')",
             ish, sish, state->probs[i]->output_file);
      }
      if (!state->probs[i]->output_file[0]) {
        info("problem.%s.output_file set to %s", ish, DFLT_P_OUTPUT_FILE);
        snprintf(state->probs[i]->output_file, sizeof(state->probs[i]->output_file),
                 "%s", DFLT_P_OUTPUT_FILE);
      }

      if (state->probs[i]->variant_num == -1 && si != -1
          && state->abstr_probs[si]->variant_num != -1) {
        state->probs[i]->variant_num = state->abstr_probs[si]->variant_num;
        info("problem.%s.variant_num inherited from problem.%s (%d)",
             ish, sish, state->probs[i]->variant_num);
      }
      if (state->probs[i]->variant_num == -1) {
        state->probs[i]->variant_num = 0;
      }

      prepare_set_prob_value(PREPARE_FIELD_PROB_USE_CORR,
                             state->probs[i], aprob, state->global);

      prepare_set_prob_value(PREPARE_FIELD_PROB_CHECKER_REAL_TIME_LIMIT,
                             state->probs[i], aprob, state->global);
    }

    if (state->probs[i]->test_sets) {
      if (parse_testsets(state->probs[i]->test_sets,
                         &state->probs[i]->ts_total,
                         &state->probs[i]->ts_infos) < 0)
        return -1;
    }
  }

  if (mode == PREPARE_SERVE || mode == PREPARE_RUN) {
    for (i = 0; i < state->max_abstr_tester; i++) {
      if (process_abstract_tester(state, i) < 0) return -1;
    }
  }

  if (mode == PREPARE_SERVE) {
    int var_prob_num = 0;

    for (i = 0; i <= state->max_prob; i++)
      if (state->probs[i] && state->probs[i]->variant_num > 0) var_prob_num++;
    if (var_prob_num > 0) {
      if (!state->global->variant_map_file[0]) {
        err("There are variant problems, but no variant file name");
        return -1;
      }
      state->global->variant_map = parse_variant_map(state, state->global->variant_map_file);
      if (!state->global->variant_map) return -1;
    }
  }

#define TESTER_INIT_FIELD(f,d,c) do { if (!state->testers[i]->f[0]) { info("tester.%d.%s set to %s", i, #f, d); pathcat(state->testers[i]->f, d); } path_add_dir(state->testers[i]->f, state->testers[i]->c); } while(0)
  if (mode == PREPARE_SERVE || mode == PREPARE_RUN) {
    for (i = 1; i <= state->max_tester; i++) {
      struct section_tester_data *tp = 0;
      struct section_tester_data *atp = 0;

      if (!state->testers[i]) continue;
      tp = state->testers[i];

      /* we hardly can do any reasonable in this case */
      if (tp->any && mode == PREPARE_RUN) {
        continue;
      }

      si = -1;
      sish = 0;
      if (tp->super && tp->super[0]) {
        if (tp->super[1]) {
          err("concrete tester may inherit only one abstract tester");
          return -1;
        }
        for (si = 0; si < state->max_abstr_tester; si++) {
          atp = state->abstr_testers[si];
          if (!strcmp(atp->name, tp->super[0]))
            break;
        }
        if (si >= state->max_abstr_tester) {
          err("abstract tester %s not found", tp->super[0]);
          return -1;
        }
        sish = atp->name;
      }

      /* copy arch and key */
      if (!tp->arch[0] && atp && atp->arch[0]) {
        strcpy(tp->arch, atp->arch);
        info("tester.%d.arch inherited from tester.%s ('%s')",
             i, sish, tp->arch);
      }
      if (!tp->key[0] && atp && atp->key[0]) {
        strcpy(tp->key, atp->key);
        info("tester.%d.key inherited from tester.%s ('%s')",
             i, sish, tp->key);
      }

      if (!state->testers[i]->name[0]) {
        sprintf(state->testers[i]->name, "tst_%d", state->testers[i]->id);
        if (state->testers[i]->arch[0]) {
          sprintf(state->testers[i]->name + strlen(state->testers[i]->name),
                  "_%s", state->testers[i]->arch);
        }
        info("tester.%d.name set to \"%s\"", i, state->testers[i]->name);
      }

      if (mode == PREPARE_RUN) {
        if (!tp->check_dir[0] && atp && atp->check_dir[0]) {
          sformat_message(tp->check_dir, PATH_MAX, atp->check_dir,
                          state->global, state->probs[tp->problem], NULL,
                          tp, NULL, 0, 0, 0);
          info("tester.%d.check_dir inherited from tester.%s ('%s')",
               i, sish, tp->check_dir);
        }
        if (!tp->check_dir[0]) {
          info("tester.%d.check_dir inherited from global ('%s')",
               i, state->global->run_check_dir);
          pathcpy(tp->check_dir, state->global->run_check_dir);
        }
      }

      if (mode == PREPARE_SERVE) {
        if (!tp->run_dir[0] && atp && atp->run_dir[0]) {
          sformat_message(tp->run_dir, PATH_MAX, atp->run_dir,
                          state->global, state->probs[tp->problem], NULL,
                          tp, NULL, 0, 0, 0);
          info("tester.%d.run_dir inherited from tester.%s ('%s')",
               i, sish, tp->run_dir);
        }
        if (!tp->run_dir[0]) {
          info("tester.%d.run_dir inherited from global ('%s')",
               i, state->global->run_dir);
          pathcpy(tp->run_dir, state->global->run_dir);
          pathcpy(tp->run_queue_dir, state->global->run_queue_dir);
          pathcpy(tp->run_exe_dir, state->global->run_exe_dir);
          pathcpy(tp->run_out_dir, state->global->run_out_dir);
          pathcpy(tp->run_status_dir, state->global->run_status_dir);
          pathcpy(tp->run_report_dir, state->global->run_report_dir);
          if (state->global->team_enable_rep_view) {
            pathcpy(tp->run_team_report_dir, state->global->run_team_report_dir);
          }
          if (state->global->enable_full_archive) {
            pathcpy(tp->run_full_archive_dir, state->global->run_full_archive_dir);
          }
        } else {
          pathmake(tp->run_queue_dir, tp->run_dir, "/",
                   DFLT_G_RUN_QUEUE_DIR, 0);
          info("tester.%d.run_queue_dir is %s", i, tp->run_queue_dir);
          pathmake(tp->run_exe_dir, tp->run_dir, "/",
                   DFLT_G_RUN_EXE_DIR, 0);
          info("tester.%d.run_exe_dir is %s", i, tp->run_exe_dir);
          snprintf(tp->run_out_dir, sizeof(tp->run_out_dir), "%s/%06d",
                   tp->run_dir, state->global->contest_id);
          info("tester.%d.run_out_dir is %s", i, tp->run_out_dir);
          pathmake(tp->run_status_dir, tp->run_out_dir, "/",
                   DFLT_G_RUN_STATUS_DIR, 0);
          info("tester.%d.run_status_dir is %s", i, tp->run_status_dir);
          pathmake(tp->run_report_dir, tp->run_out_dir, "/",
                   DFLT_G_RUN_REPORT_DIR, 0);
          info("tester.%d.run_report_dir is %s", i, tp->run_report_dir);
          if (state->global->team_enable_rep_view) {
            pathmake(tp->run_team_report_dir, tp->run_out_dir, "/",
                     DFLT_G_RUN_TEAM_REPORT_DIR, 0);
            info("tester.%d.run_team_report_dir is %s", i, tp->run_team_report_dir);
          }
          if (state->global->enable_full_archive) {
            pathmake(tp->run_full_archive_dir, tp->run_out_dir, "/",
                     DFLT_G_RUN_FULL_ARCHIVE_DIR, 0);
            info("tester.%d.run_full_archive_dir is %s", i, tp->run_full_archive_dir);
          }
        }

        if (tp->priority_adjustment == -1000 && atp
            && atp->priority_adjustment != -1000) {
          tp->priority_adjustment = atp->priority_adjustment;
        }
        if (tp->priority_adjustment == -1000) {
          tp->priority_adjustment = 0;
        }
      }

      if (tp->no_core_dump == -1 && atp && atp->no_core_dump != -1) {
        tp->no_core_dump = atp->no_core_dump;
        info("tester.%d.no_core_dump inherited from tester.%s (%d)",
             i, sish, tp->no_core_dump);        
      }
      if (tp->no_core_dump == -1) {
        tp->no_core_dump = 0;
      }
      if (tp->enable_memory_limit_error == -1 && atp && atp->enable_memory_limit_error != -1) {
        tp->enable_memory_limit_error = atp->enable_memory_limit_error;
      }
      if (tp->enable_memory_limit_error == -1) {
        tp->enable_memory_limit_error = 0;
      }
      if (tp->clear_env == -1 && atp && atp->clear_env != -1) {
        tp->clear_env = atp->clear_env;
        info("tester.%d.clear_env inherited from tester.%s (%d)",
             i, sish, tp->clear_env);
      }
      if (tp->clear_env == -1) {
        tp->clear_env = 0;
      }
      if (tp->time_limit_adjustment == -1
          && atp && atp->time_limit_adjustment != -1) {
        tp->time_limit_adjustment = atp->time_limit_adjustment;
        info("tester.%d.time_limit_adjustment inherited from tester.%s (%d)",
             i, sish, tp->time_limit_adjustment);
      }
      if (tp->time_limit_adjustment == -1) {
        tp->time_limit_adjustment = 0;
      }
      if (!tp->kill_signal[0] && atp && atp->kill_signal[0]) {
        strcpy(tp->kill_signal, atp->kill_signal);
        info("tester.%d.kill_signal inherited from tester.%s ('%s')",
             i, sish, tp->kill_signal);
      }
      if (tp->max_stack_size == -1L && atp && atp->max_stack_size != -1L) {
        tp->max_stack_size = atp->max_stack_size;
        info("tester.%d.max_stack_size inherited from tester.%s (%zu)",
             i, sish, tp->max_stack_size);        
      }
      if (tp->max_data_size == -1L && atp && atp->max_data_size != -1L) {
        tp->max_data_size = atp->max_data_size;
        info("tester.%d.max_data_size inherited from tester.%s (%zu)",
             i, sish, tp->max_data_size);        
      }
      if (tp->max_vm_size == -1L && atp && atp->max_vm_size != -1L) {
        tp->max_vm_size = atp->max_vm_size;
        info("tester.%d.max_vm_size inherited from tester.%s (%zu)",
             i, sish, tp->max_vm_size);        
      }
      if (tp->memory_limit_type[0] != 1) {
        tp->memory_limit_type_val = prepare_parse_memory_limit_type(tp->memory_limit_type);
        if (tp->memory_limit_type_val < 0) {
          err("invalid memory limit type `%s'", tp->memory_limit_type);
          return -1;
        }
      }
      if (tp->memory_limit_type_val<0 && atp && atp->memory_limit_type_val>=0) {
        tp->memory_limit_type_val = atp->memory_limit_type_val;
      }

      if (tp->skip_testing == -1 && atp && atp->skip_testing != -1)
        tp->skip_testing = atp->skip_testing;
      if (tp->skip_testing == -1) tp->skip_testing = 0;

      if (tp->is_dos == -1 && atp && atp->is_dos != -1) {
        tp->is_dos = atp->is_dos;
        info("tester.%d.is_dos inherited from tester.%s (%d)",
             i, sish, tp->is_dos);        
      }
      if (tp->is_dos == -1) {
        tp->is_dos = 0;
      }
      if (tp->no_redirect == -1 && atp && atp->no_redirect != -1) {
        tp->no_redirect = atp->no_redirect;
        info("tester.%d.no_redirect inherited from tester.%s (%d)",
             i, sish, tp->no_redirect);        
      }
      if (tp->no_redirect == -1) {
        tp->no_redirect = 0;
      }
      if (!tp->errorcode_file[0] && atp && atp->errorcode_file) {
        sformat_message(tp->errorcode_file, PATH_MAX, atp->errorcode_file,
                        state->global, state->probs[tp->problem], NULL,
                        tp, NULL, 0, 0, 0);
        info("tester.%d.errorcode_file inherited from tester.%s ('%s')",
             i, sish, tp->errorcode_file);        
      }

      if (atp && atp->start_env) {
        tp->start_env = sarray_merge_pf(atp->start_env, tp->start_env);
      }
      if (tp->start_env) {
        for (j = 0; tp->start_env[j]; j++) {
          tp->start_env[j] = varsubst_heap(state, tp->start_env[j], 1,
                                           section_global_params,
                                           section_problem_params,
                                           section_language_params,
                                           section_tester_params);
          if (!tp->start_env[j]) return -1;
        }
      }
      if (atp && atp->checker_env) {
        tp->checker_env = sarray_merge_pf(atp->checker_env, tp->checker_env);
      }
      if (tp->checker_env) {
        for (j = 0; tp->checker_env[j]; j++) {
          tp->checker_env[j] = varsubst_heap(state, tp->checker_env[j], 1,
                                             section_global_params,
                                             section_problem_params,
                                             section_language_params,
                                             section_tester_params);
          if (!tp->checker_env[j]) return -1;
        }
      }

      if (mode == PREPARE_RUN) {
        if (!tp->error_file[0] && atp && atp->error_file[0]) {
          sformat_message(tp->error_file, PATH_MAX, atp->error_file,
                          state->global, state->probs[tp->problem], NULL,
                          tp, NULL, 0, 0, 0);
          info("tester.%d.error_file inherited from tester.%s ('%s')",
               i, sish, tp->error_file);        
        }
        if (!state->testers[i]->error_file[0]) {
          info("tester.%d.error_file set to %s", i, DFLT_T_ERROR_FILE);
          snprintf(state->testers[i]->error_file, sizeof(state->testers[i]->error_file),
                   "%s", DFLT_T_ERROR_FILE);
        }
        if (!tp->check_cmd[0] && state->probs[tp->problem]->standard_checker[0]) {
          strcpy(tp->check_cmd, state->probs[tp->problem]->standard_checker);
          pathmake4(tp->check_cmd, state->global->ejudge_checkers_dir,
                    "/", tp->check_cmd, 0);
          tp->standard_checker_used = 1;
        }
        if (!tp->check_cmd[0] && atp && atp->check_cmd[0]) {
          sformat_message(tp->check_cmd, PATH_MAX, atp->check_cmd,
                          state->global, state->probs[tp->problem], NULL,
                          tp, NULL, 0, 0, 0);
          info("tester.%d.check_cmd inherited from tester.%s ('%s')",
               i, sish, tp->check_cmd);        
        }
        if (!tp->check_cmd[0] && state->probs[tp->problem]->check_cmd[0]) {
          strcpy(tp->check_cmd, state->probs[tp->problem]->check_cmd);
        }
        if (!state->testers[i]->check_cmd[0]) {
          err("tester.%d.check_cmd must be set", i);
          return -1;
        }
        pathmake4(state->testers[i]->check_cmd, state->global->checker_dir, "/",
                  state->testers[i]->check_cmd, 0);
        if (!tp->start_cmd[0] && atp && atp->start_cmd[0]) {
          sformat_message(tp->start_cmd, PATH_MAX, atp->start_cmd,
                          state->global, state->probs[tp->problem], NULL,
                          tp, NULL, 0, 0, 0);
          info("tester.%d.start_cmd inherited from tester.%s ('%s')",
               i, sish, tp->start_cmd);        
        }
        if (state->testers[i]->start_cmd[0]) {
          pathmake4(state->testers[i]->start_cmd, state->global->script_dir, "/",
                    state->testers[i]->start_cmd, 0);
        }
        if (!tp->prepare_cmd[0] && atp && atp->prepare_cmd[0]) {
          sformat_message(tp->prepare_cmd, PATH_MAX, atp->prepare_cmd,
                          state->global, state->probs[tp->problem], NULL,
                          tp, NULL, 0, 0, 0);
          info("tester.%d.prepare_cmd inherited from tester.%s ('%s')",
               i, sish, tp->prepare_cmd);        
        }
        if (tp->prepare_cmd[0]) {
          pathmake4(tp->prepare_cmd, state->global->script_dir, "/",
                    tp->prepare_cmd, 0);
        }
      }
    }
  }

  if (mode == PREPARE_SERVE) {
    /* check language/checker pairs */
    for (i = 1; i <= state->max_lang; i++) {
      if (!state->langs[i]) continue;
      for (j = 1; j <= state->max_prob; j++) {
        if (!state->probs[j]) continue;
        if (!find_tester(state, j, state->langs[i]->arch)) {
          err("no tester for pair: %d, %s", j, state->langs[i]->arch);
          return -1;
        }
      }
    }
  }

  return 0;
}

static int
collect_sections(serve_state_t state, int mode)
{
  struct generic_section_config *p;
  struct section_language_data  *l;
  struct section_problem_data   *q;
  struct section_tester_data    *t;
  int last_lang = 0, last_prob = 0, last_tester = 0;

  state->max_lang = state->max_prob = state->max_tester = 0;

  for (p = state->config; p; p = p->next) {
    if (!strcmp(p->name, "language") && mode != PREPARE_RUN) {
      l = (struct section_language_data*) p;
      if (!l->id) info("assigned language id = %d", (l->id = last_lang + 1));
      if (l->id <= 0 || l->id > MAX_LANGUAGE) {
        err("language id %d is out of range", l->id);
        return -1;
      }
      if (state->langs[l->id]) {
        err("duplicated language id %d", l->id);
        return -1;
      }
      state->langs[l->id] = l;
      if (l->id > state->max_lang) state->max_lang = l->id;
      last_lang = l->id;
      if (!l->compile_id) l->compile_id = l->id;
    } else if (!strcmp(p->name, "problem") && mode != PREPARE_COMPILE) {
      q = (struct section_problem_data*) p;
      if (q->abstract) {
        if (state->max_abstr_prob > MAX_PROBLEM) {
          err("too many abstract problems");
          return -1;
        }
        state->abstr_probs[state->max_abstr_prob++] = q;
      } else {
        if (!q->id) info("assigned problem id = %d", (q->id=last_prob + 1));
        if (q->id <= 0 || q->id > MAX_PROBLEM) {
          err("problem id %d is out of range", q->id);
          return -1;
        }
        if (state->probs[q->id]) {
          err("duplicated problem id %d", q->id);
          return -1;
        }
        state->probs[q->id] = q;
        if (q->id > state->max_prob) state->max_prob = q->id;
        last_prob = q->id;
        if (!q->tester_id) q->tester_id = q->id;
      }
    } else if (!strcmp(p->name, "tester") && mode != PREPARE_COMPILE) {
      t = (struct section_tester_data *) p;
      if (t->abstract) {
        if (state->max_abstr_tester > MAX_TESTER) {
          err("too many abstract tester");
          return -1;
        }
        state->abstr_testers[state->max_abstr_tester++] = t;
      } else {
        if (!t->id)
          info("assigned tester id = %d",(t->id = last_tester + 1));
        if (t->id <= 0 || t->id > MAX_TESTER) {
          err("tester id %d is out of range", t->id);
          return -1;
        }
        if (state->testers[t->id]) {
          err("duplicated tester id %d", t->id);
          return -1;
        }
        if (t->any) {
          int j;
          // default tester
          // its allowed to have only one for a given architecture
          for (j = 1; j <= state->max_tester; j++) {
            if (!state->testers[j] || j == t->id) continue;
            if (state->testers[j]->any == 1 && !strcmp(state->testers[j]->arch, t->arch))
              break;
          }
          if (j <= state->max_tester) {
            err("duplicated default tester for architecture '%s'", t->arch);
            return -1;
          }
        } else {
          if (!t->problem && !t->problem_name[0]) {
            err("no problem specified for tester %d", t->id);
            return -1;
          }
          if (t->problem && t->problem_name[0]) {
            err("only one of problem id and problem name must be specified");
            return -1;
          }
          if (t->problem && !state->probs[t->problem]) {
            err("no problem %d for tester %d", t->problem, t->id);
            return -1;
          }
          if (t->problem_name[0]) {
            int j;
            
            for (j = 1; j <= state->max_prob; j++) {
              if (state->probs[j] && !strcmp(state->probs[j]->short_name, t->problem_name))
                break;
            }
            if (j > state->max_prob) {
              err("no problem %s for tester %d", t->problem_name, t->id);
              return -1;
            }
            info("tester %d: problem '%s' has id %d",
                 t->id, t->problem_name, j);
            t->problem = j;
          }
        }
        state->testers[t->id] = t;
        if (t->id > state->max_tester) state->max_tester = t->id;
        last_tester = t->id;
      }
    }
  }
  return 0;
}

int
create_dirs(serve_state_t state, int mode)
{
  int i;

  if (mode == PREPARE_SERVE) {
    if (state->global->root_dir[0] && make_dir(state->global->root_dir, 0) < 0) return -1;
    if (make_dir(state->global->var_dir, 0) < 0) return -1;

    /* COMPILE writes its response here */
    if (make_dir(state->global->compile_dir, 0) < 0) return -1;
    if (make_all_dir(state->global->compile_queue_dir, 0777) < 0) return -1;
    if (make_dir(state->global->compile_src_dir, 0) < 0) return -1;
    // remove possible symlink from previous versions
    // the return code is intentionally ignored
    remove(state->global->compile_out_dir);
    if (make_dir(state->global->compile_out_dir, 0) < 0) return -1;
    if (make_all_dir(state->global->compile_status_dir, 0) < 0) return -1;
    if (make_dir(state->global->compile_report_dir, 0) < 0) return -1;

    /* RUN writes its response here */
    if (make_dir(state->global->run_dir, 0) < 0) return -1;
    if (make_all_dir(state->global->run_queue_dir, 0) < 0) return -1;
    if (make_dir(state->global->run_exe_dir, 0) < 0) return -1;
    remove(state->global->run_out_dir);
    if (make_dir(state->global->run_out_dir, 0) < 0) return -1;
    if (make_all_dir(state->global->run_status_dir, 0777) < 0) return -1;
    if (make_dir(state->global->run_report_dir, 0777) < 0) return -1;
    if (state->global->team_enable_rep_view) {
      if (make_dir(state->global->run_team_report_dir, 0777) < 0) return -1;
    }
    if (state->global->enable_full_archive) {
      if (make_dir(state->global->run_full_archive_dir, 0777) < 0) return -1;
    }

    /* SERVE's status directory */
    if (make_all_dir(state->global->status_dir, 0) < 0) return -1;

    /* working directory (if somebody needs it) */
    if (make_dir(state->global->work_dir, 0) < 0) return -1;
    if (make_dir(state->global->print_work_dir, 0) < 0) return -1;
    if (make_dir(state->global->diff_work_dir, 0) < 0) return -1;

    /* SERVE's archive directories */
    if (make_dir(state->global->archive_dir, 0) < 0) return -1;
    if (make_dir(state->global->clar_archive_dir, 0) < 0) return -1;
    if (make_dir(state->global->run_archive_dir, 0) < 0) return -1;
    if (make_dir(state->global->xml_report_archive_dir, 0) < 0) return -1;
    if (make_dir(state->global->report_archive_dir, 0) < 0) return -1;
    if (make_dir(state->global->audit_log_dir, 0777) < 0) return -1;
    if (state->global->team_enable_rep_view) {
      if (make_dir(state->global->team_report_archive_dir, 0) < 0) return -1;
    }
    if (state->global->enable_full_archive) {
      if (make_dir(state->global->full_archive_dir, 0) < 0) return -1;
    }
    if (make_dir(state->global->team_extra_dir, 0) < 0) return -1;
  } else if (mode == PREPARE_COMPILE) {
    if (state->global->root_dir[0] && make_dir(state->global->root_dir, 0) < 0) return -1;
    if (make_dir(state->global->var_dir, 0) < 0) return -1;

    /* COMPILE reads its commands from here */
    if (make_dir(state->global->compile_dir, 0) < 0) return -1;
    if (make_all_dir(state->global->compile_queue_dir, 0777) < 0) return -1;
    if (make_dir(state->global->compile_src_dir, 0) < 0) return -1;

    /* working directory (if somebody needs it) */
    if (make_dir(state->global->work_dir, 0) < 0) return -1;
    if (make_dir(state->global->compile_work_dir, 0) < 0) return -1;
  } else if (mode == PREPARE_RUN) {
    if (state->global->root_dir[0] && make_dir(state->global->root_dir, 0) < 0) return -1;
    if (make_dir(state->global->var_dir, 0) < 0) return -1;

    /* RUN reads its commands from here */
    if (make_dir(state->global->run_dir, 0) < 0) return -1;
    if (make_all_dir(state->global->run_queue_dir, 0777) < 0) return -1;
    if (make_dir(state->global->run_exe_dir, 0) < 0) return -1;

    if (make_dir(state->global->work_dir, 0) < 0) return -1;
    if (make_dir(state->global->run_work_dir, 0) < 0) return -1;
    if (make_dir(state->global->run_check_dir, 0) < 0) return -1;
  }

  for (i = 1; i <= state->max_lang; i++) {
    if (!state->langs[i]) continue;
    if (mode == PREPARE_SERVE) {
      if (make_dir(state->langs[i]->compile_dir, 0) < 0) return -1;
      if (make_all_dir(state->langs[i]->compile_queue_dir, 0777) < 0) return -1;
      if (make_dir(state->langs[i]->compile_src_dir, 0) < 0) return -1;
      // remove possible symlink from previous versions
      // the return code is intentionally ignored
      remove(state->langs[i]->compile_out_dir);
      if (make_dir(state->langs[i]->compile_out_dir, 0) < 0) return -1;
      if (make_all_dir(state->langs[i]->compile_status_dir, 0) < 0) return -1;
      if (make_dir(state->langs[i]->compile_report_dir, 0) < 0) return -1;
    }
  }

  for (i = 1; i <= state->max_tester; i++) {
    if (!state->testers[i]) continue;
    if (mode == PREPARE_SERVE) {
      if (make_dir(state->testers[i]->run_dir, 0) < 0) return -1;
      if (make_all_dir(state->testers[i]->run_queue_dir, 0777) < 0) return -1;
      if (make_dir(state->testers[i]->run_exe_dir, 0) < 0) return -1;
      remove(state->testers[i]->run_out_dir);
      if (make_dir(state->testers[i]->run_out_dir, 0) < 0) return -1;
      if (make_all_dir(state->testers[i]->run_status_dir, 0) < 0) return -1;
      if (make_dir(state->testers[i]->run_report_dir, 0) < 0) return -1;
      if (state->global->team_enable_rep_view) {
        if (make_dir(state->testers[i]->run_team_report_dir, 0) < 0) return -1;
      }
      if (state->global->enable_full_archive) {
        if (make_dir(state->testers[i]->run_full_archive_dir, 0) < 0) return -1;
      }
    }
    if (mode == PREPARE_RUN) {
      if (state->testers[i]->any) continue;
      if (make_dir(state->testers[i]->check_dir, 0) < 0) return -1;
    }
  }

  write_log(0, LOG_INFO, "all directories created");
  return 0;
}

int
parse_version_string(int *pmajor, int *pminor, int *ppatch, int *pbuild)
{
  const unsigned char *p = compile_version;
  int n, x;

  if (sscanf(p, "%d.%dpre%d #%d%n", pmajor, pminor, ppatch, pbuild, &n) == 4
      && !p[n]) {
    *ppatch = -*ppatch;
  } else if (sscanf(p, "%d.%dpre%d%n", pmajor, pminor, ppatch, &n) == 3
             && !p[n]) {
    *ppatch = -*ppatch;
    *pbuild = 0;
  } else if (sscanf(p, "%d.%d.%d+ (SVN r%d) #%d%n", pmajor, pminor, ppatch,
                    pbuild, &x, &n) == 5 && !p[n]) {
  } else if (sscanf(p, "%d.%d.%d+ (SVN r%d)%n", pmajor, pminor, ppatch,
                    pbuild, &n) == 4 && !p[n]) {
  } else if (sscanf(p, "%d.%d.%d #%d%n", pmajor, pminor, ppatch, pbuild, &n)==4
             && !p[n]) {
  } else if (sscanf(p, "%d.%d.%d%n", pmajor, pminor, ppatch, &n) == 3
             && !p[n]) {
    *pbuild = 0;
  } else {
    err("cannot parse version string %s", compile_version);
    return -1;
  }
  if (*pmajor < 2 || *pmajor > 1000) return -1;
  if (*pminor < 0 || *pminor > 1000) return -1;
  return 0;
}

int
prepare(serve_state_t state, char const *config_file, int flags,
        int mode, char const *opts, int managed_flag)
{
  cfg_cond_var_t *cond_vars;
  int ncond_var;
  int major, minor, patch, build;

  if (parse_version_string(&major, &minor, &patch, &build) < 0) return -1;

  // initialize predefined variables
  ncond_var = 7;
  XALLOCAZ(cond_vars, ncond_var);
  cond_vars[0].name = "host";
  cond_vars[0].val.tag = PARSECFG_T_STRING;
  cond_vars[0].val.s.str = os_NodeName();
  cond_vars[1].name = "mode";
  cond_vars[1].val.tag = PARSECFG_T_LONG;
  cond_vars[1].val.l.val = mode;
  cond_vars[2].name = "major";
  cond_vars[2].val.tag = PARSECFG_T_LONG;
  cond_vars[2].val.l.val = major;
  cond_vars[3].name = "minor";
  cond_vars[3].val.tag = PARSECFG_T_LONG;
  cond_vars[3].val.l.val = minor;
  cond_vars[4].name = "patch";
  cond_vars[4].val.tag = PARSECFG_T_LONG;
  cond_vars[4].val.l.val = patch;
  cond_vars[5].name = "build";
  cond_vars[5].val.tag = PARSECFG_T_LONG;
  cond_vars[5].val.l.val = build;
  cond_vars[6].name = "managed";
  cond_vars[6].val.tag = PARSECFG_T_LONG;
  cond_vars[6].val.l.val = managed_flag;

  state->config = parse_param(config_file, 0, params, 1, ncond_var, cond_vars, 0);
  if (!state->config) return -1;
  write_log(0, LOG_INFO, "Configuration file parsed ok");
  if (collect_sections(state, mode) < 0) return -1;

  if (!state->max_lang && mode != PREPARE_RUN) {
    err("no languages specified");
    return -1;
  }
  if (!state->max_prob && mode != PREPARE_COMPILE) {
    err("no problems specified");
    return -1;
  }
  if (!state->max_tester && mode != PREPARE_COMPILE) {
    err("no testers specified");
    return -1;
  }
  if (set_defaults(state, mode) < 0) return -1;
  return 0;
}

int
prepare_tester_refinement(serve_state_t state, struct section_tester_data *out,
                          int def_tst_id, int prob_id)
{
  struct section_tester_data *tp, *atp = 0;
  struct section_problem_data *prb;
  int si, j;
  unsigned char *sish = 0;

  ASSERT(out);
  ASSERT(def_tst_id > 0 && def_tst_id <= state->max_tester);
  ASSERT(prob_id > 0 && prob_id <= state->max_prob);
  tp = state->testers[def_tst_id];
  prb = state->probs[prob_id];
  ASSERT(tp);
  ASSERT(tp->any);
  ASSERT(prb);

  // find abstract tester
  if (tp->super && tp->super[0]) {
    if (tp->super[1]) {
      err("concrete tester may inherit only one abstract tester");
      return -1;
    }

    for (si = 0; si < state->max_abstr_tester; si++) {
      atp = state->abstr_testers[si];
      if (!strcmp(atp->name, tp->super[0])) break;
    }
    if (si >= state->max_abstr_tester) {
      err("abstract tester '%s' not found", tp->super[0]);
      return -1;
    }
    sish = atp->name;
  }

  memset(out, 0, sizeof(*out));
  out->id = tp->id;
  out->problem = prob_id;

  /* copy architecture */
  strcpy(out->arch, tp->arch);
  if (!out->arch[0] && atp && atp->arch[0]) {
    strcpy(out->arch, atp->arch);
  }

  /* copy key */
  /* FIXME: key currently is not handled properly :-( */
  strcpy(out->key, tp->key);
  if (!out->key[0] && atp && atp->key[0]) {
    strcpy(out->key, atp->key);
  }

  /* generate tester name */
  /* FIXME: does the name matter? */
  /* FIXME: should we use the default tester's name? */
  if (out->arch[0]) {
    sprintf(out->name, "tst_dflt_%d_%d_%s", out->id, prob_id, out->arch);
  } else {
    sprintf(out->name, "tst_dflt_%d_%d", out->id, prob_id);
  }

  /* copy check_dir */
  strcpy(out->check_dir, tp->check_dir);
  if (!out->check_dir[0] && atp && atp->check_dir[0]) {
    sformat_message(out->check_dir, sizeof(out->check_dir),
                    atp->check_dir, state->global,
                    prb, NULL, out, NULL, 0, 0, 0);
  }
  if (!out->check_dir[0]) {
    pathcpy(out->check_dir, state->global->run_check_dir);
  }

  /* copy no_core_dump */
  out->no_core_dump = tp->no_core_dump;
  if (out->no_core_dump == -1 && atp) {
    out->no_core_dump = atp->no_core_dump;
  }
  if (out->no_core_dump == -1) {
    out->no_core_dump = 0;
  }

  /* copy enable_memory_limit */
  out->enable_memory_limit_error = tp->enable_memory_limit_error;
  if (out->enable_memory_limit_error == -1 && atp) {
    out->enable_memory_limit_error = atp->enable_memory_limit_error;
  }
  if (out->enable_memory_limit_error == -1) {
    out->enable_memory_limit_error = 0;
  }

  /* copy clear_env */
  out->clear_env = tp->clear_env;
  if (out->clear_env == -1 && atp) {
    out->clear_env = atp->clear_env;
  }
  if (out->clear_env == -1) {
    out->clear_env = 0;
  }

  /* copy time_limit_adjustment */
  out->time_limit_adjustment = tp->time_limit_adjustment;
  if (out->time_limit_adjustment == -1 && atp) {
    out->time_limit_adjustment = atp->time_limit_adjustment;
  }
  if (out->time_limit_adjustment == -1) {
    out->time_limit_adjustment = 0;
  }

  /* copy max_stack_size */
  out->max_stack_size = tp->max_stack_size;
  if (out->max_stack_size == -1L && atp) {
    out->max_stack_size = atp->max_stack_size;
  }

  /* copy max_data_size */
  out->max_data_size = tp->max_data_size;
  if (out->max_data_size == -1L && atp) {
    out->max_data_size = atp->max_data_size;
  }

  /* copy max_vm_size */
  out->max_vm_size = tp->max_vm_size;
  if (out->max_vm_size == -1L && atp) {
    out->max_vm_size = atp->max_vm_size;
  }

  if (tp->memory_limit_type[0] != 1) {
    out->memory_limit_type_val = prepare_parse_memory_limit_type(tp->memory_limit_type);
    if (out->memory_limit_type_val < 0) {
      err("invalid memory limit type `%s'", tp->memory_limit_type);
      return -1;
    }
  }
  if (out->memory_limit_type_val < 0 && atp) {
    out->memory_limit_type_val = atp->memory_limit_type_val;
  }

  out->skip_testing = tp->skip_testing;
  if (out->skip_testing == -1 && atp)
    out->skip_testing = atp->skip_testing;
  if (out->skip_testing == -1)
    out->skip_testing = 0;

  /* copy is_dos */
  out->is_dos = tp->is_dos;
  if (out->is_dos == -1 && atp) {
    out->is_dos = atp->is_dos;
  }
  if (out->is_dos == -1) {
    out->is_dos = 0;
  }

  /* copy priority_adjustment */
  out->priority_adjustment = tp->priority_adjustment;
  if (out->priority_adjustment == -1000 && atp) {
    out->priority_adjustment = atp->priority_adjustment;
  }
  if (out->priority_adjustment == -1000) {
    out->priority_adjustment = 0;
  }

  /* copy no_redirect */
  out->no_redirect = tp->no_redirect;
  if (out->no_redirect == -1 && atp) {
    out->no_redirect = atp->no_redirect;
  }
  if (out->no_redirect == -1) {
    out->no_redirect = 0;
  }

  /* copy kill_signal */
  strcpy(out->kill_signal, tp->kill_signal);
  if (!out->kill_signal[0] && atp) {
    strcpy(out->kill_signal, atp->kill_signal);
  }

  /* copy start_env */
  out->start_env = sarray_merge_pf(tp->start_env, out->start_env);
  if (atp && atp->start_env) {
    out->start_env = sarray_merge_pf(atp->start_env, out->start_env);
  }
  if (out->start_env) {
    for (j = 0; out->start_env[j]; j++) {
      out->start_env[j] = varsubst_heap(state, out->start_env[j], 1,
                                        section_global_params,
                                        section_problem_params,
                                        section_language_params,
                                        section_tester_params);
      if (!out->start_env[j]) return -1;
    }
  }

  /* copy checker_env */
  out->checker_env = sarray_merge_pf(tp->checker_env, out->checker_env);
  if (atp && atp->checker_env) {
    out->checker_env = sarray_merge_pf(atp->checker_env, out->checker_env);
  }
  if (out->checker_env) {
    for (j = 0; out->checker_env[j]; j++) {
      out->checker_env[j] = varsubst_heap(state, out->checker_env[j], 1,
                                          section_global_params,
                                          section_problem_params,
                                          section_language_params,
                                          section_tester_params);
      if (!out->checker_env[j]) return -1;
    }
  }

  /* copy errorcode_file */
  strcpy(out->errorcode_file, tp->errorcode_file);
  if (!out->errorcode_file[0] && atp && atp->errorcode_file[0]) {
    sformat_message(out->errorcode_file, sizeof(out->errorcode_file),
                    atp->errorcode_file, state->global, prb, NULL,
                    out, NULL, 0, 0, 0);
  }

  /* copy error_file */
  strcpy(out->error_file, tp->error_file);
  if (!out->error_file[0] && atp && atp->error_file[0]) {
    sformat_message(out->error_file, sizeof(out->error_file),
                    atp->error_file, state-> global, prb, NULL, out,
                    NULL, 0, 0, 0);
  }
  if (!out->error_file[0]) {
    snprintf(out->error_file, sizeof(out->error_file),
             "%s",  DFLT_T_ERROR_FILE);
  }

  /* copy check_cmd */
  if (prb->standard_checker[0]) {
    strcpy(out->check_cmd, prb->standard_checker);
    pathmake4(out->check_cmd,state->global->ejudge_checkers_dir,"/",out->check_cmd,0);
    out->standard_checker_used = 1;
  } else {
    strcpy(out->check_cmd, tp->check_cmd);
    if (!out->check_cmd[0] && atp && atp->check_cmd[0]) {
      sformat_message(out->check_cmd, sizeof(out->check_cmd),
                      atp->check_cmd, state->global, prb, NULL, out,
                      NULL, 0, 0, 0);
    }
    if (!out->check_cmd[0] && prb->check_cmd[0])
      strcpy(out->check_cmd, prb->check_cmd);
    if (!out->check_cmd[0]) {
      err("default tester for architecture '%s': check_cmd must be set",
          out->arch);
      return -1;
    }
    pathmake4(out->check_cmd, state->global->checker_dir, "/", out->check_cmd, 0);
  }

  /* copy start_cmd */
  strcpy(out->start_cmd, tp->start_cmd);
  if (!out->start_cmd[0] && atp && atp->start_cmd[0]) {
    sformat_message(out->start_cmd, sizeof(out->start_cmd),
                    atp->start_cmd, state->global, prb, NULL, out, NULL,
                    0, 0, 0);
  }
  if (out->start_cmd[0]) {
    pathmake4(out->start_cmd, state->global->script_dir, "/", out->start_cmd, 0);
  }

  /* copy prepare_cmd */
  strcpy(out->prepare_cmd, tp->prepare_cmd);
  if (!out->prepare_cmd[0] && atp && atp->prepare_cmd[0]) {
    sformat_message(out->prepare_cmd, sizeof(out->prepare_cmd),
                    atp->prepare_cmd, state->global, prb, NULL, out,
                    NULL, 0, 0, 0);
  }
  if (out->prepare_cmd[0]) {
    pathmake4(out->prepare_cmd, state->global->script_dir, "/", out->prepare_cmd, 0);
  }

  // for debug
  //print_tester(stdout, out);

  return 0;
}

int
create_tester_dirs(struct section_tester_data *tst)
{
  ASSERT(tst);

  if (make_dir(tst->check_dir, 0) < 0) return -1;
  return 0;
}

void print_global(serve_state_t state, FILE *o)
{
  int i;
  const struct config_parse_info *pp;

  for (i = 0; section_global_params[i].name; i++) {
    pp = &section_global_params[i];
    if (!strcmp(pp->type, "s")) {
      char *pc = XPDEREF(char, state->global, pp->offset);
      fprintf(o, "%s = \"%s\"\n", pp->name, pc);
    } else if (!strcmp(pp->type, "d")) {
      int *pi = XPDEREF(int, state->global, pp->offset);
      fprintf(o, "%s = %d\n", pp->name, *pi);
    }
  }
  fprintf(o, "\n");
}

void print_problem(FILE *o, struct section_problem_data *p)
{
  int i;
  const struct config_parse_info *pp;

  fprintf(o, "[problem]\n");
  for (i = 0;; i++) {
    pp = &section_problem_params[i];
    if (!pp->name) break;
    if (!strcmp(pp->type, "s")) {
      char *pc = XPDEREF(char,p, pp->offset);
      if (!strcmp(pp->name, "super")) fprintf(o, "; ");
      fprintf(o, "%s = \"%s\"\n", pp->name, pc);
    } else if (!strcmp(pp->type, "d")) {
      int *pi = XPDEREF(int,p, pp->offset);
      fprintf(o, "%s = %d\n", pp->name, *pi);
    }
  }
  fprintf(o, "\n");
}
void print_all_problems(serve_state_t state, FILE *o)
{
  int i;

  for (i = 0; i < state->max_abstr_prob; i++)
    print_problem(o, state->abstr_probs[i]);
  for (i = 1; i <= state->max_prob; i++) {
    if (!state->probs[i]) continue;
    print_problem(o, state->probs[i]);
  }
}

void print_language(FILE *o, struct section_language_data *l)
{
  int i;
  const struct config_parse_info *pp;

  fprintf(o, "[language]\n");
  for (i = 0;; i++) {
    pp = &section_language_params[i];
    if (!pp->name) break;
    if (!strcmp(pp->type, "s")) {
      char *pc = XPDEREF(char,l, pp->offset);
      fprintf(o, "%s = \"%s\"\n", pp->name, pc);
    } else if (!strcmp(pp->type, "d")) {
      int *pi = XPDEREF(int,l, pp->offset);
      fprintf(o, "%s = %d\n", pp->name, *pi);
    }
  }
  fprintf(o, "\n");
}
void print_all_languages(serve_state_t state, FILE *o)
{
  int i;

  for (i = 1; i <= state->max_lang; i++) {
    if (!state->langs[i]) continue;
    print_language(o, state->langs[i]);
  }
}

void print_tester(FILE *o, struct section_tester_data *t)
{
  int i;

  fprintf(o, "[tester]\n");
  if (t->abstract) fprintf(o, "abstract\n");
  fprintf(o, "name = \"%s\"\n", t->name);
  fprintf(o, "id = %d\n", t->id);
  if (t->super) {
    for (i = 0; t->super[i]; i++)
      fprintf(o, "; super = \"%s\"\n", t->super[i]);
    /*
    for (;t->super[i] != (char*) 1; i++)
      fprintf(o, "super = (null)\n");
    fprintf(o, "super = (1)\n");
    */
  }
  fprintf(o, "problem = %d\n", t->problem);
  fprintf(o, "problem_name = \"%s\"\n", t->problem_name);
  fprintf(o, "is_dos = %d\n", t->is_dos);
  fprintf(o, "skip_testing = %d\n", t->skip_testing);
  fprintf(o, "no_redirect = %d\n", t->no_redirect);
  fprintf(o, "arch = \"%s\"\n", t->arch);
  fprintf(o, "key = \"%s\"\n", t->key);
  fprintf(o, "check_dir = \"%s\"\n", t->check_dir);
  fprintf(o, "no_core_dump = %d\n", t->no_core_dump);
  fprintf(o, "enable_memory_limit_error = %d\n", t->enable_memory_limit_error);
  fprintf(o, "kill_signal = \"%s\"\n", t->kill_signal);
  fprintf(o, "max_stack_size = %zu\n", t->max_stack_size);
  fprintf(o, "max_data_size = %zu\n", t->max_data_size);
  fprintf(o, "max_vm_size = %zu\n", t->max_vm_size);
  fprintf(o, "clear_env = %d\n", t->clear_env);
  fprintf(o, "errorcode_file = \"%s\"\n", t->errorcode_file);
  fprintf(o, "error_file = \"%s\"\n", t->error_file);
  fprintf(o, "prepare_cmd = \"%s\"\n", t->prepare_cmd);
  fprintf(o, "start_cmd = \"%s\"\n", t->start_cmd);
  fprintf(o, "check_cmd = \"%s\"\n", t->check_cmd);

  if (t->start_env) {
    for (i = 0; t->start_env[i]; i++)
      fprintf(o, "start_env = \"%s\"\n", t->start_env[i]);
    /*
    for (;t->start_env[i] != (char*) 1; i++)
      fprintf(o, "start_env = (null)\n");
    fprintf(o, "start_env = (1)\n");
    */
  }
  fprintf(o, "\n");
}
void print_all_testers(serve_state_t state, FILE *o)
{
  int i;

  /*
  fprintf(stderr, "====%d, %d, %u\n", state->max_abstr_tester, state->max_tester,
          sizeof(struct section_tester_data));
  */

  for (i = 0; i < state->max_abstr_tester; i++)
    print_tester(o, state->abstr_testers[i]);
  for (i = 1; i <= state->max_tester; i++) {
    if (!state->testers[i]) continue;
    print_tester(o, state->testers[i]);
  }

  fflush(o);
}

void print_configuration(serve_state_t state, FILE *o)
{
  print_global(state, o);
  print_all_problems(state, o);
  print_all_languages(state, o);
  print_all_testers(state, o);
}

void
prepare_set_global_defaults(struct section_global_data *g)
{
  /*
  if (!g->sleep_time && !g->serve_sleep_time) {
  }
  */

  if (!g->sleep_time) g->sleep_time = DFLT_G_SLEEP_TIME;
  if (!g->serve_sleep_time) g->serve_sleep_time = DFLT_G_SERVE_SLEEP_TIME;
  if (g->contest_time < 0) g->contest_time = DFLT_G_CONTEST_TIME;
  if (!g->max_run_size) g->max_run_size = DFLT_G_MAX_RUN_SIZE;
  if (!g->max_run_total) g->max_run_total = DFLT_G_MAX_RUN_TOTAL;
  if (!g->max_run_num) g->max_run_num = DFLT_G_MAX_RUN_NUM;
  if (!g->max_clar_size) g->max_clar_size = DFLT_G_MAX_CLAR_SIZE;
  if (!g->max_clar_total) g->max_clar_total = DFLT_G_MAX_CLAR_TOTAL;
  if (!g->max_clar_num) g->max_clar_num = DFLT_G_MAX_CLAR_NUM;
  if (g->board_fog_time < 0) g->board_fog_time = DFLT_G_BOARD_FOG_TIME;
  if (g->board_unfog_time < 0) g->board_unfog_time = DFLT_G_BOARD_UNFOG_TIME;
  if (g->autoupdate_standings < 0) g->autoupdate_standings=DFLT_G_AUTOUPDATE_STANDINGS;
  if (g->team_enable_src_view < 0) g->team_enable_src_view=DFLT_G_TEAM_ENABLE_SRC_VIEW;
  if (g->team_enable_rep_view < 0) g->team_enable_rep_view=DFLT_G_TEAM_ENABLE_REP_VIEW;
  if (g->team_enable_ce_view < 0) g->team_enable_ce_view = DFLT_G_TEAM_ENABLE_CE_VIEW;
  if (g->always_show_problems < 0) g->always_show_problems=DFLT_G_ALWAYS_SHOW_PROBLEMS;
  if (g->disable_user_standings < 0) g->disable_user_standings=DFLT_G_DISABLE_USER_STANDINGS;
  if (g->team_show_judge_report < 0)
    g->team_show_judge_report = DFLT_G_TEAM_SHOW_JUDGE_REPORT;
  if (g->disable_clars < 0) g->disable_clars = DFLT_G_DISABLE_CLARS;
  if (g->disable_team_clars < 0) g->disable_team_clars = DFLT_G_DISABLE_TEAM_CLARS;
  if (!g->max_file_length) g->max_file_length = DFLT_G_MAX_FILE_LENGTH;
  if (!g->max_line_length) g->max_line_length = DFLT_G_MAX_LINE_LENGTH;
  if (g->ignore_compile_errors < 0)
    g->ignore_compile_errors = DFLT_G_IGNORE_COMPILE_ERRORS;
  if (g->disable_failed_test_view < 0)
    g->disable_failed_test_view = DFLT_G_DISABLE_FAILED_TEST_VIEW;
  if (g->inactivity_timeout <= 0)
    g->inactivity_timeout = DFLT_G_INACTIVITY_TIMEOUT;
  if (g->disable_auto_testing < 0)
    g->disable_auto_testing = DFLT_G_DISABLE_AUTO_TESTING;
  if (g->disable_testing < 0)
    g->disable_testing = DFLT_G_DISABLE_TESTING;
  if (!g->charset[0])
    snprintf(g->charset, sizeof(g->charset), "%s", DFLT_G_CHARSET);
  if (!g->test_dir[0])
    snprintf(g->test_dir, sizeof(g->test_dir), "%s", DFLT_G_TEST_DIR);
  if (!g->corr_dir[0])
    snprintf(g->corr_dir, sizeof(g->corr_dir), "%s", DFLT_G_CORR_DIR);
  if (!g->info_dir[0])
    snprintf(g->info_dir, sizeof(g->info_dir), "%s", DFLT_G_INFO_DIR);
  if (!g->tgz_dir[0])
    snprintf(g->tgz_dir, sizeof(g->tgz_dir), "%s", DFLT_G_TGZ_DIR);
  if (!g->checker_dir[0])
    snprintf(g->checker_dir, sizeof(g->checker_dir), "%s", DFLT_G_CHECKER_DIR);
  if (!g->statement_dir[0])
    snprintf(g->statement_dir, sizeof(g->statement_dir), "%s", DFLT_G_STATEMENT_DIR);

  if (!g->score_system[0]) {
    g->score_system_val = SCORE_ACM;
  } else if (!strcmp(g->score_system, "acm")) {
    g->score_system_val = SCORE_ACM;
  } else if (!strcmp(g->score_system, "kirov")) {
    g->score_system_val = SCORE_KIROV;
  } else if (!strcmp(g->score_system, "olympiad")) {
    g->score_system_val = SCORE_OLYMPIAD;
  } else if (!strcmp(g->score_system, "moscow")) {
    g->score_system_val = SCORE_MOSCOW;
  } else {
    g->score_system_val = SCORE_ACM;
  }

  if (!g->rounding_mode[0]) {
    g->rounding_mode_val = SEC_CEIL;
  } else if (!strcmp(g->rounding_mode, "ceil")) {
    g->rounding_mode_val = SEC_CEIL;
  } else if (!strcmp(g->rounding_mode, "floor")) {
    g->rounding_mode_val = SEC_FLOOR;
  } else if (!strcmp(g->rounding_mode, "round")) {
    g->rounding_mode_val = SEC_ROUND;
  } else {
    g->rounding_mode_val = SEC_CEIL;
  }

  if (!g->standings_file_name[0]) {
    snprintf(g->standings_file_name, sizeof(g->standings_file_name),
             "%s", DFLT_G_STANDINGS_FILE_NAME);
  }

  if (g->enable_l10n < 0) g->enable_l10n = 1; /* ??? */
  if (g->team_download_time < 0) g->team_download_time = DFLT_G_TEAM_DOWNLOAD_TIME;
  if (!g->plog_update_time) g->plog_update_time = DFLT_G_PLOG_UPDATE_TIME;
  /*
  if (!g->cr_serialization_key)
    g->cr_serialization_key = config->serialization_key;
  */
  if (g->show_astr_time < 0) g->show_astr_time = DFLT_G_SHOW_ASTR_TIME;
  if (g->ignore_duplicated_runs < 0)
    g->ignore_duplicated_runs = DFLT_G_IGNORE_DUPLICATED_RUNS;
  if (g->show_deadline < 0)
    g->show_deadline = DFLT_G_SHOW_DEADLINE;
  if (g->report_error_code < 0)
    g->report_error_code = DFLT_G_REPORT_ERROR_CODE;
  if (g->enable_continue < 0)
    g->enable_continue = DFLT_G_ENABLE_CONTINUE;
  if (g->enable_runlog_merge < 0)
    g->enable_runlog_merge = DFLT_G_ENABLE_RUNLOG_MERGE;
  if (g->ignore_success_time < 0)
    g->ignore_success_time = DFLT_G_IGNORE_SUCCESS_TIME;
  if (g->secure_run < 0)
    g->secure_run = DFLT_G_SECURE_RUN;
  if (g->enable_memory_limit_error < 0)
    g->enable_memory_limit_error = DFLT_G_ENABLE_MEMORY_LIMIT_ERROR;
  if (g->prune_empty_users < 0)
    g->prune_empty_users = DFLT_G_PRUNE_EMPTY_USERS;
  if (g->enable_report_upload < 0)
    g->enable_report_upload = DFLT_G_ENABLE_REPORT_UPLOAD;
  if (g->enable_full_archive < 0)
    g->enable_full_archive = DFLT_G_ENABLE_FULL_ARCHIVE;
  if (g->enable_printing < 0)
    g->enable_printing = DFLT_G_ENABLE_PRINTING;
  if (g->disable_banner_page < 0)
    g->disable_banner_page = DFLT_G_DISABLE_BANNER_PAGE;
  if (g->team_page_quota < 0)
    g->team_page_quota = DFLT_G_TEAM_PAGE_QUOTA;
  if (g->stand_show_warn_number < 0)
    g->stand_show_warn_number = DFLT_G_STAND_SHOW_WARN_NUMBER;
  if (g->stand_show_ok_time < 0)
    g->stand_show_ok_time = DFLT_G_STAND_SHOW_OK_TIME;
}

void
prepare_set_abstr_problem_defaults(struct section_problem_data *prob,
                                   struct section_global_data *global)
{
  if (!prob->abstract) return;

  if (prob->type[0]) {
    prob->type_val = parse_problem_type(prob->type);
    if (prob->type_val < 0 || prob->type_val >= PROB_TYPE_LAST)
      prob->type_val = -1;
  }

  if (prob->type_val < 0) prob->type_val = 0;
  if (prob->scoring_checker < 0) prob->scoring_checker = 0;
  if (prob->scoring_checker < 0) prob->manual_checking = 0;
  if (prob->examinator_num < 0) prob->examinator_num = 0;
  if (prob->check_presentation < 0) prob->check_presentation = 0;
  if (prob->use_stdin < 0) prob->use_stdin = 0;
  if (prob->use_stdout < 0) prob->use_stdout = 0;
  if (prob->binary_input < 0) prob->binary_input = DFLT_P_BINARY_INPUT;
  if (prob->ignore_exit_code < 0) prob->ignore_exit_code = 0;
  if (prob->time_limit < 0) prob->time_limit = 0;
  if (prob->time_limit_millis < 0) prob->time_limit_millis = 0;
  if (prob->real_time_limit < 0) prob->real_time_limit = 0;
  if (prob->full_score < 0) prob->full_score = DFLT_P_FULL_SCORE;
  if (prob->test_score < 0) prob->test_score = DFLT_P_TEST_SCORE;
  if (prob->variable_full_score < 0)
    prob->variable_full_score = DFLT_P_VARIABLE_FULL_SCORE;
  if (prob->run_penalty < 0) prob->run_penalty = DFLT_P_RUN_PENALTY;
  if (prob->acm_run_penalty < 0) prob->acm_run_penalty = DFLT_P_ACM_RUN_PENALTY;
  if (prob->disqualified_penalty < 0) prob->disqualified_penalty = prob->run_penalty;
  if (prob->use_corr < 0) prob->use_corr = 0;
  if (prob->use_info < 0) prob->use_info = 0;
  if (prob->use_tgz < 0) prob->use_tgz = 0;
  if (prob->tests_to_accept < 0) prob->tests_to_accept = DFLT_G_TESTS_TO_ACCEPT;
  if (prob->accept_partial < 0) prob->accept_partial = 0;
  if (prob->hidden < 0) prob->hidden = 0;
  if (prob->priority_adjustment == -1000) prob->priority_adjustment = 0;
  if (prob->variant_num < 0) prob->variant_num = 0;
  if (prob->test_sfx[0] == 1) {
    prob->test_sfx[0] = 0;
    if (global->test_sfx[0]) {
      snprintf(prob->test_sfx, sizeof(prob->test_sfx), "%s", global->test_sfx);
    }
  }
  if (prob->corr_sfx[0] == 1) {
    prob->corr_sfx[0] = 0;
    if (global->corr_sfx[0]) {
      snprintf(prob->corr_sfx, sizeof(prob->corr_sfx), "%s", global->corr_sfx);
    }
  }
  if (prob->info_sfx[0] == 1) {
    if (global->info_sfx[0]) {
      snprintf(prob->info_sfx, sizeof(prob->info_sfx), "%s", global->info_sfx);
    } else {
      snprintf(prob->info_sfx, sizeof(prob->info_sfx), "%s", DFLT_G_INFO_SFX);
    }
  }
  if (prob->tgz_sfx[0] == 1) {
    if (global->tgz_sfx[0]) {
      snprintf(prob->tgz_sfx, sizeof(prob->tgz_sfx), "%s", global->tgz_sfx);
    } else {
      snprintf(prob->tgz_sfx, sizeof(prob->tgz_sfx), "%s", DFLT_G_TGZ_SFX);
    }
  }
  if (prob->test_pat[0] == 1) {
    prob->test_pat[0] = 0;
    if (global->test_pat[0]) {
      snprintf(prob->test_pat, sizeof(prob->test_pat), "%s", global->test_pat);
    }
  }
  if (prob->corr_pat[0] == 1) {
    prob->corr_pat[0] = 0;
    if (global->corr_pat[0]) {
      snprintf(prob->corr_pat, sizeof(prob->corr_pat), "%s", global->corr_pat);
    }
  }
  if (prob->info_pat[0] == 1) {
    prob->info_pat[0] = 0;
    if (global->info_pat[0]) {
      snprintf(prob->info_pat, sizeof(prob->info_pat), "%s", global->info_pat);
    }
  }
  if (prob->tgz_pat[0] == 1) {
    prob->tgz_pat[0] = 0;
    if (global->tgz_pat[0]) {
      snprintf(prob->tgz_pat, sizeof(prob->tgz_pat), "%s", global->tgz_pat);
    }
  }
}

void
prepare_set_concr_problem_defaults(struct section_problem_data *prob,
                                   struct section_global_data *global)
{
  if (prob->abstract) return;

  if (prob->type[0]) {
    prob->type_val = parse_problem_type(prob->type);
    if (prob->type_val < 0 || prob->type_val >= PROB_TYPE_LAST)
      prob->type_val = -1;
  }
}

struct section_global_data *
prepare_new_global_section(int contest_id, const unsigned char *root_dir,
                           const struct ejudge_cfg *config)
{
  struct section_global_data *global;

  global = prepare_alloc_global();

  global->score_system_val = SCORE_ACM;
  global->rounding_mode_val = SEC_FLOOR;
  global->is_virtual = 0;

  global->contest_id = contest_id;
  global->sleep_time = DFLT_G_SLEEP_TIME;
  global->serve_sleep_time = DFLT_G_SERVE_SLEEP_TIME;
  global->contest_time = DFLT_G_CONTEST_TIME;
  global->max_run_size = DFLT_G_MAX_RUN_SIZE;
  global->max_run_total = DFLT_G_MAX_RUN_TOTAL;
  global->max_run_num = DFLT_G_MAX_RUN_NUM;
  global->max_clar_size = DFLT_G_MAX_CLAR_SIZE;
  global->max_clar_total = DFLT_G_MAX_CLAR_TOTAL;
  global->max_clar_num = DFLT_G_MAX_CLAR_NUM;
  global->board_fog_time = DFLT_G_BOARD_FOG_TIME;
  global->board_unfog_time = DFLT_G_BOARD_UNFOG_TIME;

  global->autoupdate_standings = DFLT_G_AUTOUPDATE_STANDINGS;
  global->team_enable_src_view = DFLT_G_TEAM_ENABLE_SRC_VIEW;
  global->team_enable_rep_view = DFLT_G_TEAM_ENABLE_REP_VIEW;
  global->team_enable_ce_view = 1;
  global->team_show_judge_report = DFLT_G_TEAM_SHOW_JUDGE_REPORT;
  global->disable_clars = DFLT_G_DISABLE_CLARS;
  global->disable_team_clars = DFLT_G_DISABLE_TEAM_CLARS;
  global->max_file_length = DFLT_G_MAX_FILE_LENGTH;
  global->max_line_length = DFLT_G_MAX_LINE_LENGTH;
  global->tests_to_accept = DFLT_G_TESTS_TO_ACCEPT;
  global->ignore_compile_errors = 1;
  global->disable_failed_test_view = DFLT_G_DISABLE_FAILED_TEST_VIEW;
  global->inactivity_timeout = DFLT_G_INACTIVITY_TIMEOUT;
  global->disable_auto_testing = DFLT_G_DISABLE_AUTO_TESTING;
  global->disable_testing = DFLT_G_DISABLE_TESTING;
  global->always_show_problems = DFLT_G_ALWAYS_SHOW_PROBLEMS;
  global->disable_user_standings = DFLT_G_DISABLE_USER_STANDINGS;

  global->cr_serialization_key = config->serialization_key;
  global->show_astr_time = DFLT_G_SHOW_ASTR_TIME;
  global->ignore_duplicated_runs = DFLT_G_IGNORE_DUPLICATED_RUNS;
  global->show_deadline = DFLT_G_SHOW_DEADLINE;
  global->report_error_code = DFLT_G_REPORT_ERROR_CODE;
  global->auto_short_problem_name = 0;
  global->enable_continue = DFLT_G_ENABLE_CONTINUE;
  global->checker_real_time_limit = DFLT_G_CHECKER_REAL_TIME_LIMIT;
  global->compile_real_time_limit = DFLT_G_COMPILE_REAL_TIME_LIMIT;
  global->show_deadline = 0;
  global->enable_runlog_merge = 1;
  global->ignore_success_time = DFLT_G_IGNORE_SUCCESS_TIME;
  global->secure_run = 1;
  global->enable_memory_limit_error = DFLT_G_ENABLE_MEMORY_LIMIT_ERROR;
  global->prune_empty_users = DFLT_G_PRUNE_EMPTY_USERS;
  global->enable_report_upload = DFLT_G_ENABLE_REPORT_UPLOAD;
  global->team_download_time = 0;
  global->cpu_bogomips = cpu_get_bogomips();
  global->use_gzip = DFLT_G_USE_GZIP;
  global->min_gzip_size = DFLT_G_MIN_GZIP_SIZE;
  global->use_dir_hierarchy = DFLT_G_USE_DIR_HIERARCHY;
  global->enable_full_archive = 1;
  global->enable_printing = DFLT_G_ENABLE_PRINTING;
  global->disable_banner_page = DFLT_G_DISABLE_BANNER_PAGE;
  global->team_page_quota = DFLT_G_TEAM_PAGE_QUOTA;
  global->enable_l10n = 1;
  global->stand_show_ok_time = DFLT_G_STAND_SHOW_OK_TIME;
  global->stand_show_warn_number = DFLT_G_STAND_SHOW_WARN_NUMBER;

  strcpy(global->charset, DFLT_G_CHARSET);

  snprintf(global->root_dir, sizeof(global->root_dir), "%s", root_dir);
  strcpy(global->conf_dir, DFLT_G_CONF_DIR);

  strcpy(global->test_dir, "../tests");
  strcpy(global->corr_dir, "../tests");
  strcpy(global->info_dir, "../tests");
  strcpy(global->tgz_dir, "../tests");
  strcpy(global->checker_dir, "../checkers");
  strcpy(global->statement_dir, "../statements");

  strcpy(global->standings_file_name, DFLT_G_STANDINGS_FILE_NAME);
  global->plog_update_time = DFLT_G_PLOG_UPDATE_TIME;

  /*
  GLOBAL_PARAM(test_sfx, "s"),
  GLOBAL_PARAM(corr_sfx, "s"),
  GLOBAL_PARAM(info_sfx, "s"),
  GLOBAL_PARAM(tgz_sfx, "s"),
  GLOBAL_PARAM(ejudge_checkers_dir, "s"),
  GLOBAL_PARAM(test_pat, "s"),
  GLOBAL_PARAM(corr_pat, "s"),
  GLOBAL_PARAM(info_pat, "s"),
  GLOBAL_PARAM(tgz_pat, "s"),
  GLOBAL_PARAM(contest_start_cmd, "s"),
  */

  /*
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
  GLOBAL_PARAM(script_dir, "s"),
  */

  /*
  GLOBAL_PARAM(a2ps_path, "s"),
  GLOBAL_PARAM(a2ps_args, "x"),
  GLOBAL_PARAM(lpr_path, "s"),
  GLOBAL_PARAM(lpr_args, "x"),
  GLOBAL_PARAM(diff_path, "s"),
  */

  /*
  GLOBAL_PARAM(compile_dir, "s"),
  GLOBAL_PARAM(compile_work_dir, "s"),
  */

  /*
  GLOBAL_PARAM(run_dir, "s"),
  GLOBAL_PARAM(run_work_dir, "s"),
  GLOBAL_PARAM(run_check_dir, "s"),
  */

  /*
  GLOBAL_PARAM(htdocs_dir, "s"),
  GLOBAL_PARAM(team_info_url, "s"),
  GLOBAL_PARAM(prob_info_url, "s"),
  GLOBAL_PARAM(stand_header_file, "s"),
  GLOBAL_PARAM(stand_footer_file, "s"),
  GLOBAL_PARAM(stand_symlink_dir, "s"),
  GLOBAL_PARAM(stand2_file_name, "s"),
  GLOBAL_PARAM(stand2_header_file, "s"),
  GLOBAL_PARAM(stand2_footer_file, "s"),
  GLOBAL_PARAM(stand2_symlink_dir, "s"),
  GLOBAL_PARAM(plog_file_name, "s"),
  GLOBAL_PARAM(plog_header_file, "s"),
  GLOBAL_PARAM(plog_footer_file, "s"),
  GLOBAL_PARAM(plog_update_time, "d"),
  GLOBAL_PARAM(plog_symlink_dir, "s"),
  */

  /*
  // standings table attributes
  GLOBAL_PARAM(stand_extra_format, "s"),
  GLOBAL_PARAM(stand_extra_legend, "s"),
  GLOBAL_PARAM(stand_extra_attr, "s"),
  GLOBAL_PARAM(stand_table_attr, "s"),
  GLOBAL_PARAM(stand_place_attr, "s"),
  GLOBAL_PARAM(stand_team_attr, "s"),
  GLOBAL_PARAM(stand_prob_attr, "s"),
  GLOBAL_PARAM(stand_solved_attr, "s"),
  GLOBAL_PARAM(stand_score_attr, "s"),
  GLOBAL_PARAM(stand_penalty_attr, "s"),
  GLOBAL_PARAM(stand_time_attr, "s"),
  GLOBAL_PARAM(stand_self_row_attr, "s"),
  GLOBAL_PARAM(stand_v_row_attr, "s"),
  GLOBAL_PARAM(stand_r_row_attr, "s"),
  GLOBAL_PARAM(stand_u_row_attr, "s"),
  GLOBAL_PARAM(stand_success_attr, "s"),
  GLOBAL_PARAM(stand_fail_attr, "s"),
  GLOBAL_PARAM(stand_trans_attr, "s"),
  */

  /*
  // just for fun
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
  */

  /*
  GLOBAL_PARAM(l10n_dir, "s"),
  GLOBAL_PARAM(standings_locale, "s"),
  */

  /*
  GLOBAL_PARAM(variant_map_file, "s"),
  GLOBAL_PARAM(priority_adjustment, "d"),
  GLOBAL_PARAM(user_priority_adjustments, "x"),
  GLOBAL_PARAM(contestant_status_num, "d"),
  GLOBAL_PARAM(contestant_status_legend, "x"),
  GLOBAL_PARAM(contestant_status_row_attr, "x"),
  GLOBAL_PARAM(stand_show_contestant_status, "d"),
  GLOBAL_PARAM(stand_contestant_status_attr, "s"),
  GLOBAL_PARAM(stand_warn_number_attr, "s"),
  */


  return global;
}

struct generic_section_config *
prepare_parse_config_file(const unsigned char *path, int *p_cond_count)
{
  int major, minor, patch, build, ncond_var;
  cfg_cond_var_t *cond_vars;

  if (parse_version_string(&major, &minor, &patch, &build) < 0) return 0;

  // initialize predefined variables
  ncond_var = 7;
  XALLOCAZ(cond_vars, ncond_var);
  cond_vars[0].name = "host";
  cond_vars[0].val.tag = PARSECFG_T_STRING;
  cond_vars[0].val.s.str = os_NodeName();
  cond_vars[1].name = "mode";
  cond_vars[1].val.tag = PARSECFG_T_LONG;
  cond_vars[1].val.l.val = PREPARE_SERVE;
  cond_vars[2].name = "major";
  cond_vars[2].val.tag = PARSECFG_T_LONG;
  cond_vars[2].val.l.val = major;
  cond_vars[3].name = "minor";
  cond_vars[3].val.tag = PARSECFG_T_LONG;
  cond_vars[3].val.l.val = minor;
  cond_vars[4].name = "patch";
  cond_vars[4].val.tag = PARSECFG_T_LONG;
  cond_vars[4].val.l.val = patch;
  cond_vars[5].name = "build";
  cond_vars[5].val.tag = PARSECFG_T_LONG;
  cond_vars[5].val.l.val = build;
  cond_vars[6].name = "managed";
  cond_vars[6].val.tag = PARSECFG_T_LONG;
  cond_vars[6].val.l.val = 1;

  return parse_param(path, 0, params, 1, ncond_var, cond_vars, p_cond_count);
}

struct section_global_data *
prepare_alloc_global(void)
{
  return (struct section_global_data*) param_alloc_section("global", params);
}

struct section_language_data *
prepare_alloc_language(void)
{
  return (struct section_language_data*) param_alloc_section("language", params);
}

struct section_problem_data *
prepare_alloc_problem(void)
{
  return (struct section_problem_data*) param_alloc_section("problem", params);
}

struct section_tester_data *
prepare_alloc_tester(void)
{
  return (struct section_tester_data*) param_alloc_section("tester", params);
}

struct generic_section_config *
prepare_free_config(struct generic_section_config *cfg)
{
  return param_free(cfg, params);
}

void
prepare_copy_problem(struct section_problem_data *out,
                     const struct section_problem_data *in)
{
  if (out == in) return;
  memmove(out, in, sizeof(*out));
  out->ntests = 0;
  out->tscores = 0;
  out->x_score_tests = 0;
  out->test_sets = 0;
  out->ts_total = 0;
  out->ts_infos = 0;
  out->date_penalty = 0;
  out->dp_total = 0;
  out->dp_infos = 0;
  out->disable_language = 0;
  out->enable_language = 0;
  out->require = 0;
  out->checker_env = 0;
  out->lang_time_adj = 0;
  out->personal_deadline = 0;
  out->pd_total = 0;
  out->pd_infos = 0;
  out->score_bonus_total = 0;
  out->score_bonus_val = 0;
}

void
prepare_set_prob_value(int field, struct section_problem_data *out,
                       const struct section_problem_data *abstr,
                       const struct section_global_data *global)
{
  switch (field) {
  case PREPARE_FIELD_PROB_TYPE:
    if (out->type_val == -1 && abstr) out->type_val = abstr->type_val;
    if (out->type_val == -1) out->type_val = 0;
    break;

  case PREPARE_FIELD_PROB_SCORING_CHECKER:
    if (out->scoring_checker == -1 && abstr)
      out->scoring_checker = abstr->scoring_checker;
    if (out->scoring_checker == -1) out->scoring_checker = 0;
    break;

  case PREPARE_FIELD_PROB_MANUAL_CHECKING:
    if (out->manual_checking == -1 && abstr)
      out->manual_checking = abstr->manual_checking;
    if (out->manual_checking == -1) out->manual_checking = 0;
    break;

  case PREPARE_FIELD_PROB_EXAMINATOR_NUM:
    if (out->examinator_num <= 0 && abstr)
      out->examinator_num = abstr->examinator_num;
    if (out->manual_checking <= 0) out->manual_checking = 0;
    break;

  case PREPARE_FIELD_PROB_CHECK_PRESENTATION:
    if (out->check_presentation == -1 && abstr)
      out->check_presentation = abstr->check_presentation;
    if (out->check_presentation == -1) out->check_presentation = 0;
    break;

  case PREPARE_FIELD_PROB_USE_STDIN:
    if (out->use_stdin == -1 && abstr) out->use_stdin = abstr->use_stdin;
    if (out->use_stdin == -1) out->use_stdin = 0;
    break;

  case PREPARE_FIELD_PROB_USE_STDOUT:
    if (out->use_stdout == -1 && abstr) out->use_stdout = abstr->use_stdout;
    if (out->use_stdout == -1) out->use_stdout = 0;
    break;

  case PREPARE_FIELD_PROB_BINARY_INPUT:
    if (out->binary_input == -1 && abstr) out->binary_input = abstr->binary_input;
    if (out->binary_input == -1) out->binary_input = DFLT_P_BINARY_INPUT;
    break;

  case PREPARE_FIELD_PROB_IGNORE_EXIT_CODE:
    if (out->ignore_exit_code == -1 && abstr) out->ignore_exit_code = abstr->ignore_exit_code;
    if (out->ignore_exit_code == -1) out->ignore_exit_code = 0;
    break;

  case PREPARE_FIELD_PROB_TIME_LIMIT:
    if (out->time_limit == -1 && abstr) out->time_limit = abstr->time_limit;
    if (out->time_limit == -1) out->time_limit = 0;
    break;

  case PREPARE_FIELD_PROB_TIME_LIMIT_MILLIS:
    if (out->time_limit_millis == -1 && abstr)
      out->time_limit_millis = abstr->time_limit_millis;
    if (out->time_limit_millis == -1) out->time_limit_millis = 0;
    break;

  case PREPARE_FIELD_PROB_REAL_TIME_LIMIT:
    if (out->real_time_limit == -1 && abstr)
      out->real_time_limit = abstr->real_time_limit;
    if (out->real_time_limit == -1) out->real_time_limit = 0;
    break;

  case PREPARE_FIELD_PROB_TEAM_ENABLE_REP_VIEW:
    if (out->team_enable_rep_view == -1 && abstr)
      out->team_enable_rep_view = abstr->team_enable_rep_view;
    if (out->team_enable_rep_view == -1 && global)
      out->team_enable_rep_view = global->team_enable_rep_view;
    if (out->team_enable_rep_view == -1)
      out->team_enable_rep_view = 0;
    break;

  case PREPARE_FIELD_PROB_TEAM_ENABLE_CE_VIEW:
    if (out->team_enable_ce_view == -1 && abstr)
      out->team_enable_ce_view = abstr->team_enable_ce_view;
    if (out->team_enable_ce_view == -1 && global)
      out->team_enable_ce_view = global->team_enable_ce_view;
    if (out->team_enable_ce_view == -1)
      out->team_enable_ce_view = 0;
    break;

  case PREPARE_FIELD_PROB_TEAM_SHOW_JUDGE_REPORT:
    if (out->team_show_judge_report == -1 && abstr)
      out->team_show_judge_report = abstr->team_show_judge_report;
    if (out->team_show_judge_report == -1 && global)
      out->team_show_judge_report = global->team_show_judge_report;
    if (out->team_show_judge_report == -1)
      out->team_show_judge_report = 0;
    break;

  case PREPARE_FIELD_PROB_DISABLE_USER_SUBMIT:
    if (out->disable_user_submit == -1 && abstr)
      out->disable_user_submit = abstr->disable_user_submit;
    if (out->disable_user_submit == -1)
      out->disable_user_submit = 0;
    break;

  case PREPARE_FIELD_PROB_DISABLE_SUBMIT_AFTER_OK:
    if (out->disable_submit_after_ok < 0 && abstr)
      out->disable_submit_after_ok = abstr->disable_submit_after_ok;
    if (out->disable_submit_after_ok < 0 && global)
      out->disable_submit_after_ok = global->disable_submit_after_ok;
    if (out->disable_submit_after_ok < 0)
      out->disable_submit_after_ok = 0;
    break;

  case PREPARE_FIELD_PROB_DISABLE_TESTING:
    if (out->disable_testing == -1 && abstr)
      out->disable_testing = abstr->disable_testing;
    if (out->disable_testing == -1 && global)
      out->disable_testing = global->disable_testing;
    if (out->disable_testing == -1)
      out->disable_testing = 0;
    break;

  case PREPARE_FIELD_PROB_DISABLE_AUTO_TESTING:
    if (out->disable_auto_testing == -1 && abstr)
      out->disable_auto_testing = abstr->disable_auto_testing;
    if (out->disable_auto_testing == -1 && global)
      out->disable_auto_testing = global->disable_auto_testing;
    if (out->disable_auto_testing == -1)
      out->disable_auto_testing = 0;
    break;

  case PREPARE_FIELD_PROB_ENABLE_COMPILATION:
    if (out->enable_compilation == -1 && abstr)
      out->enable_compilation = abstr->enable_compilation;
    if (out->enable_compilation == -1)
      out->enable_compilation = 0;
    break;

  case PREPARE_FIELD_PROB_SKIP_TESTING:
    if (out->skip_testing == -1 && abstr)
      out->skip_testing = abstr->skip_testing;
    if (out->skip_testing == -1)
      out->skip_testing = 0;
    break;

  case PREPARE_FIELD_PROB_FULL_SCORE:
    if (out->full_score == -1 && abstr) out->full_score = abstr->full_score;
    if (out->full_score == -1) out->full_score = DFLT_P_FULL_SCORE;
    break;

  case PREPARE_FIELD_PROB_TEST_SCORE:
    if (out->test_score == -1 && abstr) out->test_score = abstr->test_score;
    if (out->test_score == -1) out->test_score = DFLT_P_TEST_SCORE;
    break;

  case PREPARE_FIELD_PROB_RUN_PENALTY:
    if (out->run_penalty == -1 && abstr) out->run_penalty = abstr->run_penalty;
    if (out->run_penalty == -1) out->run_penalty = DFLT_P_RUN_PENALTY;
    break;

  case PREPARE_FIELD_PROB_ACM_RUN_PENALTY:
    if (out->acm_run_penalty == -1 && abstr)
      out->acm_run_penalty = abstr->acm_run_penalty;
    if (out->acm_run_penalty == -1) out->acm_run_penalty = DFLT_P_ACM_RUN_PENALTY;
    break;

  case PREPARE_FIELD_PROB_DISQUALIFIED_PENALTY:
    if (out->disqualified_penalty == -1 && abstr)
      out->disqualified_penalty = abstr->disqualified_penalty;
    if (out->disqualified_penalty == -1)
      out->disqualified_penalty = out->run_penalty;
    if (out->disqualified_penalty == -1 && abstr)
      out->disqualified_penalty = abstr->run_penalty;
    if (out->disqualified_penalty == -1)
      out->disqualified_penalty = DFLT_P_RUN_PENALTY;
    break;

  case PREPARE_FIELD_PROB_VARIABLE_FULL_SCORE:
    if (out->variable_full_score == -1 && abstr)
      out->variable_full_score = abstr->variable_full_score;
    if (out->variable_full_score == -1)
      out->variable_full_score = DFLT_P_VARIABLE_FULL_SCORE;
    break;

  case PREPARE_FIELD_PROB_TESTS_TO_ACCEPT:
    if (out->tests_to_accept == -1 && abstr)
      out->tests_to_accept = abstr->tests_to_accept;
    if (out->tests_to_accept == -1 && global)
      out->tests_to_accept = global->tests_to_accept;
    if (out->tests_to_accept == -1)
      out->tests_to_accept = DFLT_G_TESTS_TO_ACCEPT;
    break;

  case PREPARE_FIELD_PROB_ACCEPT_PARTIAL:
    if (out->accept_partial == -1 && abstr)
      out->accept_partial = abstr->accept_partial;
    if (out->accept_partial == -1)
      out->accept_partial = 0;
    break;

  case PREPARE_FIELD_PROB_HIDDEN:
    if (out->hidden == -1 && abstr)
      out->hidden = abstr->hidden;
    if (out->hidden == -1)
      out->hidden = 0;
    break;

  case PREPARE_FIELD_PROB_CHECKER_REAL_TIME_LIMIT:
    if (out->checker_real_time_limit == -1 && abstr)
      out->checker_real_time_limit = abstr->checker_real_time_limit;
    if (out->checker_real_time_limit == -1 && global)
      out->checker_real_time_limit = global->checker_real_time_limit;
    if (out->checker_real_time_limit == -1)
      out->checker_real_time_limit = DFLT_G_CHECKER_REAL_TIME_LIMIT;
    break;

  case PREPARE_FIELD_PROB_MAX_VM_SIZE:
    if (out->max_vm_size == -1L && abstr)
      out->max_vm_size = abstr->max_vm_size;
    if (out->max_vm_size == -1L)
      out->max_vm_size = 0;
    break;

  case PREPARE_FIELD_PROB_MAX_STACK_SIZE:
    if (out->max_stack_size == -1L && abstr)
      out->max_stack_size = abstr->max_stack_size;
    if (out->max_stack_size == -1L)
      out->max_stack_size = 0;
    break;

  case PREPARE_FIELD_PROB_MAX_DATA_SIZE:
    if (out->max_data_size == -1L && abstr)
      out->max_data_size = abstr->max_data_size;
    if (out->max_data_size == -1L)
      out->max_data_size = 0;
    break;

  case PREPARE_FIELD_PROB_INPUT_FILE:
    if (!out->input_file[0] && abstr && abstr->input_file[0]) {
      sformat_message(out->input_file, PATH_MAX, abstr->input_file,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->input_file[0]) {
      strcpy(out->input_file, DFLT_P_INPUT_FILE);
    }
    break;

  case PREPARE_FIELD_PROB_OUTPUT_FILE:
    if (!out->output_file[0] && abstr && abstr->output_file[0]) {
      sformat_message(out->output_file, PATH_MAX, abstr->output_file,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->output_file[0]) {
      strcpy(out->output_file, DFLT_P_OUTPUT_FILE);
    }
    break;

  case PREPARE_FIELD_PROB_USE_CORR:
    if (out->use_corr == -1 && abstr) out->use_corr = abstr->use_corr;
    if (out->use_corr == -1 && out->corr_dir[0]) out->use_corr = 1;
    if (out->use_corr == -1) out->use_corr = 0;
    break;

  case PREPARE_FIELD_PROB_USE_INFO:
    if (out->use_info == -1 && abstr) out->use_info = abstr->use_info;
    if (out->use_info == -1) out->use_info = 0;
    break;

  case PREPARE_FIELD_PROB_USE_TGZ:
    if (out->use_tgz == -1 && abstr) out->use_tgz = abstr->use_tgz;
    if (out->use_tgz == -1) out->use_tgz = 0;
    break;

  case PREPARE_FIELD_PROB_TEST_DIR:
    if (!out->test_dir[0] && abstr && abstr->test_dir[0]) {
      sformat_message(out->test_dir, PATH_MAX, abstr->test_dir,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->test_dir[0]) {
      pathcpy(out->test_dir, out->short_name);
    }
    if (global && out->test_dir[0]) {
      path_add_dir(out->test_dir, global->test_dir);
    }
    break;

  case PREPARE_FIELD_PROB_CORR_DIR:
    if (!out->corr_dir[0] && abstr && abstr->corr_dir[0]) {
      sformat_message(out->corr_dir, PATH_MAX, abstr->corr_dir,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->corr_dir[0]) {
      path_add_dir(out->corr_dir, global->corr_dir);
    }
    break;

  case PREPARE_FIELD_PROB_INFO_DIR:
    if (!out->info_dir[0] && abstr && abstr->info_dir[0]) {
      sformat_message(out->info_dir, PATH_MAX, abstr->info_dir,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->info_dir[0]) {
      snprintf(out->info_dir, sizeof(out->info_dir), "%s", out->short_name);
    }
    if (global && out->info_dir[0]) {
      path_add_dir(out->info_dir, global->info_dir);
    }
    break;

  case PREPARE_FIELD_PROB_TGZ_DIR:
    if (!out->tgz_dir[0] && abstr && abstr->tgz_dir[0]) {
      sformat_message(out->tgz_dir, PATH_MAX, abstr->tgz_dir,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->tgz_dir[0]) {
      snprintf(out->tgz_dir, sizeof(out->tgz_dir), "%s", out->short_name);
    }
    if (global && out->tgz_dir[0]) {
      path_add_dir(out->tgz_dir, global->tgz_dir);
    }
    break;

  case PREPARE_FIELD_PROB_TEST_SFX:
    if (out->test_sfx[0] == 1 && abstr && abstr->test_sfx[0] != 1) {
      strcpy(out->test_sfx, abstr->test_sfx);
    }
    if (out->test_sfx[0] == 1 && global && global->test_sfx[0] != 1) {
      strcpy(out->test_sfx, global->test_sfx);
    }
    if (out->test_sfx[0] == 1) {
      out->test_sfx[0] = 0;
    }
    break;

  case PREPARE_FIELD_PROB_CORR_SFX:
    if (out->corr_sfx[0] == 1 && abstr && abstr->corr_sfx[0] != 1) {
      strcpy(out->corr_sfx, abstr->corr_sfx);
    }
    if (out->corr_sfx[0] == 1 && global && global->corr_sfx[0] != 1) {
      strcpy(out->corr_sfx, global->corr_sfx);
    }
    if (out->corr_sfx[0] == 1) {
      out->corr_sfx[0] = 0;
    }
    break;

  case PREPARE_FIELD_PROB_INFO_SFX:
    if (out->info_sfx[0] == 1 && abstr && abstr->info_sfx[0] != 1) {
      strcpy(out->info_sfx, abstr->info_sfx);
    }
    if (out->info_sfx[0] == 1 && global && global->info_sfx[0]) {
      strcpy(out->info_sfx, global->info_sfx);
    }
    if (out->info_sfx[0] == 1) {
      strcpy(out->info_sfx, DFLT_G_INFO_SFX);
    }
    if (out->info_sfx[0] == 1) {
      out->info_sfx[0] = 0;
    }
    break;

  case PREPARE_FIELD_PROB_TGZ_SFX:
    if (out->tgz_sfx[0] == 1 && abstr && abstr->tgz_sfx[0] != 1) {
      strcpy(out->tgz_sfx, abstr->tgz_sfx);
    }
    if (out->tgz_sfx[0] == 1 && global && global->tgz_sfx[0] != 1) {
      strcpy(out->tgz_sfx, global->tgz_sfx);
    }
    if (out->tgz_sfx[0] == 1) {
      strcpy(out->tgz_sfx, DFLT_G_TGZ_SFX);
    }
    if (out->tgz_sfx[0] == 1) {
      out->tgz_sfx[0] = 0;
    }
    break;

  case PREPARE_FIELD_PROB_TEST_PAT:
    if (out->test_pat[0] == 1 && abstr && abstr->test_pat[0] != 1) {
      strcpy(out->test_pat, abstr->test_pat);
    }
    if (out->test_pat[0] == 1 && global && global->test_pat[0] != 1) {
      strcpy(out->test_pat, global->test_pat);
    }
    if (out->test_pat[0] == 1) {
      out->test_pat[0] = 0;
    }
    break;

  case PREPARE_FIELD_PROB_CORR_PAT:
    if (out->corr_pat[0] == 1 && abstr && abstr->corr_pat[0] != 1) {
      strcpy(out->corr_pat, abstr->corr_pat);
    }
    if (out->corr_pat[0] == 1 && global && global->corr_pat[0] != 1) {
      strcpy(out->corr_pat, global->corr_pat);
    }
    if (out->corr_pat[0] == 1) {
      out->corr_pat[0] = 0;
    }
    break;

  case PREPARE_FIELD_PROB_INFO_PAT:
    if (out->info_pat[0] == 1 && abstr && abstr->info_pat[0] != 1) {
      strcpy(out->info_pat, abstr->info_pat);
    }
    if (out->info_pat[0] == 1 && global && global->info_pat[0] != 1) {
      strcpy(out->info_pat, global->info_pat);
    }
    if (out->info_pat[0] == 1) {
      out->info_pat[0] = 0;
    }
    break;

  case PREPARE_FIELD_PROB_TGZ_PAT:
    if (out->tgz_pat[0] == 1 && abstr && abstr->tgz_pat[0] != 1) {
      strcpy(out->tgz_pat, abstr->tgz_pat);
    }
    if (out->tgz_pat[0] == 1 && global && global->tgz_pat[0] != 1) {
      strcpy(out->tgz_pat, global->tgz_pat);
    }
    if (out->tgz_pat[0] == 1) {
      out->tgz_pat[0] = 0;
    }
    break;

  case PREPARE_FIELD_PROB_SCORE_BONUS:
    if (!out->score_bonus[0] && abstr && abstr->score_bonus[0]) {
      strcpy(out->score_bonus, abstr->score_bonus);
    }
    /*
    if (state->probs[i]->score_bonus[0]) {
        if (parse_score_bonus(state->probs[i]->score_bonus, &state->probs[i]->score_bonus_total,
                              &state->probs[i]->score_bonus_val) < 0) return -1;
      }
    */
    break;

  case PREPARE_FIELD_PROB_CHECK_CMD:
    if (!out->check_cmd[0] && abstr && abstr->check_cmd[0]) {
      sformat_message(out->check_cmd, PATH_MAX, abstr->check_cmd,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    /*
    if (global) {
      pathmake4(out->check_cmd, global->checker_dir, "/", out->check_cmd, 0);
    }
    */
    break;

  case PREPARE_FIELD_PROB_STATEMENT_FILE:
    if (!out->statement_file[0] && abstr && abstr->statement_file[0]) {
      sformat_message(out->statement_file, PATH_MAX, abstr->statement_file,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->statement_file[0]) {
      path_add_dir(out->statement_file, global->statement_dir);
    }
    break;

  case PREPARE_FIELD_PROB_ALTERNATIVES_FILE:
    if (!out->alternatives_file[0] && abstr && abstr->alternatives_file[0]) {
      sformat_message(out->alternatives_file,PATH_MAX, abstr->alternatives_file,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->alternatives_file[0]) {
      path_add_dir(out->alternatives_file, global->statement_dir);
    }
    break;

  case PREPARE_FIELD_PROB_STAND_ATTR:
    if (!out->stand_attr[0] && abstr && abstr->stand_attr[0]) {
      snprintf(out->stand_attr, sizeof(out->stand_attr), "%s",
               abstr->stand_attr);
    }
    break;

  default:
    abort();
  }
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
