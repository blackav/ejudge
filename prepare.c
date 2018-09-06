/* -*- c -*- */

/* Copyright (C) 2000-2018 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/varsubst.h"
#include "ejudge/version.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/fileutl.h"
#include "ejudge/sformat.h"
#include "ejudge/teamdb.h"
#include "ejudge/prepare_serve.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/cpu.h"
#include "ejudge/errlog.h"
#include "ejudge/serve_state.h"
#include "ejudge/xml_utils.h"
#include "ejudge/compat.h"
#include "ejudge/variant_map.h"
#include "ejudge/dates_config.h"
#include "ejudge/l10n.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "ejudge/win32_compat.h"

static int
do_problem_parse_type(const unsigned char *str, void *ptr, size_t size);
static int
global_parse_score_system(const unsigned char *str, void *ptr, size_t size);
static int
global_parse_rounding_mode(const unsigned char *str, void *ptr, size_t size);

#define XFSIZE(t, x) (sizeof(((t*) 0)->x))

#define GLOBAL_OFFSET(x)   XOFFSET(struct section_global_data, x)
#define GLOBAL_SIZE(x)     XFSIZE(struct section_global_data, x)
#define GLOBAL_PARAM(x, t) { #x, t, GLOBAL_OFFSET(x), GLOBAL_SIZE(x) }
#define GLOBAL_PARAM_2(x, f) { #x, "f", GLOBAL_OFFSET(x), GLOBAL_SIZE(x), f}
#define GLOBAL_ALIAS(a, x, t) { #a, t, GLOBAL_OFFSET(x), GLOBAL_SIZE(x) }
static const struct config_parse_info section_global_params[] =
{
  GLOBAL_PARAM(name, "S"),
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
  GLOBAL_PARAM(use_ac_not_ok, "d"),
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
  GLOBAL_PARAM(detect_violations, "d"),
  GLOBAL_PARAM(enable_memory_limit_error, "d"),
  GLOBAL_PARAM(show_problems_link_before_start, "d"),
  GLOBAL_PARAM(show_problems_link_after_finish, "d"),
  GLOBAL_PARAM(disable_user_standings, "d"),
  GLOBAL_PARAM(disable_language, "d"),
  GLOBAL_PARAM(problem_navigation, "d"),
  GLOBAL_PARAM(problem_tab_size, "d"),
  GLOBAL_PARAM(vertical_navigation, "d"),
  GLOBAL_PARAM(disable_virtual_start, "d"),
  GLOBAL_PARAM(disable_virtual_auto_judge, "d"),
  GLOBAL_PARAM(enable_auto_print_protocol, "d"),
  GLOBAL_PARAM(notify_clar_reply, "d"),
  GLOBAL_PARAM(notify_status_change, "d"),
  GLOBAL_PARAM(memoize_user_results, "d"),
  GLOBAL_PARAM(advanced_layout, "d"),
  GLOBAL_PARAM(uuid_run_store, "d"),
  GLOBAL_PARAM(enable_32bit_checkers, "d"),
  GLOBAL_PARAM(ignore_bom, "d"),
  GLOBAL_PARAM(disable_auto_refresh, "d"),
  GLOBAL_PARAM(disable_user_database, "d"),
  GLOBAL_PARAM(enable_max_stack_size, "d"),
  GLOBAL_PARAM(enable_eoln_select, "d"),
  GLOBAL_PARAM(time_limit_retry_count, "d"),
  GLOBAL_PARAM(score_n_best_problems, "d"),
  GLOBAL_PARAM(start_on_first_login, "d"),
  GLOBAL_PARAM(enable_virtual_restart, "d"),

  GLOBAL_PARAM(stand_ignore_after, "t"),
  GLOBAL_PARAM(appeal_deadline, "t"),
  GLOBAL_PARAM(charset, "S"),
  GLOBAL_PARAM(contest_finish_time, "t"),
  GLOBAL_PARAM(standings_charset, "S"),
  GLOBAL_PARAM(stand2_charset, "S"),
  GLOBAL_PARAM(plog_charset, "S"),

  GLOBAL_PARAM(root_dir, "S"),
  GLOBAL_PARAM(conf_dir, "S"),
  GLOBAL_PARAM(problems_dir, "S"),
  GLOBAL_PARAM(script_dir, "S"),
  GLOBAL_PARAM(test_dir, "S"),
  GLOBAL_PARAM(corr_dir, "S"),
  GLOBAL_PARAM(info_dir, "S"),
  GLOBAL_PARAM(tgz_dir, "S"),
  GLOBAL_PARAM(checker_dir, "S"),
  GLOBAL_PARAM(statement_dir, "S"),
  GLOBAL_PARAM(plugin_dir, "S"),
  GLOBAL_PARAM(test_sfx, "S"),
  GLOBAL_PARAM(corr_sfx, "S"),
  GLOBAL_PARAM(info_sfx, "S"),
  GLOBAL_PARAM(tgz_sfx, "S"),
  GLOBAL_PARAM(tgzdir_sfx, "S"),
  GLOBAL_PARAM(ejudge_checkers_dir, "S"),
  GLOBAL_PARAM(test_pat, "S"),
  GLOBAL_PARAM(corr_pat, "S"),
  GLOBAL_PARAM(info_pat, "S"),
  GLOBAL_PARAM(tgz_pat, "S"),
  GLOBAL_PARAM(tgzdir_pat, "S"),
  GLOBAL_PARAM(contest_start_cmd, "S"),
  GLOBAL_PARAM(contest_stop_cmd, "S"),
  GLOBAL_PARAM(description_file, "S"),
  GLOBAL_PARAM(contest_plugin_file, "S"),
  GLOBAL_PARAM(super_run_dir, "S"),
  GLOBAL_PARAM(virtual_end_options, "S"),

  GLOBAL_PARAM(clardb_plugin, "S"),
  GLOBAL_PARAM(rundb_plugin, "S"),
  GLOBAL_PARAM(xuser_plugin, "S"),

  GLOBAL_PARAM(var_dir, "S"),

  GLOBAL_PARAM(contest_id, "d"),
  GLOBAL_PARAM(socket_path, "S"),
  GLOBAL_PARAM(contests_dir, "S"),
  GLOBAL_PARAM(serve_socket, "S"),

  GLOBAL_PARAM(lang_config_dir, "S"),

  //GLOBAL_PARAM(log_file, "s"),
  GLOBAL_PARAM(run_log_file, "S"),
  GLOBAL_PARAM(clar_log_file, "S"),
  GLOBAL_PARAM(archive_dir, "S"),
  GLOBAL_PARAM(clar_archive_dir, "S"),
  GLOBAL_PARAM(run_archive_dir, "S"),
  GLOBAL_PARAM(report_archive_dir, "S"),
  GLOBAL_PARAM(team_report_archive_dir, "S"),
  GLOBAL_PARAM(team_extra_dir, "S"),

  GLOBAL_PARAM(status_dir, "S"),
  GLOBAL_PARAM(work_dir, "S"),
  GLOBAL_PARAM(print_work_dir, "S"),
  GLOBAL_PARAM(diff_work_dir, "S"),

  GLOBAL_PARAM(a2ps_path, "S"),
  GLOBAL_PARAM(a2ps_args, "x"),
  GLOBAL_PARAM(lpr_path, "S"),
  GLOBAL_PARAM(lpr_args, "x"),
  GLOBAL_PARAM(diff_path, "S"),

  GLOBAL_PARAM(compile_dir, "S"),
  GLOBAL_PARAM(compile_work_dir, "S"),
  GLOBAL_PARAM(extra_compile_dirs, "x"),

  GLOBAL_PARAM(run_dir, "S"),
  GLOBAL_PARAM(run_work_dir, "S"),
  GLOBAL_PARAM(run_check_dir, "S"),

  GLOBAL_PARAM_2(score_system, global_parse_score_system),
  GLOBAL_PARAM_2(rounding_mode, global_parse_rounding_mode),
  GLOBAL_PARAM(is_virtual, "d"),
  GLOBAL_ALIAS(virtual, is_virtual, "d"),

  GLOBAL_PARAM(htdocs_dir, "S"),

  GLOBAL_PARAM(team_info_url, "S"),
  GLOBAL_PARAM(prob_info_url, "S"),
  GLOBAL_PARAM(standings_file_name, "S"),
  GLOBAL_PARAM(stand_header_file, "S"),
  GLOBAL_PARAM(stand_footer_file, "S"),
  GLOBAL_PARAM(stand_symlink_dir, "S"),
  GLOBAL_PARAM(users_on_page, "d"),
  GLOBAL_PARAM(stand2_file_name, "S"),
  GLOBAL_PARAM(stand2_header_file, "S"),
  GLOBAL_PARAM(stand2_footer_file, "S"),
  GLOBAL_PARAM(stand2_symlink_dir, "S"),
  GLOBAL_PARAM(plog_file_name, "S"),
  GLOBAL_PARAM(plog_header_file, "S"),
  GLOBAL_PARAM(plog_footer_file, "S"),
  GLOBAL_PARAM(plog_update_time, "d"),
  GLOBAL_PARAM(plog_symlink_dir, "S"),

  GLOBAL_PARAM(external_xml_update_time, "d"),
  GLOBAL_PARAM(internal_xml_update_time, "d"),

  // standings table attributes
  GLOBAL_PARAM(stand_fancy_style, "d"),
  GLOBAL_PARAM(stand_extra_format, "S"),
  GLOBAL_PARAM(stand_extra_legend, "S"),
  GLOBAL_PARAM(stand_extra_attr, "S"),
  GLOBAL_PARAM(stand_table_attr, "S"),
  GLOBAL_PARAM(stand_place_attr, "S"),
  GLOBAL_PARAM(stand_team_attr, "S"),
  GLOBAL_PARAM(stand_prob_attr, "S"),
  GLOBAL_PARAM(stand_solved_attr, "S"),
  GLOBAL_PARAM(stand_score_attr, "S"),
  GLOBAL_PARAM(stand_penalty_attr, "S"),
  GLOBAL_PARAM(stand_time_attr, "S"),
  GLOBAL_PARAM(stand_self_row_attr, "S"),
  GLOBAL_PARAM(stand_v_row_attr, "S"),
  GLOBAL_PARAM(stand_r_row_attr, "S"),
  GLOBAL_PARAM(stand_u_row_attr, "S"),
  GLOBAL_PARAM(stand_success_attr, "S"),
  GLOBAL_PARAM(stand_fail_attr, "S"),
  GLOBAL_PARAM(stand_trans_attr, "S"),
  GLOBAL_PARAM(stand_disq_attr, "S"),
  GLOBAL_PARAM(stand_use_login, "d"),
  GLOBAL_PARAM(stand_show_avatar, "d"),
  GLOBAL_PARAM(stand_show_first_solver, "d"),
  GLOBAL_PARAM(stand_show_ok_time, "d"),
  GLOBAL_PARAM(stand_show_att_num, "d"),
  GLOBAL_PARAM(stand_sort_by_solved, "d"),
  GLOBAL_PARAM(stand_collate_name, "d"),
  GLOBAL_PARAM(stand_enable_penalty, "d"),
  GLOBAL_PARAM(stand_row_attr, "x"),
  GLOBAL_PARAM(stand_page_table_attr, "S"),
  GLOBAL_PARAM(stand_page_row_attr, "x"),
  GLOBAL_PARAM(stand_page_col_attr, "x"),
  GLOBAL_PARAM(stand_page_cur_attr, "S"),

  // just for fun
  GLOBAL_PARAM(extended_sound, "d"),
  GLOBAL_PARAM(disable_sound, "d"),
  GLOBAL_PARAM(sound_player, "S"),
  GLOBAL_PARAM(accept_sound, "S"),
  GLOBAL_PARAM(runtime_sound, "S"),
  GLOBAL_PARAM(timelimit_sound, "S"),
  GLOBAL_PARAM(wrong_sound, "S"),
  GLOBAL_PARAM(presentation_sound, "S"),
  GLOBAL_PARAM(internal_sound, "S"),
  GLOBAL_PARAM(start_sound, "s"),

  GLOBAL_PARAM(enable_l10n, "d"),
  GLOBAL_PARAM(l10n_dir, "S"),
  GLOBAL_PARAM(standings_locale, "S"),
  GLOBAL_PARAM(checker_locale, "S"),

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
  GLOBAL_PARAM(show_sha1, "d"),
  GLOBAL_PARAM(show_judge_identity, "d"),
  GLOBAL_PARAM(enable_runlog_merge, "d"),
  GLOBAL_PARAM(prune_empty_users, "d"),
  GLOBAL_PARAM(enable_report_upload, "d"),
  GLOBAL_PARAM(ignore_success_time, "d"),
  GLOBAL_PARAM(separate_user_score, "d"),

  GLOBAL_PARAM(use_gzip, "d"),
  GLOBAL_PARAM(min_gzip_size, "d"),
  GLOBAL_PARAM(use_dir_hierarchy, "d"),
  GLOBAL_PARAM(html_report, "d"),
  GLOBAL_PARAM(xml_report, "d"),
  GLOBAL_PARAM(enable_full_archive, "d"),
  GLOBAL_PARAM(cpu_bogomips, "d"),
  GLOBAL_PARAM(skip_full_testing, "d"),
  GLOBAL_PARAM(skip_accept_testing, "d"),

  GLOBAL_PARAM(variant_map_file, "S"),

  GLOBAL_PARAM(enable_printing, "d"),
  GLOBAL_PARAM(disable_banner_page, "d"),
  GLOBAL_PARAM(printout_uses_login, "d"),
  GLOBAL_PARAM(team_page_quota, "d"),

  GLOBAL_PARAM(priority_adjustment, "d"),
  GLOBAL_PARAM(user_priority_adjustments, "x"),

  GLOBAL_PARAM(contestant_status_num, "d"),
  GLOBAL_PARAM(contestant_status_legend, "x"),
  GLOBAL_PARAM(contestant_status_row_attr, "x"),
  GLOBAL_PARAM(stand_show_contestant_status, "d"),
  GLOBAL_PARAM(stand_show_warn_number, "d"),
  GLOBAL_PARAM(stand_contestant_status_attr, "S"),
  GLOBAL_PARAM(stand_warn_number_attr, "S"),

  GLOBAL_PARAM(user_exam_protocol_header_file, "S"),
  GLOBAL_PARAM(user_exam_protocol_footer_file, "S"),
  GLOBAL_PARAM(prob_exam_protocol_header_file, "S"),
  GLOBAL_PARAM(prob_exam_protocol_footer_file, "S"),
  GLOBAL_PARAM(full_exam_protocol_header_file, "S"),
  GLOBAL_PARAM(full_exam_protocol_footer_file, "S"),

  GLOBAL_PARAM(load_user_group, "x"),

  GLOBAL_PARAM(tokens, "S"),
  GLOBAL_PARAM(dates_config_file, "S"),

  GLOBAL_PARAM(compile_max_vm_size, "E"),
  GLOBAL_PARAM(compile_max_stack_size, "E"),
  GLOBAL_PARAM(compile_max_file_size, "E"),

  { 0, 0, 0, 0 }
};

#define PROBLEM_OFFSET(x)   XOFFSET(struct section_problem_data, x)
#define PROBLEM_SIZE(x)     XFSIZE(struct section_problem_data, x)
#define PROBLEM_PARAM(x, t) { #x, t, PROBLEM_OFFSET(x), PROBLEM_SIZE(x) }
#define PROBLEM_PARAM_2(x, f) { #x, "f", PROBLEM_OFFSET(x), PROBLEM_SIZE(x), f}
#define PROBLEM_ALIAS(a, x, t) { #a, t, PROBLEM_OFFSET(x), PROBLEM_SIZE(x) }
static const struct config_parse_info section_problem_params[] =
{
  PROBLEM_PARAM(id, "d"),
  PROBLEM_PARAM(tester_id, "d"),
  PROBLEM_PARAM(abstract, "L"),
  PROBLEM_PARAM(scoring_checker, "L"),
  PROBLEM_PARAM(enable_checker_token, "L"),
  PROBLEM_PARAM(interactive_valuer, "L"),
  PROBLEM_PARAM(disable_pe, "L"),
  PROBLEM_PARAM(disable_wtl, "L"),
  PROBLEM_PARAM(wtl_is_cf, "L"),
  PROBLEM_PARAM(manual_checking, "L"),
  PROBLEM_PARAM(examinator_num, "d"),
  PROBLEM_PARAM(check_presentation, "L"),
  PROBLEM_PARAM(use_stdin, "L"),
  PROBLEM_PARAM(use_stdout, "L"),
  PROBLEM_PARAM(combined_stdin, "L"),
  PROBLEM_PARAM(combined_stdout, "L"),
  PROBLEM_PARAM(binary_input, "L"),
  PROBLEM_PARAM(binary, "L"),
  PROBLEM_PARAM(ignore_exit_code, "L"),
  PROBLEM_PARAM(olympiad_mode, "L"),
  PROBLEM_PARAM(score_latest, "L"),
  PROBLEM_PARAM(score_latest_or_unmarked, "L"),
  PROBLEM_PARAM(score_latest_marked, "L"),
  PROBLEM_PARAM(score_tokenized, "L"),
  PROBLEM_PARAM(time_limit, "d"),
  PROBLEM_PARAM(time_limit_millis, "d"),
  PROBLEM_PARAM(real_time_limit, "d"),
  PROBLEM_PARAM(use_ac_not_ok, "L"),
  PROBLEM_PARAM(ignore_prev_ac, "L"),
  PROBLEM_PARAM(team_enable_rep_view, "L"),
  PROBLEM_PARAM(team_enable_ce_view, "L"),
  PROBLEM_PARAM(team_show_judge_report, "L"),
  PROBLEM_PARAM(show_checker_comment, "L"),
  PROBLEM_PARAM(ignore_compile_errors, "L"),
  PROBLEM_PARAM(full_score, "d"),
  PROBLEM_PARAM(full_user_score, "d"),
  PROBLEM_PARAM(min_score_1, "d"),
  PROBLEM_PARAM(min_score_2, "d"),
  PROBLEM_PARAM(test_score, "d"),
  PROBLEM_PARAM(run_penalty, "d"),
  PROBLEM_PARAM(acm_run_penalty, "d"),
  PROBLEM_PARAM(disqualified_penalty, "d"),
  PROBLEM_PARAM(ignore_penalty, "L"),
  PROBLEM_PARAM(compile_error_penalty, "d"),
  PROBLEM_PARAM(use_corr, "L"),
  PROBLEM_PARAM(use_info, "L"),
  PROBLEM_PARAM(use_tgz, "L"),
  PROBLEM_PARAM(tests_to_accept, "d"),
  PROBLEM_PARAM(accept_partial, "L"),
  PROBLEM_PARAM(min_tests_to_accept, "d"),
  PROBLEM_PARAM(checker_real_time_limit, "d"),
  PROBLEM_PARAM(disable_auto_testing, "L"),
  PROBLEM_PARAM(disable_testing, "L"),
  PROBLEM_PARAM(disable_user_submit, "L"),
  PROBLEM_PARAM(disable_tab, "L"),
  PROBLEM_PARAM(unrestricted_statement, "L"),
  PROBLEM_PARAM(enable_submit_after_reject, "L"),
  PROBLEM_PARAM(restricted_statement, "L"),
  PROBLEM_PARAM(hide_file_names, "L"),
  PROBLEM_PARAM(hide_real_time_limit, "L"),
  PROBLEM_PARAM(enable_tokens, "L"),
  PROBLEM_PARAM(tokens_for_user_ac, "L"),
  PROBLEM_PARAM(disable_submit_after_ok, "L"),
  PROBLEM_PARAM(disable_security, "L"),
  PROBLEM_PARAM(enable_suid_run, "L"),
  PROBLEM_PARAM(enable_multi_header, "L"),
  PROBLEM_PARAM(use_lang_multi_header, "L"),
  PROBLEM_PARAM(require_any, "L"),
  PROBLEM_PARAM(enable_compilation, "L"),
  PROBLEM_PARAM(skip_testing, "L"),
  PROBLEM_PARAM(variable_full_score, "L"),
  PROBLEM_PARAM(hidden, "L"),
  PROBLEM_PARAM(notify_on_submit, "L"),
  PROBLEM_PARAM(priority_adjustment, "d"),
  PROBLEM_PARAM(spelling, "S"),
  PROBLEM_PARAM(stand_hide_time, "L"),
  PROBLEM_PARAM(advance_to_next, "L"),
  PROBLEM_PARAM(disable_ctrl_chars, "L"),
  PROBLEM_PARAM(valuer_sets_marked, "L"),
  PROBLEM_PARAM(ignore_unmarked, "L"),
  PROBLEM_PARAM(disable_stderr, "L"),
  PROBLEM_PARAM(enable_process_group, "L"),
  PROBLEM_PARAM(enable_testlib_mode, "L"),
  PROBLEM_PARAM(hide_variant, "L"),
  PROBLEM_PARAM(autoassign_variants, "L"),
  PROBLEM_PARAM(enable_text_form, "L"),
  PROBLEM_PARAM(stand_ignore_score, "L"),
  PROBLEM_PARAM(stand_last_column, "L"),
  PROBLEM_PARAM(score_multiplier, "d"),
  PROBLEM_PARAM(prev_runs_to_show, "d"),
  PROBLEM_PARAM(max_user_run_count, "d"),
  PROBLEM_ALIAS(output_only, type, "d"),
  PROBLEM_PARAM(max_vm_size, "E"),
  PROBLEM_PARAM(max_stack_size, "E"),
  PROBLEM_PARAM(max_data_size, "E"),
  PROBLEM_PARAM(max_core_size, "E"),
  PROBLEM_PARAM(max_file_size, "E"),
  PROBLEM_PARAM(max_open_file_count, "d"),
  PROBLEM_PARAM(max_process_count, "d"),
  PROBLEM_PARAM_2(type, do_problem_parse_type),
  PROBLEM_PARAM(interactor_time_limit, "d"),
  PROBLEM_PARAM(interactor_real_time_limit, "d"),

  PROBLEM_PARAM(super, "s"),
  PROBLEM_PARAM(short_name, "s"),
  PROBLEM_PARAM(long_name, "S"),
  PROBLEM_PARAM(group_name, "S"),
  PROBLEM_PARAM(stand_name, "S"),
  PROBLEM_PARAM(stand_column, "S"),
  PROBLEM_PARAM(internal_name, "S"),
  PROBLEM_PARAM(problem_dir, "S"),
  PROBLEM_PARAM(test_dir, "S"),
  PROBLEM_PARAM(test_sfx, "S"),
  PROBLEM_PARAM(corr_dir, "S"),
  PROBLEM_PARAM(corr_sfx, "S"),
  PROBLEM_PARAM(info_dir, "S"),
  PROBLEM_PARAM(info_sfx, "S"),
  PROBLEM_PARAM(tgz_dir, "S"),
  PROBLEM_PARAM(tgz_sfx, "S"),
  PROBLEM_PARAM(tgzdir_sfx, "S"),
  PROBLEM_PARAM(input_file, "S"),
  PROBLEM_PARAM(output_file, "S"),
  PROBLEM_PARAM(test_score_list, "S"),
  PROBLEM_PARAM(score_tests, "S"),
  PROBLEM_PARAM(test_sets, "x"),
  PROBLEM_PARAM(deadline, "t"),
  PROBLEM_PARAM(start_date, "t"),
  PROBLEM_PARAM(variant_num, "d"),
  PROBLEM_PARAM(date_penalty, "x"),
  PROBLEM_PARAM(group_start_date, "x"),
  PROBLEM_PARAM(group_deadline, "x"),
  PROBLEM_PARAM(disable_language, "x"),
  PROBLEM_PARAM(enable_language, "x"),
  PROBLEM_PARAM(require, "x"),
  PROBLEM_PARAM(provide_ok, "x"),
  PROBLEM_PARAM(standard_checker, "S"),
  PROBLEM_PARAM(lang_compiler_env, "x"),
  PROBLEM_PARAM(checker_env, "x"),
  PROBLEM_PARAM(valuer_env, "x"),
  PROBLEM_PARAM(interactor_env, "x"),
  PROBLEM_PARAM(style_checker_env, "x"),
  PROBLEM_PARAM(test_checker_env, "x"),
  PROBLEM_PARAM(init_env, "x"),
  PROBLEM_PARAM(start_env, "x"),
  PROBLEM_PARAM(lang_time_adj, "x"),
  PROBLEM_PARAM(lang_time_adj_millis, "x"),
  PROBLEM_PARAM(lang_max_vm_size, "x"),
  PROBLEM_PARAM(lang_max_stack_size, "x"),
  PROBLEM_PARAM(check_cmd, "S"),
  PROBLEM_PARAM(valuer_cmd, "S"),
  PROBLEM_PARAM(interactor_cmd, "S"),
  PROBLEM_PARAM(style_checker_cmd, "S"),
  PROBLEM_PARAM(test_checker_cmd, "S"),
  PROBLEM_PARAM(init_cmd, "S"),
  PROBLEM_PARAM(start_cmd, "S"),
  PROBLEM_PARAM(solution_src, "S"),
  PROBLEM_PARAM(solution_cmd, "S"),
  PROBLEM_PARAM(test_pat, "S"),
  PROBLEM_PARAM(corr_pat, "S"),
  PROBLEM_PARAM(info_pat, "S"),
  PROBLEM_PARAM(tgz_pat, "S"),
  PROBLEM_PARAM(tgzdir_pat, "S"),
  PROBLEM_PARAM(personal_deadline, "x"),
  PROBLEM_PARAM(score_bonus, "S"),
  PROBLEM_PARAM(open_tests, "S"),
  PROBLEM_PARAM(final_open_tests, "S"),
  PROBLEM_PARAM(token_open_tests, "S"),
  PROBLEM_PARAM(statement_file, "S"),
  PROBLEM_PARAM(alternatives_file, "S"),
  PROBLEM_PARAM(plugin_file, "S"),
  PROBLEM_PARAM(xml_file, "S"),
  PROBLEM_PARAM(alternative, "x"),
  PROBLEM_PARAM(stand_attr, "S"),
  PROBLEM_PARAM(source_header, "S"),
  PROBLEM_PARAM(source_footer, "S"),
  PROBLEM_PARAM(score_view, "x"),
  PROBLEM_PARAM(extid, "S"),
  PROBLEM_PARAM(normalization, "S"),
  PROBLEM_PARAM(super_run_dir, "S"),
  PROBLEM_PARAM(tokens, "S"),
  PROBLEM_PARAM(umask, "S"),
  PROBLEM_PARAM(ok_status, "S"),
  PROBLEM_PARAM(header_pat, "S"),
  PROBLEM_PARAM(footer_pat, "S"),
  PROBLEM_PARAM(compiler_env_pat, "S"),
  PROBLEM_PARAM(statement_env, "x"),

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
  LANGUAGE_PARAM(insecure, "d"),
  LANGUAGE_PARAM(disable_security, "d"),
  LANGUAGE_PARAM(enable_suid_run, "d"),
  LANGUAGE_PARAM(is_dos, "d"),
  LANGUAGE_PARAM(short_name, "s"),
  LANGUAGE_PARAM(long_name, "S"),
  LANGUAGE_PARAM(key, "S"),
  LANGUAGE_PARAM(arch, "S"),
  LANGUAGE_PARAM(src_sfx, "s"),
  LANGUAGE_PARAM(exe_sfx, "s"),
  LANGUAGE_PARAM(cmd, "S"),
  LANGUAGE_PARAM(content_type, "S"),
  LANGUAGE_PARAM(style_checker_cmd, "S"),
  LANGUAGE_PARAM(style_checker_env, "x"),

  LANGUAGE_PARAM(disable_auto_testing, "d"),
  LANGUAGE_PARAM(disable_testing, "d"),
  LANGUAGE_PARAM(max_vm_size, "E"),
  LANGUAGE_PARAM(max_stack_size, "E"),
  LANGUAGE_PARAM(max_file_size, "E"),
  LANGUAGE_PARAM(run_max_stack_size, "E"),

  LANGUAGE_PARAM(compile_dir, "S"),
  LANGUAGE_PARAM(compile_dir_index, "d"),
  LANGUAGE_PARAM(compile_real_time_limit, "d"),
  LANGUAGE_PARAM(compiler_env, "x"),
  LANGUAGE_PARAM(extid, "S"),
  LANGUAGE_PARAM(super_run_dir, "S"),

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
  TESTER_PARAM(ignore_stderr, "d"),
  TESTER_PARAM(is_dos, "d"),
  TESTER_PARAM(skip_testing, "d"),
  TESTER_PARAM(arch, "s"),
  TESTER_PARAM(key, "S"),
  TESTER_PARAM(any, "d"),
  TESTER_PARAM(priority_adjustment, "d"),
  TESTER_PARAM(memory_limit_type, "S"),
  TESTER_PARAM(secure_exec_type, "S"),

  TESTER_PARAM(abstract, "d"),
  TESTER_PARAM(super, "x"),

  TESTER_PARAM(no_core_dump, "d"),
  TESTER_PARAM(enable_memory_limit_error, "d"),
  TESTER_PARAM(kill_signal, "S"),
  TESTER_PARAM(max_stack_size, "z"),
  TESTER_PARAM(max_data_size, "z"),
  TESTER_PARAM(max_vm_size, "z"),
  TESTER_PARAM(clear_env, "d"),
  TESTER_PARAM(time_limit_adjustment, "d"),
  TESTER_PARAM(time_limit_adj_millis, "d"),

  TESTER_PARAM(run_dir, "S"),
  TESTER_PARAM(check_dir, "S"),
  TESTER_PARAM(errorcode_file, "S"),
  TESTER_PARAM(error_file, "S"),

  TESTER_PARAM(prepare_cmd, "S"),
  TESTER_PARAM(start_cmd, "S"),
  TESTER_PARAM(nwrun_spool_dir, "S"),

  TESTER_PARAM(start_env, "x"),

  { 0, 0, 0, 0 }
};

void prepare_problem_init_func(struct generic_section_config *);
static void tester_init_func(struct generic_section_config *);
static void global_init_func(struct generic_section_config *);
static void language_init_func(struct generic_section_config *);

static void prepare_global_free_func(struct generic_section_config *g);
static void prepare_language_free_func(struct generic_section_config *g);
static void prepare_problem_free_func(struct generic_section_config *g);
static void prepare_tester_free_func(struct generic_section_config *g);

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

static int
do_problem_parse_type(
        const unsigned char *str,
        void *ptr,
        size_t size)
{
  int val = problem_parse_type(str);
  if (val < 0 || val >= PROB_TYPE_LAST) return -1;
  *(int*) ptr = val;
  return 0;
}

static int
global_parse_score_system(
        const unsigned char *str,
        void *ptr,
        size_t size)
{
  int val = -1;

  if (!str || !str[0]) {
    val = SCORE_ACM;
  } else if (!strcasecmp(str, "acm")) {
    val = SCORE_ACM;
  } else if (!strcasecmp(str, "kirov")) {
    val = SCORE_KIROV;
  } else if (!strcasecmp(str, "olympiad")) {
    val = SCORE_OLYMPIAD;
  } else if (!strcasecmp(str, "moscow")) {
    val = SCORE_MOSCOW;
  } else {
    return -1;
  }

  *(int*) ptr = val;
  return 0;
}

int
prepare_parse_score_system(const unsigned char *str)
{
  if (!str || !str[0]) {
    return SCORE_ACM;
  } else if (!strcasecmp(str, "acm")) {
    return SCORE_ACM;
  } else if (!strcasecmp(str, "kirov")) {
    return SCORE_KIROV;
  } else if (!strcasecmp(str, "olympiad")) {
    return SCORE_OLYMPIAD;
  } else if (!strcasecmp(str, "moscow")) {
    return SCORE_MOSCOW;
  } else {
    return -1;
  }
}

static int
global_parse_rounding_mode(
        const unsigned char *str,
        void *ptr,
        size_t size)
{
  int val = -1;

  if (!str || !str[0]) {
    val = SEC_CEIL;
  } else if (!strcmp(str, "ceil")) {
    val = SEC_CEIL;
  } else if (!strcmp(str, "floor")) {
    val = SEC_FLOOR;
  } else if (!strcmp(str, "round")) {
    val = SEC_ROUND;
  } else {
    return -1;
  }

  *(int*) ptr = val;
  return 0;
}

static int verbose_info_flag = 0;
static void
vinfo(const char *format, ...)
  __attribute__((format(printf, 1, 2)));
static void
vinfo(const char *format, ...)
{
  if (!verbose_info_flag) return;

  {
    char buf[1024];
    va_list args;

    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);

    info("%s", buf);
  }
}

int
usprintf(unsigned char **pbuf, const char *format, ...)
{
  va_list args;
  char **psbuf = (char**) pbuf;
  unsigned char *saved = *pbuf;

  *pbuf = NULL;
  va_start(args, format);
  int ret = vasprintf(psbuf, format, args);
  va_end(args);
  xfree(saved);
  return ret;
}

int
find_tester(const serve_state_t state,int problem, char const *arch)
{
  int i;
  struct section_tester_data *tst;

  if (!arch) {
    for (i = 1; i <= state->max_tester; ++i) {
      if ((tst = state->testers[i]) && tst->any <= 0
          && problem == tst->problem)
        return i;
    }

    for (i = 1; i <= state->max_tester; ++i) {
      if ((tst = state->testers[i]) && tst->any)
        return i;
    }

    return 0;
  }

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
  p->enable_eoln_select = -1;
  p->start_on_first_login = -1;
  p->enable_virtual_restart = -1;
  p->ignore_compile_errors = -1;
  p->disable_failed_test_view = -1;
  p->enable_printing = -1;
  p->disable_banner_page = -1;
  p->printout_uses_login = -1;
  p->prune_empty_users = -1;
  p->enable_full_archive = -1;
  p->show_problems_link_before_start = -1;
  p->show_problems_link_after_finish = -1;
  p->disable_user_standings = -1;
  p->disable_language = -1;
  p->problem_navigation = -1;
  p->vertical_navigation = -1;
  p->disable_virtual_start = -1;
  p->disable_virtual_auto_judge = -1;
  p->enable_auto_print_protocol = -1;
  p->stand_fancy_style = -1;
  p->stand_use_login = -1;
  p->stand_show_avatar = -1;
  p->stand_show_first_solver = -1;
  p->stand_show_ok_time = -1;
  p->stand_show_warn_number = -1;
  p->disable_auto_testing = -1;
  p->disable_testing = -1;
  p->show_astr_time = -1;
  p->enable_report_upload = -1;
  p->enable_runlog_merge = -1;
  p->secure_run = -1;
  p->detect_violations = -1;
  p->enable_memory_limit_error = -1;
  p->ignore_success_time = -1;

  p->autoupdate_standings = -1;
  p->use_ac_not_ok = -1;
  p->board_fog_time = -1;
  p->board_unfog_time = -1;
  p->contest_time = -1;
  p->tests_to_accept = -1;
  p->team_download_time = -1;
  p->ignore_duplicated_runs = -1;
  p->show_deadline = -1;
  p->show_sha1 = -1;
  p->show_judge_identity = -1;
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
  p->advanced_layout = -1;
  p->uuid_run_store = -1;
  p->enable_32bit_checkers = -1;
  p->ignore_bom = -1;
  p->disable_auto_refresh = -1;
  p->disable_user_database = -1;
  p->enable_max_stack_size = -1;

  p->compile_max_vm_size = ~(ej_size64_t) 0;
  p->compile_max_stack_size = ~(ej_size64_t) 0;
  p->compile_max_file_size = ~(ej_size64_t) 0;

  p->enable_tokens = -1;
}

static void free_user_adjustment_info(struct user_adjustment_info*);
static void free_user_adjustment_map(struct user_adjustment_map*);

static struct virtual_end_info_s *
parse_virtual_end_info(const unsigned char *str)
{
  struct virtual_end_info_s *info;
  const unsigned char *p = str;
  XCALLOC(info, 1);
  info->source_mode = -1;
  info->report_mode = -1;
  info->visibility_mode = -1;
  info->score_mode = -1;
  info->checker_comment_mode = -1;
  while (1) {
    while (isspace(*p)) ++p;
    if (!*p) break;
    if (*p == '=' || *p == ',') goto fail;
    const unsigned char *q = p;
    while (*q && *q != '=' && *q != ',' && !isspace(*q)) ++q;
    const unsigned char *p1 = q;
    while (isspace(*p1)) ++p1;
    if (!*p1 || *p1 == ',') {
    } else if (*p1 != '=') {
      goto fail;
    }
    ++p1;
    while (isspace(*p1)) ++p1;
    const unsigned char *q1 = p1;
    while (*q1 && *q1 != '=' && *q1 != ',' && !isspace(*q1)) ++q1;
    // [p;q) = [p1;q1)
    if (q1 != p1) {
      int name_len = q - p;
      unsigned char *name = alloca(name_len + 1);
      memcpy(name, p, name_len);
      name[name_len] = 0;
      int value_len = q1 - p1;
      unsigned char *value = alloca(value_len + 1);
      memcpy(value, p1, value_len);
      value[value_len] = 0;
      if (!strcmp(name, "source")) {
        if (!strcmp(value, "yes")) {
          info->source_mode = 1;
        } else if (!strcmp(value, "no")) {
          info->source_mode = 0;
        } else if (!strcmp(value, "default")) {
          info->source_mode = -1;
        } else {
          goto fail;
        }
      } else if (!strcmp(name, "report")) {
        if (!strcmp(value, "yes")) {
          info->report_mode = 1;
        } else if (!strcmp(value, "no")) {
          info->report_mode = 0;
        } else if (!strcmp(value, "default")) {
          info->report_mode = -1;
        } else {
          goto fail;
        }
      } else if (!strcmp(name, "visibility")) {
        if (!strcmp(value, "token")) {
          info->visibility_mode = 1;
        } else if (!strcmp(value, "final")) {
          info->visibility_mode = 2;
        } else if (!strcmp(value, "default")) {
          info->visibility_mode = -1;
        } else {
          goto fail;
        }
      } else if (!strcmp(name, "score")) {
        if (!strcmp(value, "final")) {
          info->score_mode = 1;
        } else if (!strcmp(value, "user")) {
          info->score_mode = 0;
        } else if (!strcmp(value, "default")) {
          info->score_mode = -1;
        } else {
          goto fail;
        }
      } else if (!strcmp(name, "checker_comment")) {
        if (!strcmp(value, "show")) {
          info->checker_comment_mode = 1;
        } else {
          goto fail;
        }
      } else {
        goto fail;
      }
      //printf("<%s>,<%s>\n", name, value);
    } else {
      goto fail;
    }
    p = q1;
    while (isspace(*p)) ++p;
    if (!*p) break;
    if (*p != ',') goto fail;
    ++p;
  }
  return info;
fail:
  xfree(info);
  return NULL;
}

static struct virtual_end_info_s *
free_virtual_end_info(struct virtual_end_info_s *info)
{
  if (info) {
    xfree(info);
  }
  return NULL;
}

void
prepare_global_free_func(struct generic_section_config *gp)
{
  struct section_global_data *p = (struct section_global_data *) gp;

  sarray_free(p->a2ps_args);
  sarray_free(p->lpr_args);
  sarray_free(p->extra_compile_dirs);
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
  variant_map_free(p->variant_map);
  free_user_adjustment_info(p->user_adjustment_info);
  free_user_adjustment_map(p->user_adjustment_map);
  xfree(p->unhandled_vars);
  xfree(p->user_exam_protocol_header_txt);
  xfree(p->user_exam_protocol_footer_txt);
  xfree(p->prob_exam_protocol_header_txt);
  xfree(p->prob_exam_protocol_footer_txt);
  xfree(p->full_exam_protocol_header_txt);
  xfree(p->full_exam_protocol_footer_txt);
  xfree(p->contest_stop_cmd);
  xfree(p->virtual_end_options);
  free_virtual_end_info(p->virtual_end_info);
  sarray_free(p->load_user_group);
  xfree(p->super_run_dir);
  xfree(p->tokens);
  xfree(p->token_info);
  xfree(p->dates_config_file);
  dates_config_free(p->dates_config);
  xfree(p->checker_locale);
  xfree(p->test_dir);
  xfree(p->test_sfx);
  xfree(p->test_pat);
  xfree(p->corr_dir);
  xfree(p->corr_sfx);
  xfree(p->corr_pat);
  xfree(p->info_dir);
  xfree(p->info_sfx);
  xfree(p->info_pat);
  xfree(p->tgz_dir);
  xfree(p->tgz_sfx);
  xfree(p->tgz_pat);
  xfree(p->tgzdir_sfx);
  xfree(p->tgzdir_pat);
  xfree(p->sound_player);
  xfree(p->accept_sound);
  xfree(p->runtime_sound);
  xfree(p->timelimit_sound);
  xfree(p->presentation_sound);
  xfree(p->wrong_sound);
  xfree(p->internal_sound);
  xfree(p->start_sound);
  xfree(p->variant_map_file);
  xfree(p->user_exam_protocol_header_file);
  xfree(p->user_exam_protocol_footer_file);
  xfree(p->prob_exam_protocol_header_file);
  xfree(p->prob_exam_protocol_footer_file);
  xfree(p->full_exam_protocol_header_file);
  xfree(p->full_exam_protocol_footer_file);
  xfree(p->stand2_file_name);
  xfree(p->stand2_header_file);
  xfree(p->stand2_footer_file);
  xfree(p->stand2_symlink_dir);
  xfree(p->plog_file_name);
  xfree(p->plog_header_file);
  xfree(p->plog_footer_file);
  xfree(p->plog_symlink_dir);
  xfree(p->team_info_url);
  xfree(p->prob_info_url);
  xfree(p->standings_file_name);
  xfree(p->stand_header_file);
  xfree(p->stand_footer_file);
  xfree(p->stand_symlink_dir);
  xfree(p->stand_file_name_2);
  xfree(p->htdocs_dir);
  xfree(p->stand_extra_format);
  xfree(p->stand_extra_legend);
  xfree(p->stand_extra_attr);
  xfree(p->stand_table_attr);
  xfree(p->stand_place_attr);
  xfree(p->stand_team_attr);
  xfree(p->stand_prob_attr);
  xfree(p->stand_solved_attr);
  xfree(p->stand_score_attr);
  xfree(p->stand_penalty_attr);
  xfree(p->stand_time_attr);
  xfree(p->stand_self_row_attr);
  xfree(p->stand_r_row_attr);
  xfree(p->stand_v_row_attr);
  xfree(p->stand_u_row_attr);
  xfree(p->stand_success_attr);
  xfree(p->stand_fail_attr);
  xfree(p->stand_trans_attr);
  xfree(p->stand_disq_attr);
  xfree(p->stand_page_table_attr);
  xfree(p->stand_page_cur_attr);
  xfree(p->stand_contestant_status_attr);
  xfree(p->stand_warn_number_attr);
  xfree(p->run_dir);
  xfree(p->run_queue_dir);
  xfree(p->run_exe_dir);
  xfree(p->run_out_dir);
  xfree(p->run_status_dir);
  xfree(p->run_report_dir);
  xfree(p->run_team_report_dir);
  xfree(p->run_full_archive_dir);
  xfree(p->run_work_dir);
  xfree(p->run_check_dir);
  xfree(p->compile_dir);
  xfree(p->compile_queue_dir);
  xfree(p->compile_src_dir);
  xfree(p->compile_out_dir);
  xfree(p->compile_status_dir);
  xfree(p->compile_report_dir);
  xfree(p->compile_work_dir);
  xfree(p->status_dir);
  xfree(p->work_dir);
  xfree(p->print_work_dir);
  xfree(p->diff_work_dir);
  xfree(p->a2ps_path);
  xfree(p->lpr_path);
  xfree(p->diff_path);
  xfree(p->run_log_file);
  xfree(p->clar_log_file);
  xfree(p->archive_dir);
  xfree(p->clar_archive_dir);
  xfree(p->run_archive_dir);
  xfree(p->report_archive_dir);
  xfree(p->team_report_archive_dir);
  xfree(p->xml_report_archive_dir);
  xfree(p->full_archive_dir);
  xfree(p->audit_log_dir);
  xfree(p->uuid_archive_dir);
  xfree(p->team_extra_dir);
  xfree(p->var_dir);
  xfree(p->serve_socket);
  xfree(p->l10n_dir);
  xfree(p->socket_path);
  xfree(p->lang_config_dir);
  xfree(p->problems_dir);
  xfree(p->script_dir);
  xfree(p->checker_dir);
  xfree(p->statement_dir);
  xfree(p->plugin_dir);
  xfree(p->ejudge_checkers_dir);
  xfree(p->contest_start_cmd);
  xfree(p->description_file);
  xfree(p->contest_plugin_file);
  xfree(p->conf_dir);
  xfree(p->contests_dir);
  xfree(p->root_dir);
  xfree(p->name);
  xfree(p->standings_locale);
  xfree(p->charset);
  xfree(p->standings_charset);
  xfree(p->stand2_charset);
  xfree(p->plog_charset);
  xfree(p->clardb_plugin);
  xfree(p->rundb_plugin);
  xfree(p->xuser_plugin);

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
  p->style_checker_env = sarray_free(p->style_checker_env);
  xfree(p->unhandled_vars);
  xfree(p->extid);
  xfree(p->super_run_dir);
  xfree(p->cmd);
  xfree(p->style_checker_cmd);
  xfree(p->compile_dir);
  xfree(p->compile_queue_dir);
  xfree(p->compile_src_dir);
  xfree(p->compile_out_dir);
  xfree(p->compile_status_dir);
  xfree(p->compile_report_dir);
  xfree(p->content_type);
  xfree(p->long_name);
  xfree(p->key);
  xfree(p->arch);
  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

void
prepare_problem_init_func(struct generic_section_config *gp)
{
  struct section_problem_data *p = (struct section_problem_data*) gp;

  p->type = -1;
  p->scoring_checker = -1;
  p->enable_checker_token = -1;
  p->interactive_valuer = -1;
  p->disable_pe = -1;
  p->disable_wtl = -1;
  p->wtl_is_cf = -1;
  p->manual_checking = -1;
  p->check_presentation = -1;
  p->use_stdin = -1;
  p->use_stdout = -1;
  p->combined_stdin = -1;
  p->combined_stdout = -1;
  p->binary_input = -1;
  p->binary = -1;
  p->ignore_exit_code = -1;
  p->olympiad_mode = -1;
  p->score_latest = -1;
  p->score_latest_or_unmarked = -1;
  p->score_latest_marked = -1;
  p->score_tokenized = -1;
  p->time_limit = -1;
  p->time_limit_millis = -1;
  p->real_time_limit = -1;
  p->use_ac_not_ok = -1;
  p->ignore_prev_ac = -1;
  p->team_enable_rep_view = -1;
  p->team_enable_ce_view = -1;
  p->team_show_judge_report = -1;
  p->show_checker_comment = -1;
  p->ignore_compile_errors = -1;
  p->use_corr = -1;
  p->use_info = -1;
  p->use_tgz = -1;
  p->tests_to_accept = -1;
  p->accept_partial = -1;
  p->min_tests_to_accept = -1;
  p->run_penalty = -1;
  p->acm_run_penalty = -1;
  p->disqualified_penalty = -1;
  p->compile_error_penalty = -1;
  p->checker_real_time_limit = -1;
  p->variant_num = -1;
  p->disable_auto_testing = -1;
  p->disable_testing = -1;
  p->disable_user_submit = -1;
  p->notify_on_submit = -1;
  p->disable_tab = -1;
  p->unrestricted_statement = -1;
  p->enable_submit_after_reject = -1;
  p->hide_file_names = -1;
  p->hide_real_time_limit = -1;
  p->enable_tokens = -1;
  p->tokens_for_user_ac = -1;
  p->disable_submit_after_ok = -1;
  p->disable_security = -1;
  p->enable_suid_run = -1;
  p->enable_multi_header = -1;
  p->use_lang_multi_header = -1;
  p->require_any = -1;
  p->enable_compilation = -1;
  p->skip_testing = -1;
  p->test_score = -1;
  p->full_score = -1;
  p->full_user_score = -1;
  p->min_score_1 = -1;
  p->min_score_2 = -1;
  p->variable_full_score = -1;
  p->hidden = -1;
  p->advance_to_next = -1;
  p->stand_hide_time = -1;
  p->disable_ctrl_chars = -1;
  p->valuer_sets_marked = -1;
  p->ignore_unmarked = -1;
  p->disable_stderr = -1;
  p->enable_process_group = -1;
  p->enable_testlib_mode = -1;
  p->hide_variant = -1;
  p->autoassign_variants = -1;
  p->enable_text_form = -1;
  p->stand_ignore_score = -1;
  p->stand_last_column = -1;
  p->priority_adjustment = -1000;
  p->max_vm_size = -1LL;
  p->max_stack_size = -1LL;
  p->max_data_size = -1LL;
  p->max_core_size = -1LL;
  p->max_file_size = -1LL;
  p->max_open_file_count = -1;
  p->max_process_count = -1;
  p->interactor_time_limit = -1;
  p->interactor_real_time_limit = -1;
  p->max_user_run_count = -1;
}

void prepare_free_testsets(int t, struct testset_info *p);
static void free_deadline_penalties(int t, struct penalty_info *p);
static void free_personal_deadlines(int t, struct pers_dead_info *p);
void prepare_free_group_dates(struct group_dates *gd);

void
prepare_problem_free_func(struct generic_section_config *gp)
{
  struct section_problem_data *p = (struct section_problem_data*) gp;
  int i;

  prepare_free_group_dates(&p->gsd);
  prepare_free_group_dates(&p->gdl);
  xfree(p->problem_dir);
  xfree(p->normalization);
  xfree(p->score_bonus);
  xfree(p->tscores);
  xfree(p->x_score_tests);
  xfree(p->standard_checker);
  xfree(p->check_cmd);
  xfree(p->valuer_cmd);
  xfree(p->interactor_cmd);
  xfree(p->style_checker_cmd);
  xfree(p->test_checker_cmd);
  xfree(p->init_cmd);
  xfree(p->start_cmd);
  xfree(p->solution_src);
  xfree(p->solution_cmd);
  xfree(p->super_run_dir);
  xfree(p->test_score_list);
  xfree(p->tokens);
  xfree(p->token_info);
  xfree(p->umask);
  xfree(p->ok_status);
  xfree(p->header_pat);
  xfree(p->footer_pat);
  xfree(p->compiler_env_pat);
  sarray_free(p->test_sets);
  sarray_free(p->date_penalty);
  sarray_free(p->group_start_date);
  sarray_free(p->group_deadline);
  sarray_free(p->disable_language);
  sarray_free(p->enable_language);
  sarray_free(p->require);
  sarray_free(p->provide_ok);
  sarray_free(p->lang_compiler_env);
  sarray_free(p->checker_env);
  sarray_free(p->valuer_env);
  sarray_free(p->interactor_env);
  sarray_free(p->style_checker_env);
  sarray_free(p->test_checker_env);
  sarray_free(p->init_env);
  sarray_free(p->start_env);
  sarray_free(p->lang_time_adj);
  sarray_free(p->lang_time_adj_millis);
  sarray_free(p->lang_max_vm_size);
  sarray_free(p->lang_max_stack_size);
  sarray_free(p->personal_deadline);
  sarray_free(p->alternative);
  sarray_free(p->statement_env);
  xfree(p->score_bonus_val);
  xfree(p->open_tests);
  xfree(p->open_tests_val);
  xfree(p->final_open_tests);
  xfree(p->final_open_tests_val);
  xfree(p->token_open_tests);
  xfree(p->token_open_tests_val);
  prepare_free_testsets(p->ts_total, p->ts_infos);
  free_deadline_penalties(p->dp_total, p->dp_infos);
  free_personal_deadlines(p->pd_total, p->pd_infos);
  xfree(p->unhandled_vars);
  sarray_free(p->score_view);
  xfree(p->score_view_score);
  xfree(p->score_view_text);
  xfree(p->extid);
  xfree(p->test_dir);
  xfree(p->test_sfx);
  xfree(p->test_pat);
  xfree(p->corr_dir);
  xfree(p->corr_sfx);
  xfree(p->corr_pat);
  xfree(p->info_dir);
  xfree(p->info_sfx);
  xfree(p->info_pat);
  xfree(p->tgz_dir);
  xfree(p->tgz_sfx);
  xfree(p->tgz_pat);
  xfree(p->tgzdir_sfx);
  xfree(p->tgzdir_pat);
  xfree(p->source_header);
  xfree(p->source_footer);
  xfree(p->statement_file);
  xfree(p->alternatives_file);
  xfree(p->plugin_file);
  xfree(p->xml_file);
  xfree(p->stand_attr);
  xfree(p->spelling);
  xfree(p->score_tests);
  xfree(p->input_file);
  xfree(p->output_file);
  xfree(p->stand_name);
  xfree(p->stand_column);
  xfree(p->group_name);
  xfree(p->internal_name);
  xfree(p->long_name);
  xfree(p->xml_file_path);

  if (p->variant_num > 0 && p->xml.a) {
    for (i = 1; i <= p->variant_num; i++) {
      p->xml.a[i - 1] = problem_xml_free(p->xml.a[i - 1]);
    }
    xfree(p->xml.a);
  } else {
    problem_xml_free(p->xml.p);
  }

  if (p->variant_num > 0 && p->var_xml_file_paths) {
    for (i = 1; i <= p->variant_num; ++i) {
      xfree(p->var_xml_file_paths[i - 1]);
    }
    xfree(p->var_xml_file_paths);
  }

  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

struct section_problem_data *
prepare_problem_free(struct section_problem_data *prob)
{
  if (!prob) return 0;
  prepare_problem_free_func(&prob->g);
  return 0;
}

static void
tester_init_func(struct generic_section_config *gp)
{
  struct section_tester_data *p = (struct section_tester_data*) gp;

  p->is_dos = -1;
  p->skip_testing = -1;
  p->no_redirect = -1;
  p->ignore_stderr = -1;
  p->no_core_dump = -1;
  p->enable_memory_limit_error = -1;
  p->clear_env = -1;
  p->time_limit_adjustment = -1;
  p->time_limit_adj_millis = -1;
  p->priority_adjustment = -1000;
  p->max_vm_size = -1L;
  p->max_stack_size = -1L;
  p->max_data_size = -1L;
  p->memory_limit_type_val = -1;
  p->secure_exec_type_val = -1;
}

void
prepare_tester_free_func(struct generic_section_config *gp)
{
  struct section_tester_data *p = (struct section_tester_data*) gp;

  sarray_free(p->super);
  sarray_free(p->start_env);
  xfree(p->nwrun_spool_dir);
  xfree(p->start_cmd);
  xfree(p->prepare_cmd);
  xfree(p->error_file);
  xfree(p->errorcode_file);
  xfree(p->check_dir);
  xfree(p->run_full_archive_dir);
  xfree(p->run_team_report_dir);
  xfree(p->run_report_dir);
  xfree(p->run_status_dir);
  xfree(p->run_out_dir);
  xfree(p->run_exe_dir);
  xfree(p->run_queue_dir);
  xfree(p->run_dir);
  xfree(p->kill_signal);
  xfree(p->secure_exec_type);
  xfree(p->memory_limit_type);
  xfree(p->key);
  memset(p, 0xab, sizeof(*p));
  xfree(p);
}

struct section_tester_data *
prepare_tester_free(struct section_tester_data *tester)
{
  if (tester) {
    prepare_tester_free_func((struct generic_section_config *) tester);
  }
  return NULL;
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
    vinfo("%s.%s inherited from %s",
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
static void inh_copy_path(void *dst, void *src)
{
  memcpy(dst, src, sizeof(path_t));
}

static int inh_isdef_string(void *vps)
{
  return (*(char **) vps) != NULL;
}
static void inh_copy_string(void *dst, void *src)
{
  xstrdup3((unsigned char **) dst, *(char**) src);
}

#define TESTER_INH(f,d,c) {TESTER_OFFSET(f),#f,inh_isdef_##d,inh_copy_##c }
static const struct inheritance_info tester_inheritance_info[] =
{
  TESTER_INH(arch, path, path),
  TESTER_INH(key, string, string),
  TESTER_INH(run_dir, string, string),
  TESTER_INH(no_core_dump, int, int),
  TESTER_INH(enable_memory_limit_error, int, int),
  TESTER_INH(clear_env, int, int),
  TESTER_INH(time_limit_adjustment, int, int),
  TESTER_INH(time_limit_adj_millis, int, int),
  TESTER_INH(kill_signal, string, string),
  TESTER_INH(max_stack_size, size, size),
  TESTER_INH(max_data_size, size, size),
  TESTER_INH(max_vm_size, size, size),
  TESTER_INH(is_dos, int, int),
  TESTER_INH(skip_testing, int, int),
  TESTER_INH(no_redirect, int, int),
  TESTER_INH(ignore_stderr, int, int),
  TESTER_INH(priority_adjustment, int3, int),
  TESTER_INH(check_dir, string, string),
  TESTER_INH(errorcode_file, string, string),
  TESTER_INH(error_file, string, string),
  TESTER_INH(start_cmd, string, string),
  TESTER_INH(prepare_cmd, string, string),
  TESTER_INH(memory_limit_type, string, string),
  TESTER_INH(secure_exec_type, string, string),
  TESTER_INH(nwrun_spool_dir, string, string),

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

  if (inherit_fields(tester_inheritance_info,
                     atp, ish, stot, (void**) sups,
                     tester_get_name) < 0)
    return -1;

  // merge all the start_env fields
  nenv = sarray_merge_arr(stot + 1, envs);
  sarray_free(atp->start_env);
  atp->start_env = nenv;

  if (atp->memory_limit_type) {
    atp->memory_limit_type_val = prepare_parse_memory_limit_type(atp->memory_limit_type);
    if (atp->memory_limit_type_val < 0) {
      err("invalid memory_limit_type `%s'", atp->memory_limit_type);
      return -1;
    }
  }

  if (atp->secure_exec_type) {
    atp->secure_exec_type_val = prepare_parse_secure_exec_type(atp->secure_exec_type);
    if (atp->secure_exec_type_val < 0) {
      err("invalid secure_exec_type `%s'", atp->secure_exec_type);
      return -1;
    }
  }

  atp->is_processed = 1;
  return 0;
}

void
prepare_free_testsets(int t, struct testset_info *p)
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

int
prepare_parse_testsets(char **set_in, int *p_total, struct testset_info **p_info)
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
  }

  *p_info = info;
  *p_total = total;
  return 0;
}

static int
parse_date(const unsigned char *s, time_t *pd)
{
  return xml_parse_date(NULL, 0, 0, 0, s, pd);
}

static void
free_deadline_penalties(int t, struct penalty_info *p)
{
  if (!p) return;
  memset(p, 0xab, t * sizeof(p[0]));
  xfree(p);
}

static int
parse_penalty_expression(
        const unsigned char *expr,
        struct penalty_info *p)
{
  const unsigned char *s = expr;
  char *eptr = NULL;
  int m = 0, x;
  // [+|-]BASE[(+|-)DECAY[/SCALE]]
  p->penalty = 0;
  p->scale = 0;
  p->decay = 0;

  while (isspace(*s)) ++s;
  if (*s == '+') {
    ++s;
  } else if (*s == '-') {
    m = 1;
    ++s;
  }
  if (*s < '0' || *s > '9') goto fail;
  errno = 0;
  x = strtol(s, &eptr, 10);
  if (errno) goto fail;
  if (x > 100000) goto fail;
  s = (const unsigned char*) eptr;
  if (m) x = -x;
  p->penalty = x;
  while (isspace(*s)) ++s;
  if (!*s) goto done;
  if (*s == '+') {
    m = 0;
    ++s;
  } else if (*s == '-') {
    m = 1;
    ++s;
  } else goto fail;
  while (isspace(*s)) ++s;
  if (*s < '0' || *s > '9') goto fail;
  errno = 0; eptr = NULL;
  x = strtol(s, &eptr, 10);
  if (errno) goto fail;
  if (x > 100000) goto fail;
  s = (const unsigned char *) eptr;
  if (m) x = -x;
  p->decay = x;
  p->scale = 1;
  while (isspace(*s)) ++s;
  if (!*s) goto done;
  if (*s != '/') goto fail;
  ++s;
  while (isspace(*s)) ++s;
  if (*s >= '0' && *s <= '9') {
    errno = 0; eptr = NULL;
    x = strtol(s, &eptr, 10);
    if (errno) goto fail;
    if (x <= 0 || x > 100000) goto fail;
    s = (const unsigned char *) eptr;
  } else {
    x = 1;
  }
  if (*s == 's' || *s == 'S') {
    p->scale = x;
    ++s;
  } else if (*s == 'm' || *s == 'M') {
    p->scale = 60 * x;
    ++s;
  } else if (*s == 'h' || *s == 'H') {
    p->scale = 60*60 * x;
    ++s;
  } else if (*s == 'd' || *s == 'D') {
    p->scale = 60*60*24 * x;
    ++s;
  } else if (*s == 'w' || *s == 'W') {
    p->scale = 60*60*24*7 * x;
    ++s;
  } else goto fail;
  while (isspace(*s)) ++s;
  if (*s) goto fail;

done:
  return 0;

fail:
  return -1;
}

static int
parse_deadline_penalties(char **dpstr, int *p_total,
                         struct penalty_info **p_pens)
{
  int total = 0, i, n;
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
    if (parse_penalty_expression(b2, &v[i]) < 0) {
      err("%d: invalid penalty specification %s", i + 1, b2);
      goto failure;
    }
    if (parse_date(b1, &tt) < 0) {
      err("%d: invalid date specification %s", i + 1, b1);
      goto failure;
    }
    v[i].date = tt;
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
    } else if (sscanf(pdstr[i], "%s%s%n", s1, s2, &n) == 2 && !pdstr[i][n]) {
    } else if (sscanf(pdstr[i], "%s%n", s1, &n) == 1 && !pdstr[i][n]) {
      strcpy(s2, "2038/01/19");
    }

    if (parse_date(s2, &dinfo[i].p.date) < 0) {
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

static int
parse_score_view(struct section_problem_data *prob)
{
  int i, n, v;
  char *eptr;

  if (!prob || !prob->score_view || !prob->score_view[0]) return 0;

  for (n = 0; prob->score_view[n]; n++);
  XCALLOC(prob->score_view_score, n);
  XCALLOC(prob->score_view_text, n + 1);
  prob->score_view_text[n] = "???";

  for (i = 0; i < n; i++) {
    errno = 0;
    v = strtol(prob->score_view[i], &eptr, 10);
    if (errno || !*eptr || !isspace(*eptr) || v < 0) {
      err("%d: invalid score_view specification %s", i, prob->score_view[i]);
      return -1;
    }
    while (isspace(*eptr)) eptr++;
    if (!*eptr) {
      err("%d: invalid score_view specification %s", i, prob->score_view[i]);
      return -1;
    }
    prob->score_view_score[i] = v;
    prob->score_view_text[i] = eptr;
  }
  return 0;
}

void
prepare_free_group_dates(struct group_dates *gd)
{
  int i;

  for (i = 0; i < gd->count; ++i) {
    xfree(gd->info[i].group_name);
    gd->info[i].group_name = 0;
  }
  xfree(gd->info);
  memset(gd, 0, sizeof(*gd));
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

int
prepare_parse_open_tests(
        FILE *flog,
        const unsigned char *str,
        int **p_vals,
        int *p_count)
{
  int *x = 0;
  int x_a = 0;
  const unsigned char *p = str, *q;
  int n;
  int v1, v2;
  int visibility;

  if (*p_vals) *p_vals = 0;
  if (!str || !*str) return 0;

  while (1) {
    while (isspace(*p)) ++p;
    if (!*p) break;
    if (!isdigit(*p)) {
      if (flog) {
        fprintf(flog, "parse_open_tests: number expected\n");
      }
      goto fail;
    }
    v1 = -1; n = -1;
    if (sscanf(p, "%d%n", &v1, &n) != 1 || v1 <= 0 || v1 > 1000) {
      if (flog) {
        fprintf(flog, "parse_open_tests: invalid test number\n");
      }
      goto fail;
    }
    v2 = v1;
    p += n;
    while (isspace(*p)) ++p;
    if (*p == '-') {
      ++p;
      while (isspace(*p)) ++p;
      if (sscanf(p, "%d%n", &v2, &n) != 1 || v2 <= 0 || v2 > 1000) {
        if (flog) {
          fprintf(flog, "parse_open_tests: invalid test number\n");
        }
        goto fail;
      }
      p += n;
      if (v2 < v1) {
        if (flog) {
          fprintf(flog, "parse_open_tests: second test in range is < than the first");
        }
        goto fail;
      }
      while (isspace(*p)) ++p;
    }
    visibility = TV_FULL;
    if (*p == ':') {
      // parse visibility specification
      ++p;
      while (isspace(*p)) ++p;
      q = p;
      while (*q && isalpha(*q)) ++q;
      if (q == p) {
        if (flog) {
          fprintf(flog, "parse_open_tests: empty visibility specification");
        }
        goto fail;
      }
      visibility = test_visibility_parse_mem(p, q - p);
      if (visibility < 0) {
        if (flog) {
          fprintf(flog, "parse_open_tests: invalid visibility");
        }
        goto fail;
      }
      p = q;
      while (isspace(*p)) ++p;      
    }
    if (*p == ',') {
      ++p;
    }

    // set visibility for [v1;v2]

    if (v2 >= x_a) {
      int new_a = x_a;
      int *new_x = 0;
      if (!new_a) new_a = 8;
      while (v2 >= new_a) new_a *= 2;
      XCALLOC(new_x, new_a);
      if (x_a > 0) {
        memcpy(new_x, x, x_a * sizeof(new_x[0]));
      }
      xfree(x);
      x = new_x;
      x_a = new_a;
    }

    for (; v1 <= v2; ++v1)
      x[v1] = visibility;
  }

  if (p_vals) {
    *p_vals = x;
    *p_count = x_a;
  } else {
    xfree(x); x = 0;
  }
  return 0;

fail:
  xfree(x);
  return -1;
}

const unsigned char * const memory_limit_type_str[] =
{
  [MEMLIMIT_TYPE_DEFAULT] = "default",
  [MEMLIMIT_TYPE_DOS] = "dos",
  [MEMLIMIT_TYPE_JAVA] = "java",
  [MEMLIMIT_TYPE_MONO] = "mono",
  [MEMLIMIT_TYPE_VALGRIND] = "valgrind",

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
const unsigned char *
prepare_unparse_memory_limit_type(int value)
{
  if (value < 0 || value >= MEMLIMIT_TYPE_LAST) value = 0;
  return memory_limit_type_str[value];
}

const unsigned char * const secure_exec_type_str[] =
{
  [SEXEC_TYPE_NONE] = "none",
  [SEXEC_TYPE_STATIC] = "static",
  [SEXEC_TYPE_DLL] = "dll",
  [SEXEC_TYPE_JAVA] = "java",
  [SEXEC_TYPE_DLL32] = "dll32",
  [SEXEC_TYPE_MONO] = "mono",
  [SEXEC_TYPE_VALGRIND] = "valgrind",

  [SEXEC_TYPE_LAST] = 0,
};
int
prepare_parse_secure_exec_type(const unsigned char *str)
{
  int i;

  if (!str || !*str) return 0;
  for (i = 0; i < SEXEC_TYPE_LAST; i++)
    if (secure_exec_type_str[i] && !strcasecmp(str, secure_exec_type_str[i]))
      return i;
  return -1;
}
const unsigned char *
prepare_unparse_secure_exec_type(int value)
{
  if (value < 0 || value >= SEXEC_TYPE_LAST) value = 0;
  return secure_exec_type_str[value];
}

static int
parse_tokens_periodic(
        const unsigned char *start,
        const unsigned char **p_end,
        int *p_sign,
        int *p_value1,
        int *p_value2)
{
  int ss = 1;
  const unsigned char *p = start, *ep;
  if (*p == '+') {
  } else if (*p == '-') {
    ss = -1;
  } else {
    return 0;
  }
  ++p;
  errno = 0;
  int value1 = strtol(p, (char**) &ep, 10);
  if (errno) return 0;
  p = ep;
  while (isspace(*p)) ++p;
  if (*p != '/') return 0;
  ++p;
  while (isspace(*p)) ++p;
  if (*p < '0' || *p > '9') return 0; 
  long long value2 = strtol(p, (char**) &ep, 10);
  if (errno) return 0;
  p = ep;
  while (isspace(*p)) ++p;
  if (*p == 's' || *p == 'S') {
    ++p;
  } else if (*p == 'm' || *p == 'M') {
    value2 *= 60;
    ++p;
  } else if (*p == 'h' || *p == 'H') {
    value2 *= 60 * 60;
    ++p;
  } else if (*p == 'd' || *p == 'D') {
    value2 *= 60 * 60 * 24;
    ++p;
  } else if (*p == 'w' || *p == 'W') {
    value2 *= 60 * 60 * 24 * 7;
    ++p;
  }
  if (value2 < INT_MIN || value2 > INT_MAX) {
    return 0;
  }

  *p_end = p;
  *p_sign = ss;
  *p_value1 = value1;
  *p_value2 = value2;
  return 1;
}

static int
parse_tokens_cost(
        const unsigned char *start,
        const unsigned char **p_end,
        int *p_sign,
        int *p_value1,
        int *p_value2)
{
  // valid flags: FinalScore(1),BasicOpenTests,TokenOpenTests,FinalOpenTests
  int ss = 1;
  const unsigned char *p = start, *ep;
  while (isspace(*p)) ++p;
  if (*p == '+') {
  } else if (*p == '-') {
    ss = -1;
  } else {
    return 0;
  }
  ++p;
  errno = 0;
  int value1 = strtol(p, (char**) &ep, 10);
  if (errno) return 0;
  p = ep;
  while (isspace(*p)) ++p;
  if (*p != '/') return 0;
  ++p;
  int value2 = 0;
  while (1) {
    while (isspace(*p)) ++p;
    if (!strncasecmp(p, "finalscore", 10)) {
      value2 |= TOKEN_FINALSCORE_BIT;
      p += 10;
    } else if (!strncasecmp(p, "basicopentests", 14)){
      value2 &= ~TOKEN_TESTS_MASK;
      value2 |= TOKEN_BASICTESTS_BIT;
      p += 14;
    } else if (!strncasecmp(p, "tokenopentests", 14)){
      value2 &= ~TOKEN_TESTS_MASK;
      value2 |= TOKEN_TOKENTESTS_BIT;
      p += 14;
    } else if (!strncasecmp(p, "finalopentests", 14)) {
      value2 &= ~TOKEN_TESTS_MASK;
      value2 |= TOKEN_FINALTESTS_BIT;
      p += 14;
    } else if (!strncasecmp(p, "valuerjudgecomment", 18)) {
      value2 |= TOKEN_VALUER_JUDGE_COMMENT_BIT;
      p += 18;
    } else {
      break;
    }
    while (isspace(*p)) ++p;
    if (*p != ',') break;
    ++p;
  }

  *p_end = p;
  *p_sign = ss;
  *p_value1 = value1;
  *p_value2 = value2;
  return 1;
}

struct token_info *
prepare_parse_tokens(FILE *log_f, const unsigned char *tokens)
{
  if (!tokens || !*tokens) return NULL;

  const unsigned char *ep, *p = tokens;
  // INITIAL+-PERIODIC/INTERVAL+-COST/FLAGS
  // interval is in seconds > 0
  errno = 0;
  int initial_count = strtol(p, (char**) &ep, 10);
  if (errno) {
    fprintf(log_f, "prepare_parse_tokens: '%s': initial_count is invalid\n", tokens);
    return NULL;
  }
  p = ep;
  int periodic_sign = 0, periodic_val1 = 0, periodic_val2 = 0;
  int cost_sign = 0, cost_val1 = 0, cost_val2 = 0;
  while (isspace(*p)) ++p;
  if (*p) {
    if (!parse_tokens_periodic(p, &p, &periodic_sign, &periodic_val1, &periodic_val2)) {
      // failed, so restarting from the same place
      if (!parse_tokens_cost(p, &p, &cost_sign, &cost_val1, &cost_val2)) {
        fprintf(log_f, "prepare_parse_tokens: '%s': invalid token specification\n", tokens);
        return NULL;
      }
    } else {
      while (isspace(*p)) ++p;
      if (*p) {
        if (!parse_tokens_cost(p, &p, &cost_sign, &cost_val1, &cost_val2)) {
          fprintf(log_f, "prepare_parse_tokens: '%s': invalid token specification\n", tokens);
          return NULL;
        }
      }
    }
    while (isspace(*p)) ++p;
  }
  if (*p) {
    fprintf(log_f, "prepare_parse_tokens: '%s': garbage after specification\n", tokens);
    return NULL;
  }

  struct token_info *ti = NULL;
  XCALLOC(ti, 1);
  ti->initial_count = initial_count;
  ti->time_sign = periodic_sign;
  ti->time_increment = periodic_val1;
  ti->time_interval = periodic_val2;
  ti->open_sign = cost_sign;
  ti->open_cost = cost_val1;
  ti->open_flags = cost_val2;

  return ti;
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
    xstrdup3(&state->global->stand_file_name_2, s);
    return;
  }

  i--;
  while (i >= 0 && s[i] != '.' && s[i] != '/') i--;
  if (i < 0 || s[i] == '/') i++;
  usprintf(&state->global->stand_file_name_2,
           "%.*s%s%s", i, s, "%d", s + i);
}

int
prepare_insert_variant_num(
        unsigned char *buf,
        size_t size,
        const unsigned char *file,
        int variant)
{
  int flen, pos;

  ASSERT(file);
  flen = strlen(file);
  ASSERT(flen > 0);
  pos = flen - 1;
  while (pos >= 0 && file[pos] != '/' && file[pos] != '.') pos--;
  if (pos <= 0 || file[pos] == '/')
    return snprintf(buf, size, "%s-%d", file, variant);
  // pos > 0 && file[pos] == '.'
  return snprintf(buf, size, "%.*s-%d%s", pos, file, variant, file + pos);
}

static int
set_defaults(
        const struct contest_desc *cnts,
        const unsigned char *config_file,
        serve_state_t state,
        int mode,
        const unsigned char **subst_src,
        const unsigned char **subst_dst)
{
  struct generic_section_config *p;
  struct section_problem_data *aprob;
  struct section_problem_data *prob;
  struct section_global_data *g = 0;
  struct section_language_data *lang;

  int i, j, si;
  char *ish;
  char *sish;
  void *vptr;

  size_t tmp_len = 0;
  int r;
  path_t fpath;
  path_t start_path;
  path_t xml_path;

  int contest_id = 0;
  /* find global section */
  for (p = state->config; p; p = p->next)
    if (!p->name[0] || !strcmp(p->name, "global"))
      break;
  if (!p) {
    err("Global configuration settings not found");
    return -1;
  }
  g = state->global = (struct section_global_data*) p;

  if (cnts) {
    contest_id = cnts->id;
  } else {
    contest_id = g->contest_id;
  }

  /* userlist-server interaction */
  if (mode == PREPARE_SERVE) {
#if defined EJUDGE_SOCKET_PATH
    if (!g->socket_path || !g->socket_path[0]) {
      xstrdup3(&g->socket_path, EJUDGE_SOCKET_PATH);
    }
#endif /* EJUDGE_SOCKET_PATH */
    if (!g->socket_path || !g->socket_path[0]) {
      err("global.socket_path must be set");
      return -1;
    }
  }

  /* directory poll intervals */
  if (g->sleep_time < 0 || g->sleep_time > 10000) {
    err("Invalid global.sleep_time value");
    return -1;
  }
  if (mode == PREPARE_SERVE) {
    if (g->serve_sleep_time < 0 || g->serve_sleep_time > 10000) {
      err("Invalid global.serve_sleep_time value");
      return -1;
    }
  }
  if (!g->sleep_time && !g->serve_sleep_time) {
    vinfo("global.sleep_time set to %d", DFLT_G_SLEEP_TIME);
    g->sleep_time = DFLT_G_SLEEP_TIME;
    if (mode == PREPARE_SERVE) {
      vinfo("global.serve_sleep_time set to %d", DFLT_G_SERVE_SLEEP_TIME);
      g->serve_sleep_time = DFLT_G_SERVE_SLEEP_TIME;
    }
  } else if (!g->sleep_time) {
    vinfo("global.sleep_time set to %d", DFLT_G_SLEEP_TIME);
    g->sleep_time = DFLT_G_SLEEP_TIME;
  } else if (mode == PREPARE_SERVE && !g->serve_sleep_time) {
    vinfo("global.serve_sleep_time set to global.sleep_time");
    g->serve_sleep_time = g->sleep_time;
  }

  if (g->team_enable_src_view == -1)
    g->team_enable_src_view = DFLT_G_TEAM_ENABLE_SRC_VIEW;
  if (g->team_enable_rep_view == -1)
    g->team_enable_rep_view = DFLT_G_TEAM_ENABLE_REP_VIEW;
  if (g->team_enable_ce_view == -1)
    g->team_enable_ce_view = DFLT_G_TEAM_ENABLE_CE_VIEW;
  if (g->team_show_judge_report == -1)
    g->team_show_judge_report = DFLT_G_TEAM_SHOW_JUDGE_REPORT;
  if (g->report_error_code == -1)
    g->report_error_code = DFLT_G_REPORT_ERROR_CODE;
  if (g->disable_clars == -1)
    g->disable_clars = DFLT_G_DISABLE_CLARS;
  if (g->disable_team_clars == -1)
    g->disable_team_clars = DFLT_G_DISABLE_TEAM_CLARS;
  if (g->enable_eoln_select < 0)
    g->enable_eoln_select = 0;
  if (g->start_on_first_login < 0) g->start_on_first_login = 0;
  if (g->enable_virtual_restart < 0) g->enable_virtual_restart = 0;
  if (g->ignore_compile_errors == -1)
    g->ignore_compile_errors = DFLT_G_IGNORE_COMPILE_ERRORS;
  if (g->disable_failed_test_view == -1)
    g->disable_failed_test_view = DFLT_G_DISABLE_FAILED_TEST_VIEW;
  if (g->ignore_duplicated_runs == -1)
    g->ignore_duplicated_runs = DFLT_G_IGNORE_DUPLICATED_RUNS;
  if (g->show_deadline == -1)
    g->show_deadline = DFLT_G_SHOW_DEADLINE;
  if (g->show_sha1 < 0) g->show_sha1 = 0;
  if (g->show_judge_identity < 0) g->show_judge_identity = 0;
  if (g->enable_printing == -1)
    g->enable_printing = DFLT_G_ENABLE_PRINTING;
  if (g->disable_banner_page == -1)
    g->disable_banner_page = DFLT_G_DISABLE_BANNER_PAGE;
  if (g->printout_uses_login < 0)
    g->printout_uses_login = 0;
  if (g->prune_empty_users == -1)
    g->prune_empty_users = DFLT_G_PRUNE_EMPTY_USERS;
  if (g->enable_full_archive == -1)
    g->enable_full_archive = DFLT_G_ENABLE_FULL_ARCHIVE;
  if (g->show_problems_link_before_start == -1)
    g->show_problems_link_before_start = DFLT_G_SHOW_PROBLEMS_LINK_BEFORE_START;
  if (g->show_problems_link_after_finish == -1)
    g->show_problems_link_after_finish = DFLT_G_SHOW_PROBLEMS_LINK_AFTER_FINISH;
  if (g->disable_user_standings == -1)
    g->disable_user_standings = DFLT_G_DISABLE_USER_STANDINGS;
  if (g->disable_language == -1)
    g->disable_language = DFLT_G_DISABLE_LANGUAGE;
  if (g->problem_navigation == -1)
    g->problem_navigation = DFLT_G_PROBLEM_NAVIGATION;
  if (g->vertical_navigation == -1)
    g->vertical_navigation = DFLT_G_VERTICAL_NAVIGATION;
  if (g->disable_virtual_start == -1)
    g->disable_virtual_start = DFLT_G_DISABLE_VIRTUAL_START;
  if (g->disable_virtual_auto_judge == -1)
    g->disable_virtual_auto_judge = DFLT_G_DISABLE_VIRTUAL_AUTO_JUDGE;
  if (g->enable_auto_print_protocol == -1)
    g->enable_auto_print_protocol = DFLT_G_ENABLE_AUTO_PRINT_PROTOCOL;
  if (g->stand_fancy_style == -1)
    g->stand_fancy_style = 0;
  if (g->stand_use_login == -1)
    g->stand_use_login = DFLT_G_STAND_USE_LOGIN;
  if (g->stand_show_avatar < 0)
    g->stand_show_avatar = 0;
  if (g->stand_show_first_solver < 0)
    g->stand_show_first_solver = 0;
  if (g->stand_show_ok_time == -1)
    g->stand_show_ok_time = DFLT_G_STAND_SHOW_OK_TIME;
  if (g->stand_show_warn_number == -1)
    g->stand_show_warn_number = DFLT_G_STAND_SHOW_WARN_NUMBER;
  if (g->autoupdate_standings == -1)
    g->autoupdate_standings = DFLT_G_AUTOUPDATE_STANDINGS;
  if (g->use_ac_not_ok == -1)
    g->use_ac_not_ok = DFLT_G_USE_AC_NOT_OK;
  if (g->disable_auto_testing == -1)
    g->disable_auto_testing = DFLT_G_DISABLE_AUTO_TESTING;
  if (g->disable_testing == -1)
    g->disable_testing = DFLT_G_DISABLE_TESTING;
  if (g->show_astr_time == -1)
    g->show_astr_time = DFLT_G_SHOW_ASTR_TIME;
  if (g->enable_report_upload == -1)
    g->enable_report_upload = DFLT_G_ENABLE_REPORT_UPLOAD;
  if (g->enable_runlog_merge == -1)
    g->enable_runlog_merge = DFLT_G_ENABLE_RUNLOG_MERGE;
  if (g->ignore_success_time == -1)
    g->ignore_success_time = DFLT_G_IGNORE_SUCCESS_TIME;
  if (g->secure_run == -1) g->secure_run = DFLT_G_SECURE_RUN;
  if (g->detect_violations == -1) g->detect_violations = 0;
  if (g->enable_memory_limit_error == -1)
    g->enable_memory_limit_error = DFLT_G_ENABLE_MEMORY_LIMIT_ERROR;
  if (g->advanced_layout < 0)
    g->advanced_layout = 0;
  if (g->uuid_run_store < 0)
    g->uuid_run_store = 0;
  if (g->enable_32bit_checkers < 0)
    g->enable_32bit_checkers = 0;
  if (g->ignore_bom < 0)
    g->ignore_bom = 0;
  if (g->disable_auto_refresh < 0)
    g->disable_auto_refresh = 0;
  if (g->disable_user_database < 0)
    g->disable_user_database = 0;
  if (g->enable_max_stack_size < 0) g->enable_max_stack_size = 0;

#if defined EJUDGE_HTTPD_HTDOCS_DIR
  if (!g->htdocs_dir || !g->htdocs_dir[0]) {
    xstrdup3(&g->htdocs_dir, EJUDGE_HTTPD_HTDOCS_DIR);
  }
#endif

#define GLOBAL_INIT_NUM_FIELD(f,v) do { if (!g->f) { vinfo("global.%s set to %d", #f, v); g->f = v; } } while (0)
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
  if (g->board_fog_time < 0) {
    vinfo("global.board_fog_time set to %d", DFLT_G_BOARD_FOG_TIME);
    g->board_fog_time = DFLT_G_BOARD_FOG_TIME;
  }
  g->board_fog_time *= 60;
  if (g->board_unfog_time == -1) {
    vinfo("global.board_unfog_time set to %d", DFLT_G_BOARD_UNFOG_TIME);
    g->board_unfog_time = DFLT_G_BOARD_UNFOG_TIME;
  }
  g->board_unfog_time *= 60;
  if (g->contest_time < -1) {
    err("bad value of global.contest_time: %d", g->contest_time);
    return -1;
  }
  if (g->contest_time == -1) {
    vinfo("global.contest_time set to %d", DFLT_G_CONTEST_TIME);
    g->contest_time = DFLT_G_CONTEST_TIME;
  }
  g->contest_time *= 60;

  if (mode == PREPARE_SERVE || mode == PREPARE_RUN) {
    if (g->inactivity_timeout == -1) {
      vinfo("global.inactivity_timeout set to %d", DFLT_G_INACTIVITY_TIMEOUT);
      g->inactivity_timeout = DFLT_G_INACTIVITY_TIMEOUT;
    }
  }

  if (!g->root_dir || !g->root_dir[0]) {
    usprintf(&g->root_dir, "%06d", contest_id);
  }
  if (!os_IsAbsolutePath(g->root_dir) && ejudge_config
      && ejudge_config->contests_home_dir
      && os_IsAbsolutePath(ejudge_config->contests_home_dir)) {
    usprintf(&g->root_dir, "%s/%s", ejudge_config->contests_home_dir, g->root_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!os_IsAbsolutePath(g->root_dir)) {
    usprintf(&g->root_dir, "%s/%s", EJUDGE_CONTESTS_HOME_DIR, g->root_dir);
  }
#endif
  if (!os_IsAbsolutePath(g->root_dir)) {
    err("global.root_dir must be absolute directory!");
    return -1;
  }

  param_subst_2(&g->root_dir, subst_src, subst_dst);

  if ((!g->clardb_plugin || !g->clardb_plugin[0]) && ejudge_config
      && ejudge_config->default_clardb_plugin
      && ejudge_config->default_clardb_plugin[0]) {
    xstrdup3(&g->clardb_plugin, ejudge_config->default_clardb_plugin);
  }
  if ((!g->rundb_plugin || !g->rundb_plugin[0]) && ejudge_config
      && ejudge_config->default_rundb_plugin
      && ejudge_config->default_rundb_plugin[0]) {
    xstrdup3(&g->rundb_plugin, ejudge_config->default_rundb_plugin);
  }
  if ((!g->xuser_plugin || !g->xuser_plugin[0]) && ejudge_config
      && ejudge_config->default_xuser_plugin && ejudge_config->default_xuser_plugin[0]) {
    xstrdup3(&g->xuser_plugin, ejudge_config->default_xuser_plugin);
  }

  if (!g->conf_dir || !g->conf_dir[0]) {
    path_concat(&g->conf_dir, g->root_dir, "conf");
  } else {
    path_prepend_dir(&g->conf_dir, g->root_dir);
  }
  if (!g->var_dir || !g->var_dir[0]) {
    xstrdup3(&g->var_dir, "var");
  }
  path_prepend_dir(&g->var_dir, g->root_dir);

  /* problems integrated directory (for advanced_layout) */
  if (!g->problems_dir || !g->problems_dir[0]) {
    xstrdup3(&g->problems_dir, DFLT_G_PROBLEMS_DIR);
  }
  path_prepend_dir(&g->problems_dir, g->root_dir);

  /* CONFIGURATION FILES DEFAULTS */
#define GLOBAL_INIT_FIELD(f,d,c) do { if (!g->f[0]) { vinfo("global." #f " set to %s", d); snprintf(g->f, sizeof(g->f), "%s", d); } pathmake2(g->f,g->c, "/", g->f, NULL); } while (0)

#if defined EJUDGE_SCRIPT_DIR
  if (!g->script_dir || !g->script_dir[0]) {
    xstrdup3(&g->script_dir, EJUDGE_SCRIPT_DIR);
  }
  if (!g->ejudge_checkers_dir || !g->ejudge_checkers_dir[0]) {
    usprintf(&g->ejudge_checkers_dir, "%s/checkers", EJUDGE_SCRIPT_DIR);
  }
#endif /* EJUDGE_SCRIPT_DIR */

  if (mode == PREPARE_RUN || mode == PREPARE_SERVE) {
    if (!g->test_dir) {
      xstrdup3(&g->test_dir, DFLT_G_TEST_DIR);
    }
    if (!os_IsAbsolutePath(g->test_dir)) {
      usprintf(&g->test_dir, "%s/%s", g->conf_dir, g->test_dir);
    }
    if (!g->corr_dir) {
      xstrdup3(&g->corr_dir, DFLT_G_CORR_DIR);
    }
    if (!os_IsAbsolutePath(g->corr_dir)) {
      usprintf(&g->corr_dir, "%s/%s", g->conf_dir, g->corr_dir);
    }
    if (!g->info_dir) {
      xstrdup3(&g->info_dir, DFLT_G_INFO_DIR);
    }
    if (!os_IsAbsolutePath(g->info_dir)) {
      usprintf(&g->info_dir, "%s/%s", g->conf_dir, g->info_dir);
    }
    if (!g->tgz_dir) {
      xstrdup3(&g->tgz_dir, DFLT_G_TGZ_DIR);
    }
    if (!os_IsAbsolutePath(g->tgz_dir)) {
      usprintf(&g->tgz_dir, "%s/%s", g->conf_dir, g->tgz_dir);
    }
  }

  if (!g->checker_dir || !g->checker_dir) {
    path_concat(&g->checker_dir, g->conf_dir, DFLT_G_CHECKER_DIR);
  } else {
    path_prepend_dir(&g->checker_dir, g->conf_dir);
  }
  if (!g->statement_dir || !g->statement_dir[0]) {
    xstrdup3(&g->statement_dir, DFLT_G_STATEMENT_DIR);
  }
  path_prepend_dir(&g->statement_dir, g->conf_dir);
  if (!g->plugin_dir || !g->plugin_dir[0]) {
    path_concat(&g->plugin_dir, g->conf_dir, DFLT_G_PLUGIN_DIR);
  } else {
    path_prepend_dir(&g->plugin_dir, g->conf_dir);
  }
  if (mode == PREPARE_SERVE && g->description_file && g->description_file[0]) {
    path_prepend_dir(&g->description_file, g->statement_dir);
  }

  if (mode != PREPARE_COMPILE) {
    if (!g->info_sfx) {
      xstrdup3(&g->info_sfx, DFLT_G_INFO_SFX);
      vinfo("global.info_sfx set to %s", g->info_sfx);
    }
    if (!g->tgz_sfx) {
      xstrdup3(&g->tgz_sfx, DFLT_G_TGZ_SFX);
      vinfo("global.tgz_sfx set to %s", g->tgz_sfx);
    }
    if (!g->tgzdir_sfx) {
      xstrdup3(&g->tgzdir_sfx, DFLT_G_TGZDIR_SFX);
      vinfo("global.tgzdir_sfx set to %s", g->tgzdir_sfx);
    }
  }

  if (mode == PREPARE_SERVE) {
    if (!g->run_log_file || !g->run_log_file[0]) {
      xstrdup3(&g->run_log_file, DFLT_G_RUN_LOG_FILE);
    }
    path_prepend_dir(&g->run_log_file, g->var_dir);
    if (!g->clar_log_file || !g->clar_log_file[0]) {
      xstrdup3(&g->clar_log_file, DFLT_G_CLAR_LOG_FILE);
    }
    path_prepend_dir(&g->clar_log_file, g->var_dir);
    if (!g->archive_dir || !g->archive_dir[0]) {
      xstrdup3(&g->archive_dir, DFLT_G_ARCHIVE_DIR);
    }
    path_prepend_dir(&g->archive_dir, g->var_dir);
    if (!g->clar_archive_dir || !g->clar_archive_dir[0]) {
      xstrdup3(&g->clar_archive_dir, DFLT_G_CLAR_ARCHIVE_DIR);
    }
    path_prepend_dir(&g->clar_archive_dir, g->archive_dir);
    if (!g->run_archive_dir || !g->run_archive_dir[0]) {
      xstrdup3(&g->run_archive_dir, DFLT_G_RUN_ARCHIVE_DIR);
    }
    path_prepend_dir(&g->run_archive_dir, g->archive_dir);
    if (!g->report_archive_dir || !g->report_archive_dir[0]) {
      xstrdup3(&g->report_archive_dir, DFLT_G_REPORT_ARCHIVE_DIR);
    }
    path_prepend_dir(&g->report_archive_dir, g->archive_dir);
    if (!g->xml_report_archive_dir || !g->xml_report_archive_dir[0]) {
      xstrdup3(&g->xml_report_archive_dir, DFLT_G_XML_REPORT_ARCHIVE_DIR);
    }
    path_prepend_dir(&g->xml_report_archive_dir, g->archive_dir);
    if (!g->full_archive_dir || !g->full_archive_dir[0]) {
      xstrdup3(&g->full_archive_dir, DFLT_G_FULL_ARCHIVE_DIR);
    }
    path_prepend_dir(&g->full_archive_dir, g->archive_dir);
    if (!g->audit_log_dir || !g->audit_log_dir[0]) {
      xstrdup3(&g->audit_log_dir, DFLT_G_AUDIT_LOG_DIR);
    }
    path_prepend_dir(&g->audit_log_dir, g->archive_dir);
    if (!g->team_report_archive_dir || !g->team_report_archive_dir[0]) {
      xstrdup3(&g->team_report_archive_dir, DFLT_G_TEAM_REPORT_ARCHIVE_DIR);
    }
    path_prepend_dir(&g->team_report_archive_dir, g->archive_dir);
    if (!g->uuid_archive_dir || !g->uuid_archive_dir[0]) {
      xstrdup3(&g->uuid_archive_dir, DFLT_G_RUN_UUID_ARCHIVE_DIR);
    }
    path_prepend_dir(&g->uuid_archive_dir, g->archive_dir);
    if (!g->team_extra_dir || !g->team_extra_dir[0]) {
      xstrdup3(&g->team_extra_dir, DFLT_G_TEAM_EXTRA_DIR);
    }
    path_prepend_dir(&g->team_extra_dir, g->var_dir);

    if (!g->status_dir || !g->status_dir) {
      xstrdup3(&g->status_dir, DFLT_G_STATUS_DIR);
    }
    path_prepend_dir(&g->status_dir, g->var_dir);
    if (!g->serve_socket || !g->serve_socket[0]) {
      path_concat(&g->serve_socket, g->var_dir, DFLT_G_SERVE_SOCKET);
    } else {
      path_prepend_dir(&g->serve_socket, g->var_dir);
    }
    if (g->variant_map_file && !os_IsAbsolutePath(g->variant_map_file)) {
      usprintf(&g->variant_map_file, "%s/%s", g->conf_dir, g->variant_map_file);
    }
    if (g->contest_plugin_file && g->contest_plugin_file[0]) {
      path_prepend_dir(&g->contest_plugin_file, g->plugin_dir);
    }
  }

  if (mode == PREPARE_COMPILE || mode == PREPARE_SERVE) {
    if (!g->compile_dir || !g->compile_dir[0]) {
      xstrdup3(&g->compile_dir, DFLT_G_COMPILE_DIR);
    }
    path_prepend_dir(&g->compile_dir, g->var_dir);
    path_normalize(g->compile_dir, sizeof(g->compile_dir));
    path_concat(&g->compile_queue_dir, g->compile_dir, DFLT_G_COMPILE_QUEUE_DIR);
    path_concat(&g->compile_src_dir, g->compile_dir, DFLT_G_COMPILE_SRC_DIR);
  }

  if (mode == PREPARE_SERVE) {
    /* compile_out_dir is no longer parametrized, also it uses compile_dir */
    usprintf(&g->compile_out_dir, "%s/%06d", g->compile_dir, contest_id);
    path_concat(&g->compile_status_dir, g->compile_out_dir, DFLT_G_COMPILE_STATUS_DIR);
    path_concat(&g->compile_report_dir, g->compile_out_dir, DFLT_G_COMPILE_REPORT_DIR);
  }

  if (!g->work_dir || !g->work_dir[0]) {
    xstrdup3(&g->work_dir, DFLT_G_WORK_DIR);
  }
  path_prepend_dir(&g->work_dir, g->var_dir);
  if (!g->print_work_dir || !g->print_work_dir[0]) {
    xstrdup3(&g->print_work_dir, DFLT_G_PRINT_WORK_DIR);
  }
  path_prepend_dir(&g->print_work_dir, g->work_dir);
  if (!g->diff_work_dir || !g->diff_work_dir[0]) {
    xstrdup3(&g->diff_work_dir, DFLT_G_DIFF_WORK_DIR);
  }
  path_prepend_dir(&g->diff_work_dir, g->work_dir);

  if (!g->a2ps_path || !g->a2ps_path[0]) {
    xstrdup3(&g->a2ps_path, DFLT_G_A2PS_PATH);
  }
  if (!g->lpr_path || !g->lpr_path[0]) {
    xstrdup3(&g->lpr_path, DFLT_G_LPR_PATH);
  }
  if (!g->diff_path || !g->diff_path[0]) {
    xstrdup3(&g->diff_path, DFLT_G_DIFF_PATH);
  }

  if (g->team_page_quota < 0) {
    g->team_page_quota = DFLT_G_TEAM_PAGE_QUOTA;
  }

  if (mode == PREPARE_COMPILE) {
#if defined EJUDGE_LOCAL_DIR
    if (!g->compile_work_dir || !g->compile_work_dir[0]) {
      usprintf(&g->compile_work_dir, "%s/compile/work", EJUDGE_LOCAL_DIR);
    }
#endif
    if (!g->compile_work_dir || !g->compile_work_dir[0]) {
      xstrdup3(&g->compile_work_dir, DFLT_G_COMPILE_WORK_DIR);
    }
    path_prepend_dir(&g->compile_work_dir, g->work_dir);
    param_subst_2(&g->compile_work_dir, subst_src, subst_dst);
  }

  if (mode == PREPARE_RUN || mode == PREPARE_SERVE) {
    if (!g->run_dir || !g->run_dir[0]) xstrdup3(&g->run_dir, DFLT_G_RUN_DIR);
    path_prepend_dir(&g->run_dir, g->var_dir);
    path_concat(&g->run_queue_dir, g->run_dir, DFLT_G_RUN_QUEUE_DIR);
    path_concat(&g->run_exe_dir, g->run_dir, DFLT_G_RUN_EXE_DIR);
  }
  if (mode == PREPARE_SERVE) {
    usprintf(&g->run_out_dir, "%s/%06d", g->run_dir, contest_id);;
    path_concat(&g->run_status_dir, g->run_out_dir, DFLT_G_RUN_STATUS_DIR);
    path_concat(&g->run_report_dir, g->run_out_dir, DFLT_G_RUN_REPORT_DIR);
    if (g->team_enable_rep_view) {
      path_concat(&g->run_team_report_dir, g->run_out_dir, DFLT_G_RUN_TEAM_REPORT_DIR);
     }
    if (g->enable_full_archive) {
      path_concat(&g->run_full_archive_dir, g->run_out_dir, DFLT_G_RUN_FULL_ARCHIVE_DIR);
    }
  }

  if (mode == PREPARE_RUN) {
#if defined EJUDGE_LOCAL_DIR
    if (!g->run_work_dir || !g->run_work_dir[0]) {
      usprintf(&g->run_work_dir, "%s/%06d/work", EJUDGE_LOCAL_DIR, contest_id);
    }
#endif
    if (!g->run_work_dir || !g->run_work_dir[0]) {
      xstrdup3(&g->run_work_dir, DFLT_G_RUN_WORK_DIR);
    }
    path_prepend_dir(&g->run_work_dir, g->work_dir);

#if defined EJUDGE_LOCAL_DIR
    if (!g->run_check_dir || !g->run_check_dir[0]) {
      usprintf(&g->run_check_dir, "%s/%06d/check", EJUDGE_LOCAL_DIR, contest_id);
    }
#endif
    if (!g->run_check_dir || !g->run_check_dir[0]) {
      xstrdup3(&g->run_check_dir, DFLT_G_RUN_CHECK_DIR);
    }
    path_prepend_dir(&g->run_check_dir, g->work_dir);
  }

  if (g->enable_continue == -1) g->enable_continue = DFLT_G_ENABLE_CONTINUE;
  if (g->html_report == -1) g->html_report = 1;
  if (g->xml_report == -1) g->xml_report = 0;
  if (g->xml_report) g->html_report = 0;

  if (g->tests_to_accept == -1) {
    g->tests_to_accept = DFLT_G_TESTS_TO_ACCEPT;
  }

  if (mode == PREPARE_COMPILE) {
    if (g->lang_config_dir && g->lang_config_dir[0]) {
      param_subst_2(&g->lang_config_dir, subst_src, subst_dst);
    }

    if (g->compile_real_time_limit == -1) {
      g->compile_real_time_limit = DFLT_G_COMPILE_REAL_TIME_LIMIT;
      vinfo("global.compile_real_time_limit set to %d",
            g->compile_real_time_limit);
    }
  }

  if (g->checker_real_time_limit == -1) {
    g->checker_real_time_limit = DFLT_G_CHECKER_REAL_TIME_LIMIT;
    vinfo("global.checker_real_time_limit set to %d",
          g->checker_real_time_limit);
  }

  if (mode == PREPARE_SERVE) {
    if (!g->charset || !g->charset[0]) {
      xstrdup3(&g->charset, DFLT_G_CHARSET);
    }
    if (!g->standings_file_name || !g->standings_file_name[0]) {
      xstrdup3(&g->standings_file_name, DFLT_G_STANDINGS_FILE_NAME);
    }
    make_stand_file_name_2(state);

    if (g->contest_start_cmd && g->contest_start_cmd[0]) {
      path_prepend_dir(&g->contest_start_cmd, g->conf_dir);
      if (check_executable(g->contest_start_cmd) < 0) {
        err("contest start command %s is not executable or does not exist",
            g->contest_start_cmd);
        return -1;
      }
    }

    if (g->contest_stop_cmd && g->contest_stop_cmd[0]) {
      path_prepend_dir(&g->contest_stop_cmd, g->conf_dir);
      if (check_executable(g->contest_stop_cmd) < 0) {
        err("contest stop command %s is not executable or does not exist",
            g->contest_stop_cmd);
        return -1;
      }
    }

    if (g->stand_header_file && g->stand_header_file[0]) {
      path_prepend_dir(&g->stand_header_file, g->conf_dir);
      vptr = &g->stand_header_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->stand_header_file, "");
      if (r < 0) return -1;
    }

    if (g->stand_footer_file && g->stand_footer_file[0]) {
      path_prepend_dir(&g->stand_footer_file, g->conf_dir);
      vptr = &g->stand_footer_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->stand_footer_file, "");
      if (r < 0) return -1;
    }

    if (g->stand2_file_name && g->stand2_file_name[0]) {
      if (g->stand2_header_file && g->stand2_header_file[0]) {
        path_prepend_dir(&g->stand2_header_file, g->conf_dir);
        vptr = &g->stand2_header_txt;
        r = generic_read_file(vptr, 0,&tmp_len,0, 0, g->stand2_header_file, "");
        if (r < 0) return -1;
      }
      if (g->stand2_footer_file && g->stand2_footer_file[0]) {
        path_prepend_dir(&g->stand2_footer_file, g->conf_dir);
        vptr = &g->stand2_footer_txt;
        r = generic_read_file(vptr, 0,&tmp_len,0, 0, g->stand2_footer_file, "");
        if (r < 0) return -1;
      } 
    }

    if (g->plog_file_name && g->plog_file_name[0]) {
      if (g->plog_header_file && g->plog_header_file[0]) {
        path_prepend_dir(&g->plog_header_file, g->conf_dir);
        vptr = &g->plog_header_txt;
        r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->plog_header_file, "");
        if (r < 0) return -1;
      }
      if (g->plog_footer_file && g->plog_footer_file[0]) {
        path_prepend_dir(&g->plog_footer_file, g->conf_dir);
        vptr = &g->plog_footer_txt;
        r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->plog_footer_file, "");
        if (r < 0) return -1;
      }
      if (!g->plog_update_time) {
        g->plog_update_time = DFLT_G_PLOG_UPDATE_TIME;
      }
    } else {
      g->plog_update_time = 0;
    }

    if (g->user_exam_protocol_header_file && g->user_exam_protocol_header_file[0]) {
      path_prepend_dir(&g->user_exam_protocol_header_file, g->conf_dir);
      vptr = &g->user_exam_protocol_header_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->user_exam_protocol_header_file, "");
      if (r < 0) return -1;
    }
    if (g->user_exam_protocol_footer_file && g->user_exam_protocol_footer_file[0]) {
      path_prepend_dir(&g->user_exam_protocol_footer_file, g->conf_dir);
      vptr = &g->user_exam_protocol_footer_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->user_exam_protocol_footer_file, "");
      if (r < 0) return -1;
    }

    if (g->prob_exam_protocol_header_file && g->prob_exam_protocol_header_file[0]) {
      path_prepend_dir(&g->prob_exam_protocol_header_file, g->conf_dir);
      vptr = &g->prob_exam_protocol_header_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->prob_exam_protocol_header_file, "");
      if (r < 0) return -1;
    }
    if (g->prob_exam_protocol_footer_file && g->prob_exam_protocol_footer_file[0]) {
      path_prepend_dir(&g->prob_exam_protocol_footer_file, g->conf_dir);
      vptr = &g->prob_exam_protocol_footer_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->prob_exam_protocol_footer_file, "");
      if (r < 0) return -1;
    }

    if (g->full_exam_protocol_header_file && g->full_exam_protocol_header_file[0]) {
      path_prepend_dir(&g->full_exam_protocol_header_file, g->conf_dir);
      vptr = &g->full_exam_protocol_header_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->full_exam_protocol_header_file, "");
      if (r < 0) return -1;
    }
    if (g->full_exam_protocol_footer_file && g->full_exam_protocol_footer_file[0]) {
      path_prepend_dir(&g->full_exam_protocol_footer_file, g->conf_dir);
      vptr = &g->full_exam_protocol_footer_txt;
      r = generic_read_file(vptr, 0, &tmp_len, 0, 0, g->full_exam_protocol_footer_file, "");
      if (r < 0) return -1;
    }

    if (g->use_gzip < 0 || g->use_gzip > 1) {
      g->use_gzip = DFLT_G_USE_GZIP;
    }
    if (g->use_dir_hierarchy < 0 || g->use_dir_hierarchy > 1) {
      g->use_dir_hierarchy = DFLT_G_USE_DIR_HIERARCHY;
    }
    if (g->min_gzip_size < 0) {
      g->min_gzip_size = DFLT_G_MIN_GZIP_SIZE;
    }
  }

#if CONF_HAS_LIBINTL - 0 == 1
  if (g->enable_l10n < 0) g->enable_l10n = 1;
#if defined EJUDGE_LOCALE_DIR
  if (g->enable_l10n && (!g->l10n_dir || !g->l10n_dir[0])) {
    xstrdup3(&g->l10n_dir, EJUDGE_LOCALE_DIR);
  }
#endif /* EJUDGE_LOCALE_DIR */
  if (g->enable_l10n && (!g->l10n_dir || !g->l10n_dir[0])) {
    g->enable_l10n = 0;
  }
#else
  g->enable_l10n = 0;
#endif /* CONF_HAS_LIBINTL */

#if CONF_HAS_LIBINTL - 0 == 1
  if (mode == PREPARE_SERVE && g->enable_l10n) {
    /* convert locale string into locale id */
    g->standings_locale_id = l10n_parse_locale(g->standings_locale);
    if (g->standings_locale_id < 0) g->standings_locale_id = 0;
    vinfo("standings_locale_id is %d", g->standings_locale_id);
  }
#endif /* CONF_HAS_LIBINTL */

  if (g->team_download_time == -1) {
    g->team_download_time = DFLT_G_TEAM_DOWNLOAD_TIME;
  }
  g->team_download_time *= 60;

  if (mode == PREPARE_SERVE && g->virtual_end_options && g->virtual_end_options[0]) {
    g->virtual_end_info = parse_virtual_end_info(g->virtual_end_options);
    if (!g->virtual_end_info) {
      err("global.virtual_end_options is invalid");
      return -1;
    }
  }

  /* only run needs these parameters */
  if (mode == PREPARE_RUN || mode == PREPARE_SERVE) {
    if (!g->max_file_length) {
      g->max_file_length = DFLT_G_MAX_FILE_LENGTH;
      vinfo("global.max_file_length set to %d", g->max_file_length);
    }
    if (!g->max_line_length) {
      g->max_line_length = DFLT_G_MAX_LINE_LENGTH;
      vinfo("global.max_line_length set to %d", g->max_line_length);
    }
    if (!g->max_cmd_length) {
      g->max_cmd_length = DFLT_G_MAX_CMD_LENGTH;
      vinfo("global.max_cmd_length set to %d", g->max_cmd_length);
    }

    if (g->sound_player) {
      char *tmps;

      tmps = varsubst_heap(state, g->sound_player, 0,
                           section_global_params, section_problem_params,
                           section_language_params, section_tester_params, NULL, NULL, NULL);
      xfree(g->sound_player);
      g->sound_player = tmps;
    }
  }

  if (mode == PREPARE_SERVE && g->user_priority_adjustments) {
    g->user_adjustment_info=parse_user_adjustment(g->user_priority_adjustments);
    if (!g->user_adjustment_info) return -1;
  }

  if (mode == PREPARE_SERVE) {
    if (g->contestant_status_num<0 || g->contestant_status_num>100) {
      err("global.contestant_status_num is invalid");
      return -1;
    }
  }
  if (mode == PREPARE_SERVE && g->contestant_status_num > 0) {
    // there must be exact number of legend entries
    if (!g->contestant_status_legend) {
      err("global.contestant_status_legend is not set");
      return -1;
    }
    for (i = 0; g->contestant_status_legend[i]; i++);
    if (i != g->contestant_status_num) {
      err("global.contestant_status_legend has different number of entries, than global.contestant_status_num");
      return -1;
    }
    if (g->contestant_status_row_attr) {
      for (i = 0; g->contestant_status_row_attr[i]; i++);
      if (i != g->contestant_status_num) {
        err("global.contestant_status_row_attr has different number of entries, than global.contestant_status_num");
        return -1;
      }
    }
  }

  if (mode == PREPARE_SERVE && g->tokens && g->tokens[0]) {
    if (!(g->token_info = prepare_parse_tokens(stderr, g->tokens)))
      return -1;
  }

  if (mode == PREPARE_SERVE && g->dates_config_file && g->dates_config_file[0]) {
    if (!(g->dates_config = dates_config_parse_cfg(g->dates_config_file, config_file)))
      return -1;
  }

  for (i = 1; i <= state->max_lang && mode != PREPARE_RUN; i++) {
    if (!(lang = state->langs[i])) continue;
    if (!lang->short_name[0]) {
      vinfo("language.%d.short_name set to \"lang%d\"", i, i);
      sprintf(lang->short_name, "lang%d", i);
    }
    if (!lang->long_name || !lang->long_name[0]) {
      vinfo("language.%d.long_name set to \"Language %d\"", i, i);
      usprintf(&lang->long_name, "Language %d", i);
    }
    
    if (mode == PREPARE_SERVE) {
      if (lang->compile_dir_index > 0) {
        int extras_len = sarray_len(g->extra_compile_dirs);
        if (lang->compile_dir_index > extras_len) {
          err("language.%d: invalid value of compile_dir_index", i);
          return -1;
        }
        const unsigned char *ecd = g->extra_compile_dirs[lang->compile_dir_index - 1];
        if (os_IsAbsolutePath(ecd)) {
          usprintf(&lang->compile_dir, "%s/var/compile", ecd);
        } else if (ejudge_config && ejudge_config->contests_home_dir) {
          usprintf(&lang->compile_dir, "%s/%s/var/compile", ejudge_config->contests_home_dir, ecd);
        } else {
#if defined EJUDGE_CONTESTS_HOME_DIR
          usprintf(&lang->compile_dir, "%s/%s/var/compile", EJUDGE_CONTESTS_HOME_DIR, ecd);
#else
          err("language.d: invalid extra_compile_dirs");
          return -1;
#endif
        }
        usprintf(&lang->compile_queue_dir, "%s/%s", lang->compile_dir, DFLT_G_COMPILE_QUEUE_DIR);
        usprintf(&lang->compile_src_dir, "%s/%s", lang->compile_dir, DFLT_G_COMPILE_QUEUE_DIR);
        usprintf(&lang->compile_out_dir, "%s/%06d", lang->compile_dir, contest_id);
        usprintf(&lang->compile_status_dir, "%s/%s", lang->compile_out_dir, DFLT_G_COMPILE_STATUS_DIR);
        usprintf(&lang->compile_report_dir, "%s/%s", lang->compile_out_dir, DFLT_G_COMPILE_REPORT_DIR);
      } else if (!lang->compile_dir || !lang->compile_dir[0]) {
        // use the global compile queue settings
        xstrdup3(&lang->compile_dir, g->compile_dir);
        xstrdup3(&lang->compile_queue_dir, g->compile_queue_dir);
        xstrdup3(&lang->compile_src_dir, g->compile_src_dir);
        xstrdup3(&lang->compile_out_dir, g->compile_out_dir);
        xstrdup3(&lang->compile_status_dir, g->compile_status_dir);
        xstrdup3(&lang->compile_report_dir, g->compile_report_dir);
      } else {
        // prepare language-specific compile queue settings
        usprintf(&lang->compile_queue_dir, "%s/%s", lang->compile_dir, DFLT_G_COMPILE_QUEUE_DIR);
        usprintf(&lang->compile_src_dir, "%s/%s", lang->compile_dir, DFLT_G_COMPILE_SRC_DIR);
        usprintf(&lang->compile_out_dir, "%s/%06d", lang->compile_dir, contest_id);
        usprintf(&lang->compile_status_dir, "%s/%s", lang->compile_out_dir, DFLT_G_COMPILE_STATUS_DIR);
        usprintf(&lang->compile_report_dir, "%s/%s", lang->compile_out_dir, DFLT_G_COMPILE_REPORT_DIR);
      }
    }

    if (lang->style_checker_cmd && lang->style_checker_cmd[0] && lang->style_checker_cmd[0] != '@' && lang->style_checker_cmd[0] != '%') {
      path_prepend_dir(&lang->style_checker_cmd, g->ejudge_checkers_dir);
    }

    if (!lang->src_sfx[0]) {
      err("language.%d.src_sfx must be set", i);
      return -1;
    }

    if (mode == PREPARE_COMPILE) {
      if (!lang->cmd && !lang->cmd[0]) {
        err("language.%d.cmd must be set", i);
        return -1;
      }
      if (!os_IsAbsolutePath(lang->cmd) && ejudge_config && ejudge_config->compile_home_dir) {
        usprintf(&lang->cmd, "%s/scripts/%s", ejudge_config->compile_home_dir, lang->cmd);
      }
      if (!os_IsAbsolutePath(lang->cmd) && ejudge_config && ejudge_config->contests_home_dir) {
        usprintf(&lang->cmd, "%s/compile/scripts/%s", ejudge_config->contests_home_dir, lang->cmd);
      }
#if defined EJUDGE_CONTESTS_HOME_DIR
      if (!os_IsAbsolutePath(lang->cmd)) {
        usprintf(&lang->cmd, "%s/compile/scripts/%s", EJUDGE_CONTESTS_HOME_DIR, lang->cmd);
      }
#endif /* EJUDGE_CONTESTS_HOME_DIR */
      param_subst_2(&lang->cmd, subst_src, subst_dst);

      vinfo("language.%d.cmd is %s", i, lang->cmd);      
      if (lang->compile_real_time_limit == -1) {
        lang->compile_real_time_limit = g->compile_real_time_limit;
        vinfo("language.%d.compile_real_time_limit is inherited from global (%d)", i, lang->compile_real_time_limit);
      }
      ASSERT(lang->compile_real_time_limit >= 0);
    }

    if (lang->compiler_env) {
      for (j = 0; lang->compiler_env[j]; j++) {
        lang->compiler_env[j] = varsubst_heap(state, lang->compiler_env[j], 1,
                                              section_global_params,
                                              section_problem_params,
                                              section_language_params,
                                              section_tester_params, NULL, lang, NULL);
        if (!lang->compiler_env[j]) return -1;
      }
    }
    if (lang->style_checker_env) {
      for (j = 0; lang->style_checker_env[j]; ++j) {
        lang->style_checker_env[j] = varsubst_heap(state,
                                                   lang->style_checker_env[j],
                                                   1,
                                                   section_global_params,
                                                   section_problem_params,
                                                   section_language_params,
                                                   section_tester_params, NULL, lang, NULL);
        if (!lang->style_checker_env[j]) return -1;
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
    if (aprob->long_name && aprob->long_name[0]) {
      err("abstract problem %s must not define problem long name", ish);
      return -1;
    }
    if (aprob->super[0]) {
      err("abstract problem %s cannot have a superproblem", ish);
      return -1;
    }
  }

  for (i = 1; i <= state->max_prob && mode != PREPARE_COMPILE; i++) {
    if (!(prob = state->probs[i])) continue;
    si = -1;
    sish = 0;
    aprob = 0;
    if (prob->super[0]) {
      for (si = 0; si < state->max_abstr_prob; si++)
        if (!strcmp(state->abstr_probs[si]->short_name, prob->super))
          break;
      if (si >= state->max_abstr_prob) {
        err("abstract problem `%s' is not defined", prob->super);
        return -1;
      }
      aprob = state->abstr_probs[si];
      sish = aprob->short_name;
    }

    if (!prob->short_name[0] && g->auto_short_problem_name) {
      snprintf(prob->short_name, sizeof(prob->short_name), "%06d", prob->id);
      vinfo("problem %d short name is set to %s", i, prob->short_name);
    }
    if (!prob->short_name[0]) {
      err("problem %d short name must be set", i);
      return -1;
    }
    ish = prob->short_name;

    if (g->dates_config) {
      prepare_copy_dates(prob, g->dates_config);
    }

    prepare_set_prob_value(CNTSPROB_problem_dir, prob, aprob, g);

    /* parse XML here */
    if (!prob->xml_file && aprob && aprob->xml_file) {
      sformat_message_2(&prob->xml_file, 0, aprob->xml_file, 0, prob, 0, 0, 0, 0, 0, 0);
    }
    if (prob->xml_file && prob->xml_file[0] && g->advanced_layout <= 0) {
      if (!os_IsAbsolutePath(prob->xml_file)) {
        usprintf(&prob->xml_file, "%s/%s", g->statement_dir, prob->xml_file);
      }
    }
    if (prob->xml_file && prob->xml_file[0] && prob->variant_num > 0) {
      XCALLOC(prob->xml.a, prob->variant_num);
      XCALLOC(prob->var_xml_file_paths, prob->variant_num);
      for (j = 1; j <= prob->variant_num; j++) {
        if (g->advanced_layout > 0) {
          get_advanced_layout_path(xml_path, sizeof(xml_path), g,
                                   prob, prob->xml_file, j);
          if (!(prob->xml.a[j - 1] = problem_xml_parse_safe(NULL, xml_path))) return -1;
          prob->var_xml_file_paths[j - 1] = xstrdup(xml_path);
        } else {
          prepare_insert_variant_num(fpath, sizeof(fpath), prob->xml_file, j);
          if (!(prob->xml.a[j - 1] = problem_xml_parse_safe(NULL, fpath))) return -1;
          prob->var_xml_file_paths[j - 1] = xstrdup(fpath);
        }
      }
    } else if (prob->xml_file && prob->xml_file[0]) {
      if (g->advanced_layout > 0) {
        get_advanced_layout_path(xml_path, sizeof(xml_path), g,
                                 prob, prob->xml_file, -1);
        if (!(prob->xml.p = problem_xml_parse_safe(NULL, xml_path))) return -1;
        prob->xml_file_path = xstrdup(xml_path);
      } else {
        if (!(prob->xml.p = problem_xml_parse_safe(NULL, prob->xml_file))) return -1;
        prob->xml_file_path = xstrdup(prob->xml_file);
      }
    }

    prepare_set_prob_value(CNTSPROB_type, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_use_ac_not_ok, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_ok_status, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_header_pat, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_footer_pat, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_compiler_env_pat, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_ignore_prev_ac, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_team_enable_rep_view, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_team_enable_ce_view, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_team_show_judge_report, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_show_checker_comment, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_ignore_compile_errors, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_tests_to_accept, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_accept_partial, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_min_tests_to_accept, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_disable_user_submit, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_notify_on_submit, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_disable_tab, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_unrestricted_statement, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_enable_submit_after_reject, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_hide_file_names, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_hide_real_time_limit, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_enable_tokens, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_tokens_for_user_ac, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_disable_submit_after_ok, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_disable_auto_testing, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_disable_testing, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_enable_compilation, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_skip_testing, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_disable_security, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_enable_suid_run, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_enable_multi_header, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_use_lang_multi_header, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_require_any, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_full_score, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_full_user_score, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_min_score_1, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_min_score_2, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_variable_full_score, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_test_score, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_run_penalty, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_acm_run_penalty, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_disqualified_penalty, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_compile_error_penalty, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_hidden, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_advance_to_next, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_stand_hide_time, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_disable_ctrl_chars, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_valuer_sets_marked, prob, aprob, g);    
    prepare_set_prob_value(CNTSPROB_ignore_unmarked, prob, aprob, g);    
    prepare_set_prob_value(CNTSPROB_disable_stderr, prob, aprob, g);    
    prepare_set_prob_value(CNTSPROB_enable_process_group, prob, aprob, g);    
    prepare_set_prob_value(CNTSPROB_enable_testlib_mode, prob, aprob, g);    
    prepare_set_prob_value(CNTSPROB_hide_variant, prob, aprob, g);    
    prepare_set_prob_value(CNTSPROB_autoassign_variants, prob, aprob, g);    
    prepare_set_prob_value(CNTSPROB_enable_text_form, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_stand_ignore_score, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_stand_last_column, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_scoring_checker, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_enable_checker_token, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_interactive_valuer, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_disable_pe, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_disable_wtl, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_wtl_is_cf, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_manual_checking, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_examinator_num, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_check_presentation, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_use_stdin, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_use_stdout, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_combined_stdin, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_combined_stdout, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_binary_input, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_binary, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_ignore_exit_code, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_olympiad_mode, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_score_latest, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_score_latest_or_unmarked, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_score_latest_marked, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_score_tokenized, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_time_limit, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_time_limit_millis, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_real_time_limit, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_interactor_time_limit, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_interactor_real_time_limit, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_test_sfx, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_corr_sfx, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_info_sfx, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_tgz_sfx, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_tgzdir_sfx, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_test_pat, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_corr_pat, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_info_pat, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_tgz_pat, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_tgzdir_pat, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_check_cmd, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_valuer_cmd, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_interactor_cmd, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_style_checker_cmd, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_test_checker_cmd, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_init_cmd, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_start_cmd, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_solution_src, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_solution_cmd, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_super_run_dir, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_max_vm_size, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_max_stack_size, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_max_data_size, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_max_core_size, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_max_file_size, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_max_open_file_count, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_max_process_count, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_source_header, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_source_footer, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_normalization, prob, aprob, g);
    prepare_set_prob_value(CNTSPROB_max_user_run_count, prob, aprob, g);

    if (prob->enable_tokens > 0) {
      g->enable_tokens = 1;
    }

    if (prob->priority_adjustment == -1000 && si != -1 &&
        aprob->priority_adjustment != -1000) {
      prob->priority_adjustment = aprob->priority_adjustment;
    }
    if (prob->priority_adjustment == -1000) {
      prob->priority_adjustment = 0;
    }

    if (!prob->score_multiplier && si != -1 &&
        aprob->score_multiplier >= 1) {
      prob->score_multiplier = aprob->score_multiplier;
    }

    if (prob->prev_runs_to_show <= 0 && si != -1
        && aprob->prev_runs_to_show >= 1) {
      prob->prev_runs_to_show = aprob->prev_runs_to_show;
    }

    if (mode == PREPARE_SERVE) {
      if (prob->personal_deadline) {
        if (parse_personal_deadlines(prob->personal_deadline,
                                     &prob->pd_total, &prob->pd_infos) < 0) {
          return -1;
        }
      }
      if (prob->score_view) {
        if (parse_score_view(prob) < 0) return -1;
      }

      if (parse_deadline_penalties(prob->date_penalty, &prob->dp_total,
                                   &prob->dp_infos) < 0) return -1;

      if (si != -1 && aprob->disable_language) {
        prob->disable_language = sarray_merge_pf(aprob->disable_language, prob->disable_language);
      }
      if (si != -1 && aprob->enable_language) {
        prob->enable_language = sarray_merge_pf(aprob->enable_language, prob->enable_language);
      }
      if (si != -1 && aprob->require) {
        prob->require = sarray_merge_pf(aprob->require, prob->require);
      }
      if (si != -1 && aprob->provide_ok) {
        prob->provide_ok = sarray_merge_pf(aprob->provide_ok, prob->provide_ok);
      }
      if (si != -1 && aprob->checker_env) {
        prob->checker_env = sarray_merge_pf(aprob->checker_env,
                                            prob->checker_env);
      }
      if (prob->checker_env) {
        for (j = 0; prob->checker_env[j]; j++) {
          prob->checker_env[j] = varsubst_heap(state, prob->checker_env[j], 1,
                                               section_global_params,
                                               section_problem_params,
                                               section_language_params,
                                               section_tester_params, prob, NULL, NULL);
          if (!prob->checker_env[j]) return -1;
        }
      }

      if (si != -1 && aprob->valuer_env) {
        prob->valuer_env = sarray_merge_pf(aprob->valuer_env, prob->valuer_env);
      }
      if (prob->valuer_env) {
        for (j = 0; prob->valuer_env[j]; j++) {
          prob->valuer_env[j] = varsubst_heap(state, prob->valuer_env[j], 1,
                                              section_global_params,
                                              section_problem_params,
                                              section_language_params,
                                              section_tester_params, prob, NULL, NULL);
          if (!prob->valuer_env[j]) return -1;
        }
      }

      if (si != -1 && aprob->interactor_env) {
        prob->interactor_env = sarray_merge_pf(aprob->interactor_env,
                                               prob->interactor_env);
      }
      if (prob->interactor_env) {
        for (j = 0; prob->interactor_env[j]; j++) {
          prob->interactor_env[j] = varsubst_heap(state,
                                                  prob->interactor_env[j], 1,
                                                  section_global_params,
                                                  section_problem_params,
                                                  section_language_params,
                                                  section_tester_params, prob, NULL, NULL);
          if (!prob->interactor_env[j]) return -1;
        }
      }

      if (si != -1 && aprob->statement_env) {
        prob->statement_env = sarray_merge_pf(aprob->statement_env,
                                              prob->statement_env);
      }
      if (prob->statement_env) {
        for (j = 0; prob->statement_env[j]; j++) {
          prob->statement_env[j] = varsubst_heap(state,
                                                 prob->statement_env[j], 1,
                                                 section_global_params,
                                                 section_problem_params,
                                                 section_language_params,
                                                 section_tester_params, prob, NULL, NULL);
          if (!prob->statement_env[j]) return -1;
        }
      }

      if (si != -1 && aprob->lang_compiler_env) {
        prob->lang_compiler_env = sarray_merge_pf(aprob->lang_compiler_env,
                                                  prob->lang_compiler_env);
      }
      if (prob->lang_compiler_env) {
        for (j = 0; prob->lang_compiler_env[j]; j++) {
          prob->lang_compiler_env[j] = varsubst_heap(state,
                                                     prob->lang_compiler_env[j],
                                                     1, section_global_params,
                                                     section_problem_params,
                                                     section_language_params,
                                                     section_tester_params, prob, NULL, NULL);
          if (!prob->lang_compiler_env[j]) return -1;
        }
      }

      if (si != -1 && aprob->style_checker_env) {
        prob->style_checker_env = sarray_merge_pf(aprob->style_checker_env,
                                                  prob->style_checker_env);
      }
      if (prob->style_checker_env) {
        for (j = 0; prob->style_checker_env[j]; j++) {
          prob->style_checker_env[j] = varsubst_heap(state,
                                                     prob->style_checker_env[j],
                                                     1, section_global_params,
                                                     section_problem_params,
                                                     section_language_params,
                                                     section_tester_params, prob, NULL, NULL);
          if (!prob->style_checker_env[j]) return -1;
        }
      }

      if (si != -1 && aprob->test_checker_env) {
        prob->test_checker_env = sarray_merge_pf(aprob->test_checker_env,
                                                 prob->test_checker_env);
      }
      if (prob->test_checker_env) {
        for (j = 0; prob->test_checker_env[j]; j++) {
          prob->test_checker_env[j] = varsubst_heap(state,
                                                    prob->test_checker_env[j],
                                                    1, section_global_params,
                                                    section_problem_params,
                                                    section_language_params,
                                                    section_tester_params, prob, NULL, NULL);
          if (!prob->test_checker_env[j]) return -1;
        }
      }

      if (si != -1 && aprob->init_env) {
        prob->init_env = sarray_merge_pf(aprob->init_env,
                                         prob->init_env);
      }
      if (prob->init_env) {
        for (j = 0; prob->init_env[j]; j++) {
          prob->init_env[j] = varsubst_heap(state,
                                            prob->init_env[j],
                                            1, section_global_params,
                                            section_problem_params,
                                            section_language_params,
                                            section_tester_params, prob, NULL, NULL);
          if (!prob->init_env[j]) return -1;
        }
      }

      if (si != -1 && aprob->start_env) {
        prob->start_env = sarray_merge_pf(aprob->start_env,
                                          prob->start_env);
      }
      if (prob->start_env) {
        for (j = 0; prob->start_env[j]; j++) {
          prob->start_env[j] = varsubst_heap(state,
                                             prob->start_env[j],
                                             1, section_global_params,
                                             section_problem_params,
                                             section_language_params,
                                             section_tester_params, prob, NULL, NULL);
          if (!prob->start_env[j]) return -1;
        }
      }

      /* score bonus */
      prepare_set_prob_value(CNTSPROB_score_bonus, prob, aprob, g);
      if (prob->score_bonus && prob->score_bonus[0]) {
        if (parse_score_bonus(prob->score_bonus, &prob->score_bonus_total,
                              &prob->score_bonus_val) < 0) return -1;
      }
    }

    if (mode == PREPARE_SERVE) {
      if (!prob->statement_file && aprob && aprob->statement_file) {
        sformat_message_2(&prob->statement_file, 0, aprob->statement_file,
                          NULL, prob, NULL, NULL, NULL, 0, 0, 0);
      }
      if (prob->statement_file && prob->statement_file[0] && !os_IsAbsolutePath(prob->statement_file)) {
        usprintf(&prob->statement_file, "%s/%s", g->statement_dir, prob->statement_file);
      }

      if (!prob->alternatives_file && aprob && aprob->alternatives_file) {
        sformat_message_2(&prob->alternatives_file, 0, aprob->alternatives_file,
                          NULL, prob, NULL, NULL, NULL, 0, 0, 0);
      }
      if (prob->alternatives_file && prob->alternatives_file[0] && !os_IsAbsolutePath(prob->alternatives_file)) {
        usprintf(&prob->alternatives_file, "%s/%s", g->statement_dir, prob->alternatives_file);
      }

      if (!prob->plugin_file && aprob && aprob->plugin_file) {
        sformat_message_2(&prob->plugin_file, 0, aprob->plugin_file,
                        NULL, prob, NULL, NULL, NULL, 0, 0, 0);
      }
      if (prob->plugin_file && prob->plugin_file[0] && g->advanced_layout <= 0) {
        if (!os_IsAbsolutePath(prob->plugin_file)) {
          usprintf(&prob->plugin_file, "%s/%s", g->plugin_dir, prob->plugin_file);
        }
      }

      prepare_set_prob_value(CNTSPROB_stand_attr, prob, aprob, g);
    }

    if (mode == PREPARE_RUN || mode == PREPARE_SERVE) {
      if (!prob->test_dir && aprob && aprob->test_dir) {
        sformat_message_2(&prob->test_dir, 0, aprob->test_dir,
                          NULL, prob, NULL, NULL, NULL, 0, 0, 0);
        vinfo("problem.%s.test_dir taken from problem.%s ('%s')",
             ish, sish, prob->test_dir);
      }
      if (!prob->test_dir) {
        vinfo("problem.%s.test_dir set to %s", ish, prob->short_name);
        xstrdup3(&prob->test_dir, prob->short_name);
      }
      if (!os_IsAbsolutePath(prob->test_dir)) {
        usprintf(&prob->test_dir, "%s/%s", g->test_dir, prob->test_dir);
      }
      vinfo("problem.%s.test_dir is '%s'", ish, prob->test_dir);

      if (!prob->corr_dir && aprob && aprob->corr_dir) {
        sformat_message_2(&prob->corr_dir, 0, aprob->corr_dir,
                          NULL, prob, NULL, NULL, NULL, 0, 0, 0);
        vinfo("problem.%s.corr_dir taken from problem.%s ('%s')",
             ish, sish, prob->corr_dir);
      }
      if (prob->corr_dir && !os_IsAbsolutePath(prob->corr_dir)) {
        usprintf(&prob->corr_dir, "%s/%s", g->corr_dir, prob->corr_dir);
        vinfo("problem.%s.corr_dir is '%s'", ish, prob->corr_dir);
      }

      prepare_set_prob_value(CNTSPROB_use_info, prob, aprob, g);

      if (prob->use_info > 0) {
        if (!prob->info_dir && aprob && aprob->info_dir) {
          sformat_message_2(&prob->info_dir, 0, aprob->info_dir,
                            NULL, prob, NULL, NULL, NULL, 0, 0, 0);
          vinfo("problem.%s.info_dir taken from problem.%s ('%s')",
                ish, sish, prob->info_dir);
        }
        if (!prob->info_dir) {
          xstrdup3(&prob->info_dir, prob->short_name);
          vinfo("problem.%s.info_dir is set to '%s'", ish, prob->info_dir);
        }
        if (prob->info_dir && !os_IsAbsolutePath(prob->info_dir)) {
          usprintf(&prob->info_dir, "%s/%s", g->info_dir, prob->info_dir);
        }
      }

      if (prob->use_tgz == -1 && si != -1 && aprob->use_tgz != -1) {
        prob->use_tgz = aprob->use_tgz;
        vinfo("problem.%s.use_tgz taken from problem.%s (%d)",
             ish, sish, prob->use_tgz);
      }
      if (prob->use_tgz == -1) {
        prob->use_tgz = 0;
      }

      if (prob->use_tgz > 0) {
        if (!prob->tgz_dir && aprob && aprob->tgz_dir) {
          sformat_message_2(&prob->tgz_dir, 0, aprob->tgz_dir,
                            NULL, prob, NULL, NULL, NULL, 0, 0, 0);
          vinfo("problem.%s.tgz_dir taken from problem.%s ('%s')",
                ish, sish, prob->tgz_dir);
        }
        if (!prob->tgz_dir) {
          xstrdup3(&prob->tgz_dir, prob->short_name);
          vinfo("problem.%s.tgz_dir is set to '%s'", ish, prob->tgz_dir);
        }
        if (!os_IsAbsolutePath(prob->tgz_dir)) {
          usprintf(&prob->tgz_dir, "%s/%s", g->tgz_dir, prob->tgz_dir);
          vinfo("problem.%s.tgz_dir is '%s'", ish, prob->tgz_dir);
        }
      }

      if (prob->open_tests && prob->open_tests[0]) {
        if (prepare_parse_open_tests(stderr, prob->open_tests,
                                     &prob->open_tests_val, &prob->open_tests_count) < 0)
          return -1;
      }
      if (prob->final_open_tests && prob->final_open_tests[0]) {
        if (prepare_parse_open_tests(stderr, prob->final_open_tests,
                                     &prob->final_open_tests_val,
                                     &prob->final_open_tests_count) < 0)
          return -1;
      }
      if (prob->token_open_tests && prob->token_open_tests[0]) {
        if (prepare_parse_open_tests(stderr, prob->token_open_tests,
                                     &prob->token_open_tests_val,
                                     &prob->token_open_tests_count) < 0)
          return -1;
      }
      if (prob->tokens && prob->tokens[0]) {
        if (!(prob->token_info = prepare_parse_tokens(stderr, prob->tokens)))
          return -1;
      }
    }

    if (!prob->input_file && aprob && aprob->input_file) {
      sformat_message_2(&prob->input_file, 0, aprob->input_file,
                        NULL, prob, NULL, NULL, NULL, 0, 0, 0);
      vinfo("problem.%s.input_file inherited from problem.%s ('%s')",
            ish, sish, prob->input_file);
    }
    if (!prob->input_file || !prob->input_file[0]) {
      vinfo("problem.%s.input_file set to %s", ish, DFLT_P_INPUT_FILE);
      xstrdup3(&prob->input_file, DFLT_P_INPUT_FILE);
    }
    if (!prob->output_file && aprob && aprob->output_file) {
      sformat_message_2(&prob->output_file, 0, aprob->output_file,
                      NULL, prob, NULL, NULL, NULL, 0, 0, 0);
      vinfo("problem.%s.output_file inherited from problem.%s ('%s')",
            ish, sish, prob->output_file);
    }
    if (!prob->output_file || !prob->output_file[0]) {
      vinfo("problem.%s.output_file set to %s", ish, DFLT_P_OUTPUT_FILE);
      xstrdup3(&prob->output_file, DFLT_P_OUTPUT_FILE);
    }

    if (prob->variant_num == -1 && si != -1 && aprob->variant_num != -1) {
      prob->variant_num = aprob->variant_num;
      vinfo("problem.%s.variant_num inherited from problem.%s (%d)",
            ish, sish, prob->variant_num);
    }
    if (prob->variant_num == -1) {
      prob->variant_num = 0;
    }

    prepare_set_prob_value(CNTSPROB_use_corr, prob, aprob, g);

    prepare_set_prob_value(CNTSPROB_checker_real_time_limit, prob, aprob, g);

    if (prob->test_sets) {
      if (prepare_parse_testsets(prob->test_sets,
                                 &prob->ts_total,
                                 &prob->ts_infos) < 0)
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

    for (i = 1; i <= state->max_prob; i++) {
      if (!(prob = state->probs[i])) continue;
      if (prob && prob->variant_num > 0) var_prob_num++;
    }
    if (var_prob_num > 0) {
      if (!g->variant_map_file) {
        err("There are variant problems, but no variant file name");
        return -1;
      }
      g->variant_map = variant_map_parse(stderr, state, g->variant_map_file);
      if (!g->variant_map) return -1;
    }
  }

#define TESTER_INIT_FIELD(f,d,c) do { if (!state->testers[i]->f[0]) { vinfo("tester.%d.%s set to %s", i, #f, d); pathcat(state->testers[i]->f, d); } path_add_dir(state->testers[i]->f, state->testers[i]->c); } while(0)
  if (mode == PREPARE_SERVE || mode == PREPARE_RUN) {
    for (i = 1; i <= state->max_tester; i++) {
      struct section_tester_data *tp = 0;
      struct section_tester_data *atp = 0;
      const struct section_problem_data *tp_prob = 0;

      if (!state->testers[i]) continue;
      tp = state->testers[i];
      if (state->probs && tp->problem > 0 && tp->problem <= state->max_prob)
        tp_prob = state->probs[tp->problem];

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
        vinfo("tester.%d.arch inherited from tester.%s ('%s')",
             i, sish, tp->arch);
      }
      if ((!tp->key || !tp->key[0]) && atp && atp->key && atp->key[0]) {
        xstrdup3(&tp->key, atp->key);
        vinfo("tester.%d.key inherited from tester.%s ('%s')", i, sish, tp->key);
      }

      if (!state->testers[i]->name[0]) {
        sprintf(state->testers[i]->name, "tst_%d", state->testers[i]->id);
        if (state->testers[i]->arch[0]) {
          sprintf(state->testers[i]->name + strlen(state->testers[i]->name),
                  "_%s", state->testers[i]->arch);
        }
        vinfo("tester.%d.name set to \"%s\"", i, state->testers[i]->name);
      }

      if (mode == PREPARE_RUN) {
        if ((!tp->check_dir || !tp->check_dir[0]) && atp && atp->check_dir && atp->check_dir[0]) {
          sformat_message_2(&tp->check_dir, 0, atp->check_dir, g, tp_prob, NULL, tp, NULL, 0, 0, 0);
        }
        if (!tp->check_dir || !tp->check_dir[0]) {
          xstrdup3(&tp->check_dir, g->run_check_dir);
        }
#if defined EJUDGE_LOCAL_DIR
        if (!os_IsAbsolutePath(tp->check_dir)) {
          usprintf(&tp->check_dir, "%s/%s", EJUDGE_LOCAL_DIR, tp->check_dir);
        }
#endif
        if (!os_IsAbsolutePath(tp->check_dir)) {
          usprintf(&tp->check_dir, "%s/%s", EJUDGE_CONTESTS_HOME_DIR, tp->check_dir);
        }
      }

      if (mode == PREPARE_SERVE) {
        if ((!tp->run_dir || !tp->run_dir[0]) && atp && atp->run_dir && atp->run_dir[0]) {
          sformat_message_2(&tp->run_dir, 0, atp->run_dir, g, tp_prob, NULL, tp, NULL, 0, 0, 0);
          vinfo("tester.%d.run_dir inherited from tester.%s ('%s')", i, sish, tp->run_dir);
        }
        if (!tp->run_dir || !tp->run_dir[0]) {
          vinfo("tester.%d.run_dir inherited from global ('%s')",i, g->run_dir);
          xstrdup3(&tp->run_dir, g->run_dir);
          xstrdup3(&tp->run_queue_dir, g->run_queue_dir);
          xstrdup3(&tp->run_exe_dir, g->run_exe_dir);
          xstrdup3(&tp->run_out_dir, g->run_out_dir);
          xstrdup3(&tp->run_status_dir, g->run_status_dir);
          xstrdup3(&tp->run_report_dir, g->run_report_dir);
          if (g->team_enable_rep_view) {
            xstrdup3(&tp->run_team_report_dir, g->run_team_report_dir);
          }
          if (g->enable_full_archive) {
            xstrdup3(&tp->run_full_archive_dir, g->run_full_archive_dir);
          }
        } else {
          usprintf(&tp->run_queue_dir, "%s/%s", tp->run_dir, DFLT_G_RUN_QUEUE_DIR);
          vinfo("tester.%d.run_queue_dir is %s", i, tp->run_queue_dir);
          usprintf(&tp->run_exe_dir, "%s/%s", tp->run_dir, DFLT_G_RUN_EXE_DIR);
          vinfo("tester.%d.run_exe_dir is %s", i, tp->run_exe_dir);
          usprintf(&tp->run_out_dir, "%s/%06d", tp->run_dir, cnts->id);
          vinfo("tester.%d.run_out_dir is %s", i, tp->run_out_dir);
          usprintf(&tp->run_status_dir, "%s/%s", tp->run_out_dir, DFLT_G_RUN_STATUS_DIR);
          vinfo("tester.%d.run_status_dir is %s", i, tp->run_status_dir);
          usprintf(&tp->run_report_dir, "%s/%s", tp->run_out_dir, DFLT_G_RUN_REPORT_DIR);
          vinfo("tester.%d.run_report_dir is %s", i, tp->run_report_dir);
          if (g->team_enable_rep_view) {
            usprintf(&tp->run_team_report_dir, "%s/%s", tp->run_out_dir, DFLT_G_RUN_TEAM_REPORT_DIR);
            vinfo("tester.%d.run_team_report_dir is %s", i, tp->run_team_report_dir);
          }
          if (g->enable_full_archive) {
            usprintf(&tp->run_full_archive_dir, "%s/%s", tp->run_out_dir, DFLT_G_RUN_FULL_ARCHIVE_DIR);
            vinfo("tester.%d.run_full_archive_dir is %s", i, tp->run_full_archive_dir);
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
        vinfo("tester.%d.no_core_dump inherited from tester.%s (%d)",
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
        vinfo("tester.%d.clear_env inherited from tester.%s (%d)",
              i, sish, tp->clear_env);
      }
      if (tp->clear_env == -1) {
        tp->clear_env = 0;
      }
      if (tp->time_limit_adjustment == -1
          && atp && atp->time_limit_adjustment != -1) {
        tp->time_limit_adjustment = atp->time_limit_adjustment;
        vinfo("tester.%d.time_limit_adjustment inherited from tester.%s (%d)",
              i, sish, tp->time_limit_adjustment);
      }
      if (tp->time_limit_adjustment == -1) {
        tp->time_limit_adjustment = 0;
      }
      if (tp->time_limit_adj_millis == -1
          && atp && atp->time_limit_adj_millis != -1) {
        tp->time_limit_adj_millis = atp->time_limit_adj_millis;
      }
      if (tp->time_limit_adj_millis == -1) {
        tp->time_limit_adj_millis = 0;
      }
      if ((!tp->kill_signal || !tp->kill_signal[0]) && atp && atp->kill_signal && atp->kill_signal[0]) {
        xstrdup3(&tp->kill_signal, atp->kill_signal);
        vinfo("tester.%d.kill_signal inherited from tester.%s ('%s')", i, sish, tp->kill_signal);
      }
      if (tp->max_stack_size == -1L && atp && atp->max_stack_size != -1L) {
        tp->max_stack_size = atp->max_stack_size;
        vinfo("tester.%d.max_stack_size inherited from tester.%s (%" EJ_PRINTF_ZSPEC "u)",
              i, sish, EJ_PRINTF_ZCAST(tp->max_stack_size));
      }
      if (tp->max_data_size == -1L && atp && atp->max_data_size != -1L) {
        tp->max_data_size = atp->max_data_size;
        vinfo("tester.%d.max_data_size inherited from tester.%s (%" EJ_PRINTF_ZSPEC "u)",
              i, sish, EJ_PRINTF_ZCAST(tp->max_data_size));
      }
      if (tp->max_vm_size == -1L && atp && atp->max_vm_size != -1L) {
        tp->max_vm_size = atp->max_vm_size;
        vinfo("tester.%d.max_vm_size inherited from tester.%s (%" EJ_PRINTF_ZSPEC "u)",
              i, sish, EJ_PRINTF_ZCAST(tp->max_vm_size));
      }
      if (tp->memory_limit_type) {
        tp->memory_limit_type_val = prepare_parse_memory_limit_type(tp->memory_limit_type);
        if (tp->memory_limit_type_val < 0) {
          err("invalid memory limit type `%s'", tp->memory_limit_type);
          return -1;
        }
      }
      if (tp->memory_limit_type_val < 0 && atp && atp->memory_limit_type_val >= 0) {
        tp->memory_limit_type_val = atp->memory_limit_type_val;
      }
      if (tp->secure_exec_type) {
        tp->secure_exec_type_val = prepare_parse_secure_exec_type(tp->secure_exec_type);
        if (tp->secure_exec_type_val < 0) {
          err("invalid secure exec type `%s'", tp->secure_exec_type);
          return -1;
        }
      }
      if (tp->secure_exec_type_val<0 && atp && atp->secure_exec_type_val>=0) {
        tp->secure_exec_type_val = atp->secure_exec_type_val;
      }

      if (tp->skip_testing == -1 && atp && atp->skip_testing != -1)
        tp->skip_testing = atp->skip_testing;
      if (tp->skip_testing == -1) tp->skip_testing = 0;

      if (tp->is_dos == -1 && atp && atp->is_dos != -1) {
        tp->is_dos = atp->is_dos;
        vinfo("tester.%d.is_dos inherited from tester.%s (%d)",
              i, sish, tp->is_dos);        
      }
      if (tp->is_dos == -1) {
        tp->is_dos = 0;
      }
      if (tp->no_redirect == -1 && atp && atp->no_redirect != -1) {
        tp->no_redirect = atp->no_redirect;
        vinfo("tester.%d.no_redirect inherited from tester.%s (%d)",
              i, sish, tp->no_redirect);        
      }
      if (tp->no_redirect == -1) {
        tp->no_redirect = 0;
      }
      if (tp->ignore_stderr == -1 && atp && atp->ignore_stderr != -1) {
        tp->ignore_stderr = atp->ignore_stderr;
        vinfo("tester.%d.ignore_stderr inherited from tester.%s (%d)",
              i, sish, tp->ignore_stderr);        
      }
      if (tp->ignore_stderr == -1) {
        tp->ignore_stderr = 0;
      }
      if ((!tp->errorcode_file || !tp->errorcode_file[0]) && atp && atp->errorcode_file && atp->errorcode_file[0]) {
        sformat_message_2(&tp->errorcode_file, 0, atp->errorcode_file,
                        g, tp_prob, NULL, tp, NULL, 0, 0, 0);
        vinfo("tester.%d.errorcode_file inherited from tester.%s ('%s')",
              i, sish, tp->errorcode_file);        
      }

      if (atp && atp->start_env && !tp->any) {
        tp->start_env = sarray_merge_pf(atp->start_env, tp->start_env);
      }
      if (tp->start_env) {
        for (j = 0; tp->start_env[j]; j++) {
          tp->start_env[j] = varsubst_heap(state, tp->start_env[j], 1,
                                           section_global_params,
                                           section_problem_params,
                                           section_language_params,
                                           section_tester_params, NULL, NULL, tp);
          if (!tp->start_env[j]) return -1;
        }
      }

      if (mode == PREPARE_RUN || mode == PREPARE_SERVE) {
        if ((!tp->error_file || !tp->error_file[0]) && atp && atp->error_file && atp->error_file[0]) {
          sformat_message_2(&tp->error_file, 0, atp->error_file,
                          g, tp_prob, NULL, tp, NULL, 0, 0, 0);
          vinfo("tester.%d.error_file inherited from tester.%s ('%s')", i, sish, tp->error_file);
        }
        if (!state->testers[i]->error_file || !state->testers[i]->error_file[0]) {
          vinfo("tester.%d.error_file set to %s", i, DFLT_T_ERROR_FILE);
          xstrdup3(&state->testers[i]->error_file, DFLT_T_ERROR_FILE);
        }
        if ((!tp->start_cmd || !tp->start_cmd[0]) && atp && atp->start_cmd && atp->start_cmd[0]) {
          sformat_message_2(&tp->start_cmd, 0, atp->start_cmd, g, tp_prob, NULL, tp, NULL, 0, 0, 0);
          vinfo("tester.%d.start_cmd inherited from tester.%s ('%s')", i, sish, tp->start_cmd);
        }

        if (tp->start_cmd && tp->start_cmd[0] && !os_IsAbsolutePath(tp->start_cmd)) {
          snprintf(start_path, sizeof(start_path), "%s", tp->start_cmd);
          if (ejudge_config && ejudge_config->compile_home_dir) {
            pathmake2(start_path, ejudge_config->compile_home_dir,
                      "/", "scripts", "/", start_path, NULL);
          } else if (ejudge_config && ejudge_config->contests_home_dir) {
            pathmake2(start_path, ejudge_config->contests_home_dir,
                      "/", "compile", "/", "scripts", "/", start_path, NULL);
          }
#if defined EJUDGE_CONTESTS_HOME_DIR
          else {
            pathmake2(start_path, EJUDGE_CONTESTS_HOME_DIR,
                      "/", "compile", "/", "scripts", "/", start_path, NULL);
          }
#endif
          if (access(start_path, X_OK) >= 0) {
            xstrdup3(&tp->start_cmd, start_path);
          } else {
            if (!os_IsAbsolutePath(tp->start_cmd)) {
              usprintf(&tp->start_cmd, "%s/lang/%s", g->script_dir, tp->start_cmd);
            }
          }
        }

        if ((!tp->prepare_cmd || !tp->prepare_cmd[0]) && atp && atp->prepare_cmd && atp->prepare_cmd[0]) {
          sformat_message_2(&tp->prepare_cmd, 0, atp->prepare_cmd,
                          g, tp_prob, NULL, tp, NULL, 0, 0, 0);
          vinfo("tester.%d.prepare_cmd inherited from tester.%s ('%s')", i, sish, tp->prepare_cmd);
        }
        if (tp->prepare_cmd && tp->prepare_cmd[0] && !os_IsAbsolutePath(tp->prepare_cmd)) {
          usprintf(&tp->prepare_cmd, "%s/lang/%s", g->script_dir, tp->prepare_cmd);
        }

        if ((!tp->nwrun_spool_dir || !tp->nwrun_spool_dir[0]) && atp && atp->nwrun_spool_dir && atp->nwrun_spool_dir[0]) {
          sformat_message_2(&tp->nwrun_spool_dir, 0,atp->nwrun_spool_dir,
                          g, tp_prob, NULL, tp, NULL, 0, 0, 0);
        }
        if (tp->nwrun_spool_dir && tp->nwrun_spool_dir[0]) {
          if (!os_IsAbsolutePath(tp->nwrun_spool_dir)) {
            if (ejudge_config && ejudge_config->contests_home_dir) {
              usprintf(&tp->nwrun_spool_dir, "%s/%s", ejudge_config->contests_home_dir, tp->nwrun_spool_dir);
            } else {
#if defined EJUDGE_CONTESTS_HOME_DIR
              usprintf(&tp->nwrun_spool_dir, "%s/%s", EJUDGE_CONTESTS_HOME_DIR, tp->nwrun_spool_dir);
#endif
            }
          }
        }
      }
    }
  }

#if 0
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
#endif

  // if no problem has long_name, disable it
  g->disable_prob_long_name = 0;
  for (i = 1; i <= state->max_prob; i++) {
    if (!(prob = state->probs[i])) continue;
    if (prob && prob->long_name && prob->long_name[0])
      break;
  }
  if (i > state->max_prob)
    g->disable_prob_long_name = 1;

  // if all problems are output-only, disable number of passed tests
  g->disable_passed_tests = 0;
  for (i = 1; i <= state->max_prob; i++) {
    if (!(prob = state->probs[i])) continue;
    if (prob && prob->type == PROB_TYPE_STANDARD)
      break;
  }
  if (i > state->max_prob)
    g->disable_passed_tests = 1;

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
  int abstr_prob_count = 0, abstr_tester_count = 0;

  state->max_lang = state->max_prob = state->max_tester = 0;

  // process abstract problems and testers
  for (p = state->config; p; p = p->next) {
    if (!strcmp(p->name, "problem") && mode != PREPARE_COMPILE) {
      q = (struct section_problem_data*) p;
      if (q->abstract) abstr_prob_count++;
    } else if (!strcmp(p->name, "tester") && mode != PREPARE_COMPILE) {
      t = (struct section_tester_data *) p;
      if (t->abstract) abstr_tester_count++;
    }
  }
  if (abstr_prob_count > 0) {
    XCALLOC(state->abstr_probs, abstr_prob_count);
  }
  if (abstr_tester_count > 0) {
    XCALLOC(state->abstr_testers, abstr_tester_count);
  }

  // process concrete languages, problems, and testers
  for (p = state->config; p; p = p->next) {
    if (!strcmp(p->name, "language") && mode != PREPARE_RUN) {
      l = (struct section_language_data*) p;
      if (!l->id) vinfo("assigned language id = %d", (l->id = last_lang + 1));
      if (l->id <= 0 || l->id > EJ_MAX_LANG_ID) {
        err("language id %d is out of range", l->id);
        return -1;
      }
      if (l->id > state->max_lang) state->max_lang = l->id;
      last_lang = l->id;
      if (!l->compile_id) l->compile_id = l->id;
    } else if (!strcmp(p->name, "problem") && mode != PREPARE_COMPILE) {
      q = (struct section_problem_data*) p;
      if (q->abstract) continue;
      if (!q->id) vinfo("assigned problem id = %d", (q->id=last_prob + 1));
      if (q->id <= 0 || q->id > EJ_MAX_PROB_ID) {
        err("problem id %d is out of range", q->id);
        return -1;
      }
      if (q->id > state->max_prob) state->max_prob = q->id;
      last_prob = q->id;
      if (!q->tester_id) q->tester_id = q->id;
    } else if (!strcmp(p->name, "tester") && mode != PREPARE_COMPILE) {
      t = (struct section_tester_data *) p;
      if (t->abstract) continue;
      if (!t->id) vinfo("assigned tester id = %d",(t->id = last_tester + 1));
      if (t->id <= 0 || t->id > EJ_MAX_TESTER) {
        err("tester id %d is out of range", t->id);
        return -1;
      }
      if (t->id > state->max_tester) state->max_tester = t->id;
      last_tester = t->id;
    }
  }

  if (state->max_lang > 0) {
    XCALLOC(state->langs, state->max_lang + 1);
  }
  if (state->max_prob > 0) {
    XCALLOC(state->probs, state->max_prob + 1);
  }
  if (state->max_tester > 0) {
    XCALLOC(state->testers, state->max_tester + 1);
  }

  for (p = state->config; p; p = p->next) {
    if (!strcmp(p->name, "language") && mode != PREPARE_RUN) {
      l = (struct section_language_data*) p;
      if (state->langs[l->id]) {
        err("duplicated language id %d", l->id);
        return -1;
      }
      state->langs[l->id] = l;
    } else if (!strcmp(p->name, "problem") && mode != PREPARE_COMPILE) {
      q = (struct section_problem_data*) p;
      if (q->abstract) {
        if (state->max_abstr_prob > EJ_MAX_PROB_ID) {
          err("too many abstract problems");
          return -1;
        }
        state->abstr_probs[state->max_abstr_prob++] = q;
      } else {
        if (state->probs[q->id]) {
          err("duplicated problem id %d", q->id);
          return -1;
        }
        state->probs[q->id] = q;
      }
    } else if (!strcmp(p->name, "tester") && mode != PREPARE_COMPILE) {
      t = (struct section_tester_data *) p;
      if (t->abstract) {
        if (state->max_abstr_tester > EJ_MAX_TESTER) {
          err("too many abstract tester");
          return -1;
        }
        state->abstr_testers[state->max_abstr_tester++] = t;
      } else {
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
            vinfo("tester %d: problem '%s' has id %d",t->id,t->problem_name,j);
            t->problem = j;
          }
        }
        state->testers[t->id] = t;
      }
    }
  }

  return 0;
}

int
create_dirs(serve_state_t state, int mode)
{
  int i;
  struct section_global_data *g = state->global;

  if (mode == PREPARE_SERVE) {
    if (g->root_dir && g->root_dir[0] && make_dir(g->root_dir, 0) < 0) return -1;
    if (make_dir(g->var_dir, 0) < 0) return -1;

    /* COMPILE writes its response here */
    if (make_dir(g->compile_dir, 0) < 0) return -1;
    if (make_all_dir(g->compile_queue_dir, 0777) < 0) return -1;
    if (make_dir(g->compile_src_dir, 0) < 0) return -1;
    // remove possible symlink from previous versions
    // the return code is intentionally ignored
    remove(g->compile_out_dir);
    if (make_dir(g->compile_out_dir, 0) < 0) return -1;
    if (make_all_dir(g->compile_status_dir, 0) < 0) return -1;
    if (make_dir(g->compile_report_dir, 0) < 0) return -1;

    /* RUN writes its response here */
    if (make_dir(g->run_dir, 0) < 0) return -1;
    if (make_all_dir(g->run_queue_dir, 0) < 0) return -1;
    if (make_dir(g->run_exe_dir, 0) < 0) return -1;
    remove(g->run_out_dir);
    if (make_dir(g->run_out_dir, 0) < 0) return -1;
    if (make_all_dir(g->run_status_dir, 0777) < 0) return -1;
    if (make_dir(g->run_report_dir, 0777) < 0) return -1;
    if (g->team_enable_rep_view) {
      if (make_dir(g->run_team_report_dir, 0777) < 0) return -1;
    }
    if (g->enable_full_archive) {
      if (make_dir(g->run_full_archive_dir, 0777) < 0) return -1;
    }

    /* SERVE's status directory */
    if (make_all_dir(g->status_dir, 0) < 0) return -1;

    /* working directory (if somebody needs it) */
    if (make_dir(g->work_dir, 0) < 0) return -1;
    if (make_dir(g->print_work_dir, 0) < 0) return -1;
    if (make_dir(g->diff_work_dir, 0) < 0) return -1;

    /* SERVE's archive directories */
    if (make_dir(g->archive_dir, 0) < 0) return -1;
    if (make_dir(g->clar_archive_dir, 0) < 0) return -1;
    if (make_dir(g->run_archive_dir, 0) < 0) return -1;
    if (make_dir(g->xml_report_archive_dir, 0) < 0) return -1;
    if (make_dir(g->report_archive_dir, 0) < 0) return -1;
    if (make_dir(g->audit_log_dir, 0777) < 0) return -1;
    if (make_dir(g->uuid_archive_dir, 0755) < 0) return -1;
    if (g->team_enable_rep_view) {
      if (make_dir(g->team_report_archive_dir, 0) < 0) return -1;
    }
    if (g->enable_full_archive) {
      if (make_dir(g->full_archive_dir, 0) < 0) return -1;
    }
    if (make_dir(g->team_extra_dir, 0) < 0) return -1;
  } else if (mode == PREPARE_COMPILE) {
    if (g->root_dir && g->root_dir[0] && make_dir(g->root_dir, 0) < 0) return -1;
    if (make_dir(g->var_dir, 0) < 0) return -1;

#if 0
    /* Win program incorrectly parses dir names. Add leading slashes manually*/
    sprintf(bufstr, "/%s", g->compile_dir);
    strcpy(g->compile_dir, bufstr);
    sprintf(bufstr, "/%s", g->compile_queue_dir);
    strcpy(g->compile_queue_dir, bufstr);
    sprintf(bufstr, "/%s", g->compile_src_dir);
    strcpy(g->compile_src_dir, bufstr);
#endif /* __WIN32__ */

    /* COMPILE reads its commands from here */
    if (make_dir(g->compile_dir, 0) < 0) return -1;
    if (make_all_dir(g->compile_queue_dir, 0777) < 0) return -1;
    if (make_dir(g->compile_src_dir, 0) < 0) return -1;

    /* working directory (if somebody needs it) */
    if (make_dir(g->work_dir, 0) < 0) return -1;
    if (os_MakeDirPath(g->compile_work_dir, 0775) < 0) return -1;
  } else if (mode == PREPARE_RUN) {
    if (g->root_dir && g->root_dir[0] && make_dir(g->root_dir, 0) < 0) return -1;
    if (make_dir(g->var_dir, 0) < 0) return -1;

    /* RUN reads its commands from here */
    if (make_dir(g->run_dir, 0) < 0) return -1;
    if (make_all_dir(g->run_queue_dir, 0777) < 0) return -1;
    if (make_dir(g->run_exe_dir, 0) < 0) return -1;

    if (make_dir(g->work_dir, 0) < 0) return -1;
    if (os_MakeDirPath(g->run_work_dir, 0775) < 0) return -1;
    if (os_MakeDirPath(g->run_check_dir, 0) < 0) return -1;
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
    //if (state->testers[i]->any) continue;
    if (mode == PREPARE_SERVE) {
      if (make_dir(state->testers[i]->run_dir, 0) < 0) return -1;
      if (make_all_dir(state->testers[i]->run_queue_dir, 0777) < 0) return -1;
      if (make_dir(state->testers[i]->run_exe_dir, 0) < 0) return -1;
      remove(state->testers[i]->run_out_dir);
      if (make_dir(state->testers[i]->run_out_dir, 0) < 0) return -1;
      if (make_all_dir(state->testers[i]->run_status_dir, 0) < 0) return -1;
      if (make_dir(state->testers[i]->run_report_dir, 0) < 0) return -1;
      if (g->team_enable_rep_view) {
        if (make_dir(state->testers[i]->run_team_report_dir, 0) < 0) return -1;
      }
      if (g->enable_full_archive) {
        if (make_dir(state->testers[i]->run_full_archive_dir, 0) < 0) return -1;
      }
    }
    if (mode == PREPARE_RUN) {
      if (state->testers[i]->any) continue;
      if (make_dir(state->testers[i]->check_dir, 0) < 0) return -1;
    }
  }

  //write_log(0, LOG_INFO, "all directories created");
  return 0;
}

static int
parse_version_string(int *pmajor, int *pminor, int *ppatch, int *pbuild)
{
  const unsigned char *p = compile_version;
  int n, x;

  if (sscanf(p, "%d.%dpre%d #%d%n", pmajor, pminor, ppatch, pbuild, &n) == 4 && !p[n]) {
    *ppatch = -*ppatch;
  } else if (sscanf(p, "%d.%dpre%d%n", pmajor, pminor, ppatch, &n) == 3 && !p[n]) {
    *ppatch = -*ppatch;
    *pbuild = 0;
  } else if (sscanf(p, "%d.%d.%d+ (GIT %x) #%d%n", pmajor, pminor, ppatch, pbuild, &x, &n) == 5 && !p[n]) {
  } else if (sscanf(p, "%d.%d.%d+ (GIT %x)%n", pmajor, pminor, ppatch, pbuild, &n) == 4 && !p[n]) {
  } else if (sscanf(p, "%d.%d.%d+ (SVN r%d) #%d%n", pmajor, pminor, ppatch, pbuild, &x, &n) == 5 && !p[n]) {
  } else if (sscanf(p, "%d.%d.%d+ (SVN r%d)%n", pmajor, pminor, ppatch, pbuild, &n) == 4 && !p[n]) {
  } else if (sscanf(p, "%d.%d.%d #%d%n", pmajor, pminor, ppatch, pbuild, &n)==4 && !p[n]) {
  } else if (sscanf(p, "%d.%d.%d%n", pmajor, pminor, ppatch, &n) == 3 && !p[n]) {
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
prepare(
        const struct contest_desc *cnts,
        serve_state_t state,
        char const *config_file,
        int flags,
        int mode,
        char const *opts,
        int managed_flag,
        const unsigned char **subst_src,
        const unsigned char **subst_dst)
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

  //write_log(0, LOG_INFO, "Loading configuration file");
  state->config = parse_param(config_file, 0, params, 1, ncond_var, cond_vars, 0);
  if (!state->config) return -1;
  write_log(0, LOG_INFO, "configuration file parsed ok");
  if (collect_sections(state, mode) < 0) return -1;

  /*
  if (!state->max_lang && mode == PREPARE_COMPILE) {
    err("no languages specified");
    return -1;
  }
  if (!state->max_prob && mode != PREPARE_COMPILE) {
    err("no problems specified");
    return -1;
  }
  if (!state->max_tester && mode == PREPARE_RUN) {
    err("no testers specified");
    return -1;
  }
  */
  if (set_defaults(cnts, config_file, state, mode, subst_src, subst_dst) < 0) return -1;
  return 0;
}

int
prepare_tester_refinement(serve_state_t state, struct section_tester_data *out,
                          int def_tst_id, int prob_id)
{
  struct section_tester_data *tp, *atp = 0;
  struct section_problem_data *prb;
  int si, j;
  path_t start_path;

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
  }

  memset(out, 0, sizeof(*out));
  tester_init_func((struct generic_section_config*) out);
  out->id = tp->id;
  out->problem = prob_id;

  /* copy architecture */
  strcpy(out->arch, tp->arch);
  if (!out->arch[0] && atp && atp->arch[0]) {
    strcpy(out->arch, atp->arch);
  }

  /* copy key */
  /* FIXME: key currently is not handled properly :-( */
  xstrdup3(&out->key, tp->key);
  if ((!out->key || !out->key[0]) && atp && atp->key && atp->key[0]) {
    xstrdup3(&out->key, atp->key);
  }

  /* generate tester name */
  /* FIXME: does the name matter? */
  /* FIXME: should we use the default tester's name? */
  if (out->arch[0]) {
#if __GNUC__ >= 7
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
    snprintf(out->name, sizeof(out->name), "tst_dflt_%d_%d_%s", out->id, prob_id, out->arch);
  } else {
    snprintf(out->name, sizeof(out->name), "tst_dflt_%d_%d", out->id, prob_id);
  }

  /* copy check_dir */
  xstrdup3(&out->check_dir, tp->check_dir);
  if ((!out->check_dir || !out->check_dir[0]) && atp && atp->check_dir && atp->check_dir[0]) {
    sformat_message_2(&out->check_dir, 0, atp->check_dir, state->global, prb, NULL, out, NULL, 0, 0, 0);
  }
  if (!out->check_dir || !out->check_dir[0]) {
    xstrdup3(&out->check_dir, state->global->run_check_dir);
  }
#if defined EJUDGE_LOCAL_DIR
  if (!os_IsAbsolutePath(out->check_dir)) {
    usprintf(&out->check_dir, "%s/%s", EJUDGE_LOCAL_DIR, out->check_dir);
  }
#endif
  if (!os_IsAbsolutePath(out->check_dir)) {
    usprintf(&out->check_dir, "%s/%s", EJUDGE_CONTESTS_HOME_DIR, out->check_dir);
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

  out->time_limit_adj_millis = tp->time_limit_adj_millis;
  if (out->time_limit_adj_millis == -1 && atp) {
    out->time_limit_adj_millis = atp->time_limit_adj_millis;
  }
  if (out->time_limit_adj_millis == -1) {
    out->time_limit_adj_millis = 0;
  }

  /* copy max_stack_size */
  out->max_stack_size = tp->max_stack_size;
  if (out->max_stack_size == -1L && atp) {
    out->max_stack_size = atp->max_stack_size;
  }
  if (out->max_stack_size == -1L) out->max_stack_size = 0;

  /* copy max_data_size */
  out->max_data_size = tp->max_data_size;
  if (out->max_data_size == -1L && atp) {
    out->max_data_size = atp->max_data_size;
  }
  if (out->max_data_size == -1L) out->max_data_size = 0;

  /* copy max_vm_size */
  out->max_vm_size = tp->max_vm_size;
  if (out->max_vm_size == -1L && atp) {
    out->max_vm_size = atp->max_vm_size;
  }
  if (out->max_vm_size == -1L) out->max_vm_size = 0;

  if (tp->memory_limit_type) {
    out->memory_limit_type_val = prepare_parse_memory_limit_type(tp->memory_limit_type);
    if (out->memory_limit_type_val < 0) {
      err("invalid memory limit type `%s'", tp->memory_limit_type);
      return -1;
    }
  }
  if (out->memory_limit_type_val < 0 && atp) {
    if (atp->memory_limit_type_val < 0 && atp->memory_limit_type) {
      atp->memory_limit_type_val = prepare_parse_memory_limit_type(atp->memory_limit_type);
      if (atp->memory_limit_type_val < 0) {
        err("invalid memory limit type `%s'", atp->memory_limit_type);
        return -1;
      }
    }
    out->memory_limit_type_val = atp->memory_limit_type_val;
  }
  xstrdup3(&out->memory_limit_type, prepare_unparse_memory_limit_type(out->memory_limit_type_val));
  
  if (tp->secure_exec_type) {
    out->secure_exec_type_val = prepare_parse_secure_exec_type(tp->secure_exec_type);
    if (out->secure_exec_type_val < 0) {
      err("invalid secure exec type `%s'", tp->secure_exec_type);
      return -1;
    }
  }
  if (out->secure_exec_type_val < 0 && atp) {
    if (atp->secure_exec_type_val < 0 && atp->secure_exec_type) {
      atp->secure_exec_type_val = prepare_parse_secure_exec_type(atp->secure_exec_type);
      if (atp->secure_exec_type_val < 0) {
        err("invalid secure exec type `%s'", atp->secure_exec_type);
        return -1;
      }
    }
    out->secure_exec_type_val = atp->secure_exec_type_val;
  }
  xstrdup3(&out->secure_exec_type, prepare_unparse_secure_exec_type(out->secure_exec_type_val));

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

  /* copy ignore_stderr */
  out->ignore_stderr = tp->ignore_stderr;
  if (out->ignore_stderr == -1 && atp) {
    out->ignore_stderr = atp->ignore_stderr;
  }
  if (out->ignore_stderr == -1) {
    out->ignore_stderr = 0;
  }

  /* copy kill_signal */
  xstrdup3(&out->kill_signal, tp->kill_signal);
  if ((!out->kill_signal || !out->kill_signal[0]) && atp) {
    xstrdup3(&out->kill_signal, atp->kill_signal);
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
                                        section_tester_params, NULL, NULL, out);
      if (!out->start_env[j]) return -1;
    }
  }

  /* copy checker_env */
  /*
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
  */

  /* copy errorcode_file */
  xstrdup3(&out->errorcode_file, tp->errorcode_file);
  if ((!out->errorcode_file || !out->errorcode_file[0]) && atp && atp->errorcode_file && atp->errorcode_file[0]) {
    sformat_message_2(&out->errorcode_file, 0,
                    atp->errorcode_file, state->global, prb, NULL,
                    out, NULL, 0, 0, 0);
  }

  /* copy error_file */
  xstrdup3(&out->error_file, tp->error_file);
  if ((!out->error_file || !out->error_file[0]) && atp && atp->error_file && atp->error_file[0]) {
    sformat_message_2(&out->error_file, 0,
                    atp->error_file, state->global, prb, NULL, out,
                    NULL, 0, 0, 0);
  }
  if (!out->error_file || !out->error_file[0]) {
    xstrdup3(&out->error_file, DFLT_T_ERROR_FILE);
  }

  /* copy valuer_cmd */
  /*
  if (prb->valuer_cmd[0]) {
    strcpy(out->valuer_cmd, prb->valuer_cmd);
    pathmake2(out->valuer_cmd, state->global->checker_dir, "/", out->valuer_cmd, NULL);
  }
  */

  /* copy start_cmd */
  xstrdup3(&out->start_cmd, tp->start_cmd);
  if ((!out->start_cmd || !out->start_cmd[0]) && atp && atp->start_cmd && atp->start_cmd[0]) {
    sformat_message_2(&out->start_cmd, 0,
                      atp->start_cmd, state->global, prb, NULL, out, NULL,
                      0, 0, 0);
  }

  if (out->start_cmd && out->start_cmd[0] && !os_IsAbsolutePath(out->start_cmd)) {
    snprintf(start_path, sizeof(start_path), "%s", out->start_cmd);
    if (ejudge_config && ejudge_config->compile_home_dir) {
      pathmake2(start_path, ejudge_config->compile_home_dir,
                "/", "scripts", "/", start_path, NULL);
    } else if (ejudge_config && ejudge_config->contests_home_dir) {
      pathmake2(start_path, ejudge_config->contests_home_dir,
                "/", "compile", "/", "scripts", "/", start_path, NULL);
    }
#if defined EJUDGE_CONTESTS_HOME_DIR
    else {
      pathmake2(start_path, EJUDGE_CONTESTS_HOME_DIR,
                "/", "compile", "/", "scripts", "/", start_path, NULL);
    }
#endif /* EJUDGE_CONTESTS_HOME_DIR */
    if (access(start_path, X_OK) >= 0) {
      xstrdup3(&out->start_cmd, start_path);
    } else {
      if (!os_IsAbsolutePath(out->start_cmd)) {
        usprintf(&out->start_cmd, "%s/lang/%s", state->global->script_dir, out->start_cmd);
      }
    }
  }

  /* copy prepare_cmd */
  xstrdup3(&out->prepare_cmd, tp->prepare_cmd);
  if ((!out->prepare_cmd || !out->prepare_cmd[0]) && atp && atp->prepare_cmd && atp->prepare_cmd[0]) {
    sformat_message_2(&out->prepare_cmd, 0,
                    atp->prepare_cmd, state->global, prb, NULL, out,
                    NULL, 0, 0, 0);
  }
  if (out->prepare_cmd && out->prepare_cmd[0] && !os_IsAbsolutePath(out->prepare_cmd)) {
    usprintf(&out->prepare_cmd, "%s/lang/%s", state->global->script_dir, out->prepare_cmd);
  }

  /* copy nwrun_spool_dir */
  xstrdup3(&out->nwrun_spool_dir, tp->nwrun_spool_dir);
  if ((!out->nwrun_spool_dir || !out->nwrun_spool_dir[0]) && atp && atp->nwrun_spool_dir && atp->nwrun_spool_dir[0]) {
    sformat_message_2(&out->nwrun_spool_dir, 0,
                      atp->nwrun_spool_dir, state->global, prb, NULL, out,
                      NULL, 0, 0, 0);
  }
  if (out->nwrun_spool_dir && out->nwrun_spool_dir[0]) {
    if (!os_IsAbsolutePath(out->nwrun_spool_dir)) {
      if (ejudge_config && ejudge_config->contests_home_dir) {
        usprintf(&out->nwrun_spool_dir, "%s/%s", ejudge_config->contests_home_dir, out->nwrun_spool_dir);
      } else {
#if defined EJUDGE_CONTESTS_HOME_DIR
        usprintf(&out->nwrun_spool_dir, "%s/%s", EJUDGE_CONTESTS_HOME_DIR, out->nwrun_spool_dir);
#endif
      }
    }
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
  if (g->use_ac_not_ok < 0) g->use_ac_not_ok = DFLT_G_USE_AC_NOT_OK;
  if (g->team_enable_src_view < 0) g->team_enable_src_view=DFLT_G_TEAM_ENABLE_SRC_VIEW;
  if (g->team_enable_rep_view < 0) g->team_enable_rep_view=DFLT_G_TEAM_ENABLE_REP_VIEW;
  if (g->team_enable_ce_view < 0) g->team_enable_ce_view = DFLT_G_TEAM_ENABLE_CE_VIEW;
  if (g->show_problems_link_before_start < 0) g->show_problems_link_before_start=DFLT_G_SHOW_PROBLEMS_LINK_BEFORE_START;
  if (g->show_problems_link_after_finish < 0) g->show_problems_link_after_finish=DFLT_G_SHOW_PROBLEMS_LINK_AFTER_FINISH;
  if (g->disable_user_standings < 0) g->disable_user_standings=DFLT_G_DISABLE_USER_STANDINGS;
  if (g->disable_language < 0) g->disable_language = DFLT_G_DISABLE_LANGUAGE;
  if (g->problem_navigation < 0) g->problem_navigation = DFLT_G_PROBLEM_NAVIGATION;
  if (g->vertical_navigation < 0) g->vertical_navigation = DFLT_G_VERTICAL_NAVIGATION;
  if (g->disable_virtual_start < 0) g->disable_virtual_start = DFLT_G_DISABLE_VIRTUAL_START;
  if (g->disable_virtual_auto_judge < 0) g->disable_virtual_auto_judge = DFLT_G_DISABLE_VIRTUAL_AUTO_JUDGE;
  if (g->enable_auto_print_protocol < 0) g->enable_auto_print_protocol = DFLT_G_ENABLE_AUTO_PRINT_PROTOCOL;
  if (g->team_show_judge_report < 0)
    g->team_show_judge_report = DFLT_G_TEAM_SHOW_JUDGE_REPORT;
  if (g->disable_clars < 0) g->disable_clars = DFLT_G_DISABLE_CLARS;
  if (g->disable_team_clars < 0) g->disable_team_clars = DFLT_G_DISABLE_TEAM_CLARS;
  if (g->enable_eoln_select < 0) g->enable_eoln_select = 0;
  if (g->start_on_first_login < 0) g->start_on_first_login = 0;
  if (g->enable_virtual_restart < 0) g->enable_virtual_restart = 0;
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
  if (!g->charset || !g->charset[0])
    xstrdup3(&g->charset, DFLT_G_CHARSET);
  if (!g->test_dir)
    xstrdup3(&g->test_dir, DFLT_G_TEST_DIR);
  if (!g->corr_dir)
    xstrdup3(&g->corr_dir, DFLT_G_CORR_DIR);
  if (!g->info_dir)
    xstrdup3(&g->info_dir, DFLT_G_INFO_DIR);
  if (!g->tgz_dir)
    xstrdup3(&g->tgz_dir, DFLT_G_TGZ_DIR);
  if (!g->checker_dir || !g->checker_dir[0]) {
    xstrdup3(&g->checker_dir, DFLT_G_CHECKER_DIR);
  }
  if (!g->statement_dir || !g->statement_dir[0]) {
    xstrdup3(&g->statement_dir, DFLT_G_STATEMENT_DIR);
  }
  if (!g->plugin_dir || !g->plugin_dir[0]) {
    xstrdup3(&g->plugin_dir, DFLT_G_PLUGIN_DIR);
  }

  if (!g->standings_file_name || !g->standings_file_name[0]) {
    xstrdup3(&g->standings_file_name, DFLT_G_STANDINGS_FILE_NAME);
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
  if (g->show_sha1 < 0) g->show_sha1 = 0;
  if (g->show_judge_identity < 0) g->show_judge_identity = 0;
  if (g->report_error_code < 0)
    g->report_error_code = DFLT_G_REPORT_ERROR_CODE;
  if (g->enable_continue < 0)
    g->enable_continue = DFLT_G_ENABLE_CONTINUE;
  if (g->enable_runlog_merge < 0)
    g->enable_runlog_merge = DFLT_G_ENABLE_RUNLOG_MERGE;
  if (g->ignore_success_time < 0)
    g->ignore_success_time = DFLT_G_IGNORE_SUCCESS_TIME;
  if (g->secure_run < 0) g->secure_run = DFLT_G_SECURE_RUN;
  if (g->detect_violations < 0) g->detect_violations = 0;
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
  if (g->printout_uses_login < 0)
    g->printout_uses_login = 0;
  if (g->team_page_quota < 0)
    g->team_page_quota = DFLT_G_TEAM_PAGE_QUOTA;
  if (g->stand_show_warn_number < 0)
    g->stand_show_warn_number = DFLT_G_STAND_SHOW_WARN_NUMBER;
  if (g->stand_fancy_style < 0)
    g->stand_fancy_style = 0;
  if (g->stand_show_ok_time < 0)
    g->stand_show_ok_time = DFLT_G_STAND_SHOW_OK_TIME;
  if (g->stand_use_login < 0)
    g->stand_use_login = DFLT_G_STAND_USE_LOGIN;
  if (g->stand_show_avatar < 0)
    g->stand_show_avatar = 0;
  if (g->stand_show_first_solver < 0)
    g->stand_show_first_solver = 0;
  if (g->advanced_layout < 0)
    g->advanced_layout = 0;
  if (g->uuid_run_store < 0)
    g->uuid_run_store = 0;
  if (g->enable_32bit_checkers < 0)
    g->enable_32bit_checkers = 0;
  if (g->ignore_bom < 0)
    g->ignore_bom = 0;
  if (g->disable_auto_refresh < 0)
    g->disable_auto_refresh = 0;
  if (g->disable_user_database < 0)
    g->disable_user_database = 0;
  if (g->enable_max_stack_size < 0) g->enable_max_stack_size = 0;
}

void
prepare_set_abstr_problem_defaults(struct section_problem_data *prob,
                                   struct section_global_data *global)
{
  if (!prob->abstract) return;

  if (prob->type < 0) prob->type = 0;
  if (prob->scoring_checker < 0) prob->scoring_checker = 0;
  if (prob->enable_checker_token < 0) prob->enable_checker_token = 0;
  if (prob->interactive_valuer < 0) prob->interactive_valuer = 0;
  if (prob->disable_pe < 0) prob->disable_pe = 0;
  if (prob->disable_wtl < 0) prob->disable_wtl = 0;
  if (prob->wtl_is_cf < 0) prob->wtl_is_cf = 0;
  if (prob->manual_checking < 0) prob->manual_checking = 0;
  if (prob->examinator_num < 0) prob->examinator_num = 0;
  if (prob->check_presentation < 0) prob->check_presentation = 0;
  if (prob->use_stdin < 0) prob->use_stdin = 0;
  if (prob->use_stdout < 0) prob->use_stdout = 0;
  if (prob->combined_stdin < 0) prob->combined_stdin = 0;
  if (prob->combined_stdout < 0) prob->combined_stdout = 0;
  if (prob->binary_input < 0) prob->binary_input = DFLT_P_BINARY_INPUT;
  if (prob->binary < 0) prob->binary = 0;
  if (prob->ignore_exit_code < 0) prob->ignore_exit_code = 0;
  if (prob->olympiad_mode < 0) prob->olympiad_mode = 0;
  if (prob->score_latest < 0) prob->score_latest = 0;
  if (prob->score_latest_or_unmarked < 0) prob->score_latest_or_unmarked = 0;
  if (prob->score_latest_marked < 0) prob->score_latest_marked = 0;
  if (prob->score_tokenized < 0) prob->score_tokenized = 0;
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
  if (prob->advance_to_next < 0) prob->advance_to_next = 0;
  if (prob->stand_hide_time < 0) prob->stand_hide_time = 0;
  if (prob->disable_ctrl_chars < 0) prob->disable_ctrl_chars = 0;
  if (prob->valuer_sets_marked < 0) prob->valuer_sets_marked = 0;
  if (prob->ignore_unmarked < 0) prob->ignore_unmarked = 0;
  if (prob->disable_stderr < 0) prob->disable_stderr = 0;
  if (prob->enable_text_form < 0) prob->enable_text_form = 0;
  if (prob->stand_ignore_score < 0) prob->stand_ignore_score = 0;
  if (prob->stand_last_column < 0) prob->stand_last_column = 0;
  if (prob->priority_adjustment == -1000) prob->priority_adjustment = 0;
  if (prob->variant_num < 0) prob->variant_num = 0;
  if (!prob->test_sfx) {
    if (global->test_sfx) {
      xstrdup3(&prob->test_sfx, global->test_sfx);
    }
  }
  if (!prob->corr_sfx) {
    if (global->corr_sfx) {
      xstrdup3(&prob->corr_sfx, global->corr_sfx);
    }
  }
  if (!prob->info_sfx) {
    if (global->info_sfx) {
      xstrdup3(&prob->info_sfx, global->info_sfx);
    } else {
      xstrdup3(&prob->info_sfx, DFLT_G_INFO_SFX);
    }
  }
  if (!prob->tgz_sfx) {
    if (global->tgz_sfx) {
      xstrdup3(&prob->tgz_sfx, global->tgz_sfx);
    } else {
      xstrdup3(&prob->tgz_sfx, DFLT_G_TGZ_SFX);
    }
  }
  if (!prob->tgzdir_sfx) {
    if (global->tgzdir_sfx) {
      xstrdup3(&prob->tgzdir_sfx, global->tgzdir_sfx);
    } else {
      xstrdup3(&prob->tgzdir_sfx, DFLT_G_TGZDIR_SFX);
    }
  }
  if (!prob->test_pat) {
    if (global->test_pat) {
      xstrdup3(&prob->test_pat, global->test_pat);
    }
  }
  if (!prob->corr_pat) {
    if (global->corr_pat) {
      xstrdup3(&prob->corr_pat, global->corr_pat);
    }
  }
  if (!prob->info_pat) {
    if (global->info_pat) {
      xstrdup3(&prob->info_pat, global->info_pat);
    }
  }
  if (!prob->tgz_pat) {
    if (global->tgz_pat) {
      xstrdup3(&prob->tgz_pat, global->tgz_pat);
    }
  }
  if (!prob->tgzdir_pat) {
    if (global->tgzdir_pat) {
      xstrdup3(&prob->tgzdir_pat, global->tgzdir_pat);
    }
  }
}

void
prepare_set_concr_problem_defaults(struct section_problem_data *prob,
                                   struct section_global_data *global)
{
  if (prob->abstract) return;
}

struct section_global_data *
prepare_new_global_section(int contest_id, const unsigned char *root_dir,
                           const struct ejudge_cfg *config)
{
  struct section_global_data *global;

  global = prepare_alloc_global();

  global->score_system = SCORE_ACM;
  global->rounding_mode = SEC_FLOOR;
  global->is_virtual = 0;

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
  global->use_ac_not_ok = DFLT_G_USE_AC_NOT_OK;
  global->team_enable_src_view = DFLT_G_TEAM_ENABLE_SRC_VIEW;
  global->team_enable_rep_view = DFLT_G_TEAM_ENABLE_REP_VIEW;
  global->team_enable_ce_view = 1;
  global->team_show_judge_report = DFLT_G_TEAM_SHOW_JUDGE_REPORT;
  global->disable_clars = DFLT_G_DISABLE_CLARS;
  global->disable_team_clars = DFLT_G_DISABLE_TEAM_CLARS;
  global->enable_eoln_select = 0;
  global->start_on_first_login = 0;
  global->enable_virtual_restart = 0;
  global->max_file_length = DFLT_G_MAX_FILE_LENGTH;
  global->max_line_length = DFLT_G_MAX_LINE_LENGTH;
  global->tests_to_accept = DFLT_G_TESTS_TO_ACCEPT;
  global->ignore_compile_errors = 1;
  global->disable_failed_test_view = DFLT_G_DISABLE_FAILED_TEST_VIEW;
  global->inactivity_timeout = DFLT_G_INACTIVITY_TIMEOUT;
  global->disable_auto_testing = DFLT_G_DISABLE_AUTO_TESTING;
  global->disable_testing = DFLT_G_DISABLE_TESTING;
  global->show_problems_link_before_start = DFLT_G_SHOW_PROBLEMS_LINK_BEFORE_START;
  global->show_problems_link_after_finish = DFLT_G_SHOW_PROBLEMS_LINK_AFTER_FINISH;
  global->disable_user_standings = DFLT_G_DISABLE_USER_STANDINGS;
  global->disable_language = DFLT_G_DISABLE_LANGUAGE;
  global->problem_navigation = 1;
  global->vertical_navigation = DFLT_G_VERTICAL_NAVIGATION;
  global->disable_virtual_start = DFLT_G_DISABLE_VIRTUAL_START;
  global->disable_virtual_auto_judge = DFLT_G_DISABLE_VIRTUAL_AUTO_JUDGE;
  global->enable_auto_print_protocol = DFLT_G_ENABLE_AUTO_PRINT_PROTOCOL;

  global->cr_serialization_key = config->serialization_key;
  global->show_astr_time = DFLT_G_SHOW_ASTR_TIME;
  global->ignore_duplicated_runs = DFLT_G_IGNORE_DUPLICATED_RUNS;
  global->show_sha1 = 0;
  global->show_judge_identity = 0;
  global->report_error_code = DFLT_G_REPORT_ERROR_CODE;
  global->auto_short_problem_name = 0;
  global->enable_continue = DFLT_G_ENABLE_CONTINUE;
  global->checker_real_time_limit = DFLT_G_CHECKER_REAL_TIME_LIMIT;
  global->compile_real_time_limit = DFLT_G_COMPILE_REAL_TIME_LIMIT;
  global->show_deadline = 0;
  global->enable_runlog_merge = 1;
  global->ignore_success_time = DFLT_G_IGNORE_SUCCESS_TIME;
  global->secure_run = 1;
  global->detect_violations = 0;
  global->enable_memory_limit_error = DFLT_G_ENABLE_MEMORY_LIMIT_ERROR;
  global->prune_empty_users = DFLT_G_PRUNE_EMPTY_USERS;
  global->enable_report_upload = DFLT_G_ENABLE_REPORT_UPLOAD;
  global->team_download_time = 0;
  global->cpu_bogomips = cpu_get_bogomips();
  global->use_gzip = DFLT_G_USE_GZIP;
  global->min_gzip_size = DFLT_G_MIN_GZIP_SIZE;
  global->use_dir_hierarchy = DFLT_G_USE_DIR_HIERARCHY;
  global->enable_full_archive = 0;
  global->enable_printing = DFLT_G_ENABLE_PRINTING;
  global->disable_banner_page = DFLT_G_DISABLE_BANNER_PAGE;
  global->printout_uses_login = 0;
  global->team_page_quota = DFLT_G_TEAM_PAGE_QUOTA;
  global->enable_l10n = 1;
  global->stand_fancy_style = 0;
  global->stand_use_login = DFLT_G_STAND_USE_LOGIN;
  global->stand_show_avatar = 0;
  global->stand_show_first_solver = 0;
  global->stand_show_ok_time = DFLT_G_STAND_SHOW_OK_TIME;
  global->stand_show_warn_number = DFLT_G_STAND_SHOW_WARN_NUMBER;
  global->use_ac_not_ok = 0;

  xstrdup3(&global->charset, DFLT_G_CHARSET);

  xstrdup3(&global->root_dir, root_dir);
  xstrdup3(&global->conf_dir, DFLT_G_CONF_DIR);

  global->advanced_layout = 1;

  xstrdup3(&global->test_dir, "../tests");
  xstrdup3(&global->corr_dir, "../tests");
  xstrdup3(&global->info_dir, "../tests");
  xstrdup3(&global->tgz_dir, "../tests");
  xstrdup3(&global->checker_dir, "../checkers");
  xstrdup3(&global->statement_dir, "../statements");
  xstrdup3(&global->plugin_dir, "../plugins");

  xstrdup3(&global->standings_file_name, DFLT_G_STANDINGS_FILE_NAME);
  global->plog_update_time = DFLT_G_PLOG_UPDATE_TIME;

  global->compile_max_vm_size = ~(ej_size64_t) 0;
  global->compile_max_stack_size = ~(ej_size64_t) 0;
  global->compile_max_file_size = ~(ej_size64_t) 0;

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
  GLOBAL_PARAM(contest_stop_cmd, "S"),
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

struct section_problem_data *
prepare_copy_problem(const struct section_problem_data *in)
{
  struct section_problem_data *out = prepare_alloc_problem();

  // copy field-by-field
  out->id = in->id;
  out->tester_id = in->tester_id;
  out->abstract = in->abstract;
  out->type = in->type;
  out->manual_checking = in->manual_checking;
  out->examinator_num = in->examinator_num;
  out->check_presentation = in->check_presentation;
  out->scoring_checker = in->scoring_checker;
  out->enable_checker_token = in->enable_checker_token;
  out->interactive_valuer = in->interactive_valuer;
  out->disable_pe = in->disable_pe;
  out->disable_wtl = in->disable_wtl;
  out->wtl_is_cf = in->wtl_is_cf;
  out->use_stdin = in->use_stdin;
  out->use_stdout = in->use_stdout;
  out->combined_stdin = in->combined_stdin;
  out->combined_stdout = in->combined_stdout;
  out->binary_input = in->binary_input;
  out->binary = in->binary;
  out->ignore_exit_code = in->ignore_exit_code;
  out->olympiad_mode = in->olympiad_mode;
  out->score_latest = in->score_latest;
  out->score_latest_or_unmarked = in->score_latest_or_unmarked;
  out->score_latest_marked = in->score_latest_marked;
  out->score_tokenized = in->score_tokenized;
  out->real_time_limit = in->real_time_limit;
  out->time_limit = in->time_limit;
  out->time_limit_millis = in->time_limit_millis;
  out->use_ac_not_ok = in->use_ac_not_ok;
  out->ignore_prev_ac = in->ignore_prev_ac;
  out->team_enable_rep_view = in->team_enable_rep_view;
  out->team_enable_ce_view = in->team_enable_ce_view;
  out->team_show_judge_report = in->team_show_judge_report;
  out->show_checker_comment = in->show_checker_comment;
  out->ignore_compile_errors = in->ignore_compile_errors;
  out->full_score = in->full_score;
  out->full_user_score = in->full_user_score;
  out->min_score_1 = in->min_score_1;
  out->min_score_2 = in->min_score_2;
  out->variable_full_score = in->variable_full_score;
  out->test_score = in->test_score;
  out->run_penalty = in->run_penalty;
  out->acm_run_penalty = in->acm_run_penalty;
  out->disqualified_penalty = in->disqualified_penalty;
  out->compile_error_penalty = in->compile_error_penalty;
  out->ignore_penalty = in->ignore_penalty;
  out->use_corr = in->use_corr;
  out->use_info = in->use_info;
  out->use_tgz = in->use_tgz;
  out->tests_to_accept = in->tests_to_accept;
  out->accept_partial = in->accept_partial;
  out->min_tests_to_accept = in->min_tests_to_accept;
  out->checker_real_time_limit = in->checker_real_time_limit;
  out->disable_user_submit = in->disable_user_submit;
  out->notify_on_submit = in->notify_on_submit;
  out->disable_tab = in->disable_tab;
  out->unrestricted_statement = in->unrestricted_statement;
  out->restricted_statement = in->restricted_statement;
  out->enable_submit_after_reject = in->enable_submit_after_reject;
  out->hide_file_names = in->hide_file_names;
  out->hide_real_time_limit = in->hide_real_time_limit;
  out->enable_tokens = in->enable_tokens;
  out->tokens_for_user_ac = in->tokens_for_user_ac;
  out->disable_submit_after_ok = in->disable_submit_after_ok;
  out->disable_auto_testing = in->disable_auto_testing;
  out->disable_testing = in->disable_testing;
  out->enable_compilation = in->enable_compilation;
  out->skip_testing = in->skip_testing;
  out->hidden = in->hidden;
  out->priority_adjustment = in->priority_adjustment;
  out->stand_hide_time = in->stand_hide_time;
  out->score_multiplier = in->score_multiplier;
  out->prev_runs_to_show = in->prev_runs_to_show;
  out->max_user_run_count = in->max_user_run_count;
  out->advance_to_next = in->advance_to_next;
  out->disable_ctrl_chars = in->disable_ctrl_chars;
  out->enable_text_form = in->enable_text_form;
  out->stand_ignore_score = in->stand_ignore_score;
  out->stand_last_column = in->stand_last_column;
  out->disable_security = in->disable_security;
  out->enable_suid_run = in->enable_suid_run;
  out->enable_multi_header = in->enable_multi_header;
  out->use_lang_multi_header = in->use_lang_multi_header;
  out->require_any = in->require_any;
  memmove(out->super, in->super, sizeof(out->super));
  memmove(out->short_name, in->short_name, sizeof(out->short_name));
  xstrdup3(&out->long_name, in->long_name);
  xstrdup3(&out->stand_name, in->stand_name);
  xstrdup3(&out->stand_column, in->stand_column);
  xstrdup3(&out->group_name, in->group_name);
  xstrdup3(&out->internal_name, in->internal_name);
  xstrdup3(&out->problem_dir, in->problem_dir);
  xstrdup3(&out->test_dir, in->test_dir);
  xstrdup3(&out->test_sfx, in->test_sfx);
  xstrdup3(&out->corr_dir, in->corr_dir);
  xstrdup3(&out->corr_sfx, in->corr_sfx);
  xstrdup3(&out->info_dir, in->info_dir);
  xstrdup3(&out->info_sfx, in->info_sfx);
  xstrdup3(&out->tgz_dir, in->tgz_dir);
  xstrdup3(&out->tgz_sfx, in->tgz_sfx);
  xstrdup3(&out->tgzdir_sfx, in->tgzdir_sfx);
  xstrdup3(&out->input_file, in->input_file);
  xstrdup3(&out->output_file, in->output_file);
  xstrdup3(&out->test_score_list, in->test_score_list);
  xstrdup3(&out->tokens, in->tokens);
  xstrdup3(&out->umask, in->umask);
  xstrdup3(&out->ok_status, in->ok_status);
  xstrdup3(&out->header_pat, in->header_pat);
  xstrdup3(&out->footer_pat, in->footer_pat);
  xstrdup3(&out->compiler_env_pat, in->compiler_env_pat);
  //out->token_info = NULL;
  xstrdup3(&out->score_tests, in->score_tests);
  xstrdup3(&out->standard_checker, in->standard_checker);
  xstrdup3(&out->spelling, in->spelling);
  xstrdup3(&out->statement_file, in->statement_file);
  xstrdup3(&out->alternatives_file, in->alternatives_file);
  xstrdup3(&out->plugin_file, in->plugin_file);
  xstrdup3(&out->xml_file, in->xml_file);
  xstrdup3(&out->stand_attr, in->stand_attr);
  xstrdup3(&out->source_header, in->source_header);
  xstrdup3(&out->source_footer, in->source_footer);
  out->valuer_sets_marked = in->valuer_sets_marked;
  out->ignore_unmarked = in->ignore_unmarked;
  out->interactor_time_limit = in->interactor_time_limit;
  out->interactor_real_time_limit = in->interactor_real_time_limit;
  out->disable_stderr = in->disable_stderr;
  out->enable_process_group = in->enable_process_group;
  out->hide_variant = in->hide_variant;
  out->enable_testlib_mode = in->enable_testlib_mode;
  xstrdup3(&out->test_pat, in->test_pat);
  xstrdup3(&out->corr_pat, in->corr_pat);
  xstrdup3(&out->info_pat, in->info_pat);
  xstrdup3(&out->tgz_pat, in->tgz_pat);
  xstrdup3(&out->tgzdir_pat, in->tgzdir_pat);
  //out->ntests = 0;
  //out->tscores = NULL;
  //out->x_score_tests = NULL;
  //out->test_sets = NULL;
  //out->ts_total = 0;
  //out->ts_infos = NULL;
  xstrdup3(&out->normalization, in->normalization);
  out->normalization_val = in->normalization_val;
  out->deadline = in->deadline;
  out->start_date = in->start_date;
  out->autoassign_variants = in->autoassign_variants;
  out->variant_num = in->variant_num;
  //out->date_penalty = NULL;
  //out->dp_total = 0;
  //out->dp_infos = NULL;
  //out->group_start_date = NULL;
  //out->group_deadline = NULL;
  //memset(&out->gsd, 0, sizeof(out->gsd));
  //memset(&out->gdl, 0, sizeof(out->gdl));
  //out->disable_language = NULL;
  //out->enable_language = NULL;
  //out->require = NULL;
  //out->provide_ok = NULL;
  out->lang_compiler_env = sarray_copy(in->lang_compiler_env);
  out->checker_env = sarray_copy(in->checker_env);
  out->valuer_env = sarray_copy(in->valuer_env);
  out->interactor_env = sarray_copy(in->interactor_env);
  out->style_checker_env = sarray_copy(in->style_checker_env);
  out->test_checker_env = sarray_copy(in->test_checker_env);
  out->init_env = sarray_copy(in->init_env);
  out->start_env = sarray_copy(in->start_env);
  xstrdup3(&out->check_cmd, in->check_cmd);
  xstrdup3(&out->valuer_cmd, in->valuer_cmd);
  xstrdup3(&out->interactor_cmd, in->interactor_cmd);
  xstrdup3(&out->style_checker_cmd, in->style_checker_cmd);
  xstrdup3(&out->test_checker_cmd, in->test_checker_cmd);
  xstrdup3(&out->init_cmd, in->init_cmd);
  xstrdup3(&out->start_cmd, in->start_cmd);
  xstrdup3(&out->solution_src, in->solution_src);
  xstrdup3(&out->solution_cmd, in->solution_cmd);
  //out->lang_time_adj = NULL;
  //out->lang_time_adj_millis = NULL;
  xstrdup3(&out->super_run_dir, in->super_run_dir);
  out->lang_max_vm_size = sarray_copy(in->lang_max_vm_size);
  out->lang_max_stack_size = sarray_copy(in->lang_max_stack_size);
  out->statement_env = sarray_copy(in->statement_env);
  //out->alternative = NULL;
  //out->personal_deadline = NULL;
  //out->pd_total = 0;
  //out->pd_infos = NULL;
  xstrdup3(&out->score_bonus, in->score_bonus);
  //out->score_bonus_total = 0;
  //out->score_bonus_val = NULL;
  xstrdup3(&out->open_tests, in->open_tests);
  //out->open_tests_count = 0;
  //out->open_tests_val = 0;
  xstrdup3(&out->final_open_tests, in->final_open_tests);
  //out->final_open_tests_count = 0;
  //out->final_open_tests_val = 0;
  xstrdup3(&out->token_open_tests, in->token_open_tests);
  //out->token_open_tests_count = 0;
  //out->token_open_tests_val = 0;
  out->max_vm_size = in->max_vm_size;
  out->max_data_size = in->max_data_size;
  out->max_stack_size = in->max_stack_size;
  out->max_core_size = in->max_core_size;
  out->max_file_size = in->max_file_size;
  out->max_open_file_count = in->max_open_file_count;
  out->max_process_count = in->max_process_count;
  xstrdup3(&out->extid, in->extid);
  //out->unhandled_vars = NULL;
  //out->score_view = NULL;
  //out->score_view_score = NULL;
  //out->score_view_text = NULL;
  //out->xml.p = NULL;

  return out;
}

void
prepare_set_prob_value(
        int field,
        struct section_problem_data *out,
        const struct section_problem_data *abstr,
        const struct section_global_data *global)
{
  path_t tmp_buf;

  switch (field) {
  case CNTSPROB_type:
    if (out->type < 0 && abstr) out->type = abstr->type;
    if (out->type < 0) out->type = 0;
    if (out->type >= PROB_TYPE_LAST) out->type = 0;
    break;

#define INHERIT_BOOLEAN(f) case CNTSPROB_##f: if (out->f < 0 && abstr) out->f = abstr->f; if (out->f < 0) out->f = 0; if (out->f > 0) out->f = 1; break

  INHERIT_BOOLEAN(scoring_checker);
  INHERIT_BOOLEAN(enable_checker_token);
  INHERIT_BOOLEAN(interactive_valuer);
  INHERIT_BOOLEAN(disable_pe);
  INHERIT_BOOLEAN(disable_wtl);
  INHERIT_BOOLEAN(wtl_is_cf);
  INHERIT_BOOLEAN(manual_checking);

  case CNTSPROB_problem_dir:
    if (abstr && abstr->problem_dir && abstr->problem_dir[0] == '/'
        && out->problem_dir && *out->problem_dir && *out->problem_dir != '/' && *out->problem_dir != '.') {
      usprintf(&out->problem_dir, "%s/%s", abstr->problem_dir, out->problem_dir);
    }
    break;

  case CNTSPROB_examinator_num:
    if (out->examinator_num < 0 && abstr) out->examinator_num = abstr->examinator_num;
    if (out->manual_checking < 0) out->manual_checking = 0;
    break;

  INHERIT_BOOLEAN(check_presentation);
  INHERIT_BOOLEAN(use_stdin);
  INHERIT_BOOLEAN(use_stdout);
  INHERIT_BOOLEAN(combined_stdin);
  INHERIT_BOOLEAN(combined_stdout);
  INHERIT_BOOLEAN(binary_input);
  INHERIT_BOOLEAN(binary);
  INHERIT_BOOLEAN(ignore_exit_code);
  INHERIT_BOOLEAN(olympiad_mode);
  INHERIT_BOOLEAN(score_latest);
  INHERIT_BOOLEAN(score_latest_or_unmarked);
  INHERIT_BOOLEAN(score_latest_marked);
  INHERIT_BOOLEAN(score_tokenized);

  case CNTSPROB_time_limit:
    if (out->time_limit < 0 && abstr) out->time_limit = abstr->time_limit;
    if (out->time_limit < 0) out->time_limit = 0;
    break;

  case CNTSPROB_time_limit_millis:
    if (out->time_limit_millis < 0 && abstr) out->time_limit_millis = abstr->time_limit_millis;
    if (out->time_limit_millis < 0) out->time_limit_millis = 0;
    break;

  case CNTSPROB_real_time_limit:
    if (out->real_time_limit < 0 && abstr) out->real_time_limit = abstr->real_time_limit;
    if (out->real_time_limit < 0) out->real_time_limit = 0;
    break;

  case CNTSPROB_interactor_time_limit:
    if (out->interactor_time_limit < 0 && abstr) out->interactor_time_limit = abstr->interactor_time_limit;
    if (out->interactor_time_limit < 0) out->interactor_time_limit = 0;
    break;

  case CNTSPROB_interactor_real_time_limit:
    if (out->interactor_real_time_limit < 0 && abstr) out->interactor_real_time_limit = abstr->interactor_real_time_limit;
    if (out->interactor_real_time_limit < 0) out->interactor_real_time_limit = 0;
    break;

#define INHERIT_BOOLEAN_2(f) case CNTSPROB_##f: if (out->f < 0 && abstr) out->f = abstr->f; if (out->f < 0 && global) out->f = global->f; if (out->f < 0) out->f = 0; if (out->f > 0) out->f = 1; break

  INHERIT_BOOLEAN_2(use_ac_not_ok);

  case CNTSPROB_ok_status:
    if (!out->ok_status && abstr && abstr->ok_status) {
      out->ok_status = xstrdup(abstr->ok_status);
    }
    break;
  case CNTSPROB_header_pat:
    if (!out->header_pat && abstr && abstr->header_pat) {
      out->header_pat = xstrdup(abstr->header_pat);
    }
    break;
  case CNTSPROB_footer_pat:
    if (!out->footer_pat && abstr && abstr->footer_pat) {
      out->footer_pat = xstrdup(abstr->footer_pat);
    }
    break;
  case CNTSPROB_compiler_env_pat:
    if (!out->compiler_env_pat && abstr && abstr->compiler_env_pat) {
      out->compiler_env_pat = xstrdup(abstr->compiler_env_pat);
    }
    break;

  INHERIT_BOOLEAN(ignore_prev_ac);
  INHERIT_BOOLEAN_2(team_enable_rep_view);
  INHERIT_BOOLEAN_2(team_enable_ce_view);
  INHERIT_BOOLEAN_2(team_show_judge_report);
  INHERIT_BOOLEAN(show_checker_comment);
  INHERIT_BOOLEAN_2(ignore_compile_errors);
  INHERIT_BOOLEAN(disable_user_submit);
  INHERIT_BOOLEAN(notify_on_submit);
  INHERIT_BOOLEAN(disable_tab);
  INHERIT_BOOLEAN(unrestricted_statement);
  INHERIT_BOOLEAN(enable_submit_after_reject);
  INHERIT_BOOLEAN(hide_file_names);
  INHERIT_BOOLEAN(hide_real_time_limit);
  INHERIT_BOOLEAN(enable_tokens);
  INHERIT_BOOLEAN(tokens_for_user_ac);
  INHERIT_BOOLEAN_2(disable_submit_after_ok);
  INHERIT_BOOLEAN(disable_security);
  INHERIT_BOOLEAN(enable_suid_run);
  INHERIT_BOOLEAN(enable_multi_header);
  INHERIT_BOOLEAN(use_lang_multi_header);
  INHERIT_BOOLEAN(require_any);
  INHERIT_BOOLEAN_2(disable_testing);
  INHERIT_BOOLEAN_2(disable_auto_testing);
  INHERIT_BOOLEAN(enable_compilation);
  INHERIT_BOOLEAN(skip_testing);

  case CNTSPROB_max_user_run_count:
    if (out->max_user_run_count < 0 && abstr) out->max_user_run_count = abstr->max_user_run_count;
    if (out->max_user_run_count < 0) out->max_user_run_count = 0;
    break;

  case CNTSPROB_full_score:
    if (out->full_score < 0 && abstr) out->full_score = abstr->full_score;
    if (out->full_score < 0) out->full_score = DFLT_P_FULL_SCORE;
    break;

  case CNTSPROB_full_user_score:
    if (out->full_user_score < 0 && abstr) out->full_user_score = abstr->full_user_score;
    break;

  case CNTSPROB_min_score_1:
    if (out->min_score_1 < 0 && abstr) out->min_score_1 = abstr->min_score_1;
    break;

  case CNTSPROB_min_score_2:
    if (out->min_score_2 < 0 && abstr) out->min_score_2 = abstr->min_score_2;
    break;

  case CNTSPROB_test_score:
    if (out->test_score < 0 && abstr) out->test_score = abstr->test_score;
    if (out->test_score < 0) out->test_score = DFLT_P_TEST_SCORE;
    break;

  case CNTSPROB_run_penalty:
    if (out->run_penalty < 0 && abstr) out->run_penalty = abstr->run_penalty;
    if (out->run_penalty < 0) out->run_penalty = DFLT_P_RUN_PENALTY;
    break;

  case CNTSPROB_acm_run_penalty:
    if (out->acm_run_penalty < 0 && abstr) out->acm_run_penalty = abstr->acm_run_penalty;
    if (out->acm_run_penalty < 0) out->acm_run_penalty = DFLT_P_ACM_RUN_PENALTY;
    break;

  case CNTSPROB_disqualified_penalty:
    if (out->disqualified_penalty < 0 && abstr) out->disqualified_penalty = abstr->disqualified_penalty;
    if (out->disqualified_penalty < 0) out->disqualified_penalty = DFLT_P_RUN_PENALTY;;
    break;

  case CNTSPROB_compile_error_penalty:
    if (out->compile_error_penalty < 0 && abstr) out->compile_error_penalty = abstr->compile_error_penalty;
    break;

  INHERIT_BOOLEAN(variable_full_score);

  case CNTSPROB_tests_to_accept:
    if (out->tests_to_accept < 0 && abstr) out->tests_to_accept = abstr->tests_to_accept;
    if (out->tests_to_accept < 0 && global) out->tests_to_accept = global->tests_to_accept;
    if (out->tests_to_accept < 0) out->tests_to_accept = DFLT_G_TESTS_TO_ACCEPT;
    break;

  INHERIT_BOOLEAN(accept_partial);

  case CNTSPROB_min_tests_to_accept:
    if (out->min_tests_to_accept < 0 && abstr) out->min_tests_to_accept = abstr->min_tests_to_accept;
    break;

  INHERIT_BOOLEAN(hidden);
  INHERIT_BOOLEAN(advance_to_next);
  INHERIT_BOOLEAN(stand_hide_time);
  INHERIT_BOOLEAN(disable_ctrl_chars);
  INHERIT_BOOLEAN(valuer_sets_marked);
  INHERIT_BOOLEAN(ignore_unmarked);
  INHERIT_BOOLEAN(disable_stderr);
  INHERIT_BOOLEAN(enable_process_group);
  INHERIT_BOOLEAN(enable_testlib_mode);
  INHERIT_BOOLEAN(hide_variant);
  INHERIT_BOOLEAN(autoassign_variants);
  INHERIT_BOOLEAN(enable_text_form);
  INHERIT_BOOLEAN(stand_ignore_score);
  INHERIT_BOOLEAN(stand_last_column);

  case CNTSPROB_checker_real_time_limit:
    if (out->checker_real_time_limit < 0 && abstr) out->checker_real_time_limit = abstr->checker_real_time_limit;
    if (out->checker_real_time_limit < 0 && global) out->checker_real_time_limit = global->checker_real_time_limit;
    if (out->checker_real_time_limit < 0) out->checker_real_time_limit = DFLT_G_CHECKER_REAL_TIME_LIMIT;
    break;

  case CNTSPROB_max_vm_size:
    if (out->max_vm_size < 0 && abstr) out->max_vm_size = abstr->max_vm_size;
    break;

  case CNTSPROB_max_stack_size:
    if (out->max_stack_size < 0 && abstr) out->max_stack_size = abstr->max_stack_size;
    break;

  case CNTSPROB_max_data_size:
    if (out->max_data_size < 0 && abstr) out->max_data_size = abstr->max_data_size;
    break;

  case CNTSPROB_max_core_size:
    if (out->max_core_size < 0 && abstr) out->max_core_size = abstr->max_core_size;
    break;

  case CNTSPROB_max_file_size:
    if (out->max_file_size < 0 && abstr) out->max_file_size = abstr->max_file_size;
    break;

  case CNTSPROB_max_open_file_count:
    if (out->max_open_file_count < 0 && abstr) out->max_open_file_count = abstr->max_open_file_count;
    break;

  case CNTSPROB_max_process_count:
    if (out->max_process_count < 0 && abstr) out->max_process_count = abstr->max_process_count;
    break;

  case CNTSPROB_input_file:
    if (!out->input_file && abstr && abstr->input_file) {
      sformat_message_2(&out->input_file, 0, abstr->input_file,
                        NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->input_file || !out->input_file[0]) {
      xstrdup3(&out->input_file, DFLT_P_INPUT_FILE);
    }
    break;

  case CNTSPROB_output_file:
    if (!out->output_file && abstr && abstr->output_file) {
      sformat_message_2(&out->output_file, 0, abstr->output_file,
                        NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->output_file || !out->output_file[0]) {
      xstrdup3(&out->output_file, DFLT_P_OUTPUT_FILE);
    }
    break;

  case CNTSPROB_use_corr:
    if (out->use_corr < 0 && abstr) out->use_corr = abstr->use_corr;
    if (out->use_corr < 0 && out->corr_dir) out->use_corr = 1;
    if (out->use_corr < 0) out->use_corr = 0;
    if (out->use_corr > 0) out->use_corr = 1;
    break;

  INHERIT_BOOLEAN(use_info);
  INHERIT_BOOLEAN(use_tgz);

  case CNTSPROB_test_dir:
    if (!out->test_dir && abstr && abstr->test_dir) {
      sformat_message_2(&out->test_dir, 0, abstr->test_dir, NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->test_dir) {
      xstrdup3(&out->test_dir, out->short_name);
    }
    if (global && out->test_dir && out->test_dir[0]) {
      if (!os_IsAbsolutePath(out->test_dir)) {
        usprintf(&out->test_dir, "%s/%s", global->test_dir, out->test_dir);
      }
    }
    break;

  case CNTSPROB_corr_dir:
    if (!out->corr_dir && abstr && abstr->corr_dir) {
      sformat_message_2(&out->corr_dir, 0, abstr->corr_dir, NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->corr_dir && out->corr_dir[0]) {
      if (!os_IsAbsolutePath(out->corr_dir)) {
        usprintf(&out->corr_dir, "%s/%s", global->corr_dir, out->corr_dir);
      }
    }
    break;

  case CNTSPROB_info_dir:
    if (!out->info_dir && abstr && abstr->info_dir) {
      sformat_message_2(&out->info_dir, 0, abstr->info_dir, NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->info_dir) {
      xstrdup3(&out->info_dir, out->short_name);
    }
    if (global && out->info_dir && !os_IsAbsolutePath(out->info_dir)) {
      usprintf(&out->info_dir, "%s/%s", global->info_dir, out->info_dir);
    }
    break;

  case CNTSPROB_tgz_dir:
    if (!out->tgz_dir && abstr && abstr->tgz_dir) {
      sformat_message_2(&out->tgz_dir, 0, abstr->tgz_dir, NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (!out->tgz_dir) {
      xstrdup3(&out->tgz_dir, out->short_name);
    }
    if (global && out->tgz_dir && !os_IsAbsolutePath(out->tgz_dir)) {
      usprintf(&out->tgz_dir, "%s/%s", global->tgz_dir, out->tgz_dir);
    }
    break;

  case CNTSPROB_test_sfx:
    if (!out->test_sfx && abstr && abstr->test_sfx) {
      xstrdup3(&out->test_sfx, abstr->test_sfx);
    }
    if (!out->test_sfx && global && global->test_sfx) {
      xstrdup3(&out->test_sfx, global->test_sfx);
    }
    break;

  case CNTSPROB_corr_sfx:
    if (!out->corr_sfx && abstr && abstr->corr_sfx) {
      xstrdup3(&out->corr_sfx, abstr->corr_sfx);
    }
    if (!out->corr_sfx && global && global->corr_sfx) {
      xstrdup3(&out->corr_sfx, global->corr_sfx);
    }
    break;

  case CNTSPROB_info_sfx:
    if (!out->info_sfx && abstr && abstr->info_sfx) {
      xstrdup3(&out->info_sfx, abstr->info_sfx);
    }
    if (!out->info_sfx && global && global->info_sfx) {
      xstrdup3(&out->info_sfx, global->info_sfx);
    }
    if (!out->info_sfx) {
      xstrdup3(&out->info_sfx, DFLT_G_INFO_SFX);
    }
    break;

  case CNTSPROB_tgz_sfx:
    if (!out->tgz_sfx && abstr && abstr->tgz_sfx) {
      xstrdup3(&out->tgz_sfx, abstr->tgz_sfx);
    }
    if (!out->tgz_sfx && global && global->tgz_sfx) {
      xstrdup3(&out->tgz_sfx, global->tgz_sfx);
    }
    if (!out->tgz_sfx) {
      xstrdup3(&out->tgz_sfx, DFLT_G_TGZ_SFX);
    }
    break;

  case CNTSPROB_tgzdir_sfx:
    if (!out->tgzdir_sfx && abstr && abstr->tgzdir_sfx) {
      xstrdup3(&out->tgzdir_sfx, abstr->tgzdir_sfx);
    }
    if (!out->tgzdir_sfx && global && global->tgzdir_sfx) {
      xstrdup3(&out->tgzdir_sfx, global->tgzdir_sfx);
    }
    if (!out->tgzdir_sfx) {
      xstrdup3(&out->tgzdir_sfx, DFLT_G_TGZDIR_SFX);
    }
    break;

  case CNTSPROB_test_pat:
    if (!out->test_pat && abstr && abstr->test_pat) {
      xstrdup3(&out->test_pat, abstr->test_pat);
    }
    if (!out->test_pat && global && global->test_pat) {
      xstrdup3(&out->test_pat, global->test_pat);
    }
    break;

  case CNTSPROB_corr_pat:
    if (!out->corr_pat && abstr && abstr->corr_pat) {
      xstrdup3(&out->corr_pat, abstr->corr_pat);
    }
    if (!out->corr_pat && global && global->corr_pat) {
      xstrdup3(&out->corr_pat, global->corr_pat);
    }
    break;

  case CNTSPROB_info_pat:
    if (!out->info_pat && abstr && abstr->info_pat) {
      xstrdup3(&out->info_pat, abstr->info_pat);
    }
    if (!out->info_pat && global && global->info_pat) {
      xstrdup3(&out->info_pat, global->info_pat);
    }
    break;

  case CNTSPROB_tgz_pat:
    if (!out->tgz_pat && abstr && abstr->tgz_pat) {
      xstrdup3(&out->tgz_pat, abstr->tgz_pat);
    }
    if (!out->tgz_pat && global && global->tgz_pat) {
      xstrdup3(&out->tgz_pat, global->tgz_pat);
    }
    break;

  case CNTSPROB_tgzdir_pat:
    if (!out->tgzdir_pat && abstr && abstr->tgzdir_pat) {
      xstrdup3(&out->tgzdir_pat, abstr->tgzdir_pat);
    }
    if (!out->tgzdir_pat && global && global->tgzdir_pat) {
      xstrdup3(&out->tgzdir_pat, global->tgzdir_pat);
    }
    break;

  case CNTSPROB_score_bonus:
    if (!out->score_bonus && abstr && abstr->score_bonus) {
      xstrdup3(&out->score_bonus, abstr->score_bonus);
    }
    /*
    if (state->probs[i]->score_bonus[0]) {
    if (parse_score_bonus(state->probs[i]->score_bonus, &state->probs[i]->score_bonus_total,
                              &state->probs[i]->score_bonus_val) < 0) return -1;
      }
    */
    break;

  case CNTSPROB_check_cmd:
    if (!out->check_cmd && abstr && abstr->check_cmd) {
      sformat_message_2(&out->check_cmd, 0, abstr->check_cmd, NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    /*
    if (global) {
      pathmake2(out->check_cmd, global->checker_dir, "/", out->check_cmd, NULL);
    }
    */
    break;

  case CNTSPROB_valuer_cmd:
    if (!out->valuer_cmd && abstr && abstr->valuer_cmd) {
      sformat_message_2(&out->valuer_cmd, 0, abstr->valuer_cmd, NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->valuer_cmd && out->valuer_cmd[0] && global->advanced_layout <= 0) {
      if (!os_IsAbsolutePath(out->valuer_cmd)) {
        usprintf(&out->valuer_cmd, "%s/%s", global->checker_dir, out->valuer_cmd);
      }
    }
    break;

  case CNTSPROB_interactor_cmd:
    if ((!out->interactor_cmd || !out->interactor_cmd[0]) && abstr && abstr->interactor_cmd && abstr->interactor_cmd[0]) {
      sformat_message_2(&out->interactor_cmd, 0, abstr->interactor_cmd, NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->interactor_cmd && out->interactor_cmd[0] && global->advanced_layout <= 0) {
      if (!os_IsAbsolutePath(out->interactor_cmd)) {
        usprintf(&out->interactor_cmd, "%s/%s", global->checker_dir, out->interactor_cmd);
      }
    }
    break;

  case CNTSPROB_style_checker_cmd:
    if ((!out->style_checker_cmd || !out->style_checker_cmd[0]) && abstr && abstr->style_checker_cmd && abstr->style_checker_cmd[0]) {
      sformat_message_2(&out->style_checker_cmd, 0, abstr->style_checker_cmd, NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->style_checker_cmd && out->style_checker_cmd[0] && global->advanced_layout <= 0) {
      if (!os_IsAbsolutePath(out->style_checker_cmd)) {
        usprintf(&out->style_checker_cmd, "%s/%s", global->checker_dir, out->style_checker_cmd);
      }
    }
    break;

  case CNTSPROB_test_checker_cmd:
    if (!out->test_checker_cmd && abstr && abstr->test_checker_cmd) {
      sformat_message(tmp_buf, sizeof(tmp_buf), 0, abstr->test_checker_cmd, NULL, out, NULL, NULL, NULL, 0, 0, 0);
      out->test_checker_cmd = xstrdup(tmp_buf);
    }
    if (out->test_checker_cmd && out->test_checker_cmd[0]
        && global && global->advanced_layout <= 0
        && !os_IsAbsolutePath(out->test_checker_cmd)) {
      usprintf(&out->test_checker_cmd, "%s/%s", global->checker_dir, out->test_checker_cmd);
    }
    break;

  case CNTSPROB_init_cmd:
    if (!out->init_cmd && abstr && abstr->init_cmd) {
      sformat_message(tmp_buf, sizeof(tmp_buf), 0, abstr->init_cmd,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
      out->init_cmd = xstrdup(tmp_buf);
    }
    if (out->init_cmd && out->init_cmd[0]
        && global && global->advanced_layout <= 0
        && !os_IsAbsolutePath(out->init_cmd)) {
      usprintf(&out->init_cmd, "%s/%s", global->checker_dir, out->init_cmd);
    }
    break;

  case CNTSPROB_start_cmd:
    if (!out->start_cmd && abstr && abstr->start_cmd) {
      sformat_message(tmp_buf, sizeof(tmp_buf), 0, abstr->start_cmd,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
      out->start_cmd = xstrdup(tmp_buf);
    }
    if (out->start_cmd && out->start_cmd[0]
        && global && global->advanced_layout <= 0
        && !os_IsAbsolutePath(out->start_cmd)) {
      usprintf(&out->start_cmd, "%s/%s", global->checker_dir, out->start_cmd);
    }
    break;

  case CNTSPROB_solution_src:
    if (!out->solution_src && abstr && abstr->solution_src) {
      sformat_message(tmp_buf, sizeof(tmp_buf), 0, abstr->solution_src,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
      out->solution_src = xstrdup(tmp_buf);
    }
    if (out->solution_src && out->solution_src[0]
        && global && global->advanced_layout <= 0
        && !os_IsAbsolutePath(out->solution_src)) {
      usprintf(&out->solution_src, "%s/%s", global->checker_dir, out->solution_src);
    }
    break;

  case CNTSPROB_solution_cmd:
    if (!out->solution_cmd && abstr && abstr->solution_cmd) {
      sformat_message(tmp_buf, sizeof(tmp_buf), 0, abstr->solution_cmd,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
      out->solution_cmd = xstrdup(tmp_buf);
    }
    if (out->solution_cmd && out->solution_cmd[0]
        && global && global->advanced_layout <= 0
        && !os_IsAbsolutePath(out->solution_cmd)) {
      usprintf(&out->solution_cmd, "%s/%s", global->checker_dir, out->solution_cmd);
    }
    break;

  case CNTSPROB_statement_file:
    if (!out->statement_file && abstr && abstr->statement_file) {
      sformat_message_2(&out->statement_file, 0, abstr->statement_file,
                        NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->statement_file && out->statement_file[0]) {
      if (!os_IsAbsolutePath(out->statement_file)) {
        usprintf(&out->statement_file, "%s/%s", global->statement_dir, out->statement_file);
      }
    }
    break;

  case CNTSPROB_alternatives_file:
    if (!out->alternatives_file && abstr && abstr->alternatives_file) {
      sformat_message_2(&out->alternatives_file, 0, abstr->alternatives_file,
                        NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->alternatives_file && out->alternatives_file[0]) {
      if (!os_IsAbsolutePath(out->alternatives_file)) {
        usprintf(&out->alternatives_file, "%s/%s", global->statement_dir, out->alternatives_file);
      }
    }
    break;

  case CNTSPROB_plugin_file:
    if (!out->plugin_file && abstr && abstr->plugin_file) {
      sformat_message_2(&out->plugin_file, 0, abstr->plugin_file,
                        NULL, out, NULL, NULL, NULL, 0, 0, 0);
    }
    if (global && out->plugin_file && out->plugin_file[0] && global->advanced_layout <= 0) {
      if (!os_IsAbsolutePath(out->plugin_file)) {
        usprintf(&out->plugin_file, "%s/%s", global->statement_dir, out->plugin_file);
      }
    }
    break;

  case CNTSPROB_super_run_dir:
    if (!out->super_run_dir && abstr && abstr->super_run_dir) {
      sformat_message(tmp_buf, sizeof(tmp_buf), 0, abstr->super_run_dir,
                      NULL, out, NULL, NULL, NULL, 0, 0, 0);
      out->super_run_dir = xstrdup(tmp_buf);
    }
    break;

  case CNTSPROB_stand_attr:
    if (!out->stand_attr && abstr && abstr->stand_attr) {
      xstrdup3(&out->stand_attr, abstr->stand_attr);
    }
    break;

  case CNTSPROB_source_header:
    if (!out->source_header && abstr && abstr->source_header) {
      xstrdup3(&out->source_header, abstr->source_header);
    }
    break;

  case CNTSPROB_source_footer:
    if (!out->source_footer && abstr && abstr->source_footer) {
      xstrdup3(&out->source_footer, abstr->source_footer);
    }
    break;

  case CNTSPROB_normalization:
    if (!out->normalization && abstr && abstr->normalization) {
      xstrdup3(&out->normalization, abstr->normalization);
    }
    break;

  case CNTSPROB_xml_file:
    if (!out->xml_file && abstr && abstr->xml_file) {
      sformat_message_2(&out->xml_file, 0, abstr->xml_file, 0, out, 0, 0, 0, 0, 0, 0);
    }
    if (global && out->xml_file && out->xml_file[0] && global->advanced_layout <= 0) {
      if (!os_IsAbsolutePath(out->xml_file)) {
        usprintf(&out->xml_file, "%s/%s", global->statement_dir, out->xml_file);
      }
    }
    break;

  case CNTSPROB_open_tests:
    break;

  case CNTSPROB_final_open_tests:
    break;

  case CNTSPROB_token_open_tests:
    break;

  default:
    abort();
  }
}

void
prepare_set_all_prob_values(
        struct section_problem_data *out,
        const struct section_problem_data *abstr,
        const struct section_global_data *global)
{
  static int fields[] =
  {
    CNTSPROB_type,
    CNTSPROB_manual_checking,
    CNTSPROB_examinator_num,
    CNTSPROB_check_presentation,
    CNTSPROB_scoring_checker,
    CNTSPROB_enable_checker_token,
    CNTSPROB_interactive_valuer,
    CNTSPROB_disable_pe,
    CNTSPROB_disable_wtl,
    CNTSPROB_wtl_is_cf,
    CNTSPROB_use_stdin,
    CNTSPROB_use_stdout,
    CNTSPROB_combined_stdin,
    CNTSPROB_combined_stdout,
    CNTSPROB_binary_input,
    CNTSPROB_binary,
    CNTSPROB_ignore_exit_code,
    CNTSPROB_olympiad_mode,
    CNTSPROB_score_latest,
    CNTSPROB_score_latest_or_unmarked,
    CNTSPROB_score_latest_marked,
    CNTSPROB_score_tokenized,
    CNTSPROB_real_time_limit,
    CNTSPROB_time_limit,
    CNTSPROB_time_limit_millis,
    CNTSPROB_use_ac_not_ok,
    CNTSPROB_ignore_prev_ac,
    CNTSPROB_team_enable_rep_view,
    CNTSPROB_team_enable_ce_view,
    CNTSPROB_team_show_judge_report,
    CNTSPROB_show_checker_comment,
    CNTSPROB_ignore_compile_errors,
    CNTSPROB_full_score,
    CNTSPROB_full_user_score,
    CNTSPROB_min_score_1,
    CNTSPROB_min_score_2,
    CNTSPROB_variable_full_score,
    CNTSPROB_test_score,
    CNTSPROB_run_penalty,
    CNTSPROB_acm_run_penalty,
    CNTSPROB_disqualified_penalty,
    CNTSPROB_compile_error_penalty,
    //CNTSPROB_ignore_penalty,
    CNTSPROB_use_corr,
    CNTSPROB_use_info,
    CNTSPROB_use_tgz,
    CNTSPROB_tests_to_accept,
    CNTSPROB_accept_partial,
    CNTSPROB_min_tests_to_accept,
    CNTSPROB_checker_real_time_limit,
    CNTSPROB_disable_user_submit,
    CNTSPROB_notify_on_submit,
    CNTSPROB_disable_tab,
    CNTSPROB_unrestricted_statement,
    CNTSPROB_enable_submit_after_reject,
    CNTSPROB_hide_file_names,
    CNTSPROB_hide_real_time_limit,
    CNTSPROB_enable_tokens,
    CNTSPROB_tokens_for_user_ac,
    CNTSPROB_disable_submit_after_ok,
    CNTSPROB_disable_auto_testing,
    CNTSPROB_disable_testing,
    CNTSPROB_enable_compilation,
    CNTSPROB_skip_testing,
    CNTSPROB_hidden,
    //CNTSPROB_priority_adjustment,
    CNTSPROB_stand_hide_time,
    //CNTSPROB_score_multiplier,
    //CNTSPROB_prev_runs_to_show,
    CNTSPROB_max_user_run_count,
    CNTSPROB_advance_to_next,
    CNTSPROB_disable_ctrl_chars,
    CNTSPROB_enable_text_form,
    CNTSPROB_stand_ignore_score,
    CNTSPROB_stand_last_column,
    CNTSPROB_disable_security,
    CNTSPROB_enable_suid_run,
    CNTSPROB_enable_multi_header,
    CNTSPROB_use_lang_multi_header,
    CNTSPROB_require_any,
    //CNTSPROB_super,
    //CNTSPROB_short_name,
    //CNTSPROB_long_name,
    //CNTSPROB_stand_name,
    //CNTSPROB_stand_column,
    //CNTSPROB_group_name,
    //CNTSPROB_internal_name,
    CNTSPROB_test_dir,
    CNTSPROB_test_sfx,
    CNTSPROB_corr_dir,
    CNTSPROB_corr_sfx,
    CNTSPROB_info_dir,
    CNTSPROB_info_sfx,
    CNTSPROB_tgz_dir,
    CNTSPROB_tgz_sfx,
    CNTSPROB_tgzdir_sfx,
    CNTSPROB_input_file,
    CNTSPROB_output_file,
    //CNTSPROB_test_score_list,
    //CNTSPROB_tokens,
    //CNTSPROB_umask,
    CNTSPROB_ok_status,
    CNTSPROB_header_pat,
    CNTSPROB_footer_pat,
    CNTSPROB_compiler_env_pat,
    //CNTSPROB_token_info,
    //CNTSPROB_score_tests,
    //CNTSPROB_standard_checker,
    //CNTSPROB_spelling,
    CNTSPROB_xml_file,
    CNTSPROB_stand_attr,
    CNTSPROB_source_header,
    CNTSPROB_source_footer,
    CNTSPROB_valuer_sets_marked,
    CNTSPROB_ignore_unmarked,
    CNTSPROB_interactor_time_limit,
    CNTSPROB_interactor_real_time_limit,
    CNTSPROB_disable_stderr,
    CNTSPROB_enable_process_group,
    CNTSPROB_enable_testlib_mode,
    CNTSPROB_hide_variant,
    CNTSPROB_test_pat,
    CNTSPROB_corr_pat,
    CNTSPROB_info_pat,
    CNTSPROB_tgz_pat,
    CNTSPROB_tgzdir_pat,
    //CNTSPROB_test_sets,
    CNTSPROB_normalization,
    //CNTSPROB_deadline,
    //CNTSPROB_start_date,
    CNTSPROB_autoassign_variants,
    //CNTSPROB_variant_num,
    //CNTSPROB_date_penalty,
    //CNTSPROB_group_start_date,
    //CNTSPROB_group_deadline,
    //CNTSPROB_disable_language,
    //CNTSPROB_enable_language,
    //CNTSPROB_require,
    //CNTSPROB_provide_ok,
    //CNTSPROB_lang_compiler_env,
    //CNTSPROB_checker_env,
    //CNTSPROB_valuer_env,
    //CNTSPROB_interactor_env,
    //CNTSPROB_style_checker_env,
    //CNTSPROB_test_checker_env,
    //CNTSPROB_init_env,
    //CNTSPROB_start_env,
    CNTSPROB_problem_dir,
    CNTSPROB_check_cmd,
    CNTSPROB_valuer_cmd,
    CNTSPROB_interactor_cmd,
    CNTSPROB_style_checker_cmd,
    CNTSPROB_test_checker_cmd,
    CNTSPROB_init_cmd,
    CNTSPROB_start_cmd,
    CNTSPROB_solution_src,
    CNTSPROB_solution_cmd,
    //CNTSPROB_lang_time_adj,
    //CNTSPROB_lang_time_adj_millis,
    CNTSPROB_super_run_dir,
    //CNTSPROB_lang_max_vm_size,
    //CNTSPROB_lang_max_stack_size,
    //CNTSPROB_personal_deadline,
    CNTSPROB_score_bonus,
    CNTSPROB_open_tests,
    CNTSPROB_final_open_tests,
    CNTSPROB_token_open_tests,
    CNTSPROB_max_vm_size,
    CNTSPROB_max_data_size,
    CNTSPROB_max_stack_size,
    CNTSPROB_max_core_size,
    CNTSPROB_max_file_size,
    CNTSPROB_max_open_file_count,
    CNTSPROB_max_process_count,
    //CNTSPROB_extid,
    //CNTSPROB_score_view,
    //CNTSPROB_score_view_text,
    0
  };

  for (int i = 0; fields[i]; ++i) {
    prepare_set_prob_value(fields[i], out, abstr, global);
  }
}

const unsigned char*
get_advanced_layout_path(
        unsigned char *buf,
        size_t bufsize,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        const unsigned char *entry,
        int variant)
{
  path_t path1;
  const unsigned char *prob_name;

  if (prob && prob->problem_dir && prob->problem_dir[0] == '/') {
    if (!entry) {
      if (variant < 0 || prob->variant_num <= 0) {
        snprintf(buf, bufsize, "%s", prob->problem_dir);
      } else {
        snprintf(buf, bufsize, "%s-%d", prob->problem_dir, variant);
      }
    } else {
      if (variant < 0 || prob->variant_num <= 0) {
        snprintf(buf, bufsize, "%s/%s", prob->problem_dir, entry);
      } else {
        snprintf(buf, bufsize, "%s-%d/%s", prob->problem_dir, variant, entry);
      }
    }
    return buf;
  }

  if (global->problems_dir && global->problems_dir[0]) {
    if (os_IsAbsolutePath(global->problems_dir)) {
      snprintf(path1, sizeof(path1), "%s", global->problems_dir);
    } else {
      snprintf(path1, sizeof(path1), "%s/%s", global->root_dir, global->problems_dir);
    }
  } else {
    snprintf(path1, sizeof(path1), "%s/%s", global->root_dir, DFLT_G_PROBLEMS_DIR);
  }

  if (!prob) {
    snprintf(buf, bufsize, "%s", path1);
    return buf;
  }

  prob_name = prob->short_name;
  if (prob->problem_dir && prob->problem_dir[0]) {
    prob_name = prob->problem_dir;
  } else if (prob->internal_name) {
    prob_name = prob->internal_name;
  }

  if (!entry) {
    if (variant < 0 || prob->variant_num <= 0) {
      snprintf(buf, bufsize, "%s/%s", path1, prob_name);
    } else {
      snprintf(buf, bufsize, "%s/%s-%d", path1, prob_name, variant);
    }
  } else {
    if (variant < 0 || prob->variant_num <= 0) {
      snprintf(buf, bufsize, "%s/%s/%s", path1, prob_name, entry);
    } else {
      snprintf(buf, bufsize, "%s/%s-%d/%s", path1, prob_name, variant, entry);
    }
  }

  return buf;
}

int
cntsprob_get_test_visibility(
        const struct section_problem_data *prob,
        int num,
        int final_mode,
        int token_flags)
{
  if (!prob) return TV_NORMAL;
  if (final_mode && prob->final_open_tests_val) {
    if (num <= 0 || num >= prob->final_open_tests_count)
      return TV_NORMAL;
    return prob->final_open_tests_val[num];
  }
  if ((token_flags & TOKEN_TESTS_MASK) == TOKEN_BASICTESTS_BIT) {
    if (!prob->open_tests_val || num <= 0 || num >= prob->open_tests_count)
      return TV_NORMAL;
    return prob->open_tests_val[num];
  } else if ((token_flags & TOKEN_TESTS_MASK) == TOKEN_TOKENTESTS_BIT) {
    if (!prob->token_open_tests_val || num <= 0 || num >= prob->token_open_tests_count)
      return TV_NORMAL;
    return prob->token_open_tests_val[num];
  } else if ((token_flags & TOKEN_TESTS_MASK) == TOKEN_FINALTESTS_BIT) {
    if (!prob->final_open_tests_val || num <= 0 || num >= prob->final_open_tests_count)
      return TV_NORMAL;
    return prob->final_open_tests_val[num];
  }
  if (!prob->open_tests_val
      || num <= 0 || num >= prob->open_tests_count)
    return TV_NORMAL;
  return prob->open_tests_val[num];
}

int
prepare_parse_test_score_list(
        FILE *log_f,
        const unsigned char *test_score_list,
        int **pscores,
        int *pcount)
{
  int *arr = NULL;

  *pscores = NULL;
  *pcount = 0;
  if (!test_score_list || !*test_score_list) return 0;

  int cur_index = 0;
  int max_index = 0;
  int ind, score, n;
  const unsigned char *s = test_score_list;
  while (1) {
    while (isspace(*s)) ++s;
    if (!*s) break;

    if (*s == '[') {
      ind = -1;
      ++s;
      if (sscanf(s, "%d%n", &ind, &n) != 1) {
        goto fail;
      }
      if (ind <= 0 || ind >= 100000) {
        goto fail;
      }
      s += n;
      while (isspace(*s)) ++s;
      if (*s != ']') {
        goto fail;
      }
      ++s;
      cur_index = ind - 1;
    }

    score = -1;
    if (sscanf(s, "%d%n", &score, &n) != 1) {
      goto fail;
    }
    if (score < 0 || score > 100000) {
      goto fail;
    }
    s += n;
    ++cur_index;
    if (cur_index > max_index) max_index = cur_index;
  }

  if (max_index <= 0) return 0;

  cur_index = 0;
  s = test_score_list;
  XCALLOC(arr, max_index + 1);
  for (n = 0; n <= max_index; ++n) {
    arr[n] = -1;
  }

  while (1) {
    while (isspace(*s)) ++s;
    if (!*s) break;

    if (*s == '[') {
      ind = -1;
      ++s;
      if (sscanf(s, "%d%n", &ind, &n) != 1) {
        goto fail;
      }
      if (ind <= 0 || ind >= 100000) {
        goto fail;
      }
      s += n;
      while (isspace(*s)) ++s;
      if (*s != ']') {
        goto fail;
      }
      ++s;
      cur_index = ind - 1;
    }

    score = -1;
    if (sscanf(s, "%d%n", &score, &n) != 1) {
      goto fail;
    }
    if (score < 0 || score > 100000) {
      goto fail;
    }
    s += n;
    ++cur_index;
    arr[cur_index] = score;
  }

  *pscores = arr;
  *pcount = max_index + 1;
  return 0;

fail:
  if (log_f) {
    fprintf(log_f, "invalid test_score_list '%s'\n", test_score_list);
  } else {
    err("invalid test_score_list '%s'", test_score_list);
  }
  xfree(arr);
  return -1;
}
