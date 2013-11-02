// This is an auto-generated file, do not edit
// Generated 2013/11/02 20:35:09

#include "problem_config_meta.h"
#include "problem_config.h"
#include "meta_generic.h"

#include "reuse_xalloc.h"

#include "reuse_logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_problem_config_section_data[] =
{
  [META_PROBLEM_CONFIG_SECTION_manual_checking] = { META_PROBLEM_CONFIG_SECTION_manual_checking, 'B', XSIZE(struct problem_config_section, manual_checking), "manual_checking", XOFFSET(struct problem_config_section, manual_checking) },
  [META_PROBLEM_CONFIG_SECTION_check_presentation] = { META_PROBLEM_CONFIG_SECTION_check_presentation, 'B', XSIZE(struct problem_config_section, check_presentation), "check_presentation", XOFFSET(struct problem_config_section, check_presentation) },
  [META_PROBLEM_CONFIG_SECTION_scoring_checker] = { META_PROBLEM_CONFIG_SECTION_scoring_checker, 'B', XSIZE(struct problem_config_section, scoring_checker), "scoring_checker", XOFFSET(struct problem_config_section, scoring_checker) },
  [META_PROBLEM_CONFIG_SECTION_interactive_valuer] = { META_PROBLEM_CONFIG_SECTION_interactive_valuer, 'B', XSIZE(struct problem_config_section, interactive_valuer), "interactive_valuer", XOFFSET(struct problem_config_section, interactive_valuer) },
  [META_PROBLEM_CONFIG_SECTION_disable_pe] = { META_PROBLEM_CONFIG_SECTION_disable_pe, 'B', XSIZE(struct problem_config_section, disable_pe), "disable_pe", XOFFSET(struct problem_config_section, disable_pe) },
  [META_PROBLEM_CONFIG_SECTION_disable_wtl] = { META_PROBLEM_CONFIG_SECTION_disable_wtl, 'B', XSIZE(struct problem_config_section, disable_wtl), "disable_wtl", XOFFSET(struct problem_config_section, disable_wtl) },
  [META_PROBLEM_CONFIG_SECTION_use_stdin] = { META_PROBLEM_CONFIG_SECTION_use_stdin, 'B', XSIZE(struct problem_config_section, use_stdin), "use_stdin", XOFFSET(struct problem_config_section, use_stdin) },
  [META_PROBLEM_CONFIG_SECTION_use_stdout] = { META_PROBLEM_CONFIG_SECTION_use_stdout, 'B', XSIZE(struct problem_config_section, use_stdout), "use_stdout", XOFFSET(struct problem_config_section, use_stdout) },
  [META_PROBLEM_CONFIG_SECTION_combined_stdin] = { META_PROBLEM_CONFIG_SECTION_combined_stdin, 'B', XSIZE(struct problem_config_section, combined_stdin), "combined_stdin", XOFFSET(struct problem_config_section, combined_stdin) },
  [META_PROBLEM_CONFIG_SECTION_combined_stdout] = { META_PROBLEM_CONFIG_SECTION_combined_stdout, 'B', XSIZE(struct problem_config_section, combined_stdout), "combined_stdout", XOFFSET(struct problem_config_section, combined_stdout) },
  [META_PROBLEM_CONFIG_SECTION_binary_input] = { META_PROBLEM_CONFIG_SECTION_binary_input, 'B', XSIZE(struct problem_config_section, binary_input), "binary_input", XOFFSET(struct problem_config_section, binary_input) },
  [META_PROBLEM_CONFIG_SECTION_binary] = { META_PROBLEM_CONFIG_SECTION_binary, 'B', XSIZE(struct problem_config_section, binary), "binary", XOFFSET(struct problem_config_section, binary) },
  [META_PROBLEM_CONFIG_SECTION_ignore_exit_code] = { META_PROBLEM_CONFIG_SECTION_ignore_exit_code, 'B', XSIZE(struct problem_config_section, ignore_exit_code), "ignore_exit_code", XOFFSET(struct problem_config_section, ignore_exit_code) },
  [META_PROBLEM_CONFIG_SECTION_olympiad_mode] = { META_PROBLEM_CONFIG_SECTION_olympiad_mode, 'B', XSIZE(struct problem_config_section, olympiad_mode), "olympiad_mode", XOFFSET(struct problem_config_section, olympiad_mode) },
  [META_PROBLEM_CONFIG_SECTION_score_latest] = { META_PROBLEM_CONFIG_SECTION_score_latest, 'B', XSIZE(struct problem_config_section, score_latest), "score_latest", XOFFSET(struct problem_config_section, score_latest) },
  [META_PROBLEM_CONFIG_SECTION_score_latest_or_unmarked] = { META_PROBLEM_CONFIG_SECTION_score_latest_or_unmarked, 'B', XSIZE(struct problem_config_section, score_latest_or_unmarked), "score_latest_or_unmarked", XOFFSET(struct problem_config_section, score_latest_or_unmarked) },
  [META_PROBLEM_CONFIG_SECTION_score_latest_marked] = { META_PROBLEM_CONFIG_SECTION_score_latest_marked, 'B', XSIZE(struct problem_config_section, score_latest_marked), "score_latest_marked", XOFFSET(struct problem_config_section, score_latest_marked) },
  [META_PROBLEM_CONFIG_SECTION_use_ac_not_ok] = { META_PROBLEM_CONFIG_SECTION_use_ac_not_ok, 'B', XSIZE(struct problem_config_section, use_ac_not_ok), "use_ac_not_ok", XOFFSET(struct problem_config_section, use_ac_not_ok) },
  [META_PROBLEM_CONFIG_SECTION_ignore_prev_ac] = { META_PROBLEM_CONFIG_SECTION_ignore_prev_ac, 'B', XSIZE(struct problem_config_section, ignore_prev_ac), "ignore_prev_ac", XOFFSET(struct problem_config_section, ignore_prev_ac) },
  [META_PROBLEM_CONFIG_SECTION_team_enable_rep_view] = { META_PROBLEM_CONFIG_SECTION_team_enable_rep_view, 'B', XSIZE(struct problem_config_section, team_enable_rep_view), "team_enable_rep_view", XOFFSET(struct problem_config_section, team_enable_rep_view) },
  [META_PROBLEM_CONFIG_SECTION_team_enable_ce_view] = { META_PROBLEM_CONFIG_SECTION_team_enable_ce_view, 'B', XSIZE(struct problem_config_section, team_enable_ce_view), "team_enable_ce_view", XOFFSET(struct problem_config_section, team_enable_ce_view) },
  [META_PROBLEM_CONFIG_SECTION_team_show_judge_report] = { META_PROBLEM_CONFIG_SECTION_team_show_judge_report, 'B', XSIZE(struct problem_config_section, team_show_judge_report), "team_show_judge_report", XOFFSET(struct problem_config_section, team_show_judge_report) },
  [META_PROBLEM_CONFIG_SECTION_show_checker_comment] = { META_PROBLEM_CONFIG_SECTION_show_checker_comment, 'B', XSIZE(struct problem_config_section, show_checker_comment), "show_checker_comment", XOFFSET(struct problem_config_section, show_checker_comment) },
  [META_PROBLEM_CONFIG_SECTION_ignore_compile_errors] = { META_PROBLEM_CONFIG_SECTION_ignore_compile_errors, 'B', XSIZE(struct problem_config_section, ignore_compile_errors), "ignore_compile_errors", XOFFSET(struct problem_config_section, ignore_compile_errors) },
  [META_PROBLEM_CONFIG_SECTION_variable_full_score] = { META_PROBLEM_CONFIG_SECTION_variable_full_score, 'B', XSIZE(struct problem_config_section, variable_full_score), "variable_full_score", XOFFSET(struct problem_config_section, variable_full_score) },
  [META_PROBLEM_CONFIG_SECTION_ignore_penalty] = { META_PROBLEM_CONFIG_SECTION_ignore_penalty, 'B', XSIZE(struct problem_config_section, ignore_penalty), "ignore_penalty", XOFFSET(struct problem_config_section, ignore_penalty) },
  [META_PROBLEM_CONFIG_SECTION_use_corr] = { META_PROBLEM_CONFIG_SECTION_use_corr, 'B', XSIZE(struct problem_config_section, use_corr), "use_corr", XOFFSET(struct problem_config_section, use_corr) },
  [META_PROBLEM_CONFIG_SECTION_use_info] = { META_PROBLEM_CONFIG_SECTION_use_info, 'B', XSIZE(struct problem_config_section, use_info), "use_info", XOFFSET(struct problem_config_section, use_info) },
  [META_PROBLEM_CONFIG_SECTION_use_tgz] = { META_PROBLEM_CONFIG_SECTION_use_tgz, 'B', XSIZE(struct problem_config_section, use_tgz), "use_tgz", XOFFSET(struct problem_config_section, use_tgz) },
  [META_PROBLEM_CONFIG_SECTION_accept_partial] = { META_PROBLEM_CONFIG_SECTION_accept_partial, 'B', XSIZE(struct problem_config_section, accept_partial), "accept_partial", XOFFSET(struct problem_config_section, accept_partial) },
  [META_PROBLEM_CONFIG_SECTION_disable_user_submit] = { META_PROBLEM_CONFIG_SECTION_disable_user_submit, 'B', XSIZE(struct problem_config_section, disable_user_submit), "disable_user_submit", XOFFSET(struct problem_config_section, disable_user_submit) },
  [META_PROBLEM_CONFIG_SECTION_disable_tab] = { META_PROBLEM_CONFIG_SECTION_disable_tab, 'B', XSIZE(struct problem_config_section, disable_tab), "disable_tab", XOFFSET(struct problem_config_section, disable_tab) },
  [META_PROBLEM_CONFIG_SECTION_restricted_statement] = { META_PROBLEM_CONFIG_SECTION_restricted_statement, 'B', XSIZE(struct problem_config_section, restricted_statement), "restricted_statement", XOFFSET(struct problem_config_section, restricted_statement) },
  [META_PROBLEM_CONFIG_SECTION_disable_submit_after_ok] = { META_PROBLEM_CONFIG_SECTION_disable_submit_after_ok, 'B', XSIZE(struct problem_config_section, disable_submit_after_ok), "disable_submit_after_ok", XOFFSET(struct problem_config_section, disable_submit_after_ok) },
  [META_PROBLEM_CONFIG_SECTION_disable_auto_testing] = { META_PROBLEM_CONFIG_SECTION_disable_auto_testing, 'B', XSIZE(struct problem_config_section, disable_auto_testing), "disable_auto_testing", XOFFSET(struct problem_config_section, disable_auto_testing) },
  [META_PROBLEM_CONFIG_SECTION_disable_testing] = { META_PROBLEM_CONFIG_SECTION_disable_testing, 'B', XSIZE(struct problem_config_section, disable_testing), "disable_testing", XOFFSET(struct problem_config_section, disable_testing) },
  [META_PROBLEM_CONFIG_SECTION_enable_compilation] = { META_PROBLEM_CONFIG_SECTION_enable_compilation, 'B', XSIZE(struct problem_config_section, enable_compilation), "enable_compilation", XOFFSET(struct problem_config_section, enable_compilation) },
  [META_PROBLEM_CONFIG_SECTION_skip_testing] = { META_PROBLEM_CONFIG_SECTION_skip_testing, 'B', XSIZE(struct problem_config_section, skip_testing), "skip_testing", XOFFSET(struct problem_config_section, skip_testing) },
  [META_PROBLEM_CONFIG_SECTION_hidden] = { META_PROBLEM_CONFIG_SECTION_hidden, 'B', XSIZE(struct problem_config_section, hidden), "hidden", XOFFSET(struct problem_config_section, hidden) },
  [META_PROBLEM_CONFIG_SECTION_stand_hide_time] = { META_PROBLEM_CONFIG_SECTION_stand_hide_time, 'B', XSIZE(struct problem_config_section, stand_hide_time), "stand_hide_time", XOFFSET(struct problem_config_section, stand_hide_time) },
  [META_PROBLEM_CONFIG_SECTION_advance_to_next] = { META_PROBLEM_CONFIG_SECTION_advance_to_next, 'B', XSIZE(struct problem_config_section, advance_to_next), "advance_to_next", XOFFSET(struct problem_config_section, advance_to_next) },
  [META_PROBLEM_CONFIG_SECTION_disable_ctrl_chars] = { META_PROBLEM_CONFIG_SECTION_disable_ctrl_chars, 'B', XSIZE(struct problem_config_section, disable_ctrl_chars), "disable_ctrl_chars", XOFFSET(struct problem_config_section, disable_ctrl_chars) },
  [META_PROBLEM_CONFIG_SECTION_enable_text_form] = { META_PROBLEM_CONFIG_SECTION_enable_text_form, 'B', XSIZE(struct problem_config_section, enable_text_form), "enable_text_form", XOFFSET(struct problem_config_section, enable_text_form) },
  [META_PROBLEM_CONFIG_SECTION_stand_ignore_score] = { META_PROBLEM_CONFIG_SECTION_stand_ignore_score, 'B', XSIZE(struct problem_config_section, stand_ignore_score), "stand_ignore_score", XOFFSET(struct problem_config_section, stand_ignore_score) },
  [META_PROBLEM_CONFIG_SECTION_stand_last_column] = { META_PROBLEM_CONFIG_SECTION_stand_last_column, 'B', XSIZE(struct problem_config_section, stand_last_column), "stand_last_column", XOFFSET(struct problem_config_section, stand_last_column) },
  [META_PROBLEM_CONFIG_SECTION_disable_security] = { META_PROBLEM_CONFIG_SECTION_disable_security, 'B', XSIZE(struct problem_config_section, disable_security), "disable_security", XOFFSET(struct problem_config_section, disable_security) },
  [META_PROBLEM_CONFIG_SECTION_valuer_sets_marked] = { META_PROBLEM_CONFIG_SECTION_valuer_sets_marked, 'B', XSIZE(struct problem_config_section, valuer_sets_marked), "valuer_sets_marked", XOFFSET(struct problem_config_section, valuer_sets_marked) },
  [META_PROBLEM_CONFIG_SECTION_ignore_unmarked] = { META_PROBLEM_CONFIG_SECTION_ignore_unmarked, 'B', XSIZE(struct problem_config_section, ignore_unmarked), "ignore_unmarked", XOFFSET(struct problem_config_section, ignore_unmarked) },
  [META_PROBLEM_CONFIG_SECTION_disable_stderr] = { META_PROBLEM_CONFIG_SECTION_disable_stderr, 'B', XSIZE(struct problem_config_section, disable_stderr), "disable_stderr", XOFFSET(struct problem_config_section, disable_stderr) },
  [META_PROBLEM_CONFIG_SECTION_enable_process_group] = { META_PROBLEM_CONFIG_SECTION_enable_process_group, 'B', XSIZE(struct problem_config_section, enable_process_group), "enable_process_group", XOFFSET(struct problem_config_section, enable_process_group) },
  [META_PROBLEM_CONFIG_SECTION_id] = { META_PROBLEM_CONFIG_SECTION_id, 'i', XSIZE(struct problem_config_section, id), "id", XOFFSET(struct problem_config_section, id) },
  [META_PROBLEM_CONFIG_SECTION_real_time_limit] = { META_PROBLEM_CONFIG_SECTION_real_time_limit, 'i', XSIZE(struct problem_config_section, real_time_limit), "real_time_limit", XOFFSET(struct problem_config_section, real_time_limit) },
  [META_PROBLEM_CONFIG_SECTION_time_limit] = { META_PROBLEM_CONFIG_SECTION_time_limit, 'i', XSIZE(struct problem_config_section, time_limit), "time_limit", XOFFSET(struct problem_config_section, time_limit) },
  [META_PROBLEM_CONFIG_SECTION_time_limit_millis] = { META_PROBLEM_CONFIG_SECTION_time_limit_millis, 'i', XSIZE(struct problem_config_section, time_limit_millis), "time_limit_millis", XOFFSET(struct problem_config_section, time_limit_millis) },
  [META_PROBLEM_CONFIG_SECTION_full_score] = { META_PROBLEM_CONFIG_SECTION_full_score, 'i', XSIZE(struct problem_config_section, full_score), "full_score", XOFFSET(struct problem_config_section, full_score) },
  [META_PROBLEM_CONFIG_SECTION_full_user_score] = { META_PROBLEM_CONFIG_SECTION_full_user_score, 'i', XSIZE(struct problem_config_section, full_user_score), "full_user_score", XOFFSET(struct problem_config_section, full_user_score) },
  [META_PROBLEM_CONFIG_SECTION_test_score] = { META_PROBLEM_CONFIG_SECTION_test_score, 'i', XSIZE(struct problem_config_section, test_score), "test_score", XOFFSET(struct problem_config_section, test_score) },
  [META_PROBLEM_CONFIG_SECTION_run_penalty] = { META_PROBLEM_CONFIG_SECTION_run_penalty, 'i', XSIZE(struct problem_config_section, run_penalty), "run_penalty", XOFFSET(struct problem_config_section, run_penalty) },
  [META_PROBLEM_CONFIG_SECTION_acm_run_penalty] = { META_PROBLEM_CONFIG_SECTION_acm_run_penalty, 'i', XSIZE(struct problem_config_section, acm_run_penalty), "acm_run_penalty", XOFFSET(struct problem_config_section, acm_run_penalty) },
  [META_PROBLEM_CONFIG_SECTION_disqualified_penalty] = { META_PROBLEM_CONFIG_SECTION_disqualified_penalty, 'i', XSIZE(struct problem_config_section, disqualified_penalty), "disqualified_penalty", XOFFSET(struct problem_config_section, disqualified_penalty) },
  [META_PROBLEM_CONFIG_SECTION_min_tests_to_accept] = { META_PROBLEM_CONFIG_SECTION_min_tests_to_accept, 'i', XSIZE(struct problem_config_section, min_tests_to_accept), "min_tests_to_accept", XOFFSET(struct problem_config_section, min_tests_to_accept) },
  [META_PROBLEM_CONFIG_SECTION_checker_real_time_limit] = { META_PROBLEM_CONFIG_SECTION_checker_real_time_limit, 'i', XSIZE(struct problem_config_section, checker_real_time_limit), "checker_real_time_limit", XOFFSET(struct problem_config_section, checker_real_time_limit) },
  [META_PROBLEM_CONFIG_SECTION_priority_adjustment] = { META_PROBLEM_CONFIG_SECTION_priority_adjustment, 'i', XSIZE(struct problem_config_section, priority_adjustment), "priority_adjustment", XOFFSET(struct problem_config_section, priority_adjustment) },
  [META_PROBLEM_CONFIG_SECTION_score_multiplier] = { META_PROBLEM_CONFIG_SECTION_score_multiplier, 'i', XSIZE(struct problem_config_section, score_multiplier), "score_multiplier", XOFFSET(struct problem_config_section, score_multiplier) },
  [META_PROBLEM_CONFIG_SECTION_prev_runs_to_show] = { META_PROBLEM_CONFIG_SECTION_prev_runs_to_show, 'i', XSIZE(struct problem_config_section, prev_runs_to_show), "prev_runs_to_show", XOFFSET(struct problem_config_section, prev_runs_to_show) },
  [META_PROBLEM_CONFIG_SECTION_max_user_run_count] = { META_PROBLEM_CONFIG_SECTION_max_user_run_count, 'i', XSIZE(struct problem_config_section, max_user_run_count), "max_user_run_count", XOFFSET(struct problem_config_section, max_user_run_count) },
  [META_PROBLEM_CONFIG_SECTION_interactor_time_limit] = { META_PROBLEM_CONFIG_SECTION_interactor_time_limit, 'i', XSIZE(struct problem_config_section, interactor_time_limit), "interactor_time_limit", XOFFSET(struct problem_config_section, interactor_time_limit) },
  [META_PROBLEM_CONFIG_SECTION_max_open_file_count] = { META_PROBLEM_CONFIG_SECTION_max_open_file_count, 'i', XSIZE(struct problem_config_section, max_open_file_count), "max_open_file_count", XOFFSET(struct problem_config_section, max_open_file_count) },
  [META_PROBLEM_CONFIG_SECTION_max_process_count] = { META_PROBLEM_CONFIG_SECTION_max_process_count, 'i', XSIZE(struct problem_config_section, max_process_count), "max_process_count", XOFFSET(struct problem_config_section, max_process_count) },
  [META_PROBLEM_CONFIG_SECTION_tests_to_accept] = { META_PROBLEM_CONFIG_SECTION_tests_to_accept, 'i', XSIZE(struct problem_config_section, tests_to_accept), "tests_to_accept", XOFFSET(struct problem_config_section, tests_to_accept) },
  [META_PROBLEM_CONFIG_SECTION_deadline] = { META_PROBLEM_CONFIG_SECTION_deadline, 't', XSIZE(struct problem_config_section, deadline), "deadline", XOFFSET(struct problem_config_section, deadline) },
  [META_PROBLEM_CONFIG_SECTION_start_date] = { META_PROBLEM_CONFIG_SECTION_start_date, 't', XSIZE(struct problem_config_section, start_date), "start_date", XOFFSET(struct problem_config_section, start_date) },
  [META_PROBLEM_CONFIG_SECTION_max_vm_size] = { META_PROBLEM_CONFIG_SECTION_max_vm_size, 'Z', XSIZE(struct problem_config_section, max_vm_size), "max_vm_size", XOFFSET(struct problem_config_section, max_vm_size) },
  [META_PROBLEM_CONFIG_SECTION_max_data_size] = { META_PROBLEM_CONFIG_SECTION_max_data_size, 'Z', XSIZE(struct problem_config_section, max_data_size), "max_data_size", XOFFSET(struct problem_config_section, max_data_size) },
  [META_PROBLEM_CONFIG_SECTION_max_stack_size] = { META_PROBLEM_CONFIG_SECTION_max_stack_size, 'Z', XSIZE(struct problem_config_section, max_stack_size), "max_stack_size", XOFFSET(struct problem_config_section, max_stack_size) },
  [META_PROBLEM_CONFIG_SECTION_max_core_size] = { META_PROBLEM_CONFIG_SECTION_max_core_size, 'Z', XSIZE(struct problem_config_section, max_core_size), "max_core_size", XOFFSET(struct problem_config_section, max_core_size) },
  [META_PROBLEM_CONFIG_SECTION_max_file_size] = { META_PROBLEM_CONFIG_SECTION_max_file_size, 'Z', XSIZE(struct problem_config_section, max_file_size), "max_file_size", XOFFSET(struct problem_config_section, max_file_size) },
  [META_PROBLEM_CONFIG_SECTION_type] = { META_PROBLEM_CONFIG_SECTION_type, 's', XSIZE(struct problem_config_section, type), "type", XOFFSET(struct problem_config_section, type) },
  [META_PROBLEM_CONFIG_SECTION_short_name] = { META_PROBLEM_CONFIG_SECTION_short_name, 's', XSIZE(struct problem_config_section, short_name), "short_name", XOFFSET(struct problem_config_section, short_name) },
  [META_PROBLEM_CONFIG_SECTION_long_name] = { META_PROBLEM_CONFIG_SECTION_long_name, 's', XSIZE(struct problem_config_section, long_name), "long_name", XOFFSET(struct problem_config_section, long_name) },
  [META_PROBLEM_CONFIG_SECTION_long_name_en] = { META_PROBLEM_CONFIG_SECTION_long_name_en, 's', XSIZE(struct problem_config_section, long_name_en), "long_name_en", XOFFSET(struct problem_config_section, long_name_en) },
  [META_PROBLEM_CONFIG_SECTION_stand_name] = { META_PROBLEM_CONFIG_SECTION_stand_name, 's', XSIZE(struct problem_config_section, stand_name), "stand_name", XOFFSET(struct problem_config_section, stand_name) },
  [META_PROBLEM_CONFIG_SECTION_internal_name] = { META_PROBLEM_CONFIG_SECTION_internal_name, 's', XSIZE(struct problem_config_section, internal_name), "internal_name", XOFFSET(struct problem_config_section, internal_name) },
  [META_PROBLEM_CONFIG_SECTION_test_dir] = { META_PROBLEM_CONFIG_SECTION_test_dir, 's', XSIZE(struct problem_config_section, test_dir), "test_dir", XOFFSET(struct problem_config_section, test_dir) },
  [META_PROBLEM_CONFIG_SECTION_test_sfx] = { META_PROBLEM_CONFIG_SECTION_test_sfx, 's', XSIZE(struct problem_config_section, test_sfx), "test_sfx", XOFFSET(struct problem_config_section, test_sfx) },
  [META_PROBLEM_CONFIG_SECTION_corr_sfx] = { META_PROBLEM_CONFIG_SECTION_corr_sfx, 's', XSIZE(struct problem_config_section, corr_sfx), "corr_sfx", XOFFSET(struct problem_config_section, corr_sfx) },
  [META_PROBLEM_CONFIG_SECTION_info_sfx] = { META_PROBLEM_CONFIG_SECTION_info_sfx, 's', XSIZE(struct problem_config_section, info_sfx), "info_sfx", XOFFSET(struct problem_config_section, info_sfx) },
  [META_PROBLEM_CONFIG_SECTION_tgz_sfx] = { META_PROBLEM_CONFIG_SECTION_tgz_sfx, 's', XSIZE(struct problem_config_section, tgz_sfx), "tgz_sfx", XOFFSET(struct problem_config_section, tgz_sfx) },
  [META_PROBLEM_CONFIG_SECTION_tgzdir_sfx] = { META_PROBLEM_CONFIG_SECTION_tgzdir_sfx, 's', XSIZE(struct problem_config_section, tgzdir_sfx), "tgzdir_sfx", XOFFSET(struct problem_config_section, tgzdir_sfx) },
  [META_PROBLEM_CONFIG_SECTION_input_file] = { META_PROBLEM_CONFIG_SECTION_input_file, 's', XSIZE(struct problem_config_section, input_file), "input_file", XOFFSET(struct problem_config_section, input_file) },
  [META_PROBLEM_CONFIG_SECTION_output_file] = { META_PROBLEM_CONFIG_SECTION_output_file, 's', XSIZE(struct problem_config_section, output_file), "output_file", XOFFSET(struct problem_config_section, output_file) },
  [META_PROBLEM_CONFIG_SECTION_test_score_list] = { META_PROBLEM_CONFIG_SECTION_test_score_list, 's', XSIZE(struct problem_config_section, test_score_list), "test_score_list", XOFFSET(struct problem_config_section, test_score_list) },
  [META_PROBLEM_CONFIG_SECTION_score_tests] = { META_PROBLEM_CONFIG_SECTION_score_tests, 's', XSIZE(struct problem_config_section, score_tests), "score_tests", XOFFSET(struct problem_config_section, score_tests) },
  [META_PROBLEM_CONFIG_SECTION_standard_checker] = { META_PROBLEM_CONFIG_SECTION_standard_checker, 's', XSIZE(struct problem_config_section, standard_checker), "standard_checker", XOFFSET(struct problem_config_section, standard_checker) },
  [META_PROBLEM_CONFIG_SECTION_spelling] = { META_PROBLEM_CONFIG_SECTION_spelling, 's', XSIZE(struct problem_config_section, spelling), "spelling", XOFFSET(struct problem_config_section, spelling) },
  [META_PROBLEM_CONFIG_SECTION_plugin_file] = { META_PROBLEM_CONFIG_SECTION_plugin_file, 's', XSIZE(struct problem_config_section, plugin_file), "plugin_file", XOFFSET(struct problem_config_section, plugin_file) },
  [META_PROBLEM_CONFIG_SECTION_xml_file] = { META_PROBLEM_CONFIG_SECTION_xml_file, 's', XSIZE(struct problem_config_section, xml_file), "xml_file", XOFFSET(struct problem_config_section, xml_file) },
  [META_PROBLEM_CONFIG_SECTION_stand_attr] = { META_PROBLEM_CONFIG_SECTION_stand_attr, 's', XSIZE(struct problem_config_section, stand_attr), "stand_attr", XOFFSET(struct problem_config_section, stand_attr) },
  [META_PROBLEM_CONFIG_SECTION_source_header] = { META_PROBLEM_CONFIG_SECTION_source_header, 's', XSIZE(struct problem_config_section, source_header), "source_header", XOFFSET(struct problem_config_section, source_header) },
  [META_PROBLEM_CONFIG_SECTION_source_footer] = { META_PROBLEM_CONFIG_SECTION_source_footer, 's', XSIZE(struct problem_config_section, source_footer), "source_footer", XOFFSET(struct problem_config_section, source_footer) },
  [META_PROBLEM_CONFIG_SECTION_test_pat] = { META_PROBLEM_CONFIG_SECTION_test_pat, 's', XSIZE(struct problem_config_section, test_pat), "test_pat", XOFFSET(struct problem_config_section, test_pat) },
  [META_PROBLEM_CONFIG_SECTION_corr_pat] = { META_PROBLEM_CONFIG_SECTION_corr_pat, 's', XSIZE(struct problem_config_section, corr_pat), "corr_pat", XOFFSET(struct problem_config_section, corr_pat) },
  [META_PROBLEM_CONFIG_SECTION_info_pat] = { META_PROBLEM_CONFIG_SECTION_info_pat, 's', XSIZE(struct problem_config_section, info_pat), "info_pat", XOFFSET(struct problem_config_section, info_pat) },
  [META_PROBLEM_CONFIG_SECTION_tgz_pat] = { META_PROBLEM_CONFIG_SECTION_tgz_pat, 's', XSIZE(struct problem_config_section, tgz_pat), "tgz_pat", XOFFSET(struct problem_config_section, tgz_pat) },
  [META_PROBLEM_CONFIG_SECTION_tgzdir_pat] = { META_PROBLEM_CONFIG_SECTION_tgzdir_pat, 's', XSIZE(struct problem_config_section, tgzdir_pat), "tgzdir_pat", XOFFSET(struct problem_config_section, tgzdir_pat) },
  [META_PROBLEM_CONFIG_SECTION_normalization] = { META_PROBLEM_CONFIG_SECTION_normalization, 's', XSIZE(struct problem_config_section, normalization), "normalization", XOFFSET(struct problem_config_section, normalization) },
  [META_PROBLEM_CONFIG_SECTION_check_cmd] = { META_PROBLEM_CONFIG_SECTION_check_cmd, 's', XSIZE(struct problem_config_section, check_cmd), "check_cmd", XOFFSET(struct problem_config_section, check_cmd) },
  [META_PROBLEM_CONFIG_SECTION_valuer_cmd] = { META_PROBLEM_CONFIG_SECTION_valuer_cmd, 's', XSIZE(struct problem_config_section, valuer_cmd), "valuer_cmd", XOFFSET(struct problem_config_section, valuer_cmd) },
  [META_PROBLEM_CONFIG_SECTION_interactor_cmd] = { META_PROBLEM_CONFIG_SECTION_interactor_cmd, 's', XSIZE(struct problem_config_section, interactor_cmd), "interactor_cmd", XOFFSET(struct problem_config_section, interactor_cmd) },
  [META_PROBLEM_CONFIG_SECTION_style_checker_cmd] = { META_PROBLEM_CONFIG_SECTION_style_checker_cmd, 's', XSIZE(struct problem_config_section, style_checker_cmd), "style_checker_cmd", XOFFSET(struct problem_config_section, style_checker_cmd) },
  [META_PROBLEM_CONFIG_SECTION_test_checker_cmd] = { META_PROBLEM_CONFIG_SECTION_test_checker_cmd, 's', XSIZE(struct problem_config_section, test_checker_cmd), "test_checker_cmd", XOFFSET(struct problem_config_section, test_checker_cmd) },
  [META_PROBLEM_CONFIG_SECTION_init_cmd] = { META_PROBLEM_CONFIG_SECTION_init_cmd, 's', XSIZE(struct problem_config_section, init_cmd), "init_cmd", XOFFSET(struct problem_config_section, init_cmd) },
  [META_PROBLEM_CONFIG_SECTION_solution_src] = { META_PROBLEM_CONFIG_SECTION_solution_src, 's', XSIZE(struct problem_config_section, solution_src), "solution_src", XOFFSET(struct problem_config_section, solution_src) },
  [META_PROBLEM_CONFIG_SECTION_solution_cmd] = { META_PROBLEM_CONFIG_SECTION_solution_cmd, 's', XSIZE(struct problem_config_section, solution_cmd), "solution_cmd", XOFFSET(struct problem_config_section, solution_cmd) },
  [META_PROBLEM_CONFIG_SECTION_score_bonus] = { META_PROBLEM_CONFIG_SECTION_score_bonus, 's', XSIZE(struct problem_config_section, score_bonus), "score_bonus", XOFFSET(struct problem_config_section, score_bonus) },
  [META_PROBLEM_CONFIG_SECTION_open_tests] = { META_PROBLEM_CONFIG_SECTION_open_tests, 's', XSIZE(struct problem_config_section, open_tests), "open_tests", XOFFSET(struct problem_config_section, open_tests) },
  [META_PROBLEM_CONFIG_SECTION_final_open_tests] = { META_PROBLEM_CONFIG_SECTION_final_open_tests, 's', XSIZE(struct problem_config_section, final_open_tests), "final_open_tests", XOFFSET(struct problem_config_section, final_open_tests) },
  [META_PROBLEM_CONFIG_SECTION_extid] = { META_PROBLEM_CONFIG_SECTION_extid, 's', XSIZE(struct problem_config_section, extid), "extid", XOFFSET(struct problem_config_section, extid) },
  [META_PROBLEM_CONFIG_SECTION_revision] = { META_PROBLEM_CONFIG_SECTION_revision, 's', XSIZE(struct problem_config_section, revision), "revision", XOFFSET(struct problem_config_section, revision) },
  [META_PROBLEM_CONFIG_SECTION_test_sets] = { META_PROBLEM_CONFIG_SECTION_test_sets, 'x', XSIZE(struct problem_config_section, test_sets), "test_sets", XOFFSET(struct problem_config_section, test_sets) },
  [META_PROBLEM_CONFIG_SECTION_date_penalty] = { META_PROBLEM_CONFIG_SECTION_date_penalty, 'x', XSIZE(struct problem_config_section, date_penalty), "date_penalty", XOFFSET(struct problem_config_section, date_penalty) },
  [META_PROBLEM_CONFIG_SECTION_group_start_date] = { META_PROBLEM_CONFIG_SECTION_group_start_date, 'x', XSIZE(struct problem_config_section, group_start_date), "group_start_date", XOFFSET(struct problem_config_section, group_start_date) },
  [META_PROBLEM_CONFIG_SECTION_group_deadline] = { META_PROBLEM_CONFIG_SECTION_group_deadline, 'x', XSIZE(struct problem_config_section, group_deadline), "group_deadline", XOFFSET(struct problem_config_section, group_deadline) },
  [META_PROBLEM_CONFIG_SECTION_disable_language] = { META_PROBLEM_CONFIG_SECTION_disable_language, 'x', XSIZE(struct problem_config_section, disable_language), "disable_language", XOFFSET(struct problem_config_section, disable_language) },
  [META_PROBLEM_CONFIG_SECTION_enable_language] = { META_PROBLEM_CONFIG_SECTION_enable_language, 'x', XSIZE(struct problem_config_section, enable_language), "enable_language", XOFFSET(struct problem_config_section, enable_language) },
  [META_PROBLEM_CONFIG_SECTION_require] = { META_PROBLEM_CONFIG_SECTION_require, 'x', XSIZE(struct problem_config_section, require), "require", XOFFSET(struct problem_config_section, require) },
  [META_PROBLEM_CONFIG_SECTION_provide_ok] = { META_PROBLEM_CONFIG_SECTION_provide_ok, 'x', XSIZE(struct problem_config_section, provide_ok), "provide_ok", XOFFSET(struct problem_config_section, provide_ok) },
  [META_PROBLEM_CONFIG_SECTION_lang_time_adj] = { META_PROBLEM_CONFIG_SECTION_lang_time_adj, 'x', XSIZE(struct problem_config_section, lang_time_adj), "lang_time_adj", XOFFSET(struct problem_config_section, lang_time_adj) },
  [META_PROBLEM_CONFIG_SECTION_lang_time_adj_millis] = { META_PROBLEM_CONFIG_SECTION_lang_time_adj_millis, 'x', XSIZE(struct problem_config_section, lang_time_adj_millis), "lang_time_adj_millis", XOFFSET(struct problem_config_section, lang_time_adj_millis) },
  [META_PROBLEM_CONFIG_SECTION_lang_max_vm_size] = { META_PROBLEM_CONFIG_SECTION_lang_max_vm_size, 'x', XSIZE(struct problem_config_section, lang_max_vm_size), "lang_max_vm_size", XOFFSET(struct problem_config_section, lang_max_vm_size) },
  [META_PROBLEM_CONFIG_SECTION_lang_max_stack_size] = { META_PROBLEM_CONFIG_SECTION_lang_max_stack_size, 'x', XSIZE(struct problem_config_section, lang_max_stack_size), "lang_max_stack_size", XOFFSET(struct problem_config_section, lang_max_stack_size) },
  [META_PROBLEM_CONFIG_SECTION_personal_deadline] = { META_PROBLEM_CONFIG_SECTION_personal_deadline, 'x', XSIZE(struct problem_config_section, personal_deadline), "personal_deadline", XOFFSET(struct problem_config_section, personal_deadline) },
  [META_PROBLEM_CONFIG_SECTION_score_view] = { META_PROBLEM_CONFIG_SECTION_score_view, 'x', XSIZE(struct problem_config_section, score_view), "score_view", XOFFSET(struct problem_config_section, score_view) },
  [META_PROBLEM_CONFIG_SECTION_score_view_text] = { META_PROBLEM_CONFIG_SECTION_score_view_text, 'x', XSIZE(struct problem_config_section, score_view_text), "score_view_text", XOFFSET(struct problem_config_section, score_view_text) },
  [META_PROBLEM_CONFIG_SECTION_lang_compiler_env] = { META_PROBLEM_CONFIG_SECTION_lang_compiler_env, 'X', XSIZE(struct problem_config_section, lang_compiler_env), "lang_compiler_env", XOFFSET(struct problem_config_section, lang_compiler_env) },
  [META_PROBLEM_CONFIG_SECTION_checker_env] = { META_PROBLEM_CONFIG_SECTION_checker_env, 'X', XSIZE(struct problem_config_section, checker_env), "checker_env", XOFFSET(struct problem_config_section, checker_env) },
  [META_PROBLEM_CONFIG_SECTION_valuer_env] = { META_PROBLEM_CONFIG_SECTION_valuer_env, 'X', XSIZE(struct problem_config_section, valuer_env), "valuer_env", XOFFSET(struct problem_config_section, valuer_env) },
  [META_PROBLEM_CONFIG_SECTION_interactor_env] = { META_PROBLEM_CONFIG_SECTION_interactor_env, 'X', XSIZE(struct problem_config_section, interactor_env), "interactor_env", XOFFSET(struct problem_config_section, interactor_env) },
  [META_PROBLEM_CONFIG_SECTION_style_checker_env] = { META_PROBLEM_CONFIG_SECTION_style_checker_env, 'X', XSIZE(struct problem_config_section, style_checker_env), "style_checker_env", XOFFSET(struct problem_config_section, style_checker_env) },
  [META_PROBLEM_CONFIG_SECTION_test_checker_env] = { META_PROBLEM_CONFIG_SECTION_test_checker_env, 'X', XSIZE(struct problem_config_section, test_checker_env), "test_checker_env", XOFFSET(struct problem_config_section, test_checker_env) },
  [META_PROBLEM_CONFIG_SECTION_init_env] = { META_PROBLEM_CONFIG_SECTION_init_env, 'X', XSIZE(struct problem_config_section, init_env), "init_env", XOFFSET(struct problem_config_section, init_env) },
  [META_PROBLEM_CONFIG_SECTION_start_env] = { META_PROBLEM_CONFIG_SECTION_start_env, 'X', XSIZE(struct problem_config_section, start_env), "start_env", XOFFSET(struct problem_config_section, start_env) },
};

int meta_problem_config_section_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_PROBLEM_CONFIG_SECTION_LAST_FIELD);
  return meta_info_problem_config_section_data[tag].type;
}

size_t meta_problem_config_section_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_PROBLEM_CONFIG_SECTION_LAST_FIELD);
  return meta_info_problem_config_section_data[tag].size;
}

const char *meta_problem_config_section_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_PROBLEM_CONFIG_SECTION_LAST_FIELD);
  return meta_info_problem_config_section_data[tag].name;
}

const void *meta_problem_config_section_get_ptr(const struct problem_config_section *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_PROBLEM_CONFIG_SECTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_problem_config_section_data[tag].offset);
}

void *meta_problem_config_section_get_ptr_nc(struct problem_config_section *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_PROBLEM_CONFIG_SECTION_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_problem_config_section_data[tag].offset);
}

int meta_problem_config_section_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_problem_config_section_data, META_PROBLEM_CONFIG_SECTION_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_problem_config_section_methods =
{
  META_PROBLEM_CONFIG_SECTION_LAST_FIELD,
  sizeof(struct problem_config_section),
  meta_problem_config_section_get_type,
  meta_problem_config_section_get_size,
  meta_problem_config_section_get_name,
  (const void *(*)(const void *ptr, int tag))meta_problem_config_section_get_ptr,
  (void *(*)(void *ptr, int tag))meta_problem_config_section_get_ptr_nc,
  meta_problem_config_section_lookup_field,
};

