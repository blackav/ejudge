// This is an auto-generated file, do not edit

#include "ejudge/meta/problem_config_meta.h"
#include "ejudge/problem_config.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

#include "ejudge/parsecfg.h"

#include "ejudge/logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_problem_config_section_data[] =
{
  [META_PROBLEM_CONFIG_SECTION_manual_checking] = { META_PROBLEM_CONFIG_SECTION_manual_checking, 'f', XSIZE(struct problem_config_section, manual_checking), "manual_checking", XOFFSET(struct problem_config_section, manual_checking) },
  [META_PROBLEM_CONFIG_SECTION_check_presentation] = { META_PROBLEM_CONFIG_SECTION_check_presentation, 'f', XSIZE(struct problem_config_section, check_presentation), "check_presentation", XOFFSET(struct problem_config_section, check_presentation) },
  [META_PROBLEM_CONFIG_SECTION_scoring_checker] = { META_PROBLEM_CONFIG_SECTION_scoring_checker, 'f', XSIZE(struct problem_config_section, scoring_checker), "scoring_checker", XOFFSET(struct problem_config_section, scoring_checker) },
  [META_PROBLEM_CONFIG_SECTION_enable_checker_token] = { META_PROBLEM_CONFIG_SECTION_enable_checker_token, 'f', XSIZE(struct problem_config_section, enable_checker_token), "enable_checker_token", XOFFSET(struct problem_config_section, enable_checker_token) },
  [META_PROBLEM_CONFIG_SECTION_interactive_valuer] = { META_PROBLEM_CONFIG_SECTION_interactive_valuer, 'f', XSIZE(struct problem_config_section, interactive_valuer), "interactive_valuer", XOFFSET(struct problem_config_section, interactive_valuer) },
  [META_PROBLEM_CONFIG_SECTION_disable_pe] = { META_PROBLEM_CONFIG_SECTION_disable_pe, 'f', XSIZE(struct problem_config_section, disable_pe), "disable_pe", XOFFSET(struct problem_config_section, disable_pe) },
  [META_PROBLEM_CONFIG_SECTION_disable_wtl] = { META_PROBLEM_CONFIG_SECTION_disable_wtl, 'f', XSIZE(struct problem_config_section, disable_wtl), "disable_wtl", XOFFSET(struct problem_config_section, disable_wtl) },
  [META_PROBLEM_CONFIG_SECTION_wtl_is_cf] = { META_PROBLEM_CONFIG_SECTION_wtl_is_cf, 'f', XSIZE(struct problem_config_section, wtl_is_cf), "wtl_is_cf", XOFFSET(struct problem_config_section, wtl_is_cf) },
  [META_PROBLEM_CONFIG_SECTION_use_stdin] = { META_PROBLEM_CONFIG_SECTION_use_stdin, 'f', XSIZE(struct problem_config_section, use_stdin), "use_stdin", XOFFSET(struct problem_config_section, use_stdin) },
  [META_PROBLEM_CONFIG_SECTION_use_stdout] = { META_PROBLEM_CONFIG_SECTION_use_stdout, 'f', XSIZE(struct problem_config_section, use_stdout), "use_stdout", XOFFSET(struct problem_config_section, use_stdout) },
  [META_PROBLEM_CONFIG_SECTION_combined_stdin] = { META_PROBLEM_CONFIG_SECTION_combined_stdin, 'f', XSIZE(struct problem_config_section, combined_stdin), "combined_stdin", XOFFSET(struct problem_config_section, combined_stdin) },
  [META_PROBLEM_CONFIG_SECTION_combined_stdout] = { META_PROBLEM_CONFIG_SECTION_combined_stdout, 'f', XSIZE(struct problem_config_section, combined_stdout), "combined_stdout", XOFFSET(struct problem_config_section, combined_stdout) },
  [META_PROBLEM_CONFIG_SECTION_binary_input] = { META_PROBLEM_CONFIG_SECTION_binary_input, 'f', XSIZE(struct problem_config_section, binary_input), "binary_input", XOFFSET(struct problem_config_section, binary_input) },
  [META_PROBLEM_CONFIG_SECTION_binary] = { META_PROBLEM_CONFIG_SECTION_binary, 'f', XSIZE(struct problem_config_section, binary), "binary", XOFFSET(struct problem_config_section, binary) },
  [META_PROBLEM_CONFIG_SECTION_ignore_exit_code] = { META_PROBLEM_CONFIG_SECTION_ignore_exit_code, 'f', XSIZE(struct problem_config_section, ignore_exit_code), "ignore_exit_code", XOFFSET(struct problem_config_section, ignore_exit_code) },
  [META_PROBLEM_CONFIG_SECTION_ignore_term_signal] = { META_PROBLEM_CONFIG_SECTION_ignore_term_signal, 'f', XSIZE(struct problem_config_section, ignore_term_signal), "ignore_term_signal", XOFFSET(struct problem_config_section, ignore_term_signal) },
  [META_PROBLEM_CONFIG_SECTION_olympiad_mode] = { META_PROBLEM_CONFIG_SECTION_olympiad_mode, 'f', XSIZE(struct problem_config_section, olympiad_mode), "olympiad_mode", XOFFSET(struct problem_config_section, olympiad_mode) },
  [META_PROBLEM_CONFIG_SECTION_score_latest] = { META_PROBLEM_CONFIG_SECTION_score_latest, 'f', XSIZE(struct problem_config_section, score_latest), "score_latest", XOFFSET(struct problem_config_section, score_latest) },
  [META_PROBLEM_CONFIG_SECTION_score_latest_or_unmarked] = { META_PROBLEM_CONFIG_SECTION_score_latest_or_unmarked, 'f', XSIZE(struct problem_config_section, score_latest_or_unmarked), "score_latest_or_unmarked", XOFFSET(struct problem_config_section, score_latest_or_unmarked) },
  [META_PROBLEM_CONFIG_SECTION_score_latest_marked] = { META_PROBLEM_CONFIG_SECTION_score_latest_marked, 'f', XSIZE(struct problem_config_section, score_latest_marked), "score_latest_marked", XOFFSET(struct problem_config_section, score_latest_marked) },
  [META_PROBLEM_CONFIG_SECTION_score_tokenized] = { META_PROBLEM_CONFIG_SECTION_score_tokenized, 'f', XSIZE(struct problem_config_section, score_tokenized), "score_tokenized", XOFFSET(struct problem_config_section, score_tokenized) },
  [META_PROBLEM_CONFIG_SECTION_use_ac_not_ok] = { META_PROBLEM_CONFIG_SECTION_use_ac_not_ok, 'f', XSIZE(struct problem_config_section, use_ac_not_ok), "use_ac_not_ok", XOFFSET(struct problem_config_section, use_ac_not_ok) },
  [META_PROBLEM_CONFIG_SECTION_ignore_prev_ac] = { META_PROBLEM_CONFIG_SECTION_ignore_prev_ac, 'f', XSIZE(struct problem_config_section, ignore_prev_ac), "ignore_prev_ac", XOFFSET(struct problem_config_section, ignore_prev_ac) },
  [META_PROBLEM_CONFIG_SECTION_team_enable_rep_view] = { META_PROBLEM_CONFIG_SECTION_team_enable_rep_view, 'f', XSIZE(struct problem_config_section, team_enable_rep_view), "team_enable_rep_view", XOFFSET(struct problem_config_section, team_enable_rep_view) },
  [META_PROBLEM_CONFIG_SECTION_team_enable_ce_view] = { META_PROBLEM_CONFIG_SECTION_team_enable_ce_view, 'f', XSIZE(struct problem_config_section, team_enable_ce_view), "team_enable_ce_view", XOFFSET(struct problem_config_section, team_enable_ce_view) },
  [META_PROBLEM_CONFIG_SECTION_team_show_judge_report] = { META_PROBLEM_CONFIG_SECTION_team_show_judge_report, 'f', XSIZE(struct problem_config_section, team_show_judge_report), "team_show_judge_report", XOFFSET(struct problem_config_section, team_show_judge_report) },
  [META_PROBLEM_CONFIG_SECTION_show_checker_comment] = { META_PROBLEM_CONFIG_SECTION_show_checker_comment, 'f', XSIZE(struct problem_config_section, show_checker_comment), "show_checker_comment", XOFFSET(struct problem_config_section, show_checker_comment) },
  [META_PROBLEM_CONFIG_SECTION_ignore_compile_errors] = { META_PROBLEM_CONFIG_SECTION_ignore_compile_errors, 'f', XSIZE(struct problem_config_section, ignore_compile_errors), "ignore_compile_errors", XOFFSET(struct problem_config_section, ignore_compile_errors) },
  [META_PROBLEM_CONFIG_SECTION_variable_full_score] = { META_PROBLEM_CONFIG_SECTION_variable_full_score, 'f', XSIZE(struct problem_config_section, variable_full_score), "variable_full_score", XOFFSET(struct problem_config_section, variable_full_score) },
  [META_PROBLEM_CONFIG_SECTION_ignore_penalty] = { META_PROBLEM_CONFIG_SECTION_ignore_penalty, 'f', XSIZE(struct problem_config_section, ignore_penalty), "ignore_penalty", XOFFSET(struct problem_config_section, ignore_penalty) },
  [META_PROBLEM_CONFIG_SECTION_use_corr] = { META_PROBLEM_CONFIG_SECTION_use_corr, 'f', XSIZE(struct problem_config_section, use_corr), "use_corr", XOFFSET(struct problem_config_section, use_corr) },
  [META_PROBLEM_CONFIG_SECTION_use_info] = { META_PROBLEM_CONFIG_SECTION_use_info, 'f', XSIZE(struct problem_config_section, use_info), "use_info", XOFFSET(struct problem_config_section, use_info) },
  [META_PROBLEM_CONFIG_SECTION_use_tgz] = { META_PROBLEM_CONFIG_SECTION_use_tgz, 'f', XSIZE(struct problem_config_section, use_tgz), "use_tgz", XOFFSET(struct problem_config_section, use_tgz) },
  [META_PROBLEM_CONFIG_SECTION_accept_partial] = { META_PROBLEM_CONFIG_SECTION_accept_partial, 'f', XSIZE(struct problem_config_section, accept_partial), "accept_partial", XOFFSET(struct problem_config_section, accept_partial) },
  [META_PROBLEM_CONFIG_SECTION_disable_user_submit] = { META_PROBLEM_CONFIG_SECTION_disable_user_submit, 'f', XSIZE(struct problem_config_section, disable_user_submit), "disable_user_submit", XOFFSET(struct problem_config_section, disable_user_submit) },
  [META_PROBLEM_CONFIG_SECTION_disable_tab] = { META_PROBLEM_CONFIG_SECTION_disable_tab, 'f', XSIZE(struct problem_config_section, disable_tab), "disable_tab", XOFFSET(struct problem_config_section, disable_tab) },
  [META_PROBLEM_CONFIG_SECTION_unrestricted_statement] = { META_PROBLEM_CONFIG_SECTION_unrestricted_statement, 'f', XSIZE(struct problem_config_section, unrestricted_statement), "unrestricted_statement", XOFFSET(struct problem_config_section, unrestricted_statement) },
  [META_PROBLEM_CONFIG_SECTION_statement_ignore_ip] = { META_PROBLEM_CONFIG_SECTION_statement_ignore_ip, 'f', XSIZE(struct problem_config_section, statement_ignore_ip), "statement_ignore_ip", XOFFSET(struct problem_config_section, statement_ignore_ip) },
  [META_PROBLEM_CONFIG_SECTION_restricted_statement] = { META_PROBLEM_CONFIG_SECTION_restricted_statement, 'f', XSIZE(struct problem_config_section, restricted_statement), "restricted_statement", XOFFSET(struct problem_config_section, restricted_statement) },
  [META_PROBLEM_CONFIG_SECTION_enable_submit_after_reject] = { META_PROBLEM_CONFIG_SECTION_enable_submit_after_reject, 'f', XSIZE(struct problem_config_section, enable_submit_after_reject), "enable_submit_after_reject", XOFFSET(struct problem_config_section, enable_submit_after_reject) },
  [META_PROBLEM_CONFIG_SECTION_hide_file_names] = { META_PROBLEM_CONFIG_SECTION_hide_file_names, 'f', XSIZE(struct problem_config_section, hide_file_names), "hide_file_names", XOFFSET(struct problem_config_section, hide_file_names) },
  [META_PROBLEM_CONFIG_SECTION_hide_real_time_limit] = { META_PROBLEM_CONFIG_SECTION_hide_real_time_limit, 'f', XSIZE(struct problem_config_section, hide_real_time_limit), "hide_real_time_limit", XOFFSET(struct problem_config_section, hide_real_time_limit) },
  [META_PROBLEM_CONFIG_SECTION_enable_tokens] = { META_PROBLEM_CONFIG_SECTION_enable_tokens, 'f', XSIZE(struct problem_config_section, enable_tokens), "enable_tokens", XOFFSET(struct problem_config_section, enable_tokens) },
  [META_PROBLEM_CONFIG_SECTION_tokens_for_user_ac] = { META_PROBLEM_CONFIG_SECTION_tokens_for_user_ac, 'f', XSIZE(struct problem_config_section, tokens_for_user_ac), "tokens_for_user_ac", XOFFSET(struct problem_config_section, tokens_for_user_ac) },
  [META_PROBLEM_CONFIG_SECTION_disable_submit_after_ok] = { META_PROBLEM_CONFIG_SECTION_disable_submit_after_ok, 'f', XSIZE(struct problem_config_section, disable_submit_after_ok), "disable_submit_after_ok", XOFFSET(struct problem_config_section, disable_submit_after_ok) },
  [META_PROBLEM_CONFIG_SECTION_disable_auto_testing] = { META_PROBLEM_CONFIG_SECTION_disable_auto_testing, 'f', XSIZE(struct problem_config_section, disable_auto_testing), "disable_auto_testing", XOFFSET(struct problem_config_section, disable_auto_testing) },
  [META_PROBLEM_CONFIG_SECTION_disable_testing] = { META_PROBLEM_CONFIG_SECTION_disable_testing, 'f', XSIZE(struct problem_config_section, disable_testing), "disable_testing", XOFFSET(struct problem_config_section, disable_testing) },
  [META_PROBLEM_CONFIG_SECTION_enable_compilation] = { META_PROBLEM_CONFIG_SECTION_enable_compilation, 'f', XSIZE(struct problem_config_section, enable_compilation), "enable_compilation", XOFFSET(struct problem_config_section, enable_compilation) },
  [META_PROBLEM_CONFIG_SECTION_skip_testing] = { META_PROBLEM_CONFIG_SECTION_skip_testing, 'f', XSIZE(struct problem_config_section, skip_testing), "skip_testing", XOFFSET(struct problem_config_section, skip_testing) },
  [META_PROBLEM_CONFIG_SECTION_hidden] = { META_PROBLEM_CONFIG_SECTION_hidden, 'f', XSIZE(struct problem_config_section, hidden), "hidden", XOFFSET(struct problem_config_section, hidden) },
  [META_PROBLEM_CONFIG_SECTION_stand_hide_time] = { META_PROBLEM_CONFIG_SECTION_stand_hide_time, 'f', XSIZE(struct problem_config_section, stand_hide_time), "stand_hide_time", XOFFSET(struct problem_config_section, stand_hide_time) },
  [META_PROBLEM_CONFIG_SECTION_advance_to_next] = { META_PROBLEM_CONFIG_SECTION_advance_to_next, 'f', XSIZE(struct problem_config_section, advance_to_next), "advance_to_next", XOFFSET(struct problem_config_section, advance_to_next) },
  [META_PROBLEM_CONFIG_SECTION_disable_ctrl_chars] = { META_PROBLEM_CONFIG_SECTION_disable_ctrl_chars, 'f', XSIZE(struct problem_config_section, disable_ctrl_chars), "disable_ctrl_chars", XOFFSET(struct problem_config_section, disable_ctrl_chars) },
  [META_PROBLEM_CONFIG_SECTION_enable_text_form] = { META_PROBLEM_CONFIG_SECTION_enable_text_form, 'f', XSIZE(struct problem_config_section, enable_text_form), "enable_text_form", XOFFSET(struct problem_config_section, enable_text_form) },
  [META_PROBLEM_CONFIG_SECTION_stand_ignore_score] = { META_PROBLEM_CONFIG_SECTION_stand_ignore_score, 'f', XSIZE(struct problem_config_section, stand_ignore_score), "stand_ignore_score", XOFFSET(struct problem_config_section, stand_ignore_score) },
  [META_PROBLEM_CONFIG_SECTION_stand_last_column] = { META_PROBLEM_CONFIG_SECTION_stand_last_column, 'f', XSIZE(struct problem_config_section, stand_last_column), "stand_last_column", XOFFSET(struct problem_config_section, stand_last_column) },
  [META_PROBLEM_CONFIG_SECTION_disable_security] = { META_PROBLEM_CONFIG_SECTION_disable_security, 'f', XSIZE(struct problem_config_section, disable_security), "disable_security", XOFFSET(struct problem_config_section, disable_security) },
  [META_PROBLEM_CONFIG_SECTION_enable_suid_run] = { META_PROBLEM_CONFIG_SECTION_enable_suid_run, 'f', XSIZE(struct problem_config_section, enable_suid_run), "enable_suid_run", XOFFSET(struct problem_config_section, enable_suid_run) },
  [META_PROBLEM_CONFIG_SECTION_enable_container] = { META_PROBLEM_CONFIG_SECTION_enable_container, 'f', XSIZE(struct problem_config_section, enable_container), "enable_container", XOFFSET(struct problem_config_section, enable_container) },
  [META_PROBLEM_CONFIG_SECTION_enable_dynamic_priority] = { META_PROBLEM_CONFIG_SECTION_enable_dynamic_priority, 'f', XSIZE(struct problem_config_section, enable_dynamic_priority), "enable_dynamic_priority", XOFFSET(struct problem_config_section, enable_dynamic_priority) },
  [META_PROBLEM_CONFIG_SECTION_valuer_sets_marked] = { META_PROBLEM_CONFIG_SECTION_valuer_sets_marked, 'f', XSIZE(struct problem_config_section, valuer_sets_marked), "valuer_sets_marked", XOFFSET(struct problem_config_section, valuer_sets_marked) },
  [META_PROBLEM_CONFIG_SECTION_ignore_unmarked] = { META_PROBLEM_CONFIG_SECTION_ignore_unmarked, 'f', XSIZE(struct problem_config_section, ignore_unmarked), "ignore_unmarked", XOFFSET(struct problem_config_section, ignore_unmarked) },
  [META_PROBLEM_CONFIG_SECTION_disable_stderr] = { META_PROBLEM_CONFIG_SECTION_disable_stderr, 'f', XSIZE(struct problem_config_section, disable_stderr), "disable_stderr", XOFFSET(struct problem_config_section, disable_stderr) },
  [META_PROBLEM_CONFIG_SECTION_enable_process_group] = { META_PROBLEM_CONFIG_SECTION_enable_process_group, 'f', XSIZE(struct problem_config_section, enable_process_group), "enable_process_group", XOFFSET(struct problem_config_section, enable_process_group) },
  [META_PROBLEM_CONFIG_SECTION_enable_kill_all] = { META_PROBLEM_CONFIG_SECTION_enable_kill_all, 'f', XSIZE(struct problem_config_section, enable_kill_all), "enable_kill_all", XOFFSET(struct problem_config_section, enable_kill_all) },
  [META_PROBLEM_CONFIG_SECTION_hide_variant] = { META_PROBLEM_CONFIG_SECTION_hide_variant, 'f', XSIZE(struct problem_config_section, hide_variant), "hide_variant", XOFFSET(struct problem_config_section, hide_variant) },
  [META_PROBLEM_CONFIG_SECTION_enable_testlib_mode] = { META_PROBLEM_CONFIG_SECTION_enable_testlib_mode, 'f', XSIZE(struct problem_config_section, enable_testlib_mode), "enable_testlib_mode", XOFFSET(struct problem_config_section, enable_testlib_mode) },
  [META_PROBLEM_CONFIG_SECTION_autoassign_variants] = { META_PROBLEM_CONFIG_SECTION_autoassign_variants, 'f', XSIZE(struct problem_config_section, autoassign_variants), "autoassign_variants", XOFFSET(struct problem_config_section, autoassign_variants) },
  [META_PROBLEM_CONFIG_SECTION_require_any] = { META_PROBLEM_CONFIG_SECTION_require_any, 'f', XSIZE(struct problem_config_section, require_any), "require_any", XOFFSET(struct problem_config_section, require_any) },
  [META_PROBLEM_CONFIG_SECTION_enable_extended_info] = { META_PROBLEM_CONFIG_SECTION_enable_extended_info, 'f', XSIZE(struct problem_config_section, enable_extended_info), "enable_extended_info", XOFFSET(struct problem_config_section, enable_extended_info) },
  [META_PROBLEM_CONFIG_SECTION_stop_on_first_fail] = { META_PROBLEM_CONFIG_SECTION_stop_on_first_fail, 'f', XSIZE(struct problem_config_section, stop_on_first_fail), "stop_on_first_fail", XOFFSET(struct problem_config_section, stop_on_first_fail) },
  [META_PROBLEM_CONFIG_SECTION_enable_control_socket] = { META_PROBLEM_CONFIG_SECTION_enable_control_socket, 'f', XSIZE(struct problem_config_section, enable_control_socket), "enable_control_socket", XOFFSET(struct problem_config_section, enable_control_socket) },
  [META_PROBLEM_CONFIG_SECTION_copy_exe_to_tgzdir] = { META_PROBLEM_CONFIG_SECTION_copy_exe_to_tgzdir, 'f', XSIZE(struct problem_config_section, copy_exe_to_tgzdir), "copy_exe_to_tgzdir", XOFFSET(struct problem_config_section, copy_exe_to_tgzdir) },
  [META_PROBLEM_CONFIG_SECTION_enable_multi_header] = { META_PROBLEM_CONFIG_SECTION_enable_multi_header, 'f', XSIZE(struct problem_config_section, enable_multi_header), "enable_multi_header", XOFFSET(struct problem_config_section, enable_multi_header) },
  [META_PROBLEM_CONFIG_SECTION_use_lang_multi_header] = { META_PROBLEM_CONFIG_SECTION_use_lang_multi_header, 'f', XSIZE(struct problem_config_section, use_lang_multi_header), "use_lang_multi_header", XOFFSET(struct problem_config_section, use_lang_multi_header) },
  [META_PROBLEM_CONFIG_SECTION_notify_on_submit] = { META_PROBLEM_CONFIG_SECTION_notify_on_submit, 'f', XSIZE(struct problem_config_section, notify_on_submit), "notify_on_submit", XOFFSET(struct problem_config_section, notify_on_submit) },
  [META_PROBLEM_CONFIG_SECTION_enable_user_input] = { META_PROBLEM_CONFIG_SECTION_enable_user_input, 'f', XSIZE(struct problem_config_section, enable_user_input), "enable_user_input", XOFFSET(struct problem_config_section, enable_user_input) },
  [META_PROBLEM_CONFIG_SECTION_enable_vcs] = { META_PROBLEM_CONFIG_SECTION_enable_vcs, 'f', XSIZE(struct problem_config_section, enable_vcs), "enable_vcs", XOFFSET(struct problem_config_section, enable_vcs) },
  [META_PROBLEM_CONFIG_SECTION_enable_iframe_statement] = { META_PROBLEM_CONFIG_SECTION_enable_iframe_statement, 'f', XSIZE(struct problem_config_section, enable_iframe_statement), "enable_iframe_statement", XOFFSET(struct problem_config_section, enable_iframe_statement) },
  [META_PROBLEM_CONFIG_SECTION_enable_src_for_testing] = { META_PROBLEM_CONFIG_SECTION_enable_src_for_testing, 'f', XSIZE(struct problem_config_section, enable_src_for_testing), "enable_src_for_testing", XOFFSET(struct problem_config_section, enable_src_for_testing) },
  [META_PROBLEM_CONFIG_SECTION_disable_vm_size_limit] = { META_PROBLEM_CONFIG_SECTION_disable_vm_size_limit, 'f', XSIZE(struct problem_config_section, disable_vm_size_limit), "disable_vm_size_limit", XOFFSET(struct problem_config_section, disable_vm_size_limit) },
  [META_PROBLEM_CONFIG_SECTION_enable_group_merge] = { META_PROBLEM_CONFIG_SECTION_enable_group_merge, 'f', XSIZE(struct problem_config_section, enable_group_merge), "enable_group_merge", XOFFSET(struct problem_config_section, enable_group_merge) },
  [META_PROBLEM_CONFIG_SECTION_id] = { META_PROBLEM_CONFIG_SECTION_id, 'i', XSIZE(struct problem_config_section, id), "id", XOFFSET(struct problem_config_section, id) },
  [META_PROBLEM_CONFIG_SECTION_variant_num] = { META_PROBLEM_CONFIG_SECTION_variant_num, 'i', XSIZE(struct problem_config_section, variant_num), "variant_num", XOFFSET(struct problem_config_section, variant_num) },
  [META_PROBLEM_CONFIG_SECTION_full_score] = { META_PROBLEM_CONFIG_SECTION_full_score, 'i', XSIZE(struct problem_config_section, full_score), "full_score", XOFFSET(struct problem_config_section, full_score) },
  [META_PROBLEM_CONFIG_SECTION_full_user_score] = { META_PROBLEM_CONFIG_SECTION_full_user_score, 'i', XSIZE(struct problem_config_section, full_user_score), "full_user_score", XOFFSET(struct problem_config_section, full_user_score) },
  [META_PROBLEM_CONFIG_SECTION_min_score_1] = { META_PROBLEM_CONFIG_SECTION_min_score_1, 'i', XSIZE(struct problem_config_section, min_score_1), "min_score_1", XOFFSET(struct problem_config_section, min_score_1) },
  [META_PROBLEM_CONFIG_SECTION_min_score_2] = { META_PROBLEM_CONFIG_SECTION_min_score_2, 'i', XSIZE(struct problem_config_section, min_score_2), "min_score_2", XOFFSET(struct problem_config_section, min_score_2) },
  [META_PROBLEM_CONFIG_SECTION_real_time_limit] = { META_PROBLEM_CONFIG_SECTION_real_time_limit, 'i', XSIZE(struct problem_config_section, real_time_limit), "real_time_limit", XOFFSET(struct problem_config_section, real_time_limit) },
  [META_PROBLEM_CONFIG_SECTION_time_limit] = { META_PROBLEM_CONFIG_SECTION_time_limit, 'i', XSIZE(struct problem_config_section, time_limit), "time_limit", XOFFSET(struct problem_config_section, time_limit) },
  [META_PROBLEM_CONFIG_SECTION_time_limit_millis] = { META_PROBLEM_CONFIG_SECTION_time_limit_millis, 'i', XSIZE(struct problem_config_section, time_limit_millis), "time_limit_millis", XOFFSET(struct problem_config_section, time_limit_millis) },
  [META_PROBLEM_CONFIG_SECTION_test_score] = { META_PROBLEM_CONFIG_SECTION_test_score, 'i', XSIZE(struct problem_config_section, test_score), "test_score", XOFFSET(struct problem_config_section, test_score) },
  [META_PROBLEM_CONFIG_SECTION_run_penalty] = { META_PROBLEM_CONFIG_SECTION_run_penalty, 'i', XSIZE(struct problem_config_section, run_penalty), "run_penalty", XOFFSET(struct problem_config_section, run_penalty) },
  [META_PROBLEM_CONFIG_SECTION_acm_run_penalty] = { META_PROBLEM_CONFIG_SECTION_acm_run_penalty, 'i', XSIZE(struct problem_config_section, acm_run_penalty), "acm_run_penalty", XOFFSET(struct problem_config_section, acm_run_penalty) },
  [META_PROBLEM_CONFIG_SECTION_disqualified_penalty] = { META_PROBLEM_CONFIG_SECTION_disqualified_penalty, 'i', XSIZE(struct problem_config_section, disqualified_penalty), "disqualified_penalty", XOFFSET(struct problem_config_section, disqualified_penalty) },
  [META_PROBLEM_CONFIG_SECTION_compile_error_penalty] = { META_PROBLEM_CONFIG_SECTION_compile_error_penalty, 'i', XSIZE(struct problem_config_section, compile_error_penalty), "compile_error_penalty", XOFFSET(struct problem_config_section, compile_error_penalty) },
  [META_PROBLEM_CONFIG_SECTION_tests_to_accept] = { META_PROBLEM_CONFIG_SECTION_tests_to_accept, 'i', XSIZE(struct problem_config_section, tests_to_accept), "tests_to_accept", XOFFSET(struct problem_config_section, tests_to_accept) },
  [META_PROBLEM_CONFIG_SECTION_min_tests_to_accept] = { META_PROBLEM_CONFIG_SECTION_min_tests_to_accept, 'i', XSIZE(struct problem_config_section, min_tests_to_accept), "min_tests_to_accept", XOFFSET(struct problem_config_section, min_tests_to_accept) },
  [META_PROBLEM_CONFIG_SECTION_checker_real_time_limit] = { META_PROBLEM_CONFIG_SECTION_checker_real_time_limit, 'i', XSIZE(struct problem_config_section, checker_real_time_limit), "checker_real_time_limit", XOFFSET(struct problem_config_section, checker_real_time_limit) },
  [META_PROBLEM_CONFIG_SECTION_checker_time_limit_ms] = { META_PROBLEM_CONFIG_SECTION_checker_time_limit_ms, 'i', XSIZE(struct problem_config_section, checker_time_limit_ms), "checker_time_limit_ms", XOFFSET(struct problem_config_section, checker_time_limit_ms) },
  [META_PROBLEM_CONFIG_SECTION_priority_adjustment] = { META_PROBLEM_CONFIG_SECTION_priority_adjustment, 'i', XSIZE(struct problem_config_section, priority_adjustment), "priority_adjustment", XOFFSET(struct problem_config_section, priority_adjustment) },
  [META_PROBLEM_CONFIG_SECTION_score_multiplier] = { META_PROBLEM_CONFIG_SECTION_score_multiplier, 'i', XSIZE(struct problem_config_section, score_multiplier), "score_multiplier", XOFFSET(struct problem_config_section, score_multiplier) },
  [META_PROBLEM_CONFIG_SECTION_prev_runs_to_show] = { META_PROBLEM_CONFIG_SECTION_prev_runs_to_show, 'i', XSIZE(struct problem_config_section, prev_runs_to_show), "prev_runs_to_show", XOFFSET(struct problem_config_section, prev_runs_to_show) },
  [META_PROBLEM_CONFIG_SECTION_max_user_run_count] = { META_PROBLEM_CONFIG_SECTION_max_user_run_count, 'i', XSIZE(struct problem_config_section, max_user_run_count), "max_user_run_count", XOFFSET(struct problem_config_section, max_user_run_count) },
  [META_PROBLEM_CONFIG_SECTION_interactor_time_limit] = { META_PROBLEM_CONFIG_SECTION_interactor_time_limit, 'i', XSIZE(struct problem_config_section, interactor_time_limit), "interactor_time_limit", XOFFSET(struct problem_config_section, interactor_time_limit) },
  [META_PROBLEM_CONFIG_SECTION_interactor_real_time_limit] = { META_PROBLEM_CONFIG_SECTION_interactor_real_time_limit, 'i', XSIZE(struct problem_config_section, interactor_real_time_limit), "interactor_real_time_limit", XOFFSET(struct problem_config_section, interactor_real_time_limit) },
  [META_PROBLEM_CONFIG_SECTION_max_open_file_count] = { META_PROBLEM_CONFIG_SECTION_max_open_file_count, 'i', XSIZE(struct problem_config_section, max_open_file_count), "max_open_file_count", XOFFSET(struct problem_config_section, max_open_file_count) },
  [META_PROBLEM_CONFIG_SECTION_max_process_count] = { META_PROBLEM_CONFIG_SECTION_max_process_count, 'i', XSIZE(struct problem_config_section, max_process_count), "max_process_count", XOFFSET(struct problem_config_section, max_process_count) },
  [META_PROBLEM_CONFIG_SECTION_deadline] = { META_PROBLEM_CONFIG_SECTION_deadline, 't', XSIZE(struct problem_config_section, deadline), "deadline", XOFFSET(struct problem_config_section, deadline) },
  [META_PROBLEM_CONFIG_SECTION_start_date] = { META_PROBLEM_CONFIG_SECTION_start_date, 't', XSIZE(struct problem_config_section, start_date), "start_date", XOFFSET(struct problem_config_section, start_date) },
  [META_PROBLEM_CONFIG_SECTION_max_vm_size] = { META_PROBLEM_CONFIG_SECTION_max_vm_size, 'E', XSIZE(struct problem_config_section, max_vm_size), "max_vm_size", XOFFSET(struct problem_config_section, max_vm_size) },
  [META_PROBLEM_CONFIG_SECTION_max_data_size] = { META_PROBLEM_CONFIG_SECTION_max_data_size, 'E', XSIZE(struct problem_config_section, max_data_size), "max_data_size", XOFFSET(struct problem_config_section, max_data_size) },
  [META_PROBLEM_CONFIG_SECTION_max_stack_size] = { META_PROBLEM_CONFIG_SECTION_max_stack_size, 'E', XSIZE(struct problem_config_section, max_stack_size), "max_stack_size", XOFFSET(struct problem_config_section, max_stack_size) },
  [META_PROBLEM_CONFIG_SECTION_max_rss_size] = { META_PROBLEM_CONFIG_SECTION_max_rss_size, 'E', XSIZE(struct problem_config_section, max_rss_size), "max_rss_size", XOFFSET(struct problem_config_section, max_rss_size) },
  [META_PROBLEM_CONFIG_SECTION_max_core_size] = { META_PROBLEM_CONFIG_SECTION_max_core_size, 'E', XSIZE(struct problem_config_section, max_core_size), "max_core_size", XOFFSET(struct problem_config_section, max_core_size) },
  [META_PROBLEM_CONFIG_SECTION_max_file_size] = { META_PROBLEM_CONFIG_SECTION_max_file_size, 'E', XSIZE(struct problem_config_section, max_file_size), "max_file_size", XOFFSET(struct problem_config_section, max_file_size) },
  [META_PROBLEM_CONFIG_SECTION_checker_max_vm_size] = { META_PROBLEM_CONFIG_SECTION_checker_max_vm_size, 'E', XSIZE(struct problem_config_section, checker_max_vm_size), "checker_max_vm_size", XOFFSET(struct problem_config_section, checker_max_vm_size) },
  [META_PROBLEM_CONFIG_SECTION_checker_max_stack_size] = { META_PROBLEM_CONFIG_SECTION_checker_max_stack_size, 'E', XSIZE(struct problem_config_section, checker_max_stack_size), "checker_max_stack_size", XOFFSET(struct problem_config_section, checker_max_stack_size) },
  [META_PROBLEM_CONFIG_SECTION_checker_max_rss_size] = { META_PROBLEM_CONFIG_SECTION_checker_max_rss_size, 'E', XSIZE(struct problem_config_section, checker_max_rss_size), "checker_max_rss_size", XOFFSET(struct problem_config_section, checker_max_rss_size) },
  [META_PROBLEM_CONFIG_SECTION_type] = { META_PROBLEM_CONFIG_SECTION_type, 's', XSIZE(struct problem_config_section, type), "type", XOFFSET(struct problem_config_section, type) },
  [META_PROBLEM_CONFIG_SECTION_short_name] = { META_PROBLEM_CONFIG_SECTION_short_name, 's', XSIZE(struct problem_config_section, short_name), "short_name", XOFFSET(struct problem_config_section, short_name) },
  [META_PROBLEM_CONFIG_SECTION_long_name] = { META_PROBLEM_CONFIG_SECTION_long_name, 's', XSIZE(struct problem_config_section, long_name), "long_name", XOFFSET(struct problem_config_section, long_name) },
  [META_PROBLEM_CONFIG_SECTION_long_name_en] = { META_PROBLEM_CONFIG_SECTION_long_name_en, 's', XSIZE(struct problem_config_section, long_name_en), "long_name_en", XOFFSET(struct problem_config_section, long_name_en) },
  [META_PROBLEM_CONFIG_SECTION_stand_name] = { META_PROBLEM_CONFIG_SECTION_stand_name, 's', XSIZE(struct problem_config_section, stand_name), "stand_name", XOFFSET(struct problem_config_section, stand_name) },
  [META_PROBLEM_CONFIG_SECTION_stand_column] = { META_PROBLEM_CONFIG_SECTION_stand_column, 's', XSIZE(struct problem_config_section, stand_column), "stand_column", XOFFSET(struct problem_config_section, stand_column) },
  [META_PROBLEM_CONFIG_SECTION_group_name] = { META_PROBLEM_CONFIG_SECTION_group_name, 's', XSIZE(struct problem_config_section, group_name), "group_name", XOFFSET(struct problem_config_section, group_name) },
  [META_PROBLEM_CONFIG_SECTION_internal_name] = { META_PROBLEM_CONFIG_SECTION_internal_name, 's', XSIZE(struct problem_config_section, internal_name), "internal_name", XOFFSET(struct problem_config_section, internal_name) },
  [META_PROBLEM_CONFIG_SECTION_plugin_entry_name] = { META_PROBLEM_CONFIG_SECTION_plugin_entry_name, 's', XSIZE(struct problem_config_section, plugin_entry_name), "plugin_entry_name", XOFFSET(struct problem_config_section, plugin_entry_name) },
  [META_PROBLEM_CONFIG_SECTION_uuid] = { META_PROBLEM_CONFIG_SECTION_uuid, 's', XSIZE(struct problem_config_section, uuid), "uuid", XOFFSET(struct problem_config_section, uuid) },
  [META_PROBLEM_CONFIG_SECTION_test_dir] = { META_PROBLEM_CONFIG_SECTION_test_dir, 's', XSIZE(struct problem_config_section, test_dir), "test_dir", XOFFSET(struct problem_config_section, test_dir) },
  [META_PROBLEM_CONFIG_SECTION_test_sfx] = { META_PROBLEM_CONFIG_SECTION_test_sfx, 's', XSIZE(struct problem_config_section, test_sfx), "test_sfx", XOFFSET(struct problem_config_section, test_sfx) },
  [META_PROBLEM_CONFIG_SECTION_corr_dir] = { META_PROBLEM_CONFIG_SECTION_corr_dir, 's', XSIZE(struct problem_config_section, corr_dir), "corr_dir", XOFFSET(struct problem_config_section, corr_dir) },
  [META_PROBLEM_CONFIG_SECTION_corr_sfx] = { META_PROBLEM_CONFIG_SECTION_corr_sfx, 's', XSIZE(struct problem_config_section, corr_sfx), "corr_sfx", XOFFSET(struct problem_config_section, corr_sfx) },
  [META_PROBLEM_CONFIG_SECTION_info_dir] = { META_PROBLEM_CONFIG_SECTION_info_dir, 's', XSIZE(struct problem_config_section, info_dir), "info_dir", XOFFSET(struct problem_config_section, info_dir) },
  [META_PROBLEM_CONFIG_SECTION_info_sfx] = { META_PROBLEM_CONFIG_SECTION_info_sfx, 's', XSIZE(struct problem_config_section, info_sfx), "info_sfx", XOFFSET(struct problem_config_section, info_sfx) },
  [META_PROBLEM_CONFIG_SECTION_tgz_dir] = { META_PROBLEM_CONFIG_SECTION_tgz_dir, 's', XSIZE(struct problem_config_section, tgz_dir), "tgz_dir", XOFFSET(struct problem_config_section, tgz_dir) },
  [META_PROBLEM_CONFIG_SECTION_tgz_sfx] = { META_PROBLEM_CONFIG_SECTION_tgz_sfx, 's', XSIZE(struct problem_config_section, tgz_sfx), "tgz_sfx", XOFFSET(struct problem_config_section, tgz_sfx) },
  [META_PROBLEM_CONFIG_SECTION_tgzdir_sfx] = { META_PROBLEM_CONFIG_SECTION_tgzdir_sfx, 's', XSIZE(struct problem_config_section, tgzdir_sfx), "tgzdir_sfx", XOFFSET(struct problem_config_section, tgzdir_sfx) },
  [META_PROBLEM_CONFIG_SECTION_input_file] = { META_PROBLEM_CONFIG_SECTION_input_file, 's', XSIZE(struct problem_config_section, input_file), "input_file", XOFFSET(struct problem_config_section, input_file) },
  [META_PROBLEM_CONFIG_SECTION_output_file] = { META_PROBLEM_CONFIG_SECTION_output_file, 's', XSIZE(struct problem_config_section, output_file), "output_file", XOFFSET(struct problem_config_section, output_file) },
  [META_PROBLEM_CONFIG_SECTION_test_score_list] = { META_PROBLEM_CONFIG_SECTION_test_score_list, 's', XSIZE(struct problem_config_section, test_score_list), "test_score_list", XOFFSET(struct problem_config_section, test_score_list) },
  [META_PROBLEM_CONFIG_SECTION_tokens] = { META_PROBLEM_CONFIG_SECTION_tokens, 's', XSIZE(struct problem_config_section, tokens), "tokens", XOFFSET(struct problem_config_section, tokens) },
  [META_PROBLEM_CONFIG_SECTION_umask] = { META_PROBLEM_CONFIG_SECTION_umask, 's', XSIZE(struct problem_config_section, umask), "umask", XOFFSET(struct problem_config_section, umask) },
  [META_PROBLEM_CONFIG_SECTION_ok_status] = { META_PROBLEM_CONFIG_SECTION_ok_status, 's', XSIZE(struct problem_config_section, ok_status), "ok_status", XOFFSET(struct problem_config_section, ok_status) },
  [META_PROBLEM_CONFIG_SECTION_header_pat] = { META_PROBLEM_CONFIG_SECTION_header_pat, 's', XSIZE(struct problem_config_section, header_pat), "header_pat", XOFFSET(struct problem_config_section, header_pat) },
  [META_PROBLEM_CONFIG_SECTION_footer_pat] = { META_PROBLEM_CONFIG_SECTION_footer_pat, 's', XSIZE(struct problem_config_section, footer_pat), "footer_pat", XOFFSET(struct problem_config_section, footer_pat) },
  [META_PROBLEM_CONFIG_SECTION_compiler_env_pat] = { META_PROBLEM_CONFIG_SECTION_compiler_env_pat, 's', XSIZE(struct problem_config_section, compiler_env_pat), "compiler_env_pat", XOFFSET(struct problem_config_section, compiler_env_pat) },
  [META_PROBLEM_CONFIG_SECTION_container_options] = { META_PROBLEM_CONFIG_SECTION_container_options, 's', XSIZE(struct problem_config_section, container_options), "container_options", XOFFSET(struct problem_config_section, container_options) },
  [META_PROBLEM_CONFIG_SECTION_score_tests] = { META_PROBLEM_CONFIG_SECTION_score_tests, 's', XSIZE(struct problem_config_section, score_tests), "score_tests", XOFFSET(struct problem_config_section, score_tests) },
  [META_PROBLEM_CONFIG_SECTION_standard_checker] = { META_PROBLEM_CONFIG_SECTION_standard_checker, 's', XSIZE(struct problem_config_section, standard_checker), "standard_checker", XOFFSET(struct problem_config_section, standard_checker) },
  [META_PROBLEM_CONFIG_SECTION_spelling] = { META_PROBLEM_CONFIG_SECTION_spelling, 's', XSIZE(struct problem_config_section, spelling), "spelling", XOFFSET(struct problem_config_section, spelling) },
  [META_PROBLEM_CONFIG_SECTION_statement_file] = { META_PROBLEM_CONFIG_SECTION_statement_file, 's', XSIZE(struct problem_config_section, statement_file), "statement_file", XOFFSET(struct problem_config_section, statement_file) },
  [META_PROBLEM_CONFIG_SECTION_plugin_file] = { META_PROBLEM_CONFIG_SECTION_plugin_file, 's', XSIZE(struct problem_config_section, plugin_file), "plugin_file", XOFFSET(struct problem_config_section, plugin_file) },
  [META_PROBLEM_CONFIG_SECTION_xml_file] = { META_PROBLEM_CONFIG_SECTION_xml_file, 's', XSIZE(struct problem_config_section, xml_file), "xml_file", XOFFSET(struct problem_config_section, xml_file) },
  [META_PROBLEM_CONFIG_SECTION_stand_attr] = { META_PROBLEM_CONFIG_SECTION_stand_attr, 's', XSIZE(struct problem_config_section, stand_attr), "stand_attr", XOFFSET(struct problem_config_section, stand_attr) },
  [META_PROBLEM_CONFIG_SECTION_source_header] = { META_PROBLEM_CONFIG_SECTION_source_header, 's', XSIZE(struct problem_config_section, source_header), "source_header", XOFFSET(struct problem_config_section, source_header) },
  [META_PROBLEM_CONFIG_SECTION_source_footer] = { META_PROBLEM_CONFIG_SECTION_source_footer, 's', XSIZE(struct problem_config_section, source_footer), "source_footer", XOFFSET(struct problem_config_section, source_footer) },
  [META_PROBLEM_CONFIG_SECTION_custom_compile_cmd] = { META_PROBLEM_CONFIG_SECTION_custom_compile_cmd, 's', XSIZE(struct problem_config_section, custom_compile_cmd), "custom_compile_cmd", XOFFSET(struct problem_config_section, custom_compile_cmd) },
  [META_PROBLEM_CONFIG_SECTION_custom_lang_name] = { META_PROBLEM_CONFIG_SECTION_custom_lang_name, 's', XSIZE(struct problem_config_section, custom_lang_name), "custom_lang_name", XOFFSET(struct problem_config_section, custom_lang_name) },
  [META_PROBLEM_CONFIG_SECTION_extra_src_dir] = { META_PROBLEM_CONFIG_SECTION_extra_src_dir, 's', XSIZE(struct problem_config_section, extra_src_dir), "extra_src_dir", XOFFSET(struct problem_config_section, extra_src_dir) },
  [META_PROBLEM_CONFIG_SECTION_standard_valuer] = { META_PROBLEM_CONFIG_SECTION_standard_valuer, 's', XSIZE(struct problem_config_section, standard_valuer), "standard_valuer", XOFFSET(struct problem_config_section, standard_valuer) },
  [META_PROBLEM_CONFIG_SECTION_md_file] = { META_PROBLEM_CONFIG_SECTION_md_file, 's', XSIZE(struct problem_config_section, md_file), "md_file", XOFFSET(struct problem_config_section, md_file) },
  [META_PROBLEM_CONFIG_SECTION_test_pat] = { META_PROBLEM_CONFIG_SECTION_test_pat, 's', XSIZE(struct problem_config_section, test_pat), "test_pat", XOFFSET(struct problem_config_section, test_pat) },
  [META_PROBLEM_CONFIG_SECTION_corr_pat] = { META_PROBLEM_CONFIG_SECTION_corr_pat, 's', XSIZE(struct problem_config_section, corr_pat), "corr_pat", XOFFSET(struct problem_config_section, corr_pat) },
  [META_PROBLEM_CONFIG_SECTION_info_pat] = { META_PROBLEM_CONFIG_SECTION_info_pat, 's', XSIZE(struct problem_config_section, info_pat), "info_pat", XOFFSET(struct problem_config_section, info_pat) },
  [META_PROBLEM_CONFIG_SECTION_tgz_pat] = { META_PROBLEM_CONFIG_SECTION_tgz_pat, 's', XSIZE(struct problem_config_section, tgz_pat), "tgz_pat", XOFFSET(struct problem_config_section, tgz_pat) },
  [META_PROBLEM_CONFIG_SECTION_tgzdir_pat] = { META_PROBLEM_CONFIG_SECTION_tgzdir_pat, 's', XSIZE(struct problem_config_section, tgzdir_pat), "tgzdir_pat", XOFFSET(struct problem_config_section, tgzdir_pat) },
  [META_PROBLEM_CONFIG_SECTION_check_cmd] = { META_PROBLEM_CONFIG_SECTION_check_cmd, 's', XSIZE(struct problem_config_section, check_cmd), "check_cmd", XOFFSET(struct problem_config_section, check_cmd) },
  [META_PROBLEM_CONFIG_SECTION_valuer_cmd] = { META_PROBLEM_CONFIG_SECTION_valuer_cmd, 's', XSIZE(struct problem_config_section, valuer_cmd), "valuer_cmd", XOFFSET(struct problem_config_section, valuer_cmd) },
  [META_PROBLEM_CONFIG_SECTION_interactor_cmd] = { META_PROBLEM_CONFIG_SECTION_interactor_cmd, 's', XSIZE(struct problem_config_section, interactor_cmd), "interactor_cmd", XOFFSET(struct problem_config_section, interactor_cmd) },
  [META_PROBLEM_CONFIG_SECTION_style_checker_cmd] = { META_PROBLEM_CONFIG_SECTION_style_checker_cmd, 's', XSIZE(struct problem_config_section, style_checker_cmd), "style_checker_cmd", XOFFSET(struct problem_config_section, style_checker_cmd) },
  [META_PROBLEM_CONFIG_SECTION_test_checker_cmd] = { META_PROBLEM_CONFIG_SECTION_test_checker_cmd, 's', XSIZE(struct problem_config_section, test_checker_cmd), "test_checker_cmd", XOFFSET(struct problem_config_section, test_checker_cmd) },
  [META_PROBLEM_CONFIG_SECTION_test_generator_cmd] = { META_PROBLEM_CONFIG_SECTION_test_generator_cmd, 's', XSIZE(struct problem_config_section, test_generator_cmd), "test_generator_cmd", XOFFSET(struct problem_config_section, test_generator_cmd) },
  [META_PROBLEM_CONFIG_SECTION_init_cmd] = { META_PROBLEM_CONFIG_SECTION_init_cmd, 's', XSIZE(struct problem_config_section, init_cmd), "init_cmd", XOFFSET(struct problem_config_section, init_cmd) },
  [META_PROBLEM_CONFIG_SECTION_start_cmd] = { META_PROBLEM_CONFIG_SECTION_start_cmd, 's', XSIZE(struct problem_config_section, start_cmd), "start_cmd", XOFFSET(struct problem_config_section, start_cmd) },
  [META_PROBLEM_CONFIG_SECTION_solution_src] = { META_PROBLEM_CONFIG_SECTION_solution_src, 's', XSIZE(struct problem_config_section, solution_src), "solution_src", XOFFSET(struct problem_config_section, solution_src) },
  [META_PROBLEM_CONFIG_SECTION_solution_cmd] = { META_PROBLEM_CONFIG_SECTION_solution_cmd, 's', XSIZE(struct problem_config_section, solution_cmd), "solution_cmd", XOFFSET(struct problem_config_section, solution_cmd) },
  [META_PROBLEM_CONFIG_SECTION_post_pull_cmd] = { META_PROBLEM_CONFIG_SECTION_post_pull_cmd, 's', XSIZE(struct problem_config_section, post_pull_cmd), "post_pull_cmd", XOFFSET(struct problem_config_section, post_pull_cmd) },
  [META_PROBLEM_CONFIG_SECTION_vcs_compile_cmd] = { META_PROBLEM_CONFIG_SECTION_vcs_compile_cmd, 's', XSIZE(struct problem_config_section, vcs_compile_cmd), "vcs_compile_cmd", XOFFSET(struct problem_config_section, vcs_compile_cmd) },
  [META_PROBLEM_CONFIG_SECTION_open_tests] = { META_PROBLEM_CONFIG_SECTION_open_tests, 's', XSIZE(struct problem_config_section, open_tests), "open_tests", XOFFSET(struct problem_config_section, open_tests) },
  [META_PROBLEM_CONFIG_SECTION_final_open_tests] = { META_PROBLEM_CONFIG_SECTION_final_open_tests, 's', XSIZE(struct problem_config_section, final_open_tests), "final_open_tests", XOFFSET(struct problem_config_section, final_open_tests) },
  [META_PROBLEM_CONFIG_SECTION_token_open_tests] = { META_PROBLEM_CONFIG_SECTION_token_open_tests, 's', XSIZE(struct problem_config_section, token_open_tests), "token_open_tests", XOFFSET(struct problem_config_section, token_open_tests) },
  [META_PROBLEM_CONFIG_SECTION_extid] = { META_PROBLEM_CONFIG_SECTION_extid, 's', XSIZE(struct problem_config_section, extid), "extid", XOFFSET(struct problem_config_section, extid) },
  [META_PROBLEM_CONFIG_SECTION_normalization] = { META_PROBLEM_CONFIG_SECTION_normalization, 's', XSIZE(struct problem_config_section, normalization), "normalization", XOFFSET(struct problem_config_section, normalization) },
  [META_PROBLEM_CONFIG_SECTION_src_normalization] = { META_PROBLEM_CONFIG_SECTION_src_normalization, 's', XSIZE(struct problem_config_section, src_normalization), "src_normalization", XOFFSET(struct problem_config_section, src_normalization) },
  [META_PROBLEM_CONFIG_SECTION_score_bonus] = { META_PROBLEM_CONFIG_SECTION_score_bonus, 's', XSIZE(struct problem_config_section, score_bonus), "score_bonus", XOFFSET(struct problem_config_section, score_bonus) },
  [META_PROBLEM_CONFIG_SECTION_super_run_dir] = { META_PROBLEM_CONFIG_SECTION_super_run_dir, 's', XSIZE(struct problem_config_section, super_run_dir), "super_run_dir", XOFFSET(struct problem_config_section, super_run_dir) },
  [META_PROBLEM_CONFIG_SECTION_revision] = { META_PROBLEM_CONFIG_SECTION_revision, 's', XSIZE(struct problem_config_section, revision), "revision", XOFFSET(struct problem_config_section, revision) },
  [META_PROBLEM_CONFIG_SECTION_iframe_statement] = { META_PROBLEM_CONFIG_SECTION_iframe_statement, 's', XSIZE(struct problem_config_section, iframe_statement), "iframe_statement", XOFFSET(struct problem_config_section, iframe_statement) },
  [META_PROBLEM_CONFIG_SECTION_test_sets] = { META_PROBLEM_CONFIG_SECTION_test_sets, 'x', XSIZE(struct problem_config_section, test_sets), "test_sets", XOFFSET(struct problem_config_section, test_sets) },
  [META_PROBLEM_CONFIG_SECTION_date_penalty] = { META_PROBLEM_CONFIG_SECTION_date_penalty, 'x', XSIZE(struct problem_config_section, date_penalty), "date_penalty", XOFFSET(struct problem_config_section, date_penalty) },
  [META_PROBLEM_CONFIG_SECTION_group_start_date] = { META_PROBLEM_CONFIG_SECTION_group_start_date, 'x', XSIZE(struct problem_config_section, group_start_date), "group_start_date", XOFFSET(struct problem_config_section, group_start_date) },
  [META_PROBLEM_CONFIG_SECTION_group_deadline] = { META_PROBLEM_CONFIG_SECTION_group_deadline, 'x', XSIZE(struct problem_config_section, group_deadline), "group_deadline", XOFFSET(struct problem_config_section, group_deadline) },
  [META_PROBLEM_CONFIG_SECTION_disable_language] = { META_PROBLEM_CONFIG_SECTION_disable_language, 'x', XSIZE(struct problem_config_section, disable_language), "disable_language", XOFFSET(struct problem_config_section, disable_language) },
  [META_PROBLEM_CONFIG_SECTION_enable_language] = { META_PROBLEM_CONFIG_SECTION_enable_language, 'x', XSIZE(struct problem_config_section, enable_language), "enable_language", XOFFSET(struct problem_config_section, enable_language) },
  [META_PROBLEM_CONFIG_SECTION_require] = { META_PROBLEM_CONFIG_SECTION_require, 'x', XSIZE(struct problem_config_section, require), "require", XOFFSET(struct problem_config_section, require) },
  [META_PROBLEM_CONFIG_SECTION_provide_ok] = { META_PROBLEM_CONFIG_SECTION_provide_ok, 'x', XSIZE(struct problem_config_section, provide_ok), "provide_ok", XOFFSET(struct problem_config_section, provide_ok) },
  [META_PROBLEM_CONFIG_SECTION_allow_ip] = { META_PROBLEM_CONFIG_SECTION_allow_ip, 'x', XSIZE(struct problem_config_section, allow_ip), "allow_ip", XOFFSET(struct problem_config_section, allow_ip) },
  [META_PROBLEM_CONFIG_SECTION_lang_time_adj] = { META_PROBLEM_CONFIG_SECTION_lang_time_adj, 'x', XSIZE(struct problem_config_section, lang_time_adj), "lang_time_adj", XOFFSET(struct problem_config_section, lang_time_adj) },
  [META_PROBLEM_CONFIG_SECTION_lang_time_adj_millis] = { META_PROBLEM_CONFIG_SECTION_lang_time_adj_millis, 'x', XSIZE(struct problem_config_section, lang_time_adj_millis), "lang_time_adj_millis", XOFFSET(struct problem_config_section, lang_time_adj_millis) },
  [META_PROBLEM_CONFIG_SECTION_lang_max_vm_size] = { META_PROBLEM_CONFIG_SECTION_lang_max_vm_size, 'x', XSIZE(struct problem_config_section, lang_max_vm_size), "lang_max_vm_size", XOFFSET(struct problem_config_section, lang_max_vm_size) },
  [META_PROBLEM_CONFIG_SECTION_lang_max_stack_size] = { META_PROBLEM_CONFIG_SECTION_lang_max_stack_size, 'x', XSIZE(struct problem_config_section, lang_max_stack_size), "lang_max_stack_size", XOFFSET(struct problem_config_section, lang_max_stack_size) },
  [META_PROBLEM_CONFIG_SECTION_lang_max_rss_size] = { META_PROBLEM_CONFIG_SECTION_lang_max_rss_size, 'x', XSIZE(struct problem_config_section, lang_max_rss_size), "lang_max_rss_size", XOFFSET(struct problem_config_section, lang_max_rss_size) },
  [META_PROBLEM_CONFIG_SECTION_checker_extra_files] = { META_PROBLEM_CONFIG_SECTION_checker_extra_files, 'x', XSIZE(struct problem_config_section, checker_extra_files), "checker_extra_files", XOFFSET(struct problem_config_section, checker_extra_files) },
  [META_PROBLEM_CONFIG_SECTION_personal_deadline] = { META_PROBLEM_CONFIG_SECTION_personal_deadline, 'x', XSIZE(struct problem_config_section, personal_deadline), "personal_deadline", XOFFSET(struct problem_config_section, personal_deadline) },
  [META_PROBLEM_CONFIG_SECTION_lang_compiler_env] = { META_PROBLEM_CONFIG_SECTION_lang_compiler_env, 'X', XSIZE(struct problem_config_section, lang_compiler_env), "lang_compiler_env", XOFFSET(struct problem_config_section, lang_compiler_env) },
  [META_PROBLEM_CONFIG_SECTION_lang_compiler_container_options] = { META_PROBLEM_CONFIG_SECTION_lang_compiler_container_options, 'X', XSIZE(struct problem_config_section, lang_compiler_container_options), "lang_compiler_container_options", XOFFSET(struct problem_config_section, lang_compiler_container_options) },
  [META_PROBLEM_CONFIG_SECTION_checker_env] = { META_PROBLEM_CONFIG_SECTION_checker_env, 'X', XSIZE(struct problem_config_section, checker_env), "checker_env", XOFFSET(struct problem_config_section, checker_env) },
  [META_PROBLEM_CONFIG_SECTION_valuer_env] = { META_PROBLEM_CONFIG_SECTION_valuer_env, 'X', XSIZE(struct problem_config_section, valuer_env), "valuer_env", XOFFSET(struct problem_config_section, valuer_env) },
  [META_PROBLEM_CONFIG_SECTION_interactor_env] = { META_PROBLEM_CONFIG_SECTION_interactor_env, 'X', XSIZE(struct problem_config_section, interactor_env), "interactor_env", XOFFSET(struct problem_config_section, interactor_env) },
  [META_PROBLEM_CONFIG_SECTION_style_checker_env] = { META_PROBLEM_CONFIG_SECTION_style_checker_env, 'X', XSIZE(struct problem_config_section, style_checker_env), "style_checker_env", XOFFSET(struct problem_config_section, style_checker_env) },
  [META_PROBLEM_CONFIG_SECTION_test_checker_env] = { META_PROBLEM_CONFIG_SECTION_test_checker_env, 'X', XSIZE(struct problem_config_section, test_checker_env), "test_checker_env", XOFFSET(struct problem_config_section, test_checker_env) },
  [META_PROBLEM_CONFIG_SECTION_test_generator_env] = { META_PROBLEM_CONFIG_SECTION_test_generator_env, 'X', XSIZE(struct problem_config_section, test_generator_env), "test_generator_env", XOFFSET(struct problem_config_section, test_generator_env) },
  [META_PROBLEM_CONFIG_SECTION_init_env] = { META_PROBLEM_CONFIG_SECTION_init_env, 'X', XSIZE(struct problem_config_section, init_env), "init_env", XOFFSET(struct problem_config_section, init_env) },
  [META_PROBLEM_CONFIG_SECTION_start_env] = { META_PROBLEM_CONFIG_SECTION_start_env, 'X', XSIZE(struct problem_config_section, start_env), "start_env", XOFFSET(struct problem_config_section, start_env) },
  [META_PROBLEM_CONFIG_SECTION_statement_env] = { META_PROBLEM_CONFIG_SECTION_statement_env, 'X', XSIZE(struct problem_config_section, statement_env), "statement_env", XOFFSET(struct problem_config_section, statement_env) },
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

void meta_problem_config_section_copy(struct problem_config_section *dst, const struct problem_config_section *src)
{
  // hidden g
  dst->manual_checking = src->manual_checking;
  dst->check_presentation = src->check_presentation;
  dst->scoring_checker = src->scoring_checker;
  dst->enable_checker_token = src->enable_checker_token;
  dst->interactive_valuer = src->interactive_valuer;
  dst->disable_pe = src->disable_pe;
  dst->disable_wtl = src->disable_wtl;
  dst->wtl_is_cf = src->wtl_is_cf;
  dst->use_stdin = src->use_stdin;
  dst->use_stdout = src->use_stdout;
  dst->combined_stdin = src->combined_stdin;
  dst->combined_stdout = src->combined_stdout;
  dst->binary_input = src->binary_input;
  dst->binary = src->binary;
  dst->ignore_exit_code = src->ignore_exit_code;
  dst->ignore_term_signal = src->ignore_term_signal;
  dst->olympiad_mode = src->olympiad_mode;
  dst->score_latest = src->score_latest;
  dst->score_latest_or_unmarked = src->score_latest_or_unmarked;
  dst->score_latest_marked = src->score_latest_marked;
  dst->score_tokenized = src->score_tokenized;
  dst->use_ac_not_ok = src->use_ac_not_ok;
  dst->ignore_prev_ac = src->ignore_prev_ac;
  dst->team_enable_rep_view = src->team_enable_rep_view;
  dst->team_enable_ce_view = src->team_enable_ce_view;
  dst->team_show_judge_report = src->team_show_judge_report;
  dst->show_checker_comment = src->show_checker_comment;
  dst->ignore_compile_errors = src->ignore_compile_errors;
  dst->variable_full_score = src->variable_full_score;
  dst->ignore_penalty = src->ignore_penalty;
  dst->use_corr = src->use_corr;
  dst->use_info = src->use_info;
  dst->use_tgz = src->use_tgz;
  dst->accept_partial = src->accept_partial;
  dst->disable_user_submit = src->disable_user_submit;
  dst->disable_tab = src->disable_tab;
  dst->unrestricted_statement = src->unrestricted_statement;
  dst->statement_ignore_ip = src->statement_ignore_ip;
  dst->restricted_statement = src->restricted_statement;
  dst->enable_submit_after_reject = src->enable_submit_after_reject;
  dst->hide_file_names = src->hide_file_names;
  dst->hide_real_time_limit = src->hide_real_time_limit;
  dst->enable_tokens = src->enable_tokens;
  dst->tokens_for_user_ac = src->tokens_for_user_ac;
  dst->disable_submit_after_ok = src->disable_submit_after_ok;
  dst->disable_auto_testing = src->disable_auto_testing;
  dst->disable_testing = src->disable_testing;
  dst->enable_compilation = src->enable_compilation;
  dst->skip_testing = src->skip_testing;
  dst->hidden = src->hidden;
  dst->stand_hide_time = src->stand_hide_time;
  dst->advance_to_next = src->advance_to_next;
  dst->disable_ctrl_chars = src->disable_ctrl_chars;
  dst->enable_text_form = src->enable_text_form;
  dst->stand_ignore_score = src->stand_ignore_score;
  dst->stand_last_column = src->stand_last_column;
  dst->disable_security = src->disable_security;
  dst->enable_suid_run = src->enable_suid_run;
  dst->enable_container = src->enable_container;
  dst->enable_dynamic_priority = src->enable_dynamic_priority;
  dst->valuer_sets_marked = src->valuer_sets_marked;
  dst->ignore_unmarked = src->ignore_unmarked;
  dst->disable_stderr = src->disable_stderr;
  dst->enable_process_group = src->enable_process_group;
  dst->enable_kill_all = src->enable_kill_all;
  dst->hide_variant = src->hide_variant;
  dst->enable_testlib_mode = src->enable_testlib_mode;
  dst->autoassign_variants = src->autoassign_variants;
  dst->require_any = src->require_any;
  dst->enable_extended_info = src->enable_extended_info;
  dst->stop_on_first_fail = src->stop_on_first_fail;
  dst->enable_control_socket = src->enable_control_socket;
  dst->copy_exe_to_tgzdir = src->copy_exe_to_tgzdir;
  dst->enable_multi_header = src->enable_multi_header;
  dst->use_lang_multi_header = src->use_lang_multi_header;
  dst->notify_on_submit = src->notify_on_submit;
  dst->enable_user_input = src->enable_user_input;
  dst->enable_vcs = src->enable_vcs;
  dst->enable_iframe_statement = src->enable_iframe_statement;
  dst->enable_src_for_testing = src->enable_src_for_testing;
  dst->disable_vm_size_limit = src->disable_vm_size_limit;
  dst->enable_group_merge = src->enable_group_merge;
  dst->id = src->id;
  dst->variant_num = src->variant_num;
  dst->full_score = src->full_score;
  dst->full_user_score = src->full_user_score;
  dst->min_score_1 = src->min_score_1;
  dst->min_score_2 = src->min_score_2;
  dst->real_time_limit = src->real_time_limit;
  dst->time_limit = src->time_limit;
  dst->time_limit_millis = src->time_limit_millis;
  dst->test_score = src->test_score;
  dst->run_penalty = src->run_penalty;
  dst->acm_run_penalty = src->acm_run_penalty;
  dst->disqualified_penalty = src->disqualified_penalty;
  dst->compile_error_penalty = src->compile_error_penalty;
  dst->tests_to_accept = src->tests_to_accept;
  dst->min_tests_to_accept = src->min_tests_to_accept;
  dst->checker_real_time_limit = src->checker_real_time_limit;
  dst->checker_time_limit_ms = src->checker_time_limit_ms;
  dst->priority_adjustment = src->priority_adjustment;
  dst->score_multiplier = src->score_multiplier;
  dst->prev_runs_to_show = src->prev_runs_to_show;
  dst->max_user_run_count = src->max_user_run_count;
  dst->interactor_time_limit = src->interactor_time_limit;
  dst->interactor_real_time_limit = src->interactor_real_time_limit;
  dst->max_open_file_count = src->max_open_file_count;
  dst->max_process_count = src->max_process_count;
  dst->deadline = src->deadline;
  dst->start_date = src->start_date;
  dst->max_vm_size = src->max_vm_size;
  dst->max_data_size = src->max_data_size;
  dst->max_stack_size = src->max_stack_size;
  dst->max_rss_size = src->max_rss_size;
  dst->max_core_size = src->max_core_size;
  dst->max_file_size = src->max_file_size;
  dst->checker_max_vm_size = src->checker_max_vm_size;
  dst->checker_max_stack_size = src->checker_max_stack_size;
  dst->checker_max_rss_size = src->checker_max_rss_size;
  if (src->type) {
    dst->type = strdup(src->type);
  }
  if (src->short_name) {
    dst->short_name = strdup(src->short_name);
  }
  if (src->long_name) {
    dst->long_name = strdup(src->long_name);
  }
  if (src->long_name_en) {
    dst->long_name_en = strdup(src->long_name_en);
  }
  if (src->stand_name) {
    dst->stand_name = strdup(src->stand_name);
  }
  if (src->stand_column) {
    dst->stand_column = strdup(src->stand_column);
  }
  if (src->group_name) {
    dst->group_name = strdup(src->group_name);
  }
  if (src->internal_name) {
    dst->internal_name = strdup(src->internal_name);
  }
  if (src->plugin_entry_name) {
    dst->plugin_entry_name = strdup(src->plugin_entry_name);
  }
  if (src->uuid) {
    dst->uuid = strdup(src->uuid);
  }
  if (src->test_dir) {
    dst->test_dir = strdup(src->test_dir);
  }
  if (src->test_sfx) {
    dst->test_sfx = strdup(src->test_sfx);
  }
  if (src->corr_dir) {
    dst->corr_dir = strdup(src->corr_dir);
  }
  if (src->corr_sfx) {
    dst->corr_sfx = strdup(src->corr_sfx);
  }
  if (src->info_dir) {
    dst->info_dir = strdup(src->info_dir);
  }
  if (src->info_sfx) {
    dst->info_sfx = strdup(src->info_sfx);
  }
  if (src->tgz_dir) {
    dst->tgz_dir = strdup(src->tgz_dir);
  }
  if (src->tgz_sfx) {
    dst->tgz_sfx = strdup(src->tgz_sfx);
  }
  if (src->tgzdir_sfx) {
    dst->tgzdir_sfx = strdup(src->tgzdir_sfx);
  }
  if (src->input_file) {
    dst->input_file = strdup(src->input_file);
  }
  if (src->output_file) {
    dst->output_file = strdup(src->output_file);
  }
  if (src->test_score_list) {
    dst->test_score_list = strdup(src->test_score_list);
  }
  if (src->tokens) {
    dst->tokens = strdup(src->tokens);
  }
  if (src->umask) {
    dst->umask = strdup(src->umask);
  }
  if (src->ok_status) {
    dst->ok_status = strdup(src->ok_status);
  }
  if (src->header_pat) {
    dst->header_pat = strdup(src->header_pat);
  }
  if (src->footer_pat) {
    dst->footer_pat = strdup(src->footer_pat);
  }
  if (src->compiler_env_pat) {
    dst->compiler_env_pat = strdup(src->compiler_env_pat);
  }
  if (src->container_options) {
    dst->container_options = strdup(src->container_options);
  }
  if (src->score_tests) {
    dst->score_tests = strdup(src->score_tests);
  }
  if (src->standard_checker) {
    dst->standard_checker = strdup(src->standard_checker);
  }
  if (src->spelling) {
    dst->spelling = strdup(src->spelling);
  }
  if (src->statement_file) {
    dst->statement_file = strdup(src->statement_file);
  }
  if (src->plugin_file) {
    dst->plugin_file = strdup(src->plugin_file);
  }
  if (src->xml_file) {
    dst->xml_file = strdup(src->xml_file);
  }
  if (src->stand_attr) {
    dst->stand_attr = strdup(src->stand_attr);
  }
  if (src->source_header) {
    dst->source_header = strdup(src->source_header);
  }
  if (src->source_footer) {
    dst->source_footer = strdup(src->source_footer);
  }
  if (src->custom_compile_cmd) {
    dst->custom_compile_cmd = strdup(src->custom_compile_cmd);
  }
  if (src->custom_lang_name) {
    dst->custom_lang_name = strdup(src->custom_lang_name);
  }
  if (src->extra_src_dir) {
    dst->extra_src_dir = strdup(src->extra_src_dir);
  }
  if (src->standard_valuer) {
    dst->standard_valuer = strdup(src->standard_valuer);
  }
  if (src->md_file) {
    dst->md_file = strdup(src->md_file);
  }
  if (src->test_pat) {
    dst->test_pat = strdup(src->test_pat);
  }
  if (src->corr_pat) {
    dst->corr_pat = strdup(src->corr_pat);
  }
  if (src->info_pat) {
    dst->info_pat = strdup(src->info_pat);
  }
  if (src->tgz_pat) {
    dst->tgz_pat = strdup(src->tgz_pat);
  }
  if (src->tgzdir_pat) {
    dst->tgzdir_pat = strdup(src->tgzdir_pat);
  }
  if (src->check_cmd) {
    dst->check_cmd = strdup(src->check_cmd);
  }
  if (src->valuer_cmd) {
    dst->valuer_cmd = strdup(src->valuer_cmd);
  }
  if (src->interactor_cmd) {
    dst->interactor_cmd = strdup(src->interactor_cmd);
  }
  if (src->style_checker_cmd) {
    dst->style_checker_cmd = strdup(src->style_checker_cmd);
  }
  if (src->test_checker_cmd) {
    dst->test_checker_cmd = strdup(src->test_checker_cmd);
  }
  if (src->test_generator_cmd) {
    dst->test_generator_cmd = strdup(src->test_generator_cmd);
  }
  if (src->init_cmd) {
    dst->init_cmd = strdup(src->init_cmd);
  }
  if (src->start_cmd) {
    dst->start_cmd = strdup(src->start_cmd);
  }
  if (src->solution_src) {
    dst->solution_src = strdup(src->solution_src);
  }
  if (src->solution_cmd) {
    dst->solution_cmd = strdup(src->solution_cmd);
  }
  if (src->post_pull_cmd) {
    dst->post_pull_cmd = strdup(src->post_pull_cmd);
  }
  if (src->vcs_compile_cmd) {
    dst->vcs_compile_cmd = strdup(src->vcs_compile_cmd);
  }
  if (src->open_tests) {
    dst->open_tests = strdup(src->open_tests);
  }
  if (src->final_open_tests) {
    dst->final_open_tests = strdup(src->final_open_tests);
  }
  if (src->token_open_tests) {
    dst->token_open_tests = strdup(src->token_open_tests);
  }
  if (src->extid) {
    dst->extid = strdup(src->extid);
  }
  if (src->normalization) {
    dst->normalization = strdup(src->normalization);
  }
  if (src->src_normalization) {
    dst->src_normalization = strdup(src->src_normalization);
  }
  if (src->score_bonus) {
    dst->score_bonus = strdup(src->score_bonus);
  }
  if (src->super_run_dir) {
    dst->super_run_dir = strdup(src->super_run_dir);
  }
  if (src->revision) {
    dst->revision = strdup(src->revision);
  }
  if (src->iframe_statement) {
    dst->iframe_statement = strdup(src->iframe_statement);
  }
  dst->test_sets = (typeof(dst->test_sets)) sarray_copy((char**) src->test_sets);
  dst->date_penalty = (typeof(dst->date_penalty)) sarray_copy((char**) src->date_penalty);
  dst->group_start_date = (typeof(dst->group_start_date)) sarray_copy((char**) src->group_start_date);
  dst->group_deadline = (typeof(dst->group_deadline)) sarray_copy((char**) src->group_deadline);
  dst->disable_language = (typeof(dst->disable_language)) sarray_copy((char**) src->disable_language);
  dst->enable_language = (typeof(dst->enable_language)) sarray_copy((char**) src->enable_language);
  dst->require = (typeof(dst->require)) sarray_copy((char**) src->require);
  dst->provide_ok = (typeof(dst->provide_ok)) sarray_copy((char**) src->provide_ok);
  dst->allow_ip = (typeof(dst->allow_ip)) sarray_copy((char**) src->allow_ip);
  dst->lang_time_adj = (typeof(dst->lang_time_adj)) sarray_copy((char**) src->lang_time_adj);
  dst->lang_time_adj_millis = (typeof(dst->lang_time_adj_millis)) sarray_copy((char**) src->lang_time_adj_millis);
  dst->lang_max_vm_size = (typeof(dst->lang_max_vm_size)) sarray_copy((char**) src->lang_max_vm_size);
  dst->lang_max_stack_size = (typeof(dst->lang_max_stack_size)) sarray_copy((char**) src->lang_max_stack_size);
  dst->lang_max_rss_size = (typeof(dst->lang_max_rss_size)) sarray_copy((char**) src->lang_max_rss_size);
  dst->checker_extra_files = (typeof(dst->checker_extra_files)) sarray_copy((char**) src->checker_extra_files);
  dst->personal_deadline = (typeof(dst->personal_deadline)) sarray_copy((char**) src->personal_deadline);
  dst->lang_compiler_env = (typeof(dst->lang_compiler_env)) sarray_copy((char**) src->lang_compiler_env);
  dst->lang_compiler_container_options = (typeof(dst->lang_compiler_container_options)) sarray_copy((char**) src->lang_compiler_container_options);
  dst->checker_env = (typeof(dst->checker_env)) sarray_copy((char**) src->checker_env);
  dst->valuer_env = (typeof(dst->valuer_env)) sarray_copy((char**) src->valuer_env);
  dst->interactor_env = (typeof(dst->interactor_env)) sarray_copy((char**) src->interactor_env);
  dst->style_checker_env = (typeof(dst->style_checker_env)) sarray_copy((char**) src->style_checker_env);
  dst->test_checker_env = (typeof(dst->test_checker_env)) sarray_copy((char**) src->test_checker_env);
  dst->test_generator_env = (typeof(dst->test_generator_env)) sarray_copy((char**) src->test_generator_env);
  dst->init_env = (typeof(dst->init_env)) sarray_copy((char**) src->init_env);
  dst->start_env = (typeof(dst->start_env)) sarray_copy((char**) src->start_env);
  dst->statement_env = (typeof(dst->statement_env)) sarray_copy((char**) src->statement_env);
}

void meta_problem_config_section_free(struct problem_config_section *ptr)
{
  // hidden g
  free(ptr->type);
  free(ptr->short_name);
  free(ptr->long_name);
  free(ptr->long_name_en);
  free(ptr->stand_name);
  free(ptr->stand_column);
  free(ptr->group_name);
  free(ptr->internal_name);
  free(ptr->plugin_entry_name);
  free(ptr->uuid);
  free(ptr->test_dir);
  free(ptr->test_sfx);
  free(ptr->corr_dir);
  free(ptr->corr_sfx);
  free(ptr->info_dir);
  free(ptr->info_sfx);
  free(ptr->tgz_dir);
  free(ptr->tgz_sfx);
  free(ptr->tgzdir_sfx);
  free(ptr->input_file);
  free(ptr->output_file);
  free(ptr->test_score_list);
  free(ptr->tokens);
  free(ptr->umask);
  free(ptr->ok_status);
  free(ptr->header_pat);
  free(ptr->footer_pat);
  free(ptr->compiler_env_pat);
  free(ptr->container_options);
  free(ptr->score_tests);
  free(ptr->standard_checker);
  free(ptr->spelling);
  free(ptr->statement_file);
  free(ptr->plugin_file);
  free(ptr->xml_file);
  free(ptr->stand_attr);
  free(ptr->source_header);
  free(ptr->source_footer);
  free(ptr->custom_compile_cmd);
  free(ptr->custom_lang_name);
  free(ptr->extra_src_dir);
  free(ptr->standard_valuer);
  free(ptr->md_file);
  free(ptr->test_pat);
  free(ptr->corr_pat);
  free(ptr->info_pat);
  free(ptr->tgz_pat);
  free(ptr->tgzdir_pat);
  free(ptr->check_cmd);
  free(ptr->valuer_cmd);
  free(ptr->interactor_cmd);
  free(ptr->style_checker_cmd);
  free(ptr->test_checker_cmd);
  free(ptr->test_generator_cmd);
  free(ptr->init_cmd);
  free(ptr->start_cmd);
  free(ptr->solution_src);
  free(ptr->solution_cmd);
  free(ptr->post_pull_cmd);
  free(ptr->vcs_compile_cmd);
  free(ptr->open_tests);
  free(ptr->final_open_tests);
  free(ptr->token_open_tests);
  free(ptr->extid);
  free(ptr->normalization);
  free(ptr->src_normalization);
  free(ptr->score_bonus);
  free(ptr->super_run_dir);
  free(ptr->revision);
  free(ptr->iframe_statement);
  sarray_free((char**) ptr->test_sets);
  sarray_free((char**) ptr->date_penalty);
  sarray_free((char**) ptr->group_start_date);
  sarray_free((char**) ptr->group_deadline);
  sarray_free((char**) ptr->disable_language);
  sarray_free((char**) ptr->enable_language);
  sarray_free((char**) ptr->require);
  sarray_free((char**) ptr->provide_ok);
  sarray_free((char**) ptr->allow_ip);
  sarray_free((char**) ptr->lang_time_adj);
  sarray_free((char**) ptr->lang_time_adj_millis);
  sarray_free((char**) ptr->lang_max_vm_size);
  sarray_free((char**) ptr->lang_max_stack_size);
  sarray_free((char**) ptr->lang_max_rss_size);
  sarray_free((char**) ptr->checker_extra_files);
  sarray_free((char**) ptr->personal_deadline);
  sarray_free((char**) ptr->lang_compiler_env);
  sarray_free((char**) ptr->lang_compiler_container_options);
  sarray_free((char**) ptr->checker_env);
  sarray_free((char**) ptr->valuer_env);
  sarray_free((char**) ptr->interactor_env);
  sarray_free((char**) ptr->style_checker_env);
  sarray_free((char**) ptr->test_checker_env);
  sarray_free((char**) ptr->test_generator_env);
  sarray_free((char**) ptr->init_env);
  sarray_free((char**) ptr->start_env);
  sarray_free((char**) ptr->statement_env);
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
  (void (*)(void *, const void *))meta_problem_config_section_copy,
  (void (*)(void *))meta_problem_config_section_free,
  meta_info_problem_config_section_data,
};

