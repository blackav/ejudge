// This is an auto-generated file, do not edit
// Generated 2013/11/09 23:52:19

#include "prepare_meta.h"
#include "prepare.h"
#include "meta_generic.h"

#include "reuse_xalloc.h"

#include "reuse_logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_section_global_data_data[] =
{
  [CNTSGLOB_sleep_time] = { CNTSGLOB_sleep_time, 'i', XSIZE(struct section_global_data, sleep_time), "sleep_time", XOFFSET(struct section_global_data, sleep_time) },
  [CNTSGLOB_serve_sleep_time] = { CNTSGLOB_serve_sleep_time, 'i', XSIZE(struct section_global_data, serve_sleep_time), "serve_sleep_time", XOFFSET(struct section_global_data, serve_sleep_time) },
  [CNTSGLOB_contest_time] = { CNTSGLOB_contest_time, 'i', XSIZE(struct section_global_data, contest_time), "contest_time", XOFFSET(struct section_global_data, contest_time) },
  [CNTSGLOB_max_run_size] = { CNTSGLOB_max_run_size, 'z', XSIZE(struct section_global_data, max_run_size), "max_run_size", XOFFSET(struct section_global_data, max_run_size) },
  [CNTSGLOB_max_run_total] = { CNTSGLOB_max_run_total, 'z', XSIZE(struct section_global_data, max_run_total), "max_run_total", XOFFSET(struct section_global_data, max_run_total) },
  [CNTSGLOB_max_run_num] = { CNTSGLOB_max_run_num, 'i', XSIZE(struct section_global_data, max_run_num), "max_run_num", XOFFSET(struct section_global_data, max_run_num) },
  [CNTSGLOB_max_clar_size] = { CNTSGLOB_max_clar_size, 'z', XSIZE(struct section_global_data, max_clar_size), "max_clar_size", XOFFSET(struct section_global_data, max_clar_size) },
  [CNTSGLOB_max_clar_total] = { CNTSGLOB_max_clar_total, 'z', XSIZE(struct section_global_data, max_clar_total), "max_clar_total", XOFFSET(struct section_global_data, max_clar_total) },
  [CNTSGLOB_max_clar_num] = { CNTSGLOB_max_clar_num, 'i', XSIZE(struct section_global_data, max_clar_num), "max_clar_num", XOFFSET(struct section_global_data, max_clar_num) },
  [CNTSGLOB_board_fog_time] = { CNTSGLOB_board_fog_time, 'i', XSIZE(struct section_global_data, board_fog_time), "board_fog_time", XOFFSET(struct section_global_data, board_fog_time) },
  [CNTSGLOB_board_unfog_time] = { CNTSGLOB_board_unfog_time, 'i', XSIZE(struct section_global_data, board_unfog_time), "board_unfog_time", XOFFSET(struct section_global_data, board_unfog_time) },
  [CNTSGLOB_autoupdate_standings] = { CNTSGLOB_autoupdate_standings, 'B', XSIZE(struct section_global_data, autoupdate_standings), "autoupdate_standings", XOFFSET(struct section_global_data, autoupdate_standings) },
  [CNTSGLOB_use_ac_not_ok] = { CNTSGLOB_use_ac_not_ok, 'B', XSIZE(struct section_global_data, use_ac_not_ok), "use_ac_not_ok", XOFFSET(struct section_global_data, use_ac_not_ok) },
  [CNTSGLOB_inactivity_timeout] = { CNTSGLOB_inactivity_timeout, 'i', XSIZE(struct section_global_data, inactivity_timeout), "inactivity_timeout", XOFFSET(struct section_global_data, inactivity_timeout) },
  [CNTSGLOB_disable_auto_testing] = { CNTSGLOB_disable_auto_testing, 'B', XSIZE(struct section_global_data, disable_auto_testing), "disable_auto_testing", XOFFSET(struct section_global_data, disable_auto_testing) },
  [CNTSGLOB_disable_testing] = { CNTSGLOB_disable_testing, 'B', XSIZE(struct section_global_data, disable_testing), "disable_testing", XOFFSET(struct section_global_data, disable_testing) },
  [CNTSGLOB_enable_runlog_merge] = { CNTSGLOB_enable_runlog_merge, 'B', XSIZE(struct section_global_data, enable_runlog_merge), "enable_runlog_merge", XOFFSET(struct section_global_data, enable_runlog_merge) },
  [CNTSGLOB_secure_run] = { CNTSGLOB_secure_run, 'B', XSIZE(struct section_global_data, secure_run), "secure_run", XOFFSET(struct section_global_data, secure_run) },
  [CNTSGLOB_detect_violations] = { CNTSGLOB_detect_violations, 'B', XSIZE(struct section_global_data, detect_violations), "detect_violations", XOFFSET(struct section_global_data, detect_violations) },
  [CNTSGLOB_enable_memory_limit_error] = { CNTSGLOB_enable_memory_limit_error, 'B', XSIZE(struct section_global_data, enable_memory_limit_error), "enable_memory_limit_error", XOFFSET(struct section_global_data, enable_memory_limit_error) },
  [CNTSGLOB_advanced_layout] = { CNTSGLOB_advanced_layout, 'B', XSIZE(struct section_global_data, advanced_layout), "advanced_layout", XOFFSET(struct section_global_data, advanced_layout) },
  [CNTSGLOB_uuid_run_store] = { CNTSGLOB_uuid_run_store, 'B', XSIZE(struct section_global_data, uuid_run_store), "uuid_run_store", XOFFSET(struct section_global_data, uuid_run_store) },
  [CNTSGLOB_enable_32bit_checkers] = { CNTSGLOB_enable_32bit_checkers, 'B', XSIZE(struct section_global_data, enable_32bit_checkers), "enable_32bit_checkers", XOFFSET(struct section_global_data, enable_32bit_checkers) },
  [CNTSGLOB_ignore_bom] = { CNTSGLOB_ignore_bom, 'B', XSIZE(struct section_global_data, ignore_bom), "ignore_bom", XOFFSET(struct section_global_data, ignore_bom) },
  [CNTSGLOB_disable_user_database] = { CNTSGLOB_disable_user_database, 'B', XSIZE(struct section_global_data, disable_user_database), "disable_user_database", XOFFSET(struct section_global_data, disable_user_database) },
  [CNTSGLOB_enable_max_stack_size] = { CNTSGLOB_enable_max_stack_size, 'B', XSIZE(struct section_global_data, enable_max_stack_size), "enable_max_stack_size", XOFFSET(struct section_global_data, enable_max_stack_size) },
  [CNTSGLOB_time_limit_retry_count] = { CNTSGLOB_time_limit_retry_count, 'i', XSIZE(struct section_global_data, time_limit_retry_count), "time_limit_retry_count", XOFFSET(struct section_global_data, time_limit_retry_count) },
  [CNTSGLOB_score_n_best_problems] = { CNTSGLOB_score_n_best_problems, 'i', XSIZE(struct section_global_data, score_n_best_problems), "score_n_best_problems", XOFFSET(struct section_global_data, score_n_best_problems) },
  [CNTSGLOB_stand_ignore_after] = { CNTSGLOB_stand_ignore_after, 't', XSIZE(struct section_global_data, stand_ignore_after), "stand_ignore_after", XOFFSET(struct section_global_data, stand_ignore_after) },
  [CNTSGLOB_contest_finish_time] = { CNTSGLOB_contest_finish_time, 't', XSIZE(struct section_global_data, contest_finish_time), "contest_finish_time", XOFFSET(struct section_global_data, contest_finish_time) },
  [CNTSGLOB_appeal_deadline] = { CNTSGLOB_appeal_deadline, 't', XSIZE(struct section_global_data, appeal_deadline), "appeal_deadline", XOFFSET(struct section_global_data, appeal_deadline) },
  [CNTSGLOB_fog_standings_updated] = { CNTSGLOB_fog_standings_updated, 'i', XSIZE(struct section_global_data, fog_standings_updated), NULL, XOFFSET(struct section_global_data, fog_standings_updated) },
  [CNTSGLOB_start_standings_updated] = { CNTSGLOB_start_standings_updated, 'i', XSIZE(struct section_global_data, start_standings_updated), NULL, XOFFSET(struct section_global_data, start_standings_updated) },
  [CNTSGLOB_unfog_standings_updated] = { CNTSGLOB_unfog_standings_updated, 'i', XSIZE(struct section_global_data, unfog_standings_updated), NULL, XOFFSET(struct section_global_data, unfog_standings_updated) },
  [CNTSGLOB_team_enable_src_view] = { CNTSGLOB_team_enable_src_view, 'B', XSIZE(struct section_global_data, team_enable_src_view), "team_enable_src_view", XOFFSET(struct section_global_data, team_enable_src_view) },
  [CNTSGLOB_team_enable_rep_view] = { CNTSGLOB_team_enable_rep_view, 'B', XSIZE(struct section_global_data, team_enable_rep_view), "team_enable_rep_view", XOFFSET(struct section_global_data, team_enable_rep_view) },
  [CNTSGLOB_team_enable_ce_view] = { CNTSGLOB_team_enable_ce_view, 'B', XSIZE(struct section_global_data, team_enable_ce_view), "team_enable_ce_view", XOFFSET(struct section_global_data, team_enable_ce_view) },
  [CNTSGLOB_team_show_judge_report] = { CNTSGLOB_team_show_judge_report, 'B', XSIZE(struct section_global_data, team_show_judge_report), "team_show_judge_report", XOFFSET(struct section_global_data, team_show_judge_report) },
  [CNTSGLOB_disable_clars] = { CNTSGLOB_disable_clars, 'B', XSIZE(struct section_global_data, disable_clars), "disable_clars", XOFFSET(struct section_global_data, disable_clars) },
  [CNTSGLOB_disable_team_clars] = { CNTSGLOB_disable_team_clars, 'B', XSIZE(struct section_global_data, disable_team_clars), "disable_team_clars", XOFFSET(struct section_global_data, disable_team_clars) },
  [CNTSGLOB_disable_submit_after_ok] = { CNTSGLOB_disable_submit_after_ok, 'B', XSIZE(struct section_global_data, disable_submit_after_ok), "disable_submit_after_ok", XOFFSET(struct section_global_data, disable_submit_after_ok) },
  [CNTSGLOB_ignore_compile_errors] = { CNTSGLOB_ignore_compile_errors, 'B', XSIZE(struct section_global_data, ignore_compile_errors), "ignore_compile_errors", XOFFSET(struct section_global_data, ignore_compile_errors) },
  [CNTSGLOB_enable_continue] = { CNTSGLOB_enable_continue, 'B', XSIZE(struct section_global_data, enable_continue), "enable_continue", XOFFSET(struct section_global_data, enable_continue) },
  [CNTSGLOB_enable_report_upload] = { CNTSGLOB_enable_report_upload, 'B', XSIZE(struct section_global_data, enable_report_upload), "enable_report_upload", XOFFSET(struct section_global_data, enable_report_upload) },
  [CNTSGLOB_priority_adjustment] = { CNTSGLOB_priority_adjustment, 'i', XSIZE(struct section_global_data, priority_adjustment), "priority_adjustment", XOFFSET(struct section_global_data, priority_adjustment) },
  [CNTSGLOB_ignore_success_time] = { CNTSGLOB_ignore_success_time, 'B', XSIZE(struct section_global_data, ignore_success_time), "ignore_success_time", XOFFSET(struct section_global_data, ignore_success_time) },
  [CNTSGLOB_disable_failed_test_view] = { CNTSGLOB_disable_failed_test_view, 'B', XSIZE(struct section_global_data, disable_failed_test_view), "disable_failed_test_view", XOFFSET(struct section_global_data, disable_failed_test_view) },
  [CNTSGLOB_always_show_problems] = { CNTSGLOB_always_show_problems, 'B', XSIZE(struct section_global_data, always_show_problems), "always_show_problems", XOFFSET(struct section_global_data, always_show_problems) },
  [CNTSGLOB_disable_user_standings] = { CNTSGLOB_disable_user_standings, 'B', XSIZE(struct section_global_data, disable_user_standings), "disable_user_standings", XOFFSET(struct section_global_data, disable_user_standings) },
  [CNTSGLOB_disable_language] = { CNTSGLOB_disable_language, 'B', XSIZE(struct section_global_data, disable_language), "disable_language", XOFFSET(struct section_global_data, disable_language) },
  [CNTSGLOB_problem_navigation] = { CNTSGLOB_problem_navigation, 'B', XSIZE(struct section_global_data, problem_navigation), "problem_navigation", XOFFSET(struct section_global_data, problem_navigation) },
  [CNTSGLOB_problem_tab_size] = { CNTSGLOB_problem_tab_size, 'i', XSIZE(struct section_global_data, problem_tab_size), "problem_tab_size", XOFFSET(struct section_global_data, problem_tab_size) },
  [CNTSGLOB_vertical_navigation] = { CNTSGLOB_vertical_navigation, 'B', XSIZE(struct section_global_data, vertical_navigation), "vertical_navigation", XOFFSET(struct section_global_data, vertical_navigation) },
  [CNTSGLOB_disable_virtual_start] = { CNTSGLOB_disable_virtual_start, 'B', XSIZE(struct section_global_data, disable_virtual_start), "disable_virtual_start", XOFFSET(struct section_global_data, disable_virtual_start) },
  [CNTSGLOB_disable_virtual_auto_judge] = { CNTSGLOB_disable_virtual_auto_judge, 'B', XSIZE(struct section_global_data, disable_virtual_auto_judge), "disable_virtual_auto_judge", XOFFSET(struct section_global_data, disable_virtual_auto_judge) },
  [CNTSGLOB_enable_auto_print_protocol] = { CNTSGLOB_enable_auto_print_protocol, 'B', XSIZE(struct section_global_data, enable_auto_print_protocol), "enable_auto_print_protocol", XOFFSET(struct section_global_data, enable_auto_print_protocol) },
  [CNTSGLOB_notify_clar_reply] = { CNTSGLOB_notify_clar_reply, 'B', XSIZE(struct section_global_data, notify_clar_reply), "notify_clar_reply", XOFFSET(struct section_global_data, notify_clar_reply) },
  [CNTSGLOB_notify_status_change] = { CNTSGLOB_notify_status_change, 'B', XSIZE(struct section_global_data, notify_status_change), "notify_status_change", XOFFSET(struct section_global_data, notify_status_change) },
  [CNTSGLOB_memoize_user_results] = { CNTSGLOB_memoize_user_results, 'B', XSIZE(struct section_global_data, memoize_user_results), "memoize_user_results", XOFFSET(struct section_global_data, memoize_user_results) },
  [CNTSGLOB_disable_auto_refresh] = { CNTSGLOB_disable_auto_refresh, 'B', XSIZE(struct section_global_data, disable_auto_refresh), "disable_auto_refresh", XOFFSET(struct section_global_data, disable_auto_refresh) },
  [CNTSGLOB_enable_eoln_select] = { CNTSGLOB_enable_eoln_select, 'B', XSIZE(struct section_global_data, enable_eoln_select), "enable_eoln_select", XOFFSET(struct section_global_data, enable_eoln_select) },
  [CNTSGLOB_name] = { CNTSGLOB_name, 'S', XSIZE(struct section_global_data, name), "name", XOFFSET(struct section_global_data, name) },
  [CNTSGLOB_root_dir] = { CNTSGLOB_root_dir, 'S', XSIZE(struct section_global_data, root_dir), "root_dir", XOFFSET(struct section_global_data, root_dir) },
  [CNTSGLOB_serve_socket] = { CNTSGLOB_serve_socket, 'S', XSIZE(struct section_global_data, serve_socket), "serve_socket", XOFFSET(struct section_global_data, serve_socket) },
  [CNTSGLOB_enable_l10n] = { CNTSGLOB_enable_l10n, 'B', XSIZE(struct section_global_data, enable_l10n), "enable_l10n", XOFFSET(struct section_global_data, enable_l10n) },
  [CNTSGLOB_l10n_dir] = { CNTSGLOB_l10n_dir, 'S', XSIZE(struct section_global_data, l10n_dir), "l10n_dir", XOFFSET(struct section_global_data, l10n_dir) },
  [CNTSGLOB_standings_locale] = { CNTSGLOB_standings_locale, 'S', XSIZE(struct section_global_data, standings_locale), "standings_locale", XOFFSET(struct section_global_data, standings_locale) },
  [CNTSGLOB_standings_locale_id] = { CNTSGLOB_standings_locale_id, 'i', XSIZE(struct section_global_data, standings_locale_id), NULL, XOFFSET(struct section_global_data, standings_locale_id) },
  [CNTSGLOB_checker_locale] = { CNTSGLOB_checker_locale, 's', XSIZE(struct section_global_data, checker_locale), "checker_locale", XOFFSET(struct section_global_data, checker_locale) },
  [CNTSGLOB_contest_id] = { CNTSGLOB_contest_id, 'i', XSIZE(struct section_global_data, contest_id), "contest_id", XOFFSET(struct section_global_data, contest_id) },
  [CNTSGLOB_socket_path] = { CNTSGLOB_socket_path, 'S', XSIZE(struct section_global_data, socket_path), "socket_path", XOFFSET(struct section_global_data, socket_path) },
  [CNTSGLOB_contests_dir] = { CNTSGLOB_contests_dir, 'S', XSIZE(struct section_global_data, contests_dir), "contests_dir", XOFFSET(struct section_global_data, contests_dir) },
  [CNTSGLOB_lang_config_dir] = { CNTSGLOB_lang_config_dir, 'S', XSIZE(struct section_global_data, lang_config_dir), "lang_config_dir", XOFFSET(struct section_global_data, lang_config_dir) },
  [CNTSGLOB_charset] = { CNTSGLOB_charset, 'S', XSIZE(struct section_global_data, charset), "charset", XOFFSET(struct section_global_data, charset) },
  [CNTSGLOB_standings_charset] = { CNTSGLOB_standings_charset, 'S', XSIZE(struct section_global_data, standings_charset), "standings_charset", XOFFSET(struct section_global_data, standings_charset) },
  [CNTSGLOB_stand2_charset] = { CNTSGLOB_stand2_charset, 'S', XSIZE(struct section_global_data, stand2_charset), "stand2_charset", XOFFSET(struct section_global_data, stand2_charset) },
  [CNTSGLOB_plog_charset] = { CNTSGLOB_plog_charset, 'S', XSIZE(struct section_global_data, plog_charset), "plog_charset", XOFFSET(struct section_global_data, plog_charset) },
  [CNTSGLOB_conf_dir] = { CNTSGLOB_conf_dir, 'S', XSIZE(struct section_global_data, conf_dir), "conf_dir", XOFFSET(struct section_global_data, conf_dir) },
  [CNTSGLOB_problems_dir] = { CNTSGLOB_problems_dir, 'S', XSIZE(struct section_global_data, problems_dir), "problems_dir", XOFFSET(struct section_global_data, problems_dir) },
  [CNTSGLOB_script_dir] = { CNTSGLOB_script_dir, 'S', XSIZE(struct section_global_data, script_dir), "script_dir", XOFFSET(struct section_global_data, script_dir) },
  [CNTSGLOB_test_dir] = { CNTSGLOB_test_dir, 'S', XSIZE(struct section_global_data, test_dir), "test_dir", XOFFSET(struct section_global_data, test_dir) },
  [CNTSGLOB_corr_dir] = { CNTSGLOB_corr_dir, 'S', XSIZE(struct section_global_data, corr_dir), "corr_dir", XOFFSET(struct section_global_data, corr_dir) },
  [CNTSGLOB_info_dir] = { CNTSGLOB_info_dir, 'S', XSIZE(struct section_global_data, info_dir), "info_dir", XOFFSET(struct section_global_data, info_dir) },
  [CNTSGLOB_tgz_dir] = { CNTSGLOB_tgz_dir, 'S', XSIZE(struct section_global_data, tgz_dir), "tgz_dir", XOFFSET(struct section_global_data, tgz_dir) },
  [CNTSGLOB_checker_dir] = { CNTSGLOB_checker_dir, 'S', XSIZE(struct section_global_data, checker_dir), "checker_dir", XOFFSET(struct section_global_data, checker_dir) },
  [CNTSGLOB_statement_dir] = { CNTSGLOB_statement_dir, 'S', XSIZE(struct section_global_data, statement_dir), "statement_dir", XOFFSET(struct section_global_data, statement_dir) },
  [CNTSGLOB_plugin_dir] = { CNTSGLOB_plugin_dir, 'S', XSIZE(struct section_global_data, plugin_dir), "plugin_dir", XOFFSET(struct section_global_data, plugin_dir) },
  [CNTSGLOB_test_sfx] = { CNTSGLOB_test_sfx, 'S', XSIZE(struct section_global_data, test_sfx), "test_sfx", XOFFSET(struct section_global_data, test_sfx) },
  [CNTSGLOB_corr_sfx] = { CNTSGLOB_corr_sfx, 'S', XSIZE(struct section_global_data, corr_sfx), "corr_sfx", XOFFSET(struct section_global_data, corr_sfx) },
  [CNTSGLOB_info_sfx] = { CNTSGLOB_info_sfx, 'S', XSIZE(struct section_global_data, info_sfx), "info_sfx", XOFFSET(struct section_global_data, info_sfx) },
  [CNTSGLOB_tgz_sfx] = { CNTSGLOB_tgz_sfx, 'S', XSIZE(struct section_global_data, tgz_sfx), "tgz_sfx", XOFFSET(struct section_global_data, tgz_sfx) },
  [CNTSGLOB_tgzdir_sfx] = { CNTSGLOB_tgzdir_sfx, 'S', XSIZE(struct section_global_data, tgzdir_sfx), "tgzdir_sfx", XOFFSET(struct section_global_data, tgzdir_sfx) },
  [CNTSGLOB_ejudge_checkers_dir] = { CNTSGLOB_ejudge_checkers_dir, 'S', XSIZE(struct section_global_data, ejudge_checkers_dir), "ejudge_checkers_dir", XOFFSET(struct section_global_data, ejudge_checkers_dir) },
  [CNTSGLOB_contest_start_cmd] = { CNTSGLOB_contest_start_cmd, 'S', XSIZE(struct section_global_data, contest_start_cmd), "contest_start_cmd", XOFFSET(struct section_global_data, contest_start_cmd) },
  [CNTSGLOB_contest_stop_cmd] = { CNTSGLOB_contest_stop_cmd, 's', XSIZE(struct section_global_data, contest_stop_cmd), "contest_stop_cmd", XOFFSET(struct section_global_data, contest_stop_cmd) },
  [CNTSGLOB_description_file] = { CNTSGLOB_description_file, 'S', XSIZE(struct section_global_data, description_file), "description_file", XOFFSET(struct section_global_data, description_file) },
  [CNTSGLOB_contest_plugin_file] = { CNTSGLOB_contest_plugin_file, 'S', XSIZE(struct section_global_data, contest_plugin_file), "contest_plugin_file", XOFFSET(struct section_global_data, contest_plugin_file) },
  [CNTSGLOB_super_run_dir] = { CNTSGLOB_super_run_dir, 's', XSIZE(struct section_global_data, super_run_dir), "super_run_dir", XOFFSET(struct section_global_data, super_run_dir) },
  [CNTSGLOB_test_pat] = { CNTSGLOB_test_pat, 'S', XSIZE(struct section_global_data, test_pat), "test_pat", XOFFSET(struct section_global_data, test_pat) },
  [CNTSGLOB_corr_pat] = { CNTSGLOB_corr_pat, 'S', XSIZE(struct section_global_data, corr_pat), "corr_pat", XOFFSET(struct section_global_data, corr_pat) },
  [CNTSGLOB_info_pat] = { CNTSGLOB_info_pat, 'S', XSIZE(struct section_global_data, info_pat), "info_pat", XOFFSET(struct section_global_data, info_pat) },
  [CNTSGLOB_tgz_pat] = { CNTSGLOB_tgz_pat, 'S', XSIZE(struct section_global_data, tgz_pat), "tgz_pat", XOFFSET(struct section_global_data, tgz_pat) },
  [CNTSGLOB_tgzdir_pat] = { CNTSGLOB_tgzdir_pat, 'S', XSIZE(struct section_global_data, tgzdir_pat), "tgzdir_pat", XOFFSET(struct section_global_data, tgzdir_pat) },
  [CNTSGLOB_clardb_plugin] = { CNTSGLOB_clardb_plugin, 'S', XSIZE(struct section_global_data, clardb_plugin), "clardb_plugin", XOFFSET(struct section_global_data, clardb_plugin) },
  [CNTSGLOB_rundb_plugin] = { CNTSGLOB_rundb_plugin, 'S', XSIZE(struct section_global_data, rundb_plugin), "rundb_plugin", XOFFSET(struct section_global_data, rundb_plugin) },
  [CNTSGLOB_xuser_plugin] = { CNTSGLOB_xuser_plugin, 'S', XSIZE(struct section_global_data, xuser_plugin), "xuser_plugin", XOFFSET(struct section_global_data, xuser_plugin) },
  [CNTSGLOB_var_dir] = { CNTSGLOB_var_dir, 'S', XSIZE(struct section_global_data, var_dir), "var_dir", XOFFSET(struct section_global_data, var_dir) },
  [CNTSGLOB_run_log_file] = { CNTSGLOB_run_log_file, 'S', XSIZE(struct section_global_data, run_log_file), "run_log_file", XOFFSET(struct section_global_data, run_log_file) },
  [CNTSGLOB_clar_log_file] = { CNTSGLOB_clar_log_file, 'S', XSIZE(struct section_global_data, clar_log_file), "clar_log_file", XOFFSET(struct section_global_data, clar_log_file) },
  [CNTSGLOB_archive_dir] = { CNTSGLOB_archive_dir, 'S', XSIZE(struct section_global_data, archive_dir), "archive_dir", XOFFSET(struct section_global_data, archive_dir) },
  [CNTSGLOB_clar_archive_dir] = { CNTSGLOB_clar_archive_dir, 'S', XSIZE(struct section_global_data, clar_archive_dir), "clar_archive_dir", XOFFSET(struct section_global_data, clar_archive_dir) },
  [CNTSGLOB_run_archive_dir] = { CNTSGLOB_run_archive_dir, 'S', XSIZE(struct section_global_data, run_archive_dir), "run_archive_dir", XOFFSET(struct section_global_data, run_archive_dir) },
  [CNTSGLOB_report_archive_dir] = { CNTSGLOB_report_archive_dir, 'S', XSIZE(struct section_global_data, report_archive_dir), "report_archive_dir", XOFFSET(struct section_global_data, report_archive_dir) },
  [CNTSGLOB_team_report_archive_dir] = { CNTSGLOB_team_report_archive_dir, 'S', XSIZE(struct section_global_data, team_report_archive_dir), "team_report_archive_dir", XOFFSET(struct section_global_data, team_report_archive_dir) },
  [CNTSGLOB_xml_report_archive_dir] = { CNTSGLOB_xml_report_archive_dir, 'S', XSIZE(struct section_global_data, xml_report_archive_dir), "xml_report_archive_dir", XOFFSET(struct section_global_data, xml_report_archive_dir) },
  [CNTSGLOB_full_archive_dir] = { CNTSGLOB_full_archive_dir, 'S', XSIZE(struct section_global_data, full_archive_dir), "full_archive_dir", XOFFSET(struct section_global_data, full_archive_dir) },
  [CNTSGLOB_audit_log_dir] = { CNTSGLOB_audit_log_dir, 'S', XSIZE(struct section_global_data, audit_log_dir), "audit_log_dir", XOFFSET(struct section_global_data, audit_log_dir) },
  [CNTSGLOB_uuid_archive_dir] = { CNTSGLOB_uuid_archive_dir, 'S', XSIZE(struct section_global_data, uuid_archive_dir), "uuid_archive_dir", XOFFSET(struct section_global_data, uuid_archive_dir) },
  [CNTSGLOB_team_extra_dir] = { CNTSGLOB_team_extra_dir, 'S', XSIZE(struct section_global_data, team_extra_dir), "team_extra_dir", XOFFSET(struct section_global_data, team_extra_dir) },
  [CNTSGLOB_status_dir] = { CNTSGLOB_status_dir, 'S', XSIZE(struct section_global_data, status_dir), "status_dir", XOFFSET(struct section_global_data, status_dir) },
  [CNTSGLOB_work_dir] = { CNTSGLOB_work_dir, 'S', XSIZE(struct section_global_data, work_dir), "work_dir", XOFFSET(struct section_global_data, work_dir) },
  [CNTSGLOB_print_work_dir] = { CNTSGLOB_print_work_dir, 'S', XSIZE(struct section_global_data, print_work_dir), "print_work_dir", XOFFSET(struct section_global_data, print_work_dir) },
  [CNTSGLOB_diff_work_dir] = { CNTSGLOB_diff_work_dir, 'S', XSIZE(struct section_global_data, diff_work_dir), "diff_work_dir", XOFFSET(struct section_global_data, diff_work_dir) },
  [CNTSGLOB_a2ps_path] = { CNTSGLOB_a2ps_path, 'S', XSIZE(struct section_global_data, a2ps_path), "a2ps_path", XOFFSET(struct section_global_data, a2ps_path) },
  [CNTSGLOB_a2ps_args] = { CNTSGLOB_a2ps_args, 'x', XSIZE(struct section_global_data, a2ps_args), "a2ps_args", XOFFSET(struct section_global_data, a2ps_args) },
  [CNTSGLOB_lpr_path] = { CNTSGLOB_lpr_path, 'S', XSIZE(struct section_global_data, lpr_path), "lpr_path", XOFFSET(struct section_global_data, lpr_path) },
  [CNTSGLOB_lpr_args] = { CNTSGLOB_lpr_args, 'x', XSIZE(struct section_global_data, lpr_args), "lpr_args", XOFFSET(struct section_global_data, lpr_args) },
  [CNTSGLOB_diff_path] = { CNTSGLOB_diff_path, 'S', XSIZE(struct section_global_data, diff_path), "diff_path", XOFFSET(struct section_global_data, diff_path) },
  [CNTSGLOB_compile_dir] = { CNTSGLOB_compile_dir, 'S', XSIZE(struct section_global_data, compile_dir), "compile_dir", XOFFSET(struct section_global_data, compile_dir) },
  [CNTSGLOB_compile_queue_dir] = { CNTSGLOB_compile_queue_dir, 'S', XSIZE(struct section_global_data, compile_queue_dir), "compile_queue_dir", XOFFSET(struct section_global_data, compile_queue_dir) },
  [CNTSGLOB_compile_src_dir] = { CNTSGLOB_compile_src_dir, 'S', XSIZE(struct section_global_data, compile_src_dir), "compile_src_dir", XOFFSET(struct section_global_data, compile_src_dir) },
  [CNTSGLOB_extra_compile_dirs] = { CNTSGLOB_extra_compile_dirs, 'x', XSIZE(struct section_global_data, extra_compile_dirs), "extra_compile_dirs", XOFFSET(struct section_global_data, extra_compile_dirs) },
  [CNTSGLOB_compile_out_dir] = { CNTSGLOB_compile_out_dir, 'S', XSIZE(struct section_global_data, compile_out_dir), "compile_out_dir", XOFFSET(struct section_global_data, compile_out_dir) },
  [CNTSGLOB_compile_status_dir] = { CNTSGLOB_compile_status_dir, 'S', XSIZE(struct section_global_data, compile_status_dir), "compile_status_dir", XOFFSET(struct section_global_data, compile_status_dir) },
  [CNTSGLOB_compile_report_dir] = { CNTSGLOB_compile_report_dir, 'S', XSIZE(struct section_global_data, compile_report_dir), "compile_report_dir", XOFFSET(struct section_global_data, compile_report_dir) },
  [CNTSGLOB_compile_work_dir] = { CNTSGLOB_compile_work_dir, 'S', XSIZE(struct section_global_data, compile_work_dir), "compile_work_dir", XOFFSET(struct section_global_data, compile_work_dir) },
  [CNTSGLOB_run_dir] = { CNTSGLOB_run_dir, 'S', XSIZE(struct section_global_data, run_dir), "run_dir", XOFFSET(struct section_global_data, run_dir) },
  [CNTSGLOB_run_queue_dir] = { CNTSGLOB_run_queue_dir, 'S', XSIZE(struct section_global_data, run_queue_dir), "run_queue_dir", XOFFSET(struct section_global_data, run_queue_dir) },
  [CNTSGLOB_run_exe_dir] = { CNTSGLOB_run_exe_dir, 'S', XSIZE(struct section_global_data, run_exe_dir), "run_exe_dir", XOFFSET(struct section_global_data, run_exe_dir) },
  [CNTSGLOB_run_out_dir] = { CNTSGLOB_run_out_dir, 'S', XSIZE(struct section_global_data, run_out_dir), "run_out_dir", XOFFSET(struct section_global_data, run_out_dir) },
  [CNTSGLOB_run_status_dir] = { CNTSGLOB_run_status_dir, 'S', XSIZE(struct section_global_data, run_status_dir), "run_status_dir", XOFFSET(struct section_global_data, run_status_dir) },
  [CNTSGLOB_run_report_dir] = { CNTSGLOB_run_report_dir, 'S', XSIZE(struct section_global_data, run_report_dir), "run_report_dir", XOFFSET(struct section_global_data, run_report_dir) },
  [CNTSGLOB_run_team_report_dir] = { CNTSGLOB_run_team_report_dir, 'S', XSIZE(struct section_global_data, run_team_report_dir), "run_team_report_dir", XOFFSET(struct section_global_data, run_team_report_dir) },
  [CNTSGLOB_run_full_archive_dir] = { CNTSGLOB_run_full_archive_dir, 'S', XSIZE(struct section_global_data, run_full_archive_dir), "run_full_archive_dir", XOFFSET(struct section_global_data, run_full_archive_dir) },
  [CNTSGLOB_run_work_dir] = { CNTSGLOB_run_work_dir, 'S', XSIZE(struct section_global_data, run_work_dir), "run_work_dir", XOFFSET(struct section_global_data, run_work_dir) },
  [CNTSGLOB_run_check_dir] = { CNTSGLOB_run_check_dir, 'S', XSIZE(struct section_global_data, run_check_dir), "run_check_dir", XOFFSET(struct section_global_data, run_check_dir) },
  [CNTSGLOB_htdocs_dir] = { CNTSGLOB_htdocs_dir, 'S', XSIZE(struct section_global_data, htdocs_dir), "htdocs_dir", XOFFSET(struct section_global_data, htdocs_dir) },
  [CNTSGLOB_score_system] = { CNTSGLOB_score_system, 'i', XSIZE(struct section_global_data, score_system), "score_system", XOFFSET(struct section_global_data, score_system) },
  [CNTSGLOB_tests_to_accept] = { CNTSGLOB_tests_to_accept, 'i', XSIZE(struct section_global_data, tests_to_accept), "tests_to_accept", XOFFSET(struct section_global_data, tests_to_accept) },
  [CNTSGLOB_is_virtual] = { CNTSGLOB_is_virtual, 'B', XSIZE(struct section_global_data, is_virtual), "is_virtual", XOFFSET(struct section_global_data, is_virtual) },
  [CNTSGLOB_prune_empty_users] = { CNTSGLOB_prune_empty_users, 'B', XSIZE(struct section_global_data, prune_empty_users), "prune_empty_users", XOFFSET(struct section_global_data, prune_empty_users) },
  [CNTSGLOB_rounding_mode] = { CNTSGLOB_rounding_mode, 'i', XSIZE(struct section_global_data, rounding_mode), "rounding_mode", XOFFSET(struct section_global_data, rounding_mode) },
  [CNTSGLOB_max_file_length] = { CNTSGLOB_max_file_length, 'z', XSIZE(struct section_global_data, max_file_length), "max_file_length", XOFFSET(struct section_global_data, max_file_length) },
  [CNTSGLOB_max_line_length] = { CNTSGLOB_max_line_length, 'z', XSIZE(struct section_global_data, max_line_length), "max_line_length", XOFFSET(struct section_global_data, max_line_length) },
  [CNTSGLOB_max_cmd_length] = { CNTSGLOB_max_cmd_length, 'z', XSIZE(struct section_global_data, max_cmd_length), "max_cmd_length", XOFFSET(struct section_global_data, max_cmd_length) },
  [CNTSGLOB_team_info_url] = { CNTSGLOB_team_info_url, 'S', XSIZE(struct section_global_data, team_info_url), "team_info_url", XOFFSET(struct section_global_data, team_info_url) },
  [CNTSGLOB_prob_info_url] = { CNTSGLOB_prob_info_url, 'S', XSIZE(struct section_global_data, prob_info_url), "prob_info_url", XOFFSET(struct section_global_data, prob_info_url) },
  [CNTSGLOB_standings_file_name] = { CNTSGLOB_standings_file_name, 'S', XSIZE(struct section_global_data, standings_file_name), "standings_file_name", XOFFSET(struct section_global_data, standings_file_name) },
  [CNTSGLOB_stand_header_file] = { CNTSGLOB_stand_header_file, 'S', XSIZE(struct section_global_data, stand_header_file), "stand_header_file", XOFFSET(struct section_global_data, stand_header_file) },
  [CNTSGLOB_stand_footer_file] = { CNTSGLOB_stand_footer_file, 'S', XSIZE(struct section_global_data, stand_footer_file), "stand_footer_file", XOFFSET(struct section_global_data, stand_footer_file) },
  [CNTSGLOB_stand_symlink_dir] = { CNTSGLOB_stand_symlink_dir, 'S', XSIZE(struct section_global_data, stand_symlink_dir), "stand_symlink_dir", XOFFSET(struct section_global_data, stand_symlink_dir) },
  [CNTSGLOB_users_on_page] = { CNTSGLOB_users_on_page, 'i', XSIZE(struct section_global_data, users_on_page), "users_on_page", XOFFSET(struct section_global_data, users_on_page) },
  [CNTSGLOB_stand_file_name_2] = { CNTSGLOB_stand_file_name_2, 'S', XSIZE(struct section_global_data, stand_file_name_2), "stand_file_name_2", XOFFSET(struct section_global_data, stand_file_name_2) },
  [CNTSGLOB_stand_fancy_style] = { CNTSGLOB_stand_fancy_style, 'B', XSIZE(struct section_global_data, stand_fancy_style), "stand_fancy_style", XOFFSET(struct section_global_data, stand_fancy_style) },
  [CNTSGLOB_stand_extra_format] = { CNTSGLOB_stand_extra_format, 'S', XSIZE(struct section_global_data, stand_extra_format), "stand_extra_format", XOFFSET(struct section_global_data, stand_extra_format) },
  [CNTSGLOB_stand_extra_legend] = { CNTSGLOB_stand_extra_legend, 'S', XSIZE(struct section_global_data, stand_extra_legend), "stand_extra_legend", XOFFSET(struct section_global_data, stand_extra_legend) },
  [CNTSGLOB_stand_extra_attr] = { CNTSGLOB_stand_extra_attr, 'S', XSIZE(struct section_global_data, stand_extra_attr), "stand_extra_attr", XOFFSET(struct section_global_data, stand_extra_attr) },
  [CNTSGLOB_stand_table_attr] = { CNTSGLOB_stand_table_attr, 'S', XSIZE(struct section_global_data, stand_table_attr), "stand_table_attr", XOFFSET(struct section_global_data, stand_table_attr) },
  [CNTSGLOB_stand_place_attr] = { CNTSGLOB_stand_place_attr, 'S', XSIZE(struct section_global_data, stand_place_attr), "stand_place_attr", XOFFSET(struct section_global_data, stand_place_attr) },
  [CNTSGLOB_stand_team_attr] = { CNTSGLOB_stand_team_attr, 'S', XSIZE(struct section_global_data, stand_team_attr), "stand_team_attr", XOFFSET(struct section_global_data, stand_team_attr) },
  [CNTSGLOB_stand_prob_attr] = { CNTSGLOB_stand_prob_attr, 'S', XSIZE(struct section_global_data, stand_prob_attr), "stand_prob_attr", XOFFSET(struct section_global_data, stand_prob_attr) },
  [CNTSGLOB_stand_solved_attr] = { CNTSGLOB_stand_solved_attr, 'S', XSIZE(struct section_global_data, stand_solved_attr), "stand_solved_attr", XOFFSET(struct section_global_data, stand_solved_attr) },
  [CNTSGLOB_stand_score_attr] = { CNTSGLOB_stand_score_attr, 'S', XSIZE(struct section_global_data, stand_score_attr), "stand_score_attr", XOFFSET(struct section_global_data, stand_score_attr) },
  [CNTSGLOB_stand_penalty_attr] = { CNTSGLOB_stand_penalty_attr, 'S', XSIZE(struct section_global_data, stand_penalty_attr), "stand_penalty_attr", XOFFSET(struct section_global_data, stand_penalty_attr) },
  [CNTSGLOB_stand_time_attr] = { CNTSGLOB_stand_time_attr, 'S', XSIZE(struct section_global_data, stand_time_attr), "stand_time_attr", XOFFSET(struct section_global_data, stand_time_attr) },
  [CNTSGLOB_stand_self_row_attr] = { CNTSGLOB_stand_self_row_attr, 'S', XSIZE(struct section_global_data, stand_self_row_attr), "stand_self_row_attr", XOFFSET(struct section_global_data, stand_self_row_attr) },
  [CNTSGLOB_stand_r_row_attr] = { CNTSGLOB_stand_r_row_attr, 'S', XSIZE(struct section_global_data, stand_r_row_attr), "stand_r_row_attr", XOFFSET(struct section_global_data, stand_r_row_attr) },
  [CNTSGLOB_stand_v_row_attr] = { CNTSGLOB_stand_v_row_attr, 'S', XSIZE(struct section_global_data, stand_v_row_attr), "stand_v_row_attr", XOFFSET(struct section_global_data, stand_v_row_attr) },
  [CNTSGLOB_stand_u_row_attr] = { CNTSGLOB_stand_u_row_attr, 'S', XSIZE(struct section_global_data, stand_u_row_attr), "stand_u_row_attr", XOFFSET(struct section_global_data, stand_u_row_attr) },
  [CNTSGLOB_stand_success_attr] = { CNTSGLOB_stand_success_attr, 'S', XSIZE(struct section_global_data, stand_success_attr), "stand_success_attr", XOFFSET(struct section_global_data, stand_success_attr) },
  [CNTSGLOB_stand_fail_attr] = { CNTSGLOB_stand_fail_attr, 'S', XSIZE(struct section_global_data, stand_fail_attr), "stand_fail_attr", XOFFSET(struct section_global_data, stand_fail_attr) },
  [CNTSGLOB_stand_trans_attr] = { CNTSGLOB_stand_trans_attr, 'S', XSIZE(struct section_global_data, stand_trans_attr), "stand_trans_attr", XOFFSET(struct section_global_data, stand_trans_attr) },
  [CNTSGLOB_stand_disq_attr] = { CNTSGLOB_stand_disq_attr, 'S', XSIZE(struct section_global_data, stand_disq_attr), "stand_disq_attr", XOFFSET(struct section_global_data, stand_disq_attr) },
  [CNTSGLOB_stand_use_login] = { CNTSGLOB_stand_use_login, 'B', XSIZE(struct section_global_data, stand_use_login), "stand_use_login", XOFFSET(struct section_global_data, stand_use_login) },
  [CNTSGLOB_stand_show_ok_time] = { CNTSGLOB_stand_show_ok_time, 'B', XSIZE(struct section_global_data, stand_show_ok_time), "stand_show_ok_time", XOFFSET(struct section_global_data, stand_show_ok_time) },
  [CNTSGLOB_stand_show_att_num] = { CNTSGLOB_stand_show_att_num, 'B', XSIZE(struct section_global_data, stand_show_att_num), "stand_show_att_num", XOFFSET(struct section_global_data, stand_show_att_num) },
  [CNTSGLOB_stand_sort_by_solved] = { CNTSGLOB_stand_sort_by_solved, 'B', XSIZE(struct section_global_data, stand_sort_by_solved), "stand_sort_by_solved", XOFFSET(struct section_global_data, stand_sort_by_solved) },
  [CNTSGLOB_stand_row_attr] = { CNTSGLOB_stand_row_attr, 'x', XSIZE(struct section_global_data, stand_row_attr), "stand_row_attr", XOFFSET(struct section_global_data, stand_row_attr) },
  [CNTSGLOB_stand_page_table_attr] = { CNTSGLOB_stand_page_table_attr, 'S', XSIZE(struct section_global_data, stand_page_table_attr), "stand_page_table_attr", XOFFSET(struct section_global_data, stand_page_table_attr) },
  [CNTSGLOB_stand_page_row_attr] = { CNTSGLOB_stand_page_row_attr, 'x', XSIZE(struct section_global_data, stand_page_row_attr), "stand_page_row_attr", XOFFSET(struct section_global_data, stand_page_row_attr) },
  [CNTSGLOB_stand_page_col_attr] = { CNTSGLOB_stand_page_col_attr, 'x', XSIZE(struct section_global_data, stand_page_col_attr), "stand_page_col_attr", XOFFSET(struct section_global_data, stand_page_col_attr) },
  [CNTSGLOB_stand_page_cur_attr] = { CNTSGLOB_stand_page_cur_attr, 'S', XSIZE(struct section_global_data, stand_page_cur_attr), "stand_page_cur_attr", XOFFSET(struct section_global_data, stand_page_cur_attr) },
  [CNTSGLOB_stand_collate_name] = { CNTSGLOB_stand_collate_name, 'B', XSIZE(struct section_global_data, stand_collate_name), "stand_collate_name", XOFFSET(struct section_global_data, stand_collate_name) },
  [CNTSGLOB_stand_enable_penalty] = { CNTSGLOB_stand_enable_penalty, 'B', XSIZE(struct section_global_data, stand_enable_penalty), "stand_enable_penalty", XOFFSET(struct section_global_data, stand_enable_penalty) },
  [CNTSGLOB_stand_header_txt] = { CNTSGLOB_stand_header_txt, 's', XSIZE(struct section_global_data, stand_header_txt), NULL, XOFFSET(struct section_global_data, stand_header_txt) },
  [CNTSGLOB_stand_footer_txt] = { CNTSGLOB_stand_footer_txt, 's', XSIZE(struct section_global_data, stand_footer_txt), NULL, XOFFSET(struct section_global_data, stand_footer_txt) },
  [CNTSGLOB_stand2_file_name] = { CNTSGLOB_stand2_file_name, 'S', XSIZE(struct section_global_data, stand2_file_name), "stand2_file_name", XOFFSET(struct section_global_data, stand2_file_name) },
  [CNTSGLOB_stand2_header_file] = { CNTSGLOB_stand2_header_file, 'S', XSIZE(struct section_global_data, stand2_header_file), "stand2_header_file", XOFFSET(struct section_global_data, stand2_header_file) },
  [CNTSGLOB_stand2_footer_file] = { CNTSGLOB_stand2_footer_file, 'S', XSIZE(struct section_global_data, stand2_footer_file), "stand2_footer_file", XOFFSET(struct section_global_data, stand2_footer_file) },
  [CNTSGLOB_stand2_header_txt] = { CNTSGLOB_stand2_header_txt, 's', XSIZE(struct section_global_data, stand2_header_txt), NULL, XOFFSET(struct section_global_data, stand2_header_txt) },
  [CNTSGLOB_stand2_footer_txt] = { CNTSGLOB_stand2_footer_txt, 's', XSIZE(struct section_global_data, stand2_footer_txt), NULL, XOFFSET(struct section_global_data, stand2_footer_txt) },
  [CNTSGLOB_stand2_symlink_dir] = { CNTSGLOB_stand2_symlink_dir, 'S', XSIZE(struct section_global_data, stand2_symlink_dir), "stand2_symlink_dir", XOFFSET(struct section_global_data, stand2_symlink_dir) },
  [CNTSGLOB_plog_file_name] = { CNTSGLOB_plog_file_name, 'S', XSIZE(struct section_global_data, plog_file_name), "plog_file_name", XOFFSET(struct section_global_data, plog_file_name) },
  [CNTSGLOB_plog_header_file] = { CNTSGLOB_plog_header_file, 'S', XSIZE(struct section_global_data, plog_header_file), "plog_header_file", XOFFSET(struct section_global_data, plog_header_file) },
  [CNTSGLOB_plog_footer_file] = { CNTSGLOB_plog_footer_file, 'S', XSIZE(struct section_global_data, plog_footer_file), "plog_footer_file", XOFFSET(struct section_global_data, plog_footer_file) },
  [CNTSGLOB_plog_header_txt] = { CNTSGLOB_plog_header_txt, 's', XSIZE(struct section_global_data, plog_header_txt), NULL, XOFFSET(struct section_global_data, plog_header_txt) },
  [CNTSGLOB_plog_footer_txt] = { CNTSGLOB_plog_footer_txt, 's', XSIZE(struct section_global_data, plog_footer_txt), NULL, XOFFSET(struct section_global_data, plog_footer_txt) },
  [CNTSGLOB_plog_update_time] = { CNTSGLOB_plog_update_time, 'i', XSIZE(struct section_global_data, plog_update_time), "plog_update_time", XOFFSET(struct section_global_data, plog_update_time) },
  [CNTSGLOB_plog_symlink_dir] = { CNTSGLOB_plog_symlink_dir, 'S', XSIZE(struct section_global_data, plog_symlink_dir), "plog_symlink_dir", XOFFSET(struct section_global_data, plog_symlink_dir) },
  [CNTSGLOB_internal_xml_update_time] = { CNTSGLOB_internal_xml_update_time, 'i', XSIZE(struct section_global_data, internal_xml_update_time), "internal_xml_update_time", XOFFSET(struct section_global_data, internal_xml_update_time) },
  [CNTSGLOB_external_xml_update_time] = { CNTSGLOB_external_xml_update_time, 'i', XSIZE(struct section_global_data, external_xml_update_time), "external_xml_update_time", XOFFSET(struct section_global_data, external_xml_update_time) },
  [CNTSGLOB_user_exam_protocol_header_file] = { CNTSGLOB_user_exam_protocol_header_file, 'S', XSIZE(struct section_global_data, user_exam_protocol_header_file), "user_exam_protocol_header_file", XOFFSET(struct section_global_data, user_exam_protocol_header_file) },
  [CNTSGLOB_user_exam_protocol_footer_file] = { CNTSGLOB_user_exam_protocol_footer_file, 'S', XSIZE(struct section_global_data, user_exam_protocol_footer_file), "user_exam_protocol_footer_file", XOFFSET(struct section_global_data, user_exam_protocol_footer_file) },
  [CNTSGLOB_user_exam_protocol_header_txt] = { CNTSGLOB_user_exam_protocol_header_txt, 's', XSIZE(struct section_global_data, user_exam_protocol_header_txt), NULL, XOFFSET(struct section_global_data, user_exam_protocol_header_txt) },
  [CNTSGLOB_user_exam_protocol_footer_txt] = { CNTSGLOB_user_exam_protocol_footer_txt, 's', XSIZE(struct section_global_data, user_exam_protocol_footer_txt), NULL, XOFFSET(struct section_global_data, user_exam_protocol_footer_txt) },
  [CNTSGLOB_prob_exam_protocol_header_file] = { CNTSGLOB_prob_exam_protocol_header_file, 'S', XSIZE(struct section_global_data, prob_exam_protocol_header_file), "prob_exam_protocol_header_file", XOFFSET(struct section_global_data, prob_exam_protocol_header_file) },
  [CNTSGLOB_prob_exam_protocol_footer_file] = { CNTSGLOB_prob_exam_protocol_footer_file, 'S', XSIZE(struct section_global_data, prob_exam_protocol_footer_file), "prob_exam_protocol_footer_file", XOFFSET(struct section_global_data, prob_exam_protocol_footer_file) },
  [CNTSGLOB_prob_exam_protocol_header_txt] = { CNTSGLOB_prob_exam_protocol_header_txt, 's', XSIZE(struct section_global_data, prob_exam_protocol_header_txt), NULL, XOFFSET(struct section_global_data, prob_exam_protocol_header_txt) },
  [CNTSGLOB_prob_exam_protocol_footer_txt] = { CNTSGLOB_prob_exam_protocol_footer_txt, 's', XSIZE(struct section_global_data, prob_exam_protocol_footer_txt), NULL, XOFFSET(struct section_global_data, prob_exam_protocol_footer_txt) },
  [CNTSGLOB_full_exam_protocol_header_file] = { CNTSGLOB_full_exam_protocol_header_file, 'S', XSIZE(struct section_global_data, full_exam_protocol_header_file), "full_exam_protocol_header_file", XOFFSET(struct section_global_data, full_exam_protocol_header_file) },
  [CNTSGLOB_full_exam_protocol_footer_file] = { CNTSGLOB_full_exam_protocol_footer_file, 'S', XSIZE(struct section_global_data, full_exam_protocol_footer_file), "full_exam_protocol_footer_file", XOFFSET(struct section_global_data, full_exam_protocol_footer_file) },
  [CNTSGLOB_full_exam_protocol_header_txt] = { CNTSGLOB_full_exam_protocol_header_txt, 's', XSIZE(struct section_global_data, full_exam_protocol_header_txt), NULL, XOFFSET(struct section_global_data, full_exam_protocol_header_txt) },
  [CNTSGLOB_full_exam_protocol_footer_txt] = { CNTSGLOB_full_exam_protocol_footer_txt, 's', XSIZE(struct section_global_data, full_exam_protocol_footer_txt), NULL, XOFFSET(struct section_global_data, full_exam_protocol_footer_txt) },
  [CNTSGLOB_extended_sound] = { CNTSGLOB_extended_sound, 'B', XSIZE(struct section_global_data, extended_sound), "extended_sound", XOFFSET(struct section_global_data, extended_sound) },
  [CNTSGLOB_disable_sound] = { CNTSGLOB_disable_sound, 'B', XSIZE(struct section_global_data, disable_sound), "disable_sound", XOFFSET(struct section_global_data, disable_sound) },
  [CNTSGLOB_sound_player] = { CNTSGLOB_sound_player, 'S', XSIZE(struct section_global_data, sound_player), "sound_player", XOFFSET(struct section_global_data, sound_player) },
  [CNTSGLOB_accept_sound] = { CNTSGLOB_accept_sound, 'S', XSIZE(struct section_global_data, accept_sound), "accept_sound", XOFFSET(struct section_global_data, accept_sound) },
  [CNTSGLOB_runtime_sound] = { CNTSGLOB_runtime_sound, 'S', XSIZE(struct section_global_data, runtime_sound), "runtime_sound", XOFFSET(struct section_global_data, runtime_sound) },
  [CNTSGLOB_timelimit_sound] = { CNTSGLOB_timelimit_sound, 'S', XSIZE(struct section_global_data, timelimit_sound), "timelimit_sound", XOFFSET(struct section_global_data, timelimit_sound) },
  [CNTSGLOB_presentation_sound] = { CNTSGLOB_presentation_sound, 'S', XSIZE(struct section_global_data, presentation_sound), "presentation_sound", XOFFSET(struct section_global_data, presentation_sound) },
  [CNTSGLOB_wrong_sound] = { CNTSGLOB_wrong_sound, 'S', XSIZE(struct section_global_data, wrong_sound), "wrong_sound", XOFFSET(struct section_global_data, wrong_sound) },
  [CNTSGLOB_internal_sound] = { CNTSGLOB_internal_sound, 'S', XSIZE(struct section_global_data, internal_sound), "internal_sound", XOFFSET(struct section_global_data, internal_sound) },
  [CNTSGLOB_start_sound] = { CNTSGLOB_start_sound, 'S', XSIZE(struct section_global_data, start_sound), "start_sound", XOFFSET(struct section_global_data, start_sound) },
  [CNTSGLOB_team_download_time] = { CNTSGLOB_team_download_time, 'i', XSIZE(struct section_global_data, team_download_time), "team_download_time", XOFFSET(struct section_global_data, team_download_time) },
  [CNTSGLOB_cr_serialization_key] = { CNTSGLOB_cr_serialization_key, 'i', XSIZE(struct section_global_data, cr_serialization_key), "cr_serialization_key", XOFFSET(struct section_global_data, cr_serialization_key) },
  [CNTSGLOB_show_astr_time] = { CNTSGLOB_show_astr_time, 'B', XSIZE(struct section_global_data, show_astr_time), "show_astr_time", XOFFSET(struct section_global_data, show_astr_time) },
  [CNTSGLOB_ignore_duplicated_runs] = { CNTSGLOB_ignore_duplicated_runs, 'B', XSIZE(struct section_global_data, ignore_duplicated_runs), "ignore_duplicated_runs", XOFFSET(struct section_global_data, ignore_duplicated_runs) },
  [CNTSGLOB_report_error_code] = { CNTSGLOB_report_error_code, 'B', XSIZE(struct section_global_data, report_error_code), "report_error_code", XOFFSET(struct section_global_data, report_error_code) },
  [CNTSGLOB_auto_short_problem_name] = { CNTSGLOB_auto_short_problem_name, 'B', XSIZE(struct section_global_data, auto_short_problem_name), "auto_short_problem_name", XOFFSET(struct section_global_data, auto_short_problem_name) },
  [CNTSGLOB_compile_real_time_limit] = { CNTSGLOB_compile_real_time_limit, 'i', XSIZE(struct section_global_data, compile_real_time_limit), "compile_real_time_limit", XOFFSET(struct section_global_data, compile_real_time_limit) },
  [CNTSGLOB_checker_real_time_limit] = { CNTSGLOB_checker_real_time_limit, 'i', XSIZE(struct section_global_data, checker_real_time_limit), "checker_real_time_limit", XOFFSET(struct section_global_data, checker_real_time_limit) },
  [CNTSGLOB_show_deadline] = { CNTSGLOB_show_deadline, 'B', XSIZE(struct section_global_data, show_deadline), "show_deadline", XOFFSET(struct section_global_data, show_deadline) },
  [CNTSGLOB_separate_user_score] = { CNTSGLOB_separate_user_score, 'B', XSIZE(struct section_global_data, separate_user_score), "separate_user_score", XOFFSET(struct section_global_data, separate_user_score) },
  [CNTSGLOB_use_gzip] = { CNTSGLOB_use_gzip, 'B', XSIZE(struct section_global_data, use_gzip), "use_gzip", XOFFSET(struct section_global_data, use_gzip) },
  [CNTSGLOB_min_gzip_size] = { CNTSGLOB_min_gzip_size, 'z', XSIZE(struct section_global_data, min_gzip_size), "min_gzip_size", XOFFSET(struct section_global_data, min_gzip_size) },
  [CNTSGLOB_use_dir_hierarchy] = { CNTSGLOB_use_dir_hierarchy, 'B', XSIZE(struct section_global_data, use_dir_hierarchy), "use_dir_hierarchy", XOFFSET(struct section_global_data, use_dir_hierarchy) },
  [CNTSGLOB_html_report] = { CNTSGLOB_html_report, 'B', XSIZE(struct section_global_data, html_report), "html_report", XOFFSET(struct section_global_data, html_report) },
  [CNTSGLOB_xml_report] = { CNTSGLOB_xml_report, 'B', XSIZE(struct section_global_data, xml_report), "xml_report", XOFFSET(struct section_global_data, xml_report) },
  [CNTSGLOB_enable_full_archive] = { CNTSGLOB_enable_full_archive, 'B', XSIZE(struct section_global_data, enable_full_archive), "enable_full_archive", XOFFSET(struct section_global_data, enable_full_archive) },
  [CNTSGLOB_cpu_bogomips] = { CNTSGLOB_cpu_bogomips, 'i', XSIZE(struct section_global_data, cpu_bogomips), "cpu_bogomips", XOFFSET(struct section_global_data, cpu_bogomips) },
  [CNTSGLOB_skip_full_testing] = { CNTSGLOB_skip_full_testing, 'B', XSIZE(struct section_global_data, skip_full_testing), "skip_full_testing", XOFFSET(struct section_global_data, skip_full_testing) },
  [CNTSGLOB_skip_accept_testing] = { CNTSGLOB_skip_accept_testing, 'B', XSIZE(struct section_global_data, skip_accept_testing), "skip_accept_testing", XOFFSET(struct section_global_data, skip_accept_testing) },
  [CNTSGLOB_variant_map_file] = { CNTSGLOB_variant_map_file, 'S', XSIZE(struct section_global_data, variant_map_file), "variant_map_file", XOFFSET(struct section_global_data, variant_map_file) },
  [CNTSGLOB_variant_map] = { CNTSGLOB_variant_map, '?', XSIZE(struct section_global_data, variant_map), NULL, XOFFSET(struct section_global_data, variant_map) },
  [CNTSGLOB_enable_printing] = { CNTSGLOB_enable_printing, 'B', XSIZE(struct section_global_data, enable_printing), "enable_printing", XOFFSET(struct section_global_data, enable_printing) },
  [CNTSGLOB_disable_banner_page] = { CNTSGLOB_disable_banner_page, 'B', XSIZE(struct section_global_data, disable_banner_page), "disable_banner_page", XOFFSET(struct section_global_data, disable_banner_page) },
  [CNTSGLOB_printout_uses_login] = { CNTSGLOB_printout_uses_login, 'B', XSIZE(struct section_global_data, printout_uses_login), "printout_uses_login", XOFFSET(struct section_global_data, printout_uses_login) },
  [CNTSGLOB_team_page_quota] = { CNTSGLOB_team_page_quota, 'i', XSIZE(struct section_global_data, team_page_quota), "team_page_quota", XOFFSET(struct section_global_data, team_page_quota) },
  [CNTSGLOB_compile_max_vm_size] = { CNTSGLOB_compile_max_vm_size, 'Z', XSIZE(struct section_global_data, compile_max_vm_size), "compile_max_vm_size", XOFFSET(struct section_global_data, compile_max_vm_size) },
  [CNTSGLOB_compile_max_stack_size] = { CNTSGLOB_compile_max_stack_size, 'Z', XSIZE(struct section_global_data, compile_max_stack_size), "compile_max_stack_size", XOFFSET(struct section_global_data, compile_max_stack_size) },
  [CNTSGLOB_compile_max_file_size] = { CNTSGLOB_compile_max_file_size, 'Z', XSIZE(struct section_global_data, compile_max_file_size), "compile_max_file_size", XOFFSET(struct section_global_data, compile_max_file_size) },
  [CNTSGLOB_user_priority_adjustments] = { CNTSGLOB_user_priority_adjustments, 'x', XSIZE(struct section_global_data, user_priority_adjustments), "user_priority_adjustments", XOFFSET(struct section_global_data, user_priority_adjustments) },
  [CNTSGLOB_user_adjustment_info] = { CNTSGLOB_user_adjustment_info, '?', XSIZE(struct section_global_data, user_adjustment_info), NULL, XOFFSET(struct section_global_data, user_adjustment_info) },
  [CNTSGLOB_user_adjustment_map] = { CNTSGLOB_user_adjustment_map, '?', XSIZE(struct section_global_data, user_adjustment_map), NULL, XOFFSET(struct section_global_data, user_adjustment_map) },
  [CNTSGLOB_contestant_status_num] = { CNTSGLOB_contestant_status_num, 'i', XSIZE(struct section_global_data, contestant_status_num), "contestant_status_num", XOFFSET(struct section_global_data, contestant_status_num) },
  [CNTSGLOB_contestant_status_legend] = { CNTSGLOB_contestant_status_legend, 'x', XSIZE(struct section_global_data, contestant_status_legend), "contestant_status_legend", XOFFSET(struct section_global_data, contestant_status_legend) },
  [CNTSGLOB_contestant_status_row_attr] = { CNTSGLOB_contestant_status_row_attr, 'x', XSIZE(struct section_global_data, contestant_status_row_attr), "contestant_status_row_attr", XOFFSET(struct section_global_data, contestant_status_row_attr) },
  [CNTSGLOB_stand_show_contestant_status] = { CNTSGLOB_stand_show_contestant_status, 'B', XSIZE(struct section_global_data, stand_show_contestant_status), "stand_show_contestant_status", XOFFSET(struct section_global_data, stand_show_contestant_status) },
  [CNTSGLOB_stand_show_warn_number] = { CNTSGLOB_stand_show_warn_number, 'B', XSIZE(struct section_global_data, stand_show_warn_number), "stand_show_warn_number", XOFFSET(struct section_global_data, stand_show_warn_number) },
  [CNTSGLOB_stand_contestant_status_attr] = { CNTSGLOB_stand_contestant_status_attr, 'S', XSIZE(struct section_global_data, stand_contestant_status_attr), "stand_contestant_status_attr", XOFFSET(struct section_global_data, stand_contestant_status_attr) },
  [CNTSGLOB_stand_warn_number_attr] = { CNTSGLOB_stand_warn_number_attr, 'S', XSIZE(struct section_global_data, stand_warn_number_attr), "stand_warn_number_attr", XOFFSET(struct section_global_data, stand_warn_number_attr) },
  [CNTSGLOB_load_user_group] = { CNTSGLOB_load_user_group, 'x', XSIZE(struct section_global_data, load_user_group), "load_user_group", XOFFSET(struct section_global_data, load_user_group) },
  [CNTSGLOB_unhandled_vars] = { CNTSGLOB_unhandled_vars, 's', XSIZE(struct section_global_data, unhandled_vars), "unhandled_vars", XOFFSET(struct section_global_data, unhandled_vars) },
  [CNTSGLOB_disable_prob_long_name] = { CNTSGLOB_disable_prob_long_name, 'B', XSIZE(struct section_global_data, disable_prob_long_name), NULL, XOFFSET(struct section_global_data, disable_prob_long_name) },
  [CNTSGLOB_disable_passed_tests] = { CNTSGLOB_disable_passed_tests, 'B', XSIZE(struct section_global_data, disable_passed_tests), NULL, XOFFSET(struct section_global_data, disable_passed_tests) },
};

int cntsglob_get_type(int tag)
{
  ASSERT(tag > 0 && tag < CNTSGLOB_LAST_FIELD);
  return meta_info_section_global_data_data[tag].type;
}

size_t cntsglob_get_size(int tag)
{
  ASSERT(tag > 0 && tag < CNTSGLOB_LAST_FIELD);
  return meta_info_section_global_data_data[tag].size;
}

const char *cntsglob_get_name(int tag)
{
  ASSERT(tag > 0 && tag < CNTSGLOB_LAST_FIELD);
  return meta_info_section_global_data_data[tag].name;
}

const void *cntsglob_get_ptr(const struct section_global_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTSGLOB_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_global_data_data[tag].offset);
}

void *cntsglob_get_ptr_nc(struct section_global_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTSGLOB_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_global_data_data[tag].offset);
}

int cntsglob_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_section_global_data_data, CNTSGLOB_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods cntsglob_methods =
{
  CNTSGLOB_LAST_FIELD,
  sizeof(struct section_global_data),
  cntsglob_get_type,
  cntsglob_get_size,
  cntsglob_get_name,
  (const void *(*)(const void *ptr, int tag))cntsglob_get_ptr,
  (void *(*)(void *ptr, int tag))cntsglob_get_ptr_nc,
  cntsglob_lookup_field,
};

static struct meta_info_item meta_info_section_problem_data_data[] =
{
  [CNTSPROB_id] = { CNTSPROB_id, 'i', XSIZE(struct section_problem_data, id), "id", XOFFSET(struct section_problem_data, id) },
  [CNTSPROB_tester_id] = { CNTSPROB_tester_id, 'i', XSIZE(struct section_problem_data, tester_id), "tester_id", XOFFSET(struct section_problem_data, tester_id) },
  [CNTSPROB_abstract] = { CNTSPROB_abstract, 'B', XSIZE(struct section_problem_data, abstract), "abstract", XOFFSET(struct section_problem_data, abstract) },
  [CNTSPROB_type] = { CNTSPROB_type, 'i', XSIZE(struct section_problem_data, type), "type", XOFFSET(struct section_problem_data, type) },
  [CNTSPROB_manual_checking] = { CNTSPROB_manual_checking, 'B', XSIZE(struct section_problem_data, manual_checking), "manual_checking", XOFFSET(struct section_problem_data, manual_checking) },
  [CNTSPROB_examinator_num] = { CNTSPROB_examinator_num, 'i', XSIZE(struct section_problem_data, examinator_num), "examinator_num", XOFFSET(struct section_problem_data, examinator_num) },
  [CNTSPROB_check_presentation] = { CNTSPROB_check_presentation, 'B', XSIZE(struct section_problem_data, check_presentation), "check_presentation", XOFFSET(struct section_problem_data, check_presentation) },
  [CNTSPROB_scoring_checker] = { CNTSPROB_scoring_checker, 'B', XSIZE(struct section_problem_data, scoring_checker), "scoring_checker", XOFFSET(struct section_problem_data, scoring_checker) },
  [CNTSPROB_interactive_valuer] = { CNTSPROB_interactive_valuer, 'B', XSIZE(struct section_problem_data, interactive_valuer), "interactive_valuer", XOFFSET(struct section_problem_data, interactive_valuer) },
  [CNTSPROB_disable_pe] = { CNTSPROB_disable_pe, 'B', XSIZE(struct section_problem_data, disable_pe), "disable_pe", XOFFSET(struct section_problem_data, disable_pe) },
  [CNTSPROB_disable_wtl] = { CNTSPROB_disable_wtl, 'B', XSIZE(struct section_problem_data, disable_wtl), "disable_wtl", XOFFSET(struct section_problem_data, disable_wtl) },
  [CNTSPROB_use_stdin] = { CNTSPROB_use_stdin, 'B', XSIZE(struct section_problem_data, use_stdin), "use_stdin", XOFFSET(struct section_problem_data, use_stdin) },
  [CNTSPROB_use_stdout] = { CNTSPROB_use_stdout, 'B', XSIZE(struct section_problem_data, use_stdout), "use_stdout", XOFFSET(struct section_problem_data, use_stdout) },
  [CNTSPROB_combined_stdin] = { CNTSPROB_combined_stdin, 'B', XSIZE(struct section_problem_data, combined_stdin), "combined_stdin", XOFFSET(struct section_problem_data, combined_stdin) },
  [CNTSPROB_combined_stdout] = { CNTSPROB_combined_stdout, 'B', XSIZE(struct section_problem_data, combined_stdout), "combined_stdout", XOFFSET(struct section_problem_data, combined_stdout) },
  [CNTSPROB_binary_input] = { CNTSPROB_binary_input, 'B', XSIZE(struct section_problem_data, binary_input), "binary_input", XOFFSET(struct section_problem_data, binary_input) },
  [CNTSPROB_binary] = { CNTSPROB_binary, 'B', XSIZE(struct section_problem_data, binary), "binary", XOFFSET(struct section_problem_data, binary) },
  [CNTSPROB_ignore_exit_code] = { CNTSPROB_ignore_exit_code, 'B', XSIZE(struct section_problem_data, ignore_exit_code), "ignore_exit_code", XOFFSET(struct section_problem_data, ignore_exit_code) },
  [CNTSPROB_olympiad_mode] = { CNTSPROB_olympiad_mode, 'B', XSIZE(struct section_problem_data, olympiad_mode), "olympiad_mode", XOFFSET(struct section_problem_data, olympiad_mode) },
  [CNTSPROB_score_latest] = { CNTSPROB_score_latest, 'B', XSIZE(struct section_problem_data, score_latest), "score_latest", XOFFSET(struct section_problem_data, score_latest) },
  [CNTSPROB_score_latest_or_unmarked] = { CNTSPROB_score_latest_or_unmarked, 'B', XSIZE(struct section_problem_data, score_latest_or_unmarked), "score_latest_or_unmarked", XOFFSET(struct section_problem_data, score_latest_or_unmarked) },
  [CNTSPROB_score_latest_marked] = { CNTSPROB_score_latest_marked, 'B', XSIZE(struct section_problem_data, score_latest_marked), "score_latest_marked", XOFFSET(struct section_problem_data, score_latest_marked) },
  [CNTSPROB_real_time_limit] = { CNTSPROB_real_time_limit, 'i', XSIZE(struct section_problem_data, real_time_limit), "real_time_limit", XOFFSET(struct section_problem_data, real_time_limit) },
  [CNTSPROB_time_limit] = { CNTSPROB_time_limit, 'i', XSIZE(struct section_problem_data, time_limit), "time_limit", XOFFSET(struct section_problem_data, time_limit) },
  [CNTSPROB_time_limit_millis] = { CNTSPROB_time_limit_millis, 'i', XSIZE(struct section_problem_data, time_limit_millis), "time_limit_millis", XOFFSET(struct section_problem_data, time_limit_millis) },
  [CNTSPROB_use_ac_not_ok] = { CNTSPROB_use_ac_not_ok, 'B', XSIZE(struct section_problem_data, use_ac_not_ok), "use_ac_not_ok", XOFFSET(struct section_problem_data, use_ac_not_ok) },
  [CNTSPROB_ignore_prev_ac] = { CNTSPROB_ignore_prev_ac, 'B', XSIZE(struct section_problem_data, ignore_prev_ac), "ignore_prev_ac", XOFFSET(struct section_problem_data, ignore_prev_ac) },
  [CNTSPROB_team_enable_rep_view] = { CNTSPROB_team_enable_rep_view, 'B', XSIZE(struct section_problem_data, team_enable_rep_view), "team_enable_rep_view", XOFFSET(struct section_problem_data, team_enable_rep_view) },
  [CNTSPROB_team_enable_ce_view] = { CNTSPROB_team_enable_ce_view, 'B', XSIZE(struct section_problem_data, team_enable_ce_view), "team_enable_ce_view", XOFFSET(struct section_problem_data, team_enable_ce_view) },
  [CNTSPROB_team_show_judge_report] = { CNTSPROB_team_show_judge_report, 'B', XSIZE(struct section_problem_data, team_show_judge_report), "team_show_judge_report", XOFFSET(struct section_problem_data, team_show_judge_report) },
  [CNTSPROB_show_checker_comment] = { CNTSPROB_show_checker_comment, 'B', XSIZE(struct section_problem_data, show_checker_comment), "show_checker_comment", XOFFSET(struct section_problem_data, show_checker_comment) },
  [CNTSPROB_ignore_compile_errors] = { CNTSPROB_ignore_compile_errors, 'B', XSIZE(struct section_problem_data, ignore_compile_errors), "ignore_compile_errors", XOFFSET(struct section_problem_data, ignore_compile_errors) },
  [CNTSPROB_full_score] = { CNTSPROB_full_score, 'i', XSIZE(struct section_problem_data, full_score), "full_score", XOFFSET(struct section_problem_data, full_score) },
  [CNTSPROB_full_user_score] = { CNTSPROB_full_user_score, 'i', XSIZE(struct section_problem_data, full_user_score), "full_user_score", XOFFSET(struct section_problem_data, full_user_score) },
  [CNTSPROB_variable_full_score] = { CNTSPROB_variable_full_score, 'B', XSIZE(struct section_problem_data, variable_full_score), "variable_full_score", XOFFSET(struct section_problem_data, variable_full_score) },
  [CNTSPROB_test_score] = { CNTSPROB_test_score, 'i', XSIZE(struct section_problem_data, test_score), "test_score", XOFFSET(struct section_problem_data, test_score) },
  [CNTSPROB_run_penalty] = { CNTSPROB_run_penalty, 'i', XSIZE(struct section_problem_data, run_penalty), "run_penalty", XOFFSET(struct section_problem_data, run_penalty) },
  [CNTSPROB_acm_run_penalty] = { CNTSPROB_acm_run_penalty, 'i', XSIZE(struct section_problem_data, acm_run_penalty), "acm_run_penalty", XOFFSET(struct section_problem_data, acm_run_penalty) },
  [CNTSPROB_disqualified_penalty] = { CNTSPROB_disqualified_penalty, 'i', XSIZE(struct section_problem_data, disqualified_penalty), "disqualified_penalty", XOFFSET(struct section_problem_data, disqualified_penalty) },
  [CNTSPROB_ignore_penalty] = { CNTSPROB_ignore_penalty, 'B', XSIZE(struct section_problem_data, ignore_penalty), "ignore_penalty", XOFFSET(struct section_problem_data, ignore_penalty) },
  [CNTSPROB_use_corr] = { CNTSPROB_use_corr, 'B', XSIZE(struct section_problem_data, use_corr), "use_corr", XOFFSET(struct section_problem_data, use_corr) },
  [CNTSPROB_use_info] = { CNTSPROB_use_info, 'B', XSIZE(struct section_problem_data, use_info), "use_info", XOFFSET(struct section_problem_data, use_info) },
  [CNTSPROB_use_tgz] = { CNTSPROB_use_tgz, 'B', XSIZE(struct section_problem_data, use_tgz), "use_tgz", XOFFSET(struct section_problem_data, use_tgz) },
  [CNTSPROB_tests_to_accept] = { CNTSPROB_tests_to_accept, 'B', XSIZE(struct section_problem_data, tests_to_accept), "tests_to_accept", XOFFSET(struct section_problem_data, tests_to_accept) },
  [CNTSPROB_accept_partial] = { CNTSPROB_accept_partial, 'B', XSIZE(struct section_problem_data, accept_partial), "accept_partial", XOFFSET(struct section_problem_data, accept_partial) },
  [CNTSPROB_min_tests_to_accept] = { CNTSPROB_min_tests_to_accept, 'i', XSIZE(struct section_problem_data, min_tests_to_accept), "min_tests_to_accept", XOFFSET(struct section_problem_data, min_tests_to_accept) },
  [CNTSPROB_checker_real_time_limit] = { CNTSPROB_checker_real_time_limit, 'i', XSIZE(struct section_problem_data, checker_real_time_limit), "checker_real_time_limit", XOFFSET(struct section_problem_data, checker_real_time_limit) },
  [CNTSPROB_disable_user_submit] = { CNTSPROB_disable_user_submit, 'B', XSIZE(struct section_problem_data, disable_user_submit), "disable_user_submit", XOFFSET(struct section_problem_data, disable_user_submit) },
  [CNTSPROB_disable_tab] = { CNTSPROB_disable_tab, 'B', XSIZE(struct section_problem_data, disable_tab), "disable_tab", XOFFSET(struct section_problem_data, disable_tab) },
  [CNTSPROB_restricted_statement] = { CNTSPROB_restricted_statement, 'B', XSIZE(struct section_problem_data, restricted_statement), "restricted_statement", XOFFSET(struct section_problem_data, restricted_statement) },
  [CNTSPROB_disable_submit_after_ok] = { CNTSPROB_disable_submit_after_ok, 'B', XSIZE(struct section_problem_data, disable_submit_after_ok), "disable_submit_after_ok", XOFFSET(struct section_problem_data, disable_submit_after_ok) },
  [CNTSPROB_disable_auto_testing] = { CNTSPROB_disable_auto_testing, 'B', XSIZE(struct section_problem_data, disable_auto_testing), "disable_auto_testing", XOFFSET(struct section_problem_data, disable_auto_testing) },
  [CNTSPROB_disable_testing] = { CNTSPROB_disable_testing, 'B', XSIZE(struct section_problem_data, disable_testing), "disable_testing", XOFFSET(struct section_problem_data, disable_testing) },
  [CNTSPROB_enable_compilation] = { CNTSPROB_enable_compilation, 'B', XSIZE(struct section_problem_data, enable_compilation), "enable_compilation", XOFFSET(struct section_problem_data, enable_compilation) },
  [CNTSPROB_skip_testing] = { CNTSPROB_skip_testing, 'B', XSIZE(struct section_problem_data, skip_testing), "skip_testing", XOFFSET(struct section_problem_data, skip_testing) },
  [CNTSPROB_hidden] = { CNTSPROB_hidden, 'B', XSIZE(struct section_problem_data, hidden), "hidden", XOFFSET(struct section_problem_data, hidden) },
  [CNTSPROB_priority_adjustment] = { CNTSPROB_priority_adjustment, 'i', XSIZE(struct section_problem_data, priority_adjustment), "priority_adjustment", XOFFSET(struct section_problem_data, priority_adjustment) },
  [CNTSPROB_stand_hide_time] = { CNTSPROB_stand_hide_time, 'B', XSIZE(struct section_problem_data, stand_hide_time), "stand_hide_time", XOFFSET(struct section_problem_data, stand_hide_time) },
  [CNTSPROB_score_multiplier] = { CNTSPROB_score_multiplier, 'i', XSIZE(struct section_problem_data, score_multiplier), "score_multiplier", XOFFSET(struct section_problem_data, score_multiplier) },
  [CNTSPROB_prev_runs_to_show] = { CNTSPROB_prev_runs_to_show, 'i', XSIZE(struct section_problem_data, prev_runs_to_show), "prev_runs_to_show", XOFFSET(struct section_problem_data, prev_runs_to_show) },
  [CNTSPROB_max_user_run_count] = { CNTSPROB_max_user_run_count, 'i', XSIZE(struct section_problem_data, max_user_run_count), "max_user_run_count", XOFFSET(struct section_problem_data, max_user_run_count) },
  [CNTSPROB_advance_to_next] = { CNTSPROB_advance_to_next, 'B', XSIZE(struct section_problem_data, advance_to_next), "advance_to_next", XOFFSET(struct section_problem_data, advance_to_next) },
  [CNTSPROB_disable_ctrl_chars] = { CNTSPROB_disable_ctrl_chars, 'B', XSIZE(struct section_problem_data, disable_ctrl_chars), "disable_ctrl_chars", XOFFSET(struct section_problem_data, disable_ctrl_chars) },
  [CNTSPROB_enable_text_form] = { CNTSPROB_enable_text_form, 'B', XSIZE(struct section_problem_data, enable_text_form), "enable_text_form", XOFFSET(struct section_problem_data, enable_text_form) },
  [CNTSPROB_stand_ignore_score] = { CNTSPROB_stand_ignore_score, 'B', XSIZE(struct section_problem_data, stand_ignore_score), "stand_ignore_score", XOFFSET(struct section_problem_data, stand_ignore_score) },
  [CNTSPROB_stand_last_column] = { CNTSPROB_stand_last_column, 'B', XSIZE(struct section_problem_data, stand_last_column), "stand_last_column", XOFFSET(struct section_problem_data, stand_last_column) },
  [CNTSPROB_disable_security] = { CNTSPROB_disable_security, 'B', XSIZE(struct section_problem_data, disable_security), "disable_security", XOFFSET(struct section_problem_data, disable_security) },
  [CNTSPROB_super] = { CNTSPROB_super, 'S', XSIZE(struct section_problem_data, super), "super", XOFFSET(struct section_problem_data, super) },
  [CNTSPROB_short_name] = { CNTSPROB_short_name, 'S', XSIZE(struct section_problem_data, short_name), "short_name", XOFFSET(struct section_problem_data, short_name) },
  [CNTSPROB_long_name] = { CNTSPROB_long_name, 'S', XSIZE(struct section_problem_data, long_name), "long_name", XOFFSET(struct section_problem_data, long_name) },
  [CNTSPROB_stand_name] = { CNTSPROB_stand_name, 'S', XSIZE(struct section_problem_data, stand_name), "stand_name", XOFFSET(struct section_problem_data, stand_name) },
  [CNTSPROB_stand_column] = { CNTSPROB_stand_column, 'S', XSIZE(struct section_problem_data, stand_column), "stand_column", XOFFSET(struct section_problem_data, stand_column) },
  [CNTSPROB_group_name] = { CNTSPROB_group_name, 'S', XSIZE(struct section_problem_data, group_name), "group_name", XOFFSET(struct section_problem_data, group_name) },
  [CNTSPROB_internal_name] = { CNTSPROB_internal_name, 'S', XSIZE(struct section_problem_data, internal_name), "internal_name", XOFFSET(struct section_problem_data, internal_name) },
  [CNTSPROB_test_dir] = { CNTSPROB_test_dir, 'S', XSIZE(struct section_problem_data, test_dir), "test_dir", XOFFSET(struct section_problem_data, test_dir) },
  [CNTSPROB_test_sfx] = { CNTSPROB_test_sfx, 'S', XSIZE(struct section_problem_data, test_sfx), "test_sfx", XOFFSET(struct section_problem_data, test_sfx) },
  [CNTSPROB_corr_dir] = { CNTSPROB_corr_dir, 'S', XSIZE(struct section_problem_data, corr_dir), "corr_dir", XOFFSET(struct section_problem_data, corr_dir) },
  [CNTSPROB_corr_sfx] = { CNTSPROB_corr_sfx, 'S', XSIZE(struct section_problem_data, corr_sfx), "corr_sfx", XOFFSET(struct section_problem_data, corr_sfx) },
  [CNTSPROB_info_dir] = { CNTSPROB_info_dir, 'S', XSIZE(struct section_problem_data, info_dir), "info_dir", XOFFSET(struct section_problem_data, info_dir) },
  [CNTSPROB_info_sfx] = { CNTSPROB_info_sfx, 'S', XSIZE(struct section_problem_data, info_sfx), "info_sfx", XOFFSET(struct section_problem_data, info_sfx) },
  [CNTSPROB_tgz_dir] = { CNTSPROB_tgz_dir, 'S', XSIZE(struct section_problem_data, tgz_dir), "tgz_dir", XOFFSET(struct section_problem_data, tgz_dir) },
  [CNTSPROB_tgz_sfx] = { CNTSPROB_tgz_sfx, 'S', XSIZE(struct section_problem_data, tgz_sfx), "tgz_sfx", XOFFSET(struct section_problem_data, tgz_sfx) },
  [CNTSPROB_tgzdir_sfx] = { CNTSPROB_tgzdir_sfx, 'S', XSIZE(struct section_problem_data, tgzdir_sfx), "tgzdir_sfx", XOFFSET(struct section_problem_data, tgzdir_sfx) },
  [CNTSPROB_input_file] = { CNTSPROB_input_file, 'S', XSIZE(struct section_problem_data, input_file), "input_file", XOFFSET(struct section_problem_data, input_file) },
  [CNTSPROB_output_file] = { CNTSPROB_output_file, 'S', XSIZE(struct section_problem_data, output_file), "output_file", XOFFSET(struct section_problem_data, output_file) },
  [CNTSPROB_test_score_list] = { CNTSPROB_test_score_list, 's', XSIZE(struct section_problem_data, test_score_list), "test_score_list", XOFFSET(struct section_problem_data, test_score_list) },
  [CNTSPROB_score_tests] = { CNTSPROB_score_tests, 'S', XSIZE(struct section_problem_data, score_tests), "score_tests", XOFFSET(struct section_problem_data, score_tests) },
  [CNTSPROB_standard_checker] = { CNTSPROB_standard_checker, 'S', XSIZE(struct section_problem_data, standard_checker), "standard_checker", XOFFSET(struct section_problem_data, standard_checker) },
  [CNTSPROB_spelling] = { CNTSPROB_spelling, 'S', XSIZE(struct section_problem_data, spelling), "spelling", XOFFSET(struct section_problem_data, spelling) },
  [CNTSPROB_statement_file] = { CNTSPROB_statement_file, 'S', XSIZE(struct section_problem_data, statement_file), "statement_file", XOFFSET(struct section_problem_data, statement_file) },
  [CNTSPROB_alternatives_file] = { CNTSPROB_alternatives_file, 'S', XSIZE(struct section_problem_data, alternatives_file), "alternatives_file", XOFFSET(struct section_problem_data, alternatives_file) },
  [CNTSPROB_plugin_file] = { CNTSPROB_plugin_file, 'S', XSIZE(struct section_problem_data, plugin_file), "plugin_file", XOFFSET(struct section_problem_data, plugin_file) },
  [CNTSPROB_xml_file] = { CNTSPROB_xml_file, 'S', XSIZE(struct section_problem_data, xml_file), "xml_file", XOFFSET(struct section_problem_data, xml_file) },
  [CNTSPROB_stand_attr] = { CNTSPROB_stand_attr, 'S', XSIZE(struct section_problem_data, stand_attr), "stand_attr", XOFFSET(struct section_problem_data, stand_attr) },
  [CNTSPROB_source_header] = { CNTSPROB_source_header, 'S', XSIZE(struct section_problem_data, source_header), "source_header", XOFFSET(struct section_problem_data, source_header) },
  [CNTSPROB_source_footer] = { CNTSPROB_source_footer, 'S', XSIZE(struct section_problem_data, source_footer), "source_footer", XOFFSET(struct section_problem_data, source_footer) },
  [CNTSPROB_valuer_sets_marked] = { CNTSPROB_valuer_sets_marked, 'B', XSIZE(struct section_problem_data, valuer_sets_marked), "valuer_sets_marked", XOFFSET(struct section_problem_data, valuer_sets_marked) },
  [CNTSPROB_ignore_unmarked] = { CNTSPROB_ignore_unmarked, 'B', XSIZE(struct section_problem_data, ignore_unmarked), "ignore_unmarked", XOFFSET(struct section_problem_data, ignore_unmarked) },
  [CNTSPROB_interactor_time_limit] = { CNTSPROB_interactor_time_limit, 'i', XSIZE(struct section_problem_data, interactor_time_limit), "interactor_time_limit", XOFFSET(struct section_problem_data, interactor_time_limit) },
  [CNTSPROB_disable_stderr] = { CNTSPROB_disable_stderr, 'B', XSIZE(struct section_problem_data, disable_stderr), "disable_stderr", XOFFSET(struct section_problem_data, disable_stderr) },
  [CNTSPROB_enable_process_group] = { CNTSPROB_enable_process_group, 'B', XSIZE(struct section_problem_data, enable_process_group), "enable_process_group", XOFFSET(struct section_problem_data, enable_process_group) },
  [CNTSPROB_test_pat] = { CNTSPROB_test_pat, 'S', XSIZE(struct section_problem_data, test_pat), "test_pat", XOFFSET(struct section_problem_data, test_pat) },
  [CNTSPROB_corr_pat] = { CNTSPROB_corr_pat, 'S', XSIZE(struct section_problem_data, corr_pat), "corr_pat", XOFFSET(struct section_problem_data, corr_pat) },
  [CNTSPROB_info_pat] = { CNTSPROB_info_pat, 'S', XSIZE(struct section_problem_data, info_pat), "info_pat", XOFFSET(struct section_problem_data, info_pat) },
  [CNTSPROB_tgz_pat] = { CNTSPROB_tgz_pat, 'S', XSIZE(struct section_problem_data, tgz_pat), "tgz_pat", XOFFSET(struct section_problem_data, tgz_pat) },
  [CNTSPROB_tgzdir_pat] = { CNTSPROB_tgzdir_pat, 'S', XSIZE(struct section_problem_data, tgzdir_pat), "tgzdir_pat", XOFFSET(struct section_problem_data, tgzdir_pat) },
  [CNTSPROB_ntests] = { CNTSPROB_ntests, 'i', XSIZE(struct section_problem_data, ntests), NULL, XOFFSET(struct section_problem_data, ntests) },
  [CNTSPROB_tscores] = { CNTSPROB_tscores, '?', XSIZE(struct section_problem_data, tscores), NULL, XOFFSET(struct section_problem_data, tscores) },
  [CNTSPROB_x_score_tests] = { CNTSPROB_x_score_tests, '?', XSIZE(struct section_problem_data, x_score_tests), NULL, XOFFSET(struct section_problem_data, x_score_tests) },
  [CNTSPROB_test_sets] = { CNTSPROB_test_sets, 'x', XSIZE(struct section_problem_data, test_sets), "test_sets", XOFFSET(struct section_problem_data, test_sets) },
  [CNTSPROB_ts_total] = { CNTSPROB_ts_total, 'i', XSIZE(struct section_problem_data, ts_total), NULL, XOFFSET(struct section_problem_data, ts_total) },
  [CNTSPROB_ts_infos] = { CNTSPROB_ts_infos, '?', XSIZE(struct section_problem_data, ts_infos), NULL, XOFFSET(struct section_problem_data, ts_infos) },
  [CNTSPROB_normalization] = { CNTSPROB_normalization, 'S', XSIZE(struct section_problem_data, normalization), "normalization", XOFFSET(struct section_problem_data, normalization) },
  [CNTSPROB_normalization_val] = { CNTSPROB_normalization_val, 'i', XSIZE(struct section_problem_data, normalization_val), NULL, XOFFSET(struct section_problem_data, normalization_val) },
  [CNTSPROB_deadline] = { CNTSPROB_deadline, 't', XSIZE(struct section_problem_data, deadline), "deadline", XOFFSET(struct section_problem_data, deadline) },
  [CNTSPROB_start_date] = { CNTSPROB_start_date, 't', XSIZE(struct section_problem_data, start_date), "start_date", XOFFSET(struct section_problem_data, start_date) },
  [CNTSPROB_variant_num] = { CNTSPROB_variant_num, 'i', XSIZE(struct section_problem_data, variant_num), "variant_num", XOFFSET(struct section_problem_data, variant_num) },
  [CNTSPROB_date_penalty] = { CNTSPROB_date_penalty, 'x', XSIZE(struct section_problem_data, date_penalty), "date_penalty", XOFFSET(struct section_problem_data, date_penalty) },
  [CNTSPROB_dp_total] = { CNTSPROB_dp_total, 'i', XSIZE(struct section_problem_data, dp_total), NULL, XOFFSET(struct section_problem_data, dp_total) },
  [CNTSPROB_dp_infos] = { CNTSPROB_dp_infos, '?', XSIZE(struct section_problem_data, dp_infos), NULL, XOFFSET(struct section_problem_data, dp_infos) },
  [CNTSPROB_group_start_date] = { CNTSPROB_group_start_date, 'x', XSIZE(struct section_problem_data, group_start_date), "group_start_date", XOFFSET(struct section_problem_data, group_start_date) },
  [CNTSPROB_group_deadline] = { CNTSPROB_group_deadline, 'x', XSIZE(struct section_problem_data, group_deadline), "group_deadline", XOFFSET(struct section_problem_data, group_deadline) },
  [CNTSPROB_gsd] = { CNTSPROB_gsd, '?', XSIZE(struct section_problem_data, gsd), NULL, XOFFSET(struct section_problem_data, gsd) },
  [CNTSPROB_gdl] = { CNTSPROB_gdl, '?', XSIZE(struct section_problem_data, gdl), NULL, XOFFSET(struct section_problem_data, gdl) },
  [CNTSPROB_disable_language] = { CNTSPROB_disable_language, 'x', XSIZE(struct section_problem_data, disable_language), "disable_language", XOFFSET(struct section_problem_data, disable_language) },
  [CNTSPROB_enable_language] = { CNTSPROB_enable_language, 'x', XSIZE(struct section_problem_data, enable_language), "enable_language", XOFFSET(struct section_problem_data, enable_language) },
  [CNTSPROB_require] = { CNTSPROB_require, 'x', XSIZE(struct section_problem_data, require), "require", XOFFSET(struct section_problem_data, require) },
  [CNTSPROB_provide_ok] = { CNTSPROB_provide_ok, 'x', XSIZE(struct section_problem_data, provide_ok), "provide_ok", XOFFSET(struct section_problem_data, provide_ok) },
  [CNTSPROB_lang_compiler_env] = { CNTSPROB_lang_compiler_env, 'X', XSIZE(struct section_problem_data, lang_compiler_env), "lang_compiler_env", XOFFSET(struct section_problem_data, lang_compiler_env) },
  [CNTSPROB_checker_env] = { CNTSPROB_checker_env, 'X', XSIZE(struct section_problem_data, checker_env), "checker_env", XOFFSET(struct section_problem_data, checker_env) },
  [CNTSPROB_valuer_env] = { CNTSPROB_valuer_env, 'X', XSIZE(struct section_problem_data, valuer_env), "valuer_env", XOFFSET(struct section_problem_data, valuer_env) },
  [CNTSPROB_interactor_env] = { CNTSPROB_interactor_env, 'X', XSIZE(struct section_problem_data, interactor_env), "interactor_env", XOFFSET(struct section_problem_data, interactor_env) },
  [CNTSPROB_style_checker_env] = { CNTSPROB_style_checker_env, 'X', XSIZE(struct section_problem_data, style_checker_env), "style_checker_env", XOFFSET(struct section_problem_data, style_checker_env) },
  [CNTSPROB_test_checker_env] = { CNTSPROB_test_checker_env, 'X', XSIZE(struct section_problem_data, test_checker_env), "test_checker_env", XOFFSET(struct section_problem_data, test_checker_env) },
  [CNTSPROB_init_env] = { CNTSPROB_init_env, 'X', XSIZE(struct section_problem_data, init_env), "init_env", XOFFSET(struct section_problem_data, init_env) },
  [CNTSPROB_start_env] = { CNTSPROB_start_env, 'X', XSIZE(struct section_problem_data, start_env), "start_env", XOFFSET(struct section_problem_data, start_env) },
  [CNTSPROB_check_cmd] = { CNTSPROB_check_cmd, 'S', XSIZE(struct section_problem_data, check_cmd), "check_cmd", XOFFSET(struct section_problem_data, check_cmd) },
  [CNTSPROB_valuer_cmd] = { CNTSPROB_valuer_cmd, 'S', XSIZE(struct section_problem_data, valuer_cmd), "valuer_cmd", XOFFSET(struct section_problem_data, valuer_cmd) },
  [CNTSPROB_interactor_cmd] = { CNTSPROB_interactor_cmd, 'S', XSIZE(struct section_problem_data, interactor_cmd), "interactor_cmd", XOFFSET(struct section_problem_data, interactor_cmd) },
  [CNTSPROB_style_checker_cmd] = { CNTSPROB_style_checker_cmd, 'S', XSIZE(struct section_problem_data, style_checker_cmd), "style_checker_cmd", XOFFSET(struct section_problem_data, style_checker_cmd) },
  [CNTSPROB_test_checker_cmd] = { CNTSPROB_test_checker_cmd, 's', XSIZE(struct section_problem_data, test_checker_cmd), "test_checker_cmd", XOFFSET(struct section_problem_data, test_checker_cmd) },
  [CNTSPROB_init_cmd] = { CNTSPROB_init_cmd, 's', XSIZE(struct section_problem_data, init_cmd), "init_cmd", XOFFSET(struct section_problem_data, init_cmd) },
  [CNTSPROB_solution_src] = { CNTSPROB_solution_src, 's', XSIZE(struct section_problem_data, solution_src), "solution_src", XOFFSET(struct section_problem_data, solution_src) },
  [CNTSPROB_solution_cmd] = { CNTSPROB_solution_cmd, 's', XSIZE(struct section_problem_data, solution_cmd), "solution_cmd", XOFFSET(struct section_problem_data, solution_cmd) },
  [CNTSPROB_lang_time_adj] = { CNTSPROB_lang_time_adj, 'x', XSIZE(struct section_problem_data, lang_time_adj), "lang_time_adj", XOFFSET(struct section_problem_data, lang_time_adj) },
  [CNTSPROB_lang_time_adj_millis] = { CNTSPROB_lang_time_adj_millis, 'x', XSIZE(struct section_problem_data, lang_time_adj_millis), "lang_time_adj_millis", XOFFSET(struct section_problem_data, lang_time_adj_millis) },
  [CNTSPROB_super_run_dir] = { CNTSPROB_super_run_dir, 's', XSIZE(struct section_problem_data, super_run_dir), "super_run_dir", XOFFSET(struct section_problem_data, super_run_dir) },
  [CNTSPROB_lang_max_vm_size] = { CNTSPROB_lang_max_vm_size, 'x', XSIZE(struct section_problem_data, lang_max_vm_size), "lang_max_vm_size", XOFFSET(struct section_problem_data, lang_max_vm_size) },
  [CNTSPROB_lang_max_stack_size] = { CNTSPROB_lang_max_stack_size, 'x', XSIZE(struct section_problem_data, lang_max_stack_size), "lang_max_stack_size", XOFFSET(struct section_problem_data, lang_max_stack_size) },
  [CNTSPROB_alternative] = { CNTSPROB_alternative, 'x', XSIZE(struct section_problem_data, alternative), "alternative", XOFFSET(struct section_problem_data, alternative) },
  [CNTSPROB_personal_deadline] = { CNTSPROB_personal_deadline, 'x', XSIZE(struct section_problem_data, personal_deadline), "personal_deadline", XOFFSET(struct section_problem_data, personal_deadline) },
  [CNTSPROB_pd_total] = { CNTSPROB_pd_total, 'i', XSIZE(struct section_problem_data, pd_total), NULL, XOFFSET(struct section_problem_data, pd_total) },
  [CNTSPROB_pd_infos] = { CNTSPROB_pd_infos, '?', XSIZE(struct section_problem_data, pd_infos), NULL, XOFFSET(struct section_problem_data, pd_infos) },
  [CNTSPROB_score_bonus] = { CNTSPROB_score_bonus, 'S', XSIZE(struct section_problem_data, score_bonus), "score_bonus", XOFFSET(struct section_problem_data, score_bonus) },
  [CNTSPROB_score_bonus_total] = { CNTSPROB_score_bonus_total, 'i', XSIZE(struct section_problem_data, score_bonus_total), NULL, XOFFSET(struct section_problem_data, score_bonus_total) },
  [CNTSPROB_score_bonus_val] = { CNTSPROB_score_bonus_val, '?', XSIZE(struct section_problem_data, score_bonus_val), NULL, XOFFSET(struct section_problem_data, score_bonus_val) },
  [CNTSPROB_open_tests] = { CNTSPROB_open_tests, 'S', XSIZE(struct section_problem_data, open_tests), "open_tests", XOFFSET(struct section_problem_data, open_tests) },
  [CNTSPROB_open_tests_count] = { CNTSPROB_open_tests_count, 'i', XSIZE(struct section_problem_data, open_tests_count), NULL, XOFFSET(struct section_problem_data, open_tests_count) },
  [CNTSPROB_open_tests_val] = { CNTSPROB_open_tests_val, '?', XSIZE(struct section_problem_data, open_tests_val), NULL, XOFFSET(struct section_problem_data, open_tests_val) },
  [CNTSPROB_final_open_tests] = { CNTSPROB_final_open_tests, 'S', XSIZE(struct section_problem_data, final_open_tests), "final_open_tests", XOFFSET(struct section_problem_data, final_open_tests) },
  [CNTSPROB_final_open_tests_count] = { CNTSPROB_final_open_tests_count, 'i', XSIZE(struct section_problem_data, final_open_tests_count), NULL, XOFFSET(struct section_problem_data, final_open_tests_count) },
  [CNTSPROB_final_open_tests_val] = { CNTSPROB_final_open_tests_val, '?', XSIZE(struct section_problem_data, final_open_tests_val), NULL, XOFFSET(struct section_problem_data, final_open_tests_val) },
  [CNTSPROB_max_vm_size] = { CNTSPROB_max_vm_size, 'Z', XSIZE(struct section_problem_data, max_vm_size), "max_vm_size", XOFFSET(struct section_problem_data, max_vm_size) },
  [CNTSPROB_max_data_size] = { CNTSPROB_max_data_size, 'Z', XSIZE(struct section_problem_data, max_data_size), "max_data_size", XOFFSET(struct section_problem_data, max_data_size) },
  [CNTSPROB_max_stack_size] = { CNTSPROB_max_stack_size, 'Z', XSIZE(struct section_problem_data, max_stack_size), "max_stack_size", XOFFSET(struct section_problem_data, max_stack_size) },
  [CNTSPROB_max_core_size] = { CNTSPROB_max_core_size, 'Z', XSIZE(struct section_problem_data, max_core_size), "max_core_size", XOFFSET(struct section_problem_data, max_core_size) },
  [CNTSPROB_max_file_size] = { CNTSPROB_max_file_size, 'Z', XSIZE(struct section_problem_data, max_file_size), "max_file_size", XOFFSET(struct section_problem_data, max_file_size) },
  [CNTSPROB_max_open_file_count] = { CNTSPROB_max_open_file_count, 'i', XSIZE(struct section_problem_data, max_open_file_count), "max_open_file_count", XOFFSET(struct section_problem_data, max_open_file_count) },
  [CNTSPROB_max_process_count] = { CNTSPROB_max_process_count, 'i', XSIZE(struct section_problem_data, max_process_count), "max_process_count", XOFFSET(struct section_problem_data, max_process_count) },
  [CNTSPROB_extid] = { CNTSPROB_extid, 's', XSIZE(struct section_problem_data, extid), "extid", XOFFSET(struct section_problem_data, extid) },
  [CNTSPROB_unhandled_vars] = { CNTSPROB_unhandled_vars, 's', XSIZE(struct section_problem_data, unhandled_vars), "unhandled_vars", XOFFSET(struct section_problem_data, unhandled_vars) },
  [CNTSPROB_score_view] = { CNTSPROB_score_view, 'x', XSIZE(struct section_problem_data, score_view), "score_view", XOFFSET(struct section_problem_data, score_view) },
  [CNTSPROB_score_view_score] = { CNTSPROB_score_view_score, '?', XSIZE(struct section_problem_data, score_view_score), NULL, XOFFSET(struct section_problem_data, score_view_score) },
  [CNTSPROB_score_view_text] = { CNTSPROB_score_view_text, 'x', XSIZE(struct section_problem_data, score_view_text), "score_view_text", XOFFSET(struct section_problem_data, score_view_text) },
};

int cntsprob_get_type(int tag)
{
  ASSERT(tag > 0 && tag < CNTSPROB_LAST_FIELD);
  return meta_info_section_problem_data_data[tag].type;
}

size_t cntsprob_get_size(int tag)
{
  ASSERT(tag > 0 && tag < CNTSPROB_LAST_FIELD);
  return meta_info_section_problem_data_data[tag].size;
}

const char *cntsprob_get_name(int tag)
{
  ASSERT(tag > 0 && tag < CNTSPROB_LAST_FIELD);
  return meta_info_section_problem_data_data[tag].name;
}

const void *cntsprob_get_ptr(const struct section_problem_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTSPROB_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_problem_data_data[tag].offset);
}

void *cntsprob_get_ptr_nc(struct section_problem_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTSPROB_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_problem_data_data[tag].offset);
}

int cntsprob_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_section_problem_data_data, CNTSPROB_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods cntsprob_methods =
{
  CNTSPROB_LAST_FIELD,
  sizeof(struct section_problem_data),
  cntsprob_get_type,
  cntsprob_get_size,
  cntsprob_get_name,
  (const void *(*)(const void *ptr, int tag))cntsprob_get_ptr,
  (void *(*)(void *ptr, int tag))cntsprob_get_ptr_nc,
  cntsprob_lookup_field,
};

static struct meta_info_item meta_info_section_language_data_data[] =
{
  [CNTSLANG_id] = { CNTSLANG_id, 'i', XSIZE(struct section_language_data, id), "id", XOFFSET(struct section_language_data, id) },
  [CNTSLANG_compile_id] = { CNTSLANG_compile_id, 'i', XSIZE(struct section_language_data, compile_id), "compile_id", XOFFSET(struct section_language_data, compile_id) },
  [CNTSLANG_disabled] = { CNTSLANG_disabled, 'B', XSIZE(struct section_language_data, disabled), "disabled", XOFFSET(struct section_language_data, disabled) },
  [CNTSLANG_compile_real_time_limit] = { CNTSLANG_compile_real_time_limit, 'i', XSIZE(struct section_language_data, compile_real_time_limit), "compile_real_time_limit", XOFFSET(struct section_language_data, compile_real_time_limit) },
  [CNTSLANG_binary] = { CNTSLANG_binary, 'B', XSIZE(struct section_language_data, binary), "binary", XOFFSET(struct section_language_data, binary) },
  [CNTSLANG_priority_adjustment] = { CNTSLANG_priority_adjustment, 'i', XSIZE(struct section_language_data, priority_adjustment), "priority_adjustment", XOFFSET(struct section_language_data, priority_adjustment) },
  [CNTSLANG_insecure] = { CNTSLANG_insecure, 'B', XSIZE(struct section_language_data, insecure), "insecure", XOFFSET(struct section_language_data, insecure) },
  [CNTSLANG_disable_security] = { CNTSLANG_disable_security, 'B', XSIZE(struct section_language_data, disable_security), "disable_security", XOFFSET(struct section_language_data, disable_security) },
  [CNTSLANG_is_dos] = { CNTSLANG_is_dos, 'B', XSIZE(struct section_language_data, is_dos), "is_dos", XOFFSET(struct section_language_data, is_dos) },
  [CNTSLANG_short_name] = { CNTSLANG_short_name, 'S', XSIZE(struct section_language_data, short_name), "short_name", XOFFSET(struct section_language_data, short_name) },
  [CNTSLANG_long_name] = { CNTSLANG_long_name, 'S', XSIZE(struct section_language_data, long_name), "long_name", XOFFSET(struct section_language_data, long_name) },
  [CNTSLANG_key] = { CNTSLANG_key, 'S', XSIZE(struct section_language_data, key), "key", XOFFSET(struct section_language_data, key) },
  [CNTSLANG_arch] = { CNTSLANG_arch, 'S', XSIZE(struct section_language_data, arch), "arch", XOFFSET(struct section_language_data, arch) },
  [CNTSLANG_src_sfx] = { CNTSLANG_src_sfx, 'S', XSIZE(struct section_language_data, src_sfx), "src_sfx", XOFFSET(struct section_language_data, src_sfx) },
  [CNTSLANG_exe_sfx] = { CNTSLANG_exe_sfx, 'S', XSIZE(struct section_language_data, exe_sfx), "exe_sfx", XOFFSET(struct section_language_data, exe_sfx) },
  [CNTSLANG_content_type] = { CNTSLANG_content_type, 'S', XSIZE(struct section_language_data, content_type), "content_type", XOFFSET(struct section_language_data, content_type) },
  [CNTSLANG_cmd] = { CNTSLANG_cmd, 'S', XSIZE(struct section_language_data, cmd), "cmd", XOFFSET(struct section_language_data, cmd) },
  [CNTSLANG_style_checker_cmd] = { CNTSLANG_style_checker_cmd, 'S', XSIZE(struct section_language_data, style_checker_cmd), "style_checker_cmd", XOFFSET(struct section_language_data, style_checker_cmd) },
  [CNTSLANG_style_checker_env] = { CNTSLANG_style_checker_env, 'X', XSIZE(struct section_language_data, style_checker_env), "style_checker_env", XOFFSET(struct section_language_data, style_checker_env) },
  [CNTSLANG_extid] = { CNTSLANG_extid, 's', XSIZE(struct section_language_data, extid), "extid", XOFFSET(struct section_language_data, extid) },
  [CNTSLANG_super_run_dir] = { CNTSLANG_super_run_dir, 's', XSIZE(struct section_language_data, super_run_dir), "super_run_dir", XOFFSET(struct section_language_data, super_run_dir) },
  [CNTSLANG_disable_auto_testing] = { CNTSLANG_disable_auto_testing, 'B', XSIZE(struct section_language_data, disable_auto_testing), "disable_auto_testing", XOFFSET(struct section_language_data, disable_auto_testing) },
  [CNTSLANG_disable_testing] = { CNTSLANG_disable_testing, 'B', XSIZE(struct section_language_data, disable_testing), "disable_testing", XOFFSET(struct section_language_data, disable_testing) },
  [CNTSLANG_max_vm_size] = { CNTSLANG_max_vm_size, 'Z', XSIZE(struct section_language_data, max_vm_size), "max_vm_size", XOFFSET(struct section_language_data, max_vm_size) },
  [CNTSLANG_max_stack_size] = { CNTSLANG_max_stack_size, 'Z', XSIZE(struct section_language_data, max_stack_size), "max_stack_size", XOFFSET(struct section_language_data, max_stack_size) },
  [CNTSLANG_max_file_size] = { CNTSLANG_max_file_size, 'Z', XSIZE(struct section_language_data, max_file_size), "max_file_size", XOFFSET(struct section_language_data, max_file_size) },
  [CNTSLANG_compile_dir_index] = { CNTSLANG_compile_dir_index, 'i', XSIZE(struct section_language_data, compile_dir_index), "compile_dir_index", XOFFSET(struct section_language_data, compile_dir_index) },
  [CNTSLANG_compile_dir] = { CNTSLANG_compile_dir, 'S', XSIZE(struct section_language_data, compile_dir), "compile_dir", XOFFSET(struct section_language_data, compile_dir) },
  [CNTSLANG_compile_queue_dir] = { CNTSLANG_compile_queue_dir, 'S', XSIZE(struct section_language_data, compile_queue_dir), "compile_queue_dir", XOFFSET(struct section_language_data, compile_queue_dir) },
  [CNTSLANG_compile_src_dir] = { CNTSLANG_compile_src_dir, 'S', XSIZE(struct section_language_data, compile_src_dir), "compile_src_dir", XOFFSET(struct section_language_data, compile_src_dir) },
  [CNTSLANG_compile_out_dir] = { CNTSLANG_compile_out_dir, 'S', XSIZE(struct section_language_data, compile_out_dir), "compile_out_dir", XOFFSET(struct section_language_data, compile_out_dir) },
  [CNTSLANG_compile_status_dir] = { CNTSLANG_compile_status_dir, 'S', XSIZE(struct section_language_data, compile_status_dir), "compile_status_dir", XOFFSET(struct section_language_data, compile_status_dir) },
  [CNTSLANG_compile_report_dir] = { CNTSLANG_compile_report_dir, 'S', XSIZE(struct section_language_data, compile_report_dir), "compile_report_dir", XOFFSET(struct section_language_data, compile_report_dir) },
  [CNTSLANG_compiler_env] = { CNTSLANG_compiler_env, 'X', XSIZE(struct section_language_data, compiler_env), "compiler_env", XOFFSET(struct section_language_data, compiler_env) },
  [CNTSLANG_unhandled_vars] = { CNTSLANG_unhandled_vars, 's', XSIZE(struct section_language_data, unhandled_vars), "unhandled_vars", XOFFSET(struct section_language_data, unhandled_vars) },
  [CNTSLANG_disabled_by_config] = { CNTSLANG_disabled_by_config, 'i', XSIZE(struct section_language_data, disabled_by_config), NULL, XOFFSET(struct section_language_data, disabled_by_config) },
};

int cntslang_get_type(int tag)
{
  ASSERT(tag > 0 && tag < CNTSLANG_LAST_FIELD);
  return meta_info_section_language_data_data[tag].type;
}

size_t cntslang_get_size(int tag)
{
  ASSERT(tag > 0 && tag < CNTSLANG_LAST_FIELD);
  return meta_info_section_language_data_data[tag].size;
}

const char *cntslang_get_name(int tag)
{
  ASSERT(tag > 0 && tag < CNTSLANG_LAST_FIELD);
  return meta_info_section_language_data_data[tag].name;
}

const void *cntslang_get_ptr(const struct section_language_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTSLANG_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_language_data_data[tag].offset);
}

void *cntslang_get_ptr_nc(struct section_language_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTSLANG_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_language_data_data[tag].offset);
}

int cntslang_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_section_language_data_data, CNTSLANG_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods cntslang_methods =
{
  CNTSLANG_LAST_FIELD,
  sizeof(struct section_language_data),
  cntslang_get_type,
  cntslang_get_size,
  cntslang_get_name,
  (const void *(*)(const void *ptr, int tag))cntslang_get_ptr,
  (void *(*)(void *ptr, int tag))cntslang_get_ptr_nc,
  cntslang_lookup_field,
};

static struct meta_info_item meta_info_section_tester_data_data[] =
{
  [CNTSTESTER_id] = { CNTSTESTER_id, 'i', XSIZE(struct section_tester_data, id), "id", XOFFSET(struct section_tester_data, id) },
  [CNTSTESTER_name] = { CNTSTESTER_name, 'S', XSIZE(struct section_tester_data, name), "name", XOFFSET(struct section_tester_data, name) },
  [CNTSTESTER_problem] = { CNTSTESTER_problem, 'i', XSIZE(struct section_tester_data, problem), "problem", XOFFSET(struct section_tester_data, problem) },
  [CNTSTESTER_problem_name] = { CNTSTESTER_problem_name, 'S', XSIZE(struct section_tester_data, problem_name), "problem_name", XOFFSET(struct section_tester_data, problem_name) },
  [CNTSTESTER_any] = { CNTSTESTER_any, 'B', XSIZE(struct section_tester_data, any), "any", XOFFSET(struct section_tester_data, any) },
  [CNTSTESTER_is_dos] = { CNTSTESTER_is_dos, 'B', XSIZE(struct section_tester_data, is_dos), "is_dos", XOFFSET(struct section_tester_data, is_dos) },
  [CNTSTESTER_no_redirect] = { CNTSTESTER_no_redirect, 'B', XSIZE(struct section_tester_data, no_redirect), "no_redirect", XOFFSET(struct section_tester_data, no_redirect) },
  [CNTSTESTER_priority_adjustment] = { CNTSTESTER_priority_adjustment, 'i', XSIZE(struct section_tester_data, priority_adjustment), "priority_adjustment", XOFFSET(struct section_tester_data, priority_adjustment) },
  [CNTSTESTER_ignore_stderr] = { CNTSTESTER_ignore_stderr, 'B', XSIZE(struct section_tester_data, ignore_stderr), "ignore_stderr", XOFFSET(struct section_tester_data, ignore_stderr) },
  [CNTSTESTER_arch] = { CNTSTESTER_arch, 'S', XSIZE(struct section_tester_data, arch), "arch", XOFFSET(struct section_tester_data, arch) },
  [CNTSTESTER_key] = { CNTSTESTER_key, 'S', XSIZE(struct section_tester_data, key), "key", XOFFSET(struct section_tester_data, key) },
  [CNTSTESTER_memory_limit_type] = { CNTSTESTER_memory_limit_type, 'S', XSIZE(struct section_tester_data, memory_limit_type), "memory_limit_type", XOFFSET(struct section_tester_data, memory_limit_type) },
  [CNTSTESTER_secure_exec_type] = { CNTSTESTER_secure_exec_type, 'S', XSIZE(struct section_tester_data, secure_exec_type), "secure_exec_type", XOFFSET(struct section_tester_data, secure_exec_type) },
  [CNTSTESTER_abstract] = { CNTSTESTER_abstract, 'B', XSIZE(struct section_tester_data, abstract), "abstract", XOFFSET(struct section_tester_data, abstract) },
  [CNTSTESTER_super] = { CNTSTESTER_super, 'x', XSIZE(struct section_tester_data, super), "super", XOFFSET(struct section_tester_data, super) },
  [CNTSTESTER_is_processed] = { CNTSTESTER_is_processed, 'B', XSIZE(struct section_tester_data, is_processed), NULL, XOFFSET(struct section_tester_data, is_processed) },
  [CNTSTESTER_skip_testing] = { CNTSTESTER_skip_testing, 'B', XSIZE(struct section_tester_data, skip_testing), "skip_testing", XOFFSET(struct section_tester_data, skip_testing) },
  [CNTSTESTER_no_core_dump] = { CNTSTESTER_no_core_dump, 'B', XSIZE(struct section_tester_data, no_core_dump), "no_core_dump", XOFFSET(struct section_tester_data, no_core_dump) },
  [CNTSTESTER_enable_memory_limit_error] = { CNTSTESTER_enable_memory_limit_error, 'B', XSIZE(struct section_tester_data, enable_memory_limit_error), "enable_memory_limit_error", XOFFSET(struct section_tester_data, enable_memory_limit_error) },
  [CNTSTESTER_kill_signal] = { CNTSTESTER_kill_signal, 'S', XSIZE(struct section_tester_data, kill_signal), "kill_signal", XOFFSET(struct section_tester_data, kill_signal) },
  [CNTSTESTER_max_stack_size] = { CNTSTESTER_max_stack_size, 'Z', XSIZE(struct section_tester_data, max_stack_size), "max_stack_size", XOFFSET(struct section_tester_data, max_stack_size) },
  [CNTSTESTER_max_data_size] = { CNTSTESTER_max_data_size, 'Z', XSIZE(struct section_tester_data, max_data_size), "max_data_size", XOFFSET(struct section_tester_data, max_data_size) },
  [CNTSTESTER_max_vm_size] = { CNTSTESTER_max_vm_size, 'Z', XSIZE(struct section_tester_data, max_vm_size), "max_vm_size", XOFFSET(struct section_tester_data, max_vm_size) },
  [CNTSTESTER_clear_env] = { CNTSTESTER_clear_env, 'B', XSIZE(struct section_tester_data, clear_env), "clear_env", XOFFSET(struct section_tester_data, clear_env) },
  [CNTSTESTER_time_limit_adjustment] = { CNTSTESTER_time_limit_adjustment, 'i', XSIZE(struct section_tester_data, time_limit_adjustment), "time_limit_adjustment", XOFFSET(struct section_tester_data, time_limit_adjustment) },
  [CNTSTESTER_time_limit_adj_millis] = { CNTSTESTER_time_limit_adj_millis, 'i', XSIZE(struct section_tester_data, time_limit_adj_millis), "time_limit_adj_millis", XOFFSET(struct section_tester_data, time_limit_adj_millis) },
  [CNTSTESTER_run_dir] = { CNTSTESTER_run_dir, 'S', XSIZE(struct section_tester_data, run_dir), "run_dir", XOFFSET(struct section_tester_data, run_dir) },
  [CNTSTESTER_run_queue_dir] = { CNTSTESTER_run_queue_dir, 'S', XSIZE(struct section_tester_data, run_queue_dir), "run_queue_dir", XOFFSET(struct section_tester_data, run_queue_dir) },
  [CNTSTESTER_run_exe_dir] = { CNTSTESTER_run_exe_dir, 'S', XSIZE(struct section_tester_data, run_exe_dir), "run_exe_dir", XOFFSET(struct section_tester_data, run_exe_dir) },
  [CNTSTESTER_run_out_dir] = { CNTSTESTER_run_out_dir, 'S', XSIZE(struct section_tester_data, run_out_dir), "run_out_dir", XOFFSET(struct section_tester_data, run_out_dir) },
  [CNTSTESTER_run_status_dir] = { CNTSTESTER_run_status_dir, 'S', XSIZE(struct section_tester_data, run_status_dir), "run_status_dir", XOFFSET(struct section_tester_data, run_status_dir) },
  [CNTSTESTER_run_report_dir] = { CNTSTESTER_run_report_dir, 'S', XSIZE(struct section_tester_data, run_report_dir), "run_report_dir", XOFFSET(struct section_tester_data, run_report_dir) },
  [CNTSTESTER_run_team_report_dir] = { CNTSTESTER_run_team_report_dir, 'S', XSIZE(struct section_tester_data, run_team_report_dir), "run_team_report_dir", XOFFSET(struct section_tester_data, run_team_report_dir) },
  [CNTSTESTER_run_full_archive_dir] = { CNTSTESTER_run_full_archive_dir, 'S', XSIZE(struct section_tester_data, run_full_archive_dir), "run_full_archive_dir", XOFFSET(struct section_tester_data, run_full_archive_dir) },
  [CNTSTESTER_check_dir] = { CNTSTESTER_check_dir, 'S', XSIZE(struct section_tester_data, check_dir), "check_dir", XOFFSET(struct section_tester_data, check_dir) },
  [CNTSTESTER_errorcode_file] = { CNTSTESTER_errorcode_file, 'S', XSIZE(struct section_tester_data, errorcode_file), "errorcode_file", XOFFSET(struct section_tester_data, errorcode_file) },
  [CNTSTESTER_error_file] = { CNTSTESTER_error_file, 'S', XSIZE(struct section_tester_data, error_file), "error_file", XOFFSET(struct section_tester_data, error_file) },
  [CNTSTESTER_prepare_cmd] = { CNTSTESTER_prepare_cmd, 'S', XSIZE(struct section_tester_data, prepare_cmd), "prepare_cmd", XOFFSET(struct section_tester_data, prepare_cmd) },
  [CNTSTESTER_start_cmd] = { CNTSTESTER_start_cmd, 'S', XSIZE(struct section_tester_data, start_cmd), "start_cmd", XOFFSET(struct section_tester_data, start_cmd) },
  [CNTSTESTER_nwrun_spool_dir] = { CNTSTESTER_nwrun_spool_dir, 'S', XSIZE(struct section_tester_data, nwrun_spool_dir), "nwrun_spool_dir", XOFFSET(struct section_tester_data, nwrun_spool_dir) },
  [CNTSTESTER_start_env] = { CNTSTESTER_start_env, 'X', XSIZE(struct section_tester_data, start_env), "start_env", XOFFSET(struct section_tester_data, start_env) },
  [CNTSTESTER_memory_limit_type_val] = { CNTSTESTER_memory_limit_type_val, 'i', XSIZE(struct section_tester_data, memory_limit_type_val), NULL, XOFFSET(struct section_tester_data, memory_limit_type_val) },
  [CNTSTESTER_secure_exec_type_val] = { CNTSTESTER_secure_exec_type_val, 'i', XSIZE(struct section_tester_data, secure_exec_type_val), NULL, XOFFSET(struct section_tester_data, secure_exec_type_val) },
};

int cntstester_get_type(int tag)
{
  ASSERT(tag > 0 && tag < CNTSTESTER_LAST_FIELD);
  return meta_info_section_tester_data_data[tag].type;
}

size_t cntstester_get_size(int tag)
{
  ASSERT(tag > 0 && tag < CNTSTESTER_LAST_FIELD);
  return meta_info_section_tester_data_data[tag].size;
}

const char *cntstester_get_name(int tag)
{
  ASSERT(tag > 0 && tag < CNTSTESTER_LAST_FIELD);
  return meta_info_section_tester_data_data[tag].name;
}

const void *cntstester_get_ptr(const struct section_tester_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTSTESTER_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_tester_data_data[tag].offset);
}

void *cntstester_get_ptr_nc(struct section_tester_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTSTESTER_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_tester_data_data[tag].offset);
}

int cntstester_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_section_tester_data_data, CNTSTESTER_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods cntstester_methods =
{
  CNTSTESTER_LAST_FIELD,
  sizeof(struct section_tester_data),
  cntstester_get_type,
  cntstester_get_size,
  cntstester_get_name,
  (const void *(*)(const void *ptr, int tag))cntstester_get_ptr,
  (void *(*)(void *ptr, int tag))cntstester_get_ptr_nc,
  cntstester_lookup_field,
};

