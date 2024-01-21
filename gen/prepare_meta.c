// This is an auto-generated file, do not edit

#include "ejudge/meta/prepare_meta.h"
#include "ejudge/prepare.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

#include "ejudge/parsecfg.h"

#include "ejudge/logger.h"
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
  [CNTSGLOB_require_problem_uuid] = { CNTSGLOB_require_problem_uuid, 'B', XSIZE(struct section_global_data, require_problem_uuid), "require_problem_uuid", XOFFSET(struct section_global_data, require_problem_uuid) },
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
  [CNTSGLOB_start_on_first_login] = { CNTSGLOB_start_on_first_login, 'B', XSIZE(struct section_global_data, start_on_first_login), "start_on_first_login", XOFFSET(struct section_global_data, start_on_first_login) },
  [CNTSGLOB_enable_virtual_restart] = { CNTSGLOB_enable_virtual_restart, 'B', XSIZE(struct section_global_data, enable_virtual_restart), "enable_virtual_restart", XOFFSET(struct section_global_data, enable_virtual_restart) },
  [CNTSGLOB_preserve_line_numbers] = { CNTSGLOB_preserve_line_numbers, 'B', XSIZE(struct section_global_data, preserve_line_numbers), "preserve_line_numbers", XOFFSET(struct section_global_data, preserve_line_numbers) },
  [CNTSGLOB_enable_remote_cache] = { CNTSGLOB_enable_remote_cache, 'B', XSIZE(struct section_global_data, enable_remote_cache), "enable_remote_cache", XOFFSET(struct section_global_data, enable_remote_cache) },
  [CNTSGLOB_name] = { CNTSGLOB_name, 's', XSIZE(struct section_global_data, name), "name", XOFFSET(struct section_global_data, name) },
  [CNTSGLOB_root_dir] = { CNTSGLOB_root_dir, 's', XSIZE(struct section_global_data, root_dir), "root_dir", XOFFSET(struct section_global_data, root_dir) },
  [CNTSGLOB_serve_socket] = { CNTSGLOB_serve_socket, 's', XSIZE(struct section_global_data, serve_socket), "serve_socket", XOFFSET(struct section_global_data, serve_socket) },
  [CNTSGLOB_enable_l10n] = { CNTSGLOB_enable_l10n, 'B', XSIZE(struct section_global_data, enable_l10n), "enable_l10n", XOFFSET(struct section_global_data, enable_l10n) },
  [CNTSGLOB_l10n_dir] = { CNTSGLOB_l10n_dir, 's', XSIZE(struct section_global_data, l10n_dir), "l10n_dir", XOFFSET(struct section_global_data, l10n_dir) },
  [CNTSGLOB_standings_locale] = { CNTSGLOB_standings_locale, 's', XSIZE(struct section_global_data, standings_locale), "standings_locale", XOFFSET(struct section_global_data, standings_locale) },
  [CNTSGLOB_standings_locale_id] = { CNTSGLOB_standings_locale_id, 'i', XSIZE(struct section_global_data, standings_locale_id), NULL, XOFFSET(struct section_global_data, standings_locale_id) },
  [CNTSGLOB_checker_locale] = { CNTSGLOB_checker_locale, 's', XSIZE(struct section_global_data, checker_locale), "checker_locale", XOFFSET(struct section_global_data, checker_locale) },
  [CNTSGLOB_contest_id] = { CNTSGLOB_contest_id, 'i', XSIZE(struct section_global_data, contest_id), "contest_id", XOFFSET(struct section_global_data, contest_id) },
  [CNTSGLOB_socket_path] = { CNTSGLOB_socket_path, 's', XSIZE(struct section_global_data, socket_path), "socket_path", XOFFSET(struct section_global_data, socket_path) },
  [CNTSGLOB_contests_dir] = { CNTSGLOB_contests_dir, 's', XSIZE(struct section_global_data, contests_dir), "contests_dir", XOFFSET(struct section_global_data, contests_dir) },
  [CNTSGLOB_lang_config_dir] = { CNTSGLOB_lang_config_dir, 's', XSIZE(struct section_global_data, lang_config_dir), "lang_config_dir", XOFFSET(struct section_global_data, lang_config_dir) },
  [CNTSGLOB_charset] = { CNTSGLOB_charset, 's', XSIZE(struct section_global_data, charset), "charset", XOFFSET(struct section_global_data, charset) },
  [CNTSGLOB_standings_charset] = { CNTSGLOB_standings_charset, 's', XSIZE(struct section_global_data, standings_charset), "standings_charset", XOFFSET(struct section_global_data, standings_charset) },
  [CNTSGLOB_stand2_charset] = { CNTSGLOB_stand2_charset, 's', XSIZE(struct section_global_data, stand2_charset), "stand2_charset", XOFFSET(struct section_global_data, stand2_charset) },
  [CNTSGLOB_plog_charset] = { CNTSGLOB_plog_charset, 's', XSIZE(struct section_global_data, plog_charset), "plog_charset", XOFFSET(struct section_global_data, plog_charset) },
  [CNTSGLOB_conf_dir] = { CNTSGLOB_conf_dir, 's', XSIZE(struct section_global_data, conf_dir), "conf_dir", XOFFSET(struct section_global_data, conf_dir) },
  [CNTSGLOB_problems_dir] = { CNTSGLOB_problems_dir, 's', XSIZE(struct section_global_data, problems_dir), "problems_dir", XOFFSET(struct section_global_data, problems_dir) },
  [CNTSGLOB_script_dir] = { CNTSGLOB_script_dir, 's', XSIZE(struct section_global_data, script_dir), "script_dir", XOFFSET(struct section_global_data, script_dir) },
  [CNTSGLOB_test_dir] = { CNTSGLOB_test_dir, 's', XSIZE(struct section_global_data, test_dir), "test_dir", XOFFSET(struct section_global_data, test_dir) },
  [CNTSGLOB_corr_dir] = { CNTSGLOB_corr_dir, 's', XSIZE(struct section_global_data, corr_dir), "corr_dir", XOFFSET(struct section_global_data, corr_dir) },
  [CNTSGLOB_info_dir] = { CNTSGLOB_info_dir, 's', XSIZE(struct section_global_data, info_dir), "info_dir", XOFFSET(struct section_global_data, info_dir) },
  [CNTSGLOB_tgz_dir] = { CNTSGLOB_tgz_dir, 's', XSIZE(struct section_global_data, tgz_dir), "tgz_dir", XOFFSET(struct section_global_data, tgz_dir) },
  [CNTSGLOB_checker_dir] = { CNTSGLOB_checker_dir, 's', XSIZE(struct section_global_data, checker_dir), "checker_dir", XOFFSET(struct section_global_data, checker_dir) },
  [CNTSGLOB_statement_dir] = { CNTSGLOB_statement_dir, 's', XSIZE(struct section_global_data, statement_dir), "statement_dir", XOFFSET(struct section_global_data, statement_dir) },
  [CNTSGLOB_plugin_dir] = { CNTSGLOB_plugin_dir, 's', XSIZE(struct section_global_data, plugin_dir), "plugin_dir", XOFFSET(struct section_global_data, plugin_dir) },
  [CNTSGLOB_test_sfx] = { CNTSGLOB_test_sfx, 's', XSIZE(struct section_global_data, test_sfx), "test_sfx", XOFFSET(struct section_global_data, test_sfx) },
  [CNTSGLOB_corr_sfx] = { CNTSGLOB_corr_sfx, 's', XSIZE(struct section_global_data, corr_sfx), "corr_sfx", XOFFSET(struct section_global_data, corr_sfx) },
  [CNTSGLOB_info_sfx] = { CNTSGLOB_info_sfx, 's', XSIZE(struct section_global_data, info_sfx), "info_sfx", XOFFSET(struct section_global_data, info_sfx) },
  [CNTSGLOB_tgz_sfx] = { CNTSGLOB_tgz_sfx, 's', XSIZE(struct section_global_data, tgz_sfx), "tgz_sfx", XOFFSET(struct section_global_data, tgz_sfx) },
  [CNTSGLOB_tgzdir_sfx] = { CNTSGLOB_tgzdir_sfx, 's', XSIZE(struct section_global_data, tgzdir_sfx), "tgzdir_sfx", XOFFSET(struct section_global_data, tgzdir_sfx) },
  [CNTSGLOB_ejudge_checkers_dir] = { CNTSGLOB_ejudge_checkers_dir, 's', XSIZE(struct section_global_data, ejudge_checkers_dir), "ejudge_checkers_dir", XOFFSET(struct section_global_data, ejudge_checkers_dir) },
  [CNTSGLOB_contest_start_cmd] = { CNTSGLOB_contest_start_cmd, 's', XSIZE(struct section_global_data, contest_start_cmd), "contest_start_cmd", XOFFSET(struct section_global_data, contest_start_cmd) },
  [CNTSGLOB_contest_stop_cmd] = { CNTSGLOB_contest_stop_cmd, 's', XSIZE(struct section_global_data, contest_stop_cmd), "contest_stop_cmd", XOFFSET(struct section_global_data, contest_stop_cmd) },
  [CNTSGLOB_description_file] = { CNTSGLOB_description_file, 's', XSIZE(struct section_global_data, description_file), "description_file", XOFFSET(struct section_global_data, description_file) },
  [CNTSGLOB_contest_plugin_file] = { CNTSGLOB_contest_plugin_file, 's', XSIZE(struct section_global_data, contest_plugin_file), "contest_plugin_file", XOFFSET(struct section_global_data, contest_plugin_file) },
  [CNTSGLOB_virtual_end_options] = { CNTSGLOB_virtual_end_options, 's', XSIZE(struct section_global_data, virtual_end_options), "virtual_end_options", XOFFSET(struct section_global_data, virtual_end_options) },
  [CNTSGLOB_virtual_end_info] = { CNTSGLOB_virtual_end_info, '?', XSIZE(struct section_global_data, virtual_end_info), NULL, XOFFSET(struct section_global_data, virtual_end_info) },
  [CNTSGLOB_super_run_dir] = { CNTSGLOB_super_run_dir, 's', XSIZE(struct section_global_data, super_run_dir), "super_run_dir", XOFFSET(struct section_global_data, super_run_dir) },
  [CNTSGLOB_compile_server_id] = { CNTSGLOB_compile_server_id, 's', XSIZE(struct section_global_data, compile_server_id), "compile_server_id", XOFFSET(struct section_global_data, compile_server_id) },
  [CNTSGLOB_test_pat] = { CNTSGLOB_test_pat, 's', XSIZE(struct section_global_data, test_pat), "test_pat", XOFFSET(struct section_global_data, test_pat) },
  [CNTSGLOB_corr_pat] = { CNTSGLOB_corr_pat, 's', XSIZE(struct section_global_data, corr_pat), "corr_pat", XOFFSET(struct section_global_data, corr_pat) },
  [CNTSGLOB_info_pat] = { CNTSGLOB_info_pat, 's', XSIZE(struct section_global_data, info_pat), "info_pat", XOFFSET(struct section_global_data, info_pat) },
  [CNTSGLOB_tgz_pat] = { CNTSGLOB_tgz_pat, 's', XSIZE(struct section_global_data, tgz_pat), "tgz_pat", XOFFSET(struct section_global_data, tgz_pat) },
  [CNTSGLOB_tgzdir_pat] = { CNTSGLOB_tgzdir_pat, 's', XSIZE(struct section_global_data, tgzdir_pat), "tgzdir_pat", XOFFSET(struct section_global_data, tgzdir_pat) },
  [CNTSGLOB_clardb_plugin] = { CNTSGLOB_clardb_plugin, 's', XSIZE(struct section_global_data, clardb_plugin), "clardb_plugin", XOFFSET(struct section_global_data, clardb_plugin) },
  [CNTSGLOB_rundb_plugin] = { CNTSGLOB_rundb_plugin, 's', XSIZE(struct section_global_data, rundb_plugin), "rundb_plugin", XOFFSET(struct section_global_data, rundb_plugin) },
  [CNTSGLOB_xuser_plugin] = { CNTSGLOB_xuser_plugin, 's', XSIZE(struct section_global_data, xuser_plugin), "xuser_plugin", XOFFSET(struct section_global_data, xuser_plugin) },
  [CNTSGLOB_status_plugin] = { CNTSGLOB_status_plugin, 's', XSIZE(struct section_global_data, status_plugin), "status_plugin", XOFFSET(struct section_global_data, status_plugin) },
  [CNTSGLOB_variant_plugin] = { CNTSGLOB_variant_plugin, 's', XSIZE(struct section_global_data, variant_plugin), "variant_plugin", XOFFSET(struct section_global_data, variant_plugin) },
  [CNTSGLOB_var_dir] = { CNTSGLOB_var_dir, 's', XSIZE(struct section_global_data, var_dir), "var_dir", XOFFSET(struct section_global_data, var_dir) },
  [CNTSGLOB_run_log_file] = { CNTSGLOB_run_log_file, 's', XSIZE(struct section_global_data, run_log_file), "run_log_file", XOFFSET(struct section_global_data, run_log_file) },
  [CNTSGLOB_clar_log_file] = { CNTSGLOB_clar_log_file, 's', XSIZE(struct section_global_data, clar_log_file), "clar_log_file", XOFFSET(struct section_global_data, clar_log_file) },
  [CNTSGLOB_archive_dir] = { CNTSGLOB_archive_dir, 's', XSIZE(struct section_global_data, archive_dir), "archive_dir", XOFFSET(struct section_global_data, archive_dir) },
  [CNTSGLOB_clar_archive_dir] = { CNTSGLOB_clar_archive_dir, 's', XSIZE(struct section_global_data, clar_archive_dir), "clar_archive_dir", XOFFSET(struct section_global_data, clar_archive_dir) },
  [CNTSGLOB_run_archive_dir] = { CNTSGLOB_run_archive_dir, 's', XSIZE(struct section_global_data, run_archive_dir), "run_archive_dir", XOFFSET(struct section_global_data, run_archive_dir) },
  [CNTSGLOB_report_archive_dir] = { CNTSGLOB_report_archive_dir, 's', XSIZE(struct section_global_data, report_archive_dir), "report_archive_dir", XOFFSET(struct section_global_data, report_archive_dir) },
  [CNTSGLOB_team_report_archive_dir] = { CNTSGLOB_team_report_archive_dir, 's', XSIZE(struct section_global_data, team_report_archive_dir), "team_report_archive_dir", XOFFSET(struct section_global_data, team_report_archive_dir) },
  [CNTSGLOB_xml_report_archive_dir] = { CNTSGLOB_xml_report_archive_dir, 's', XSIZE(struct section_global_data, xml_report_archive_dir), "xml_report_archive_dir", XOFFSET(struct section_global_data, xml_report_archive_dir) },
  [CNTSGLOB_full_archive_dir] = { CNTSGLOB_full_archive_dir, 's', XSIZE(struct section_global_data, full_archive_dir), "full_archive_dir", XOFFSET(struct section_global_data, full_archive_dir) },
  [CNTSGLOB_audit_log_dir] = { CNTSGLOB_audit_log_dir, 's', XSIZE(struct section_global_data, audit_log_dir), "audit_log_dir", XOFFSET(struct section_global_data, audit_log_dir) },
  [CNTSGLOB_uuid_archive_dir] = { CNTSGLOB_uuid_archive_dir, 's', XSIZE(struct section_global_data, uuid_archive_dir), "uuid_archive_dir", XOFFSET(struct section_global_data, uuid_archive_dir) },
  [CNTSGLOB_team_extra_dir] = { CNTSGLOB_team_extra_dir, 's', XSIZE(struct section_global_data, team_extra_dir), "team_extra_dir", XOFFSET(struct section_global_data, team_extra_dir) },
  [CNTSGLOB_legacy_status_dir] = { CNTSGLOB_legacy_status_dir, 's', XSIZE(struct section_global_data, legacy_status_dir), "legacy_status_dir", XOFFSET(struct section_global_data, legacy_status_dir) },
  [CNTSGLOB_work_dir] = { CNTSGLOB_work_dir, 's', XSIZE(struct section_global_data, work_dir), "work_dir", XOFFSET(struct section_global_data, work_dir) },
  [CNTSGLOB_print_work_dir] = { CNTSGLOB_print_work_dir, 's', XSIZE(struct section_global_data, print_work_dir), "print_work_dir", XOFFSET(struct section_global_data, print_work_dir) },
  [CNTSGLOB_diff_work_dir] = { CNTSGLOB_diff_work_dir, 's', XSIZE(struct section_global_data, diff_work_dir), "diff_work_dir", XOFFSET(struct section_global_data, diff_work_dir) },
  [CNTSGLOB_a2ps_path] = { CNTSGLOB_a2ps_path, 's', XSIZE(struct section_global_data, a2ps_path), "a2ps_path", XOFFSET(struct section_global_data, a2ps_path) },
  [CNTSGLOB_a2ps_args] = { CNTSGLOB_a2ps_args, 'x', XSIZE(struct section_global_data, a2ps_args), "a2ps_args", XOFFSET(struct section_global_data, a2ps_args) },
  [CNTSGLOB_lpr_path] = { CNTSGLOB_lpr_path, 's', XSIZE(struct section_global_data, lpr_path), "lpr_path", XOFFSET(struct section_global_data, lpr_path) },
  [CNTSGLOB_lpr_args] = { CNTSGLOB_lpr_args, 'x', XSIZE(struct section_global_data, lpr_args), "lpr_args", XOFFSET(struct section_global_data, lpr_args) },
  [CNTSGLOB_diff_path] = { CNTSGLOB_diff_path, 's', XSIZE(struct section_global_data, diff_path), "diff_path", XOFFSET(struct section_global_data, diff_path) },
  [CNTSGLOB_compile_dir] = { CNTSGLOB_compile_dir, 's', XSIZE(struct section_global_data, compile_dir), "compile_dir", XOFFSET(struct section_global_data, compile_dir) },
  [CNTSGLOB_compile_queue_dir] = { CNTSGLOB_compile_queue_dir, 's', XSIZE(struct section_global_data, compile_queue_dir), "compile_queue_dir", XOFFSET(struct section_global_data, compile_queue_dir) },
  [CNTSGLOB_compile_src_dir] = { CNTSGLOB_compile_src_dir, 's', XSIZE(struct section_global_data, compile_src_dir), "compile_src_dir", XOFFSET(struct section_global_data, compile_src_dir) },
  [CNTSGLOB_extra_compile_dirs] = { CNTSGLOB_extra_compile_dirs, 'x', XSIZE(struct section_global_data, extra_compile_dirs), "extra_compile_dirs", XOFFSET(struct section_global_data, extra_compile_dirs) },
  [CNTSGLOB_compile_out_dir] = { CNTSGLOB_compile_out_dir, 's', XSIZE(struct section_global_data, compile_out_dir), "compile_out_dir", XOFFSET(struct section_global_data, compile_out_dir) },
  [CNTSGLOB_compile_status_dir] = { CNTSGLOB_compile_status_dir, 's', XSIZE(struct section_global_data, compile_status_dir), "compile_status_dir", XOFFSET(struct section_global_data, compile_status_dir) },
  [CNTSGLOB_compile_report_dir] = { CNTSGLOB_compile_report_dir, 's', XSIZE(struct section_global_data, compile_report_dir), "compile_report_dir", XOFFSET(struct section_global_data, compile_report_dir) },
  [CNTSGLOB_compile_work_dir] = { CNTSGLOB_compile_work_dir, 's', XSIZE(struct section_global_data, compile_work_dir), "compile_work_dir", XOFFSET(struct section_global_data, compile_work_dir) },
  [CNTSGLOB_run_dir] = { CNTSGLOB_run_dir, 's', XSIZE(struct section_global_data, run_dir), "run_dir", XOFFSET(struct section_global_data, run_dir) },
  [CNTSGLOB_run_queue_dir] = { CNTSGLOB_run_queue_dir, 's', XSIZE(struct section_global_data, run_queue_dir), "run_queue_dir", XOFFSET(struct section_global_data, run_queue_dir) },
  [CNTSGLOB_run_exe_dir] = { CNTSGLOB_run_exe_dir, 's', XSIZE(struct section_global_data, run_exe_dir), "run_exe_dir", XOFFSET(struct section_global_data, run_exe_dir) },
  [CNTSGLOB_run_out_dir] = { CNTSGLOB_run_out_dir, 's', XSIZE(struct section_global_data, run_out_dir), "run_out_dir", XOFFSET(struct section_global_data, run_out_dir) },
  [CNTSGLOB_run_status_dir] = { CNTSGLOB_run_status_dir, 's', XSIZE(struct section_global_data, run_status_dir), "run_status_dir", XOFFSET(struct section_global_data, run_status_dir) },
  [CNTSGLOB_run_report_dir] = { CNTSGLOB_run_report_dir, 's', XSIZE(struct section_global_data, run_report_dir), "run_report_dir", XOFFSET(struct section_global_data, run_report_dir) },
  [CNTSGLOB_run_team_report_dir] = { CNTSGLOB_run_team_report_dir, 's', XSIZE(struct section_global_data, run_team_report_dir), "run_team_report_dir", XOFFSET(struct section_global_data, run_team_report_dir) },
  [CNTSGLOB_run_full_archive_dir] = { CNTSGLOB_run_full_archive_dir, 's', XSIZE(struct section_global_data, run_full_archive_dir), "run_full_archive_dir", XOFFSET(struct section_global_data, run_full_archive_dir) },
  [CNTSGLOB_run_work_dir] = { CNTSGLOB_run_work_dir, 's', XSIZE(struct section_global_data, run_work_dir), "run_work_dir", XOFFSET(struct section_global_data, run_work_dir) },
  [CNTSGLOB_run_check_dir] = { CNTSGLOB_run_check_dir, 's', XSIZE(struct section_global_data, run_check_dir), "run_check_dir", XOFFSET(struct section_global_data, run_check_dir) },
  [CNTSGLOB_htdocs_dir] = { CNTSGLOB_htdocs_dir, 's', XSIZE(struct section_global_data, htdocs_dir), "htdocs_dir", XOFFSET(struct section_global_data, htdocs_dir) },
  [CNTSGLOB_score_system] = { CNTSGLOB_score_system, 'i', XSIZE(struct section_global_data, score_system), "score_system", XOFFSET(struct section_global_data, score_system) },
  [CNTSGLOB_tests_to_accept] = { CNTSGLOB_tests_to_accept, 'i', XSIZE(struct section_global_data, tests_to_accept), "tests_to_accept", XOFFSET(struct section_global_data, tests_to_accept) },
  [CNTSGLOB_is_virtual] = { CNTSGLOB_is_virtual, 'B', XSIZE(struct section_global_data, is_virtual), "is_virtual", XOFFSET(struct section_global_data, is_virtual) },
  [CNTSGLOB_prune_empty_users] = { CNTSGLOB_prune_empty_users, 'B', XSIZE(struct section_global_data, prune_empty_users), "prune_empty_users", XOFFSET(struct section_global_data, prune_empty_users) },
  [CNTSGLOB_rounding_mode] = { CNTSGLOB_rounding_mode, 'i', XSIZE(struct section_global_data, rounding_mode), "rounding_mode", XOFFSET(struct section_global_data, rounding_mode) },
  [CNTSGLOB_max_file_length] = { CNTSGLOB_max_file_length, 'z', XSIZE(struct section_global_data, max_file_length), "max_file_length", XOFFSET(struct section_global_data, max_file_length) },
  [CNTSGLOB_max_line_length] = { CNTSGLOB_max_line_length, 'z', XSIZE(struct section_global_data, max_line_length), "max_line_length", XOFFSET(struct section_global_data, max_line_length) },
  [CNTSGLOB_max_cmd_length] = { CNTSGLOB_max_cmd_length, 'z', XSIZE(struct section_global_data, max_cmd_length), "max_cmd_length", XOFFSET(struct section_global_data, max_cmd_length) },
  [CNTSGLOB_team_info_url] = { CNTSGLOB_team_info_url, 's', XSIZE(struct section_global_data, team_info_url), "team_info_url", XOFFSET(struct section_global_data, team_info_url) },
  [CNTSGLOB_prob_info_url] = { CNTSGLOB_prob_info_url, 's', XSIZE(struct section_global_data, prob_info_url), "prob_info_url", XOFFSET(struct section_global_data, prob_info_url) },
  [CNTSGLOB_standings_file_name] = { CNTSGLOB_standings_file_name, 's', XSIZE(struct section_global_data, standings_file_name), "standings_file_name", XOFFSET(struct section_global_data, standings_file_name) },
  [CNTSGLOB_stand_header_file] = { CNTSGLOB_stand_header_file, 's', XSIZE(struct section_global_data, stand_header_file), "stand_header_file", XOFFSET(struct section_global_data, stand_header_file) },
  [CNTSGLOB_stand_footer_file] = { CNTSGLOB_stand_footer_file, 's', XSIZE(struct section_global_data, stand_footer_file), "stand_footer_file", XOFFSET(struct section_global_data, stand_footer_file) },
  [CNTSGLOB_stand_symlink_dir] = { CNTSGLOB_stand_symlink_dir, 's', XSIZE(struct section_global_data, stand_symlink_dir), "stand_symlink_dir", XOFFSET(struct section_global_data, stand_symlink_dir) },
  [CNTSGLOB_users_on_page] = { CNTSGLOB_users_on_page, 'i', XSIZE(struct section_global_data, users_on_page), "users_on_page", XOFFSET(struct section_global_data, users_on_page) },
  [CNTSGLOB_stand_file_name_2] = { CNTSGLOB_stand_file_name_2, 's', XSIZE(struct section_global_data, stand_file_name_2), "stand_file_name_2", XOFFSET(struct section_global_data, stand_file_name_2) },
  [CNTSGLOB_stand_fancy_style] = { CNTSGLOB_stand_fancy_style, 'B', XSIZE(struct section_global_data, stand_fancy_style), "stand_fancy_style", XOFFSET(struct section_global_data, stand_fancy_style) },
  [CNTSGLOB_stand_extra_format] = { CNTSGLOB_stand_extra_format, 's', XSIZE(struct section_global_data, stand_extra_format), "stand_extra_format", XOFFSET(struct section_global_data, stand_extra_format) },
  [CNTSGLOB_stand_extra_legend] = { CNTSGLOB_stand_extra_legend, 's', XSIZE(struct section_global_data, stand_extra_legend), "stand_extra_legend", XOFFSET(struct section_global_data, stand_extra_legend) },
  [CNTSGLOB_stand_extra_attr] = { CNTSGLOB_stand_extra_attr, 's', XSIZE(struct section_global_data, stand_extra_attr), "stand_extra_attr", XOFFSET(struct section_global_data, stand_extra_attr) },
  [CNTSGLOB_stand_table_attr] = { CNTSGLOB_stand_table_attr, 's', XSIZE(struct section_global_data, stand_table_attr), "stand_table_attr", XOFFSET(struct section_global_data, stand_table_attr) },
  [CNTSGLOB_stand_place_attr] = { CNTSGLOB_stand_place_attr, 's', XSIZE(struct section_global_data, stand_place_attr), "stand_place_attr", XOFFSET(struct section_global_data, stand_place_attr) },
  [CNTSGLOB_stand_team_attr] = { CNTSGLOB_stand_team_attr, 's', XSIZE(struct section_global_data, stand_team_attr), "stand_team_attr", XOFFSET(struct section_global_data, stand_team_attr) },
  [CNTSGLOB_stand_prob_attr] = { CNTSGLOB_stand_prob_attr, 's', XSIZE(struct section_global_data, stand_prob_attr), "stand_prob_attr", XOFFSET(struct section_global_data, stand_prob_attr) },
  [CNTSGLOB_stand_solved_attr] = { CNTSGLOB_stand_solved_attr, 's', XSIZE(struct section_global_data, stand_solved_attr), "stand_solved_attr", XOFFSET(struct section_global_data, stand_solved_attr) },
  [CNTSGLOB_stand_score_attr] = { CNTSGLOB_stand_score_attr, 's', XSIZE(struct section_global_data, stand_score_attr), "stand_score_attr", XOFFSET(struct section_global_data, stand_score_attr) },
  [CNTSGLOB_stand_penalty_attr] = { CNTSGLOB_stand_penalty_attr, 's', XSIZE(struct section_global_data, stand_penalty_attr), "stand_penalty_attr", XOFFSET(struct section_global_data, stand_penalty_attr) },
  [CNTSGLOB_stand_time_attr] = { CNTSGLOB_stand_time_attr, 's', XSIZE(struct section_global_data, stand_time_attr), "stand_time_attr", XOFFSET(struct section_global_data, stand_time_attr) },
  [CNTSGLOB_stand_self_row_attr] = { CNTSGLOB_stand_self_row_attr, 's', XSIZE(struct section_global_data, stand_self_row_attr), "stand_self_row_attr", XOFFSET(struct section_global_data, stand_self_row_attr) },
  [CNTSGLOB_stand_r_row_attr] = { CNTSGLOB_stand_r_row_attr, 's', XSIZE(struct section_global_data, stand_r_row_attr), "stand_r_row_attr", XOFFSET(struct section_global_data, stand_r_row_attr) },
  [CNTSGLOB_stand_v_row_attr] = { CNTSGLOB_stand_v_row_attr, 's', XSIZE(struct section_global_data, stand_v_row_attr), "stand_v_row_attr", XOFFSET(struct section_global_data, stand_v_row_attr) },
  [CNTSGLOB_stand_u_row_attr] = { CNTSGLOB_stand_u_row_attr, 's', XSIZE(struct section_global_data, stand_u_row_attr), "stand_u_row_attr", XOFFSET(struct section_global_data, stand_u_row_attr) },
  [CNTSGLOB_stand_success_attr] = { CNTSGLOB_stand_success_attr, 's', XSIZE(struct section_global_data, stand_success_attr), "stand_success_attr", XOFFSET(struct section_global_data, stand_success_attr) },
  [CNTSGLOB_stand_fail_attr] = { CNTSGLOB_stand_fail_attr, 's', XSIZE(struct section_global_data, stand_fail_attr), "stand_fail_attr", XOFFSET(struct section_global_data, stand_fail_attr) },
  [CNTSGLOB_stand_trans_attr] = { CNTSGLOB_stand_trans_attr, 's', XSIZE(struct section_global_data, stand_trans_attr), "stand_trans_attr", XOFFSET(struct section_global_data, stand_trans_attr) },
  [CNTSGLOB_stand_disq_attr] = { CNTSGLOB_stand_disq_attr, 's', XSIZE(struct section_global_data, stand_disq_attr), "stand_disq_attr", XOFFSET(struct section_global_data, stand_disq_attr) },
  [CNTSGLOB_stand_use_login] = { CNTSGLOB_stand_use_login, 'B', XSIZE(struct section_global_data, stand_use_login), "stand_use_login", XOFFSET(struct section_global_data, stand_use_login) },
  [CNTSGLOB_stand_show_avatar] = { CNTSGLOB_stand_show_avatar, 'B', XSIZE(struct section_global_data, stand_show_avatar), "stand_show_avatar", XOFFSET(struct section_global_data, stand_show_avatar) },
  [CNTSGLOB_stand_show_first_solver] = { CNTSGLOB_stand_show_first_solver, 'B', XSIZE(struct section_global_data, stand_show_first_solver), "stand_show_first_solver", XOFFSET(struct section_global_data, stand_show_first_solver) },
  [CNTSGLOB_stand_show_ok_time] = { CNTSGLOB_stand_show_ok_time, 'B', XSIZE(struct section_global_data, stand_show_ok_time), "stand_show_ok_time", XOFFSET(struct section_global_data, stand_show_ok_time) },
  [CNTSGLOB_stand_show_att_num] = { CNTSGLOB_stand_show_att_num, 'B', XSIZE(struct section_global_data, stand_show_att_num), "stand_show_att_num", XOFFSET(struct section_global_data, stand_show_att_num) },
  [CNTSGLOB_stand_sort_by_solved] = { CNTSGLOB_stand_sort_by_solved, 'B', XSIZE(struct section_global_data, stand_sort_by_solved), "stand_sort_by_solved", XOFFSET(struct section_global_data, stand_sort_by_solved) },
  [CNTSGLOB_stand_row_attr] = { CNTSGLOB_stand_row_attr, 'x', XSIZE(struct section_global_data, stand_row_attr), "stand_row_attr", XOFFSET(struct section_global_data, stand_row_attr) },
  [CNTSGLOB_stand_page_table_attr] = { CNTSGLOB_stand_page_table_attr, 's', XSIZE(struct section_global_data, stand_page_table_attr), "stand_page_table_attr", XOFFSET(struct section_global_data, stand_page_table_attr) },
  [CNTSGLOB_stand_page_row_attr] = { CNTSGLOB_stand_page_row_attr, 'x', XSIZE(struct section_global_data, stand_page_row_attr), "stand_page_row_attr", XOFFSET(struct section_global_data, stand_page_row_attr) },
  [CNTSGLOB_stand_page_col_attr] = { CNTSGLOB_stand_page_col_attr, 'x', XSIZE(struct section_global_data, stand_page_col_attr), "stand_page_col_attr", XOFFSET(struct section_global_data, stand_page_col_attr) },
  [CNTSGLOB_stand_page_cur_attr] = { CNTSGLOB_stand_page_cur_attr, 's', XSIZE(struct section_global_data, stand_page_cur_attr), "stand_page_cur_attr", XOFFSET(struct section_global_data, stand_page_cur_attr) },
  [CNTSGLOB_stand_collate_name] = { CNTSGLOB_stand_collate_name, 'B', XSIZE(struct section_global_data, stand_collate_name), "stand_collate_name", XOFFSET(struct section_global_data, stand_collate_name) },
  [CNTSGLOB_stand_enable_penalty] = { CNTSGLOB_stand_enable_penalty, 'B', XSIZE(struct section_global_data, stand_enable_penalty), "stand_enable_penalty", XOFFSET(struct section_global_data, stand_enable_penalty) },
  [CNTSGLOB_stand_header_txt] = { CNTSGLOB_stand_header_txt, 's', XSIZE(struct section_global_data, stand_header_txt), NULL, XOFFSET(struct section_global_data, stand_header_txt) },
  [CNTSGLOB_stand_footer_txt] = { CNTSGLOB_stand_footer_txt, 's', XSIZE(struct section_global_data, stand_footer_txt), NULL, XOFFSET(struct section_global_data, stand_footer_txt) },
  [CNTSGLOB_stand2_file_name] = { CNTSGLOB_stand2_file_name, 's', XSIZE(struct section_global_data, stand2_file_name), "stand2_file_name", XOFFSET(struct section_global_data, stand2_file_name) },
  [CNTSGLOB_stand2_header_file] = { CNTSGLOB_stand2_header_file, 's', XSIZE(struct section_global_data, stand2_header_file), "stand2_header_file", XOFFSET(struct section_global_data, stand2_header_file) },
  [CNTSGLOB_stand2_footer_file] = { CNTSGLOB_stand2_footer_file, 's', XSIZE(struct section_global_data, stand2_footer_file), "stand2_footer_file", XOFFSET(struct section_global_data, stand2_footer_file) },
  [CNTSGLOB_stand2_header_txt] = { CNTSGLOB_stand2_header_txt, 's', XSIZE(struct section_global_data, stand2_header_txt), NULL, XOFFSET(struct section_global_data, stand2_header_txt) },
  [CNTSGLOB_stand2_footer_txt] = { CNTSGLOB_stand2_footer_txt, 's', XSIZE(struct section_global_data, stand2_footer_txt), NULL, XOFFSET(struct section_global_data, stand2_footer_txt) },
  [CNTSGLOB_stand2_symlink_dir] = { CNTSGLOB_stand2_symlink_dir, 's', XSIZE(struct section_global_data, stand2_symlink_dir), "stand2_symlink_dir", XOFFSET(struct section_global_data, stand2_symlink_dir) },
  [CNTSGLOB_plog_file_name] = { CNTSGLOB_plog_file_name, 's', XSIZE(struct section_global_data, plog_file_name), "plog_file_name", XOFFSET(struct section_global_data, plog_file_name) },
  [CNTSGLOB_plog_header_file] = { CNTSGLOB_plog_header_file, 's', XSIZE(struct section_global_data, plog_header_file), "plog_header_file", XOFFSET(struct section_global_data, plog_header_file) },
  [CNTSGLOB_plog_footer_file] = { CNTSGLOB_plog_footer_file, 's', XSIZE(struct section_global_data, plog_footer_file), "plog_footer_file", XOFFSET(struct section_global_data, plog_footer_file) },
  [CNTSGLOB_plog_header_txt] = { CNTSGLOB_plog_header_txt, 's', XSIZE(struct section_global_data, plog_header_txt), NULL, XOFFSET(struct section_global_data, plog_header_txt) },
  [CNTSGLOB_plog_footer_txt] = { CNTSGLOB_plog_footer_txt, 's', XSIZE(struct section_global_data, plog_footer_txt), NULL, XOFFSET(struct section_global_data, plog_footer_txt) },
  [CNTSGLOB_plog_update_time] = { CNTSGLOB_plog_update_time, 'i', XSIZE(struct section_global_data, plog_update_time), "plog_update_time", XOFFSET(struct section_global_data, plog_update_time) },
  [CNTSGLOB_plog_symlink_dir] = { CNTSGLOB_plog_symlink_dir, 's', XSIZE(struct section_global_data, plog_symlink_dir), "plog_symlink_dir", XOFFSET(struct section_global_data, plog_symlink_dir) },
  [CNTSGLOB_internal_xml_update_time] = { CNTSGLOB_internal_xml_update_time, 'i', XSIZE(struct section_global_data, internal_xml_update_time), "internal_xml_update_time", XOFFSET(struct section_global_data, internal_xml_update_time) },
  [CNTSGLOB_external_xml_update_time] = { CNTSGLOB_external_xml_update_time, 'i', XSIZE(struct section_global_data, external_xml_update_time), "external_xml_update_time", XOFFSET(struct section_global_data, external_xml_update_time) },
  [CNTSGLOB_user_exam_protocol_header_file] = { CNTSGLOB_user_exam_protocol_header_file, 's', XSIZE(struct section_global_data, user_exam_protocol_header_file), "user_exam_protocol_header_file", XOFFSET(struct section_global_data, user_exam_protocol_header_file) },
  [CNTSGLOB_user_exam_protocol_footer_file] = { CNTSGLOB_user_exam_protocol_footer_file, 's', XSIZE(struct section_global_data, user_exam_protocol_footer_file), "user_exam_protocol_footer_file", XOFFSET(struct section_global_data, user_exam_protocol_footer_file) },
  [CNTSGLOB_user_exam_protocol_header_txt] = { CNTSGLOB_user_exam_protocol_header_txt, 's', XSIZE(struct section_global_data, user_exam_protocol_header_txt), NULL, XOFFSET(struct section_global_data, user_exam_protocol_header_txt) },
  [CNTSGLOB_user_exam_protocol_footer_txt] = { CNTSGLOB_user_exam_protocol_footer_txt, 's', XSIZE(struct section_global_data, user_exam_protocol_footer_txt), NULL, XOFFSET(struct section_global_data, user_exam_protocol_footer_txt) },
  [CNTSGLOB_prob_exam_protocol_header_file] = { CNTSGLOB_prob_exam_protocol_header_file, 's', XSIZE(struct section_global_data, prob_exam_protocol_header_file), "prob_exam_protocol_header_file", XOFFSET(struct section_global_data, prob_exam_protocol_header_file) },
  [CNTSGLOB_prob_exam_protocol_footer_file] = { CNTSGLOB_prob_exam_protocol_footer_file, 's', XSIZE(struct section_global_data, prob_exam_protocol_footer_file), "prob_exam_protocol_footer_file", XOFFSET(struct section_global_data, prob_exam_protocol_footer_file) },
  [CNTSGLOB_prob_exam_protocol_header_txt] = { CNTSGLOB_prob_exam_protocol_header_txt, 's', XSIZE(struct section_global_data, prob_exam_protocol_header_txt), NULL, XOFFSET(struct section_global_data, prob_exam_protocol_header_txt) },
  [CNTSGLOB_prob_exam_protocol_footer_txt] = { CNTSGLOB_prob_exam_protocol_footer_txt, 's', XSIZE(struct section_global_data, prob_exam_protocol_footer_txt), NULL, XOFFSET(struct section_global_data, prob_exam_protocol_footer_txt) },
  [CNTSGLOB_full_exam_protocol_header_file] = { CNTSGLOB_full_exam_protocol_header_file, 's', XSIZE(struct section_global_data, full_exam_protocol_header_file), "full_exam_protocol_header_file", XOFFSET(struct section_global_data, full_exam_protocol_header_file) },
  [CNTSGLOB_full_exam_protocol_footer_file] = { CNTSGLOB_full_exam_protocol_footer_file, 's', XSIZE(struct section_global_data, full_exam_protocol_footer_file), "full_exam_protocol_footer_file", XOFFSET(struct section_global_data, full_exam_protocol_footer_file) },
  [CNTSGLOB_full_exam_protocol_header_txt] = { CNTSGLOB_full_exam_protocol_header_txt, 's', XSIZE(struct section_global_data, full_exam_protocol_header_txt), NULL, XOFFSET(struct section_global_data, full_exam_protocol_header_txt) },
  [CNTSGLOB_full_exam_protocol_footer_txt] = { CNTSGLOB_full_exam_protocol_footer_txt, 's', XSIZE(struct section_global_data, full_exam_protocol_footer_txt), NULL, XOFFSET(struct section_global_data, full_exam_protocol_footer_txt) },
  [CNTSGLOB_extended_sound] = { CNTSGLOB_extended_sound, 'B', XSIZE(struct section_global_data, extended_sound), "extended_sound", XOFFSET(struct section_global_data, extended_sound) },
  [CNTSGLOB_disable_sound] = { CNTSGLOB_disable_sound, 'B', XSIZE(struct section_global_data, disable_sound), "disable_sound", XOFFSET(struct section_global_data, disable_sound) },
  [CNTSGLOB_sound_player] = { CNTSGLOB_sound_player, 's', XSIZE(struct section_global_data, sound_player), "sound_player", XOFFSET(struct section_global_data, sound_player) },
  [CNTSGLOB_accept_sound] = { CNTSGLOB_accept_sound, 's', XSIZE(struct section_global_data, accept_sound), "accept_sound", XOFFSET(struct section_global_data, accept_sound) },
  [CNTSGLOB_runtime_sound] = { CNTSGLOB_runtime_sound, 's', XSIZE(struct section_global_data, runtime_sound), "runtime_sound", XOFFSET(struct section_global_data, runtime_sound) },
  [CNTSGLOB_timelimit_sound] = { CNTSGLOB_timelimit_sound, 's', XSIZE(struct section_global_data, timelimit_sound), "timelimit_sound", XOFFSET(struct section_global_data, timelimit_sound) },
  [CNTSGLOB_presentation_sound] = { CNTSGLOB_presentation_sound, 's', XSIZE(struct section_global_data, presentation_sound), "presentation_sound", XOFFSET(struct section_global_data, presentation_sound) },
  [CNTSGLOB_wrong_sound] = { CNTSGLOB_wrong_sound, 's', XSIZE(struct section_global_data, wrong_sound), "wrong_sound", XOFFSET(struct section_global_data, wrong_sound) },
  [CNTSGLOB_internal_sound] = { CNTSGLOB_internal_sound, 's', XSIZE(struct section_global_data, internal_sound), "internal_sound", XOFFSET(struct section_global_data, internal_sound) },
  [CNTSGLOB_start_sound] = { CNTSGLOB_start_sound, 's', XSIZE(struct section_global_data, start_sound), "start_sound", XOFFSET(struct section_global_data, start_sound) },
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
  [CNTSGLOB_show_sha1] = { CNTSGLOB_show_sha1, 'B', XSIZE(struct section_global_data, show_sha1), "show_sha1", XOFFSET(struct section_global_data, show_sha1) },
  [CNTSGLOB_show_judge_identity] = { CNTSGLOB_show_judge_identity, 'B', XSIZE(struct section_global_data, show_judge_identity), "show_judge_identity", XOFFSET(struct section_global_data, show_judge_identity) },
  [CNTSGLOB_use_gzip] = { CNTSGLOB_use_gzip, 'B', XSIZE(struct section_global_data, use_gzip), "use_gzip", XOFFSET(struct section_global_data, use_gzip) },
  [CNTSGLOB_min_gzip_size] = { CNTSGLOB_min_gzip_size, 'z', XSIZE(struct section_global_data, min_gzip_size), "min_gzip_size", XOFFSET(struct section_global_data, min_gzip_size) },
  [CNTSGLOB_use_dir_hierarchy] = { CNTSGLOB_use_dir_hierarchy, 'B', XSIZE(struct section_global_data, use_dir_hierarchy), "use_dir_hierarchy", XOFFSET(struct section_global_data, use_dir_hierarchy) },
  [CNTSGLOB_html_report] = { CNTSGLOB_html_report, 'B', XSIZE(struct section_global_data, html_report), "html_report", XOFFSET(struct section_global_data, html_report) },
  [CNTSGLOB_xml_report] = { CNTSGLOB_xml_report, 'B', XSIZE(struct section_global_data, xml_report), "xml_report", XOFFSET(struct section_global_data, xml_report) },
  [CNTSGLOB_enable_full_archive] = { CNTSGLOB_enable_full_archive, 'B', XSIZE(struct section_global_data, enable_full_archive), "enable_full_archive", XOFFSET(struct section_global_data, enable_full_archive) },
  [CNTSGLOB_cpu_bogomips] = { CNTSGLOB_cpu_bogomips, 'i', XSIZE(struct section_global_data, cpu_bogomips), "cpu_bogomips", XOFFSET(struct section_global_data, cpu_bogomips) },
  [CNTSGLOB_skip_full_testing] = { CNTSGLOB_skip_full_testing, 'B', XSIZE(struct section_global_data, skip_full_testing), "skip_full_testing", XOFFSET(struct section_global_data, skip_full_testing) },
  [CNTSGLOB_skip_accept_testing] = { CNTSGLOB_skip_accept_testing, 'B', XSIZE(struct section_global_data, skip_accept_testing), "skip_accept_testing", XOFFSET(struct section_global_data, skip_accept_testing) },
  [CNTSGLOB_enable_problem_history] = { CNTSGLOB_enable_problem_history, 'B', XSIZE(struct section_global_data, enable_problem_history), "enable_problem_history", XOFFSET(struct section_global_data, enable_problem_history) },
  [CNTSGLOB_variant_map_file] = { CNTSGLOB_variant_map_file, 's', XSIZE(struct section_global_data, variant_map_file), "variant_map_file", XOFFSET(struct section_global_data, variant_map_file) },
  [CNTSGLOB_enable_printing] = { CNTSGLOB_enable_printing, 'B', XSIZE(struct section_global_data, enable_printing), "enable_printing", XOFFSET(struct section_global_data, enable_printing) },
  [CNTSGLOB_disable_banner_page] = { CNTSGLOB_disable_banner_page, 'B', XSIZE(struct section_global_data, disable_banner_page), "disable_banner_page", XOFFSET(struct section_global_data, disable_banner_page) },
  [CNTSGLOB_printout_uses_login] = { CNTSGLOB_printout_uses_login, 'B', XSIZE(struct section_global_data, printout_uses_login), "printout_uses_login", XOFFSET(struct section_global_data, printout_uses_login) },
  [CNTSGLOB_team_page_quota] = { CNTSGLOB_team_page_quota, 'i', XSIZE(struct section_global_data, team_page_quota), "team_page_quota", XOFFSET(struct section_global_data, team_page_quota) },
  [CNTSGLOB_print_just_copy] = { CNTSGLOB_print_just_copy, 'B', XSIZE(struct section_global_data, print_just_copy), "print_just_copy", XOFFSET(struct section_global_data, print_just_copy) },
  [CNTSGLOB_compile_max_vm_size] = { CNTSGLOB_compile_max_vm_size, 'E', XSIZE(struct section_global_data, compile_max_vm_size), "compile_max_vm_size", XOFFSET(struct section_global_data, compile_max_vm_size) },
  [CNTSGLOB_compile_max_stack_size] = { CNTSGLOB_compile_max_stack_size, 'E', XSIZE(struct section_global_data, compile_max_stack_size), "compile_max_stack_size", XOFFSET(struct section_global_data, compile_max_stack_size) },
  [CNTSGLOB_compile_max_file_size] = { CNTSGLOB_compile_max_file_size, 'E', XSIZE(struct section_global_data, compile_max_file_size), "compile_max_file_size", XOFFSET(struct section_global_data, compile_max_file_size) },
  [CNTSGLOB_compile_max_rss_size] = { CNTSGLOB_compile_max_rss_size, 'E', XSIZE(struct section_global_data, compile_max_rss_size), "compile_max_rss_size", XOFFSET(struct section_global_data, compile_max_rss_size) },
  [CNTSGLOB_user_priority_adjustments] = { CNTSGLOB_user_priority_adjustments, 'x', XSIZE(struct section_global_data, user_priority_adjustments), "user_priority_adjustments", XOFFSET(struct section_global_data, user_priority_adjustments) },
  [CNTSGLOB_user_adjustment_info] = { CNTSGLOB_user_adjustment_info, '?', XSIZE(struct section_global_data, user_adjustment_info), NULL, XOFFSET(struct section_global_data, user_adjustment_info) },
  [CNTSGLOB_user_adjustment_map] = { CNTSGLOB_user_adjustment_map, '?', XSIZE(struct section_global_data, user_adjustment_map), NULL, XOFFSET(struct section_global_data, user_adjustment_map) },
  [CNTSGLOB_contestant_status_num] = { CNTSGLOB_contestant_status_num, 'i', XSIZE(struct section_global_data, contestant_status_num), "contestant_status_num", XOFFSET(struct section_global_data, contestant_status_num) },
  [CNTSGLOB_contestant_status_legend] = { CNTSGLOB_contestant_status_legend, 'x', XSIZE(struct section_global_data, contestant_status_legend), "contestant_status_legend", XOFFSET(struct section_global_data, contestant_status_legend) },
  [CNTSGLOB_contestant_status_row_attr] = { CNTSGLOB_contestant_status_row_attr, 'x', XSIZE(struct section_global_data, contestant_status_row_attr), "contestant_status_row_attr", XOFFSET(struct section_global_data, contestant_status_row_attr) },
  [CNTSGLOB_stand_show_contestant_status] = { CNTSGLOB_stand_show_contestant_status, 'B', XSIZE(struct section_global_data, stand_show_contestant_status), "stand_show_contestant_status", XOFFSET(struct section_global_data, stand_show_contestant_status) },
  [CNTSGLOB_stand_show_warn_number] = { CNTSGLOB_stand_show_warn_number, 'B', XSIZE(struct section_global_data, stand_show_warn_number), "stand_show_warn_number", XOFFSET(struct section_global_data, stand_show_warn_number) },
  [CNTSGLOB_stand_contestant_status_attr] = { CNTSGLOB_stand_contestant_status_attr, 's', XSIZE(struct section_global_data, stand_contestant_status_attr), "stand_contestant_status_attr", XOFFSET(struct section_global_data, stand_contestant_status_attr) },
  [CNTSGLOB_stand_warn_number_attr] = { CNTSGLOB_stand_warn_number_attr, 's', XSIZE(struct section_global_data, stand_warn_number_attr), "stand_warn_number_attr", XOFFSET(struct section_global_data, stand_warn_number_attr) },
  [CNTSGLOB_load_user_group] = { CNTSGLOB_load_user_group, 'x', XSIZE(struct section_global_data, load_user_group), "load_user_group", XOFFSET(struct section_global_data, load_user_group) },
  [CNTSGLOB_tokens] = { CNTSGLOB_tokens, 's', XSIZE(struct section_global_data, tokens), "tokens", XOFFSET(struct section_global_data, tokens) },
  [CNTSGLOB_token_info] = { CNTSGLOB_token_info, '?', XSIZE(struct section_global_data, token_info), NULL, XOFFSET(struct section_global_data, token_info) },
  [CNTSGLOB_enable_tokens] = { CNTSGLOB_enable_tokens, 'i', XSIZE(struct section_global_data, enable_tokens), NULL, XOFFSET(struct section_global_data, enable_tokens) },
  [CNTSGLOB_dates_config_file] = { CNTSGLOB_dates_config_file, 's', XSIZE(struct section_global_data, dates_config_file), "dates_config_file", XOFFSET(struct section_global_data, dates_config_file) },
  [CNTSGLOB_dates_config] = { CNTSGLOB_dates_config, '?', XSIZE(struct section_global_data, dates_config), NULL, XOFFSET(struct section_global_data, dates_config) },
  [CNTSGLOB_unhandled_vars] = { CNTSGLOB_unhandled_vars, 's', XSIZE(struct section_global_data, unhandled_vars), "unhandled_vars", XOFFSET(struct section_global_data, unhandled_vars) },
  [CNTSGLOB_disable_prob_long_name] = { CNTSGLOB_disable_prob_long_name, 'B', XSIZE(struct section_global_data, disable_prob_long_name), NULL, XOFFSET(struct section_global_data, disable_prob_long_name) },
  [CNTSGLOB_disable_passed_tests] = { CNTSGLOB_disable_passed_tests, 'B', XSIZE(struct section_global_data, disable_passed_tests), NULL, XOFFSET(struct section_global_data, disable_passed_tests) },
  [CNTSGLOB_time_between_submits] = { CNTSGLOB_time_between_submits, 'i', XSIZE(struct section_global_data, time_between_submits), "time_between_submits", XOFFSET(struct section_global_data, time_between_submits) },
  [CNTSGLOB_max_input_size] = { CNTSGLOB_max_input_size, 'z', XSIZE(struct section_global_data, max_input_size), "max_input_size", XOFFSET(struct section_global_data, max_input_size) },
  [CNTSGLOB_max_submit_num] = { CNTSGLOB_max_submit_num, 'i', XSIZE(struct section_global_data, max_submit_num), "max_submit_num", XOFFSET(struct section_global_data, max_submit_num) },
  [CNTSGLOB_max_submit_total] = { CNTSGLOB_max_submit_total, 'z', XSIZE(struct section_global_data, max_submit_total), "max_submit_total", XOFFSET(struct section_global_data, max_submit_total) },
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

void cntsglob_copy(struct section_global_data *dst, const struct section_global_data *src)
{
  // hidden g
  dst->sleep_time = src->sleep_time;
  dst->serve_sleep_time = src->serve_sleep_time;
  dst->contest_time = src->contest_time;
  dst->max_run_size = src->max_run_size;
  dst->max_run_total = src->max_run_total;
  dst->max_run_num = src->max_run_num;
  dst->max_clar_size = src->max_clar_size;
  dst->max_clar_total = src->max_clar_total;
  dst->max_clar_num = src->max_clar_num;
  dst->board_fog_time = src->board_fog_time;
  dst->board_unfog_time = src->board_unfog_time;
  dst->autoupdate_standings = src->autoupdate_standings;
  dst->use_ac_not_ok = src->use_ac_not_ok;
  dst->inactivity_timeout = src->inactivity_timeout;
  dst->disable_auto_testing = src->disable_auto_testing;
  dst->disable_testing = src->disable_testing;
  dst->enable_runlog_merge = src->enable_runlog_merge;
  dst->secure_run = src->secure_run;
  dst->detect_violations = src->detect_violations;
  dst->enable_memory_limit_error = src->enable_memory_limit_error;
  dst->advanced_layout = src->advanced_layout;
  dst->uuid_run_store = src->uuid_run_store;
  dst->enable_32bit_checkers = src->enable_32bit_checkers;
  dst->ignore_bom = src->ignore_bom;
  dst->disable_user_database = src->disable_user_database;
  dst->enable_max_stack_size = src->enable_max_stack_size;
  dst->time_limit_retry_count = src->time_limit_retry_count;
  dst->score_n_best_problems = src->score_n_best_problems;
  dst->require_problem_uuid = src->require_problem_uuid;
  dst->stand_ignore_after = src->stand_ignore_after;
  dst->contest_finish_time = src->contest_finish_time;
  dst->appeal_deadline = src->appeal_deadline;
  // private fog_standings_updated
  // private start_standings_updated
  // private unfog_standings_updated
  dst->team_enable_src_view = src->team_enable_src_view;
  dst->team_enable_rep_view = src->team_enable_rep_view;
  dst->team_enable_ce_view = src->team_enable_ce_view;
  dst->team_show_judge_report = src->team_show_judge_report;
  dst->disable_clars = src->disable_clars;
  dst->disable_team_clars = src->disable_team_clars;
  dst->disable_submit_after_ok = src->disable_submit_after_ok;
  dst->ignore_compile_errors = src->ignore_compile_errors;
  dst->enable_continue = src->enable_continue;
  dst->enable_report_upload = src->enable_report_upload;
  dst->priority_adjustment = src->priority_adjustment;
  dst->ignore_success_time = src->ignore_success_time;
  dst->disable_failed_test_view = src->disable_failed_test_view;
  dst->always_show_problems = src->always_show_problems;
  dst->disable_user_standings = src->disable_user_standings;
  dst->disable_language = src->disable_language;
  dst->problem_navigation = src->problem_navigation;
  dst->problem_tab_size = src->problem_tab_size;
  dst->vertical_navigation = src->vertical_navigation;
  dst->disable_virtual_start = src->disable_virtual_start;
  dst->disable_virtual_auto_judge = src->disable_virtual_auto_judge;
  dst->enable_auto_print_protocol = src->enable_auto_print_protocol;
  dst->notify_clar_reply = src->notify_clar_reply;
  dst->notify_status_change = src->notify_status_change;
  dst->memoize_user_results = src->memoize_user_results;
  dst->disable_auto_refresh = src->disable_auto_refresh;
  dst->enable_eoln_select = src->enable_eoln_select;
  dst->start_on_first_login = src->start_on_first_login;
  dst->enable_virtual_restart = src->enable_virtual_restart;
  dst->preserve_line_numbers = src->preserve_line_numbers;
  dst->enable_remote_cache = src->enable_remote_cache;
  if (src->name) {
    dst->name = strdup(src->name);
  }
  if (src->root_dir) {
    dst->root_dir = strdup(src->root_dir);
  }
  if (src->serve_socket) {
    dst->serve_socket = strdup(src->serve_socket);
  }
  dst->enable_l10n = src->enable_l10n;
  if (src->l10n_dir) {
    dst->l10n_dir = strdup(src->l10n_dir);
  }
  if (src->standings_locale) {
    dst->standings_locale = strdup(src->standings_locale);
  }
  // private standings_locale_id
  if (src->checker_locale) {
    dst->checker_locale = strdup(src->checker_locale);
  }
  dst->contest_id = src->contest_id;
  if (src->socket_path) {
    dst->socket_path = strdup(src->socket_path);
  }
  if (src->contests_dir) {
    dst->contests_dir = strdup(src->contests_dir);
  }
  if (src->lang_config_dir) {
    dst->lang_config_dir = strdup(src->lang_config_dir);
  }
  if (src->charset) {
    dst->charset = strdup(src->charset);
  }
  if (src->standings_charset) {
    dst->standings_charset = strdup(src->standings_charset);
  }
  if (src->stand2_charset) {
    dst->stand2_charset = strdup(src->stand2_charset);
  }
  if (src->plog_charset) {
    dst->plog_charset = strdup(src->plog_charset);
  }
  if (src->conf_dir) {
    dst->conf_dir = strdup(src->conf_dir);
  }
  if (src->problems_dir) {
    dst->problems_dir = strdup(src->problems_dir);
  }
  if (src->script_dir) {
    dst->script_dir = strdup(src->script_dir);
  }
  if (src->test_dir) {
    dst->test_dir = strdup(src->test_dir);
  }
  if (src->corr_dir) {
    dst->corr_dir = strdup(src->corr_dir);
  }
  if (src->info_dir) {
    dst->info_dir = strdup(src->info_dir);
  }
  if (src->tgz_dir) {
    dst->tgz_dir = strdup(src->tgz_dir);
  }
  if (src->checker_dir) {
    dst->checker_dir = strdup(src->checker_dir);
  }
  if (src->statement_dir) {
    dst->statement_dir = strdup(src->statement_dir);
  }
  if (src->plugin_dir) {
    dst->plugin_dir = strdup(src->plugin_dir);
  }
  if (src->test_sfx) {
    dst->test_sfx = strdup(src->test_sfx);
  }
  if (src->corr_sfx) {
    dst->corr_sfx = strdup(src->corr_sfx);
  }
  if (src->info_sfx) {
    dst->info_sfx = strdup(src->info_sfx);
  }
  if (src->tgz_sfx) {
    dst->tgz_sfx = strdup(src->tgz_sfx);
  }
  if (src->tgzdir_sfx) {
    dst->tgzdir_sfx = strdup(src->tgzdir_sfx);
  }
  if (src->ejudge_checkers_dir) {
    dst->ejudge_checkers_dir = strdup(src->ejudge_checkers_dir);
  }
  if (src->contest_start_cmd) {
    dst->contest_start_cmd = strdup(src->contest_start_cmd);
  }
  if (src->contest_stop_cmd) {
    dst->contest_stop_cmd = strdup(src->contest_stop_cmd);
  }
  if (src->description_file) {
    dst->description_file = strdup(src->description_file);
  }
  if (src->contest_plugin_file) {
    dst->contest_plugin_file = strdup(src->contest_plugin_file);
  }
  if (src->virtual_end_options) {
    dst->virtual_end_options = strdup(src->virtual_end_options);
  }
  // private virtual_end_info
  if (src->super_run_dir) {
    dst->super_run_dir = strdup(src->super_run_dir);
  }
  if (src->compile_server_id) {
    dst->compile_server_id = strdup(src->compile_server_id);
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
  if (src->clardb_plugin) {
    dst->clardb_plugin = strdup(src->clardb_plugin);
  }
  if (src->rundb_plugin) {
    dst->rundb_plugin = strdup(src->rundb_plugin);
  }
  if (src->xuser_plugin) {
    dst->xuser_plugin = strdup(src->xuser_plugin);
  }
  if (src->status_plugin) {
    dst->status_plugin = strdup(src->status_plugin);
  }
  if (src->variant_plugin) {
    dst->variant_plugin = strdup(src->variant_plugin);
  }
  if (src->var_dir) {
    dst->var_dir = strdup(src->var_dir);
  }
  if (src->run_log_file) {
    dst->run_log_file = strdup(src->run_log_file);
  }
  if (src->clar_log_file) {
    dst->clar_log_file = strdup(src->clar_log_file);
  }
  if (src->archive_dir) {
    dst->archive_dir = strdup(src->archive_dir);
  }
  if (src->clar_archive_dir) {
    dst->clar_archive_dir = strdup(src->clar_archive_dir);
  }
  if (src->run_archive_dir) {
    dst->run_archive_dir = strdup(src->run_archive_dir);
  }
  if (src->report_archive_dir) {
    dst->report_archive_dir = strdup(src->report_archive_dir);
  }
  if (src->team_report_archive_dir) {
    dst->team_report_archive_dir = strdup(src->team_report_archive_dir);
  }
  if (src->xml_report_archive_dir) {
    dst->xml_report_archive_dir = strdup(src->xml_report_archive_dir);
  }
  if (src->full_archive_dir) {
    dst->full_archive_dir = strdup(src->full_archive_dir);
  }
  if (src->audit_log_dir) {
    dst->audit_log_dir = strdup(src->audit_log_dir);
  }
  if (src->uuid_archive_dir) {
    dst->uuid_archive_dir = strdup(src->uuid_archive_dir);
  }
  if (src->team_extra_dir) {
    dst->team_extra_dir = strdup(src->team_extra_dir);
  }
  if (src->legacy_status_dir) {
    dst->legacy_status_dir = strdup(src->legacy_status_dir);
  }
  if (src->work_dir) {
    dst->work_dir = strdup(src->work_dir);
  }
  if (src->print_work_dir) {
    dst->print_work_dir = strdup(src->print_work_dir);
  }
  if (src->diff_work_dir) {
    dst->diff_work_dir = strdup(src->diff_work_dir);
  }
  if (src->a2ps_path) {
    dst->a2ps_path = strdup(src->a2ps_path);
  }
  dst->a2ps_args = (typeof(dst->a2ps_args)) sarray_copy((char**) src->a2ps_args);
  if (src->lpr_path) {
    dst->lpr_path = strdup(src->lpr_path);
  }
  dst->lpr_args = (typeof(dst->lpr_args)) sarray_copy((char**) src->lpr_args);
  if (src->diff_path) {
    dst->diff_path = strdup(src->diff_path);
  }
  if (src->compile_dir) {
    dst->compile_dir = strdup(src->compile_dir);
  }
  if (src->compile_queue_dir) {
    dst->compile_queue_dir = strdup(src->compile_queue_dir);
  }
  if (src->compile_src_dir) {
    dst->compile_src_dir = strdup(src->compile_src_dir);
  }
  dst->extra_compile_dirs = (typeof(dst->extra_compile_dirs)) sarray_copy((char**) src->extra_compile_dirs);
  if (src->compile_out_dir) {
    dst->compile_out_dir = strdup(src->compile_out_dir);
  }
  if (src->compile_status_dir) {
    dst->compile_status_dir = strdup(src->compile_status_dir);
  }
  if (src->compile_report_dir) {
    dst->compile_report_dir = strdup(src->compile_report_dir);
  }
  if (src->compile_work_dir) {
    dst->compile_work_dir = strdup(src->compile_work_dir);
  }
  if (src->run_dir) {
    dst->run_dir = strdup(src->run_dir);
  }
  if (src->run_queue_dir) {
    dst->run_queue_dir = strdup(src->run_queue_dir);
  }
  if (src->run_exe_dir) {
    dst->run_exe_dir = strdup(src->run_exe_dir);
  }
  if (src->run_out_dir) {
    dst->run_out_dir = strdup(src->run_out_dir);
  }
  if (src->run_status_dir) {
    dst->run_status_dir = strdup(src->run_status_dir);
  }
  if (src->run_report_dir) {
    dst->run_report_dir = strdup(src->run_report_dir);
  }
  if (src->run_team_report_dir) {
    dst->run_team_report_dir = strdup(src->run_team_report_dir);
  }
  if (src->run_full_archive_dir) {
    dst->run_full_archive_dir = strdup(src->run_full_archive_dir);
  }
  if (src->run_work_dir) {
    dst->run_work_dir = strdup(src->run_work_dir);
  }
  if (src->run_check_dir) {
    dst->run_check_dir = strdup(src->run_check_dir);
  }
  if (src->htdocs_dir) {
    dst->htdocs_dir = strdup(src->htdocs_dir);
  }
  dst->score_system = src->score_system;
  dst->tests_to_accept = src->tests_to_accept;
  dst->is_virtual = src->is_virtual;
  dst->prune_empty_users = src->prune_empty_users;
  dst->rounding_mode = src->rounding_mode;
  dst->max_file_length = src->max_file_length;
  dst->max_line_length = src->max_line_length;
  dst->max_cmd_length = src->max_cmd_length;
  if (src->team_info_url) {
    dst->team_info_url = strdup(src->team_info_url);
  }
  if (src->prob_info_url) {
    dst->prob_info_url = strdup(src->prob_info_url);
  }
  if (src->standings_file_name) {
    dst->standings_file_name = strdup(src->standings_file_name);
  }
  if (src->stand_header_file) {
    dst->stand_header_file = strdup(src->stand_header_file);
  }
  if (src->stand_footer_file) {
    dst->stand_footer_file = strdup(src->stand_footer_file);
  }
  if (src->stand_symlink_dir) {
    dst->stand_symlink_dir = strdup(src->stand_symlink_dir);
  }
  dst->users_on_page = src->users_on_page;
  if (src->stand_file_name_2) {
    dst->stand_file_name_2 = strdup(src->stand_file_name_2);
  }
  dst->stand_fancy_style = src->stand_fancy_style;
  if (src->stand_extra_format) {
    dst->stand_extra_format = strdup(src->stand_extra_format);
  }
  if (src->stand_extra_legend) {
    dst->stand_extra_legend = strdup(src->stand_extra_legend);
  }
  if (src->stand_extra_attr) {
    dst->stand_extra_attr = strdup(src->stand_extra_attr);
  }
  if (src->stand_table_attr) {
    dst->stand_table_attr = strdup(src->stand_table_attr);
  }
  if (src->stand_place_attr) {
    dst->stand_place_attr = strdup(src->stand_place_attr);
  }
  if (src->stand_team_attr) {
    dst->stand_team_attr = strdup(src->stand_team_attr);
  }
  if (src->stand_prob_attr) {
    dst->stand_prob_attr = strdup(src->stand_prob_attr);
  }
  if (src->stand_solved_attr) {
    dst->stand_solved_attr = strdup(src->stand_solved_attr);
  }
  if (src->stand_score_attr) {
    dst->stand_score_attr = strdup(src->stand_score_attr);
  }
  if (src->stand_penalty_attr) {
    dst->stand_penalty_attr = strdup(src->stand_penalty_attr);
  }
  if (src->stand_time_attr) {
    dst->stand_time_attr = strdup(src->stand_time_attr);
  }
  if (src->stand_self_row_attr) {
    dst->stand_self_row_attr = strdup(src->stand_self_row_attr);
  }
  if (src->stand_r_row_attr) {
    dst->stand_r_row_attr = strdup(src->stand_r_row_attr);
  }
  if (src->stand_v_row_attr) {
    dst->stand_v_row_attr = strdup(src->stand_v_row_attr);
  }
  if (src->stand_u_row_attr) {
    dst->stand_u_row_attr = strdup(src->stand_u_row_attr);
  }
  if (src->stand_success_attr) {
    dst->stand_success_attr = strdup(src->stand_success_attr);
  }
  if (src->stand_fail_attr) {
    dst->stand_fail_attr = strdup(src->stand_fail_attr);
  }
  if (src->stand_trans_attr) {
    dst->stand_trans_attr = strdup(src->stand_trans_attr);
  }
  if (src->stand_disq_attr) {
    dst->stand_disq_attr = strdup(src->stand_disq_attr);
  }
  dst->stand_use_login = src->stand_use_login;
  dst->stand_show_avatar = src->stand_show_avatar;
  dst->stand_show_first_solver = src->stand_show_first_solver;
  dst->stand_show_ok_time = src->stand_show_ok_time;
  dst->stand_show_att_num = src->stand_show_att_num;
  dst->stand_sort_by_solved = src->stand_sort_by_solved;
  dst->stand_row_attr = (typeof(dst->stand_row_attr)) sarray_copy((char**) src->stand_row_attr);
  if (src->stand_page_table_attr) {
    dst->stand_page_table_attr = strdup(src->stand_page_table_attr);
  }
  dst->stand_page_row_attr = (typeof(dst->stand_page_row_attr)) sarray_copy((char**) src->stand_page_row_attr);
  dst->stand_page_col_attr = (typeof(dst->stand_page_col_attr)) sarray_copy((char**) src->stand_page_col_attr);
  if (src->stand_page_cur_attr) {
    dst->stand_page_cur_attr = strdup(src->stand_page_cur_attr);
  }
  dst->stand_collate_name = src->stand_collate_name;
  dst->stand_enable_penalty = src->stand_enable_penalty;
  // private stand_header_txt
  // private stand_footer_txt
  if (src->stand2_file_name) {
    dst->stand2_file_name = strdup(src->stand2_file_name);
  }
  if (src->stand2_header_file) {
    dst->stand2_header_file = strdup(src->stand2_header_file);
  }
  if (src->stand2_footer_file) {
    dst->stand2_footer_file = strdup(src->stand2_footer_file);
  }
  // private stand2_header_txt
  // private stand2_footer_txt
  if (src->stand2_symlink_dir) {
    dst->stand2_symlink_dir = strdup(src->stand2_symlink_dir);
  }
  if (src->plog_file_name) {
    dst->plog_file_name = strdup(src->plog_file_name);
  }
  if (src->plog_header_file) {
    dst->plog_header_file = strdup(src->plog_header_file);
  }
  if (src->plog_footer_file) {
    dst->plog_footer_file = strdup(src->plog_footer_file);
  }
  // private plog_header_txt
  // private plog_footer_txt
  dst->plog_update_time = src->plog_update_time;
  if (src->plog_symlink_dir) {
    dst->plog_symlink_dir = strdup(src->plog_symlink_dir);
  }
  dst->internal_xml_update_time = src->internal_xml_update_time;
  dst->external_xml_update_time = src->external_xml_update_time;
  if (src->user_exam_protocol_header_file) {
    dst->user_exam_protocol_header_file = strdup(src->user_exam_protocol_header_file);
  }
  if (src->user_exam_protocol_footer_file) {
    dst->user_exam_protocol_footer_file = strdup(src->user_exam_protocol_footer_file);
  }
  // private user_exam_protocol_header_txt
  // private user_exam_protocol_footer_txt
  if (src->prob_exam_protocol_header_file) {
    dst->prob_exam_protocol_header_file = strdup(src->prob_exam_protocol_header_file);
  }
  if (src->prob_exam_protocol_footer_file) {
    dst->prob_exam_protocol_footer_file = strdup(src->prob_exam_protocol_footer_file);
  }
  // private prob_exam_protocol_header_txt
  // private prob_exam_protocol_footer_txt
  if (src->full_exam_protocol_header_file) {
    dst->full_exam_protocol_header_file = strdup(src->full_exam_protocol_header_file);
  }
  if (src->full_exam_protocol_footer_file) {
    dst->full_exam_protocol_footer_file = strdup(src->full_exam_protocol_footer_file);
  }
  // private full_exam_protocol_header_txt
  // private full_exam_protocol_footer_txt
  dst->extended_sound = src->extended_sound;
  dst->disable_sound = src->disable_sound;
  if (src->sound_player) {
    dst->sound_player = strdup(src->sound_player);
  }
  if (src->accept_sound) {
    dst->accept_sound = strdup(src->accept_sound);
  }
  if (src->runtime_sound) {
    dst->runtime_sound = strdup(src->runtime_sound);
  }
  if (src->timelimit_sound) {
    dst->timelimit_sound = strdup(src->timelimit_sound);
  }
  if (src->presentation_sound) {
    dst->presentation_sound = strdup(src->presentation_sound);
  }
  if (src->wrong_sound) {
    dst->wrong_sound = strdup(src->wrong_sound);
  }
  if (src->internal_sound) {
    dst->internal_sound = strdup(src->internal_sound);
  }
  if (src->start_sound) {
    dst->start_sound = strdup(src->start_sound);
  }
  dst->team_download_time = src->team_download_time;
  dst->cr_serialization_key = src->cr_serialization_key;
  dst->show_astr_time = src->show_astr_time;
  dst->ignore_duplicated_runs = src->ignore_duplicated_runs;
  dst->report_error_code = src->report_error_code;
  dst->auto_short_problem_name = src->auto_short_problem_name;
  dst->compile_real_time_limit = src->compile_real_time_limit;
  dst->checker_real_time_limit = src->checker_real_time_limit;
  dst->show_deadline = src->show_deadline;
  dst->separate_user_score = src->separate_user_score;
  dst->show_sha1 = src->show_sha1;
  dst->show_judge_identity = src->show_judge_identity;
  dst->use_gzip = src->use_gzip;
  dst->min_gzip_size = src->min_gzip_size;
  dst->use_dir_hierarchy = src->use_dir_hierarchy;
  dst->html_report = src->html_report;
  dst->xml_report = src->xml_report;
  dst->enable_full_archive = src->enable_full_archive;
  dst->cpu_bogomips = src->cpu_bogomips;
  dst->skip_full_testing = src->skip_full_testing;
  dst->skip_accept_testing = src->skip_accept_testing;
  dst->enable_problem_history = src->enable_problem_history;
  if (src->variant_map_file) {
    dst->variant_map_file = strdup(src->variant_map_file);
  }
  dst->enable_printing = src->enable_printing;
  dst->disable_banner_page = src->disable_banner_page;
  dst->printout_uses_login = src->printout_uses_login;
  dst->team_page_quota = src->team_page_quota;
  dst->print_just_copy = src->print_just_copy;
  dst->compile_max_vm_size = src->compile_max_vm_size;
  dst->compile_max_stack_size = src->compile_max_stack_size;
  dst->compile_max_file_size = src->compile_max_file_size;
  dst->compile_max_rss_size = src->compile_max_rss_size;
  dst->user_priority_adjustments = (typeof(dst->user_priority_adjustments)) sarray_copy((char**) src->user_priority_adjustments);
  // private user_adjustment_info
  // private user_adjustment_map
  dst->contestant_status_num = src->contestant_status_num;
  dst->contestant_status_legend = (typeof(dst->contestant_status_legend)) sarray_copy((char**) src->contestant_status_legend);
  dst->contestant_status_row_attr = (typeof(dst->contestant_status_row_attr)) sarray_copy((char**) src->contestant_status_row_attr);
  dst->stand_show_contestant_status = src->stand_show_contestant_status;
  dst->stand_show_warn_number = src->stand_show_warn_number;
  if (src->stand_contestant_status_attr) {
    dst->stand_contestant_status_attr = strdup(src->stand_contestant_status_attr);
  }
  if (src->stand_warn_number_attr) {
    dst->stand_warn_number_attr = strdup(src->stand_warn_number_attr);
  }
  dst->load_user_group = (typeof(dst->load_user_group)) sarray_copy((char**) src->load_user_group);
  if (src->tokens) {
    dst->tokens = strdup(src->tokens);
  }
  // private token_info
  // private enable_tokens
  if (src->dates_config_file) {
    dst->dates_config_file = strdup(src->dates_config_file);
  }
  // private dates_config
  if (src->unhandled_vars) {
    dst->unhandled_vars = strdup(src->unhandled_vars);
  }
  // private disable_prob_long_name
  // private disable_passed_tests
  dst->time_between_submits = src->time_between_submits;
  dst->max_input_size = src->max_input_size;
  dst->max_submit_num = src->max_submit_num;
  dst->max_submit_total = src->max_submit_total;
}

void cntsglob_free(struct section_global_data *ptr)
{
  // hidden g
  // private fog_standings_updated
  // private start_standings_updated
  // private unfog_standings_updated
  free(ptr->name);
  free(ptr->root_dir);
  free(ptr->serve_socket);
  free(ptr->l10n_dir);
  free(ptr->standings_locale);
  // private standings_locale_id
  free(ptr->checker_locale);
  free(ptr->socket_path);
  free(ptr->contests_dir);
  free(ptr->lang_config_dir);
  free(ptr->charset);
  free(ptr->standings_charset);
  free(ptr->stand2_charset);
  free(ptr->plog_charset);
  free(ptr->conf_dir);
  free(ptr->problems_dir);
  free(ptr->script_dir);
  free(ptr->test_dir);
  free(ptr->corr_dir);
  free(ptr->info_dir);
  free(ptr->tgz_dir);
  free(ptr->checker_dir);
  free(ptr->statement_dir);
  free(ptr->plugin_dir);
  free(ptr->test_sfx);
  free(ptr->corr_sfx);
  free(ptr->info_sfx);
  free(ptr->tgz_sfx);
  free(ptr->tgzdir_sfx);
  free(ptr->ejudge_checkers_dir);
  free(ptr->contest_start_cmd);
  free(ptr->contest_stop_cmd);
  free(ptr->description_file);
  free(ptr->contest_plugin_file);
  free(ptr->virtual_end_options);
  // private virtual_end_info
  free(ptr->super_run_dir);
  free(ptr->compile_server_id);
  free(ptr->test_pat);
  free(ptr->corr_pat);
  free(ptr->info_pat);
  free(ptr->tgz_pat);
  free(ptr->tgzdir_pat);
  free(ptr->clardb_plugin);
  free(ptr->rundb_plugin);
  free(ptr->xuser_plugin);
  free(ptr->status_plugin);
  free(ptr->variant_plugin);
  free(ptr->var_dir);
  free(ptr->run_log_file);
  free(ptr->clar_log_file);
  free(ptr->archive_dir);
  free(ptr->clar_archive_dir);
  free(ptr->run_archive_dir);
  free(ptr->report_archive_dir);
  free(ptr->team_report_archive_dir);
  free(ptr->xml_report_archive_dir);
  free(ptr->full_archive_dir);
  free(ptr->audit_log_dir);
  free(ptr->uuid_archive_dir);
  free(ptr->team_extra_dir);
  free(ptr->legacy_status_dir);
  free(ptr->work_dir);
  free(ptr->print_work_dir);
  free(ptr->diff_work_dir);
  free(ptr->a2ps_path);
  sarray_free((char**) ptr->a2ps_args);
  free(ptr->lpr_path);
  sarray_free((char**) ptr->lpr_args);
  free(ptr->diff_path);
  free(ptr->compile_dir);
  free(ptr->compile_queue_dir);
  free(ptr->compile_src_dir);
  sarray_free((char**) ptr->extra_compile_dirs);
  free(ptr->compile_out_dir);
  free(ptr->compile_status_dir);
  free(ptr->compile_report_dir);
  free(ptr->compile_work_dir);
  free(ptr->run_dir);
  free(ptr->run_queue_dir);
  free(ptr->run_exe_dir);
  free(ptr->run_out_dir);
  free(ptr->run_status_dir);
  free(ptr->run_report_dir);
  free(ptr->run_team_report_dir);
  free(ptr->run_full_archive_dir);
  free(ptr->run_work_dir);
  free(ptr->run_check_dir);
  free(ptr->htdocs_dir);
  free(ptr->team_info_url);
  free(ptr->prob_info_url);
  free(ptr->standings_file_name);
  free(ptr->stand_header_file);
  free(ptr->stand_footer_file);
  free(ptr->stand_symlink_dir);
  free(ptr->stand_file_name_2);
  free(ptr->stand_extra_format);
  free(ptr->stand_extra_legend);
  free(ptr->stand_extra_attr);
  free(ptr->stand_table_attr);
  free(ptr->stand_place_attr);
  free(ptr->stand_team_attr);
  free(ptr->stand_prob_attr);
  free(ptr->stand_solved_attr);
  free(ptr->stand_score_attr);
  free(ptr->stand_penalty_attr);
  free(ptr->stand_time_attr);
  free(ptr->stand_self_row_attr);
  free(ptr->stand_r_row_attr);
  free(ptr->stand_v_row_attr);
  free(ptr->stand_u_row_attr);
  free(ptr->stand_success_attr);
  free(ptr->stand_fail_attr);
  free(ptr->stand_trans_attr);
  free(ptr->stand_disq_attr);
  sarray_free((char**) ptr->stand_row_attr);
  free(ptr->stand_page_table_attr);
  sarray_free((char**) ptr->stand_page_row_attr);
  sarray_free((char**) ptr->stand_page_col_attr);
  free(ptr->stand_page_cur_attr);
  // private stand_header_txt
  // private stand_footer_txt
  free(ptr->stand2_file_name);
  free(ptr->stand2_header_file);
  free(ptr->stand2_footer_file);
  // private stand2_header_txt
  // private stand2_footer_txt
  free(ptr->stand2_symlink_dir);
  free(ptr->plog_file_name);
  free(ptr->plog_header_file);
  free(ptr->plog_footer_file);
  // private plog_header_txt
  // private plog_footer_txt
  free(ptr->plog_symlink_dir);
  free(ptr->user_exam_protocol_header_file);
  free(ptr->user_exam_protocol_footer_file);
  // private user_exam_protocol_header_txt
  // private user_exam_protocol_footer_txt
  free(ptr->prob_exam_protocol_header_file);
  free(ptr->prob_exam_protocol_footer_file);
  // private prob_exam_protocol_header_txt
  // private prob_exam_protocol_footer_txt
  free(ptr->full_exam_protocol_header_file);
  free(ptr->full_exam_protocol_footer_file);
  // private full_exam_protocol_header_txt
  // private full_exam_protocol_footer_txt
  free(ptr->sound_player);
  free(ptr->accept_sound);
  free(ptr->runtime_sound);
  free(ptr->timelimit_sound);
  free(ptr->presentation_sound);
  free(ptr->wrong_sound);
  free(ptr->internal_sound);
  free(ptr->start_sound);
  free(ptr->variant_map_file);
  sarray_free((char**) ptr->user_priority_adjustments);
  // private user_adjustment_info
  // private user_adjustment_map
  sarray_free((char**) ptr->contestant_status_legend);
  sarray_free((char**) ptr->contestant_status_row_attr);
  free(ptr->stand_contestant_status_attr);
  free(ptr->stand_warn_number_attr);
  sarray_free((char**) ptr->load_user_group);
  free(ptr->tokens);
  // private token_info
  // private enable_tokens
  free(ptr->dates_config_file);
  // private dates_config
  free(ptr->unhandled_vars);
  // private disable_prob_long_name
  // private disable_passed_tests
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
  (void (*)(void *, const void *))cntsglob_copy,
  (void (*)(void *))cntsglob_free,
};

static struct meta_info_item meta_info_section_problem_data_data[] =
{
  [CNTSPROB_id] = { CNTSPROB_id, 'i', XSIZE(struct section_problem_data, id), "id", XOFFSET(struct section_problem_data, id) },
  [CNTSPROB_tester_id] = { CNTSPROB_tester_id, 'i', XSIZE(struct section_problem_data, tester_id), "tester_id", XOFFSET(struct section_problem_data, tester_id) },
  [CNTSPROB_type] = { CNTSPROB_type, 'i', XSIZE(struct section_problem_data, type), "type", XOFFSET(struct section_problem_data, type) },
  [CNTSPROB_variant_num] = { CNTSPROB_variant_num, 'i', XSIZE(struct section_problem_data, variant_num), "variant_num", XOFFSET(struct section_problem_data, variant_num) },
  [CNTSPROB_full_score] = { CNTSPROB_full_score, 'i', XSIZE(struct section_problem_data, full_score), "full_score", XOFFSET(struct section_problem_data, full_score) },
  [CNTSPROB_full_user_score] = { CNTSPROB_full_user_score, 'i', XSIZE(struct section_problem_data, full_user_score), "full_user_score", XOFFSET(struct section_problem_data, full_user_score) },
  [CNTSPROB_min_score_1] = { CNTSPROB_min_score_1, 'i', XSIZE(struct section_problem_data, min_score_1), "min_score_1", XOFFSET(struct section_problem_data, min_score_1) },
  [CNTSPROB_min_score_2] = { CNTSPROB_min_score_2, 'i', XSIZE(struct section_problem_data, min_score_2), "min_score_2", XOFFSET(struct section_problem_data, min_score_2) },
  [CNTSPROB_super] = { CNTSPROB_super, 'S', XSIZE(struct section_problem_data, super), "super", XOFFSET(struct section_problem_data, super) },
  [CNTSPROB_short_name] = { CNTSPROB_short_name, 'S', XSIZE(struct section_problem_data, short_name), "short_name", XOFFSET(struct section_problem_data, short_name) },
  [CNTSPROB_abstract] = { CNTSPROB_abstract, 'f', XSIZE(struct section_problem_data, abstract), "abstract", XOFFSET(struct section_problem_data, abstract) },
  [CNTSPROB_manual_checking] = { CNTSPROB_manual_checking, 'f', XSIZE(struct section_problem_data, manual_checking), "manual_checking", XOFFSET(struct section_problem_data, manual_checking) },
  [CNTSPROB_check_presentation] = { CNTSPROB_check_presentation, 'f', XSIZE(struct section_problem_data, check_presentation), "check_presentation", XOFFSET(struct section_problem_data, check_presentation) },
  [CNTSPROB_scoring_checker] = { CNTSPROB_scoring_checker, 'f', XSIZE(struct section_problem_data, scoring_checker), "scoring_checker", XOFFSET(struct section_problem_data, scoring_checker) },
  [CNTSPROB_enable_checker_token] = { CNTSPROB_enable_checker_token, 'f', XSIZE(struct section_problem_data, enable_checker_token), "enable_checker_token", XOFFSET(struct section_problem_data, enable_checker_token) },
  [CNTSPROB_interactive_valuer] = { CNTSPROB_interactive_valuer, 'f', XSIZE(struct section_problem_data, interactive_valuer), "interactive_valuer", XOFFSET(struct section_problem_data, interactive_valuer) },
  [CNTSPROB_disable_pe] = { CNTSPROB_disable_pe, 'f', XSIZE(struct section_problem_data, disable_pe), "disable_pe", XOFFSET(struct section_problem_data, disable_pe) },
  [CNTSPROB_disable_wtl] = { CNTSPROB_disable_wtl, 'f', XSIZE(struct section_problem_data, disable_wtl), "disable_wtl", XOFFSET(struct section_problem_data, disable_wtl) },
  [CNTSPROB_wtl_is_cf] = { CNTSPROB_wtl_is_cf, 'f', XSIZE(struct section_problem_data, wtl_is_cf), "wtl_is_cf", XOFFSET(struct section_problem_data, wtl_is_cf) },
  [CNTSPROB_use_stdin] = { CNTSPROB_use_stdin, 'f', XSIZE(struct section_problem_data, use_stdin), "use_stdin", XOFFSET(struct section_problem_data, use_stdin) },
  [CNTSPROB_use_stdout] = { CNTSPROB_use_stdout, 'f', XSIZE(struct section_problem_data, use_stdout), "use_stdout", XOFFSET(struct section_problem_data, use_stdout) },
  [CNTSPROB_combined_stdin] = { CNTSPROB_combined_stdin, 'f', XSIZE(struct section_problem_data, combined_stdin), "combined_stdin", XOFFSET(struct section_problem_data, combined_stdin) },
  [CNTSPROB_combined_stdout] = { CNTSPROB_combined_stdout, 'f', XSIZE(struct section_problem_data, combined_stdout), "combined_stdout", XOFFSET(struct section_problem_data, combined_stdout) },
  [CNTSPROB_binary_input] = { CNTSPROB_binary_input, 'f', XSIZE(struct section_problem_data, binary_input), "binary_input", XOFFSET(struct section_problem_data, binary_input) },
  [CNTSPROB_binary] = { CNTSPROB_binary, 'f', XSIZE(struct section_problem_data, binary), "binary", XOFFSET(struct section_problem_data, binary) },
  [CNTSPROB_ignore_exit_code] = { CNTSPROB_ignore_exit_code, 'f', XSIZE(struct section_problem_data, ignore_exit_code), "ignore_exit_code", XOFFSET(struct section_problem_data, ignore_exit_code) },
  [CNTSPROB_ignore_term_signal] = { CNTSPROB_ignore_term_signal, 'f', XSIZE(struct section_problem_data, ignore_term_signal), "ignore_term_signal", XOFFSET(struct section_problem_data, ignore_term_signal) },
  [CNTSPROB_olympiad_mode] = { CNTSPROB_olympiad_mode, 'f', XSIZE(struct section_problem_data, olympiad_mode), "olympiad_mode", XOFFSET(struct section_problem_data, olympiad_mode) },
  [CNTSPROB_score_latest] = { CNTSPROB_score_latest, 'f', XSIZE(struct section_problem_data, score_latest), "score_latest", XOFFSET(struct section_problem_data, score_latest) },
  [CNTSPROB_score_latest_or_unmarked] = { CNTSPROB_score_latest_or_unmarked, 'f', XSIZE(struct section_problem_data, score_latest_or_unmarked), "score_latest_or_unmarked", XOFFSET(struct section_problem_data, score_latest_or_unmarked) },
  [CNTSPROB_score_latest_marked] = { CNTSPROB_score_latest_marked, 'f', XSIZE(struct section_problem_data, score_latest_marked), "score_latest_marked", XOFFSET(struct section_problem_data, score_latest_marked) },
  [CNTSPROB_score_tokenized] = { CNTSPROB_score_tokenized, 'f', XSIZE(struct section_problem_data, score_tokenized), "score_tokenized", XOFFSET(struct section_problem_data, score_tokenized) },
  [CNTSPROB_use_ac_not_ok] = { CNTSPROB_use_ac_not_ok, 'f', XSIZE(struct section_problem_data, use_ac_not_ok), "use_ac_not_ok", XOFFSET(struct section_problem_data, use_ac_not_ok) },
  [CNTSPROB_ignore_prev_ac] = { CNTSPROB_ignore_prev_ac, 'f', XSIZE(struct section_problem_data, ignore_prev_ac), "ignore_prev_ac", XOFFSET(struct section_problem_data, ignore_prev_ac) },
  [CNTSPROB_team_enable_rep_view] = { CNTSPROB_team_enable_rep_view, 'f', XSIZE(struct section_problem_data, team_enable_rep_view), "team_enable_rep_view", XOFFSET(struct section_problem_data, team_enable_rep_view) },
  [CNTSPROB_team_enable_ce_view] = { CNTSPROB_team_enable_ce_view, 'f', XSIZE(struct section_problem_data, team_enable_ce_view), "team_enable_ce_view", XOFFSET(struct section_problem_data, team_enable_ce_view) },
  [CNTSPROB_team_show_judge_report] = { CNTSPROB_team_show_judge_report, 'f', XSIZE(struct section_problem_data, team_show_judge_report), "team_show_judge_report", XOFFSET(struct section_problem_data, team_show_judge_report) },
  [CNTSPROB_show_checker_comment] = { CNTSPROB_show_checker_comment, 'f', XSIZE(struct section_problem_data, show_checker_comment), "show_checker_comment", XOFFSET(struct section_problem_data, show_checker_comment) },
  [CNTSPROB_ignore_compile_errors] = { CNTSPROB_ignore_compile_errors, 'f', XSIZE(struct section_problem_data, ignore_compile_errors), "ignore_compile_errors", XOFFSET(struct section_problem_data, ignore_compile_errors) },
  [CNTSPROB_variable_full_score] = { CNTSPROB_variable_full_score, 'f', XSIZE(struct section_problem_data, variable_full_score), "variable_full_score", XOFFSET(struct section_problem_data, variable_full_score) },
  [CNTSPROB_ignore_penalty] = { CNTSPROB_ignore_penalty, 'f', XSIZE(struct section_problem_data, ignore_penalty), "ignore_penalty", XOFFSET(struct section_problem_data, ignore_penalty) },
  [CNTSPROB_use_corr] = { CNTSPROB_use_corr, 'f', XSIZE(struct section_problem_data, use_corr), "use_corr", XOFFSET(struct section_problem_data, use_corr) },
  [CNTSPROB_use_info] = { CNTSPROB_use_info, 'f', XSIZE(struct section_problem_data, use_info), "use_info", XOFFSET(struct section_problem_data, use_info) },
  [CNTSPROB_use_tgz] = { CNTSPROB_use_tgz, 'f', XSIZE(struct section_problem_data, use_tgz), "use_tgz", XOFFSET(struct section_problem_data, use_tgz) },
  [CNTSPROB_accept_partial] = { CNTSPROB_accept_partial, 'f', XSIZE(struct section_problem_data, accept_partial), "accept_partial", XOFFSET(struct section_problem_data, accept_partial) },
  [CNTSPROB_disable_user_submit] = { CNTSPROB_disable_user_submit, 'f', XSIZE(struct section_problem_data, disable_user_submit), "disable_user_submit", XOFFSET(struct section_problem_data, disable_user_submit) },
  [CNTSPROB_disable_tab] = { CNTSPROB_disable_tab, 'f', XSIZE(struct section_problem_data, disable_tab), "disable_tab", XOFFSET(struct section_problem_data, disable_tab) },
  [CNTSPROB_unrestricted_statement] = { CNTSPROB_unrestricted_statement, 'f', XSIZE(struct section_problem_data, unrestricted_statement), "unrestricted_statement", XOFFSET(struct section_problem_data, unrestricted_statement) },
  [CNTSPROB_statement_ignore_ip] = { CNTSPROB_statement_ignore_ip, 'f', XSIZE(struct section_problem_data, statement_ignore_ip), "statement_ignore_ip", XOFFSET(struct section_problem_data, statement_ignore_ip) },
  [CNTSPROB_restricted_statement] = { CNTSPROB_restricted_statement, 'f', XSIZE(struct section_problem_data, restricted_statement), "restricted_statement", XOFFSET(struct section_problem_data, restricted_statement) },
  [CNTSPROB_enable_submit_after_reject] = { CNTSPROB_enable_submit_after_reject, 'f', XSIZE(struct section_problem_data, enable_submit_after_reject), "enable_submit_after_reject", XOFFSET(struct section_problem_data, enable_submit_after_reject) },
  [CNTSPROB_hide_file_names] = { CNTSPROB_hide_file_names, 'f', XSIZE(struct section_problem_data, hide_file_names), "hide_file_names", XOFFSET(struct section_problem_data, hide_file_names) },
  [CNTSPROB_hide_real_time_limit] = { CNTSPROB_hide_real_time_limit, 'f', XSIZE(struct section_problem_data, hide_real_time_limit), "hide_real_time_limit", XOFFSET(struct section_problem_data, hide_real_time_limit) },
  [CNTSPROB_enable_tokens] = { CNTSPROB_enable_tokens, 'f', XSIZE(struct section_problem_data, enable_tokens), "enable_tokens", XOFFSET(struct section_problem_data, enable_tokens) },
  [CNTSPROB_tokens_for_user_ac] = { CNTSPROB_tokens_for_user_ac, 'f', XSIZE(struct section_problem_data, tokens_for_user_ac), "tokens_for_user_ac", XOFFSET(struct section_problem_data, tokens_for_user_ac) },
  [CNTSPROB_disable_submit_after_ok] = { CNTSPROB_disable_submit_after_ok, 'f', XSIZE(struct section_problem_data, disable_submit_after_ok), "disable_submit_after_ok", XOFFSET(struct section_problem_data, disable_submit_after_ok) },
  [CNTSPROB_disable_auto_testing] = { CNTSPROB_disable_auto_testing, 'f', XSIZE(struct section_problem_data, disable_auto_testing), "disable_auto_testing", XOFFSET(struct section_problem_data, disable_auto_testing) },
  [CNTSPROB_disable_testing] = { CNTSPROB_disable_testing, 'f', XSIZE(struct section_problem_data, disable_testing), "disable_testing", XOFFSET(struct section_problem_data, disable_testing) },
  [CNTSPROB_enable_compilation] = { CNTSPROB_enable_compilation, 'f', XSIZE(struct section_problem_data, enable_compilation), "enable_compilation", XOFFSET(struct section_problem_data, enable_compilation) },
  [CNTSPROB_skip_testing] = { CNTSPROB_skip_testing, 'f', XSIZE(struct section_problem_data, skip_testing), "skip_testing", XOFFSET(struct section_problem_data, skip_testing) },
  [CNTSPROB_hidden] = { CNTSPROB_hidden, 'f', XSIZE(struct section_problem_data, hidden), "hidden", XOFFSET(struct section_problem_data, hidden) },
  [CNTSPROB_stand_hide_time] = { CNTSPROB_stand_hide_time, 'f', XSIZE(struct section_problem_data, stand_hide_time), "stand_hide_time", XOFFSET(struct section_problem_data, stand_hide_time) },
  [CNTSPROB_advance_to_next] = { CNTSPROB_advance_to_next, 'f', XSIZE(struct section_problem_data, advance_to_next), "advance_to_next", XOFFSET(struct section_problem_data, advance_to_next) },
  [CNTSPROB_disable_ctrl_chars] = { CNTSPROB_disable_ctrl_chars, 'f', XSIZE(struct section_problem_data, disable_ctrl_chars), "disable_ctrl_chars", XOFFSET(struct section_problem_data, disable_ctrl_chars) },
  [CNTSPROB_enable_text_form] = { CNTSPROB_enable_text_form, 'f', XSIZE(struct section_problem_data, enable_text_form), "enable_text_form", XOFFSET(struct section_problem_data, enable_text_form) },
  [CNTSPROB_stand_ignore_score] = { CNTSPROB_stand_ignore_score, 'f', XSIZE(struct section_problem_data, stand_ignore_score), "stand_ignore_score", XOFFSET(struct section_problem_data, stand_ignore_score) },
  [CNTSPROB_stand_last_column] = { CNTSPROB_stand_last_column, 'f', XSIZE(struct section_problem_data, stand_last_column), "stand_last_column", XOFFSET(struct section_problem_data, stand_last_column) },
  [CNTSPROB_disable_security] = { CNTSPROB_disable_security, 'f', XSIZE(struct section_problem_data, disable_security), "disable_security", XOFFSET(struct section_problem_data, disable_security) },
  [CNTSPROB_enable_suid_run] = { CNTSPROB_enable_suid_run, 'f', XSIZE(struct section_problem_data, enable_suid_run), "enable_suid_run", XOFFSET(struct section_problem_data, enable_suid_run) },
  [CNTSPROB_enable_container] = { CNTSPROB_enable_container, 'f', XSIZE(struct section_problem_data, enable_container), "enable_container", XOFFSET(struct section_problem_data, enable_container) },
  [CNTSPROB_enable_dynamic_priority] = { CNTSPROB_enable_dynamic_priority, 'f', XSIZE(struct section_problem_data, enable_dynamic_priority), "enable_dynamic_priority", XOFFSET(struct section_problem_data, enable_dynamic_priority) },
  [CNTSPROB_valuer_sets_marked] = { CNTSPROB_valuer_sets_marked, 'f', XSIZE(struct section_problem_data, valuer_sets_marked), "valuer_sets_marked", XOFFSET(struct section_problem_data, valuer_sets_marked) },
  [CNTSPROB_ignore_unmarked] = { CNTSPROB_ignore_unmarked, 'f', XSIZE(struct section_problem_data, ignore_unmarked), "ignore_unmarked", XOFFSET(struct section_problem_data, ignore_unmarked) },
  [CNTSPROB_disable_stderr] = { CNTSPROB_disable_stderr, 'f', XSIZE(struct section_problem_data, disable_stderr), "disable_stderr", XOFFSET(struct section_problem_data, disable_stderr) },
  [CNTSPROB_enable_process_group] = { CNTSPROB_enable_process_group, 'f', XSIZE(struct section_problem_data, enable_process_group), "enable_process_group", XOFFSET(struct section_problem_data, enable_process_group) },
  [CNTSPROB_enable_kill_all] = { CNTSPROB_enable_kill_all, 'f', XSIZE(struct section_problem_data, enable_kill_all), "enable_kill_all", XOFFSET(struct section_problem_data, enable_kill_all) },
  [CNTSPROB_hide_variant] = { CNTSPROB_hide_variant, 'f', XSIZE(struct section_problem_data, hide_variant), "hide_variant", XOFFSET(struct section_problem_data, hide_variant) },
  [CNTSPROB_enable_testlib_mode] = { CNTSPROB_enable_testlib_mode, 'f', XSIZE(struct section_problem_data, enable_testlib_mode), "enable_testlib_mode", XOFFSET(struct section_problem_data, enable_testlib_mode) },
  [CNTSPROB_autoassign_variants] = { CNTSPROB_autoassign_variants, 'f', XSIZE(struct section_problem_data, autoassign_variants), "autoassign_variants", XOFFSET(struct section_problem_data, autoassign_variants) },
  [CNTSPROB_require_any] = { CNTSPROB_require_any, 'f', XSIZE(struct section_problem_data, require_any), "require_any", XOFFSET(struct section_problem_data, require_any) },
  [CNTSPROB_enable_extended_info] = { CNTSPROB_enable_extended_info, 'f', XSIZE(struct section_problem_data, enable_extended_info), "enable_extended_info", XOFFSET(struct section_problem_data, enable_extended_info) },
  [CNTSPROB_stop_on_first_fail] = { CNTSPROB_stop_on_first_fail, 'f', XSIZE(struct section_problem_data, stop_on_first_fail), "stop_on_first_fail", XOFFSET(struct section_problem_data, stop_on_first_fail) },
  [CNTSPROB_enable_control_socket] = { CNTSPROB_enable_control_socket, 'f', XSIZE(struct section_problem_data, enable_control_socket), "enable_control_socket", XOFFSET(struct section_problem_data, enable_control_socket) },
  [CNTSPROB_copy_exe_to_tgzdir] = { CNTSPROB_copy_exe_to_tgzdir, 'f', XSIZE(struct section_problem_data, copy_exe_to_tgzdir), "copy_exe_to_tgzdir", XOFFSET(struct section_problem_data, copy_exe_to_tgzdir) },
  [CNTSPROB_enable_multi_header] = { CNTSPROB_enable_multi_header, 'f', XSIZE(struct section_problem_data, enable_multi_header), "enable_multi_header", XOFFSET(struct section_problem_data, enable_multi_header) },
  [CNTSPROB_use_lang_multi_header] = { CNTSPROB_use_lang_multi_header, 'f', XSIZE(struct section_problem_data, use_lang_multi_header), "use_lang_multi_header", XOFFSET(struct section_problem_data, use_lang_multi_header) },
  [CNTSPROB_notify_on_submit] = { CNTSPROB_notify_on_submit, 'f', XSIZE(struct section_problem_data, notify_on_submit), "notify_on_submit", XOFFSET(struct section_problem_data, notify_on_submit) },
  [CNTSPROB_enable_user_input] = { CNTSPROB_enable_user_input, 'f', XSIZE(struct section_problem_data, enable_user_input), "enable_user_input", XOFFSET(struct section_problem_data, enable_user_input) },
  [CNTSPROB_enable_vcs] = { CNTSPROB_enable_vcs, 'f', XSIZE(struct section_problem_data, enable_vcs), "enable_vcs", XOFFSET(struct section_problem_data, enable_vcs) },
  [CNTSPROB_enable_iframe_statement] = { CNTSPROB_enable_iframe_statement, 'f', XSIZE(struct section_problem_data, enable_iframe_statement), "enable_iframe_statement", XOFFSET(struct section_problem_data, enable_iframe_statement) },
  [CNTSPROB_enable_src_for_testing] = { CNTSPROB_enable_src_for_testing, 'f', XSIZE(struct section_problem_data, enable_src_for_testing), "enable_src_for_testing", XOFFSET(struct section_problem_data, enable_src_for_testing) },
  [CNTSPROB_disable_vm_size_limit] = { CNTSPROB_disable_vm_size_limit, 'f', XSIZE(struct section_problem_data, disable_vm_size_limit), "disable_vm_size_limit", XOFFSET(struct section_problem_data, disable_vm_size_limit) },
  [CNTSPROB_examinator_num] = { CNTSPROB_examinator_num, 'i', XSIZE(struct section_problem_data, examinator_num), "examinator_num", XOFFSET(struct section_problem_data, examinator_num) },
  [CNTSPROB_real_time_limit] = { CNTSPROB_real_time_limit, 'i', XSIZE(struct section_problem_data, real_time_limit), "real_time_limit", XOFFSET(struct section_problem_data, real_time_limit) },
  [CNTSPROB_time_limit] = { CNTSPROB_time_limit, 'i', XSIZE(struct section_problem_data, time_limit), "time_limit", XOFFSET(struct section_problem_data, time_limit) },
  [CNTSPROB_time_limit_millis] = { CNTSPROB_time_limit_millis, 'i', XSIZE(struct section_problem_data, time_limit_millis), "time_limit_millis", XOFFSET(struct section_problem_data, time_limit_millis) },
  [CNTSPROB_test_score] = { CNTSPROB_test_score, 'i', XSIZE(struct section_problem_data, test_score), "test_score", XOFFSET(struct section_problem_data, test_score) },
  [CNTSPROB_run_penalty] = { CNTSPROB_run_penalty, 'i', XSIZE(struct section_problem_data, run_penalty), "run_penalty", XOFFSET(struct section_problem_data, run_penalty) },
  [CNTSPROB_acm_run_penalty] = { CNTSPROB_acm_run_penalty, 'i', XSIZE(struct section_problem_data, acm_run_penalty), "acm_run_penalty", XOFFSET(struct section_problem_data, acm_run_penalty) },
  [CNTSPROB_disqualified_penalty] = { CNTSPROB_disqualified_penalty, 'i', XSIZE(struct section_problem_data, disqualified_penalty), "disqualified_penalty", XOFFSET(struct section_problem_data, disqualified_penalty) },
  [CNTSPROB_compile_error_penalty] = { CNTSPROB_compile_error_penalty, 'i', XSIZE(struct section_problem_data, compile_error_penalty), "compile_error_penalty", XOFFSET(struct section_problem_data, compile_error_penalty) },
  [CNTSPROB_tests_to_accept] = { CNTSPROB_tests_to_accept, 'i', XSIZE(struct section_problem_data, tests_to_accept), "tests_to_accept", XOFFSET(struct section_problem_data, tests_to_accept) },
  [CNTSPROB_min_tests_to_accept] = { CNTSPROB_min_tests_to_accept, 'i', XSIZE(struct section_problem_data, min_tests_to_accept), "min_tests_to_accept", XOFFSET(struct section_problem_data, min_tests_to_accept) },
  [CNTSPROB_checker_real_time_limit] = { CNTSPROB_checker_real_time_limit, 'i', XSIZE(struct section_problem_data, checker_real_time_limit), "checker_real_time_limit", XOFFSET(struct section_problem_data, checker_real_time_limit) },
  [CNTSPROB_checker_time_limit_ms] = { CNTSPROB_checker_time_limit_ms, 'i', XSIZE(struct section_problem_data, checker_time_limit_ms), "checker_time_limit_ms", XOFFSET(struct section_problem_data, checker_time_limit_ms) },
  [CNTSPROB_priority_adjustment] = { CNTSPROB_priority_adjustment, 'i', XSIZE(struct section_problem_data, priority_adjustment), "priority_adjustment", XOFFSET(struct section_problem_data, priority_adjustment) },
  [CNTSPROB_score_multiplier] = { CNTSPROB_score_multiplier, 'i', XSIZE(struct section_problem_data, score_multiplier), "score_multiplier", XOFFSET(struct section_problem_data, score_multiplier) },
  [CNTSPROB_prev_runs_to_show] = { CNTSPROB_prev_runs_to_show, 'i', XSIZE(struct section_problem_data, prev_runs_to_show), "prev_runs_to_show", XOFFSET(struct section_problem_data, prev_runs_to_show) },
  [CNTSPROB_max_user_run_count] = { CNTSPROB_max_user_run_count, 'i', XSIZE(struct section_problem_data, max_user_run_count), "max_user_run_count", XOFFSET(struct section_problem_data, max_user_run_count) },
  [CNTSPROB_long_name] = { CNTSPROB_long_name, 's', XSIZE(struct section_problem_data, long_name), "long_name", XOFFSET(struct section_problem_data, long_name) },
  [CNTSPROB_stand_name] = { CNTSPROB_stand_name, 's', XSIZE(struct section_problem_data, stand_name), "stand_name", XOFFSET(struct section_problem_data, stand_name) },
  [CNTSPROB_stand_column] = { CNTSPROB_stand_column, 's', XSIZE(struct section_problem_data, stand_column), "stand_column", XOFFSET(struct section_problem_data, stand_column) },
  [CNTSPROB_group_name] = { CNTSPROB_group_name, 's', XSIZE(struct section_problem_data, group_name), "group_name", XOFFSET(struct section_problem_data, group_name) },
  [CNTSPROB_internal_name] = { CNTSPROB_internal_name, 's', XSIZE(struct section_problem_data, internal_name), "internal_name", XOFFSET(struct section_problem_data, internal_name) },
  [CNTSPROB_plugin_entry_name] = { CNTSPROB_plugin_entry_name, 's', XSIZE(struct section_problem_data, plugin_entry_name), "plugin_entry_name", XOFFSET(struct section_problem_data, plugin_entry_name) },
  [CNTSPROB_uuid] = { CNTSPROB_uuid, 's', XSIZE(struct section_problem_data, uuid), "uuid", XOFFSET(struct section_problem_data, uuid) },
  [CNTSPROB_problem_dir] = { CNTSPROB_problem_dir, 's', XSIZE(struct section_problem_data, problem_dir), "problem_dir", XOFFSET(struct section_problem_data, problem_dir) },
  [CNTSPROB_test_dir] = { CNTSPROB_test_dir, 's', XSIZE(struct section_problem_data, test_dir), "test_dir", XOFFSET(struct section_problem_data, test_dir) },
  [CNTSPROB_test_sfx] = { CNTSPROB_test_sfx, 's', XSIZE(struct section_problem_data, test_sfx), "test_sfx", XOFFSET(struct section_problem_data, test_sfx) },
  [CNTSPROB_corr_dir] = { CNTSPROB_corr_dir, 's', XSIZE(struct section_problem_data, corr_dir), "corr_dir", XOFFSET(struct section_problem_data, corr_dir) },
  [CNTSPROB_corr_sfx] = { CNTSPROB_corr_sfx, 's', XSIZE(struct section_problem_data, corr_sfx), "corr_sfx", XOFFSET(struct section_problem_data, corr_sfx) },
  [CNTSPROB_info_dir] = { CNTSPROB_info_dir, 's', XSIZE(struct section_problem_data, info_dir), "info_dir", XOFFSET(struct section_problem_data, info_dir) },
  [CNTSPROB_info_sfx] = { CNTSPROB_info_sfx, 's', XSIZE(struct section_problem_data, info_sfx), "info_sfx", XOFFSET(struct section_problem_data, info_sfx) },
  [CNTSPROB_tgz_dir] = { CNTSPROB_tgz_dir, 's', XSIZE(struct section_problem_data, tgz_dir), "tgz_dir", XOFFSET(struct section_problem_data, tgz_dir) },
  [CNTSPROB_tgz_sfx] = { CNTSPROB_tgz_sfx, 's', XSIZE(struct section_problem_data, tgz_sfx), "tgz_sfx", XOFFSET(struct section_problem_data, tgz_sfx) },
  [CNTSPROB_tgzdir_sfx] = { CNTSPROB_tgzdir_sfx, 's', XSIZE(struct section_problem_data, tgzdir_sfx), "tgzdir_sfx", XOFFSET(struct section_problem_data, tgzdir_sfx) },
  [CNTSPROB_input_file] = { CNTSPROB_input_file, 's', XSIZE(struct section_problem_data, input_file), "input_file", XOFFSET(struct section_problem_data, input_file) },
  [CNTSPROB_output_file] = { CNTSPROB_output_file, 's', XSIZE(struct section_problem_data, output_file), "output_file", XOFFSET(struct section_problem_data, output_file) },
  [CNTSPROB_test_score_list] = { CNTSPROB_test_score_list, 's', XSIZE(struct section_problem_data, test_score_list), "test_score_list", XOFFSET(struct section_problem_data, test_score_list) },
  [CNTSPROB_tokens] = { CNTSPROB_tokens, 's', XSIZE(struct section_problem_data, tokens), "tokens", XOFFSET(struct section_problem_data, tokens) },
  [CNTSPROB_umask] = { CNTSPROB_umask, 's', XSIZE(struct section_problem_data, umask), "umask", XOFFSET(struct section_problem_data, umask) },
  [CNTSPROB_ok_status] = { CNTSPROB_ok_status, 's', XSIZE(struct section_problem_data, ok_status), "ok_status", XOFFSET(struct section_problem_data, ok_status) },
  [CNTSPROB_header_pat] = { CNTSPROB_header_pat, 's', XSIZE(struct section_problem_data, header_pat), "header_pat", XOFFSET(struct section_problem_data, header_pat) },
  [CNTSPROB_footer_pat] = { CNTSPROB_footer_pat, 's', XSIZE(struct section_problem_data, footer_pat), "footer_pat", XOFFSET(struct section_problem_data, footer_pat) },
  [CNTSPROB_compiler_env_pat] = { CNTSPROB_compiler_env_pat, 's', XSIZE(struct section_problem_data, compiler_env_pat), "compiler_env_pat", XOFFSET(struct section_problem_data, compiler_env_pat) },
  [CNTSPROB_container_options] = { CNTSPROB_container_options, 's', XSIZE(struct section_problem_data, container_options), "container_options", XOFFSET(struct section_problem_data, container_options) },
  [CNTSPROB_token_info] = { CNTSPROB_token_info, '?', XSIZE(struct section_problem_data, token_info), NULL, XOFFSET(struct section_problem_data, token_info) },
  [CNTSPROB_score_tests] = { CNTSPROB_score_tests, 's', XSIZE(struct section_problem_data, score_tests), "score_tests", XOFFSET(struct section_problem_data, score_tests) },
  [CNTSPROB_standard_checker] = { CNTSPROB_standard_checker, 's', XSIZE(struct section_problem_data, standard_checker), "standard_checker", XOFFSET(struct section_problem_data, standard_checker) },
  [CNTSPROB_spelling] = { CNTSPROB_spelling, 's', XSIZE(struct section_problem_data, spelling), "spelling", XOFFSET(struct section_problem_data, spelling) },
  [CNTSPROB_statement_file] = { CNTSPROB_statement_file, 's', XSIZE(struct section_problem_data, statement_file), "statement_file", XOFFSET(struct section_problem_data, statement_file) },
  [CNTSPROB_alternatives_file] = { CNTSPROB_alternatives_file, 's', XSIZE(struct section_problem_data, alternatives_file), "alternatives_file", XOFFSET(struct section_problem_data, alternatives_file) },
  [CNTSPROB_plugin_file] = { CNTSPROB_plugin_file, 's', XSIZE(struct section_problem_data, plugin_file), "plugin_file", XOFFSET(struct section_problem_data, plugin_file) },
  [CNTSPROB_xml_file] = { CNTSPROB_xml_file, 's', XSIZE(struct section_problem_data, xml_file), "xml_file", XOFFSET(struct section_problem_data, xml_file) },
  [CNTSPROB_stand_attr] = { CNTSPROB_stand_attr, 's', XSIZE(struct section_problem_data, stand_attr), "stand_attr", XOFFSET(struct section_problem_data, stand_attr) },
  [CNTSPROB_source_header] = { CNTSPROB_source_header, 's', XSIZE(struct section_problem_data, source_header), "source_header", XOFFSET(struct section_problem_data, source_header) },
  [CNTSPROB_source_footer] = { CNTSPROB_source_footer, 's', XSIZE(struct section_problem_data, source_footer), "source_footer", XOFFSET(struct section_problem_data, source_footer) },
  [CNTSPROB_interactor_time_limit] = { CNTSPROB_interactor_time_limit, 'i', XSIZE(struct section_problem_data, interactor_time_limit), "interactor_time_limit", XOFFSET(struct section_problem_data, interactor_time_limit) },
  [CNTSPROB_interactor_real_time_limit] = { CNTSPROB_interactor_real_time_limit, 'i', XSIZE(struct section_problem_data, interactor_real_time_limit), "interactor_real_time_limit", XOFFSET(struct section_problem_data, interactor_real_time_limit) },
  [CNTSPROB_custom_compile_cmd] = { CNTSPROB_custom_compile_cmd, 's', XSIZE(struct section_problem_data, custom_compile_cmd), "custom_compile_cmd", XOFFSET(struct section_problem_data, custom_compile_cmd) },
  [CNTSPROB_custom_lang_name] = { CNTSPROB_custom_lang_name, 's', XSIZE(struct section_problem_data, custom_lang_name), "custom_lang_name", XOFFSET(struct section_problem_data, custom_lang_name) },
  [CNTSPROB_extra_src_dir] = { CNTSPROB_extra_src_dir, 's', XSIZE(struct section_problem_data, extra_src_dir), "extra_src_dir", XOFFSET(struct section_problem_data, extra_src_dir) },
  [CNTSPROB_test_pat] = { CNTSPROB_test_pat, 's', XSIZE(struct section_problem_data, test_pat), "test_pat", XOFFSET(struct section_problem_data, test_pat) },
  [CNTSPROB_corr_pat] = { CNTSPROB_corr_pat, 's', XSIZE(struct section_problem_data, corr_pat), "corr_pat", XOFFSET(struct section_problem_data, corr_pat) },
  [CNTSPROB_info_pat] = { CNTSPROB_info_pat, 's', XSIZE(struct section_problem_data, info_pat), "info_pat", XOFFSET(struct section_problem_data, info_pat) },
  [CNTSPROB_tgz_pat] = { CNTSPROB_tgz_pat, 's', XSIZE(struct section_problem_data, tgz_pat), "tgz_pat", XOFFSET(struct section_problem_data, tgz_pat) },
  [CNTSPROB_tgzdir_pat] = { CNTSPROB_tgzdir_pat, 's', XSIZE(struct section_problem_data, tgzdir_pat), "tgzdir_pat", XOFFSET(struct section_problem_data, tgzdir_pat) },
  [CNTSPROB_ntests] = { CNTSPROB_ntests, 'i', XSIZE(struct section_problem_data, ntests), NULL, XOFFSET(struct section_problem_data, ntests) },
  [CNTSPROB_tscores] = { CNTSPROB_tscores, '?', XSIZE(struct section_problem_data, tscores), NULL, XOFFSET(struct section_problem_data, tscores) },
  [CNTSPROB_x_score_tests] = { CNTSPROB_x_score_tests, '?', XSIZE(struct section_problem_data, x_score_tests), NULL, XOFFSET(struct section_problem_data, x_score_tests) },
  [CNTSPROB_test_sets] = { CNTSPROB_test_sets, 'x', XSIZE(struct section_problem_data, test_sets), "test_sets", XOFFSET(struct section_problem_data, test_sets) },
  [CNTSPROB_ts_total] = { CNTSPROB_ts_total, 'i', XSIZE(struct section_problem_data, ts_total), NULL, XOFFSET(struct section_problem_data, ts_total) },
  [CNTSPROB_ts_infos] = { CNTSPROB_ts_infos, '?', XSIZE(struct section_problem_data, ts_infos), NULL, XOFFSET(struct section_problem_data, ts_infos) },
  [CNTSPROB_normalization] = { CNTSPROB_normalization, 's', XSIZE(struct section_problem_data, normalization), "normalization", XOFFSET(struct section_problem_data, normalization) },
  [CNTSPROB_normalization_val] = { CNTSPROB_normalization_val, 'i', XSIZE(struct section_problem_data, normalization_val), NULL, XOFFSET(struct section_problem_data, normalization_val) },
  [CNTSPROB_deadline] = { CNTSPROB_deadline, 't', XSIZE(struct section_problem_data, deadline), "deadline", XOFFSET(struct section_problem_data, deadline) },
  [CNTSPROB_start_date] = { CNTSPROB_start_date, 't', XSIZE(struct section_problem_data, start_date), "start_date", XOFFSET(struct section_problem_data, start_date) },
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
  [CNTSPROB_allow_ip] = { CNTSPROB_allow_ip, 'x', XSIZE(struct section_problem_data, allow_ip), "allow_ip", XOFFSET(struct section_problem_data, allow_ip) },
  [CNTSPROB_lang_compiler_env] = { CNTSPROB_lang_compiler_env, 'X', XSIZE(struct section_problem_data, lang_compiler_env), "lang_compiler_env", XOFFSET(struct section_problem_data, lang_compiler_env) },
  [CNTSPROB_lang_compiler_container_options] = { CNTSPROB_lang_compiler_container_options, 'X', XSIZE(struct section_problem_data, lang_compiler_container_options), "lang_compiler_container_options", XOFFSET(struct section_problem_data, lang_compiler_container_options) },
  [CNTSPROB_checker_env] = { CNTSPROB_checker_env, 'X', XSIZE(struct section_problem_data, checker_env), "checker_env", XOFFSET(struct section_problem_data, checker_env) },
  [CNTSPROB_valuer_env] = { CNTSPROB_valuer_env, 'X', XSIZE(struct section_problem_data, valuer_env), "valuer_env", XOFFSET(struct section_problem_data, valuer_env) },
  [CNTSPROB_interactor_env] = { CNTSPROB_interactor_env, 'X', XSIZE(struct section_problem_data, interactor_env), "interactor_env", XOFFSET(struct section_problem_data, interactor_env) },
  [CNTSPROB_style_checker_env] = { CNTSPROB_style_checker_env, 'X', XSIZE(struct section_problem_data, style_checker_env), "style_checker_env", XOFFSET(struct section_problem_data, style_checker_env) },
  [CNTSPROB_test_checker_env] = { CNTSPROB_test_checker_env, 'X', XSIZE(struct section_problem_data, test_checker_env), "test_checker_env", XOFFSET(struct section_problem_data, test_checker_env) },
  [CNTSPROB_test_generator_env] = { CNTSPROB_test_generator_env, 'X', XSIZE(struct section_problem_data, test_generator_env), "test_generator_env", XOFFSET(struct section_problem_data, test_generator_env) },
  [CNTSPROB_init_env] = { CNTSPROB_init_env, 'X', XSIZE(struct section_problem_data, init_env), "init_env", XOFFSET(struct section_problem_data, init_env) },
  [CNTSPROB_start_env] = { CNTSPROB_start_env, 'X', XSIZE(struct section_problem_data, start_env), "start_env", XOFFSET(struct section_problem_data, start_env) },
  [CNTSPROB_check_cmd] = { CNTSPROB_check_cmd, 's', XSIZE(struct section_problem_data, check_cmd), "check_cmd", XOFFSET(struct section_problem_data, check_cmd) },
  [CNTSPROB_valuer_cmd] = { CNTSPROB_valuer_cmd, 's', XSIZE(struct section_problem_data, valuer_cmd), "valuer_cmd", XOFFSET(struct section_problem_data, valuer_cmd) },
  [CNTSPROB_interactor_cmd] = { CNTSPROB_interactor_cmd, 's', XSIZE(struct section_problem_data, interactor_cmd), "interactor_cmd", XOFFSET(struct section_problem_data, interactor_cmd) },
  [CNTSPROB_style_checker_cmd] = { CNTSPROB_style_checker_cmd, 's', XSIZE(struct section_problem_data, style_checker_cmd), "style_checker_cmd", XOFFSET(struct section_problem_data, style_checker_cmd) },
  [CNTSPROB_test_checker_cmd] = { CNTSPROB_test_checker_cmd, 's', XSIZE(struct section_problem_data, test_checker_cmd), "test_checker_cmd", XOFFSET(struct section_problem_data, test_checker_cmd) },
  [CNTSPROB_test_generator_cmd] = { CNTSPROB_test_generator_cmd, 's', XSIZE(struct section_problem_data, test_generator_cmd), "test_generator_cmd", XOFFSET(struct section_problem_data, test_generator_cmd) },
  [CNTSPROB_init_cmd] = { CNTSPROB_init_cmd, 's', XSIZE(struct section_problem_data, init_cmd), "init_cmd", XOFFSET(struct section_problem_data, init_cmd) },
  [CNTSPROB_start_cmd] = { CNTSPROB_start_cmd, 's', XSIZE(struct section_problem_data, start_cmd), "start_cmd", XOFFSET(struct section_problem_data, start_cmd) },
  [CNTSPROB_solution_src] = { CNTSPROB_solution_src, 's', XSIZE(struct section_problem_data, solution_src), "solution_src", XOFFSET(struct section_problem_data, solution_src) },
  [CNTSPROB_solution_cmd] = { CNTSPROB_solution_cmd, 's', XSIZE(struct section_problem_data, solution_cmd), "solution_cmd", XOFFSET(struct section_problem_data, solution_cmd) },
  [CNTSPROB_post_pull_cmd] = { CNTSPROB_post_pull_cmd, 's', XSIZE(struct section_problem_data, post_pull_cmd), "post_pull_cmd", XOFFSET(struct section_problem_data, post_pull_cmd) },
  [CNTSPROB_vcs_compile_cmd] = { CNTSPROB_vcs_compile_cmd, 's', XSIZE(struct section_problem_data, vcs_compile_cmd), "vcs_compile_cmd", XOFFSET(struct section_problem_data, vcs_compile_cmd) },
  [CNTSPROB_lang_time_adj] = { CNTSPROB_lang_time_adj, 'x', XSIZE(struct section_problem_data, lang_time_adj), "lang_time_adj", XOFFSET(struct section_problem_data, lang_time_adj) },
  [CNTSPROB_lang_time_adj_millis] = { CNTSPROB_lang_time_adj_millis, 'x', XSIZE(struct section_problem_data, lang_time_adj_millis), "lang_time_adj_millis", XOFFSET(struct section_problem_data, lang_time_adj_millis) },
  [CNTSPROB_super_run_dir] = { CNTSPROB_super_run_dir, 's', XSIZE(struct section_problem_data, super_run_dir), "super_run_dir", XOFFSET(struct section_problem_data, super_run_dir) },
  [CNTSPROB_lang_max_vm_size] = { CNTSPROB_lang_max_vm_size, 'x', XSIZE(struct section_problem_data, lang_max_vm_size), "lang_max_vm_size", XOFFSET(struct section_problem_data, lang_max_vm_size) },
  [CNTSPROB_lang_max_stack_size] = { CNTSPROB_lang_max_stack_size, 'x', XSIZE(struct section_problem_data, lang_max_stack_size), "lang_max_stack_size", XOFFSET(struct section_problem_data, lang_max_stack_size) },
  [CNTSPROB_lang_max_rss_size] = { CNTSPROB_lang_max_rss_size, 'x', XSIZE(struct section_problem_data, lang_max_rss_size), "lang_max_rss_size", XOFFSET(struct section_problem_data, lang_max_rss_size) },
  [CNTSPROB_checker_extra_files] = { CNTSPROB_checker_extra_files, 'x', XSIZE(struct section_problem_data, checker_extra_files), "checker_extra_files", XOFFSET(struct section_problem_data, checker_extra_files) },
  [CNTSPROB_statement_env] = { CNTSPROB_statement_env, 'X', XSIZE(struct section_problem_data, statement_env), "statement_env", XOFFSET(struct section_problem_data, statement_env) },
  [CNTSPROB_alternative] = { CNTSPROB_alternative, 'x', XSIZE(struct section_problem_data, alternative), "alternative", XOFFSET(struct section_problem_data, alternative) },
  [CNTSPROB_personal_deadline] = { CNTSPROB_personal_deadline, 'x', XSIZE(struct section_problem_data, personal_deadline), "personal_deadline", XOFFSET(struct section_problem_data, personal_deadline) },
  [CNTSPROB_pd_total] = { CNTSPROB_pd_total, 'i', XSIZE(struct section_problem_data, pd_total), NULL, XOFFSET(struct section_problem_data, pd_total) },
  [CNTSPROB_pd_infos] = { CNTSPROB_pd_infos, '?', XSIZE(struct section_problem_data, pd_infos), NULL, XOFFSET(struct section_problem_data, pd_infos) },
  [CNTSPROB_score_bonus] = { CNTSPROB_score_bonus, 's', XSIZE(struct section_problem_data, score_bonus), "score_bonus", XOFFSET(struct section_problem_data, score_bonus) },
  [CNTSPROB_score_bonus_total] = { CNTSPROB_score_bonus_total, 'i', XSIZE(struct section_problem_data, score_bonus_total), NULL, XOFFSET(struct section_problem_data, score_bonus_total) },
  [CNTSPROB_score_bonus_val] = { CNTSPROB_score_bonus_val, '?', XSIZE(struct section_problem_data, score_bonus_val), NULL, XOFFSET(struct section_problem_data, score_bonus_val) },
  [CNTSPROB_open_tests] = { CNTSPROB_open_tests, 's', XSIZE(struct section_problem_data, open_tests), "open_tests", XOFFSET(struct section_problem_data, open_tests) },
  [CNTSPROB_open_tests_count] = { CNTSPROB_open_tests_count, 'i', XSIZE(struct section_problem_data, open_tests_count), NULL, XOFFSET(struct section_problem_data, open_tests_count) },
  [CNTSPROB_open_tests_val] = { CNTSPROB_open_tests_val, '?', XSIZE(struct section_problem_data, open_tests_val), NULL, XOFFSET(struct section_problem_data, open_tests_val) },
  [CNTSPROB_open_tests_group] = { CNTSPROB_open_tests_group, '?', XSIZE(struct section_problem_data, open_tests_group), NULL, XOFFSET(struct section_problem_data, open_tests_group) },
  [CNTSPROB_final_open_tests] = { CNTSPROB_final_open_tests, 's', XSIZE(struct section_problem_data, final_open_tests), "final_open_tests", XOFFSET(struct section_problem_data, final_open_tests) },
  [CNTSPROB_final_open_tests_count] = { CNTSPROB_final_open_tests_count, 'i', XSIZE(struct section_problem_data, final_open_tests_count), NULL, XOFFSET(struct section_problem_data, final_open_tests_count) },
  [CNTSPROB_final_open_tests_val] = { CNTSPROB_final_open_tests_val, '?', XSIZE(struct section_problem_data, final_open_tests_val), NULL, XOFFSET(struct section_problem_data, final_open_tests_val) },
  [CNTSPROB_final_open_tests_group] = { CNTSPROB_final_open_tests_group, '?', XSIZE(struct section_problem_data, final_open_tests_group), NULL, XOFFSET(struct section_problem_data, final_open_tests_group) },
  [CNTSPROB_token_open_tests] = { CNTSPROB_token_open_tests, 's', XSIZE(struct section_problem_data, token_open_tests), "token_open_tests", XOFFSET(struct section_problem_data, token_open_tests) },
  [CNTSPROB_token_open_tests_count] = { CNTSPROB_token_open_tests_count, 'i', XSIZE(struct section_problem_data, token_open_tests_count), NULL, XOFFSET(struct section_problem_data, token_open_tests_count) },
  [CNTSPROB_token_open_tests_val] = { CNTSPROB_token_open_tests_val, '?', XSIZE(struct section_problem_data, token_open_tests_val), NULL, XOFFSET(struct section_problem_data, token_open_tests_val) },
  [CNTSPROB_token_open_tests_group] = { CNTSPROB_token_open_tests_group, '?', XSIZE(struct section_problem_data, token_open_tests_group), NULL, XOFFSET(struct section_problem_data, token_open_tests_group) },
  [CNTSPROB_max_vm_size] = { CNTSPROB_max_vm_size, 'E', XSIZE(struct section_problem_data, max_vm_size), "max_vm_size", XOFFSET(struct section_problem_data, max_vm_size) },
  [CNTSPROB_max_data_size] = { CNTSPROB_max_data_size, 'E', XSIZE(struct section_problem_data, max_data_size), "max_data_size", XOFFSET(struct section_problem_data, max_data_size) },
  [CNTSPROB_max_stack_size] = { CNTSPROB_max_stack_size, 'E', XSIZE(struct section_problem_data, max_stack_size), "max_stack_size", XOFFSET(struct section_problem_data, max_stack_size) },
  [CNTSPROB_max_rss_size] = { CNTSPROB_max_rss_size, 'E', XSIZE(struct section_problem_data, max_rss_size), "max_rss_size", XOFFSET(struct section_problem_data, max_rss_size) },
  [CNTSPROB_max_core_size] = { CNTSPROB_max_core_size, 'E', XSIZE(struct section_problem_data, max_core_size), "max_core_size", XOFFSET(struct section_problem_data, max_core_size) },
  [CNTSPROB_max_file_size] = { CNTSPROB_max_file_size, 'E', XSIZE(struct section_problem_data, max_file_size), "max_file_size", XOFFSET(struct section_problem_data, max_file_size) },
  [CNTSPROB_checker_max_vm_size] = { CNTSPROB_checker_max_vm_size, 'E', XSIZE(struct section_problem_data, checker_max_vm_size), "checker_max_vm_size", XOFFSET(struct section_problem_data, checker_max_vm_size) },
  [CNTSPROB_checker_max_stack_size] = { CNTSPROB_checker_max_stack_size, 'E', XSIZE(struct section_problem_data, checker_max_stack_size), "checker_max_stack_size", XOFFSET(struct section_problem_data, checker_max_stack_size) },
  [CNTSPROB_checker_max_rss_size] = { CNTSPROB_checker_max_rss_size, 'E', XSIZE(struct section_problem_data, checker_max_rss_size), "checker_max_rss_size", XOFFSET(struct section_problem_data, checker_max_rss_size) },
  [CNTSPROB_max_open_file_count] = { CNTSPROB_max_open_file_count, 'i', XSIZE(struct section_problem_data, max_open_file_count), "max_open_file_count", XOFFSET(struct section_problem_data, max_open_file_count) },
  [CNTSPROB_max_process_count] = { CNTSPROB_max_process_count, 'i', XSIZE(struct section_problem_data, max_process_count), "max_process_count", XOFFSET(struct section_problem_data, max_process_count) },
  [CNTSPROB_extid] = { CNTSPROB_extid, 's', XSIZE(struct section_problem_data, extid), "extid", XOFFSET(struct section_problem_data, extid) },
  [CNTSPROB_unhandled_vars] = { CNTSPROB_unhandled_vars, 's', XSIZE(struct section_problem_data, unhandled_vars), "unhandled_vars", XOFFSET(struct section_problem_data, unhandled_vars) },
  [CNTSPROB_score_view] = { CNTSPROB_score_view, 'x', XSIZE(struct section_problem_data, score_view), "score_view", XOFFSET(struct section_problem_data, score_view) },
  [CNTSPROB_score_view_score] = { CNTSPROB_score_view_score, '?', XSIZE(struct section_problem_data, score_view_score), NULL, XOFFSET(struct section_problem_data, score_view_score) },
  [CNTSPROB_score_view_text] = { CNTSPROB_score_view_text, 'x', XSIZE(struct section_problem_data, score_view_text), "score_view_text", XOFFSET(struct section_problem_data, score_view_text) },
  [CNTSPROB_xml_file_path] = { CNTSPROB_xml_file_path, 's', XSIZE(struct section_problem_data, xml_file_path), NULL, XOFFSET(struct section_problem_data, xml_file_path) },
  [CNTSPROB_var_xml_file_paths] = { CNTSPROB_var_xml_file_paths, 'x', XSIZE(struct section_problem_data, var_xml_file_paths), NULL, XOFFSET(struct section_problem_data, var_xml_file_paths) },
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

void cntsprob_copy(struct section_problem_data *dst, const struct section_problem_data *src)
{
  // hidden g
  dst->id = src->id;
  dst->tester_id = src->tester_id;
  dst->type = src->type;
  dst->variant_num = src->variant_num;
  dst->full_score = src->full_score;
  dst->full_user_score = src->full_user_score;
  dst->min_score_1 = src->min_score_1;
  dst->min_score_2 = src->min_score_2;
  strcpy(dst->super, src->super);
  strcpy(dst->short_name, src->short_name);
  dst->abstract = src->abstract;
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
  dst->examinator_num = src->examinator_num;
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
  if (src->long_name) {
    dst->long_name = strdup(src->long_name);
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
  if (src->problem_dir) {
    dst->problem_dir = strdup(src->problem_dir);
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
  // private token_info
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
  if (src->alternatives_file) {
    dst->alternatives_file = strdup(src->alternatives_file);
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
  dst->interactor_time_limit = src->interactor_time_limit;
  dst->interactor_real_time_limit = src->interactor_real_time_limit;
  if (src->custom_compile_cmd) {
    dst->custom_compile_cmd = strdup(src->custom_compile_cmd);
  }
  if (src->custom_lang_name) {
    dst->custom_lang_name = strdup(src->custom_lang_name);
  }
  if (src->extra_src_dir) {
    dst->extra_src_dir = strdup(src->extra_src_dir);
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
  // private ntests
  // private tscores
  // private x_score_tests
  dst->test_sets = (typeof(dst->test_sets)) sarray_copy((char**) src->test_sets);
  // private ts_total
  // private ts_infos
  if (src->normalization) {
    dst->normalization = strdup(src->normalization);
  }
  // private normalization_val
  dst->deadline = src->deadline;
  dst->start_date = src->start_date;
  dst->date_penalty = (typeof(dst->date_penalty)) sarray_copy((char**) src->date_penalty);
  // private dp_total
  // private dp_infos
  dst->group_start_date = (typeof(dst->group_start_date)) sarray_copy((char**) src->group_start_date);
  dst->group_deadline = (typeof(dst->group_deadline)) sarray_copy((char**) src->group_deadline);
  // private gsd
  // private gdl
  dst->disable_language = (typeof(dst->disable_language)) sarray_copy((char**) src->disable_language);
  dst->enable_language = (typeof(dst->enable_language)) sarray_copy((char**) src->enable_language);
  dst->require = (typeof(dst->require)) sarray_copy((char**) src->require);
  dst->provide_ok = (typeof(dst->provide_ok)) sarray_copy((char**) src->provide_ok);
  dst->allow_ip = (typeof(dst->allow_ip)) sarray_copy((char**) src->allow_ip);
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
  dst->lang_time_adj = (typeof(dst->lang_time_adj)) sarray_copy((char**) src->lang_time_adj);
  dst->lang_time_adj_millis = (typeof(dst->lang_time_adj_millis)) sarray_copy((char**) src->lang_time_adj_millis);
  if (src->super_run_dir) {
    dst->super_run_dir = strdup(src->super_run_dir);
  }
  dst->lang_max_vm_size = (typeof(dst->lang_max_vm_size)) sarray_copy((char**) src->lang_max_vm_size);
  dst->lang_max_stack_size = (typeof(dst->lang_max_stack_size)) sarray_copy((char**) src->lang_max_stack_size);
  dst->lang_max_rss_size = (typeof(dst->lang_max_rss_size)) sarray_copy((char**) src->lang_max_rss_size);
  dst->checker_extra_files = (typeof(dst->checker_extra_files)) sarray_copy((char**) src->checker_extra_files);
  dst->statement_env = (typeof(dst->statement_env)) sarray_copy((char**) src->statement_env);
  dst->alternative = (typeof(dst->alternative)) sarray_copy((char**) src->alternative);
  dst->personal_deadline = (typeof(dst->personal_deadline)) sarray_copy((char**) src->personal_deadline);
  // private pd_total
  // private pd_infos
  if (src->score_bonus) {
    dst->score_bonus = strdup(src->score_bonus);
  }
  // private score_bonus_total
  // private score_bonus_val
  if (src->open_tests) {
    dst->open_tests = strdup(src->open_tests);
  }
  // private open_tests_count
  // private open_tests_val
  // private open_tests_group
  if (src->final_open_tests) {
    dst->final_open_tests = strdup(src->final_open_tests);
  }
  // private final_open_tests_count
  // private final_open_tests_val
  // private final_open_tests_group
  if (src->token_open_tests) {
    dst->token_open_tests = strdup(src->token_open_tests);
  }
  // private token_open_tests_count
  // private token_open_tests_val
  // private token_open_tests_group
  dst->max_vm_size = src->max_vm_size;
  dst->max_data_size = src->max_data_size;
  dst->max_stack_size = src->max_stack_size;
  dst->max_rss_size = src->max_rss_size;
  dst->max_core_size = src->max_core_size;
  dst->max_file_size = src->max_file_size;
  dst->checker_max_vm_size = src->checker_max_vm_size;
  dst->checker_max_stack_size = src->checker_max_stack_size;
  dst->checker_max_rss_size = src->checker_max_rss_size;
  dst->max_open_file_count = src->max_open_file_count;
  dst->max_process_count = src->max_process_count;
  if (src->extid) {
    dst->extid = strdup(src->extid);
  }
  if (src->unhandled_vars) {
    dst->unhandled_vars = strdup(src->unhandled_vars);
  }
  dst->score_view = (typeof(dst->score_view)) sarray_copy((char**) src->score_view);
  // private score_view_score
  dst->score_view_text = (typeof(dst->score_view_text)) sarray_copy((char**) src->score_view_text);
  // private xml_file_path
  // private var_xml_file_paths
  // hidden xml
}

void cntsprob_free(struct section_problem_data *ptr)
{
  // hidden g
  free(ptr->long_name);
  free(ptr->stand_name);
  free(ptr->stand_column);
  free(ptr->group_name);
  free(ptr->internal_name);
  free(ptr->plugin_entry_name);
  free(ptr->uuid);
  free(ptr->problem_dir);
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
  // private token_info
  free(ptr->score_tests);
  free(ptr->standard_checker);
  free(ptr->spelling);
  free(ptr->statement_file);
  free(ptr->alternatives_file);
  free(ptr->plugin_file);
  free(ptr->xml_file);
  free(ptr->stand_attr);
  free(ptr->source_header);
  free(ptr->source_footer);
  free(ptr->custom_compile_cmd);
  free(ptr->custom_lang_name);
  free(ptr->extra_src_dir);
  free(ptr->test_pat);
  free(ptr->corr_pat);
  free(ptr->info_pat);
  free(ptr->tgz_pat);
  free(ptr->tgzdir_pat);
  // private ntests
  // private tscores
  // private x_score_tests
  sarray_free((char**) ptr->test_sets);
  // private ts_total
  // private ts_infos
  free(ptr->normalization);
  // private normalization_val
  sarray_free((char**) ptr->date_penalty);
  // private dp_total
  // private dp_infos
  sarray_free((char**) ptr->group_start_date);
  sarray_free((char**) ptr->group_deadline);
  // private gsd
  // private gdl
  sarray_free((char**) ptr->disable_language);
  sarray_free((char**) ptr->enable_language);
  sarray_free((char**) ptr->require);
  sarray_free((char**) ptr->provide_ok);
  sarray_free((char**) ptr->allow_ip);
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
  sarray_free((char**) ptr->lang_time_adj);
  sarray_free((char**) ptr->lang_time_adj_millis);
  free(ptr->super_run_dir);
  sarray_free((char**) ptr->lang_max_vm_size);
  sarray_free((char**) ptr->lang_max_stack_size);
  sarray_free((char**) ptr->lang_max_rss_size);
  sarray_free((char**) ptr->checker_extra_files);
  sarray_free((char**) ptr->statement_env);
  sarray_free((char**) ptr->alternative);
  sarray_free((char**) ptr->personal_deadline);
  // private pd_total
  // private pd_infos
  free(ptr->score_bonus);
  // private score_bonus_total
  // private score_bonus_val
  free(ptr->open_tests);
  // private open_tests_count
  // private open_tests_val
  // private open_tests_group
  free(ptr->final_open_tests);
  // private final_open_tests_count
  // private final_open_tests_val
  // private final_open_tests_group
  free(ptr->token_open_tests);
  // private token_open_tests_count
  // private token_open_tests_val
  // private token_open_tests_group
  free(ptr->extid);
  free(ptr->unhandled_vars);
  sarray_free((char**) ptr->score_view);
  // private score_view_score
  sarray_free((char**) ptr->score_view_text);
  // private xml_file_path
  // private var_xml_file_paths
  // hidden xml
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
  (void (*)(void *, const void *))cntsprob_copy,
  (void (*)(void *))cntsprob_free,
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
  [CNTSLANG_enable_suid_run] = { CNTSLANG_enable_suid_run, 'B', XSIZE(struct section_language_data, enable_suid_run), "enable_suid_run", XOFFSET(struct section_language_data, enable_suid_run) },
  [CNTSLANG_is_dos] = { CNTSLANG_is_dos, 'B', XSIZE(struct section_language_data, is_dos), "is_dos", XOFFSET(struct section_language_data, is_dos) },
  [CNTSLANG_short_name] = { CNTSLANG_short_name, 'S', XSIZE(struct section_language_data, short_name), "short_name", XOFFSET(struct section_language_data, short_name) },
  [CNTSLANG_long_name] = { CNTSLANG_long_name, 's', XSIZE(struct section_language_data, long_name), "long_name", XOFFSET(struct section_language_data, long_name) },
  [CNTSLANG_key] = { CNTSLANG_key, 's', XSIZE(struct section_language_data, key), "key", XOFFSET(struct section_language_data, key) },
  [CNTSLANG_arch] = { CNTSLANG_arch, 's', XSIZE(struct section_language_data, arch), "arch", XOFFSET(struct section_language_data, arch) },
  [CNTSLANG_src_sfx] = { CNTSLANG_src_sfx, 'S', XSIZE(struct section_language_data, src_sfx), "src_sfx", XOFFSET(struct section_language_data, src_sfx) },
  [CNTSLANG_exe_sfx] = { CNTSLANG_exe_sfx, 'S', XSIZE(struct section_language_data, exe_sfx), "exe_sfx", XOFFSET(struct section_language_data, exe_sfx) },
  [CNTSLANG_content_type] = { CNTSLANG_content_type, 's', XSIZE(struct section_language_data, content_type), "content_type", XOFFSET(struct section_language_data, content_type) },
  [CNTSLANG_cmd] = { CNTSLANG_cmd, 's', XSIZE(struct section_language_data, cmd), "cmd", XOFFSET(struct section_language_data, cmd) },
  [CNTSLANG_style_checker_cmd] = { CNTSLANG_style_checker_cmd, 's', XSIZE(struct section_language_data, style_checker_cmd), "style_checker_cmd", XOFFSET(struct section_language_data, style_checker_cmd) },
  [CNTSLANG_style_checker_env] = { CNTSLANG_style_checker_env, 'X', XSIZE(struct section_language_data, style_checker_env), "style_checker_env", XOFFSET(struct section_language_data, style_checker_env) },
  [CNTSLANG_extid] = { CNTSLANG_extid, 's', XSIZE(struct section_language_data, extid), "extid", XOFFSET(struct section_language_data, extid) },
  [CNTSLANG_super_run_dir] = { CNTSLANG_super_run_dir, 's', XSIZE(struct section_language_data, super_run_dir), "super_run_dir", XOFFSET(struct section_language_data, super_run_dir) },
  [CNTSLANG_disable_auto_testing] = { CNTSLANG_disable_auto_testing, 'B', XSIZE(struct section_language_data, disable_auto_testing), "disable_auto_testing", XOFFSET(struct section_language_data, disable_auto_testing) },
  [CNTSLANG_disable_testing] = { CNTSLANG_disable_testing, 'B', XSIZE(struct section_language_data, disable_testing), "disable_testing", XOFFSET(struct section_language_data, disable_testing) },
  [CNTSLANG_enable_custom] = { CNTSLANG_enable_custom, 'B', XSIZE(struct section_language_data, enable_custom), "enable_custom", XOFFSET(struct section_language_data, enable_custom) },
  [CNTSLANG_enable_ejudge_env] = { CNTSLANG_enable_ejudge_env, 'B', XSIZE(struct section_language_data, enable_ejudge_env), "enable_ejudge_env", XOFFSET(struct section_language_data, enable_ejudge_env) },
  [CNTSLANG_preserve_line_numbers] = { CNTSLANG_preserve_line_numbers, 'B', XSIZE(struct section_language_data, preserve_line_numbers), "preserve_line_numbers", XOFFSET(struct section_language_data, preserve_line_numbers) },
  [CNTSLANG_max_vm_size] = { CNTSLANG_max_vm_size, 'E', XSIZE(struct section_language_data, max_vm_size), "max_vm_size", XOFFSET(struct section_language_data, max_vm_size) },
  [CNTSLANG_max_stack_size] = { CNTSLANG_max_stack_size, 'E', XSIZE(struct section_language_data, max_stack_size), "max_stack_size", XOFFSET(struct section_language_data, max_stack_size) },
  [CNTSLANG_max_file_size] = { CNTSLANG_max_file_size, 'E', XSIZE(struct section_language_data, max_file_size), "max_file_size", XOFFSET(struct section_language_data, max_file_size) },
  [CNTSLANG_max_rss_size] = { CNTSLANG_max_rss_size, 'E', XSIZE(struct section_language_data, max_rss_size), "max_rss_size", XOFFSET(struct section_language_data, max_rss_size) },
  [CNTSLANG_run_max_stack_size] = { CNTSLANG_run_max_stack_size, 'E', XSIZE(struct section_language_data, run_max_stack_size), "run_max_stack_size", XOFFSET(struct section_language_data, run_max_stack_size) },
  [CNTSLANG_run_max_vm_size] = { CNTSLANG_run_max_vm_size, 'E', XSIZE(struct section_language_data, run_max_vm_size), "run_max_vm_size", XOFFSET(struct section_language_data, run_max_vm_size) },
  [CNTSLANG_run_max_rss_size] = { CNTSLANG_run_max_rss_size, 'E', XSIZE(struct section_language_data, run_max_rss_size), "run_max_rss_size", XOFFSET(struct section_language_data, run_max_rss_size) },
  [CNTSLANG_compile_dir_index] = { CNTSLANG_compile_dir_index, 'i', XSIZE(struct section_language_data, compile_dir_index), "compile_dir_index", XOFFSET(struct section_language_data, compile_dir_index) },
  [CNTSLANG_compile_dir] = { CNTSLANG_compile_dir, 's', XSIZE(struct section_language_data, compile_dir), "compile_dir", XOFFSET(struct section_language_data, compile_dir) },
  [CNTSLANG_compile_queue_dir] = { CNTSLANG_compile_queue_dir, 's', XSIZE(struct section_language_data, compile_queue_dir), "compile_queue_dir", XOFFSET(struct section_language_data, compile_queue_dir) },
  [CNTSLANG_compile_src_dir] = { CNTSLANG_compile_src_dir, 's', XSIZE(struct section_language_data, compile_src_dir), "compile_src_dir", XOFFSET(struct section_language_data, compile_src_dir) },
  [CNTSLANG_compile_out_dir] = { CNTSLANG_compile_out_dir, 's', XSIZE(struct section_language_data, compile_out_dir), "compile_out_dir", XOFFSET(struct section_language_data, compile_out_dir) },
  [CNTSLANG_compile_status_dir] = { CNTSLANG_compile_status_dir, 's', XSIZE(struct section_language_data, compile_status_dir), "compile_status_dir", XOFFSET(struct section_language_data, compile_status_dir) },
  [CNTSLANG_compile_report_dir] = { CNTSLANG_compile_report_dir, 's', XSIZE(struct section_language_data, compile_report_dir), "compile_report_dir", XOFFSET(struct section_language_data, compile_report_dir) },
  [CNTSLANG_compiler_env] = { CNTSLANG_compiler_env, 'X', XSIZE(struct section_language_data, compiler_env), "compiler_env", XOFFSET(struct section_language_data, compiler_env) },
  [CNTSLANG_compile_server_id] = { CNTSLANG_compile_server_id, 's', XSIZE(struct section_language_data, compile_server_id), "compile_server_id", XOFFSET(struct section_language_data, compile_server_id) },
  [CNTSLANG_multi_header_suffix] = { CNTSLANG_multi_header_suffix, 's', XSIZE(struct section_language_data, multi_header_suffix), "multi_header_suffix", XOFFSET(struct section_language_data, multi_header_suffix) },
  [CNTSLANG_container_options] = { CNTSLANG_container_options, 's', XSIZE(struct section_language_data, container_options), "container_options", XOFFSET(struct section_language_data, container_options) },
  [CNTSLANG_compiler_container_options] = { CNTSLANG_compiler_container_options, 's', XSIZE(struct section_language_data, compiler_container_options), "compiler_container_options", XOFFSET(struct section_language_data, compiler_container_options) },
  [CNTSLANG_clean_up_cmd] = { CNTSLANG_clean_up_cmd, 's', XSIZE(struct section_language_data, clean_up_cmd), "clean_up_cmd", XOFFSET(struct section_language_data, clean_up_cmd) },
  [CNTSLANG_run_env_file] = { CNTSLANG_run_env_file, 's', XSIZE(struct section_language_data, run_env_file), "run_env_file", XOFFSET(struct section_language_data, run_env_file) },
  [CNTSLANG_clean_up_env_file] = { CNTSLANG_clean_up_env_file, 's', XSIZE(struct section_language_data, clean_up_env_file), "clean_up_env_file", XOFFSET(struct section_language_data, clean_up_env_file) },
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

void cntslang_copy(struct section_language_data *dst, const struct section_language_data *src)
{
  // hidden g
  dst->id = src->id;
  dst->compile_id = src->compile_id;
  dst->disabled = src->disabled;
  dst->compile_real_time_limit = src->compile_real_time_limit;
  dst->binary = src->binary;
  dst->priority_adjustment = src->priority_adjustment;
  dst->insecure = src->insecure;
  dst->disable_security = src->disable_security;
  dst->enable_suid_run = src->enable_suid_run;
  dst->is_dos = src->is_dos;
  strcpy(dst->short_name, src->short_name);
  if (src->long_name) {
    dst->long_name = strdup(src->long_name);
  }
  if (src->key) {
    dst->key = strdup(src->key);
  }
  if (src->arch) {
    dst->arch = strdup(src->arch);
  }
  strcpy(dst->src_sfx, src->src_sfx);
  strcpy(dst->exe_sfx, src->exe_sfx);
  if (src->content_type) {
    dst->content_type = strdup(src->content_type);
  }
  if (src->cmd) {
    dst->cmd = strdup(src->cmd);
  }
  if (src->style_checker_cmd) {
    dst->style_checker_cmd = strdup(src->style_checker_cmd);
  }
  dst->style_checker_env = (typeof(dst->style_checker_env)) sarray_copy((char**) src->style_checker_env);
  if (src->extid) {
    dst->extid = strdup(src->extid);
  }
  if (src->super_run_dir) {
    dst->super_run_dir = strdup(src->super_run_dir);
  }
  dst->disable_auto_testing = src->disable_auto_testing;
  dst->disable_testing = src->disable_testing;
  dst->enable_custom = src->enable_custom;
  dst->enable_ejudge_env = src->enable_ejudge_env;
  dst->preserve_line_numbers = src->preserve_line_numbers;
  dst->max_vm_size = src->max_vm_size;
  dst->max_stack_size = src->max_stack_size;
  dst->max_file_size = src->max_file_size;
  dst->max_rss_size = src->max_rss_size;
  dst->run_max_stack_size = src->run_max_stack_size;
  dst->run_max_vm_size = src->run_max_vm_size;
  dst->run_max_rss_size = src->run_max_rss_size;
  dst->compile_dir_index = src->compile_dir_index;
  if (src->compile_dir) {
    dst->compile_dir = strdup(src->compile_dir);
  }
  if (src->compile_queue_dir) {
    dst->compile_queue_dir = strdup(src->compile_queue_dir);
  }
  if (src->compile_src_dir) {
    dst->compile_src_dir = strdup(src->compile_src_dir);
  }
  if (src->compile_out_dir) {
    dst->compile_out_dir = strdup(src->compile_out_dir);
  }
  if (src->compile_status_dir) {
    dst->compile_status_dir = strdup(src->compile_status_dir);
  }
  if (src->compile_report_dir) {
    dst->compile_report_dir = strdup(src->compile_report_dir);
  }
  dst->compiler_env = (typeof(dst->compiler_env)) sarray_copy((char**) src->compiler_env);
  if (src->compile_server_id) {
    dst->compile_server_id = strdup(src->compile_server_id);
  }
  if (src->multi_header_suffix) {
    dst->multi_header_suffix = strdup(src->multi_header_suffix);
  }
  if (src->container_options) {
    dst->container_options = strdup(src->container_options);
  }
  if (src->compiler_container_options) {
    dst->compiler_container_options = strdup(src->compiler_container_options);
  }
  if (src->clean_up_cmd) {
    dst->clean_up_cmd = strdup(src->clean_up_cmd);
  }
  if (src->run_env_file) {
    dst->run_env_file = strdup(src->run_env_file);
  }
  if (src->clean_up_env_file) {
    dst->clean_up_env_file = strdup(src->clean_up_env_file);
  }
  if (src->unhandled_vars) {
    dst->unhandled_vars = strdup(src->unhandled_vars);
  }
  // private disabled_by_config
}

void cntslang_free(struct section_language_data *ptr)
{
  // hidden g
  free(ptr->long_name);
  free(ptr->key);
  free(ptr->arch);
  free(ptr->content_type);
  free(ptr->cmd);
  free(ptr->style_checker_cmd);
  sarray_free((char**) ptr->style_checker_env);
  free(ptr->extid);
  free(ptr->super_run_dir);
  free(ptr->compile_dir);
  free(ptr->compile_queue_dir);
  free(ptr->compile_src_dir);
  free(ptr->compile_out_dir);
  free(ptr->compile_status_dir);
  free(ptr->compile_report_dir);
  sarray_free((char**) ptr->compiler_env);
  free(ptr->compile_server_id);
  free(ptr->multi_header_suffix);
  free(ptr->container_options);
  free(ptr->compiler_container_options);
  free(ptr->clean_up_cmd);
  free(ptr->run_env_file);
  free(ptr->clean_up_env_file);
  free(ptr->unhandled_vars);
  // private disabled_by_config
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
  (void (*)(void *, const void *))cntslang_copy,
  (void (*)(void *))cntslang_free,
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
  [CNTSTESTER_key] = { CNTSTESTER_key, 's', XSIZE(struct section_tester_data, key), "key", XOFFSET(struct section_tester_data, key) },
  [CNTSTESTER_memory_limit_type] = { CNTSTESTER_memory_limit_type, 's', XSIZE(struct section_tester_data, memory_limit_type), "memory_limit_type", XOFFSET(struct section_tester_data, memory_limit_type) },
  [CNTSTESTER_secure_exec_type] = { CNTSTESTER_secure_exec_type, 's', XSIZE(struct section_tester_data, secure_exec_type), "secure_exec_type", XOFFSET(struct section_tester_data, secure_exec_type) },
  [CNTSTESTER_abstract] = { CNTSTESTER_abstract, 'B', XSIZE(struct section_tester_data, abstract), "abstract", XOFFSET(struct section_tester_data, abstract) },
  [CNTSTESTER_super] = { CNTSTESTER_super, 'x', XSIZE(struct section_tester_data, super), "super", XOFFSET(struct section_tester_data, super) },
  [CNTSTESTER_is_processed] = { CNTSTESTER_is_processed, 'B', XSIZE(struct section_tester_data, is_processed), NULL, XOFFSET(struct section_tester_data, is_processed) },
  [CNTSTESTER_skip_testing] = { CNTSTESTER_skip_testing, 'B', XSIZE(struct section_tester_data, skip_testing), "skip_testing", XOFFSET(struct section_tester_data, skip_testing) },
  [CNTSTESTER_no_core_dump] = { CNTSTESTER_no_core_dump, 'B', XSIZE(struct section_tester_data, no_core_dump), "no_core_dump", XOFFSET(struct section_tester_data, no_core_dump) },
  [CNTSTESTER_enable_memory_limit_error] = { CNTSTESTER_enable_memory_limit_error, 'B', XSIZE(struct section_tester_data, enable_memory_limit_error), "enable_memory_limit_error", XOFFSET(struct section_tester_data, enable_memory_limit_error) },
  [CNTSTESTER_kill_signal] = { CNTSTESTER_kill_signal, 's', XSIZE(struct section_tester_data, kill_signal), "kill_signal", XOFFSET(struct section_tester_data, kill_signal) },
  [CNTSTESTER_max_stack_size] = { CNTSTESTER_max_stack_size, 'Z', XSIZE(struct section_tester_data, max_stack_size), "max_stack_size", XOFFSET(struct section_tester_data, max_stack_size) },
  [CNTSTESTER_max_data_size] = { CNTSTESTER_max_data_size, 'Z', XSIZE(struct section_tester_data, max_data_size), "max_data_size", XOFFSET(struct section_tester_data, max_data_size) },
  [CNTSTESTER_max_vm_size] = { CNTSTESTER_max_vm_size, 'Z', XSIZE(struct section_tester_data, max_vm_size), "max_vm_size", XOFFSET(struct section_tester_data, max_vm_size) },
  [CNTSTESTER_max_rss_size] = { CNTSTESTER_max_rss_size, 'Z', XSIZE(struct section_tester_data, max_rss_size), "max_rss_size", XOFFSET(struct section_tester_data, max_rss_size) },
  [CNTSTESTER_clear_env] = { CNTSTESTER_clear_env, 'B', XSIZE(struct section_tester_data, clear_env), "clear_env", XOFFSET(struct section_tester_data, clear_env) },
  [CNTSTESTER_time_limit_adjustment] = { CNTSTESTER_time_limit_adjustment, 'i', XSIZE(struct section_tester_data, time_limit_adjustment), "time_limit_adjustment", XOFFSET(struct section_tester_data, time_limit_adjustment) },
  [CNTSTESTER_time_limit_adj_millis] = { CNTSTESTER_time_limit_adj_millis, 'i', XSIZE(struct section_tester_data, time_limit_adj_millis), "time_limit_adj_millis", XOFFSET(struct section_tester_data, time_limit_adj_millis) },
  [CNTSTESTER_enable_ejudge_env] = { CNTSTESTER_enable_ejudge_env, 'B', XSIZE(struct section_tester_data, enable_ejudge_env), "enable_ejudge_env", XOFFSET(struct section_tester_data, enable_ejudge_env) },
  [CNTSTESTER_run_dir] = { CNTSTESTER_run_dir, 's', XSIZE(struct section_tester_data, run_dir), "run_dir", XOFFSET(struct section_tester_data, run_dir) },
  [CNTSTESTER_run_queue_dir] = { CNTSTESTER_run_queue_dir, 's', XSIZE(struct section_tester_data, run_queue_dir), "run_queue_dir", XOFFSET(struct section_tester_data, run_queue_dir) },
  [CNTSTESTER_run_exe_dir] = { CNTSTESTER_run_exe_dir, 's', XSIZE(struct section_tester_data, run_exe_dir), "run_exe_dir", XOFFSET(struct section_tester_data, run_exe_dir) },
  [CNTSTESTER_run_out_dir] = { CNTSTESTER_run_out_dir, 's', XSIZE(struct section_tester_data, run_out_dir), "run_out_dir", XOFFSET(struct section_tester_data, run_out_dir) },
  [CNTSTESTER_run_status_dir] = { CNTSTESTER_run_status_dir, 's', XSIZE(struct section_tester_data, run_status_dir), "run_status_dir", XOFFSET(struct section_tester_data, run_status_dir) },
  [CNTSTESTER_run_report_dir] = { CNTSTESTER_run_report_dir, 's', XSIZE(struct section_tester_data, run_report_dir), "run_report_dir", XOFFSET(struct section_tester_data, run_report_dir) },
  [CNTSTESTER_run_team_report_dir] = { CNTSTESTER_run_team_report_dir, 's', XSIZE(struct section_tester_data, run_team_report_dir), "run_team_report_dir", XOFFSET(struct section_tester_data, run_team_report_dir) },
  [CNTSTESTER_run_full_archive_dir] = { CNTSTESTER_run_full_archive_dir, 's', XSIZE(struct section_tester_data, run_full_archive_dir), "run_full_archive_dir", XOFFSET(struct section_tester_data, run_full_archive_dir) },
  [CNTSTESTER_check_dir] = { CNTSTESTER_check_dir, 's', XSIZE(struct section_tester_data, check_dir), "check_dir", XOFFSET(struct section_tester_data, check_dir) },
  [CNTSTESTER_errorcode_file] = { CNTSTESTER_errorcode_file, 's', XSIZE(struct section_tester_data, errorcode_file), "errorcode_file", XOFFSET(struct section_tester_data, errorcode_file) },
  [CNTSTESTER_error_file] = { CNTSTESTER_error_file, 's', XSIZE(struct section_tester_data, error_file), "error_file", XOFFSET(struct section_tester_data, error_file) },
  [CNTSTESTER_prepare_cmd] = { CNTSTESTER_prepare_cmd, 's', XSIZE(struct section_tester_data, prepare_cmd), "prepare_cmd", XOFFSET(struct section_tester_data, prepare_cmd) },
  [CNTSTESTER_start_cmd] = { CNTSTESTER_start_cmd, 's', XSIZE(struct section_tester_data, start_cmd), "start_cmd", XOFFSET(struct section_tester_data, start_cmd) },
  [CNTSTESTER_nwrun_spool_dir] = { CNTSTESTER_nwrun_spool_dir, 's', XSIZE(struct section_tester_data, nwrun_spool_dir), "nwrun_spool_dir", XOFFSET(struct section_tester_data, nwrun_spool_dir) },
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

void cntstester_copy(struct section_tester_data *dst, const struct section_tester_data *src)
{
  // hidden g
  dst->id = src->id;
  strcpy(dst->name, src->name);
  dst->problem = src->problem;
  strcpy(dst->problem_name, src->problem_name);
  dst->any = src->any;
  dst->is_dos = src->is_dos;
  dst->no_redirect = src->no_redirect;
  dst->priority_adjustment = src->priority_adjustment;
  dst->ignore_stderr = src->ignore_stderr;
  strcpy(dst->arch, src->arch);
  if (src->key) {
    dst->key = strdup(src->key);
  }
  if (src->memory_limit_type) {
    dst->memory_limit_type = strdup(src->memory_limit_type);
  }
  if (src->secure_exec_type) {
    dst->secure_exec_type = strdup(src->secure_exec_type);
  }
  dst->abstract = src->abstract;
  dst->super = (typeof(dst->super)) sarray_copy((char**) src->super);
  // private is_processed
  dst->skip_testing = src->skip_testing;
  dst->no_core_dump = src->no_core_dump;
  dst->enable_memory_limit_error = src->enable_memory_limit_error;
  if (src->kill_signal) {
    dst->kill_signal = strdup(src->kill_signal);
  }
  dst->max_stack_size = src->max_stack_size;
  dst->max_data_size = src->max_data_size;
  dst->max_vm_size = src->max_vm_size;
  dst->max_rss_size = src->max_rss_size;
  dst->clear_env = src->clear_env;
  dst->time_limit_adjustment = src->time_limit_adjustment;
  dst->time_limit_adj_millis = src->time_limit_adj_millis;
  dst->enable_ejudge_env = src->enable_ejudge_env;
  if (src->run_dir) {
    dst->run_dir = strdup(src->run_dir);
  }
  if (src->run_queue_dir) {
    dst->run_queue_dir = strdup(src->run_queue_dir);
  }
  if (src->run_exe_dir) {
    dst->run_exe_dir = strdup(src->run_exe_dir);
  }
  if (src->run_out_dir) {
    dst->run_out_dir = strdup(src->run_out_dir);
  }
  if (src->run_status_dir) {
    dst->run_status_dir = strdup(src->run_status_dir);
  }
  if (src->run_report_dir) {
    dst->run_report_dir = strdup(src->run_report_dir);
  }
  if (src->run_team_report_dir) {
    dst->run_team_report_dir = strdup(src->run_team_report_dir);
  }
  if (src->run_full_archive_dir) {
    dst->run_full_archive_dir = strdup(src->run_full_archive_dir);
  }
  if (src->check_dir) {
    dst->check_dir = strdup(src->check_dir);
  }
  if (src->errorcode_file) {
    dst->errorcode_file = strdup(src->errorcode_file);
  }
  if (src->error_file) {
    dst->error_file = strdup(src->error_file);
  }
  if (src->prepare_cmd) {
    dst->prepare_cmd = strdup(src->prepare_cmd);
  }
  if (src->start_cmd) {
    dst->start_cmd = strdup(src->start_cmd);
  }
  if (src->nwrun_spool_dir) {
    dst->nwrun_spool_dir = strdup(src->nwrun_spool_dir);
  }
  dst->start_env = (typeof(dst->start_env)) sarray_copy((char**) src->start_env);
  // private memory_limit_type_val
  // private secure_exec_type_val
}

void cntstester_free(struct section_tester_data *ptr)
{
  // hidden g
  free(ptr->key);
  free(ptr->memory_limit_type);
  free(ptr->secure_exec_type);
  sarray_free((char**) ptr->super);
  // private is_processed
  free(ptr->kill_signal);
  free(ptr->run_dir);
  free(ptr->run_queue_dir);
  free(ptr->run_exe_dir);
  free(ptr->run_out_dir);
  free(ptr->run_status_dir);
  free(ptr->run_report_dir);
  free(ptr->run_team_report_dir);
  free(ptr->run_full_archive_dir);
  free(ptr->check_dir);
  free(ptr->errorcode_file);
  free(ptr->error_file);
  free(ptr->prepare_cmd);
  free(ptr->start_cmd);
  free(ptr->nwrun_spool_dir);
  sarray_free((char**) ptr->start_env);
  // private memory_limit_type_val
  // private secure_exec_type_val
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
  (void (*)(void *, const void *))cntstester_copy,
  (void (*)(void *))cntstester_free,
};

