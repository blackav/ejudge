// This is an auto-generated file, do not edit
// Generated 2008/11/20 15:50:58

#include "prepare_meta.h"
#include "prepare.h"
#include "meta_generic.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_section_global_data_data[] =
{
  [SGLOB_sleep_time] = { SGLOB_sleep_time, 'i', XSIZE(struct section_global_data, sleep_time), "sleep_time", XOFFSET(struct section_global_data, sleep_time) },
  [SGLOB_serve_sleep_time] = { SGLOB_serve_sleep_time, 'i', XSIZE(struct section_global_data, serve_sleep_time), "serve_sleep_time", XOFFSET(struct section_global_data, serve_sleep_time) },
  [SGLOB_contest_time] = { SGLOB_contest_time, 'i', XSIZE(struct section_global_data, contest_time), "contest_time", XOFFSET(struct section_global_data, contest_time) },
  [SGLOB_max_run_size] = { SGLOB_max_run_size, 'z', XSIZE(struct section_global_data, max_run_size), "max_run_size", XOFFSET(struct section_global_data, max_run_size) },
  [SGLOB_max_run_total] = { SGLOB_max_run_total, 'z', XSIZE(struct section_global_data, max_run_total), "max_run_total", XOFFSET(struct section_global_data, max_run_total) },
  [SGLOB_max_run_num] = { SGLOB_max_run_num, 'i', XSIZE(struct section_global_data, max_run_num), "max_run_num", XOFFSET(struct section_global_data, max_run_num) },
  [SGLOB_max_clar_size] = { SGLOB_max_clar_size, 'z', XSIZE(struct section_global_data, max_clar_size), "max_clar_size", XOFFSET(struct section_global_data, max_clar_size) },
  [SGLOB_max_clar_total] = { SGLOB_max_clar_total, 'z', XSIZE(struct section_global_data, max_clar_total), "max_clar_total", XOFFSET(struct section_global_data, max_clar_total) },
  [SGLOB_max_clar_num] = { SGLOB_max_clar_num, 'i', XSIZE(struct section_global_data, max_clar_num), "max_clar_num", XOFFSET(struct section_global_data, max_clar_num) },
  [SGLOB_board_fog_time] = { SGLOB_board_fog_time, 'i', XSIZE(struct section_global_data, board_fog_time), "board_fog_time", XOFFSET(struct section_global_data, board_fog_time) },
  [SGLOB_board_unfog_time] = { SGLOB_board_unfog_time, 'i', XSIZE(struct section_global_data, board_unfog_time), "board_unfog_time", XOFFSET(struct section_global_data, board_unfog_time) },
  [SGLOB_autoupdate_standings] = { SGLOB_autoupdate_standings, 'B', XSIZE(struct section_global_data, autoupdate_standings), "autoupdate_standings", XOFFSET(struct section_global_data, autoupdate_standings) },
  [SGLOB_use_ac_not_ok] = { SGLOB_use_ac_not_ok, 'B', XSIZE(struct section_global_data, use_ac_not_ok), "use_ac_not_ok", XOFFSET(struct section_global_data, use_ac_not_ok) },
  [SGLOB_inactivity_timeout] = { SGLOB_inactivity_timeout, 'i', XSIZE(struct section_global_data, inactivity_timeout), "inactivity_timeout", XOFFSET(struct section_global_data, inactivity_timeout) },
  [SGLOB_disable_auto_testing] = { SGLOB_disable_auto_testing, 'B', XSIZE(struct section_global_data, disable_auto_testing), "disable_auto_testing", XOFFSET(struct section_global_data, disable_auto_testing) },
  [SGLOB_disable_testing] = { SGLOB_disable_testing, 'B', XSIZE(struct section_global_data, disable_testing), "disable_testing", XOFFSET(struct section_global_data, disable_testing) },
  [SGLOB_enable_runlog_merge] = { SGLOB_enable_runlog_merge, 'B', XSIZE(struct section_global_data, enable_runlog_merge), "enable_runlog_merge", XOFFSET(struct section_global_data, enable_runlog_merge) },
  [SGLOB_secure_run] = { SGLOB_secure_run, 'B', XSIZE(struct section_global_data, secure_run), "secure_run", XOFFSET(struct section_global_data, secure_run) },
  [SGLOB_detect_violations] = { SGLOB_detect_violations, 'B', XSIZE(struct section_global_data, detect_violations), "detect_violations", XOFFSET(struct section_global_data, detect_violations) },
  [SGLOB_enable_memory_limit_error] = { SGLOB_enable_memory_limit_error, 'B', XSIZE(struct section_global_data, enable_memory_limit_error), "enable_memory_limit_error", XOFFSET(struct section_global_data, enable_memory_limit_error) },
  [SGLOB_stand_ignore_after] = { SGLOB_stand_ignore_after, 'S', XSIZE(struct section_global_data, stand_ignore_after), "stand_ignore_after", XOFFSET(struct section_global_data, stand_ignore_after) },
  [SGLOB_stand_ignore_after_d] = { SGLOB_stand_ignore_after_d, 't', XSIZE(struct section_global_data, stand_ignore_after_d), NULL, XOFFSET(struct section_global_data, stand_ignore_after_d) },
  [SGLOB_contest_finish_time] = { SGLOB_contest_finish_time, 'S', XSIZE(struct section_global_data, contest_finish_time), "contest_finish_time", XOFFSET(struct section_global_data, contest_finish_time) },
  [SGLOB_contest_finish_time_d] = { SGLOB_contest_finish_time_d, 't', XSIZE(struct section_global_data, contest_finish_time_d), NULL, XOFFSET(struct section_global_data, contest_finish_time_d) },
  [SGLOB_appeal_deadline] = { SGLOB_appeal_deadline, 'S', XSIZE(struct section_global_data, appeal_deadline), "appeal_deadline", XOFFSET(struct section_global_data, appeal_deadline) },
  [SGLOB_appeal_deadline_d] = { SGLOB_appeal_deadline_d, 't', XSIZE(struct section_global_data, appeal_deadline_d), NULL, XOFFSET(struct section_global_data, appeal_deadline_d) },
  [SGLOB_fog_standings_updated] = { SGLOB_fog_standings_updated, 'i', XSIZE(struct section_global_data, fog_standings_updated), NULL, XOFFSET(struct section_global_data, fog_standings_updated) },
  [SGLOB_start_standings_updated] = { SGLOB_start_standings_updated, 'i', XSIZE(struct section_global_data, start_standings_updated), NULL, XOFFSET(struct section_global_data, start_standings_updated) },
  [SGLOB_unfog_standings_updated] = { SGLOB_unfog_standings_updated, 'i', XSIZE(struct section_global_data, unfog_standings_updated), NULL, XOFFSET(struct section_global_data, unfog_standings_updated) },
  [SGLOB_team_enable_src_view] = { SGLOB_team_enable_src_view, 'B', XSIZE(struct section_global_data, team_enable_src_view), "team_enable_src_view", XOFFSET(struct section_global_data, team_enable_src_view) },
  [SGLOB_team_enable_rep_view] = { SGLOB_team_enable_rep_view, 'B', XSIZE(struct section_global_data, team_enable_rep_view), "team_enable_rep_view", XOFFSET(struct section_global_data, team_enable_rep_view) },
  [SGLOB_team_enable_ce_view] = { SGLOB_team_enable_ce_view, 'B', XSIZE(struct section_global_data, team_enable_ce_view), "team_enable_ce_view", XOFFSET(struct section_global_data, team_enable_ce_view) },
  [SGLOB_team_show_judge_report] = { SGLOB_team_show_judge_report, 'B', XSIZE(struct section_global_data, team_show_judge_report), "team_show_judge_report", XOFFSET(struct section_global_data, team_show_judge_report) },
  [SGLOB_disable_clars] = { SGLOB_disable_clars, 'B', XSIZE(struct section_global_data, disable_clars), "disable_clars", XOFFSET(struct section_global_data, disable_clars) },
  [SGLOB_disable_team_clars] = { SGLOB_disable_team_clars, 'B', XSIZE(struct section_global_data, disable_team_clars), "disable_team_clars", XOFFSET(struct section_global_data, disable_team_clars) },
  [SGLOB_disable_submit_after_ok] = { SGLOB_disable_submit_after_ok, 'B', XSIZE(struct section_global_data, disable_submit_after_ok), "disable_submit_after_ok", XOFFSET(struct section_global_data, disable_submit_after_ok) },
  [SGLOB_ignore_compile_errors] = { SGLOB_ignore_compile_errors, 'B', XSIZE(struct section_global_data, ignore_compile_errors), "ignore_compile_errors", XOFFSET(struct section_global_data, ignore_compile_errors) },
  [SGLOB_enable_continue] = { SGLOB_enable_continue, 'B', XSIZE(struct section_global_data, enable_continue), "enable_continue", XOFFSET(struct section_global_data, enable_continue) },
  [SGLOB_enable_report_upload] = { SGLOB_enable_report_upload, 'B', XSIZE(struct section_global_data, enable_report_upload), "enable_report_upload", XOFFSET(struct section_global_data, enable_report_upload) },
  [SGLOB_priority_adjustment] = { SGLOB_priority_adjustment, 'i', XSIZE(struct section_global_data, priority_adjustment), "priority_adjustment", XOFFSET(struct section_global_data, priority_adjustment) },
  [SGLOB_ignore_success_time] = { SGLOB_ignore_success_time, 'B', XSIZE(struct section_global_data, ignore_success_time), "ignore_success_time", XOFFSET(struct section_global_data, ignore_success_time) },
  [SGLOB_disable_failed_test_view] = { SGLOB_disable_failed_test_view, 'B', XSIZE(struct section_global_data, disable_failed_test_view), "disable_failed_test_view", XOFFSET(struct section_global_data, disable_failed_test_view) },
  [SGLOB_always_show_problems] = { SGLOB_always_show_problems, 'B', XSIZE(struct section_global_data, always_show_problems), "always_show_problems", XOFFSET(struct section_global_data, always_show_problems) },
  [SGLOB_disable_user_standings] = { SGLOB_disable_user_standings, 'B', XSIZE(struct section_global_data, disable_user_standings), "disable_user_standings", XOFFSET(struct section_global_data, disable_user_standings) },
  [SGLOB_disable_language] = { SGLOB_disable_language, 'B', XSIZE(struct section_global_data, disable_language), "disable_language", XOFFSET(struct section_global_data, disable_language) },
  [SGLOB_problem_navigation] = { SGLOB_problem_navigation, 'B', XSIZE(struct section_global_data, problem_navigation), "problem_navigation", XOFFSET(struct section_global_data, problem_navigation) },
  [SGLOB_problem_tab_size] = { SGLOB_problem_tab_size, 'i', XSIZE(struct section_global_data, problem_tab_size), "problem_tab_size", XOFFSET(struct section_global_data, problem_tab_size) },
  [SGLOB_vertical_navigation] = { SGLOB_vertical_navigation, 'B', XSIZE(struct section_global_data, vertical_navigation), "vertical_navigation", XOFFSET(struct section_global_data, vertical_navigation) },
  [SGLOB_disable_virtual_start] = { SGLOB_disable_virtual_start, 'B', XSIZE(struct section_global_data, disable_virtual_start), "disable_virtual_start", XOFFSET(struct section_global_data, disable_virtual_start) },
  [SGLOB_disable_virtual_auto_judge] = { SGLOB_disable_virtual_auto_judge, 'B', XSIZE(struct section_global_data, disable_virtual_auto_judge), "disable_virtual_auto_judge", XOFFSET(struct section_global_data, disable_virtual_auto_judge) },
  [SGLOB_enable_auto_print_protocol] = { SGLOB_enable_auto_print_protocol, 'B', XSIZE(struct section_global_data, enable_auto_print_protocol), "enable_auto_print_protocol", XOFFSET(struct section_global_data, enable_auto_print_protocol) },
  [SGLOB_notify_clar_reply] = { SGLOB_notify_clar_reply, 'B', XSIZE(struct section_global_data, notify_clar_reply), "notify_clar_reply", XOFFSET(struct section_global_data, notify_clar_reply) },
  [SGLOB_notify_status_change] = { SGLOB_notify_status_change, 'B', XSIZE(struct section_global_data, notify_status_change), "notify_status_change", XOFFSET(struct section_global_data, notify_status_change) },
  [SGLOB_name] = { SGLOB_name, 'S', XSIZE(struct section_global_data, name), "name", XOFFSET(struct section_global_data, name) },
  [SGLOB_root_dir] = { SGLOB_root_dir, 'S', XSIZE(struct section_global_data, root_dir), "root_dir", XOFFSET(struct section_global_data, root_dir) },
  [SGLOB_serve_socket] = { SGLOB_serve_socket, 'S', XSIZE(struct section_global_data, serve_socket), "serve_socket", XOFFSET(struct section_global_data, serve_socket) },
  [SGLOB_enable_l10n] = { SGLOB_enable_l10n, 'B', XSIZE(struct section_global_data, enable_l10n), "enable_l10n", XOFFSET(struct section_global_data, enable_l10n) },
  [SGLOB_l10n_dir] = { SGLOB_l10n_dir, 'S', XSIZE(struct section_global_data, l10n_dir), "l10n_dir", XOFFSET(struct section_global_data, l10n_dir) },
  [SGLOB_standings_locale] = { SGLOB_standings_locale, 'S', XSIZE(struct section_global_data, standings_locale), "standings_locale", XOFFSET(struct section_global_data, standings_locale) },
  [SGLOB_standings_locale_id] = { SGLOB_standings_locale_id, 'i', XSIZE(struct section_global_data, standings_locale_id), NULL, XOFFSET(struct section_global_data, standings_locale_id) },
  [SGLOB_contest_id] = { SGLOB_contest_id, 'i', XSIZE(struct section_global_data, contest_id), "contest_id", XOFFSET(struct section_global_data, contest_id) },
  [SGLOB_socket_path] = { SGLOB_socket_path, 'S', XSIZE(struct section_global_data, socket_path), "socket_path", XOFFSET(struct section_global_data, socket_path) },
  [SGLOB_contests_dir] = { SGLOB_contests_dir, 'S', XSIZE(struct section_global_data, contests_dir), "contests_dir", XOFFSET(struct section_global_data, contests_dir) },
  [SGLOB_lang_config_dir] = { SGLOB_lang_config_dir, 'S', XSIZE(struct section_global_data, lang_config_dir), "lang_config_dir", XOFFSET(struct section_global_data, lang_config_dir) },
  [SGLOB_charset] = { SGLOB_charset, 'S', XSIZE(struct section_global_data, charset), "charset", XOFFSET(struct section_global_data, charset) },
  [SGLOB_standings_charset] = { SGLOB_standings_charset, 'S', XSIZE(struct section_global_data, standings_charset), "standings_charset", XOFFSET(struct section_global_data, standings_charset) },
  [SGLOB_stand2_charset] = { SGLOB_stand2_charset, 'S', XSIZE(struct section_global_data, stand2_charset), "stand2_charset", XOFFSET(struct section_global_data, stand2_charset) },
  [SGLOB_plog_charset] = { SGLOB_plog_charset, 'S', XSIZE(struct section_global_data, plog_charset), "plog_charset", XOFFSET(struct section_global_data, plog_charset) },
  [SGLOB_conf_dir] = { SGLOB_conf_dir, 'S', XSIZE(struct section_global_data, conf_dir), "conf_dir", XOFFSET(struct section_global_data, conf_dir) },
  [SGLOB_script_dir] = { SGLOB_script_dir, 'S', XSIZE(struct section_global_data, script_dir), "script_dir", XOFFSET(struct section_global_data, script_dir) },
  [SGLOB_test_dir] = { SGLOB_test_dir, 'S', XSIZE(struct section_global_data, test_dir), "test_dir", XOFFSET(struct section_global_data, test_dir) },
  [SGLOB_corr_dir] = { SGLOB_corr_dir, 'S', XSIZE(struct section_global_data, corr_dir), "corr_dir", XOFFSET(struct section_global_data, corr_dir) },
  [SGLOB_info_dir] = { SGLOB_info_dir, 'S', XSIZE(struct section_global_data, info_dir), "info_dir", XOFFSET(struct section_global_data, info_dir) },
  [SGLOB_tgz_dir] = { SGLOB_tgz_dir, 'S', XSIZE(struct section_global_data, tgz_dir), "tgz_dir", XOFFSET(struct section_global_data, tgz_dir) },
  [SGLOB_checker_dir] = { SGLOB_checker_dir, 'S', XSIZE(struct section_global_data, checker_dir), "checker_dir", XOFFSET(struct section_global_data, checker_dir) },
  [SGLOB_statement_dir] = { SGLOB_statement_dir, 'S', XSIZE(struct section_global_data, statement_dir), "statement_dir", XOFFSET(struct section_global_data, statement_dir) },
  [SGLOB_plugin_dir] = { SGLOB_plugin_dir, 'S', XSIZE(struct section_global_data, plugin_dir), "plugin_dir", XOFFSET(struct section_global_data, plugin_dir) },
  [SGLOB_test_sfx] = { SGLOB_test_sfx, 'S', XSIZE(struct section_global_data, test_sfx), "test_sfx", XOFFSET(struct section_global_data, test_sfx) },
  [SGLOB_corr_sfx] = { SGLOB_corr_sfx, 'S', XSIZE(struct section_global_data, corr_sfx), "corr_sfx", XOFFSET(struct section_global_data, corr_sfx) },
  [SGLOB_info_sfx] = { SGLOB_info_sfx, 'S', XSIZE(struct section_global_data, info_sfx), "info_sfx", XOFFSET(struct section_global_data, info_sfx) },
  [SGLOB_tgz_sfx] = { SGLOB_tgz_sfx, 'S', XSIZE(struct section_global_data, tgz_sfx), "tgz_sfx", XOFFSET(struct section_global_data, tgz_sfx) },
  [SGLOB_ejudge_checkers_dir] = { SGLOB_ejudge_checkers_dir, 'S', XSIZE(struct section_global_data, ejudge_checkers_dir), "ejudge_checkers_dir", XOFFSET(struct section_global_data, ejudge_checkers_dir) },
  [SGLOB_contest_start_cmd] = { SGLOB_contest_start_cmd, 'S', XSIZE(struct section_global_data, contest_start_cmd), "contest_start_cmd", XOFFSET(struct section_global_data, contest_start_cmd) },
  [SGLOB_description_file] = { SGLOB_description_file, 'S', XSIZE(struct section_global_data, description_file), "description_file", XOFFSET(struct section_global_data, description_file) },
  [SGLOB_contest_plugin_file] = { SGLOB_contest_plugin_file, 'S', XSIZE(struct section_global_data, contest_plugin_file), "contest_plugin_file", XOFFSET(struct section_global_data, contest_plugin_file) },
  [SGLOB_test_pat] = { SGLOB_test_pat, 'S', XSIZE(struct section_global_data, test_pat), "test_pat", XOFFSET(struct section_global_data, test_pat) },
  [SGLOB_corr_pat] = { SGLOB_corr_pat, 'S', XSIZE(struct section_global_data, corr_pat), "corr_pat", XOFFSET(struct section_global_data, corr_pat) },
  [SGLOB_info_pat] = { SGLOB_info_pat, 'S', XSIZE(struct section_global_data, info_pat), "info_pat", XOFFSET(struct section_global_data, info_pat) },
  [SGLOB_tgz_pat] = { SGLOB_tgz_pat, 'S', XSIZE(struct section_global_data, tgz_pat), "tgz_pat", XOFFSET(struct section_global_data, tgz_pat) },
  [SGLOB_clardb_plugin] = { SGLOB_clardb_plugin, 'S', XSIZE(struct section_global_data, clardb_plugin), "clardb_plugin", XOFFSET(struct section_global_data, clardb_plugin) },
  [SGLOB_rundb_plugin] = { SGLOB_rundb_plugin, 'S', XSIZE(struct section_global_data, rundb_plugin), "rundb_plugin", XOFFSET(struct section_global_data, rundb_plugin) },
  [SGLOB_xuser_plugin] = { SGLOB_xuser_plugin, 'S', XSIZE(struct section_global_data, xuser_plugin), "xuser_plugin", XOFFSET(struct section_global_data, xuser_plugin) },
  [SGLOB_var_dir] = { SGLOB_var_dir, 'S', XSIZE(struct section_global_data, var_dir), "var_dir", XOFFSET(struct section_global_data, var_dir) },
  [SGLOB_run_log_file] = { SGLOB_run_log_file, 'S', XSIZE(struct section_global_data, run_log_file), "run_log_file", XOFFSET(struct section_global_data, run_log_file) },
  [SGLOB_clar_log_file] = { SGLOB_clar_log_file, 'S', XSIZE(struct section_global_data, clar_log_file), "clar_log_file", XOFFSET(struct section_global_data, clar_log_file) },
  [SGLOB_archive_dir] = { SGLOB_archive_dir, 'S', XSIZE(struct section_global_data, archive_dir), "archive_dir", XOFFSET(struct section_global_data, archive_dir) },
  [SGLOB_clar_archive_dir] = { SGLOB_clar_archive_dir, 'S', XSIZE(struct section_global_data, clar_archive_dir), "clar_archive_dir", XOFFSET(struct section_global_data, clar_archive_dir) },
  [SGLOB_run_archive_dir] = { SGLOB_run_archive_dir, 'S', XSIZE(struct section_global_data, run_archive_dir), "run_archive_dir", XOFFSET(struct section_global_data, run_archive_dir) },
  [SGLOB_report_archive_dir] = { SGLOB_report_archive_dir, 'S', XSIZE(struct section_global_data, report_archive_dir), "report_archive_dir", XOFFSET(struct section_global_data, report_archive_dir) },
  [SGLOB_team_report_archive_dir] = { SGLOB_team_report_archive_dir, 'S', XSIZE(struct section_global_data, team_report_archive_dir), "team_report_archive_dir", XOFFSET(struct section_global_data, team_report_archive_dir) },
  [SGLOB_xml_report_archive_dir] = { SGLOB_xml_report_archive_dir, 'S', XSIZE(struct section_global_data, xml_report_archive_dir), "xml_report_archive_dir", XOFFSET(struct section_global_data, xml_report_archive_dir) },
  [SGLOB_full_archive_dir] = { SGLOB_full_archive_dir, 'S', XSIZE(struct section_global_data, full_archive_dir), "full_archive_dir", XOFFSET(struct section_global_data, full_archive_dir) },
  [SGLOB_audit_log_dir] = { SGLOB_audit_log_dir, 'S', XSIZE(struct section_global_data, audit_log_dir), "audit_log_dir", XOFFSET(struct section_global_data, audit_log_dir) },
  [SGLOB_team_extra_dir] = { SGLOB_team_extra_dir, 'S', XSIZE(struct section_global_data, team_extra_dir), "team_extra_dir", XOFFSET(struct section_global_data, team_extra_dir) },
  [SGLOB_status_dir] = { SGLOB_status_dir, 'S', XSIZE(struct section_global_data, status_dir), "status_dir", XOFFSET(struct section_global_data, status_dir) },
  [SGLOB_work_dir] = { SGLOB_work_dir, 'S', XSIZE(struct section_global_data, work_dir), "work_dir", XOFFSET(struct section_global_data, work_dir) },
  [SGLOB_print_work_dir] = { SGLOB_print_work_dir, 'S', XSIZE(struct section_global_data, print_work_dir), "print_work_dir", XOFFSET(struct section_global_data, print_work_dir) },
  [SGLOB_diff_work_dir] = { SGLOB_diff_work_dir, 'S', XSIZE(struct section_global_data, diff_work_dir), "diff_work_dir", XOFFSET(struct section_global_data, diff_work_dir) },
  [SGLOB_a2ps_path] = { SGLOB_a2ps_path, 'S', XSIZE(struct section_global_data, a2ps_path), "a2ps_path", XOFFSET(struct section_global_data, a2ps_path) },
  [SGLOB_a2ps_args] = { SGLOB_a2ps_args, 'x', XSIZE(struct section_global_data, a2ps_args), "a2ps_args", XOFFSET(struct section_global_data, a2ps_args) },
  [SGLOB_lpr_path] = { SGLOB_lpr_path, 'S', XSIZE(struct section_global_data, lpr_path), "lpr_path", XOFFSET(struct section_global_data, lpr_path) },
  [SGLOB_lpr_args] = { SGLOB_lpr_args, 'x', XSIZE(struct section_global_data, lpr_args), "lpr_args", XOFFSET(struct section_global_data, lpr_args) },
  [SGLOB_diff_path] = { SGLOB_diff_path, 'S', XSIZE(struct section_global_data, diff_path), "diff_path", XOFFSET(struct section_global_data, diff_path) },
  [SGLOB_compile_dir] = { SGLOB_compile_dir, 'S', XSIZE(struct section_global_data, compile_dir), "compile_dir", XOFFSET(struct section_global_data, compile_dir) },
  [SGLOB_compile_queue_dir] = { SGLOB_compile_queue_dir, 'S', XSIZE(struct section_global_data, compile_queue_dir), "compile_queue_dir", XOFFSET(struct section_global_data, compile_queue_dir) },
  [SGLOB_compile_src_dir] = { SGLOB_compile_src_dir, 'S', XSIZE(struct section_global_data, compile_src_dir), "compile_src_dir", XOFFSET(struct section_global_data, compile_src_dir) },
  [SGLOB_compile_out_dir] = { SGLOB_compile_out_dir, 'S', XSIZE(struct section_global_data, compile_out_dir), "compile_out_dir", XOFFSET(struct section_global_data, compile_out_dir) },
  [SGLOB_compile_status_dir] = { SGLOB_compile_status_dir, 'S', XSIZE(struct section_global_data, compile_status_dir), "compile_status_dir", XOFFSET(struct section_global_data, compile_status_dir) },
  [SGLOB_compile_report_dir] = { SGLOB_compile_report_dir, 'S', XSIZE(struct section_global_data, compile_report_dir), "compile_report_dir", XOFFSET(struct section_global_data, compile_report_dir) },
  [SGLOB_compile_work_dir] = { SGLOB_compile_work_dir, 'S', XSIZE(struct section_global_data, compile_work_dir), "compile_work_dir", XOFFSET(struct section_global_data, compile_work_dir) },
  [SGLOB_run_dir] = { SGLOB_run_dir, 'S', XSIZE(struct section_global_data, run_dir), "run_dir", XOFFSET(struct section_global_data, run_dir) },
  [SGLOB_run_queue_dir] = { SGLOB_run_queue_dir, 'S', XSIZE(struct section_global_data, run_queue_dir), "run_queue_dir", XOFFSET(struct section_global_data, run_queue_dir) },
  [SGLOB_run_exe_dir] = { SGLOB_run_exe_dir, 'S', XSIZE(struct section_global_data, run_exe_dir), "run_exe_dir", XOFFSET(struct section_global_data, run_exe_dir) },
  [SGLOB_run_out_dir] = { SGLOB_run_out_dir, 'S', XSIZE(struct section_global_data, run_out_dir), "run_out_dir", XOFFSET(struct section_global_data, run_out_dir) },
  [SGLOB_run_status_dir] = { SGLOB_run_status_dir, 'S', XSIZE(struct section_global_data, run_status_dir), "run_status_dir", XOFFSET(struct section_global_data, run_status_dir) },
  [SGLOB_run_report_dir] = { SGLOB_run_report_dir, 'S', XSIZE(struct section_global_data, run_report_dir), "run_report_dir", XOFFSET(struct section_global_data, run_report_dir) },
  [SGLOB_run_team_report_dir] = { SGLOB_run_team_report_dir, 'S', XSIZE(struct section_global_data, run_team_report_dir), "run_team_report_dir", XOFFSET(struct section_global_data, run_team_report_dir) },
  [SGLOB_run_full_archive_dir] = { SGLOB_run_full_archive_dir, 'S', XSIZE(struct section_global_data, run_full_archive_dir), "run_full_archive_dir", XOFFSET(struct section_global_data, run_full_archive_dir) },
  [SGLOB_run_work_dir] = { SGLOB_run_work_dir, 'S', XSIZE(struct section_global_data, run_work_dir), "run_work_dir", XOFFSET(struct section_global_data, run_work_dir) },
  [SGLOB_run_check_dir] = { SGLOB_run_check_dir, 'S', XSIZE(struct section_global_data, run_check_dir), "run_check_dir", XOFFSET(struct section_global_data, run_check_dir) },
  [SGLOB_htdocs_dir] = { SGLOB_htdocs_dir, 'S', XSIZE(struct section_global_data, htdocs_dir), "htdocs_dir", XOFFSET(struct section_global_data, htdocs_dir) },
  [SGLOB_score_system] = { SGLOB_score_system, 'S', XSIZE(struct section_global_data, score_system), "score_system", XOFFSET(struct section_global_data, score_system) },
  [SGLOB_score_system_val] = { SGLOB_score_system_val, 'i', XSIZE(struct section_global_data, score_system_val), NULL, XOFFSET(struct section_global_data, score_system_val) },
  [SGLOB_tests_to_accept] = { SGLOB_tests_to_accept, 'i', XSIZE(struct section_global_data, tests_to_accept), "tests_to_accept", XOFFSET(struct section_global_data, tests_to_accept) },
  [SGLOB_is_virtual] = { SGLOB_is_virtual, 'B', XSIZE(struct section_global_data, is_virtual), "is_virtual", XOFFSET(struct section_global_data, is_virtual) },
  [SGLOB_prune_empty_users] = { SGLOB_prune_empty_users, 'B', XSIZE(struct section_global_data, prune_empty_users), "prune_empty_users", XOFFSET(struct section_global_data, prune_empty_users) },
  [SGLOB_rounding_mode] = { SGLOB_rounding_mode, 'S', XSIZE(struct section_global_data, rounding_mode), "rounding_mode", XOFFSET(struct section_global_data, rounding_mode) },
  [SGLOB_rounding_mode_val] = { SGLOB_rounding_mode_val, 'i', XSIZE(struct section_global_data, rounding_mode_val), NULL, XOFFSET(struct section_global_data, rounding_mode_val) },
  [SGLOB_max_file_length] = { SGLOB_max_file_length, 'z', XSIZE(struct section_global_data, max_file_length), "max_file_length", XOFFSET(struct section_global_data, max_file_length) },
  [SGLOB_max_line_length] = { SGLOB_max_line_length, 'z', XSIZE(struct section_global_data, max_line_length), "max_line_length", XOFFSET(struct section_global_data, max_line_length) },
  [SGLOB_max_cmd_length] = { SGLOB_max_cmd_length, 'z', XSIZE(struct section_global_data, max_cmd_length), "max_cmd_length", XOFFSET(struct section_global_data, max_cmd_length) },
  [SGLOB_team_info_url] = { SGLOB_team_info_url, 'S', XSIZE(struct section_global_data, team_info_url), "team_info_url", XOFFSET(struct section_global_data, team_info_url) },
  [SGLOB_prob_info_url] = { SGLOB_prob_info_url, 'S', XSIZE(struct section_global_data, prob_info_url), "prob_info_url", XOFFSET(struct section_global_data, prob_info_url) },
  [SGLOB_standings_file_name] = { SGLOB_standings_file_name, 'S', XSIZE(struct section_global_data, standings_file_name), "standings_file_name", XOFFSET(struct section_global_data, standings_file_name) },
  [SGLOB_stand_header_file] = { SGLOB_stand_header_file, 'S', XSIZE(struct section_global_data, stand_header_file), "stand_header_file", XOFFSET(struct section_global_data, stand_header_file) },
  [SGLOB_stand_footer_file] = { SGLOB_stand_footer_file, 'S', XSIZE(struct section_global_data, stand_footer_file), "stand_footer_file", XOFFSET(struct section_global_data, stand_footer_file) },
  [SGLOB_stand_symlink_dir] = { SGLOB_stand_symlink_dir, 'S', XSIZE(struct section_global_data, stand_symlink_dir), "stand_symlink_dir", XOFFSET(struct section_global_data, stand_symlink_dir) },
  [SGLOB_users_on_page] = { SGLOB_users_on_page, 'i', XSIZE(struct section_global_data, users_on_page), "users_on_page", XOFFSET(struct section_global_data, users_on_page) },
  [SGLOB_stand_file_name_2] = { SGLOB_stand_file_name_2, 'S', XSIZE(struct section_global_data, stand_file_name_2), "stand_file_name_2", XOFFSET(struct section_global_data, stand_file_name_2) },
  [SGLOB_stand_fancy_style] = { SGLOB_stand_fancy_style, 'B', XSIZE(struct section_global_data, stand_fancy_style), "stand_fancy_style", XOFFSET(struct section_global_data, stand_fancy_style) },
  [SGLOB_stand_extra_format] = { SGLOB_stand_extra_format, 'S', XSIZE(struct section_global_data, stand_extra_format), "stand_extra_format", XOFFSET(struct section_global_data, stand_extra_format) },
  [SGLOB_stand_extra_legend] = { SGLOB_stand_extra_legend, 'S', XSIZE(struct section_global_data, stand_extra_legend), "stand_extra_legend", XOFFSET(struct section_global_data, stand_extra_legend) },
  [SGLOB_stand_extra_attr] = { SGLOB_stand_extra_attr, 'S', XSIZE(struct section_global_data, stand_extra_attr), "stand_extra_attr", XOFFSET(struct section_global_data, stand_extra_attr) },
  [SGLOB_stand_table_attr] = { SGLOB_stand_table_attr, 'S', XSIZE(struct section_global_data, stand_table_attr), "stand_table_attr", XOFFSET(struct section_global_data, stand_table_attr) },
  [SGLOB_stand_place_attr] = { SGLOB_stand_place_attr, 'S', XSIZE(struct section_global_data, stand_place_attr), "stand_place_attr", XOFFSET(struct section_global_data, stand_place_attr) },
  [SGLOB_stand_team_attr] = { SGLOB_stand_team_attr, 'S', XSIZE(struct section_global_data, stand_team_attr), "stand_team_attr", XOFFSET(struct section_global_data, stand_team_attr) },
  [SGLOB_stand_prob_attr] = { SGLOB_stand_prob_attr, 'S', XSIZE(struct section_global_data, stand_prob_attr), "stand_prob_attr", XOFFSET(struct section_global_data, stand_prob_attr) },
  [SGLOB_stand_solved_attr] = { SGLOB_stand_solved_attr, 'S', XSIZE(struct section_global_data, stand_solved_attr), "stand_solved_attr", XOFFSET(struct section_global_data, stand_solved_attr) },
  [SGLOB_stand_score_attr] = { SGLOB_stand_score_attr, 'S', XSIZE(struct section_global_data, stand_score_attr), "stand_score_attr", XOFFSET(struct section_global_data, stand_score_attr) },
  [SGLOB_stand_penalty_attr] = { SGLOB_stand_penalty_attr, 'S', XSIZE(struct section_global_data, stand_penalty_attr), "stand_penalty_attr", XOFFSET(struct section_global_data, stand_penalty_attr) },
  [SGLOB_stand_time_attr] = { SGLOB_stand_time_attr, 'S', XSIZE(struct section_global_data, stand_time_attr), "stand_time_attr", XOFFSET(struct section_global_data, stand_time_attr) },
  [SGLOB_stand_self_row_attr] = { SGLOB_stand_self_row_attr, 'S', XSIZE(struct section_global_data, stand_self_row_attr), "stand_self_row_attr", XOFFSET(struct section_global_data, stand_self_row_attr) },
  [SGLOB_stand_r_row_attr] = { SGLOB_stand_r_row_attr, 'S', XSIZE(struct section_global_data, stand_r_row_attr), "stand_r_row_attr", XOFFSET(struct section_global_data, stand_r_row_attr) },
  [SGLOB_stand_v_row_attr] = { SGLOB_stand_v_row_attr, 'S', XSIZE(struct section_global_data, stand_v_row_attr), "stand_v_row_attr", XOFFSET(struct section_global_data, stand_v_row_attr) },
  [SGLOB_stand_u_row_attr] = { SGLOB_stand_u_row_attr, 'S', XSIZE(struct section_global_data, stand_u_row_attr), "stand_u_row_attr", XOFFSET(struct section_global_data, stand_u_row_attr) },
  [SGLOB_stand_success_attr] = { SGLOB_stand_success_attr, 'S', XSIZE(struct section_global_data, stand_success_attr), "stand_success_attr", XOFFSET(struct section_global_data, stand_success_attr) },
  [SGLOB_stand_fail_attr] = { SGLOB_stand_fail_attr, 'S', XSIZE(struct section_global_data, stand_fail_attr), "stand_fail_attr", XOFFSET(struct section_global_data, stand_fail_attr) },
  [SGLOB_stand_trans_attr] = { SGLOB_stand_trans_attr, 'S', XSIZE(struct section_global_data, stand_trans_attr), "stand_trans_attr", XOFFSET(struct section_global_data, stand_trans_attr) },
  [SGLOB_stand_disq_attr] = { SGLOB_stand_disq_attr, 'S', XSIZE(struct section_global_data, stand_disq_attr), "stand_disq_attr", XOFFSET(struct section_global_data, stand_disq_attr) },
  [SGLOB_stand_use_login] = { SGLOB_stand_use_login, 'B', XSIZE(struct section_global_data, stand_use_login), "stand_use_login", XOFFSET(struct section_global_data, stand_use_login) },
  [SGLOB_stand_show_ok_time] = { SGLOB_stand_show_ok_time, 'B', XSIZE(struct section_global_data, stand_show_ok_time), "stand_show_ok_time", XOFFSET(struct section_global_data, stand_show_ok_time) },
  [SGLOB_stand_show_att_num] = { SGLOB_stand_show_att_num, 'B', XSIZE(struct section_global_data, stand_show_att_num), "stand_show_att_num", XOFFSET(struct section_global_data, stand_show_att_num) },
  [SGLOB_stand_sort_by_solved] = { SGLOB_stand_sort_by_solved, 'B', XSIZE(struct section_global_data, stand_sort_by_solved), "stand_sort_by_solved", XOFFSET(struct section_global_data, stand_sort_by_solved) },
  [SGLOB_stand_row_attr] = { SGLOB_stand_row_attr, 'x', XSIZE(struct section_global_data, stand_row_attr), "stand_row_attr", XOFFSET(struct section_global_data, stand_row_attr) },
  [SGLOB_stand_page_table_attr] = { SGLOB_stand_page_table_attr, 'S', XSIZE(struct section_global_data, stand_page_table_attr), "stand_page_table_attr", XOFFSET(struct section_global_data, stand_page_table_attr) },
  [SGLOB_stand_page_row_attr] = { SGLOB_stand_page_row_attr, 'x', XSIZE(struct section_global_data, stand_page_row_attr), "stand_page_row_attr", XOFFSET(struct section_global_data, stand_page_row_attr) },
  [SGLOB_stand_page_col_attr] = { SGLOB_stand_page_col_attr, 'x', XSIZE(struct section_global_data, stand_page_col_attr), "stand_page_col_attr", XOFFSET(struct section_global_data, stand_page_col_attr) },
  [SGLOB_stand_page_cur_attr] = { SGLOB_stand_page_cur_attr, 'S', XSIZE(struct section_global_data, stand_page_cur_attr), "stand_page_cur_attr", XOFFSET(struct section_global_data, stand_page_cur_attr) },
  [SGLOB_stand_collate_name] = { SGLOB_stand_collate_name, 'B', XSIZE(struct section_global_data, stand_collate_name), "stand_collate_name", XOFFSET(struct section_global_data, stand_collate_name) },
  [SGLOB_stand_enable_penalty] = { SGLOB_stand_enable_penalty, 'B', XSIZE(struct section_global_data, stand_enable_penalty), "stand_enable_penalty", XOFFSET(struct section_global_data, stand_enable_penalty) },
  [SGLOB_stand_header_txt] = { SGLOB_stand_header_txt, 's', XSIZE(struct section_global_data, stand_header_txt), NULL, XOFFSET(struct section_global_data, stand_header_txt) },
  [SGLOB_stand_footer_txt] = { SGLOB_stand_footer_txt, 's', XSIZE(struct section_global_data, stand_footer_txt), NULL, XOFFSET(struct section_global_data, stand_footer_txt) },
  [SGLOB_stand2_file_name] = { SGLOB_stand2_file_name, 'S', XSIZE(struct section_global_data, stand2_file_name), "stand2_file_name", XOFFSET(struct section_global_data, stand2_file_name) },
  [SGLOB_stand2_header_file] = { SGLOB_stand2_header_file, 'S', XSIZE(struct section_global_data, stand2_header_file), "stand2_header_file", XOFFSET(struct section_global_data, stand2_header_file) },
  [SGLOB_stand2_footer_file] = { SGLOB_stand2_footer_file, 'S', XSIZE(struct section_global_data, stand2_footer_file), "stand2_footer_file", XOFFSET(struct section_global_data, stand2_footer_file) },
  [SGLOB_stand2_header_txt] = { SGLOB_stand2_header_txt, 's', XSIZE(struct section_global_data, stand2_header_txt), NULL, XOFFSET(struct section_global_data, stand2_header_txt) },
  [SGLOB_stand2_footer_txt] = { SGLOB_stand2_footer_txt, 's', XSIZE(struct section_global_data, stand2_footer_txt), NULL, XOFFSET(struct section_global_data, stand2_footer_txt) },
  [SGLOB_stand2_symlink_dir] = { SGLOB_stand2_symlink_dir, 'S', XSIZE(struct section_global_data, stand2_symlink_dir), "stand2_symlink_dir", XOFFSET(struct section_global_data, stand2_symlink_dir) },
  [SGLOB_plog_file_name] = { SGLOB_plog_file_name, 'S', XSIZE(struct section_global_data, plog_file_name), "plog_file_name", XOFFSET(struct section_global_data, plog_file_name) },
  [SGLOB_plog_header_file] = { SGLOB_plog_header_file, 'S', XSIZE(struct section_global_data, plog_header_file), "plog_header_file", XOFFSET(struct section_global_data, plog_header_file) },
  [SGLOB_plog_footer_file] = { SGLOB_plog_footer_file, 'S', XSIZE(struct section_global_data, plog_footer_file), "plog_footer_file", XOFFSET(struct section_global_data, plog_footer_file) },
  [SGLOB_plog_header_txt] = { SGLOB_plog_header_txt, 's', XSIZE(struct section_global_data, plog_header_txt), NULL, XOFFSET(struct section_global_data, plog_header_txt) },
  [SGLOB_plog_footer_txt] = { SGLOB_plog_footer_txt, 's', XSIZE(struct section_global_data, plog_footer_txt), NULL, XOFFSET(struct section_global_data, plog_footer_txt) },
  [SGLOB_plog_update_time] = { SGLOB_plog_update_time, 'i', XSIZE(struct section_global_data, plog_update_time), "plog_update_time", XOFFSET(struct section_global_data, plog_update_time) },
  [SGLOB_plog_symlink_dir] = { SGLOB_plog_symlink_dir, 'S', XSIZE(struct section_global_data, plog_symlink_dir), "plog_symlink_dir", XOFFSET(struct section_global_data, plog_symlink_dir) },
  [SGLOB_internal_xml_update_time] = { SGLOB_internal_xml_update_time, 'i', XSIZE(struct section_global_data, internal_xml_update_time), "internal_xml_update_time", XOFFSET(struct section_global_data, internal_xml_update_time) },
  [SGLOB_external_xml_update_time] = { SGLOB_external_xml_update_time, 'i', XSIZE(struct section_global_data, external_xml_update_time), "external_xml_update_time", XOFFSET(struct section_global_data, external_xml_update_time) },
  [SGLOB_user_exam_protocol_header_file] = { SGLOB_user_exam_protocol_header_file, 'S', XSIZE(struct section_global_data, user_exam_protocol_header_file), "user_exam_protocol_header_file", XOFFSET(struct section_global_data, user_exam_protocol_header_file) },
  [SGLOB_user_exam_protocol_footer_file] = { SGLOB_user_exam_protocol_footer_file, 'S', XSIZE(struct section_global_data, user_exam_protocol_footer_file), "user_exam_protocol_footer_file", XOFFSET(struct section_global_data, user_exam_protocol_footer_file) },
  [SGLOB_user_exam_protocol_header_txt] = { SGLOB_user_exam_protocol_header_txt, 's', XSIZE(struct section_global_data, user_exam_protocol_header_txt), NULL, XOFFSET(struct section_global_data, user_exam_protocol_header_txt) },
  [SGLOB_user_exam_protocol_footer_txt] = { SGLOB_user_exam_protocol_footer_txt, 's', XSIZE(struct section_global_data, user_exam_protocol_footer_txt), NULL, XOFFSET(struct section_global_data, user_exam_protocol_footer_txt) },
  [SGLOB_prob_exam_protocol_header_file] = { SGLOB_prob_exam_protocol_header_file, 'S', XSIZE(struct section_global_data, prob_exam_protocol_header_file), "prob_exam_protocol_header_file", XOFFSET(struct section_global_data, prob_exam_protocol_header_file) },
  [SGLOB_prob_exam_protocol_footer_file] = { SGLOB_prob_exam_protocol_footer_file, 'S', XSIZE(struct section_global_data, prob_exam_protocol_footer_file), "prob_exam_protocol_footer_file", XOFFSET(struct section_global_data, prob_exam_protocol_footer_file) },
  [SGLOB_prob_exam_protocol_header_txt] = { SGLOB_prob_exam_protocol_header_txt, 's', XSIZE(struct section_global_data, prob_exam_protocol_header_txt), NULL, XOFFSET(struct section_global_data, prob_exam_protocol_header_txt) },
  [SGLOB_prob_exam_protocol_footer_txt] = { SGLOB_prob_exam_protocol_footer_txt, 's', XSIZE(struct section_global_data, prob_exam_protocol_footer_txt), NULL, XOFFSET(struct section_global_data, prob_exam_protocol_footer_txt) },
  [SGLOB_full_exam_protocol_header_file] = { SGLOB_full_exam_protocol_header_file, 'S', XSIZE(struct section_global_data, full_exam_protocol_header_file), "full_exam_protocol_header_file", XOFFSET(struct section_global_data, full_exam_protocol_header_file) },
  [SGLOB_full_exam_protocol_footer_file] = { SGLOB_full_exam_protocol_footer_file, 'S', XSIZE(struct section_global_data, full_exam_protocol_footer_file), "full_exam_protocol_footer_file", XOFFSET(struct section_global_data, full_exam_protocol_footer_file) },
  [SGLOB_full_exam_protocol_header_txt] = { SGLOB_full_exam_protocol_header_txt, 's', XSIZE(struct section_global_data, full_exam_protocol_header_txt), NULL, XOFFSET(struct section_global_data, full_exam_protocol_header_txt) },
  [SGLOB_full_exam_protocol_footer_txt] = { SGLOB_full_exam_protocol_footer_txt, 's', XSIZE(struct section_global_data, full_exam_protocol_footer_txt), NULL, XOFFSET(struct section_global_data, full_exam_protocol_footer_txt) },
  [SGLOB_extended_sound] = { SGLOB_extended_sound, 'B', XSIZE(struct section_global_data, extended_sound), "extended_sound", XOFFSET(struct section_global_data, extended_sound) },
  [SGLOB_disable_sound] = { SGLOB_disable_sound, 'B', XSIZE(struct section_global_data, disable_sound), "disable_sound", XOFFSET(struct section_global_data, disable_sound) },
  [SGLOB_sound_player] = { SGLOB_sound_player, 'S', XSIZE(struct section_global_data, sound_player), "sound_player", XOFFSET(struct section_global_data, sound_player) },
  [SGLOB_accept_sound] = { SGLOB_accept_sound, 'S', XSIZE(struct section_global_data, accept_sound), "accept_sound", XOFFSET(struct section_global_data, accept_sound) },
  [SGLOB_runtime_sound] = { SGLOB_runtime_sound, 'S', XSIZE(struct section_global_data, runtime_sound), "runtime_sound", XOFFSET(struct section_global_data, runtime_sound) },
  [SGLOB_timelimit_sound] = { SGLOB_timelimit_sound, 'S', XSIZE(struct section_global_data, timelimit_sound), "timelimit_sound", XOFFSET(struct section_global_data, timelimit_sound) },
  [SGLOB_presentation_sound] = { SGLOB_presentation_sound, 'S', XSIZE(struct section_global_data, presentation_sound), "presentation_sound", XOFFSET(struct section_global_data, presentation_sound) },
  [SGLOB_wrong_sound] = { SGLOB_wrong_sound, 'S', XSIZE(struct section_global_data, wrong_sound), "wrong_sound", XOFFSET(struct section_global_data, wrong_sound) },
  [SGLOB_internal_sound] = { SGLOB_internal_sound, 'S', XSIZE(struct section_global_data, internal_sound), "internal_sound", XOFFSET(struct section_global_data, internal_sound) },
  [SGLOB_start_sound] = { SGLOB_start_sound, 'S', XSIZE(struct section_global_data, start_sound), "start_sound", XOFFSET(struct section_global_data, start_sound) },
  [SGLOB_team_download_time] = { SGLOB_team_download_time, 'i', XSIZE(struct section_global_data, team_download_time), "team_download_time", XOFFSET(struct section_global_data, team_download_time) },
  [SGLOB_cr_serialization_key] = { SGLOB_cr_serialization_key, 'i', XSIZE(struct section_global_data, cr_serialization_key), "cr_serialization_key", XOFFSET(struct section_global_data, cr_serialization_key) },
  [SGLOB_show_astr_time] = { SGLOB_show_astr_time, 'B', XSIZE(struct section_global_data, show_astr_time), "show_astr_time", XOFFSET(struct section_global_data, show_astr_time) },
  [SGLOB_ignore_duplicated_runs] = { SGLOB_ignore_duplicated_runs, 'B', XSIZE(struct section_global_data, ignore_duplicated_runs), "ignore_duplicated_runs", XOFFSET(struct section_global_data, ignore_duplicated_runs) },
  [SGLOB_report_error_code] = { SGLOB_report_error_code, 'B', XSIZE(struct section_global_data, report_error_code), "report_error_code", XOFFSET(struct section_global_data, report_error_code) },
  [SGLOB_auto_short_problem_name] = { SGLOB_auto_short_problem_name, 'B', XSIZE(struct section_global_data, auto_short_problem_name), "auto_short_problem_name", XOFFSET(struct section_global_data, auto_short_problem_name) },
  [SGLOB_compile_real_time_limit] = { SGLOB_compile_real_time_limit, 'i', XSIZE(struct section_global_data, compile_real_time_limit), "compile_real_time_limit", XOFFSET(struct section_global_data, compile_real_time_limit) },
  [SGLOB_checker_real_time_limit] = { SGLOB_checker_real_time_limit, 'i', XSIZE(struct section_global_data, checker_real_time_limit), "checker_real_time_limit", XOFFSET(struct section_global_data, checker_real_time_limit) },
  [SGLOB_show_deadline] = { SGLOB_show_deadline, 'B', XSIZE(struct section_global_data, show_deadline), "show_deadline", XOFFSET(struct section_global_data, show_deadline) },
  [SGLOB_use_gzip] = { SGLOB_use_gzip, 'B', XSIZE(struct section_global_data, use_gzip), "use_gzip", XOFFSET(struct section_global_data, use_gzip) },
  [SGLOB_min_gzip_size] = { SGLOB_min_gzip_size, 'z', XSIZE(struct section_global_data, min_gzip_size), "min_gzip_size", XOFFSET(struct section_global_data, min_gzip_size) },
  [SGLOB_use_dir_hierarchy] = { SGLOB_use_dir_hierarchy, 'B', XSIZE(struct section_global_data, use_dir_hierarchy), "use_dir_hierarchy", XOFFSET(struct section_global_data, use_dir_hierarchy) },
  [SGLOB_html_report] = { SGLOB_html_report, 'B', XSIZE(struct section_global_data, html_report), "html_report", XOFFSET(struct section_global_data, html_report) },
  [SGLOB_xml_report] = { SGLOB_xml_report, 'B', XSIZE(struct section_global_data, xml_report), "xml_report", XOFFSET(struct section_global_data, xml_report) },
  [SGLOB_enable_full_archive] = { SGLOB_enable_full_archive, 'B', XSIZE(struct section_global_data, enable_full_archive), "enable_full_archive", XOFFSET(struct section_global_data, enable_full_archive) },
  [SGLOB_cpu_bogomips] = { SGLOB_cpu_bogomips, 'i', XSIZE(struct section_global_data, cpu_bogomips), "cpu_bogomips", XOFFSET(struct section_global_data, cpu_bogomips) },
  [SGLOB_skip_full_testing] = { SGLOB_skip_full_testing, 'B', XSIZE(struct section_global_data, skip_full_testing), "skip_full_testing", XOFFSET(struct section_global_data, skip_full_testing) },
  [SGLOB_skip_accept_testing] = { SGLOB_skip_accept_testing, 'B', XSIZE(struct section_global_data, skip_accept_testing), "skip_accept_testing", XOFFSET(struct section_global_data, skip_accept_testing) },
  [SGLOB_variant_map_file] = { SGLOB_variant_map_file, 'S', XSIZE(struct section_global_data, variant_map_file), "variant_map_file", XOFFSET(struct section_global_data, variant_map_file) },
  [SGLOB_variant_map] = { SGLOB_variant_map, '?', XSIZE(struct section_global_data, variant_map), "variant_map", XOFFSET(struct section_global_data, variant_map) },
  [SGLOB_enable_printing] = { SGLOB_enable_printing, 'B', XSIZE(struct section_global_data, enable_printing), "enable_printing", XOFFSET(struct section_global_data, enable_printing) },
  [SGLOB_disable_banner_page] = { SGLOB_disable_banner_page, 'B', XSIZE(struct section_global_data, disable_banner_page), "disable_banner_page", XOFFSET(struct section_global_data, disable_banner_page) },
  [SGLOB_team_page_quota] = { SGLOB_team_page_quota, 'i', XSIZE(struct section_global_data, team_page_quota), "team_page_quota", XOFFSET(struct section_global_data, team_page_quota) },
  [SGLOB_user_priority_adjustments] = { SGLOB_user_priority_adjustments, 'x', XSIZE(struct section_global_data, user_priority_adjustments), "user_priority_adjustments", XOFFSET(struct section_global_data, user_priority_adjustments) },
  [SGLOB_user_adjustment_info] = { SGLOB_user_adjustment_info, '?', XSIZE(struct section_global_data, user_adjustment_info), "user_adjustment_info", XOFFSET(struct section_global_data, user_adjustment_info) },
  [SGLOB_user_adjustment_map] = { SGLOB_user_adjustment_map, '?', XSIZE(struct section_global_data, user_adjustment_map), "user_adjustment_map", XOFFSET(struct section_global_data, user_adjustment_map) },
  [SGLOB_contestant_status_num] = { SGLOB_contestant_status_num, 'i', XSIZE(struct section_global_data, contestant_status_num), "contestant_status_num", XOFFSET(struct section_global_data, contestant_status_num) },
  [SGLOB_contestant_status_legend] = { SGLOB_contestant_status_legend, 'x', XSIZE(struct section_global_data, contestant_status_legend), "contestant_status_legend", XOFFSET(struct section_global_data, contestant_status_legend) },
  [SGLOB_contestant_status_row_attr] = { SGLOB_contestant_status_row_attr, 'x', XSIZE(struct section_global_data, contestant_status_row_attr), "contestant_status_row_attr", XOFFSET(struct section_global_data, contestant_status_row_attr) },
  [SGLOB_stand_show_contestant_status] = { SGLOB_stand_show_contestant_status, 'B', XSIZE(struct section_global_data, stand_show_contestant_status), "stand_show_contestant_status", XOFFSET(struct section_global_data, stand_show_contestant_status) },
  [SGLOB_stand_show_warn_number] = { SGLOB_stand_show_warn_number, 'B', XSIZE(struct section_global_data, stand_show_warn_number), "stand_show_warn_number", XOFFSET(struct section_global_data, stand_show_warn_number) },
  [SGLOB_stand_contestant_status_attr] = { SGLOB_stand_contestant_status_attr, 'S', XSIZE(struct section_global_data, stand_contestant_status_attr), "stand_contestant_status_attr", XOFFSET(struct section_global_data, stand_contestant_status_attr) },
  [SGLOB_stand_warn_number_attr] = { SGLOB_stand_warn_number_attr, 'S', XSIZE(struct section_global_data, stand_warn_number_attr), "stand_warn_number_attr", XOFFSET(struct section_global_data, stand_warn_number_attr) },
  [SGLOB_unhandled_vars] = { SGLOB_unhandled_vars, 's', XSIZE(struct section_global_data, unhandled_vars), NULL, XOFFSET(struct section_global_data, unhandled_vars) },
  [SGLOB_disable_prob_long_name] = { SGLOB_disable_prob_long_name, 'B', XSIZE(struct section_global_data, disable_prob_long_name), NULL, XOFFSET(struct section_global_data, disable_prob_long_name) },
  [SGLOB_disable_passed_tests] = { SGLOB_disable_passed_tests, 'B', XSIZE(struct section_global_data, disable_passed_tests), NULL, XOFFSET(struct section_global_data, disable_passed_tests) },
};

int global_get_type(int tag)
{
  ASSERT(tag > 0 && tag < SGLOB_LAST_FIELD);
  return meta_info_section_global_data_data[tag].type;
}

size_t global_get_size(int tag)
{
  ASSERT(tag > 0 && tag < SGLOB_LAST_FIELD);
  return meta_info_section_global_data_data[tag].size;
}

const char *global_get_name(int tag)
{
  ASSERT(tag > 0 && tag < SGLOB_LAST_FIELD);
  return meta_info_section_global_data_data[tag].name;
}

const void *global_get_ptr(const struct section_global_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < SGLOB_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_global_data_data[tag].offset);
}

void *global_get_ptr_nc(struct section_global_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < SGLOB_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_global_data_data[tag].offset);
}

int global_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_section_global_data_data, SGLOB_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

static struct meta_info_item meta_info_section_problem_data_data[] =
{
  [SPROB_id] = { SPROB_id, 'i', XSIZE(struct section_problem_data, id), "id", XOFFSET(struct section_problem_data, id) },
  [SPROB_tester_id] = { SPROB_tester_id, 'i', XSIZE(struct section_problem_data, tester_id), "tester_id", XOFFSET(struct section_problem_data, tester_id) },
  [SPROB_abstract] = { SPROB_abstract, 'i', XSIZE(struct section_problem_data, abstract), "abstract", XOFFSET(struct section_problem_data, abstract) },
  [SPROB_type_val] = { SPROB_type_val, 'i', XSIZE(struct section_problem_data, type_val), "type_val", XOFFSET(struct section_problem_data, type_val) },
  [SPROB_manual_checking] = { SPROB_manual_checking, 'i', XSIZE(struct section_problem_data, manual_checking), "manual_checking", XOFFSET(struct section_problem_data, manual_checking) },
  [SPROB_examinator_num] = { SPROB_examinator_num, 'i', XSIZE(struct section_problem_data, examinator_num), "examinator_num", XOFFSET(struct section_problem_data, examinator_num) },
  [SPROB_check_presentation] = { SPROB_check_presentation, 'i', XSIZE(struct section_problem_data, check_presentation), "check_presentation", XOFFSET(struct section_problem_data, check_presentation) },
  [SPROB_scoring_checker] = { SPROB_scoring_checker, 'i', XSIZE(struct section_problem_data, scoring_checker), "scoring_checker", XOFFSET(struct section_problem_data, scoring_checker) },
  [SPROB_use_stdin] = { SPROB_use_stdin, 'i', XSIZE(struct section_problem_data, use_stdin), "use_stdin", XOFFSET(struct section_problem_data, use_stdin) },
  [SPROB_use_stdout] = { SPROB_use_stdout, 'i', XSIZE(struct section_problem_data, use_stdout), "use_stdout", XOFFSET(struct section_problem_data, use_stdout) },
  [SPROB_binary_input] = { SPROB_binary_input, 'i', XSIZE(struct section_problem_data, binary_input), "binary_input", XOFFSET(struct section_problem_data, binary_input) },
  [SPROB_ignore_exit_code] = { SPROB_ignore_exit_code, 'i', XSIZE(struct section_problem_data, ignore_exit_code), "ignore_exit_code", XOFFSET(struct section_problem_data, ignore_exit_code) },
  [SPROB_olympiad_mode] = { SPROB_olympiad_mode, 'i', XSIZE(struct section_problem_data, olympiad_mode), "olympiad_mode", XOFFSET(struct section_problem_data, olympiad_mode) },
  [SPROB_score_latest] = { SPROB_score_latest, 'i', XSIZE(struct section_problem_data, score_latest), "score_latest", XOFFSET(struct section_problem_data, score_latest) },
  [SPROB_real_time_limit] = { SPROB_real_time_limit, 'i', XSIZE(struct section_problem_data, real_time_limit), "real_time_limit", XOFFSET(struct section_problem_data, real_time_limit) },
  [SPROB_time_limit] = { SPROB_time_limit, 'i', XSIZE(struct section_problem_data, time_limit), "time_limit", XOFFSET(struct section_problem_data, time_limit) },
  [SPROB_time_limit_millis] = { SPROB_time_limit_millis, 'i', XSIZE(struct section_problem_data, time_limit_millis), "time_limit_millis", XOFFSET(struct section_problem_data, time_limit_millis) },
  [SPROB_use_ac_not_ok] = { SPROB_use_ac_not_ok, 'i', XSIZE(struct section_problem_data, use_ac_not_ok), "use_ac_not_ok", XOFFSET(struct section_problem_data, use_ac_not_ok) },
  [SPROB_team_enable_rep_view] = { SPROB_team_enable_rep_view, 'i', XSIZE(struct section_problem_data, team_enable_rep_view), "team_enable_rep_view", XOFFSET(struct section_problem_data, team_enable_rep_view) },
  [SPROB_team_enable_ce_view] = { SPROB_team_enable_ce_view, 'i', XSIZE(struct section_problem_data, team_enable_ce_view), "team_enable_ce_view", XOFFSET(struct section_problem_data, team_enable_ce_view) },
  [SPROB_team_show_judge_report] = { SPROB_team_show_judge_report, 'i', XSIZE(struct section_problem_data, team_show_judge_report), "team_show_judge_report", XOFFSET(struct section_problem_data, team_show_judge_report) },
  [SPROB_ignore_compile_errors] = { SPROB_ignore_compile_errors, 'i', XSIZE(struct section_problem_data, ignore_compile_errors), "ignore_compile_errors", XOFFSET(struct section_problem_data, ignore_compile_errors) },
  [SPROB_full_score] = { SPROB_full_score, 'i', XSIZE(struct section_problem_data, full_score), "full_score", XOFFSET(struct section_problem_data, full_score) },
  [SPROB_variable_full_score] = { SPROB_variable_full_score, 'i', XSIZE(struct section_problem_data, variable_full_score), "variable_full_score", XOFFSET(struct section_problem_data, variable_full_score) },
  [SPROB_test_score] = { SPROB_test_score, 'i', XSIZE(struct section_problem_data, test_score), "test_score", XOFFSET(struct section_problem_data, test_score) },
  [SPROB_run_penalty] = { SPROB_run_penalty, 'i', XSIZE(struct section_problem_data, run_penalty), "run_penalty", XOFFSET(struct section_problem_data, run_penalty) },
  [SPROB_acm_run_penalty] = { SPROB_acm_run_penalty, 'i', XSIZE(struct section_problem_data, acm_run_penalty), "acm_run_penalty", XOFFSET(struct section_problem_data, acm_run_penalty) },
  [SPROB_disqualified_penalty] = { SPROB_disqualified_penalty, 'i', XSIZE(struct section_problem_data, disqualified_penalty), "disqualified_penalty", XOFFSET(struct section_problem_data, disqualified_penalty) },
  [SPROB_ignore_penalty] = { SPROB_ignore_penalty, 'i', XSIZE(struct section_problem_data, ignore_penalty), "ignore_penalty", XOFFSET(struct section_problem_data, ignore_penalty) },
  [SPROB_use_corr] = { SPROB_use_corr, 'i', XSIZE(struct section_problem_data, use_corr), "use_corr", XOFFSET(struct section_problem_data, use_corr) },
  [SPROB_use_info] = { SPROB_use_info, 'i', XSIZE(struct section_problem_data, use_info), "use_info", XOFFSET(struct section_problem_data, use_info) },
  [SPROB_use_tgz] = { SPROB_use_tgz, 'i', XSIZE(struct section_problem_data, use_tgz), "use_tgz", XOFFSET(struct section_problem_data, use_tgz) },
  [SPROB_tests_to_accept] = { SPROB_tests_to_accept, 'i', XSIZE(struct section_problem_data, tests_to_accept), "tests_to_accept", XOFFSET(struct section_problem_data, tests_to_accept) },
  [SPROB_accept_partial] = { SPROB_accept_partial, 'i', XSIZE(struct section_problem_data, accept_partial), "accept_partial", XOFFSET(struct section_problem_data, accept_partial) },
  [SPROB_min_tests_to_accept] = { SPROB_min_tests_to_accept, 'i', XSIZE(struct section_problem_data, min_tests_to_accept), "min_tests_to_accept", XOFFSET(struct section_problem_data, min_tests_to_accept) },
  [SPROB_checker_real_time_limit] = { SPROB_checker_real_time_limit, 'i', XSIZE(struct section_problem_data, checker_real_time_limit), "checker_real_time_limit", XOFFSET(struct section_problem_data, checker_real_time_limit) },
  [SPROB_disable_user_submit] = { SPROB_disable_user_submit, 'i', XSIZE(struct section_problem_data, disable_user_submit), "disable_user_submit", XOFFSET(struct section_problem_data, disable_user_submit) },
  [SPROB_disable_tab] = { SPROB_disable_tab, 'i', XSIZE(struct section_problem_data, disable_tab), "disable_tab", XOFFSET(struct section_problem_data, disable_tab) },
  [SPROB_restricted_statement] = { SPROB_restricted_statement, 'i', XSIZE(struct section_problem_data, restricted_statement), "restricted_statement", XOFFSET(struct section_problem_data, restricted_statement) },
  [SPROB_disable_submit_after_ok] = { SPROB_disable_submit_after_ok, 'i', XSIZE(struct section_problem_data, disable_submit_after_ok), "disable_submit_after_ok", XOFFSET(struct section_problem_data, disable_submit_after_ok) },
  [SPROB_disable_auto_testing] = { SPROB_disable_auto_testing, 'i', XSIZE(struct section_problem_data, disable_auto_testing), "disable_auto_testing", XOFFSET(struct section_problem_data, disable_auto_testing) },
  [SPROB_disable_testing] = { SPROB_disable_testing, 'i', XSIZE(struct section_problem_data, disable_testing), "disable_testing", XOFFSET(struct section_problem_data, disable_testing) },
  [SPROB_enable_compilation] = { SPROB_enable_compilation, 'i', XSIZE(struct section_problem_data, enable_compilation), "enable_compilation", XOFFSET(struct section_problem_data, enable_compilation) },
  [SPROB_skip_testing] = { SPROB_skip_testing, 'i', XSIZE(struct section_problem_data, skip_testing), "skip_testing", XOFFSET(struct section_problem_data, skip_testing) },
  [SPROB_hidden] = { SPROB_hidden, 'i', XSIZE(struct section_problem_data, hidden), "hidden", XOFFSET(struct section_problem_data, hidden) },
  [SPROB_priority_adjustment] = { SPROB_priority_adjustment, 'i', XSIZE(struct section_problem_data, priority_adjustment), "priority_adjustment", XOFFSET(struct section_problem_data, priority_adjustment) },
  [SPROB_stand_hide_time] = { SPROB_stand_hide_time, 'i', XSIZE(struct section_problem_data, stand_hide_time), "stand_hide_time", XOFFSET(struct section_problem_data, stand_hide_time) },
  [SPROB_score_multiplier] = { SPROB_score_multiplier, 'i', XSIZE(struct section_problem_data, score_multiplier), "score_multiplier", XOFFSET(struct section_problem_data, score_multiplier) },
  [SPROB_prev_runs_to_show] = { SPROB_prev_runs_to_show, 'i', XSIZE(struct section_problem_data, prev_runs_to_show), "prev_runs_to_show", XOFFSET(struct section_problem_data, prev_runs_to_show) },
  [SPROB_advance_to_next] = { SPROB_advance_to_next, 'i', XSIZE(struct section_problem_data, advance_to_next), "advance_to_next", XOFFSET(struct section_problem_data, advance_to_next) },
  [SPROB_enable_text_form] = { SPROB_enable_text_form, 'i', XSIZE(struct section_problem_data, enable_text_form), "enable_text_form", XOFFSET(struct section_problem_data, enable_text_form) },
  [SPROB_stand_ignore_score] = { SPROB_stand_ignore_score, 'i', XSIZE(struct section_problem_data, stand_ignore_score), "stand_ignore_score", XOFFSET(struct section_problem_data, stand_ignore_score) },
  [SPROB_stand_last_column] = { SPROB_stand_last_column, 'i', XSIZE(struct section_problem_data, stand_last_column), "stand_last_column", XOFFSET(struct section_problem_data, stand_last_column) },
  [SPROB_disable_security] = { SPROB_disable_security, 'i', XSIZE(struct section_problem_data, disable_security), "disable_security", XOFFSET(struct section_problem_data, disable_security) },
  [SPROB_super] = { SPROB_super, 'S', XSIZE(struct section_problem_data, super), "super", XOFFSET(struct section_problem_data, super) },
  [SPROB_short_name] = { SPROB_short_name, 'S', XSIZE(struct section_problem_data, short_name), "short_name", XOFFSET(struct section_problem_data, short_name) },
  [SPROB_long_name] = { SPROB_long_name, 'S', XSIZE(struct section_problem_data, long_name), "long_name", XOFFSET(struct section_problem_data, long_name) },
  [SPROB_group_name] = { SPROB_group_name, 'S', XSIZE(struct section_problem_data, group_name), "group_name", XOFFSET(struct section_problem_data, group_name) },
  [SPROB_test_dir] = { SPROB_test_dir, 'S', XSIZE(struct section_problem_data, test_dir), "test_dir", XOFFSET(struct section_problem_data, test_dir) },
  [SPROB_test_sfx] = { SPROB_test_sfx, 'S', XSIZE(struct section_problem_data, test_sfx), "test_sfx", XOFFSET(struct section_problem_data, test_sfx) },
  [SPROB_corr_dir] = { SPROB_corr_dir, 'S', XSIZE(struct section_problem_data, corr_dir), "corr_dir", XOFFSET(struct section_problem_data, corr_dir) },
  [SPROB_corr_sfx] = { SPROB_corr_sfx, 'S', XSIZE(struct section_problem_data, corr_sfx), "corr_sfx", XOFFSET(struct section_problem_data, corr_sfx) },
  [SPROB_info_dir] = { SPROB_info_dir, 'S', XSIZE(struct section_problem_data, info_dir), "info_dir", XOFFSET(struct section_problem_data, info_dir) },
  [SPROB_info_sfx] = { SPROB_info_sfx, 'S', XSIZE(struct section_problem_data, info_sfx), "info_sfx", XOFFSET(struct section_problem_data, info_sfx) },
  [SPROB_tgz_dir] = { SPROB_tgz_dir, 'S', XSIZE(struct section_problem_data, tgz_dir), "tgz_dir", XOFFSET(struct section_problem_data, tgz_dir) },
  [SPROB_tgz_sfx] = { SPROB_tgz_sfx, 'S', XSIZE(struct section_problem_data, tgz_sfx), "tgz_sfx", XOFFSET(struct section_problem_data, tgz_sfx) },
  [SPROB_input_file] = { SPROB_input_file, 'S', XSIZE(struct section_problem_data, input_file), "input_file", XOFFSET(struct section_problem_data, input_file) },
  [SPROB_output_file] = { SPROB_output_file, 'S', XSIZE(struct section_problem_data, output_file), "output_file", XOFFSET(struct section_problem_data, output_file) },
  [SPROB_test_score_list] = { SPROB_test_score_list, 'S', XSIZE(struct section_problem_data, test_score_list), "test_score_list", XOFFSET(struct section_problem_data, test_score_list) },
  [SPROB_score_tests] = { SPROB_score_tests, 'S', XSIZE(struct section_problem_data, score_tests), "score_tests", XOFFSET(struct section_problem_data, score_tests) },
  [SPROB_standard_checker] = { SPROB_standard_checker, 'S', XSIZE(struct section_problem_data, standard_checker), "standard_checker", XOFFSET(struct section_problem_data, standard_checker) },
  [SPROB_spelling] = { SPROB_spelling, 'S', XSIZE(struct section_problem_data, spelling), "spelling", XOFFSET(struct section_problem_data, spelling) },
  [SPROB_statement_file] = { SPROB_statement_file, 'S', XSIZE(struct section_problem_data, statement_file), "statement_file", XOFFSET(struct section_problem_data, statement_file) },
  [SPROB_alternatives_file] = { SPROB_alternatives_file, 'S', XSIZE(struct section_problem_data, alternatives_file), "alternatives_file", XOFFSET(struct section_problem_data, alternatives_file) },
  [SPROB_plugin_file] = { SPROB_plugin_file, 'S', XSIZE(struct section_problem_data, plugin_file), "plugin_file", XOFFSET(struct section_problem_data, plugin_file) },
  [SPROB_xml_file] = { SPROB_xml_file, 'S', XSIZE(struct section_problem_data, xml_file), "xml_file", XOFFSET(struct section_problem_data, xml_file) },
  [SPROB_stand_attr] = { SPROB_stand_attr, 'S', XSIZE(struct section_problem_data, stand_attr), "stand_attr", XOFFSET(struct section_problem_data, stand_attr) },
  [SPROB_source_header] = { SPROB_source_header, 'S', XSIZE(struct section_problem_data, source_header), "source_header", XOFFSET(struct section_problem_data, source_header) },
  [SPROB_source_footer] = { SPROB_source_footer, 'S', XSIZE(struct section_problem_data, source_footer), "source_footer", XOFFSET(struct section_problem_data, source_footer) },
  [SPROB_test_pat] = { SPROB_test_pat, 'S', XSIZE(struct section_problem_data, test_pat), "test_pat", XOFFSET(struct section_problem_data, test_pat) },
  [SPROB_corr_pat] = { SPROB_corr_pat, 'S', XSIZE(struct section_problem_data, corr_pat), "corr_pat", XOFFSET(struct section_problem_data, corr_pat) },
  [SPROB_info_pat] = { SPROB_info_pat, 'S', XSIZE(struct section_problem_data, info_pat), "info_pat", XOFFSET(struct section_problem_data, info_pat) },
  [SPROB_tgz_pat] = { SPROB_tgz_pat, 'S', XSIZE(struct section_problem_data, tgz_pat), "tgz_pat", XOFFSET(struct section_problem_data, tgz_pat) },
  [SPROB_type] = { SPROB_type, 'S', XSIZE(struct section_problem_data, type), "type", XOFFSET(struct section_problem_data, type) },
  [SPROB_ntests] = { SPROB_ntests, 'i', XSIZE(struct section_problem_data, ntests), "ntests", XOFFSET(struct section_problem_data, ntests) },
  [SPROB_tscores] = { SPROB_tscores, '?', XSIZE(struct section_problem_data, tscores), "tscores", XOFFSET(struct section_problem_data, tscores) },
  [SPROB_x_score_tests] = { SPROB_x_score_tests, '?', XSIZE(struct section_problem_data, x_score_tests), "x_score_tests", XOFFSET(struct section_problem_data, x_score_tests) },
  [SPROB_test_sets] = { SPROB_test_sets, 'x', XSIZE(struct section_problem_data, test_sets), "test_sets", XOFFSET(struct section_problem_data, test_sets) },
  [SPROB_ts_total] = { SPROB_ts_total, 'i', XSIZE(struct section_problem_data, ts_total), "ts_total", XOFFSET(struct section_problem_data, ts_total) },
  [SPROB_ts_infos] = { SPROB_ts_infos, '?', XSIZE(struct section_problem_data, ts_infos), "ts_infos", XOFFSET(struct section_problem_data, ts_infos) },
  [SPROB_deadline] = { SPROB_deadline, 'S', XSIZE(struct section_problem_data, deadline), "deadline", XOFFSET(struct section_problem_data, deadline) },
  [SPROB_t_deadline] = { SPROB_t_deadline, 't', XSIZE(struct section_problem_data, t_deadline), "t_deadline", XOFFSET(struct section_problem_data, t_deadline) },
  [SPROB_start_date] = { SPROB_start_date, 'S', XSIZE(struct section_problem_data, start_date), "start_date", XOFFSET(struct section_problem_data, start_date) },
  [SPROB_t_start_date] = { SPROB_t_start_date, 't', XSIZE(struct section_problem_data, t_start_date), "t_start_date", XOFFSET(struct section_problem_data, t_start_date) },
  [SPROB_variant_num] = { SPROB_variant_num, 'i', XSIZE(struct section_problem_data, variant_num), "variant_num", XOFFSET(struct section_problem_data, variant_num) },
  [SPROB_date_penalty] = { SPROB_date_penalty, 'x', XSIZE(struct section_problem_data, date_penalty), "date_penalty", XOFFSET(struct section_problem_data, date_penalty) },
  [SPROB_dp_total] = { SPROB_dp_total, 'i', XSIZE(struct section_problem_data, dp_total), "dp_total", XOFFSET(struct section_problem_data, dp_total) },
  [SPROB_dp_infos] = { SPROB_dp_infos, '?', XSIZE(struct section_problem_data, dp_infos), "dp_infos", XOFFSET(struct section_problem_data, dp_infos) },
  [SPROB_disable_language] = { SPROB_disable_language, 'x', XSIZE(struct section_problem_data, disable_language), "disable_language", XOFFSET(struct section_problem_data, disable_language) },
  [SPROB_enable_language] = { SPROB_enable_language, 'x', XSIZE(struct section_problem_data, enable_language), "enable_language", XOFFSET(struct section_problem_data, enable_language) },
  [SPROB_require] = { SPROB_require, 'x', XSIZE(struct section_problem_data, require), "require", XOFFSET(struct section_problem_data, require) },
  [SPROB_checker_env] = { SPROB_checker_env, 'x', XSIZE(struct section_problem_data, checker_env), "checker_env", XOFFSET(struct section_problem_data, checker_env) },
  [SPROB_valuer_env] = { SPROB_valuer_env, 'x', XSIZE(struct section_problem_data, valuer_env), "valuer_env", XOFFSET(struct section_problem_data, valuer_env) },
  [SPROB_check_cmd] = { SPROB_check_cmd, 'S', XSIZE(struct section_problem_data, check_cmd), "check_cmd", XOFFSET(struct section_problem_data, check_cmd) },
  [SPROB_valuer_cmd] = { SPROB_valuer_cmd, 'S', XSIZE(struct section_problem_data, valuer_cmd), "valuer_cmd", XOFFSET(struct section_problem_data, valuer_cmd) },
  [SPROB_lang_time_adj] = { SPROB_lang_time_adj, 'x', XSIZE(struct section_problem_data, lang_time_adj), "lang_time_adj", XOFFSET(struct section_problem_data, lang_time_adj) },
  [SPROB_lang_time_adj_millis] = { SPROB_lang_time_adj_millis, 'x', XSIZE(struct section_problem_data, lang_time_adj_millis), "lang_time_adj_millis", XOFFSET(struct section_problem_data, lang_time_adj_millis) },
  [SPROB_alternative] = { SPROB_alternative, 'x', XSIZE(struct section_problem_data, alternative), "alternative", XOFFSET(struct section_problem_data, alternative) },
  [SPROB_personal_deadline] = { SPROB_personal_deadline, 'x', XSIZE(struct section_problem_data, personal_deadline), "personal_deadline", XOFFSET(struct section_problem_data, personal_deadline) },
  [SPROB_pd_total] = { SPROB_pd_total, 'i', XSIZE(struct section_problem_data, pd_total), "pd_total", XOFFSET(struct section_problem_data, pd_total) },
  [SPROB_pd_infos] = { SPROB_pd_infos, '?', XSIZE(struct section_problem_data, pd_infos), "pd_infos", XOFFSET(struct section_problem_data, pd_infos) },
  [SPROB_score_bonus] = { SPROB_score_bonus, 'S', XSIZE(struct section_problem_data, score_bonus), "score_bonus", XOFFSET(struct section_problem_data, score_bonus) },
  [SPROB_score_bonus_total] = { SPROB_score_bonus_total, 'i', XSIZE(struct section_problem_data, score_bonus_total), "score_bonus_total", XOFFSET(struct section_problem_data, score_bonus_total) },
  [SPROB_score_bonus_val] = { SPROB_score_bonus_val, '?', XSIZE(struct section_problem_data, score_bonus_val), "score_bonus_val", XOFFSET(struct section_problem_data, score_bonus_val) },
  [SPROB_max_vm_size] = { SPROB_max_vm_size, '?', XSIZE(struct section_problem_data, max_vm_size), "max_vm_size", XOFFSET(struct section_problem_data, max_vm_size) },
  [SPROB_max_data_size] = { SPROB_max_data_size, '?', XSIZE(struct section_problem_data, max_data_size), "max_data_size", XOFFSET(struct section_problem_data, max_data_size) },
  [SPROB_max_stack_size] = { SPROB_max_stack_size, '?', XSIZE(struct section_problem_data, max_stack_size), "max_stack_size", XOFFSET(struct section_problem_data, max_stack_size) },
  [SPROB_unhandled_vars] = { SPROB_unhandled_vars, 's', XSIZE(struct section_problem_data, unhandled_vars), "unhandled_vars", XOFFSET(struct section_problem_data, unhandled_vars) },
  [SPROB_score_view] = { SPROB_score_view, 'x', XSIZE(struct section_problem_data, score_view), "score_view", XOFFSET(struct section_problem_data, score_view) },
  [SPROB_score_view_score] = { SPROB_score_view_score, '?', XSIZE(struct section_problem_data, score_view_score), "score_view_score", XOFFSET(struct section_problem_data, score_view_score) },
  [SPROB_score_view_text] = { SPROB_score_view_text, 'x', XSIZE(struct section_problem_data, score_view_text), "score_view_text", XOFFSET(struct section_problem_data, score_view_text) },
  [SPROB_xml] = { SPROB_xml, '?', XSIZE(struct section_problem_data, xml), "xml", XOFFSET(struct section_problem_data, xml) },
};

int prob_get_type(int tag)
{
  ASSERT(tag > 0 && tag < SPROB_LAST_FIELD);
  return meta_info_section_problem_data_data[tag].type;
}

size_t prob_get_size(int tag)
{
  ASSERT(tag > 0 && tag < SPROB_LAST_FIELD);
  return meta_info_section_problem_data_data[tag].size;
}

const char *prob_get_name(int tag)
{
  ASSERT(tag > 0 && tag < SPROB_LAST_FIELD);
  return meta_info_section_problem_data_data[tag].name;
}

const void *prob_get_ptr(const struct section_problem_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < SPROB_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_problem_data_data[tag].offset);
}

void *prob_get_ptr_nc(struct section_problem_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < SPROB_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_problem_data_data[tag].offset);
}

int prob_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_section_problem_data_data, SPROB_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

static struct meta_info_item meta_info_section_language_data_data[] =
{
  [SLANG_id] = { SLANG_id, 'i', XSIZE(struct section_language_data, id), "id", XOFFSET(struct section_language_data, id) },
  [SLANG_compile_id] = { SLANG_compile_id, 'i', XSIZE(struct section_language_data, compile_id), "compile_id", XOFFSET(struct section_language_data, compile_id) },
  [SLANG_disabled] = { SLANG_disabled, 'i', XSIZE(struct section_language_data, disabled), "disabled", XOFFSET(struct section_language_data, disabled) },
  [SLANG_compile_real_time_limit] = { SLANG_compile_real_time_limit, 'i', XSIZE(struct section_language_data, compile_real_time_limit), "compile_real_time_limit", XOFFSET(struct section_language_data, compile_real_time_limit) },
  [SLANG_binary] = { SLANG_binary, 'i', XSIZE(struct section_language_data, binary), "binary", XOFFSET(struct section_language_data, binary) },
  [SLANG_priority_adjustment] = { SLANG_priority_adjustment, 'i', XSIZE(struct section_language_data, priority_adjustment), "priority_adjustment", XOFFSET(struct section_language_data, priority_adjustment) },
  [SLANG_insecure] = { SLANG_insecure, 'i', XSIZE(struct section_language_data, insecure), "insecure", XOFFSET(struct section_language_data, insecure) },
  [SLANG_short_name] = { SLANG_short_name, 'S', XSIZE(struct section_language_data, short_name), "short_name", XOFFSET(struct section_language_data, short_name) },
  [SLANG_long_name] = { SLANG_long_name, 'S', XSIZE(struct section_language_data, long_name), "long_name", XOFFSET(struct section_language_data, long_name) },
  [SLANG_key] = { SLANG_key, 'S', XSIZE(struct section_language_data, key), "key", XOFFSET(struct section_language_data, key) },
  [SLANG_arch] = { SLANG_arch, 'S', XSIZE(struct section_language_data, arch), "arch", XOFFSET(struct section_language_data, arch) },
  [SLANG_src_sfx] = { SLANG_src_sfx, 'S', XSIZE(struct section_language_data, src_sfx), "src_sfx", XOFFSET(struct section_language_data, src_sfx) },
  [SLANG_exe_sfx] = { SLANG_exe_sfx, 'S', XSIZE(struct section_language_data, exe_sfx), "exe_sfx", XOFFSET(struct section_language_data, exe_sfx) },
  [SLANG_content_type] = { SLANG_content_type, 'S', XSIZE(struct section_language_data, content_type), "content_type", XOFFSET(struct section_language_data, content_type) },
  [SLANG_cmd] = { SLANG_cmd, 'S', XSIZE(struct section_language_data, cmd), "cmd", XOFFSET(struct section_language_data, cmd) },
  [SLANG_disable_auto_testing] = { SLANG_disable_auto_testing, 'i', XSIZE(struct section_language_data, disable_auto_testing), "disable_auto_testing", XOFFSET(struct section_language_data, disable_auto_testing) },
  [SLANG_disable_testing] = { SLANG_disable_testing, 'i', XSIZE(struct section_language_data, disable_testing), "disable_testing", XOFFSET(struct section_language_data, disable_testing) },
  [SLANG_compile_dir] = { SLANG_compile_dir, 'S', XSIZE(struct section_language_data, compile_dir), "compile_dir", XOFFSET(struct section_language_data, compile_dir) },
  [SLANG_compile_queue_dir] = { SLANG_compile_queue_dir, 'S', XSIZE(struct section_language_data, compile_queue_dir), "compile_queue_dir", XOFFSET(struct section_language_data, compile_queue_dir) },
  [SLANG_compile_src_dir] = { SLANG_compile_src_dir, 'S', XSIZE(struct section_language_data, compile_src_dir), "compile_src_dir", XOFFSET(struct section_language_data, compile_src_dir) },
  [SLANG_compile_out_dir] = { SLANG_compile_out_dir, 'S', XSIZE(struct section_language_data, compile_out_dir), "compile_out_dir", XOFFSET(struct section_language_data, compile_out_dir) },
  [SLANG_compile_status_dir] = { SLANG_compile_status_dir, 'S', XSIZE(struct section_language_data, compile_status_dir), "compile_status_dir", XOFFSET(struct section_language_data, compile_status_dir) },
  [SLANG_compile_report_dir] = { SLANG_compile_report_dir, 'S', XSIZE(struct section_language_data, compile_report_dir), "compile_report_dir", XOFFSET(struct section_language_data, compile_report_dir) },
  [SLANG_compiler_env] = { SLANG_compiler_env, 'x', XSIZE(struct section_language_data, compiler_env), "compiler_env", XOFFSET(struct section_language_data, compiler_env) },
  [SLANG_unhandled_vars] = { SLANG_unhandled_vars, 's', XSIZE(struct section_language_data, unhandled_vars), "unhandled_vars", XOFFSET(struct section_language_data, unhandled_vars) },
  [SLANG_disabled_by_config] = { SLANG_disabled_by_config, 'i', XSIZE(struct section_language_data, disabled_by_config), "disabled_by_config", XOFFSET(struct section_language_data, disabled_by_config) },
};

int lang_get_type(int tag)
{
  ASSERT(tag > 0 && tag < SLANG_LAST_FIELD);
  return meta_info_section_language_data_data[tag].type;
}

size_t lang_get_size(int tag)
{
  ASSERT(tag > 0 && tag < SLANG_LAST_FIELD);
  return meta_info_section_language_data_data[tag].size;
}

const char *lang_get_name(int tag)
{
  ASSERT(tag > 0 && tag < SLANG_LAST_FIELD);
  return meta_info_section_language_data_data[tag].name;
}

const void *lang_get_ptr(const struct section_language_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < SLANG_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_language_data_data[tag].offset);
}

void *lang_get_ptr_nc(struct section_language_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < SLANG_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_language_data_data[tag].offset);
}

int lang_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_section_language_data_data, SLANG_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

static struct meta_info_item meta_info_section_tester_data_data[] =
{
  [STESTER_id] = { STESTER_id, 'i', XSIZE(struct section_tester_data, id), "id", XOFFSET(struct section_tester_data, id) },
  [STESTER_name] = { STESTER_name, 'S', XSIZE(struct section_tester_data, name), "name", XOFFSET(struct section_tester_data, name) },
  [STESTER_problem] = { STESTER_problem, 'i', XSIZE(struct section_tester_data, problem), "problem", XOFFSET(struct section_tester_data, problem) },
  [STESTER_problem_name] = { STESTER_problem_name, 'S', XSIZE(struct section_tester_data, problem_name), "problem_name", XOFFSET(struct section_tester_data, problem_name) },
  [STESTER_any] = { STESTER_any, 'i', XSIZE(struct section_tester_data, any), "any", XOFFSET(struct section_tester_data, any) },
  [STESTER_is_dos] = { STESTER_is_dos, 'i', XSIZE(struct section_tester_data, is_dos), "is_dos", XOFFSET(struct section_tester_data, is_dos) },
  [STESTER_no_redirect] = { STESTER_no_redirect, 'i', XSIZE(struct section_tester_data, no_redirect), "no_redirect", XOFFSET(struct section_tester_data, no_redirect) },
  [STESTER_priority_adjustment] = { STESTER_priority_adjustment, 'i', XSIZE(struct section_tester_data, priority_adjustment), "priority_adjustment", XOFFSET(struct section_tester_data, priority_adjustment) },
  [STESTER_ignore_stderr] = { STESTER_ignore_stderr, 'i', XSIZE(struct section_tester_data, ignore_stderr), "ignore_stderr", XOFFSET(struct section_tester_data, ignore_stderr) },
  [STESTER_arch] = { STESTER_arch, 'S', XSIZE(struct section_tester_data, arch), "arch", XOFFSET(struct section_tester_data, arch) },
  [STESTER_key] = { STESTER_key, 'S', XSIZE(struct section_tester_data, key), "key", XOFFSET(struct section_tester_data, key) },
  [STESTER_memory_limit_type] = { STESTER_memory_limit_type, 'S', XSIZE(struct section_tester_data, memory_limit_type), "memory_limit_type", XOFFSET(struct section_tester_data, memory_limit_type) },
  [STESTER_secure_exec_type] = { STESTER_secure_exec_type, 'S', XSIZE(struct section_tester_data, secure_exec_type), "secure_exec_type", XOFFSET(struct section_tester_data, secure_exec_type) },
  [STESTER_abstract] = { STESTER_abstract, 'i', XSIZE(struct section_tester_data, abstract), "abstract", XOFFSET(struct section_tester_data, abstract) },
  [STESTER_super] = { STESTER_super, 'x', XSIZE(struct section_tester_data, super), "super", XOFFSET(struct section_tester_data, super) },
  [STESTER_is_processed] = { STESTER_is_processed, 'i', XSIZE(struct section_tester_data, is_processed), "is_processed", XOFFSET(struct section_tester_data, is_processed) },
  [STESTER_skip_testing] = { STESTER_skip_testing, 'i', XSIZE(struct section_tester_data, skip_testing), "skip_testing", XOFFSET(struct section_tester_data, skip_testing) },
  [STESTER_no_core_dump] = { STESTER_no_core_dump, 'i', XSIZE(struct section_tester_data, no_core_dump), "no_core_dump", XOFFSET(struct section_tester_data, no_core_dump) },
  [STESTER_enable_memory_limit_error] = { STESTER_enable_memory_limit_error, 'i', XSIZE(struct section_tester_data, enable_memory_limit_error), "enable_memory_limit_error", XOFFSET(struct section_tester_data, enable_memory_limit_error) },
  [STESTER_kill_signal] = { STESTER_kill_signal, 'S', XSIZE(struct section_tester_data, kill_signal), "kill_signal", XOFFSET(struct section_tester_data, kill_signal) },
  [STESTER_max_stack_size] = { STESTER_max_stack_size, '?', XSIZE(struct section_tester_data, max_stack_size), "max_stack_size", XOFFSET(struct section_tester_data, max_stack_size) },
  [STESTER_max_data_size] = { STESTER_max_data_size, '?', XSIZE(struct section_tester_data, max_data_size), "max_data_size", XOFFSET(struct section_tester_data, max_data_size) },
  [STESTER_max_vm_size] = { STESTER_max_vm_size, '?', XSIZE(struct section_tester_data, max_vm_size), "max_vm_size", XOFFSET(struct section_tester_data, max_vm_size) },
  [STESTER_clear_env] = { STESTER_clear_env, 'i', XSIZE(struct section_tester_data, clear_env), "clear_env", XOFFSET(struct section_tester_data, clear_env) },
  [STESTER_time_limit_adjustment] = { STESTER_time_limit_adjustment, 'i', XSIZE(struct section_tester_data, time_limit_adjustment), "time_limit_adjustment", XOFFSET(struct section_tester_data, time_limit_adjustment) },
  [STESTER_time_limit_adj_millis] = { STESTER_time_limit_adj_millis, 'i', XSIZE(struct section_tester_data, time_limit_adj_millis), "time_limit_adj_millis", XOFFSET(struct section_tester_data, time_limit_adj_millis) },
  [STESTER_run_dir] = { STESTER_run_dir, 'S', XSIZE(struct section_tester_data, run_dir), "run_dir", XOFFSET(struct section_tester_data, run_dir) },
  [STESTER_run_queue_dir] = { STESTER_run_queue_dir, 'S', XSIZE(struct section_tester_data, run_queue_dir), "run_queue_dir", XOFFSET(struct section_tester_data, run_queue_dir) },
  [STESTER_run_exe_dir] = { STESTER_run_exe_dir, 'S', XSIZE(struct section_tester_data, run_exe_dir), "run_exe_dir", XOFFSET(struct section_tester_data, run_exe_dir) },
  [STESTER_run_out_dir] = { STESTER_run_out_dir, 'S', XSIZE(struct section_tester_data, run_out_dir), "run_out_dir", XOFFSET(struct section_tester_data, run_out_dir) },
  [STESTER_run_status_dir] = { STESTER_run_status_dir, 'S', XSIZE(struct section_tester_data, run_status_dir), "run_status_dir", XOFFSET(struct section_tester_data, run_status_dir) },
  [STESTER_run_report_dir] = { STESTER_run_report_dir, 'S', XSIZE(struct section_tester_data, run_report_dir), "run_report_dir", XOFFSET(struct section_tester_data, run_report_dir) },
  [STESTER_run_team_report_dir] = { STESTER_run_team_report_dir, 'S', XSIZE(struct section_tester_data, run_team_report_dir), "run_team_report_dir", XOFFSET(struct section_tester_data, run_team_report_dir) },
  [STESTER_run_full_archive_dir] = { STESTER_run_full_archive_dir, 'S', XSIZE(struct section_tester_data, run_full_archive_dir), "run_full_archive_dir", XOFFSET(struct section_tester_data, run_full_archive_dir) },
  [STESTER_check_dir] = { STESTER_check_dir, 'S', XSIZE(struct section_tester_data, check_dir), "check_dir", XOFFSET(struct section_tester_data, check_dir) },
  [STESTER_errorcode_file] = { STESTER_errorcode_file, 'S', XSIZE(struct section_tester_data, errorcode_file), "errorcode_file", XOFFSET(struct section_tester_data, errorcode_file) },
  [STESTER_error_file] = { STESTER_error_file, 'S', XSIZE(struct section_tester_data, error_file), "error_file", XOFFSET(struct section_tester_data, error_file) },
  [STESTER_prepare_cmd] = { STESTER_prepare_cmd, 'S', XSIZE(struct section_tester_data, prepare_cmd), "prepare_cmd", XOFFSET(struct section_tester_data, prepare_cmd) },
  [STESTER_start_cmd] = { STESTER_start_cmd, 'S', XSIZE(struct section_tester_data, start_cmd), "start_cmd", XOFFSET(struct section_tester_data, start_cmd) },
  [STESTER_check_cmd] = { STESTER_check_cmd, 'S', XSIZE(struct section_tester_data, check_cmd), "check_cmd", XOFFSET(struct section_tester_data, check_cmd) },
  [STESTER_start_env] = { STESTER_start_env, 'x', XSIZE(struct section_tester_data, start_env), "start_env", XOFFSET(struct section_tester_data, start_env) },
  [STESTER_checker_env] = { STESTER_checker_env, 'x', XSIZE(struct section_tester_data, checker_env), "checker_env", XOFFSET(struct section_tester_data, checker_env) },
  [STESTER_standard_checker_used] = { STESTER_standard_checker_used, 'i', XSIZE(struct section_tester_data, standard_checker_used), "standard_checker_used", XOFFSET(struct section_tester_data, standard_checker_used) },
  [STESTER_memory_limit_type_val] = { STESTER_memory_limit_type_val, 'i', XSIZE(struct section_tester_data, memory_limit_type_val), "memory_limit_type_val", XOFFSET(struct section_tester_data, memory_limit_type_val) },
  [STESTER_secure_exec_type_val] = { STESTER_secure_exec_type_val, 'i', XSIZE(struct section_tester_data, secure_exec_type_val), "secure_exec_type_val", XOFFSET(struct section_tester_data, secure_exec_type_val) },
};

int tester_get_type(int tag)
{
  ASSERT(tag > 0 && tag < STESTER_LAST_FIELD);
  return meta_info_section_tester_data_data[tag].type;
}

size_t tester_get_size(int tag)
{
  ASSERT(tag > 0 && tag < STESTER_LAST_FIELD);
  return meta_info_section_tester_data_data[tag].size;
}

const char *tester_get_name(int tag)
{
  ASSERT(tag > 0 && tag < STESTER_LAST_FIELD);
  return meta_info_section_tester_data_data[tag].name;
}

const void *tester_get_ptr(const struct section_tester_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < STESTER_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_tester_data_data[tag].offset);
}

void *tester_get_ptr_nc(struct section_tester_data *ptr, int tag)
{
  ASSERT(tag > 0 && tag < STESTER_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_section_tester_data_data[tag].offset);
}

int tester_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_section_tester_data_data, STESTER_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

