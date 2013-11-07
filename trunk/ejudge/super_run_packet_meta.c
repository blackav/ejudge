// This is an auto-generated file, do not edit
// Generated 2013/11/07 22:02:04

#include "super_run_packet_meta.h"
#include "super_run_packet.h"
#include "meta_generic.h"

#include "reuse_xalloc.h"

#include "reuse_logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_super_run_in_global_packet_data[] =
{
  [META_SUPER_RUN_IN_GLOBAL_PACKET_contest_id] = { META_SUPER_RUN_IN_GLOBAL_PACKET_contest_id, 'i', XSIZE(struct super_run_in_global_packet, contest_id), "contest_id", XOFFSET(struct super_run_in_global_packet, contest_id) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_judge_id] = { META_SUPER_RUN_IN_GLOBAL_PACKET_judge_id, 'i', XSIZE(struct super_run_in_global_packet, judge_id), "judge_id", XOFFSET(struct super_run_in_global_packet, judge_id) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_run_id] = { META_SUPER_RUN_IN_GLOBAL_PACKET_run_id, 'i', XSIZE(struct super_run_in_global_packet, run_id), "run_id", XOFFSET(struct super_run_in_global_packet, run_id) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_reply_spool_dir] = { META_SUPER_RUN_IN_GLOBAL_PACKET_reply_spool_dir, 's', XSIZE(struct super_run_in_global_packet, reply_spool_dir), "reply_spool_dir", XOFFSET(struct super_run_in_global_packet, reply_spool_dir) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_reply_report_dir] = { META_SUPER_RUN_IN_GLOBAL_PACKET_reply_report_dir, 's', XSIZE(struct super_run_in_global_packet, reply_report_dir), "reply_report_dir", XOFFSET(struct super_run_in_global_packet, reply_report_dir) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_reply_full_archive_dir] = { META_SUPER_RUN_IN_GLOBAL_PACKET_reply_full_archive_dir, 's', XSIZE(struct super_run_in_global_packet, reply_full_archive_dir), "reply_full_archive_dir", XOFFSET(struct super_run_in_global_packet, reply_full_archive_dir) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_reply_packet_name] = { META_SUPER_RUN_IN_GLOBAL_PACKET_reply_packet_name, 's', XSIZE(struct super_run_in_global_packet, reply_packet_name), "reply_packet_name", XOFFSET(struct super_run_in_global_packet, reply_packet_name) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_priority] = { META_SUPER_RUN_IN_GLOBAL_PACKET_priority, 'i', XSIZE(struct super_run_in_global_packet, priority), "priority", XOFFSET(struct super_run_in_global_packet, priority) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_variant] = { META_SUPER_RUN_IN_GLOBAL_PACKET_variant, 'i', XSIZE(struct super_run_in_global_packet, variant), "variant", XOFFSET(struct super_run_in_global_packet, variant) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_lang_short_name] = { META_SUPER_RUN_IN_GLOBAL_PACKET_lang_short_name, 's', XSIZE(struct super_run_in_global_packet, lang_short_name), "lang_short_name", XOFFSET(struct super_run_in_global_packet, lang_short_name) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_arch] = { META_SUPER_RUN_IN_GLOBAL_PACKET_arch, 's', XSIZE(struct super_run_in_global_packet, arch), "arch", XOFFSET(struct super_run_in_global_packet, arch) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_lang_key] = { META_SUPER_RUN_IN_GLOBAL_PACKET_lang_key, 's', XSIZE(struct super_run_in_global_packet, lang_key), "lang_key", XOFFSET(struct super_run_in_global_packet, lang_key) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_secure_run] = { META_SUPER_RUN_IN_GLOBAL_PACKET_secure_run, 'B', XSIZE(struct super_run_in_global_packet, secure_run), "secure_run", XOFFSET(struct super_run_in_global_packet, secure_run) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_detect_violations] = { META_SUPER_RUN_IN_GLOBAL_PACKET_detect_violations, 'B', XSIZE(struct super_run_in_global_packet, detect_violations), "detect_violations", XOFFSET(struct super_run_in_global_packet, detect_violations) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_enable_memory_limit_error] = { META_SUPER_RUN_IN_GLOBAL_PACKET_enable_memory_limit_error, 'B', XSIZE(struct super_run_in_global_packet, enable_memory_limit_error), "enable_memory_limit_error", XOFFSET(struct super_run_in_global_packet, enable_memory_limit_error) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_enable_max_stack_size] = { META_SUPER_RUN_IN_GLOBAL_PACKET_enable_max_stack_size, 'B', XSIZE(struct super_run_in_global_packet, enable_max_stack_size), "enable_max_stack_size", XOFFSET(struct super_run_in_global_packet, enable_max_stack_size) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_user_id] = { META_SUPER_RUN_IN_GLOBAL_PACKET_user_id, 'i', XSIZE(struct super_run_in_global_packet, user_id), "user_id", XOFFSET(struct super_run_in_global_packet, user_id) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_user_login] = { META_SUPER_RUN_IN_GLOBAL_PACKET_user_login, 's', XSIZE(struct super_run_in_global_packet, user_login), "user_login", XOFFSET(struct super_run_in_global_packet, user_login) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_user_name] = { META_SUPER_RUN_IN_GLOBAL_PACKET_user_name, 's', XSIZE(struct super_run_in_global_packet, user_name), "user_name", XOFFSET(struct super_run_in_global_packet, user_name) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_user_spelling] = { META_SUPER_RUN_IN_GLOBAL_PACKET_user_spelling, 's', XSIZE(struct super_run_in_global_packet, user_spelling), "user_spelling", XOFFSET(struct super_run_in_global_packet, user_spelling) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_score_system] = { META_SUPER_RUN_IN_GLOBAL_PACKET_score_system, 's', XSIZE(struct super_run_in_global_packet, score_system), "score_system", XOFFSET(struct super_run_in_global_packet, score_system) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_is_virtual] = { META_SUPER_RUN_IN_GLOBAL_PACKET_is_virtual, 'B', XSIZE(struct super_run_in_global_packet, is_virtual), "is_virtual", XOFFSET(struct super_run_in_global_packet, is_virtual) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_max_file_length] = { META_SUPER_RUN_IN_GLOBAL_PACKET_max_file_length, 'z', XSIZE(struct super_run_in_global_packet, max_file_length), "max_file_length", XOFFSET(struct super_run_in_global_packet, max_file_length) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_max_line_length] = { META_SUPER_RUN_IN_GLOBAL_PACKET_max_line_length, 'z', XSIZE(struct super_run_in_global_packet, max_line_length), "max_line_length", XOFFSET(struct super_run_in_global_packet, max_line_length) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_max_cmd_length] = { META_SUPER_RUN_IN_GLOBAL_PACKET_max_cmd_length, 'z', XSIZE(struct super_run_in_global_packet, max_cmd_length), "max_cmd_length", XOFFSET(struct super_run_in_global_packet, max_cmd_length) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_enable_full_archive] = { META_SUPER_RUN_IN_GLOBAL_PACKET_enable_full_archive, 'B', XSIZE(struct super_run_in_global_packet, enable_full_archive), "enable_full_archive", XOFFSET(struct super_run_in_global_packet, enable_full_archive) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_accepting_mode] = { META_SUPER_RUN_IN_GLOBAL_PACKET_accepting_mode, 'B', XSIZE(struct super_run_in_global_packet, accepting_mode), "accepting_mode", XOFFSET(struct super_run_in_global_packet, accepting_mode) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_separate_user_score] = { META_SUPER_RUN_IN_GLOBAL_PACKET_separate_user_score, 'B', XSIZE(struct super_run_in_global_packet, separate_user_score), "separate_user_score", XOFFSET(struct super_run_in_global_packet, separate_user_score) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_mime_type] = { META_SUPER_RUN_IN_GLOBAL_PACKET_mime_type, 'i', XSIZE(struct super_run_in_global_packet, mime_type), "mime_type", XOFFSET(struct super_run_in_global_packet, mime_type) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_notify_flag] = { META_SUPER_RUN_IN_GLOBAL_PACKET_notify_flag, 'B', XSIZE(struct super_run_in_global_packet, notify_flag), "notify_flag", XOFFSET(struct super_run_in_global_packet, notify_flag) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_advanced_layout] = { META_SUPER_RUN_IN_GLOBAL_PACKET_advanced_layout, 'B', XSIZE(struct super_run_in_global_packet, advanced_layout), "advanced_layout", XOFFSET(struct super_run_in_global_packet, advanced_layout) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_ts1] = { META_SUPER_RUN_IN_GLOBAL_PACKET_ts1, 'i', XSIZE(struct super_run_in_global_packet, ts1), "ts1", XOFFSET(struct super_run_in_global_packet, ts1) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_ts1_us] = { META_SUPER_RUN_IN_GLOBAL_PACKET_ts1_us, 'i', XSIZE(struct super_run_in_global_packet, ts1_us), "ts1_us", XOFFSET(struct super_run_in_global_packet, ts1_us) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_ts2] = { META_SUPER_RUN_IN_GLOBAL_PACKET_ts2, 'i', XSIZE(struct super_run_in_global_packet, ts2), "ts2", XOFFSET(struct super_run_in_global_packet, ts2) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_ts2_us] = { META_SUPER_RUN_IN_GLOBAL_PACKET_ts2_us, 'i', XSIZE(struct super_run_in_global_packet, ts2_us), "ts2_us", XOFFSET(struct super_run_in_global_packet, ts2_us) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_ts3] = { META_SUPER_RUN_IN_GLOBAL_PACKET_ts3, 'i', XSIZE(struct super_run_in_global_packet, ts3), "ts3", XOFFSET(struct super_run_in_global_packet, ts3) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_ts3_us] = { META_SUPER_RUN_IN_GLOBAL_PACKET_ts3_us, 'i', XSIZE(struct super_run_in_global_packet, ts3_us), "ts3_us", XOFFSET(struct super_run_in_global_packet, ts3_us) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_ts4] = { META_SUPER_RUN_IN_GLOBAL_PACKET_ts4, 'i', XSIZE(struct super_run_in_global_packet, ts4), "ts4", XOFFSET(struct super_run_in_global_packet, ts4) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_ts4_us] = { META_SUPER_RUN_IN_GLOBAL_PACKET_ts4_us, 'i', XSIZE(struct super_run_in_global_packet, ts4_us), "ts4_us", XOFFSET(struct super_run_in_global_packet, ts4_us) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_lang_time_limit_adj_ms] = { META_SUPER_RUN_IN_GLOBAL_PACKET_lang_time_limit_adj_ms, 'i', XSIZE(struct super_run_in_global_packet, lang_time_limit_adj_ms), "lang_time_limit_adj_ms", XOFFSET(struct super_run_in_global_packet, lang_time_limit_adj_ms) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_exe_sfx] = { META_SUPER_RUN_IN_GLOBAL_PACKET_exe_sfx, 's', XSIZE(struct super_run_in_global_packet, exe_sfx), "exe_sfx", XOFFSET(struct super_run_in_global_packet, exe_sfx) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_restart] = { META_SUPER_RUN_IN_GLOBAL_PACKET_restart, 'B', XSIZE(struct super_run_in_global_packet, restart), "restart", XOFFSET(struct super_run_in_global_packet, restart) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_disable_sound] = { META_SUPER_RUN_IN_GLOBAL_PACKET_disable_sound, 'B', XSIZE(struct super_run_in_global_packet, disable_sound), "disable_sound", XOFFSET(struct super_run_in_global_packet, disable_sound) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_is_dos] = { META_SUPER_RUN_IN_GLOBAL_PACKET_is_dos, 'B', XSIZE(struct super_run_in_global_packet, is_dos), "is_dos", XOFFSET(struct super_run_in_global_packet, is_dos) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_time_limit_retry_count] = { META_SUPER_RUN_IN_GLOBAL_PACKET_time_limit_retry_count, 'i', XSIZE(struct super_run_in_global_packet, time_limit_retry_count), "time_limit_retry_count", XOFFSET(struct super_run_in_global_packet, time_limit_retry_count) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_checker_locale] = { META_SUPER_RUN_IN_GLOBAL_PACKET_checker_locale, 's', XSIZE(struct super_run_in_global_packet, checker_locale), "checker_locale", XOFFSET(struct super_run_in_global_packet, checker_locale) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_run_uuid] = { META_SUPER_RUN_IN_GLOBAL_PACKET_run_uuid, 's', XSIZE(struct super_run_in_global_packet, run_uuid), "run_uuid", XOFFSET(struct super_run_in_global_packet, run_uuid) },
};

int meta_super_run_in_global_packet_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_GLOBAL_PACKET_LAST_FIELD);
  return meta_info_super_run_in_global_packet_data[tag].type;
}

size_t meta_super_run_in_global_packet_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_GLOBAL_PACKET_LAST_FIELD);
  return meta_info_super_run_in_global_packet_data[tag].size;
}

const char *meta_super_run_in_global_packet_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_GLOBAL_PACKET_LAST_FIELD);
  return meta_info_super_run_in_global_packet_data[tag].name;
}

const void *meta_super_run_in_global_packet_get_ptr(const struct super_run_in_global_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_GLOBAL_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_super_run_in_global_packet_data[tag].offset);
}

void *meta_super_run_in_global_packet_get_ptr_nc(struct super_run_in_global_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_GLOBAL_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_super_run_in_global_packet_data[tag].offset);
}

int meta_super_run_in_global_packet_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_super_run_in_global_packet_data, META_SUPER_RUN_IN_GLOBAL_PACKET_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_super_run_in_global_packet_methods =
{
  META_SUPER_RUN_IN_GLOBAL_PACKET_LAST_FIELD,
  sizeof(struct super_run_in_global_packet),
  meta_super_run_in_global_packet_get_type,
  meta_super_run_in_global_packet_get_size,
  meta_super_run_in_global_packet_get_name,
  (const void *(*)(const void *ptr, int tag))meta_super_run_in_global_packet_get_ptr,
  (void *(*)(void *ptr, int tag))meta_super_run_in_global_packet_get_ptr_nc,
  meta_super_run_in_global_packet_lookup_field,
};

static struct meta_info_item meta_info_super_run_in_problem_packet_data[] =
{
  [META_SUPER_RUN_IN_PROBLEM_PACKET_type] = { META_SUPER_RUN_IN_PROBLEM_PACKET_type, 's', XSIZE(struct super_run_in_problem_packet, type), "type", XOFFSET(struct super_run_in_problem_packet, type) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_id] = { META_SUPER_RUN_IN_PROBLEM_PACKET_id, 'i', XSIZE(struct super_run_in_problem_packet, id), "id", XOFFSET(struct super_run_in_problem_packet, id) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_check_presentation] = { META_SUPER_RUN_IN_PROBLEM_PACKET_check_presentation, 'B', XSIZE(struct super_run_in_problem_packet, check_presentation), "check_presentation", XOFFSET(struct super_run_in_problem_packet, check_presentation) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_scoring_checker] = { META_SUPER_RUN_IN_PROBLEM_PACKET_scoring_checker, 'B', XSIZE(struct super_run_in_problem_packet, scoring_checker), "scoring_checker", XOFFSET(struct super_run_in_problem_packet, scoring_checker) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_interactive_valuer] = { META_SUPER_RUN_IN_PROBLEM_PACKET_interactive_valuer, 'B', XSIZE(struct super_run_in_problem_packet, interactive_valuer), "interactive_valuer", XOFFSET(struct super_run_in_problem_packet, interactive_valuer) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_disable_pe] = { META_SUPER_RUN_IN_PROBLEM_PACKET_disable_pe, 'B', XSIZE(struct super_run_in_problem_packet, disable_pe), "disable_pe", XOFFSET(struct super_run_in_problem_packet, disable_pe) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_disable_wtl] = { META_SUPER_RUN_IN_PROBLEM_PACKET_disable_wtl, 'B', XSIZE(struct super_run_in_problem_packet, disable_wtl), "disable_wtl", XOFFSET(struct super_run_in_problem_packet, disable_wtl) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_use_stdin] = { META_SUPER_RUN_IN_PROBLEM_PACKET_use_stdin, 'B', XSIZE(struct super_run_in_problem_packet, use_stdin), "use_stdin", XOFFSET(struct super_run_in_problem_packet, use_stdin) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_use_stdout] = { META_SUPER_RUN_IN_PROBLEM_PACKET_use_stdout, 'B', XSIZE(struct super_run_in_problem_packet, use_stdout), "use_stdout", XOFFSET(struct super_run_in_problem_packet, use_stdout) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_combined_stdin] = { META_SUPER_RUN_IN_PROBLEM_PACKET_combined_stdin, 'B', XSIZE(struct super_run_in_problem_packet, combined_stdin), "combined_stdin", XOFFSET(struct super_run_in_problem_packet, combined_stdin) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_combined_stdout] = { META_SUPER_RUN_IN_PROBLEM_PACKET_combined_stdout, 'B', XSIZE(struct super_run_in_problem_packet, combined_stdout), "combined_stdout", XOFFSET(struct super_run_in_problem_packet, combined_stdout) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_ignore_exit_code] = { META_SUPER_RUN_IN_PROBLEM_PACKET_ignore_exit_code, 'B', XSIZE(struct super_run_in_problem_packet, ignore_exit_code), "ignore_exit_code", XOFFSET(struct super_run_in_problem_packet, ignore_exit_code) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_binary_input] = { META_SUPER_RUN_IN_PROBLEM_PACKET_binary_input, 'B', XSIZE(struct super_run_in_problem_packet, binary_input), "binary_input", XOFFSET(struct super_run_in_problem_packet, binary_input) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_binary_output] = { META_SUPER_RUN_IN_PROBLEM_PACKET_binary_output, 'B', XSIZE(struct super_run_in_problem_packet, binary_output), "binary_output", XOFFSET(struct super_run_in_problem_packet, binary_output) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_real_time_limit_ms] = { META_SUPER_RUN_IN_PROBLEM_PACKET_real_time_limit_ms, 'i', XSIZE(struct super_run_in_problem_packet, real_time_limit_ms), "real_time_limit_ms", XOFFSET(struct super_run_in_problem_packet, real_time_limit_ms) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_time_limit_ms] = { META_SUPER_RUN_IN_PROBLEM_PACKET_time_limit_ms, 'i', XSIZE(struct super_run_in_problem_packet, time_limit_ms), "time_limit_ms", XOFFSET(struct super_run_in_problem_packet, time_limit_ms) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_use_ac_not_ok] = { META_SUPER_RUN_IN_PROBLEM_PACKET_use_ac_not_ok, 'B', XSIZE(struct super_run_in_problem_packet, use_ac_not_ok), "use_ac_not_ok", XOFFSET(struct super_run_in_problem_packet, use_ac_not_ok) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_full_score] = { META_SUPER_RUN_IN_PROBLEM_PACKET_full_score, 'i', XSIZE(struct super_run_in_problem_packet, full_score), "full_score", XOFFSET(struct super_run_in_problem_packet, full_score) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_full_user_score] = { META_SUPER_RUN_IN_PROBLEM_PACKET_full_user_score, 'i', XSIZE(struct super_run_in_problem_packet, full_user_score), "full_user_score", XOFFSET(struct super_run_in_problem_packet, full_user_score) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_variable_full_score] = { META_SUPER_RUN_IN_PROBLEM_PACKET_variable_full_score, 'B', XSIZE(struct super_run_in_problem_packet, variable_full_score), "variable_full_score", XOFFSET(struct super_run_in_problem_packet, variable_full_score) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_score] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_score, 'i', XSIZE(struct super_run_in_problem_packet, test_score), "test_score", XOFFSET(struct super_run_in_problem_packet, test_score) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_use_corr] = { META_SUPER_RUN_IN_PROBLEM_PACKET_use_corr, 'B', XSIZE(struct super_run_in_problem_packet, use_corr), "use_corr", XOFFSET(struct super_run_in_problem_packet, use_corr) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_use_info] = { META_SUPER_RUN_IN_PROBLEM_PACKET_use_info, 'B', XSIZE(struct super_run_in_problem_packet, use_info), "use_info", XOFFSET(struct super_run_in_problem_packet, use_info) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_use_tgz] = { META_SUPER_RUN_IN_PROBLEM_PACKET_use_tgz, 'B', XSIZE(struct super_run_in_problem_packet, use_tgz), "use_tgz", XOFFSET(struct super_run_in_problem_packet, use_tgz) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_tests_to_accept] = { META_SUPER_RUN_IN_PROBLEM_PACKET_tests_to_accept, 'i', XSIZE(struct super_run_in_problem_packet, tests_to_accept), "tests_to_accept", XOFFSET(struct super_run_in_problem_packet, tests_to_accept) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_accept_partial] = { META_SUPER_RUN_IN_PROBLEM_PACKET_accept_partial, 'B', XSIZE(struct super_run_in_problem_packet, accept_partial), "accept_partial", XOFFSET(struct super_run_in_problem_packet, accept_partial) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_min_tests_to_accept] = { META_SUPER_RUN_IN_PROBLEM_PACKET_min_tests_to_accept, 'i', XSIZE(struct super_run_in_problem_packet, min_tests_to_accept), "min_tests_to_accept", XOFFSET(struct super_run_in_problem_packet, min_tests_to_accept) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_checker_real_time_limit_ms] = { META_SUPER_RUN_IN_PROBLEM_PACKET_checker_real_time_limit_ms, 'i', XSIZE(struct super_run_in_problem_packet, checker_real_time_limit_ms), "checker_real_time_limit_ms", XOFFSET(struct super_run_in_problem_packet, checker_real_time_limit_ms) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_short_name] = { META_SUPER_RUN_IN_PROBLEM_PACKET_short_name, 's', XSIZE(struct super_run_in_problem_packet, short_name), "short_name", XOFFSET(struct super_run_in_problem_packet, short_name) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_long_name] = { META_SUPER_RUN_IN_PROBLEM_PACKET_long_name, 's', XSIZE(struct super_run_in_problem_packet, long_name), "long_name", XOFFSET(struct super_run_in_problem_packet, long_name) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_internal_name] = { META_SUPER_RUN_IN_PROBLEM_PACKET_internal_name, 's', XSIZE(struct super_run_in_problem_packet, internal_name), "internal_name", XOFFSET(struct super_run_in_problem_packet, internal_name) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_problem_dir] = { META_SUPER_RUN_IN_PROBLEM_PACKET_problem_dir, 's', XSIZE(struct super_run_in_problem_packet, problem_dir), "problem_dir", XOFFSET(struct super_run_in_problem_packet, problem_dir) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_dir] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_dir, 's', XSIZE(struct super_run_in_problem_packet, test_dir), "test_dir", XOFFSET(struct super_run_in_problem_packet, test_dir) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_corr_dir] = { META_SUPER_RUN_IN_PROBLEM_PACKET_corr_dir, 's', XSIZE(struct super_run_in_problem_packet, corr_dir), "corr_dir", XOFFSET(struct super_run_in_problem_packet, corr_dir) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_info_dir] = { META_SUPER_RUN_IN_PROBLEM_PACKET_info_dir, 's', XSIZE(struct super_run_in_problem_packet, info_dir), "info_dir", XOFFSET(struct super_run_in_problem_packet, info_dir) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_tgz_dir] = { META_SUPER_RUN_IN_PROBLEM_PACKET_tgz_dir, 's', XSIZE(struct super_run_in_problem_packet, tgz_dir), "tgz_dir", XOFFSET(struct super_run_in_problem_packet, tgz_dir) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_input_file] = { META_SUPER_RUN_IN_PROBLEM_PACKET_input_file, 's', XSIZE(struct super_run_in_problem_packet, input_file), "input_file", XOFFSET(struct super_run_in_problem_packet, input_file) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_output_file] = { META_SUPER_RUN_IN_PROBLEM_PACKET_output_file, 's', XSIZE(struct super_run_in_problem_packet, output_file), "output_file", XOFFSET(struct super_run_in_problem_packet, output_file) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_score_list] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_score_list, 's', XSIZE(struct super_run_in_problem_packet, test_score_list), "test_score_list", XOFFSET(struct super_run_in_problem_packet, test_score_list) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_score_tests] = { META_SUPER_RUN_IN_PROBLEM_PACKET_score_tests, 's', XSIZE(struct super_run_in_problem_packet, score_tests), "score_tests", XOFFSET(struct super_run_in_problem_packet, score_tests) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_standard_checker] = { META_SUPER_RUN_IN_PROBLEM_PACKET_standard_checker, 's', XSIZE(struct super_run_in_problem_packet, standard_checker), "standard_checker", XOFFSET(struct super_run_in_problem_packet, standard_checker) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_valuer_sets_marked] = { META_SUPER_RUN_IN_PROBLEM_PACKET_valuer_sets_marked, 'B', XSIZE(struct super_run_in_problem_packet, valuer_sets_marked), "valuer_sets_marked", XOFFSET(struct super_run_in_problem_packet, valuer_sets_marked) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_time_limit_ms] = { META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_time_limit_ms, 'i', XSIZE(struct super_run_in_problem_packet, interactor_time_limit_ms), "interactor_time_limit_ms", XOFFSET(struct super_run_in_problem_packet, interactor_time_limit_ms) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_disable_stderr] = { META_SUPER_RUN_IN_PROBLEM_PACKET_disable_stderr, 'B', XSIZE(struct super_run_in_problem_packet, disable_stderr), "disable_stderr", XOFFSET(struct super_run_in_problem_packet, disable_stderr) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_pat] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_pat, 's', XSIZE(struct super_run_in_problem_packet, test_pat), "test_pat", XOFFSET(struct super_run_in_problem_packet, test_pat) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_corr_pat] = { META_SUPER_RUN_IN_PROBLEM_PACKET_corr_pat, 's', XSIZE(struct super_run_in_problem_packet, corr_pat), "corr_pat", XOFFSET(struct super_run_in_problem_packet, corr_pat) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_info_pat] = { META_SUPER_RUN_IN_PROBLEM_PACKET_info_pat, 's', XSIZE(struct super_run_in_problem_packet, info_pat), "info_pat", XOFFSET(struct super_run_in_problem_packet, info_pat) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_tgz_pat] = { META_SUPER_RUN_IN_PROBLEM_PACKET_tgz_pat, 's', XSIZE(struct super_run_in_problem_packet, tgz_pat), "tgz_pat", XOFFSET(struct super_run_in_problem_packet, tgz_pat) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_tgzdir_pat] = { META_SUPER_RUN_IN_PROBLEM_PACKET_tgzdir_pat, 's', XSIZE(struct super_run_in_problem_packet, tgzdir_pat), "tgzdir_pat", XOFFSET(struct super_run_in_problem_packet, tgzdir_pat) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_sets] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_sets, 'x', XSIZE(struct super_run_in_problem_packet, test_sets), "test_sets", XOFFSET(struct super_run_in_problem_packet, test_sets) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_checker_env] = { META_SUPER_RUN_IN_PROBLEM_PACKET_checker_env, 'X', XSIZE(struct super_run_in_problem_packet, checker_env), "checker_env", XOFFSET(struct super_run_in_problem_packet, checker_env) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_valuer_env] = { META_SUPER_RUN_IN_PROBLEM_PACKET_valuer_env, 'X', XSIZE(struct super_run_in_problem_packet, valuer_env), "valuer_env", XOFFSET(struct super_run_in_problem_packet, valuer_env) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_env] = { META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_env, 'X', XSIZE(struct super_run_in_problem_packet, interactor_env), "interactor_env", XOFFSET(struct super_run_in_problem_packet, interactor_env) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_checker_env] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_checker_env, 'X', XSIZE(struct super_run_in_problem_packet, test_checker_env), "test_checker_env", XOFFSET(struct super_run_in_problem_packet, test_checker_env) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_init_env] = { META_SUPER_RUN_IN_PROBLEM_PACKET_init_env, 'X', XSIZE(struct super_run_in_problem_packet, init_env), "init_env", XOFFSET(struct super_run_in_problem_packet, init_env) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_start_env] = { META_SUPER_RUN_IN_PROBLEM_PACKET_start_env, 'X', XSIZE(struct super_run_in_problem_packet, start_env), "start_env", XOFFSET(struct super_run_in_problem_packet, start_env) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_check_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_check_cmd, 's', XSIZE(struct super_run_in_problem_packet, check_cmd), "check_cmd", XOFFSET(struct super_run_in_problem_packet, check_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_valuer_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_valuer_cmd, 's', XSIZE(struct super_run_in_problem_packet, valuer_cmd), "valuer_cmd", XOFFSET(struct super_run_in_problem_packet, valuer_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_cmd, 's', XSIZE(struct super_run_in_problem_packet, interactor_cmd), "interactor_cmd", XOFFSET(struct super_run_in_problem_packet, interactor_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_checker_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_checker_cmd, 's', XSIZE(struct super_run_in_problem_packet, test_checker_cmd), "test_checker_cmd", XOFFSET(struct super_run_in_problem_packet, test_checker_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_init_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_init_cmd, 's', XSIZE(struct super_run_in_problem_packet, init_cmd), "init_cmd", XOFFSET(struct super_run_in_problem_packet, init_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_solution_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_solution_cmd, 's', XSIZE(struct super_run_in_problem_packet, solution_cmd), "solution_cmd", XOFFSET(struct super_run_in_problem_packet, solution_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_vm_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_vm_size, 'Z', XSIZE(struct super_run_in_problem_packet, max_vm_size), "max_vm_size", XOFFSET(struct super_run_in_problem_packet, max_vm_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_data_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_data_size, 'Z', XSIZE(struct super_run_in_problem_packet, max_data_size), "max_data_size", XOFFSET(struct super_run_in_problem_packet, max_data_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_stack_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_stack_size, 'Z', XSIZE(struct super_run_in_problem_packet, max_stack_size), "max_stack_size", XOFFSET(struct super_run_in_problem_packet, max_stack_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_core_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_core_size, 'Z', XSIZE(struct super_run_in_problem_packet, max_core_size), "max_core_size", XOFFSET(struct super_run_in_problem_packet, max_core_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_file_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_file_size, 'Z', XSIZE(struct super_run_in_problem_packet, max_file_size), "max_file_size", XOFFSET(struct super_run_in_problem_packet, max_file_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_open_file_count] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_open_file_count, 'i', XSIZE(struct super_run_in_problem_packet, max_open_file_count), "max_open_file_count", XOFFSET(struct super_run_in_problem_packet, max_open_file_count) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_process_count] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_process_count, 'i', XSIZE(struct super_run_in_problem_packet, max_process_count), "max_process_count", XOFFSET(struct super_run_in_problem_packet, max_process_count) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_spelling] = { META_SUPER_RUN_IN_PROBLEM_PACKET_spelling, 's', XSIZE(struct super_run_in_problem_packet, spelling), "spelling", XOFFSET(struct super_run_in_problem_packet, spelling) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_open_tests] = { META_SUPER_RUN_IN_PROBLEM_PACKET_open_tests, 's', XSIZE(struct super_run_in_problem_packet, open_tests), "open_tests", XOFFSET(struct super_run_in_problem_packet, open_tests) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_enable_process_group] = { META_SUPER_RUN_IN_PROBLEM_PACKET_enable_process_group, 'B', XSIZE(struct super_run_in_problem_packet, enable_process_group), "enable_process_group", XOFFSET(struct super_run_in_problem_packet, enable_process_group) },
};

int meta_super_run_in_problem_packet_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_PROBLEM_PACKET_LAST_FIELD);
  return meta_info_super_run_in_problem_packet_data[tag].type;
}

size_t meta_super_run_in_problem_packet_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_PROBLEM_PACKET_LAST_FIELD);
  return meta_info_super_run_in_problem_packet_data[tag].size;
}

const char *meta_super_run_in_problem_packet_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_PROBLEM_PACKET_LAST_FIELD);
  return meta_info_super_run_in_problem_packet_data[tag].name;
}

const void *meta_super_run_in_problem_packet_get_ptr(const struct super_run_in_problem_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_PROBLEM_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_super_run_in_problem_packet_data[tag].offset);
}

void *meta_super_run_in_problem_packet_get_ptr_nc(struct super_run_in_problem_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_PROBLEM_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_super_run_in_problem_packet_data[tag].offset);
}

int meta_super_run_in_problem_packet_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_super_run_in_problem_packet_data, META_SUPER_RUN_IN_PROBLEM_PACKET_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_super_run_in_problem_packet_methods =
{
  META_SUPER_RUN_IN_PROBLEM_PACKET_LAST_FIELD,
  sizeof(struct super_run_in_problem_packet),
  meta_super_run_in_problem_packet_get_type,
  meta_super_run_in_problem_packet_get_size,
  meta_super_run_in_problem_packet_get_name,
  (const void *(*)(const void *ptr, int tag))meta_super_run_in_problem_packet_get_ptr,
  (void *(*)(void *ptr, int tag))meta_super_run_in_problem_packet_get_ptr_nc,
  meta_super_run_in_problem_packet_lookup_field,
};

static struct meta_info_item meta_info_super_run_in_tester_packet_data[] =
{
  [META_SUPER_RUN_IN_TESTER_PACKET_name] = { META_SUPER_RUN_IN_TESTER_PACKET_name, 's', XSIZE(struct super_run_in_tester_packet, name), "name", XOFFSET(struct super_run_in_tester_packet, name) },
  [META_SUPER_RUN_IN_TESTER_PACKET_is_dos] = { META_SUPER_RUN_IN_TESTER_PACKET_is_dos, 'B', XSIZE(struct super_run_in_tester_packet, is_dos), "is_dos", XOFFSET(struct super_run_in_tester_packet, is_dos) },
  [META_SUPER_RUN_IN_TESTER_PACKET_no_redirect] = { META_SUPER_RUN_IN_TESTER_PACKET_no_redirect, 'B', XSIZE(struct super_run_in_tester_packet, no_redirect), "no_redirect", XOFFSET(struct super_run_in_tester_packet, no_redirect) },
  [META_SUPER_RUN_IN_TESTER_PACKET_priority_adjustment] = { META_SUPER_RUN_IN_TESTER_PACKET_priority_adjustment, 'i', XSIZE(struct super_run_in_tester_packet, priority_adjustment), "priority_adjustment", XOFFSET(struct super_run_in_tester_packet, priority_adjustment) },
  [META_SUPER_RUN_IN_TESTER_PACKET_ignore_stderr] = { META_SUPER_RUN_IN_TESTER_PACKET_ignore_stderr, 'B', XSIZE(struct super_run_in_tester_packet, ignore_stderr), "ignore_stderr", XOFFSET(struct super_run_in_tester_packet, ignore_stderr) },
  [META_SUPER_RUN_IN_TESTER_PACKET_arch] = { META_SUPER_RUN_IN_TESTER_PACKET_arch, 's', XSIZE(struct super_run_in_tester_packet, arch), "arch", XOFFSET(struct super_run_in_tester_packet, arch) },
  [META_SUPER_RUN_IN_TESTER_PACKET_key] = { META_SUPER_RUN_IN_TESTER_PACKET_key, 's', XSIZE(struct super_run_in_tester_packet, key), "key", XOFFSET(struct super_run_in_tester_packet, key) },
  [META_SUPER_RUN_IN_TESTER_PACKET_memory_limit_type] = { META_SUPER_RUN_IN_TESTER_PACKET_memory_limit_type, 's', XSIZE(struct super_run_in_tester_packet, memory_limit_type), "memory_limit_type", XOFFSET(struct super_run_in_tester_packet, memory_limit_type) },
  [META_SUPER_RUN_IN_TESTER_PACKET_secure_exec_type] = { META_SUPER_RUN_IN_TESTER_PACKET_secure_exec_type, 's', XSIZE(struct super_run_in_tester_packet, secure_exec_type), "secure_exec_type", XOFFSET(struct super_run_in_tester_packet, secure_exec_type) },
  [META_SUPER_RUN_IN_TESTER_PACKET_no_core_dump] = { META_SUPER_RUN_IN_TESTER_PACKET_no_core_dump, 'B', XSIZE(struct super_run_in_tester_packet, no_core_dump), "no_core_dump", XOFFSET(struct super_run_in_tester_packet, no_core_dump) },
  [META_SUPER_RUN_IN_TESTER_PACKET_enable_memory_limit_error] = { META_SUPER_RUN_IN_TESTER_PACKET_enable_memory_limit_error, 'B', XSIZE(struct super_run_in_tester_packet, enable_memory_limit_error), "enable_memory_limit_error", XOFFSET(struct super_run_in_tester_packet, enable_memory_limit_error) },
  [META_SUPER_RUN_IN_TESTER_PACKET_kill_signal] = { META_SUPER_RUN_IN_TESTER_PACKET_kill_signal, 's', XSIZE(struct super_run_in_tester_packet, kill_signal), "kill_signal", XOFFSET(struct super_run_in_tester_packet, kill_signal) },
  [META_SUPER_RUN_IN_TESTER_PACKET_clear_env] = { META_SUPER_RUN_IN_TESTER_PACKET_clear_env, 'B', XSIZE(struct super_run_in_tester_packet, clear_env), "clear_env", XOFFSET(struct super_run_in_tester_packet, clear_env) },
  [META_SUPER_RUN_IN_TESTER_PACKET_time_limit_adjustment_ms] = { META_SUPER_RUN_IN_TESTER_PACKET_time_limit_adjustment_ms, 'i', XSIZE(struct super_run_in_tester_packet, time_limit_adjustment_ms), "time_limit_adjustment_ms", XOFFSET(struct super_run_in_tester_packet, time_limit_adjustment_ms) },
  [META_SUPER_RUN_IN_TESTER_PACKET_errorcode_file] = { META_SUPER_RUN_IN_TESTER_PACKET_errorcode_file, 's', XSIZE(struct super_run_in_tester_packet, errorcode_file), "errorcode_file", XOFFSET(struct super_run_in_tester_packet, errorcode_file) },
  [META_SUPER_RUN_IN_TESTER_PACKET_error_file] = { META_SUPER_RUN_IN_TESTER_PACKET_error_file, 's', XSIZE(struct super_run_in_tester_packet, error_file), "error_file", XOFFSET(struct super_run_in_tester_packet, error_file) },
  [META_SUPER_RUN_IN_TESTER_PACKET_prepare_cmd] = { META_SUPER_RUN_IN_TESTER_PACKET_prepare_cmd, 's', XSIZE(struct super_run_in_tester_packet, prepare_cmd), "prepare_cmd", XOFFSET(struct super_run_in_tester_packet, prepare_cmd) },
  [META_SUPER_RUN_IN_TESTER_PACKET_start_cmd] = { META_SUPER_RUN_IN_TESTER_PACKET_start_cmd, 's', XSIZE(struct super_run_in_tester_packet, start_cmd), "start_cmd", XOFFSET(struct super_run_in_tester_packet, start_cmd) },
  [META_SUPER_RUN_IN_TESTER_PACKET_start_env] = { META_SUPER_RUN_IN_TESTER_PACKET_start_env, 'X', XSIZE(struct super_run_in_tester_packet, start_env), "start_env", XOFFSET(struct super_run_in_tester_packet, start_env) },
};

int meta_super_run_in_tester_packet_get_type(int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_TESTER_PACKET_LAST_FIELD);
  return meta_info_super_run_in_tester_packet_data[tag].type;
}

size_t meta_super_run_in_tester_packet_get_size(int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_TESTER_PACKET_LAST_FIELD);
  return meta_info_super_run_in_tester_packet_data[tag].size;
}

const char *meta_super_run_in_tester_packet_get_name(int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_TESTER_PACKET_LAST_FIELD);
  return meta_info_super_run_in_tester_packet_data[tag].name;
}

const void *meta_super_run_in_tester_packet_get_ptr(const struct super_run_in_tester_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_TESTER_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_super_run_in_tester_packet_data[tag].offset);
}

void *meta_super_run_in_tester_packet_get_ptr_nc(struct super_run_in_tester_packet *ptr, int tag)
{
  ASSERT(tag > 0 && tag < META_SUPER_RUN_IN_TESTER_PACKET_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_super_run_in_tester_packet_data[tag].offset);
}

int meta_super_run_in_tester_packet_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_super_run_in_tester_packet_data, META_SUPER_RUN_IN_TESTER_PACKET_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods meta_super_run_in_tester_packet_methods =
{
  META_SUPER_RUN_IN_TESTER_PACKET_LAST_FIELD,
  sizeof(struct super_run_in_tester_packet),
  meta_super_run_in_tester_packet_get_type,
  meta_super_run_in_tester_packet_get_size,
  meta_super_run_in_tester_packet_get_name,
  (const void *(*)(const void *ptr, int tag))meta_super_run_in_tester_packet_get_ptr,
  (void *(*)(void *ptr, int tag))meta_super_run_in_tester_packet_get_ptr_nc,
  meta_super_run_in_tester_packet_lookup_field,
};

