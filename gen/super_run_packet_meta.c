// This is an auto-generated file, do not edit

#include "ejudge/meta/super_run_packet_meta.h"
#include "ejudge/super_run_packet.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

#include "ejudge/parsecfg.h"

#include "ejudge/logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_super_run_in_global_packet_data[] =
{
  [META_SUPER_RUN_IN_GLOBAL_PACKET_contest_id] = { META_SUPER_RUN_IN_GLOBAL_PACKET_contest_id, 'i', XSIZE(struct super_run_in_global_packet, contest_id), "contest_id", XOFFSET(struct super_run_in_global_packet, contest_id) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_judge_id] = { META_SUPER_RUN_IN_GLOBAL_PACKET_judge_id, 'i', XSIZE(struct super_run_in_global_packet, judge_id), "judge_id", XOFFSET(struct super_run_in_global_packet, judge_id) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_run_id] = { META_SUPER_RUN_IN_GLOBAL_PACKET_run_id, 'i', XSIZE(struct super_run_in_global_packet, run_id), "run_id", XOFFSET(struct super_run_in_global_packet, run_id) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_submit_id] = { META_SUPER_RUN_IN_GLOBAL_PACKET_submit_id, 'E', XSIZE(struct super_run_in_global_packet, submit_id), "submit_id", XOFFSET(struct super_run_in_global_packet, submit_id) },
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
  [META_SUPER_RUN_IN_GLOBAL_PACKET_suid_run] = { META_SUPER_RUN_IN_GLOBAL_PACKET_suid_run, 'B', XSIZE(struct super_run_in_global_packet, suid_run), "suid_run", XOFFSET(struct super_run_in_global_packet, suid_run) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_enable_container] = { META_SUPER_RUN_IN_GLOBAL_PACKET_enable_container, 'B', XSIZE(struct super_run_in_global_packet, enable_container), "enable_container", XOFFSET(struct super_run_in_global_packet, enable_container) },
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
  [META_SUPER_RUN_IN_GLOBAL_PACKET_rejudge_flag] = { META_SUPER_RUN_IN_GLOBAL_PACKET_rejudge_flag, 'B', XSIZE(struct super_run_in_global_packet, rejudge_flag), "rejudge_flag", XOFFSET(struct super_run_in_global_packet, rejudge_flag) },
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
  [META_SUPER_RUN_IN_GLOBAL_PACKET_judge_uuid] = { META_SUPER_RUN_IN_GLOBAL_PACKET_judge_uuid, 's', XSIZE(struct super_run_in_global_packet, judge_uuid), "judge_uuid", XOFFSET(struct super_run_in_global_packet, judge_uuid) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_zip_mode] = { META_SUPER_RUN_IN_GLOBAL_PACKET_zip_mode, 'B', XSIZE(struct super_run_in_global_packet, zip_mode), "zip_mode", XOFFSET(struct super_run_in_global_packet, zip_mode) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_testlib_mode] = { META_SUPER_RUN_IN_GLOBAL_PACKET_testlib_mode, 'B', XSIZE(struct super_run_in_global_packet, testlib_mode), "testlib_mode", XOFFSET(struct super_run_in_global_packet, testlib_mode) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_contest_server_id] = { META_SUPER_RUN_IN_GLOBAL_PACKET_contest_server_id, 's', XSIZE(struct super_run_in_global_packet, contest_server_id), "contest_server_id", XOFFSET(struct super_run_in_global_packet, contest_server_id) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_separate_run_spool_mode] = { META_SUPER_RUN_IN_GLOBAL_PACKET_separate_run_spool_mode, 'B', XSIZE(struct super_run_in_global_packet, separate_run_spool_mode), "separate_run_spool_mode", XOFFSET(struct super_run_in_global_packet, separate_run_spool_mode) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_bson_available] = { META_SUPER_RUN_IN_GLOBAL_PACKET_bson_available, 'B', XSIZE(struct super_run_in_global_packet, bson_available), "bson_available", XOFFSET(struct super_run_in_global_packet, bson_available) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_lang_container_options] = { META_SUPER_RUN_IN_GLOBAL_PACKET_lang_container_options, 's', XSIZE(struct super_run_in_global_packet, lang_container_options), "lang_container_options", XOFFSET(struct super_run_in_global_packet, lang_container_options) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_not_ok_is_cf] = { META_SUPER_RUN_IN_GLOBAL_PACKET_not_ok_is_cf, 'B', XSIZE(struct super_run_in_global_packet, not_ok_is_cf), "not_ok_is_cf", XOFFSET(struct super_run_in_global_packet, not_ok_is_cf) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_prepended_size] = { META_SUPER_RUN_IN_GLOBAL_PACKET_prepended_size, 'i', XSIZE(struct super_run_in_global_packet, prepended_size), "prepended_size", XOFFSET(struct super_run_in_global_packet, prepended_size) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_cached_on_remote] = { META_SUPER_RUN_IN_GLOBAL_PACKET_cached_on_remote, 'i', XSIZE(struct super_run_in_global_packet, cached_on_remote), "cached_on_remote", XOFFSET(struct super_run_in_global_packet, cached_on_remote) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_src_sfx] = { META_SUPER_RUN_IN_GLOBAL_PACKET_src_sfx, 's', XSIZE(struct super_run_in_global_packet, src_sfx), "src_sfx", XOFFSET(struct super_run_in_global_packet, src_sfx) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_src_file] = { META_SUPER_RUN_IN_GLOBAL_PACKET_src_file, 's', XSIZE(struct super_run_in_global_packet, src_file), "src_file", XOFFSET(struct super_run_in_global_packet, src_file) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_enable_ejudge_env] = { META_SUPER_RUN_IN_GLOBAL_PACKET_enable_ejudge_env, 'B', XSIZE(struct super_run_in_global_packet, enable_ejudge_env), "enable_ejudge_env", XOFFSET(struct super_run_in_global_packet, enable_ejudge_env) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_clean_up_cmd] = { META_SUPER_RUN_IN_GLOBAL_PACKET_clean_up_cmd, 's', XSIZE(struct super_run_in_global_packet, clean_up_cmd), "clean_up_cmd", XOFFSET(struct super_run_in_global_packet, clean_up_cmd) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_run_env_file] = { META_SUPER_RUN_IN_GLOBAL_PACKET_run_env_file, 's', XSIZE(struct super_run_in_global_packet, run_env_file), "run_env_file", XOFFSET(struct super_run_in_global_packet, run_env_file) },
  [META_SUPER_RUN_IN_GLOBAL_PACKET_clean_up_env_file] = { META_SUPER_RUN_IN_GLOBAL_PACKET_clean_up_env_file, 's', XSIZE(struct super_run_in_global_packet, clean_up_env_file), "clean_up_env_file", XOFFSET(struct super_run_in_global_packet, clean_up_env_file) },
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

void meta_super_run_in_global_packet_copy(struct super_run_in_global_packet *dst, const struct super_run_in_global_packet *src)
{
  // hidden g
  dst->contest_id = src->contest_id;
  dst->judge_id = src->judge_id;
  dst->run_id = src->run_id;
  dst->submit_id = src->submit_id;
  if (src->reply_spool_dir) {
    dst->reply_spool_dir = strdup(src->reply_spool_dir);
  }
  if (src->reply_report_dir) {
    dst->reply_report_dir = strdup(src->reply_report_dir);
  }
  if (src->reply_full_archive_dir) {
    dst->reply_full_archive_dir = strdup(src->reply_full_archive_dir);
  }
  if (src->reply_packet_name) {
    dst->reply_packet_name = strdup(src->reply_packet_name);
  }
  dst->priority = src->priority;
  dst->variant = src->variant;
  if (src->lang_short_name) {
    dst->lang_short_name = strdup(src->lang_short_name);
  }
  if (src->arch) {
    dst->arch = strdup(src->arch);
  }
  if (src->lang_key) {
    dst->lang_key = strdup(src->lang_key);
  }
  dst->secure_run = src->secure_run;
  dst->detect_violations = src->detect_violations;
  dst->enable_memory_limit_error = src->enable_memory_limit_error;
  dst->suid_run = src->suid_run;
  dst->enable_container = src->enable_container;
  dst->enable_max_stack_size = src->enable_max_stack_size;
  dst->user_id = src->user_id;
  if (src->user_login) {
    dst->user_login = strdup(src->user_login);
  }
  if (src->user_name) {
    dst->user_name = strdup(src->user_name);
  }
  if (src->user_spelling) {
    dst->user_spelling = strdup(src->user_spelling);
  }
  if (src->score_system) {
    dst->score_system = strdup(src->score_system);
  }
  dst->is_virtual = src->is_virtual;
  dst->max_file_length = src->max_file_length;
  dst->max_line_length = src->max_line_length;
  dst->max_cmd_length = src->max_cmd_length;
  dst->enable_full_archive = src->enable_full_archive;
  dst->accepting_mode = src->accepting_mode;
  dst->separate_user_score = src->separate_user_score;
  dst->mime_type = src->mime_type;
  dst->notify_flag = src->notify_flag;
  dst->advanced_layout = src->advanced_layout;
  dst->rejudge_flag = src->rejudge_flag;
  dst->ts1 = src->ts1;
  dst->ts1_us = src->ts1_us;
  dst->ts2 = src->ts2;
  dst->ts2_us = src->ts2_us;
  dst->ts3 = src->ts3;
  dst->ts3_us = src->ts3_us;
  dst->ts4 = src->ts4;
  dst->ts4_us = src->ts4_us;
  dst->lang_time_limit_adj_ms = src->lang_time_limit_adj_ms;
  if (src->exe_sfx) {
    dst->exe_sfx = strdup(src->exe_sfx);
  }
  dst->restart = src->restart;
  dst->disable_sound = src->disable_sound;
  dst->is_dos = src->is_dos;
  dst->time_limit_retry_count = src->time_limit_retry_count;
  if (src->checker_locale) {
    dst->checker_locale = strdup(src->checker_locale);
  }
  if (src->run_uuid) {
    dst->run_uuid = strdup(src->run_uuid);
  }
  if (src->judge_uuid) {
    dst->judge_uuid = strdup(src->judge_uuid);
  }
  dst->zip_mode = src->zip_mode;
  dst->testlib_mode = src->testlib_mode;
  if (src->contest_server_id) {
    dst->contest_server_id = strdup(src->contest_server_id);
  }
  dst->separate_run_spool_mode = src->separate_run_spool_mode;
  dst->bson_available = src->bson_available;
  if (src->lang_container_options) {
    dst->lang_container_options = strdup(src->lang_container_options);
  }
  dst->not_ok_is_cf = src->not_ok_is_cf;
  dst->prepended_size = src->prepended_size;
  dst->cached_on_remote = src->cached_on_remote;
  if (src->src_sfx) {
    dst->src_sfx = strdup(src->src_sfx);
  }
  if (src->src_file) {
    dst->src_file = strdup(src->src_file);
  }
  dst->enable_ejudge_env = src->enable_ejudge_env;
  if (src->clean_up_cmd) {
    dst->clean_up_cmd = strdup(src->clean_up_cmd);
  }
  if (src->run_env_file) {
    dst->run_env_file = strdup(src->run_env_file);
  }
  if (src->clean_up_env_file) {
    dst->clean_up_env_file = strdup(src->clean_up_env_file);
  }
  // hidden scoring_system_val
}

void meta_super_run_in_global_packet_free(struct super_run_in_global_packet *ptr)
{
  // hidden g
  free(ptr->reply_spool_dir);
  free(ptr->reply_report_dir);
  free(ptr->reply_full_archive_dir);
  free(ptr->reply_packet_name);
  free(ptr->lang_short_name);
  free(ptr->arch);
  free(ptr->lang_key);
  free(ptr->user_login);
  free(ptr->user_name);
  free(ptr->user_spelling);
  free(ptr->score_system);
  free(ptr->exe_sfx);
  free(ptr->checker_locale);
  free(ptr->run_uuid);
  free(ptr->judge_uuid);
  free(ptr->contest_server_id);
  free(ptr->lang_container_options);
  free(ptr->src_sfx);
  free(ptr->src_file);
  free(ptr->clean_up_cmd);
  free(ptr->run_env_file);
  free(ptr->clean_up_env_file);
  // hidden scoring_system_val
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
  (void (*)(void *, const void *))meta_super_run_in_global_packet_copy,
  (void (*)(void *))meta_super_run_in_global_packet_free,
};

static struct meta_info_item meta_info_super_run_in_problem_packet_data[] =
{
  [META_SUPER_RUN_IN_PROBLEM_PACKET_type] = { META_SUPER_RUN_IN_PROBLEM_PACKET_type, 's', XSIZE(struct super_run_in_problem_packet, type), "type", XOFFSET(struct super_run_in_problem_packet, type) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_id] = { META_SUPER_RUN_IN_PROBLEM_PACKET_id, 'i', XSIZE(struct super_run_in_problem_packet, id), "id", XOFFSET(struct super_run_in_problem_packet, id) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_check_presentation] = { META_SUPER_RUN_IN_PROBLEM_PACKET_check_presentation, 'B', XSIZE(struct super_run_in_problem_packet, check_presentation), "check_presentation", XOFFSET(struct super_run_in_problem_packet, check_presentation) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_scoring_checker] = { META_SUPER_RUN_IN_PROBLEM_PACKET_scoring_checker, 'B', XSIZE(struct super_run_in_problem_packet, scoring_checker), "scoring_checker", XOFFSET(struct super_run_in_problem_packet, scoring_checker) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_enable_checker_token] = { META_SUPER_RUN_IN_PROBLEM_PACKET_enable_checker_token, 'B', XSIZE(struct super_run_in_problem_packet, enable_checker_token), "enable_checker_token", XOFFSET(struct super_run_in_problem_packet, enable_checker_token) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_interactive_valuer] = { META_SUPER_RUN_IN_PROBLEM_PACKET_interactive_valuer, 'B', XSIZE(struct super_run_in_problem_packet, interactive_valuer), "interactive_valuer", XOFFSET(struct super_run_in_problem_packet, interactive_valuer) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_disable_pe] = { META_SUPER_RUN_IN_PROBLEM_PACKET_disable_pe, 'B', XSIZE(struct super_run_in_problem_packet, disable_pe), "disable_pe", XOFFSET(struct super_run_in_problem_packet, disable_pe) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_disable_wtl] = { META_SUPER_RUN_IN_PROBLEM_PACKET_disable_wtl, 'B', XSIZE(struct super_run_in_problem_packet, disable_wtl), "disable_wtl", XOFFSET(struct super_run_in_problem_packet, disable_wtl) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_wtl_is_cf] = { META_SUPER_RUN_IN_PROBLEM_PACKET_wtl_is_cf, 'B', XSIZE(struct super_run_in_problem_packet, wtl_is_cf), "wtl_is_cf", XOFFSET(struct super_run_in_problem_packet, wtl_is_cf) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_use_stdin] = { META_SUPER_RUN_IN_PROBLEM_PACKET_use_stdin, 'B', XSIZE(struct super_run_in_problem_packet, use_stdin), "use_stdin", XOFFSET(struct super_run_in_problem_packet, use_stdin) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_use_stdout] = { META_SUPER_RUN_IN_PROBLEM_PACKET_use_stdout, 'B', XSIZE(struct super_run_in_problem_packet, use_stdout), "use_stdout", XOFFSET(struct super_run_in_problem_packet, use_stdout) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_combined_stdin] = { META_SUPER_RUN_IN_PROBLEM_PACKET_combined_stdin, 'B', XSIZE(struct super_run_in_problem_packet, combined_stdin), "combined_stdin", XOFFSET(struct super_run_in_problem_packet, combined_stdin) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_combined_stdout] = { META_SUPER_RUN_IN_PROBLEM_PACKET_combined_stdout, 'B', XSIZE(struct super_run_in_problem_packet, combined_stdout), "combined_stdout", XOFFSET(struct super_run_in_problem_packet, combined_stdout) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_ignore_exit_code] = { META_SUPER_RUN_IN_PROBLEM_PACKET_ignore_exit_code, 'B', XSIZE(struct super_run_in_problem_packet, ignore_exit_code), "ignore_exit_code", XOFFSET(struct super_run_in_problem_packet, ignore_exit_code) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_ignore_term_signal] = { META_SUPER_RUN_IN_PROBLEM_PACKET_ignore_term_signal, 'B', XSIZE(struct super_run_in_problem_packet, ignore_term_signal), "ignore_term_signal", XOFFSET(struct super_run_in_problem_packet, ignore_term_signal) },
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
  [META_SUPER_RUN_IN_PROBLEM_PACKET_checker_time_limit_ms] = { META_SUPER_RUN_IN_PROBLEM_PACKET_checker_time_limit_ms, 'i', XSIZE(struct super_run_in_problem_packet, checker_time_limit_ms), "checker_time_limit_ms", XOFFSET(struct super_run_in_problem_packet, checker_time_limit_ms) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_checker_max_vm_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_checker_max_vm_size, 'E', XSIZE(struct super_run_in_problem_packet, checker_max_vm_size), "checker_max_vm_size", XOFFSET(struct super_run_in_problem_packet, checker_max_vm_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_checker_max_stack_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_checker_max_stack_size, 'E', XSIZE(struct super_run_in_problem_packet, checker_max_stack_size), "checker_max_stack_size", XOFFSET(struct super_run_in_problem_packet, checker_max_stack_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_checker_max_rss_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_checker_max_rss_size, 'E', XSIZE(struct super_run_in_problem_packet, checker_max_rss_size), "checker_max_rss_size", XOFFSET(struct super_run_in_problem_packet, checker_max_rss_size) },
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
  [META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_real_time_limit_ms] = { META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_real_time_limit_ms, 'i', XSIZE(struct super_run_in_problem_packet, interactor_real_time_limit_ms), "interactor_real_time_limit_ms", XOFFSET(struct super_run_in_problem_packet, interactor_real_time_limit_ms) },
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
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_generator_env] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_generator_env, 'X', XSIZE(struct super_run_in_problem_packet, test_generator_env), "test_generator_env", XOFFSET(struct super_run_in_problem_packet, test_generator_env) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_init_env] = { META_SUPER_RUN_IN_PROBLEM_PACKET_init_env, 'X', XSIZE(struct super_run_in_problem_packet, init_env), "init_env", XOFFSET(struct super_run_in_problem_packet, init_env) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_start_env] = { META_SUPER_RUN_IN_PROBLEM_PACKET_start_env, 'X', XSIZE(struct super_run_in_problem_packet, start_env), "start_env", XOFFSET(struct super_run_in_problem_packet, start_env) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_check_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_check_cmd, 's', XSIZE(struct super_run_in_problem_packet, check_cmd), "check_cmd", XOFFSET(struct super_run_in_problem_packet, check_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_valuer_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_valuer_cmd, 's', XSIZE(struct super_run_in_problem_packet, valuer_cmd), "valuer_cmd", XOFFSET(struct super_run_in_problem_packet, valuer_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_interactor_cmd, 's', XSIZE(struct super_run_in_problem_packet, interactor_cmd), "interactor_cmd", XOFFSET(struct super_run_in_problem_packet, interactor_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_checker_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_checker_cmd, 's', XSIZE(struct super_run_in_problem_packet, test_checker_cmd), "test_checker_cmd", XOFFSET(struct super_run_in_problem_packet, test_checker_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_generator_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_generator_cmd, 's', XSIZE(struct super_run_in_problem_packet, test_generator_cmd), "test_generator_cmd", XOFFSET(struct super_run_in_problem_packet, test_generator_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_init_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_init_cmd, 's', XSIZE(struct super_run_in_problem_packet, init_cmd), "init_cmd", XOFFSET(struct super_run_in_problem_packet, init_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_start_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_start_cmd, 's', XSIZE(struct super_run_in_problem_packet, start_cmd), "start_cmd", XOFFSET(struct super_run_in_problem_packet, start_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_solution_cmd] = { META_SUPER_RUN_IN_PROBLEM_PACKET_solution_cmd, 's', XSIZE(struct super_run_in_problem_packet, solution_cmd), "solution_cmd", XOFFSET(struct super_run_in_problem_packet, solution_cmd) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_vm_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_vm_size, 'E', XSIZE(struct super_run_in_problem_packet, max_vm_size), "max_vm_size", XOFFSET(struct super_run_in_problem_packet, max_vm_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_data_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_data_size, 'E', XSIZE(struct super_run_in_problem_packet, max_data_size), "max_data_size", XOFFSET(struct super_run_in_problem_packet, max_data_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_stack_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_stack_size, 'E', XSIZE(struct super_run_in_problem_packet, max_stack_size), "max_stack_size", XOFFSET(struct super_run_in_problem_packet, max_stack_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_rss_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_rss_size, 'E', XSIZE(struct super_run_in_problem_packet, max_rss_size), "max_rss_size", XOFFSET(struct super_run_in_problem_packet, max_rss_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_core_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_core_size, 'E', XSIZE(struct super_run_in_problem_packet, max_core_size), "max_core_size", XOFFSET(struct super_run_in_problem_packet, max_core_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_file_size] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_file_size, 'E', XSIZE(struct super_run_in_problem_packet, max_file_size), "max_file_size", XOFFSET(struct super_run_in_problem_packet, max_file_size) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_open_file_count] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_open_file_count, 'i', XSIZE(struct super_run_in_problem_packet, max_open_file_count), "max_open_file_count", XOFFSET(struct super_run_in_problem_packet, max_open_file_count) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_max_process_count] = { META_SUPER_RUN_IN_PROBLEM_PACKET_max_process_count, 'i', XSIZE(struct super_run_in_problem_packet, max_process_count), "max_process_count", XOFFSET(struct super_run_in_problem_packet, max_process_count) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_spelling] = { META_SUPER_RUN_IN_PROBLEM_PACKET_spelling, 's', XSIZE(struct super_run_in_problem_packet, spelling), "spelling", XOFFSET(struct super_run_in_problem_packet, spelling) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_open_tests] = { META_SUPER_RUN_IN_PROBLEM_PACKET_open_tests, 's', XSIZE(struct super_run_in_problem_packet, open_tests), "open_tests", XOFFSET(struct super_run_in_problem_packet, open_tests) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_enable_process_group] = { META_SUPER_RUN_IN_PROBLEM_PACKET_enable_process_group, 'B', XSIZE(struct super_run_in_problem_packet, enable_process_group), "enable_process_group", XOFFSET(struct super_run_in_problem_packet, enable_process_group) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_umask] = { META_SUPER_RUN_IN_PROBLEM_PACKET_umask, 's', XSIZE(struct super_run_in_problem_packet, umask), "umask", XOFFSET(struct super_run_in_problem_packet, umask) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_enable_kill_all] = { META_SUPER_RUN_IN_PROBLEM_PACKET_enable_kill_all, 'B', XSIZE(struct super_run_in_problem_packet, enable_kill_all), "enable_kill_all", XOFFSET(struct super_run_in_problem_packet, enable_kill_all) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_uuid] = { META_SUPER_RUN_IN_PROBLEM_PACKET_uuid, 's', XSIZE(struct super_run_in_problem_packet, uuid), "uuid", XOFFSET(struct super_run_in_problem_packet, uuid) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_enable_extended_info] = { META_SUPER_RUN_IN_PROBLEM_PACKET_enable_extended_info, 'B', XSIZE(struct super_run_in_problem_packet, enable_extended_info), "enable_extended_info", XOFFSET(struct super_run_in_problem_packet, enable_extended_info) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_stop_on_first_fail] = { META_SUPER_RUN_IN_PROBLEM_PACKET_stop_on_first_fail, 'B', XSIZE(struct super_run_in_problem_packet, stop_on_first_fail), "stop_on_first_fail", XOFFSET(struct super_run_in_problem_packet, stop_on_first_fail) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_enable_control_socket] = { META_SUPER_RUN_IN_PROBLEM_PACKET_enable_control_socket, 'B', XSIZE(struct super_run_in_problem_packet, enable_control_socket), "enable_control_socket", XOFFSET(struct super_run_in_problem_packet, enable_control_socket) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_container_options] = { META_SUPER_RUN_IN_PROBLEM_PACKET_container_options, 's', XSIZE(struct super_run_in_problem_packet, container_options), "container_options", XOFFSET(struct super_run_in_problem_packet, container_options) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_enable_user_input] = { META_SUPER_RUN_IN_PROBLEM_PACKET_enable_user_input, 'B', XSIZE(struct super_run_in_problem_packet, enable_user_input), "enable_user_input", XOFFSET(struct super_run_in_problem_packet, enable_user_input) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_user_input_file] = { META_SUPER_RUN_IN_PROBLEM_PACKET_user_input_file, 's', XSIZE(struct super_run_in_problem_packet, user_input_file), "user_input_file", XOFFSET(struct super_run_in_problem_packet, user_input_file) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_test_count] = { META_SUPER_RUN_IN_PROBLEM_PACKET_test_count, 'i', XSIZE(struct super_run_in_problem_packet, test_count), "test_count", XOFFSET(struct super_run_in_problem_packet, test_count) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_copy_exe_to_tgzdir] = { META_SUPER_RUN_IN_PROBLEM_PACKET_copy_exe_to_tgzdir, 'B', XSIZE(struct super_run_in_problem_packet, copy_exe_to_tgzdir), "copy_exe_to_tgzdir", XOFFSET(struct super_run_in_problem_packet, copy_exe_to_tgzdir) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_checker_extra_files] = { META_SUPER_RUN_IN_PROBLEM_PACKET_checker_extra_files, 'x', XSIZE(struct super_run_in_problem_packet, checker_extra_files), "checker_extra_files", XOFFSET(struct super_run_in_problem_packet, checker_extra_files) },
  [META_SUPER_RUN_IN_PROBLEM_PACKET_disable_vm_size_limit] = { META_SUPER_RUN_IN_PROBLEM_PACKET_disable_vm_size_limit, 'B', XSIZE(struct super_run_in_problem_packet, disable_vm_size_limit), "disable_vm_size_limit", XOFFSET(struct super_run_in_problem_packet, disable_vm_size_limit) },
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

void meta_super_run_in_problem_packet_copy(struct super_run_in_problem_packet *dst, const struct super_run_in_problem_packet *src)
{
  // hidden g
  if (src->type) {
    dst->type = strdup(src->type);
  }
  dst->id = src->id;
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
  dst->ignore_exit_code = src->ignore_exit_code;
  dst->ignore_term_signal = src->ignore_term_signal;
  dst->binary_input = src->binary_input;
  dst->binary_output = src->binary_output;
  dst->real_time_limit_ms = src->real_time_limit_ms;
  dst->time_limit_ms = src->time_limit_ms;
  dst->use_ac_not_ok = src->use_ac_not_ok;
  dst->full_score = src->full_score;
  dst->full_user_score = src->full_user_score;
  dst->variable_full_score = src->variable_full_score;
  dst->test_score = src->test_score;
  dst->use_corr = src->use_corr;
  dst->use_info = src->use_info;
  dst->use_tgz = src->use_tgz;
  dst->tests_to_accept = src->tests_to_accept;
  dst->accept_partial = src->accept_partial;
  dst->min_tests_to_accept = src->min_tests_to_accept;
  dst->checker_real_time_limit_ms = src->checker_real_time_limit_ms;
  dst->checker_time_limit_ms = src->checker_time_limit_ms;
  dst->checker_max_vm_size = src->checker_max_vm_size;
  dst->checker_max_stack_size = src->checker_max_stack_size;
  dst->checker_max_rss_size = src->checker_max_rss_size;
  if (src->short_name) {
    dst->short_name = strdup(src->short_name);
  }
  if (src->long_name) {
    dst->long_name = strdup(src->long_name);
  }
  if (src->internal_name) {
    dst->internal_name = strdup(src->internal_name);
  }
  if (src->problem_dir) {
    dst->problem_dir = strdup(src->problem_dir);
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
  if (src->input_file) {
    dst->input_file = strdup(src->input_file);
  }
  if (src->output_file) {
    dst->output_file = strdup(src->output_file);
  }
  if (src->test_score_list) {
    dst->test_score_list = strdup(src->test_score_list);
  }
  if (src->score_tests) {
    dst->score_tests = strdup(src->score_tests);
  }
  if (src->standard_checker) {
    dst->standard_checker = strdup(src->standard_checker);
  }
  dst->valuer_sets_marked = src->valuer_sets_marked;
  dst->interactor_time_limit_ms = src->interactor_time_limit_ms;
  dst->interactor_real_time_limit_ms = src->interactor_real_time_limit_ms;
  dst->disable_stderr = src->disable_stderr;
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
  dst->test_sets = (typeof(dst->test_sets)) sarray_copy((char**) src->test_sets);
  dst->checker_env = (typeof(dst->checker_env)) sarray_copy((char**) src->checker_env);
  dst->valuer_env = (typeof(dst->valuer_env)) sarray_copy((char**) src->valuer_env);
  dst->interactor_env = (typeof(dst->interactor_env)) sarray_copy((char**) src->interactor_env);
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
  if (src->solution_cmd) {
    dst->solution_cmd = strdup(src->solution_cmd);
  }
  dst->max_vm_size = src->max_vm_size;
  dst->max_data_size = src->max_data_size;
  dst->max_stack_size = src->max_stack_size;
  dst->max_rss_size = src->max_rss_size;
  dst->max_core_size = src->max_core_size;
  dst->max_file_size = src->max_file_size;
  dst->max_open_file_count = src->max_open_file_count;
  dst->max_process_count = src->max_process_count;
  if (src->spelling) {
    dst->spelling = strdup(src->spelling);
  }
  if (src->open_tests) {
    dst->open_tests = strdup(src->open_tests);
  }
  dst->enable_process_group = src->enable_process_group;
  if (src->umask) {
    dst->umask = strdup(src->umask);
  }
  dst->enable_kill_all = src->enable_kill_all;
  if (src->uuid) {
    dst->uuid = strdup(src->uuid);
  }
  dst->enable_extended_info = src->enable_extended_info;
  dst->stop_on_first_fail = src->stop_on_first_fail;
  dst->enable_control_socket = src->enable_control_socket;
  if (src->container_options) {
    dst->container_options = strdup(src->container_options);
  }
  dst->enable_user_input = src->enable_user_input;
  if (src->user_input_file) {
    dst->user_input_file = strdup(src->user_input_file);
  }
  dst->test_count = src->test_count;
  dst->copy_exe_to_tgzdir = src->copy_exe_to_tgzdir;
  dst->checker_extra_files = (typeof(dst->checker_extra_files)) sarray_copy((char**) src->checker_extra_files);
  dst->disable_vm_size_limit = src->disable_vm_size_limit;
  // hidden type_val
}

void meta_super_run_in_problem_packet_free(struct super_run_in_problem_packet *ptr)
{
  // hidden g
  free(ptr->type);
  free(ptr->short_name);
  free(ptr->long_name);
  free(ptr->internal_name);
  free(ptr->problem_dir);
  free(ptr->test_dir);
  free(ptr->corr_dir);
  free(ptr->info_dir);
  free(ptr->tgz_dir);
  free(ptr->input_file);
  free(ptr->output_file);
  free(ptr->test_score_list);
  free(ptr->score_tests);
  free(ptr->standard_checker);
  free(ptr->test_pat);
  free(ptr->corr_pat);
  free(ptr->info_pat);
  free(ptr->tgz_pat);
  free(ptr->tgzdir_pat);
  sarray_free((char**) ptr->test_sets);
  sarray_free((char**) ptr->checker_env);
  sarray_free((char**) ptr->valuer_env);
  sarray_free((char**) ptr->interactor_env);
  sarray_free((char**) ptr->test_checker_env);
  sarray_free((char**) ptr->test_generator_env);
  sarray_free((char**) ptr->init_env);
  sarray_free((char**) ptr->start_env);
  free(ptr->check_cmd);
  free(ptr->valuer_cmd);
  free(ptr->interactor_cmd);
  free(ptr->test_checker_cmd);
  free(ptr->test_generator_cmd);
  free(ptr->init_cmd);
  free(ptr->start_cmd);
  free(ptr->solution_cmd);
  free(ptr->spelling);
  free(ptr->open_tests);
  free(ptr->umask);
  free(ptr->uuid);
  free(ptr->container_options);
  free(ptr->user_input_file);
  sarray_free((char**) ptr->checker_extra_files);
  // hidden type_val
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
  (void (*)(void *, const void *))meta_super_run_in_problem_packet_copy,
  (void (*)(void *))meta_super_run_in_problem_packet_free,
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
  [META_SUPER_RUN_IN_TESTER_PACKET_enable_ejudge_env] = { META_SUPER_RUN_IN_TESTER_PACKET_enable_ejudge_env, 'B', XSIZE(struct super_run_in_tester_packet, enable_ejudge_env), "enable_ejudge_env", XOFFSET(struct super_run_in_tester_packet, enable_ejudge_env) },
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

void meta_super_run_in_tester_packet_copy(struct super_run_in_tester_packet *dst, const struct super_run_in_tester_packet *src)
{
  // hidden g
  if (src->name) {
    dst->name = strdup(src->name);
  }
  dst->is_dos = src->is_dos;
  dst->no_redirect = src->no_redirect;
  dst->priority_adjustment = src->priority_adjustment;
  dst->ignore_stderr = src->ignore_stderr;
  if (src->arch) {
    dst->arch = strdup(src->arch);
  }
  if (src->key) {
    dst->key = strdup(src->key);
  }
  if (src->memory_limit_type) {
    dst->memory_limit_type = strdup(src->memory_limit_type);
  }
  if (src->secure_exec_type) {
    dst->secure_exec_type = strdup(src->secure_exec_type);
  }
  dst->no_core_dump = src->no_core_dump;
  dst->enable_memory_limit_error = src->enable_memory_limit_error;
  if (src->kill_signal) {
    dst->kill_signal = strdup(src->kill_signal);
  }
  dst->clear_env = src->clear_env;
  dst->enable_ejudge_env = src->enable_ejudge_env;
  dst->time_limit_adjustment_ms = src->time_limit_adjustment_ms;
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
  dst->start_env = (typeof(dst->start_env)) sarray_copy((char**) src->start_env);
}

void meta_super_run_in_tester_packet_free(struct super_run_in_tester_packet *ptr)
{
  // hidden g
  free(ptr->name);
  free(ptr->arch);
  free(ptr->key);
  free(ptr->memory_limit_type);
  free(ptr->secure_exec_type);
  free(ptr->kill_signal);
  free(ptr->errorcode_file);
  free(ptr->error_file);
  free(ptr->prepare_cmd);
  free(ptr->start_cmd);
  sarray_free((char**) ptr->start_env);
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
  (void (*)(void *, const void *))meta_super_run_in_tester_packet_copy,
  (void (*)(void *))meta_super_run_in_tester_packet_free,
};

