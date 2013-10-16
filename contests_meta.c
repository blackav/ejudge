// This is an auto-generated file, do not edit
// Generated 2013/10/17 00:54:49

#include "contests_meta.h"
#include "contests.h"
#include "meta_generic.h"

#include "reuse_xalloc.h"

#include "reuse_logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_contest_desc_data[] =
{
  [CNTS_id] = { CNTS_id, 'i', XSIZE(struct contest_desc, id), "id", XOFFSET(struct contest_desc, id) },
  [CNTS_autoregister] = { CNTS_autoregister, 'b', XSIZE(struct contest_desc, autoregister), "autoregister", XOFFSET(struct contest_desc, autoregister) },
  [CNTS_disable_team_password] = { CNTS_disable_team_password, 'b', XSIZE(struct contest_desc, disable_team_password), "disable_team_password", XOFFSET(struct contest_desc, disable_team_password) },
  [CNTS_managed] = { CNTS_managed, 'b', XSIZE(struct contest_desc, managed), "managed", XOFFSET(struct contest_desc, managed) },
  [CNTS_run_managed] = { CNTS_run_managed, 'b', XSIZE(struct contest_desc, run_managed), "run_managed", XOFFSET(struct contest_desc, run_managed) },
  [CNTS_clean_users] = { CNTS_clean_users, 'b', XSIZE(struct contest_desc, clean_users), "clean_users", XOFFSET(struct contest_desc, clean_users) },
  [CNTS_closed] = { CNTS_closed, 'b', XSIZE(struct contest_desc, closed), "closed", XOFFSET(struct contest_desc, closed) },
  [CNTS_invisible] = { CNTS_invisible, 'b', XSIZE(struct contest_desc, invisible), "invisible", XOFFSET(struct contest_desc, invisible) },
  [CNTS_simple_registration] = { CNTS_simple_registration, 'b', XSIZE(struct contest_desc, simple_registration), "simple_registration", XOFFSET(struct contest_desc, simple_registration) },
  [CNTS_send_passwd_email] = { CNTS_send_passwd_email, 'b', XSIZE(struct contest_desc, send_passwd_email), "send_passwd_email", XOFFSET(struct contest_desc, send_passwd_email) },
  [CNTS_assign_logins] = { CNTS_assign_logins, 'b', XSIZE(struct contest_desc, assign_logins), "assign_logins", XOFFSET(struct contest_desc, assign_logins) },
  [CNTS_force_registration] = { CNTS_force_registration, 'b', XSIZE(struct contest_desc, force_registration), "force_registration", XOFFSET(struct contest_desc, force_registration) },
  [CNTS_disable_name] = { CNTS_disable_name, 'b', XSIZE(struct contest_desc, disable_name), "disable_name", XOFFSET(struct contest_desc, disable_name) },
  [CNTS_enable_password_recovery] = { CNTS_enable_password_recovery, 'b', XSIZE(struct contest_desc, enable_password_recovery), "enable_password_recovery", XOFFSET(struct contest_desc, enable_password_recovery) },
  [CNTS_exam_mode] = { CNTS_exam_mode, 'b', XSIZE(struct contest_desc, exam_mode), "exam_mode", XOFFSET(struct contest_desc, exam_mode) },
  [CNTS_disable_password_change] = { CNTS_disable_password_change, 'b', XSIZE(struct contest_desc, disable_password_change), "disable_password_change", XOFFSET(struct contest_desc, disable_password_change) },
  [CNTS_disable_locale_change] = { CNTS_disable_locale_change, 'b', XSIZE(struct contest_desc, disable_locale_change), "disable_locale_change", XOFFSET(struct contest_desc, disable_locale_change) },
  [CNTS_personal] = { CNTS_personal, 'b', XSIZE(struct contest_desc, personal), "personal", XOFFSET(struct contest_desc, personal) },
  [CNTS_allow_reg_data_edit] = { CNTS_allow_reg_data_edit, 'b', XSIZE(struct contest_desc, allow_reg_data_edit), "allow_reg_data_edit", XOFFSET(struct contest_desc, allow_reg_data_edit) },
  [CNTS_disable_member_delete] = { CNTS_disable_member_delete, 'b', XSIZE(struct contest_desc, disable_member_delete), "disable_member_delete", XOFFSET(struct contest_desc, disable_member_delete) },
  [CNTS_old_run_managed] = { CNTS_old_run_managed, 'b', XSIZE(struct contest_desc, old_run_managed), "old_run_managed", XOFFSET(struct contest_desc, old_run_managed) },
  [CNTS_ready] = { CNTS_ready, 'b', XSIZE(struct contest_desc, ready), "ready", XOFFSET(struct contest_desc, ready) },
  [CNTS_reg_deadline] = { CNTS_reg_deadline, 't', XSIZE(struct contest_desc, reg_deadline), "reg_deadline", XOFFSET(struct contest_desc, reg_deadline) },
  [CNTS_sched_time] = { CNTS_sched_time, 't', XSIZE(struct contest_desc, sched_time), "sched_time", XOFFSET(struct contest_desc, sched_time) },
  [CNTS_open_time] = { CNTS_open_time, 't', XSIZE(struct contest_desc, open_time), "open_time", XOFFSET(struct contest_desc, open_time) },
  [CNTS_close_time] = { CNTS_close_time, 't', XSIZE(struct contest_desc, close_time), "close_time", XOFFSET(struct contest_desc, close_time) },
  [CNTS_update_time] = { CNTS_update_time, 't', XSIZE(struct contest_desc, update_time), "update_time", XOFFSET(struct contest_desc, update_time) },
  [CNTS_name] = { CNTS_name, 's', XSIZE(struct contest_desc, name), "name", XOFFSET(struct contest_desc, name) },
  [CNTS_name_en] = { CNTS_name_en, 's', XSIZE(struct contest_desc, name_en), "name_en", XOFFSET(struct contest_desc, name_en) },
  [CNTS_main_url] = { CNTS_main_url, 's', XSIZE(struct contest_desc, main_url), "main_url", XOFFSET(struct contest_desc, main_url) },
  [CNTS_keywords] = { CNTS_keywords, 's', XSIZE(struct contest_desc, keywords), "keywords", XOFFSET(struct contest_desc, keywords) },
  [CNTS_users_header_file] = { CNTS_users_header_file, 's', XSIZE(struct contest_desc, users_header_file), "users_header_file", XOFFSET(struct contest_desc, users_header_file) },
  [CNTS_users_footer_file] = { CNTS_users_footer_file, 's', XSIZE(struct contest_desc, users_footer_file), "users_footer_file", XOFFSET(struct contest_desc, users_footer_file) },
  [CNTS_register_header_file] = { CNTS_register_header_file, 's', XSIZE(struct contest_desc, register_header_file), "register_header_file", XOFFSET(struct contest_desc, register_header_file) },
  [CNTS_register_footer_file] = { CNTS_register_footer_file, 's', XSIZE(struct contest_desc, register_footer_file), "register_footer_file", XOFFSET(struct contest_desc, register_footer_file) },
  [CNTS_team_header_file] = { CNTS_team_header_file, 's', XSIZE(struct contest_desc, team_header_file), "team_header_file", XOFFSET(struct contest_desc, team_header_file) },
  [CNTS_team_menu_1_file] = { CNTS_team_menu_1_file, 's', XSIZE(struct contest_desc, team_menu_1_file), "team_menu_1_file", XOFFSET(struct contest_desc, team_menu_1_file) },
  [CNTS_team_menu_2_file] = { CNTS_team_menu_2_file, 's', XSIZE(struct contest_desc, team_menu_2_file), "team_menu_2_file", XOFFSET(struct contest_desc, team_menu_2_file) },
  [CNTS_team_menu_3_file] = { CNTS_team_menu_3_file, 's', XSIZE(struct contest_desc, team_menu_3_file), "team_menu_3_file", XOFFSET(struct contest_desc, team_menu_3_file) },
  [CNTS_team_separator_file] = { CNTS_team_separator_file, 's', XSIZE(struct contest_desc, team_separator_file), "team_separator_file", XOFFSET(struct contest_desc, team_separator_file) },
  [CNTS_team_footer_file] = { CNTS_team_footer_file, 's', XSIZE(struct contest_desc, team_footer_file), "team_footer_file", XOFFSET(struct contest_desc, team_footer_file) },
  [CNTS_priv_header_file] = { CNTS_priv_header_file, 's', XSIZE(struct contest_desc, priv_header_file), "priv_header_file", XOFFSET(struct contest_desc, priv_header_file) },
  [CNTS_priv_footer_file] = { CNTS_priv_footer_file, 's', XSIZE(struct contest_desc, priv_footer_file), "priv_footer_file", XOFFSET(struct contest_desc, priv_footer_file) },
  [CNTS_copyright_file] = { CNTS_copyright_file, 's', XSIZE(struct contest_desc, copyright_file), "copyright_file", XOFFSET(struct contest_desc, copyright_file) },
  [CNTS_register_email] = { CNTS_register_email, 's', XSIZE(struct contest_desc, register_email), "register_email", XOFFSET(struct contest_desc, register_email) },
  [CNTS_register_url] = { CNTS_register_url, 's', XSIZE(struct contest_desc, register_url), "register_url", XOFFSET(struct contest_desc, register_url) },
  [CNTS_team_url] = { CNTS_team_url, 's', XSIZE(struct contest_desc, team_url), "team_url", XOFFSET(struct contest_desc, team_url) },
  [CNTS_login_template] = { CNTS_login_template, 's', XSIZE(struct contest_desc, login_template), "login_template", XOFFSET(struct contest_desc, login_template) },
  [CNTS_login_template_options] = { CNTS_login_template_options, 's', XSIZE(struct contest_desc, login_template_options), "login_template_options", XOFFSET(struct contest_desc, login_template_options) },
  [CNTS_root_dir] = { CNTS_root_dir, 's', XSIZE(struct contest_desc, root_dir), "root_dir", XOFFSET(struct contest_desc, root_dir) },
  [CNTS_conf_dir] = { CNTS_conf_dir, 's', XSIZE(struct contest_desc, conf_dir), "conf_dir", XOFFSET(struct contest_desc, conf_dir) },
  [CNTS_standings_url] = { CNTS_standings_url, 's', XSIZE(struct contest_desc, standings_url), "standings_url", XOFFSET(struct contest_desc, standings_url) },
  [CNTS_problems_url] = { CNTS_problems_url, 's', XSIZE(struct contest_desc, problems_url), "problems_url", XOFFSET(struct contest_desc, problems_url) },
  [CNTS_serve_user] = { CNTS_serve_user, 's', XSIZE(struct contest_desc, serve_user), "serve_user", XOFFSET(struct contest_desc, serve_user) },
  [CNTS_serve_group] = { CNTS_serve_group, 's', XSIZE(struct contest_desc, serve_group), "serve_group", XOFFSET(struct contest_desc, serve_group) },
  [CNTS_run_user] = { CNTS_run_user, 's', XSIZE(struct contest_desc, run_user), "run_user", XOFFSET(struct contest_desc, run_user) },
  [CNTS_run_group] = { CNTS_run_group, 's', XSIZE(struct contest_desc, run_group), "run_group", XOFFSET(struct contest_desc, run_group) },
  [CNTS_register_email_file] = { CNTS_register_email_file, 's', XSIZE(struct contest_desc, register_email_file), "register_email_file", XOFFSET(struct contest_desc, register_email_file) },
  [CNTS_register_subject] = { CNTS_register_subject, 's', XSIZE(struct contest_desc, register_subject), "register_subject", XOFFSET(struct contest_desc, register_subject) },
  [CNTS_register_subject_en] = { CNTS_register_subject_en, 's', XSIZE(struct contest_desc, register_subject_en), "register_subject_en", XOFFSET(struct contest_desc, register_subject_en) },
  [CNTS_register_access] = { CNTS_register_access, '?', XSIZE(struct contest_desc, register_access), "register_access", XOFFSET(struct contest_desc, register_access) },
  [CNTS_users_access] = { CNTS_users_access, '?', XSIZE(struct contest_desc, users_access), "users_access", XOFFSET(struct contest_desc, users_access) },
  [CNTS_master_access] = { CNTS_master_access, '?', XSIZE(struct contest_desc, master_access), "master_access", XOFFSET(struct contest_desc, master_access) },
  [CNTS_judge_access] = { CNTS_judge_access, '?', XSIZE(struct contest_desc, judge_access), "judge_access", XOFFSET(struct contest_desc, judge_access) },
  [CNTS_team_access] = { CNTS_team_access, '?', XSIZE(struct contest_desc, team_access), "team_access", XOFFSET(struct contest_desc, team_access) },
  [CNTS_serve_control_access] = { CNTS_serve_control_access, '?', XSIZE(struct contest_desc, serve_control_access), "serve_control_access", XOFFSET(struct contest_desc, serve_control_access) },
  [CNTS_fields] = { CNTS_fields, '?', XSIZE(struct contest_desc, fields), "fields", XOFFSET(struct contest_desc, fields) },
  [CNTS_members] = { CNTS_members, '?', XSIZE(struct contest_desc, members), "members", XOFFSET(struct contest_desc, members) },
  [CNTS_caps_node] = { CNTS_caps_node, '?', XSIZE(struct contest_desc, caps_node), "caps_node", XOFFSET(struct contest_desc, caps_node) },
  [CNTS_capabilities] = { CNTS_capabilities, '?', XSIZE(struct contest_desc, capabilities), "capabilities", XOFFSET(struct contest_desc, capabilities) },
  [CNTS_users_head_style] = { CNTS_users_head_style, 's', XSIZE(struct contest_desc, users_head_style), "users_head_style", XOFFSET(struct contest_desc, users_head_style) },
  [CNTS_users_par_style] = { CNTS_users_par_style, 's', XSIZE(struct contest_desc, users_par_style), "users_par_style", XOFFSET(struct contest_desc, users_par_style) },
  [CNTS_users_table_style] = { CNTS_users_table_style, 's', XSIZE(struct contest_desc, users_table_style), "users_table_style", XOFFSET(struct contest_desc, users_table_style) },
  [CNTS_users_verb_style] = { CNTS_users_verb_style, 's', XSIZE(struct contest_desc, users_verb_style), "users_verb_style", XOFFSET(struct contest_desc, users_verb_style) },
  [CNTS_users_table_format] = { CNTS_users_table_format, 's', XSIZE(struct contest_desc, users_table_format), "users_table_format", XOFFSET(struct contest_desc, users_table_format) },
  [CNTS_users_table_format_en] = { CNTS_users_table_format_en, 's', XSIZE(struct contest_desc, users_table_format_en), "users_table_format_en", XOFFSET(struct contest_desc, users_table_format_en) },
  [CNTS_users_table_legend] = { CNTS_users_table_legend, 's', XSIZE(struct contest_desc, users_table_legend), "users_table_legend", XOFFSET(struct contest_desc, users_table_legend) },
  [CNTS_users_table_legend_en] = { CNTS_users_table_legend_en, 's', XSIZE(struct contest_desc, users_table_legend_en), "users_table_legend_en", XOFFSET(struct contest_desc, users_table_legend_en) },
  [CNTS_register_head_style] = { CNTS_register_head_style, 's', XSIZE(struct contest_desc, register_head_style), "register_head_style", XOFFSET(struct contest_desc, register_head_style) },
  [CNTS_register_par_style] = { CNTS_register_par_style, 's', XSIZE(struct contest_desc, register_par_style), "register_par_style", XOFFSET(struct contest_desc, register_par_style) },
  [CNTS_register_table_style] = { CNTS_register_table_style, 's', XSIZE(struct contest_desc, register_table_style), "register_table_style", XOFFSET(struct contest_desc, register_table_style) },
  [CNTS_team_head_style] = { CNTS_team_head_style, 's', XSIZE(struct contest_desc, team_head_style), "team_head_style", XOFFSET(struct contest_desc, team_head_style) },
  [CNTS_team_par_style] = { CNTS_team_par_style, 's', XSIZE(struct contest_desc, team_par_style), "team_par_style", XOFFSET(struct contest_desc, team_par_style) },
  [CNTS_cf_notify_email] = { CNTS_cf_notify_email, 's', XSIZE(struct contest_desc, cf_notify_email), "cf_notify_email", XOFFSET(struct contest_desc, cf_notify_email) },
  [CNTS_clar_notify_email] = { CNTS_clar_notify_email, 's', XSIZE(struct contest_desc, clar_notify_email), "clar_notify_email", XOFFSET(struct contest_desc, clar_notify_email) },
  [CNTS_daily_stat_email] = { CNTS_daily_stat_email, 's', XSIZE(struct contest_desc, daily_stat_email), "daily_stat_email", XOFFSET(struct contest_desc, daily_stat_email) },
  [CNTS_user_name_comment] = { CNTS_user_name_comment, 's', XSIZE(struct contest_desc, user_name_comment), "user_name_comment", XOFFSET(struct contest_desc, user_name_comment) },
  [CNTS_allowed_languages] = { CNTS_allowed_languages, 's', XSIZE(struct contest_desc, allowed_languages), "allowed_languages", XOFFSET(struct contest_desc, allowed_languages) },
  [CNTS_allowed_regions] = { CNTS_allowed_regions, 's', XSIZE(struct contest_desc, allowed_regions), "allowed_regions", XOFFSET(struct contest_desc, allowed_regions) },
  [CNTS_user_contest] = { CNTS_user_contest, 's', XSIZE(struct contest_desc, user_contest), "user_contest", XOFFSET(struct contest_desc, user_contest) },
  [CNTS_dir_mode] = { CNTS_dir_mode, 's', XSIZE(struct contest_desc, dir_mode), "dir_mode", XOFFSET(struct contest_desc, dir_mode) },
  [CNTS_dir_group] = { CNTS_dir_group, 's', XSIZE(struct contest_desc, dir_group), "dir_group", XOFFSET(struct contest_desc, dir_group) },
  [CNTS_file_mode] = { CNTS_file_mode, 's', XSIZE(struct contest_desc, file_mode), "file_mode", XOFFSET(struct contest_desc, file_mode) },
  [CNTS_file_group] = { CNTS_file_group, 's', XSIZE(struct contest_desc, file_group), "file_group", XOFFSET(struct contest_desc, file_group) },
  [CNTS_default_locale] = { CNTS_default_locale, 's', XSIZE(struct contest_desc, default_locale), "default_locale", XOFFSET(struct contest_desc, default_locale) },
  [CNTS_welcome_file] = { CNTS_welcome_file, 's', XSIZE(struct contest_desc, welcome_file), "welcome_file", XOFFSET(struct contest_desc, welcome_file) },
  [CNTS_reg_welcome_file] = { CNTS_reg_welcome_file, 's', XSIZE(struct contest_desc, reg_welcome_file), "reg_welcome_file", XOFFSET(struct contest_desc, reg_welcome_file) },
  [CNTS_logo_url] = { CNTS_logo_url, 's', XSIZE(struct contest_desc, logo_url), "logo_url", XOFFSET(struct contest_desc, logo_url) },
  [CNTS_css_url] = { CNTS_css_url, 's', XSIZE(struct contest_desc, css_url), "css_url", XOFFSET(struct contest_desc, css_url) },
  [CNTS_ext_id] = { CNTS_ext_id, 's', XSIZE(struct contest_desc, ext_id), "ext_id", XOFFSET(struct contest_desc, ext_id) },
  [CNTS_problem_count] = { CNTS_problem_count, 's', XSIZE(struct contest_desc, problem_count), "problem_count", XOFFSET(struct contest_desc, problem_count) },
  [CNTS_slave_rules] = { CNTS_slave_rules, '?', XSIZE(struct contest_desc, slave_rules), "slave_rules", XOFFSET(struct contest_desc, slave_rules) },
  [CNTS_user_contest_num] = { CNTS_user_contest_num, 'i', XSIZE(struct contest_desc, user_contest_num), "user_contest_num", XOFFSET(struct contest_desc, user_contest_num) },
  [CNTS_default_locale_num] = { CNTS_default_locale_num, 'i', XSIZE(struct contest_desc, default_locale_num), "default_locale_num", XOFFSET(struct contest_desc, default_locale_num) },
};

int contest_desc_get_type(int tag)
{
  ASSERT(tag > 0 && tag < CNTS_LAST_FIELD);
  return meta_info_contest_desc_data[tag].type;
}

size_t contest_desc_get_size(int tag)
{
  ASSERT(tag > 0 && tag < CNTS_LAST_FIELD);
  return meta_info_contest_desc_data[tag].size;
}

const char *contest_desc_get_name(int tag)
{
  ASSERT(tag > 0 && tag < CNTS_LAST_FIELD);
  return meta_info_contest_desc_data[tag].name;
}

const void *contest_desc_get_ptr(const struct contest_desc *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTS_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_contest_desc_data[tag].offset);
}

void *contest_desc_get_ptr_nc(struct contest_desc *ptr, int tag)
{
  ASSERT(tag > 0 && tag < CNTS_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_contest_desc_data[tag].offset);
}

int contest_desc_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_contest_desc_data, CNTS_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods contest_desc_methods =
{
  CNTS_LAST_FIELD,
  sizeof(struct contest_desc),
  contest_desc_get_type,
  contest_desc_get_size,
  contest_desc_get_name,
  (const void *(*)(const void *ptr, int tag))contest_desc_get_ptr,
  (void *(*)(void *ptr, int tag))contest_desc_get_ptr_nc,
  contest_desc_lookup_field,
};

