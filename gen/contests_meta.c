// This is an auto-generated file, do not edit

#include "ejudge/meta/contests_meta.h"
#include "ejudge/contests.h"
#include "ejudge/meta_generic.h"

#include "ejudge/xalloc.h"

#include "ejudge/parsecfg.h"

#include "ejudge/logger.h"
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
  [CNTS_force_password_change] = { CNTS_force_password_change, 'b', XSIZE(struct contest_desc, force_password_change), "force_password_change", XOFFSET(struct contest_desc, force_password_change) },
  [CNTS_enable_user_telegram] = { CNTS_enable_user_telegram, 'b', XSIZE(struct contest_desc, enable_user_telegram), "enable_user_telegram", XOFFSET(struct contest_desc, enable_user_telegram) },
  [CNTS_enable_avatar] = { CNTS_enable_avatar, 'b', XSIZE(struct contest_desc, enable_avatar), "enable_avatar", XOFFSET(struct contest_desc, enable_avatar) },
  [CNTS_enable_local_pages] = { CNTS_enable_local_pages, 'b', XSIZE(struct contest_desc, enable_local_pages), "enable_local_pages", XOFFSET(struct contest_desc, enable_local_pages) },
  [CNTS_read_only_name] = { CNTS_read_only_name, 'b', XSIZE(struct contest_desc, read_only_name), "read_only_name", XOFFSET(struct contest_desc, read_only_name) },
  [CNTS_enable_oauth] = { CNTS_enable_oauth, 'b', XSIZE(struct contest_desc, enable_oauth), "enable_oauth", XOFFSET(struct contest_desc, enable_oauth) },
  [CNTS_enable_reminders] = { CNTS_enable_reminders, 'b', XSIZE(struct contest_desc, enable_reminders), "enable_reminders", XOFFSET(struct contest_desc, enable_reminders) },
  [CNTS_disable_standalone_reg] = { CNTS_disable_standalone_reg, 'b', XSIZE(struct contest_desc, disable_standalone_reg), "disable_standalone_reg", XOFFSET(struct contest_desc, disable_standalone_reg) },
  [CNTS_enable_telegram_registration] = { CNTS_enable_telegram_registration, 'b', XSIZE(struct contest_desc, enable_telegram_registration), "enable_telegram_registration", XOFFSET(struct contest_desc, enable_telegram_registration) },
  [CNTS_enable_special_flow] = { CNTS_enable_special_flow, 'b', XSIZE(struct contest_desc, enable_special_flow), "enable_special_flow", XOFFSET(struct contest_desc, enable_special_flow) },
  [CNTS_enable_user_finish] = { CNTS_enable_user_finish, 'b', XSIZE(struct contest_desc, enable_user_finish), "enable_user_finish", XOFFSET(struct contest_desc, enable_user_finish) },
  [CNTS_disable_user_finish] = { CNTS_disable_user_finish, 'b', XSIZE(struct contest_desc, disable_user_finish), "disable_user_finish", XOFFSET(struct contest_desc, disable_user_finish) },
  [CNTS_reg_deadline] = { CNTS_reg_deadline, 't', XSIZE(struct contest_desc, reg_deadline), "reg_deadline", XOFFSET(struct contest_desc, reg_deadline) },
  [CNTS_sched_time] = { CNTS_sched_time, 't', XSIZE(struct contest_desc, sched_time), "sched_time", XOFFSET(struct contest_desc, sched_time) },
  [CNTS_open_time] = { CNTS_open_time, 't', XSIZE(struct contest_desc, open_time), "open_time", XOFFSET(struct contest_desc, open_time) },
  [CNTS_close_time] = { CNTS_close_time, 't', XSIZE(struct contest_desc, close_time), "close_time", XOFFSET(struct contest_desc, close_time) },
  [CNTS_update_time] = { CNTS_update_time, 't', XSIZE(struct contest_desc, update_time), "update_time", XOFFSET(struct contest_desc, update_time) },
  [CNTS_name] = { CNTS_name, 's', XSIZE(struct contest_desc, name), "name", XOFFSET(struct contest_desc, name) },
  [CNTS_name_en] = { CNTS_name_en, 's', XSIZE(struct contest_desc, name_en), "name_en", XOFFSET(struct contest_desc, name_en) },
  [CNTS_main_url] = { CNTS_main_url, 's', XSIZE(struct contest_desc, main_url), "main_url", XOFFSET(struct contest_desc, main_url) },
  [CNTS_keywords] = { CNTS_keywords, 's', XSIZE(struct contest_desc, keywords), "keywords", XOFFSET(struct contest_desc, keywords) },
  [CNTS_comment] = { CNTS_comment, 's', XSIZE(struct contest_desc, comment), "comment", XOFFSET(struct contest_desc, comment) },
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
  [CNTS_analytics_url] = { CNTS_analytics_url, 's', XSIZE(struct contest_desc, analytics_url), "analytics_url", XOFFSET(struct contest_desc, analytics_url) },
  [CNTS_analytics_key] = { CNTS_analytics_key, 's', XSIZE(struct contest_desc, analytics_key), "analytics_key", XOFFSET(struct contest_desc, analytics_key) },
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
  [CNTS_telegram_bot_id] = { CNTS_telegram_bot_id, 's', XSIZE(struct contest_desc, telegram_bot_id), "telegram_bot_id", XOFFSET(struct contest_desc, telegram_bot_id) },
  [CNTS_telegram_admin_chat_id] = { CNTS_telegram_admin_chat_id, 's', XSIZE(struct contest_desc, telegram_admin_chat_id), "telegram_admin_chat_id", XOFFSET(struct contest_desc, telegram_admin_chat_id) },
  [CNTS_telegram_user_chat_id] = { CNTS_telegram_user_chat_id, 's', XSIZE(struct contest_desc, telegram_user_chat_id), "telegram_user_chat_id", XOFFSET(struct contest_desc, telegram_user_chat_id) },
  [CNTS_avatar_plugin] = { CNTS_avatar_plugin, 's', XSIZE(struct contest_desc, avatar_plugin), "avatar_plugin", XOFFSET(struct contest_desc, avatar_plugin) },
  [CNTS_content_plugin] = { CNTS_content_plugin, 's', XSIZE(struct contest_desc, content_plugin), "content_plugin", XOFFSET(struct contest_desc, content_plugin) },
  [CNTS_content_url_prefix] = { CNTS_content_url_prefix, 's', XSIZE(struct contest_desc, content_url_prefix), "content_url_prefix", XOFFSET(struct contest_desc, content_url_prefix) },
  [CNTS_special_flow_options] = { CNTS_special_flow_options, 's', XSIZE(struct contest_desc, special_flow_options), "special_flow_options", XOFFSET(struct contest_desc, special_flow_options) },
  [CNTS_client_headers_file] = { CNTS_client_headers_file, 's', XSIZE(struct contest_desc, client_headers_file), "client_headers_file", XOFFSET(struct contest_desc, client_headers_file) },
  [CNTS_slave_rules] = { CNTS_slave_rules, '?', XSIZE(struct contest_desc, slave_rules), "slave_rules", XOFFSET(struct contest_desc, slave_rules) },
  [CNTS_oauth_rules] = { CNTS_oauth_rules, '?', XSIZE(struct contest_desc, oauth_rules), "oauth_rules", XOFFSET(struct contest_desc, oauth_rules) },
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

void contest_desc_copy(struct contest_desc *dst, const struct contest_desc *src)
{
  // hidden b
  dst->id = src->id;
  dst->autoregister = src->autoregister;
  dst->disable_team_password = src->disable_team_password;
  dst->managed = src->managed;
  dst->run_managed = src->run_managed;
  dst->clean_users = src->clean_users;
  dst->closed = src->closed;
  dst->invisible = src->invisible;
  dst->simple_registration = src->simple_registration;
  dst->send_passwd_email = src->send_passwd_email;
  dst->assign_logins = src->assign_logins;
  dst->force_registration = src->force_registration;
  dst->disable_name = src->disable_name;
  dst->enable_password_recovery = src->enable_password_recovery;
  dst->exam_mode = src->exam_mode;
  dst->disable_password_change = src->disable_password_change;
  dst->disable_locale_change = src->disable_locale_change;
  dst->personal = src->personal;
  dst->allow_reg_data_edit = src->allow_reg_data_edit;
  dst->disable_member_delete = src->disable_member_delete;
  dst->old_run_managed = src->old_run_managed;
  dst->ready = src->ready;
  dst->force_password_change = src->force_password_change;
  dst->enable_user_telegram = src->enable_user_telegram;
  dst->enable_avatar = src->enable_avatar;
  dst->enable_local_pages = src->enable_local_pages;
  dst->read_only_name = src->read_only_name;
  dst->enable_oauth = src->enable_oauth;
  dst->enable_reminders = src->enable_reminders;
  dst->disable_standalone_reg = src->disable_standalone_reg;
  dst->enable_telegram_registration = src->enable_telegram_registration;
  dst->enable_special_flow = src->enable_special_flow;
  dst->enable_user_finish = src->enable_user_finish;
  dst->disable_user_finish = src->disable_user_finish;
  dst->reg_deadline = src->reg_deadline;
  dst->sched_time = src->sched_time;
  dst->open_time = src->open_time;
  dst->close_time = src->close_time;
  dst->update_time = src->update_time;
  if (src->name) {
    dst->name = strdup(src->name);
  }
  if (src->name_en) {
    dst->name_en = strdup(src->name_en);
  }
  if (src->main_url) {
    dst->main_url = strdup(src->main_url);
  }
  if (src->keywords) {
    dst->keywords = strdup(src->keywords);
  }
  if (src->comment) {
    dst->comment = strdup(src->comment);
  }
  if (src->users_header_file) {
    dst->users_header_file = strdup(src->users_header_file);
  }
  if (src->users_footer_file) {
    dst->users_footer_file = strdup(src->users_footer_file);
  }
  if (src->register_header_file) {
    dst->register_header_file = strdup(src->register_header_file);
  }
  if (src->register_footer_file) {
    dst->register_footer_file = strdup(src->register_footer_file);
  }
  if (src->team_header_file) {
    dst->team_header_file = strdup(src->team_header_file);
  }
  if (src->team_menu_1_file) {
    dst->team_menu_1_file = strdup(src->team_menu_1_file);
  }
  if (src->team_menu_2_file) {
    dst->team_menu_2_file = strdup(src->team_menu_2_file);
  }
  if (src->team_menu_3_file) {
    dst->team_menu_3_file = strdup(src->team_menu_3_file);
  }
  if (src->team_separator_file) {
    dst->team_separator_file = strdup(src->team_separator_file);
  }
  if (src->team_footer_file) {
    dst->team_footer_file = strdup(src->team_footer_file);
  }
  if (src->priv_header_file) {
    dst->priv_header_file = strdup(src->priv_header_file);
  }
  if (src->priv_footer_file) {
    dst->priv_footer_file = strdup(src->priv_footer_file);
  }
  if (src->copyright_file) {
    dst->copyright_file = strdup(src->copyright_file);
  }
  if (src->register_email) {
    dst->register_email = strdup(src->register_email);
  }
  if (src->register_url) {
    dst->register_url = strdup(src->register_url);
  }
  if (src->team_url) {
    dst->team_url = strdup(src->team_url);
  }
  if (src->login_template) {
    dst->login_template = strdup(src->login_template);
  }
  if (src->login_template_options) {
    dst->login_template_options = strdup(src->login_template_options);
  }
  if (src->root_dir) {
    dst->root_dir = strdup(src->root_dir);
  }
  if (src->conf_dir) {
    dst->conf_dir = strdup(src->conf_dir);
  }
  if (src->standings_url) {
    dst->standings_url = strdup(src->standings_url);
  }
  if (src->problems_url) {
    dst->problems_url = strdup(src->problems_url);
  }
  if (src->analytics_url) {
    dst->analytics_url = strdup(src->analytics_url);
  }
  if (src->analytics_key) {
    dst->analytics_key = strdup(src->analytics_key);
  }
  if (src->serve_user) {
    dst->serve_user = strdup(src->serve_user);
  }
  if (src->serve_group) {
    dst->serve_group = strdup(src->serve_group);
  }
  if (src->run_user) {
    dst->run_user = strdup(src->run_user);
  }
  if (src->run_group) {
    dst->run_group = strdup(src->run_group);
  }
  if (src->register_email_file) {
    dst->register_email_file = strdup(src->register_email_file);
  }
  if (src->register_subject) {
    dst->register_subject = strdup(src->register_subject);
  }
  if (src->register_subject_en) {
    dst->register_subject_en = strdup(src->register_subject_en);
  }
  // register_access
  // users_access
  // master_access
  // judge_access
  // team_access
  // serve_control_access
  // fields
  // members
  // caps_node
  // capabilities
  if (src->users_head_style) {
    dst->users_head_style = strdup(src->users_head_style);
  }
  if (src->users_par_style) {
    dst->users_par_style = strdup(src->users_par_style);
  }
  if (src->users_table_style) {
    dst->users_table_style = strdup(src->users_table_style);
  }
  if (src->users_verb_style) {
    dst->users_verb_style = strdup(src->users_verb_style);
  }
  if (src->users_table_format) {
    dst->users_table_format = strdup(src->users_table_format);
  }
  if (src->users_table_format_en) {
    dst->users_table_format_en = strdup(src->users_table_format_en);
  }
  if (src->users_table_legend) {
    dst->users_table_legend = strdup(src->users_table_legend);
  }
  if (src->users_table_legend_en) {
    dst->users_table_legend_en = strdup(src->users_table_legend_en);
  }
  if (src->register_head_style) {
    dst->register_head_style = strdup(src->register_head_style);
  }
  if (src->register_par_style) {
    dst->register_par_style = strdup(src->register_par_style);
  }
  if (src->register_table_style) {
    dst->register_table_style = strdup(src->register_table_style);
  }
  if (src->team_head_style) {
    dst->team_head_style = strdup(src->team_head_style);
  }
  if (src->team_par_style) {
    dst->team_par_style = strdup(src->team_par_style);
  }
  if (src->cf_notify_email) {
    dst->cf_notify_email = strdup(src->cf_notify_email);
  }
  if (src->clar_notify_email) {
    dst->clar_notify_email = strdup(src->clar_notify_email);
  }
  if (src->daily_stat_email) {
    dst->daily_stat_email = strdup(src->daily_stat_email);
  }
  if (src->user_name_comment) {
    dst->user_name_comment = strdup(src->user_name_comment);
  }
  if (src->allowed_languages) {
    dst->allowed_languages = strdup(src->allowed_languages);
  }
  if (src->allowed_regions) {
    dst->allowed_regions = strdup(src->allowed_regions);
  }
  if (src->user_contest) {
    dst->user_contest = strdup(src->user_contest);
  }
  if (src->dir_mode) {
    dst->dir_mode = strdup(src->dir_mode);
  }
  if (src->dir_group) {
    dst->dir_group = strdup(src->dir_group);
  }
  if (src->file_mode) {
    dst->file_mode = strdup(src->file_mode);
  }
  if (src->file_group) {
    dst->file_group = strdup(src->file_group);
  }
  if (src->default_locale) {
    dst->default_locale = strdup(src->default_locale);
  }
  if (src->welcome_file) {
    dst->welcome_file = strdup(src->welcome_file);
  }
  if (src->reg_welcome_file) {
    dst->reg_welcome_file = strdup(src->reg_welcome_file);
  }
  if (src->logo_url) {
    dst->logo_url = strdup(src->logo_url);
  }
  if (src->css_url) {
    dst->css_url = strdup(src->css_url);
  }
  if (src->ext_id) {
    dst->ext_id = strdup(src->ext_id);
  }
  if (src->problem_count) {
    dst->problem_count = strdup(src->problem_count);
  }
  if (src->telegram_bot_id) {
    dst->telegram_bot_id = strdup(src->telegram_bot_id);
  }
  if (src->telegram_admin_chat_id) {
    dst->telegram_admin_chat_id = strdup(src->telegram_admin_chat_id);
  }
  if (src->telegram_user_chat_id) {
    dst->telegram_user_chat_id = strdup(src->telegram_user_chat_id);
  }
  if (src->avatar_plugin) {
    dst->avatar_plugin = strdup(src->avatar_plugin);
  }
  if (src->content_plugin) {
    dst->content_plugin = strdup(src->content_plugin);
  }
  if (src->content_url_prefix) {
    dst->content_url_prefix = strdup(src->content_url_prefix);
  }
  if (src->special_flow_options) {
    dst->special_flow_options = strdup(src->special_flow_options);
  }
  if (src->client_headers_file) {
    dst->client_headers_file = strdup(src->client_headers_file);
  }
  // slave_rules
  // oauth_rules
  dst->user_contest_num = src->user_contest_num;
  dst->default_locale_num = src->default_locale_num;
  // hidden last_check_time
  // hidden last_file_time
}

void contest_desc_free(struct contest_desc *ptr)
{
  // hidden b
  free(ptr->name);
  free(ptr->name_en);
  free(ptr->main_url);
  free(ptr->keywords);
  free(ptr->comment);
  free(ptr->users_header_file);
  free(ptr->users_footer_file);
  free(ptr->register_header_file);
  free(ptr->register_footer_file);
  free(ptr->team_header_file);
  free(ptr->team_menu_1_file);
  free(ptr->team_menu_2_file);
  free(ptr->team_menu_3_file);
  free(ptr->team_separator_file);
  free(ptr->team_footer_file);
  free(ptr->priv_header_file);
  free(ptr->priv_footer_file);
  free(ptr->copyright_file);
  free(ptr->register_email);
  free(ptr->register_url);
  free(ptr->team_url);
  free(ptr->login_template);
  free(ptr->login_template_options);
  free(ptr->root_dir);
  free(ptr->conf_dir);
  free(ptr->standings_url);
  free(ptr->problems_url);
  free(ptr->analytics_url);
  free(ptr->analytics_key);
  free(ptr->serve_user);
  free(ptr->serve_group);
  free(ptr->run_user);
  free(ptr->run_group);
  free(ptr->register_email_file);
  free(ptr->register_subject);
  free(ptr->register_subject_en);
  // register_access
  // users_access
  // master_access
  // judge_access
  // team_access
  // serve_control_access
  // fields
  // members
  // caps_node
  // capabilities
  free(ptr->users_head_style);
  free(ptr->users_par_style);
  free(ptr->users_table_style);
  free(ptr->users_verb_style);
  free(ptr->users_table_format);
  free(ptr->users_table_format_en);
  free(ptr->users_table_legend);
  free(ptr->users_table_legend_en);
  free(ptr->register_head_style);
  free(ptr->register_par_style);
  free(ptr->register_table_style);
  free(ptr->team_head_style);
  free(ptr->team_par_style);
  free(ptr->cf_notify_email);
  free(ptr->clar_notify_email);
  free(ptr->daily_stat_email);
  free(ptr->user_name_comment);
  free(ptr->allowed_languages);
  free(ptr->allowed_regions);
  free(ptr->user_contest);
  free(ptr->dir_mode);
  free(ptr->dir_group);
  free(ptr->file_mode);
  free(ptr->file_group);
  free(ptr->default_locale);
  free(ptr->welcome_file);
  free(ptr->reg_welcome_file);
  free(ptr->logo_url);
  free(ptr->css_url);
  free(ptr->ext_id);
  free(ptr->problem_count);
  free(ptr->telegram_bot_id);
  free(ptr->telegram_admin_chat_id);
  free(ptr->telegram_user_chat_id);
  free(ptr->avatar_plugin);
  free(ptr->content_plugin);
  free(ptr->content_url_prefix);
  free(ptr->special_flow_options);
  free(ptr->client_headers_file);
  // slave_rules
  // oauth_rules
  // hidden last_check_time
  // hidden last_file_time
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
  (void (*)(void *, const void *))contest_desc_copy,
  (void (*)(void *))contest_desc_free,
  meta_info_contest_desc_data,
};

