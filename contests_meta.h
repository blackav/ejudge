// This is an auto-generated file, do not edit
// Generated 2013/10/17 00:54:49

#ifndef __CONTESTS_META_H__
#define __CONTESTS_META_H__

#include <stdlib.h>

enum
{
  CNTS_id = 1,
  CNTS_autoregister,
  CNTS_disable_team_password,
  CNTS_managed,
  CNTS_run_managed,
  CNTS_clean_users,
  CNTS_closed,
  CNTS_invisible,
  CNTS_simple_registration,
  CNTS_send_passwd_email,
  CNTS_assign_logins,
  CNTS_force_registration,
  CNTS_disable_name,
  CNTS_enable_password_recovery,
  CNTS_exam_mode,
  CNTS_disable_password_change,
  CNTS_disable_locale_change,
  CNTS_personal,
  CNTS_allow_reg_data_edit,
  CNTS_disable_member_delete,
  CNTS_old_run_managed,
  CNTS_ready,
  CNTS_reg_deadline,
  CNTS_sched_time,
  CNTS_open_time,
  CNTS_close_time,
  CNTS_update_time,
  CNTS_name,
  CNTS_name_en,
  CNTS_main_url,
  CNTS_keywords,
  CNTS_users_header_file,
  CNTS_users_footer_file,
  CNTS_register_header_file,
  CNTS_register_footer_file,
  CNTS_team_header_file,
  CNTS_team_menu_1_file,
  CNTS_team_menu_2_file,
  CNTS_team_menu_3_file,
  CNTS_team_separator_file,
  CNTS_team_footer_file,
  CNTS_priv_header_file,
  CNTS_priv_footer_file,
  CNTS_copyright_file,
  CNTS_register_email,
  CNTS_register_url,
  CNTS_team_url,
  CNTS_login_template,
  CNTS_login_template_options,
  CNTS_root_dir,
  CNTS_conf_dir,
  CNTS_standings_url,
  CNTS_problems_url,
  CNTS_serve_user,
  CNTS_serve_group,
  CNTS_run_user,
  CNTS_run_group,
  CNTS_register_email_file,
  CNTS_register_subject,
  CNTS_register_subject_en,
  CNTS_register_access,
  CNTS_users_access,
  CNTS_master_access,
  CNTS_judge_access,
  CNTS_team_access,
  CNTS_serve_control_access,
  CNTS_fields,
  CNTS_members,
  CNTS_caps_node,
  CNTS_capabilities,
  CNTS_users_head_style,
  CNTS_users_par_style,
  CNTS_users_table_style,
  CNTS_users_verb_style,
  CNTS_users_table_format,
  CNTS_users_table_format_en,
  CNTS_users_table_legend,
  CNTS_users_table_legend_en,
  CNTS_register_head_style,
  CNTS_register_par_style,
  CNTS_register_table_style,
  CNTS_team_head_style,
  CNTS_team_par_style,
  CNTS_cf_notify_email,
  CNTS_clar_notify_email,
  CNTS_daily_stat_email,
  CNTS_user_name_comment,
  CNTS_allowed_languages,
  CNTS_allowed_regions,
  CNTS_user_contest,
  CNTS_dir_mode,
  CNTS_dir_group,
  CNTS_file_mode,
  CNTS_file_group,
  CNTS_default_locale,
  CNTS_welcome_file,
  CNTS_reg_welcome_file,
  CNTS_logo_url,
  CNTS_css_url,
  CNTS_ext_id,
  CNTS_problem_count,
  CNTS_slave_rules,
  CNTS_user_contest_num,
  CNTS_default_locale_num,

  CNTS_LAST_FIELD,
};

struct contest_desc;

int contest_desc_get_type(int tag);
size_t contest_desc_get_size(int tag);
const char *contest_desc_get_name(int tag);
const void *contest_desc_get_ptr(const struct contest_desc *ptr, int tag);
void *contest_desc_get_ptr_nc(struct contest_desc *ptr, int tag);
int contest_desc_lookup_field(const char *name);

struct meta_methods;
extern const struct meta_methods contest_desc_methods;

#endif
