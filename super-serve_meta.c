// This is an auto-generated file, do not edit
// Generated 2013/11/25 14:41:48

#include "super-serve_meta.h"
#include "super-serve.h"
#include "meta_generic.h"

#include "reuse_xalloc.h"

#include "reuse_logger.h"
#include <string.h>
#include <stdlib.h>

static struct meta_info_item meta_info_sid_state_data[] =
{
  [SSSS_next] = { SSSS_next, '?', XSIZE(struct sid_state, next), "next", XOFFSET(struct sid_state, next) },
  [SSSS_prev] = { SSSS_prev, '?', XSIZE(struct sid_state, prev), "prev", XOFFSET(struct sid_state, prev) },
  [SSSS_sid] = { SSSS_sid, '?', XSIZE(struct sid_state, sid), "sid", XOFFSET(struct sid_state, sid) },
  [SSSS_remote_addr] = { SSSS_remote_addr, '?', XSIZE(struct sid_state, remote_addr), "remote_addr", XOFFSET(struct sid_state, remote_addr) },
  [SSSS_init_time] = { SSSS_init_time, 't', XSIZE(struct sid_state, init_time), "init_time", XOFFSET(struct sid_state, init_time) },
  [SSSS_flags] = { SSSS_flags, '?', XSIZE(struct sid_state, flags), "flags", XOFFSET(struct sid_state, flags) },
  [SSSS_edited_cnts] = { SSSS_edited_cnts, '?', XSIZE(struct sid_state, edited_cnts), "edited_cnts", XOFFSET(struct sid_state, edited_cnts) },
  [SSSS_user_id] = { SSSS_user_id, 'i', XSIZE(struct sid_state, user_id), "user_id", XOFFSET(struct sid_state, user_id) },
  [SSSS_user_login] = { SSSS_user_login, 's', XSIZE(struct sid_state, user_login), "user_login", XOFFSET(struct sid_state, user_login) },
  [SSSS_user_name] = { SSSS_user_name, 's', XSIZE(struct sid_state, user_name), "user_name", XOFFSET(struct sid_state, user_name) },
  [SSSS_edit_page] = { SSSS_edit_page, 'i', XSIZE(struct sid_state, edit_page), "edit_page", XOFFSET(struct sid_state, edit_page) },
  [SSSS_advanced_view] = { SSSS_advanced_view, 'B', XSIZE(struct sid_state, advanced_view), "advanced_view", XOFFSET(struct sid_state, advanced_view) },
  [SSSS_show_html_attrs] = { SSSS_show_html_attrs, 'B', XSIZE(struct sid_state, show_html_attrs), "show_html_attrs", XOFFSET(struct sid_state, show_html_attrs) },
  [SSSS_show_html_headers] = { SSSS_show_html_headers, 'B', XSIZE(struct sid_state, show_html_headers), "show_html_headers", XOFFSET(struct sid_state, show_html_headers) },
  [SSSS_show_paths] = { SSSS_show_paths, 'B', XSIZE(struct sid_state, show_paths), "show_paths", XOFFSET(struct sid_state, show_paths) },
  [SSSS_show_access_rules] = { SSSS_show_access_rules, 'B', XSIZE(struct sid_state, show_access_rules), "show_access_rules", XOFFSET(struct sid_state, show_access_rules) },
  [SSSS_show_permissions] = { SSSS_show_permissions, 'B', XSIZE(struct sid_state, show_permissions), "show_permissions", XOFFSET(struct sid_state, show_permissions) },
  [SSSS_show_form_fields] = { SSSS_show_form_fields, 'B', XSIZE(struct sid_state, show_form_fields), "show_form_fields", XOFFSET(struct sid_state, show_form_fields) },
  [SSSS_show_notifications] = { SSSS_show_notifications, 'B', XSIZE(struct sid_state, show_notifications), "show_notifications", XOFFSET(struct sid_state, show_notifications) },
  [SSSS_users_header_text] = { SSSS_users_header_text, 's', XSIZE(struct sid_state, users_header_text), "users_header_text", XOFFSET(struct sid_state, users_header_text) },
  [SSSS_users_footer_text] = { SSSS_users_footer_text, 's', XSIZE(struct sid_state, users_footer_text), "users_footer_text", XOFFSET(struct sid_state, users_footer_text) },
  [SSSS_register_header_text] = { SSSS_register_header_text, 's', XSIZE(struct sid_state, register_header_text), "register_header_text", XOFFSET(struct sid_state, register_header_text) },
  [SSSS_register_footer_text] = { SSSS_register_footer_text, 's', XSIZE(struct sid_state, register_footer_text), "register_footer_text", XOFFSET(struct sid_state, register_footer_text) },
  [SSSS_team_header_text] = { SSSS_team_header_text, 's', XSIZE(struct sid_state, team_header_text), "team_header_text", XOFFSET(struct sid_state, team_header_text) },
  [SSSS_team_menu_1_text] = { SSSS_team_menu_1_text, 's', XSIZE(struct sid_state, team_menu_1_text), "team_menu_1_text", XOFFSET(struct sid_state, team_menu_1_text) },
  [SSSS_team_menu_2_text] = { SSSS_team_menu_2_text, 's', XSIZE(struct sid_state, team_menu_2_text), "team_menu_2_text", XOFFSET(struct sid_state, team_menu_2_text) },
  [SSSS_team_menu_3_text] = { SSSS_team_menu_3_text, 's', XSIZE(struct sid_state, team_menu_3_text), "team_menu_3_text", XOFFSET(struct sid_state, team_menu_3_text) },
  [SSSS_team_separator_text] = { SSSS_team_separator_text, 's', XSIZE(struct sid_state, team_separator_text), "team_separator_text", XOFFSET(struct sid_state, team_separator_text) },
  [SSSS_team_footer_text] = { SSSS_team_footer_text, 's', XSIZE(struct sid_state, team_footer_text), "team_footer_text", XOFFSET(struct sid_state, team_footer_text) },
  [SSSS_priv_header_text] = { SSSS_priv_header_text, 's', XSIZE(struct sid_state, priv_header_text), "priv_header_text", XOFFSET(struct sid_state, priv_header_text) },
  [SSSS_priv_footer_text] = { SSSS_priv_footer_text, 's', XSIZE(struct sid_state, priv_footer_text), "priv_footer_text", XOFFSET(struct sid_state, priv_footer_text) },
  [SSSS_register_email_text] = { SSSS_register_email_text, 's', XSIZE(struct sid_state, register_email_text), "register_email_text", XOFFSET(struct sid_state, register_email_text) },
  [SSSS_copyright_text] = { SSSS_copyright_text, 's', XSIZE(struct sid_state, copyright_text), "copyright_text", XOFFSET(struct sid_state, copyright_text) },
  [SSSS_welcome_text] = { SSSS_welcome_text, 's', XSIZE(struct sid_state, welcome_text), "welcome_text", XOFFSET(struct sid_state, welcome_text) },
  [SSSS_reg_welcome_text] = { SSSS_reg_welcome_text, 's', XSIZE(struct sid_state, reg_welcome_text), "reg_welcome_text", XOFFSET(struct sid_state, reg_welcome_text) },
  [SSSS_users_header_loaded] = { SSSS_users_header_loaded, 'B', XSIZE(struct sid_state, users_header_loaded), "users_header_loaded", XOFFSET(struct sid_state, users_header_loaded) },
  [SSSS_users_footer_loaded] = { SSSS_users_footer_loaded, 'B', XSIZE(struct sid_state, users_footer_loaded), "users_footer_loaded", XOFFSET(struct sid_state, users_footer_loaded) },
  [SSSS_register_header_loaded] = { SSSS_register_header_loaded, 'B', XSIZE(struct sid_state, register_header_loaded), "register_header_loaded", XOFFSET(struct sid_state, register_header_loaded) },
  [SSSS_register_footer_loaded] = { SSSS_register_footer_loaded, 'B', XSIZE(struct sid_state, register_footer_loaded), "register_footer_loaded", XOFFSET(struct sid_state, register_footer_loaded) },
  [SSSS_team_header_loaded] = { SSSS_team_header_loaded, 'B', XSIZE(struct sid_state, team_header_loaded), "team_header_loaded", XOFFSET(struct sid_state, team_header_loaded) },
  [SSSS_team_menu_1_loaded] = { SSSS_team_menu_1_loaded, 'B', XSIZE(struct sid_state, team_menu_1_loaded), "team_menu_1_loaded", XOFFSET(struct sid_state, team_menu_1_loaded) },
  [SSSS_team_menu_2_loaded] = { SSSS_team_menu_2_loaded, 'B', XSIZE(struct sid_state, team_menu_2_loaded), "team_menu_2_loaded", XOFFSET(struct sid_state, team_menu_2_loaded) },
  [SSSS_team_menu_3_loaded] = { SSSS_team_menu_3_loaded, 'B', XSIZE(struct sid_state, team_menu_3_loaded), "team_menu_3_loaded", XOFFSET(struct sid_state, team_menu_3_loaded) },
  [SSSS_team_separator_loaded] = { SSSS_team_separator_loaded, 'B', XSIZE(struct sid_state, team_separator_loaded), "team_separator_loaded", XOFFSET(struct sid_state, team_separator_loaded) },
  [SSSS_team_footer_loaded] = { SSSS_team_footer_loaded, 'B', XSIZE(struct sid_state, team_footer_loaded), "team_footer_loaded", XOFFSET(struct sid_state, team_footer_loaded) },
  [SSSS_priv_header_loaded] = { SSSS_priv_header_loaded, 'B', XSIZE(struct sid_state, priv_header_loaded), "priv_header_loaded", XOFFSET(struct sid_state, priv_header_loaded) },
  [SSSS_priv_footer_loaded] = { SSSS_priv_footer_loaded, 'B', XSIZE(struct sid_state, priv_footer_loaded), "priv_footer_loaded", XOFFSET(struct sid_state, priv_footer_loaded) },
  [SSSS_register_email_loaded] = { SSSS_register_email_loaded, 'B', XSIZE(struct sid_state, register_email_loaded), "register_email_loaded", XOFFSET(struct sid_state, register_email_loaded) },
  [SSSS_copyright_loaded] = { SSSS_copyright_loaded, 'B', XSIZE(struct sid_state, copyright_loaded), "copyright_loaded", XOFFSET(struct sid_state, copyright_loaded) },
  [SSSS_welcome_loaded] = { SSSS_welcome_loaded, 'B', XSIZE(struct sid_state, welcome_loaded), "welcome_loaded", XOFFSET(struct sid_state, welcome_loaded) },
  [SSSS_reg_welcome_loaded] = { SSSS_reg_welcome_loaded, 'B', XSIZE(struct sid_state, reg_welcome_loaded), "reg_welcome_loaded", XOFFSET(struct sid_state, reg_welcome_loaded) },
  [SSSS_serve_parse_errors] = { SSSS_serve_parse_errors, 's', XSIZE(struct sid_state, serve_parse_errors), "serve_parse_errors", XOFFSET(struct sid_state, serve_parse_errors) },
  [SSSS_cfg] = { SSSS_cfg, '?', XSIZE(struct sid_state, cfg), "cfg", XOFFSET(struct sid_state, cfg) },
  [SSSS_global] = { SSSS_global, '?', XSIZE(struct sid_state, global), "global", XOFFSET(struct sid_state, global) },
  [SSSS_lang_a] = { SSSS_lang_a, 'i', XSIZE(struct sid_state, lang_a), "lang_a", XOFFSET(struct sid_state, lang_a) },
  [SSSS_langs] = { SSSS_langs, '?', XSIZE(struct sid_state, langs), "langs", XOFFSET(struct sid_state, langs) },
  [SSSS_loc_cs_map] = { SSSS_loc_cs_map, '?', XSIZE(struct sid_state, loc_cs_map), "loc_cs_map", XOFFSET(struct sid_state, loc_cs_map) },
  [SSSS_cs_loc_map] = { SSSS_cs_loc_map, '?', XSIZE(struct sid_state, cs_loc_map), "cs_loc_map", XOFFSET(struct sid_state, cs_loc_map) },
  [SSSS_lang_opts] = { SSSS_lang_opts, 'x', XSIZE(struct sid_state, lang_opts), "lang_opts", XOFFSET(struct sid_state, lang_opts) },
  [SSSS_lang_flags] = { SSSS_lang_flags, '?', XSIZE(struct sid_state, lang_flags), "lang_flags", XOFFSET(struct sid_state, lang_flags) },
  [SSSS_aprob_u] = { SSSS_aprob_u, 'i', XSIZE(struct sid_state, aprob_u), "aprob_u", XOFFSET(struct sid_state, aprob_u) },
  [SSSS_aprob_a] = { SSSS_aprob_a, 'i', XSIZE(struct sid_state, aprob_a), "aprob_a", XOFFSET(struct sid_state, aprob_a) },
  [SSSS_aprobs] = { SSSS_aprobs, '?', XSIZE(struct sid_state, aprobs), "aprobs", XOFFSET(struct sid_state, aprobs) },
  [SSSS_aprob_flags] = { SSSS_aprob_flags, '?', XSIZE(struct sid_state, aprob_flags), "aprob_flags", XOFFSET(struct sid_state, aprob_flags) },
  [SSSS_prob_a] = { SSSS_prob_a, 'i', XSIZE(struct sid_state, prob_a), "prob_a", XOFFSET(struct sid_state, prob_a) },
  [SSSS_probs] = { SSSS_probs, '?', XSIZE(struct sid_state, probs), "probs", XOFFSET(struct sid_state, probs) },
  [SSSS_prob_flags] = { SSSS_prob_flags, '?', XSIZE(struct sid_state, prob_flags), "prob_flags", XOFFSET(struct sid_state, prob_flags) },
  [SSSS_atester_total] = { SSSS_atester_total, 'i', XSIZE(struct sid_state, atester_total), "atester_total", XOFFSET(struct sid_state, atester_total) },
  [SSSS_atesters] = { SSSS_atesters, '?', XSIZE(struct sid_state, atesters), "atesters", XOFFSET(struct sid_state, atesters) },
  [SSSS_tester_total] = { SSSS_tester_total, 'i', XSIZE(struct sid_state, tester_total), "tester_total", XOFFSET(struct sid_state, tester_total) },
  [SSSS_testers] = { SSSS_testers, '?', XSIZE(struct sid_state, testers), "testers", XOFFSET(struct sid_state, testers) },
  [SSSS_show_global_1] = { SSSS_show_global_1, 'B', XSIZE(struct sid_state, show_global_1), "show_global_1", XOFFSET(struct sid_state, show_global_1) },
  [SSSS_show_global_2] = { SSSS_show_global_2, 'B', XSIZE(struct sid_state, show_global_2), "show_global_2", XOFFSET(struct sid_state, show_global_2) },
  [SSSS_show_global_3] = { SSSS_show_global_3, 'B', XSIZE(struct sid_state, show_global_3), "show_global_3", XOFFSET(struct sid_state, show_global_3) },
  [SSSS_show_global_4] = { SSSS_show_global_4, 'B', XSIZE(struct sid_state, show_global_4), "show_global_4", XOFFSET(struct sid_state, show_global_4) },
  [SSSS_show_global_5] = { SSSS_show_global_5, 'B', XSIZE(struct sid_state, show_global_5), "show_global_5", XOFFSET(struct sid_state, show_global_5) },
  [SSSS_show_global_6] = { SSSS_show_global_6, 'B', XSIZE(struct sid_state, show_global_6), "show_global_6", XOFFSET(struct sid_state, show_global_6) },
  [SSSS_show_global_7] = { SSSS_show_global_7, 'B', XSIZE(struct sid_state, show_global_7), "show_global_7", XOFFSET(struct sid_state, show_global_7) },
  [SSSS_enable_stand2] = { SSSS_enable_stand2, 'B', XSIZE(struct sid_state, enable_stand2), "enable_stand2", XOFFSET(struct sid_state, enable_stand2) },
  [SSSS_enable_plog] = { SSSS_enable_plog, 'B', XSIZE(struct sid_state, enable_plog), "enable_plog", XOFFSET(struct sid_state, enable_plog) },
  [SSSS_enable_extra_col] = { SSSS_enable_extra_col, 'B', XSIZE(struct sid_state, enable_extra_col), "enable_extra_col", XOFFSET(struct sid_state, enable_extra_col) },
  [SSSS_disable_compilation_server] = { SSSS_disable_compilation_server, 'B', XSIZE(struct sid_state, disable_compilation_server), "disable_compilation_server", XOFFSET(struct sid_state, disable_compilation_server) },
  [SSSS_enable_win32_languages] = { SSSS_enable_win32_languages, 'B', XSIZE(struct sid_state, enable_win32_languages), "enable_win32_languages", XOFFSET(struct sid_state, enable_win32_languages) },
  [SSSS_cs_langs_loaded] = { SSSS_cs_langs_loaded, 'i', XSIZE(struct sid_state, cs_langs_loaded), "cs_langs_loaded", XOFFSET(struct sid_state, cs_langs_loaded) },
  [SSSS_cs_lang_total] = { SSSS_cs_lang_total, 'i', XSIZE(struct sid_state, cs_lang_total), "cs_lang_total", XOFFSET(struct sid_state, cs_lang_total) },
  [SSSS_cs_cfg] = { SSSS_cs_cfg, '?', XSIZE(struct sid_state, cs_cfg), "cs_cfg", XOFFSET(struct sid_state, cs_cfg) },
  [SSSS_cs_langs] = { SSSS_cs_langs, '?', XSIZE(struct sid_state, cs_langs), "cs_langs", XOFFSET(struct sid_state, cs_langs) },
  [SSSS_cs_lang_names] = { SSSS_cs_lang_names, 'x', XSIZE(struct sid_state, cs_lang_names), "cs_lang_names", XOFFSET(struct sid_state, cs_lang_names) },
  [SSSS_extra_cs_cfgs_total] = { SSSS_extra_cs_cfgs_total, 'i', XSIZE(struct sid_state, extra_cs_cfgs_total), "extra_cs_cfgs_total", XOFFSET(struct sid_state, extra_cs_cfgs_total) },
  [SSSS_extra_cs_cfgs] = { SSSS_extra_cs_cfgs, '?', XSIZE(struct sid_state, extra_cs_cfgs), "extra_cs_cfgs", XOFFSET(struct sid_state, extra_cs_cfgs) },
  [SSSS_cur_lang] = { SSSS_cur_lang, '?', XSIZE(struct sid_state, cur_lang), "cur_lang", XOFFSET(struct sid_state, cur_lang) },
  [SSSS_cur_prob] = { SSSS_cur_prob, '?', XSIZE(struct sid_state, cur_prob), "cur_prob", XOFFSET(struct sid_state, cur_prob) },
  [SSSS_prob_show_adv] = { SSSS_prob_show_adv, 'B', XSIZE(struct sid_state, prob_show_adv), "prob_show_adv", XOFFSET(struct sid_state, prob_show_adv) },
  [SSSS_contest_start_cmd_text] = { SSSS_contest_start_cmd_text, 's', XSIZE(struct sid_state, contest_start_cmd_text), "contest_start_cmd_text", XOFFSET(struct sid_state, contest_start_cmd_text) },
  [SSSS_contest_stop_cmd_text] = { SSSS_contest_stop_cmd_text, 's', XSIZE(struct sid_state, contest_stop_cmd_text), "contest_stop_cmd_text", XOFFSET(struct sid_state, contest_stop_cmd_text) },
  [SSSS_stand_header_text] = { SSSS_stand_header_text, 's', XSIZE(struct sid_state, stand_header_text), "stand_header_text", XOFFSET(struct sid_state, stand_header_text) },
  [SSSS_stand_footer_text] = { SSSS_stand_footer_text, 's', XSIZE(struct sid_state, stand_footer_text), "stand_footer_text", XOFFSET(struct sid_state, stand_footer_text) },
  [SSSS_stand2_header_text] = { SSSS_stand2_header_text, 's', XSIZE(struct sid_state, stand2_header_text), "stand2_header_text", XOFFSET(struct sid_state, stand2_header_text) },
  [SSSS_stand2_footer_text] = { SSSS_stand2_footer_text, 's', XSIZE(struct sid_state, stand2_footer_text), "stand2_footer_text", XOFFSET(struct sid_state, stand2_footer_text) },
  [SSSS_plog_header_text] = { SSSS_plog_header_text, 's', XSIZE(struct sid_state, plog_header_text), "plog_header_text", XOFFSET(struct sid_state, plog_header_text) },
  [SSSS_plog_footer_text] = { SSSS_plog_footer_text, 's', XSIZE(struct sid_state, plog_footer_text), "plog_footer_text", XOFFSET(struct sid_state, plog_footer_text) },
  [SSSS_var_header_text] = { SSSS_var_header_text, 's', XSIZE(struct sid_state, var_header_text), "var_header_text", XOFFSET(struct sid_state, var_header_text) },
  [SSSS_var_footer_text] = { SSSS_var_footer_text, 's', XSIZE(struct sid_state, var_footer_text), "var_footer_text", XOFFSET(struct sid_state, var_footer_text) },
  [SSSS_compile_home_dir] = { SSSS_compile_home_dir, 's', XSIZE(struct sid_state, compile_home_dir), "compile_home_dir", XOFFSET(struct sid_state, compile_home_dir) },
  [SSSS_user_filter_set] = { SSSS_user_filter_set, 'B', XSIZE(struct sid_state, user_filter_set), "user_filter_set", XOFFSET(struct sid_state, user_filter_set) },
  [SSSS_user_filter] = { SSSS_user_filter, 's', XSIZE(struct sid_state, user_filter), "user_filter", XOFFSET(struct sid_state, user_filter) },
  [SSSS_user_offset] = { SSSS_user_offset, 'i', XSIZE(struct sid_state, user_offset), "user_offset", XOFFSET(struct sid_state, user_offset) },
  [SSSS_user_count] = { SSSS_user_count, 'i', XSIZE(struct sid_state, user_count), "user_count", XOFFSET(struct sid_state, user_count) },
  [SSSS_group_filter_set] = { SSSS_group_filter_set, 'B', XSIZE(struct sid_state, group_filter_set), "group_filter_set", XOFFSET(struct sid_state, group_filter_set) },
  [SSSS_group_filter] = { SSSS_group_filter, 's', XSIZE(struct sid_state, group_filter), "group_filter", XOFFSET(struct sid_state, group_filter) },
  [SSSS_group_offset] = { SSSS_group_offset, 'i', XSIZE(struct sid_state, group_offset), "group_offset", XOFFSET(struct sid_state, group_offset) },
  [SSSS_group_count] = { SSSS_group_count, 'i', XSIZE(struct sid_state, group_count), "group_count", XOFFSET(struct sid_state, group_count) },
  [SSSS_contest_user_filter_set] = { SSSS_contest_user_filter_set, 'B', XSIZE(struct sid_state, contest_user_filter_set), "contest_user_filter_set", XOFFSET(struct sid_state, contest_user_filter_set) },
  [SSSS_contest_user_filter] = { SSSS_contest_user_filter, 's', XSIZE(struct sid_state, contest_user_filter), "contest_user_filter", XOFFSET(struct sid_state, contest_user_filter) },
  [SSSS_contest_user_offset] = { SSSS_contest_user_offset, 'i', XSIZE(struct sid_state, contest_user_offset), "contest_user_offset", XOFFSET(struct sid_state, contest_user_offset) },
  [SSSS_contest_user_count] = { SSSS_contest_user_count, 'i', XSIZE(struct sid_state, contest_user_count), "contest_user_count", XOFFSET(struct sid_state, contest_user_count) },
  [SSSS_group_user_filter_set] = { SSSS_group_user_filter_set, 'B', XSIZE(struct sid_state, group_user_filter_set), "group_user_filter_set", XOFFSET(struct sid_state, group_user_filter_set) },
  [SSSS_group_user_filter] = { SSSS_group_user_filter, 's', XSIZE(struct sid_state, group_user_filter), "group_user_filter", XOFFSET(struct sid_state, group_user_filter) },
  [SSSS_group_user_offset] = { SSSS_group_user_offset, 'i', XSIZE(struct sid_state, group_user_offset), "group_user_offset", XOFFSET(struct sid_state, group_user_offset) },
  [SSSS_group_user_count] = { SSSS_group_user_count, 'i', XSIZE(struct sid_state, group_user_count), "group_user_count", XOFFSET(struct sid_state, group_user_count) },
  [SSSS_marked] = { SSSS_marked, '?', XSIZE(struct sid_state, marked), "marked", XOFFSET(struct sid_state, marked) },
  [SSSS_update_state] = { SSSS_update_state, '?', XSIZE(struct sid_state, update_state), "update_state", XOFFSET(struct sid_state, update_state) },
  [SSSS_te_state] = { SSSS_te_state, '?', XSIZE(struct sid_state, te_state), "te_state", XOFFSET(struct sid_state, te_state) },
};

int ss_sid_state_get_type(int tag)
{
  ASSERT(tag > 0 && tag < SSSS_LAST_FIELD);
  return meta_info_sid_state_data[tag].type;
}

size_t ss_sid_state_get_size(int tag)
{
  ASSERT(tag > 0 && tag < SSSS_LAST_FIELD);
  return meta_info_sid_state_data[tag].size;
}

const char *ss_sid_state_get_name(int tag)
{
  ASSERT(tag > 0 && tag < SSSS_LAST_FIELD);
  return meta_info_sid_state_data[tag].name;
}

const void *ss_sid_state_get_ptr(const struct sid_state *ptr, int tag)
{
  ASSERT(tag > 0 && tag < SSSS_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_sid_state_data[tag].offset);
}

void *ss_sid_state_get_ptr_nc(struct sid_state *ptr, int tag)
{
  ASSERT(tag > 0 && tag < SSSS_LAST_FIELD);
  return XPDEREF(void, ptr, meta_info_sid_state_data[tag].offset);
}

int ss_sid_state_lookup_field(const char *name)
{
  static struct meta_automaton *atm = 0;
  ASSERT(name);
  if (!atm) atm = meta_build_automaton(meta_info_sid_state_data, SSSS_LAST_FIELD);
  return meta_lookup_string(atm, name);
}

const struct meta_methods ss_sid_state_methods =
{
  SSSS_LAST_FIELD,
  sizeof(struct sid_state),
  ss_sid_state_get_type,
  ss_sid_state_get_size,
  ss_sid_state_get_name,
  (const void *(*)(const void *ptr, int tag))ss_sid_state_get_ptr,
  (void *(*)(void *ptr, int tag))ss_sid_state_get_ptr_nc,
  ss_sid_state_lookup_field,
};

