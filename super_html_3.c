/* -*- mode: c -*- */

/* Copyright (C) 2005-2015 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ejudge/config.h"
#include "ejudge/version.h"
#include "ejudge/super_html.h"
#include "ejudge/super-serve.h"
#include "ejudge/misctext.h"
#include "ejudge/mischtml.h"
#include "ejudge/prepare.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/super_proto.h"
#include "ejudge/fileutl.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/xml_utils.h"
#include "ejudge/ej_process.h"
#include "ejudge/cpu.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/userlist_proto.h"
#include "ejudge/userlist.h"
#include "ejudge/prepare_serve.h"
#include "ejudge/errlog.h"
#include "ejudge/random.h"
#include "ejudge/compat.h"
#include "ejudge/file_perms.h"
#include "ejudge/build_support.h"
#include "ejudge/variant_map.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/wait.h>
#include <errno.h>

#if defined EJUDGE_CHARSET
#define INTERNAL_CHARSET EJUDGE_CHARSET
#else
#define INTERNAL_CHARSET "utf-8"
#endif

#define ARMOR(s)  html_armor_buf(&ab, (s))

static const unsigned char head_row_attr[] =
  " bgcolor=\"#a0a0a0\"";
static const unsigned char prob_row_attr[] =
  " bgcolor=\"#b0b0b0\"";
static const unsigned char * const form_row_attrs[]=
{
  " bgcolor=\"#d0d0d0\"",
  " bgcolor=\"#e0e0e0\"",
};

void
html_select(FILE *f, int value, const unsigned char *param_name,
            const unsigned char * const *options)
{
  int i;

  fprintf(f, "<select name=\"%s\">", param_name);
  for (i = 0; options[i]; i++)
    fprintf(f, "<option value=\"%d\"%s>%s</option>",
            i, (i == value) ? " selected=\"1\"" : "", options[i]);
  fprintf(f, "</select>\n");
}

const unsigned char * const super_serve_help_urls[SSERV_CMD_LAST] =
{
  /*
  SSERV_CMD_CNTS_EDIT_PERMISSION,
  SSERV_CMD_CNTS_EDIT_FORM_FIELDS,
  SSERV_CMD_CNTS_EDIT_CONTESTANT_FIELDS,
  SSERV_CMD_CNTS_EDIT_RESERVE_FIELDS,
  SSERV_CMD_CNTS_EDIT_COACH_FIELDS,
  SSERV_CMD_CNTS_EDIT_ADVISOR_FIELDS,
  SSERV_CMD_CNTS_EDIT_GUEST_FIELDS,
  SSERV_CMD_CNTS_EDIT_USERS_HEADER,
  SSERV_CMD_CNTS_EDIT_USERS_FOOTER,
  SSERV_CMD_CNTS_EDIT_REGISTER_HEADER,
  SSERV_CMD_CNTS_EDIT_REGISTER_FOOTER,
  SSERV_CMD_CNTS_EDIT_TEAM_HEADER,
  SSERV_CMD_CNTS_EDIT_TEAM_MENU_1,
  SSERV_CMD_CNTS_EDIT_TEAM_MENU_2,
  SSERV_CMD_CNTS_EDIT_TEAM_MENU_3,
  SSERV_CMD_CNTS_EDIT_TEAM_SEPARATOR,
  SSERV_CMD_CNTS_EDIT_TEAM_FOOTER,
  SSERV_CMD_CNTS_EDIT_PRIV_HEADER,
  SSERV_CMD_CNTS_EDIT_PRIV_FOOTER,
  SSERV_CMD_CNTS_EDIT_COPYRIGHT,
  SSERV_CMD_CNTS_EDIT_WELCOME,
  SSERV_CMD_CNTS_EDIT_REG_WELCOME,
  SSERV_CMD_CNTS_EDIT_REGISTER_EMAIL_FILE,
  */

  [SSERV_CMD_CNTS_CHANGE_NAME] = "Contest.xml:name",
  [SSERV_CMD_CNTS_CHANGE_NAME_EN] = "Contest.xml:name_en",
  [SSERV_CMD_CNTS_CHANGE_MAIN_URL] = "Contest.xml:main_url",
  [SSERV_CMD_CNTS_CHANGE_KEYWORDS] = "Contest.xml:keywords",
  [SSERV_CMD_CNTS_CHANGE_USER_CONTEST] = "Contest.xml:user_contest",
  [SSERV_CMD_CNTS_CHANGE_DEFAULT_LOCALE] = "Contest.xml:default_locale",
  [SSERV_CMD_CNTS_CHANGE_AUTOREGISTER] = "Contest.xml:autoregister",
  [SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD] = "Contest.xml:disable_team_password",
  [SSERV_CMD_CNTS_CHANGE_SIMPLE_REGISTRATION] = "Contest.xml:simple_registration",
  [SSERV_CMD_CNTS_CHANGE_ASSIGN_LOGINS] = "Contest.xml:assign_logins",
  [SSERV_CMD_CNTS_CHANGE_FORCE_REGISTRATION] = "Contest.xml:force_registration",
  [SSERV_CMD_CNTS_CHANGE_DISABLE_NAME] = "Contest.xml:disable_name",
  [SSERV_CMD_CNTS_CHANGE_ENABLE_PASSWORD_RECOVERY] = "Contest.xml:enable_password_recovery",
  [SSERV_CMD_CNTS_CHANGE_EXAM_MODE] = "Contest.xml:exam_mode",
  [SSERV_CMD_CNTS_CHANGE_DISABLE_PASSWORD_CHANGE] = "Contest.xml:disable_password_change",
  [SSERV_CMD_CNTS_CHANGE_DISABLE_LOCALE_CHANGE] = "Contest.xml:disable_locale_change",
  [SSERV_CMD_CNTS_CHANGE_PERSONAL] = "Contest.xml:personal",
  [SSERV_CMD_CNTS_CHANGE_ALLOW_REG_DATA_EDIT] = "Contest.xml:allow_reg_data_edit",
  [SSERV_CMD_CNTS_CHANGE_SEND_PASSWD_EMAIL] = "Contest.xml:send_passwd_email",
  [SSERV_CMD_CNTS_CHANGE_MANAGED] = "Contest.xml:managed",
  [SSERV_CMD_CNTS_CHANGE_RUN_MANAGED] = "Contest.xml:run_managed",
  [SSERV_CMD_CNTS_CHANGE_OLD_RUN_MANAGED] = "Contest.xml:old_run_managed",
  [SSERV_CMD_CNTS_CHANGE_CLEAN_USERS] = "Contest.xml:clean_users",
  [SSERV_CMD_CNTS_CHANGE_CLOSED] = "Contest.xml:closed",
  [SSERV_CMD_CNTS_CHANGE_INVISIBLE] = "Contest.xml:invisible",
  [SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE] = "Contest.xml:disable_member_delete",
  [SSERV_CMD_CNTS_CHANGE_DEADLINE] = "Contest.xml:registration_deadline",
  [SSERV_CMD_CNTS_CHANGE_SCHED_TIME] = "Contest.xml:sched_time",
  [SSERV_CMD_CNTS_CHANGE_OPEN_TIME] = "Contest.xml:open_time",
  [SSERV_CMD_CNTS_CHANGE_CLOSE_TIME] = "Contest.xml:close_time",
  [SSERV_CMD_CNTS_CHANGE_USERS_HEADER] = "Contest.xml:users_header_file",
  [SSERV_CMD_CNTS_CHANGE_USERS_FOOTER] = "Contest.xml:users_footer_file",
  [SSERV_CMD_CNTS_CHANGE_REGISTER_HEADER] = "Contest.xml:register_header_file",
  [SSERV_CMD_CNTS_CHANGE_REGISTER_FOOTER] = "Contest.xml:register_footer_file",
  [SSERV_CMD_CNTS_CHANGE_TEAM_HEADER] = "Contest.xml:team_header_file",
  [SSERV_CMD_CNTS_CHANGE_TEAM_MENU_1] = "Contest.xml:team_menu_1_file",
  [SSERV_CMD_CNTS_CHANGE_TEAM_MENU_2] = "Contest.xml:team_menu_2_file",
  [SSERV_CMD_CNTS_CHANGE_TEAM_MENU_3] = "Contest.xml:team_menu_3_file",
  [SSERV_CMD_CNTS_CHANGE_TEAM_SEPARATOR] = "Contest.xml:team_separator_file",
  [SSERV_CMD_CNTS_CHANGE_TEAM_FOOTER] = "Contest.xml:team_footer_file",
  [SSERV_CMD_CNTS_CHANGE_PRIV_HEADER] = "Contest.xml:priv_header_file",
  [SSERV_CMD_CNTS_CHANGE_PRIV_FOOTER] = "Contest.xml:priv_footer_file",
  [SSERV_CMD_CNTS_CHANGE_COPYRIGHT] = "Contest.xml:copyright_file",
  [SSERV_CMD_CNTS_CHANGE_WELCOME] = "Contest.xml:welcome_file",
  [SSERV_CMD_CNTS_CHANGE_REG_WELCOME] = "Contest.xml:reg_welcome_file",
  [SSERV_CMD_CNTS_CHANGE_USERS_HEAD_STYLE] = "Contest.xml:users_head_style",
  [SSERV_CMD_CNTS_CHANGE_USERS_PAR_STYLE] = "Contest.xml:users_par_style",
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_STYLE] = "Contest.xml:users_table_style",
  [SSERV_CMD_CNTS_CHANGE_USERS_VERB_STYLE] = "Contest.xml:users_verb_style",
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT] = "Contest.xml:users_table_format",
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT_EN] = "Contest.xml:users_table_format_en",
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND] = "Contest.xml:users_table_legend",
  [SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND_EN] = "Contest.xml:users_table_legend_en",
  [SSERV_CMD_CNTS_CHANGE_REGISTER_HEAD_STYLE] = "Contest.xml:register_head_style",
  [SSERV_CMD_CNTS_CHANGE_REGISTER_PAR_STYLE] = "Contest.xml:register_par_style",
  [SSERV_CMD_CNTS_CHANGE_REGISTER_TABLE_STYLE] = "Contest.xml:register_table_style",
  [SSERV_CMD_CNTS_CHANGE_REGISTER_NAME_COMMENT] = "Contest.xml:user_name_comment",
  [SSERV_CMD_CNTS_CHANGE_ALLOWED_LANGUAGES] = "Contest.xml:allowed_languages",
  [SSERV_CMD_CNTS_CHANGE_ALLOWED_REGIONS] = "Contest.xml:allowed_regions",
  [SSERV_CMD_CNTS_CHANGE_CF_NOTIFY_EMAIL] = "Contest.xml:cf_notify_email",
  [SSERV_CMD_CNTS_CHANGE_CLAR_NOTIFY_EMAIL] = "Contest.xml:clar_notify_email",
  [SSERV_CMD_CNTS_CHANGE_DAILY_STAT_EMAIL] = "Contest.xml:daily_stat_email",
  [SSERV_CMD_CNTS_CHANGE_TEAM_HEAD_STYLE] = "Contest.xml:team_head_style",
  [SSERV_CMD_CNTS_CHANGE_TEAM_PAR_STYLE] = "Contest.xml:team_par_style",
  [SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL] = "Contest.xml:register_email",
  [SSERV_CMD_CNTS_CHANGE_REGISTER_URL] = "Contest.xml:register_url",
  [SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE] = "Contest.xml:login_template",
  [SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE_OPTIONS] = "Contest.xml:login_template_options",
  [SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL_FILE] = "Contest.xml:register_email_file",
  [SSERV_CMD_CNTS_CHANGE_TEAM_URL] = "Contest.xml:team_url",
  [SSERV_CMD_CNTS_CHANGE_STANDINGS_URL] = "Contest.xml:standings_url",
  [SSERV_CMD_CNTS_CHANGE_PROBLEMS_URL] = "Contest.xml:problems_url",
  [SSERV_CMD_CNTS_CHANGE_LOGO_URL] = "Contest.xml:logo_url",
  [SSERV_CMD_CNTS_CHANGE_ROOT_DIR] = "Contest.xml:root_dir",
  [SSERV_CMD_CNTS_CHANGE_CONF_DIR] = "Contest.xml:conf_dir",
  [SSERV_CMD_CNTS_CHANGE_DIR_MODE] = "Contest.xml:dir_mode",
  [SSERV_CMD_CNTS_CHANGE_DIR_GROUP] = "Contest.xml:dir_group",
  [SSERV_CMD_CNTS_CHANGE_FILE_MODE] = "Contest.xml:file_mode",
  [SSERV_CMD_CNTS_CHANGE_FILE_GROUP] = "Contest.xml:file_group",
  [SSERV_CMD_CNTS_DEFAULT_ACCESS] = "Contest.xml",
  [SSERV_CMD_CNTS_ADD_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_CHANGE_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_DELETE_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_UP_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_DOWN_RULE] = "Contest.xml",
  [SSERV_CMD_CNTS_COPY_ACCESS] = "Contest.xml",
  [SSERV_CMD_CNTS_DELETE_PERMISSION] = "Contest.xml",
  [SSERV_CMD_CNTS_ADD_PERMISSION] = "Contest.xml",
  [SSERV_CMD_CNTS_SAVE_PERMISSIONS] = "Contest.xml",
  [SSERV_CMD_CNTS_SET_PREDEF_PERMISSIONS] = "Contest.xml",

  [SSERV_CMD_GLOB_CHANGE_DURATION] = "Serve.cfg:global:contest_time",
  [SSERV_CMD_GLOB_CHANGE_TYPE] = "Serve.cfg:global:score_system",
  [SSERV_CMD_GLOB_CHANGE_FOG_TIME] = "Serve.cfg:global:board_fog_time",
  [SSERV_CMD_GLOB_CHANGE_UNFOG_TIME] = "Serve.cfg:global:board_unfog_time",
  [SSERV_CMD_GLOB_CHANGE_STAND_LOCALE] = "Serve.cfg:global:standings_locale",
  [SSERV_CMD_GLOB_CHANGE_CHECKER_LOCALE] = "Serve.cfg:global:checker_locale",
  [SSERV_CMD_GLOB_CHANGE_TOKENS] = "Serve.cfg:global:tokens",
  [SSERV_CMD_GLOB_CHANGE_SRC_VIEW] = "Serve.cfg:global:team_enable_src_view",
  [SSERV_CMD_GLOB_CHANGE_REP_VIEW] = "Serve.cfg:global:team_enable_rep_view",
  [SSERV_CMD_GLOB_CHANGE_CE_VIEW] = "Serve.cfg:global:team_enable_ce_view",
  [SSERV_CMD_GLOB_CHANGE_JUDGE_REPORT] = "Serve.cfg:global:team_show_judge_report",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_CLARS] = "Serve.cfg:global:disable_clars",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_TEAM_CLARS] = "Serve.cfg:global:disable_team_clars",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_EOLN_SELECT] = "Serve.cfg:global:enable_eoln_select",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK] = "Serve.cfg:global:disable_submit_after_ok",
  [SSERV_CMD_GLOB_CHANGE_IGNORE_COMPILE_ERRORS] = "Serve.cfg:global:ignore_compile_errors",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW] = "Serve.cfg:global:disable_failed_test_view",
  [SSERV_CMD_GLOB_CHANGE_IGNORE_DUPLICATED_RUNS] = "Serve.cfg:global:ignore_duplicated_runs",
  [SSERV_CMD_GLOB_CHANGE_REPORT_ERROR_CODE] = "Serve.cfg:global:report_error_code",
  [SSERV_CMD_GLOB_CHANGE_SHOW_DEADLINE] = "Serve.cfg:global:show_deadline",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_PRINTING] = "Serve.cfg:global:enable_printing",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_BANNER_PAGE] = "Serve.cfg:global:disable_banner_page",
  [SSERV_CMD_GLOB_CHANGE_PRINTOUT_USES_LOGIN] = "Serve.cfg:global:printout_uses_login",
  [SSERV_CMD_GLOB_CHANGE_PRUNE_EMPTY_USERS] = "Serve.cfg:global:prune_empty_users",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_FULL_ARCHIVE] = "Serve.cfg:global:enable_full_archive",
  [SSERV_CMD_GLOB_CHANGE_ADVANCED_LAYOUT] = "Serve.cfg:global:advanced_layout",
  [SSERV_CMD_GLOB_CHANGE_UUID_RUN_STORE] = "Serve.cfg:global:uuid_run_store",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_32BIT_CHECKERS] = "Serve.cfg:global:enable_32bit_checkers",
  [SSERV_CMD_GLOB_CHANGE_IGNORE_BOM] = "Serve.cfg:global:ignore_bom",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_USER_DATABASE] = "Serve.cfg:global:disable_user_database",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_MAX_STACK_SIZE] = "Serve.cfg:global:enable_max_stack_size",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_REFRESH] = "Serve.cfg:global:disable_auto_refresh",
  [SSERV_CMD_GLOB_CHANGE_ALWAYS_SHOW_PROBLEMS] = "Serve.cfg:global:always_show_problems",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_USER_STANDINGS] = "Serve.cfg:global:disable_user_standings",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_LANGUAGE] = "Serve.cfg:global:disable_language",
  [SSERV_CMD_GLOB_CHANGE_PROBLEM_NAVIGATION] = "Serve.cfg:global:problem_navigation",
  [SSERV_CMD_GLOB_CHANGE_VERTICAL_NAVIGATION] = "Serve.cfg:global:vertical_navigation",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_START] = "Serve.cfg:global:disable_virtual_start",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_AUTO_JUDGE] = "Serve.cfg:global:disable_virtual_auto_judge",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_AUTO_PRINT_PROTOCOL] = "Serve.cfg:global:enable_auto_print_protocol",
  [SSERV_CMD_GLOB_CHANGE_NOTIFY_CLAR_REPLY] = "Serve.cfg:global:notify_clar_reply",
  [SSERV_CMD_GLOB_CHANGE_NOTIFY_STATUS_CHANGE] = "Serve.cfg:global:notify_status_change",
  [SSERV_CMD_GLOB_CHANGE_TEST_DIR] = "Serve.cfg:global:test_dir",
  [SSERV_CMD_GLOB_CHANGE_CORR_DIR] = "Serve.cfg:global:corr_dir",
  [SSERV_CMD_GLOB_CHANGE_INFO_DIR] = "Serve.cfg:global:info_dir",
  [SSERV_CMD_GLOB_CHANGE_TGZ_DIR] = "Serve.cfg:global:tgz_dir",
  [SSERV_CMD_GLOB_CHANGE_CHECKER_DIR] = "Serve.cfg:global:checker_dir",
  [SSERV_CMD_GLOB_CHANGE_STATEMENT_DIR] = "Serve.cfg:global:statement_dir",
  [SSERV_CMD_GLOB_CHANGE_PLUGIN_DIR] = "Serve.cfg:global:plugin_dir",
  [SSERV_CMD_GLOB_CHANGE_DESCRIPTION_FILE] = "Serve.cfg:global:description_file",
  [SSERV_CMD_GLOB_CHANGE_CONTEST_START_CMD] = "Serve.cfg:global:contest_start_cmd",
  [SSERV_CMD_GLOB_CHANGE_CONTEST_STOP_CMD] = "Serve.cfg:global:contest_stop_cmd",
  [SSERV_CMD_GLOB_CHANGE_MAX_RUN_SIZE] = "Serve.cfg:global:max_run_size",
  [SSERV_CMD_GLOB_CHANGE_MAX_RUN_TOTAL] = "Serve.cfg:global:max_run_total",
  [SSERV_CMD_GLOB_CHANGE_MAX_RUN_NUM] = "Serve.cfg:global:max_run_num",
  [SSERV_CMD_GLOB_CHANGE_MAX_CLAR_SIZE] = "Serve.cfg:global:max_clar_size",
  [SSERV_CMD_GLOB_CHANGE_MAX_CLAR_TOTAL] = "Serve.cfg:global:max_clar_total",
  [SSERV_CMD_GLOB_CHANGE_MAX_CLAR_NUM] = "Serve.cfg:global:max_clar_num",
  [SSERV_CMD_GLOB_CHANGE_TEAM_PAGE_QUOTA] = "Serve.cfg:global:team_page_quota",
  [SSERV_CMD_GLOB_CHANGE_TEAM_INFO_URL] = "Serve.cfg:global:team_info_url",
  [SSERV_CMD_GLOB_CHANGE_PROB_INFO_URL] = "Serve.cfg:global:prob_info_url",
  [SSERV_CMD_GLOB_CHANGE_STAND_FILE_NAME] = "Serve.cfg:global:stand_file_name",
  [SSERV_CMD_GLOB_CHANGE_USERS_ON_PAGE] = "Serve.cfg:global:users_on_page",
  [SSERV_CMD_GLOB_CHANGE_STAND_HEADER_FILE] = "Serve.cfg:global:stand_header_file",
  [SSERV_CMD_GLOB_CHANGE_STAND_FOOTER_FILE] = "Serve.cfg:global:stand_footer_file",
  [SSERV_CMD_GLOB_CHANGE_STAND_SYMLINK_DIR] = "Serve.cfg:global:stand_symlink_dir",
  [SSERV_CMD_GLOB_CHANGE_STAND_IGNORE_AFTER] = "Serve.cfg:global:stand_ignore_after",
  [SSERV_CMD_GLOB_CHANGE_APPEAL_DEADLINE] = "Serve.cfg:global:appeal_deadline",
  [SSERV_CMD_GLOB_CHANGE_CONTEST_FINISH_TIME] = "Serve.cfg:global:contest_finish_time",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_STAND2] = "Serve.cfg:global:enable_stand2",
  [SSERV_CMD_GLOB_CHANGE_STAND2_FILE_NAME] = "Serve.cfg:global:stand2_file_name",
  [SSERV_CMD_GLOB_CHANGE_STAND2_HEADER_FILE] = "Serve.cfg:global:stand2_header_file",
  [SSERV_CMD_GLOB_CHANGE_STAND2_FOOTER_FILE] = "Serve.cfg:global:stand2_footer_file",
  [SSERV_CMD_GLOB_CHANGE_STAND2_SYMLINK_DIR] = "Serve.cfg:global:stand2_symlink_dir",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_PLOG] = "Serve.cfg:global:enable_plog",
  [SSERV_CMD_GLOB_CHANGE_PLOG_FILE_NAME] = "Serve.cfg:global:plog_file_name",
  [SSERV_CMD_GLOB_CHANGE_PLOG_HEADER_FILE] = "Serve.cfg:global:plog_header_file",
  [SSERV_CMD_GLOB_CHANGE_PLOG_FOOTER_FILE] = "Serve.cfg:global:plog_footer_file",
  [SSERV_CMD_GLOB_CHANGE_PLOG_SYMLINK_DIR] = "Serve.cfg:global:plog_symlink_dir",
  [SSERV_CMD_GLOB_CHANGE_PLOG_UPDATE_TIME] = "Serve.cfg:global:plog_update_time",
  [SSERV_CMD_GLOB_CHANGE_EXTERNAL_XML_UPDATE_TIME] = "Serve.cfg:global:external_xml_update_time",
  [SSERV_CMD_GLOB_CHANGE_INTERNAL_XML_UPDATE_TIME] = "Serve.cfg:global:internal_xml_update_time",
  [SSERV_CMD_GLOB_CHANGE_STAND_FANCY_STYLE] = "Serve.cfg:global:stand_fancy_style",
  [SSERV_CMD_GLOB_CHANGE_STAND_TABLE_ATTR] = "Serve.cfg:global:stand_table_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_PLACE_ATTR] = "Serve.cfg:global:stand_place_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_TEAM_ATTR] = "Serve.cfg:global:stand_team_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_PROB_ATTR] = "Serve.cfg:global:stand_prob_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_SOLVED_ATTR] = "Serve.cfg:global:stand_solved_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_SCORE_ATTR] = "Serve.cfg:global:stand_score_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_PENALTY_ATTR] = "Serve.cfg:global:stand_penalty_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_USE_LOGIN] = "Serve.cfg:global:stand_use_login",
  [SSERV_CMD_GLOB_CHANGE_STAND_SHOW_OK_TIME] = "Serve.cfg:global:stand_show_ok_time",
  [SSERV_CMD_GLOB_CHANGE_STAND_SHOW_ATT_NUM] = "Serve.cfg:global:stand_show_att_num",
  [SSERV_CMD_GLOB_CHANGE_STAND_SORT_BY_SOLVED] = "Serve.cfg:global:stand_sort_by_solved",
  [SSERV_CMD_GLOB_CHANGE_IGNORE_SUCCESS_TIME] = "Serve.cfg:global:ignore_success_time",
  [SSERV_CMD_GLOB_CHANGE_STAND_COLLATE_NAME] = "Serve.cfg:global:stand_collate_name",
  [SSERV_CMD_GLOB_CHANGE_STAND_ENABLE_PENALTY] = "Serve.cfg:global:stand_enable_penalty",
  [SSERV_CMD_GLOB_CHANGE_STAND_TIME_ATTR] = "Serve.cfg:global:stand_time_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_SUCCESS_ATTR] = "Serve.cfg:global:stand_success_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_FAIL_ATTR] = "Serve.cfg:global:stand_fail_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_TRANS_ATTR] = "Serve.cfg:global:stand_trans_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_DISQ_ATTR] = "Serve.cfg:global:stand_disq_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_SELF_ROW_ATTR] = "Serve.cfg:global:stand_self_row_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_V_ROW_ATTR] = "Serve.cfg:global:stand_v_row_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_R_ROW_ATTR] = "Serve.cfg:global:stand_r_row_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_U_ROW_ATTR] = "Serve.cfg:global:stand_u_row_attr",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_EXTRA_COL] = "Serve.cfg:global:enable_extra_col",
  [SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_FORMAT] = "Serve.cfg:global:stand_extra_format",
  [SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_LEGEND] = "Serve.cfg:global:stand_extra_legend",
  [SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_ATTR] = "Serve.cfg:global:stand_extra_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER] = "Serve.cfg:global:stand_show_warn_number",
  [SSERV_CMD_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR] = "Serve.cfg:global:stand_warn_number_attr",
  [SSERV_CMD_GLOB_CHANGE_SLEEP_TIME] = "Serve.cfg:global:sleep_time",
  [SSERV_CMD_GLOB_CHANGE_SERVE_SLEEP_TIME] = "Serve.cfg:global:serve_sleep_time",
  [SSERV_CMD_GLOB_CHANGE_AUTOUPDATE_STANDINGS] = "Serve.cfg:global:autoupdate_standings",
  [SSERV_CMD_GLOB_CHANGE_USE_AC_NOT_OK] = "Serve.cfg:global:use_ac_not_ok",
  [SSERV_CMD_GLOB_CHANGE_ROUNDING_MODE] = "Serve.cfg:global:rounding_mode",
  [SSERV_CMD_GLOB_CHANGE_MAX_FILE_LENGTH] = "Serve.cfg:global:max_file_length",
  [SSERV_CMD_GLOB_CHANGE_MAX_LINE_LENGTH] = "Serve.cfg:global:max_line_length",
  [SSERV_CMD_GLOB_CHANGE_INACTIVITY_TIMEOUT] = "Serve.cfg:global:inactivity_timeout",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_TESTING] = "Serve.cfg:global:disable_auto_testing",
  [SSERV_CMD_GLOB_CHANGE_DISABLE_TESTING] = "Serve.cfg:global:disable_testing",
  [SSERV_CMD_GLOB_CHANGE_CR_SERIALIZATION_KEY] = "Serve.cfg:global:cr_serialization_key",
  [SSERV_CMD_GLOB_CHANGE_SHOW_ASTR_TIME] = "Serve.cfg:global:show_astr_time",
  [SSERV_CMD_GLOB_CHANGE_MEMOIZE_USER_RESULTS] = "Serve.cfg:global:memoize_user_results",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_CONTINUE] = "Serve.cfg:global:enable_continue",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_REPORT_UPLOAD] = "Serve.cfg:global:enable_report_upload",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_RUNLOG_MERGE] = "Serve.cfg:global:enable_runlog_merge",
  [SSERV_CMD_GLOB_CHANGE_USE_COMPILATION_SERVER] = "Serve.cfg:global:use_compilation_server",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_WIN32_LANGUAGES] = "Serve.cfg:global:enable_win32_languages",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_L10N] = "Serve.cfg:global:enable_l10n",
  [SSERV_CMD_GLOB_CHANGE_CHARSET] = "Serve.cfg:global:charset",
  [SSERV_CMD_GLOB_CHANGE_STANDINGS_CHARSET] = "Serve.cfg:global:standings_charset",
  [SSERV_CMD_GLOB_CHANGE_STAND2_CHARSET] = "Serve.cfg:global:stand2_charset",
  [SSERV_CMD_GLOB_CHANGE_PLOG_CHARSET] = "Serve.cfg:global:plog_charset",
  [SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME] = "Serve.cfg:global:team_download_time",
  [SSERV_CMD_GLOB_CHANGE_CPU_BOGOMIPS] = "Serve.cfg:global:cpu_bogomips",
  [SSERV_CMD_GLOB_CHANGE_SECURE_RUN] = "Serve.cfg:global:secure_run",
  [SSERV_CMD_GLOB_CHANGE_DETECT_VIOLATIONS] = "Serve.cfg:global:detect_violations",
  [SSERV_CMD_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR] = "Serve.cfg:global:enable_memory_limit_error",
  [SSERV_CMD_GLOB_CHANGE_SEPARATE_USER_SCORE] = "Serve.cfg:global:separate_user_score",
  [SSERV_CMD_GLOB_CHANGE_STAND_ROW_ATTR] = "Serve.cfg:global:stand_row_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR] = "Serve.cfg:global:stand_page_table_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_CUR_ATTR] = "Serve.cfg:global:stand_page_cur_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_ROW_ATTR] = "Serve.cfg:global:stand_page_row_attr",
  [SSERV_CMD_GLOB_CHANGE_STAND_PAGE_COL_ATTR] = "Serve.cfg:global:stand_page_col_attr",
  [SSERV_CMD_GLOB_CHANGE_LOAD_USER_GROUP] = "Serve.cfg:global:load_user_group",
  [SSERV_CMD_GLOB_CHANGE_CLARDB_PLUGIN] = "Serve.cfg:global:clardb_plugin",
  [SSERV_CMD_GLOB_CHANGE_RUNDB_PLUGIN] = "Serve.cfg:global:rundb_plugin",
  [SSERV_CMD_GLOB_CHANGE_XUSER_PLUGIN] = "Serve.cfg:global:xuser_plugin",
  [SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_VM_SIZE] = "Serve.cfg:global:compile_max_vm_size",
  [SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_STACK_SIZE] = "Serve.cfg:global:compile_max_stack_size",
  [SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_FILE_SIZE] = "Serve.cfg:global:compile_max_file_size",

  [SSERV_CMD_LANG_CHANGE_DISABLED] = "Serve.cfg:language:disabled",
  [SSERV_CMD_LANG_CHANGE_INSECURE] = "Serve.cfg:language:insecure",
  [SSERV_CMD_LANG_CHANGE_LONG_NAME] = "Serve.cfg:language:long_name",
  [SSERV_CMD_LANG_CHANGE_EXTID] = "Serve.cfg:language:extid",
  [SSERV_CMD_LANG_CHANGE_DISABLE_SECURITY] = "Serve.cfg:language:disable_security",
  [SSERV_CMD_LANG_CHANGE_DISABLE_AUTO_TESTING] = "Serve.cfg:language:disable_auto_testing",
  [SSERV_CMD_LANG_CHANGE_DISABLE_TESTING] = "Serve.cfg:language:disable_testing",
  [SSERV_CMD_LANG_CHANGE_BINARY] = "Serve.cfg:language:binary",
  [SSERV_CMD_LANG_CHANGE_IS_DOS] = "Serve.cfg:language:is_dos",
  [SSERV_CMD_LANG_CHANGE_MAX_VM_SIZE] = "Serve.cfg:language:max_vm_size",
  [SSERV_CMD_LANG_CHANGE_MAX_STACK_SIZE] = "Serve.cfg:language:max_stack_size",
  [SSERV_CMD_LANG_CHANGE_MAX_FILE_SIZE] = "Serve.cfg:language:max_file_size",
  [SSERV_CMD_LANG_CHANGE_CONTENT_TYPE] = "Serve.cfg:language:content_type",
  [SSERV_CMD_LANG_CHANGE_OPTS] = "Serve.cfg:language:compiler_options",
  [SSERV_CMD_LANG_CHANGE_STYLE_CHECKER_CMD] = "Serve.cfg:language:style_checker_cmd",
  [SSERV_CMD_LANG_CHANGE_STYLE_CHECKER_ENV] = "Serve.cfg:language:style_checker_env",

  [SSERV_CMD_PROB_CHANGE_SHORT_NAME] = "Serve.cfg:problem:short_name",
  [SSERV_CMD_PROB_CHANGE_LONG_NAME] = "Serve.cfg:problem:long_name",
  [SSERV_CMD_PROB_CHANGE_STAND_NAME] = "Serve.cfg:problem:stand_name",
  [SSERV_CMD_PROB_CHANGE_STAND_COLUMN] = "Serve.cfg:problem:stand_column",
  [SSERV_CMD_PROB_CHANGE_INTERNAL_NAME] = "Serve.cfg:problem:internal_name",
  [SSERV_CMD_PROB_CHANGE_SUPER] = "Serve.cfg:problem:super",
  [SSERV_CMD_PROB_CHANGE_TYPE] = "Serve.cfg:problem:type",
  [SSERV_CMD_PROB_CHANGE_SCORING_CHECKER] = "Serve.cfg:problem:scoring_checker",
  [SSERV_CMD_PROB_CHANGE_INTERACTIVE_VALUER] = "Serve.cfg:problem:interactive_valuer",
  [SSERV_CMD_PROB_CHANGE_DISABLE_PE] = "Serve.cfg:problem:disable_pe",
  [SSERV_CMD_PROB_CHANGE_DISABLE_WTL] = "Serve.cfg:problem:disable_wtl",
  [SSERV_CMD_PROB_CHANGE_MANUAL_CHECKING] = "Serve.cfg:problem:manual_checking",
  [SSERV_CMD_PROB_CHANGE_EXAMINATOR_NUM] = "Serve.cfg:problem:examinator_num",
  [SSERV_CMD_PROB_CHANGE_CHECK_PRESENTATION] = "Serve.cfg:problem:check_presentation",
  [SSERV_CMD_PROB_CHANGE_USE_STDIN] = "Serve.cfg:problem:use_stdin",
  [SSERV_CMD_PROB_CHANGE_USE_STDOUT] = "Serve.cfg:problem:use_stdout",
  [SSERV_CMD_PROB_CHANGE_COMBINED_STDIN] = "Serve.cfg:problem:combined_stdin",
  [SSERV_CMD_PROB_CHANGE_COMBINED_STDOUT] = "Serve.cfg:problem:combined_stdout",
  [SSERV_CMD_PROB_CHANGE_BINARY_INPUT] = "Serve.cfg:problem:binary_input",
  [SSERV_CMD_PROB_CHANGE_BINARY] = "Serve.cfg:problem:binary",
  [SSERV_CMD_PROB_CHANGE_IGNORE_EXIT_CODE] = "Serve.cfg:problem:ignore_exit_code",
  [SSERV_CMD_PROB_CHANGE_OLYMPIAD_MODE] = "Serve.cfg:problem:olympiad_mode",
  [SSERV_CMD_PROB_CHANGE_SCORE_LATEST] = "Serve.cfg:problem:score_latest",
  [SSERV_CMD_PROB_CHANGE_SCORE_LATEST_OR_UNMARKED] = "Serve.cfg:problem:score_latest_or_unmarked",
  [SSERV_CMD_PROB_CHANGE_SCORE_LATEST_MARKED] = "Serve.cfg:problem:score_latest_marked",
  [SSERV_CMD_PROB_CHANGE_SCORE_TOKENIZED] = "Serve.cfg:problem:score_tokenized",
  [SSERV_CMD_PROB_CHANGE_TIME_LIMIT] = "Serve.cfg:problem:time_limit",
  [SSERV_CMD_PROB_CHANGE_TIME_LIMIT_MILLIS] = "Serve.cfg:problem:time_limit_millis",
  [SSERV_CMD_PROB_CHANGE_REAL_TIME_LIMIT] = "Serve.cfg:problem:real_time_limit",
  [SSERV_CMD_PROB_CHANGE_USE_AC_NOT_OK] = "Serve.cfg:problem:use_ac_not_ok",
  [SSERV_CMD_PROB_CHANGE_IGNORE_PREV_AC] = "Serve.cfg:problem:ignore_prev_ac",
  [SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_REP_VIEW] = "Serve.cfg:problem:team_enable_rep_view",
  [SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_CE_VIEW] = "Serve.cfg:problem:team_enable_ce_view",
  [SSERV_CMD_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT] = "Serve.cfg:problem:team_show_judge_report",
  [SSERV_CMD_PROB_CHANGE_SHOW_CHECKER_COMMENT] = "Serve.cfg:problem:show_checker_comment",
  [SSERV_CMD_PROB_CHANGE_IGNORE_COMPILE_ERRORS] = "Serve.cfg:problem:ignore_compile_errors",
  [SSERV_CMD_PROB_CHANGE_DISABLE_USER_SUBMIT] = "Serve.cfg:problem:disable_user_submit",
  [SSERV_CMD_PROB_CHANGE_DISABLE_TAB] = "Serve.cfg:problem:disable_tab",
  [SSERV_CMD_PROB_CHANGE_UNRESTRICTED_STATEMENT] = "Serve.cfg:problem:unrestricted_statement",
  [SSERV_CMD_PROB_CHANGE_HIDE_FILE_NAMES] = "Serve.cfg:problem:hide_file_names",
  [SSERV_CMD_PROB_CHANGE_HIDE_REAL_TIME_LIMIT] = "Serve.cfg:problem:hide_real_time_limit",
  [SSERV_CMD_PROB_CHANGE_ENABLE_TOKENS] = "Serve.cfg:problem:enable_tokens",
  [SSERV_CMD_PROB_CHANGE_TOKENS_FOR_USER_AC] = "Serve.cfg:problem:tokens_for_user_ac",
  [SSERV_CMD_PROB_CHANGE_DISABLE_SUBMIT_AFTER_OK] = "Serve.cfg:problem:disable_submit_after_ok",
  [SSERV_CMD_PROB_CHANGE_DISABLE_SECURITY] = "Serve.cfg:problem:disable_security",
  [SSERV_CMD_PROB_CHANGE_DISABLE_TESTING] = "Serve.cfg:problem:disable_testing",
  [SSERV_CMD_PROB_CHANGE_DISABLE_AUTO_TESTING] = "Serve.cfg:problem:disable_auto_testing",
  [SSERV_CMD_PROB_CHANGE_ENABLE_COMPILATION] = "Serve.cfg:problem:enable_compilation",
  [SSERV_CMD_PROB_CHANGE_FULL_SCORE] = "Serve.cfg:problem:full_score",
  [SSERV_CMD_PROB_CHANGE_FULL_USER_SCORE] = "Serve.cfg:problem:full_user_score",
  [SSERV_CMD_PROB_CHANGE_TEST_SCORE] = "Serve.cfg:problem:test_score",
  [SSERV_CMD_PROB_CHANGE_RUN_PENALTY] = "Serve.cfg:problem:run_penalty",
  [SSERV_CMD_PROB_CHANGE_ACM_RUN_PENALTY] = "Serve.cfg:problem:acm_run_penalty",
  [SSERV_CMD_PROB_CHANGE_MAX_USER_RUN_COUNT] = "Serve.cfg:problem:max_user_run_count",
  [SSERV_CMD_PROB_CHANGE_DISQUALIFIED_PENALTY] = "Serve.cfg:problem:disqualified_penalty",
  [SSERV_CMD_PROB_CHANGE_VARIABLE_FULL_SCORE] = "Serve.cfg:problem:variable_full_score",
  [SSERV_CMD_PROB_CHANGE_TEST_SCORE_LIST] = "Serve.cfg:problem:test_score_list",
  [SSERV_CMD_PROB_CHANGE_TOKENS] = "Serve.cfg:problem:tokens",
  [SSERV_CMD_PROB_CHANGE_UMASK] = "Serve.cfg:problem:umask",
  [SSERV_CMD_PROB_CHANGE_SCORE_TESTS] = "Serve.cfg:problem:score_tests",
  [SSERV_CMD_PROB_CHANGE_TESTS_TO_ACCEPT] = "Serve.cfg:problem:tests_to_accept",
  [SSERV_CMD_PROB_CHANGE_ACCEPT_PARTIAL] = "Serve.cfg:problem:accept_partial",
  [SSERV_CMD_PROB_CHANGE_MIN_TESTS_TO_ACCEPT] = "Serve.cfg:problem:min_tests_to_accept",
  [SSERV_CMD_PROB_CHANGE_HIDDEN] = "Serve.cfg:problem:hidden",
  [SSERV_CMD_PROB_CHANGE_STAND_HIDE_TIME] = "Serve.cfg:problem:stand_hide_time",
  [SSERV_CMD_PROB_CHANGE_ADVANCE_TO_NEXT] = "Serve.cfg:problem:advance_to_next",
  [SSERV_CMD_PROB_CHANGE_DISABLE_CTRL_CHARS] = "Serve.cfg:problem:disable_ctrl_chars",
  [SSERV_CMD_PROB_CHANGE_VALUER_SETS_MARKED] = "Serve.cfg:problem:valuer_sets_marked",
  [SSERV_CMD_PROB_CHANGE_IGNORE_UNMARKED] = "Serve.cfg:problem:ignore_unmarked",
  [SSERV_CMD_PROB_CHANGE_DISABLE_STDERR] = "Serve.cfg:problem:disable_stderr",
  [SSERV_CMD_PROB_CHANGE_ENABLE_PROCESS_GROUP] = "Serve.cfg:problem:enable_process_group",
  [SSERV_CMD_PROB_CHANGE_HIDE_VARIANT] = "Serve.cfg:problem:hide_variant",
  [SSERV_CMD_PROB_CHANGE_AUTOASSIGN_VARIANTS] = "Serve.cfg:problem:autoassign_variants",
  [SSERV_CMD_PROB_CHANGE_ENABLE_TEXT_FORM] = "Serve.cfg:problem:enable_text_form",
  [SSERV_CMD_PROB_CHANGE_STAND_IGNORE_SCORE] = "Serve.cfg:problem:stand_ignore_score",
  [SSERV_CMD_PROB_CHANGE_STAND_LAST_COLUMN] = "Serve.cfg:problem:stand_last_column",
  [SSERV_CMD_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT] = "Serve.cfg:problem:checker_real_time_limit",
  [SSERV_CMD_PROB_CHANGE_INTERACTOR_TIME_LIMIT] = "Serve.cfg:problem:interactor_time_limit",
  [SSERV_CMD_PROB_CHANGE_MAX_VM_SIZE] = "Serve.cfg:problem:max_vm_size",
  [SSERV_CMD_PROB_CHANGE_MAX_STACK_SIZE] = "Serve.cfg:problem:max_stack_size",
  [SSERV_CMD_PROB_CHANGE_MAX_CORE_SIZE] = "Serve.cfg:problem:max_core_size",
  [SSERV_CMD_PROB_CHANGE_MAX_FILE_SIZE] = "Serve.cfg:problem:max_file_size",
  [SSERV_CMD_PROB_CHANGE_MAX_OPEN_FILE_COUNT] = "Serve.cfg:problem:max_open_file_count",
  [SSERV_CMD_PROB_CHANGE_MAX_PROCESS_COUNT] = "Serve.cfg:problem:max_process_count",
  [SSERV_CMD_PROB_CHANGE_INPUT_FILE] = "Serve.cfg:problem:input_file",
  [SSERV_CMD_PROB_CHANGE_OUTPUT_FILE] = "Serve.cfg:problem:output_file",
  [SSERV_CMD_PROB_CHANGE_USE_CORR] = "Serve.cfg:problem:use_corr",
  [SSERV_CMD_PROB_CHANGE_USE_INFO] = "Serve.cfg:problem:use_info",
  [SSERV_CMD_PROB_CHANGE_USE_TGZ] = "Serve.cfg:problem:use_tgz",
  [SSERV_CMD_PROB_CHANGE_TEST_DIR] = "Serve.cfg:problem:test_dir",
  [SSERV_CMD_PROB_CHANGE_CORR_DIR] = "Serve.cfg:problem:corr_dir",
  [SSERV_CMD_PROB_CHANGE_INFO_DIR] = "Serve.cfg:problem:info_dir",
  [SSERV_CMD_PROB_CHANGE_TEST_SFX] = "Serve.cfg:problem:test_sfx",
  [SSERV_CMD_PROB_CHANGE_TEST_PAT] = "Serve.cfg:problem:test_pat",
  [SSERV_CMD_PROB_CHANGE_CORR_SFX] = "Serve.cfg:problem:corr_sfx",
  [SSERV_CMD_PROB_CHANGE_CORR_PAT] = "Serve.cfg:problem:corr_pat",
  [SSERV_CMD_PROB_CHANGE_INFO_SFX] = "Serve.cfg:problem:info_sfx",
  [SSERV_CMD_PROB_CHANGE_INFO_PAT] = "Serve.cfg:problem:info_pat",
  [SSERV_CMD_PROB_CHANGE_TGZ_SFX] = "Serve.cfg:problem:tgz_sfx",
  [SSERV_CMD_PROB_CHANGE_TGZ_PAT] = "Serve.cfg:problem:tgz_pat",
  [SSERV_CMD_PROB_CHANGE_TGZDIR_SFX] = "Serve.cfg:problem:tgzdir_sfx",
  [SSERV_CMD_PROB_CHANGE_TGZDIR_PAT] = "Serve.cfg:problem:tgzdir_pat",
  [SSERV_CMD_PROB_CHANGE_STANDARD_CHECKER] = "Serve.cfg:problem:standard_checker",
  [SSERV_CMD_PROB_CHANGE_SCORE_BONUS] = "Serve.cfg:problem:score_bonus",
  [SSERV_CMD_PROB_CHANGE_OPEN_TESTS] = "Serve.cfg:problem:open_tests",
  [SSERV_CMD_PROB_CHANGE_FINAL_OPEN_TESTS] = "Serve.cfg:problem:final_open_tests",
  [SSERV_CMD_PROB_CHANGE_TOKEN_OPEN_TESTS] = "Serve.cfg:problem:token_open_tests",
  [SSERV_CMD_PROB_CHANGE_LANG_COMPILER_ENV] = "Serve.cfg:problem:lang_compiler_env",
  [SSERV_CMD_PROB_CHANGE_CHECK_CMD] = "Serve.cfg:problem:check_cmd",
  [SSERV_CMD_PROB_CHANGE_CHECKER_ENV] = "Serve.cfg:problem:checker_env",
  [SSERV_CMD_PROB_CHANGE_VALUER_CMD] = "Serve.cfg:problem:valuer_cmd",
  [SSERV_CMD_PROB_CHANGE_VALUER_ENV] = "Serve.cfg:problem:valuer_env",
  [SSERV_CMD_PROB_CHANGE_INTERACTOR_CMD] = "Serve.cfg:problem:interactor_cmd",
  [SSERV_CMD_PROB_CHANGE_INTERACTOR_ENV] = "Serve.cfg:problem:interactor_env",
  [SSERV_CMD_PROB_CHANGE_STYLE_CHECKER_CMD] = "Serve.cfg:problem:style_checker_cmd",
  [SSERV_CMD_PROB_CHANGE_STYLE_CHECKER_ENV] = "Serve.cfg:problem:style_checker_env",
  [SSERV_CMD_PROB_CHANGE_TEST_CHECKER_CMD] = "Serve.cfg:problem:test_checker_cmd",
  [SSERV_CMD_PROB_CHANGE_TEST_CHECKER_ENV] = "Serve.cfg:problem:test_checker_env",
  [SSERV_CMD_PROB_CHANGE_INIT_CMD] = "Serve.cfg:problem:init_cmd",
  [SSERV_CMD_PROB_CHANGE_START_CMD] = "Serve.cfg:problem:start_cmd",
  [SSERV_CMD_PROB_CHANGE_INIT_ENV] = "Serve.cfg:problem:init_env",
  [SSERV_CMD_PROB_CHANGE_START_ENV] = "Serve.cfg:problem:start_env",
  [SSERV_CMD_PROB_CHANGE_SOLUTION_SRC] = "Serve.cfg:problem:solution_src",
  [SSERV_CMD_PROB_CHANGE_SOLUTION_CMD] = "Serve.cfg:problem:solution_cmd",
  [SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ] = "Serve.cfg:problem:lang_time_adj",
  [SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ_MILLIS] = "Serve.cfg:problem:lang_time_adj_millis",
  [SSERV_CMD_PROB_CHANGE_LANG_MAX_VM_SIZE] = "Serve.cfg:problem:lang_max_vm_size",
  [SSERV_CMD_PROB_CHANGE_LANG_MAX_STACK_SIZE] = "Serve.cfg:problem:lang_max_stack_size",
  [SSERV_CMD_PROB_CHANGE_DISABLE_LANGUAGE] = "Serve.cfg:problem:disable_language",
  [SSERV_CMD_PROB_CHANGE_ENABLE_LANGUAGE] = "Serve.cfg:problem:enable_language",
  [SSERV_CMD_PROB_CHANGE_REQUIRE] = "Serve.cfg:problem:require",
  [SSERV_CMD_PROB_CHANGE_PROVIDE_OK] = "Serve.cfg:problem:provide_ok",
  [SSERV_CMD_PROB_CHANGE_TEST_SETS] = "Serve.cfg:problem:test_sets",
  [SSERV_CMD_PROB_CHANGE_SCORE_VIEW] = "Serve.cfg:problem:score_view",
  [SSERV_CMD_PROB_CHANGE_START_DATE] = "Serve.cfg:problem:start_date",
  [SSERV_CMD_PROB_CHANGE_DEADLINE] = "Serve.cfg:problem:deadline",
  [SSERV_CMD_PROB_CHANGE_VARIANT_NUM] = "Serve.cfg:problem:variant_num",
  [SSERV_CMD_PROB_CHANGE_XML_FILE] = "Serve.cfg:problem:xml_file",
  [SSERV_CMD_PROB_CHANGE_ALTERNATIVES_FILE] = "Serve.cfg:problem:alternatives_file",
  [SSERV_CMD_PROB_CHANGE_PLUGIN_FILE] = "Serve.cfg:problem:plugin_file",
  [SSERV_CMD_PROB_CHANGE_STAND_ATTR] = "Serve.cfg:problem:stand_attr",
  [SSERV_CMD_PROB_CHANGE_SOURCE_HEADER] = "Serve.cfg:problem:source_header",
  [SSERV_CMD_PROB_CHANGE_SOURCE_FOOTER] = "Serve.cfg:problem:source_footer",
  [SSERV_CMD_PROB_CHANGE_NORMALIZATION] = "Serve.cfg:problem:normalization",
};

void
print_help_url(FILE *f, int action)
{
  const unsigned char *help_url = 0;

  if (action > 0 && action < SSERV_CMD_LAST) {
    help_url = super_serve_help_urls[action];
  }
  if (help_url) {
    fprintf(f, "<td><a target=\"_blank\" href=\"http://www.ejudge.ru/wiki/index.php/%s\">%s</a></td>",
            help_url, "Help");
  } else {
    fprintf(f, "<td>&nbsp;</td>");
  }
}

#define GLOB_SET_STRING(f) p_str = global->f; str_size = sizeof(global->f); goto handle_string
#define GLOB_CLEAR_STRING(f) global->f[0] = 0; return 0

#define SIZE_G (1024 * 1024 * 1024)
#define SIZE_M (1024 * 1024)
#define SIZE_K (1024)

int
super_html_global_param(struct sid_state *sstate, int cmd,
                        const struct ejudge_cfg *config,
                        int param1, const unsigned char *param2,
                        int param3, int param4)
{
  struct section_global_data *global = sstate->global;
  int hh, mm, n, val, default_val;
  unsigned char *s;
  int *p_int;
  unsigned char *p_str;
  size_t str_size;
  char **tmp_env = 0;
  size_t *p_size, zval;

  if (!global) return -SSERV_ERR_CONTEST_NOT_EDITED;

  switch (cmd) {
  case SSERV_CMD_GLOB_CHANGE_DURATION:
    if (sscanf(param2, "%d:%d%n", &hh, &mm, &n) == 2 && !param2[n]) {
      if (hh < 0 || hh >= 1000000) return -SSERV_ERR_INVALID_PARAMETER;
      if (mm < 0 || mm >= 60) return -SSERV_ERR_INVALID_PARAMETER;
      global->contest_time = hh * 60 + mm;
      return 0;
    }
    if (sscanf(param2, "%d%n", &mm, &n) != 1 || param2[n] ||
        mm < 0 || mm >= 1000000)
      return -SSERV_ERR_INVALID_PARAMETER;
    global->contest_time = mm;
    if (global->contest_time > global->board_fog_time)
      global->board_fog_time = global->contest_time;
    if (!global->contest_time) global->board_unfog_time = 0;
    return 0;

  case SSERV_CMD_GLOB_UNLIMITED_DURATION:
    global->contest_time = 0;
    global->board_fog_time = 0;
    global->board_unfog_time = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_TYPE:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > SCORE_TOTAL + 2)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < SCORE_TOTAL) {
      global->score_system = val;
      global->is_virtual = 0;
    } else {
      if (val == SCORE_TOTAL) global->score_system = SCORE_ACM;
      else global->score_system = SCORE_OLYMPIAD;
      global->is_virtual = 1;
    }
    return 0;

  case SSERV_CMD_GLOB_CHANGE_FOG_TIME:
    if (sscanf(param2, "%d:%d%n", &hh, &mm, &n) == 2 && !param2[n]) {
      if (hh < 0 || hh >= 1000000) return -SSERV_ERR_INVALID_PARAMETER;
      if (mm < 0 || mm >= 60) return -SSERV_ERR_INVALID_PARAMETER;
      mm = hh * 60 + mm;
    } else if (sscanf(param2, "%d%n", &mm, &n) != 1 || param2[n] ||
               mm < 0 || mm >= 1000000) {
      return -SSERV_ERR_INVALID_PARAMETER;
    }
    if (mm > global->contest_time) mm = global->contest_time;
    global->board_fog_time = mm;
    if (!global->board_fog_time) global->board_unfog_time = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_UNFOG_TIME:
    if (sscanf(param2, "%d:%d%n", &hh, &mm, &n) == 2 && !param2[n]) {
      if (hh < 0 || hh >= 1000000) return -SSERV_ERR_INVALID_PARAMETER;
      if (mm < 0 || mm >= 60) return -SSERV_ERR_INVALID_PARAMETER;
      mm = hh * 60 + mm;
    } else if (sscanf(param2, "%d%n", &mm, &n) != 1 || param2[n] ||
               mm < 0 || mm >= 1000000) {
      return -SSERV_ERR_INVALID_PARAMETER;
    }
    if (!global->contest_time) mm = 0;
    if (!global->board_fog_time) mm = 0;
    global->board_unfog_time = mm;
    return 0;

  case SSERV_CMD_GLOB_DISABLE_FOG:
    global->board_fog_time = 0;
    global->board_unfog_time = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_LOCALE:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    switch (val) {
    case 0: s = "en"; break;
    case 1: s = "ru"; break;
    default:
      abort();
    }
    snprintf(global->standings_locale, sizeof(global->standings_locale), "%s", s);
    return 0;

  case SSERV_CMD_GLOB_CHANGE_CHECKER_LOCALE:
    xfree(global->checker_locale);
    global->checker_locale = xstrdup(param2);
    return 0;

  case SSERV_CMD_GLOB_CLEAR_CHECKER_LOCALE:
    xfree(global->checker_locale); global->checker_locale = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_TOKENS:
    xfree(global->tokens);
    global->tokens = xstrdup(param2);
    return 0;

  case SSERV_CMD_GLOB_CLEAR_TOKENS:
    xfree(global->tokens); global->tokens = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_SRC_VIEW:
    p_int = &global->team_enable_src_view;

  handle_boolean:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_REP_VIEW:
    p_int = &global->team_enable_rep_view;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_CE_VIEW:
    p_int = &global->team_enable_ce_view;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_JUDGE_REPORT:
    p_int = &global->team_show_judge_report;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_CLARS:
    p_int = &global->disable_clars;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_TEAM_CLARS:
    p_int = &global->disable_team_clars;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_EOLN_SELECT:
    p_int = &global->enable_eoln_select;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_SUBMIT_AFTER_OK:
    p_int = &global->disable_submit_after_ok;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_IGNORE_COMPILE_ERRORS:
    p_int = &global->ignore_compile_errors;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_FAILED_TEST_VIEW:
    p_int = &global->disable_failed_test_view;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_IGNORE_DUPLICATED_RUNS:
    p_int = &global->ignore_duplicated_runs;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_REPORT_ERROR_CODE:
    p_int = &global->report_error_code;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_SHOW_DEADLINE:
    p_int = &global->show_deadline;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_PRINTING:
    p_int = &global->enable_printing;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_BANNER_PAGE:
    p_int = &global->disable_banner_page;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_PRINTOUT_USES_LOGIN:
    p_int = &global->printout_uses_login;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_PRUNE_EMPTY_USERS:
    p_int = &global->prune_empty_users;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_FULL_ARCHIVE:
    p_int = &global->enable_full_archive;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ADVANCED_LAYOUT:
    p_int = &global->advanced_layout;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_UUID_RUN_STORE:
    p_int = &global->uuid_run_store;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_32BIT_CHECKERS:
    p_int = &global->enable_32bit_checkers;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_IGNORE_BOM:
    p_int = &global->ignore_bom;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_USER_DATABASE:
    p_int = &global->disable_user_database;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_MAX_STACK_SIZE:
    p_int = &global->enable_max_stack_size;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_REFRESH:
    p_int = &global->disable_auto_refresh;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ALWAYS_SHOW_PROBLEMS:
    p_int = &global->always_show_problems;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_USER_STANDINGS:
    p_int = &global->disable_user_standings;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_LANGUAGE:
    p_int = &global->disable_language;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_PROBLEM_NAVIGATION:
    p_int = &global->problem_navigation;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_VERTICAL_NAVIGATION:
    p_int = &global->vertical_navigation;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_START:
    p_int = &global->disable_virtual_start;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_VIRTUAL_AUTO_JUDGE:
    p_int = &global->disable_virtual_auto_judge;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_AUTO_PRINT_PROTOCOL:
    p_int = &global->enable_auto_print_protocol;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_NOTIFY_CLAR_REPLY:
    p_int = &global->notify_clar_reply;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_NOTIFY_STATUS_CHANGE:
    p_int = &global->notify_status_change;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_TEST_DIR:
    GLOB_SET_STRING(test_dir);

  handle_string:
    snprintf(p_str, str_size, "%s", param2);
    return 0;
    
  case SSERV_CMD_GLOB_CLEAR_TEST_DIR:
    GLOB_CLEAR_STRING(test_dir);

  case SSERV_CMD_GLOB_CHANGE_CORR_DIR:
    GLOB_SET_STRING(corr_dir);

  case SSERV_CMD_GLOB_CLEAR_CORR_DIR:
    GLOB_CLEAR_STRING(corr_dir);

  case SSERV_CMD_GLOB_CHANGE_INFO_DIR:
    GLOB_SET_STRING(info_dir);

  case SSERV_CMD_GLOB_CLEAR_INFO_DIR: 
    GLOB_CLEAR_STRING(info_dir);

  case SSERV_CMD_GLOB_CHANGE_TGZ_DIR:
    GLOB_SET_STRING(tgz_dir);

  case SSERV_CMD_GLOB_CLEAR_TGZ_DIR: 
    GLOB_CLEAR_STRING(tgz_dir);

  case SSERV_CMD_GLOB_CHANGE_CHECKER_DIR:
    GLOB_SET_STRING(checker_dir);

  case SSERV_CMD_GLOB_CLEAR_CHECKER_DIR:
    GLOB_CLEAR_STRING(checker_dir);

  case SSERV_CMD_GLOB_CHANGE_STATEMENT_DIR:
    GLOB_SET_STRING(statement_dir);

  case SSERV_CMD_GLOB_CLEAR_STATEMENT_DIR:
    GLOB_CLEAR_STRING(statement_dir);

  case SSERV_CMD_GLOB_CHANGE_PLUGIN_DIR:
    GLOB_SET_STRING(plugin_dir);

  case SSERV_CMD_GLOB_CLEAR_PLUGIN_DIR:
    GLOB_CLEAR_STRING(plugin_dir);

  case SSERV_CMD_GLOB_CHANGE_DESCRIPTION_FILE:
    GLOB_SET_STRING(description_file);

  case SSERV_CMD_GLOB_CLEAR_DESCRIPTION_FILE:
    GLOB_CLEAR_STRING(description_file);

  case SSERV_CMD_GLOB_CHANGE_CONTEST_START_CMD:
    GLOB_SET_STRING(contest_start_cmd);

  case SSERV_CMD_GLOB_CLEAR_CONTEST_START_CMD:
    GLOB_CLEAR_STRING(contest_start_cmd);

  case SSERV_CMD_GLOB_CHANGE_CONTEST_STOP_CMD:
    xfree(global->contest_stop_cmd);
    global->contest_stop_cmd = xstrdup(param2);
    break;

  case SSERV_CMD_GLOB_CLEAR_CONTEST_STOP_CMD:
    xfree(global->contest_stop_cmd);
    global->contest_stop_cmd = 0;
    break;

  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_SIZE:
    p_int = &global->max_run_size;
    goto handle_size;

  handle_size:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || val < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (param2[n] == 'k' || param2[n] == 'K') {
      val *= SIZE_K;
      n++;
    } else if (param2[n] == 'm' || param2[n] == 'M') {
      val *= SIZE_M;
      n++;
    }
    if (param2[n]) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_TOTAL:
    p_int = &global->max_run_total;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_MAX_RUN_NUM:
    p_int = &global->max_run_num;

  handle_int:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_SIZE:
    p_int = &global->max_clar_size;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_TOTAL:
    p_int = &global->max_clar_total;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_MAX_CLAR_NUM:
    p_int = &global->max_clar_num;
    goto handle_int;

  case SSERV_CMD_GLOB_CHANGE_TEAM_PAGE_QUOTA:
    p_int = &global->team_page_quota;
    goto handle_int;

  case SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_VM_SIZE:
    p_size = &global->compile_max_vm_size;

  handle_size_t:
    zval = 0;
    if (size_str_to_size_t(param2, &zval) < 0) return -SSERV_ERR_INVALID_PARAMETER;
    *p_size = zval;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_STACK_SIZE:
    p_size = &global->compile_max_stack_size;
    goto handle_size_t;

  case SSERV_CMD_GLOB_CHANGE_COMPILE_MAX_FILE_SIZE:
    p_size = &global->compile_max_file_size;
    goto handle_size_t;

  case SSERV_CMD_GLOB_CHANGE_TEAM_INFO_URL:
    GLOB_SET_STRING(team_info_url);

  case SSERV_CMD_GLOB_CLEAR_TEAM_INFO_URL:
    GLOB_CLEAR_STRING(team_info_url);

  case SSERV_CMD_GLOB_CHANGE_PROB_INFO_URL:
    GLOB_SET_STRING(prob_info_url);

  case SSERV_CMD_GLOB_CLEAR_PROB_INFO_URL:
    GLOB_CLEAR_STRING(prob_info_url);

  case SSERV_CMD_GLOB_CHANGE_STAND_FILE_NAME:
    GLOB_SET_STRING(standings_file_name);

  case SSERV_CMD_GLOB_CLEAR_STAND_FILE_NAME:
    GLOB_CLEAR_STRING(standings_file_name);

  case SSERV_CMD_GLOB_CHANGE_USERS_ON_PAGE:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val <= 0) val = 0;
    global->users_on_page = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_HEADER_FILE:
    GLOB_SET_STRING(stand_header_file);

  case SSERV_CMD_GLOB_CLEAR_STAND_HEADER_FILE:
    GLOB_CLEAR_STRING(stand_header_file);

  case SSERV_CMD_GLOB_CHANGE_STAND_FOOTER_FILE:
    GLOB_SET_STRING(stand_footer_file);

  case SSERV_CMD_GLOB_CLEAR_STAND_FOOTER_FILE:
    GLOB_CLEAR_STRING(stand_footer_file);

  case SSERV_CMD_GLOB_CHANGE_STAND_SYMLINK_DIR:
    GLOB_SET_STRING(stand_symlink_dir);

  case SSERV_CMD_GLOB_CLEAR_STAND_SYMLINK_DIR:
    GLOB_CLEAR_STRING(stand_symlink_dir);

  case SSERV_CMD_GLOB_CHANGE_STAND_IGNORE_AFTER:
    if (xml_parse_date(NULL, "", 0, 0, param2, &global->stand_ignore_after) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_STAND_IGNORE_AFTER:
    global->stand_ignore_after = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_APPEAL_DEADLINE:
    if (xml_parse_date(NULL, "", 0, 0, param2, &global->appeal_deadline) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_APPEAL_DEADLINE:
    global->appeal_deadline = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_CONTEST_FINISH_TIME:
    if (xml_parse_date(NULL, "", 0, 0, param2, &global->contest_finish_time) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_CONTEST_FINISH_TIME:
    global->contest_finish_time = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_STAND2:
    p_int = &sstate->enable_stand2;
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    if (val && !global->stand2_file_name[0])
      strcpy(global->stand2_file_name, "standings2.html");
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND2_FILE_NAME:
    GLOB_SET_STRING(stand2_file_name);

  case SSERV_CMD_GLOB_CLEAR_STAND2_FILE_NAME:
    GLOB_CLEAR_STRING(stand2_file_name);

  case SSERV_CMD_GLOB_CHANGE_STAND2_HEADER_FILE:
    GLOB_SET_STRING(stand2_header_file);

  case SSERV_CMD_GLOB_CLEAR_STAND2_HEADER_FILE:
    GLOB_CLEAR_STRING(stand2_header_file);

  case SSERV_CMD_GLOB_CHANGE_STAND2_FOOTER_FILE:
    GLOB_SET_STRING(stand2_footer_file);

  case SSERV_CMD_GLOB_CLEAR_STAND2_FOOTER_FILE:
    GLOB_CLEAR_STRING(stand2_footer_file);

  case SSERV_CMD_GLOB_CHANGE_STAND2_SYMLINK_DIR:
    GLOB_SET_STRING(stand2_symlink_dir);

  case SSERV_CMD_GLOB_CLEAR_STAND2_SYMLINK_DIR:
    GLOB_CLEAR_STRING(stand2_symlink_dir);

  case SSERV_CMD_GLOB_CHANGE_ENABLE_PLOG:
    p_int = &sstate->enable_plog;
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    if (val && !global->plog_file_name[0])
      strcpy(global->plog_file_name, "plog.html");
    return 0;

  case SSERV_CMD_GLOB_CHANGE_PLOG_FILE_NAME:
    GLOB_SET_STRING(plog_file_name);

  case SSERV_CMD_GLOB_CLEAR_PLOG_FILE_NAME:
    GLOB_CLEAR_STRING(plog_file_name);

  case SSERV_CMD_GLOB_CHANGE_PLOG_HEADER_FILE:
    GLOB_SET_STRING(plog_header_file);

  case SSERV_CMD_GLOB_CLEAR_PLOG_HEADER_FILE:
    GLOB_CLEAR_STRING(plog_header_file);

  case SSERV_CMD_GLOB_CHANGE_PLOG_FOOTER_FILE:
    GLOB_SET_STRING(plog_footer_file);

  case SSERV_CMD_GLOB_CLEAR_PLOG_FOOTER_FILE:
    GLOB_CLEAR_STRING(plog_footer_file);

  case SSERV_CMD_GLOB_CHANGE_PLOG_SYMLINK_DIR:
    GLOB_SET_STRING(plog_symlink_dir);

  case SSERV_CMD_GLOB_CLEAR_PLOG_SYMLINK_DIR:
    GLOB_CLEAR_STRING(plog_symlink_dir);

  case SSERV_CMD_GLOB_CHANGE_PLOG_UPDATE_TIME:
    p_int = &global->plog_update_time;
    goto handle_int;

  case SSERV_CMD_GLOB_CHANGE_EXTERNAL_XML_UPDATE_TIME:
    p_int = &global->external_xml_update_time;
    goto handle_int;
  case SSERV_CMD_GLOB_CHANGE_INTERNAL_XML_UPDATE_TIME:
    p_int = &global->internal_xml_update_time;
    goto handle_int;

  case SSERV_CMD_GLOB_CHANGE_STAND_FANCY_STYLE:
    p_int = &global->stand_fancy_style;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_TABLE_ATTR:
    GLOB_SET_STRING(stand_table_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_TABLE_ATTR:
    GLOB_CLEAR_STRING(stand_table_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PLACE_ATTR:
    GLOB_SET_STRING(stand_place_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PLACE_ATTR:
    GLOB_CLEAR_STRING(stand_place_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_TEAM_ATTR:
    GLOB_SET_STRING(stand_team_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_TEAM_ATTR:
    GLOB_CLEAR_STRING(stand_team_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PROB_ATTR:
    GLOB_SET_STRING(stand_prob_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PROB_ATTR:
    GLOB_CLEAR_STRING(stand_prob_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SOLVED_ATTR:
    GLOB_SET_STRING(stand_solved_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_SOLVED_ATTR:
    GLOB_CLEAR_STRING(stand_solved_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SCORE_ATTR:
    GLOB_SET_STRING(stand_score_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_SCORE_ATTR:
    GLOB_CLEAR_STRING(stand_score_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PENALTY_ATTR:
    GLOB_SET_STRING(stand_penalty_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PENALTY_ATTR:
    GLOB_CLEAR_STRING(stand_penalty_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_USE_LOGIN:
    p_int = &global->stand_use_login;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_OK_TIME:
    p_int = &global->stand_show_ok_time;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_ATT_NUM:
    p_int = &global->stand_show_att_num;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_SORT_BY_SOLVED:
    p_int = &global->stand_sort_by_solved;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_IGNORE_SUCCESS_TIME:
    p_int = &global->ignore_success_time;
    goto handle_boolean;    

  case SSERV_CMD_GLOB_CHANGE_STAND_COLLATE_NAME:
    p_int = &global->stand_collate_name;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_ENABLE_PENALTY:
    p_int = &global->stand_enable_penalty;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_TIME_ATTR:
    GLOB_SET_STRING(stand_time_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_TIME_ATTR:
    GLOB_CLEAR_STRING(stand_time_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SUCCESS_ATTR:
    GLOB_SET_STRING(stand_success_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_SUCCESS_ATTR:
    GLOB_CLEAR_STRING(stand_success_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_FAIL_ATTR:
    GLOB_SET_STRING(stand_fail_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_FAIL_ATTR:
    GLOB_CLEAR_STRING(stand_fail_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_TRANS_ATTR:
    GLOB_SET_STRING(stand_trans_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_TRANS_ATTR:
    GLOB_CLEAR_STRING(stand_trans_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_DISQ_ATTR:
    GLOB_SET_STRING(stand_disq_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_DISQ_ATTR:
    GLOB_CLEAR_STRING(stand_disq_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SELF_ROW_ATTR:
    GLOB_SET_STRING(stand_self_row_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_SELF_ROW_ATTR:
    GLOB_CLEAR_STRING(stand_self_row_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_V_ROW_ATTR:
    GLOB_SET_STRING(stand_v_row_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_V_ROW_ATTR:
    GLOB_CLEAR_STRING(stand_v_row_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_R_ROW_ATTR:
    GLOB_SET_STRING(stand_r_row_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_R_ROW_ATTR:
    GLOB_CLEAR_STRING(stand_r_row_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_U_ROW_ATTR:
    GLOB_SET_STRING(stand_u_row_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_U_ROW_ATTR:
    GLOB_CLEAR_STRING(stand_u_row_attr);

  case SSERV_CMD_GLOB_CHANGE_ENABLE_EXTRA_COL:
    p_int = &sstate->enable_extra_col;
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    if (val && !global->stand_extra_format[0]) {
      strcpy(global->stand_extra_format, "%Mc");
      strcpy(global->stand_extra_legend, "City");
    }
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_FORMAT:
    GLOB_SET_STRING(stand_extra_format);

  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_FORMAT:
    GLOB_CLEAR_STRING(stand_extra_format);

  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_LEGEND:
    GLOB_SET_STRING(stand_extra_legend);

  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_LEGEND:
    GLOB_CLEAR_STRING(stand_extra_legend);

  case SSERV_CMD_GLOB_CHANGE_STAND_EXTRA_ATTR:
    GLOB_SET_STRING(stand_extra_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_EXTRA_ATTR:
    GLOB_CLEAR_STRING(stand_extra_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_SHOW_WARN_NUMBER:
    p_int = &global->stand_show_warn_number;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_STAND_WARN_NUMBER_ATTR:
    GLOB_SET_STRING(stand_warn_number_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_WARN_NUMBER_ATTR:
    GLOB_CLEAR_STRING(stand_warn_number_attr);

  case SSERV_CMD_GLOB_CHANGE_SLEEP_TIME:
    p_int = &global->sleep_time; default_val = 1000;

  handle_int_def:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (!val) val = default_val;
    *p_int = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_SERVE_SLEEP_TIME:
    p_int = &global->serve_sleep_time; default_val = 500;
    goto handle_int_def;

  case SSERV_CMD_GLOB_CHANGE_AUTOUPDATE_STANDINGS:
    p_int = &global->autoupdate_standings;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_USE_AC_NOT_OK:
    p_int = &global->use_ac_not_ok;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ROUNDING_MODE:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > 2) return -SSERV_ERR_INVALID_PARAMETER;
    global->rounding_mode = val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_MAX_FILE_LENGTH:
    p_int = &global->max_file_length;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_MAX_LINE_LENGTH:
    p_int = &global->max_line_length;
    goto handle_size;

  case SSERV_CMD_GLOB_CHANGE_INACTIVITY_TIMEOUT:
    p_int = &global->inactivity_timeout; default_val = 120;
    goto handle_int_def;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_AUTO_TESTING:
    p_int = &global->disable_auto_testing;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DISABLE_TESTING:
    p_int = &global->disable_testing;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_CR_SERIALIZATION_KEY:
    p_int = &global->cr_serialization_key; default_val = config->serialization_key;
    goto handle_int_def;

  case SSERV_CMD_GLOB_CHANGE_SHOW_ASTR_TIME:
    p_int = &global->show_astr_time;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_MEMOIZE_USER_RESULTS:
    p_int = &global->memoize_user_results;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_CONTINUE:
    p_int = &global->enable_continue;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_REPORT_UPLOAD:
    p_int = &global->enable_report_upload;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_RUNLOG_MERGE:
    p_int = &global->enable_runlog_merge;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_USE_COMPILATION_SERVER:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    sstate->disable_compilation_server = !val;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_WIN32_LANGUAGES:
    if (sscanf(param2, "%d%n", &val, &n) != 1 || param2[n] || val < 0 || val > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    sstate->enable_win32_languages = val;
    if (val) {
      // check, that win32_compile is already added
      if (global->extra_compile_dirs) {
        for (int i = 0; global->extra_compile_dirs[i]; ++i) {
          if (!strcmp(global->extra_compile_dirs[i], "win32_compile"))
            return 0;
        }
      }
      global->extra_compile_dirs = sarray_append(global->extra_compile_dirs, "win32_compile");
    }
    return 0;    

  case SSERV_CMD_GLOB_CHANGE_SECURE_RUN:
    p_int = &global->secure_run;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_DETECT_VIOLATIONS:
    p_int = &global->detect_violations;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_MEMORY_LIMIT_ERROR:
    p_int = &global->enable_memory_limit_error;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_SEPARATE_USER_SCORE:
    p_int = &global->separate_user_score;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_ENABLE_L10N:
    p_int = &global->enable_l10n;
    goto handle_boolean;

  case SSERV_CMD_GLOB_CHANGE_CHARSET:
    GLOB_SET_STRING(charset);

  case SSERV_CMD_GLOB_CLEAR_CHARSET:
    GLOB_CLEAR_STRING(charset);

  case SSERV_CMD_GLOB_CHANGE_STANDINGS_CHARSET:
    GLOB_SET_STRING(standings_charset);

  case SSERV_CMD_GLOB_CLEAR_STANDINGS_CHARSET:
    GLOB_CLEAR_STRING(standings_charset);

  case SSERV_CMD_GLOB_CHANGE_STAND2_CHARSET:
    GLOB_SET_STRING(stand2_charset);

  case SSERV_CMD_GLOB_CLEAR_STAND2_CHARSET:
    GLOB_CLEAR_STRING(stand2_charset);

  case SSERV_CMD_GLOB_CHANGE_PLOG_CHARSET:
    GLOB_SET_STRING(plog_charset);

  case SSERV_CMD_GLOB_CLEAR_PLOG_CHARSET:
    GLOB_CLEAR_STRING(plog_charset);

  case SSERV_CMD_GLOB_CHANGE_TEAM_DOWNLOAD_TIME:
    p_int = &global->team_download_time;
    goto handle_int;

  case SSERV_CMD_GLOB_DISABLE_TEAM_DOWNLOAD_TIME:
    global->team_download_time = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_CPU_BOGOMIPS:
    p_int = &global->cpu_bogomips;
    goto handle_int;

  case SSERV_CMD_GLOB_DETECT_CPU_BOGOMIPS:
    global->cpu_bogomips = cpu_get_bogomips();
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_ROW_ATTR:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(global->stand_row_attr);
    global->stand_row_attr = tmp_env;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_STAND_ROW_ATTR:
    sarray_free(global->stand_row_attr);
    global->stand_row_attr = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_TABLE_ATTR:
    GLOB_SET_STRING(stand_page_table_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_TABLE_ATTR:
    GLOB_CLEAR_STRING(stand_page_table_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_CUR_ATTR:
    GLOB_SET_STRING(stand_page_cur_attr);

  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_CUR_ATTR:
    GLOB_CLEAR_STRING(stand_page_cur_attr);

  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_ROW_ATTR:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(global->stand_page_row_attr);
    global->stand_page_row_attr = tmp_env;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_ROW_ATTR:
    sarray_free(global->stand_page_row_attr);
    global->stand_page_row_attr = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_STAND_PAGE_COL_ATTR:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(global->stand_page_col_attr);
    global->stand_page_col_attr = tmp_env;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_STAND_PAGE_COL_ATTR:
    sarray_free(global->stand_page_col_attr);
    global->stand_page_col_attr = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_LOAD_USER_GROUP:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(global->load_user_group);
    global->load_user_group = tmp_env;
    return 0;

  case SSERV_CMD_GLOB_CLEAR_LOAD_USER_GROUP:
    sarray_free(global->load_user_group);
    global->load_user_group = 0;
    return 0;

  case SSERV_CMD_GLOB_CHANGE_CLARDB_PLUGIN:
    GLOB_SET_STRING(clardb_plugin);

  case SSERV_CMD_GLOB_CLEAR_CLARDB_PLUGIN:
    GLOB_CLEAR_STRING(clardb_plugin);

  case SSERV_CMD_GLOB_CHANGE_RUNDB_PLUGIN:
    GLOB_SET_STRING(rundb_plugin);

  case SSERV_CMD_GLOB_CLEAR_RUNDB_PLUGIN:
    GLOB_CLEAR_STRING(rundb_plugin);

  case SSERV_CMD_GLOB_CHANGE_XUSER_PLUGIN:
    GLOB_SET_STRING(xuser_plugin);

  case SSERV_CMD_GLOB_CLEAR_XUSER_PLUGIN:
    GLOB_CLEAR_STRING(xuser_plugin);

  default:
    abort();
  }
  return 0;
}

static int
super_html_find_lang_id(
        struct sid_state *sstate,
        const struct section_language_data *cs_lang)
{
  int i, max_cs_lang_id;

  /* out of currently activated languages */
  if (cs_lang->id >= sstate->lang_a) {
    return cs_lang->id;
  }
  /* not an activated slot */
  if (!sstate->langs[cs_lang->id]) {
    return cs_lang->id;
  }
  /* we cannot use the same id for compilation and contest server */
  max_cs_lang_id = 0;
  for (i = 1; i < sstate->cs_lang_total; ++i) {
    if (sstate->cs_langs[i]) {
      max_cs_lang_id = i;
    }
  }
  /* max_cs_lang_id is the max of lang_ids of compile server */
  /* consider 30 to be safe interval */
  i = max_cs_lang_id + 30;
  while (i < sstate->lang_a && sstate->langs[i] && sstate->loc_cs_map[i]) {
    ++i;
  }
  return i;
}

void
super_html_lang_activate(
        struct sid_state *sstate,
        int cs_lang_id)
{
  const struct section_language_data *cs_lang = 0;
  struct section_language_data *lang;
  int lang_id;

  ASSERT(sstate);
  if (cs_lang_id <= 0 || cs_lang_id >= sstate->cs_lang_total
      || !(cs_lang = sstate->cs_langs[cs_lang_id]))
    return;

  /* already activated */
  if (sstate->cs_loc_map[cs_lang_id] > 0) return;

  /* create language structure */
  lang = prepare_alloc_language();
  sstate->cfg = param_merge(&lang->g, sstate->cfg);

  lang_id = super_html_find_lang_id(sstate, cs_lang);
  if (lang_id <= 0) return;
  lang->id = lang_id;
  lang->compile_id = cs_lang_id;
  /*
  max_id = 0;
  for (i = 1; i < sstate->lang_a; i++)
    if (sstate->langs[i] && sstate->loc_cs_map[i] && i > max_id)
      max_id = i;

  if (cs_lang->id > max_id) {
    lang->id = cs_lang->id;
    lang->compile_id = cs_lang->id;
  } else {
    while (1) {
      max_id++;
      for (i = 1; i < sstate->lang_a; i++)
        if (sstate->langs[i] && sstate->langs[i]->id == max_id)
          break;
      if (i < sstate->lang_a) continue;
      for (i = 1; i < sstate->cs_lang_total; i++)
        if (sstate->cs_langs[i] && sstate->cs_langs[i]->id == max_id)
          break;
      if (i == sstate->cs_lang_total)
        break;
    }
    lang->id = max_id;
    lang->compile_id = cs_lang->id;
  }
  lang_id = lang->id;
  */

  /* extend the language arrays */
  if (lang_id >= sstate->lang_a) {
    int new_lang_a = sstate->lang_a;
    struct section_language_data **new_langs;
    int *new_loc_cs_map;
    unsigned char **new_lang_opts;
    unsigned char **new_lang_libs;
    int *new_lang_flags;

    if (!new_lang_a) new_lang_a = 4;
    while (lang_id >= new_lang_a) new_lang_a *= 2;
    XCALLOC(new_langs, new_lang_a);
    XCALLOC(new_loc_cs_map, new_lang_a);
    XCALLOC(new_lang_opts, new_lang_a);
    XCALLOC(new_lang_libs, new_lang_a);
    XCALLOC(new_lang_flags, new_lang_a);
    if (sstate->lang_a > 0) {
      XMEMMOVE(new_langs, sstate->langs, sstate->lang_a);
      XMEMMOVE(new_loc_cs_map, sstate->loc_cs_map, sstate->lang_a);
      XMEMMOVE(new_lang_opts, sstate->lang_opts, sstate->lang_a);
      XMEMMOVE(new_lang_libs, sstate->lang_libs, sstate->lang_a);
      XMEMMOVE(new_lang_flags, sstate->lang_flags, sstate->lang_a);
    }
    xfree(sstate->langs);
    xfree(sstate->loc_cs_map);
    xfree(sstate->lang_opts);
    xfree(sstate->lang_libs);
    xfree(sstate->lang_flags);
    sstate->lang_a = new_lang_a;
    sstate->langs = new_langs;
    sstate->loc_cs_map = new_loc_cs_map;
    sstate->lang_opts = new_lang_opts;
    sstate->lang_libs = new_lang_libs;
    sstate->lang_flags = new_lang_flags;
  }
  sstate->langs[lang_id] = lang;
  sstate->lang_opts[lang_id] = 0;
  sstate->lang_libs[lang_id] = 0;
  sstate->lang_flags[lang_id] = 0;
  sstate->cs_loc_map[lang->compile_id] = lang_id;

  strcpy(lang->short_name, cs_lang->short_name);
  if (sstate->cs_lang_names[cs_lang_id]
      && *sstate->cs_lang_names[cs_lang_id]) {
    snprintf(lang->long_name, sizeof(lang->long_name),
             "%s", sstate->cs_lang_names[cs_lang_id]);
  } else {
    snprintf(lang->long_name, sizeof(lang->long_name),
             "%s", cs_lang->long_name);
  }
  strcpy(lang->arch, cs_lang->arch);
  strcpy(lang->src_sfx, cs_lang->src_sfx);
  strcpy(lang->exe_sfx, cs_lang->exe_sfx);
  lang->binary = cs_lang->binary;
  lang->insecure = cs_lang->insecure;
  strcpy(lang->content_type, cs_lang->content_type);
  lang->compile_dir_index = cs_lang->compile_dir_index;
  lang->max_vm_size = cs_lang->max_vm_size;
  lang->max_stack_size = cs_lang->max_stack_size;
  lang->max_file_size = cs_lang->max_file_size;
}

void
super_html_lang_deactivate(
        struct sid_state *sstate,
        int cs_lang_id)
{
  struct section_language_data *lang = 0;
  int lang_id;

  ASSERT(sstate);
  if (cs_lang_id <= 0 || cs_lang_id >= sstate->cs_lang_total
      || !sstate->cs_langs[cs_lang_id])
    return;
  if ((lang_id = sstate->cs_loc_map[cs_lang_id]) <= 0) return;
  if (lang_id >= sstate->lang_a || !(lang = sstate->langs[lang_id])) return;
  if (sstate->loc_cs_map[lang_id]) return;

  sstate->langs[lang_id] = 0;
  xfree(sstate->lang_opts[lang_id]);
  xfree(sstate->lang_libs[lang_id]);
  sstate->lang_opts[lang_id] = 0;
  sstate->lang_libs[lang_id] = 0;
  sstate->lang_flags[lang_id] = 0;
  sstate->cs_loc_map[cs_lang_id] = 0;
}

int
super_html_lang_cmd(struct sid_state *sstate, int cmd,
                    int lang_id, const unsigned char *param2,
                    int param3, int param4)
{
  struct section_language_data *pl_new;
  int val, n;
  int *p_int;
  size_t *p_size, zval;
  char **tmp_env = 0;

  if (!sstate->cs_langs) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }
  if (lang_id <= 0 || lang_id >= sstate->cs_lang_total
      || !sstate->cs_langs[lang_id]) {
    return -SSERV_ERR_INVALID_PARAMETER;
  }

  pl_new = 0;
  if (sstate->cs_loc_map[lang_id] > 0)
    pl_new = sstate->langs[sstate->cs_loc_map[lang_id]];

  switch (cmd) {
  case SSERV_CMD_LANG_SHOW_DETAILS:
    if (!pl_new) return 0;
    sstate->lang_flags[pl_new->id] = 1;
    break;

  case SSERV_CMD_LANG_HIDE_DETAILS:
    if (!pl_new) return 0;
    sstate->lang_flags[pl_new->id] = 0;
    break;

  case SSERV_CMD_LANG_DEACTIVATE:
    super_html_lang_deactivate(sstate, lang_id);
    break;

  case SSERV_CMD_LANG_ACTIVATE:
    super_html_lang_activate(sstate, lang_id);
    break;

  case SSERV_CMD_LANG_CHANGE_DISABLED:
    if (!pl_new) return 0;
    p_int = &pl_new->disabled;

  handle_boolean:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    break;

  case SSERV_CMD_LANG_CHANGE_INSECURE:
    if (!pl_new) return 0;
    p_int = &pl_new->insecure;
    goto handle_boolean;

  case SSERV_CMD_LANG_CHANGE_LONG_NAME:
    if (!pl_new) return 0;
    snprintf(pl_new->long_name, sizeof(pl_new->long_name), "%s", param2);
    break;

  case SSERV_CMD_LANG_CHANGE_EXTID:
    if (!pl_new) return 0;
    xfree(pl_new->extid); pl_new->extid = NULL;
    if (param2 && param2[0]) {
      pl_new->extid = xstrdup(param2);
    }
    break;

  case SSERV_CMD_LANG_CHANGE_CONTENT_TYPE:
    if (!pl_new) return 0;
    snprintf(pl_new->content_type, sizeof(pl_new->content_type), "%s", param2);
    break;

  case SSERV_CMD_LANG_CHANGE_STYLE_CHECKER_CMD:
    if (!pl_new) return 0;
    snprintf(pl_new->style_checker_cmd, sizeof(pl_new->style_checker_cmd), "%s", param2);
    break;

  case SSERV_CMD_LANG_CLEAR_LONG_NAME:
    if (!pl_new) return 0;
    pl_new->long_name[0] = 0;
    break;

  case SSERV_CMD_LANG_CLEAR_EXTID:
    if (!pl_new) return 0;
    xfree(pl_new->extid); pl_new->extid = NULL;
    break;

  case SSERV_CMD_LANG_CLEAR_CONTENT_TYPE:
    if (!pl_new) return 0;
    pl_new->content_type[0] = 0;
    break;

  case SSERV_CMD_LANG_CLEAR_STYLE_CHECKER_CMD:
    if (!pl_new) return 0;
    pl_new->style_checker_cmd[0] = 0;
    break;

  case SSERV_CMD_LANG_CHANGE_STYLE_CHECKER_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(pl_new->style_checker_env);
    pl_new->style_checker_env = tmp_env; tmp_env = 0;
    break;

  case SSERV_CMD_LANG_CLEAR_STYLE_CHECKER_ENV:
    pl_new->style_checker_env = sarray_free(pl_new->style_checker_env);
    break;

  case SSERV_CMD_LANG_CHANGE_DISABLE_SECURITY:
    if (!pl_new) return 0;
    p_int = &pl_new->disable_security;
    goto handle_boolean;

  case SSERV_CMD_LANG_CHANGE_DISABLE_AUTO_TESTING:
    if (!pl_new) return 0;
    p_int = &pl_new->disable_auto_testing;
    goto handle_boolean;

  case SSERV_CMD_LANG_CHANGE_DISABLE_TESTING:
    if (!pl_new) return 0;
    p_int = &pl_new->disable_testing;
    goto handle_boolean;

  case SSERV_CMD_LANG_CHANGE_BINARY:
    if (!pl_new) return 0;
    p_int = &pl_new->binary;
    goto handle_boolean;

  case SSERV_CMD_LANG_CHANGE_IS_DOS:
    if (!pl_new) return 0;
    p_int = &pl_new->is_dos;
    goto handle_boolean;

  case SSERV_CMD_LANG_CHANGE_MAX_VM_SIZE:
    p_size = &pl_new->max_vm_size;

  handle_size_t:
    zval = 0;
    if (size_str_to_size_t(param2, &zval) < 0) return -SSERV_ERR_INVALID_PARAMETER;
    *p_size = zval;
    return 0;

  case SSERV_CMD_LANG_CHANGE_MAX_STACK_SIZE:
    p_size = &pl_new->max_stack_size;
    goto handle_size_t;

  case SSERV_CMD_LANG_CHANGE_MAX_FILE_SIZE:
    p_size = &pl_new->max_file_size;
    goto handle_size_t;

  case SSERV_CMD_LANG_CHANGE_OPTS:
    if (!pl_new) return 0;
    xfree(sstate->lang_opts[lang_id]);
    sstate->lang_opts[lang_id] = xstrdup(param2);
    break;

  case SSERV_CMD_LANG_CLEAR_OPTS:
    if (!pl_new) return 0;
    xfree(sstate->lang_opts[lang_id]);
    sstate->lang_opts[lang_id] = 0;
    break;

  case SSERV_CMD_LANG_CHANGE_LIBS:
    if (!pl_new) return 0;
    xfree(sstate->lang_libs[lang_id]);
    sstate->lang_libs[lang_id] = xstrdup(param2);
    break;

  case SSERV_CMD_LANG_CLEAR_LIBS:
    if (!pl_new) return 0;
    xfree(sstate->lang_libs[lang_id]);
    sstate->lang_libs[lang_id] = 0;
    break;

  default:
    abort();
  }

  return 0;
}

int
super_html_update_versions(struct sid_state *sstate)
{
  int i, j;

  if (!sstate->cs_langs) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }

  for (i = 1; i < sstate->lang_a; i++) {
    if (!sstate->langs[i]) continue;
    j = 0;
    if (sstate->loc_cs_map) {
      j = sstate->loc_cs_map[i];
      if (j <= 0 || j >= sstate->cs_lang_total || !sstate->cs_langs[j])
        j = 0;
    }
    if (j > 0) {
      snprintf(sstate->langs[i]->long_name,sizeof(sstate->langs[i]->long_name),
               "%s", sstate->cs_lang_names[j]);
    }
  }
  return 0;
}

struct std_checker_info super_html_std_checkers[] =
{
  { "", "" },
  { "cmp_file", "compare two files (trailing whitespace ignored)" },
  { "cmp_file_nospace", "compare two files (duplicated whitespace ignored)" },
  { "cmp_bytes", "compare two files byte by byte" },
  { "cmp_int", "compare two ints (32 bit)" },
  { "cmp_int_seq", "compare two sequences of ints (32 bit)" },
  { "cmp_long_long", "compare two long longs (64 bit)" },
  { "cmp_long_long_seq", "compare two sequences of long longs (64 bit)" },
  { "cmp_unsigned_int", "compare two unsigned ints (32 bit)" },
  { "cmp_unsigned_int_seq", "compare two sequences of unsigned ints (32 bit)" },
  { "cmp_unsigned_long_long", "compare two unsigned long longs (64 bit)" },
  { "cmp_unsigned_long_long_seq", "compare two sequences of unsigned long longs (64 bit)" },
  { "cmp_huge_int", "compare two arbitrarily long ints" },
  { "cmp_double", "compare two doubles (EPS env. var is required)" },
  { "cmp_double_seq", "compare two sequences of doubles (EPS is required)" },
  { "cmp_long_double", "compare two long doubles (EPS is required)" },
  { "cmp_long_double_seq", "compare two sequences of long doubles (EPS is required)" },
  { "cmp_sexpr", "compare two S-expressions" },
  { "cmp_yesno", "compare YES/NO answers" },
  { 0, 0 },
};

const unsigned char *
super_html_get_standard_checker_description(const unsigned char *standard_checker)
{
  if (!standard_checker) return NULL;

  for (int i = 0; super_html_std_checkers[i].name; ++i) {
    if (!strcmp(super_html_std_checkers[i].name, standard_checker)) {
      return super_html_std_checkers[i].desc;
    }
  }
  return NULL;
}

void
problem_id_to_short_name(int num, unsigned char *buf)
{
  if (num < 0) num = 0;
  unsigned char *s = buf;
  if (!num) {
    *s++ = 'A';
    *s = 0;
  } else {
    while (num > 0) {
      *s++ = 'A' + (num % 26);
      num /= 26;
    }
    *s-- = 0;
    unsigned char *q = buf;
    while (q < s) {
      unsigned char t = *q; *q = *s; *s = t;
      ++q; --s;
    }
  }
}

int
super_html_add_problem(
        struct sid_state *sstate,
        int prob_id)
{
  int i;
  struct section_problem_data *prob = 0;

  if (prob_id < 0 || prob_id > EJ_MAX_PROB_ID)
    return -1;

  if (!prob_id) {
    for (i = 1; i < sstate->prob_a; i++)
      if (!sstate->probs[i])
        break;
    prob_id = i;
  }

  prob = super_html_create_problem(sstate, prob_id);
  if (!prob) return -SSERV_ERR_DUPLICATED_PROBLEM;

  problem_id_to_short_name(prob_id - 1, prob->short_name);
  if (sstate->aprob_u == 1)
    snprintf(prob->super, sizeof(prob->super), "%s",
             sstate->aprobs[0]->short_name);
  prob->variant_num = 0;
  return 0;
}

int
super_html_add_abstract_problem(
        struct sid_state *sstate,
        const unsigned char *short_name)
{
  struct section_problem_data *prob = 0;
  int i;

  if (!short_name || !*short_name) return -1;
  if (check_str(short_name, login_accept_chars) < 0) return -1;
  for (i = 0; i < sstate->prob_a; i++)
    if (sstate->probs[i] && !strcmp(sstate->probs[i]->short_name, short_name))
      break;
  if (i < sstate->prob_a) return -1;
  for (i = 0; i < sstate->aprob_u; i++)
    if (!strcmp(sstate->aprobs[i]->short_name, short_name))
      break;
  if (i < sstate->aprob_u) return -1;
  if (i == sstate->aprob_a) {
    if (!sstate->aprob_a) sstate->aprob_a = 4;
    sstate->aprob_a *= 2;
    XREALLOC(sstate->aprobs, sstate->aprob_a);
    XREALLOC(sstate->aprob_flags, sstate->aprob_a);
  }
  prob = prepare_alloc_problem();
  prepare_problem_init_func(&prob->g);
  sstate->cfg = param_merge(&prob->g, sstate->cfg);
  sstate->aprobs[i] = prob;
  sstate->aprob_flags[i] = 0;
  sstate->aprob_u++;
  snprintf(prob->short_name, sizeof(prob->short_name), "%s", short_name);
  prob->abstract = 1;
  prob->type = 0;
  prob->manual_checking = 0;
  prob->examinator_num = 0;
  prob->check_presentation = 0;
  prob->scoring_checker = 0;
  prob->interactive_valuer = 0;
  prob->disable_pe = 0;
  prob->disable_wtl = 0;
  prob->use_stdin = 1;
  prob->use_stdout = 1;
  prob->combined_stdin = 0;
  prob->combined_stdout = 0;
  prob->binary_input = DFLT_P_BINARY_INPUT;
  prob->binary = 0;
  prob->ignore_exit_code = 0;
  prob->olympiad_mode = 0;
  prob->score_latest = 0;
  prob->score_latest_or_unmarked = 0;
  prob->score_latest_marked = 0;
  prob->score_tokenized = 0;
  prob->time_limit = 1;
  prob->time_limit_millis = 0;
  prob->real_time_limit = 5;
  snprintf(prob->test_dir, sizeof(prob->test_sfx), "%s", "%Ps");
  snprintf(prob->test_sfx, sizeof(prob->test_sfx), "%s", ".dat");
  prob->use_corr = 1;
  snprintf(prob->corr_dir, sizeof(prob->corr_dir), "%s", "%Ps");
  snprintf(prob->corr_sfx, sizeof(prob->corr_sfx), "%s", ".ans");
  prob->use_info = 0;
  snprintf(prob->info_dir, sizeof(prob->info_dir), "%s", "%Ps");
  snprintf(prob->info_sfx, sizeof(prob->info_sfx), "%s", ".inf");
  prob->use_tgz = 0;
  snprintf(prob->tgz_dir, sizeof(prob->tgz_dir), "%s", "%Ps");
  snprintf(prob->tgz_sfx, sizeof(prob->tgz_sfx), "%s", ".tgz");
  snprintf(prob->tgzdir_sfx, sizeof(prob->tgzdir_sfx), "%s", ".dir");
  if (sstate->global && sstate->global->advanced_layout > 0) {
    snprintf(prob->check_cmd, sizeof(prob->check_cmd), "%s", DFLT_P_CHECK_CMD);
  } else {
    snprintf(prob->check_cmd, sizeof(prob->check_cmd), "%s", "check_%Ps");
  }
  prob->max_vm_size = 64 * SIZE_M;
  prob->variant_num = 0;
  return 0;
}

int
super_html_prob_cmd(struct sid_state *sstate, int cmd,
                    int prob_id, const unsigned char *param2,
                    int param3, int param4)
{
  int new_val_1, new_val_2;

  switch (cmd) {
  case SSERV_CMD_PROB_ADD:
    return super_html_add_problem(sstate, prob_id);

  case SSERV_CMD_PROB_ADD_ABSTRACT:
    return super_html_add_abstract_problem(sstate, param2);

  case SSERV_CMD_PROB_SHOW_DETAILS:
    new_val_1 = SID_STATE_SHOW_HIDDEN;
    new_val_2 = 0;
    goto do_handle_details_flag;
  case SSERV_CMD_PROB_HIDE_DETAILS:
    new_val_1 = 0;
    new_val_2 = SID_STATE_SHOW_HIDDEN;
    goto do_handle_details_flag;
  case SSERV_CMD_PROB_SHOW_ADVANCED:
    new_val_1 = SID_STATE_SHOW_CLOSED;
    new_val_2 = 0;
    goto do_handle_details_flag;
  case SSERV_CMD_PROB_HIDE_ADVANCED:
    new_val_1 = 0;
    new_val_2 = SID_STATE_SHOW_CLOSED;
    goto do_handle_details_flag;
  do_handle_details_flag:;
    if (prob_id <= 0) {
      prob_id = -prob_id;
      if (prob_id >= sstate->aprob_u)
        return -SSERV_ERR_INVALID_PARAMETER;
      sstate->aprob_flags[prob_id] |= new_val_1;
      sstate->aprob_flags[prob_id] &= ~new_val_2;
    } else {
      if (prob_id >= sstate->prob_a || !sstate->probs[prob_id])
        return -SSERV_ERR_INVALID_PARAMETER;
      sstate->prob_flags[prob_id] |= new_val_1;
      sstate->prob_flags[prob_id] &= ~new_val_2;
    }
    return 0;

  default:
    abort();
  }
}

#define PROB_ASSIGN_STRING(f) snprintf(prob->f, sizeof(prob->f), "%s", param2)
#define PROB_CLEAR_STRING(f) prob->f[0] = 0

int
super_html_prob_param(struct sid_state *sstate, int cmd,
                      int prob_id, const unsigned char *param2,
                      int param3, int param4)
{
  struct section_problem_data *prob;
  int i, n, val;
  int *p_int;
  char **tmp_env = 0;
  size_t *p_size, zval;
  time_t *p_time;

  if (prob_id > 0) {
    if (prob_id >= sstate->prob_a || !sstate->probs[prob_id])
      return -SSERV_ERR_INVALID_PARAMETER;
    prob = sstate->probs[prob_id];
  } else {
    prob_id = -prob_id;
    if (prob_id >= sstate->aprob_u || !sstate->aprobs[prob_id])
      return -SSERV_ERR_INVALID_PARAMETER;
    prob = sstate->aprobs[prob_id];
  }

  switch (cmd) {
  case SSERV_CMD_PROB_DELETE:
    if (prob->abstract && prob->short_name[0]) {
      for (i = 1; i < sstate->prob_a; i++)
        if (sstate->probs[i]
            && !strcmp(sstate->probs[i]->short_name, prob->short_name))
          break;
      if (i < sstate->prob_a) return -SSERV_ERR_PROBLEM_IS_USED;
      for (i = prob_id + 1; i < sstate->aprob_u; i++) {
        sstate->aprobs[i - 1] = sstate->aprobs[i];
        sstate->aprob_flags[i - 1] = sstate->aprob_flags[i];
      }
      sstate->aprob_u--;
      sstate->aprobs[sstate->aprob_u] = 0;
      sstate->aprob_flags[sstate->aprob_u] = 0;
    } else {
      sstate->probs[prob_id] = 0;
      sstate->prob_flags[prob_id] = 0;
    }
    return 0;
  case SSERV_CMD_PROB_CHANGE_SHORT_NAME:
    if (!param2 || !*param2 || check_str(param2, login_accept_chars) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (prob->abstract) {
      for (i = 0; i < sstate->aprob_u; i++)
        if (i != prob_id && !strcmp(sstate->aprobs[i]->short_name, param2))
          break;
      if (i < sstate->aprob_u)
        return -SSERV_ERR_DUPLICATED_PROBLEM;
    }
    PROB_ASSIGN_STRING(short_name);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SHORT_NAME:
    if (prob->abstract) return -SSERV_ERR_INVALID_PARAMETER;
    PROB_CLEAR_STRING(short_name);
    return 0;

  case SSERV_CMD_PROB_CHANGE_LONG_NAME:
    PROB_ASSIGN_STRING(long_name);
    return 0;

  case SSERV_CMD_PROB_CLEAR_LONG_NAME:
    PROB_CLEAR_STRING(long_name);
    return 0;

  case SSERV_CMD_PROB_CHANGE_STAND_NAME:
    PROB_ASSIGN_STRING(stand_name);
    return 0;

  case SSERV_CMD_PROB_CLEAR_STAND_NAME:
    PROB_CLEAR_STRING(stand_name);
    return 0;

  case SSERV_CMD_PROB_CHANGE_STAND_COLUMN:
    PROB_ASSIGN_STRING(stand_column);
    return 0;

  case SSERV_CMD_PROB_CLEAR_STAND_COLUMN:
    PROB_CLEAR_STRING(stand_column);
    return 0;

  case SSERV_CMD_PROB_CHANGE_INTERNAL_NAME:
    PROB_ASSIGN_STRING(internal_name);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INTERNAL_NAME:
    PROB_CLEAR_STRING(internal_name);
    return 0;

  case SSERV_CMD_PROB_CHANGE_SUPER:
    if (prob->abstract) return -SSERV_ERR_INVALID_PARAMETER;
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < 0 || val > sstate->aprob_u)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (!val) {
      prob->super[0] = 0;
    } else {
      val--;
      if (!sstate->aprobs[val]) return -SSERV_ERR_INVALID_PARAMETER;
      snprintf(prob->super, sizeof(prob->super), "%s", sstate->aprobs[val]->short_name);
    }
    return 0;

  case SSERV_CMD_PROB_CHANGE_TYPE:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < -1 || val >= PROB_TYPE_LAST)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (prob->abstract && val < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    prob->type = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_SCORING_CHECKER:
    p_int = &prob->scoring_checker;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_INTERACTIVE_VALUER:
    p_int = &prob->interactive_valuer;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_DISABLE_PE:
    p_int = &prob->disable_pe;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_DISABLE_WTL:
    p_int = &prob->disable_wtl;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_MANUAL_CHECKING:
    p_int = &prob->manual_checking;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_EXAMINATOR_NUM:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n]
        || val < 0 || val > 3)
      return -SSERV_ERR_INVALID_PARAMETER;
    prob->examinator_num = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_CHECK_PRESENTATION:
    p_int = &prob->check_presentation;
    goto handle_boolean_1;
    
  case SSERV_CMD_PROB_CHANGE_USE_STDIN:
    p_int = &prob->use_stdin;

  handle_boolean_1:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (prob->abstract) {
      if (val < 0 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    } else {
      if (val < -1 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    }
    *p_int = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_USE_STDOUT:
    p_int = &prob->use_stdout;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_COMBINED_STDIN:
    p_int = &prob->combined_stdin;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_COMBINED_STDOUT:
    p_int = &prob->combined_stdout;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_BINARY_INPUT:
    p_int = &prob->binary_input;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_BINARY:
    p_int = &prob->binary;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_IGNORE_EXIT_CODE:
    p_int = &prob->ignore_exit_code;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_OLYMPIAD_MODE:
    p_int = &prob->olympiad_mode;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_SCORE_LATEST:
    p_int = &prob->score_latest;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_SCORE_LATEST_OR_UNMARKED:
    p_int = &prob->score_latest_or_unmarked;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_SCORE_LATEST_MARKED:
    p_int = &prob->score_latest_marked;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_SCORE_TOKENIZED:
    p_int = &prob->score_tokenized;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_TIME_LIMIT:
    p_int = &prob->time_limit;

  handle_int_1:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < -1) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TIME_LIMIT_MILLIS:
    p_int = &prob->time_limit_millis;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_REAL_TIME_LIMIT:
    p_int = &prob->real_time_limit;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_USE_AC_NOT_OK:
    p_int = &prob->use_ac_not_ok;

  handle_boolean_2:
    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < -1 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_IGNORE_PREV_AC:
    p_int = &prob->ignore_prev_ac;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_REP_VIEW:
    p_int = &prob->team_enable_rep_view;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_TEAM_ENABLE_CE_VIEW:
    p_int = &prob->team_enable_ce_view;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_TEAM_SHOW_JUDGE_REPORT:
    p_int = &prob->team_show_judge_report;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_SHOW_CHECKER_COMMENT:
    p_int = &prob->show_checker_comment;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_IGNORE_COMPILE_ERRORS:
    p_int = &prob->ignore_compile_errors;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_USER_SUBMIT:
    p_int = &prob->disable_user_submit;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_TAB:
    p_int = &prob->disable_tab;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_UNRESTRICTED_STATEMENT:
    p_int = &prob->unrestricted_statement;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_HIDE_FILE_NAMES:
    p_int = &prob->hide_file_names;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_HIDE_REAL_TIME_LIMIT:
    p_int = &prob->hide_real_time_limit;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_ENABLE_TOKENS:
    p_int = &prob->enable_tokens;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_TOKENS_FOR_USER_AC:
    p_int = &prob->tokens_for_user_ac;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_SUBMIT_AFTER_OK:
    p_int = &prob->disable_submit_after_ok;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_SECURITY:
    p_int = &prob->disable_security;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_TESTING:
    p_int = &prob->disable_testing;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_DISABLE_AUTO_TESTING:
    p_int = &prob->disable_auto_testing;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_ENABLE_COMPILATION:
    p_int = &prob->enable_compilation;
    goto handle_boolean_2;

  case SSERV_CMD_PROB_CHANGE_FULL_SCORE:
    p_int = &prob->full_score;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_FULL_USER_SCORE:
    p_int = &prob->full_user_score;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_TEST_SCORE:
    p_int = &prob->test_score;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_RUN_PENALTY:
    p_int = &prob->run_penalty;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_ACM_RUN_PENALTY:
    p_int = &prob->acm_run_penalty;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_MAX_USER_RUN_COUNT:
    p_int = &prob->max_user_run_count;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_DISQUALIFIED_PENALTY:
    p_int = &prob->disqualified_penalty;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_VARIABLE_FULL_SCORE:
    p_int = &prob->variable_full_score;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_TEST_SCORE_LIST:
    // FIXME: check for correctness
    xfree(prob->test_score_list);
    prob->test_score_list = xstrdup(param2);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_SCORE_LIST:
    xfree(prob->test_score_list);
    prob->test_score_list = NULL;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TOKENS:
    // FIXME: check for correctness
    xfree(prob->tokens);
    prob->tokens = xstrdup(param2);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TOKENS:
    xfree(prob->tokens);
    prob->tokens = NULL;
    return 0;

  case SSERV_CMD_PROB_CHANGE_UMASK:
    // FIXME: check for correctness
    xfree(prob->umask);
    prob->umask = xstrdup(param2);
    return 0;

  case SSERV_CMD_PROB_CLEAR_UMASK:
    xfree(prob->umask);
    prob->umask = NULL;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TOKEN_OPEN_TESTS:
    // FIXME: check for correctness
    xfree(prob->token_open_tests);
    prob->token_open_tests = xstrdup(param2);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TOKEN_OPEN_TESTS:
    xfree(prob->token_open_tests);
    prob->token_open_tests = NULL;
    return 0;

  case SSERV_CMD_PROB_CHANGE_SCORE_TESTS:
    // FIXME: check for correctness
    PROB_ASSIGN_STRING(score_tests);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SCORE_TESTS:
    PROB_CLEAR_STRING(score_tests);
    return 0;

  case SSERV_CMD_PROB_CHANGE_TESTS_TO_ACCEPT:
    p_int = &prob->tests_to_accept;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_ACCEPT_PARTIAL:
    p_int = &prob->accept_partial;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_MIN_TESTS_TO_ACCEPT:
    p_int = &prob->min_tests_to_accept;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_HIDDEN:
    p_int = &prob->hidden;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_STAND_HIDE_TIME:
    p_int = &prob->stand_hide_time;

    if (!param2 || sscanf(param2, "%d%n", &val, &n) != 1 || param2[n])
      return -SSERV_ERR_INVALID_PARAMETER;
    if (val < 0 || val > 1) return -SSERV_ERR_INVALID_PARAMETER;
    *p_int = val;
    return 0;

  case SSERV_CMD_PROB_CHANGE_ADVANCE_TO_NEXT:
    p_int = &prob->advance_to_next;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_DISABLE_CTRL_CHARS:
    p_int = &prob->disable_ctrl_chars;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_VALUER_SETS_MARKED:
    p_int = &prob->valuer_sets_marked;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_IGNORE_UNMARKED:
    p_int = &prob->ignore_unmarked;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_DISABLE_STDERR:
    p_int = &prob->disable_stderr;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_ENABLE_PROCESS_GROUP:
    p_int = &prob->enable_process_group;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_HIDE_VARIANT:
    p_int = &prob->hide_variant;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_AUTOASSIGN_VARIANTS:
    p_int = &prob->autoassign_variants;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_ENABLE_TEXT_FORM:
    p_int = &prob->enable_text_form;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_STAND_IGNORE_SCORE:
    p_int = &prob->stand_ignore_score;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_STAND_LAST_COLUMN:
    p_int = &prob->stand_last_column;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_CHECKER_REAL_TIME_LIMIT:
    p_int = &prob->checker_real_time_limit;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_INTERACTOR_TIME_LIMIT:
    p_int = &prob->interactor_time_limit;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_MAX_VM_SIZE:
    p_size = &prob->max_vm_size;

  handle_size_t:
    zval = 0;
    if (size_str_to_size_t(param2, &zval) < 0) return -SSERV_ERR_INVALID_PARAMETER;
    *p_size = zval;
    return 0;

  case SSERV_CMD_PROB_CHANGE_MAX_STACK_SIZE:
    p_size = &prob->max_stack_size;
    goto handle_size_t;

  case SSERV_CMD_PROB_CHANGE_MAX_CORE_SIZE:
    p_size = &prob->max_core_size;
    goto handle_size_t;

  case SSERV_CMD_PROB_CHANGE_MAX_FILE_SIZE:
    p_size = &prob->max_file_size;
    goto handle_size_t;

  case SSERV_CMD_PROB_CHANGE_MAX_OPEN_FILE_COUNT:
    p_int = &prob->max_open_file_count;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_MAX_PROCESS_COUNT:
    p_int = &prob->max_process_count;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_INPUT_FILE:
    PROB_ASSIGN_STRING(input_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INPUT_FILE:
    PROB_CLEAR_STRING(input_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_OUTPUT_FILE:
    PROB_ASSIGN_STRING(output_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_OUTPUT_FILE:
    PROB_CLEAR_STRING(output_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_USE_CORR:
    p_int = &prob->use_corr;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_USE_INFO:
    p_int = &prob->use_info;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_USE_TGZ:
    p_int = &prob->use_tgz;
    goto handle_boolean_1;

  case SSERV_CMD_PROB_CHANGE_TEST_DIR:
    PROB_ASSIGN_STRING(test_dir);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_DIR:
    PROB_CLEAR_STRING(test_dir);
    return 0;

  case SSERV_CMD_PROB_CHANGE_CORR_DIR:
    PROB_ASSIGN_STRING(corr_dir);
    return 0;

  case SSERV_CMD_PROB_CLEAR_CORR_DIR:
    PROB_CLEAR_STRING(corr_dir);
    return 0;

  case SSERV_CMD_PROB_CHANGE_INFO_DIR:
    PROB_ASSIGN_STRING(info_dir);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INFO_DIR:
    PROB_CLEAR_STRING(info_dir);
    return 0;

  case SSERV_CMD_PROB_CHANGE_TEST_SFX:
    PROB_ASSIGN_STRING(test_sfx);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_SFX:
    prob->test_sfx[0] = 1;
    prob->test_sfx[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TEST_PAT:
    PROB_ASSIGN_STRING(test_pat);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_PAT:
    prob->test_pat[0] = 1;
    prob->test_pat[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_CORR_SFX:
    PROB_ASSIGN_STRING(corr_sfx);
    return 0;

  case SSERV_CMD_PROB_CLEAR_CORR_SFX:
    prob->corr_sfx[0] = 1;
    prob->corr_sfx[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_CORR_PAT:
    PROB_ASSIGN_STRING(corr_pat);
    return 0;

  case SSERV_CMD_PROB_CLEAR_CORR_PAT:
    prob->corr_pat[0] = 1;
    prob->corr_pat[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_INFO_SFX:
    PROB_ASSIGN_STRING(info_sfx);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INFO_SFX:
    prob->info_sfx[0] = 1;
    prob->info_sfx[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_INFO_PAT:
    PROB_ASSIGN_STRING(info_pat);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INFO_PAT:
    prob->info_pat[0] = 1;
    prob->info_pat[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TGZ_SFX:
    PROB_ASSIGN_STRING(tgz_sfx);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TGZ_SFX:
    prob->tgz_sfx[0] = 1;
    prob->tgz_sfx[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TGZ_PAT:
    PROB_ASSIGN_STRING(tgz_pat);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TGZ_PAT:
    prob->tgz_pat[0] = 1;
    prob->tgz_pat[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TGZDIR_SFX:
    PROB_ASSIGN_STRING(tgzdir_sfx);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TGZDIR_SFX:
    prob->tgzdir_sfx[0] = 1;
    prob->tgzdir_sfx[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TGZDIR_PAT:
    PROB_ASSIGN_STRING(tgzdir_pat);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TGZDIR_PAT:
    prob->tgzdir_pat[0] = 1;
    prob->tgzdir_pat[1] = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_STANDARD_CHECKER:
    if (!param2 || !*param2) {
      PROB_CLEAR_STRING(standard_checker);
    } else if (check_str(param2, login_accept_chars) < 0) {
      return -SSERV_ERR_INVALID_PARAMETER;
    } else {
      PROB_ASSIGN_STRING(standard_checker);
    }
    return 0;

  case SSERV_CMD_PROB_CHANGE_SCORE_BONUS:
    // FIXME: check string for correctness
    PROB_ASSIGN_STRING(score_bonus);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SCORE_BONUS:
    PROB_CLEAR_STRING(score_bonus);
    return 0;

  case SSERV_CMD_PROB_CHANGE_OPEN_TESTS:
    // FIXME: check string for correctness
    PROB_ASSIGN_STRING(open_tests);
    return 0;

  case SSERV_CMD_PROB_CLEAR_OPEN_TESTS:
    PROB_CLEAR_STRING(open_tests);
    return 0;

  case SSERV_CMD_PROB_CHANGE_FINAL_OPEN_TESTS:
    PROB_ASSIGN_STRING(final_open_tests);
    return 0;

  case SSERV_CMD_PROB_CLEAR_FINAL_OPEN_TESTS:
    PROB_CLEAR_STRING(final_open_tests);
    return 0;

  case SSERV_CMD_PROB_CHANGE_CHECK_CMD:
    PROB_ASSIGN_STRING(check_cmd);
    return 0;

  case SSERV_CMD_PROB_CLEAR_CHECK_CMD:
    PROB_CLEAR_STRING(check_cmd);
    return 0;

  case SSERV_CMD_PROB_CHANGE_CHECKER_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->checker_env);
    prob->checker_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_CHECKER_ENV:
    sarray_free(prob->checker_env);
    prob->checker_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_VALUER_CMD:
    PROB_ASSIGN_STRING(valuer_cmd);
    return 0;

  case SSERV_CMD_PROB_CLEAR_VALUER_CMD:
    PROB_CLEAR_STRING(valuer_cmd);
    return 0;

  case SSERV_CMD_PROB_CHANGE_VALUER_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->valuer_env);
    prob->valuer_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_VALUER_ENV:
    sarray_free(prob->valuer_env);
    prob->valuer_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_INTERACTOR_CMD:
    PROB_ASSIGN_STRING(interactor_cmd);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INTERACTOR_CMD:
    PROB_CLEAR_STRING(interactor_cmd);
    return 0;

  case SSERV_CMD_PROB_CHANGE_INTERACTOR_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->interactor_env);
    prob->interactor_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_INTERACTOR_ENV:
    sarray_free(prob->interactor_env);
    prob->interactor_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_STYLE_CHECKER_CMD:
    PROB_ASSIGN_STRING(style_checker_cmd);
    return 0;

  case SSERV_CMD_PROB_CLEAR_STYLE_CHECKER_CMD:
    PROB_CLEAR_STRING(style_checker_cmd);
    return 0;

  case SSERV_CMD_PROB_CHANGE_STYLE_CHECKER_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->style_checker_env);
    prob->style_checker_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_STYLE_CHECKER_ENV:
    sarray_free(prob->style_checker_env);
    prob->style_checker_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_LANG_COMPILER_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->lang_compiler_env);
    prob->lang_compiler_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_LANG_COMPILER_ENV:
    sarray_free(prob->lang_compiler_env);
    prob->lang_compiler_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TEST_CHECKER_CMD:
    xfree(prob->test_checker_cmd);
    prob->test_checker_cmd = xstrdup(param2);
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_CHECKER_CMD:
    xfree(prob->test_checker_cmd);
    prob->test_checker_cmd = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TEST_CHECKER_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->test_checker_env);
    prob->test_checker_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_CHECKER_ENV:
    sarray_free(prob->test_checker_env);
    prob->test_checker_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_INIT_CMD:
    xfree(prob->init_cmd);
    prob->init_cmd = xstrdup(param2);
    return 0;

  case SSERV_CMD_PROB_CLEAR_INIT_CMD:
    xfree(prob->init_cmd);
    prob->init_cmd = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_START_CMD:
    xfree(prob->start_cmd);
    prob->start_cmd = xstrdup(param2);
    return 0;

  case SSERV_CMD_PROB_CLEAR_START_CMD:
    xfree(prob->start_cmd);
    prob->start_cmd = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_INIT_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->init_env);
    prob->init_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_INIT_ENV:
    sarray_free(prob->init_env);
    prob->init_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_START_ENV:
    if (sarray_parse(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->start_env);
    prob->start_env = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_START_ENV:
    sarray_free(prob->start_env);
    prob->start_env = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_SOLUTION_SRC:
    xfree(prob->solution_src);
    prob->solution_src = xstrdup(param2);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SOLUTION_SRC:
    xfree(prob->solution_src);
    prob->solution_src = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_SOLUTION_CMD:
    xfree(prob->solution_cmd);
    prob->solution_cmd = xstrdup(param2);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SOLUTION_CMD:
    xfree(prob->solution_cmd);
    prob->solution_cmd = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->lang_time_adj);
    prob->lang_time_adj = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ:
    sarray_free(prob->lang_time_adj);
    prob->lang_time_adj = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_LANG_TIME_ADJ_MILLIS:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->lang_time_adj_millis);
    prob->lang_time_adj_millis = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_LANG_TIME_ADJ_MILLIS:
    sarray_free(prob->lang_time_adj_millis);
    prob->lang_time_adj_millis = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_LANG_MAX_VM_SIZE:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->lang_max_vm_size);
    prob->lang_max_vm_size = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_LANG_MAX_VM_SIZE:
    sarray_free(prob->lang_max_vm_size);
    prob->lang_max_vm_size = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_LANG_MAX_STACK_SIZE:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->lang_max_stack_size);
    prob->lang_max_stack_size = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_LANG_MAX_STACK_SIZE:
    sarray_free(prob->lang_max_stack_size);
    prob->lang_max_stack_size = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_DISABLE_LANGUAGE:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->disable_language);
    prob->disable_language = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_DISABLE_LANGUAGE:
    sarray_free(prob->disable_language);
    prob->disable_language = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_ENABLE_LANGUAGE:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->enable_language);
    prob->enable_language = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_ENABLE_LANGUAGE:
    sarray_free(prob->enable_language);
    prob->enable_language = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_REQUIRE:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->require);
    prob->require = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_REQUIRE:
    sarray_free(prob->require);
    prob->require = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_PROVIDE_OK:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->provide_ok);
    prob->provide_ok = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_PROVIDE_OK:
    sarray_free(prob->provide_ok);
    prob->provide_ok = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_TEST_SETS:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->test_sets);
    prob->test_sets = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_TEST_SETS:
    sarray_free(prob->test_sets);
    prob->test_sets = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_SCORE_VIEW:
    if (sarray_parse_2(param2, &tmp_env) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    sarray_free(prob->score_view);
    prob->score_view = tmp_env;
    return 0;

  case SSERV_CMD_PROB_CLEAR_SCORE_VIEW:
    sarray_free(prob->score_view);
    prob->score_view = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_START_DATE:
    p_time = &prob->start_date;
  handle_date:;
    if (xml_parse_date(NULL, 0, 0, 0, param2, p_time) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;

  case SSERV_CMD_PROB_CLEAR_START_DATE:
    prob->start_date = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_DEADLINE:
    p_time = &prob->deadline;
    goto handle_date;

  case SSERV_CMD_PROB_CLEAR_DEADLINE:
    prob->deadline = 0;
    return 0;

  case SSERV_CMD_PROB_CHANGE_VARIANT_NUM:
    p_int = &prob->variant_num;
    goto handle_int_1;

  case SSERV_CMD_PROB_CHANGE_XML_FILE:
    PROB_ASSIGN_STRING(xml_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_XML_FILE:
    PROB_CLEAR_STRING(xml_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_ALTERNATIVES_FILE:
    PROB_ASSIGN_STRING(alternatives_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_ALTERNATIVES_FILE:
    PROB_CLEAR_STRING(alternatives_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_PLUGIN_FILE:
    PROB_ASSIGN_STRING(plugin_file);
    return 0;

  case SSERV_CMD_PROB_CLEAR_PLUGIN_FILE:
    PROB_CLEAR_STRING(plugin_file);
    return 0;

  case SSERV_CMD_PROB_CHANGE_STAND_ATTR:
    PROB_ASSIGN_STRING(stand_attr);
    return 0;

  case SSERV_CMD_PROB_CLEAR_STAND_ATTR:
    PROB_CLEAR_STRING(stand_attr);
    return 0;

  case SSERV_CMD_PROB_CHANGE_SOURCE_HEADER:
    PROB_ASSIGN_STRING(source_header);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SOURCE_HEADER:
    PROB_CLEAR_STRING(source_header);
    return 0;

  case SSERV_CMD_PROB_CHANGE_SOURCE_FOOTER:
    PROB_ASSIGN_STRING(source_footer);
    return 0;

  case SSERV_CMD_PROB_CLEAR_SOURCE_FOOTER:
    PROB_CLEAR_STRING(source_footer);
    return 0;

  case SSERV_CMD_PROB_CHANGE_NORMALIZATION:
    PROB_ASSIGN_STRING(normalization);
    return 0;

  case SSERV_CMD_PROB_CLEAR_NORMALIZATION:
    PROB_CLEAR_STRING(normalization);
    return 0;

  default:
    abort();
  }
}

static unsigned char *
strsubst(const unsigned char *str, const unsigned char *from,
         const unsigned char *to)
{
  unsigned char *p, *q;
  size_t from_len = strlen(from);
  size_t to_len = strlen(to);
  size_t str_len = strlen(str);

  if (!(p = strstr(str, from))) return 0;

  q = xmalloc(str_len - from_len + to_len + 1);
  memcpy(q, str, p - str);
  memcpy(q + (p - str), to, to_len);
  strcpy(q + (p - str) + to_len, p + from_len);
  return q;
}

static void
subst_param(unsigned char **p_param,
            int n,
            unsigned char s_from[][32], unsigned char s_to[][32])
{
  int i;
  unsigned char *t;
  unsigned char *param = *p_param;

  if (!param) return;
  for (i = 0; i < n; i++) {
    if (!(t = strsubst(param, s_from[i], s_to[i]))) continue;
    xfree(param);
    *p_param = t;
    return;
  }
}

void
super_html_fix_serve(struct sid_state *sstate,
                     int orig_id, int contest_id)
{
  unsigned char substs_from[6][32];
  unsigned char substs_to[6][32];
  struct section_global_data *global = sstate->global;
  unsigned char *s;

  if (!global) return;

  snprintf(substs_from[0], sizeof(substs_from[0]), "%06d", orig_id);
  snprintf(substs_from[1], sizeof(substs_from[0]), "%05d", orig_id);
  snprintf(substs_from[2], sizeof(substs_from[0]), "%04d", orig_id);
  snprintf(substs_from[3], sizeof(substs_from[0]), "%03d", orig_id);
  snprintf(substs_from[4], sizeof(substs_from[0]), "%02d", orig_id);
  snprintf(substs_from[5], sizeof(substs_from[0]), "%d", orig_id);
  snprintf(substs_to[0], sizeof(substs_to[0]), "%06d", contest_id);
  snprintf(substs_to[1], sizeof(substs_to[0]), "%05d", contest_id);
  snprintf(substs_to[2], sizeof(substs_to[0]), "%04d", contest_id);
  snprintf(substs_to[3], sizeof(substs_to[0]), "%03d", contest_id);
  snprintf(substs_to[4], sizeof(substs_to[0]), "%02d", contest_id);
  snprintf(substs_to[5], sizeof(substs_to[0]), "%d", contest_id);

  s = xstrdup(global->standings_file_name);
  subst_param(&s, 6, substs_from, substs_to);
  snprintf(global->standings_file_name, sizeof(global->standings_file_name),
           "%s", s);
  xfree(s);

  if (global->stand2_file_name[0]) {
    s = xstrdup(global->stand2_file_name);
    subst_param(&s, 6, substs_from, substs_to);
    snprintf(global->stand2_file_name, sizeof(global->stand2_file_name),
             "%s", s);
    xfree(s);
  }

  if (global->plog_file_name[0]) {
    s = xstrdup(global->plog_file_name);
    subst_param(&s, 6, substs_from, substs_to);
    snprintf(global->plog_file_name, sizeof(global->plog_file_name),
             "%s", s);
    xfree(s);
  }

  global->stand_ignore_after = 0;
}

static void
mkpath(unsigned char *out, const unsigned char *d, const unsigned char *n,
       const unsigned char *i)
{
  if (!n || !*n) {
    snprintf(out, sizeof(path_t), "%s/%s", d, i);
  } else if (!os_IsAbsolutePath(n)) {
    snprintf(out, sizeof(path_t), "%s/%s", d, n);
  } else {
    snprintf(out, sizeof(path_t), "%s", n);
  }
}

static int
check_test_file(
        FILE *flog,
        int n,
        const unsigned char *path,
        const unsigned char *pat,
        const unsigned char *sfx,
        int q_flag,
        int bin_flag,
        int file_group,
        int file_mode)
{
  path_t name;
  path_t name2;
  path_t full;
  path_t full2;
  struct stat stbuf;
  DIR *d;
  struct dirent *dd;
  char *test_txt = 0;
  size_t test_len = 0;
  unsigned char *d2u_txt = 0, *out_txt = 0;
  int changed = 0;
  int old_group = 0, old_mode = 0;

  if (pat && *pat) {
    snprintf(name, sizeof(name), pat, n);
  } else {
    snprintf(name, sizeof(name), "%03d%s", n, sfx);
  }

  snprintf(full, sizeof(full), "%s/%s", path, name);
  if (stat(full, &stbuf) < 0) {
    // try case-insensitive search
    name2[0] = 0;
    if (!(d = opendir(path))) {
      fprintf(flog, "Error: cannot open directory %s\n", path);
      return -1;
    }
    while ((dd = readdir(d))) {
      if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, ".."))
        continue;
      if (!strcasecmp(name, dd->d_name)) {
        snprintf(name2, sizeof(name2), dd->d_name);
        break;
      }
    }
    closedir(d);
    if (!name2[0]) {
      if (!q_flag)
        fprintf(flog, "Error: file %s not found even case insensetively\n", name);
      return 0;
    }
    snprintf(full2, sizeof(full2), "%s/%s", path, name2);
    fprintf(flog, "Info: found %s using case-insensetive search\n", name2);
    if (stat(full2, &stbuf) < 0) {
      fprintf(flog, "Error: file %s is not found. Strange!\n", full2);
      return -1;
    }
    if (!S_ISREG(stbuf.st_mode)) {
      fprintf(flog, "Error: file %s is not regular\n", full2);
      return -1;
    }
    if (rename(full2, full) < 0) {
      fprintf(flog, "Error: rename %s -> %s failed: %s\n", full2, full,
              os_ErrorMsg());
      return -1;
    }
    fprintf(flog, "Info: file renamed: %s -> %s\n", full2, full);
  } else {
    if (!S_ISREG(stbuf.st_mode)) {
      fprintf(flog, "Error: file %s is not regular\n", full);
      return -1;
    }
  }

  file_perms_get(full, &old_group, &old_mode);

  if (!bin_flag) {
    if (generic_read_file(&test_txt, 0, &test_len, 0, 0, full, 0) < 0) {
      fprintf(flog, "Error: failed to read %s\n", full);
      return -1;
    }
    if (test_len != strlen(test_txt)) {
      fprintf(flog, "Error: file %s contains NUL (\\0) bytes\n", full);
      xfree(test_txt);
      return -1;
    }
    d2u_txt = dos2unix_str(test_txt);
    if (strcmp(d2u_txt, test_txt)) {
      changed = 1;
      fprintf(flog, "Info: file %s converted from DOS to UNIX format\n", full);
    }
    xfree(test_txt); test_txt = 0;
    test_len = strlen(d2u_txt);
    if (test_len > 0 && d2u_txt[test_len - 1] != '\n') {
      changed = 1;
      out_txt = xmalloc(test_len + 2);
      strcpy(out_txt, d2u_txt);
      out_txt[test_len] = '\n';
      out_txt[test_len + 1] = 0;
      xfree(d2u_txt); d2u_txt = 0;
      fprintf(flog, "Info: file %s: final newline appended\n", full);
      test_len++;
    } else {
      out_txt = d2u_txt; d2u_txt = 0;
    }
  }

  if (changed) {
    if (generic_write_file(out_txt, test_len, KEEP_ON_FAIL, 0, full, 0) < 0) {
      fprintf(flog, "Error: write of %s failed\n", full);
      xfree(out_txt);
      return -1;
    }
    fprintf(flog, "Info: file %s successfully written\n", full);
    file_perms_set(flog, full, file_group, file_mode, old_group, old_mode);
  }

  xfree(out_txt);
  return 1;
}

static int
invoke_test_checker(
        FILE *flog,
        int n,
        const unsigned char *test_checker_cmd,
        char **test_checker_env,
        const unsigned char *tst_dir,
        const unsigned char *tst_pat,
        const unsigned char *tst_sfx,
        const unsigned char *ans_dir,
        const unsigned char *ans_pat,
        const unsigned char *ans_sfx)
{
  path_t tst_name;
  path_t tst_path;
  int retval = 0;
  char *args[4];
  unsigned char *out_text = 0;
  unsigned char *err_text = 0;

  if (!test_checker_cmd || !test_checker_cmd[0]) return 0;

  if (tst_pat && *tst_pat) {
    snprintf(tst_name, sizeof(tst_name), tst_pat, n);
  } else {
    snprintf(tst_name, sizeof(tst_name), "%03d%s", n, tst_sfx);
  }
  snprintf(tst_path, sizeof(tst_path), "%s/%s", tst_dir, tst_name);

  args[0] = (char*) test_checker_cmd;
  args[1] = NULL;

  retval = ejudge_invoke_process(args, test_checker_env, tst_dir, tst_path, NULL,
                                 1, &out_text, &err_text);
  if ((err_text && *err_text) || (out_text && *out_text) || retval != 0) {
    fprintf(flog, "%s %s\n", test_checker_cmd, tst_path);
  }
  if (err_text) {
    fprintf(flog, "%s", err_text);
    xfree(err_text); err_text = 0;
  }
  if (out_text) {
    fprintf(flog, "%s", out_text);
    xfree(out_text); out_text = 0;
  }
  if (retval >= 256) {
    fprintf(flog, "test checker process is terminated by signal %d %s\n",
            retval - 256, os_GetSignalString(retval - 256));
    retval = -1;
  } else if (retval > 0) {
    fprintf(flog, "test checker process exited with code %d\n", retval);
    retval = -1;
  }

  return retval;
}

static int
invoke_compile_process(
        FILE *flog,
        const unsigned char *cur_dir,
        const unsigned char *cmd)
{
  int retval = 0;
  unsigned char *out_text = 0, *err_text = 0;
  char *args[4];

  fprintf(flog, "Starting compilation: %s\n", cmd);

  args[0] = "/bin/sh";
  args[1] = "-c";
  args[2] = (char*) cmd;
  args[3] = 0;

  retval = ejudge_invoke_process(args, NULL, cur_dir, NULL, NULL, 1,
                                 &out_text, &err_text);
  if (err_text) {
    fprintf(flog, "%s", err_text);
    xfree(err_text); err_text = 0;
  }
  if (out_text) {
    fprintf(flog, "%s", out_text);
    xfree(out_text); out_text = 0;
  }
  
  if (!retval) {
    fprintf(flog, "process is completed successfully\n");
  } else if (retval >= 256) {
    fprintf(flog, "process is terminated by signal %d %s\n",
            retval - 256, os_GetSignalString(retval - 256));
  } else if (retval > 0) {
    fprintf(flog, "process exited with code %d\n", retval);
  }

  return retval;
}

enum
{
  CHECKER_LANG_FIRST,
  CHECKER_LANG_PAS = CHECKER_LANG_FIRST,
  CHECKER_LANG_DPR,
  CHECKER_LANG_C,
  CHECKER_LANG_CPP,

  CHECKER_LANG_LAST,
};
static const unsigned char * const supported_suffixes[] =
{
  ".pas",
  ".dpr",
  ".c",
  ".cpp",
  0,
};

static unsigned char *fpc_path = 0;
static unsigned char *dcc_path = 0;
static unsigned char *gcc_path = 0;
static unsigned char *gpp_path = 0;

static unsigned char *
get_compiler_path(
        const struct ejudge_cfg *config,
        const unsigned char *short_name,
        unsigned char *old_path)
{
  unsigned char *s = 0;
  path_t script_path;
  path_t cmd;

  if (old_path) return old_path;

  script_path[0] = 0;
  if (config->compile_home_dir) {
    snprintf(script_path, sizeof(script_path), "%s/scripts",
             config->compile_home_dir);
  }
  if (!script_path[0] && config->contests_home_dir) {
    snprintf(script_path, sizeof(script_path), "%s/compile/scripts",
             config->contests_home_dir);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!script_path[0] && config->contests_home_dir) {
    snprintf(script_path, sizeof(script_path), "%s/compile/scripts",
             EJUDGE_CONTESTS_HOME_DIR);
  }
#endif

  snprintf(cmd, sizeof(cmd), "\"%s/%s-version\" -p",
           script_path, short_name);
  if (!(s = read_process_output(cmd, 0, 0, 0))) s = xstrdup("");
  return s;
} 

static int
recompile_checker(
        const struct ejudge_cfg *config,
        FILE *f,
        const unsigned char *checker_path)
{
  struct stat stbuf1, stbuf2;
  path_t checker_src;
  path_t checker_obj;
  int need_recompile = 0, retcode = 0;
  path_t cmd;
  path_t check_dir;
  path_t filename;
  path_t filename2;
  int lang_ind, i;

  lang_ind = -1;
  for (i = CHECKER_LANG_FIRST; i < CHECKER_LANG_LAST; i++) {
    snprintf(checker_src, sizeof(checker_src), "%s%s", checker_path,
             supported_suffixes[i]);
    if (stat(checker_src, &stbuf2) < 0) continue;
    if (!S_ISREG(stbuf2.st_mode)) {
      fprintf(f, "Error: checker source %s is not a regular file\n", checker_src);
      return -1;
    }
    if (lang_ind >= 0) {
      fprintf(f, "Error: several source files (%s, %s) are found for a checker\n",
              supported_suffixes[lang_ind], supported_suffixes[i]);
      return -1;
    }
    lang_ind = i;
  }
  if (lang_ind < 0) {
    if (stat(checker_path, &stbuf1) < 0) {
      fprintf(f, "Error: checker %s does not exist and cannot be compiled\n",
              checker_path);
      return -1;
    }
    if (!S_ISREG(stbuf1.st_mode)) {
      fprintf(f, "Error: checker %s is not a regular file\n", checker_path);
      return -1;
    }
    if (access(checker_path, X_OK) < 0) {
      fprintf(f, "Error: checker %s is not executable\n", checker_path);
      return -1;
    }
    fprintf(f, "Warning: no source file or unsupported language for checker %s\n", checker_path);
    return 0;
  }

  snprintf(checker_src, sizeof(checker_src), "%s%s", checker_path,
           supported_suffixes[lang_ind]);
  // FIXME: make configurable object file suffix
  snprintf(checker_obj, sizeof(checker_obj), "%s.o", checker_path);
  if (stat(checker_path, &stbuf1) < 0) {
    fprintf(f, "Warning: checker %s does not exist\n", checker_path);
    if (stat(checker_src, &stbuf2) < 0) {
      fprintf(f, "Error: checker source %s is missing\n", checker_src);
      return -1;
    }
    need_recompile = 1;
  } else {
    if (stat(checker_src, &stbuf2) >= 0 && stbuf2.st_mtime > stbuf1.st_mtime) {
      fprintf(f, "Info: checker source %s is newer, than %s\n", checker_src,
              checker_path);
      need_recompile = 1;
    }
  }
  if (!need_recompile) return 0;

  os_rDirName(checker_path, check_dir, sizeof(check_dir));
  os_rGetBasename(checker_path, filename, sizeof(filename));
  snprintf(filename2, sizeof(filename2), "%s%s", filename,
           supported_suffixes[lang_ind]);

  switch (lang_ind) {
  case CHECKER_LANG_PAS:
    fpc_path = get_compiler_path(config, "fpc", fpc_path);
    if (!*fpc_path) {
      fprintf(f, "Error: Free Pascal support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -dEJUDGE -Fu%s/share/ejudge/testlib/fpc %s",
             fpc_path, EJUDGE_PREFIX_DIR, filename2);
    break;
  case CHECKER_LANG_DPR:
    dcc_path = get_compiler_path(config, "dcc", dcc_path);
    if (!*dcc_path) {
      fprintf(f, "Error: Delphi (Kylix) support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -DEJUDGE -U%s/share/ejudge/testlib/delphi %s",
             dcc_path, EJUDGE_PREFIX_DIR, filename2);
    break;
  case CHECKER_LANG_C:
    gcc_path = get_compiler_path(config, "gcc", gcc_path);
    if (!*gcc_path) {
      fprintf(f, "Error: GNU C support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -DEJUDGE -std=gnu99 -O2 -Wall -I%s/include/ejudge -L%s/lib -Wl,--rpath,%s/lib %s -o %s -lchecker -lm", gcc_path, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, filename2, filename);
    break;
  case CHECKER_LANG_CPP:
    gpp_path = get_compiler_path(config, "g++", gpp_path);
    if (!*gpp_path) {
      fprintf(f, "Error: GNU C++ support is not configured\n");
      return -1;
    }
    snprintf(cmd, sizeof(cmd), "%s -DEJUDGE -O2 -Wall -I%s/include/ejudge -L%s/lib -Wl,--rpath,%s/lib %s -o %s -lchecker -lm", gpp_path, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, EJUDGE_PREFIX_DIR, filename2, filename);
    break;

  default:
    abort();
  }

  // remove old executable and object file
  unlink(checker_obj);
  unlink(checker_path);

  fprintf(f, "Info: using command line %s\n", cmd);
  if ((retcode = invoke_compile_process(f, check_dir, cmd)) < 0) {
    fprintf(f, "Error: failed to start the compiler\n");
    return -1;
  } else if (retcode > 0) {
    fprintf(f, "Error: compiler exit code %d\n", retcode);
    return -1;
  }
  if (stat(checker_path, &stbuf1)) {
    fprintf(f, "Error: checker is not created by the compiler\n");
    return -1;
  } else {
    fprintf(f, "Info: checker %s is recompiled\n", filename);
  }
  return 0;
}

static int
invoke_make(
        FILE *flog,
        const struct ejudge_cfg *config,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant)
{
  path_t makefile_path;
  path_t problem_dir;
  struct stat stbuf;
  int r;
  unsigned char cmd[8192];

  get_advanced_layout_path(problem_dir, sizeof(problem_dir), global,
                           prob, NULL, variant);
  if (access(problem_dir, R_OK | X_OK) < 0) {
    fprintf(flog, "Error: problem directory %s does not exist or is not accessible\n", problem_dir);
    return -1;
  }
  snprintf(makefile_path, sizeof(makefile_path), "%s/Makefile", problem_dir);
  if (stat(makefile_path, &stbuf) < 0) {
    fprintf(flog, "Info: Makefile in %s does not exist\n", problem_dir);
    return 0;
  }

#if defined EJUDGE_LOCAL_DIR
  snprintf(cmd, sizeof(cmd), "make EJUDGE_PREFIX_DIR=\"%s\" EJUDGE_CONTESTS_HOME_DIR=\"%s\" EJUDGE_LOCAL_DIR=\"%s\" check_settings", EJUDGE_PREFIX_DIR, EJUDGE_CONTESTS_HOME_DIR, EJUDGE_LOCAL_DIR);
#else
  snprintf(cmd, sizeof(cmd), "make EJUDGE_PREFIX_DIR=\"%s\" EJUDGE_CONTESTS_HOME_DIR=\"%s\" check_settings", EJUDGE_PREFIX_DIR, EJUDGE_CONTESTS_HOME_DIR);
#endif
  r = invoke_compile_process(flog, problem_dir, cmd);
  if (r < 0) {
    fprintf(flog, "Error: failed to start make\n");
    return -1;
  } else if (r > 0) {
    fprintf(flog, "Error: make failed with exit code %d\n", r);
    return -1;
  }
  // check for checker
  if (!prob->standard_checker[0]) {
    get_advanced_layout_path(cmd, sizeof(cmd), global, prob,
                             prob->check_cmd, variant);
    if (access(cmd, X_OK) < 0) {
      fprintf(flog, "Error: checker executable %s is not created\n", cmd);
      return -1;
    }
  }
  // check for valuer
  if (prob->valuer_cmd[0]) {
    get_advanced_layout_path(cmd, sizeof(cmd), global, prob,
                             prob->valuer_cmd, variant);
    if (access(cmd, X_OK) < 0) {
      fprintf(flog, "Error: valuer executable %s is not created\n", cmd);
      return -1;
    }
  }
  // check for interactor
  if (prob->interactor_cmd[0]) {
    // FIXME: complete
  }
  // check for style checker
  if (prob->style_checker_cmd[0]) {
    // FIXME: complete
  }
  // check for test checker
  if (prob->test_checker_cmd && prob->test_checker_cmd[0]) {
    get_advanced_layout_path(cmd, sizeof(cmd), global, prob,
                             prob->test_checker_cmd, variant);
    if (access(cmd, X_OK) < 0) {
      fprintf(flog, "Error: test checker executable %s is not created\n", cmd);
      return -1;
    }
  }

  return 1;
}

static int
check_test_score(FILE *flog, int ntests, int test_score, int full_score,
                 const unsigned char *test_score_list)
{
  int *scores;
  int i, sum;
  int index, score, n, tn = 1, was_indices = 0;
  const unsigned char *s;

  ASSERT(ntests >= 0);

  if (test_score < 0) {
    fprintf(flog, "Error: test_score is negative\n");
    return -1;
  }

  XALLOCA(scores, ntests + 1);
  for (i = 0; i <= ntests; i++)
    scores[i] = test_score;

  if (test_score_list && *test_score_list) {
    s = test_score_list;

    while (1) {
      while (*s > 0 && *s <= ' ') s++;
      if (!*s) break;

      if (*s == '[') {
        if (sscanf(s, "[ %d ] %d%n", &index, &score, &n) != 2) {
          fprintf(flog, "Error: invalid test_score_list specification \"%s\"\n",
                  test_score_list);
          return -1;
        }
        if (index < 1 || index > ntests) {
          fprintf(flog, "Error: test index %d is out of range\n", index);
          return -1;
        }
        if (score < 0) {
          fprintf(flog, "Error: score %d is invalid\n", score);
          return -1;
        }
        tn = index;
        was_indices = 1;
      } else {
        if (sscanf(s, "%d%n", &score, &n) != 1) {
          fprintf(flog, "Error: invalid test_score_list specification \"%s\"\n",
                  test_score_list);
          return -1;
        }
        if (score < 0) {
          fprintf(flog, "Error: score %d is invalid\n", score);
          return -1;
        }
        if (tn > ntests) {
          fprintf(flog, "Error: too many scores specified\n");
          return -1;
        }
      }
      scores[tn++] = score;
      s += n;
    }

    if (!was_indices && tn <= ntests) {
      fprintf(flog, "Info: test_score_list defines only %d tests\n", tn - 1);
    }
  }

  for (i = 1, sum = 0; i <= ntests; i++)
    sum += scores[i];

  if (sum > full_score) {
    fprintf(flog, "Error: summ of all test scores (%d) is greater than full_score (%d)\n", sum, full_score);
    return -1;
  } else if (sum < full_score) {
    fprintf(flog, "Warning: summ of all test scores (%d) is less than full_score (%d)\n", sum, full_score);
  }

  return 0;
}

int
super_html_new_check_tests(
        FILE *flog,
        const struct ejudge_cfg *config,
        struct sid_state *sstate)
{
  int retval = -1;
  path_t conf_path;
  path_t g_test_path;
  path_t g_corr_path;
  path_t g_info_path;
  path_t g_tgz_path;
  path_t g_checker_path;
  path_t test_path, corr_path, info_path, checker_path;
  path_t v_test_path, v_corr_path, v_info_path, v_checker_path;
  struct contest_desc *cnts;
  struct section_global_data *global;
  struct section_problem_data *prob, *abstr;
  struct section_problem_data *tmp_prob = 0;
  int i, j, k, variant;
  struct stat stbuf;
  int total_tests = 0, v_total_tests = 0;
  int file_group, file_mode;
  int already_compiled = 0;
  path_t test_checker_cmd;

  if (sstate->serve_parse_errors) {
    fprintf(flog, "%s\n", sstate->serve_parse_errors);
    goto cleanup;
  }

  if (!sstate->edited_cnts || !sstate->global) {
    fprintf(flog, "The tests cannot be checked: No contest\n");
    goto cleanup;
  }

  cnts = sstate->edited_cnts;
  global = sstate->global;

  file_group = file_perms_parse_group(cnts->file_group);
  file_mode = file_perms_parse_mode(cnts->file_mode);

  mkpath(conf_path, cnts->root_dir, cnts->conf_dir, DFLT_G_CONF_DIR);
  mkpath(g_test_path, conf_path, global->test_dir, DFLT_G_TEST_DIR);
  mkpath(g_corr_path, conf_path, global->corr_dir, DFLT_G_CORR_DIR);
  mkpath(g_info_path, conf_path, global->info_dir, DFLT_G_INFO_DIR);
  mkpath(g_tgz_path, conf_path, global->tgz_dir, DFLT_G_TGZ_DIR);
  mkpath(g_checker_path, conf_path, global->checker_dir, DFLT_G_CHECKER_DIR);

  for (i = 1; i < sstate->prob_a; i++) {
    if (!(prob = sstate->probs[i])) continue;
    already_compiled = 0;

    if (prob->internal_name && prob->internal_name[0] > ' ') {
      fprintf(flog, "*** Checking problem %s (%s) ***\n", prob->short_name, prob->internal_name);
    } else {
      fprintf(flog, "*** Checking problem %s ***\n", prob->short_name);
    }
    if (prob->disable_testing > 0) {
      fprintf(flog, "Testing is disabled, skipping\n");
      continue;
    }

    abstr = 0;
    if (prob->super[0]) {
      for (j = 0; j < sstate->aprob_u; j++)
        if (!strcmp(prob->super, sstate->aprobs[j]->short_name))
          break;
      if (j < sstate->aprob_u)
        abstr = sstate->aprobs[j];
      if (!abstr) {
        fprintf(flog, "Error: no abstract checker for problem `%s'\n",
                prob->short_name);
        goto cleanup;
      }
    }

    tmp_prob = prepare_problem_free(tmp_prob);
    tmp_prob = prepare_copy_problem(prob);
    prepare_set_prob_value(CNTSPROB_type, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_xml_file, tmp_prob, abstr, global);

    if (tmp_prob->type == PROB_TYPE_SELECT_ONE && tmp_prob->xml_file[0]) {
      fprintf(flog, "Select-one XML-specified problem, skipping\n");
      continue;
    }

    prepare_set_prob_value(CNTSPROB_normalization, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_stdin, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_stdout, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_combined_stdin, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_combined_stdout, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_input_file, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_output_file, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_scoring_checker, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_interactive_valuer, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_manual_checking, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_examinator_num, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_check_presentation, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_binary_input, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_binary, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_ignore_exit_code, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_valuer_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_interactor_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_style_checker_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_checker_cmd, tmp_prob, abstr, global);
    //prepare_set_prob_value(CNTSPROB_test_checker_env, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_dir, tmp_prob, abstr, 0);
    prepare_set_prob_value(CNTSPROB_use_corr, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_sfx, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_pat, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_test_score, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_full_score, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_full_user_score, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_solution_cmd, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_solution_src, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_source_header, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_source_footer, tmp_prob, abstr, global);
    mkpath(test_path, g_test_path, tmp_prob->test_dir, "");
    if (tmp_prob->use_corr) {
      prepare_set_prob_value(CNTSPROB_corr_dir, tmp_prob, abstr, 0);
      prepare_set_prob_value(CNTSPROB_corr_sfx, tmp_prob, abstr, global);
      prepare_set_prob_value(CNTSPROB_corr_pat, tmp_prob, abstr, global);
      mkpath(corr_path, g_corr_path, tmp_prob->corr_dir, "");
    }
    prepare_set_prob_value(CNTSPROB_use_info, tmp_prob, abstr, global);
    prepare_set_prob_value(CNTSPROB_use_tgz, tmp_prob, abstr, global);
    if (tmp_prob->use_info) {
      prepare_set_prob_value(CNTSPROB_info_dir, tmp_prob, abstr, 0);
      prepare_set_prob_value(CNTSPROB_info_sfx, tmp_prob, abstr, global);
      prepare_set_prob_value(CNTSPROB_info_pat, tmp_prob, abstr, global);
      mkpath(info_path, g_info_path, tmp_prob->info_dir, "");
    }
    checker_path[0] = 0;
    if (!tmp_prob->standard_checker[0]) {
      prepare_set_prob_value(CNTSPROB_check_cmd, tmp_prob, abstr, 0);
      if (global->advanced_layout > 0) {
        get_advanced_layout_path(checker_path, sizeof(checker_path),
                                 global, tmp_prob, tmp_prob->check_cmd, -1);
      } else {
        mkpath(checker_path, g_checker_path, tmp_prob->check_cmd, "");
      }
    }

    if (global->advanced_layout > 0) {
      if (prob->variant_num <= 0) {
        if (build_generate_makefile(flog, config, cnts, NULL, sstate, global, tmp_prob, 0) < 0)
          goto cleanup;
        if ((j = invoke_make(flog, config, global, tmp_prob, -1)) < 0)
          goto cleanup;
      } else {
        for (variant = 1; variant <= prob->variant_num; ++variant) {
          if (build_generate_makefile(flog, config, cnts, NULL, sstate, global, tmp_prob, variant) < 0)
            goto cleanup;
          if ((j = invoke_make(flog, config, global, tmp_prob, variant)) < 0)
            goto cleanup;
        }
      }
      continue;
    }

    if (!tmp_prob->standard_checker[0] && !already_compiled) {
      if (prob->variant_num <= 0) {
        if (recompile_checker(config, flog, checker_path) < 0)
          goto cleanup;
      } else {
        for (variant = 1; variant <= prob->variant_num; variant++) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(v_checker_path, sizeof(v_checker_path),
                                     global, tmp_prob, NULL, variant);
          } else {
            snprintf(v_checker_path, sizeof(v_checker_path), "%s-%d",
                     checker_path, variant);
          }
          if (recompile_checker(config, flog, v_checker_path) < 0)
            goto cleanup;
        }
      }
    }

    if (prob->type == PROB_TYPE_TESTS) goto skip_tests;

    // check tests
    if (prob->variant_num <= 0) {
      if (global->advanced_layout > 0) {
        get_advanced_layout_path(test_path, sizeof(test_path), global,
                                 tmp_prob, DFLT_P_TEST_DIR, -1);
      }
      if (stat(test_path, &stbuf) < 0) {
        fprintf(flog, "Error: test directory %s does not exist\n", test_path);
        goto cleanup;
      }
      if (!S_ISDIR(stbuf.st_mode)) {
        fprintf(flog, "Error: test directory %s is not a directory\n", test_path);
        goto cleanup;
      }
      if (tmp_prob->use_corr) {
        if (global->advanced_layout > 0) {
          get_advanced_layout_path(corr_path, sizeof(corr_path), global,
                                   tmp_prob, DFLT_P_CORR_DIR, -1);
        }
        if (stat(corr_path, &stbuf) < 0) {
          fprintf(flog, "Error: test directory %s does not exist\n", corr_path);
          goto cleanup;
        }
        if (!S_ISDIR(stbuf.st_mode)) {
          fprintf(flog, "Error: test directory %s is not a directory\n", corr_path);
          goto cleanup;
        }
      }
      if (tmp_prob->use_info) {
        if (global->advanced_layout > 0) {
          get_advanced_layout_path(info_path, sizeof(info_path), global,
                                   tmp_prob, DFLT_P_INFO_DIR, -1);
        }
        if (stat(info_path, &stbuf) < 0) {
          fprintf(flog, "Error: test directory %s does not exist\n", info_path);
          goto cleanup;
        }
        if (!S_ISDIR(stbuf.st_mode)) {
          fprintf(flog, "Error: test directory %s is not a directory\n", info_path);
          goto cleanup;
        }
      }

      test_checker_cmd[0] = 0;
      if (tmp_prob->test_checker_cmd && tmp_prob->test_checker_cmd[0]) {
        if (global->advanced_layout > 0) {
          get_advanced_layout_path(test_checker_cmd, sizeof(test_checker_cmd),
                                   global, tmp_prob,
                                   tmp_prob->test_checker_cmd, -1);
        } else if (os_IsAbsolutePath(tmp_prob->test_checker_cmd)) {
          snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s",
                   tmp_prob->test_checker_cmd);
        } else {
          snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s/%s",
                   global->checker_dir, tmp_prob->test_checker_cmd);
        }
        if (access(test_checker_cmd, X_OK) < 0) {
          fprintf(flog, "Error: test checker %s does not exist or non-executable", test_checker_cmd);
          goto cleanup;
        }
      }

      total_tests = 1;
      while (1) {
        k = check_test_file(flog, total_tests, test_path,
                            tmp_prob->test_pat, tmp_prob->test_sfx, 1,
                            tmp_prob->binary_input, file_group, file_mode);
        if (k < 0) goto cleanup;
        if (!k) break;
        total_tests++;
      }
      total_tests--;
      if (!total_tests) {
        fprintf(flog, "Error: no tests defined for the problem\n");
        goto cleanup;
      }
      if (tmp_prob->type > 0 && total_tests != 1) {
        fprintf(flog, "Error: output-only problem must have only one test\n");
        goto cleanup;
      }
      fprintf(flog, "Info: assuming, that there are %d tests for this problem\n",
              total_tests);
      
      for (j = 1; j <= total_tests; j++) {
        if (tmp_prob->use_corr
            && check_test_file(flog, j, corr_path, tmp_prob->corr_pat,
                               tmp_prob->corr_sfx, 0, tmp_prob->binary_input,
                               file_group, file_mode) <= 0)
          goto cleanup;
        if (tmp_prob->use_info
            && check_test_file(flog, j, info_path, tmp_prob->info_pat,
                               tmp_prob->info_sfx, 0, 0, file_group,
                               file_mode) <= 0)
          goto cleanup;

        if (invoke_test_checker(flog, j, test_checker_cmd,
                                tmp_prob->test_checker_env,
                                test_path, tmp_prob->test_pat,
                                tmp_prob->test_sfx,
                                corr_path, tmp_prob->corr_pat,
                                tmp_prob->corr_sfx) < 0)
          goto cleanup;
      }

      if (tmp_prob->use_corr
          && check_test_file(flog, j, corr_path, tmp_prob->corr_pat,
                             tmp_prob->corr_sfx, 1, tmp_prob->binary_input,
                             file_group, file_mode) != 0) {
        fprintf(flog, "Error: there is answer file for test %d, but no data file\n", j);
        goto cleanup;
      }
      if (tmp_prob->use_info
          && check_test_file(flog, j, info_path, tmp_prob->info_pat,
                             tmp_prob->info_sfx, 1, 0,
                             file_group, file_mode) != 0) {
        fprintf(flog, "Error: there is test info file for test %d, but no data file\n", j);
        goto cleanup;
      }
    } else {
      for (variant = 1; variant <= prob->variant_num; variant++) {
        if (global->advanced_layout > 0) {
          get_advanced_layout_path(v_test_path, sizeof(v_test_path), global,
                                   tmp_prob, DFLT_P_TEST_DIR, variant);
        } else {
          snprintf(v_test_path, sizeof(v_test_path), "%s-%d", test_path,
                   variant);
        }
        if (stat(v_test_path, &stbuf) < 0) {
          fprintf(flog, "Error: test directory %s does not exist\n", v_test_path);
          goto cleanup;
        }
        if (!S_ISDIR(stbuf.st_mode)) {
          fprintf(flog, "Error: test directory %s is not a directory\n", v_test_path);
          goto cleanup;
        }
        if (tmp_prob->use_corr) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(v_corr_path, sizeof(v_corr_path), global,
                                     tmp_prob, DFLT_P_INFO_DIR, variant);
          } else {
            snprintf(v_corr_path, sizeof(v_corr_path), "%s-%d", corr_path,
                     variant);
          }
          if (stat(v_corr_path, &stbuf) < 0) {
            fprintf(flog, "Error: test directory %s does not exist\n", v_corr_path);
            goto cleanup;
          }
          if (!S_ISDIR(stbuf.st_mode)) {
            fprintf(flog, "Error: test directory %s is not a directory\n", v_corr_path);
            goto cleanup;
          }
        }
        if (tmp_prob->use_info) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(v_info_path, sizeof(v_info_path), global,
                                     tmp_prob, DFLT_P_INFO_DIR, variant);
          } else {
            snprintf(v_info_path, sizeof(v_info_path), "%s-%d", info_path,
                     variant);
          }
          if (stat(v_info_path, &stbuf) < 0) {
            fprintf(flog, "Error: test directory %s does not exist\n", v_info_path);
            goto cleanup;
          }
          if (!S_ISDIR(stbuf.st_mode)) {
            fprintf(flog, "Error: test directory %s is not a directory\n", v_info_path);
            goto cleanup;
          }
        }

        test_checker_cmd[0] = 0;
        if (tmp_prob->test_checker_cmd && tmp_prob->test_checker_cmd[0]) {
          if (global->advanced_layout > 0) {
            get_advanced_layout_path(test_checker_cmd, sizeof(test_checker_cmd),
                                     global, tmp_prob,
                                     tmp_prob->test_checker_cmd, variant);
          } else if (os_IsAbsolutePath(tmp_prob->test_checker_cmd)) {
            snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s-%d",
                     tmp_prob->test_checker_cmd, variant);
          } else {
            snprintf(test_checker_cmd, sizeof(test_checker_cmd), "%s/%s-%d",
                     global->checker_dir, tmp_prob->test_checker_cmd, variant);
          }
          if (access(test_checker_cmd, X_OK) < 0) {
            fprintf(flog, "Error: test checker %s does not exist or non-executable", test_checker_cmd);
            goto cleanup;
          }
        }

        total_tests = 1;
        while (1) {
          k = check_test_file(flog, total_tests, v_test_path,
                              tmp_prob->test_pat, tmp_prob->test_sfx, 1,
                              tmp_prob->binary_input, file_group, file_mode);
          if (k < 0) goto cleanup;
          if (!k) break;
          total_tests++;
        }
        total_tests--;
        if (!total_tests) {
          fprintf(flog, "Error: no tests defined for the problem\n");
          goto cleanup;
        }
        if (tmp_prob->type > 0 && total_tests != 1) {
          fprintf(flog, "Error: output-only problem must have only one test\n");
          goto cleanup;
        }
        if (variant == 1) {
          fprintf(flog, "Info: assuming, that there are %d tests for this problem\n",
                  total_tests);
          v_total_tests = total_tests;
        } else {
          if (v_total_tests != total_tests) {
            fprintf(flog, "Error: variant 1 defines %d tests, but variant %d defines %d tests\n", v_total_tests, variant, total_tests);
            goto cleanup;
          }
        }
      
        for (j = 1; j <= total_tests; j++) {
          if (tmp_prob->use_corr
              && check_test_file(flog, j, v_corr_path, tmp_prob->corr_pat,
                                 tmp_prob->corr_sfx, 0, tmp_prob->binary_input,
                                 file_group, file_mode) <= 0)
            goto cleanup;
          if (tmp_prob->use_info
              && check_test_file(flog, j, v_info_path, tmp_prob->info_pat,
                                 tmp_prob->info_sfx, 0, 0, file_group,
                                 file_mode) <= 0)
            goto cleanup;

          if (invoke_test_checker(flog, j, test_checker_cmd,
                                  tmp_prob->test_checker_env,
                                  v_test_path, tmp_prob->test_pat,
                                  tmp_prob->test_sfx,
                                  v_corr_path, tmp_prob->corr_pat,
                                  tmp_prob->corr_sfx) < 0)
            goto cleanup;
        }

        if (tmp_prob->use_corr
            && check_test_file(flog, j, v_corr_path, tmp_prob->corr_pat,
                               tmp_prob->corr_sfx, 1, tmp_prob->binary_input,
                               file_group, file_mode) != 0) {
          fprintf(flog, "Error: there is answer file for test %d, but no data file, variant %d\n", j, variant);
          goto cleanup;
        }
        if (tmp_prob->use_info
            && check_test_file(flog, j, v_info_path, tmp_prob->info_pat,
                               tmp_prob->info_sfx, 1, 0, file_group,
                               file_mode) != 0) {
          fprintf(flog, "Error: there is test info file for test %d, but no data file, variant %d\n", j, variant);
          goto cleanup;
        }
      }
    }

    if (global->score_system != SCORE_ACM
        && global->score_system != SCORE_MOSCOW) {
      if (check_test_score(flog, total_tests, tmp_prob->test_score,
                           tmp_prob->full_score, tmp_prob->test_score_list) < 0)
        goto cleanup;
    }
  }

skip_tests:
  retval = 0;

cleanup:
  tmp_prob = prepare_problem_free(tmp_prob);

  return retval;
}

static int
vmap_sort_func(const void *v1, const void *v2)
{
  const struct variant_map_item *p1 = (typeof(p1)) v1;
  const struct variant_map_item *p2 = (typeof(p2)) v2;

  if (p1->user_id > 0 && p2->user_id > 0) {
    if (p1->user_id < p2->user_id) return -1;
    if (p1->user_id > p2->user_id) return 1;
    return 0;
  }
  if (p1->user_id > 0) return -1;
  if (p2->user_id > 0) return 1;
  return strcmp(p1->login, p2->login);
}

int
super_html_update_variant_map(FILE *flog, int contest_id,
                              struct userlist_clnt *server_conn,
                              const struct contest_desc *cnts,
                              struct section_global_data *global,
                              int total_probs,
                              struct section_problem_data **probs)
{
  int r;
  unsigned char *xml_text = 0;
  struct userlist_list *users = 0;
  path_t conf_dir;
  path_t variant_file;
  struct stat stbuf;
  int var_prob_num, i, n, j, uid;
  struct variant_map *vmap = 0;
  int *tvec = 0, *new_map, *new_rev_map;
  struct userlist_user *user;
  struct userlist_user_info *ui;

  if (!cnts->root_dir && !cnts->root_dir[0]) {
    fprintf(flog, "update_variant_map: contest root_dir is not set");
    goto failed;
  }
  if (!os_IsAbsolutePath(cnts->root_dir)) {
    fprintf(flog, "update_variant_map: contest root_dir is not absolute");
    goto failed;
  }

  if (!global->variant_map) {
    if (!cnts->conf_dir || !cnts->conf_dir[0]) {
      snprintf(conf_dir, sizeof(conf_dir), "%s/conf", cnts->root_dir);
    } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
      snprintf(conf_dir, sizeof(conf_dir), "%s/%s", cnts->root_dir, cnts->conf_dir);
    } else {
      snprintf(conf_dir, sizeof(conf_dir), "%s", cnts->conf_dir);
    }

    if (!global->variant_map_file[0]) {
      snprintf(global->variant_map_file, sizeof(global->variant_map_file),
               "variant.map");
    }

    if (!os_IsAbsolutePath(global->variant_map_file)) {
      snprintf(variant_file, sizeof(variant_file), "%s/%s", conf_dir,
               global->variant_map_file);
    } else {
      snprintf(variant_file, sizeof(variant_file), "%s", global->variant_map_file);
    }

    if (stat(variant_file, &stbuf) < 0) {
      XCALLOC(global->variant_map, 1);
    } else {
      if (!S_ISREG(stbuf.st_mode)) {
        fprintf(flog, "update_variant_map: variant map file %s is not regular file\n",
                variant_file);
        goto failed;
      }

      if (!(global->variant_map = variant_map_parse(flog, 0, variant_file)))
        goto failed;
    }
  }

  if (!(vmap = global->variant_map)) {
    fprintf(flog, "update_variant_map: variant map is not set");
    goto failed;
  }

  // remap problems, if necessary
  for (var_prob_num = 0, i = 1; i < total_probs; i++)
    if (probs[i] && probs[i]->variant_num > 0)
      var_prob_num++;

  if (!var_prob_num) {
    fprintf(flog, "update_variant_map: no variant problems");
    goto failed;
  }

  if (vmap->prob_map) {
    ASSERT(vmap->prob_map_size > 0);
    ASSERT(vmap->prob_rev_map_size > 0);
    ASSERT(vmap->prob_rev_map);
    // update forward and reverse mappings
    XCALLOC(new_map, total_probs);
    memset(new_map, -1, sizeof(new_map[0]) * total_probs);
    XCALLOC(new_rev_map, var_prob_num);
    for (i = 1, j = 0; i < total_probs; i++)
      if (probs[i] && probs[i]->variant_num > 0) {
        new_map[i] = j;
        new_rev_map[j] = i;
        j++;
      }
    for (i = 0; i < vmap->u; i++) {
      XCALLOC(tvec, var_prob_num);
      ASSERT(vmap->v[i].var_num == vmap->prob_rev_map_size);
      for (j = 0; j < vmap->prob_rev_map_size; j++) {
        n = vmap->prob_rev_map[j];
        if (n > 0 && n < total_probs && probs[n] && probs[n]->variant_num > 0)
          tvec[new_map[n]] = vmap->v[i].variants[j];
      }
      xfree(vmap->v[i].variants);
      vmap->v[i].var_num = var_prob_num;
      vmap->v[i].variants = tvec;
    }
    xfree(vmap->prob_map);
    xfree(vmap->prob_rev_map);
    vmap->prob_map = new_map;
    vmap->prob_map_size = total_probs;
    vmap->prob_rev_map = new_rev_map;
    vmap->prob_rev_map_size = var_prob_num;
  } else if (vmap->var_prob_num > 0) {
    // reallocate new array for each entry
    for (i = 0; i < vmap->u; i++) {
      if (vmap->v[i].var_num != var_prob_num) {
        XCALLOC(tvec, var_prob_num);
        if (vmap->v[i].var_num > 0) {
          n = vmap->v[i].var_num;
          if (n > var_prob_num) n = var_prob_num;
          memcpy(tvec, vmap->v[i].variants, n * sizeof(tvec[0]));
          xfree(vmap->v[i].variants);
        }
        vmap->v[i].var_num = var_prob_num;
        vmap->v[i].variants = tvec;
      }
    }
    // create forward and reverse mappings
    vmap->prob_map_size = total_probs;
    XCALLOC(vmap->prob_map, total_probs);
    memset(vmap->prob_map, -1, sizeof(vmap->prob_map[0]) * total_probs);
    vmap->prob_rev_map_size = var_prob_num;
    XCALLOC(vmap->prob_rev_map, var_prob_num);
    for (i = 1, j = 0; i < total_probs; i++)
      if (probs[i] && probs[i]->variant_num > 0) {
        vmap->prob_map[i] = j;
        vmap->prob_rev_map[j] = i;
        j++;
      }
  } else {
    // allocate new array
    for (i = 0; i < vmap->u; i++) {
      vmap->v[i].var_num = var_prob_num;
      XCALLOC(vmap->v[i].variants, var_prob_num);
    }
    // create forward and reverse mappings
    vmap->prob_map_size = total_probs;
    XCALLOC(vmap->prob_map, total_probs);
    memset(vmap->prob_map, -1, sizeof(vmap->prob_map[0]) * total_probs);
    vmap->prob_rev_map_size = var_prob_num;
    XCALLOC(vmap->prob_rev_map, var_prob_num);
    for (i = 1, j = 0; i < total_probs; i++)
      if (probs[i] && probs[i]->variant_num > 0) {
        vmap->prob_map[i] = j;
        vmap->prob_rev_map[j] = i;
        j++;
      }
  }

  if ((r = userlist_clnt_list_all_users(server_conn, ULS_LIST_ALL_USERS,
                                        contest_id, &xml_text)) < 0) {
    fprintf(flog, "update_variant_map: cannot get list of participants\n");
    goto failed;
  }
  if (!(users = userlist_parse_str(xml_text))) {
    fprintf(flog, "update_variant_map: parsing of XML file failed\n");
    goto failed;
  }
  xfree(xml_text); xml_text = 0;

  // find registered users, which are not in the variant map
  for (uid = 1; uid < users->user_map_size; uid++) {
    if (!(user = users->user_map[uid])) continue;
    ui = user->cnts0;
    if (!user->login || !user->login[0]) continue;
    for (i = 0; i < vmap->u; i++)
      if (!strcmp(user->login, vmap->v[i].login))
        break;
    if (i < vmap->u) {
      vmap->v[i].user_id = uid;
      if (vmap->v[i].name && ui && ui->name) {
        if (strcmp(vmap->v[i].name, ui->name)) {
          xfree(vmap->v[i].name);
          vmap->v[i].name = xstrdup(ui->name);
        }
      } else if (ui && ui->name) {
        vmap->v[i].name = xstrdup(ui->name);
      } else {
        xfree(vmap->v[i].name);
        vmap->v[i].name = 0;
      }
      continue;
    }
    if (vmap->u >= vmap->a) {
      if (!vmap->a) vmap->a = 32;
      vmap->a *= 2;
      vmap->v = (typeof(vmap->v)) xrealloc(vmap->v,
                                           vmap->a * sizeof(vmap->v[0]));
    }
    memset(&vmap->v[vmap->u], 0, sizeof(vmap->v[vmap->u]));
    vmap->v[vmap->u].login = xstrdup(user->login);
    vmap->v[vmap->u].user_id = uid;
    vmap->v[vmap->u].var_num = vmap->prob_rev_map_size;
    vmap->v[vmap->u].name = 0;
    if (ui && ui->name) vmap->v[vmap->u].name = xstrdup(ui->name);
    XCALLOC(vmap->v[vmap->u].variants, vmap->prob_rev_map_size);
    vmap->u++;
  }
  userlist_free(&users->b); users = 0;

  // sort the entries by the user_id
  qsort(vmap->v, vmap->u, sizeof(vmap->v[0]), vmap_sort_func);

  return 0;

 failed:
  xfree(xml_text);
  if (users) userlist_free(&users->b);
  return -1;
}

int
super_html_variant_param(struct sid_state *sstate, int cmd,
                         int map_i, const unsigned char *param2,
                         int param3, int param4)
{
  struct variant_map *vmap = 0;
  const unsigned char *s;
  int n, total, i;
  int *vars = 0;
  struct section_problem_data *prob = 0;

  if (!sstate || !sstate->global) return -SSERV_ERR_INVALID_PARAMETER;
  if (!(vmap = sstate->global->variant_map)) return -SSERV_ERR_INVALID_PARAMETER;
  if (map_i < 0 || map_i >= vmap->u) return -SSERV_ERR_INVALID_PARAMETER;
  if (!sstate->prob_a || !sstate->probs) return -SSERV_ERR_INVALID_PARAMETER;

  s = param2;
  if (sscanf(s, "%d%n", &total, &n) != 1) return -SSERV_ERR_INVALID_PARAMETER;
  s += n;
  if (total < 0 || total != vmap->prob_rev_map_size)
    return -SSERV_ERR_INVALID_PARAMETER;
  XALLOCAZ(vars, total);
  for (i = 0; i < total; i++) {
    if (sscanf(s, "%d%n", &vars[i], &n) != 1) return -SSERV_ERR_INVALID_PARAMETER;
    s += n;
    if (vars[i] < 0 || vmap->prob_rev_map[i] <= 0
        || vmap->prob_rev_map[i] >= sstate->prob_a
        || !(prob = sstate->probs[vmap->prob_rev_map[i]]))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (prob->variant_num <= 0 || vars[i] > prob->variant_num)
      return -SSERV_ERR_INVALID_PARAMETER;
  }

  switch (cmd) {
  case SSERV_CMD_PROB_DELETE_VARIANTS:
    if (vmap->v[map_i].user_id > 0) {
      for (i = 0; i < total; i++)
        vmap->v[map_i].variants[i] = 0;
    } else {
      xfree(vmap->v[map_i].variants);
      xfree(vmap->v[map_i].login);
      xfree(vmap->v[map_i].name);
      if (map_i < vmap->u - 1)
        memmove(&vmap->v[map_i], &vmap->v[map_i + 1],
                (vmap->u - map_i - 1) * sizeof(vmap->v[0]));
      vmap->u--;
    }
  case SSERV_CMD_PROB_CHANGE_VARIANTS:
    for (i = 0; i < total; i++)
      vmap->v[map_i].variants[i] = vars[i];
    break;
  default:
    abort();
  }

  return 0;
}

int
super_html_variant_prob_op(struct sid_state *sstate, int cmd, int prob_id)
{
  struct variant_map *vmap = 0;
  struct section_problem_data *prob = 0;
  int j, i;

  if (!sstate || !sstate->global) return -SSERV_ERR_INVALID_PARAMETER;
  if (!(vmap = sstate->global->variant_map)) return-SSERV_ERR_INVALID_PARAMETER;
  if (!sstate->prob_a || !sstate->probs) return -SSERV_ERR_INVALID_PARAMETER;
  if (prob_id <= 0 || prob_id >= sstate->prob_a)
    return -SSERV_ERR_INVALID_PARAMETER;
  if (!(prob = sstate->probs[prob_id])) return -SSERV_ERR_INVALID_PARAMETER;
  if (prob->variant_num <= 0) return -SSERV_ERR_INVALID_PARAMETER;
  j = vmap->prob_map[prob_id];
  if (j < 0 || j >= vmap->prob_map_size) return -SSERV_ERR_INVALID_PARAMETER;

  switch (cmd) {
  case SSERV_CMD_PROB_CLEAR_VARIANTS:
    for (i = 0; i < vmap->u; i++)
      vmap->v[i].variants[j] = 0;
    break;
  case SSERV_CMD_PROB_RANDOM_VARIANTS:
    for (i = 0; i < vmap->u; i++) {
      if (prob->variant_num == 1) {
        vmap->v[i].variants[j] = 1;
        continue;
      }
      vmap->v[i].variants[j] = random_range(1, prob->variant_num + 1);
    }
    break;
  default:
    return -SSERV_ERR_INVALID_PARAMETER;
  }

  return 0;
}
