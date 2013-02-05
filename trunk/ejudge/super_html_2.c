/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005-2013 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "version.h"
#include "ej_limits.h"

#include "super_html.h"
#include "super-serve.h"
#include "super_proto.h"
#include "contests.h"
#include "misctext.h"
#include "mischtml.h"
#include "opcaps.h"
#include "protocol.h"
#include "ejudge_cfg.h"
#include "pathutl.h"
#include "fileutl.h"
#include "xml_utils.h"
#include "prepare.h"
#include "userlist_proto.h"
#include "userlist_clnt.h"
#include "userlist.h"
#include "ej_process.h"
#include "vcs.h"
#include "compat.h"
#include "file_perms.h"

#include "reuse_xalloc.h"
#include "reuse_logger.h"
#include "reuse_osdeps.h"

#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJ_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

int
super_html_clear_variable(struct sid_state *sstate, int cmd)
{
  unsigned char **p_str = 0;
  struct contest_desc *cnts = sstate->edited_cnts;

  if (!cnts) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }

  switch (cmd) {
  case SSERV_CMD_CNTS_CLEAR_DEADLINE:
    cnts->reg_deadline = 0;
    return 0;

  case SSERV_CMD_CNTS_CLEAR_SCHED_TIME:
    cnts->sched_time = 0;
    return 0;

  case SSERV_CMD_CNTS_CLEAR_OPEN_TIME:
    cnts->open_time = 0;
    return 0;

  case SSERV_CMD_CNTS_CLEAR_CLOSE_TIME:
    cnts->close_time = 0;
    return 0;
    
  case SSERV_CMD_CNTS_CLEAR_NAME: p_str = &cnts->name; break;
  case SSERV_CMD_CNTS_CLEAR_NAME_EN: p_str = &cnts->name_en; break;
  case SSERV_CMD_CNTS_CLEAR_MAIN_URL: p_str = &cnts->main_url; break;
  case SSERV_CMD_CNTS_CLEAR_KEYWORDS: p_str = &cnts->keywords; break;
  case SSERV_CMD_CNTS_CLEAR_USER_CONTEST: p_str = &cnts->user_contest; break;
  case SSERV_CMD_CNTS_CLEAR_DEFAULT_LOCALE: p_str = &cnts->default_locale; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_HEADER: p_str = &cnts->users_header_file; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_FOOTER: p_str = &cnts->users_footer_file; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER: p_str = &cnts->register_header_file; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER: p_str = &cnts->register_footer_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEADER: p_str = &cnts->team_header_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1: p_str = &cnts->team_menu_1_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_2: p_str = &cnts->team_menu_2_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_3: p_str = &cnts->team_menu_3_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_SEPARATOR: p_str = &cnts->team_separator_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER: p_str = &cnts->team_footer_file; break;
  case SSERV_CMD_CNTS_CLEAR_PRIV_HEADER: p_str = &cnts->priv_header_file; break;
  case SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER: p_str = &cnts->priv_footer_file; break;
  case SSERV_CMD_CNTS_CLEAR_COPYRIGHT: p_str = &cnts->copyright_file; break;
  case SSERV_CMD_CNTS_CLEAR_WELCOME: p_str = &cnts->welcome_file; break;
  case SSERV_CMD_CNTS_CLEAR_REG_WELCOME: p_str = &cnts->reg_welcome_file; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_HEAD_STYLE: p_str = &cnts->users_head_style; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_PAR_STYLE: p_str = &cnts->users_par_style; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_STYLE: p_str = &cnts->users_table_style; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_VERB_STYLE: p_str = &cnts->users_verb_style; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT: p_str = &cnts->users_table_format; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_FORMAT_EN: p_str = &cnts->users_table_format_en; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND: p_str = &cnts->users_table_legend; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_TABLE_LEGEND_EN: p_str = &cnts->users_table_legend_en; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEAD_STYLE: p_str=&cnts->register_head_style;break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_PAR_STYLE: p_str = &cnts->register_par_style; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_TABLE_STYLE: p_str = &cnts->register_table_style; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_NAME_COMMENT: p_str = &cnts->user_name_comment; break;
  case SSERV_CMD_CNTS_CLEAR_ALLOWED_LANGUAGES: p_str = &cnts->allowed_languages; break;
  case SSERV_CMD_CNTS_CLEAR_ALLOWED_REGIONS: p_str = &cnts->allowed_regions; break;
  case SSERV_CMD_CNTS_CLEAR_CF_NOTIFY_EMAIL: p_str = &cnts->cf_notify_email; break;
  case SSERV_CMD_CNTS_CLEAR_CLAR_NOTIFY_EMAIL: p_str = &cnts->clar_notify_email; break;
  case SSERV_CMD_CNTS_CLEAR_DAILY_STAT_EMAIL: p_str = &cnts->daily_stat_email; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEAD_STYLE: p_str = &cnts->team_head_style; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_PAR_STYLE: p_str = &cnts->team_par_style; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL: p_str = &cnts->register_email; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_URL: p_str = &cnts->register_url; break;
  case SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE: p_str = &cnts->login_template; break;
  case SSERV_CMD_CNTS_CLEAR_LOGIN_TEMPLATE_OPTIONS: p_str = &cnts->login_template_options; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE: p_str = &cnts->register_email_file; break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_URL: p_str = &cnts->team_url; break;
  case SSERV_CMD_CNTS_CLEAR_STANDINGS_URL: p_str = &cnts->standings_url; break;
  case SSERV_CMD_CNTS_CLEAR_PROBLEMS_URL: p_str = &cnts->problems_url; break;
  case SSERV_CMD_CNTS_CLEAR_LOGO_URL: p_str = &cnts->logo_url; break;
  case SSERV_CMD_CNTS_CLEAR_CSS_URL: p_str = &cnts->css_url; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_SUBJECT: p_str = &cnts->register_subject; break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_SUBJECT_EN: p_str = &cnts->register_subject_en; break;
  case SSERV_CMD_CNTS_CLEAR_ROOT_DIR: p_str = &cnts->root_dir; break;
  case SSERV_CMD_CNTS_CLEAR_CONF_DIR: p_str = &cnts->conf_dir; break;
  case SSERV_CMD_CNTS_CLEAR_DIR_MODE: p_str = &cnts->dir_mode; break;
  case SSERV_CMD_CNTS_CLEAR_DIR_GROUP: p_str = &cnts->dir_group; break;
  case SSERV_CMD_CNTS_CLEAR_FILE_MODE: p_str = &cnts->file_mode; break;
  case SSERV_CMD_CNTS_CLEAR_FILE_GROUP: p_str = &cnts->file_group; break;
  case SSERV_CMD_CNTS_CLEAR_USERS_HEADER_TEXT:
    p_str = &sstate->users_header_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_USERS_FOOTER_TEXT:
    p_str = &sstate->users_footer_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_HEADER_TEXT:
    p_str = &sstate->register_header_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_FOOTER_TEXT:
    p_str = &sstate->register_footer_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_HEADER_TEXT:
    p_str = &sstate->team_header_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_1_TEXT:
    p_str = &sstate->team_menu_1_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_2_TEXT:
    p_str = &sstate->team_menu_2_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_MENU_3_TEXT:
    p_str = &sstate->team_menu_3_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_SEPARATOR_TEXT:
    p_str = &sstate->team_separator_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_TEAM_FOOTER_TEXT:
    p_str = &sstate->team_footer_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_PRIV_HEADER_TEXT:
    p_str = &sstate->priv_header_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_PRIV_FOOTER_TEXT:
    p_str = &sstate->priv_footer_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_COPYRIGHT_TEXT:
    p_str = &sstate->copyright_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_WELCOME_TEXT:
    p_str = &sstate->welcome_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_REG_WELCOME_TEXT:
    p_str = &sstate->reg_welcome_text;
    break;
  case SSERV_CMD_CNTS_CLEAR_REGISTER_EMAIL_FILE_TEXT:
    p_str = &sstate->register_email_text;
    break;
  default:
    abort();
  }

  xfree(*p_str);
  *p_str = 0;
  return 0;
}

static const int access_tags_map[] =
{
  CONTEST_REGISTER_ACCESS,
  CONTEST_USERS_ACCESS,
  CONTEST_MASTER_ACCESS,
  CONTEST_JUDGE_ACCESS,
  CONTEST_TEAM_ACCESS,
  CONTEST_SERVE_CONTROL_ACCESS,
};

static struct xml_tree*
get_nth_child(struct xml_tree *t, int n)
{
  struct xml_tree *p;

  if (!t) return 0;
  for (p = t->first_down; p && n; p = p->right, n--);
  return p;
}

static struct contest_access **
get_contest_access_by_num(const struct contest_desc *cnts, int num)
{
  switch (num) {
  case 0: return (struct contest_access **) &cnts->register_access;
  case 1: return (struct contest_access **) &cnts->users_access;
  case 2: return (struct contest_access **) &cnts->master_access;
  case 3: return (struct contest_access **) &cnts->judge_access;
  case 4: return (struct contest_access **) &cnts->team_access;
  case 5: return (struct contest_access **) &cnts->serve_control_access;
  default:
    return 0;
  }
}

struct contest_access *
super_html_copy_contest_access(const struct contest_access *p)
{
  struct contest_access *q;
  struct contest_ip *pp, *qq;

  if (!p) return 0;
  switch (p->b.tag) {
  case CONTEST_REGISTER_ACCESS:
  case CONTEST_USERS_ACCESS:
  case CONTEST_MASTER_ACCESS:
  case CONTEST_JUDGE_ACCESS:
  case CONTEST_TEAM_ACCESS:
  case CONTEST_SERVE_CONTROL_ACCESS:
    break;

  default:
    abort();
  }

  q = (struct contest_access*) contests_new_node(p->b.tag);
  q->default_is_allow = p->default_is_allow;

  for (pp = (struct contest_ip*) p->b.first_down;
       pp; pp = (struct contest_ip*) pp->b.right) {
    qq = (struct contest_ip*) contests_new_node(CONTEST_IP);
    qq->allow = pp->allow;
    qq->ssl = pp->ssl;
    qq->addr = pp->addr;
    qq->mask = pp->mask;
    xml_link_node_last(&q->b, &qq->b);
  }

  return q;
}

int
super_html_set_contest_var(struct sid_state *sstate, int cmd,
                           int param1, const unsigned char *param2,
                           int param3, int param4, int param5)
{
  unsigned char **p_str = 0, **p_str_d2u = 0;
  unsigned char **p_email = 0;
  unsigned char *p_bool = 0;
  time_t *p_date = 0;
  int v, n, memb_ind;
  struct contest_desc *cnts = sstate->edited_cnts;
  struct contest_access **p_access = 0, **p_src_access = 0;
  unsigned int ip_addr, ip_mask;
  struct contest_ip *new_ip;
  struct opcap_list_item *cap_node;
  const struct contest_desc *src_cnts = 0;
  const unsigned char *s = 0;

  if (!cnts) {
    return -SSERV_ERR_CONTEST_NOT_EDITED;
  }

  switch (cmd) {
  case SSERV_CMD_CNTS_CHANGE_NAME:
    p_str = &cnts->name;
    break;
  case SSERV_CMD_CNTS_CHANGE_NAME_EN:
    p_str = &cnts->name_en;
    break;
  case SSERV_CMD_CNTS_CHANGE_MAIN_URL:
    p_str = &cnts->main_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_KEYWORDS:
    p_str = &cnts->keywords;
    break;
  case SSERV_CMD_CNTS_CHANGE_USER_CONTEST:
    p_str = &cnts->user_contest;
    break;
  case SSERV_CMD_CNTS_CHANGE_DEFAULT_LOCALE:
    p_str = &cnts->default_locale;
    break;
  case SSERV_CMD_CNTS_CHANGE_AUTOREGISTER:
    p_bool = &cnts->autoregister;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_PASSWD:
    p_bool = &cnts->disable_team_password;
    break;
  case SSERV_CMD_CNTS_CHANGE_SIMPLE_REGISTRATION:
    p_bool = &cnts->simple_registration;
    break;
  case SSERV_CMD_CNTS_CHANGE_ASSIGN_LOGINS:
    p_bool = &cnts->assign_logins;
    break;
  case SSERV_CMD_CNTS_CHANGE_FORCE_REGISTRATION:
    p_bool = &cnts->force_registration;
    break;
  case SSERV_CMD_CNTS_CHANGE_DISABLE_NAME:
    p_bool = &cnts->disable_name;
    break;
  case SSERV_CMD_CNTS_CHANGE_ENABLE_PASSWORD_RECOVERY:
    p_bool = &cnts->enable_password_recovery;
    break;
  case SSERV_CMD_CNTS_CHANGE_EXAM_MODE:
    p_bool = &cnts->exam_mode;
    break;
  case SSERV_CMD_CNTS_CHANGE_DISABLE_PASSWORD_CHANGE:
    p_bool = &cnts->disable_password_change;
    break;
  case SSERV_CMD_CNTS_CHANGE_DISABLE_LOCALE_CHANGE:
    p_bool = &cnts->disable_locale_change;
    break;
  case SSERV_CMD_CNTS_CHANGE_PERSONAL:
    p_bool = &cnts->personal;
    break;
  case SSERV_CMD_CNTS_CHANGE_ALLOW_REG_DATA_EDIT:
    p_bool = &cnts->allow_reg_data_edit;
    break;
  case SSERV_CMD_CNTS_CHANGE_SEND_PASSWD_EMAIL:
    p_bool = &cnts->send_passwd_email;
    break;
  case SSERV_CMD_CNTS_CHANGE_MANAGED:
    p_bool = &cnts->managed;
    break;
  case SSERV_CMD_CNTS_CHANGE_RUN_MANAGED:
    p_bool = &cnts->run_managed;
    break;
  case SSERV_CMD_CNTS_CHANGE_OLD_RUN_MANAGED:
    p_bool = &cnts->old_run_managed;
    break;
  case SSERV_CMD_CNTS_CHANGE_CLEAN_USERS:
    p_bool = &cnts->clean_users;
    break;
  case SSERV_CMD_CNTS_CHANGE_CLOSED:
    p_bool = &cnts->closed;
    break;
  case SSERV_CMD_CNTS_CHANGE_INVISIBLE:
    p_bool = &cnts->invisible;
    break;
  case SSERV_CMD_CNTS_CHANGE_MEMBER_DELETE:
    p_bool = &cnts->disable_member_delete;
    break;
  case SSERV_CMD_CNTS_CHANGE_DEADLINE:
    p_date = &cnts->reg_deadline;
    break;
  case SSERV_CMD_CNTS_CHANGE_SCHED_TIME:
    p_date = &cnts->sched_time;
    break;
  case SSERV_CMD_CNTS_CHANGE_OPEN_TIME:
    p_date = &cnts->open_time;
    break;
  case SSERV_CMD_CNTS_CHANGE_CLOSE_TIME:
    p_date = &cnts->close_time;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_HEADER:
    p_str = &cnts->users_header_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_FOOTER:
    p_str = &cnts->users_footer_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_HEADER:
    p_str = &cnts->register_header_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_FOOTER:
    p_str = &cnts->register_footer_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_HEADER:
    p_str = &cnts->team_header_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_MENU_1:
    p_str = &cnts->team_menu_1_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_MENU_2:
    p_str = &cnts->team_menu_2_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_MENU_3:
    p_str = &cnts->team_menu_3_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_SEPARATOR:
    p_str = &cnts->team_separator_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_FOOTER:
    p_str = &cnts->team_footer_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_PRIV_HEADER:
    p_str = &cnts->priv_header_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_PRIV_FOOTER:
    p_str = &cnts->priv_footer_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_COPYRIGHT:
    p_str = &cnts->copyright_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_WELCOME:
    p_str = &cnts->welcome_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_REG_WELCOME:
    p_str = &cnts->reg_welcome_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_HEAD_STYLE:
    p_str = &cnts->users_head_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_PAR_STYLE:
    p_str = &cnts->users_par_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_STYLE:
    p_str = &cnts->users_table_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_VERB_STYLE:
    p_str = &cnts->users_verb_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT:
    p_str = &cnts->users_table_format;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_FORMAT_EN:
    p_str = &cnts->users_table_format_en;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND:
    p_str = &cnts->users_table_legend;
    break;
  case SSERV_CMD_CNTS_CHANGE_USERS_TABLE_LEGEND_EN:
    p_str = &cnts->users_table_legend_en;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_HEAD_STYLE:
    p_str = &cnts->register_head_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_PAR_STYLE:
    p_str = &cnts->register_par_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_TABLE_STYLE:
    p_str = &cnts->register_table_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_NAME_COMMENT:
    p_str = &cnts->user_name_comment;
    break;
  case SSERV_CMD_CNTS_CHANGE_ALLOWED_LANGUAGES:
    p_str = &cnts->allowed_languages;
    break;
  case SSERV_CMD_CNTS_CHANGE_ALLOWED_REGIONS:
    p_str = &cnts->allowed_regions;
    break;
  case SSERV_CMD_CNTS_CHANGE_CF_NOTIFY_EMAIL:
    p_email = &cnts->cf_notify_email;
    break;
  case SSERV_CMD_CNTS_CHANGE_CLAR_NOTIFY_EMAIL:
    p_email = &cnts->clar_notify_email;
    break;
  case SSERV_CMD_CNTS_CHANGE_DAILY_STAT_EMAIL:
    p_email = &cnts->daily_stat_email;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_HEAD_STYLE:
    p_str = &cnts->team_head_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_PAR_STYLE:
    p_str = &cnts->team_par_style;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL:
    p_email = &cnts->register_email;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_URL:
    p_str = &cnts->register_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE:
    p_str = &cnts->login_template;
    break;
  case SSERV_CMD_CNTS_CHANGE_LOGIN_TEMPLATE_OPTIONS:
    p_str = &cnts->login_template_options;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_EMAIL_FILE:
    p_str = &cnts->register_email_file;
    break;
  case SSERV_CMD_CNTS_CHANGE_TEAM_URL:
    p_str = &cnts->team_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_STANDINGS_URL:
    p_str = &cnts->standings_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_PROBLEMS_URL:
    p_str = &cnts->problems_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_LOGO_URL:
    p_str = &cnts->logo_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_CSS_URL:
    p_str = &cnts->css_url;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_SUBJECT:
    p_str = &cnts->register_subject;
    break;
  case SSERV_CMD_CNTS_CHANGE_REGISTER_SUBJECT_EN:
    p_str = &cnts->register_subject_en;
    break;
  case SSERV_CMD_CNTS_CHANGE_ROOT_DIR:
    p_str = &cnts->root_dir;
    break;
  case SSERV_CMD_CNTS_CHANGE_CONF_DIR:
    p_str = &cnts->conf_dir;
    break;

  case SSERV_CMD_CNTS_CHANGE_DIR_MODE:
    p_str = &cnts->dir_mode;
    break;
  case SSERV_CMD_CNTS_CHANGE_DIR_GROUP:
    p_str = &cnts->dir_group;
    break;
  case SSERV_CMD_CNTS_CHANGE_FILE_MODE:
    p_str = &cnts->file_mode;
    break;
  case SSERV_CMD_CNTS_CHANGE_FILE_GROUP:
    p_str = &cnts->file_group;
    break;

  case SSERV_CMD_CNTS_SAVE_USERS_HEADER:
    p_str_d2u = &sstate->users_header_text;
    break;
  case SSERV_CMD_CNTS_SAVE_USERS_FOOTER:
    p_str_d2u = &sstate->users_footer_text;
    break;
  case SSERV_CMD_CNTS_SAVE_REGISTER_HEADER:
    p_str_d2u = &sstate->register_header_text;
    break;
  case SSERV_CMD_CNTS_SAVE_REGISTER_FOOTER:
    p_str_d2u = &sstate->register_footer_text;
    break;
  case SSERV_CMD_CNTS_SAVE_TEAM_HEADER:
    p_str_d2u = &sstate->team_header_text;
    break;
  case SSERV_CMD_CNTS_SAVE_TEAM_MENU_1:
    p_str_d2u = &sstate->team_menu_1_text;
    break;
  case SSERV_CMD_CNTS_SAVE_TEAM_MENU_2:
    p_str_d2u = &sstate->team_menu_2_text;
    break;
  case SSERV_CMD_CNTS_SAVE_TEAM_MENU_3:
    p_str_d2u = &sstate->team_menu_3_text;
    break;
  case SSERV_CMD_CNTS_SAVE_TEAM_SEPARATOR:
    p_str_d2u = &sstate->team_separator_text;
    break;
  case SSERV_CMD_CNTS_SAVE_TEAM_FOOTER:
    p_str_d2u = &sstate->team_footer_text;
    break;
  case SSERV_CMD_CNTS_SAVE_PRIV_HEADER:
    p_str_d2u = &sstate->priv_header_text;
    break;
  case SSERV_CMD_CNTS_SAVE_PRIV_FOOTER:
    p_str_d2u = &sstate->priv_footer_text;
    break;
  case SSERV_CMD_CNTS_SAVE_COPYRIGHT:
    p_str_d2u = &sstate->copyright_text;
    break;
  case SSERV_CMD_CNTS_SAVE_WELCOME:
    p_str_d2u = &sstate->welcome_text;
    break;
  case SSERV_CMD_CNTS_SAVE_REG_WELCOME:
    p_str_d2u = &sstate->reg_welcome_text;
    break;
  case SSERV_CMD_CNTS_SAVE_REGISTER_EMAIL_FILE:
    p_str_d2u = &sstate->register_email_text;
    break;

  case SSERV_CMD_CNTS_DEFAULT_ACCESS:
    if (!(p_access = get_contest_access_by_num(cnts, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (param3 < 0 || param3 > 1) return -SSERV_ERR_INVALID_PARAMETER;
    contests_set_default(cnts, p_access, access_tags_map[param1], param3);
    return 0;
  case SSERV_CMD_CNTS_ADD_RULE:
    if (!(p_access = get_contest_access_by_num(cnts, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (param3 < 0 || param3 > 1) return -SSERV_ERR_INVALID_PARAMETER;
    if (xml_parse_ip_mask(NULL, 0, -1, 0, param2, &ip_addr, &ip_mask) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    contests_add_ip(cnts, p_access, access_tags_map[param1],
                    ip_addr, ip_mask, param5, param3);
    return 0;
  case SSERV_CMD_CNTS_CHANGE_RULE:
    if (!(p_access = get_contest_access_by_num(cnts, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (param3 < 0 || param3 > 1) return -SSERV_ERR_INVALID_PARAMETER;
    if (!(new_ip = (struct contest_ip*) get_nth_child(&(*p_access)->b, param4)))
      return -SSERV_ERR_INVALID_PARAMETER;
    new_ip->allow = param3;
    new_ip->ssl = param5;
    return 0;
  case SSERV_CMD_CNTS_DELETE_RULE:
    if (!(p_access = get_contest_access_by_num(cnts, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (contests_delete_ip_rule(p_access, param4) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;
  case SSERV_CMD_CNTS_UP_RULE:
    if (!(p_access = get_contest_access_by_num(cnts, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (contests_forward_ip_rule(p_access, param4) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;
  case SSERV_CMD_CNTS_DOWN_RULE:
    if (!(p_access = get_contest_access_by_num(cnts, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (contests_backward_ip_rule(p_access, param4) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;

  case SSERV_CMD_CNTS_COPY_ACCESS:
    /*
     * param1 - destination access list
     * param3 - source contest
     * param4 - source access list
     */
    // cnts - current contest
    if (param3 > 0) {
      if (contests_get(param3, &src_cnts) < 0)
        return -SSERV_ERR_INVALID_PARAMETER;
    } else {
      src_cnts = cnts;
    }
    if (!(p_access = get_contest_access_by_num(cnts, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (!(p_src_access = get_contest_access_by_num(src_cnts, param4)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (*p_access == *p_src_access) return 0;
    xml_unlink_node(&(*p_access)->b);
    contests_free_2(&(*p_access)->b);
    *p_access = super_html_copy_contest_access(*p_src_access);
    xml_link_node_last(&cnts->b, &(*p_access)->b);
    return 0;

  case SSERV_CMD_CNTS_DELETE_PERMISSION:
    if (contests_remove_nth_permission(cnts, param1) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;

  case SSERV_CMD_CNTS_ADD_PERMISSION:
    if (!param2 || !*param2) return -SSERV_ERR_INVALID_PARAMETER;
    if (check_str(param2, login_accept_chars) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    contests_add_permission(cnts, param2, 0);
    return 0;

  case SSERV_CMD_CNTS_SAVE_PERMISSIONS:
    if (!(cap_node = (struct opcap_list_item*) get_nth_child(cnts->caps_node, param1)))
      return -SSERV_ERR_INVALID_PARAMETER;
    if (strlen(param2) != 64) return -SSERV_ERR_INVALID_PARAMETER;
    for (n = 0; n < 64; n++)
      if (param2[n] != '0' && param2[n] != '1')
        return -SSERV_ERR_INVALID_PARAMETER;

    cap_node->caps = 0ULL;
    for (n = 0; n < 64; n++)
      if (param2[n] == '1')
        cap_node->caps |= (1ULL << n);
    return 0;

  case SSERV_CMD_CNTS_SAVE_FORM_FIELDS:
    if (param1 != -1 || param3 != -1 || param4 != -1)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (strlen(param2) != CONTEST_LAST_FIELD)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (param2[0] != '0')
      return -SSERV_ERR_INVALID_PARAMETER;
    for (n = 1; n < CONTEST_LAST_FIELD; n++)
      if (param2[n] < '0' || param2[n] > '2')
        return -SSERV_ERR_INVALID_PARAMETER;
    for (n = 1; n < CONTEST_LAST_FIELD; n++) {
      s = 0;
      if (cnts->fields[n]) s = cnts->fields[n]->legend;
      contests_set_general_field(cnts, n, param2[n] - '0', s);
    }
    return 0;

  case SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS:
  case SSERV_CMD_CNTS_SAVE_RESERVE_FIELDS:
  case SSERV_CMD_CNTS_SAVE_COACH_FIELDS:
  case SSERV_CMD_CNTS_SAVE_ADVISOR_FIELDS:
  case SSERV_CMD_CNTS_SAVE_GUEST_FIELDS:
    // param1 - init_count
    // param2 - field flags
    // param3 - min_count
    // param4 - max_count
    memb_ind = cmd - SSERV_CMD_CNTS_SAVE_CONTESTANT_FIELDS;

    if (param1 < 0 || param1 > 5) return -SSERV_ERR_INVALID_PARAMETER;
    if (param3 < 0 || param3 > 5) return -SSERV_ERR_INVALID_PARAMETER;
    if (param4 < 0 || param4 > 5) return -SSERV_ERR_INVALID_PARAMETER;
    if (param3 > param4) return -SSERV_ERR_INVALID_PARAMETER;
    if (param1 < param3 || param1 > param4) return -SSERV_ERR_INVALID_PARAMETER;
    if (strlen(param2) != CONTEST_LAST_MEMBER_FIELD)
      return -SSERV_ERR_INVALID_PARAMETER;
    if (param2[0] != '0')
      return -SSERV_ERR_INVALID_PARAMETER;
    for (n = 1; n < CONTEST_LAST_MEMBER_FIELD; n++)
      if (param2[n] < '0' || param2[n] > '2')
        return -SSERV_ERR_INVALID_PARAMETER;

    // check, that we must remove this member
    if (!param1 && !param3 && !param4) {
      for (n = 1; n < CONTEST_LAST_MEMBER_FIELD; n++)
        if (param2[n] != '0')
          break;
      if (n == CONTEST_LAST_MEMBER_FIELD) {
        contests_delete_member_fields(cnts, memb_ind);
        return 0;
      }
    }

    contests_set_member_counts(cnts, memb_ind, param3, param4, param1);

    for (n = 1; n < CONTEST_LAST_MEMBER_FIELD; n++) {
      s = 0;
      if (cnts->members[memb_ind] && cnts->members[memb_ind]->fields[n])
        s = cnts->members[memb_ind]->fields[n]->legend;
      contests_set_member_field(cnts, memb_ind, n, param2[n] - '0', s);
    }
    return 0;

  default:
    abort();
  }

  if (p_email) {
    if (param2 && *param2 && !is_valid_email_address(param2))
      return -SSERV_ERR_INVALID_PARAMETER;
    p_str = p_email; p_email = 0;
  }

  if (p_date) {
    if (xml_parse_date(NULL, "", 0, 0, param2, p_date) < 0)
      return -SSERV_ERR_INVALID_PARAMETER;
    return 0;
  }

  if (p_bool) {
    // boolean variable
    if (!param2 || sscanf(param2, "%d%n", &v, &n) != 1 || param2[n] || v < 0 || v > 1)
      return -SSERV_ERR_INVALID_PARAMETER;
    *p_bool = v;
    return 0;
  }

  if (p_str_d2u) {
    xfree(*p_str_d2u);
    *p_str_d2u = dos2unix_str(param2);
    return 0;
  }

  if (p_str) {
    // text variable
    xfree(*p_str);
    *p_str = xstrdup(param2);
    return 0;
  }

  abort();
}

static void
make_conf_path(unsigned char *p, const unsigned char *d, const unsigned char *f)
{
  if (!os_IsAbsolutePath(f)) {
    snprintf(p, sizeof(path_t), "%s/%s", d, f);
  } else {
    snprintf(p, sizeof(path_t), "%s", f);
  }
}

static int
make_temp_file(unsigned char *out, const unsigned char *in)
{
  path_t buf;

  int n = 1, r;
  do {
    snprintf(buf, sizeof(path_t), "%s.%d", in, n++);
  } while ((r = open(buf, O_CREAT | O_EXCL | O_WRONLY | O_TRUNC, 0664)) < 0
           && errno == EEXIST);
  if (r >= 0) {
    close(r);
    r = 0;
    snprintf(out, sizeof(path_t), "%s", buf);
  }
  return r;
}

static int
save_conf_file(FILE *flog, const unsigned char *desc,
               const unsigned char *file, const unsigned char *text,
               const unsigned char *conf_path,
               unsigned char *path, unsigned char *path_2)
{
  int errcode;
  char *old_text = 0;
  size_t old_size = 0;

  if (file && *file && text) {
    make_conf_path(path, conf_path, file);

    // try to read the file
    errcode = generic_read_file(&old_text, 0, &old_size, 0, 0, path, 0);
    if (errcode >= 0 && strlen(text) == old_size
        && memcmp(text, old_text, old_size) == 0) {
      // file not changed
      fprintf(flog, "%s `%s' is not changed\n", desc, file);
      xfree(old_text);
      return 0;
    }
    xfree(old_text); old_text = 0; old_size = 0;

    if (make_temp_file(path_2, path) < 0) {
      fprintf(flog, "error: cannot create a temporary %s `%s'\n"
              "error: %s\n", desc, path, os_ErrorMsg());
      return -1;
    }
    if (generic_write_file(text, strlen(text), 0, 0, path_2, 0) < 0) {
      fprintf(flog, "error: saving of temporary %s `%s' failed\n"
              "error: %s\n", desc, path_2, os_ErrorMsg());
      return -1;
    }
    fprintf(flog, "%s `%s' is temporarily saved as `%s'\n", desc, file, path_2);
  }
  return 1;
}

static void
rename_files(
        FILE *flog,
        int flag,
        const unsigned char *to,
        const unsigned char *from,
        int group,
        int mode)
{
  int old_group = 0, old_mode = 0;

  if (!flag) return;
  if (!from || !*from || !to || !*to) return;
  file_perms_get(to, &old_group, &old_mode);
  if (rename(from, to) < 0) {
    fprintf(flog, "error: renaming %s to %s failed: %s\n",
            from, to, os_ErrorMsg());
  } else {
    fprintf(flog, "renamed %s to %s\n", from, to);
  }
  file_perms_set(flog, to, group, mode, old_group, old_mode);
}

static unsigned char *
diff_func(const unsigned char *path1, const unsigned char *path2)
{
  path_t diff_cmdline;

  snprintf(diff_cmdline, sizeof(diff_cmdline),
           "/usr/bin/diff -u \"%s\" \"%s\"", path1, path2);
  return read_process_output(diff_cmdline, 0, 1, 0);
}

/*
int
super_html_serve_probe_run(FILE *f,
                           int priv_level,
                           int user_id,
                           int contest_id,
                           const unsigned char *login,
                           ej_cookie_t session_id,
                           ej_ip_t ip_address,
                           int ssl,
                           struct ejudge_cfg *config,
                           const unsigned char *self_url,
                           const unsigned char *hidden_vars,
                           const unsigned char *extra_args)
{
  int errcode;
  const struct contest_desc *cnts = 0;
  struct contest_extra *extra = 0;
  unsigned char *serve_buf = 0, *s = 0;
  opcap_t caps;
  unsigned char hbuf[1024];

  if ((errcode = contests_get(contest_id, &cnts)) < 0) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "Invalid contest %d!", contest_id);
  }
  if (priv_level < PRIV_LEVEL_JUDGE
      || opcaps_find(&cnts->capabilities, login, &caps) < 0
      || opcaps_check(caps, OPCAP_CONTROL_CONTEST) < 0
      || !contests_check_serve_control_ip_2(cnts, ip_address, ssl)) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "Permission denied");
  }
  if (!cnts->root_dir) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "Root dir is not defined");
  }
  if (!(extra = get_existing_contest_extra(contest_id))) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "Contest is not handled");
  }

  errcode = super_serve_start_serve_test_mode(cnts, &serve_buf, extra->socket_fd);
  s = html_armor_string_dup(serve_buf);
  fprintf(f, "<p>Probe run log:<br><pre>%s</pre>\n", s);
  xfree(s);
  xfree(serve_buf);
  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td>%sTo the top</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url,extra_args,0));
  fprintf(f, "<td>%sBack</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "contest_id=%d&action=%d", contest_id,
                        SSERV_CMD_CONTEST_PAGE));
  fprintf(f, "</tr></table>\n");
  return 0;
}
*/

int
super_html_commit_contest(FILE *f,
                          int priv_level,
                          int user_id,
                          const unsigned char *login,
                          ej_cookie_t session_id,
                          ej_ip4_t ip_address,
                          struct ejudge_cfg *config,
                          struct userlist_clnt *us_conn,
                          struct sid_state *sstate,
                          int cmd,
                          const unsigned char *self_url,
                          const unsigned char *hidden_vars,
                          const unsigned char *extra_args)
{
  struct contest_desc *cnts = sstate->edited_cnts;
  struct section_global_data *global = sstate->global;
  struct stat sb;
  char *flog_txt = 0;
  size_t flog_size = 0;
  FILE *flog = 0;
  int errcode;
  unsigned char *s = 0;
  unsigned char hbuf[1024];
  unsigned char *xml_header = 0;
  unsigned char *xml_footer = 0;
  unsigned char *serve_header = 0;
  unsigned char *serve_footer = 0;
  unsigned char audit_rec[1024];
  unsigned char serve_audit_rec[1024];
  int i, j;

  path_t conf_path;
  path_t xml_path;
  path_t serve_cfg_path;
  path_t serve_cfg_path_2 = { 0 };
  path_t users_header_path = { 0 };
  path_t users_header_path_2 = { 0 };
  path_t users_footer_path = { 0 };
  path_t users_footer_path_2 = { 0 };
  path_t register_header_path = { 0 };
  path_t register_header_path_2 = { 0 };
  path_t register_footer_path = { 0 };
  path_t register_footer_path_2 = { 0 };
  path_t team_header_path = { 0 };
  path_t team_header_path_2 = { 0 };
  path_t team_menu_1_path = { 0 };
  path_t team_menu_1_path_2 = { 0 };
  path_t team_menu_2_path = { 0 };
  path_t team_menu_2_path_2 = { 0 };
  path_t team_menu_3_path = { 0 };
  path_t team_menu_3_path_2 = { 0 };
  path_t team_separator_path = { 0 };
  path_t team_separator_path_2 = { 0 };
  path_t team_footer_path = { 0 };
  path_t team_footer_path_2 = { 0 };
  path_t priv_header_path = { 0 };
  path_t priv_header_path_2 = { 0 };
  path_t priv_footer_path = { 0 };
  path_t priv_footer_path_2 = { 0 };
  path_t copyright_path = { 0 };
  path_t copyright_path_2 = { 0 };
  path_t welcome_path = { 0 };
  path_t welcome_path_2 = { 0 };
  path_t reg_welcome_path = { 0 };
  path_t reg_welcome_path_2 = { 0 };
  path_t register_email_path = { 0 };
  path_t register_email_path_2 = { 0 };
  path_t contest_start_cmd_path = { 0 };
  path_t contest_start_cmd_path_2 = { 0 };
  path_t contest_stop_cmd_path = { 0 };
  path_t contest_stop_cmd_path_2 = { 0 };
  path_t stand_header_path = { 0 };
  path_t stand_header_path_2 = { 0 };
  path_t stand_footer_path = { 0 };
  path_t stand_footer_path_2 = { 0 };
  path_t stand2_header_path = { 0 };
  path_t stand2_header_path_2 = { 0 };
  path_t stand2_footer_path = { 0 };
  path_t stand2_footer_path_2 = { 0 };
  path_t plog_header_path = { 0 };
  path_t plog_header_path_2 = { 0 };
  path_t plog_footer_path = { 0 };
  path_t plog_footer_path_2 = { 0 };
  path_t vmap_path = { 0 };
  path_t vmap_path_2 = { 0 };

  int uhf, uff, rhf, rff, thf, tff, ref;
  int csf = 0, shf = 0, sff = 0, s2hf = 0, s2ff = 0, phf = 0, pff = 0, sf = 0, vmf = 0, cpf = 0, ihf = 0, iff = 0, tsf = 0, cwf = 0, crwf = 0, t1f = 0, t2f = 0, t3f = 0, ctf = 0;

  path_t diff_cmdline;
  unsigned char *diff_str = 0, *vcs_str = 0;
  int vcs_add_flag = 0, serve_vcs_add_flag = 0;
  int need_variant_map = 0, vmap_vcs_add_flag = 0, uid;
  char *vmap_txt = 0;
  size_t vmap_size = 0;
  FILE *vmap_f = 0;
  struct opcap_list_item *capp;
  int dir_mode = -1, dir_group = -1, file_mode = -1, file_group = -1; 
  int old_vmap_group = 0, old_vmap_mode = 0;
  int old_serve_group = 0, old_serve_mode = 0;

  if (!cnts) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "No current contest!");
  }
  if (!cnts->root_dir || !*cnts->root_dir) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "root_dir is not set!");
  }
  if (!cnts->name) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "contest name is not defined");
  }
  if (!os_IsAbsolutePath(cnts->root_dir)) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "root_dir is not an absolute path!");
  }
  if (stat(cnts->root_dir, &sb) >= 0 && !S_ISDIR(sb.st_mode)) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "root_dir is not a directory!");
  }
  if (!sstate->serve_parse_errors && sstate->disable_compilation_server) {
    return super_html_report_error(f, session_id, self_url, extra_args,
                                   "Compilation server must be enabled");
  }
  if (!sstate->serve_parse_errors && sstate->global) {
    j = 0;
    if (sstate->langs) {
      for (i = 1; i < sstate->lang_a; i++)
        if (sstate->langs[i]) j++;
    }
    /*
    if (!j)
      return super_html_report_error(f, session_id, self_url, extra_args,
                                     "No languages activated");
    */

    j = 0;
    if (sstate->probs) {
      for (i = 1; i < sstate->prob_a; i++)
        if (sstate->probs[i]) j++;
    }
    /*
    if (!j)
      return super_html_report_error(f, session_id, self_url, extra_args,
                                     "No problems defined");
    */
    if (sstate->probs) {
      for (i = 1; i < sstate->prob_a; i++)
        if (sstate->probs[i] && sstate->probs[i]->variant_num > 0)
          need_variant_map = 1;
    }

    if (need_variant_map && !sstate->global->variant_map_file)
      snprintf(sstate->global->variant_map_file,
               sizeof(sstate->global->variant_map_file), "variant.map");
    if (need_variant_map && !sstate->global->variant_map) {
      flog = open_memstream(&flog_txt, &flog_size);
      if (super_html_update_variant_map(flog, sstate->edited_cnts->id,
                                        us_conn, sstate->edited_cnts,
                                        sstate->global, sstate->prob_a,
                                        sstate->probs,
                                        &sstate->var_header_text,
                                        &sstate->var_footer_text) < 0) {
        close_memstream(flog); flog = 0;
        xfree(flog_txt); flog_txt = 0; flog_size = 0;
        return super_html_report_error(f, session_id, self_url, extra_args,
                                       "Cannot update the variant map");
      }
      close_memstream(flog); flog = 0;
      xfree(flog_txt); flog_txt = 0; flog_size = 0;
    }
    if (need_variant_map && !sstate->global->variant_map)
      return super_html_report_error(f, session_id, self_url, extra_args,
                                     "No variant map defined");
  }
  // FIXME: what else we should validate

  // cnts->dir_mode, cnts->dir_group, cnts->file_mode, cnts->file_group
  dir_mode = file_perms_parse_mode(cnts->dir_mode);
  dir_group = file_perms_parse_group(cnts->dir_group);
  file_mode = file_perms_parse_mode(cnts->file_mode);
  file_group = file_perms_parse_group(cnts->file_group);

  if (!cnts->conf_dir) {
    snprintf(conf_path, sizeof(conf_path), "%s/%s", cnts->root_dir, "conf");
  } else if (!os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(conf_path, sizeof(conf_path), "%s/%s", cnts->root_dir, cnts->conf_dir);
  } else {
    snprintf(conf_path, sizeof(conf_path), "%s", cnts->conf_dir);
  }

  flog = open_memstream(&flog_txt, &flog_size);

  /* Create the contest root directory */
  if (stat(cnts->root_dir, &sb) >= 0) {
    if (!S_ISDIR(sb.st_mode)) {
      fprintf(flog, "error: contest root directory `%s' is not actually a directory\n",
              cnts->root_dir);
      goto failed;
    }
    fprintf(flog, "contest root directory `%s' already exists\n", cnts->root_dir);
  } else {
    if ((errcode = os_MakeDirPath(cnts->root_dir, 0775)) < 0) {
      fprintf(flog, "error: contest root directory `%s' creation failed\n",
              cnts->root_dir);
      fprintf(flog, "error: %s\n", os_GetErrorString(-errcode));
      goto failed;
    }
    fprintf(flog, "contest root directory `%s' is created\n", cnts->root_dir);
    file_perms_set(flog, cnts->root_dir, dir_group, dir_mode, 0, 0);
    if (vcs_add_dir(cnts->root_dir, &vcs_str) > 0) {
      fprintf(flog, "Version control:\n%s\n", vcs_str);
      xfree(vcs_str); vcs_str = 0;
    }
  }

  /* Create the contest configuration directory */
  if (stat(conf_path, &sb) >= 0) {
    if (!S_ISDIR(sb.st_mode)) {
      fprintf(flog, "error: contest configuration directory `%s' is not actually a directory\n", conf_path);
      goto failed;
    }
    fprintf(flog, "contest configuration directory `%s' already exists\n", conf_path);
  } else {
    if ((errcode = os_MakeDirPath(conf_path, 0775)) < 0) {
      fprintf(flog, "error: contest configuration directory `%s' creation failed\n",
              conf_path);
      fprintf(flog, "error: %s\n", os_GetErrorString(-errcode));
      goto failed;
    }
    file_perms_set(flog, conf_path, dir_group, dir_mode, 0, 0);
    fprintf(flog, "contest configuration directory `%s' is created\n", conf_path);
    if (vcs_add_dir(conf_path, &vcs_str) > 0) {
      fprintf(flog, "Version control:\n%s\n", vcs_str);
      xfree(vcs_str); vcs_str = 0;
    }
  }

  /* FIXME: create statement, test, checker directories, etc... */

  /* Save the users_header_file as temporary file */
  if ((uhf = save_conf_file(flog, "`users' HTML header file",
                            cnts->users_header_file, sstate->users_header_text,
                            conf_path,
                            users_header_path, users_header_path_2)) < 0)
    goto failed;

  /* Save the users_footer_file as temporary file */
  if ((uff = save_conf_file(flog, "`users' HTML footer file",
                            cnts->users_footer_file, sstate->users_footer_text,
                            conf_path,
                            users_footer_path, users_footer_path_2)) < 0)
    goto failed;

  /* Save the register_header_file as temporary file */
  if ((rhf = save_conf_file(flog, "`register' HTML header file",
                            cnts->register_header_file, sstate->register_header_text,
                            conf_path,
                            register_header_path, register_header_path_2)) < 0)
    goto failed;

  /* Save the register_footer_file as temporary file */
  if ((rff = save_conf_file(flog, "`register' HTML footer file",
                            cnts->register_footer_file, sstate->register_footer_text,
                            conf_path,
                            register_footer_path, register_footer_path_2)) < 0)
    goto failed;

  /* Save the team_header_file as temporary file */
  if ((thf = save_conf_file(flog, "`team' HTML header file",
                            cnts->team_header_file, sstate->team_header_text,
                            conf_path,
                            team_header_path, team_header_path_2)) < 0)
    goto failed;

  /* Save the team_menu_1_file as temporary file */
  if ((t1f = save_conf_file(flog, "`team' HTML content menu1",
                            cnts->team_menu_1_file, sstate->team_menu_1_text,
                            conf_path,
                            team_menu_1_path, team_menu_1_path_2)) < 0)

  /* Save the team_menu_2_file as temporary file */
  if ((t2f = save_conf_file(flog, "`team' HTML content menu2",
                            cnts->team_menu_2_file, sstate->team_menu_2_text,
                            conf_path,
                            team_menu_2_path, team_menu_2_path_2)) < 0)
    goto failed;
  /* Save the team_menu_2_file as temporary file */
  if ((t3f = save_conf_file(flog, "`team' HTML content menu3",
                            cnts->team_menu_3_file, sstate->team_menu_3_text,
                            conf_path,
                            team_menu_3_path, team_menu_3_path_2)) < 0)
    goto failed;

  /* Save the team_separator_file as temporary file */
  if ((tsf = save_conf_file(flog, "`team' HTML separator file",
                            cnts->team_separator_file,
                            sstate->team_separator_text,
                            conf_path,
                            team_separator_path, team_separator_path_2)) < 0)
    goto failed;

  /* Save the team_footer_file as temporary file */
  if ((tff = save_conf_file(flog, "`team' HTML footer file",
                            cnts->team_footer_file, sstate->team_footer_text,
                            conf_path,
                            team_footer_path, team_footer_path_2)) < 0)
    goto failed;

  /* Save the priv_header_file as temporary file */
  if ((ihf = save_conf_file(flog, "privileged HTML header file",
                            cnts->priv_header_file, sstate->priv_header_text,
                            conf_path,
                            priv_header_path, priv_header_path_2)) < 0)
    goto failed;

  /* Save the priv_footer_file as temporary file */
  if ((iff = save_conf_file(flog, "privileged HTML footer file",
                            cnts->priv_footer_file, sstate->priv_footer_text,
                            conf_path,
                            priv_footer_path, priv_footer_path_2)) < 0)
    goto failed;

  /* Save the copyright_file as temporary file */
  if ((cpf = save_conf_file(flog, "copyright notice file",
                            cnts->copyright_file, sstate->copyright_text,
                            conf_path,
                            copyright_path, copyright_path_2)) < 0)
    goto failed;

  /* Save the welcome_file as temporary file */
  if ((cwf = save_conf_file(flog, "welcome file",
                            cnts->welcome_file, sstate->welcome_text,
                            conf_path,
                            welcome_path, welcome_path_2)) < 0)
    goto failed;

  /* Save the reg_welcome_file as temporary file */
  if ((crwf = save_conf_file(flog, "registration welcome file",
                             cnts->reg_welcome_file, sstate->reg_welcome_text,
                             conf_path,
                             reg_welcome_path, reg_welcome_path_2)) < 0)
    goto failed;

  /* Save the register_email_file as temporary file */
  if ((ref = save_conf_file(flog, "registration e-mail template",
                            cnts->register_email_file, sstate->register_email_text,
                            conf_path,
                            register_email_path, register_email_path_2)) < 0)
    goto failed;

  if (global) {
    if ((csf = save_conf_file(flog, "contest start command script",
                              global->contest_start_cmd,
                              sstate->contest_start_cmd_text,
                              conf_path,
                              contest_start_cmd_path,
                              contest_start_cmd_path_2)) < 0)
      goto failed;
    if ((ctf = save_conf_file(flog, "contest stop command script",
                              global->contest_stop_cmd,
                              sstate->contest_stop_cmd_text,
                              conf_path,
                              contest_stop_cmd_path,
                              contest_stop_cmd_path_2)) < 0)
      goto failed;
    if ((shf = save_conf_file(flog, "standings HTML header file",
                              global->stand_header_file, sstate->stand_header_text,
                              conf_path,
                              stand_header_path, stand_header_path_2)) < 0)
      goto failed;
    if ((sff = save_conf_file(flog, "standings HTML footer file",
                              global->stand_footer_file, sstate->stand_footer_text,
                              conf_path,
                              stand_footer_path, stand_footer_path_2)) < 0)
      goto failed;
    if ((s2hf = save_conf_file(flog, "supplementary standings HTML header file",
                               global->stand2_header_file, sstate->stand2_header_text,
                               conf_path,
                               stand2_header_path, stand2_header_path_2)) < 0)
      goto failed;
    if ((s2ff = save_conf_file(flog, "supplementary standings HTML footer file",
                               global->stand2_footer_file, sstate->stand2_footer_text,
                               conf_path,
                               stand2_footer_path, stand2_footer_path_2)) < 0)
      goto failed;
    if ((phf = save_conf_file(flog, "public submission log HTML header file",
                              global->plog_header_file, sstate->plog_header_text,
                              conf_path,
                              plog_header_path, plog_header_path_2)) < 0)
      goto failed;
    if ((pff = save_conf_file(flog, "public submission log HTML footer file",
                              global->plog_footer_file, sstate->plog_footer_text,
                              conf_path,
                              plog_footer_path, plog_footer_path_2)) < 0)
      goto failed;

    if (need_variant_map) {
      vmap_f = open_memstream(&vmap_txt, &vmap_size);
      prepare_unparse_variants(vmap_f, global->variant_map,
                               sstate->var_header_text, sstate->var_footer_text);
      close_memstream(vmap_f); vmap_f = 0;
      if ((vmf = save_conf_file(flog, "variant map file",
                                global->variant_map_file, vmap_txt,
                                conf_path,
                                vmap_path, vmap_path_2)) < 0)
        goto failed;
      if (access(vmap_path, F_OK) < 0) vmap_vcs_add_flag = 1;
    }
  }

  /* 10. Load the previous contest.xml and extract header and footer */
  contests_make_path(xml_path, sizeof(xml_path), cnts->id);
  errcode = super_html_get_contest_header_and_footer(xml_path, &xml_header, &xml_footer);
  if (errcode == -SSERV_ERR_FILE_NOT_EXIST) {
    fprintf(flog, "XML file `%s' does not exist\n", xml_path);
    snprintf(audit_rec, sizeof(audit_rec),
             "<!-- audit: created %s %d (%s) %s -->\n",
             xml_unparse_date(time(0)), user_id, login,
             xml_unparse_ip(ip_address));
    vcs_add_flag = 1;
  } else if (errcode < 0) {
    fprintf(flog, "Failed to read XML file `%s': %s\n",
            xml_path, super_proto_strerror(-errcode));
    goto failed;
  } else {
    snprintf(audit_rec, sizeof(audit_rec),
             "<!-- audit: edited %s %d (%s) %s -->\n",
             xml_unparse_date(time(0)), user_id, login,
             xml_unparse_ip(ip_address));
  }
  if (!xml_header) {
    snprintf(hbuf, sizeof(hbuf),
             "<!-- $%s$ -->\n", "Id");
    xml_header = xstrdup(hbuf);
  }
  if (!xml_footer) xml_footer = xstrdup("\n");

  /* Load the previous serve.cfg */
  if (!sstate->serve_parse_errors && sstate->global) {
    snprintf(serve_cfg_path, sizeof(serve_cfg_path), "%s/serve.cfg", conf_path);
    if (make_temp_file(serve_cfg_path_2, serve_cfg_path) < 0) {
      fprintf(flog, "error: cannot create a temporary serve.cfg `%s'\n"
              "error: %s\n", serve_cfg_path, os_ErrorMsg());
      goto failed;
    }

    errcode = super_html_get_serve_header_and_footer(serve_cfg_path, &serve_header, &serve_footer);
    if (errcode == -SSERV_ERR_FILE_NOT_EXIST) {
      fprintf(flog, "serve configuration file `%s' does not exist\n", serve_cfg_path);
      serve_header = xstrdup("# $" "Id" "$\n");
      snprintf(serve_audit_rec, sizeof(serve_audit_rec),
               "# audit: created %s %d (%s) %s\n",
               xml_unparse_date(time(0)), user_id, login,
               xml_unparse_ip(ip_address));
      serve_vcs_add_flag = 1;
    } else if (errcode < 0) {
      fprintf(flog, "failed to read serve configuration file `%s': %s\n",
              serve_cfg_path, super_proto_strerror(-errcode));
      goto failed;
    } else {
      snprintf(serve_audit_rec, sizeof(audit_rec),
               "# audit: edited %s %d (%s) %s\n",
               xml_unparse_date(time(0)), user_id, login,
               xml_unparse_ip(ip_address));
    }

    if ((sf = super_html_serve_unparse_and_save(serve_cfg_path, serve_cfg_path_2,
                                                sstate, config, NULL,
                                                serve_header, serve_footer,
                                                serve_audit_rec)) < 0)
      goto failed;
    xfree(serve_header); serve_header = 0;
    xfree(serve_footer); serve_footer = 0;

    if (sf > 0) {
      // invoke diff on the new and old config files
      snprintf(diff_cmdline, sizeof(diff_cmdline),
               "/usr/bin/diff -u \"%s\" \"%s\"", serve_cfg_path, serve_cfg_path_2);
      diff_str = read_process_output(diff_cmdline, 0, 1, 0);
      fprintf(flog, "Changes in serve.cfg:\n%s\n", diff_str);
      xfree(diff_str); diff_str = 0;
    }
  }

  /* 11. Save the XML file */
  errcode = contests_unparse_and_save(cnts, NULL, xml_header, xml_footer,
                                      audit_rec, diff_func, &diff_str);
  if (errcode < 0) {
    fprintf(flog, "error: saving of `%s' failed: %s\n", xml_path,
            contests_strerror(-errcode));
    goto failed;
  } else if (diff_str && *diff_str) {
    fprintf(flog, "contest XML file `%s' saved successfully\n", xml_path);
    fprintf(flog, "Changes in the file:\n%s\n", diff_str);
    if (vcs_add_flag && vcs_add(xml_path, &vcs_str) > 0) {
      fprintf(flog, "Version control:\n%s\n", vcs_str);
      xfree(vcs_str); vcs_str = 0;
    }
    if (vcs_commit(xml_path, &vcs_str) > 0) {
      fprintf(flog, "Version control:\n%s\n", vcs_str);
    }
  } else {
    if (vcs_add_flag) {
      fprintf(flog, "contest XML file `%s' is generated\n", xml_path);
      if (vcs_add(xml_path, &vcs_str) > 0) {
        fprintf(flog, "Version control:\n%s\n", vcs_str);
        xfree(vcs_str); vcs_str = 0;
      }
      if (vcs_commit(xml_path, &vcs_str) > 0) {
        fprintf(flog, "Version control:\n%s\n", vcs_str);
      }
    } else {
      fprintf(flog, "contest XML file `%s' is not changed\n", xml_path);
    }
  }
  xfree(diff_str); diff_str = 0;
  xfree(vcs_str); vcs_str = 0;
        

  /* 12. Rename files */
  rename_files(flog, uhf, users_header_path, users_header_path_2, file_group, file_mode);
  rename_files(flog, uff, users_footer_path, users_footer_path_2, file_group, file_mode);
  rename_files(flog, rhf, register_header_path, register_header_path_2, file_group, file_mode);
  rename_files(flog, rff, register_footer_path, register_footer_path_2, file_group, file_mode);
  rename_files(flog, thf, team_header_path, team_header_path_2, file_group, file_mode);
  
  rename_files(flog, t1f, team_menu_1_path, team_menu_1_path_2, file_group, file_mode);
  rename_files(flog, t2f, team_menu_2_path, team_menu_2_path_2, file_group, file_mode);
  rename_files(flog, t3f, team_menu_3_path, team_menu_3_path_2, file_group, file_mode);
  rename_files(flog, tsf, team_separator_path, team_separator_path_2, file_group, file_mode);
  rename_files(flog, tff, team_footer_path, team_footer_path_2, file_group, file_mode);
  rename_files(flog, ihf, priv_header_path, priv_header_path_2, file_group, file_mode);
  rename_files(flog, iff, priv_footer_path, priv_footer_path_2, file_group, file_mode);
  rename_files(flog, cpf, copyright_path, copyright_path_2, file_group, file_mode);
  rename_files(flog, cwf, welcome_path, welcome_path_2, file_group, file_mode);
  rename_files(flog, crwf, reg_welcome_path, reg_welcome_path_2, file_group, file_mode);
  rename_files(flog, ref, register_email_path, register_email_path_2, file_group, file_mode);
  rename_files(flog, csf, contest_start_cmd_path,contest_start_cmd_path_2,file_group,file_mode);
  if (csf) chmod(contest_start_cmd_path, 0775);

  rename_files(flog, csf, contest_stop_cmd_path,
               contest_stop_cmd_path_2, file_group,file_mode);
  if (ctf) chmod(contest_stop_cmd_path, 0775);

  rename_files(flog, shf, stand_header_path, stand_header_path_2, file_group, file_mode);
  rename_files(flog, sff, stand_footer_path, stand_footer_path_2, file_group, file_mode);
  rename_files(flog, s2hf, stand2_header_path, stand2_header_path_2, file_group, file_mode);
  rename_files(flog, s2ff, stand2_footer_path, stand2_footer_path_2, file_group, file_mode);
  rename_files(flog, phf, plog_header_path, plog_header_path_2, file_group, file_mode);
  rename_files(flog, pff, plog_footer_path, plog_footer_path_2, file_group, file_mode);
  file_perms_get(vmap_path, &old_vmap_group, &old_vmap_mode);
  rename_files(flog, vmf, vmap_path, vmap_path_2, file_group, file_mode);
  file_perms_get(serve_cfg_path, &old_serve_group, &old_serve_mode);
  rename_files(flog, sf, serve_cfg_path, serve_cfg_path_2, file_group, file_mode);

  if (vmf > 0) {
    if (vmap_vcs_add_flag && vcs_add(vmap_path, &vcs_str) > 0) {
      fprintf(flog, "Version control:\n%s\n", vcs_str);
      xfree(vcs_str); vcs_str = 0;
    }
    if (vcs_commit(vmap_path, &vcs_str) > 0) {
      fprintf(flog, "Version control:\n%s\n", vcs_str);
    }
    xfree(vcs_str); vcs_str = 0;
    file_perms_set(flog, vmap_path, file_group, file_mode,
                   old_vmap_group, old_vmap_mode);
  }

  if (sf > 0) {
    if (serve_vcs_add_flag && vcs_add(serve_cfg_path, &vcs_str) > 0) {
      fprintf(flog, "Version control:\n%s\n", vcs_str);
      xfree(vcs_str); vcs_str = 0;
    }
    if (vcs_commit(serve_cfg_path, &vcs_str) > 0) {
      fprintf(flog, "Version control:\n%s\n", vcs_str);
    }
    xfree(vcs_str); vcs_str = 0;
    file_perms_set(flog, serve_cfg_path, file_group, file_mode,
                   old_serve_group, old_serve_mode);
  }

  // FIXME: register and make invisible all the privileged users
  if (cnts && cnts->caps_node) {
    capp = (struct opcap_list_item*) cnts->caps_node->first_down;

    for (; capp; capp = (struct opcap_list_item*) capp->b.right) {
      if ((i = userlist_clnt_lookup_user(us_conn, capp->login, 0, &uid, NULL)) != ULS_LOGIN_OK) {
        fprintf(flog, "Error: cannot find user \"%s\": %s\n", capp->login,
                userlist_strerror(-i));
        continue;
      }
      if ((i = userlist_clnt_register_contest(us_conn,ULS_PRIV_REGISTER_CONTEST,
                                              uid, cnts->id, 0, 0)) < 0
          || (i = userlist_clnt_change_registration(us_conn, uid, cnts->id,
                                                    USERLIST_REG_OK, 0, 0)) < 0
          || (i = userlist_clnt_change_registration(us_conn,uid,cnts->id,-1, 1,
                                                    USERLIST_UC_INVISIBLE))<0) {
        fprintf(flog, "Error: failed to register user %s (%d) for contest %d: %s\n", capp->login, uid, cnts->id, userlist_strerror(-i));
        continue;
      }
      fprintf(flog, "user %s (%d) is registered for contest %d\n",
              capp->login, uid, cnts->id);
    }
  }

  /*
  if ((i = userlist_clnt_register_contest(us_conn, ULS_PRIV_REGISTER_CONTEST,
                                          user_id, cnts->id)) < 0
      || (i = userlist_clnt_change_registration(us_conn, user_id, cnts->id,
                                                USERLIST_REG_OK, 0, 0) < 0)) {
    fprintf(flog, "failed to register user %s (%d) for contest %d: %s\n",
            login, user_id, cnts->id, userlist_strerror(-i));
  } else {
    fprintf(flog, "user %s (%d) is registered for contest %d\n",
            login, user_id, cnts->id);
  }
  */

  // start serve and create all the necessary dirs
  close_memstream(flog); flog = 0;
  xfree(xml_header);
  xfree(xml_footer);

  /* all is done */
  fprintf(f, "<h2>Contest is saved successfully</h2>\n");
  s = html_armor_string_dup(flog_txt);
  fprintf(f, "<p>Contest saving log:<br><pre>%s</pre>\n", s);
  xfree(s);
  xfree(flog_txt);

  if (!sstate->serve_parse_errors) {
    flog_txt = 0; flog_size = 0;
    flog = open_memstream(&flog_txt, &flog_size);
    prepare_further_instructions(flog, cnts->root_dir, cnts->conf_dir,
                                 global, sstate->aprob_u, sstate->aprobs,
                                 sstate->prob_a, sstate->probs);
    close_memstream(flog); flog = 0;
    //s = html_armor_string_dup(flog_txt);
    fprintf(f, "<h2>Further instructions</h2>%s\n", flog_txt);
    //xfree(s);
    xfree(flog_txt); flog_txt = 0; flog_size = 0;
  }

  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td>%sTo the top</a></td>\n",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url,extra_args,0));

  unsigned char new_hidden_vars[1024];
  snprintf(new_hidden_vars, sizeof(new_hidden_vars),
           "%s<input type=\"hidden\" name=\"contest_id\" value=\"%d\"/>",
           hidden_vars, cnts->id);

  fprintf(f, "<td>");
  html_start_form(f, 1, self_url, new_hidden_vars);
  fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\"/>",
          SSERV_CMD_CHECK_TESTS, "Check contest settings");
  fprintf(f, "</form></td>\n");
  fprintf(f, "</tr></table>\n");

  super_serve_clear_edited_contest(sstate);
  return 0;

 failed:
  xfree(serve_header);
  xfree(serve_footer);
  xfree(xml_header);
  xfree(xml_footer);
  if (flog) close_memstream(flog);
  if (vmap_f) close_memstream(vmap_f);
  xfree(vmap_txt);

  if (users_header_path_2[0]) unlink(users_header_path_2);
  if (users_footer_path_2[0]) unlink(users_footer_path_2);
  if (register_header_path_2[0]) unlink(register_header_path_2);
  if (register_footer_path_2[0]) unlink(register_footer_path_2);
  if (team_header_path_2[0]) unlink(team_header_path_2);
  if (team_menu_1_path_2[0]) unlink(team_menu_1_path_2);
  if (team_menu_2_path_2[0]) unlink(team_menu_2_path_2);
  if (team_menu_3_path_2[0]) unlink(team_menu_3_path_2);
  if (team_separator_path_2[0]) unlink(team_separator_path_2);
  if (team_footer_path_2[0]) unlink(team_footer_path_2);
  if (priv_header_path_2[0]) unlink(priv_header_path_2);
  if (priv_footer_path_2[0]) unlink(priv_footer_path_2);
  if (copyright_path_2[0]) unlink(copyright_path_2);
  if (welcome_path_2[0]) unlink(welcome_path_2);
  if (reg_welcome_path_2[0]) unlink(reg_welcome_path_2);
  if (register_email_path_2[0]) unlink(register_email_path_2);
  if (contest_start_cmd_path_2[0]) unlink(contest_start_cmd_path_2);
  if (contest_stop_cmd_path_2[0]) unlink(contest_stop_cmd_path_2);
  if (stand_header_path_2[0]) unlink(stand_header_path_2);
  if (stand_footer_path_2[0]) unlink(stand_footer_path_2);
  if (stand2_header_path_2[0]) unlink(stand2_header_path_2);
  if (stand2_footer_path_2[0]) unlink(stand2_footer_path_2);
  if (plog_header_path_2[0]) unlink(plog_header_path_2);
  if (plog_footer_path_2[0]) unlink(plog_footer_path_2);
  if (serve_cfg_path_2[0]) unlink(serve_cfg_path_2);

  fprintf(f, "<h2><font color=\"red\">Contest saving failed</font></h2>\n");
  s = html_armor_string_dup(flog_txt);
  fprintf(f, "<p>Contest saving log:<br><pre>%s</pre>\n", s);
  xfree(s);
  xfree(flog_txt);
  fprintf(f, "<table border=\"0\"><tr>");
  fprintf(f, "<td>%sTo the top</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url,extra_args,0));
  fprintf(f, "<td>%sBack</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), session_id, self_url, extra_args,
                        "action=%d", SSERV_CMD_EDIT_CURRENT_CONTEST));
  fprintf(f, "</tr></table>\n");
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 * End:
 */
