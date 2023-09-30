/* -*- mode: c -*- */

/* Copyright (C) 2002-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/contests.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/userlist.h"
#include "ejudge/xml_utils.h"
#include "ejudge/misctext.h"
#include "ejudge/fileutl.h"
#include "ejudge/l10n.h"
#include "ejudge/ejudge_cfg.h"
#include "ejudge/meta/contests_meta.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

#if defined EJUDGE_CHARSET
#define INTERNAL_CHARSET EJUDGE_CHARSET
#else
#define INTERNAL_CHARSET "utf-8"
#endif

#define CONTEST_CHECK_TIME 5

const int contests_tag_to_meta_map[CONTEST_LAST_TAG] =
{
  [CONTEST_REGISTER_ACCESS] = CNTS_register_access,
  [CONTEST_USERS_ACCESS] = CNTS_users_access,
  [CONTEST_MASTER_ACCESS] = CNTS_master_access,
  [CONTEST_JUDGE_ACCESS] = CNTS_judge_access,
  [CONTEST_TEAM_ACCESS] = CNTS_team_access,
  [CONTEST_SERVE_CONTROL_ACCESS] = CNTS_serve_control_access,
  [CONTEST_NAME] = CNTS_name,
  [CONTEST_NAME_EN] = CNTS_name_en,
  [CONTEST_MAIN_URL] = CNTS_main_url,
  [CONTEST_KEYWORDS] = CNTS_keywords,
  [CONTEST_USERS_HEADER_FILE] = CNTS_users_header_file,
  [CONTEST_USERS_FOOTER_FILE] = CNTS_users_footer_file,
  [CONTEST_REGISTER_EMAIL] = CNTS_register_email,
  [CONTEST_REGISTER_URL] = CNTS_register_url,
  [CONTEST_LOGIN_TEMPLATE] = CNTS_login_template,
  [CONTEST_TEAM_URL] = CNTS_team_url,
  [CONTEST_REGISTRATION_DEADLINE] = CNTS_reg_deadline,
  [CONTEST_SCHED_TIME] = CNTS_sched_time,
  [CONTEST_ROOT_DIR] = CNTS_root_dir,
  [CONTEST_STANDINGS_URL] = CNTS_standings_url,
  [CONTEST_PROBLEMS_URL] = CNTS_problems_url,
  [CONTEST_SERVE_USER] = CNTS_serve_user,
  [CONTEST_SERVE_GROUP] = CNTS_serve_group,
  [CONTEST_REGISTER_HEADER_FILE] = CNTS_register_header_file,
  [CONTEST_REGISTER_FOOTER_FILE] = CNTS_register_footer_file,
  [CONTEST_TEAM_HEADER_FILE] = CNTS_team_header_file,
  [CONTEST_TEAM_MENU_1_FILE] = CNTS_team_menu_1_file,
  [CONTEST_TEAM_MENU_2_FILE] = CNTS_team_menu_2_file,
  [CONTEST_TEAM_MENU_3_FILE] = CNTS_team_menu_3_file,
  [CONTEST_TEAM_SEPARATOR_FILE] = CNTS_team_separator_file,
  [CONTEST_TEAM_FOOTER_FILE] = CNTS_team_footer_file,
  [CONTEST_COPYRIGHT_FILE] = CNTS_copyright_file,
  [CONTEST_USERS_HEAD_STYLE] = CNTS_users_head_style,
  [CONTEST_USERS_PAR_STYLE] = CNTS_users_par_style,
  [CONTEST_USERS_TABLE_STYLE] = CNTS_users_table_style,
  [CONTEST_USERS_VERB_STYLE] = CNTS_users_verb_style,
  [CONTEST_USERS_TABLE_FORMAT] = CNTS_users_table_format,
  [CONTEST_USERS_TABLE_FORMAT_EN] = CNTS_users_table_format_en,
  [CONTEST_USERS_TABLE_LEGEND] = CNTS_users_table_legend,
  [CONTEST_USERS_TABLE_LEGEND_EN] = CNTS_users_table_legend_en,
  [CONTEST_REGISTER_HEAD_STYLE] = CNTS_register_head_style,
  [CONTEST_REGISTER_PAR_STYLE] = CNTS_register_par_style,
  [CONTEST_REGISTER_TABLE_STYLE] = CNTS_register_table_style,
  [CONTEST_TEAM_HEAD_STYLE] = CNTS_team_head_style,
  [CONTEST_TEAM_PAR_STYLE] = CNTS_team_par_style,
  [CONTEST_CONF_DIR] = CNTS_conf_dir,
  [CONTEST_RUN_USER] = CNTS_run_user,
  [CONTEST_RUN_GROUP] = CNTS_run_group,
  [CONTEST_REGISTER_EMAIL_FILE] = CNTS_register_email_file,
  [CONTEST_USER_NAME_COMMENT] = CNTS_user_name_comment,
  [CONTEST_ALLOWED_LANGUAGES] = CNTS_allowed_languages,
  [CONTEST_CF_NOTIFY_EMAIL] = CNTS_cf_notify_email,
  [CONTEST_CLAR_NOTIFY_EMAIL] = CNTS_clar_notify_email,
  [CONTEST_DAILY_STAT_EMAIL] = CNTS_daily_stat_email,
  [CONTEST_PRIV_HEADER_FILE] = CNTS_priv_header_file,
  [CONTEST_PRIV_FOOTER_FILE] = CNTS_priv_footer_file,
  [CONTEST_ALLOWED_REGIONS] = CNTS_allowed_regions,
  [CONTEST_LOGIN_TEMPLATE_OPTIONS] = CNTS_login_template_options,
  [CONTEST_DIR_MODE] = CNTS_dir_mode,
  [CONTEST_DIR_GROUP] = CNTS_dir_group,
  [CONTEST_FILE_MODE] = CNTS_file_mode,
  [CONTEST_FILE_GROUP] = CNTS_file_group,
  [CONTEST_DEFAULT_LOCALE] = CNTS_default_locale,
  [CONTEST_WELCOME_FILE] = CNTS_welcome_file,
  [CONTEST_REG_WELCOME_FILE] = CNTS_reg_welcome_file,
  [CONTEST_USER_CONTEST] = CNTS_user_contest,
  [CONTEST_LOGO_URL] = CNTS_logo_url,
  [CONTEST_CSS_URL] = CNTS_css_url,
  [CONTEST_REGISTER_SUBJECT] = CNTS_register_subject,
  [CONTEST_REGISTER_SUBJECT_EN] = CNTS_register_subject_en,
  [CONTEST_OPEN_TIME] = CNTS_open_time,
  [CONTEST_CLOSE_TIME] = CNTS_close_time,
  [CONTEST_EXT_ID] = CNTS_ext_id,
  [CONTEST_UPDATE_TIME] = CNTS_update_time,
  [CONTEST_PROBLEM_COUNT] = CNTS_problem_count,
  [CONTEST_TELEGRAM_BOT_ID] = CNTS_telegram_bot_id,
  [CONTEST_TELEGRAM_ADMIN_CHAT_ID] = CNTS_telegram_admin_chat_id,
  [CONTEST_TELEGRAM_USER_CHAT_ID] = CNTS_telegram_user_chat_id,
  [CONTEST_AVATAR_PLUGIN] = CNTS_avatar_plugin,
  [CONTEST_CONTENT_PLUGIN] = CNTS_content_plugin,
  [CONTEST_CONTENT_URL_PREFIX] = CNTS_content_url_prefix,
  [CONTEST_COMMENT] = CNTS_comment,
  /*
  [CONTEST_OAUTH_RULES] = CNTS_oauth_rules,
  [CONTEST_OAUTH_RULE] = CNTS_oauth_rule,
  */
};
const int contests_attr_to_meta_map[CONTEST_LAST_ATTR] =
{
  [CONTEST_A_ID] = CNTS_id,
  [CONTEST_A_AUTOREGISTER] = CNTS_autoregister,
  [CONTEST_A_DISABLE_TEAM_PASSWORD] = CNTS_disable_team_password,
  [CONTEST_A_MANAGED] = CNTS_managed,
  [CONTEST_A_NEW_MANAGED] = CNTS_managed,
  [CONTEST_A_CLEAN_USERS] = CNTS_clean_users,
  [CONTEST_A_RUN_MANAGED] = CNTS_run_managed,
  [CONTEST_A_CLOSED] = CNTS_closed,
  [CONTEST_A_INVISIBLE] = CNTS_invisible,
  [CONTEST_A_SIMPLE_REGISTRATION] = CNTS_simple_registration,
  [CONTEST_A_SEND_PASSWD_EMAIL] = CNTS_send_passwd_email,
  [CONTEST_A_ASSIGN_LOGINS] = CNTS_assign_logins,
  [CONTEST_A_FORCE_REGISTRATION] = CNTS_force_registration,
  [CONTEST_A_DISABLE_NAME] = CNTS_disable_name,
  [CONTEST_A_ENABLE_FORGOT_PASSWORD] = CNTS_enable_password_recovery,
  [CONTEST_A_EXAM_MODE] = CNTS_exam_mode,
  [CONTEST_A_DISABLE_PASSWORD_CHANGE] = CNTS_disable_password_change,
  [CONTEST_A_DISABLE_LOCALE_CHANGE] = CNTS_disable_locale_change,
  [CONTEST_A_PERSONAL] = CNTS_personal,
  [CONTEST_A_ALLOW_REG_DATA_EDIT] = CNTS_allow_reg_data_edit,
  [CONTEST_A_ENABLE_PASSWORD_RECOVERY] = CNTS_enable_password_recovery,
  [CONTEST_A_DISABLE_MEMBER_DELETE] = CNTS_disable_member_delete,
  [CONTEST_A_OLD_RUN_MANAGED] = CNTS_old_run_managed,
  [CONTEST_A_READY] = CNTS_ready,
  [CONTEST_A_FORCE_PASSWORD_CHANGE] = CNTS_force_password_change,
  [CONTEST_A_ENABLE_USER_TELEGRAM] = CNTS_enable_user_telegram,
  [CONTEST_A_ENABLE_AVATAR] = CNTS_enable_avatar,
  [CONTEST_A_ENABLE_LOCAL_PAGES] = CNTS_enable_local_pages,
  [CONTEST_A_READ_ONLY_NAME] = CNTS_read_only_name,
  [CONTEST_A_ENABLE_OAUTH] = CNTS_enable_oauth,
  /*
  [CONTEST_A_DOMAIN] = CNTS_domain,
  [CONTEST_A_STRIP_DOMAIN] = CNTS_strip_domain,
  */
  [CONTEST_A_ENABLE_REMINDERS] = CNTS_enable_reminders,
  [CONTEST_A_DISABLE_STANDALONE_REG] = CNTS_disable_standalone_reg,
  [CONTEST_A_ENABLE_TELEGRAM_REGISTRATION] = CNTS_enable_telegram_registration,
};

char const * const contests_elem_map[] =
{
  0,
  "contests",
  "contest",
  "register_access",
  "users_access",
  "master_access",
  "judge_access",
  "team_access",
  "serve_control_access",
  "ip",
  "field",
  "name",
  "name_en",
  "main_url",
  "keywords",
  "contestants",
  "reserves",
  "coaches",
  "advisors",
  "guests",
  "users_header_file",
  "users_footer_file",
  "register_email",
  "register_url",
  "login_template",
  "team_url",
  "registration_deadline",
  "sched_time",
  "cap",
  "caps",
  "root_dir",
  "standings_url",
  "problems_url",
  "client_flags",
  "serve_user",
  "serve_group",
  "register_header_file",
  "register_footer_file",
  "team_header_file",
  "team_menu_1_file",
  "team_menu_2_file",
  "team_menu_3_file",
  "team_separator_file",
  "team_footer_file",
  "copyright_file",
  "users_head_style",
  "users_par_style",
  "users_table_style",
  "users_verb_style",
  "users_table_format",
  "users_table_format_en",
  "users_table_legend",
  "users_table_legend_en",
  "register_head_style",
  "register_par_style",
  "register_table_style",
  "team_head_style",
  "team_par_style",
  "conf_dir",
  "run_user",
  "run_group",
  "register_email_file",
  "user_name_comment",
  "allowed_languages",
  "cf_notify_email",
  "clar_notify_email",
  "daily_stat_email",
  "priv_header_file",
  "priv_footer_file",
  "allowed_regions",
  "login_template_options",
  "dir_mode",
  "dir_group",
  "file_mode",
  "file_group",
  "default_locale",
  "welcome_file",
  "reg_welcome_file",
  "slave_rules",
  "run_managed_on",
  "user_contest",
  "logo_url",
  "css_url",
  "register_subject",
  "register_subject_en",
  "open_time",
  "close_time",
  "ext_id",
  "update_time",
  "problem_count",
  "telegram_bot_id",
  "telegram_admin_chat_id",
  "telegram_user_chat_id",
  "avatar_plugin",
  "content_plugin",
  "content_url_prefix",
  "comment",
  "oauth_rules",
  "oauth_rule",

  0
};
char const * const contests_attr_map[] =
{
  0,
  "id",
  "default",
  "allow",
  "deny",
  "mandatory",
  "optional",
  "min",
  "max",
  "autoregister",
  "initial",
  "disable_team_password",
  "login",
  "managed",
  "new_managed",
  "clean_users",
  "run_managed",
  "closed",
  "invisible",
  "ssl",
  "simple_registration",
  "send_passwd_email",
  "assign_logins",
  "force_registration",
  "disable_name",
  "enable_forgot_password",
  "exam_mode",
  "disable_password_change",
  "disable_locale_change",
  "personal",
  "allow_reg_data_edit",
  "enable_password_recovery",
  "disable_member_delete",
  "separator",
  "options",
  "checkbox",
  "old_run_managed",
  "ready",
  "force_password_change",
  "enable_user_telegram",
  "enable_avatar",
  "enable_local_pages",
  "is_password",
  "read_only_name",
  "enable_oauth",
  "domain",
  "strip_domain",
  "disable_email_check",
  "enable_reminders",
  "disable_standalone_reg",
  "enable_telegram_registration",

  0
};
static size_t const elem_sizes[CONTEST_LAST_TAG] =
{
  [CONTEST_CONTESTS] = sizeof(struct contest_list),
  [CONTEST_CONTEST] = sizeof(struct contest_desc),
  [CONTEST_REGISTER_ACCESS] = sizeof(struct contest_access),
  [CONTEST_USERS_ACCESS] = sizeof(struct contest_access),
  [CONTEST_MASTER_ACCESS] = sizeof(struct contest_access),
  [CONTEST_JUDGE_ACCESS] = sizeof(struct contest_access),
  [CONTEST_TEAM_ACCESS] = sizeof(struct contest_access),
  [CONTEST_SERVE_CONTROL_ACCESS] = sizeof(struct contest_access),
  [CONTEST_IP] = sizeof(struct contest_ip),
  [CONTEST_FIELD] = sizeof(struct contest_field),
  [CONTEST_CONTESTANTS] = sizeof(struct contest_member),
  [CONTEST_RESERVES] = sizeof(struct contest_member),
  [CONTEST_COACHES] = sizeof(struct contest_member),
  [CONTEST_ADVISORS] = sizeof(struct contest_member),
  [CONTEST_GUESTS] = sizeof(struct contest_member),
  [CONTEST_CAP] = sizeof(struct opcap_list_item),
};

static void
node_free(struct xml_tree *t)
{
  int i;

  switch (t->tag) {
  case CONTEST_CONTESTS:
    xfree(((struct contest_list *) t)->id_map);
    break;
  case CONTEST_CONTEST:
    {
      struct contest_desc *cnts = (struct contest_desc*) t;
      // free everything of type 's'
      for (i = 1; i < CNTS_LAST_FIELD; ++i) {
        if (contest_desc_get_type(i) != 's') continue;
        unsigned char **p = (unsigned char **) contest_desc_get_ptr_nc(cnts, i);
        xfree(*p); *p = 0;
      }
    }
    break;
  case CONTEST_CAP:
    {
      struct opcap_list_item *pp = (struct opcap_list_item*) t;
      xfree(pp->login);
    }
    break;
  case CONTEST_FIELD:
    {
      struct contest_field *ff = (struct contest_field*) t;
      xfree(ff->legend);
      xfree(ff->separator);
      xfree(ff->options);
    }
    break;
  }
}

static struct xml_parse_spec contests_parse_spec =
{
  .elem_map = contests_elem_map,
  .attr_map = contests_attr_map,
  .elem_sizes = elem_sizes,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = node_free,
  .attr_free = NULL,
};

char const * const contests_field_map[] =
{
  0,
  "homepage",
  "phone",
  "inst",
  "inst_en",
  "instshort",
  "instshort_en",
  "instnum",
  "fac",
  "fac_en",
  "facshort",
  "facshort_en",
  "city",
  "city_en",
  "country",
  "country_en",
  "region",
  "area",
  "zip",
  "street",
  "languages",
  "field0",
  "field1",
  "field2",
  "field3",
  "field4",
  "field5",
  "field6",
  "field7",
  "field8",
  "field9",

  0
};

char const * const contests_member_field_map[] =
{
  0,
  "firstname",
  "firstname_en",
  "middlename",
  "middlename_en",
  "surname",
  "surname_en",
  "status",
  "gender",
  "grade",
  "group",
  "group_en",
  "email",
  "homepage",
  "phone",
  "inst",
  "inst_en",
  "instshort",
  "instshort_en",
  "fac",
  "fac_en",
  "facshort",
  "facshort_en",
  "occupation",
  "occupation_en",
  "discipline",
  "birth_date",
  "entry_date",
  "graduation_date",

  0,
};

static int
parse_access(struct contest_access *acc, char const *path)
{
  struct xml_attr *a;
  struct xml_tree *t;
  struct contest_ip *ip;

  for (a = acc->b.first; a; a = a->next) {
    switch (a->tag) {
    case CONTEST_A_DEFAULT:
      if (!strcasecmp(a->text, "allow")) {
        acc->default_is_allow = 1;
      } else if (!strcasecmp(a->text, "deny")) {
        acc->default_is_allow = 0;
      } else {
        return xml_err_attr_invalid(a);
      }
      xfree(a->text); a->text = 0;
      break;
    default:
      return xml_err_attr_not_allowed(&acc->b, a);
    }
  }

  for (t = acc->b.first_down; t; t = t->right) {
    if (t->tag != CONTEST_IP) return xml_err_elem_not_allowed(t);
    if (t->first_down) return xml_err_nested_elems(t);

    ip = (struct contest_ip*) t;
    ip->allow = -1;
    ip->ssl = -1;
    for (a = ip->b.first; a; a = a->next) {
      if (a->tag == CONTEST_A_SSL) {
        if (!strcasecmp(a->text, "yes")) {
          ip->ssl = 1;
        } else if (!strcasecmp(a->text, "no")) {
          ip->ssl = 0;
        } else if (!strcasecmp(a->text, "any")) {
          ip->ssl = -1;
        } else {
          return xml_err_attr_invalid(a);
        }
        xfree(a->text); a->text = 0;
        continue;
      }
      if (a->tag != CONTEST_A_ALLOW && a->tag != CONTEST_A_DENY)
        return xml_err_attr_not_allowed(&ip->b, a);
      if (ip->allow != -1) {
        xml_err_a(a, "attribute \"allow\" already defined");
        return -1;
      }
      if (xml_attr_bool(a, &ip->allow) < 0) return -1;
      if (a->tag == CONTEST_A_DENY) ip->allow = !ip->allow;
      xfree(a->text); a->text = 0;
    }
    if (ip->allow == -1) ip->allow = 0;

    if (xml_parse_ipv6_mask(NULL, path, ip->b.line, ip->b.column,
                          ip->b.text, &ip->addr, &ip->mask) < 0) return -1;
    xfree(t->text); t->text = 0;
  }

  xfree(acc->b.text); acc->b.text = 0;
  return 0;
}

static int
parse_member(struct contest_member *mb, char const *path)
{
  struct xml_attr *a;
  struct xml_tree *t;
  struct contest_field *pf;
  int i, n;

  /*
  mb->min_count = -1;
  mb->max_count = -1;
  */
  for (a = mb->b.first; a; a = a->next) {
    switch (a->tag) {
    case CONTEST_A_MIN:
    case CONTEST_A_MAX:
    case CONTEST_A_INITIAL:
      if (!a->text || sscanf(a->text, "%d %n", &i, &n) != 1
          || a->text[n] || i < 0 || i > 100)
        return xml_err_attr_invalid(a);
      switch (a->tag) {
      case CONTEST_A_MIN:     mb->min_count = i;  break;
      case CONTEST_A_MAX:     mb->max_count = i;  break;
      case CONTEST_A_INITIAL: mb->init_count = i; break;
      }
      xfree(a->text); a->text = 0;
      break;
    default:
      return xml_err_attr_not_allowed(&mb->b, a);
    }
  }

  xfree(mb->b.text); mb->b.text = 0;
  for (t = mb->b.first_down; t; t = t->right) {
    if (t->tag != CONTEST_FIELD) return xml_err_elem_not_allowed(t);
    if (t->first_down) return xml_err_nested_elems(t);
    pf = (struct contest_field*) t;
    if (t->text && *t->text) {
      pf->legend = t->text; t->text = 0;
    }
    xfree(t->text); t->text = 0;

    pf->mandatory = -1;
    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case CONTEST_A_ID:
        for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
          if (!contests_member_field_map[i]) continue;
          if (!strcmp(a->text, contests_member_field_map[i])) break;
        }
        if (i >= CONTEST_LAST_MEMBER_FIELD) {
          xml_err_a(a, "invalid field id \"%s\"", a->text);
          return -1;
        }
        if (mb->fields[i]) {
          xml_err_a(a, "field \"%s\" already defined", a->text);
          return -1;
        }
        mb->fields[i] = pf;
        break;
      case CONTEST_A_MANDATORY:
      case CONTEST_A_OPTIONAL:
        if (pf->mandatory != -1) {
          xml_err_a(a, "attribute \"mandatory\" already defined");
          return -1;
        }
        if (xml_attr_bool(a, &pf->mandatory) < 0) return -1;
        if (a->tag == CONTEST_A_OPTIONAL) pf->mandatory = !pf->mandatory;
        break;
      case CONTEST_A_IS_PASSWORD:
        if (xml_attr_bool(a, &pf->is_password) < 0) return -1;
        break;
      default:
        return xml_err_attr_not_allowed(t, a);
      }
    }
    if (pf->mandatory == -1) pf->mandatory = 0;
  }
  return 0;
}

static int
handle_final_tag(char const *path, struct xml_tree *t, unsigned char **ps)
{
  if (*ps) {
    err("%s:%d:%d: duplicated element <%s>",
        path, t->line, t->column, contests_elem_map[t->tag]);
    return -1;
  }
  /*
  if (!t->text || !*t->text) {
    err("%s:%d:%d: empty element <%s>", path, t->line, t->column,
        contests_elem_map[t->tag]);
    return -1;
  }
  */
  if (t->first_down) {
    err("%s:%d:%d: element <%s> cannot contain nested elements",
        path, t->line, t->column, contests_elem_map[t->tag]);
    return -1;
  }
  if (t->first) {
    err("%s:%d:%d: element <%s> cannot have attributes",
        path, t->line, t->column, contests_elem_map[t->tag]);
    return -1;
  }
  *ps = t->text; t->text = 0;
  return 0;
}

static int
parse_capabilities(unsigned char const *path,
                   struct contest_desc *cnts,
                   struct xml_tree *ct)
{
  struct xml_tree *p;
  struct opcap_list_item *pp, *qq;

  ASSERT(ct->tag == CONTEST_CAPS);

  if (cnts->capabilities.first) return xml_err_elem_redefined(ct);

  cnts->caps_node = ct;
  xfree(ct->text); ct->text = 0;
  if (ct->first) return xml_err_attrs(ct);
  p = ct->first_down;
  if (!p) return 0;
  cnts->capabilities.first = (struct opcap_list_item*) p;

  for (; p; p = p->right) {
    if (p->tag != CONTEST_CAP) return xml_err_elem_not_allowed(p);
    pp = (struct opcap_list_item*) p;

    if (!p->first) return xml_err_attr_undefined(p, CONTEST_A_LOGIN);
    if (p->first->next) return xml_err_attr_not_allowed(p, p->first->next);
    if (p->first->tag != CONTEST_A_LOGIN)
      return xml_err_attr_undefined(p, CONTEST_A_LOGIN);
    pp->login = p->first->text; p->first->text = 0;
    if (!pp->login || !*pp->login) return xml_err_attr_invalid(p->first);
    for (qq = CNTS_FIRST_PERM(cnts); qq != pp; qq = CNTS_NEXT_PERM_NC(qq)) {
      if (!strcmp(pp->login, qq->login)) {
        xml_err(p, "duplicated login");
        return -1;
      }
    }
    if (opcaps_parse(p->text, &pp->caps) < 0) return xml_err_elem_invalid(p);
    xfree(p->text); p->text = 0;
  }
  return 0;
}

static int
parse_client_flags(unsigned char const *path, struct contest_desc *cnts,
                   struct xml_tree *xt)
{
  int len;
  unsigned char *str2, *q, *str3;
  unsigned char const *p, *s, *str;

  str = xt->text;
  if (!str) str = "";
  len = strlen(str);
  str2 = (unsigned char *) alloca(len + 10);
  for (p = str, q = str2; *p; p++) {
    if (isspace(*p)) continue;
    if (isalpha(*p)) {
      *q++ = toupper(*p);
    } else {
      *q++ = *p;
    }
  }
  *q++ = 0;

  str3 = (unsigned char *) alloca(len + 10);
  p = str2;
  while (1) {
    while (*p == ',') p++;
    if (!*p) break;
    for (s = p; *s && *s != ','; s++);
    memset(str3, 0, len + 10);
    memcpy(str3, p, s - p);
    p = s;

    if (!strcmp(str3, "IGNORE_TIME_SKEW")) {
      /* DO NOTHING: compatibility with previous versions */
    } else if (!strcmp(str3, "DISABLE_TEAM")) {
      /* DO NOTHING: compatibility with previous versions */
    } else if (!strcmp(str3, "DISABLE_MEMBER_DELETE")) {
      cnts->disable_member_delete = 1;
    } else {
      return xml_err_elem_invalid(xt);
    }
  }

  xfree(xt->text); xt->text = 0;
  return 0;
}

static void
process_conf_file_path(struct contest_desc *cnts, unsigned char **pstr)
{
  unsigned char *str = *pstr;
  unsigned char pathbuf[PATH_MAX];

  if (!str || os_IsAbsolutePath(str) || !cnts->conf_dir) return;
  snprintf(pathbuf, sizeof(pathbuf), "%s/%s", cnts->conf_dir, str);
  xfree(str);
  str = xstrdup(pathbuf);
  *pstr = str;
}

static const unsigned char contest_final_set[CONTEST_LAST_TAG] =
{
  [CONTEST_NAME] = 1,
  [CONTEST_NAME_EN] = 1,
  [CONTEST_MAIN_URL] = 1,
  [CONTEST_KEYWORDS] = 1,
  [CONTEST_USERS_HEADER_FILE] = 1,
  [CONTEST_USERS_FOOTER_FILE] = 1,
  [CONTEST_REGISTER_EMAIL] = 1,
  [CONTEST_REGISTER_URL] = 1,
  [CONTEST_LOGIN_TEMPLATE] = 1,
  [CONTEST_LOGIN_TEMPLATE_OPTIONS] = 1,
  [CONTEST_TEAM_URL] = 1,
  [CONTEST_ROOT_DIR] = 1,
  [CONTEST_STANDINGS_URL] = 1,
  [CONTEST_PROBLEMS_URL] = 1,
  [CONTEST_SERVE_USER] = 1,
  [CONTEST_SERVE_GROUP] = 1,
  [CONTEST_REGISTER_HEADER_FILE] = 1,
  [CONTEST_REGISTER_FOOTER_FILE] = 1,
  [CONTEST_TEAM_HEADER_FILE] = 1,
  [CONTEST_TEAM_MENU_1_FILE] = 1,
  [CONTEST_TEAM_MENU_2_FILE] = 1,
  [CONTEST_TEAM_MENU_3_FILE] = 1,
  [CONTEST_TEAM_SEPARATOR_FILE] = 1,
  [CONTEST_TEAM_FOOTER_FILE] = 1,
  [CONTEST_COPYRIGHT_FILE] = 1,
  [CONTEST_USERS_HEAD_STYLE] = 1,
  [CONTEST_USERS_PAR_STYLE] = 1,
  [CONTEST_USERS_TABLE_STYLE] = 1,
  [CONTEST_USERS_VERB_STYLE] = 1,
  [CONTEST_USERS_TABLE_FORMAT] = 1,
  [CONTEST_USERS_TABLE_FORMAT_EN] = 1,
  [CONTEST_USERS_TABLE_LEGEND] = 1,
  [CONTEST_USERS_TABLE_LEGEND_EN] = 1,
  [CONTEST_REGISTER_HEAD_STYLE] = 1,
  [CONTEST_REGISTER_PAR_STYLE] = 1,
  [CONTEST_REGISTER_TABLE_STYLE] = 1,
  [CONTEST_TEAM_HEAD_STYLE] = 1,
  [CONTEST_TEAM_PAR_STYLE] = 1,
  [CONTEST_CONF_DIR] = 1,
  [CONTEST_RUN_USER] = 1,
  [CONTEST_RUN_GROUP] = 1,
  [CONTEST_REGISTER_EMAIL_FILE] = 1,
  [CONTEST_USER_NAME_COMMENT] = 1,
  [CONTEST_ALLOWED_LANGUAGES] = 1,
  [CONTEST_ALLOWED_REGIONS] = 1,
  [CONTEST_CF_NOTIFY_EMAIL] = 1,
  [CONTEST_CLAR_NOTIFY_EMAIL] = 1,
  [CONTEST_DAILY_STAT_EMAIL] = 1,
  [CONTEST_PRIV_HEADER_FILE] = 1,
  [CONTEST_PRIV_FOOTER_FILE] = 1,
  [CONTEST_DIR_MODE] = 1,
  [CONTEST_DIR_GROUP] = 1,
  [CONTEST_FILE_MODE] = 1,
  [CONTEST_FILE_GROUP] = 1,
  [CONTEST_DEFAULT_LOCALE] = 1,
  [CONTEST_WELCOME_FILE] = 1,
  [CONTEST_REG_WELCOME_FILE] = 1,
  [CONTEST_USER_CONTEST] = 1,
  [CONTEST_LOGO_URL] = 1,
  [CONTEST_CSS_URL] = 1,
  [CONTEST_REGISTER_SUBJECT] = 1,
  [CONTEST_REGISTER_SUBJECT_EN] = 1,
  [CONTEST_EXT_ID]  = 1,
  [CONTEST_PROBLEM_COUNT] = 1,
  [CONTEST_TELEGRAM_BOT_ID] = 1,
  [CONTEST_TELEGRAM_ADMIN_CHAT_ID] = 1,
  [CONTEST_TELEGRAM_USER_CHAT_ID] = 1,
  [CONTEST_AVATAR_PLUGIN] = 1,
  [CONTEST_CONTENT_PLUGIN] = 1,
  [CONTEST_CONTENT_URL_PREFIX] = 1,
  [CONTEST_COMMENT] = 1,
};

static const unsigned char contest_access_set[CONTEST_LAST_TAG] =
{
  [CONTEST_REGISTER_ACCESS] = 1,
  [CONTEST_USERS_ACCESS] = 1,
  [CONTEST_MASTER_ACCESS] = 1,
  [CONTEST_JUDGE_ACCESS] = 1,
  [CONTEST_TEAM_ACCESS] = 1,
  [CONTEST_SERVE_CONTROL_ACCESS] = 1,
};

static const unsigned char contest_bool_attr_set[CONTEST_LAST_ATTR] =
{
  [CONTEST_A_AUTOREGISTER] = 1,
  [CONTEST_A_DISABLE_TEAM_PASSWORD] = 1,
  [CONTEST_A_MANAGED] = 1,
  [CONTEST_A_NEW_MANAGED] = 1,
  [CONTEST_A_CLEAN_USERS] = 1,
  [CONTEST_A_RUN_MANAGED] = 1,
  [CONTEST_A_CLOSED] = 1,
  [CONTEST_A_INVISIBLE] = 1,
  [CONTEST_A_SIMPLE_REGISTRATION] = 1,
  [CONTEST_A_SEND_PASSWD_EMAIL] = 1,
  [CONTEST_A_ASSIGN_LOGINS] = 1,
  [CONTEST_A_FORCE_REGISTRATION] = 1,
  [CONTEST_A_DISABLE_NAME] = 1,
  [CONTEST_A_ENABLE_FORGOT_PASSWORD] = 1,
  [CONTEST_A_EXAM_MODE] = 1,
  [CONTEST_A_DISABLE_PASSWORD_CHANGE] = 1,
  [CONTEST_A_DISABLE_LOCALE_CHANGE] = 1,
  [CONTEST_A_PERSONAL] = 1,
  [CONTEST_A_ALLOW_REG_DATA_EDIT] = 1,
  [CONTEST_A_ENABLE_PASSWORD_RECOVERY] = 1,
  [CONTEST_A_DISABLE_MEMBER_DELETE] = 1,
  [CONTEST_A_OLD_RUN_MANAGED] = 1,
  [CONTEST_A_READY] = 1,
  [CONTEST_A_FORCE_PASSWORD_CHANGE] = 1,
  [CONTEST_A_ENABLE_USER_TELEGRAM] = 1,
  [CONTEST_A_ENABLE_AVATAR] = 1,
  [CONTEST_A_ENABLE_LOCAL_PAGES] = 1,
  [CONTEST_A_READ_ONLY_NAME] = 1,
  [CONTEST_A_ENABLE_OAUTH] = 1,
  [CONTEST_A_ENABLE_REMINDERS] = 1,
  [CONTEST_A_DISABLE_STANDALONE_REG] = 1,
  [CONTEST_A_ENABLE_TELEGRAM_REGISTRATION] = 1,
};

static void
fix_personal_contest(struct contest_desc *cnts)
{
  struct xml_tree *p;
  struct contest_member *m;

  if (!cnts->personal) return;

  if (!cnts->members[CONTEST_M_CONTESTANT]) {
    p = contests_new_node(CONTEST_CONTESTANTS);
    xml_link_node_last(&cnts->b, p);
    cnts->members[CONTEST_M_CONTESTANT] = (struct contest_member*) p;
  }
  m = cnts->members[CONTEST_M_CONTESTANT];
  m->min_count = 1;
  m->max_count = 1;
  m->init_count = 1;

  if (cnts->members[CONTEST_M_RESERVE]) {
    p = (struct xml_tree*) cnts->members[CONTEST_M_RESERVE];
    xml_unlink_node(p);
    xml_tree_free(p, &contests_parse_spec);
    cnts->members[CONTEST_M_RESERVE] = 0;
  }
}

int
contests_guess_id(const char *path)
{
  if (!path) return -1;
  const char *p = strrchr(path, '/');
  if (!p) p = path;
  else ++p;
  int x = 0, n = 0;
  if (sscanf(p, "%d%n", &x, &n) != 1) return -1;
  if (x <= 0) return -1;
  if (strcmp(p + n, ".xml") != 0) return -1;
  return x;
}

static int
parse_contest(
        struct contest_desc *cnts,
        char const *path,
        int no_subst_flag,
        int auto_contest_id)
{
  struct xml_attr *a;
  struct xml_tree *t;
  int x, n, mb_id, i;
  unsigned char *date_str = 0;
  struct contest_access **pacc;
  unsigned char pathbuf[PATH_MAX];
  unsigned char *p_field;
  unsigned char **p_str;
  char *eptr;
  const int *flist;

  cnts->clean_users = 1;

  for (a = cnts->b.first; a; a = a->next) {
    if (contest_bool_attr_set[a->tag] > 0) {
      // boolean fields
      p_field = (unsigned char*) contest_desc_get_ptr_nc(cnts, contests_attr_to_meta_map[a->tag]);
      if (xml_attr_bool_byte(a, p_field) < 0) return -1;
      continue;
    }

    switch (a->tag) {
    case CONTEST_A_ID:
      if (!strcmp(a->text, "auto")) {
        if (auto_contest_id > 0) {
          cnts->id = auto_contest_id;
        } else if (auto_contest_id == -1) {
          x = contests_guess_id(path);
          if (x > 0) cnts->id = x;
        }
      } else {
        x = n = 0;
        if (sscanf(a->text, "%d %n", &x, &n) != 1 || a->text[n]
            || x <= 0 || x > EJ_MAX_CONTEST_ID) return xml_err_attr_invalid(a);
        cnts->id = x;
      }
      break;
    default:
      return xml_err_attr_not_allowed(&cnts->b, a);
    }
  }

  if (!cnts->id) return xml_err_attr_undefined(&cnts->b, CONTEST_A_ID);

  for (t = cnts->b.first_down; t; t = t->right) {
    if (contest_final_set[t->tag] > 0) {
      p_str = (unsigned char**) contest_desc_get_ptr_nc(cnts, contests_tag_to_meta_map[t->tag]);
      if (xml_leaf_elem(t, p_str, 1, 0) < 0) return -1;
      continue;
    }
    if (contest_access_set[t->tag] > 0) {
      pacc = (struct contest_access**) contest_desc_get_ptr_nc(cnts, contests_tag_to_meta_map[t->tag]);
      if (*pacc) return xml_err_elem_redefined(t);
      *pacc = (struct contest_access*) t;
      if (parse_access(*pacc, path) < 0) return -1;
      continue;
    }

    switch(t->tag) {
    case CONTEST_CLIENT_FLAGS:
      if (t->first_down) return xml_err_nested_elems(t);
      if (t->first) return xml_err_attrs(t);
      if (parse_client_flags(path, cnts, t) < 0) return -1;
      break;
    case CONTEST_REGISTRATION_DEADLINE:
    case CONTEST_SCHED_TIME:
    case CONTEST_OPEN_TIME:
    case CONTEST_CLOSE_TIME:
    case CONTEST_UPDATE_TIME:
      if (handle_final_tag(path, t, &date_str) < 0) {
        xfree(date_str);
        return -1;
      }
      if (xml_parse_date(NULL, path, t->line, t->column, date_str, (time_t*) contest_desc_get_ptr_nc(cnts, contests_tag_to_meta_map[t->tag])) < 0) {
        xfree(date_str); date_str = 0;
        return -1;
      }
      xfree(date_str); date_str = 0;
      break;
    case CONTEST_SLAVE_RULES:
      cnts->slave_rules = t;
      break;

    case CONTEST_OAUTH_RULES:
      cnts->oauth_rules = t;
      break;

    case CONTEST_CAPS:
      if (parse_capabilities(path, cnts, t) < 0) return -1;
      break;

    case CONTEST_CONTESTANTS:
      mb_id = CONTEST_M_CONTESTANT;
      goto process_members;
    case CONTEST_RESERVES:
      mb_id = CONTEST_M_RESERVE;
      goto process_members;
    case CONTEST_COACHES:
      mb_id = CONTEST_M_COACH;
      goto process_members;
    case CONTEST_ADVISORS:
      mb_id = CONTEST_M_ADVISOR;
      goto process_members;
    case CONTEST_GUESTS:
      mb_id = CONTEST_M_GUEST;

    process_members:
      if (cnts->members[mb_id]) return xml_err_elem_redefined(t);
      if (parse_member((struct contest_member*) t, path) < 0)
        return -1;
      cnts->members[mb_id] = (struct contest_member*) t;
      break;

    case CONTEST_FIELD:
      if (t->first_down) return xml_err_nested_elems(t);
      {
        struct contest_field *pf = (struct contest_field*) t;
        int i;

        if (t->text && *t->text) {
          pf->legend = t->text; t->text = 0;
        }
        xfree(t->text); t->text = 0;

        pf->mandatory = -1;
        for (a = t->first; a; a = a->next) {
          switch (a->tag) {
          case CONTEST_A_ID:
            for (i = 1; i < CONTEST_LAST_FIELD; i++) {
              if (!contests_field_map[i]) continue;
              if (!strcmp(a->text, contests_field_map[i])) break;
            }
            if (i >= CONTEST_LAST_FIELD) {
              xml_err_a(a, "invalid field id \"%s\"", a->text);
              return -1;
            }
            if (cnts->fields[i]) {
              xml_err_a(a, "field \"%s\" already defined", a->text);
              return -1;
            }
            cnts->fields[i] = pf;
            break;
          case CONTEST_A_MANDATORY:
          case CONTEST_A_OPTIONAL:
            if (pf->mandatory != -1) {
              xml_err_a(a, "attribute \"mandatory\" already defined");
              return -1;
            }
            if (xml_attr_bool(a, &pf->mandatory) < 0) return -1;
            if (a->tag == CONTEST_A_OPTIONAL) pf->mandatory = !pf->mandatory;
            break;
          case CONTEST_A_SEPARATOR:
            pf->separator = a->text; a->text = 0;
            break;
          case CONTEST_A_OPTIONS:
            pf->options = a->text; a->text = 0;
            break;
          case CONTEST_A_CHECKBOX:
            if (xml_attr_bool(a, &pf->checkbox) < 0) return -1;
            break;
          default:
            return xml_err_attr_not_allowed(t, a);
          }
        }
        if (pf->mandatory == -1) pf->mandatory = 0;
      }
      break;

    default:
      return xml_err_elem_not_allowed(t);
    }
  }
  xfree(cnts->b.text); cnts->b.text = 0;

  if (!cnts->name) return xml_err_elem_undefined(&cnts->b, CONTEST_NAME);

  if (!cnts->root_dir) {
    // use the standard pattern?
    snprintf(pathbuf, sizeof(pathbuf), "%06d", cnts->id);
    cnts->root_dir = xstrdup(pathbuf);
  }
  if (!os_IsAbsolutePath(cnts->root_dir) && ejudge_config
      && ejudge_config->contests_home_dir
      && os_IsAbsolutePath(ejudge_config->contests_home_dir)) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
             ejudge_config->contests_home_dir, cnts->root_dir);
    xfree(cnts->root_dir);
    cnts->root_dir = xstrdup(pathbuf);
  }
#if defined EJUDGE_CONTESTS_HOME_DIR
  if (!os_IsAbsolutePath(cnts->root_dir)
      && os_IsAbsolutePath(EJUDGE_CONTESTS_HOME_DIR)) {
    snprintf(pathbuf, sizeof(pathbuf), "%s/%s", EJUDGE_CONTESTS_HOME_DIR,
             cnts->root_dir);
    xfree(cnts->root_dir);
    cnts->root_dir = xstrdup(pathbuf);
  }
#endif
  if (!os_IsAbsolutePath(cnts->root_dir)) {
    xml_err(&cnts->b, "<root_dir> must be absolute path");
    return -1;
  }

  if (!no_subst_flag) {
    if (cnts->root_dir && !cnts->conf_dir) {
      snprintf(pathbuf, sizeof(pathbuf), "%s/conf", cnts->root_dir);
      cnts->conf_dir = xstrdup(pathbuf);
    } else if (cnts->root_dir && !os_IsAbsolutePath(cnts->conf_dir)) {
      snprintf(pathbuf, sizeof(pathbuf), "%s/%s", cnts->root_dir,cnts->conf_dir);
      xfree(cnts->conf_dir);
      cnts->conf_dir = xstrdup(pathbuf);
    } else if (!cnts->root_dir && cnts->conf_dir
               && !os_IsAbsolutePath(cnts->conf_dir)) {
      xml_err(&cnts->b, "<conf_dir> must be absolute path");
      return -1;
    }

    flist = (const int[]) {
      CNTS_register_header_file, CNTS_register_footer_file,
      CNTS_users_header_file, CNTS_users_footer_file,
      CNTS_team_header_file, CNTS_team_menu_1_file, CNTS_team_menu_2_file,
      CNTS_team_menu_3_file, CNTS_team_separator_file, CNTS_team_footer_file,
      CNTS_copyright_file, CNTS_register_email_file,
      CNTS_priv_header_file, CNTS_priv_footer_file,
      CNTS_welcome_file, CNTS_reg_welcome_file,
      0 };
    for (i = 0; flist[i]; ++i) {
      process_conf_file_path(cnts,
                             (unsigned char**)contest_desc_get_ptr_nc(cnts, flist[i]));
    }

    if (!cnts->users_head_style) {
      cnts->users_head_style = xstrdup("h2");
    }
    if (!cnts->register_head_style) {
      cnts->register_head_style = xstrdup("h2");
    }
    if (!cnts->team_head_style) {
      cnts->team_head_style = xstrdup("h2");
    }
    if (!cnts->users_par_style)
      cnts->users_par_style = xstrdup("");
    if (!cnts->register_par_style)
      cnts->register_par_style = xstrdup("");
    if (!cnts->team_par_style)
      cnts->team_par_style = xstrdup("");
    if (!cnts->users_table_style)
      cnts->users_table_style = xstrdup("");
    if (!cnts->register_table_style)
      cnts->register_table_style = xstrdup("");
    if (!cnts->users_verb_style)
      cnts->users_verb_style = xstrdup("");
  }

  if (cnts->user_contest) {
    errno = 0;
    cnts->user_contest_num = strtol(cnts->user_contest, &eptr, 10);
    if (*eptr || errno || cnts->user_contest_num < 0) {
      xml_err(&cnts->b, "invalid value of <user_contest>");
      return -1;
    }
  }

  /* personal contests do not have "reserve" and have only one participant */
  fix_personal_contest(cnts);

  cnts->default_locale_num = l10n_parse_locale(cnts->default_locale);

  return 0;
}

static struct contest_desc *
parse_one_contest_xml(
        char const *path,
        int no_subst_flag,
        int auto_contest_id)
{
  struct xml_tree *tree = 0;
  struct contest_desc *d = 0;

  xml_err_path = path;
  xml_err_spec = &contests_parse_spec;

  tree = xml_build_tree(NULL, path, &contests_parse_spec);
  if (!tree) goto failed;
  if (tree->tag != CONTEST_CONTEST) {
    xml_err_top_level(tree, CONTEST_CONTEST);
    goto failed;
  }
  d = (struct contest_desc *) tree;
  if (parse_contest(d, path, no_subst_flag, auto_contest_id) < 0) goto failed;
  return d;

 failed:
  if (tree) xml_tree_free(tree, &contests_parse_spec);
  return 0;
}

static void
contests_merge(struct contest_desc *pold, struct contest_desc *pnew)
{
  struct xml_tree *p, *q;
  int i;
  unsigned char **p_str_old, **p_str_new;
  struct contest_access **p_acc_old, **p_acc_new;
  unsigned char *p_b_old, *p_b_new;

  // unlink and free all the old root node childs
  for (p = pold->b.first_down; p; p = q) {
    q = p->right;
    xml_unlink_node(p);
    xml_tree_free(p, &contests_parse_spec);
  }

  // copy offsetted fields
  for (i = 0; i < CONTEST_LAST_TAG; i++) {
    if (contest_final_set[i]) {
      p_str_old = (unsigned char**) contest_desc_get_ptr_nc(pold, contests_tag_to_meta_map[i]);
      p_str_new = (unsigned char**) contest_desc_get_ptr_nc(pnew, contests_tag_to_meta_map[i]);
      xfree(*p_str_old);
      *p_str_old = *p_str_new;
      *p_str_new = 0;
    } else if (contest_access_set[i]) {
      p_acc_old = (struct contest_access**) contest_desc_get_ptr_nc(pold, contests_tag_to_meta_map[i]);
      p_acc_new = (struct contest_access**) contest_desc_get_ptr_nc(pnew, contests_tag_to_meta_map[i]);
      p = &(*p_acc_new)->b;
      if (p) {
        xml_unlink_node(p);
        xml_link_node_last(&pold->b, p);
      }
      *p_acc_old = (struct contest_access*) p;
      *p_acc_new = 0;
    }
  }
  for (i = 0; i < CONTEST_LAST_ATTR; i++) {
    if (contest_bool_attr_set[i]) {
      p_b_old = (unsigned char*) contest_desc_get_ptr_nc(pold, contests_attr_to_meta_map[i]);
      p_b_new = (unsigned char*) contest_desc_get_ptr_nc(pnew, contests_attr_to_meta_map[i]);
      *p_b_old = *p_b_new;
    }
  }

  for (i = CONTEST_FIRST_FIELD; i < CONTEST_LAST_FIELD; i++) {
    p = (struct xml_tree*) pnew->fields[i];
    if (p) {
      xml_unlink_node(p);
      xml_link_node_last(&pold->b, p);
    }
    pold->fields[i] = (struct contest_field*) p;
    pnew->fields[i] = 0;
  }
  for (i = 0; i < CONTEST_LAST_MEMBER; i++) {
    p = (struct xml_tree*) pnew->members[i];
    if (p) {
      xml_unlink_node(p);
      xml_link_node_last(&pold->b, p);
    }
    pold->members[i] = (struct contest_member*) p;
    pnew->members[i] = 0;
  }
  p = pnew->caps_node;
  if (p) {
    xml_unlink_node(p);
    xml_link_node_last(&pold->b, p);
  }
  pold->caps_node = p;
  pnew->caps_node = 0;
  pold->capabilities.first = pnew->capabilities.first;
  pnew->capabilities.first = 0;

  if ((p = pnew->slave_rules)) {
    xml_unlink_node(p);
    xml_link_node_last(&pold->b, p);
  }
  pold->slave_rules = p;
  pnew->slave_rules = 0;

  if ((p = pnew->oauth_rules)) {
    xml_unlink_node(p);
    xml_link_node_last(&pold->b, p);
  }
  pold->oauth_rules = p;
  pnew->oauth_rules = NULL;

  pold->reg_deadline = pnew->reg_deadline;
  pold->sched_time = pnew->sched_time;
  pold->disable_member_delete = pnew->disable_member_delete;
  pold->last_check_time = pnew->last_check_time;
  pold->last_file_time = pnew->last_file_time;
  pold->user_contest_num = pnew->user_contest_num;
  pold->open_time = pnew->open_time;
  pold->close_time = pnew->close_time;

  pold->default_locale_num = l10n_parse_locale(pold->default_locale);
}

int
contests_load(int number, struct contest_desc **p_cnts)
{
  unsigned char c_path[PATH_MAX];
  struct stat sb;
  struct contest_desc *cnts;

  ASSERT(p_cnts);
  *p_cnts = 0;
  contests_make_path(c_path, sizeof(c_path), number);
  if (stat(c_path, &sb) < 0) return -CONTEST_ERR_NO_CONTEST;
  cnts = parse_one_contest_xml(c_path, 1, number);
  if (!cnts) return -CONTEST_ERR_BAD_XML;
  if (cnts->id != number) {
    contests_free(cnts);
    return -CONTEST_ERR_ID_NOT_MATCH;
  }
  *p_cnts = cnts;
  return 0;
}

int
contests_load_file(const unsigned char *path, struct contest_desc **p_cnts)
{
  struct stat sb;
  struct contest_desc *cnts;

  ASSERT(p_cnts);
  *p_cnts = 0;
  if (stat(path, &sb) < 0) return -CONTEST_ERR_NO_CONTEST;
  cnts = parse_one_contest_xml(path, 1, -1);
  if (!cnts) return -CONTEST_ERR_BAD_XML;
  *p_cnts = cnts;
  return 0;
}

struct xml_tree *
contests_new_node(int tag)
{
  struct xml_tree *p = xml_elem_alloc(tag, elem_sizes);
  p->tag = tag;
  return p;
}

static int
do_check_ip(struct contest_access *acc, const ej_ip_t *pip, int ssl)
{
  struct contest_ip *p;

  if (!acc) return 0;
  //if (!ip && acc->default_is_allow) return 1;
  //if (!ip) return 0;

  for (p = (struct contest_ip*) acc->b.first_down;
       p; p = (struct contest_ip*) p->b.right) {
    if (ipv6_match_mask(&p->addr, &p->mask, pip) && (p->ssl == -1 || p->ssl == ssl))
      return p->allow;
  }
  return acc->default_is_allow;
}

int
contests_check_ip(int num, int field, const ej_ip_t *pip, int ssl)
{
  const struct contest_desc *d = 0;
  struct contest_access *acc = 0;
  int e;

  if ((e = contests_get(num, &d)) < 0) {
    err("contests_check_ip: %d: %s", num, contests_strerror(-e));
    return 0;
  }
  switch (field) {
  case CONTEST_REGISTER_ACCESS: acc = d->register_access; break;
  case CONTEST_USERS_ACCESS:    acc = d->users_access; break;
  case CONTEST_MASTER_ACCESS:   acc = d->master_access; break;
  case CONTEST_JUDGE_ACCESS:    acc = d->judge_access; break;
  case CONTEST_TEAM_ACCESS:     acc = d->team_access; break;
  case CONTEST_SERVE_CONTROL_ACCESS: acc = d->serve_control_access; break;
  default:
    err("contests_check_ip: %d: invalid field %d", num, field);
    return 0;
  }
  return do_check_ip(acc, pip, ssl);
}

int
contests_check_register_ip(int num, const ej_ip_t *pip, int ssl)
{
  return contests_check_ip(num, CONTEST_REGISTER_ACCESS, pip, ssl);
}
int
contests_check_register_ip_2(const struct contest_desc *cnts, const ej_ip_t *pip, int ssl)
{
  return do_check_ip(cnts->register_access, pip, ssl);
}
int
contests_check_users_ip(int num, const ej_ip_t *pip, int ssl)
{
  return contests_check_ip(num, CONTEST_USERS_ACCESS, pip, ssl);
}
int
contests_check_users_ip_2(const struct contest_desc *cnts, const ej_ip_t *pip, int ssl)
{
  return do_check_ip(cnts->users_access, pip, ssl);
}
int
contests_check_master_ip(int num, const ej_ip_t *pip, int ssl)
{
  return contests_check_ip(num, CONTEST_MASTER_ACCESS, pip, ssl);
}
int
contests_check_master_ip_2(const struct contest_desc *cnts, const ej_ip_t *pip, int ssl)
{
  return do_check_ip(cnts->master_access, pip, ssl);
}
int
contests_check_judge_ip(int num, const ej_ip_t *pip, int ssl)
{
  return contests_check_ip(num, CONTEST_JUDGE_ACCESS, pip, ssl);
}
int
contests_check_judge_ip_2(const struct contest_desc *cnts, const ej_ip_t *pip, int ssl)
{
  return do_check_ip(cnts->judge_access, pip, ssl);
}
int
contests_check_team_ip(int num, const ej_ip_t *pip, int ssl)
{
  return contests_check_ip(num, CONTEST_TEAM_ACCESS, pip, ssl);
}
int
contests_check_team_ip_2(const struct contest_desc *cnts, const ej_ip_t *pip, int ssl)
{
  return do_check_ip(cnts->team_access, pip, ssl);
}
int
contests_check_serve_control_ip(int num, const ej_ip_t *pip, int ssl)
{
  return contests_check_ip(num, CONTEST_SERVE_CONTROL_ACCESS, pip, ssl);
}
int
contests_check_serve_control_ip_2(const struct contest_desc *cnts, const ej_ip_t *pip, int ssl)
{
  return do_check_ip(cnts->serve_control_access, pip, ssl);
}

struct callback_list_item
{
  struct callback_list_item *next;
  void (*func)(const struct contest_desc *);
};
static struct callback_list_item *load_list;
static struct callback_list_item *unload_list;

static struct callback_list_item *
contests_set_callback(struct callback_list_item *list,
                      void (*f)(const struct contest_desc *))
{
  struct callback_list_item *p = 0;

  if (!f) return list;
  for (p = list; p; p = p->next)
    if (p->func == f)
      return list;

  p = (struct callback_list_item *) xcalloc(1, sizeof(*p));
  p->next = list;
  p->func = f;
  return p;
}

void
contests_set_load_callback(void (*f)(const struct contest_desc *))
{
  load_list = contests_set_callback(load_list, f);
}
void
contests_set_unload_callback(void (*f)(const struct contest_desc *))
{
  unload_list = contests_set_callback(unload_list, f);
}

unsigned char *contests_dir;
static unsigned int contests_allocd;
static struct contest_desc **contests_desc;

struct contest_desc *
contests_free(struct contest_desc *cnts)
{
  if (!cnts) return 0;
  xml_tree_free((struct xml_tree *) cnts, &contests_parse_spec);
  return 0;
}

void
contests_free_2(struct xml_tree *t)
{
  if (t) xml_tree_free(t, &contests_parse_spec);
}

int
contests_make_path(unsigned char *buf, size_t sz, int num)
{
  return snprintf(buf, sz, "%s/%06d.xml", contests_dir, num);
}

int
contests_set_directory(unsigned char const *dir)
{
  struct stat bbb;

  if (!dir) return -CONTEST_ERR_BAD_DIR;
  if (stat(dir, &bbb) < 0) return -CONTEST_ERR_BAD_DIR;
  if (!S_ISDIR(bbb.st_mode)) return -CONTEST_ERR_BAD_DIR;
  xfree(contests_dir);
  contests_dir = xstrdup(dir);
  return 0;
}

struct get_list_state
{
  time_t last_check_time;
  time_t last_update_time;
  int max_num;
  int u;
  int a;
  int *ids;
  unsigned char *map;
  int map_a;
};
static struct get_list_state gl_state;

static int
int_sort_func(const void *p1, const void *p2)
{
  int i1 = *(const int*) p1;
  int i2 = *(const int*) p2;
  if (i1 < i2) return -1;
  if (i1 > i2) return 1;
  return 0;
}

int
contests_get_list(const int **p_list)
{
  DIR *d = 0;
  struct dirent *dd = 0;
  int i, j;
  struct stat bbb;
  unsigned char c_path[1024];
  time_t cur_time = time(0);

  if (p_list) *p_list = 0;
  if (cur_time <= gl_state.last_check_time) {
    if (p_list) *p_list = gl_state.ids;
    return gl_state.u;
  }
  gl_state.last_check_time = cur_time;
  if (stat(contests_dir, &bbb) < 0) return -CONTEST_ERR_BAD_DIR;
  if (!S_ISDIR(bbb.st_mode)) return -CONTEST_ERR_BAD_DIR;
  if (bbb.st_mtime <= gl_state.last_update_time) {
    if (p_list) *p_list = gl_state.ids;
    return gl_state.u;
  }
  gl_state.last_update_time = cur_time;

  // we don't check specifically for "." or ".."
  if (!(d = opendir(contests_dir))) return -CONTEST_ERR_BAD_DIR;
  gl_state.u = 0;
  gl_state.max_num = 0;
  while ((dd = readdir(d))) {
    if (sscanf(dd->d_name, "%d", &j) != 1 || j <= 0) continue;
    snprintf(c_path, sizeof(c_path), "%06d.xml", j);
    if (strcmp(c_path, dd->d_name)) continue;
    snprintf(c_path, sizeof(c_path), "%s/%06d.xml", contests_dir, j);
    if (access(c_path, R_OK) < 0) continue;
    //if (stat(c_path, &bbb) < 0) continue;
    //if (!S_ISREG(bbb.st_mode)) continue;

    if (gl_state.u == gl_state.a) {
      if (!gl_state.a) gl_state.a = 64;
      gl_state.a *= 2;
      XREALLOC(gl_state.ids, gl_state.a);
    }
    gl_state.ids[gl_state.u++] = j;
    if (j > gl_state.max_num) gl_state.max_num = j;
  }
  closedir(d);
  if (!gl_state.max_num) return 0;

  if (gl_state.max_num < 1000) {
    unsigned char *tmp_map = alloca(gl_state.max_num + 1);
    memset(tmp_map, 0, gl_state.max_num + 1);
    for (i = 0; i < gl_state.u; i++) {
      ASSERT(gl_state.ids[i] > 0 && gl_state.ids[i] <= gl_state.max_num);
      tmp_map[gl_state.ids[i]] = 1;
    }
    j = 0;
    for (i = 0; i <= gl_state.max_num; i++)
      if (tmp_map[i])
        gl_state.ids[j++] = i;
    ASSERT(j == gl_state.u);
  } else {
    qsort(gl_state.ids, gl_state.u, sizeof(gl_state.ids[0]), int_sort_func);
  }

  if (gl_state.max_num >= gl_state.map_a) {
    if (!gl_state.map_a) gl_state.map_a = 32;
    while (gl_state.max_num >= gl_state.map_a) gl_state.map_a *= 2;
    xfree(gl_state.map);
    XCALLOC(gl_state.map, gl_state.map_a);
  } else {
    memset(gl_state.map, 0, gl_state.map_a);
  }

  for (i = 0; i < gl_state.u; i++) {
    ASSERT(gl_state.ids[i] > 0 && gl_state.ids[i] <= gl_state.max_num);
    gl_state.map[gl_state.ids[i]] = 1;
  }
  if (p_list) *p_list = gl_state.ids;
  return gl_state.u;
}

int
contests_get_set(const unsigned char **p_map)
{
  DIR *d = 0;
  struct dirent *dd = 0;
  int i, j;
  struct stat bbb;
  unsigned char c_path[1024];
  time_t cur_time = time(0);

  if (p_map) *p_map = 0;
  if (cur_time <= gl_state.last_check_time) {
    if (p_map) *p_map = gl_state.map;
    return gl_state.max_num + 1;
  }
  gl_state.last_check_time = cur_time;
  if (stat(contests_dir, &bbb) < 0) return -CONTEST_ERR_BAD_DIR;
  if (!S_ISDIR(bbb.st_mode)) return -CONTEST_ERR_BAD_DIR;
  if (bbb.st_mtime <= gl_state.last_update_time) {
    if (p_map) *p_map = gl_state.map;
    return gl_state.max_num + 1;
  }
  gl_state.last_update_time = cur_time;

  // we don't check specifically for "." or ".."
  if (!(d = opendir(contests_dir))) return -CONTEST_ERR_BAD_DIR;
  gl_state.u = 0;
  gl_state.max_num = 0;
  while ((dd = readdir(d))) {
    if (sscanf(dd->d_name, "%d", &j) != 1 || j <= 0) continue;
    snprintf(c_path, sizeof(c_path), "%06d.xml", j);
    if (strcmp(c_path, dd->d_name)) continue;
    snprintf(c_path, sizeof(c_path), "%s/%06d.xml", contests_dir, j);
    if (access(c_path, R_OK) < 0) continue;
    //if (stat(c_path, &bbb) < 0) continue;
    //if (!S_ISREG(bbb.st_mode)) continue;

    if (gl_state.u == gl_state.a) {
      if (!gl_state.a) gl_state.a = 64;
      gl_state.a *= 2;
      XREALLOC(gl_state.ids, gl_state.a);
    }
    gl_state.ids[gl_state.u++] = j;
    if (j > gl_state.max_num) gl_state.max_num = j;
  }
  closedir(d);
  if (!gl_state.max_num) return 0;

  if (gl_state.max_num < 1000) {
    unsigned char *tmp_map = alloca(gl_state.max_num + 1);
    memset(tmp_map, 0, gl_state.max_num + 1);
    for (i = 0; i < gl_state.u; i++) {
      ASSERT(gl_state.ids[i] > 0 && gl_state.ids[i] <= gl_state.max_num);
      tmp_map[gl_state.ids[i]] = 1;
    }
    j = 0;
    for (i = 0; i <= gl_state.max_num; i++)
      if (tmp_map[i])
        gl_state.ids[j++] = i;
    ASSERT(j == gl_state.u);
  } else {
    qsort(gl_state.ids, gl_state.u, sizeof(gl_state.ids[0]), int_sort_func);
  }

  if (gl_state.max_num >= gl_state.map_a) {
    if (!gl_state.map_a) gl_state.map_a = 32;
    while (gl_state.max_num >= gl_state.map_a) gl_state.map_a *= 2;
    xfree(gl_state.map);
    XCALLOC(gl_state.map, gl_state.map_a);
  } else {
    memset(gl_state.map, 0, gl_state.map_a);
  }

  for (i = 0; i < gl_state.u; i++) {
    ASSERT(gl_state.ids[i] > 0 && gl_state.ids[i] <= gl_state.max_num);
    gl_state.map[gl_state.ids[i]] = 1;
  }
  if (p_map) *p_map = gl_state.map;
  return gl_state.max_num + 1;
}

void
contests_clear_cache(void)
{
  gl_state.last_check_time = 0;
  gl_state.last_update_time = 0;
}

int
contests_get(int number, const struct contest_desc **p_desc)
{
  unsigned char c_path[1024];
  struct stat sb;
  struct contest_desc *cnts;
  time_t cur_time;

  ASSERT(p_desc);
  *p_desc = 0;
  if (number <= 0) return -CONTEST_ERR_BAD_ID;

  if (number >= contests_allocd || !contests_desc[number]) {
    // no previous info about the contest
    contests_make_path(c_path, sizeof(c_path), number);
    if (stat(c_path, &sb) < 0) return -CONTEST_ERR_NO_CONTEST;
    // load the info and adjust time marks
    cnts = parse_one_contest_xml(c_path, 0, number);
    if (!cnts) return -CONTEST_ERR_BAD_XML;
    if (cnts->id != number) {
      contests_free(cnts);
      return -CONTEST_ERR_ID_NOT_MATCH;
    }
    cnts->last_check_time = time(0);
    cnts->last_file_time = sb.st_mtime;
    // extend arrays
    if (number >= contests_allocd) {
      unsigned int new_allocd = contests_allocd;
      struct contest_desc **new_contests = 0;

      if (!new_allocd) new_allocd = 32;
      while (number >= new_allocd) new_allocd *= 2;
      new_contests = xcalloc(new_allocd, sizeof(new_contests[0]));
      if (contests_allocd > 0) {
        memcpy(new_contests, contests_desc,
               contests_allocd * sizeof(new_contests[0]));
      }
      xfree(contests_desc);
      contests_allocd = new_allocd;
      contests_desc = new_contests;
    }
    // put new contest into the array
    contests_desc[number] = cnts;
    *p_desc = cnts;
    return 0;
  }

  cur_time = time(0);
  cnts = contests_desc[number];
  ASSERT(cnts->id == number);
  // check the time since last check
  if (cur_time <= cnts->last_check_time + CONTEST_CHECK_TIME) {
    *p_desc = cnts;
    return 0;
  }

  contests_make_path(c_path, sizeof(c_path), number);
  if (stat(c_path, &sb) < 0) {
    // FIXME: contest removed. what to do?
    contests_free(cnts);
    contests_desc[number] = 0;
    return -CONTEST_ERR_REMOVED;
  }
  // check whether update timestamp is changed
  if (sb.st_mtime == cnts->last_file_time) {
    *p_desc = cnts;
    return 0;
  }

  // load the info and adjust time marks
  cnts = parse_one_contest_xml(c_path, 0, number);
  if (!cnts) return -CONTEST_ERR_BAD_XML;
  if (cnts->id != number) {
    contests_free(cnts);
    return -CONTEST_ERR_ID_NOT_MATCH;
  }
  cnts->last_check_time = time(0);
  cnts->last_file_time = sb.st_mtime;
  /* FIXME: there may be pointers to the current cnts structure
   * outta there, so we should not just free the old contest
   * description
   */
  contests_merge(contests_desc[number], cnts);
  contests_free(cnts);
  *p_desc = contests_desc[number];
  return 0;
}

static unsigned char const * const contests_errors[] =
{
  "no error",
  "invalid contests directory",
  "invalid contest id",
  "contest does not exist",
  "error during XML reading",
  "contest id in the file and file name do not match",
  "contest is removed",
  "cannot create a file in contest directory",
  "i/o error",

  [CONTEST_ERR_LAST] = "unknown error"
};

const unsigned char *
contests_strerror(int e)
{
  if (e < 0) e = -e;
  if (e > CONTEST_ERR_LAST) e = CONTEST_ERR_LAST;
  return (const unsigned char *) contests_errors[e];
}

void
contests_get_path_in_conf_dir(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const unsigned char *file)
{
  path_t home_dir;
  path_t root_dir;
  path_t conf_dir;

  if (os_IsAbsolutePath(file)) {
    snprintf(buf, size, "%s", file);
    return;
  }

  if (cnts && cnts->conf_dir && os_IsAbsolutePath(cnts->conf_dir)) {
    snprintf(buf, size, "%s/%s", cnts->conf_dir, file);
    return;
  }

  if (cnts && cnts->root_dir && os_IsAbsolutePath(cnts->root_dir)) {
    snprintf(root_dir, sizeof(root_dir), "%s", cnts->root_dir);
  } else {
    home_dir[0] = 0;
#if defined CONTESTS_HOME_DIR
    snprintf(home_dir, sizeof(home_dir), "%s", CONTESTS_HOME_DIR);
#endif
    if (!home_dir[0]) {
      snprintf(home_dir, sizeof(home_dir), "%s", "/home/judges");
    }
    if (cnts->root_dir) {
      snprintf(root_dir, sizeof(root_dir), "%s/%s", home_dir, cnts->root_dir);
    } else {
      snprintf(root_dir, sizeof(root_dir), "%s/%06d", home_dir, cnts->id);
    }
  }

  if (cnts && cnts->conf_dir) {
    snprintf(conf_dir, sizeof(conf_dir), "%s/%s", root_dir, cnts->conf_dir);
  } else {
    snprintf(conf_dir, sizeof(conf_dir), "%s/conf", root_dir);
  }
  snprintf(buf, size, "%s/%s", conf_dir, file);
}

static const unsigned char *const form_field_names[] =
{
  [CONTEST_F_HOMEPAGE] = "Home page",
  [CONTEST_F_PHONE] = "Phone",
  [CONTEST_F_INST] = "Institution",
  [CONTEST_F_INST_EN] = "Institution (English)",
  [CONTEST_F_INSTSHORT] = "Institution, short",
  [CONTEST_F_INSTSHORT_EN] = "Institution, short (English)",
  [CONTEST_F_INSTNUM] = "Institution number",
  [CONTEST_F_FAC] = "Faculty",
  [CONTEST_F_FAC_EN] = "Faculty (English)",
  [CONTEST_F_FACSHORT] = "Faculty, short",
  [CONTEST_F_FACSHORT_EN] = "Faculty, short (English)",
  [CONTEST_F_CITY] = "City",
  [CONTEST_F_CITY_EN] = "City (English)",
  [CONTEST_F_COUNTRY] = "Country",
  [CONTEST_F_COUNTRY_EN] = "Country (English)",
  [CONTEST_F_REGION] = "Region",
  [CONTEST_F_AREA] = "Area",
  [CONTEST_F_ZIP] = "Zip code",
  [CONTEST_F_STREET] = "Street address",
  [CONTEST_F_LANGUAGES] = "Programming Languages",
  [CONTEST_F_FIELD0] = "Field 0",
  [CONTEST_F_FIELD1] = "Field 1",
  [CONTEST_F_FIELD2] = "Field 2",
  [CONTEST_F_FIELD3] = "Field 3",
  [CONTEST_F_FIELD4] = "Field 4",
  [CONTEST_F_FIELD5] = "Field 5",
  [CONTEST_F_FIELD6] = "Field 6",
  [CONTEST_F_FIELD7] = "Field 7",
  [CONTEST_F_FIELD8] = "Field 8",
  [CONTEST_F_FIELD9] = "Field 9",
};
const unsigned char *
contests_get_form_field_name(int ff)
{
  ASSERT(ff > 0 && ff < CONTEST_LAST_FIELD);
  return form_field_names[ff];
}

static const unsigned char *const member_field_names[] =
{
  [CONTEST_MF_FIRSTNAME] = "First Name",
  [CONTEST_MF_FIRSTNAME_EN] = "First Name (English)",
  [CONTEST_MF_MIDDLENAME] = "Middle Name",
  [CONTEST_MF_MIDDLENAME_EN] = "Middle Name (English)",
  [CONTEST_MF_SURNAME] = "Surname",
  [CONTEST_MF_SURNAME_EN] = "Surname (English)",
  [CONTEST_MF_STATUS] = "Status",
  [CONTEST_MF_GENDER] = "Gender",
  [CONTEST_MF_GRADE] = "Grade",
  [CONTEST_MF_GROUP] = "Group",
  [CONTEST_MF_GROUP_EN] = "Group (English)",
  [CONTEST_MF_EMAIL] = "E-mail",
  [CONTEST_MF_HOMEPAGE] = "Homepage",
  [CONTEST_MF_PHONE] = "Phone",
  [CONTEST_MF_INST] = "Institution",
  [CONTEST_MF_INST_EN] = "Institution (English)",
  [CONTEST_MF_INSTSHORT] = "Institution, short",
  [CONTEST_MF_INSTSHORT_EN] = "Institution, short (English)",
  [CONTEST_MF_FAC] = "Faculty",
  [CONTEST_MF_FAC_EN] = "Faculty (English)",
  [CONTEST_MF_FACSHORT] = "Faculty, short",
  [CONTEST_MF_FACSHORT_EN] = "Faculty, short (English)",
  [CONTEST_MF_OCCUPATION] = "Occupation",
  [CONTEST_MF_OCCUPATION_EN] = "Occupation (English)",
  [CONTEST_MF_DISCIPLINE] = "Discipline",
  [CONTEST_MF_BIRTH_DATE] = "Birth date",
  [CONTEST_MF_ENTRY_DATE] = "Entry date",
  [CONTEST_MF_GRADUATION_DATE] = "Graduation date",
};
const unsigned char *
contests_get_member_field_name(int ff)
{
  ASSERT(ff > 0 && ff < CONTEST_LAST_MEMBER_FIELD);
  return member_field_names[ff];
}

static const unsigned char *const member_names[] =
{
  [CONTEST_M_CONTESTANT] = "Contestant",
  [CONTEST_M_RESERVE] = "Reserve",
  [CONTEST_M_COACH] = "Coach",
  [CONTEST_M_ADVISOR] = "Advisor",
  [CONTEST_M_GUEST] = "Guest",
};
const unsigned char *
contests_get_member_name(int ff)
{
  ASSERT(ff >= 0 && ff < CONTEST_LAST_MEMBER);
  return member_names[ff];
}

// 0 - always closed, 1 - so-so, 2 - always open
int
contests_get_access_type(const struct contest_desc *cnts, int field)
{
  struct contest_access *acc = 0;
  switch (field) {
  case CONTEST_REGISTER_ACCESS:      acc = cnts->register_access; break;
  case CONTEST_USERS_ACCESS:         acc = cnts->users_access; break;
  case CONTEST_MASTER_ACCESS:        acc = cnts->master_access; break;
  case CONTEST_JUDGE_ACCESS:         acc = cnts->judge_access; break;
  case CONTEST_TEAM_ACCESS:          acc = cnts->team_access; break;
  case CONTEST_SERVE_CONTROL_ACCESS: acc = cnts->serve_control_access; break;
  default:
    abort();
  }

  // default is always closed
  if (!acc) return 0;

  int allow_count = 0;
  int deny_count = 0;

  for (const struct contest_ip *p = (const struct contest_ip*) acc->b.first_down;
       p; p = (const struct contest_ip*) p->b.right) {
    if (p->allow) ++allow_count;
    else ++deny_count;
  }

  if (acc->default_is_allow) ++allow_count;
  else ++deny_count;

  if (allow_count > 0 && deny_count > 0) return 1; // so-so
  if (allow_count > 0) return 2; // always allowed
  return 0;
}

int
contests_get_register_access_type(const struct contest_desc *cnts)
{
  return contests_get_access_type(cnts, CONTEST_REGISTER_ACCESS);
}

int
contests_get_users_access_type(const struct contest_desc *cnts)
{
  return contests_get_access_type(cnts, CONTEST_USERS_ACCESS);
}

int
contests_get_participant_access_type(const struct contest_desc *cnts)
{
  return contests_get_access_type(cnts, CONTEST_TEAM_ACCESS);
}

int
contests_apply_oauth_rules(
        const struct contest_desc *cnts,
        const unsigned char *email,
        unsigned char **p_login,
        int *p_disable_email_check)
{
  const unsigned char *domain_part = strchr(email, '@');
  if (!domain_part) return 0;
  ++domain_part;
  if (!*domain_part) return 0;
  int name_len = domain_part - email - 1;

  if (!cnts->oauth_rules) {
    if (p_login) *p_login = xstrdup(email);
    if (p_disable_email_check) *p_disable_email_check = -1;
    return 1;
  }
  for (const struct xml_tree *p = cnts->oauth_rules->first_down; p; p = p->right) {
    if (p->tag == CONTEST_OAUTH_RULE) {
      const unsigned char *domain = NULL;
      int allow = -1, deny = -1, strip_domain = -1, disable_email_check = -1;
      for (struct xml_attr *a = p->first; a; a = a->next) {
        switch (a->tag) {
        case CONTEST_A_DOMAIN:
          domain = a->text;
          break;
        case CONTEST_A_ALLOW:
          xml_parse_bool(NULL, NULL, 0, 0, a->text, &allow);
          break;
        case CONTEST_A_DENY:
          xml_parse_bool(NULL, NULL, 0, 0, a->text, &deny);
          break;
        case CONTEST_A_STRIP_DOMAIN:
          xml_parse_bool(NULL, NULL, 0, 0, a->text, &strip_domain);
          break;
        case CONTEST_A_DISABLE_EMAIL_CHECK:
          xml_parse_bool(NULL, NULL, 0, 0, a->text, &disable_email_check);
          break;
        }
      }
      if (!domain || !*domain) {
        // catch-all rule
        if (allow > 0 || deny == 0 || (allow < 0 && deny < 0)) {
          if (strip_domain <= 0) {
            if (p_login) *p_login = xstrdup(email);
            if (p_disable_email_check) *p_disable_email_check = disable_email_check;
          } else {
            if (p_login) *p_login = xmemdup(email, name_len);
            if (p_disable_email_check) *p_disable_email_check = disable_email_check;
          }
          return 1;
        }
        return 0;
      }
      if (!strcasecmp(domain, domain_part)) {
        if (allow > 0 || deny == 0 || (allow < 0 && deny < 0)) {
          if (strip_domain <= 0) {
            if (p_login) *p_login = xstrdup(email);
            if (p_disable_email_check) *p_disable_email_check = disable_email_check;
          } else {
            if (p_login) *p_login = xmemdup(email, name_len);
            if (p_disable_email_check) *p_disable_email_check = disable_email_check;
          }
          return 1;
        }
        return 0;
      }
    }
  }

  if (p_login) *p_login = xstrdup(email);
  if (p_disable_email_check) *p_disable_email_check = -1;
  return 1;
}
