/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "contests.h"
#include "pathutl.h"
#include "errlog.h"
#include "userlist.h"
#include "xml_utils.h"
#include "misctext.h"
#include "fileutl.h"
#include "xml_utils.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

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

#define MAX_CONTEST_ID 1000
#define CONTEST_CHECK_TIME 5

static char const * const elem_map[] =
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
  "team_footer_file",
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

  0
};
static char const * const attr_map[] =
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
  switch (t->tag) {
  case CONTEST_CONTESTS:
    xfree(((struct contest_list *) t)->id_map);
    break;
  case CONTEST_CONTEST:
    {
      struct contest_desc *cnts = (struct contest_desc*) t;
      xfree(cnts->name);
      xfree(cnts->name_en);
      xfree(cnts->main_url);
      xfree(cnts->users_header_file);
      xfree(cnts->users_footer_file);
      xfree(cnts->register_header_file);
      xfree(cnts->register_footer_file);
      xfree(cnts->team_header_file);
      xfree(cnts->team_footer_file);
      xfree(cnts->register_email);
      xfree(cnts->register_url);
      xfree(cnts->login_template);
      xfree(cnts->login_template_options);
      xfree(cnts->team_url);
      xfree(cnts->root_dir);
      xfree(cnts->conf_dir);
      xfree(cnts->standings_url);
      xfree(cnts->problems_url);
      xfree(cnts->serve_user);
      xfree(cnts->serve_group);
      xfree(cnts->run_user);
      xfree(cnts->run_group);
      xfree(cnts->register_email_file);
      xfree(cnts->users_head_style);
      xfree(cnts->users_par_style);
      xfree(cnts->users_table_style);
      xfree(cnts->users_verb_style);
      xfree(cnts->users_table_format);
      xfree(cnts->users_table_format_en);
      xfree(cnts->users_table_legend);
      xfree(cnts->users_table_legend_en);
      xfree(cnts->register_head_style);
      xfree(cnts->register_par_style);
      xfree(cnts->register_table_style);
      xfree(cnts->team_head_style);
      xfree(cnts->team_par_style);
      xfree(cnts->user_name_comment);
      xfree(cnts->allowed_languages);
      xfree(cnts->allowed_regions);
      xfree(cnts->cf_notify_email);
      xfree(cnts->clar_notify_email);
      xfree(cnts->daily_stat_email);
      xfree(cnts->priv_header_file);
      xfree(cnts->priv_footer_file);
    }
    break;
  case CONTEST_CAP:
    {
      struct opcap_list_item *pp = (struct opcap_list_item*) t;
      xfree(pp->login);
    }
    break;
  }
}

static struct xml_parse_spec contests_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = elem_sizes,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = node_free,
  .attr_free = NULL,
};

static char const * const field_map[] =
{
  0,
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
  "city",
  "city_en",
  "country",
  "country_en",
  "region",
  "languages",

  0
};

static char const * const member_field_map[] =
{
  0,
  "firstname",
  "firstname_en",
  "middlename",
  "middlename_en",
  "surname",
  "surname_en",
  "status",
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

    if (xml_parse_ip_mask(path, ip->b.line, ip->b.column,
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
    if (t->text && *t->text) return xml_err_elem_empty(t);
    if (t->first_down) return xml_err_nested_elems(t);
    pf = (struct contest_field*) t;

    pf->mandatory = -1;
    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case CONTEST_A_ID:
        for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
          if (!member_field_map[i]) continue;
          if (!strcmp(a->text, member_field_map[i])) break;
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
        path, t->line, t->column, elem_map[t->tag]);
    return -1;
  }
  if (!t->text || !*t->text) {
    err("%s:%d:%d: empty element <%s>", path, t->line, t->column,
        elem_map[t->tag]);
    return -1;
  }
  if (t->first_down) {
    err("%s:%d:%d: element <%s> cannot contain nested elements",
        path, t->line, t->column, elem_map[t->tag]);
    return -1;
  }
  if (t->first) {
    err("%s:%d:%d: element <%s> cannot have attributes",
        path, t->line, t->column, elem_map[t->tag]);
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
    for (qq = cnts->capabilities.first; qq != pp;
         qq = (struct opcap_list_item*) qq->b.right) {
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
      cnts->client_ignore_time_skew = 1;
    } else if (!strcmp(str3, "DISABLE_TEAM")) {
      cnts->client_disable_team = 1;
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

#define CONTEST_DESC_OFFSET(f) XOFFSET(struct contest_desc, f)

static const size_t contest_final_offsets[CONTEST_LAST_TAG] =
{
  [CONTEST_NAME] = CONTEST_DESC_OFFSET(name),
  [CONTEST_NAME_EN] = CONTEST_DESC_OFFSET(name_en),
  [CONTEST_MAIN_URL] = CONTEST_DESC_OFFSET(main_url),
  [CONTEST_USERS_HEADER_FILE] = CONTEST_DESC_OFFSET(users_header_file),
  [CONTEST_USERS_FOOTER_FILE] = CONTEST_DESC_OFFSET(users_footer_file),
  [CONTEST_REGISTER_EMAIL] = CONTEST_DESC_OFFSET(register_email),
  [CONTEST_REGISTER_URL] = CONTEST_DESC_OFFSET(register_url),
  [CONTEST_LOGIN_TEMPLATE] = CONTEST_DESC_OFFSET(login_template),
  [CONTEST_LOGIN_TEMPLATE_OPTIONS]=CONTEST_DESC_OFFSET(login_template_options),
  [CONTEST_TEAM_URL] = CONTEST_DESC_OFFSET(team_url),
  [CONTEST_ROOT_DIR] = CONTEST_DESC_OFFSET(root_dir),
  [CONTEST_STANDINGS_URL] = CONTEST_DESC_OFFSET(standings_url),
  [CONTEST_PROBLEMS_URL] = CONTEST_DESC_OFFSET(problems_url),
  [CONTEST_SERVE_USER] = CONTEST_DESC_OFFSET(serve_user),
  [CONTEST_SERVE_GROUP] = CONTEST_DESC_OFFSET(serve_group),
  [CONTEST_REGISTER_HEADER_FILE] = CONTEST_DESC_OFFSET(register_header_file),
  [CONTEST_REGISTER_FOOTER_FILE] = CONTEST_DESC_OFFSET(register_footer_file),
  [CONTEST_TEAM_HEADER_FILE] = CONTEST_DESC_OFFSET(team_header_file),
  [CONTEST_TEAM_FOOTER_FILE] = CONTEST_DESC_OFFSET(team_footer_file),
  [CONTEST_USERS_HEAD_STYLE] = CONTEST_DESC_OFFSET(users_head_style),
  [CONTEST_USERS_PAR_STYLE] = CONTEST_DESC_OFFSET(users_par_style),
  [CONTEST_USERS_TABLE_STYLE] = CONTEST_DESC_OFFSET(users_table_style),
  [CONTEST_USERS_VERB_STYLE] = CONTEST_DESC_OFFSET(users_verb_style),
  [CONTEST_USERS_TABLE_FORMAT] = CONTEST_DESC_OFFSET(users_table_format),
  [CONTEST_USERS_TABLE_FORMAT_EN] = CONTEST_DESC_OFFSET(users_table_format_en),
  [CONTEST_USERS_TABLE_LEGEND] = CONTEST_DESC_OFFSET(users_table_legend),
  [CONTEST_USERS_TABLE_LEGEND_EN] = CONTEST_DESC_OFFSET(users_table_legend_en),
  [CONTEST_REGISTER_HEAD_STYLE] = CONTEST_DESC_OFFSET(register_head_style),
  [CONTEST_REGISTER_PAR_STYLE] = CONTEST_DESC_OFFSET(register_par_style),
  [CONTEST_REGISTER_TABLE_STYLE] = CONTEST_DESC_OFFSET(register_table_style),
  [CONTEST_TEAM_HEAD_STYLE] = CONTEST_DESC_OFFSET(team_head_style),
  [CONTEST_TEAM_PAR_STYLE] = CONTEST_DESC_OFFSET(team_par_style),
  [CONTEST_CONF_DIR] = CONTEST_DESC_OFFSET(conf_dir),
  [CONTEST_RUN_USER] = CONTEST_DESC_OFFSET(run_user),
  [CONTEST_RUN_GROUP] = CONTEST_DESC_OFFSET(run_group),
  [CONTEST_REGISTER_EMAIL_FILE] = CONTEST_DESC_OFFSET(register_email_file),
  [CONTEST_USER_NAME_COMMENT] = CONTEST_DESC_OFFSET(user_name_comment),
  [CONTEST_ALLOWED_LANGUAGES] = CONTEST_DESC_OFFSET(allowed_languages),
  [CONTEST_ALLOWED_REGIONS] = CONTEST_DESC_OFFSET(allowed_regions),
  [CONTEST_CF_NOTIFY_EMAIL] = CONTEST_DESC_OFFSET(cf_notify_email),
  [CONTEST_CLAR_NOTIFY_EMAIL] = CONTEST_DESC_OFFSET(clar_notify_email),
  [CONTEST_DAILY_STAT_EMAIL] = CONTEST_DESC_OFFSET(daily_stat_email),
  [CONTEST_PRIV_HEADER_FILE] = CONTEST_DESC_OFFSET(priv_header_file),
  [CONTEST_PRIV_FOOTER_FILE] = CONTEST_DESC_OFFSET(priv_footer_file),
};

static const size_t contest_access_offsets[CONTEST_LAST_TAG] =
{
  [CONTEST_REGISTER_ACCESS] = CONTEST_DESC_OFFSET(register_access),
  [CONTEST_USERS_ACCESS] = CONTEST_DESC_OFFSET(users_access),
  [CONTEST_MASTER_ACCESS] = CONTEST_DESC_OFFSET(master_access),
  [CONTEST_JUDGE_ACCESS] = CONTEST_DESC_OFFSET(judge_access),
  [CONTEST_TEAM_ACCESS] = CONTEST_DESC_OFFSET(team_access),
  [CONTEST_SERVE_CONTROL_ACCESS] = CONTEST_DESC_OFFSET(serve_control_access),
};

static const size_t contest_bool_attr_offsets[CONTEST_LAST_TAG] =
{
  [CONTEST_A_AUTOREGISTER] = CONTEST_DESC_OFFSET(autoregister),
  [CONTEST_A_DISABLE_TEAM_PASSWORD] =CONTEST_DESC_OFFSET(disable_team_password),
  [CONTEST_A_MANAGED] = CONTEST_DESC_OFFSET(managed),
  [CONTEST_A_NEW_MANAGED] = CONTEST_DESC_OFFSET(new_managed),
  [CONTEST_A_CLEAN_USERS] = CONTEST_DESC_OFFSET(clean_users),
  [CONTEST_A_RUN_MANAGED] = CONTEST_DESC_OFFSET(run_managed),
  [CONTEST_A_CLOSED] = CONTEST_DESC_OFFSET(closed),
  [CONTEST_A_INVISIBLE] = CONTEST_DESC_OFFSET(invisible),
  [CONTEST_A_SIMPLE_REGISTRATION] = CONTEST_DESC_OFFSET(simple_registration),
  [CONTEST_A_SEND_PASSWD_EMAIL] = CONTEST_DESC_OFFSET(send_passwd_email),
  [CONTEST_A_ASSIGN_LOGINS] = CONTEST_DESC_OFFSET(assign_logins),
  [CONTEST_A_FORCE_REGISTRATION] = CONTEST_DESC_OFFSET(force_registration),
  [CONTEST_A_DISABLE_NAME] = CONTEST_DESC_OFFSET(disable_name),
};

static int
parse_contest(struct contest_desc *cnts, char const *path, int no_subst_flag)
{
  struct xml_attr *a;
  struct xml_tree *t;
  int x, n, mb_id;
  unsigned char *reg_deadline_str = 0;
  struct contest_access **pacc;
  unsigned char pathbuf[PATH_MAX];
  unsigned char *p_field;
  unsigned char **p_str;

  cnts->clean_users = 1;

  for (a = cnts->b.first; a; a = a->next) {
    if (contest_bool_attr_offsets[a->tag] > 0) {
      // boolean fields
      p_field = XPDEREF(unsigned char, cnts, contest_bool_attr_offsets[a->tag]);
      if (xml_attr_bool_byte(a, p_field) < 0) return -1;
      continue;
    }

    switch (a->tag) {
    case CONTEST_A_ID:
      x = n = 0;
      if (sscanf(a->text, "%d %n", &x, &n) != 1 || a->text[n]
          || x <= 0 || x > MAX_CONTEST_ID) return xml_err_attr_invalid(a);
      cnts->id = x;
      break;
    default:
      return xml_err_attr_not_allowed(&cnts->b, a);
    }
  }

  if (!cnts->id) return xml_err_attr_undefined(&cnts->b, CONTEST_A_ID);

  for (t = cnts->b.first_down; t; t = t->right) {
    if (contest_final_offsets[t->tag] > 0) {
      p_str = XPDEREF(unsigned char *, cnts, contest_final_offsets[t->tag]);
      if (xml_leaf_elem(t, p_str, 1, 0) < 0) return -1;
      continue;
    }
    if (contest_access_offsets[t->tag] > 0) {
      pacc=XPDEREF(struct contest_access*,cnts,contest_access_offsets[t->tag]);
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
      if (handle_final_tag(path, t, &reg_deadline_str) < 0) {
        xfree(reg_deadline_str);
        return -1;
      }
      t->text = reg_deadline_str;
      if (xml_parse_date(path, t->line, t->column,
                         reg_deadline_str, &cnts->reg_deadline) < 0)
        return -1;
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
      if (xml_empty_text(t) < 0) return -1;
      xfree(t->text);
      t->text = 0;
      {
        struct contest_field *pf = (struct contest_field*) t;
        int i;

        pf->mandatory = -1;
        for (a = t->first; a; a = a->next) {
          switch (a->tag) {
          case CONTEST_A_ID:
            for (i = 1; i < CONTEST_LAST_FIELD; i++) {
              if (!field_map[i]) continue;
              if (!strcmp(a->text, field_map[i])) break;
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

  if (cnts->root_dir && !os_IsAbsolutePath(cnts->root_dir)) {
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

    process_conf_file_path(cnts, &cnts->register_header_file);
    process_conf_file_path(cnts, &cnts->register_footer_file);
    process_conf_file_path(cnts, &cnts->users_header_file);
    process_conf_file_path(cnts, &cnts->users_footer_file);
    process_conf_file_path(cnts, &cnts->team_header_file);
    process_conf_file_path(cnts, &cnts->team_footer_file);
    process_conf_file_path(cnts, &cnts->register_email_file);
    process_conf_file_path(cnts, &cnts->priv_header_file);
    process_conf_file_path(cnts, &cnts->priv_footer_file);

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

  return 0;
}

static struct contest_desc *
parse_one_contest_xml(char const *path, int number, int no_subst_flag)
{
  struct xml_tree *tree = 0;
  struct contest_desc *d = 0;

  xml_err_path = path;
  xml_err_spec = &contests_parse_spec;

  tree = xml_build_tree(path, &contests_parse_spec);
  if (!tree) goto failed;
  if (tree->tag != CONTEST_CONTEST) {
    xml_err_top_level(tree, CONTEST_CONTEST);
    goto failed;
  }
  d = (struct contest_desc *) tree;
  if (parse_contest(d, path, no_subst_flag) < 0) goto failed;
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
    if (contest_final_offsets[i]) {
      p_str_old = XPDEREF(unsigned char *, pold, contest_final_offsets[i]);
      p_str_new = XPDEREF(unsigned char *, pnew, contest_final_offsets[i]);
      xfree(*p_str_old);
      *p_str_old = *p_str_new;
      *p_str_new = 0;
    } else if (contest_access_offsets[i]) {
      p_acc_old = XPDEREF(struct contest_access*, pold, 
                          contest_access_offsets[i]);
      p_acc_new = XPDEREF(struct contest_access*, pnew, 
                          contest_access_offsets[i]);
      p = &(*p_acc_new)->b;
      if (p) {
        xml_unlink_node(p);
        xml_link_node_last(&pold->b, p);
      }
      *p_acc_old = (struct contest_access*) p;
      *p_acc_new = 0;
    } else if (contest_bool_attr_offsets[i]) {
      p_b_old = XPDEREF(unsigned char, pold, contest_bool_attr_offsets[i]);
      p_b_new = XPDEREF(unsigned char, pnew, contest_bool_attr_offsets[i]);
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

  pold->reg_deadline = pnew->reg_deadline;
  pold->client_ignore_time_skew = pnew->client_ignore_time_skew;
  pold->client_disable_team = pnew->client_disable_team;
  pold->disable_member_delete = pnew->disable_member_delete;
  pold->last_check_time = pnew->last_check_time;
  pold->last_file_time = pnew->last_file_time;
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
  cnts = parse_one_contest_xml(c_path, number, 1);
  if (!cnts) return -CONTEST_ERR_BAD_XML;
  if (cnts->id != number) {
    contests_free(cnts);
    return -CONTEST_ERR_ID_NOT_MATCH;
  }
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
do_check_ip(struct contest_access *acc, ej_ip_t ip, int ssl)
{
  struct contest_ip *p;

  if (!acc) return 0;
  if (!ip && acc->default_is_allow) return 1;
  if (!ip) return 0;

  for (p = (struct contest_ip*) acc->b.first_down;
       p; p = (struct contest_ip*) p->b.right) {
    if ((ip & p->mask) == p->addr && (p->ssl == -1 || p->ssl == ssl))
      return p->allow;
  }
  return acc->default_is_allow;
}

int
contests_check_ip(int num, int field, ej_ip_t ip, int ssl)
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
  return do_check_ip(acc, ip, ssl);
}

int
contests_check_register_ip(int num, ej_ip_t ip, int ssl)
{
  return contests_check_ip(num, CONTEST_REGISTER_ACCESS, ip, ssl);
}
int
contests_check_register_ip_2(const struct contest_desc *cnts, ej_ip_t ip, int ssl)
{
  return do_check_ip(cnts->register_access, ip, ssl);
}
int
contests_check_users_ip(int num, ej_ip_t ip, int ssl)
{
  return contests_check_ip(num, CONTEST_USERS_ACCESS, ip, ssl);
}
int
contests_check_users_ip_2(const struct contest_desc *cnts, ej_ip_t ip, int ssl)
{
  return do_check_ip(cnts->users_access, ip, ssl);
}
int
contests_check_master_ip(int num, ej_ip_t ip, int ssl)
{
  return contests_check_ip(num, CONTEST_MASTER_ACCESS, ip, ssl);
}
int
contests_check_master_ip_2(const struct contest_desc *cnts, ej_ip_t ip, int ssl)
{
  return do_check_ip(cnts->master_access, ip, ssl);
}
int
contests_check_judge_ip(int num, ej_ip_t ip, int ssl)
{
  return contests_check_ip(num, CONTEST_JUDGE_ACCESS, ip, ssl);
}
int
contests_check_judge_ip_2(const struct contest_desc *cnts, ej_ip_t ip, int ssl)
{
  return do_check_ip(cnts->judge_access, ip, ssl);
}
int
contests_check_team_ip(int num, ej_ip_t ip, int ssl)
{
  return contests_check_ip(num, CONTEST_TEAM_ACCESS, ip, ssl);
}
int
contests_check_team_ip_2(const struct contest_desc *cnts, ej_ip_t ip, int ssl)
{
  return do_check_ip(cnts->team_access, ip, ssl);
}
int
contests_check_serve_control_ip(int num, ej_ip_t ip, int ssl)
{
  return contests_check_ip(num, CONTEST_SERVE_CONTROL_ACCESS, ip, ssl);
}
int
contests_check_serve_control_ip_2(const struct contest_desc *cnts, ej_ip_t ip, int ssl)
{
  return do_check_ip(cnts->serve_control_access, ip, ssl);
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

static unsigned char *contests_dir;
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

int
contests_get_list(unsigned char **p_map)
{
  DIR *d = 0;
  struct dirent *dd = 0;
  int entries_num = -1, i, j;
  unsigned char *flags = 0;
  struct stat bbb;
  unsigned char c_path[1024];

  // we don't check specifically for "." or ".."
  if (!(d = opendir(contests_dir))) return -CONTEST_ERR_BAD_DIR;
  while ((dd = readdir(d))) {
    if (sscanf(dd->d_name, "%d", &j) == 1) {
      snprintf(c_path, sizeof(c_path), "%06d.xml", j);
      if (!strcmp(c_path, dd->d_name) && j > entries_num) entries_num = j;
    }
  }
  closedir(d);
  if (entries_num < 0) {
    *p_map = 0;
    return 0;
  }

  flags = (unsigned char *) alloca(entries_num + 1);
  memset(flags, 0, entries_num + 1);

  for (i = 1; i <= entries_num; i++) {
    contests_make_path(c_path, sizeof(c_path), i);
    if (stat(c_path, &bbb) < 0) continue;
    if (access(c_path, R_OK) < 0) continue;
    if (!S_ISREG(bbb.st_mode)) continue;
    // FIXME: check the owner of the file?
    flags[i] = 1;
  }

  while (entries_num >= 0 && !flags[entries_num]) entries_num--;
  if (!p_map) return entries_num + 1;
  *p_map = 0;
  if (entries_num < 0) return 0;
  *p_map = (unsigned char *) xmalloc(entries_num + 1);
  memcpy(*p_map, flags, entries_num + 1);
  return entries_num + 1;
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
    cnts = parse_one_contest_xml(c_path, number, 0);
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
  cnts = parse_one_contest_xml(c_path, number, 0);
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

  [CONTEST_ERR_LAST] "unknown error"
};

const unsigned char *
contests_strerror(int e)
{
  if (e < 0) e = -e;
  if (e > CONTEST_ERR_LAST) e = CONTEST_ERR_LAST;
  return (const unsigned char *) contests_errors[e];
}

void
contests_write_header(FILE *f, const struct contest_desc *cnts)
{
  fprintf(f,
          "<%s %s=\"%d\"", elem_map[CONTEST_CONTEST],
          attr_map[CONTEST_A_ID], cnts->id);
  if (cnts->autoregister) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_AUTOREGISTER], "yes");
  }
  if (cnts->disable_team_password) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_DISABLE_TEAM_PASSWORD], "yes");
  }
  if (!cnts->clean_users) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_CLEAN_USERS], "no");
  }
  if (cnts->simple_registration) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_SIMPLE_REGISTRATION], "yes");
  }
  if (cnts->send_passwd_email) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_SEND_PASSWD_EMAIL], "yes");
  }
  if (cnts->assign_logins) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_ASSIGN_LOGINS], "yes");
  }
  if (cnts->force_registration) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_FORCE_REGISTRATION], "yes");
  }
  if (cnts->disable_name) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_DISABLE_NAME], "yes");
  }

  if (cnts->closed) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_CLOSED], "yes");
  }
  if (cnts->invisible) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_INVISIBLE], "yes");
  }
  if (cnts->managed) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_MANAGED], "yes");
  }
  if (cnts->new_managed) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_NEW_MANAGED], "yes");
  }
  if (cnts->run_managed) {
    fprintf(f, "\n         %s=\"%s\"",
            attr_map[CONTEST_A_RUN_MANAGED], "yes");
  }
  fprintf(f, ">");
}

static void
unparse_access(FILE *f, const struct contest_access *acc, int tag)
{
  struct contest_ip *ip;
  unsigned char ssl_str[64];

  if (!acc) return;
  if (!acc->default_is_allow && !acc->b.first_down) return;
  if (!acc->b.first_down) {
    fprintf(f, "  <%s default=\"%s\"/>\n", elem_map[tag],
            acc->default_is_allow?"allow":"deny");
    return;
  }
  fprintf(f, "  <%s default=\"%s\">\n", elem_map[tag],
          acc->default_is_allow?"allow":"deny");
  for (ip = (typeof(ip)) acc->b.first_down; ip;
       ip = (typeof(ip)) ip->b.right) {
    ssl_str[0] = 0;
    if (ip->ssl >= 0)
      snprintf(ssl_str, sizeof(ssl_str), " %s=\"%s\"",
               attr_map[CONTEST_A_SSL], ip->ssl?"yes":"no");
    fprintf(f, "    <%s %s=\"%s\"%s>%s</%s>\n",
            elem_map[CONTEST_IP], attr_map[CONTEST_A_ALLOW],
            ip->allow?"yes":"no", ssl_str,
            xml_unparse_ip_mask(ip->addr, ip->mask),
            elem_map[CONTEST_IP]);
  }
  fprintf(f, "  </%s>\n", elem_map[tag]);
}
static void
unparse_fields(FILE *f, const struct contest_member *memb, int tag)
{
  int i;

  if (!memb) return;
  fprintf(f, "  <%s", elem_map[tag]);
  if (memb->min_count >= 0)
    fprintf(f, " %s=\"%d\"", attr_map[CONTEST_A_MIN], memb->min_count);
  if (memb->max_count >= 0)
    fprintf(f, " %s=\"%d\"", attr_map[CONTEST_A_MAX], memb->max_count);
  if (memb->init_count >= 0)
    fprintf(f, " %s=\"%d\"", attr_map[CONTEST_A_INITIAL], memb->init_count);
  fprintf(f, ">\n");
  for (i = 1; i < CONTEST_LAST_MEMBER_FIELD; i++) {
    if (!memb->fields[i]) continue;
    fprintf(f, "    <%s %s=\"%s\" %s=\"%s\"/>\n",
            elem_map[CONTEST_FIELD], attr_map[CONTEST_A_ID], member_field_map[i],
            attr_map[CONTEST_A_MANDATORY],
            memb->fields[i]->mandatory?"yes":"no");
  }
  fprintf(f, "  </%s>\n", elem_map[tag]);
}

static void
unparse_text(FILE *f, int tag, const unsigned char *txt)
{
  size_t arm_sz;
  unsigned char *arm_txt;

  if (!txt) return;
  if (html_armor_needed(txt, &arm_sz)) {
    arm_txt = (unsigned char*) alloca(arm_sz + 1);
    html_armor_string(txt, arm_txt);
    txt = arm_txt;
  }
  fprintf(f, "  <%s>%s</%s>\n", elem_map[tag], txt, elem_map[tag]);
}

void
contests_unparse(FILE *f,
                 const struct contest_desc *cnts)
{
  struct opcap_list_item *cap;
  unsigned char *s;
  int i;

  contests_write_header(f, cnts);
  fprintf(f, "\n");

  unparse_text(f, CONTEST_NAME, cnts->name);
  unparse_text(f, CONTEST_NAME_EN, cnts->name_en);
  unparse_text(f, CONTEST_MAIN_URL, cnts->main_url);
  unparse_text(f, CONTEST_ROOT_DIR, cnts->root_dir);
  unparse_text(f, CONTEST_CONF_DIR, cnts->conf_dir);
  if (cnts->reg_deadline) {
    fprintf(f, "  <%s>%s</%s>\n", elem_map[CONTEST_REGISTRATION_DEADLINE],
            xml_unparse_date(cnts->reg_deadline),
            elem_map[CONTEST_REGISTRATION_DEADLINE]);
  }
  unparse_text(f, CONTEST_REGISTER_EMAIL, cnts->register_email);
  unparse_text(f, CONTEST_REGISTER_URL, cnts->register_url);
  unparse_text(f, CONTEST_TEAM_URL, cnts->team_url);
  unparse_text(f, CONTEST_STANDINGS_URL, cnts->standings_url);
  unparse_text(f, CONTEST_PROBLEMS_URL, cnts->problems_url);
  unparse_text(f, CONTEST_REGISTER_EMAIL_FILE, cnts->register_email_file);
  unparse_text(f, CONTEST_LOGIN_TEMPLATE, cnts->login_template);
  unparse_text(f, CONTEST_LOGIN_TEMPLATE_OPTIONS, cnts->login_template_options);

  unparse_access(f, cnts->register_access, CONTEST_REGISTER_ACCESS);
  unparse_access(f, cnts->users_access, CONTEST_USERS_ACCESS);
  unparse_access(f, cnts->master_access, CONTEST_MASTER_ACCESS);
  unparse_access(f, cnts->judge_access, CONTEST_JUDGE_ACCESS);
  unparse_access(f, cnts->team_access, CONTEST_TEAM_ACCESS);
  unparse_access(f, cnts->serve_control_access, CONTEST_SERVE_CONTROL_ACCESS);

  if (cnts->caps_node) {
    fprintf(f, "  <%s>\n", elem_map[CONTEST_CAPS]);
    for (cap = cnts->capabilities.first; cap;
         cap = (typeof(cap)) cap->b.right) {
      fprintf(f, "    <%s %s = \"%s\">\n",
              elem_map[CONTEST_CAP], attr_map[CONTEST_A_LOGIN], cap->login);
      s = opcaps_unparse(6, 60, cap->caps);
      fprintf(f, "%s", s);
      xfree(s);
      fprintf(f, "    </%s>\n", elem_map[CONTEST_CAP]);
    }
    fprintf(f, "  </%s>\n", elem_map[CONTEST_CAPS]);
  }

  for (i = 1; i < CONTEST_LAST_FIELD; i++) {
    if (!cnts->fields[i]) continue;
    fprintf(f, "  <%s %s=\"%s\" %s=\"%s\"/>\n",
            elem_map[CONTEST_FIELD], attr_map[CONTEST_A_ID],
            field_map[i], attr_map[CONTEST_A_MANDATORY],
            cnts->fields[i]->mandatory?"yes":"no");
  }

  unparse_fields(f, cnts->members[CONTEST_M_CONTESTANT], CONTEST_CONTESTANTS);
  unparse_fields(f, cnts->members[CONTEST_M_RESERVE], CONTEST_RESERVES);
  unparse_fields(f, cnts->members[CONTEST_M_COACH], CONTEST_COACHES);
  unparse_fields(f, cnts->members[CONTEST_M_ADVISOR], CONTEST_ADVISORS);
  unparse_fields(f, cnts->members[CONTEST_M_GUEST], CONTEST_GUESTS);

  unparse_text(f, CONTEST_USERS_HEADER_FILE, cnts->users_header_file);
  unparse_text(f, CONTEST_USERS_FOOTER_FILE, cnts->users_footer_file);
  unparse_text(f, CONTEST_REGISTER_HEADER_FILE, cnts->register_header_file);
  unparse_text(f, CONTEST_REGISTER_FOOTER_FILE, cnts->register_footer_file);
  unparse_text(f, CONTEST_TEAM_HEADER_FILE, cnts->team_header_file);
  unparse_text(f, CONTEST_TEAM_FOOTER_FILE, cnts->team_footer_file);
  unparse_text(f, CONTEST_PRIV_HEADER_FILE, cnts->priv_header_file);
  unparse_text(f, CONTEST_PRIV_FOOTER_FILE, cnts->priv_footer_file);

  unparse_text(f, CONTEST_USERS_HEAD_STYLE, cnts->users_head_style);
  unparse_text(f, CONTEST_USERS_PAR_STYLE, cnts->users_par_style);
  unparse_text(f, CONTEST_USERS_TABLE_STYLE, cnts->users_table_style);
  unparse_text(f, CONTEST_USERS_VERB_STYLE, cnts->users_verb_style);
  unparse_text(f, CONTEST_USERS_TABLE_FORMAT, cnts->users_table_format);
  unparse_text(f, CONTEST_USERS_TABLE_FORMAT_EN, cnts->users_table_format_en);
  unparse_text(f, CONTEST_USERS_TABLE_LEGEND, cnts->users_table_legend);
  unparse_text(f, CONTEST_USERS_TABLE_LEGEND_EN, cnts->users_table_legend_en);
  unparse_text(f, CONTEST_REGISTER_HEAD_STYLE, cnts->register_head_style);
  unparse_text(f, CONTEST_REGISTER_PAR_STYLE, cnts->register_par_style);
  unparse_text(f, CONTEST_REGISTER_TABLE_STYLE, cnts->register_table_style);
  unparse_text(f, CONTEST_TEAM_HEAD_STYLE, cnts->team_head_style);
  unparse_text(f, CONTEST_TEAM_PAR_STYLE, cnts->team_par_style);

  unparse_text(f, CONTEST_SERVE_USER, cnts->serve_user);
  unparse_text(f, CONTEST_SERVE_GROUP, cnts->serve_group);
  unparse_text(f, CONTEST_RUN_USER, cnts->run_user);
  unparse_text(f, CONTEST_RUN_GROUP, cnts->run_group);

  unparse_text(f, CONTEST_USER_NAME_COMMENT, cnts->user_name_comment);
  unparse_text(f, CONTEST_ALLOWED_LANGUAGES, cnts->allowed_languages);
  unparse_text(f, CONTEST_ALLOWED_REGIONS, cnts->allowed_regions);
  unparse_text(f, CONTEST_CF_NOTIFY_EMAIL, cnts->cf_notify_email);
  unparse_text(f, CONTEST_CLAR_NOTIFY_EMAIL, cnts->clar_notify_email);
  unparse_text(f, CONTEST_DAILY_STAT_EMAIL, cnts->daily_stat_email);

  if (cnts->client_ignore_time_skew || cnts->client_disable_team) {
    fprintf(f, "  <%s>\n", elem_map[CONTEST_CLIENT_FLAGS]);
    if (cnts->client_ignore_time_skew)
      fprintf(f, "    IGNORE_TIME_SKEW,\n");
    if (cnts->client_disable_team)
      fprintf(f, "    DISABLE_TEAM,\n");
    if (cnts->disable_member_delete)
      fprintf(f, "    DISABLE_MEMBER_DELETE,\n");
    fprintf(f, "  </%s>\n", elem_map[CONTEST_CLIENT_FLAGS]);
  }
  fprintf(f, "</%s>", elem_map[CONTEST_CONTEST]);
}

int
contests_save_xml(struct contest_desc *cnts,
                  const unsigned char *txt1,
                  const unsigned char *txt2,
                  const unsigned char *txt3)
{
  int serial = 1;
  unsigned char tmp_path[1024];
  unsigned char xml_path[1024];
  int fd;
  FILE *f;
  struct stat xml_stat;

  while (1) {
    snprintf(tmp_path, sizeof(tmp_path), "%s/_contests_tmp_%d.xml",
             contests_dir, serial++);
    if ((fd = open(tmp_path, O_WRONLY| O_CREAT| O_TRUNC|O_EXCL, 0600)) >= 0)
      break;
    if (errno != EEXIST) return -CONTEST_ERR_FILE_CREATION_ERROR;
  }
  if (!(f = fdopen(fd, "w"))) {
    close(fd);
    unlink(tmp_path);
    return -CONTEST_ERR_FILE_CREATION_ERROR;
  }

  fputs(txt1, f);
  contests_write_header(f, cnts);
  fputs(txt2, f);
  fputs(txt3, f);
  if (ferror(f)) {
    fclose(f);
    unlink(tmp_path);
    return -CONTEST_ERR_IO_ERROR;
  }
  if (fclose(f) < 0) {
    unlink(tmp_path);
    return -CONTEST_ERR_IO_ERROR;
  }

  contests_make_path(xml_path, sizeof(xml_path), cnts->id);
  if (stat(xml_path, &xml_stat) < 0) {
    unlink(tmp_path);
    return -CONTEST_ERR_NO_CONTEST;
  }
  if (!S_ISREG(xml_stat.st_mode)) {
    unlink(tmp_path);
    return -CONTEST_ERR_NO_CONTEST;
  }

  // try to change the owner, but ignore the error
  chown(tmp_path, xml_stat.st_uid, -1);
  // try to change the group and log errors
  if (chown(tmp_path, -1, xml_stat.st_gid) < 0) {
    err("contests_save_xml: chgrp failed: %s", os_ErrorMsg());
  }
  // try to change permissions and log errors
  if (chmod(tmp_path, xml_stat.st_mode & 07777) < 0) {
    err("contests_save_xml: chmod failed: %s", os_ErrorMsg());
  }

  if (rename(tmp_path, xml_path) < 0) {
    err("contests_save_xml: rename failed: %s", os_ErrorMsg());
    unlink(tmp_path);
    return -CONTEST_ERR_FILE_CREATION_ERROR;
  }
  return 0;
}

int
contests_unparse_and_save(struct contest_desc *cnts,
                          const unsigned char *header,
                          const unsigned char *footer,
                          const unsigned char *add_footer,
                          unsigned char *(*diff_func)(const unsigned char *,
                                                      const unsigned char *),
                          unsigned char **p_diff_txt)
{
  int serial = 1;
  unsigned char tmp_path[1024];
  unsigned char xml_path[1024];
  int fd;
  FILE *f;
  struct stat xml_stat;
  char *old_text = 0;
  size_t old_size = 0;
  char *new_text = 0;
  size_t new_size = 0;
  unsigned char *diff_txt = 0;

  f = open_memstream(&new_text, &new_size);
  fputs(header, f);
  contests_unparse(f, cnts);
  fputs(footer, f);
  fclose(f); f = 0;

  contests_make_path(xml_path, sizeof(xml_path), cnts->id);

  // read the previuos file and compare it with the new
  if (generic_read_file(&old_text, 0, &old_size, 0, 0, xml_path, 0) >= 0
      && new_size == old_size && memcmp(new_text, old_text, new_size) == 0) {
    info("contest_save_xml: %d is not changed", cnts->id);
    xfree(old_text);
    xfree(new_text);
    return 0;
  }
  xfree(old_text); old_text = 0;
  old_size = 0;

  while (1) {
    snprintf(tmp_path, sizeof(tmp_path), "%s/_contests_tmp_%d.xml",
             contests_dir, serial++);
    if ((fd = open(tmp_path, O_WRONLY| O_CREAT| O_TRUNC|O_EXCL, 0600)) >= 0)
      break;
    if (errno != EEXIST) {
      xfree(new_text);
      return -CONTEST_ERR_FILE_CREATION_ERROR;
    }
  }
  if (!(f = fdopen(fd, "w"))) {
    close(fd);
    xfree(new_text);
    unlink(tmp_path);
    return -CONTEST_ERR_FILE_CREATION_ERROR;
  }

  fwrite(new_text, 1, new_size, f);
  xfree(new_text); new_text = 0;
  new_size = 0;
  fputs(add_footer, f);
  if (ferror(f)) {
    fclose(f);
    unlink(tmp_path);
    return -CONTEST_ERR_IO_ERROR;
  }
  if (fclose(f) < 0) {
    unlink(tmp_path);
    return -CONTEST_ERR_IO_ERROR;
  }

  if (diff_func && p_diff_txt) {
    diff_txt = (*diff_func)(xml_path, tmp_path);
  }

  if (stat(xml_path, &xml_stat) >= 0) {
    if (!S_ISREG(xml_stat.st_mode)) {
      unlink(tmp_path);
      xfree(diff_txt);
      return -CONTEST_ERR_NO_CONTEST;
    }

    // try to change the owner, but ignore the error
    chown(tmp_path, xml_stat.st_uid, -1);
    // try to change the group and log errors
    if (chown(tmp_path, -1, xml_stat.st_gid) < 0) {
      err("contests_save_xml: chgrp failed: %s", os_ErrorMsg());
    }
    // try to change permissions and log errors
    if (chmod(tmp_path, xml_stat.st_mode & 07777) < 0) {
      err("contests_save_xml: chmod failed: %s", os_ErrorMsg());
    }
  } else {
    if (chmod(tmp_path, 0664) < 0) {
      err("contests_save_xml: chmod failed: %s", os_ErrorMsg());
    }
  }

  if (rename(tmp_path, xml_path) < 0) {
    err("contests_save_xml: rename failed: %s", os_ErrorMsg());
    unlink(tmp_path);
    xfree(diff_txt);
    return -CONTEST_ERR_FILE_CREATION_ERROR;
  }
  if (p_diff_txt) *p_diff_txt = diff_txt;
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
