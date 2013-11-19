/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2013 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_limits.h"

#include "userlist.h"
#include "errlog.h"
#include "protocol.h"
#include "misctext.h"
#include "xml_utils.h"

#include "reuse_xalloc.h"
#include "reuse_logger.h"

#include <expat.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include "win32_compat.h"

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJ_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

static char const * const elem_map[] =
{
  0,
  "userlist",
  "user",
  "login",
  "name",
  "inst",
  "inst_en",
  "instshort",
  "instshort_en",
  "instnum",
  "fac",
  "fac_en",
  "facshort",
  "facshort_en",
  "password",
  "email",
  "homepage",
  "phone",
  "member",
  "surname",
  "surname_en",
  "middlename",
  "middlename_en",
  "grade",
  "group",
  "group_en",
  "cookies",
  "cookie",
  "contests",
  "contest",
  "status",
  "occupation",
  "occupation_en",
  "discipline",
  "members",
  "contestants",
  "reserves",
  "coaches",
  "advisors",
  "guests",
  "firstname",
  "firstname_en",
  "team_password",
  "city",
  "city_en",
  "country",
  "country_en",
  "region",
  "area",
  "zip",
  "street",
  "location",
  "spelling",
  "printer_name",
  "exam_id",
  "exam_cypher",
  "languages",
  "extra1",
  "cntsinfos",
  "cntsinfo",
  "birth_date",
  "entry_date",
  "graduation_date",
  "gender",
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
  "usergroups",
  "usergroup",
  "usergroupmembers",
  "usergroupmember",

  0
};
static char const * const attr_map[] =
{
  0,
  "name",
  "id",
  "method",
  "ip",
  "value",
  "locale_id",
  "expire",
  "contest_id",
  "registered",
  "last_login",
  "last_access",
  "last_change",
  "invisible",
  "banned",
  "locked",
  "incomplete",
  "disqualified",
  "status",
  "last_pwdchange",
  "public",
  "use_cookies",
  "last_minor_change",
  "member_serial",
  "serial",
  "read_only",
  "priv_level",
  "never_clean",
  "privileged",
  "date",
  "simple_registration",
  "cnts_read_only",
  "create",
  "copied_from",
  "ssl",
  "last_info_pwdchange",
  "last_info_change",
  "role",
  "cnts_last_login",
  "info_create",
  "recovery",
  "team_login",
  "group_id",
  "group_name",
  "description",
  "user_id",
  "client_key",

  0
};
static size_t const elem_sizes[USERLIST_LAST_TAG] =
{
  [USERLIST_T_USERLIST] = sizeof(struct userlist_list),
  [USERLIST_T_USER] = sizeof(struct userlist_user),
  [USERLIST_T_MEMBER] = sizeof(struct userlist_member),
  [USERLIST_T_COOKIE] = sizeof(struct userlist_cookie),
  [USERLIST_T_CONTEST] = sizeof(struct userlist_contest),
  [USERLIST_T_MEMBERS] = sizeof(struct userlist_members),
  [USERLIST_T_CNTSINFO] = sizeof(struct userlist_user_info),
  [USERLIST_T_USERGROUP] = sizeof(struct userlist_group),
  [USERLIST_T_USERGROUPMEMBER] = sizeof(struct userlist_groupmember),
};

struct xml_tree *
userlist_node_alloc(int tag)
{
  struct xml_tree *p = xml_elem_alloc(tag, elem_sizes);
  p->tag = tag;
  return p;
}

static void
elem_free(struct xml_tree *t)
{
  switch (t->tag) {
  case USERLIST_T_USERLIST:
    {
      struct userlist_list *p = (struct userlist_list*) t;
      xfree(p->user_map);
      xfree(p->name);
      xfree(p->login_hash_table);
      xfree(p->cookie_hash_table);
      xfree(p->client_key_hash_table);
      xfree(p->group_map);
      xfree(p->group_hash_table);
    }
    break;
  case USERLIST_T_USER:
    {
      struct userlist_user *p = (struct userlist_user*) t;
      xfree(p->login);
      xfree(p->email);
      xfree(p->passwd);
      xfree(p->extra1);
      xfree(p->cntsinfo);
    }
    break;
  case USERLIST_T_MEMBER:
    {
      struct userlist_member *p = (struct userlist_member*) t;
      xfree(p->firstname);
      xfree(p->firstname_en);
      xfree(p->middlename);
      xfree(p->middlename_en);
      xfree(p->surname);
      xfree(p->surname_en);
      xfree(p->group);
      xfree(p->group_en);
      xfree(p->email);
      xfree(p->homepage);
      xfree(p->occupation);
      xfree(p->occupation_en);
      xfree(p->discipline);
      xfree(p->inst);
      xfree(p->inst_en);
      xfree(p->instshort);
      xfree(p->instshort_en);
      xfree(p->fac);
      xfree(p->fac_en);
      xfree(p->facshort);
      xfree(p->facshort_en);
      xfree(p->phone);
    }
    break;
  case USERLIST_T_MEMBERS:
    {
      struct userlist_members *p = (struct userlist_members*) t;
      xfree(p->m);
    }
    break;
  case USERLIST_T_CNTSINFO:
    {
      struct userlist_user_info *p = (struct userlist_user_info*) t;
      xfree(p->name);
      xfree(p->team_passwd);
      xfree(p->inst);
      xfree(p->inst_en);
      xfree(p->instshort);
      xfree(p->instshort_en);
      xfree(p->fac);
      xfree(p->fac_en);
      xfree(p->facshort);
      xfree(p->facshort_en);
      xfree(p->homepage);
      xfree(p->city);
      xfree(p->city_en);
      xfree(p->country);
      xfree(p->country_en);
      xfree(p->region);
      xfree(p->area);
      xfree(p->zip);
      xfree(p->street);
      xfree(p->location);
      xfree(p->spelling);
      xfree(p->printer_name);
      xfree(p->exam_id);
      xfree(p->exam_cypher);
      xfree(p->languages);
      xfree(p->phone);
      xfree(p->field0);
      xfree(p->field1);
      xfree(p->field2);
      xfree(p->field3);
      xfree(p->field4);
      xfree(p->field5);
      xfree(p->field6);
      xfree(p->field7);
      xfree(p->field8);
      xfree(p->field9);
    }
    break;
  case USERLIST_T_USERGROUP:
    {
      struct userlist_group *p = (struct userlist_group*) t;
      xfree(p->group_name);
      xfree(p->description);
    }
    break;
  case USERLIST_T_USERGROUPMEMBER:
    {
      struct userlist_groupmember *p = (struct userlist_groupmember*) t;
      xfree(p->rights);
    }
    break;
  }
}

static struct xml_parse_spec userlist_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = elem_sizes,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = elem_free,
  .attr_free = NULL,
};

void
userlist_elem_free_data(struct xml_tree *t)
{
  int tag;
  size_t sz = 0;

  if (!t) return;

  tag = t->tag;
  // free the data
  elem_free(t);
  // initialize with 0
  if (tag > 0 || tag < USERLIST_LAST_TAG) sz = elem_sizes[tag];
  if (!sz) sz = sizeof(struct xml_tree);
  memset(t, 0, sz);
  t->tag = tag;
}

void
userlist_free_attrs(struct xml_tree *t)
{
  xml_tree_free_attrs(t, &userlist_parse_spec);
}

struct string_to_int_tbl
{
  const unsigned char *str;
  int val;
};

static int
string_to_enum(const unsigned char *str, const struct string_to_int_tbl *tbl)
{
  int i;

  if (!str) return -1;
  for (i = 0; tbl[i].str; i++)
    if (!strcasecmp(str, tbl[i].str))
      return tbl[i].val;
  return -1;
}

static int
parse_priv_level_attr(struct xml_attr *a, int *p_val)
{
  int v;

  static struct string_to_int_tbl priv_level_tbl[] =
  {
    { "user", PRIV_LEVEL_USER },
    { "judge", PRIV_LEVEL_JUDGE },
    { "administrator", PRIV_LEVEL_ADMIN },
    { "admin", PRIV_LEVEL_ADMIN },

    { 0, 0 },
  };

  if ((v = string_to_enum(a->text, priv_level_tbl)) < 0)
    return xml_err_attr_invalid(a);
  *p_val = v;
  return v;
}

static int
parse_password_method_attr(struct xml_attr *a, int *p_val)
{
  int v;

  static struct string_to_int_tbl password_method_tbl[] =
  {
    { "plain", USERLIST_PWD_PLAIN },
    { "base64", USERLIST_PWD_BASE64 },
    { "sha1", USERLIST_PWD_SHA1 },

    { 0, 0 },
  };

  if ((v = string_to_enum(a->text, password_method_tbl)) < 0)
    return xml_err_attr_invalid(a);
  *p_val = v;
  return v;
}

static int
parse_reg_status_attr(struct xml_attr *a, int *p_val)
{
  int v;

  static struct string_to_int_tbl reg_status_tbl[] =
  {
    { "ok", USERLIST_REG_OK },
    { "pending", USERLIST_REG_PENDING },
    { "rejected", USERLIST_REG_REJECTED },

    { 0, 0 },
  };

  if ((v = string_to_enum(a->text, reg_status_tbl)) < 0)
    return xml_err_attr_invalid(a);
  *p_val = v;
  return v;
}

static int
parse_contestant_status_elem(struct xml_tree *p, int *p_val)
{
  int v;

  static struct string_to_int_tbl contestant_status_tbl[] =
  {
    { "schoolchild", USERLIST_ST_SCHOOL },
    { "student", USERLIST_ST_STUDENT },
    { "magistrant", USERLIST_ST_MAG },
    { "phdstudent", USERLIST_ST_ASP },
    { "teacher", USERLIST_ST_TEACHER },
    { "professor", USERLIST_ST_PROF },
    { "scientist", USERLIST_ST_SCIENTIST },
    { "other", USERLIST_ST_OTHER },

    { 0, 0 },
  };

  if ((v = string_to_enum(p->text, contestant_status_tbl)) < 0)
    return xml_err_elem_invalid(p);
  *p_val = v;
  return v;
}

static int
parse_contestant_gender_elem(struct xml_tree *p, int *p_val)
{
  int v;

  static struct string_to_int_tbl contestant_gender_tbl[] =
  {
    { "male", USERLIST_SX_MALE },
    { "female", USERLIST_SX_FEMALE },

    { 0, 0 },
  };

  if ((v = string_to_enum(p->text, contestant_gender_tbl)) < 0)
    return xml_err_elem_invalid(p);
  *p_val = v;
  return v;
}

static int
parse_passwd(struct xml_tree *t, unsigned char **p_pwd, int *p_method)
{
  struct xml_attr *a;

  ASSERT(t->tag == USERLIST_T_PASSWORD || t->tag == USERLIST_T_TEAM_PASSWORD);

  if (t->first_down) {
    xml_err_nested_elems(t);
    return -1;
  }
  if (!t->text) t->text = xstrdup("");

  for (a = t->first; a; a = a->next) {
    if (a->tag != USERLIST_A_METHOD) {
      xml_err_attr_not_allowed(t, a);
      return -1;
    }
    if (parse_password_method_attr(a, p_method) < 0) return -1;
  }
  userlist_free_attrs(t);
  if (!*t->text) *p_method = USERLIST_PWD_PLAIN;
  *p_pwd = t->text; t->text = 0;
  return 0;
}

static int
parse_cookies(
        char const *path,
        struct xml_tree *cookies,
        struct userlist_user *usr)
{
  struct xml_tree *t;
  struct xml_attr *a;
  struct userlist_cookie *c;
  int has_ip = 0;

  if (cookies->first) return xml_err_attrs(cookies);
  if (xml_empty_text(cookies) < 0) return -1;
  for (t = cookies->first_down; t; t = t->right) {
    if (t->tag != USERLIST_T_COOKIE) return xml_err_elem_not_allowed(t);
    c = (struct userlist_cookie*) t;
    if (xml_empty_text(t) < 0) return -1;
    if (t->first_down) return xml_err_nested_elems(t);
    c->contest_id = -1;
    c->locale_id = -1;
    c->user_id = usr->id;
    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_IP:
        if (xml_parse_ipv6(NULL, path, a->line, a->column, a->text, &c->ip) < 0)
          return -1;
        has_ip = 1;
        break;
      case USERLIST_A_VALUE:
        if (xml_parse_full_cookie(a->text, &c->cookie, &c->client_key) < 0) {
          xml_err_attr_invalid(a);
          return -1;
        }
        break;
      case USERLIST_A_SSL:
        if (xml_attr_bool(a, &c->ssl) < 0) return -1;
        break;
      case USERLIST_A_RECOVERY:
        if (xml_attr_bool(a, &c->recovery) < 0) return -1;
        break;
      case USERLIST_A_TEAM_LOGIN:
        if (xml_attr_bool(a, &c->team_login) < 0) return -1;
        break;
      case USERLIST_A_EXPIRE:
        if (xml_parse_date(NULL, path, a->line, a->column, a->text, &c->expire) < 0)
          return -1;
        break;
      case USERLIST_A_LOCALE_ID:
        if (xml_parse_int(NULL, path, a->line, a->column, a->text, &c->locale_id) < 0)
          return -1;
        if (c->locale_id < -1 || c->locale_id > 127)
          return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_CONTEST_ID:
        if (xml_parse_int(NULL, path, a->line, a->column, a->text, &c->contest_id) < 0)
          return -1;
        if (c->contest_id < 0)
          return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_PRIV_LEVEL:
        if (parse_priv_level_attr(a, &c->priv_level) < 0) return -1;
        break;
      case USERLIST_A_ROLE:
        if (xml_attr_int(a, &c->role) < 0) return -1;
        if (c->role < 0) return -1;
        break;
      default:
        return xml_err_attr_not_allowed(t, a);
      }
    }
    userlist_free_attrs(t);
    if (!has_ip) return xml_err_attr_undefined(t, USERLIST_A_IP);
    if (!c->cookie) return xml_err_attr_undefined(t, USERLIST_A_VALUE);
    if (!c->expire) return xml_err_attr_undefined(t, USERLIST_A_EXPIRE);
    if (c->contest_id < 0 && (c->priv_level > 0 || c->role > 0))
      c->contest_id = 0;
  }
  return 0;
}

#define MEMBER_OFFSET(f) XOFFSET(struct userlist_member, f)

static const size_t leaf_member_offsets[USERLIST_LAST_TAG] =
{
  [USERLIST_T_INST] = MEMBER_OFFSET(inst),
  [USERLIST_T_INST_EN] = MEMBER_OFFSET(inst_en),
  [USERLIST_T_INSTSHORT] = MEMBER_OFFSET(instshort),
  [USERLIST_T_INSTSHORT_EN] = MEMBER_OFFSET(instshort_en),
  [USERLIST_T_FAC] = MEMBER_OFFSET(fac),
  [USERLIST_T_FAC_EN] = MEMBER_OFFSET(fac_en),
  [USERLIST_T_FACSHORT] = MEMBER_OFFSET(facshort),
  [USERLIST_T_FACSHORT_EN] = MEMBER_OFFSET(facshort_en),
  [USERLIST_T_EMAIL] = MEMBER_OFFSET(email),
  [USERLIST_T_HOMEPAGE] = MEMBER_OFFSET(homepage),
  [USERLIST_T_PHONE] = MEMBER_OFFSET(phone),
  [USERLIST_T_SURNAME] = MEMBER_OFFSET(surname),
  [USERLIST_T_SURNAME_EN] = MEMBER_OFFSET(surname_en),
  [USERLIST_T_MIDDLENAME] = MEMBER_OFFSET(middlename),
  [USERLIST_T_MIDDLENAME_EN] = MEMBER_OFFSET(middlename_en),
  [USERLIST_T_GROUP] = MEMBER_OFFSET(group),
  [USERLIST_T_GROUP_EN] = MEMBER_OFFSET(group_en),
  [USERLIST_T_OCCUPATION] = MEMBER_OFFSET(occupation),
  [USERLIST_T_OCCUPATION_EN] = MEMBER_OFFSET(occupation_en),
  [USERLIST_T_DISCIPLINE] = MEMBER_OFFSET(discipline),
  [USERLIST_T_FIRSTNAME] = MEMBER_OFFSET(firstname),
  [USERLIST_T_FIRSTNAME_EN] = MEMBER_OFFSET(firstname_en),
};

static const size_t date_member_offsets[USERLIST_LAST_TAG] =
{
  [USERLIST_T_BIRTH_DATE] = MEMBER_OFFSET(birth_date),
  [USERLIST_T_ENTRY_DATE] = MEMBER_OFFSET(entry_date),
  [USERLIST_T_GRADUATION_DATE] = MEMBER_OFFSET(graduation_date),
};

static int
parse_members(
        char const *path,
        struct xml_tree *q,
        struct xml_tree *link_node,
        struct userlist_user_info *ui)
{
  struct xml_tree *t;
  struct userlist_member *mb;
  struct xml_tree *p, *saved_next, *saved_next_2;
  struct xml_attr *a;
  struct userlist_members *mmm;
  unsigned char **p_str;
  time_t *p_time;
  int role;

  if (q->tag < USERLIST_T_CONTESTANTS || q->tag > USERLIST_T_GUESTS)
    return xml_err_elem_not_allowed(q);
  role = q->tag - USERLIST_T_CONTESTANTS;
  if (q->first) return xml_err_attrs(q);
  xfree(q->text); q->text = 0;

  for (t = q->first_down; t; t = saved_next_2) {
    saved_next_2 = t->right;

    if (t->tag != USERLIST_T_MEMBER) return xml_err_elem_not_allowed(t);
    mb = (struct userlist_member*) t;
    xfree(t->text); t->text = 0;
    mb->grade = -1;
    mb->team_role = role;

    if (!ui->members) {
      mmm=(struct userlist_members*)userlist_node_alloc(USERLIST_T_MEMBERS);
      ui->members = mmm;
      xml_link_node_last(link_node, &mmm->b);
    }
    mmm = ui->members;

    if (mmm->u == mmm->a) {
      if (!mmm->a) mmm->a = 4;
      else mmm->a *= 2;
      XREALLOC(mmm->m, mmm->a);
    }
    mmm->m[mmm->u++] = mb;
    xml_unlink_node(t);
    xml_link_node_last(&mmm->b, t);

    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_SERIAL:
        if (xml_attr_int(a, &mb->serial) < 0)
          return xml_err_attr_invalid(a);
        if (mb->serial <= 0) return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_ROLE:
        if (xml_attr_int(a, &mb->team_role) < 0)
          return xml_err_attr_invalid(a);
        if (mb->team_role < 0 || mb->team_role >= USERLIST_MB_LAST)
          return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_COPIED_FROM:
        if (xml_attr_int(a, &mb->copied_from) < 0)
          return xml_err_attr_invalid(a);
        if (mb->copied_from < 0) mb->copied_from = 0;
        break;
      case USERLIST_A_CREATE:
        if (xml_attr_date(a, &mb->create_time) < 0)
          return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_LAST_CHANGE:
        if (xml_attr_date(a, &mb->last_change_time) < 0)
          return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_LAST_ACCESS:
        if (xml_attr_date(a, &mb->last_access_time) < 0)
          return xml_err_attr_invalid(a);
        break;
      default:
        return xml_err_attr_not_allowed(t, a);
      }
    }
    userlist_free_attrs(t);

    for (p = t->first_down; p; p = saved_next) {
      saved_next = p->right;

      if (leaf_member_offsets[p->tag] > 0) {
        p_str = XPDEREF(unsigned char *, mb, leaf_member_offsets[p->tag]);
        if (xml_leaf_elem(p, p_str, 1, 1) < 0) return -1;
        xml_unlink_node(p);
        userlist_free(p);
        continue;
      }

      if (date_member_offsets[p->tag] > 0) {
        p_time = XPDEREF(time_t, mb, date_member_offsets[p->tag]);
        if (p->first) return xml_err_attrs(p);
        if (p->first_down) return xml_err_nested_elems(p);
        if (*p_time > 0) return xml_err_elem_redefined(p);
        if (userlist_parse_date_2(p->text, p_time) < 0)
          return xml_err_elem_invalid(p);
        xml_unlink_node(p);
        userlist_free(p);
        continue;
      }

      switch (p->tag) {
      case USERLIST_T_STATUS:
        if (mb->status) return xml_err_elem_redefined(p);
        if (p->first) return xml_err_attrs(p);
        if (p->first_down) return xml_err_nested_elems(p);
        if (parse_contestant_status_elem(p, &mb->status) < 0) return -1;
        xml_unlink_node(p);
        userlist_free(p);
        break;
      case USERLIST_T_GENDER:
        if (mb->gender) return xml_err_elem_redefined(p);
        if (p->first) return xml_err_attrs(p);
        if (p->first_down) return xml_err_nested_elems(p);
        if (parse_contestant_gender_elem(p, &mb->gender) < 0) return -1;
        xml_unlink_node(p);
        userlist_free(p);
        break;
      case USERLIST_T_GRADE:
        if (mb->grade >= 0) return xml_err_elem_redefined(p);
        if (p->first) return xml_err_attrs(p);
        if (p->first_down) return xml_err_nested_elems(p);
        if (!p->text || !*p->text) break;
        if (xml_parse_int(NULL, path, p->line, p->column, p->text, &mb->grade) < 0)
          return xml_err_elem_invalid(p);
        if (mb->grade < -1 || mb->grade >= 100000)
          return xml_err_elem_invalid(p);
        xml_unlink_node(p);
        userlist_free(p);
        break;
      default:
        return xml_err_elem_not_allowed(p);
      }
    }
  }

  return 0;
}
static int
parse_contest(char const *path, struct xml_tree *t,
              struct userlist_user *usr)
{
  struct xml_tree *p;
  struct userlist_contest *reg;
  struct xml_attr *a;
  int tmp;

  ASSERT(t->tag == USERLIST_T_CONTESTS);
  if (usr) {
    if (usr->contests) return xml_err_elem_redefined(t);
    usr->contests = t;
  }
  xfree(t->text); t->text = 0;
  if (t->first) xml_err_attrs(t);

  for (p = t->first_down; p; p = p->right) {
    if (p->tag != USERLIST_T_CONTEST)
      return xml_err_elem_not_allowed(p);
    if (p->first_down) return xml_err_nested_elems(p);
    if (xml_empty_text(p) < 0) return -1;
    reg = (struct userlist_contest*) p;
    
    reg->id = -1;
    reg->status = -1;
    for (a = p->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_ID:
        if (xml_parse_int(NULL, path, a->line, a->column, a->text, &reg->id) < 0)
          return -1;
        if (reg->id <= 0) return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_STATUS:
        if (parse_reg_status_attr(a, &reg->status) < 0) return -1;
        break;
      case USERLIST_A_BANNED:
        if (xml_attr_bool(a, &tmp) < 0) return -1;
        if (tmp) reg->flags |= USERLIST_UC_BANNED;
        break;
      case USERLIST_A_INVISIBLE:
        if (xml_attr_bool(a, &tmp) < 0) return -1;
        if (tmp) reg->flags |= USERLIST_UC_INVISIBLE;
        break;
      case USERLIST_A_LOCKED:
        if (xml_attr_bool(a, &tmp) < 0) return -1;
        if (tmp) reg->flags |= USERLIST_UC_LOCKED;
        break;
      case USERLIST_A_INCOMPLETE:
        if (xml_attr_bool(a, &tmp) < 0) return -1;
        if (tmp) reg->flags |= USERLIST_UC_INCOMPLETE;
        break;
      case USERLIST_A_DISQUALIFIED:
        if (xml_attr_bool(a, &tmp) < 0) return -1;
        if (tmp) reg->flags |= USERLIST_UC_DISQUALIFIED;
        break;
      case USERLIST_A_DATE:
        if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                           &reg->create_time) < 0)
          return -1;
        break;
      default:
        return xml_err_attr_not_allowed(p, a);
      }
    }
    userlist_free_attrs(p);
    if (reg->id == -1)
      return xml_err_attr_undefined(p, USERLIST_A_ID);
    if (reg->status == -1)
      return xml_err_attr_undefined(p, USERLIST_A_STATUS);
  }

  return 0;
}

#define INFO_OFFSET(f) XOFFSET(struct userlist_user_info, f)

static const size_t leaf_info_offsets[USERLIST_LAST_TAG] =
{
  [USERLIST_T_NAME] = INFO_OFFSET(name),
  [USERLIST_T_INST] = INFO_OFFSET(inst),
  [USERLIST_T_INST_EN] = INFO_OFFSET(inst_en),
  [USERLIST_T_INSTSHORT] = INFO_OFFSET(instshort),
  [USERLIST_T_INSTSHORT_EN] = INFO_OFFSET(instshort_en),
  [USERLIST_T_FAC] = INFO_OFFSET(fac),
  [USERLIST_T_FAC_EN] = INFO_OFFSET(fac_en),
  [USERLIST_T_FACSHORT] = INFO_OFFSET(facshort),
  [USERLIST_T_FACSHORT_EN] = INFO_OFFSET(facshort_en),
  [USERLIST_T_HOMEPAGE] = INFO_OFFSET(homepage),
  [USERLIST_T_PHONE] = INFO_OFFSET(phone),
  [USERLIST_T_CITY] = INFO_OFFSET(city),
  [USERLIST_T_CITY_EN] = INFO_OFFSET(city_en),
  [USERLIST_T_COUNTRY] = INFO_OFFSET(country),
  [USERLIST_T_COUNTRY_EN] = INFO_OFFSET(country_en),
  [USERLIST_T_REGION] = INFO_OFFSET(region),
  [USERLIST_T_AREA] = INFO_OFFSET(area),
  [USERLIST_T_ZIP] = INFO_OFFSET(zip),
  [USERLIST_T_STREET] = INFO_OFFSET(street),
  [USERLIST_T_LOCATION] = INFO_OFFSET(location),
  [USERLIST_T_SPELLING] = INFO_OFFSET(spelling),
  [USERLIST_T_PRINTER_NAME] = INFO_OFFSET(printer_name),
  [USERLIST_T_EXAM_ID] = INFO_OFFSET(exam_id),
  [USERLIST_T_EXAM_CYPHER] = INFO_OFFSET(exam_cypher),
  [USERLIST_T_LANGUAGES] = INFO_OFFSET(languages),
  [USERLIST_T_FIELD0] = INFO_OFFSET(field0),
  [USERLIST_T_FIELD1] = INFO_OFFSET(field1),
  [USERLIST_T_FIELD2] = INFO_OFFSET(field2),
  [USERLIST_T_FIELD3] = INFO_OFFSET(field3),
  [USERLIST_T_FIELD4] = INFO_OFFSET(field4),
  [USERLIST_T_FIELD5] = INFO_OFFSET(field5),
  [USERLIST_T_FIELD6] = INFO_OFFSET(field6),
  [USERLIST_T_FIELD7] = INFO_OFFSET(field7),
  [USERLIST_T_FIELD8] = INFO_OFFSET(field8),
  [USERLIST_T_FIELD9] = INFO_OFFSET(field9),
};

static int
parse_cntsinfo(const char *path, struct xml_tree *node,
               struct userlist_user *usr)
{
  struct userlist_user_info *ui;
  struct xml_attr *a;
  struct xml_tree *p, *saved_next;
  time_t *pt;
  unsigned char **p_str;

  ASSERT(node);
  ASSERT(node->tag == USERLIST_T_CNTSINFO);
  ui = (struct userlist_user_info*) node;

  if (xml_empty_text(node) < 0) return -1;

  /* parse attributes */
  ui->contest_id = 0;
  for (a = node->first; a; a = a->next) {
    switch (a->tag) {
    case USERLIST_A_CONTEST_ID:
      if (xml_attr_int(a, &ui->contest_id) < 0) return -1;
      if (ui->contest_id <= 0 || ui->contest_id > EJ_MAX_CONTEST_ID)
        return xml_err_attr_invalid(a);
      if (ui->contest_id < usr->cntsinfo_a && usr->cntsinfo[ui->contest_id]) {
        xml_err_a(a, "duplicated contest_id %d", ui->contest_id);
        return -1;
      }
      break;
    case USERLIST_A_CNTS_READ_ONLY:
      if (xml_attr_bool(a, &ui->cnts_read_only) < 0) return -1;
      break;
    case USERLIST_A_LAST_CHANGE:
    case USERLIST_A_LAST_INFO_CHANGE:
      pt = &ui->last_change_time;
    parse_date_attr:
      if (xml_attr_date(a, pt) < 0) return -1;
      break;
    case USERLIST_A_LAST_ACCESS:
      pt = &ui->last_access_time;
      goto parse_date_attr;
    case USERLIST_A_LAST_PWDCHANGE:
    case USERLIST_A_LAST_INFO_PWDCHANGE:
      pt = &ui->last_pwdchange_time;
      goto parse_date_attr;
    case USERLIST_A_INFO_CREATE:
    case USERLIST_A_CREATE:
      pt = &ui->create_time;
      goto parse_date_attr;
    case USERLIST_A_CNTS_LAST_LOGIN:
      pt = &ui->last_login_time;
      goto parse_date_attr;
    default:
      return xml_err_attr_not_allowed(node, a);
    }
  }
  userlist_free_attrs(node);

  if (ui->contest_id <= 0)
    return xml_err_attr_undefined(node, USERLIST_A_CONTEST_ID);
  ui->instnum = -1;

  /* parse elements */
  for (p = node->first_down; p; p = saved_next) {
    saved_next = p->right;

    if (leaf_info_offsets[p->tag] > 0) {
      p_str = XPDEREF(unsigned char *, ui, leaf_info_offsets[p->tag]);
      if (xml_leaf_elem(p, p_str, 1, 1) < 0) return -1;
      xml_unlink_node(p);
      userlist_free(p);
      continue;
    }

    switch(p->tag) {
    case USERLIST_T_TEAM_PASSWORD:
      if (ui->team_passwd) return xml_err_elem_redefined(p);
      if (parse_passwd(p, &ui->team_passwd, &ui->team_passwd_method) < 0)
        return -1;
      break;
    case USERLIST_T_CONTESTANTS:
    case USERLIST_T_RESERVES:
    case USERLIST_T_COACHES:
    case USERLIST_T_ADVISORS:
    case USERLIST_T_GUESTS:
      if (parse_members(path, p, &ui->b, ui) < 0) return -1;
      break;
    case USERLIST_T_INSTNUM:
      if (xml_parse_int(NULL, path, p->line, p->column, p->text, &ui->instnum) < 0)
        return -1;
      if (ui->instnum < 0) return xml_err_elem_invalid(p);
      break;
    case USERLIST_T_MEMBERS:
      break;
    default:
      return xml_err_elem_not_allowed(p);
    }
  }

  if (!ui->name) ui->name = xstrdup("");

  userlist_expand_cntsinfo(usr, ui->contest_id);
  usr->cntsinfo[ui->contest_id] = ui;

  return 0;
}

static int
parse_cntsinfos(const char *path, struct xml_tree *node,
                struct userlist_user *usr)
{
  struct xml_tree *p;

  ASSERT(node);
  ASSERT(node->tag == USERLIST_T_CNTSINFOS);

  if (xml_empty_text(node) < 0) return -1;
  if (node->first) return xml_err_attrs(node);
  if (usr->cntsinfo_a > 0) return xml_err_elem_redefined(node);

  for (p = node->first_down; p; p = p->right) {
    if (p->tag != USERLIST_T_CNTSINFO)
      return xml_err_elem_not_allowed(p);
    if (parse_cntsinfo(path, p, usr) < 0) return -1;
  }
  return 0;
}

static int
do_parse_user(char const *path, struct userlist_user *usr)
{
  struct xml_attr *a;
  struct xml_tree *t, *saved_next;
  unsigned char **p_str;
  struct userlist_user_info *ui;

  xfree(usr->b.text); usr->b.text = 0;

  usr->id = -1;
  for (a = usr->b.first; a; a = a->next) {
    switch (a->tag) {
    case USERLIST_A_ID:
      if (xml_parse_int(NULL, path, a->line, a->column, a->text, &usr->id) < 0)
        return -1;
      if (usr->id <= 0)
        return xml_err_attr_invalid(a);
      break;
    case USERLIST_A_REGISTERED:
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                     &usr->registration_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_LOGIN:
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                     &usr->last_login_time) < 0) return -1;
      break;
    case USERLIST_A_CNTS_LAST_LOGIN:
      ui = userlist_get_cnts0(usr);
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                     &ui->last_login_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_ACCESS:
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                     &usr->last_access_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_CHANGE:
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                     &usr->last_change_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_INFO_CHANGE:
      ui = userlist_get_cnts0(usr);
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                     &ui->last_change_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_PWDCHANGE:
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                     &usr->last_pwdchange_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_INFO_PWDCHANGE:
      ui = userlist_get_cnts0(usr);
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                     &ui->last_pwdchange_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_MINOR_CHANGE:
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                     &usr->last_minor_change_time) < 0) return -1;
      break;
    case USERLIST_A_INFO_CREATE:
      ui = userlist_get_cnts0(usr);
      if (xml_parse_date(NULL, path, a->line, a->column, a->text,
                         &ui->create_time) < 0) return -1;
      break;
    case USERLIST_A_PRIVILEGED:
      if (xml_attr_bool(a, &usr->is_privileged) < 0) return -1;
      break;
    case USERLIST_A_INVISIBLE:
      if (xml_attr_bool(a, &usr->is_invisible) < 0) return -1;
      break;
    case USERLIST_A_BANNED:
      if (xml_attr_bool(a, &usr->is_banned) < 0) return -1;
      break;
    case USERLIST_A_LOCKED:
      if (xml_attr_bool(a, &usr->is_locked) < 0) return -1;
      break;
    case USERLIST_A_USE_COOKIES:
      // ignored for compatibility
      break;
    case USERLIST_A_READ_ONLY:
      if (xml_attr_bool(a, &usr->read_only) < 0) return -1;
      break;
    case USERLIST_A_CNTS_READ_ONLY:
      ui = userlist_get_cnts0(usr);
      if (xml_attr_bool(a, &ui->cnts_read_only) < 0) return -1;
      break;
    case USERLIST_A_NEVER_CLEAN:
      if (xml_attr_bool(a, &usr->never_clean) < 0) return -1;
      break;
    case USERLIST_A_SIMPLE_REGISTRATION:
      if (xml_attr_bool(a, &usr->simple_registration) < 0) return -1;
      break;
    default:
      return xml_err_attr_not_allowed(&usr->b, a);
    }
  }
  userlist_free_attrs(&usr->b);
  if (usr->id == -1)
    return xml_err_attr_undefined(&usr->b, USERLIST_A_ID);
  if (usr->cnts0) usr->cnts0->instnum = -1;

  for (t = usr->b.first_down; t; t = saved_next) {
    saved_next = t->right;

    if (leaf_info_offsets[t->tag] > 0) {
      ui = userlist_get_cnts0(usr);
      p_str = XPDEREF(unsigned char *, ui, leaf_info_offsets[t->tag]);
      if (xml_leaf_elem(t, p_str, 1, 1) < 0) return -1;
      xml_unlink_node(t);
      userlist_free(t);
      continue;
    }

    switch (t->tag) {
    case USERLIST_T_LOGIN:
      if (usr->login) return xml_err_elem_redefined(t);
      if (!t->text || !*t->text) return xml_err_elem_empty(t);
      if (t->first_down) return xml_err_nested_elems(t);
      for (a = t->first; a; a = a->next) {
        if (a->tag != USERLIST_A_PUBLIC)
          return xml_err_attr_not_allowed(t, a);
        if (xml_attr_bool(a, &usr->show_login) < 0) return -1;
      }
      usr->login = t->text; t->text = 0;
      xml_unlink_node(t);
      userlist_free(t);
      break;
    case USERLIST_T_PASSWORD:
      if (usr->passwd) return xml_err_elem_redefined(t);
      if (parse_passwd(t, &usr->passwd, &usr->passwd_method) < 0)
        return -1;
      break;
    case USERLIST_T_TEAM_PASSWORD:
      ui = userlist_get_cnts0(usr);
      if (ui->team_passwd) return xml_err_elem_redefined(t);
      if (parse_passwd(t, &ui->team_passwd, &ui->team_passwd_method) < 0)
        return -1;
      break;
    case USERLIST_T_EMAIL:
      if (usr->email) return xml_err_elem_redefined(t);
      if (t->first_down) return xml_err_nested_elems(t);
      for (a = t->first; a; a = a->next) {
        if (a->tag != USERLIST_A_PUBLIC)
          return xml_err_attr_not_allowed(t, a);
        if (xml_attr_bool(a, &usr->show_email) < 0) return -1;
      }
      usr->email = t->text; t->text = 0;
      if (!usr->email) usr->email = xstrdup("");
      xml_unlink_node(t);
      userlist_free(t);
      break;
    case USERLIST_T_COOKIES:
      if (usr->cookies) return xml_err_elem_redefined(t);
      usr->cookies = t;
      if (parse_cookies(path, t, usr) < 0) return -1;
      break;
    case USERLIST_T_EXTRA1:
      if (xml_leaf_elem(t, &usr->extra1, 1, 1) < 0) return -1;
      xml_unlink_node(t);
      userlist_free(t);
      break;
    case USERLIST_T_CONTESTS:
      if (parse_contest(path, t, usr) < 0) return -1;
      break;
    case USERLIST_T_CONTESTANTS:
    case USERLIST_T_RESERVES:
    case USERLIST_T_COACHES:
    case USERLIST_T_ADVISORS:
    case USERLIST_T_GUESTS:
      ui = userlist_get_cnts0(usr);
      if (parse_members(path, t, &usr->b, ui) < 0) return -1;
      break;
    case USERLIST_T_CNTSINFOS:
      if (parse_cntsinfos(path, t, usr) < 0) return -1;
      break;
    case USERLIST_T_INSTNUM:
      ui = userlist_get_cnts0(usr);
      if (xml_parse_int(NULL, path,t->line,t->column,t->text,&ui->instnum) < 0)
        return -1;
      if (ui->instnum < 0) return xml_err_elem_invalid(t);
      break;
    case USERLIST_T_MEMBERS:
      break;
    case USERLIST_T_CNTSINFO:
      break;
    default:
      return xml_err_elem_not_allowed(t);
    }
  }
  if (!usr->login)
    return xml_err_elem_undefined(&usr->b, USERLIST_T_LOGIN);
  /*
  if (!usr->passwd)
    return xml_err_elem_undefined(&usr->b, USERLIST_T_PASSWORD);
  */
  if (usr->cnts0 && !usr->cnts0->name)
    usr->cnts0->name = xstrdup("");
  return 0;
}

static int
do_parse_usergroups(
        const unsigned char *path,
        struct userlist_list *lst,
        struct xml_tree *groups)
{
  struct xml_tree *t;
  struct userlist_group *grp;
  int max_group_id = -1;
  int group_size = 16;

  if (!groups) return 0;
  lst->groups_node = groups;

  if (groups->first) return xml_err_attrs(groups);
  for (t = groups->first_down; t; t = t->right) {
    int group_id = -1;
    unsigned char *group_name = 0;
    unsigned char *description = 0;
    struct xml_attr *a;

    if (t->tag != USERLIST_T_USERGROUP) {
      return xml_err_elem_not_allowed(t);
    }
    if (t->first_down) {
      return xml_err_nested_elems(t);
    }
    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_GROUP_ID:
        if (xml_attr_int(a, &group_id) < 0) {
          xfree(group_name);
          xfree(description);
          return -1;
        }
        break;
      case USERLIST_A_GROUP_NAME:
        xfree(group_name);
        group_name = a->text;
        a->text = 0;
        break;
      case USERLIST_A_DESCRIPTION:
        xfree(description);
        description = a->text;
        a->text = 0;
        break;
      default:
        return xml_err_attr_not_allowed(t, a);
      }
    }

    grp = (struct userlist_group*) t;
    if (group_id == -1) {
      xfree(group_name);
      xfree(description);
      return xml_err_attr_undefined(t, USERLIST_A_GROUP_ID);
    }
    if (group_id <= 0 || group_id >= 1000000) {
      xfree(group_name);
      xfree(description);
      return xml_err_elem_invalid(t);
    }
    if (!group_name) {
      xfree(group_name);
      xfree(description);
      return xml_err_attr_undefined(t, USERLIST_A_GROUP_ID);
    }
    grp->group_id = group_id;
    grp->group_name = group_name; group_name = 0;
    grp->description = description; description = 0;
    if (group_id > max_group_id) max_group_id = group_id;
  }

  // no groups
  if (max_group_id <= 0) return 0;

  /* collect groups, check unuqieness of group_id */
  while (group_size <= max_group_id) group_size *= 2;
  lst->group_map_size = group_size;
  XCALLOC(lst->group_map, group_size);
  for (t = groups->first_down; t; t = t->right) {
    grp = (struct userlist_group*) t;
    ASSERT(grp->group_id > 0 && grp->group_id < group_size);
    if (lst->group_map[grp->group_id]) {
      xml_err(t, "duplicated group_id %d", grp->group_id);
      return -1;
    }
    lst->group_map[grp->group_id] = grp;
  }

  return 0;
}

static int
do_parse_usergroupmembers(
        const unsigned char *path,
        struct userlist_list *lst,
        struct xml_tree *groupmembers)
{
  struct xml_tree *t;
  struct userlist_groupmember *gm;
  struct xml_attr *a;

  if (!groupmembers) return 0;
  lst->groupmembers_node = groupmembers;

  if (groupmembers->first) return xml_err_attrs(groupmembers);
  for (t = groupmembers->first_down; t; t = t->right) {
    int group_id = -1;
    int user_id = -1;

    if (t->tag != USERLIST_T_USERGROUPMEMBER) {
      return xml_err_elem_not_allowed(t);
    }
    if (t->first_down) {
      return xml_err_nested_elems(t);
    }
    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_GROUP_ID:
        if (xml_attr_int(a, &group_id) < 0) return -1;
        break;
      case USERLIST_A_USER_ID:
        if (xml_attr_int(a, &user_id) < 0) return -1;
        break;
      default:
        return xml_err_attr_not_allowed(t, a);
      }
    }

    gm = (struct userlist_groupmember*) t;
    if (group_id == -1) {
      return xml_err_attr_undefined(t, USERLIST_A_GROUP_ID);
    }
    if (group_id <= 0 || group_id > 1000000) {
      return xml_err_elem_invalid(t);
    }
    if (user_id == -1) {
      return xml_err_attr_undefined(t, USERLIST_A_USER_ID);
    }
    if (user_id <= 0) {
      return xml_err_elem_invalid(t);
    }
    gm->group_id = group_id;
    gm->user_id = user_id;
  }

  return 0;
}

static void
collect_usergroups(struct userlist_list *lst)
{
  struct xml_tree *t;
  struct userlist_groupmember *gm;
  struct userlist_group *g;
  struct userlist_user *u;

  if (!lst->groupmembers_node) return;
  for (t = lst->groupmembers_node->first_down; t; t = t->right) {
    gm = (struct userlist_groupmember*) t;

    if (gm->group_id <= 0 || gm->group_id >= lst->group_map_size
        || !(g = lst->group_map[gm->group_id]))
      continue;
    if (gm->user_id <= 0 || gm->user_id >= lst->user_map_size
        || !(u = lst->user_map[gm->user_id]))
      continue;

    /* append to the list of users belonging to the same group */
    gm->user_next = 0;
    gm->user_prev = g->user_last;
    g->user_last = t;
    if (g->user_first) {
      ((struct userlist_groupmember*) gm->user_prev)->user_next = t;
    } else {
      g->user_first = t;
    }
    /* append to the list of groups containing the same user */
    gm->group_next = 0;
    gm->group_prev = u->group_last;
    u->group_last = t;
    if (u->group_first) {
      ((struct userlist_groupmember*) gm->group_prev)->group_next = t;
    } else {
      u->group_first = t;
    }
  }
}

static int
do_parse_userlist(char const *path, struct userlist_list *lst)
{
  struct xml_attr *a;
  struct xml_tree *t;
  struct userlist_user *u;
  int map_size;

  for (a = lst->b.first; a; a = a->next) {
    switch (a->tag) {
    case USERLIST_A_NAME:
      xfree(lst->name);
      lst->name = a->text; a->text = 0;
      break;
    case USERLIST_A_MEMBER_SERIAL:
      {
        int x = 0, n = 0;

        if (!a->text || sscanf(a->text, "%d %n", &x, &n) != 1 || a->text[n]
            || x < 0)
          return xml_err_attr_invalid(a);
        lst->member_serial = x;
      }
      break;
    default:
      return xml_err_attr_not_allowed(&lst->b, a);
    }
  }
  xfree(lst->b.text); lst->b.text = 0;
  if (!lst->member_serial) lst->member_serial = 1;
  userlist_free_attrs(&lst->b);

  for (t = lst->b.first_down; t; t = t->right) {
    if (t->tag == USERLIST_T_USERGROUPS) {
      if (do_parse_usergroups(path, lst, t) < 0)
        return -1;
    } else if (t->tag == USERLIST_T_USERGROUPMEMBERS) {
      if (do_parse_usergroupmembers(path, lst, t) < 0)
        return -1;
    } else if (t->tag == USERLIST_T_USER) {
      if (do_parse_user(path, (struct userlist_user*) t) < 0) return -1;
    } else {
      return xml_err_elem_not_allowed(t);
    }
  }

  map_size = 16;
  for (u = (struct userlist_user*) lst->b.first_down; u;
       u = (struct userlist_user*) u->b.right) {
    if (u->b.tag == USERLIST_T_USER) {
      ASSERT(u->id > 0);
      while (u->id >= map_size)
        map_size *= 2;
    }
  }
  lst->user_map_size = map_size;
  lst->user_map = (struct userlist_user**) xcalloc(map_size, sizeof(lst->user_map[0]));
  for (u = (struct userlist_user*) lst->b.first_down; u;
       u = (struct userlist_user*) u->b.right) {
    if (u->b.tag == USERLIST_T_USER) {
      if (lst->user_map[u->id]) {
        xml_err(&u->b, "duplicated user id %d", u->id);
        return -1;
      }
      lst->user_map[u->id] = u;
    }
  }
  collect_usergroups(lst);

  return 0;
}

struct userlist_user *
userlist_parse_user_str(char const *str)
{
  struct xml_tree *tree = 0;
  struct userlist_user *user = 0;

  xml_err_path = 0;
  xml_err_spec = &userlist_parse_spec;

  tree = xml_build_tree_str(NULL, str, &userlist_parse_spec);
  if (!tree) goto failed;
  if (tree->tag != USERLIST_T_USER) {
    xml_err_top_level(tree, USERLIST_T_USER);
    goto failed;
  }
  user = (struct userlist_user*) tree;
  if (do_parse_user("", user) < 0) goto failed;
  return user;

 failed:
  if (tree) xml_tree_free(tree, &userlist_parse_spec);
  return 0;
}

struct xml_tree *
userlist_parse_contests_str(unsigned char const *str)
{
  struct xml_tree *tree = 0;

  xml_err_path = 0;
  xml_err_spec = &userlist_parse_spec;

  tree = xml_build_tree_str(NULL, str, &userlist_parse_spec);
  if (!tree) return 0;
  if (tree->tag != USERLIST_T_CONTESTS) {
    xml_err_top_level(tree, USERLIST_T_CONTESTS);
    xml_tree_free(tree, &userlist_parse_spec);
    return 0;
  }
  if (parse_contest("", tree, 0) < 0) {
    xml_tree_free(tree, &userlist_parse_spec);
    return 0;
  }
  return tree;
}

struct userlist_list *
userlist_parse(char const *path)
{
  struct xml_tree *tree = 0;
  struct userlist_list *lst = 0;

  xml_err_path = path;
  xml_err_spec = &userlist_parse_spec;

  tree = xml_build_tree(NULL, path, &userlist_parse_spec);
  if (!tree) goto failed;
  if (tree->tag != USERLIST_T_USERLIST) {
    xml_err_top_level(tree, USERLIST_T_USERLIST);
    goto failed;
  }
  lst = (struct userlist_list *) tree;
  if (do_parse_userlist(path, lst) < 0) goto failed;
  return lst;

 failed:
  if (tree) xml_tree_free(tree, &userlist_parse_spec);
  return 0;
}

struct userlist_list *
userlist_parse_str(unsigned char const *str)
{
  struct xml_tree *tree = 0;
  struct userlist_list *lst = 0;

  xml_err_path = 0;
  xml_err_spec = &userlist_parse_spec;

  tree = xml_build_tree_str(NULL, str, &userlist_parse_spec);
  if (!tree) goto failed;
  if (tree->tag != USERLIST_T_USERLIST) {
    xml_err_top_level(tree, USERLIST_T_USERLIST);
    goto failed;
  }
  lst = (struct userlist_list *) tree;
  if (do_parse_userlist("", lst) < 0) goto failed;
  return lst;

 failed:
  if (tree) xml_tree_free(tree, &userlist_parse_spec);
  return 0;
}

void *
userlist_free(struct xml_tree *p)
{
  if (p) xml_tree_free(p, &userlist_parse_spec);
  return 0;
}

static unsigned char const *
unparse_passwd_method(int m)
{
  static char const * const pwd_method_map[] =
  {
    "plain", "base64", "sha1"
  };
  ASSERT(m >= USERLIST_PWD_PLAIN && m <= USERLIST_PWD_SHA1);
  return pwd_method_map[m];
}
static unsigned char const *
unparse_reg_status(int s)
{
  static char const * const reg_status_map[] =
  {
    "ok", "pending", "rejected"
  };
  ASSERT(s >= USERLIST_REG_OK && s <= USERLIST_REG_REJECTED);
  return reg_status_map[s];
}
unsigned char const *
userlist_unparse_reg_status(int s)
{
  return unparse_reg_status(s);
}
static unsigned char const *
unparse_member_status(int s)
{
  static char const * const member_status_map[] =
  {
    0, "schoolchild", "student", "magistrant",
    "phdstudent", "teacher", "professor", "scientist", "other"
  };
  ASSERT(s >= USERLIST_ST_SCHOOL && s <= USERLIST_ST_OTHER);
  return member_status_map[s];
}
static unsigned char const *
unparse_member_gender(int gender)
{
  static char const * const member_gender_map[] =
  {
    0, "male", "female",
  };
  ASSERT(gender>= 0 && gender <= 2);
  return member_gender_map[gender];
}

static void
unparse_bool_attr(FILE *f, int attr, int val)
{
  if (val) {
    fprintf(f, " %s=\"%s\"", attr_map[attr], xml_unparse_bool(val));
  }
}

static void
unparse_date_attr(FILE *f, int attr, time_t val)
{
  if (val > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[attr], xml_unparse_date(val));
  }
}

static void
unparse_attributed_elem(FILE *f, int t, unsigned char const *val,
                        const unsigned char *attr_str,
                        unsigned char const *ind)
{
  size_t alen = 0;
  unsigned char *astr;

  if (!val) return;
  if (html_armor_needed(val, &alen)) {
    astr = alloca(alen + 2);
    html_armor_string(val, astr);
    val = astr;
  }
  fprintf(f, "%s<%s%s>%s</%s>\n", ind, elem_map[t], attr_str, val, elem_map[t]);
}

static void
unparse_member(const struct userlist_member *p, FILE *f)
{
  unsigned char const *ind = "        ";
  int i;
  unsigned char **p_str;
  time_t *p_time;
  unsigned char dbuf[64];

  if (!p) return;
  ASSERT(p->b.tag == USERLIST_T_MEMBER);
  fprintf(f, "      <%s %s=\"%d\"", elem_map[USERLIST_T_MEMBER],
          attr_map[USERLIST_A_SERIAL], p->serial);
  if (p->copied_from > 0)
    fprintf(f, " %s=\"%d\"", attr_map[USERLIST_A_COPIED_FROM], p->copied_from);
  if (p->create_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_CREATE],
            xml_unparse_date(p->create_time));
  }
  if (p->last_change_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_LAST_CHANGE],
            xml_unparse_date(p->last_change_time));
  }
  if (p->last_access_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_LAST_ACCESS],
            xml_unparse_date(p->last_access_time));
  }
  fprintf(f, ">\n");

  for (i = 1; i < USERLIST_LAST_TAG; i++) {
    if (leaf_member_offsets[i] > 0) {
      p_str = XPDEREF(unsigned char *, p, leaf_member_offsets[i]);
      xml_unparse_text(f, elem_map[i], *p_str, ind);
    }
  }

  for (i = 1; i < USERLIST_LAST_TAG; i++) {
    if (date_member_offsets[i] > 0) {
      p_time = XPDEREF(time_t, p, date_member_offsets[i]);
      if (*p_time > 0) {
        fprintf(f, "%s<%s>%s</%s>\n",
                ind, elem_map[i],
                userlist_unparse_date_2(dbuf, sizeof(dbuf), *p_time, 0),
                elem_map[i]);
      }
    }
  }

  if (p->status) {
    xml_unparse_text(f, elem_map[USERLIST_T_STATUS],
                     unparse_member_status(p->status),
                     ind);
  }
  if (p->gender) {
    xml_unparse_text(f, elem_map[USERLIST_T_GENDER],
                     unparse_member_gender(p->gender),
                     ind);
  }
  if (p->grade >= 0) {
    fprintf(f, "        <%s>%d</%s>\n",
            elem_map[USERLIST_T_GRADE], p->grade, elem_map[USERLIST_T_GRADE]);
  }
  fprintf(f, "      </%s>\n", elem_map[USERLIST_T_MEMBER]);
}

static void
unparse_members(const struct userlist_members *p, FILE *f)
{
  int i, j, cnt;
  struct userlist_member *m;

  if (!p) return;
  for (i = 0; i < USERLIST_MB_LAST; i++) {
    cnt = 0;
    for (j = 0; j < p->u; ++j) {
      if (!(m = p->m[j])) continue;
      if (m->team_role != i) continue;
      if (!cnt) fprintf(f, "    <%s>\n", elem_map[USERLIST_T_CONTESTANTS + i]);
      cnt++;
      unparse_member(p->m[j], f);
    }
    if (cnt > 0) fprintf(f,"    </%s>\n", elem_map[USERLIST_T_CONTESTANTS + i]);
  }
}
static void
unparse_cookies(const struct xml_tree *p, FILE *f)
{
  struct userlist_cookie *c;
  unsigned char buf[64];

  if (!p) return;
  ASSERT(p->tag == USERLIST_T_COOKIES);
  fprintf(f, "    <%s>\n", elem_map[USERLIST_T_COOKIES]);
  for (p = p->first_down; p; p = p->right) {
    ASSERT(p->tag == USERLIST_T_COOKIE);
    c = (struct userlist_cookie*) p;
    fprintf(f, "      <%s %s=\"%s\" %s=\"%s\" %s=\"%s\" %s=\"%s\"",
            elem_map[USERLIST_T_COOKIE],
            attr_map[USERLIST_A_IP], xml_unparse_ipv6(&c->ip),
            attr_map[USERLIST_A_VALUE], xml_unparse_full_cookie(buf, sizeof(buf), &c->cookie, &c->client_key),
            attr_map[USERLIST_A_EXPIRE], xml_unparse_date(c->expire),
            attr_map[USERLIST_A_PRIV_LEVEL],
            protocol_priv_level_str(c->priv_level));
    if (c->ssl > 0) {
      fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_SSL],
              xml_unparse_bool(c->ssl));
    }
    if (c->recovery > 0) {
      fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_RECOVERY],
              xml_unparse_bool(c->recovery));
    }
    if (c->team_login > 0) {
      fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_TEAM_LOGIN],
              xml_unparse_bool(c->team_login));
    }
    if (c->locale_id >= 0) {
      fprintf(f, " %s=\"%d\"", attr_map[USERLIST_A_LOCALE_ID], c->locale_id);
    }
    if (c->contest_id > 0) {
      fprintf(f, " %s=\"%d\"", attr_map[USERLIST_A_CONTEST_ID], c->contest_id);
    }
    if (c->role > 0) {
      fprintf(f, " %s=\"%d\"", attr_map[USERLIST_A_ROLE], c->role);
    }
    fputs("/>\n", f);
  }
  fprintf(f, "    </%s>\n", elem_map[USERLIST_T_COOKIES]);
}
void
userlist_unparse_contest(const struct userlist_contest *cc, FILE *f,
                         unsigned char const *indent)
{
  if (!cc) return;
  fprintf(f, "%s<%s %s=\"%d\" %s=\"%s\"",
          indent, elem_map[USERLIST_T_CONTEST],
          attr_map[USERLIST_A_ID], cc->id,
          attr_map[USERLIST_A_STATUS], unparse_reg_status(cc->status));
  if ((cc->flags & USERLIST_UC_BANNED)) {
    fprintf(f, " %s=\"yes\"", attr_map[USERLIST_A_BANNED]);
  }
  if ((cc->flags & USERLIST_UC_INVISIBLE)) {
    fprintf(f, " %s=\"yes\"", attr_map[USERLIST_A_INVISIBLE]);
  }
  if ((cc->flags & USERLIST_UC_LOCKED)) {
    fprintf(f, " %s=\"yes\"", attr_map[USERLIST_A_LOCKED]);
  }
  if ((cc->flags & USERLIST_UC_INCOMPLETE)) {
    fprintf(f, " %s=\"yes\"", attr_map[USERLIST_A_INCOMPLETE]);
  }
  if ((cc->flags & USERLIST_UC_DISQUALIFIED)) {
    fprintf(f, " %s=\"yes\"", attr_map[USERLIST_A_DISQUALIFIED]);
  }
  if (cc->create_time) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_DATE],
            xml_unparse_date(cc->create_time));
  }
  fprintf(f, "/>\n");
}
static void
unparse_contests(const struct xml_tree *p, FILE *f, int mode, int contest_id)
{
  if (!p) return;
  ASSERT(p->tag == USERLIST_T_CONTESTS);
  fprintf(f, "    <%s>\n", elem_map[USERLIST_T_CONTESTS]);
  for (p = p->first_down; p; p = p->right) {
    ASSERT(p->tag == USERLIST_T_CONTEST);
    if (mode == USERLIST_MODE_STAND && contest_id > 0
        && ((struct userlist_contest*) p)->id != contest_id)
      continue;
    userlist_unparse_contest((struct userlist_contest*) p, f, "      ");
  }
  fprintf(f, "    </%s>\n", elem_map[USERLIST_T_CONTESTS]);
}

static void
unparse_cntsinfo(const struct userlist_user_info *p, FILE *f)
{
  unsigned char attr_str[256];
  const unsigned char *sp1 = "      ";
  int i;
  unsigned char **p_str;

  if (!p) return;
  fprintf(f, "    <%s %s=\"%d\"",
          elem_map[USERLIST_T_CNTSINFO], attr_map[USERLIST_A_CONTEST_ID],
          p->contest_id);
  if (p->cnts_read_only) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_CNTS_READ_ONLY],
            xml_unparse_bool(p->cnts_read_only));
  }
  if (p->create_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_INFO_CREATE],
            xml_unparse_date(p->create_time));
  }
  if (p->last_login_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_CNTS_LAST_LOGIN],
            xml_unparse_date(p->last_login_time));
  }
  if (p->last_change_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_LAST_INFO_CHANGE],
            xml_unparse_date(p->last_change_time));
  }
  if (p->last_access_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_LAST_ACCESS],
            xml_unparse_date(p->last_access_time));
  }
  if (p->last_pwdchange_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_LAST_INFO_PWDCHANGE],
            xml_unparse_date(p->last_pwdchange_time));
  }
  fprintf(f, ">\n");

  if (p->instnum >= 0) {
    fprintf(f, "%s<%s>%d</%s>\n", sp1, elem_map[USERLIST_T_INSTNUM],
            p->instnum, elem_map[USERLIST_T_INSTNUM]);
  }

  for (i = 1; i < USERLIST_LAST_TAG; i++) {
    if (leaf_info_offsets[i] > 0) {
      p_str = XPDEREF(unsigned char *, p, leaf_info_offsets[i]);
      xml_unparse_text(f, elem_map[i], *p_str, sp1);
    }
  }

  if (p->team_passwd) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attr_map[USERLIST_A_METHOD],
             unparse_passwd_method(p->team_passwd_method));
    unparse_attributed_elem(f, USERLIST_T_TEAM_PASSWORD,
                            p->team_passwd, attr_str, sp1);
  }

  unparse_members(p->members, f);

  fprintf(f, "    </%s>\n", elem_map[USERLIST_T_CNTSINFO]);
}

static void
xml_unparse_text_attr(
        FILE *fout,
        const unsigned char *attr_name,
        const unsigned char *value)
{
  size_t alen = 0;
  unsigned char *astr = 0;

  if (!value) return;

  if (html_armor_needed(value, &alen)) {
    astr = alloca(alen + 2);
    html_armor_string(value, astr);
    value = astr;
  }
  fprintf(fout, " %s=\"%s\"", attr_name, value);
}

void
userlist_unparse_usergroup(
        FILE *fout,
        const struct userlist_group *grp,
        const unsigned char *prefix,
        const unsigned char *suffix)
{
  fprintf(fout, "%s<%s %s=\"%d\"", prefix,
          elem_map[USERLIST_T_USERGROUP],
          attr_map[USERLIST_A_GROUP_ID],
          grp->group_id);
  xml_unparse_text_attr(fout, attr_map[USERLIST_A_GROUP_NAME],
                        grp->group_name);
  xml_unparse_text_attr(fout, attr_map[USERLIST_A_DESCRIPTION],
                        grp->description);
  fprintf(fout, " />%s", suffix);
}

static void
unparse_usergroups(
        FILE *fout,
        const struct userlist_list *lst)
{
  int cnt = 0, i;
  const struct userlist_group *grp;

  if (lst->group_map_size <= 0) return;

  for (i = 1; i < lst->group_map_size; ++i) {
    cnt += (lst->group_map[i] != 0);
  }
  if (cnt <= 0) return;

  fprintf(fout, "  <%s>\n", elem_map[USERLIST_T_USERGROUPS]);
  for (i = 1; i < lst->group_map_size; ++i) {
    if ((grp = lst->group_map[i])) {
      userlist_unparse_usergroup(fout, grp, "      ", "\n");
    }
  }  
  fprintf(fout, "  </%s>\n", elem_map[USERLIST_T_USERGROUPS]);
}

void
userlist_unparse_usergroupmember(
        FILE *fout,
        const struct userlist_groupmember *gm,
        const unsigned char *prefix,
        const unsigned char *suffix)
{
  fprintf(fout, "%s<%s %s=\"%d\" %s=\"%d\" />%s", prefix,
          elem_map[USERLIST_T_USERGROUPMEMBER],
          attr_map[USERLIST_A_GROUP_ID], gm->group_id,
          attr_map[USERLIST_A_USER_ID], gm->user_id,
          suffix);
}

static void
unparse_usergroupmembers(
        FILE *fout,
        const struct userlist_list *lst)
{
  const struct xml_tree *p;
  const struct userlist_groupmember *gm;

  if (!lst->groupmembers_node) return;
  if (!lst->groupmembers_node->first_down) return;

  fprintf(fout, "  <%s>\n", elem_map[USERLIST_T_USERGROUPMEMBERS]);
  for (p = lst->groupmembers_node->first_down; p; p = p->right) {
    gm = (const struct userlist_groupmember*) p;
    if (gm->user_id <= 0 || gm->user_id >= lst->user_map_size
        || !lst->user_map[gm->user_id])
      continue;
    if (gm->group_id <= 0 || gm->group_id >= lst->group_map_size
        || !lst->group_map[gm->group_id])
      continue;
    userlist_unparse_usergroupmember(fout, gm, "      ", "\n");
  }
  fprintf(fout, "  </%s>\n", elem_map[USERLIST_T_USERGROUPMEMBERS]);
}

/* called from `userlist_unparse_short' */
void
userlist_unparse_user_short(const struct userlist_user *p, FILE *f,
                            int contest_id)
{
  const struct userlist_contest *uc = 0;
  const struct userlist_user_info *ui;

  if (!p) return;

  if (p->cntsinfo && contest_id > 0 && contest_id < p->cntsinfo_a
      && p->cntsinfo[contest_id]) {
    ui = p->cntsinfo[contest_id];
  } else {
    ui = p->cnts0;
  }

  if (contest_id) {
    if (!p->contests) return;
    for (uc = (struct userlist_contest*) p->contests->first_down;
         uc; uc = (struct userlist_contest*) uc->b.right) {
      if (uc->id == contest_id) break;
    }
    if (!uc) return;
  }
  fprintf(f, "  <%s %s=\"%d\"", elem_map[USERLIST_T_USER],
          attr_map[USERLIST_A_ID], p->id);
  if (ui && ui->last_login_time > 0) {
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_CNTS_LAST_LOGIN],
            xml_unparse_date(ui->last_login_time));
  }
  fprintf(f, ">");
  xml_unparse_text(f, elem_map[USERLIST_T_LOGIN], p->login, "    ");
  if (ui && ui->name && *ui->name) {
    xml_unparse_text(f, elem_map[USERLIST_T_NAME], ui->name, "    ");
  }
  xml_unparse_text(f, elem_map[USERLIST_T_EMAIL], p->email, "    ");
  if (uc) {
    fprintf(f, "    <%s>\n", elem_map[USERLIST_T_CONTESTS]);
    userlist_unparse_contest(uc, f, "      ");
    fprintf(f, "    </%s>\n", elem_map[USERLIST_T_CONTESTS]);
  }
  fprintf(f, "  </%s>\n", elem_map[USERLIST_T_USER]);
}

/* called from `userlist_unparse_user', `userlist_unparse',
   `userlist_unparse_for_standings'
 modes: USERLIST_MODE_USER, USERLIST_MODE_ALL, USERLIST_MODE_STAND
 contest_id == -1 - print all the information
 contest_id == 0  - print the default information
 contest_id >0    - print the specific information (if exist),
                    or print the default information
*/
void
userlist_real_unparse_user(
        const struct userlist_user *p,
        FILE *f,
        int mode,
        int contest_id,
        int flags)
{
  unsigned char attr_str[128];
  int i, cnt;
  const struct userlist_user_info *ui;
  const struct userlist_member *m;
  unsigned char **p_str;

  if (!p) return;

  if (contest_id > 0 && p->cntsinfo && contest_id < p->cntsinfo_a
      && p->cntsinfo[contest_id]) {
    ui = p->cntsinfo[contest_id];
  } else {
    ui = p->cnts0;
  }

  fprintf(f, "  <%s %s=\"%d\"", elem_map[USERLIST_T_USER],
          attr_map[USERLIST_A_ID], p->id);
  unparse_bool_attr(f, USERLIST_A_PRIVILEGED, p->is_privileged);
  if (mode == USERLIST_MODE_ALL) {
    unparse_bool_attr(f, USERLIST_A_INVISIBLE, p->is_invisible);
    unparse_bool_attr(f, USERLIST_A_BANNED, p->is_banned);
    unparse_bool_attr(f, USERLIST_A_LOCKED, p->is_locked);
  }
  if (mode != USERLIST_MODE_STAND) {
    unparse_bool_attr(f, USERLIST_A_READ_ONLY, p->read_only);
    unparse_bool_attr(f, USERLIST_A_NEVER_CLEAN, p->never_clean);
    unparse_bool_attr(f, USERLIST_A_SIMPLE_REGISTRATION,p->simple_registration);

    /* cnts_read_only is contest-specific */
  }
  if (ui) unparse_bool_attr(f, USERLIST_A_CNTS_READ_ONLY, ui->cnts_read_only);
  if (mode == USERLIST_MODE_ALL) {
    unparse_date_attr(f, USERLIST_A_REGISTERED, p->registration_time);
    unparse_date_attr(f, USERLIST_A_LAST_LOGIN, p->last_login_time);
    unparse_date_attr(f, USERLIST_A_LAST_MINOR_CHANGE,
                      p->last_minor_change_time);
    unparse_date_attr(f, USERLIST_A_LAST_CHANGE, p->last_change_time);
    unparse_date_attr(f, USERLIST_A_LAST_PWDCHANGE, p->last_pwdchange_time);

    if (ui) {
    /* last_access_time is contest-specific */
      unparse_date_attr(f, USERLIST_A_LAST_ACCESS, ui->last_access_time);
    /* last_change_time is contest-specific */
      unparse_date_attr(f, USERLIST_A_INFO_CREATE, ui->create_time);
      unparse_date_attr(f, USERLIST_A_LAST_INFO_CHANGE, ui->last_change_time);
    /* last_pwdchange_time is contest-specific */
      unparse_date_attr(f, USERLIST_A_LAST_INFO_PWDCHANGE, ui->last_pwdchange_time);
    }
  }
  if (mode == USERLIST_MODE_ALL || mode == USERLIST_MODE_STAND) {
    if (ui) {
      unparse_date_attr(f, USERLIST_A_CNTS_LAST_LOGIN, ui->last_login_time);
    }
  }
  fputs(">\n", f);

  if (p->login) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attr_map[USERLIST_A_PUBLIC], xml_unparse_bool(p->show_login));
    unparse_attributed_elem(f, USERLIST_T_LOGIN, p->login, attr_str, "    ");
  }
  if (p->passwd && (flags & USERLIST_SHOW_REG_PASSWD)
      && (mode == USERLIST_MODE_ALL || mode == USERLIST_MODE_STAND)) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attr_map[USERLIST_A_METHOD],
             unparse_passwd_method(p->passwd_method));
    unparse_attributed_elem(f, USERLIST_T_PASSWORD, p->passwd,attr_str, "    ");
  }
  if (ui && ui->team_passwd && (flags & USERLIST_SHOW_CNTS_PASSWD)
      && (mode == USERLIST_MODE_ALL || mode == USERLIST_MODE_STAND)) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attr_map[USERLIST_A_METHOD],
             unparse_passwd_method(ui->team_passwd_method));
    unparse_attributed_elem(f, USERLIST_T_TEAM_PASSWORD,
                            ui->team_passwd, attr_str, "    ");
  }
  if (ui && ui->name && *ui->name) {
    xml_unparse_text(f, elem_map[USERLIST_T_NAME], ui->name, "    ");
  }
  if (p->email) { // && mode != USERLIST_MODE_STAND) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attr_map[USERLIST_A_PUBLIC], xml_unparse_bool(p->show_email));
    unparse_attributed_elem(f, USERLIST_T_EMAIL, p->email, attr_str, "    ");
  }
  if (mode == USERLIST_MODE_ALL) {
    unparse_cookies(p->cookies, f);
  }
  unparse_contests(p->contests, f, USERLIST_MODE_STAND, contest_id);

  if (ui && ui->instnum >= 0) {
    fprintf(f, "    <%s>%d</%s>\n", elem_map[USERLIST_T_INSTNUM],
            ui->instnum, elem_map[USERLIST_T_INSTNUM]);
  }

  if (ui) {
    for (i = 1; i < USERLIST_LAST_TAG; i++) {
      if (i != USERLIST_T_NAME && leaf_info_offsets[i] > 0) {
        p_str = XPDEREF(unsigned char *, ui, leaf_info_offsets[i]);
        xml_unparse_text(f, elem_map[i], *p_str, "    ");
      }
    }
  }

  /*
  if (mode == USERLIST_MODE_STAND) {
    // generate some information about the first participant
    const struct userlist_members **pmemb = (const struct userlist_members **) ui->members;

    if (pmemb && pmemb[USERLIST_MB_CONTESTANT]
        && pmemb[USERLIST_MB_CONTESTANT]->total > 0
        && pmemb[USERLIST_MB_CONTESTANT]->members
        && pmemb[USERLIST_MB_CONTESTANT]->members[0]
        && pmemb[USERLIST_MB_CONTESTANT]->members[0]->grade > 0) {
      fprintf(f, "    <%s>%d</%s>\n",
              elem_map[USERLIST_T_EXTRA1],
              pmemb[USERLIST_MB_CONTESTANT]->members[0]->grade,
              elem_map[USERLIST_T_EXTRA1]);
    }
  }
  */

  if (ui) {
    if (mode == USERLIST_MODE_STAND && (flags & USERLIST_FORCE_FIRST_MEMBER)
        && (m = userlist_members_get_first(ui->members))) {
      fprintf(f, "    <%s>\n", elem_map[USERLIST_T_CONTESTANTS]);
      unparse_member(m, f);
      fprintf(f, "    </%s>\n", elem_map[USERLIST_T_CONTESTANTS]);
    }

    if (mode != USERLIST_MODE_STAND) {
      unparse_members(ui->members, f);
    }
  }

  if (contest_id < 0 && p->cntsinfo) {
    for (cnt = 0, i = 0; i < p->cntsinfo_a; i++)
      if (p->cntsinfo[i])
        cnt++;
    fprintf(f, "    <%s>\n", elem_map[USERLIST_T_CNTSINFOS]);
    for (i = 0; i < p->cntsinfo_a; i++)
      unparse_cntsinfo(p->cntsinfo[i], f);
    fprintf(f, "    </%s>\n", elem_map[USERLIST_T_CNTSINFOS]);
  }

  fprintf(f, "  </%s>\n", elem_map[USERLIST_T_USER]);
}

/*
 * called from userlist-server.c:cmd_get_user_info, when generating
 *   user info for `register' program
 *     userlist_unparse_user(user, f, USERLIST_MODE_USER);
 * called from userlist-server.c:cmd_priv_get_user_info, when generating
 *   user info for `edit-userlist' program
 *     userlist_unparse_user(user, f, USERLIST_MODE_ALL);
 */
void
userlist_unparse_user(
        const struct userlist_user *p,
        FILE *f,
        int mode,
        int contest_id,
        int flags)
{
  if (!p) return;

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n",
          EJUDGE_CHARSET);
  userlist_real_unparse_user(p, f, mode, contest_id, flags);
}

/*
 * called from userlist-server.c:cmd_get_user_contests, when generating
 *   the list of available contests for `register' program
 *     userlist_unparse_contests(user, f);
 */
void
userlist_unparse_contests(struct userlist_user *p, FILE *f)
{
  if (!p) return;
  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n",
          EJUDGE_CHARSET);
  if (!p->contests) {
    fprintf(f, "<%s></%s>\n", elem_map[USERLIST_T_CONTESTS],
            elem_map[USERLIST_T_CONTESTS]);
  } else {
    unparse_contests(p->contests, f, 0, 0);
  }
}

void
userlist_write_contests_xml_header(FILE *f)
{
  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", EJUDGE_CHARSET);
  fprintf(f, "<%s>\n", elem_map[USERLIST_T_CONTESTS]);
}

void
userlist_write_contests_xml_footer(FILE *f)
{
  fprintf(f, "</%s>\n", elem_map[USERLIST_T_CONTESTS]);
}


void
userlist_write_groups_header(FILE *f)
{
  fprintf(f, "  <%s>\n", elem_map[USERLIST_T_USERGROUPS]);
}

void
userlist_write_groups_footer(FILE *f)
{
  fprintf(f, "  </%s>\n", elem_map[USERLIST_T_USERGROUPS]);
}

void
userlist_write_groupmembers_header(FILE *f)
{
  fprintf(f, "  <%s>\n", elem_map[USERLIST_T_USERGROUPMEMBERS]);
}

void
userlist_write_groupmembers_footer(FILE *f)
{
  fprintf(f, "  </%s>\n", elem_map[USERLIST_T_USERGROUPMEMBERS]);
}

/*
 * do full dump of the database
 * called from userlist-server.c:do_backup
 * called from userlist-server.c:flush_database
 *   for complete userlist generation
 *     userlist_unparse(userlist, f);
 * called from slice-userlist.c:main
 *   for userlist generation after XML tree processing
 */
void
userlist_unparse(struct userlist_list *p, FILE *f)
{
  int i;

  if (!p) return;

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n", 
          EJUDGE_CHARSET);
  fprintf(f, "<%s %s=\"%d\"", elem_map[USERLIST_T_USERLIST],
          attr_map[USERLIST_A_MEMBER_SERIAL], p->member_serial);
  
  if (p->name && *p->name)
    fprintf(f, " %s=\"%s\"", attr_map[USERLIST_A_NAME], p->name);
  fputs(">\n", f);
  for (i = 1; i < p->user_map_size; i++)
    userlist_real_unparse_user(p->user_map[i], f, 0, -1, USERLIST_SHOW_REG_PASSWD | USERLIST_SHOW_CNTS_PASSWD);

  unparse_usergroups(f, p);
  unparse_usergroupmembers(f, p);
  fprintf(f, "</%s>\n", elem_map[USERLIST_T_USERLIST]);
}

/*
 * called from userlist-server.c:cmd_list_all_users, when generating
 *   the list of all registered users or all contest users
 *   for `edit-userlist' program, also the list of all registered
 *   users is used in `super-serve' program for editing the variant map
 *   of the contest
 *     userlist_unparse_short(userlist, f, data->contest_id);
 */
void
userlist_unparse_short(struct userlist_list *p, FILE *f, int contest_id)
{
  int i;

  if (!p) return;

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n",
          EJUDGE_CHARSET);
  fprintf(f, "<%s>", elem_map[USERLIST_T_USERLIST]);
  for (i = 1; i < p->user_map_size; i++)
    userlist_unparse_user_short(p->user_map[i], f, contest_id);
  fprintf(f, "</%s>\n", elem_map[USERLIST_T_USERLIST]);
}

void
userlist_write_xml_header(FILE *f)
{
  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n",
          EJUDGE_CHARSET);
  fprintf(f, "<%s>", elem_map[USERLIST_T_USERLIST]);
}

void
userlist_write_xml_footer(FILE *f)
{
  fprintf(f, "</%s>\n", elem_map[USERLIST_T_USERLIST]);
}

/*
 * currently unused
 */
void
userlist_unparse_for_standings(
        struct userlist_list *p,
        FILE *f,
        int contest_id,
        int flags,
        int priv_map_size,
        const unsigned char *priv_map)
{
  int i;
  struct userlist_user *uu;
  struct userlist_contest *uc;
  int subflags = 0;

  if (!p) return;
  if (contest_id < 0) contest_id = 0;

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n",
          EJUDGE_CHARSET);
  fprintf(f, "<%s>", elem_map[USERLIST_T_USERLIST]);

  for (i = 1; i < p->user_map_size; i++) {
    uu = p->user_map[i];
    if (!uu) continue;
    if (contest_id > 0) {
      if (!uu->contests) continue;
      for (uc = (struct userlist_contest*) uu->contests->first_down;
           uc; uc = (struct userlist_contest*) uc->b.right) {
        if (uc->id == contest_id) break;
      }
      if (!uc) continue;
      if (uc->status != USERLIST_REG_OK) continue;
    }

    subflags = flags & USERLIST_FORCE_FIRST_MEMBER;
    if (i < priv_map_size && priv_map[i]) {
      if ((flags & USERLIST_SHOW_PRIV_REG_PASSWD))
        subflags |= USERLIST_SHOW_REG_PASSWD;
      if ((flags & USERLIST_SHOW_PRIV_CNTS_PASSWD))
        subflags |= USERLIST_SHOW_CNTS_PASSWD;
    } else {
      subflags |= flags & (USERLIST_SHOW_REG_PASSWD|USERLIST_SHOW_CNTS_PASSWD);
    }

    userlist_real_unparse_user(uu, f, USERLIST_MODE_STAND, contest_id,
                               subflags);
  }
  fprintf(f, "</%s>\n", elem_map[USERLIST_T_USERLIST]);
}

unsigned char const *
userlist_tag_to_str(int t)
{
  ASSERT(t > 0 && t < USERLIST_LAST_TAG);
  return elem_map[t];
}
