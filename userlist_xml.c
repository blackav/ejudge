/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ispras.ru> */

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
#include "settings.h"
#include "ej_limits.h"

#include "userlist.h"
#include "errlog.h"
#include "protocol.h"
#include "misctext.h"
#include "xml_utils.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <expat.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

static char const * const tag_map[] =
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
  "location",
  "spelling",
  "printer_name",
  "languages",
  "extra1",
  "cntsinfos",
  "cntsinfo",

  0
};
static char const * const attn_map[] =
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

  0
};
static size_t const tag_sizes[USERLIST_LAST_TAG] =
{
  0,
  sizeof(struct userlist_list), /* USERLIST */
  sizeof(struct userlist_user), /* USER */
  sizeof(struct xml_tree),      /* LOGIN */
  sizeof(struct xml_tree),      /* NAME */
  sizeof(struct xml_tree),      /* INST */
  sizeof(struct xml_tree),      /* INST_EN */
  sizeof(struct xml_tree),      /* INSTSHORT */
  sizeof(struct xml_tree),      /* INSTSHORT_EN */
  sizeof(struct xml_tree),      /* FAC */
  sizeof(struct xml_tree),      /* FAC_EN */
  sizeof(struct xml_tree),      /* FACSHORT */
  sizeof(struct xml_tree),      /* FACSHORT_EN */
  sizeof(struct userlist_passwd), /* PASSWORD */
  sizeof(struct xml_tree),      /* EMAIL */
  sizeof(struct xml_tree),      /* HOMEPAGE */
  sizeof(struct xml_tree),      /* PHONE */
  sizeof(struct userlist_member), /* MEMBER */
  sizeof(struct xml_tree),      /* SURNAME */
  sizeof(struct xml_tree),      /* SURNAME_EN */
  sizeof(struct xml_tree),      /* MIDDLENAME */
  sizeof(struct xml_tree),      /* MIDDLENAME_EN */
  sizeof(struct xml_tree),      /* GRADE */
  sizeof(struct xml_tree),      /* GROUP */
  sizeof(struct xml_tree),      /* GROUP_EN */
  sizeof(struct xml_tree),      /* COOKIES */
  sizeof(struct userlist_cookie), /* COOKIE */
  sizeof(struct xml_tree),      /* CONTESTS */
  sizeof(struct userlist_contest), /* CONTEST */
  sizeof(struct xml_tree),      /* STATUS */
  sizeof(struct xml_tree),      /* OCCUPATION */
  sizeof(struct xml_tree),      /* OCCUPATION_EN */
  sizeof(struct userlist_members), /* CONTESTANTS */
  sizeof(struct userlist_members), /* RESERVES */
  sizeof(struct userlist_members), /* COACHES */
  sizeof(struct userlist_members), /* ADVISORS */
  sizeof(struct userlist_members), /* GUESTS */
  sizeof(struct xml_tree),      /* FIRSTNAME */
  sizeof(struct xml_tree),      /* FIRSTNAME_EN */
  sizeof(struct userlist_passwd), /* TEAM_PASSWORD */
  sizeof(struct xml_tree),      /* CITY */
  sizeof(struct xml_tree),      /* CITY_EN */
  sizeof(struct xml_tree),      /* COUNTRY */
  sizeof(struct xml_tree),      /* COUNTRY_EN */
  sizeof(struct xml_tree),      /* LOCATION */
  sizeof(struct xml_tree),      /* SPELLING */
  sizeof(struct xml_tree),      /* PRINTER_NAME */
  sizeof(struct xml_tree),      /* LANGUAGES */
  sizeof(struct xml_tree),      /* EXTRA1 */
  sizeof(struct xml_tree),      /* CNTSINFOS */
  sizeof(struct userlist_cntsinfo), /* CNTSINFO */
};

static void *
node_alloc(int tag)
{
  size_t sz;

  ASSERT(tag >= 1 && tag < USERLIST_LAST_TAG);
  sz = tag_sizes[tag];
  if (!sz) { fprintf(stderr, "%d (%s)!\n", tag, tag_map[tag]); }
  ASSERT(sz);
  //if (!sz) sz = sizeof(struct xml_tree);
  return xcalloc(1, sz);
}
struct xml_tree *
userlist_node_alloc(int tag)
{
  struct xml_tree *t;
  t = node_alloc(tag);
  t->tag = tag;
  return t;
}
static void *
attn_alloc(int tag)
{
  return xcalloc(1, sizeof(struct xml_attn));
}
static void
node_free(struct xml_tree *t)
{
  switch (t->tag) {
  case USERLIST_T_USERLIST:
    {
      struct userlist_list *p = (struct userlist_list*) t;
      xfree(p->user_map);
      xfree(p->name);
    }
    break;
  case USERLIST_T_USER:
    {
      struct userlist_user *p = (struct userlist_user*) t;
      xfree(p->login);
      xfree(p->i.name);
      xfree(p->email);
      xfree(p->i.inst);
      xfree(p->i.inst_en);
      xfree(p->i.instshort);
      xfree(p->i.instshort_en);
      xfree(p->i.fac);
      xfree(p->i.fac_en);
      xfree(p->i.facshort);
      xfree(p->i.facshort_en);
      xfree(p->i.homepage);
      xfree(p->i.city);
      xfree(p->i.city_en);
      xfree(p->i.country);
      xfree(p->i.country_en);
      xfree(p->i.location);
      xfree(p->i.spelling);
      xfree(p->i.printer_name);
      xfree(p->i.languages);
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
      xfree(p->inst);
      xfree(p->inst_en);
      xfree(p->instshort);
      xfree(p->instshort_en);
      xfree(p->fac);
      xfree(p->fac_en);
      xfree(p->facshort);
      xfree(p->facshort_en);
    }
    break;
  case USERLIST_T_CONTESTANTS:
  case USERLIST_T_RESERVES:
  case USERLIST_T_COACHES:
  case USERLIST_T_ADVISORS:
  case USERLIST_T_GUESTS:
    {
      struct userlist_members *p = (struct userlist_members*) t;
      xfree(p->members);
    }
    break;
  case USERLIST_T_CNTSINFO:
    {
      struct userlist_cntsinfo *p = (struct userlist_cntsinfo*) t;
      xfree(p->i.name);
      xfree(p->i.inst);
      xfree(p->i.inst_en);
      xfree(p->i.instshort);
      xfree(p->i.instshort_en);
      xfree(p->i.fac);
      xfree(p->i.fac_en);
      xfree(p->i.facshort);
      xfree(p->i.facshort_en);
      xfree(p->i.homepage);
      xfree(p->i.city);
      xfree(p->i.city_en);
      xfree(p->i.country);
      xfree(p->i.country_en);
      xfree(p->i.location);
      xfree(p->i.spelling);
      xfree(p->i.printer_name);
      xfree(p->i.languages);
    }
    break;
  }
}
static void
attn_free(struct xml_attn *a)
{
}

static int
parse_priv_level(char const *path, int l, int c, char const *str)
{
  if (str) {
    if (!strcasecmp(str, "user")) return PRIV_LEVEL_USER;
    if (!strcasecmp(str, "judge")) return PRIV_LEVEL_JUDGE;
    if (!strcasecmp(str, "administrator")) return PRIV_LEVEL_ADMIN;
    if (!strcasecmp(str, "admin")) return PRIV_LEVEL_ADMIN;
  }
  err("%s:%d:%d: invalid priv_level value", path, l, c);
  return -1;
}

static struct userlist_passwd *
parse_passwd(char const *path, struct xml_tree *t)
{
  struct userlist_passwd *pwd;
  struct xml_attn *a;

  ASSERT(t->tag == USERLIST_T_PASSWORD || t->tag == USERLIST_T_TEAM_PASSWORD);
  pwd = (struct userlist_passwd*) t;

  if (t->first_down) {
    xml_err_nested_elems(t);
    return 0;
  }
  if (!t->text) t->text = xstrdup("");
  /*
  if (!t->text || !*t->text) {
    xml_err_elem_empty(t);
    return 0;
  }
  */

  for (a = t->first; a; a = a->next) {
    if (a->tag != USERLIST_A_METHOD) {
      xml_err_attr_not_allowed(t, a);
      return 0;
    }
    if (!strcasecmp(a->text, "plain")) {
      pwd->method = USERLIST_PWD_PLAIN;
    } else if (!strcasecmp(a->text, "base64")) {
      pwd->method = USERLIST_PWD_BASE64;
    } else if (!strcasecmp(a->text, "sha1")) {
      pwd->method = USERLIST_PWD_SHA1;
    } else {
      err("%s:%d:%d: invalid password method", path, a->line, a->column);
      return 0;
    }
    /*
    if (pwd->method != USERLIST_PWD_PLAIN) {
      err("%s:%d:%d: this password method not yet supported",
          path, a->line, a->column);
      return 0;
    }
    */
  }
  if (!*t->text) pwd->method = USERLIST_PWD_PLAIN;
  return pwd;
}

static int
parse_cookies(char const *path, struct xml_tree *cookies,
              struct userlist_user *usr)
{
  struct xml_tree *t;
  struct xml_attn *a;
  struct userlist_cookie *c;

  if (cookies->first) return xml_err_attrs(cookies);
  xfree(cookies->text); cookies->text = 0;
  for (t = cookies->first_down; t; t = t->right) {
    if (t->tag != USERLIST_T_COOKIE) return xml_err_elem_not_allowed(t);
    c = (struct userlist_cookie*) t;
    if (xml_empty_text(t) < 0) return -1;
    if (t->first_down) return xml_err_nested_elems(t);
    c->contest_id = -1;
    c->locale_id = -1;
    c->user = usr;
    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_IP:
        if (xml_parse_ip(path, a->line, a->column, a->text, &c->ip) < 0)
          return -1;
        break;
      case USERLIST_A_VALUE:
        {
          ej_cookie_t val;
          int n;

          if (!a->text || sscanf(a->text, "%llx %n", &val, &n) != 1
              || !val) {
            xml_err_attr_invalid(a);
            return -1;
          }
          c->cookie = val;
        }
        break;
      case USERLIST_A_EXPIRE:
        if (xml_parse_date(path, a->line, a->column, a->text, &c->expire) < 0)
          return -1;
        break;
      case USERLIST_A_LOCALE_ID:
        if (xml_parse_int(path, a->line, a->column, a->text, &c->locale_id) < 0)
          return -1;
        if (c->locale_id < -1 || c->locale_id > 127)
          return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_CONTEST_ID:
        if (xml_parse_int(path, a->line, a->column, a->text, &c->contest_id) < 0)
          return -1;
        if (c->contest_id < 0)
          return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_PRIV_LEVEL:
        c->priv_level = parse_priv_level(path, a->line, a->column, a->text);
        if (c->priv_level < 0 || c->priv_level > PRIV_LEVEL_ADMIN) return -1;
        break;
      default:
        return xml_err_attr_not_allowed(t, a);
      }
    }
    if (!c->ip) return xml_err_attr_undefined(t, USERLIST_A_IP);
    if (!c->cookie) return xml_err_attr_undefined(t, USERLIST_A_VALUE);
    if (!c->expire) return xml_err_attr_undefined(t, USERLIST_A_EXPIRE);
  }
  return 0;
}

static int
parse_members(char const *path, struct xml_tree *q,
              struct userlist_members **pmemb)
{
  struct xml_tree *t;
  struct userlist_members *mbs = (struct userlist_members*) q;
  struct userlist_member *mb;
  struct xml_tree *p;
  struct xml_attn *a;
  int role, i;

  if (q->tag < USERLIST_T_CONTESTANTS || q->tag > USERLIST_T_GUESTS)
    return xml_err_elem_not_allowed(q);
  role = q->tag - USERLIST_T_CONTESTANTS;
  if (pmemb[role]) return xml_err_elem_redefined(q);
  pmemb[role] = mbs;
  mbs->role = role;

  if (mbs->b.first) return xml_err_attrs(q);
  xfree(mbs->b.text); mbs->b.text = 0;

  for (t = mbs->b.first_down; t; t = t->right) {
    if (t->tag != USERLIST_T_MEMBER)
      return xml_err_elem_not_allowed(t);
    mbs->total++;
    mb = (struct userlist_member*) t;
    xfree(t->text); t->text = 0;

    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_SERIAL:
        if (xml_parse_int(path, a->line, a->column, a->text, &mb->serial) < 0)
          return xml_err_attr_invalid(a);
        if (mb->serial <= 0) return xml_err_attr_invalid(a);
        break;
      default:
        return xml_err_attr_not_allowed(t, a);
      }
    }

    for (p = t->first_down; p; p = p->right) {
      switch (p->tag) {
      case USERLIST_T_FIRSTNAME:
        if (xml_leaf_elem(p, &mb->firstname, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_FIRSTNAME_EN:
        if (xml_leaf_elem(p, &mb->firstname_en, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_SURNAME:
        if (xml_leaf_elem(p, &mb->surname, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_SURNAME_EN:
        if (xml_leaf_elem(p, &mb->surname_en, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_MIDDLENAME:
        if (xml_leaf_elem(p, &mb->middlename, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_MIDDLENAME_EN:
        if (xml_leaf_elem(p, &mb->middlename_en, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_EMAIL:
        if (xml_leaf_elem(p, &mb->email, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_PHONE:
        if (xml_leaf_elem(p, &mb->phone, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_HOMEPAGE:
        if (xml_leaf_elem(p, &mb->homepage, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_OCCUPATION:
        if (xml_leaf_elem(p, &mb->occupation, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_OCCUPATION_EN:
        if (xml_leaf_elem(p, &mb->occupation_en, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_INST:
        if (xml_leaf_elem(p, &mb->inst, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_INST_EN:
        if (xml_leaf_elem(p, &mb->inst_en, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_INSTSHORT:
        if (xml_leaf_elem(p, &mb->instshort, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_INSTSHORT_EN:
        if (xml_leaf_elem(p, &mb->instshort_en, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_FAC:
        if (xml_leaf_elem(p, &mb->fac, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_FAC_EN:
        if (xml_leaf_elem(p, &mb->fac_en, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_FACSHORT:
        if (xml_leaf_elem(p, &mb->facshort, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_FACSHORT_EN:
        if (xml_leaf_elem(p, &mb->facshort_en, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_STATUS:
        if (mb->status) return xml_err_elem_redefined(p);
        if (p->first) return xml_err_attrs(p);
        if (p->first_down) return xml_err_nested_elems(p);
        if (!p->text || !*p->text) break;
        if (p->text) {
          if (!strcasecmp(p->text, "schoolchild")) {
            mb->status = USERLIST_ST_SCHOOL;
            break;
          } else if (!strcasecmp(p->text, "student")) {
            mb->status = USERLIST_ST_STUDENT;
            break;
          } else if (!strcasecmp(p->text, "magistrant")) {
            mb->status = USERLIST_ST_MAG;
            break;
          } else if (!strcasecmp(p->text, "phdstudent")) {
            mb->status = USERLIST_ST_ASP;
            break;
          } else if (!strcasecmp(p->text, "teacher")) {
            mb->status = USERLIST_ST_TEACHER;
            break;
          } else if (!strcasecmp(p->text, "professor")) {
            mb->status = USERLIST_ST_PROF;
            break;
          } else if (!strcasecmp(p->text, "scientist")) {
            mb->status = USERLIST_ST_SCIENTIST;
            break;
          } else if (!strcasecmp(p->text, "other")) {
            mb->status = USERLIST_ST_OTHER;
            break;
          }
        }
        return xml_err_elem_invalid(p);
      case USERLIST_T_GRADE:
        if (mb->grade) return xml_err_elem_redefined(p);
        if (p->first) return xml_err_attrs(p);
        if (p->first_down) return xml_err_nested_elems(p);
        if (!p->text || !*p->text) break;
        if (xml_parse_int(path, p->line, p->column, p->text, &mb->grade) < 0)
          return xml_err_elem_invalid(p);
        if (mb->grade < 0 || mb->grade >= 100000)
          return xml_err_elem_invalid(p);
        break;
      case USERLIST_T_GROUP:
        if (xml_leaf_elem(p, &mb->group, 1, 1) < 0) return -1;
        break;
      case USERLIST_T_GROUP_EN:
        if (xml_leaf_elem(p, &mb->group_en, 1, 1) < 0) return -1;
        break;
      default:
        return xml_err_elem_not_allowed(p);
      }
    }
  }

  mbs->allocd = 8;
  while (mbs->allocd < mbs->total) {
    mbs->allocd *= 2;
  }
  mbs->members = (struct userlist_member**) xcalloc(mbs->allocd,
                                                    sizeof(mbs->members[0]));
  for (t = mbs->b.first_down, i = 0; t; t = t->right, i++) {
    mbs->members[i] = (struct userlist_member*) t;
  }
  return 0;
}
static int
parse_contest(char const *path, struct xml_tree *t,
              struct userlist_user *usr)
{
  struct xml_tree *p;
  struct userlist_contest *reg;
  struct xml_attn *a;
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
        if (xml_parse_int(path, a->line, a->column, a->text, &reg->id) < 0)
          return -1;
        if (reg->id <= 0) return xml_err_attr_invalid(a);
        break;
      case USERLIST_A_STATUS:
        if (a->text) {
          if (!strcasecmp(a->text, "ok")) {
            reg->status = USERLIST_REG_OK;
            break;
          } else if (!strcasecmp(a->text, "pending")) {
            reg->status = USERLIST_REG_PENDING;
            break;
          } else if (!strcasecmp(a->text, "rejected")) {
            reg->status = USERLIST_REG_REJECTED;
            break;
          }
        }
        return xml_err_attr_invalid(a);
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
      case USERLIST_A_DATE:
        if (xml_parse_date(path, a->line, a->column, a->text, &reg->date) < 0)
          return -1;
        break;
      default:
        return xml_err_attr_not_allowed(p, a);
      }
    }
    if (reg->id == -1)
      return xml_err_attr_undefined(p, USERLIST_A_ID);
    if (reg->status == -1)
      return xml_err_attr_undefined(p, USERLIST_A_STATUS);
  }

  return 0;
}

static int
parse_cntsinfo(const char *path, struct xml_tree *node,
               struct userlist_user *usr)
{
  struct userlist_cntsinfo *ui;
  struct xml_attn *a;
  struct xml_tree *p;
  time_t *pt;
  unsigned char **puc;

  ASSERT(node);
  ASSERT(node->tag == USERLIST_T_CNTSINFO);
  ui = (struct userlist_cntsinfo*) node;

  if (xml_empty_text(node) < 0) return -1;

  /* parse attributes */
  ui->contest_id = 0;
  for (a = node->first; a; a = a->next) {
    switch (a->tag) {
    case USERLIST_A_CONTEST_ID:
      if (xml_attr_int(a, &ui->contest_id) < 0) return -1;
      if (ui->contest_id <= 0 || ui->contest_id > MAX_CONTEST_ID)
        return xml_err_attr_invalid(a);
      if (ui->contest_id < usr->cntsinfo_a && usr->cntsinfo[ui->contest_id]) {
        xml_err_a(a, "duplicated contest_id %d", ui->contest_id);
        return -1;
      }
      break;
    case USERLIST_A_CNTS_READ_ONLY:
      if (xml_attr_bool(a, &ui->i.cnts_read_only) < 0) return -1;
      break;
    case USERLIST_A_LAST_CHANGE:
      pt = &ui->i.last_change_time;
    parse_date_attr:
      if (xml_attr_date(a, pt) < 0) return -1;
      break;
    case USERLIST_A_LAST_ACCESS:
      pt = &ui->i.last_access_time;
      goto parse_date_attr;
    case USERLIST_A_LAST_PWDCHANGE:
      pt = &ui->i.last_pwdchange_time;
      goto parse_date_attr;
    default:
      return xml_err_attr_not_allowed(node, a);
    }
  }

  if (ui->contest_id <= 0)
    return xml_err_attr_undefined(node, USERLIST_A_CONTEST_ID);

  /* parse elements */
  for (p = node->first_down; p; p = p->right) {
    switch(p->tag) {
    case USERLIST_T_NAME:
      puc = &ui->i.name;
    parse_leaf_elem:
      if (xml_leaf_elem(p, puc, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_TEAM_PASSWORD:
      if (ui->i.team_passwd) return xml_err_elem_redefined(p);
      if (!(ui->i.team_passwd = parse_passwd(path, p))) return -1;
      break;
    case USERLIST_T_INST:
      puc = &ui->i.inst;
      goto parse_leaf_elem;
    case USERLIST_T_INST_EN:
      puc = &ui->i.inst_en;
      goto parse_leaf_elem;
    case USERLIST_T_INSTSHORT:
      puc = &ui->i.instshort;
      goto parse_leaf_elem;
    case USERLIST_T_INSTSHORT_EN:
      puc = &ui->i.instshort_en;
      goto parse_leaf_elem;
    case USERLIST_T_FAC:
      puc = &ui->i.fac;
      goto parse_leaf_elem;
    case USERLIST_T_FAC_EN:
      puc = &ui->i.fac_en;
      goto parse_leaf_elem;
    case USERLIST_T_FACSHORT:
      puc = &ui->i.facshort;
      goto parse_leaf_elem;
    case USERLIST_T_FACSHORT_EN:
      puc = &ui->i.facshort_en;
      goto parse_leaf_elem;
    case USERLIST_T_HOMEPAGE:
      puc = &ui->i.homepage;
      goto parse_leaf_elem;
    case USERLIST_T_CITY:
      puc = &ui->i.city;
      goto parse_leaf_elem;
    case USERLIST_T_CITY_EN:
      puc = &ui->i.city_en;
      goto parse_leaf_elem;
    case USERLIST_T_COUNTRY:
      puc = &ui->i.country;
      goto parse_leaf_elem;
    case USERLIST_T_COUNTRY_EN:
      puc = &ui->i.country_en;
      goto parse_leaf_elem;
    case USERLIST_T_LOCATION:
      puc = &ui->i.location;
      goto parse_leaf_elem;
    case USERLIST_T_SPELLING:
      puc = &ui->i.spelling;
      goto parse_leaf_elem;
    case USERLIST_T_PRINTER_NAME:
      puc = &ui->i.printer_name;
      goto parse_leaf_elem;
    case USERLIST_T_LANGUAGES:
      puc = &ui->i.languages;
      goto parse_leaf_elem;
    case USERLIST_T_PHONE:
      puc = &ui->i.phone;
      goto parse_leaf_elem;
    case USERLIST_T_CONTESTANTS:
    case USERLIST_T_RESERVES:
    case USERLIST_T_COACHES:
    case USERLIST_T_ADVISORS:
    case USERLIST_T_GUESTS:
      if (parse_members(path, p, ui->i.members) < 0) return -1;
      break;
    default:
      return xml_err_elem_not_allowed(p);
    }
  }

  if (!ui->i.name) ui->i.name = xstrdup("");

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
  struct xml_attn *a;
  struct xml_tree *t;

  xfree(usr->b.text); usr->b.text = 0;

  usr->id = -1;
  for (a = usr->b.first; a; a = a->next) {
    switch (a->tag) {
    case USERLIST_A_ID:
      if (xml_parse_int(path, a->line, a->column, a->text, &usr->id) < 0)
        return -1;
      if (usr->id <= 0)
        return xml_err_attr_invalid(a);
      break;
    case USERLIST_A_REGISTERED:
      if (xml_parse_date(path, a->line, a->column, a->text,
                     &usr->registration_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_LOGIN:
      if (xml_parse_date(path, a->line, a->column, a->text,
                     &usr->last_login_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_ACCESS:
      if (xml_parse_date(path, a->line, a->column, a->text,
                     &usr->last_access_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_CHANGE:
      if (xml_parse_date(path, a->line, a->column, a->text,
                     &usr->last_change_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_PWDCHANGE:
      if (xml_parse_date(path, a->line, a->column, a->text,
                     &usr->last_pwdchange_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_MINOR_CHANGE:
      if (xml_parse_date(path, a->line, a->column, a->text,
                     &usr->last_minor_change_time) < 0) return -1;
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
      if (xml_attr_bool(a, &usr->i.cnts_read_only) < 0) return -1;
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
  if (usr->id == -1)
    return xml_err_attr_undefined(&usr->b, USERLIST_A_ID);

  for (t = usr->b.first_down; t; t = t->right) {
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
      break;
    case USERLIST_T_NAME:
      if (xml_leaf_elem(t, &usr->i.name, 1, 1) < 0) return -1;
      if (!usr->i.name) usr->i.name = xstrdup("");
      break;
    case USERLIST_T_PASSWORD:
      if (usr->register_passwd) return xml_err_elem_redefined(t);
      if (!(usr->register_passwd = parse_passwd(path, t))) return -1;
      break;
    case USERLIST_T_TEAM_PASSWORD:
      if (usr->i.team_passwd) return xml_err_elem_redefined(t);
      if (!(usr->i.team_passwd = parse_passwd(path, t))) return -1;
      break;
    case USERLIST_T_EMAIL:
      if (usr->email) return xml_err_elem_redefined(t);
      if (!t->text || !*t->text) return xml_err_elem_empty(t);
      if (t->first_down) return xml_err_nested_elems(t);
      for (a = t->first; a; a = a->next) {
        if (a->tag != USERLIST_A_PUBLIC)
          return xml_err_attr_not_allowed(t, a);
        if (xml_attr_bool(a, &usr->show_email) < 0) return -1;
      }
      usr->email = t->text; t->text = 0;
      break;
    case USERLIST_T_COOKIES:
      if (usr->cookies) return xml_err_elem_redefined(t);
      usr->cookies = t;
      if (parse_cookies(path, t, usr) < 0) return -1;
      break;
    case USERLIST_T_INST:
      if (xml_leaf_elem(t, &usr->i.inst, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_INST_EN:
      if (xml_leaf_elem(t, &usr->i.inst_en, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_INSTSHORT:
      if (xml_leaf_elem(t, &usr->i.instshort, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_INSTSHORT_EN:
      if (xml_leaf_elem(t, &usr->i.instshort_en, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_FAC:
      if (xml_leaf_elem(t, &usr->i.fac, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_FAC_EN:
      if (xml_leaf_elem(t, &usr->i.fac_en, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_FACSHORT:
      if (xml_leaf_elem(t, &usr->i.facshort, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_FACSHORT_EN:
      if (xml_leaf_elem(t, &usr->i.facshort_en, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_CITY:
      if (xml_leaf_elem(t, &usr->i.city, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_CITY_EN:
      if (xml_leaf_elem(t, &usr->i.city_en, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_COUNTRY:
      if (xml_leaf_elem(t, &usr->i.country, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_COUNTRY_EN:
      if (xml_leaf_elem(t, &usr->i.country_en, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_LOCATION:
      if (xml_leaf_elem(t, &usr->i.location, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_SPELLING:
      if (xml_leaf_elem(t, &usr->i.spelling, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_PRINTER_NAME:
      if (xml_leaf_elem(t, &usr->i.printer_name, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_LANGUAGES:
      if (xml_leaf_elem(t, &usr->i.languages, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_EXTRA1:
      if (xml_leaf_elem(t, &usr->extra1, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_PHONE:
      if (xml_leaf_elem(t, &usr->i.phone, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_HOMEPAGE:
      if (xml_leaf_elem(t, &usr->i.homepage, 1, 1) < 0) return -1;
      break;
    case USERLIST_T_CONTESTS:
      if (parse_contest(path, t, usr) < 0) return -1;
      break;
    case USERLIST_T_CONTESTANTS:
    case USERLIST_T_RESERVES:
    case USERLIST_T_COACHES:
    case USERLIST_T_ADVISORS:
    case USERLIST_T_GUESTS:
      if (parse_members(path, t, usr->i.members) < 0) return -1;
      break;
    case USERLIST_T_CNTSINFOS:
      if (parse_cntsinfos(path, t, usr) < 0) return -1;
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
  if (!usr->i.name)
    usr->i.name = xstrdup("");
  return 0;
}

static int
do_parse_userlist(char const *path, struct userlist_list *lst)
{
  struct xml_attn *a;
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

  for (t = lst->b.first_down; t; t = t->right) {
    if (t->tag != USERLIST_T_USER)
      return xml_err_elem_not_allowed(t);
    if (do_parse_user(path, (struct userlist_user*) t) < 0) return -1;
  }

  map_size = 16;
  for (u = (struct userlist_user*) lst->b.first_down; u;
       u = (struct userlist_user*) u->b.right) {
    ASSERT(u->b.tag == USERLIST_T_USER);
    ASSERT(u->id > 0);
    while (u->id >= map_size)
      map_size *= 2;
  }
  lst->user_map_size = map_size;
  lst->user_map = (struct userlist_user**) xcalloc(map_size, sizeof(lst->user_map[0]));
  for (u = (struct userlist_user*) lst->b.first_down; u;
       u = (struct userlist_user*) u->b.right) {
    if (lst->user_map[u->id]) {
      err("%s:%d:%d: duplicated user id %d", path, u->b.line, u->b.column,
          u->id);
      return -1;
    }
    lst->user_map[u->id] = u;
  }

  return 0;
}

struct userlist_user *
userlist_parse_user_str(char const *str)
{
  struct xml_tree *tree = 0;
  struct userlist_user *user = 0;

  xml_err_path = 0;
  xml_err_elem_names = tag_map;
  xml_err_attr_names = attn_map;

  tree = xml_build_tree_str(str, tag_map, attn_map, node_alloc, attn_alloc);
  if (!tree) goto failed;
  if (tree->tag != USERLIST_T_USER) {
    err("top-level tag must be <user>");
    goto failed;
  }
  user = (struct userlist_user*) tree;
  if (do_parse_user("", user) < 0) goto failed;
  return user;

 failed:
  if (tree) xml_tree_free(tree, node_free, attn_free);
  return 0;
}

struct xml_tree *
userlist_parse_contests_str(unsigned char const *str)
{
  struct xml_tree *tree = 0;

  xml_err_path = 0;
  xml_err_elem_names = tag_map;
  xml_err_attr_names = attn_map;

  tree = xml_build_tree_str(str, tag_map, attn_map, node_alloc, attn_alloc);
  if (!tree) return 0;
  if (tree->tag != USERLIST_T_CONTESTS) {
    err("top-level tag must be <contests>");
    xml_tree_free(tree, node_free, attn_free);
    return 0;
  }
  if (parse_contest("", tree, 0) < 0) {
    xml_tree_free(tree, node_free, attn_free);
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
  xml_err_elem_names = tag_map;
  xml_err_attr_names = attn_map;

  tree = xml_build_tree(path, tag_map, attn_map, node_alloc, attn_alloc);
  if (!tree) goto failed;
  if (tree->tag != USERLIST_T_USERLIST) {
    err("%s:%d:%d: top-level tag must be <userlist>",
        path, tree->line, tree->column);
    goto failed;
  }
  lst = (struct userlist_list *) tree;
  if (do_parse_userlist(path, lst) < 0) goto failed;
  return lst;

 failed:
  if (tree) xml_tree_free(tree, node_free, attn_free);
  return 0;
}

struct userlist_list *
userlist_parse_str(unsigned char const *str)
{
  struct xml_tree *tree = 0;
  struct userlist_list *lst = 0;

  xml_err_path = 0;
  xml_err_elem_names = tag_map;
  xml_err_attr_names = attn_map;

  tree = xml_build_tree_str(str, tag_map, attn_map, node_alloc, attn_alloc);
  if (!tree) goto failed;
  if (tree->tag != USERLIST_T_USERLIST) {
    err("%s:%d:%d: top-level tag must be <userlist>",
        "", tree->line, tree->column);
    goto failed;
  }
  lst = (struct userlist_list *) tree;
  if (do_parse_userlist("", lst) < 0) goto failed;
  return lst;

 failed:
  if (tree) xml_tree_free(tree, node_free, attn_free);
  return 0;
}

void *
userlist_free(struct xml_tree *p)
{
  if (p) xml_tree_free(p, node_free, attn_free);
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

static void
unparse_bool_attr(FILE *f, int attr, int val)
{
  if (val) {
    fprintf(f, " %s=\"%s\"", attn_map[attr], xml_unparse_bool(val));
  }
}

static void
unparse_date_attr(FILE *f, int attr, time_t val)
{
  if (val > 0) {
    fprintf(f, " %s=\"%s\"", attn_map[attr], xml_unparse_date(val));
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
  fprintf(f, "%s<%s%s>%s</%s>\n", ind, tag_map[t], attr_str, val, tag_map[t]);
}

static void
unparse_member(struct userlist_member *p, FILE *f)
{
  unsigned char const *ind = "        ";

  if (!p) return;
  ASSERT(p->b.tag == USERLIST_T_MEMBER);
  fprintf(f, "      <%s %s=\"%d\">\n", tag_map[USERLIST_T_MEMBER],
          attn_map[USERLIST_A_SERIAL], p->serial);
  xml_unparse_text(f, tag_map[USERLIST_T_FIRSTNAME], p->firstname, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_FIRSTNAME_EN], p->firstname_en, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_MIDDLENAME], p->middlename, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_MIDDLENAME_EN], p->middlename_en, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_SURNAME], p->surname, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_SURNAME_EN], p->surname_en, ind);
  if (p->status) {
    xml_unparse_text(f, tag_map[USERLIST_T_STATUS], unparse_member_status(p->status),
                      ind);
  }
  if (p->grade) {
    fprintf(f, "        <%s>%d</%s>\n",
            tag_map[USERLIST_T_GRADE], p->grade, tag_map[USERLIST_T_GRADE]);
  }
  xml_unparse_text(f, tag_map[USERLIST_T_GROUP], p->group, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_GROUP_EN], p->group_en, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_OCCUPATION], p->occupation, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_OCCUPATION_EN], p->occupation_en, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_HOMEPAGE], p->homepage, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_PHONE], p->phone, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_INST], p->inst, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_INST_EN], p->inst_en, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_INSTSHORT], p->instshort, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_INSTSHORT_EN], p->instshort_en, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_FAC], p->fac, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_FAC_EN], p->fac_en, ind);
  xml_unparse_text(f, tag_map[USERLIST_T_FACSHORT], p->facshort, ind);  
  xml_unparse_text(f, tag_map[USERLIST_T_FACSHORT_EN], p->facshort_en, ind);  
  fprintf(f, "      </%s>\n", tag_map[USERLIST_T_MEMBER]);
}
static void
unparse_members(struct userlist_members **p, FILE *f)
{
  int i, j;

  if (!p) return;
  for (i = 0; i < USERLIST_MB_LAST; i++) {
    if (!p[i]) continue;
    fprintf(f, "    <%s>\n", tag_map[USERLIST_T_CONTESTANTS + i]);
    for (j = 0; j < p[i]->total; j++) {
      unparse_member((struct userlist_member*) p[i]->members[j], f);
    }
    fprintf(f, "    </%s>\n", tag_map[USERLIST_T_CONTESTANTS + i]);
  }
}
static void
unparse_cookies(struct xml_tree *p, FILE *f)
{
  struct userlist_cookie *c;

  if (!p) return;
  ASSERT(p->tag == USERLIST_T_COOKIES);
  fprintf(f, "    <%s>\n", tag_map[USERLIST_T_COOKIES]);
  for (p = p->first_down; p; p = p->right) {
    ASSERT(p->tag == USERLIST_T_COOKIE);
    c = (struct userlist_cookie*) p;
    fprintf(f, "      <%s %s=\"%s\" %s=\"%llx\" %s=\"%s\" %s=\"%s\"",
            tag_map[USERLIST_T_COOKIE],
            attn_map[USERLIST_A_IP], xml_unparse_ip(c->ip),
            attn_map[USERLIST_A_VALUE], c->cookie,
            attn_map[USERLIST_A_EXPIRE], xml_unparse_date(c->expire),
            attn_map[USERLIST_A_PRIV_LEVEL],
            protocol_priv_level_str(c->priv_level));
    if (c->locale_id >= 0) {
      fprintf(f, " %s=\"%d\"", attn_map[USERLIST_A_LOCALE_ID], c->locale_id);
    }
    if (c->contest_id > 0) {
      fprintf(f, " %s=\"%d\"", attn_map[USERLIST_A_CONTEST_ID], c->contest_id);
    }
    fputs("/>\n", f);
  }
  fprintf(f, "    </%s>\n", tag_map[USERLIST_T_COOKIES]);
}
static void
unparse_contest(struct userlist_contest const *cc, FILE *f,
                unsigned char const *indent)
{
  if (!cc) return;
  fprintf(f, "%s<%s %s=\"%d\" %s=\"%s\"",
          indent, tag_map[USERLIST_T_CONTEST],
          attn_map[USERLIST_A_ID], cc->id,
          attn_map[USERLIST_A_STATUS], unparse_reg_status(cc->status));
  if ((cc->flags & USERLIST_UC_BANNED)) {
    fprintf(f, " %s=\"yes\"", attn_map[USERLIST_A_BANNED]);
  }
  if ((cc->flags & USERLIST_UC_INVISIBLE)) {
    fprintf(f, " %s=\"yes\"", attn_map[USERLIST_A_INVISIBLE]);
  }
  if ((cc->flags & USERLIST_UC_LOCKED)) {
    fprintf(f, " %s=\"yes\"", attn_map[USERLIST_A_LOCKED]);
  }
  if (cc->date) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_DATE],
            xml_unparse_date(cc->date));
  }
  fprintf(f, "/>\n");
}
static void
unparse_contests(struct xml_tree *p, FILE *f, int mode, int contest_id)
{
  if (!p) return;
  ASSERT(p->tag == USERLIST_T_CONTESTS);
  fprintf(f, "    <%s>\n", tag_map[USERLIST_T_CONTESTS]);
  for (p = p->first_down; p; p = p->right) {
    ASSERT(p->tag == USERLIST_T_CONTEST);
    if (mode == USERLIST_MODE_STAND && contest_id > 0
        && ((struct userlist_contest*) p)->id != contest_id)
      continue;
    unparse_contest((struct userlist_contest*) p, f, "      ");
  }
  fprintf(f, "    </%s>\n", tag_map[USERLIST_T_CONTESTS]);
}

static void
unparse_cntsinfo(struct userlist_cntsinfo *p, FILE *f)
{
  unsigned char attr_str[256];
  const unsigned char *sp1 = "      ";

  if (!p) return;
  fprintf(f, "    <%s %s=\"%d\"",
          tag_map[USERLIST_T_CNTSINFO], attn_map[USERLIST_A_CONTEST_ID],
          p->contest_id);
  if (p->i.cnts_read_only) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_CNTS_READ_ONLY],
            xml_unparse_bool(p->i.cnts_read_only));
  }
  if (p->i.last_change_time > 0) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_CHANGE],
            xml_unparse_date(p->i.last_change_time));
  }
  if (p->i.last_access_time > 0) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_ACCESS],
            xml_unparse_date(p->i.last_access_time));
  }
  if (p->i.last_pwdchange_time > 0) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_PWDCHANGE],
            xml_unparse_date(p->i.last_pwdchange_time));
  }
  fprintf(f, ">\n");

  if (p->i.name && *p->i.name) {
    xml_unparse_text(f, tag_map[USERLIST_T_NAME], p->i.name, sp1);
  }

  if (p->i.team_passwd) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attn_map[USERLIST_A_METHOD],
             unparse_passwd_method(p->i.team_passwd->method));
    unparse_attributed_elem(f, USERLIST_T_TEAM_PASSWORD,
                            p->i.team_passwd->b.text, attr_str, sp1);
  }

  xml_unparse_text(f, tag_map[USERLIST_T_INST], p->i.inst, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_INST_EN], p->i.inst_en, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_INSTSHORT], p->i.instshort, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_INSTSHORT_EN], p->i.instshort_en, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_FAC], p->i.fac, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_FAC_EN], p->i.fac_en, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_FACSHORT], p->i.facshort, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_FACSHORT_EN], p->i.facshort_en, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_HOMEPAGE], p->i.homepage, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_PHONE], p->i.phone, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_CITY], p->i.city, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_CITY_EN], p->i.city_en, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_COUNTRY], p->i.country, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_COUNTRY_EN], p->i.country_en, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_LOCATION], p->i.location, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_SPELLING], p->i.spelling, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_PRINTER_NAME], p->i.printer_name, sp1);
  xml_unparse_text(f, tag_map[USERLIST_T_LANGUAGES], p->i.languages, sp1);

  unparse_members(p->i.members, f);

  fprintf(f, "    </%s>\n", tag_map[USERLIST_T_CNTSINFO]);
}

/* called from `userlist_unparse_short' */
static void
unparse_user_short(struct userlist_user *p, FILE *f, int contest_id)
{
  struct userlist_contest *uc = 0;
  struct userlist_user_info *ui;

  if (!p) return;

  if (p->cntsinfo && contest_id > 0 && contest_id < p->cntsinfo_a
      && p->cntsinfo[contest_id]) {
    ui = &p->cntsinfo[contest_id]->i;
  } else {
    ui = &p->i;
  }

  if (contest_id) {
    if (!p->contests) return;
    for (uc = (struct userlist_contest*) p->contests->first_down;
         uc; uc = (struct userlist_contest*) uc->b.right) {
      if (uc->id == contest_id) break;
    }
    if (!uc) return;
  }
  fprintf(f, "  <%s %s=\"%d\">", tag_map[USERLIST_T_USER],
          attn_map[USERLIST_A_ID], p->id);
  xml_unparse_text(f, tag_map[USERLIST_T_LOGIN], p->login, "    ");
  if (ui->name && *ui->name) {
    xml_unparse_text(f, tag_map[USERLIST_T_NAME], ui->name, "    ");
  }
  xml_unparse_text(f, tag_map[USERLIST_T_EMAIL], p->email, "    ");
  if (uc) {
    fprintf(f, "    <%s>\n", tag_map[USERLIST_T_CONTESTS]);
    unparse_contest(uc, f, "      ");
    fprintf(f, "    </%s>\n", tag_map[USERLIST_T_CONTESTS]);
  }
  fprintf(f, "  </%s>\n", tag_map[USERLIST_T_USER]);
}

/* called from `userlist_unparse_user', `userlist_unparse',
   `userlist_unparse_for_standings'
 modes: USERLIST_MODE_USER, USERLIST_MODE_ALL, USERLIST_MODE_STAND
 contest_id == -1 - print all the information
 contest_id == 0  - print the default information
 contest_id >0    - print the specific information (if exist),
                    or print the default information
*/
static void
unparse_user(struct userlist_user *p, FILE *f, int mode, int contest_id)
{
  unsigned char attr_str[128];
  int i, cnt;
  struct userlist_user_info *ui;

  if (!p) return;

  if (contest_id > 0 && p->cntsinfo && contest_id < p->cntsinfo_a) {
    ui = &p->cntsinfo[contest_id]->i;
  } else {
    ui = &p->i;
  }

  fprintf(f, "  <%s %s=\"%d\"", tag_map[USERLIST_T_USER],
          attn_map[USERLIST_A_ID], p->id);
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
    unparse_bool_attr(f, USERLIST_A_CNTS_READ_ONLY, ui->cnts_read_only);
  }
  if (mode == USERLIST_MODE_ALL) {
    unparse_date_attr(f, USERLIST_A_REGISTERED, p->registration_time);
    unparse_date_attr(f, USERLIST_A_LAST_LOGIN, p->last_login_time);
    unparse_date_attr(f, USERLIST_A_LAST_MINOR_CHANGE,
                      p->last_minor_change_time);

    /* last_access_time is contest-specific */
    unparse_date_attr(f, USERLIST_A_LAST_ACCESS, ui->last_access_time);
    /* last_change_time is contest-specific */
    unparse_date_attr(f, USERLIST_A_LAST_CHANGE, ui->last_change_time);
    /* last_pwdchange_time is contest-specific */
    unparse_date_attr(f, USERLIST_A_LAST_PWDCHANGE, ui->last_pwdchange_time);
  }
  fputs(">\n", f);

  if (p->login) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attn_map[USERLIST_A_PUBLIC], xml_unparse_bool(p->show_login));
    unparse_attributed_elem(f, USERLIST_T_LOGIN, p->login, attr_str, "    ");
  }
  if (p->register_passwd && mode == USERLIST_MODE_ALL) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attn_map[USERLIST_A_METHOD],
             unparse_passwd_method(p->register_passwd->method));
    unparse_attributed_elem(f, USERLIST_T_PASSWORD, p->register_passwd->b.text,
                            attr_str, "    ");
  }
  if (ui->team_passwd && mode == USERLIST_MODE_ALL) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attn_map[USERLIST_A_METHOD],
             unparse_passwd_method(ui->team_passwd->method));
    unparse_attributed_elem(f, USERLIST_T_TEAM_PASSWORD,
                            ui->team_passwd->b.text, attr_str, "    ");
  }
  if (ui->name && *ui->name) {
    xml_unparse_text(f, tag_map[USERLIST_T_NAME], ui->name, "    ");
  }
  if (p->email) { // && mode != USERLIST_MODE_STAND) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attn_map[USERLIST_A_PUBLIC], xml_unparse_bool(p->show_email));
    unparse_attributed_elem(f, USERLIST_T_EMAIL, p->email, attr_str, "    ");
  }
  if (mode == USERLIST_MODE_ALL) {
    unparse_cookies(p->cookies, f);
  }
  unparse_contests(p->contests, f, USERLIST_MODE_STAND, contest_id);

  xml_unparse_text(f, tag_map[USERLIST_T_INST], ui->inst, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_INST_EN], ui->inst_en, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_INSTSHORT], ui->instshort, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_INSTSHORT_EN],ui->instshort_en,"    ");
  xml_unparse_text(f, tag_map[USERLIST_T_FAC], ui->fac, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_FAC_EN], ui->fac_en, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_FACSHORT], ui->facshort, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_FACSHORT_EN], ui->facshort_en, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_HOMEPAGE], ui->homepage, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_PHONE], ui->phone, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_CITY], ui->city, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_CITY_EN], ui->city_en, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_COUNTRY], ui->country, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_COUNTRY_EN], ui->country_en, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_LOCATION], ui->location, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_SPELLING], ui->spelling, "    ");
  xml_unparse_text(f, tag_map[USERLIST_T_PRINTER_NAME],ui->printer_name,"    ");
  xml_unparse_text(f, tag_map[USERLIST_T_LANGUAGES], ui->languages, "    ");

  if (mode == USERLIST_MODE_STAND) {
    // generate some information about the first participant
    struct userlist_members **pmemb = ui->members;

    if (pmemb && pmemb[USERLIST_MB_CONTESTANT]
        && pmemb[USERLIST_MB_CONTESTANT]->total > 0
        && pmemb[USERLIST_MB_CONTESTANT]->members
        && pmemb[USERLIST_MB_CONTESTANT]->members[0]
        && pmemb[USERLIST_MB_CONTESTANT]->members[0]->grade > 0) {
      fprintf(f, "    <%s>%d</%s>\n",
              tag_map[USERLIST_T_EXTRA1],
              pmemb[USERLIST_MB_CONTESTANT]->members[0]->grade,
              tag_map[USERLIST_T_EXTRA1]);
    }
  }

  if (mode != USERLIST_MODE_STAND) {
    unparse_members(ui->members, f);
  }

  if (contest_id < 0 && p->cntsinfo) {
    for (cnt = 0, i = 0; i < p->cntsinfo_a; i++)
      if (p->cntsinfo[i])
        cnt++;
    fprintf(f, "    <%s>\n", tag_map[USERLIST_T_CNTSINFOS]);
    for (i = 0; i < p->cntsinfo_a; i++)
      unparse_cntsinfo(p->cntsinfo[i], f);
    fprintf(f, "    </%s>\n", tag_map[USERLIST_T_CNTSINFOS]);
  }

  fprintf(f, "  </%s>\n", tag_map[USERLIST_T_USER]);
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
userlist_unparse_user(struct userlist_user *p, FILE *f, int mode,
                      int contest_id)
{
  if (!p) return;

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n",
          EJUDGE_CHARSET);
  unparse_user(p, f, mode, contest_id);
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
    fprintf(f, "<%s></%s>\n", tag_map[USERLIST_T_CONTESTS],
            tag_map[USERLIST_T_CONTESTS]);
  } else {
    unparse_contests(p->contests, f, 0, 0);
  }
}

/*
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
  fprintf(f, "<%s %s=\"%d\"", tag_map[USERLIST_T_USERLIST],
          attn_map[USERLIST_A_MEMBER_SERIAL], p->member_serial);
  
  if (p->name && *p->name)
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_NAME], p->name);
  fputs(">\n", f);
  for (i = 1; i < p->user_map_size; i++)
    unparse_user(p->user_map[i], f, 0, -1);
  fprintf(f, "</%s>\n", tag_map[USERLIST_T_USERLIST]);
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
  fprintf(f, "<%s>", tag_map[USERLIST_T_USERLIST]);
  for (i = 1; i < p->user_map_size; i++)
    unparse_user_short(p->user_map[i], f, contest_id);
  fprintf(f, "</%s>\n", tag_map[USERLIST_T_USERLIST]);
}

/*
 * called from userlist-server.c:cmd_list_standings_users, when
 *   generating the list of contestants for `serve' program
 *     userlist_unparse_for_standings(userlist, f, data->contest_id);
 */
void
userlist_unparse_for_standings(struct userlist_list *p,
                               FILE *f, int contest_id)
{
  int i;
  struct userlist_user *uu;
  struct userlist_contest *uc;

  if (!p) return;
  if (contest_id < 0) contest_id = 0;

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n",
          EJUDGE_CHARSET);
  fprintf(f, "<%s>", tag_map[USERLIST_T_USERLIST]);

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

    unparse_user(uu, f, USERLIST_MODE_STAND, contest_id);
  }
  fprintf(f, "</%s>\n", tag_map[USERLIST_T_USERLIST]);
}

unsigned char const *
userlist_tag_to_str(int t)
{
  ASSERT(t > 0 && t < USERLIST_LAST_TAG);
  return tag_map[t];
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 * End:
 */
