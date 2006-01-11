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

#include "userlist.h"
#include "errlog.h"
#include "protocol.h"
#include "misctext.h"

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
};
/*
static size_t const attn_sizes[USERLIST_LAST_ATTN] =
{
  0,
  sizeof(struct xml_attn),
  sizeof(struct xml_attn),
};
*/

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
      xfree(p->name);
      xfree(p->email);
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
      xfree(p->location);
      xfree(p->spelling);
      xfree(p->printer_name);
      xfree(p->languages);
      xfree(p->extra1);
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
  }
}
static void
attn_free(struct xml_attn *a)
{
}

static int
parse_int(char const *path, int l, int c, char const *str, int *pval)
{
  int x, n;
  if (!str || sscanf(str, "%d %n", &x, &n) != 1 || str[n]) {
    err("%s:%d:%d: cannot parse integer value", path, l, c);
    return -1;
  }
  *pval = x;
  return 0;
}
static int
parse_ip(char const *path, int l, int c, char const *s, ej_ip_t *pip)
{
  unsigned int b1, b2, b3, b4;
  int n;
  ej_ip_t ip;

  if (!s || sscanf(s, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || s[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
    err("%s:%d:%d: invalid IP-address", path, l, c);
    return -1;
  }
  ip = b1 << 24 | b2 << 16 | b3 << 8 | b4;
  *pip = ip;
  return 0;
}
static int
parse_date(char const *path, int l, int c, char const *s, time_t *pd)
{
  int year, month, day, hour, min, sec, n;
  time_t t;
  struct tm tt;

  memset(&tt, 0, sizeof(tt));
  tt.tm_isdst = -1;
  if (!s) goto failed;
  if (sscanf(s, "%d/%d/%d %d:%d:%d %n", &year, &month, &day, &hour,
             &min, &sec, &n) != 6) goto failed;
  if (s[n]) goto failed;
  if (year < 1900 || year > 2100 || month < 1 || month > 12
      || day < 1 || day > 31 || hour < 0 || hour >= 24
      || min < 0 || min >= 60 || sec < 0 || sec >= 60) goto failed;
  tt.tm_sec = sec;
  tt.tm_min = min;
  tt.tm_hour = hour;
  tt.tm_mday = day;
  tt.tm_mon = month - 1;
  tt.tm_year = year - 1900;
  if ((t = mktime(&tt)) == (time_t) -1) goto failed;
  *pd = t;
  return 0;

 failed:
  err("%s:%d:%d: invalid date", path, l, c);
  return -1;
}
static int
parse_bool(char const *path, int l, int c, char const *str, int *pval)
{
  if (str) {
    if (!strcasecmp(str, "true")
        || !strcasecmp(str, "yes")
        || !strcasecmp(str, "1")) {
      *pval = 1;
      return 0;
    }
    if (!strcasecmp(str, "false")
        || !strcasecmp(str, "no")
        || !strcasecmp(str, "0")) {
      *pval = 0;
      return 0;
    }
  }
  err("%s:%d:%d: invalid boolean value", path, l, c);
  return -1;
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

static int
invalid_tag(char const *path, struct xml_tree *tag)
{
  err("%s:%d:%d: tag <%s> is invalid here", path, tag->line, tag->column,
      tag_map[tag->tag]);
  return -1;
}
static int
invalid_tag_value(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: value of tag <%s> is invalid",
      path, t->line, t->column, attn_map[t->tag]);
  return -1;
}
static int
duplicated_tag(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: tag <%s> may appear only once", path, t->line, t->column,
      tag_map[t->tag]);
  return -1;
}
static int
undefined_tag(char const *path, struct xml_tree *t, int tag)
{
  err("%s:%d:%d: tag <%s> is undefined", path, t->line, t->column,
      tag_map[tag]);
  return -1;
}
static int
empty_tag(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: tag <%s> is empty",
      path, t->line, t->column, tag_map[t->tag]);
  return -1;
}
static int
nested_tag(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: nested tags are not allowed for tag <%s>",
      path, t->line, t->column, tag_map[t->tag]);
  return -1;
}
static int
no_text(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: text is not allowed tag <%s>",
      path, t->line, t->column, tag_map[t->tag]);
  return -1;
}
static int
no_attr(char const *path, struct xml_tree *t)
{
  err("%s:%d:%d: attributes are not allowed for tag <%s>",
      path, t->line, t->column, tag_map[t->tag]);
  return -1;
}
static int
invalid_attn(char const *path, struct xml_attn *a)
{
  err("%s:%d:%d: attribute \"%s\" is invalid here", path, a->line, a->column,
      attn_map[a->tag]);
  return -1;
}
static int
invalid_attn_value(char const *path, struct xml_attn *a)
{
  err("%s:%d:%d: value of attribute \"%s\" is invalid",
      path, a->line, a->column, attn_map[a->tag]);
  return -1;
}
static int
duplicated_attn(char const *path, struct xml_attn *a)
{
  err("%s:%d:%d: attribute \"%s\" is already defined",
      path, a->line, a->column, attn_map[a->tag]);
  return -1;
}
static int
undefined_attn(char const *path, struct xml_tree *t, int a)
{
  err("%s:%d:%d: attribute \"%s\" is undefined",
      path, t->line, t->column, attn_map[a]);
  return -1;
}

static int
handle_final_tag(char const *path, struct xml_tree *t, unsigned char **ps)
{
  if (*ps) return duplicated_tag(path, t);
  //if (!t->text || !*t->text) return empty_tag(path, t);
  if (t->first_down) return nested_tag(path, t);
  if (t->first) return no_attr(path, t);
  *ps = t->text; t->text = 0;
  return 0;
}

static struct userlist_passwd *
parse_passwd(char const *path, struct xml_tree *t)
{
  struct userlist_passwd *pwd;
  struct xml_attn *a;

  ASSERT(t->tag == USERLIST_T_PASSWORD || t->tag == USERLIST_T_TEAM_PASSWORD);
  pwd = (struct userlist_passwd*) t;

  if (t->first_down) {
    nested_tag(path, t);
    return 0;
  }
  if (!t->text) t->text = xstrdup("");
  /*
  if (!t->text || !*t->text) {
    empty_tag(path, t);
    return 0;
  }
  */

  for (a = t->first; a; a = a->next) {
    if (a->tag != USERLIST_A_METHOD) {
      invalid_attn(path, a);
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

  if (cookies->first) return no_attr(path, cookies);
  xfree(cookies->text); cookies->text = 0;
  for (t = cookies->first_down; t; t = t->right) {
    if (t->tag != USERLIST_T_COOKIE) return invalid_tag(path, t);
    c = (struct userlist_cookie*) t;
    if (t->text && *t->text) return no_text(path, t);
    if (t->first_down) return nested_tag(path, t);
    c->contest_id = -1;
    c->locale_id = -1;
    c->user = usr;
    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_IP:
        if (parse_ip(path, a->line, a->column, a->text, &c->ip) < 0)
          return -1;
        break;
      case USERLIST_A_VALUE:
        {
          ej_cookie_t val;
          int n;

          if (!a->text || sscanf(a->text, "%llx %n", &val, &n) != 1
              || !val) {
            invalid_attn_value(path, a);
            return -1;
          }
          c->cookie = val;
        }
        break;
      case USERLIST_A_EXPIRE:
        if (parse_date(path, a->line, a->column, a->text, &c->expire) < 0)
          return -1;
        break;
      case USERLIST_A_LOCALE_ID:
        if (parse_int(path, a->line, a->column, a->text, &c->locale_id) < 0)
          return -1;
        if (c->locale_id < -1 || c->locale_id > 127)
          return invalid_attn_value(path, a);
        break;
      case USERLIST_A_CONTEST_ID:
        if (parse_int(path, a->line, a->column, a->text, &c->contest_id) < 0)
          return -1;
        if (c->contest_id < 0)
          return invalid_attn_value(path, a);
        break;
      case USERLIST_A_PRIV_LEVEL:
        c->priv_level = parse_priv_level(path, a->line, a->column, a->text);
        if (c->priv_level < 0 || c->priv_level > PRIV_LEVEL_ADMIN) return -1;
        break;
      default:
        return invalid_attn(path, a);
      }
    }
    if (!c->ip) return undefined_attn(path, t, USERLIST_A_IP);
    if (!c->cookie) return undefined_attn(path, t, USERLIST_A_VALUE);
    if (!c->expire) return undefined_attn(path, t, USERLIST_A_EXPIRE);
  }
  return 0;
}

static int
parse_members(char const *path, struct xml_tree *q,
              struct userlist_user *usr)
{
  struct xml_tree *t;
  struct userlist_members *mbs = (struct userlist_members*) q;
  struct userlist_member *mb;
  struct xml_tree *p;
  struct xml_attn *a;
  int role, i;

  if (q->tag < USERLIST_T_CONTESTANTS || q->tag > USERLIST_T_GUESTS)
    return invalid_tag(path, q);
  role = q->tag - USERLIST_T_CONTESTANTS;
  if (usr->members[role]) return duplicated_tag(path, q);
  usr->members[role] = mbs;
  mbs->role = role;

  if (mbs->b.first) return no_attr(path, q);
  xfree(mbs->b.text); mbs->b.text = 0;

  for (t = mbs->b.first_down; t; t = t->right) {
    if (t->tag != USERLIST_T_MEMBER) return invalid_tag(path, t);
    mbs->total++;
    mb = (struct userlist_member*) t;
    xfree(t->text); t->text = 0;

    for (a = t->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_SERIAL:
        if (parse_int(path, a->line, a->column, a->text, &mb->serial) < 0)
          return invalid_attn_value(path, a);
        if (mb->serial <= 0) return invalid_attn_value(path, a);
        break;
      default:
        return invalid_attn(path, a);
      }
    }

    for (p = t->first_down; p; p = p->right) {
      switch (p->tag) {
      case USERLIST_T_FIRSTNAME:
        if (handle_final_tag(path, p, &mb->firstname) < 0) return -1;
        break;
      case USERLIST_T_FIRSTNAME_EN:
        if (handle_final_tag(path, p, &mb->firstname_en) < 0) return -1;
        break;
      case USERLIST_T_SURNAME:
        if (handle_final_tag(path, p, &mb->surname) < 0) return -1;
        break;
      case USERLIST_T_SURNAME_EN:
        if (handle_final_tag(path, p, &mb->surname_en) < 0) return -1;
        break;
      case USERLIST_T_MIDDLENAME:
        if (handle_final_tag(path, p, &mb->middlename) < 0) return -1;
        break;
      case USERLIST_T_MIDDLENAME_EN:
        if (handle_final_tag(path, p, &mb->middlename_en) < 0) return -1;
        break;
      case USERLIST_T_EMAIL:
        if (handle_final_tag(path, p, &mb->email) < 0) return -1;
        break;
      case USERLIST_T_PHONE:
        if (handle_final_tag(path, p, &mb->phone) < 0) return -1;
        break;
      case USERLIST_T_HOMEPAGE:
        if (handle_final_tag(path, p, &mb->homepage) < 0) return -1;
        break;
      case USERLIST_T_OCCUPATION:
        if (handle_final_tag(path, p, &mb->occupation) < 0) return -1;
        break;
      case USERLIST_T_OCCUPATION_EN:
        if (handle_final_tag(path, p, &mb->occupation_en) < 0) return -1;
        break;
      case USERLIST_T_INST:
        if (handle_final_tag(path, p, &mb->inst) < 0) return -1;
        break;
      case USERLIST_T_INST_EN:
        if (handle_final_tag(path, p, &mb->inst_en) < 0) return -1;
        break;
      case USERLIST_T_INSTSHORT:
        if (handle_final_tag(path, p, &mb->instshort) < 0) return -1;
        break;
      case USERLIST_T_INSTSHORT_EN:
        if (handle_final_tag(path, p, &mb->instshort_en) < 0) return -1;
        break;
      case USERLIST_T_FAC:
        if (handle_final_tag(path, p, &mb->fac) < 0) return -1;
        break;
      case USERLIST_T_FAC_EN:
        if (handle_final_tag(path, p, &mb->fac_en) < 0) return -1;
        break;
      case USERLIST_T_FACSHORT:
        if (handle_final_tag(path, p, &mb->facshort) < 0) return -1;
        break;
      case USERLIST_T_FACSHORT_EN:
        if (handle_final_tag(path, p, &mb->facshort_en) < 0) return -1;
        break;
      case USERLIST_T_STATUS:
        if (mb->status) return duplicated_tag(path, p);
        if (p->first) return no_attr(path, p);
        if (p->first_down) return nested_tag(path, p);
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
        return invalid_tag_value(path, p);
      case USERLIST_T_GRADE:
        if (mb->grade) return duplicated_tag(path, p);
        if (p->first) return no_attr(path, p);
        if (p->first_down) return nested_tag(path, p);
        if (!p->text || !*p->text) break;
        if (parse_int(path, p->line, p->column, p->text, &mb->grade) < 0)
          return invalid_tag_value(path, p);
        if (mb->grade < 0 || mb->grade >= 100000)
          return invalid_tag_value(path, p);
        break;
      case USERLIST_T_GROUP:
        if (handle_final_tag(path, p, &mb->group) < 0) return -1;
        break;
      case USERLIST_T_GROUP_EN:
        if (handle_final_tag(path, p, &mb->group_en) < 0) return -1;
        break;
      default:
        return invalid_tag(path, p);
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
    if (usr->contests) return duplicated_tag(path, t);
    usr->contests = t;
  }
  xfree(t->text); t->text = 0;
  if (t->first) no_attr(path, t);

  for (p = t->first_down; p; p = p->right) {
    if (p->tag != USERLIST_T_CONTEST) return invalid_tag(path, p);
    if (p->first_down) return nested_tag(path, p);
    if (p->text && *p->text) return no_text(path, p);
    reg = (struct userlist_contest*) p;
    
    reg->id = -1;
    reg->status = -1;
    for (a = p->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_ID:
        if (parse_int(path, a->line, a->column, a->text, &reg->id) < 0)
          return -1;
        if (reg->id <= 0) return invalid_attn_value(path, a);
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
        return invalid_attn_value(path, a);
      case USERLIST_A_BANNED:
        if (parse_bool(path, a->line, a->column, a->text, &tmp) < 0) return -1;
        if (tmp) reg->flags |= USERLIST_UC_BANNED;
        break;
      case USERLIST_A_INVISIBLE:
        if (parse_bool(path, a->line, a->column, a->text, &tmp) < 0) return -1;
        if (tmp) reg->flags |= USERLIST_UC_INVISIBLE;
        break;
      case USERLIST_A_LOCKED:
        if (parse_bool(path, a->line, a->column, a->text, &tmp) < 0) return -1;
        if (tmp) reg->flags |= USERLIST_UC_LOCKED;
        break;
      case USERLIST_A_DATE:
        if (parse_date(path, a->line, a->column, a->text, &reg->date) < 0)
          return -1;
        break;
      default:
        return invalid_attn(path, a);
      }
    }
    if (reg->id == -1)
      return undefined_attn(path, p, USERLIST_A_ID);
    if (reg->status == -1)
      return undefined_attn(path, p, USERLIST_A_STATUS);
  }

  return 0;
}

static int
do_parse_user(char const *path, struct userlist_user *usr)
{
  struct xml_attn *a;
  struct xml_tree *t;

  xfree(usr->b.text); usr->b.text = 0;

  usr->default_use_cookies = -1;
  usr->id = -1;
  for (a = usr->b.first; a; a = a->next) {
    switch (a->tag) {
    case USERLIST_A_ID:
      if (parse_int(path, a->line, a->column, a->text, &usr->id) < 0)
        return -1;
      if (usr->id <= 0)
        return invalid_attn_value(path, a);
      break;
    case USERLIST_A_REGISTERED:
      if (parse_date(path, a->line, a->column, a->text,
                     &usr->registration_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_LOGIN:
      if (parse_date(path, a->line, a->column, a->text,
                     &usr->last_login_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_ACCESS:
      if (parse_date(path, a->line, a->column, a->text,
                     &usr->last_access_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_CHANGE:
      if (parse_date(path, a->line, a->column, a->text,
                     &usr->last_change_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_PWDCHANGE:
      if (parse_date(path, a->line, a->column, a->text,
                     &usr->last_pwdchange_time) < 0) return -1;
      break;
    case USERLIST_A_LAST_MINOR_CHANGE:
      if (parse_date(path, a->line, a->column, a->text,
                     &usr->last_minor_change_time) < 0) return -1;
      break;
    case USERLIST_A_PRIVILEGED:
      if (parse_bool(path, a->line, a->column, a->text,
                     &usr->is_privileged) < 0) return -1;
      break;
    case USERLIST_A_INVISIBLE:
      if (parse_bool(path, a->line, a->column, a->text,
                     &usr->is_invisible) < 0) return -1;
      break;
    case USERLIST_A_BANNED:
      if (parse_bool(path, a->line, a->column, a->text,
                     &usr->is_banned) < 0) return -1;
      break;
    case USERLIST_A_LOCKED:
      if (parse_bool(path, a->line, a->column, a->text,
                     &usr->is_locked) < 0) return -1;
      break;
    case USERLIST_A_USE_COOKIES:
      if (parse_bool(path, a->line, a->column, a->text,
                     &usr->default_use_cookies) < 0) return -1;
      break;
    case USERLIST_A_READ_ONLY:
      if (parse_bool(path, a->line, a->column, a->text,
                     &usr->read_only) < 0) return -1;
      break;
    case USERLIST_A_NEVER_CLEAN:
      if (parse_bool(path, a->line, a->column, a->text,
                     &usr->never_clean) < 0) return -1;
      break;
    default:
      return invalid_attn(path, a);
    }
  }
  if (usr->id == -1)
    return undefined_attn(path, (struct xml_tree*) usr, USERLIST_A_ID);

  for (t = usr->b.first_down; t; t = t->right) {
    switch (t->tag) {
    case USERLIST_T_LOGIN:
      if (usr->login) return duplicated_tag(path, t);
      if (!t->text || !*t->text) return empty_tag(path, t);
      if (t->first_down) return nested_tag(path, t);
      for (a = t->first; a; a = a->next) {
        if (a->tag != USERLIST_A_PUBLIC) return invalid_attn(path, a);
        if (parse_bool(path, a->line, a->column, a->text,
                       &usr->show_login) < 0) return -1;
      }
      usr->login = t->text; t->text = 0;
      break;
    case USERLIST_T_NAME:
      if (handle_final_tag(path, t, &usr->name) < 0) return -1;
      if (!usr->name) usr->name = xstrdup("");
      break;
    case USERLIST_T_PASSWORD:
      if (usr->register_passwd) return duplicated_tag(path, t);
      if (!(usr->register_passwd = parse_passwd(path, t))) return -1;
      break;
    case USERLIST_T_TEAM_PASSWORD:
      if (usr->team_passwd) return duplicated_tag(path, t);
      if (!(usr->team_passwd = parse_passwd(path, t))) return -1;
      break;
    case USERLIST_T_EMAIL:
      if (usr->email) return duplicated_tag(path, t);
      if (!t->text || !*t->text) return empty_tag(path, t);
      if (t->first_down) return nested_tag(path, t);
      for (a = t->first; a; a = a->next) {
        if (a->tag != USERLIST_A_PUBLIC) return invalid_attn(path, a);
        if (parse_bool(path, a->line, a->column, a->text,
                       &usr->show_email) < 0) return -1;
      }
      usr->email = t->text; t->text = 0;
      break;
    case USERLIST_T_COOKIES:
      if (usr->cookies) return duplicated_tag(path, t);
      usr->cookies = t;
      if (parse_cookies(path, t, usr) < 0) return -1;
      break;
    case USERLIST_T_INST:
      if (handle_final_tag(path, t, &usr->inst) < 0) return -1;
      break;
    case USERLIST_T_INST_EN:
      if (handle_final_tag(path, t, &usr->inst_en) < 0) return -1;
      break;
    case USERLIST_T_INSTSHORT:
      if (handle_final_tag(path, t, &usr->instshort) < 0) return -1;
      break;
    case USERLIST_T_INSTSHORT_EN:
      if (handle_final_tag(path, t, &usr->instshort_en) < 0) return -1;
      break;
    case USERLIST_T_FAC:
      if (handle_final_tag(path, t, &usr->fac) < 0) return -1;
      break;
    case USERLIST_T_FAC_EN:
      if (handle_final_tag(path, t, &usr->fac_en) < 0) return -1;
      break;
    case USERLIST_T_FACSHORT:
      if (handle_final_tag(path, t, &usr->facshort) < 0) return -1;
      break;
    case USERLIST_T_FACSHORT_EN:
      if (handle_final_tag(path, t, &usr->facshort_en) < 0) return -1;
      break;
    case USERLIST_T_CITY:
      if (handle_final_tag(path, t, &usr->city) < 0) return -1;
      break;
    case USERLIST_T_CITY_EN:
      if (handle_final_tag(path, t, &usr->city_en) < 0) return -1;
      break;
    case USERLIST_T_COUNTRY:
      if (handle_final_tag(path, t, &usr->country) < 0) return -1;
      break;
    case USERLIST_T_COUNTRY_EN:
      if (handle_final_tag(path, t, &usr->country_en) < 0) return -1;
      break;
    case USERLIST_T_LOCATION:
      if (handle_final_tag(path, t, &usr->location) < 0) return -1;
      break;
    case USERLIST_T_SPELLING:
      if (handle_final_tag(path, t, &usr->spelling) < 0) return -1;
      break;
    case USERLIST_T_PRINTER_NAME:
      if (handle_final_tag(path, t, &usr->printer_name) < 0) return -1;
      break;
    case USERLIST_T_LANGUAGES:
      if (handle_final_tag(path, t, &usr->languages) < 0) return -1;
      break;
    case USERLIST_T_EXTRA1:
      if (handle_final_tag(path, t, &usr->extra1) < 0) return -1;
      break;
    case USERLIST_T_PHONE:
      if (handle_final_tag(path, t, &usr->phone) < 0) return -1;
      break;
    case USERLIST_T_HOMEPAGE:
      if (handle_final_tag(path, t, &usr->homepage) < 0) return -1;
      break;
    case USERLIST_T_CONTESTS:
      if (parse_contest(path, t, usr) < 0) return -1;
      break;
    case USERLIST_T_CONTESTANTS:
    case USERLIST_T_RESERVES:
    case USERLIST_T_COACHES:
    case USERLIST_T_ADVISORS:
    case USERLIST_T_GUESTS:
      if (parse_members(path, t, usr) < 0) return -1;
      break;
    default:
      return invalid_tag(path, t);
    }
  }
  if (!usr->login)
    return undefined_tag(path, (struct xml_tree*) usr, USERLIST_T_LOGIN);
  /*
  if (!usr->passwd)
    return undefined_tag(path, (struct xml_tree*) usr, USERLIST_T_PASSWORD);
  */
  if (!usr->name)
    usr->name = xstrdup("");
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
      if (lst->name) return duplicated_attn(path, a);
      lst->name = a->text; a->text = 0;
      break;
    case USERLIST_A_MEMBER_SERIAL:
      {
        int x = 0, n = 0;

        if (!a->text || sscanf(a->text, "%d %n", &x, &n) != 1 || a->text[n]
            || x < 0)
          return invalid_attn_value(path, a);
        lst->member_serial = x;
      }
      break;
    default:
      return invalid_attn(path, a);
    }
  }
  xfree(lst->b.text); lst->b.text = 0;
  if (!lst->member_serial) lst->member_serial = 1;

  for (t = lst->b.first_down; t; t = t->right) {
    if (t->tag != USERLIST_T_USER)
      return invalid_tag(path, t);
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

static unsigned char *
unparse_date(time_t d)
{
  static char buf[64];
  struct tm *ptm;

  ptm = localtime(&d);
  snprintf(buf, sizeof(buf), "%d/%02d/%02d %02d:%02d:%02d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  return buf;
}
static unsigned char *
unparse_bool(int b)
{
  if (b) return "yes";
  return "no";
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
unsigned char *
userlist_unparse_ip(ej_ip_t ip)
{
  static char buf[64];

  snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
           ip >> 24, (ip >> 16) & 0xff,
           (ip >> 8) & 0xff, ip & 0xff);
  return buf;
}

static void
unparse_final_tag(FILE *f, int t, unsigned char const *val,
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
  fprintf(f, "%s<%s>%s</%s>\n", ind, tag_map[t], val, tag_map[t]);
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
  unparse_final_tag(f, USERLIST_T_FIRSTNAME, p->firstname, ind);
  unparse_final_tag(f, USERLIST_T_FIRSTNAME_EN, p->firstname_en, ind);
  unparse_final_tag(f, USERLIST_T_MIDDLENAME, p->middlename, ind);
  unparse_final_tag(f, USERLIST_T_MIDDLENAME_EN, p->middlename_en, ind);
  unparse_final_tag(f, USERLIST_T_SURNAME, p->surname, ind);
  unparse_final_tag(f, USERLIST_T_SURNAME_EN, p->surname_en, ind);
  if (p->status) {
    unparse_final_tag(f, USERLIST_T_STATUS, unparse_member_status(p->status),
                      ind);
  }
  if (p->grade) {
    fprintf(f, "        <%s>%d</%s>\n",
            tag_map[USERLIST_T_GRADE], p->grade, tag_map[USERLIST_T_GRADE]);
  }
  unparse_final_tag(f, USERLIST_T_GROUP, p->group, ind);
  unparse_final_tag(f, USERLIST_T_GROUP_EN, p->group_en, ind);
  unparse_final_tag(f, USERLIST_T_OCCUPATION, p->occupation, ind);
  unparse_final_tag(f, USERLIST_T_OCCUPATION_EN, p->occupation_en, ind);
  unparse_final_tag(f, USERLIST_T_HOMEPAGE, p->homepage, ind);
  unparse_final_tag(f, USERLIST_T_PHONE, p->phone, ind);
  unparse_final_tag(f, USERLIST_T_INST, p->inst, ind);
  unparse_final_tag(f, USERLIST_T_INST_EN, p->inst_en, ind);
  unparse_final_tag(f, USERLIST_T_INSTSHORT, p->instshort, ind);
  unparse_final_tag(f, USERLIST_T_INSTSHORT_EN, p->instshort_en, ind);
  unparse_final_tag(f, USERLIST_T_FAC, p->fac, ind);
  unparse_final_tag(f, USERLIST_T_FAC_EN, p->fac_en, ind);
  unparse_final_tag(f, USERLIST_T_FACSHORT, p->facshort, ind);  
  unparse_final_tag(f, USERLIST_T_FACSHORT_EN, p->facshort_en, ind);  
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
            attn_map[USERLIST_A_IP], userlist_unparse_ip(c->ip),
            attn_map[USERLIST_A_VALUE], c->cookie,
            attn_map[USERLIST_A_EXPIRE], unparse_date(c->expire),
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
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_DATE], unparse_date(cc->date));
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
unparse_user_short(struct userlist_user *p, FILE *f, int contest_id)
{
  struct userlist_contest *uc = 0;

  if (!p) return;
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
  unparse_final_tag(f, USERLIST_T_LOGIN, p->login, "    ");
  if (p->name && *p->name) {
    unparse_final_tag(f, USERLIST_T_NAME, p->name, "    ");
  }
  unparse_final_tag(f, USERLIST_T_EMAIL, p->email, "    ");
  if (uc) {
    fprintf(f, "    <%s>\n", tag_map[USERLIST_T_CONTESTS]);
    unparse_contest(uc, f, "      ");
    fprintf(f, "    </%s>\n", tag_map[USERLIST_T_CONTESTS]);
  }
  fprintf(f, "  </%s>\n", tag_map[USERLIST_T_USER]);
}

static void
unparse_user(struct userlist_user *p, FILE *f, int mode, int contest_id)
{
  unsigned char attr_str[128];

  if (!p) return;
  fprintf(f, "  <%s %s=\"%d\"", tag_map[USERLIST_T_USER],
          attn_map[USERLIST_A_ID], p->id);
  if (p->default_use_cookies >= 0 && mode != USERLIST_MODE_STAND) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_USE_COOKIES],
            unparse_bool(p->default_use_cookies));
  }
  if (p->is_privileged) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_PRIVILEGED],
            unparse_bool(p->is_privileged));
  }
  if (p->is_invisible && mode == USERLIST_MODE_ALL) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_INVISIBLE],
            unparse_bool(p->is_invisible));
  }
  if (p->is_banned && mode == USERLIST_MODE_ALL) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_BANNED],
            unparse_bool(p->is_banned));
  }
  if (p->is_locked && mode == USERLIST_MODE_ALL) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LOCKED],
            unparse_bool(p->is_locked));
  }
  if (p->read_only && mode != USERLIST_MODE_STAND) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_READ_ONLY],
            unparse_bool(p->read_only));
  }
  if (p->never_clean && mode != USERLIST_MODE_STAND) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_NEVER_CLEAN],
            unparse_bool(p->never_clean));
  }
  if (p->registration_time && mode == USERLIST_MODE_ALL) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_REGISTERED],
            unparse_date(p->registration_time));
  }
  if (p->last_login_time && mode == USERLIST_MODE_ALL) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_LOGIN],
            unparse_date(p->last_login_time));
  }
  if (p->last_access_time && mode == USERLIST_MODE_ALL) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_ACCESS],
            unparse_date(p->last_access_time));
  }
  if (p->last_change_time && mode == USERLIST_MODE_ALL) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_CHANGE],
            unparse_date(p->last_change_time));
  }
  if (p->last_pwdchange_time && mode == USERLIST_MODE_ALL) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_PWDCHANGE],
            unparse_date(p->last_pwdchange_time));
  }
  if (p->last_minor_change_time && mode == USERLIST_MODE_ALL) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_MINOR_CHANGE],
            unparse_date(p->last_minor_change_time));
  }
  fputs(">\n", f);
  if (p->login) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attn_map[USERLIST_A_PUBLIC], unparse_bool(p->show_login));
    unparse_attributed_elem(f, USERLIST_T_LOGIN, p->login, attr_str, "    ");
  }
  if (p->register_passwd && mode == USERLIST_MODE_ALL) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attn_map[USERLIST_A_METHOD],
             unparse_passwd_method(p->register_passwd->method));
    unparse_attributed_elem(f, USERLIST_T_PASSWORD, p->register_passwd->b.text,
                            attr_str, "    ");
  }
  if (p->team_passwd && mode == USERLIST_MODE_ALL) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attn_map[USERLIST_A_METHOD],
             unparse_passwd_method(p->team_passwd->method));
    unparse_attributed_elem(f, USERLIST_T_TEAM_PASSWORD,
                            p->team_passwd->b.text, attr_str, "    ");
  }
  if (p->name && *p->name) {
    unparse_final_tag(f, USERLIST_T_NAME, p->name, "    ");
  }
  if (p->email) { // && mode != USERLIST_MODE_STAND) {
    snprintf(attr_str, sizeof(attr_str), " %s=\"%s\"",
             attn_map[USERLIST_A_PUBLIC], unparse_bool(p->show_email));
    unparse_attributed_elem(f, USERLIST_T_EMAIL, p->email, attr_str, "    ");
  }
  if (mode == USERLIST_MODE_ALL) {
    unparse_cookies(p->cookies, f);
  }
  unparse_contests(p->contests, f, USERLIST_MODE_STAND, contest_id);

  unparse_final_tag(f, USERLIST_T_INST, p->inst, "    ");
  unparse_final_tag(f, USERLIST_T_INST_EN, p->inst_en, "    ");
  unparse_final_tag(f, USERLIST_T_INSTSHORT, p->instshort, "    ");
  unparse_final_tag(f, USERLIST_T_INSTSHORT_EN, p->instshort_en, "    ");
  unparse_final_tag(f, USERLIST_T_FAC, p->fac, "    ");
  unparse_final_tag(f, USERLIST_T_FAC_EN, p->fac_en, "    ");
  unparse_final_tag(f, USERLIST_T_FACSHORT, p->facshort, "    ");
  unparse_final_tag(f, USERLIST_T_FACSHORT_EN, p->facshort_en, "    ");
  unparse_final_tag(f, USERLIST_T_HOMEPAGE, p->homepage, "    ");
  unparse_final_tag(f, USERLIST_T_PHONE, p->phone, "    ");
  unparse_final_tag(f, USERLIST_T_CITY, p->city, "    ");
  unparse_final_tag(f, USERLIST_T_CITY_EN, p->city_en, "    ");
  unparse_final_tag(f, USERLIST_T_COUNTRY, p->country, "    ");
  unparse_final_tag(f, USERLIST_T_COUNTRY_EN, p->country_en, "    ");
  unparse_final_tag(f, USERLIST_T_LOCATION, p->location, "    ");
  unparse_final_tag(f, USERLIST_T_SPELLING, p->spelling, "    ");
  unparse_final_tag(f, USERLIST_T_PRINTER_NAME, p->printer_name, "    ");
  unparse_final_tag(f, USERLIST_T_LANGUAGES, p->languages, "    ");

  if (mode == USERLIST_MODE_STAND) {
    // generate some information about the first participant
    struct userlist_members **pmemb = p->members;

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
    unparse_members(p->members, f);
  }

  fprintf(f, "  </%s>\n", tag_map[USERLIST_T_USER]);
}

void
userlist_unparse_user(struct userlist_user *p, FILE *f, int mode)
{
  if (!p) return;

  fprintf(f, "<?xml version=\"1.0\" encoding=\"%s\" ?>\n",
          EJUDGE_CHARSET);
  unparse_user(p, f, mode, 0);
}

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
    unparse_user(p->user_map[i], f, 0, 0);
  fprintf(f, "</%s>\n", tag_map[USERLIST_T_USERLIST]);
}
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

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 * End:
 */
