/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "nls.h"
#include "utf8_utils.h"
#include "userlist.h"
#include "pathutl.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <expat.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

static char const * const tag_map[] =
{
  0,
  "userlist",
  "user",
  "login",
  "name",
  "inst",
  "instshort",
  "fac",
  "facshort",
  "password",
  "email",
  "homepage",
  "phones",
  "phone",
  "members",
  "member",
  "surname",
  "middlename",
  "grade",
  "group",
  "cookies",
  "cookie",
  "registrations",
  "registration",
  "status",
  "occupation",

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
  "role",
  "contest_id",
  "registered",
  "last_login",
  "last_access",
  "last_change",
  "invisible",
  "banned",
  "status",
  "last_pwdchange",

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
  sizeof(struct xml_tree),      /* INSTSHORT */
  sizeof(struct xml_tree),      /* FAC */
  sizeof(struct xml_tree),      /* FACSHORT */
  sizeof(struct xml_tree),      /* PASSWORD */
  sizeof(struct xml_tree),      /* EMAIL */
  sizeof(struct xml_tree),      /* HOMEPAGE */
  sizeof(struct xml_tree),      /* PHONES */
  sizeof(struct xml_tree),      /* PHONE */
  sizeof(struct userlist_members), /* MEMBERS */
  sizeof(struct userlist_member), /* MEMBER */
  sizeof(struct xml_tree),      /* SURNAME */
  sizeof(struct xml_tree),      /* MIDDLENAME */
  sizeof(struct xml_tree),      /* GRADE */
  sizeof(struct xml_tree),      /* GROUP */
  sizeof(struct xml_tree),      /* COOKIES */
  sizeof(struct userlist_cookie), /* COOKIE */
  sizeof(struct xml_tree),      /* REGISTRATIONS */
  sizeof(struct userlist_reg),  /* REGISTRATION */
  sizeof(struct xml_tree),      /* STATUS */
  sizeof(struct xml_tree),      /* OCCUPATION */
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
parse_ip(char const *path, int l, int c, char const *s, unsigned long *pip)
{
  unsigned int b1, b2, b3, b4;
  int n;
  unsigned long ip;

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
parse_date(char const *path, int l, int c, char const *s, unsigned long *pd)
{
  int year, month, day, hour, min, sec, n;
  time_t t;
  struct tm tt;

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
  if (!t->text || !*t->text) return empty_tag(path, t);
  if (t->first_down) return nested_tag(path, t);
  if (t->first) return no_attr(path, t);
  *ps = t->text;
  return 0;
}

static int
parse_passwd(char const *path, struct xml_tree *t, struct userlist_user *usr)
{
  struct xml_attn *a;

  if (t->first_down) return nested_tag(path, t);
  if (!t->text || !*t->text) return empty_tag(path, t);
  usr->passwd = t->text;
  for (a = t->first; a; a = a->next) {
    if (a->tag != USERLIST_A_METHOD) return invalid_attn(path, a);
    if (!strcasecmp(a->text, "plain")) {
      usr->passwd_method = USERLIST_PWD_PLAIN;
    } else if (!strcasecmp(a->text, "base64")) {
      usr->passwd_method = USERLIST_PWD_BASE64;
    } else if (!strcasecmp(a->text, "sha1")) {
      usr->passwd_method = USERLIST_PWD_SHA1;
    } else {
      err("%s:%d:%d: invalid password method", path, a->line, a->column);
      return -1;
    }
    if (usr->passwd_method != USERLIST_PWD_PLAIN) {
      err("%s:%d:%d: this password method not yet supported",
          path, a->line, a->column);
    }
  }
  return 0;
}

static struct xml_tree*
parse_phones(char const *path, struct xml_tree *t)
{
  struct xml_tree *q;

  ASSERT(t->tag == USERLIST_T_PHONES);
  if (t->first) {
    no_attr(path, t);
    return 0;
  }
  xfree(t->text); t->text = 0;
  for (q = t->first_down; q; q = q->right) {
    if (q->tag != USERLIST_T_PHONE) {
      invalid_tag(path, q);
      return 0;
    }
    if (q->first) {
      no_attr(path, q);
      return 0;
    }
    if (q->first_down) {
      nested_tag(path, q);
      return 0;
    }
    if (!q->text || !*q->text) {
      empty_tag(path, q);
      return 0;
    }
  }
  return t;
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
          unsigned long long val;
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
  struct xml_attn *a;
  struct xml_tree *p;

  if (mbs->b.first) return no_attr(path, q);
  xfree(mbs->b.text); mbs->b.text = 0;
  for (t = mbs->b.first_down; t; t = t->right) {
    if (t->tag != USERLIST_T_MEMBER) return invalid_tag(path, t);
    mb = (struct userlist_member*) t;
    xfree(t->text); t->text = 0;
    
    for (a = t->first; a; a = a->next) {
      if (a->tag != USERLIST_A_ROLE) return invalid_attn(path, a);
      if (!strcasecmp(a->text, "contestant")) {
        mb->role = USERLIST_MB_CONTESTANT;
        mbs->contestants_total++;
      } else if (!strcasecmp(a->text, "reserve")) {
        mb->role = USERLIST_MB_RESERVE;
        mbs->reserves_total++;
      } else if (!strcasecmp(a->text, "advisor")) {
        mb->role = USERLIST_MB_ADVISOR;
        mbs->advisors_total++;
      } else if (!strcasecmp(a->text, "coach")) {
        mb->role = USERLIST_MB_COACH;
        mbs->coaches_total++;
      } else {
        return invalid_attn_value(path, a);
      }
    }

    for (p = t->first_down; p; p = p->right) {
      switch (p->tag) {
      case USERLIST_T_NAME:
        if (handle_final_tag(path, p, &mb->name) < 0) return -1;
        break;
      case USERLIST_T_SURNAME:
        if (handle_final_tag(path, p, &mb->surname) < 0) return -1;
        break;
      case USERLIST_T_MIDDLENAME:
        if (handle_final_tag(path, p, &mb->middlename) < 0) return -1;
        break;
      case USERLIST_T_EMAIL:
        if (handle_final_tag(path, p, &mb->email) < 0) return -1;
        break;
      case USERLIST_T_PHONES:
        if (!(mb->phones = parse_phones(path, p))) return -1;
        break;
      case USERLIST_T_HOMEPAGE:
        if (handle_final_tag(path, p, &mb->homepage) < 0) return -1;
        break;
      case USERLIST_T_OCCUPATION:
        if (handle_final_tag(path, p, &mb->occupation) < 0) return -1;
        break;
      case USERLIST_T_STATUS:
        if (mb->status) return duplicated_tag(path, p);
        if (p->first) return no_attr(path, p);
        if (p->first_down) return nested_tag(path, p);
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
            mb->status = USERLIST_ST_SCHOOL;
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
        if (parse_int(path, p->line, p->column, p->text, &mb->grade) < 0)
          return invalid_tag_value(path, p);
        break;
      case USERLIST_T_GROUP:
        if (handle_final_tag(path, p, &mb->group) < 0) return -1;
        break;
      default:
        return invalid_tag(path, p);
      }
    }

    if (!mb->name) return undefined_tag(path, t, USERLIST_T_NAME);
  }
  return 0;
}
static int
parse_registration(char const *path, struct xml_tree *t,
                   struct userlist_user *usr)
{
  struct xml_tree *p;
  struct userlist_reg *reg;
  struct xml_attn *a;

  ASSERT(t->tag == USERLIST_T_REGISTRATIONS);
  if (usr->registrations) return duplicated_tag(path, t);
  usr->registrations = t;
  xfree(t->text); t->text = 0;
  if (t->first) no_attr(path, t);

  for (p = t->first_down; p; p = p->right) {
    if (p->tag != USERLIST_T_REGISTRATION) return invalid_tag(path, p);
    if (p->first_down) return nested_tag(path, p);
    if (p->text && *p->text) return no_text(path, p);
    reg = (struct userlist_reg*) p;
    
    reg->contest_id = -1;
    reg->status = -1;
    for (a = p->first; a; a = a->next) {
      switch (a->tag) {
      case USERLIST_A_CONTEST_ID:
        if (parse_int(path, a->line, a->column, a->text, &reg->contest_id) < 0)
          return -1;
        if (reg->contest_id <= 0) return invalid_attn_value(path, a);
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
      default:
        return invalid_attn(path, a);
      }
    }
    if (reg->contest_id == -1)
      return undefined_attn(path, p, USERLIST_A_CONTEST_ID);
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
    case USERLIST_A_INVISIBLE:
      if (parse_bool(path, a->line, a->column, a->text,
                     &usr->is_invisible) < 0) return -1;
      break;
    case USERLIST_A_BANNED:
      if (parse_bool(path, a->line, a->column, a->text,
                     &usr->is_banned) < 0) return -1;
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
      if (handle_final_tag(path, t, &usr->login) < 0) return -1;
      break;
    case USERLIST_T_NAME:
      if (handle_final_tag(path, t, &usr->name) < 0) return -1;
      break;
    case USERLIST_T_PASSWORD:
      if (usr->passwd) return duplicated_tag(path, t);
      if (parse_passwd(path, t, usr) < 0) return -1;
      break;
    case USERLIST_T_EMAIL:
      if (handle_final_tag(path, t, &usr->email) < 0) return -1;
      break;
    case USERLIST_T_COOKIES:
      if (usr->cookies) return duplicated_tag(path, t);
      usr->cookies = t;
      if (parse_cookies(path, t, usr) < 0) return -1;
      break;
    case USERLIST_T_INST:
      if (handle_final_tag(path, t, &usr->inst) < 0) return -1;
      break;
    case USERLIST_T_INSTSHORT:
      if (handle_final_tag(path, t, &usr->instshort) < 0) return -1;
      break;
    case USERLIST_T_FAC:
      if (handle_final_tag(path, t, &usr->fac) < 0) return -1;
      break;
    case USERLIST_T_FACSHORT:
      if (handle_final_tag(path, t, &usr->facshort) < 0) return -1;
      break;
    case USERLIST_T_MEMBERS:
      if (usr->members) return duplicated_tag(path, t);
      if (parse_members(path, t, usr) < 0) return -1;
      usr->members = (struct userlist_members*) t;
      break;
    case USERLIST_T_PHONES:
      if (!(usr->phones = parse_phones(path, t))) return -1;
      break;
    case USERLIST_T_HOMEPAGE:
      if (handle_final_tag(path, t, &usr->homepage) < 0) return -1;
      break;
    case USERLIST_T_REGISTRATIONS:
      if (parse_registration(path, t, usr) < 0) return -1;
      break;
    default:
      return invalid_tag(path, t);
    }
  }
  if (!usr->login)
    return undefined_tag(path, (struct xml_tree*) usr, USERLIST_T_LOGIN);
  if (!usr->passwd)
    return undefined_tag(path, (struct xml_tree*) usr, USERLIST_T_PASSWORD);
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
    if (a->tag != USERLIST_A_NAME) 
      return invalid_attn(path, a);
    if (lst->name)
      return duplicated_attn(path, a);
    lst->name = a->text;
  }
  xfree(lst->b.text); lst->b.text = 0;

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
userlist_free(struct userlist_list *p)
{
  if (p) xml_tree_free(&p->b, node_free, attn_free);
  return 0;
}

static unsigned char *
unparse_date(unsigned long d)
{
  static char buf[64];
  struct tm *ptm;

  ptm = localtime(&d);
  snprintf(buf, sizeof(buf), "%d/%d/%d %d:%d:%d",
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
static unsigned char const *
unparse_member_role(int r)
{
  static char const * const member_role_map[] =
  {
    "contestant", "reserve", "advisor", "coach"
  };
  ASSERT(r >= USERLIST_MB_CONTESTANT && r <= USERLIST_MB_COACH);
  return member_role_map[r];
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
static unsigned char *
unparse_ip(unsigned long ip)
{
  static char buf[64];

  snprintf(buf, sizeof(buf), "%lu.%lu.%lu.%lu",
           ip >> 24, (ip >> 16) & 0xff,
           (ip >> 8) & 0xff, ip & 0xff);
  return buf;
}

static void
unparse_final_tag(FILE *f, int t, unsigned char const *val,
                  unsigned char const *ind)
{
  if (!val) return;
  fprintf(f, "%s<%s>%s</%s>\n", ind, tag_map[t], val, tag_map[t]);
}

static void
unparse_phones(struct xml_tree *p, FILE *f, char const *i)
{
  char ind_buf[32];

  if (!p) return;
  ASSERT(p->tag == USERLIST_T_PHONES);
  fprintf(f, "%s<%s>\n", i, tag_map[USERLIST_T_PHONES]);
  snprintf(ind_buf, sizeof(ind_buf), "%s  ", i);
  for (p = p->first_down; p; p = p->right) {
    ASSERT(p->tag == USERLIST_T_PHONE);
    unparse_final_tag(f, USERLIST_T_PHONE, p->text, ind_buf);
  }
  fprintf(f, "%s</%s>\n", i, tag_map[USERLIST_T_PHONES]);
}
static void
unparse_member(struct userlist_member *p, FILE *f)
{
  unsigned char const *ind = "        ";

  if (!p) return;
  ASSERT(p->b.tag == USERLIST_T_MEMBER);
  fprintf(f, "      <%s %s=\"%s\">\n",
          tag_map[USERLIST_T_MEMBER],
          attn_map[USERLIST_A_ROLE], unparse_member_role(p->role));
  unparse_final_tag(f, USERLIST_T_NAME, p->name, ind);
  unparse_final_tag(f, USERLIST_T_MIDDLENAME, p->middlename, ind);
  unparse_final_tag(f, USERLIST_T_SURNAME, p->surname, ind);
  if (p->status) {
    unparse_final_tag(f, USERLIST_T_STATUS, unparse_member_status(p->status),
                      ind);
  }
  if (p->grade) {
    fprintf(f, "        <%s>%d</%s>\n",
            tag_map[USERLIST_T_GRADE], p->grade, tag_map[USERLIST_T_GRADE]);
  }
  unparse_final_tag(f, USERLIST_T_GROUP, p->group, ind);
  unparse_final_tag(f, USERLIST_T_OCCUPATION, p->occupation, ind);
  unparse_final_tag(f, USERLIST_T_HOMEPAGE, p->homepage, ind);
  unparse_phones(p->phones, f, "        ");
  fprintf(f, "      </%s>\n", tag_map[USERLIST_T_MEMBER]);
}
static void
unparse_members(struct userlist_members *p, FILE *f)
{
  struct xml_tree *q;

  if (!p) return;
  fprintf(f, "    <%s>\n", tag_map[USERLIST_T_MEMBERS]);
  for (q = p->b.first_down; q; q = q->right) {
    ASSERT(q->tag == USERLIST_T_MEMBER);
    unparse_member((struct userlist_member*) q, f);
  }
  fprintf(f, "    </%s>\n", tag_map[USERLIST_T_MEMBERS]);
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
    fprintf(f, "      <%s %s=\"%s\" %s=\"%llx\" %s=\"%s\"",
            tag_map[USERLIST_T_COOKIE],
            attn_map[USERLIST_A_IP], unparse_ip(c->ip),
            attn_map[USERLIST_A_VALUE], c->cookie,
            attn_map[USERLIST_A_EXPIRE], unparse_date(c->expire));
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
unparse_registrations(struct xml_tree *p, FILE *f)
{
  struct userlist_reg *r;

  if (!p) return;
  ASSERT(p->tag == USERLIST_T_REGISTRATIONS);
  fprintf(f, "    <%s>\n", tag_map[USERLIST_T_REGISTRATIONS]);
  for (p = p->first_down; p; p = p->right) {
    ASSERT(p->tag == USERLIST_T_REGISTRATION);
    r = (struct userlist_reg*) p;
    fprintf(f, "      <%s %s=\"%d\" %s=\"%s\"/>\n",
            tag_map[USERLIST_T_REGISTRATION],
            attn_map[USERLIST_A_CONTEST_ID], r->contest_id,
            attn_map[USERLIST_A_STATUS], unparse_reg_status(r->status));
  }
  fprintf(f, "    </%s>\n", tag_map[USERLIST_T_REGISTRATIONS]);
}

static void
unparse_user(struct userlist_user *p, FILE *f)
{
  if (!p) return;
  fprintf(f, "  <%s %s=\"%d\"", tag_map[USERLIST_T_USER],
          attn_map[USERLIST_A_ID], p->id);
  if (p->is_invisible) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_INVISIBLE],
            unparse_bool(p->is_invisible));
  }
  if (p->is_banned) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_BANNED],
            unparse_bool(p->is_banned));
  }
  if (p->registration_time) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_REGISTERED],
            unparse_date(p->registration_time));
  }
  if (p->last_login_time) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_LOGIN],
            unparse_date(p->last_login_time));
  }
  if (p->last_access_time) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_ACCESS],
            unparse_date(p->last_access_time));
  }
  if (p->last_change_time) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_CHANGE],
            unparse_date(p->last_change_time));
  }
  if (p->last_pwdchange_time) {
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_LAST_PWDCHANGE],
            unparse_date(p->last_pwdchange_time));
  }
  fputs(">\n", f);
  if (p->login) {
    fprintf(f, "    <%s>%s</%s>\n", tag_map[USERLIST_T_LOGIN],
            p->login, tag_map[USERLIST_T_LOGIN]);
  }
  if (p->passwd) {
    fprintf(f, "    <%s %s=\"%s\">%s</%s>\n",
            tag_map[USERLIST_T_PASSWORD], attn_map[USERLIST_A_METHOD],
            unparse_passwd_method(p->passwd_method),
            p->passwd, tag_map[USERLIST_T_PASSWORD]);
  }
  if (p->name) {
    fprintf(f, "    <%s>%s</%s>\n", tag_map[USERLIST_T_NAME],
            p->name, tag_map[USERLIST_T_NAME]);
  }
  if (p->email) {
    fprintf(f, "    <%s>%s</%s>\n", tag_map[USERLIST_T_EMAIL],
            p->email, tag_map[USERLIST_T_EMAIL]);
  }
  unparse_cookies(p->cookies, f);
  unparse_registrations(p->registrations, f);

  if (p->inst) {
    fprintf(f, "    <%s>%s</%s>\n", tag_map[USERLIST_T_INST],
            p->inst, tag_map[USERLIST_T_INST]);
  }
  if (p->instshort) {
    fprintf(f, "    <%s>%s</%s>\n", tag_map[USERLIST_T_INSTSHORT],
            p->instshort, tag_map[USERLIST_T_INSTSHORT]);
  }
  if (p->fac) {
    fprintf(f, "    <%s>%s</%s>\n", tag_map[USERLIST_T_FAC],
            p->fac, tag_map[USERLIST_T_FAC]);
  }
  if (p->facshort) {
    fprintf(f, "    <%s>%s</%s>\n", tag_map[USERLIST_T_FACSHORT],
            p->facshort, tag_map[USERLIST_T_FACSHORT]);
  }
  if (p->homepage) {
    fprintf(f, "    <%s>%s</%s>\n", tag_map[USERLIST_T_HOMEPAGE],
            p->homepage, tag_map[USERLIST_T_HOMEPAGE]);
  }

  unparse_phones(p->phones, f, "    ");
  unparse_members(p->members, f);

  fprintf(f, "  </%s>\n", tag_map[USERLIST_T_USER]);
}

void
userlist_unparse(struct userlist_list *p, FILE *f)
{
  int i;

  if (!p) return;

  fputs("<?xml version=\"1.0\" encoding=\"koi8-r\"?>\n", f);
  fprintf(f, "<%s", tag_map[USERLIST_T_USERLIST]);
  if (p->name && *p->name)
    fprintf(f, " %s=\"%s\"", attn_map[USERLIST_A_NAME], p->name);
  fputs(">\n", f);
  for (i = 1; i < p->user_map_size; i++)
    unparse_user(p->user_map[i], f);
  fprintf(f, "</%s>\n", tag_map[USERLIST_T_USERLIST]);
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "XML_Parser" "XML_Char" "XML_Encoding")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
