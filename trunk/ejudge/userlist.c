/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002,2003 Alexander Chernov <cher@ispras.ru> */

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

#include "userlist.h"
#include "contests.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define _(x) x

struct userlist_list *
userlist_new(void)
{
  struct userlist_list *p = 0;

  p = (struct userlist_list*) xcalloc(1, sizeof(*p));
  p->name = xstrdup("unknown");
  p->user_map_size = 16;
  p->user_map = xcalloc(p->user_map_size, sizeof(p->user_map[0]));
  p->member_serial = 1;
  return p;
}

void
userlist_remove_user(struct userlist_list *lst, struct userlist_user *usr)
{
  ASSERT(lst && lst->b.tag == USERLIST_T_USERLIST);
  ASSERT(usr && usr->b.tag == USERLIST_T_USER);
  ASSERT(usr->id > 0 && usr->id < lst->user_map_size);
  if (!usr->b.left) {
    lst->b.first_down = usr->b.right;
  } else {
    usr->b.left->right = usr->b.right;
  }
  if (!usr->b.right) {
    lst->b.last_down = usr->b.left;
  } else {
    usr->b.right->left = usr->b.left;
  }
  lst->user_map[usr->id] = 0;
  usr->b.up = 0;
  usr->b.left = 0;
  usr->b.right = 0;
  userlist_free((struct xml_tree*) usr);
}

static char const * const member_status_string[] =
{
  "",
  _("School student"),
  _("Student"),
  _("Magistrant"),
  _("PhD student"),
  _("School teacher"),
  _("Professor"),
  _("Scientist"),
  _("Other")
};
unsigned char const *
userlist_member_status_str(int status)
{
  ASSERT(status >= 0 && status <= USERLIST_ST_LAST);
  return member_status_string[status];
}

int
userlist_parse_date(unsigned char const *s, unsigned long *pd)
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
  return -1;
}

unsigned char const *
userlist_unparse_bool(int b)
{
  if (b) return "yes";
  return "no";
}

unsigned char *
userlist_unparse_date(unsigned long d, int show_null)
{
  static unsigned char buf[64];
  struct tm *ptm;

  if (!d) {
    strcpy(buf, "<Not set>");
    return buf;
  }
  ptm = localtime(&d);
  snprintf(buf, sizeof(buf), "%d/%02d/%02d %02d:%02d:%02d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  return buf;
}

int
userlist_parse_bool(unsigned char const *str)
{
  if (!str) return -1;
  if (!strcasecmp(str, "true")
      || !strcasecmp(str, "yes")
      || !strcasecmp(str, "1"))
    return 1;
  
  if (!strcasecmp(str, "false")
      || !strcasecmp(str, "no")
      || !strcasecmp(str, "0"))
    return 0;

  return -1;
}

int
userlist_get_member_field_str(unsigned char *buf, size_t len,
                              struct userlist_member *m, int field_id,
                              int convert_null)
{
  unsigned char *s = 0;

  switch (field_id) {
  case USERLIST_NM_SERIAL:
    return snprintf(buf, len, "%d", m->serial);
  case USERLIST_NM_GRADE:
    return snprintf(buf, len, "%d", m->grade);
  case USERLIST_NM_STATUS:
    return snprintf(buf, len, "%s", userlist_member_status_str(m->status));
  case USERLIST_NM_FIRSTNAME:  s = m->firstname;  break;
  case USERLIST_NM_FIRSTNAME_EN: s = m->firstname_en; break;
  case USERLIST_NM_MIDDLENAME: s = m->middlename; break;
  case USERLIST_NM_MIDDLENAME_EN: s = m->middlename_en; break;
  case USERLIST_NM_SURNAME:    s = m->surname;    break;
  case USERLIST_NM_SURNAME_EN: s = m->surname_en; break;
  case USERLIST_NM_GROUP:      s = m->group;      break;
  case USERLIST_NM_GROUP_EN:   s = m->group_en;   break;
  case USERLIST_NM_OCCUPATION: s = m->occupation; break;
  case USERLIST_NM_OCCUPATION_EN: s = m->occupation_en; break;
  case USERLIST_NM_EMAIL:      s = m->email;      break;
  case USERLIST_NM_HOMEPAGE:   s = m->homepage;   break;
  case USERLIST_NM_INST:       s = m->inst;       break;
  case USERLIST_NM_INST_EN:    s = m->inst_en;    break;
  case USERLIST_NM_INSTSHORT:  s = m->instshort;  break;
  case USERLIST_NM_INSTSHORT_EN: s = m->instshort_en; break;
  case USERLIST_NM_FAC:        s = m->fac;        break;
  case USERLIST_NM_FAC_EN:     s = m->fac_en;     break;
  case USERLIST_NM_FACSHORT:   s = m->facshort;   break;
  case USERLIST_NM_FACSHORT_EN: s = m->facshort_en; break;
  default:
    SWERR(("unhandled field_id: %d", field_id));
  }
  if (!s) {
    if (convert_null) s = "<NULL>";
    else s = "";
  }
  return snprintf(buf, len, "%s", s);
}

int
userlist_delete_member_field(struct userlist_member *m, int field_id)
{
  unsigned char **ps = 0;

  switch (field_id) {
  case USERLIST_NM_GRADE:
    if (!m->grade) return 0;
    m->grade = 0;
    return 1;
  case USERLIST_NM_STATUS:
    if (!m->status) return 0;
    m->status = 0;
    return 1;
  case USERLIST_NM_FIRSTNAME:
    ps = &m->firstname; goto do_text_field;
  case USERLIST_NM_FIRSTNAME_EN:
    ps = &m->firstname_en; goto do_text_field;
  case USERLIST_NM_MIDDLENAME:
    ps = &m->middlename; goto do_text_field;
  case USERLIST_NM_MIDDLENAME_EN:
    ps = &m->middlename_en; goto do_text_field;
  case USERLIST_NM_SURNAME:
    ps = &m->surname; goto do_text_field;
  case USERLIST_NM_SURNAME_EN:
    ps = &m->surname_en; goto do_text_field;
  case USERLIST_NM_GROUP:
    ps = &m->group; goto do_text_field;
  case USERLIST_NM_GROUP_EN:
    ps = &m->group_en; goto do_text_field;
  case USERLIST_NM_OCCUPATION:
    ps = &m->occupation; goto do_text_field;
  case USERLIST_NM_OCCUPATION_EN:
    ps = &m->occupation_en; goto do_text_field;
  case USERLIST_NM_EMAIL:
    ps = &m->email; goto do_text_field;
  case USERLIST_NM_HOMEPAGE:
    ps = &m->homepage; goto do_text_field;
  case USERLIST_NM_INST:
    ps = &m->inst; goto do_text_field;
  case USERLIST_NM_INST_EN:
    ps = &m->inst_en; goto do_text_field;
  case USERLIST_NM_INSTSHORT:
    ps = &m->instshort; goto do_text_field;
  case USERLIST_NM_INSTSHORT_EN:
    ps = &m->instshort_en; goto do_text_field;
  case USERLIST_NM_FAC:
    ps = &m->fac; goto do_text_field;
  case USERLIST_NM_FAC_EN:
    ps = &m->fac_en; goto do_text_field;
  case USERLIST_NM_FACSHORT:
    ps = &m->facshort; goto do_text_field;
  case USERLIST_NM_FACSHORT_EN:
    ps = &m->facshort_en; goto do_text_field;
  do_text_field:
    if (!*ps) return 0;
    xfree(*ps);
    *ps = 0;
    return 1;

  case USERLIST_NM_SERIAL:
  default:
    return -1;
  }
  return -1;
}

int
userlist_set_member_field_str(struct userlist_member *m, int field_id,
                              unsigned char const *field_val)
{
  unsigned char **ps = 0;
  int x, n;
  int updated = 0;

  switch (field_id) {
  case USERLIST_NM_SERIAL:
    return -1;
  case USERLIST_NM_GRADE:
    if (!field_val) {
      x = 0;
    } else {
      if (sscanf(field_val, "%d %n", &x, &n) != 1 || field_val[n]
          || x < 0 || x >= 20) {
        return -1;
      }
    }
    if (x != m->grade) {
      m->grade = x;
      updated = 1;
    }
    return updated;
  case USERLIST_NM_STATUS:
    if (!field_val) {
      x = 0;
    } else {
      if (sscanf(field_val, "%d %n", &x, &n) != 1 || field_val[n]
          || x < 0 || x >= USERLIST_ST_LAST) {
        return -1;
      }
    }
    if (x != m->status) {
      m->status = x;
      updated = 1;
    }
    return updated;
  case USERLIST_NM_FIRSTNAME:  ps = &m->firstname;  break;
  case USERLIST_NM_FIRSTNAME_EN: ps = &m->firstname_en; break;
  case USERLIST_NM_MIDDLENAME: ps = &m->middlename; break;
  case USERLIST_NM_MIDDLENAME_EN: ps = &m->middlename_en; break;
  case USERLIST_NM_SURNAME:    ps = &m->surname;    break;
  case USERLIST_NM_SURNAME_EN: ps = &m->surname_en; break;
  case USERLIST_NM_GROUP:      ps = &m->group;      break;
  case USERLIST_NM_GROUP_EN:   ps = &m->group_en;   break;
  case USERLIST_NM_OCCUPATION: ps = &m->occupation; break;
  case USERLIST_NM_OCCUPATION_EN: ps = &m->occupation_en; break;
  case USERLIST_NM_EMAIL:      ps = &m->email;      break;
  case USERLIST_NM_HOMEPAGE:   ps = &m->homepage;   break;
  case USERLIST_NM_INST:       ps = &m->inst;       break;
  case USERLIST_NM_INST_EN:    ps = &m->inst_en;    break;
  case USERLIST_NM_INSTSHORT:  ps = &m->instshort;  break;
  case USERLIST_NM_INSTSHORT_EN: ps = &m->instshort_en; break;
  case USERLIST_NM_FAC:        ps = &m->fac;        break;
  case USERLIST_NM_FAC_EN:     ps = &m->fac_en;     break;
  case USERLIST_NM_FACSHORT:   ps = &m->facshort;   break;
  case USERLIST_NM_FACSHORT_EN: ps = &m->facshort_en; break;
  default:
    SWERR(("unhandled field_id: %d", field_id));
  }
  if (!ps) return -1;
  if (!*ps && field_val) {
    *ps = xstrdup(field_val);
    updated = 1;
  } else if (*ps && !field_val) { 
    xfree(*ps); *ps = 0;
    updated = 1;
  } else if (*ps && field_val && strcmp(*ps, field_val) != 0) {
    xfree(*ps); *ps = 0;
    *ps = xstrdup(field_val);
    updated = 1;
  }
  return updated;
}

int
userlist_get_user_field_str(unsigned char *buf, size_t len,
                            struct userlist_user *u, int field_id,
                            int convert_null)
{
  unsigned char const *s = 0;

  switch (field_id) {
  case USERLIST_NN_ID:
    return snprintf(buf, len, "%d", u->id);
  case USERLIST_NN_LOGIN: s = u->login; break;
  case USERLIST_NN_EMAIL: s = u->email; break;
  case USERLIST_NN_NAME: s = u->name; break;
  case USERLIST_NN_IS_INVISIBLE:
    s = userlist_unparse_bool(u->is_invisible); break;
  case USERLIST_NN_IS_BANNED:
    s = userlist_unparse_bool(u->is_banned); break;
  case USERLIST_NN_IS_LOCKED:
    s = userlist_unparse_bool(u->is_locked); break;
  case USERLIST_NN_SHOW_LOGIN:
    s = userlist_unparse_bool(u->show_login); break;
  case USERLIST_NN_SHOW_EMAIL:
    s = userlist_unparse_bool(u->show_email); break;
  case USERLIST_NN_USE_COOKIES:
    s = userlist_unparse_bool(u->default_use_cookies); break;
  case USERLIST_NN_READ_ONLY:
    s = userlist_unparse_bool(u->read_only); break;
  case USERLIST_NN_TIMESTAMPS: break;    /* !!! */
  case USERLIST_NN_REG_TIME:
    s = userlist_unparse_date(u->registration_time, convert_null); break;
  case USERLIST_NN_LOGIN_TIME:
    s = userlist_unparse_date(u->last_login_time, convert_null); break;
  case USERLIST_NN_ACCESS_TIME:
    s = userlist_unparse_date(u->last_access_time, convert_null); break;
  case USERLIST_NN_CHANGE_TIME:
    s = userlist_unparse_date(u->last_change_time, convert_null); break;
  case USERLIST_NN_PWD_CHANGE_TIME:
    s = userlist_unparse_date(u->last_pwdchange_time, convert_null); break;
  case USERLIST_NN_MINOR_CHANGE_TIME:
    s = userlist_unparse_date(u->last_minor_change_time, convert_null);break;
  case USERLIST_NN_PASSWORDS: break;     /* !!! */
  case USERLIST_NN_REG_PASSWORD:
    if (u->register_passwd) s = u->register_passwd->b.text;
    break;
  case USERLIST_NN_TEAM_PASSWORD:
    if (u->team_passwd) s = u->team_passwd->b.text;
    break;
  case USERLIST_NN_GENERAL_INFO: break;  /* !!! */
  case USERLIST_NN_INST: s = u->inst; break;
  case USERLIST_NN_INST_EN: s = u->inst_en; break;
  case USERLIST_NN_INSTSHORT: s = u->instshort; break;
  case USERLIST_NN_INSTSHORT_EN: s = u->instshort_en; break;
  case USERLIST_NN_FAC: s = u->fac; break;
  case USERLIST_NN_FAC_EN: s = u->fac_en; break;
  case USERLIST_NN_FACSHORT: s = u->facshort; break;
  case USERLIST_NN_FACSHORT_EN: s = u->facshort_en; break;
  case USERLIST_NN_HOMEPAGE: s = u->homepage; break;
  case USERLIST_NN_CITY: s = u->city; break;
  case USERLIST_NN_CITY_EN: s = u->city_en; break;
  case USERLIST_NN_COUNTRY: s = u->country; break;
  case USERLIST_NN_COUNTRY_EN: s = u->country_en; break;
  }
  if (!s) {
    if (convert_null) s = "<NULL>";
    else s = "";
  }
  return snprintf(buf, len, "%s", s);
}

int
userlist_set_user_field_str(struct userlist_user *u, int field_id,
                            unsigned char const *field_val)
{
  int updated = 0;
  int *iptr;
  int new_ival;
  unsigned char **sptr;

  if (!field_val) field_val = "";

  switch (field_id) {
  case USERLIST_NN_LOGIN:
    if (!*field_val) return -1;
    sptr = &u->login; goto do_text_fields;
  case USERLIST_NN_EMAIL:
    if (!*field_val) return -1;
    sptr = &u->email; goto do_text_fields;
  case USERLIST_NN_NAME:
    sptr = &u->name;
  do_text_fields:
    if (*sptr && !strcmp(*sptr, field_val)) break;
    xfree(*sptr);
    *sptr = xstrdup(field_val);
    updated = 1;
    break;

  case USERLIST_NN_IS_INVISIBLE:
    iptr = &u->is_invisible; goto do_bool_fields;
  case USERLIST_NN_IS_BANNED:
    iptr = &u->is_banned; goto do_bool_fields;
  case USERLIST_NN_IS_LOCKED:
    iptr = &u->is_locked; goto do_bool_fields;
  case USERLIST_NN_SHOW_LOGIN:
    iptr = &u->show_login; goto do_bool_fields;
  case USERLIST_NN_SHOW_EMAIL:
    iptr = &u->show_email; goto do_bool_fields;
  case USERLIST_NN_USE_COOKIES:
    iptr = &u->default_use_cookies; goto do_bool_fields;
  case USERLIST_NN_READ_ONLY:
    iptr = &u->read_only;
  do_bool_fields:
    new_ival = userlist_parse_bool(field_val);
    if (new_ival < 0 || new_ival > 1) return -1;
    if (new_ival == *iptr) break;
    *iptr = new_ival;
    updated = 1;
    break;

  case USERLIST_NN_REG_PASSWORD:
    if (!u->register_passwd) {
      u->register_passwd = (struct userlist_passwd*) userlist_node_alloc(USERLIST_T_PASSWORD);
      xml_link_node_last(&u->b, &u->register_passwd->b);
      u->register_passwd->b.text = xstrdup("");
      u->register_passwd->method = USERLIST_PWD_PLAIN;
      updated = 1;
    }
    if (!strcmp(u->register_passwd->b.text, field_val)) break;
    xfree(u->register_passwd->b.text);
    u->register_passwd->b.text = xstrdup(field_val);
    u->register_passwd->method = USERLIST_PWD_PLAIN;
    updated = 1;
    break;

  case USERLIST_NN_TEAM_PASSWORD:
    if (!u->team_passwd) {
      u->team_passwd = (struct userlist_passwd*) userlist_node_alloc(USERLIST_T_TEAM_PASSWORD);
      xml_link_node_last(&u->b, &u->team_passwd->b);
      u->team_passwd->b.text = xstrdup("");
      u->team_passwd->method = USERLIST_PWD_PLAIN;
      updated = 1;
    }
    if (!strcmp(u->team_passwd->b.text, field_val)) break;
    xfree(u->team_passwd->b.text);
    u->team_passwd->b.text = xstrdup(field_val);
    u->team_passwd->method = USERLIST_PWD_PLAIN;
    updated = 1;
    break;

  case USERLIST_NN_INST:
    sptr = &u->inst; goto do_text_fields;
  case USERLIST_NN_INST_EN:
    sptr = &u->inst_en; goto do_text_fields;
  case USERLIST_NN_INSTSHORT:
    sptr = &u->instshort; goto do_text_fields;
  case USERLIST_NN_INSTSHORT_EN:
    sptr = &u->instshort_en; goto do_text_fields;
  case USERLIST_NN_FAC:
    sptr = &u->fac; goto do_text_fields;
  case USERLIST_NN_FAC_EN:
    sptr = &u->fac_en; goto do_text_fields;
  case USERLIST_NN_FACSHORT:
    sptr = &u->facshort; goto do_text_fields;
  case USERLIST_NN_FACSHORT_EN:
    sptr = &u->facshort_en; goto do_text_fields;
  case USERLIST_NN_HOMEPAGE:
    sptr = &u->homepage; goto do_text_fields;
  case USERLIST_NN_CITY:
    sptr = &u->city; goto do_text_fields;
  case USERLIST_NN_CITY_EN:
    sptr = &u->city_en; goto do_text_fields;
  case USERLIST_NN_COUNTRY:
    sptr = &u->country; goto do_text_fields;
  case USERLIST_NN_COUNTRY_EN:
    sptr = &u->country_en; goto do_text_fields;

  case USERLIST_NN_ID:
  case USERLIST_NN_TIMESTAMPS:
  case USERLIST_NN_REG_TIME:
  case USERLIST_NN_LOGIN_TIME:
  case USERLIST_NN_ACCESS_TIME:
  case USERLIST_NN_CHANGE_TIME:
  case USERLIST_NN_PWD_CHANGE_TIME:
  case USERLIST_NN_MINOR_CHANGE_TIME:
  case USERLIST_NN_PASSWORDS:
  case USERLIST_NN_GENERAL_INFO:
  default:
    return -1;
  }
  return updated;
}

int
userlist_delete_user_field(struct userlist_user *u, int field_id)
{
  unsigned long *tptr;
  int *iptr;
  unsigned char **sptr;
  int retval = -1;

  switch (field_id) {
  case USERLIST_NN_NAME:
    sptr = &u->name;
    if (*sptr && **sptr) retval = 1;
    xfree(*sptr); *sptr = xstrdup("");
    break;

  case USERLIST_NN_IS_INVISIBLE:
    iptr = &u->is_invisible; goto do_flags_delete;
  case USERLIST_NN_IS_BANNED:
    iptr = &u->is_banned; goto do_flags_delete;
  case USERLIST_NN_IS_LOCKED:
    iptr = &u->is_locked; goto do_flags_delete;
  case USERLIST_NN_SHOW_LOGIN:
    iptr = &u->show_login; goto do_flags_delete;
  case USERLIST_NN_SHOW_EMAIL:
    iptr = &u->show_email; goto do_flags_delete;
  case USERLIST_NN_USE_COOKIES:
    iptr = &u->default_use_cookies; goto do_flags_delete;
  case USERLIST_NN_READ_ONLY:
    iptr = &u->read_only;
  do_flags_delete:
    retval = !(*iptr == 0);
    *iptr = 0;
    break;

  case USERLIST_NN_REG_PASSWORD:
    return -1;
#if 0
    if (!u->register_passwd) break;
    if (!u->register_passwd->b.text || !*u->register_passwd->b.text) break;
    xfree(u->register_passwd->b.text);
    u->register_passwd->b.text = xstrdup("");
    break;
#endif

  case USERLIST_NN_TEAM_PASSWORD:
    if (!u->team_passwd) break;
    xml_unlink_node(&u->team_passwd->b);
    userlist_free(&u->team_passwd->b);
    u->team_passwd = 0;
    retval = 1;
    break;

  case USERLIST_NN_INST:
    sptr = &u->inst; goto do_string_delete;
  case USERLIST_NN_INST_EN:
    sptr = &u->inst_en; goto do_string_delete;
  case USERLIST_NN_INSTSHORT:
    sptr = &u->instshort; goto do_string_delete;
  case USERLIST_NN_INSTSHORT_EN:
    sptr = &u->instshort_en; goto do_string_delete;
  case USERLIST_NN_FAC:
    sptr = &u->fac; goto do_string_delete;
  case USERLIST_NN_FAC_EN:
    sptr = &u->fac_en; goto do_string_delete;
  case USERLIST_NN_FACSHORT:
    sptr = &u->facshort; goto do_string_delete;
  case USERLIST_NN_FACSHORT_EN:
    sptr = &u->facshort_en; goto do_string_delete;
  case USERLIST_NN_HOMEPAGE:
    sptr = &u->homepage; goto do_string_delete;
  case USERLIST_NN_CITY:
    sptr = &u->city; goto do_string_delete;
  case USERLIST_NN_CITY_EN:
    sptr = &u->city_en; goto do_string_delete;
  case USERLIST_NN_COUNTRY:
    sptr = &u->country; goto do_string_delete;
  case USERLIST_NN_COUNTRY_EN:
    sptr = &u->country_en; goto do_string_delete;
  do_string_delete:
    retval = !(*sptr == 0);
    xfree(*sptr); *sptr = 0;
    break;

  case USERLIST_NN_REG_TIME:
    tptr = &u->registration_time; goto do_timestamp_delete;
  case USERLIST_NN_LOGIN_TIME:
    tptr = &u->last_login_time; goto do_timestamp_delete;
  case USERLIST_NN_ACCESS_TIME:
    tptr = &u->last_access_time; goto do_timestamp_delete;
  case USERLIST_NN_CHANGE_TIME:
    tptr = &u->last_change_time; goto do_timestamp_delete;
  case USERLIST_NN_PWD_CHANGE_TIME:
    tptr = &u->last_pwdchange_time; goto do_timestamp_delete;
  case USERLIST_NN_MINOR_CHANGE_TIME:
    tptr = &u->last_minor_change_time;
  do_timestamp_delete:
    retval = !(*tptr == 0);
    *tptr = 0;
    break;

  case USERLIST_NN_ID:
  case USERLIST_NN_LOGIN:
  case USERLIST_NN_EMAIL:
  case USERLIST_NN_TIMESTAMPS:
  case USERLIST_NN_PASSWORDS:
  case USERLIST_NN_GENERAL_INFO:
  default:
    return -1;
  }
  return retval;
}


/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

