/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

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
#include "pathutl.h"
#include "errlog.h"
#include "tsc.h"

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

  // FIXME: dumb!!!
  if (lst->login_hash_table) {
    if (userlist_build_login_hash(lst) < 0) {
      // FIXME: handle gracefully?
      SWERR(("userlist_build_login_hash failed unexpectedly"));
    }
  }
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
userlist_parse_date(unsigned char const *s, time_t *pd)
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
  return -1;
}

unsigned char const *
userlist_unparse_bool(int b)
{
  if (b) return "yes";
  return "no";
}

unsigned char *
userlist_unparse_date(time_t d, int show_null)
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
  case USERLIST_NM_PHONE:      s = m->phone;      break;
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
  case USERLIST_NM_PHONE:
    ps = &m->phone; goto do_text_field;
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
  case USERLIST_NM_PHONE:      ps = &m->phone;      break;
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
  case USERLIST_NN_IS_PRIVILEGED:
    s = userlist_unparse_bool(u->is_privileged); break;
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
  case USERLIST_NN_NEVER_CLEAN:
    s = userlist_unparse_bool(u->never_clean); break;
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
  case USERLIST_NN_PHONE: s = u->phone; break;
  case USERLIST_NN_CITY: s = u->city; break;
  case USERLIST_NN_CITY_EN: s = u->city_en; break;
  case USERLIST_NN_COUNTRY: s = u->country; break;
  case USERLIST_NN_COUNTRY_EN: s = u->country_en; break;
  case USERLIST_NN_LOCATION: s = u->location; break;
  case USERLIST_NN_SPELLING: s = u->spelling; break;
  case USERLIST_NN_PRINTER_NAME: s = u->printer_name; break;
  case USERLIST_NN_LANGUAGES: s = u->languages; break;
  }
  if (!s) {
    if (convert_null) s = "<NULL>";
    else s = "";
  }
  return snprintf(buf, len, "%s", s);
}

int
userlist_set_user_field_str(struct userlist_list *lst,
                            struct userlist_user *u, int field_id,
                            unsigned char const *field_val)
{
  int updated = 0;
  int *iptr;
  int new_ival, i;
  unsigned char **sptr, *old_login;
  userlist_login_hash_t login_hash;
  struct userlist_user *tmpu;

  if (!field_val) field_val = "";

  switch (field_id) {
  case USERLIST_NN_LOGIN:
    if (!*field_val) return -1;
    if (!lst) {
      sptr = &u->login;
      goto do_text_fields;
    }

    ASSERT(u->login);
    if (!strcmp(u->login, field_val)) break;

    /*
      We cannot simply change `login' field, as it is
      a primary key. We have to ensure its uniqueness.
     */
    if (lst->login_hash_table) {
      login_hash = userlist_login_hash(field_val);
      i = login_hash % lst->login_hash_size;
      while (1) {
        if (!(tmpu = lst->login_hash_table[i])) break;
        if (tmpu != u && tmpu->login_hash == login_hash
            && !strcmp(tmpu->login, field_val)) break;
        i = (i + lst->login_hash_step) % lst->login_hash_size;
      }
      if (lst->login_hash_table[i]) {
        /* new login is not unique */
        return -1;
      }
    } else {
      for (i = 1; i < lst->user_map_size; i++) {
        if (!lst->user_map[i]) continue;
        if (lst->user_map[i] == u) continue;
        if (!strcmp(field_val, lst->user_map[i]->login)) break;
      }
      if (i < lst->user_map_size) {
        /* new login is not unique */
        return -1;
      }
    }

    /* new login is unique */
    old_login = u->login;
    u->login = xstrdup(field_val);

    /* This is dump, however it will work */
    if (userlist_build_login_hash(lst) < 0) {
      SWERR(("userlist_build_login_hash failed unexpectedly"));
    }

    xfree(old_login);
    updated = 1;
    break;
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

  case USERLIST_NN_IS_PRIVILEGED:
    iptr = &u->is_privileged; goto do_bool_fields;
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
    iptr = &u->read_only; goto do_bool_fields;
  case USERLIST_NN_NEVER_CLEAN:
    iptr = &u->never_clean; goto do_bool_fields;
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
  case USERLIST_NN_PHONE:
    sptr = &u->phone; goto do_text_fields;
  case USERLIST_NN_CITY:
    sptr = &u->city; goto do_text_fields;
  case USERLIST_NN_CITY_EN:
    sptr = &u->city_en; goto do_text_fields;
  case USERLIST_NN_COUNTRY:
    sptr = &u->country; goto do_text_fields;
  case USERLIST_NN_COUNTRY_EN:
    sptr = &u->country_en; goto do_text_fields;
  case USERLIST_NN_LOCATION:
    sptr = &u->location; goto do_text_fields;
  case USERLIST_NN_SPELLING:
    sptr = &u->spelling; goto do_text_fields;
  case USERLIST_NN_PRINTER_NAME:
    sptr = &u->printer_name; goto do_text_fields;
  case USERLIST_NN_LANGUAGES:
    sptr = &u->languages; goto do_text_fields;

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
  time_t *tptr;
  int *iptr;
  unsigned char **sptr;
  int retval = -1;

  switch (field_id) {
  case USERLIST_NN_NAME:
    sptr = &u->name;
    if (*sptr && **sptr) retval = 1;
    xfree(*sptr); *sptr = xstrdup("");
    break;

  case USERLIST_NN_IS_PRIVILEGED:
    iptr = &u->is_privileged; goto do_flags_delete;
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
    iptr = &u->read_only; goto do_flags_delete;
  case USERLIST_NN_NEVER_CLEAN:
    iptr = &u->never_clean; goto do_flags_delete;
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
  case USERLIST_NN_PHONE:
    sptr = &u->phone; goto do_string_delete;
  case USERLIST_NN_CITY:
    sptr = &u->city; goto do_string_delete;
  case USERLIST_NN_CITY_EN:
    sptr = &u->city_en; goto do_string_delete;
  case USERLIST_NN_COUNTRY:
    sptr = &u->country; goto do_string_delete;
  case USERLIST_NN_COUNTRY_EN:
    sptr = &u->country_en; goto do_string_delete;
  case USERLIST_NN_LOCATION:
    sptr = &u->location; goto do_string_delete;
  case USERLIST_NN_SPELLING:
    sptr = &u->spelling; goto do_string_delete;
  case USERLIST_NN_PRINTER_NAME:
    sptr = &u->printer_name; goto do_string_delete;
  case USERLIST_NN_LANGUAGES:
    sptr = &u->languages; goto do_string_delete;
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

static const unsigned char id_hash_map[256] =
{
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,64,62,65,
   0, 1, 2, 3, 4, 5, 6, 7, 8, 9,65,65,65,65,65,65,
  65,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
  25,26,27,28,29,30,31,32,33,34,35,65,65,65,65,63,
  65,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,
  51,52,53,54,55,56,57,58,59,60,61,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
  65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,
};

unsigned long
userlist_login_hash(const unsigned char *p)
{
  unsigned long hash = 0;

  if (!p) return 0;
  for (; *p; p++)
    hash = hash * 66 + id_hash_map[*p];
  return hash;
}

static int primes[] =
{
  4099,
  8209,
  16411,
  32771,
  65537,
  131101,
  262147,
  524309,
  1048583,
  0,
};

int
userlist_build_login_hash(struct userlist_list *p)
{
  int i, count, coll_count = 0, j, coll1_count = 0;
  struct userlist_user *u;
  ej_tsc_t tsc1, tsc2;

  if (p->login_hash_table) xfree(p->login_hash_table);
  p->login_hash_table = 0;
  p->login_hash_size = 0;
  p->login_hash_step = 23;

  for (i = 1, count = 0; i < p->user_map_size; i++)
    if (p->user_map[i])
      count++;

  for (i = 0; primes[i] && primes[i] < count * 3; i++);
  if (!primes[i]) {
    err("size of hash table %d is too large", count * 3);
    goto cleanup;
  }
  p->login_hash_size = primes[i];
  p->login_thresh = p->login_hash_size * 2 / 3;
  p->login_cur_fill = count;
  XCALLOC(p->login_hash_table, p->login_hash_size);

  rdtscll(tsc1);
  for (i = 1; i < p->user_map_size; i++) {
    u = p->user_map[i];
    if (!u) continue;
    ASSERT(u->login);
    u->login_hash = userlist_login_hash(u->login);
    j = u->login_hash % p->login_hash_size;
    while (p->login_hash_table[j]) {
      if (!strcmp(u->login, p->login_hash_table[j]->login)) {
        err("duplicated login %s", u->login);
        goto cleanup;
      }
      if (p->login_hash_table[j]->login_hash == u->login_hash) coll1_count++;
      coll_count++;
      j = (j + p->login_hash_step) % p->login_hash_size;
    }
    p->login_hash_table[j] = u;
  }
  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  info("login hashtable: size = %zu, shift = %zu, thresh = %zu, current = %zu",
       p->login_hash_size, p->login_hash_step, p->login_thresh,
       p->login_cur_fill);
  info("login hashtable: collisions = %d, hash collisions = %d",
       coll_count, coll1_count);
  info("login hashtable: time = %llu (us)", tsc2);
  return 0;

 cleanup:
  p->login_hash_size = 0;
  p->login_hash_step = 0;
  p->login_thresh = 0;
  p->login_cur_fill = 0;
  xfree(p->login_hash_table); p->login_hash_table = 0;
  return -1;
}

int
userlist_build_cookie_hash(struct userlist_list *p)
{
  struct userlist_user *u;
  int i, j;
  size_t cookie_count = 0, collision_count = 0;
  struct userlist_cookie *ck;
  ej_tsc_t tsc1, tsc2;

  rdtscll(tsc1);

  p->cookie_hash_size = 0;
  p->cookie_hash_step = 0;
  p->cookie_thresh = 0;
  p->cookie_cur_fill = 0;
  xfree(p->cookie_hash_table);
  p->cookie_hash_table = 0;

  /* count the number of cookies */
  for (i = 1; i < p->user_map_size; i++) {
    if (!(u = p->user_map[i])) continue;
    if (!u->cookies) continue;
    ASSERT(u->cookies->tag == USERLIST_T_COOKIES);
    ck = (struct userlist_cookie*) u->cookies->first_down;
    while (ck) {
      ASSERT(ck->b.tag == USERLIST_T_COOKIE);
      ASSERT(ck->user);
      ASSERT(ck->user == u);
      ASSERT(ck->cookie);
      cookie_count++;
      ck = (struct userlist_cookie*) ck->b.right;
    }
  }

  /* choose hashtable size */
  for (i = 0; primes[i] && primes[i] < cookie_count * 3; i++);
  if (!primes[i]) {
    err("size of hash table %zu is too large", cookie_count * 3);
    goto cleanup;
  }
  p->cookie_hash_size = primes[i];
  p->cookie_hash_step = 37;
  p->cookie_thresh = p->cookie_hash_size * 2 / 3;
  p->cookie_cur_fill = cookie_count;
  XCALLOC(p->cookie_hash_table, p->cookie_hash_size);

  /* insert cookies to hashtable */
  for (i = 1; i < p->user_map_size; i++) {
    if (!(u = p->user_map[i])) continue;
    if (!u->cookies) continue;
    ck = (struct userlist_cookie*) u->cookies->first_down;
    while (ck) {
      j = ck->cookie % p->cookie_hash_size;
      while (p->cookie_hash_table[j]) {
        if (ck->cookie == p->cookie_hash_table[j]->cookie) {
          err("duplicated cookie value %016llx (uids=%d,%d)",
              ck->cookie, u->id, p->cookie_hash_table[j]->user->id);
          goto cleanup;
        }
        collision_count++;
        j = (j + p->cookie_hash_step) % p->cookie_hash_size;
      }
      p->cookie_hash_table[j] = ck;
      ck = (struct userlist_cookie*) ck->b.right;
    }
  }

  rdtscll(tsc2);
  tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;

  info("cookie hashtable: size = %zu, step = %zu, thresh = %zu, current = %zu",
       p->cookie_hash_size, p->cookie_hash_step, p->cookie_thresh,
       p->cookie_cur_fill);
  info("cookie hashtable: collisions = %zu", collision_count);
  info("cookie hashtable: time = %llu (us)", tsc2);

  return 0;

 cleanup:
  p->cookie_hash_size = 0;
  p->cookie_hash_step = 0;
  p->cookie_thresh = 0;
  p->cookie_cur_fill = 0;
  xfree(p->cookie_hash_table);
  p->cookie_hash_table = 0;
  return -1;
}

int
userlist_cookie_hash_add(struct userlist_list *p, struct userlist_cookie *ck)
{
  int i;

  ASSERT(p);
  if (!p->cookie_hash_table) return 0;
  ASSERT(ck);
  ASSERT(ck->b.tag == USERLIST_T_COOKIE);
  ASSERT(ck->cookie);
  ASSERT(ck->user);

  if (p->cookie_cur_fill >= p->cookie_thresh) {
    if (userlist_build_cookie_hash(p) < 0) {
      SWERR(("userlist_build_cookie_hash failed unexpectedly"));
    }
  }

  i = ck->cookie % p->cookie_hash_size;
  while (p->cookie_hash_table[i]) {
    if (p->cookie_hash_table[i] == ck) return 0;
    if (p->cookie_hash_table[i]->cookie == ck->cookie) {
      err("duplicated cookie value %016llx (uids=%d,%d)",
          ck->cookie, ck->user->id, p->cookie_hash_table[i]->user->id);
      return -1;
    }
    i = (i + p->cookie_hash_step) % p->cookie_hash_size;
  }
  p->cookie_hash_table[i] = ck;
  p->cookie_cur_fill++;
  return 0;
}

int
userlist_cookie_hash_del(struct userlist_list *p, struct userlist_cookie *ck)
{
  int i;
  int rehash_count = 0;
  int j;
  struct userlist_cookie **saves;

  ASSERT(p);
  if (!p->cookie_hash_table) return 0;
  ASSERT(ck);
  ASSERT(ck->b.tag == USERLIST_T_COOKIE);
  ASSERT(ck->cookie);
  ASSERT(ck->user);

  i = ck->cookie % p->cookie_hash_size;
  j = -1;
  while (p->cookie_hash_table[i]) {
    if (p->cookie_hash_table[i] == ck) {
      ASSERT(j == -1);
      j = i;
    } else {
      rehash_count++;
    }
    i = (i + p->cookie_hash_step) % p->cookie_hash_size;
  }
  if (j == -1) return 0;
  if (!rehash_count) {
    i = ck->cookie % p->cookie_hash_size;
    ASSERT(p->cookie_hash_table[i] == ck);
    p->cookie_hash_table[i] = 0;
    p->cookie_cur_fill--;
    return 0;
  }

  saves = alloca(rehash_count * sizeof(saves[0]));
  memset(saves, 0, rehash_count * sizeof(saves[0]));
  i = ck->cookie % p->cookie_hash_size;
  j = 0;
  while (p->cookie_hash_table[i]) {
    if (p->cookie_hash_table[i] != ck)
      saves[j++] = p->cookie_hash_table[i];
    p->cookie_hash_table[i] = 0;
    i = (i + p->cookie_hash_step) % p->cookie_hash_size;
  }
  ASSERT(j == rehash_count);

  for (j = 0; j < rehash_count; j++) {
    i = saves[j]->cookie % p->cookie_hash_size;
    while (p->cookie_hash_table[i])
      i = (i + p->cookie_hash_step) % p->cookie_hash_size;
    p->cookie_hash_table[i] = saves[j];
  }

  p->cookie_cur_fill--;
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

