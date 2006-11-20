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

#include "userlist.h"
#include "contests.h"
#include "pathutl.h"
#include "errlog.h"
#include "tsc.h"
#include "xml_utils.h"
#include "ej_limits.h"

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

const unsigned char *
userlist_unparse_date(time_t d, int convert_null)
{
  static unsigned char buf[64];

  if (!d && convert_null) {
    strcpy(buf, "<Not set>");
    return buf;
  }
  return xml_unparse_date(d);
}

const unsigned char *
userlist_unparse_date_2(unsigned char *buf, size_t size,
                        time_t d, int convert_null)
{
  struct tm *ptm;

  if (!d && convert_null) {
    snprintf(buf, size, "<Not set>");
    return buf;
  }
  ptm = localtime(&d);
  snprintf(buf, size, "%04d/%02d/%02d", ptm->tm_year + 1900,
           ptm->tm_mon + 1, ptm->tm_mday);
  return buf;
}

int
userlist_parse_date_2(const unsigned char *str, time_t *pd)
{
  int year, month, day, n;
  struct tm tt;
  time_t t;

  memset(&tt, 0, sizeof(tt));
  tt.tm_isdst = -1;
  tt.tm_hour = 12;

  if (!str) return -1;
  if (sscanf(str, "%d/%d/%d%n", &year, &month, &day, &n) != 3 || str[n])
    return -1;
  if (year < 1970) return -1;
  if (month < 1 || month > 12) return -1;
  if (day < 1 || day > 31) return -1;
  tt.tm_mday = day;
  tt.tm_mon = month - 1;
  tt.tm_year = year - 1900;
  if ((t = mktime(&tt)) == (time_t) -1) return -1;
  *pd = t;
  return 0;
}

#define MEMBER_OFFSET(f) XOFFSET(struct userlist_member, f)
static int member_field_offsets[] =
{
  [USERLIST_NM_SERIAL] = MEMBER_OFFSET(serial),
  [USERLIST_NM_STATUS] = MEMBER_OFFSET(status),
  [USERLIST_NM_GRADE] = MEMBER_OFFSET(grade),
  [USERLIST_NM_FIRSTNAME] = MEMBER_OFFSET(firstname),
  [USERLIST_NM_FIRSTNAME_EN] = MEMBER_OFFSET(firstname_en),
  [USERLIST_NM_MIDDLENAME] = MEMBER_OFFSET(middlename),
  [USERLIST_NM_MIDDLENAME_EN] = MEMBER_OFFSET(middlename_en),
  [USERLIST_NM_SURNAME] = MEMBER_OFFSET(surname),
  [USERLIST_NM_SURNAME_EN] = MEMBER_OFFSET(surname_en),
  [USERLIST_NM_GROUP] = MEMBER_OFFSET(group),
  [USERLIST_NM_GROUP_EN] = MEMBER_OFFSET(group_en),
  [USERLIST_NM_EMAIL] = MEMBER_OFFSET(email),
  [USERLIST_NM_HOMEPAGE] = MEMBER_OFFSET(homepage),
  [USERLIST_NM_OCCUPATION] = MEMBER_OFFSET(occupation),
  [USERLIST_NM_OCCUPATION_EN] = MEMBER_OFFSET(occupation_en),
  [USERLIST_NM_INST] = MEMBER_OFFSET(inst),
  [USERLIST_NM_INST_EN] = MEMBER_OFFSET(inst_en),
  [USERLIST_NM_INSTSHORT] = MEMBER_OFFSET(instshort),
  [USERLIST_NM_INSTSHORT_EN] = MEMBER_OFFSET(instshort_en),
  [USERLIST_NM_FAC] = MEMBER_OFFSET(fac),
  [USERLIST_NM_FAC_EN] = MEMBER_OFFSET(fac_en),
  [USERLIST_NM_FACSHORT] = MEMBER_OFFSET(facshort),
  [USERLIST_NM_FACSHORT_EN] = MEMBER_OFFSET(facshort_en),
  [USERLIST_NM_PHONE] = MEMBER_OFFSET(phone),
  [USERLIST_NM_CREATE_TIME] = MEMBER_OFFSET(create_time),
  [USERLIST_NM_LAST_CHANGE_TIME] = MEMBER_OFFSET(last_change_time),
  [USERLIST_NM_BIRTH_DATE] = MEMBER_OFFSET(birth_date),
  [USERLIST_NM_ENTRY_DATE] = MEMBER_OFFSET(entry_date),
  [USERLIST_NM_GRADUATE_DATE] = MEMBER_OFFSET(graduate_date),
};

void *
userlist_get_member_field_ptr(const struct userlist_member *ptr, int code)
{
  ASSERT(ptr);
  ASSERT(code >= USERLIST_NM_FIRST && code < USERLIST_NM_LAST);
  return XPDEREF(void, ptr, member_field_offsets[code]);
}

/* type of handling */
static int member_field_types[] =
{
  [USERLIST_NM_SERIAL] = USERLIST_NM_SERIAL,
  [USERLIST_NM_STATUS] = USERLIST_NM_STATUS,
  [USERLIST_NM_GRADE] = USERLIST_NM_GRADE,
  [USERLIST_NM_FIRSTNAME] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_FIRSTNAME_EN] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_MIDDLENAME] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_MIDDLENAME_EN] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_SURNAME] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_SURNAME_EN] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_GROUP] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_GROUP_EN] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_EMAIL] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_HOMEPAGE] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_OCCUPATION] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_OCCUPATION_EN] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_INST] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_INST_EN] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_INSTSHORT] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_INSTSHORT_EN] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_FAC] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_FAC_EN] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_FACSHORT] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_FACSHORT_EN] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_PHONE] = USERLIST_NM_FIRSTNAME,
  [USERLIST_NM_CREATE_TIME] = USERLIST_NM_CREATE_TIME,
  [USERLIST_NM_LAST_CHANGE_TIME] = USERLIST_NM_CREATE_TIME,
  [USERLIST_NM_BIRTH_DATE] = USERLIST_NM_BIRTH_DATE,
  [USERLIST_NM_ENTRY_DATE] = USERLIST_NM_BIRTH_DATE,
  [USERLIST_NM_GRADUATE_DATE] = USERLIST_NM_BIRTH_DATE,
};

int
userlist_is_empty_member_field(const struct userlist_member *m, int field_id)
{
  const int *p_int;
  const unsigned char **p_str;
  const time_t *p_time;

  ASSERT(m);
  ASSERT(field_id >= USERLIST_NM_FIRST && field_id < USERLIST_NM_LAST);

  switch (member_field_types[field_id]) {
  case USERLIST_NM_SERIAL:
    return 0;
  case USERLIST_NM_STATUS:
  case USERLIST_NM_GRADE:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    return (*p_int == 0);
  case USERLIST_NM_FIRSTNAME:
    p_str = (const unsigned char**) userlist_get_member_field_ptr(m, field_id);
    return (*p_str == 0);
  case USERLIST_NM_CREATE_TIME:
    return 0;
  case USERLIST_NM_BIRTH_DATE:
    p_time = (const time_t*) userlist_get_member_field_ptr(m, field_id);
    return (*p_time <= 0);
  default:
    abort();
  }
}

int
userlist_is_equal_member_field(const struct userlist_member *m, int field_id,
                               const unsigned char *value)
{
  unsigned char buf[64];
  const int *p_int;
  const unsigned char **p_str;
  const time_t *p_time;

  ASSERT(m);
  ASSERT(field_id >= USERLIST_NM_FIRST && field_id < USERLIST_NM_LAST);
  switch (member_field_types[field_id]) {
  case USERLIST_NM_SERIAL:
  case USERLIST_NM_STATUS:
  case USERLIST_NM_GRADE:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    if (!value && !*p_int) return 1;
    if (!value) return 0;
    snprintf(buf, sizeof(buf), "%d", *p_int);
    return (strcmp(buf, value) == 0);
  case USERLIST_NM_FIRSTNAME:
    p_str = (const unsigned char**) userlist_get_member_field_ptr(m, field_id);
    if (!value && !*p_str) return 1;
    if (!value || !*p_str) return 0;
    return (strcmp(value, *p_str) == 0);
  case USERLIST_NM_CREATE_TIME:
    p_time = (const time_t*) userlist_get_member_field_ptr(m, field_id);
    if ((!value || !*value) && *p_time == 0) return 1;
    if (!value || !*value) return 0;
    return (strcmp(xml_unparse_date(*p_time), value) == 0);
  case USERLIST_NM_BIRTH_DATE:
    p_time = (const time_t*) userlist_get_member_field_ptr(m, field_id);
    if ((!value || !*value) && *p_time == 0) return 1;
    if (!value || !*value) return 0;
    return (strcmp(userlist_unparse_date_2(buf, sizeof(buf), *p_time, 0),
                   value) == 0);
  default:
    abort();
  }
}

int
userlist_get_member_field_str(unsigned char *buf, size_t len,
                              const struct userlist_member *m, int field_id,
                              int convert_null)
{
  unsigned char dbuf[64];
  const int *p_int;
  const unsigned char **p_str;
  const time_t *p_time;
  const unsigned char *s;

  ASSERT(m);
  ASSERT(field_id >= USERLIST_NM_FIRST && field_id < USERLIST_NM_LAST);
  switch (member_field_types[field_id]) {
  case USERLIST_NM_SERIAL:
  case USERLIST_NM_GRADE:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    return snprintf(buf, len, "%d", *p_int);
  case USERLIST_NM_STATUS:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    return snprintf(buf, len, "%s", userlist_member_status_str(*p_int));
  case USERLIST_NM_FIRSTNAME:
    p_str = (const unsigned char**) userlist_get_member_field_ptr(m, field_id);
    s = *p_str;
    if (!s) {
      if (convert_null) s = "<NULL>";
      else s = "";
    }
    return snprintf(buf, len, "%s", s);
  case USERLIST_NM_CREATE_TIME:
    p_time = (const time_t*) userlist_get_member_field_ptr(m, field_id);
    return snprintf(buf, len, "%s", userlist_unparse_date(*p_time, convert_null));
  case USERLIST_NM_BIRTH_DATE:
    p_time = (const time_t*) userlist_get_member_field_ptr(m, field_id);
    return snprintf(buf, len, "%s",
                    userlist_unparse_date_2(dbuf, sizeof(dbuf),
                                            *p_time, convert_null));
  default:
    abort();
  }
}

int
userlist_delete_member_field(struct userlist_member *m, int field_id)
{
  int *p_int;
  unsigned char **p_str;
  time_t *p_time;

  ASSERT(m);
  ASSERT(field_id >= USERLIST_NM_FIRST && field_id < USERLIST_NM_LAST);
  switch (member_field_types[field_id]) {
  case USERLIST_NM_SERIAL:
    return -1;
  case USERLIST_NM_STATUS:
  case USERLIST_NM_GRADE:
    p_int = (int*) userlist_get_member_field_ptr(m, field_id);
    if (!*p_int) return 0;
    *p_int = 0;
    return 1;
  case USERLIST_NM_FIRSTNAME:
    p_str = (unsigned char**) userlist_get_member_field_ptr(m, field_id);
    if (!*p_str) return 0;
    xfree(*p_str); *p_str = 0;
    return 1;
  case USERLIST_NM_CREATE_TIME:
  case USERLIST_NM_BIRTH_DATE:
    p_time = (time_t*) userlist_get_member_field_ptr(m, field_id);
    if (!*p_time) return 0;
    *p_time = 0;
    return 1;
  default:
    abort();
  }
}

int
userlist_set_member_field_str(struct userlist_member *m, int field_id,
                              unsigned char const *field_val)
{
  int *p_int;
  unsigned char **p_str;
  time_t *p_time;
  int x, n;
  time_t newt;

  ASSERT(m);
  ASSERT(field_id >= USERLIST_NM_FIRST && field_id < USERLIST_NM_LAST);
  switch (member_field_types[field_id]) {
  case USERLIST_NM_SERIAL:
    return -1;
  case USERLIST_NM_STATUS:
    p_int = (int*) userlist_get_member_field_ptr(m, field_id);
    x = 0;
    if (field_val &&
        (sscanf(field_val, "%d%n", &x, &n) != 1 || field_val[n]
         || x < 0 || x >= USERLIST_ST_LAST))
      return -1;
    if (x == *p_int) return 0;
    *p_int = x;
    return 1;
  case USERLIST_NM_GRADE:
    p_int = (int*) userlist_get_member_field_ptr(m, field_id);
    x = 0;
    if (field_val &&
        (sscanf(field_val, "%d%n", &x, &n) != 1 || field_val[n]
         || x < 0 || x >= 100))
      return -1;
    if (x == *p_int) return 0;
    *p_int = x;
    return 1;
  case USERLIST_NM_FIRSTNAME:
    p_str = (unsigned char**) userlist_get_member_field_ptr(m, field_id);
    if (!*p_str && !field_val) return 0;
    if (!field_val) {
      xfree(*p_str); *p_str = 0;
      return 1;
    }
    if (!*p_str) {
      *p_str = xstrdup(field_val);
      return 1;
    }
    if (!strcmp(*p_str, field_val)) return 0;
    xfree(*p_str);
    *p_str = xstrdup(field_val);
    return 1;
  case USERLIST_NM_CREATE_TIME:
    p_time = (time_t*) userlist_get_member_field_ptr(m, field_id);
    if (!*p_time && !field_val) return 0;
    if (!field_val) {
      *p_time = 0;
      return 1;
    }
    if (xml_parse_date(0, 0, 0, field_val, &newt) < 0) return -1;
    if (*p_time == newt) return 0;
    *p_time = newt;
    return 1;
  case USERLIST_NM_BIRTH_DATE:
    p_time = (time_t*) userlist_get_member_field_ptr(m, field_id);
    if (!*p_time && !field_val) return 0;
    if (!field_val) {
      *p_time = 0;
      return 1;
    }
    if (userlist_parse_date_2(field_val, &newt) < 0) return -1;
    if (*p_time == newt) return 0;
    *p_time = newt;
    return 1;
  default:
    abort();
  }
}

#define USER_INFO_OFFSET(f) XOFFSET(struct userlist_user_info, f)
static int user_info_field_offsets[] =
{
  [USERLIST_NC_CNTS_READ_ONLY] = USER_INFO_OFFSET(cnts_read_only),
  [USERLIST_NC_NAME] = USER_INFO_OFFSET(name),
  [USERLIST_NC_TEAM_PASSWD] = USER_INFO_OFFSET(team_passwd),
  [USERLIST_NC_INST] = USER_INFO_OFFSET(inst),
  [USERLIST_NC_INST_EN] = USER_INFO_OFFSET(inst_en),
  [USERLIST_NC_INSTSHORT] = USER_INFO_OFFSET(instshort),
  [USERLIST_NC_INSTSHORT_EN] = USER_INFO_OFFSET(instshort_en),
  [USERLIST_NC_FAC] = USER_INFO_OFFSET(fac),
  [USERLIST_NC_FAC_EN] = USER_INFO_OFFSET(fac_en),
  [USERLIST_NC_FACSHORT] = USER_INFO_OFFSET(facshort),
  [USERLIST_NC_FACSHORT_EN] = USER_INFO_OFFSET(facshort_en),
  [USERLIST_NC_HOMEPAGE] = USER_INFO_OFFSET(homepage),
  [USERLIST_NC_CITY] = USER_INFO_OFFSET(city),
  [USERLIST_NC_CITY_EN] = USER_INFO_OFFSET(city_en),
  [USERLIST_NC_COUNTRY] = USER_INFO_OFFSET(country),
  [USERLIST_NC_COUNTRY_EN] = USER_INFO_OFFSET(country_en),
  [USERLIST_NC_REGION] = USER_INFO_OFFSET(region),
  [USERLIST_NC_LOCATION] = USER_INFO_OFFSET(location),
  [USERLIST_NC_SPELLING] = USER_INFO_OFFSET(spelling),
  [USERLIST_NC_PRINTER_NAME] = USER_INFO_OFFSET(printer_name),
  [USERLIST_NC_LANGUAGES] = USER_INFO_OFFSET(languages),
  [USERLIST_NC_PHONE] = USER_INFO_OFFSET(phone),
  [USERLIST_NC_CREATE_TIME] = USER_INFO_OFFSET(create_time),
  [USERLIST_NC_LAST_LOGIN_TIME] = USER_INFO_OFFSET(last_login_time),
  [USERLIST_NC_LAST_CHANGE_TIME] = USER_INFO_OFFSET(last_change_time),
  [USERLIST_NC_LAST_PWDCHANGE_TIME] = USER_INFO_OFFSET(last_pwdchange_time),
};

void *
userlist_get_user_info_field_ptr(const struct userlist_user_info *ptr, int code)
{
  ASSERT(ptr);
  ASSERT(code >= USERLIST_NC_FIRST && code < USERLIST_NC_LAST);
  return XPDEREF(void, ptr, user_info_field_offsets[code]);
}

static int user_info_field_types[] =
{
  [USERLIST_NC_CNTS_READ_ONLY] = USERLIST_NC_CNTS_READ_ONLY,
  [USERLIST_NC_NAME] = USERLIST_NC_NAME,
  [USERLIST_NC_TEAM_PASSWD] = USERLIST_NC_TEAM_PASSWD,
  [USERLIST_NC_INST] = USERLIST_NC_INST,
  [USERLIST_NC_INST_EN] = USERLIST_NC_INST,
  [USERLIST_NC_INSTSHORT] = USERLIST_NC_INST,
  [USERLIST_NC_INSTSHORT_EN] = USERLIST_NC_INST,
  [USERLIST_NC_FAC] = USERLIST_NC_INST,
  [USERLIST_NC_FAC_EN] = USERLIST_NC_INST,
  [USERLIST_NC_FACSHORT] = USERLIST_NC_INST,
  [USERLIST_NC_FACSHORT_EN] = USERLIST_NC_INST,
  [USERLIST_NC_HOMEPAGE] = USERLIST_NC_INST,
  [USERLIST_NC_CITY] = USERLIST_NC_INST,
  [USERLIST_NC_CITY_EN] = USERLIST_NC_INST,
  [USERLIST_NC_COUNTRY] = USERLIST_NC_INST,
  [USERLIST_NC_COUNTRY_EN] = USERLIST_NC_INST,
  [USERLIST_NC_REGION] = USERLIST_NC_INST,
  [USERLIST_NC_LOCATION] = USERLIST_NC_INST,
  [USERLIST_NC_SPELLING] = USERLIST_NC_INST,
  [USERLIST_NC_PRINTER_NAME] = USERLIST_NC_INST,
  [USERLIST_NC_LANGUAGES] = USERLIST_NC_INST,
  [USERLIST_NC_PHONE] = USERLIST_NC_INST,
  [USERLIST_NC_CREATE_TIME] = USERLIST_NC_CREATE_TIME,
  [USERLIST_NC_LAST_LOGIN_TIME] = USERLIST_NC_CREATE_TIME,
  [USERLIST_NC_LAST_CHANGE_TIME] = USERLIST_NC_CREATE_TIME,
  [USERLIST_NC_LAST_PWDCHANGE_TIME] = USERLIST_NC_CREATE_TIME,
};

int
userlist_is_empty_user_info_field(const struct userlist_user_info *ui,
                                  int field_id)
{
  const int *p_int;
  const unsigned char **p_str;
  const time_t *p_time;

  ASSERT(ui);
  ASSERT(field_id >= USERLIST_NC_FIRST && field_id < USERLIST_NC_LAST);

  switch (user_info_field_types[field_id]) {
  case USERLIST_NC_CNTS_READ_ONLY:
    p_int = (const int*) userlist_get_user_info_field_ptr(ui, field_id);
    return (*p_int == 0);
  case USERLIST_NC_NAME:
    p_str=(const unsigned char**)userlist_get_user_info_field_ptr(ui, field_id);
    return (*p_str == 0 || **p_str == 0);
  case USERLIST_NC_TEAM_PASSWD:
    return (ui->team_passwd == 0);
  case USERLIST_NC_INST:
    p_str=(const unsigned char**)userlist_get_user_info_field_ptr(ui, field_id);
    return (*p_str == 0);
  case USERLIST_NC_CREATE_TIME:
    p_time = (const time_t*) userlist_get_user_info_field_ptr(ui, field_id);
    return (*p_time == 0);
  default:
    abort();
  }
}

int
userlist_is_equal_user_info_field(const struct userlist_user_info *ui,
                                  int field_id,
                                  const unsigned char *value)
{
  const int *p_int;
  const unsigned char **p_str;
  const time_t *p_time;
  unsigned char buf[64];

  ASSERT(ui);
  ASSERT(field_id >= USERLIST_NC_FIRST && field_id < USERLIST_NC_LAST);

  switch (user_info_field_types[field_id]) {
  case USERLIST_NC_CNTS_READ_ONLY:
    p_int = (const int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (!value && !*p_int) return 1;
    if (!value) return 0;
    snprintf(buf, sizeof(buf), "%d", *p_int);
    return (strcmp(buf, value) == 0);
  case USERLIST_NC_NAME:
    p_str=(const unsigned char**)userlist_get_user_info_field_ptr(ui, field_id);
    if ((!value || !*value) && (!*p_str || !**p_str)) return 1;
    if ((!value || !*value) || (!*p_str || !**p_str)) return 0;
    return (strcmp(*p_str, value) == 0);
  case USERLIST_NC_TEAM_PASSWD:
    if (!value && !ui->team_passwd) return 1;
    if (!value || !ui->team_passwd) return 0;
    if (ui->team_passwd_method != USERLIST_PWD_PLAIN) return 0;
    return (strcmp(ui->team_passwd, value) == 0);
  case USERLIST_NC_INST:
    p_str=(const unsigned char**)userlist_get_user_info_field_ptr(ui, field_id);
    if (!value && !*p_str) return 1;
    if (!value || !*p_str) return 0;
    return (strcmp(*p_str, value) == 0);
  case USERLIST_NC_CREATE_TIME:
    p_time = (const time_t*) userlist_get_user_info_field_ptr(ui, field_id);
    if (!value && !*p_time) return 1;
    if (!value) return 0;
    return (strcmp(xml_unparse_date(*p_time), value) == 0);
  default:
    abort();
  }
}

int
userlist_get_user_info_field_str(unsigned char *buf, size_t len,
                                 const struct userlist_user_info *ui,
                                 int field_id,
                                 int convert_null)
{
  const int *p_int;
  const unsigned char **p_str;
  const time_t *p_time;
  const unsigned char *s;

  ASSERT(ui);
  ASSERT(field_id >= USERLIST_NC_FIRST && field_id < USERLIST_NC_LAST);

  switch (user_info_field_types[field_id]) {
  case USERLIST_NC_CNTS_READ_ONLY:
    p_int = (const int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (convert_null) return snprintf(buf, len, "%s", xml_unparse_bool(*p_int));
    return snprintf(buf, len, "%d", *p_int);
  case USERLIST_NC_NAME:
    p_str=(const unsigned char**)userlist_get_user_info_field_ptr(ui, field_id);
    s = *p_str;
    if (!s) s = "";
    return snprintf(buf, len, "%s", s);
  case USERLIST_NC_TEAM_PASSWD:
    s = ui->team_passwd;
    if (!s) {
      if (convert_null) s = "<NULL>";
      else s = "";
    }
    return snprintf(buf, len, "%s", s);
  case USERLIST_NC_INST:
    p_str=(const unsigned char**)userlist_get_user_info_field_ptr(ui, field_id);
    s = *p_str;
    if (!s) {
      if (convert_null) s = "<NULL>";
      else s = "";
    }
    return snprintf(buf, len, "%s", s);
  case USERLIST_NC_CREATE_TIME:
    p_time = (const time_t*) userlist_get_user_info_field_ptr(ui, field_id);
    return snprintf(buf, len, "%s", userlist_unparse_date(*p_time, convert_null));    
  default:
    abort();
  }
}

int
userlist_set_user_info_field_str(struct userlist_user_info *ui,
                                 int field_id,
                                 unsigned char const *field_val)
{
  int *p_int;
  unsigned char **p_str;
  time_t *p_time;
  int x, n;
  time_t newt;

  ASSERT(ui);
  ASSERT(field_id >= USERLIST_NC_FIRST && field_id < USERLIST_NC_LAST);

  if (!field_val) return userlist_delete_user_info_field(ui, field_id);

  switch (user_info_field_types[field_id]) {
  case USERLIST_NC_CNTS_READ_ONLY:
    p_int = (int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (sscanf(field_val, "%d%n", &x, &n) != 1 || field_val[n]
        || x < 0 || x > 1)
      return -1;
    if (*p_int == x) return 0;
    *p_int = x;
    return 1;
  case USERLIST_NC_NAME:
    p_str = (unsigned char**) userlist_get_user_info_field_ptr(ui, field_id);
    if ((!*p_str || !**p_str) && !*field_val) return 0;
    if (!*p_str || !**p_str) {
      xfree(*p_str);
      *p_str = xstrdup(field_val);
      return 1;
    }
    if (!strcmp(*p_str, field_val)) return 0;
    xfree(*p_str);
    *p_str = xstrdup(field_val);
    return 1;
  case USERLIST_NC_TEAM_PASSWD:
    if (!ui->team_passwd) {
      ui->team_passwd = xstrdup(field_val);
      ui->team_passwd_method = USERLIST_PWD_PLAIN;
      return 1;
    }
    if (ui->team_passwd_method == USERLIST_PWD_PLAIN
        && !strcmp(ui->team_passwd, field_val))
      return 0;
    xfree(ui->team_passwd);
    ui->team_passwd = xstrdup(field_val);
    ui->team_passwd_method = USERLIST_PWD_PLAIN;
    return 1;
  case USERLIST_NC_INST:
    p_str = (unsigned char**) userlist_get_user_info_field_ptr(ui, field_id);
    if (!*p_str) {
      *p_str = xstrdup(field_val);
      return 1;
    }
    if (!strcmp(*p_str, field_val)) return 0;
    xfree(*p_str);
    *p_str = xstrdup(field_val);
    return 1;
  case USERLIST_NC_CREATE_TIME:
    p_time = (time_t*) userlist_get_user_info_field_ptr(ui, field_id);
    if (xml_parse_date(0, 0, 0, field_val, &newt) < 0) return -1;
    if (newt == *p_time) return 0;
    *p_time = newt;
    return 1;
  default:
    abort();
  }
}

int
userlist_delete_user_info_field(struct userlist_user_info *ui,
                                int field_id)
{
  int *p_int;
  unsigned char **p_str;
  time_t *p_time;

  ASSERT(ui);
  ASSERT(field_id >= USERLIST_NC_FIRST && field_id < USERLIST_NC_LAST);

  switch (user_info_field_types[field_id]) {
  case USERLIST_NC_CNTS_READ_ONLY:
    p_int = (int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (!*p_int) return 0;
    *p_int = 0;
    return 1;
  case USERLIST_NC_NAME:
    p_str = (unsigned char**) userlist_get_user_info_field_ptr(ui, field_id);
    if (!*p_str || !**p_str) return 0;
    xfree(*p_str);
    *p_str = xstrdup("");
    return 1;
  case USERLIST_NC_TEAM_PASSWD:
    if (!ui->team_passwd) return 0;
    xfree(ui->team_passwd);
    ui->team_passwd = 0;
    ui->team_passwd_method = USERLIST_PWD_PLAIN;
    return 1;
  case USERLIST_NC_INST:
    p_str = (unsigned char**) userlist_get_user_info_field_ptr(ui, field_id);
    if (!*p_str) return 0;
    xfree(*p_str);
    *p_str = 0;
    return 1;
  case USERLIST_NC_CREATE_TIME:
    p_time = (time_t*) userlist_get_user_info_field_ptr(ui, field_id);
    if (!*p_time) return 0;
    *p_time = 0;
    return 1;
  default:
    abort();
  }
}

#define USER_OFFSET(f) XOFFSET(struct userlist_user, f)
static int user_field_offsets[] =
{
  [USERLIST_NN_ID] = USER_OFFSET(id),
  [USERLIST_NN_IS_PRIVILEGED] = USER_OFFSET(is_privileged),
  [USERLIST_NN_IS_INVISIBLE] = USER_OFFSET(is_invisible),
  [USERLIST_NN_IS_BANNED] = USER_OFFSET(is_banned),
  [USERLIST_NN_IS_LOCKED] = USER_OFFSET(is_locked),
  [USERLIST_NN_SHOW_LOGIN] = USER_OFFSET(show_login),
  [USERLIST_NN_SHOW_EMAIL] = USER_OFFSET(show_email),
  [USERLIST_NN_READ_ONLY] = USER_OFFSET(read_only),
  [USERLIST_NN_NEVER_CLEAN] = USER_OFFSET(never_clean),
  [USERLIST_NN_SIMPLE_REGISTRATION] = USER_OFFSET(simple_registration),
  [USERLIST_NN_LOGIN] = USER_OFFSET(login),
  [USERLIST_NN_EMAIL] = USER_OFFSET(email),
  [USERLIST_NN_PASSWD] = USER_OFFSET(passwd),
  [USERLIST_NN_REGISTRATION_TIME] = USER_OFFSET(registration_time),
  [USERLIST_NN_LAST_LOGIN_TIME] = USER_OFFSET(last_login_time),
  [USERLIST_NN_LAST_CHANGE_TIME] = USER_OFFSET(last_change_time),
  [USERLIST_NN_LAST_PWDCHANGE_TIME] = USER_OFFSET(last_pwdchange_time),
};

void *
userlist_get_user_field_ptr(const struct userlist_user *ptr, int code)
{
  ASSERT(ptr);
  ASSERT(code >= USERLIST_NN_FIRST && code < USERLIST_NN_LAST);
  return XPDEREF(void, ptr, user_field_offsets[code]);
}

static int user_field_types[] =
{
  [USERLIST_NN_ID] = USERLIST_NN_ID,
  [USERLIST_NN_IS_PRIVILEGED] = USERLIST_NN_IS_PRIVILEGED,
  [USERLIST_NN_IS_INVISIBLE] = USERLIST_NN_IS_INVISIBLE,
  [USERLIST_NN_IS_BANNED] = USERLIST_NN_IS_INVISIBLE,
  [USERLIST_NN_IS_LOCKED] = USERLIST_NN_IS_INVISIBLE,
  [USERLIST_NN_SHOW_LOGIN] = USERLIST_NN_IS_INVISIBLE,
  [USERLIST_NN_SHOW_EMAIL] = USERLIST_NN_IS_INVISIBLE,
  [USERLIST_NN_READ_ONLY] = USERLIST_NN_IS_INVISIBLE,
  [USERLIST_NN_NEVER_CLEAN] = USERLIST_NN_IS_INVISIBLE,
  [USERLIST_NN_SIMPLE_REGISTRATION] = USERLIST_NN_IS_INVISIBLE,
  [USERLIST_NN_LOGIN] = USERLIST_NN_LOGIN,
  [USERLIST_NN_EMAIL] = USERLIST_NN_EMAIL,
  [USERLIST_NN_PASSWD] = USERLIST_NN_PASSWD,
  [USERLIST_NN_REGISTRATION_TIME] = USERLIST_NN_REGISTRATION_TIME,
  [USERLIST_NN_LAST_LOGIN_TIME] = USERLIST_NN_REGISTRATION_TIME,
  [USERLIST_NN_LAST_CHANGE_TIME] = USERLIST_NN_REGISTRATION_TIME,
  [USERLIST_NN_LAST_PWDCHANGE_TIME] = USERLIST_NN_REGISTRATION_TIME,
};

int
userlist_is_empty_user_field(const struct userlist_user *u, int field_id)
{
  const int *p_int;
  const unsigned char **p_str;
  const time_t *p_time;

  ASSERT(u);
  ASSERT(field_id >= USERLIST_NN_FIRST && field_id < USERLIST_NN_LAST);

  switch (user_field_types[field_id]) {
    // individual fields
  case USERLIST_NN_ID:
  case USERLIST_NN_LOGIN:
    return 0;
  case USERLIST_NN_IS_PRIVILEGED:
    return (u->is_privileged == 0);
  case USERLIST_NN_PASSWD:
    return (u->passwd == 0);
    // mass fields
  case USERLIST_NN_IS_INVISIBLE:
    p_int = (const int*) userlist_get_user_field_ptr(u, field_id);
    return (*p_int == 0);
  case USERLIST_NN_EMAIL:
    p_str = (const unsigned char **) userlist_get_user_field_ptr(u, field_id);
    return (*p_str == 0);
  case USERLIST_NN_REGISTRATION_TIME:
    p_time = (const time_t *) userlist_get_user_field_ptr(u, field_id);
    return (*p_time == 0);
  default:
    abort();
  }
}

int
userlist_is_equal_user_field(const struct userlist_user *u,
                             int field_id,
                             const unsigned char *field_val)
{
  const int *p_int;
  const unsigned char **p_str;
  const time_t *p_time;
  int x, n;
  time_t newt;

  ASSERT(u);
  ASSERT(field_id >= USERLIST_NN_FIRST && field_id < USERLIST_NN_LAST);

  switch (user_field_types[field_id]) {
    // individual fields
  case USERLIST_NN_ID:
    if (sscanf(field_val, "%d%n", &x, &n) != 1 || field_val[n] || x <= 0)
      return 0;
    return (u->id == x);
  case USERLIST_NN_IS_PRIVILEGED:
    if (sscanf(field_val, "%d%n", &x, &n) != 1 || field_val[n]
        || x < 0 || x > 1)
      return 0;
    return (u->is_privileged == x);
  case USERLIST_NN_LOGIN:
    if ((!u->login || !*u->login) && (!field_val || !*field_val)) return 1;
    if ((!u->login || !*u->login) || (!field_val || !*field_val)) return 0;
    return (strcmp(u->login, field_val) == 0);
  case USERLIST_NN_PASSWD:
    if (!u->passwd && !field_val) return 1;
    if (!u->passwd || !field_val) return 0;
    if (u->passwd_method != USERLIST_PWD_PLAIN) return 0;
    return (strcmp(u->passwd, field_val) == 0);
    // mass fields
  case USERLIST_NN_IS_INVISIBLE:
    p_int = (const int*) userlist_get_user_field_ptr(u, field_id);
    if (sscanf(field_val, "%d%n", &x, &n) != 1 || field_val[n]
        || x < 0 || x > 1)
      return 0;
    return (*p_int == x);
  case USERLIST_NN_EMAIL:
    p_str = (const unsigned char **) userlist_get_user_field_ptr(u, field_id);
    if (!*p_str && !field_val) return 1;
    if (!*p_str || !field_val) return 1;
    return (strcmp(*p_str, field_val) == 0);
  case USERLIST_NN_REGISTRATION_TIME:
    p_time = (const time_t *) userlist_get_user_field_ptr(u, field_id);
    if (!*p_time && !field_val) return 1;
    if (!field_val) return 0;
    if (xml_parse_date(0, 0, 0, field_val, &newt) < 0) return 0;
    return (*p_time == newt);
  default:
    abort();
  }
}

int
userlist_get_user_field_str(unsigned char *buf, size_t len,
                            const struct userlist_user *u,
                            int field_id,
                            int convert_null)
{
  const int *p_int;
  const unsigned char **p_str;
  const time_t *p_time;
  const unsigned char *s;

  ASSERT(u);
  ASSERT(field_id >= USERLIST_NN_FIRST && field_id < USERLIST_NN_LAST);

  switch (user_field_types[field_id]) {
    // individual fields
  case USERLIST_NN_ID:
    return snprintf(buf, len, "%d", u->id);
  case USERLIST_NN_IS_PRIVILEGED:
    if (convert_null)
      return snprintf(buf, len, "%s", xml_unparse_bool(u->is_privileged));
    return snprintf(buf, len, "%d", u->is_privileged);
    // mass fields
  case USERLIST_NN_IS_INVISIBLE:
    p_int = (const int*) userlist_get_user_field_ptr(u, field_id);
    if (convert_null)
      return snprintf(buf, len, "%s", xml_unparse_bool(*p_int));
    return snprintf(buf, len, "%d", *p_int);
  case USERLIST_NN_LOGIN:
  case USERLIST_NN_PASSWD:
  case USERLIST_NN_EMAIL:
    p_str = (const unsigned char **) userlist_get_user_field_ptr(u, field_id);
    s = *p_str;
    if (!s) {
      if (convert_null) s = "<NULL>";
      else s = "";
    }
    return snprintf(buf, len, "%s", s);
  case USERLIST_NN_REGISTRATION_TIME:
    p_time = (const time_t *) userlist_get_user_field_ptr(u, field_id);
    return snprintf(buf, len, "%s", userlist_unparse_date(*p_time, convert_null));    
  default:
    abort();
  }
}

int
userlist_set_user_field_str(struct userlist_user *u,
                            int field_id,
                            unsigned char const *field_val)
{
  int *p_int;
  unsigned char **p_str;
  time_t *p_time;
  int x, n;
  time_t newt;

  ASSERT(u);
  ASSERT(field_id >= USERLIST_NN_FIRST && field_id < USERLIST_NN_LAST);

  if (!field_val) return userlist_delete_user_field(u, field_id);

  switch (user_field_types[field_id]) {
    // individual fields
  case USERLIST_NN_ID:
    return -1;
  case USERLIST_NN_PASSWD:
    if (!u->passwd) {
      u->passwd = xstrdup(field_val);
      u->passwd_method = USERLIST_PWD_PLAIN;
      return 1;
    }
    if (u->passwd_method == USERLIST_PWD_PLAIN
        && !strcmp(u->passwd, field_val))
      return 0;
    xfree(u->passwd);
    u->passwd = xstrdup(field_val);
    u->passwd_method = USERLIST_PWD_PLAIN;
    return 1;
    // mass fields
  case USERLIST_NN_IS_INVISIBLE:
  case USERLIST_NN_IS_PRIVILEGED:
    p_int = (int*) userlist_get_user_field_ptr(u, field_id);
    if (sscanf(field_val, "%d%n", &x, &n) != 1 || field_val[n]
        || n < 0 || n > 1)
      return -1;
    if (*p_int == x) return 0;
    *p_int = x;
    return 1;
  case USERLIST_NN_LOGIN:
  case USERLIST_NN_EMAIL:
    p_str = (unsigned char **) userlist_get_user_field_ptr(u, field_id);
    if (!*p_str) {
      *p_str = xstrdup(field_val);
      return 1;
    }
    if (!strcmp(*p_str, field_val)) return 0;
    xfree(*p_str);
    *p_str = xstrdup(field_val);
    return 1;
  case USERLIST_NN_REGISTRATION_TIME:
    p_time = (time_t *) userlist_get_user_field_ptr(u, field_id);
    if (xml_parse_date(0, 0, 0, field_val, &newt) < 0) return 0;
    if (*p_time == newt) return 0;
    *p_time = newt;
    return 1;
  default:
    abort();
  }
}

int
userlist_delete_user_field(struct userlist_user *u, int field_id)
{
  int *p_int;
  unsigned char **p_str;
  time_t *p_time;

  ASSERT(u);
  ASSERT(field_id >= USERLIST_NN_FIRST && field_id < USERLIST_NN_LAST);

  switch (user_field_types[field_id]) {
    // individual fields
  case USERLIST_NN_ID:
  case USERLIST_NN_IS_PRIVILEGED:
  case USERLIST_NN_LOGIN:
    return -1;
  case USERLIST_NN_PASSWD:
    if (!u->passwd) return 0;
    xfree(u->passwd); u->passwd = 0;
    u->passwd_method = USERLIST_PWD_PLAIN;
    return 1;
    // mass fields
  case USERLIST_NN_IS_INVISIBLE:
    p_int = (int*) userlist_get_user_field_ptr(u, field_id);
    if (!*p_int) return 0;
    *p_int = 0;
    return 1;
  case USERLIST_NN_EMAIL:
    p_str = (unsigned char **) userlist_get_user_field_ptr(u, field_id);
    if (!*p_str) return 0;
    xfree(*p_str); *p_str = 0;
    return 1;
  case USERLIST_NN_REGISTRATION_TIME:
    p_time = (time_t *) userlist_get_user_field_ptr(u, field_id);
    if (!*p_time) return 0;
    *p_time = 0;
    return 1;
  default:
    abort();
  }
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

static const int primes[] =
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
      ASSERT(ck->user_id > 0);
      ASSERT(ck->user_id == u->id);
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
              ck->cookie, u->id, p->cookie_hash_table[j]->user_id);
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
userlist_cookie_hash_add(struct userlist_list *p,
                         const struct userlist_cookie *ck)
{
  int i;

  ASSERT(p);
  if (!p->cookie_hash_table) return 0;
  ASSERT(ck);
  ASSERT(ck->b.tag == USERLIST_T_COOKIE);
  ASSERT(ck->cookie);
  ASSERT(ck->user_id > 0);

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
          ck->cookie, ck->user_id, p->cookie_hash_table[i]->user_id);
      return -1;
    }
    i = (i + p->cookie_hash_step) % p->cookie_hash_size;
  }
  p->cookie_hash_table[i] = (struct userlist_cookie*) ck;
  p->cookie_cur_fill++;
  return 0;
}

int
userlist_cookie_hash_del(struct userlist_list *p,
                         const struct userlist_cookie *ck)
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
  ASSERT(ck->user_id > 0);

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

void
userlist_expand_cntsinfo(struct userlist_user *u, int contest_id)
{
  int new_size;
  struct userlist_cntsinfo **new_arr;

  if (contest_id < u->cntsinfo_a) return;

  if (!(new_size = u->cntsinfo_a)) new_size = 32;
  while (contest_id >= new_size) new_size *= 2;
  XCALLOC(new_arr, new_size);
  if (u->cntsinfo_a > 0) {
    memcpy(new_arr, u->cntsinfo, u->cntsinfo_a * sizeof(new_arr[0]));
  }
  xfree(u->cntsinfo);
  u->cntsinfo_a = new_size;
  u->cntsinfo = new_arr;
}

/*
 * if the source string is NULL, also NULL is returned, as opposed
 * to the `xstrdup', which returns "" in case of NULL.
 */
static unsigned char *
copy_field(const unsigned char *s)
{
  if (!s) return 0;
  return xstrdup(s);
}

struct userlist_member *
userlist_clone_member(struct userlist_member *src, int *p_serial,
                      time_t current_time)
{
  struct userlist_member *dst;

  if (!src) return 0;
  ASSERT(src->b.tag == USERLIST_T_MEMBER);

  dst = (struct userlist_member*) userlist_node_alloc(USERLIST_T_MEMBER);

  dst->serial = (*p_serial)++;
  dst->copied_from = src->serial;
  dst->status = src->status;
  dst->grade = src->grade;

  dst->firstname = copy_field(src->firstname);
  dst->firstname_en = copy_field(src->firstname_en);
  dst->middlename = copy_field(src->middlename);
  dst->middlename_en = copy_field(src->middlename_en);
  dst->surname = copy_field(src->surname);
  dst->surname_en = copy_field(src->surname_en);
  dst->group = copy_field(src->group);
  dst->group_en = copy_field(src->group_en);
  dst->email = copy_field(src->email);
  dst->homepage = copy_field(src->homepage);
  dst->phone = copy_field(src->phone);
  dst->occupation = copy_field(src->occupation);
  dst->occupation_en = copy_field(src->occupation_en);
  dst->inst = copy_field(src->inst);
  dst->inst_en = copy_field(src->inst_en);
  dst->instshort = copy_field(src->instshort);
  dst->instshort_en = copy_field(src->instshort_en);
  dst->fac = copy_field(src->fac);
  dst->fac_en = copy_field(src->fac_en);
  dst->facshort = copy_field(src->facshort);
  dst->facshort_en = copy_field(src->facshort_en);

  dst->create_time = current_time;
  dst->last_change_time = current_time;
  dst->last_access_time = 0;
  src->last_access_time = current_time;

  return dst;
}

struct userlist_cntsinfo *
userlist_clone_user_info(struct userlist_user *u, int contest_id,
                         int *p_serial, time_t current_time,
                         int *p_cloned_flag)
{
  struct xml_tree *p;
  struct userlist_cntsinfo *ci;
  struct userlist_members *mm, *ms;
  int mt, i, sz;

  if (p_cloned_flag) *p_cloned_flag = 0;
  if (contest_id <= 0 || contest_id > MAX_CONTEST_ID) return 0;
  if (!u) return 0;
  if (u->cntsinfo && contest_id < u->cntsinfo_a && u->cntsinfo[contest_id])
    return u->cntsinfo[contest_id];

  // ok, needs clone
  // 1. find <cntsinfos> element in the list of childs
  for (p = u->b.first_down; p && p->tag != USERLIST_T_CNTSINFOS; p = p->right);
  if (!p) {
    // <cntsinfos> not found, create a new one
    p = userlist_node_alloc(USERLIST_T_CNTSINFOS);
    xml_link_node_last(&u->b, p);
  }

  ci = (struct userlist_cntsinfo*) userlist_node_alloc(USERLIST_T_CNTSINFO);
  xml_link_node_last(p, &ci->b);

  ci->contest_id = contest_id;

  // NOTE: should we reset the cnts_read_only flag?
  ci->i.cnts_read_only = u->i.cnts_read_only;

  ci->i.name = xstrdup(u->i.name);

  ci->i.inst = copy_field(u->i.inst);
  ci->i.inst_en = copy_field(u->i.inst_en);
  ci->i.instshort = copy_field(u->i.instshort);
  ci->i.instshort_en = copy_field(u->i.instshort_en);
  ci->i.fac = copy_field(u->i.fac);
  ci->i.fac_en = copy_field(u->i.fac_en);
  ci->i.facshort = copy_field(u->i.facshort);
  ci->i.facshort_en = copy_field(u->i.facshort_en);
  ci->i.homepage = copy_field(u->i.homepage);
  ci->i.city = copy_field(u->i.city);
  ci->i.city_en = copy_field(u->i.city_en);
  ci->i.country = copy_field(u->i.country);
  ci->i.country_en = copy_field(u->i.country_en);
  ci->i.region = copy_field(u->i.region);
  ci->i.location = copy_field(u->i.location);
  ci->i.spelling = copy_field(u->i.spelling);
  ci->i.printer_name = copy_field(u->i.printer_name);
  ci->i.languages = copy_field(u->i.languages);
  ci->i.phone = copy_field(u->i.phone);

  ci->i.create_time = current_time;
  ci->i.last_change_time = u->i.last_change_time;
  ci->i.last_access_time = 0;
  ci->i.last_pwdchange_time = u->i.last_pwdchange_time;
  u->i.last_access_time = current_time;

  if (u->i.team_passwd) {
    ci->i.team_passwd = xstrdup(u->i.team_passwd);
    ci->i.team_passwd_method = u->i.team_passwd_method;
  }

  for (mt = 0; mt < USERLIST_MB_LAST; mt++) {
    if (!u->i.members[mt]) continue;
    ms = u->i.members[mt];
    mm = (struct userlist_members*) userlist_node_alloc(USERLIST_T_CONTESTANTS);
    mm->role = mt;
    ci->i.members[mt] = mm;
    xml_link_node_last(&ci->b, &mm->b);

    sz = 1;
    while (sz < ms->total) sz *= 2;
    mm->allocd = sz;
    mm->total = ms->total;
    XCALLOC(mm->members, sz);
    for (i = 0; i < ms->total; i++) {
      mm->members[i] = userlist_clone_member(ms->members[i], p_serial,
                                             current_time);
      xml_link_node_last(&mm->b, &mm->members[i]->b);
    }
  }

  userlist_expand_cntsinfo(u, contest_id);
  u->cntsinfo[contest_id] = ci;

  if (p_cloned_flag) *p_cloned_flag = 1;
  return ci;
}

struct userlist_cntsinfo *
userlist_new_cntsinfo(struct userlist_user *u, int contest_id,
                      time_t current_time)
{
  struct xml_tree *p;
  struct userlist_cntsinfo *ci;

  ASSERT(contest_id > 0 && contest_id <= MAX_CONTEST_ID);
  ASSERT(u);

  if (u->cntsinfo && contest_id < u->cntsinfo_a && u->cntsinfo[contest_id])
    return u->cntsinfo[contest_id];

  // ok, needs clone
  // 1. find <cntsinfos> element in the list of childs
  for (p = u->b.first_down; p && p->tag != USERLIST_T_CNTSINFOS; p = p->right);
  if (!p) {
    // <cntsinfos> not found, create a new one
    p = userlist_node_alloc(USERLIST_T_CNTSINFOS);
    xml_link_node_last(&u->b, p);
  }

  ci = (struct userlist_cntsinfo*) userlist_node_alloc(USERLIST_T_CNTSINFO);
  xml_link_node_last(p, &ci->b);
  userlist_expand_cntsinfo(u, contest_id);
  u->cntsinfo[contest_id] = ci;

  ci->contest_id = contest_id;
  ci->i.create_time = current_time;
  ci->i.last_change_time = current_time;

  return ci;
}

const struct userlist_user_info *
userlist_get_user_info(const struct userlist_user *u, int contest_id)
{
  ASSERT(u);

  if (contest_id > 0 && contest_id < u->cntsinfo_a
      && u->cntsinfo[contest_id])
    return &u->cntsinfo[contest_id]->i;
  return &u->i;
}

struct userlist_user_info *
userlist_get_user_info_nc(struct userlist_user *u, int contest_id)
{
  ASSERT(u);

  if (contest_id > 0 && contest_id < u->cntsinfo_a
      && u->cntsinfo[contest_id])
    return &u->cntsinfo[contest_id]->i;
  return &u->i;
}

const struct userlist_contest *
userlist_get_user_contest(const struct userlist_user *u, int contest_id)
{
  const struct xml_tree *t;
  const struct userlist_contest *c;

  if (!u || !u->contests) return 0;
  for (t = u->contests->first_down; t; t = t->right) {
    c = (const struct userlist_contest*) t;
    if (c->id == contest_id) return c;
  }
  return 0;
}

struct userlist_member *
userlist_get_member_nc(struct userlist_user_info *ui, int serial,
                       int *p_role, int *p_num)
{
  int i, j;
  struct userlist_members *mm;
  struct userlist_member *m;

  if (!ui) return 0;
  if (serial <= 0) return 0;
  for (i = 0; i < USERLIST_MB_LAST; i++) {
    if (!(mm = ui->members[i])) continue;
    for (j = 0; j < mm->total; j++) {
      m = mm->members[j];
      if (m->serial == serial || m->copied_from == serial) {
        if (p_role) *p_role = i;
        if (p_num) *p_num = j;
        return m;
      }
    }
  }
  return 0;
}

void
userlist_clear_copied_from(struct userlist_user_info *ui)
{
  int i, j;
  struct userlist_members *mm;
  struct userlist_member *m;

  if (!ui) return;
  for (i = 0; i < USERLIST_MB_LAST; i++) {
    if (!(mm = ui->members[i])) continue;
    for (j = 0; j < mm->total; j++) {
      m = mm->members[j];
      m->copied_from = 0;
    }
  }
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
