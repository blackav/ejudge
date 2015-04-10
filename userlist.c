/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/userlist.h"
#include "ejudge/contests.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/tsc.h"
#include "ejudge/xml_utils.h"
#include "ejudge/ej_limits.h"
#include "ejudge/win32_compat.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#endif

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

static char const * const gender_string[] =
{
  "",
  _("Male"),
  _("Female"),
};
unsigned char const *
userlist_gender_str(int gender)
{
  ASSERT(gender >= 0 && gender <= 2);
  return gender_string[gender];
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
  //tt.tm_hour = 12;

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
  [USERLIST_NM_GENDER] = MEMBER_OFFSET(gender),
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
  [USERLIST_NM_DISCIPLINE] = MEMBER_OFFSET(discipline),
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
  [USERLIST_NM_GRADUATION_DATE] = MEMBER_OFFSET(graduation_date),
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
  [USERLIST_NM_GENDER] = USERLIST_NM_GENDER,
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
  [USERLIST_NM_DISCIPLINE] = USERLIST_NM_FIRSTNAME,
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
  [USERLIST_NM_GRADUATION_DATE] = USERLIST_NM_BIRTH_DATE,
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
  case USERLIST_NM_GENDER:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    return (*p_int == 0);
  case USERLIST_NM_GRADE:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    return (*p_int < 0);
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
  case USERLIST_NM_GENDER:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    if (!value && !*p_int) return 1;
    if (!value) return 0;
    snprintf(buf, sizeof(buf), "%d", *p_int);
    return (strcmp(buf, value) == 0);
  case USERLIST_NM_GRADE:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    if (!value && *p_int < 0) return 1;
    if (!value || *p_int < 0) return 0;
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
userlist_get_member_field_str(
        unsigned char *buf,
        size_t len,
        const struct userlist_member *m,
        int field_id,
        int convert_null,
        int use_locale)
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
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    return snprintf(buf, len, "%d", *p_int);
  case USERLIST_NM_GRADE:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    if (*p_int < 0 && convert_null) return snprintf(buf,len,"%s", "<Not set>");
    if (*p_int < 0) return snprintf(buf, len, "%s", "");
    return snprintf(buf, len, "%d", *p_int);
  case USERLIST_NM_STATUS:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    s = userlist_member_status_str(*p_int);
#if CONF_HAS_LIBINTL - 0 == 1
    if (use_locale) s = gettext(s);
#endif
    return snprintf(buf, len, "%s", s);
  case USERLIST_NM_GENDER:
    p_int = (const int*) userlist_get_member_field_ptr(m, field_id);
    s = userlist_gender_str(*p_int);
#if CONF_HAS_LIBINTL - 0 == 1
    if (use_locale) s = gettext(s);
#endif
    return snprintf(buf, len, "%s", s);
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
  case USERLIST_NM_GENDER:
    p_int = (int*) userlist_get_member_field_ptr(m, field_id);
    if (!*p_int) return 0;
    *p_int = 0;
    return 1;
  case USERLIST_NM_GRADE:
    p_int = (int*) userlist_get_member_field_ptr(m, field_id);
    if (*p_int < 0) return 0;
    *p_int = -1;
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
  unsigned char *buf;
  int buflen;
  char *eptr;

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
  case USERLIST_NM_GENDER:
    p_int = (int*) userlist_get_member_field_ptr(m, field_id);
    x = 0;
    if (field_val &&
        (sscanf(field_val, "%d%n", &x, &n) != 1 || field_val[n]
         || x < 0 || x > 2))
      return -1;
    if (x == *p_int) return 0;
    *p_int = x;
    return 1;
  case USERLIST_NM_GRADE:
    p_int = (int*) userlist_get_member_field_ptr(m, field_id);
    if (!field_val) {
      if (*p_int < 0) return 0;
      *p_int = -1;
      return 1;
    }
    buflen = strlen(field_val);
    buf = (unsigned char*) alloca(buflen + 1);
    strcpy(buf, field_val);
    while (buflen > 0 && isspace(buf[buflen - 1])) buflen--;
    buf[buflen] = 0;
    if (!buf[0]) {
      if (*p_int < 0) return 0;
      *p_int = -1;
      return 1;
    }
    errno = 0;
    x = strtol(buf, &eptr, 10);
    if (errno || *eptr || x < -1 || x >= 100) return -1;
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
    if (xml_parse_date(NULL, 0, 0, 0, field_val, &newt) < 0) return -1;
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
  [USERLIST_NC_INSTNUM] = USER_INFO_OFFSET(instnum),
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
  [USERLIST_NC_AREA] = USER_INFO_OFFSET(area),
  [USERLIST_NC_ZIP] = USER_INFO_OFFSET(zip),
  [USERLIST_NC_STREET] = USER_INFO_OFFSET(street),
  [USERLIST_NC_LOCATION] = USER_INFO_OFFSET(location),
  [USERLIST_NC_SPELLING] = USER_INFO_OFFSET(spelling),
  [USERLIST_NC_PRINTER_NAME] = USER_INFO_OFFSET(printer_name),
  [USERLIST_NC_EXAM_ID] = USER_INFO_OFFSET(exam_id),
  [USERLIST_NC_EXAM_CYPHER] = USER_INFO_OFFSET(exam_cypher),
  [USERLIST_NC_LANGUAGES] = USER_INFO_OFFSET(languages),
  [USERLIST_NC_PHONE] = USER_INFO_OFFSET(phone),
  [USERLIST_NC_FIELD0] = USER_INFO_OFFSET(field0),
  [USERLIST_NC_FIELD1] = USER_INFO_OFFSET(field1),
  [USERLIST_NC_FIELD2] = USER_INFO_OFFSET(field2),
  [USERLIST_NC_FIELD3] = USER_INFO_OFFSET(field3),
  [USERLIST_NC_FIELD4] = USER_INFO_OFFSET(field4),
  [USERLIST_NC_FIELD5] = USER_INFO_OFFSET(field5),
  [USERLIST_NC_FIELD6] = USER_INFO_OFFSET(field6),
  [USERLIST_NC_FIELD7] = USER_INFO_OFFSET(field7),
  [USERLIST_NC_FIELD8] = USER_INFO_OFFSET(field8),
  [USERLIST_NC_FIELD9] = USER_INFO_OFFSET(field9),
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
  [USERLIST_NC_INSTNUM] = USERLIST_NC_INSTNUM,
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
  [USERLIST_NC_AREA] = USERLIST_NC_INST,
  [USERLIST_NC_ZIP] = USERLIST_NC_INST,
  [USERLIST_NC_STREET] = USERLIST_NC_INST,
  [USERLIST_NC_LOCATION] = USERLIST_NC_INST,
  [USERLIST_NC_SPELLING] = USERLIST_NC_INST,
  [USERLIST_NC_PRINTER_NAME] = USERLIST_NC_INST,
  [USERLIST_NC_EXAM_ID] = USERLIST_NC_INST,
  [USERLIST_NC_EXAM_CYPHER] = USERLIST_NC_INST,
  [USERLIST_NC_LANGUAGES] = USERLIST_NC_INST,
  [USERLIST_NC_PHONE] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD0] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD1] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD2] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD3] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD4] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD5] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD6] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD7] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD8] = USERLIST_NC_INST,
  [USERLIST_NC_FIELD9] = USERLIST_NC_INST,
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

  if (!ui) return 1;
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
  case USERLIST_NC_INSTNUM:
    p_int = (const int*) userlist_get_user_info_field_ptr(ui, field_id);
    return (*p_int < 0);
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
  unsigned char buf[64];
  int v_int;
  const unsigned char *v_str;
  time_t v_time;

  ASSERT(field_id >= USERLIST_NC_FIRST && field_id < USERLIST_NC_LAST);

  switch (user_info_field_types[field_id]) {
  case USERLIST_NC_CNTS_READ_ONLY:
    v_int = 0;
    if (ui) v_int = *(int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (!value && !v_int) return 1;
    if (!value) return 0;
    snprintf(buf, sizeof(buf), "%d", v_int);
    return (strcmp(buf, value) == 0);
  case USERLIST_NC_NAME:
    v_str = 0;
    if (ui) {
      v_str=*(const unsigned char**)userlist_get_user_info_field_ptr(ui, field_id);
    }
    if ((!value || !*value) && (!v_str || !*v_str)) return 1;
    if ((!value || !*value) || (!v_str || !*v_str)) return 0;
    return (strcmp(v_str, value) == 0);
  case USERLIST_NC_TEAM_PASSWD:
    v_str = 0;
    if (ui) v_str = ui->team_passwd;
    if (!value && !v_str) return 1;
    if (!value || !v_str) return 0;
    if (!ui) return 0;
    if (ui->team_passwd_method != USERLIST_PWD_PLAIN) return 0;
    return (strcmp(v_str, value) == 0);
  case USERLIST_NC_INST:
    v_str = 0;
    if (ui) {
      v_str=*(const unsigned char**)userlist_get_user_info_field_ptr(ui, field_id);
    }
    if (!value && !v_str) return 1;
    if (!value || !v_str) return 0;
    return (strcmp(v_str, value) == 0);
  case USERLIST_NC_INSTNUM:
    v_int = -1;
    if (ui) v_int = *(int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (!value && v_int < 0) return 1;
    if (!value || v_int < 0) return 0;
    snprintf(buf, sizeof(buf), "%d", v_int);
    return (strcmp(buf, value) == 0);
  case USERLIST_NC_CREATE_TIME:
    v_time = 0;
    if (ui) v_time = *(time_t*) userlist_get_user_info_field_ptr(ui, field_id);
    if (!value && !v_time) return 1;
    if (!value) return 0;
    return (strcmp(xml_unparse_date(v_time), value) == 0);
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
  int v_int;
  const unsigned char *v_str;
  time_t v_time;

  ASSERT(field_id >= USERLIST_NC_FIRST && field_id < USERLIST_NC_LAST);

  switch (user_info_field_types[field_id]) {
  case USERLIST_NC_CNTS_READ_ONLY:
    v_int = 0;
    if (ui) v_int = *(int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (convert_null) return snprintf(buf, len, "%s", xml_unparse_bool(v_int));
    return snprintf(buf, len, "%d", v_int);
  case USERLIST_NC_NAME:
    v_str = 0;
    if (ui) {
      v_str=*(const unsigned char**)userlist_get_user_info_field_ptr(ui,field_id);
    }
    if (!v_str) v_str = "";
    return snprintf(buf, len, "%s", v_str);
  case USERLIST_NC_TEAM_PASSWD:
    v_str = 0;
    if (ui) v_str = ui->team_passwd;
    if (!v_str) {
      if (convert_null) v_str = "<NULL>";
      else v_str = "";
    }
    return snprintf(buf, len, "%s", v_str);
  case USERLIST_NC_INST:
    v_str = 0;
    if (ui) {
      v_str=*(const unsigned char**)userlist_get_user_info_field_ptr(ui, field_id);
    }
    if (!v_str) {
      if (convert_null) v_str = "<NULL>";
      else v_str = "";
    }
    return snprintf(buf, len, "%s", v_str);
  case USERLIST_NC_INSTNUM:
    v_int = -1;
    if (ui) v_int = *(int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (convert_null && v_int < 0) return snprintf(buf, len, "<Not set>");
    if (v_int < 0) return snprintf(buf, len, "%s", "");
    return snprintf(buf, len, "%d", v_int);
  case USERLIST_NC_CREATE_TIME:
    v_time = 0;
    if (ui) v_time = *(time_t*) userlist_get_user_info_field_ptr(ui, field_id);
    return snprintf(buf,len,"%s",userlist_unparse_date(v_time,convert_null));
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
  unsigned char *buf;
  char *eptr;
  int buflen;

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
  case USERLIST_NC_INSTNUM:
    p_int = (int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (*p_int < 0 && !field_val) return 0;
    if (!field_val) {
      *p_int = -1;
      return 1;
    }
    buflen = strlen(field_val);
    buf = (unsigned char*) alloca(buflen + 1);
    strcpy(buf, field_val);
    while (buflen > 0 && isspace(buf[buflen - 1])) buflen--;
    buf[buflen] = 0;
    if (*p_int < 0 && !buf[0]) return 0;
    if (!buf[0]) {
      *p_int = -1;
      return 1;
    }
    errno = 0;
    x = strtol(buf, &eptr, 10);
    if (errno || *eptr || x < 0) return -1;
    if (*p_int == x) return 0;
    *p_int = x;
    return 1;
  case USERLIST_NC_CREATE_TIME:
    p_time = (time_t*) userlist_get_user_info_field_ptr(ui, field_id);
    if (xml_parse_date(NULL, 0, 0, 0, field_val, &newt) < 0) return -1;
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
  case USERLIST_NC_INSTNUM:
    p_int = (int*) userlist_get_user_info_field_ptr(ui, field_id);
    if (*p_int < 0) return 0;
    *p_int = -1;
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
    if (xml_parse_date(NULL, 0, 0, 0, field_val, &newt) < 0) return 0;
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
    if (xml_parse_date(NULL, 0, 0, 0, field_val, &newt) < 0) return 0;
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
  2097169,
  4194319,
  8388617,
  16777259,
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
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

  info("login hashtable: size = %" EJ_PRINTF_ZSPEC "u, shift = %" EJ_PRINTF_ZSPEC "u, thresh = %" EJ_PRINTF_ZSPEC "u, current = %" EJ_PRINTF_ZSPEC "u",
       EJ_PRINTF_ZCAST(p->login_hash_size), EJ_PRINTF_ZCAST(p->login_hash_step),
       EJ_PRINTF_ZCAST(p->login_thresh), EJ_PRINTF_ZCAST(p->login_cur_fill));
  info("login hashtable: collisions = %d, hash collisions = %d",
       coll_count, coll1_count);
  info("login hashtable: time = %" EJ_PRINTF_LLSPEC "u (us)", tsc2);
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
  size_t cookie_count = 0, collision_count = 0, key_collision_count = 0;
  struct userlist_cookie *ck;
  ej_tsc_t tsc1, tsc2;

  rdtscll(tsc1);

  p->cookie_hash_size = 0;
  p->cookie_hash_step = 0;
  p->cookie_thresh = 0;
  p->cookie_cur_fill = 0;
  xfree(p->cookie_hash_table);
  p->cookie_hash_table = 0;

  p->client_key_hash_size = 0;
  p->client_key_hash_step = 0;
  p->client_key_thresh = 0;
  p->client_key_cur_fill = 0;
  xfree(p->client_key_hash_table);
  p->client_key_hash_table = NULL;

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
    err("size of hash table %" EJ_PRINTF_ZSPEC "u is too large", EJ_PRINTF_ZCAST(cookie_count * 3));
    goto cleanup;
  }
  p->cookie_hash_size = primes[i];
  p->cookie_hash_step = 37;
  p->cookie_thresh = p->cookie_hash_size * 2 / 3;
  p->cookie_cur_fill = cookie_count;
  XCALLOC(p->cookie_hash_table, p->cookie_hash_size);

  p->client_key_hash_size = primes[i];
  p->client_key_hash_step = 37;
  p->client_key_thresh = p->client_key_hash_size * 2 / 3;
  p->client_key_cur_fill = 0;
  XCALLOC(p->client_key_hash_table, p->client_key_hash_size);

  /* insert cookies to hashtable */
  for (i = 1; i < p->user_map_size; i++) {
    if (!(u = p->user_map[i])) continue;
    if (!u->cookies) continue;
    ck = (struct userlist_cookie*) u->cookies->first_down;
    while (ck) {
      j = ck->cookie % p->cookie_hash_size;
      while (p->cookie_hash_table[j]) {
        if (ck->cookie == p->cookie_hash_table[j]->cookie) {
          err("duplicated cookie value %016" EJ_PRINTF_LLSPEC "x (uids=%d,%d)",
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

  /* insert client_key to hashtable */
  for (i = 1; i < p->user_map_size; ++i) {
    if (!(u = p->user_map[i])) continue;
    if (!u->cookies) continue;
    for (ck = (struct userlist_cookie*) u->cookies->first_down; ck; ck = (struct userlist_cookie*) ck->b.right) {
      if (ck->client_key != 0) {
        j = ck->client_key % p->client_key_hash_size;
        while (p->client_key_hash_table[j]) {
          j = (j + p->client_key_hash_step) % p->client_key_hash_size;
          ++key_collision_count;
        }
        p->client_key_hash_table[j] = ck;
        ++p->client_key_cur_fill;
      }
    }
  }

  rdtscll(tsc2);
  if (cpu_frequency > 0) {
    tsc2 = (tsc2 - tsc1) * 1000000 / cpu_frequency;
  } else {
    tsc2 = tsc2 - tsc1;
  }

  info("cookie hashtable: size = %" EJ_PRINTF_ZSPEC "u, step = %" EJ_PRINTF_ZSPEC "u, thresh = %" EJ_PRINTF_ZSPEC "u, current = %" EJ_PRINTF_ZSPEC "u",
       EJ_PRINTF_ZCAST(p->cookie_hash_size), EJ_PRINTF_ZCAST(p->cookie_hash_step),
       EJ_PRINTF_ZCAST(p->cookie_thresh), EJ_PRINTF_ZCAST(p->cookie_cur_fill));
  info("cookie hashtable: collisions = %" EJ_PRINTF_ZSPEC "u", EJ_PRINTF_ZCAST(collision_count));

  info("client_key_hashtable: size = %d, step = %d, thresh = %d, current = %d, collisions = %d",
       (int) p->client_key_hash_size, (int) p->client_key_hash_step, (int) p->client_key_thresh, (int) p->client_key_cur_fill,
       (int) key_collision_count);

  info("cookie hashtable: time = %" EJ_PRINTF_LLSPEC "u (us)", tsc2);

  return 0;

 cleanup:
  p->cookie_hash_size = 0;
  p->cookie_hash_step = 0;
  p->cookie_thresh = 0;
  p->cookie_cur_fill = 0;
  xfree(p->cookie_hash_table);
  p->cookie_hash_table = 0;

  p->client_key_hash_size = 0;
  p->client_key_hash_step = 0;
  p->client_key_thresh = 0;
  p->client_key_cur_fill = 0;
  xfree(p->client_key_hash_table);
  p->client_key_hash_table = 0;

  return -1;
}

int
userlist_cookie_hash_add(
        struct userlist_list *p,
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
      err("duplicated cookie value %016" EJ_PRINTF_LLSPEC "x (uids=%d,%d)",
          ck->cookie, ck->user_id, p->cookie_hash_table[i]->user_id);
      return -1;
    }
    i = (i + p->cookie_hash_step) % p->cookie_hash_size;
  }
  p->cookie_hash_table[i] = (struct userlist_cookie*) ck;
  p->cookie_cur_fill++;

  if (ck->client_key != 0) {
    i = ck->client_key % p->client_key_hash_size;
    while (p->client_key_hash_table[i]) {
      i = (i + p->client_key_hash_step) % p->client_key_hash_size;
    }
    p->client_key_hash_table[i] = (struct userlist_cookie *) ck;
    ++p->client_key_cur_fill;
  }

  return 0;
}

static void
delete_cookie(
        struct userlist_list *p,
        const struct userlist_cookie *ck)
{
  int i = ck->cookie % p->cookie_hash_size;
  int j = -1;
  struct userlist_cookie **saves = NULL;
  int rehash_count = 0;

  while (p->cookie_hash_table[i]) {
    if (p->cookie_hash_table[i] == ck) {
      ASSERT(j == -1);
      j = i;
    } else {
      rehash_count++;
    }
    i = (i + p->cookie_hash_step) % p->cookie_hash_size;
  }
  if (j == -1) return;
  if (!rehash_count) {
    i = ck->cookie % p->cookie_hash_size;
    ASSERT(p->cookie_hash_table[i] == ck);
    p->cookie_hash_table[i] = 0;
    p->cookie_cur_fill--;
    return;
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
}

static void
delete_client_key(
        struct userlist_list *p,
        const struct userlist_cookie *ck)
{
  if (!ck->client_key) return;

  int rehash_count = 0;
  int i = ck->client_key % p->client_key_hash_size;
  int j = -1;

  while (p->client_key_hash_table[i]) {
    if (p->client_key_hash_table[i] == ck) {
      j = i;
    } else {
      ++rehash_count;
    }
    i = (i + p->client_key_hash_step) % p->client_key_hash_size;
  }
  if (j == -1) return;
  if (!rehash_count) {
    i = ck->client_key % p->client_key_hash_size;
    p->client_key_hash_table[i] = NULL;
    --p->client_key_cur_fill;
    return;
  }

  struct userlist_cookie **saves = alloca(rehash_count * sizeof(saves[0]));
  memset(saves, 0, rehash_count * sizeof(saves[0]));
  i = ck->client_key % p->client_key_hash_size;
  j = 0;
  while (p->client_key_hash_table[i]) {
    if (p->client_key_hash_table[i] != ck)
      saves[j++] = p->client_key_hash_table[i];
    p->client_key_hash_table[i] = 0;
    i = (i + p->client_key_hash_step) % p->client_key_hash_size;
  }

  for (j = 0; j < rehash_count; ++j) {
    i = saves[j]->client_key % p->client_key_hash_size;
    while (p->client_key_hash_table[i])
      i = (i + p->client_key_hash_step) % p->client_key_hash_size;
    p->client_key_hash_table[i] = saves[j];
  }
  --p->client_key_cur_fill;
}

int
userlist_cookie_hash_del(
        struct userlist_list *p,
        const struct userlist_cookie *ck)
{
  ASSERT(p);
  if (!p->cookie_hash_table) return 0;
  ASSERT(ck);
  ASSERT(ck->b.tag == USERLIST_T_COOKIE);
  ASSERT(ck->cookie);
  ASSERT(ck->user_id > 0);

  delete_cookie(p, ck);
  delete_client_key(p, ck);

  return 0;
}

void
userlist_expand_cntsinfo(struct userlist_user *u, int contest_id)
{
  int new_size;
  struct userlist_user_info **new_arr;

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

struct userlist_user_info *
userlist_new_cntsinfo(struct userlist_user *u, int contest_id,
                      time_t current_time)
{
  struct xml_tree *p;
  struct userlist_user_info *ui;

  ASSERT(contest_id > 0 && contest_id <= EJ_MAX_CONTEST_ID);
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

  ui = (struct userlist_user_info*) userlist_node_alloc(USERLIST_T_CNTSINFO);
  xml_link_node_last(p, &ui->b);
  userlist_expand_cntsinfo(u, contest_id);
  u->cntsinfo[contest_id] = ui;

  ui->contest_id = contest_id;
  ui->instnum = -1;
  ui->create_time = current_time;
  ui->last_change_time = current_time;

  return ui;
}

const struct userlist_user_info *
userlist_get_user_info(const struct userlist_user *u, int contest_id)
{
  ASSERT(u);

  if (contest_id > 0 && contest_id < u->cntsinfo_a
      && u->cntsinfo[contest_id])
    return u->cntsinfo[contest_id];
  return u->cnts0;
}

struct userlist_user_info *
userlist_get_user_info_nc(struct userlist_user *u, int contest_id)
{
  ASSERT(u);

  if (contest_id > 0 && contest_id < u->cntsinfo_a
      && u->cntsinfo[contest_id])
    return u->cntsinfo[contest_id];
  return u->cnts0;
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
userlist_get_member_nc(
        struct userlist_members *mm,
        int serial,
        int *p_role,
        int *p_num)
{
  int i;
  struct userlist_member *m;
  int role_num[USERLIST_MB_LAST];

  memset(role_num, 0, sizeof(role_num));
  if (serial <= 0) return 0;
  if (!mm) return 0;
  for (i = 0; i < mm->u; i++) {
    if (!(m = mm->m[i])) continue;
    ASSERT(m->team_role >= 0 && m->team_role < USERLIST_MB_LAST);
    if (m->serial == serial || m->copied_from == serial) {
      if (p_role) *p_role = m->team_role;
      if (p_num) *p_num = role_num[m->team_role];
      return m;
    }
    role_num[m->team_role]++;
  }
  return 0;
}

void
userlist_clear_copied_from(struct userlist_members *mm)
{
  int i;
  struct userlist_member *m;

  if (!mm) return;
  for (i = 0; i < mm->u; i++)
    if ((m = mm->m[i]))
      m->copied_from = 0;
}

static const int user_to_contest_field_map[USERLIST_NM_LAST] =
{
  [USERLIST_NC_INST] = CONTEST_F_INST,
  [USERLIST_NC_INST_EN] = CONTEST_F_INST_EN,
  [USERLIST_NC_INSTSHORT] = CONTEST_F_INSTSHORT,
  [USERLIST_NC_INSTSHORT_EN] = CONTEST_F_INSTSHORT_EN,
  [USERLIST_NC_INSTNUM] = CONTEST_F_INSTNUM,
  [USERLIST_NC_FAC] = CONTEST_F_FAC,
  [USERLIST_NC_FAC_EN] = CONTEST_F_FAC_EN,
  [USERLIST_NC_FACSHORT] = CONTEST_F_FACSHORT,
  [USERLIST_NC_FACSHORT_EN] = CONTEST_F_FACSHORT_EN,
  [USERLIST_NC_HOMEPAGE] = CONTEST_F_HOMEPAGE,
  [USERLIST_NC_CITY] = CONTEST_F_CITY,
  [USERLIST_NC_CITY_EN] = CONTEST_F_CITY_EN,
  [USERLIST_NC_COUNTRY] = CONTEST_F_COUNTRY,
  [USERLIST_NC_COUNTRY_EN] = CONTEST_F_COUNTRY_EN,
  [USERLIST_NC_REGION] = CONTEST_F_REGION,
  [USERLIST_NC_AREA] = CONTEST_F_AREA,
  [USERLIST_NC_ZIP] = CONTEST_F_ZIP,
  [USERLIST_NC_STREET] = CONTEST_F_STREET,
  [USERLIST_NC_LANGUAGES] = CONTEST_F_LANGUAGES,
  [USERLIST_NC_PHONE] = CONTEST_F_PHONE,
  [USERLIST_NC_FIELD0] = CONTEST_F_FIELD0,
  [USERLIST_NC_FIELD1] = CONTEST_F_FIELD1,
  [USERLIST_NC_FIELD2] = CONTEST_F_FIELD2,
  [USERLIST_NC_FIELD3] = CONTEST_F_FIELD3,
  [USERLIST_NC_FIELD4] = CONTEST_F_FIELD4,
  [USERLIST_NC_FIELD5] = CONTEST_F_FIELD5,
  [USERLIST_NC_FIELD6] = CONTEST_F_FIELD6,
  [USERLIST_NC_FIELD7] = CONTEST_F_FIELD7,
  [USERLIST_NC_FIELD8] = CONTEST_F_FIELD8,
  [USERLIST_NC_FIELD9] = CONTEST_F_FIELD9,

  [USERLIST_NM_SERIAL] = CONTEST_MF_SERIAL,
  [USERLIST_NM_STATUS] = CONTEST_MF_STATUS ,
  [USERLIST_NM_GENDER] = CONTEST_MF_GENDER ,
  [USERLIST_NM_GRADE] = CONTEST_MF_GRADE ,
  [USERLIST_NM_FIRSTNAME] = CONTEST_MF_FIRSTNAME ,
  [USERLIST_NM_FIRSTNAME_EN] = CONTEST_MF_FIRSTNAME_EN ,
  [USERLIST_NM_MIDDLENAME] = CONTEST_MF_MIDDLENAME ,
  [USERLIST_NM_MIDDLENAME_EN] = CONTEST_MF_MIDDLENAME_EN ,
  [USERLIST_NM_SURNAME] = CONTEST_MF_SURNAME ,
  [USERLIST_NM_SURNAME_EN] = CONTEST_MF_SURNAME_EN ,
  [USERLIST_NM_GROUP] = CONTEST_MF_GROUP ,
  [USERLIST_NM_GROUP_EN] = CONTEST_MF_GROUP_EN ,
  [USERLIST_NM_EMAIL] = CONTEST_MF_EMAIL ,
  [USERLIST_NM_HOMEPAGE] = CONTEST_MF_HOMEPAGE ,
  [USERLIST_NM_OCCUPATION] = CONTEST_MF_OCCUPATION ,
  [USERLIST_NM_OCCUPATION_EN] = CONTEST_MF_OCCUPATION_EN ,
  [USERLIST_NM_DISCIPLINE] = CONTEST_MF_DISCIPLINE ,
  [USERLIST_NM_INST] = CONTEST_MF_INST ,
  [USERLIST_NM_INST_EN] = CONTEST_MF_INST_EN ,
  [USERLIST_NM_INSTSHORT] = CONTEST_MF_INSTSHORT ,
  [USERLIST_NM_INSTSHORT_EN] = CONTEST_MF_INSTSHORT_EN ,
  [USERLIST_NM_FAC] = CONTEST_MF_FAC ,
  [USERLIST_NM_FAC_EN] = CONTEST_MF_FAC_EN ,
  [USERLIST_NM_FACSHORT] = CONTEST_MF_FACSHORT ,
  [USERLIST_NM_FACSHORT_EN] = CONTEST_MF_FACSHORT_EN ,
  [USERLIST_NM_PHONE] = CONTEST_MF_PHONE ,
  //[USERLIST_NM_CREATE_TIME] = 0 ,
  //[USERLIST_NM_LAST_CHANGE_TIME] = 0 ,
  [USERLIST_NM_BIRTH_DATE] = CONTEST_MF_BIRTH_DATE ,
  [USERLIST_NM_ENTRY_DATE] = CONTEST_MF_ENTRY_DATE ,
  [USERLIST_NM_GRADUATION_DATE] = CONTEST_MF_GRADUATION_DATE ,
};

int
userlist_map_userlist_to_contest_field(int uf)
{
  int n;
  ASSERT(uf >= USERLIST_NC_FIRST && uf < USERLIST_NC_LAST);
  n = user_to_contest_field_map[uf];
  ASSERT(n);
  return n;
}

static const struct
{
  const unsigned char *name;
  int value;
} user_field_map[] =
{
  { "NN_ID", USERLIST_NN_ID },
  { "NN_IS_PRIVILEGED", USERLIST_NN_IS_PRIVILEGED },
  { "NN_IS_INVISIBLE", USERLIST_NN_IS_INVISIBLE },
  { "NN_IS_BANNED", USERLIST_NN_IS_BANNED },
  { "NN_IS_LOCKED", USERLIST_NN_IS_LOCKED },
  { "NN_SHOW_LOGIN", USERLIST_NN_SHOW_LOGIN },
  { "NN_SHOW_EMAIL", USERLIST_NN_SHOW_EMAIL },
  { "NN_READ_ONLY", USERLIST_NN_READ_ONLY },
  { "NN_NEVER_CLEAN", USERLIST_NN_NEVER_CLEAN },
  { "NN_SIMPLE_REGISTRATION", USERLIST_NN_SIMPLE_REGISTRATION },
  { "NN_LOGIN", USERLIST_NN_LOGIN },
  { "NN_EMAIL", USERLIST_NN_EMAIL },
  { "NN_PASSWD", USERLIST_NN_PASSWD },
  { "NN_REGISTRATION_TIME", USERLIST_NN_REGISTRATION_TIME },
  { "NN_LAST_LOGIN_TIME", USERLIST_NN_LAST_LOGIN_TIME },
  { "NN_LAST_CHANGE_TIME", USERLIST_NN_LAST_CHANGE_TIME },
  { "NN_LAST_PWDCHANGE_TIME", USERLIST_NN_LAST_PWDCHANGE_TIME },
  { "NC_CNTS_READ_ONLY", USERLIST_NC_CNTS_READ_ONLY },
  { "NC_NAME", USERLIST_NC_NAME },
  { "NC_TEAM_PASSWD", USERLIST_NC_TEAM_PASSWD },
  { "NC_INST", USERLIST_NC_INST },
  { "NC_INST_EN", USERLIST_NC_INST_EN },
  { "NC_INSTSHORT", USERLIST_NC_INSTSHORT },
  { "NC_INSTSHORT_EN", USERLIST_NC_INSTSHORT_EN },
  { "NC_INSTNUM", USERLIST_NC_INSTNUM },
  { "NC_FAC", USERLIST_NC_FAC },
  { "NC_FAC_EN", USERLIST_NC_FAC_EN },
  { "NC_FACSHORT", USERLIST_NC_FACSHORT },
  { "NC_FACSHORT_EN", USERLIST_NC_FACSHORT_EN },
  { "NC_HOMEPAGE", USERLIST_NC_HOMEPAGE },
  { "NC_CITY", USERLIST_NC_CITY },
  { "NC_CITY_EN", USERLIST_NC_CITY_EN },
  { "NC_COUNTRY", USERLIST_NC_COUNTRY },
  { "NC_COUNTRY_EN", USERLIST_NC_COUNTRY_EN },
  { "NC_REGION", USERLIST_NC_REGION },
  { "NC_AREA", USERLIST_NC_AREA },
  { "NC_ZIP", USERLIST_NC_ZIP },
  { "NC_STREET", USERLIST_NC_STREET },
  { "NC_LOCATION", USERLIST_NC_LOCATION },
  { "NC_SPELLING", USERLIST_NC_SPELLING },
  { "NC_PRINTER_NAME", USERLIST_NC_PRINTER_NAME },
  { "NC_EXAM_ID", USERLIST_NC_EXAM_ID },
  { "NC_EXAM_CYPHER", USERLIST_NC_EXAM_CYPHER },
  { "NC_LANGUAGES", USERLIST_NC_LANGUAGES },
  { "NC_PHONE", USERLIST_NC_PHONE },
  { "NC_FIELD0", USERLIST_NC_FIELD0 },
  { "NC_FIELD1", USERLIST_NC_FIELD1 },
  { "NC_FIELD2", USERLIST_NC_FIELD2 },
  { "NC_FIELD3", USERLIST_NC_FIELD3 },
  { "NC_FIELD4", USERLIST_NC_FIELD4 },
  { "NC_FIELD5", USERLIST_NC_FIELD5 },
  { "NC_FIELD6", USERLIST_NC_FIELD6 },
  { "NC_FIELD7", USERLIST_NC_FIELD7 },
  { "NC_FIELD8", USERLIST_NC_FIELD8 },
  { "NC_FIELD9", USERLIST_NC_FIELD9 },
  { "NC_CREATE_TIME", USERLIST_NC_CREATE_TIME },
  { "NC_LAST_LOGIN_TIME", USERLIST_NC_LAST_LOGIN_TIME },
  { "NC_LAST_CHANGE_TIME", USERLIST_NC_LAST_CHANGE_TIME },
  { "NC_LAST_PWDCHANGE_TIME", USERLIST_NC_LAST_PWDCHANGE_TIME },
  { "NM_SERIAL", USERLIST_NM_SERIAL },
  { "NM_STATUS", USERLIST_NM_STATUS },
  { "NM_GENDER", USERLIST_NM_GENDER },
  { "NM_GRADE", USERLIST_NM_GRADE },
  { "NM_FIRSTNAME", USERLIST_NM_FIRSTNAME },
  { "NM_FIRSTNAME_EN", USERLIST_NM_FIRSTNAME_EN },
  { "NM_MIDDLENAME", USERLIST_NM_MIDDLENAME },
  { "NM_MIDDLENAME_EN", USERLIST_NM_MIDDLENAME_EN },
  { "NM_SURNAME", USERLIST_NM_SURNAME },
  { "NM_SURNAME_EN", USERLIST_NM_SURNAME_EN },
  { "NM_GROUP", USERLIST_NM_GROUP },
  { "NM_GROUP_EN", USERLIST_NM_GROUP_EN },
  { "NM_EMAIL", USERLIST_NM_EMAIL },
  { "NM_HOMEPAGE", USERLIST_NM_HOMEPAGE },
  { "NM_OCCUPATION", USERLIST_NM_OCCUPATION },
  { "NM_OCCUPATION_EN", USERLIST_NM_OCCUPATION_EN },
  { "NM_DISCIPLINE", USERLIST_NM_DISCIPLINE },
  { "NM_INST", USERLIST_NM_INST },
  { "NM_INST_EN", USERLIST_NM_INST_EN },
  { "NM_INSTSHORT", USERLIST_NM_INSTSHORT },
  { "NM_INSTSHORT_EN", USERLIST_NM_INSTSHORT_EN },
  { "NM_FAC", USERLIST_NM_FAC },
  { "NM_FAC_EN", USERLIST_NM_FAC_EN },
  { "NM_FACSHORT", USERLIST_NM_FACSHORT },
  { "NM_FACSHORT_EN", USERLIST_NM_FACSHORT_EN },
  { "NM_PHONE", USERLIST_NM_PHONE },
  { "NM_CREATE_TIME", USERLIST_NM_CREATE_TIME },
  { "NM_LAST_CHANGE_TIME", USERLIST_NM_LAST_CHANGE_TIME },
  { "NM_BIRTH_DATE", USERLIST_NM_BIRTH_DATE },
  { "NM_ENTRY_DATE", USERLIST_NM_ENTRY_DATE },
  { "NM_GRADUATION_DATE", USERLIST_NM_GRADUATION_DATE },

  { 0 },
};

int
userlist_str_to_user_field_code(const unsigned char *str)
{
  int i;

  for (i = 0; user_field_map[i].name; i++)
    if (!strcmp(user_field_map[i].name, str))
      return user_field_map[i].value;
  return -1;
}

int
userlist_members_count(const struct userlist_members *mmm, int role)
{
  const struct userlist_member *m;
  int j, cnt;

  if (!mmm || mmm->u <= 0) return 0;
  for (j = 0, cnt = 0; j < mmm->u; j++)
    if ((m = mmm->m[j]) && m->team_role == role)
      cnt++;
  return cnt;
}

const struct userlist_member *
userlist_members_get_first(const struct userlist_members *mmm)
{
  const struct userlist_member *m;
  int j;

  if (!mmm || mmm->u <= 0) return NULL;
  for (j = 0; j < mmm->u; j++)
    if ((m = mmm->m[j]) && m->team_role == USERLIST_MB_CONTESTANT)
      return m;
  return NULL;
}

const struct userlist_member *
userlist_members_get_nth(
        const struct userlist_members *mmm,
        int role,
        int n)
{
  const struct userlist_member *m;
  int j;

  if (!mmm || mmm->u <= 0) return NULL;
  for (j = 0; j < mmm->u; j++)
    if ((m = mmm->m[j]) && m->team_role == role) {
      if (!n) return m;
      --n;
    }
  return NULL;
}

void
userlist_members_reserve(struct userlist_members *mm, int n)
{
  int new_a = 0;
  struct userlist_member **m;

  ASSERT(mm);
  ASSERT(n >= 0);

  if (n <= mm->a) return;
  if (!(new_a = mm->a)) new_a = 4;
  while (new_a < n) new_a *= 2;
  XCALLOC(m, new_a);
  if (mm->u > 0) memcpy(m, mm->m, mm->u * sizeof(m[0]));
  xfree(mm->m);
  mm->m = m;
  mm->a = new_a;
}

struct userlist_user_info *
userlist_get_cnts0(struct userlist_user *u)
{
  ASSERT(u);
  if (u->cnts0) return u->cnts0;
  u->cnts0 = (struct userlist_user_info*) userlist_node_alloc(USERLIST_T_CNTSINFO);
  u->cnts0->instnum = -1;
  xml_link_node_last(&u->b, &u->cnts0->b);
  return u->cnts0;
}

int
userlist_member_map_userlist_to_contest_field(int uf)
{
  int n;
  ASSERT(uf >= USERLIST_NM_FIRST && uf < USERLIST_NM_LAST);
  n = user_to_contest_field_map[uf];
  ASSERT(n);
  return n;
}

const void *
userlist_group_get_ptr(const struct userlist_group *grp, int field)
{
  ASSERT(grp);
  ASSERT(field >= USERLIST_GRP_GROUP_ID && field < USERLIST_GRP_LAST);

  switch (field) {
  case USERLIST_GRP_GROUP_ID:
    return &grp->group_id;
  case USERLIST_GRP_GROUP_NAME:
    return &grp->group_name;
  case USERLIST_GRP_DESCRIPTION:
    return &grp->description;
  default:
    abort();
  }
}

void *
userlist_group_get_ptr_nc(struct userlist_group *grp, int field)
{
  ASSERT(grp);
  ASSERT(field >= USERLIST_GRP_GROUP_ID && field < USERLIST_GRP_LAST);

  switch (field) {
  case USERLIST_GRP_GROUP_ID:
    return &grp->group_id;
  case USERLIST_GRP_GROUP_NAME:
    return &grp->group_name;
  case USERLIST_GRP_DESCRIPTION:
    return &grp->description;
  default:
    abort();
  }
}

static const unsigned char * const field_lookup_table[][7] =
{
  [USERLIST_NN_ID] = { "user_id", "userid", NULL },
  [USERLIST_NN_IS_PRIVILEGED] = { "is_privileged", "isprivileged", NULL},
  [USERLIST_NN_IS_INVISIBLE] = { "is_invisible", "isinvisible", NULL },
  [USERLIST_NN_IS_BANNED] = { "is_banned", "isbanned", NULL },
  [USERLIST_NN_IS_LOCKED] = { "is_locked", "islocked", NULL },
  [USERLIST_NN_SHOW_LOGIN] = { "show_login", "showlogin", NULL },
  [USERLIST_NN_SHOW_EMAIL] = { "show_email", "showemail", NULL },
  [USERLIST_NN_READ_ONLY] = { "read_only", "readonly", NULL },
  [USERLIST_NN_NEVER_CLEAN] = { "never_clean", "neverclean", NULL },
  [USERLIST_NN_SIMPLE_REGISTRATION] = { "simple_registration", "simpleregistration", NULL },
  [USERLIST_NN_LOGIN] = { "login", NULL },
  [USERLIST_NN_EMAIL] = { "email", NULL },
  [USERLIST_NN_PASSWD] = { "password", "passwd", "reg_passwd", "regpasswd", "reg_password", "regpassword", NULL },
  /*
    USERLIST_NN_REGISTRATION_TIME,
    USERLIST_NN_LAST_LOGIN_TIME,
    USERLIST_NN_LAST_CHANGE_TIME,
    USERLIST_NN_LAST_PWDCHANGE_TIME,
  */

  [USERLIST_NC_CNTS_READ_ONLY] = { "cnts_read_only", "cntsreadonly", NULL },
  [USERLIST_NC_NAME] = { "name", "cntsname", "cnts_name", NULL },
  [USERLIST_NC_TEAM_PASSWD] = { "cnts_password", "cntspassword", "cnts_passwd", "cntspasswd", NULL },
  [USERLIST_NC_INST] = { "inst", "institution", NULL },
  [USERLIST_NC_INST_EN] = { "inst_en", "institution_en", NULL },
  [USERLIST_NC_INSTSHORT] = { "instshort", "institution_short", NULL },
  [USERLIST_NC_INSTSHORT_EN] = { "instshort_en", "institution_short_en", NULL },
  [USERLIST_NC_INSTNUM] = { "instnum", "institution_number", NULL },
  [USERLIST_NC_FAC] = { "fac", "faculty", NULL },
  [USERLIST_NC_FAC_EN] = { "fac_en", "faculty_en", NULL },
  [USERLIST_NC_FACSHORT] = { "facshort", "faculty_short", NULL },
  [USERLIST_NC_FACSHORT_EN] = { "facshort_en", "faculty_short_en", NULL },
  [USERLIST_NC_HOMEPAGE] = { "homepage", NULL },
  [USERLIST_NC_CITY] = { "city", NULL },
  [USERLIST_NC_CITY_EN] = { "city_en", NULL },
  [USERLIST_NC_COUNTRY] = { "country", NULL },
  [USERLIST_NC_COUNTRY_EN] = { "country_en", NULL },
  [USERLIST_NC_REGION] = { "region", NULL },
  [USERLIST_NC_AREA] = { "area", NULL },
  [USERLIST_NC_ZIP] = { "zip", NULL },
  [USERLIST_NC_STREET] = { "street", NULL },
  [USERLIST_NC_LOCATION] = { "location", NULL },
  [USERLIST_NC_SPELLING] = { "spelling", NULL },
  [USERLIST_NC_PRINTER_NAME] = { "printer_name", "printername", NULL },
  [USERLIST_NC_EXAM_ID] = { "exam_id", "examid", NULL },
  [USERLIST_NC_EXAM_CYPHER] = { "exam_cypher", "examcypher", NULL },
  [USERLIST_NC_LANGUAGES] = { "languages", NULL },
  [USERLIST_NC_PHONE] = { "phone", NULL },
  [USERLIST_NC_FIELD0] = { "field0", NULL },
  [USERLIST_NC_FIELD1] = { "field1", NULL },
  [USERLIST_NC_FIELD2] = { "field2", NULL },
  [USERLIST_NC_FIELD3] = { "field3", NULL },
  [USERLIST_NC_FIELD4] = { "field4", NULL },
  [USERLIST_NC_FIELD5] = { "field5", NULL },
  [USERLIST_NC_FIELD6] = { "field6", NULL },
  [USERLIST_NC_FIELD7] = { "field7", NULL },
  [USERLIST_NC_FIELD8] = { "field8", NULL },
  [USERLIST_NC_FIELD9] = { "field9", NULL },

  /*
    USERLIST_NC_CREATE_TIME,
    USERLIST_NC_LAST_LOGIN_TIME,
    USERLIST_NC_LAST_CHANGE_TIME,
    USERLIST_NC_LAST_PWDCHANGE_TIME,
    USERLIST_NC_LAST,
  */

  [USERLIST_NM_SERIAL] = { "serial", NULL },
  [USERLIST_NM_STATUS] = { "status", NULL },
  [USERLIST_NM_GENDER] = { "gender", NULL },
  [USERLIST_NM_GRADE] = { "grade", NULL },
  [USERLIST_NM_FIRSTNAME] = { "firstname", NULL },
  [USERLIST_NM_FIRSTNAME_EN] = { "firstname_en", NULL },
  [USERLIST_NM_MIDDLENAME] = { "middlename", NULL },
  [USERLIST_NM_MIDDLENAME_EN] = { "middlename_en", NULL },
  [USERLIST_NM_SURNAME] = { "surname", NULL },
  [USERLIST_NM_SURNAME_EN] = { "surname_en", NULL },
  [USERLIST_NM_GROUP] = { "group", NULL },
  [USERLIST_NM_GROUP_EN] = { "group_en", NULL},
  [USERLIST_NM_EMAIL] = { "memb_email", "membemail", "member_email", "memberemail", NULL },
  [USERLIST_NM_HOMEPAGE] = { "memb_homepage", "membhomepage", "member_homepage", "memberhomepage", NULL },
  [USERLIST_NM_OCCUPATION] = { "occupation", NULL },
  [USERLIST_NM_OCCUPATION_EN] = { "occupation_en", NULL },
  [USERLIST_NM_DISCIPLINE] = { "discipline", NULL },
  [USERLIST_NM_INST] = { "memb_inst", "member_institution", "membinst", "memberinstitution", NULL },
  [USERLIST_NM_INST_EN] = { "memb_inst_en", "member_institution_en", "membinsten", "memberinstitutionen", NULL },
  [USERLIST_NM_INSTSHORT] = { "memb_instshort", "member_institution_short", "membinstshort", "memberinstitutionshort", NULL },
  [USERLIST_NM_INSTSHORT_EN] = { "memb_instshort_en", "member_institution_short_en", "membinstshorten", "memberinstitutionshorten", NULL },
  [USERLIST_NM_FAC] = { "memb_fac", "member_faculty", "membfac", "memberfaculty", NULL },
  [USERLIST_NM_FAC_EN] = { "memb_fac_en", "member_faculty_en", "membfacen", "memberfacultyen", NULL },
  [USERLIST_NM_FACSHORT] = { "memb_facshort", "member_faculty_short", "membfacshort", "memberfacultyshort", NULL },
  [USERLIST_NM_FACSHORT_EN] = { "memb_facshort_en", "member_faculty_short_en", "membfacshorten", "memberfacultyshorten", NULL },
  [USERLIST_NM_PHONE] = { "memb_phone", "membphone", "member_phone", "memberphone", NULL },
  /*
    USERLIST_NM_CREATE_TIME,
    USERLIST_NM_LAST_CHANGE_TIME,
  */
  [USERLIST_NM_BIRTH_DATE] = { "birth_date", "birthdate", "memb_birth_date", "membbirthdate", NULL },
  [USERLIST_NM_ENTRY_DATE] = { "entry_date", "entrydate", "memb_entry_date", "membentrydate", NULL },
  [USERLIST_NM_GRADUATION_DATE] = { "graduation_date", "graduationdate", "memb_graduation_date", "membgraduationdate", NULL },
  /*
    USERLIST_NM_LAST,
  */
};

int
userlist_lookup_csv_field_name(const unsigned char *str)
{
  int field_id;

  if (!str || !*str) return -1;
  for (field_id = 1; field_id < USERLIST_NM_LAST; ++field_id) {
    for (int j = 0; field_lookup_table[field_id][j]; ++j)
      if (!strcasecmp(str, field_lookup_table[field_id][j]))
        return field_id;
  }
  return -1;
}

const unsigned char *
userlist_get_csv_field_name(int field_id)
{
  if (field_id <= 0 || field_id >= USERLIST_NM_LAST) return NULL;
  return field_lookup_table[field_id][0];
}

static const unsigned char * const filter_parse_table[] =
{
  [USER_FILTER_OP_EQ] = "eq", // 'equal'
  [USER_FILTER_OP_NE] = "ne", // 'not equal'
  [USER_FILTER_OP_LT] = "lt", // 'less'
  [USER_FILTER_OP_LE] = "le", // 'less or equal'
  [USER_FILTER_OP_GT] = "gt", // 'greater'
  [USER_FILTER_OP_GE] = "ge", // 'greater or equal'
  [USER_FILTER_OP_BW] = "bw", // 'begins with'
  [USER_FILTER_OP_BN] = "bn", // 'does not begin with'
  [USER_FILTER_OP_IN] = "in", // 'is in'
  [USER_FILTER_OP_NI] = "ni", // 'is not in'
  [USER_FILTER_OP_EW] = "ew", // 'ends with'
  [USER_FILTER_OP_EN] = "en", // 'does not end with'
  [USER_FILTER_OP_CN] = "cn", // 'contains'
  [USER_FILTER_OP_NC] = "nc", // 'does not contain'
};

int
userlist_parse_filter_op(const unsigned char *str)
{
  if (!str) return 0;
  for (int op = 0; op <= USER_FILTER_OP_NC; ++op) {
    if (filter_parse_table[op] && !strcmp(filter_parse_table[op], str))
      return op;
  }
  return 0;
}
