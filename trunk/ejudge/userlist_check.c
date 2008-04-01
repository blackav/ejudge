/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007-2008 Alexander Chernov <cher@ejudge.ru> */

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
#include "userlist.h"
#include "misctext.h"

#include <reuse/logger.h>

#include <string.h>

const unsigned char login_accept_chars[257] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1\0\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const unsigned char email_accept_chars[257] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\0\0\0\1\0\0\0\0\0\1\0\1\1\0\1\1\1\1\1\1\1\1\1\1\0\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const unsigned char name_accept_chars[257] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1";
const unsigned char name_en_accept_chars[257] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1";
//const unsigned char name_en_accept_chars[257] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1\0\1\1\1\0\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\1\1\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const unsigned char url_accept_chars[257] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1\0\1\1\1\0\0\0\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\1\1\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const unsigned char password_accept_chars[257] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\0\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1\1";

static const unsigned char * const contest_accept_chars[CONTEST_LAST_FIELD] =
{
  [CONTEST_F_HOMEPAGE] = url_accept_chars,
  [CONTEST_F_PHONE] = url_accept_chars,
  [CONTEST_F_INST] = name_accept_chars,
  [CONTEST_F_INST_EN] = name_en_accept_chars,
  [CONTEST_F_INSTSHORT] = name_accept_chars,
  [CONTEST_F_INSTSHORT_EN] = name_en_accept_chars,
  [CONTEST_F_INSTNUM] = 0,
  [CONTEST_F_FAC] = name_accept_chars,
  [CONTEST_F_FAC_EN] = name_en_accept_chars,
  [CONTEST_F_FACSHORT] = name_accept_chars,
  [CONTEST_F_FACSHORT_EN] = name_en_accept_chars,
  [CONTEST_F_CITY] = name_accept_chars,
  [CONTEST_F_CITY_EN] = name_en_accept_chars,
  [CONTEST_F_COUNTRY] = name_accept_chars,
  [CONTEST_F_COUNTRY_EN] = name_en_accept_chars,
  [CONTEST_F_REGION] = name_accept_chars,
  [CONTEST_F_AREA] = name_accept_chars,
  [CONTEST_F_ZIP] = login_accept_chars,
  [CONTEST_F_STREET] = name_accept_chars,
  [CONTEST_F_LANGUAGES] = name_accept_chars,
  [CONTEST_F_FIELD0] = name_accept_chars,
  [CONTEST_F_FIELD1] = name_accept_chars,
  [CONTEST_F_FIELD2] = name_accept_chars,
  [CONTEST_F_FIELD3] = name_accept_chars,
  [CONTEST_F_FIELD4] = name_accept_chars,
  [CONTEST_F_FIELD5] = name_accept_chars,
  [CONTEST_F_FIELD6] = name_accept_chars,
  [CONTEST_F_FIELD7] = name_accept_chars,
  [CONTEST_F_FIELD8] = name_accept_chars,
  [CONTEST_F_FIELD9] = name_accept_chars,
};

static const unsigned char * const member_accept_chars[CONTEST_LAST_MEMBER_FIELD] =
{
  [CONTEST_MF_FIRSTNAME] = name_accept_chars,
  [CONTEST_MF_FIRSTNAME_EN] = name_en_accept_chars,
  [CONTEST_MF_MIDDLENAME] = name_accept_chars,
  [CONTEST_MF_MIDDLENAME_EN] = name_en_accept_chars,
  [CONTEST_MF_SURNAME] = name_accept_chars,
  [CONTEST_MF_SURNAME_EN] = name_en_accept_chars,
  [CONTEST_MF_STATUS] = 0,
  [CONTEST_MF_GENDER] = 0,
  [CONTEST_MF_GRADE] = name_accept_chars,
  [CONTEST_MF_GROUP] = name_accept_chars,
  [CONTEST_MF_GROUP_EN] = name_en_accept_chars,
  [CONTEST_MF_EMAIL] = email_accept_chars,
  [CONTEST_MF_HOMEPAGE] = url_accept_chars,
  [CONTEST_MF_PHONE] = url_accept_chars,
  [CONTEST_MF_INST] = name_accept_chars,
  [CONTEST_MF_INST_EN] = name_en_accept_chars,
  [CONTEST_MF_INSTSHORT] = name_accept_chars,
  [CONTEST_MF_INSTSHORT_EN] = name_en_accept_chars,
  [CONTEST_MF_FAC] = name_accept_chars,
  [CONTEST_MF_FAC_EN] = name_en_accept_chars,
  [CONTEST_MF_FACSHORT] = name_accept_chars,
  [CONTEST_MF_FACSHORT_EN] = name_en_accept_chars,
  [CONTEST_MF_OCCUPATION] = name_accept_chars,
  [CONTEST_MF_OCCUPATION_EN] = name_en_accept_chars,
  [CONTEST_MF_DISCIPLINE] = name_accept_chars,
  [CONTEST_MF_BIRTH_DATE] = url_accept_chars,
  [CONTEST_MF_ENTRY_DATE] = url_accept_chars,
  [CONTEST_MF_GRADUATION_DATE] = url_accept_chars,
};

const int userlist_contest_field_ids[CONTEST_LAST_FIELD] =
{
  [CONTEST_F_HOMEPAGE] = USERLIST_NC_HOMEPAGE,
  [CONTEST_F_PHONE] = USERLIST_NC_PHONE,
  [CONTEST_F_INST] = USERLIST_NC_INST,
  [CONTEST_F_INST_EN] = USERLIST_NC_INST_EN,
  [CONTEST_F_INSTSHORT] = USERLIST_NC_INSTSHORT,
  [CONTEST_F_INSTSHORT_EN] = USERLIST_NC_INSTSHORT_EN,
  [CONTEST_F_INSTNUM] = USERLIST_NC_INSTNUM,
  [CONTEST_F_FAC] = USERLIST_NC_FAC,
  [CONTEST_F_FAC_EN] = USERLIST_NC_FAC_EN,
  [CONTEST_F_FACSHORT] = USERLIST_NC_FACSHORT,
  [CONTEST_F_FACSHORT_EN] = USERLIST_NC_FACSHORT_EN,
  [CONTEST_F_CITY] = USERLIST_NC_CITY,
  [CONTEST_F_CITY_EN] = USERLIST_NC_CITY_EN,
  [CONTEST_F_COUNTRY] = USERLIST_NC_COUNTRY,
  [CONTEST_F_COUNTRY_EN] = USERLIST_NC_COUNTRY_EN,
  [CONTEST_F_REGION] = USERLIST_NC_REGION,
  [CONTEST_F_AREA] = USERLIST_NC_AREA,
  [CONTEST_F_ZIP] = USERLIST_NC_ZIP,
  [CONTEST_F_STREET] = USERLIST_NC_STREET,
  [CONTEST_F_LANGUAGES] = USERLIST_NC_LANGUAGES,
  [CONTEST_F_FIELD0] = USERLIST_NC_FIELD0,
  [CONTEST_F_FIELD1] = USERLIST_NC_FIELD1,
  [CONTEST_F_FIELD2] = USERLIST_NC_FIELD2,
  [CONTEST_F_FIELD3] = USERLIST_NC_FIELD3,
  [CONTEST_F_FIELD4] = USERLIST_NC_FIELD4,
  [CONTEST_F_FIELD5] = USERLIST_NC_FIELD5,
  [CONTEST_F_FIELD6] = USERLIST_NC_FIELD6,
  [CONTEST_F_FIELD7] = USERLIST_NC_FIELD7,
  [CONTEST_F_FIELD8] = USERLIST_NC_FIELD8,
  [CONTEST_F_FIELD9] = USERLIST_NC_FIELD9,
};

const int userlist_member_field_ids[CONTEST_LAST_MEMBER_FIELD] =
{
  [CONTEST_MF_FIRSTNAME] = USERLIST_NM_FIRSTNAME,
  [CONTEST_MF_FIRSTNAME_EN] = USERLIST_NM_FIRSTNAME_EN,
  [CONTEST_MF_MIDDLENAME] = USERLIST_NM_MIDDLENAME,
  [CONTEST_MF_MIDDLENAME_EN] = USERLIST_NM_MIDDLENAME_EN,
  [CONTEST_MF_SURNAME] = USERLIST_NM_SURNAME,
  [CONTEST_MF_SURNAME_EN] = USERLIST_NM_SURNAME_EN,
  [CONTEST_MF_STATUS] = USERLIST_NM_STATUS,
  [CONTEST_MF_GENDER] = USERLIST_NM_GENDER,
  [CONTEST_MF_GRADE] = USERLIST_NM_GRADE,
  [CONTEST_MF_GROUP] = USERLIST_NM_GROUP,
  [CONTEST_MF_GROUP_EN] = USERLIST_NM_GROUP_EN,
  [CONTEST_MF_EMAIL] = USERLIST_NM_EMAIL,
  [CONTEST_MF_HOMEPAGE] = USERLIST_NM_HOMEPAGE,
  [CONTEST_MF_PHONE] = USERLIST_NM_PHONE,
  [CONTEST_MF_INST] = USERLIST_NM_INST,
  [CONTEST_MF_INST_EN] = USERLIST_NM_INST_EN,
  [CONTEST_MF_INSTSHORT] = USERLIST_NM_INSTSHORT,
  [CONTEST_MF_INSTSHORT_EN] = USERLIST_NM_INSTSHORT_EN,
  [CONTEST_MF_FAC] = USERLIST_NM_FAC,
  [CONTEST_MF_FAC_EN] = USERLIST_NM_FAC_EN,
  [CONTEST_MF_FACSHORT] = USERLIST_NM_FACSHORT,
  [CONTEST_MF_FACSHORT_EN] = USERLIST_NM_FACSHORT_EN,
  [CONTEST_MF_OCCUPATION] = USERLIST_NM_OCCUPATION,
  [CONTEST_MF_OCCUPATION_EN] = USERLIST_NM_OCCUPATION_EN,
  [CONTEST_MF_DISCIPLINE] = USERLIST_NM_DISCIPLINE,
  [CONTEST_MF_BIRTH_DATE] = USERLIST_NM_BIRTH_DATE,
  [CONTEST_MF_ENTRY_DATE] = USERLIST_NM_ENTRY_DATE,
  [CONTEST_MF_GRADUATION_DATE] = USERLIST_NM_GRADUATION_DATE,
};

const unsigned char *
userlist_get_contest_accepting_chars(int field)
{
  ASSERT(field >= CONTEST_FIRST_FIELD && field < CONTEST_LAST_FIELD);
  return contest_accept_chars[field];
}
const unsigned char *
userlist_get_member_accepting_chars(int field)
{
  ASSERT(field >= CONTEST_MF_FIRSTNAME && field < CONTEST_LAST_MEMBER_FIELD);
  return member_accept_chars[field];
}

int
userlist_count_info_errors(
        const struct contest_desc *cnts,
        const struct userlist_user *u,
        const struct userlist_user_info *ui,
        int role_err_count[])
{
  int err_count = 0, ff;
  unsigned char fbuf[1024];
  int rr, mm, mmbound;
  const struct userlist_member *m;

  memset(role_err_count, 0, sizeof(role_err_count[0]) * (CONTEST_LAST_MEMBER + 1));
  for (ff = CONTEST_FIRST_FIELD; ff < CONTEST_LAST_FIELD; ff++) {
    if (!cnts->fields[ff]) continue;
    if (userlist_is_empty_user_info_field(ui, userlist_contest_field_ids[ff])
        && cnts->fields[ff]->mandatory) {
      role_err_count[0]++;
      err_count++;
    } else if (contest_accept_chars[ff]) {
      userlist_get_user_info_field_str(fbuf, sizeof(fbuf), ui,
                                       userlist_contest_field_ids[ff], 0);
      if (check_str(fbuf, contest_accept_chars[ff]) < 0) {
        role_err_count[0]++;
        err_count++;
      }
    }
  }
  for (rr = CONTEST_M_CONTESTANT; rr < CONTEST_LAST_MEMBER; rr++) {
    if (cnts->personal && rr == CONTEST_M_RESERVE) continue;
    if (!cnts->members[rr] || cnts->members[rr]->max_count <= 0) continue;
    if (cnts->personal && rr == CONTEST_M_CONTESTANT
        && cnts->members[rr]->max_count == 1) {
      // if there are no mandatory fields, contestant is allowed to
      // have no member info
      for (ff = CONTEST_MF_FIRSTNAME; ff < CONTEST_LAST_MEMBER_FIELD; ff++) {
        if (!cnts->members[rr]->fields[ff]) continue;
        if (cnts->members[rr]->fields[ff]->mandatory) break;
      }
      if (ff == CONTEST_LAST_MEMBER_FIELD &&
          (!ui->members[rr] || !ui->members[rr]->total)) continue;
    }
    mmbound = 0;
    if (ui->members[rr]) mmbound = ui->members[rr]->total;
    if (mmbound < cnts->members[rr]->min_count) {
      role_err_count[rr + 1]++;
      err_count++;
    }
    // temporary hack
    if (cnts->personal && mmbound > 1) mmbound = 1;
    if (mmbound > cnts->members[rr]->max_count) {
      role_err_count[rr + 1]++;
      err_count++;
    }
    /*
    if (cnts->members[rr]->max_count < mmbound)
      mmbound = cnts->members[rr]->max_count;
    */
    for (mm = 0; mm < mmbound; mm++) {
      if (!(m = ui->members[rr]->members[mm])) {
        role_err_count[rr + 1]++;
        err_count++;
        continue;
      }
      for (ff = CONTEST_MF_FIRSTNAME; ff < CONTEST_LAST_MEMBER_FIELD; ff++) {
        if (!cnts->members[rr]->fields[ff]) continue;
        if (userlist_is_empty_member_field(m, userlist_member_field_ids[ff])
            && cnts->members[rr]->fields[ff]->mandatory) {
          role_err_count[rr + 1]++;
          err_count++;
        } else if (member_accept_chars[ff]) {
          userlist_get_member_field_str(fbuf, sizeof(fbuf), m,
                                        userlist_member_field_ids[ff], 0, 0);
          if (check_str(fbuf, member_accept_chars[ff]) < 0) {
            role_err_count[rr + 1]++;
            err_count++;
          }
        }
      }
    }
  }

  return err_count;
}
