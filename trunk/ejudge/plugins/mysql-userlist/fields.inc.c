/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

struct field_description
{
  char *sql_name;
  int field_type;
};
static struct field_description fields[USERLIST_NM_LAST] =
{
  [USERLIST_NN_IS_PRIVILEGED] = { "privileged", USERLIST_NN_IS_PRIVILEGED },
  [USERLIST_NN_IS_INVISIBLE] = { "invisible", USERLIST_NN_IS_PRIVILEGED },
  [USERLIST_NN_IS_BANNED] = { "banned", USERLIST_NN_IS_PRIVILEGED },
  [USERLIST_NN_IS_LOCKED] = { "locked", USERLIST_NN_IS_PRIVILEGED },
  [USERLIST_NN_SHOW_LOGIN] = { "unused", USERLIST_NN_SHOW_LOGIN },
  [USERLIST_NN_SHOW_EMAIL] = { "unused", USERLIST_NN_SHOW_LOGIN },
  [USERLIST_NN_READ_ONLY] = { "readonly", USERLIST_NN_IS_PRIVILEGED },
  [USERLIST_NN_NEVER_CLEAN] = { "neverclean", USERLIST_NN_IS_PRIVILEGED },
  [USERLIST_NN_SIMPLE_REGISTRATION] = { "simplereg",USERLIST_NN_IS_PRIVILEGED},
  [USERLIST_NN_LOGIN] = { "login", USERLIST_NN_LOGIN },
  [USERLIST_NN_EMAIL] = { "email", USERLIST_NN_EMAIL },
  [USERLIST_NN_PASSWD] = { "password", USERLIST_NN_PASSWD },
  [USERLIST_NN_REGISTRATION_TIME] = { "regtime",USERLIST_NN_REGISTRATION_TIME},
  [USERLIST_NN_LAST_LOGIN_TIME] = { "logintime",USERLIST_NN_REGISTRATION_TIME},
  [USERLIST_NN_LAST_CHANGE_TIME]={"changetime",USERLIST_NN_LAST_CHANGE_TIME},
 [USERLIST_NN_LAST_PWDCHANGE_TIME]={"pwdtime",USERLIST_NN_LAST_PWDCHANGE_TIME},

  /* contest-specific user info fields */
  [USERLIST_NC_CNTS_READ_ONLY] = {"cnts_read_only",USERLIST_NC_CNTS_READ_ONLY},
  [USERLIST_NC_NAME] = { "username", USERLIST_NC_NAME },
  [USERLIST_NC_TEAM_PASSWD] = { "password", USERLIST_NC_TEAM_PASSWD },
  [USERLIST_NC_INST] = { "inst", USERLIST_NC_INST },
  [USERLIST_NC_INST_EN] = { "inst_en", USERLIST_NC_INST },
  [USERLIST_NC_INSTSHORT] = { "instshort", USERLIST_NC_INST },
  [USERLIST_NC_INSTSHORT_EN] = { "instshort_en", USERLIST_NC_INST },
  [USERLIST_NC_INSTNUM] = { "instnum", USERLIST_NC_INSTNUM },
  [USERLIST_NC_FAC] = { "fac", USERLIST_NC_INST },
  [USERLIST_NC_FAC_EN] = { "fac_en", USERLIST_NC_INST },
  [USERLIST_NC_FACSHORT] = { "facshort", USERLIST_NC_INST },
  [USERLIST_NC_FACSHORT_EN] = { "facshort_en", USERLIST_NC_INST },
  [USERLIST_NC_HOMEPAGE] = { "homepage", USERLIST_NC_INST },
  [USERLIST_NC_CITY] = { "city", USERLIST_NC_INST },
  [USERLIST_NC_CITY_EN] = { "city_en", USERLIST_NC_INST },
  [USERLIST_NC_COUNTRY] = { "country", USERLIST_NC_INST },
  [USERLIST_NC_COUNTRY_EN] = { "country_en", USERLIST_NC_INST },
  [USERLIST_NC_REGION] = { "region", USERLIST_NC_INST },
  [USERLIST_NC_AREA] = { "area", USERLIST_NC_INST },
  [USERLIST_NC_ZIP] = { "zip", USERLIST_NC_INST },
  [USERLIST_NC_STREET] = { "street", USERLIST_NC_INST },
  [USERLIST_NC_LOCATION] = { "location", USERLIST_NC_INST },
  [USERLIST_NC_SPELLING] = { "spelling", USERLIST_NC_INST },
  [USERLIST_NC_PRINTER_NAME] = { "printer", USERLIST_NC_INST },
  [USERLIST_NC_EXAM_ID] = { "exam_id", USERLIST_NC_INST },
  [USERLIST_NC_EXAM_CYPHER] = { "exam_cypher", USERLIST_NC_INST },
  [USERLIST_NC_LANGUAGES] = { "languages", USERLIST_NC_INST },
  [USERLIST_NC_PHONE] = { "phone", USERLIST_NC_INST },
  [USERLIST_NC_FIELD0] = { "field0", USERLIST_NC_INST },
  [USERLIST_NC_FIELD1] = { "field1", USERLIST_NC_INST },
  [USERLIST_NC_FIELD2] = { "field2", USERLIST_NC_INST },
  [USERLIST_NC_FIELD3] = { "field3", USERLIST_NC_INST },
  [USERLIST_NC_FIELD4] = { "field4", USERLIST_NC_INST },
  [USERLIST_NC_FIELD5] = { "field5", USERLIST_NC_INST },
  [USERLIST_NC_FIELD6] = { "field6", USERLIST_NC_INST },
  [USERLIST_NC_FIELD7] = { "field7", USERLIST_NC_INST },
  [USERLIST_NC_FIELD8] = { "field8", USERLIST_NC_INST },
  [USERLIST_NC_FIELD9] = { "field9", USERLIST_NC_INST },
  [USERLIST_NC_CREATE_TIME] = { "createtime", USERLIST_NC_CREATE_TIME },
  [USERLIST_NC_LAST_LOGIN_TIME] = { "logintime", USERLIST_NC_CREATE_TIME },
  [USERLIST_NC_LAST_CHANGE_TIME]={"changetime", USERLIST_NC_LAST_CHANGE_TIME },
 [USERLIST_NC_LAST_PWDCHANGE_TIME]={"pwdtime",USERLIST_NC_LAST_PWDCHANGE_TIME},

  /* user member info fields */
  //USERLIST_NM_SERIAL,
  [USERLIST_NM_STATUS] = { "status", USERLIST_NM_STATUS },
  [USERLIST_NM_GENDER] = { "gender", USERLIST_NM_GENDER },
  [USERLIST_NM_GRADE] = { "grade", USERLIST_NM_GRADE },
  [USERLIST_NM_FIRSTNAME] = { "firstname", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_FIRSTNAME_EN] = { "firstname_en", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_MIDDLENAME] = { "middlename", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_MIDDLENAME_EN] = { "middlename_en", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_SURNAME] = { "surname", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_SURNAME_EN] = { "surname_en", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_GROUP] = { "grp", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_GROUP_EN] = { "grp_en", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_EMAIL] = { "email", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_HOMEPAGE] = { "homepage", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_OCCUPATION] = { "occupation", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_OCCUPATION_EN] = { "occupation_en", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_DISCIPLINE] = { "discipline", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_INST] = { "inst", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_INST_EN] = { "inst_en", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_INSTSHORT] = { "instshort", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_INSTSHORT_EN] = { "instshort_en", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_FAC] = { "fac", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_FAC_EN] = { "fac_en", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_FACSHORT] = { "facshort", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_FACSHORT_EN] = { "facshort_en", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_PHONE] = { "phone", USERLIST_NM_FIRSTNAME },
  [USERLIST_NM_CREATE_TIME] = { "createtime", USERLIST_NM_CREATE_TIME },
  [USERLIST_NM_LAST_CHANGE_TIME] = {"changetime",USERLIST_NM_LAST_CHANGE_TIME},
  [USERLIST_NM_BIRTH_DATE] = { "birth_date", USERLIST_NM_BIRTH_DATE },
  [USERLIST_NM_ENTRY_DATE] = { "entry_date", USERLIST_NM_BIRTH_DATE },
  [USERLIST_NM_GRADUATION_DATE] = { "graduation_date", USERLIST_NM_BIRTH_DATE},
};

/*
 * Local variables:
 *  compile-command: "make -C ../.."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "MYSQL")
 * End:
 */
