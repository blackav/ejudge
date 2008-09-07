/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_H__
#define __USERLIST_H__

/* Copyright (C) 2002-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "ej_types.h"
#include "expat_iface.h"
#include "contests.h"

#include <stdio.h>

enum
  {
    USERLIST_PWD_PLAIN,
    USERLIST_PWD_BASE64,
    USERLIST_PWD_SHA1,

    USERLIST_PWD_LAST,
  };

enum
  {
    USERLIST_MB_CONTESTANT = CONTEST_M_CONTESTANT,
    USERLIST_MB_RESERVE = CONTEST_M_RESERVE,
    USERLIST_MB_COACH = CONTEST_M_COACH,
    USERLIST_MB_ADVISOR = CONTEST_M_ADVISOR,
    USERLIST_MB_GUEST = CONTEST_M_GUEST,
    USERLIST_MB_LAST
  };

enum
  {
    USERLIST_REG_OK,
    USERLIST_REG_PENDING,
    USERLIST_REG_REJECTED,

    USERLIST_REG_LAST
  };

enum
  {
    USERLIST_ST_SCHOOL = 1,     /* school student */
    USERLIST_ST_STUDENT,        /* student (without degree) */
    USERLIST_ST_MAG,            /* magistrant */
    USERLIST_ST_ASP,            /* phd student */
    USERLIST_ST_TEACHER,        /* school teacher */
    USERLIST_ST_PROF,           /* university professor */
    USERLIST_ST_SCIENTIST,      /* a scientist */
    USERLIST_ST_OTHER,          /* other */
    USERLIST_ST_LAST
  };

enum
  {
    USERLIST_SX_MALE = 1,
    USERLIST_SX_FEMALE = 2,

    USERLIST_SX_LAST,
  };

enum
  {
    USERLIST_T_USERLIST = 1,
    USERLIST_T_USER,
    USERLIST_T_LOGIN,
    USERLIST_T_NAME,
    USERLIST_T_INST,
    USERLIST_T_INST_EN,
    USERLIST_T_INSTSHORT,
    USERLIST_T_INSTSHORT_EN,
    USERLIST_T_INSTNUM,
    USERLIST_T_FAC,
    USERLIST_T_FAC_EN,
    USERLIST_T_FACSHORT,
    USERLIST_T_FACSHORT_EN,
    USERLIST_T_PASSWORD,
    USERLIST_T_EMAIL,
    USERLIST_T_HOMEPAGE,
    USERLIST_T_PHONE,
    USERLIST_T_MEMBER,
    USERLIST_T_SURNAME,
    USERLIST_T_SURNAME_EN,
    USERLIST_T_MIDDLENAME,
    USERLIST_T_MIDDLENAME_EN,
    USERLIST_T_GRADE,
    USERLIST_T_GROUP,
    USERLIST_T_GROUP_EN,
    USERLIST_T_COOKIES,
    USERLIST_T_COOKIE,
    USERLIST_T_CONTESTS,
    USERLIST_T_CONTEST,
    USERLIST_T_STATUS,
    USERLIST_T_OCCUPATION,
    USERLIST_T_OCCUPATION_EN,
    USERLIST_T_DISCIPLINE,
    USERLIST_T_MEMBERS,
    USERLIST_T_CONTESTANTS,
    USERLIST_T_RESERVES,
    USERLIST_T_COACHES,
    USERLIST_T_ADVISORS,
    USERLIST_T_GUESTS,
    USERLIST_T_FIRSTNAME,
    USERLIST_T_FIRSTNAME_EN,
    USERLIST_T_TEAM_PASSWORD,
    USERLIST_T_CITY,
    USERLIST_T_CITY_EN,
    USERLIST_T_COUNTRY,
    USERLIST_T_COUNTRY_EN,
    USERLIST_T_REGION,
    USERLIST_T_AREA,
    USERLIST_T_ZIP,
    USERLIST_T_STREET,
    USERLIST_T_LOCATION,
    USERLIST_T_SPELLING,
    USERLIST_T_PRINTER_NAME,
    USERLIST_T_EXAM_ID,
    USERLIST_T_EXAM_CYPHER,
    USERLIST_T_LANGUAGES,
    USERLIST_T_EXTRA1,
    USERLIST_T_CNTSINFOS,
    USERLIST_T_CNTSINFO,
    USERLIST_T_BIRTH_DATE,
    USERLIST_T_ENTRY_DATE,
    USERLIST_T_GRADUATION_DATE,
    USERLIST_T_GENDER,
    USERLIST_T_FIELD0,
    USERLIST_T_FIELD1,
    USERLIST_T_FIELD2,
    USERLIST_T_FIELD3,
    USERLIST_T_FIELD4,
    USERLIST_T_FIELD5,
    USERLIST_T_FIELD6,
    USERLIST_T_FIELD7,
    USERLIST_T_FIELD8,
    USERLIST_T_FIELD9,

    USERLIST_LAST_TAG,
  };

enum
  {
    USERLIST_A_NAME = 1,
    USERLIST_A_ID,
    USERLIST_A_METHOD,
    USERLIST_A_IP,
    USERLIST_A_VALUE,
    USERLIST_A_LOCALE_ID,
    USERLIST_A_EXPIRE,
    USERLIST_A_CONTEST_ID,
    USERLIST_A_REGISTERED,
    USERLIST_A_LAST_LOGIN,
    USERLIST_A_LAST_ACCESS,
    USERLIST_A_LAST_CHANGE,
    USERLIST_A_INVISIBLE,
    USERLIST_A_BANNED,
    USERLIST_A_LOCKED,
    USERLIST_A_INCOMPLETE,
    USERLIST_A_DISQUALIFIED,
    USERLIST_A_STATUS,
    USERLIST_A_LAST_PWDCHANGE,
    USERLIST_A_PUBLIC,
    USERLIST_A_USE_COOKIES,
    USERLIST_A_LAST_MINOR_CHANGE,
    USERLIST_A_MEMBER_SERIAL,
    USERLIST_A_SERIAL,
    USERLIST_A_READ_ONLY,
    USERLIST_A_PRIV_LEVEL,
    USERLIST_A_NEVER_CLEAN,
    USERLIST_A_PRIVILEGED,
    USERLIST_A_DATE,
    USERLIST_A_SIMPLE_REGISTRATION,
    USERLIST_A_CNTS_READ_ONLY,
    USERLIST_A_CREATE,
    USERLIST_A_COPIED_FROM,
    USERLIST_A_SSL,
    USERLIST_A_LAST_INFO_PWDCHANGE,
    USERLIST_A_LAST_INFO_CHANGE,
    USERLIST_A_ROLE,
    USERLIST_A_CNTS_LAST_LOGIN,
    USERLIST_A_INFO_CREATE,
    USERLIST_A_RECOVERY,
    USERLIST_A_TEAM_LOGIN,

    USERLIST_LAST_ATTN,
  };

// this is for field editing
enum
  {
    /* general user info fields */
    /* 0 */
    USERLIST_NN_FIRST, USERLIST_NN_ID = USERLIST_NN_FIRST,
    USERLIST_NN_IS_PRIVILEGED,
    USERLIST_NN_IS_INVISIBLE,
    USERLIST_NN_IS_BANNED,
    USERLIST_NN_IS_LOCKED,
    /* 5 */
    USERLIST_NN_SHOW_LOGIN,
    USERLIST_NN_SHOW_EMAIL,
    USERLIST_NN_READ_ONLY,
    USERLIST_NN_NEVER_CLEAN,
    USERLIST_NN_SIMPLE_REGISTRATION,
    /* 10 */
    USERLIST_NN_LOGIN,
    USERLIST_NN_EMAIL,
    USERLIST_NN_PASSWD,
    USERLIST_NN_REGISTRATION_TIME,
    USERLIST_NN_LAST_LOGIN_TIME,
    /* 15 */
    USERLIST_NN_LAST_CHANGE_TIME,
    USERLIST_NN_LAST_PWDCHANGE_TIME,

    USERLIST_NN_LAST,

    /* contest-specific user info fields */
    /* 100 */
    USERLIST_NC_FIRST = 100, USERLIST_NC_CNTS_READ_ONLY = USERLIST_NC_FIRST,
    USERLIST_NC_NAME,
    USERLIST_NC_TEAM_PASSWD,
    USERLIST_NC_INST,
    USERLIST_NC_INST_EN,
    /* 105 */
    USERLIST_NC_INSTSHORT,
    USERLIST_NC_INSTSHORT_EN,
    USERLIST_NC_INSTNUM,
    USERLIST_NC_FAC,
    USERLIST_NC_FAC_EN,
    /* 110 */
    USERLIST_NC_FACSHORT,
    USERLIST_NC_FACSHORT_EN,
    USERLIST_NC_HOMEPAGE,
    USERLIST_NC_CITY,
    USERLIST_NC_CITY_EN,
    /* 115 */
    USERLIST_NC_COUNTRY,
    USERLIST_NC_COUNTRY_EN,
    USERLIST_NC_REGION,
    USERLIST_NC_AREA,
    USERLIST_NC_ZIP,
    /* 120 */
    USERLIST_NC_STREET,
    USERLIST_NC_LOCATION,
    USERLIST_NC_SPELLING,
    USERLIST_NC_PRINTER_NAME,
    USERLIST_NC_EXAM_ID,
    /* 125 */
    USERLIST_NC_EXAM_CYPHER,
    USERLIST_NC_LANGUAGES,
    USERLIST_NC_PHONE,
    USERLIST_NC_FIELD0,
    USERLIST_NC_FIELD1,
    /* 130 */
    USERLIST_NC_FIELD2,
    USERLIST_NC_FIELD3,
    USERLIST_NC_FIELD4,
    USERLIST_NC_FIELD5,
    USERLIST_NC_FIELD6,
    /* 135 */
    USERLIST_NC_FIELD7,
    USERLIST_NC_FIELD8,
    USERLIST_NC_FIELD9,
    USERLIST_NC_CREATE_TIME,
    USERLIST_NC_LAST_LOGIN_TIME,
    /* 140 */
    USERLIST_NC_LAST_CHANGE_TIME,
    USERLIST_NC_LAST_PWDCHANGE_TIME,

    USERLIST_NC_LAST,

    /* user member info fields */
    /* 200 */
    USERLIST_NM_FIRST = 200, USERLIST_NM_SERIAL = USERLIST_NM_FIRST,
    USERLIST_NM_STATUS,
    USERLIST_NM_GENDER,
    USERLIST_NM_GRADE,
    USERLIST_NM_FIRSTNAME,
    /* 205 */
    USERLIST_NM_FIRSTNAME_EN,
    USERLIST_NM_MIDDLENAME,
    USERLIST_NM_MIDDLENAME_EN,
    USERLIST_NM_SURNAME,
    USERLIST_NM_SURNAME_EN,
    /* 210 */
    USERLIST_NM_GROUP,
    USERLIST_NM_GROUP_EN,
    USERLIST_NM_EMAIL,
    USERLIST_NM_HOMEPAGE,
    USERLIST_NM_OCCUPATION,
    /* 215 */
    USERLIST_NM_OCCUPATION_EN,
    USERLIST_NM_DISCIPLINE,
    USERLIST_NM_INST,
    USERLIST_NM_INST_EN,
    USERLIST_NM_INSTSHORT,
    /* 220 */
    USERLIST_NM_INSTSHORT_EN,
    USERLIST_NM_FAC,
    USERLIST_NM_FAC_EN,
    USERLIST_NM_FACSHORT,
    USERLIST_NM_FACSHORT_EN,
    /* 225 */
    USERLIST_NM_PHONE,
    USERLIST_NM_CREATE_TIME,
    USERLIST_NM_LAST_CHANGE_TIME,
    USERLIST_NM_BIRTH_DATE,
    USERLIST_NM_ENTRY_DATE,
    /* 230 */
    USERLIST_NM_GRADUATION_DATE,

    USERLIST_NM_LAST,
  };

typedef unsigned long userlist_login_hash_t;

struct userlist_member
{
  struct xml_tree b;

  int team_role;
  int serial;
  int copied_from;
  int status;
  int gender;
  int grade;
  unsigned char *firstname;
  unsigned char *firstname_en;
  unsigned char *middlename;
  unsigned char *middlename_en;
  unsigned char *surname;
  unsigned char *surname_en;
  unsigned char *group;
  unsigned char *group_en;
  unsigned char *email;
  unsigned char *homepage;
  unsigned char *occupation;
  unsigned char *occupation_en;
  unsigned char *discipline;
  unsigned char *inst;
  unsigned char *inst_en;
  unsigned char *instshort;
  unsigned char *instshort_en;
  unsigned char *fac;
  unsigned char *fac_en;
  unsigned char *facshort;
  unsigned char *facshort_en;
  unsigned char *phone;

  time_t birth_date;
  time_t entry_date;
  time_t graduation_date;

  time_t create_time;
  time_t last_change_time;
  time_t last_access_time;
};

struct userlist_members
{
  struct xml_tree b;

  int a, u; /* allocated, used */
  struct userlist_member **m;
};

struct userlist_cookie
{
  struct xml_tree b;

  int user_id;
  ej_ip_t ip;
  int ssl;
  ej_cookie_t cookie;
  time_t expire;
  int contest_id;
  int locale_id;
  int priv_level;
  int role;
  int recovery;
  int team_login;               /* used in case when team_passwd != reg_passwd*/
};

struct userlist_contest
{
  struct xml_tree b;

  int id;
  int status;
  unsigned int flags;
  time_t create_time;
  time_t last_change_time;
};

struct userlist_user_info
{
  struct xml_tree b;

  int contest_id;
  int cnts_read_only;

  unsigned char *name;
  int instnum;

  // team password
  int team_passwd_method;
  unsigned char *team_passwd;

  unsigned char *inst;
  unsigned char *inst_en;
  unsigned char *instshort;
  unsigned char *instshort_en;
  unsigned char *fac;
  unsigned char *fac_en;
  unsigned char *facshort;
  unsigned char *facshort_en;
  unsigned char *homepage;
  unsigned char *city;
  unsigned char *city_en;
  unsigned char *country;
  unsigned char *country_en;
  unsigned char *region;
  unsigned char *area;
  unsigned char *zip;
  unsigned char *street;
  unsigned char *location;
  unsigned char *spelling;
  unsigned char *printer_name;
  unsigned char *exam_id;
  unsigned char *exam_cypher;
  unsigned char *languages;
  unsigned char *phone;
  unsigned char *field0;
  unsigned char *field1;
  unsigned char *field2;
  unsigned char *field3;
  unsigned char *field4;
  unsigned char *field5;
  unsigned char *field6;
  unsigned char *field7;
  unsigned char *field8;
  unsigned char *field9;
  struct userlist_members *members;

  time_t create_time;
  time_t last_login_time;
  time_t last_change_time;
  time_t last_access_time;
  time_t last_pwdchange_time;
};

struct userlist_user
{
  struct xml_tree b;

  int id;
  int is_privileged;
  int is_invisible;
  int is_banned;
  int is_locked;
  int show_login;
  int show_email;
  int read_only;
  int never_clean;
  int simple_registration;

  unsigned char *login;
  unsigned char *email;

  userlist_login_hash_t login_hash;

  // registration password
  int passwd_method;
  unsigned char *passwd;

  struct xml_tree *cookies;
  struct xml_tree *contests;

  unsigned char *extra1;

  time_t registration_time;
  time_t last_login_time;
  time_t last_minor_change_time;

  time_t last_change_time;
  time_t last_access_time;
  time_t last_pwdchange_time;

  /* the contest-specific information */
  int cntsinfo_a;
  struct userlist_user_info **cntsinfo;

  /* the default (legacy) values for contest-specific fields */
  /* also these fields are returned when contest_id is provided for
   * user requests
   */
  struct userlist_user_info *cnts0;
};

struct userlist_list
{
  struct xml_tree b;

  unsigned char *name;
  int user_map_size;
  struct userlist_user **user_map;
  int member_serial;

  /* login hash information */
  size_t login_hash_size;
  size_t login_hash_step;
  size_t login_thresh;
  size_t login_cur_fill;
  struct userlist_user **login_hash_table;

  /* login cookie information */
  size_t cookie_hash_size;
  size_t cookie_hash_step;
  size_t cookie_thresh;
  size_t cookie_cur_fill;
  struct userlist_cookie **cookie_hash_table;
};

// unparse modes
enum
  {
    USERLIST_MODE_ALL,
    USERLIST_MODE_USER,
    USERLIST_MODE_OTHER,
    USERLIST_MODE_SHORT,
    USERLIST_MODE_STAND,
  };

enum
  {
    USERLIST_FORCE_FIRST_MEMBER = 1,
    USERLIST_SHOW_REG_PASSWD = 2,
    USERLIST_SHOW_CNTS_PASSWD = 4,
    USERLIST_SHOW_PRIV_REG_PASSWD = 8,
    USERLIST_SHOW_PRIV_CNTS_PASSWD = 16,
  };

struct userlist_list *userlist_new(void);
struct userlist_list *userlist_parse(char const *path);
struct userlist_list *userlist_parse_str(unsigned char const *str);
struct userlist_user *userlist_parse_user_str(char const *str);
void userlist_unparse(struct userlist_list *p, FILE *f);
void userlist_unparse_user(const struct userlist_user *p, FILE *f, int mode,
                           int contest_id, int flags);
void userlist_real_unparse_user(const struct userlist_user *p, FILE *f,
                                int mode, int contest_id, int flags);
void userlist_unparse_short(struct userlist_list *p, FILE *f, int contest_id);
/*
void userlist_unparse_for_standings(struct userlist_list *, FILE *, int, int, int, const unsigned char *);
*/
void userlist_unparse_user_short(const struct userlist_user *p, FILE *f,
                                 int contest_id);

unsigned char const *userlist_unparse_reg_status(int s);
unsigned char const *userlist_member_status_str(int status);
unsigned char const *userlist_gender_str(int gender);

int userlist_parse_date_2(const unsigned char *str, time_t *pd);
const unsigned char *userlist_unparse_date_2(unsigned char *buf, size_t size,
                                             time_t d, int convert_null);

void *userlist_free(struct xml_tree *p);
void userlist_remove_user(struct userlist_list *p, struct userlist_user *u);

struct xml_tree *userlist_node_alloc(int tag);
unsigned char const *userlist_tag_to_str(int t);

void userlist_unparse_contests(struct userlist_user *p, FILE *f);
void userlist_unparse_contest(const struct userlist_contest *cc, FILE *f,
                              unsigned char const *indent);
struct xml_tree *userlist_parse_contests_str(unsigned char const *str);

const unsigned char *userlist_unparse_date(time_t d, int show_null);

// member structure operations
void *userlist_get_member_field_ptr(const struct userlist_member *ptr,
                                    int field_id);
int userlist_is_empty_member_field(const struct userlist_member *m,
                                   int field_id);
int userlist_is_equal_member_field(const struct userlist_member *m,
                                   int field_id,
                                   const unsigned char *value);
int userlist_get_member_field_str(unsigned char *buf, size_t len,
                                  const struct userlist_member *m,
                                  int field_id,
                                  int convert_null,
                                  int use_locale);
int userlist_set_member_field_str(struct userlist_member *m,
                                  int field_id,
                                  unsigned char const *field_val);
int userlist_delete_member_field(struct userlist_member *m, int field_id);

// user_info structure operations
void *userlist_get_user_info_field_ptr(const struct userlist_user_info *ptr,
                                       int field_id);
int userlist_is_empty_user_info_field(const struct userlist_user_info *ui,
                                      int field_id);
int userlist_is_equal_user_info_field(const struct userlist_user_info *ui,
                                      int field_id,
                                      const unsigned char *value);
int userlist_get_user_info_field_str(unsigned char *buf, size_t len,
                                     const struct userlist_user_info *ui,
                                     int field_id,
                                     int convert_null);
int userlist_set_user_info_field_str(struct userlist_user_info *ui,
                                     int field_id,
                                     unsigned char const *field_val);
int userlist_delete_user_info_field(struct userlist_user_info *ui,
                                    int field_id);

// user structure operations
void *userlist_get_user_field_ptr(const struct userlist_user *ptr,
                                  int field_id);
int userlist_is_empty_user_field(const struct userlist_user *u,
                                 int field_id);
int userlist_is_equal_user_field(const struct userlist_user *u,
                                 int field_id,
                                 const unsigned char *value);
int userlist_get_user_field_str(unsigned char *buf, size_t len,
                                const struct userlist_user *u,
                                int field_id,
                                int convert_null);
int userlist_set_user_field_str(struct userlist_user *u,
                                int field_id,
                                unsigned char const *field_val);
int userlist_delete_user_field(struct userlist_user *u,
                               int field_id);

userlist_login_hash_t userlist_login_hash(const unsigned char *p);
int userlist_build_login_hash(struct userlist_list *p);
int userlist_build_cookie_hash(struct userlist_list *p);

int userlist_cookie_hash_add(struct userlist_list *, const struct userlist_cookie *);
int userlist_cookie_hash_del(struct userlist_list *, const struct userlist_cookie *);

void userlist_expand_cntsinfo(struct userlist_user *u, int contest_id);

struct userlist_user_info *
userlist_new_cntsinfo(struct userlist_user *u, int contest_id,
                      time_t current_time);
const struct userlist_user_info *
userlist_get_user_info(const struct userlist_user *u, int contest_id);
struct userlist_user_info *
userlist_get_user_info_nc(struct userlist_user *u, int contest_id);
const struct userlist_contest *
userlist_get_user_contest(const struct userlist_user *u, int contest_id);
struct userlist_member *
userlist_get_member_nc(struct userlist_members *, int, int *, int *);
void userlist_clear_copied_from(struct userlist_members *mm);

void userlist_write_xml_header(FILE *f);
void userlist_write_xml_footer(FILE *f);
void userlist_write_contests_xml_header(FILE *f);
void userlist_write_contests_xml_footer(FILE *f);

int userlist_map_userlist_to_contest_field(int uf);
int userlist_str_to_user_field_code(const unsigned char *str);

/* valid character sets */
extern const unsigned char login_accept_chars[257];
extern const unsigned char email_accept_chars[257];
extern const unsigned char name_accept_chars[257];
extern const unsigned char name_en_accept_chars[257];
extern const unsigned char url_accept_chars[257];
extern const unsigned char password_accept_chars[257];

extern const int userlist_contest_field_ids[];
extern const int userlist_member_field_ids[];

const unsigned char *userlist_get_contest_accepting_chars(int f);
const unsigned char *userlist_get_member_accepting_chars(int f);
int
userlist_count_info_errors(
        const struct contest_desc *cnts,
        const struct userlist_user *u,
        const struct userlist_user_info *ui,
        const struct userlist_members *mm,
        int role_err_count[]);

void userlist_elem_free_data(struct xml_tree *t);

int userlist_members_count(const struct userlist_members *mmm, int role);
const struct userlist_member *
userlist_members_get_first(const struct userlist_members *mmm);
const struct userlist_member *
userlist_members_get_nth(
        const struct userlist_members *mmm,
        int role,
        int n);
void userlist_members_reserve(struct userlist_members *mm, int n);

struct userlist_user_info *userlist_get_cnts0(struct userlist_user *u);

#endif /* __USERLIST_H__ */
