/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_H__
#define __USERLIST_H__

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

#include "ej_types.h"
#include "expat_iface.h"
#include "contests.h"

#include <stdio.h>

enum
  {
    USERLIST_PWD_PLAIN,
    USERLIST_PWD_BASE64,
    USERLIST_PWD_SHA1
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
    USERLIST_T_USERLIST = 1,
    USERLIST_T_USER,
    USERLIST_T_LOGIN,
    USERLIST_T_NAME,
    USERLIST_T_INST,
    USERLIST_T_INST_EN,
    USERLIST_T_INSTSHORT,
    USERLIST_T_INSTSHORT_EN,
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
    USERLIST_T_LOCATION,
    USERLIST_T_SPELLING,
    USERLIST_T_PRINTER_NAME,
    USERLIST_T_LANGUAGES,
    USERLIST_T_EXTRA1,
    USERLIST_T_CNTSINFOS,
    USERLIST_T_CNTSINFO,

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

    USERLIST_LAST_ATTN,
  };

// this is for field editing
enum
  {
    USERLIST_NN_ID,             /* 0 */
    USERLIST_NN_LOGIN,          /* 1 */
    USERLIST_NN_EMAIL,          /* 2 */
    USERLIST_NN_NAME,           /* 3 */
    USERLIST_NN_IS_PRIVILEGED,  /* 4 */
    USERLIST_NN_IS_INVISIBLE,   /* 5 */
    USERLIST_NN_IS_BANNED,      /* 6 */
    USERLIST_NN_IS_LOCKED,      /* 7 */
    USERLIST_NN_SHOW_LOGIN,     /* 8 */
    USERLIST_NN_SHOW_EMAIL,     /* 9 */
    USERLIST_NN_USE_COOKIES,    /* 10 */
    USERLIST_NN_READ_ONLY,      /* 11 */
    USERLIST_NN_CNTS_READ_ONLY, /* 12 */
    USERLIST_NN_NEVER_CLEAN,    /* 13 */
    USERLIST_NN_SIMPLE_REGISTRATION, /* 14 */
    USERLIST_NN_TIMESTAMPS,     /* 15 */
    USERLIST_NN_REG_TIME,       /* 16 */
    USERLIST_NN_LOGIN_TIME,     /* 17 */
    USERLIST_NN_ACCESS_TIME,    /* 18 */
    USERLIST_NN_CHANGE_TIME,    /* 19 */
    USERLIST_NN_PWD_CHANGE_TIME, /* 20 */
    USERLIST_NN_MINOR_CHANGE_TIME, /* 21 */
    USERLIST_NN_TIMESTAMP_LAST = USERLIST_NN_MINOR_CHANGE_TIME,
    USERLIST_NN_PASSWORDS,      /* 22 */
    USERLIST_NN_REG_PASSWORD,   /* 23 */
    USERLIST_NN_TEAM_PASSWORD,  /* 24 */
    USERLIST_NN_GENERAL_INFO,   /* 25 */
    USERLIST_NN_INST,           /* 26 */
    USERLIST_NN_INST_EN,        /* 27 */
    USERLIST_NN_INSTSHORT,      /* 28 */
    USERLIST_NN_INSTSHORT_EN,   /* 29 */
    USERLIST_NN_FAC,            /* 30 */
    USERLIST_NN_FAC_EN,         /* 31 */
    USERLIST_NN_FACSHORT,       /* 32 */
    USERLIST_NN_FACSHORT_EN,    /* 33 */
    USERLIST_NN_HOMEPAGE,       /* 34 */
    USERLIST_NN_PHONE,          /* 35 */
    USERLIST_NN_CITY,           /* 36 */
    USERLIST_NN_CITY_EN,        /* 37 */
    USERLIST_NN_COUNTRY,        /* 38 */
    USERLIST_NN_COUNTRY_EN,     /* 39 */
    USERLIST_NN_LOCATION,       /* 40 */
    USERLIST_NN_SPELLING,       /* 41 */
    USERLIST_NN_PRINTER_NAME,   /* 42 */
    USERLIST_NN_LANGUAGES,      /* 43 */
    USERLIST_NN_LAST = USERLIST_NN_LANGUAGES,

    USERLIST_NM_SERIAL = 0,              /* 0 */
    USERLIST_NM_FIRSTNAME,               /* 1 */
    USERLIST_NM_FIRSTNAME_EN,            /* 2 */
    USERLIST_NM_MIDDLENAME,              /* 3 */
    USERLIST_NM_MIDDLENAME_EN,           /* 4 */
    USERLIST_NM_SURNAME,                 /* 5 */
    USERLIST_NM_SURNAME_EN,              /* 6 */
    USERLIST_NM_STATUS,                  /* 7 */
    USERLIST_NM_GRADE,                   /* 8 */
    USERLIST_NM_GROUP,                   /* 9 */
    USERLIST_NM_GROUP_EN,                /* 10 */
    USERLIST_NM_OCCUPATION,              /* 11 */
    USERLIST_NM_OCCUPATION_EN,           /* 12 */
    USERLIST_NM_EMAIL,                   /* 13 */
    USERLIST_NM_HOMEPAGE,                /* 14 */
    USERLIST_NM_PHONE,                   /* 15 */
    USERLIST_NM_INST,                    /* 16 */
    USERLIST_NM_INST_EN,                 /* 17 */
    USERLIST_NM_INSTSHORT,               /* 18 */
    USERLIST_NM_INSTSHORT_EN,            /* 19 */
    USERLIST_NM_FAC,                     /* 20 */
    USERLIST_NM_FAC_EN,                  /* 21 */
    USERLIST_NM_FACSHORT,                /* 22 */
    USERLIST_NM_FACSHORT_EN,             /* 23 */
    USERLIST_NM_LAST = USERLIST_NM_FACSHORT_EN,
  };

typedef unsigned long userlist_login_hash_t;

struct userlist_member
{
  struct xml_tree b;

  int serial;
  int status;
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
  unsigned char *inst;
  unsigned char *inst_en;
  unsigned char *instshort;
  unsigned char *instshort_en;
  unsigned char *fac;
  unsigned char *fac_en;
  unsigned char *facshort;
  unsigned char *facshort_en;
  unsigned char *phone;
};

struct userlist_members
{
  struct xml_tree b;

  int role;
  int total;
  int allocd;
  struct userlist_member **members;
};

struct userlist_cookie
{
  struct xml_tree b;

  struct userlist_user *user;
  ej_ip_t ip;
  ej_cookie_t cookie;
  time_t expire;
  int contest_id;
  int locale_id;
  int priv_level;
};

struct userlist_contest
{
  struct xml_tree b;

  int id;
  int status;
  unsigned int flags;
  time_t date;
};

struct userlist_passwd
{
  struct xml_tree b;

  int method;
};

struct userlist_cntsinfo
{
  struct xml_tree b;

  int contest_id;
  int cnts_read_only;

  unsigned char *name;
  struct userlist_passwd *team_passwd;
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
  unsigned char *location;
  unsigned char *spelling;
  unsigned char *printer_name;
  unsigned char *languages;
  unsigned char *phone;
  struct userlist_members *members[USERLIST_MB_LAST];

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
  int default_use_cookies;
  int read_only;
  int never_clean;
  int simple_registration;

  unsigned char *login;
  unsigned char *email;

  userlist_login_hash_t login_hash;

  struct userlist_passwd *register_passwd;
  struct xml_tree *cookies;
  struct xml_tree *contests;

  unsigned char *extra1;

  time_t registration_time;
  time_t last_login_time;

  time_t last_change_time;
  time_t last_access_time;
  time_t last_pwdchange_time;
  time_t last_minor_change_time;

  /* the contest-specific information */
  int cntsinfo_a;
  struct userlist_cntsinfo **cntsinfo;

  /* the default (legacy) values for contest-specific fields */
  /* also these fields are returned when contest_id is provided for
   * user requests
   */

  unsigned char *name;
  struct userlist_passwd *team_passwd;

  int cnts_read_only;

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
  unsigned char *location;
  unsigned char *spelling;
  unsigned char *printer_name;
  unsigned char *languages;
  unsigned char *phone;

  struct userlist_members *members[USERLIST_MB_LAST];
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

struct userlist_list *userlist_new(void);
struct userlist_list *userlist_parse(char const *path);
struct userlist_list *userlist_parse_str(unsigned char const *str);
struct userlist_user *userlist_parse_user_str(char const *str);
void userlist_unparse(struct userlist_list *p, FILE *f);
void userlist_unparse_user(struct userlist_user *p, FILE *f, int mode);
void userlist_unparse_short(struct userlist_list *p, FILE *f, int contest_id);
void userlist_unparse_for_standings(struct userlist_list *, FILE *, int);

unsigned char const *userlist_unparse_reg_status(int s);
unsigned char const *userlist_member_status_str(int status);

void *userlist_free(struct xml_tree *p);
void userlist_remove_user(struct userlist_list *p, struct userlist_user *u);

struct xml_tree *userlist_node_alloc(int tag);
unsigned char const *userlist_tag_to_str(int t);

void userlist_unparse_contests(struct userlist_user *p, FILE *f);
struct xml_tree *userlist_parse_contests_str(unsigned char const *str);

const unsigned char *userlist_unparse_date(time_t d, int show_null);
int userlist_get_member_field_str(unsigned char *buf, size_t len,
                                  struct userlist_member *m, int field_id,
                                  int convert_null);
int userlist_set_member_field_str(struct userlist_member *m, int field_id,
                                  unsigned char const *field_val);
int userlist_delete_member_field(struct userlist_member *m, int field_id);
int userlist_get_user_field_str(unsigned char *buf, size_t len,
                                struct userlist_user *u, int field_id,
                                int convert_null);
int userlist_set_user_field_str(struct userlist_list *lst,
                                struct userlist_user *u, int field_id,
                                unsigned char const *field_val);
int userlist_delete_user_field(struct userlist_user *u, int field_id);

userlist_login_hash_t userlist_login_hash(const unsigned char *p);
int userlist_build_login_hash(struct userlist_list *p);
int userlist_build_cookie_hash(struct userlist_list *p);

int userlist_cookie_hash_add(struct userlist_list *, struct userlist_cookie *);
int userlist_cookie_hash_del(struct userlist_list *, struct userlist_cookie *);

#endif /* __USERLIST_H__ */
