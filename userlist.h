/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_H__
#define __USERLIST_H__

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
    USERLIST_T_INSTSHORT,
    USERLIST_T_FAC,
    USERLIST_T_FACSHORT,
    USERLIST_T_PASSWORD,
    USERLIST_T_EMAIL,
    USERLIST_T_HOMEPAGE,
    USERLIST_T_PHONES,
    USERLIST_T_PHONE,
    USERLIST_T_MEMBER,
    USERLIST_T_SURNAME,
    USERLIST_T_MIDDLENAME,
    USERLIST_T_GRADE,
    USERLIST_T_GROUP,
    USERLIST_T_COOKIES,
    USERLIST_T_COOKIE,
    USERLIST_T_CONTESTS,
    USERLIST_T_CONTEST,
    USERLIST_T_STATUS,
    USERLIST_T_OCCUPATION,
    USERLIST_T_CONTESTANTS,
    USERLIST_T_RESERVES,
    USERLIST_T_COACHES,
    USERLIST_T_ADVISORS,
    USERLIST_T_GUESTS,
    USERLIST_T_FIRSTNAME,
    USERLIST_T_TEAM_PASSWORD,
    USERLIST_T_CITY,
    USERLIST_T_COUNTRY,

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
    USERLIST_A_STATUS,
    USERLIST_A_LAST_PWDCHANGE,
    USERLIST_A_PUBLIC,
    USERLIST_A_USE_COOKIES,
    USERLIST_A_LAST_MINOR_CHANGE,
    USERLIST_A_MEMBER_SERIAL,
    USERLIST_A_SERIAL,
    USERLIST_A_READ_ONLY,

    USERLIST_LAST_ATTN,
  };

// this is for field editing
enum
  {
    USERLIST_NN_ID,             /* 0 */
    USERLIST_NN_LOGIN,          /* 1 */
    USERLIST_NN_EMAIL,          /* 2 */
    USERLIST_NN_NAME,           /* 3 */
    USERLIST_NN_IS_INVISIBLE,   /* 4 */
    USERLIST_NN_IS_BANNED,      /* 5 */
    USERLIST_NN_SHOW_LOGIN,     /* 6 */
    USERLIST_NN_SHOW_EMAIL,     /* 7 */
    USERLIST_NN_USE_COOKIES,    /* 8 */
    USERLIST_NN_READ_ONLY,      /* 9 */
    USERLIST_NN_TIMESTAMPS,     /* 10 */
    USERLIST_NN_REG_TIME,       /* 11 */
    USERLIST_NN_LOGIN_TIME,     /* 12 */
    USERLIST_NN_ACCESS_TIME,    /* 13 */
    USERLIST_NN_CHANGE_TIME,    /* 14 */
    USERLIST_NN_PWD_CHANGE_TIME, /* 15 */
    USERLIST_NN_MINOR_CHANGE_TIME, /* 16 */
    USERLIST_NN_TIMESTAMP_LAST = USERLIST_NN_MINOR_CHANGE_TIME,
    USERLIST_NN_PASSWORDS,      /* 17 */
    USERLIST_NN_REG_PASSWORD,   /* 18 */
    USERLIST_NN_TEAM_PASSWORD,  /* 19 */
    USERLIST_NN_GENERAL_INFO,   /* 20 */
    USERLIST_NN_INST,           /* 21 */
    USERLIST_NN_INSTSHORT,      /* 22 */
    USERLIST_NN_FAC,            /* 23 */
    USERLIST_NN_FACSHORT,       /* 24 */
    USERLIST_NN_HOMEPAGE,       /* 25 */
    USERLIST_NN_CITY,           /* 26 */
    USERLIST_NN_COUNTRY,        /* 27 */
    USERLIST_NN_LAST = USERLIST_NN_COUNTRY,

    USERLIST_NM_SERIAL = 0,              /* 0 */
    USERLIST_NM_FIRSTNAME,               /* 1 */
    USERLIST_NM_MIDDLENAME,              /* 2 */
    USERLIST_NM_SURNAME,                 /* 3 */
    USERLIST_NM_STATUS,                  /* 4 */
    USERLIST_NM_GRADE,                   /* 5 */
    USERLIST_NM_GROUP,                   /* 6 */
    USERLIST_NM_OCCUPATION,              /* 7 */
    USERLIST_NM_EMAIL,                   /* 8 */
    USERLIST_NM_HOMEPAGE,                /* 9 */
    USERLIST_NM_INST,                    /* 10 */
    USERLIST_NM_INSTSHORT,               /* 11 */
    USERLIST_NM_FAC,                     /* 12 */
    USERLIST_NM_FACSHORT,                /* 13 */
    USERLIST_NM_LAST = USERLIST_NM_FACSHORT,
  };

#if !defined __USERLIST_UC_ENUM_DEFINED__
#define __USERLIST_UC_ENUM_DEFINED__
enum
  {
    USERLIST_UC_INVISIBLE = 0x00000001,
    USERLIST_UC_BANNED    = 0x00000002,

    USERLIST_UC_ALL       = 0x00000003
  };
#endif /* __USERLIST_UC_ENUM_DEFINED__ */

struct userlist_member
{
  struct xml_tree b;

  int serial;
  int status;
  int grade;
  unsigned char *firstname;
  unsigned char *middlename;
  unsigned char *surname;
  unsigned char *group;
  unsigned char *email;
  unsigned char *homepage;
  unsigned char *occupation;
  unsigned char *inst;
  unsigned char *instshort;
  unsigned char *fac;
  unsigned char *facshort;
  struct xml_tree *phones;
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
  unsigned long ip;
  unsigned long long cookie;
  unsigned long expire;
  int contest_id;
  int locale_id;
};

struct userlist_contest
{
  struct xml_tree b;

  int id;
  int status;
  unsigned int flags;
};

struct userlist_passwd
{
  struct xml_tree b;

  int method;
};

struct userlist_user
{
  struct xml_tree b;

  int id;
  int is_invisible;
  int is_banned;
  int show_login;
  int show_email;
  int default_use_cookies;
  int read_only;

  unsigned char *login;
  unsigned char *name;
  unsigned char *email;

  struct userlist_passwd *register_passwd;
  struct userlist_passwd *team_passwd;

  unsigned char *inst;
  unsigned char *instshort;
  unsigned char *fac;
  unsigned char *facshort;
  unsigned char *homepage;
  unsigned char *city;
  unsigned char *country;

  struct xml_tree *cookies;
  struct userlist_members *members[USERLIST_MB_LAST];
  struct xml_tree *phones;
  struct xml_tree *contests;

  unsigned long registration_time;
  unsigned long last_login_time;
  unsigned long last_change_time;
  unsigned long last_access_time;
  unsigned long last_pwdchange_time;
  unsigned long last_minor_change_time;
};

struct userlist_list
{
  struct xml_tree b;

  unsigned char *name;
  int user_map_size;
  struct userlist_user **user_map;
  int member_serial;
};

// unparse modes
enum
  {
    USERLIST_MODE_ALL,
    USERLIST_MODE_USER,
    USERLIST_MODE_OTHER,
    USERLIST_MODE_SHORT
  };

struct userlist_list *userlist_new(void);
struct userlist_list *userlist_parse(char const *path);
struct userlist_list *userlist_parse_str(unsigned char const *str);
struct userlist_user *userlist_parse_user_str(char const *str);
void userlist_unparse(struct userlist_list *p, FILE *f);
void userlist_unparse_user(struct userlist_user *p, FILE *f, int mode);
void userlist_unparse_short(struct userlist_list *p, FILE *f, int contest_id);

unsigned char const *userlist_unparse_reg_status(int s);
unsigned char const *userlist_member_status_str(int status);

void *userlist_free(struct xml_tree *p);
void userlist_remove_user(struct userlist_list *p, struct userlist_user *u);

struct xml_tree *userlist_node_alloc(int tag);
unsigned char const *userlist_tag_to_str(int t);

void userlist_unparse_contests(struct userlist_user *p, FILE *f);
struct xml_tree *userlist_parse_contests_str(unsigned char const *str);
int userlist_parse_date(unsigned char const *s, unsigned long *pd);
int userlist_parse_bool(unsigned char const *str);
unsigned char *userlist_unparse_ip(unsigned long ip);

unsigned char const *userlist_unparse_bool(int b);
unsigned char *userlist_unparse_date(unsigned long d, int show_null);
int userlist_get_member_field_str(unsigned char *buf, size_t len,
                                  struct userlist_member *m, int field_id,
                                  int convert_null);
int userlist_set_member_field_str(struct userlist_member *m, int field_id,
                                  unsigned char const *field_val);
int userlist_delete_member_field(struct userlist_member *m, int field_id);
int userlist_get_user_field_str(unsigned char *buf, size_t len,
                                struct userlist_user *u, int field_id,
                                int convert_null);
int userlist_set_user_field_str(struct userlist_user *u, int field_id,
                                unsigned char const *field_val);
int userlist_delete_user_field(struct userlist_user *u, int field_id);




#endif /* __USERLIST_H__ */
