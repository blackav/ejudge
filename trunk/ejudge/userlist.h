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

#include <stdio.h>

enum
  {
    USERLIST_PWD_PLAIN,
    USERLIST_PWD_BASE64,
    USERLIST_PWD_SHA1
  };

enum
  {
    USERLIST_MB_CONTESTANT,
    USERLIST_MB_RESERVE,
    USERLIST_MB_COACH,
    USERLIST_MB_ADVISOR
  };

enum
  {
    USERLIST_REG_OK,
    USERLIST_REG_PENDING,
    USERLIST_REG_REJECTED,
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
    USERLIST_T_MEMBERS,
    USERLIST_T_MEMBER,
    USERLIST_T_SURNAME,
    USERLIST_T_MIDDLENAME,
    USERLIST_T_GRADE,
    USERLIST_T_GROUP,
    USERLIST_T_COOKIES,
    USERLIST_T_COOKIE,
    USERLIST_T_REGISTRATIONS,
    USERLIST_T_REGISTRATION,
    USERLIST_T_STATUS,
    USERLIST_T_OCCUPATION,

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
    USERLIST_A_ROLE,
    USERLIST_A_CONTEST_ID,
    USERLIST_A_REGISTERED,
    USERLIST_A_LAST_LOGIN,
    USERLIST_A_LAST_ACCESS,
    USERLIST_A_LAST_CHANGE,
    USERLIST_A_INVISIBLE,
    USERLIST_A_BANNED,
    USERLIST_A_STATUS,
    USERLIST_A_LAST_PWDCHANGE,

    USERLIST_LAST_ATTN,
  };

struct userlist_member
{
  struct xml_tree b;

  int role;
  int status;
  int grade;
  unsigned char *name;
  unsigned char *middlename;
  unsigned char *surname;
  unsigned char *group;
  unsigned char *email;
  unsigned char *homepage;
  unsigned char *occupation;
  struct xml_tree *phones;
};

struct userlist_members
{
  struct xml_tree b;

  int contestants_total;
  int reserves_total;
  int coaches_total;
  int advisors_total;
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

struct userlist_reg
{
  struct xml_tree b;

  int contest_id;
  int status;
};

struct userlist_user
{
  struct xml_tree b;

  int id;
  int is_invisible;
  int is_banned;

  unsigned char *login;
  unsigned char *name;
  unsigned char *email;

  int passwd_method;
  unsigned char *passwd;

  unsigned char *inst;
  unsigned char *instshort;
  unsigned char *fac;
  unsigned char *facshort;
  unsigned char *homepage;

  struct xml_tree *cookies;
  struct userlist_members *members;
  struct xml_tree *phones;
  struct xml_tree *registrations;

  unsigned long registration_time;
  unsigned long last_login_time;
  unsigned long last_change_time;
  unsigned long last_access_time;
  unsigned long last_pwdchange_time;
};

struct userlist_list
{
  struct xml_tree b;

  unsigned char *name;
  int user_map_size;
  struct userlist_user **user_map;
};

struct userlist_list *userlist_parse(char const *path);
struct userlist_list *userlist_free(struct userlist_list *p);
void userlist_unparse(struct userlist_list *p, FILE *f);

#endif /* __USERLIST_H__ */
