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

enum
  {
    PWD_PLAIN,
    PWD_BASE64,
    PWD_SHA1
  };

enum
  {
    TAG_USERLIST = 1,
    TAG_USER,
    TAG_LOGIN,
    TAG_DESCR,
    TAG_INST,
    TAG_INSTSHORT,
    TAG_FAC,
    TAG_FACSHORT,
    TAG_MEMBER,
    TAG_RESERVE,
    TAG_COACH,
    TAG_ADVISOR,
    TAG_NAME,
    TAG_MIDDLENAME,
    TAG_SURNAME,
    TAG_COURSE,
    TAG_GROUP,
    TAG_OCCUP,
    TAG_EMAIL,
    TAG_PHONE,
    TAG_HOMEPAGE,
    TAG_PASSWORD,
    TAG_COUNTRY,
    TAG_ZIP,
    TAG_CITY,
    TAG_ADDRESS,
  };

struct addr_data;
struct addr_list;
struct addr_info;
struct person_data;
struct person_list;
struct user_data;
struct userlist_data;

struct addr_data
{
  struct addr_data *next;
  unsigned char *addr;
};
struct addr_list
{
  struct addr_data *first;
  struct addr_data *last;
};
struct addr_info
{
  struct addr_list phone_list;
  struct addr_list email_list;
  struct addr_list homepage_list;
};

struct person_data
{
  struct person_data *next;
  struct user_data *parent;

  unsigned char *name;
  unsigned char *middlename;
  unsigned char *surname;
  unsigned char *course;
  unsigned char *group;
  unsigned char *occup;

  struct addr_info addr;
};
struct person_list
{
  struct person_data *first;
  struct person_data *last;
};

struct user_data
{
  struct user_data *next;
  struct userlist_data *parent;

  int id;
  int invisible;
  int banned;
  unsigned char *login;
  unsigned char *descr;
  unsigned char *inst;
  unsigned char *instshort;
  unsigned char *fac;
  unsigned char *facshort;

  int passwd_method;
  unsigned char *passwd;

  struct person_list member_list;
  struct person_list reserve_list;
  struct person_list coach_list;
  struct person_list advisor_list;

  struct addr_info addr;

  unsigned char *country;
  unsigned char *zip;
  unsigned char *city;
  unsigned char *address;
};
struct userlist_data
{
  struct userlist_data *next;

  char *name;
  struct user_data *first;
  struct user_data *last;
};

unsigned char * user_data_get_field(struct user_data const *, int);
void user_data_set_field(struct user_data *, int, unsigned char const *);
unsigned char **person_data_get_ptr(struct person_data const *, int);
struct person_list *user_data_get_list_ptr(struct user_data const *, int);
struct addr_list *addr_get_list(struct addr_info const *, int);




#endif /* __USERLIST_H__ */
