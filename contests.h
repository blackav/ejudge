/* -*- c -*- */
/* $Id$ */

#ifndef __CONTESTS_H__
#define __CONTESTS_H__

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

enum
  {
    CONTEST_CONTESTS = 1,
    CONTEST_CONTEST,
    CONTEST_ACCESS,
    CONTEST_IP,
    CONTEST_FIELD,
    CONTEST_NAME,
    CONTEST_CONTESTANTS,
    CONTEST_RESERVES,
    CONTEST_COACHES,
    CONTEST_ADVISORS,
    CONTEST_GUESTS,
    CONTEST_HEADER_FILE,
    CONTEST_FOOTER_FILE,
    CONTEST_REGISTER_EMAIL,
    CONTEST_REGISTER_URL,
    CONTEST_TEAM_URL,
    CONTEST_REGISTRATION_DEADLINE,

    CONTEST_LAST_TAG
  };
enum
  {
    CONTEST_A_ID = 1,
    CONTEST_A_DEFAULT,
    CONTEST_A_ALLOW,
    CONTEST_A_DENY,
    CONTEST_A_MANDATORY,
    CONTEST_A_OPTIONAL,
    CONTEST_A_MIN,
    CONTEST_A_MAX,
    CONTEST_A_AUTOREGISTER,
    CONTEST_A_INITIAL,

    CONTEST_LAST_ATTN
  };
enum
  {
    CONTEST_FIRST_FIELD = 1,
    CONTEST_F_HOMEPAGE = CONTEST_FIRST_FIELD,
    CONTEST_F_INST,
    CONTEST_F_INSTSHORT,
    CONTEST_F_FAC,
    CONTEST_F_FACSHORT,
    CONTEST_F_CITY,
    CONTEST_F_COUNTRY,

    CONTEST_LAST_FIELD
  };
enum
  {
    CONTEST_M_CONTESTANT,
    CONTEST_M_RESERVE,
    CONTEST_M_COACH,
    CONTEST_M_ADVISOR,
    CONTEST_M_GUEST,
    CONTEST_LAST_MEMBER
  };
enum
  {
    CONTEST_MF_SERIAL = 0,
    CONTEST_MF_FIRSTNAME = 1,
    CONTEST_MF_MIDDLENAME,
    CONTEST_MF_SURNAME,
    CONTEST_MF_STATUS,
    CONTEST_MF_GRADE,
    CONTEST_MF_GROUP,
    CONTEST_MF_EMAIL,
    CONTEST_MF_HOMEPAGE,
    CONTEST_MF_INST,
    CONTEST_MF_INSTSHORT,
    CONTEST_MF_FAC,
    CONTEST_MF_FACSHORT,
    CONTEST_MF_OCCUPATION,
    CONTEST_LAST_MEMBER_FIELD
  };

struct contest_field
{
  struct xml_tree b;
  int mandatory;
  int id;
};

struct contest_ip
{
  struct xml_tree b;
  int allow;
  unsigned int addr;
  unsigned int mask;
};

struct contest_access
{
  struct xml_tree b;
  int default_is_allow;
};

struct contest_member
{
  struct xml_tree b;
  int min_count;
  int max_count;
  int init_count;
  struct contest_field *fields[CONTEST_LAST_MEMBER_FIELD];
};

struct contest_desc
{
  struct xml_tree b;
  int id;
  int autoregister;
  unsigned long  reg_deadline;
  unsigned char *name;
  unsigned char *header_file;
  unsigned char *footer_file;
  unsigned char *register_email;
  unsigned char *register_url;
  unsigned char *team_url;
  struct contest_access *access;
  struct contest_field *fields[CONTEST_LAST_FIELD];
  struct contest_member *members[CONTEST_LAST_MEMBER];
};

struct contest_list
{
  struct xml_tree b;

  int id_map_size;
  struct contest_desc **id_map;
};

struct contest_list *parse_contest_xml(char const *path);
int contests_check_ip(struct contest_desc *d, unsigned long ip);

#endif /* __CONTESTS_H__ */
