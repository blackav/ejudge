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
    CONTEST_A_SIZE,
    CONTEST_A_MAXLENGTH,

    CONTEST_LAST_ATTN
  };
enum
  {
    CONTEST_F_LOGIN = 1,
    CONTEST_F_EMAIL,
    CONTEST_F_NAME,
    CONTEST_F_HOMEPAGE,

    CONTEST_LAST_FIELD
  };

struct contest_field
{
  struct xml_tree b;
  int mandatory;
  int id;
  int size;
  int maxlength;
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

struct contest_desc
{
  struct xml_tree b;
  int id;
  unsigned char *name;
  struct contest_access *access;
};

struct contest_list
{
  struct xml_tree b;

  int id_map_size;
  struct contest_desc **id_map;
};

struct contest_list *parse_contest_xml(char const *path);

#endif /* __CONTESTS_H__ */
