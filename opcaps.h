#ifndef __OPCAPS_H__
#define __OPCAPS_H__

/* $Id$ */

/* Copyright (C) 2003-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "expat_iface.h"

/* operation capabilities bits */
enum
{
  OPCAP_MASTER_LOGIN = 0,
  OPCAP_JUDGE_LOGIN = 1,
  OPCAP_SUBMIT_RUN = 2,
  OPCAP_MAP_CONTEST = 3,
  //OPCAP_LIST_CONTEST_USERS = 4,
  //OPCAP_LIST_ALL_USERS = 5,
  OPCAP_LIST_USERS = 4,
  OPCAP_PRIV_EDIT_REG = 5,
  OPCAP_CREATE_USER = 6,
  OPCAP_GET_USER = 7,
  OPCAP_EDIT_USER = 8,
  OPCAP_DELETE_USER = 9,
  OPCAP_PRIV_EDIT_USER = 10,
  OPCAP_PRIV_DELETE_USER = 11,
  //OPCAP_GENERATE_TEAM_PASSWORDS = 12,
  OPCAP_EDIT_CONTEST = 12,
  OPCAP_CREATE_REG = 13,
  OPCAP_EDIT_REG = 14,
  OPCAP_DELETE_REG = 15,
  OPCAP_PRIV_CREATE_REG = 16,
  OPCAP_PRIV_DELETE_REG = 17,
  OPCAP_DUMP_USERS = 18,
  OPCAP_DUMP_RUNS = 19,
  OPCAP_DUMP_STANDINGS = 20,
  OPCAP_VIEW_STANDINGS = 21,
  OPCAP_VIEW_SOURCE = 22,
  OPCAP_VIEW_REPORT = 23,
  OPCAP_VIEW_CLAR = 24,
  OPCAP_EDIT_RUN = 25,
  OPCAP_REJUDGE_RUN = 26,
  OPCAP_NEW_MESSAGE = 27,
  OPCAP_REPLY_MESSAGE = 28,
  OPCAP_CONTROL_CONTEST = 29,
  OPCAP_IMPORT_XML_RUNS = 30,
  OPCAP_PRINT_RUN = 31,
  OPCAP_EDIT_PASSWD = 32,
  OPCAP_PRIV_EDIT_PASSWD = 33,

  OPCAP_LAST
};

typedef unsigned long long opcap_t;

struct opcap_list_item
{
  struct xml_tree b;
  unsigned char *login;
  int uid;
  opcap_t caps;
};

typedef struct _opcaplist
{
  struct opcap_list_item *first;
} opcaplist_t;

int opcaps_find(const opcaplist_t *list,
                unsigned char const *login,
                opcap_t *pcap);

int opcaps_find_by_uid(const opcaplist_t *list,
                       int uid,
                       opcap_t *pcap);

static inline int opcaps_check(opcap_t cap, int bit);
static inline int
opcaps_check(opcap_t cap, int bit)
{
  if ((cap & (1ULL << bit))) return 0;
  return -1;
}

int opcaps_parse(unsigned char const *str, opcap_t *pcap);

unsigned char *opcaps_unparse(int left_margin, int max_width, opcap_t cap);

int opcaps_is_contest_cap(int cap);
const unsigned char *opcaps_get_name(int cap);

#endif /* __OPCAPS_H__ */
