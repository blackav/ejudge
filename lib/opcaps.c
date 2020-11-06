/* -*- mode: c -*- */

/* Copyright (C) 2003-2020 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/opcaps.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

#if defined __GNUC__ && defined __MINGW32__
#include <malloc.h>
#endif

const unsigned char * const opcaps_cap_list [] =
{
  [OPCAP_MASTER_LOGIN]            = "MASTER_LOGIN",
  [OPCAP_JUDGE_LOGIN]             = "JUDGE_LOGIN",
  [OPCAP_SUBMIT_RUN]              = "SUBMIT_RUN",
  [OPCAP_MAP_CONTEST]             = "MAP_CONTEST",
  [OPCAP_LIST_USERS]              = "LIST_USERS",
  [OPCAP_CREATE_USER]             = "CREATE_USER",
  [OPCAP_GET_USER]                = "GET_USER",
  [OPCAP_EDIT_USER]               = "EDIT_USER",
  [OPCAP_DELETE_USER]             = "DELETE_USER",
  [OPCAP_PRIV_EDIT_USER]          = "PRIV_EDIT_USER",
  [OPCAP_PRIV_DELETE_USER]        = "PRIV_DELETE_USER",
  [OPCAP_CREATE_REG]              = "CREATE_REG",
  [OPCAP_EDIT_REG]                = "EDIT_REG",
  [OPCAP_DELETE_REG]              = "DELETE_REG",
  [OPCAP_PRIV_CREATE_REG]         = "PRIV_CREATE_REG",
  [OPCAP_PRIV_DELETE_REG]         = "PRIV_DELETE_REG",
  [OPCAP_DUMP_USERS]              = "DUMP_USERS",
  [OPCAP_DUMP_RUNS]               = "DUMP_RUNS",
  [OPCAP_DUMP_STANDINGS]          = "DUMP_STANDINGS",
  [OPCAP_VIEW_STANDINGS]          = "VIEW_STANDINGS",
  [OPCAP_VIEW_SOURCE]             = "VIEW_SOURCE",
  [OPCAP_VIEW_REPORT]             = "VIEW_REPORT",
  [OPCAP_VIEW_CLAR]               = "VIEW_CLAR",
  [OPCAP_EDIT_RUN]                = "EDIT_RUN",
  [OPCAP_REJUDGE_RUN]             = "REJUDGE_RUN",
  [OPCAP_NEW_MESSAGE]             = "NEW_MESSAGE",
  [OPCAP_REPLY_MESSAGE]           = "REPLY_MESSAGE",
  [OPCAP_CONTROL_CONTEST]         = "CONTROL_CONTEST",
  [OPCAP_IMPORT_XML_RUNS]         = "IMPORT_XML_RUNS",
  [OPCAP_PRINT_RUN]               = "PRINT_RUN",
  [OPCAP_EDIT_CONTEST]            = "EDIT_CONTEST",
  [OPCAP_PRIV_EDIT_REG]           = "PRIV_EDIT_REG",
  [OPCAP_EDIT_PASSWD]             = "EDIT_PASSWD",
  [OPCAP_PRIV_EDIT_PASSWD]        = "PRIV_EDIT_PASSWD",
  [OPCAP_RESTART]                 = "RESTART",
  [OPCAP_COMMENT_RUN]             = "COMMENT_RUN",
  [OPCAP_UNLOAD_CONTEST]          = "UNLOAD_CONTEST",
  [OPCAP_LOCAL_0]                 = "LOCAL_0",
  [OPCAP_LOCAL_1]                 = "LOCAL_1",
  [OPCAP_LOCAL_2]                 = "LOCAL_2",
  [OPCAP_LOCAL_3]                 = "LOCAL_3",

  [OPCAP_LAST]                    = 0
};

const opcap_t OPCAP_NO_PERMS = 0LL;
const opcap_t OPCAP_OBSERVER_PERMS =
  (1ULL << OPCAP_JUDGE_LOGIN)
  | (1ULL << OPCAP_LIST_USERS)
  | (1ULL << OPCAP_GET_USER)
  | (1ULL << OPCAP_DUMP_RUNS)
  | (1ULL << OPCAP_DUMP_STANDINGS)
  | (1ULL << OPCAP_VIEW_STANDINGS)
  | (1ULL << OPCAP_VIEW_SOURCE)
  | (1ULL << OPCAP_VIEW_REPORT)
  | (1ULL << OPCAP_VIEW_CLAR);
const opcap_t OPCAP_JUDGE_PERMS =
  (1ULL << OPCAP_JUDGE_LOGIN)
  | (1ULL << OPCAP_SUBMIT_RUN)
  | (1ULL << OPCAP_LIST_USERS)
  | (1ULL << OPCAP_GET_USER)
  | (1ULL << OPCAP_EDIT_USER)
  | (1ULL << OPCAP_DUMP_USERS)
  | (1ULL << OPCAP_DUMP_RUNS)
  | (1ULL << OPCAP_DUMP_STANDINGS)
  | (1ULL << OPCAP_VIEW_STANDINGS)
  | (1ULL << OPCAP_VIEW_SOURCE)
  | (1ULL << OPCAP_VIEW_REPORT)
  | (1ULL << OPCAP_VIEW_CLAR)
  | (1ULL << OPCAP_NEW_MESSAGE)
  | (1ULL << OPCAP_REPLY_MESSAGE)
  | (1ULL << OPCAP_PRINT_RUN)
  | (1ULL << OPCAP_COMMENT_RUN);
const opcap_t OPCAP_MASTER_PERMS =
  (1ULL << OPCAP_MASTER_LOGIN)
  | (1ULL << OPCAP_JUDGE_LOGIN)
  | (1ULL << OPCAP_SUBMIT_RUN)
  | (1ULL << OPCAP_MAP_CONTEST)
  | (1ULL << OPCAP_LIST_USERS)
  | (1ULL << OPCAP_PRIV_EDIT_REG)
  | (1ULL << OPCAP_CREATE_USER)
  | (1ULL << OPCAP_GET_USER)
  | (1ULL << OPCAP_EDIT_USER)
  | (1ULL << OPCAP_DELETE_USER)
  | (1ULL << OPCAP_PRIV_EDIT_USER)
  | (1ULL << OPCAP_PRIV_DELETE_USER)
  | (1ULL << OPCAP_EDIT_CONTEST)
  | (1ULL << OPCAP_CREATE_REG)
  | (1ULL << OPCAP_EDIT_REG)
  | (1ULL << OPCAP_DELETE_REG)
  | (1ULL << OPCAP_PRIV_CREATE_REG)
  | (1ULL << OPCAP_PRIV_DELETE_REG)
  | (1ULL << OPCAP_DUMP_USERS)
  | (1ULL << OPCAP_DUMP_RUNS)
  | (1ULL << OPCAP_DUMP_STANDINGS)
  | (1ULL << OPCAP_VIEW_STANDINGS)
  | (1ULL << OPCAP_VIEW_SOURCE)
  | (1ULL << OPCAP_VIEW_REPORT)
  | (1ULL << OPCAP_VIEW_CLAR)
  | (1ULL << OPCAP_EDIT_RUN)
  | (1ULL << OPCAP_REJUDGE_RUN)
  | (1ULL << OPCAP_NEW_MESSAGE)
  | (1ULL << OPCAP_REPLY_MESSAGE)
  | (1ULL << OPCAP_CONTROL_CONTEST)
  | (1ULL << OPCAP_IMPORT_XML_RUNS)
  | (1ULL << OPCAP_PRINT_RUN)
  | (1ULL << OPCAP_EDIT_PASSWD)
  | (1ULL << OPCAP_PRIV_EDIT_PASSWD)
  | (1ULL << OPCAP_RESTART)
  | (1ULL << OPCAP_COMMENT_RUN);
const opcap_t OPCAP_FULL_PERMS = (1ULL << OPCAP_LAST) - 1;

int
opcaps_find(const opcaplist_t *list,
            unsigned char const *login,
            opcap_t *pcap)
{
  const struct opcap_list_item *p;

  ASSERT(list);
  ASSERT(login);
  for (p = list->first; p; p = (const struct opcap_list_item*) p->b.right) {
    if (!strcmp(p->login, login)) {
      if (pcap) *pcap = p->caps;
      return 0;
    }
  }
  if (pcap) *pcap = 0LL;
  return -1;
}

int
opcaps_find_by_uid(const opcaplist_t *list,
                   int uid, opcap_t *pcap)
{
  const struct opcap_list_item *p;

  ASSERT(list);
  for (p = list->first; p; p = (const struct opcap_list_item*) p->b.right) {
    if (p->uid == uid) {
      if (pcap) *pcap = p->caps;
      return 0;
    }
  }
  if (pcap) *pcap = 0LL;
  return -1;
}

int
opcaps_parse(unsigned char const *str, opcap_t *pcap)
{
  opcap_t lcap = 0;
  int len, bit;
  unsigned char const *p;
  unsigned char *str2, *q, *e, *str3;
  char *tmpe = 0;

  if (pcap) *pcap = 0;
  ASSERT(str);
  len = strlen(str);

  // copy the string to internal buffer, removing whitespaces
  str2 = (unsigned char *) alloca(len + 10);
  memset(str2, 0, len + 10);
  for (p = str, q = str2; *p; p++) {
    if (*p <= ' ') continue;
    // invalid characters
    if (*p >= 127) return -1;
    *q++ = toupper(*p);
  }

  if (str2[0] >= '0' && str2[0] <= '9') {
    // a number
    errno = 0;
    lcap = strtoull(str2, &tmpe, 0);
    e = tmpe;
    if (*e || errno == ERANGE) return -1;
    // FIXME: this works, only if OPCAP_LAST < 64
    if (lcap >= (1ULL << OPCAP_LAST)) return -1;
  } else {
    // list of capabilities
    len = strlen(str2);
    str3 = (unsigned char *) alloca(len + 10);
    q = str2;
    while (*q) {
      for (e = q; *e && *e != ','; e++) {}
      memset(str3, 0, len + 10);
      memcpy(str3, q, e - q);

      if (!strcmp("FULL_SET", str3)) {
        lcap |= OPCAP_FULL_PERMS;
      } else if (!strcmp("OBSERVER_SET", str3)) {
        lcap |= OPCAP_OBSERVER_PERMS;
      } else if (!strcmp("JUDGE_SET", str3)) {
        lcap |= OPCAP_JUDGE_PERMS;
      } else if (!strcmp("MASTER_SET", str3)) {
        lcap |= OPCAP_MASTER_PERMS;
      } else if (!strcmp("GENERATE_TEAM_PASSWORDS", str3)) {
        // just ignore this bit
      } else {
        if (!strcmp("LIST_CONTEST_USERS", str3)
            || !strcmp("LIST_ALL_USERS", str3)) {
          bit = OPCAP_LIST_USERS;
        } else {
          for (bit = 0; opcaps_cap_list[bit]; bit++)
            if (!strcmp(opcaps_cap_list[bit], str3)) break;
          if (!opcaps_cap_list[bit]) return -1;
        }
        ASSERT(bit < OPCAP_LAST);
        lcap |= 1ULL << bit;
      }

      q = e;
      while (*q == ',') q++;
    }
  }

  if (pcap) *pcap = lcap;
  return 0;
}

const unsigned char *
opcaps_get_name(int cap)
{
  if (cap < 0 || cap >= OPCAP_LAST) return 0;
  return opcaps_cap_list[cap];
}


int
opcaps_is_predef_caps(opcap_t cap)
{
  if (cap == OPCAP_NO_PERMS) return OPCAP_PREDEF_NO_PERMS;
  if (cap == OPCAP_OBSERVER_PERMS) return OPCAP_PREDEF_OBSERVER;
  if (cap == OPCAP_JUDGE_PERMS) return OPCAP_PREDEF_JUDGE;
  if (cap == OPCAP_MASTER_PERMS) return OPCAP_PREDEF_MASTER;
  if (cap == OPCAP_FULL_PERMS) return OPCAP_PREDEF_FULL;
  return 0;
}

opcap_t
opcaps_get_predef_caps(int id)
{
  ASSERT(id > 0 && id < OPCAP_PREDEF_LAST);
  switch (id) {
  case OPCAP_PREDEF_NO_PERMS: return OPCAP_NO_PERMS;
  case OPCAP_PREDEF_OBSERVER: return OPCAP_OBSERVER_PERMS;
  case OPCAP_PREDEF_JUDGE:    return OPCAP_JUDGE_PERMS;
  case OPCAP_PREDEF_MASTER:   return OPCAP_MASTER_PERMS;
  case OPCAP_PREDEF_FULL:     return OPCAP_FULL_PERMS;
  default:
    abort();
  }
  return 0;
}
