/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003 Alexander Chernov <cher@ispras.ru> */

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

#include "opcaps.h"

#include <reuse/logger.h>
#include <reuse/osdeps.h>
#include <reuse/xalloc.h>

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

static const unsigned char * const cap_list [] =
{
  [OPCAP_MASTER_LOGIN]            "MASTER_LOGIN",
  [OPCAP_JUDGE_LOGIN]             "JUDGE_LOGIN",
  [OPCAP_OBSERVER_LOGIN]          "OBSERVER_LOGIN",
  [OPCAP_MAP_CONTEST]             "MAP_CONTEST",
  [OPCAP_LIST_CONTEST_USERS]      "LIST_CONTEST_USERS",
  [OPCAP_LIST_ALL_USERS]          "LIST_ALL_USERS",
  [OPCAP_CREATE_USER]             "CREATE_USER",
  [OPCAP_GET_USER]                "GET_USER",
  [OPCAP_EDIT_USER]               "EDIT_USER",
  [OPCAP_DELETE_USER]             "DELETE_USER",
  [OPCAP_PRIV_EDIT_USER]          "PRIV_EDIT_USER",
  [OPCAP_PRIV_DELETE_USER]        "PRIV_DELETE_USER",
  [OPCAP_GENERATE_TEAM_PASSWORDS] "GENERATE_TEAM_PASSWORDS",
  [OPCAP_CREATE_REG]              "CREATE_REG",
  [OPCAP_EDIT_REG]                "EDIT_REG",
  [OPCAP_DELETE_REG]              "DELETE_REG",
  [OPCAP_PRIV_CREATE_REG]         "PRIV_CREATE_REG",
  [OPCAP_PRIV_DELETE_REG]         "PRIV_DELETE_REG",
  [OPCAP_DUMP_USERS]              "DUMP_USERS",
  [OPCAP_DUMP_RUNS]               "DUMP_RUNS",
  [OPCAP_DUMP_STANDINGS]          "DUMP_STANDINGS",
  [OPCAP_VIEW_STANDINGS]          "VIEW_STANDINGS",
  [OPCAP_VIEW_SOURCE]             "VIEW_SOURCE",
  [OPCAP_VIEW_REPORT]             "VIEW_REPORT",
  [OPCAP_VIEW_CLAR]               "VIEW_CLAR",
  [OPCAP_EDIT_RUN]                "EDIT_RUN",
  [OPCAP_REJUDGE_RUN]             "REJUDGE_RUN",
  [OPCAP_NEW_MESSAGE]             "NEW_MESSAGE",
  [OPCAP_REPLY_MESSAGE]           "REPLY_MESSAGE",
  [OPCAP_CONTROL_CONTEST]         "CONTROL_CONTEST",

  [OPCAP_LAST]                    0
};

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

/* FIXME: this probably must be inlined... */
int
opcaps_check(opcap_t cap, int bit)
{
  if ((cap & (1ULL << bit))) return 0;
  return -1;
}

int
opcaps_parse(unsigned char const *str, opcap_t *pcap)
{
  opcap_t lcap = 0;
  int len, bit;
  unsigned char const *p;
  unsigned char *str2, *q, *e, *str3;

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
    lcap = strtoull(str2, (char**) &e, 0);
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

      for (bit = 0; cap_list[bit]; bit++)
        if (!strcmp(cap_list[bit], str3)) break;
      if (!cap_list[bit]) return -1;
      ASSERT(bit < OPCAP_LAST);
      lcap |= 1ULL << bit;

      q = e;
      while (*q == ',') q++;
    }
  }

  if (pcap) *pcap = lcap;
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
