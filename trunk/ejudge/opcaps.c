/* -*- mode: c -*- */
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
  [OPCAP_SUBMIT_RUN]              "SUBMIT_RUN",
  [OPCAP_MAP_CONTEST]             "MAP_CONTEST",
  //[OPCAP_LIST_CONTEST_USERS]      "LIST_CONTEST_USERS",
  //[OPCAP_LIST_ALL_USERS]          "LIST_ALL_USERS",
  [OPCAP_LIST_USERS]              "LIST_USERS",
  [OPCAP_CREATE_USER]             "CREATE_USER",
  [OPCAP_GET_USER]                "GET_USER",
  [OPCAP_EDIT_USER]               "EDIT_USER",
  [OPCAP_DELETE_USER]             "DELETE_USER",
  [OPCAP_PRIV_EDIT_USER]          "PRIV_EDIT_USER",
  [OPCAP_PRIV_DELETE_USER]        "PRIV_DELETE_USER",
  //  [OPCAP_GENERATE_TEAM_PASSWORDS] "GENERATE_TEAM_PASSWORDS",
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
  [OPCAP_IMPORT_XML_RUNS]         "IMPORT_XML_RUNS",
  [OPCAP_PRINT_RUN]               "PRINT_RUN",
  [OPCAP_EDIT_CONTEST]            "EDIT_CONTEST",
  [OPCAP_PRIV_EDIT_REG]           "PRIV_EDIT_REG",
  [OPCAP_EDIT_PASSWD]             "EDIT_PASSWD",
  [OPCAP_PRIV_EDIT_PASSWD]        "PRIV_EDIT_PASSWD",

  [OPCAP_LAST]                    0
};

static const unsigned char is_contest_cap[] =
{
  [OPCAP_MASTER_LOGIN] = 1,
  [OPCAP_JUDGE_LOGIN] = 1,
  [OPCAP_SUBMIT_RUN] = 1,
  [OPCAP_MAP_CONTEST] = 1,
  //[OPCAP_LIST_CONTEST_USERS] = 1,
  //[OPCAP_LIST_ALL_USERS] = 0,
  [OPCAP_LIST_USERS] = 1,
  [OPCAP_CREATE_USER] = 0,
  [OPCAP_GET_USER] = 1,
  [OPCAP_EDIT_USER] = 1,
  [OPCAP_DELETE_USER] = 0,
  [OPCAP_PRIV_EDIT_USER] = 1,
  [OPCAP_PRIV_DELETE_USER] = 0,
  //  [OPCAP_GENERATE_TEAM_PASSWORDS] = 1,
  [OPCAP_CREATE_REG] = 1,
  [OPCAP_EDIT_REG] = 1,
  [OPCAP_DELETE_REG] = 1,
  [OPCAP_PRIV_CREATE_REG] = 1,
  [OPCAP_PRIV_DELETE_REG] = 1,
  [OPCAP_DUMP_USERS] = 1,
  [OPCAP_DUMP_RUNS] = 1,
  [OPCAP_DUMP_STANDINGS] = 1,
  [OPCAP_VIEW_STANDINGS] = 1,
  [OPCAP_VIEW_SOURCE] = 1,
  [OPCAP_VIEW_REPORT] = 1,
  [OPCAP_VIEW_CLAR] = 1,
  [OPCAP_EDIT_RUN] = 1,
  [OPCAP_REJUDGE_RUN] = 1,
  [OPCAP_NEW_MESSAGE] = 1,
  [OPCAP_REPLY_MESSAGE] = 1,
  [OPCAP_CONTROL_CONTEST] = 1,
  [OPCAP_IMPORT_XML_RUNS] = 1,
  [OPCAP_PRINT_RUN] = 1,
  [OPCAP_EDIT_CONTEST] = 1,
  [OPCAP_PRIV_EDIT_REG] = 1,
  [OPCAP_EDIT_PASSWD] = 1,
  [OPCAP_PRIV_EDIT_PASSWD] = 1,
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
/*
int
opcaps_check(opcap_t cap, int bit)
{
  if ((cap & (1ULL << bit))) return 0;
  return -1;
}
*/

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

      // backward compatibility
      if (!strcmp("GENERATE_TEAM_PASSWORDS", str3)) {
        // just ignore this bit
      } else {
        if (!strcmp("LIST_CONTEST_USERS", str3)
            || !strcmp("LIST_ALL_USERS", str3)) {
          bit = OPCAP_LIST_USERS;
        } else {
          for (bit = 0; cap_list[bit]; bit++)
            if (!strcmp(cap_list[bit], str3)) break;
          if (!cap_list[bit]) return -1;
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

unsigned char *
opcaps_unparse(int left_margin, int max_width, opcap_t cap)
{
  char *out_str = 0;
  size_t out_len = 0;
  int first_flag = 1;
  int cur_pos = 0, i, j;
  FILE *f;

  f = open_memstream(&out_str, &out_len);
  for (i = 0; i < OPCAP_LAST; i++) {
    if (!(cap & (1ULL << i))) continue;
    if (first_flag) {
      first_flag = 0;
      for (j = 0; j < left_margin; j++) putc(' ', f);
      cur_pos = left_margin;
    }
    fprintf(f, "%s,", cap_list[i]);
    cur_pos += strlen(cap_list[i]) + 1;
    if (cur_pos >= max_width) {
      fprintf(f, "\n");
      first_flag = 1;
    }
  }
  if (!first_flag) fprintf(f, "\n");
  fclose(f);
  return out_str;
}

int
opcaps_is_contest_cap(int cap)
{
  if (cap < 0 || cap >= OPCAP_LAST) return 0;
  return is_contest_cap[cap];
}

const unsigned char *
opcaps_get_name(int cap)
{
  if (cap < 0 || cap >= OPCAP_LAST) return 0;
  return cap_list[cap];
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
