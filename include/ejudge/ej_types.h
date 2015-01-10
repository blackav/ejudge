/* -*- c -*- */
#ifndef __EJ_TYPES_H__
#define __EJ_TYPES_H__

/* Copyright (C) 2005-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/integral.h"

#include <stdio.h>

/* special types used to store/send data in binary format */
typedef rint32_t  ej_time_t;     /* time_t as stored in files */
typedef long long ej_time64_t;   /* time_t for new file formats */
typedef ruint32_t ej_size_t;     /* size_t as stored in files */
typedef ruint32_t ej_ip4_t;      /* IP address as stored in files */
typedef unsigned long long ej_cookie_t;   /* cookie */
typedef unsigned long long ej_tsc_t; /* timestamp counter type */

#define NULL_CLIENT_KEY (0ULL)

/** IPv6-ready IP address structure */
typedef struct ej_ip_t
{
  unsigned char ipv6_flag;
  unsigned char pad1[3];
  union
  {
    struct
    {
      unsigned char pad2[12];
      ruint32_t addr;
    } v4;
    struct
    {
      unsigned char addr[16];
    } v6;
  } u;
} ej_ip_t;

/* types for meta-info generator */
typedef unsigned char ejbytebool_t;
typedef int ejintbool_t;
typedef int ejintsize_t;
typedef char **ejstrlist_t;
typedef char **ejenvlist_t;

/* for CGI param parser */
typedef int ej_checkbox_t;
typedef int ej_int_opt_0_t;
typedef int ej_int_opt_1_t;
typedef int ej_int_opt_m1_t;
typedef unsigned char *ej_textbox_t;
typedef unsigned char *ej_textbox_opt_t;

/* privilege level */
enum priv_level
{
  PRIV_LEVEL_USER = 0,
  PRIV_LEVEL_JUDGE,
  PRIV_LEVEL_ADMIN,
};

#ifndef __USER_ROLE_DEFINED__
#define __USER_ROLE_DEFINED__
enum
{
  USER_ROLE_CONTESTANT,
  USER_ROLE_OBSERVER,
  USER_ROLE_EXAMINER,
  USER_ROLE_CHIEF_EXAMINER,
  USER_ROLE_COORDINATOR,
  USER_ROLE_JUDGE,
  USER_ROLE_ADMIN,

  USER_ROLE_LAST,
};
#endif

/* scoring systems */
enum scoring_system
{
  SCORE_ACM,
  SCORE_KIROV,
  SCORE_OLYMPIAD,
  SCORE_MOSCOW,

  SCORE_TOTAL,
};

enum user_flags
{
  USERLIST_UC_INVISIBLE    = 0x00000001,
  USERLIST_UC_BANNED       = 0x00000002,
  USERLIST_UC_LOCKED       = 0x00000004,
  USERLIST_UC_INCOMPLETE   = 0x00000008,
  USERLIST_UC_DISQUALIFIED = 0x00000010,

  USERLIST_UC_ALL          = 0x0000001f,
};

/* test visibility */
enum test_visibility
{
  TV_NORMAL = 0, // normal visibility, default value
  TV_FULL   = 1, // full visibility: show test, output, checker...
  TV_FULLIFMARKED = 2, // full for the marked runs, hidden elsewhere
  TV_BRIEF  = 3, // brief: only testing result
  TV_EXISTS = 4, // only existance of the test, score is counted
  TV_HIDDEN = 5, // completely hidden

  TV_LAST = 6
};

int test_visibility_parse(const unsigned char*);
int test_visibility_parse_mem(const unsigned char*, int len);
const unsigned char *test_visibility_unparse(int visibility);

/* test normalization modes */
enum
{
  TEST_NORM_FIRST = 0,
  TEST_NORM_NONE = TEST_NORM_FIRST,
  TEST_NORM_DEFAULT,
  TEST_NORM_NL,
  TEST_NORM_NLWS,
  TEST_NORM_NLWSNP,
  TEST_NORM_NLNP,
  TEST_NORM_LAST
};

int test_normalization_parse(const unsigned char *);
const unsigned char *test_normalization_unparse(int normalization);

/* valid end-of-line types for input files */
enum
{
  EOLN_UNDEFINED,
  EOLN_LF,
  EOLN_CRLF
};

const unsigned char *eoln_type_unparse_html(int value);

typedef struct Session
{
  unsigned long long session_id;
  unsigned long long client_key;
} Session;

const unsigned char *
session_unparse(
        unsigned char *buf,
        size_t size,
        const Session *ps);
const unsigned char *
session_unparse_2(
        unsigned char *buf,
        size_t size,
        unsigned long long session_id,
        unsigned long long client_key);
void
session_unparse_f(
        FILE *out_f,
        const Session *ps);
void
session_unparse_2_f(
        FILE *out_f,
        unsigned long long session_id,
        unsigned long long client_key);
int
session_parse(
        Session *ps,
        const unsigned char *str);

/* token bits */
enum
{
  TOKEN_FINALSCORE_BIT = 1, // show the final score
  TOKEN_TESTS_MASK = 6,
  TOKEN_BASICTESTS_BIT = 2, // show the basic test info
  TOKEN_TOKENTESTS_BIT = 4, // show the token test info
  TOKEN_FINALTESTS_BIT = 6, // show the final test info
  TOKEN_VALUER_JUDGE_COMMENT_BIT = 8 // show the judge's valuer comment
};

typedef struct ej_uuid_t
{
  ruint32_t v[4];
} ej_uuid_t;


#endif /* __EJ_TYPES_H__ */
