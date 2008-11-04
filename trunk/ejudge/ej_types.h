/* -*- c -*- */
/* $Id$ */
#ifndef __EJ_TYPES_H__
#define __EJ_TYPES_H__

/* Copyright (C) 2005-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include <reuse/integral.h>

/* special types used to store/send data in binary format */
typedef rint32_t  ej_time_t;     /* time_t as stored in files */
typedef long long ej_time64_t;   /* time_t for new file formats */
typedef ruint32_t ej_size_t;     /* size_t as stored in files */
typedef ruint32_t ej_ip_t;       /* IP address as stored in files */
typedef unsigned long long ej_cookie_t;   /* cookie */
typedef unsigned long long ej_tsc_t; /* timestamp counter type */

typedef unsigned char ejbytebool_t;
typedef int ejintbool_t;

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

#endif /* __EJ_TYPES_H__ */
