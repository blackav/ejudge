/* -*- c -*- */
#ifndef __RUN_PACKET_PRIV_H__
#define __RUN_PACKET_PRIV_H__

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

/* various private data structures and constants for run packets */

enum
{
  FLAGS_ACCEPTING_MODE       = 0x010,
  FLAGS_ACCEPT_PARTIAL       = 0x020,
  FLAGS_DISABLE_SOUND        = 0x040,
  FLAGS_FULL_ARCHIVE         = 0x080,
  FLAGS_MEMORY_LIMIT         = 0x100,
  FLAGS_SECURE_RUN           = 0x200,
  FLAGS_SECURITY_VIOLATION   = 0x400,
  FLAGS_NOTIFY               = 0x800,
  FLAGS_MARKED               = 0x1000,
  FLAGS_ADVANCED_LAYOUT      = 0x2000,
  FLAGS_SEPARATE_USER_SCORE  = 0x4000,
  FLAGS_HAS_USER_SCORE       = 0x8000,
  FLAGS_DISABLE_STDERR       = 0x10000,

  FLAGS_ALL_MASK             = 0x1ffff, /* scoring system incl. */
};

/* run->serve binary packet structure */
/* little-endian byte ordering is assumed */
struct run_reply_bin_packet
{
  ruint32_t packet_len;
  rint32_t  version;
  rint32_t  judge_id;
  rint32_t  contest_id;
  rint32_t  run_id;
  rint32_t  status;
  rint32_t  failed_test;
  rint32_t  tests_passed;
  rint32_t  score;
  rint32_t  user_status;
  rint32_t  user_tests_passed;
  rint32_t  user_score;
  ruint32_t flags;
  rint32_t  ts1;
  rint32_t  ts1_us;
  rint32_t  ts2;
  rint32_t  ts2_us;
  rint32_t  ts3;
  rint32_t  ts3_us;
  rint32_t  ts4;
  rint32_t  ts4_us;
  rint32_t  ts5;
  rint32_t  ts5_us;
  rint32_t  ts6;
  rint32_t  ts6_us;
  rint32_t  ts7;
  rint32_t  ts7_us;
  ej_uuid_t uuid;
  unsigned char pad[8];        /* padding to 128 bytes */
};

#endif /* __RUN_PACKET_PRIV_H__ */
