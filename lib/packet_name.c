/* -*- c -*- */

/* Copyright (C) 2014-2022 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"

#include "ejudge/packet_name.h"

#include "ejudge/logger.h"

#include <string.h>
#include <sys/time.h>
#include <stdint.h>

static const unsigned char b32_digits[]=
"0123456789ABCDEFGHIJKLMNOPQRSTUV";

unsigned char *
b32_number_2(unsigned char *dst, unsigned int num, int digits)
{
  unsigned char *end = dst + digits;
  dst += digits - 1;
  for (; digits; --digits) {
    *dst-- = b32_digits[num & 0x1f];
    num >>= 5;
  }
  return end;
}

unsigned char *
b32_number_3(unsigned char *dst, unsigned int num)
{
  int digits = 0;
  if (num < 32) { // 2^5
    digits = 1;
  } else if (num < 1024) { // 2^10
    digits = 2;
  } else if (num < 32768) { // 2^15
    digits = 3;
  } else if (num < 1048576) { // 2^20
    digits = 4;
  } else if (num < 33554432) { // 2^25
    digits = 5;
  } else if (num < 1073741824) { // 2^30
    digits = 6;
  } else {
    digits = 7;
  }
  *dst++ = b32_digits[digits];
  return b32_number_2(dst, num, digits);
}

static unsigned char *
b32_ull(unsigned char *dst, const void *pv, int shift)
{
  uint64_t value = *(const uint64_t*) pv;
  for (; shift >= 0; shift -= 5) {
    *dst++ = b32_digits[(value >> shift) & 0x1f];
  }
  return dst;
}

void
serve_packet_name(
        int contest_id,
        int run_id,
        int prio,
        const ej_uuid_t *judge_uuid,
        unsigned char buf[],
        int size) // ignored yet
{
    //unsigned long long num = 0;
  struct timeval ts;

  // generate "random" number, that would include the
  // pid of "serve", the current time (with microseconds)
  // and some small random component.
  // pid is 2 byte (15 bit)
  // run_id is 2 byte
  // time_t component - 4 byte
  // nanosec component - 4 byte

  // EJ_SERVE_PACKET_NAME_SIZE == 13
  // total packet name bits: 60 (12 * 5)

  //OLD:
  // 6666555555555544444444443333333333222222222211111111110000000000
  // 3210987654321098765432109876543210987654321098765432109876543210
  //     ==P==
  //          =====run_id====
  //                         ======pid======
  //                                        ===========time==========

  /*
  num = (getpid() & 0x7fffLLU) << 25LLU;
  num |= (run_id & 0x7fffLLU) << 40LLU;
  gettimeofday(&ts, 0);
  num |= (ts.tv_sec ^ ts.tv_usec) & 0x1ffffff;
  b32_number(num, buf);
  prio += 16;
  if (prio < 0) prio = 0;
  if (prio > 31) prio = 31;
  buf[0] = b32_digits[prio];
  */

  //NEW:
  // 6666555555555544444444443333333333222222222211111111110000000000
  // 3210987654321098765432109876543210987654321098765432109876543210
  //     ==P==
  //          =====run_id=========
  //                              =======time=========
  //                                                  ======usec=====

  prio += 16;
  if (prio < 0) prio = 0;
  if (prio > 31) prio = 31;
  gettimeofday(&ts, 0);

  /*
  num = prio;
  num <<= 55;
  num |= (run_id & 0xfffffLLU) << 35;
  num |= (ts.tv_sec & 0xfffffLLU) << 15;
  num |= (ts.tv_usec & 0x7fffLLU);
  b32_number(num, buf);
  */

  /*
  // version 3 of the packet name
  // variable length: priority sec msec contest_id run_id: 1 + 8 + 2 + 8 + 8 = 27
  int msec = (ts.tv_usec / 1000) & 1023;
  unsigned char *out = buf;
  *out++ = b32_digits[prio];
  out = b32_number_3(out, ts.tv_sec);
  out = b32_number_2(out, msec, 2);
  out = b32_number_3(out, contest_id);
  out = b32_number_3(out, run_id);
  *out = 0;
  */

  // version 4 of the packet name
  // priority timestamp_us uuid
  // 5 + 40 + 64 + 64 -> base32 35 chars
  unsigned char *out = buf;
  *out++ = b32_digits[prio];
  uint64_t tsu = ((uint64_t) ts.tv_sec << 8) + ((ts.tv_usec >> 12) & 0xff);
  out = b32_ull(out, &tsu, 35);
  out = b32_ull(out, &judge_uuid->v[2], 60);
  out = b32_ull(out, &judge_uuid->v[0], 60);
  *out = 0;
}
