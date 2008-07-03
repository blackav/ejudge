/* -*- c -*- */
/* $Id$ */
#ifndef __EJ_LIMITS_H__
#define __EJ_LIMITS_H__

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

/* maximal possible number of a contest */
#define EJ_MAX_CONTEST_ID  999999      // [1 .. MAX]

/* maximal possible number of a user */
#define EJ_MAX_USER_ID  999999         // [1 .. MAX]

/* maximal possible number of a submit */
#define EJ_MAX_RUN_ID   999999         // [0 .. MAX]

/* maximal possible number of a message */
#define EJ_MAX_CLAR_ID  999999         // [0 .. MAX]

/* maximal possible number of a programming language */
#define EJ_MAX_LANG_ID  255            // [1 .. MAX]

/* maximal possible number of a problem */
#define EJ_MAX_PROB_ID  255            // [1 .. MAX]

/* maximal number of simultaneously supported testers */
#define EJ_MAX_TESTER  100             // [1 .. MAX]

/* maximal number of tests */
#define EJ_MAX_TEST_NUM 32766

/* maximal problem score */
#define EJ_MAX_SCORE 999999            // [0 .. MAX]

/* maximal number of variants */
#define EJ_MAX_VARIANT           255   // [0 .. MAX]

/* maximal allowed time-limit ajustment in seconds */
#define EJ_MAX_TIME_LIMIT_ADJ    100

/* maximal allowed time-limit ajustment in millis */
#define EJ_MAX_TIME_LIMIT_ADJ_MILLIS    100000

/* maximal judge ID */
#define EJ_MAX_JUDGE_ID          65535

/* maximal locale identifier */
#define EJ_MAX_LOCALE_ID 127

/* maximal directory depth in base32-encoding */
#define EJ_MAX_32DIGITS 4

/* the internal charset if no default charset is specified */
#define EJ_INTERNAL_CHARSET "UTF-8"

/* the length of the serve's packet name
 * includes one character for priority
 */
#define EJ_SERVE_PACKET_NAME_SIZE 13

/* maximal length of a CGI parameter value */
#define EJ_MAX_CGI_VALUE_LEN 2097152

/* maximal length of a `serve' command packet */
#define EJ_MAX_SERVE_PACKET_LEN 1048576

/* maximal length of a `userlist-server' command packet */
#define EJ_MAX_USERLIST_PACKET_LEN 1048576

/* maximal length of run command packet */
#define EJ_MAX_RUN_PACKET_SIZE       65536

/* maximal length of user spelling */
#define EJ_MAX_USER_SPELLING_LEN 1024

/* maximal length of problem spelling */
#define EJ_MAX_PROB_SPELLING_LEN 1024

/* maximal length of the executable suffix */
#define EJ_MAX_EXE_SFX_LEN       256

/* maximal length of the architecture name */
#define EJ_MAX_ARCH_LEN          256

/* maximal length of a compile packet */
#define EJ_MAX_COMPILE_PACKET_SIZE   65536

/* maximal length of a run subblock in a compile packet */
#define EJ_MAX_COMPILE_RUN_BLOCK_LEN 65536

/* maximal number of environment vars for a compile packet */
#define EJ_MAX_COMPILE_ENV_NUM       65536

/* maximal length of environment vars for a compile packet */
#define EJ_MAX_COMPILE_ENV_LEN       65535

/* number of microseconds in a second */
#define USEC_MAX 999999

/* number of nanoseconds in a second */
#define NSEC_MAX 999999999

#endif /* __EJ_LIMITS_H__ */
