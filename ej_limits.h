/* -*- c -*- */
/* $Id$ */
#ifndef __EJ_LIMITS_H__
#define __EJ_LIMITS_H__

/* Copyright (C) 2005-2007 Alexander Chernov <cher@ejudge.ru> */

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
#define EJ_MAX_CONTEST_ID  999999

/* maximal possible number of a user */
#define EJ_MAX_USER_ID  999999

/* maximal possible number of a submit */
#define EJ_MAX_RUN_ID   999999

/* maximal possible number of a message */
#define EJ_MAX_CLAR_ID  999999

/* maximal possible number of a programming language */
#define EJ_MAX_LANG_ID  255

/* maximal possible number of a problem */
#define EJ_MAX_PROB_ID  255

/* maximal number of simultaneously supported testers */
#define EJ_MAX_TESTER  100

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

#endif /* __EJ_LIMITS_H__ */
