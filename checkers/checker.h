/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003,2004 Alexander Chernov <cher@ispras.ru> */

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

#ifndef NEED_CORR
#error You must define NEED_CORR macro
#endif /* NEED_CORR */
#ifndef NEED_INFO
#error You must define NEED_INFO macro
#endif /* NEED_INFO */
#ifndef NEED_TGZ
#define NEED_TGZ 0
#endif /* NEED_TGZ */

#ifdef __cplusplus
#define CHECK_char_t char
#else
#define CHECK_char_t unsigned char
#endif

#include "checker_internal.h"

#if NEED_INFO == 1
#include "testinfo.h"
int (*testinfo_parse_func)(const CHECK_char_t*,testinfo_t*) = testinfo_parse;
const CHECK_char_t *(*testinfo_strerror_func)(int) = testinfo_strerror;
extern testinfo_t test_info;
#else
struct testinfo_struct;
int (*testinfo_parse_func)(const CHECK_char_t*,struct testinfo_struct*) = 0;
const CHECK_char_t *(*testinfo_strerror_func)(int) = 0;
#endif /* NEED_INFO */

extern int checker_main(int, char **);
int
main(int argc, char **argv)
{
  checker_do_init(argc, argv, NEED_CORR, NEED_INFO, NEED_TGZ);
  return checker_main(argc, argv);
}
