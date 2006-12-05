/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ejudge.ru> */

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

#define NEED_TGZ 1
#include "checker_internal.h"
#include "testinfo.h"

extern int (*testinfo_parse_func)(const char*,testinfo_t*);
extern const char *(*testinfo_strerror_func)(int);
testinfo_t test_info;

void
checker_do_init(int argc, char **argv, int corr_flag, int info_flag,
                int tgz_flag)
{
  int errcode;
  int need_arg = 3;
  int arg_ind = 3;

  if (corr_flag) need_arg++;
  if (info_flag) need_arg++;
  if (tgz_flag) need_arg += 2;
  if (argc < need_arg)
    fatal_CF("Invalid number of arguments: %d instead of %d", argc, need_arg);

  if (!(f_in = fopen(argv[1], "r")))
    fatal_CF("Cannot open input file `%s'", argv[1]);
  f_arr[0] = f_in;
  if (!(f_out = fopen(argv[2], "r")))
    fatal_PE("Cannot open team output file `%s'", argv[2]);
  f_arr[1] = f_out;
  // backward compatibility
  f_team = f_out;

  if (corr_flag) {
    if (!(f_corr = fopen(argv[arg_ind], "r")))
      fatal_CF("Cannot open correct output file `%s'", argv[arg_ind]);
    f_arr[2] = f_corr;
    arg_ind++;
  }

  if (info_flag) {
    if (!testinfo_parse_func)
      fatal_CF("Test info is requested, but no code compiled in");
    errcode = (*testinfo_parse_func)(argv[arg_ind++], &test_info);
    if (errcode < 0)
      fatal_CF("Test info parsing failed: %s",
               (*testinfo_strerror_func)(errcode));
  }

#if !defined __MINGW32__
  if (tgz_flag) {
    if (!(dir_in = opendir(argv[arg_ind])))
      fatal_CF("Cannot open input directory '%s'", argv[arg_ind]);
    dir_in_path = xstrdup(argv[arg_ind]);
    arg_ind++;
    if (!(dir_out = opendir(argv[arg_ind])))
      fatal_CF("Cannot open output directory '%s'", argv[arg_ind]);
    dir_out_path = xstrdup(argv[arg_ind]);
    arg_ind++;
  }
#endif
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
