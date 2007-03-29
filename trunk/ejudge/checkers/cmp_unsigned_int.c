/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2007 Alexander Chernov <cher@ejudge.ru> */

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

#define NEED_CORR 1
#define NEED_INFO 0
#define NEED_TGZ  0
#include "checker.h"

int checker_main(int argc, char **argv)
{
  unsigned int out_ans, corr_ans;

  checker_read_corr_unsigned_int("corr_ans", 1, &corr_ans);
  checker_corr_eof();
  checker_read_out_unsigned_int("out_ans", 1, &out_ans);
  checker_out_eof();
  if (out_ans != corr_ans)
    fatal_WA("Answers do not match: out = %d, corr = %d", out_ans, corr_ans);
  checker_OK();
}

/*
 * Local variables:
 *  compile-command: "gcc -Wall -O2 -s -I. -L. cmp_unsigned_int.c -o cmp_unsigned_int -lchecker"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
