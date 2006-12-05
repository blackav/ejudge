/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005-2006 Alexander Chernov <cher@ejudge.ru> */

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
  unsigned long long out_ans, corr_ans;
  int i = 0;
  unsigned char buf[32];

  while (1) {
    i++;
    snprintf(buf, sizeof(buf), "[%d]", i);
    if (checker_read_corr_unsigned_long_long(buf, 0, &corr_ans) < 0) break;
    if (checker_read_out_unsigned_long_long(buf, 0, &out_ans) < 0) {
      fatal_WA("Too few numbers in the out output");
    }
    if (corr_ans != out_ans)
      fatal_WA("Answers differ: %s: out: %llu, corr: %llu", buf, out_ans, corr_ans);
  }
  if (checker_read_out_unsigned_long_long("x", 0, &out_ans) >= 0) {
    fatal_WA("Too many numbers in the out output");
  }
  checker_out_eof();

  checker_OK();
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
