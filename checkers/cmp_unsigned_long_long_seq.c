/* -*- mode: c -*- */

/* Copyright (C) 2005-2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "l10n_impl.h"

#include <errno.h>

int checker_main(int argc, char **argv)
{
  unsigned long long out_ans, corr_ans;
  int i = 0;
  unsigned char buf[32];
  int base = 10;
  char *s;

  checker_l10n_prepare();

  if (getenv("EJ_REQUIRE_NL")) {
    checker_require_nl(f_out, 1);
  }
  if ((s = getenv("EJ_BASE")) && *s) {
    errno = 0;
    char *eptr;
    base = strtol(s, &eptr, 10);
    if (errno || *eptr || base <= 1 || base > 36) {
      fatal_CF("invalid conversion base");
    }
  }

  checker_skip_bom(f_corr);
  checker_skip_bom(f_out);

  while (1) {
    i++;
    snprintf(buf, sizeof(buf), "[%d]", i);
    if (checker_read_unsigned_long_long_2(2, buf, 0, base, &corr_ans) < 0) break;
    if (checker_read_unsigned_long_long_2(1, buf, 0, base, &out_ans) < 0) {
      fatal_WA(_("Too few numbers in the output"));
    }
    if (corr_ans != out_ans)
      fatal_WA(_("Answers differ: %s: output: %llu, correct: %llu"), buf, out_ans, corr_ans);
  }
  if (checker_read_out_unsigned_long_long("x", 0, &out_ans) >= 0) {
    fatal_WA(_("Too many numbers in the output"));
  }
  checker_out_eof();

  checker_OK();
}
