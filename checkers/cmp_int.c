/* -*- mode: c -*- */

/* Copyright (C) 2004-2017 Alexander Chernov <cher@ejudge.ru> */

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
  int out_ans, corr_ans;
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
  checker_read_int_2(2, _("correct"), 1, base, &corr_ans);
  checker_corr_eof();
  checker_skip_bom(f_out);
  checker_read_int_2(1, _("output"), 1, base, &out_ans);
  checker_out_eof();
  if (out_ans != corr_ans)
    fatal_WA(_("Answers do not match: output: %d, correct: %d"), out_ans, corr_ans);
  checker_OK();
}
