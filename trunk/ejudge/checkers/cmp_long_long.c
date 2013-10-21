/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2013 Alexander Chernov <cher@ejudge.ru> */

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

int checker_main(int argc, char **argv)
{
  long long out_ans, corr_ans;

  checker_l10n_prepare();

  if (getenv("EJ_REQUIRE_NL")) {
    if (fseek(f_out, -1L, SEEK_END) >= 0) {
      if (getc(f_out) != '\n') fatal_PE(_("No final \\n in the output file"));
      fseek(f_out, 0L, SEEK_SET);
    }
  }

  checker_read_corr_long_long(_("correct"), 1, &corr_ans);
  checker_corr_eof();
  checker_read_out_long_long(_("output"), 1, &out_ans);
  checker_out_eof();
  if (out_ans != corr_ans)
    fatal_WA(_("Answers do not match: output: %lld, correct: %lld"),
             out_ans, corr_ans);
  checker_OK();
}
