/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2013 Alexander Chernov <cher@ejudge.ru> */

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
#include "checker.h"

#include "l10n_impl.h"

int checker_main(int argc, char **argv)
{
  checker_sexpr_t user_ans = 0, corr_ans = 0;

  checker_l10n_prepare();

  if (getenv("EJ_REQUIRE_NL")) {
    if (fseek(f_out, -1L, SEEK_END) >= 0) {
      if (getc(f_out) != '\n') fatal_PE(_("No final \\n in the output file"));
      fseek(f_out, 0L, SEEK_SET);
    }
  }

  corr_ans = checker_read_sexpr(2);
  checker_corr_eof();
  user_ans = checker_read_sexpr(1);
  checker_out_eof();
  if (!checker_eq_sexpr(user_ans, corr_ans))
    fatal_WA(_("Answers do not match"));
  checker_OK();
}
