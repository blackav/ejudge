/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005-2013 Alexander Chernov <cher@ejudge.ru> */

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
  unsigned int out_ans, corr_ans;
  int i = 0;
  unsigned char buf[32];

  if (getenv("EJ_REQUIRE_NL")) {
    if (fseek(f_out, -1L, SEEK_END) >= 0) {
      if (getc(f_out) != '\n') fatal_PE(_("No final \\n in the output file"));
      fseek(f_out, 0L, SEEK_SET);
    }
  }

  while (1) {
    i++;
    snprintf(buf, sizeof(buf), "[%d]", i);
    if (checker_read_corr_unsigned_int(buf, 0, &corr_ans) < 0) break;
    if (checker_read_out_unsigned_int(buf, 0, &out_ans) < 0) {
      fatal_WA(_("Too few numbers in the output"));
    }
    if (corr_ans != out_ans)
      fatal_WA(_("Answers differ: %s: output: %u, correct: %u"), buf, out_ans, corr_ans);
  }
  if (checker_read_out_unsigned_int("x", 0, &out_ans) >= 0) {
    fatal_WA(_("Too many numbers in the output"));
  }
  checker_out_eof();

  checker_OK();
}
