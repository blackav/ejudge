/* -*- mode: c -*- */

/* Copyright (C) 2006-2017 Alexander Chernov <cher@ejudge.ru> */

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
  char user_buf[1024], corr_buf[1024];

  if (getenv("EJ_REQUIRE_NL")) {
    checker_require_nl(f_out, 1);
  }

  checker_skip_bom(f_corr);
  checker_skip_bom(f_out);

  checker_read_buf_2(1, _("output"), 1, user_buf, sizeof(user_buf), 0, 0);
  checker_read_buf_2(2, _("correct"), 1, corr_buf, sizeof(corr_buf), 0, 0);
  if (strcasecmp(corr_buf, "yes") && strcasecmp(corr_buf, "no"))
    fatal_CF(_("Correct answer is neither `yes' nor `no' (case insensitive)"));

  if (strcasecmp(user_buf, "yes") && strcasecmp(user_buf, "no"))
    fatal_PE(_("User answer is neither `yes' nor `no' (case insensitive)"));

  if (strcasecmp(user_buf, corr_buf))
    fatal_WA(_("Answers do not match"));
  if (!getenv("CASE_INSENSITIVE"))
    if (strcmp(user_buf, corr_buf))
      fatal_PE(_("Letter case mismatch"));

  checker_corr_eof();
  checker_out_eof();

  checker_OK();
}
