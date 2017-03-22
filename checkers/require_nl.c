/* -*- mode: c -*- */

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "checker_internal.h"

#include "l10n_impl.h"

int
checker_require_nl(int allow_fail)
{
  if (fseek(f_out, -1L, SEEK_END) < 0) return 1; // non-seekable file
  if (getc_unlocked(f_out) == '\n') {
    fseek(f_out, 0L, SEEK_SET);
    return 1;
  }

  // check that the only content is BOM 0xEF, 0xBB, 0xBF
  if (fseek(f_out, 0L, SEEK_SET) < 0) return 1;
  if (getc_unlocked(f_out) == 0xEF
      && getc_unlocked(f_out) == 0xBB
      && getc_unlocked(f_out) == 0xBF
      && getc_unlocked(f_out) == EOF) {
    fseek(f_out, 0L, SEEK_SET);
    return 1;
  }

  if (allow_fail) {
    fatal_PE(_("No final \\n in the output file"));
  }
  return -1;
}
