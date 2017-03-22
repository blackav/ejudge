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

void
checker_skip_bom(FILE *f)
{
  // skip UTF-8 BOM: 0xEF, 0xBB, 0xBF
  int c;
  if ((c = getc_unlocked(f)) == 0xEF) {
    if ((c = getc_unlocked(f)) == 0xBB) {
      if ((c = getc_unlocked(f)) == 0xBF) {
        // nothing
      } else {
        if (fseek(f, -3L, SEEK_CUR) < 0)
          ungetc(c, f);
      }
    } else {
      if (fseek(f, -2L, SEEK_CUR) < 0)
        ungetc(c, f);
    }
  } else {
    if (fseek(f, -1L, SEEK_CUR) < 0)
      ungetc(c, f);
  }
}
