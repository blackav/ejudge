/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2013 Alexander Chernov <cher@ejudge.ru> */

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
checker_skip_eoln(int ind, int eof_error_flag)
{
  int c;

  c = getc(f_arr[ind]);
  while (c != EOF && c != '\n') {
    if (!isspace(c) && c < ' ') {
      fatal_read(ind, _("Invalid control character with code %d"), c);
    }
    c = getc(f_arr[ind]);
  }
  if (c == EOF && ferror(f_arr[ind])) {
    fatal_CF(_("Input error while seeking EOLN"));
  }
  if (c == EOF) {
    if (!eof_error_flag) return -1;
    fatal_read(ind, _("Unexpected EOF while seeking EOLN"));
  }
  return 0;
}
