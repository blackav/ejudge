/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2010-2013 Alexander Chernov <cher@ejudge.ru> */

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
checker_eof(
        FILE *f,
        checker_error_func_t error_func,
        const char *name)
{
  int c;

  while ((c = getc(f)) != EOF && isspace(c));
  if (c != EOF) {
    if (c < ' ') {
      error_func(_("%s: invalid control character with code %d"), name, c);
    } else {
      error_func(_("%s: garbage where EOF expected"), name);
    }
  }
  if (ferror(f)) {
    fatal_CF(_("%s: input error"), name);
  }
}
