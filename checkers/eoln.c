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
checker_eoln(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int lineno)
{
  int c;

  c = getc(f_in);
  while (c != EOF && c != '\n' && isspace(c)) c = getc(f_in);
  if (c != EOF && c != '\n') {
    if (c < ' ') {
      if (lineno > 0) {
        error_func(_("%s: %d: invalid control character with code %d"),
                   name, lineno, c);
      } else {
        error_func(_("%s: invalid control character with code %d"), name, c);
      }
    }
    if (lineno > 0) {
      error_func(_("%s: %d: end-of-line expected"), name, lineno);
    } else {
      error_func(_("%s: end-of-line expected"), name);
    }
  }
}
