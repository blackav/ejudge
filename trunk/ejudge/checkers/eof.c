/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2010 Alexander Chernov <cher@ejudge.ru> */

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
      error_func("%s: invalid control character with code %d", name, c);
    } else {
      error_func("%s: garbage where EOF expected", name);
    }
  }
  if (ferror(f)) {
    fatal_CF("%s: input error", name);
  }
}
