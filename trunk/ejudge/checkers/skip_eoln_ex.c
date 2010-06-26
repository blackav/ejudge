/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2010 Alexander Chernov <cher@ejudge.ru> */

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

int
checker_skip_eoln_ex(
        FILE *f,
        checker_error_func_t error_func,
        const char *name,
        int eof_error_flag)
{
  int c;

  c = getc(f);
  while (c != EOF && c != '\n') {
    if (!isspace(c) && c < ' ') {
      error_func("%s: invalid control character with code %d", name, c);
    }
    c = getc(f);
  }
  if (c == EOF && ferror(f)) {
    fatal_CF("%s: input error while seeking EOLN", name);
  }
  if (c == EOF) {
    if (!eof_error_flag) return -1;
    error_func("%s: unexpected EOF while seeking EOLN", name);
  }
  return 0;
}
