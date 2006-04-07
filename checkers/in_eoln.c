/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

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
checker_in_eoln(int lineno)
{
  int c;

  c = getc(f_in);
  while (c != EOF && c != '\n' && isspace(c)) c = getc(f_in);
  if (c != EOF && c != '\n') {
    if (lineno > 0) {
      fatal_CF("input: end-of-line expected at line %d", lineno);
    } else {
      fatal_CF("input: end-of-line expected");
    }
  }
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
