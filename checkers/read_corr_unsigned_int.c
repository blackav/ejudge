/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ejudge.ru> */

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
checker_read_corr_unsigned_int(const char *name,
                               int eof_error_flag,
                               unsigned int *p_val)
{
  unsigned int x = 0;
  int n = 0;

  if ((n = fscanf(f_corr, "%u", &x)) != 1) {
    if (ferror(f_corr))
      fatal_CF("Input error from correct output file");
    if (n == EOF) {
      if (!eof_error_flag) return -1;
      fatal_CF("Unexpected EOF while reading %s in correct output file", name);
    }
    fatal_CF("Cannot read int value (%s) from correct output", name);
  }
  *p_val = x;
  return 1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
