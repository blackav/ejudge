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
checker_read_unsigned_int(int ind,
                          const char *name,
                          int eof_error_flag,
                          unsigned int *p_val)
{
  unsigned int x = 0.0;
  int n;

  if (!name) name = "";
  if ((n = fscanf(f_arr[ind], "%u", &x)) != 1) {
    if (ferror(f_arr[ind])) fatal_CF("Input error from input file");
    if (n == EOF) {
      if (!eof_error_flag) return -1;
      if (ind == 1)
        fatal_PE("Unexpected EOF while reading `%s'", name);
      fatal_CF("Unexpected EOF while reading `%s'", name);
    }
    if (ind == 1)
      fatal_PE("Cannot parse long long value `%s'", name);
    fatal_CF("Cannot parse long long value `%s'", name);
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
