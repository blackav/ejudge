/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2010 Alexander Chernov <cher@ejudge.ru> */

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
checker_corr_eoln(int lineno)
{
  int c;

  c = getc(f_corr);
  while (c != EOF && c != '\n' && isspace(c)) c = getc(f_corr);
  if (c != EOF && c != '\n') {
    if (c < ' ') {
      if (lineno > 0) {
        fatal_CF("%s: %d: invalid control character with code %d",
                 f_arr_names[2], lineno, c);
      } else {
        fatal_CF("%s: invalid control character with code %d",
                 f_arr_names[2], c);
      }
    }
    if (lineno > 0) {
      fatal_CF("%s: %d: end-of-line expected",
               f_arr_names[2], lineno);
    } else {
      fatal_CF("%s: end-of-line expected", f_arr_names[2]);
    }
  }
  if (ferror(f_corr)) {
    fatal_CF("%s: input error", f_arr_names[2]);
  }
}
