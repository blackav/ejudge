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

void
checker_out_eof(void)
{
  int c;

  while ((c = getc(f_out)) != EOF && isspace(c));
  if (c != EOF) {
    if (c < ' ') {
      fatal_PE("%s: invalid control character with code %d",
               f_arr_names[1], c);
    } else {
      fatal_PE("%s: garbage where EOF expected", f_arr_names[1]);
    }
  }
  if (ferror(f_out)) {
    fatal_CF("%s: input error", f_arr_names[1]);
  }
}

void
checker_team_eof(void)
{
  return checker_out_eof();
}
