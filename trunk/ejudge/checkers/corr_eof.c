/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2010 Alexander Chernov <cher@ispras.ru> */

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
checker_corr_eof(void)
{
  int c;

  while ((c = getc(f_corr)) != EOF && isspace(c));
  if (c != EOF) {
    if (c < ' ') {
      fatal_CF("%s: invalid control character with code %d",
               f_arr_names[2], c);
    } else {
      fatal_CF("%s: garbage where EOF expected",
               f_arr_names[2]);
    }
  }
  if (ferror(f_corr)) {
    fatal_CF("%s: input error", f_arr_names[2]);
  }
}
