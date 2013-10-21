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
checker_in_open(const char *path)
{
  if (f_in && f_in == f_arr[0]) {
    fclose(f_in); f_in = 0; f_arr[0] = 0;
  }
  if (f_in) fclose(f_in);
  f_in = 0;
  if (f_arr[0]) fclose(f_arr[0]);
  f_arr[0] = 0;

  if (!(f_in = fopen(path, "r")))
    fatal_CF(_("%s: cannot open %s for reading"), gettext(f_arr_names[0]), path);
  f_arr[0] = f_in;
}
