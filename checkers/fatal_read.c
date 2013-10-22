/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005-2013 Alexander Chernov <cher@ejudge.ru> */

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

void fatal_read(int streamno, char const *format, ...)
{
  va_list args;

  fprintf(stderr, "%s: ", gettext(f_arr_names[streamno]));
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fprintf(stderr, "\n");
  exit((streamno == 1)?RUN_PRESENTATION_ERR:RUN_CHECK_FAILED);
}
