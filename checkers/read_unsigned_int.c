/* -*- mode: c -*- */

/* Copyright (C) 2004-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include <errno.h>

#include "l10n_impl.h"

int
checker_read_unsigned_int(
        int ind,
        const char *name,
        int eof_error_flag,
        unsigned int *p_val)
{
  unsigned long x;
  char sb[128], *db = 0, *vb = 0, *ep = 0;
  size_t ds = 0;

  if (!name) name = "";
  vb = checker_read_buf_2(ind, name, eof_error_flag, sb, sizeof(sb), &db, &ds);
  if (!vb) return -1;
  if (!*vb) {
    fatal_read(ind, _("%s: no uint32 value"), name);
  }

  if (vb[0] == '-') {
    fatal_read(ind, _("%s: `-' before uint32 value"), name);
  }
  errno = 0;
  x = strtoul(vb, &ep, 10);
  if (*ep) {
    fatal_read(ind, _("%s: cannot parse uint32 value"), name);
  }
  if (errno || (unsigned) x != x) {
    fatal_read(ind, _("%s: uint32 value is out of range"), name);
  }
  *p_val = x;
  return 1;
}
