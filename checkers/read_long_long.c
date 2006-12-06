/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2006 Alexander Chernov <cher@ejudge.ru> */

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

int
checker_read_long_long(int ind,
                       const char *name,
                       int eof_error_flag,
                       long long *p_val)
{
  long long x;
  char sb[128], *db = 0, *vb = 0, *ep = 0;
  size_t ds = 0;

  if (!name) name = "";
  vb = checker_read_buf_2(ind, name, eof_error_flag, sb, sizeof(sb), &db, &ds);
  if (!vb) return -1;
  errno = 0;
  x = strtoll(vb, &ep, 10);
  if (*ep) fatal_read(ind, "cannot parse int64 value for %s", name);
  if (errno) fatal_read(ind, "int64 value %s is out of range", name);
  *p_val = x;
  return 1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
