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
#include <errno.h>

int
checker_read_out_unsigned_int(const char *name,
                              int eof_error_flag,
                              unsigned int *p_val)
{
  unsigned int x;
  char sb[128], *db = 0, *vb = 0, *ep = 0;
  size_t ds = 0;

  if (!name) name = "";
  vb = checker_read_buf_2(1, name, eof_error_flag, sb, sizeof(sb), &db, &ds);
  if (!vb) return -1;
  if (vb[0] == '-') fatal_PE("minus sign before uint32 value in output");
  errno = 0;
  x = strtoul(vb, &ep, 10);
  if (*ep) fatal_PE("cannot parse uint32 value for %s from output", name);
  if (errno) fatal_PE("uint32 value %s from output is out of range", name);
  *p_val = x;
  return 1;
}

int
checker_read_team_unsigned_int(const char *name,
                               int eof_error_flag,
                               unsigned int *p_val)
{
  return checker_read_out_unsigned_int(name, eof_error_flag, p_val);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
