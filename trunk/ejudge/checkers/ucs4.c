/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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
checker_ucs4_tolower(int c)
{
  if (c < 0) return c;

  if (c >= 'A' && c <= 'Z') return c + 0x20;
  if (c >= 0x410 && c <= 0x42f) return c + 0x20;
  if (c == 0x401) return c + 0x50;
  return c;
}

int *
checker_ucs4_tolower_buf(int *buf, size_t size)
{
  int *p = buf;

  for (; size; size--) {
    if (*p >= 'A' && *p <= 'Z') *p += 0x20;
    else if (*p >= 0x410 && *p <= 0x42f) *p += 0x20;
    else if (*p == 0x401) *p += 0x50;
  }
  return buf;
}
