/* -*- mode: C -*- */
/* $Id$ */

/* Copyright (C) 2002-2014 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#define __REUSE__ 1

/* reuse include directives */
#include "ejudge/integral.h"
#include "ejudge/str_utils.h"

#include <string.h>

size_t
reuse_strncatx(char *buf, size_t size, size_t i, char const *src)
{
  size_t l = strlen(src);
  size_t s;

  if (!size || i >= size) return i + l;
  s = size - i - 1;
  if (s > l) s = l;
  if (s > 0) memmove(buf + i, src, s);
  buf[i + s] = 0;
  return i + l;
}
