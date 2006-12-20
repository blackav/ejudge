/* -*- c -*- */
/* $Id$*/

/* Copyright (C) 2005,2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "misctext.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <string.h>
#include <stdio.h>

unsigned char *
dos2unix_str(const unsigned char *s)
{
  unsigned char *out, *pout;
  const unsigned char *pin;
  size_t len;

  ASSERT(s);
  len = strlen(s);
  out = xmalloc(len + 1);
  for (pout = out, pin = s; *pin; pin++)
    if (*pin != '\r') *pout++ = *pin;
  *pout = 0;
  return out;
}

size_t
dos2unix_buf(unsigned char *s, size_t size)
{
  unsigned char *p = s, *q = s;

  for (;size; size--, p++) {
    if (*p != '\r') *q++ = *p;
  }
  *q = 0;
  return (size_t) (q - s);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
