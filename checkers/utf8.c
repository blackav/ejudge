/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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
checker_utf8_to_ucs2_buf(const char *in, unsigned short *out, size_t size)
{
  const unsigned char *p = (const unsigned char *) in;
  unsigned short *q = out;
  int w;

  while (size) {
    if (*p < 0x80) {
      *q++ = *p++;
      size--;
    } else if ((*p & 0xc0) == 0x80) {
      goto broken_coding;
    } else if ((*p & 0xe0) == 0xc0) {
      if (size < 2) goto broken_coding;
      if ((p[1] & 0xc0) != 0x80) goto broken_coding;
      w = (*p++ & 0x1f) << 6;
      w |= (*p++ & 0x3f);
      if (w < 0x80) goto broken_coding;
      *q++ = w;
      size -= 2;
    } else if ((*p & 0xf0) == 0xe0) {
      // three-byte character
      if (size < 3) goto broken_coding;
      if ((p[1] & 0xc0) != 0x80) goto broken_coding;
      if ((p[2] & 0xc0) != 0x80) goto broken_coding;
      w = (*p++ & 0x0f) << 12;
      w |= (*p++ & 0x3f) << 6;
      w |= (*p++ & 0x3f);
      if (w < 0x800) goto broken_coding;
      *q++ = w;
      size -= 3;
    } else if ((*p & 0xf8) == 0xf0) {
      // four-byte character
      if (size < 4) goto broken_coding;
      if ((p[1] & 0xc0) != 0x80) goto broken_coding;
      if ((p[2] & 0xc0) != 0x80) goto broken_coding;
      if ((p[3] & 0xc0) != 0x80) goto broken_coding;
      w = (*p++ & 0x07) << 18;
      w |= (*p++ & 0x3f) << 12;
      w |= (*p++ & 0x3f) << 6;
      w |= (*p++ & 0x3f);
      if (w < 0x10000) goto broken_coding;
      *q++ = 0xffff;
      size -= 4;
    } else {
      goto broken_coding;
    }
  }

  return q - out;

 broken_coding:
  return -1;
}
