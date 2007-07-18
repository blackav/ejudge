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
checker_utf8_to_ucs4_buf(int *out, const char *in, size_t in_size)
{
  const unsigned char *p = (const unsigned char *) in;
  int *q = out;
  int w;

  while (in_size) {
    if (*p < 0x80) {
      *q++ = *p++;
      in_size--;
    } else if ((*p & 0xc0) == 0x80) {
      goto broken_coding;
    } else if ((*p & 0xe0) == 0xc0) {
      if (in_size < 2) goto broken_coding;
      if ((p[1] & 0xc0) != 0x80) goto broken_coding;
      w = (*p++ & 0x1f) << 6;
      w |= (*p++ & 0x3f);
      if (w < 0x80) goto broken_coding;
      *q++ = w;
      in_size -= 2;
    } else if ((*p & 0xf0) == 0xe0) {
      // three-byte character
      if (in_size < 3) goto broken_coding;
      if ((p[1] & 0xc0) != 0x80) goto broken_coding;
      if ((p[2] & 0xc0) != 0x80) goto broken_coding;
      w = (*p++ & 0x0f) << 12;
      w |= (*p++ & 0x3f) << 6;
      w |= (*p++ & 0x3f);
      if (w < 0x800) goto broken_coding;
      *q++ = w;
      in_size -= 3;
    } else if ((*p & 0xf8) == 0xf0) {
      // four-byte character
      if (in_size < 4) goto broken_coding;
      if ((p[1] & 0xc0) != 0x80) goto broken_coding;
      if ((p[2] & 0xc0) != 0x80) goto broken_coding;
      if ((p[3] & 0xc0) != 0x80) goto broken_coding;
      w = (*p++ & 0x07) << 18;
      w |= (*p++ & 0x3f) << 12;
      w |= (*p++ & 0x3f) << 6;
      w |= (*p++ & 0x3f);
      if (w < 0x10000) goto broken_coding;
      *q++ = w;
      in_size -= 4;
    } else {
      goto broken_coding;
    }
  }

  return q - out;

 broken_coding:
  return -1;
}

int
checker_utf8_to_ucs4_str(int *out, const char *in)
{
  size_t in_size = strlen(in);
  int out_size = checker_utf8_to_ucs4_buf(out, in, in_size);
  if (out_size >= 0) {
    out[out_size] = 0;
  }
  return out_size;
}


size_t
checker_ucs4_to_utf8_size(const int *in)
{
  size_t out_size = 1;
  while (*in) {
    if (*in <= 0x7f) {
      out_size++;
    } else if (*in <= 0x7ff) {
      out_size += 2;
    } else if (*in <= 0xffff) {
      out_size += 3;
    } else {
      out_size += 4;
    }
  }

  return out_size;
}

const unsigned char *
checker_ucs4_to_utf8_str(unsigned char *buf, size_t size, const int *in)
{
  const int *pin = in;
  unsigned char *pout = buf;
  
  if (!buf || !size) return "";
  size--;
  while (*pin && size) {
    if (*pin <= 0x7f) {
      *pout++ = *pin;
      size--;
    } else if (*pin <= 0x7ff) {
      if (size < 2) break;
      *pout++ = (*pin >> 6) | 0xc0;
      *pout++ = (*pin & 0x3f) | 0x80;
      size -= 2;
    } else if (*pin <= 0xffff) {
      if (size < 3) break;
      *pout++ = (*pin >> 12) | 0xe0;
      *pout++ = ((*pin >> 6) & 0x3f) | 0x80;
      *pout++ = (*pin & 0x3f) | 0x80;
      size -= 3;
    } else {
      if (size < 4) break;
      *pout++ = ((*pin >> 18) & 0x07) | 0xf0;
      *pout++ = ((*pin >> 12) & 0x3f) | 0x80;
      *pout++ = ((*pin >> 6) & 0x3f) | 0x80;
      *pout++ = (*pin & 0x3f) | 0x80;
      size -= 4;
    }
    pin++;
  }
  *pout = 0;
  return buf;
}

int
checker_is_utf8_locale(void)
{
  const unsigned char *s;
  int l;

  if (!(s = getenv("LC_CTYPE")) && !(s = getenv("LC_ALL"))
      && !(s = getenv("LANG")))
    return 0;

  if ((l = strlen(s)) > 5
      && s[l - 1] == '8'
      && s[l - 2] == '-'
      && (s[l - 3] == 'f' || s[l - 3] == 'F')
      && (s[l - 4] == 't' || s[l - 4] == 'T')
      && (s[l - 5] == 'u' || s[l - 5] == 'U'))
    return 1;
  return 0;
}
