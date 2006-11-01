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

void
checker_read_file_f(FILE *f, unsigned char **out, size_t *out_len)
{
  unsigned char read_buf[512];
  unsigned char *buf = 0;
  size_t buf_len = 0, read_len = 0;

  while (1) {
    read_len = fread(read_buf, 1, sizeof(read_buf), f);
    if (!read_len) break;
    if (!buf_len) {
      buf = (unsigned char*) xcalloc(read_len + 1, 1);
      memcpy(buf, read_buf, read_len);
      buf_len = read_len;
    } else {
      buf = (unsigned char*) xrealloc(buf, buf_len + read_len);
      memcpy(buf + buf_len, read_buf, read_len);
      buf_len += read_len;
      buf[buf_len] = 0;
    }
  }
  if (ferror(f)) {
    fatal_CF("Input error");
  }
  if (!buf_len) {
    buf = (unsigned char*) xmalloc(1);
    buf[0] = 0;
    buf_len = 0;
  }
  if (out) *out = buf;
  if (out_len) *out_len = buf_len;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
