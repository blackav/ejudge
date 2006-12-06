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

char *
checker_read_buf_2(
	int ind,
        const char *name,
        int eof_error_flag,
        char *sbuf,
        size_t ssz,
        char **pdbuf,
        size_t *pdsz)
{
  int c, i = 0;
  char *dbuf = 0;
  size_t dsz = 0;

  c = getc(f_arr[ind]);
  while (isspace(c)) c = getc(f_arr[ind]);
  if (ferror(f_arr[ind])) fatal_read(ind, "input error");
  if (feof(f_arr[ind])) {
    if (eof_error_flag) fatal_read(ind, "unexpected EOF");
    else return 0;
  }

  if (sbuf && ssz > 1) {
    while (c != EOF && !isspace(c) && i + 1 < ssz) {
      sbuf[i++] = c;
      c = getc(f_arr[ind]);
    }
    if (c == EOF) {
      if (ferror(f_arr[ind])) fatal_read(ind, "input error");
      sbuf[i] = 0;
      return sbuf;
    }
    if (isspace(c)) {
      ungetc(c, f_arr[ind]);
      sbuf[i] = 0;
      return sbuf;
    }
    if (!pdbuf || !pdsz) fatal_read(ind, "input element is too long");
  } else {
    if (!pdbuf || !pdsz) fatal_CF("invalid arguments");
  }

  dbuf = *pdbuf;
  dsz = *pdsz;
  if (!dbuf || !dsz) {
    dsz = 32;
    while (i >= dsz) dsz *= 2;
    dbuf = (char *) xmalloc(dsz);
  } else {
    while (i >= dsz) dsz *= 2;
    dbuf = (char*) xrealloc(dbuf, dsz);
  }
  if (i > 0) memcpy(dbuf, sbuf, i + 1);

  while (c != EOF && !isspace(c)) {
    if (i + 1 >= dsz) {
      dsz *= 2;
      dbuf = (char*) xrealloc(dbuf, dsz);
    }
    dbuf[i++] = c;
    c = getc(f_arr[ind]);
  }
  if (c == EOF) {
    if (ferror(f_arr[ind])) fatal_read(ind, "input error");
  } else {
    ungetc(c, f_arr[ind]);
  }
  dbuf[i] = 0;
  *pdbuf = dbuf;
  *pdsz = dsz;
  return dbuf;
}
