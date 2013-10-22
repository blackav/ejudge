/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2013 Alexander Chernov <cher@ejudge.ru> */

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

#include "l10n_impl.h"

/**
   read a string (i.e. sequence of chars except whitespace)
   \param f input file
   \param error_func error reporting routine
   \param name description of data to be read
   \param eof_error_flag if TRUE, EOF condition is error
   \param sbuf static buffer for the string
   \param ssz static buffer size for the string
   \param pdbuf pointer to dynamic buffer pointer
   \param pdsz pointer to dynamic buffer size
 */
char *
checker_read_buf_ex(
        FILE *f,
        checker_error_func_t error_func,
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

  c = getc(f);
  while (isspace(c)) c = getc(f);
  if (ferror(f)) fatal_CF(_("%s: input error"), name);
  if (feof(f)) {
    if (eof_error_flag) error_func(_("%s: unexpected EOF"), name);
    else return 0;
  }

  if (c < ' ') error_func(_("%s: invalid control character %d"), name, c);

  if (sbuf && ssz > 1) {
    while (c != EOF && !isspace(c) && i + 1 < ssz) {
      if (c < ' ') error_func(_("%s: invalid control character %d"), name, c);
      sbuf[i++] = c;
      c = getc(f);
    }
    if (c == EOF) {
      if (ferror(f)) fatal_CF(_("%s: input error"), name);
      sbuf[i] = 0;
      return sbuf;
    }
    if (isspace(c)) {
      ungetc(c, f);
      sbuf[i] = 0;
      return sbuf;
    }
    if (!pdbuf || !pdsz) error_func(_("%s: input element is too long"), name);
  } else {
    if (!pdbuf || !pdsz) error_func(_("%s: invalid arguments"), name);
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
    if (c < ' ') error_func(_("%s: invalid control character %d"), name, c);
    if (i + 1 >= dsz) {
      dsz *= 2;
      dbuf = (char*) xrealloc(dbuf, dsz);
    }
    dbuf[i++] = c;
    c = getc(f);
  }
  if (c == EOF) {
    if (ferror(f)) fatal_CF(_("%s: input error"), name);
  } else {
    ungetc(c, f);
  }
  dbuf[i] = 0;
  *pdbuf = dbuf;
  *pdsz = dsz;
  return dbuf;
}
