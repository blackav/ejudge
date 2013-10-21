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
   \param ind input stream index (0 - test in, 1 - program out, 2 - correct)
   \param name description of data to be read
   \param eof_error_flag if TRUE, EOF condition is error
   \param sbuf static buffer for the string
   \param ssz static buffer size for the string
   \param pdbuf pointer to dynamic buffer pointer
   \param pdsz pointer to dynamic buffer size
 */
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
  if (ferror(f_arr[ind])) {
    fatal_CF(_("%s: input error"), gettext(f_arr_names[ind]));
  }
  if (feof(f_arr[ind])) {
    if (eof_error_flag) fatal_read(ind, _("Unexpected EOF"));
    else return 0;
  }

  if (c < ' ') fatal_read(ind, _("Invalid control character %d"), c);

  if (sbuf && ssz > 1) {
    while (c != EOF && !isspace(c) && i + 1 < ssz) {
      if (c < ' ') fatal_read(ind, _("Invalid control character %d"), c);
      sbuf[i++] = c;
      c = getc(f_arr[ind]);
    }
    if (c == EOF) {
      if (ferror(f_arr[ind])) {
        fatal_CF(_("%s: input error"), gettext(f_arr_names[ind]));
      }
      sbuf[i] = 0;
      return sbuf;
    }
    if (isspace(c)) {
      ungetc(c, f_arr[ind]);
      sbuf[i] = 0;
      return sbuf;
    }
    if (!pdbuf || !pdsz) fatal_read(ind, _("Input element is too long"));
  } else {
    if (!pdbuf || !pdsz) fatal_CF(_("Invalid arguments"));
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
    if (c < ' ') fatal_read(ind, _("Invalid control character %d"), c);
    if (i + 1 >= dsz) {
      dsz *= 2;
      dbuf = (char*) xrealloc(dbuf, dsz);
    }
    dbuf[i++] = c;
    c = getc(f_arr[ind]);
  }
  if (c == EOF) {
    if (ferror(f_arr[ind])) {
      fatal_CF(_("%s: input error"), gettext(f_arr_names[ind]));
    }
  } else {
    ungetc(c, f_arr[ind]);
  }
  dbuf[i] = 0;
  *pdbuf = dbuf;
  *pdsz = dsz;
  return dbuf;
}
