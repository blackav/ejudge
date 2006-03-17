/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ispras.ru> */

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

#include "parsecfg.h"

#include <stdio.h>
#include <ctype.h>

char *
sarray_unparse(char **a)
{
  char *out_txt = 0;
  unsigned char *s, *q;
  size_t out_len = 0;
  FILE *out;
  int i;

  out = open_memstream(&out_txt, &out_len);
  if (a) {
    for (i = 0; a[i]; i++) {
      // VAR[=[value]]
      if (i > 0) fprintf(out, " ");
      s = a[i];
      while (*s && (isalnum(*s) || *s == '_')) s++;
      if (*s && *s != '=') {
        // invalid variable name
        fprintf(out, "invalid_variable_name=");
        s = a[i];
      } else if (*s == '=' && (char*) s == a[i]) {
        fprintf(out, "empty_variable_name=");
        s++;
      } else {
        s = a[i];
        while (*s && *s != '=') putc_unlocked(*s++, out);
        if (*s == '=') putc_unlocked(*s++, out);
      }
      q = s;
      while (*q && *q > ' ' && *q < 127 && *q != '\"' && *q != '\\') q++;
      if (*q) {
        putc_unlocked('\"', out);
        for (; *s; s++) {
          if (*s < ' ') {
            fprintf(out, "\\%03o", *s);
          } else if (*s == '\"') {
            fputs("\\\"", out);
          } else if (*s == '\\') {
            fputs("\\\\", out);
          } else {
            putc_unlocked(*s, out);
          }
        }
        putc_unlocked('\"', out);
      } else {
        while (*s) putc_unlocked(*s++, out);
      }
    }
  }
  fclose(out);
  return out_txt;
}

char *
sarray_unparse_2(char **a)
{
  char *out_txt = 0;
  unsigned char *s, *q;
  size_t out_len = 0;
  FILE *out;
  int i;

  out = open_memstream(&out_txt, &out_len);
  if (a) {
    for (i = 0; a[i]; i++) {
      // VAR[=[value]]
      if (i > 0) fprintf(out, " ");
      s = a[i];
      q = s;
      while (*q && *q > ' ' && *q < 127 && *q != '\"' && *q != '\\') q++;
      if (*q) {
        putc_unlocked('\"', out);
        for (; *s; s++) {
          if (*s < ' ') {
            fprintf(out, "\\%03o", *s);
          } else if (*s == '\"') {
            fputs("\\\"", out);
          } else if (*s == '\\') {
            fputs("\\\\", out);
          } else {
            putc_unlocked(*s, out);
          }
        }
        putc_unlocked('\"', out);
      } else {
        while (*s) putc_unlocked(*s++, out);
      }
    }
  }
  fclose(out);
  return out_txt;
}
