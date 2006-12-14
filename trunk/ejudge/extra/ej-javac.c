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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

static void fatal(const char *format, ...)
  __attribute__((noreturn, format(printf, 1, 2)));
static void
fatal(const char *format, ...)
{
  char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  fprintf(stderr, "fatal error: %s\n", buf);
  exit(1);
}

static char *
extract_class_name(const char *path)
{
  FILE *fin = 0;
  int c;

  if (!(fin = fopen(path, "r"))) fatal("cannot open input file `%s'", path);
  c = getc_unlocked(fin);
  while (c != EOF) {
    if (c == '/') {
      if ((c = getc_unlocked(fin)) == EOF) break;
      if (c == '/') {
        // line comment
        c = getc_unlocked(fin);
        while (c != EOF && c != '\n') c = getc_unlocked(fin);
      } else if (c == '*') {
        // block comment
        c = getc_unlocked(fin);
        while (c != EOF) {
          if (c == '*') {
            if ((c = getc_unlocked(fin)) == EOF) break;
            if (c == '/') break;
          } else {
            c = getc_unlocked(fin);
          }
        }
      }
    } else if (c == '\"') {
      // string
      c = getc_unlocked(fin);
      while (c != EOF) {
        if (c == '\"') break;
        if (c == '\\') {
          if ((c = getc_unlocked(fin)) == EOF) break;
        }
        c = getc_unlocked(fin);
      }
    } else if (c == '\"') {
    }
  }
  fclose(fin); fin = 0;
  return 0;
}

/*
 * Synopsis: ej-javac INFILE OUTFILE [JAVACRUN [JAVAVER]]
 *   default JAVACRUN: java
 *   default JAVAVER:  1.5
 */
int
main(int argc, char *argv[])
{
  

  return 0;
}
