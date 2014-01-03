/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "c_errors.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

static int error_counter = 0;
static int warn_counter = 0;

void
c_err(pos_t *ppos, const char *format, ...)
{
  va_list args;
  unsigned char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (!ppos) {
    fprintf(stderr, "%s\n", buf);
  } else {
    fprintf(stderr, "%s:%d:%d: %s\n", pos_get_file(ppos),
            ppos->line, ppos->column, buf);
  }
  error_counter++;
}

void
c_warn(pos_t *ppos, const char *format, ...)
{
  va_list args;
  unsigned char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (!ppos) {
    fprintf(stderr, "warning: %s\n", buf);
  } else {
    fprintf(stderr, "%s:%d:%d: warning: %s\n", pos_get_file(ppos),
            ppos->line, ppos->column, buf);
  }
  warn_counter++;
}

int
c_err_get_count(void)
{
  return error_counter;
}

void
fancy_swerr(pos_t *ppos, char *file, int lineno, char *format, ...)
{
  va_list args;
  unsigned char buf[1024];

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (!ppos) {
    fprintf(stderr, "internal error: %s\n", buf);
  } else {
    fprintf(stderr, "%s:%d:%d: internal error: %s\n", pos_get_file(ppos),
            ppos->line, ppos->column, buf);
  }
  abort();
}
