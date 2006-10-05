/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "mischtml.h"

#include <stdio.h>
#include <stdarg.h>

unsigned char *
html_hyperref(unsigned char *buf, size_t size,
              ej_cookie_t session_id,
              const unsigned char *self_url,
              const unsigned char *extra_args,
              const char *format, ...)
{
  unsigned char b[1024] = { 0 };
  va_list args;

  if (format && *format) {
    va_start(args, format);
    vsnprintf(b, sizeof(b), format, args);
    va_end(args);
  }

  if (extra_args && *extra_args && *b) {
    snprintf(buf, size, "<a href=\"%s?SID=%016llx&%s&%s\">",
             self_url, session_id, extra_args, b);
  } else if (extra_args && *extra_args) {
    snprintf(buf, size, "<a href=\"%s?SID=%016llx&%s\">",
             self_url, session_id, extra_args);
  } else if (*b) {
    snprintf(buf, size, "<a href=\"%s?SID=%016llx&%s\">", self_url, session_id, b);
  } else {
    snprintf(buf, size, "<a href=\"%s?SID=%016llx\">", self_url, session_id);
  }

  return buf;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
