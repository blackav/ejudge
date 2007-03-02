/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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
html_input_password(
	unsigned char *buf,
        size_t size,
        const unsigned char *var_name,
        int text_size,
        const char *format,
        ...)
{
  va_list args;
  unsigned char bformat[1024] = { 0 };
  unsigned char bsize[128];
  unsigned char bname[128];

  if (format && *format) {
    va_start(args, format);
    vsnprintf(bformat, sizeof(bformat), format, args);
    va_end(args);
  }

  bsize[0] = 0;
  if (text_size > 0) snprintf(bsize, sizeof(bsize), " size=\"%d\"", text_size);
  bname[0] = 0;
  if (var_name) snprintf(bname, sizeof(bname), " name=\"%s\"", var_name);

  snprintf(buf, size, "<input type=\"password\"%s%s value=\"%s\"/>",
           bsize, bname, bformat);
  return buf;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
