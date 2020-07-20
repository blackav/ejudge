/* -*- mode: c -*- */

/* Copyright (C) 2006-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/mischtml.h"

#include <stdio.h>
#include <stdarg.h>

unsigned char *
html_input_text(unsigned char *buf, size_t size,
                const unsigned char *var_name,
                int text_size,
                int is_disabled,
                const char *format,
                ...)
{
  va_list args;
  unsigned char bformat[1024] = { 0 };
  unsigned char bsize[128];
  unsigned char bname[128];
  const unsigned char *dis = "";

  if (is_disabled) dis = " disabled=\"disabled\"";

  if (format && *format) {
    va_start(args, format);
    vsnprintf(bformat, sizeof(bformat), format, args);
    va_end(args);
  }

  bsize[0] = 0;
  if (text_size > 0) snprintf(bsize, sizeof(bsize), " size=\"%d\"", text_size);
  bname[0] = 0;
  if (var_name) snprintf(bname, sizeof(bname), " name=\"%s\"", var_name);

  snprintf(buf, size, "<input type=\"text\"%s%s%s value=\"%s\"/>",
           bsize, bname, dis, bformat);
  return buf;
}

unsigned char *
html_input_text_js(
        unsigned char *buf,
        size_t size,
        const unsigned char *var_name,
        int text_size,
        const unsigned char *onchange,
        const char *format,
        ...)
{
  va_list args;
  unsigned char bformat[1024] = { 0 };
  unsigned char bsize[128];
  unsigned char bname[128];
  unsigned char bonchange[128];

  if (format && *format) {
    va_start(args, format);
    vsnprintf(bformat, sizeof(bformat), format, args);
    va_end(args);
  }

  bsize[0] = 0;
  if (text_size > 0) snprintf(bsize, sizeof(bsize), " size=\"%d\"", text_size);
  bname[0] = 0;
  if (var_name) snprintf(bname, sizeof(bname), " name=\"%s\"", var_name);
  bonchange[0] = 0;
  if (onchange) snprintf(bonchange, sizeof(bonchange), " onchange=\"%s\"", onchange);

  snprintf(buf, size, "<input type=\"text\"%s%s%s value=\"%s\"/>",
           bsize, bname, bonchange, bformat);
  return buf;
}
