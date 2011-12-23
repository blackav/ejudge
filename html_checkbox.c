/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007-2011 Alexander Chernov <cher@ejudge.ru> */

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

unsigned char *
html_checkbox(
        unsigned char *buf,
        size_t size,
        const unsigned char *var_name,
        const unsigned char *value,
        int is_checked)
{
  const unsigned char *ch = "";
  unsigned char valbuf[1024];

  if (is_checked) ch = " checked=\"checked\"";
  valbuf[0] = 0;
  if (value) {
    snprintf(valbuf, sizeof(valbuf), " value=\"%s\"", value);
  }
  snprintf(buf, size, "<input type=\"checkbox\" name=\"%s\"%s%s/>", var_name, valbuf, ch);
  return buf;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list" "fd_set" "DIR")
 * End:
 */
