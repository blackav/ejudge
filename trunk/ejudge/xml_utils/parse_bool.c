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

#include "xml_utils.h"
#include "errlog.h"

#include <string.h>

int
xml_parse_bool(unsigned char const *path, int line, int column,
               unsigned char const *str, int *pv)
{
  if (!str) goto failed;
  if (!strcasecmp(str, "true")
      || !strcasecmp(str, "yes")
      || !strcasecmp(str, "1")) {
    if (pv) *pv = 1;
    return 1;
  }
  
  if (!strcasecmp(str, "false")
      || !strcasecmp(str, "no")
      || !strcasecmp(str, "0")) {
    if (pv) *pv = 0;
    return 0;
  }

 failed:
  if (path) {
    err("%s:%d:%d: invalid boolean value", path, line, column);
  } else if (line > 0) {
    err("%d:%d: invalid boolean value", line, column);
  }
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
