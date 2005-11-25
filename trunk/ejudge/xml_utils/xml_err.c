/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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
#include "expat_iface.h"

#include <stdarg.h>

void
xml_err(const struct xml_tree *pos, const char *format, ...)
{
  unsigned char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (xml_err_path && pos) {
    err("%s:%d:%d: %s", xml_err_path, pos->line, pos->column, buf);
  } else if (xml_err_path) {
    err("%s: %s", xml_err_path, buf);
  } else if (pos) {
    err("%d:%d: %s", pos->line, pos->column, buf);
  } else {
    err("%s", buf);
  }
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
