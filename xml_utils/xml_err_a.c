/* -*- c -*- */

/* Copyright (C) 2004-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/xml_utils.h"
#include "ejudge/errlog.h"
#include "ejudge/expat_iface.h"

#include <stdarg.h>

void
xml_err_a(const struct xml_attr *pos, const char *format, ...)
{
  unsigned char buf[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(buf, sizeof(buf), format, args);
  va_end(args);

  if (xml_err_file) {
    if (xml_err_path && pos) {
      fprintf(xml_err_file, "%s:%d:%d: %s\n", xml_err_path, pos->line, pos->column, buf);
    } else if (xml_err_path) {
      fprintf(xml_err_file, "%s: %s\n", xml_err_path, buf);
    } else if (pos) {
      fprintf(xml_err_file, "%d:%d: %s\n", pos->line, pos->column, buf);
    } else {
      fprintf(xml_err_file, "%s\n", buf);
    }
  } else {
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
}
