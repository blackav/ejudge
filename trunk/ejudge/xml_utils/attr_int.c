/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/errlog.h"
#include "ejudge/expat_iface.h"

int
xml_attr_int(struct xml_attr *a, int *pval)
{
  int x = 0, n = 0;
  static const char msg[] = "cannot parse integer value";

  if (!a || !a->text || sscanf(a->text, "%d %n", &x, &n) != 1 || a->text[n]) {
    if (xml_err_file) {
      if (xml_err_path) {
        fprintf(xml_err_file, "%s:%d:%d: %s\n", xml_err_path, a->line, a->column, msg);
      } else {
        fprintf(xml_err_file, "%d:%d: %s\n", a->line, a->column, msg);
      }
    } else {
      if (xml_err_path) {
        err("%s:%d:%d: %s", xml_err_path, a->line, a->column, msg);
      } else {
        err("%d:%d: %s", a->line, a->column, msg);
      }
    }
    return -1;
  }
  *pval = x;
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
