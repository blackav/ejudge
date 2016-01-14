/* -*- c -*- */

/* Copyright (C) 2012-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include <errno.h>
#include <stdlib.h>

int
xml_attr_ulong(struct xml_attr *a, unsigned long *pval)
{
  unsigned long x = 0;
  char *eptr = NULL;
  static const char msg[] = "cannot parse unsigned long value";

  if (!a || !a->text) goto fail;
  errno = 0;
  x = strtoul(a->text, &eptr, 10);
  if (errno || *eptr) goto fail;
  *pval = x;
  return 0;

fail:
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
