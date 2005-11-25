/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

int
xml_parse_int_attr(struct xml_attn *a, int *pval)
{
  int x = 0, n = 0;

  if (!a || !a->text || sscanf(a->text, "%d %n", &x, &n) != 1 || a->text[n]) {
    if (xml_err_path) {
      err("%s:%d:%d: cannot parse integer value", xml_err_path, a->line, a->column);
    } else {
      err("%d:%d: cannot parse integer value", a->line, a->column);
    }
    return -1;
  }
  *pval = x;
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
