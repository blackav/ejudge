/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/pathutl.h"
#include "expat_iface.h"

int
xml_err_elem_not_allowed(const struct xml_tree *p)
{
  if (xml_err_spec && xml_err_spec->elem_map) {
    if (p->up) {
      xml_err(p, "element <%s> is not allowed in <%s>",
              xml_err_get_elem_name(p), xml_err_get_elem_name(p->up));
    } else {
      xml_err(p, "element <%s> is not allowed", xml_err_get_elem_name(p));
    }
  } else {
    xml_err(p, "element is not allowed");
  }
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
