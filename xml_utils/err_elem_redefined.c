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
#include "ejudge/pathutl.h"
#include "ejudge/expat_iface.h"

int
xml_err_elem_redefined(const struct xml_tree *p)
{
  if (xml_err_spec && xml_err_spec->elem_map) {
    if (!p->up) {
      xml_err(p, "element <%s> already defined", xml_err_get_elem_name(p));
    } else {
      xml_err(p, "element <%s> already defined in <%s>",
              xml_err_get_elem_name(p), xml_err_get_elem_name(p->up));
    }
  } else {
    xml_err(p, "element already defined");
  }
  return -1;
}
