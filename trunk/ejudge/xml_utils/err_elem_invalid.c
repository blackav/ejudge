/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2006-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/expat_iface.h"

int
xml_err_elem_invalid(const struct xml_tree *p)
{
  if (xml_err_spec && xml_err_spec->elem_map) {
    xml_err(p, "value of element <%s> is invalid", xml_err_get_elem_name(p));
  } else {
    xml_err(p, "value of element is invalid");
  }
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
