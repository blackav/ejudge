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
#include "expat_iface.h"

int
xml_err_attr_undefined_s(const struct xml_tree *p, const unsigned char *s_attr)
{
  if (xml_err_spec && xml_err_spec->elem_map && xml_err_spec->attr_map) {
    xml_err(p, "attribute \"%s\" is not defined in <%s>",
            s_attr, xml_err_get_elem_name(p));
  } else {
    xml_err(p, "attribute \"%s\" is not defined", s_attr);
  }
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
