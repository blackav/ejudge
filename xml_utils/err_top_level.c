/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ispras.ru> */

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
#include "pathutl.h"
#include "expat_iface.h"

int
xml_err_top_level(const struct xml_tree *tree, int elem)
{
  if (xml_err_spec && xml_err_spec->elem_map) {
    xml_err(tree, "top-level element must be <%s>",
            xml_err_spec->elem_map[elem]);
  } else {
    xml_err(tree, "invalid top-level element");
  }
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
