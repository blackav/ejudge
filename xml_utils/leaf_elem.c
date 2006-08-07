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
xml_leaf_elem(struct xml_tree *tree, unsigned char **value_addr, int move_flag,
              int empty_allowed_flag)
{
  if (tree->first) {
    xml_err_attrs(tree);
    return -1;
  }
  if (tree->first_down) {
    xml_err_nested_elems(tree);
    return -1;
  }
  if (!tree->text || (!empty_allowed_flag && !tree->text[0])) {
    if (xml_err_spec && xml_err_spec->elem_map) {
      xml_err(tree, "element <%s> is empty", xml_err_get_elem_name(tree));
    } else {
      xml_err(tree, "element is empty");
    }
    return -1;
  }
  if (*value_addr) {
    xml_err_elem_redefined(tree);
    return -1;
  }
  *value_addr = tree->text;
  if (move_flag) tree->text = 0;
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
