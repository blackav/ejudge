/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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

void
xml_err_top_level(const struct xml_tree *tree, int elem)
{
  xml_err(tree, "top-level element must be <%s>", xml_err_elem_names[elem]);
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
