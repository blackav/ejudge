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

#include <reuse/xalloc.h>

#include <ctype.h>

int
xml_empty_text(struct xml_tree *tree)
{
  unsigned char *p;

  if (!tree->text) return 0;
  for (p = tree->text; *p && isspace(*p); p++);
  if (*p) {
    xml_err(tree, "text is not allowed in <%s>",
            xml_err_elem_names[tree->tag]);
    return -1;
  }
  xfree(tree->text);
  tree->text = 0;
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
