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

const unsigned char *
xml_err_get_elem_name(const struct xml_tree *p)
{
  if (xml_err_spec && xml_err_spec->elem_map) {
    if (xml_err_spec->default_elem > 0
        && xml_err_spec->default_elem == p->tag)
      return p->name[0];
    return xml_err_spec->elem_map[p->tag];
  } else {
    static unsigned char buf[32];

    snprintf(buf, sizeof(buf), "elem %d", p->tag);
    return buf;
  }
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
