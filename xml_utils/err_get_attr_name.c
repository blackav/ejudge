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
xml_err_get_attr_name(const struct xml_attr *a)
{
  if (xml_err_spec && xml_err_spec->attr_map) {
    if (xml_err_spec->default_attr > 0
        && xml_err_spec->default_attr == a->tag)
      return a->name[0];
    return xml_err_spec->attr_map[a->tag];
  } else {
    static unsigned char buf[32];

    snprintf(buf, sizeof(buf), "attr %d", a->tag);
    return buf;
  }
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
