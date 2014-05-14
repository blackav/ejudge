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

#include "ejudge/xml_utils.h"
#include "ejudge/pathutl.h"
#include "ejudge/expat_iface.h"

#include <stdarg.h>

int
xml_err_attr_invalid(const struct xml_attr *a)
{
  if (xml_err_spec && xml_err_spec->attr_map) {
    xml_err_a(a,"attribute \"%s\" value is invalid", xml_err_get_attr_name(a));
  } else {
    xml_err_a(a,"attribute value is invalid");
  }
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
