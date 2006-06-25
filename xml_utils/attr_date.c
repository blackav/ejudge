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

#include <string.h>

int
xml_attr_date(struct xml_attn *attr, time_t *value_ptr)
{
  if (!attr->text) goto invalid_value;
  if (xml_parse_date(xml_err_path, attr->line, attr->column,
                     attr->text, value_ptr) < 0)
    goto invalid_value;
  return 0;

 invalid_value:
  xml_err_attr_invalid(attr);
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
