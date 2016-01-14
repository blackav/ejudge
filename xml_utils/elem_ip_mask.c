/* -*- c -*- */

/* Copyright (C) 2004-2016 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/expat_iface.h"

#include <string.h>

int
xml_elem_ipv6_mask(
        struct xml_tree *tree,
        ej_ip_t *addr_ptr,
        ej_ip_t *mask_ptr)
{
  return xml_parse_ipv6_mask(NULL, NULL, tree->line, tree->column,
                             tree->text, addr_ptr, mask_ptr);
}
