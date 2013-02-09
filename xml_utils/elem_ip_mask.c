/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004-2013 Alexander Chernov <cher@ejudge.ru> */

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
xml_elem_ip_mask(struct xml_tree *tree,
                 unsigned int *addr_ptr, unsigned int *mask_ptr)
{
  unsigned int b1, b2, b3, b4;
  int n;

  if (!strcmp(tree->text, "0")) {
    *addr_ptr = 0;
    *mask_ptr = 0;
    return 0;
  }
  if (sscanf(tree->text, "%u.%u.%u.%u %n", &b1, &b2, &b3, &b4, &n) == 4
      && !tree->text[n] && b1 <= 255 && b2 <= 255 && b3 <= 255 && b4 <= 255) {
    *addr_ptr = b1 << 24 | b2 << 16 | b3 << 8 | b4;
    *mask_ptr = 0xFFFFFFFF;
    return 0;
  }
  if (sscanf(tree->text, "%u.%u.%u. %n", &b1, &b2, &b3, &n) == 3
      && !tree->text[n] && b1 <= 255 && b2 <= 255 && b3 <= 255) {
    *addr_ptr = b1 << 24 | b2 << 16 | b3 << 8;
    *mask_ptr = 0xFFFFFF00;
    return 0;
  }
  if (sscanf(tree->text, "%u.%u. %n", &b1, &b2, &n) == 2
      && !tree->text[n] && b1 <= 255 && b2 <= 255) {
    *addr_ptr = b1 << 24 | b2 << 16;
    *mask_ptr = 0xFFFF0000;
    return 0;
  }
  if (sscanf(tree->text, "%u. %n", &b1, &n) == 1
      && !tree->text[n] && b1 <= 255) {
    *addr_ptr = b1 << 24;
    *mask_ptr = 0xFF000000;
    return 0;
  }

  xml_err(tree, "invalid IP-address");
  return -1;
}

int
xml_elem_ipv6_mask(
        struct xml_tree *tree,
        ej_ip_t *addr_ptr,
        ej_ip_t *mask_ptr)
{
  return xml_parse_ipv6_mask(NULL, NULL, tree->line, tree->column,
                             tree->text, addr_ptr, mask_ptr);
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
