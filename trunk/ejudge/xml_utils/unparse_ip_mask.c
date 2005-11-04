/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

const unsigned char *
xml_unparse_ip_mask(ej_ip_t addr, ej_ip_t mask)
{
  static unsigned char buf[64];
  int n;
  unsigned int k;

  if (mask == 0xffffffff) {
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (addr >> 24) & 0xff,
             (addr >> 16) & 0xff,
             (addr >> 8) & 0xff,
             addr & 0xff);
  } else if (mask == 0xffffff00) {
    snprintf(buf, sizeof(buf), "%u.%u.%u.",
             (addr >> 24) & 0xff,
             (addr >> 16) & 0xff,
             (addr >> 8) & 0xff);
  } else if (mask == 0xffff0000) {
    snprintf(buf, sizeof(buf), "%u.%u.",
             (addr >> 24) & 0xff,
             (addr >> 16) & 0xff);
  } else if (mask == 0xff000000) {
    snprintf(buf, sizeof(buf), "%u.",
             (addr >> 24) & 0xff);
  } else if (mask == 0 && addr == 0) {
    snprintf(buf, sizeof(buf), "0");
  } else {
    for (k = (unsigned) -1, n = 0; n <= 32 && k != mask; n++, k <<= 1);
    if (n <= 32) 
      snprintf(buf, sizeof(buf), "%u.%u.%u.%u/%d",
               (addr >> 24) & 0xff,
               (addr >> 16) & 0xff,
               (addr >> 8) & 0xff,
               addr & 0xff, 32 - n);
    else
      snprintf(buf, sizeof(buf), "0x%08x/0x%08x", addr, mask);
  }
  return buf;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
