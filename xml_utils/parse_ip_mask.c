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
#include "pathutl.h"

#include <string.h>

int
xml_parse_ip_mask(const unsigned char *path, int line, int column,
                  const unsigned char *s,
                  ej_ip_t *p_addr, ej_ip_t *p_mask)
{
  int n;
  unsigned int b1, b2, b3, b4, b5;

  if (!s) goto failed;
  if (!strcmp(s, "0")) {
    *p_addr = 0;
    *p_mask = 0;
  } else if (sscanf(s, "%u.%u.%u.%u/%u %n", &b1, &b2, &b3, &b4, &b5, &n) == 5
      && !s[n] && b1 <= 255 && b2 <= 255 && b3 <= 255 && b4 <= 255 && b5 <= 32) {
    *p_addr = b1 << 24 | b2 << 16 | b3 << 8 | b4;
    *p_mask = ((unsigned int) -1) << (32 - b5);
  } else if (sscanf(s, "%u.%u.%u.%u %n", &b1, &b2, &b3, &b4, &n) == 4
             && !s[n] && b1 <= 255 && b2 <= 255 && b3 <= 255 && b4 <= 255) {
    *p_addr = b1 << 24 | b2 << 16 | b3 << 8 | b4;
    *p_mask = 0xFFFFFFFF;
  } else if (sscanf(s, "%u.%u.%u. %n", &b1, &b2, &b3, &n) == 3
             && !s[n] && b1 <= 255 && b2 <= 255 && b3 <= 255) {
    *p_addr = b1 << 24 | b2 << 16 | b3 << 8;
    *p_mask = 0xFFFFFF00;
  } else if (sscanf(s, "%u.%u. %n", &b1, &b2, &n) == 2
             && !s[n] && b1 <= 255 && b2 <= 255) {
    *p_addr = b1 << 24 | b2 << 16;
    *p_mask = 0xFFFF0000;
  } else if (sscanf(s, "%u. %n", &b1, &n) == 1 && !s[n] && b1 <= 255) {
    *p_addr = b1 << 24;
    *p_mask = 0xFF000000;
  } else {
    goto failed;
  }

  return 0;

 failed:
  if (line >= 0) {
    if (path) {
      err("%s:%d:%d: invalid IP-address", path, line, column);
    } else {
      err("%d:%d: invalid IP-address", line, column);
    }
  }
  return -1;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
