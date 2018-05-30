/* -*- c -*- */

/* Copyright (C) 2005-2016 Alexander Chernov <cher@ejudge.ru> */

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

const unsigned char *
xml_unparse_ip_mask(ej_ip4_t addr, ej_ip4_t mask)
{
  static unsigned char buf[64];
  int n;
  unsigned int k;

  if (mask == 0xffffffff) {
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             (addr) & 0xff,
             (addr >> 8) & 0xff,
             (addr >> 16) & 0xff,
             (addr >> 24) & 0xff);
  } else if (mask == 0xffffff00) {
    snprintf(buf, sizeof(buf), "%u.%u.%u.",
             (addr) & 0xff,
             (addr >> 8) & 0xff,
             (addr >> 16) & 0xff);
  } else if (mask == 0xffff0000) {
    snprintf(buf, sizeof(buf), "%u.%u.",
             (addr) & 0xff,
             (addr >> 8) & 0xff);
  } else if (mask == 0xff000000) {
    snprintf(buf, sizeof(buf), "%u.",
             (addr) & 0xff);
  } else if (mask == 0 && addr == 0) {
    snprintf(buf, sizeof(buf), "0");
  } else {
    for (k = (unsigned) -1, n = 0; n <= 32 && k != mask; n++, k >>= 1);
    if (n <= 32)
      snprintf(buf, sizeof(buf), "%u.%u.%u.%u/%d",
               (addr) & 0xff,
               (addr >> 8) & 0xff,
               (addr >> 16) & 0xff,
               (addr >> 24) & 0xff, 32 - n);
    else
      snprintf(buf, sizeof(buf), "0x%08x/0x%08x", addr, mask);
  }
  return buf;
}

const unsigned char *
xml_unparse_ipv6_mask(const ej_ip_t *p_addr, const ej_ip_t *p_mask)
{
  static unsigned char buf[64];

  if (!p_addr->ipv6_flag && !p_mask->ipv6_flag) {
    return xml_unparse_ip_mask(p_addr->u.v4.addr, p_mask->u.v4.addr);
  }
  int m = 0;
  const unsigned char *pb = p_mask->u.v6.addr;
  int cnt = 16;
  while (*pb == 0xff && cnt > 0) {
    m += 8;
    ++pb;
    --cnt;
  }
  if (*pb && cnt > 0) {
    switch (*pb) {
    case 0xff:
      ++m;
    case 0xfe:
      ++m;
    case 0xfc:
      ++m;
    case 0xf8:
      ++m;
    case 0xf0:
      ++m;
    case 0xe0:
      ++m;
    case 0xc0:
      ++m;
    case 0x80:
      ++m;
    }
  }
  snprintf(buf, sizeof(buf), "%s/%d", xml_unparse_ipv6(p_addr), m);
  return buf;
}
