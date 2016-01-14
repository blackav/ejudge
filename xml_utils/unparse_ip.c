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

const unsigned char *
xml_unparse_ip(ej_ip4_t ip)
{
  static char buf[64];

  /*
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
           ip >> 24, (ip >> 16) & 0xff,
           (ip >> 8) & 0xff, ip & 0xff);
  */
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
           ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
  return buf;
}

const unsigned char *
xml_unparse_ipv6(const ej_ip_t *p_addr)
{
  static char buf[64];

  if (!p_addr->ipv6_flag) {
    ej_ip4_t ip = p_addr->u.v4.addr;
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             ip & 0xff, (ip >> 8) & 0xff,
             (ip >> 16) & 0xff, (ip >> 24) & 0xff);
    /*
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
             p_addr->u.v4.addr >> 24, (p_addr->u.v4.addr >> 16) & 0xff,
             (p_addr->u.v4.addr >> 8) & 0xff, p_addr->u.v4.addr & 0xff);
    */
    return buf;
  }

  const unsigned short *data = (const unsigned short*) p_addr->u.v6.addr;
  char *out = buf;

  if (!data[0] && !data[1] && !data[2] && !data[3] && !data[4]
      && (!data[5] || data[5] == 0xffff)) {
    if (!data[5] && !data[6]) {
      if (!data[7]) {
        *out++ = ':';
        *out++ = ':';
        *out = 0;
        return buf;
      } else {
        sprintf(out, "::%x", (data[7] >> 8) | ((data[7] & 0xff) << 8));
        return buf;
      }
    }
    *out++ = ':';
    *out++ = ':';
    if (data[5]) {
      out += sprintf(out, "ffff:");
    }
    /*
    sprintf(out, "%d.%d.%d.%d",
            data[6] >> 8, data[6] & 0xff, data[7] >> 8, data[7] & 0xff);
    */
    sprintf(out, "%d.%d.%d.%d",
            data[6] & 0xff, data[6] >> 8, data[7] & 0xff, data[7] >> 8);
    return buf;
  }

  // find longest zero run
  int run_start = -1;
  int run_len = 0;
  int pos = 0;
  while (pos < 8) {
    if (data[pos]) {
      ++pos;
    } else {
      int pos2 = pos + 1;
      while (pos2 < 8 && !data[pos2]) ++pos2;
      if (pos2 - pos > 1 && pos2 - pos > run_len) {
        run_start = pos;
        run_len = pos2 - pos;
      }
      pos = pos2;
    }
  }

  if (run_start < 0) {
    for (int i = 0; i < 8; ++i) {
      out += sprintf(out, "%x", (data[i] >> 8) | ((data[i] & 0xff) << 8));
      if (i < 7) {
        *out++ = ':';
        *out = 0;
      }
    }
  } else {
    for (int i = 0; i < run_start; ++i) {
      out += sprintf(out, "%x", (data[i] >> 8) | ((data[i] & 0xff) << 8));
      if (i < run_start - 1) {
        *out++ = ':';
        *out = 0;
      }
    }
    *out++ = ':';
    *out++ = ':';
    *out = 0;
    for (int i = run_start + run_len; i < 8; ++i) {
      out += sprintf(out, "%x", (data[i] >> 8) | ((data[i] & 0xff) << 8));
      if (i < 7) {
        *out++ = ':';
        *out = 0;
      }
    }
  }

  return buf;
}
