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

const unsigned char *
xml_unparse_ip(ej_ip4_t ip)
{
  static char buf[64];

  snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
           ip >> 24, (ip >> 16) & 0xff,
           (ip >> 8) & 0xff, ip & 0xff);
  return buf;
}

#if 0
void
unparse_ipv6(FILE *out, unsigned short data[8])
{
  if (!data[0] && !data[1] && !data[2] && !data[3] && !data[4]
      && (!data[5] || data[5] == 0xffff)) {
    if (!data[5] && !data[6]) {
      if (!data[7]) {
        fprintf(out, "::");
        return;
      } else {
        fprintf(out, "::%x", (data[7] >> 8) | ((data[7] & 0xff) << 8));
        return;
      }
    }
    fprintf(out, "::");
    if (data[5]) {
      fprintf(out, "ffff:");
    }
    fprintf(out, "%d.%d.%d.%d",
            data[6] >> 8, data[6] & 0xff, data[7] >> 8, data[7] & 0xff);
    return;
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
      fprintf(out, "%x", (data[i] >> 8) | ((data[i] & 0xff) << 8));
      if (i < 7) {
        fprintf(out, ":");
      }
    }
  } else {
    for (int i = 0; i < run_start; ++i) {
      fprintf(out, "%x", (data[i] >> 8) | ((data[i] & 0xff) << 8));
      if (i < run_start - 1) {
        fprintf(out, ":");
      }
    }
    fprintf(out, "::");
    for (int i = run_start + run_len; i < 8; ++i) {
      fprintf(out, "%x", (data[i] >> 8) | ((data[i] & 0xff) << 8));
      if (i < 7) {
        fprintf(out, ":");
      }
    }
  }
}
#endif

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
