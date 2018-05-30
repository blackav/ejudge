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
#include "ejudge/errlog.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>

int
xml_parse_ip_mask(
        FILE *log_f,
        const unsigned char *path,
        int line,
        int column,
        const unsigned char *s,
        ej_ip4_t *p_addr,
        ej_ip4_t *p_mask)
{
  int n = 0;
  unsigned int b1 = 0, b2 = 0, b3 = 0, b4 = 0, b5 = 0;
  const char msg[] = "invalid IP-address";

  if (!s) goto failed;
  if (!strcmp(s, "0")) {
    *p_addr = 0;
    *p_mask = 0;
  } else if (sscanf(s, "%u.%u.%u.%u/%u %n", &b1, &b2, &b3, &b4, &b5, &n) == 5
      && !s[n] && b1 <= 255 && b2 <= 255 && b3 <= 255 && b4 <= 255 && b5 <= 32) {
    *p_addr = b1 | b2 << 8 | b3 << 16 | b4 << 24;
    //*p_mask = ((unsigned int) -1) << (32 - b5);
    *p_mask = ((unsigned int) -1) >> (32 - b5);
  } else if (sscanf(s, "%u.%u.%u.%u %n", &b1, &b2, &b3, &b4, &n) == 4
             && !s[n] && b1 <= 255 && b2 <= 255 && b3 <= 255 && b4 <= 255) {
    *p_addr = b1 | b2 << 8 | b3 << 16 | b4 << 24;
    *p_mask = 0xFFFFFFFF;
  } else if (sscanf(s, "%u.%u.%u. %n", &b1, &b2, &b3, &n) == 3
             && !s[n] && b1 <= 255 && b2 <= 255 && b3 <= 255) {
    *p_addr = b1 | b2 << 8 | b3 << 16;
    *p_mask = 0x00FFFFFF;
  } else if (sscanf(s, "%u.%u. %n", &b1, &b2, &n) == 2
             && !s[n] && b1 <= 255 && b2 <= 255) {
    *p_addr = b1 | b2 << 8;
    *p_mask = 0x0000FFFF;
  } else if (sscanf(s, "%u. %n", &b1, &n) == 1 && !s[n] && b1 <= 255) {
    *p_addr = b1;
    *p_mask = 0x000000FF;
  } else {
    goto failed;
  }

  return 0;

 failed:
  if (line >= 0) {
    if (log_f) {
      if (path) {
        fprintf(log_f, "%s:%d:%d: %s\n", path, line, column, msg);
      } else {
        fprintf(log_f, "%d:%d: %s\n", line, column, msg);
      }
    } else {
      if (path) {
        err("%s:%d:%d: %s", path, line, column, msg);
      } else {
        err("%d:%d: %s", line, column, msg);
      }
    }
  }
  return -1;
}

const ej_ip_t *
xml_make_ipv6(ej_ip4_t addr, ej_ip_t *p_addr);

int
xml_parse_ipv6_mask(
        FILE *log_f,
        const unsigned char *path,
        int line,
        int column,
        const unsigned char *s,
        ej_ip_t *p_addr,
        ej_ip_t *p_mask)
{
  if (!strchr(s, ':')) {
    ej_ip4_t addr4, mask4;
    int r = xml_parse_ip_mask(log_f, path, line, column, s, &addr4, &mask4);
    if (r < 0) return r;
    xml_make_ipv6(addr4, p_addr);
    xml_make_ipv6(mask4, p_mask);
    return 0;
  }

  const unsigned char *slash = strchr(s, '/');
  if (!slash) {
    int r = xml_parse_ipv6(log_f, path, line, column, s, p_addr);
    if (r < 0) return r;
    if (!p_addr->ipv6_flag) {
      xml_msg(log_f, path, line, column, "IPv6 expected");
      return -1;
    }
    memset(p_mask, 0, sizeof(*p_mask));
    p_mask->ipv6_flag = 1;
    memset(p_mask->u.v6.addr, 0xff, sizeof(p_mask->u.v6.addr));
    return 0;
  }

  int r = xml_do_parse_ipv6(s, slash - 1, p_addr);
  if (r < 0) {
    xml_msg(log_f, path, line, column, "Invalid IPv6 address");
    return -1;
  }
  char *eptr = NULL;
  errno = 0;
  int m = strtol(slash + 1, &eptr, 10);
  if (errno || m < 0 || m > 128) {
    xml_msg(log_f, path, line, column, "Invalid mask");
    return -1;
  }
  while (isspace(*eptr)) ++eptr;
  if (*eptr) {
    xml_msg(log_f, path, line, column, "Invalid mask");
    return -1;
  }
  memset(p_mask, 0, sizeof(*p_mask));
  p_mask->ipv6_flag = 1;
  unsigned char *pb = p_mask->u.v6.addr;
  while (m >= 8) {
    *pb++ = 0xff;
    m -= 8;
  }
  if (m > 0) {
    *pb++ = 0xffffff00 >> m;
  }
  return 0;
}
