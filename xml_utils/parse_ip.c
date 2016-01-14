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
#include "ejudge/errlog.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

void
xml_msg(FILE *log_f,
        unsigned char const *path,
        int line,
        int column,
        const char *format,
        ...)
{
  char msg[1024];
  va_list args;

  va_start(args, format);
  vsnprintf(msg, sizeof(msg), format, args);
  va_end(args);

  if (line > 0) {
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
}

int
xml_parse_ip(
        FILE *log_f,
        unsigned char const *path,
        int line,
        int column,
        unsigned char const *s,
        ej_ip4_t *pip)
{
  unsigned int b1 = 0, b2 = 0, b3 = 0, b4 = 0;
  int n = 0;
  unsigned long ip;

  if (!s || sscanf(s, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || s[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
#if !defined PYTHON
    xml_msg(log_f, path, line, column, "invalid IP-address");
#endif
    return -1;
  }
  //ip = b1 << 24 | b2 << 16 | b3 << 8 | b4;
  ip = b4 << 24 | b3 << 16 | b2 << 8 | b1;
  *pip = ip;
  return 0;
}

#define fail() do { return -__LINE__; } while (0)

static int
read_hex(const unsigned char **p_ptr, const unsigned char *eptr)
{
  const unsigned char *ptr = *p_ptr;
  if (ptr >= eptr || !isxdigit(*ptr)) fail();
  unsigned int w = 0;
  for (;ptr < eptr && isxdigit(*ptr) && w < 0x10000; ++ptr) {
    unsigned d = 0;
    if (*ptr >= '0' && *ptr <= '9') {
      d = *ptr - '0';
    } else if (*ptr >= 'A' && *ptr <= 'F') {
      d = *ptr - 'A' + 10;
    } else if (*ptr >= 'a' && *ptr <= 'f') {
      d = *ptr - 'a' + 10;
    } else {
      *p_ptr = ptr;
      fail();
    }
    w = (w << 4) | d;
  }
  *p_ptr = ptr;
  if (w >= 0x10000) {
    fail();
  }
  w = ((w & 0xff) << 8) | (w >> 8);
  return w;
}

int
xml_do_parse_ipv6(
        const unsigned char *bptr,
        const unsigned char *eptr,
        ej_ip_t *p_addr)
{
  while (bptr < eptr && isspace(*bptr)) ++bptr;
  while (bptr < eptr && isspace(eptr[-1])) --eptr;
  if (bptr >= eptr) fail();

  memset(p_addr, 0, sizeof(*p_addr));
  int addrsize = 8;
  unsigned short *addr = (unsigned short*) p_addr->u.v6.addr;

  int dcnt = 0;
  const unsigned char *last_col = NULL;
  const unsigned char *sep = NULL;
  const unsigned char *ptr = (const unsigned char *) bptr;
  for (; ptr < eptr; ++ptr) {
    if (isxdigit(*ptr)) {
      // nothing
    } else if (*ptr == ':') {
      if (ptr < eptr && ptr[1] == ':') {
        if (sep) fail();
        sep = ptr;
        ++ptr;
        last_col = ptr;
      } else {
        last_col = ptr;
      }
    } else if (*ptr == '.') {
      ++dcnt;
    } else {
      // invalid character
      fail();
    }
  }

  p_addr->ipv6_flag = 1;
  if (dcnt > 0) {
    if (!last_col) {
      ptr = bptr;
    } else {
      ptr = last_col + 1;
    }

    // A.B.C.D -> net(A.B.C.D) -> host(D.C.B.A)
    unsigned int value = 0;
    int shift = 0;
    for (int i = 0; i < 4; ++i) {
      if (ptr >= eptr) fail();
      if (!isdigit(*ptr)) fail();
      unsigned int b = 0;
      while (ptr < eptr && isdigit(*ptr) && b < 256) {
        b = b * 10 + (*ptr - '0');
        ++ptr;
      }
      if (b >= 256) fail();
      value |= b << shift;
      shift += 8;
      if (i < 3) {
        if (ptr >= eptr || *ptr != '.') fail();
        ++ptr;
      }
    }
    addr[6] = value & 0xffff;
    addr[7] = value >> 16;
    if (!last_col) {
      p_addr->ipv6_flag = 0;
      return 0;
    }
    if (sep + 1 != last_col) {
      // remove the last :
      eptr = last_col;
    } else {
      // preserve the last ::
      eptr = last_col + 1;
    }
    addrsize = 6;
  }

  if (!sep) {
    ptr = bptr;
    if (ptr >= eptr) fail();
    for (int i = 0; i < addrsize; ++i) {
      int w = read_hex(&ptr, eptr);
      if (w < 0) return w;
      addr[i] = w;
      if (i < addrsize - 1) {
        if (ptr >= eptr || *ptr != ':') fail();
        ++ptr;
      }
    }
    return 0;
  }

  // process the first part to '::'
  const unsigned char *ep1 = sep;
  int pos1 = 0;
  if (bptr < ep1) {
    ptr = bptr;
    while (ptr < ep1) {
      if (pos1 >= addrsize) fail();
      int w = read_hex(&ptr, ep1);
      if (w < 0) return w;
      addr[pos1++] = w;
      if (ptr < ep1) {
        if (*ptr != ':') fail();
        ++ptr;
      }
    }
  }

  // process the last part back to '::'
  bptr = sep + 2;
  if (bptr >= eptr) {
    return 0;
  }

  int pos2 = addrsize - 1;
  for (ptr = bptr; ptr < eptr; ++ptr) {
    if (*ptr == ':') --pos2;
  }
  if (pos1 > pos2) fail();

  ptr = bptr;
  while (ptr < eptr) {
    if (pos2 >= addrsize) fail();
    int w = read_hex(&ptr, eptr);
    if (w < 0) return w;
    addr[pos2++] = w;
    if (ptr < eptr) {
      if (*ptr != ':') fail();
      ++ptr;
    }
  }
  return 0;
}

int
xml_parse_ipv6_2(
        unsigned char const *s,
        ej_ip_t *p_addr)
{
  if (!s) return -1;
  return xml_do_parse_ipv6(s, s + strlen(s), p_addr);
}

int
xml_parse_ipv6(
        FILE *log_f,
        unsigned char const *path,
        int line,
        int column,
        unsigned char const *s,
        ej_ip_t *p_addr)
{
  int r = xml_do_parse_ipv6(s, s + strlen(s), p_addr);
  if (r < 0) {
    xml_msg(log_f, path, line, column, "invalid IP-address");
    return r;
  }
  return 0;
}

const ej_ip_t *
xml_make_ipv6(ej_ip4_t addr, ej_ip_t *p_addr)
{
  memset(p_addr, 0, sizeof(*p_addr));
  p_addr->u.v4.addr = addr;
  return p_addr;
}

ej_ip4_t
xml_make_ipv4(const ej_ip_t *p_addr)
{
  if (p_addr->ipv6_flag) {
    return 0x7f00007f;
  } else {
    return p_addr->u.v4.addr;
  }
}

int
ipv6cmp(const ej_ip_t *pip1, const ej_ip_t *pip2)
{
  if (!pip1 && !pip2) return 0;
  if (!pip1) return -1;
  if (!pip2) return 1;
  if (!pip1->ipv6_flag && !pip2->ipv6_flag) {
    if (pip1->u.v4.addr < pip2->u.v4.addr) return -1;
    if (pip1->u.v4.addr > pip2->u.v4.addr) return 1;
    return 0;
  }
  if (!pip1->ipv6_flag) return -1;
  if (!pip2->ipv6_flag) return 1;
  return memcmp(pip1->u.v6.addr, pip2->u.v6.addr, sizeof(pip1->u.v6.addr));
}

int
ipv6_match_mask(const ej_ip_t *net, const ej_ip_t *mask, const ej_ip_t *addr)
{
  if (net->ipv6_flag != mask->ipv6_flag || net->ipv6_flag != addr->ipv6_flag)
    return 0;
  if (!addr->ipv6_flag) {
    return (addr->u.v4.addr & mask->u.v4.addr) == net->u.v4.addr;
  }
  ej_ip_t tmp = *addr;
  for (int i = 0; i < 16; ++i) {
    tmp.u.v6.addr[i] &= mask->u.v6.addr[i];
  }
  return memcmp(tmp.u.v6.addr, net->u.v6.addr, 16) == 0;
}

int
ipv6_is_empty(const ej_ip_t *p_ip)
{
  if (!p_ip) return 1;
  if (p_ip->ipv6_flag) {
    for (int i = 0; i < 16; ++i) {
      if (p_ip->u.v6.addr[i])
        return 0;
    }
    return 1;
  }
  return !p_ip->u.v4.addr;
}
