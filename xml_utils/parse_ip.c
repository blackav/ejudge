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
#include "errlog.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

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
  const char msg[] = "invalid IP-address";

  if (!s || sscanf(s, "%d.%d.%d.%d%n", &b1, &b2, &b3, &b4, &n) != 4
      || s[n] || b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255) {
#if !defined PYTHON
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
#endif
    return -1;
  }
  ip = b1 << 24 | b2 << 16 | b3 << 8 | b4;
  *pip = ip;
  return 0;
}

#define fail() do { return -__LINE__; } while (0)

/*
// parse states
enum { FIRST_GROUP, IPV4_GROUP, IPV4_NETSIZE, IPV6_EMPTY_FIRST_GROUP, IPV6_GROUP };

#define FINISH_IPV4_GROUP() do { \
  if (buf_ind <= 0) fail(); \
  if (nz_ind < 0) { \
    ipv4_b[ipv4_ind++] = 0; \
  } else if (has_hex) { \
    fail(); \
  } else if (buf_ind - nz_ind > 4) { \
    fail(); \
  } else { \
    buf[buf_ind] = 0; \
    errno = 0; \
    ipv4_b[ipv4_ind] = strtol(buf, NULL, 10); \
    if (ipv4_b[ipv4_ind] < 0 || ipv4_b[ipv4_ind] >= 256) fail(); \
    ++ipv4_ind; \
  } \
  } while (0)

#define FINISH_IPV6_GROUP() do { \
  if (nz_ind < 0) { \
    ipv6_fb[ipv6_fb_ind++] = 0; \
  } else if (buf_ind - nz_ind > 5) { \
    fail(); \
  } else { \
    buf[buf_ind] = 0; \
    errno = 0; \
    ipv6_fb[ipv6_fb_ind] = strtol(buf, NULL, 16); \
    if (ipv6_fb[ipv6_fb_ind] < 0 || ipv6_fb[ipv6_fb_ind] > 0xffff) fail(); \
    ++ipv6_fb_ind; \
  } \
  } while (0)



static int
do_parse_ip6(const unsigned char *s, ej_ip6_t *pip)
{
  if (!s) fail(); // NULL address
  const unsigned char *b = s;
  while (isspace(*b)) ++b;
  if (!*b) fail(); // empty address
  const unsigned char *e = strchr(s, 0);
  while (isspace(e[-1])) --e;
  // [b, e) is the actual string
  unsigned char *buf = alloca(e - b + 1);
  int buf_ind = 0;
  int nz_ind = -1;
  buf[buf_ind] = 0;
  int has_hex = 0;
  int state = FIRST_GROUP;
  int ipv4_b[4] = { -1, -1, -1, -1 };
  int ipv4_ind = 0;
  int netsize = 0;
  int ipv6_fb[8];
  int ipv6_fb_ind = 0;
  int ipv6_rb[8];
  int ipv6_rb_ind = 0;
  const unsigned char *q = b;

  (void) ipv6_rb_ind;
  (void) ipv6_rb;

  for (; q != e; ++q) {
    if (*q == '.') {
      if (state == FIRST_GROUP) {
        // beginning of IPv4
        FINISH_IPV4_GROUP();
        state = IPV4_GROUP;
      } else if (state == IPV4_GROUP) {
        if (ipv4_ind > 3) fail();
        FINISH_IPV4_GROUP();
      } else if (state == IPV4_NETSIZE) {
        fail();
      } else if (state == IPV6_EMPTY_FIRST_GROUP) {
        fail();
      } else if (state == IPV6_GROUP) {
        // ???
      }
      buf_ind = 0;
      nz_ind = -1;
      has_hex = 0;
    } else if (*q == ':') {
      if (state == FIRST_GROUP) {
        // beginning of IPv6
        if (buf_ind <= 0) {
          state = IPV6_EMPTY_FIRST_GROUP;
        } else {
          FINISH_IPV6_GROUP();
          state = IPV6_GROUP;
        }
      } else if (state == IPV4_GROUP) {
        fail();
      } else if (state == IPV4_NETSIZE) {
        fail();
      } else if (state == IPV6_EMPTY_FIRST_GROUP) {
      } else if (state == IPV6_GROUP) {
        if (ipv6_fb_ind >= 8) fail();
        if (buf_ind <= 0) {
          // ???
        } else {
          FINISH_IPV6_GROUP();
        }
      }
      buf_ind = 0;
      nz_ind = -1;
      has_hex = 0;
    } else if (*q == '/') {
      if (state == FIRST_GROUP) {
        fail();
      } else if (state == IPV4_GROUP) {
        if (ipv4_ind != 3) fail();
        FINISH_IPV4_GROUP();
        state = IPV4_NETSIZE;
      } else if (state == IPV4_NETSIZE) {
        fail();
      } else if (state == IPV6_EMPTY_FIRST_GROUP) {
        fail();
      } else if (state == IPV6_GROUP) {
      }
      buf_ind = 0;
      nz_ind = -1;
      has_hex = 0;
    } else if (*q == '0') {
      buf[buf_ind++] = *q;
    } else if (*q >= '1' && *q <= '9') {
      if (nz_ind < 0) nz_ind = buf_ind;
      buf[buf_ind++] = *q;
    } else if (*q >= 'a' && *q <= 'f') {
      has_hex = 1;
      if (nz_ind < 0) nz_ind = buf_ind;
      buf[buf_ind++] = *q;
    } else if (*q >= 'A' && *q <= 'F') {
      has_hex = 1;
      if (nz_ind < 0) nz_ind = buf_ind;
      buf[buf_ind++] = *q;
    } else {
      fail();
    }
  }
  if (state == FIRST_GROUP) {
    fail();
  } else if (state == IPV4_GROUP) {
    if (ipv4_ind != 3) fail();
    FINISH_IPV4_GROUP();

    memset(pip, 0, sizeof(*pip));
    pip->v4 = ipv4_b[0] << 24 | ipv4_b[1] << 16 | ipv4_b[2] << 8 | ipv4_b[3];
  } else if (state == IPV4_NETSIZE) {
    if (buf_ind <= 0) fail();
    if (nz_ind < 0) fail();
    if (buf_ind - nz_ind > 4) fail();
    buf[buf_ind] = 0;
    errno = 0;
    netsize = strtol(buf, NULL, 10);
    if (netsize != 32) fail();

    memset(pip, 0, sizeof(*pip));
    pip->v4 = ipv4_b[0] << 24 | ipv4_b[1] << 16 | ipv4_b[2] << 8 | ipv4_b[3];
  } else if (state == IPV6_EMPTY_FIRST_GROUP) {
    fail();
  } else if (state == IPV6_GROUP) {
    if (buf_ind <= 0) {
    } else {
      if (ipv6_fb_ind != 7) fail();
      FINISH_IPV6_GROUP();

      memset(pip, 0, sizeof(*pip));
    }
  }

  return 0;
}

int
xml_parse_ip6(
        FILE *log_f,
        unsigned char const *path,
        int line,
        int column,
        unsigned char const *s,
        ej_ip6_t *pip)
{
  int r = do_parse_ip6(s, pip);
  // FIXME: report error
  return r;
}
*/

#if 0
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
parse_ipv6(const char *str, unsigned short addr[])
{
  if (!str) fail();

  const unsigned char *bptr = (const unsigned char *) str;
  const unsigned char *eptr = (const unsigned char *) str + strlen(str);
  while (bptr < eptr && isspace(*bptr)) ++bptr;
  while (bptr < eptr && isspace(eptr[-1])) --eptr;
  if (bptr >= eptr) fail();

  memset(addr, 0, sizeof(addr[0]) * 8);
  int addrsize = 8;

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

  if (dcnt > 0) {
    if (!last_col) {
      // plain IPv4: parse or fail?
      ptr = bptr;
    } else {
      ptr = last_col + 1;
    }

    unsigned int value = 0;
    for (int i = 0; i < 4; ++i) {
      if (ptr >= eptr) fail();
      if (!isdigit(*ptr)) fail();
      unsigned int b = 0;
      while (ptr < eptr && isdigit(*ptr) && b < 256) {
        b = b * 10 + (*ptr - '0');
        ++ptr;
      }
      if (b >= 256) fail();
      value = (value << 8) | b;
      if (i < 3) {
        if (ptr >= eptr || *ptr != '.') fail();
        ++ptr;
      }
    }
    addr[6] = value >> 16;
    addr[7] = value & 0xffff;
    if (!last_col) {
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
#endif

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
