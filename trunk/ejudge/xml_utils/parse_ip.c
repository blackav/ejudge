/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2004-2012 Alexander Chernov <cher@ejudge.ru> */

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
        ej_ip_t *pip)
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

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
