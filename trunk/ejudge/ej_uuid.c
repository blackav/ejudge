/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2012-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_uuid.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if CONF_HAS_LIBUUID - 0 != 0
#include <uuid/uuid.h>
#endif

int
ej_uuid_parse(const unsigned char *str, ruint32_t uuid[4])
{
#if CONF_HAS_LIBUUID - 0 != 0
  return uuid_parse(str, (void*) uuid);
#else
  uuid[0] = 0;
  uuid[1] = 0;
  uuid[2] = 0;
  uuid[3] = 0;
  if (!str || !*str) return 0;
  unsigned char *dst = (unsigned char *) uuid;
  for (int i = 0; i < 16; ++i) {
    if (!*str) return -1;
    if (*str == '-') ++str;
    if (!*str) return -1;
    int val = 0;
    if (*str >= '0' && *str <= '9') {
      val |= *str - '0';
    } else if (*str >= 'a' && *str <= 'f') {
      val |= *str - 'a' + 0xa;
    } else if (*str >= 'A' && *str <= 'F') {
      val |= *str - 'A' + 0xA;
    }
    val <<= 4;
    if (!*str) return -1;
    if (*str >= '0' && *str <= '9') {
      val |= *str - '0';
    } else if (*str >= 'a' && *str <= 'f') {
      val |= *str - 'a' + 0xa;
    } else if (*str >= 'A' && *str <= 'F') {
      val |= *str - 'A' + 0xA;
    }
    *dst++ = val;
  }
  return 0;
#endif
}

const unsigned char *
ej_uuid_unparse(const ruint32_t uuid[4], const unsigned char *default_value)
{
#if CONF_HAS_LIBUUID - 0 != 0
  if (uuid[0] || uuid[1] || uuid[2] || uuid[3] || !default_value) {
    static char uuid_buf[40];
    uuid_unparse((void*) uuid, uuid_buf);
    return uuid_buf;
  } else {
    return default_value;
  }
#else
  if (uuid[0] || uuid[1] || uuid[2] || uuid[3] || !default_value) {
    // must support unparse in any case
    // "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"; 
    static char uuid_buf[40];
    const unsigned char *u = (const unsigned char *) uuid;
    snprintf(uuid_buf, sizeof(uuid_buf),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
             u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
    return uuid_buf;
  } else {
    return default_value;
  }
#endif
}

void
ej_uuid_generate(ruint32_t uuid[4])
{
#if CONF_HAS_LIBUUID - 0 != 0
  uuid_generate((void*) uuid);
#else
  uuid[0] = 0;
  uuid[1] = 0;
  uuid[2] = 0;
  uuid[3] = 0;
#endif
}

int
ej_uuid_supported(void)
{
#if CONF_HAS_LIBUUID - 0 != 0
  return 1;
#else
  return 0;
#endif
}
