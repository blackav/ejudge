/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2013 Alexander Chernov <cher@ejudge.ru> */

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
xml_unparse_full_cookie(
        unsigned char *buf,
        int size,
        const ej_cookie_t *p_cookie,
        const ej_cookie_t *p_client_key)
{
  // need 33 bytes
  if (size < 33) {
    snprintf(buf, size, "INVALID_BUFFER");
    return buf;
  }
  if (*p_client_key) {
    snprintf(buf, size, "%016llx-%016llx", *p_cookie, *p_client_key);
  } else {
    snprintf(buf, size, "%016llx", *p_cookie);
  }
  return buf;
}

int
xml_parse_full_cookie(
        const unsigned char *str,
        ej_cookie_t *p_cookie,
        ej_cookie_t *p_client_key)
{
  const unsigned char *s = str;
  int n;

  if (!s) {
    return -1;
  }
  if (sscanf(s, "%llx%n", p_cookie, &n) != 1) {
    return -1;
  }
  s += n;
  if (!*s) {
    *p_client_key = 0;
    return 1;
  }
  if (*s != '-') {
    return -1;
  }
  ++s;
  if (sscanf(s, "%llx%n", p_client_key, &n) != 1) {
    return -1;
  }
  s += n;
  if (*s) {
    return -1;
  }
  return 2;
}
