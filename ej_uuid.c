/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2012 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"

#include "ej_uuid.h"

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
  return 0;
#endif
}

const unsigned char *
ej_uuid_unparse(const ruint32_t uuid[4], const unsigned char *default_value)
{
#if CONF_HAS_LIBUUID - 0 != 0
  if (uuid[0] || uuid[1] || uuid[2] || uuid[3]) {
    static char uuid_buf[40];
    uuid_unparse((void*) uuid, uuid_buf);
    return uuid_buf;
  } else {
    return default_value;
  }
#else
  return default_value;
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
