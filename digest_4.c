/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

#include "digest_io.h"

#include <reuse/logger.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int
digest_from_ascii(int kind, const unsigned char *asc, void *raw)
{
  int dlen, rlen, i;
  unsigned char b[3];
  unsigned char *p = (unsigned char *) raw;

  switch (kind) {
  case DIGEST_SHA1: dlen = 20; break;
  default:
    SWERR(("unhandled digest type %d", kind));
  }
  rlen = dlen * 2;

  if (strlen(asc) != rlen) return -1;
  for (i = 0; i < rlen; i++)
    if (!isxdigit(asc[i]))
      return -1;

  b[2] = 0;
  for (i = 0; i < dlen; i++) {
    b[0] = *asc++;
    b[1] = *asc++;
    *p++ = strtol(b, 0, 16);
  }
  return dlen;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
