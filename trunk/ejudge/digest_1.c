/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2011 Alexander Chernov <cher@ejudge.ru> */

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

#include "reuse_logger.h"

int
digest_get_ascii_size(int kind)
{
  switch (kind) {
  case DIGEST_SHA1: return 40;
  default:
    SWERR(("unhandled digest type %d", kind));
  }
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
