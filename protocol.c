/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "protocol.h"

#include <reuse/xalloc.h>

#include <stdio.h>

#define _(x) x
static unsigned char const * const error_map[] =
{
  _("no error"),
  _("generic server error"),
  _("protocol error"),
  _("unexpected EOF from server"),
  _("read error from server"),
  _("user's runs downloading disabled"),
  _("user tries to download runs too often"),
  _("action is temporarily unavailable"),
};
#undef _

unsigned char const *
protocol_strerror(int n)
{
  if (n < 0) n = -n;
  if (n >= SRV_ERR_LAST) {
    // this is error anyway, so leak some memory
    unsigned char buf[64];

    snprintf(buf, sizeof(buf), "unknown error %d", n);
    return xstrdup(buf);
  }
  return error_map[n];
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
