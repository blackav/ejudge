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
#include <reuse/logger.h>

#include <stdio.h>

#define _(x) x
static unsigned char const * const error_map[] =
{
  _("no error"),
  _("generic server error"),
  _("invalid socket path"),
  _("system call failed"),
  _("cannot connect to the server"),
  _("not connected to server"),
  _("protocol error"),
  _("unexpected EOF from server"),
  _("read error from server"),
  _("write error to server"),
  _("operation is not supported"),
  _("access denied"),
  _("invalid user_id"),
  _("invalid contest_id"),
  _("clarification requests are disabled"),
  _("invalid clar_id"),
  _("viewing run source is disabled"),
  _("invalid run_id"),
  _("invalid prob_id"),
  _("invalid lang_id"),
  _("viewing report is disabled"),
  _("user's runs downloading disabled"),
  _("user tries to download runs too often"),
  _("action is temporarily unavailable"),
  _("the contest is not started"),
  _("the contest is already finished"),
  _("the user quota is exceeded"),
  _("message subject is too long"),
  _("duplicated submission"),
  _("permission denied"),
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

static unsigned char const * const priv_level_map[] =
{
  "User", "Observer", "Judge", "Administrator"
};
unsigned char const *
protocol_priv_level_str(int n)
{
  ASSERT(n >= 0 && n <= PRIV_LEVEL_ADMIN);
  return priv_level_map[n];
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
