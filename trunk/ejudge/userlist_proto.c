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

#include "userlist_proto.h"

#include <stdio.h>

#define _(x) x
// messages to be localized at the caller level
static unsigned char const * const error_map[] =
{
  _("no error"),
  _("login already used"),
  _("invalid login"),
  _("invalid password"),
  _("nonexistent cookie"),
  _("bad user identifier"),
  _("permission denied"),
  _("packet sending failed"),
  _("out of memory"),
  _("packet receive failed"),
  _("protocol error"),
  _("no connection to server"),
  _("write error"),
  _("read error"),
  _("unexpected EOF"),
  _("XML parse error"),
  _("not implemented"),
  _("some component of request is too large"),
  _("bad contest identifier"),
  _("invalid member"),
  _("IPC operation failed"),
  _("this IP address is not allowed to use this service"),
  _("this user cannot participate in this contest"),

  0
};
#undef _

unsigned char const *
userlist_strerror(int code)
{
  static char buf[64];

  if (code < 0 || code >= ULS_ERR_LAST) {
    snprintf(buf, sizeof(buf), "unknown error %d", code);
    return buf;
  }
  return error_map[code];
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
