/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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
#include "settings.h"
#include "ej_types.h"
#include "ej_limits.h"

#include "new_server_proto.h"

#include <stdio.h>
#include <stdarg.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

static const unsigned char * const new_serve_error_messages[NEW_SRV_ERR_LAST]=
{
  [NEW_SRV_ERR_INVALID_USER_ID] = __("Invalid user_id"),
};

void
new_serve_error(FILE *log_f, int code, ...)
{
  const unsigned char *s = 0;
  va_list args;

  if (code < 0) code = -code;
  if (code >= NEW_SRV_ERR_LAST || !(s = new_serve_error_messages[code])) {
    fprintf(log_f, _("Unknown error %d.\n"), code);
    return;
  }

  va_start(args, code);
  vfprintf(log_f, gettext(s), args);
  va_end(args);
  fprintf(log_f, ".\n");
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
