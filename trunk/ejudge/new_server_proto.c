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
  [NEW_SRV_ERR_INV_USER_ID] = __("Invalid user_id"),
  [NEW_SRV_ERR_REGISTRATION_FAILED] = __("Registration failed: %s"),
  [NEW_SRV_ERR_USER_REMOVAL_FAILED] = __("Removal of user %d from contest %d failed: %s"),
  [NEW_SRV_ERR_USER_STATUS_CHANGE_FAILED] = __("Changing status of user %d in contest %d failed: %s"),
  [NEW_SRV_ERR_USER_FLAGS_CHANGE_FAILED] = __("Changing flags of user %d in contest %d failed: %s"),
  [NEW_SRV_ERR_INV_USER_LOGIN] = __("Invalid user_login"),
  [NEW_SRV_ERR_USER_LOGIN_NONEXISTANT] = __("User <tt>%s</tt> does not exist"),
  [NEW_SRV_ERR_PRIV_USER_REMOVAL_FAILED] = __("Removal of privileged user %d from contest %d failed"),
  [NEW_SRV_ERR_PRIV_USER_ROLE_ADD_FAILED] = __("Adding role %d to user %d in contest %d failed"),
  [NEW_SRV_ERR_PRIV_USER_ROLE_DEL_FAILED] = __("Deleting role %d of user %d from contest %d failed"),
  [NEW_SRV_ERR_INV_USER_ROLE] = __("Invalid user role"),
  [NEW_SRV_ERR_INV_TIME_SPEC] = __("Invalid time specification"),
  [NEW_SRV_ERR_CONTEST_ALREADY_FINISHED] = __("Contest already finished"),
  [NEW_SRV_ERR_CONTEST_ALREADY_STARTED] = __("Contest already started"),
  [NEW_SRV_ERR_INV_DUR_SPEC] = __("Invalid duration specification"),
  [NEW_SRV_ERR_DUR_TOO_SMALL] = __("New duration is too small"),
  [NEW_SRV_ERR_PERMISSION_DENIED] = __("Permission denied"),
  [NEW_SRV_ERR_CONTEST_NOT_STARTED] = __("Contest is not started"),
  [NEW_SRV_ERR_CANNOT_CONTINUE_CONTEST] = __("This contest cannot be continued"),
  [NEW_SRV_ERR_CONTEST_NOT_FINISHED] = __("Contest is not finished"),
  [NEW_SRV_ERR_INSUFFICIENT_DURATION] = __("Insufficient duration to continue the contest"),
  [NEW_SRV_ERR_INV_LOCALE_ID] = __("Invalid locale_id"),
  [NEW_SRV_ERR_SESSION_UPDATE_FAILED] = __("Session update failed: %s"),
  [NEW_SRV_ERR_LANG_DISABLED] = __("This language is disabled for use"),
  [NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM] = __("This language is not available for this problem"),
  [NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM] = __("The language %s is disabled for this problem"),
  [NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE] = __("Cannot guess the content type"),
  [NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE] = __("Content type <tt>%s</tt> is not available for this problem"),
  [NEW_SRV_ERR_CONTENT_TYPE_DISABLED] = __("Content type <tt>%s</tt> is disabled for this problem"),
  [NEW_SRV_ERR_RUNLOG_UPDATE_FAILED] = __("Run log update failed"),
  [NEW_SRV_ERR_DISK_WRITE_ERROR] = __("Disk write error (disk full?)"),
  [NEW_SRV_ERR_USER_ID_NONEXISTANT] = __("User Id %d does not exist"),
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
