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

static const unsigned char * const ns_error_messages[NEW_SRV_ERR_LAST]=
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
  [NEW_SRV_ERR_CONFLICTING_USER_ID_LOGIN] = __("Conflicting user_id (%d) and user_login (%s)"),
  [NEW_SRV_ERR_SUBJECT_TOO_LONG] = __("Subject length is too big (%zu)"),
  [NEW_SRV_ERR_SUBJECT_EMPTY] = __("Subject is empty"),
  [NEW_SRV_ERR_MESSAGE_TOO_LONG] = __("Message length is too big (%zu)"),
  [NEW_SRV_ERR_MESSAGE_EMPTY] = __("Message is empty"),
  [NEW_SRV_ERR_CLARLOG_UPDATE_FAILED] = __("Clar log update failed"),
  [NEW_SRV_ERR_INV_CLAR_ID] = __("Invalid clar_id"),
  [NEW_SRV_ERR_CANNOT_REPLY_TO_JUDGE] = __("It's not allowed to answer to judge's messages"),
  [NEW_SRV_ERR_DISK_READ_ERROR] = __("Disk read error (nonexistant file?)"),
  [NEW_SRV_ERR_INV_STATUS] = __("Invalid status"),
  [NEW_SRV_ERR_NO_RUNS_TO_REJUDGE] = __("No runs to rejudge"),
  [NEW_SRV_ERR_RUN_TO_COMPARE_UNSPECIFIED] = __("Run to compare to is not specified"),
  [NEW_SRV_ERR_INV_RUN_TO_COMPARE] = __("Invalid run to compare to"),
  [NEW_SRV_ERR_RUN_COMPARE_FAILED] = __("Error during run comparison"),
  [NEW_SRV_ERR_INV_PROB_ID] = __("Invalid problem"),
  [NEW_SRV_ERR_SOURCE_UNAVAILABLE] = __("Source for this run is not available"),
  [NEW_SRV_ERR_SOURCE_NONEXISTANT] = __("Source file does not exist"),
  [NEW_SRV_ERR_INV_LANG_ID] = __("Invalid language"),
  [NEW_SRV_ERR_INV_TEST] = __("Invalid test"),
  [NEW_SRV_ERR_OLD_PWD_TOO_LONG] = __("Old password is too long"),
  [NEW_SRV_ERR_NEW_PWD_MISMATCH] = __("New passwords do not match"),
  [NEW_SRV_ERR_NEW_PWD_TOO_LONG] = __("New password is too long"),
  [NEW_SRV_ERR_PWD_UPDATE_FAILED] = __("Password update failed: %s"),
  [NEW_SRV_ERR_RUN_ID_UNDEFINED] = __("`run_id' parameter is undefined"),
  [NEW_SRV_ERR_INV_RUN_ID] = __("`run_id' parameter value is invalid."),
  [NEW_SRV_ERR_RUN_ID_OUT_OF_RANGE] = __("`run_id' parameter value %d is out of range"),
  [NEW_SRV_ERR_RUNLOG_READ_FAILED] = __("Failed to fetch run log entry %d"),
  [NEW_SRV_ERR_PRINTING_DISABLED] = __("Printing is disabled"),
  [NEW_SRV_ERR_ALREADY_PRINTED] = __("This submit is already printed"),
  [NEW_SRV_ERR_PRINT_QUOTA_EXCEEDED] = __("Printing quota (%d pages) is exceeded"),
  [NEW_SRV_ERR_PRINTING_FAILED] = __("Printing error: %d: %s"),
  [NEW_SRV_ERR_CLIENTS_SUSPENDED] = __("Client's requests are suspended. Please wait until the contest administrator resumes the contest"),
  [NEW_SRV_ERR_RUN_QUOTA_EXCEEDED] = __("User quota exceeded. This submit is too large, you already have too many submits,\nor the total size of your submits is too big"),
  [NEW_SRV_ERR_PROB_UNAVAILABLE] = __("This problem is not yet available"),
  [NEW_SRV_ERR_PROB_DEADLINE_EXPIRED] = __("Deadline for this problem is expired"),
  [NEW_SRV_ERR_VARIANT_UNASSIGNED] = __("No assigned variant"),
  [NEW_SRV_ERR_DUPLICATE_SUBMIT] = __("This submit is duplicate of the run %d"),
  [NEW_SRV_ERR_PROB_ALREADY_SOLVED] = __("This problem is already solved"),
  [NEW_SRV_ERR_NOT_ALL_REQ_SOLVED] = __("Not all pre-required problems are solved"),
  [NEW_SRV_ERR_CLARS_DISABLED] = __("Clarification requests are disabled"),
  [NEW_SRV_ERR_CLAR_QUOTA_EXCEEDED] = __("User quota exceeded. This clarification request is too large, you already have too many clarification requests, or the total size of your clarification requests is too big"),
  [NEW_SRV_ERR_SOURCE_VIEW_DISABLED] = __("Submit source viewing is disabled"),
  [NEW_SRV_ERR_REPORT_UNAVAILABLE] = __("Report is not available"),
  [NEW_SRV_ERR_REPORT_VIEW_DISABLED] = __("Report viewing is disabled"),
  [NEW_SRV_ERR_REPORT_NONEXISTANT] = __("Report file does not exist"),
  [NEW_SRV_ERR_TEST_NONEXISTANT] = __("Test file does not exist"),
  [NEW_SRV_ERR_CHECKSUMMING_FAILED] = __("Cannot calculate the file checksum"),
  [NEW_SRV_ERR_OUTPUT_ERROR] = __("Output error"),
  [NEW_SRV_ERR_TEST_UNAVAILABLE] = __("Test file is not available"),
  [NEW_SRV_ERR_INV_VARIANT] = __("Invalid variant"),
  [NEW_SRV_ERR_PWD_GENERATION_FAILED] = __("Password generation failed: %s"),
  [NEW_SRV_ERR_TEAM_PWD_DISABLED] = __("Contest passwords are disabled"),
  [NEW_SRV_ERR_APPEALS_DISABLED] = __("Appeals are disabled"),
  [NEW_SRV_ERR_APPEALS_FINISHED] = __("Appeals deadline is exceeded"),
  [NEW_SRV_ERR_NOT_VIRTUAL] = __("Not a virtual contest"),
  [NEW_SRV_ERR_VIRTUAL_NOT_STARTED] = __("Virtual contest is not started"),
  [NEW_SRV_ERR_UNHANDLED_ACTION] = __("Unhandled action: %d"),
  [NEW_SRV_ERR_UNDEFINED_USER_ID_LOGIN] = __("Undefined user_id and login"),
  [NEW_SRV_ERR_INV_PARAM] = __("Invalid parameter"),
  [NEW_SRV_ERR_BINARY_FILE] = __("Attempt to submit a binary file"),
  [NEW_SRV_ERR_INV_SCORE] = __("Invalid score"),
  [NEW_SRV_ERR_INV_SCORE_ADJ] = __("Invalid score adjustment"),
  [NEW_SRV_ERR_INV_PAGES] = __("Invalid pages count"),
  [NEW_SRV_ERR_RUN_READ_ONLY] = __("Run is read-only"),
  [NEW_SRV_ERR_INV_WARN_TEXT] = __("Invalid text of warning"),
  [NEW_SRV_ERR_WARN_TEXT_EMPTY] = __("Empty text of warning"),
  [NEW_SRV_ERR_INV_WARN_CMT] = __("Invalid text of warning comment"),
  [NEW_SRV_ERR_SUBMIT_EMPTY] = __("Empty submit"),
  [NEW_SRV_ERR_AUDIT_LOG_NONEXISTANT] = __("Audit log file does not exist"),
  [NEW_SRV_ERR_INV_RUN_SELECTION] = __("Invalid run selection type"),
  [NEW_SRV_ERR_INV_DIR_STRUCT] = __("Invalid directory structure type"),
  [NEW_SRV_ERR_MKDIR_FAILED] = __("Mkdir(%s) failed: %s"),
  [NEW_SRV_ERR_TAR_FAILED] = __("Archive creation with tar failed"),
  [NEW_SRV_ERR_FILE_UNSPECIFIED] = __("File is not specified"),
  [NEW_SRV_ERR_FILE_EMPTY] = __("File is empty"),
  [NEW_SRV_ERR_TRY_AGAIN] = __("Try again this operation later"),
  [NEW_SRV_ERR_NOT_SUPPORTED] = __("Operation is not supported"),
};

const unsigned char *
ns_strerror(int code, ...)
{
  static unsigned char buf[1024];
  unsigned char buf2[1024];
  const unsigned char *s = 0;
  va_list args;

  if (code < 0) code = -code;
  if (code >= NEW_SRV_ERR_LAST || !(s = ns_error_messages[code])) {
    snprintf(buf, sizeof(buf), _("Unknown error %d.\n"), code);
    return buf;
  }

  va_start(args, code);
  snprintf(buf2, sizeof(buf2), gettext(s), args);
  va_end(args);
  snprintf(buf, sizeof(buf), "%s.\n", buf2);
  return buf;
}

const unsigned char *
ns_strerror_r(unsigned char *buf, size_t size, int code, ...)
{
  unsigned char buf2[1024];
  const unsigned char *s = 0;
  va_list args;

  if (code < 0) code = -code;
  if (code >= NEW_SRV_ERR_LAST || !(s = ns_error_messages[code])) {
    snprintf(buf, sizeof(buf), _("Unknown error %d.\n"), code);
    return buf;
  }

  va_start(args, code);
  snprintf(buf2, sizeof(buf2), gettext(s), args);
  va_end(args);
  snprintf(buf, sizeof(buf), "%s.\n", buf2);
  return buf;
}

void
ns_error(FILE *log_f, int code, ...)
{
  const unsigned char *s = 0;
  va_list args;

  if (code < 0) code = -code;
  if (code >= NEW_SRV_ERR_LAST || !(s = ns_error_messages[code])) {
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
