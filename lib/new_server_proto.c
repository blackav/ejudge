/* -*- mode: c -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/new_server_proto.h"

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
  [NEW_SRV_ERR_UNKNOWN_ERROR] = __("Unknown error"),
  [NEW_SRV_ERR_BAD_SOCKET_NAME] = __("Bad socket name"),
  [NEW_SRV_ERR_SYSTEM_ERROR] = __("System error"),
  [NEW_SRV_ERR_CONNECT_FAILED] = __("Connection failed"),
  [NEW_SRV_ERR_WRITE_ERROR] = __("Write error"),
  [NEW_SRV_ERR_NOT_CONNECTED] = __("Not connected"),
  [NEW_SRV_ERR_READ_ERROR] = __("Read error"),
  [NEW_SRV_ERR_UNEXPECTED_EOF] = __("Unexpected EOF"),
  [NEW_SRV_ERR_PACKET_TOO_BIG] = __("Packet is too big"),
  [NEW_SRV_ERR_PACKET_TOO_SMALL] = __("Packet is too small"),
  [NEW_SRV_ERR_PROTOCOL_ERROR] = __("Protocol error"),
  [NEW_SRV_ERR_PARAM_OUT_OF_RANGE] = __("Parameter is out of range"),

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
  [NEW_SRV_ERR_CONTEST_NOT_STOPPED] = __("Contest is not stopped"),
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
  [NEW_SRV_ERR_PRINTING_FAILED] = __("Printing error"),
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
  [NEW_SRV_ERR_INV_ACTION] = __("Invalid action"),
  [NEW_SRV_ERR_INV_CONTEST_ID] = __("Invalid contest"),
  [NEW_SRV_ERR_INV_ROLE] = __("Invalid role"),
  [NEW_SRV_ERR_USERLIST_SERVER_DOWN] = __("Userlist server is down"),
  [NEW_SRV_ERR_INTERNAL] = __("Internal error"),
  [NEW_SRV_ERR_INV_FILTER_EXPR] = __("Invalid filter expression"),
  [NEW_SRV_ERR_CONTEST_UNLOADED] = __("Contest is unloaded"),
  [NEW_SRV_ERR_PENDING_IMPORT_EXISTS] = __("Pending XML import already exists"),
  [NEW_SRV_ERR_ANSWER_UNSPECIFIED] = __("Answer is unspecified"),
  [NEW_SRV_ERR_LOGIN_BINARY] = __("Login contains invalid characters"),
  [NEW_SRV_ERR_LOGIN_UNSPECIFIED] = __("Login is not specified"),
  [NEW_SRV_ERR_LOGIN_INV_CHARS] = __("Login contains invalid characters"),
  [NEW_SRV_ERR_EMAIL_BINARY] = __("E-mail contains invalid characters"),
  [NEW_SRV_ERR_EMAIL_UNSPECIFIED] = __("E-mail is not specified"),
  [NEW_SRV_ERR_EMAIL_INV_CHARS] = __("E-mail contains invalid characters"),
  [NEW_SRV_ERR_UL_CONNECT_FAILED] = __("No connection to the server"),
  [NEW_SRV_ERR_PLUGIN_NOT_AVAIL] = __("No plugin is available for problem"),
  [NEW_SRV_ERR_INV_FILE_NAME] = __("Invalid file name"),
  [NEW_SRV_ERR_VIRTUAL_START_FAILED] = __("Virtual start failed"),
  [NEW_SRV_ERR_INV_CHAR] = __("Invalid character"),
  [NEW_SRV_ERR_DATABASE_FAILED] = __("Database error"),
  [NEW_SRV_ERR_PROB_CONFIG] = __("Problem configuration error"),
  [NEW_SRV_ERR_PROB_TOO_MANY_ATTEMPTS] = __("Max problem submit count is exceeded"),
  [NEW_SRV_ERR_INV_SESSION] = __("Invalid session"),
  [NEW_SRV_ERR_REGISTRATION_INCOMPLETE] = __("Registration is incomplete"),
  [NEW_SRV_ERR_SERVICE_NOT_AVAILABLE] = __("Service is not available"),
  [NEW_SRV_ERR_DISQUALIFIED] = __("Disqualified"),
  [NEW_SRV_ERR_SIMPLE_REGISTERED] = __("User is simple registered"),
  [NEW_SRV_ERR_CNTS_UNAVAILABLE] = __("Contest is not available"),
  [NEW_SRV_ERR_OPERATION_FAILED] = __("Operation failed"),
  [NEW_SRV_ERR_INV_TOKEN] = __("Invalid token"),
  [NEW_SRV_ERR_INV_UUID] = __("Invalid UUID"),
  [NEW_SRV_ERR_RATE_EXCEEDED] = __("Rate exceeded"),
  [NEW_SRV_ERR_INV_SUBMIT_ID] = __("Invalid submit ID"),
  [NEW_SRV_ERR_INV_USERPROB_ID] = __("Invalid ID"),
  [NEW_SRV_ERR_INV_EXT_USER] = __("Invalid external user"),
  [NEW_SRV_ERR_INV_NOTIFY] = __("Invalid notification"),
};

static const unsigned char * const ns_error_titles[NEW_SRV_ERR_LAST]=
{
  [NEW_SRV_ERR_UNKNOWN_ERROR] = __("Unknown error"),
  [NEW_SRV_ERR_BAD_SOCKET_NAME] = __("Bad socket name"),
  [NEW_SRV_ERR_SYSTEM_ERROR] = __("System error"),
  [NEW_SRV_ERR_CONNECT_FAILED] = __("Connection failed"),
  [NEW_SRV_ERR_WRITE_ERROR] = __("Write error"),
  [NEW_SRV_ERR_NOT_CONNECTED] = __("Not connected"),
  [NEW_SRV_ERR_READ_ERROR] = __("Read error"),
  [NEW_SRV_ERR_UNEXPECTED_EOF] = __("Unexpected EOF"),
  [NEW_SRV_ERR_PACKET_TOO_BIG] = __("Packet is too big"),
  [NEW_SRV_ERR_PACKET_TOO_SMALL] = __("Packet is too small"),
  [NEW_SRV_ERR_PROTOCOL_ERROR] = __("Protocol error"),
  [NEW_SRV_ERR_PARAM_OUT_OF_RANGE] = __("Parameter is out of range"),

  [NEW_SRV_ERR_INV_USER_ID] = __("Invalid user_id"),
  [NEW_SRV_ERR_REGISTRATION_FAILED] = __("Registration failed"),
  [NEW_SRV_ERR_USER_REMOVAL_FAILED] = __("Removal of user from contest failed"),
  [NEW_SRV_ERR_USER_STATUS_CHANGE_FAILED] = __("Changing status of user in contest failed"),
  [NEW_SRV_ERR_USER_FLAGS_CHANGE_FAILED] = __("Changing flags of user in contest failed"),
  [NEW_SRV_ERR_INV_USER_LOGIN] = __("Invalid user_login"),
  [NEW_SRV_ERR_USER_LOGIN_NONEXISTANT] = __("User does not exist"),
  [NEW_SRV_ERR_PRIV_USER_REMOVAL_FAILED] = __("Removal of privileged user from contest failed"),
  [NEW_SRV_ERR_PRIV_USER_ROLE_ADD_FAILED] = __("Adding role to user in contest failed"),
  [NEW_SRV_ERR_PRIV_USER_ROLE_DEL_FAILED] = __("Deleting role of user from contest failed"),
  [NEW_SRV_ERR_INV_USER_ROLE] = __("Invalid user role"),
  [NEW_SRV_ERR_INV_TIME_SPEC] = __("Invalid time specification"),
  [NEW_SRV_ERR_CONTEST_ALREADY_FINISHED] = __("Contest already finished"),
  [NEW_SRV_ERR_CONTEST_ALREADY_STARTED] = __("Contest already started"),
  [NEW_SRV_ERR_INV_DUR_SPEC] = __("Invalid duration specification"),
  [NEW_SRV_ERR_DUR_TOO_SMALL] = __("New duration is too small"),
  [NEW_SRV_ERR_PERMISSION_DENIED] = __("Permission denied"),
  [NEW_SRV_ERR_CONTEST_NOT_STARTED] = __("Contest is not started"),
  [NEW_SRV_ERR_CONTEST_NOT_STOPPED] = __("Contest is not stopped"),
  [NEW_SRV_ERR_CANNOT_CONTINUE_CONTEST] = __("This contest cannot be continued"),
  [NEW_SRV_ERR_CONTEST_NOT_FINISHED] = __("Contest is not finished"),
  [NEW_SRV_ERR_INSUFFICIENT_DURATION] = __("Insufficient duration to continue the contest"),
  [NEW_SRV_ERR_INV_LOCALE_ID] = __("Invalid locale_id"),
  [NEW_SRV_ERR_SESSION_UPDATE_FAILED] = __("Session update failed"),
  [NEW_SRV_ERR_LANG_DISABLED] = __("This language is disabled for use"),
  [NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM] = __("This language is not available for this problem"),
  [NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM] = __("The language is disabled for this problem"),
  [NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE] = __("Cannot guess the content type"),
  [NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE] = __("Content type is not available for this problem"),
  [NEW_SRV_ERR_CONTENT_TYPE_DISABLED] = __("Content type is disabled for this problem"),
  [NEW_SRV_ERR_RUNLOG_UPDATE_FAILED] = __("Run log update failed"),
  [NEW_SRV_ERR_DISK_WRITE_ERROR] = __("Disk write error (disk full?)"),
  [NEW_SRV_ERR_USER_ID_NONEXISTANT] = __("User Id does not exist"),
  [NEW_SRV_ERR_CONFLICTING_USER_ID_LOGIN] = __("Conflicting user_id and user_login"),
  [NEW_SRV_ERR_SUBJECT_TOO_LONG] = __("Subject length is too big"),
  [NEW_SRV_ERR_SUBJECT_EMPTY] = __("Subject is empty"),
  [NEW_SRV_ERR_MESSAGE_TOO_LONG] = __("Message length is too big"),
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
  [NEW_SRV_ERR_PWD_UPDATE_FAILED] = __("Password update failed"),
  [NEW_SRV_ERR_RUN_ID_UNDEFINED] = __("`run_id' parameter is undefined"),
  [NEW_SRV_ERR_INV_RUN_ID] = __("`run_id' parameter value is invalid."),
  [NEW_SRV_ERR_RUN_ID_OUT_OF_RANGE] = __("`run_id' parameter value is out of range"),
  [NEW_SRV_ERR_RUNLOG_READ_FAILED] = __("Failed to fetch run log entry"),
  [NEW_SRV_ERR_PRINTING_DISABLED] = __("Printing is disabled"),
  [NEW_SRV_ERR_ALREADY_PRINTED] = __("This submit is already printed"),
  [NEW_SRV_ERR_PRINT_QUOTA_EXCEEDED] = __("Printing quota is exceeded"),
  [NEW_SRV_ERR_PRINTING_FAILED] = __("Printing error"),
  [NEW_SRV_ERR_CLIENTS_SUSPENDED] = __("Client's requests are suspended. Please wait until the contest administrator resumes the contest"),
  [NEW_SRV_ERR_RUN_QUOTA_EXCEEDED] = __("User quota exceeded. This submit is too large, you already have too many submits,\nor the total size of your submits is too big"),
  [NEW_SRV_ERR_PROB_UNAVAILABLE] = __("This problem is not yet available"),
  [NEW_SRV_ERR_PROB_DEADLINE_EXPIRED] = __("Deadline for this problem is expired"),
  [NEW_SRV_ERR_VARIANT_UNASSIGNED] = __("No assigned variant"),
  [NEW_SRV_ERR_DUPLICATE_SUBMIT] = __("This submit is duplicate of another run"),
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
  [NEW_SRV_ERR_PWD_GENERATION_FAILED] = __("Password generation failed"),
  [NEW_SRV_ERR_TEAM_PWD_DISABLED] = __("Contest passwords are disabled"),
  [NEW_SRV_ERR_APPEALS_DISABLED] = __("Appeals are disabled"),
  [NEW_SRV_ERR_APPEALS_FINISHED] = __("Appeals deadline is exceeded"),
  [NEW_SRV_ERR_NOT_VIRTUAL] = __("Not a virtual contest"),
  [NEW_SRV_ERR_VIRTUAL_NOT_STARTED] = __("Virtual contest is not started"),
  [NEW_SRV_ERR_UNHANDLED_ACTION] = __("Unhandled action"),
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
  [NEW_SRV_ERR_MKDIR_FAILED] = __("Mkdir failed"),
  [NEW_SRV_ERR_TAR_FAILED] = __("Archive creation with tar failed"),
  [NEW_SRV_ERR_FILE_UNSPECIFIED] = __("File is not specified"),
  [NEW_SRV_ERR_FILE_EMPTY] = __("File is empty"),
  [NEW_SRV_ERR_TRY_AGAIN] = __("Try again this operation later"),
  [NEW_SRV_ERR_NOT_SUPPORTED] = __("Operation is not supported"),
  [NEW_SRV_ERR_INV_ACTION] = __("Invalid action"),
  [NEW_SRV_ERR_INV_CONTEST_ID] = __("Invalid contest"),
  [NEW_SRV_ERR_INV_ROLE] = __("Invalid role"),
  [NEW_SRV_ERR_USERLIST_SERVER_DOWN] = __("Userlist server is down"),
  [NEW_SRV_ERR_INTERNAL] = __("Internal error"),
  [NEW_SRV_ERR_INV_FILTER_EXPR] = __("Invalid filter expression"),
  [NEW_SRV_ERR_CONTEST_UNLOADED] = __("Contest is unloaded"),
  [NEW_SRV_ERR_PENDING_IMPORT_EXISTS] = __("Pending XML import already exists"),
  [NEW_SRV_ERR_ANSWER_UNSPECIFIED] = __("Answer is unspecified"),
  [NEW_SRV_ERR_LOGIN_BINARY] = __("Login contains invalid characters"),
  [NEW_SRV_ERR_LOGIN_UNSPECIFIED] = __("Login is not specified"),
  [NEW_SRV_ERR_LOGIN_INV_CHARS] = __("Login contains invalid characters"),
  [NEW_SRV_ERR_EMAIL_BINARY] = __("E-mail contains invalid characters"),
  [NEW_SRV_ERR_EMAIL_UNSPECIFIED] = __("E-mail is not specified"),
  [NEW_SRV_ERR_EMAIL_INV_CHARS] = __("E-mail contains invalid characters"),
  [NEW_SRV_ERR_UL_CONNECT_FAILED] = __("No connection to the server"),
  [NEW_SRV_ERR_PLUGIN_NOT_AVAIL] = __("No plugin is available for problem"),
  [NEW_SRV_ERR_INV_FILE_NAME] = __("Invalid file name"),
  [NEW_SRV_ERR_VIRTUAL_START_FAILED] = __("Virtual start failed"),
  [NEW_SRV_ERR_INV_CHAR] = __("Invalid character"),
  [NEW_SRV_ERR_DATABASE_FAILED] = __("Database error"),
  [NEW_SRV_ERR_PROB_CONFIG] = __("Problem configuration error"),
  [NEW_SRV_ERR_PROB_TOO_MANY_ATTEMPTS] = __("Max problem submit count is exceeded"),
  [NEW_SRV_ERR_INV_SESSION] = __("Invalid session"),
  [NEW_SRV_ERR_REGISTRATION_INCOMPLETE] = __("Registration is incomplete"),
  [NEW_SRV_ERR_SERVICE_NOT_AVAILABLE] = __("Service is not available"),
  [NEW_SRV_ERR_DISQUALIFIED] = __("Disqualified"),
  [NEW_SRV_ERR_SIMPLE_REGISTERED] = __("User is simple registered"),
  [NEW_SRV_ERR_CNTS_UNAVAILABLE] = __("Contest is not available"),
  [NEW_SRV_ERR_OPERATION_FAILED] = __("Operation failed"),
  [NEW_SRV_ERR_INV_TOKEN] = __("Invalid token"),
  [NEW_SRV_ERR_INV_UUID] = __("Invalid UUID"),
  [NEW_SRV_ERR_RATE_EXCEEDED] = __("Rate exceeded"),
  [NEW_SRV_ERR_INV_SUBMIT_ID] = __("Invalid submit ID"),
  [NEW_SRV_ERR_INV_USERPROB_ID] = __("Invalid ID"),
  [NEW_SRV_ERR_INV_EXT_USER] = __("Invalid external user"),
  [NEW_SRV_ERR_INV_NOTIFY] = __("Invalid notification"),
};

static const unsigned char * const ns_error_symbols[NEW_SRV_ERR_LAST]=
{
  [NEW_SRV_ERR_UNKNOWN_ERROR] = "ERR_UNKNOWN_ERROR",
  [NEW_SRV_ERR_BAD_SOCKET_NAME] = "ERR_BAD_SOCKET_NAME",
  [NEW_SRV_ERR_SYSTEM_ERROR] = "ERR_SYSTEM_ERROR",
  [NEW_SRV_ERR_CONNECT_FAILED] = "ERR_CONNECT_FAILED",
  [NEW_SRV_ERR_WRITE_ERROR] = "ERR_WRITE_ERROR",
  [NEW_SRV_ERR_NOT_CONNECTED] = "ERR_NOT_CONNECTED",
  [NEW_SRV_ERR_READ_ERROR] = "ERR_READ_ERROR",
  [NEW_SRV_ERR_UNEXPECTED_EOF] = "ERR_UNEXPECTED_EOF",
  [NEW_SRV_ERR_PACKET_TOO_BIG] = "ERR_PACKET_TOO_BIG",
  [NEW_SRV_ERR_PACKET_TOO_SMALL] = "ERR_PACKET_TOO_SMALL",
  [NEW_SRV_ERR_PROTOCOL_ERROR] = "ERR_PROTOCOL_ERROR",
  [NEW_SRV_ERR_PARAM_OUT_OF_RANGE] = "ERR_PARAM_OUT_OF_RANGE",
  [NEW_SRV_ERR_INV_USER_ID] = "ERR_INV_USER_ID",
  [NEW_SRV_ERR_REGISTRATION_FAILED] = "ERR_REGISTRATION_FAILED",
  [NEW_SRV_ERR_USER_REMOVAL_FAILED] = "ERR_USER_REMOVAL_FAILED",
  [NEW_SRV_ERR_USER_STATUS_CHANGE_FAILED] = "ERR_USER_STATUS_CHANGE_FAILED",
  [NEW_SRV_ERR_USER_FLAGS_CHANGE_FAILED] = "ERR_USER_FLAGS_CHANGE_FAILED",
  [NEW_SRV_ERR_INV_USER_LOGIN] = "ERR_INV_USER_LOGIN",
  [NEW_SRV_ERR_USER_LOGIN_NONEXISTANT] = "ERR_USER_LOGIN_NONEXISTANT",
  [NEW_SRV_ERR_PRIV_USER_REMOVAL_FAILED] = "ERR_PRIV_USER_REMOVAL_FAILED",
  [NEW_SRV_ERR_PRIV_USER_ROLE_ADD_FAILED] = "ERR_PRIV_USER_ROLE_ADD_FAILED",
  [NEW_SRV_ERR_PRIV_USER_ROLE_DEL_FAILED] = "ERR_PRIV_USER_ROLE_DEL_FAILED",
  [NEW_SRV_ERR_INV_USER_ROLE] = "ERR_INV_USER_ROLE",
  [NEW_SRV_ERR_INV_TIME_SPEC] = "ERR_INV_TIME_SPEC",
  [NEW_SRV_ERR_CONTEST_ALREADY_FINISHED] = "ERR_CONTEST_ALREADY_FINISHED",
  [NEW_SRV_ERR_CONTEST_ALREADY_STARTED] = "ERR_CONTEST_ALREADY_STARTED",
  [NEW_SRV_ERR_INV_DUR_SPEC] = "ERR_INV_DUR_SPEC",
  [NEW_SRV_ERR_DUR_TOO_SMALL] = "ERR_DUR_TOO_SMALL",
  [NEW_SRV_ERR_PERMISSION_DENIED] = "ERR_PERMISSION_DENIED",
  [NEW_SRV_ERR_CONTEST_NOT_STARTED] = "ERR_CONTEST_NOT_STARTED",
  [NEW_SRV_ERR_CONTEST_NOT_STOPPED] = "ERR_CONTEST_NOT_STOPPED",
  [NEW_SRV_ERR_CANNOT_CONTINUE_CONTEST] = "ERR_CANNOT_CONTINUE_CONTEST",
  [NEW_SRV_ERR_CONTEST_NOT_FINISHED] = "ERR_CONTEST_NOT_FINISHED",
  [NEW_SRV_ERR_INSUFFICIENT_DURATION] = "ERR_INSUFFICIENT_DURATION",
  [NEW_SRV_ERR_INV_LOCALE_ID] = "ERR_INV_LOCALE_ID",
  [NEW_SRV_ERR_SESSION_UPDATE_FAILED] = "ERR_SESSION_UPDATE_FAILED",
  [NEW_SRV_ERR_LANG_DISABLED] = "ERR_LANG_DISABLED",
  [NEW_SRV_ERR_LANG_NOT_AVAIL_FOR_PROBLEM] = "ERR_LANG_NOT_AVAIL_FOR_PROBLEM",
  [NEW_SRV_ERR_LANG_DISABLED_FOR_PROBLEM] = "ERR_LANG_DISABLED_FOR_PROBLEM",
  [NEW_SRV_ERR_CANNOT_DETECT_CONTENT_TYPE] = "ERR_CANNOT_DETECT_CONTENT_TYPE",
  [NEW_SRV_ERR_CONTENT_TYPE_NOT_AVAILABLE] = "ERR_CONTENT_TYPE_NOT_AVAILABLE",
  [NEW_SRV_ERR_CONTENT_TYPE_DISABLED] = "ERR_CONTENT_TYPE_DISABLED",
  [NEW_SRV_ERR_RUNLOG_UPDATE_FAILED] = "ERR_RUNLOG_UPDATE_FAILED",
  [NEW_SRV_ERR_DISK_WRITE_ERROR] = "ERR_DISK_WRITE_ERROR",
  [NEW_SRV_ERR_USER_ID_NONEXISTANT] = "ERR_USER_ID_NONEXISTANT",
  [NEW_SRV_ERR_CONFLICTING_USER_ID_LOGIN] = "ERR_CONFLICTING_USER_ID_LOGIN",
  [NEW_SRV_ERR_SUBJECT_TOO_LONG] = "ERR_SUBJECT_TOO_LONG",
  [NEW_SRV_ERR_SUBJECT_EMPTY] = "ERR_SUBJECT_EMPTY",
  [NEW_SRV_ERR_MESSAGE_TOO_LONG] = "ERR_MESSAGE_TOO_LONG",
  [NEW_SRV_ERR_MESSAGE_EMPTY] = "ERR_MESSAGE_EMPTY",
  [NEW_SRV_ERR_CLARLOG_UPDATE_FAILED] = "ERR_CLARLOG_UPDATE_FAILED",
  [NEW_SRV_ERR_INV_CLAR_ID] = "ERR_INV_CLAR_ID",
  [NEW_SRV_ERR_CANNOT_REPLY_TO_JUDGE] = "ERR_CANNOT_REPLY_TO_JUDGE",
  [NEW_SRV_ERR_DISK_READ_ERROR] = "ERR_DISK_READ_ERROR",
  [NEW_SRV_ERR_INV_STATUS] = "ERR_INV_STATUS",
  [NEW_SRV_ERR_NO_RUNS_TO_REJUDGE] = "ERR_NO_RUNS_TO_REJUDGE",
  [NEW_SRV_ERR_RUN_TO_COMPARE_UNSPECIFIED] = "ERR_RUN_TO_COMPARE_UNSPECIFIED",
  [NEW_SRV_ERR_INV_RUN_TO_COMPARE] = "ERR_INV_RUN_TO_COMPARE",
  [NEW_SRV_ERR_RUN_COMPARE_FAILED] = "ERR_RUN_COMPARE_FAILED",
  [NEW_SRV_ERR_INV_PROB_ID] = "ERR_INV_PROB_ID",
  [NEW_SRV_ERR_SOURCE_UNAVAILABLE] = "ERR_SOURCE_UNAVAILABLE",
  [NEW_SRV_ERR_SOURCE_NONEXISTANT] = "ERR_SOURCE_NONEXISTANT",
  [NEW_SRV_ERR_INV_LANG_ID] = "ERR_INV_LANG_ID",
  [NEW_SRV_ERR_INV_TEST] = "ERR_INV_TEST",
  [NEW_SRV_ERR_OLD_PWD_TOO_LONG] = "ERR_OLD_PWD_TOO_LONG",
  [NEW_SRV_ERR_NEW_PWD_MISMATCH] = "ERR_NEW_PWD_MISMATCH",
  [NEW_SRV_ERR_NEW_PWD_TOO_LONG] = "ERR_NEW_PWD_TOO_LONG",
  [NEW_SRV_ERR_PWD_UPDATE_FAILED] = "ERR_PWD_UPDATE_FAILED",
  [NEW_SRV_ERR_RUN_ID_UNDEFINED] = "ERR_RUN_ID_UNDEFINED",
  [NEW_SRV_ERR_INV_RUN_ID] = "ERR_INV_RUN_ID",
  [NEW_SRV_ERR_RUN_ID_OUT_OF_RANGE] = "ERR_RUN_ID_OUT_OF_RANGE",
  [NEW_SRV_ERR_RUNLOG_READ_FAILED] = "ERR_RUNLOG_READ_FAILED",
  [NEW_SRV_ERR_PRINTING_DISABLED] = "ERR_PRINTING_DISABLED",
  [NEW_SRV_ERR_ALREADY_PRINTED] = "ERR_ALREADY_PRINTED",
  [NEW_SRV_ERR_PRINT_QUOTA_EXCEEDED] = "ERR_PRINT_QUOTA_EXCEEDED",
  [NEW_SRV_ERR_PRINTING_FAILED] = "ERR_PRINTING_FAILED",
  [NEW_SRV_ERR_CLIENTS_SUSPENDED] = "ERR_CLIENTS_SUSPENDED",
  [NEW_SRV_ERR_RUN_QUOTA_EXCEEDED] = "ERR_RUN_QUOTA_EXCEEDED",
  [NEW_SRV_ERR_PROB_UNAVAILABLE] = "ERR_PROB_UNAVAILABLE",
  [NEW_SRV_ERR_PROB_DEADLINE_EXPIRED] = "ERR_PROB_DEADLINE_EXPIRED",
  [NEW_SRV_ERR_VARIANT_UNASSIGNED] = "ERR_VARIANT_UNASSIGNED",
  [NEW_SRV_ERR_DUPLICATE_SUBMIT] = "ERR_DUPLICATE_SUBMIT",
  [NEW_SRV_ERR_PROB_ALREADY_SOLVED] = "ERR_PROB_ALREADY_SOLVED",
  [NEW_SRV_ERR_NOT_ALL_REQ_SOLVED] = "ERR_NOT_ALL_REQ_SOLVED",
  [NEW_SRV_ERR_CLARS_DISABLED] = "ERR_CLARS_DISABLED",
  [NEW_SRV_ERR_CLAR_QUOTA_EXCEEDED] = "ERR_CLAR_QUOTA_EXCEEDED",
  [NEW_SRV_ERR_SOURCE_VIEW_DISABLED] = "ERR_SOURCE_VIEW_DISABLED",
  [NEW_SRV_ERR_REPORT_UNAVAILABLE] = "ERR_REPORT_UNAVAILABLE",
  [NEW_SRV_ERR_REPORT_VIEW_DISABLED] = "ERR_REPORT_VIEW_DISABLED",
  [NEW_SRV_ERR_REPORT_NONEXISTANT] = "ERR_REPORT_NONEXISTANT",
  [NEW_SRV_ERR_TEST_NONEXISTANT] = "ERR_TEST_NONEXISTANT",
  [NEW_SRV_ERR_CHECKSUMMING_FAILED] = "ERR_CHECKSUMMING_FAILED",
  [NEW_SRV_ERR_OUTPUT_ERROR] = "ERR_OUTPUT_ERROR",
  [NEW_SRV_ERR_TEST_UNAVAILABLE] = "ERR_TEST_UNAVAILABLE",
  [NEW_SRV_ERR_INV_VARIANT] = "ERR_INV_VARIANT",
  [NEW_SRV_ERR_PWD_GENERATION_FAILED] = "ERR_PWD_GENERATION_FAILED",
  [NEW_SRV_ERR_TEAM_PWD_DISABLED] = "ERR_TEAM_PWD_DISABLED",
  [NEW_SRV_ERR_APPEALS_DISABLED] = "ERR_APPEALS_DISABLED",
  [NEW_SRV_ERR_APPEALS_FINISHED] = "ERR_APPEALS_FINISHED",
  [NEW_SRV_ERR_NOT_VIRTUAL] = "ERR_NOT_VIRTUAL",
  [NEW_SRV_ERR_VIRTUAL_NOT_STARTED] = "ERR_VIRTUAL_NOT_STARTED",
  [NEW_SRV_ERR_UNHANDLED_ACTION] = "ERR_UNHANDLED_ACTION",
  [NEW_SRV_ERR_UNDEFINED_USER_ID_LOGIN] = "ERR_UNDEFINED_USER_ID_LOGIN",
  [NEW_SRV_ERR_INV_PARAM] = "ERR_INV_PARAM",
  [NEW_SRV_ERR_BINARY_FILE] = "ERR_BINARY_FILE",
  [NEW_SRV_ERR_INV_SCORE] = "ERR_INV_SCORE",
  [NEW_SRV_ERR_INV_SCORE_ADJ] = "ERR_INV_SCORE_ADJ",
  [NEW_SRV_ERR_INV_PAGES] = "ERR_INV_PAGES",
  [NEW_SRV_ERR_RUN_READ_ONLY] = "ERR_RUN_READ_ONLY",
  [NEW_SRV_ERR_INV_WARN_TEXT] = "ERR_INV_WARN_TEXT",
  [NEW_SRV_ERR_WARN_TEXT_EMPTY] = "ERR_WARN_TEXT_EMPTY",
  [NEW_SRV_ERR_INV_WARN_CMT] = "ERR_INV_WARN_CMT",
  [NEW_SRV_ERR_SUBMIT_EMPTY] = "ERR_SUBMIT_EMPTY",
  [NEW_SRV_ERR_AUDIT_LOG_NONEXISTANT] = "ERR_AUDIT_LOG_NONEXISTANT",
  [NEW_SRV_ERR_INV_RUN_SELECTION] = "ERR_INV_RUN_SELECTION",
  [NEW_SRV_ERR_INV_DIR_STRUCT] = "ERR_INV_DIR_STRUCT",
  [NEW_SRV_ERR_MKDIR_FAILED] = "ERR_MKDIR_FAILED",
  [NEW_SRV_ERR_TAR_FAILED] = "ERR_TAR_FAILED",
  [NEW_SRV_ERR_FILE_UNSPECIFIED] = "ERR_FILE_UNSPECIFIED",
  [NEW_SRV_ERR_FILE_EMPTY] = "ERR_FILE_EMPTY",
  [NEW_SRV_ERR_TRY_AGAIN] = "ERR_TRY_AGAIN",
  [NEW_SRV_ERR_NOT_SUPPORTED] = "ERR_NOT_SUPPORTED",
  [NEW_SRV_ERR_INV_ACTION] = "ERR_INV_ACTION",
  [NEW_SRV_ERR_INV_CONTEST_ID] = "ERR_INV_CONTEST_ID",
  [NEW_SRV_ERR_INV_ROLE] = "ERR_INV_ROLE",
  [NEW_SRV_ERR_USERLIST_SERVER_DOWN] = "ERR_USERLIST_SERVER_DOWN",
  [NEW_SRV_ERR_INTERNAL] = "ERR_INTERNAL",
  [NEW_SRV_ERR_INV_FILTER_EXPR] = "ERR_INV_FILTER_EXPR",
  [NEW_SRV_ERR_CONTEST_UNLOADED] = "ERR_CONTEST_UNLOADED",
  [NEW_SRV_ERR_PENDING_IMPORT_EXISTS] = "ERR_PENDING_IMPORT_EXISTS",
  [NEW_SRV_ERR_ANSWER_UNSPECIFIED] = "ERR_ANSWER_UNSPECIFIED",
  [NEW_SRV_ERR_LOGIN_BINARY] = "ERR_LOGIN_BINARY",
  [NEW_SRV_ERR_LOGIN_UNSPECIFIED] = "ERR_LOGIN_UNSPECIFIED",
  [NEW_SRV_ERR_LOGIN_INV_CHARS] = "ERR_LOGIN_INV_CHARS",
  [NEW_SRV_ERR_EMAIL_BINARY] = "ERR_EMAIL_BINARY",
  [NEW_SRV_ERR_EMAIL_UNSPECIFIED] = "ERR_EMAIL_UNSPECIFIED",
  [NEW_SRV_ERR_EMAIL_INV_CHARS] = "ERR_EMAIL_INV_CHARS",
  [NEW_SRV_ERR_UL_CONNECT_FAILED] = "ERR_UL_CONNECT_FAILED",
  [NEW_SRV_ERR_PLUGIN_NOT_AVAIL] = "ERR_PLUGIN_NOT_AVAIL",
  [NEW_SRV_ERR_INV_FILE_NAME] = "ERR_INV_FILE_NAME",
  [NEW_SRV_ERR_VIRTUAL_START_FAILED] = "ERR_VIRTUAL_START_FAILED",
  [NEW_SRV_ERR_INV_CHAR] = "ERR_INV_CHAR",
  [NEW_SRV_ERR_DATABASE_FAILED] = "ERR_DATABASE_FAILED",
  [NEW_SRV_ERR_PROB_CONFIG] = "ERR_PROB_CONFIG",
  [NEW_SRV_ERR_PROB_TOO_MANY_ATTEMPTS] = "ERR_PROB_TOO_MANY_ATTEMPTS",
  [NEW_SRV_ERR_INV_SESSION] = "ERR_INV_SESSION",
  [NEW_SRV_ERR_REGISTRATION_INCOMPLETE] = "ERR_REGISTRATION_INCOMPLETE",
  [NEW_SRV_ERR_SERVICE_NOT_AVAILABLE] = "ERR_SERVICE_NOT_AVAILABLE",
  [NEW_SRV_ERR_DISQUALIFIED] = "ERR_DISQUALIFIED",
  [NEW_SRV_ERR_SIMPLE_REGISTERED] = "ERR_SIMPLE_REGISTERED",
  [NEW_SRV_ERR_CNTS_UNAVAILABLE] = "ERR_CNTS_UNAVAILABLE",
  [NEW_SRV_ERR_OPERATION_FAILED] = "ERR_OPERATION_FAILED",
  [NEW_SRV_ERR_INV_TOKEN] = "ERR_INV_TOKEN",
  [NEW_SRV_ERR_INV_UUID] = "ERR_INV_UUID",
  [NEW_SRV_ERR_RATE_EXCEEDED] = "ERR_RATE_EXCEEDED",
  [NEW_SRV_ERR_INV_SUBMIT_ID] = "ERR_INV_SUBMIT_ID",
  [NEW_SRV_ERR_INV_USERPROB_ID] = "ERR_INV_USERPROB_ID",
  [NEW_SRV_ERR_INV_EXT_USER] = "ERR_INV_EXT_USER",
  [NEW_SRV_ERR_INV_NOTIFY] = "ERR_INV_NOTIFY",
};

const unsigned char *
ns_error_title(int error_code)
{
  if (error_code < 0) error_code = -error_code;
  if (error_code <= 0 || error_code >= NEW_SRV_ERR_LAST) return _("Invalid error code");
  return gettext(ns_error_titles[error_code]);
}

const unsigned char *
ns_error_title_2(int error_code)
{
  if (error_code < 0) error_code = -error_code;
  if (error_code <= 0 || error_code >= NEW_SRV_ERR_LAST) return NULL;
  return ns_error_titles[error_code];
}

const unsigned char *
ns_error_symbol(int error_code)
{
  if (error_code < 0) error_code = -error_code;
  if (!error_code) return "";
  if (error_code >= NEW_SRV_ERR_LAST) return "ERR";
  return ns_error_symbols[error_code];
}

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
  vsnprintf(buf2, sizeof(buf2), gettext(s), args);
  va_end(args);
  snprintf(buf, sizeof(buf), "%s.\n", buf2);
  return buf;
}

const unsigned char *
ns_strerror_2(int code, ...)
{
  static unsigned char buf[1024];
  const unsigned char *s = 0;
  va_list args;

  if (code < 0) code = -code;
  if (code >= NEW_SRV_ERR_LAST || !(s = ns_error_messages[code])) {
    snprintf(buf, sizeof(buf), _("Unknown error %d"), code);
    return buf;
  }

  va_start(args, code);
  vsnprintf(buf, sizeof(buf), gettext(s), args);
  va_end(args);
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
    snprintf(buf, size, _("Unknown error %d.\n"), code);
    return buf;
  }

  va_start(args, code);
  vsnprintf(buf2, sizeof(buf2), gettext(s), args);
  va_end(args);
  snprintf(buf, size, "%s.\n", buf2);
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
