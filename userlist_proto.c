/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "userlist_proto.h"

#include <stdio.h>
#include <string.h>

#define _(x) x
// messages to be localized at the caller level
static unsigned char const * const error_map[] =
{
  _("no error"),
  _("error code 1"),
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
  _("this user is not registered for this contest"),
  _("this field cannot be deleted"),
  _("this field cannot be changed"),
  _("contest deadline exceeded"),
  _("peer closed connection"),
  _("e-mail sending failed"),
  _("incomplete registration"),
  _("invalid field"),
  _("transitive user contest sharing"),
  _("unspecified error"),

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

static const unsigned char * const requests[] =
{
  [ULS_PASS_FD]                   = "PASS_FD",
  [ULS_STOP]                      = "STOP",
  [ULS_RESTART]                   = "RESTART",
  [ULS_REGISTER_NEW]              = "REGISTER_NEW",
  [ULS_DO_LOGIN]                  = "DO_LOGIN",
  [ULS_CHECK_COOKIE]              = "CHECK_COOKIE",
  [ULS_DO_LOGOUT]                 = "DO_LOGOUT",
  [ULS_GET_USER_INFO]             = "GET_USER_INFO",
  [ULS_SET_USER_INFO]             = "SET_USER_INFO",
  [ULS_SET_PASSWD]                = "SET_PASSWD",
  [ULS_GET_USER_CONTESTS]         = "GET_USER_CONTESTS",
  [ULS_REGISTER_CONTEST]          = "REGISTER_CONTEST",
  [ULS_DELETE_MEMBER]             = "DELETE_MEMBER",
  [ULS_LIST_USERS]                = "LIST_USERS",
  [ULS_MAP_CONTEST]               = "MAP_CONTEST",
  [ULS_ADMIN_PROCESS]             = "ADMIN_PROCESS",
  [ULS_GENERATE_TEAM_PASSWORDS]   = "GENERATE_TEAM_PASSWORDS",
  [ULS_TEAM_LOGIN]                = "TEAM_LOGIN",
  [ULS_TEAM_CHECK_COOKIE]         = "TEAM_CHECK_COOKIE",
  [ULS_GET_CONTEST_NAME]          = "GET_CONTEST_NAME",
  [ULS_TEAM_SET_PASSWD]           = "TEAM_SET_PASSWD",
  [ULS_LIST_ALL_USERS]            = "LIST_ALL_USERS",
  [ULS_EDIT_REGISTRATION]         = "EDIT_REGISTRATION",
  [ULS_EDIT_FIELD]                = "EDIT_FIELD",
  [ULS_DELETE_FIELD]              = "DELETE_FIELD",
  [ULS_ADD_FIELD]                 = "ADD_FIELD",
  [ULS_GET_UID_BY_PID]            = "GET_UID_BY_PID",
  [ULS_PRIV_LOGIN]                = "PRIV_LOGIN",
  [ULS_PRIV_CHECK_COOKIE]         = "PRIV_CHECK_COOKIE",
  [ULS_DUMP_DATABASE]             = "DUMP_DATABASE",
  [ULS_PRIV_GET_USER_INFO]        = "PRIV_GET_USER_INFO",
  [ULS_PRIV_SET_USER_INFO]        = "PRIV_SET_USER_INFO",
  [ULS_PRIV_REGISTER_CONTEST]     = "PRIV_REGISTER_CONTEST",
  [ULS_GENERATE_PASSWORDS]        = "GENERATE_PASSWORDS",
  [ULS_CLEAR_TEAM_PASSWORDS]      = "CLEAR_TEAM_PASSWORDS",
  [ULS_LIST_STANDINGS_USERS]      = "LIST_STANDINGS_USERS",
  [ULS_GET_UID_BY_PID_2]          = "GET_UID_BY_PID_2",
  [ULS_IS_VALID_COOKIE]           = "IS_VALID_COOKIE",
  [ULS_DUMP_WHOLE_DATABASE]       = "DUMP_WHOLE_DATABASE",
  [ULS_RANDOM_PASSWD]             = "RANDOM_PASSWD",
  [ULS_RANDOM_TEAM_PASSWD]        = "RANDOM_TEAM_PASSWD",
  [ULS_COPY_TO_TEAM]              = "COPY_TO_TEAM",
  [ULS_COPY_TO_REGISTER]          = "COPY_TO_REGISTER",
  [ULS_FIX_PASSWORD]              = "FIX_PASSWORD",
  [ULS_LOOKUP_USER]               = "LOOKUP_USER",
  [ULS_REGISTER_NEW_2]            = "REGISTER_NEW_2",
  [ULS_DELETE_USER]               = "DELETE_USER",
  [ULS_DELETE_COOKIE]             = "DELETE_COOKIE",
  [ULS_DELETE_USER_INFO]          = "DELETE_USER_INFO",
  [ULS_CREATE_USER]               = "CREATE_USER",
  [ULS_CREATE_MEMBER]             = "CREATE_MEMBER",
  [ULS_PRIV_DELETE_MEMBER]        = "PRIV_DELETE_MEMBER",
  [ULS_PRIV_CHECK_USER]           = "PRIV_CHECK_USER",
  [ULS_PRIV_GET_COOKIE]           = "PRIV_GET_COOKIE",
  [ULS_LOOKUP_USER_ID]            = "LOOKUP_USER_ID",
  [ULS_TEAM_CHECK_USER]           = "TEAM_CHECK_USER",
  [ULS_TEAM_GET_COOKIE]           = "TEAM_GET_COOKIE",
  [ULS_ADD_NOTIFY]                = "ADD_NOTIFY",
  [ULS_DEL_NOTIFY]                = "DEL_NOTIFY",
  [ULS_SET_COOKIE_LOCALE]         = "SET_COOKIE_LOCALE",
  [ULS_PRIV_SET_REG_PASSWD]       = "PRIV_SET_REG_PASSWD",
  [ULS_PRIV_SET_TEAM_PASSWD]      = "PRIV_SET_TEAM_PASSWD",
  [ULS_GENERATE_TEAM_PASSWORDS_2] = "GENERATE_TEAM_PASSWORDS_2",
  [ULS_GENERATE_PASSWORDS_2]      = "GENERATE_PASSWORDS_2",
  [ULS_GET_DATABASE]              = "GET_DATABASE",
  [ULS_COPY_USER_INFO]            = "COPY_USER_INFO",
  [ULS_RECOVER_PASSWORD_1]        = "RECOVER_PASSWORD_1",
  [ULS_RECOVER_PASSWORD_2]        = "RECOVER_PASSWORD_2",
  [ULS_PRIV_COOKIE_LOGIN]         = "PRIV_COOKIE_LOGIN",
  [ULS_CHECK_USER]                = "CHECK_USER",
  [ULS_REGISTER_CONTEST_2]        = "REGISTER_CONTEST_2",
  [ULS_GET_COOKIE]                = "GET_COOKIE",
  [ULS_EDIT_FIELD_SEQ]            = "EDIT_FIELD_SEQ",
  [ULS_MOVE_MEMBER]               = "MOVE_MEMBER",
  [ULS_IMPORT_CSV_USERS]          = "IMPORT_CSV_USERS",

  NULL,
};

int
userlist_str_to_request(const unsigned char *reqs)
{
  int i;

  if (!reqs) return -1;
  for (i = 1; requests[i]; i++)
    if (!strcmp(requests[i], reqs))
      return i;
  return -1;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
