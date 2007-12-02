/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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

#include <Python.h>

#include "config.h"
#include "userlist_clnt.h"
#include "userlist_proto.h"
#include "userlist.h"
#include "xml_utils.h"

/* userlist_clnt implementation status
 *
 * userlist_clnt_register_new
 * userlist_clnt_register_new_2			OK
 * userlist_clnt_login				OK
 * userlist_clnt_lookup_user			OK
 * userlist_clnt_lookup_user_id			OK
 * userlist_clnt_get_cookie			OK
 * userlist_clnt_set_cookie			OK
 * userlist_clnt_lookup_cookie			OK
 * userlist_clnt_team_cookie			OK
 * userlist_clnt_get_info			OK
 * userlist_clnt_get_database			OK
 * userlist_clnt_get_param
 * userlist_clnt_set_info
 * userlist_clnt_set_passwd			OK
 * userlist_clnt_get_contests
 * userlist_clnt_register_contest		OK
 * userlist_clnt_delete_info			OK
 * userlist_clnt_move_member			OK
 * userlist_clnt_list_users
 * userlist_clnt_admin_process			OK
 * userlist_clnt_map_contest
 * userlist_clnt_generate_team_passwd
 * userlist_clnt_list_all_users			OK
 * userlist_clnt_change_registration		OK
 * userlist_clnt_edit_field			OK
 * userlist_clnt_edit_field_seq
 * userlist_clnt_delete_field			OK
 * userlist_clnt_delete_cookie			OK
 * userlist_clnt_create_user			OK
 * userlist_clnt_create_member			OK
 * userlist_clnt_copy_user_info			OK
 * userlist_clnt_get_uid_by_pid
 * userlist_clnt_get_uid_by_pid_2
 * userlist_clnt_priv_login			OK
 * userlist_clnt_priv_cookie
 * userlist_clnt_logout				OK
 * userlist_clnt_dump_database
 * userlist_clnt_cnts_passwd_op			OK
 * userlist_clnt_notify
 * userlist_clnt_read_notification
 * userlist_clnt_bytes_available
 * userlist_clnt_set_notification_callback	
 * userlist_clnt_recover_passwd_2
 * userlist_clnt_control			OK
 * userlist_clnt_priv_cookie_login
 * userlist_clnt_import_csv_users		OK
 */

/*
    ULS_PASS_FD,				-
    ULS_STOP,					OK
    ULS_RESTART,				OK
    ULS_REGISTER_NEW,
    ULS_DO_LOGIN,				OK
    ULS_CHECK_COOKIE,				OK	FIX IT!
    ULS_DO_LOGOUT,				OK
    ULS_GET_USER_INFO,				OK
    ULS_SET_USER_INFO,
    ULS_SET_PASSWD,				OK
    ULS_GET_USER_CONTESTS,
    ULS_REGISTER_CONTEST,			OK
    ULS_DELETE_MEMBER,				OK
    ULS_LIST_USERS,
    ULS_MAP_CONTEST,
    ULS_ADMIN_PROCESS,				OK
    ULS_GENERATE_TEAM_PASSWORDS,
    ULS_TEAM_LOGIN,				OK
    ULS_TEAM_CHECK_COOKIE,			OK	FIX IT!
    ULS_GET_CONTEST_NAME,
    ULS_TEAM_SET_PASSWD,			OK
    ULS_LIST_ALL_USERS,				OK
    ULS_EDIT_REGISTRATION,			OK
    ULS_EDIT_FIELD,				OK
    ULS_DELETE_FIELD,				OK
    ULS_ADD_FIELD,				*
    ULS_GET_UID_BY_PID,
    ULS_PRIV_LOGIN,				OK
    ULS_PRIV_CHECK_COOKIE,
    ULS_DUMP_DATABASE,
    ULS_PRIV_GET_USER_INFO,			OK
    ULS_PRIV_SET_USER_INFO,
    ULS_PRIV_REGISTER_CONTEST,			OK
    ULS_GENERATE_PASSWORDS,
    ULS_CLEAR_TEAM_PASSWORDS,			OK
    ULS_LIST_STANDINGS_USERS,			OK
    ULS_GET_UID_BY_PID_2,
    ULS_IS_VALID_COOKIE,			*
    ULS_DUMP_WHOLE_DATABASE,
    ULS_RANDOM_PASSWD,				OK
    ULS_RANDOM_TEAM_PASSWD,			OK
    ULS_COPY_TO_TEAM,				OK
    ULS_COPY_TO_REGISTER,			OK
    ULS_FIX_PASSWORD,				OK
    ULS_LOOKUP_USER,				OK
    ULS_REGISTER_NEW_2,				OK
    ULS_DELETE_USER,				OK
    ULS_DELETE_COOKIE,				OK
    ULS_DELETE_USER_INFO,			*
    ULS_CREATE_USER,				OK
    ULS_CREATE_MEMBER,				OK
    ULS_PRIV_DELETE_MEMBER,			OK
    ULS_PRIV_CHECK_USER,			OK
    ULS_PRIV_GET_COOKIE,			OK
    ULS_LOOKUP_USER_ID,				OK
    ULS_TEAM_CHECK_USER,			OK
    ULS_TEAM_GET_COOKIE,			OK
    ULS_ADD_NOTIFY,
    ULS_DEL_NOTIFY,
    ULS_SET_COOKIE_LOCALE,			OK
    ULS_PRIV_SET_REG_PASSWD,			OK
    ULS_PRIV_SET_TEAM_PASSWD,			OK
    ULS_GENERATE_TEAM_PASSWORDS_2,		OK
    ULS_GENERATE_PASSWORDS_2,			OK
    ULS_GET_DATABASE,				OK
    ULS_COPY_USER_INFO,				OK
    ULS_RECOVER_PASSWORD_1,
    ULS_RECOVER_PASSWORD_2,
    ULS_PRIV_COOKIE_LOGIN,
    ULS_CHECK_USER,				OK
    ULS_REGISTER_CONTEST_2,			OK
    ULS_GET_COOKIE,				OK
    ULS_EDIT_FIELD_SEQ,
    ULS_MOVE_MEMBER,				OK
    ULS_IMPORT_CSV_USERS,			OK
 */

static const struct
{
  const unsigned char *name;
  int value;
} user_field_map[] =
{
  { "NN_ID", USERLIST_NN_ID },
  { "NN_IS_PRIVILEGED", USERLIST_NN_IS_PRIVILEGED },
  { "NN_IS_INVISIBLE", USERLIST_NN_IS_INVISIBLE },
  { "NN_IS_BANNED", USERLIST_NN_IS_BANNED },
  { "NN_IS_LOCKED", USERLIST_NN_IS_LOCKED },
  { "NN_SHOW_LOGIN", USERLIST_NN_SHOW_LOGIN },
  { "NN_SHOW_EMAIL", USERLIST_NN_SHOW_EMAIL },
  { "NN_READ_ONLY", USERLIST_NN_READ_ONLY },
  { "NN_NEVER_CLEAN", USERLIST_NN_NEVER_CLEAN },
  { "NN_SIMPLE_REGISTRATION", USERLIST_NN_SIMPLE_REGISTRATION },
  { "NN_LOGIN", USERLIST_NN_LOGIN },
  { "NN_EMAIL", USERLIST_NN_EMAIL },
  { "NN_PASSWD", USERLIST_NN_PASSWD },
  { "NN_REGISTRATION_TIME", USERLIST_NN_REGISTRATION_TIME },
  { "NN_LAST_LOGIN_TIME", USERLIST_NN_LAST_LOGIN_TIME },
  { "NN_LAST_CHANGE_TIME", USERLIST_NN_LAST_CHANGE_TIME },
  { "NN_LAST_PWDCHANGE_TIME", USERLIST_NN_LAST_PWDCHANGE_TIME },
  { "NC_CNTS_READ_ONLY", USERLIST_NC_CNTS_READ_ONLY },
  { "NC_NAME", USERLIST_NC_NAME },
  { "NC_TEAM_PASSWD", USERLIST_NC_TEAM_PASSWD },
  { "NC_INST", USERLIST_NC_INST },
  { "NC_INST_EN", USERLIST_NC_INST_EN },
  { "NC_INSTSHORT", USERLIST_NC_INSTSHORT },
  { "NC_INSTSHORT_EN", USERLIST_NC_INSTSHORT_EN },
  { "NC_INSTNUM", USERLIST_NC_INSTNUM },
  { "NC_FAC", USERLIST_NC_FAC },
  { "NC_FAC_EN", USERLIST_NC_FAC_EN },
  { "NC_FACSHORT", USERLIST_NC_FACSHORT },
  { "NC_FACSHORT_EN", USERLIST_NC_FACSHORT_EN },
  { "NC_HOMEPAGE", USERLIST_NC_HOMEPAGE },
  { "NC_CITY", USERLIST_NC_CITY },
  { "NC_CITY_EN", USERLIST_NC_CITY_EN },
  { "NC_COUNTRY", USERLIST_NC_COUNTRY },
  { "NC_COUNTRY_EN", USERLIST_NC_COUNTRY_EN },
  { "NC_REGION", USERLIST_NC_REGION },
  { "NC_AREA", USERLIST_NC_AREA },
  { "NC_ZIP", USERLIST_NC_ZIP },
  { "NC_STREET", USERLIST_NC_STREET },
  { "NC_LOCATION", USERLIST_NC_LOCATION },
  { "NC_SPELLING", USERLIST_NC_SPELLING },
  { "NC_PRINTER_NAME", USERLIST_NC_PRINTER_NAME },
  { "NC_EXAM_ID", USERLIST_NC_EXAM_ID },
  { "NC_EXAM_CYPHER", USERLIST_NC_EXAM_CYPHER },
  { "NC_LANGUAGES", USERLIST_NC_LANGUAGES },
  { "NC_PHONE", USERLIST_NC_PHONE },
  { "NC_FIELD0", USERLIST_NC_FIELD0 },
  { "NC_FIELD1", USERLIST_NC_FIELD1 },
  { "NC_FIELD2", USERLIST_NC_FIELD2 },
  { "NC_FIELD3", USERLIST_NC_FIELD3 },
  { "NC_FIELD4", USERLIST_NC_FIELD4 },
  { "NC_FIELD5", USERLIST_NC_FIELD5 },
  { "NC_FIELD6", USERLIST_NC_FIELD6 },
  { "NC_FIELD7", USERLIST_NC_FIELD7 },
  { "NC_FIELD8", USERLIST_NC_FIELD8 },
  { "NC_FIELD9", USERLIST_NC_FIELD9 },
  { "NC_CREATE_TIME", USERLIST_NC_CREATE_TIME },
  { "NC_LAST_LOGIN_TIME", USERLIST_NC_LAST_LOGIN_TIME },
  { "NC_LAST_CHANGE_TIME", USERLIST_NC_LAST_CHANGE_TIME },
  { "NC_LAST_PWDCHANGE_TIME", USERLIST_NC_LAST_PWDCHANGE_TIME },
  { "NM_SERIAL", USERLIST_NM_SERIAL },
  { "NM_STATUS", USERLIST_NM_STATUS },
  { "NM_GENDER", USERLIST_NM_GENDER },
  { "NM_GRADE", USERLIST_NM_GRADE },
  { "NM_FIRSTNAME", USERLIST_NM_FIRSTNAME },
  { "NM_FIRSTNAME_EN", USERLIST_NM_FIRSTNAME_EN },
  { "NM_MIDDLENAME", USERLIST_NM_MIDDLENAME },
  { "NM_MIDDLENAME_EN", USERLIST_NM_MIDDLENAME_EN },
  { "NM_SURNAME", USERLIST_NM_SURNAME },
  { "NM_SURNAME_EN", USERLIST_NM_SURNAME_EN },
  { "NM_GROUP", USERLIST_NM_GROUP },
  { "NM_GROUP_EN", USERLIST_NM_GROUP_EN },
  { "NM_EMAIL", USERLIST_NM_EMAIL },
  { "NM_HOMEPAGE", USERLIST_NM_HOMEPAGE },
  { "NM_OCCUPATION", USERLIST_NM_OCCUPATION },
  { "NM_OCCUPATION_EN", USERLIST_NM_OCCUPATION_EN },
  { "NM_DISCIPLINE", USERLIST_NM_DISCIPLINE },
  { "NM_INST", USERLIST_NM_INST },
  { "NM_INST_EN", USERLIST_NM_INST_EN },
  { "NM_INSTSHORT", USERLIST_NM_INSTSHORT },
  { "NM_INSTSHORT_EN", USERLIST_NM_INSTSHORT_EN },
  { "NM_FAC", USERLIST_NM_FAC },
  { "NM_FAC_EN", USERLIST_NM_FAC_EN },
  { "NM_FACSHORT", USERLIST_NM_FACSHORT },
  { "NM_FACSHORT_EN", USERLIST_NM_FACSHORT_EN },
  { "NM_PHONE", USERLIST_NM_PHONE },
  { "NM_CREATE_TIME", USERLIST_NM_CREATE_TIME },
  { "NM_LAST_CHANGE_TIME", USERLIST_NM_LAST_CHANGE_TIME },
  { "NM_BIRTH_DATE", USERLIST_NM_BIRTH_DATE },
  { "NM_ENTRY_DATE", USERLIST_NM_ENTRY_DATE },
  { "NM_GRADUATION_DATE", USERLIST_NM_GRADUATION_DATE },

  { 0 },
};

static int
str_to_user_field_code(const unsigned char *str)
{
  int i;

  for (i = 0; user_field_map[i].name; i++)
    if (!strcmp(user_field_map[i].name, str))
      return user_field_map[i].value;
  return -1;
}

typedef struct
{
  PyObject_HEAD /* ; */
  /* Type-specific fields go here. */
  userlist_clnt_t clnt;
} UlObject;

static PyObject *
Ul_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  UlObject *self = (UlObject *) type->tp_alloc(type, 0);

  if (self) {
    self->clnt = 0;
  }
  return (PyObject*) self;
}

static int
Ul_init(UlObject *self, PyObject *args, PyObject *kwds)
{
  const char *socket_path = 0;
  static char * kwlist[] = { "path", NULL };

  self->clnt = userlist_clnt_close(self->clnt);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|s", kwlist, &socket_path))
    return -1;

#if defined EJUDGE_SOCKET_PATH
  if (!socket_path) socket_path = EJUDGE_SOCKET_PATH;
#endif /* EJUDGE_SOCKET_PATH */

  if (!socket_path) {
    PyErr_SetString(PyExc_IOError, "socket path is undefined");
    return -1;
  }

  if (!(self->clnt = userlist_clnt_open(socket_path))) {
    // assume, that python exception is already thrown during opening
    // PyErr_SetString(PyExc_IOError, "cannot open connection");
    return -1;
  }

  return 0;
}

static void
Ul_dealloc(UlObject *self)
{
  self->clnt = userlist_clnt_close(self->clnt);
}

static PyObject *
Ul_adminProcess(UlObject *self)
{
  int uid = 0, r;
  unsigned char *login = 0, *name = 0;
  PyObject *val = 0;

  if (!self->clnt) {
    PyErr_SetString(PyExc_IOError, "connection is not opened");
    return 0;
  }

  if ((r = userlist_clnt_admin_process(self->clnt, &uid, &login, &name)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }

  val = Py_BuildValue("{s:i,s:s,s:s}",
                      "user_id", uid, "login", login, "name", name);
  free(login);
  free(name);
  return val;
}

static PyObject *
Ul_do_login(int cmd, UlObject *self, PyObject *args)
{
  int ssl_flag, contest_id, locale_id, r, uid;
  const char *ip_str, *login, *password;
  unsigned char *name = 0;
  ej_ip_t ip_val;
  ej_cookie_t sid;
  PyObject *val = 0;

  if (!PyArg_ParseTuple(args, "siiiss", &ip_str, &ssl_flag,
                        &contest_id, &locale_id, &login, &password))
    return 0;

  if (xml_parse_ip(0, -1, 0, ip_str, &ip_val) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid IP");
    return 0;
  }

  if ((r = userlist_clnt_login(self->clnt, cmd, ip_val, ssl_flag, contest_id,
                               locale_id, login, password,
                               &uid, &sid, &name)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }

  val = Py_BuildValue("{s:i,s:K,s:s}",
                      "user_id", uid, "sid", sid, "name", name);

  free(name);
  return val;
}

static PyObject *
Ul_login(UlObject *self, PyObject *args)
{
  return Ul_do_login(ULS_DO_LOGIN, self, args);
}
static PyObject *
Ul_contestLogin(UlObject *self, PyObject *args)
{
  return Ul_do_login(ULS_TEAM_LOGIN, self, args);
}
static PyObject *
Ul_checkUser(UlObject *self, PyObject *args)
{
  return Ul_do_login(ULS_CHECK_USER, self, args);
}
static PyObject *
Ul_checkContestUser(UlObject *self, PyObject *args)
{
  return Ul_do_login(ULS_TEAM_CHECK_USER, self, args);
}

static PyObject *
Ul_registerNew2(UlObject *self, PyObject *args)
{
  const char *ip_str = 0, *login = 0, *email = 0, *self_url = 0;
  int ssl_flag = 0, contest_id = 0, locale_id = 0, action = 0, r, user_id = 0;
  ej_ip_t ip_val = 0;
  unsigned char *password = 0, *login_out = 0;
  PyObject *val = 0;

  if (!PyArg_ParseTuple(args, "siiiisss", &ip_str,
                        &ssl_flag, &contest_id, &locale_id, &action,
                        &login, &email, &self_url))
    return 0;

  if (xml_parse_ip(0, -1, 0, ip_str, &ip_val) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid IP");
    return 0;
  }

  if ((r = userlist_clnt_register_new_2(self->clnt, ip_val, ssl_flag,
                                        contest_id, locale_id, action,
                                        login, email, self_url,
                                        &user_id, &login_out, &password)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }

  val = Py_BuildValue("{s:i,s:s,s:s}",
                      "user_id", user_id, "login", login_out,
                      "password", password);

  free(login_out);
  free(password);
  return val;
}

static PyObject *
Ul_privCreateUser(UlObject *self, PyObject *args)
{
  const char *login = 0;
  int r, user_id = 0;

  if (!PyArg_ParseTuple(args, "z", &login))
    return 0;
  if ((r = userlist_clnt_create_user(self->clnt, login, &user_id)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", user_id);
}

static PyObject *
Ul_privEditField(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, serial = 0, field_id, r;
  const char *field_str = 0, *value = 0;

  if (!PyArg_ParseTuple(args, "iiiss", &user_id, &contest_id, &serial,
                        &field_str, &value))
    return 0;
  if ((field_id = str_to_user_field_code(field_str)) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid field");
    return 0;
  }
  if ((r = userlist_clnt_edit_field(self->clnt, user_id, contest_id,
                                    serial, field_id, value)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static const unsigned char * const status_map[] =
{
  [0] = "REMOVE",
  [1] = "NOP",
  [USERLIST_REG_OK+2] = "OK",
  [USERLIST_REG_PENDING+2] = "PENDING",
  [USERLIST_REG_REJECTED+2] = "REJECTED",
  NULL,
};
static int
str_to_registration_status(const unsigned char *str)
{
  int i;

  for (i = 0; status_map[i]; i++)
    if (!strcmp(status_map[i], str))
      return i - 2;
  return -3;
}

static const unsigned char * const operation_map[] =
{
  "NOP", "SET", "CLEAR", "FLIP", NULL,
};
static int
str_to_registration_op(const unsigned char *str)
{
  int i;

  for (i = 0; operation_map[i]; i++)
    if (!strcmp(operation_map[i], str))
      return i;
  return -1;
}

static PyObject *
Ul_privChangeContestReg(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, flags = 0, status_val, cmd_val, r;
  const char *cmd_str = 0, *status_str = 0;

  if (!PyArg_ParseTuple(args, "iizzi", &user_id, &contest_id, &status_str,
                        &cmd_str, &flags))
    return 0;
  if (status_str) {
    if ((status_val = str_to_registration_status(status_str)) < -2) {
      PyErr_SetString(PyExc_ValueError, "invalid status");
      return 0;
    }
  } else {
    status_val = -1;
  }
  if (cmd_str) {
    if ((cmd_val = str_to_registration_op(cmd_str)) < 0) {
      PyErr_SetString(PyExc_ValueError, "invalid operation");
      return 0;
    }
  } else {
    cmd_val = 0;
  }
  if ((r = userlist_clnt_change_registration(self->clnt, user_id, contest_id,
                                             status_val, cmd_val, flags)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_registerContest(UlObject *self, PyObject *args)
{
  int contest_id = 0, r, ssl_flag = 0;
  ej_ip_t ip_val = 0;
  const char *ip_str = 0;

  if (!PyArg_ParseTuple(args, "izi", &contest_id, &ip_str, &ssl_flag))
    return 0;
  if (ip_str && xml_parse_ip(0, -1, 0, ip_str, &ip_val) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid IP");
    return 0;
  }
  if ((r = userlist_clnt_register_contest(self->clnt, ULS_REGISTER_CONTEST,
                                          0, contest_id,
                                          ip_val, ssl_flag)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_privForcedRegisterContest(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, r;

  if (!PyArg_ParseTuple(args, "ii", &user_id, &contest_id))
    return 0;
  if ((r = userlist_clnt_register_contest(self->clnt, ULS_PRIV_REGISTER_CONTEST,
                                          user_id, contest_id, 0, 0)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_privRegisterContest(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, r, ssl_flag = 0;
  ej_ip_t ip_val = 0;
  const char *ip_str = 0;

  if (!PyArg_ParseTuple(args,"iizi",&user_id,&contest_id,&ip_str,&ssl_flag))
    return 0;
  if (ip_str && xml_parse_ip(0, -1, 0, ip_str, &ip_val) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid IP");
    return 0;
  }
  if ((r = userlist_clnt_register_contest(self->clnt, ULS_REGISTER_CONTEST_2,
                                          user_id, contest_id,
                                          ip_val, ssl_flag)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_privLookupUser(UlObject *self, PyObject *args)
{
  const char *login = 0;
  unsigned char *name = 0;
  int user_id = 0, contest_id = 0, r;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "si", &login, &contest_id))
    return 0;
  if ((r = userlist_clnt_lookup_user(self->clnt, login, contest_id,
                                     &user_id, &name)) < 0) {
    if (r == -ULS_ERR_INVALID_LOGIN) {
      Py_RETURN_NONE;
    }
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("{s:i,s:s}", "user_id", user_id, "name", name);
  free(name);
  return val;
}

static PyObject *
Ul_privLookupUserId(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, r;
  unsigned char *login = 0, *name = 0;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "ii", &user_id, &contest_id))
    return 0;
  if ((r = userlist_clnt_lookup_user_id(self->clnt, user_id, contest_id,
                                     &login, &name)) < 0) {
    if (r == -ULS_ERR_BAD_UID) {
      Py_RETURN_NONE;
    }
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("{s:s,s:s}", "login", login, "name", name);
  free(login);
  free(name);
  return val;
}

static PyObject *
Ul_privDeleteField(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, serial = 0, field_val, r;
  const char *field_str = 0;

  if (!PyArg_ParseTuple(args, "iiii",
                        &user_id, &contest_id, &serial, &field_str))
    return 0;
  if ((field_val = str_to_user_field_code(field_str)) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid field");
    return 0;
  }
  if ((r = userlist_clnt_delete_field(self->clnt, user_id, contest_id,
                                      serial, field_val)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_privCopyUserInfo(UlObject *self, PyObject *args)
{
  int user_id = 0, cnts_from = 0, cnts_to = 0, r;

  if (!PyArg_ParseTuple(args, "iii", &user_id, &cnts_from, &cnts_to))
    return 0;
  if ((r = userlist_clnt_copy_user_info(self->clnt, user_id, cnts_from,
                                        cnts_to)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_do_get_cookie(int cmd, UlObject *self, PyObject *args)
{
  const char *ip_str = 0;
  unsigned char *login = 0, *name = 0;
  ej_cookie_t sid = 0;
  ej_ip_t ip_val = 0;
  int ssl_flag = 0, user_id = 0, contest_id = 0, locale_id = 0,
    priv_level = 0, role = 0, is_contest = 0, reg_status = 0,
    reg_flags = 0, r;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "siK", &ip_str, &ssl_flag, &sid))
    return 0;
  if (xml_parse_ip(0, -1, 0, ip_str, &ip_val) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid IP");
    return 0;
  }
  if ((r = userlist_clnt_get_cookie
       (self->clnt, cmd, ip_val, ssl_flag, sid,
        &user_id, &contest_id, &locale_id, &priv_level,
        &role, &is_contest, &reg_status, &reg_flags, &login, &name)) < 0) {
    if (r == -ULS_ERR_NO_COOKIE) {
      Py_RETURN_NONE;
    }
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("{s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:i,s:s,s:s}",
                      "user_id", user_id,
                      "contest_id", contest_id,
                      "locale_id", locale_id,
                      "priv_level", priv_level,
                      "role", role,
                      "is_contest", is_contest,
                      "reg_status", reg_status,
                      "reg_flags", reg_flags,
                      "login", login,
                      "name", name);
  free(login);
  free(name);
  return val;
}

static PyObject *
Ul_getCookie(UlObject *self, PyObject *args)
{
  return Ul_do_get_cookie(ULS_GET_COOKIE, self, args);
}
static PyObject *
Ul_getContestCookie(UlObject *self, PyObject *args)
{
  return Ul_do_get_cookie(ULS_TEAM_GET_COOKIE, self, args);
}
static PyObject *
Ul_getPrivCookie(UlObject *self, PyObject *args)
{
  return Ul_do_get_cookie(ULS_PRIV_GET_COOKIE, self, args);
}

static PyObject *
Ul_logout(UlObject *self, PyObject *args)
{
  int ssl_flag = 0, r;
  ej_ip_t ip_val = 0;
  ej_cookie_t sid = 0;
  const char *ip_str = 0;

  if (!PyArg_ParseTuple(args, "siK", &ip_str, &ssl_flag, &sid))
    return 0;
  if (xml_parse_ip(0, -1, 0, ip_str, &ip_val) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid IP");
    return 0;
  }
  if ((r = userlist_clnt_logout(self->clnt, ULS_DO_LOGOUT, ip_val, ssl_flag, sid)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_do_priv_login(int cmd, UlObject *self, PyObject *args)
{
  PyObject *val;
  const char *ip_str = 0, *login = 0, *password = 0;
  ej_ip_t ip_val = 0;
  ej_cookie_t sid = 0;
  unsigned char *name = 0;
  int ssl_flag = 0, contest_id = 0, locale_id = 0, priv_level = 0, role = 0, user_id = 0, priv_level_out = 0, r;

  if (!PyArg_ParseTuple(args, "siiiiiss", &ip_str, &ssl_flag, &contest_id, &locale_id, &priv_level, &role, &login, &password))
    return 0;
  if (xml_parse_ip(0, -1, 0, ip_str, &ip_val) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid IP");
    return 0;
  }
  if ((r = userlist_clnt_priv_login(self->clnt, cmd, ip_val, ssl_flag, contest_id, locale_id, priv_level, role, login, password, &user_id, &sid, &priv_level_out, &name)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("{s:i,s:K,s:i,s:s}","user_id", user_id, "sid", sid, "priv_level", priv_level_out, "name", name);
  free(name);
  return val;
}

static PyObject *
Ul_privLogin(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_priv_login(ULS_PRIV_LOGIN, self, args);
}
static PyObject *
Ul_checkPrivUser(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_priv_login(ULS_PRIV_CHECK_USER, self, args);
}

static PyObject *
Ul_do_set_cookie(int cmd, UlObject *self, PyObject *args)
{
  ej_cookie_t sid = 0;
  int locale_id = 0, r;

  if (!PyArg_ParseTuple(args, "Ki", &sid, &locale_id))
    return 0;
  if ((r = userlist_clnt_set_cookie(self->clnt, cmd, sid, locale_id)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}
static PyObject *
Ul_setCookieLocale(UlObject *self, PyObject *args)
{
  return Ul_do_set_cookie(ULS_SET_COOKIE_LOCALE, self, args);
}

static PyObject *
Ul_do_set_passwd(int cmd, UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, r;
  const char *old_pwd = 0, *new_pwd = 0;

  if (!PyArg_ParseTuple(args, "iiss", &user_id, &contest_id, &old_pwd,&new_pwd))
    return 0;
  if ((r = userlist_clnt_set_passwd(self->clnt, cmd, user_id, contest_id, old_pwd, new_pwd)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}
static PyObject *
Ul_setPassword(UlObject *self, PyObject *args)
{
  return Ul_do_set_passwd(ULS_SET_PASSWD, self, args);
}
static PyObject *
Ul_setContestPassword(UlObject *self, PyObject *args)
{
  return Ul_do_set_passwd(ULS_TEAM_SET_PASSWD, self, args);
}
static PyObject *
Ul_privSetContestPassword(UlObject *self, PyObject *args)
{
  return Ul_do_set_passwd(ULS_PRIV_SET_TEAM_PASSWD, self, args);
}

static PyObject *
Ul_privSetPassword(UlObject *self, PyObject *args)
{
  int user_id = 0, r;
  const char *old_pwd = 0, *new_pwd = 0;

  if (!PyArg_ParseTuple(args, "iss", &user_id, &old_pwd, &new_pwd))
    return 0;
  if ((r = userlist_clnt_set_passwd(self->clnt, ULS_PRIV_SET_REG_PASSWD,
                                    user_id, 0, old_pwd, new_pwd)) < 0){
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_stop(UlObject *self)
{
  int r;

  if ((r = userlist_clnt_control(self->clnt, ULS_STOP)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}
static PyObject *
Ul_restart(UlObject *self)
{
  int r;

  if ((r = userlist_clnt_control(self->clnt, ULS_RESTART)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_deleteCookie(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, r;
  ej_cookie_t sid = 0;

  if (!PyArg_ParseTuple(args, "iiK", &user_id, &contest_id, &sid))
    return 0;
  if ((r = userlist_clnt_delete_cookie(self->clnt, user_id, contest_id,
                                       sid)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_deleteMember(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, serial = 0, r;

  if (!PyArg_ParseTuple(args, "iii", &user_id, &contest_id, &serial))
    return 0;
  if ((r = userlist_clnt_delete_info(self->clnt, ULS_DELETE_MEMBER,
                                     user_id, contest_id, serial)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_privDeleteMember(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, serial = 0, r;

  if (!PyArg_ParseTuple(args, "iii", &user_id, &contest_id, &serial))
    return 0;
  if ((r = userlist_clnt_delete_info(self->clnt, ULS_PRIV_DELETE_MEMBER,
                                     user_id, contest_id, serial)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}
static PyObject *
Ul_privDeleteUser(UlObject *self, PyObject *args)
{
  int user_id = 0, r;

  if (!PyArg_ParseTuple(args, "i", &user_id))
    return 0;
  if ((r = userlist_clnt_delete_info(self->clnt, ULS_DELETE_USER,
                                     user_id, 0, 0)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_privMoveMember(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, serial = 0, new_role = 0, r;

  if (!PyArg_ParseTuple(args, "iiii", &user_id, &contest_id, &serial, &new_role))
    return 0;
  if ((r = userlist_clnt_move_member(self->clnt, ULS_MOVE_MEMBER,
                                     user_id, contest_id, serial,
                                     new_role)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_do_cnts_passwd_op(int cmd, UlObject *self, PyObject *args)
{
  int contest_id = 0, r;

  if (!PyArg_ParseTuple(args, "i", &contest_id))
    return 0;
  if ((r = userlist_clnt_cnts_passwd_op(self->clnt, cmd, contest_id)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}
static PyObject *
Ul_privClearContestPasswords(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_cnts_passwd_op(ULS_CLEAR_TEAM_PASSWORDS, self, args);
}
static PyObject *
Ul_privGenerateRandomContestPasswords(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_cnts_passwd_op(ULS_GENERATE_TEAM_PASSWORDS_2, self, args);
}
static PyObject *
Ul_privGenerateRandomPasswords(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_cnts_passwd_op(ULS_GENERATE_PASSWORDS_2, self, args);
}

static PyObject *
Ul_createMember(UlObject *self, PyObject *args)
{
  int contest_id = 0, role = 0, r;

  if (!PyArg_ParseTuple(args, "ii", &contest_id, &role))
    return 0;
  if ((r = userlist_clnt_create_member(self->clnt, 0, contest_id,
                                       role)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", r);
}

static PyObject *
Ul_privCreateMember(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, role = 0, r;

  if (!PyArg_ParseTuple(args, "iii", &user_id, &contest_id, &role))
    return 0;
  if ((r = userlist_clnt_create_member(self->clnt, user_id, contest_id,
                                       role)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_importCSVUsers(UlObject *self, PyObject *args)
{
  int contest_id = 0, flags = 0, r, status = 0;
  const char *separator = 0, *text = 0;
  unsigned char *log_text = 0;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "isis", &contest_id, &separator, &flags, &text))
    return 0;
  if ((r = userlist_clnt_import_csv_users(self->clnt, ULS_IMPORT_CSV_USERS,
                                          contest_id, separator[0],
                                          flags, text, &log_text)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  if (r == ULS_TEXT_DATA) status = 1;
  val = Py_BuildValue("{s:i,s:s}", "status", status, "log", log_text);
  free(log_text);
  return val;
}

static PyObject *
Ul_do_user_passwd_op(int cmd, UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, r;

  if (!PyArg_ParseTuple(args, "ii", &user_id, &contest_id))
    return 0;
  if ((r = userlist_clnt_register_contest(self->clnt,cmd,user_id,contest_id,0,0)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}
static PyObject *
Ul_privGenerateRandomContestPassword(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_user_passwd_op(ULS_RANDOM_TEAM_PASSWD, self, args);
}
static PyObject *
Ul_privCopyContestPasswordToPassword(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_user_passwd_op(ULS_COPY_TO_REGISTER, self, args);
}
static PyObject *
Ul_privCopyPasswordToContestPassword(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_user_passwd_op(ULS_COPY_TO_TEAM, self, args);
}
static PyObject *
Ul_privFixPassword(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_user_passwd_op(ULS_FIX_PASSWORD, self, args);
}

static PyObject *
Ul_privGenerateRandomPassword(int cmd, UlObject *self, PyObject *args)
{
  int user_id = 0, r;

  if (!PyArg_ParseTuple(args, "i", &user_id))
    return 0;
  if ((r = userlist_clnt_register_contest(self->clnt, ULS_RANDOM_PASSWD,
                                          user_id, 0, 0, 0)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyObject *
Ul_lookupCookie(UlObject *self, PyObject *args)
{
  const char *ip_str = 0;
  ej_cookie_t sid = 0;
  ej_ip_t ip_val = 0;
  int ssl_flag = 0, user_id = 0, locale_id = 0, contest_id = 0, r;
  unsigned char *login = 0, *name = 0;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "siK", &ip_str, &ssl_flag, &sid))
    return 0;
  if (xml_parse_ip(0, -1, 0, ip_str, &ip_val) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid IP");
    return 0;
  }
  if ((r = userlist_clnt_lookup_cookie
       (self->clnt, ip_val, ssl_flag, sid,
        &user_id, &login, &name, &locale_id, &contest_id)) < 0) {
    if (r == -ULS_ERR_NO_COOKIE) {
      Py_RETURN_NONE;
    }
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("{s:i,s:i,s:i,s:s,s:s}",
                      "user_id", user_id,
                      "contest_id", contest_id,
                      "locale_id", locale_id,
                      "login", login,
                      "name", name);
  free(login);
  free(name);
  return val;
}

static PyObject *
Ul_lookupContestCookie(UlObject *self, PyObject *args)
{
  const char *ip_str = 0;
  ej_cookie_t sid = 0;
  ej_ip_t ip_val = 0;
  int ssl_flag = 0, user_id = 0, locale_id = 0, contest_id = 0, r;
  unsigned char *login = 0, *name = 0;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "siiK", &ip_str, &ssl_flag, &contest_id, &sid))
    return 0;
  if (xml_parse_ip(0, -1, 0, ip_str, &ip_val) < 0) {
    PyErr_SetString(PyExc_ValueError, "invalid IP");
    return 0;
  }
  if ((r = userlist_clnt_team_cookie
       (self->clnt, ip_val, ssl_flag, contest_id, sid,
        &user_id, &locale_id, &login, &name)) < 0) {
    if (r == -ULS_ERR_NO_COOKIE) {
      Py_RETURN_NONE;
    }
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("{s:i,s:i,s:i,s:s,s:s}",
                      "user_id", user_id,
                      "locale_id", locale_id,
                      "login", login,
                      "name", name);
  free(login);
  free(name);
  return val;
}

static PyObject *
Ul_getUserInfo(UlObject *self, PyObject *args)
{
  int contest_id = 0, r;
  unsigned char *xml_text = 0;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "i", &contest_id))
    return 0;
  if ((r = userlist_clnt_get_info(self->clnt, ULS_GET_USER_INFO, 0, contest_id,
                                  &xml_text)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("s", xml_text);
  free(xml_text);
  return val;
}

static PyObject *
Ul_privGetUserInfo(UlObject *self, PyObject *args)
{
  int user_id = 0, contest_id = 0, r;
  unsigned char *xml_text = 0;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "ii", &user_id, &contest_id))
    return 0;
  if ((r = userlist_clnt_get_info(self->clnt, ULS_PRIV_GET_USER_INFO,
                                  user_id, contest_id,
                                  &xml_text)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("s", xml_text);
  free(xml_text);
  return val;
}

static PyObject *
Ul_getDatabase(UlObject *self, PyObject *args)
{
  int contest_id = 0, r;
  unsigned char *db_text = 0;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "i", &contest_id))
    return 0;
  if ((r = userlist_clnt_get_database(self->clnt, ULS_GET_DATABASE, contest_id,
                                      &db_text)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("s", db_text);
  free(db_text);
  return val;
}

static PyObject *
Ul_do_list_users(int cmd, UlObject *self, PyObject *args)
{
  int contest_id = 0, r;
  unsigned char *xml_text = 0;
  PyObject *val;

  if (!PyArg_ParseTuple(args, "i", &contest_id))
    return 0;
  if ((r = userlist_clnt_list_all_users(self->clnt, cmd, contest_id,
                                        &xml_text)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("s", xml_text);
  free(xml_text);
  return val;
}
static PyObject *
Ul_privListContestUsers(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_list_users(ULS_LIST_ALL_USERS, self, args);
}
static PyObject *
Ul_privGetContestUsers(int cmd, UlObject *self, PyObject *args)
{
  return Ul_do_list_users(ULS_LIST_STANDINGS_USERS, self, args);
}

static PyObject *
Ul_privListAllUsers(UlObject *self)
{
  int r;
  unsigned char *xml_text = 0;
  PyObject *val;

  if ((r = userlist_clnt_list_all_users(self->clnt, ULS_LIST_ALL_USERS, 0,
                                        &xml_text)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  val = Py_BuildValue("s", xml_text);
  free(xml_text);
  return val;
}

static PyMethodDef Ul_methods[] =
{
  { "adminProcess", (PyCFunction) Ul_adminProcess, METH_NOARGS,
    "adminProcess*" },
  { "login", (PyCFunction) Ul_login, METH_VARARGS,
    "login*" },
  { "contestLogin", (PyCFunction) Ul_contestLogin, METH_VARARGS,
    "contestLogin*" },
  { "checkUser", (PyCFunction) Ul_checkUser, METH_VARARGS,
    "checkUser" },
  { "checkContestUser", (PyCFunction) Ul_checkContestUser, METH_VARARGS,
    "checkContestUser" },
  { "registerNew2", (PyCFunction) Ul_registerNew2, METH_VARARGS,
    "registerNew2" },
  { "privCreateUser", (PyCFunction) Ul_privCreateUser, METH_VARARGS,
    "privCreateUser*" },
  { "privEditField", (PyCFunction) Ul_privEditField, METH_VARARGS,
    "privEditField*" },
  { "privChangeContestReg", (PyCFunction) Ul_privChangeContestReg, METH_VARARGS,
    "privChangeContestReg*" },
  { "registerContest", (PyCFunction) Ul_registerContest, METH_VARARGS,
    "registerContest*" },
  { "privRegisterContest", (PyCFunction) Ul_privRegisterContest, METH_VARARGS,
    "privRegisterContest*" },
  { "privForcedRegisterContest", (PyCFunction) Ul_privForcedRegisterContest, METH_VARARGS,
    "privForcedRegisterContest*" },
  { "privLookupUser", (PyCFunction) Ul_privLookupUser, METH_VARARGS,
    "privLookupUser*" },
  { "privLookupUserId", (PyCFunction) Ul_privLookupUserId, METH_VARARGS,
    "privLookupUserId*" },
  { "privDeleteField", (PyCFunction) Ul_privDeleteField, METH_VARARGS,
    "privDeleteField*" },
  { "privCopyUserInfo", (PyCFunction) Ul_privCopyUserInfo, METH_VARARGS,
    "privCopyUserInfo*" },
  { "getCookie", (PyCFunction) Ul_getCookie, METH_VARARGS,
    "getCookie" },
  { "getContestCookie", (PyCFunction) Ul_getContestCookie, METH_VARARGS,
    "getContestCookie" },
  { "getPrivCookie", (PyCFunction) Ul_getPrivCookie, METH_VARARGS,
    "getPrivCookie" },
  { "logout", (PyCFunction) Ul_logout, METH_VARARGS,
    "logout" },
  { "privLogin", (PyCFunction) Ul_privLogin, METH_VARARGS,
    "privLogin" },
  { "checkPrivUser", (PyCFunction) Ul_checkPrivUser, METH_VARARGS,
    "checkPrivUser" },
  { "setCookieLocale", (PyCFunction) Ul_setCookieLocale, METH_VARARGS,
    "setCookieLocale" },
  { "setPassword", (PyCFunction) Ul_setPassword, METH_VARARGS,
    "setPassword" },
  { "setContestPassword", (PyCFunction) Ul_setContestPassword, METH_VARARGS,
    "setContestPassword" },
  { "privSetPassword", (PyCFunction) Ul_privSetPassword, METH_VARARGS,
    "privSetPassword" },
  { "privSetContestPassword", (PyCFunction) Ul_privSetContestPassword, METH_VARARGS,
    "privSetContestPassword" },
  { "stop", (PyCFunction) Ul_stop, METH_NOARGS,
    "stop" },
  { "restart", (PyCFunction) Ul_restart, METH_NOARGS,
    "restart" },
  { "deleteCookie", (PyCFunction) Ul_deleteCookie, METH_VARARGS,
    "deleteCookie" },
  { "deleteMember", (PyCFunction) Ul_deleteMember, METH_VARARGS,
    "deleteMember" },
  { "privDeleteMember", (PyCFunction) Ul_privDeleteMember, METH_VARARGS,
    "privDeleteMember*" },
  { "privDeleteUser", (PyCFunction) Ul_privDeleteUser, METH_VARARGS,
    "privDeleteUser" },
  { "privMoveMember", (PyCFunction) Ul_privMoveMember, METH_VARARGS,
    "privMoveMember" },
  { "privClearContestPasswords", (PyCFunction) Ul_privClearContestPasswords, METH_VARARGS,
    "privClearContestPasswords*" },
  { "privGenerateRandomContestPasswords", (PyCFunction) Ul_privGenerateRandomContestPasswords, METH_VARARGS,
    "privGenerateRandomContestPasswords*" },
  { "privGenerateRandomPasswords", (PyCFunction) Ul_privGenerateRandomPasswords, METH_VARARGS,
    "privGenerateRandomPasswords*" },
  { "createMember", (PyCFunction) Ul_createMember, METH_VARARGS,
    "createMember" },
  { "privCreateMember", (PyCFunction) Ul_privCreateMember, METH_VARARGS,
    "privCreateMember" },
  { "importCSVUsers", (PyCFunction) Ul_importCSVUsers, METH_VARARGS,
    "importCSVUsers" },
  { "privGenerateRandomPassword", (PyCFunction) Ul_privGenerateRandomPassword, METH_VARARGS,
    "privGenerateRandomPassword*" },
  { "privGenerateRandomContestPassword", (PyCFunction) Ul_privGenerateRandomContestPassword, METH_VARARGS,
    "privGenerateRandomContestPassword*" },
  { "privCopyContestPasswordToPassword", (PyCFunction) Ul_privCopyContestPasswordToPassword, METH_VARARGS,
    "privCopyContestPasswordToPassword*" },
  { "privCopyPasswordToContestPassword", (PyCFunction) Ul_privCopyPasswordToContestPassword, METH_VARARGS,
    "privCopyPasswordToContestPassword*" },
  { "privFixPassword", (PyCFunction) Ul_privFixPassword, METH_VARARGS,
    "privFixPassword" },
  { "lookupCookie", (PyCFunction) Ul_lookupCookie, METH_VARARGS,
    "lookupCookie" },
  { "lookupContestCookie", (PyCFunction) Ul_lookupContestCookie, METH_VARARGS,
    "lookupContestCookie" },
  { "getUserInfo", (PyCFunction) Ul_getUserInfo, METH_VARARGS,
    "getUserInfo*" },
  { "privGetUserInfo", (PyCFunction) Ul_privGetUserInfo, METH_VARARGS,
    "privGetUserInfo*" },
  { "getDatabase", (PyCFunction) Ul_getDatabase, METH_VARARGS,
    "getDatabase" },
  { "privListContestUsers", (PyCFunction) Ul_privListContestUsers, METH_VARARGS,
    "privListContestUsers*" },
  { "privGetContestUsers", (PyCFunction) Ul_privGetContestUsers, METH_VARARGS,
    "privGetContestUsers*" },
  { "privListAllUsers", (PyCFunction) Ul_privListAllUsers, METH_NOARGS,
    "privListAllUsers*" },

  { NULL }
};

static PyTypeObject UlType =
{
  PyObject_HEAD_INIT(NULL)
  0,                            /* ob_size */
  "ejudge.Userlist",            /* tp_name */
  sizeof(UlObject),             /* tp_basicsize */
  0,                            /* tp_itemsize */
  (destructor) Ul_dealloc,      /* tp_dealloc */
  0,                            /* tp_print */
  0,                            /* tp_getattr */
  0,                            /* tp_setattr */
  0,                            /* tp_compare */
  0,                            /* tp_repr */
  0,                            /* tp_as_number */
  0,                            /* tp_as_sequence */
  0,                            /* tp_as_mapping */
  0,                            /* tp_hash */
  0,                            /* tp_call */
  0,                            /* tp_str */
  0,                            /* tp_getattro */
  0,                            /* tp_setattro */
  0,                            /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,           /* tp_flags */
  "Ejudge Userlist objects",    /* tp_doc */
  0,                            /* tp_traverse */
  0,                            /* tp_clear */
  0,                            /* tp_richcompare */
  0,                            /* tp_weaklistoffset */
  0,                            /* tp_iter */
  0,                            /* tp_iternext */
  Ul_methods,                   /* tp_methods */
  0,                            /* tp_members */
  0,                            /* tp_getset */
  0,                            /* tp_base */
  0,                            /* tp_dict */
  0,                            /* tp_descr_get */
  0,                            /* tp_descr_set */
  0,                            /* tp_dictoffset */
  (initproc)Ul_init,            /* tp_init */
  0,                            /* tp_alloc */
  Ul_new,                       /* tp_new */
};

static PyMethodDef ejudge_methods[] =
{
  {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initejudge(void) 
{
  PyObject *m;
  PyObject *t = (PyObject*) (void*) &UlType;

  //UlType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&UlType) < 0)
    return;

  m = Py_InitModule3("ejudge", ejudge_methods,
                     "Ejudge interface module.");

  Py_INCREF(&UlType);
  PyModule_AddObject(m, "Userlist", t);
}
