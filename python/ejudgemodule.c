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
 * userlist_clnt_lookup_user
 * userlist_clnt_lookup_user_id
 * userlist_clnt_get_cookie
 * userlist_clnt_set_cookie
 * userlist_clnt_lookup_cookie
 * userlist_clnt_team_cookie
 * userlist_clnt_get_info
 * userlist_clnt_get_database
 * userlist_clnt_get_param
 * userlist_clnt_set_info
 * userlist_clnt_set_passwd
 * userlist_clnt_get_contests
 * userlist_clnt_register_contest		OK
 * userlist_clnt_delete_info
 * userlist_clnt_move_member
 * userlist_clnt_list_users
 * userlist_clnt_admin_process			OK
 * userlist_clnt_map_contest
 * userlist_clnt_generate_team_passwd
 * userlist_clnt_list_all_users
 * userlist_clnt_change_registration		OK
 * userlist_clnt_edit_field			OK
 * userlist_clnt_edit_field_seq
 * userlist_clnt_delete_field
 * userlist_clnt_delete_cookie
 * userlist_clnt_create_user			OK
 * userlist_clnt_create_member
 * userlist_clnt_copy_user_info
 * userlist_clnt_get_uid_by_pid
 * userlist_clnt_get_uid_by_pid_2
 * userlist_clnt_priv_login
 * userlist_clnt_priv_cookie
 * userlist_clnt_logout
 * userlist_clnt_dump_database
 * userlist_clnt_cnts_passwd_op
 * userlist_clnt_notify
 * userlist_clnt_read_notification
 * userlist_clnt_bytes_available
 * userlist_clnt_set_notification_callback	
 * userlist_clnt_recover_passwd_2
 * userlist_clnt_control
 * userlist_clnt_priv_cookie_login
 * userlist_clnt_import_csv_users
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
                      "uid", uid, "login", login, "name", name);
  free(login);
  free(name);
  return val;
}

static PyObject *
Ul_login(UlObject *self, PyObject *args, PyObject *kwds)
{
  int cmd, ssl_flag, contest_id, locale_id, r, uid;
  const char *cmd_str, *ip_str, *login, *password;
  unsigned char *name = 0;
  ej_ip_t ip_val;
  ej_cookie_t sid;
  PyObject *val = 0;

  if (!PyArg_ParseTuple(args, "ssiiiss", &cmd_str, &ip_str, &ssl_flag,
                        &contest_id, &locale_id, &login, &password))
    return 0;

  if ((cmd = userlist_str_to_request(cmd_str)) <= 0) {
    PyErr_SetString(PyExc_ValueError, "invalid command");
    return 0;
  }
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
                      "uid", uid, "sid", sid, "name", name);

  free(name);
  return val;
}

static PyObject *
Ul_registerNew2(UlObject *self, PyObject *args, PyObject *kwds)
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
                      "uid", user_id, "login", login_out, "password", password);

  free(login_out);
  free(password);
  return val;
}

static PyObject *
Ul_createUser(UlObject *self, PyObject *args, PyObject *kwds)
{
  const char *login = 0;
  int r, user_id = 0;

  if (!PyArg_ParseTuple(args, "s", &login))
    return 0;
  if ((r = userlist_clnt_create_user(self->clnt, login, &user_id)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", user_id);
}

static PyObject *
Ul_editField(UlObject *self, PyObject *args, PyObject *kwds)
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
  [USERLIST_REG_OK] = "OK",
  [USERLIST_REG_PENDING] = "PENDING",
  [USERLIST_REG_REJECTED] = "REJECTED",
  NULL,
};
static int
str_to_registration_status(const unsigned char *str)
{
  int i;

  for (i = 0; status_map[i]; i++)
    if (!strcmp(status_map[i], str))
      return i;
  return -1;
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
Ul_changeRegistration(UlObject *self, PyObject *args, PyObject *kwds)
{
  int user_id = 0, contest_id = 0, flags = 0, status_val, cmd_val, r;
  const char *cmd_str = 0, *status_str = 0;

  if (!PyArg_ParseTuple(args, "iizzi", &user_id, &contest_id, &status_str,
                        &cmd_str, &flags))
    return 0;
  if (status_str) {
    if ((status_val = str_to_registration_status(status_str)) < 0) {
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
Ul_registerContest(UlObject *self, PyObject *args, PyObject *kwds)
{
  int user_id = 0, contest_id = 0, r, cmd;
  const char *cmd_str = 0;

  if (!PyArg_ParseTuple(args, "sii", &cmd_str, &user_id, &contest_id))
    return 0;
  if ((cmd = userlist_str_to_request(cmd_str)) <= 0) {
    PyErr_SetString(PyExc_ValueError, "invalid command");
    return 0;
  }
  if ((r = userlist_clnt_register_contest(self->clnt, cmd, user_id,
                                          contest_id)) < 0) {
    if (r < -1) PyErr_SetString(PyExc_IOError, userlist_strerror(-r));
    return 0;
  }
  return Py_BuildValue("i", 0);
}

static PyMethodDef Ul_methods[] =
{
  { "adminProcess", (PyCFunction) Ul_adminProcess, METH_NOARGS,
    "adminProcess" },
  { "login", (PyCFunction) Ul_login, METH_VARARGS,
    "login" },
  { "registerNew2", (PyCFunction) Ul_registerNew2, METH_VARARGS,
    "registerNew2" },
  { "createUser", (PyCFunction) Ul_createUser, METH_VARARGS,
    "createUser" },
  { "editField", (PyCFunction) Ul_editField, METH_VARARGS,
    "editField" },
  { "changeRegistration", (PyCFunction) Ul_changeRegistration, METH_VARARGS,
    "changeRegistration" },
  { "registerContest", (PyCFunction) Ul_registerContest, METH_VARARGS,
    "registerContest" },

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
  PyObject* m;

  //UlType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&UlType) < 0)
    return;

  m = Py_InitModule3("ejudge", ejudge_methods,
                     "Ejudge interface module.");

  Py_INCREF(&UlType);
  PyModule_AddObject(m, "Userlist", (PyObject *)&UlType);
}
