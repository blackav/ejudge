/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

typedef struct
{
  PyObject_HEAD /* ; */
  /* Type-specific fields go here. */
  FILE *f;
} InputStreamObject;

static PyObject *
InputStream_new(
        PyTypeObject *type,
        PyObject *args,
        PyObject *kwds)
{
  InputStreamObject *self = (InputStreamObject *) type->tp_alloc(type, 0);

  if (self) self->f = 0;
  return (PyObject*) self;
}

static int
InputStream_init(
        InputStreamObject *self,
        PyObject *args,
        PyObject *kwds)
{
  const char *path = 0;

  if (!PyArg_ParseTuple(args, "z", &path))
    return -1;

  if (!path || !*path) {
    self->f = stdin;
    return 0;
  }

  if (!(self->f = fopen(path, "r"))) {
    PyErr_SetString(PyExc_IOError, "cannot open input file");
    return -1;
  }

  return 0;
}

static void
InputStream_dealloc(InputStreamObject *self)
{
  if (self->f && self->f != stdin) {
    fclose(self->f);
    self->f = 0;
  }
}

static PyObject *
InputStream_readChar(InputStreamObject *self)
{
  int c = getc(self->f);

  if (c == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (c == EOF) {
    PyErr_SetString(PyExc_EOFError, "EOF");
    return 0;
  }

  return Py_BuildValue("c", c);
}

static PyObject *
InputStream_readByte(InputStreamObject *self)
{
  int c = getc(self->f);

  if (c == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (c == EOF) {
    PyErr_SetString(PyExc_EOFError, "EOF");
    return 0;
  }

  return Py_BuildValue("i", c);
}

static PyObject *
InputStream_readInt32(InputStreamObject *self)
{
  int r, v;

  r = fscanf(self->f, "%d", &v);

  if (!r) {
    PyErr_SetString(PyExc_ValueError, "");
    return 0;
  }
  if (r == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (r == EOF) {
    PyErr_SetString(PyExc_EOFError, "EOF");
    return 0;
  }

  return Py_BuildValue("i", v);
}

static PyObject *
InputStream_readInt(InputStreamObject *self)
{
  int r, v;

  r = fscanf(self->f, "%d", &v);

  if (!r) {
    PyErr_SetString(PyExc_ValueError, "");
    return 0;
  }
  if (r == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (r == EOF) {
    PyErr_SetString(PyExc_EOFError, "EOF");
    return 0;
  }

  return Py_BuildValue("i", v);
}

static PyObject *
InputStream_readWord32(InputStreamObject *self)
{
  int r;
  unsigned v;

  r = fscanf(self->f, "%u", &v);

  if (!r) {
    PyErr_SetString(PyExc_ValueError, "");
    return 0;
  }
  if (r == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (r == EOF) {
    PyErr_SetString(PyExc_EOFError, "EOF");
    return 0;
  }

  return Py_BuildValue("I", v);
}

static PyObject *
InputStream_readInt64(InputStreamObject *self)
{
  int r;
  long long v;

  r = fscanf(self->f, "%lld", &v);

  if (!r) {
    PyErr_SetString(PyExc_ValueError, "");
    return 0;
  }
  if (r == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (r == EOF) {
    PyErr_SetString(PyExc_EOFError, "EOF");
    return 0;
  }

  return Py_BuildValue("L", v);
}

static PyObject *
InputStream_readWord64(InputStreamObject *self)
{
  int r;
  unsigned long long v;

  r = fscanf(self->f, "%llu", &v);

  if (!r) {
    PyErr_SetString(PyExc_ValueError, "");
    return 0;
  }
  if (r == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (r == EOF) {
    PyErr_SetString(PyExc_EOFError, "EOF");
    return 0;
  }

  return Py_BuildValue("K", v);
}

static PyObject *
InputStream_readDouble(InputStreamObject *self)
{
  int r;
  double v;

  r = fscanf(self->f, "%lf", &v);

  if (!r) {
    PyErr_SetString(PyExc_ValueError, "");
    return 0;
  }
  if (r == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (r == EOF) {
    PyErr_SetString(PyExc_EOFError, "EOF");
    return 0;
  }

  return Py_BuildValue("d", v);
}

static PyObject *
InputStream_readString(InputStreamObject *self)
{
  unsigned char *s = 0;
  int c;
  size_t u = 0, a = 0;
  PyObject *o = 0;

  while ((c = getc(self->f)) != EOF && isspace(c));
  if (c == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (c == EOF) {
    PyErr_SetString(PyExc_EOFError, "EOF");
    return 0;
  }

  do {
    if (u >= a) {
      if (!a) a = 32;
      a *= 2;
      if (!(s = (unsigned char*) realloc(s, a))) {
        PyErr_SetString(PyExc_MemoryError, "");
        return 0;
      }
    }
    s[u++] = c;
  } while ((c = getc(self->f)) != EOF && !isspace(c));
  if (c == EOF && ferror(self->f)) {
    PyErr_SetString(PyExc_IOError, strerror(errno));
    return 0;
  }
  if (c != EOF) ungetc(c, self->f);

  o = Py_BuildValue("s#", s, u);
  free(s);
  return o;
}

static PyMethodDef InputStream_methods[] =
{
  { "readChar", (PyCFunction) InputStream_readChar, METH_NOARGS,
    "readChar" },
  { "readByte", (PyCFunction) InputStream_readByte, METH_NOARGS,
    "readByte" },
  { "readInt", (PyCFunction) InputStream_readInt, METH_NOARGS,
    "readInt" },
  { "readInt32", (PyCFunction) InputStream_readInt32, METH_NOARGS,
    "readInt32" },
  { "readWord32", (PyCFunction) InputStream_readWord32, METH_NOARGS,
    "readWord32" },
  { "readInt64", (PyCFunction) InputStream_readInt64, METH_NOARGS,
    "readInt64" },
  { "readWord64", (PyCFunction) InputStream_readWord64, METH_NOARGS,
    "readWord64" },
  { "readDouble", (PyCFunction) InputStream_readDouble, METH_NOARGS,
    "readDouble" },
  { "readString", (PyCFunction) InputStream_readString, METH_NOARGS,
    "readString" },

  { NULL }
};

static PyTypeObject InputStreamType =
{
  PyObject_HEAD_INIT(NULL)
  0,                            /* ob_size */
  "streamio.InputStream",       /* tp_name */
  sizeof(InputStreamObject),    /* tp_basicsize */
  0,                            /* tp_itemsize */
  (destructor) InputStream_dealloc, /* tp_dealloc */
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
  "InputStream",                /* tp_doc */
  0,                            /* tp_traverse */
  0,                            /* tp_clear */
  0,                            /* tp_richcompare */
  0,                            /* tp_weaklistoffset */
  0,                            /* tp_iter */
  0,                            /* tp_iternext */
  InputStream_methods,          /* tp_methods */
  0,                            /* tp_members */
  0,                            /* tp_getset */
  0,                            /* tp_base */
  0,                            /* tp_dict */
  0,                            /* tp_descr_get */
  0,                            /* tp_descr_set */
  0,                            /* tp_dictoffset */
  (initproc)InputStream_init,   /* tp_init */
  0,                            /* tp_alloc */
  InputStream_new,              /* tp_new */
};

static PyMethodDef streamio_methods[] =
{
  {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initstreamio(void)
{
  PyObject *m;
  PyObject *t = (PyObject*) (void*) &InputStreamType;

  //InputStreamType.tp_new = PyType_GenericNew;
  if (PyType_Ready(&InputStreamType) < 0)
    return;

  m = Py_InitModule3("streamio", streamio_methods,
                     "Stream Input/Output");

  Py_INCREF(&InputStreamType);
  PyModule_AddObject(m, "InputStream", t);
}
