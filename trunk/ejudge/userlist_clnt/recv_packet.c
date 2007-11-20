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

#include "userlist_clnt/private.h"

#include "errlog.h"

int
userlist_clnt_recv_packet(struct userlist_clnt *clnt,
                          size_t *p_size, void **p_data)
{
  unsigned char len_buf[4], *b, *bb = 0;
  int r, n;
  int sz;
#if !defined PYTHON
  int code = 0;
#endif

#if !defined PYTHON
  ASSERT(clnt);
  ASSERT(p_size);
  ASSERT(p_data);
  ASSERT(clnt->fd >= 0);
#endif

  *p_size = 0;
  *p_data = 0;

  // read length
  b = len_buf;
  r = 4;
  while (r > 0) {
    n = read(clnt->fd, b, r);
    if (n < 0) {
#if defined PYTHON
      PyErr_SetFromErrno(PyExc_IOError);
#else
      err("read() from userlist-server failed: %s", os_ErrorMsg());
      code = -ULS_ERR_READ_ERROR;
#endif
      goto io_error;
    }
    if (!n) {
#if defined PYTHON
      PyErr_SetString(PyExc_IOError, "unexpected EOF");
#else
      err("unexpected EOF from userlist-server");
      code = -ULS_ERR_UNEXPECTED_EOF;
#endif
      goto io_error;
    }
    r -= n; b += n;
  }
  memcpy(&sz, len_buf, 4);
  if (sz <= 0) {
#if defined PYTHON
    PyErr_SetString(PyExc_IOError, "invalid packet length");
#else
    err("invalid packet length %d from userlist-server", sz);
    code = -ULS_ERR_PROTOCOL;
#endif
    goto io_error;
  }
  bb = b = (unsigned char*) xcalloc(1, sz);
  r = sz;

  // read the packet
  while (r > 0) {
    n = read(clnt->fd, b, r);
    if (n < 0) {
#if defined PYTHON
      PyErr_SetFromErrno(PyExc_IOError);
#else
      err("read() from userlist-server failed: %s", os_ErrorMsg());
      code = -ULS_ERR_READ_ERROR;
#endif
      goto io_error;
    }
    if (!n) {
#if defined PYTHON
      PyErr_SetString(PyExc_IOError, "unexpected EOF");
#else
      err("unexpected EOF from userlist-server");
      code = -ULS_ERR_UNEXPECTED_EOF;
#endif
      goto io_error;
    }
    r -= n; b += n;
  }

  *p_size = sz;
  *p_data = bb;

  return 0;
 io_error:
#if defined PYTHON
  free(bb);
  return -1;
#else
  xfree(bb);
  return code;
#endif
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
