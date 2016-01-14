/* -*- mode: c -*- */

/* Copyright (C) 2002-2016 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/errlog.h"
#include "ejudge/sock_op.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <signal.h>

struct userlist_clnt*
userlist_clnt_open(char const *socketpath)
{
  int fd = -1;
  struct userlist_clnt *clnt = 0;
  int max_path_buf = 100;
  struct sockaddr_un addr;

#if !defined PYTHON
  signal(SIGPIPE, SIG_IGN);

  ASSERT(socketpath);
  max_path_buf = sizeof(struct sockaddr_un) - 
    XOFFSET(struct sockaddr_un, sun_path);
  if (strlen(socketpath) >= max_path_buf) {
    err("socket path length is too long (%zu)", strlen(socketpath));
    goto failure;
  }
#endif

  if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
#if defined PYTHON
    PyErr_SetFromErrno(PyExc_IOError);
#else
    err("socket() failed: %s", os_ErrorMsg());
#endif
    goto failure;
  }

  if (sock_op_enable_creds(fd) < 0) {
#if defined PYTHON
    PyErr_SetFromErrno(PyExc_IOError);
#endif
    goto failure;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socketpath, max_path_buf - 1);
  if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
#if defined PYTHON
    PyErr_SetFromErrnoWithFilename(PyExc_IOError, (char*) socketpath);
#else
    err("connect() failed: %s", os_ErrorMsg());
#endif
    goto failure;
  }

  if (sock_op_put_creds(fd) < 0) {
#if defined PYTHON
    PyErr_SetString(PyExc_IOError, "sock_op_put_creds");
#endif
    goto failure;
  }

  clnt = (struct userlist_clnt*) xcalloc(1, sizeof(*clnt));
  clnt->fd = fd;
  return clnt;

 failure:
  if (fd >= 0) close(fd);
  if (clnt) xfree(clnt);
  return 0;
}
