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
#include "ejudge/sock_op.h"
#include "ejudge/errlog.h"

int
userlist_clnt_do_pass_fd(
        struct userlist_clnt *clnt,
        int fds_num,
        int *fds)
{
#if !defined PYTHON
  ASSERT(clnt);
  ASSERT(fds_num > 0 && fds_num <= 32);
  ASSERT(fds);
#endif

  if (sock_op_put_fds(clnt->fd, fds_num, fds) < 0) {
#if defined PYTHON
    PyErr_SetString(PyExc_IOError, "sock_op_put_fds failed");
    return -1;
#else
    err("%s: sock_op_put_fds failed", __FUNCTION__);
    return -ULS_ERR_WRITE_ERROR;
#endif
  }
  return 0;
}
