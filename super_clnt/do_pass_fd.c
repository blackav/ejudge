/* -*- mode: c -*- */

/* Copyright (C) 2004-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/super_clnt.h"
#include "ejudge/super_proto.h"
#include "ejudge/sock_op.h"
#include "ejudge/errlog.h"

#include "ejudge/osdeps.h"

int
super_clnt_do_pass_fd(
        int sock_fd,
        int fds_num,
        int *fds)
{
  int n;

  if (sock_fd < 0) return -SSERV_ERR_NOT_CONNECTED;
  if (fds_num <= 0 || fds_num > 2 || !fds) return -SSERV_ERR_INVALID_FD;
  for (n = 0; n < fds_num; n++)
    if (fds[n] < 0) return -SSERV_ERR_INVALID_FD;
  if (sock_op_put_fds(sock_fd, fds_num, fds) < 0) {
    err("super_clnt_do_pass_fd: sock_op_put_fds failed");
    return -SSERV_ERR_WRITE_TO_SERVER;
  }
  return 0;
}
