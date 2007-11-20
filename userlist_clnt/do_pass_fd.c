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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <errno.h>

int
userlist_clnt_do_pass_fd(struct userlist_clnt *clnt,
                         int fds_num,
                         int *fds)
{
  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct iovec send_vec[1];
  int *fd2;
  int arrsize, val, ret;

#if !defined PYTHON
  ASSERT(clnt);
  ASSERT(fds_num > 0 && fds_num <= 32);
  ASSERT(fds);
#endif

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = msgbuf;
  msg.msg_controllen = sizeof(msgbuf);
  arrsize = sizeof(int) * fds_num;
  pmsg = CMSG_FIRSTHDR(&msg);
  fd2 = (int*) CMSG_DATA(pmsg);
  memcpy(fd2, fds, arrsize);
  pmsg->cmsg_level = SOL_SOCKET;
  pmsg->cmsg_type = SCM_RIGHTS;
  pmsg->cmsg_len = CMSG_LEN(arrsize);
  msg.msg_controllen = CMSG_SPACE(arrsize);
  send_vec[0].iov_base = &val;
  send_vec[0].iov_len = 4;
  msg.msg_iov = send_vec;
  msg.msg_iovlen = 1;
  val = 0;
  ret = sendmsg(clnt->fd, &msg, 0);
  if (ret < 0) {
#if defined PYTHON
    PyErr_SetFromErrno(PyExc_IOError);
    return -1;
#else
    ret = errno;
    err("sendmsg() failed: %s", os_ErrorMsg());
    if (ret == EPIPE) return -ULS_ERR_DISCONNECT;
    return -ULS_ERR_WRITE_ERROR;
#endif
  }
  if (ret != 4) {
#if defined PYTHON
    PyErr_SetString(PyExc_IOError, "short write");
    return -1;
#else
    err("sendmsg() short write: %d bytes", ret);
    return -ULS_ERR_WRITE_ERROR;
#endif
  }
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
