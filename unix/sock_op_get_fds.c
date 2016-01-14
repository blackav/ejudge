/* -*- mode: c -*- */

/* Copyright (C) 2008-2016 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/sock_op.h"
#include "ejudge/errlog.h"

#include "ejudge/osdeps.h"

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

int
sock_op_get_fds(
	int sock_fd,
        int conn_id,
        int *client_fds)
{
  const unsigned char *fn = __FUNCTION__;
  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct iovec recv_vec[1];
  int val = -1, r;
  const int *fds;

  // we expect 4 zero bytes and 1 or 2 file descriptors
  memset(&msg, 0, sizeof(msg));
  msg.msg_flags = 0;
  msg.msg_control = msgbuf;
  msg.msg_controllen = sizeof(msgbuf);
  recv_vec[0].iov_base = &val;
  recv_vec[0].iov_len = 4;
  msg.msg_iov = recv_vec;
  msg.msg_iovlen = 1;

  if ((r = recvmsg(sock_fd, &msg, 0)) < 0) {
    err("%s: recvmsg failed: %s", fn, os_ErrorMsg());
    return -1;
  }
  if (r != 4) {
    err("%s: read %d bytes instead of 4", fn, r);
    return -1;
  }
  if (val != 0) {
    err("%s: expected 4 zero bytes", fn);
    return -1;
  }
  if ((msg.msg_flags & MSG_CTRUNC)) {
    err("%s: protocol error: control buffer too small", fn);
    return -1;
  }

  pmsg = CMSG_FIRSTHDR(&msg);
  while (1) {
    if (!pmsg) break;
    if (pmsg->cmsg_level == SOL_SOCKET && pmsg->cmsg_type == SCM_RIGHTS)
      break;
    pmsg = CMSG_NXTHDR(&msg, pmsg);
  }
  if (!pmsg) {
    err("%s: empty control data", fn);
    return -1;
  }

  fds = (int*) CMSG_DATA(pmsg);
  if (pmsg->cmsg_len == CMSG_LEN(2 * sizeof(int))) {
    //info("%d: received 2 file descriptors: %d, %d", conn_id, fds[0], fds[1]);
    client_fds[0] = fds[0];
    client_fds[1] = fds[1];
  } else if (pmsg->cmsg_len == CMSG_LEN(1 * sizeof(int))) {
    //info("%d: received 1 file descriptor: %d", conn_id, fds[0]);
    client_fds[0] = fds[0];
    client_fds[1] = -1;
  } else {
    err("%d: invalid number of file descriptors passed", conn_id);
    return -1;
  }

  if (CMSG_NXTHDR(&msg, pmsg)) {
    err("%d: protocol error: unexpected control data", conn_id);
    return -1;
  }
  return 0;
}
