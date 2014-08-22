/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2008-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/sock_op.h"
#include "ejudge/errlog.h"

#include "ejudge/osdeps.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

int
sock_op_get_creds(
        int sock_fd,
        int conn_id,
        int *p_pid,
        int *p_uid,
        int *p_gid)
{
#if HAVE_SO_PASSCRED
  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct ucred *pcred;
  struct iovec recv_vec[1];
  int val = -1, r;

  memset(&msg, 0, sizeof(msg));
  msg.msg_flags = 0;
  msg.msg_control = msgbuf;
  msg.msg_controllen = sizeof(msgbuf);
  recv_vec[0].iov_base = &val;
  recv_vec[0].iov_len = 4;
  msg.msg_iov = recv_vec;
  msg.msg_iovlen = 1;

  if ((r = recvmsg(sock_fd, &msg, 0)) < 0) {
    err("%d: recvmsg failed: %s", conn_id, os_ErrorMsg());
    return -1;
  }
  if (r != 4) {
    err("%d: read %d bytes instead of 4", conn_id, r);
    return -1;
  }
  if (val != 0) {
    err("%d: expected 4 zero bytes", conn_id);
    return -1;
  }
  if ((msg.msg_flags & MSG_CTRUNC)) {
    err("%d: protocol error: control buffer too small", conn_id);
    return -1;
  }
  pmsg = CMSG_FIRSTHDR(&msg);
  if (!pmsg) {
    err("%d: empty control data", conn_id);
    return -1;
  }
  if (pmsg->cmsg_level != SOL_SOCKET || pmsg->cmsg_type != SCM_CREDENTIALS
      || pmsg->cmsg_len != CMSG_LEN(sizeof(*pcred))) {
    err("%d: protocol error: unexpected control data", conn_id);
    return -1;
  }
  pcred = (struct ucred*) CMSG_DATA(pmsg);
  if (p_pid) *p_pid = pcred->pid;
  if (p_uid) *p_uid = pcred->uid;
  if (p_gid) *p_gid = pcred->gid;
  if (CMSG_NXTHDR(&msg, pmsg)) {
    err("%d: protocol error: unexpected control data", conn_id);
    return -1;
  }
#else
  if (p_pid) *p_pid = getpid();
  if (p_uid) *p_uid = getuid();
  if (p_gid) *p_gid = getgid();
#endif
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
