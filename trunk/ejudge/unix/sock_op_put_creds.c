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

#include "sock_op.h"
#include "errlog.h"

#include <reuse/osdeps.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

int
sock_op_put_creds(int sock_fd)
{
  int val, ret;
  struct ucred *pcred;
  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct iovec send_vec[1];

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = msgbuf;
  msg.msg_controllen = sizeof(msgbuf);
  pmsg = CMSG_FIRSTHDR(&msg);
  pcred = (struct ucred*) CMSG_DATA(pmsg);
  pcred->pid = getpid();
  pcred->uid = getuid();
  pcred->gid = getgid();
  pmsg->cmsg_level = SOL_SOCKET;
  pmsg->cmsg_type = SCM_CREDENTIALS;
  pmsg->cmsg_len = CMSG_LEN(sizeof(*pcred));
  msg.msg_controllen = CMSG_SPACE(sizeof(*pcred));
  send_vec[0].iov_base = &val;
  send_vec[0].iov_len = 4;
  msg.msg_iov = send_vec;
  msg.msg_iovlen = 1;
  val = 0;
  ret = sendmsg(sock_fd, &msg, 0);
  if (ret < 0) {
    err("%s: sendmsg() failed: %s", __FUNCTION__, os_ErrorMsg());
    return -1;
  }
  if (ret != 4) {
    err("%s: sendmsg() short write: %d bytes", __FUNCTION__, ret);
    return -1;
  }
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
