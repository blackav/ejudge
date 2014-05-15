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

#include "ejudge/sock_op.h"

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

int
sock_op_put_fds(
	int sock_fd,
        int fds_num,
        const int *fds)
{
  struct msghdr msg;
  unsigned char msgbuf[512];
  size_t arrsize;
  struct cmsghdr *pmsg;
  struct iovec send_vec[1];
  int *fd2;
  int val = 0;

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

  if (sendmsg(sock_fd, &msg, 0) != 4) return -1;
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
