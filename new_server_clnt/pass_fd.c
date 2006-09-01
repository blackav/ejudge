/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "new_server_clnt/new_server_clnt_priv.h"
#include "new_server_proto.h"
#include "errlog.h"

#include <reuse/osdeps.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

int
new_server_clnt_pass_fd(new_server_conn_t conn, int fds_num, const int *fds)
{
  struct new_server_prot_packet *out = 0;
  int out_size = 0;
  int r;

  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct iovec send_vec[1];
  int *fd2;
  int arrsize, val, ret;

  if (!conn || conn->fd < 0) return -NEW_SRV_ERR_NOT_CONNECTED;

  out_size = sizeof(*out);
  out = alloca(out_size);
  out->id = NEW_SRV_CMD_PASS_FD;
  out->magic = NEW_SERVER_PROT_PACKET_MAGIC;
  if ((r = new_server_clnt_send_packet(conn, out_size, out)) < 0) return r;

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
  ret = sendmsg(conn->fd, &msg, 0);
  if (ret < 0) {
    err("new_server_clnt_pass_fd: sendmsg() failed: %s", os_ErrorMsg());
    return -NEW_SRV_ERR_WRITE_ERROR;
  }
  if (ret != 4) {
    err("new_server_clnt_pass_fd: sendmsg() short write: %d bytes", ret);
    return -NEW_SRV_ERR_WRITE_ERROR;
  }
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
