/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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

#include "super_clnt.h"
#include "super_proto.h"
#include "errlog.h"

#include <reuse/osdeps.h>

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

int
super_clnt_open(const unsigned char *socket_path)
{
  struct sockaddr_un addr;
  int fd = -1;
  int code = -SSERV_UNKNOWN_ERROR;
  int val, ret;
  struct ucred *pcred;
  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct iovec send_vec[1];

  signal(SIGPIPE, SIG_IGN);

  if (!socket_path) return -SSERV_ERR_BAD_SOCKET_NAME;

  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
  if (strcmp(socket_path, addr.sun_path)!=0) return -SSERV_ERR_BAD_SOCKET_NAME;

  if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
    err("super_clnt_open: socket() failed: %s", os_ErrorMsg());
    code = -SSERV_ERR_SYSTEM_ERROR;
    goto failure;
  }

  val = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val)) < 0) {
    err("super_clnt_open: setsockopt() failed: %s", os_ErrorMsg());
    code = -SSERV_ERR_SYSTEM_ERROR;
    goto failure;
  }

  if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    err("super_clnt_open: connect() failed: %s", os_ErrorMsg());
    code = -SSERV_ERR_CONNECT_FAILED;
    goto failure;
  }

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
  ret = sendmsg(fd, &msg, 0);
  if (ret < 0) {
    err("super_clnt_open: sendmsg() failed: %s", os_ErrorMsg());
    code = -SSERV_ERR_WRITE_TO_SERVER;
    goto failure;
  }
  if (ret != 4) {
    err("super_clnt_open: sendmsg() short write: %d bytes", ret);
    code = -SSERV_ERR_WRITE_TO_SERVER;
    goto failure;
  }

  return fd;

 failure:
  if (fd >= 0) close(fd);
  return code;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
