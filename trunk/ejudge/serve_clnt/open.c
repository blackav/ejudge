/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2005 Alexander Chernov <cher@ispras.ru> */

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

#include "serve_clnt.h"
#include "protocol.h"
#include "errlog.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

int
serve_clnt_open(char const *socketpath)
{
  int fd = -1;
  int max_path_buf;
  int val;
  struct sockaddr_un addr;
  int ret;
  struct ucred *pcred;
  struct msghdr msg;
  unsigned char msgbuf[512];
  struct cmsghdr *pmsg;
  struct iovec send_vec[1];
  int code = -1;

  signal(SIGPIPE, SIG_IGN);

  if (!socketpath) return -SRV_ERR_BAD_SOCKET_NAME;
  max_path_buf = sizeof(struct sockaddr_un) - 
    XOFFSET(struct sockaddr_un, sun_path);
  if (strlen(socketpath) >= max_path_buf) {
    err("serve_clnt_open: socket path length is too long (%zu)",
        strlen(socketpath));
    return -SRV_ERR_BAD_SOCKET_NAME;
  }

  if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
    err("serve_clnt_open: socket() failed: %s", os_ErrorMsg());
    code = -SRV_ERR_SYSTEM_ERROR;
    goto failure;
  }

  val = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val)) < 0) {
    err("serve_clnt_open: setsockopt() failed: %s", os_ErrorMsg());
    code = -SRV_ERR_SYSTEM_ERROR;
    goto failure;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socketpath, max_path_buf - 1);
  if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    err("serve_clnt_open: connect() failed: %s", os_ErrorMsg());
    code = -SRV_ERR_CONNECT_FAILED;
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
    err("serve_clnt_open: sendmsg() failed: %s", os_ErrorMsg());
    code = -SRV_ERR_WRITE_TO_SERVER;
    goto failure;
  }
  if (ret != 4) {
    err("serve_clnt_open: sendmsg() short write: %d bytes", ret);
    code = -SRV_ERR_WRITE_TO_SERVER;
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
