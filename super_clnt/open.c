/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2014 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/errlog.h"
#include "ejudge/sock_op.h"

#include "ejudge/osdeps.h"

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

  if (sock_op_enable_creds(fd) < 0) {
    code = -SSERV_ERR_SYSTEM_ERROR;
    goto failure;
  }

  if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    err("super_clnt_open: connect() failed: %s", os_ErrorMsg());
    code = -SSERV_ERR_CONNECT_FAILED;
    goto failure;
  }

  if (sock_op_put_creds(fd) < 0) {
    code = -SSERV_ERR_WRITE_TO_SERVER;
    goto failure;
  }
  return fd;

 failure:
  if (fd >= 0) close(fd);
  return code;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 * End:
 */
