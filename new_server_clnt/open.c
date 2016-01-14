/* -*- mode: c -*- */

/* Copyright (C) 2006-2016 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/new_server_proto.h"
#include "ejudge/errlog.h"
#include "ejudge/sock_op.h"

#include "ejudge/xalloc.h"
#include "ejudge/osdeps.h"

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

int
new_server_clnt_open(const unsigned char *socketpath, new_server_conn_t *p_conn)
{
  int fd = -1;
  int max_path_buf;
  struct sockaddr_un addr;
  int code = -1;
  new_server_conn_t new_conn = 0;

  signal(SIGPIPE, SIG_IGN);

  if (!socketpath) return -NEW_SRV_ERR_BAD_SOCKET_NAME;
  max_path_buf = sizeof(struct sockaddr_un) - 
    XOFFSET(struct sockaddr_un, sun_path);
  if (strlen(socketpath) >= max_path_buf) {
    err("new_server_clnt_open: socket path length is too long (%zu)",
        strlen(socketpath));
    return -NEW_SRV_ERR_BAD_SOCKET_NAME;
  }

  if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
    err("new_server_clnt_open: socket() failed: %s", os_ErrorMsg());
    code = -NEW_SRV_ERR_SYSTEM_ERROR;
    goto failure;
  }

  if (sock_op_enable_creds(fd) < 0) {
    code = -NEW_SRV_ERR_SYSTEM_ERROR;
    goto failure;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socketpath, max_path_buf - 1);
  if (connect(fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    err("new_server_clnt_open: connect() failed: %s", os_ErrorMsg());
    code = -NEW_SRV_ERR_CONNECT_FAILED;
    goto failure;
  }

  if (sock_op_put_creds(fd) < 0) {
    code = -NEW_SRV_ERR_WRITE_ERROR;
    goto failure;
  }


  XCALLOC(new_conn, 1);
  new_conn->fd = fd;
  *p_conn = new_conn;
  return 0;

 failure:
  if (fd >= 0) close(fd);
  return code;
}
