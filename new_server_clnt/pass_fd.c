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
#include "ejudge/sock_op.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/errlog.h"

#include "ejudge/osdeps.h"

#include <stdlib.h>

int
new_server_clnt_pass_fd(
        new_server_conn_t conn,
        int fds_num,
        const int *fds)
{
  struct new_server_prot_packet *out = 0;
  int out_size = 0;
  int r;

  if (!conn || conn->fd < 0) return -NEW_SRV_ERR_NOT_CONNECTED;

  out_size = sizeof(*out);
  out = alloca(out_size);
  out->id = NEW_SRV_CMD_PASS_FD;
  out->magic = NEW_SERVER_PROT_PACKET_MAGIC;
  if ((r = new_server_clnt_send_packet(conn, out_size, out)) < 0) return r;
  if (sock_op_put_fds(conn->fd, fds_num, fds) < 0) {
    err("new_server_clnt_pass_fd: sock_op_put_fds failed");
    return -NEW_SRV_ERR_WRITE_ERROR;
  }
  return 0;
}
