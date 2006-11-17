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

#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <unistd.h>

static int
quiet_recv_packet(new_server_conn_t conn, size_t *p_size, void **p_data)
{
  unsigned char len_buf[4], *b, *bb = 0;
  int r, n;
  ej_size_t sz;
  int code = 0;
  struct new_server_prot_packet *pkt;

  if (!conn || conn->fd < 0) return -NEW_SRV_ERR_NOT_CONNECTED;
  *p_size = 0;
  *p_data = 0;

  // read length
  b = len_buf;
  r = 4;
  while (r > 0) {
    n = read(conn->fd, b, r);
    if (n < 0) {
      code = -NEW_SRV_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
      code = -NEW_SRV_ERR_UNEXPECTED_EOF;
      goto io_error;
    }
    r -= n; b += n;
  }
  memcpy(&sz, len_buf, 4);

  if (sz <= 0 || sz >= 256 * 1024) {
    code = -NEW_SRV_ERR_PACKET_TOO_BIG;
    goto io_error;
  }
  bb = b = (unsigned char*) xcalloc(1, sz);
  r = sz;

  // read the packet
  while (r > 0) {
    n = read(conn->fd, b, r);
    if (n < 0) {
      code = -NEW_SRV_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
      code = -NEW_SRV_ERR_UNEXPECTED_EOF;
      goto io_error;
    }
    r -= n; b += n;
  }

  if (sz < sizeof(struct new_server_prot_packet)) {
    code = -NEW_SRV_ERR_PACKET_TOO_SMALL;
    goto io_error;
  }
  pkt = (struct new_server_prot_packet*) bb;
  if (pkt->magic != NEW_SERVER_PROT_PACKET_MAGIC) {
    code = -NEW_SRV_ERR_PROTOCOL_ERROR;
    goto io_error;
  }

  *p_size = sz;
  *p_data = bb;

  return 0;

 io_error:
  if (bb) xfree(bb);
  return code;
}

int
new_server_clnt_control(new_server_conn_t conn, int cmd)
{
  struct new_server_prot_packet *out = 0;
  struct new_server_prot_packet *in = 0;
  size_t out_size = 0, in_size = 0;
  void *void_in = 0;
  int errcode = 0;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, sizeof(*out));
  out->magic = NEW_SERVER_PROT_PACKET_MAGIC;
  out->id = cmd;
  if ((errcode = new_server_clnt_send_packet(conn, out_size, out)) < 0)
    goto failed;
  errcode = quiet_recv_packet(conn, &in_size, &void_in);
  if (errcode == -NEW_SRV_ERR_UNEXPECTED_EOF) {
    errcode = 0;
    goto failed;
  }
  if (errcode < 0) goto failed;
  errcode = -NEW_SRV_ERR_PROTOCOL_ERROR;
  if (in_size != sizeof(*in)) {
    goto failed;
  }
  in = (struct new_server_prot_packet*) void_in;
  if (in->magic != NEW_SERVER_PROT_PACKET_MAGIC) {
    goto failed;
  }
  errcode = in->id;
  if (errcode < 0) goto failed;
  if (errcode >= 0) errcode = -NEW_SRV_ERR_PROTOCOL_ERROR;

 failed:
  xfree(void_in);
  return errcode;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
