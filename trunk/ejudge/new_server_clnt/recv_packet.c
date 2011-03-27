/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2011 Alexander Chernov <cher@ejudge.ru> */

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

#include "reuse_xalloc.h"
#include "reuse_osdeps.h"

#include <unistd.h>

int
new_server_clnt_recv_packet(new_server_conn_t conn, size_t *p_size, void **p_data)
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
      err("new_server_cnlt_recv_packet: read() failed: %s", os_ErrorMsg());
      code = -NEW_SRV_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
      err("new_server_cnlt_recv_packet: unexpected EOF");
      code = -NEW_SRV_ERR_UNEXPECTED_EOF;
      goto io_error;
    }
    r -= n; b += n;
  }
  memcpy(&sz, len_buf, 4);

  if (sz <= 0 || sz >= 256 * 1024) {
    err("server_cnlt_recv_packet: invalid packet length %u", sz);
    code = -NEW_SRV_ERR_PACKET_TOO_BIG;
    goto io_error;
  }
  bb = b = (unsigned char*) xcalloc(1, sz);
  r = sz;

  // read the packet
  while (r > 0) {
    n = read(conn->fd, b, r);
    if (n < 0) {
      err("new_server_cnlt_recv_packet: read() failed: %s", os_ErrorMsg());
      code = -NEW_SRV_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
      err("new_server_cnlt_recv_packet: unexpected EOF");
      code = -NEW_SRV_ERR_UNEXPECTED_EOF;
      goto io_error;
    }
    r -= n; b += n;
  }

  if (sz < sizeof(struct new_server_prot_packet)) {
    err("new_server_clnt_recv_packet: packet is too small: %u", sz);
    code = -NEW_SRV_ERR_PACKET_TOO_SMALL;
    goto io_error;
  }
  pkt = (struct new_server_prot_packet*) bb;
  if (pkt->magic != NEW_SERVER_PROT_PACKET_MAGIC) {
    err("new_server_cnlt_recv_packet: bad magic in packet: %04x", pkt->magic);
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

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
