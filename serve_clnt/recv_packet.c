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
serve_clnt_recv_packet(int sock_fd, size_t *p_size, void **p_data)
{
  unsigned char len_buf[4], *b, *bb = 0;
  int r, n;
  size_t sz;
  int code = 0;
  struct prot_serve_packet *pkt;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  *p_size = 0;
  *p_data = 0;

  // read length
  b = len_buf;
  r = 4;
  while (r > 0) {
    n = read(sock_fd, b, r);
    if (n < 0) {
      err("serve_cnlt_recv_packet: read() failed: %s", os_ErrorMsg());
      code = -SRV_ERR_READ_FROM_SERVER;
      goto io_error;
    }
    if (!n) {
      err("serve_cnlt_recv_packet: unexpected EOF");
      code = -SRV_ERR_EOF_FROM_SERVER;
      goto io_error;
    }
    r -= n; b += n;
  }
  memcpy(&sz, len_buf, 4);
  if (sz <= 0 || sz >= 256 * 1024) {
    err("serve_cnlt_recv_packet: invalid packet length %zd", sz);
    code = -SRV_ERR_PROTOCOL;
    goto io_error;
  }
  bb = b = (unsigned char*) xcalloc(1, sz);
  r = sz;

  // read the packet
  while (r > 0) {
    n = read(sock_fd, b, r);
    if (n < 0) {
      err("serve_cnlt_recv_packet: read() failed: %s", os_ErrorMsg());
      code = -SRV_ERR_READ_FROM_SERVER;
      goto io_error;
    }
    if (!n) {
      err("serve_cnlt_recv_packet: unexpected EOF");
      code = -SRV_ERR_EOF_FROM_SERVER;
      goto io_error;
    }
    r -= n; b += n;
  }

  if (sz < sizeof(struct prot_serve_packet)) {
    err("serve_clnt_recv_packet: packet is too small: %zu", sz);
    code = -SRV_ERR_PROTOCOL;
    goto io_error;
  }
  pkt = (struct prot_serve_packet*) bb;
  if (pkt->magic != PROT_SERVE_PACKET_MAGIC) {
    err("serve_cnlt_recv_packet: bad magic in packet: %04x", pkt->magic);
    code = -SRV_ERR_PROTOCOL;
    goto io_error;
  }

  *p_size = sz;
  *p_data = bb;

  return 0;
 io_error:
  if (bb) xfree(bb);
  return code;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
