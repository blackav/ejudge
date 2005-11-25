/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004-2005 Alexander Chernov <cher@ispras.ru> */

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
#include <reuse/xalloc.h>

#include <unistd.h>

int
super_clnt_recv_packet(int sock_fd,
                       struct prot_super_packet *p_res,
                       size_t *p_size, void **p_data)
{
  unsigned char *b, *alloc_mem = 0, *bb;
  int in_size, r, n, code = -SSERV_UNKNOWN_ERROR;
  struct prot_super_packet *pkt;

  if (sock_fd < 0) return -SSERV_ERR_NOT_CONNECTED;

  // read packet length
  b = (unsigned char*) &in_size;
  r = 4;
  while (r > 0) {
    if ((n = read(sock_fd, b, r)) < 0) {
      err("super_cnlt_recv_packet: read() failed: %s", os_ErrorMsg());
      code = -SSERV_ERR_READ_FROM_SERVER;
      goto failed;
    }
    if (!n) {
      err("super_cnlt_recv_packet: unexpected EOF");
      code = -SSERV_ERR_EOF_FROM_SERVER;
      goto failed;
    }
    r -= n; b += n;
  }

  if (p_res) {
    if (in_size != sizeof(*p_res)) {
      err("super_cnlt_recv_packet: unexpected size: %d", in_size);
      code = -SSERV_ERR_PROTOCOL_ERROR;
      goto failed;
    }
    if (p_size || p_data) {
      err("super_cnlt_recv_packet: p_size and p_data must be 0");
      code = -SSERV_ERR_PROTOCOL_ERROR;
      goto failed;
    }
    bb = b = (unsigned char*) p_res;
    r = in_size;
  } else {
    if (!p_size || !p_data) {
      err("super_cnlt_recv_packet: p_size and p_data must be set");
      code = -SSERV_ERR_PROTOCOL_ERROR;
      goto failed;
    }
    if (in_size < sizeof(struct prot_super_packet) || in_size >= 256 * 1024) {
      err("super_cnlt_recv_packet: invalid packet length %d", in_size);
      code = -SSERV_ERR_PROTOCOL_ERROR;
      goto failed;
    }
    bb = b = alloc_mem = (unsigned char*) xcalloc(1, in_size);
    r = in_size;
  }

  while (r > 0) {
    if ((n = read(sock_fd, b, r)) < 0) {
      err("super_cnlt_recv_packet: read() failed: %s", os_ErrorMsg());
      code = -SSERV_ERR_READ_FROM_SERVER;
      goto failed;
    }
    if (!n) {
      err("super_cnlt_recv_packet: unexpected EOF");
      code = -SSERV_ERR_EOF_FROM_SERVER;
      goto failed;
    }
    r -= n; b += n;
  }

  pkt = (struct prot_super_packet*) bb;
  if (pkt->magic != PROT_SUPER_PACKET_MAGIC) {
    err("super_cnlt_recv_packet: bad magic in packet: %04x", pkt->magic);
    code = -SSERV_ERR_PROTOCOL_ERROR;
    goto failed;
  }

  if (p_size) *p_size = in_size;
  if (p_data) *p_data = bb;

  return 0;

 failed:
  xfree(alloc_mem);
  return code;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
