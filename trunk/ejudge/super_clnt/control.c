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

#include "super_clnt.h"
#include "super_proto.h"

#include <stdlib.h>
#include <unistd.h>

static int
silent_recv_packet(int sock_fd, struct prot_super_packet *p_res)
{
  unsigned char *b, *bb;
  int in_size, r, n, code = -SSERV_UNKNOWN_ERROR;
  struct prot_super_packet *pkt;

  if (sock_fd < 0) return -SSERV_ERR_NOT_CONNECTED;

  // read packet length
  b = (unsigned char*) &in_size;
  r = 4;
  while (r > 0) {
    if ((n = read(sock_fd, b, r)) < 0) {
      code = -SSERV_ERR_READ_FROM_SERVER;
      goto failed;
    }
    if (!n) {
      code = -SSERV_ERR_EOF_FROM_SERVER;
      goto failed;
    }
    r -= n; b += n;
  }

  if (p_res) {
    if (in_size != sizeof(*p_res)) {
      code = -SSERV_ERR_PROTOCOL_ERROR;
      goto failed;
    }
    bb = b = (unsigned char*) p_res;
    r = in_size;
  }

  while (r > 0) {
    if ((n = read(sock_fd, b, r)) < 0) {
      code = -SSERV_ERR_READ_FROM_SERVER;
      goto failed;
    }
    if (!n) {
      code = -SSERV_ERR_EOF_FROM_SERVER;
      goto failed;
    }
    r -= n; b += n;
  }

  pkt = (struct prot_super_packet*) bb;
  if (pkt->magic != PROT_SUPER_PACKET_MAGIC) {
    code = -SSERV_ERR_PROTOCOL_ERROR;
    goto failed;
  }

  return 0;

 failed:
  return code;
}

int
super_clnt_control(int sock_fd, int cmd)
{
  struct prot_super_packet *out = 0;
  struct prot_super_packet *in = 0;
  size_t out_size;
  int r;

  if (sock_fd < 0) return -SSERV_ERR_NOT_CONNECTED;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->id = cmd;
  out->magic = PROT_SUPER_PACKET_MAGIC;

  in = (struct prot_super_packet*) alloca(sizeof(*in));
  memset(in, 0, sizeof(*in));

  if ((r = super_clnt_send_packet(sock_fd, out_size, out)) < 0) return r;
  r = silent_recv_packet(sock_fd, in);
  if (r == -SSERV_ERR_EOF_FROM_SERVER) return 0;
  if (r < 0) return r;
  if (in->id >= 0) {
    return -SSERV_ERR_PROTOCOL_ERROR;
  }
  return in->id;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
