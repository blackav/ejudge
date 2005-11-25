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

#include <stdlib.h>

int
super_clnt_simple_cmd(int sock_fd,
                      int cmd,
                      int contest_id)
{
  struct prot_super_pkt_simple_cmd *out = 0;
  struct prot_super_packet *in = 0;
  size_t out_size;
  int r;

  if (sock_fd < 0) return -SSERV_ERR_NOT_CONNECTED;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->b.id = cmd;
  out->b.magic = PROT_SUPER_PACKET_MAGIC;
  out->contest_id = contest_id;

  in = (struct prot_super_packet*) alloca(sizeof(*in));
  memset(in, 0, sizeof(*in));

  if ((r = super_clnt_send_packet(sock_fd, out_size, out)) < 0) return r;
  if ((r = super_clnt_recv_packet(sock_fd, in, 0, 0)) < 0) return r;
  if (in->id > 0) {
    err("super_clnt_simple_cmd: unexpected reply: %d", in->id);
    return -SSERV_ERR_PROTOCOL_ERROR;
  }
  return in->id;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
