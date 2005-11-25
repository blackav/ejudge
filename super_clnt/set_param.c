/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

#include <stdlib.h>
#include <unistd.h>

int
super_clnt_set_param(int sock_fd,
                     int cmd,
                     int param1,
                     const unsigned char *param2,
                     int param3,
                     int param4,
                     int param5)
{
  size_t param2_len, out_size;
  struct prot_super_pkt_set_param *out = 0;
  struct prot_super_packet *in = 0;
  unsigned char *param2_ptr;
  int r;

  if (sock_fd < 0) return -SSERV_ERR_NOT_CONNECTED;

  if (!param2) param2 = "";
  param2_len = strlen(param2);
  out_size = sizeof(*out) + param2_len;

  out = (struct prot_super_pkt_set_param *) alloca(out_size);
  memset(out, 0, out_size);
  param2_ptr = out->data;

  out->b.id = cmd;
  out->b.magic = PROT_SUPER_PACKET_MAGIC;
  out->param1 = param1;
  out->param2_len = param2_len;
  memcpy(param2_ptr, param2, param2_len);
  out->param3 = param3;
  out->param4 = param4;
  out->param5 = param5;

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
