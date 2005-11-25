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

#include "serve_clnt.h"
#include "protocol.h"
#include "errlog.h"

#include <reuse/xalloc.h>

int
serve_clnt_get_param(int sock_fd, int cmd, unsigned char **p_data)
{
  struct prot_serve_packet out;
  void *void_in = 0;
  size_t in_size = 0, in_data_len = 0;
  struct prot_serve_pkt_data *in = 0;
  int r;
  int errnum = 0;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;

  memset(&out, 0, sizeof(out));
  out.magic = PROT_SERVE_PACKET_MAGIC;
  out.id = cmd;
  if ((r = serve_clnt_send_packet(sock_fd, sizeof(out), &out)) < 0)
    return r;
  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, &void_in)) < 0)
    return r;
  in = void_in;
  if (in_size < sizeof(struct prot_serve_packet)) {
    errnum = 1;
    goto protocol_error;
  }
  if (in->b.magic != PROT_SERVE_PACKET_MAGIC) {
    errnum = 2;
    goto protocol_error;
  }
  if (in->b.id < 0) {
    if (in_size != sizeof(struct prot_serve_packet)) {
      errnum = 3;
      goto protocol_error;
    }
    r = in->b.id;
    xfree(in);
    return r;
  }
  if (in->b.id != SRV_RPL_DATA) {
    errnum = 4;
    goto protocol_error;
  }
  if (in_size < sizeof(*in)) {
    errnum = 5;
    goto protocol_error;
  }
  in_data_len = strlen(in->data);
  if (in_data_len != in->data_len) {
    errnum = 6;
    goto protocol_error;
  }
  if (in_data_len + sizeof(*in) != in_size) {
    errnum = 7;
    goto protocol_error;
  }
  *p_data = xstrdup(in->data);
  xfree(in);
  return 0;

 protocol_error:
  err("serve_clnt_get_param: error %d", errnum);
  if (in) xfree(in);
  return -SRV_ERR_PROTOCOL;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
