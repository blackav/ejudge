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

#include "serve_clnt.h"
#include "protocol.h"
#include "pathutl.h"

#include <reuse/xalloc.h>

#include <stdlib.h>

int
serve_clnt_reset_filter(int sock_fd,
                        int cmd,
                        ej_cookie_t session_id,
                        int user_id,
                        int contest_id)
{
  struct prot_serve_pkt_reset_filter *out = 0;
  struct prot_serve_packet *in = 0;
  size_t out_size = 0, in_size = 0;
  int r;
  void *void_in = 0;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->b.id = cmd;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->session_id = session_id;
  out->user_id = user_id;
  out->contest_id = contest_id;
  if ((r = serve_clnt_send_packet(sock_fd, out_size, out)) < 0) {
    return r;
  }
  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, &void_in)) < 0) {
    return r;
  }
  in = void_in;
  if (in_size != sizeof(*in)) {
    xfree(in);
    err("serve_clnt_upload_report: unexpected reply length %zu", in_size);
    return -SRV_ERR_PROTOCOL;
  }
  if (in->id < 0) {
    r = in->id;
    xfree(in);
    return r;
  }
  if (in->id != SRV_RPL_OK) {
    xfree(in);
    err("serve_clnt_submit_run: unexpected reply: %d", in->id);
    return -SRV_ERR_PROTOCOL;
  }
  xfree(in);
  return SRV_RPL_OK;
}
                        

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
