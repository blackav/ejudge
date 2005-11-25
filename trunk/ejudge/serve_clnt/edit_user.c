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

#include "serve_clnt.h"
#include "protocol.h"
#include "errlog.h"

#include <reuse/xalloc.h>

int
serve_clnt_edit_user(int sock_fd, int cmd, int user_id, int status,
                     const unsigned char *txt, const unsigned char *cmt)
{
  struct prot_serve_pkt_user_info *out;
  struct prot_serve_packet *in = 0;
  void *void_in;
  size_t out_size = 0, in_size = 0, txt_len, cmt_len;
  unsigned char *cmt_ptr, *txt_ptr;
  int r;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;

  if (!txt) txt = "";
  if (!cmt) cmt = "";
  txt_len = strlen(txt);
  cmt_len = strlen(cmt);
  out_size = sizeof(*out) + txt_len + cmt_len;
  out = (struct prot_serve_pkt_user_info*) alloca(out_size);
  memset(out, 0, out_size);
  txt_ptr = out->data;
  cmt_ptr = out->data + txt_len + 1;

  out->b.id = cmd;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->user_id = user_id;
  out->status = status;
  out->txt_len = txt_len;
  out->cmt_len = cmt_len;
  strcpy(txt_ptr, txt);
  strcpy(cmt_ptr, cmt);

  if ((r = serve_clnt_send_packet(sock_fd, out_size, out)) < 0) return r;
  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, &void_in)) < 0) return r;

  in = void_in;
  if (in_size != sizeof(*in)) {
    xfree(in);
    err("serve_clnt_edit_run: packet length mismatch: %zu", in_size);
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
