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

int
serve_clnt_message(int sock_fd,
                   int cmd,
                   int dest_user_id,
                   int ref_clar_id,
                   unsigned char const *dest_login,
                   unsigned char const *subj,
                   unsigned char const *text)
{
  size_t subj_len, text_len, dest_login_len, out_size, in_size = 0;
  struct prot_serve_pkt_submit_clar *out;
  struct prot_serve_packet *in = 0;
  unsigned char *dest_login_ptr, *subj_ptr, *text_ptr;
  int r;
  void *void_in = 0;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  if (cmd != SRV_CMD_PRIV_MSG && cmd != SRV_CMD_PRIV_REPLY) {
    return -SRV_ERR_PROTOCOL;
  }
  if (!dest_login) dest_login = "";
  if (!subj) subj = "";
  if (!text) text = "";
  dest_login_len = strlen(dest_login);
  subj_len = strlen(subj);
  text_len = strlen(text);
  out_size = sizeof(*out) + dest_login_len + subj_len + text_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  dest_login_ptr = out->data;
  subj_ptr = dest_login_ptr + dest_login_len + 1;
  text_ptr = subj_ptr + subj_len + 1;

  out->b.id = cmd;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->dest_user_id = dest_user_id;
  out->ref_clar_id = ref_clar_id;
  out->dest_login_len = dest_login_len;
  out->subj_len = subj_len;
  out->text_len = text_len;
  strcpy(dest_login_ptr, dest_login);
  strcpy(subj_ptr, subj);
  strcpy(text_ptr, text);

  if ((r = serve_clnt_send_packet(sock_fd, out_size, out)) < 0) {
    return r;
  }
  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, &void_in)) < 0) {
    return r;
  }
  in = void_in;
  if (in->id < 0) {
    r = in->id;
    xfree(in);
    return r;
  }
  if (in->id != SRV_RPL_OK) {
    xfree(in);
    err("serve_clnt_submit_clar: unexpected reply: %d", in->id);
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
