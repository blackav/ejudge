/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002,2003 Alexander Chernov <cher@ispras.ru> */

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

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

int
serve_clnt_edit_run(int sock_fd, int run_id, int mask,
                    int user_id, int prob_id, int lang_id, int status,
                    int is_imported, int variant, int is_hidden,
                    unsigned char const *user_login)
{
  struct prot_serve_pkt_run_info *out;
  struct prot_serve_packet *in = 0;
  size_t out_size, in_size = 0, user_login_len;
  unsigned char *user_login_ptr;
  int r;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  if (!user_login) user_login = "";
  user_login_len = strlen(user_login);
  out_size = sizeof(*out) + user_login_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  user_login_ptr = out->data;
  out->b.id = SRV_CMD_EDIT_RUN;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->run_id = run_id;
  out->mask = mask;
  out->user_id = user_id;
  out->prob_id = prob_id;
  out->lang_id = lang_id;
  out->status = status;
  out->is_imported = is_imported;
  out->variant = variant;
  out->is_hidden = is_hidden;
  out->user_login_len = user_login_len;
  strcpy(user_login_ptr, user_login);

  if ((r = serve_clnt_send_packet(sock_fd, out_size, out)) < 0) {
    return r;
  }
  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, (void**) &in)) < 0) {
    return r;
  }
  if (in_size != sizeof(*in)) {
    xfree(in);
    err("serve_clnt_edit_run: packet length mismatch: %d", in_size);
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
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
