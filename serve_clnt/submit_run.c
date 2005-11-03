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
#include "pathutl.h"

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
serve_clnt_submit_run(int sock_fd, int cmd,
                      int user_id, int contest_id, int locale_id,
                      ej_ip_t ip, int ssl,
                      int prob_id, int lang_id,
                      int variant,
                      size_t run_size,
                      unsigned char const *run_src)
{
  struct prot_serve_pkt_submit_run *out = 0;
  struct prot_serve_packet *in = 0;
  int r;
  size_t out_size, in_size = 0;
  void *void_in = 0;

  if (cmd != SRV_CMD_SUBMIT_RUN && cmd != SRV_CMD_PRIV_SUBMIT_RUN)
    return -SRV_ERR_PROTOCOL;
  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  out_size = sizeof(*out) + run_size;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->b.id = cmd;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->user_id = user_id;
  out->contest_id = contest_id;
  out->locale_id = locale_id;
  out->ip = ip;
  out->ssl = ssl;
  out->prob_id = prob_id;
  out->lang_id = lang_id;
  out->variant = variant;
  out->run_len = run_size;
  memcpy(out->data, run_src, run_size);

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
