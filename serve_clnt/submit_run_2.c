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

#include "ej_limits.h"
#include "serve_clnt.h"
#include "protocol.h"

#include <reuse/xalloc.h>

#include <stdlib.h>

int
serve_clnt_submit_run_2(int sock_fd, int cmd,
                        int user_id, int contest_id,
                        ej_ip_t ip, int ssl,
                        const unsigned char *prob_name,
                        const unsigned char *lang_name,
                        int variant,
                        size_t run_size,
                        const unsigned char *run_src,
                        int *p_run_id)
{
  struct prot_serve_pkt_submit_run_2 *out = 0;
  struct prot_serve_packet *in = 0;
  struct prot_serve_pkt_val *in_val = 0;
  int r;
  size_t prob_size, lang_size, in_size = 0, out_size = 0;
  unsigned char *prob_ptr, *lang_ptr, *src_ptr;
  void *void_in;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  prob_size = strlen(prob_name);
  lang_size = strlen(lang_name);
  out_size = sizeof(*out) + prob_size + lang_size + run_size;
  out = alloca(out_size);
  memset(out, 0, out_size);
  prob_ptr = out->data;
  lang_ptr = prob_ptr + prob_size + 1;
  src_ptr = lang_ptr + lang_size + 1;
  out->b.id = cmd;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->user_id = user_id;
  out->contest_id = contest_id;
  out->ip = ip;
  out->ssl = ssl;
  out->prob_size = prob_size;
  out->lang_size = lang_size;
  out->variant = variant;
  out->run_size = run_size;
  memcpy(prob_ptr, prob_name, prob_size);
  memcpy(lang_ptr, lang_name, lang_size);
  memcpy(src_ptr, run_src, run_size);

  if ((r = serve_clnt_send_packet(sock_fd, out_size, out)) < 0) return r;
  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, &void_in)) < 0) return r;
  if (in_size < sizeof(*in)) goto protocol_error;
  in = (struct prot_serve_packet*) void_in;
  if (in->id < 0) {
    if (in_size != sizeof(*in)) goto protocol_error;
    r = in->id;
    xfree(in);
    return r;
  }
  in_val = (struct prot_serve_pkt_val*) void_in;
  if (in_size != sizeof(*in_val)) goto protocol_error;
  if (in_val->b.id != SRV_RPL_VALUE) goto protocol_error;
  if (in_val->value < 0 || in_val->value > EJ_MAX_RUN_ID) goto protocol_error;
  if (p_run_id) *p_run_id = in_val->value;
  xfree(in);
  return 0;

 protocol_error:
  xfree(in);
  return -SRV_ERR_PROTOCOL;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
