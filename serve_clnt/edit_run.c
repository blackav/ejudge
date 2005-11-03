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

static int
do_serve_clnt_edit_run(int sock_fd, int cmd, int run_id, int mask,
                       int user_id, int prob_id, int lang_id, int status,
                       int is_imported, int variant, int is_hidden,
                       int tests, int score, int is_readonly, int pages,
                       ej_ip_t ip, int ssl, int run_size,
                       unsigned char const *user_login,
                       unsigned char const *run_src,
                       int score_adj)
{
  struct prot_serve_pkt_run_info *out;
  struct prot_serve_packet *in = 0;
  size_t out_size, in_size = 0, user_login_len;
  unsigned char *user_login_ptr, *run_src_ptr;
  int r;
  void *void_in;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  if (!user_login) user_login = "";
  if (!run_src) {
    run_src = "";
    run_size = 0;
  }
  if (run_size < 0) {
    err("serve_clnt_edit_run: negative source length");
    return -SRV_ERR_PROTOCOL;
  }
  user_login_len = strlen(user_login);
  out_size = sizeof(*out) + user_login_len + run_size;
  out = alloca(out_size);
  memset(out, 0, out_size);
  user_login_ptr = out->data;
  run_src_ptr = user_login_ptr + user_login_len + 1;
  if (cmd != SRV_CMD_EDIT_RUN && cmd != SRV_CMD_NEW_RUN) {
    err("serve_clnt_edit_run: invalid command %d", cmd);
    return -SRV_ERR_PROTOCOL;
  }
  out->b.id = cmd;
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
  out->tests = tests;
  out->score = score;
  out->is_readonly = is_readonly;
  out->pages = pages;
  out->ip = ip;
  out->ssl = ssl;
  out->score_adj = score_adj;
  out->user_login_len = user_login_len;
  out->run_src_len = run_size;
  strcpy(user_login_ptr, user_login);
  memcpy(run_src_ptr, run_src, run_size);

  if ((r = serve_clnt_send_packet(sock_fd, out_size, out)) < 0) {
    return r;
  }
  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, &void_in)) < 0) {
    return r;
  }
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

int
serve_clnt_edit_run(int sock_fd, int run_id, int mask,
                    int user_id, int prob_id, int lang_id, int status,
                    int is_imported, int variant, int is_hidden,
                    int tests, int score, int is_readonly, int pages,
                    unsigned char const *user_login, int score_adj)
{
  return do_serve_clnt_edit_run(sock_fd, SRV_CMD_EDIT_RUN, run_id, mask,
                                user_id, prob_id, lang_id, status,
                                is_imported, variant, is_hidden,
                                tests, score, is_readonly, pages, 0, 0,0,
                                user_login, 0, score_adj);
}

int
serve_clnt_new_run(int sock_fd, int mask,
                   int user_id, int prob_id, int lang_id, int status,
                   int is_imported, int variant, int is_hidden,
                   int tests, int score, int is_readonly, int pages,
                   ej_ip_t ip, int ssl, int run_size,
                   unsigned char const *user_login,
                   unsigned char const *run_src)
{
  return do_serve_clnt_edit_run(sock_fd, SRV_CMD_NEW_RUN, 0, mask,
                                user_id, prob_id, lang_id, status,
                                is_imported, variant, is_hidden,
                                tests, score, is_readonly, pages, ip,
                                ssl, run_size, user_login, run_src, 0);
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
