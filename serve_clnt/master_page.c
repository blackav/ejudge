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
serve_clnt_master_page(int sock_fd,
                       int out_fd,
                       int cmd,
                       ej_cookie_t session_id,
                       int user_id,
                       int contest_id,
                       int locale_id,
                       ej_ip_t ip,
                       int ssl,
                       int priv_level,
                       int first_run,
                       int last_run,
                       int mode_clar,
                       int first_clar,
                       int last_clar,
                       unsigned char const *self_url,
                       unsigned char const *filter_expr,
                       unsigned char const *hidden_vars,
                       unsigned char const *extra_args)
{
  struct prot_serve_pkt_master_page *out = 0;
  struct prot_serve_packet *in = 0;
  size_t self_url_len, filter_expr_len, hidden_vars_len, extra_args_len;
  size_t out_size, in_size = 0;
  unsigned char *self_url_ptr, *filter_expr_ptr, *hidden_vars_ptr, c;
  unsigned char *extra_args_ptr;
  int r, pipe_fd[2], pass_fd[2];
  void *void_in = 0;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  if (!self_url) self_url = "";
  if (!filter_expr) filter_expr = "";
  if (!hidden_vars) hidden_vars = "";
  if (!extra_args) extra_args = "";
  self_url_len = strlen(self_url);
  filter_expr_len = strlen(filter_expr);
  hidden_vars_len = strlen(hidden_vars);
  extra_args_len = strlen(extra_args);
  out_size = sizeof(*out) + self_url_len + filter_expr_len + hidden_vars_len + extra_args_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  self_url_ptr = out->data;
  filter_expr_ptr = self_url_ptr + self_url_len + 1;
  hidden_vars_ptr = filter_expr_ptr + filter_expr_len + 1;
  extra_args_ptr = hidden_vars_ptr + hidden_vars_len + 1;
  out->b.id = cmd;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->session_id = session_id;
  out->user_id = user_id;
  out->contest_id = contest_id;
  out->locale_id = locale_id;
  out->ip = ip;
  out->ssl = ssl;
  out->priv_level = priv_level;
  out->first_run = first_run;
  out->last_run = last_run;
  out->mode_clar = mode_clar;
  out->first_clar = first_clar;
  out->last_clar = last_clar;
  out->self_url_len = self_url_len;
  out->filter_expr_len = filter_expr_len;
  out->hidden_vars_len = hidden_vars_len;
  out->extra_args_len = extra_args_len;
  memcpy(self_url_ptr, self_url, self_url_len);
  memcpy(filter_expr_ptr, filter_expr, filter_expr_len);
  memcpy(hidden_vars_ptr, hidden_vars, hidden_vars_len);
  memcpy(extra_args_ptr, extra_args, extra_args_len);

  if (pipe(pipe_fd) < 0) {
    err("serve_clnt_team_page: pipe() failed: %s", os_ErrorMsg());
    return -SRV_ERR_SYSTEM_ERROR;
  }
  pass_fd[0] = out_fd;
  pass_fd[1] = pipe_fd[1];
  if ((r = serve_clnt_pass_fd(sock_fd, 2, pass_fd)) < 0) {
    close(pipe_fd[1]); close(pipe_fd[0]);
    return r;
  }
  close(pipe_fd[1]);

  if ((r = serve_clnt_send_packet(sock_fd, out_size, out)) < 0) {
    close(pipe_fd[0]);
    return r;
  }
  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, &void_in)) < 0) {
    close(pipe_fd[0]);
    return r;
  }
  in = void_in;
  if (in->id < 0) {
    close(pipe_fd[0]);
    r = in->id;
    xfree(in);
    return r;
  }
  if (in->id != SRV_RPL_OK) {
    close(pipe_fd[0]);
    xfree(in);
    err("serve_clnt_submit_run: unexpected reply: %d", in->id);
    return -SRV_ERR_PROTOCOL;
  }
  xfree(in);
  r = read(pipe_fd[0], &c, 1);
  if (r < 0) {
    err("serve_clnt_list_runs: read() failed: %s", os_ErrorMsg());
    close(pipe_fd[0]);
    return -SRV_ERR_READ_FROM_SERVER;
  }
  if (r > 0) {
    err("serve_clnt_list_runs: data in wait pipe");
    close(pipe_fd[0]);
    return -SRV_ERR_PROTOCOL;
  }
  close(pipe_fd[0]);
  return SRV_RPL_OK;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
