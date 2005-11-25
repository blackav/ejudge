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
super_clnt_create_contest(int sock_fd,
                          int out_fd,
                          int cmd,
                          int num_mode,
                          int templ_mode,
                          int contest_id,
                          int templ_id,
                          const unsigned char *self_url,
                          const unsigned char *hidden_vars,
                          const unsigned char *extra_args)
{
  struct prot_super_pkt_create_contest *out = 0;
  struct prot_super_packet *in = 0;
  size_t self_url_len, hidden_vars_len, extra_args_len, out_size;
  unsigned char *self_url_ptr, *hidden_vars_ptr, *extra_args_ptr;
  int r, pipe_fd[2], pass_fd[2];
  char c;

  if (sock_fd < 0) return -SSERV_ERR_NOT_CONNECTED;

  if (!self_url) self_url = "";
  if (!hidden_vars) hidden_vars = "";
  if (!extra_args) extra_args = "";
  self_url_len = strlen(self_url);
  hidden_vars_len = strlen(hidden_vars);
  extra_args_len = strlen(extra_args);
  out_size = sizeof(*out) + self_url_len + hidden_vars_len + extra_args_len;

  out = alloca(out_size);
  memset(out, 0, out_size);
  self_url_ptr = out->data;
  hidden_vars_ptr = self_url_ptr + self_url_len + 1;
  extra_args_ptr = hidden_vars_ptr + hidden_vars_len + 1;

  out->b.id = cmd;
  out->b.magic = PROT_SUPER_PACKET_MAGIC;
  out->num_mode = num_mode;
  out->templ_mode = templ_mode;
  out->contest_id = contest_id;
  out->templ_id = templ_id;
  out->self_url_len = self_url_len;
  out->hidden_vars_len = hidden_vars_len;
  out->extra_args_len = extra_args_len;
  memcpy(self_url_ptr, self_url, self_url_len);
  memcpy(hidden_vars_ptr, hidden_vars, hidden_vars_len);
  memcpy(extra_args_ptr, extra_args, extra_args_len);

  if (pipe(pipe_fd) < 0) {
    err("super_clnt_main_page: pipe() failed: %s", os_ErrorMsg());
    return -SSERV_ERR_SYSTEM_ERROR;
  }
  pass_fd[0] = out_fd;
  pass_fd[1] = pipe_fd[1];
  if ((r = super_clnt_pass_fd(sock_fd, 2, pass_fd)) < 0) {
    close(pipe_fd[0]); close(pipe_fd[1]);
    return r;
  }
  close(pipe_fd[1]);

  if ((r = super_clnt_send_packet(sock_fd, out_size, out)) < 0) {
    close(pipe_fd[0]);
    return r;
  }

  in = (struct prot_super_packet*) alloca(sizeof(*in));
  memset(in, 0, sizeof(*in));
  if ((r = super_clnt_recv_packet(sock_fd, in, 0, 0)) < 0) {
    close(pipe_fd[0]);
    return r;
  }

  if (in->id < 0) {
    close(pipe_fd[0]);
    return in->id;
  }
  if (in->id != SSERV_RPL_OK) {
    close(pipe_fd[0]);
    err("super_clnt_main_page: unexpected reply: %d", in->id);
    return -SSERV_ERR_PROTOCOL_ERROR;
  }

  if ((r = read(pipe_fd[0], &c, 1)) < 0) {
    err("super_clnt_main_page: read() failed: %s", os_ErrorMsg());
    close(pipe_fd[0]);
    return -SSERV_ERR_READ_FROM_SERVER;
  }
  if (r > 0) {
    err("super_clnt_main_page: data in wait pipe");
    close(pipe_fd[0]);
    return -SSERV_ERR_PROTOCOL_ERROR;
  }
  close(pipe_fd[0]);
  return SSERV_RPL_OK;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
