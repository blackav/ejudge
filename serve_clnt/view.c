/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "serve_clnt.h"
#include "protocol.h"
#include "pathutl.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <unistd.h>

int
serve_clnt_view(int sock_fd,
                int out_fd,
                int cmd,
                int item,
                int sid_mode,
                unsigned char const *self_url,
                unsigned char const *hidden_vars)
{
  struct prot_serve_pkt_view *out;
  struct prot_serve_packet *in = 0;
  size_t self_url_len, hidden_vars_len;
  size_t out_size, in_size = 0;
  unsigned char *self_url_ptr, *hidden_vars_ptr, c;
  int r, pipe_fd[2], pass_fd[2];

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  if (!self_url) self_url = "";
  if (!hidden_vars) hidden_vars = "";
  self_url_len = strlen(self_url);
  hidden_vars_len = strlen(hidden_vars);
  out_size = sizeof(*out) + self_url_len + hidden_vars_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  self_url_ptr = out->data;
  hidden_vars_ptr = self_url_ptr + hidden_vars_len + 1;
  if (cmd != SRV_CMD_VIEW_REPORT && cmd != SRV_CMD_VIEW_CLAR
      && cmd != SRV_CMD_VIEW_SOURCE
      && cmd != SRV_CMD_VIEW_USERS) {
    err("serve_clnt_view: invalid command %d", cmd);
    return -SRV_ERR_PROTOCOL;
  }

  out->b.id = cmd;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->item = item;
  out->sid_mode = sid_mode;
  out->self_url_len = self_url_len;
  out->hidden_vars_len = hidden_vars_len;
  memcpy(self_url_ptr, self_url, self_url_len);
  memcpy(hidden_vars_ptr, hidden_vars, hidden_vars_len);

  if (pipe(pipe_fd) < 0) {
    err("serve_clnt_view: pipe() failed: %s", os_ErrorMsg());
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

  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, (void**) &in)) < 0) {
    close(pipe_fd[0]);
    return r;
  }
  if (in->id < 0) {
    close(pipe_fd[0]);
    r = in->id;
    xfree(in);
    return r;
  }
  if (in->id != SRV_RPL_OK) {
    close(pipe_fd[0]);
    xfree(in);
    err("serve_clnt_view: unexpected reply: %d", in->id);
    return -SRV_ERR_PROTOCOL;
  }
  xfree(in);
  r = read(pipe_fd[0], &c, 1);
  if (r < 0) {
    err("serve_clnt_view: read() failed: %s", os_ErrorMsg());
    close(pipe_fd[0]);
    return -SRV_ERR_READ_FROM_SERVER;
  }
  if (r > 0) {
    err("serve_clnt_view: data in wait pipe");
    close(pipe_fd[0]);
    return -SRV_ERR_PROTOCOL;
  }
  close(pipe_fd[0]);
  return SRV_RPL_OK;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
