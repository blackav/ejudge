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
serve_clnt_team_page(int sock_fd, int out_fd,
                     int user_id, int contest_id, int locale_id,
                     unsigned long ip, unsigned int flags,
                     unsigned char const *simple_form,
                     unsigned char const *multi_form)
{
  struct prot_serve_pkt_team_page *out = 0;
  struct prot_serve_packet *in = 0;
  size_t simple_form_len, multi_form_len, out_size, in_size = 0;
  unsigned char *simple_form_ptr, *multi_form_ptr, c;
  int r, pipe_fd[2], pass_fd[2];

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  if (!simple_form) simple_form = "";
  if (!multi_form) multi_form = "";
  simple_form_len = strlen(simple_form);
  multi_form_len = strlen(multi_form);
  out_size = sizeof(*out) + simple_form_len + multi_form_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  simple_form_ptr = out->data;
  multi_form_ptr = simple_form_ptr + simple_form_len + 1;
  out->b.id = SRV_CMD_TEAM_PAGE;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->user_id = user_id;
  out->contest_id = contest_id;
  out->locale_id = locale_id;
  out->ip = ip;
  out->flags = flags;
  out->simple_form_len = simple_form_len;
  out->multi_form_len = multi_form_len;
  memcpy(simple_form_ptr, simple_form, simple_form_len);
  memcpy(multi_form_ptr, multi_form, multi_form_len);

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
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
