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
serve_clnt_show_item(int sock_fd, int out_fd, int cmd,
                     int user_id, int contest_id, int locale_id,
                     int item_id)
{
  struct prot_serve_pkt_show_item *out;
  struct prot_serve_packet *in;
  int r;
  size_t out_size, in_size = 0;
  int pipe_fd[2], pass_fd[2];
  unsigned char c;
  void *void_in = 0;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  if (cmd != SRV_CMD_SHOW_CLAR
      && cmd != SRV_CMD_SHOW_SOURCE
      && cmd != SRV_CMD_VIRTUAL_STANDINGS
      && cmd != SRV_CMD_SHOW_REPORT)
    return -SRV_ERR_PROTOCOL;

  if (pipe(pipe_fd) < 0) {
    err("serve_clnt_show_item: pipe() failed: %s", os_ErrorMsg());
    return -SRV_ERR_SYSTEM_ERROR;
  }
  pass_fd[0] = out_fd;
  pass_fd[1] = pipe_fd[1];
  if ((r = serve_clnt_pass_fd(sock_fd, 2, pass_fd)) < 0) {
    close(pipe_fd[1]); close(pipe_fd[0]);
    return r;
  }
  close(pipe_fd[1]);

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->b.id = cmd;
  out->user_id = user_id;
  out->contest_id = contest_id;
  out->locale_id = locale_id;
  out->item_id = item_id;

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
    r = in->id;
    close(pipe_fd[0]);
    xfree(in);
    return r;
  }
  if (in->id != SRV_RPL_OK) {
    close(pipe_fd[0]);
    xfree(in);
    err("serve_clnt_show_item: unexpected reply: %d", in->id);
    return -SRV_ERR_PROTOCOL;
  }
  xfree(in);
  r = read(pipe_fd[0], &c, 1);
  if (r < 0) {
    err("serve_clnt_show_item: read() failed: %s", os_ErrorMsg());
    close(pipe_fd[0]);
    return -SRV_ERR_READ_FROM_SERVER;
  }
  if (r > 0) {
    err("serve_clnt_show_item: data in wait pipe");
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
