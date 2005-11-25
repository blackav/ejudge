/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2005 Alexander Chernov <cher@ispras.ru> */

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
#include <stdlib.h>
#include <unistd.h>

int
serve_clnt_import_xml_runs(int sock_fd, int out_fd,
                           int flags,
                           const unsigned char *xml_runs)
{
  struct prot_serve_pkt_archive_path *out = 0;
  struct prot_serve_packet *in = 0;
  size_t out_size, xml_runs_len, in_size = 0;
  int r, pipe_fd[2], pass_fd[2];
  unsigned char c;
  void *void_in = 0;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  if (!xml_runs) xml_runs = "";
  xml_runs_len = strlen(xml_runs);
  out_size = sizeof(*out) + xml_runs_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->b.id = SRV_CMD_IMPORT_XML_RUNS;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->token = flags;
  out->path_len = xml_runs_len;
  memcpy(out->data, xml_runs, xml_runs_len);

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
