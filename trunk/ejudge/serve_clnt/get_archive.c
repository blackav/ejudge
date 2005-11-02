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

#define XALLOCAZB(p,s) (((p) = (typeof(p)) alloca((s))),(memset((p), 0, (s))))

int
serve_clnt_get_archive(int sock_fd, int user_id, int contest_id,
                       int locale_id, int *p_token,
                       unsigned char **p_path)
{
  size_t out_size, in_size;
  int r;
  struct prot_serve_pkt_get_archive *out;
  struct prot_serve_pkt_archive_path *in;
  void *void_in = 0;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  *p_token = 0;
  *p_path = 0;
  out_size = sizeof(*out);
  XALLOCAZB(out, out_size);
  out->b.id = SRV_CMD_GET_ARCHIVE;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  out->user_id = user_id;
  out->contest_id = contest_id;
  out->locale_id = locale_id;
  if ((r = serve_clnt_send_packet(sock_fd, out_size, out)) < 0)
    return r;
  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, &void_in)) < 0)
    return r;
  in = void_in;
  if (in->b.id < 0) {
    r = in->b.id;
    xfree(in);
    return r;
  }
  if (in->b.id != SRV_RPL_ARCHIVE_PATH) {
    err("serve_clnt_get_archive: unexpected reply: %d", in->b.id);
    xfree(in);
    return -SRV_ERR_PROTOCOL;
  }
  if (in_size < sizeof(*in)) {
    err("serve_clnt_get_archive: packet length mismatch: %zu", in_size);
    xfree(in);
    return -SRV_ERR_PROTOCOL;
  }
  if (strlen(in->data) != in->path_len) {
    err("serve_clnt_get_archive: path_len mismatch");
    xfree(in);
    return -SRV_ERR_PROTOCOL;
  }
  if (in_size != sizeof(*in) + in->path_len) {
    err("serve_clnt_get_archive: packet length mismatch: %zu", in_size);
    xfree(in);
    return -SRV_ERR_PROTOCOL;
  }
  r = in->b.id;
  *p_token = in->token;
  *p_path = xstrdup(in->data);
  xfree(in);
  return r;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
