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
serve_clnt_simple_cmd(int sock_fd, int cmd, void const *val, size_t val_len)
{
  struct prot_serve_pkt_simple *out;
  struct prot_serve_packet *in = 0;
  size_t out_size, in_size = 0;
  int r;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  if (val_len > sizeof(out->v)) return -SRV_ERR_PROTOCOL;
  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->b.id = cmd;
  out->b.magic = PROT_SERVE_PACKET_MAGIC;
  if (val_len) {
    memcpy(&out->v, val, val_len);
  }

  if ((r = serve_clnt_send_packet(sock_fd, out_size, out)) < 0) {
    return r;
  }

  if ((r = serve_clnt_recv_packet(sock_fd, &in_size, (void**) &in)) < 0) {
    return r;
  }

  if (in->id < 0) {
    r = in->id;
    xfree(in);
    return r;
  }
  if (in->id != SRV_RPL_OK) {
    xfree(in);
    err("serve_clnt_view: unexpected reply: %d", in->id);
    return -SRV_ERR_PROTOCOL;
  }
  xfree(in);
  return SRV_RPL_OK;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */

