/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2004 Alexander Chernov <cher@ispras.ru> */

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

#include <stdlib.h>

int
super_clnt_pass_fd(int sock_fd, int nfd, int *fds)
{
  struct prot_super_packet *out = 0;
  int out_size = 0;
  int r;

  if (sock_fd < 0) return -SSERV_ERR_NOT_CONNECTED;
  if (nfd <= 0 || nfd > 2 || !fds) return -SSERV_ERR_INVALID_FD;
  for (r = 0; r < nfd; r++)
    if (fds[r] < 0) return -SSERV_ERR_INVALID_FD;

  out_size = sizeof(*out);
  out = alloca(out_size);
  out->id = SSERV_CMD_PASS_FD;
  out->magic = PROT_SUPER_PACKET_MAGIC;
  if ((r = super_clnt_send_packet(sock_fd, out_size, out)) < 0) return r;
  return super_clnt_do_pass_fd(sock_fd, nfd, fds);
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
