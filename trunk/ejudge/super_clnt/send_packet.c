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
#include "pathutl.h"

#include <reuse/osdeps.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* FIXME: maybe it is better to use writev? */
int
super_clnt_send_packet(int sock_fd, int size, const void *buf)
{
  unsigned char *b;
  int w = size + sizeof(size), n;

  if (sock_fd < 0) return -SSERV_ERR_NOT_CONNECTED;

  b = (unsigned char *) alloca(w);
  memcpy(b, &size, sizeof(size));
  memcpy(b + sizeof(size), buf, size);

  while (w > 0) {
    if ((n = write(sock_fd, b, w)) <= 0) {
      err("super_clnt_send_packet: write() failed: %s", os_ErrorMsg());
      return -SSERV_ERR_WRITE_TO_SERVER;
    }
    w -= n; b += n;
  }
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
