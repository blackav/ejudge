/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002,2004 Alexander Chernov <cher@ispras.ru> */

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
serve_clnt_send_packet(int sock_fd, int size, void const *buf)
{
  unsigned char *b;
  int w, n;

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;
  b = (unsigned char*) alloca(size + 4);
  memcpy(b, &size, 4);
  memcpy(b + 4, buf, size);
  w = size + 4;

  while (w > 0) {
    n = write(sock_fd, b, w);
    if (n <= 0) {
      err("serve_clnt_send_packet: write() failed: %s", os_ErrorMsg());
      return -SRV_ERR_WRITE_TO_SERVER;
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
