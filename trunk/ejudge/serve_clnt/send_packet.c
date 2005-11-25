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
#include "errlog.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>
#include <reuse/integral.h>

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

int
serve_clnt_send_packet(int sock_fd, size_t size, void const *buf)
{
  const unsigned char *b;
  int w, n;
  rint32_t size32;
  struct iovec vv[2];

  if (sock_fd < 0) return -SRV_ERR_NOT_CONNECTED;

  /* -1073741824 is 0xc0000000 or 0xffffffffc0000000 */
  if ((size & -1073741824L)) {
    err("send_packet: packet length exceeds 1GiB");
    return -SRV_ERR_WRITE_TO_SERVER;
  }
  size32 = (ruint32_t) size;

  vv[0].iov_base = &size32;
  vv[0].iov_len = sizeof(size32);
  vv[1].iov_base = (void*) buf;
  vv[1].iov_len = size;

  n = writev(sock_fd, vv, 2);
  if (n == size + 4) return 0;
  if (n <= 0) goto write_error;

  /* if the fast method did not work out, try the slow one */
  if (n < 4) {
    w = 4 - n;
    b = (const unsigned char*) &size32 + n;
    while (w > 0) {
      if ((n = write(sock_fd, b, w)) <= 0) goto write_error;
      w -= n;
      b += n;
    }
    n = 4;
  }

  w = size + 4 - n;
  b = (const unsigned char*) buf + n - 4;
  while (w > 0) {
    if ((n = write(sock_fd, b, w)) <= 0) goto write_error;
    w -= n;
    b += n;
  }

  return 0;

 write_error:
  err("serve_clnt_send_packet: write() failed: %s", os_ErrorMsg());
  return -SRV_ERR_WRITE_TO_SERVER;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
