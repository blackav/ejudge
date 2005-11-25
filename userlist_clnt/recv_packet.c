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

#include "userlist_clnt/private.h"

#include "errlog.h"

int
userlist_clnt_recv_packet(struct userlist_clnt *clnt,
                          size_t *p_size, void **p_data)
{
  unsigned char len_buf[4], *b, *bb = 0;
  int r, n;
  int sz;
  int code = 0;

  ASSERT(clnt);
  ASSERT(p_size);
  ASSERT(p_data);
  ASSERT(clnt->fd >= 0);

  *p_size = 0;
  *p_data = 0;

  // read length
  b = len_buf;
  r = 4;
  while (r > 0) {
    n = read(clnt->fd, b, r);
    if (n < 0) {
      err("read() from userlist-server failed: %s", os_ErrorMsg());
      code = -ULS_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
      err("unexpected EOF from userlist-server");
      code = -ULS_ERR_UNEXPECTED_EOF;
      goto io_error;
    }
    r -= n; b += n;
  }
  memcpy(&sz, len_buf, 4);
  if (sz <= 0) {
    err("invalid packet length %d from userlist-server", sz);
    code = -ULS_ERR_PROTOCOL;
    goto io_error;
  }
  bb = b = (unsigned char*) xcalloc(1, sz);
  r = sz;

  // read the packet
  while (r > 0) {
    n = read(clnt->fd, b, r);
    if (n < 0) {
      err("read() from userlist-server failed: %s", os_ErrorMsg());
      code = -ULS_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
      err("unexpected EOF from userlist-server");
      code = -ULS_ERR_UNEXPECTED_EOF;
      goto io_error;
    }
    r -= n; b += n;
  }

  *p_size = sz;
  *p_data = bb;

  return 0;
 io_error:
  if (bb) xfree(bb);
  close(clnt->fd);
  clnt->fd = -1;
  return code;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
