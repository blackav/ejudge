/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

int
silent_recv_packet(struct userlist_clnt *clnt, size_t *p_size, void **p_data)
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
      code = -ULS_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
      code = -ULS_ERR_UNEXPECTED_EOF;
      goto io_error;
    }
    r -= n; b += n;
  }
  memcpy(&sz, len_buf, 4);
  if (sz <= 0) {
    code = -ULS_ERR_PROTOCOL;
    goto io_error;
  }
  bb = b = (unsigned char*) xcalloc(1, sz);
  r = sz;

  // read the packet
  while (r > 0) {
    n = read(clnt->fd, b, r);
    if (n < 0) {
      code = -ULS_ERR_READ_ERROR;
      goto io_error;
    }
    if (!n) {
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
  return code;
}

int
userlist_clnt_control(struct userlist_clnt *clnt, int cmd)
{
  struct userlist_packet *out = 0;
  struct userlist_packet *in = 0;
  size_t out_size = 0, in_size = 0;
  void *void_in = 0;
  int r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->id = cmd;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  r = silent_recv_packet(clnt, &in_size, &void_in);
  if (r == -ULS_ERR_UNEXPECTED_EOF) return 0;
  if (r < 0) return r;
  if (in_size != sizeof(*in)) {
    r = -ULS_ERR_PROTOCOL;
  } else {
    in = (struct userlist_packet*) void_in;
    r = in->id;
  }
  xfree(void_in);
  return r;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
