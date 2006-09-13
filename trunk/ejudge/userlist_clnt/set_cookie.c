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
userlist_clnt_set_cookie(struct userlist_clnt *clnt,
                         int cmd,
                         ej_cookie_t cookie,
                         int value)
{
  struct userlist_pk_edit_field *out = 0;
  struct userlist_packet *in = 0;
  size_t out_size = 0, in_size = 0;
  void *void_in = 0;
  int r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = cmd;
  out->cookie = cookie;
  out->serial = value;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &void_in)) < 0)
    return r;
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
