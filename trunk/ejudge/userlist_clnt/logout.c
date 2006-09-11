/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ejudge.ru> */

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
userlist_clnt_logout(struct userlist_clnt *clnt,
                     int cmd,
                     ej_ip_t origin_ip,
                     int ssl,
                     ej_cookie_t cookie)
{
  struct userlist_pk_do_logout out;
  struct userlist_packet *in = 0;
  void *void_in = 0;
  size_t in_size = 0;
  int r;

  memset(&out, 0, sizeof(out));
  out.request_id = cmd;
  out.origin_ip = origin_ip;
  out.ssl = ssl;
  out.cookie = cookie;
  if ((r = userlist_clnt_send_packet(clnt, sizeof(out), &out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &void_in)) < 0)
    return r;
  in = void_in;
  if (in_size != sizeof(*in) || in->id > 0) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
