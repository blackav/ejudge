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
userlist_clnt_read_notification(struct userlist_clnt *clnt, int *p_contest_id)
{
  void *void_in = 0;
  struct userlist_pk_notification *in = 0;
  int r;
  size_t in_size = 0;

  if ((r = userlist_clnt_recv_packet(clnt, &in_size, &void_in)) < 0) return r;
  in = (struct userlist_pk_notification*) void_in;
  if (in_size != sizeof(*in)) {
    r = -ULS_ERR_PROTOCOL;
    goto done;
  }
  r = in->reply_id;
  if (in->reply_id < 0) goto done;
  if (in->reply_id != ULS_NOTIFICATION) {
    r = -ULS_ERR_PROTOCOL;
    goto done;
  }
  if (p_contest_id) *p_contest_id = in->contest_id;

 done:
  xfree(in);
  return r;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
