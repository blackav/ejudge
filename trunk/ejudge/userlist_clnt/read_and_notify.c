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
userlist_clnt_read_and_notify(struct userlist_clnt *clnt,
                              size_t *p_size, void **p_data)
{
  int r;
  struct userlist_pk_notification *in;

  while (1) {
    if ((r = userlist_clnt_recv_packet(clnt, p_size, p_data)) < 0)
      return r;
    if (*p_size != sizeof(*in)) return 0;
    in = (struct userlist_pk_notification*) *p_data;
    if (in->reply_id != ULS_NOTIFICATION) return 0;
    if (clnt->notification_callback)
      clnt->notification_callback(clnt->notification_user_data, in->contest_id);
    xfree(in);
    *p_size = 0;
    *p_data = 0;
  }
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
