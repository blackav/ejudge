/* -*- mode: c -*- */

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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
userlist_clnt_copy_user_info(
        struct userlist_clnt *clnt,
        int cmd,
        int user_id,
        int cnts_from,
        int cnts_to)
{
  struct userlist_pk_edit_field *out = 0;
  struct userlist_packet *in = 0;
  int r;
  size_t out_size, in_size = 0;
  void *void_in = 0;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = cmd;
  out->user_id = user_id;
  out->contest_id = cnts_from;
  out->serial = cnts_to;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &void_in)) < 0)
    return r;
  in = (struct userlist_packet *) void_in;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}
