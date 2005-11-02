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

int
userlist_clnt_set_info(struct userlist_clnt *clnt,
                       int uid, int contest_id, const unsigned char *info)
{
  struct userlist_pk_set_user_info *out;
  struct userlist_packet *in = 0;
  size_t out_size, in_size = 0;
  int r;

  ASSERT(clnt);
  ASSERT(clnt->fd >= 0);
  ASSERT(info);

  out_size = sizeof(*out) + strlen(info);
  out = (struct userlist_pk_set_user_info*) alloca(out_size);
  if (!out) return -ULS_ERR_OUT_OF_MEM;
  memset(out, 0, out_size);
  out->request_id = ULS_SET_USER_INFO;
  out->user_id = uid;
  out->contest_id = contest_id;
  strcpy(out->data, info);
  out->info_len = strlen(info);
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_recv_packet(clnt, &in_size, (void*) &in)) < 0)
    return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
