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
userlist_clnt_set_passwd(struct userlist_clnt *clnt,
                         int uid,
                         const unsigned char *old_pwd,
                         const unsigned char *new_pwd)
{
  struct userlist_pk_set_password *out;
  struct userlist_packet *in;
  int old_len, new_len, r;
  size_t out_size = 0, in_size = 0;
  unsigned char *pkt_old_ptr;
  unsigned char *pkt_new_ptr;

  ASSERT(clnt);
  ASSERT(old_pwd);
  ASSERT(new_pwd);

  old_len = strlen(old_pwd);
  new_len = strlen(new_pwd);
  if (old_len > 255) return -ULS_ERR_INVALID_SIZE;
  if (new_len > 255) return -ULS_ERR_INVALID_SIZE;
  out_size = sizeof(*out) + old_len + new_len;
  out = (struct userlist_pk_set_password *) alloca(out_size);
  if (!out) return -ULS_ERR_OUT_OF_MEM;
  memset(out, 0, out_size);
  out->request_id = ULS_SET_PASSWD;
  out->user_id = uid;
  out->old_len = old_len;
  out->new_len = new_len;
  pkt_old_ptr = out->data;
  pkt_new_ptr = pkt_old_ptr + old_len + 1;
  memcpy(pkt_old_ptr, old_pwd, old_len + 1);
  memcpy(pkt_new_ptr, new_pwd, new_len + 1);
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
