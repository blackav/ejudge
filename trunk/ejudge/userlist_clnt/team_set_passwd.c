/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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
userlist_clnt_team_set_passwd(struct userlist_clnt *clnt,
                              int uid, unsigned char *old_pwd,
                              unsigned char *new_pwd)
{
  struct userlist_pk_set_password *out = 0;
  struct userlist_packet *in = 0;
  int out_size = 0, in_size = 0, old_len = 0, new_len = 0, r;
  unsigned char *old_ptr, *new_ptr;

  ASSERT(clnt);
  ASSERT(old_pwd);
  ASSERT(new_pwd);

  old_len = strlen(old_pwd);
  new_len = strlen(new_pwd);
  if (old_len > 255) return -ULS_ERR_INVALID_SIZE;
  if (new_len > 255) return -ULS_ERR_INVALID_SIZE;
  out_size = sizeof(*out) + old_len + new_len + 2;
  out = (struct userlist_pk_set_password *) alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_TEAM_SET_PASSWD;
  out->user_id = uid;
  out->old_len = old_len;
  out->new_len = new_len;
  old_ptr = out->data;
  new_ptr = old_ptr + old_len + 1;
  strcpy(old_ptr, old_pwd);
  strcpy(new_ptr, new_pwd);
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
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
