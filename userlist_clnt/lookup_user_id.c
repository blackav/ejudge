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
userlist_clnt_lookup_user_id(struct userlist_clnt *clnt,
                             int user_id, int contest_id,
                             unsigned char **p_login,
                             unsigned char **p_name)
{
  struct userlist_pk_get_user_info *out = 0;
  struct userlist_pk_login_ok *in = 0;
  unsigned char *login_ptr, *name_ptr;
  int r;
  size_t out_size = 0, in_size = 0;
  void *void_in = 0;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_LOOKUP_USER_ID;
  out->user_id = user_id;
  out->contest_id = contest_id;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &void_in)) < 0)
    return r;
  in = void_in;
  if (in->reply_id != ULS_LOGIN_OK) {
    r = in->reply_id;
    goto cleanup;
  }
  if (in_size < sizeof(*in)) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  login_ptr = in->data;
  if (strlen(login_ptr) != in->login_len) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  name_ptr = login_ptr + in->login_len + 1;
  if (strlen(name_ptr) != in->name_len) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  if (in_size != sizeof(*in) + in->login_len + in->name_len) {
    r = -ULS_ERR_PROTOCOL;
    goto cleanup;
  }
  if (p_login) *p_login = xstrdup(login_ptr);
  if (p_name) *p_name = xstrdup(name_ptr);

  r = in->reply_id;
 cleanup:
  xfree(in);
  return r;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
