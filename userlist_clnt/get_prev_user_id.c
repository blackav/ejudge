/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2011 Alexander Chernov <cher@ejudge.ru> */

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

enum { MAX_FILTER_LEN = 8192 };

int
userlist_clnt_get_prev_user_id(
        struct userlist_clnt *clnt,
        int cmd,
        int contest_id,
        int group_id,
        int user_id,
        const unsigned char *filter,
        int *p_user_id)
{
  struct userlist_pk_list_users_2 *out = 0;
  struct userlist_pk_login_ok *in = 0;
  struct userlist_packet *in_generic = 0;
  void *in_void = 0;
  int filter_len = 0, r;
  size_t out_size, in_size = 0;

  if (!filter) filter = "";
  filter_len = strlen(filter);
  if (filter_len < 0 || filter_len > MAX_FILTER_LEN)
    return -ULS_ERR_PROTOCOL;

  out_size = sizeof(*out) + filter_len;
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = cmd;
  out->contest_id = contest_id;
  out->group_id = group_id;
  out->user_id = user_id;
  out->filter_len = filter_len;
  memcpy(out->data, filter, filter_len + 1);

  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &in_void)) < 0)
    return r;

  if (in_size < sizeof(*in_generic)) {
    xfree(in_void); in_void = 0;
    return -ULS_ERR_PROTOCOL;
  }
  in_generic = (struct userlist_packet *) in_void; in_void = 0;
  if (in_generic->id < 0) {
    r = in_generic->id;
    xfree(in_generic); in_generic = 0;
    return r;
  }
  if (in_generic->id != ULS_LOGIN_OK) {
    r = in_generic->id;
    xfree(in_generic); in_generic = 0;
    return -ULS_ERR_PROTOCOL;
  }
  if (in_size != sizeof(*in)) {
    xfree(in_generic); in_generic = 0;
    return -ULS_ERR_PROTOCOL;
  }
  in = (struct userlist_pk_login_ok*) in_generic; in_generic = 0;
  user_id = in->user_id;
  if (user_id < 0) {
    xfree(in); in = 0;
    return -ULS_ERR_PROTOCOL;
  }
  xfree(in); in = 0;
  if (p_user_id) *p_user_id = user_id;

  return ULS_LOGIN_OK;
}
