/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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
userlist_clnt_priv_cookie_login(
	struct userlist_clnt *clnt,
        int cmd,
        ej_ip_t origin_ip,
        int ssl,
        int contest_id,
        ej_cookie_t cookie,
        int locale_id,
        int role,
        // output parameters
        int *p_user_id,
        ej_cookie_t *p_cookie,
        unsigned char **p_login,
        unsigned char **p_name)
{
  struct userlist_pk_cookie_login *out = 0;
  struct userlist_pk_login_ok *in = 0;
  size_t out_size, in_size = 0;
  int r;
  void *void_in = 0;
  const unsigned char *login_ptr = 0, *name_ptr = 0;

  if (!clnt) return -ULS_ERR_NO_CONNECT;
  if (!origin_ip) return -ULS_ERR_IP_NOT_ALLOWED;
  if (!cookie) return -ULS_ERR_NO_COOKIE;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = cmd;
  out->origin_ip = origin_ip;
  out->ssl = ssl;
  out->contest_id = contest_id;
  out->cookie = cookie;
  out->locale_id = locale_id;
  out->role = role;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &void_in)) < 0)
    return r;
  in = void_in;
  if (in->reply_id < 0) {
    r = in->reply_id;
    goto cleanup;
  }
  if (in->reply_id != ULS_LOGIN_COOKIE) {
    r = -ULS_ERR_PROTOCOL;
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
  if (p_user_id) *p_user_id = in->user_id;
  if (p_cookie) *p_cookie = in->cookie;
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
