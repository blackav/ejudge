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
userlist_clnt_priv_cookie(struct userlist_clnt *clnt,
                          unsigned long origin_ip,
                          int ssl,
                          int contest_id,
                          unsigned long long cookie,
                          int locale_id,
                          int priv_level,
                          int *p_user_id,
                          int *p_contest_id,
                          int *p_locale_id,
                          int *p_priv_level,
                          unsigned char **p_login,
                          unsigned char **p_name)
{
  struct userlist_pk_check_cookie *out = 0;
  struct userlist_pk_login_ok *in = 0;
  int out_size = 0, in_size = 0, r;
  unsigned char *login_ptr, *name_ptr;
  void *void_in = 0;

  if (!clnt) return -ULS_ERR_NO_CONNECT;
  if (!origin_ip) return -ULS_ERR_IP_NOT_ALLOWED;
  if (!cookie) return -ULS_ERR_NO_COOKIE;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_PRIV_CHECK_COOKIE;
  out->origin_ip = origin_ip;
  out->ssl = ssl;
  out->contest_id = contest_id;
  out->cookie = cookie;
  out->locale_id = locale_id;
  out->priv_level = priv_level;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_recv_packet(clnt, &in_size, &void_in)) < 0)
    return r;
  in = void_in;
  if (in->reply_id < 0) {
    r = in->reply_id;
    goto cleanup;
  }
  if (in->reply_id != ULS_LOGIN_COOKIE || in_size < sizeof(*in)) {
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
  if (p_locale_id) *p_locale_id = in->locale_id;
  if (p_contest_id) *p_contest_id = in->contest_id;
  if (p_priv_level) *p_priv_level = in->priv_level;
  if (p_login) *p_login = xstrdup(login_ptr);
  if (p_name) *p_name = xstrdup(name_ptr);

  r = in->reply_id;
 cleanup:
  xfree(in);
  return r;


}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
