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
userlist_clnt_recover_passwd_2(struct userlist_clnt *clnt,
                               int cmd,
                               ej_ip_t ip,
                               int ssl_flag,
                               int contest_id,
                               ej_cookie_t cookie,
                               int *p_user_id,
                               unsigned char **p_login,
                               unsigned char **p_name,
                               unsigned char **p_passwd)
{
  struct userlist_pk_check_cookie *out;
  void *in1 = 0;
  struct userlist_packet *in2;
  struct userlist_pk_new_password *in;
  size_t out_size, in_size, login_len, name_len, passwd_len, packet_len;
  int r;
  unsigned char *login_ptr, *name_ptr, *passwd_ptr;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = cmd;
  out->origin_ip = ip;
  out->ssl = ssl_flag;
  out->contest_id = contest_id;
  out->cookie = cookie;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &in1)) < 0)
    return r;
  if (in_size < sizeof(*in2)) goto protocol_error;
  in2 = (struct userlist_packet*) in1;
  if (in2->id < 0) {
    r = in2->id;
    xfree(in1);
    return r;
  }
  if (in2->id != ULS_NEW_PASSWORD) goto protocol_error;
  if (in_size < sizeof(*in)) goto protocol_error;
  in = (struct userlist_pk_new_password *) in1;
  login_ptr = in->data;
  login_len = strlen(login_ptr);
  if (login_len != in->login_len) goto protocol_error;
  name_ptr = login_ptr + login_len + 1;
  name_len = strlen(name_ptr);
  if (name_len != in->name_len) goto protocol_error;
  passwd_ptr = name_ptr + name_len + 1;
  passwd_len = strlen(passwd_ptr);
  if (passwd_len != in->passwd_len) goto protocol_error;
  packet_len = sizeof(*in);
  packet_len += login_len + name_len + passwd_len;
  if (packet_len != in_size) goto protocol_error;

  if (p_user_id) *p_user_id = in->user_id;
  if (p_login) *p_login = xstrdup(login_ptr);
  if (p_name) *p_name = xstrdup(name_ptr);
  if (p_passwd) *p_passwd = xstrdup(passwd_ptr);

  xfree(in1);
  return ULS_NEW_PASSWORD;

 protocol_error:
  xfree(in1);
  return -ULS_ERR_PROTOCOL;

}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
