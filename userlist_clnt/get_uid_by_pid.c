/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ejudge.ru> */

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
userlist_clnt_get_uid_by_pid(struct userlist_clnt *clnt,
                             int system_uid,
                             int system_gid,
                             int system_pid,
                             int contest_id,
                             int *p_uid,
                             int *p_priv_level,
                             ej_cookie_t *p_cookie,
                             ej_ip_t *p_ip,
                             int *p_ssl)
{
  struct userlist_pk_get_uid_by_pid *out = 0;
  struct userlist_pk_uid *in = 0;
  size_t out_size = 0, in_size = 0;
  int r;

  out_size = sizeof(*out);
  out = alloca(out_size);
  memset(out, 0, out_size);
  out->request_id = ULS_GET_UID_BY_PID;
  out->system_uid = system_uid;
  out->system_gid = system_gid;
  out->system_pid = system_pid;
  out->contest_id = contest_id;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, (void*) &in)) < 0)
    return r;
  if (in_size < sizeof(struct userlist_packet)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  if (in->reply_id < 0) {
    r = in->reply_id;
    xfree(in);
    return r;
  }
  if (in->reply_id != ULS_UID || in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  if (p_uid) *p_uid = in->uid;
  if (p_cookie) *p_cookie = in->cookie;
  if (p_priv_level) *p_priv_level = in->priv_level;
  if (p_ip) *p_ip = in->ip;
  if (p_ssl) *p_ssl = in->ssl;
  xfree(in);
  return ULS_UID;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
