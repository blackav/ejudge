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

#include "errlog.h"

int
userlist_clnt_list_users(struct userlist_clnt *clnt,
                         ej_ip_t origin_ip,
                         int ssl,
                         int contest_id,
                         int locale_id,
                         int user_id,
                         unsigned long flags,
                         const unsigned char *url,
                         const unsigned char *srch)
{
  struct userlist_pk_list_users *out = 0;
  struct userlist_packet *in = 0;
  int r;
  size_t out_size, url_len, srch_len, in_size = 0;
  unsigned char *url_ptr, *srch_ptr;
  int pp[2];
  int pfd[2];
  char b;

  if (pipe(pp) < 0) {
    err("pipe() failed: %s", os_ErrorMsg());
    return -ULS_ERR_WRITE_ERROR;
  }
  pfd[0] = 1;
  pfd[1] = pp[1];

  if (!url) url = "";
  if (!srch) srch = "";
  url_len = strlen(url);
  srch_len = strlen(srch);
  if (url_len > 255) return -ULS_ERR_PROTOCOL;
  if (srch_len > 255) return -ULS_ERR_PROTOCOL;
  if (user_id < 0) return -ULS_ERR_PROTOCOL;
  out_size = sizeof(*out) + url_len + srch_len;
  out = (struct userlist_pk_list_users*) alloca(out_size);
  if (!out) return -ULS_ERR_OUT_OF_MEM;
  memset(out, 0, sizeof(*out));
  url_ptr = out->data;
  srch_ptr = url_ptr + url_len + 1;
  out->request_id = ULS_LIST_USERS;
  out->origin_ip = origin_ip;
  out->ssl = ssl;
  out->contest_id = contest_id;
  out->locale_id = locale_id;
  out->user_id = user_id;
  out->flags = flags;
  out->url_len = url_len;
  out->srch_len = srch_len;
  memcpy(url_ptr, url, url_len + 1);
  memcpy(srch_ptr, srch, srch_len + 1);

  if ((r = userlist_clnt_pass_fd(clnt, 2, pfd)) < 0) return r;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, (void*) &in)) < 0)
    return r;
  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  if (r < 0) return r;

  close(pfd[1]);
  r = read(pp[0], &b, 1);
  if (r > 0) return -ULS_ERR_PROTOCOL;
  if (r < 0) return -ULS_ERR_READ_ERROR;
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
