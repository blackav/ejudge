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
userlist_clnt_register_new(struct userlist_clnt *clnt,
                           int cmd,
                           ej_ip_t origin_ip,
                           int ssl,
                           int contest_id,
                           int locale_id,
                           int action,
                           unsigned char const *login,
                           unsigned char const *email,
                           unsigned char const *self_url)
{
  struct userlist_pk_register_new *data;
  int len;
  short * answer;
  size_t anslen;
  int res;
  int r;
  unsigned char *p;

  if (!self_url) self_url = "";
  len = sizeof(*data);
  len += strlen(login);
  len += strlen(email);
  len += strlen(self_url);
  data = alloca(len);
  memset(data, 0, len);
  data->request_id = cmd;
  data->origin_ip = origin_ip;
  data->ssl = ssl;
  data->contest_id = contest_id;
  data->locale_id = locale_id;
  data->action = action;
  data->login_length = strlen(login);
  data->email_length = strlen(email);
  data->self_url_length = strlen(self_url);
  p = data->data;
  strcpy(p, login); p += data->login_length + 1;
  strcpy(p, email); p += data->email_length + 1;
  strcpy(p, self_url);
  if ((r = userlist_clnt_send_packet(clnt,len,data)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt,&anslen,(void*) &answer)) < 0)
    return r;
  res = *answer;
  xfree(answer);
  return res;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
