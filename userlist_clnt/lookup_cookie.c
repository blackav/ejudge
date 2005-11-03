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
userlist_clnt_lookup_cookie(struct userlist_clnt *clnt,
                            ej_ip_t origin_ip,
                            int ssl,
                            ej_cookie_t cookie,
                            int *p_user_id,
                            unsigned char **p_login,
                            unsigned char **p_name,
                            int *p_locale_id,
                            int *p_contest_id)
{
  struct userlist_pk_check_cookie * data;
  struct userlist_pk_login_ok * answer = 0;
  void *void_answer = 0;
  int len;
  size_t anslen;
  int res;
  int r;

  len = sizeof (struct userlist_pk_check_cookie);
  data = alloca(len);
  memset(data, 0, len);
  data->request_id = ULS_CHECK_COOKIE;
  data->origin_ip = origin_ip;
  data->ssl = ssl;
  //  data->contest_id = contest_id;
  data->cookie = cookie;
  data->locale_id = -1;
  if ((r = userlist_clnt_send_packet(clnt,len,data)) < 0) return r;
  if ((r = userlist_clnt_recv_packet(clnt,&anslen,&void_answer)) < 0)
    return r;
  answer = void_answer;
  if (answer->reply_id == ULS_LOGIN_COOKIE) {
    *p_user_id = answer->user_id;
    *p_locale_id = answer->locale_id;
    *p_login = xstrdup(answer->data);
    *p_name = xcalloc(1,answer->name_len + 1);
    *p_contest_id = answer->contest_id;
    strcpy(*p_name,answer->data + answer->login_len + 1);
  }
  res = answer->reply_id;
  xfree(answer);
  return res;
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
