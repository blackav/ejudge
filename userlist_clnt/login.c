/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ispras.ru> */

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
userlist_clnt_login(struct userlist_clnt *clnt,
                    ej_ip_t origin_ip,
                    int ssl,
                    int contest_id,
                    int locale_id,
                    unsigned char const *login,
                    unsigned char const *passwd,
                    int *p_user_id,
                    ej_cookie_t *p_cookie,
                    unsigned char **p_name,
                    int *p_locale_id)
{
  struct userlist_pk_do_login * data;
  struct userlist_pk_login_ok * answer;
  void *void_answer = 0;
  int len;
  size_t anslen;
  int res;
  int r;

  len = sizeof(struct userlist_pk_do_login) + strlen(login) + strlen(passwd);
  data = alloca(len);
  memset(data, 0, len);
  data->request_id = ULS_DO_LOGIN;
  data->origin_ip = origin_ip;
  data->ssl = ssl;
  data->contest_id = contest_id;
  data->locale_id = locale_id;
  data->login_length = strlen(login);
  data->password_length = strlen(passwd);
  strcpy(data->data,login);
  strcpy(data->data + data->login_length + 1,passwd);
  if ((r = userlist_clnt_send_packet(clnt,len,data)) < 0) return r;
  if ((r = userlist_clnt_recv_packet(clnt,&anslen, &void_answer)) < 0)
    return r;
  answer = void_answer;
  if ((answer->reply_id == ULS_LOGIN_OK)||
      (answer->reply_id == ULS_LOGIN_COOKIE)) {

    *p_user_id = answer->user_id;
    *p_cookie = answer->cookie;
    *p_locale_id = answer->locale_id;
    *p_name = xcalloc(1,answer->name_len + 1);
    strcpy(*p_name,answer->data + answer->login_len);
  }
  res = answer->reply_id;
  xfree(answer);
  return res;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
