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
userlist_clnt_register_new_2(struct userlist_clnt *clnt,
                             ej_ip_t origin_ip,
                             int ssl,
                             int contest_id,
                             int locale_id,
                             int action,
                             unsigned char const *login,
                             unsigned char const *email,
                             const unsigned char *self_url,
                             unsigned char **p_login,
                             unsigned char **p_passwd)
{
  struct userlist_pk_register_new *data;
  struct userlist_pk_new_password *answer;
  unsigned char *p;
  void *v_ans;
  short *s_ans;
  int len, login_len, email_len, self_url_len;
  size_t anslen;
  int res;
  int r;

  if (!login) login = "";
  if (!email) email = "";
  if (!self_url) self_url = "";
  login_len = strlen(login);
  email_len = strlen(email);
  self_url_len = strlen(self_url);

  len = sizeof(struct userlist_pk_register_new)
    + login_len + email_len + self_url_len;
  data = alloca(len);
  memset(data, 0, len);
  data->request_id = ULS_REGISTER_NEW_2;
  data->origin_ip = origin_ip;
  data->ssl = ssl;
  data->contest_id = contest_id;
  data->locale_id = locale_id;
  data->action = action;
  data->login_length = login_len;
  data->email_length = email_len;
  data->self_url_length = self_url_len;
  p = data->data; strcpy(p, login);
  p += login_len + 1; strcpy(p, email);
  p += email_len + 1; strcpy(p, self_url);
  if ((r = userlist_clnt_send_packet(clnt,len,data)) < 0) return r;
  if ((r = userlist_clnt_read_and_notify(clnt,&anslen,(void*) &v_ans)) < 0)
    return r;
  if (anslen < sizeof(short)) goto protocol_error;
  s_ans = (short*) v_ans;
  if (*s_ans < 0) {
    res = *s_ans;
    xfree(v_ans);
    return res;
  }
  if (*s_ans != ULS_PASSWORD) goto protocol_error;
  answer = (struct userlist_pk_new_password*) v_ans;
  if (anslen < sizeof(*answer)) goto protocol_error;
  if (sizeof(*answer) + answer->login_len + answer->passwd_len != anslen)
    goto protocol_error;
  if (strlen(answer->data) != answer->login_len) goto protocol_error;
  if (strlen(answer->data + answer->login_len + 2) != answer->passwd_len)
    goto protocol_error;

  if (p_login) *p_login = xstrdup(answer->data);
  if (p_passwd) *p_passwd = xstrdup(answer->data + answer->login_len + 2);
  xfree(answer);
  return ULS_PASSWORD;

 protocol_error:
  xfree(v_ans);
  return -ULS_ERR_PROTOCOL;
}

/*
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
