/* -*- mode: c -*- */

/* Copyright (C) 2011-2023 Alexander Chernov <cher@ejudge.ru> */

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

enum { MAX_LEN = 65535, MAX_SIZE = 1024*1024 };

int
userlist_clnt_create_user_2(
        struct userlist_clnt *clnt,
        int cmd,
        const struct userlist_pk_create_user_2 *params,
        const unsigned char *login_str,
        const unsigned char *email_str,
        const unsigned char *reg_password_str,
        const unsigned char *cnts_password_str,
        const unsigned char *cnts_name_str,
        int *p_user_id)
{
  if (!params) return -ULS_ERR_PROTOCOL;
  if (!login_str) login_str = "";
  if (!email_str) email_str = "";
  if (!reg_password_str) reg_password_str = "";
  if (!cnts_password_str) cnts_password_str = "";
  if (!cnts_name_str) cnts_name_str = "";

  size_t login_len = strlen(login_str);
  if (login_len > MAX_LEN) return -ULS_ERR_PROTOCOL;
  size_t email_len = strlen(email_str);
  if (email_len > MAX_LEN) return -ULS_ERR_PROTOCOL;
  size_t reg_password_len = strlen(reg_password_str);
  if (reg_password_len > MAX_LEN) return -ULS_ERR_PROTOCOL;
  size_t cnts_password_len = strlen(cnts_password_str);
  if (cnts_password_len > MAX_LEN) return -ULS_ERR_PROTOCOL;
  size_t cnts_name_len = strlen(cnts_name_str);
  if (cnts_name_len > MAX_LEN) return -ULS_ERR_PROTOCOL;

  size_t out_size = sizeof(struct userlist_pk_create_user_2) + login_len + email_len + reg_password_len + cnts_password_len + cnts_name_len;
  if (out_size > MAX_SIZE) return -ULS_ERR_PROTOCOL;

  struct userlist_pk_create_user_2 *out = (struct userlist_pk_create_user_2*) xcalloc(out_size, 1);
  unsigned char *login_ptr = out->data;
  unsigned char *email_ptr = login_ptr + login_len + 1;
  unsigned char *reg_password_ptr = email_ptr + email_len + 1;
  unsigned char *cnts_password_ptr = reg_password_ptr + reg_password_len + 1;
  unsigned char *cnts_name_ptr = cnts_password_ptr + cnts_password_len + 1;

  out->request_id = cmd;
  out->login_len = login_len;
  out->email_len = email_len;
  out->send_email_flag = params->send_email_flag;
  out->confirm_email_flag = params->confirm_email_flag;
  out->random_password_flag = params->random_password_flag;
  out->reg_password_len = reg_password_len;
  out->use_sha1_flag = params->use_sha1_flag;
  out->is_privileged_flag = params->is_privileged_flag;
  out->is_invisible_flag = params->is_invisible_flag;
  out->is_banned_flag = params->is_banned_flag;
  out->is_locked_flag = params->is_locked_flag;
  out->show_login_flag = params->show_login_flag;
  out->show_email_flag = params->show_email_flag;
  out->read_only_flag = params->read_only_flag;
  out->never_clean_flag = params->never_clean_flag;
  out->simple_registration_flag = params->simple_registration_flag;
  out->contest_id = params->contest_id;
  out->cnts_status = params->cnts_status;
  out->cnts_is_invisible_flag = params->cnts_is_invisible_flag;
  out->cnts_is_banned_flag = params->cnts_is_banned_flag;
  out->cnts_is_locked_flag = params->cnts_is_locked_flag;
  out->cnts_is_incomplete_flag = params->cnts_is_incomplete_flag;
  out->cnts_is_disqualified_flag = params->cnts_is_disqualified_flag;
  out->cnts_is_privileged_flag = params->cnts_is_privileged_flag;
  out->cnts_is_reg_readonly_flag = params->cnts_is_reg_readonly_flag;
  out->cnts_use_reg_passwd_flag = params->cnts_use_reg_passwd_flag;
  out->cnts_set_null_passwd_flag = params->cnts_set_null_passwd_flag;
  out->cnts_random_password_flag = params->cnts_random_password_flag;
  out->cnts_password_len = cnts_password_len;
  out->cnts_use_sha1_flag = params->cnts_use_sha1_flag;
  out->cnts_name_len = cnts_name_len;
  out->group_id = params->group_id;
  out->register_existing_flag = params->register_existing_flag;
  out->reset_existing_passwords_flag = params->reset_existing_passwords_flag;

  memcpy(login_ptr, login_str, login_len + 1);
  memcpy(email_ptr, email_str, email_len + 1);
  memcpy(reg_password_ptr, reg_password_str, reg_password_len + 1);
  memcpy(cnts_password_ptr, cnts_password_str, cnts_password_len + 1);
  memcpy(cnts_name_ptr, cnts_name_str, cnts_name_len + 1);

  int r = 0;
  if ((r = userlist_clnt_send_packet(clnt, out_size, out)) < 0) {
    free(out);
    return r;
  }

  free(out);
  size_t in_size = 0;
  void *void_in = 0;
  if ((r = userlist_clnt_read_and_notify(clnt, &in_size, &void_in)) < 0)
    return r;
  struct userlist_packet *in = (struct userlist_packet *) void_in;
  struct userlist_pk_login_ok *uin = 0;
  if (in_size < sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  if (in->id == ULS_LOGIN_OK) {
    uin = (struct userlist_pk_login_ok*) in;
    if (in_size != sizeof(*uin)) {
      xfree(in);
      return -ULS_ERR_PROTOCOL;
    }
    if (p_user_id) *p_user_id = uin->user_id;
    xfree(in);
    return ULS_LOGIN_OK;
  }

  if (in_size != sizeof(*in)) {
    xfree(in);
    return -ULS_ERR_PROTOCOL;
  }
  r = in->id;
  xfree(in);
  return r;
}
