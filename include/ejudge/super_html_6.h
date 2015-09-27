/* -*- c -*- */

#ifndef __SUPER_HTML_6_H__
#define __SUPER_HTML_6_H__

/* Copyright (C) 2011-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"

struct ss_op_param_USER_CREATE_ONE_ACTION
{
  ej_int_opt_0_t   contest_id;
  ej_int_opt_0_t   group_id;
  ej_textbox_t     other_login;
  ej_textbox_opt_t other_email;
  ej_checkbox_t    send_email;
  ej_checkbox_t    confirm_email;
  ej_textbox_t     reg_password1;
  ej_textbox_t     reg_password2;
  ej_checkbox_t    reg_sha1;
  ej_checkbox_t    field_1;          // USERLIST_NN_IS_PRIVILEGED,
  ej_checkbox_t    field_2;          // USERLIST_NN_IS_INVISIBLE,
  ej_checkbox_t    field_3;          // USERLIST_NN_IS_BANNED,
  ej_checkbox_t    field_4;          // USERLIST_NN_IS_LOCKED,
  ej_checkbox_t    field_5;          // USERLIST_NN_SHOW_LOGIN,
  ej_checkbox_t    field_6;          // USERLIST_NN_SHOW_EMAIL,
  ej_checkbox_t    field_7;          // USERLIST_NN_READ_ONLY,
  ej_checkbox_t    field_8;          // USERLIST_NN_NEVER_CLEAN,
  ej_checkbox_t    field_9;          // USERLIST_NN_SIMPLE_REGISTRATION,
  ej_checkbox_t    reg_cnts_create;
  ej_int_opt_0_t   other_contest_id_1;
  ej_int_opt_1_t   cnts_status;
  ej_checkbox_t    is_invisible;
  ej_checkbox_t    is_banned;
  ej_checkbox_t    is_locked;
  ej_checkbox_t    is_incomplete;
  ej_checkbox_t    is_disqualified;
  ej_checkbox_t    cnts_use_reg_passwd;
  ej_checkbox_t    cnts_null_passwd;
  ej_textbox_opt_t cnts_password1;
  ej_textbox_opt_t cnts_password2;
  ej_checkbox_t    cnts_sha1;
  ej_textbox_opt_t cnts_name;
  ej_checkbox_t    group_create;
  ej_int_opt_0_t   other_group_id;
};

struct ss_op_param_USER_CREATE_MANY_ACTION
{
  ej_int_opt_0_t   contest_id;
  ej_int_opt_0_t   group_id;
  ej_int_opt_m1_t  first_serial;
  ej_int_opt_m1_t  last_serial;
  ej_textbox_t     login_template;
  ej_checkbox_t    reg_random;
  ej_textbox_opt_t reg_password_template;
  ej_checkbox_t    reg_sha1;
  ej_checkbox_t    field_1;          // USERLIST_NN_IS_PRIVILEGED,
  ej_checkbox_t    field_2;          // USERLIST_NN_IS_INVISIBLE,
  ej_checkbox_t    field_3;          // USERLIST_NN_IS_BANNED,
  ej_checkbox_t    field_4;          // USERLIST_NN_IS_LOCKED,
  ej_checkbox_t    field_5;          // USERLIST_NN_SHOW_LOGIN,
  ej_checkbox_t    field_6;          // USERLIST_NN_SHOW_EMAIL,
  ej_checkbox_t    field_7;          // USERLIST_NN_READ_ONLY,
  ej_checkbox_t    field_8;          // USERLIST_NN_NEVER_CLEAN,
  ej_checkbox_t    field_9;          // USERLIST_NN_SIMPLE_REGISTRATION,
  ej_checkbox_t    reg_cnts_create;
  ej_int_opt_0_t   other_contest_id_1;
  ej_int_opt_1_t   cnts_status;
  ej_checkbox_t    is_invisible;
  ej_checkbox_t    is_banned;
  ej_checkbox_t    is_locked;
  ej_checkbox_t    is_incomplete;
  ej_checkbox_t    is_disqualified;
  ej_checkbox_t    cnts_use_reg_passwd;
  ej_checkbox_t    cnts_null_passwd;
  ej_checkbox_t    cnts_random_passwd;
  ej_textbox_opt_t cnts_password_template;
  ej_checkbox_t    cnts_sha1;
  ej_textbox_opt_t cnts_name_template;
  ej_checkbox_t    group_create;
  ej_int_opt_0_t   other_group_id;
};

struct ss_op_param_USER_CREATE_FROM_CSV_ACTION
{
  ej_int_opt_0_t   contest_id;
  ej_int_opt_0_t   group_id;
  ej_checkbox_t    send_email;
  ej_checkbox_t    confirm_email;
  ej_checkbox_t    reg_random;
  ej_checkbox_t    reg_sha1;
  ej_checkbox_t    field_1;          // USERLIST_NN_IS_PRIVILEGED,
  ej_checkbox_t    field_2;          // USERLIST_NN_IS_INVISIBLE,
  ej_checkbox_t    field_3;          // USERLIST_NN_IS_BANNED,
  ej_checkbox_t    field_4;          // USERLIST_NN_IS_LOCKED,
  ej_checkbox_t    field_5;          // USERLIST_NN_SHOW_LOGIN,
  ej_checkbox_t    field_6;          // USERLIST_NN_SHOW_EMAIL,
  ej_checkbox_t    field_7;          // USERLIST_NN_READ_ONLY,
  ej_checkbox_t    field_8;          // USERLIST_NN_NEVER_CLEAN,
  ej_checkbox_t    field_9;          // USERLIST_NN_SIMPLE_REGISTRATION,
  ej_checkbox_t    reg_cnts_create;
  ej_int_opt_0_t   other_contest_id_1;
  ej_int_opt_1_t   cnts_status;
  ej_checkbox_t    is_invisible;
  ej_checkbox_t    is_banned;
  ej_checkbox_t    is_locked;
  ej_checkbox_t    is_incomplete;
  ej_checkbox_t    is_disqualified;
  ej_checkbox_t    cnts_use_reg_passwd;
  ej_checkbox_t    cnts_null_passwd;
  ej_checkbox_t    cnts_random_passwd;
  ej_checkbox_t    cnts_sha1;
  ej_textbox_opt_t cnts_name_template;
  ej_checkbox_t    group_create;
  ej_int_opt_0_t   other_group_id;
  ej_textbox_opt_t separator;
  ej_textbox_opt_t charset;
  ej_checkbox_t    register_existing;
};

struct ss_op_param_USER_CREATE_REG_ACTION
{
  ej_int_opt_0_t   other_user_id;
  ej_int_opt_0_t   contest_id;
  ej_int_opt_0_t   group_id;
  ej_int_opt_0_t   other_contest_id_1;
  ej_int_opt_1_t   status;
  ej_checkbox_t    is_invisible;
  ej_checkbox_t    is_banned;
  ej_checkbox_t    is_locked;
  ej_checkbox_t    is_incomplete;
  ej_checkbox_t    is_disqualified;
};

struct ss_op_param_USER_EDIT_REG_ACTION
{
  ej_int_opt_0_t   other_user_id;
  ej_int_opt_0_t   other_contest_id;
  ej_int_opt_0_t   contest_id;
  ej_int_opt_0_t   group_id;
  ej_int_opt_0_t   next_op;
  ej_int_opt_1_t   status;
  ej_checkbox_t    is_invisible;
  ej_checkbox_t    is_banned;
  ej_checkbox_t    is_locked;
  ej_checkbox_t    is_incomplete;
  ej_checkbox_t    is_disqualified;
};

#endif /* __SUPER_HTML_6_H__ */
