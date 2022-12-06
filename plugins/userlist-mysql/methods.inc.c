/* -*- mode: c -*- */

/* Copyright (C) 2008-2022 Alexander Chernov <cher@ejudge.ru> */

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

static struct common_plugin_data *
init_func(void);
static int
finish_func(struct common_plugin_data *);
static int
prepare_func(
        struct common_plugin_data *,
        const struct ejudge_cfg *,
        struct xml_tree *);
static int
open_func(void *data);
static int
close_func(void *data);
static int
check_func(void *data);
static int
create_func(void *data);
static int
insert_func(
        void *data,
        const struct userlist_user *user,
        int *p_member_serial);
static int_iterator_t
get_user_id_iterator_func(void *data);
static int
get_user_by_login_func(
        void *data,
        const unsigned char *login);
static void
sync_func(void *);
static void
forced_sync_func(void *);
static unsigned char *
get_login_func(
        void *data,
        int user_id);
static int
new_user_func(
        void *data,
        const unsigned char *login,
        const unsigned char *email,
        int passwd_method,
        const unsigned char *passwd,
        int is_privileged,
        int is_invisible,
        int is_banned,
        int is_locked,
        int show_login,
        int show_email,
        int read_only,
        int never_clean,
        int simple_registration);
static int
remove_user_func(
        void *data,
        int user_id);
static int
get_cookie_func(
        void *data,
        ej_cookie_t value,
        ej_cookie_t client_key,
        const struct userlist_cookie **p_cookie);
static int
new_cookie_func(
        void *,
        int user_id,
        const ej_ip_t *pip,
        int ssl_flag,
        ej_cookie_t cookie,
        time_t,
        int contest_id,
        int locale_id,
        int priv_level,
        int role,
        int recovery,
        int team_login,
        const struct userlist_cookie **);
static int
remove_cookie_func(
        void *data,
        const struct userlist_cookie *c);
static int
remove_user_cookies_func(
        void *data,
        int user_id);
static int
remove_expired_cookies_func(
        void *data,
        time_t cur_time);
static ptr_iterator_t
get_user_contest_iterator_func(
        void *data,
        int user_id);
static int
remove_expired_users_func(
        void *data,
        time_t min_reg_time);
static int
get_user_info_1_func(
        void *data,
        int user_id,
        const struct userlist_user **p_user);
static int
get_user_info_2_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_u,
        const struct userlist_user_info **p_ui);
static int
touch_login_time_func(
        void *data,
        int user_id,
        int contest_id,
        time_t cur_time);
static int
get_user_info_3_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user,
        const struct userlist_user_info **p_info,
        const struct userlist_contest **p_contest);
static int
set_cookie_contest_func(
        void *data,
        const struct userlist_cookie *c,
        int contest_id);
static int
set_cookie_locale_func(
        void *data,
        const struct userlist_cookie *c,
        int locale_id);
static int
set_cookie_priv_level_func(
        void *data,
        const struct userlist_cookie *c,
        int priv_level);
static int
get_user_info_4_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user);
static int
get_user_info_5_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user);
static ptr_iterator_t
get_brief_list_iterator_func(
        void *data,
        int contest_id);
static ptr_iterator_t
get_standings_list_iterator_func(
        void *data,
        int contest_id);
static int
check_user_func(
        void *data,
        int user_id);
static int
set_reg_passwd_func(
        void *data,
        int user_id,
        int method,
        const unsigned char *password,
        time_t cur_time);
static int
set_team_passwd_func(
        void *data,
        int user_id,
        int contest_id,
        int method,
        const unsigned char *password,
        time_t cur_time,
        int *p_cloned_flag);
static int
register_contest_func(
        void *data,
        int user_id,
        int contest_id,
        int status,
        int flags,
        time_t cur_time,
        const struct userlist_contest **p_c);
static int
remove_member_func(
        void *data,
        int user_id,
        int contest_id,
        int serial,
        time_t cur_time,
        int *p_cloned_flag);
static int
is_read_only_func(
        void *data,
        int user_id,
        int contest_id);
static ptr_iterator_t
get_info_list_iterator_func(
        void *data,
        int contest_id,
        unsigned flag_mask);
static int
clear_team_passwd_func(
        void *data,
        int user_id,
        int contest_id,
        int *p_cloned_flag);
static int
remove_registration_func(
        void *data,
        int user_id,
        int contest_id);
static int
set_reg_status_func(
        void *data,
        int user_id,
        int contest_id,
        int status);
static int
set_reg_flags_func(
        void *data,
        int user_id,
        int contest_id,
        int cmd,
        unsigned int value);
static int
remove_user_contest_info_func(
        void *data,
        int user_id,
        int contest_id);
static int
clear_user_field_func(
        void *data,
        int user_id,
        int field_id,
        time_t cur_time);
static int
clear_user_field_func(
        void *data,
        int user_id,
        int field_id,
        time_t cur_time);
static int
clear_user_info_field_func(
        void *data,
        int user_id,
        int contest_id,
        int field_id,
        time_t cur_time,
        int *p_cloned_flag);
static int
clear_user_member_field_func(
        void *data,
        int user_id,
        int contest_id,
        int serial,
        int field_id,
        time_t cur_time,
        int *p_cloned_flag);
static int
set_user_field_func(
        void *data,
        int user_id,
        int field_id,
        const unsigned char *value,
        time_t cur_time);
static int
set_user_info_field_func(
        void *data,
        int user_id,
        int contest_id,
        int field_id,
        const unsigned char *value,
        time_t cur_time,
        int *p_cloned_flag);
static int
set_user_member_field_func(
        void *data,
        int user_id,
        int contest_id,
        int serial,
        int field_id,
        const unsigned char *value,
        time_t cur_time,
        int *p_cloned_flag);
static int
new_member_func(
        void *data,
        int user_id,
        int contest_id,
        int role,
        time_t cur_time,
        int *p_cloned_flag);
static int
maintenance_func(
        void *data,
        time_t cur_time);
static int
set_user_xml_func(
        void *data,
        int user_id,
        int contest_id,
        struct userlist_user *new_u,
        time_t cur_time,
        int *p_cloned_flag);
static int
copy_user_info_func(
        void *data,
        int user_id,
        int from_cnts,
        int to_cnts,
        int copy_passwd_flag,
        time_t cur_time,
        const struct contest_desc *cnts);
static int
check_user_reg_data_func(
        void *data,
        int user_id,
        int contest_id);
static int
move_member_func(
        void *data,
        int user_id,
        int contest_id,
        int serial,
        int new_role,
        time_t cur_time,
        int *p_cloned_flag);
static int
set_cookie_team_login_func(
        void *data,
        const struct userlist_cookie *c,
        int team_login);
static int
get_user_info_6_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user,
        const struct userlist_user_info **p_info,
        const struct userlist_contest **p_contest,
        const struct userlist_members **p_members);
static int
get_user_info_7_func(
        void *data,
        int user_id,
        int contest_id,
        const struct userlist_user **p_user,
        const struct userlist_user_info **p_info,
        const struct userlist_members **p_members);
static int
get_member_serial_func(void *data);
static int
set_member_serial_func(void *data, int new_serial);
static void
unlock_user_func(
        void *data,
        const struct userlist_user *c_u)
  __attribute__((unused));
static const struct userlist_contest *
get_contest_reg_func(
        void *data,
        int user_id,
        int contest_id);
static void drop_cache_func(void *data);
static void disable_cache_func(void *data);
static void enable_cache_func(void *data);
static int
try_new_login_func(
        void *data,
        unsigned char *buf,
        size_t bufsize,
        const char *format,
        int serial,
        int serial_step);
static int
set_simple_reg_func(
        void *data,
        int user_id,
        int value,
        time_t cur_time);
static ptr_iterator_t
get_group_iterator_func(void *data);
static const struct userlist_group*
get_group_by_name_func(
        void *data,
        const unsigned char *group_name);
static int
try_new_group_name_func(
        void *data,
        unsigned char *buf,
        size_t bufsize,
        const char *format,
        int serial,
        int step);
static int
create_group_func(
        void *data,
        const unsigned char *group_name,
        int created_by);
static int
remove_group_func(
        void *data,
        int group_id);
static int
edit_group_field_func(
        void *data,
        int group_id,
        int field,
        const unsigned char *value);
static int
clear_group_field_func(
        void *data,
        int group_id,
        int field);
static const struct userlist_group*
get_group_func(
        void *data,
        int group_id);
static ptr_iterator_t
get_group_user_iterator_func(void *data, int group_id);
static ptr_iterator_t
get_group_member_iterator_func(void *data, int group_id);
static int
create_group_member_func(void *data, int group_id, int user_id);
static int
remove_group_member_func(void *data, int group_id, int user_id);
static ptr_iterator_t
get_brief_list_iterator_2_func(
        void *data,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int offset,
        int count,
        int page,
        int sort_field,
        int sort_order,
        int filter_field,
        int filter_op);
static int
get_user_count_func(
        void *data,
        int contest_id,
        int group_id,
        const unsigned char *filter,
        int filter_field,
        int filter_op,
        int new_mode,
        long long *p_count);
static ptr_iterator_t
get_group_iterator_2_func(
        void *data,
        const unsigned char *filter,
        int offset,
        int count);
static int
get_group_count_func(
        void *data,
        const unsigned char *filter,
        long long *p_count);
static int
get_prev_user_id_func(
        void *data,
        int contest_id,
        int group_id,
        int user_id,
        const unsigned char *filter,
        int *p_user_id);
static int
get_next_user_id_func(
        void *data,
        int contest_id,
        int group_id,
        int user_id,
        const unsigned char *filter,
        int *p_user_id);
static int
new_cookie_2_func(
        void *,
        int user_id,
        const ej_ip_t *pip,
        int ssl_flag,
        ej_cookie_t cookie,
        ej_cookie_t client_key,
        time_t,
        int contest_id,
        int locale_id,
        int priv_level,
        int role,
        int recovery,
        int team_login,
        int is_ws,
        int is_job,
        const struct userlist_cookie **);
static int
get_client_key_func(
        void *data,
        ej_cookie_t client_key,
        const struct userlist_cookie **p_cookie);
static int
new_api_key_func(
        void *data,
        struct userlist_api_key *in_api_key,
        const struct userlist_api_key **p_api_key);
static int
get_api_key_func(
        void *,
        const char *token,
        const struct userlist_api_key **);
static int
get_api_key_secret_func(
        void *,
        const char *secret,
        const struct userlist_api_key **);
static int
get_api_keys_count_func(
        void *,
        int user_id);
static int
get_api_keys_for_user_func(
        void *,
        int user_id,
        const struct userlist_api_key ***);
static int
remove_api_key_func(
        void *,
        int user_id,
        const char *token);
