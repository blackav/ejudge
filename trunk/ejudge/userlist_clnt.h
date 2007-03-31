/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_CLNT_H__
#define __USERLIST_CLNT_H__

/* Copyright (C) 2002-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "ej_types.h"

#include <string.h>

struct userlist_clnt;
typedef struct userlist_clnt *userlist_clnt_t;

userlist_clnt_t userlist_clnt_open(char const *);
userlist_clnt_t userlist_clnt_close(userlist_clnt_t);
long userlist_clnt_get_fd(userlist_clnt_t);

int userlist_clnt_send_packet(struct userlist_clnt *clnt,
                              size_t size, void const *buf);
int userlist_clnt_recv_packet(struct userlist_clnt *clnt,
                              size_t *p_size, void **p_data);
int userlist_clnt_do_pass_fd(struct userlist_clnt *clnt,
                             int fds_num,
                             int *fds);
int userlist_clnt_read_and_notify(struct userlist_clnt *clnt,
                                  size_t *p_size, void **p_data);

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
                           unsigned char const *self_url);

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
                             unsigned char **p_passwd);

int
userlist_clnt_login(struct userlist_clnt *clnt,
                    int cmd,
                    ej_ip_t origin_ip,
                    int ssl,
                    int contest_id,
                    int locale_id,
                    unsigned char const *login,
                    unsigned char const *passwd,
                    int *p_user_id,
                    ej_cookie_t *p_cookie,
                    unsigned char **p_name);

int
userlist_clnt_team_login(struct userlist_clnt *clnt,
                         int cmd,
                         ej_ip_t origin_ip,
                         int ssl,
                         int contest_id,
                         int locale_id,
                         unsigned char const *login,
                         unsigned char const *passwd,
                         int *p_user_id,
                         ej_cookie_t *p_cookie,
                         unsigned char **p_name);

int
userlist_clnt_lookup_user(struct userlist_clnt *clnt,
                          unsigned char const *login,
                          int *p_user_id,
                          unsigned char **p_name);

int
userlist_clnt_lookup_user_id(struct userlist_clnt *clnt,
                             int user_id, int contest_id,
                             unsigned char **p_login,
                             unsigned char **p_name);

int
userlist_clnt_get_cookie(struct userlist_clnt *clnt,
                         int cmd,
                         ej_ip_t origin_ip,
                         int ssl,
                         ej_cookie_t cookie,
                         int *p_user_id,
                         int *p_contest_id,
                         int *p_locale_id,
                         int *p_priv_level,
                         int *p_role,
                         int *p_team_login,
                         int *p_reg_status,
                         int *p_reg_flags,
                         unsigned char **p_login,
                         unsigned char **p_name);

int
userlist_clnt_set_cookie(struct userlist_clnt *clnt,
                         int cmd,
                         ej_cookie_t cookie,
                         int value);

int
userlist_clnt_lookup_cookie(struct userlist_clnt *clnt,
                            ej_ip_t origin_ip,
                            int ssl,
                            ej_cookie_t cookie,
                            int *p_user_id,
                            unsigned char **p_login,
                            unsigned char **p_name,
                            int *p_locale_id,
                            int *p_contest_id);

int
userlist_clnt_team_cookie(struct userlist_clnt *clnt,
                          ej_ip_t origin_ip,
                          int ssl,
                          int contest_id,
                          ej_cookie_t cookie,
                          int locale_id,
                          int *p_user_id,
                          int *p_contest_id,
                          int *p_locale_id,
                          unsigned char **p_login,
                          unsigned char **p_name);

int
userlist_clnt_get_info(struct userlist_clnt *clnt, int cmd,
                       int uid, int contest_id, unsigned char **p_info);
int
userlist_clnt_get_database(struct userlist_clnt *clnt,
                           int cmd, int contest_id, unsigned char **p_info);
int
userlist_clnt_get_param(struct userlist_clnt *clnt,
                        int cmd, int contest_id, unsigned char **p_info);
int
userlist_clnt_set_info(struct userlist_clnt *clnt,
                       int uid, int contest_id, const unsigned char *info);
int
userlist_clnt_set_passwd(struct userlist_clnt *clnt,
                         int cmd,
                         int user_id,
                         int contest_id,
                         const unsigned char *old_pwd,
                         const unsigned char *new_pwd);
int
userlist_clnt_get_contests(struct userlist_clnt *clnt,
                           int uid, unsigned char **p_info);
int
userlist_clnt_register_contest(struct userlist_clnt *clnt,
                               int cmd,
                               int user_id,
                               int contest_id);
int
userlist_clnt_delete_info(struct userlist_clnt *clnt, int cmd,
                          int user_id, int contest_id, int serial);

int
userlist_clnt_pass_fd(struct userlist_clnt *clnt,
                      int fds_num,
                      int *fds);

int
userlist_clnt_list_users(struct userlist_clnt *clnt,
                         ej_ip_t origin_ip,
                         int ssl,
                         int contest_id,
                         int locale_id,
                         int user_id,
                         unsigned long flags,
                         const unsigned char *url,
                         const unsigned char *srch);

int
userlist_clnt_admin_process(struct userlist_clnt *clnt,
                            int *p_uid,
                            unsigned char **p_login,
                            unsigned char **p_name);

int
userlist_clnt_map_contest(struct userlist_clnt *clnt,
                          int contest_id,
                          int *p_sem_key,
                          int *p_shm_key);

int
userlist_clnt_generate_team_passwd(struct userlist_clnt *clnt,
                                   int cmd,
                                   int contest_id, int out_fd);


int
userlist_clnt_list_all_users(struct userlist_clnt *clnt,
                             int cmd,
                             int contest_id,
                             unsigned char **p_info);

int
userlist_clnt_change_registration(struct userlist_clnt *clnt,
                                  int user_id,
                                  int contest_id,
                                  int new_status,
                                  int flags_cmd,
                                  unsigned int new_flags);

int
userlist_clnt_edit_field(struct userlist_clnt *clnt,
                         int user_id,
                         int contest_id,
                         int serial,
                         int field,
                         unsigned char const *value);

int
userlist_clnt_edit_field_seq(
	struct userlist_clnt *clnt,
        int cmd,
        int user_id,
        int contest_id,
        int serial,
        int deleted_num,
        int edited_num,
        int deleted_ids[],
        int edited_ids[],
        const unsigned char **edited_strs);

int
userlist_clnt_delete_field(struct userlist_clnt *clnt,
                           int user_id,
                           int contest_id,
                           int serial,
                           int field);
int
userlist_clnt_delete_cookie(struct userlist_clnt *clnt,
                            int user_id,
                            int contest_id,
                            ej_cookie_t cookie);

int userlist_clnt_create_user(struct userlist_clnt *clnt, int *p_user_id);
int userlist_clnt_create_member(struct userlist_clnt *clnt, int user_id,
                                int contest_id, int role);
int userlist_clnt_copy_user_info(struct userlist_clnt *clnt, int user_id,
                                 int cnts_from, int cnts_to);

int userlist_clnt_get_uid_by_pid(struct userlist_clnt *clnt,
                                 int system_uid,
                                 int system_gid,
                                 int system_pid,
                                 int contest_id,
                                 int *p_uid,
                                 int *p_priv_level,
                                 ej_cookie_t *p_cookie,
                                 ej_ip_t *p_ip,
                                 int *p_ssl);

int userlist_clnt_get_uid_by_pid_2(struct userlist_clnt *clnt,
                                   int system_uid,
                                   int system_gid,
                                   int system_pid,
                                   int contest_id,
                                   int *p_uid,
                                   int *p_priv_level,
                                   ej_cookie_t *p_cookie,
                                   ej_ip_t *p_ip,
                                   int *p_ssl,
                                   unsigned char **p_login,
                                   unsigned char **p_name);

int userlist_clnt_priv_login(struct userlist_clnt *clnt,
                             int cmd,
                             ej_ip_t origin_ip,
                             int ssl,
                             int contest_id,
                             int locale_id,
                             int priv_level,
                             int role,
                             unsigned char const *login,
                             unsigned char const *passwd,
                             int *p_user_id,
                             ej_cookie_t *p_cookie,
                             int *p_priv_level,
                             unsigned char **p_name);

int userlist_clnt_priv_cookie(struct userlist_clnt *clnt,
                              ej_ip_t origin_ip,
                              int ssl,
                              int contest_id,
                              ej_cookie_t cookie,
                              int locale_id,
                              int priv_level,
                              int *p_user_id,
                              int *p_contest_id,
                              int *p_locale_id,
                              int *p_priv_level,
                              unsigned char **p_login,
                              unsigned char **p_name);

int userlist_clnt_logout(struct userlist_clnt *clnt,
                         int cmd,
                         ej_ip_t origin_ip,
                         int ssl,
                         ej_cookie_t cookie);

int userlist_clnt_dump_database(struct userlist_clnt *clnt, int cmd,
                                int contest_id, int out_fd, int html_flag);

int userlist_clnt_cnts_passwd_op(struct userlist_clnt *clnt,
                                 int cmd,
                                 int contest_id);

int userlist_clnt_notify(struct userlist_clnt *clnt, int cmd, int contest_id);
int userlist_clnt_read_notification(struct userlist_clnt *clnt, int *p_contest_id);

int userlist_clnt_bytes_available(struct userlist_clnt *clnt);
void userlist_clnt_set_notification_callback(struct userlist_clnt *clnt,
                                             void (*callback)(void *, int),
                                             void *user_data);

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
                               unsigned char **p_passwd);

int userlist_clnt_control(struct userlist_clnt *clnt, int cmd);

int userlist_clnt_priv_cookie_login(
	struct userlist_clnt *clnt,
        int cmd,
        ej_ip_t origin_ip,
        int ssl,
        int contest_id,
        ej_cookie_t cookie,
        int locale_id,
        int priv_level,
        int role,
        // output parameters
        int *p_user_id,
        ej_cookie_t *p_cookie,
        unsigned char **p_login,
        unsigned char **p_name
                                    );

#endif /* __USERLIST_CLNT_H__ */
