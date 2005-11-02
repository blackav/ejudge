/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_CLNT_H__
#define __USERLIST_CLNT_H__

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

#include <string.h>

struct userlist_clnt;
typedef struct userlist_clnt *userlist_clnt_t;

userlist_clnt_t userlist_clnt_open(char const *);
userlist_clnt_t userlist_clnt_close(userlist_clnt_t);

int userlist_clnt_send_packet(struct userlist_clnt *clnt,
                              size_t size, void const *buf);
int userlist_clnt_recv_packet(struct userlist_clnt *clnt,
                              size_t *p_size, void **p_data);
int userlist_clnt_do_pass_fd(struct userlist_clnt *clnt,
                             int fds_num,
                             int *fds);

int
userlist_clnt_register_new(struct userlist_clnt *clnt,
                           unsigned long origin_ip,
                           int contest_id,
                           int locale_id,
                           int use_cookies,
                           unsigned char const *login,
                           unsigned char const *email);

int
userlist_clnt_login(struct userlist_clnt *clnt,
                    unsigned long origin_ip,
                    int ssl,
                    int contest_id,
                    int locale_id,
                    int use_cookies,
                    unsigned char const *login,
                    unsigned char const *passwd,
                    int *p_user_id,
                    unsigned long long *p_cookie,
                    unsigned char **p_name,
                    int *p_locale_id);

int
userlist_clnt_team_login(struct userlist_clnt *clnt,
                         unsigned long origin_ip,
                         int ssl,
                         int contest_id,
                         int locale_id,
                         int use_cookies,
                         unsigned char const *login,
                         unsigned char const *passwd,
                         int *p_user_id,
                         unsigned long long *p_cookie,
                         int *p_locale_id,
                         unsigned char **p_name);

int
userlist_clnt_lookup_cookie(struct userlist_clnt *clnt,
                            unsigned long origin_ip,
                            int ssl,
                            unsigned long long cookie,
                            int *p_user_id,
                            unsigned char **p_login,
                            unsigned char **p_name,
                            int *p_locale_id,
                            int *p_contest_id);

int
userlist_clnt_team_cookie(struct userlist_clnt *clnt,
                          unsigned long origin_ip,
                          int ssl,
                          int contest_id,
                          unsigned long long cookie,
                          int locale_id,
                          int *p_user_id,
                          int *p_contest_id,
                          int *p_locale_id,
                          unsigned char **p_login,
                          unsigned char **p_name);

int
userlist_clnt_get_info(struct userlist_clnt *clnt, int cmd,
                       int uid, unsigned char **p_info);
int
userlist_clnt_get_param(struct userlist_clnt *clnt,
                        int cmd, int contest_id, unsigned char **p_info);
int
userlist_clnt_set_info(struct userlist_clnt *clnt,
                       int uid, int contest_id, const unsigned char *info);
int
userlist_clnt_set_passwd(struct userlist_clnt *clnt,
                         int uid,
                         const unsigned char *old_pwd,
                         const unsigned char *new_pwd);
int
userlist_clnt_team_set_passwd(struct userlist_clnt *clnt,
                              int uid, int contest_id,
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
userlist_clnt_remove_member(struct userlist_clnt *clnt,
		            int user_id, int role_id, int pers_id,
			    int serial);

int
userlist_clnt_pass_fd(struct userlist_clnt *clnt,
                      int fds_num,
                      int *fds);

int
userlist_clnt_list_users(struct userlist_clnt *clnt,
                         unsigned long origin_ip, int contest_id,
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
                         int role,
                         int pers,
                         int field,
                         unsigned char const *value);

int
userlist_clnt_delete_field(struct userlist_clnt *clnt,
                           int user_id,
                           int role,
                           int pers,
                           int field);

int
userlist_clnt_add_field(struct userlist_clnt *clnt,
                        int *p_user_id,
                        int role,
                        int pers,
                        int field);

int userlist_clnt_get_uid_by_pid(struct userlist_clnt *clnt,
                                 int system_uid,
                                 int system_gid,
                                 int system_pid,
                                 int *p_uid,
                                 int *p_priv_level,
                                 unsigned long long *p_cookie,
                                 unsigned long *p_ip,
                                 int *p_ssl);

int userlist_clnt_get_uid_by_pid_2(struct userlist_clnt *clnt,
                                   int system_uid,
                                   int system_gid,
                                   int system_pid,
                                   int *p_uid,
                                   int *p_priv_level,
                                   unsigned long long *p_cookie,
                                   unsigned long *p_ip,
                                   int *p_ssl,
                                   unsigned char **p_login,
                                   unsigned char **p_name);

int userlist_clnt_priv_login(struct userlist_clnt *clnt,
                             unsigned long origin_ip,
                             int ssl,
                             int contest_id,
                             int locale_id,
                             int use_cookies,
                             int priv_level,
                             unsigned char const *login,
                             unsigned char const *passwd,
                             int *p_user_id,
                             unsigned long long *p_cookie,
                             int *p_locale_id,
                             int *p_priv_level,
                             unsigned char **p_name);

int userlist_clnt_priv_cookie(struct userlist_clnt *clnt,
                              unsigned long origin_ip,
                              int ssl,
                              int contest_id,
                              unsigned long long cookie,
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
                         unsigned long origin_ip,
                         unsigned long long cookie);

int userlist_clnt_dump_database(struct userlist_clnt *clnt, int cmd,
                                int contest_id, int out_fd, int html_flag);

int userlist_clnt_clear_team_passwords(struct userlist_clnt *clnt,
                                       int contest_id);

#endif /* __USERLIST_CLNT_H__ */
