/* -*- c -*- */
/* $Id$ */

#ifndef __USERLIST_CLNT_H__
#define __USERLIST_CLNT_H__

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

struct userlist_clnt;
typedef struct userlist_clnt *userlist_clnt_t;

userlist_clnt_t userlist_clnt_open(char const *);
userlist_clnt_t userlist_clnt_close(userlist_clnt_t);

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
userlist_clnt_lookup_cookie(struct userlist_clnt *clnt,
                            unsigned long origin_ip,
                            unsigned long long cookie,
                            int *p_user_id,
                            unsigned char **p_login,
                            unsigned char **p_name,
                            int *p_locale_id,
                            int *p_contest_id);

int
userlist_clnt_get_info(struct userlist_clnt *clnt,
                       int uid, unsigned char **p_info);
int
userlist_clnt_set_info(struct userlist_clnt *clnt,
                       int uid, unsigned char *info);
int
userlist_clnt_set_passwd(struct userlist_clnt *clnt,
                         int uid, unsigned char *old_pwd,
                         unsigned char *new_pwd);
int
userlist_clnt_get_contests(struct userlist_clnt *clnt,
                           int uid, unsigned char **p_info);
int
userlist_clnt_register_contest(struct userlist_clnt *clnt,
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
userlist_list_users(struct userlist_clnt *clnt,
                    unsigned long origin_ip, int contest_id,
                    int locale_id);

#endif /* __USERLIST_CLNT_H__ */
