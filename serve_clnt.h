/* -*- c -*- */
/* $Id$ */

#ifndef __SERVE_CLNT_H__
#define __SERVE_CLNT_H__

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

#include <string.h>

/* error codes are defined in protocol.h */

int serve_clnt_open(char const *);
int serve_clnt_do_pass_fd(int sock_fd, int fds_num, int *fds);
int serve_clnt_send_packet(int sock_fd, int size, void const *buf);
int serve_clnt_recv_packet(int sock_fd, size_t *p_size, void **p_data);

int serve_clnt_pass_fd(int sock_fd, int nfd, int *fds);

int serve_clnt_get_archive(int sock_fd,
                           int user_id,
                           int contest_id,
                           int locale_id,
                           int *p_token,
                           unsigned char **p_path);

int serve_clnt_list_runs(int sock_fd,
                         int out_fd,
                         int cmd,
                         int user_id,
                         int contest_id,
                         int locale_id,
                         unsigned int flags,
                         unsigned char const *form_start);

int serve_clnt_show_item(int sock_fd,
                         int out_fd,
                         int cmd,
                         int user_id,
                         int contest_id,
                         int locale_id,
                         int item_id);

int serve_clnt_submit_run(int sock_fd,
                          int user_id,
                          int contest_id,
                          int locale_id,
                          unsigned long ip,
                          int prob_id,
                          int lang_id,
                          unsigned char const *run_src);

int serve_clnt_submit_clar(int sock_fd,
                           int user_id,
                           int contest_id,
                           int locale_id,
                           unsigned long ip,
                           unsigned char const *subj,
                           unsigned char const *text);

int serve_clnt_team_page(int sock_fd,
                         int out_fd,
                         int user_id,
                         int contest_id,
                         int locale_id,
                         unsigned long ip,
                         unsigned int flags,
                         unsigned char const *simple_form,
                         unsigned char const *multi_form);

#endif /* __SERVE_CLNT_H__ */
