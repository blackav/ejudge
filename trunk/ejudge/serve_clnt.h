/* -*- c -*- */
/* $Id$ */

#ifndef __SERVE_CLNT_H__
#define __SERVE_CLNT_H__

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

/* error codes are defined in protocol.h */

int serve_clnt_open(char const *);
int serve_clnt_do_pass_fd(int sock_fd, int fds_num, int *fds);
int serve_clnt_send_packet(int sock_fd, size_t size, void const *buf);
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
                          int cmd,
                          int user_id,
                          int contest_id,
                          int locale_id,
                          unsigned long ip,
                          int prob_id,
                          int lang_id,
                          int variant,
                          size_t run_size,
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
                         int locale_id,
                         unsigned int flags,
                         unsigned char const *self_url,
                         unsigned char const *hidden_vars,
                         unsigned char const *extra_args);

int serve_clnt_master_page(int sock_fd,
                           int out_fd,
                           int cmd,
                           unsigned long long session_id,
                           int user_id,
                           int contest_id,
                           int locale_id,
                           unsigned long ip,
                           int priv_level,
                           int first_run,
                           int last_run,
                           int mode_clar,
                           int first_clar,
                           int last_clar,
                           unsigned char const *self_url,
                           unsigned char const *filter_expr,
                           unsigned char const *hidden_vars,
                           unsigned char const *extra_args);

int serve_clnt_standings(int sock_fd,
                         int out_fd,
                         int user_id,
                         int contest_id,
                         int locale_id,
                         int priv_level,
                         unsigned char const *self_url,
                         unsigned char const *hidden_vars,
                         unsigned char const *extra_args);

int serve_clnt_view(int sock_fd,
                    int out_fd,
                    int cmd,
                    int item,
                    int item2,
                    unsigned int flags,
                    unsigned char const *self_url,
                    unsigned char const *hidden_vars,
                    unsigned char const *extra_args);

int serve_clnt_message(int sock_fd,
                       int cmd,
                       int dest_user_id,
                       int ref_clar_id,
                       unsigned char const *dest_login,
                       unsigned char const *subj,
                       unsigned char const *text);

int serve_clnt_userlist_cmd(int sock_fd, int cmd, int out_fd);

int serve_clnt_simple_cmd(int sock_fd,
                          int cmd,
                          void const *val,
                          size_t val_len);

int serve_clnt_edit_run(int sock_fd,
                        int run_id,
                        int mask,
                        int user_id,
                        int prob_id,
                        int lang_id,
                        int status,
                        int is_imported,
                        int variant,
                        int is_hidden,
                        int tests,
                        int score,
                        int is_readonly,
                        int pages,
                        unsigned char const *user_login,
                        int score_adj);

int serve_clnt_new_run(int sock_fd, int mask,
                       int user_id, int prob_id, int lang_id, int status,
                       int is_imported, int variant, int is_hidden,
                       int tests, int score, int is_readonly, int pages,
                       unsigned long ip, int run_size,
                       unsigned char const *user_login,
                       unsigned char const *run_src);

int serve_clnt_edit_user(int sock_fd, int cmd, int user_id, int status,
                         const unsigned char *, const unsigned char *);

int serve_clnt_import_xml_runs(int sock_fd,
                               int out_fd,
                               int flags,
                               const unsigned char *xml_runs);

int serve_clnt_upload_report(int sock_fd, int cmd,
                             int user_id, int contest_id, int run_id,
                             unsigned int flags, size_t report_size,
                             const unsigned char *report_data);

int serve_clnt_reset_filter(int sock_fd, int cmd,
                            unsigned long long session_id,
                            int user_id, int contest_id);

int serve_clnt_rejudge_by_mask(int sock_fd, int cmd, int mask_size,
                               const unsigned long *mask);

int
serve_clnt_get_param(int sock_fd, int cmd, unsigned char **p_data);

#endif /* __SERVE_CLNT_H__ */
