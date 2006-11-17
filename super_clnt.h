/* -*- c -*- */
/* $Id$ */

#ifndef __SUPER_CLNT_H__
#define __SUPER_CLNT_H__

/* Copyright (C) 2004-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "super_proto.h"

#include <string.h>

int super_clnt_open(const unsigned char *path);

int super_clnt_do_pass_fd(int sock_fd, int fds_num, int *fds);
int super_clnt_send_packet(int sock_fd, size_t size, const void *buf);
int super_clnt_recv_packet(int sock_fd,
                           struct prot_super_packet *p_res,
                           size_t *p_size, void **p_data);

int super_clnt_pass_fd(int sock_fd, int nfd, int *fds);

int super_clnt_main_page(int sock_fd,
                         int out_fd,
                         int cmd,
                         int contest_id,
                         int locale_id,
                         unsigned int flags,
                         const unsigned char *self_url,
                         const unsigned char *hidden_vars,
                         const unsigned char *extra_args);

int super_clnt_simple_cmd(int sock_fd,
                          int cmd,
                          int contest_id);

int super_clnt_create_contest(int sock_fd,
                              int out_fd,
                              int cmd,
                              int num_mode,
                              int templ_mode,
                              int contest_id,
                              int templ_id,
                              const unsigned char *self_url,
                              const unsigned char *hidden_vars,
                              const unsigned char *extra_args);

int super_clnt_set_param(int sock_fd,
                         int cmd,
                         int param1,
                         const unsigned char *param2,
                         int param3,
                         int param4,
                         int param5);

int super_clnt_control(int sock_fd, int cmd);

#endif /* __SUPER_CLNT_H__ */
