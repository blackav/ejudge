/* -*- c -*- */
/* $Id$ */
#ifndef __SOCK_OP_H__
#define __SOCK_OP_H__

/* Copyright (C) 2008 Alexander Chernov <cher@ejudge.ru> */

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

/*
 * various system-dependent socket operations
 */
int
sock_op_put_fds(
	int sock_fd,
        int fds_num,
        const int *fds);

int
sock_op_get_fds(
	int sock_fd,
        int conn_id,
        int *fds);

int
sock_op_enable_creds(int sock_fd);

int
sock_op_put_creds(int sock_fd);

int
sock_op_get_creds(
        int sock_fd,
        int conn_id,
        int *p_pid,
        int *p_uid,
        int *p_gid);

#endif /* __SOCK_OP_H__ */
