/* -*- c -*- */
/* $Id$ */

#ifndef __NEW_SERVER_CLNT_H__
#define __NEW_SERVER_CLNT_H__

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

struct new_server_conn;
typedef struct new_server_conn *new_server_conn_t;

int new_server_clnt_open(const unsigned char *, new_server_conn_t *);
int new_server_clnt_send_packet(new_server_conn_t, size_t, void const *);
int new_server_clnt_recv_packet(new_server_conn_t, size_t *, void **);
int new_server_clnt_pass_fd(new_server_conn_t, int, const int *);
int new_server_clnt_close(new_server_conn_t);

int new_server_clnt_http_request(new_server_conn_t, int out_fd,
                                 unsigned char *args[],
                                 unsigned char *envs[],
                                 int param_num,
                                 unsigned char *param_names[],
                                 size_t param_sizes[],
                                 unsigned char *params[]);

int new_server_clnt_control(new_server_conn_t conn, int cmd);

#endif /* __NEW_SERVER_CLNT_H__ */
