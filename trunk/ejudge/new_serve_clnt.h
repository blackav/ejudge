/* -*- c -*- */
/* $Id$ */

#ifndef __NEW_SERVE_CLNT_H__
#define __NEW_SERVE_CLNT_H__

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

struct new_serve_conn;
typedef struct new_serve_conn *new_serve_conn_t;

int new_serve_clnt_open(const unsigned char *, new_serve_conn_t *);
int new_serve_clnt_send_packet(new_serve_conn_t, size_t, void const *);
int new_serve_clnt_recv_packet(new_serve_conn_t, size_t *, void **);
int new_serve_clnt_pass_fd(new_serve_conn_t, int, const int *);
int new_serve_clnt_close(new_serve_conn_t);

int new_serve_http_request(new_serve_conn_t, int out_fd,
                           char *args[], char *environ[],
                           int nparams, size_t param_sizes[],
                           char *params[]);

#endif /* __NEW_SERVE_CLNT_H__ */
