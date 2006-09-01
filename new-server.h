/* -*- c -*- */
/* $Id$ */

#ifndef __NEW_SERVER_H__
#define __NEW_SERVER_H__

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
#include "server_framework.h"

#include <stdio.h>

struct http_request_info
{
  // program invocation arguments
  int arg_num;
  const unsigned char **args;
  // environment variables
  int env_num;
  const unsigned char **envs;
  // HTTP request parameters
  int param_num;
  const unsigned char **param_names;
  const size_t *param_sizes;
  const unsigned char **params;

  const unsigned char *self_url;
  int ssl_flag;
  ej_ip_t ip;
  ej_cookie_t session_id;
  int contest_id;
  int locale_id;
  int role;
};

void
new_server_handle_http_request(struct server_framework_state *state,
                               struct client_state *p,
                               FILE *out,
                               struct http_request_info *phr);

#endif /* __NEW_SERVER_H__ */
