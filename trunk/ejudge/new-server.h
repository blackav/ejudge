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
#include "iterators.h"

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

// a structure to store some persistent information
struct session_info
{
  struct session_info *next;
  struct session_info *prev;
  ej_cookie_t session_id;
  time_t expire_time;

  int user_view_all_runs;
  int user_view_all_clars;
};

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
  int action;
  int user_id;
  unsigned char *login;
  unsigned char *name;
  unsigned char *name_arm;
  const unsigned char *hidden_vars;
  struct session_info *session_extra;

  struct timeval timestamp1;
  struct timeval timestamp2;
};

void
new_server_handle_http_request(struct server_framework_state *state,
                               struct client_state *p,
                               FILE *out,
                               struct http_request_info *phr);

struct ejudge_cfg;
struct userlist_clnt;
extern struct ejudge_cfg *config;
extern struct userlist_clnt *ul_conn;
extern int ul_uid;
extern unsigned char *ul_login;

enum
{
  USER_ROLE_CONTESTANT,
  USER_ROLE_OBSERVER,
  USER_ROLE_JUDGE,
  USER_ROLE_CHIEF_JUDGE,
  USER_ROLE_COORDINATOR,
  USER_ROLE_ADMIN,

  USER_ROLE_LAST,
};

int nsdb_check_role(int user_id, int contest_id, int role);
int_iterator_t nsdb_get_contest_user_id_iterator(int contest_id);
int nsdb_get_priv_role_mask_by_iter(int_iterator_t iter, unsigned int *p_mask);
int nsdb_add_role(int user_id, int contest_id, int role);
int nsdb_del_role(int user_id, int contest_id, int role);
int nsdb_priv_remove_user(int user_id, int contest_id);

void
new_server_html_err_internal_error(struct server_framework_state *state,
                                   struct client_state *p,
                                   FILE *fout,
                                   struct http_request_info *phr,
                                   int priv_mode,
                                   const char *format, ...);

struct session_info *
new_server_get_session(ej_cookie_t session_id, time_t cur_time);

#endif /* __NEW_SERVER_H__ */
