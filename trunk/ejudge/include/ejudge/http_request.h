/* -*- c -*- */
/* $Id$ */
#ifndef __HTTP_REQUEST_H__
#define __HTTP_REQUEST_H__

/* Copyright (C) 2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"
#include "ejudge/opcaps.h"

#include <stdio.h>
#include <sys/time.h>

struct server_framework_state;
struct client_state;
struct session_info;
struct contest_desc;
struct contest_extra;
struct ejudge_cfg;
struct sid_state;
struct userlist_clnt;

struct http_request_info
{
  int id;
  struct server_framework_state *fw_state;
  struct client_state *client_state;

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

  const unsigned char *http_host;
  const unsigned char *self_url;
  const unsigned char *context_url;
  const unsigned char *script_name;
  int ssl_flag;
  ej_ip_t ip;
  ej_cookie_t session_id;
  ej_cookie_t client_key;
  int contest_id;
  int locale_id;
  int role;
  int action;
  unsigned char role_name[32];
  int anonymous_mode; // not authentificated

  int priv_level;
  int user_id;
  int plain_text;
  int json_reply;
  int reg_status;
  int reg_flags;
  int rest_mode;
  unsigned char *login;
  unsigned char *html_login; // not used by ej-contests
  unsigned char *name;
  unsigned char *name_arm;
  // super-serve uses that
  unsigned char *html_name;  // used by super-serve
  const unsigned char *hidden_vars;
  struct session_info *session_extra;
  opcap_t caps;
  opcap_t dbcaps;
  unsigned char *script_part;
  unsigned char *body_attr;
  int online_users;

  // for the next state
  unsigned char next_extra[128];
  int protocol_reply;
  int allow_empty_output;
  int no_reply;
  int error_code;
  unsigned char *redirect;

  // content type
  unsigned char content_type[128];

  time_t current_time;
  struct timeval timestamp1;
  struct timeval timestamp2;

  const struct contest_desc *cnts;
  struct contest_extra *extra;

  // these fields used by super-serve
  const unsigned char *system_login;
  const struct ejudge_cfg *config;
  struct sid_state *ss;
  struct userlist_clnt *userlist_clnt;

  // should we suspend reply because of background process?
  int suspend_reply;
  // pointer to suspend data (client_state actually)
  void *suspend_context;
  void (*continuation)(struct http_request_info *);

  // output streams
  FILE *out_f;
  char *out_t;
  size_t out_z;

  FILE *log_f;
  char *log_t;
  size_t log_z;

  unsigned char data[0];
};

const unsigned char*
hr_getenv(
        const struct http_request_info *phr,
        const unsigned char *var);

int
hr_cgi_param(
        const struct http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value);

int
hr_cgi_param_bin(
        const struct http_request_info *phr,
        const unsigned char *param,
        const unsigned char **p_value,
        size_t *p_size);

const unsigned char *
hr_cgi_nname(
        const struct http_request_info *phr,
        const unsigned char *prefix,
        size_t pflen);

int
hr_cgi_param_int(
        const struct http_request_info *phr,
        const unsigned char *name,
        int *p_val);
int
hr_cgi_param_int_2(
        const struct http_request_info *phr,
        const unsigned char *name,
        int *p_val);

int
hr_cgi_param_int_opt(
        struct http_request_info *phr,
        const unsigned char *name,
        int *p_val,
        int default_value);

int
hr_cgi_param_int_opt_2(
        struct http_request_info *phr,
        const unsigned char *name,
        int *p_val,
        int *p_set_flag);

void
hr_master_url(
        FILE *out_f,
        const struct http_request_info *phr);
void
hr_judge_url(
        FILE *out_f,
        const struct http_request_info *phr);
void
hr_register_url(
        FILE *out_f,
        const struct http_request_info *phr);
void
hr_client_url(
        FILE *out_f,
        const struct http_request_info *phr);

void
hr_set_symbolic_action_table(
        int table_size,
        const unsigned char * const *table, 
        const unsigned char * const *submit_labels,
        const unsigned char * const *helps);

const unsigned char *
hr_url_2(
        FILE *out_f,
        const struct http_request_info *phr,
        int action);
const unsigned char *
hr_url_3(
        FILE *out_f,
        const struct http_request_info *phr,
        int action);
const unsigned char *
hr_url_4(
        FILE *out_f,
        const struct http_request_info *phr,
        int action);

void
hr_submit_button(
        FILE *out_f,
        const unsigned char *var_name,
        int action,
        const unsigned char *label);

const unsigned char *
hr_redirect_2(
        FILE *out_f,
        const struct http_request_info *phr,
        int action);

void
hr_print_help_url(FILE *f, int action);

#endif /* __HTTP_REQUEST_H__ */

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
