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
#include "watched_file.h"
#include "serve_state.h"

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
  int user_viewed_section;
};

struct server_framework_state;

struct http_request_info
{
  int id;
  struct server_framework_state *fw_state;

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
  opcap_t caps;

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
  USER_ROLE_EXAMINER,
  USER_ROLE_CHIEF_EXAMINER,
  USER_ROLE_COORDINATOR,
  USER_ROLE_JUDGE,
  USER_ROLE_ADMIN,

  USER_ROLE_LAST,
};

enum
{
  NEW_SRV_ACTION_LOGIN_PAGE = 1,
  NEW_SRV_ACTION_MAIN_PAGE,
  NEW_SRV_ACTION_VIEW_USERS,
  NEW_SRV_ACTION_USERS_REMOVE_REGISTRATIONS,
  NEW_SRV_ACTION_USERS_SET_PENDING,
  NEW_SRV_ACTION_USERS_SET_OK,
  NEW_SRV_ACTION_USERS_SET_REJECTED,
  NEW_SRV_ACTION_USERS_SET_INVISIBLE,
  NEW_SRV_ACTION_USERS_CLEAR_INVISIBLE,
  NEW_SRV_ACTION_USERS_SET_BANNED,
  NEW_SRV_ACTION_USERS_CLEAR_BANNED,
  NEW_SRV_ACTION_USERS_SET_LOCKED,
  NEW_SRV_ACTION_USERS_CLEAR_LOCKED,
  NEW_SRV_ACTION_USERS_ADD_BY_LOGIN,
  NEW_SRV_ACTION_USERS_ADD_BY_USER_ID,
  NEW_SRV_ACTION_PRIV_USERS_VIEW,
  NEW_SRV_ACTION_PRIV_USERS_REMOVE,
  NEW_SRV_ACTION_PRIV_USERS_ADD_OBSERVER,
  NEW_SRV_ACTION_PRIV_USERS_DEL_OBSERVER,
  NEW_SRV_ACTION_PRIV_USERS_ADD_EXAMINER,
  NEW_SRV_ACTION_PRIV_USERS_DEL_EXAMINER,
  NEW_SRV_ACTION_PRIV_USERS_ADD_CHIEF_EXAMINER,
  NEW_SRV_ACTION_PRIV_USERS_DEL_CHIEF_EXAMINER,
  NEW_SRV_ACTION_PRIV_USERS_ADD_COORDINATOR,
  NEW_SRV_ACTION_PRIV_USERS_DEL_COORDINATOR,
  NEW_SRV_ACTION_PRIV_USERS_ADD_BY_LOGIN,
  NEW_SRV_ACTION_PRIV_USERS_ADD_BY_USER_ID,
  NEW_SRV_ACTION_CHANGE_LANGUAGE,
  NEW_SRV_ACTION_CHANGE_PASSWORD,
  NEW_SRV_ACTION_VIEW_SOURCE,
  NEW_SRV_ACTION_VIEW_REPORT,
  NEW_SRV_ACTION_PRINT_RUN,
  NEW_SRV_ACTION_VIEW_CLAR,
  NEW_SRV_ACTION_SUBMIT_RUN,
  NEW_SRV_ACTION_SUBMIT_CLAR,
  NEW_SRV_ACTION_START_CONTEST,
  NEW_SRV_ACTION_STOP_CONTEST,
  NEW_SRV_ACTION_CONTINUE_CONTEST,
  NEW_SRV_ACTION_SCHEDULE,
  NEW_SRV_ACTION_CHANGE_DURATION,
  NEW_SRV_ACTION_UPDATE_STANDINGS_1,
  NEW_SRV_ACTION_RESET_1,
  NEW_SRV_ACTION_SUSPEND,
  NEW_SRV_ACTION_RESUME,
  NEW_SRV_ACTION_TEST_SUSPEND,
  NEW_SRV_ACTION_TEST_RESUME,
  NEW_SRV_ACTION_PRINT_SUSPEND,
  NEW_SRV_ACTION_PRINT_RESUME,
  NEW_SRV_ACTION_SET_JUDGING_MODE,
  NEW_SRV_ACTION_SET_ACCEPTING_MODE,
  NEW_SRV_ACTION_GENERATE_PASSWORDS_1,
  NEW_SRV_ACTION_CLEAR_PASSWORDS_1,
  NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_1,
  NEW_SRV_ACTION_RELOAD_SERVER,
  NEW_SRV_ACTION_PRIV_SUBMIT_CLAR,
  NEW_SRV_ACTION_RESET_FILTER,
  NEW_SRV_ACTION_CLEAR_RUN,
  NEW_SRV_ACTION_CHANGE_STATUS,
  NEW_SRV_ACTION_REJUDGE_ALL_1,
  NEW_SRV_ACTION_REJUDGE_SUSPENDED_1,
  NEW_SRV_ACTION_REJUDGE_DISPLAYED_1,
  NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1,
  NEW_SRV_ACTION_SQUEEZE_RUNS,
  NEW_SRV_ACTION_RESET_CLAR_FILTER,
  NEW_SRV_ACTION_LOGOUT,
  NEW_SRV_ACTION_CHANGE_RUN_USER_ID,
  NEW_SRV_ACTION_CHANGE_RUN_USER_LOGIN,
  NEW_SRV_ACTION_CHANGE_RUN_PROB_ID,
  NEW_SRV_ACTION_CHANGE_RUN_VARIANT,
  NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED,
  NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN,
  NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY,
  NEW_SRV_ACTION_CHANGE_RUN_STATUS,
  NEW_SRV_ACTION_CHANGE_RUN_TEST,
  NEW_SRV_ACTION_CHANGE_RUN_SCORE,
  NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ,
  NEW_SRV_ACTION_CHANGE_RUN_PAGES,
  NEW_SRV_ACTION_PRIV_DOWNLOAD_RUN,
  NEW_SRV_ACTION_COMPARE_RUNS,
  NEW_SRV_ACTION_UPLOAD_REPORT,
  NEW_SRV_ACTION_STANDINGS,
  NEW_SRV_ACTION_REJUDGE_PROBLEM_1,
  NEW_SRV_ACTION_CLAR_REPLY,
  NEW_SRV_ACTION_CLAR_REPLY_ALL,
  NEW_SRV_ACTION_CLAR_REPLY_READ_PROBLEM,
  NEW_SRV_ACTION_CLAR_REPLY_NO_COMMENTS,
  NEW_SRV_ACTION_CLAR_REPLY_YES,
  NEW_SRV_ACTION_CLAR_REPLY_NO,
  NEW_SRV_ACTION_REJUDGE_DISPLAYED_2,
  NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_2,
  NEW_SRV_ACTION_REJUDGE_PROBLEM_2,
  NEW_SRV_ACTION_REJUDGE_ALL_2,
  NEW_SRV_ACTION_REJUDGE_SUSPENDED_2,
  NEW_SRV_ACTION_VIEW_TEST_INPUT,
  NEW_SRV_ACTION_VIEW_TEST_ANSWER,
  NEW_SRV_ACTION_VIEW_TEST_INFO,
  NEW_SRV_ACTION_VIEW_TEST_OUTPUT,
  NEW_SRV_ACTION_VIEW_TEST_ERROR,
  NEW_SRV_ACTION_VIEW_TEST_CHECKER,
  NEW_SRV_ACTION_VIEW_AUDIT_LOG,

  NEW_SRV_ACTION_LAST,
};

struct contest_extra
{
  struct watched_file header;
  struct watched_file footer;
  struct watched_file priv_header;
  struct watched_file priv_footer;

  const unsigned char *header_txt;
  const unsigned char *footer_txt;
  unsigned char *contest_arm;

  serve_state_t serve_state;
  time_t last_access_time;
};

int nsdb_check_role(int user_id, int contest_id, int role);
int_iterator_t nsdb_get_contest_user_id_iterator(int contest_id);
int nsdb_get_priv_role_mask_by_iter(int_iterator_t iter, unsigned int *p_mask);
int nsdb_add_role(int user_id, int contest_id, int role);
int nsdb_del_role(int user_id, int contest_id, int role);
int nsdb_priv_remove_user(int user_id, int contest_id);

void
new_server_html_err_internal_error(FILE *fout,
                                   struct http_request_info *phr,
                                   int priv_mode,
                                   const char *format, ...)
  __attribute__((format(printf, 4, 5)));

struct session_info *
new_server_get_session(ej_cookie_t session_id, time_t cur_time);

void new_server_remove_session(ej_cookie_t session_id);

void new_server_unload_contests(void);

void new_server_loop_callback(struct server_framework_state *state);
void new_server_post_select_callback(struct server_framework_state *state);

unsigned char *
new_serve_submit_button(unsigned char *buf, size_t size,
                        const unsigned char *var_name, int action,
                        const unsigned char *label);

unsigned char *
new_serve_url(unsigned char *buf, size_t size,
              const struct http_request_info *phr,
              int action, const char *format, ...)
  __attribute__((format(printf, 5, 6)));
unsigned char *
new_serve_aref(unsigned char *buf, size_t size,
               const struct http_request_info *phr,
               int action, const char *format, ...)
  __attribute__((format(printf, 5, 6)));

void
new_serve_write_priv_all_runs(FILE *f,
                              struct http_request_info *phr,
                              const struct contest_desc *cnts,
                              struct contest_extra *extra,
                              int first_run, int last_run,
                              unsigned char const *filter_expr);
void
new_serve_write_all_clars(FILE *f,
                          struct http_request_info *phr,
                          const struct contest_desc *cnts,
                          struct contest_extra *extra,
                          int mode_clar, int first_clar, int last_clar);

void new_serve_write_priv_source(const serve_state_t state,
                                 FILE *f,
                                 FILE *log_f,
                                 struct http_request_info *phr,
                                 const struct contest_desc *cnts,
                                 struct contest_extra *extra,
                                 int run_id);

void new_serve_write_priv_report(const serve_state_t cs,
                                 FILE *f,
                                 FILE *log_f,
                                 struct http_request_info *phr,
                                 const struct contest_desc *cnts,
                                 struct contest_extra *extra,
                                 int team_report_flag,
                                 int run_id);

void
new_serve_write_priv_clar(const serve_state_t cs,
                          FILE *f,
                          FILE *log_f,
                          struct http_request_info *phr,
                          const struct contest_desc *cnts,
                          struct contest_extra *extra,
                          int clar_id);

void new_serve_header(FILE *out, unsigned char const *template,
                      unsigned char const *content_type,
                      unsigned char const *charset,
                      int locale_id,
                      char const *format, ...)
  __attribute__((format(printf, 6, 7)));

const unsigned char *new_serve_unparse_role(int role);

void
new_serve_write_tests(const serve_state_t cs, FILE *fout, FILE *log_f,
                      int action, int run_id, int test_num);

extern const unsigned char * const new_serve_submit_button_labels[];
extern const int new_serve_priv_next_state[];
extern const int new_serve_priv_prev_state[];
extern const int new_serve_unpriv_prev_state[];

#endif /* __NEW_SERVER_H__ */
