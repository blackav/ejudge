/* -*- c -*- */
/* $Id$ */

#ifndef __NEW_SERVER_H__
#define __NEW_SERVER_H__

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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
struct userlist_user;

struct session_info
{
  struct session_info *next;
  struct session_info *prev;
  ej_cookie_t session_id;
  time_t expire_time;

  int user_view_all_runs;
  int user_view_all_clars;
  int user_viewed_section;

  struct userlist_user *user_info;
};

struct server_framework_state;
struct client_state;

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

  const unsigned char *self_url;
  int ssl_flag;
  ej_ip_t ip;
  ej_cookie_t session_id;
  int contest_id;
  int locale_id;
  int role;
  int action;
  int user_id;
  int reg_status;
  int reg_flags;
  unsigned char *login;
  unsigned char *name;
  unsigned char *name_arm;
  const unsigned char *hidden_vars;
  struct session_info *session_extra;
  opcap_t caps;
  unsigned char *script_part;
  unsigned char *body_attr;

  // for the next state
  int next_run_id;
  int protocol_reply;
  int allow_empty_output;
  int no_reply;

  struct timeval timestamp1;
  struct timeval timestamp2;
};

void
ns_handle_http_request(struct server_framework_state *state,
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
  NEW_SRV_ACTION_MAIN_PAGE = 2,
  NEW_SRV_ACTION_COOKIE_LOGIN = 3, /* number needed for super-serve */
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
  NEW_SRV_ACTION_USERS_SET_INCOMPLETE,
  NEW_SRV_ACTION_USERS_CLEAR_INCOMPLETE,
  NEW_SRV_ACTION_USERS_SET_DISQUALIFIED,
  NEW_SRV_ACTION_USERS_CLEAR_DISQUALIFIED,
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
  NEW_SRV_ACTION_CHANGE_RUN_LANG_ID,
  NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED,
  NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN,
  NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE,
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
  NEW_SRV_ACTION_UPDATE_STANDINGS_2,
  NEW_SRV_ACTION_RESET_2,
  NEW_SRV_ACTION_GENERATE_PASSWORDS_2,
  NEW_SRV_ACTION_CLEAR_PASSWORDS_2,
  NEW_SRV_ACTION_GENERATE_REG_PASSWORDS_2,
  NEW_SRV_ACTION_VIEW_CNTS_PWDS,
  NEW_SRV_ACTION_VIEW_REG_PWDS,
  NEW_SRV_ACTION_TOGGLE_VISIBILITY,
  NEW_SRV_ACTION_TOGGLE_BAN,
  NEW_SRV_ACTION_TOGGLE_LOCK,
  NEW_SRV_ACTION_TOGGLE_INCOMPLETENESS,
  NEW_SRV_ACTION_SET_DISQUALIFICATION,
  NEW_SRV_ACTION_CLEAR_DISQUALIFICATION,
  NEW_SRV_ACTION_USER_CHANGE_STATUS,
  NEW_SRV_ACTION_VIEW_USER_INFO,
  NEW_SRV_ACTION_ISSUE_WARNING,
  NEW_SRV_ACTION_NEW_RUN_FORM,
  NEW_SRV_ACTION_NEW_RUN,
  NEW_SRV_ACTION_VIEW_USER_DUMP,
  NEW_SRV_ACTION_FORGOT_PASSWORD_1,
  NEW_SRV_ACTION_FORGOT_PASSWORD_2,
  NEW_SRV_ACTION_FORGOT_PASSWORD_3,
  NEW_SRV_ACTION_SUBMIT_APPEAL,
  NEW_SRV_ACTION_VIEW_PROBLEM_SUMMARY,
  NEW_SRV_ACTION_VIEW_PROBLEM_STATEMENTS,
  NEW_SRV_ACTION_VIEW_PROBLEM_SUBMIT,
  NEW_SRV_ACTION_VIEW_SUBMISSIONS,
  NEW_SRV_ACTION_VIEW_CLAR_SUBMIT,
  NEW_SRV_ACTION_VIEW_CLARS,
  NEW_SRV_ACTION_VIEW_SETTINGS,
  NEW_SRV_ACTION_VIRTUAL_START,
  NEW_SRV_ACTION_VIRTUAL_STOP,
  NEW_SRV_ACTION_VIEW_USER_REPORT,
  NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_1,
  NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_2,
  NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_1,
  NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_2,
  NEW_SRV_ACTION_VIEW_RUNS_DUMP,
  NEW_SRV_ACTION_EXPORT_XML_RUNS,
  NEW_SRV_ACTION_WRITE_XML_RUNS,
  NEW_SRV_ACTION_WRITE_XML_RUNS_WITH_SRC,
  NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_1,
  NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_2,
  NEW_SRV_ACTION_LOGIN,         /* for new-server-cmd */
  NEW_SRV_ACTION_DUMP_PROBLEMS,
  NEW_SRV_ACTION_SOFT_UPDATE_STANDINGS,
  NEW_SRV_ACTION_HAS_TRANSIENT_RUNS,
  NEW_SRV_ACTION_DUMP_RUN_STATUS,
  NEW_SRV_ACTION_DUMP_SOURCE,
  NEW_SRV_ACTION_DUMP_CLAR,
  NEW_SRV_ACTION_GET_CONTEST_NAME,
  NEW_SRV_ACTION_GET_CONTEST_TYPE,
  NEW_SRV_ACTION_DUMP_MASTER_RUNS,
  NEW_SRV_ACTION_DUMP_REPORT,
  NEW_SRV_ACTION_FULL_UPLOAD_RUNLOG_XML,
  NEW_SRV_ACTION_XML_USER_STATE,
  NEW_SRV_ACTION_VIEW_STARTSTOP,
  NEW_SRV_ACTION_CLEAR_DISPLAYED_1,
  NEW_SRV_ACTION_CLEAR_DISPLAYED_2,
  NEW_SRV_ACTION_IGNORE_DISPLAYED_1,
  NEW_SRV_ACTION_IGNORE_DISPLAYED_2,
  NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1,
  NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_2,
  NEW_SRV_ACTION_UPDATE_ANSWER,
  NEW_SRV_ACTION_UPSOLVING_CONFIG_1,
  NEW_SRV_ACTION_UPSOLVING_CONFIG_2,
  NEW_SRV_ACTION_UPSOLVING_CONFIG_3,
  NEW_SRV_ACTION_UPSOLVING_CONFIG_4,
  NEW_SRV_ACTION_EXAMINERS_PAGE,
  NEW_SRV_ACTION_ASSIGN_CHIEF_EXAMINER,
  NEW_SRV_ACTION_ASSIGN_EXAMINER,
  NEW_SRV_ACTION_UNASSIGN_EXAMINER,

  /* new-register stuff */
  NEW_SRV_ACTION_REG_CREATE_ACCOUNT_PAGE,
  NEW_SRV_ACTION_REG_CREATE_ACCOUNT,
  NEW_SRV_ACTION_REG_ACCOUNT_CREATED_PAGE,
  NEW_SRV_ACTION_REG_LOGIN_PAGE,
  NEW_SRV_ACTION_REG_LOGIN,
  NEW_SRV_ACTION_REG_VIEW_GENERAL,
  NEW_SRV_ACTION_REG_VIEW_CONTESTANTS,
  NEW_SRV_ACTION_REG_VIEW_RESERVES,
  NEW_SRV_ACTION_REG_VIEW_COACHES,
  NEW_SRV_ACTION_REG_VIEW_ADVISORS,
  NEW_SRV_ACTION_REG_VIEW_GUESTS,
  NEW_SRV_ACTION_REG_ADD_MEMBER_PAGE,
  NEW_SRV_ACTION_REG_EDIT_GENERAL_PAGE,
  NEW_SRV_ACTION_REG_EDIT_MEMBER_PAGE,
  NEW_SRV_ACTION_REG_MOVE_MEMBER,
  NEW_SRV_ACTION_REG_REMOVE_MEMBER,
  NEW_SRV_ACTION_REG_SUBMIT_GENERAL_EDITING,
  NEW_SRV_ACTION_REG_CANCEL_GENERAL_EDITING,
  NEW_SRV_ACTION_REG_SUBMIT_MEMBER_EDITING,
  NEW_SRV_ACTION_REG_CANCEL_MEMBER_EDITING,
  NEW_SRV_ACTION_REG_REGISTER,

  NEW_SRV_ACTION_LAST,
};

struct contest_extra
{
  struct watched_file header;
  struct watched_file menu_1;
  struct watched_file menu_2;
  struct watched_file separator;
  struct watched_file footer;
  struct watched_file priv_header;
  struct watched_file priv_footer;
  struct watched_file copyright;
  struct watched_file welcome;

  const unsigned char *header_txt;
  const unsigned char *menu_1_txt;
  const unsigned char *menu_2_txt;
  const unsigned char *footer_txt;
  const unsigned char *separator_txt;
  const unsigned char *copyright_txt;
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
int nsdb_find_chief_examiner(int contest_id, int prob_id);
int nsdb_assign_chief_examiner(int user_id, int contest_id, int prob_id);
int nsdb_assign_examiner(int user_id, int contest_id, int prob_id);
int nsdb_remove_examiner(int user_id, int contest_id, int prob_id);
int_iterator_t nsdb_get_examiner_user_id_iterator(int contest_id, int prob_id);
int nsdb_get_examiner_count(int contest_id, int prob_id);


struct contest_extra *ns_get_contest_extra(int contest_id);

void
ns_html_err_internal_error(FILE *fout,
                           struct http_request_info *phr,
                           int priv_mode,
                           const char *format, ...)
  __attribute__((format(printf, 4, 5)));
void
ns_html_err_no_perm(FILE *fout,
                    struct http_request_info *phr,
                    int priv_mode,
                    const char *format, ...)
  __attribute__((format(printf, 4, 5)));
void
ns_html_err_inv_param(FILE *fout,
                      struct http_request_info *phr,
                      int priv_mode,
                      const char *format, ...)
  __attribute__((format(printf, 4, 5)));
void
ns_html_err_service_not_available(FILE *fout,
                                  struct http_request_info *phr,
                                  int priv_mode,
                                  const char *format, ...)
  __attribute__((format(printf, 4, 5)));
void
ns_html_err_cnts_unavailable(FILE *fout,
                             struct http_request_info *phr,
                             int priv_mode,
                             const char *format, ...)
  __attribute__((format(printf, 4, 5)));
void
ns_html_err_ul_server_down(FILE *fout,
                           struct http_request_info *phr,
                           int priv_mode,
                           const char *format, ...)
  __attribute__((format(printf, 4, 5)));
void
ns_html_err_inv_session(FILE *fout,
                        struct http_request_info *phr,
                        int priv_mode,
                        const char *format, ...)
  __attribute__((format(printf, 4, 5)));
void
ns_html_err_registration_incomplete(
	FILE *fout,
        struct http_request_info *phr);
void
ns_html_err_disqualified(
	FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);

struct session_info *
ns_get_session(ej_cookie_t session_id, time_t cur_time);

void ns_remove_session(ej_cookie_t session_id);

void ns_unload_contests(void);

void ns_loop_callback(struct server_framework_state *state);
void ns_post_select_callback(struct server_framework_state *state);

unsigned char *
ns_submit_button(unsigned char *buf, size_t size,
                 const unsigned char *var_name, int action,
                 const unsigned char *label);

unsigned char *
ns_url(unsigned char *buf, size_t size,
       const struct http_request_info *phr,
       int action, const char *format, ...)
  __attribute__((format(printf, 5, 6)));
unsigned char *
ns_url_unescaped(unsigned char *buf, size_t size,
                 const struct http_request_info *phr,
                 int action, const char *format,
                 ...)
  __attribute__((format(printf, 5, 6)));
unsigned char *
ns_aref(unsigned char *buf, size_t size,
        const struct http_request_info *phr,
        int action, const char *format, ...)
  __attribute__((format(printf, 5, 6)));
unsigned char *
ns_aref_2(unsigned char *buf, size_t size,
          const struct http_request_info *phr,
          const unsigned char *style,
          int action, const char *format, ...)
  __attribute__((format(printf, 6, 7)));

void
ns_refresh_page(FILE *fout, struct http_request_info *phr, int new_action,
                const unsigned char *extra);
void
ns_refresh_page_2(FILE *fout, const unsigned char *url);

void
ns_write_priv_all_runs(FILE *f,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra,
                       int first_run, int last_run,
                       unsigned char const *filter_expr);
void
ns_write_all_clars(FILE *f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra,
                   int mode_clar, int first_clar, int last_clar);

void ns_write_priv_source(const serve_state_t state,
                          FILE *f,
                          FILE *log_f,
                          struct http_request_info *phr,
                          const struct contest_desc *cnts,
                          struct contest_extra *extra,
                          int run_id);

void ns_write_priv_report(const serve_state_t cs,
                          FILE *f,
                          FILE *log_f,
                          struct http_request_info *phr,
                          const struct contest_desc *cnts,
                          struct contest_extra *extra,
                          int team_report_flag,
                          int run_id);

void ns_write_audit_log(
	const serve_state_t state,
        FILE *f,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int run_id);

void
ns_write_priv_clar(const serve_state_t cs,
                   FILE *f,
                   FILE *log_f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra,
                   int clar_id);

void ns_header(FILE *out, unsigned char const *template,
               unsigned char const *content_type,
               unsigned char const *charset,
               const unsigned char *script_part,
               const unsigned char *body_attr,
               int locale_id,
               char const *format, ...)
  __attribute__((format(printf, 8, 9)));
void ns_footer(FILE *out, unsigned char const *templ,
               const unsigned char *copyright, int locale_id);

const unsigned char *ns_unparse_role(int role);

void
ns_write_tests(const serve_state_t cs, FILE *fout, FILE *log_f,
               int action, int run_id, int test_num);

int
ns_write_passwords(FILE *fout, FILE *log_f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra);

int
ns_user_info_page(FILE *fout, FILE *log_f,
                  struct http_request_info *phr,
                  const struct contest_desc *cnts,
                  struct contest_extra *extra,
                  int view_user_id);
int
ns_new_run_form(FILE *fout, FILE *log_f,
                struct http_request_info *phr,
                const struct contest_desc *cnts,
                struct contest_extra *extra);

void
ns_write_priv_standings(const serve_state_t state,
                        const struct contest_desc *cnts,
                        FILE *f, int accepting_mode);

extern const unsigned char * const ns_submit_button_labels[];
extern const int ns_priv_next_state[];
extern const int ns_priv_prev_state[];
extern const int ns_unpriv_prev_state[];

extern const unsigned char ns_default_header[];
extern const unsigned char ns_default_footer[];
extern const unsigned char ns_default_separator[];
extern const unsigned char ns_fancy_header[];
extern const unsigned char ns_fancy_footer[];
extern const unsigned char ns_fancy_footer_2[];
extern const unsigned char ns_fancy_separator[];
extern const unsigned char ns_fancy_empty_status[];
extern const unsigned char * const ns_ssl_flag_str[];
extern const unsigned char ns_fancy_priv_header[];
extern const unsigned char ns_fancy_priv_footer[];
extern const unsigned char ns_fancy_priv_separator[];
extern const unsigned char ns_fancy_unpriv_content_header[];

enum
{
  NS_RUNSEL_ALL = 0,
  NS_RUNSEL_DISPLAYED,
  NS_RUNSEL_OK,

  NS_FILE_PATTERN_RUN = 0x1,
  NS_FILE_PATTERN_UID = 0x2,
  NS_FILE_PATTERN_LOGIN = 0x4,
  NS_FILE_PATTERN_PROB = 0x8,
  NS_FILE_PATTERN_LANG = 0x10,
  NS_FILE_PATTERN_SUFFIX = 0x20,
  NS_FILE_PATTERN_NAME = 0x40,
};

void
ns_download_runs(
	const serve_state_t cs, FILE *fout, FILE *log_f,
        int run_selection,
        int dir_struct,
        int file_name_mask,
        size_t run_mask_size,
        unsigned long *run_mask);

int
ns_upload_csv_runs(
	struct http_request_info *phr,
	const serve_state_t cs, FILE *log_f,
        const unsigned char *csv_text);

int
ns_write_user_run_status(
	const serve_state_t cs,
        FILE *fout,
        int run_id);
void
ns_write_olympiads_user_runs(
	struct http_request_info *phr,
        FILE *fout,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int all_runs,
        int prob_id,
        const unsigned char *table_class);

int
new_server_cmd_handler(FILE *fout, struct http_request_info *phr);

int
ns_cgi_param(const struct http_request_info *phr, const unsigned char *param,
             const unsigned char **p_value);
int ns_cgi_param_bin(const struct http_request_info *phr,
                     const unsigned char *param,
                     const unsigned char **p_value, size_t *p_size);
int ns_cgi_param_int( struct http_request_info *phr,
                      const unsigned char *name,
                      int *p_val);


struct server_framework_state;
int ns_open_ul_connection(struct server_framework_state *state);

int
ns_list_all_users_callback(
	void *user_data,
        int contest_id,
        unsigned char **p_xml);
void
ns_check_contest_events(serve_state_t cs, const struct contest_desc *cnts);
void ns_contest_unload_callback(serve_state_t cs);
void ns_client_destroy_callback(struct client_state *p);
struct client_state *ns_get_client_by_id(int client_id);
void ns_send_reply(struct client_state *p, int answer);
void ns_new_autoclose(struct client_state *p, void *, size_t);

void
ns_get_user_problems_summary(
	const serve_state_t cs, int user_id, int accepting_mode,
        unsigned char *solved_flag,   /* whether the problem was OK */
        unsigned char *accepted_flag, /* whether the problem was accepted */
        unsigned char *pending_flag,  /* whether there are pending runs */
        unsigned char *trans_flag,    /* whether there are transient runs */
        int *best_run,                /* the number of the best run */
        int *attempts,                /* the number of previous attempts */
        int *disqualified,            /* the number of prev. disq. attempts */
        int *best_score,              /* the best score for the problem */
        int *prev_successes,          /* the number of prev. successes */
        int *all_attempts);           /* all attempts count */

void
ns_write_user_problems_summary(
	const struct contest_desc *cnts,
	const serve_state_t cs,
        FILE *fout,
        int user_id,
        int accepting_mode,
        const unsigned char *table_class,
        unsigned char *solved_flag,   /* whether the problem was OK */
        unsigned char *accepted_flag, /* whether the problem was accepted */
        unsigned char *pending_flag,  /* whether there are pending runs */
        unsigned char *trans_flag,    /* whether there are transient runs */
        int *best_run,                /* the number of the best run */
        int *attempts,                /* the number of previous attempts */
        int *disqualified,            /* the number of prev. disq. attempts */
        int *best_score,              /* the best score for the problem */
        int *prev_successes);         /* the number of prev. successes */

int ns_insert_variant_num(unsigned char *buf, size_t size,
                          const unsigned char *file, int variant);
void ns_register_pages(FILE *fout, struct http_request_info *phr);

int
ns_examiners_page(
	FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);

#endif /* __NEW_SERVER_H__ */
