/* -*- c -*- */

#ifndef __NEW_SERVER_H__
#define __NEW_SERVER_H__

/* Copyright (C) 2006-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/server_framework.h"
#include "ejudge/iterators.h"
#include "ejudge/watched_file.h"
#include "ejudge/serve_state.h"
#include "ejudge/http_request.h"

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

// a structure to store some persistent information
struct userlist_user;

struct session_info
{
  struct session_info *next;
  struct session_info *prev;
  ej_cookie_t _session_id;
  ej_cookie_t _client_key;
  time_t expire_time;

  int user_view_all_runs;
  int user_view_all_clars;
  int user_viewed_section;

  struct userlist_user *user_info;
};

struct server_framework_state;
struct client_state;
struct contest_desc;
struct contest_extra;

void
ns_handle_http_request(
        struct server_framework_state *state,
        FILE *out,
        struct http_request_info *phr);

struct ejudge_cfg;
struct userlist_clnt;
extern struct ejudge_cfg *ejudge_config;
extern struct userlist_clnt *ul_conn;
extern int ul_uid;
extern unsigned char *ul_login;

#ifndef __USER_ROLE_DEFINED__
#define __USER_ROLE_DEFINED__
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
#endif

struct last_access_info
{
  ej_ip_t ip;
  int     ssl;
  time_t  time;
  int     user_id;
};

struct last_access_array
{
  struct last_access_info *v;
  int a, u;
};

struct last_access_idx
{
  short *v;
  int a;
};

struct avatar_loaded_plugin;
struct content_loaded_plugin;
struct ContestExternalActions;

struct contest_extra
{
  int contest_id;

  struct watched_file copyright;
  struct watched_file welcome;
  struct watched_file reg_welcome;

  const unsigned char *header_txt;
  const unsigned char *footer_txt;
  const unsigned char *separator_txt;

  const unsigned char *priv_header_txt;
  const unsigned char *priv_footer_txt;
  const unsigned char *priv_separator_txt;

  const unsigned char *copyright_txt;
  unsigned char *contest_arm;

  struct last_access_array user_access[USER_ROLE_LAST];
  struct last_access_idx   user_access_idx;

  serve_state_t serve_state;
  time_t last_access_time;

  // the main avatar plugin
  // FIXME: implement multiple avatar plugins per contest
  struct avatar_loaded_plugin *main_avatar_plugin;
  // FIXME: the same for content plugin
  struct content_loaded_plugin *main_content_plugin;

  // contest-specific pages
  struct ContestExternalActions *cnts_actions;
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

void
ns_for_each_contest_extra(
        void (*callback)(struct contest_extra *, void *ptr),
        void *ptr);

struct contest_extra *ns_get_contest_extra(
        const struct contest_desc *cnts,
        const struct ejudge_cfg *config);
struct contest_extra *ns_try_contest_extra(int contest_id);

void
ns_html_error(
        FILE *fout,
        struct http_request_info *phr,
        int priv_mode,
        int error_code);

void
ns_invalidate_session(
        unsigned long long session_id,
        unsigned long long client_key);

void ns_unload_contests(void);

int  ns_loop_callback(struct server_framework_state *state);
void ns_post_select_callback(struct server_framework_state *state);

unsigned char *
ns_submit_button(unsigned char *buf, size_t size,
                 const unsigned char *var_name, int action,
                 const unsigned char *label);

unsigned char *
ns_submit_button_2(
        unsigned char *buf,
        size_t size,
        const unsigned char *class_name,
        const unsigned char *var_name,
        int action,
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
ns_refresh_page_2(
        FILE *fout,
        ej_cookie_t client_key,
        const unsigned char *url);

void
ns_write_priv_all_runs(FILE *f,
                       struct http_request_info *phr,
                       const struct contest_desc *cnts,
                       struct contest_extra *extra,
                       int first_run_set, int first_run, int last_run_set, int last_run,
                       unsigned char const *filter_expr);

// clar filter options
enum
{
  CLAR_FILTER_ALL_CLARS = 1,
  CLAR_FILTER_UNANS_CLARS_COMMENTS,
  CLAR_FILTER_ALL_CLARS_COMMENTS,
  CLAR_FILTER_CLARS_TO_ALL,
  CLAR_FILTER_NONE, // show even empty entries
};

void
ns_write_all_clars(
        FILE *f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int mode_clar,
        const unsigned char *first_clar_str,
        const unsigned char *last_clar_str);

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

void
ns_priv_edit_clar_page(
        const serve_state_t cs,
        FILE *f,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int clar_id);

int
ns_priv_edit_clar_action(
        FILE *out_f,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);

void
ns_priv_edit_run_page(
        const serve_state_t cs,
        FILE *f,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int run_id);

int
ns_priv_edit_run_action(
        FILE *out_f,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);

void
ns_header(
        FILE *out,
        unsigned char const *template,
        unsigned char const *content_type,
        unsigned char const *charset,
        const unsigned char *script_part,
        const unsigned char *body_attr,
        int locale_id,
        const struct contest_desc *cnts,
        ej_cookie_t client_key,
        char const *format,
        ...)
  __attribute__((format(printf, 10, 11)));
void
ns_separator(
        FILE *out,
        unsigned char const *templ,
        const struct contest_desc *cnts);
void ns_footer(
        FILE *out,
        unsigned char const *templ,
        const unsigned char *copyright,
        int locale_id);

const unsigned char *ns_unparse_role(int role);

int
ns_write_tests(
        const serve_state_t cs,
        FILE *fout,
        FILE *log_f,
        int action,
        int run_id,
        int test_num);

int
ns_write_passwords(FILE *fout, FILE *log_f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra);
int
ns_write_online_users(FILE *fout, FILE *log_f,
                      struct http_request_info *phr,
                      const struct contest_desc *cnts,
                      struct contest_extra *extra);

int
ns_write_exam_info(FILE *fout, FILE *log_f,
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
ns_write_judging_priorities(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);
int
ns_new_run_form(FILE *fout, FILE *log_f,
                struct http_request_info *phr,
                const struct contest_desc *cnts,
                struct contest_extra *extra);

void
ns_write_priv_standings(
        const serve_state_t state,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        FILE *f,
        int accepting_mode);

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
  NS_RUNSEL_OKPR,
  NS_RUNSEL_OKPRRJ,

  NS_FILE_PATTERN_RUN = 0x1,
  NS_FILE_PATTERN_UID = 0x2,
  NS_FILE_PATTERN_LOGIN = 0x4,
  NS_FILE_PATTERN_PROB = 0x8,
  NS_FILE_PATTERN_LANG = 0x10,
  NS_FILE_PATTERN_SUFFIX = 0x20,
  NS_FILE_PATTERN_NAME = 0x40,
  NS_FILE_PATTERN_CONTEST = 0x80,
  NS_FILE_PATTERN_TIME = 0x100,
};

void
ns_download_runs(
        const struct contest_desc *cnts,
        const serve_state_t cs,
        FILE *fout,
        FILE *log_f,
        int run_selection,
        int dir_struct,
        int file_name_mask,
        int use_problem_extid,
        int use_problem_dir,
        const unsigned char *problem_dir_prefix,
        size_t run_mask_size,
        unsigned long *run_mask);

int
ns_upload_csv_runs(
        struct http_request_info *phr,
        const serve_state_t cs, FILE *log_f,
        const unsigned char *csv_text);
int
ns_upload_csv_results(
        struct http_request_info *phr,
        const serve_state_t cs,
        FILE *log_f,
        const unsigned char *csv_text,
        int add_flag);

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
        const unsigned char *table_class,
        const struct UserProblemInfo *pinfo,
        int back_action);

int
new_server_cmd_handler(FILE *fout, struct http_request_info *phr);

struct server_framework_state;
int ns_open_ul_connection(struct server_framework_state *state);

struct UserlistBinaryHeader;

int
ns_list_all_users_callback(
        void *user_data,
        int contest_id,
        unsigned char **p_xml,
        struct UserlistBinaryHeader **p_header);
void
ns_check_contest_events(
        struct contest_extra *extra,
        serve_state_t cs,
        const struct contest_desc *cnts);
void ns_contest_unload_callback(serve_state_t cs);

void ns_client_destroy_callback(struct client_state *p);

int ns_is_valid_client_id(int client_id);
void ns_client_state_clear_contest_id(int client_id);
void ns_close_client_fds(int client_id);
void ns_send_reply_2(int client_id, int answer);
void ns_new_autoclose_2(int client_id, void *write_buf, size_t write_len);

struct UserProblemInfo;
void
ns_get_user_problems_summary(
        const serve_state_t cs,
        int user_id,
        const unsigned char *user_login,
        int accepting_mode,
        time_t start_time,
        time_t stop_time,
        const ej_ip_t *ip,
        struct UserProblemInfo *pinfo); /* user problem info */

int ns_insert_variant_num(unsigned char *buf, size_t size,
                          const unsigned char *file, int variant);
void ns_register_pages(FILE *fout, struct http_request_info *phr);

unsigned char *
ns_get_checker_comment(
        const serve_state_t cs,
        int run_id,
        int need_html_armor);

int
ns_examiners_page(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);
int
ns_print_user_exam_protocol(
        const struct contest_desc *cnts,
        const serve_state_t cs,
        FILE *log_f,
        int user_id,
        int locale_id,
        int use_user_printer,
        int full_report,
        int use_cypher);
int
ns_print_user_exam_protocols(
        const struct contest_desc *cnts,
        const serve_state_t cs,
        FILE *log_f,
        int nuser,
        int *user_ids,
        int locale_id,
        int use_user_printer,
        int full_report,
        int use_cypher,
        int include_testing_report,
        int run_latex,
        int print_pdfs,
        int clear_working_directory);

int
ns_olympiad_final_user_report(
        FILE *fout,
        FILE *log_f,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int user_id,
        int locale_id);

int
ns_print_prob_exam_protocol(
        const struct contest_desc *cnts,
        const serve_state_t cs,
        FILE *log_f,
        int prob_id,
        int locale_id,
        int use_exam_cypher);

int
ns_write_user_ips(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);

int
ns_write_ip_users(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);

int
ns_write_testing_queue(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);

void
ns_set_stand_filter(
        const serve_state_t state,
        struct http_request_info *phr);

void
ns_reset_stand_filter(
        const serve_state_t state,
        struct http_request_info *phr);

int
ns_write_admin_contest_settings(
        FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra);

int
ns_submit_run(
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        const unsigned char *prob_param_name,
        const unsigned char *lang_param_name,
        int enable_ans_collect,
        int enable_path,
        int enable_uuid,
        int enable_user_id,
        int enable_status,
        int admin_mode,
        int is_hidden,
        int *p_run_id,
        int *p_mime_type,
        int *p_next_prob_id);

extern int utf8_mode;
extern time_t server_start_time;

struct UserProblemInfo;
void
new_write_user_runs(
        const serve_state_t,
        FILE *f,
        struct http_request_info *phr,
        unsigned int show_flags,
        int prob_id,
        const unsigned char *table_class,
        const struct UserProblemInfo *pinfo,
        int back_action,
        time_t start_time,
        time_t stop_time);
struct RunDisplayInfos;
struct RunDisplayInfo;
void
fill_user_run_info(
        const serve_state_t cs,
        const struct UserProblemInfo *pinfo,
        int run_id,
        const struct run_entry *pre,
        time_t start_time,
        time_t stop_time,
        int gen_strings_flag,
        struct RunDisplayInfo *ri); // out
void
filter_user_runs(
        const serve_state_t cs,
        struct http_request_info *phr,
        int prob_id,
        const struct UserProblemInfo *pinfo,
        time_t start_time,
        time_t stop_time,
        int gen_strings_flag,
        struct RunDisplayInfos *rinfo);

void
new_write_user_clars(
        const serve_state_t,
        FILE *f,
        struct http_request_info *phr,
        unsigned int show_flags,
        const unsigned char *table_class);

struct testing_report_xml;

int
write_xml_team_testing_report(
        serve_state_t state,
        const struct section_problem_data *prob,
        FILE *f,
        struct http_request_info *phr,
        int output_only,
        int is_marked,
        int token_flags,
        const struct testing_report_xml *tr,
        const unsigned char *table_class);

int
write_xml_team_accepting_report(
        FILE *f,
        struct http_request_info *phr,
        const struct testing_report_xml *tr,
        int rid,
        const struct run_entry *re,
        const struct section_problem_data *prob,
        int exam_mode,
        const unsigned char *table_class);

int
write_xml_team_tests_report(
        const serve_state_t state,
        const struct section_problem_data *prob,
        FILE *f,
        const struct testing_report_xml *r,
        const unsigned char *table_class);

int
write_xml_testing_report(
        FILE *f,
        struct http_request_info *phr,
        int user_mode,
        const struct testing_report_xml *r,
        const unsigned char *class1,
        const unsigned char *class2);

struct TestingQueueArray;
void
ns_scan_run_queue(
        serve_state_t cs,
        struct TestingQueueArray *vec);
struct super_run_status_vector;
void
ns_scan_heartbeat_dirs(
        serve_state_t cs,
        struct super_run_status_vector *vec);

int
ns_parse_run_id(
        FILE *fout,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int *p_run_id,
        struct run_entry *pe);

int
ns_parse_run_mask(
        struct http_request_info *phr,
        const unsigned char **p_size_str,
        const unsigned char **p_mask_str,
        size_t *p_size,
        unsigned long **p_mask);

void
html_role_select(
        FILE *fout,
        int role,
        int allow_admin,
        const unsigned char *var_name);

const unsigned char *
ns_get_register_url(
        unsigned char *buf,
        size_t size,
        const struct contest_desc *cnts,
        const struct http_request_info *phr);

struct UserProblemInfo;

// problem status flags
enum
{
  PROB_STATUS_VIEWABLE = 1,
  PROB_STATUS_SUBMITTABLE = 2,
  PROB_STATUS_TABABLE = 4,

  PROB_STATUS_GOOD = PROB_STATUS_VIEWABLE | PROB_STATUS_SUBMITTABLE,
};

void
html_problem_selection(
        serve_state_t cs,
        FILE *fout,
        struct http_request_info *phr,
        const struct UserProblemInfo *pinfo,
        const unsigned char *var_name,
        int light_mode,
        time_t start_time);

void
html_problem_selection_2(
        serve_state_t cs,
        FILE *fout,
        struct http_request_info *phr,
        const unsigned char *var_name,
        time_t start_time);

int
is_judged_virtual_olympiad(serve_state_t cs, int user_id);

int
get_last_language(serve_state_t cs, int user_id, int *p_last_eoln_type);

unsigned char *
get_last_source(serve_state_t cs, int user_id, int prob_id);

int
get_last_answer_select_one(serve_state_t cs, int user_id, int prob_id);

int
compute_available_tokens(
        serve_state_t cs,
        const struct section_problem_data *prob,
        time_t start_time);

void
ns_reload_server_all(void);

void
ns_reload_statement(
        int contest_id,
        int prob_id,
        int variant,
        int reload_all);

void
ns_add_review_comment(
        int contest_id,
        serve_state_t cs,
        int run_id,
        const unsigned char *review_comment);

struct ExternalActionState;
typedef struct ContestExternalActions
{
  int nref; // reference counter
  int contest_id;
  int actions_size;
  int errors_size;
  int ints_size; // internal actions
  struct ExternalActionState **priv_actions;
  struct ExternalActionState **priv_errors;
  struct ExternalActionState **unpriv_actions;
  struct ExternalActionState **unpriv_errors;
  struct ExternalActionState **reg_actions;
  struct ExternalActionState **reg_errors;
  struct ExternalActionState **int_actions; // internal actions
} ContestExternalActions;

struct ContestExternalActions *
ns_get_contest_external_actions(
        int contest_id,
        time_t current_time);

int
ns_int_external_action(
        struct http_request_info *phr,
        int action);

void
ns_write_public_log(
        struct http_request_info *phr,
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        FILE *f,
        char const *header_str,
        char const *footer_str,
        int user_mode);

void
ns_write_standings(
        struct http_request_info *phr,
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        FILE *f,
        const unsigned char *stand_dir,
        const unsigned char *file_name,
        const unsigned char *file_name2,
        int users_on_page,
        int page_index,
        int client_flag,
        int only_table_flag,
        int user_id,
        const unsigned char *header_str,
        const unsigned char *footer_str,
        int accepting_mode,
        const unsigned char *user_name,
        int force_fancy_style,
        int charset_id,
        struct user_filter_info *user_filter,
        int user_mode,
        time_t cur_time,
        int compat_mode);
void
write_json_run_info(
        FILE *fout,
        const serve_state_t cs,
        const struct http_request_info *phr,
        int run_id,
        const struct run_entry *pre,
        time_t start_time,
        time_t stop_time,
        int accepting_mode);
const unsigned char *
write_json_content(
        FILE *fout,
        const unsigned char *data,
        size_t size,
        const unsigned char *sep,
        const unsigned char *indent);

int
ns_ws_check_session(
        struct server_framework_state *state,
        struct ws_client_state *p,
        unsigned long long sid_1,
        unsigned long long sid_2);

int
ns_ws_create_session(
        struct server_framework_state *state,
        struct ws_client_state *p);

int
ns_load_problem_uuid(
        FILE *log_f,
        const struct section_global_data *global,
        const struct section_problem_data *prob,
        int variant);

void
ns_get_accepted_set(
        serve_state_t cs,
        int user_id,
        unsigned char *acc_set);

#endif /* __NEW_SERVER_H__ */
