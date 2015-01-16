/* -*- c -*- */
#ifndef __SERVE_STATE_H__
#define __SERVE_STATE_H__

/* Copyright (C) 2006-2015 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/opcaps.h"
#include "ejudge/watched_file.h"
#include "ejudge/problem_plugin.h"
#include "ejudge/contest_plugin.h"

#include <time.h>

struct generic_section_config;
struct section_global_data;
struct section_language_data;
struct section_problem_data;
struct section_tester_data;
struct contest_desc;
struct clarlog_state;
struct teamdb_state;
struct team_extra_state;
struct user_state_info;
struct user_filter_info;
struct teamdb_db_callbacks;
struct userlist_clnt;
struct ejudge_cfg;

/* error codes */
enum
{
  SERVE_ERR_GENERIC = 1,
  SERVE_ERR_SRC_HEADER,
  SERVE_ERR_SRC_FOOTER,
  SERVE_ERR_COMPILE_PACKET_WRITE,
  SERVE_ERR_SOURCE_READ,
  SERVE_ERR_SOURCE_WRITE,
  SERVE_ERR_DB,

  SERVE_ERR_LAST,
};

struct user_filter_info
{
  struct user_filter_info *next;

  ej_cookie_t session_id;
  int prev_first_run_set;
  int prev_first_run;
  int prev_last_run_set;
  int prev_last_run;
  int prev_first_clar;
  int prev_last_clar;
  int prev_mode_clar;           /* 1 - view all, 2 - view unanswered */
  unsigned char *prev_filter_expr;
  struct filter_tree *prev_tree;
  struct filter_tree_mem *tree_mem;
  unsigned char *error_msgs;

  int run_fields;

  /* standings filter */
  unsigned char *stand_user_expr;
  struct filter_tree *stand_user_tree;
  unsigned char *stand_prob_expr;
  struct filter_tree *stand_prob_tree;
  unsigned char *stand_run_expr;
  struct filter_tree *stand_run_tree;
  struct filter_tree_mem *stand_mem;
  unsigned char *stand_error_msgs;
};

struct user_state_info
{
  struct user_filter_info *first_filter;
};

struct compile_dir_item
{
  unsigned char *status_dir;
  unsigned char *report_dir;
};
struct run_dir_item
{
  unsigned char *status_dir;
  unsigned char *report_dir;
  unsigned char *team_report_dir;
  unsigned char *full_report_dir;
};

struct problem_extra_info
{
  struct watched_file stmt;
  struct watched_file *v_stmts;
  // alternative selection
  struct watched_file alt;
  struct watched_file *v_alts;

  // problem plugins
  int plugin_error;
  struct problem_plugin_iface *plugin;
  void *plugin_data;
};

enum
{
  SERVE_EVENT_VIRTUAL_STOP = 1,
  SERVE_EVENT_JUDGE_OLYMPIAD,

  SERVE_EVENT_LAST,
};

struct serve_state;
struct serve_event_queue;
typedef void (*serve_event_hander_t)(
        const struct contest_desc *cnts,
        struct serve_state *cs,
        struct serve_event_queue *p);

struct serve_event_queue
{
  struct serve_event_queue *next, *prev;
  time_t time;                  /* the time for queue ordering */
  int type;
  int user_id;
  serve_event_hander_t handler;
  time_t real_time;             /* the actual event time */
};

/** memoized user results for use in filter expressions */
struct serve_user_results
{
  int total_score;
};

/** user group information */
struct serve_user_group
{
  int group_id;
  unsigned char *group_name;
  unsigned char *description;
  int serial;
  int member_count;
  int *members;
};

struct serve_group_member
{
  int user_id;
  unsigned int *group_bitmap;
};

#define EJ_SERVE_STATE_TOTAL_PROBS 28

struct serve_state
{
  unsigned char *config_path;

  int contest_id;
  time_t last_timestamp;
  time_t last_check_time;

  /* serve.cfg parsed config */
  struct generic_section_config *config;
  struct section_global_data    *global;

  struct section_language_data **langs;
  struct section_problem_data  **probs;
  struct section_tester_data   **testers;

  int max_lang;
  int max_prob;
  int max_tester;

  /* clarlog internal state */
  struct clarlog_state *clarlog_state;

  /* teamdb internal state */
  struct teamdb_state *teamdb_state;

  /* team_extra internal state */
  struct team_extra_state *team_extra_state;

  /* runlog internal state */
  struct runlog_state *runlog_state;

  /* for master_html to store the filter expressions */
  int users_a;
  struct user_state_info **users;
  struct user_filter_info *cur_user;

  /* for prepare to store the abstract entities */
  struct section_problem_data **abstr_probs;
  struct section_tester_data **abstr_testers;
  int max_abstr_prob;
  int max_abstr_tester;

  /* user groups */
  int user_group_count;         /* the total number of the loaded groups */
  int user_group_map_size;      /* the size of the map */
  struct serve_user_group *user_groups;
  int *user_group_map;

  int group_member_count;
  int group_member_map_size;
  struct serve_group_member *group_members;
  int *group_member_map;

  time_t load_time;
  time_t current_time;
  int clients_suspended;
  int testing_suspended;
  int printing_suspended;
  int accepting_mode;
  int testing_finished;
  int standings_updated;
  int has_olympiad_mode;

  // upsolving mode
  int upsolving_mode;
  int upsolving_freeze_standings;
  int upsolving_view_source;
  int upsolving_view_protocol;
  int upsolving_full_protocol;
  int upsolving_disable_clars;

  /**
     Enable source view for the participants.
     Overrides team_enable_src_view if set.
     0 - undefined, -1 - disabled, 1 - enabled.
   */
  int online_view_source;
  /**
     Enable report view for the participants.
     Overrides team_enable_rep_view if set.
     0 - undefined, -1 - disabled, 1 - enabled.
   */
  int online_view_report;
  /**
     Show the main (judge) scores to the participants.
     Works for contests with separate_user_score mode set.
     0 - no, 1 - yes.
   */
  int online_view_judge_score;
  /**
     Use the final visibility rules for the tests.
     The final visibility rules are specified by final_open_tests
     problem configuration variable.
     0 - no, 1 - yes.
   */
  int online_final_visibility;

  time_t stat_last_check_time;
  time_t stat_reported_before;
  time_t stat_report_time;

  time_t last_update_public_log;
  time_t last_update_external_xml_log;
  time_t last_update_internal_xml_log;
  time_t last_update_status_file;

  struct compile_dir_item *compile_dirs;
  int compile_dirs_u, compile_dirs_a;

  struct run_dir_item *run_dirs;
  int run_dirs_u, run_dirs_a;

  struct problem_extra_info *prob_extras;
  unsigned short compile_request_id;

  struct watched_file description;

  struct serve_event_queue *event_first, *event_last;

  time_t max_online_time;
  int max_online_count;

  struct contest_plugin_iface *contest_plugin;
  void *contest_plugin_data;

  // for full import
  int saved_testing_suspended;
  int client_id;
  unsigned char *pending_xml_import;
  void (*destroy_callback)(struct serve_state *cs);

  // problem priorities
  signed char prob_prio[EJ_SERVE_STATE_TOTAL_PROBS];

  // memoized user results
  int user_result_a; // allocated size
  struct serve_user_results *user_results;
};
typedef struct serve_state *serve_state_t;

/* extra data, which is passed through compilation phase */
struct compile_run_extra
{
  int accepting_mode;
  int priority_adjustment;
  int notify_flag;
  int is_dos;
  int rejudge_flag;
};

serve_state_t serve_state_init(int contest_id);
serve_state_t serve_state_destroy(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        struct userlist_clnt *ul_conn);
void
serve_state_destroy_stand_expr(struct user_filter_info *u);

void serve_state_set_config_path(serve_state_t state, const unsigned char *);

void serve_update_standings_file(serve_state_t state,
                                 const struct contest_desc *cnts,
                                 int force_flag);
void serve_update_public_log_file(serve_state_t state,
                                  const struct contest_desc *cnts);
void serve_update_external_xml_log(serve_state_t state,
                                   const struct contest_desc *cnts);
void serve_update_internal_xml_log(serve_state_t state,
                                   const struct contest_desc *cnts);
int  serve_update_status_file(serve_state_t state, int force_flag);
void serve_load_status_file(serve_state_t state);
void serve_remove_status_file(serve_state_t state);

int serve_check_user_quota(serve_state_t, int user_id, size_t size);
int serve_check_clar_quota(serve_state_t, int user_id, size_t size);

int serve_check_cnts_caps(serve_state_t state, const struct contest_desc *,
                          int user_id, int bit);
int serve_get_cnts_caps(serve_state_t state, const struct contest_desc *,
                        int user_id, opcap_t *out_caps);

void serve_build_compile_dirs(serve_state_t state);
void serve_build_run_dirs(serve_state_t state, int contest_id);

int serve_create_symlinks(serve_state_t state);

const unsigned char *serve_get_email_sender(const struct ejudge_cfg *config,
                                            const struct contest_desc *cnts);
void serve_check_stat_generation(const struct ejudge_cfg *config,
                                 serve_state_t state,
                                 const struct contest_desc *cnts,
                                 int force_flag, int utf8_mode);

struct ejudge_cfg;
int
serve_state_load_contest_config(
        const struct ejudge_cfg *config,
        int contest_id,
        const struct contest_desc *cnts,
        serve_state_t *p_state);
int serve_state_load_contest(
        const struct ejudge_cfg *,
        int contest_id,
        struct userlist_clnt *ul_conn,
        struct teamdb_db_callbacks *teamdb_callbacks,
        serve_state_t *p_state,
        const struct contest_desc **p_cnts,
        int no_users_flag);

int serve_count_unread_clars(const serve_state_t state, int user_id,
                             time_t start_time);

struct user_filter_info *
user_filter_info_allocate(serve_state_t state, int user_id,
                          ej_cookie_t session_id);

void serve_move_files_to_insert_run(serve_state_t state, int run_id);

struct run_entry;
void
serve_audit_log(
        serve_state_t state,
        int run_id,
        const struct run_entry *re,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        const unsigned char *command,
        const unsigned char *status,
        int run_status,
        const char *format,
        ...)
  __attribute__((format(printf, 10, 11)));

int
serve_compile_request(
        serve_state_t state,
        unsigned char const *str,
        int len,
        int contest_id,
        int run_id,
        int user_id,
        int lang_id,
        int variant,
        int locale_id,
        int output_only,
        unsigned char const *sfx,
        char **compiler_env,
        int style_check_only,
        const unsigned char *style_checker_cmd,
        char **style_checker_env,
        int accepting_mode,
        int priority_adjustment,
        int notify_flag,
        const struct section_problem_data *prob,
        const struct section_language_data *lang,
        int no_db_flag,
        const ej_uuid_t *puuid,
        int store_flags,
        int rejudge_flag)
#if defined __GNUC__
  __attribute__((warn_unused_result))
#endif
;

struct compile_reply_packet;
int
serve_run_request(
        serve_state_t state,
        const struct contest_desc *cnts,
        FILE *errf,
        const unsigned char *run_text,
        size_t run_size,
        int contest_id,
        int run_id,
        int user_id,
        int prob_id,
        int lang_id,
        int variant,
        int priority_adjustment,
        int judge_id,
        int accepting_mode,
        int notify_flag,
        int mime_type,
        int eoln_type,
        int locale_id,
        const unsigned char *compile_report_dir,
        const struct compile_reply_packet *comp_pkt,
        int no_db_flag,
        ej_uuid_t *puuid,
        int rejudge_flag);

int serve_is_valid_status(serve_state_t state, int status, int mode);

void serve_send_clar_notify_email(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        int user_id,
        const unsigned char *user_name,
        const unsigned char *subject,
        const unsigned char *text);
void
serve_send_check_failed_email(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        int run_id);

void
serve_rejudge_run(
        const struct ejudge_cfg *config,
        const struct contest_desc *,
        serve_state_t state,
        int run_id,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int force_full_rejudge,
        int priority_adjustment);

struct server_framework_job;
struct server_framework_job *
serve_rejudge_by_mask(
        const struct ejudge_cfg *config,
        const struct contest_desc *,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int mask_size,
        unsigned long *mask,
        int force_flag,
        int priority_adjustment,
        int create_job_flag);

void
serve_mark_by_mask(
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int mask_size,
        unsigned long *mask,
        int mark_value);

void
serve_tokenize_by_mask(
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int mask_size,
        unsigned long *mask,
        int token_count,
        int token_flags);

struct server_framework_job *
serve_rejudge_problem(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnst,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int prob_id,
        int priority_adjustment,
        int create_job_flag);

struct server_framework_job *
serve_judge_suspended(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int priority_adjustment,
        int create_job_flag);

struct server_framework_job *
serve_rejudge_all(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag,
        int priority_adjustment,
        int create_job_flag);

int
serve_read_compile_packet(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        const unsigned char *compile_status_dir,
        const unsigned char *compile_report_dir,
        const unsigned char *pname);
int
serve_read_run_packet(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        const unsigned char *run_status_dir,
        const unsigned char *run_report_dir,
        const unsigned char *run_full_archive_dir,
        const unsigned char *pname);

struct run_entry;
struct problem_desc;
void
serve_judge_built_in_problem(
        const struct ejudge_cfg *config,
        serve_state_t state,
        const struct contest_desc *cnts,
        int run_id,
        int judge_id,
        int variant,
        int accepting_mode,
        struct run_entry *re,
        const struct section_problem_data *prob,
        struct problem_desc *px,
        int user_id,
        const ej_ip_t *ip,
        int ssl_flag);

void serve_invoke_start_script(serve_state_t state);
void serve_invoke_stop_script(serve_state_t state);

void serve_reset_contest(const struct contest_desc *, serve_state_t state);
void serve_squeeze_runs(serve_state_t state);
int serve_count_transient_runs(serve_state_t state);

void serve_event_add(serve_state_t state, time_t time, int type, int user_id,
                     serve_event_hander_t);
void serve_event_remove(serve_state_t state, struct serve_event_queue *event);
void serve_event_destroy_queue(serve_state_t state);
int serve_event_remove_matching(serve_state_t state, time_t time, int type,
                                int user_id);

int serve_collect_virtual_stop_events(serve_state_t cs);
void serve_handle_events(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t cs);
void serve_judge_virtual_olympiad(
        const struct ejudge_cfg *config,
        const struct contest_desc *,
        serve_state_t cs,
        int user_id,
        int run_id,
        int priority_adjustment);

void serve_clear_by_mask(serve_state_t state,
                         int user_id, const ej_ip_t *ip, int ssl_flag,
                         int mask_size, unsigned long *mask);
void serve_ignore_by_mask(serve_state_t state,
                          int user_id, const ej_ip_t *ip, int ssl_flag,
                          int mask_size, unsigned long *mask,
                          int new_status);
void
serve_send_email_to_user(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int user_id,
        const unsigned char *subject,
        const unsigned char *text);

void
serve_notify_user_run_status_change(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int user_id,
        int run_id,
        int new_status);

void
serve_store_user_result(
        serve_state_t state,
        int user_id,
        int score);
int
serve_get_user_result_score(
        serve_state_t state,
        int user_id);

int
serve_testing_queue_delete(
        const struct contest_desc *cnts, 
        serve_state_t state,
        const unsigned char *packet,
        const unsigned char *user_login);
int
serve_testing_queue_change_priority(
        const struct contest_desc *cnts,
        const serve_state_t state,
        const unsigned char *packet_name,
        int adjustment,
        const unsigned char *user_login);

int
serve_testing_queue_delete_all(
        const struct contest_desc *cnts, 
        serve_state_t state,
        const unsigned char *user_login);

int
serve_testing_queue_change_priority_all(
        const struct contest_desc *cnts,
        const serve_state_t state,
        int adjustment,
        const unsigned char *user_login);

extern const size_t serve_struct_sizes_array[];
extern const size_t serve_struct_sizes_array_size;
extern const size_t serve_struct_sizes_array_num;

int
serve_is_problem_started(
        const serve_state_t state,
        int user_id,
        const struct section_problem_data *prob);
int
serve_is_problem_deadlined(
        const serve_state_t state,
        int user_id,
        const unsigned char *user_login,
        const struct section_problem_data *prob,
        time_t *p_deadline);
int
serve_is_problem_started_2(
        const serve_state_t state,
        int user_id,
        int prob_id);
int
serve_is_problem_deadlined_2(
        const serve_state_t state,
        int user_id,
        const unsigned char *user_login,
        int prob_id,
        time_t *p_deadline);

const unsigned char *serve_err_str(int serve_err);

void
serve_report_check_failed(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        serve_state_t state,
        int run_id,
        const unsigned char *error_text);

int
serve_make_source_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re);
int
serve_make_xml_report_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re);
int
serve_make_report_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re);
int
serve_make_team_report_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re);
int
serve_make_full_report_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re);
int
serve_make_audit_read_path(
        const serve_state_t state,
        unsigned char *path,
        size_t size,
        const struct run_entry *re);

#endif /* __SERVE_STATE_H__ */
