/* -*- c -*- */
/* $Id$ */
#ifndef __SERVE_STATE_H__
#define __SERVE_STATE_H__

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

#include "settings.h"
#include "ej_types.h"
#include "opcaps.h"
#include "watched_file.h"
#include "problem_plugin.h"

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

struct user_filter_info
{
  struct user_filter_info *next;

  ej_cookie_t session_id;
  int prev_first_run;
  int prev_last_run;
  int prev_first_clar;
  int prev_last_clar;
  int prev_mode_clar;           /* 1 - view all, 2 - view unanswered */
  unsigned char *prev_filter_expr;
  struct filter_tree *prev_tree;
  struct filter_tree_mem *tree_mem;
  unsigned char *error_msgs;
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
  time_t time;
  int type;
  int user_id;
  serve_event_hander_t handler;
};

struct serve_state
{
  unsigned char *config_path;

  /* serve.cfg parsed config */
  struct generic_section_config *config;
  struct section_global_data    *global;

  struct section_language_data *langs[MAX_LANGUAGE + 1];
  struct section_problem_data  *probs[MAX_PROBLEM + 1];
  struct section_tester_data   *testers[MAX_TESTER + 1];

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
  struct section_problem_data  *abstr_probs[MAX_PROBLEM + 1];
  struct section_tester_data   *abstr_testers[MAX_TESTER + 1];
  int max_abstr_prob;
  int max_abstr_tester;

  time_t current_time;
  int clients_suspended;
  int testing_suspended;
  int printing_suspended;
  int accepting_mode;
  int testing_finished;
  int standings_updated;

  // upsolving mode
  int upsolving_mode;
  int freeze_standings;
  int view_source;
  int view_protocol;
  int full_protocol;
  int disable_clars;

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

  // for full import
  int saved_testing_suspended;
  int client_id;
  unsigned char *pending_xml_import;
  void (*destroy_callback)(struct serve_state *cs);
};
typedef struct serve_state *serve_state_t;

/* extra data, which is passed through compilation phase */
struct compile_run_extra
{
  int accepting_mode;
  int priority_adjustment;
};

serve_state_t serve_state_init(void);
serve_state_t serve_state_destroy(serve_state_t state,
                                  const struct contest_desc *cnts,
                                  struct userlist_clnt *ul_conn);

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

int serve_check_user_quota(serve_state_t, int user_id, size_t size);
int serve_check_clar_quota(serve_state_t, int user_id, size_t size);

int serve_check_cnts_caps(serve_state_t state, const struct contest_desc *,
                          int user_id, int bit);
int serve_get_cnts_caps(serve_state_t state, const struct contest_desc *,
                        int user_id, opcap_t *out_caps);

void serve_build_compile_dirs(serve_state_t state);
void serve_build_run_dirs(serve_state_t state);

int serve_create_symlinks(serve_state_t state);

const unsigned char *serve_get_email_sender(const struct contest_desc *cnts);
void serve_check_stat_generation(serve_state_t state,
                                 const struct contest_desc *cnts,
                                 int force_flag);

int serve_state_load_contest(int contest_id,
                             struct userlist_clnt *ul_conn,
                             struct teamdb_db_callbacks *teamdb_callbacks,
                             serve_state_t *p_state,
                             const struct contest_desc **p_cnts);

int serve_count_unread_clars(const serve_state_t state, int user_id,
                             time_t start_time);

struct user_filter_info *
user_filter_info_allocate(serve_state_t state, int user_id,
                          ej_cookie_t session_id);

void serve_move_files_to_insert_run(serve_state_t state, int run_id);

void serve_audit_log(serve_state_t, int, int,
                     ej_ip_t, int, const char *, ...)
  __attribute__((format(printf, 6, 7)));

void serve_packet_name(int run_id, int prio, unsigned char buf[]);

int serve_compile_request(serve_state_t state,
                          unsigned char const *str, int len,
                          int run_id, int lang_id, int locale_id,
                          int output_only,
                          unsigned char const *sfx,
                          char **compiler_env,
                          int accepting_mode,
                          int priority_adjustment,
                          const struct section_problem_data *prob,
                          const struct section_language_data *lang);

struct compile_reply_packet;
int
serve_run_request(serve_state_t state,
                  FILE *errf,
                  const unsigned char *run_text,
                  size_t run_size,
                  int run_id,
                  int user_id,
                  int prob_id,
                  int lang_id,
                  int variant,
                  int priority_adjustment,
                  int judge_id,
                  int accepting_mode,
                  const unsigned char *compile_report_dir,
                  const struct compile_reply_packet *comp_pkt);

int serve_is_valid_status(serve_state_t state, int status, int mode);

void serve_send_clar_notify_email(serve_state_t state,
                                  const struct contest_desc *cnts,
                                  int user_id, const unsigned char *user_name,
                                  const unsigned char *subject,
                                  const unsigned char *text);
void
serve_send_check_failed_email(const struct contest_desc *cnts, int run_id);

void
serve_rejudge_run(const struct contest_desc *, serve_state_t state,
                  int run_id, int user_id, ej_ip_t ip, int ssl_flag,
                  int force_full_rejudge, int priority_adjustment);
void
serve_rejudge_by_mask(const struct contest_desc *, serve_state_t state,
                      int user_id, ej_ip_t ip, int ssl_flag,
                      int mask_size, unsigned long *mask,
                      int force_flag, int priority_adjustment);

void
serve_rejudge_problem(const struct contest_desc *cnst, serve_state_t state,
                      int user_id, ej_ip_t ip, int ssl_flag,
                      int prob_id);

void
serve_judge_suspended(const struct contest_desc *cnts, serve_state_t state,
                      int user_id, ej_ip_t ip, int ssl_flag);

void
serve_rejudge_all(const struct contest_desc *cnts, serve_state_t state,
                  int user_id, ej_ip_t ip, int ssl_flag);

int
serve_read_compile_packet(serve_state_t state,
                          const struct contest_desc *cnts,
                          const unsigned char *compile_status_dir,
                          const unsigned char *compile_report_dir,
                          const unsigned char *pname);
int
serve_read_run_packet(serve_state_t state,
                      const struct contest_desc *cnts,
                      const unsigned char *run_status_dir,
                      const unsigned char *run_report_dir,
                      const unsigned char *run_full_archive_dir,
                      const unsigned char *pname);

struct run_entry;
struct problem_desc;
void
serve_judge_built_in_problem(
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
        ej_ip_t ip,
        int ssl_flag);

void serve_invoke_start_script(serve_state_t state);

void serve_send_run_quit(const serve_state_t state);
void serve_reset_contest(serve_state_t state);
void serve_squeeze_runs(serve_state_t state);
int serve_count_transient_runs(serve_state_t state);

void serve_event_add(serve_state_t state, time_t time, int type, int user_id,
                     serve_event_hander_t);
void serve_event_remove(serve_state_t state, struct serve_event_queue *event);
void serve_event_destroy_queue(serve_state_t state);
int serve_event_remove_matching(serve_state_t state, time_t time, int type,
                                int user_id);

int serve_collect_virtual_stop_events(serve_state_t cs);
void serve_handle_events(const struct contest_desc *cnts, serve_state_t cs);
void serve_judge_virtual_olympiad(const struct contest_desc *,
                                  serve_state_t cs, int user_id, int run_id);

void serve_clear_by_mask(serve_state_t state,
                         int user_id, ej_ip_t ip, int ssl_flag,
                         int mask_size, unsigned long *mask);
void serve_ignore_by_mask(serve_state_t state,
                          int user_id, ej_ip_t ip, int ssl_flag,
                          int mask_size, unsigned long *mask,
                          int new_status);

#endif /* __SERVE_STATE_H__ */
