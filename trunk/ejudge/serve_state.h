/* -*- c -*- */
/* $Id$ */
#ifndef __SERVE_STATE_H__
#define __SERVE_STATE_H__

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

#include "settings.h"
#include "ej_types.h"
#include "opcaps.h"
#include "watched_file.h"

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

  const struct contest_desc *cur_contest;

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
  time_t contest_start_time;
  time_t contest_sched_time;
  time_t contest_duration;
  time_t contest_stop_time;
  int clients_suspended;
  int testing_suspended;
  int printing_suspended;
  int olympiad_judging_mode;
  int accepting_mode;
  int standings_updated;

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
};
typedef struct serve_state *serve_state_t;

serve_state_t serve_state_init(void);
serve_state_t serve_state_destroy(serve_state_t state);

void serve_state_set_config_path(serve_state_t state, const unsigned char *);

void serve_update_standings_file(serve_state_t state, int force_flag);
void serve_update_public_log_file(serve_state_t state);
void serve_update_external_xml_log(serve_state_t state);
void serve_update_internal_xml_log(serve_state_t state);
int  serve_update_status_file(serve_state_t state, int force_flag);
void serve_load_status_file(serve_state_t state);

int serve_check_user_quota(serve_state_t, int user_id, size_t size);
int serve_check_clar_qouta(serve_state_t, int user_id, size_t size);

int serve_check_cnts_caps(serve_state_t state, int user_id, int bit);
int serve_get_cnts_caps(serve_state_t state, int user_id, opcap_t *out_caps);

void serve_build_compile_dirs(serve_state_t state);
void serve_build_run_dirs(serve_state_t state);

int serve_create_symlinks(serve_state_t state);

const unsigned char *serve_get_email_sender(const struct contest_desc *cnts);
void serve_check_stat_generation(serve_state_t state, int force_flag);

int serve_state_load_contest(int contest_id,
                             struct userlist_clnt *ul_conn,
                             struct teamdb_db_callbacks *teamdb_callbacks,
                             serve_state_t *p_state);

int serve_count_unread_clars(const serve_state_t state, int user_id,
                             time_t start_time);

#endif /* __SERVE_STATE_H__ */
