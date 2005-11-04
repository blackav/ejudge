/* -*- c -*- */
/* $Id$ */
#ifndef __SUPER_SERVE_H__
#define __SUPER_SERVE_H__

/* Copyright (C) 2004,2005 Alexander Chernov <cher@ispras.ru> */

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

#include <time.h>

struct contest_extra
{
  int id;
  unsigned char serve_used;
  unsigned char run_used;
  unsigned char dnotify_flag;
  unsigned char serve_suspended;
  unsigned char run_suspended;

  int serve_pid;
  int run_pid;
  int socket_fd;
  int run_dir_fd;
  int serve_uid;
  int serve_gid;
  int run_uid;
  int run_gid;

  unsigned char *root_dir;
  unsigned char *conf_file;
  unsigned char *var_dir;

  unsigned char *socket_path;
  unsigned char *log_file;
  unsigned char *run_queue_dir;
  unsigned char *run_log_file;
  unsigned char *messages;

  time_t serve_last_start;
  time_t serve_suspend_end;
  time_t run_last_start;
  time_t run_suspend_end;
  time_t last_forced_check;
};

struct contest_extra *get_contest_extra(int num);
struct contest_extra *get_existing_contest_extra(int num);

enum
{
  SID_STATE_SHOW_HIDDEN = 1,
  SID_STATE_SHOW_CLOSED = 2,
  SID_STATE_SHOW_UNMNG = 4,
};

struct contest_desc;
struct section_global_data;
struct section_language_data;
struct section_problem_data;
struct section_tester_data;

struct sid_state
{
  struct sid_state *next;
  struct sid_state *prev;
  ej_cookie_t sid;
  time_t init_time;
  unsigned long flags;
  struct contest_desc *edited_cnts;
  int advanced_view;
  int show_html_attrs;
  int show_html_headers;
  int show_paths;
  int show_access_rules;
  int show_permissions;
  int show_form_fields;

  unsigned char *users_header_text;
  unsigned char *users_footer_text;
  unsigned char *register_header_text;
  unsigned char *register_footer_text;
  unsigned char *team_header_text;
  unsigned char *team_footer_text;
  unsigned char *register_email_text;

  unsigned char *serve_parse_errors;

  struct generic_section_config *cfg;
  struct section_global_data *global;
  int lang_a;
  struct section_language_data **langs;
  int *loc_cs_map;              /* map from local ids to compile ids */
  int *cs_loc_map;              /* reverse map */
  unsigned char **lang_opts;
  int *lang_flags;

  /* abstract problems */
  int aprob_u;
  int aprob_a;
  struct section_problem_data **aprobs;
  int *aprob_flags;

  /* concrete problems */
  int prob_a;
  struct section_problem_data **probs;
  int *prob_flags;

  int atester_total;
  struct section_tester_data **atesters;

  int tester_total;
  struct section_tester_data **testers;

  int show_global_1;
  int show_global_2;
  int show_global_3;
  int show_global_4;
  int show_global_5;
  int show_global_6;
  int show_global_7;
  int enable_stand2;
  int enable_plog;
  int enable_extra_col;
  int disable_compilation_server;

  int cs_langs_loaded;
  int cs_lang_total;
  struct generic_section_config *cs_cfg;
  struct section_language_data **cs_langs;
  unsigned char **cs_lang_names;

  unsigned char *contest_start_cmd_text;
  unsigned char *stand_header_text;
  unsigned char *stand_footer_text;
  unsigned char *stand2_header_text;
  unsigned char *stand2_footer_text;
  unsigned char *plog_header_text;
  unsigned char *plog_footer_text;

  unsigned char *var_header_text;
  unsigned char *var_footer_text;
};

void super_serve_clear_edited_contest(struct sid_state *sstate);
int super_serve_start_serve_test_mode(struct contest_desc *cnts, unsigned char **p_log,
                                      int pass_socket);

#endif /* __SUPER_SERVE_H__ */
