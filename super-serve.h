/* -*- c -*- */
/* $Id$ */
#ifndef __SUPER_SERVE_H__
#define __SUPER_SERVE_H__

/* Copyright (C) 2004-2008 Alexander Chernov <cher@ejudge.ru> */

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

#include "opcaps.h"

#include <time.h>

#ifndef META_ATTRIB
#if defined __RCC__
#undef __attribute__
#define META_ATTRIB(x) __attribute__(x)
#else
#define META_ATTRIB(x)
#endif /* __RCC__ */
#endif /* META_ATTRIB */

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
  int user_id;
  unsigned char *user_login;
  unsigned char *user_name;

  ejintbool_t advanced_view;
  ejintbool_t show_html_attrs;
  ejintbool_t show_html_headers;
  ejintbool_t show_paths;
  ejintbool_t show_access_rules;
  ejintbool_t show_permissions;
  ejintbool_t show_form_fields;
  ejintbool_t show_notifications;

  unsigned char *users_header_text;
  unsigned char *users_footer_text;
  unsigned char *register_header_text;
  unsigned char *register_footer_text;
  unsigned char *team_header_text;
  unsigned char *team_menu_1_text;
  unsigned char *team_menu_2_text;
  unsigned char *team_menu_3_text;
  unsigned char *team_separator_text;
  unsigned char *team_footer_text;
  unsigned char *priv_header_text;
  unsigned char *priv_footer_text;
  unsigned char *register_email_text;
  unsigned char *copyright_text;
  unsigned char *welcome_text;
  unsigned char *reg_welcome_text;

  ejintbool_t users_header_loaded;
  ejintbool_t users_footer_loaded;
  ejintbool_t register_header_loaded;
  ejintbool_t register_footer_loaded;
  ejintbool_t team_header_loaded;
  ejintbool_t team_menu_1_loaded;
  ejintbool_t team_menu_2_loaded;
  ejintbool_t team_menu_3_loaded;
  ejintbool_t team_separator_loaded;
  ejintbool_t team_footer_loaded;
  ejintbool_t priv_header_loaded;
  ejintbool_t priv_footer_loaded;
  ejintbool_t register_email_loaded;
  ejintbool_t copyright_loaded;
  ejintbool_t welcome_loaded;
  ejintbool_t reg_welcome_loaded;

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

  ejintbool_t show_global_1;
  ejintbool_t show_global_2;
  ejintbool_t show_global_3;
  ejintbool_t show_global_4;
  ejintbool_t show_global_5;
  ejintbool_t show_global_6;
  ejintbool_t show_global_7;
  ejintbool_t enable_stand2;
  ejintbool_t enable_plog;
  ejintbool_t enable_extra_col;
  ejintbool_t disable_compilation_server;

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

  unsigned char *compile_home_dir;
};

struct sid_state;
struct super_http_request_info
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

  const struct ejudge_cfg *config;
  struct sid_state *ss;

  int opcode;

  // the URL
  ej_ip_t ip;
  int ssl_flag;
  const unsigned char *self_url; // points into stack buffer
  const unsigned char *script_name; // points into stack buffer
  const unsigned char *system_login;

  unsigned long long session_id;

  // authentification info
  int user_id;
  int priv_level;
  opcap_t caps;
  unsigned char *login;
  unsigned char *name;
  unsigned char *html_login;
  unsigned char *html_name;

  int contest_id;

  // should we use json for reply?
  int json_reply;
};

void super_serve_clear_edited_contest(struct sid_state *sstate);
void super_serve_move_edited_contest(struct sid_state *dst,
                                     struct sid_state *src);
int super_serve_start_serve_test_mode(const struct contest_desc *cnts,
                                      unsigned char **p_log,
                                      int pass_socket);

int super_serve_sid_state_get_max_edited_cnts(void);
const struct sid_state* super_serve_sid_state_get_cnts_editor(int contest_id);
struct sid_state* super_serve_sid_state_get_cnts_editor_nc(int contest_id);

#endif /* __SUPER_SERVE_H__ */
