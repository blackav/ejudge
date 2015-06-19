/* -*- c -*- */
#ifndef __SUPER_SERVE_H__
#define __SUPER_SERVE_H__

/* Copyright (C) 2004-2015 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/bitset.h"
#include "ejudge/http_request.h"

#include <time.h>

#ifndef META_ATTRIB
#if defined __RCC__
#undef __attribute__
#define META_ATTRIB(x) __attribute__(x)
#else
#define META_ATTRIB(x)
#endif /* __RCC__ */
#endif /* META_ATTRIB */

struct ss_contest_extra
{
  int id;
  unsigned char run_used;
  unsigned char dnotify_flag;
  unsigned char run_suspended;

  int run_pid;
  int run_uid;
  int run_gid;
  int run_wd;                   // inotify watch descriptor

  unsigned char *root_dir;
  unsigned char *conf_file;
  unsigned char *var_dir;

  unsigned char *run_queue_dir;
  unsigned char *run_log_file;
  unsigned char *messages;

  time_t run_last_start;
  time_t run_suspend_end;
  time_t last_forced_check;
};

struct ss_contest_extra *get_contest_extra(int num);
struct ss_contest_extra *get_existing_contest_extra(int num);

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
struct serve_state;

struct update_state
{
  time_t start_time;
  int create_mode;
  int contest_mode;
  int contest_id;
  unsigned char *working_dir;
  unsigned char *conf_file;
  unsigned char *log_file;
  unsigned char *status_file;
  unsigned char *pid_file;
};

/* sizeof(struct sid_state) == 500 */
struct sid_state
{
  struct sid_state *next;
  struct sid_state *prev;
  ej_cookie_t sid;
  ej_ip_t remote_addr;
  time_t init_time;
  unsigned long flags;
  struct contest_desc *edited_cnts;
  int user_id;
  unsigned char *user_login;
  unsigned char *user_name;
  int edit_page;

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
  unsigned char **lang_libs;
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

  ejintbool_t enable_stand2;
  ejintbool_t enable_plog;
  ejintbool_t enable_extra_col;
  ejintbool_t disable_compilation_server;
  ejintbool_t enable_win32_languages;

  int cs_langs_loaded;
  int cs_lang_total;
  struct generic_section_config *cs_cfg;
  struct section_language_data **cs_langs;
  unsigned char **cs_lang_names;

  int extra_cs_cfgs_total;
  struct generic_section_config **extra_cs_cfgs;

  const struct section_language_data *cur_lang;
  const struct section_problem_data *cur_prob;
  ejintbool_t prob_show_adv;

  unsigned char *contest_start_cmd_text;
  unsigned char *contest_stop_cmd_text;
  unsigned char *stand_header_text;
  unsigned char *stand_footer_text;
  unsigned char *stand2_header_text;
  unsigned char *stand2_footer_text;
  unsigned char *plog_header_text;
  unsigned char *plog_footer_text;

  unsigned char *compile_home_dir;

  ejintbool_t user_filter_set;
  unsigned char *user_filter;
  int user_offset;
  int user_count;

  ejintbool_t group_filter_set;
  unsigned char *group_filter;
  int group_offset;
  int group_count;

  ejintbool_t contest_user_filter_set;
  unsigned char *contest_user_filter;
  int contest_user_offset;
  int contest_user_count;

  ejintbool_t group_user_filter_set;
  unsigned char *group_user_filter;
  int group_user_offset;
  int group_user_count;

  bitset_t marked;

  struct update_state *update_state;

  /* serve state for test editing */
  struct serve_state *te_state;
};

struct sid_state;
struct userlist_conn;

void super_serve_clear_edited_contest(struct sid_state *sstate);
void super_serve_move_edited_contest(struct sid_state *dst,
                                     struct sid_state *src);
int super_serve_start_serve_test_mode(const struct contest_desc *cnts,
                                      unsigned char **p_log,
                                      int pass_socket);

int super_serve_sid_state_get_max_edited_cnts(void);
const struct sid_state* super_serve_sid_state_get_cnts_editor(int contest_id);
struct sid_state* super_serve_sid_state_get_cnts_editor_nc(int contest_id);
const struct sid_state* super_serve_sid_state_get_test_editor(int contest_id);
struct sid_state* super_serve_sid_state_get_test_editor_nc(int contest_id);

struct background_process;
void super_serve_register_process(struct background_process *prc);
struct background_process *super_serve_find_process(const unsigned char *name);

struct update_state *
update_state_create(void);
struct update_state *
update_state_free(struct update_state *us);

struct section_problem_data *
super_serve_find_problem(struct sid_state *ss, const unsigned char *name);

#endif /* __SUPER_SERVE_H__ */
