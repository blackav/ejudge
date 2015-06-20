/* -*- c -*- */
#ifndef __SUPER_RUN_PACKET_H__
#define __SUPER_RUN_PACKET_H__

/* Copyright (C) 2012-2015 Alexander Chernov <cher@ejudge.ru> */

/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include "ejudge/ej_types.h"
#include "ejudge/parsecfg.h"

#ifndef META_ATTRIB
#if defined __RCC__
#undef __attribute__
#define META_ATTRIB(x) __attribute__(x)
#else
#define META_ATTRIB(x)
#endif /* __RCC__ */
#endif /* META_ATTRIB */

struct super_run_in_global_packet
{
  struct generic_section_config g META_ATTRIB((meta_hidden));

  int contest_id;
  int judge_id;
  int run_id;
  unsigned char *reply_spool_dir;
  unsigned char *reply_report_dir;
  unsigned char *reply_full_archive_dir;
  unsigned char *reply_packet_name;
  int priority;
  int variant;
  unsigned char *lang_short_name;
  unsigned char *arch;
  unsigned char *lang_key;
  ejintbool_t secure_run;
  ejintbool_t detect_violations;
  ejintbool_t enable_memory_limit_error;
  ejintbool_t enable_max_stack_size;
  int user_id;
  unsigned char *user_login;
  unsigned char *user_name;
  unsigned char *user_spelling;
  unsigned char *score_system;
  ejintbool_t is_virtual;
  ejintsize_t max_file_length;
  ejintsize_t max_line_length;
  ejintsize_t max_cmd_length;
  ejintbool_t enable_full_archive;
  ejintbool_t accepting_mode;
  ejintbool_t separate_user_score;
  int mime_type;
  ejintbool_t notify_flag;
  ejintbool_t advanced_layout;
  ejintbool_t rejudge_flag;
  int ts1;
  int ts1_us;
  int ts2;
  int ts2_us;
  int ts3;
  int ts3_us;
  int ts4;
  int ts4_us;
  int lang_time_limit_adj_ms;
  unsigned char *exe_sfx;
  ejintbool_t restart;
  ejintbool_t disable_sound;
  ejintbool_t is_dos;
  int time_limit_retry_count;
  unsigned char *checker_locale;
  unsigned char *run_uuid;

  int scoring_system_val META_ATTRIB((meta_hidden));
};

struct super_run_in_problem_packet
{
  struct generic_section_config g META_ATTRIB((meta_hidden));

  unsigned char *type;
  int id;
  ejintbool_t check_presentation;
  ejintbool_t scoring_checker;
  ejintbool_t interactive_valuer;
  ejintbool_t disable_pe;
  ejintbool_t disable_wtl;
  ejintbool_t use_stdin;
  ejintbool_t use_stdout;
  ejintbool_t combined_stdin;
  ejintbool_t combined_stdout;
  ejintbool_t ignore_exit_code;
  ejintbool_t binary_input;
  ejintbool_t binary_output;
  int real_time_limit_ms;
  int time_limit_ms;
  ejintbool_t use_ac_not_ok;
  int full_score;
  int full_user_score;
  ejintbool_t variable_full_score;
  int test_score;
  ejintbool_t use_corr;
  ejintbool_t use_info;
  ejintbool_t use_tgz;
  int tests_to_accept;
  ejintbool_t accept_partial;
  int min_tests_to_accept;
  int checker_real_time_limit_ms;
  unsigned char *short_name;
  unsigned char *long_name;
  unsigned char *internal_name;
  unsigned char *problem_dir;
  unsigned char *test_dir;
  unsigned char *corr_dir;
  unsigned char *info_dir;
  unsigned char *tgz_dir;
  unsigned char *input_file;
  unsigned char *output_file;
  unsigned char *test_score_list;
  unsigned char *score_tests;
  unsigned char *standard_checker;
  ejintbool_t valuer_sets_marked;
  int interactor_time_limit_ms;
  ejintbool_t disable_stderr;
  unsigned char *test_pat;
  unsigned char *corr_pat;
  unsigned char *info_pat;
  unsigned char *tgz_pat;
  unsigned char *tgzdir_pat;
  char **test_sets;
  ejenvlist_t checker_env;
  ejenvlist_t valuer_env;
  ejenvlist_t interactor_env;
  ejenvlist_t test_checker_env;
  ejenvlist_t init_env;
  ejenvlist_t start_env;
  unsigned char *check_cmd;
  unsigned char *valuer_cmd;
  unsigned char *interactor_cmd;
  unsigned char *test_checker_cmd;
  unsigned char *init_cmd;
  unsigned char *start_cmd;
  unsigned char *solution_cmd;
  ej_size64_t max_vm_size;
  ej_size64_t max_data_size;
  ej_size64_t max_stack_size;
  ej_size64_t max_core_size;
  ej_size64_t max_file_size;
  int max_open_file_count;
  int max_process_count;
  unsigned char *spelling;
  unsigned char *open_tests;
  ejintbool_t enable_process_group;
  unsigned char *umask;

  int type_val META_ATTRIB((meta_hidden));
};

struct super_run_in_tester_packet
{
  struct generic_section_config g META_ATTRIB((meta_hidden));

  unsigned char *name;
  ejintbool_t is_dos;
  ejintbool_t no_redirect;
  int priority_adjustment;
  ejintbool_t ignore_stderr;
  unsigned char *arch;
  unsigned char *key;
  unsigned char *memory_limit_type;
  unsigned char *secure_exec_type;
  ejintbool_t no_core_dump;
  ejintbool_t enable_memory_limit_error;
  unsigned char *kill_signal;
  ejintbool_t clear_env;
  int time_limit_adjustment_ms;
  unsigned char *errorcode_file;
  unsigned char *error_file;
  unsigned char *prepare_cmd;
  unsigned char *start_cmd;
  ejenvlist_t start_env;
};

struct super_run_in_packet
{
  struct super_run_in_global_packet *global;
  struct super_run_in_problem_packet *problem;
  struct super_run_in_tester_packet *tester;
};

struct super_run_in_packet *
super_run_in_packet_alloc(void);
void
super_run_in_packet_set_default(struct super_run_in_packet *p);
struct super_run_in_packet *
super_run_in_packet_free(struct super_run_in_packet *p);
void
super_run_in_packet_free_tester(struct super_run_in_packet *p);

void
super_run_in_packet_unparse_cfg(FILE *out_f, struct super_run_in_packet *p);

struct super_run_in_packet *
super_run_in_packet_parse_cfg_str(const unsigned char *path, char *buf, size_t size);

#endif /* __SUPER_RUN_PACKET_H__ */
