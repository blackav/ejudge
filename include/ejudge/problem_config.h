/* -*- c -*- */
#ifndef __PROBLEM_CONFIG_H__
#define __PROBLEM_CONFIG_H__

/* Copyright (C) 2012-2025 Alexander Chernov <cher@ejudge.ru> */

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

#include <time.h>

#ifndef META_ATTRIB
#if defined __RCC__
#undef __attribute__
#define META_ATTRIB(x) __attribute__(x)
#else
#define META_ATTRIB(x)
#endif /* __RCC__ */
#endif /* META_ATTRIB */

/* sizeof(struct problem_config_section) == 1088 */
struct problem_config_section
{
  struct generic_section_config g META_ATTRIB((meta_hidden));

  ejbyteflag_t manual_checking;
  ejbyteflag_t check_presentation;
  ejbyteflag_t scoring_checker;
  ejbyteflag_t enable_checker_token;
  ejbyteflag_t interactive_valuer;
  ejbyteflag_t disable_pe;
  ejbyteflag_t disable_wtl;
  ejbyteflag_t wtl_is_cf;
  ejbyteflag_t use_stdin;
  ejbyteflag_t use_stdout;
  ejbyteflag_t combined_stdin;
  ejbyteflag_t combined_stdout;
  ejbyteflag_t binary_input;
  ejbyteflag_t binary;
  ejbyteflag_t ignore_exit_code;
  ejbyteflag_t ignore_term_signal;
  ejbyteflag_t olympiad_mode;
  ejbyteflag_t score_latest;
  ejbyteflag_t score_latest_or_unmarked;
  ejbyteflag_t score_latest_marked;
  ejbyteflag_t score_tokenized;
  ejbyteflag_t use_ac_not_ok;
  ejbyteflag_t ignore_prev_ac;
  ejbyteflag_t team_enable_rep_view;
  ejbyteflag_t team_enable_ce_view;
  ejbyteflag_t team_show_judge_report;
  ejbyteflag_t show_checker_comment;
  ejbyteflag_t ignore_compile_errors;
  ejbyteflag_t variable_full_score;
  ejbyteflag_t ignore_penalty;
  ejbyteflag_t use_corr;
  ejbyteflag_t use_info;
  ejbyteflag_t use_tgz;
  ejbyteflag_t accept_partial;
  ejbyteflag_t disable_user_submit;
  ejbyteflag_t disable_tab;
  ejbyteflag_t unrestricted_statement;
  ejbyteflag_t statement_ignore_ip;
  ejbyteflag_t restricted_statement;
  ejbyteflag_t enable_submit_after_reject;
  ejbyteflag_t hide_file_names;
  ejbyteflag_t hide_real_time_limit;
  ejbyteflag_t enable_tokens;
  ejbyteflag_t tokens_for_user_ac;
  ejbyteflag_t disable_submit_after_ok;
  ejbyteflag_t disable_auto_testing;
  ejbyteflag_t disable_testing;
  ejbyteflag_t enable_compilation;
  ejbyteflag_t skip_testing;
  ejbyteflag_t hidden;
  ejbyteflag_t stand_hide_time;
  ejbyteflag_t advance_to_next;
  ejbyteflag_t disable_ctrl_chars;
  ejbyteflag_t enable_text_form;
  ejbyteflag_t stand_ignore_score;
  ejbyteflag_t stand_last_column;
  ejbyteflag_t disable_security;
  ejbyteflag_t enable_suid_run;
  ejbyteflag_t enable_container;
  ejbyteflag_t enable_dynamic_priority;
  ejbyteflag_t valuer_sets_marked;
  ejbyteflag_t ignore_unmarked;
  ejbyteflag_t disable_stderr;
  ejbyteflag_t enable_process_group;
  ejbyteflag_t enable_kill_all;
  ejbyteflag_t hide_variant;
  ejbyteflag_t enable_testlib_mode;
  ejbyteflag_t autoassign_variants;
  ejbyteflag_t require_any;
  ejbyteflag_t enable_extended_info;
  ejbyteflag_t stop_on_first_fail;
  ejbyteflag_t enable_control_socket;
  ejbyteflag_t copy_exe_to_tgzdir;
  ejbyteflag_t enable_multi_header;
  ejbyteflag_t use_lang_multi_header;
  ejbyteflag_t notify_on_submit;
  ejbyteflag_t enable_user_input;
  ejbyteflag_t enable_vcs;
  ejbyteflag_t enable_iframe_statement;
  ejbyteflag_t enable_src_for_testing;
  ejbyteflag_t disable_vm_size_limit;
  ejbyteflag_t enable_group_merge;
  ejbyteflag_t ignore_sigpipe;

  int id;
  int variant_num;
  int full_score;
  int full_user_score;
  int min_score_1;
  int min_score_2;
  int real_time_limit;
  int time_limit;
  int time_limit_millis;
  int test_score;
  int run_penalty;
  int acm_run_penalty;
  int disqualified_penalty;
  int compile_error_penalty;
  int tests_to_accept;
  int min_tests_to_accept;
  int checker_real_time_limit;
  int checker_time_limit_ms;
  int priority_adjustment;
  int score_multiplier;
  int prev_runs_to_show;
  int max_user_run_count;
  int interactor_time_limit;
  int interactor_real_time_limit;
  int max_open_file_count;
  int max_process_count;
  int forced_test_count;

  time_t deadline;
  time_t start_date;

  ej_size64_t max_vm_size;
  ej_size64_t max_data_size;
  ej_size64_t max_stack_size;
  ej_size64_t max_rss_size;
  ej_size64_t max_core_size;
  ej_size64_t max_file_size;
  ej_size64_t checker_max_vm_size;
  ej_size64_t checker_max_stack_size;
  ej_size64_t checker_max_rss_size;

  unsigned char *type;             // int type;       // in prepare.h
  unsigned char *short_name;       // short_name[32]; // in prepare.h

  unsigned char *long_name;
  unsigned char *long_name_en;     // not in prepare.h
  unsigned char *stand_name;
  unsigned char *stand_column;
  unsigned char *group_name;
  unsigned char *internal_name;
  unsigned char *plugin_entry_name;
  unsigned char *uuid;
  unsigned char *test_dir;
  unsigned char *test_sfx;
  unsigned char *corr_dir;
  unsigned char *corr_sfx;
  unsigned char *info_dir;
  unsigned char *info_sfx;
  unsigned char *tgz_dir;
  unsigned char *tgz_sfx;
  unsigned char *tgzdir_sfx;
  unsigned char *input_file;
  unsigned char *output_file;
  unsigned char *test_score_list;
  unsigned char *tokens;
  unsigned char *umask;
  unsigned char *ok_status;
  unsigned char *header_pat;
  unsigned char *footer_pat;
  unsigned char *compiler_env_pat;
  unsigned char *container_options;
  unsigned char *score_tests;
  unsigned char *standard_checker;
  unsigned char *spelling;
  unsigned char *statement_file;
  unsigned char *plugin_file;
  unsigned char *xml_file;
  unsigned char *stand_attr;
  unsigned char *source_header;
  unsigned char *source_footer;
  unsigned char *custom_compile_cmd;
  unsigned char *custom_lang_name;
  unsigned char *extra_src_dir;
  unsigned char *standard_valuer;
  unsigned char *md_file;
  unsigned char *test_pat;
  unsigned char *corr_pat;
  unsigned char *info_pat;
  unsigned char *tgz_pat;
  unsigned char *tgzdir_pat;
  unsigned char *check_cmd;
  unsigned char *valuer_cmd;
  unsigned char *interactor_cmd;
  unsigned char *style_checker_cmd;
  unsigned char *test_checker_cmd;
  unsigned char *test_generator_cmd;
  unsigned char *init_cmd;
  unsigned char *start_cmd;
  unsigned char *solution_src;
  unsigned char *solution_cmd;
  unsigned char *post_pull_cmd;
  unsigned char *vcs_compile_cmd;
  unsigned char *open_tests;
  unsigned char *final_open_tests;
  unsigned char *token_open_tests;
  unsigned char *extid;
  unsigned char *normalization;
  unsigned char *src_normalization;
  unsigned char *score_bonus;
  unsigned char *super_run_dir;
  unsigned char *revision;           // not in prepare.h
  unsigned char *iframe_statement;   // not in prepare.h

  char **test_sets;
  char **date_penalty;
  char **group_start_date;
  char **group_deadline;
  char **disable_language;
  char **enable_language;
  char **require;
  char **provide_ok;
  char **allow_ip;
  char **lang_time_adj;
  char **lang_time_adj_millis;
  char **lang_max_vm_size;
  char **lang_max_stack_size;
  char **lang_max_rss_size;
  char **checker_extra_files;
  char **personal_deadline;

  ejenvlist_t lang_compiler_env;
  ejenvlist_t lang_compiler_container_options;
  ejenvlist_t checker_env;
  ejenvlist_t valuer_env;
  ejenvlist_t interactor_env;
  ejenvlist_t style_checker_env;
  ejenvlist_t test_checker_env;
  ejenvlist_t test_generator_env;
  ejenvlist_t init_env;
  ejenvlist_t start_env;
  ejenvlist_t statement_env;
};

void
problem_config_section_init(struct generic_section_config *gp);
struct problem_config_section *
problem_config_section_alloc(void);
void
problem_config_section_free(struct generic_section_config *gp);
struct problem_config_section *
problem_config_section_parse_cfg(const unsigned char *path, FILE *f);
struct problem_config_section *
problem_config_section_parse_cfg_str(const unsigned char *path, char *buf, size_t size);
void
problem_config_section_unparse_cfg(FILE *out_f, const struct problem_config_section *p);


#endif /* __PROBLEM_CONFIG_H__ */
