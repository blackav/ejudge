/* -*- c -*- */
#ifndef __RUN_H__
#define __RUN_H__

/* Copyright (C) 2010-2026 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdlib.h>

struct serve_state;
struct run_request_packet;
struct run_reply_packet;
struct section_global_data;
struct section_problem_data;
struct super_run_in_packet;

struct run_test_file
{
  unsigned char *data;          /* the file content */
  ssize_t orig_size;            /* the original file size */
  ssize_t stored_size;          /* the stored (maybe truncated) size */
  unsigned char is_here;        /* the file content is here */
  unsigned char is_binary;      /* if this file is binary */
  unsigned char is_too_long;    /* the content is too long */
  unsigned char is_too_wide;    /* the content contains too long lines */
  unsigned char is_fixed;       /* the content is changed in some way */
  unsigned char is_base64;      /* content is base-64 encoded */
  unsigned char is_archived;    /* content is in a separate archive */
};

struct run_test_info
{
  int            status;        /* the execution status */
  int            code;          /* the process exit code */
  int            termsig;       /* the termination signal */
  int            score;         /* score gained for this test */
  int            max_score;     /* maximal score for this test */
  long           times;         /* execution time */
  long           real_time;     /* execution real time */
  unsigned long  max_memory_used;
  long long      max_rss;
  int            has_input_digest;
  unsigned char  input_digest[32];
  int            has_correct_digest;
  unsigned char  correct_digest[32];
  int            has_info_digest;
  unsigned char  info_digest[32];
  unsigned char *args;          /* command-line arguments */
  unsigned char *comment;       /* judge's comment */
  unsigned char *team_comment;  /* team's comment */
  unsigned char *exit_comment;  /* comment on exit status */
  int            visibility;    /* test visibility */
  unsigned char *program_stats_str;
  unsigned char *interactor_stats_str;
  unsigned char *checker_stats_str;
  unsigned char *checker_token;
  /* for output-only separate-user-score problems */
  int user_status;
  int user_score;
  int user_tests_passed;
  int user_nominal_score;
  /* test checker on user input */
  struct run_test_file input;
  struct run_test_file output;
  struct run_test_file correct;
  struct run_test_file error;
  struct run_test_file chk_out;
  struct run_test_file test_checker;
};

struct run_test_info_vector
{
  int reserved, size;
  struct run_test_info *data;
};

struct run_listener;
struct run_listener_ops
{
  __attribute__((warn_unused_result))
  int (*before_test)(struct run_listener *self, int test_no, int reconnect_flag);
};
struct run_listener
{
  const struct run_listener_ops *ops;
};

struct remap_spec
{
  unsigned char *src_dir; // must begin and end with /, NULL terminate the list
  unsigned char *dst_dir;
  int src_len;
  int dst_len;
};

struct AgentClient;

void
run_inverse_testing(
        struct serve_state *state,
        struct AgentClient *agent,
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        const unsigned char *pkt_name,
        const unsigned char *run_exe_dir,
        unsigned char *report_path,
        size_t report_path_size,
        int utf8_mode);

struct full_archive;
struct serve_state;
struct section_tester_data;
struct ejudge_cfg;
struct run_properties;

void
run_tests(
        const struct ejudge_cfg *config,
        struct serve_state *state,
        const struct section_tester_data *tst,
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        struct AgentClient *agent,
        char const *exe_name,
        char const *new_base,
        char *report_path,                /* path to the report */
        char *full_report_path,           /* path to the full output dir */
        const unsigned char *mirror_dir,
        int utf8_mode,
        struct run_listener *listener,
        const unsigned char *hostname,
        const struct remap_spec *remaps,
        int user_input_mode,
        const unsigned char *inp_data,
        size_t inp_size,
        const unsigned char *src_path,
        const struct run_properties *run_props);

#endif /* __RUN_H__ */
