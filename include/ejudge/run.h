/* -*- c -*- */
#ifndef __RUN_H__
#define __RUN_H__

/* Copyright (C) 2010-2016 Alexander Chernov <cher@ejudge.ru> */

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

struct testinfo
{
  int            status;        /* the execution status */
  int            code;          /* the process exit code */
  int            termsig;       /* the termination signal */
  int            score;         /* score gained for this test */
  int            max_score;     /* maximal score for this test */
  long           times;         /* execution time */
  long           real_time;     /* execution real time */
  unsigned long  max_memory_used;
  char          *input;         /* the input */
  long           input_size;
  int            has_input_digest;
  unsigned char  input_digest[32];
  char          *output;        /* the output */
  long           output_size;
  char          *error;         /* the error */
  long           error_size;
  char          *correct;       /* the correct result */
  long           correct_size;
  int            has_correct_digest;
  unsigned char  correct_digest[32];
  int            has_info_digest;
  unsigned char  info_digest[32];
  char          *chk_out;       /* checker's output */
  long           chk_out_size;
  unsigned char *args;          /* command-line arguments */
  unsigned char *comment;       /* judge's comment */
  unsigned char *team_comment;  /* team's comment */
  unsigned char *exit_comment;  /* comment on exit status */
  int            visibility;    /* test visibility */
};

struct testinfo_vector
{
  int reserved, size;
  struct testinfo *data;
};

struct run_listener;
struct run_listener_ops
{
  void (*before_test)(struct run_listener *self, int test_no);
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

void
run_inverse_testing(
        struct serve_state *state,
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

void
run_tests(
        const struct ejudge_cfg *config,
        struct serve_state *state,
        const struct section_tester_data *tst,
        const struct super_run_in_packet *srp,
        struct run_reply_packet *reply_pkt,
        int accept_testing,
        int accept_partial,
        int cur_variant,
        char const *exe_name,
        char const *new_base,
        char *report_path,                /* path to the report */
        char *full_report_path,           /* path to the full output dir */
        const unsigned char *user_spelling,
        const unsigned char *problem_spelling,
        const unsigned char *mirror_dir,
        int utf8_mode,
        struct run_listener *listener,
        const unsigned char *hostname,
        const struct remap_spec *remaps);

#endif /* __RUN_H__ */
