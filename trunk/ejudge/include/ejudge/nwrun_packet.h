/* -*- c -*- */
/* $Id$ */
#ifndef __NWRUN_PACKET_H__
#define __NWRUN_PACKET_H__

/* Copyright (C) 2010-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/parsecfg.h"

#ifndef EJ_PATH_MAX
#define EJ_PATH_MAX 4096
#endif

struct nwrun_in_packet
{
  struct generic_section_config g;

  int priority;
  int contest_id;
  int run_id;
  int prob_id;
  int test_num;
  int judge_id;
  int use_contest_id_in_reply;
  int enable_unix2dos;
  int disable_stdin;
  int ignore_stdout;
  int ignore_stderr;
  int redirect_stdin;
  int redirect_stdout;
  int redirect_stderr;
  int combined_stdin;
  int combined_stdout;
  int time_limit_millis;
  int real_time_limit_millis;
  size_t max_stack_size;
  size_t max_data_size;
  size_t max_vm_size;
  int max_output_file_size;
  int max_error_file_size;
  int enable_memory_limit_error;
  int enable_security_violation_error;
  int enable_secure_run;

  unsigned char prob_short_name[32];
  unsigned char program_name[EJ_PATH_MAX];
  /** name of the file with test data */
  unsigned char test_file_name[EJ_PATH_MAX];
  /** name of the input file for the program being tested */
  unsigned char input_file_name[EJ_PATH_MAX];
  /** name of the output file for the program being tested */
  unsigned char output_file_name[EJ_PATH_MAX];
  /** name of the file with the program result in the packet directory */
  unsigned char result_file_name[EJ_PATH_MAX];
  unsigned char error_file_name[EJ_PATH_MAX];
  unsigned char log_file_name[EJ_PATH_MAX];
};

struct nwrun_out_packet
{
  struct generic_section_config g;

  int contest_id;
  int run_id;
  int prob_id;
  int test_num;
  int judge_id;
  int status;

  int output_file_existed;
  int output_file_orig_size;
  int output_file_too_big;

  int error_file_existed;
  int error_file_orig_size;
  int error_file_truncated;
  int error_file_size;

  int cpu_time_millis;
  int real_time_millis;
  int real_time_available;

  size_t max_memory_used;

  int is_signaled;
  int signal_num;
  int exit_code;

  unsigned char hostname[64];
  unsigned char comment[1024];
  unsigned char exit_comment[1024];
};

struct generic_section_config *
nwrun_in_packet_parse(const unsigned char *path, struct nwrun_in_packet **pkt);
struct generic_section_config *
nwrun_in_packet_free(struct generic_section_config *config);
void
nwrun_in_packet_print(FILE *fout, const struct nwrun_in_packet *p);

struct generic_section_config *
nwrun_out_packet_parse(const unsigned char*path,struct nwrun_out_packet **pkt);
struct generic_section_config *
nwrun_out_packet_free(struct generic_section_config *config);
void
nwrun_out_packet_print(FILE *fout, const struct nwrun_out_packet *result);

#endif /* __NWRUN_PACKET_H__ */
