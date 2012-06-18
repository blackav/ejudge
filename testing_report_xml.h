/* -*- c -*- */
/* $Id$ */
#ifndef __TESTING_REPORT_XML_H__
#define __TESTING_REPORT_XML_H__

/* Copyright (C) 2005-2012 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>

struct testing_report_test
{
  int num;
  int status;
  int time;
  int real_time;
  int exit_code;
  int term_signal;
  int nominal_score;
  int score;
  int output_available;
  int stderr_available;
  int checker_output_available;
  int args_too_long;
  int has_input_digest;
  int has_correct_digest;
  int has_info_digest;
  int visibility;
  unsigned long max_memory_used;

  unsigned char input_digest[32];
  unsigned char correct_digest[32];
  unsigned char info_digest[32];

  unsigned char *comment;
  unsigned char *team_comment;
  unsigned char *checker_comment;
  unsigned char *exit_comment;

  unsigned char *args;

  /* input data for the program */
  unsigned char *input;
  int input_size;

  /* output data */
  unsigned char *output;
  int output_size;

  /* correct answer */
  unsigned char *correct;
  int correct_size;

  /* stderr */
  unsigned char *error;
  int error_size;

  /* checker output */
  unsigned char *checker;
  int checker_size;
};

struct testing_report_row
{
  int row;
  unsigned char *name;
  int must_fail;
  int status;
  int nominal_score;
  int score;
};

struct testing_report_cell
{
  int row;
  int column;
  int status;
  int time;
  int real_time;
};

typedef struct testing_report_xml
{
  int run_id;
  int judge_id;
  int status;
  int scoring_system;
  int archive_available;
  int correct_available;
  int info_available;
  int real_time_available;
  int max_memory_used_available;
  int run_tests;
  int variant;
  int accepting_mode;
  int failed_test;
  int tests_passed;
  int score;
  int max_score;
  int time_limit_ms;
  int real_time_limit_ms;
  int marked_flag;
  int tests_mode;
  /* user-visible scores */
  int user_status;
  int user_tests_passed;
  int user_score;
  int user_max_score;
  int user_run_tests;
  unsigned char *comment;       /* additional testing comment */
  unsigned char *valuer_comment;
  unsigned char *valuer_judge_comment;
  unsigned char *valuer_errors;
  unsigned char *host;
  unsigned char *errors;
  unsigned char *compiler_output;

  struct testing_report_test **tests;

  int tt_row_count;
  int tt_column_count;
  struct testing_report_row **tt_rows;
  struct testing_report_cell ***tt_cells;
} *testing_report_xml_t;

testing_report_xml_t testing_report_alloc(int run_id, int judge_id);
testing_report_xml_t testing_report_parse_xml(const unsigned char *path);
testing_report_xml_t testing_report_free(testing_report_xml_t r);
void
testing_report_unparse_xml(
        FILE *out,
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        testing_report_xml_t r);

#endif /* __TESTING_REPORT_XML_H__ */
