/* -*- c -*- */
#ifndef __TESTING_REPORT_XML_H__
#define __TESTING_REPORT_XML_H__

/* Copyright (C) 2005-2015 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdio.h>

// outputs preserved in the testing report
enum
{
  TESTING_REPORT_INPUT,
  TESTING_REPORT_OUTPUT,
  TESTING_REPORT_CORRECT,
  TESTING_REPORT_ERROR,
  TESTING_REPORT_CHECKER
};

struct testing_report_file_content
{
  long long      size;
  long long      orig_size;
  unsigned char *data;
  int            is_too_big;
  int            is_base64;
};

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

  // digests are BINARY SHA1 (20 bytes)
  unsigned char input_digest[32];
  unsigned char correct_digest[32];
  unsigned char info_digest[32];

  unsigned char *comment;
  unsigned char *team_comment;
  unsigned char *checker_comment;
  unsigned char *exit_comment;

  unsigned char *args;

  /* input data for the program */
  struct testing_report_file_content input;
  /* output data */
  struct testing_report_file_content output;
  /* correct answer */
  struct testing_report_file_content correct;
  /* stderr */
  struct testing_report_file_content error;
  /* checker output */
  struct testing_report_file_content checker;
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
  int contest_id;
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
  int compile_error; // only compiler_output is filled 
  unsigned char *comment;       /* additional testing comment */
  unsigned char *valuer_comment;
  unsigned char *valuer_judge_comment;
  unsigned char *valuer_errors;
  unsigned char *host;
  unsigned char *cpu_model;
  unsigned char *cpu_mhz;
  unsigned char *errors;
  unsigned char *compiler_output;

  ej_uuid_t uuid;

  struct testing_report_test **tests;

  int tt_row_count;
  int tt_column_count;
  struct testing_report_row **tt_rows;
  struct testing_report_cell ***tt_cells;
} *testing_report_xml_t;

struct testing_report_test *
testing_report_test_alloc(int num, int status);

testing_report_xml_t testing_report_alloc(int contest_id, int run_id, int judge_id);
testing_report_xml_t testing_report_parse_xml(const unsigned char *path);
testing_report_xml_t testing_report_free(testing_report_xml_t r);
void
testing_report_unparse_xml(
        FILE *out,
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        testing_report_xml_t r);

void
testing_report_to_str(
        char **pstr,
        size_t *psize,
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        testing_report_xml_t r);
int
testing_report_to_file(
        const unsigned char *path,
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        testing_report_xml_t r);

#endif /* __TESTING_REPORT_XML_H__ */
