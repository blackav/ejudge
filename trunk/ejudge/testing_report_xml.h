/* -*- c -*- */
/* $Id$ */
#ifndef __TESTING_REPORT_XML_H__
#define __TESTING_REPORT_XML_H__

/* Copyright (C) 2005 Alexander Chernov <cher@ispras.ru> */

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

struct testing_report_test
{
  int num;
  int status;
  int time;
  int exit_code;
  int term_signal;
  int nominal_score;
  int score;
  int output_available;
  int stderr_available;
  int checker_output_available;
  int args_too_long;

  unsigned char *comment;
  unsigned char *checker_comment;

  unsigned char *args;
  unsigned char *input;
  unsigned char *output;
  unsigned char *correct;
  unsigned char *error;
  unsigned char *checker;
};

typedef struct testing_report_xml
{
  int run_id;
  int judge_id;
  int status;
  int scoring_system;
  int archive_available;
  int correct_available;
  int run_tests;
  int variant;
  int accepting_mode;
  int failed_test;
  int tests_passed;
  int score;
  int max_score;
  unsigned char *comment;       /* additional testing comment */

  struct testing_report_test **tests;
} *testing_report_xml_t;

testing_report_xml_t testing_report_parse_xml(const unsigned char *path);
testing_report_xml_t testing_report_free(testing_report_xml_t r);

#endif /* __TESTING_REPORT_XML_H__ */
