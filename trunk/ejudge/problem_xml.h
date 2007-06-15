/* -*- c -*- */
/* $Id$ */

#ifndef __PROBLEM_XML_H__
#define __PROBLEM_XML_H__

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "expat_iface.h"
#include "problem_common.h"

#include <time.h>
#include <stdio.h>

enum
{
  PROB_T_PROBLEM = 1,
  PROB_T_STATEMENT,
  PROB_T_TITLE,
  PROB_T_DESCRIPTION,
  PROB_T_INPUT_FORMAT,
  PROB_T_OUTPUT_FORMAT,
  PROB_T_EXAMPLES,
  PROB_T_EXAMPLE,
  PROB_T_INPUT,
  PROB_T_OUTPUT,
  PROB_T_MAX_VM_SIZE,
  PROB_T_MAX_STACK_SIZE,
  PROB_T_TIME_LIMITS,
  PROB_T_TIME_LIMIT,
  PROB_T_ANSWER_VARIANTS,
  PROB_T_ANSWER,
  PROB_T_TRANSLATION,

  PROB_T__BARRIER,
  PROB_T__DEFAULT,
  PROB_T__TEXT,

  PROB_LAST_TAG,
};

enum
{
  PROB_A_ID = 1,
  PROB_A_TYPE,
  PROB_A_LANG,
  PROB_A_CPU,
  PROB_A_WORDSIZE,
  PROB_A_FREQ,
  PROB_A_BOGOMIPS,
  PROB_A_CORRECT,

  PROB_A__BARRIER,
  PROB_A__DEFAULT,

  PROB_LAST_ATTR,
};

struct problem_desc;
typedef struct problem_desc *problem_xml_t;

struct problem_stmt
{
  struct xml_tree b;

  struct problem_stmt *next_stmt;
  unsigned char *lang;

  struct xml_tree *title;
  struct xml_tree *desc;
  struct xml_tree *input_format;
  struct xml_tree *output_format;
  struct xml_tree *examples;
};

struct problem_time_limit
{
  struct xml_tree b;
  struct problem_time_limit *next_tl;

  int time_limit_ms;

  unsigned char *cpu;
  int wordsize;
  double bogomips;
  long long freq;
};

struct problem_desc
{
  struct xml_tree b;

  int type;

  size_t max_vm_size;
  size_t max_stack_size;

  unsigned char *id;            /* corresponds to short_name */
  struct problem_stmt *stmts;
  struct xml_tree *examples;
  struct problem_time_limit *tls;
  int correct_answer;
  int cur_tl_ms;                /* TL on the current hardware (ms) */

  time_t last_check;
  time_t last_update;
};

problem_xml_t problem_xml_parse(const unsigned char *path);
problem_xml_t problem_xml_parse_string(const unsigned char *path,
                                       const unsigned char *str);
problem_xml_t problem_xml_parse_stream(const unsigned char *path, FILE *f);

problem_xml_t problem_xml_free(problem_xml_t r);

struct problem_stmt *problem_xml_unparse_elem(
	FILE *fout,
        problem_xml_t p,
        int elem,                  /* STATEMENT, INPUT_FORMAT, etc */
        const unsigned char *lang, /* 0 - default language */
        struct problem_stmt *stmt, /* previously found element */
        const unsigned char **subst); /* attribute value substitutions */

#endif /* __PROBLEM_XML_H__ */
