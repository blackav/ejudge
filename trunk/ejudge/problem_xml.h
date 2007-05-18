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

enum
{
  PROB_T_PROBLEM = 1,
  PROB_T_STATEMENT,
  PROB_T_DESCRIPTION,
  PROB_T_INPUT_FORMAT,
  PROB_T_OUTPUT_FORMAT,
  PROB_T_EXAMPLES,
  PROB_T_EXAMPLE,
  PROB_T_INPUT,
  PROB_T_OUTPUT,

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

  struct xml_tree *desc;
  struct xml_tree *input_format;
  struct xml_tree *output_format;
  struct xml_tree *examples;
};

struct problem_desc
{
  struct xml_tree b;

  int type;

  unsigned char *id;            /* corresponds to short_name */
  struct problem_stmt *stmts;
};

#endif /* __PROBLEM_XML_H__ */
