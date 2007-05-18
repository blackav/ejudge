/* -*- c -*- */
/* $Id$ */

#ifndef __PROBLEM_COMMON_H__
#define __PROBLEM_COMMON_H__

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

/* problem types */
enum
{
  PROB_TYPE_STANDARD = 0,       /* standard problem */
  PROB_TYPE_OUTPUT_ONLY,        /* output-only problem */
  PROB_TYPE_SHORT_ANSWER,       /* output-only with short answer */
  PROB_TYPE_TEXT_ANSWER,        /* output-only with textarea input */
  PROB_TYPE_SELECT_ONE,         /* select one answer from the list */
  PROB_TYPE_SELECT_MANY,        /* select many answers from the list */
  PROB_TYPE_CUSTOM,             /* custom form (part of prob. stmt) */

  PROB_TYPE_LAST,
};

int problem_parse_type(const unsigned char *str);
const unsigned char *problem_unparse_type(int val);

#endif /* __PROBLEM_COMMON_H__ */
