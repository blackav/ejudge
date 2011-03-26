/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007-2011 Alexander Chernov <cher@ejudge.ru> */

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

#include "problem_common.h"
#include "ej_types.h"

#include "reuse_logger.h"

#include <string.h>

const unsigned char * const problem_type_str[] =
{
  [PROB_TYPE_STANDARD] = "standard",
  [PROB_TYPE_OUTPUT_ONLY] = "output-only",
  [PROB_TYPE_SHORT_ANSWER] = "short-answer",
  [PROB_TYPE_TEXT_ANSWER] = "text-answer",
  [PROB_TYPE_SELECT_ONE] = "select-one",
  [PROB_TYPE_SELECT_MANY] = "select-many",
  [PROB_TYPE_CUSTOM] = "custom",
  [PROB_TYPE_TESTS] = "tests",

  [PROB_TYPE_LAST] = 0,
};

int
problem_parse_type(const unsigned char *str)
{
  int i;

  if (!str) return 0;
  for (i = 0; i < PROB_TYPE_LAST; i++)
    if (problem_type_str[i] && !strcasecmp(str, problem_type_str[i]))
      return i;
  return -1;
}
const unsigned char *
problem_unparse_type(int val)
{
  ASSERT(val >= 0 && val < PROB_TYPE_LAST);
  ASSERT(problem_type_str[val]);
  return problem_type_str[val];
}

const unsigned char * const test_visibility_str[] =
{
  [TV_NORMAL] = "normal",
  [TV_FULL] = "full",
  [TV_FULLIFMARKED] = "fullifmarked",
  [TV_BRIEF] = "brief",
  [TV_EXISTS] = "exists",
  [TV_HIDDEN] = "hidden",

  [TV_LAST] = 0
};

int
test_visibility_parse(const unsigned char *str)
{
  int i;

  if (!str || !*str) return TV_NORMAL;
  for (i = 0; i < TV_LAST; ++i) {
    if (test_visibility_str[i] && !strcasecmp(test_visibility_str[i], str))
      return i;
  }
  return -1;
}

int
test_visibility_parse_mem(const unsigned char *str, int len)
{
  int i;

  if (!str || !*str) return TV_NORMAL;
  for (i = 0; i < TV_LAST; ++i) {
    if (test_visibility_str[i] && strlen(test_visibility_str[i]) == len && !strncasecmp(test_visibility_str[i], str, len))
      return i;
  }
  return -1;
}

const unsigned char *
test_visibility_unparse(int value)
{
  if (value < 0 || value >= TV_LAST) value = 0;
  return test_visibility_str[value];
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
