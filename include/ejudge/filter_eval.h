/* -*- c -*- */

#ifndef __FILTER_EVAL_H__
#define __FILTER_EVAL_H__

/* Copyright (C) 2002-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/prepare.h"
#include "ejudge/runlog.h"
#include "ejudge/filter_tree.h"
#include "ejudge/teamdb.h"
#include "ejudge/serve_state.h"

struct filter_env
{
  teamdb_state_t teamdb_state;
  serve_state_t serve_state;
  struct filter_tree_mem *mem;
  int maxlang;
  const struct section_language_data * const *langs;
  int maxprob;
  const struct section_problem_data * const *probs;
  int rbegin;
  int rtotal;
  struct run_header rhead;
  const struct run_entry *rentries;
  int rid;
  const struct run_entry *cur;
  time_t cur_time;
  long long cur_time_us;
};

int filter_tree_bool_eval(struct filter_env *env, struct filter_tree *t);

#endif /* __FILTER_EVAL_H__ */
