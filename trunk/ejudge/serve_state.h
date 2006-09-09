/* -*- c -*- */
/* $Id$ */
#ifndef __SERVE_STATE_H__
#define __SERVE_STATE_H__

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "settings.h"

struct generic_section_config;
struct section_global_data;
struct section_language_data;
struct section_problem_data;
struct section_tester_data;
struct contest_desc;
struct clarlog_state;
struct teamdb_state;
struct team_extra_state;
struct user_state_info;
struct user_filter_info;

struct serve_state
{
  /* serve.cfg parsed config */
  struct generic_section_config *config;
  struct section_global_data    *global;

  struct section_language_data *langs[MAX_LANGUAGE + 1];
  struct section_problem_data  *probs[MAX_PROBLEM + 1];
  struct section_tester_data   *testers[MAX_TESTER + 1];

  int max_lang;
  int max_prob;
  int max_tester;

  const struct contest_desc *cur_contest;

  /* clarlog internal state */
  struct clarlog_state *clarlog_state;

  /* teamdb internal state */
  struct teamdb_state *teamdb_state;

  /* team_extra internal state */
  struct team_extra_state *team_extra_state;

  /* runlog internal state */
  struct runlog_state *runlog_state;

  /* for master_html to store the filter expressions */
  int users_a;
  struct user_state_info **users;
  struct user_filter_info *cur_user;

  /* for prepare to store the abstract entities */
  struct section_problem_data  *abstr_probs[MAX_PROBLEM + 1];
  struct section_tester_data   *abstr_testers[MAX_TESTER + 1];
  int max_abstr_prob;
  int max_abstr_tester;
};
typedef struct serve_state *serve_state_t;

#endif /* __SERVE_STATE_H__ */
