/* -*- c -*- */

/* Copyright (C) 2010-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/teamdb.h"
#include "ejudge/teamdb_priv.h"
#include "ejudge/userlist.h"
#include "ejudge/serve_state.h"
#include "ejudge/filter_eval.h"

#include <string.h>

void
teamdb_get_user_map(
        struct serve_state *cs,
        time_t cur_time,
        int u_max,             // maximal user id
        unsigned char *u_runs, // map of users forced to skip
        int *p_u_tot,          // [out] number of users
        int *u_rev,            // user_id -> user_serial
        int *u_ind,            // user_serial -> user_id
        struct user_filter_info *filter)
{
  int i, u_tot = 0, f;
  teamdb_state_t state = cs->teamdb_state;
  struct filter_env env;
  struct run_entry fake_entries[1];

  if (state->disabled) {
    for (i = 1; i < u_max; ++i) {
      if (!u_runs[i]) continue;
      u_rev[i] = u_tot;
      u_ind[u_tot++] = i;
    }
    *p_u_tot = u_tot;
    return;
  }

  *p_u_tot = u_tot;
  if (!state->users || state->users->user_map_size <= 0) {
    return;
  }

  if (u_max > state->users->user_map_size) {
    u_max = state->users->user_map_size;
  }

  memset(u_rev, -1, u_max * sizeof(u_rev[0]));
  memset(&env, 0, sizeof(env));
  memset(fake_entries, 0, sizeof(fake_entries[0]) * 1);

  if (filter && filter->stand_user_tree) {
    env.teamdb_state = cs->teamdb_state;
    env.serve_state = cs;
    env.mem = filter_tree_new();
    env.maxlang = cs->max_lang;
    env.langs = (const struct section_language_data * const *) cs->langs;
    env.maxprob = cs->max_prob;
    env.probs = (const struct section_problem_data * const *) cs->probs;
    env.rtotal = 1;
    env.cur_time = cur_time;
    env.cur_time_us = cur_time * 1000000LL; // FIXME
    env.rentries = fake_entries;
    env.rid = 0;
  }

  if (u_runs) {
    if (filter && filter->stand_user_tree) {
      for (i = 1; i < u_max; ++i) {
        if (!state->users->user_map[i]) continue;
        if (state->u_contests[i]->status != 0) continue;
        f = state->u_contests[i]->flags;
        if ((f & (USERLIST_UC_INVISIBLE
                  | USERLIST_UC_BANNED
                  | USERLIST_UC_DISQUALIFIED)))
          continue;
        if (!u_runs[i]) continue;
        fake_entries[0].user_id = i;
        if (filter_tree_bool_eval(&env, filter->stand_user_tree) <= 0) continue;
        u_rev[i] = u_tot;
        u_ind[u_tot++] = i;
      }
    } else {
      for (i = 1; i < u_max; ++i) {
        if (!state->users->user_map[i]) continue;
        if (state->u_contests[i]->status != 0) continue;
        f = state->u_contests[i]->flags;
        if ((f & (USERLIST_UC_INVISIBLE
                  | USERLIST_UC_BANNED
                  | USERLIST_UC_DISQUALIFIED)))
          continue;
        if (!u_runs[i]) continue;
        u_rev[i] = u_tot;
        u_ind[u_tot++] = i;
      }
    }
  } else {
    if (filter && filter->stand_user_tree) {
      for (i = 1; i < u_max; ++i) {
        if (!state->users->user_map[i]) continue;
        if (state->u_contests[i]->status != 0) continue;
        f = state->u_contests[i]->flags;
        if ((f & (USERLIST_UC_INVISIBLE
                  | USERLIST_UC_BANNED
                  | USERLIST_UC_DISQUALIFIED)))
          continue;
        fake_entries[0].user_id = i;
        if (filter_tree_bool_eval(&env, filter->stand_user_tree) <= 0) continue;
        u_rev[i] = u_tot;
        u_ind[u_tot++] = i;
      }
    } else {
      for (i = 1; i < u_max; ++i) {
        if (!state->users->user_map[i]) continue;
        if (state->u_contests[i]->status != 0) continue;
        f = state->u_contests[i]->flags;
        if ((f & (USERLIST_UC_INVISIBLE
                  | USERLIST_UC_BANNED
                  | USERLIST_UC_DISQUALIFIED)))
          continue;
        u_rev[i] = u_tot;
        u_ind[u_tot++] = i;
      }
    }
  }

  /*
   * FIXME: why is that?
  env.mem = filter_tree_delete(env.mem);
  filter->stand_user_tree = 0;
  */
  *p_u_tot = u_tot;
}
