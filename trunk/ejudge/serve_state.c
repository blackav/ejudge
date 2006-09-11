/* -*- mode: c -*- */
/* $Id$ */

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

#include "serve_state.h"
#include "filter_tree.h"
#include "runlog.h"
#include "team_extra.h"
#include "teamdb.h"
#include "clarlog.h"
#include "prepare.h"

#include <reuse/xalloc.h>

#include <string.h>

serve_state_t
serve_state_init(void)
{
  serve_state_t state;

  XCALLOC(state, 1);
  state->clarlog_state = clar_init();
  state->teamdb_state = teamdb_init();
  state->team_extra_state = team_extra_init();
  state->runlog_state = run_init(state->teamdb_state);
  return state;
}

serve_state_t
serve_state_destroy(serve_state_t state)
{
  int i;
  struct user_filter_info *ufp, *ufp2;

  run_destroy(state->runlog_state);
  team_extra_destroy(state->team_extra_state);
  teamdb_destroy(state->teamdb_state);
  clar_destroy(state->clarlog_state);

  prepare_free_config(state->config);

  for (i = 0; i < state->users_a; i++) {
    for (ufp = state->users[i]->first_filter; ufp; ufp = ufp2) {
      ufp2 = ufp->next;
      xfree(ufp->prev_filter_expr);
      xfree(ufp->error_msgs);
      filter_tree_delete(ufp->tree_mem);
      xfree(ufp);
    }
    xfree(state->users[i]);
  }
  xfree(state->users);

  for (i = 0; i < state->compile_dirs_u; i++) {
    xfree(state->compile_dirs[i].status_dir);
    xfree(state->compile_dirs[i].report_dir);
  }
  xfree(state->compile_dirs);
  for (i = 0; i < state->run_dirs_u; i++) {
    xfree(state->run_dirs[i].status_dir);
    xfree(state->run_dirs[i].report_dir);
    xfree(state->run_dirs[i].team_report_dir);
    xfree(state->run_dirs[i].full_report_dir);
  }
  xfree(state->run_dirs);

  memset(state, 0, sizeof(*state));
  xfree(state);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
