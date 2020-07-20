/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2010-2014 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/config.h"
#include "ejudge/ej_limits.h"
#include "ejudge/t3m_submits.h"
#include "ejudge/list_ops.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <stdio.h>
#include <stdlib.h>

struct submit_block_state *
submit_block_create(void)
{
  struct submit_block_state *p = 0;

  XCALLOC(p, 1);
  return p;
}

void
submit_block_add(
        struct submit_block_state *state,
        int contest_id,
        int first_run_id,
        int submit_count,
        submit_block_compile_result_handler_t compile_result_handler,
        submit_block_run_result_handler_t run_result_handler,
        void *data)
{
  struct submit_block_info *p;

  ASSERT(state);
  ASSERT(contest_id > 0);
  ASSERT(first_run_id >= 0);
  ASSERT(submit_count > 0);

  // check for overlaying packet
  for (p = state->first; p; p = p->next) {
    if (p->contest_id == contest_id
        && ((p->first_run_id < first_run_id + submit_count
             && p->first_run_id >= first_run_id)
            || (first_run_id < p->first_run_id + p->submit_count
                && first_run_id >= p->first_run_id))) {
      fprintf(stderr, "overlaying packets: contest_id=%d: (%d, %d), (%d, %d)",
              p->contest_id, p->first_run_id, p->submit_count,
              first_run_id, submit_count);
      abort();
    }
  }

  XCALLOC(p, 1);
  p->contest_id = contest_id;
  p->first_run_id = first_run_id;
  p->submit_count = submit_count;
  p->data = data;
  p->compile_result_handler = compile_result_handler;
  p->run_result_handler = run_result_handler;
  LINK_LAST(p, state->first, state->last, prev, next);
}

void
submit_block_remove(
        struct submit_block_state *state,
        int contest_id,
        int first_run_id,
        int submit_count)
{
  struct submit_block_info *p;

  for (p = state->first; p; p = p->next) {
    if (p->contest_id == contest_id && p->first_run_id == first_run_id
        && p->submit_count == submit_count) {
      break;
    }
  }
  if (!p) return;

  UNLINK_FROM_LIST(p, state->first, state->last, prev, next);
  // FIXME: free 'p' item
}

struct submit_block_info *
submit_block_find(
        struct submit_block_state *state,
        int contest_id,
        int run_id)
{
  struct submit_block_info *p;

  for (p = state->first; p; p = p->next) {
    if (p->contest_id == contest_id && p->first_run_id <= run_id
        && p->first_run_id + p->submit_count > run_id) {
      return p;
    }
  }

  return 0;
}
