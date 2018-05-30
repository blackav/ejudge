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
#include "ejudge/t3m_dir_listener.h"
#include "ejudge/list_ops.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <string.h>
#include <stdio.h>

struct dir_listener_state *
dir_listener_create(void)
{
  struct dir_listener_state *state = 0;

  XCALLOC(state, 1);
  return state;
}

int
dir_listener_add(
        struct dir_listener_state *state,
        const unsigned char *spool_dir,
        dir_listener_handler_t handler,
        dir_listener_checker_t checker,
        void *data)
{
  struct dir_listener_info *p = 0, *q;

  ASSERT(spool_dir);
  ASSERT(handler);

  for (p = state->first; p; p = p->next) {
    if (!strcmp(p->spool_dir, spool_dir))
      return -1;
  }

  XCALLOC(q, 1);
  q->spool_dir = xstrdup(spool_dir);
  q->handler = handler;
  q->checker = checker;
  q->data = data;
  LINK_LAST(q, state->first, state->last, prev, next);
  return 0;
}

int
dir_listener_remove(
        struct dir_listener_state *state,
        const unsigned char *spool_dir)
{
  struct dir_listener_info *p = 0;

  ASSERT(spool_dir);

  for (p = state->first; p; p = p->next) {
    if (!strcmp(p->spool_dir, spool_dir)) {
      UNLINK_FROM_LIST(p, state->first, state->last, prev, next);
      xfree(p->spool_dir);
      memset(p, 0, sizeof(*p));
      xfree(p);
      return 0;
    }
  }

  return -1;
}

int
dir_listener_find(
        struct dir_listener_state *state,
        const unsigned char *spool_dir,
        dir_listener_handler_t *p_handler,
        dir_listener_checker_t *p_checker,
        void **p_data)
{
  struct dir_listener_info *p;

  ASSERT(spool_dir);

  for (p = state->first; p; p = p->next) {
    if (!strcmp(p->spool_dir, spool_dir)) {
      if (p_handler) *p_handler = p->handler;
      if (p_checker) *p_checker = p->checker;
      if (p_data) *p_data = p->data;
      return 0;
    }
  }

  return -1;
}
