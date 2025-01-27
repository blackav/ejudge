/* -*- mode: c -*- */

/* Copyright (C) 2025 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/version.h"
#include "ejudge/super-serve.h"
#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <string.h>
#include <time.h>

static struct sid_state *sid_state_first = NULL;
static struct sid_state *sid_state_last = NULL;
static time_t sid_state_last_check_time = 0;

#define SID_STATE_CLEANUP_TIME (24*3600)
#define SID_STATE_CHECK_INTERVAL 3600

struct sid_state*
sid_state_find(ej_cookie_t sid)
{
  struct sid_state *p;

  ASSERT(sid);
  for (p = sid_state_first; p; p = p->next)
    if (p->sid == sid) break;
  return p;
}

struct sid_state*
sid_state_add(
        ej_cookie_t sid,
        const ej_ip_t *remote_addr,
        int user_id,
        const unsigned char *user_login,
        const unsigned char *user_name)
{
  struct sid_state *n;

  ASSERT(sid);
  XCALLOC(n, 1);
  n->sid = sid;
  n->remote_addr = *remote_addr;
  n->init_time = time(0);
  n->flags |= SID_STATE_SHOW_CLOSED;
  n->user_id = user_id;
  n->user_login = xstrdup(user_login);
  n->user_name = xstrdup(user_name);

  if (!sid_state_last) {
    ASSERT(!sid_state_first);
    sid_state_first = sid_state_last = n;
  } else {
    ASSERT(sid_state_first);
    sid_state_last->next = n;
    n->prev = sid_state_last;
    sid_state_last = n;
  }
  return n;
}

struct sid_state*
sid_state_get(
        ej_cookie_t sid,
        const ej_ip_t *remote_addr,
        int user_id,
        const unsigned char *user_login,
        const unsigned char *user_name)
{
  struct sid_state *p;

  if (!(p = sid_state_find(sid)))
    p = sid_state_add(sid, remote_addr, user_id, user_login, user_name);
  return p;
}

void
sid_state_clear(struct sid_state *p)
{
    void *config = NULL; ////////////////////////// FIXME

  super_serve_clear_edited_contest(p);
  xfree(p->user_login);
  xfree(p->user_name);
  xfree(p->user_filter);
  bitset_free(&p->marked);
  serve_state_destroy(NULL, config, p->te_state, NULL, NULL);
  update_state_free(p->update_state);
  XMEMZERO(p, 1);
}

struct sid_state*
sid_state_delete(struct sid_state *p)
{
  ASSERT(p);
  if (!p->prev) {
    sid_state_first = p->next;
  } else {
    p->prev->next = p->next;
  }
  if (!p->next) {
    sid_state_last = p->prev;
  } else {
    p->next->prev = p->prev;
  }
  sid_state_clear(p);
  xfree(p);
  return 0;
}

void
sid_state_cleanup(void)
{
  time_t cur_time;
  struct sid_state *p;

  cur_time = time(0);
  do {
    for (p = sid_state_first; p; p = p->next) {
      if (p->init_time + SID_STATE_CLEANUP_TIME < cur_time) {
        sid_state_delete(p);
        break;
      }
    }
  } while (p);
}

int
super_serve_sid_state_get_max_edited_cnts(void)
{
  struct sid_state *p;
  int max_cnts_id = 0;

  for (p = sid_state_first; p; p = p->next) {
    if (p->edited_cnts && p->edited_cnts->id > max_cnts_id)
      max_cnts_id = p->edited_cnts->id;
  }
  return max_cnts_id;
}

const struct sid_state*
super_serve_sid_state_get_cnts_editor(int contest_id)
{
  struct sid_state *p;

  for (p = sid_state_first; p; p = p->next)
    if (p->edited_cnts && p->edited_cnts->id == contest_id)
      return p;
  return 0;
}

struct sid_state*
super_serve_sid_state_get_cnts_editor_nc(int contest_id)
{
  struct sid_state *p;

  for (p = sid_state_first; p; p = p->next)
    if (p->edited_cnts && p->edited_cnts->id == contest_id)
      return p;
  return 0;
}

const struct sid_state*
super_serve_sid_state_get_test_editor(int contest_id)
{
  struct sid_state *p;

  for (p = sid_state_first; p; p = p->next)
    if (p->te_state && p->te_state->contest_id == contest_id)
      return p;
  return 0;
}

struct sid_state*
super_serve_sid_state_get_test_editor_nc(int contest_id)
{
  struct sid_state *p;

  for (p = sid_state_first; p; p = p->next)
    if (p->te_state && p->te_state->contest_id == contest_id)
      return p;
  return 0;
}

struct sid_state *
super_serve_sid_state_get_first(void)
{
  return sid_state_first;
}

void
super_serve_sid_state_clear(ej_cookie_t sid)
{
  struct sid_state *p = sid_state_find(sid);
  if (p) {
    sid_state_delete(p);
  }
}

void
super_serve_sid_state_cleanup(time_t current_time)
{
  if (sid_state_last_check_time < current_time + SID_STATE_CHECK_INTERVAL) {
    sid_state_cleanup();
    sid_state_last_check_time = current_time;
  }
}