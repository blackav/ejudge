/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"

#include "prepare.h"
#include "settings.h"
#include "varsubst.h"
#include "version.h"
#include "prepare_serve.h"
#include "teamdb.h"
#include "errlog.h"
#include "serve_state.h"

#include <reuse/xalloc.h>

int
find_variant(
        const serve_state_t state,
        int user_id,
        int prob_id,
        int *p_virtual_variant)
{
  int i, new_vint;
  struct variant_map *pmap = state->global->variant_map;
  struct variant_map_item *vi;

  if (!pmap) return 0;
  if (prob_id <= 0 || prob_id > state->max_prob || !state->probs[prob_id]) return 0;
  if (state->probs[prob_id]->variant_num <= 0) return 0;
  if (!pmap->prob_map[prob_id]) return 0;

  teamdb_refresh(state->teamdb_state);
  new_vint = teamdb_get_vintage(state->teamdb_state);
  if (new_vint != pmap->vintage || !pmap->user_map_size || !pmap->user_map) {
    info("find_variant: new vintage: %d, old: %d, updating variant map",
         new_vint, pmap->vintage);
    xfree(pmap->user_map);
    pmap->user_map_size = 0;
    pmap->user_map = 0;

    pmap->user_map_size = teamdb_get_max_team_id(state->teamdb_state) + 1;
    XCALLOC(pmap->user_map, pmap->user_map_size);

    for (i = 0; i < pmap->u; i++) {
      pmap->v[i].user_id = teamdb_lookup_login(state->teamdb_state, pmap->v[i].login);
      if (pmap->v[i].user_id < 0) pmap->v[i].user_id = 0;
      if (!pmap->v[i].user_id) continue;
      if (pmap->v[i].user_id >= pmap->user_map_size) continue;
      pmap->user_map[pmap->v[i].user_id] = &pmap->v[i];
    }
    pmap->vintage = new_vint;
  }

  if (user_id <= 0 || user_id >= pmap->user_map_size) return 0;
  if ((vi = pmap->user_map[user_id])) {
    if (vi->real_variant) {
      if (p_virtual_variant) {
        if (vi->virtual_variant) *p_virtual_variant = vi->virtual_variant;
        else *p_virtual_variant = vi->real_variant;
      }
      return vi->real_variant;
    }
    if (p_virtual_variant)
      *p_virtual_variant = vi->variants[pmap->prob_map[prob_id]];
    return vi->variants[pmap->prob_map[prob_id]];
  }
  return 0;
}

int
find_user_variant(
        const serve_state_t state,
        int user_id,
        int *p_virtual_variant)
{
  int i, new_vint;
  struct variant_map *pmap = state->global->variant_map;
  struct variant_map_item *vi;

  if (!pmap) return 0;

  teamdb_refresh(state->teamdb_state);
  new_vint = teamdb_get_vintage(state->teamdb_state);
  if (new_vint != pmap->vintage || !pmap->user_map_size || !pmap->user_map) {
    info("find_variant: new vintage: %d, old: %d, updating variant map",
         new_vint, pmap->vintage);
    xfree(pmap->user_map);
    pmap->user_map_size = 0;
    pmap->user_map = 0;

    pmap->user_map_size = teamdb_get_max_team_id(state->teamdb_state) + 1;
    XCALLOC(pmap->user_map, pmap->user_map_size);

    for (i = 0; i < pmap->u; i++) {
      pmap->v[i].user_id = teamdb_lookup_login(state->teamdb_state, pmap->v[i].login);
      if (pmap->v[i].user_id < 0) pmap->v[i].user_id = 0;
      if (!pmap->v[i].user_id) continue;
      if (pmap->v[i].user_id >= pmap->user_map_size) continue;
      pmap->user_map[pmap->v[i].user_id] = &pmap->v[i];
    }
    pmap->vintage = new_vint;
  }

  if (user_id <= 0 || user_id >= pmap->user_map_size) return 0;
  if ((vi = pmap->user_map[user_id])) {
    if (vi->real_variant) {
      if (p_virtual_variant) {
        if (vi->virtual_variant) *p_virtual_variant = vi->virtual_variant;
        else *p_virtual_variant = vi->real_variant;
      }
      return vi->real_variant;
    }
    if (p_virtual_variant) *p_virtual_variant = 0;
    return 0;
  }
  return 0;
}

int
find_user_priority_adjustment(const serve_state_t state, int user_id)
{
  struct user_adjustment_map *pmap = state->global->user_adjustment_map;
  struct user_adjustment_info *pinfo = state->global->user_adjustment_info;
  int new_vint, i;

  if (!pinfo) return 0;
  new_vint = teamdb_get_vintage(state->teamdb_state);
  if (!pmap || new_vint != pmap->vintage) {
    if (!pmap) {
      XCALLOC(pmap, 1);
      state->global->user_adjustment_map = pmap;
    }
    xfree(pmap->user_map);

    pmap->user_map_size = teamdb_get_max_team_id(state->teamdb_state) + 1;
    XCALLOC(pmap->user_map, pmap->user_map_size);

    for (i = 0; pinfo[i].login; i++) {
      pinfo[i].id = teamdb_lookup_login(state->teamdb_state, pinfo[i].login);
      if (pinfo[i].id <= 0 || pinfo[i].id >= pmap->user_map_size) {
        pinfo[i].id = 0;
        continue;
      }
      if (pmap->user_map[pinfo[i].id]) continue;
      pmap->user_map[pinfo[i].id] = &pinfo[i];
    }

    pmap->vintage = new_vint;
  }

  if (user_id <= 0 || user_id >= pmap->user_map_size) return 0;
  if (!pmap->user_map[user_id]) return 0;
  return pmap->user_map[user_id]->adjustment;
}

int
prepare_serve_defaults(serve_state_t state, const struct contest_desc **p_cnts)
{
  int i;

#if defined EJUDGE_CONTESTS_DIR
  if (!state->global->contests_dir[0]) {
    snprintf(state->global->contests_dir, sizeof(state->global->contests_dir),
             "%s", EJUDGE_CONTESTS_DIR);
  }
#endif /* EJUDGE_CONTESTS_DIR */
  if (!state->global->contests_dir[0]) {
    err("global.contests_dir must be set");
    return -1;
  }
  if ((i = contests_set_directory(state->global->contests_dir)) < 0) {
    err("invalid contests directory '%s': %s", state->global->contests_dir,
        contests_strerror(-i));
    return -1;
  }
  if (p_cnts) {
    if ((i = contests_get(state->global->contest_id, p_cnts)) < 0) {
      err("cannot load contest information: %s",
          contests_strerror(-i));
      return -1;
    }
    snprintf(state->global->name, sizeof(state->global->name), "%s",
             (*p_cnts)->name);
  }
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
