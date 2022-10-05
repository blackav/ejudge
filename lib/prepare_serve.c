/* -*- c -*- */

/* Copyright (C) 2005-2022 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/prepare.h"
#include "ejudge/varsubst.h"
#include "ejudge/version.h"
#include "ejudge/prepare_serve.h"
#include "ejudge/teamdb.h"
#include "ejudge/errlog.h"
#include "ejudge/serve_state.h"
#include "ejudge/runlog.h"
#include "ejudge/variant_map.h"
#include "ejudge/random.h"
#include "ejudge/variant_plugin.h"

#include "ejudge/xalloc.h"

static __attribute__((unused)) int
to_remove_find_variant(
        const serve_state_t state,
        int user_id,
        int prob_id,
        int *p_virtual_variant)
{
  int i, new_vint, ui;
  struct variant_map *pmap = NULL; //state->global->variant_map;
  struct variant_map_item *vi;
  const struct section_problem_data *prob = NULL;

  if (!pmap) return 0;
  if (prob_id <= 0 || prob_id > state->max_prob || !(prob = state->probs[prob_id])) return 0;
  if (prob->variant_num <= 0) return 0;
  if (!pmap->prob_map[prob_id]) return 0;

  teamdb_refresh(state->teamdb_state);
  new_vint = teamdb_get_vintage(state->teamdb_state);
  if (new_vint != pmap->vintage || !pmap->user_ind_size || !pmap->user_inds) {
    info("find_variant: new vintage: %d, old: %d, updating variant map", new_vint, pmap->vintage);
    xfree(pmap->user_inds);
    pmap->user_ind_size = 0;
    pmap->user_inds = NULL;

    if (state->global->disable_user_database > 0) {
      pmap->user_ind_size = run_get_max_user_id(state->runlog_state) + 1;
    } else {
      pmap->user_ind_size = teamdb_get_max_team_id(state->teamdb_state) + 1;
    }
    pmap->user_inds = malloc(pmap->user_ind_size * sizeof(pmap->user_inds[0]));
    memset(pmap->user_inds, -1, pmap->user_ind_size * sizeof(pmap->user_inds[0]));

    for (i = 0; i < pmap->u; i++) {
      pmap->v[i].user_id = teamdb_lookup_login(state->teamdb_state, pmap->v[i].login);
      if (pmap->v[i].user_id < 0) pmap->v[i].user_id = 0;
      if (!pmap->v[i].user_id) continue;
      if (pmap->v[i].user_id >= pmap->user_ind_size) continue;
      pmap->user_inds[pmap->v[i].user_id] = i;
    }
    pmap->vintage = new_vint;
  }

  if (user_id <= 0 || user_id >= pmap->user_ind_size) return 0;
  if ((ui = pmap->user_inds[user_id]) >= 0) {
    vi = pmap->v + ui;
    if (vi->real_variant) {
      if (p_virtual_variant) {
        if (vi->virtual_variant) *p_virtual_variant = vi->virtual_variant;
        else *p_virtual_variant = vi->real_variant;
      }
      // safety check
      if (vi->real_variant < 0 || vi->real_variant > prob->variant_num)
        return 0;
      return vi->real_variant;
    }
    if (p_virtual_variant)
      *p_virtual_variant = vi->variants[pmap->prob_map[prob_id]];
    int v = vi->variants[pmap->prob_map[prob_id]];
    if (!v && prob->autoassign_variants > 0) {
      v = random_range(1, prob->variant_num + 1);
      variant_map_set_variant(pmap, user_id,
                              teamdb_get_login(state->teamdb_state, user_id),
                              prob_id,
                              v);
      // FIXME: handle errors
      variant_map_save(stderr, pmap, state->global->variant_map_file, 1);
    }
    if (v < 0 || v > prob->variant_num)
      return 0;
    return v;
  } else if (prob->autoassign_variants > 0) {
    int v = random_range(1, prob->variant_num + 1);
    variant_map_set_variant(pmap, user_id,
                            teamdb_get_login(state->teamdb_state, user_id),
                            prob_id,
                            v);
    // FIXME: handle errors
    variant_map_save(stderr, pmap, state->global->variant_map_file, 1);
    if (v < 0 || v > prob->variant_num)
      return 0;
    return v;
  }
  return 0;
}

static __attribute__((unused)) int
to_remove_find_user_variant(
        const serve_state_t state,
        int user_id,
        int *p_virtual_variant)
{
  int i, new_vint, ui;
  struct variant_map *pmap = NULL; //state->global->variant_map;
  struct variant_map_item *vi;

  if (!pmap) return 0;

  teamdb_refresh(state->teamdb_state);
  new_vint = teamdb_get_vintage(state->teamdb_state);
  if (new_vint != pmap->vintage || !pmap->user_ind_size || !pmap->user_inds) {
    info("find_variant: new vintage: %d, old: %d, updating variant map", new_vint, pmap->vintage);
    xfree(pmap->user_inds);
    pmap->user_ind_size = 0;
    pmap->user_inds = NULL;

    if (state->global->disable_user_database > 0) {
      pmap->user_ind_size = run_get_max_user_id(state->runlog_state) + 1;
    } else {
      pmap->user_ind_size = teamdb_get_max_team_id(state->teamdb_state) + 1;
    }
    pmap->user_inds = malloc(pmap->user_ind_size * sizeof(pmap->user_inds[0]));
    memset(pmap->user_inds, -1, pmap->user_ind_size * sizeof(pmap->user_inds[0]));

    for (i = 0; i < pmap->u; i++) {
      pmap->v[i].user_id = teamdb_lookup_login(state->teamdb_state, pmap->v[i].login);
      if (pmap->v[i].user_id < 0) pmap->v[i].user_id = 0;
      if (!pmap->v[i].user_id) continue;
      if (pmap->v[i].user_id >= pmap->user_ind_size) continue;
      pmap->user_inds[pmap->v[i].user_id] = i;
    }
    pmap->vintage = new_vint;
  }

  if (user_id <= 0 || user_id >= pmap->user_ind_size) return 0;
  ui = pmap->user_inds[user_id];
  if (ui >= 0) {
    vi = pmap->v + ui;
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

    if (state->global->disable_user_database > 0) {
      pmap->user_map_size = run_get_max_user_id(state->runlog_state) + 1;
    } else {
      pmap->user_map_size = teamdb_get_max_team_id(state->teamdb_state) + 1;
    }
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
prepare_serve_defaults(
        const struct contest_desc *cnts,
        serve_state_t state,
        const struct contest_desc **p_cnts)
{
  int i;

#if defined EJUDGE_CONTESTS_DIR
  if (!state->global->contests_dir || !state->global->contests_dir[0]) {
    xstrdup3(&state->global->contests_dir, EJUDGE_CONTESTS_DIR);
  }
#endif /* EJUDGE_CONTESTS_DIR */
  if (!state->global->contests_dir || !state->global->contests_dir[0]) {
    err("global.contests_dir must be set");
    return -1;
  }
  if ((i = contests_set_directory(state->global->contests_dir)) < 0) {
    err("invalid contests directory '%s': %s", state->global->contests_dir,
        contests_strerror(-i));
    return -1;
  }
  if (p_cnts) {
    int contest_id = 0;
    if (cnts) {
      contest_id = cnts->id;
    } else {
      contest_id = state->global->contest_id;
    }
    if ((i = contests_get(contest_id, p_cnts)) < 0) {
      err("cannot load contest information: %s",
          contests_strerror(-i));
      return -1;
    }
    xstrdup3(&state->global->name, (*p_cnts)->name);
  }
  return 0;
}

int
find_variant(
        const serve_state_t state,
        int user_id,
        int prob_id,
        int *p_virtual_variant)
{
  if (!state->variant_state) return 0;

  return state->variant_state->vt->find_variant(
    state->variant_state,
    state,
    user_id,
    prob_id,
    p_virtual_variant);
}

int
find_user_variant(
        const serve_state_t state,
        int user_id,
        int *p_virtual_variant)
{
  if (!state->variant_state) return 0;

  return state->variant_state->vt->find_user_variant(
    state->variant_state,
    state,
    user_id,
    p_virtual_variant);
}
