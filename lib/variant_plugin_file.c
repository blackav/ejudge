/* -*- mode: c; c-basic-offset: 4 -*- */

/* Copyright (C) 2022 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/common_plugin.h"
#include "ejudge/variant_plugin.h"
#include "ejudge/contests.h"
#include "ejudge/variant_map.h"
#include "ejudge/serve_state.h"
#include "ejudge/teamdb.h"
#include "ejudge/runlog.h"
#include "ejudge/prepare.h"
#include "ejudge/random.h"
#include "ejudge/xalloc.h"
#include "ejudge/errlog.h"

#include <string.h>

struct variant_file_data
{
    struct variant_plugin_data b;
    int nref;
};

static struct common_plugin_data *
init_func(void)
{
    struct variant_file_data *state = NULL;
    XCALLOC(state, 1);
    return &state->b.b;
}

static int
finish_func(struct common_plugin_data *data)
{
    return 0;
}

static int
prepare_func(
        struct common_plugin_data *data,
        const struct ejudge_cfg *config,
        struct xml_tree *tree)
{
    struct variant_file_data *vmd = (struct variant_file_data *) data;
    (void) vmd;

    return 0;
}

struct variant_cnts_file_data
{
    struct variant_cnts_plugin_data b;
    struct variant_file_data *vfd;
    int contest_id;
    struct variant_map *vmap;
};

extern struct variant_plugin_iface plugin_variant_file;

static struct variant_cnts_plugin_data *
open_func(
        struct common_plugin_data *data,
        FILE *log_f,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct serve_state *state,
        int flags)
{
    struct variant_file_data *vfd = (struct variant_file_data *) data;

    struct variant_cnts_file_data *vcfd = NULL;
    XCALLOC(vcfd, 1);
    vcfd->b.vt = &plugin_variant_file;
    vcfd->vfd = vfd;
    vcfd->contest_id = cnts->id;
    ++vfd->nref;

    const unsigned char *path = state->global->variant_map_file;
    if (path && *path) {
        vcfd->vmap = variant_map_parse(log_f, state, path);
        if (!vcfd->vmap) goto fail;
    }

    return &vcfd->b;

fail:
    if (vcfd) {
        vcfd->b.vt->close(&vcfd->b);
    }
    return NULL;
}

static struct variant_cnts_plugin_data *
close_func(
        struct variant_cnts_plugin_data *data)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;
    if (vcfd) {
        variant_map_free(vcfd->vmap);
        if (vcfd->vfd && vcfd->vfd->nref > 0) {
            --vcfd->vfd->nref;
        }
        xfree(vcfd);
    }
    return NULL;
}

static int
find_variant_func(
        struct variant_cnts_plugin_data *data,
        const struct serve_state *state,
        int user_id,
        int prob_id,
        int *p_virtual_variant)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;

    int i, new_vint, ui;
    struct variant_map *pmap = vcfd->vmap;
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

static int
find_user_variant_func(
        struct variant_cnts_plugin_data *data,
        const struct serve_state *state,
        int user_id,
        int *p_virtual_variant)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;

    int i, new_vint, ui;
    struct variant_map *pmap = vcfd->vmap;
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

static int
get_entry_count_func(
        struct variant_cnts_plugin_data *data)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;
    if (!vcfd->vmap) return 0;
    return vcfd->vmap->u;
}

static int
get_keys_func(
        struct variant_cnts_plugin_data *data,
        int *p_count,
        int64_t **p_keys)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;
    if (!vcfd->vmap || !vcfd->vmap->u) {
        *p_count = 0;
        *p_keys = NULL;
        return 0;
    }
    int64_t *keys = NULL;
    XCALLOC(keys, vcfd->vmap->u);
    for (int64_t i = 0; i < vcfd->vmap->u; ++i) {
        keys[i] = i;
    }
    *p_count = vcfd->vmap->u;
    *p_keys = keys;
    return vcfd->vmap->u;
}

static unsigned char *
get_login_func(
        struct variant_cnts_plugin_data *data,
        int64_t key)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;
    if (key < 0 || key >= vcfd->vmap->u) return NULL;
    unsigned char *login = vcfd->vmap->v[key].login;
    if (!login) return NULL;
    return xstrdup(login);
}

static int
get_user_variant_func(
        struct variant_cnts_plugin_data *data,
        int64_t key,
        int *p_virtual_variant)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;
    if (key < 0 || key >= vcfd->vmap->u) return 0;
    struct variant_map_item *vi = &vcfd->vmap->v[key];
    if (vi->real_variant <= 0) return 0;
    if (p_virtual_variant) {
        if (vi->virtual_variant >= 0) {
            *p_virtual_variant = vi->virtual_variant;
        } else {
            *p_virtual_variant = vi->real_variant;
        }
    }
    return vi->real_variant;
}

static int
get_problem_ids_func(
        struct variant_cnts_plugin_data *data,
        int *p_count,
        int **p_ids)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;
    struct variant_map *pmap = vcfd->vmap;
    if (!pmap || pmap->var_prob_num <= 0) {
        *p_count = 0;
        *p_ids = NULL;
        return 0;
    }
    int *ids = NULL;
    XCALLOC(ids, pmap->var_prob_num);
    for (int i = 0; i < pmap->var_prob_num; ++i) {
        ids[i] = pmap->prob_rev_map[i + 1];
    }
    *p_count = pmap->var_prob_num;
    *p_ids = ids;
    return pmap->var_prob_num;
}

static int
get_variant_func(
        struct variant_cnts_plugin_data *data,
        int64_t key,
        int prob_id)
{
    struct variant_cnts_file_data *vcfd = (struct variant_cnts_file_data *) data;
    struct variant_map *pmap = vcfd->vmap;
    if (key < 0 || key >= vcfd->vmap->u) {
        return 0;
    }
    if (prob_id <= 0 || prob_id >= pmap->prob_map_size) {
        return 0;
    }
    struct variant_map_item *vi = &vcfd->vmap->v[key];
    return vi->variants[pmap->prob_map[prob_id]];
}

struct variant_plugin_iface plugin_variant_file =
{
    {
        {
            sizeof (struct variant_plugin_iface),
            EJUDGE_PLUGIN_IFACE_VERSION,
            "variant",
            "file",
        },
        COMMON_PLUGIN_IFACE_VERSION,
        init_func,
        finish_func,
        prepare_func,
    },
    VARIANT_PLUGIN_IFACE_VERSION,
    open_func,
    close_func,
    find_variant_func,
    find_user_variant_func,
    get_entry_count_func,
    get_keys_func,
    get_login_func,
    get_user_variant_func,
    get_problem_ids_func,
    get_variant_func,
};
