/* -*- mode: c -*- */

/* Copyright (C) 2017 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/html.h"
#include "ejudge/prepare.h"

#include <string.h>

void
stand_setup_style(
        struct standings_style *ps,
        const struct section_global_data *global,
        int force_fancy_style)
{
    memset(ps, 0, sizeof(*ps));

    ps->table_attr = global->stand_table_attr;
    if (!ps->table_attr) ps->table_attr = "";

    if (!ps->table_attr[0]) {
        if (global->stand_fancy_style || force_fancy_style)
            ps->table_attr = " width=\"100%\" class=\"standings\"";
        else if (!global->stand_row_attr)
            ps->table_attr = " border=\"1\"";
    }

    ps->success_attr = global->stand_success_attr;
    if (!ps->success_attr) ps->success_attr = "";

    if (!(ps->place_attr = global->stand_place_attr)) ps->place_attr = "";
    if (!(ps->team_attr = global->stand_team_attr)) ps->team_attr = "";
    if (!(ps->extra_attr = global->stand_extra_attr)) ps->extra_attr = "";
    if (!(ps->prob_attr = global->stand_prob_attr)) ps->prob_attr = "";
    if (!(ps->solved_attr = global->stand_solved_attr)) ps->solved_attr = "";
    if (!(ps->score_attr = global->stand_score_attr)) ps->score_attr = "";
    if (!(ps->penalty_attr = global->stand_penalty_attr)) ps->penalty_attr = "";
    if (!(ps->time_attr = global->stand_time_attr)) ps->time_attr = "";
    if (!(ps->contestant_status_attr = global->stand_contestant_status_attr)) ps->contestant_status_attr = "";
    if (!(ps->warn_number_attr = global->stand_warn_number_attr)) ps->warn_number_attr = "";

    if (!(ps->self_row_attr = global->stand_self_row_attr)) ps->self_row_attr = "";
    if (!(ps->v_row_attr = global->stand_v_row_attr)) ps->v_row_attr = "";
    if (!(ps->r_row_attr = global->stand_r_row_attr)) ps->r_row_attr = "";
    if (!(ps->u_row_attr = global->stand_u_row_attr)) ps->u_row_attr = "";

    if (!(ps->fail_attr = global->stand_fail_attr)) ps->fail_attr = "";
    if (!(ps->trans_attr = global->stand_trans_attr)) ps->trans_attr = "";
    if (!(ps->disq_attr = global->stand_disq_attr)) ps->disq_attr = "";
    ps->pr_attr = NULL;
    ps->sm_attr = NULL;
    ps->rj_attr = NULL;

    if (!(ps->page_table_attr = global->stand_page_table_attr)) ps->page_table_attr = "";
    if (!(ps->page_cur_attr = global->stand_page_cur_attr)) ps->page_cur_attr = "";

    if (global->stand_fancy_style || force_fancy_style) {
        //ps->success_attr = global->stand_success_attr;

        if (!ps->place_attr[0])
            ps->place_attr = " class=\"st_place\"";
        if (!ps->team_attr[0])
            ps->team_attr = " class=\"st_team\"";
        if (!ps->extra_attr[0])
            ps->extra_attr = " class=\"st_extra\"";
        if (!ps->prob_attr[0])
            ps->prob_attr = " class=\"st_prob\"";
        if (!ps->solved_attr[0])
            ps->solved_attr = " class=\"st_total\"";
        if (!ps->score_attr[0])
            ps->score_attr = " class=\"st_score\"";
        if (!ps->penalty_attr[0])
            ps->penalty_attr = " class=\"st_pen\"";
        if (!ps->time_attr[0])
            ps->time_attr = " class=\"st_time\"";
        if (!ps->warn_number_attr[0])
            ps->warn_number_attr = " class=\"st_warns\"";
        if (!ps->contestant_status_attr[0])
            ps->contestant_status_attr = " class=\"st_status\"";

        //ps->self_row_attr = global->stand_self_row_attr;
        //ps->v_row_attr = global->stand_v_row_attr;
        //ps->r_row_attr = global->stand_r_row_attr;
        //ps->u_row_attr = global->stand_u_row_attr;

        if (!ps->fail_attr[0])
            ps->fail_attr = " class=\"st_prob cell_attr_cf\"";
        if (!ps->trans_attr[0])
            ps->trans_attr = " class=\"st_prob cell_attr_tr\"";
        if (!ps->disq_attr[0])
            ps->disq_attr = " class=\"st_prob cell_attr_dq\"";
        if (!ps->pr_attr || !*ps->pr_attr) {
            ps->pr_attr = " class=\"st_prob cell_attr_pr\"";
        }
        if (!ps->sm_attr || !*ps->sm_attr) {
            ps->sm_attr = " class=\"st_prob cell_attr_sm\"";
        }
        if (!ps->rj_attr || !*ps->rj_attr) {
            ps->rj_attr = " class=\"st_prob cell_attr_rj\"";
        }
        ps->first_attr = " class=\"st_prob cell_attr_first\"";

        //ps->page_table_attr = global->stand_page_table_attr;
        //ps->page_cur_attr = global->stand_page_cur_attr;
    }
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
