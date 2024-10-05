/* -*- c -*- */
#ifndef __INTERNAL_PAGES_H__
#define __INTERNAL_PAGES_H__

/* Copyright (C) 2017-2024 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/ej_types.h"

#include "ejudge/external_action.h"

typedef struct StandingsCell
{
    ej_time64_t sol_time; // solution time
    ej_time64_t eff_time; // effective time (for enable_submit_after_reject)
    ej_time64_t last_fogged_time; // the last submit made during standings fog period
    int score;       // the standings score for the cell
    int att_num;     // the number of attempts
    int disq_num;    // the number of disqualified attempts
    int ce_num;      // the number of compilation error attempts
    int sol_att;     // the number of attempts before successful solution
    int trans_num;   // the number of "transient" runs
    int penalty;     // the cell penalty
    int cf_num;      // the number of check failed runs
    unsigned short fogged_num; // the number of fogged submits
    unsigned char full_sol; // 1, if full solution
    unsigned char pr_flag;  // 1, if pending review
    unsigned char sm_flag;  // 1, if summoned for defence
    unsigned char rj_flag;  // 1, if rejected
    unsigned char marked_flag; // 1, if marked
    unsigned char first_solver; // 1, if first solution of the problem
    int group_count;        // the count of test groups (if enable_group_merge is set)
    int group_scores[15];   // the test group scores (if enable_group_merge is set)
} StandingsCell;

typedef struct StandingsUserRow
{
    time_t start_time; // user personal start time (for virtual contests)
    time_t stop_time; // user personal stop time (for virtual contests)
    int tot_score; // the total score
    int tot_full;  // the number of completely solved problems
    int tot_penalty; // the total penalty
    const unsigned char *name;
    unsigned char *avatar_url;
} StandingsUserRow;

typedef struct StandingsProblemColumn
{
    int succ_att; // successful attempts
    int tot_att; // total attempts
    int is_solved; // if this problem is already solved, used for first_solver computation
} StandingsProblemColumn;

typedef struct StandingsPlace
{
    int t_n1;
    int t_n2;
} StandingsPlace;

typedef struct StandingsTablePage
{
    unsigned char *pgref;
    int pg_n1;
    int pg_n2;
} StandingsTablePage;

typedef struct StandingsPage
{
    PageInterface b;

    int separate_user_score;
    time_t start_time; // contest/virtual start time, <= 0 --- contest is not started
    time_t stop_time; // contest/virtual stop_time, <= 0 --- contest is not stopped
    time_t duration; // contest duration ( <= 0 --- unlimited contest)
    time_t cur_time; // time moment for standings generation
    time_t cur_duration; // duration from the start to the current time moment
    time_t user_start_time; // user-specific start time (esp. for virtual users)
    time_t user_stop_time;  // user-specific stop time
    time_t user_duration;

    int r_beg; // first loaded run
    int r_tot; // total number of runs
    const struct run_entry *runs;

    int t_max; // size of user_id indices (i.e. max user_id + 1)
    int t_tot; // total number of indexed participants
    int *t_ind; // t_ind[0..t_tot-1] - index array:   team_idx -> team_id
    int *t_rev; // t_rev[0..t_max-1] - reverse index: team_id -> team_idx

    int p_max; // size of prob_id indices (i.e. max_prob + 1)
    int p_tot; // total number of indexed problems
    int *p_ind; // index array:   prob_idx -> prob_id
    int *p_rev; // reverse index: prob_id -> prob_idx
    int last_col_ind; // index of the "last" column in the standings

    int row_sz; // number of elements in the standings row, always power of 2, so << operation can be used
    int row_sh; // shift for standings row

    int last_submit_run;
    int last_success_run;

    int total_prs;
    int total_summoned;
    int total_disqualified;
    int total_rejected;
    int total_pending;
    int total_accepted;
    int total_trans;
    int total_check_failed;

    StandingsCell *cells;
    StandingsUserRow *rows;
    StandingsProblemColumn *columns;
    StandingsPlace *places;
    int *t_sort;

    int total_pages;
    StandingsTablePage *pages;

    struct xuser_team_extras *extras;
    int not_started_flag;
    time_t duration_before_fog;
    int fog_flag;
    int unfog_flag;
} StandingsPage;

#endif

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
