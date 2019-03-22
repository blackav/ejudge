/* -*- c -*- */

#ifndef __STATUSDB_H__
#define __STATUSDB_H__

/* Copyright (C) 2019 Alexander Chernov <cher@ejudge.ru> */

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

#include <stdint.h>

// number of problems with dynamic priority stored in serve_status structure
#define EJ_SERVE_STATUS_TOTAL_PROBS_NEW 32

/*
 * this structure is loaded from file into memory, it does not contain magic header
 */
struct prot_serve_status
{
    ej_time64_t cur_time;
    ej_time64_t start_time;
    ej_time64_t sched_time;
    ej_time64_t stop_time;
    ej_time64_t freeze_time;
    ej_time64_t finish_time;
    ej_time64_t stat_reported_before;
    ej_time64_t stat_report_time;
    ej_time64_t max_online_time;
    ej_time64_t last_daily_reminder;

    /* 80 */
    int32_t duration;
    int32_t total_runs;
    int32_t total_clars;
    int32_t download_interval;
    int32_t max_online_count;

    /* 100 */
    unsigned char clars_disabled;
    unsigned char team_clars_disabled;
    unsigned char standings_frozen;
    unsigned char score_system;
    unsigned char clients_suspended;
    unsigned char testing_suspended;
    unsigned char is_virtual;
    unsigned char continuation_enabled;
    unsigned char printing_enabled;
    unsigned char printing_suspended;
    unsigned char always_show_problems;
    unsigned char accepting_mode;

    // upsolving mode
    unsigned char upsolving_mode;
    unsigned char upsolving_freeze_standings;
    unsigned char upsolving_view_source;
    unsigned char upsolving_view_protocol;
    unsigned char upsolving_full_protocol;
    unsigned char upsolving_disable_clars;
    unsigned char testing_finished;

    signed char online_view_source;
    signed char online_view_report;
    unsigned char online_view_judge_score;
    unsigned char online_final_visibility;
    unsigned char online_valuer_judge_comments;

    unsigned char _pad[20];

    /* 144 */
    // priority adjustments for problems
    signed char   prob_prio[EJ_SERVE_STATUS_TOTAL_PROBS_NEW];
    /* 176 */
};

struct status_db_state;
struct ejudge_cfg;
struct contest_desc;
struct section_global_data;

struct status_db_state *
status_db_open(
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        const unsigned char *plugin_name,
        int flags);

void
status_db_close(
        struct status_db_state *sds);

int
status_db_load(
        struct status_db_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        struct prot_serve_status *stat);

int
status_db_save(
        struct status_db_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global,
        int flags,
        const struct prot_serve_status *stat);

void
status_db_remove(
        struct status_db_state *sds,
        const struct ejudge_cfg *config,
        const struct contest_desc *cnts,
        const struct section_global_data *global);

#endif /* __STATUSDB_H__ */
