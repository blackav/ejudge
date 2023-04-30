/* -*- c -*- */

/* Copyright (C) 2017-2023 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/new-server.h"
#include "ejudge/internal_pages.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/external_action.h"
#include "ejudge/prepare.h"
#include "ejudge/filter_eval.h"
#include "ejudge/new_server_pi.h"
#include "ejudge/team_extra.h"
#include "ejudge/xuser_plugin.h"
#include "ejudge/content_plugin.h"
#include "ejudge/userlist.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"

#include <string.h>

extern int
csp_view_int_standings(
        PageInterface *ps,
        FILE *log_f,
        FILE *out_f,
        struct http_request_info *phr);
static int
csp_execute_int_standings(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr);
static void
csp_destroy_int_standings(
        PageInterface *ps);

static struct PageInterfaceOps ops __attribute__((unused)) =
{
    csp_destroy_int_standings,
    csp_execute_int_standings,
    csp_view_int_standings,
};

PageInterface *
csp_get_int_standings(void)
{
    StandingsPage *pg = NULL;

    XCALLOC(pg, 1);
    pg->b.ops = &ops;
    pg->last_col_ind = -1;
    pg->last_submit_run = -1;
    pg->last_success_run = -1;
    return (PageInterface*) pg;
}

static void
csp_destroy_int_standings(
        PageInterface *ps)
{
    StandingsPage *pg = (StandingsPage *) ps;
    if (pg->pages) {
        for (int i = 0; i < pg->total_pages; ++i) {
            xfree(pg->pages[i].pgref);
        }
        xfree(pg->pages);
    }
    xfree(pg->t_sort);
    xfree(pg->places);
    xfree(pg->columns);
    if (pg->rows) {
        for (int i = 0; i < pg->t_tot; ++i) {
            xfree(pg->rows[i].avatar_url);
        }
        xfree(pg->rows);
    }
    xfree(pg->cells);
    xfree(pg->p_ind);
    xfree(pg->p_rev);
    if (pg->extras) pg->extras->free(pg->extras);
    xfree(pg->t_ind);
    xfree(pg->t_rev);
    xfree(pg);
}

void
get_problem_map(
        const serve_state_t state,
        time_t cur_time,        /* the current time */
        int *p_rev,             /* prob_id -> prob_ind map */
        int p_max,              /* the size of the probs */
        int *p_ind,             /* the problem index array */
        int *p_p_tot,           /* [OUT] the size of the problem index array */
        int *p_last_col_ind,    /* [OUT] the index of the last column prob */
        struct user_filter_info *filter);
static int
sec_to_min(int rounding_mode, int secs)
{
  switch (rounding_mode) {
  case SEC_CEIL:
    return (secs + 59) / 60;
  case SEC_FLOOR:
    return secs / 60;
  case SEC_ROUND:
    return (secs + 30) / 60;
  }
  abort();
}
int
calc_kirov_score(
        unsigned char *outbuf,
        size_t outsize,
        time_t start_time,
        int separate_user_score,
        int user_mode,
        int token_flags,
        const struct run_entry *pe,
        const struct section_problem_data *pr,
        int attempts,
        int disq_attempts,
        int ce_attempts,
        int prev_successes,
        int *p_date_penalty,
        int format,
        time_t effective_time);

static void
process_acm_run(
    StandingsPage *pg,
    StandingsExtraInfo *sii,
    struct serve_state *cs,
    int run_id,
    const struct run_entry *pe,
    int need_eff_time)
{
    const struct section_global_data *global = cs->global;
    int tind = pg->t_rev[pe->user_id];
    int pind = pg->p_rev[pe->prob_id];
    int up_ind = (tind << pg->row_sh) + pind;
    const struct section_problem_data *prob = cs->probs[pe->prob_id];
    StandingsCell *cell = &pg->cells[up_ind];
    StandingsUserRow *row = &pg->rows[tind];
    StandingsProblemColumn *col = &pg->columns[pind];
    time_t run_time = pe->time;
    time_t run_duration = run_time - row->start_time;
    if (run_duration < 0) run_duration = 0;

    if (pe->status == RUN_OK) {
        if (cell->full_sol) return;
        pg->last_success_run = run_id;
        pg->last_submit_run = run_id;
        cell->full_sol = 1;
        cell->penalty += prob->acm_run_penalty * cell->sol_att;
        cell->sol_time = run_time;
        cell->eff_time = sec_to_min(global->rounding_mode, run_duration);
        if (global->ignore_success_time <= 0) {
            cell->penalty += cell->eff_time;
        }
        ++col->succ_att;
        ++col->tot_att;
        if (!col->is_solved) {
            if (global->is_virtual <= 0 && global->stand_show_first_solver > 0) {
                cell->first_solver = 1;
            }
            col->is_solved = 1;
        }
    } else if (pe->status == RUN_COMPILE_ERR && prob->ignore_compile_errors <= 0) {
        if (cell->full_sol) return;
        pg->last_submit_run = run_id;
        ++cell->sol_att;
        ++col->tot_att;
    } else if (run_is_failed_attempt(pe->status)) {
        if (cell->full_sol) return;
        pg->last_submit_run = run_id;
        ++cell->sol_att;
        ++col->tot_att;
    } else if (pe->status == RUN_DISQUALIFIED) {
        ++cell->disq_num;
    } else if (pe->status == RUN_PENDING_REVIEW || pe->status == RUN_SUMMONED) {
        cell->pr_flag = 1;
    } else if (pe->status == RUN_PENDING || pe->status == RUN_ACCEPTED) {
        ++cell->trans_num;
    } else if (pe->status >= RUN_TRANSIENT_FIRST && pe->status <= RUN_TRANSIENT_LAST) {
        ++cell->trans_num;
    } else if (pe->status == RUN_CHECK_FAILED) {
        ++cell->cf_num;
    }
}

static void
sort_acm(
        StandingsPage *pg,
        StandingsExtraInfo *sii,
        struct serve_state *cs)
{
    if (pg->t_tot <= 0) return;

    int max_pen = -1;
    int max_solved = -1;
    for (int i = 0; i < pg->t_tot; ++i) {
        StandingsUserRow *row = &pg->rows[i];
        ASSERT(row->tot_full >= 0);
        ASSERT(row->tot_penalty >= 0);
        if (row->tot_full > max_solved) max_solved = row->tot_full;
        if (row->tot_penalty > max_pen) max_pen = row->tot_penalty;
    }

    int *prob_cnt = NULL;
    XALLOCAZ(prob_cnt, max_solved + 1);
    int *pen_cnt = NULL;
    XCALLOC(pen_cnt, max_pen + 1);

    for (int i = 0; i < pg->t_tot; ++i) {
        StandingsUserRow *row = &pg->rows[i];
        ++prob_cnt[row->tot_full];
        ++pen_cnt[row->tot_penalty];
    }
    int i = 0;
    for (int t = max_solved - 1; t >= 0; --t) {
        int j = prob_cnt[t + 1] + i;
        prob_cnt[t + 1] = i;
        i = j;
    }
    prob_cnt[0] = i;
    i = 0;
    int t;
    for (t = 1; t <= max_pen; ++t) {
        int j = pen_cnt[t - 1] + i;
        pen_cnt[t - 1] = i;
        i = j;
    }
    pen_cnt[t - 1] = i;
    int *t_sort2 = NULL;
    XALLOCA(t_sort2, pg->t_tot);
    XCALLOC(pg->t_sort, pg->t_tot);
    for (t = 0; t < pg->t_tot; ++t) {
        StandingsUserRow *row = &pg->rows[t];
        t_sort2[pen_cnt[row->tot_penalty]++] = t;
    }
    for (t = 0; t < pg->t_tot; ++t) {
        StandingsUserRow *row = &pg->rows[t_sort2[t]];
        pg->t_sort[prob_cnt[row->tot_full]++] = t_sort2[t];
    }

    /* now resolve ties */
    for(i = 0; i < pg->t_tot;) {
        int j;
        for (j = i + 1; j < pg->t_tot; ++j) {
            StandingsUserRow *ri = &pg->rows[pg->t_sort[i]];
            StandingsUserRow *rj = &pg->rows[pg->t_sort[j]];
            if (ri->tot_full != rj->tot_full || ri->tot_penalty != rj->tot_penalty) break;
        }
        for (int k = i; k < j; ++k) {
            pg->places[k].t_n1 = i;
            pg->places[k].t_n2 = j - 1;
        }
        i = j;
    }
    xfree(pen_cnt);
}

static void
process_kirov_run(
    StandingsPage *pg,
    StandingsExtraInfo *sii,
    struct serve_state *cs,
    int run_id,
    const struct run_entry *pe,
    int need_eff_time)
{
    const struct section_global_data *global = cs->global;
    int tind = pg->t_rev[pe->user_id];
    int pind = pg->p_rev[pe->prob_id];
    int up_ind = (tind << pg->row_sh) + pind;
    const struct section_problem_data *prob = cs->probs[pe->prob_id];
    StandingsCell *cell = &pg->cells[up_ind];
    StandingsUserRow *row = &pg->rows[tind];
    StandingsProblemColumn *col = &pg->columns[pind];
    time_t run_time = pe->time;

    int token_flags = 0;
    if (sii->user_mode && sii->user_id > 0 && sii->user_id == pe->user_id) {
        token_flags = pe->token_flags;
    }

    if (prob->score_tokenized > 0 && !pe->token_flags) return;

    int run_status = RUN_CHECK_FAILED;
    int run_score = 0;
    int run_tests = 0;
    if (pg->separate_user_score > 0 && sii->user_mode && pe->is_saved && !(pe->token_flags & TOKEN_FINALSCORE_BIT)) {
        run_status = pe->saved_status;
        run_score = pe->saved_score;
        if (run_status == RUN_OK && !prob->variable_full_score) {
            if (prob->full_user_score >= 0) {
                run_score = prob->full_user_score;
            } else {
                run_score = prob->full_score;
            }
        }
        run_tests = pe->saved_test;
    } else {
        run_status = pe->status;
        run_score = pe->score;
        if (run_status == RUN_OK && !prob->variable_full_score) {
            run_score = prob->full_score;
        }
        if (pe->passed_mode > 0) {
            run_tests = pe->test;
        } else {
            run_tests = pe->test - 1;
        }
    }

    if (run_status == RUN_REJECTED && prob->enable_submit_after_reject > 0 && run_time > 0) {
        if (cell->eff_time <= 0) {
            cell->eff_time = run_time;
        } else if (run_time < cell->eff_time) {
            cell->eff_time = run_time;
        }
    }
    time_t effective_time = 0;
    if (need_eff_time) {
        effective_time = cell->eff_time;
    }

    if (global->score_system == SCORE_OLYMPIAD && sii->accepting_mode) {
        if (run_score < 0) run_score = 0;
        if (run_tests < 0) run_tests = 0;
        if (run_status == RUN_WRONG_ANSWER_ERR && prob->type != 0) run_status = RUN_PARTIAL;
        switch (run_status) {
        case RUN_OK:
        case RUN_ACCEPTED:
        case RUN_PENDING_REVIEW:
        case RUN_SUMMONED:
            if (!cell->full_sol) ++cell->sol_att;
            cell->full_sol = 1;
            cell->score = prob->tests_to_accept;
            ++cell->att_num;  /* hmm, it is not used... */
            if (run_status == RUN_PENDING_REVIEW)
                cell->pr_flag = 1;
            if (run_status == RUN_SUMMONED)
                cell->sm_flag = 1;
            if (!col->is_solved) {
                if (global->is_virtual <= 0 && global->stand_show_first_solver > 0) {
                    cell->first_solver = 1;
                }
                col->is_solved = 1;
            }
            break;
        case RUN_PARTIAL:
            if (!cell->full_sol) ++cell->sol_att;
            if (run_tests > prob->tests_to_accept)
                run_tests = prob->tests_to_accept;
            if (run_tests > cell->score) 
                cell->score = run_tests;
            cell->full_sol = 1;
            ++cell->att_num;
            break;
        case RUN_COMPILE_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_WALL_TIME_LIMIT_ERR:
        case RUN_RUN_TIME_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_PRESENTATION_ERR:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
        case RUN_SYNC_ERR:
        case RUN_STYLE_ERR:
        case RUN_REJECTED:
            if (!cell->full_sol) ++cell->sol_att;
            if (run_tests > prob->tests_to_accept)
                run_tests = prob->tests_to_accept;
            if (run_tests > cell->score) 
                cell->score = run_score;
            ++cell->att_num;
            break;
        case RUN_DISQUALIFIED:
            if (!cell->full_sol) ++cell->sol_att;
            ++cell->disq_num;
            break;
        case RUN_PENDING:
            if (!cell->full_sol) ++cell->sol_att;
            ++cell->att_num;
            ++cell->trans_num;
            break;
        case RUN_COMPILING:
        case RUN_RUNNING:
            ++cell->trans_num;
            break;
        case RUN_CHECK_FAILED:
            ++cell->cf_num;
            break;
        default:
            break;
        }
    } else if (global->score_system == SCORE_OLYMPIAD) {
        run_score += pe->score_adj;
        if (run_score < 0) run_score = 0;
        if (run_status == RUN_WRONG_ANSWER_ERR && prob->type != 0) run_status = RUN_PARTIAL;
        switch (run_status) {
        case RUN_OK:
            if (prob->score_latest > 0) {
                // score best, actually
                if (run_score > cell->score) {
                    cell->full_sol = 1;
                    cell->score = run_score;
                } else if (run_score == cell->score) {
                    cell->full_sol = 1;
                }
            } else {
                cell->full_sol = 1;
                cell->score = run_score;
            }
            cell->trans_num = 0;
            ++cell->att_num;
            if (global->stand_enable_penalty && prob->ignore_penalty <= 0) {
                cell->penalty += sec_to_min(global->rounding_mode, run_time);
            }
            //if (run_score > prob->full_score) run_score = prob->full_score;
            if (!col->is_solved) {
                if (global->is_virtual <= 0 && global->stand_show_first_solver > 0) {
                    cell->first_solver = 1;
                }
                col->is_solved = 1;
            }
            break;
        case RUN_PARTIAL:
            if (prob->score_latest > 0) {
                // score best, actually
                if (run_score > cell->score) {
                    cell->full_sol = 0;
                    cell->score = run_score;
                }
            } else {
                cell->score = run_score;
                cell->full_sol = 0;
            }
            cell->trans_num = 0;
            ++cell->att_num;
            if (global->stand_enable_penalty && prob->ignore_penalty <= 0) {
                cell->penalty += sec_to_min(global->rounding_mode, run_time - row->start_time);
            }
            break;
        case RUN_ACCEPTED:
            ++cell->att_num;
            ++cell->trans_num;
            break;
        case RUN_PENDING_REVIEW:
            ++cell->att_num;
            ++cell->trans_num;
            cell->pr_flag = 1;
            break;
        case RUN_SUMMONED:
            ++cell->att_num;
            ++cell->trans_num;
            cell->sm_flag = 1;
            break;
        case RUN_PENDING:
            ++cell->att_num;
            ++cell->trans_num;
            break;
        case RUN_COMPILE_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_WALL_TIME_LIMIT_ERR:
        case RUN_RUN_TIME_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_PRESENTATION_ERR:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
        case RUN_SYNC_ERR:
        case RUN_STYLE_ERR:
        case RUN_REJECTED:
            ++cell->att_num;
            break;
        case RUN_DISQUALIFIED:
            ++cell->disq_num;
            break;
        case RUN_COMPILING:
        case RUN_RUNNING:
            ++cell->trans_num;
            break;
        case RUN_CHECK_FAILED:
            ++cell->cf_num;
            break;
        default:
            break;
        }
    } else {
        // KIROV system with variations
        if (run_score == -1) run_score = 0;

        if (prob->score_latest_or_unmarked > 0) {
            if (run_status == RUN_OK || run_status == RUN_PENDING_REVIEW || run_status == RUN_SUMMONED) {
                if (run_status == RUN_PENDING_REVIEW) {
                    cell->pr_flag = 1;
                    ++pg->total_prs;
                }
                if (run_status == RUN_SUMMONED) {
                    cell->sm_flag = 1;
                    ++pg->total_summoned;
                }
                cell->rj_flag = 0;

                int score = calc_kirov_score(0, 0, row->start_time,
                                             pg->separate_user_score, sii->user_mode, token_flags,
                                             pe, prob, cell->att_num,
                                             cell->disq_num, cell->ce_num,
                                             cell->full_sol?RUN_TOO_MANY:col->succ_att,
                                             0, 0, effective_time);
                if (pe->is_marked) {
                    // latest
                    cell->marked_flag = 1;
                    cell->score = score;
                    if (prob->stand_hide_time <= 0) cell->sol_time = run_time;
                } else if (cell->marked_flag) {
                    // do nothing
                } else if (score > cell->score) {
                    // best score
                    cell->score = score;
                    if (prob->stand_hide_time <= 0) cell->sol_time = run_time;
                }
                ++cell->sol_att;
                ++col->succ_att;
                ++col->tot_att;
                ++cell->att_num;
                cell->full_sol = 1;
                pg->last_submit_run = run_id;
                pg->last_success_run = run_id;
                if (!col->is_solved) {
                    if (global->is_virtual <= 0 && global->stand_show_first_solver > 0) {
                        cell->first_solver = 1;
                    }
                    col->is_solved = 1;
                }
            } else if (run_status == RUN_PARTIAL || (run_status == RUN_WRONG_ANSWER_ERR && prob->type != 0)) {
                int score = calc_kirov_score(0, 0, row->start_time,
                                             pg->separate_user_score, sii->user_mode, token_flags,
                                             pe, prob, cell->att_num,
                                             cell->disq_num, cell->ce_num, RUN_TOO_MANY, 0, 0,
                                             effective_time);
                if (pe->is_marked) {
                    // latest
                    cell->marked_flag = 1;
                    cell->score = score;
                    if (prob->stand_hide_time <= 0) cell->sol_time = run_time;
                } else if (cell->marked_flag) {
                    // do nothing
                } else if (score > cell->score) {
                    // best score
                    cell->score = score;
                    if (prob->stand_hide_time <= 0) cell->sol_time = run_time;
                }
                if (!cell->full_sol) ++cell->sol_att;
                ++cell->att_num;
                if (!cell->full_sol) ++col->tot_att;
                cell->full_sol = 0;
                pg->last_submit_run = run_id;
            } else if (run_status == RUN_COMPILE_ERR) {
                if (prob->ignore_compile_errors <= 0) {
                    if (prob->compile_error_penalty >= 0) {
                        ++cell->ce_num;
                    } else {
                        ++cell->att_num;
                    }
                    if (!cell->full_sol) ++cell->sol_att;
                    if (!cell->full_sol) ++col->tot_att;
                    pg->last_submit_run = run_id;
                }
            } else if (run_status == RUN_DISQUALIFIED) {
                if (!cell->full_sol) ++cell->sol_att;
                ++cell->disq_num;
                ++pg->total_disqualified;
            } else if (run_status == RUN_PENDING_REVIEW) {
                cell->pr_flag = 1;
                ++pg->total_prs;
            } else if (run_status == RUN_SUMMONED) {
                cell->sm_flag = 1;
                ++pg->total_summoned;
            } else if (run_status == RUN_REJECTED) {
                if (!cell->full_sol)
                    cell->rj_flag = 1;
                ++pg->total_rejected;
            } else if (run_status == RUN_PENDING) {
                ++cell->trans_num;
                ++pg->total_pending;
            } else if (run_status == RUN_ACCEPTED) {
                ++cell->trans_num;
                ++pg->total_accepted;
            } else if (run_status == RUN_COMPILING || run_status == RUN_RUNNING) {
                ++cell->trans_num;
                ++pg->total_trans;
            } else if (run_status == RUN_CHECK_FAILED) {
                ++cell->cf_num;
                ++pg->total_check_failed;
            } else if (run_status == RUN_STYLE_ERR || run_status == RUN_REJECTED) {
            } else {
                /* something strange... */
            }
        } else {
            if (run_status == RUN_OK || run_status == RUN_PENDING_REVIEW || run_status == RUN_SUMMONED) {
                if (run_status == RUN_PENDING_REVIEW) {
                    cell->pr_flag = 1;
                    ++pg->total_prs;
                }
                if (run_status == RUN_SUMMONED) {
                    cell->sm_flag = 1;
                    ++pg->total_summoned;
                }
                cell->rj_flag = 0;

                if (!col->is_solved) {
                    if (global->is_virtual <= 0 && global->stand_show_first_solver > 0) {
                        cell->first_solver = 1;
                    }
                    col->is_solved = 1;
                }

                if (!cell->marked_flag || prob->ignore_unmarked <= 0 || pe->is_marked) {
                    cell->marked_flag = pe->is_marked;
                    //if (!cell->full_sol) ++cell->sol_att;
                    int score = calc_kirov_score(0, 0, row->start_time,
                                                 pg->separate_user_score, sii->user_mode, token_flags,
                                                 pe, prob, cell->sol_att,
                                                 cell->disq_num, cell->ce_num,
                                                 cell->full_sol?RUN_TOO_MANY:col->succ_att,
                                                 0, 0, effective_time);
                    if (prob->score_latest > 0 || score > cell->score) {
                        cell->score = score;
                        if (prob->stand_hide_time <= 0) cell->sol_time = run_time;
                    }
                    if (!cell->sol_time && prob->stand_hide_time <= 0)
                        cell->sol_time = run_time;
                    if (!cell->full_sol) {
                        ++col->succ_att;
                        ++col->tot_att;
                    }
                    ++cell->att_num;
                    cell->full_sol = 1;
                    pg->last_submit_run = run_id;
                    pg->last_success_run = run_id;
                    if (prob->provide_ok) {
                        for (int dst_i = 0; prob->provide_ok[dst_i]; ++dst_i) {
                            // find a matching problem
                            int dst_pind = 0;
                            for (dst_pind = 0; dst_pind < pg->p_tot; ++dst_pind) {
                                if (!strcmp(prob->provide_ok[dst_i], cs->probs[pg->p_ind[dst_pind]]->short_name))
                                    break;
                            }
                            if (dst_pind >= pg->p_tot) continue;

                            int dst_up_ind = (tind << pg->row_sh) + dst_pind;
                            const struct section_problem_data *dst_prob = cs->probs[pg->p_ind[dst_pind]];
                            StandingsCell *dest_cell = &pg->cells[dst_up_ind];
                            dest_cell->marked_flag = pe->is_marked;
                            //if (!dest_cell->full_sol) ++dest_cell->sol_att;
                            score = dst_prob->full_score;
                            /*
                              score = calc_kirov_score(0, 0, start_time,
                              separate_user_score, user_mode,
                              pe, prob, att_num[up_ind],
                              disq_num[up_ind],
                              full_sol[up_ind]?RUN_TOO_MANY:succ_att[pind],
                              0, 0);
                            */
                            if (dst_prob->score_latest > 0 || score > dest_cell->score) {
                                dest_cell->score = score;
                                if (dst_prob->stand_hide_time <= 0) dest_cell->sol_time = run_time;
                            }
                            if (!dest_cell->sol_time && dst_prob->stand_hide_time <= 0) {
                                dest_cell->sol_time = run_time;
                            }
                            if (!dest_cell->full_sol) {
                                ++pg->columns[dst_pind].succ_att;
                                ++pg->columns[dst_pind].tot_att;
                            }
                            ++dest_cell->att_num;
                            dest_cell->full_sol = 1;
                        }
                    }
                }
            } else if (run_status == RUN_PARTIAL) {
                if (!cell->marked_flag || prob->ignore_unmarked <= 0 || pe->is_marked) {
                    cell->marked_flag = pe->is_marked;
                    int score = calc_kirov_score(0, 0, row->start_time,
                                                 pg->separate_user_score, sii->user_mode, token_flags,
                                                 pe, prob, cell->sol_att,
                                                 cell->disq_num, cell->ce_num, RUN_TOO_MANY, 0, 0,
                                                 effective_time);
                    ++cell->sol_att;
                    if (prob->score_latest > 0 || score > cell->score) {
                        cell->score = score;
                    }
                    if (prob->score_latest > 0) {
                        cell->full_sol = 0;
                    }
                    ++cell->att_num;
                    if (!cell->full_sol) ++col->tot_att;
                    pg->last_submit_run = run_id;
                }
            } else if (run_status == RUN_WRONG_ANSWER_ERR && prob->type != 0) {
                int score = calc_kirov_score(0, 0, row->start_time,
                                             pg->separate_user_score, sii->user_mode, token_flags,
                                             pe, prob, cell->sol_att,
                                             cell->disq_num, cell->ce_num, RUN_TOO_MANY, 0, 0,
                                             effective_time);
                ++cell->sol_att;
                if (prob->score_latest > 0 || score > cell->score) {
                    cell->score = score;
                }
                ++cell->att_num;
                if (!cell->full_sol) ++col->tot_att;
                pg->last_submit_run = run_id;
            } else if (run_status == RUN_COMPILE_ERR) {
                if (prob->ignore_compile_errors <= 0) {
                    if (prob->compile_error_penalty >= 0) {
                        ++cell->ce_num;
                    } else {
                        ++cell->att_num;
                        ++cell->sol_att;
                    }
                    //if (!cell->full_sol) ++cell->sol_att;
                    if (!cell->full_sol) ++col->tot_att;
                    pg->last_submit_run = run_id;
                }
            } else if (run_status == RUN_DISQUALIFIED) {
                //if (!cell->full_sol) ++cell->sol_att;
                ++cell->disq_num;
                ++pg->total_disqualified;
            } else if (run_status == RUN_PENDING) {
                ++cell->trans_num;
                ++pg->total_pending;
            } else if (run_status == RUN_ACCEPTED) {
                ++cell->trans_num;
                ++pg->total_accepted;
            } else if (run_status == RUN_REJECTED) {
                if (!cell->full_sol)
                    cell->rj_flag = 1;
                ++pg->total_rejected;
            } else if (run_status == RUN_COMPILING || run_status == RUN_RUNNING) {
                ++cell->trans_num;
                ++pg->total_trans;
            } else if (run_status == RUN_CHECK_FAILED) {
                ++cell->cf_num;
                ++pg->total_check_failed;
            } else if (run_status == RUN_STYLE_ERR || run_status == RUN_REJECTED) {
            } else {
                /* something strange... */
            }
        }
    }
}

static void
sort_kirov(
        StandingsPage *pg,
        StandingsExtraInfo *sii,
        struct serve_state *cs)
{
    const struct section_global_data *global = cs->global;

    if (pg->t_tot <= 0) return;

    int max_full = -1;
    int max_score = -1;
    for (int t = 0; t < pg->t_tot; ++t) {
        StandingsUserRow *row = &pg->rows[t];
        if (row->tot_full > max_full) max_full = row->tot_full;
        if (row->tot_score > max_score) max_score = row->tot_score;
    }
    int *ind_full;
    XALLOCAZ(ind_full, max_full + 1);
    int *ind_score;
    XALLOCAZ(ind_score, max_score + 1);
    for (int t = 0; t < pg->t_tot; ++t) {
        StandingsUserRow *row = &pg->rows[t];
        ++ind_full[row->tot_full];
        ++ind_score[row->tot_score];
    }
    int i = 0;
    for (int t = max_full - 1; t >= 0; --t) {
        int j = ind_full[t + 1] + i;
        ind_full[t + 1] = i;
        i = j;
    }
    ind_full[0] = i;
    i = 0;
    for (int t = max_score - 1; t >= 0; --t) {
        int j = ind_score[t + 1] + i;
        ind_score[t + 1] = i;
        i = j;
    }
    ind_score[0] = i;

    XCALLOC(pg->t_sort, pg->t_tot);
    if (sii->accepting_mode) {
        /* sort by the number of solved problems */
        for (int t = 0; t < pg->t_tot; ++t)
            pg->t_sort[ind_full[pg->rows[t].tot_full]++] = t;

        /* resolve ties */
        for(int i = 0; i < pg->t_tot;) {
            int j;
            for (j = i + 1; j < pg->t_tot; ++j) {
                if (pg->rows[pg->t_sort[i]].tot_full != pg->rows[pg->t_sort[j]].tot_full) break;
            }
            for (int k = i; k < j; ++k) {
                pg->places[k].t_n1 = i;
                pg->places[k].t_n2 = j - 1;
            }
            i = j;
        }
    } else if (global->stand_sort_by_solved) {
        /* sort by the number of solved problems, then by the score */
        int *t_sort2;
        XALLOCA(t_sort2, pg->t_tot);
        for (int t = 0; t < pg->t_tot; ++t)
            t_sort2[ind_score[pg->rows[t].tot_score]++] = t;
        for (int t = 0; t < pg->t_tot; ++t)
            pg->t_sort[ind_full[pg->rows[t_sort2[t]].tot_full]++] = t_sort2[t];

        /* resolve ties */
        for(int i = 0; i < pg->t_tot;) {
            int j;
            for (j = i + 1; j < pg->t_tot; ++j) {
                if (pg->rows[pg->t_sort[i]].tot_full != pg->rows[pg->t_sort[j]].tot_full
                    || pg->rows[pg->t_sort[i]].tot_score != pg->rows[pg->t_sort[j]].tot_score)
                    break;
            }
            for (int k = i; k < j; ++k) {
                pg->places[k].t_n1 = i;
                pg->places[k].t_n2 = j - 1;
            }
            i = j;
        }
    } else if (global->stand_enable_penalty) {
        /* sort by the number of solved problems, then by the penalty */
        for (int t = 0; t < pg->t_tot; ++t)
            pg->t_sort[ind_score[pg->rows[t].tot_score]++] = t;
        // bubble sort on penalty
        int sort_flag;
        do {
            sort_flag = 0;
            for (int i = 1; i < pg->t_tot; ++i)
                if (pg->rows[pg->t_sort[i-1]].tot_score == pg->rows[pg->t_sort[i]].tot_score
                    && pg->rows[pg->t_sort[i-1]].tot_penalty > pg->rows[pg->t_sort[i]].tot_penalty) {
                    int j = pg->t_sort[i - 1];
                    pg->t_sort[i - 1] = pg->t_sort[i];
                    pg->t_sort[i] = j;
                    sort_flag = 1;
                }
        } while (sort_flag);

        /* resolve ties */
        for(int i = 0; i < pg->t_tot;) {
            int j;
            for (j = i + 1; j < pg->t_tot; ++j) {
                if (pg->rows[pg->t_sort[i]].tot_penalty != pg->rows[pg->t_sort[j]].tot_penalty
                    || pg->rows[pg->t_sort[i]].tot_score != pg->rows[pg->t_sort[j]].tot_score)
                    break;
            }
            for (int k = i; k < j; ++k) {
                pg->places[k].t_n1 = i;
                pg->places[k].t_n2 = j - 1;
            }
            i = j;
        }
    } else {
        /* sort by the score */
        for (int t = 0; t < pg->t_tot; ++t)
            pg->t_sort[ind_score[pg->rows[t].tot_score]++] = t;

        /* resolve ties */
        for(int i = 0; i < pg->t_tot;) {
            int j;
            for (j = i + 1; j < pg->t_tot; ++j) {
                if (pg->rows[pg->t_sort[i]].tot_score != pg->rows[pg->t_sort[j]].tot_score)
                    break;
            }
            for (int k = i; k < j; ++k) {
                pg->places[k].t_n1 = i;
                pg->places[k].t_n2 = j - 1;
            }
            i = j;
        }
    }
}

static void
process_moscow_run(
    StandingsPage *pg,
    StandingsExtraInfo *sii,
    struct serve_state *cs,
    int run_id,
    const struct run_entry *pe,
    int need_eff_time)
{
    const struct section_global_data *global = cs->global;
    int tind = pg->t_rev[pe->user_id];
    int pind = pg->p_rev[pe->prob_id];
    int up_ind = (tind << pg->row_sh) + pind;
    const struct section_problem_data *prob = cs->probs[pe->prob_id];
    StandingsCell *cell = &pg->cells[up_ind];
    StandingsUserRow *row = &pg->rows[tind];
    StandingsProblemColumn *col = &pg->columns[pind];
    time_t run_time = pe->time;
    time_t run_duration = run_time - row->start_time;
    if (run_duration < 0) run_duration = 0;

    if (pe->status == RUN_OK) {
        if (cell->full_sol) return;
        pg->last_success_run = run_id;
        pg->last_submit_run = run_id;
        cell->full_sol = 1;
        cell->penalty += prob->acm_run_penalty * cell->sol_att;
        cell->sol_time = run_time;
        cell->eff_time = sec_to_min(global->rounding_mode, run_duration);
        if (global->ignore_success_time <= 0) {
            cell->penalty += cell->eff_time;
        }
        cell->score = prob->full_score;
        if (prob->variable_full_score) cell->score = pe->score;
        ++col->succ_att;
        ++col->tot_att;
        if (!col->is_solved) {
            if (global->is_virtual <= 0 && global->stand_show_first_solver > 0) {
                cell->first_solver = 1;
            }
            col->is_solved = 1;
        }
        /*
      up_att[up_ind] = up_totatt[up_ind];
      up_pen[up_ind] = sec_to_min(global->rounding_mode, udur);
      up_totatt[up_ind]++;
      up_score[up_ind] = prob->full_score;
      p_att[p]++;
      p_succ[p]++;
        */
    } else if (pe->status == RUN_COMPILE_ERR && prob->ignore_compile_errors <= 0) {
        if (cell->full_sol) return;
        pg->last_submit_run = run_id;
        ++cell->sol_att;
        ++col->tot_att;
        cell->score = pe->score;
        /*
      if (pe->score > up_score[up_ind]) {
        up_att[up_ind] = up_totatt[up_ind];
        up_pen[up_ind] = sec_to_min(global->rounding_mode, udur);
        up_time[up_ind] = run_time;
      }
        */
    } else if (run_is_failed_attempt(pe->status)) {
        if (cell->full_sol) return;
        pg->last_submit_run = run_id;
        ++cell->sol_att;
        ++col->tot_att;
    } else if (pe->status == RUN_DISQUALIFIED) {
        ++cell->disq_num;
    } else if (pe->status == RUN_PENDING_REVIEW || pe->status == RUN_SUMMONED) {
        cell->pr_flag = 1;
    } else if (pe->status == RUN_PENDING || pe->status == RUN_ACCEPTED) {
        ++cell->trans_num;
    } else if (pe->status >= RUN_TRANSIENT_FIRST && pe->status <= RUN_TRANSIENT_LAST) {
        ++cell->trans_num;
    } else if (pe->status == RUN_CHECK_FAILED) {
        ++cell->cf_num;
    }
}

static void
sort_moscow(
        StandingsPage *pg,
        StandingsExtraInfo *sii,
        struct serve_state *cs)
{
    if (pg->t_tot <= 0) return;

    int *pen_cnt = NULL;
    int *pen_st = NULL;
    int max_pen = -1;
    int max_score = -1;
    int *u_sort1 = NULL;
    XCALLOC(pg->t_sort, pg->t_tot);
    XALLOCAZ(u_sort1, pg->t_tot);
    for (int u = 0; u < pg->t_tot; ++u) {
        StandingsUserRow *row = &pg->rows[u];
        if (row->tot_penalty > max_pen)
            max_pen = row->tot_penalty;
        if (row->tot_score > max_score)
            max_score = row->tot_score;
    }
    if (max_pen >= 0) {
        XCALLOC(pen_cnt, max_pen + 1);
        XCALLOC(pen_st, max_pen + 1);
        for (int u = 0; u < pg->t_tot; ++u) {
            StandingsUserRow *row = &pg->rows[u];
            ++pen_cnt[row->tot_penalty];
        }
        for (int i = 1; i <= max_pen; ++i)
            pen_st[i] = pen_cnt[i - 1] + pen_st[i - 1];
        for (int u = 0; u < pg->t_tot; ++u) {
            StandingsUserRow *row = &pg->rows[u];
            u_sort1[pen_st[row->tot_penalty]++] = u;
        }
    }
    int *sc_cnt = NULL;
    int *sc_st = NULL;
    if (max_score >= 0) {
        XALLOCAZ(sc_cnt, max_score + 1);
        XALLOCAZ(sc_st, max_score + 1);
        for (int u = 0; u < pg->t_tot; ++u) {
            StandingsUserRow *row = &pg->rows[u];
            ++sc_cnt[row->tot_score];
        }
        for (int i = max_score - 1; i >= 0; --i)
            sc_st[i] = sc_cnt[i + 1] + sc_st[i + 1];
        for (int u = 0; u < pg->t_tot; ++u) {
            pg->t_sort[sc_st[pg->rows[u_sort1[u]].tot_score]++] = u_sort1[u];
        }
    }
    for (int u = 0; u < pg->t_tot; ) {
        int i;
        for (i = u + 1;
             i < pg->t_tot
                 && pg->rows[pg->t_sort[u]].tot_score == pg->rows[pg->t_sort[i]].tot_score
                 && pg->rows[pg->t_sort[u]].tot_penalty == pg->rows[pg->t_sort[i]].tot_penalty;
             ++i);
        for (int j = u; j < i; ++j) {
            pg->places[j].t_n1 = u;
            pg->places[j].t_n2 = i - 1;
        }
        u = i;
    }
    xfree(pen_cnt);
    xfree(pen_st);
}

static int
csp_execute_int_standings(
        PageInterface *ps,
        FILE *log_f,
        struct http_request_info *phr)
{
    StandingsPage *pg = (StandingsPage *) ps;
    StandingsExtraInfo *sii = (StandingsExtraInfo*) phr->extra_info;
    struct contest_extra *extra = phr->extra;
    struct serve_state *cs = extra->serve_state;
    const struct section_global_data *global = cs->global;
    struct filter_env env;
    //const struct run_entry *runs = NULL;
    unsigned char *t_runs = NULL;
    int need_eff_time = 0; // need to compute the effective submit time
    struct content_loaded_plugin *cp = NULL;
    int content_enabled = 0;
    unsigned char avatar_url[1024];
    __attribute__((unused)) int _;

    memset(&env, 0, sizeof(env));

    if (global->score_system == SCORE_KIROV) {
        pg->separate_user_score = global->separate_user_score > 0 && cs->online_view_judge_score <= 0;
    }

    pg->cur_time = sii->stand_time;
    if (!pg->cur_time) pg->cur_time = time(NULL);

    pg->start_time = run_get_start_time(cs->runlog_state);
    if (pg->start_time <= 0 || pg->cur_time < pg->start_time) {
        // contest is not started
        pg->not_started_flag = 1;
        goto cleanup;
    }

    pg->stop_time = run_get_stop_time(cs->runlog_state, 0, 0);
    pg->duration = run_get_duration(cs->runlog_state, 0);

    if (sii->user_filter && sii->user_filter->stand_time_expr_mode == 1) {
        // relative to the contest start
        time_t new_time = pg->start_time + sii->user_filter->stand_time_expr_time;
        if (new_time < pg->start_time) new_time = pg->start_time;
        if (pg->stop_time > 0 && new_time > pg->stop_time) {
            new_time = pg->stop_time;
        } else if (pg->stop_time <= 0 && new_time > pg->cur_time) {
            new_time = pg->cur_time;
        }
        pg->cur_time = new_time;
    } else if (sii->user_filter && sii->user_filter->stand_time_expr_mode == 2) {
        // relative to the current time or contest end
        time_t new_time;
        if (pg->stop_time > 0) {
            new_time = pg->stop_time - sii->user_filter->stand_time_expr_time;
            if (new_time < pg->start_time) new_time = pg->start_time;
            if (new_time > pg->stop_time) new_time = pg->stop_time;
        } else {
            new_time = pg->cur_time - sii->user_filter->stand_time_expr_time;
            if (new_time < pg->start_time) new_time = pg->start_time;
            if (new_time > pg->cur_time) new_time = pg->cur_time;
        }
        pg->cur_time = new_time;
    } else if (sii->user_filter && sii->user_filter->stand_time_expr_mode == 3) {
        time_t new_time = sii->user_filter->stand_time_expr_time;
        if (new_time < pg->start_time) new_time = pg->start_time;
        if (pg->stop_time > 0) {
            if (new_time > pg->stop_time) new_time = pg->stop_time;
        } else {
            if (new_time > pg->cur_time) new_time = pg->cur_time;
        }
        pg->cur_time = new_time;
    }

    if (global->is_virtual > 0 && sii->user_id > 0) {
        pg->user_start_time = run_get_virtual_start_time(cs->runlog_state, sii->user_id);
        if (pg->user_start_time <= 0 || pg->cur_time < pg->user_start_time) {
            // contest is not started
            pg->not_started_flag = 1;
            goto cleanup;
        }
        pg->user_stop_time = run_get_virtual_stop_time(cs->runlog_state, sii->user_id, 0);
        pg->user_duration = pg->duration;
        if (pg->user_stop_time <= 0 && pg->user_duration > 0) {
            if (pg->cur_time > pg->user_stop_time + pg->user_duration) {
                pg->user_stop_time = pg->user_stop_time + pg->user_duration;
            }
        }
    } else {
        pg->user_start_time = pg->start_time;
        pg->user_stop_time = pg->stop_time;
        pg->user_duration = pg->duration;
    }
    pg->cur_duration = pg->cur_time - pg->user_start_time;

    pg->duration_before_fog = -1;
    if (sii->user_mode && pg->duration > 0 && global->board_fog_time > 0) {
        pg->duration_before_fog = pg->duration - global->board_fog_time;
        if (pg->duration_before_fog < 0) pg->duration_before_fog = 0;
    }
    if (pg->duration_before_fog >= 0 && pg->cur_time > pg->user_start_time + pg->duration_before_fog) {
        pg->fog_flag = 1;
    }
    if (pg->duration_before_fog >= 0 && global->board_unfog_time >= 0) {
        time_t stop_time = pg->user_stop_time;
        if (stop_time <= 0) stop_time = pg->user_start_time + pg->duration;
        if (pg->cur_time > stop_time + global->board_unfog_time) {
            pg->fog_flag = 0;
            pg->unfog_flag = 1;
        }
    }

    pg->r_beg = run_get_first(cs->runlog_state);
    pg->r_tot = run_get_total(cs->runlog_state);
    pg->runs = run_get_entries_ptr(cs->runlog_state);

    if (global->disable_user_database > 0) {
        pg->t_max = run_get_max_user_id(cs->runlog_state) + 1;
    } else {
        pg->t_max = teamdb_get_max_team_id(cs->teamdb_state) + 1;
    }

    t_runs = malloc(pg->t_max);
    if (global->prune_empty_users > 0 || global->disable_user_database > 0) {
        memset(t_runs, 0, pg->t_max);
        for (int k = pg->r_beg; k < pg->r_tot; k++) {
            if (pg->runs[k].status == RUN_EMPTY) continue;
            if (pg->runs[k].is_hidden) continue;
            if(pg->runs[k].user_id <= 0 && pg->runs[k].user_id >= pg->t_max) continue;
            t_runs[pg->runs[k].user_id] = 1;
        }
    } else {
        memset(t_runs, 1, pg->t_max);
    }

    /* make team index */
    /* t_tot             - total number of teams in index array
     * t_max             - maximal possible number of teams
     * t_ind[0..t_tot-1] - index array:   team_idx -> team_id
     * t_rev[0..t_max-1] - reverse index: team_id -> team_idx
     */
    pg->t_ind = malloc(pg->t_max * sizeof(pg->t_ind[0]));
    pg->t_rev = malloc(pg->t_max * sizeof(pg->t_rev[0]));
    if (global->stand_collate_name > 0) {
        memset(pg->t_rev, -1, pg->t_max * sizeof(pg->t_rev[0]));
        for (int i = 1, t_tot = 0; i < pg->t_max; i++) {
            if (!teamdb_lookup(cs->teamdb_state, i)) continue;
            if ((teamdb_get_flags(cs->teamdb_state,  i) & (TEAM_INVISIBLE | TEAM_BANNED | TEAM_DISQUALIFIED)))
                continue;
            if (!t_runs[i]) continue;

            int j;
            for (j = 0; j < t_tot; j++) {
                if (!strcmp(teamdb_get_name_2(cs->teamdb_state, pg->t_ind[j]),
                            teamdb_get_name_2(cs->teamdb_state, i))) {
                    pg->t_rev[i] = j;
                    break;
                }
            }
            if (j < pg->t_tot) continue;

            pg->t_rev[i] = pg->t_tot;
            pg->t_ind[pg->t_tot++] = i;
        }
    } else {
        // use a fast function, if no `stand_collate_name'
        teamdb_get_user_map(cs, pg->cur_time, pg->t_max, t_runs, &pg->t_tot, pg->t_rev, pg->t_ind, sii->user_filter);
    }

    if (global->stand_show_contestant_status > 0 || global->stand_show_warn_number > 0 || global->contestant_status_row_attr > 0) {
        if (cs->xuser_state) {
            pg->extras = cs->xuser_state->vt->get_entries(cs->xuser_state, pg->t_tot, pg->t_ind);
        }
    }

    /* make problem index */
    /* p_tot             - total number of problems in index array
     * p_max             - maximal possible number of problems
     * p_ind[0..p_tot-1] - index array:   prob_idx -> prob_id
     * p_rev[0..p_max-1] - reverse index: prob_id -> prob_idx
     */
    pg->p_max = cs->max_prob + 1;
    pg->p_ind = malloc(pg->p_max * sizeof(pg->p_ind[0]));
    pg->p_rev = malloc(pg->p_max * sizeof(pg->p_rev[0]));
    get_problem_map(cs, pg->cur_time, pg->p_rev, pg->p_max, pg->p_ind, &pg->p_tot, &pg->last_col_ind, sii->user_filter);
    if (cs->probs) {
        for (int i = 1; i < pg->p_max; i++) {
            const struct section_problem_data *prob = cs->probs[i];
            if (!prob) continue;
            need_eff_time = (prob->enable_submit_after_reject > 0);
            if (!prob->stand_column) continue;
            if (prob->start_date > 0 && pg->cur_time < prob->start_date) continue;
            for (int j = 1; j < pg->p_max; j++) {
                if (!cs->probs[j]) continue;
                if (!strcmp(cs->probs[j]->short_name, prob->stand_column)
                    || (cs->probs[j]->stand_name && !strcmp(cs->probs[j]->stand_name, prob->stand_column))) {
                    pg->p_rev[i] = pg->p_rev[j];
                }
            }
        }
    }

    /* calculate the power of 2 not less than p_tot */
    for (pg->row_sz = 1, pg->row_sh = 0; pg->row_sz < pg->p_tot; pg->row_sz <<= 1, pg->row_sh++) {}

    if (pg->t_tot > 0 && pg->p_tot > 0) {
        pg->cells = calloc(pg->t_tot * pg->row_sz, sizeof(pg->cells[0]));
    }
    if (pg->t_tot > 0) {
        pg->rows = calloc(pg->t_tot, sizeof(pg->rows[0]));
        pg->places = calloc(pg->t_tot, sizeof(pg->places[0]));
    }
    if (pg->p_tot > 0) {
        pg->columns = calloc(pg->p_tot, sizeof(pg->columns[0]));
    }

    if (global->stand_show_avatar > 0) {
        if ((cp = content_plugin_get(phr->extra, phr->cnts, phr->config, NULL))) {
            content_enabled = cp->iface->is_enabled(cp->data, phr->cnts);
        }
    }

    for (int i = 0; i < pg->t_tot; ++i) {
        int user_id = pg->t_ind[i];
        StandingsUserRow *row = &pg->rows[i];
        if (global->is_virtual > 0) {
            row->start_time = run_get_virtual_start_time(cs->runlog_state, user_id);
            row->stop_time = run_get_virtual_stop_time(cs->runlog_state, user_id, 0);
        } else {
            row->start_time = pg->start_time;
            row->stop_time = pg->stop_time;
        }
        if (global->stand_use_login > 0) {
            row->name = teamdb_get_login(cs->teamdb_state, user_id);
        } else {
            row->name = teamdb_get_name_2(cs->teamdb_state, user_id);
        }
        if (global->stand_show_avatar > 0) {
            const struct userlist_user *u = teamdb_get_userlist(cs->teamdb_state, user_id);
            const struct userlist_user_info *ui = NULL;
            if (u) ui = u->cnts0;
            if (ui && ui->avatar_id && ui->avatar_id[0]) {
                if (content_enabled) {
                    cp->iface->get_url(cp->data, avatar_url, sizeof(avatar_url),
                                       phr->cnts, ui->avatar_id, ui->avatar_suffix);
                    row->avatar_url = xstrdup(avatar_url);
                } else if (phr->self_url && phr->session_id) {
                    snprintf(avatar_url, sizeof(avatar_url), "%s?SID=%llx&key=%s&action=%d",
                             phr->self_url, phr->session_id, ui->avatar_id, NEW_SRV_ACTION_GET_AVATAR);
                    row->avatar_url = xstrdup(avatar_url);
                }
            }
        }
    }

    if (sii->user_filter && sii->user_filter->stand_run_tree) {
        env.teamdb_state = cs->teamdb_state;
        env.serve_state = cs;
        env.mem = filter_tree_new();
        env.maxlang = cs->max_lang;
        env.langs = (const struct section_language_data * const *) cs->langs;
        env.maxprob = cs->max_prob;
        env.probs = (const struct section_problem_data * const *) cs->probs;
        env.rbegin = pg->r_beg;
        env.rtotal = pg->r_tot;
        env.cur_time = pg->cur_time;
        env.rentries = pg->runs;
        env.rid = 0;
    }

    for (int k = pg->r_beg; k < pg->r_tot; ++k) {
        const struct run_entry *pe = &pg->runs[k];

        if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP || pe->status == RUN_EMPTY) continue;
        if (pe->user_id <= 0 || pe->user_id >= pg->t_max) continue;
        if (pe->prob_id <= 0 || pe->prob_id > cs->max_prob) continue;
        if (pe->is_hidden) continue;
        if (sii->user_filter && sii->user_filter->stand_run_tree) {
            env.rid = k;
            if (filter_tree_bool_eval(&env, sii->user_filter->stand_run_tree) <= 0)
                continue;
        }
    
        int tind = pg->t_rev[pe->user_id];
        if (tind < 0) continue;
        int pind = pg->p_rev[pe->prob_id];
        if (pind < 0) continue;
        const struct section_problem_data *prob = cs->probs[pe->prob_id];
        if (!prob || prob->hidden) continue;
        StandingsUserRow *row = &pg->rows[tind];
        int up_ind = (tind << pg->row_sh) + pind;
        StandingsCell *cell = &pg->cells[up_ind];

        if (row->start_time <= 0) continue;
        time_t run_time = pe->time;
        if (row->stop_time > 0 && run_time > row->stop_time && cs->upsolving_freeze_standings > 0) continue;
        time_t run_duration = run_time - row->start_time;
        if (run_duration < 0) run_duration = 0;

        /*
        if (sii->user_id > 0) {
            // run from the (virtual) future
            if (run_duration > pg->cur_duration) continue;
        }
        */
        if (run_duration > pg->cur_duration) continue;

        if (pg->duration_before_fog >= 0) {
            if (!pg->unfog_flag && run_duration >= pg->duration_before_fog) {
                // this is fogged run
                if (run_time > cell->last_fogged_time) {
                    cell->last_fogged_time = run_time;
                }
                ++cell->fogged_num;
                if (!cell->fogged_num) --cell->fogged_num; // overflow, keep the value at USHRT_MAX
                continue;
            }
        }

        if (global->score_system == SCORE_ACM) {
            process_acm_run(pg, sii, cs, k, pe, need_eff_time);
        } else if (global->score_system == SCORE_MOSCOW) {
            process_moscow_run(pg, sii, cs, k, pe, need_eff_time);
        } else {
            process_kirov_run(pg, sii, cs, k, pe, need_eff_time);
        }
    }

    /* compute the total for each team */
    if (global->score_n_best_problems > 0 && pg->p_tot > 0) {
        unsigned char *used_flag = alloca(pg->p_tot);
        for (int i = 0; i < pg->t_tot; ++i) {
            StandingsUserRow *row = &pg->rows[i];
            memset(used_flag, 0, pg->p_tot);
            for (int k = 0; k < global->score_n_best_problems; ++k) {
                int max_ind = -1;
                int max_score = -1;
                for (int j = 0; j < pg->p_tot; ++j) {
                    int up_ind = (i << pg->row_sh) + j;
                    StandingsCell *cell = &pg->cells[up_ind];
                    if (!used_flag[j] && cell->score > 0 && (max_ind < 0 || cell->score > max_score)) {
                        max_ind = j;
                        max_score = cell->score;
                    }
                }
                if (max_ind < 0) break;
                {
                    int up_ind = (i << pg->row_sh) + max_ind;
                    StandingsCell *cell = &pg->cells[up_ind];
                    row->tot_score += cell->score;
                    row->tot_full += cell->full_sol;
                    row->tot_penalty += cell->penalty;
                    used_flag[max_ind] = 1;
                }
            }
        }
    } else {
        for (int i = 0; i < pg->t_tot; ++i) {
            StandingsUserRow *row = &pg->rows[i];
            for (int j = 0; j < pg->p_tot; ++j) {
                int up_ind = (i << pg->row_sh) + j;
                StandingsCell *cell = &pg->cells[up_ind];
                if (cs->probs[pg->p_ind[j]]->stand_ignore_score <= 0) {
                    row->tot_score += cell->score;
                    row->tot_full += cell->full_sol;
                    row->tot_penalty += cell->penalty;
                }
            }
        }
    }

    if (global->score_system == SCORE_ACM) {
        sort_acm(pg, sii, cs);
    } else if (global->score_system == SCORE_MOSCOW) {
        sort_moscow(pg, sii, cs);
    } else {
        sort_kirov(pg, sii, cs);
    }

    /* recompute the total number of rejected runs */
    if (pg->total_rejected > 0) {
        pg->total_rejected = 0;
        for (int i = 0; i < pg->t_tot; ++i) {
            for (int j = 0; j < pg->p_tot; ++j) {
                int up_ind = (i << pg->row_sh) + j;
                StandingsCell *cell = &pg->cells[up_ind];
                int rj_flag = cell->rj_flag;
                if (cell->full_sol) rj_flag = 0;
                if (cell->sm_flag) rj_flag = 0;
                if (cell->pr_flag) rj_flag = 0;
                if (cell->trans_num) rj_flag = 0;
                if (cell->disq_num > 0) rj_flag = 0;
                if (cell->cf_num > 0) rj_flag = 0;
                pg->total_rejected += rj_flag;
            }
        }
    }

    /* memoize the results */
    if (!sii->accepting_mode && global->memoize_user_results) {
        for (int i = 0; i < pg->t_tot; ++i) {
            int t = pg->t_sort[i]; // indexed user
            serve_store_user_result(cs, pg->t_ind[t], pg->rows[t].tot_score);
        }
    }

    /* make page table */
    if (!sii->client_flag && sii->users_on_page > 0 && pg->t_tot > sii->users_on_page) {
        pg->total_pages = (pg->t_tot + sii->users_on_page - 1) / sii->users_on_page;
        XCALLOC(pg->pages, pg->total_pages);
        char *s = NULL;
        _ = asprintf(&s, global->standings_file_name, 1);
        pg->pages[0].pgref = s;
        for (int j = 1; j < pg->total_pages; ++j) {
            s = NULL;
            _ = asprintf(&s, global->stand_file_name_2, j + 1);
            pg->pages[j].pgref = s;
        }
        for (int j = 0; j < pg->total_pages; ++j) {
            pg->pages[j].pg_n1 = 1 + sii->users_on_page * j;
            pg->pages[j].pg_n2 = sii->users_on_page * (j + 1);
        }
        pg->pages[pg->total_pages - 1].pg_n2 = pg->t_tot;
    }

cleanup:;
    filter_tree_delete(env.mem);
    xfree(t_runs);
    return 0;
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
