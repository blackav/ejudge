/* -*- c -*- */

/* Copyright (C) 2015 Alexander Chernov <cher@ejudge.ru> */

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

#include "ejudge/prepare.h"
#include "ejudge/dates_config.h"
#include "ejudge/xalloc.h"

#include <string.h>

void
prepare_copy_dates(struct section_problem_data *prob, struct dates_config *dcfg)
{
    if (!prob || !dcfg) return;
    if (prob->abstract > 0) return;

    struct dates_problem_data *dprob = NULL;
    for (int i = 0; i < dcfg->prob_count; ++i) {
        if (!strcmp(prob->short_name, dcfg->probs[i]->short_name)) {
            dprob = dcfg->probs[i];
            break;
        }
    }

    if ((!prob->extid || !prob->extid[0]) && (dprob && dprob->extid && dprob->extid[0])) {
        xfree(prob->extid);
        prob->extid = xstrdup(dprob->extid);
    }

    if (dprob && dprob->use_dates_of_ref) {
        dprob = dprob->use_dates_of_ref;
    }
    struct dates_problem_data *aprob = NULL;
    if (dprob) aprob = dprob->super_ref;
    struct dates_global_data *global = dcfg->global;

    if (prob->start_date <= 0) {
        if (dprob && dprob->start_date > 0) {
            prob->start_date = dprob->start_date;
        } else if (aprob && aprob->start_date > 0) {
            prob->start_date = aprob->start_date;
        } else if (global && global->start_date > 0) {
            prob->start_date = global->start_date;
        }
    }

    if (prob->deadline <= 0) {
        if (dprob && dprob->deadline > 0) {
            prob->deadline = dprob->deadline;
        } else if (aprob && aprob->deadline > 0) {
            prob->deadline = aprob->deadline;
        } else if (global && global->deadline > 0) {
            prob->deadline = global->deadline;
        }
    }

    if (!prob->date_penalty) {
        if (dprob && dprob->date_penalty) {
            prob->date_penalty = sarray_copy(dprob->date_penalty);
        } else if (aprob && aprob->date_penalty) {
            prob->date_penalty = sarray_copy(aprob->date_penalty);
        } else if (global && global->date_penalty) {
            prob->date_penalty = sarray_copy(global->date_penalty);
        }
    }

    if (!prob->personal_deadline) {
        if (dprob && dprob->personal_deadline) {
            prob->personal_deadline = sarray_copy(dprob->personal_deadline);
        } else if (aprob && aprob->personal_deadline) {
            prob->personal_deadline = sarray_copy(aprob->personal_deadline);
        } else if (global && global->personal_deadline) {
            prob->personal_deadline = sarray_copy(global->personal_deadline);
        }
    }

    if (!prob->group_start_date) {
        if (dprob && dprob->group_start_date) {
            prob->group_start_date = sarray_copy(dprob->group_start_date);
        } else if (aprob && aprob->group_start_date) {
            prob->group_start_date = sarray_copy(aprob->group_start_date);
        } else if (global && global->group_start_date) {
            prob->group_start_date = sarray_copy(global->group_start_date);
        }
    }

    if (!prob->group_deadline) {
        if (dprob && dprob->group_deadline) {
            prob->group_deadline = sarray_copy(dprob->group_deadline);
        } else if (aprob && aprob->group_deadline) {
            prob->group_deadline = sarray_copy(aprob->group_deadline);
        } else if (global && global->group_deadline) {
            prob->group_deadline = sarray_copy(global->group_deadline);
        }
    }
}

/*
 * Local variables:
 *  c-basic-offset: 4
 * End:
 */
