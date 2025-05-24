/* -*- c -*- */

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
#include "ejudge/parsecfg.h"
#include "ejudge/prepare.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/xalloc.h"

#include <string.h>
#include <time.h>

const unsigned char problem_typically_ignored_fields[CNTSPROB_LAST_FIELD] =
{
    [CNTSPROB_ntests] = 1,
    [CNTSPROB_tscores] = 1,
    [CNTSPROB_x_score_tests] = 1,
    [CNTSPROB_ts_total] = 1,
    [CNTSPROB_ts_infos] = 1,
    [CNTSPROB_normalization_val] = 1,
    [CNTSPROB_dp_total] = 1,
    [CNTSPROB_dp_infos] = 1,
    [CNTSPROB_gsd] = 1,
    [CNTSPROB_gdl] = 1,
    [CNTSPROB_pd_total] = 1,
    [CNTSPROB_pd_infos] = 1,
    [CNTSPROB_score_bonus_total] = 1,
    [CNTSPROB_score_bonus_val] = 1,
    [CNTSPROB_open_tests_count] = 1,
    [CNTSPROB_open_tests_val] = 1,
    [CNTSPROB_open_tests_group] = 1,
    [CNTSPROB_final_open_tests_count] = 1,
    [CNTSPROB_final_open_tests_val] = 1,
    [CNTSPROB_final_open_tests_group] = 1,
    [CNTSPROB_token_open_tests_count] = 1,
    [CNTSPROB_token_open_tests_val] = 1,
    [CNTSPROB_token_open_tests_group] = 1,
    [CNTSPROB_score_view_score] = 1,
    [CNTSPROB_score_view_text] = 1,
    [CNTSPROB_xml_file_path] = 1,
    [CNTSPROB_var_xml_file_paths] = 1,
};

static void
problem_minimize_abstract(struct section_problem_data *prob)
{
    prob->abstract = 1;
    prob->super[0] = 0;
    prob->variant_num = 0;
    prob->examinator_num = 0;
    if (prob->time_limit_millis > 0) {
        prob->time_limit = -1;
    } else {
        prob->time_limit_millis = -1;
    }
    if (prob->input_file && !strcmp(prob->input_file, DFLT_P_INPUT_FILE)) {
        xfree(prob->input_file);
        prob->input_file = NULL;
    }
    if (prob->output_file && !strcmp(prob->output_file, DFLT_P_OUTPUT_FILE)) {
        xfree(prob->output_file);
        prob->output_file = NULL;
    }
    if (prob->full_score == DFLT_P_FULL_SCORE) {
        prob->full_score = -1;
    }
    if (prob->test_score == DFLT_P_TEST_SCORE) {
        prob->test_score = -1;
    }
    if (prob->run_penalty == DFLT_P_RUN_PENALTY) {
        prob->run_penalty = -1;
    }
    if (prob->acm_run_penalty == DFLT_P_ACM_RUN_PENALTY) {
        prob->acm_run_penalty = -1;
    }
    if (prob->priority_adjustment > 15) {
        prob->priority_adjustment = 15;
    } else if (prob->priority_adjustment < -16) {
        prob->priority_adjustment = -16;
    }
    for (int field_id = 1; field_id < CNTSPROB_LAST_FIELD; ++field_id) {
        if (problem_typically_ignored_fields[field_id]) continue;
        switch (field_id) {
        case CNTSPROB_abstract:
        case CNTSPROB_super:
        case CNTSPROB_variant_num:
        case CNTSPROB_examinator_num:
        case CNTSPROB_time_limit_millis:
        case CNTSPROB_priority_adjustment:
            continue;
        }

        int t = cntsprob_get_type(field_id);
        void *ptr = cntsprob_get_ptr_nc(prob, field_id);

        switch (t) {
        case 'i': // int
            break;
        case 'S': // unsigned char[]
            break;
        case 'f': { // ejbyteflag_t
            ejbyteflag_t *field_ptr = (ejbyteflag_t*) ptr;
            if (*field_ptr <= 0) {
                *field_ptr = -1;
            } else {
                *field_ptr = 1;
            }
            break;
        }
        case 's': { // unsigned char *
            unsigned char **field_ptr = (unsigned char **) ptr;
            if (*field_ptr && !**field_ptr) {
                xfree(*field_ptr);
                *field_ptr = NULL;
            }
            break;
        }
        case 'x': { // char **
            char ***field_ptr = (char ***) ptr;
            if (*field_ptr && !**field_ptr) {
                sarray_free(*field_ptr);
                *field_ptr = NULL;
            }
            break;
        }
        case 't': { // time_t
            time_t *field_ptr = (time_t *) ptr;
            if (*field_ptr <= 0) {
                *field_ptr = -1;
            }
            break;
        }
        case 'X': { // ejenvlist_t
            char ***field_ptr = (char ***) ptr;
            if (*field_ptr && !**field_ptr) {
                sarray_free(*field_ptr);
                *field_ptr = NULL;
            }
            break;
        }
        case 'E': { // ej_size64_t
            ej_size64_t *field_ptr = (ej_size64_t *) ptr;
            if (*field_ptr <= 0) {
                *field_ptr = -1;
            }
            break;
        }
        }
    }
}

static void
problem_minimize_standalone(struct section_problem_data *prob)
{
    prob->abstract = -1;
    prob->super[0] = 0;
    prob->examinator_num = 0;
    if (prob->time_limit_millis > 0) {
        prob->time_limit = -1;
    } else {
        prob->time_limit_millis = -1;
    }
    if (prob->input_file && !strcmp(prob->input_file, DFLT_P_INPUT_FILE)) {
        xfree(prob->input_file);
        prob->input_file = NULL;
    }
    if (prob->output_file && !strcmp(prob->output_file, DFLT_P_OUTPUT_FILE)) {
        xfree(prob->output_file);
        prob->output_file = NULL;
    }
    if (prob->full_score == DFLT_P_FULL_SCORE) {
        prob->full_score = -1;
    }
    if (prob->test_score == DFLT_P_TEST_SCORE) {
        prob->test_score = -1;
    }
    if (prob->run_penalty == DFLT_P_RUN_PENALTY) {
        prob->run_penalty = -1;
    }
    if (prob->acm_run_penalty == DFLT_P_ACM_RUN_PENALTY) {
        prob->acm_run_penalty = -1;
    }
    if (prob->priority_adjustment > 15) {
        prob->priority_adjustment = 15;
    } else if (prob->priority_adjustment < -16) {
        prob->priority_adjustment = -16;
    }
    for (int field_id = 1; field_id < CNTSPROB_LAST_FIELD; ++field_id) {
        if (problem_typically_ignored_fields[field_id]) continue;
        switch (field_id) {
        case CNTSPROB_abstract:
        case CNTSPROB_super:
        case CNTSPROB_variant_num:
        case CNTSPROB_examinator_num:
        case CNTSPROB_time_limit_millis:
        case CNTSPROB_priority_adjustment:
            continue;
        }

        int t = cntsprob_get_type(field_id);
        void *ptr = cntsprob_get_ptr_nc(prob, field_id);

        switch (t) {
        case 'i': // int
            break;
        case 'S': // unsigned char[]
            break;
        case 'f': { // ejbyteflag_t
            ejbyteflag_t *field_ptr = (ejbyteflag_t*) ptr;
            if (*field_ptr <= 0) {
                *field_ptr = -1;
            } else {
                *field_ptr = 1;
            }
            break;
        }
        case 's': { // unsigned char *
            unsigned char **field_ptr = (unsigned char **) ptr;
            if (*field_ptr && !**field_ptr) {
                xfree(*field_ptr);
                *field_ptr = NULL;
            }
            break;
        }
        case 'x': { // char **
            char ***field_ptr = (char ***) ptr;
            if (*field_ptr && !**field_ptr) {
                sarray_free(*field_ptr);
                *field_ptr = NULL;
            }
            break;
        }
        case 't': { // time_t
            time_t *field_ptr = (time_t *) ptr;
            if (*field_ptr <= 0) {
                *field_ptr = -1;
            }
            break;
        }
        case 'X': { // ejenvlist_t
            char ***field_ptr = (char ***) ptr;
            if (*field_ptr && !**field_ptr) {
                sarray_free(*field_ptr);
                *field_ptr = NULL;
            }
            break;
        }
        case 'E': { // ej_size64_t
            ej_size64_t *field_ptr = (ej_size64_t *) ptr;
            if (*field_ptr <= 0) {
                *field_ptr = -1;
            }
            break;
        }
        }
    }
}

static void
problem_minimize_inherited(struct section_problem_data *prob, const struct section_problem_data *aprob)
{
    prob->examinator_num = 0;
    if (prob->time_limit_millis > 0) {
        prob->time_limit = -1;
        if (aprob->time_limit <= 0 && aprob->time_limit_millis == prob->time_limit_millis) {
            prob->time_limit_millis = -1;
        }
    } else {
        prob->time_limit_millis = -1;
        if (prob->time_limit > 0) {
            if (aprob->time_limit == prob->time_limit && aprob->time_limit_millis <= 0) {
                prob->time_limit = -1;
            }
        }
    }
    if (prob->input_file && aprob->input_file && !strcmp(prob->input_file, aprob->input_file)) {
        xfree(prob->input_file); prob->input_file = NULL;
    } else if (prob->input_file && !aprob->input_file && !strcmp(prob->input_file, DFLT_P_INPUT_FILE)) {
        xfree(prob->input_file); prob->input_file = NULL;
    }
    if (prob->output_file && aprob->output_file && !strcmp(prob->output_file, aprob->output_file)) {
        xfree(prob->output_file); prob->output_file = NULL;
    } else if (prob->output_file && !aprob->output_file && !strcmp(prob->output_file, DFLT_P_OUTPUT_FILE)) {
        xfree(prob->output_file); prob->output_file = NULL;
    }
    if (prob->full_score >= 0 && prob->full_score == aprob->full_score) {
        prob->full_score = -1;
    } else if (aprob->full_score < 0 && prob->full_score == DFLT_P_FULL_SCORE) {
        prob->full_score = -1;
    }
    if (prob->test_score >= 0 && prob->test_score == aprob->test_score) {
        prob->test_score = -1;
    } else if (aprob->test_score < 0 && prob->test_score == DFLT_P_TEST_SCORE) {
        prob->test_score = -1;
    }
    if (prob->run_penalty >= 0 && prob->run_penalty == aprob->run_penalty) {
        prob->run_penalty = -1;
    } else if (aprob->run_penalty < 0 && prob->run_penalty == DFLT_P_RUN_PENALTY) {
        prob->run_penalty = -1;
    }
    if (prob->acm_run_penalty >= 0 && prob->acm_run_penalty == aprob->acm_run_penalty) {
        prob->acm_run_penalty = -1;
    } else if (aprob->acm_run_penalty < 0 && prob->acm_run_penalty == DFLT_P_ACM_RUN_PENALTY) {
        prob->acm_run_penalty = -1;
    }
    if (prob->priority_adjustment > 15) {
        prob->priority_adjustment = 15;
    } else if (prob->priority_adjustment < -16) {
        prob->priority_adjustment = -16;
    }
    if (prob->priority_adjustment > 0 && prob->priority_adjustment == aprob->priority_adjustment) {
        prob->priority_adjustment = -1;
    } else if (prob->priority_adjustment < -1 && prob->priority_adjustment == aprob->priority_adjustment) {
        prob->priority_adjustment = -1;
    }
    for (int field_id = 1; field_id < CNTSPROB_LAST_FIELD; ++field_id) {
        if (problem_typically_ignored_fields[field_id]) continue;
        switch (field_id) {
        case CNTSPROB_abstract:
        case CNTSPROB_super:
        case CNTSPROB_examinator_num:
        case CNTSPROB_time_limit_millis:
        case CNTSPROB_time_limit:
        case CNTSPROB_input_file:
        case CNTSPROB_output_file:
        case CNTSPROB_full_score:
        case CNTSPROB_test_score:
        case CNTSPROB_run_penalty:
        case CNTSPROB_acm_run_penalty:
        case CNTSPROB_priority_adjustment:
            continue;
        }
        int t = cntsprob_get_type(field_id);
        void *ptr = cntsprob_get_ptr_nc(prob, field_id);
        const void *aptr = cntsprob_get_ptr(aprob, field_id);

        switch (t) {
        case 'i': { // int
            int *field_ptr = (int*) ptr;
            const int *afield_ptr = (const int *) aptr;
            if (*field_ptr < 0) {
                *field_ptr = -1;
            } else if (*field_ptr == *afield_ptr) {
                *field_ptr = -1;
            }
            break;
        }
        case 'S': // unsigned char[]
            break;
        case 'f': { // ejbyteflag_t
            ejbyteflag_t *field_ptr = (ejbyteflag_t *) ptr;
            const ejbyteflag_t *afield_ptr = (const ejbyteflag_t *) aptr;
            if (*field_ptr < 0) {
                *field_ptr = -1;
            } else if (*field_ptr > 0) {
                if (*afield_ptr > 0) {
                    *field_ptr = -1;
                } else {
                    *field_ptr = 1;
                }
            } else if (!*afield_ptr) {
                *field_ptr = -1;
            }
            break;
        }
        case 's': { // unsigned char *
            unsigned char **field_ptr = (unsigned char **) ptr;
            const unsigned char **afield_ptr = (const unsigned char **) aptr;
            if (*field_ptr && *afield_ptr) {
                if (!strcmp(*field_ptr, *afield_ptr)) {
                    xfree(*field_ptr); *field_ptr = NULL;
                }
            } else if (*field_ptr && !**field_ptr && !*afield_ptr) {
                xfree(*field_ptr); *field_ptr = NULL;
            }
            break;
        }
        case 'x': // char **
            break;
        case 't': { // time_t
            time_t *field_ptr = (time_t *) ptr;
            const time_t *afield_ptr = (const time_t *) aptr;
            if (*field_ptr < 0) {
                *field_ptr = -1;
            } else if (*field_ptr >= 0 && *field_ptr == *afield_ptr) {
                *field_ptr = -1;
            }
            break;
        }
        case 'X': // ejenvlist_t
            break;
        case 'E': { // ej_size64_t
            ej_size64_t *field_ptr = (ej_size64_t *) ptr;
            const ej_size64_t *afield_ptr = (const ej_size64_t *) aptr;
            if (*field_ptr < 0) {
                *field_ptr = -1;
            } else if (*field_ptr >= 0 && *field_ptr == *afield_ptr) {
                *field_ptr = -1;
            }
            break;
        }
        }
    }
}

void
problem_minimize(struct section_problem_data *prob, const struct section_problem_data *aprob)
{
    if (prob->abstract > 0) {
        problem_minimize_abstract(prob);
    } else if (!prob->super[0]) {
        problem_minimize_standalone(prob);
    } else {
        problem_minimize_inherited(prob, aprob);
    }
}

int
problem_delete_field(struct section_problem_data *prob, int field_id)
{
    if (problem_typically_ignored_fields[field_id]) {
        return -1;
    }

    switch (field_id) {
    case CNTSPROB_abstract:
    case CNTSPROB_short_name:
    case CNTSPROB_id:
        return -1;
    case CNTSPROB_priority_adjustment:
        prob->priority_adjustment = 0;
        return 0;
    default:
        break;
    }

    int t = cntsprob_get_type(field_id);
    void *ptr = cntsprob_get_ptr_nc(prob, field_id);
    switch (t) {
    case 'i': { // int
        int *field_ptr = (int*) ptr;
        *field_ptr = -1;
        break;
    }
    case 'S': { // unsigned char[]
        unsigned char *field_ptr = (unsigned char *) ptr;
        *field_ptr = 0;
        break;
    }
    case 'f': { // ejbyteflag_t
        ejbyteflag_t *field_ptr = (ejbyteflag_t *) ptr;
        *field_ptr = -1;
        break;
    }
    case 's': { // unsigned char *
        unsigned char **field_ptr = (unsigned char **) ptr;
        xfree(*field_ptr); *field_ptr = NULL;
        break;
    }
    case 'x': { // char **
        char ***field_ptr = (char ***) ptr;
        sarray_free(*field_ptr); *field_ptr = NULL;
        break;
    }
    case 't': { // time_t
        time_t *field_ptr = (time_t *) ptr;
        *field_ptr = -1;
        break;
    }
    case 'X': { // ejenvlist_t
        char ***field_ptr = (char ***) ptr;
        sarray_free(*field_ptr); *field_ptr = NULL;
        break;
    }
    case 'E': { // ej_size64_t
        ej_size64_t *field_ptr = (ej_size64_t *) ptr;
        *field_ptr = -1;
        break;
    }
    }
    return 0;
}