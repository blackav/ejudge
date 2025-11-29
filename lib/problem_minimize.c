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
#include "ejudge/prepare_dflt.h"
#include "ejudge/problem_common.h"
#include "ejudge/problem_config.h"
#include "ejudge/xalloc.h"
#include "ejudge/cJSON.h"
#include "ejudge/xml_utils.h"
#include "ejudge/meta/prepare_meta.h"
#include "ejudge/meta/problem_config_meta.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <math.h>
#include <errno.h>

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
problem_delete_field(
        struct section_problem_data *prob,
        int field_id,
        int *p_changed)
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
        if (prob->priority_adjustment != 0) {
            prob->priority_adjustment = 0;
            *p_changed = 1;
        }
        return 0;
    default:
        break;
    }

    int t = cntsprob_get_type(field_id);
    void *ptr = cntsprob_get_ptr_nc(prob, field_id);
    switch (t) {
    case 'i': { // int
        int *field_ptr = (int*) ptr;
        if (*field_ptr != -1) {
            *field_ptr = -1;
            *p_changed = 1;
        }
        break;
    }
    case 'S': { // unsigned char[]
        unsigned char *field_ptr = (unsigned char *) ptr;
        if (*field_ptr) {
            *field_ptr = 0;
            *p_changed = 1;
        }
        break;
    }
    case 'f': { // ejbyteflag_t
        ejbyteflag_t *field_ptr = (ejbyteflag_t *) ptr;
        if (*field_ptr != -1) {
            *field_ptr = -1;
            *p_changed = 1;
        }
        break;
    }
    case 's': { // unsigned char *
        unsigned char **field_ptr = (unsigned char **) ptr;
        if (*field_ptr) {
            xfree(*field_ptr); *field_ptr = NULL;
            *p_changed = 1;
        }
        break;
    }
    case 'x': { // char **
        char ***field_ptr = (char ***) ptr;
        if (*field_ptr) {
            sarray_free(*field_ptr); *field_ptr = NULL;
            *p_changed = 1;
        }
        break;
    }
    case 't': { // time_t
        time_t *field_ptr = (time_t *) ptr;
        if (*field_ptr != -1) {
            *field_ptr = -1;
            *p_changed = 1;
        }
        break;
    }
    case 'X': { // ejenvlist_t
        char ***field_ptr = (char ***) ptr;
        if (*field_ptr) {
            sarray_free(*field_ptr); *field_ptr = NULL;
            *p_changed = 1;
        }
        break;
    }
    case 'E': { // ej_size64_t
        ej_size64_t *field_ptr = (ej_size64_t *) ptr;
        if (*field_ptr != -1) {
            *field_ptr = -1;
            *p_changed = 1;
        }
        break;
    }
    }
    return 0;
}

static int __attribute__((format(printf,3,4)))
flog(FILE *f, const unsigned char *name, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    char buf[1024];
    if (f) {
        vsnprintf(buf, sizeof(buf), format, args);
        fprintf(f, "field %s: %s\n", name, buf);
    }
    va_end(args);
    return -1;
}

static int
parse_json_int(
        FILE *log_f,
        const unsigned char *name,
        cJSON *jv,
        int *p_v)
{
    if (!jv) {
        return flog(log_f, name, "is missing");
    } else if (jv->type == cJSON_Number) {
        if (isnan(jv->valuedouble)) {
            return flog(log_f, name, "is NaN");
        }
        if (jv->valuedouble < INT_MIN || jv->valuedouble > INT_MAX) {
            return flog(log_f, name, "is out of range");
        }
        double fp = 0;
        if (modf(jv->valuedouble, &fp)) {
            return flog(log_f, name, "is not integral");
        }
        if (p_v) *p_v = (int) jv->valuedouble;
        return 1;
    } else if (jv->type == cJSON_String) {
        char *eptr = NULL;
        errno = 0;
        long v = strtol(jv->valuestring, &eptr, 10);
        if (errno || *eptr || eptr == jv->valuestring || (int) v != v) {
            return flog(log_f, name, "value is invalid");
        }
        if (p_v) *p_v = (int) v;
        return 1;
    } else {
        return flog(log_f, name, "has invalid type");
    }
}

static int
parse_json_bool(
        FILE *log_f,
        const unsigned char *name,
        cJSON *jv,
        ejbyteflag_t *p_v)
{
    if (!jv) {
        return flog(log_f, name, "is missing");
    } else if (jv->type == cJSON_Number) {
        if (isnan(jv->valuedouble)) {
            return flog(log_f, name, "is NaN");
        }
        if (jv->valuedouble > 0) {
            if (p_v) *p_v = 1;
        } else if (jv->valuedouble < 0) {
            return flog(log_f, name, "invalid value");
        } else {
            if (p_v) *p_v = 0;
        }
        return 1;
    } else if (jv->type == cJSON_True) {
        if (p_v) *p_v = 1;
        return 1;
    } else if (jv->type == cJSON_False) {
        if (p_v) *p_v = 0;
        return 1;
    } else if (jv->type == cJSON_String) {
        if (!strcasecmp(jv->valuestring, "true")
            || !strcasecmp(jv->valuestring, "on")
            || !strcasecmp(jv->valuestring, "yes")) {
            if (p_v) *p_v = 1;
            return 1;
        }
        if (!strcasecmp(jv->valuestring, "false")
            || !strcasecmp(jv->valuestring, "off")
            || !strcasecmp(jv->valuestring, "no")) {
            if (p_v) *p_v = 0;
            return 1;
        }
        char *eptr = NULL;
        errno = 0;
        long v = strtol(jv->valuestring, &eptr, 10);
        if (errno || *eptr || eptr == jv->valuestring || (int) v != v) {
            return flog(log_f, name, "value is invalid");
        }
        if (v > 0) {
            if (p_v) *p_v = 1;
        } else if (v < 0) {
            return flog(log_f, name, "invalid value");
        } else {
            if (p_v) *p_v = 0;
        }
        return 1;
    } else {
        return flog(log_f, name, "has invalid type");
    }
}

static int
parse_json_size64(
        FILE *log_f,
        const unsigned char *name,
        cJSON *jv,
        ej_size64_t *p_v)
{
    if (!jv) {
        return flog(log_f, name, "is missing");
    } else if (jv->type == cJSON_Number) {
        if (isnan(jv->valuedouble)) {
            return flog(log_f, name, "is NaN");
        }
        if (jv->valuedouble < INT_MIN || jv->valuedouble > INT_MAX) {
            return flog(log_f, name, "is out of range");
        }
        double fp = 0;
        if (modf(jv->valuedouble, &fp)) {
            return flog(log_f, name, "is not integral");
        }
        if (p_v) *p_v = (int) jv->valuedouble;
        return 1;
    } else if (jv->type == cJSON_String) {
        char *eptr = NULL;
        errno = 0;
        long long v = strtoll(jv->valuestring, &eptr, 10);
        if (errno || eptr == jv->valuestring || v < 0) {
            return flog(log_f, name, "value is invalid");
        }
        if (*eptr == 'k' || *eptr == 'K') {
            if (__builtin_mul_overflow(v, 1024LL, &v)) {
                return flog(log_f, name, "value is invalid");
            }
        } else if (*eptr == 'm' || *eptr == 'M') {
            if (__builtin_mul_overflow(v, 1024LL*1024LL, &v)) {
                return flog(log_f, name, "value is invalid");
            }
        } else if (*eptr == 'g' || *eptr == 'G') {
            if (__builtin_mul_overflow(v, 1024LL*1024LL*1024LL, &v)) {
                return flog(log_f, name, "value is invalid");
            }
        }
        if (*eptr) {
            return flog(log_f, name, "value is invalid");
        }
        if (p_v) *p_v = (ej_size64_t) v;
        return 1;
    } else {
        return flog(log_f, name, "has invalid type");
    }
}

static int
parse_json_time(
        FILE *log_f,
        const unsigned char *name,
        cJSON *jv,
        time_t *p_v)
{
    if (!jv) {
        return flog(log_f, name, "is missing");
    } else if (jv->type == cJSON_Number) {
        if (isnan(jv->valuedouble)) {
            return flog(log_f, name, "is NaN");
        }
        if (jv->valuedouble < 0 || jv->valuedouble > LONG_LONG_MAX) {
            return flog(log_f, name, "is out of range");
        }
        double fp = 0;
        if (modf(jv->valuedouble, &fp)) {
            return flog(log_f, name, "is not integral");
        }
        long long llv = (long long) jv->valuedouble;
        if ((time_t) llv != llv) {
            return flog(log_f, name, "is out of range");
        }
        if (p_v) *p_v = (time_t) jv->valuedouble;
        return 1;
    } else if (jv->type == cJSON_String) {
        time_t value = 0;
        if (xml_parse_date(NULL, NULL, 0, 0, jv->valuestring, &value) < 0) {
            return flog(log_f, name, "is invalid");
        }
        if (value < 0) {
            return flog(log_f, name, "is out of range");
        }
        if (p_v) *p_v = value;
        return 1;
    } else {
        return flog(log_f, name, "has invalid type");
    }
}

static int
parse_json_sarray(
        FILE *log_f,
        const unsigned char *name,
        cJSON *jv,
        char ***p_v)
{
    if (!jv) {
        return flog(log_f, name, "is missing");
    } else if (jv->type == cJSON_Array) {
        int len = 0;
        for (cJSON *c = jv->child; c; c = c->next) {
            if (c->type != cJSON_String) {
                return flog(log_f, name, "has invalid element type");
            }
            ++len;
        }
        if (!p_v) {
            return 0;
        }
        char **res = NULL;
        XCALLOC(res, len + 1);
        int i = 0;
        for (cJSON *c = jv->child; c; c = c->next) {
            if (c->type == cJSON_String) {
                res[i] = xstrdup(c->valuestring);
            }
            ++i;
        }
        *p_v = res;
        return 1;
    } else {
        return flog(log_f, name, "has invalid type");
    }
}

static int
strcmpex(const unsigned char *s1, const unsigned char *s2)
{
    if (!s1 && !s2) {
        return 0;
    } else if (!s1) {
        return -1;
    } else if (!s2) {
        return 1;
    } else {
        return strcmp(s1, s2);
    }
}

int
problem_assign_json(
        struct section_problem_data *prob,
        cJSON *protected_fields,
        cJSON *allowed_fields,
        cJSON *jp,
        FILE *log_f,
        int *p_changed)
{
    unsigned char ignored_fields[CNTSPROB_LAST_FIELD];
    unsigned char af[CNTSPROB_LAST_FIELD];
    memcpy(ignored_fields, problem_typically_ignored_fields, sizeof(ignored_fields));
    if (prob->abstract > 0) {
        ignored_fields[CNTSPROB_short_name] = 1;
    }
    ignored_fields[CNTSPROB_id] = 1;
    ignored_fields[CNTSPROB_abstract] = 1;
    if (protected_fields && protected_fields->type == cJSON_Array) {
        for (cJSON *c = protected_fields->child; c; c = c->next) {
            if (c->type == cJSON_String) {
                int id = cntsprob_lookup_field(c->valuestring);
                if (id >= 1 && id < CNTSPROB_LAST_FIELD) {
                    ignored_fields[id] = 1;
                }
            }
        }
    }
    memset(af, 0, sizeof(af));
    if (allowed_fields && allowed_fields->type == cJSON_Array) {
        for (cJSON *c = allowed_fields->child; c; c = c->next) {
            if (c->type == cJSON_String) {
                int id = cntsprob_lookup_field(c->valuestring);
                if (id >= 1 && id < CNTSPROB_LAST_FIELD) {
                    af[id] = 1;
                }
            }
        }
        for (int field_id = CNTSPROB_id; field_id < CNTSPROB_LAST_FIELD; ++field_id) {
            if (af[field_id]) {
                ignored_fields[field_id] = 1;
            }
        }
    }
    for (int field_id = CNTSPROB_id; field_id < CNTSPROB_LAST_FIELD; ++field_id) {
        if (ignored_fields[field_id]) continue;
        const unsigned char *field_name = cntsprob_get_name(field_id);
        cJSON *ji = cJSON_GetObjectItem(jp, field_name);
        if (!ji) {
            problem_delete_field(prob, field_id, p_changed);
            continue;
        }
        if (field_id == CNTSPROB_type) {
            if (ji->type != cJSON_String) {
                flog(log_f, field_name, "invalid value");
                continue;
            }
            int val = problem_parse_type(ji->valuestring);
            if (val < 0) {
                flog(log_f, field_name, "invalid value");
                continue;
            }
            if (prob->type != val) {
                prob->type = val;
                *p_changed = 1;
            }
            continue;
        }
        int t = cntsprob_get_type(field_id);
        void *ptr = cntsprob_get_ptr_nc(prob, field_id);
        switch (t) {
        case 'i': {
            int *p = (int*) ptr;
            int value = 0;
            if (parse_json_int(log_f, field_name, ji, &value) < 0) {
                break;
            }
            if (field_id == CNTSPROB_priority_adjustment) {
                if (value < -16 || value > 15) {
                    flog(log_f, field_name, "invalid value");
                    continue;
                }
                if (*p != value) {
                    *p = value;
                    *p_changed = 1;
                }
                continue;
            }
            if (value < 0) {
                flog(log_f, field_name, "invalid value");
                continue;
            }
            /*
              tester_id variant_num full_score full_user_score min_score_1
              min_score_2 examinator_num real_time_limit time_limit time_limit_millis
              test_score run_penalty acm_run_penalty disqualified_penalty compile_error_penalty
              tests_to_accept min_tests_to_accept checker_real_time_limit checker_time_limit_ms score_multiplier
              prev_runs_to_show max_user_run_count interactor_time_limit interactor_real_time_limit max_open_file_count
              max_process_count
             */
            if (*p != value) {
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 'S': {
            unsigned char *p = (unsigned char*) ptr;
            if (ji->type != cJSON_String) {
                flog(log_f, field_name, "invalid value");
                continue;
            }
            size_t sz = cntsprob_get_size(field_id);
            if (strlen(ji->valuestring) >= sz) {
                flog(log_f, field_name, "too long");
                continue;
            }
            /*
              super short_name
             */
            if (strcmp(p, ji->valuestring) != 0) {
                snprintf(p, sz, "%s", ji->valuestring);
                *p_changed = 1;
            }
            break;
        }
        case 'f': {
            ejbyteflag_t *p = (ejbyteflag_t*) ptr;
            ejbyteflag_t value = 0;
            if (parse_json_bool(log_f, field_name, ji, &value) < 0) {
                break;
            }
            /*
              manual_checking check_presentation scoring_checker enable_checker_token interactive_valuer
              disable_pe disable_wtl wtl_is_cf use_stdin use_stdout
              combined_stdin combined_stdout binary_input binary ignore_exit_code
              ignore_term_signal olympiad_mode score_latest score_latest_or_unmarked score_latest_marked
              score_tokenized use_ac_not_ok ignore_prev_ac team_enable_rep_view team_enable_ce_view
              team_show_judge_report show_checker_comment ignore_compile_errors variable_full_score ignore_penalty
              use_corr use_info use_tgz accept_partial disable_user_submit
              disable_tab unrestricted_statement statement_ignore_ip restricted_statement enable_submit_after_reject
              hide_file_names hide_real_time_limit enable_tokens tokens_for_user_ac disable_submit_after_ok
              disable_auto_testing disable_testing enable_compilation skip_testing hidden
              stand_hide_time advance_to_next disable_ctrl_chars enable_text_form stand_ignore_score
              stand_last_column disable_security enable_suid_run enable_container enable_dynamic_priority
              valuer_sets_marked ignore_unmarked disable_stderr enable_process_group enable_kill_all
              hide_variant enable_testlib_mode autoassign_variants require_any enable_extended_info
              stop_on_first_fail enable_control_socket copy_exe_to_tgzdir enable_multi_header use_lang_multi_header
              notify_on_submit enable_user_input enable_vcs enable_iframe_statement enable_src_for_testing
              disable_vm_size_limit enable_group_merge ignore_sigpipe
             */
            if (*p != value) {
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 's': {
            unsigned char **p = (unsigned char **) ptr;
            if (ji->type != cJSON_String) {
                flog(log_f, field_name, "invalid value");
                continue;
            }
            if (field_id == CNTSPROB_normalization) {
                if (test_normalization_parse(ji->valuestring) < 0) {
                    flog(log_f, field_name, "invalid value");
                    continue;
                }
            }
            if (field_id == CNTSPROB_src_normalization) {
                if (test_normalization_parse(ji->valuestring) < 0) {
                    flog(log_f, field_name, "invalid value");
                    continue;
                }
            }
            /*
              long_name stand_name stand_column group_name internal_name
              plugin_entry_name uuid problem_dir test_dir test_sfx
              corr_dir corr_sfx info_dir info_sfx tgz_dir
              tgz_sfx tgzdir_sfx input_file output_file test_score_list
              tokens umask ok_status header_pat footer_pat
              compiler_env_pat container_options score_tests standard_checker spelling
              statement_file alternatives_file plugin_file xml_file stand_attr
              source_header source_footer custom_compile_cmd custom_lang_name extra_src_dir
              standard_valuer test_pat corr_pat info_pat tgz_pat
              tgzdir_pat normalization check_cmd valuer_cmd interactor_cmd
              style_checker_cmd test_checker_cmd test_generator_cmd init_cmd start_cmd
              solution_src solution_cmd post_pull_cmd vcs_compile_cmd super_run_dir
              score_bonus open_tests final_open_tests token_open_tests extid src_normalization
             */
            if (strcmpex(*p, ji->valuestring) != 0) {
                if (*p) {
                    xfree(*p); *p = NULL;
                }
                *p = xstrdup(ji->valuestring);
                *p_changed = 1;
            }
            break;
        }
        case 'x': {
            char ***p = (char***) ptr;
            char **value = NULL;
            if (parse_json_sarray(log_f, field_name, ji, &value) < 0) {
                break;
            }
            /*
              test_sets date_penalty group_start_date group_deadline disable_language
              enable_language require provide_ok allow_ip lang_time_adj
              lang_time_adj_millis lang_max_vm_size lang_max_stack_size lang_max_rss_size checker_extra_files
              alternative personal_deadline score_view
             */
            if (sarray_cmp(*p, value) != 0) {
                sarray_free(*p);
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 't': {
            time_t *p = (time_t*) ptr;
            time_t value = 0;
            if (parse_json_time(log_f, field_name, ji, &value) < 0) {
                break;
            }
            /*
              deadline start_date
             */
            if (*p != value) {
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 'X': {
            ejenvlist_t *p = (ejenvlist_t*) ptr;
            char **value = NULL;
            if (parse_json_sarray(log_f, field_name, ji, &value) < 0) {
                break;
            }
            /*
              lang_compiler_env lang_compiler_container_options checker_env valuer_env interactor_env
              style_checker_env test_checker_env test_generator_env init_env start_env
              statement_env
             */
            if (sarray_cmp(*p, value) != 0) {
                sarray_free(*p);
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 'E': {
            ej_size64_t *p = (ej_size64_t*) ptr;
            ej_size64_t value = 0;
            if (parse_json_size64(log_f, field_name, ji, &value) < 0) {
                break;
            }
            /*
              max_vm_size max_data_size max_stack_size max_rss_size max_core_size
              max_file_size checker_max_vm_size checker_max_stack_size checker_max_rss_size
             */
            if (*p != value) {
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        }
    }
    return 0;
}

static const int cnts_to_cfg_field_map[CNTSPROB_LAST_FIELD] =
{
  [CNTSPROB_id] = META_PROBLEM_CONFIG_SECTION_id,
  [CNTSPROB_tester_id] = 0,
  [CNTSPROB_type] = META_PROBLEM_CONFIG_SECTION_type,
  [CNTSPROB_variant_num] = META_PROBLEM_CONFIG_SECTION_variant_num,
  [CNTSPROB_full_score] = META_PROBLEM_CONFIG_SECTION_full_score,
  [CNTSPROB_full_user_score] = META_PROBLEM_CONFIG_SECTION_full_user_score,
  [CNTSPROB_min_score_1] = META_PROBLEM_CONFIG_SECTION_min_score_1,
  [CNTSPROB_min_score_2] = META_PROBLEM_CONFIG_SECTION_min_score_2,
  [CNTSPROB_super] = 0,
  [CNTSPROB_short_name] = META_PROBLEM_CONFIG_SECTION_short_name,
  [CNTSPROB_abstract] = 0,
  [CNTSPROB_manual_checking] = META_PROBLEM_CONFIG_SECTION_manual_checking,
  [CNTSPROB_check_presentation] = META_PROBLEM_CONFIG_SECTION_check_presentation,
  [CNTSPROB_scoring_checker] = META_PROBLEM_CONFIG_SECTION_scoring_checker,
  [CNTSPROB_enable_checker_token] = META_PROBLEM_CONFIG_SECTION_enable_checker_token,
  [CNTSPROB_interactive_valuer] = META_PROBLEM_CONFIG_SECTION_interactive_valuer,
  [CNTSPROB_disable_pe] = META_PROBLEM_CONFIG_SECTION_disable_pe,
  [CNTSPROB_disable_wtl] = META_PROBLEM_CONFIG_SECTION_disable_wtl,
  [CNTSPROB_wtl_is_cf] = META_PROBLEM_CONFIG_SECTION_wtl_is_cf,
  [CNTSPROB_use_stdin] = META_PROBLEM_CONFIG_SECTION_use_stdin,
  [CNTSPROB_use_stdout] = META_PROBLEM_CONFIG_SECTION_use_stdout,
  [CNTSPROB_combined_stdin] = META_PROBLEM_CONFIG_SECTION_combined_stdin,
  [CNTSPROB_combined_stdout] = META_PROBLEM_CONFIG_SECTION_combined_stdout,
  [CNTSPROB_binary_input] = META_PROBLEM_CONFIG_SECTION_binary_input,
  [CNTSPROB_binary] = META_PROBLEM_CONFIG_SECTION_binary,
  [CNTSPROB_ignore_exit_code] = META_PROBLEM_CONFIG_SECTION_ignore_exit_code,
  [CNTSPROB_ignore_term_signal] = META_PROBLEM_CONFIG_SECTION_ignore_term_signal,
  [CNTSPROB_olympiad_mode] = META_PROBLEM_CONFIG_SECTION_olympiad_mode,
  [CNTSPROB_score_latest] = META_PROBLEM_CONFIG_SECTION_score_latest,
  [CNTSPROB_score_latest_or_unmarked] = META_PROBLEM_CONFIG_SECTION_score_latest_or_unmarked,
  [CNTSPROB_score_latest_marked] = META_PROBLEM_CONFIG_SECTION_score_latest_marked,
  [CNTSPROB_score_tokenized] = META_PROBLEM_CONFIG_SECTION_score_tokenized,
  [CNTSPROB_use_ac_not_ok] = META_PROBLEM_CONFIG_SECTION_use_ac_not_ok,
  [CNTSPROB_ignore_prev_ac] = META_PROBLEM_CONFIG_SECTION_ignore_prev_ac,
  [CNTSPROB_team_enable_rep_view] = META_PROBLEM_CONFIG_SECTION_team_enable_rep_view,
  [CNTSPROB_team_enable_ce_view] = META_PROBLEM_CONFIG_SECTION_team_enable_ce_view,
  [CNTSPROB_team_show_judge_report] = META_PROBLEM_CONFIG_SECTION_team_show_judge_report,
  [CNTSPROB_show_checker_comment] = META_PROBLEM_CONFIG_SECTION_show_checker_comment,
  [CNTSPROB_ignore_compile_errors] = META_PROBLEM_CONFIG_SECTION_ignore_compile_errors,
  [CNTSPROB_variable_full_score] = META_PROBLEM_CONFIG_SECTION_variable_full_score,
  [CNTSPROB_ignore_penalty] = META_PROBLEM_CONFIG_SECTION_ignore_penalty,
  [CNTSPROB_use_corr] = META_PROBLEM_CONFIG_SECTION_use_corr,
  [CNTSPROB_use_info] = META_PROBLEM_CONFIG_SECTION_use_info,
  [CNTSPROB_use_tgz] = META_PROBLEM_CONFIG_SECTION_use_tgz,
  [CNTSPROB_accept_partial] = META_PROBLEM_CONFIG_SECTION_accept_partial,
  [CNTSPROB_disable_user_submit] = META_PROBLEM_CONFIG_SECTION_disable_user_submit,
  [CNTSPROB_disable_tab] = META_PROBLEM_CONFIG_SECTION_disable_tab,
  [CNTSPROB_unrestricted_statement] = META_PROBLEM_CONFIG_SECTION_unrestricted_statement,
  [CNTSPROB_statement_ignore_ip] = META_PROBLEM_CONFIG_SECTION_statement_ignore_ip,
  [CNTSPROB_restricted_statement] = META_PROBLEM_CONFIG_SECTION_restricted_statement,
  [CNTSPROB_enable_submit_after_reject] = META_PROBLEM_CONFIG_SECTION_enable_submit_after_reject,
  [CNTSPROB_hide_file_names] = META_PROBLEM_CONFIG_SECTION_hide_file_names,
  [CNTSPROB_hide_real_time_limit] = META_PROBLEM_CONFIG_SECTION_hide_real_time_limit,
  [CNTSPROB_enable_tokens] = META_PROBLEM_CONFIG_SECTION_enable_tokens,
  [CNTSPROB_tokens_for_user_ac] = META_PROBLEM_CONFIG_SECTION_tokens_for_user_ac,
  [CNTSPROB_disable_submit_after_ok] = META_PROBLEM_CONFIG_SECTION_disable_submit_after_ok,
  [CNTSPROB_disable_auto_testing] = META_PROBLEM_CONFIG_SECTION_disable_auto_testing,
  [CNTSPROB_disable_testing] = META_PROBLEM_CONFIG_SECTION_disable_testing,
  [CNTSPROB_enable_compilation] = META_PROBLEM_CONFIG_SECTION_enable_compilation,
  [CNTSPROB_skip_testing] = META_PROBLEM_CONFIG_SECTION_skip_testing,
  [CNTSPROB_hidden] = META_PROBLEM_CONFIG_SECTION_hidden,
  [CNTSPROB_stand_hide_time] = META_PROBLEM_CONFIG_SECTION_stand_hide_time,
  [CNTSPROB_advance_to_next] = META_PROBLEM_CONFIG_SECTION_advance_to_next,
  [CNTSPROB_disable_ctrl_chars] = META_PROBLEM_CONFIG_SECTION_disable_ctrl_chars,
  [CNTSPROB_enable_text_form] = META_PROBLEM_CONFIG_SECTION_enable_text_form,
  [CNTSPROB_stand_ignore_score] = META_PROBLEM_CONFIG_SECTION_stand_ignore_score,
  [CNTSPROB_stand_last_column] = META_PROBLEM_CONFIG_SECTION_stand_last_column,
  [CNTSPROB_disable_security] = META_PROBLEM_CONFIG_SECTION_disable_security,
  [CNTSPROB_enable_suid_run] = META_PROBLEM_CONFIG_SECTION_enable_suid_run,
  [CNTSPROB_enable_container] = META_PROBLEM_CONFIG_SECTION_enable_container,
  [CNTSPROB_enable_dynamic_priority] = META_PROBLEM_CONFIG_SECTION_enable_dynamic_priority,
  [CNTSPROB_valuer_sets_marked] = META_PROBLEM_CONFIG_SECTION_valuer_sets_marked,
  [CNTSPROB_ignore_unmarked] = META_PROBLEM_CONFIG_SECTION_ignore_unmarked,
  [CNTSPROB_disable_stderr] = META_PROBLEM_CONFIG_SECTION_disable_stderr,
  [CNTSPROB_enable_process_group] = META_PROBLEM_CONFIG_SECTION_enable_process_group,
  [CNTSPROB_enable_kill_all] = META_PROBLEM_CONFIG_SECTION_enable_kill_all,
  [CNTSPROB_hide_variant] = META_PROBLEM_CONFIG_SECTION_hide_variant,
  [CNTSPROB_enable_testlib_mode] = META_PROBLEM_CONFIG_SECTION_enable_testlib_mode,
  [CNTSPROB_autoassign_variants] = META_PROBLEM_CONFIG_SECTION_autoassign_variants,
  [CNTSPROB_require_any] = META_PROBLEM_CONFIG_SECTION_require_any,
  [CNTSPROB_enable_extended_info] = META_PROBLEM_CONFIG_SECTION_enable_extended_info,
  [CNTSPROB_stop_on_first_fail] = META_PROBLEM_CONFIG_SECTION_stop_on_first_fail,
  [CNTSPROB_enable_control_socket] = META_PROBLEM_CONFIG_SECTION_enable_control_socket,
  [CNTSPROB_copy_exe_to_tgzdir] = META_PROBLEM_CONFIG_SECTION_copy_exe_to_tgzdir,
  [CNTSPROB_enable_multi_header] = META_PROBLEM_CONFIG_SECTION_enable_multi_header,
  [CNTSPROB_use_lang_multi_header] = META_PROBLEM_CONFIG_SECTION_use_lang_multi_header,
  [CNTSPROB_notify_on_submit] = META_PROBLEM_CONFIG_SECTION_notify_on_submit,
  [CNTSPROB_enable_user_input] = META_PROBLEM_CONFIG_SECTION_enable_user_input,
  [CNTSPROB_enable_vcs] = META_PROBLEM_CONFIG_SECTION_enable_vcs,
  [CNTSPROB_enable_iframe_statement] = META_PROBLEM_CONFIG_SECTION_enable_iframe_statement,
  [CNTSPROB_enable_src_for_testing] = META_PROBLEM_CONFIG_SECTION_enable_src_for_testing,
  [CNTSPROB_disable_vm_size_limit] = META_PROBLEM_CONFIG_SECTION_disable_vm_size_limit,
  [CNTSPROB_enable_group_merge] = META_PROBLEM_CONFIG_SECTION_enable_group_merge,
  [CNTSPROB_ignore_sigpipe] = META_PROBLEM_CONFIG_SECTION_ignore_sigpipe,
  [CNTSPROB_examinator_num] = 0,
  [CNTSPROB_real_time_limit] = META_PROBLEM_CONFIG_SECTION_real_time_limit,
  [CNTSPROB_time_limit] = META_PROBLEM_CONFIG_SECTION_time_limit,
  [CNTSPROB_time_limit_millis] = META_PROBLEM_CONFIG_SECTION_time_limit_millis,
  [CNTSPROB_test_score] = META_PROBLEM_CONFIG_SECTION_test_score,
  [CNTSPROB_run_penalty] = META_PROBLEM_CONFIG_SECTION_run_penalty,
  [CNTSPROB_acm_run_penalty] = META_PROBLEM_CONFIG_SECTION_acm_run_penalty,
  [CNTSPROB_disqualified_penalty] = META_PROBLEM_CONFIG_SECTION_disqualified_penalty,
  [CNTSPROB_compile_error_penalty] = META_PROBLEM_CONFIG_SECTION_compile_error_penalty,
  [CNTSPROB_tests_to_accept] = META_PROBLEM_CONFIG_SECTION_tests_to_accept,
  [CNTSPROB_min_tests_to_accept] = META_PROBLEM_CONFIG_SECTION_min_tests_to_accept,
  [CNTSPROB_checker_real_time_limit] = META_PROBLEM_CONFIG_SECTION_checker_real_time_limit,
  [CNTSPROB_checker_time_limit_ms] = META_PROBLEM_CONFIG_SECTION_checker_time_limit_ms,
  [CNTSPROB_priority_adjustment] = META_PROBLEM_CONFIG_SECTION_priority_adjustment,
  [CNTSPROB_score_multiplier] = META_PROBLEM_CONFIG_SECTION_score_multiplier,
  [CNTSPROB_prev_runs_to_show] = META_PROBLEM_CONFIG_SECTION_prev_runs_to_show,
  [CNTSPROB_max_user_run_count] = META_PROBLEM_CONFIG_SECTION_max_user_run_count,
  [CNTSPROB_long_name] = META_PROBLEM_CONFIG_SECTION_long_name,
  [CNTSPROB_stand_name] = META_PROBLEM_CONFIG_SECTION_stand_name,
  [CNTSPROB_stand_column] = META_PROBLEM_CONFIG_SECTION_stand_column,
  [CNTSPROB_group_name] = META_PROBLEM_CONFIG_SECTION_group_name,
  [CNTSPROB_internal_name] = META_PROBLEM_CONFIG_SECTION_internal_name,
  [CNTSPROB_plugin_entry_name] = META_PROBLEM_CONFIG_SECTION_plugin_entry_name,
  [CNTSPROB_uuid] = META_PROBLEM_CONFIG_SECTION_uuid,
  [CNTSPROB_problem_dir] = 0,
  [CNTSPROB_test_dir] = META_PROBLEM_CONFIG_SECTION_test_dir,
  [CNTSPROB_test_sfx] = META_PROBLEM_CONFIG_SECTION_test_sfx,
  [CNTSPROB_corr_dir] = META_PROBLEM_CONFIG_SECTION_corr_dir,
  [CNTSPROB_corr_sfx] = META_PROBLEM_CONFIG_SECTION_corr_sfx,
  [CNTSPROB_info_dir] = META_PROBLEM_CONFIG_SECTION_info_dir,
  [CNTSPROB_info_sfx] = META_PROBLEM_CONFIG_SECTION_info_sfx,
  [CNTSPROB_tgz_dir] = META_PROBLEM_CONFIG_SECTION_tgz_dir,
  [CNTSPROB_tgz_sfx] = META_PROBLEM_CONFIG_SECTION_tgz_sfx,
  [CNTSPROB_tgzdir_sfx] = META_PROBLEM_CONFIG_SECTION_tgzdir_sfx,
  [CNTSPROB_input_file] = META_PROBLEM_CONFIG_SECTION_input_file,
  [CNTSPROB_output_file] = META_PROBLEM_CONFIG_SECTION_output_file,
  [CNTSPROB_test_score_list] = META_PROBLEM_CONFIG_SECTION_test_score_list,
  [CNTSPROB_tokens] = META_PROBLEM_CONFIG_SECTION_tokens,
  [CNTSPROB_umask] = META_PROBLEM_CONFIG_SECTION_umask,
  [CNTSPROB_ok_status] = META_PROBLEM_CONFIG_SECTION_ok_status,
  [CNTSPROB_header_pat] = META_PROBLEM_CONFIG_SECTION_header_pat,
  [CNTSPROB_footer_pat] = META_PROBLEM_CONFIG_SECTION_footer_pat,
  [CNTSPROB_compiler_env_pat] = META_PROBLEM_CONFIG_SECTION_compiler_env_pat,
  [CNTSPROB_container_options] = META_PROBLEM_CONFIG_SECTION_container_options,
  [CNTSPROB_token_info] = 0,
  [CNTSPROB_score_tests] = META_PROBLEM_CONFIG_SECTION_score_tests,
  [CNTSPROB_standard_checker] = META_PROBLEM_CONFIG_SECTION_standard_checker,
  [CNTSPROB_spelling] = META_PROBLEM_CONFIG_SECTION_spelling,
  [CNTSPROB_statement_file] = META_PROBLEM_CONFIG_SECTION_statement_file,
  [CNTSPROB_alternatives_file] = 0,
  [CNTSPROB_plugin_file] = META_PROBLEM_CONFIG_SECTION_plugin_file,
  [CNTSPROB_xml_file] = META_PROBLEM_CONFIG_SECTION_xml_file,
  [CNTSPROB_stand_attr] = META_PROBLEM_CONFIG_SECTION_stand_attr,
  [CNTSPROB_source_header] = META_PROBLEM_CONFIG_SECTION_source_header,
  [CNTSPROB_source_footer] = META_PROBLEM_CONFIG_SECTION_source_footer,
  [CNTSPROB_interactor_time_limit] = META_PROBLEM_CONFIG_SECTION_interactor_time_limit,
  [CNTSPROB_interactor_real_time_limit] = META_PROBLEM_CONFIG_SECTION_interactor_real_time_limit,
  [CNTSPROB_custom_compile_cmd] = META_PROBLEM_CONFIG_SECTION_custom_compile_cmd,
  [CNTSPROB_custom_lang_name] = META_PROBLEM_CONFIG_SECTION_custom_lang_name,
  [CNTSPROB_extra_src_dir] = META_PROBLEM_CONFIG_SECTION_extra_src_dir,
  [CNTSPROB_standard_valuer] = META_PROBLEM_CONFIG_SECTION_standard_valuer,
  [CNTSPROB_md_file] = META_PROBLEM_CONFIG_SECTION_md_file,
  [CNTSPROB_test_pat] = META_PROBLEM_CONFIG_SECTION_test_pat,
  [CNTSPROB_corr_pat] = META_PROBLEM_CONFIG_SECTION_corr_pat,
  [CNTSPROB_info_pat] = META_PROBLEM_CONFIG_SECTION_info_pat,
  [CNTSPROB_tgz_pat] = META_PROBLEM_CONFIG_SECTION_tgz_pat,
  [CNTSPROB_tgzdir_pat] = META_PROBLEM_CONFIG_SECTION_tgzdir_pat,
  [CNTSPROB_ntests] = 0,
  [CNTSPROB_tscores] = 0,
  [CNTSPROB_x_score_tests] = 0,
  [CNTSPROB_test_sets] = META_PROBLEM_CONFIG_SECTION_test_sets,
  [CNTSPROB_ts_total] = 0,
  [CNTSPROB_ts_infos] = 0,
  [CNTSPROB_normalization] = META_PROBLEM_CONFIG_SECTION_normalization,
  [CNTSPROB_normalization_val] = 0,
  [CNTSPROB_src_normalization] = META_PROBLEM_CONFIG_SECTION_src_normalization,
  [CNTSPROB_deadline] = META_PROBLEM_CONFIG_SECTION_deadline,
  [CNTSPROB_start_date] = META_PROBLEM_CONFIG_SECTION_start_date,
  [CNTSPROB_date_penalty] = META_PROBLEM_CONFIG_SECTION_date_penalty,
  [CNTSPROB_dp_total] = 0,
  [CNTSPROB_dp_infos] = 0,
  [CNTSPROB_group_start_date] = META_PROBLEM_CONFIG_SECTION_group_start_date,
  [CNTSPROB_group_deadline] = META_PROBLEM_CONFIG_SECTION_group_deadline,
  [CNTSPROB_gsd] = 0,
  [CNTSPROB_gdl] = 0,
  [CNTSPROB_disable_language] = META_PROBLEM_CONFIG_SECTION_disable_language,
  [CNTSPROB_enable_language] = META_PROBLEM_CONFIG_SECTION_enable_language,
  [CNTSPROB_require] = META_PROBLEM_CONFIG_SECTION_require,
  [CNTSPROB_provide_ok] = META_PROBLEM_CONFIG_SECTION_provide_ok,
  [CNTSPROB_allow_ip] = META_PROBLEM_CONFIG_SECTION_allow_ip,
  [CNTSPROB_lang_compiler_env] = META_PROBLEM_CONFIG_SECTION_lang_compiler_env,
  [CNTSPROB_lang_compiler_container_options] = META_PROBLEM_CONFIG_SECTION_lang_compiler_container_options,
  [CNTSPROB_checker_env] = META_PROBLEM_CONFIG_SECTION_checker_env,
  [CNTSPROB_valuer_env] = META_PROBLEM_CONFIG_SECTION_valuer_env,
  [CNTSPROB_interactor_env] = META_PROBLEM_CONFIG_SECTION_interactor_env,
  [CNTSPROB_style_checker_env] = META_PROBLEM_CONFIG_SECTION_style_checker_env,
  [CNTSPROB_test_checker_env] = META_PROBLEM_CONFIG_SECTION_test_checker_env,
  [CNTSPROB_test_generator_env] = META_PROBLEM_CONFIG_SECTION_test_generator_env,
  [CNTSPROB_init_env] = META_PROBLEM_CONFIG_SECTION_init_env,
  [CNTSPROB_start_env] = META_PROBLEM_CONFIG_SECTION_start_env,
  [CNTSPROB_check_cmd] = META_PROBLEM_CONFIG_SECTION_check_cmd,
  [CNTSPROB_valuer_cmd] = META_PROBLEM_CONFIG_SECTION_valuer_cmd,
  [CNTSPROB_interactor_cmd] = META_PROBLEM_CONFIG_SECTION_interactor_cmd,
  [CNTSPROB_style_checker_cmd] = META_PROBLEM_CONFIG_SECTION_style_checker_cmd,
  [CNTSPROB_test_checker_cmd] = META_PROBLEM_CONFIG_SECTION_test_checker_cmd,
  [CNTSPROB_test_generator_cmd] = META_PROBLEM_CONFIG_SECTION_test_generator_cmd,
  [CNTSPROB_init_cmd] = META_PROBLEM_CONFIG_SECTION_init_cmd,
  [CNTSPROB_start_cmd] = META_PROBLEM_CONFIG_SECTION_start_cmd,
  [CNTSPROB_solution_src] = 0,
  [CNTSPROB_solution_cmd] = 0,
  [CNTSPROB_post_pull_cmd] = META_PROBLEM_CONFIG_SECTION_post_pull_cmd,
  [CNTSPROB_vcs_compile_cmd] = META_PROBLEM_CONFIG_SECTION_vcs_compile_cmd,
  [CNTSPROB_lang_time_adj] = META_PROBLEM_CONFIG_SECTION_lang_time_adj,
  [CNTSPROB_lang_time_adj_millis] = META_PROBLEM_CONFIG_SECTION_lang_time_adj_millis,
  [CNTSPROB_super_run_dir] = META_PROBLEM_CONFIG_SECTION_super_run_dir,
  [CNTSPROB_lang_max_vm_size] = META_PROBLEM_CONFIG_SECTION_lang_max_vm_size,
  [CNTSPROB_lang_max_stack_size] = META_PROBLEM_CONFIG_SECTION_lang_max_stack_size,
  [CNTSPROB_lang_max_rss_size] = META_PROBLEM_CONFIG_SECTION_lang_max_rss_size,
  [CNTSPROB_checker_extra_files] = META_PROBLEM_CONFIG_SECTION_checker_extra_files,
  [CNTSPROB_statement_env] = META_PROBLEM_CONFIG_SECTION_statement_env,
  [CNTSPROB_alternative] = 0,
  [CNTSPROB_personal_deadline] = META_PROBLEM_CONFIG_SECTION_personal_deadline,
  [CNTSPROB_pd_total] = 0,
  [CNTSPROB_pd_infos] = 0,
  [CNTSPROB_score_bonus] = META_PROBLEM_CONFIG_SECTION_score_bonus,
  [CNTSPROB_score_bonus_total] = 0,
  [CNTSPROB_score_bonus_val] = 0,
  [CNTSPROB_open_tests] = META_PROBLEM_CONFIG_SECTION_open_tests,
  [CNTSPROB_open_tests_count] = 0,
  [CNTSPROB_open_tests_val] = 0,
  [CNTSPROB_open_tests_group] = 0,
  [CNTSPROB_final_open_tests] = META_PROBLEM_CONFIG_SECTION_final_open_tests,
  [CNTSPROB_final_open_tests_count] = 0,
  [CNTSPROB_final_open_tests_val] = 0,
  [CNTSPROB_final_open_tests_group] = 0,
  [CNTSPROB_token_open_tests] = META_PROBLEM_CONFIG_SECTION_token_open_tests,
  [CNTSPROB_token_open_tests_count] = 0,
  [CNTSPROB_token_open_tests_val] = 0,
  [CNTSPROB_token_open_tests_group] = 0,
  [CNTSPROB_max_vm_size] = META_PROBLEM_CONFIG_SECTION_max_vm_size,
  [CNTSPROB_max_data_size] = META_PROBLEM_CONFIG_SECTION_max_data_size,
  [CNTSPROB_max_stack_size] = META_PROBLEM_CONFIG_SECTION_max_stack_size,
  [CNTSPROB_max_rss_size] = META_PROBLEM_CONFIG_SECTION_max_rss_size,
  [CNTSPROB_max_core_size] = META_PROBLEM_CONFIG_SECTION_max_core_size,
  [CNTSPROB_max_file_size] = META_PROBLEM_CONFIG_SECTION_max_file_size,
  [CNTSPROB_checker_max_vm_size] = META_PROBLEM_CONFIG_SECTION_checker_max_vm_size,
  [CNTSPROB_checker_max_stack_size] = META_PROBLEM_CONFIG_SECTION_checker_max_stack_size,
  [CNTSPROB_checker_max_rss_size] = META_PROBLEM_CONFIG_SECTION_checker_max_rss_size,
  [CNTSPROB_max_open_file_count] = META_PROBLEM_CONFIG_SECTION_max_open_file_count,
  [CNTSPROB_max_process_count] = META_PROBLEM_CONFIG_SECTION_max_process_count,
  [CNTSPROB_extid] = META_PROBLEM_CONFIG_SECTION_extid,
  [CNTSPROB_unhandled_vars] = 0,
  [CNTSPROB_score_view] = 0,
  [CNTSPROB_score_view_score] = 0,
  [CNTSPROB_score_view_text] = 0,
  [CNTSPROB_xml_file_path] = 0,
  [CNTSPROB_var_xml_file_paths] = 0,
  [CNTSPROB_md_files] = 0,
  [CNTSPROB_md_size] = 0,
};

int
problem_assign_cfg(
        struct section_problem_data *prob,
        cJSON *protected_fields,
        cJSON *allowed_fields,
        const struct problem_config_section *pp,
        FILE *log_f,
        int *p_changed)
{
    unsigned char ignored_fields[CNTSPROB_LAST_FIELD];
    unsigned char af[CNTSPROB_LAST_FIELD];
    memcpy(ignored_fields, problem_typically_ignored_fields, sizeof(ignored_fields));
    if (prob->abstract > 0) {
        ignored_fields[CNTSPROB_short_name] = 1;
    }
    ignored_fields[CNTSPROB_id] = 1;
    ignored_fields[CNTSPROB_abstract] = 1;
    if (protected_fields && protected_fields->type == cJSON_Array) {
        for (cJSON *c = protected_fields->child; c; c = c->next) {
            if (c->type == cJSON_String) {
                int id = cntsprob_lookup_field(c->valuestring);
                if (id >= 1 && id < CNTSPROB_LAST_FIELD) {
                    ignored_fields[id] = 1;
                }
            }
        }
    }
    memset(af, 0, sizeof(af));
    if (allowed_fields && allowed_fields->type == cJSON_Array) {
        for (cJSON *c = allowed_fields->child; c; c = c->next) {
            if (c->type == cJSON_String) {
                int id = cntsprob_lookup_field(c->valuestring);
                if (id >= 1 && id < CNTSPROB_LAST_FIELD) {
                    af[id] = 1;
                }
            }
        }
        for (int field_id = CNTSPROB_id; field_id < CNTSPROB_LAST_FIELD; ++field_id) {
            if (af[field_id]) {
                ignored_fields[field_id] = 1;
            }
        }
    }

    for (int field_id = CNTSPROB_id; field_id < CNTSPROB_LAST_FIELD; ++field_id) {
        if (ignored_fields[field_id]) continue;
        int cfg_field_id = cnts_to_cfg_field_map[field_id];
        if (!cfg_field_id) continue;
        const unsigned char *field_name = cntsprob_get_name(field_id);

        if (field_id == CNTSPROB_type) {
            if (!pp->type || !pp->type[0]) {
                // standard problem
                if (prob->type != PROB_TYPE_STANDARD) *p_changed = 1;
                prob->type = PROB_TYPE_STANDARD;
            } else {
                int val = problem_parse_type(pp->type);
                if (val < 0) {
                    flog(log_f, "type", "invalid value");
                    continue;
                }
                if (prob->type != val) {
                    prob->type = val;
                    *p_changed = 1;
                }
            }
            continue;
        }
        if (field_id == CNTSPROB_short_name) {
            unsigned char short_name[sizeof(prob->short_name)] = {};
            if (pp->short_name) {
                snprintf(short_name, sizeof(short_name), "%s", pp->short_name);
            }
            if (strcmp(prob->short_name, short_name) != 0) {
                memcpy(prob->short_name, short_name, sizeof(short_name));
                *p_changed = 1;
            }
            continue;
        }

        int t = cntsprob_get_type(field_id);
        int t2 = meta_problem_config_section_get_type(cfg_field_id);
        if (t != t2) abort();
        void *ptr = cntsprob_get_ptr_nc(prob, field_id);
        const void *cfg_ptr = meta_problem_config_section_get_ptr(pp, cfg_field_id);
        switch (t) {
        case 'i': {
            int *p = (int*) ptr;
            int value = *(const int*) cfg_ptr;
            if (field_id == CNTSPROB_priority_adjustment) {
                if (value < -16 || value > 15) {
                    flog(log_f, field_name, "invalid value");
                    continue;
                }
                if (*p != value) {
                    *p = value;
                    *p_changed = 1;
                }
                continue;
            }
            if (value < 0) value = -1;
            /*
              tester_id variant_num full_score full_user_score min_score_1
              min_score_2 examinator_num real_time_limit time_limit time_limit_millis
              test_score run_penalty acm_run_penalty disqualified_penalty compile_error_penalty
              tests_to_accept min_tests_to_accept checker_real_time_limit checker_time_limit_ms score_multiplier
              prev_runs_to_show max_user_run_count interactor_time_limit interactor_real_time_limit max_open_file_count
              max_process_count
             */
            if (*p != value) {
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 'S': {
            abort();
        }
        case 'f': {
            ejbyteflag_t *p = (ejbyteflag_t*) ptr;
            ejbyteflag_t value = *(const ejbyteflag_t*) cfg_ptr;
            if (value < 0) value = -1;
            if (value > 0) value = 1;
            /*
              manual_checking check_presentation scoring_checker enable_checker_token interactive_valuer
              disable_pe disable_wtl wtl_is_cf use_stdin use_stdout
              combined_stdin combined_stdout binary_input binary ignore_exit_code
              ignore_term_signal olympiad_mode score_latest score_latest_or_unmarked score_latest_marked
              score_tokenized use_ac_not_ok ignore_prev_ac team_enable_rep_view team_enable_ce_view
              team_show_judge_report show_checker_comment ignore_compile_errors variable_full_score ignore_penalty
              use_corr use_info use_tgz accept_partial disable_user_submit
              disable_tab unrestricted_statement statement_ignore_ip restricted_statement enable_submit_after_reject
              hide_file_names hide_real_time_limit enable_tokens tokens_for_user_ac disable_submit_after_ok
              disable_auto_testing disable_testing enable_compilation skip_testing hidden
              stand_hide_time advance_to_next disable_ctrl_chars enable_text_form stand_ignore_score
              stand_last_column disable_security enable_suid_run enable_container enable_dynamic_priority
              valuer_sets_marked ignore_unmarked disable_stderr enable_process_group enable_kill_all
              hide_variant enable_testlib_mode autoassign_variants require_any enable_extended_info
              stop_on_first_fail enable_control_socket copy_exe_to_tgzdir enable_multi_header use_lang_multi_header
              notify_on_submit enable_user_input enable_vcs enable_iframe_statement enable_src_for_testing
              disable_vm_size_limit enable_group_merge ignore_sigpipe
             */
            if (*p != value) {
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 's': {
            unsigned char **p = (unsigned char **) ptr;
            const unsigned char *valuestring = *(const unsigned char **) cfg_ptr;
            if (field_id == CNTSPROB_normalization) {
                if (test_normalization_parse(valuestring) < 0) {
                    flog(log_f, field_name, "invalid value");
                    continue;
                }
            }
            if (field_id == CNTSPROB_src_normalization) {
                if (test_normalization_parse(valuestring) < 0) {
                    flog(log_f, field_name, "invalid value");
                    continue;
                }
            }
            /*
              long_name stand_name stand_column group_name internal_name
              plugin_entry_name uuid problem_dir test_dir test_sfx
              corr_dir corr_sfx info_dir info_sfx tgz_dir
              tgz_sfx tgzdir_sfx input_file output_file test_score_list
              tokens umask ok_status header_pat footer_pat
              compiler_env_pat container_options score_tests standard_checker spelling
              statement_file alternatives_file plugin_file xml_file stand_attr
              source_header source_footer custom_compile_cmd custom_lang_name extra_src_dir
              standard_valuer test_pat corr_pat info_pat tgz_pat
              tgzdir_pat normalization check_cmd valuer_cmd interactor_cmd
              style_checker_cmd test_checker_cmd test_generator_cmd init_cmd start_cmd
              solution_src solution_cmd post_pull_cmd vcs_compile_cmd super_run_dir
              score_bonus open_tests final_open_tests token_open_tests extid src_normalization
             */
            if (strcmpex(*p, valuestring) != 0) {
                if (*p) {
                    xfree(*p); *p = NULL;
                }
                *p = xstrdup(valuestring);
                *p_changed = 1;
            }
            break;
        }
        case 'x': {
            char ***p = (char***) ptr;
            char **value = *(char ***) cfg_ptr;
            /*
              test_sets date_penalty group_start_date group_deadline disable_language
              enable_language require provide_ok allow_ip lang_time_adj
              lang_time_adj_millis lang_max_vm_size lang_max_stack_size lang_max_rss_size checker_extra_files
              alternative personal_deadline score_view
             */
            if (sarray_cmp(*p, value) != 0) {
                sarray_free(*p);
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 't': {
            time_t *p = (time_t*) ptr;
            time_t value = *(const time_t *) cfg_ptr;
            /*
              deadline start_date
             */
            if (*p != value) {
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 'X': {
            ejenvlist_t *p = (ejenvlist_t*) ptr;
            ejenvlist_t value = *(ejenvlist_t *) cfg_ptr;
            /*
              lang_compiler_env lang_compiler_container_options checker_env valuer_env interactor_env
              style_checker_env test_checker_env test_generator_env init_env start_env
              statement_env
             */
            if (sarray_cmp(*p, value) != 0) {
                sarray_free(*p);
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        case 'E': {
            ej_size64_t *p = (ej_size64_t*) ptr;
            ej_size64_t value = *(const ej_size64_t *) cfg_ptr;
            /*
              max_vm_size max_data_size max_stack_size max_rss_size max_core_size
              max_file_size checker_max_vm_size checker_max_stack_size checker_max_rss_size
             */
            if (*p != value) {
                *p = value;
                *p_changed = 1;
            }
            break;
        }
        }
    }
    return 0;
}
