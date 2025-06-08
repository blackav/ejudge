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
#include "ejudge/cJSON.h"
#include "ejudge/xml_utils.h"

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
            prob->type = val;
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
                *p = value;
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
            *p = value;
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
            snprintf(p, sz, "%s", ji->valuestring);
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
              disable_vm_size_limit enable_group_merge
             */
            *p = value;
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
              score_bonus open_tests final_open_tests token_open_tests extid
             */
            if (*p) {
                xfree(*p); *p = NULL;
            }
            *p = xstrdup(ji->valuestring);
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
            *p = value;
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
            *p = value;
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
            *p = value;
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
            *p = value;
            break;
        }
        }
    }
    return 0;
}
