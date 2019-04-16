/* -*- mode: c -*- */

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

#include "ejudge/config.h"

#include "ejudge/runlog.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/bson_utils.h"
#include "ejudge/xalloc.h"

#include <stdio.h>

#if HAVE_LIBMONGOC - 0 > 0

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#else
#include <mongoc.h>
#endif

#include "testing_report_tags.c"

static int
parse_file(bson_iter_t *bi, struct testing_report_file_content *fc)
{
    while (bson_iter_next(bi)) {
        const unsigned char *key = bson_iter_key(bi);
        int tag = match(key);
        switch(tag) {
        case Tag_too_big:
            if (ej_bson_parse_boolean_new(bi, key, &fc->is_too_big) < 0)
                return -1;
            break;
        case Tag_original_size:
            {
                long long original_size = -1;
                if (ej_bson_parse_int64_new(bi, key, &original_size) < 0 || original_size < 0)
                    return -1;
                fc->orig_size = original_size;
            }
            break;
        case Tag_base64:
            if (ej_bson_parse_boolean_new(bi, key, &fc->is_base64) < 0)
                return -1;
            break;
        case Tag_bzip2:
            if (ej_bson_parse_boolean_new(bi, key, &fc->is_bzip2) < 0)
                return -1;
            break;
        case Tag_data:
            {
                if (bson_iter_type(bi) != BSON_TYPE_BINARY)
                    return -1;
                bson_subtype_t bt = 0;
                uint32_t bz = 0;
                const uint8_t *bd = NULL;
                bson_iter_binary(bi, &bt, &bz, &bd);
                if (bt != BSON_SUBTYPE_USER)
                    return -1;
                if (fc->data) free(fc->data);
                if (!(fc->data = malloc(bz + 1)))
                    return -1;
                memcpy(fc->data, bd, bz);
                fc->data[bz] = 0;
                fc->size = bz;
            }
            break;
        }
    }
    return 0;
}

static int
parse_test(int index, bson_iter_t *bi, testing_report_xml_t r)
{
    int retval = -1;
    struct testing_report_test *p = 0;
    struct testing_report_file_content *trfc = NULL;
    bson_iter_t iter2;

    p = testing_report_test_alloc(-1, -1);
    p->num = -1;
    p->status = -1;
    p->time = -1;
    p->real_time = -1;
    p->exit_code = -1;
    p->term_signal = -1;
    p->nominal_score = -1;
    p->score = -1;
    p->user_status = -1;
    p->user_score = -1;
    p->user_nominal_score = -1;

    while (bson_iter_next(bi)) {
        const unsigned char *key = bson_iter_key(bi);
        int tag = match(key);
        switch(tag) {
        case Tag_num:
            if (ej_bson_parse_int_new(bi, key, &p->num, 1, 1, 0, 0) < 0)
                goto cleanup;
            if (p->num > r->run_tests)
                goto cleanup;
            break;
        case Tag_status:
            if (ej_bson_parse_int_new(bi, key, &p->status, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_user_status:
            if (ej_bson_parse_int_new(bi, key, &p->user_status, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_time:
            if (ej_bson_parse_int_new(bi, key, &p->time, 0, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_real_time:
            if (ej_bson_parse_int_new(bi, key, &p->real_time, 0, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_max_memory_used:
            {
                long long v;
                if (ej_bson_parse_int64_new(bi, key, &v) < 0)
                    goto cleanup;
                p->max_memory_used = v;
            }
            break;
        case Tag_exit_code:
            if (ej_bson_parse_int_new(bi, key, &p->exit_code, 0, 0, 0, 0) < 0)
                goto cleanup;
            if (p->exit_code < 0) p->exit_code = 255;
            if (p->exit_code > 255) p->exit_code = 255;
            break;
        case Tag_term_signal:
            if (ej_bson_parse_int_new(bi, key, &p->term_signal, 1, 1, 1, 255) < 0)
                goto cleanup;
            break;
        case Tag_nominal_score:
            if (ej_bson_parse_int_new(bi, key, &p->nominal_score, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_score:
            if (ej_bson_parse_int_new(bi, key, &p->score, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_user_score:
            if (ej_bson_parse_int_new(bi, key, &p->user_score, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_user_nominal_score:
            if (ej_bson_parse_int_new(bi, key, &p->user_nominal_score, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_visibility:
            if (ej_bson_parse_int_new(bi, key, &p->visibility, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_comment:
            if (ej_bson_parse_string_new(bi, key, &p->comment) < 0)
                goto cleanup;
            break;
        case Tag_team_comment:
            if (ej_bson_parse_string_new(bi, key, &p->team_comment) < 0)
                goto cleanup;
            break;
        case Tag_checker_comment:
            if (ej_bson_parse_string_new(bi, key, &p->checker_comment) < 0)
                goto cleanup;
            break;
        case Tag_exit_comment:
            if (ej_bson_parse_string_new(bi, key, &p->exit_comment) < 0)
                goto cleanup;
            break;
        case Tag_checker_token:
            if (ej_bson_parse_string_new(bi, key, &p->checker_token) < 0)
                goto cleanup;
            break;
        case Tag_output_available:
            if (ej_bson_parse_boolean_new(bi, key, &p->output_available) < 0)
                goto cleanup;
            break;
        case Tag_stderr_available:
            if (ej_bson_parse_boolean_new(bi, key, &p->stderr_available) < 0)
                goto cleanup;
            break;
        case Tag_checker_output_available:
            if (ej_bson_parse_boolean_new(bi, key, &p->checker_output_available) < 0)
                goto cleanup;
            break;
        case Tag_has_user:
            if (ej_bson_parse_boolean_new(bi, key, &p->has_user) < 0)
                goto cleanup;
            break;
        case Tag_args_too_long:
            if (ej_bson_parse_boolean_new(bi, key, &p->args_too_long) < 0)
                goto cleanup;
            break;
        case Tag_input_digest:
            if (ej_bson_parse_sha1_new(bi, key, p->input_digest) < 0)
                goto cleanup;
            p->has_input_digest = 1;
            break;
        case Tag_correct_digest:
            if (ej_bson_parse_sha1_new(bi, key, p->correct_digest) < 0)
                goto cleanup;
            p->has_correct_digest = 1;
            break;
        case Tag_info_digest:
            if (ej_bson_parse_sha1_new(bi, key, p->info_digest) < 0)
                goto cleanup;
            p->has_info_digest = 1;
            break;
        case Tag_args:
            if (ej_bson_parse_string_new(bi, key, &p->args) < 0)
                goto cleanup;
            break;
        case Tag_program_stats_str:
            if (ej_bson_parse_string_new(bi, key, &p->program_stats_str) < 0)
                goto cleanup;
            break;
        case Tag_interactor_stats_str:
            if (ej_bson_parse_string_new(bi, key, &p->interactor_stats_str) < 0)
                goto cleanup;
            break;
        case Tag_checker_stats_str:
            if (ej_bson_parse_string_new(bi, key, &p->checker_stats_str) < 0)
                goto cleanup;
            break;
        case Tag_input:
            trfc = &p->input;
            goto common_file_content;
        case Tag_output:
            trfc = &p->output;
            goto common_file_content;
        case Tag_correct:
            trfc = &p->correct;
            goto common_file_content;
        case Tag_stderr:
            trfc = &p->error;
            goto common_file_content;
        case Tag_checker:
            trfc = &p->checker;
            goto common_file_content;
        common_file_content:
            if (bson_iter_type(bi) != BSON_TYPE_DOCUMENT)
                goto cleanup;
            if (!bson_iter_recurse(bi, &iter2))
                goto cleanup;
            if (parse_file(&iter2, trfc) < 0)
                goto cleanup;
            break;
        }
    }

    if (p->num <= 0 || p->num >= r->run_tests || r->tests[p->num - 1])
        goto cleanup;
    r->tests[p->num - 1] = p;
    p = NULL;

    retval = 0;

cleanup:
    testing_report_test_free(p);
    return retval;
}

static int
parse_ttcell(int index, bson_iter_t *bi, testing_report_xml_t r)
{
    int retval = -1;
    int row = -1, column = -1, status = RUN_CHECK_FAILED, time = -1, real_time = -1;
    struct testing_report_cell *ttc = NULL;

    while (bson_iter_next(bi)) {
        const unsigned char *key = bson_iter_key(bi);
        int tag = match(key);
        switch(tag) {
        case Tag_row:
            if (ej_bson_parse_int_new(bi, key, &row, 0, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_column:
            if (ej_bson_parse_int_new(bi, key, &column, 0, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_status:
            if (ej_bson_parse_int_new(bi, key, &status, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_time:
            if (ej_bson_parse_int_new(bi, key, &time, 0, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_real_time:
            if (ej_bson_parse_int_new(bi, key, &real_time, 0, 0, 0, 0) < 0)
                goto cleanup;
            break;
        }
    }

    if (row < 0 || row >= r->tt_row_count) goto cleanup;
    if (column < 0 || column >= r->tt_column_count) goto cleanup;

    ttc = r->tt_cells[row][column];
    ttc->row = row;
    ttc->column = column;
    ttc->status = status;
    ttc->time = time;
    ttc->real_time = real_time;

    retval = 0;

cleanup:
    return retval;
}

static int
parse_ttrow(int index, bson_iter_t *bi, testing_report_xml_t r)
{
    int retval = -1;
    unsigned char *name = NULL;
    int row = -1, must_fail = 0, status = RUN_CHECK_FAILED, nominal_score = -1, score = -1;

    while (bson_iter_next(bi)) {
        const unsigned char *key = bson_iter_key(bi);
        int tag = match(key);
        switch(tag) {
        case Tag_row:
            if (ej_bson_parse_int_new(bi, key, &row, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_name:
            if (ej_bson_parse_string_new(bi, key, &name) < 0)
                goto cleanup;
            break;
        case Tag_must_fail:
            if (ej_bson_parse_boolean_new(bi, key, &must_fail) < 0)
                goto cleanup;
            break;
        case Tag_status:
            if (ej_bson_parse_int_new(bi, key, &status, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_nominal_score:
            if (ej_bson_parse_int_new(bi, key, &nominal_score, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        case Tag_score:
            if (ej_bson_parse_int_new(bi, key, &score, 1, 0, 0, 0) < 0)
                goto cleanup;
            break;
        }
    }
    if (row < 0 || row >= r->tt_row_count)
        goto cleanup;
    if (!name)
        goto cleanup;

    r->tt_rows[row]->row = row;
    r->tt_rows[row]->name = name;
    r->tt_rows[row]->status = status;
    r->tt_rows[row]->must_fail = must_fail;
    r->tt_rows[row]->nominal_score = nominal_score;
    r->tt_rows[row]->score = score;
    name = NULL;
    retval = 0;

cleanup:
    xfree(name);
    return retval;
}

static int
parse_array(bson_iter_t *bi, testing_report_xml_t r, int (*func)(int, bson_iter_t *, testing_report_xml_t))
{
    int index = -1;
    while (bson_iter_next(bi)) {
        const char *key = bson_iter_key(bi);
        ++index;
        errno = 0;
        char *eptr = NULL;
        long val = strtol(key, &eptr, 10);
        if (errno || *eptr || eptr == key || val != index)
            return -1;
        if (bson_iter_type(bi) != BSON_TYPE_DOCUMENT)
            return -1;
        bson_iter_t iter3;
        if (!bson_iter_recurse(bi, &iter3))
            return -1;
        if (func(index, &iter3, r) < 0)
            return -1;
    }
    return 0;
}

static int
parse_testing_report_bson(bson_iter_t *bi, testing_report_xml_t r)
{
    bson_iter_t tests_iter;
    bson_iter_t ttrows_iter;
    bson_iter_t ttcells_iter;
    int has_tests = 0;
    int has_ttrows = 0;
    int has_ttcells = 0;

    r->run_id = -1;
    r->judge_id = -1;
    r->status = -1;
    r->scoring_system = -1;
    r->archive_available = 0;
    r->run_tests = -1;
    r->variant = 0;
    r->accepting_mode = 0;
    r->failed_test = -1;
    r->tests_passed = -1;
    r->score = -1;
    r->max_score = -1;
    r->time_limit_ms = -1;
    r->real_time_limit_ms = -1;
    r->marked_flag = -1;
    r->user_status = -1;
    r->user_tests_passed = -1;
    r->user_score = -1;
    r->user_max_score = -1;
    r->user_run_tests = -1;

    while (bson_iter_next(bi)) {
        const unsigned char *key = bson_iter_key(bi);
        int tag = match(key);
        switch(tag) {
        case Tag_contest_id:
            if (ej_bson_parse_int_new(bi, key, &r->contest_id, 1, 1, 0, 0) < 0)
                return -1;
            break;
        case Tag_run_id:
            if (ej_bson_parse_int_new(bi, key, &r->run_id, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_judge_id:
            if (ej_bson_parse_int_new(bi, key, &r->judge_id, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_status:
            if (ej_bson_parse_int_new(bi, key, &r->status, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_user_status:
            if (ej_bson_parse_int_new(bi, key, &r->user_status, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_scoring:
            if (ej_bson_parse_int_new(bi, key, &r->scoring_system, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_archive_available:
            if (ej_bson_parse_boolean_new(bi, key, &r->archive_available) < 0)
                return -1;
            break;
        case Tag_correct_available:
            if (ej_bson_parse_boolean_new(bi, key, &r->correct_available) < 0)
                return -1;
            break;
        case Tag_info_available:
            if (ej_bson_parse_boolean_new(bi, key, &r->info_available) < 0)
                return -1;
            break;
        case Tag_real_time_available:
            if (ej_bson_parse_boolean_new(bi, key, &r->real_time_available) < 0)
                return -1;
            break;
        case Tag_max_memory_used_available:
            if (ej_bson_parse_boolean_new(bi, key, &r->max_memory_used_available) < 0)
                return -1;
            break;
        case Tag_compile_error:
            if (ej_bson_parse_boolean_new(bi, key, &r->compile_error) < 0)
                return -1;
            break;
        case Tag_run_tests:
            if (ej_bson_parse_int_new(bi, key, &r->run_tests, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_user_run_tests:
            if (ej_bson_parse_int_new(bi, key, &r->user_run_tests, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_variant:
            if (ej_bson_parse_int_new(bi, key, &r->variant, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_accepting_mode:
            if (ej_bson_parse_boolean_new(bi, key, &r->accepting_mode) < 0)
                return -1;
            break;
        case Tag_failed_test:
            if (ej_bson_parse_int_new(bi, key, &r->failed_test, 1, 1, 0, 0) < 0)
                return -1;
            break;
        case Tag_tests_passed:
            if (ej_bson_parse_int_new(bi, key, &r->tests_passed, 1, -1, 0, 0) < 0)
                return -1;
            if (r->tests_passed < 0) r->tests_passed = 0;
            break;
        case Tag_user_tests_passed:
            if (ej_bson_parse_int_new(bi, key, &r->user_tests_passed, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_score:
            if (ej_bson_parse_int_new(bi, key, &r->score, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_user_score:
            if (ej_bson_parse_int_new(bi, key, &r->user_score, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_max_score:
            if (ej_bson_parse_int_new(bi, key, &r->max_score, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_user_max_score:
            if (ej_bson_parse_int_new(bi, key, &r->user_max_score, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_time_limit_ms:
            if (ej_bson_parse_int_new(bi, key, &r->time_limit_ms, 0, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_real_time_limit_ms:
            if (ej_bson_parse_int_new(bi, key, &r->real_time_limit_ms, 0, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_marked_flag:
            if (ej_bson_parse_boolean_new(bi, key, &r->marked_flag) < 0)
                return -1;
            break;
        case Tag_tests_mode:
            if (ej_bson_parse_boolean_new(bi, key, &r->tests_mode) < 0)
                return -1;
            break;
        case Tag_tt_row_count:
            if (ej_bson_parse_int_new(bi, key, &r->tt_row_count, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_tt_column_count:
            if (ej_bson_parse_int_new(bi, key, &r->tt_column_count, 1, 0, 0, 0) < 0)
                return -1;
            break;
        case Tag_comment:
            if (ej_bson_parse_string_new(bi, key, &r->comment) < 0)
                return -1;
            break;
        case Tag_valuer_comment:
            if (ej_bson_parse_string_new(bi, key, &r->valuer_comment) < 0)
                return -1;
            break;
        case Tag_valuer_judge_comment:
            if (ej_bson_parse_string_new(bi, key, &r->valuer_judge_comment) < 0)
                return -1;
            break;
        case Tag_valuer_errors:
            if (ej_bson_parse_string_new(bi, key, &r->valuer_errors) < 0)
                return -1;
            break;
        case Tag_host:
            if (ej_bson_parse_string_new(bi, key, &r->host) < 0)
                return -1;
            break;
        case Tag_cpu_model:
            if (ej_bson_parse_string_new(bi, key, &r->cpu_model) < 0)
                return -1;
            break;
        case Tag_cpu_mhz:
            if (ej_bson_parse_string_new(bi, key, &r->cpu_mhz) < 0)
                return -1;
            break;
        case Tag_errors:
            if (ej_bson_parse_string_new(bi, key, &r->errors) < 0)
                return -1;
            break;
        case Tag_compiler_output:
            if (ej_bson_parse_string_new(bi, key, &r->compiler_output) < 0)
                return -1;
            break;
        case Tag_uuid:
            if (ej_bson_parse_uuid_new(bi, key, &r->uuid) < 0)
                return -1;
            break;
        case Tag_tests:
            if (bson_iter_type(bi) == BSON_TYPE_ARRAY && bson_iter_recurse(bi, &tests_iter)) {
                has_tests = 1;
            }
            break;
        case Tag_ttrows:
            if (bson_iter_type(bi) == BSON_TYPE_ARRAY && bson_iter_recurse(bi, &ttrows_iter)) {
                has_ttrows = 1;
            }
            break;
        case Tag_ttcells:
            if (bson_iter_type(bi) == BSON_TYPE_ARRAY && bson_iter_recurse(bi, &ttcells_iter)) {
                has_ttcells = 1;
            }
            break;
        }
    }

    /*
  if (r->tests_mode > 0) {
    if (!r->tt_row_count || !r->tt_column_count) {
    }
  } else {
    if (r->tt_row_count > 0 || r->tt_column_count > 0) {
      return -1;
    }
  }
    */

    if (r->run_tests > 0) {
        XCALLOC(r->tests, r->run_tests);
    }

    if (r->tests_mode > 0) {
        if (r->tt_row_count > 0 && r->tt_column_count > 0) {
            XCALLOC(r->tt_rows, r->tt_row_count);
            XCALLOC(r->tt_cells, r->tt_row_count);
            for (int i = 0; i < r->tt_row_count; ++i) {
                struct testing_report_row *ttr = 0;
                XCALLOC(ttr, 1);
                r->tt_rows[i] = ttr;
                ttr->row = i;
                ttr->status = RUN_CHECK_FAILED;
                ttr->nominal_score = -1;
                ttr->score = -1;
                XCALLOC(r->tt_cells[i], r->tt_column_count);
                for (int j = 0; j < r->tt_column_count; ++j) {
                    struct testing_report_cell *ttc = 0;
                    XCALLOC(ttc, 1);
                    r->tt_cells[i][j] = ttc;
                    ttc->row = i;
                    ttc->column = j;
                    ttc->status = RUN_CHECK_FAILED;
                    ttc->time = -1;
                    ttc->real_time = -1;
                }
            }
        }
    }

    if (r->tests_mode) {
        if (has_tests) {
            if (parse_array(&tests_iter, r, parse_test) < 0)
                return -1;
        }
    } else {
        if (has_ttrows) {
            if (parse_array(&ttrows_iter, r, parse_ttrow) < 0)
                return -1;
        }
        if (has_ttcells) {
            if (parse_array(&ttcells_iter, r, parse_ttcell) < 0)
                return -1;
        }
    }

    return 0;
}

int testing_report_bson_available(void)
{
    return 1;
}
testing_report_xml_t
testing_report_parse_data(
        const unsigned char *data,
        unsigned int size)
{
    bson_t sb;
    bson_iter_t iter;
    testing_report_xml_t r = NULL;

    if (bson_init_static(&sb, data, size) && bson_iter_init(&iter, &sb)) {
        XCALLOC(r, 1);
        if (parse_testing_report_bson(&iter, r) >= 0) {
            return r;
        }
        testing_report_free(r);
    }
    return NULL;
}

static bson_t *
do_unparse(
        int max_file_length,
        int max_line_length,
        testing_report_xml_t r)
    __attribute__((unused));
static bson_t *
do_unparse(
        int max_file_length,
        int max_line_length,
        testing_report_xml_t r)
{
    return 0;
}


#else
// stubs when bson format is not available
int testing_report_bson_available(void)
{
    return 0;
}
testing_report_xml_t
testing_report_parse_data(
        const unsigned char *data,
        unsigned int size)
{
    return NULL;
}
#endif
