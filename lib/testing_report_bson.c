/* -*- mode: c -*- */

/* Copyright (C) 2019-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/errlog.h"
#include "ejudge/osdeps.h"
#include "ejudge/ej_uuid.h"

#include <stdio.h>
#include <sys/mman.h>

#if HAVE_LIBMONGOC - 0 > 0

#if HAVE_LIBMONGOC - 0 > 1
#include <mongoc/mongoc.h>
#else
#include <mongoc.h>
#endif

#include "gen/testing_report_tags.c"

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
                if (ej_bson_parse_int64_new(bi, key, &original_size) < 0)
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
        case Tag_size: {
            long long sz = -1;
            if (ej_bson_parse_int64_new(bi, key, &sz) < 0 || sz < 0)
                return -1;
            fc->size = sz;
            break;
        }
        case Tag_data:
            if (bson_iter_type(bi) == BSON_TYPE_UTF8) {
                unsigned char *value = NULL;
                if (ej_bson_parse_string_new(bi, key, &value) < 0)
                    return -1;
                free(fc->data);
                fc->data = value;
            } else if (bson_iter_type(bi) == BSON_TYPE_BINARY) {
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
            } else {
                return -1;
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
        case Tag_max_rss:
            {
                long long v;
                if (ej_bson_parse_int64_new(bi, key, &v) < 0)
                    goto cleanup;
                p->max_rss = v;
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
        case Tag_test_checker:
            trfc = &p->test_checker;
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

    if (p->num <= 0 || p->num > r->run_tests || r->tests[p->num - 1])
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
        case Tag_submit_id: {
            long long v;
            if (ej_bson_parse_int64_new(bi, key, &v) < 0)
                return -1;
            r->submit_id = v;
            break;
        }
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
        case Tag_max_rss_available:
            if (ej_bson_parse_boolean_new(bi, key, &r->max_rss_available) < 0)
                return -1;
            break;
        case Tag_separate_user_score:
            if (ej_bson_parse_boolean_new(bi, key, &r->separate_user_score) < 0)
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
        case Tag_judge_uuid:
            if (ej_bson_parse_uuid_new(bi, key, &r->judge_uuid) < 0)
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
        case Tag_verdict_bits:
            if (ej_bson_parse_int_new(bi, key, &r->verdict_bits, 1, 0, 0, 0) < 0)
                return -1;
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

    if (r->tests_mode > 0) {
        if (has_ttrows) {
            if (parse_array(&ttrows_iter, r, parse_ttrow) < 0)
                return -1;
        }
        if (has_ttcells) {
            if (parse_array(&ttcells_iter, r, parse_ttcell) < 0)
                return -1;
        }
    } else {
        if (has_tests) {
            if (parse_array(&tests_iter, r, parse_test) < 0)
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
testing_report_parse_bson_data(
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

testing_report_xml_t
testing_report_parse_bson_file(
        const unsigned char *path)
{
    int fd = -1;
    struct stat stb;
    size_t memz = 0;
    unsigned char *memp = NULL;
    testing_report_xml_t r = NULL;

    if ((fd = open(path, O_RDONLY | O_NOCTTY | O_NONBLOCK, 0)) < 0) {
        err("testing_report_parse_bson_file: open %s failed: %s", path, os_ErrorMsg());
        goto fail;
    }
    if (fstat(fd, &stb) < 0) {
        err("testing_report_parse_bson_file: fstat %s failed: %s", path, os_ErrorMsg());
        goto fail;
    }
    if (!S_ISREG(stb.st_mode)) {
        err("testing_report_parse_bson_file: %s is not regular", path);
        goto fail;
    }
    long long fz = stb.st_size;
    if (fz <= 0 || (int) fz != fz) {
        err("testing_report_parse_bson_file: %s has invalid size %lld", path, fz);
        goto fail;
    }
    memz = fz;
    if ((memp = mmap(NULL, memz, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        err("testing_report_parse_bson_file: mmap %s failed: %s", path, os_ErrorMsg());
        goto fail;
    }
    close(fd); fd = -1;
    if (!(r = testing_report_parse_bson_data(memp, memz))) {
        goto fail;
    }
    munmap(memp, memz);
    return r;

fail:
    if (memp) munmap(memp, memz);
    if (fd < 0) close(fd);
    return NULL;
}

static void
unparse_digest_attr(
        bson_t *b,
        const char *tag,
        const void *raw)
{
    const unsigned int *v = raw;
    if (v[0] || v[1] || v[2] || v[3] || v[4]) {
        bson_append_binary(b, tag, -1, BSON_SUBTYPE_USER, raw, 20);
    }
}

static void
unparse_file_content(
        bson_t *b,
        const char *tag,
        struct testing_report_file_content *fc)
{
    if (fc->size >= 0) {
        bson_t b_fc;
        bson_append_document_begin(b, tag, -1, &b_fc);
        if (fc->is_too_big) {
            bson_append_bool(&b_fc, tag_table[Tag_too_big], -1, 1);
        }
        bson_append_int64(&b_fc, tag_table[Tag_original_size], -1, fc->orig_size);
        bson_append_int64(&b_fc, tag_table[Tag_size], -1, fc->size);
        if (fc->is_base64 > 0) {
          bson_append_bool(&b_fc, tag_table[Tag_base64], -1, 1);
        }
        if (fc->is_bzip2 > 0) {
          bson_append_bool(&b_fc, tag_table[Tag_bzip2], -1, 1);
        }
        if (fc->data) {
          if (fc->is_base64 > 0) {
            bson_append_utf8(&b_fc, tag_table[Tag_data], -1, fc->data, -1);
          } else {
            bson_append_binary(&b_fc, tag_table[Tag_data], -1, BSON_SUBTYPE_USER, fc->data, fc->size);
          }
        }
        bson_append_document_end(b, &b_fc);
    }
}

static bson_t *
do_unparse(
        bson_t *b,
        testing_report_xml_t r)
{

    bson_append_int32(b, tag_table[Tag_run_id], -1, r->run_id);
    bson_append_int32(b, tag_table[Tag_judge_id], -1, r->judge_id);
    bson_append_int32(b, tag_table[Tag_status], -1, r->status);
    bson_append_int32(b, tag_table[Tag_scoring], -1, r->scoring_system);
    bson_append_int32(b, tag_table[Tag_run_tests], -1, r->run_tests);
    if (r->submit_id > 0) {
        bson_append_int64(b, tag_table[Tag_submit_id], -1, r->submit_id);
    }

    if (r->contest_id > 0) {
        bson_append_int32(b, tag_table[Tag_contest_id], -1, r->contest_id);
    }
    if (r->archive_available > 0) {
        bson_append_bool(b, tag_table[Tag_archive_available], -1, 1);
    }
    if (r->real_time_available > 0) {
        bson_append_bool(b, tag_table[Tag_real_time_available], -1, 1);
    }
    if (r->max_memory_used_available > 0) {
        bson_append_bool(b, tag_table[Tag_max_memory_used_available], -1, 1);
    }
    if (r->max_rss_available > 0) {
        bson_append_bool(b, tag_table[Tag_max_rss_available], -1, 1);
    }
    if (r->separate_user_score > 0) {
        bson_append_bool(b, tag_table[Tag_separate_user_score], -1, 1);
    }
    if (r->correct_available > 0) {
        bson_append_bool(b, tag_table[Tag_correct_available], -1, 1);
    }
    if (r->info_available > 0) {
        bson_append_bool(b, tag_table[Tag_info_available], -1, 1);
    }
    if (r->compile_error > 0) {
        bson_append_bool(b, tag_table[Tag_compile_error], -1, 1);
    }
    if (r->variant > 0) {
        bson_append_int32(b, tag_table[Tag_variant], -1, r->variant);
    }
    if (r->accepting_mode > 0) {
        bson_append_bool(b, tag_table[Tag_accepting_mode], -1, 1);
    }
    if (r->tests_passed >= 0) {
        bson_append_int32(b, tag_table[Tag_tests_passed], -1, r->tests_passed);
    }
    if (r->scoring_system == SCORE_OLYMPIAD && r->accepting_mode > 0 && r->status != RUN_ACCEPTED) {
        if (r->failed_test > 0) {
            bson_append_int32(b, tag_table[Tag_failed_test], -1, r->failed_test);
        }
    } else if (r->scoring_system == SCORE_ACM && r->status != RUN_OK) {
        if (r->failed_test > 0) {
            bson_append_int32(b, tag_table[Tag_failed_test], -1, r->failed_test);
        }
    } else if (r->scoring_system == SCORE_OLYMPIAD && r->accepting_mode <= 0) {
        bson_append_int32(b, tag_table[Tag_score], -1, r->score);
        bson_append_int32(b, tag_table[Tag_max_score], -1, r->max_score);
    } else if (r->scoring_system == SCORE_KIROV) {
        bson_append_int32(b, tag_table[Tag_score], -1, r->score);
        bson_append_int32(b, tag_table[Tag_max_score], -1, r->max_score);
    } else if (r->scoring_system == SCORE_MOSCOW) {
        if (r->status != RUN_OK) {
            if (r->failed_test > 0) {
                bson_append_int32(b, tag_table[Tag_failed_test], -1, r->failed_test);
            }
        }
        bson_append_int32(b, tag_table[Tag_score], -1, r->score);
        bson_append_int32(b, tag_table[Tag_max_score], -1, r->max_score);
    }

    if (r->time_limit_ms > 0) {
        bson_append_int32(b, tag_table[Tag_time_limit_ms], -1, r->time_limit_ms);
    }
    if (r->real_time_limit_ms > 0) {
        bson_append_int32(b, tag_table[Tag_real_time_limit_ms], -1, r->real_time_limit_ms);
    }
    if (r->marked_flag >= 0) {
        bson_append_bool(b, tag_table[Tag_marked_flag], -1, r->marked_flag);
    }
    if (r->tests_mode > 0) {
        bson_append_bool(b, tag_table[Tag_tests_mode], -1, 1);
    }
    if (r->tests_mode > 0 && r->tt_row_count > 0  && r->tt_column_count > 0) {
        bson_append_int32(b, tag_table[Tag_tt_row_count], -1, r->tt_row_count);
        bson_append_int32(b, tag_table[Tag_tt_column_count], -1, r->tt_column_count);
    }
    if (r->user_status >= 0) {
        bson_append_int32(b, tag_table[Tag_user_status], -1, r->user_status);
    }
    if (r->user_tests_passed >= 0) {
        bson_append_int32(b, tag_table[Tag_user_tests_passed], -1, r->user_tests_passed);
    }
    if (r->user_score >= 0) {
        bson_append_int32(b, tag_table[Tag_user_score], -1, r->user_score);
    }
    if (r->user_max_score >= 0) {
        bson_append_int32(b, tag_table[Tag_user_max_score], -1, r->user_max_score);
    }
    if (r->user_run_tests >= 0) {
        bson_append_int32(b, tag_table[Tag_user_run_tests], -1, r->user_run_tests);
    }
    if (r->uuid.v[0] || r->uuid.v[1] || r->uuid.v[2] || r->uuid.v[3]) {
        ej_bson_append_uuid_new(b, tag_table[Tag_uuid], &r->uuid);
    }
    if (ej_uuid_is_nonempty(r->judge_uuid)) {
        ej_bson_append_uuid_new(b, tag_table[Tag_judge_uuid], &r->judge_uuid);
    }
    if (r->comment && r->comment[0]) {
        bson_append_utf8(b, tag_table[Tag_comment], -1, r->comment, -1);
    }
    if (r->valuer_comment && r->valuer_comment[0]) {
        bson_append_utf8(b, tag_table[Tag_valuer_comment], -1, r->valuer_comment, -1);
    }
    if (r->valuer_judge_comment && r->valuer_judge_comment[0]) {
        bson_append_utf8(b, tag_table[Tag_valuer_judge_comment], -1, r->valuer_judge_comment, -1);
    }
    if (r->valuer_errors && r->valuer_errors[0]) {
        bson_append_utf8(b, tag_table[Tag_valuer_errors], -1, r->valuer_errors, -1);
    }
    if (r->host && r->host[0]) {
        bson_append_utf8(b, tag_table[Tag_host], -1, r->host, -1);
    }
    if (r->cpu_model && r->cpu_model[0]) {
        bson_append_utf8(b, tag_table[Tag_cpu_model], -1, r->cpu_model, -1);
    }
    if (r->cpu_mhz && r->cpu_mhz[0]) {
        bson_append_utf8(b, tag_table[Tag_cpu_mhz], -1, r->cpu_mhz, -1);
    }
    if (r->errors && r->errors[0]) {
        bson_append_utf8(b, tag_table[Tag_errors], -1, r->errors, -1);
    }
    if (r->compiler_output && r->compiler_output[0]) {
        bson_append_utf8(b, tag_table[Tag_compiler_output], -1, r->compiler_output, -1);
    }
    if (r->verdict_bits) {
        bson_append_int32(b, tag_table[Tag_verdict_bits], -1, r->verdict_bits);
    }
    if (r->run_tests > 0 && r->tests) {
        bson_t b_tests, *b_testsp = &b_tests;
        int index = -1;
        bson_append_array_begin(b, tag_table[Tag_tests], -1, b_testsp);
        for (int i = 0; i < r->run_tests; ++i) {
            struct testing_report_test *t;
            if (!(t = r->tests[i])) continue;
            ++index;
            bson_t b_test, *b_testp = &b_test;
            {
                char buf[32];
                const char *key;
                uint32_t z = bson_uint32_to_string(index, &key, buf, sizeof(buf));
                bson_append_document_begin(b_testsp, key, z, b_testp);
            }
            bson_append_int32(b_testp, tag_table[Tag_num], -1, i + 1);
            bson_append_int32(b_testp, tag_table[Tag_status], -1, t->status);
            if (t->term_signal > 0) {
                bson_append_int32(b_testp, tag_table[Tag_term_signal], -1, t->term_signal);
            }
            if (t->exit_code > 0) {
                bson_append_int32(b_testp, tag_table[Tag_exit_code], -1, t->exit_code);
            }
            if (t->time >= 0) {
                bson_append_int32(b_testp, tag_table[Tag_time], -1, t->time);
            }
            if (r->real_time_available > 0 && t->real_time >= 0) {
                bson_append_int32(b_testp, tag_table[Tag_real_time], -1, t->real_time);
            }
            if (r->max_memory_used_available > 0 && t->max_memory_used > 0) {
                bson_append_int64(b_testp, tag_table[Tag_max_memory_used], -1, t->max_memory_used);
            }
            if (r->max_rss_available > 0 && t->max_rss > 0) {
                bson_append_int64(b_testp, tag_table[Tag_max_rss], -1, t->max_rss);
            }
            if (r->scoring_system == SCORE_OLYMPIAD && r->accepting_mode <= 0) {
                bson_append_int32(b_testp, tag_table[Tag_nominal_score], -1, t->nominal_score);
                bson_append_int32(b_testp, tag_table[Tag_score], -1, t->score);
            } else if (r->scoring_system == SCORE_KIROV) {
                bson_append_int32(b_testp, tag_table[Tag_nominal_score], -1, t->nominal_score);
                bson_append_int32(b_testp, tag_table[Tag_score], -1, t->score);
            }
            if (t->comment && t->comment[0]) {
                bson_append_utf8(b_testp, tag_table[Tag_comment], -1, t->comment, -1);
            }
            if (t->team_comment && t->team_comment[0]) {
                bson_append_utf8(b_testp, tag_table[Tag_team_comment], -1, t->team_comment, -1);
            }
            if (t->exit_comment && t->exit_comment[0]) {
                bson_append_utf8(b_testp, tag_table[Tag_exit_comment], -1, t->exit_comment, -1);
            }
            if (t->checker_comment && t->checker_comment[0]) {
                bson_append_utf8(b_testp, tag_table[Tag_checker_comment], -1, t->checker_comment, -1);
            }
            if (t->checker_token && t->checker_token[0]) {
                bson_append_utf8(b_testp, tag_table[Tag_checker_token], -1, t->checker_token, -1);
            }
            unparse_digest_attr(b_testp, tag_table[Tag_input_digest], t->input_digest);
            unparse_digest_attr(b_testp, tag_table[Tag_correct_digest], t->correct_digest);
            unparse_digest_attr(b_testp, tag_table[Tag_info_digest], t->info_digest);
            if (t->output_available > 0) {
                bson_append_bool(b_testp, tag_table[Tag_output_available], -1, 1);
            }
            if (t->stderr_available > 0) {
                bson_append_bool(b_testp, tag_table[Tag_stderr_available], -1, 1);
            }
            if (t->checker_output_available > 0) {
                bson_append_bool(b_testp, tag_table[Tag_checker_output_available], -1, 1);
            }
            if (t->args_too_long > 0) {
                bson_append_bool(b_testp, tag_table[Tag_args_too_long], -1, 1);
            }
            if (t->visibility > 0) {
                bson_append_int32(b_testp, tag_table[Tag_visibility], -1, t->visibility);
            }
            if (t->has_user > 0) {
                bson_append_bool(b_testp, tag_table[Tag_has_user], -1, 1);
                if (t->user_status >= 0) {
                    bson_append_int32(b_testp, tag_table[Tag_user_status], -1, t->user_status);
                }
                if (t->user_score >= 0) {
                    bson_append_int32(b_testp, tag_table[Tag_user_score], -1, t->user_score);
                }
                if (t->user_nominal_score >= 0) {
                    bson_append_int32(b_testp, tag_table[Tag_user_nominal_score], -1, t->user_nominal_score);
                }
            }
            if (t->args && t->args[0]) {
                bson_append_utf8(b_testp, tag_table[Tag_args], -1, t->args, -1);
            }
            if (t->program_stats_str && t->program_stats_str[0]) {
                bson_append_utf8(b_testp, tag_table[Tag_program_stats_str], -1, t->program_stats_str, -1);
            }
            if (t->interactor_stats_str && t->interactor_stats_str[0]) {
                bson_append_utf8(b_testp, tag_table[Tag_interactor_stats_str], -1, t->interactor_stats_str, -1);
            }
            if (t->checker_stats_str && t->checker_stats_str[0]) {
                bson_append_utf8(b_testp, tag_table[Tag_checker_stats_str], -1, t->checker_stats_str, -1);
            }
            unparse_file_content(b_testp, tag_table[Tag_input], &t->input);
            unparse_file_content(b_testp, tag_table[Tag_output], &t->output);
            unparse_file_content(b_testp, tag_table[Tag_correct], &t->correct);
            unparse_file_content(b_testp, tag_table[Tag_stderr], &t->error);
            unparse_file_content(b_testp, tag_table[Tag_checker], &t->checker);
            unparse_file_content(b_testp, tag_table[Tag_test_checker], &t->test_checker);
            bson_append_document_end(b_testsp, b_testp);
        }
        bson_append_array_end(b, b_testsp);
    }
    if (r->tt_row_count > 0 && r->tt_rows) {
        bson_t b_ttrows;
        bson_append_array_begin(b, tag_table[Tag_ttrows], -1, &b_ttrows);
        int index = -1;
        for (int i = 0; i < r->tt_row_count; ++i) {
            struct testing_report_row *ttr;
            if (!(ttr = r->tt_rows[i])) continue;
            ++index;
            bson_t b_ttrow;
            {
                char buf[32];
                const char *key;
                uint32_t z = bson_uint32_to_string(index, &key, buf, sizeof(buf));
                bson_append_document_begin(&b_ttrows, key, z, &b_ttrow);
            }
            bson_append_int32(&b_ttrow, tag_table[Tag_row], -1, ttr->row);
            bson_append_utf8(&b_ttrow, tag_table[Tag_name], -1, ttr->name, -1);
            bson_append_int32(&b_ttrow, tag_table[Tag_status], -1, ttr->status);
            if (ttr->must_fail) {
                bson_append_bool(&b_ttrow, tag_table[Tag_must_fail], -1, 1);
            }
            if (ttr->score >= 0) {
                bson_append_int32(&b_ttrow, tag_table[Tag_score], -1, ttr->score);
            }
            if (ttr->nominal_score >= 0) {
                bson_append_int32(&b_ttrow, tag_table[Tag_nominal_score], -1, ttr->nominal_score);
            }
            bson_append_document_end(&b_ttrows, &b_ttrow);
        }
        bson_append_array_end(b, &b_ttrows);
    }

    if (r->tt_row_count > 0 && r->tt_column_count > 0 && r->tt_cells) {
        bson_t b_ttcells;
        bson_append_array_begin(b, tag_table[Tag_ttcells], -1, &b_ttcells);
        int index = -1;
        for (int i = 0; i < r->tt_row_count; ++i) {
            if (!r->tt_cells[i]) continue;
            for (int j = 0; j < r->tt_column_count; ++j) {
                struct testing_report_cell *ttc;
                if (!(ttc = r->tt_cells[i][j])) continue;
                ++index;
                bson_t b_ttcell;
                {
                    char buf[32];
                    const char *key;
                    uint32_t z = bson_uint32_to_string(index, &key, buf, sizeof(buf));
                    bson_append_document_begin(&b_ttcells, key, z, &b_ttcell);
                }
                bson_append_int32(&b_ttcell, tag_table[Tag_row], -1, i);
                bson_append_int32(&b_ttcell, tag_table[Tag_column], -1, j);
                bson_append_int32(&b_ttcell, tag_table[Tag_status], -1, ttc->status);
                if (ttc->time >= 0) {
                    bson_append_int32(&b_ttcell, tag_table[Tag_time], -1, ttc->time);
                }
                if (ttc->real_time >= 0) {
                    bson_append_int32(&b_ttcell, tag_table[Tag_real_time], -1, ttc->real_time);
                }
                bson_append_document_end(&b_ttcells, &b_ttcell);
            }
        }
        bson_append_array_end(b, &b_ttcells);
    }
    return 0;
}

int
testing_report_to_mem_bson(
        char **pstr,
        size_t *psize,
        testing_report_xml_t r)
{
    bson_t *b = bson_new();
    do_unparse(b, r);
    const unsigned char *data = bson_get_data(b);
    char *res = malloc(b->len);
    memcpy(res, data, b->len);
    *pstr = res;
    *psize = b->len;
    bson_destroy(b);
    return 0;
}

int
testing_report_to_file_bson(
        const unsigned char *path,
        testing_report_xml_t r)
{
    int retval = -1;
    bson_t *b = bson_new();
    int fd = -1;
    void *ptr = MAP_FAILED;
    do_unparse(b, r);
    const unsigned char *data = bson_get_data(b);

    fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        err("testing_report_to_file_bson: open: %s: failed: %s", path, os_ErrorMsg());
        goto cleanup;
    }
    if (ftruncate(fd, b->len) < 0) {
        err("testing_report_to_file_bson: ftruncate: %s: failed: %s", path, os_ErrorMsg());
        goto cleanup;
    }
    if (b->len > 0) {
        ptr = mmap(NULL, b->len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
            err("testing_report_to_file_bson: mmap: %s: failed: %s", path, os_ErrorMsg());
            goto cleanup;
        }
        memcpy(ptr, data, b->len);
        munmap(ptr, b->len);
    }
    close(fd); fd = -1;
    bson_destroy(b); b = NULL;
    retval = 0;

cleanup:
    if (b) bson_destroy(b);
    if (fd < 0) close(fd);
    return retval;
}
#else
// stubs when bson format is not available
int testing_report_bson_available(void)
{
    return 0;
}

testing_report_xml_t
testing_report_parse_bson_data(
        const unsigned char *data,
        unsigned int size)
{
    return NULL;
}

testing_report_xml_t
testing_report_parse_bson_file(
        const unsigned char *path)
{
    return NULL;
}

int
testing_report_to_mem_bson(
        char **pstr,
        size_t *psize,
        testing_report_xml_t r)
{
    return -1;
}

int
testing_report_to_file_bson(
        const unsigned char *path,
        testing_report_xml_t r)
{
    return -1;
}
#endif
