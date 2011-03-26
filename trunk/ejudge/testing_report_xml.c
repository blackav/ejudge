/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2011 Alexander Chernov <cher@ejudge.ru> */

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

#include "config.h"
#include "ej_limits.h"

#include "testing_report_xml.h"
#include "expat_iface.h"
#include "xml_utils.h"
#include "protocol.h"
#include "runlog.h"
#include "digest_io.h"
#include "misctext.h"

#include "reuse_xalloc.h"
#include "reuse_logger.h"

#include <string.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJ_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

/*
<testing-report run-id="N" judge-id="N" status="O" scoring="R" archive-available="B" [correct-available="B"] [info-available="B"] run-tests="N" [variant="N"] [accepting-mode="B"] [failed-test="N"] [tests-passed="N"] [score="N"] [time_limit_ms="T" real_time_limit_ms="T" [real-time-available="B"] [max-memory-used-available="T"] [marked-flag="B"] [tests-mode="B"] [tt-row-count="N"] [tt-column-count="N"] [user-status="O"] [user-tests-passed="N"] [user-score="N"] [user-max-score="N"] [user-run-tests="N"] >
  <comment>T</comment>
  <valuer_comment>T</valuer_comment>
  <valuer_judge_comment>T</valuer_judge_comment>
  <valuer_errors>T</valuer_errors>
  <host>T</host>
  <errors>T</errors>
  <tests>
    <test num="N" status="O" [exit-code="N"] [term-signal="N"] time="N" real-time="N" [max-memory-used="N"] [nominal-score="N" score="N"] [comment="S"] [team-comment="S"] [checker-comment="S"] [exit-comment="S"] output-available="B" stderr-available="B" checker-output-available="B" args-too-long="B" [input-digest="X"] [correct-digest="X"] [visibility="O"]>
       [<args>T</args>]
       [<input>T</input>]
       [<output>T</output>]
       [<correct>T</correct>]
       [<stderr>T</stderr>]
       [<checker>T</checker>]
    </test>
  </tests>
  <ttrows>
    <ttrow id="N" name="S" must-fail="B" />
  </ttrows>
  <ttcells>
    <ttcell row="N" column="N" status="O" time="N" real-time="N" />
  </ttcells>
</testing-report>
 */

/* elements */
enum
{
  TR_T_TESTING_REPORT = 1,
  TR_T_TESTS,
  TR_T_TEST,
  TR_T_ARGS,
  TR_T_INPUT,
  TR_T_OUTPUT,
  TR_T_CORRECT,
  TR_T_STDERR,
  TR_T_CHECKER,
  TR_T_COMMENT,
  TR_T_VALUER_COMMENT,
  TR_T_VALUER_JUDGE_COMMENT,
  TR_T_VALUER_ERRORS,
  TR_T_HOST,
  TR_T_ERRORS,
  TR_T_TTROWS,
  TR_T_TTROW,
  TR_T_TTCELLS,
  TR_T_TTCELL,

  TR_T_LAST_TAG,
};
enum
{
  TR_A_RUN_ID = 1,
  TR_A_JUDGE_ID,
  TR_A_STATUS,
  TR_A_SCORING,
  TR_A_ARCHIVE_AVAILABLE,
  TR_A_CORRECT_AVAILABLE,
  TR_A_INFO_AVAILABLE,
  TR_A_RUN_TESTS,
  TR_A_VARIANT,
  TR_A_ACCEPTING_MODE,
  TR_A_FAILED_TEST,
  TR_A_TESTS_PASSED,
  TR_A_MAX_SCORE,
  TR_A_SCORE,
  TR_A_NUM,
  TR_A_EXIT_CODE,
  TR_A_TERM_SIGNAL,
  TR_A_TIME,
  TR_A_REAL_TIME,
  TR_A_NOMINAL_SCORE,
  TR_A_COMMENT,
  TR_A_TEAM_COMMENT,
  TR_A_CHECKER_COMMENT,
  TR_A_OUTPUT_AVAILABLE,
  TR_A_STDERR_AVAILABLE,
  TR_A_CHECKER_OUTPUT_AVAILABLE,
  TR_A_ARGS_TOO_LONG,
  TR_A_INPUT_DIGEST,
  TR_A_CORRECT_DIGEST,
  TR_A_INFO_DIGEST,
  TR_A_TIME_LIMIT_MS,
  TR_A_REAL_TIME_LIMIT_MS,
  TR_A_EXIT_COMMENT,
  TR_A_MAX_MEMORY_USED,
  TR_A_REAL_TIME_AVAILABLE,
  TR_A_MAX_MEMORY_USED_AVAILABLE,
  TR_A_MARKED_FLAG,
  TR_A_TESTS_MODE,
  TR_A_TT_ROW_COUNT,
  TR_A_TT_COLUMN_COUNT,
  TR_A_NAME,
  TR_A_MUST_FAIL,
  TR_A_ROW,
  TR_A_COLUMN,
  TR_A_VISIBILITY,
  TR_A_USER_STATUS,
  TR_A_USER_TESTS_PASSED,
  TR_A_USER_SCORE,
  TR_A_USER_MAX_SCORE,
  TR_A_USER_RUN_TESTS,

  TR_A_LAST_ATTR,
};

static const char * const elem_map[] =
{
  [TR_T_TESTING_REPORT] = "testing-report",
  [TR_T_TESTS] = "tests",
  [TR_T_TEST] = "test",
  [TR_T_ARGS] = "args",
  [TR_T_INPUT] = "input",
  [TR_T_OUTPUT] = "output",
  [TR_T_CORRECT] = "correct",
  [TR_T_STDERR] = "stderr",
  [TR_T_CHECKER] = "checker",
  [TR_T_COMMENT] = "comment",
  [TR_T_VALUER_COMMENT] = "valuer-comment",
  [TR_T_VALUER_JUDGE_COMMENT] = "valuer-judge-comment",
  [TR_T_VALUER_ERRORS] = "valuer-errors",
  [TR_T_HOST] = "host",
  [TR_T_ERRORS] = "errors",
  [TR_T_TTROWS] = "ttrows",
  [TR_T_TTROW] = "ttrow",
  [TR_T_TTCELLS] = "ttcells",
  [TR_T_TTCELL] = "ttcell",

  [TR_T_LAST_TAG] = 0,
};
static const char * const attr_map[] =
{
  [TR_A_RUN_ID] = "run-id",
  [TR_A_JUDGE_ID] = "judge-id",
  [TR_A_STATUS] = "status",
  [TR_A_SCORING] = "scoring",
  [TR_A_ARCHIVE_AVAILABLE] = "archive-available",
  [TR_A_CORRECT_AVAILABLE] = "correct-available",
  [TR_A_INFO_AVAILABLE] = "info-available",
  [TR_A_RUN_TESTS] = "run-tests",
  [TR_A_VARIANT] = "variant",
  [TR_A_ACCEPTING_MODE] = "accepting-mode",
  [TR_A_FAILED_TEST] = "failed-test",
  [TR_A_TESTS_PASSED] = "tests-passed",
  [TR_A_SCORE] = "score",
  [TR_A_MAX_SCORE] = "max-score",
  [TR_A_NUM] = "num",
  [TR_A_EXIT_CODE] = "exit-code",
  [TR_A_TERM_SIGNAL] = "term-signal",
  [TR_A_TIME] = "time",
  [TR_A_REAL_TIME] = "real-time",
  [TR_A_NOMINAL_SCORE] = "nominal-score",
  [TR_A_COMMENT] = "comment",
  [TR_A_TEAM_COMMENT] = "team-comment",
  [TR_A_CHECKER_COMMENT] = "checker-comment",
  [TR_A_OUTPUT_AVAILABLE] = "output-available",
  [TR_A_STDERR_AVAILABLE] = "stderr-available",
  [TR_A_CHECKER_OUTPUT_AVAILABLE] = "checker-output-available",
  [TR_A_ARGS_TOO_LONG] = "args-too-long",
  [TR_A_INPUT_DIGEST] = "input-digest",
  [TR_A_CORRECT_DIGEST] = "correct-digest",
  [TR_A_INFO_DIGEST] = "info-digest",
  [TR_A_TIME_LIMIT_MS] = "time-limit-ms",
  [TR_A_REAL_TIME_LIMIT_MS] = "real-time-limit-ms",
  [TR_A_EXIT_COMMENT] = "exit-comment",
  [TR_A_MAX_MEMORY_USED] = "max-memory-used",
  [TR_A_REAL_TIME_AVAILABLE] = "real-time-available",
  [TR_A_MAX_MEMORY_USED_AVAILABLE] = "max-memory-used-available",
  [TR_A_MARKED_FLAG] = "marked-flag",
  [TR_A_TESTS_MODE] = "tests-mode",
  [TR_A_TT_ROW_COUNT] = "tt-row-count",
  [TR_A_TT_COLUMN_COUNT] = "tt-column-count",
  [TR_A_NAME] = "name",
  [TR_A_MUST_FAIL] = "must-fail",
  [TR_A_ROW] = "row",
  [TR_A_COLUMN] = "column",
  [TR_A_VISIBILITY] = "visibility",
  [TR_A_USER_STATUS] = "user-status",
  [TR_A_USER_TESTS_PASSED] = "user-tests-passed",
  [TR_A_USER_SCORE] = "user-score",
  [TR_A_USER_MAX_SCORE] = "user-max-score",
  [TR_A_USER_RUN_TESTS] = "user-run-tests",

  [TR_A_LAST_ATTR] = 0,
};

static struct xml_parse_spec testing_report_parse_spec =
{
  .elem_map = elem_map,
  .attr_map = attr_map,
  .elem_sizes = NULL,
  .attr_sizes = NULL,
  .default_elem = 0,
  .default_attr = 0,
  .elem_alloc = NULL,
  .attr_alloc = NULL,
  .elem_free = NULL,
  .attr_free = NULL,
};

static int
parse_scoring(const unsigned char *str, int *px)
{
  if (!str) return -1;
  if (!strcasecmp(str, "ACM")) {
    *px = SCORE_ACM;
  } else if (!strcasecmp(str, "KIROV")) {
    *px = SCORE_KIROV;
  } else if (!strcasecmp(str, "OLYMPIAD")) {
    *px = SCORE_OLYMPIAD;
  } else if (!strcasecmp(str, "MOSCOW")) {
    *px = SCORE_MOSCOW;
  } else {
    return -1;
  }
  return 0;
}

static struct testing_report_test * testing_report_test_free(struct testing_report_test *p);

static int
parse_test(struct xml_tree *t, testing_report_xml_t r)
{
  struct testing_report_test *p = 0, *q = 0;
  struct xml_attr *a;
  struct xml_tree *t2;
  int x;

  if (t->tag != TR_T_TEST) {
    xml_err_elem_not_allowed(t);
    return -1;
  }
  if (xml_empty_text(t) < 0) goto failure;

  XCALLOC(p, 1);
  p->num = -1;
  p->status = -1;
  p->time = -1;
  p->real_time = -1;
  p->exit_code = -1;
  p->term_signal = -1;
  p->nominal_score = -1;
  p->score = -1;

  for (a = t->first; a; a = a->next) {
    switch (a->tag) {
    case TR_A_NUM:
      if (xml_attr_int(a, &x) < 0) goto failure;
      if (x <= 0 || x > r->run_tests) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->num = x;
      break;
    case TR_A_STATUS:
      if (!a->text || run_str_short_to_status(a->text, &x) < 0
          || !run_is_valid_test_status(x)) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->status = x;
      break;
    case TR_A_TIME:
      if (xml_attr_int(a, &x) < 0) goto failure;
      if (x < 0) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->time = x;
      break;
    case TR_A_REAL_TIME:
      if (xml_attr_int(a, &x) < 0) goto failure;
      if (x < 0) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->real_time = x;
      break;
    case TR_A_MAX_MEMORY_USED:
      if (xml_attr_int(a, &x) < 0) goto failure;
      if (x < 0) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->max_memory_used = x;
      break;
    case TR_A_EXIT_CODE:
      if (xml_attr_int(a, &x) < 0) goto failure;
      if (x < 0) x = 255;
      if (x < 0 || x > 255) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->exit_code = x;
      break;
    case TR_A_TERM_SIGNAL:
      if (xml_attr_int(a, &x) < 0) goto failure;
      if (x <= 0 || x > 255) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->term_signal = x;
      break;
    case TR_A_NOMINAL_SCORE:
      if (xml_attr_int(a, &x) < 0) goto failure;
      if (x < 0 || x > EJ_MAX_SCORE) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->nominal_score = x;
      break;
    case TR_A_SCORE:
      if (xml_attr_int(a, &x) < 0) goto failure;
      if (x < 0 || x > EJ_MAX_SCORE) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->score = x;
      break;
    case TR_A_VISIBILITY:
      x = test_visibility_parse(a->text);
      if (x < 0 || x >= TV_LAST) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->visibility = x;
      break;
    case TR_A_COMMENT:
      p->comment = a->text;
      a->text = 0;
      break;

    case TR_A_TEAM_COMMENT:
      p->team_comment = a->text;
      a->text = 0;
      break;

    case TR_A_CHECKER_COMMENT:
      p->checker_comment = a->text;
      a->text = 0;
      break;

    case TR_A_EXIT_COMMENT:
      p->exit_comment = a->text;
      a->text = 0;
      break;

    case TR_A_OUTPUT_AVAILABLE:
      if (xml_attr_bool(a, &x) < 0) goto failure;
      p->output_available = x;
      break;
    case TR_A_STDERR_AVAILABLE:
      if (xml_attr_bool(a, &x) < 0) goto failure;
      p->stderr_available = x;
      break;
    case TR_A_CHECKER_OUTPUT_AVAILABLE:
      if (xml_attr_bool(a, &x) < 0) goto failure;
      p->checker_output_available = x;
      break;
    case TR_A_ARGS_TOO_LONG:
      if (xml_attr_bool(a, &x) < 0) goto failure;
      p->args_too_long = x;
      break;
    case TR_A_INPUT_DIGEST:
      if (digest_from_ascii(DIGEST_SHA1, a->text, p->input_digest) < 0) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->has_input_digest = 1;
      break;
    case TR_A_CORRECT_DIGEST:
      if (digest_from_ascii(DIGEST_SHA1, a->text, p->correct_digest) < 0) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->has_correct_digest = 1;
      break;
    case TR_A_INFO_DIGEST:
      if (digest_from_ascii(DIGEST_SHA1, a->text, p->info_digest) < 0) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->has_info_digest = 1;
      break;

    default:
      xml_err_attr_not_allowed(t, a);
      goto failure;
    }
  }

  if (p->num < 0) {
    xml_err_attr_undefined(t, TR_A_NUM);
    goto failure;
  }
  if (p->status < 0) {
    xml_err_attr_undefined(t, TR_A_STATUS);
    goto failure;
  }
  if (r->tests[p->num - 1]) {
    xml_err(t, "duplicated test %d", p->num);
    goto failure;
  }
  q = r->tests[p->num - 1] = p;
  p = 0;

  for (t2 = t->first_down; t2; t2 = t2->right) {
    switch (t2->tag) {
    case TR_T_ARGS:
      if (xml_leaf_elem(t2, &q->args, 1, 1) < 0) goto failure;
      break;
    case TR_T_INPUT:
      if (xml_leaf_elem(t2, &q->input, 1, 1) < 0) goto failure;
      break;
    case TR_T_OUTPUT:
      if (xml_leaf_elem(t2, &q->output, 1, 1) < 0) goto failure;
      break;
    case TR_T_CORRECT:
      if (xml_leaf_elem(t2, &q->correct, 1, 1) < 0) goto failure;
      break;
    case TR_T_STDERR:
      if (xml_leaf_elem(t2, &q->error, 1, 1) < 0) goto failure;
      break;
    case TR_T_CHECKER:
      if (xml_leaf_elem(t2, &q->checker, 1, 1) < 0) goto failure;
      break;

    default:
      xml_err_elem_not_allowed(t2);
      goto failure;
    }
  }
  return 0;

 failure:
  testing_report_test_free(p);
  return -1;
}

static int
parse_tests(struct xml_tree *t, testing_report_xml_t r)
{
  struct xml_tree *p;

  if (t->tag != TR_T_TESTS) {
    xml_err_elem_not_allowed(t);
    return -1;
  }
  if (t->first) {
    xml_err_attrs(t);
    return -1;
  }
  if (xml_empty_text(t) < 0) return -1;

  for (p = t->first_down; p; p = p->right) {
    if (parse_test(p, r) < 0) return -1;
  }

  return 0;
}

static int
parse_ttrow(struct xml_tree *t, testing_report_xml_t r)
{
  struct xml_attr *a;
  int x, row = -1, status = RUN_CHECK_FAILED, must_fail = 0;
  int nominal_score = -1, score = -1;
  unsigned char *name = 0;

  if (t->tag != TR_T_TTROW) {
    return xml_err_elem_not_allowed(t);
  }
  if (xml_empty_text(t) < 0) return -1;
  if (t->first_down) {
    return xml_err_nested_elems(t);
  }
  for (a = t->first; a; a = a->next) {
    switch (a->tag) {
    case TR_A_ROW:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x >= r->tt_row_count) return xml_err_attr_invalid(a);
      row = x;
      break;
    case TR_A_NAME:
      name = a->text;
      a->text = 0;
      break;
    case TR_A_MUST_FAIL:
      if (xml_attr_bool(a, &x) < 0) return -1;
      must_fail = x;
      break;
    case TR_A_STATUS:
      if (!a->text || run_str_short_to_status(a->text, &x) < 0)
        return xml_err_attr_invalid(a);
      status = x;
      break;
    case TR_A_NOMINAL_SCORE:
      if (xml_attr_int(a, &x) < 0) return xml_err_attr_invalid(a);
      if (x < 0 || x > EJ_MAX_SCORE) return xml_err_attr_invalid(a);
      nominal_score = x;
      break;
    case TR_A_SCORE:
      if (xml_attr_int(a, &x) < 0) return xml_err_attr_invalid(a);
      if (x < 0 || x > EJ_MAX_SCORE) return xml_err_attr_invalid(a);
      score = x;
      break;
    default:
      return xml_err_attr_not_allowed(t, a);
    }
  }

  if (row < 0) return xml_err_attr_undefined(t, TR_A_ROW);
  if (!name) return xml_err_attr_undefined(t, TR_A_NAME);

  r->tt_rows[row]->row = row;
  r->tt_rows[row]->name = name;
  r->tt_rows[row]->status = status;
  r->tt_rows[row]->must_fail = must_fail;
  r->tt_rows[row]->nominal_score = nominal_score;
  r->tt_rows[row]->score = score;

  return 0;
}

static int
parse_ttrows(struct xml_tree *t, testing_report_xml_t r)
{
  struct xml_tree *p;

  if (t->tag != TR_T_TTROWS) {
    xml_err_elem_not_allowed(t);
    return -1;
  }
  if (t->first) {
    xml_err_attrs(t);
    return -1;
  }
  if (xml_empty_text(t) < 0) return -1;

  for (p = t->first_down; p; p = p->right) {
    if (parse_ttrow(p, r) < 0) return -1;
  }

  return 0;
}

static int
parse_ttcell(struct xml_tree *t, testing_report_xml_t r)
{
  struct xml_attr *a;
  int row = -1, column = -1;
  int status = RUN_CHECK_FAILED;
  int time = -1, real_time = -1, x;
  struct testing_report_cell *ttc = 0;

  if (t->tag != TR_T_TTCELL) {
    return xml_err_elem_not_allowed(t);
  }
  if (xml_empty_text(t) < 0) return -1;
  if (t->first_down) {
    return xml_err_nested_elems(t);
  }
  for (a = t->first; a; a = a->next) {
    switch (a->tag) {
    case TR_A_ROW:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x >= r->tt_row_count) return xml_err_attr_invalid(a);
      row = x;
      break;
    case TR_A_COLUMN:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x >= r->tt_column_count) return xml_err_attr_invalid(a);
      column = x;
      break;
    case TR_A_STATUS:
      if (!a->text || run_str_short_to_status(a->text, &x) < 0)
        return xml_err_attr_invalid(a);
      status = x;
      break;
    case TR_A_TIME:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < -1) return xml_err_attr_invalid(a);
      time = x;
      break;
    case TR_A_REAL_TIME:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < -1) return xml_err_attr_invalid(a);
      real_time = x;
      break;
    default:
      return xml_err_attr_not_allowed(t, a);
    }
  }

  ttc = r->tt_cells[row][column];
  ttc->row = row;
  ttc->column = column;
  ttc->status = status;
  ttc->time = time;
  ttc->real_time = real_time;

  return 0;
}

static int
parse_ttcells(struct xml_tree *t, testing_report_xml_t r)
{
  struct xml_tree *p;

  if (t->tag != TR_T_TTCELLS) {
    xml_err_elem_not_allowed(t);
    return -1;
  }
  if (t->first) {
    xml_err_attrs(t);
    return -1;
  }
  if (xml_empty_text(t) < 0) return -1;

  for (p = t->first_down; p; p = p->right) {
    if (parse_ttcell(p, r) < 0) return -1;
  }

  return 0;
}

static int
parse_testing_report(struct xml_tree *t, testing_report_xml_t r)
{
  struct xml_attr *a;
  int x, was_tests = 0, was_ttrows = 0, was_ttcells = 0;
  struct xml_attr *a_failed_test = 0, *a_tests_passed = 0, *a_score = 0;
  struct xml_attr *a_max_score = 0;
  struct xml_tree *t2;
  int i, j;

  if (t->tag != TR_T_TESTING_REPORT) {
    xml_err_top_level(t, TR_T_TESTING_REPORT);
    return -1;
  }
  if (xml_empty_text(t) < 0) return -1;

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

  for (a = t->first; a; a = a->next) {
    switch (a->tag) {
    case TR_A_RUN_ID:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_RUN_ID) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->run_id = x;
      break;

    case TR_A_JUDGE_ID:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_JUDGE_ID) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->judge_id = x;
      break;

    case TR_A_STATUS:
      if (!a->text || run_str_short_to_status(a->text, &x) < 0) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->status = x;
      break;
    case TR_A_USER_STATUS:
      if (!a->text || run_str_short_to_status(a->text, &x) < 0) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->user_status = x;
      break;

    case TR_A_SCORING:
      if (parse_scoring(a->text, &x) < 0) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->scoring_system = x;
      break;

    case TR_A_ARCHIVE_AVAILABLE:
      if (xml_attr_bool(a, &x) < 0) return -1;
      r->archive_available = x;
      break;

    case TR_A_CORRECT_AVAILABLE:
      if (xml_attr_bool(a, &x) < 0) return -1;
      r->correct_available = x;
      break;

    case TR_A_INFO_AVAILABLE:
      if (xml_attr_bool(a, &x) < 0) return -1;
      r->info_available = x;
      break;

    case TR_A_REAL_TIME_AVAILABLE:
      if (xml_attr_bool(a, &x) < 0) return -1;
      r->real_time_available = x;
      break;

    case TR_A_MAX_MEMORY_USED_AVAILABLE:
      if (xml_attr_bool(a, &x) < 0) return -1;
      r->max_memory_used_available = x;
      break;

      /*
        The total number of tests is allowed to be 0.
       */
    case TR_A_RUN_TESTS:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_TEST_NUM) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->run_tests = x;
      break;

    case TR_A_USER_RUN_TESTS:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_TEST_NUM) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->user_run_tests = x;
      break;

    case TR_A_VARIANT:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_VARIANT) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->variant = x;
      break;

    case TR_A_ACCEPTING_MODE:
      if (xml_attr_bool(a, &x) < 0) return -1;
      r->accepting_mode = x;
      break;

      /*
        Tests are counted from 1.
       */
    case TR_A_FAILED_TEST:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x <= 0 || x >= EJ_MAX_TEST_NUM) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->failed_test = x;
      a_failed_test = a;
      break;

    case TR_A_TESTS_PASSED:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_TEST_NUM) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->tests_passed = x;
      a_tests_passed = a;
      break;
    case TR_A_USER_TESTS_PASSED:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_TEST_NUM) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->user_tests_passed = x;
      break;

    case TR_A_SCORE:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_SCORE) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->score = x;
      a_score = a;
      break;
    case TR_A_USER_SCORE:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_SCORE) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->user_score = x;
      break;

    case TR_A_MAX_SCORE:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_SCORE) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->max_score = x;
      a_max_score = a;
      break;
    case TR_A_USER_MAX_SCORE:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > EJ_MAX_SCORE) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->user_max_score = x;
      break;

    case TR_A_TIME_LIMIT_MS:
      if (xml_attr_int(a, &x) < 0) return -1;
      r->time_limit_ms = x;
      break;

    case TR_A_REAL_TIME_LIMIT_MS:
      if (xml_attr_int(a, &x) < 0) return -1;
      r->real_time_limit_ms = x;
      break;

    case TR_A_MARKED_FLAG:
      if (xml_attr_bool(a, &x) < 0) return -1;
      r->marked_flag = x;
      break;

    case TR_A_TESTS_MODE:
      if (xml_attr_bool(a, &x) < 0) return -1;
      r->tests_mode = x;
      break;

    case TR_A_TT_ROW_COUNT:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->tt_row_count = x;
      break;

    case TR_A_TT_COLUMN_COUNT:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->tt_column_count = x;
      break;

    default:
      xml_err_attr_not_allowed(t, a);
      return -1;
    }
  }

  if (r->tt_row_count < 0 || r->tt_column_count < 0) {
    /* FIXME: report an error */
    return -1;
  }
  if (r->tests_mode > 0) {
    if (!r->tt_row_count || !r->tt_column_count) {
      /* FIXME: report an error */
    }
  } else {
    if (r->tt_row_count > 0 || r->tt_column_count > 0) {
      /* FIXME: report an error */
      return -1;
    }
  }

  if (r->run_id < 0) {
    xml_err_attr_undefined(t, TR_A_RUN_ID);
    return -1;
  }
  if (r->judge_id < 0) {
    xml_err_attr_undefined(t, TR_A_JUDGE_ID);
    return -1;
  }
  if (r->status < 0) {
    xml_err_attr_undefined(t, TR_A_STATUS);
    return -1;
  }
  if (r->scoring_system < 0) {
    xml_err_attr_undefined(t, TR_A_SCORING);
    return -1;
  }
  if (r->run_tests < 0) {
    xml_err_attr_undefined(t, TR_A_RUN_TESTS);
    return -1;
  }
  if ((r->scoring_system == SCORE_ACM && r->status != RUN_OK)
      || (r->scoring_system == SCORE_OLYMPIAD && r->accepting_mode
          && r->status != RUN_ACCEPTED)) {
    /*
    if (r->failed_test < 0) {
      xml_err_attr_undefined(t, TR_A_FAILED_TEST);
      return -1;
    }
    */
    if (r->tests_passed >= 0) {
      xml_err_attr_not_allowed(t, a_tests_passed);
      return -1;
    }
    if (r->score >= 0) {
      xml_err_attr_not_allowed(t, a_score);
      return -1;
    }
    if (r->max_score >= 0) {
      xml_err_attr_not_allowed(t, a_max_score);
      return -1;
    }
  } else if ((r->scoring_system == SCORE_OLYMPIAD && !r->accepting_mode
              && r->status != RUN_OK)
             || (r->scoring_system == SCORE_KIROV && r->status != RUN_OK)) {
    if (r->failed_test >= 0) {
      xml_err_attr_not_allowed(t, a_failed_test);
      return -1;
    }
    if (r->tests_passed < 0) {
      xml_err_attr_undefined(t, TR_A_TESTS_PASSED);
      return -1;
    }
    if (r->score < 0) {
      xml_err_attr_undefined(t, TR_A_SCORE);
      return -1;
    }
    if (r->max_score < 0) {
      xml_err_attr_undefined(t, TR_A_MAX_SCORE);
      return -1;
    }
  }

  if (!t->first_down) {
    xml_err_elem_undefined(t, TR_T_TESTS);
    return -1;
  }
  /*
  if (t->first_down->right) {
    xml_err_elem_not_allowed(t->first_down->right);
    return -1;
  }
  */

  if (r->run_tests > 0) {
    XCALLOC(r->tests, r->run_tests);
  }

  if (r->tests_mode > 0) {
    if (r->tt_row_count > 0 && r->tt_column_count > 0) {
      XCALLOC(r->tt_rows, r->tt_row_count);
      XCALLOC(r->tt_cells, r->tt_row_count);
      for (i = 0; i < r->tt_row_count; ++i) {
        struct testing_report_row *ttr = 0;
        XCALLOC(ttr, 1);
        r->tt_rows[i] = ttr;
        ttr->row = i;
        ttr->status = RUN_CHECK_FAILED;
        ttr->nominal_score = -1;
        ttr->score = -1;
        XCALLOC(r->tt_cells[i], r->tt_column_count);
        for (j = 0; j < r->tt_column_count; ++j) {
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

  for (t2 = t->first_down; t2; t2 = t2->right) {
    switch (t2->tag) {
    case TR_T_COMMENT:
      if (xml_leaf_elem(t2, &r->comment, 1, 1) < 0) return -1;
      break;
    case TR_T_VALUER_COMMENT:
      if (xml_leaf_elem(t2, &r->valuer_comment, 1, 1) < 0) return -1;
      break;
    case TR_T_VALUER_JUDGE_COMMENT:
      if (xml_leaf_elem(t2, &r->valuer_judge_comment, 1, 1) < 0) return -1;
      break;
    case TR_T_VALUER_ERRORS:
      if (xml_leaf_elem(t2, &r->valuer_errors, 1, 1) < 0) return -1;
      break;
    case TR_T_HOST:
      if (xml_leaf_elem(t2, &r->host, 1, 1) < 0) return -1;
      break;
    case TR_T_ERRORS:
      if (xml_leaf_elem(t2, &r->errors, 1, 1) < 0) return -1;
      break;
    case TR_T_TESTS:
      if (was_tests) {
        xml_err(t2, "duplicated element <tests>");
        return -1;
      }
      was_tests = 1;
      if (parse_tests(t2, r) < 0) return -1;
      break;
    case TR_T_TTROWS:
      if (was_ttrows) {
        xml_err(t2, "duplicated element <ttrows>");
        return -1;
      }
      was_ttrows = 1;
      if (parse_ttrows(t2, r) < 0) return -1;
      break;
    case TR_T_TTCELLS:
      if (was_ttcells) {
        xml_err(t2, "duplicated element <ttcells>");
        return -1;
      }
      was_ttcells = 1;
      if (parse_ttcells(t2, r) < 0) return -1;
      break;
    default:
      xml_err_elem_not_allowed(t2);
      return -1;
    }
  }
  return 0;
}

testing_report_xml_t
testing_report_parse_xml(const unsigned char *str)
{
  struct xml_tree *t = 0;
  testing_report_xml_t r = 0;

  t = xml_build_tree_str(str, &testing_report_parse_spec);
  if (!t) goto failure;

  xml_err_path = "<string>";
  xml_err_spec = &testing_report_parse_spec;

  XCALLOC(r, 1);
  if (parse_testing_report(t, r) < 0) goto failure;
  xml_tree_free(t, &testing_report_parse_spec);
  return r;

 failure:
  testing_report_free(r);
  if (t) xml_tree_free(t, &testing_report_parse_spec);
  return 0;
}

static struct testing_report_test *
testing_report_test_free(struct testing_report_test *p)
{
  if (!p) return 0;

  xfree(p->comment); p->comment = 0;
  xfree(p->team_comment); p->comment = 0;
  xfree(p->checker_comment); p->checker_comment = 0;
  xfree(p->exit_comment); p->exit_comment = 0;

  xfree(p->args); p->args = 0;
  xfree(p->input); p->input = 0;
  xfree(p->output); p->output = 0;
  xfree(p->correct); p->correct = 0;
  xfree(p->error); p->error = 0;
  xfree(p->checker); p->checker = 0;

  xfree(p);
  return 0;
}

testing_report_xml_t
testing_report_free(testing_report_xml_t r)
{
  int i, j;

  if (!r) return 0;

  if (r->tests) {
    for (i = 0; i < r->run_tests; i++) {
      r->tests[i] = testing_report_test_free(r->tests[i]);
    }
    xfree(r->tests);
    r->run_tests = 0;
  }
  xfree(r->comment); r->comment = 0;
  xfree(r->valuer_comment); r->valuer_comment = 0;
  xfree(r->valuer_judge_comment); r->valuer_judge_comment = 0;
  xfree(r->valuer_errors); r->valuer_errors = 0;
  xfree(r->host); r->host = 0;
  xfree(r->errors); r->errors = 0;

  if (r->tt_rows) {
    for (i = 0; i < r->tt_row_count; ++i) {
      if (r->tt_rows[i]) {
        xfree(r->tt_rows[i]->name);
        xfree(r->tt_rows[i]);
      }
    }
    xfree(r->tt_rows); r->tt_rows = 0;
  }

  if (r->tt_cells) {
    for (i = 0; i < r->tt_row_count; ++i) {
      if (r->tt_cells[i]) {
        for (j = 0; j < r->tt_column_count; ++j) {
          if (r->tt_cells[i][j]) {
            // free the cell
            xfree(r->tt_cells[i][j]);
          }
        }
        xfree(r->tt_cells[i]);
      }
    }
    xfree(r->tt_cells); r->tt_cells = 0;
  }

  xfree(r);
  return 0;
}

testing_report_xml_t
testing_report_alloc(int run_id, int judge_id)
{
  testing_report_xml_t r = 0;
  XCALLOC(r, 1);
  r->run_id = run_id;
  r->judge_id = judge_id;
  r->status = RUN_CHECK_FAILED;
  r->scoring_system = -1;
  r->marked_flag = -1;
  return r;
}

static const char * const scoring_system_strs[] =
{
  [SCORE_ACM] "ACM",
  [SCORE_KIROV] "KIROV",
  [SCORE_OLYMPIAD] "OLYMPIAD",
  [SCORE_MOSCOW] "MOSCOW",
};
static const unsigned char *
unparse_scoring_system(unsigned char *buf, size_t size, int val)
{
  if (val >= SCORE_ACM && val < SCORE_TOTAL) return scoring_system_strs[val];
  snprintf(buf, size, "scoring_%d", val);
  return buf;
}

#define ARMOR(s)  html_armor_buf(&ab, s)

static void
unparse_bool_attr(FILE *out, int attr_index, int value)
{
  if (value > 0) {
    fprintf(out, " %s=\"%s\"", attr_map[attr_index], xml_unparse_bool(value));
  }
}
static void
unparse_bool_attr2(FILE *out, int attr_index, int value)
{
  if (value >= 0) {
    fprintf(out, " %s=\"%s\"", attr_map[attr_index], xml_unparse_bool(value));
  }
}
static void
unparse_string_elem(
        FILE *out,
        struct html_armor_buffer *pab,
        int elem_index,
        const unsigned char *value)
{
  if (value) {
    fprintf(out, "  <%s>%s</%s>\n", elem_map[elem_index],
            html_armor_buf(pab, value), elem_map[elem_index]);
  }
}
static void
unparse_string_attr(
        FILE *out,
        struct html_armor_buffer *pab,
        int attr_index,
        const unsigned char *value)
{
  if (value && value[0]) {
    fprintf(out, "  %s=\"%s\"", attr_map[attr_index],
            html_armor_buf(pab, value));
  }
}

static void
unparse_file_contents(
        FILE *out,
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        int elem_index,
        const unsigned char *str,
        int size)
{
  if (size >= 0) {
    fprintf(out, "      <%s>", elem_map[elem_index]);
    html_print_by_line(out, utf8_mode, max_file_length, max_line_length,
                       str, size);
    fprintf(out, "</%s>\n", elem_map[elem_index]);
  }
}

void
testing_report_unparse_xml(
        FILE *out,
        int utf8_mode,
        int max_file_length,
        int max_line_length,
        testing_report_xml_t r)
{
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char buf1[128], buf2[128];
  struct testing_report_test *t;
  int i, j;
  struct testing_report_row *ttr;
  struct testing_report_cell *ttc;
  const unsigned char *scoring = 0;

  run_status_to_str_short(buf1, sizeof(buf1), r->status);
  scoring = unparse_scoring_system(buf2, sizeof(buf2), r->scoring_system);

  fprintf(out, "<%s %s=\"%d\" %s=\"%d\" %s=\"%s\" %s=\"%s\" %s=\"%d\"",
          elem_map[TR_T_TESTING_REPORT],
          attr_map[TR_A_RUN_ID], r->run_id,
          attr_map[TR_A_JUDGE_ID], r->judge_id,
          attr_map[TR_A_STATUS], buf1,
          attr_map[TR_A_SCORING], scoring,
          attr_map[TR_A_RUN_TESTS], r->run_tests);

  unparse_bool_attr(out, TR_A_ARCHIVE_AVAILABLE, r->archive_available);
  unparse_bool_attr(out, TR_A_REAL_TIME_AVAILABLE, r->real_time_available);
  unparse_bool_attr(out, TR_A_MAX_MEMORY_USED_AVAILABLE,
                    r->max_memory_used_available);
  unparse_bool_attr(out, TR_A_CORRECT_AVAILABLE, r->correct_available);
  unparse_bool_attr(out, TR_A_INFO_AVAILABLE, r->info_available);
  if (r->variant > 0) {
    fprintf(out, " %s=\"%d\"", attr_map[TR_A_VARIANT], r->variant);
  }
  unparse_bool_attr(out, TR_A_ACCEPTING_MODE, r->accepting_mode);
  if (r->scoring_system == SCORE_OLYMPIAD && r->accepting_mode > 0
      && r->status != RUN_ACCEPTED) {
    if (r->failed_test > 0) {
      fprintf(out, " %s=\"%d\"", attr_map[TR_A_FAILED_TEST], r->failed_test);
    }
  } else if (r->scoring_system == SCORE_ACM && r->status != RUN_OK) {
    if (r->failed_test > 0) {
      fprintf(out, " %s=\"%d\"", attr_map[TR_A_FAILED_TEST], r->failed_test);
    }
  } else if (r->scoring_system == SCORE_OLYMPIAD && r->accepting_mode <= 0) {
    fprintf(out, " %s=\"%d\" %s=\"%d\" %s=\"%d\"",
            attr_map[TR_A_TESTS_PASSED], r->tests_passed,
            attr_map[TR_A_SCORE], r->score,
            attr_map[TR_A_MAX_SCORE], r->max_score);
  } else if (r->scoring_system == SCORE_KIROV) {
    fprintf(out, " %s=\"%d\" %s=\"%d\" %s=\"%d\"",
            attr_map[TR_A_TESTS_PASSED], r->tests_passed,
            attr_map[TR_A_SCORE], r->score,
            attr_map[TR_A_MAX_SCORE], r->max_score);
  } else if (r->scoring_system == SCORE_MOSCOW) {
    if (r->status != RUN_OK) {
      if (r->failed_test > 0) {
        fprintf(out, " %s=\"%d\"", attr_map[TR_A_FAILED_TEST], r->failed_test);
      }
    }
    fprintf(out, " %s=\"%d\" %s=\"%d\"",
            attr_map[TR_A_SCORE], r->score,
            attr_map[TR_A_MAX_SCORE], r->max_score);
  }

  if (r->time_limit_ms > 0) {
    fprintf(out, " %s=\"%d\"", attr_map[TR_A_TIME_LIMIT_MS], r->time_limit_ms);
  }
  if (r->real_time_limit_ms > 0) {
    fprintf(out, " %s=\"%d\"",
            attr_map[TR_A_REAL_TIME_LIMIT_MS], r->real_time_limit_ms);
  }
  unparse_bool_attr2(out, TR_A_MARKED_FLAG, r->marked_flag);
  unparse_bool_attr(out, TR_A_TESTS_MODE, r->tests_mode);
  if (r->tests_mode > 0 && r->tt_row_count > 0  && r->tt_column_count > 0) {
    fprintf(out, " %s=\"%d\"", attr_map[TR_A_TT_ROW_COUNT], r->tt_row_count);
    fprintf(out, " %s=\"%d\"", attr_map[TR_A_TT_COLUMN_COUNT],
            r->tt_column_count);
  }
  if (r->user_status >= 0) {
    run_status_to_str_short(buf1, sizeof(buf1), r->user_status);
    fprintf(out, " %s=\"%s\"", attr_map[TR_A_USER_STATUS], buf1);
  }
  if (r->user_tests_passed >= 0) {
    fprintf(out, " %s=\"%d\"", attr_map[TR_A_USER_TESTS_PASSED], r->user_tests_passed);
  }
  if (r->user_score >= 0) {
    fprintf(out, " %s=\"%d\"", attr_map[TR_A_USER_SCORE], r->user_score);
  }
  if (r->user_max_score >= 0) {
    fprintf(out, " %s=\"%d\"", attr_map[TR_A_USER_MAX_SCORE],
            r->user_max_score);
  }
  if (r->user_run_tests >= 0) {
    fprintf(out, " %s=\"%d\"", attr_map[TR_A_USER_RUN_TESTS],
            r->user_run_tests);
  }
  fprintf(out, " >\n");

  unparse_string_elem(out, &ab, TR_T_COMMENT, r->comment);
  unparse_string_elem(out, &ab, TR_T_VALUER_COMMENT, r->valuer_comment);
  unparse_string_elem(out, &ab, TR_T_VALUER_JUDGE_COMMENT,
                      r->valuer_judge_comment);
  unparse_string_elem(out, &ab, TR_T_VALUER_ERRORS, r->valuer_errors);
  unparse_string_elem(out, &ab, TR_T_HOST, r->host);
  unparse_string_elem(out, &ab, TR_T_ERRORS, r->errors);

  if (r->run_tests > 0 && r->tests) {
    fprintf(out, "  <%s>\n", elem_map[TR_T_TESTS]);
    for (i = 0; i < r->run_tests; ++i) {
      if (!(t = r->tests[i])) continue;

      run_status_to_str_short(buf1, sizeof(buf1), t->status);
      fprintf(out, "    <%s %s=\"%d\" %s=\"%s\"",
              elem_map[TR_T_TEST], attr_map[TR_A_NUM], i + 1,
              attr_map[TR_A_STATUS], buf1);
      if (t->term_signal > 0) {
        fprintf(out, " %s=\"%d\"", attr_map[TR_A_TERM_SIGNAL], t->term_signal);
      }
      if (t->exit_code > 0) {
        fprintf(out, " %s=\"%d\"", attr_map[TR_A_EXIT_CODE], t->exit_code);
      }
      if (t->time >= 0) {
        fprintf(out, " %s=\"%d\"", attr_map[TR_A_TIME], t->time);
      }
      if (r->real_time_available > 0 && t->real_time >= 0) {
        fprintf(out, " %s=\"%d\"", attr_map[TR_A_REAL_TIME], t->real_time);
      }
      if (r->max_memory_used_available > 0 && t->max_memory_used > 0) {
        fprintf(out, " %s=\"%d\"", attr_map[TR_A_MAX_MEMORY_USED],
                t->max_memory_used);
      }
      if (r->scoring_system == SCORE_OLYMPIAD && r->accepting_mode <= 0) {
        fprintf(out, " %s=\"%d\" %s=\"%d\"",
                attr_map[TR_A_NOMINAL_SCORE], t->nominal_score,
                attr_map[TR_A_SCORE], r->score);
      } else if (r->scoring_system == SCORE_KIROV) {
        fprintf(out, " %s=\"%d\" %s=\"%d\"",
                attr_map[TR_A_NOMINAL_SCORE], t->nominal_score,
                attr_map[TR_A_SCORE], r->score);
      }
      unparse_string_attr(out, &ab, TR_A_COMMENT, t->comment);
      unparse_string_attr(out, &ab, TR_A_TEAM_COMMENT, t->team_comment);
      unparse_string_attr(out, &ab, TR_A_EXIT_COMMENT, t->exit_comment);
      unparse_string_attr(out, &ab, TR_A_CHECKER_COMMENT, t->checker_comment);
      unparse_string_attr(out, &ab, TR_A_INPUT_DIGEST, t->input_digest);
      unparse_string_attr(out, &ab, TR_A_CORRECT_DIGEST, t->correct_digest);
      unparse_string_attr(out, &ab, TR_A_INFO_DIGEST, t->info_digest);
      unparse_bool_attr(out, TR_A_OUTPUT_AVAILABLE, t->output_available);
      unparse_bool_attr(out, TR_A_STDERR_AVAILABLE, t->stderr_available);
      unparse_bool_attr(out, TR_A_CHECKER_OUTPUT_AVAILABLE,
                        t->checker_output_available);
      unparse_bool_attr(out, TR_A_ARGS_TOO_LONG, t->args_too_long);
      if (t->visibility > 0) {
        fprintf(out, " %s=\"%d\"", attr_map[TR_A_VISIBILITY], t->visibility);
      }
      fprintf(out, " >\n");

      unparse_string_elem(out, &ab, TR_T_ARGS, t->args);

      unparse_file_contents(out, utf8_mode, max_file_length, max_line_length,
                            TR_T_INPUT, t->input, t->input_size);
      unparse_file_contents(out, utf8_mode, max_file_length, max_line_length,
                            TR_T_OUTPUT, t->output, t->output_size);
      unparse_file_contents(out, utf8_mode, max_file_length, max_line_length,
                            TR_T_CORRECT, t->correct, t->correct_size);
      unparse_file_contents(out, utf8_mode, max_file_length, max_line_length,
                            TR_T_STDERR, t->error, t->error_size);
      unparse_file_contents(out, utf8_mode, max_file_length, max_line_length,
                            TR_T_CHECKER, t->checker, t->checker_size);
      fprintf(out, "    </%s>\n", elem_map[TR_T_TEST]);
    }
    fprintf(out, "  </%s>\n", elem_map[TR_T_TESTS]);
  }

  if (r->tt_row_count > 0 && r->tt_rows) {
    fprintf(out, "  <%s>\n", elem_map[TR_T_TTROWS]);
    for (i = 0; i < r->tt_row_count; ++i) {
      run_status_to_str_short(buf1, sizeof(buf1), r->tt_rows[i]->status);
      if (!(ttr = r->tt_rows[i])) continue;
      fprintf(out, "    <%s %s=\"%d\" %s=\"%s\" %s=\"%s\" %s=\"%s\"",
              elem_map[TR_T_TTROW], attr_map[TR_A_ROW], ttr->row,
              attr_map[TR_A_NAME], ARMOR(ttr->name),
              attr_map[TR_A_MUST_FAIL], xml_unparse_bool(ttr->must_fail),
              attr_map[TR_A_STATUS], buf1);
      if (ttr->nominal_score >= 0) {
        fprintf(out, " %s=\"%d\"", attr_map[TR_A_NOMINAL_SCORE],
                ttr->nominal_score);
      }
      if (ttr->score >= 0) {
        fprintf(out, " %s=\"%d\"", attr_map[TR_A_SCORE], ttr->score);
      }
      fprintf(out, "/>\n");
    }
    fprintf(out, "  </%s>\n", elem_map[TR_T_TTROWS]);
  }

  if (r->tt_row_count > 0 && r->tt_column_count > 0 && r->tt_cells) {
    fprintf(out, "  <%s>\n", elem_map[TR_T_TTCELLS]);
    for (i = 0; i < r->tt_row_count; ++i) {
      if (!r->tt_cells[i]) continue;
      for (j = 0; j < r->tt_column_count; ++j) {
        if (!(ttc = r->tt_cells[i][j])) continue;
        run_status_to_str_short(buf1, sizeof(buf1), ttc->status);
        fprintf(out, "    <%s %s=\"%d\" %s=\"%d\" %s=\"%s\"",
                elem_map[TR_T_TTCELL], attr_map[TR_A_ROW], i,
                attr_map[TR_A_COLUMN], j,
                attr_map[TR_A_STATUS], buf1);
        if (ttc->time >= 0) {
          fprintf(out, " %s=\"%d\"", attr_map[TR_A_TIME], ttc->time);
        }
        if (ttc->real_time >= 0) {
          fprintf(out, " %s=\"%d\"", attr_map[TR_A_REAL_TIME], ttc->real_time);
        }
        fprintf (out, " />\n");
      }
    }
    fprintf(out, "  </%s>\n", elem_map[TR_T_TTCELLS]);
  }

  fprintf(out, "</%s>\n", elem_map[TR_T_TESTING_REPORT]);
  html_armor_free(&ab);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
