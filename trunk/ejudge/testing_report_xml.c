/* -*- c -*- */
/* $Id$ */

/* Copyright (C) 2005-2006 Alexander Chernov <cher@ispras.ru> */

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
#include "settings.h"

#include "testing_report_xml.h"
#include "expat_iface.h"
#include "xml_utils.h"
#include "protocol.h"
#include "runlog.h"
#include "digest_io.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>

#include <string.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

/*
<testing-report run-id="N" judge-id="N" status="O" scoring="R" archive-available="B" [correct-available="B"] [info-available="B"] run-tests="N" [variant="N"] [accepting-mode="B"] [failed-test="N"] [tests-passed="N"] [score="N"]>
  <comment>T</comment>
  <tests>
    <test num="N" status="O" [exit-code="N"] [term-signal="N"] time="N" real-time="N" [nominal-score="N" score="N"] [comment="S"] [team-comment="S"] [checker-comment="S"] output-available="B" stderr-available="B" checker-output-available="B" args-too-long="B" [input-digest="X"] [correct-digest="X"]>
       [<args>T</args>]
       [<input>T</input>]
       [<output>T</output>]
       [<correct>T</correct>]
       [<stderr>T</stderr>]
       [<checker>T</checker>]
    </test>
  </tests>
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

  [TR_A_LAST_ATTR] = 0,
};
static const size_t elem_sizes[TR_T_LAST_TAG];
static const size_t attr_sizes[TR_A_LAST_ATTR];

static void *
elem_alloc(int tag)
{
  size_t sz;
  ASSERT(tag >= 1 && tag < TR_T_LAST_TAG);
  if (!(sz = elem_sizes[tag])) sz = sizeof(struct xml_tree);
  return xcalloc(1, sz);
}
static void *
attr_alloc(int tag)
{
  size_t sz;

  ASSERT(tag >= 1 && tag < TR_A_LAST_ATTR);
  if (!(sz = attr_sizes[tag])) sz = sizeof(struct xml_attr);
  return xcalloc(1, sz);
}
static void
elem_free(struct xml_tree *t)
{
}
static void
attr_free(struct xml_attr *a)
{
}

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
    case TR_A_EXIT_CODE:
      if (xml_attr_int(a, &x) < 0) goto failure;
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
      if (x < 0 || x > 100000) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->nominal_score = x;
      break;
    case TR_A_SCORE:
      if (xml_attr_int(a, &x) < 0) goto failure;
      if (x < 0 || x > 100000) {
        xml_err_attr_invalid(a);
        goto failure;
      }
      p->score = x;
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
parse_testing_report(struct xml_tree *t, testing_report_xml_t r)
{
  struct xml_attr *a;
  int x, was_tests = 0;
  struct xml_attr *a_failed_test = 0, *a_tests_passed = 0, *a_score = 0;
  struct xml_attr *a_max_score = 0;
  struct xml_tree *t2;

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

  for (a = t->first; a; a = a->next) {
    switch (a->tag) {
    case TR_A_RUN_ID:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > 999999) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->run_id = x;
      break;

    case TR_A_JUDGE_ID:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > 65535) {
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

    case TR_A_RUN_TESTS:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > 255) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->run_tests = x;
      break;

    case TR_A_VARIANT:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > 127) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->variant = x;
      break;

    case TR_A_ACCEPTING_MODE:
      if (xml_attr_bool(a, &x) < 0) return -1;
      r->accepting_mode = x;
      break;

    case TR_A_FAILED_TEST:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x <= 0 || x > 255) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->failed_test = x;
      a_failed_test = a;
      break;

    case TR_A_TESTS_PASSED:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > 255) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->tests_passed = x;
      a_tests_passed = a;
      break;

    case TR_A_SCORE:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > 100000) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->score = x;
      a_score = a;
      break;

    case TR_A_MAX_SCORE:
      if (xml_attr_int(a, &x) < 0) return -1;
      if (x < 0 || x > 100000) {
        xml_err_attr_invalid(a);
        return -1;
      }
      r->max_score = x;
      a_max_score = a;
      break;

    default:
      xml_err_attr_not_allowed(t, a);
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
    if (r->failed_test < 0) {
      xml_err_attr_undefined(t, TR_A_FAILED_TEST);
      return -1;
    }
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

  for (t2 = t->first_down; t2; t2 = t2->right) {
    switch (t2->tag) {
    case TR_T_COMMENT:
      if (xml_leaf_elem(t2, &r->comment, 1, 1) < 0) return -1;
      break;
    case TR_T_TESTS:
      if (was_tests) {
        xml_err(t2, "duplicated element <tests>");
        return -1;
      }
      was_tests = 1;
      if (parse_tests(t2, r) < 0) return -1;
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

  t = xml_build_tree_str(str, elem_map, attr_map, elem_alloc, attr_alloc);
  if (!t) goto failure;

  xml_err_path = "<string>";
  xml_err_elem_names = elem_map;
  xml_err_attr_names = attr_map;

  XCALLOC(r, 1);
  if (parse_testing_report(t, r) < 0) goto failure;
  xml_tree_free(t, elem_free, attr_free);
  return r;

 failure:
  testing_report_free(r);
  if (t) xml_tree_free(t, elem_free, attr_free);
  return 0;
}

static struct testing_report_test *
testing_report_test_free(struct testing_report_test *p)
{
  if (!p) return 0;

  xfree(p->comment); p->comment = 0;
  xfree(p->team_comment); p->comment = 0;
  xfree(p->checker_comment); p->checker_comment = 0;

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
  int i;

  if (!r) return 0;

  if (r->tests) {
    for (i = 0; i < r->run_tests; i++) {
      r->tests[i] = testing_report_test_free(r->tests[i]);
    }
    xfree(r->tests);
    r->run_tests = 0;
  }
  xfree(r->comment); r->comment = 0;

  xfree(r);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */
