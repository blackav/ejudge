/* -*- mode: c -*- */

/* Copyright (C) 2000-2022 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_limits.h"
#include "ejudge/html.h"
#include "ejudge/misctext.h"
#include "ejudge/mischtml.h"
#include "ejudge/pathutl.h"
#include "ejudge/errlog.h"
#include "ejudge/fileutl.h"
#include "ejudge/runlog.h"
#include "ejudge/clarlog.h"
#include "ejudge/teamdb.h"
#include "ejudge/prepare.h"
#include "ejudge/base64.h"
#include "ejudge/sformat.h"
#include "ejudge/protocol.h"
#include "ejudge/copyright.h"
#include "ejudge/archive_paths.h"
#include "ejudge/team_extra.h"
#include "ejudge/xml_utils.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/serve_state.h"
#include "ejudge/charsets.h"
#include "ejudge/compat.h"
#include "ejudge/filter_eval.h"
#include "ejudge/xuser_plugin.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJ_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

#define ARMOR(s)  html_armor_buf(&ab, s)

FILE *
sf_fopen(char const *path, char const *flags)
{
  FILE *f = fopen(path, flags);
  if (f) return f;
  err("fopen(\"%s\",\"%s\") failed: %s", path, flags, os_ErrorMsg());
  return NULL;
}

/* format: 0 - HTML, 1 - plain text */
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
        time_t effective_time)
{
  int score, init_score, dpi, score_mult = 1, score_bonus = 0;
  int status, dp = 0;
  time_t base_time = 0;
  struct penalty_info *pi = NULL;

  ASSERT(pe);
  ASSERT(pr);
  ASSERT(attempts >= 0);

  if (separate_user_score > 0 && user_mode > 0 && pe->is_saved && !(token_flags & TOKEN_FINALSCORE_BIT)) {
    status = pe->saved_status;
    if (status == RUN_PENDING_REVIEW || status == RUN_SUMMONED) status = RUN_OK;
    init_score = pe->saved_score;
    if (status == RUN_OK && !pr->variable_full_score) {
      if (pr->full_user_score >= 0) init_score = pr->full_user_score;
      else init_score = pr->full_user_score;
    }
  } else {
    status = pe->status;
    if (status == RUN_PENDING_REVIEW || status == RUN_SUMMONED) status = RUN_OK;
    init_score = pe->score;
    if (status == RUN_OK && !pr->variable_full_score)
      init_score = pr->full_score;
  }
  if (pr->score_multiplier > 1) score_mult = pr->score_multiplier;

  // get date_penalty
  if (pr->dp_total > 0) {
    if (pr->start_date > 0) {
      base_time = pr->start_date;
    } else if (start_time > 0) {
      base_time = start_time;
    }
    if (effective_time <= 0) effective_time = pe->time;
    for (dpi = 0; dpi < pr->dp_total; dpi++)
      if (effective_time < pr->dp_infos[dpi].date)
        break;
    if (dpi < pr->dp_total) {
      if (dpi > 0) {
        base_time = pr->dp_infos[dpi - 1].date;
      }
      pi = &pr->dp_infos[dpi];
    }
  }

  // count the bonus depending on the number of previous successes
  if (status == RUN_OK && pr->score_bonus_total > 0) {
    if (prev_successes >= 0 && prev_successes < pr->score_bonus_total)
      score_bonus = pr->score_bonus_val[prev_successes];
  }

  // score_mult is applied to the initial score
  // run_penalty is subtracted, but date_penalty is added

  if (base_time > 0 && pi) {
    dp = pi->penalty;
    if (pi->scale > 0) {
      time_t offset = effective_time - base_time;
      if (offset < 0) offset = 0;
      dp += pi->decay * (offset / pi->scale);
    }
  }
  if (p_date_penalty) *p_date_penalty = dp;
  //score = init_score * score_mult - attempts * pr->run_penalty + dp + pe->score_adj - disq_attempts * pr->disqualified_penalty + score_bonus;
  //if (score > pr->full_score) score = pr->full_score;
  // solution score is the initial score minus all score penalties plus score_bonus
  if (status != RUN_OK && pr->run_penalty < 0) {
    score = init_score * score_mult + pe->score_adj + score_bonus;
  } else {
    score = init_score * score_mult - attempts * pr->run_penalty + pe->score_adj + score_bonus;
  }
  if (pr->compile_error_penalty < -1) {
    fprintf(stderr, "COMPILE_PENALTY: %d\n", pr->compile_error_penalty);
  }
  if (pr->compile_error_penalty > 0 || pr->compile_error_penalty < -1) {
    if (pr->compile_error_penalty > 0 || status == RUN_OK) {
      score -= ce_attempts * pr->compile_error_penalty;
    }
  }
  if (status == RUN_OK && pr->min_score_1 > 0 && score < pr->min_score_1) score = pr->min_score_1;
  score += dp;
  if (status == RUN_OK && pr->min_score_2 > 0 && score < pr->min_score_2) score = pr->min_score_2;
  score -= disq_attempts * pr->disqualified_penalty;
  if (score < 0) score = 0;

  if (!outbuf) return score;

  if (pr && pr->score_view && pr->score_view[0]) {
    score_view_display(outbuf, outsize, pr, score);
    return score;
  }

  {
    unsigned char init_score_str[64];
    unsigned char run_penalty_str[64];
    unsigned char ce_penalty_str[64];
    unsigned char date_penalty_str[64];
    unsigned char final_score_str[64];
    unsigned char score_adj_str[64];
    unsigned char disq_penalty_str[64];
    unsigned char score_bonus_str[64];

    if (score_mult > 1) {
      snprintf(init_score_str, sizeof(init_score_str),
               "%d*%d", init_score, score_mult);
    } else {
      snprintf(init_score_str, sizeof(init_score_str), "%d", init_score);
    }

    if (attempts > 0 && (pr->run_penalty > 0 || pr->run_penalty < -1)) {
      snprintf(run_penalty_str, sizeof(run_penalty_str),
               "-%d*%d", attempts, pr->run_penalty);
    } else {
      run_penalty_str[0] = 0;
    }

    if (ce_attempts > 0 && (pr->compile_error_penalty > 0 || pr->compile_error_penalty < -1)) {
      snprintf(ce_penalty_str, sizeof(ce_penalty_str),
               "-%d*%d", ce_attempts, pr->compile_error_penalty);
    } else {
      ce_penalty_str[0] = 0;
    }

    if (dp != 0) {
      snprintf(date_penalty_str, sizeof(date_penalty_str), "%+d", dp);
    } else {
      date_penalty_str[0] = 0;
    }

    if (pe->score_adj != 0) {
      snprintf(score_adj_str, sizeof(score_adj_str), "%+d", pe->score_adj);
    } else {
      score_adj_str[0] = 0;
    }

    if (disq_attempts > 0 && pr->disqualified_penalty > 0) {
      snprintf(disq_penalty_str, sizeof(disq_penalty_str),
               "-%d*%d", disq_attempts, pr->disqualified_penalty);
    } else {
      disq_penalty_str[0] = 0;
    }

    if (score_bonus > 0) {
      snprintf(score_bonus_str, sizeof(score_bonus_str), "%+d", score_bonus);
    } else {
      score_bonus_str[0] = 0;
    }

    if (score_mult > 1 || run_penalty_str[0] || ce_penalty_str[0] || date_penalty_str[0]
        || score_adj_str[0] || disq_penalty_str[0] || score_bonus_str[0]) {
      if (format == 0) {
        snprintf(final_score_str, sizeof(final_score_str),
                 "<b>%d</b>=", score);
      } else {
        snprintf(final_score_str, sizeof(final_score_str), "%d=", score);
      }
    } else {
      init_score_str[0] = 0;
      if (format == 0) {
        snprintf(final_score_str, sizeof(final_score_str),
                 "<b>%d</b>", score);
      } else {
        snprintf(final_score_str, sizeof(final_score_str), "%d", score);
      }
    }

    snprintf(outbuf, outsize, "%s%s%s%s%s%s%s%s",
             final_score_str,
             init_score_str, run_penalty_str, ce_penalty_str, date_penalty_str, score_adj_str,
             disq_penalty_str, score_bonus_str);
    return score;
  }
}

void
write_json_run_status(
        const serve_state_t state,
        FILE *f,
        time_t start_time,
        const struct run_entry *pe,
        int priv_level,
        int attempts,
        int disq_attempts,
        int ce_attempts,
        int prev_successes,
        int disable_failed,
        int run_fields,
        time_t effective_time,
        const unsigned char *indent)
{
  const struct section_global_data *global = state->global;
  struct section_problem_data *prob = NULL;

  if (!indent) indent = "";

  int status, score, test;
  int separate_user_score = global->separate_user_score > 0 && state->online_view_judge_score <= 0;
  if (separate_user_score > 0 && pe->is_saved && priv_level <= 0) {
    if (pe->token_count > 0 && (pe->token_flags & TOKEN_FINALSCORE_BIT)) {
      status = pe->status;
      score = pe->score;
      test = pe->test;
    } else {
      status = pe->saved_status;
      score = pe->saved_score;
      test = pe->saved_test;
    }
  } else {
    status = pe->status;
    score = pe->score;
    test = pe->test;
  }

  if (pe->prob_id > 0 && pe->prob_id <= state->max_prob && state->probs) {
    prob = state->probs[pe->prob_id];
  }
  if (status >= RUN_PSEUDO_FIRST && status <= RUN_PSEUDO_LAST) {
    return;
  }
  if (!run_is_normal_status(status)) {
    return;
  }
  switch (status) {
  case RUN_CHECK_FAILED:
    if (!priv_level) return;
    break;
  case RUN_OK:
    if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD) break;
    return;
  case RUN_IGNORED:
  case RUN_DISQUALIFIED:
  case RUN_PENDING:
  case RUN_COMPILE_ERR:
  case RUN_STYLE_ERR:
  case RUN_REJECTED:
    return;
  }

  if (global->score_system == SCORE_ACM) {
    if (run_fields & (1 << RUN_VIEW_TEST)) {
      if (pe->passed_mode > 0) {
        ++test;
      }
      if (priv_level > 0) {
        fprintf(f, ",\n%s\"raw_test\": %d", indent, pe->test);
        fprintf(f, ",\n%s\"passed_mode\": %d", indent, pe->passed_mode);
        fprintf(f, ",\n%s\"failed_test\": %d", indent, test);
      } else if (!disable_failed) {
        if (status != RUN_OK && status != RUN_ACCEPTED && status != RUN_PENDING_REVIEW && status != RUN_SUMMONED && test > 0 && global->disable_failed_test_view <= 0) {
          fprintf(f, ",\n%s\"failed_test\": %d", indent, test);
        }
      }
    }
    return;
  }
  if (global->score_system == SCORE_MOSCOW) {
    if (run_fields & (1 << RUN_VIEW_TEST)) {
      if (pe->passed_mode > 0) {
        ++test;
      }
      if (priv_level > 0) {
        fprintf(f, ",\n%s\"raw_test\": %d", indent, pe->test);
        fprintf(f, ",\n%s\"passed_mode\": %d", indent, pe->passed_mode);
        fprintf(f, ",\n%s\"failed_test\": %d", indent, test);
      } else if (!disable_failed) {
        if (status != RUN_OK && status != RUN_ACCEPTED && status != RUN_PENDING_REVIEW && status != RUN_SUMMONED && test > 0 && global->disable_failed_test_view <= 0) {
          fprintf(f, ",\n%s\"failed_test\": %d", indent, test);
        }
      }
    }
    if (run_fields & (1 << RUN_VIEW_SCORE)) {
      if (priv_level > 0) {
        fprintf(f, ",\n%s\"raw_score\": %d", indent, pe->score);
      }
      fprintf(f, ",\n%s\"score\": %d", indent, score);
    }
    return;
  }
  if (global->score_system == SCORE_OLYMPIAD) {
    if (run_fields & (1 << RUN_VIEW_TEST)) {
      if (pe->passed_mode > 0) {
        if (priv_level > 0) {
          fprintf(f, ",\n%s\"raw_test\": %d", indent, pe->test);
          fprintf(f, ",\n%s\"passed_mode\": %d", indent, pe->passed_mode);
          fprintf(f, ",\n%s\"tests_passed\": %d", indent, test);
        } else {
          fprintf(f, ",\n%s\"tests_passed\": %d", indent, test);
        }
      } else {
        if (priv_level > 0) {
          fprintf(f, ",\n%s\"raw_test\": %d", indent, pe->test);
          fprintf(f, ",\n%s\"passed_mode\": %d", indent, pe->passed_mode);
        }
        if (status == RUN_RUN_TIME_ERR
            || status == RUN_TIME_LIMIT_ERR
            || status == RUN_PRESENTATION_ERR
            || status == RUN_WRONG_ANSWER_ERR
            || status == RUN_MEM_LIMIT_ERR
            || status == RUN_SECURITY_ERR
            || status == RUN_SYNC_ERR
            || status == RUN_WALL_TIME_LIMIT_ERR) {
          if (test > 0) {
            fprintf(f, ",\n%s\"failed_test\": %d", indent, test);
          }
        } else {
          if (test > 0) {
            fprintf(f, ",\n%s\"tests_passed\": %d", indent, test - 1);
          }
        }
      }
    }
    if (run_fields & (1 << RUN_VIEW_SCORE)) {
      if (priv_level > 0) {
        fprintf(f, ",\n%s\"raw_score\": %d", indent, pe->score);
      }
      if (score >= 0 && prob) {
        unsigned char score_str[128];
        int final_score = calc_kirov_score(score_str, sizeof(score_str),
                                           start_time, separate_user_score, !priv_level, pe->token_flags,
                                           pe, prob, attempts, disq_attempts, ce_attempts, prev_successes,
                                           NULL, 1, effective_time);
        fprintf(f, ",\n%s\"score\": %d", indent, final_score);
        fprintf(f, ",\n%s\"score_str\": \"%s\"", indent, score_str);
      }
    }
    return;
  }
  if (global->score_system == SCORE_KIROV) {
    if (run_fields & (1 << RUN_VIEW_TEST)) {
      if (priv_level > 0) {
        fprintf(f, ",\n%s\"raw_test\": %d", indent, pe->test);
        fprintf(f, ",\n%s\"passed_mode\": %d", indent, pe->passed_mode);
      }
      if (pe->passed_mode > 0) {
        if (test >= 0) {
          fprintf(f, ",\n%s\"tests_passed\": %d", indent, test);
        }
      } else {
        if (test > 0) {
          fprintf(f, ",\n%s\"tests_passed\": %d", indent, test - 1);
        }
      }
    }

    if (run_fields & (1 << RUN_VIEW_SCORE)) {
      if (priv_level > 0) {
        fprintf(f, ",\n%s\"raw_score\": %d", indent, pe->score);
      }
      if (score >= 0 && prob) {
        unsigned char score_str[128];
        int final_score = calc_kirov_score(score_str, sizeof(score_str),
                                           start_time, separate_user_score, !priv_level, pe->token_flags,
                                           pe, prob, attempts, disq_attempts, ce_attempts, prev_successes,
                                           NULL, 1, effective_time);
        fprintf(f, ",\n%s\"score\": %d", indent, final_score);
        fprintf(f, ",\n%s\"score_str\": \"%s\"", indent, score_str);
      }
    }
  }
}

void
write_html_run_status(
        const serve_state_t state,
        FILE *f,
        time_t start_time,
        const struct run_entry *pe,
        int user_mode, /* works for separate_user_score */
        int priv_level,
        int attempts,
        int disq_attempts,
        int ce_attempts,
        int prev_successes,
        const unsigned char *td_class,
        int disable_failed,
        int enable_js_status_menu,
        int run_fields,
        time_t effective_time)
{
  const struct section_global_data *global = state->global;
  unsigned char status_str[128], score_str[128];
  struct section_problem_data *pr = 0;
  int need_extra_col = 0;
  unsigned char cl[128] = { 0 };
  int status, score, test;
  int separate_user_score = 0;

  if (td_class && *td_class) {
    snprintf(cl, sizeof(cl), " class=\"%s\"", td_class);
  }

  separate_user_score = global->separate_user_score > 0 && state->online_view_judge_score <= 0;
  if (separate_user_score > 0 && pe->is_saved && user_mode) {
    if (pe->token_count > 0 && (pe->token_flags & TOKEN_FINALSCORE_BIT)) {
      status = pe->status;
      score = pe->score;
      test = pe->test;
    } else {
      status = pe->saved_status;
      score = pe->saved_score;
      test = pe->saved_test;
    }
  } else {
    status = pe->status;
    score = pe->score;
    test = pe->test;
  }

  if (pe->prob_id > 0 && pe->prob_id <= state->max_prob && state->probs)
    pr = state->probs[pe->prob_id];
  run_status_str(status, status_str, sizeof(status_str),
                 pr?pr->type:0, pr?pr->scoring_checker:0);
  if (run_fields & (1 << RUN_VIEW_STATUS)) {
    if (enable_js_status_menu) {
      fprintf(f, "<td%s><a href=\"javascript:ej_stat(%d)\">%s</a><div class=\"ej_dd\" id=\"ej_dd_%d\"></div></td>", cl, pe->run_id, status_str, pe->run_id);
    } else {
      fprintf(f, "<td%s>%s</td>", cl, status_str);
    }
  }

  if (global->score_system == SCORE_KIROV
      || global->score_system == SCORE_OLYMPIAD
      || global->score_system == SCORE_MOSCOW)
    need_extra_col = 1;

  if (status >= RUN_PSEUDO_FIRST && status <= RUN_PSEUDO_LAST) {
    if (run_fields & (1 << RUN_VIEW_TEST)) {
        fprintf(f, "<td%s>&nbsp;</td>", cl);
      }
    if (need_extra_col && run_fields & (1 << RUN_VIEW_SCORE)) {
      fprintf(f, "<td%s>&nbsp;</td>", cl);
    }
    return;
  } else if (!run_is_normal_status(status)) {
    if (run_fields & (1 << RUN_VIEW_TEST)) {
      fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
    }
    if (need_extra_col && run_fields & (1 << RUN_VIEW_SCORE)) {
      fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
    }
    return;
  }

  switch (status) {
  case RUN_CHECK_FAILED:
    if (priv_level > 0) break;
    goto dona;
  case RUN_OK:
    if (global->score_system == SCORE_KIROV
        || global->score_system == SCORE_OLYMPIAD) break;
    goto dona;
    //case RUN_ACCEPTED:
    //case RUN_PENDING_REVIEW:
    //case RUN_SUMMONED:
  case RUN_IGNORED:
  case RUN_DISQUALIFIED:
  case RUN_PENDING:
  case RUN_COMPILE_ERR:
  case RUN_STYLE_ERR:
  case RUN_REJECTED:
  dona:
    if (run_fields & (1 << RUN_VIEW_TEST)) {
      fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
    }
    if (need_extra_col && run_fields & (1 << RUN_VIEW_SCORE)) {
      fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
    }
    return;
  }

  if (global->score_system == SCORE_ACM) {
    if (run_fields & (1 << RUN_VIEW_TEST)) {
      if (pe->passed_mode > 0) {
        // if passed_mode is set, in 'test' the number of ok tests is stored
        // add +1 for compatibility, until the legend is updated
        ++test;
      }
      if (!disable_failed) {
        if (status == RUN_OK || status == RUN_ACCEPTED || status == RUN_PENDING_REVIEW || status == RUN_SUMMONED || test <= 0
            || global->disable_failed_test_view > 0) {
          fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
        } else {
          fprintf(f, "<td%s>%d</td>", cl, test);
        }
      } else {
        fprintf(f, "<td%s>&nbsp;</td>", cl);
      }
    }
    return;
  }

  if (global->score_system == SCORE_MOSCOW) {
    if (run_fields & (1 << RUN_VIEW_TEST)) {
      if (pe->passed_mode > 0) {
        // if passed_mode is set, in 'test' the number of ok tests is stored
        // add +1 for compatibility, until the legend is updated
        ++test;
      }
      if (status == RUN_OK || status == RUN_ACCEPTED || status == RUN_PENDING_REVIEW || status == RUN_SUMMONED || test <= 0
          || global->disable_failed_test_view > 0) {
        fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
      } else {
        fprintf(f, "<td%s>%d</td>", cl, test);
      }
    }
    if (run_fields & (1 << RUN_VIEW_SCORE)) {
      if (status == RUN_OK) {
        fprintf(f, "<td%s><b>%d</b></td>", cl, score);
      } else {
        fprintf(f, "<td%s>%d</td>", cl, score);
      }
    }
    return;
  }

  if (run_fields & (1 << RUN_VIEW_TEST)) {
    if (global->score_system == SCORE_OLYMPIAD) {
      if (pe->passed_mode > 0) {
        // always report the count of passed tests
        if (test < 0) {
          fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
        } else {
          fprintf(f, "<td%s>%d</td>", cl, test);
        }
      } else {
        // we have to guess what to report: the count of passed tests
        // or the number of the first failed test...
        if (status == RUN_RUN_TIME_ERR
            || status == RUN_TIME_LIMIT_ERR
            || status == RUN_PRESENTATION_ERR
            || status == RUN_WRONG_ANSWER_ERR
            || status == RUN_MEM_LIMIT_ERR
            || status == RUN_SECURITY_ERR
            || status == RUN_SYNC_ERR
            || status == RUN_WALL_TIME_LIMIT_ERR) {
          // do like ACM
          if (test <= 0) {
            fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
          } else {
            fprintf(f, "<td%s><i>%d</i></td>", cl, test);
          }
        } else {
          if (test <= 0) {
            fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
          } else {
            fprintf(f, "<td%s>%d</td>", cl, test - 1);
          }
        }
      }
    } else {
      if (pe->passed_mode > 0) {
        if (test < 0) {
          fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
        } else {
          fprintf(f, "<td%s>%d</td>", cl, test);
        }
      } else {
        if (test <= 0) {
          fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
        } else {
          fprintf(f, "<td%s>%d</td>", cl, test - 1);
        }
      }
    }
  }

  if (run_fields & (1 << RUN_VIEW_SCORE)) {
    if (score < 0 || !pr) {
      fprintf(f, "<td%s>%s</td>", cl, _("N/A"));
    } else {
      calc_kirov_score(score_str, sizeof(score_str),
                       start_time, separate_user_score, user_mode, pe->token_flags,
                       pe, pr, attempts,
                       disq_attempts, ce_attempts, prev_successes, 0, 0, effective_time);
      fprintf(f, "<td%s>%s</td>", cl, score_str);
    }
  }
}

void
write_text_run_status(
        const serve_state_t state,
        FILE *f,
        time_t start_time,
        struct run_entry *pe,
        int user_mode,
        int priv_level,
        int attempts,
        int disq_attempts,
        int ce_attempts,
        int prev_successes,
        time_t effective_time)
{
  const struct section_global_data *global = state->global;
  unsigned char status_str[64], score_str[64];
  struct section_problem_data *pr = 0;
  int status, score, test;
  int separate_user_score = 0;

  separate_user_score = global->separate_user_score > 0 && state->online_view_judge_score <= 0;
  if (separate_user_score > 0 && user_mode && pe->is_saved) {
    status = pe->saved_status;
    score = pe->saved_score;
    test = pe->saved_test;
  } else {
    status = pe->status;
    score = pe->score;
    test = pe->test;
  }

  if (pe->prob_id > 0 && pe->prob_id <= state->max_prob && state->probs)
    pr = state->probs[pe->prob_id];
  run_status_to_str_short(status_str, sizeof(status_str), status);
  fprintf(f, "%s;", status_str);

  if (status >= RUN_PSEUDO_FIRST && status <= RUN_PSEUDO_LAST) {
    return;
  } else if (!run_is_normal_status(status)) {
    return;
  }

  switch (status) {
  case RUN_CHECK_FAILED:
    if (priv_level > 0) break;
  case RUN_ACCEPTED:
  case RUN_PENDING_REVIEW:
  case RUN_SUMMONED:
  case RUN_IGNORED:
  case RUN_DISQUALIFIED:
  case RUN_PENDING:
  case RUN_COMPILE_ERR:
  case RUN_STYLE_ERR:
  case RUN_REJECTED:
    return;
  }

  if (global->score_system == SCORE_ACM) {
    if (pe->passed_mode > 0) {
      ++test;
    }
    if (status == RUN_OK || status == RUN_ACCEPTED || status == RUN_PENDING_REVIEW || status == RUN_SUMMONED || test <= 0
        || global->disable_failed_test_view > 0) {
      fprintf(f, ";");
    } else {
      fprintf(f, "%d;", test);
    }
    return;
  }

  if (global->score_system == SCORE_MOSCOW) {
    if (pe->passed_mode > 0) {
      ++test;
    }
    if (status == RUN_OK || status == RUN_ACCEPTED || status == RUN_PENDING_REVIEW || status == RUN_SUMMONED || test <= 0
        || global->disable_failed_test_view > 0) {
      fprintf(f, ";");
    } else {
      fprintf(f, "%d;", test);
    }
    if (status == RUN_OK) {
      fprintf(f, "%d;", score);
    } else {
      fprintf(f, "%d;", score);
    }
    return;
  }

  if (pe->passed_mode > 0) {
    if (test < 0) {
      fprintf(f, ";");
    } else {
      fprintf(f, "%d;", test);
    }
  } else {
    if (test <= 0) {
      fprintf(f, ";");
    } else {
      fprintf(f, "%d;", test - 1);
    }
  }

  if (score < 0 || !pr) {
    fprintf(f, ";");
  } else {
    calc_kirov_score(score_str, sizeof(score_str),
                     start_time, separate_user_score, user_mode, pe->token_flags,
                     pe, pr, attempts,
                     disq_attempts, ce_attempts, prev_successes, 0, 1, effective_time);
    fprintf(f, "%s;", score_str);
  }
}

static __attribute__((unused)) const unsigned char *
stand_get_name(serve_state_t state, int user_id)
{
  if (state->global->stand_use_login)
    return teamdb_get_login(state->teamdb_state, user_id);
  else
    return teamdb_get_name_2(state->teamdb_state, user_id);
}

static void
process_template(FILE *out,
                 unsigned char const *template,
                 unsigned char const *content_type,
                 unsigned char const *charset,
                 unsigned char const *title,
                 unsigned char const *copyright)
{
  unsigned char const *s = template;

  while (*s) {
    if (*s != '%') {
      putc(*s++, out);
      continue;
    }
    switch (*++s) {
    case 'C':
      if (charset) fputs(charset, out);
      break;
    case 'T':
      if (content_type) fputs(content_type, out);
      break;
    case 'H':
      if (title) fputs(title, out);
      break;
    case 'R':
      if (copyright) fputs(copyright, out);
      break;
    default:
      putc('%', out);
      continue;
    }
    s++;
  }
}

void
write_standings_header(const serve_state_t state,
                       const struct contest_desc *cnts,
                       FILE *f, int client_flag,
                       int user_id,
                       unsigned char const *header_str,
                       unsigned char const *user_name)
{
  const struct section_global_data *global = state->global;
  time_t start_time, stop_time, cur_time;
  unsigned char header[1024];
  unsigned char dur_str[64];
  int show_astr_time;

  start_time = run_get_start_time(state->runlog_state);
  stop_time = run_get_stop_time(state->runlog_state, 0, 0);
  if (global->is_virtual && user_id > 0) {
    start_time = run_get_virtual_start_time(state->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(state->runlog_state, user_id, 0);
  }

  if (!start_time) {
    if (user_name) {
      if (global->name && global->name[0] && !client_flag) {
        sprintf(header, "%s - &quot;%s&quot; - %s",
                user_name, global->name, _("standings"));
      } else {
        sprintf(header, "%s - %s", user_name, _("Standings"));
      }
    } else {
      if (global->name && global->name[0] && !client_flag) {
        sprintf(header, "%s &quot;%s&quot; - %s",
                _("Contest"), global->name, _("standings"));
      } else {
        sprintf(header, "%s", _("Standings"));
      }
    }

    if (!client_flag) {
      stand_write_header(f, header_str, global->charset, header);
    } else {
      fprintf(f, "<%s>%s</%s>\n", cnts->team_head_style,
              header, cnts->team_head_style);
    }
    return;
  }

  cur_time = time(0);
  if (start_time > cur_time) cur_time = start_time;
  if (stop_time && cur_time > stop_time) cur_time = stop_time;
  show_astr_time = global->show_astr_time;
  if (global->is_virtual && !user_id) {
    show_astr_time = 1;
    cur_time = time(0);
  }
  duration_str(show_astr_time, cur_time, start_time, dur_str, 0);

  if (user_name) {
    if (global->name && global->name[0] && !client_flag) {
      sprintf(header, "%s  - &quot;%s&quot; - %s [%s]",
              user_name, global->name, _("standings"), dur_str);
    } else {
      sprintf(header, "%s - %s [%s]",
              user_name, _("Standings"), dur_str);
    }
  } else {
    if (global->name && global->name[0] && !client_flag) {
      sprintf(header, "%s &quot;%s&quot; - %s [%s]",
              _("Contest"), global->name, _("standings"), dur_str);
    } else {
      sprintf(header, "%s [%s]", _("Standings"), dur_str);
    }
  }

  if (!client_flag) {
    stand_write_header(f, header_str, global->charset, header);
  } else {
    fprintf(f, "<%s>%s</%s>\n", cnts->team_head_style,
            header, cnts->team_head_style);
  }
}

void
stand_write_header(
        FILE *f,
        const unsigned char *header_str,
        const unsigned char *charset,
        const unsigned char *header)
{
  if (!header) header = "";
  if (!charset) charset = EJUDGE_CHARSET;
  if (header_str) {
    process_template(f, header_str, 0, charset, header, 0);
  } else {
    fprintf(f, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"/><title>%s</title></head><body><h1>%s</h1>\n",
                charset,
                header, header);
  }
}

void
stand_write_footer(FILE *f, const unsigned char *footer_str)
{
  if (footer_str) {
    process_template(f, footer_str, 0, 0, 0, get_copyright(0));
  } else {
    fprintf(f, "</body></html>");
  }
}

static __attribute__((unused)) void
write_kirov_page_table(const struct standings_style *pss,
                       FILE *f, int total_pages, int current_page,
                       unsigned char **pgrefs,
                       int *u_sort, int *u_full, int *u_score,
                       int *pg_n1, int *pg_n2,
                       unsigned char **row_attrs, unsigned char **col_attrs)
{
  int j;

  fprintf(f, "<table%s>\n<tr%s><td%s>&nbsp;</td>",
          pss->page_table_attr, row_attrs[0], col_attrs[0]);
  for (j = 0; j < total_pages; j++)
    if (current_page != j + 1)
      fprintf(f, "<td%s><a href=\"%s\">%d</a></td>",
              col_attrs[1], pgrefs[j], j + 1);
    else
      fprintf(f, "<td%s>%d</td>", col_attrs[1], j + 1);

  fprintf(f, "</tr>\n<tr%s><td%s>%s</td>",
          row_attrs[1], col_attrs[0], _("Place"));
  for (j = 0; j < total_pages; j++)
    if (current_page != j + 1)
      fprintf(f, "<td%s><a href=\"%s\">[%d-%d]</a></td>",
              col_attrs[1], pgrefs[j], pg_n1[j], pg_n2[j]);
    else
      fprintf(f, "<td%s>[%d-%d]</td>",
              col_attrs[1], pg_n1[j], pg_n2[j]);

  fprintf(f, "</tr>\n<tr%s><td%s>%s</td>",
          row_attrs[2], col_attrs[0], _("Solved"));
  for (j = 0; j < total_pages; j++)
    if (current_page != j + 1)
      fprintf(f, "<td%s><a href=\"%s\">[%d-%d]</a></td>",
              col_attrs[1], pgrefs[j],
              u_full[u_sort[pg_n1[j] - 1]],
              u_full[u_sort[pg_n2[j] - 1]]);
    else
      fprintf(f, "<td%s>[%d-%d]</td>", col_attrs[1],
              u_full[u_sort[pg_n1[j] - 1]],
              u_full[u_sort[pg_n2[j] - 1]]);


  fprintf(f, "</tr>\n<tr%s><td%s>%s</td>",
          row_attrs[3], col_attrs[0], _("Score"));
  for (j = 0; j < total_pages; j++)
    if (current_page != j + 1)
      fprintf(f, "<td%s><a href=\"%s\">[%d-%d]</a></td>",
              col_attrs[1], pgrefs[j],
              u_score[u_sort[pg_n1[j] - 1]],
              u_score[u_sort[pg_n2[j] - 1]]);
    else
      fprintf(f, "<td%s>[%d-%d]</td>", col_attrs[1],
              u_score[u_sort[pg_n1[j] - 1]],
              u_score[u_sort[pg_n2[j] - 1]]);

  fprintf(f, "</tr>\n</table>\n");
}

static int sec_to_min(int rounding_mode, int secs);

unsigned char *
score_view_display(
        unsigned char *buf,
        size_t size,
        const struct section_problem_data *prob,
        int score)
{
  int i;

  if (!prob || !prob->score_view || !prob->score_view[0]
      || !prob->score_view_score) {
    snprintf(buf, size, "%d", score);
    return buf;
  }

  for (i = 0; prob->score_view[i] && prob->score_view_score[i] != score; i++);
  //snprintf(buf, size, "%s", prob->score_view_text[i]);
  if (!prob->score_view[i]) {
    snprintf(buf, size, "%d", score);
  } else {
    snprintf(buf, size, "%s", prob->score_view_text[i]);
  }
  return buf;
}

void
score_view_display_f(
        FILE *out_f,
        const struct section_problem_data *prob,
        int score)
{
  int i;

  if (!prob || !prob->score_view || !prob->score_view[0] || !prob->score_view_score) {
    if (score < 0) score = 0;
    fprintf(out_f, "%d", score);
    return;
  }

  for (i = 0; prob->score_view[i] && prob->score_view_score[i] != score; i++);
  if (!prob->score_view[i]) {
    if (score < 0) score = 0;
    fprintf(out_f, "%d", score);
  } else {
    fprintf(out_f, "%s", prob->score_view_text[i]);
  }
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
        struct user_filter_info *filter)
{
  int p_tot, i;
  const struct section_problem_data *prob;
  struct filter_env env;
  struct run_entry fake_entries[1];

  memset(p_rev, -1, p_max * sizeof(p_rev[0]));
  memset(&env, 0, sizeof(env));
  memset(fake_entries, 0, sizeof(fake_entries[0]) * 1);

  if (filter && filter->stand_prob_tree) {
    env.teamdb_state = state->teamdb_state;
    env.serve_state = state;
    env.mem = filter_tree_new();
    env.maxlang = state->max_lang;
    env.langs = (const struct section_language_data * const *) state->langs;
    env.maxprob = state->max_prob;
    env.probs = (const struct section_problem_data * const *) state->probs;
    env.rtotal = 1;
    env.cur_time = cur_time;
    env.rentries = fake_entries;
    env.rid = 0;
  }

  for (i = 1, p_tot = 0; i < p_max; i++) {
    if (!state->probs) continue;
    if (!(prob = state->probs[i])) continue;
    if (prob->hidden > 0) continue;
    if (prob->stand_column) continue;
    if (prob->start_date > 0 && cur_time < prob->start_date) continue;
    if (filter && filter->stand_prob_tree) {
      fake_entries[0].prob_id = i;
      if (filter_tree_bool_eval(&env, filter->stand_prob_tree) <= 0) continue;
    }
    if (prob->stand_last_column > 0 && *p_last_col_ind && *p_last_col_ind < 0){
      *p_last_col_ind = p_tot;
    }
    p_rev[i] = p_tot;
    p_ind[p_tot++] = i;
  }

  env.mem = filter_tree_delete(env.mem);
  *p_p_tot = p_tot;
}

static __attribute__((unused)) int
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

static __attribute__((unused)) void
write_moscow_page_table(const struct standings_style *pss,
                        FILE *f, int total_pages, int current_page,
                        unsigned char **pgrefs,
                        int *pg_n1, int *pg_n2,
                        int *pg_sc1, int *pg_sc2,
                        int *pg_pen1, int *pg_pen2,
                        unsigned char **pr_attrs, unsigned char **pc_attrs)
{
  int j;

  fprintf(f, "<table%s>\n<tr%s><td%s>%s</td>",
          pss->page_table_attr, pr_attrs[0], pc_attrs[0], _("Page"));
  for (j = 1; j <= total_pages; j++)
    if (current_page != j)
      fprintf(f, "<td%s><b><a href=\"%s\">%d</a></b></td>",
              pc_attrs[1], pgrefs[j - 1], j);
    else
      fprintf(f, "<td%s><b>%d</b></td>", pc_attrs[1], j);

  fprintf(f, "</tr>\n<tr%s><td%s>%s</td>",
          pr_attrs[1], pc_attrs[0], _("Place"));
  for (j = 0; j < total_pages; j++)
    if (current_page != j + 1)
      fprintf(f, "<td%s><a href=\"%s\">[%d-%d]</a></td>",
              pc_attrs[1], pgrefs[j], pg_n1[j], pg_n2[j]);
    else
      fprintf(f, "<td%s>[%d-%d]</td>", pc_attrs[1], pg_n1[j], pg_n2[j]);

  fprintf(f, "</tr>\n<tr%s><td%s>%s</td>",
          pr_attrs[2], pc_attrs[0], _("Score"));
  for (j = 0; j < total_pages; j++)
    if (current_page != j + 1)
      fprintf(f, "<td%s><a href=\"%s\">[%d-%d]</a></td>",
              pc_attrs[1], pgrefs[j], pg_sc1[j], pg_sc2[j]);
    else
      fprintf(f, "<td%s>[%d-%d]</td>", pc_attrs[1], pg_sc1[j], pg_sc2[j]);

  fprintf(f, "</tr>\n<tr%s><td%s>%s</td>",
          pr_attrs[3], pc_attrs[0], _("Penalty"));
  for (j = 0; j < total_pages; j++)
    if (current_page != j + 1)
      fprintf(f, "<td%s><a href=\"%s\">[%d-%d]</a></td>",
              pr_attrs[1], pgrefs[j], pg_pen1[j], pg_pen2[j]);
    else
      fprintf(f, "<td%s>[%d-%d]</td>", pr_attrs[1],
              pg_pen1[j], pg_pen2[j]);
  fprintf(f, "</tr></table>\n");
}

typedef void (*write_standings_func_t)(
        struct http_request_info *phr,
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        FILE *f,
        const unsigned char *stand_dir,
        const unsigned char *file_name,
        const unsigned char *file_name2,
        int users_on_page,
        int page_index,
        int client_flag,
        int only_table_flag,
        int user_id,
        const unsigned char *header_str,
        const unsigned char *footer_str,
        int accepting_mode,
        const unsigned char *user_name,
        int force_fancy_style,
        int charset_id,
        struct user_filter_info *user_filter,
        int user_mode,
        time_t stand_time,
        int compat_mode);

void
write_standings(
        struct contest_extra *extra,
        serve_state_t state,
        const struct contest_desc *cnts,
        char const *stat_dir,
        char const *name,   // file name for the first or the only standings page
        char const *name2,  // file name for the second and next standings pages
        int users_on_page,
        char const *header_str,
        char const *footer_str,
        int accepting_mode,
        int force_fancy_style,
        int charset_id,
        int user_mode)
{
  // to break compile-time dependency!
  static write_standings_func_t stand_func = NULL;
  if (!stand_func) {
    stand_func = dlsym(NULL, "ns_write_standings");
  }
  if (stand_func) {
    stand_func(NULL /* struct http_request_info *phr */,
               extra /* struct contest_extra *extra */,
               cnts /* const struct contest_desc *cnts */,
               NULL /* FILE *f */,
               stat_dir /* const unsigned char *stand_dir */,
               name /* const unsigned char *file_name */,
               name2 /* const unsigned char *file_name2 */,
               users_on_page /* int users_on_page */,
               -1 /* int page_index */,
               0 /* int client_flag */,
               0 /* int only_table_flag */,
               0 /* int user_id */,
               header_str /* const unsigned char *header_str */,
               footer_str /* const unsigned char *footer_str */,
               accepting_mode /* int accepting_mode */,
               NULL /* const unsigned char *user_name */,
               force_fancy_style /* int force_fancy_style */,
               charset_id /* int charset_id */,
               NULL /* struct user_filter_info *u */,
               user_mode /* int user_mode */,
               0 /* time_t cur_time */,
               0 /* int compat_mode */);
  }
}

typedef void (*write_public_log_func_t)(
        struct http_request_info *phr,
        struct contest_extra *extra,
        const struct contest_desc *cnts,
        FILE *f,
        char const *header_str,
        char const *footer_str,
        int user_mode);

void
write_public_log(
        struct contest_extra *extra,
        const serve_state_t state,
        const struct contest_desc *cnts,
        char const *stat_dir,
        char const *name,
        char const *header_str,
        char const *footer_str,
        int charset_id,
        int user_mode)
{
  char    tbuf[64];
  path_t  tpath;
  FILE   *f = 0;
  char *encode_txt = 0;
  size_t encode_len = 0;

  sprintf(tbuf, "XXX_%lu%d", time(0), getpid());
  pathmake(tpath, stat_dir, "/", tbuf, 0);
  if (charset_id > 0) {
    if (!(f = open_memstream(&encode_txt, &encode_len))) return;
  } else {
    if (!(f = sf_fopen(tpath, "w"))) return;
  }

  // to break compile-time dependency!
  static write_public_log_func_t public_log_func = NULL;
  if (!public_log_func) {
    public_log_func = dlsym(NULL, "ns_write_public_log");
  }
  if (public_log_func) {
    public_log_func(NULL /* struct http_request_info *phr */,
                    extra,
                    cnts,
                    f,
                    header_str,
                    footer_str,
                    user_mode);
  }

  fclose(f); f = 0;
  if (charset_id > 0) {
    encode_txt = charset_encode_heap(charset_id, encode_txt);
    encode_len = strlen(encode_txt);
    generic_write_file(encode_txt, encode_len, 0, NULL, tpath, NULL);
    xfree(encode_txt); encode_txt = 0; encode_len = 0;
  }
  generic_copy_file(REMOVE, stat_dir, tbuf, "",
                    SAFE, stat_dir, name, "");
  return;
}

void
html_print_testing_report_file_content(
        FILE *out_f,
        struct html_armor_buffer *pab,
        struct testing_report_file_content *fc,
        int type)
{
  switch (type) {
  case TESTING_REPORT_INPUT:
    if (fc->is_too_big) {
      fprintf(out_f, _("<u>--- Input: file is too large, original size %lld ---</u>\n"), fc->orig_size);
    } else if (fc->is_base64) {
      fprintf(out_f, _("<u>--- Input: file is binary, size %lld ---</u>\n"), fc->size);
    } else {
      fprintf(out_f, _("<u>--- Input: size %lld ---</u>\n"), fc->size);
    }
    break;
  case TESTING_REPORT_OUTPUT:
    if (fc->is_too_big) {
      fprintf(out_f, _("<u>--- Output: file is too large, original size %lld ---</u>\n"), fc->orig_size);
    } else if (fc->is_base64) {
      fprintf(out_f, _("<u>--- Output: file is binary, size %lld ---</u>\n"), fc->size);
    } else {
      fprintf(out_f, _("<u>--- Output: size %lld ---</u>\n"), fc->size);
    }
    break;
  case TESTING_REPORT_CORRECT:
    if (fc->is_too_big) {
      fprintf(out_f, _("<u>--- Correct: file is too large, original size %lld ---</u>\n"), fc->orig_size);
    } else if (fc->is_base64) {
      fprintf(out_f, _("<u>--- Correct: file is binary, size %lld ---</u>\n"), fc->size);
    } else {
      fprintf(out_f, _("<u>--- Correct: size %lld ---</u>\n"), fc->size);
    }
    break;
  case TESTING_REPORT_ERROR:
    if (fc->is_too_big) {
      fprintf(out_f, _("<u>--- Stderr: file is too large, original size %lld ---</u>\n"), fc->orig_size);
    } else if (fc->is_base64) {
      fprintf(out_f, _("<u>--- Stderr: file is binary, size %lld ---</u>\n"), fc->size);
    } else {
      fprintf(out_f, _("<u>--- Stderr: size %lld ---</u>\n"), fc->size);
    }
    break;
  case TESTING_REPORT_CHECKER:
    if (fc->is_too_big) {
      fprintf(out_f, _("<u>--- Checker output: file is too large, original size %lld ---</u>\n"), fc->orig_size);
    } else if (fc->is_base64) {
      fprintf(out_f, _("<u>--- Checker output: file is binary, size %lld ---</u>\n"), fc->size);
    } else {
      fprintf(out_f, _("<u>--- Checker output: size %lld ---</u>\n"), fc->size);
    }
    break;
  default:
    abort();
  }

  if (fc->is_too_big) {
  } else if (fc->is_base64) {
    const unsigned char * const *at = html_get_armor_table();
    int b64len = strlen(fc->data);
    unsigned char *data = xmalloc(b64len + 1);
    int size = base64_decode(fc->data, b64len, data, NULL);

    for (int offset = 0; offset < size; offset += 16) {
      fprintf(out_f, "%06x", offset);
      for (int i = 0; i < 16; ++i) {
        int off2 = offset + i;
        if (off2 < size) {
          fprintf(out_f, " %02x", data[off2]);
        } else {
          fprintf(out_f, "   ");
        }
      }
      fprintf(out_f, " ");
      for (int i = 0; i < 16; ++i) {
        int off2 = offset + i;
        if (off2 < size) {
          if (data[off2] >= ' ' && data[off2] < 127) {
            const unsigned char *ate = at[data[off2]];
            if (ate) {
              fprintf(out_f, "%s", ate);
            } else {
              putc(data[off2], out_f);
            }
          } else {
            fprintf(out_f, ".");
          }
        } else {
          fprintf(out_f, " ");
        }
      }
      fprintf(out_f, "\n");
    }
    xfree(data);
  } else {
    fprintf(out_f, "%s\n", html_armor_buf(pab, fc->data));
  }
}
