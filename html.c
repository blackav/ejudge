/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2000-2005 Alexander Chernov <cher@ispras.ru> */

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

#include "html.h"
#include "misctext.h"
#include "pathutl.h"
#include "fileutl.h"
#include "runlog.h"
#include "clarlog.h"
#include "teamdb.h"
#include "prepare.h"
#include "prepare_vars.h"
#include "base64.h"
#include "sformat.h"
#include "protocol.h"
#include "client_actions.h"
#include "copyright.h"
#include "archive_paths.h"
#include "team_extra.h"
#include "xml_utils.h"
#include "testing_report_xml.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <time.h>
#include <unistd.h>

#ifndef EJUDGE_CHARSET
#define EJUDGE_CHARSET EJUDGE_INTERNAL_CHARSET
#endif /* EJUDGE_CHARSET */

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

FILE *
sf_fopen(char const *path, char const *flags)
{
  FILE *f = fopen(path, flags);
  if (f) return f;
  err("fopen(\"%s\",\"%s\") failed: %s", path, flags, os_ErrorMsg());
  return NULL;
}

int
calc_kirov_score(unsigned char *outbuf,
                 size_t outsize,
                 struct run_entry *pe,
                 struct section_problem_data *pr,
                 int attempts,
                 int disq_attempts,
                 int prev_successes,
                 int *p_date_penalty)
{
  int score, init_score, dpi, date_penalty = 0, score_mult = 1, score_bonus = 0;

  ASSERT(pe);
  ASSERT(pr);
  ASSERT(attempts >= 0);

  init_score = pe->score;
  if (pe->status == RUN_OK && !pr->variable_full_score)
    init_score = pr->full_score;
  if (pr->score_multiplier > 1) score_mult = pr->score_multiplier;

  // get date_penalty
  for (dpi = 0; dpi < pr->dp_total; dpi++)
    if (pe->timestamp < pr->dp_infos[dpi].deadline)
      break;
  if (dpi < pr->dp_total) {
    date_penalty = pr->dp_infos[dpi].penalty;
  }
  if (p_date_penalty) *p_date_penalty = date_penalty;

  // count the bonus depending on the number of previous successes
  if (pr->score_bonus_total > 0) {
    if (prev_successes >= 0 && prev_successes < pr->score_bonus_total)
      score_bonus = pr->score_bonus_val[prev_successes];
  }

  // score_mult is applied to the initial score
  // run_penalty is subtracted, but date_penalty is added
  score = init_score * score_mult - attempts * pr->run_penalty + date_penalty + pe->score_adj - disq_attempts * pr->disqualified_penalty + score_bonus;
  //if (score > pr->full_score) score = pr->full_score;
  if (score < 0) score = 0;
  if (!outbuf) return score;

  {
    unsigned char init_score_str[64];
    unsigned char run_penalty_str[64];
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

    if (attempts > 0 && pr->run_penalty > 0) {
      snprintf(run_penalty_str, sizeof(run_penalty_str),
               "-%d*%d", attempts, pr->run_penalty);
    } else {
      run_penalty_str[0] = 0;
    }

    if (date_penalty != 0) {
      snprintf(date_penalty_str, sizeof(date_penalty_str),
               "%+d", date_penalty);
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

    if (score_mult > 1 || run_penalty_str[0] || date_penalty_str[0]
        || score_adj_str[0] || disq_penalty_str[0] || score_bonus_str[0]) {
      snprintf(final_score_str, sizeof(final_score_str),
               "<b>%d</b>=", score);
    } else {
      init_score_str[0] = 0;
      snprintf(final_score_str, sizeof(final_score_str),
               "<b>%d</b>", score);
    }

    snprintf(outbuf, outsize, "%s%s%s%s%s%s%s",
             final_score_str,
             init_score_str, run_penalty_str, date_penalty_str, score_adj_str,
             disq_penalty_str, score_bonus_str);
    return score;
  }
}

void
write_html_run_status(FILE *f, struct run_entry *pe,
                      int priv_level, int attempts, int disq_attempts,
                      int prev_successes)
{
  unsigned char status_str[64], score_str[64];
  struct section_problem_data *pr = 0;
  int need_extra_col = 0;

  if (pe->problem > 0 && pe->problem <= max_prob) pr = probs[pe->problem];
  run_status_str(pe->status, status_str, 0);
  fprintf(f, "<td>%s</td>", status_str);

  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD
      || global->score_system_val == SCORE_MOSCOW)
    need_extra_col = 1;

  if (pe->status >= RUN_PSEUDO_FIRST && pe->status <= RUN_PSEUDO_LAST) {
    fprintf(f, "<td>&nbsp;</td>");
    if (need_extra_col) {
      fprintf(f, "<td>&nbsp;</td>");
    }
    return;
  } else if (pe->status > RUN_MAX_STATUS) {
    fprintf(f, "<td>%s</td>", _("N/A"));
    if (need_extra_col) {
      fprintf(f, "<td>%s</td>", _("N/A"));
    }
    return;
  }

  switch (pe->status) {
  case RUN_CHECK_FAILED:
    if (priv_level > 0) break;
  case RUN_ACCEPTED:
  case RUN_IGNORED:
  case RUN_DISQUALIFIED:
  case RUN_PENDING:
  case RUN_COMPILE_ERR:
    fprintf(f, "<td>%s</td>", _("N/A"));
    if (need_extra_col) {
      fprintf(f, "<td>%s</td>", _("N/A"));
    }
    return;
  }

  if (global->score_system_val == SCORE_ACM) {
    if (pe->status == RUN_OK || pe->test <= 0) {
      fprintf(f, "<td>%s</td>", _("N/A"));
    } else {
      fprintf(f, "<td>%d</td>", pe->test);
    }
    return;
  }

  if (global->score_system_val == SCORE_MOSCOW) {
    if (pe->status == RUN_OK || pe->test <= 0) {
      fprintf(f, "<td>%s</td>", _("N/A"));
    } else {
      fprintf(f, "<td>%d</td>", pe->test);
    }
    if (pe->status == RUN_OK) {
      fprintf(f, "<td><b>%d</b></td>", pe->score);
    } else {
      fprintf(f, "<td>%d</td>", pe->score);
    }
    return;
  }

  if (pe->test <= 0) {
    fprintf(f, "<td>%s</td>", _("N/A"));
  } else {
    fprintf(f, "<td>%d</td>", pe->test - 1);
  }

  if (pe->score < 0 || !pr) {
    fprintf(f, "<td>%s</td>", _("N/A"));
  } else {
    calc_kirov_score(score_str, sizeof(score_str), pe, pr, attempts,
                     disq_attempts, prev_successes, 0);
    fprintf(f, "<td>%s</td>", score_str);
  }
}

static void
write_user_problems_summary(FILE *f, int user_id, int accepting_mode,
                            unsigned char *solved_flag)
{
  time_t start_time;
  int total_runs, run_id, cur_score, total_teams, prob_id, total_score = 0;
  int *best_run = 0;
  int *attempts = 0;
  int *disqualified = 0;
  int *best_score = 0;
  int *prev_successes = 0;
  unsigned char *user_flag = 0;
  unsigned char *accepted_flag = 0;
  unsigned char *pending_flag = 0;
  struct run_entry re;
  struct section_problem_data *cur_prob = 0;
  unsigned char *s;
  unsigned char url_buf[1024];
  unsigned char status_str[64];
  time_t current_time = time(0);

  if (global->virtual) {
    start_time = run_get_virtual_start_time(user_id);
  } else {
    start_time = run_get_start_time();
  }
  total_runs = run_get_total();
  total_teams = teamdb_get_max_team_id() + 1;

  XALLOCA(best_run, max_prob + 1);
  memset(best_run, -1, sizeof(best_run[0]) * (max_prob + 1));
  XALLOCAZ(accepted_flag, max_prob + 1);
  XALLOCAZ(pending_flag, max_prob + 1);
  XALLOCAZ(attempts, max_prob + 1);
  XALLOCAZ(disqualified, max_prob + 1);
  XALLOCAZ(best_score, max_prob + 1);
  XALLOCAZ(prev_successes, max_prob + 1);
  XALLOCAZ(user_flag, (max_prob + 1) * total_teams);

  for (run_id = 0; run_id < total_runs; run_id++) {
    if (run_get_entry(run_id, &re) < 0) continue;
    if (re.status > RUN_MAX_STATUS) continue;

    cur_prob = 0;
    if (re.problem > 0 && re.problem <= max_prob) cur_prob = probs[re.problem];
    if (!cur_prob) continue;

    if (re.team <= 0 || re.team >= total_teams) continue;
    if (re.team != user_id) {
      if (re.status == RUN_OK) {
        if (!user_flag[re.team * (max_prob + 1) + re.problem]) {
          prev_successes[re.problem]++;
        }
        user_flag[re.team * (max_prob + 1) + re.problem] = 1;
      }
      continue;
    }

    if (global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
      // OLYMPIAD contest in accepting mode
      switch (re.status) {
      case RUN_OK:
        solved_flag[re.problem] = 1;
        accepted_flag[re.problem] = 1;
        best_run[re.problem] = run_id;
        break;

      case RUN_COMPILE_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        if (!accepted_flag[re.problem]) {
          best_run[re.problem] = run_id;
          attempts[re.problem]++;
        }
        break;

      case RUN_PARTIAL:
        attempts[re.problem]++;
      case RUN_ACCEPTED:
        if (!solved_flag[re.problem]) {
          accepted_flag[re.problem] = 1;
          best_run[re.problem] = run_id;
        }
        break;

      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
        break;

      case RUN_PENDING:
        pending_flag[re.problem] = 1;
        attempts[re.problem]++;
        if (best_run[re.problem] < 0) best_run[re.problem] = run_id;
        break;

      default:
        abort();
      }
    } else if (global->score_system_val == SCORE_OLYMPIAD) {
      // OLYMPIAD contest in judging mode
      if (solved_flag[re.problem]) continue;

      switch (re.status) {
      case RUN_OK:
        solved_flag[re.problem] = 1;
        best_run[re.problem] = run_id;
        cur_score = calc_kirov_score(0, 0, &re, cur_prob, 0, 0, 0, 0);
        if (cur_score > best_score[re.problem])
          best_score[re.problem] = cur_score;
        break;

      case RUN_COMPILE_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        break;

      case RUN_PARTIAL:
        best_run[re.problem] = run_id;
        attempts[re.problem]++;
        cur_score = calc_kirov_score(0, 0, &re, cur_prob, 0, 0, 0, 0);
        if (cur_score > best_score[re.problem])
          best_score[re.problem] = cur_score;
        break;

      case RUN_ACCEPTED:
        break;

      case RUN_IGNORED:
        break;

      case RUN_DISQUALIFIED:
        break;

      case RUN_PENDING:
        pending_flag[re.problem] = 1;
        if (best_run[re.problem] < 0) best_run[re.problem] = run_id;
        break;

      default:
        abort();
      }
    } else if (global->score_system_val == SCORE_KIROV) {
      // KIROV contest
      if (solved_flag[re.problem]) continue;

      switch (re.status) {
      case RUN_OK:
        solved_flag[re.problem] = 1;
        cur_score = calc_kirov_score(0, 0, &re, cur_prob,
                                     attempts[re.problem],
                                     disqualified[re.problem],
                                     prev_successes[re.problem], 0);

        if (cur_score >= best_score[re.problem]) {
          best_score[re.problem] = cur_score;
          best_run[re.problem] = run_id;
        }
        break;

      case RUN_COMPILE_ERR:
        if (!global->ignore_compile_errors) {
          attempts[re.problem]++;
          cur_score = 0;
          if (cur_score >= best_score[re.problem]) {
            best_score[re.problem] = cur_score;
            best_run[re.problem] = run_id;
          }
        }
        break;

      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        break;

      case RUN_PARTIAL:
        cur_score = calc_kirov_score(0, 0, &re, cur_prob,
                                     attempts[re.problem],
                                     disqualified[re.problem],
                                     prev_successes[re.problem], 0);

        attempts[re.problem]++;
        if (cur_score >= best_score[re.problem]) {
          best_score[re.problem] = cur_score;
          best_run[re.problem] = run_id;
        }
        break;

      case RUN_ACCEPTED:
        break;

      case RUN_IGNORED:
        break;

      case RUN_DISQUALIFIED:
        disqualified[re.problem]++;
        break;

      case RUN_PENDING:
        pending_flag[re.problem] = 1;
        attempts[re.problem]++;
        if (best_run[re.problem] < 0) best_run[re.problem] = run_id;
        break;

      default:
        abort();
      }
    } else if (global->score_system_val == SCORE_MOSCOW) {
      if (solved_flag[re.problem]) continue;

      switch (re.status) {
      case RUN_OK:
        solved_flag[re.problem] = 1;
        best_run[re.problem] = run_id;
        cur_score = cur_prob->full_score;
        if (cur_score >= best_score[re.problem]) {
          best_score[re.problem] = cur_score;
          best_run[re.problem] = run_id;
        }
        break;

      case RUN_COMPILE_ERR:
        if (!global->ignore_compile_errors) {
          attempts[re.problem]++;
          cur_score = 0;
          if (cur_score >= best_score[re.problem]
              || best_run[re.problem] < 0) {
            best_score[re.problem] = cur_score;
            best_run[re.problem] = run_id;
          }
        }
        break;
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        attempts[re.problem]++;
        cur_score = re.score;
        if (cur_score >= best_score[re.problem]
            || best_run[re.problem] < 0) {
          best_score[re.problem] = cur_score;
          best_run[re.problem] = run_id;
        }
        break;

      case RUN_PARTIAL:
      case RUN_ACCEPTED:
      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
        break;

      case RUN_PENDING:
        pending_flag[re.problem] = 1;
        attempts[re.problem]++;
        if (best_run[re.problem] < 0) best_run[re.problem] = run_id;
        break;

      default:
        abort();
      }
    } else {
      // ACM contest
      if (solved_flag[re.problem]) continue;

      switch (re.status) {
      case RUN_OK:
        solved_flag[re.problem] = 1;
        best_run[re.problem] = run_id;
        break;

      case RUN_COMPILE_ERR:
        if (!global->ignore_compile_errors) {
          attempts[re.problem]++;
          best_run[re.problem] = run_id;
        }
        break;
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        attempts[re.problem]++;
        best_run[re.problem] = run_id;
        break;

      case RUN_PARTIAL:
      case RUN_ACCEPTED:
      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
        break;

      case RUN_PENDING:
        pending_flag[re.problem] = 1;
        attempts[re.problem]++;
        if (best_run[re.problem] < 0) best_run[re.problem] = run_id;
        break;

      default:
        abort();
      }
    }
  }

  fprintf(f, "<table border=\"1\"><tr>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>",
          _("Short name"),
          _("Long name"),
          _("Status"));
  if (global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
    fprintf(f, "<th>%s</th>", _("Tests passed"));
  } else if ((global->score_system_val == SCORE_OLYMPIAD && !accepting_mode)
      || global->score_system_val == SCORE_KIROV) {
    fprintf(f, "<th>%s</th>", _("Tests passed"));
    fprintf(f, "<th>%s</th>", _("Score"));
  } else if (global->score_system_val == SCORE_MOSCOW) {
    fprintf(f, "<th>%s</th>", _("Failed test"));
    fprintf(f, "<th>%s</th>", _("Score"));
  } else {
    fprintf(f, "<th>%s</th>", _("Failed test"));
  }
  fprintf(f, "<th>%s</th></tr>\n", _("Run ID"));

  for (prob_id = 1; prob_id <= max_prob; prob_id++) {
    if (!(cur_prob = probs[prob_id])) continue;
    if (cur_prob->t_start_date && current_time < cur_prob->t_start_date)
      continue;
    s = "";
    if (accepted_flag[prob_id] || solved_flag[prob_id])
      s = " bgcolor=\"#ddffdd\"";
    else if (!pending_flag[prob_id] && attempts[prob_id])
      s = " bgcolor=\"#ffdddd\"";
    fprintf(f, "<tr%s>", s);
    fprintf(f, "<td>");
    if (global->prob_info_url[0]) {
      sformat_message(url_buf, sizeof(url_buf), global->prob_info_url,
                      NULL, cur_prob, NULL, NULL, NULL, 0, 0, 0);
      fprintf(f, "<a href=\"%s\" target=\"_blank\">", url_buf);
    }
    s = html_armor_string_dup(cur_prob->short_name);
    fprintf(f, "%s", s);
    xfree(s);
    fprintf(f, "</td>");
    s = html_armor_string_dup(cur_prob->long_name);
    fprintf(f, "<td>%s</td>", s);
    xfree(s);
    if (best_run[prob_id] < 0) {
      if ((global->score_system_val == SCORE_KIROV && !accepting_mode)
          || global->score_system_val == SCORE_OLYMPIAD
          || global->score_system_val == SCORE_MOSCOW) {
        fprintf(f, "<td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n");
      } else {
        fprintf(f, "<td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n");
      }
      continue;
    }

    run_get_entry(best_run[prob_id], &re);
    run_status_str(re.status, status_str, 0);
    fprintf(f, "<td>%s</td>", status_str);

    if (global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
      switch (re.status) {
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        fprintf(f, "<td>%d</td>", re.test);
        break;
      default:
        fprintf(f, "<td>&nbsp;</td>");
        break;
      }
    } else if (global->score_system_val == SCORE_OLYMPIAD) {
      total_score += best_score[prob_id];
      switch (re.status) {
      case RUN_OK:
      case RUN_PARTIAL:
        fprintf(f, "<td>%d</td><td>%d</td>", re.test - 1, best_score[prob_id]);
        break;
      default:
        fprintf(f, "<td>&nbsp;</td><td>&nbsp;</td>");
        break;
      }
    } else if (global->score_system_val == SCORE_KIROV) {
      total_score += best_score[prob_id];
      switch (re.status) {
      case RUN_OK:
      case RUN_PARTIAL:
        fprintf(f, "<td>%d</td><td>%d</td>", re.test - 1, best_score[prob_id]);
        break;
      default:
        fprintf(f, "<td>&nbsp;</td><td>&nbsp;</td>");
        break;
      }
    } else if (global->score_system_val == SCORE_MOSCOW) {
      total_score += best_score[prob_id];
      switch (re.status) {
      case RUN_OK:
        fprintf(f, "<td>&nbsp;</td><td>%d</td>", best_score[prob_id]);
        break;
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        fprintf(f, "<td>%d</td><td>%d</td>", re.test, best_score[prob_id]);
        break;
      default:
        fprintf(f, "<td>&nbsp;</td><td>&nbsp;</td>");
        break;
      }
    } else {
      // ACM contest
      switch (re.status) {
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        fprintf(f, "<td>%d</td>", re.test);
        break;
      default:
        fprintf(f, "<td>&nbsp;</td>");
        break;
      }
    }
    fprintf(f, "<td>%d</td>", best_run[prob_id]);
    fprintf(f, "</tr>\n");
  }

  fprintf(f, "</table>\n");

  if ((global->score_system_val == SCORE_OLYMPIAD && !accepting_mode)
      || global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_MOSCOW) {
    fprintf(f, "<p><big>%s: %d</big></p>\n", _("Total score"), total_score);
  }
}

void
new_write_user_runs(FILE *f, int uid, int printing_suspended,
                    unsigned int show_flags,
                    ej_cookie_t sid,
                    unsigned char const *self_url,
                    unsigned char const *hidden_vars,
                    unsigned char const *extra_args)
{
  int i, showed, runs_to_show;
  int attempts, disq_attempts, prev_successes;
  time_t start_time, time;
  unsigned char dur_str[64];
  unsigned char stat_str[64];
  unsigned char *prob_str;
  unsigned char *lang_str;
  unsigned char href[128];
  struct run_entry re;
  const unsigned char *run_kind_str = 0;
  struct section_problem_data *cur_prob;

  if (global->virtual) {
    start_time = run_get_virtual_start_time(uid);
  } else {
    start_time = run_get_start_time();
  }
  runs_to_show = 15;
  if (show_flags) runs_to_show = 100000;

  /* write run statistics: show last 15 in the reverse order */
  fprintf(f,"<table border=\"1\"><tr><th>%s</th><th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th><th>%s</th><th>%s</th>",
          _("Run ID"), _("Time"), _("Size"), _("Problem"),
          _("Language"), _("Result"));

  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD) {
    fprintf(f, "<th>%s</th>", _("Tests passed"));
    fprintf(f, "<th>%s</th>", _("Score"));
  } else if (global->score_system_val == SCORE_MOSCOW) {
    fprintf(f, "<th>%s</th><th>%s</th>", _("Failed test"), _("Score"));
  } else {
    fprintf(f, "<th>%s</th>", _("Failed test"));
  }

  if (global->team_enable_src_view)
    fprintf(f, "<th>%s</th>", _("View source"));
  if (global->team_enable_rep_view || global->team_enable_ce_view)
    fprintf(f, "<th>%s</th>", _("View report"));
  if (global->enable_printing && !printing_suspended)
    fprintf(f, "<th>%s</th>", _("Print sources"));

  fprintf(f, "</tr>\n");

  for (showed = 0, i = run_get_total() - 1;
       i >= 0 && showed < runs_to_show;
       i--) {
    if (run_get_entry(i, &re) < 0) continue;
    if (re.status == RUN_VIRTUAL_START || re.status == RUN_VIRTUAL_STOP
        || re.status == RUN_EMPTY)
      continue;
    if (re.team != uid) continue;
    showed++;

    attempts = 0; disq_attempts = 0;
    if (global->score_system_val == SCORE_KIROV && !re.is_hidden)
      run_get_attempts(i, &attempts, &disq_attempts,
                       global->ignore_compile_errors);

    cur_prob = 0;
    if (re.problem > 0 && re.problem <= max_prob) cur_prob = probs[re.problem];

    prev_successes = RUN_TOO_MANY;
    if (global->score_system_val == SCORE_KIROV
        && re.status == RUN_OK
        && !re.is_hidden
        && cur_prob && cur_prob->score_bonus_total > 0) {
      if ((prev_successes = run_get_prev_successes(i)) < 0)
        prev_successes = RUN_TOO_MANY;
    }

    run_kind_str = "";
    if (re.is_imported) run_kind_str = "*";
    if (re.is_hidden) run_kind_str = "#";

    time = re.timestamp;
    if (!start_time) time = start_time;
    if (start_time > time) time = start_time;
    duration_str(global->show_astr_time, time, start_time, dur_str, 0);
    run_status_str(re.status, stat_str, 0);
    prob_str = "???";
    if (probs[re.problem]) {
      if (probs[re.problem]->variant_num > 0) {
        int variant = re.variant;
        if (!variant) variant = find_variant(re.team, re.problem);
        prob_str = alloca(strlen(probs[re.problem]->short_name) + 10);
        if (variant > 0) {
          sprintf(prob_str, "%s-%d", probs[re.problem]->short_name, variant);
        } else {
          sprintf(prob_str, "%s-?", probs[re.problem]->short_name);
        }
      } else {
        prob_str = probs[re.problem]->short_name;
      }
    }
    lang_str = "???";
    if (langs[re.language]) lang_str = langs[re.language]->short_name;

    fprintf(f, "<tr>\n");
    fprintf(f, "<td>%d%s</td>", i, run_kind_str);
    fprintf(f, "<td>%s</td>", dur_str);
    fprintf(f, "<td>%u</td>", re.size);
    fprintf(f, "<td>%s</td>", prob_str);
    fprintf(f, "<td>%s</td>", lang_str);

    write_html_run_status(f, &re, 0, attempts, disq_attempts, prev_successes);

    if (global->team_enable_src_view) {
      fprintf(f, "<td>");
      fprintf(f, "%s%s</a>", html_hyperref(href, sizeof(href), sid,
                                           self_url, extra_args,
                                           "source_%d=1", i), _("View"));
      fprintf(f, "</td>");
    }
    if (global->team_enable_rep_view) {
      fprintf(f, "<td>");
      if (re.status == RUN_CHECK_FAILED || re.status == RUN_IGNORED
          || re.status == RUN_PENDING || re.status > RUN_MAX_STATUS) {
        fprintf(f, "N/A");
      } else {
        fprintf(f, "%s%s</a>", html_hyperref(href, sizeof(href), sid, self_url, extra_args, "report_%d=1", i), _("View"));
      }
      fprintf(f, "</td>");
    } else if (global->team_enable_ce_view) {
      fprintf(f, "<td>");
      if (re.status != RUN_COMPILE_ERR) {
        fprintf(f, "N/A");
      } else {
        fprintf(f, "%s%s</a>", html_hyperref(href, sizeof(href), sid, self_url, extra_args, "report_%d=1", i), _("View"));
      }
      fprintf(f, "</td>");
    }

    if (global->enable_printing && !printing_suspended) {
      fprintf(f, "<td>");
      if (re.pages > 0) {
        fprintf(f, "N/A");
      } else {
        fprintf(f, "%s%s</a>", html_hyperref(href, sizeof(href), sid, self_url, extra_args, "print_%d=1", i), _("Print"));
      }
      fprintf(f, "</td>\n");
    }

    fprintf(f, "\n</tr>\n");
  }
  fputs("</table>\n", f);
}

static unsigned char *
team_clar_flags(int user_id, int clar_id, int flags, int from, int to)
{
  if (from != user_id) {
    if (!team_extra_get_clar_status(user_id, clar_id)) return "N";
    else return "&nbsp;";
  }
  if (!flags) return "U";
  return clar_flags_html(flags, from, to, 0, 0);
}

static int
count_unread_clars(int user_id)
{
  int i, total = 0, from, to;

  for (i = clar_get_total() - 1; i >= 0; i--) {
    if (clar_get_record(i, 0, 0, 0, &from, &to, 0, 0) < 0)
      continue;
    if (to > 0 && to != user_id) continue;
    if (!to && from > 0) continue;
    if (from != user_id && !team_extra_get_clar_status(user_id, i))
      total++;
  }
  return total;
}

void
new_write_user_clars(FILE *f, int uid, unsigned int show_flags,
                     ej_cookie_t sid,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args)
{
  int showed, i, clars_to_show;
  int from, to, flags, n;
  size_t size;
  time_t start_time, time;
  int show_astr_time = 0;

  char  dur_str[64];
  char  subj[CLAR_MAX_SUBJ_LEN + 4];      /* base64 subj */
  char  psubj[CLAR_MAX_SUBJ_TXT_LEN + 4]; /* plain text subj */
  char *asubj = 0; /* html armored subj */
  int   asubj_len = 0; /* html armored subj len */
  unsigned char href[128];

  start_time = run_get_start_time();
  clars_to_show = 15;
  if (show_flags) clars_to_show = 100000;
  show_astr_time = global->show_astr_time;
  if (global->virtual) show_astr_time = 1;

  /* write clars statistics for the last 15 in the reverse order */
  fprintf(f,"<table border=\"1\"><tr><th>%s</th><th>%s</th><th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th><th>%s</th>"
          "<th>%s</th><th>%s</th></tr>\n",
          _("Clar ID"), _("Flags"), _("Time"), _("Size"), _("From"),
          _("To"), _("Subject"), _("View"));
  for (showed = 0, i = clar_get_total() - 1;
       showed < clars_to_show && i >= 0;
       i--) {
    if (clar_get_record(i, &time, &size,
                        0, &from, &to, &flags, subj) < 0)
      continue;
    if (from > 0 && from != uid) continue;
    if (to > 0 && to != uid) continue;
    showed++;

    base64_decode_str(subj, psubj, 0);
    n = html_armored_strlen(psubj);
    if (n + 4 > asubj_len) {
      asubj_len = (n + 7) & ~3;
      asubj = alloca(asubj_len);
    }
    html_armor_string(psubj, asubj);
    if (!start_time) time = start_time;
    if (start_time > time) time = start_time;
    duration_str(show_astr_time, time, start_time, dur_str, 0);

    fputs("<tr>", f);
    fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", team_clar_flags(uid, i, flags, from, to));
    fprintf(f, "<td>%s</td>", dur_str);
    fprintf(f, "<td>%zu</td>", size);
    if (!from) {
      fprintf(f, "<td><b>%s</b></td>", _("judges"));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_login(from));
    }
    if (!to && !from) {
      fprintf(f, "<td><b>%s</b></td>", _("all"));
    } else if (!to) {
      fprintf(f, "<td><b>%s</b></td>", _("judges"));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_login(to));
    }
    fprintf(f, "<td>%s</td>", asubj);
    fprintf(f, "<td>");
    fprintf(f, "%s%s</a>", html_hyperref(href, sizeof(href), sid,
                                         self_url, extra_args,
                                         "clar_%d=1", i), _("View"));
    fprintf(f, "</td>");
    fprintf(f, "</tr>\n");
  }
  fputs("</table>\n", f);
}

int
new_write_user_clar(FILE *f, int uid, int cid)
{
  time_t start_time, time;
  size_t size;
  int from, to;
  int  asubj_len, atxt_len;
  char subj[CLAR_MAX_SUBJ_LEN + 4];
  char psubj[CLAR_MAX_SUBJ_TXT_LEN + 4];
  char *asubj, *atxt;
  char dur_str[64];
  char cname[64];
  char *csrc = 0;
  size_t csize = 0;
  int show_astr_time;

  if (global->disable_clars) {
    err("clarifications are disabled");
    return -SRV_ERR_CLARS_DISABLED;
  }
  if (cid < 0 || cid >= clar_get_total()) {
    err("invalid clar_id %d", cid);
    return -SRV_ERR_BAD_CLAR_ID;
  }

  show_astr_time = global->show_astr_time;
  if (global->virtual) show_astr_time = 1;
  start_time = run_get_start_time();
  if (clar_get_record(cid, &time, &size, NULL,
                      &from, &to, NULL, subj) < 0) {
    return -SRV_ERR_BAD_CLAR_ID;
  }
  if (from > 0 && from != uid) return -SRV_ERR_ACCESS_DENIED;
  if (to > 0 && to != uid) return -SRV_ERR_ACCESS_DENIED;

  if (from != uid) {
    team_extra_set_clar_status(uid, cid);
  }

  sprintf(cname, "%06d", cid);
  if (generic_read_file(&csrc, 0, &csize, 0,
                        global->clar_archive_dir, cname, "") < 0) {
    return -SRV_ERR_SYSTEM_ERROR;
  }

  base64_decode_str(subj, psubj, 0);
  asubj_len = html_armored_strlen(psubj);
  asubj = alloca(asubj_len + 4);
  html_armor_string(psubj, asubj);
  atxt_len = html_armored_strlen(csrc);
  atxt = alloca(atxt_len + 4);
  html_armor_string(csrc, atxt);
  xfree(csrc);

  if (!start_time) time = start_time;
  if (time < start_time) time = start_time;
  duration_str(show_astr_time, time, start_time, dur_str, 0);

  fprintf(f, "<%s>%s #%d</%s>\n", cur_contest->team_head_style,
          _("Message"), cid, cur_contest->team_head_style);
  fprintf(f, "<table border=\"0\">\n");
  fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>\n", _("Number"), cid);
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Time"), dur_str);
  fprintf(f, "<tr><td>%s:</td><td>%zu</td></tr>\n", _("Size"), size);
  fprintf(f, "<tr><td>%s:</td>", _("Sender"));
  if (!from) {
    fprintf(f, "<td><b>%s</b></td>", _("judges"));
  } else {
    fprintf(f, "<td>%s</td>", teamdb_get_name(from));
  }
  fprintf(f, "</tr>\n<tr><td>%s:</td>", _("To"));
  if (!to && !from) {
    fprintf(f, "<td><b>%s</b></td>", _("all"));
  } else if (!to) {
    fprintf(f, "<td><b>%s</b></td>", _("judges"));
  } else {
    fprintf(f, "<td>%s</td>", teamdb_get_name(to));
  }
  fprintf(f, "</tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>", _("Subject"), asubj);
  fprintf(f, "</table>\n");
  fprintf(f, "<hr><pre>");
  fprintf(f, "%s", atxt);
  fprintf(f, "</pre>");

  return 0;
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
write_standings_header(FILE *f, int client_flag,
                       int user_id,
                       unsigned char const *header_str,
                       unsigned char const *user_name)
{
  time_t start_time, stop_time, cur_time;
  unsigned char header[1024];
  unsigned char dur_str[64];
  int show_astr_time;

  start_time = run_get_start_time();
  stop_time = run_get_stop_time();
  if (global->virtual && user_id > 0) {
    start_time = run_get_virtual_start_time(user_id);
    stop_time = run_get_virtual_stop_time(user_id, 0);
  }

  if (!start_time) {
    if (user_name) {
      if (global->name[0] && !client_flag) {
        sprintf(header, "%s - &quot;%s&quot; - %s",
                user_name, global->name, _("team standings"));
      } else {
        sprintf(header, "%s - %s", user_name, _("Team standings"));
      }
    } else {
      if (global->name[0] && !client_flag) {
        sprintf(header, "%s &quot;%s&quot; - %s",
                _("Contest"), global->name, _("team standings"));
      } else {
        sprintf(header, "%s", _("Team standings"));
      }
    }

    if (!client_flag) {
      if (header_str) {
        process_template(f, header_str, 0, global->charset, header, 0);
      } else {
        fprintf(f, "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>%s</title></head><body><h1>%s</h1>\n",
                global->charset,
                header, header);
      }
    } else {
      fprintf(f, "<%s>%s</%s>\n", cur_contest->team_head_style,
              header, cur_contest->team_head_style);
    }
    return;
  }

  cur_time = time(0);
  if (start_time > cur_time) cur_time = start_time;
  if (stop_time && cur_time > stop_time) cur_time = stop_time;
  show_astr_time = global->show_astr_time;
  if (global->virtual && !user_id) {
    show_astr_time = 1;
    cur_time = time(0);
  }
  duration_str(show_astr_time, cur_time, start_time, dur_str, 0);

  if (user_name) {
    if (global->name[0] && !client_flag) {
      sprintf(header, "%s  - &quot;%s&quot; - %s [%s]",
              user_name, global->name, _("team standings"), dur_str);
    } else {
      sprintf(header, "%s - %s [%s]",
              user_name, _("Team standings"), dur_str);
    }
  } else {
    if (global->name[0] && !client_flag) {
      sprintf(header, "%s &quot;%s&quot; - %s [%s]",
              _("Contest"), global->name, _("team standings"), dur_str);
    } else {
      sprintf(header, "%s [%s]", _("Team standings"), dur_str);
    }
  }

  if (!client_flag) {
    if (header_str) {
      process_template(f, header_str, 0, global->charset, header, 0);
    } else {
      fprintf(f, "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>%s</title></head><body><h1>%s</h1>",
              global->charset,
              header, header);
    }
  } else {
    fprintf(f, "<%s>%s</%s>\n", cur_contest->team_head_style,
            header, cur_contest->team_head_style);
  }
}

static void
write_kirov_page_table(FILE *f, int total_pages, int current_page,
                       unsigned char **pgrefs,
                       int *u_sort, int *u_full, int *u_score,
                       int *pg_n1, int *pg_n2,
                       unsigned char **row_attrs, unsigned char **col_attrs)
{
  int j;

  fprintf(f, "<table%s>\n<tr%s><td%s>&nbsp;</td>",
          global->stand_page_table_attr, row_attrs[0], col_attrs[0]);
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


void
do_write_kirov_standings(FILE *f,
                         const unsigned char *stand_dir,
                         int client_flag,
                         const unsigned char *header_str,
                         unsigned char const *footer_str,
                         int raw_flag,
                         int accepting_mode)
{
  time_t start_time;
  time_t stop_time;
  time_t cur_time;
  time_t cur_duration;
  time_t run_time;

  int  t_max, t_tot, p_max, p_tot, r_tot;
  int *t_ind, *t_rev, *p_ind, *p_rev;
  unsigned char *t_runs;

  int i, k, j;
  int last_submit_run = -1;
  int last_success_run = -1;

  int *prob_score = 0;
  int *att_num = 0;
  int *disq_num = 0;
  int *sol_att = 0;
  int *full_sol = 0;
  time_t *sol_time = 0;
  int *trans_num = 0;

  int  *tot_score, *tot_full, *succ_att, *tot_att;
  int  *t_sort = 0, *t_sort2, *t_n1, *t_n2;
  char dur_str[1024];
  unsigned char *head_style;
  struct teamdb_export u_info;
  struct run_entry *runs;
  int ttot_att, ttot_succ, perc, t;
  struct team_extra *t_extra;
  const unsigned char *row_attr = 0;
  int users_per_page, total_pages, current_page, user_on_page, dur_len;
  unsigned char **pgrefs = 0;
  int *pg_n1 = 0, *pg_n2 = 0;
  path_t stand_name, stand_tmp, stand_path;
  unsigned char att_buf[128];
  unsigned char *r_attrs[2][2] = { { "", "" }, { "", "" }};
  unsigned char *pr_attrs[4] = { "", "", "", ""};
  unsigned char *pc_attrs[2] = { "", "" };
  unsigned char *r0_attr = "", *rT_attr = "", *table_attr;
  int attr_num;
  int max_full, max_score;
  int *ind_full = 0, *ind_score = 0;
  int row_sz, row_sh, up_ind;
  int prev_prob = -1, row_ind = 0, group_ind = 1;
  int total_trans = 0;

  if (client_flag) head_style = cur_contest->team_head_style;
  else head_style = "h2";

  if (!global->stand_table_attr[0] && !global->stand_row_attr) {
    table_attr = " border=\"1\"";
  } else {
    table_attr = global->stand_table_attr;
  }

  attr_num = sarray_len(global->stand_row_attr);
  i = 0;
  if (attr_num >= 5) {
    r0_attr = global->stand_row_attr[i++];
    r_attrs[0][0] = global->stand_row_attr[i++];
    r_attrs[0][1] = global->stand_row_attr[i++];
    r_attrs[1][0] = global->stand_row_attr[i++];
    r_attrs[1][1] = global->stand_row_attr[i++];
    attr_num -= 5;
  }
  if (attr_num >= 1) {
    rT_attr = global->stand_row_attr[i++];
    attr_num -= 1;
  }

  attr_num = sarray_len(global->stand_page_row_attr);
  for (i = 0; i < 4 && i < attr_num; i++)
    pr_attrs[i] = global->stand_page_row_attr[i];
  attr_num = sarray_len(global->stand_page_col_attr);
  for (i = 0; i < 2 && i < attr_num; i++)
    pc_attrs[i] = global->stand_page_col_attr[i];

  /* Check that the contest is started */
  start_time = run_get_start_time();
  stop_time = run_get_stop_time();
  cur_time = time(0);

  if (!start_time || cur_time < start_time) {
    if (raw_flag) goto cleanup;
    if (!client_flag) write_standings_header(f, client_flag, 0, header_str, 0);    
    fprintf(f, "<%s>%s</%s>", head_style, _("The contest is not started"),
            head_style);
    if (!client_flag) {
      if (footer_str) {
        process_template(f, footer_str, 0, 0, 0, get_copyright());
      } else {
        fprintf(f, "</body></html>");
      }
    }
    goto cleanup;
  }

  if (start_time > cur_time) cur_time = start_time;
  if (stop_time && cur_time > stop_time) cur_time = stop_time;
  cur_duration = cur_time - start_time;

  /* The contest is started, so we can collect scores */

  /* download all runs in the whole */
  r_tot = run_get_total();
  runs = alloca(r_tot * sizeof(runs[0]));
  run_get_all_entries(runs);

  /* prune participants, which did not send any solution */
  /* t_runs - 1, if the participant should remain */
  t_max = teamdb_get_max_team_id() + 1;
  t_runs = alloca(t_max);
  if (global->prune_empty_users) {
    memset(t_runs, 0, t_max);
    for (k = 0; k < r_tot; k++) {
      if (runs[k].status == RUN_EMPTY || runs[k].status == RUN_VIRTUAL_START
          || runs[k].status == RUN_VIRTUAL_STOP) continue;
      if (runs[k].is_hidden) continue;
      if(runs[k].team <= 0 && runs[k].team >= t_max) continue;
      t_runs[runs[k].team] = 1;
    }
  } else {
    memset(t_runs, 1, t_max);
  }

  /* make team index */
  /* t_tot             - total number of teams in index array
   * t_max             - maximal possible number of teams
   * t_ind[0..t_tot-1] - index array:   team_idx -> team_id
   * t_rev[0..t_max-1] - reverse index: team_id -> team_idx
   */
  XALLOCAZ(t_ind, t_max);
  XALLOCAZ(t_rev, t_max);
  for (i = 1, t_tot = 0; i < t_max; i++) {
    t_rev[i] = -1;
    if (!teamdb_lookup(i)) continue;
    if ((teamdb_get_flags(i) & (TEAM_INVISIBLE | TEAM_BANNED))) continue;
    if (!t_runs[i]) continue;
    t_rev[i] = t_tot;
    t_ind[t_tot++] = i;
  }

  /* make problem index */
  /* p_tot             - total number of problems in index array
   * p_max             - maximal possible number of problems
   * p_ind[0..p_tot-1] - index array:   prob_idx -> prob_id
   * p_rev[0..p_max-1] - reverse index: prob_id -> prob_idx
   */
  p_max = max_prob + 1;
  XALLOCAZ(p_ind, p_max);
  XALLOCAZ(p_rev, p_max);
  for (i = 1, p_tot = 0; i < p_max; i++) {
    p_rev[i] = -1;
    if (!probs[i] || probs[i]->hidden) continue;
    p_rev[i] = p_tot;
    p_ind[p_tot++] = i;
  }

  /* calculate the power of 2 not less than p_tot */
  for (row_sz = 1, row_sh = 0; row_sz < p_tot; row_sz <<= 1, row_sh++);
  /* all two-dimensional arrays will have rows of size row_sz */

  /* calculation tables */
  /* prob_score[0..t_tot-1][0..p_tot-1] - maximum score for the problem
   * att_num[0..t_tot-1][0..p_tot-1]    - number of attempts made
   * tot_score[0..t_tot-1]              - total scores for teams
   * full_sol[0..t_tot-1][0..p_tot-1]   - 1, if full solution
   * tot_full[0..t_tot-1]               - total number of fully solved
   * sol_time[0..t_tot-1][0..p_tot-1]   - solution time
   * succ_att[0..p_tot-1]               - successfull attempts
   * tot_att[0..p_tot-1]                - total attempt
   * disq_num[0..t_tot-1][0..p_tot-1]   - number of disqualified attempts
   * sol_att[0..t_tot-1][0..p_tot-1]    - number of attempts before the problem solved
   */
  if (t_tot > 0) {
    up_ind = t_tot * row_sz;
    XCALLOC(prob_score, up_ind);
    XCALLOC(att_num, up_ind);
    XCALLOC(disq_num, up_ind);
    XCALLOC(full_sol, up_ind);
    XCALLOC(sol_time, up_ind);
    XCALLOC(sol_att, up_ind);
    XCALLOC(trans_num, up_ind);
  }
  XALLOCAZ(tot_score, t_tot);
  XALLOCAZ(tot_full, t_tot);
  XALLOCAZ(succ_att, p_tot);
  XALLOCAZ(tot_att, p_tot);

  /* auxiluary sorting stuff */
  /* t_sort[0..t_tot-1] - indices of teams (sorted)
   * t_n1[0..t_tot-1]   - first place in interval in case of ties
   * t_n2[0..t_tot-1]   - last place in interval in case of ties
   */
  XALLOCAZ(t_n1, t_tot);
  XALLOCAZ(t_n2, t_tot);

  for (k = 0; k < r_tot; k++) {
    int tind;
    int pind;
    int score, run_score, run_tests;
    struct section_problem_data *p;
    struct run_entry *pe = &runs[k];

    if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP
        || pe->status == RUN_EMPTY) continue;
    if (pe->team <= 0 || pe->team >= t_max) continue;
    if (pe->problem <= 0 || pe->problem > max_prob) continue;
    if (pe->is_hidden) continue;
    tind = t_rev[pe->team];
    pind = p_rev[pe->problem];
    up_ind = (tind << row_sh) + pind;
    p = probs[pe->problem];
    if (!p || tind < 0 || pind < 0 || p->hidden) continue;

    // ignore future runs when not in privileged mode
    if (!client_flag) {
      run_time = pe->timestamp;
      if (run_time < start_time) run_time = start_time;
      if (stop_time && run_time > stop_time) run_time = stop_time;
      if (run_time - start_time > cur_duration) continue;
      if (global->stand_ignore_after_d > 0
          && pe->timestamp >= global->stand_ignore_after_d)
        continue;
    }

    run_score = pe->score;
    run_tests = pe->test - 1;
    if (global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
      if (run_score < 0) run_score = 0;
      if (run_tests < 0) run_tests = 0;
      switch (pe->status) {
      case RUN_OK:
      case RUN_ACCEPTED:
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        full_sol[up_ind] = 1;
        prob_score[up_ind] = p->tests_to_accept;
        att_num[up_ind]++;  /* hmm, it is not used... */
        break;
      case RUN_PARTIAL:
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        if (run_tests > p->tests_to_accept) run_tests = p->tests_to_accept;
        if (run_tests > prob_score[up_ind]) 
          prob_score[up_ind] = run_tests;
        full_sol[up_ind] = 1;
        att_num[up_ind]++;
        break;
      case RUN_COMPILE_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        if (run_tests > p->tests_to_accept) run_tests = p->tests_to_accept;
        if (run_tests > prob_score[up_ind]) 
          prob_score[up_ind] = run_score;
        att_num[up_ind]++;
        break;
      case RUN_DISQUALIFIED:
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        disq_num[up_ind]++;
        break;
      case RUN_PENDING:
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        att_num[up_ind]++;
        trans_num[up_ind]++;
        break;
      case RUN_COMPILING:
      case RUN_RUNNING:
        trans_num[up_ind]++;
        break;
      default:
        break;
      }
    } else if (global->score_system_val == SCORE_OLYMPIAD) {
      if (run_score == -1) run_score = 0;
      switch (pe->status) {
      case RUN_OK:
        full_sol[up_ind] = 1;
        //if (run_score > p->full_score) run_score = p->full_score;
      case RUN_PARTIAL:
        prob_score[up_ind] = run_score;
        att_num[up_ind]++;
        break;
      case RUN_ACCEPTED:
        att_num[up_ind]++;
        break;
      case RUN_PENDING:
        att_num[up_ind]++;
        trans_num[up_ind]++;
        break;
      case RUN_COMPILE_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        att_num[up_ind]++;
        break;
      case RUN_DISQUALIFIED:
        disq_num[up_ind]++;
        break;
      case RUN_COMPILING:
      case RUN_RUNNING:
        trans_num[up_ind]++;
        break;
      default:
        break;
      }
    } else {
      if (run_score == -1) run_score = 0;
      if (pe->status == RUN_OK) {
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        score = calc_kirov_score(0, 0, pe, p, att_num[up_ind],
                                 disq_num[up_ind],
                                 full_sol[up_ind]?RUN_TOO_MANY:succ_att[pind],
                                 0);
        if (score > prob_score[up_ind]) {
          prob_score[up_ind] = score;
          if (!p->stand_hide_time) sol_time[up_ind] = pe->timestamp;
        }
        if (!sol_time[up_ind] && !p->stand_hide_time)
          sol_time[up_ind] = pe->timestamp;
        if (!full_sol[up_ind]) {
          succ_att[pind]++;
          tot_att[pind]++;
        }
        att_num[up_ind]++;
        full_sol[up_ind] = 1;
        last_submit_run = k;
        last_success_run = k;
      } else if (pe->status == RUN_PARTIAL) {
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        score = calc_kirov_score(0, 0, pe, p, att_num[up_ind],
                                 disq_num[up_ind], RUN_TOO_MANY, 0);
        if (score > prob_score[up_ind]) prob_score[up_ind] = score;
        att_num[up_ind]++;
        if (!full_sol[up_ind]) tot_att[pind]++;
        last_submit_run = k;
      } else if (pe->status==RUN_COMPILE_ERR&&!global->ignore_compile_errors) {
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        att_num[up_ind]++;
        if (!full_sol[up_ind]) tot_att[pind]++;
        last_submit_run = k;
      } else if (pe->status == RUN_DISQUALIFIED) {
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        disq_num[up_ind]++;
      } else if (pe->status == RUN_PENDING
                 || pe->status == RUN_COMPILING
                 || pe->status == RUN_RUNNING) {
        trans_num[up_ind]++;
        total_trans++;
      } else {
        /* something strange... */
      }
    }
  }

  /* compute the total for each team */
  for (i = 0; i < t_tot; i++) {
    for (j = 0; j < p_tot; j++) {
      up_ind = (i << row_sh) + j;
      tot_score[i] += prob_score[up_ind];
      tot_full[i] += full_sol[up_ind];
    }
  }

  if (t_tot > 0) {
    max_full = -1;
    max_score = -1;
    for (t = 0; t < t_tot; t++) {
      if (tot_full[t] > max_full) max_full = tot_full[t];
      if (tot_score[t] > max_score) max_score = tot_score[t];
    }
    XALLOCAZ(ind_full, max_full + 1);
    XALLOCAZ(ind_score, max_score + 1);
    for (t = 0; t < t_tot; t++) {
      ind_full[tot_full[t]]++;
      ind_score[tot_score[t]]++;
    }
    i = 0;
    for (t = max_full - 1; t >= 0; t--) {
      j = ind_full[t + 1] + i;
      ind_full[t + 1] = i;
      i = j;
    }
    ind_full[0] = i;
    i = 0;
    for (t = max_score - 1; t >= 0; t--) {
      j = ind_score[t + 1] + i;
      ind_score[t + 1] = i;
      i = j;
    }
    ind_score[0] = i;

    if (accepting_mode) {
      /* sort by the number of solved problems */
      XALLOCA(t_sort, t_tot);
      for (t = 0; t < t_tot; t++)
        t_sort[ind_full[tot_full[t]]++] = t;

      /* resolve ties */
      for(i = 0; i < t_tot;) {
        for (j = i + 1; j < t_tot; j++) {
          if (tot_full[t_sort[i]] != tot_full[t_sort[j]]) break;
        }
        for (k = i; k < j; k++) {
          t_n1[k] = i;
          t_n2[k] = j - 1;
        }
        i = j;
      }
    } else if (global->stand_sort_by_solved) {
      /* sort by the number of solved problems, then by the score */
      XALLOCA(t_sort, t_tot);
      XALLOCA(t_sort2, t_tot);
      for (t = 0; t < t_tot; t++)
        t_sort2[ind_score[tot_score[t]]++] = t;
      for (t = 0; t < t_tot; t++)
        t_sort[ind_full[tot_full[t_sort2[t]]]++] = t_sort2[t];

      /* resolve ties */
      for(i = 0; i < t_tot;) {
        for (j = i + 1; j < t_tot; j++) {
          if (tot_full[t_sort[i]] != tot_full[t_sort[j]]
              || tot_score[t_sort[i]] != tot_score[t_sort[j]]) break;
        }
        for (k = i; k < j; k++) {
          t_n1[k] = i;
          t_n2[k] = j - 1;
        }
        i = j;
      }
    } else {
      /* sort by the score */
      XALLOCA(t_sort, t_tot);
      for (t = 0; t < t_tot; t++)
        t_sort[ind_score[tot_score[t]]++] = t;

      /* resolve ties */
      for(i = 0; i < t_tot;) {
        for (j = i + 1; j < t_tot; j++) {
          if (tot_score[t_sort[i]] != tot_score[t_sort[j]]) break;
        }
        for (k = i; k < j; k++) {
          t_n1[k] = i;
          t_n2[k] = j - 1;
        }
        i = j;
      }
    }
  }


  if (raw_flag) {
    /* print table contents */
    for (i = 0; i < t_tot; i++) {
      int t = t_sort[i];

      fprintf(f, "%d;%d;", t_n1[i] + 1, t_n2[i] + 1);
      fprintf(f, "%d;", t_ind[t]);
      for (j = 0; j < p_tot; j++) {
        up_ind = (t << row_sh) + j;
        if (!att_num[up_ind]) {
          fprintf(f, "0;0;;");
        } else if (full_sol[up_ind]) {
          fprintf(f, "%d;1;%d;", att_num[up_ind], prob_score[up_ind]);
        } else {
          fprintf(f, "%d;0;%d;", att_num[up_ind], prob_score[up_ind]);
        }
      }
      fprintf(f, "%d;%d;", tot_full[t], tot_score[t]);
      fprintf(f, "\n");
    }
    goto cleanup;
  }

  /* print standings table */
  users_per_page = t_tot;
  total_pages = 1;
  current_page = 0;
  user_on_page = 0;
  if (!client_flag && global->users_on_page > 0) {
    users_per_page = global->users_on_page;
    total_pages = (t_tot + users_per_page - 1) / users_per_page;
    XALLOCA(pgrefs, total_pages);
    dur_len = snprintf(dur_str, sizeof(dur_str), global->standings_file_name, 1);
    pgrefs[0] = alloca(dur_len + 1);
    strcpy(pgrefs[0], dur_str);
    for (j = 2; j <= total_pages; j++) {
      dur_len = snprintf(dur_str, sizeof(dur_str), global->stand_file_name_2, j);
      pgrefs[j - 1] = alloca(dur_len + 1);
      strcpy(pgrefs[j - 1], dur_str);
    }
    XALLOCA(pg_n1, total_pages);
    XALLOCA(pg_n2, total_pages);
    for (j = 1; j <= total_pages; j++) {
      pg_n1[j - 1] = 1 + users_per_page * (j - 1);
      pg_n2[j - 1] = users_per_page * j;
    }
    pg_n2[total_pages - 1] = t_tot;
  }

  // no teams registered at all
  if (!t_tot) {
    if (!client_flag) write_standings_header(f, client_flag, 0, header_str, 0);
    /* print table header */
    fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
            table_attr, r0_attr,
            global->stand_place_attr, _("Place"),
            global->stand_team_attr, _("User "));
    if (global->stand_extra_format[0]) {
      if (global->stand_extra_legend[0])
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                global->stand_extra_legend);
      else
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                _("Extra info"));
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<th%s>%s</th>", global->stand_contestant_status_attr,
              _("Status"));
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<th%s>%s</th>", global->stand_warn_number_attr,
              _("Warnings"));
    }
    for (j = 0; j < p_tot; j++) {
      fprintf(f, "<th%s>", global->stand_prob_attr);
      if (global->prob_info_url[0]) {
        sformat_message(dur_str, sizeof(dur_str), global->prob_info_url,
                        NULL, probs[p_ind[j]], NULL, NULL, NULL, 0, 0, 0);
        fprintf(f, "<a href=\"%s\">", dur_str);
      }
      fprintf(f, "%s", probs[p_ind[j]]->short_name);
      if (global->prob_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</th>");
    }
    fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>\n",
            global->stand_solved_attr, _("Solved<br>problems"),
            global->stand_score_attr, _("Score"));
  }

  for (i = 0; i < t_tot; i++, user_on_page = (user_on_page + 1) % users_per_page) {
    if (!user_on_page) {
      current_page++;
      if (!f) {
        snprintf(stand_name, sizeof(stand_name), global->stand_file_name_2,
                 current_page);
        snprintf(stand_tmp, sizeof(stand_path), "%s/in/%s.tmp", stand_dir, stand_name);
        snprintf(stand_path, sizeof(stand_path), "%s/dir/%s", stand_dir, stand_name);
        if (!(f = sf_fopen(stand_tmp, "w"))) goto cleanup;
      }
      if (!client_flag) write_standings_header(f, client_flag, 0, header_str, 0);

      /* print "Last success" information */
      if (last_success_run >= 0) {
        duration_str(global->show_astr_time,
                     runs[last_success_run].timestamp, start_time,
                     dur_str, sizeof(dur_str));

        fprintf(f, "<p%s>%s: %s, ",
                global->stand_success_attr, _("Last success"), dur_str);
        if (global->team_info_url[0]) {
          teamdb_export_team(runs[last_success_run].team, &u_info);
          sformat_message(dur_str, sizeof(dur_str), global->team_info_url,
                          NULL, NULL, NULL, NULL, &u_info, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        fprintf(f, "%s", teamdb_get_name(runs[last_success_run].team));
        if (global->team_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ", ");

        if (global->prob_info_url[0]) {
          sformat_message(dur_str, sizeof(dur_str), global->prob_info_url,
                          NULL, probs[runs[last_success_run].problem],
                          NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        fprintf(f, "%s", probs[runs[last_success_run].problem]->short_name);
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ".</p>\n");
      }
      /* print "Last submit" information */
      if (last_submit_run >= 0) {
        duration_str(global->show_astr_time,
                     runs[last_submit_run].timestamp, start_time,
                     dur_str, sizeof(dur_str));
        fprintf(f, "<p%s>%s: %s, ",
                global->stand_success_attr, _("Last submit"), dur_str);
        if (global->team_info_url[0]) {
          teamdb_export_team(runs[last_submit_run].team, &u_info);
          sformat_message(dur_str, sizeof(dur_str), global->team_info_url,
                          NULL, NULL, NULL, NULL, &u_info, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        fprintf(f, "%s", teamdb_get_name(runs[last_submit_run].team));
        if (global->team_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ", ");

        if (global->prob_info_url[0]) {
          sformat_message(dur_str, sizeof(dur_str), global->prob_info_url,
                          NULL, probs[runs[last_submit_run].problem],
                          NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        fprintf(f, "%s", probs[runs[last_submit_run].problem]->short_name);
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ".</p>\n");
      }
      if (total_trans) {
        fprintf(f, "<p%s>%s: %d</p>",
                global->stand_success_attr, _("Runs being processed"), total_trans);
      }

      if (total_pages > 1) {
        fprintf(f, _("<p%s>Page %d of %d.</p>\n"),
                global->stand_page_cur_attr, current_page, total_pages);

        write_kirov_page_table(f, total_pages, current_page, pgrefs,
                               t_sort, tot_full, tot_score, pg_n1, pg_n2,
                               pr_attrs, pc_attrs);
      }

      /* print table header */
      fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
              table_attr, r0_attr,
              global->stand_place_attr, _("Place"),
              global->stand_team_attr, _("User "));
      if (global->stand_extra_format[0]) {
        if (global->stand_extra_legend[0])
          fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                  global->stand_extra_legend);
        else
          fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                  _("Extra info"));
      }
      if (global->stand_show_contestant_status
          && global->contestant_status_num > 0) {
        fprintf(f, "<th%s>%s</th>", global->stand_contestant_status_attr,
                _("Status"));
      }
      if (global->stand_show_warn_number) {
        fprintf(f, "<th%s>%s</th>", global->stand_warn_number_attr,
                _("Warnings"));
      }
      for (j = 0; j < p_tot; j++) {
        fprintf(f, "<th%s>", global->stand_prob_attr);
        if (global->prob_info_url[0]) {
          sformat_message(dur_str, sizeof(dur_str), global->prob_info_url,
                          NULL, probs[p_ind[j]], NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        fprintf(f, "%s", probs[p_ind[j]]->short_name);
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, "</th>");
      }
      fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>\n",
              global->stand_solved_attr, _("Solved<br>problems"),
              global->stand_score_attr, _("Score"));
    }

    /* print page contents */
    t = t_sort[i];

    if (global->team_info_url[0] || global->stand_extra_format[0]) {
      teamdb_export_team(t_ind[t], &u_info);
    } else {
      memset(&u_info, 0, sizeof(u_info));
    }
    if (global->stand_show_contestant_status
        || global->stand_show_warn_number
        || global->contestant_status_row_attr) {
      t_extra = team_extra_get_entry(t_ind[t]);
    } else {
      t_extra = 0;
    }
    if (tot_full[t] != prev_prob) {
      prev_prob = tot_full[t];
      group_ind ^= 1;
      row_ind = 0;
    } else {
      row_ind ^= 1;
    }
    row_attr = r_attrs[group_ind][row_ind];
    if (global->contestant_status_row_attr
        && t_extra && t_extra->status >= 0
        && t_extra->status < global->contestant_status_num) {
      row_attr = global->contestant_status_row_attr[t_extra->status];
    }
    fprintf(f, "<tr%s><td%s>", row_attr, global->stand_place_attr);
    if (t_n1[i] == t_n2[i]) fprintf(f, "%d", t_n1[i] + 1);
    else fprintf(f, "%d-%d", t_n1[i] + 1, t_n2[i] + 1);
    fputs("</td>", f);
    fprintf(f, "<td%s>", global->stand_team_attr);
    if (global->team_info_url[0]) {
      sformat_message(dur_str, sizeof(dur_str), global->team_info_url,
                      NULL, NULL, NULL, NULL, &u_info, 0, 0, 0);
      fprintf(f, "<a href=\"%s\">", dur_str);
    }
    fprintf(f, "%s", teamdb_get_name(t_ind[t]));
    if (global->team_info_url[0]) {
      fprintf(f, "</a>");
    }
    fprintf(f, "</td>");
    if (global->stand_extra_format[0]) {
      sformat_message(dur_str, sizeof(dur_str), global->stand_extra_format,
                      NULL, NULL, NULL, NULL, &u_info, 0, 0, 0);
      fprintf(f, "<td%s>%s</td>", global->stand_extra_attr, dur_str);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      if (t_extra && t_extra->status >= 0
          && t_extra->status < global->contestant_status_num) {
        fprintf(f, "<td%s>%s</td>", global->stand_contestant_status_attr,
                global->contestant_status_legend[t_extra->status]);
      } else {
        fprintf(f, "<td%s>?</td>", global->stand_contestant_status_attr);
      }
    }
    if (global->stand_show_warn_number) {
      if (t_extra && t_extra->warn_u > 0) {
        fprintf(f, "<td%s>%d</td>", global->stand_warn_number_attr,
                t_extra->warn_u);
      } else {
        fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
      }
    }
    for (j = 0; j < p_tot; j++) {
      up_ind = (t << row_sh) + j;
      row_attr = global->stand_prob_attr;
      if (trans_num[up_ind] && global->stand_trans_attr[0])
        row_attr = global->stand_trans_attr;
      if (!att_num[up_ind]) {
        fprintf(f, "<td%s>&nbsp;</td>", row_attr);
      } else if (full_sol[up_ind]) {
        att_buf[0] = 0;
        if (global->stand_show_att_num) {
          snprintf(att_buf, sizeof(att_buf), " (%d)", sol_att[up_ind]);
        }
        if (global->stand_show_ok_time && sol_time[up_ind] > 0) {
          duration_str(global->show_astr_time, sol_time[up_ind], start_time,
                       dur_str, 0);
          fprintf(f, "<td%s><b>%d</b>%s<div%s>%s</div></td>",
                  row_attr, prob_score[up_ind], att_buf,
                  global->stand_time_attr, dur_str);
        } else {
          fprintf(f, "<td%s><b>%d</b>%s</td>", row_attr, 
                  prob_score[up_ind], att_buf);
        }
      } else {
        att_buf[0] = 0;
        if (global->stand_show_att_num) {
          snprintf(att_buf, sizeof(att_buf), " (%d)", sol_att[up_ind]);
        }
        if (global->stand_show_ok_time && sol_time[up_ind] > 0) {
          duration_str(global->show_astr_time, sol_time[up_ind],
                       start_time, dur_str, 0);
          fprintf(f, "<td%s>%d%s<div%s>%s</div></td>",
                  row_attr, prob_score[up_ind], att_buf,
                  global->stand_time_attr, dur_str);
        } else {
          fprintf(f, "<td%s>%d%s</td>", row_attr, prob_score[up_ind], att_buf);
        }
      }
    }
    fprintf(f, "<td%s>%d</td><td%s>%d</td></tr>\n",
            global->stand_solved_attr, tot_full[t],
            global->stand_score_attr, tot_score[t]);

    if (user_on_page == users_per_page - 1 && current_page != total_pages) {
      fputs("</table>\n", f);

      write_kirov_page_table(f, total_pages, current_page, pgrefs,
                             t_sort, tot_full, tot_score, pg_n1, pg_n2,
                             pr_attrs, pc_attrs);

      if (!client_flag) {
        if (footer_str) {
          process_template(f, footer_str, 0, 0, 0, get_copyright());
        } else {
          fputs("</body></html>", f);
        }
      }
      if (current_page > 1) fclose(f);
      f = 0;
      if (current_page > 1) {
        rename(stand_tmp, stand_path);
      }
    }
  }

  // print row of total
  fprintf(f, "<tr%s>", rT_attr);
  fprintf(f, "<td%s>&nbsp;</td>", global->stand_place_attr);
  fprintf(f, "<td%s>%s:</td>", global->stand_team_attr, _("Total"));
  if (global->stand_extra_format[0]) {
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_extra_attr);
  }
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0) {
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_contestant_status_attr);
  }
  if (global->stand_show_warn_number) {
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
  }
  for (j = 0, ttot_att = 0; j < p_tot; j++) {
    fprintf(f, "<td%s>%d</td>", global->stand_prob_attr, tot_att[j]);
    ttot_att += tot_att[j];
  }
  fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          global->stand_solved_attr, ttot_att, global->stand_penalty_attr);
  // print row of success
  fprintf(f, "<tr%s>", rT_attr);
  fprintf(f, "<td%s>&nbsp;</td>", global->stand_place_attr);
  fprintf(f, "<td%s>%s:</td>", global->stand_team_attr, _("Success"));
  if (global->stand_extra_format[0]) {
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_extra_attr);
  }
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0) {
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_contestant_status_attr);
  }
  if (global->stand_show_warn_number) {
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
  }
  for (j = 0, ttot_succ = 0; j < p_tot; j++) {
    fprintf(f, "<td%s>%d</td>", global->stand_prob_attr, succ_att[j]);
    ttot_succ += succ_att[j];
  }
  fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          global->stand_solved_attr, ttot_succ, global->stand_penalty_attr);
  // print row of percentage
  fprintf(f, "<tr%s>", rT_attr);
  fprintf(f, "<td%s>&nbsp;</td>", global->stand_place_attr);
  fprintf(f, "<td%s>%%:</td>", global->stand_team_attr);
  if (global->stand_extra_format[0]) {
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_extra_attr);
  }
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0) {
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_contestant_status_attr);
  }
  if (global->stand_show_warn_number) {
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
  }
  for (j = 0; j < p_tot; j++) {
    perc = 0;
    if (tot_att[j] > 0) {
      perc = (int) ((double) succ_att[j] / tot_att[j] * 100.0 + 0.5);
    }
    fprintf(f, "<td%s>%d%%</td>", global->stand_prob_attr, perc);
  }
  perc = 0;
  if (ttot_att > 0) {
    perc = (int) ((double) ttot_succ / ttot_att * 100.0 + 0.5);
  }
  fprintf(f, "<td%s>%d%%</td><td%s>&nbsp;</td></tr>\n",
          global->stand_solved_attr, perc, global->stand_penalty_attr);

  fputs("</table>\n", f);

  if (!client_flag) {
    if (total_pages > 1)
      write_kirov_page_table(f, total_pages, current_page, pgrefs,
                             t_sort, tot_full, tot_score, pg_n1, pg_n2,
                             pr_attrs, pc_attrs);

    if (footer_str) {
      process_template(f, footer_str, 0, 0, 0, get_copyright());
    } else {
      fputs("</body></html>", f);
    }
  }
  if (total_pages > 1) {
    fclose(f); f = 0;
    rename(stand_tmp, stand_path); // FIXME: handle errors
  }

 cleanup:
  xfree(prob_score);
  xfree(att_num);
  xfree(disq_num);
  xfree(sol_att);
  xfree(full_sol);
  xfree(sol_time);
  xfree(trans_num);
}

static int
sec_to_min(int secs)
{
  switch (global->rounding_mode_val) {
  case SEC_CEIL:
    return (secs + 59) / 60;
  case SEC_FLOOR:
    return secs / 60;
  case SEC_ROUND:
    return (secs + 30) / 60;
  }
  abort();
}

static void
write_moscow_page_table(FILE *f, int total_pages, int current_page,
                        unsigned char **pgrefs,
                        int *pg_n1, int *pg_n2,
                        int *pg_sc1, int *pg_sc2,
                        int *pg_pen1, int *pg_pen2,
                        unsigned char **pr_attrs, unsigned char **pc_attrs)
{
  int j;

  fprintf(f, "<table%s>\n<tr%s><td%s>%s</td>",
          global->stand_page_table_attr, pr_attrs[0], pc_attrs[0], _("Page"));
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

void
do_write_moscow_standings(FILE *f,
                          const unsigned char *stand_dir,
                          int client_flag,
                          int user_id,
                          const unsigned char *header_str,
                          const unsigned char *footer_str,
                          int raw_flag,
                          const unsigned char *user_name)
{
  const unsigned char *head_style;
  time_t cur_time;
  time_t start_time;
  time_t stop_time;
  time_t contest_dur;
  time_t current_dur;
  time_t ustart;
  time_t udur = 0;
  time_t last_success_time = 0;
  time_t last_success_start = 0;
  time_t last_success_dur = 0;
  time_t last_submit_time = 0;
  time_t last_submit_start = 0;
  time_t last_submit_dur = 0;

  int r_tot;                    /* total number of runs */
  const struct run_entry *runs; /* the pointer to the PRIMARY runs storage */
  int u_max;                    /* maximal user_id + 1 */
  int u_tot;                    /* total active users */
  unsigned char *u_runs;        /* whether user submitted runs (on stack) */
  int *u_ind;                   /* active user num -> user_id map */
  int *u_rev;                   /* user_id -> active user num map */
  int p_max;                    /* maximal prob_id + 1 */
  int p_tot;                    /* total active problems */
  int *p_ind;                   /* active problem num -> prob_id map */
  int *p_rev;                   /* prob_id -> active problem num map */
  int row_sz;                   /* number of columns for two-dim. tables */
  int row_sh;                   /* shift count for two-dim. tables */
  int *u_sort;                  /* sorted index to u_ind */
  int *u_sort1;                 /* intermediate sorted index */
  int *u_score = 0;             /* total score for a user */
  int *u_pen = 0;               /* total penalty for a user */
  int *p_att;                   /* total attempts for a problem */
  int *p_succ;                  /* full solutions for a problem */
  int *pen_cnt;                 /* counters for all penalty values */
  int *pen_st;                  /* starting position for all penalty values */
  int *sc_cnt;                  /* counters for all score values */
  int *sc_st;                   /* starting position for all score values */
  int *u_n1;                    /* first place number */
  int *u_n2;                    /* second place number */
  int i, u, p, j, up_ind;       /* various index variables */
  int max_pen;                  /* maximal penalty for all users */
  int max_score;                /* maximal score for all users */
  int users_per_page;
  int total_pages;
  int current_page;
  int user_on_page;
  int all_att;
  int all_succ;
  unsigned char **pgrefs = 0;   /* file names for all stangings pages */
  int *pg_n1 = 0;               /* first place on a page */
  int *pg_n2 = 0;               /* last place on a page  */
  int *pg_sc1 = 0;              /* first score on a page */
  int *pg_sc2 = 0;              /* last score on a page */
  int *pg_pen1 = 0;             /* first penalty on a page */
  int *pg_pen2 = 0;             /* last penalty on a page */
  unsigned char strbuf[1024];   /* buffer for different purposes */
  size_t strbuflen;
  int last_success_run = -1;
  int last_submit_run = -1;
  struct teamdb_export u_info;
  struct team_extra *u_extra;
  path_t stand_tmp;             /* temporary file path */
  path_t stand_path;            /* final path for a standings page */
  unsigned char *row_attr;
  unsigned char *r_attrs[2][2] = { { "", ""}, { "", "" }};
  unsigned char *pr_attrs[4] = { "", "", "", "" };
  unsigned char *pc_attrs[2] = { "", "" };
  unsigned char *r0_attr = "", *rT_attr = "", *table_attr;
  int attr_num;
  int prev_prob = -1, row_ind = 0, group_ind = 1;

  /* variables, that must be freed */
  int *up_score = 0;            /* the best score gained by a user for a problem */
  int *up_att = 0;              /* attempts used to gain the best score */
  int *up_totatt = 0;           /* attempts to gain a better score */
  int *up_time = 0;             /* time for a best score by a user for a problem */
  int *up_pen = 0;              /* penalty for a best score by a user  */
  unsigned char *up_solved = 0; /* whether a problem was completely soved by a user */
  unsigned char *up_trans = 0;  /* whether there exist transient runs */
  unsigned char *up_cf = 0;     /* whether there exist "Check failed" messages */
  
  if (client_flag) head_style = cur_contest->team_head_style;
  else head_style = "h2";

  if (!global->stand_table_attr[0] && !global->stand_row_attr) {
    table_attr = " border=\"1\"";
  } else {
    table_attr = global->stand_table_attr;
  }

  attr_num = sarray_len(global->stand_row_attr);
  i = 0;
  if (attr_num >= 5) {
    r0_attr = global->stand_row_attr[i++];
    r_attrs[0][0] = global->stand_row_attr[i++];
    r_attrs[0][1] = global->stand_row_attr[i++];
    r_attrs[1][0] = global->stand_row_attr[i++];
    r_attrs[1][1] = global->stand_row_attr[i++];
    attr_num -= 5;
  }
  if (attr_num >= 1) {
    rT_attr = global->stand_row_attr[i++];
    attr_num -= 1;
  }

  attr_num = sarray_len(global->stand_page_row_attr);
  for (i = 0; i < 4 && i < attr_num; i++)
    pr_attrs[i] = global->stand_page_row_attr[i];
  attr_num = sarray_len(global->stand_page_col_attr);
  for (i = 0; i < 2 && i < attr_num; i++)
    pc_attrs[i] = global->stand_page_col_attr[i];

  cur_time = time(0);
  last_submit_start = last_success_start = start_time = run_get_start_time();
  stop_time = run_get_stop_time();
  contest_dur = run_get_duration();
  if (start_time && global->virtual && user_id > 0) {
    start_time = run_get_virtual_start_time(user_id);
    stop_time = run_get_virtual_stop_time(user_id, 0);
  }
  if (start_time && !stop_time && cur_time >= start_time + contest_dur) {
    stop_time = start_time + contest_dur;
  }
  if (start_time && cur_time < start_time) {
    cur_time = start_time;
  }
  if (stop_time && cur_time > stop_time) {
    cur_time = stop_time;
  }
  current_dur = cur_time - start_time;
  if (!start_time) {
    if (raw_flag) return;
    write_standings_header(f, client_flag, user_id, header_str, user_name);
    fprintf(f, "<%s>%s</%s>", head_style, _("The contest is not started"),
            head_style);
    if (!client_flag) {
      if (footer_str) {
        process_template(f, footer_str, 0, 0, 0, get_copyright());
      } else {
        fprintf(f, "</body></html>");
      }
    }
    return;
  }

  r_tot = run_get_total();
  runs = run_get_entries_ptr();

  u_max = teamdb_get_max_team_id() + 1;
  u_runs = (unsigned char*) alloca(u_max);
  if (global->prune_empty_users) {
    memset(u_runs, 0, u_max);
    for (i = 0; i < r_tot; i++)
      if (runs[i].status != RUN_EMPTY
          && runs[i].team > 0 && runs[i].team < u_max
          && !runs[i].is_hidden)
        u_runs[runs[i].team] = 1;
  } else {
    memset(u_runs, 1, u_max);
  }

  /* make users index */
  XALLOCA(u_ind, u_max);
  XALLOCA(u_rev, u_max);
  memset(u_rev, -1, u_max * sizeof(u_rev[0]));
  for (i = 1, u_tot = 0; i < u_max; i++)
    if (teamdb_lookup(i) > 0
        && !(teamdb_get_flags(i) & (TEAM_INVISIBLE | TEAM_BANNED))
        && u_runs[i]) {
      u_rev[i] = u_tot;
      u_ind[u_tot] = i;
      u_tot++;
    }

  /* sorted index to u_ind */
  XALLOCA(u_sort, u_tot);
  for (i = 0; i < u_tot; i++)
    u_sort[i] = i;

  /* make problems index */
  p_max = max_prob + 1;
  XALLOCA(p_ind, p_max);
  XALLOCA(p_rev, p_max);
  memset(p_rev, -1, p_max * sizeof(p_rev[0]));
  for (i = 1, p_tot = 0; i < p_max; i++)
    if (probs[i] && !probs[i]->hidden) {
      p_rev[i] = p_tot;
      p_ind[p_tot] = i;
      p_tot++;
    }

  /* calculate the power of 2 not less than p_tot */
  for (row_sz = 1, row_sh = 0; row_sz < p_tot; row_sz <<= 1, row_sh++);
  /* all two-dimensional arrays will have rows of size row_sz */

  if (u_tot > 0) {
    /* the best score gained by a user for a problem */
    XCALLOC(up_score, row_sz * u_tot);
    /* attempts used to gain the best score */
    XCALLOC(up_att, row_sz * u_tot);
    /* attempts to gain a better score */
    XCALLOC(up_totatt, row_sz * u_tot);
    /* total score for a user */
    XALLOCAZ(u_score, u_tot);
    /* time for the best score received by a user for a problem */
    XCALLOC(up_time, row_sz * u_tot);
    /* penalty for the best score received by a user for a problem (minutes) */
    XCALLOC(up_pen, row_sz * u_tot);
    /* total penalty for a user */
    XALLOCAZ(u_pen, u_tot);
    /* 1, if a user fully solved a problem */
    XCALLOC(up_solved, row_sz * u_tot);
    /* 1, if there are transient runs for a user and a problem */
    XCALLOC(up_trans, row_sz * u_tot);
    /* 1, if there are "Check failed" messages */
    XCALLOC(up_cf, row_sz * u_tot);
  }

  /* total attempts for a problem */
  XALLOCAZ(p_att, p_tot);
  /* full solutions for a problem */
  XALLOCAZ(p_succ, p_tot);

  for (i = 0; i < r_tot; i++) {
    const struct run_entry *pe = &runs[i];
    time_t run_time = pe->timestamp;
    const struct section_problem_data *prob;
    int up_ind;

    if (pe->is_hidden) continue;
    if (pe->status > RUN_MAX_STATUS && pe->status < RUN_TRANSIENT_FIRST) continue;
    if (pe->status > RUN_TRANSIENT_LAST) continue;
    if (pe->team <= 0 || pe->team >= u_max || (u = u_rev[pe->team]) < 0) continue;
    if (pe->problem <= 0 || pe->problem > max_prob) continue;
    if ((p = p_rev[pe->problem]) < 0) continue;
    prob = probs[pe->problem];
    up_ind = (u << row_sh) + p;

    if (up_solved[up_ind]) continue;
    if (pe->status >= RUN_TRANSIENT_FIRST && pe->status <= RUN_TRANSIENT_LAST) {
      up_trans[up_ind] = 1;
      continue;
    }
    if (pe->status == RUN_PENDING) {
      up_trans[up_ind] = 1;
      continue;
    }
    ustart = start_time;
    if (global->virtual) {
      // filter "future" virtual runs
      ustart = run_get_virtual_start_time(pe->team);
      if (run_time < ustart) run_time = ustart;
      udur = run_time - ustart;
      if (udur > contest_dur) udur = contest_dur;
      if (user_id > 0 && udur > current_dur) continue;
    } else if (client_flag != 1 || user_id) {
      // filter future real runs for unprivileged standings
      if (run_time < start_time) run_time = start_time;
      udur = run_time - start_time;
      if (current_dur > 0 && udur > current_dur) continue;
      if (global->stand_ignore_after_d > 0
          && pe->timestamp >= global->stand_ignore_after_d)
        continue;
    } else {
      if (run_time < start_time) run_time = start_time;
      udur = run_time - start_time;
    }

    if (pe->status == RUN_OK) {
      up_solved[up_ind] = 1;
      up_att[up_ind] = up_totatt[up_ind];
      up_pen[up_ind] = sec_to_min(udur);
      up_time[up_ind] = run_time;
      up_totatt[up_ind]++;
      up_score[up_ind] = prob->full_score;
      if (prob->variable_full_score) up_score[up_ind] = pe->score;
      p_att[p]++;
      p_succ[p]++;
      if (!global->virtual) {
        last_success_run = i;
        last_success_time = pe->timestamp;
        last_success_start = ustart;
        last_success_dur = udur;
        last_submit_run = i;
        last_submit_time = pe->timestamp;
        last_submit_start = ustart;
        last_submit_dur = udur;
      }
    } else if (run_is_failed_attempt(pe->status)) {
      if (pe->score > up_score[up_ind]) {
        up_att[up_ind] = up_totatt[up_ind];
        up_pen[up_ind] = sec_to_min(udur);
        up_time[up_ind] = run_time;
        up_score[up_ind] = pe->score;
      }
      up_totatt[up_ind]++;
      p_att[p]++;
      if (!global->virtual) {
        last_submit_run = i;
        last_submit_time = pe->timestamp;
        last_submit_start = ustart;
        last_submit_dur = udur;
      }
    } else if (pe->status == RUN_COMPILE_ERR && !global->ignore_compile_errors) {
      up_totatt[up_ind]++;
      p_att[p]++;
      if (!global->virtual) {
        last_submit_run = i;
        last_submit_time = pe->timestamp;
        last_submit_start = ustart;
        last_submit_dur = udur;
      }
    } else if (pe->status == RUN_COMPILE_ERR) {
      // silently ignore compilation error
    } else if (pe->status == RUN_CHECK_FAILED) {
      up_cf[up_ind] = 1;
    } else {
      // FIXME: do some checking
      // silently ignore such run
    }
  }

  /* calculate the total penalty and the total score */
  for (u = 0; u < u_tot; u++)
    for (p = 0; p < p_tot; p++) {
      u_score[u] += up_score[(u << row_sh) + p];
      if (!global->ignore_success_time) u_pen[u] += up_pen[(u << row_sh) + p];
      u_pen[u] += 20 * up_att[(u << row_sh) + p];
    }

  /* sort the users in descending order by score and ascending order by penalty */
  /* 1. bucket sort by penalty */
  max_pen = -1;
  XALLOCAZ(u_sort1, u_tot);
  for (u = 0; u < u_tot; u++)
    if (u_pen[u] > max_pen)
      max_pen = u_pen[u];
  if (max_pen >= 0) {
    XALLOCAZ(pen_cnt, max_pen + 1);
    XALLOCAZ(pen_st, max_pen + 1);
    for (u = 0; u < u_tot; u++)
      pen_cnt[u_pen[u]]++;
    for (i = 1; i <= max_pen; i++)
      pen_st[i] = pen_cnt[i - 1] + pen_st[i - 1];
    for (u = 0; u < u_tot; u++)
      u_sort1[pen_st[u_pen[u]]++] = u;
  }
  /* 2. bucket sort by score in descending order */
  max_score = -1;
  for (u = 0; u < u_tot; u++)
    if (u_score[u] > max_score)
      max_score = u_score[u];
  if (max_score >= 0) {
    XALLOCAZ(sc_cnt, max_score + 1);
    XALLOCAZ(sc_st, max_score + 1);
    for (u = 0; u < u_tot; u++)
      sc_cnt[u_score[u]]++;
    for (i = max_score - 1; i >= 0; i--)
      sc_st[i] = sc_cnt[i + 1] + sc_st[i + 1];
    for (u = 0; u < u_tot; u++)
      u_sort[sc_st[u_score[u_sort1[u]]]++] = u_sort1[u];
  }

  /* resolve the ties */
  XALLOCA(u_n1, u_tot);
  XALLOCA(u_n2, u_tot);
  for (u = 0; u < u_tot; ) {
    for (i = u + 1;
         i < u_tot
           && u_score[u_sort[u]] == u_score[u_sort[i]]
           && u_pen[u_sort[u]] == u_pen[u_sort[i]];
         i++);
    for (j = u; j < i; j++) {
      u_n1[j] = u;
      u_n2[j] = i - 1;
    }
    u = i;
  }

  if (raw_flag) {
    for (i = 0; i < u_tot; i++) {
      u = u_sort[i];
      fprintf(f, "%d;%d;%d;", u_n1[i] + 1, u_n2[i] + 1, u_ind[u]);
      for (p = 0; p < p_tot; p++) {
        up_ind = (u << row_sh) + p;
        fprintf(f, "%d;%d;%d;%d;%d;", up_solved[up_ind],
                up_score[up_ind], up_att[up_ind], up_time[up_ind],
                up_totatt[up_ind]);
      }
      fprintf(f, "%d;%d;\n", u_score[u], u_pen[u]);
    }
    goto free_resorces;
  }

  users_per_page = u_tot;
  total_pages = 1;
  current_page = 0;
  user_on_page = 0;
  if (!client_flag && !user_id && global->users_on_page > 0) {
    users_per_page = global->users_on_page;
    total_pages = (u_tot + users_per_page - 1) / users_per_page;
    XALLOCA(pgrefs, total_pages);
    XALLOCA(pg_n1, total_pages);
    XALLOCA(pg_n2, total_pages);
    XALLOCA(pg_sc1, total_pages);
    XALLOCA(pg_sc2, total_pages);
    XALLOCA(pg_pen1, total_pages);
    XALLOCA(pg_pen2, total_pages);

    strbuflen = snprintf(strbuf, sizeof(strbuf), global->standings_file_name, 1);
    pgrefs[0] = (unsigned char*) alloca(strbuflen + 1);
    strcpy(pgrefs[0], strbuf);
    for (j = 1; j < total_pages; j++) {
      strbuflen = snprintf(strbuf, sizeof(strbuf), global->stand_file_name_2, j + 1);
      pgrefs[j] = (unsigned char*) alloca(strbuflen + 1);
      strcpy(pgrefs[j], strbuf);
    }
    for (j = 0; j < total_pages; j++) {
      u = u_sort[users_per_page * j];
      pg_n1[j] = users_per_page * j;
      pg_sc1[j] = u_score[u];
      pg_pen1[j] = u_pen[u];
      i = users_per_page*(j + 1) - 1;
      if (i >= u_tot) i = u_tot - 1;
      u = u_sort[i];
      pg_n2[j] = i;
      pg_sc2[j] = u_score[u];
      pg_pen2[j] = u_pen[u];
    }
  }

  if (!u_tot) {
    write_standings_header(f, client_flag, user_id, header_str, user_name);
    /* print the table header */
    fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
            table_attr, r0_attr,
            global->stand_place_attr, _("Place"),
            global->stand_team_attr, _("Participant"));
    if (global->stand_extra_format[0]) {
      if (global->stand_extra_legend[0])
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                global->stand_extra_legend);
      else
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                _("Extra info"));
    }
    if (global->stand_show_contestant_status && global->contestant_status_num > 0)
      fprintf(f, "<th%s>%s</th>", global->stand_contestant_status_attr,
              _("Status"));
    if (global->stand_show_warn_number)
      fprintf(f, "<th%s>%s</th>", global->stand_warn_number_attr,
              _("Warnings"));
    for (j = 0; j < p_tot; j++) {
      fprintf(f, "<th%s>", global->stand_prob_attr);
      if (global->prob_info_url[0]) {
        sformat_message(strbuf, sizeof(strbuf), global->prob_info_url,
                        NULL, probs[p_ind[j]], NULL, NULL, NULL, 0, 0, 0);
        fprintf(f, "<a href=\"%s\">", strbuf);
      }
      fprintf(f, "%s", probs[p_ind[j]]->short_name);
      if (global->prob_info_url[0])
        fprintf(f, "</a>");
      fprintf(f, "</th>");
    }
    fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>\n",
            global->stand_score_attr, _("Score"),
            global->stand_penalty_attr, _("Penalty"));
  }

  for (i = 0; i < u_tot; i++, user_on_page = (user_on_page + 1) % users_per_page) {
    if (!user_on_page) {
      current_page++;
      if (!f) {
        snprintf(stand_tmp, sizeof(stand_tmp), "%s/in/%s.tmp",
                 stand_dir, pgrefs[current_page - 1]);
        snprintf(stand_path, sizeof(stand_path), "%s/dir/%s", stand_dir,
                 pgrefs[current_page - 1]);
        if (!(f = sf_fopen(stand_tmp, "w"))) return;
      }
      if (!client_flag)
        write_standings_header(f, client_flag, user_id, header_str, user_name);
      /* print "Last success" information */
      if (last_success_run >= 0) {
        if (global->virtual && !user_id) {
          duration_str(1, last_success_time, last_success_start,
                       strbuf, sizeof(strbuf));
        } else {
          duration_str(global->show_astr_time, last_success_time, last_success_start,
                       strbuf, sizeof(strbuf));
        }
        fprintf(f, "<p%s>%s: %s, ",
                global->stand_success_attr, _("Last success"), strbuf);
        if (global->team_info_url[0]) {
          teamdb_export_team(runs[last_success_run].team, &u_info);
          sformat_message(strbuf, sizeof(strbuf), global->team_info_url,
                          NULL, NULL, NULL, NULL, &u_info, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        fprintf(f, "%s", teamdb_get_name(runs[last_success_run].team));
        if (global->team_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ", ");

        if (global->prob_info_url[0]) {
          sformat_message(strbuf, sizeof(strbuf), global->prob_info_url,
                          NULL, probs[runs[last_success_run].problem],
                          NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        fprintf(f, "%s", probs[runs[last_success_run].problem]->short_name);
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ".</p>\n");
      }
      /* print "Last submit" information */
      if (last_submit_run >= 0) {
        if (global->virtual && !user_id) {
          duration_str(1, last_submit_time, last_submit_start,
                       strbuf, sizeof(strbuf));
        } else {
          duration_str(global->show_astr_time, last_submit_time, last_submit_start,
                       strbuf, sizeof(strbuf));
        }
        fprintf(f, "<p%s>%s: %s, ",
                global->stand_success_attr, _("Last submit"), strbuf);
        if (global->team_info_url[0]) {
          teamdb_export_team(runs[last_submit_run].team, &u_info);
          sformat_message(strbuf, sizeof(strbuf), global->team_info_url,
                          NULL, NULL, NULL, NULL, &u_info, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        fprintf(f, "%s", teamdb_get_name(runs[last_submit_run].team));
        if (global->team_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ", ");

        if (global->prob_info_url[0]) {
          sformat_message(strbuf, sizeof(strbuf), global->prob_info_url,
                          NULL, probs[runs[last_submit_run].problem],
                          NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        fprintf(f, "%s", probs[runs[last_submit_run].problem]->short_name);
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ".</p>\n");
      }
      /* print page number information and references */
      if (total_pages > 1) {
        fprintf(f, _("<p%s>Page %d of %d.</p>\n"),
                global->stand_page_cur_attr, current_page, total_pages);

        write_moscow_page_table(f, total_pages, current_page,
                                pgrefs, pg_n1, pg_n2, pg_sc1, pg_sc2,
                                pg_pen1, pg_pen2, pr_attrs, pc_attrs);
      }

      /* print the table header */
      fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
              table_attr, r0_attr,
              global->stand_place_attr, _("Place"),
              global->stand_team_attr, _("User "));
      if (global->stand_extra_format[0]) {
        if (global->stand_extra_legend[0])
          fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                  global->stand_extra_legend);
        else
          fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                  _("Extra info"));
      }
      if (global->stand_show_contestant_status && global->contestant_status_num > 0)
        fprintf(f, "<th%s>%s</th>", global->stand_contestant_status_attr,
                _("Status"));
      if (global->stand_show_warn_number)
        fprintf(f, "<th%s>%s</th>", global->stand_warn_number_attr,
                _("Warnings"));
      for (j = 0; j < p_tot; j++) {
        fprintf(f, "<th%s>", global->stand_prob_attr);
        if (global->prob_info_url[0]) {
          sformat_message(strbuf, sizeof(strbuf), global->prob_info_url,
                          NULL, probs[p_ind[j]], NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        fprintf(f, "%s", probs[p_ind[j]]->short_name);
        if (global->prob_info_url[0])
          fprintf(f, "</a>");
        fprintf(f, "</th>");
      }
      fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>\n",
              global->stand_score_attr, _("Score"),
              global->stand_penalty_attr, _("Penalty"));
    }

    // print the standings row
    u = u_sort[i];

    if (global->team_info_url[0] || global->stand_extra_format[0]) {
      teamdb_export_team(u_ind[u], &u_info);
    } else {
      memset(&u_info, 0, sizeof(u_info));
    }
    u_extra = 0;
    if (global->stand_show_contestant_status
        || global->stand_show_warn_number
        || global->contestant_status_row_attr)
      u_extra = team_extra_get_entry(u_ind[u]);
    /* FIXME: consider virtual and real users */
    if (prev_prob != u_score[u]) {
      prev_prob = u_score[u];
      group_ind ^= 1;
      row_ind = 0;
    } else {
      row_ind ^= 1;
    }
    row_attr = r_attrs[group_ind][row_ind];
    if (global->contestant_status_row_attr
        && u_extra && u_extra->status >= 0
        && u_extra->status < global->contestant_status_num)
      row_attr = global->contestant_status_row_attr[u_extra->status];
    fprintf(f, "<tr%s><td%s>", row_attr, global->stand_place_attr);
    if (u_n1[i] == u_n2[i]) fprintf(f, "%d", u_n1[i] + 1);
    else fprintf(f, "%d-%d", u_n1[i] + 1, u_n2[i] + 1);
    fprintf(f, "</td><td%s>", global->stand_team_attr);
    if (global->team_info_url[0]) {
      sformat_message(strbuf, sizeof(strbuf), global->team_info_url,
                      NULL, NULL, NULL, NULL, &u_info, 0, 0, 0);
      fprintf(f, "<a href=\"%s\">", strbuf);
    }
    fprintf(f, "%s", teamdb_get_name(u_ind[u]));
    if (global->team_info_url[0]) {
      fprintf(f, "</a>");
    }
    fprintf(f, "</td>");
    if (global->stand_extra_format[0]) {
      sformat_message(strbuf, sizeof(strbuf), global->stand_extra_format,
                      NULL, NULL, NULL, NULL, &u_info, 0, 0, 0);
      fprintf(f, "<td%s>%s</td>", global->stand_extra_attr, strbuf);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      if (u_extra && u_extra->status >= 0
          && u_extra->status < global->contestant_status_num) {
        fprintf(f, "<td%s>%s</td>", global->stand_contestant_status_attr,
                global->contestant_status_legend[u_extra->status]);
      } else {
        fprintf(f, "<td%s>?</td>", global->stand_contestant_status_attr);
      }
    }
    if (global->stand_show_warn_number) {
      if (u_extra && u_extra->warn_u > 0) {
        fprintf(f, "<td%s>%d</td>", global->stand_warn_number_attr,
                u_extra->warn_u);
      } else {
        fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
      }
    }

    for (j = 0; j < p_tot; j++) {
      up_ind = (u << row_sh) + j;

      row_attr = global->stand_prob_attr;
      if (up_trans[up_ind] && global->stand_trans_attr[0])
        row_attr = global->stand_trans_attr;
      if (up_cf[up_ind] && global->stand_fail_attr[0])
        row_attr = global->stand_fail_attr;
      fprintf(f, "<td%s>", row_attr);

      if (!up_totatt[up_ind]) {
        fprintf(f, "&nbsp;");
      } else if (up_solved[up_ind]) {
        if (global->stand_show_ok_time && up_time[up_ind] > 0) {
          if (global->show_astr_time) {
            duration_str(1, up_time[up_ind], start_time, strbuf, 0);
          } else {
            snprintf(strbuf, sizeof(strbuf), "%d:%02d",
                     up_pen[up_ind] / 60, up_pen[up_ind] % 60);
          }
          fprintf(f, "<b>%d</b> <div%s>(%d,%s)</div>",
                  up_score[up_ind], global->stand_time_attr,
                  up_att[up_ind] + 1, strbuf);
        } else
          fprintf(f, "<b>%d</b> <div%s>(%d)</div>", up_score[up_ind],
                  global->stand_time_attr, up_att[up_ind] + 1);
      } else if (up_score[up_ind] > 0) {
        if (global->stand_show_ok_time && up_time[up_ind] > 0) {
          if (global->show_astr_time) {
            duration_str(1, up_time[up_ind], start_time, strbuf, 0);
          } else {
            snprintf(strbuf, sizeof(strbuf), "%d:%02d",
                     up_pen[up_ind] / 60, up_pen[up_ind] % 60);
          }
          fprintf(f, "%d <div%s>(%d,%s)</div> -%d",
                  up_score[up_ind], global->stand_time_attr, up_att[up_ind] + 1,
                  strbuf, up_totatt[up_ind]);
        } else
          fprintf(f, "%d <div%s>(%d)</div> -%d",
                  up_score[up_ind], global->stand_time_attr, up_att[up_ind] + 1,
                  up_totatt[up_ind]);
      } else
        fprintf(f, "0 -%d", up_totatt[up_ind]);

      fprintf(f, "</td>");
    }

    fprintf(f, "<td%s>%d</td><td%s>%d</td></tr>\n",
            global->stand_score_attr, u_score[u],
            global->stand_penalty_attr, u_pen[u]);

    if (user_on_page == users_per_page - 1 && current_page != total_pages) {
      fputs("</table>\n", f);
      if (!client_flag) {
        write_moscow_page_table(f, total_pages, current_page,
                                pgrefs, pg_n1, pg_n2, pg_sc1, pg_sc2,
                                pg_pen1, pg_pen2, pr_attrs, pc_attrs);
        if (footer_str) {
          process_template(f, footer_str, 0, 0, 0, get_copyright());
        } else {
          fputs("</body></html>", f);
        }
      }
      if (current_page > 1) fclose(f);
      f = 0;
      if (current_page > 1) {
        rename(stand_tmp, stand_path);
      }
    }
  }

  fprintf(f, "<tr%s><td%s>&nbsp;</td><td%s>%s:</td>", rT_attr,
          global->stand_place_attr, global->stand_team_attr, _("Total"));
  if (global->stand_extra_format[0])
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_extra_attr);
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0)
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_contestant_status_attr);
  if (global->stand_show_warn_number)
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
  for (j = 0, all_att = 0; j < p_tot; j++) {
    fprintf(f, "<td%s>%d</td>", global->stand_prob_attr, p_att[j]);
    all_att += p_att[j];
  }
  fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          global->stand_solved_attr, all_att, global->stand_penalty_attr);

  fprintf(f, "<tr%s><td%s>&nbsp;</td><td%s>%s:</td>", rT_attr,
          global->stand_place_attr, global->stand_team_attr, _("Success"));
  if (global->stand_extra_format[0])
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_extra_attr);
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0)
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_contestant_status_attr);
  if (global->stand_show_warn_number)
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
  for (j = 0, all_succ = 0; j < p_tot; j++) {
    fprintf(f, "<td%s>%d</td>", global->stand_prob_attr, p_succ[j]);
    all_succ += p_succ[j];
  }
  fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          global->stand_solved_attr, all_succ, global->stand_penalty_attr);

  fprintf(f, "<tr%s><td%s>&nbsp;</td><td%s>%%:</td>", rT_attr,
          global->stand_place_attr, global->stand_team_attr);
  if (global->stand_extra_format[0])
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_extra_attr);
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0)
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_contestant_status_attr);
  if (global->stand_show_warn_number)
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
  for (j = 0; j < p_tot; j++) {
    if (!p_att[j])
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_prob_attr);
    else
      fprintf(f, "<td%s>%d%%</td>", global->stand_prob_attr,
              (int)(p_succ[j] * 100.0 / p_att[j] + 0.5));
  }
  if (!all_att)
    fprintf(f, "<td%s>&nbsp;</td><td%s>&nbsp;</td></tr>\n",
            global->stand_solved_attr, global->stand_penalty_attr);
  else
    fprintf(f, "<td%s>%d%%</td><td%s>&nbsp;</td></tr>\n",
            global->stand_solved_attr,
            (int)(all_succ * 100.0 / all_att + 0.5),
            global->stand_penalty_attr);
  
  fputs("</table>\n", f);
  if (!client_flag) {
    if (total_pages > 1) {
      write_moscow_page_table(f, total_pages, current_page,
                              pgrefs, pg_n1, pg_n2, pg_sc1, pg_sc2,
                              pg_pen1, pg_pen2, pr_attrs, pc_attrs);
    }
    if (footer_str) {
      process_template(f, footer_str, 0, 0, 0, get_copyright());
    } else {
      fputs("</body></html>", f);
    }
  }
  if (total_pages > 1) {
    fclose(f); f = 0;
    rename(stand_tmp, stand_path);
  }

 free_resorces:
  xfree(up_cf);
  xfree(up_trans);
  xfree(up_solved);
  xfree(up_score);
  xfree(up_att);
  xfree(up_totatt);
  xfree(up_time);
  xfree(up_pen);
}

/*
 * ACM-style standings
 */
void
do_write_standings(FILE *f, int client_flag, int user_id,
                   const unsigned char *header_str,
                   unsigned char const *footer_str, int raw_flag,
                   const unsigned char *user_name)
{
  int      i, j, t;

  int     *t_ind;
  int      t_max;
  int      t_tot;
  int     *t_prob;
  int     *t_pen;
  int     *t_rev;
  int     *t_sort = 0;
  int     *t_sort2;
  int     *prob_cnt;
  int     *pen_cnt;
  int      max_pen, max_solved;
  int     *t_n1;
  int     *t_n2;
  int     *p_ind;
  int     *p_rev;
  int      p_max;
  int      p_tot;
  int      r_tot, k;
  int      tt, pp;
  int      ttot_att, ttot_succ, perc;

  time_t *ok_time = 0;
  int    *calc = 0;

  time_t start_time;
  time_t stop_time;
  time_t cur_time;
  time_t        contest_dur;
  time_t        current_dur, run_time;
  time_t        tdur = 0, tstart = 0;

  char          url_str[1024];
  unsigned char *bgcolor_ptr;
  unsigned char *head_style;
  struct teamdb_export ttt;      
  struct run_entry *runs, *pe;
  unsigned char *t_runs;
  int last_success_run = -1;
  time_t last_success_time = 0;
  time_t last_success_start = 0;
  int *tot_att, *succ_att;
  struct team_extra *t_extra;
  unsigned char *r0_attr = "", *rT_attr = "", *table_attr;
  unsigned char *r_attrs[2][2] = {{"", ""}, {"", ""}};
  int row_sh, row_sz, up_ind, attr_num;
  int prev_prob = -1, row_ind = 0, group_ind = 1;

  write_standings_header(f, client_flag, user_id, header_str, user_name);

  if (client_flag) head_style = cur_contest->team_head_style;
  else head_style = "h2";

  if (!global->stand_table_attr[0] && !global->stand_row_attr) {
    table_attr = " border=\"1\"";
  } else {
    table_attr = global->stand_table_attr;
  }

  attr_num = sarray_len(global->stand_row_attr);
  i = 0;
  if (attr_num >= 5) {
    r0_attr = global->stand_row_attr[i++];
    r_attrs[0][0] = global->stand_row_attr[i++];
    r_attrs[0][1] = global->stand_row_attr[i++];
    r_attrs[1][0] = global->stand_row_attr[i++];
    r_attrs[1][1] = global->stand_row_attr[i++];
    attr_num -= 5;
  }
  if (attr_num >= 1) {
    rT_attr = global->stand_row_attr[i++];
    attr_num -= 1;
  }

  cur_time = time(0);
  start_time = run_get_start_time();
  stop_time = run_get_stop_time();
  contest_dur = run_get_duration();
  if (start_time && global->virtual && user_id > 0) {
    start_time = run_get_virtual_start_time(user_id);
    stop_time = run_get_virtual_stop_time(user_id, 0);
  }
  if (start_time && !stop_time && cur_time >= start_time + contest_dur) {
    stop_time = start_time + contest_dur;
  }
  if (start_time && cur_time < start_time) {
    cur_time = start_time;
  }
  if (stop_time && cur_time > stop_time) {
    cur_time = stop_time;
  }
  current_dur = cur_time - start_time;
  if (!start_time) {
    if (raw_flag) return;

    fprintf(f, "<%s>%s</%s>", head_style, _("The contest is not started"),
            head_style);
    if (!client_flag) {
      if (footer_str) {
        process_template(f, footer_str, 0, 0, 0, get_copyright());
      } else {
        fprintf(f, "</body></html>");
      }
    }
    return;
  }

  r_tot = run_get_total();
  runs = alloca(r_tot * sizeof(runs[0]));
  run_get_all_entries(runs);

  t_max = teamdb_get_max_team_id() + 1;
  t_runs = alloca(t_max);
  if (global->prune_empty_users) {
    memset(t_runs, 0, t_max);
    for (k = 0; k < r_tot; k++) {
      if (runs[k].status == RUN_EMPTY) continue;
      if (runs[k].team <= 0 || runs[k].team >= t_max) continue;
      if (runs[k].is_hidden) continue;
      t_runs[runs[k].team] = 1;
    }
  } else {
    memset(t_runs, 1, t_max);
  }

  /* make team index */
  XALLOCAZ(t_ind, t_max);
  XALLOCAZ(t_rev, t_max);
  for (i = 1, t_tot = 0; i < t_max; i++) {
    t_rev[i] = -1;
    if (!teamdb_lookup(i)) continue;
    if ((teamdb_get_flags(i) & (TEAM_INVISIBLE | TEAM_BANNED))) continue;
    if (!t_runs[i]) continue;
    t_rev[i] = t_tot;
    t_ind[t_tot++] = i;
  }
  XALLOCAZ(t_prob, t_tot);
  XALLOCAZ(t_pen,t_tot);
  XALLOCA(t_n1, t_tot);
  XALLOCA(t_n2, t_tot);

  /* make problem index */
  p_max = max_prob + 1;
  XALLOCAZ(p_ind, p_max);
  XALLOCAZ(p_rev, p_max);
  for (i = 1, p_tot = 0; i < p_max; i++) {
    p_rev[i] = -1;
    if (!probs[i] || probs[i]->hidden) continue;
    p_rev[i] = p_tot;
    p_ind[p_tot++] = i;
  }

  /* calculate the power of 2 not less than p_tot */
  for (row_sz = 1, row_sh = 0; row_sz < p_tot; row_sz <<= 1, row_sh++);
  /* all two-dimensional arrays will have rows of size row_sz */

  if (t_tot > 0) {
    XCALLOC(calc, t_tot * row_sz);
    XCALLOC(ok_time, t_tot * row_sz);
  }

  XALLOCAZ(succ_att, p_tot);
  XALLOCAZ(tot_att, p_tot);

  /* now scan runs log */
  for (k = 0; k < r_tot; k++) {
    pe = &runs[k];
    run_time = pe->timestamp;
    if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP
        || pe->status == RUN_EMPTY) continue;
    if (pe->team <= 0 || pe->team >= t_max || t_rev[pe->team] < 0) continue;
    if (pe->problem <= 0 || pe->problem > max_prob || p_rev[pe->problem] < 0)
      continue;
    if (!probs[pe->problem] || probs[pe->problem]->hidden) continue;
    if (pe->is_hidden) continue;
    if (global->virtual) {
      // filter "future" virtual runs
      tstart = run_get_virtual_start_time(pe->team);
      ASSERT(run_time >= tstart);
      tdur = run_time - tstart;
      ASSERT(tdur <= contest_dur);
      if (user_id > 0 && tdur > current_dur) continue;
    } else {
      // for a regular contest --- filter future runs for
      // unprivileged standings
      // client_flag == 1 && user_id == 0 --- privileged standings
      if (client_flag != 1 || user_id) {
        if (run_time < start_time) run_time = start_time;
        if (current_dur > 0 && run_time - start_time > current_dur) continue;
        if (global->stand_ignore_after_d > 0
            && pe->timestamp >= global->stand_ignore_after_d)
          continue;
      }
    }
    tt = t_rev[pe->team];
    pp = p_rev[pe->problem];
    up_ind = (tt << row_sh) + pp;

    if (pe->status == RUN_OK) {
      /* program accepted */
      if (calc[up_ind] > 0) continue;

      last_success_run = k;
      t_pen[tt] += 20 * - calc[up_ind];
      calc[up_ind] = 1 - calc[up_ind];
      t_prob[tt]++;
      succ_att[pp]++;
      tot_att[pp]++;
      if (global->virtual) {
        ok_time[up_ind] = sec_to_min(tdur);
        if (!global->ignore_success_time) t_pen[tt] += ok_time[up_ind];
        last_success_time = run_time;
        last_success_start = tstart;
      } else {
        if (run_time < start_time) run_time = start_time;
        ok_time[up_ind] = sec_to_min(run_time - start_time);
        if (!global->ignore_success_time) t_pen[tt] += ok_time[up_ind];
        last_success_time = run_time;
        last_success_start = start_time;
      }
    } else if (pe->status==RUN_COMPILE_ERR && !global->ignore_compile_errors) {
      if (calc[up_ind] <= 0) {
        calc[up_ind]--;
        tot_att[pp]++;
      }
    } else if (run_is_failed_attempt(pe->status)) {
      /* some error */
      if (calc[up_ind] <= 0) {
        calc[up_ind]--;
        tot_att[pp]++;
      }
    }
  }

  /* now sort the teams in the descending order */
  /* t_sort: sorted->unsorted index map */
  /* ties are resolved in the order of the team's ids */
  if (t_tot > 0) {
    max_pen = -1;
    max_solved = -1;
    for (i = 0; i < t_tot; i++) {
      if (t_prob[i] > max_solved) max_solved = t_prob[i];
      if (t_pen[i] > max_pen) max_pen = t_pen[i];
    }
    XALLOCAZ(prob_cnt, max_solved + 1);
    XALLOCAZ(pen_cnt, max_pen + 1);
    for (i = 0; i < t_tot; i++) {
      prob_cnt[t_prob[i]]++;
      pen_cnt[t_pen[i]]++;
    }
    i = 0;
    for (t = max_solved - 1; t >= 0; t--) {
      j = prob_cnt[t + 1] + i;
      prob_cnt[t + 1] = i;
      i = j;
    }
    prob_cnt[0] = i;
    i = 0;
    for (t = 1; t <= max_pen; t++) {
      j = pen_cnt[t - 1] + i;
      pen_cnt[t - 1] = i;
      i = j;
    }
    pen_cnt[t - 1] = i;
    XALLOCA(t_sort2, t_tot);
    XALLOCA(t_sort, t_tot);
    for (t = 0; t < t_tot; t++)
      t_sort2[pen_cnt[t_pen[t]]++] = t;
    for (t = 0; t < t_tot; t++)
      t_sort[prob_cnt[t_prob[t_sort2[t]]]++] = t_sort2[t];
  }

  /* now resolve ties */
  for(i = 0; i < t_tot;) {
    for (j = i + 1; j < t_tot; j++) {
      if (t_prob[t_sort[i]] != t_prob[t_sort[j]]
          || t_pen[t_sort[i]] != t_pen[t_sort[j]]) break;
    }
    for (k = i; k < j; k++) {
      t_n1[k] = i;
      t_n2[k] = j - 1;
    }
    i = j;
  }

  if (raw_flag) {
    for (i = 0; i < t_tot; i++) {
      t = t_sort[i];
      fprintf(f, "%d;%d;", t_n1[i] + 1, t_n2[i] + 1);
      fprintf(f, "%d;", t_ind[t]);
      for (j = 0; j < p_tot; j++) {
        up_ind = (t << row_sh) + j;
        if (calc[up_ind] < 0) {
          fprintf(f, "%d;0;;", -calc[up_ind]);
        } else if (calc[up_ind] > 0) {
          fprintf(f, "%d;1;%ld;", calc[up_ind] - 1, ok_time[up_ind]);
        } else {
          fprintf(f, "0;0;;");
        }
      }
      fprintf(f, "%d;%d;", t_prob[t], t_pen[t]);
      fprintf(f, "\n");
    }
  } else {
    /* print "last success" string */
    if (last_success_run >= 0) {
      unsigned char dur_buf[128];

      if (global->virtual && !user_id) {
        duration_str(1, last_success_time, last_success_start,
                     dur_buf, sizeof(dur_buf));
      } else {
        duration_str(0, last_success_time, last_success_start,
                     dur_buf, sizeof(dur_buf));
      }
      fprintf(f, "<p%s>%s: %s, ",
              global->stand_success_attr, _("Last success"), dur_buf);
      if (global->team_info_url[0]) {
        teamdb_export_team(runs[last_success_run].team, &ttt);
        sformat_message(dur_buf, sizeof(dur_buf), global->team_info_url,
                        NULL, NULL, NULL, NULL, &ttt, 0, 0, 0);
        fprintf(f, "<a href=\"%s\">", dur_buf);      
      }
      fprintf(f, "%s", teamdb_get_name(runs[last_success_run].team));
      if (global->team_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, ", ");
      if (global->prob_info_url[0]) {
        sformat_message(dur_buf, sizeof(dur_buf), global->prob_info_url,
                        NULL, probs[runs[last_success_run].problem],
                        NULL, NULL, NULL, 0, 0, 0);
        fprintf(f, "<a href=\"%s\">", dur_buf);
      }
      fprintf(f, "%s", probs[runs[last_success_run].problem]->short_name);
      if (global->prob_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, ".</p>\n");
    }
    /* print table header */
    fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
            table_attr, r0_attr,
            global->stand_place_attr, _("Place"),
            global->stand_team_attr, _("User "));
    if (global->stand_extra_format[0]) {
      if (global->stand_extra_legend[0])
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                global->stand_extra_legend);
      else
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                _("Extra info"));
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<th%s>%s</th>", global->stand_contestant_status_attr,
              _("Status"));
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<th%s>%s</th>", global->stand_warn_number_attr,
              _("Warnings"));
    }
    for (j = 0; j < p_tot; j++) {
      fprintf(f, "<th%s>", global->stand_prob_attr);
      if (global->prob_info_url[0]) {
        sformat_message(url_str, sizeof(url_str), global->prob_info_url,
                        NULL, probs[p_ind[j]], NULL, NULL, NULL, 0, 0, 0);
        fprintf(f, "<a href=\"%s\">", url_str);
      }
      fprintf(f, "%s", probs[p_ind[j]]->short_name);
      if (global->prob_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</th>");
    }
    fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>\n",
            global->stand_solved_attr, _("Total"),
            global->stand_penalty_attr, _("Penalty"));

    for (i = 0; i < t_tot; i++) {
      t = t_sort[i];

      if (global->stand_show_contestant_status
          || global->stand_show_warn_number
          || global->contestant_status_row_attr) {
        t_extra = team_extra_get_entry(t_ind[t]);
      } else {
        t_extra = 0;
      }

      if (prev_prob != t_prob[t]) {
        prev_prob = t_prob[t];
        group_ind ^= 1;
        row_ind = 0;
      } else {
        row_ind ^= 1;
      }
      bgcolor_ptr = r_attrs[group_ind][row_ind];
      if (user_id > 0 && user_id == t_ind[t] &&
          global->stand_self_row_attr[0]) {
        bgcolor_ptr = global->stand_self_row_attr;
      } else if (global->virtual) {
        int vstat = run_get_virtual_status(t_ind[t]);
        if (vstat == 1 && global->stand_r_row_attr[0]) {
          bgcolor_ptr = global->stand_r_row_attr;
        } else if (vstat == 2 && global->stand_v_row_attr[0]) {
          bgcolor_ptr = global->stand_v_row_attr;
        } else if (!vstat && global->stand_u_row_attr[0]) {
          bgcolor_ptr = global->stand_u_row_attr;
        }
      }
      if (!bgcolor_ptr
          && global->contestant_status_row_attr
          && t_extra && t_extra->status >= 0
          && t_extra->status < global->contestant_status_num) {
        bgcolor_ptr = global->contestant_status_row_attr[t_extra->status];
      }
      fprintf(f, "<tr%s><td%s>", bgcolor_ptr, global->stand_place_attr);
      if (t_n1[i] == t_n2[i]) fprintf(f, "%d", t_n1[i] + 1);
      else fprintf(f, "%d-%d", t_n1[i] + 1, t_n2[i] + 1);
      fputs("</td>", f);
      fprintf(f, "<td%s>", global->stand_team_attr);
      if (global->team_info_url[0] || global->stand_extra_format[0]) {
        teamdb_export_team(t_ind[t], &ttt);
      } else {
        memset(&ttt, 0, sizeof(ttt));
      }
      if (global->team_info_url[0]) {
        sformat_message(url_str, sizeof(url_str), global->team_info_url,
                        NULL, NULL, NULL, NULL, &ttt, 0, 0, 0);
        fprintf(f, "<a href=\"%s\">", url_str);      
      }
      fprintf(f, "%s", teamdb_get_name(t_ind[t]));
      if (global->team_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</td>");
      if (global->stand_extra_format[0]) {
        sformat_message(url_str, sizeof(url_str), global->stand_extra_format,
                        NULL, NULL, NULL, NULL, &ttt, 0, 0, 0);
        fprintf(f, "<td%s>%s</td>", global->stand_extra_attr, url_str);
      }
      if (global->stand_show_contestant_status
          && global->contestant_status_num > 0) {
        if (t_extra && t_extra->status >= 0
            && t_extra->status < global->contestant_status_num) {
          fprintf(f, "<td%s>%s</td>", global->stand_contestant_status_attr,
                  global->contestant_status_legend[t_extra->status]);
        } else {
          fprintf(f, "<td%s>?</td>", global->stand_contestant_status_attr);
        }
      }
      if (global->stand_show_warn_number) {
        if (t_extra && t_extra->warn_u > 0) {
          fprintf(f, "<td%s>%d</td>", global->stand_warn_number_attr,
                  t_extra->warn_u);
        } else {
          fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
        }
      }
      for (j = 0; j < p_tot; j++) {
        up_ind = (t << row_sh) + j;
        fprintf(f, "<td%s>", global->stand_prob_attr);
        if (calc[up_ind] < 0) {
          fprintf(f, "%d", calc[up_ind]);
        } else if (calc[up_ind] == 1) {
          if (global->ignore_success_time || !global->stand_show_ok_time) {
            fprintf(f, "+");
          } else {
            fprintf(f, "+ <div%s>(%ld:%02ld)</div>",
                    global->stand_time_attr,
                    ok_time[up_ind] / 60, ok_time[up_ind] % 60);
          }
        } else if (calc[up_ind] > 0) {
          if (global->ignore_success_time || !global->stand_show_ok_time) {
            fprintf(f, "+%d", calc[up_ind] - 1);
          } else {
            fprintf(f, "+%d <div%s>(%ld:%02ld)</div>", calc[up_ind] - 1,
                    global->stand_time_attr,
                    ok_time[up_ind] / 60, ok_time[up_ind] % 60);
          }
        } else {
          fprintf(f, "&nbsp;");
        }
        fputs("</td>", f);
      }
      fprintf(f, "<td%s>%d</td><td%s>%d</td></tr>\n",
              global->stand_solved_attr, t_prob[t],
              global->stand_penalty_attr, t_pen[t]);
    }

    // print row of total
    fprintf(f, "<tr%s>", rT_attr);
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_place_attr);
    fprintf(f, "<td%s>Total:</td>", global->stand_team_attr);
    if (global->stand_extra_format[0]) {
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_extra_attr);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_contestant_status_attr);
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
    }
    for (j = 0, ttot_att = 0; j < p_tot; j++) {
      fprintf(f, "<td%s>%d</td>", global->stand_prob_attr, tot_att[j]);
      ttot_att += tot_att[j];
    }
    fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
            global->stand_solved_attr, ttot_att, global->stand_penalty_attr);
    // print row of success
    fprintf(f, "<tr%s>", rT_attr);
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_place_attr);
    fprintf(f, "<td%s>Success:</td>", global->stand_team_attr);
    if (global->stand_extra_format[0]) {
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_extra_attr);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_contestant_status_attr);
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
    }
    for (j = 0, ttot_succ = 0; j < p_tot; j++) {
      fprintf(f, "<td%s>%d</td>", global->stand_prob_attr, succ_att[j]);
      ttot_succ += succ_att[j];
    }
    fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
            global->stand_solved_attr, ttot_succ, global->stand_penalty_attr);
    // print row of percentage
    fprintf(f, "<tr%s>", rT_attr);
    fprintf(f, "<td%s>&nbsp;</td>", global->stand_place_attr);
    fprintf(f, "<td%s>%%:</td>", global->stand_team_attr);
    if (global->stand_extra_format[0]) {
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_extra_attr);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_contestant_status_attr);
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<td%s>&nbsp;</td>", global->stand_warn_number_attr);
    }
    for (j = 0; j < p_tot; j++) {
      perc = 0;
      if (tot_att[j] > 0) {
        perc = (int) ((double) succ_att[j] / tot_att[j] * 100.0 + 0.5);
      }
      fprintf(f, "<td%s>%d%%</td>", global->stand_prob_attr, perc);
    }
    perc = 0;
    if (ttot_att > 0) {
      perc = (int) ((double) ttot_succ / ttot_att * 100.0 + 0.5);
    }
    fprintf(f, "<td%s>%d%%</td><td%s>&nbsp;</td></tr>\n",
            global->stand_solved_attr, perc, global->stand_penalty_attr);
    
    fputs("</table>\n", f);
    if (!client_flag) {
      if (footer_str) {
        process_template(f, footer_str, 0, 0, 0, get_copyright());
      } else {
        fputs("</body></html>", f);
      } 
    }
  }

  xfree(calc);
  xfree(ok_time);
}

void
write_standings(char const *stat_dir, char const *name, int users_on_page,
                char const *header_str, char const *footer_str,
                int accepting_mode)
{
  char    tbuf[64];
  path_t  tpath;
  FILE   *f;

  sprintf(tbuf, "XXX_%lu%d", time(0), getpid());
  pathmake(tpath, stat_dir, "/", tbuf, 0);
  if (!(f = sf_fopen(tpath, "w"))) return;
  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD)
    do_write_kirov_standings(f, stat_dir, 0, header_str, footer_str, 0, accepting_mode);
  else if (global->score_system_val == SCORE_MOSCOW)
    do_write_moscow_standings(f, stat_dir, 0, 0, header_str, footer_str, 0, 0);
  else
    do_write_standings(f, 0, 0, header_str, footer_str, 0, 0);
  fclose(f);
  generic_copy_file(REMOVE, stat_dir, tbuf, "",
                    SAFE, stat_dir, name, "");
  return;
}

static void
do_write_public_log(FILE *f, char const *header_str, char const *footer_str)
{
  int total;
  int i;

  time_t time, start;
  int attempts, disq_attempts, prev_successes;

  char durstr[64], statstr[64];
  char *str1 = 0, *str2 = 0;

  struct run_entry *runs, *pe;
  struct section_problem_data *cur_prob;

  start = run_get_start_time();
  total = run_get_total();
  runs = alloca(total * sizeof(runs[0]));
  run_get_all_entries(runs);

  switch (global->score_system_val) {
  case SCORE_ACM:
    str1 = _("Failed test");
    break;
  case SCORE_KIROV:
  case SCORE_OLYMPIAD:
    str1 = _("Tests passed");
    str2 = _("Score");
  case SCORE_MOSCOW:
    str1 = _("Failed test");
    str2 = _("Score");
    break;
  default:
    abort();
  }

  if (header_str) {
    fprintf(f, "%s", header_str);
  } else {
    fprintf(f, "Content-type: text/plain; charset=%s\n\n", EJUDGE_CHARSET);
  }

  /* header */
  fprintf(f, "<p%s>%s: %d</p>\n", cur_contest->team_par_style,
          _("Total submissions"), total);
  fprintf(f, "<table border=\"1\"><tr><th>%s</th><th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th><th>%s</th>"
          "<th>%s</th><th>%s</th>", 
          _("Run ID"), _("Time"),
          _("Team name"), _("Problem"),
          _("Language"), _("Result"), str1);
  if (str2) {
    fprintf(f, "<th>%s</th>", str2);
  }
  fprintf(f, "</tr>\n");

  for (i = total - 1; i >= 0; i--) {
    pe = &runs[i];
    if (pe->is_hidden) continue;

    cur_prob = 0;
    if (pe->problem > 0 && pe->problem <= max_prob)
      cur_prob = probs[pe->problem];

    attempts = 0;
    disq_attempts = 0;
    prev_successes = RUN_TOO_MANY;

    time = pe->timestamp;
    if (global->score_system_val == SCORE_KIROV) {
      run_get_attempts(i, &attempts, &disq_attempts,
                       global->ignore_compile_errors);
      if (pe->status == RUN_OK && cur_prob && cur_prob->score_bonus_total > 0){
        prev_successes = run_get_prev_successes(i);
        if (prev_successes < 0) prev_successes = RUN_TOO_MANY;
      }
    }

    if (!start) time = start;
    if (start > time) time = start;
    duration_str(global->show_astr_time, time, start, durstr, 0);
    run_status_str(pe->status, statstr, 0);

    fputs("<tr>", f);
    fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", durstr);
    fprintf(f, "<td>%s</td>", teamdb_get_name(pe->team));
    if (probs[pe->problem]) {
      if (probs[pe->problem]->variant_num > 0) {
        int variant = pe->variant;
        if (!variant) variant = find_variant(pe->team, pe->problem);
        if (variant > 0) {
          fprintf(f, "<td>%s-%d</td>", probs[pe->problem]->short_name,variant);
        } else {
          fprintf(f, "<td>%s-?</td>", probs[pe->problem]->short_name);
        }
      } else {
        fprintf(f, "<td>%s</td>", probs[pe->problem]->short_name);
      }
    }
    else fprintf(f, "<td>??? - %d</td>", pe->problem);
    if (langs[pe->language])
      fprintf(f, "<td>%s</td>", langs[pe->language]->short_name);
    else fprintf(f, "<td>??? - %d</td>", pe->language);

    write_html_run_status(f, pe, 0, attempts, disq_attempts, prev_successes);

    fputs("</tr>\n", f);
  }

  fputs("</table>\n", f);
  if (footer_str) {
    fprintf(f, "%s", footer_str);
  }
}

void
write_public_log(char const *stat_dir, char const *name,
                 char const *header_str, char const *footer_str)
{
  char    tbuf[64];
  path_t  tpath;
  FILE   *f;

  sprintf(tbuf, "XXX_%lu%d", time(0), getpid());
  pathmake(tpath, stat_dir, "/", tbuf, 0);
  if (!(f = sf_fopen(tpath, "w"))) return;
  do_write_public_log(f, header_str, footer_str);
  fclose(f);
  generic_copy_file(REMOVE, stat_dir, tbuf, "",
                    SAFE, stat_dir, name, "");
  return;
}

int
new_write_user_source_view(FILE *f, int uid, int rid)
{
  path_t  src_path;
  int html_len, src_flags;
  size_t src_len = 0;
  char   *src = 0, *html = 0;
  struct run_entry re;

  if (!global->team_enable_src_view) {
    err("viewing user source is disabled");
    return -SRV_ERR_SOURCE_DISABLED;
  }
  if (rid < 0 || rid >= run_get_total()) {
    err("invalid run_id: %d", rid);
    return -SRV_ERR_BAD_RUN_ID;
  }
  run_get_entry(rid, &re);
  if (uid != re.team) {
    err("user ids does not match");
    return -SRV_ERR_ACCESS_DENIED;
  }

  if ((src_flags=archive_make_read_path(src_path, sizeof(src_path),
                                        global->run_archive_dir,rid,0,1))<0){
    return -SRV_ERR_FILE_NOT_EXIST;
  }
  if (generic_read_file(&src, 0, &src_len, src_flags, 0, src_path, "") < 0) {
    return -SRV_ERR_SYSTEM_ERROR;
  }

  html_len = html_armored_memlen(src, src_len);
  html = alloca(html_len + 16);
  html_armor_text(src, src_len, html);
  html[html_len] = 0;
  xfree(src);

  fprintf(f, "<pre>%s</pre>", html);
  return 0;
}

int
write_xml_team_testing_report(FILE *f, const unsigned char *txt)
{
  testing_report_xml_t r = 0;
  struct testing_report_test *t;
  unsigned char *font_color = 0, *s;
  int need_comment = 0, need_info = 0, is_kirov = 0, i;

  if (!(r = testing_report_parse_xml(txt))) {
    fprintf(f, "<p><big>Cannot parse XML file!</big></p>\n");
    return 0;
  }

  if (r->status == RUN_OK || r->status == RUN_ACCEPTED) {
    font_color = "green";
  } else {
    font_color = "red";
  }
  fprintf(f, "<h2><font color=\"%s\">%s</font></h2>\n",
          font_color, run_status_str(r->status, 0, 0));

  if (r->scoring_system == SCORE_KIROV ||
      (r->scoring_system == SCORE_OLYMPIAD && !r->accepting_mode)) {
    is_kirov = 1;
  }

  if (is_kirov) {
    fprintf(f, _("<big>%d total tests runs, %d passed, %d failed.<br>\n"),
            r->run_tests, r->tests_passed, r->run_tests - r->tests_passed);
    fprintf(f, _("Score gained: %d (out of %d).<br><br></big>\n"),
            r->score, r->max_score);
  } else {
    if (r->status != RUN_OK && r->status != RUN_ACCEPTED) {
      fprintf(f, _("<big>Failed test: %d.<br><br></big>\n"), r->failed_test);
    }
  }

  if (r->comment) {
    s = html_armor_string_dup(r->comment);
    fprintf(f, "<big>Note: %s.<br><br></big>\n", s);
    xfree(s);
  }

  for (i = 0; i < r->run_tests; i++) {
    if (!(t = r->tests[i])) continue;
    if (t->team_comment) {
      need_comment = 1;
    }
    if (global->report_error_code && t->status == RUN_RUN_TIME_ERR) {
      need_info = 1;
    }
  }

  fprintf(f,
          "<table border=\"1\">"
          "<tr><th>N</th><th>%s</th><th>%s</th><th>%s</th>",
          _("Result"), _("Time (sec)"), _("Real time (sec)"));
  if (need_info) {
    fprintf(f, "<th>%s</th>", _("Extra info"));
  }
  if (is_kirov) {
    fprintf(f, "<th>%s</th>", _("Score"));
  }
  if (need_comment) {
    fprintf(f, "<th>%s</th>", _("Comment"));
  }

  fprintf(f, "</tr>\n");
  fprintf(f, "</tr>\n");
  for (i = 0; i < r->run_tests; i++) {
    if (!(t = r->tests[i])) continue;
    fprintf(f, "<tr>");
    fprintf(f, "<td>%d</td>", t->num);
    if (t->status == RUN_OK || t->status == RUN_ACCEPTED) {
      font_color = "green";
    } else {
      font_color = "red";
    }
    fprintf(f, "<td><font color=\"%s\">%s</font></td>\n",
            font_color, run_status_str(t->status, 0, 0));
    fprintf(f, "<td>%d.%03d</td>", t->time / 1000, t->time % 1000);
    if (t->real_time > 0) {
      fprintf(f, "<td>%d.%03d</td>", t->real_time / 1000, t->real_time % 1000);
    } else {
      fprintf(f, "<td>N/A</td>");
    }
    if (need_info) {
      fprintf(f, "<td>");
      if (t->status == RUN_RUN_TIME_ERR && global->report_error_code) {
        if (t->term_signal >= 0) {
          fprintf(f, "%s %d (%s)", _("Signal"), t->term_signal,
                  os_GetSignalString(t->term_signal));
        } else {
          fprintf(f, "%s %d", _("Exit code"), t->exit_code);
        }
      } else {
        fprintf(f, "&nbsp;");
      }
      fprintf(f, "</td>");
    }
    if (is_kirov) {
      fprintf(f, "<td>%d (%d)</td>", t->score, t->nominal_score);
    }
    if (need_comment) {
      if (!t->team_comment) {
        fprintf(f, "<td>&nbsp;</td>");
      } else {
        s = html_armor_string_dup(t->team_comment);
        fprintf(f, "<td>%s</td>", s);
        xfree(s);
      }
    }
    fprintf(f, "</tr>\n");
  }
  fprintf(f, "</table>\n");
  return 0;
}

int
new_write_user_report_view(FILE *f, int uid, int rid,
                           ej_cookie_t sid,
                           const unsigned char *self_url,
                           const unsigned char *hidden_vars,
                           const unsigned char *extra_args)
{
  int html_len = 0, report_flags, content_type;
  size_t report_len = 0;
  path_t report_path;
  char *report = 0, *html_report;
  const unsigned char *start_ptr = 0;
  const unsigned char *archive_dir = 0;
  struct run_entry re;
  struct section_problem_data *prb = 0;

  if (rid < 0 || rid >= run_get_total()) {
    err("invalid run_id: %d", rid);
    return -SRV_ERR_BAD_RUN_ID;
  }
  if (run_get_entry(rid, &re) < 0) {
    return -SRV_ERR_BAD_RUN_ID;
  }
  if (re.problem <= 0 || re.problem > max_prob || !(prb = probs[re.problem])) {
    err("get_record returned bad prob_id %d", re.problem);
    return -SRV_ERR_BAD_PROB_ID;
  }
  if (uid != re.team) {
    err("user ids does not match");
    return -SRV_ERR_ACCESS_DENIED;
  }
  if (!prb->team_enable_rep_view
      && (!prb->team_enable_ce_view || re.status != RUN_COMPILE_ERR)) {
    err("viewing report is disabled for this problem");
    return -SRV_ERR_REPORT_DISABLED;
  }
  if (!run_is_team_report_available(re.status)) {
    return -SRV_ERR_REPORT_NOT_AVAILABLE;
  }

  report_flags = archive_make_read_path(report_path, sizeof(report_path),
                                        global->xml_report_archive_dir, rid, 0, 1);
  if (report_flags >= 0) {
    if (generic_read_file(&report, 0, &report_len, report_flags,
                          0, report_path, "") < 0) {
      return -SRV_ERR_SYSTEM_ERROR;
    }
    content_type = get_content_type(report, &start_ptr);
    if (content_type != CONTENT_TYPE_XML && re.status != RUN_COMPILE_ERR)
      return -SRV_ERR_REPORT_NOT_AVAILABLE;
  } else {
    if (prb->team_enable_ce_view && re.status == RUN_COMPILE_ERR)
      archive_dir = global->report_archive_dir;
    else if (prb->team_show_judge_report)
      archive_dir = global->report_archive_dir;
    else
      archive_dir = global->team_report_archive_dir;
    report_flags = archive_make_read_path(report_path, sizeof(report_path),
                                          archive_dir, rid, 0, 1);
    if (report_flags < 0) return -SRV_ERR_FILE_NOT_EXIST;
    if (generic_read_file(&report, 0, &report_len, report_flags,
                          0, report_path, "") < 0) {
      return -SRV_ERR_SYSTEM_ERROR;
    }
    content_type = get_content_type(report, &start_ptr);
  }

  switch (content_type) {
  case CONTENT_TYPE_TEXT:
    html_len = html_armored_memlen(report, report_len);
    html_report = alloca(html_len + 16);
    html_armor_text(report, report_len, html_report);
    html_report[html_len] = 0;
    fprintf(f, "<pre>%s</pre>", html_report);
    break;
  case CONTENT_TYPE_HTML:
    fprintf(f, "%s", start_ptr);
    break;
  case CONTENT_TYPE_XML:
    if (prb->team_show_judge_report) {
      write_xml_testing_report(f, start_ptr, sid, self_url, extra_args);
    } else {
      write_xml_team_testing_report(f, start_ptr);
    }
    break;
  default:
    abort();
  }

  xfree(report);

  return 0;
}

static void
print_nav_buttons(FILE *f,
                  ej_cookie_t sid,
                  unsigned char const *self_url,
                  unsigned char const *hidden_vars,
                  unsigned char const *extra_args,
                  unsigned char const *t1,
                  unsigned char const *t2,
                  unsigned char const *t3)
{
  unsigned char hbuf[128];

  if (!t1) t1 = _("Refresh");
  if (!t2) t2 = _("Virtual standings");
  if (!t3) t3 = _("Log out");

  fprintf(f, "<table><tr><td>");
  fprintf(f, "%s",
          html_hyperref(hbuf, sizeof(hbuf), sid, self_url, extra_args, 0));
  fprintf(f, "%s</a></td><td>", t1);
  if (global->virtual) {
    fprintf(f, "%s",
            html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                          extra_args, "action=%d", ACTION_STANDINGS));
    fprintf(f, "%s</a></td><td>", t2);
  }
  fprintf(f, "%s",
          html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                        extra_args, "action=%d", ACTION_LOGOUT));
  fprintf(f, "%s</a></td></tr></table>\n", t3);
}

static unsigned char *
time_to_str(unsigned char *buf, time_t time)
{
  unsigned char *s = ctime(&time);
  int l = strlen(s);
  strcpy(buf, s);
  if (l > 0) buf[l - 1] = 0;
  return buf;
}

void
write_team_page(FILE *f, int user_id,
                int printing_suspended,
                ej_cookie_t sid,
                int all_runs, int all_clars,
                unsigned char const *self_url,
                unsigned char const *hidden_vars,
                unsigned char const *extra_args,
                time_t server_start, time_t server_end, int accepting_mode)
{
  int i, pdi, dpi;
  unsigned char hbuf[128];
  struct tm *dl_time;
  unsigned char dl_time_str[128];
  unsigned char pd_time_str[128];
  time_t current_time = time(0);
  unsigned char *prob_str;
  int unread_clars = 0;
  struct team_extra *t_extra;
  struct team_warning *cur_warn;
  time_t user_deadline;
  int user_penalty;
  unsigned char *user_login = teamdb_get_login(user_id);
  struct pers_dead_info *pdinfo;
  unsigned char *accepted_flag = 0;

  XALLOCAZ(accepted_flag, max_prob + 1);

  if (global->virtual) {
    time_t dur;
    unsigned char tbuf[64];
    unsigned char *ststr;
    time_t global_server_start;
    time_t global_server_end;

    global_server_start = server_start;
    global_server_end = server_end;
    server_start = run_get_virtual_start_time(user_id);
    server_end = run_get_virtual_stop_time(user_id, 0);
    dur = run_get_duration();
    if (server_start && !server_end && dur > 0) {
      if (server_start + dur < current_time) {
        server_end = server_start + dur;
      }
    }

    fprintf(f, "<table border=\"0\">\n");
    if (!server_start) {
      ststr = _("Virtual contest is not started");
    } else if (server_end) {
      ststr = _("Virtual contest is finished");
    } else {
      ststr = _("Virtual contest is in progress");
    }
    fprintf(f, "<tr><td colspan=\"2\"><b><big>%s</big></b></td></tr>\n",
            ststr);
    fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Server time"), time_to_str(tbuf, current_time));
    if (dur) {
      duration_str(0, dur, 0, tbuf, 0);
    } else {
      snprintf(tbuf, sizeof(tbuf), _("Unlimited"));
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Duration"), tbuf);
    if (server_start) {
      fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
              _("Contest start time"), time_to_str(tbuf, server_start));
      if (server_end) {
        fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Contest stop time"), time_to_str(tbuf, server_end));
      } else if (dur) {
        fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Expected stop time"),
                time_to_str(tbuf, server_start + dur));
        duration_str(0, current_time, server_start, tbuf, 0);
        fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Elapsed time"), tbuf);
        duration_str(0, server_start + dur, current_time, tbuf, 0);
        fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
                _("Remaining time"), tbuf);
      }
    }
    fprintf(f, "</table>\n");
    if (!server_start && global_server_start) {
      html_start_form(f, 1, sid, self_url, hidden_vars);
      fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
              ACTION_START_VIRTUAL, _("Start virtual contest"));
      fprintf(f, "</form>\n");
    } else if (server_start && !server_end) {
      html_start_form(f, 1, sid, self_url, hidden_vars);
      fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
              ACTION_STOP_VIRTUAL, _("Stop virtual contest"));
      fprintf(f, "</form>\n");
    }
    print_nav_buttons(f, sid, self_url, hidden_vars, extra_args,
                      0, 0, 0);
  }

  if (!global->disable_clars || !global->disable_team_clars){
    unread_clars = count_unread_clars(user_id);
    if (unread_clars > 0) {
      fprintf(f, _("<hr><big><b>You have %d unread message(s)!</b></big>\n"),
              unread_clars);
    }
  }

  t_extra = team_extra_get_entry(user_id);
  if (t_extra && t_extra->warn_u > 0) {
    fprintf(f, "<hr><%s>%s (%s %d)</%s>\n", cur_contest->team_head_style,
            _("Warnings"), _("total"), t_extra->warn_u,
            cur_contest->team_head_style);
    for (i = 0; i < t_extra->warn_u; i++) {
      if (!(cur_warn = t_extra->warns[i])) continue;
      fprintf(f, "<p><big><b>%s %d: %s: %s.</b></big>\n",
              _("Warning"), i + 1, _("Received"),
              xml_unparse_date(cur_warn->date));
      //fprintf(f, "<p>%s:\n", _("Explanation"));
      fprintf(f, "<p>");
      xml_unparse_text(f, "pre", cur_warn->text, "");
    }
  }

  if (server_start) {
    fprintf(f, "<hr><a name=\"probstat\"></a><%s>%s</%s>\n",
            cur_contest->team_head_style,
            _("Problem status summary"),
            cur_contest->team_head_style);
    if (cur_contest->problems_url) {
      fprintf(f, "<p><a href=\"%s\" target=\"_blank\">%s</a></p>\n",
              cur_contest->problems_url, _("All problems"));
    }
    write_user_problems_summary(f, user_id, accepting_mode, accepted_flag);
  }

  if (server_start && !server_end) {
    fprintf(f, "<hr><a name=\"submit\"></a><%s>%s</%s>\n",
            cur_contest->team_head_style, _("Send a submission"),
            cur_contest->team_head_style);
    html_start_form(f, 2, sid, self_url, hidden_vars);
    fprintf(f, "<table>\n");
    fprintf(f, "<tr><td>%s:</td><td>", _("Problem"));
    fprintf(f, "<select name=\"problem\"><option value=\"\">\n");
    for (i = 1; i <= max_prob; i++)
      if (probs[i]) {
        if (global->disable_submit_after_ok > 0 && accepted_flag[i]) continue;
        user_deadline = 0;
        user_penalty = 0;
        for (pdi = 0, pdinfo = probs[i]->pd_infos;
             pdi < probs[i]->pd_total;
             pdi++, pdinfo++) {
          if (!strcmp(user_login, pdinfo->login)) {
            user_deadline = pdinfo->deadline;
            break;
          }
        }
        if (!user_deadline) user_deadline = probs[i]->t_deadline;
        if (user_deadline && current_time >= user_deadline) continue;
        if (probs[i]->t_start_date && current_time < probs[i]->t_start_date)
          continue;

        for (dpi = 0; dpi < probs[i]->dp_total; dpi++)
          if (current_time < probs[i]->dp_infos[dpi].deadline)
            break;
        if (dpi < probs[i]->dp_total)
          user_penalty = probs[i]->dp_infos[dpi].penalty;

        dl_time_str[0] = 0;
        if (user_deadline && global->show_deadline) {
          dl_time = localtime(&user_deadline);
          snprintf(dl_time_str, sizeof(dl_time_str),
                   " (%04d/%02d/%02d %02d:%02d:%02d)",
                   dl_time->tm_year + 1900, dl_time->tm_mon + 1,
                   dl_time->tm_mday, dl_time->tm_hour,
                   dl_time->tm_min, dl_time->tm_sec);
        }
        pd_time_str[0] = 0;
        if (user_penalty && global->show_deadline) {
          snprintf(pd_time_str, sizeof(pd_time_str), " [%d]", user_penalty);
        }

        if (probs[i]->variant_num > 0) {
          int variant = find_variant(user_id, i);
          prob_str = alloca(strlen(probs[i]->short_name) + 10);
          if (variant > 0) {
            sprintf(prob_str, "%s-%d", probs[i]->short_name, variant);
          } else {
            sprintf(prob_str, "%s-?", probs[i]->short_name);
          }
        } else {
          prob_str = probs[i]->short_name;
        }
        fprintf(f, "<option value=\"%d\">%s - %s%s%s\n",
                probs[i]->id, prob_str, probs[i]->long_name,
                pd_time_str, dl_time_str);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "</td></tr>\n");
    fprintf(f, "<tr><td>%s:</td><td>", _("Language"));
    fprintf(f, "<select name=\"language\"><option value=\"\">\n");
    for (i = 1; i <= max_lang; i++)
      if (langs[i] && !langs[i]->disabled) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                langs[i]->id, langs[i]->short_name, langs[i]->long_name);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "</td></tr>\n");
    fprintf(f, "<tr><td>%s:</td>"
            "<td><input type=\"file\" name=\"file\"></td></tr>\n"
            "<tr><td>%s</td>"
            "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr>",
            _("File"), _("Send!"), ACTION_SUBMIT_RUN, _("Send!"));
    fprintf(f, "</table></form>\n");
    print_nav_buttons(f, sid, self_url, hidden_vars, extra_args, 0, 0, 0);
  }

  if (server_start) {
    fprintf(f, "<hr><a name=\"runstat\"></a><%s>%s (%s)</%s>\n",
            cur_contest->team_head_style,
            _("Sent submissions"),
            all_runs?_("all"):_("last 15"),
            cur_contest->team_head_style);
    new_write_user_runs(f, user_id, printing_suspended, all_runs,
                        sid, self_url, hidden_vars, extra_args);

    fprintf(f, "<p%s>%s%s</a></p>",
            cur_contest->team_par_style,
            html_hyperref(hbuf, sizeof(hbuf), sid, self_url, extra_args, "all_runs=1"),
            _("View all"));

    print_nav_buttons(f, sid, self_url, hidden_vars, extra_args, 0, 0, 0);
    if (global->team_download_time > 0) {
      fprintf(f, "<p%s>", cur_contest->team_par_style);
      html_start_form(f, 1, sid, self_url, hidden_vars);
      fprintf(f,
              "<input type=\"submit\" name=\"archive\" value=\"%s\"></form>\n",
              _("Download your submits"));
      fprintf(f, _("<p%s><b>Note,</b> if downloads are allowed, you may download your runs once per %d minutes. The archive is in <tt>.tar.gz</tt> (<tt>.tgz</tt>) format.</p>\n"), cur_contest->team_par_style, global->team_download_time / 60);
    }
  }

  if (!global->disable_clars && !global->disable_team_clars
      && server_start && !server_end) {
    fprintf(f, "<hr><a name=\"clar\"></a><%s>%s</%s>\n",
            cur_contest->team_head_style, _("Send a message to judges"),
            cur_contest->team_head_style);
    html_start_form(f, 2, sid, self_url, hidden_vars);
    fprintf(f, "<table><tr><td>%s:</td><td>", _("Problem"));
    fprintf(f, "<select name=\"problem\"><option value=\"\">\n");
    for (i = 1; i <= max_prob; i++)
      if (probs[i]) {
        user_deadline = 0;
        user_penalty = 0;
        for (pdi = 0, pdinfo = probs[i]->pd_infos;
             pdi < probs[i]->pd_total;
             pdi++, pdinfo++) {
          if (!strcmp(user_login, pdinfo->login)) {
            user_deadline = pdinfo->deadline;
            break;
          }
        }
        if (!user_deadline) user_deadline = probs[i]->t_deadline;
        if (user_deadline && current_time >= user_deadline) continue;
        if (probs[i]->t_start_date && current_time < probs[i]->t_start_date)
          continue;

        for (dpi = 0; dpi < probs[i]->dp_total; dpi++)
          if (current_time < probs[i]->dp_infos[dpi].deadline)
            break;
        if (dpi < probs[i]->dp_total)
          user_penalty = probs[i]->dp_infos[dpi].penalty;

        dl_time_str[0] = 0;
        if (user_deadline && global->show_deadline) {
          dl_time = localtime(&user_deadline);
          snprintf(dl_time_str, sizeof(dl_time_str),
                   " (%04d/%02d/%02d %02d:%02d:%02d)",
                   dl_time->tm_year + 1900, dl_time->tm_mon + 1,
                   dl_time->tm_mday, dl_time->tm_hour,
                   dl_time->tm_min, dl_time->tm_sec);
        }
        pd_time_str[0] = 0;
        if (user_penalty && global->show_deadline) {
          snprintf(pd_time_str, sizeof(pd_time_str), " [%d]", user_penalty);
        }

        if (probs[i]->variant_num > 0) {
          int variant = find_variant(user_id, i);
          prob_str = alloca(strlen(probs[i]->short_name) + 10);
          if (variant > 0) {
            sprintf(prob_str, "%s-%d", probs[i]->short_name, variant);
          } else {
            sprintf(prob_str, "%s-?", probs[i]->short_name);
          }
        } else {
          prob_str = probs[i]->short_name;
        }
        fprintf(f, "<option value=\"%s\">%s - %s%s%s\n",
                probs[i]->short_name,
                prob_str, probs[i]->long_name, pd_time_str, dl_time_str);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "<tr><td>%s:</td>"
            "<td><input type=\"text\" name=\"subject\"></td></tr>\n"
            "<tr><td colspan=\"2\"><textarea name=\"text\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n"
            "<tr><td colspan=\"2\"><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr>\n"
            "</table></form>\n",
            _("Subject"), ACTION_SUBMIT_CLAR, _("Send!"));
    print_nav_buttons(f, sid, self_url, hidden_vars, extra_args, 0, 0, 0);
  }

  if (!global->disable_clars) {
    fprintf(f, "<hr><a name=\"clarstat\"></a><%s>%s (%s)</%s>\n",
            cur_contest->team_head_style, _("Messages"),
            all_clars?_("all"):_("last 15"), cur_contest->team_head_style);

    new_write_user_clars(f, user_id, all_clars, sid,
                         self_url, hidden_vars, extra_args);

    fprintf(f, "<p%s>%s%s</a></p>",
            cur_contest->team_par_style,
            html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                          extra_args, "all_clars=1"),
            _("View all"));

    print_nav_buttons(f, sid, self_url, hidden_vars, extra_args,
                      0, 0, 0);
  }
}

int
write_virtual_standings(FILE *f, int user_id)
{
  unsigned char *user_name, *astr;
  size_t alen;

  user_name = teamdb_get_name(user_id);
  if (!user_name || !*user_name) user_name = teamdb_get_login(user_id);
  if (!user_name) user_name = "";
  alen = html_armored_strlen(user_name);
  astr = alloca(alen + 16);
  html_armor_string(user_name, astr);
  do_write_standings(f, 1, user_id, 0, 0, 0, astr);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

