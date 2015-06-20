/* -*- mode: c -*- */

/* Copyright (C) 2000-2015 Alexander Chernov <cher@ejudge.ru> */

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
        int prev_successes,
        int *p_date_penalty,
        int format)
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
    if (status == RUN_PENDING_REVIEW) status = RUN_OK;
    init_score = pe->saved_score;
    if (status == RUN_OK && !pr->variable_full_score) {
      if (pr->full_user_score >= 0) init_score = pr->full_user_score;
      else init_score = pr->full_user_score;
    }
  } else {
    status = pe->status;
    if (status == RUN_PENDING_REVIEW) status = RUN_OK;
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
    for (dpi = 0; dpi < pr->dp_total; dpi++)
      if (pe->time < pr->dp_infos[dpi].date)
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
      time_t offset = pe->time - base_time;
      if (offset < 0) offset = 0;
      dp += pi->decay * (offset / pi->scale);
    }
  }
  if (p_date_penalty) *p_date_penalty = dp;
  score = init_score * score_mult - attempts * pr->run_penalty + dp + pe->score_adj - disq_attempts * pr->disqualified_penalty + score_bonus;
  //if (score > pr->full_score) score = pr->full_score;
  if (score < 0) score = 0;
  if (!outbuf) return score;

  if (pr && pr->score_view && pr->score_view[0]) {
    score_view_display(outbuf, outsize, pr, score);
    return score;
  }

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

    if (score_mult > 1 || run_penalty_str[0] || date_penalty_str[0]
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

    snprintf(outbuf, outsize, "%s%s%s%s%s%s%s",
             final_score_str,
             init_score_str, run_penalty_str, date_penalty_str, score_adj_str,
             disq_penalty_str, score_bonus_str);
    return score;
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
        int prev_successes,
        const unsigned char *td_class,
        int disable_failed,
        int enable_js_status_menu,
        int run_fields)
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
  } else if (status < 0 || status > RUN_MAX_STATUS) {
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
        if (status == RUN_OK || status == RUN_ACCEPTED || status == RUN_PENDING_REVIEW || test <= 0
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
      if (status == RUN_OK || status == RUN_ACCEPTED || status == RUN_PENDING_REVIEW || test <= 0
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
                       disq_attempts, prev_successes, 0, 0);
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
        int prev_successes)
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
  } else if (status > RUN_MAX_STATUS) {
    return;
  }

  switch (status) {
  case RUN_CHECK_FAILED:
    if (priv_level > 0) break;
  case RUN_ACCEPTED:
  case RUN_PENDING_REVIEW:
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
    if (status == RUN_OK || status == RUN_ACCEPTED || status == RUN_PENDING_REVIEW || test <= 0
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
    if (status == RUN_OK || status == RUN_ACCEPTED || status == RUN_PENDING_REVIEW || test <= 0
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
                     disq_attempts, prev_successes, 0, 1);
    fprintf(f, "%s;", score_str);
  }
}

/* structure to tune standings style */
struct standings_style
{
  // "last success", "last submit"
  const unsigned char *success_attr;

  // for tables
  const unsigned char *table_attr;
  const unsigned char *place_attr;
  const unsigned char *team_attr;
  const unsigned char *extra_attr;
  const unsigned char *prob_attr;
  const unsigned char *solved_attr;
  const unsigned char *score_attr;
  const unsigned char *penalty_attr;
  const unsigned char *time_attr;
  const unsigned char *contestant_status_attr;
  const unsigned char *warn_number_attr;

  // for virtual contests
  const unsigned char *self_row_attr;
  const unsigned char *v_row_attr;
  const unsigned char *r_row_attr;
  const unsigned char *u_row_attr;

  // for table cells
  const unsigned char *fail_attr;
  const unsigned char *trans_attr;
  const unsigned char *disq_attr;
  const unsigned char *pr_attr;   // for pending reviews

  // for page table
  const unsigned char *page_table_attr;
  const unsigned char *page_cur_attr;
  /*
  GLOBAL_PARAM(page_row_attr, "x"),
  GLOBAL_PARAM(page_col_attr, "x"),
  */
};

static void
setup_standings_style(struct standings_style *ps,
                      const struct section_global_data *global,
                      int force_fancy_style)
{
  memset(ps, 0, sizeof(*ps));

  ps->table_attr = global->stand_table_attr;
  if (!ps->table_attr[0]) {
    if (global->stand_fancy_style || force_fancy_style)
      ps->table_attr = " width=\"100%\" class=\"standings\"";
    else if (!global->stand_row_attr)
      ps->table_attr = " border=\"1\"";
  }

  ps->success_attr = global->stand_success_attr;

  ps->place_attr = global->stand_place_attr;
  ps->team_attr = global->stand_team_attr;
  ps->extra_attr = global->stand_extra_attr;
  ps->prob_attr = global->stand_prob_attr;
  ps->solved_attr = global->stand_solved_attr;
  ps->score_attr = global->stand_score_attr;
  ps->penalty_attr = global->stand_penalty_attr;
  ps->time_attr = global->stand_time_attr;
  ps->contestant_status_attr = global->stand_contestant_status_attr;
  ps->warn_number_attr = global->stand_warn_number_attr;

  ps->self_row_attr = global->stand_self_row_attr;
  ps->v_row_attr = global->stand_v_row_attr;
  ps->r_row_attr = global->stand_r_row_attr;
  ps->u_row_attr = global->stand_u_row_attr;

  ps->fail_attr = global->stand_fail_attr;
  ps->trans_attr = global->stand_trans_attr;
  ps->disq_attr = global->stand_disq_attr;
  ps->pr_attr = NULL;

  ps->page_table_attr = global->stand_page_table_attr;
  ps->page_cur_attr = global->stand_page_cur_attr;

  if (global->stand_fancy_style || force_fancy_style) {
    //ps->success_attr = global->stand_success_attr;

    if (!ps->place_attr[0])
      ps->place_attr = " class=\"st_place\"";
    if (!ps->team_attr[0])
      ps->team_attr = " class=\"st_team\"";
    if (!ps->extra_attr[0])
      ps->extra_attr = " class=\"st_extra\"";
    if (!ps->prob_attr[0])
      ps->prob_attr = " class=\"st_prob\"";
    if (!ps->solved_attr[0])
      ps->solved_attr = " class=\"st_total\"";
    if (!ps->score_attr[0])
      ps->score_attr = " class=\"st_score\"";
    if (!ps->penalty_attr[0])
      ps->penalty_attr = " class=\"st_pen\"";
    if (!ps->time_attr[0])
      ps->time_attr = " class=\"st_time\"";
    if (!ps->warn_number_attr[0])
      ps->warn_number_attr = " class=\"st_warns\"";
    if (!ps->contestant_status_attr[0])
      ps->contestant_status_attr = " class=\"st_status\"";

    //ps->self_row_attr = global->stand_self_row_attr;
    //ps->v_row_attr = global->stand_v_row_attr;
    //ps->r_row_attr = global->stand_r_row_attr;
    //ps->u_row_attr = global->stand_u_row_attr;

    if (!ps->fail_attr[0])
      ps->fail_attr = " class=\"st_prob\" bgcolor=\"#ff8888\"";
    if (!ps->trans_attr[0])
      ps->trans_attr = " class=\"st_prob\" bgcolor=\"#ffff88\"";
    if (!ps->disq_attr[0])
      ps->disq_attr = " class=\"st_prob\" bgcolor=\"#ffcccc\"";
    if (!ps->pr_attr || !*ps->pr_attr) {
      ps->pr_attr = " class=\"st_prob\" bgcolor=\"#99cc99\"";
    }

    //ps->page_table_attr = global->stand_page_table_attr;
    //ps->page_cur_attr = global->stand_page_cur_attr;
  }
}

static const unsigned char *
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
  stop_time = run_get_stop_time(state->runlog_state);
  if (global->is_virtual && user_id > 0) {
    start_time = run_get_virtual_start_time(state->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(state->runlog_state, user_id, 0);
  }

  if (!start_time) {
    if (user_name) {
      if (global->name[0] && !client_flag) {
        sprintf(header, "%s - &quot;%s&quot; - %s",
                user_name, global->name, _("standings"));
      } else {
        sprintf(header, "%s - %s", user_name, _("Standings"));
      }
    } else {
      if (global->name[0] && !client_flag) {
        sprintf(header, "%s &quot;%s&quot; - %s",
                _("Contest"), global->name, _("standings"));
      } else {
        sprintf(header, "%s", _("Standings"));
      }
    }

    if (!client_flag) {
      if (header_str) {
        process_template(f, header_str, 0, global->charset, header, 0);
      } else {
        fprintf(f, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"/><title>%s</title></head><body><h1>%s</h1>\n",
                global->charset,
                header, header);
      }
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
    if (global->name[0] && !client_flag) {
      sprintf(header, "%s  - &quot;%s&quot; - %s [%s]",
              user_name, global->name, _("standings"), dur_str);
    } else {
      sprintf(header, "%s - %s [%s]",
              user_name, _("Standings"), dur_str);
    }
  } else {
    if (global->name[0] && !client_flag) {
      sprintf(header, "%s &quot;%s&quot; - %s [%s]",
              _("Contest"), global->name, _("standings"), dur_str);
    } else {
      sprintf(header, "%s [%s]", _("Standings"), dur_str);
    }
  }

  if (!client_flag) {
    if (header_str) {
      process_template(f, header_str, 0, global->charset, header, 0);
    } else {
      fprintf(f, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"/><title>%s</title></head><body><h1>%s</h1>",
              global->charset,
              header, header);
    }
  } else {
    fprintf(f, "<%s>%s</%s>\n", cnts->team_head_style,
            header, cnts->team_head_style);
  }
}

static void
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

static void
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
    if (prob->stand_column[0]) continue;
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

void
do_write_kirov_standings(
        const serve_state_t state,
        const struct contest_desc *cnts,
        FILE *f,
        const unsigned char *stand_dir,
        int client_flag,
        int only_table_flag,
        int user_id,
        const unsigned char *header_str,
        unsigned char const *footer_str,
        int raw_flag,
        int accepting_mode,
        int force_fancy_style,
        time_t cur_time,
        int charset_id,
        struct user_filter_info *user_filter,
        int user_mode)
{
  struct section_global_data *global = state->global;
  const struct section_problem_data *prob;
  time_t start_time;
  time_t stop_time;
  time_t cur_duration;
  time_t run_time;

  int  t_max, t_tot, p_max, p_tot, r_tot;
  int *t_ind = 0, *t_rev = 0, *p_ind = 0, *p_rev = 0;
  unsigned char *t_runs = 0;

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
  unsigned char *pr_flag = NULL;
  int *penalty = 0;
  int *cf_num = 0;
  int *marked_flag = 0;

  int  *tot_score = 0, *tot_full = 0, *succ_att = 0, *tot_att = 0, *tot_penalty = 0;
  int  *t_sort = 0, *t_sort2 = 0, *t_n1 = 0, *t_n2 = 0;
  char dur_str[1024];
  unsigned char *head_style;
  struct teamdb_export u_info;
  const struct run_entry *runs;
  int ttot_att, ttot_succ, perc, t;
  const struct team_extra *t_extra;
  const unsigned char *row_attr = 0;
  const unsigned char *col_attr = 0;
  int users_per_page, total_pages, current_page, user_on_page, dur_len;
  unsigned char **pgrefs = 0;
  int *pg_n1 = 0, *pg_n2 = 0;
  path_t stand_name, stand_tmp, stand_path;
  unsigned char att_buf[128];
  unsigned char score_buf[128];
  unsigned char *r_attrs[2][2] = { { "", "" }, { "", "" }};
  unsigned char *pr_attrs[4] = { "", "", "", ""};
  unsigned char *pc_attrs[2] = { "", "" };
  unsigned char *r0_attr = "", *rT_attr = "";
  int attr_num;
  int max_full, max_score;
  int *ind_full = 0, *ind_score = 0;
  int row_sz, row_sh, up_ind;
  int prev_prob = -1, row_ind = 0, group_ind = 1;
  int total_trans = 0;
  int total_prs = 0;
  int total_pending = 0;
  int total_accepted = 0;
  int total_disqualified = 0;
  int total_check_failed = 0;
  struct standings_style ss;
  int sort_flag;
  struct sformat_extra_data fed;
  int last_col_ind = -1;
  char *encode_txt = 0;
  size_t encode_len = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct filter_env env;
  int separate_user_score = 0;
  int token_flags = 0;
  struct xuser_team_extras *extras = NULL;

  memset(&env, 0, sizeof(env));

  if (client_flag) head_style = cnts->team_head_style;
  else head_style = "h2";

  setup_standings_style(&ss, global, force_fancy_style);
  separate_user_score = global->separate_user_score > 0 && state->online_view_judge_score <= 0;

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
  start_time = run_get_start_time(state->runlog_state);
  stop_time = run_get_stop_time(state->runlog_state);
  if (cur_time <= 0) cur_time = time(0);

  if (!start_time || cur_time < start_time) {
    if (raw_flag) goto cleanup;
    if (!client_flag && !only_table_flag) 
      write_standings_header(state, cnts, f, client_flag, 0, header_str, 0);
    if (!only_table_flag)
      fprintf(f, "<%s>%s</%s>", head_style, _("The contest is not started"),
              head_style);
    if (!client_flag && !only_table_flag) {
      if (footer_str) {
        process_template(f, footer_str, 0, 0, 0, get_copyright(0));
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
  r_tot = run_get_total(state->runlog_state);
  runs = run_get_entries_ptr(state->runlog_state);

  /* prune participants, which did not send any solution */
  /* t_runs - 1, if the participant should remain */
  if (global->disable_user_database > 0) {
    t_max = run_get_max_user_id(state->runlog_state) + 1;
  } else {
    t_max = teamdb_get_max_team_id(state->teamdb_state) + 1;
  }
  t_runs = alloca(t_max);
  if (global->prune_empty_users || global->disable_user_database > 0) {
    memset(t_runs, 0, t_max);
    for (k = 0; k < r_tot; k++) {
      if (runs[k].status == RUN_EMPTY || runs[k].status == RUN_VIRTUAL_START
          || runs[k].status == RUN_VIRTUAL_STOP) continue;
      if (runs[k].is_hidden) continue;
      if(runs[k].user_id <= 0 && runs[k].user_id >= t_max) continue;
      t_runs[runs[k].user_id] = 1;
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
  if (global->stand_collate_name) {
    memset(t_rev, -1, t_max * sizeof(t_rev[0]));
    for (i = 1, t_tot = 0; i < t_max; i++) {
      t_rev[i] = -1;
      if (!teamdb_lookup(state->teamdb_state, i)) continue;
      if ((teamdb_get_flags(state->teamdb_state, 
                            i) & (TEAM_INVISIBLE | TEAM_BANNED
                                  | TEAM_DISQUALIFIED))) continue;
      if (!t_runs[i]) continue;

      if (global->stand_collate_name) {
        // collate on team names
        for (j = 0; j < t_tot; j++)
          if (!strcmp(teamdb_get_name_2(state->teamdb_state, t_ind[j]),
                      teamdb_get_name_2(state->teamdb_state, i))) {
            t_rev[i] = j;
            break;
          }
        if (j < t_tot) continue;
      }

      t_rev[i] = t_tot;
      t_ind[t_tot++] = i;
    }
  } else {
    // use a fast function, if no `stand_collate_name'
    teamdb_get_user_map(state, cur_time, t_max,t_runs,&t_tot, t_rev, t_ind,
                        user_filter);
  }

  if (global->stand_show_contestant_status
      || global->stand_show_warn_number
      || global->contestant_status_row_attr) {
    if (state->xuser_state) {
      extras = state->xuser_state->vt->get_entries(state->xuser_state, t_tot, t_ind);
    }
  }

  /* make problem index */
  /* p_tot             - total number of problems in index array
   * p_max             - maximal possible number of problems
   * p_ind[0..p_tot-1] - index array:   prob_idx -> prob_id
   * p_rev[0..p_max-1] - reverse index: prob_id -> prob_idx
   */
  p_max = state->max_prob + 1;
  XALLOCAZ(p_ind, p_max);
  XALLOCAZ(p_rev, p_max);
  get_problem_map(state, cur_time, p_rev, p_max, p_ind, &p_tot, &last_col_ind,
                  user_filter);
  for (i = 1; i < p_max; i++) {
    if (!state->probs) continue;
    if (!(prob = state->probs[i]) || !prob->stand_column[0]) continue;
    if (prob->start_date > 0 && cur_time < prob->start_date) continue;
    for (j = 1; j < p_max; j++) {
      if (!state->probs[j]) continue;
      if (!strcmp(state->probs[j]->short_name, prob->stand_column)
          || !strcmp(state->probs[j]->stand_name, prob->stand_column))
        p_rev[i] = p_rev[j];
    }
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
    XCALLOC(pr_flag, up_ind);
    XCALLOC(penalty, up_ind);
    XCALLOC(cf_num, up_ind);
    XCALLOC(marked_flag, up_ind);
  }
  XALLOCAZ(tot_score, t_tot);
  XALLOCAZ(tot_full, t_tot);
  XALLOCAZ(tot_penalty, t_tot);
  XALLOCAZ(succ_att, p_tot);
  XALLOCAZ(tot_att, p_tot);

  /* auxiluary sorting stuff */
  /* t_sort[0..t_tot-1] - indices of teams (sorted)
   * t_n1[0..t_tot-1]   - first place in interval in case of ties
   * t_n2[0..t_tot-1]   - last place in interval in case of ties
   */
  XALLOCAZ(t_n1, t_tot);
  XALLOCAZ(t_n2, t_tot);

  if (user_filter && user_filter->stand_run_tree) {
    env.teamdb_state = state->teamdb_state;
    env.serve_state = state;
    env.mem = filter_tree_new();
    env.maxlang = state->max_lang;
    env.langs = (const struct section_language_data * const *) state->langs;
    env.maxprob = state->max_prob;
    env.probs = (const struct section_problem_data * const *) state->probs;
    env.rtotal = r_tot;
    env.cur_time = cur_time;
    env.rentries = runs;
    env.rid = 0;
  }

  for (k = 0; k < r_tot; k++) {
    int tind;
    int pind;
    int score, run_score, run_tests, run_status;
    const struct run_entry *pe = &runs[k];

    if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP
        || pe->status == RUN_EMPTY) continue;
    if (pe->user_id <= 0 || pe->user_id >= t_max) continue;
    if (pe->prob_id <= 0 || pe->prob_id > state->max_prob) continue;
    if (pe->is_hidden) continue;
    if (user_filter && user_filter->stand_run_tree) {
      env.rid = k;
      if (filter_tree_bool_eval(&env, user_filter->stand_run_tree) <= 0)
        continue;
    }
    tind = t_rev[pe->user_id];
    pind = p_rev[pe->prob_id];
    up_ind = (tind << row_sh) + pind;
    prob = state->probs[pe->prob_id];
    if (!prob || tind < 0 || pind < 0 || prob->hidden) continue;

    /*
      if (client_flag != 1 || user_id) {
        if (run_time < start_time) run_time = start_time;
        if (current_dur > 0 && run_time - start_time > current_dur) continue;
        if (global->stand_ignore_after > 0
            && pe->time >= global->stand_ignore_after)
          continue;
      }
     */

    // ignore future runs when not in privileged mode
    if (!client_flag || user_id > 0) {
      run_time = pe->time;
      if (run_time < start_time) run_time = start_time;
      if (stop_time && run_time > stop_time) run_time = stop_time;
      if (run_time - start_time > cur_duration) continue;
      if (global->stand_ignore_after > 0
          && pe->time >= global->stand_ignore_after)
        continue;
    }

    token_flags = 0;
    if (user_mode && user_id > 0 && user_id == pe->user_id) {
      token_flags = pe->token_flags;
    }

    if (separate_user_score > 0 && user_mode && pe->is_saved && !(pe->token_flags & TOKEN_FINALSCORE_BIT)) {
      run_status = pe->saved_status;
      run_score = pe->saved_score;
      if (run_status == RUN_OK && !prob->variable_full_score) {
        if (prob->full_user_score >= 0) run_score = prob->full_user_score;
        else run_score = prob->full_score;
      }
      run_tests = pe->saved_test;
    } else {
      run_status = pe->status;
      run_score = pe->score;
      if (run_status == RUN_OK && !prob->variable_full_score) {
        run_score = prob->full_score;
      }
      if (pe->passed_mode > 0) {
        run_tests = pe->test;
      } else {
        run_tests = pe->test - 1;
      }
    }

    if (global->score_system == SCORE_OLYMPIAD && accepting_mode) {
      if (run_score < 0) run_score = 0;
      if (run_tests < 0) run_tests = 0;
      if (run_status == RUN_WRONG_ANSWER_ERR && prob->type != 0) run_status = RUN_PARTIAL;
      switch (run_status) {
      case RUN_OK:
      case RUN_ACCEPTED:
      case RUN_PENDING_REVIEW:
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        full_sol[up_ind] = 1;
        prob_score[up_ind] = prob->tests_to_accept;
        att_num[up_ind]++;  /* hmm, it is not used... */
        if (run_status == RUN_PENDING_REVIEW)
          pr_flag[up_ind] = 1;
        break;
      case RUN_PARTIAL:
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        if (run_tests > prob->tests_to_accept)
          run_tests = prob->tests_to_accept;
        if (run_tests > prob_score[up_ind]) 
          prob_score[up_ind] = run_tests;
        full_sol[up_ind] = 1;
        att_num[up_ind]++;
        break;
      case RUN_COMPILE_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_STYLE_ERR:
      case RUN_REJECTED:
        if (!full_sol[up_ind]) sol_att[up_ind]++;
        if (run_tests > prob->tests_to_accept)
          run_tests = prob->tests_to_accept;
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
      case RUN_CHECK_FAILED:
        cf_num[up_ind]++;
        break;
      default:
        break;
      }
    } else if (global->score_system == SCORE_OLYMPIAD) {
      run_score += pe->score_adj;
      if (run_score < 0) run_score = 0;
      if (run_status == RUN_WRONG_ANSWER_ERR && prob->type != 0) run_status = RUN_PARTIAL;
      switch (run_status) {
      case RUN_OK:
        full_sol[up_ind] = 1;
        trans_num[up_ind] = 0;
        prob_score[up_ind] = run_score;
        att_num[up_ind]++;
        if (global->stand_enable_penalty && prob->ignore_penalty <= 0) {
          penalty[up_ind] += sec_to_min(global->rounding_mode, pe->time - start_time);
        }
        //if (run_score > prob->full_score) run_score = prob->full_score;
        break;
      case RUN_PARTIAL:
        prob_score[up_ind] = run_score;
        full_sol[up_ind] = 0;
        trans_num[up_ind] = 0;
        att_num[up_ind]++;
        if (global->stand_enable_penalty && prob->ignore_penalty <= 0) {
          penalty[up_ind] += sec_to_min(global->rounding_mode, pe->time - start_time);
        }
        break;
      case RUN_ACCEPTED:
        att_num[up_ind]++;
        trans_num[up_ind]++;
        break;
      case RUN_PENDING_REVIEW:
        att_num[up_ind]++;
        trans_num[up_ind]++;
        pr_flag[up_ind] = 1;
        break;
      case RUN_PENDING:
        att_num[up_ind]++;
        trans_num[up_ind]++;
        break;
      case RUN_COMPILE_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_STYLE_ERR:
      case RUN_REJECTED:
        att_num[up_ind]++;
        break;
      case RUN_DISQUALIFIED:
        disq_num[up_ind]++;
        break;
      case RUN_COMPILING:
      case RUN_RUNNING:
        trans_num[up_ind]++;
        break;
      case RUN_CHECK_FAILED:
        cf_num[up_ind]++;
        break;
      default:
        break;
      }
    } else {
      // KIROV system with variations
      if (run_score == -1) run_score = 0;


      /////
      if (prob->score_latest_or_unmarked > 0) {
        if (run_status == RUN_OK) {
          score = calc_kirov_score(0, 0, start_time,
                                   separate_user_score, user_mode, token_flags,
                                   pe, prob, att_num[up_ind],
                                   disq_num[up_ind],
                                   full_sol[up_ind]?RUN_TOO_MANY:succ_att[pind],
                                   0, 0);
          if (pe->is_marked) {
            // latest
            marked_flag[up_ind] = 1;
            prob_score[up_ind] = score;
            if (prob->stand_hide_time <= 0) sol_time[up_ind] = pe->time;
          } else if (marked_flag[up_ind]) {
            // do nothing
          } else if (score > prob_score[up_ind]) {
            // best score
            prob_score[up_ind] = score;
            if (prob->stand_hide_time <= 0) sol_time[up_ind] = pe->time;
          }
          sol_att[up_ind]++;
          succ_att[pind]++;
          tot_att[pind]++;
          att_num[up_ind]++;
          full_sol[up_ind] = 1;
          last_submit_run = k;
          last_success_run = k;
        } else if (run_status == RUN_PARTIAL || (run_status == RUN_WRONG_ANSWER_ERR && prob->type != 0)) {
          score = calc_kirov_score(0, 0, start_time,
                                   separate_user_score, user_mode, token_flags,
                                   pe, prob, att_num[up_ind],
                                   disq_num[up_ind], RUN_TOO_MANY, 0, 0);
          if (pe->is_marked) {
            // latest
            marked_flag[up_ind] = 1;
            prob_score[up_ind] = score;
            if (prob->stand_hide_time <= 0) sol_time[up_ind] = pe->time;
          } else if (marked_flag[up_ind]) {
            // do nothing
          } else if (score > prob_score[up_ind]) {
            // best score
            prob_score[up_ind] = score;
            if (prob->stand_hide_time <= 0) sol_time[up_ind] = pe->time;
          }
          if (!full_sol[up_ind]) sol_att[up_ind]++;
          att_num[up_ind]++;
          if (!full_sol[up_ind]) tot_att[pind]++;
          full_sol[up_ind] = 0;
          last_submit_run = k;
        } else if ((run_status == RUN_COMPILE_ERR
                    || run_status == RUN_STYLE_ERR
                    || run_status == RUN_REJECTED)
                   && !prob->ignore_compile_errors) {
          if (!full_sol[up_ind]) sol_att[up_ind]++;
          att_num[up_ind]++;
          if (!full_sol[up_ind]) tot_att[pind]++;
          last_submit_run = k;
        } else if (run_status == RUN_DISQUALIFIED) {
          if (!full_sol[up_ind]) sol_att[up_ind]++;
          disq_num[up_ind]++;
          ++total_disqualified;
        } else if (run_status == RUN_PENDING_REVIEW) {
          pr_flag[up_ind] = 1;
          ++total_prs;
        } else if (run_status == RUN_PENDING) {
          ++trans_num[up_ind];
          ++total_pending;
        } else if (run_status == RUN_ACCEPTED) {
          ++trans_num[up_ind];
          ++total_accepted;
        } else if (run_status == RUN_COMPILING
                   || run_status == RUN_RUNNING) {
          trans_num[up_ind]++;
          total_trans++;
        } else if (run_status == RUN_CHECK_FAILED) {
          cf_num[up_ind]++;
          ++total_check_failed;
        } else {
          /* something strange... */
        }
      } else {
        if (run_status == RUN_OK) {
          if (!marked_flag[up_ind] || prob->ignore_unmarked <= 0
              || pe->is_marked) {
            marked_flag[up_ind] = pe->is_marked;
            if (!full_sol[up_ind]) sol_att[up_ind]++;
            score = calc_kirov_score(0, 0, start_time,
                                     separate_user_score, user_mode, token_flags,
                                     pe, prob, att_num[up_ind],
                                     disq_num[up_ind],
                                     full_sol[up_ind]?RUN_TOO_MANY:succ_att[pind],
                                     0, 0);
            if (prob->score_latest > 0 || score > prob_score[up_ind]) {
              prob_score[up_ind] = score;
              if (prob->stand_hide_time <= 0) sol_time[up_ind] = pe->time;
            }
            if (!sol_time[up_ind] && prob->stand_hide_time <= 0)
              sol_time[up_ind] = pe->time;
            if (!full_sol[up_ind]) {
              succ_att[pind]++;
              tot_att[pind]++;
            }
            att_num[up_ind]++;
            full_sol[up_ind] = 1;
            last_submit_run = k;
            last_success_run = k;
            if (prob->provide_ok) {
              for (int dst_i = 0; prob->provide_ok[dst_i]; ++dst_i) {
                // find a matching problem
                int dst_pind = 0;
                for (dst_pind = 0; dst_pind < p_tot; ++dst_pind) {
                  if (!strcmp(prob->provide_ok[dst_i], state->probs[p_ind[dst_pind]]->short_name))
                    break;
                }
                if (dst_pind >= p_tot) continue;

                int dst_up_ind = (tind << row_sh) + dst_pind;
                const struct section_problem_data *dst_prob = state->probs[p_ind[dst_pind]];
                marked_flag[dst_up_ind] = pe->is_marked;
                if (!full_sol[dst_up_ind]) ++sol_att[dst_up_ind];
                score = dst_prob->full_score;
                /*
            score = calc_kirov_score(0, 0, start_time,
                                     separate_user_score, user_mode,
                                     pe, prob, att_num[up_ind],
                                     disq_num[up_ind],
                                     full_sol[up_ind]?RUN_TOO_MANY:succ_att[pind],
                                     0, 0);
                */
                if (dst_prob->score_latest > 0 || score > prob_score[dst_up_ind]) {
                  prob_score[dst_up_ind] = score;
                  if (dst_prob->stand_hide_time <= 0) sol_time[dst_up_ind] = pe->time;
                }
                if (!sol_time[dst_up_ind] && dst_prob->stand_hide_time <= 0) {
                  sol_time[dst_up_ind] = pe->time;
                }
                if (!full_sol[dst_up_ind]) {
                  ++succ_att[dst_pind];
                  ++tot_att[dst_pind];
                }
                ++att_num[dst_up_ind];
                full_sol[dst_up_ind] = 1;
              }
            }
          }
        } else if (run_status == RUN_PARTIAL) {
          if (!marked_flag[up_ind] || prob->ignore_unmarked <= 0
              || pe->is_marked) {
            marked_flag[up_ind] = pe->is_marked;
            if (!full_sol[up_ind]) sol_att[up_ind]++;
            score = calc_kirov_score(0, 0, start_time,
                                     separate_user_score, user_mode, token_flags,
                                     pe, prob, att_num[up_ind],
                                     disq_num[up_ind], RUN_TOO_MANY, 0, 0);
            if (prob->score_latest > 0 || score > prob_score[up_ind]) {
              prob_score[up_ind] = score;
            }
            if (prob->score_latest > 0) {
              full_sol[up_ind] = 0;
            }
            att_num[up_ind]++;
            if (!full_sol[up_ind]) tot_att[pind]++;
            last_submit_run = k;
          }
        } else if (run_status == RUN_WRONG_ANSWER_ERR && prob->type != 0) {
          if (!full_sol[up_ind]) sol_att[up_ind]++;
          score = calc_kirov_score(0, 0, start_time,
                                   separate_user_score, user_mode, token_flags,
                                   pe, prob, att_num[up_ind],
                                   disq_num[up_ind], RUN_TOO_MANY, 0, 0);
          if (prob->score_latest > 0 || score > prob_score[up_ind]) {
            prob_score[up_ind] = score;
          }
          att_num[up_ind]++;
          if (!full_sol[up_ind]) tot_att[pind]++;
          last_submit_run = k;
        } else if ((run_status == RUN_COMPILE_ERR 
                    || run_status == RUN_STYLE_ERR
                    || run_status == RUN_REJECTED)
                   && !prob->ignore_compile_errors) {
          if (!full_sol[up_ind]) sol_att[up_ind]++;
          att_num[up_ind]++;
          if (!full_sol[up_ind]) tot_att[pind]++;
          last_submit_run = k;
        } else if (run_status == RUN_DISQUALIFIED) {
          if (!full_sol[up_ind]) sol_att[up_ind]++;
          disq_num[up_ind]++;
          ++total_disqualified;
        } else if (run_status == RUN_PENDING_REVIEW) {
          pr_flag[up_ind] = 1;
          ++total_prs;
        } else if (run_status == RUN_PENDING) {
          ++trans_num[up_ind];
          ++total_pending;
        } else if (run_status == RUN_ACCEPTED) {
          ++trans_num[up_ind];
          ++total_accepted;
        } else if (run_status == RUN_COMPILING
                   || run_status == RUN_RUNNING) {
          trans_num[up_ind]++;
          total_trans++;
        } else if (run_status == RUN_CHECK_FAILED) {
          cf_num[up_ind]++;
          ++total_check_failed;
        } else {
          /* something strange... */
        }
      }
      /////
    }
  }

  /* compute the total for each team */
  if (global->score_n_best_problems > 0 && p_tot > 0) {
    unsigned char *used_flag = alloca(p_tot);
    for (i = 0; i < t_tot; ++i) {
      memset(used_flag, 0, p_tot);
      for (int k = 0; k < global->score_n_best_problems; ++k) {
        int max_ind = -1;
        int max_score = -1;
        for (j = 0; j < p_tot; ++j) {
          up_ind = (i << row_sh) + j;
          if (!used_flag[j] && prob_score[up_ind] > 0 && (max_ind < 0 || prob_score[up_ind] > max_score)) {
            max_ind = j;
            max_score = prob_score[up_ind];
          }
        }
        if (max_ind < 0) break;
        up_ind = (i << row_sh) + max_ind;
        tot_score[i] += prob_score[up_ind];
        tot_full[i] += full_sol[up_ind];
        tot_penalty[i] += penalty[up_ind];
        used_flag[max_ind] = 1;
      }
    }
  } else {
    for (i = 0; i < t_tot; i++) {
      for (j = 0; j < p_tot; j++) {
        up_ind = (i << row_sh) + j;
        if (state->probs[p_ind[j]]->stand_ignore_score <= 0) {
          tot_score[i] += prob_score[up_ind];
          tot_full[i] += full_sol[up_ind];
          tot_penalty[i] += penalty[up_ind];
        }
      }
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
    } else if (global->stand_enable_penalty) {
      /* sort by the number of solved problems, then by the penalty */
      XALLOCA(t_sort, t_tot);
      for (t = 0; t < t_tot; t++)
        t_sort[ind_score[tot_score[t]]++] = t;
      // bubble sort on penalty
      do {
        sort_flag = 0;
        for (i = 1; i < t_tot; i++)
          if (tot_score[t_sort[i-1]] == tot_score[t_sort[i]]
              && tot_penalty[t_sort[i-1]] > tot_penalty[t_sort[i]]) {
            j = t_sort[i - 1]; t_sort[i - 1] = t_sort[i]; t_sort[i] = j;
            sort_flag = 1;
          }
      } while (sort_flag);

      /* resolve ties */
      for(i = 0; i < t_tot;) {
        for (j = i + 1; j < t_tot; j++) {
          if (tot_penalty[t_sort[i]] != tot_penalty[t_sort[j]]
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

  /* memoize the results */
  if (!accepting_mode && global->memoize_user_results) {
    for (i = 0; i < t_tot; ++i) {
      int t = t_sort[i]; // indexed user
      serve_store_user_result(state, t_ind[t], tot_score[t]);
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
    if (!client_flag && !only_table_flag)
      write_standings_header(state, cnts, f, client_flag, 0, header_str, 0);
    /* print table header */
    fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
            ss.table_attr, r0_attr, ss.place_attr, _("Place"),
            ss.team_attr, _("User"));
    if (global->stand_extra_format[0]) {
      if (global->stand_extra_legend[0])
        fprintf(f, "<th%s>%s</th>", ss.extra_attr,
                global->stand_extra_legend);
      else
        fprintf(f, "<th%s>%s</th>", ss.extra_attr, _("Extra info"));
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<th%s>%s</th>", ss.contestant_status_attr, _("Status"));
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<th%s>%s</th>", ss.warn_number_attr, _("Warnings"));
    }
    for (j = 0; j < p_tot; j++) {
      fprintf(f, "<th%s>", ss.prob_attr);
      if (global->prob_info_url[0]) {
        sformat_message(dur_str, sizeof(dur_str), 0, global->prob_info_url,
                        NULL, state->probs[p_ind[j]], NULL, NULL, NULL, 0, 0, 0);
        fprintf(f, "<a href=\"%s\">", dur_str);
      }
      if (state->probs[p_ind[j]]->stand_name[0]) {
        fprintf(f, "%s", state->probs[p_ind[j]]->stand_name);
      } else {
        fprintf(f, "%s", state->probs[p_ind[j]]->short_name);
      }
      if (global->prob_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</th>");
    }
    fprintf(f, "<th%s>%s</th><th%s>%s</th>",
            ss.solved_attr, _("Solved<br/>problems"),
            ss.score_attr, _("Score"));
    fprintf(f, "</tr>\n");
  }

  for (i = 0; i < t_tot; i++, user_on_page = (user_on_page + 1) % users_per_page) {
    if (!user_on_page) {
      current_page++;
      if (!f) {
        snprintf(stand_name, sizeof(stand_name), global->stand_file_name_2,
                 current_page);
        snprintf(stand_tmp, sizeof(stand_path), "%s/in/%s.tmp", stand_dir, stand_name);
        snprintf(stand_path, sizeof(stand_path), "%s/dir/%s", stand_dir, stand_name);
        if (charset_id > 0) {
          if (!(f = open_memstream(&encode_txt, &encode_len))) goto cleanup;
        } else {
          if (!(f = sf_fopen(stand_tmp, "w"))) goto cleanup;
        }
      }
      if (!client_flag && !only_table_flag)
        write_standings_header(state, cnts, f, client_flag, 0, header_str, 0);

      /* print "Last success" information */
      fprintf(f, "<table class=\"table-14\">\n");
      if (last_success_run >= 0) {
        duration_str(global->show_astr_time,
                     runs[last_success_run].time, start_time,
                     dur_str, sizeof(dur_str));

        fprintf(f, "<tr%s><td>%s:</td><td>%s, ",
                ss.success_attr, _("Last success"), dur_str);
        if (global->team_info_url[0]) {
          teamdb_export_team(state->teamdb_state,
                             runs[last_success_run].user_id,
                             &u_info);
          sformat_message(dur_str, sizeof(dur_str), 0, global->team_info_url,
                          NULL, NULL, NULL, NULL, &u_info, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        fprintf(f, "%s", ARMOR(stand_get_name(state, runs[last_success_run].user_id)));
        if (global->team_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ", ");

        if (global->prob_info_url[0]) {
          sformat_message(dur_str, sizeof(dur_str), 0, global->prob_info_url,
                          NULL, state->probs[runs[last_success_run].prob_id],
                          NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        j = runs[last_success_run].prob_id;
        if (state->probs[j]->stand_name[0]) {
          fprintf(f, "%s", state->probs[j]->stand_name);
        } else {
          fprintf(f, "%s", state->probs[j]->short_name);
        }
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ".</td></tr>\n");
      }
      /* print "Last submit" information */
      if (last_submit_run >= 0) {
        duration_str(global->show_astr_time,
                     runs[last_submit_run].time, start_time,
                     dur_str, sizeof(dur_str));
        fprintf(f, "<tr%s><td>%s:</td><td>%s, ",
                ss.success_attr, _("Last submit"), dur_str);
        if (global->team_info_url[0]) {
          teamdb_export_team(state->teamdb_state,
                             runs[last_submit_run].user_id,
                             &u_info);
          sformat_message(dur_str, sizeof(dur_str), 0, global->team_info_url,
                          NULL, NULL, NULL, NULL, &u_info, u_info.user, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        fprintf(f, "%s", ARMOR(stand_get_name(state, runs[last_submit_run].user_id)));
        if (global->team_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ", ");

        if (global->prob_info_url[0]) {
          sformat_message(dur_str, sizeof(dur_str), 0, global->prob_info_url,
                          NULL, state->probs[runs[last_submit_run].prob_id],
                          NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        j = runs[last_submit_run].prob_id;
        if (state->probs[j]->stand_name[0]) {
          fprintf(f, "%s", state->probs[j]->stand_name);
        } else {
          fprintf(f, "%s", state->probs[j]->short_name);
        }
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ".</td></tr>\n");
      }
      if (total_trans) {
        row_attr = "";
        if (ss.trans_attr && ss.trans_attr[0]) row_attr = ss.trans_attr;
        fprintf(f, "<tr%s><td%s>%s:</td><td%s>%d</td></tr>",
                ss.success_attr, row_attr, _("Runs being processed"), row_attr, total_trans);
      }
      if (total_prs > 0) {
        if (ss.pr_attr && ss.pr_attr[0]) row_attr = ss.pr_attr;
        fprintf(f, "<tr%s><td%s>%s:</td><td%s>%d</td></tr>",
                ss.success_attr, row_attr, _("Runs pending review"), row_attr, total_prs);
      }
      if (total_pending > 0) {
        if (ss.trans_attr && ss.trans_attr[0]) row_attr = ss.trans_attr;
        fprintf(f, "<tr%s><td%s>%s:</td><td%s>%d</td></tr>",
                ss.success_attr, row_attr, _("Runs pending testing"), row_attr, total_pending);
      }
      if (total_accepted > 0) {
        if (ss.trans_attr && ss.trans_attr[0]) row_attr = ss.trans_attr;
        fprintf(f, "<tr%s><td%s>%s:</td><td%s>%d</td></tr>",
                ss.success_attr, row_attr, _("Runs accepted for testing"), row_attr, total_accepted);
      }
      if (total_disqualified > 0) {
        if (ss.disq_attr && ss.disq_attr[0]) row_attr = ss.disq_attr;
        fprintf(f, "<tr%s><td%s>%s:</td><td%s>%d</td></tr>",
                ss.success_attr, row_attr, _("Disqualified runs"), row_attr, total_disqualified);
      }
      if (total_check_failed > 0) {
        if (ss.fail_attr && ss.fail_attr[0]) row_attr = ss.fail_attr;
        fprintf(f, "<tr%s><td%s>%s:</td><td%s>%d</td></tr>",
                ss.success_attr, row_attr, _("Check failed runs"), row_attr, total_check_failed);
      }

      if (total_pages > 1) {
        fprintf(f, _("<tr%s><td colspan=\"2\">Page %d of %d.</td></tr>\n"),
                ss.page_cur_attr, current_page, total_pages);

        write_kirov_page_table(&ss, f, total_pages, current_page, pgrefs,
                               t_sort, tot_full, tot_score, pg_n1, pg_n2,
                               pr_attrs, pc_attrs);
      }
      fprintf(f, "</table>\n");

      /* print table header */
      fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
              ss.table_attr, r0_attr,
              ss.place_attr, _("Place"),
              ss.team_attr, _("User"));
      if (global->stand_extra_format[0]) {
        if (global->stand_extra_legend[0])
          fprintf(f, "<th%s>%s</th>", ss.extra_attr,
                  global->stand_extra_legend);
        else
          fprintf(f, "<th%s>%s</th>", ss.extra_attr, _("Extra info"));
      }
      if (global->stand_show_contestant_status
          && global->contestant_status_num > 0) {
        fprintf(f, "<th%s>%s</th>", ss.contestant_status_attr, _("Status"));
      }
      if (global->stand_show_warn_number) {
        fprintf(f, "<th%s>%s</th>", ss.warn_number_attr, _("Warnings"));
      }
      for (j = 0; j < p_tot; j++) {
        if (state->probs[p_ind[j]]->stand_last_column > 0) continue;
        col_attr = state->probs[p_ind[j]]->stand_attr;
        if (!*col_attr) col_attr = ss.prob_attr;
        fprintf(f, "<th%s>", col_attr);
        if (global->prob_info_url[0]) {
          sformat_message(dur_str, sizeof(dur_str), 0, global->prob_info_url,
                          NULL, state->probs[p_ind[j]], NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", dur_str);
        }
        if (state->probs[p_ind[j]]->stand_name[0]) {
          fprintf(f, "%s", state->probs[p_ind[j]]->stand_name);
        } else {
          fprintf(f, "%s", state->probs[p_ind[j]]->short_name);
        }
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, "</th>");
      }
      fprintf(f, "<th%s>%s</th><th%s>%s</th>",
              ss.solved_attr, _("Solved<br/>problems"),
              ss.score_attr, _("Score"));
      if (global->stand_enable_penalty) {
        fprintf(f, "<th%s>%s</th>", ss.penalty_attr, _("Penalty"));
      }

      if (last_col_ind >= 0) {
        for (j = last_col_ind; j < p_tot; j++) {
          if (state->probs[p_ind[j]]->stand_last_column <= 0) continue;
          col_attr = state->probs[p_ind[j]]->stand_attr;
          if (!*col_attr) col_attr = ss.prob_attr;
          fprintf(f, "<th%s>", col_attr);
          if (global->prob_info_url[0]) {
            sformat_message(dur_str, sizeof(dur_str), 0, global->prob_info_url,
                            NULL, state->probs[p_ind[j]], NULL, NULL, NULL,
                            0, 0, 0);
            fprintf(f, "<a href=\"%s\">", dur_str);
          }
          if (state->probs[p_ind[j]]->stand_name[0]) {
            fprintf(f, "%s", state->probs[p_ind[j]]->stand_name);
          } else {
            fprintf(f, "%s", state->probs[p_ind[j]]->short_name);
          }
          if (global->prob_info_url[0]) {
            fprintf(f, "</a>");
          }
          fprintf(f, "</th>");
        }
      }

      fprintf(f, "</tr>\n");
    }

    /* print page contents */
    t = t_sort[i];

    if (global->team_info_url[0] || global->stand_extra_format[0]) {
      teamdb_export_team(state->teamdb_state, t_ind[t], &u_info);
    } else {
      memset(&u_info, 0, sizeof(u_info));
    }
    t_extra = NULL;
    if (extras) {
      t_extra = extras->get(extras, t_ind[t]);
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
    fprintf(f, "<tr%s><td%s>", row_attr, ss.place_attr);
    if (t_n1[i] == t_n2[i]) fprintf(f, "%d", t_n1[i] + 1);
    else fprintf(f, "%d-%d", t_n1[i] + 1, t_n2[i] + 1);
    fputs("</td>", f);
    fprintf(f, "<td%s>", ss.team_attr);
    if (global->team_info_url[0]) {
      sformat_message(dur_str, sizeof(dur_str), 0, global->team_info_url,
                      NULL, NULL, NULL, NULL, &u_info, u_info.user, 0, 0);
      fprintf(f, "<a href=\"%s\">", dur_str);
    }
    fprintf(f, "%s", ARMOR(stand_get_name(state, t_ind[t])));
    if (global->team_info_url[0]) {
      fprintf(f, "</a>");
    }
    fprintf(f, "</td>");
    if (global->stand_extra_format[0]) {
      memset(&fed, 0, sizeof(fed));
      fed.variant = find_user_variant(state, u_info.id, 0);
      sformat_message(dur_str, sizeof(dur_str), 1, global->stand_extra_format,
                      NULL, NULL, NULL, NULL, &u_info, u_info.user, 0, &fed);
      fprintf(f, "<td%s>%s</td>", ss.extra_attr, dur_str);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      if (t_extra && t_extra->status >= 0
          && t_extra->status < global->contestant_status_num) {
        fprintf(f, "<td%s>%s</td>", ss.contestant_status_attr,
                global->contestant_status_legend[t_extra->status]);
      } else {
        fprintf(f, "<td%s>?</td>", ss.contestant_status_attr);
      }
    }
    if (global->stand_show_warn_number) {
      if (t_extra && t_extra->warn_u > 0) {
        fprintf(f, "<td%s>%d</td>", ss.warn_number_attr, t_extra->warn_u);
      } else {
        fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
      }
    }
    for (j = 0; j < p_tot; j++) {
      if (state->probs[p_ind[j]]->stand_last_column > 0) continue;
      up_ind = (t << row_sh) + j;
      row_attr = state->probs[p_ind[j]]->stand_attr;
      if (!*row_attr) row_attr = ss.prob_attr;
      if (pr_flag[up_ind] && ss.pr_attr && ss.pr_attr[0])
        row_attr = ss.pr_attr;
      if (trans_num[up_ind] && ss.trans_attr && ss.trans_attr[0])
        row_attr = ss.trans_attr;
      if (disq_num[up_ind] > 0 && ss.disq_attr && ss.disq_attr[0])
        row_attr = ss.disq_attr;
      if (cf_num[up_ind] > 0 && ss.fail_attr && ss.fail_attr[0])
        row_attr = ss.fail_attr;
      if (!att_num[up_ind]) {
        fprintf(f, "<td%s>&nbsp;</td>", row_attr);
      } else if (full_sol[up_ind]) {
        att_buf[0] = 0;
        if (global->stand_show_att_num) {
          snprintf(att_buf, sizeof(att_buf), " (%d)", sol_att[up_ind]);
        }
        score_view_display(score_buf, sizeof(score_buf),
                           state->probs[p_ind[j]], prob_score[up_ind]);
        if (global->stand_show_ok_time && sol_time[up_ind] > 0) {
          duration_str(global->show_astr_time, sol_time[up_ind], start_time,
                       dur_str, 0);
          fprintf(f, "<td%s><b>%s</b>%s<div%s>%s</div></td>",
                  row_attr, score_buf, att_buf,
                  ss.time_attr, dur_str);
        } else {
          fprintf(f, "<td%s><b>%s</b>%s</td>", row_attr, 
                  score_buf, att_buf);
        }
      } else {
        att_buf[0] = 0;
        if (global->stand_show_att_num) {
          snprintf(att_buf, sizeof(att_buf), " (%d)", sol_att[up_ind]);
        }
        score_view_display(score_buf, sizeof(score_buf),
                           state->probs[p_ind[j]], prob_score[up_ind]);
        if (global->stand_show_ok_time && sol_time[up_ind] > 0) {
          duration_str(global->show_astr_time, sol_time[up_ind],
                       start_time, dur_str, 0);
          fprintf(f, "<td%s>%s%s<div%s>%s</div></td>",
                  row_attr, score_buf, att_buf,
                  ss.time_attr, dur_str);
        } else {
          fprintf(f, "<td%s>%s%s</td>", row_attr, score_buf, att_buf);
        }
      }
    }
    fprintf(f, "<td%s>%d</td><td%s>%d</td>",
            ss.solved_attr, tot_full[t],
            ss.score_attr, tot_score[t]);
    if (global->stand_enable_penalty) {
      fprintf(f, "<td%s>%d</td>", ss.penalty_attr, tot_penalty[t]);
    }
    if (last_col_ind >= 0) {
      for (j = last_col_ind; j < p_tot; j++) {
        if (state->probs[p_ind[j]]->stand_last_column <= 0) continue;
        up_ind = (t << row_sh) + j;
        row_attr = state->probs[p_ind[j]]->stand_attr;
        if (!*row_attr) row_attr = ss.prob_attr;
        if (pr_flag[up_ind] && ss.pr_attr && ss.pr_attr[0])
          row_attr = ss.pr_attr;
        if (trans_num[up_ind] && ss.trans_attr && ss.trans_attr[0])
          row_attr = ss.trans_attr;
        if (disq_num[up_ind] > 0 && ss.disq_attr && ss.disq_attr[0])
          row_attr = ss.disq_attr;
        if (cf_num[up_ind] > 0 && ss.fail_attr && ss.fail_attr[0])
          row_attr = ss.fail_attr;
        if (!att_num[up_ind]) {
          fprintf(f, "<td%s>&nbsp;</td>", row_attr);
        } else if (full_sol[up_ind]) {
          att_buf[0] = 0;
          if (global->stand_show_att_num) {
            snprintf(att_buf, sizeof(att_buf), " (%d)", sol_att[up_ind]);
          }
          score_view_display(score_buf, sizeof(score_buf),
                             state->probs[p_ind[j]], prob_score[up_ind]);
          if (global->stand_show_ok_time && sol_time[up_ind] > 0) {
            duration_str(global->show_astr_time, sol_time[up_ind], start_time,
                         dur_str, 0);
            fprintf(f, "<td%s><b>%s</b>%s<div%s>%s</div></td>",
                    row_attr, score_buf, att_buf,
                    ss.time_attr, dur_str);
          } else {
            fprintf(f, "<td%s><b>%s</b>%s</td>", row_attr, 
                    score_buf, att_buf);
          }
        } else {
          att_buf[0] = 0;
          if (global->stand_show_att_num) {
            snprintf(att_buf, sizeof(att_buf), " (%d)", sol_att[up_ind]);
          }
          score_view_display(score_buf, sizeof(score_buf),
                             state->probs[p_ind[j]], prob_score[up_ind]);
          if (global->stand_show_ok_time && sol_time[up_ind] > 0) {
            duration_str(global->show_astr_time, sol_time[up_ind],
                         start_time, dur_str, 0);
            fprintf(f, "<td%s>%s%s<div%s>%s</div></td>",
                    row_attr, score_buf, att_buf,
                    ss.time_attr, dur_str);
          } else {
            fprintf(f, "<td%s>%s%s</td>", row_attr, score_buf, att_buf);
          }
        }
      }
    }
    fprintf(f, "</tr>\n");

    if (user_on_page == users_per_page - 1 && current_page != total_pages) {
      fputs("</table>\n", f);

      write_kirov_page_table(&ss, f, total_pages, current_page, pgrefs,
                             t_sort, tot_full, tot_score, pg_n1, pg_n2,
                             pr_attrs, pc_attrs);

      if (!client_flag) {
        if (footer_str) {
          process_template(f, footer_str, 0, 0, 0, get_copyright(0));
        } else {
          fputs("</body></html>", f);
        }
      }
      if (current_page > 1) {
        fclose(f);
        if (charset_id > 0) {
          encode_txt = charset_encode_heap(charset_id, encode_txt);
          encode_len = strlen(encode_txt);
          generic_write_file(encode_txt, encode_len, 0, NULL, stand_tmp, NULL);
          xfree(encode_txt); encode_txt = 0; encode_len = 0;
        }
        rename(stand_tmp, stand_path);
      }
      f = 0;
    }
  }

  // print row of total
  fprintf(f, "<tr%s>", rT_attr);
  fprintf(f, "<td%s>&nbsp;</td>", ss.place_attr);
  fprintf(f, "<td%s>%s:</td>", ss.team_attr, _("Total"));
  if (global->stand_extra_format[0]) {
    fprintf(f, "<td%s>&nbsp;</td>", ss.extra_attr);
  }
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0) {
    fprintf(f, "<td%s>&nbsp;</td>", ss.contestant_status_attr);
  }
  if (global->stand_show_warn_number) {
    fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
  }
  for (j = 0, ttot_att = 0; j < p_tot; j++) {
    if (state->probs[p_ind[j]]->stand_last_column > 0) continue;
    fprintf(f, "<td%s>%d</td>", ss.prob_attr, tot_att[j]);
    ttot_att += tot_att[j];
  }
  fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td>",
          ss.solved_attr, ttot_att, ss.penalty_attr);
  if (last_col_ind >= 0) {
    for (j = last_col_ind, ttot_att = 0; j < p_tot; j++) {
      if (state->probs[p_ind[j]]->stand_last_column <= 0) continue;
      fprintf(f, "<td%s>%d</td>", ss.prob_attr, tot_att[j]);
      ttot_att += tot_att[j];
    }
  }
  fprintf(f, "</tr>\n");
  // print row of success
  fprintf(f, "<tr%s>", rT_attr);
  fprintf(f, "<td%s>&nbsp;</td>", ss.place_attr);
  fprintf(f, "<td%s>%s:</td>", ss.team_attr, _("Success"));
  if (global->stand_extra_format[0]) {
    fprintf(f, "<td%s>&nbsp;</td>", ss.extra_attr);
  }
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0) {
    fprintf(f, "<td%s>&nbsp;</td>", ss.contestant_status_attr);
  }
  if (global->stand_show_warn_number) {
    fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
  }
  for (j = 0, ttot_succ = 0; j < p_tot; j++) {
    if (state->probs[p_ind[j]]->stand_last_column > 0) continue;
    fprintf(f, "<td%s>%d</td>", ss.prob_attr, succ_att[j]);
    ttot_succ += succ_att[j];
  }
  fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td>",
          ss.solved_attr, ttot_succ, ss.penalty_attr);
  if (last_col_ind >= 0) {
    for (j = last_col_ind, ttot_succ = 0; j < p_tot; j++) {
      if (state->probs[p_ind[j]]->stand_last_column <= 0) continue;
      fprintf(f, "<td%s>%d</td>", ss.prob_attr, succ_att[j]);
      ttot_succ += succ_att[j];
    }
  }
  fprintf(f, "</tr>\n");
  // print row of percentage
  fprintf(f, "<tr%s>", rT_attr);
  fprintf(f, "<td%s>&nbsp;</td>", ss.place_attr);
  fprintf(f, "<td%s>%%:</td>", ss.team_attr);
  if (global->stand_extra_format[0]) {
    fprintf(f, "<td%s>&nbsp;</td>", ss.extra_attr);
  }
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0) {
    fprintf(f, "<td%s>&nbsp;</td>", ss.contestant_status_attr);
  }
  if (global->stand_show_warn_number) {
    fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
  }
  for (j = 0; j < p_tot; j++) {
    if (state->probs[p_ind[j]]->stand_last_column > 0) continue;
    perc = 0;
    if (tot_att[j] > 0) {
      perc = (int) ((double) succ_att[j] / tot_att[j] * 100.0 + 0.5);
    }
    fprintf(f, "<td%s>%d%%</td>", ss.prob_attr, perc);
  }
  perc = 0;
  if (ttot_att > 0) {
    perc = (int) ((double) ttot_succ / ttot_att * 100.0 + 0.5);
  }
  fprintf(f, "<td%s>%d%%</td><td%s>&nbsp;</td>",
          ss.solved_attr, perc, ss.penalty_attr);
  if (last_col_ind >= 0) {
    for (j = last_col_ind; j < p_tot; j++) {
      if (state->probs[p_ind[j]]->stand_last_column <= 0) continue;
      perc = 0;
      if (tot_att[j] > 0) {
        perc = (int) ((double) succ_att[j] / tot_att[j] * 100.0 + 0.5);
      }
      fprintf(f, "<td%s>%d%%</td>", ss.prob_attr, perc);
    }
  }
  fprintf(f, "</tr>\n");

  fputs("</table>\n", f);

  if (!client_flag && !only_table_flag) {
    if (total_pages > 1)
      write_kirov_page_table(&ss, f, total_pages, current_page, pgrefs,
                             t_sort, tot_full, tot_score, pg_n1, pg_n2,
                             pr_attrs, pc_attrs);

    if (footer_str) {
      process_template(f, footer_str, 0, 0, 0, get_copyright(0));
    } else {
      fputs("</body></html>", f);
    }
  }
  if (total_pages > 1) {
    fclose(f); f = 0;
    if (charset_id > 0) {
      encode_txt = charset_encode_heap(charset_id, encode_txt);
      encode_len = strlen(encode_txt);
      generic_write_file(encode_txt, encode_len, 0, NULL, stand_tmp, NULL);
      xfree(encode_txt); encode_txt = 0; encode_len = 0;
    }
    rename(stand_tmp, stand_path); // FIXME: handle errors
  }

 cleanup:
  // xfree(t_runs):      currently on stack
  // xfree(t_ind):       currently on stack
  // xfree(t_rev):       currently on stack
  // xfree(p_ind):       currently on stack
  // xfree(p_rev):       currently on stack
  // xfree(tot_score):   currently on stack
  // xfree(tot_full):    currently on stack
  // xfree(tot_penalty): currently on stack
  // xfree(tot_att):     currently on stack
  // xfree(succ_att):    currently on stack
  // xfree(t_n1):        currently on stack
  // xfree(t_n2):        currently on stack
  // xfree(ind_full):    currently on stack
  // xfree(ind_score):   currently on stack
  // xfree(t_sort):      currently on stack
  // xfree(t_sort2):     currently on stack
  // xfree(pgrefs):      currently on stack
  // xfree(pg_n1):       currently on stack
  // xfree(pg_n2):       currently on stack

  xfree(prob_score);
  xfree(att_num);
  xfree(disq_num);
  xfree(sol_att);
  xfree(full_sol);
  xfree(sol_time);
  xfree(trans_num);
  xfree(pr_flag);
  xfree(cf_num);
  xfree(penalty);
  xfree(marked_flag);
  html_armor_free(&ab);
  env.mem = filter_tree_delete(env.mem);
  if (extras) extras->free(extras);
}

static int
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

static void
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

void
do_write_moscow_standings(
        const serve_state_t state,
        const struct contest_desc *cnts,
        FILE *f,
        const unsigned char *stand_dir,
        int client_flag,
        int only_table_flag,
        int user_id,
        const unsigned char *header_str,
        const unsigned char *footer_str,
        int raw_flag,
        const unsigned char *user_name,
        int force_fancy_style,
        time_t cur_time,
        int charset_id,
        struct user_filter_info *user_filter)
{
  struct section_global_data *global = state->global;
  const unsigned char *head_style;
  time_t start_time;
  time_t stop_time;
  time_t contest_dur;
  time_t current_dur;
  time_t ustart;
  time_t udur = 0;
  time_t last_success_time = 0;
  time_t last_success_start = 0;
  time_t last_submit_time = 0;
  time_t last_submit_start = 0;

  int r_tot;                    /* total number of runs */
  const struct run_entry *runs; /* the pointer to the PRIMARY runs storage */
  int u_max;                    /* maximal user_id + 1 */
  int u_tot;                    /* total active users */
  unsigned char *u_runs = 0;    /* whether user submitted runs (on stack) */
  int *u_ind = 0;               /* active user num -> user_id map */
  int *u_rev = 0;               /* user_id -> active user num map */
  int p_max;                    /* maximal prob_id + 1 */
  int p_tot;                    /* total active problems */
  int *p_ind = 0;               /* active problem num -> prob_id map */
  int *p_rev = 0;               /* prob_id -> active problem num map */
  int row_sz;                   /* number of columns for two-dim. tables */
  int row_sh;                   /* shift count for two-dim. tables */
  int *u_sort = 0;              /* sorted index to u_ind */
  int *u_sort1 = 0;             /* intermediate sorted index */
  int *u_score = 0;             /* total score for a user */
  int *u_pen = 0;               /* total penalty for a user */
  int *p_att = 0;               /* total attempts for a problem */
  int *p_succ = 0;              /* full solutions for a problem */
  int *pen_cnt = 0;             /* counters for all penalty values */
  int *pen_st = 0;              /* starting position for all penalty values */
  int *sc_cnt = 0;              /* counters for all score values */
  int *sc_st = 0;               /* starting position for all score values */
  int *u_n1 = 0;                /* first place number */
  int *u_n2 = 0;                /* second place number */
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
  const struct team_extra *u_extra;
  path_t stand_tmp;             /* temporary file path */
  path_t stand_path;            /* final path for a standings page */
  const unsigned char *row_attr;
  unsigned char *r_attrs[2][2] = { { "", ""}, { "", "" }};
  unsigned char *pr_attrs[4] = { "", "", "", "" };
  unsigned char *pc_attrs[2] = { "", "" };
  unsigned char *r0_attr = "", *rT_attr = "";
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
  struct standings_style ss;
  const struct section_problem_data *prob;
  struct sformat_extra_data fed;
  char *encode_txt = 0;
  size_t encode_len = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct filter_env env;
  struct xuser_team_extras *extras = NULL;
  
  memset(&env, 0, sizeof(env));

  if (client_flag) head_style = cnts->team_head_style;
  else head_style = "h2";

  setup_standings_style(&ss, global, force_fancy_style);

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

  if (cur_time <= 0) cur_time = time(0);
  last_submit_start = last_success_start = start_time = run_get_start_time(state->runlog_state);
  stop_time = run_get_stop_time(state->runlog_state);
  contest_dur = run_get_duration(state->runlog_state);
  if (start_time && global->is_virtual && user_id > 0) {
    start_time = run_get_virtual_start_time(state->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(state->runlog_state, user_id, 0);
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
    if (only_table_flag) return;
    write_standings_header(state, cnts, f, client_flag, user_id, header_str,
                           user_name);
    fprintf(f, "<%s>%s</%s>", head_style, _("The contest is not started"),
            head_style);
    if (!client_flag) {
      if (footer_str) {
        process_template(f, footer_str, 0, 0, 0, get_copyright(0));
      } else {
        fprintf(f, "</body></html>");
      }
    }
    return;
  }

  r_tot = run_get_total(state->runlog_state);
  runs = run_get_entries_ptr(state->runlog_state);

  if (global->disable_user_database > 0) {
    u_max = run_get_max_user_id(state->runlog_state) + 1;
  } else {
    u_max = teamdb_get_max_team_id(state->teamdb_state) + 1;
  }
  u_runs = (unsigned char*) alloca(u_max);
  if (global->prune_empty_users || global->disable_user_database > 0) {
    memset(u_runs, 0, u_max);
    for (i = 0; i < r_tot; i++)
      if (runs[i].status != RUN_EMPTY
          && runs[i].user_id > 0 && runs[i].user_id < u_max
          && !runs[i].is_hidden)
        u_runs[runs[i].user_id] = 1;
  } else {
    memset(u_runs, 1, u_max);
  }

  /* make users index */
  XALLOCA(u_ind, u_max);
  XALLOCA(u_rev, u_max);
  teamdb_get_user_map(state, cur_time, u_max, u_runs, &u_tot, u_rev, u_ind,
                      user_filter);
  /*
  for (i = 1, u_tot = 0; i < u_max; i++)
    if (teamdb_lookup(state->teamdb_state, i) > 0
        && !(teamdb_get_flags(state->teamdb_state,
                              i) & (TEAM_INVISIBLE | TEAM_BANNED | TEAM_DISQUALIFIED))
        && u_runs[i]) {
      u_rev[i] = u_tot;
      u_ind[u_tot] = i;
      u_tot++;
    }
  */

  if (global->stand_show_contestant_status
      || global->stand_show_warn_number
      || global->contestant_status_row_attr) {
    if (state->xuser_state) {
      extras = state->xuser_state->vt->get_entries(state->xuser_state, u_tot, u_ind);
    }
  }

  /* sorted index to u_ind */
  XALLOCA(u_sort, u_tot);
  for (i = 0; i < u_tot; i++)
    u_sort[i] = i;

  /* make problems index */
  p_max = state->max_prob + 1;
  XALLOCA(p_ind, p_max);
  XALLOCA(p_rev, p_max);
  get_problem_map(state, cur_time, p_rev, p_max, p_ind, &p_tot, NULL,
                  user_filter);
  for (i = 1; i < p_max; i++) {
    if (!(prob = state->probs[i])) continue;
    if (!prob->stand_column[0]) continue;
    if (prob->start_date > 0 && cur_time < prob->start_date) continue;
    for (j = 1; j < p_max; j++) {
      if (!state->probs[j]) continue;
      if (!strcmp(prob->stand_column, state->probs[j]->short_name)
          || !strcmp(prob->stand_column, state->probs[j]->stand_name))
        p_rev[i] = p_rev[j];
    }
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

  if (user_filter && user_filter->stand_run_tree) {
    env.teamdb_state = state->teamdb_state;
    env.serve_state = state;
    env.mem = filter_tree_new();
    env.maxlang = state->max_lang;
    env.langs = (const struct section_language_data * const *) state->langs;
    env.maxprob = state->max_prob;
    env.probs = (const struct section_problem_data * const *) state->probs;
    env.rtotal = r_tot;
    env.cur_time = cur_time;
    env.rentries = runs;
    env.rid = 0;
  }

  for (i = 0; i < r_tot; i++) {
    const struct run_entry *pe = &runs[i];
    time_t run_time = pe->time;
    int up_ind;

    if (pe->is_hidden) continue;
    if (pe->status > RUN_MAX_STATUS && pe->status < RUN_TRANSIENT_FIRST) continue;
    if (pe->status > RUN_TRANSIENT_LAST) continue;
    if (pe->user_id <= 0 || pe->user_id >= u_max || (u = u_rev[pe->user_id]) < 0) continue;
    if (pe->prob_id <= 0 || pe->prob_id > state->max_prob) continue;
    if ((p = p_rev[pe->prob_id]) < 0) continue;
    if (user_filter && user_filter->stand_run_tree) {
      env.rid = i;
      if (filter_tree_bool_eval(&env, user_filter->stand_run_tree) <= 0)
        continue;
    }
    prob = state->probs[pe->prob_id];
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
    if (global->is_virtual) {
      // filter "future" virtual runs
      ustart = run_get_virtual_start_time(state->runlog_state, pe->user_id);
      if (run_time < ustart) run_time = ustart;
      udur = run_time - ustart;
      if (udur > contest_dur) udur = contest_dur;
      if (user_id > 0 && udur > current_dur) continue;
    } else if (client_flag != 1 || user_id) {
      // filter future real runs for unprivileged standings
      if (run_time < start_time) run_time = start_time;
      udur = run_time - start_time;
      if (current_dur > 0 && udur > current_dur) continue;
      if (global->stand_ignore_after > 0
          && pe->time >= global->stand_ignore_after)
        continue;
    } else {
      if (run_time < start_time) run_time = start_time;
      udur = run_time - start_time;
    }

    if (pe->status == RUN_OK) {
      up_solved[up_ind] = 1;
      up_att[up_ind] = up_totatt[up_ind];
      up_pen[up_ind] = sec_to_min(global->rounding_mode, udur);
      up_time[up_ind] = run_time;
      up_totatt[up_ind]++;
      up_score[up_ind] = prob->full_score;
      if (prob->variable_full_score) up_score[up_ind] = pe->score;
      p_att[p]++;
      p_succ[p]++;
      if (!global->is_virtual) {
        last_success_run = i;
        last_success_time = pe->time;
        last_success_start = ustart;
        last_submit_run = i;
        last_submit_time = pe->time;
        last_submit_start = ustart;
      }
    } else if (run_is_failed_attempt(pe->status)) {
      if (pe->score > up_score[up_ind]) {
        up_att[up_ind] = up_totatt[up_ind];
        up_pen[up_ind] = sec_to_min(global->rounding_mode, udur);
        up_time[up_ind] = run_time;
        up_score[up_ind] = pe->score;
      }
      up_totatt[up_ind]++;
      p_att[p]++;
      if (!global->is_virtual) {
        last_submit_run = i;
        last_submit_time = pe->time;
        last_submit_start = ustart;
      }
    } else if ((pe->status == RUN_COMPILE_ERR
                || pe->status == RUN_STYLE_ERR
                || pe->status == RUN_REJECTED)
               && !prob->ignore_compile_errors) {
      up_totatt[up_ind]++;
      p_att[p]++;
      if (!global->is_virtual) {
        last_submit_run = i;
        last_submit_time = pe->time;
        last_submit_start = ustart;
      }
    } else if (pe->status == RUN_COMPILE_ERR
               || pe->status == RUN_STYLE_ERR
               || pe->status == RUN_REJECTED) {
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
      const struct section_problem_data *prob = state->probs[p_ind[p]];
      u_score[u] += up_score[(u << row_sh) + p];
      if (!global->ignore_success_time) u_pen[u] += up_pen[(u << row_sh) + p];
      u_pen[u] += prob->acm_run_penalty * up_att[(u << row_sh) + p];
    }

  /* sort the users in descending order by score and ascending order by penalty */
  /* 1. bucket sort by penalty */
  max_pen = -1;
  XALLOCAZ(u_sort1, u_tot);
  for (u = 0; u < u_tot; u++)
    if (u_pen[u] > max_pen)
      max_pen = u_pen[u];
  if (max_pen >= 0) {
    XCALLOC(pen_cnt, max_pen + 1);
    XCALLOC(pen_st, max_pen + 1);
    //XALLOCAZ(pen_cnt, max_pen + 1);
    //XALLOCAZ(pen_st, max_pen + 1);
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
    goto free_resources;
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
    if (!only_table_flag)
      write_standings_header(state, cnts, f, client_flag, user_id, header_str,
                             user_name);
    /* print the table header */
    fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
            ss.table_attr, r0_attr,
            ss.place_attr, _("Place"),
            ss.team_attr, _("Participant"));
    if (global->stand_extra_format[0]) {
      if (global->stand_extra_legend[0])
        fprintf(f, "<th%s>%s</th>", ss.extra_attr,
                global->stand_extra_legend);
      else
        fprintf(f, "<th%s>%s</th>", ss.extra_attr,
                _("Extra info"));
    }
    if (global->stand_show_contestant_status && global->contestant_status_num > 0)
      fprintf(f, "<th%s>%s</th>", ss.contestant_status_attr,
              _("Status"));
    if (global->stand_show_warn_number)
      fprintf(f, "<th%s>%s</th>", ss.warn_number_attr,
              _("Warnings"));
    for (j = 0; j < p_tot; j++) {
      row_attr = state->probs[p_ind[j]]->stand_attr;
      if (!*row_attr) row_attr = ss.prob_attr;
      fprintf(f, "<th%s>", row_attr);
      if (global->prob_info_url[0]) {
        sformat_message(strbuf, sizeof(strbuf), 0, global->prob_info_url,
                        NULL, state->probs[p_ind[j]], NULL, NULL, NULL, 0, 0, 0);
        fprintf(f, "<a href=\"%s\">", strbuf);
      }
      if (state->probs[p_ind[j]]->stand_name[0]) {
        fprintf(f, "%s", state->probs[p_ind[j]]->stand_name);
      } else {
        fprintf(f, "%s", state->probs[p_ind[j]]->short_name);
      }
      if (global->prob_info_url[0])
        fprintf(f, "</a>");
      fprintf(f, "</th>");
    }
    fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>\n",
            ss.score_attr, _("Score"),
            ss.penalty_attr, _("Penalty"));
  }

  for (i = 0; i < u_tot; i++, user_on_page = (user_on_page + 1) % users_per_page) {
    if (!user_on_page) {
      current_page++;
      if (!f) {
        snprintf(stand_tmp, sizeof(stand_tmp), "%s/in/%s.tmp",
                 stand_dir, pgrefs[current_page - 1]);
        snprintf(stand_path, sizeof(stand_path), "%s/dir/%s", stand_dir,
                 pgrefs[current_page - 1]);
        if (charset_id > 0) {
          if (!(f = open_memstream(&encode_txt, &encode_len))) return;
        } else {
          if (!(f = sf_fopen(stand_tmp, "w"))) return;
        }
      }
      if (!client_flag && only_table_flag)
        write_standings_header(state, cnts, f, client_flag, user_id, header_str,
                               user_name);
      /* print "Last success" information */
      if (last_success_run >= 0) {
        if (global->is_virtual && !user_id) {
          duration_str(1, last_success_time, last_success_start,
                       strbuf, sizeof(strbuf));
        } else {
          duration_str(global->show_astr_time, last_success_time, last_success_start,
                       strbuf, sizeof(strbuf));
        }
        fprintf(f, "<p%s>%s: %s, ",
                ss.success_attr, _("Last success"), strbuf);
        if (global->team_info_url[0]) {
          teamdb_export_team(state->teamdb_state, runs[last_success_run].user_id,
                             &u_info);
          sformat_message(strbuf, sizeof(strbuf), 0, global->team_info_url,
                          NULL, NULL, NULL, NULL, &u_info, u_info.user, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        fprintf(f, "%s", ARMOR(stand_get_name(state, runs[last_success_run].user_id)));
        if (global->team_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ", ");

        if (global->prob_info_url[0]) {
          sformat_message(strbuf, sizeof(strbuf), 0, global->prob_info_url,
                          NULL, state->probs[runs[last_success_run].prob_id],
                          NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        j = runs[last_success_run].prob_id;
        if (state->probs[j]->stand_name[0]) {
          fprintf(f, "%s", state->probs[j]->stand_name);
        } else {
          fprintf(f, "%s", state->probs[j]->short_name);
        }
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ".</p>\n");
      }
      /* print "Last submit" information */
      if (last_submit_run >= 0) {
        if (global->is_virtual && !user_id) {
          duration_str(1, last_submit_time, last_submit_start,
                       strbuf, sizeof(strbuf));
        } else {
          duration_str(global->show_astr_time, last_submit_time, last_submit_start,
                       strbuf, sizeof(strbuf));
        }
        fprintf(f, "<p%s>%s: %s, ",
                ss.success_attr, _("Last submit"), strbuf);
        if (global->team_info_url[0]) {
          teamdb_export_team(state->teamdb_state, runs[last_submit_run].user_id, &u_info);
          sformat_message(strbuf, sizeof(strbuf), 0, global->team_info_url,
                          NULL, NULL, NULL, NULL, &u_info, u_info.user, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        fprintf(f, "%s", ARMOR(stand_get_name(state, runs[last_submit_run].user_id)));
        if (global->team_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ", ");

        if (global->prob_info_url[0]) {
          sformat_message(strbuf, sizeof(strbuf), 0, global->prob_info_url,
                          NULL, state->probs[runs[last_submit_run].prob_id],
                          NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        j = runs[last_submit_run].prob_id;
        if (state->probs[j]->stand_name[0]) {
          fprintf(f, "%s", state->probs[j]->stand_name);
        } else {
          fprintf(f, "%s", state->probs[j]->short_name);
        }
        if (global->prob_info_url[0]) {
          fprintf(f, "</a>");
        }
        fprintf(f, ".</p>\n");
      }
      /* print page number information and references */
      if (total_pages > 1) {
        fprintf(f, _("<p%s>Page %d of %d.</p>\n"),
                ss.page_cur_attr, current_page, total_pages);

        write_moscow_page_table(&ss, f, total_pages, current_page,
                                pgrefs, pg_n1, pg_n2, pg_sc1, pg_sc2,
                                pg_pen1, pg_pen2, pr_attrs, pc_attrs);
      }

      /* print the table header */
      fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
              ss.table_attr, r0_attr,
              ss.place_attr, _("Place"),
              ss.team_attr, _("User"));
      if (global->stand_extra_format[0]) {
        if (global->stand_extra_legend[0])
          fprintf(f, "<th%s>%s</th>", ss.extra_attr,
                  global->stand_extra_legend);
        else
          fprintf(f, "<th%s>%s</th>", ss.extra_attr,
                  _("Extra info"));
      }
      if (global->stand_show_contestant_status && global->contestant_status_num > 0)
        fprintf(f, "<th%s>%s</th>", ss.contestant_status_attr,
                _("Status"));
      if (global->stand_show_warn_number)
        fprintf(f, "<th%s>%s</th>", ss.warn_number_attr,
                _("Warnings"));
      for (j = 0; j < p_tot; j++) {
        row_attr = state->probs[p_ind[j]]->stand_attr;
        if (!*row_attr) row_attr = ss.prob_attr;
        fprintf(f, "<th%s>", row_attr);
        if (global->prob_info_url[0]) {
          sformat_message(strbuf, sizeof(strbuf), 0, global->prob_info_url,
                          NULL, state->probs[p_ind[j]], NULL, NULL, NULL, 0, 0, 0);
          fprintf(f, "<a href=\"%s\">", strbuf);
        }
        if (state->probs[p_ind[j]]->stand_name[0]) {
          fprintf(f, "%s", state->probs[p_ind[j]]->stand_name);
        } else {
          fprintf(f, "%s", state->probs[p_ind[j]]->short_name);
        }
        if (global->prob_info_url[0])
          fprintf(f, "</a>");
        fprintf(f, "</th>");
      }
      fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>\n",
              ss.score_attr, _("Score"),
              ss.penalty_attr, _("Penalty"));
    }

    // print the standings row
    u = u_sort[i];

    if (global->team_info_url[0] || global->stand_extra_format[0]) {
      teamdb_export_team(state->teamdb_state, u_ind[u], &u_info);
    } else {
      memset(&u_info, 0, sizeof(u_info));
    }
    u_extra = 0;
    if (extras) {
      u_extra = extras->get(extras, u_ind[u]);
    }
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
    fprintf(f, "<tr%s><td%s>", row_attr, ss.place_attr);
    if (u_n1[i] == u_n2[i]) fprintf(f, "%d", u_n1[i] + 1);
    else fprintf(f, "%d-%d", u_n1[i] + 1, u_n2[i] + 1);
    fprintf(f, "</td><td%s>", ss.team_attr);
    if (global->team_info_url[0]) {
      sformat_message(strbuf, sizeof(strbuf), 0, global->team_info_url,
                      NULL, NULL, NULL, NULL, &u_info, u_info.user, 0, 0);
      fprintf(f, "<a href=\"%s\">", strbuf);
    }
    fprintf(f, "%s", ARMOR(stand_get_name(state, u_ind[u])));
    if (global->team_info_url[0]) {
      fprintf(f, "</a>");
    }
    fprintf(f, "</td>");
    if (global->stand_extra_format[0]) {
      memset(&fed, 0, sizeof(fed));
      fed.variant = find_user_variant(state, u_info.id, 0);
      sformat_message(strbuf, sizeof(strbuf), 1, global->stand_extra_format,
                      NULL, NULL, NULL, NULL, &u_info, u_info.user, 0, &fed);
      fprintf(f, "<td%s>%s</td>", ss.extra_attr, strbuf);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      if (u_extra && u_extra->status >= 0
          && u_extra->status < global->contestant_status_num) {
        fprintf(f, "<td%s>%s</td>", ss.contestant_status_attr,
                global->contestant_status_legend[u_extra->status]);
      } else {
        fprintf(f, "<td%s>?</td>", ss.contestant_status_attr);
      }
    }
    if (global->stand_show_warn_number) {
      if (u_extra && u_extra->warn_u > 0) {
        fprintf(f, "<td%s>%d</td>", ss.warn_number_attr,
                u_extra->warn_u);
      } else {
        fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
      }
    }

    for (j = 0; j < p_tot; j++) {
      up_ind = (u << row_sh) + j;

      row_attr = ss.prob_attr;
      if (up_trans[up_ind] && ss.trans_attr && ss.trans_attr[0])
        row_attr = ss.trans_attr;
      if (up_cf[up_ind] && global->stand_fail_attr[0])
        row_attr = ss.fail_attr;
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
                  up_score[up_ind], ss.time_attr,
                  up_att[up_ind] + 1, strbuf);
        } else
          fprintf(f, "<b>%d</b> <div%s>(%d)</div>", up_score[up_ind],
                  ss.time_attr, up_att[up_ind] + 1);
      } else if (up_score[up_ind] > 0) {
        if (global->stand_show_ok_time && up_time[up_ind] > 0) {
          if (global->show_astr_time) {
            duration_str(1, up_time[up_ind], start_time, strbuf, 0);
          } else {
            snprintf(strbuf, sizeof(strbuf), "%d:%02d",
                     up_pen[up_ind] / 60, up_pen[up_ind] % 60);
          }
          fprintf(f, "%d <div%s>(%d,%s)</div> -%d",
                  up_score[up_ind], ss.time_attr, up_att[up_ind] + 1,
                  strbuf, up_totatt[up_ind]);
        } else
          fprintf(f, "%d <div%s>(%d)</div> -%d",
                  up_score[up_ind], ss.time_attr, up_att[up_ind] + 1,
                  up_totatt[up_ind]);
      } else
        fprintf(f, "0 -%d", up_totatt[up_ind]);

      fprintf(f, "</td>");
    }

    fprintf(f, "<td%s>%d</td><td%s>%d</td></tr>\n",
            ss.score_attr, u_score[u],
            ss.penalty_attr, u_pen[u]);

    if (user_on_page == users_per_page - 1 && current_page != total_pages) {
      fputs("</table>\n", f);
      if (!client_flag) {
        write_moscow_page_table(&ss, f, total_pages, current_page,
                                pgrefs, pg_n1, pg_n2, pg_sc1, pg_sc2,
                                pg_pen1, pg_pen2, pr_attrs, pc_attrs);
        if (footer_str) {
          process_template(f, footer_str, 0, 0, 0, get_copyright(0));
        } else {
          fputs("</body></html>", f);
        }
      }
      if (current_page > 1) {
        fclose(f);
        if (charset_id > 0) {
          encode_txt = charset_encode_heap(charset_id, encode_txt);
          encode_len = strlen(encode_txt);
          generic_write_file(encode_txt, encode_len, 0, NULL, stand_tmp, NULL);
          xfree(encode_txt); encode_txt = 0; encode_len = 0;
        }
        rename(stand_tmp, stand_path);
      }
      f = 0;
    }
  }

  fprintf(f, "<tr%s><td%s>&nbsp;</td><td%s>%s:</td>", rT_attr,
          ss.place_attr, ss.team_attr, _("Total"));
  if (global->stand_extra_format[0])
    fprintf(f, "<td%s>&nbsp;</td>", ss.extra_attr);
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0)
    fprintf(f, "<td%s>&nbsp;</td>", ss.contestant_status_attr);
  if (global->stand_show_warn_number)
    fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
  for (j = 0, all_att = 0; j < p_tot; j++) {
    fprintf(f, "<td%s>%d</td>", ss.prob_attr, p_att[j]);
    all_att += p_att[j];
  }
  fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          ss.solved_attr, all_att, ss.penalty_attr);

  fprintf(f, "<tr%s><td%s>&nbsp;</td><td%s>%s:</td>", rT_attr,
          ss.place_attr, ss.team_attr, _("Success"));
  if (global->stand_extra_format[0])
    fprintf(f, "<td%s>&nbsp;</td>", ss.extra_attr);
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0)
    fprintf(f, "<td%s>&nbsp;</td>", ss.contestant_status_attr);
  if (global->stand_show_warn_number)
    fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
  for (j = 0, all_succ = 0; j < p_tot; j++) {
    fprintf(f, "<td%s>%d</td>", ss.prob_attr, p_succ[j]);
    all_succ += p_succ[j];
  }
  fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
          ss.solved_attr, all_succ, ss.penalty_attr);

  fprintf(f, "<tr%s><td%s>&nbsp;</td><td%s>%%:</td>", rT_attr,
          ss.place_attr, ss.team_attr);
  if (global->stand_extra_format[0])
    fprintf(f, "<td%s>&nbsp;</td>", ss.extra_attr);
  if (global->stand_show_contestant_status
      && global->contestant_status_num > 0)
    fprintf(f, "<td%s>&nbsp;</td>", ss.contestant_status_attr);
  if (global->stand_show_warn_number)
    fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
  for (j = 0; j < p_tot; j++) {
    if (!p_att[j])
      fprintf(f, "<td%s>&nbsp;</td>", ss.prob_attr);
    else
      fprintf(f, "<td%s>%d%%</td>", ss.prob_attr,
              (int)(p_succ[j] * 100.0 / p_att[j] + 0.5));
  }
  if (!all_att)
    fprintf(f, "<td%s>&nbsp;</td><td%s>&nbsp;</td></tr>\n",
            ss.solved_attr, ss.penalty_attr);
  else
    fprintf(f, "<td%s>%d%%</td><td%s>&nbsp;</td></tr>\n",
            ss.solved_attr,
            (int)(all_succ * 100.0 / all_att + 0.5),
            ss.penalty_attr);
  
  fputs("</table>\n", f);
  if (!client_flag) {
    if (total_pages > 1) {
      write_moscow_page_table(&ss, f, total_pages, current_page,
                              pgrefs, pg_n1, pg_n2, pg_sc1, pg_sc2,
                              pg_pen1, pg_pen2, pr_attrs, pc_attrs);
    }
    if (footer_str) {
      process_template(f, footer_str, 0, 0, 0, get_copyright(0));
    } else {
      fputs("</body></html>", f);
    }
  }
  if (total_pages > 1) {
    fclose(f); f = 0;
    if (charset_id > 0) {
      encode_txt = charset_encode_heap(charset_id, encode_txt);
      encode_len = strlen(encode_txt);
      generic_write_file(encode_txt, encode_len, 0, NULL, stand_tmp, NULL);
      xfree(encode_txt); encode_txt = 0; encode_len = 0;
    }
    rename(stand_tmp, stand_path);
  }

 free_resources:
  // xfree(u_runs):  currently on stack
  // xfree(u_ind):   currently on stack
  // xfree(u_rev):   currently on stack
  // xfree(u_sort):  currently on stack
  // xfree(p_ind):   currently on stack
  // xfree(p_rev):   currently on stack
  // xfree(u_score): currently on stack
  // xfree(u_pen):   currently on stack
  // xfree(p_att):   currently on stack
  // xfree(p_succ):  currently on stack
  // xfree(u_sort1): currently on stack
  // xfree(sc_cnt):  currently on stack
  // xfree(sc_st):   currently on stack
  // xfree(u_n1):    currently on stack
  // xfree(u_n2):    currently on stack
  // xfree(pgrefs):  currently on stack
  // xfree(pg_n1):   currently on stack
  // xfree(pg_n2):   currently on stack
  // xfree(pg_sc1):  currently on stack
  // xfree(pg_sc2):  currently on stack
  // xfree(pg_pen1): currently on stack
  // xfree(pg_pen2): currently on stack

  xfree(pen_cnt);
  xfree(pen_st);
  xfree(up_cf);
  xfree(up_trans);
  xfree(up_solved);
  xfree(up_score);
  xfree(up_att);
  xfree(up_totatt);
  xfree(up_time);
  xfree(up_pen);
  html_armor_free(&ab);
  env.mem = filter_tree_delete(env.mem);
  if (extras) extras->free(extras);
}

/*
 * ACM-style standings
 */
void
do_write_standings(
        const serve_state_t state,
        const struct contest_desc *cnts,
        FILE *f,
        int client_flag,
        int only_table_flag,
        int user_id,
        const unsigned char *header_str,
        unsigned char const *footer_str,
        int raw_flag,
        const unsigned char *user_name,
        int force_fancy_style,
        time_t cur_time,
        struct user_filter_info *user_filter)
{
  struct section_global_data *global = state->global;
  int      i, j, t;

  int     *t_ind = 0;
  int      t_max;
  int      t_tot;
  int     *t_prob = 0;
  int     *t_pen = 0;
  int     *t_rev = 0;
  int     *t_sort = 0;
  int     *t_sort2 = 0;
  int     *prob_cnt = 0;
  int     *pen_cnt = 0;
  int      max_pen, max_solved;
  int     *t_n1 = 0;
  int     *t_n2 = 0;
  int     *p_ind = 0;
  int     *p_rev = 0;
  int      p_max;
  int      p_tot;
  int      r_tot, k;
  int      tt, pp;
  int      ttot_att, ttot_succ, perc;

  time_t *ok_time = 0;
  int    *calc = 0;

  time_t start_time;
  time_t stop_time;
  time_t        contest_dur;
  time_t        current_dur, run_time;
  time_t        tdur = 0, tstart = 0;

  char          url_str[1024];
  const unsigned char *bgcolor_ptr;
  unsigned char *head_style;
  struct teamdb_export ttt;      
  const struct run_entry *runs, *pe;
  unsigned char *t_runs = 0;
  int last_success_run = -1;
  time_t last_success_time = 0;
  time_t last_success_start = 0;
  int *tot_att = 0, *succ_att = 0;
  const struct team_extra *t_extra;
  unsigned char *r0_attr = "", *rT_attr = "";
  unsigned char *r_attrs[2][2] = {{"", ""}, {"", ""}};
  int row_sh, row_sz, up_ind, attr_num;
  int prev_prob = -1, row_ind = 0, group_ind = 1;
  const unsigned char *col_attr = 0;
  struct standings_style ss;
  const struct section_problem_data *prob = 0;
  struct sformat_extra_data fed;
  unsigned char *trans_flag = 0;
  unsigned char *pr_flag = 0;
  unsigned char *disq_flag = 0;
  unsigned char *cf_flag = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct filter_env env;
  struct xuser_team_extras *extras = NULL;

  memset(&env, 0, sizeof(env));

  if (cur_time <= 0) cur_time = time(0);
  if (!only_table_flag) {
    write_standings_header(state, cnts, f, client_flag, user_id, header_str,
                           user_name);
  }

  if (client_flag) head_style = cnts->team_head_style;
  else head_style = "h2";

  setup_standings_style(&ss, global, force_fancy_style);

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

  start_time = run_get_start_time(state->runlog_state);
  stop_time = run_get_stop_time(state->runlog_state);
  contest_dur = run_get_duration(state->runlog_state);
  if (start_time && global->is_virtual && user_id > 0) {
    start_time = run_get_virtual_start_time(state->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(state->runlog_state, user_id, 0);
  }
  if (start_time > 0 && cur_time < start_time) {
    cur_time = start_time;
  }
  if (start_time > 0 && contest_dur > 0) {
    if (stop_time <= 0 && cur_time >= start_time + contest_dur) {
      stop_time = start_time + contest_dur;
    }
    if (stop_time > 0 && cur_time > stop_time) {
      cur_time = stop_time;
    }
  }
  current_dur = cur_time - start_time;
  if (!start_time) {
    if (raw_flag) return;

    if (!only_table_flag) {
      fprintf(f, "<%s>%s</%s>", head_style, _("The contest is not started"),
              head_style);
      if (!client_flag) {
        if (footer_str) {
          process_template(f, footer_str, 0, 0, 0, get_copyright(0));
        } else {
          fprintf(f, "</body></html>");
        }
      }
    }
    return;
  }

  r_tot = run_get_total(state->runlog_state);
  runs = run_get_entries_ptr(state->runlog_state);

  if (global->disable_user_database > 0) {
    t_max = run_get_max_user_id(state->runlog_state) + 1;
  } else {
    t_max = teamdb_get_max_team_id(state->teamdb_state) + 1;
  }
  t_runs = alloca(t_max);
  if (global->prune_empty_users || global->disable_user_database > 0) {
    memset(t_runs, 0, t_max);
    for (k = 0; k < r_tot; k++) {
      if (runs[k].status == RUN_EMPTY) continue;
      if (runs[k].user_id <= 0 || runs[k].user_id >= t_max) continue;
      if (runs[k].is_hidden) continue;
      t_runs[runs[k].user_id] = 1;
    }
  } else {
    memset(t_runs, 1, t_max);
  }

  /* make team index */
  XALLOCAZ(t_ind, t_max);
  XALLOCAZ(t_rev, t_max);
  teamdb_get_user_map(state, cur_time, t_max, t_runs, &t_tot, t_rev, t_ind,
                      user_filter);
  /*
  for (i = 1, t_tot = 0; i < t_max; i++) {
    t_rev[i] = -1;
    if (!teamdb_lookup(state->teamdb_state, i)) continue;
    if ((teamdb_get_flags(state->teamdb_state,
                          i) & (TEAM_INVISIBLE | TEAM_BANNED | TEAM_DISQUALIFIED))) continue;
    if (!t_runs[i]) continue;
    t_rev[i] = t_tot;
    t_ind[t_tot++] = i;
  }
  */
  XALLOCAZ(t_prob, t_tot);
  XALLOCAZ(t_pen,t_tot);
  XALLOCA(t_n1, t_tot);
  XALLOCA(t_n2, t_tot);

  if (global->stand_show_contestant_status
      || global->stand_show_warn_number
      || global->contestant_status_row_attr) {
    if (state->xuser_state) {
      extras = state->xuser_state->vt->get_entries(state->xuser_state, t_tot, t_ind);
    }
  }

  /* make problem index */
  p_max = state->max_prob + 1;
  XALLOCAZ(p_ind, p_max);
  XALLOCAZ(p_rev, p_max);
  get_problem_map(state, cur_time, p_rev, p_max, p_ind, &p_tot, NULL,
                  user_filter);
  for (i = 1; i < p_max; i++) {
    if (!(prob = state->probs[i])) continue;
    if (!prob->stand_column[0]) continue;
    if (prob->start_date > 0 && cur_time < prob->start_date) continue;
    for (j = 1; j < p_max; j++) {
      if (!state->probs[j]) continue;
      if (!strcmp(prob->stand_column, state->probs[j]->short_name)
          || !strcmp(prob->stand_column, state->probs[j]->stand_name))
        p_rev[i] = p_rev[j];
    }
  }

  /* calculate the power of 2 not less than p_tot */
  for (row_sz = 1, row_sh = 0; row_sz < p_tot; row_sz <<= 1, row_sh++);
  /* all two-dimensional arrays will have rows of size row_sz */

  if (t_tot > 0) {
    XCALLOC(calc, t_tot * row_sz);
    XCALLOC(ok_time, t_tot * row_sz);
    XCALLOC(trans_flag, t_tot * row_sz);
    XCALLOC(pr_flag, t_tot * row_sz);
    XCALLOC(disq_flag, t_tot * row_sz);
    XCALLOC(cf_flag, t_tot * row_sz);
  }

  XALLOCAZ(succ_att, p_tot);
  XALLOCAZ(tot_att, p_tot);

  if (user_filter && user_filter->stand_run_tree) {
    env.teamdb_state = state->teamdb_state;
    env.serve_state = state;
    env.mem = filter_tree_new();
    env.maxlang = state->max_lang;
    env.langs = (const struct section_language_data * const *) state->langs;
    env.maxprob = state->max_prob;
    env.probs = (const struct section_problem_data * const *) state->probs;
    env.rtotal = r_tot;
    env.cur_time = cur_time;
    env.rentries = runs;
    env.rid = 0;
  }

  /* now scan runs log */
  for (k = 0; k < r_tot; k++) {
    pe = &runs[k];
    run_time = pe->time;
    if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP
        || pe->status == RUN_EMPTY) continue;
    if (pe->user_id <= 0 || pe->user_id >= t_max || t_rev[pe->user_id] < 0) continue;
    if (pe->prob_id <= 0 || pe->prob_id > state->max_prob || p_rev[pe->prob_id] < 0)
      continue;
    if (!state->probs[pe->prob_id] || state->probs[pe->prob_id]->hidden) continue;
    if (pe->is_hidden) continue;
    if (user_filter && user_filter->stand_run_tree) {
      env.rid = k;
      if (filter_tree_bool_eval(&env, user_filter->stand_run_tree) <= 0)
        continue;
    }
    prob = state->probs[pe->prob_id];

    if (global->is_virtual) {
      // filter "future" virtual runs
      tstart = run_get_virtual_start_time(state->runlog_state, pe->user_id);
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
        if (global->stand_ignore_after > 0
            && pe->time >= global->stand_ignore_after)
          continue;
      }
    }
    tt = t_rev[pe->user_id];
    pp = p_rev[pe->prob_id];
    up_ind = (tt << row_sh) + pp;

    if (pe->status == RUN_OK) {
      /* program accepted */
      if (calc[up_ind] > 0) continue;

      last_success_run = k;
      t_pen[tt] += state->probs[pe->prob_id]->acm_run_penalty * - calc[up_ind];
      calc[up_ind] = 1 - calc[up_ind];
      t_prob[tt]++;
      succ_att[pp]++;
      tot_att[pp]++;
      if (global->is_virtual) {
        ok_time[up_ind] = sec_to_min(global->rounding_mode, tdur);
        if (!global->ignore_success_time) t_pen[tt] += ok_time[up_ind];
        last_success_time = run_time;
        last_success_start = tstart;
      } else {
        if (run_time < start_time) run_time = start_time;
        ok_time[up_ind] = sec_to_min(global->rounding_mode, run_time - start_time);
        if (!global->ignore_success_time) t_pen[tt] += ok_time[up_ind];
        last_success_time = run_time;
        last_success_start = start_time;
      }
    } else if ((pe->status == RUN_COMPILE_ERR
                || pe->status == RUN_STYLE_ERR
                || pe->status == RUN_REJECTED)
               && !prob->ignore_compile_errors) {
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
    } else if (pe->status == RUN_DISQUALIFIED) {
      disq_flag[up_ind] = 1;
    } else if (pe->status == RUN_PENDING_REVIEW) {
      pr_flag[up_ind] = 1;
    } else if (pe->status == RUN_PENDING || pe->status == RUN_ACCEPTED) {
      trans_flag[up_ind] = 1;
    } else if (pe->status >= RUN_TRANSIENT_FIRST
               && pe->status <= RUN_TRANSIENT_LAST) {
      trans_flag[up_ind] = 1;
    } else if (pe->status == RUN_CHECK_FAILED) {
      cf_flag[up_ind] = 1;
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
    //XALLOCAZ(pen_cnt, max_pen + 1);
    XCALLOC(pen_cnt, max_pen + 1);
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

      if (global->is_virtual && !user_id) {
        duration_str(1, last_success_time, last_success_start,
                     dur_buf, sizeof(dur_buf));
      } else {
        duration_str(0, last_success_time, last_success_start,
                     dur_buf, sizeof(dur_buf));
      }
      fprintf(f, "<p%s>%s: %s, ",
              ss.success_attr, _("Last success"), dur_buf);
      if (global->team_info_url[0]) {
        teamdb_export_team(state->teamdb_state, runs[last_success_run].user_id, &ttt);
        sformat_message(dur_buf, sizeof(dur_buf), 0, global->team_info_url,
                        NULL, NULL, NULL, NULL, &ttt, ttt.user, 0, 0);
        fprintf(f, "<a href=\"%s\">", dur_buf);      
      }
      fprintf(f, "%s", ARMOR(stand_get_name(state, runs[last_success_run].user_id)));
      if (global->team_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, ", ");
      if (global->prob_info_url[0]) {
        sformat_message(dur_buf, sizeof(dur_buf), 0, global->prob_info_url,
                        NULL, state->probs[runs[last_success_run].prob_id],
                        NULL, NULL, NULL, 0, 0, 0);
        fprintf(f, "<a href=\"%s\">", dur_buf);
      }
      j = runs[last_success_run].prob_id;
      if (state->probs[j]->stand_name[0]) {
        fprintf(f, "%s", state->probs[j]->stand_name);
      } else {
        fprintf(f, "%s", state->probs[j]->short_name);
      }
      if (global->prob_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, ".</p>\n");
    }
    /* print table header */
    fprintf(f, "<table%s><tr%s><th%s>%s</th><th%s>%s</th>",
            ss.table_attr, r0_attr,
            ss.place_attr, _("Place"),
            ss.team_attr, _("User"));
    if (global->stand_extra_format[0]) {
      if (global->stand_extra_legend[0])
        fprintf(f, "<th%s>%s</th>", ss.extra_attr,
                global->stand_extra_legend);
      else
        fprintf(f, "<th%s>%s</th>", ss.extra_attr,
                _("Extra info"));
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<th%s>%s</th>", ss.contestant_status_attr,
              _("Status"));
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<th%s>%s</th>", ss.warn_number_attr,
              _("Warnings"));
    }
    for (j = 0; j < p_tot; j++) {
      col_attr = state->probs[p_ind[j]]->stand_attr;
      if (!*col_attr) col_attr = ss.prob_attr;
      fprintf(f, "<th%s>", col_attr);
      if (global->prob_info_url[0]) {
        sformat_message(url_str, sizeof(url_str), 0, global->prob_info_url,
                        NULL, state->probs[p_ind[j]], NULL, NULL, NULL, 0, 0,
                        0);
        fprintf(f, "<a href=\"%s\">", url_str);
      }
      if (state->probs[p_ind[j]]->stand_name[0]) {
        fprintf(f, "%s", state->probs[p_ind[j]]->stand_name);
      } else {
        fprintf(f, "%s", state->probs[p_ind[j]]->short_name);
      }
      if (global->prob_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</th>");
    }
    fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>\n",
            ss.solved_attr, _("Total"),
            ss.penalty_attr, _("Penalty"));

    for (i = 0; i < t_tot; i++) {
      t = t_sort[i];

      t_extra = 0;
      if (extras) {
        t_extra = extras->get(extras, t_ind[t]);
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
        bgcolor_ptr = ss.self_row_attr;
      } else if (global->is_virtual) {
        int vstat = run_get_virtual_status(state->runlog_state, t_ind[t]);
        if (vstat == 1 && ss.r_row_attr[0]) {
          bgcolor_ptr = ss.r_row_attr;
        } else if (vstat == 2 && ss.v_row_attr[0]) {
          bgcolor_ptr = ss.v_row_attr;
        } else if (!vstat && ss.u_row_attr[0]) {
          bgcolor_ptr = ss.u_row_attr;
        }
      }
      if ((!bgcolor_ptr || !*bgcolor_ptr)
          && global->contestant_status_row_attr
          && t_extra && t_extra->status >= 0
          && t_extra->status < global->contestant_status_num) {
        bgcolor_ptr = global->contestant_status_row_attr[t_extra->status];
      }
      fprintf(f, "<tr%s><td%s>", bgcolor_ptr, ss.place_attr);
      if (t_n1[i] == t_n2[i]) fprintf(f, "%d", t_n1[i] + 1);
      else fprintf(f, "%d-%d", t_n1[i] + 1, t_n2[i] + 1);
      fputs("</td>", f);
      fprintf(f, "<td%s>", ss.team_attr);
      if (global->team_info_url[0] || global->stand_extra_format[0]) {
        teamdb_export_team(state->teamdb_state, t_ind[t], &ttt);
      } else {
        memset(&ttt, 0, sizeof(ttt));
      }
      if (global->team_info_url[0]) {
        sformat_message(url_str, sizeof(url_str), 0, global->team_info_url,
                        NULL, NULL, NULL, NULL, &ttt, ttt.user, 0, 0);
        fprintf(f, "<a href=\"%s\">", url_str);      
      }
      fprintf(f, "%s", ARMOR(stand_get_name(state, t_ind[t])));
      if (global->team_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</td>");
      if (global->stand_extra_format[0]) {
        memset(&fed, 0, sizeof(fed));
        fed.variant = find_user_variant(state, ttt.id, 0);
        sformat_message(url_str, sizeof(url_str), 1,global->stand_extra_format,
                        NULL, NULL, NULL, NULL, &ttt, ttt.user, 0, 0);
        fprintf(f, "<td%s>%s</td>", ss.extra_attr, url_str);
      }
      if (global->stand_show_contestant_status
          && global->contestant_status_num > 0) {
        if (t_extra && t_extra->status >= 0
            && t_extra->status < global->contestant_status_num) {
          fprintf(f, "<td%s>%s</td>", ss.contestant_status_attr,
                  global->contestant_status_legend[t_extra->status]);
        } else {
          fprintf(f, "<td%s>?</td>", ss.contestant_status_attr);
        }
      }
      if (global->stand_show_warn_number) {
        if (t_extra && t_extra->warn_u > 0) {
          fprintf(f, "<td%s>%d</td>", ss.warn_number_attr,
                  t_extra->warn_u);
        } else {
          fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
        }
      }
      for (j = 0; j < p_tot; j++) {
        up_ind = (t << row_sh) + j;
        col_attr = state->probs[p_ind[j]]->stand_attr;
        if (!*col_attr) col_attr = ss.prob_attr;
        if (pr_flag[up_ind] && ss.pr_attr && ss.pr_attr[0])
          col_attr = ss.pr_attr;
        if (trans_flag[up_ind] && ss.trans_attr && ss.trans_attr[0])
          col_attr = ss.trans_attr;
        if (disq_flag[up_ind] && ss.disq_attr && ss.disq_attr[0])
          col_attr = ss.disq_attr;
        if (cf_flag[up_ind] && ss.fail_attr && ss.fail_attr[0])
          col_attr = ss.fail_attr;
        fprintf(f, "<td%s>", col_attr);
        if (calc[up_ind] < 0) {
          fprintf(f, "%d", calc[up_ind]);
        } else if (calc[up_ind] == 1) {
          if (global->ignore_success_time || !global->stand_show_ok_time) {
            fprintf(f, "+");
          } else {
            fprintf(f, "+ <div%s>(%ld:%02ld)</div>",
                    ss.time_attr,
                    ok_time[up_ind] / 60, ok_time[up_ind] % 60);
          }
        } else if (calc[up_ind] > 0) {
          if (global->ignore_success_time || !global->stand_show_ok_time) {
            fprintf(f, "+%d", calc[up_ind] - 1);
          } else {
            fprintf(f, "+%d <div%s>(%ld:%02ld)</div>", calc[up_ind] - 1,
                    ss.time_attr,
                    ok_time[up_ind] / 60, ok_time[up_ind] % 60);
          }
        } else {
          fprintf(f, "&nbsp;");
        }
        fputs("</td>", f);
      }
      fprintf(f, "<td%s>%d</td><td%s>%d</td></tr>\n",
              ss.solved_attr, t_prob[t],
              ss.penalty_attr, t_pen[t]);
    }

    // print row of total
    fprintf(f, "<tr%s>", rT_attr);
    fprintf(f, "<td%s>&nbsp;</td>", ss.place_attr);
    fprintf(f, "<td%s>Total:</td>", ss.team_attr);
    if (global->stand_extra_format[0]) {
      fprintf(f, "<td%s>&nbsp;</td>", ss.extra_attr);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<td%s>&nbsp;</td>", ss.contestant_status_attr);
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
    }
    for (j = 0, ttot_att = 0; j < p_tot; j++) {
      fprintf(f, "<td%s>%d</td>", ss.prob_attr, tot_att[j]);
      ttot_att += tot_att[j];
    }
    fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
            ss.solved_attr, ttot_att, ss.penalty_attr);
    // print row of success
    fprintf(f, "<tr%s>", rT_attr);
    fprintf(f, "<td%s>&nbsp;</td>", ss.place_attr);
    fprintf(f, "<td%s>Success:</td>", ss.team_attr);
    if (global->stand_extra_format[0]) {
      fprintf(f, "<td%s>&nbsp;</td>", ss.extra_attr);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<td%s>&nbsp;</td>", ss.contestant_status_attr);
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
    }
    for (j = 0, ttot_succ = 0; j < p_tot; j++) {
      fprintf(f, "<td%s>%d</td>", ss.prob_attr, succ_att[j]);
      ttot_succ += succ_att[j];
    }
    fprintf(f, "<td%s>%d</td><td%s>&nbsp;</td></tr>\n",
            ss.solved_attr, ttot_succ, ss.penalty_attr);
    // print row of percentage
    fprintf(f, "<tr%s>", rT_attr);
    fprintf(f, "<td%s>&nbsp;</td>", ss.place_attr);
    fprintf(f, "<td%s>%%:</td>", ss.team_attr);
    if (global->stand_extra_format[0]) {
      fprintf(f, "<td%s>&nbsp;</td>", ss.extra_attr);
    }
    if (global->stand_show_contestant_status
        && global->contestant_status_num > 0) {
      fprintf(f, "<td%s>&nbsp;</td>", ss.contestant_status_attr);
    }
    if (global->stand_show_warn_number) {
      fprintf(f, "<td%s>&nbsp;</td>", ss.warn_number_attr);
    }
    for (j = 0; j < p_tot; j++) {
      perc = 0;
      if (tot_att[j] > 0) {
        perc = (int) ((double) succ_att[j] / tot_att[j] * 100.0 + 0.5);
      }
      fprintf(f, "<td%s>%d%%</td>", ss.prob_attr, perc);
    }
    perc = 0;
    if (ttot_att > 0) {
      perc = (int) ((double) ttot_succ / ttot_att * 100.0 + 0.5);
    }
    fprintf(f, "<td%s>%d%%</td><td%s>&nbsp;</td></tr>\n",
            ss.solved_attr, perc, ss.penalty_attr);
    
    fputs("</table>\n", f);
    if (!client_flag && !only_table_flag) {
      if (footer_str) {
        process_template(f, footer_str, 0, 0, 0, get_copyright(0));
      } else {
        fputs("</body></html>", f);
      } 
    }
  }

  // xfree(t_runs):   currently on stack
  // xfree(t_ind):    currently on stack
  // xfree(t_rev):    currently on stack
  // xfree(t_prob):   currently on stack
  // xfree(t_pen):    currently on stack
  // xfree(t_n1):     currently on stack
  // xfree(t_n2):     currently on stack
  // xfree(p_ind):    currently on stack
  // xfree(p_rev):    currently on stack
  // xfree(succ_att): currently on stack
  // xfree(tot_att):  currently on stack
  // xfree(prob_cnt): currently on stack
  // xfree(t_sort):   currently on stack
  // xfree(t_sort2):  currently on stack

  xfree(pen_cnt);
  xfree(calc);
  xfree(ok_time);
  xfree(trans_flag);
  xfree(pr_flag);
  xfree(disq_flag);
  xfree(cf_flag);
  html_armor_free(&ab);
  env.mem = filter_tree_delete(env.mem);
  if (extras) extras->free(extras);
}

void
write_standings(
        const serve_state_t state,
        const struct contest_desc *cnts,
        char const *stat_dir,
        char const *name,
        int users_on_page,
        char const *header_str,
        char const *footer_str,
        int accepting_mode,
        int force_fancy_style,
        int charset_id,
        int user_mode)
{
  const struct section_global_data *global = state->global;
  char    tbuf[64];
  path_t  tpath;
  FILE   *f;
  char *encode_txt = 0;
  size_t encode_len = 0;

  sprintf(tbuf, "XXX_%lu%d", time(0), getpid());
  pathmake(tpath, stat_dir, "/", tbuf, 0);
  if (charset_id > 0) {
    if (!(f = open_memstream(&encode_txt, &encode_len)))
      return;
  } else {
    if (!(f = sf_fopen(tpath, "w")))
      return;
  }
  if (global->score_system == SCORE_KIROV
      || global->score_system == SCORE_OLYMPIAD)
    do_write_kirov_standings(state, cnts, f, stat_dir, 0, 0, 0, header_str,
                             footer_str, 0, accepting_mode, force_fancy_style,
                             0, charset_id, NULL, user_mode);
  else if (global->score_system == SCORE_MOSCOW)
    do_write_moscow_standings(state, cnts, f, stat_dir, 0, 0, 0, header_str,
                              footer_str, 0, 0, force_fancy_style, 0,
                              charset_id, NULL);
  else
    do_write_standings(state, cnts, f, 0, 0, 0, header_str, footer_str, 0, 0,
                       force_fancy_style, 0, NULL);
  if (charset_id > 0) {
    fclose(f); f = 0; encode_len = 0;
    encode_txt = charset_encode_heap(charset_id, encode_txt);
    encode_len = strlen(encode_txt);
    generic_write_file(encode_txt, encode_len, 0, stat_dir, tbuf, NULL);
    xfree(encode_txt); encode_txt = 0; encode_len = 0;
  } else {
    fclose(f);
  }
  generic_copy_file(REMOVE, stat_dir, tbuf, "", SAFE, stat_dir, name, "");
  return;
}

static void
do_write_public_log(
        const serve_state_t state,
        const struct contest_desc *cnts,
        FILE *f,
        char const *header_str,
        char const *footer_str,
        int user_mode)
{
  const struct section_global_data *global = state->global;
  int total;
  int i;

  time_t run_time, start_time, cur_time, stop_time;
  int attempts, disq_attempts, prev_successes;

  char durstr[64], statstr[128];
  char *str1 = 0, *str2 = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char header[1024];

  const struct run_entry *runs, *pe;
  const struct section_problem_data *cur_prob;
  int separate_user_score = 0;

  start_time = run_get_start_time(state->runlog_state);
  stop_time = run_get_stop_time(state->runlog_state);
  total = run_get_total(state->runlog_state);
  runs = run_get_entries_ptr(state->runlog_state);
  separate_user_score = global->separate_user_score > 0 && state->online_view_judge_score <= 0;

  switch (global->score_system) {
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

  if (!start_time) {
    if (global->name[0]) {
      sprintf(header, "%s &quot;%s&quot; - %s",
              _("Contest"), ARMOR(global->name), _("submission log"));
    } else {
      sprintf(header, "%s", _("Submission log"));
    }

    if (header_str) {
      process_template(f, header_str, 0, global->charset, header, 0);
    } else {
      fprintf(f, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"/><title>%s</title></head><body><h1>%s</h1>\n",
              global->charset,
              header, header);
    }
  } else {
    cur_time = time(0);
    if (start_time > cur_time) cur_time = start_time;
    if (stop_time && cur_time > stop_time) cur_time = stop_time;
    duration_str(global->show_astr_time, cur_time, start_time, durstr, 0);

    if (global->name[0]) {
      sprintf(header, "%s &quot;%s&quot; - %s [%s]",
              _("Contest"), ARMOR(global->name), _("submission log"), durstr);
    } else {
      sprintf(header, "%s [%s]", _("Submission log"), durstr);
    }

    if (header_str) {
      process_template(f, header_str, 0, global->charset, header, 0);
    } else {
      fprintf(f, "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"/><title>%s</title></head><body><h1>%s</h1>",
              global->charset,
              header, header);
    }
  }


  /* header */
  fprintf(f, "<p%s>%s: %d</p>\n", cnts->team_par_style,
          _("Total submissions"), total);
  fprintf(f, "<table border=\"1\"><tr><th>%s</th><th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th><th>%s</th>"
          "<th>%s</th><th>%s</th>", 
          _("Run ID"), _("Time"),
          _("User name"), _("Problem"),
          _("Language"), _("Result"), str1);
  if (str2) {
    fprintf(f, "<th>%s</th>", str2);
  }
  fprintf(f, "</tr>\n");

  for (i = total - 1; i >= 0; i--) {
    int status;

    pe = &runs[i];
    if (pe->is_hidden) continue;

    if (separate_user_score > 0 && user_mode && pe->is_saved) {
      status = pe->saved_status;
    } else {
      status = pe->status;
    }

    cur_prob = 0;
    if (pe->prob_id > 0 && pe->prob_id <= state->max_prob)
      cur_prob = state->probs[pe->prob_id];

    attempts = 0;
    disq_attempts = 0;
    prev_successes = RUN_TOO_MANY;

    run_time = pe->time;
    if (global->score_system == SCORE_KIROV) {
      run_get_attempts(state->runlog_state, i, &attempts, &disq_attempts,
                       cur_prob->ignore_compile_errors);
      if (status == RUN_OK && cur_prob && cur_prob->score_bonus_total > 0){
        prev_successes = run_get_prev_successes(state->runlog_state, i);
        if (prev_successes < 0) prev_successes = RUN_TOO_MANY;
      }
    }

    if (!start_time) run_time = start_time;
    if (start_time > run_time) run_time = start_time;
    duration_str(global->show_astr_time, run_time, start_time, durstr, 0);
    run_status_str(status, statstr, sizeof(statstr), 0, 0);

    fputs("<tr>", f);
    fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", durstr);
    fprintf(f, "<td>%s</td>",
            ARMOR(teamdb_get_name_2(state->teamdb_state, pe->user_id)));
    if (cur_prob) {
      if (cur_prob->variant_num > 0) {
        int variant = pe->variant;
        if (!variant) variant = find_variant(state, pe->user_id, pe->prob_id, 0);
        if (variant > 0) {
          fprintf(f, "<td>%s-%d</td>", cur_prob->short_name, variant);
        } else {
          fprintf(f, "<td>%s-?</td>", cur_prob->short_name);
        }
      } else {
        fprintf(f, "<td>%s</td>", cur_prob->short_name);
      }
    }
    else fprintf(f, "<td>??? - %d</td>", pe->prob_id);
    if (state->langs[pe->lang_id])
      fprintf(f, "<td>%s</td>", state->langs[pe->lang_id]->short_name);
    else fprintf(f, "<td>??? - %d</td>", pe->lang_id);

    write_html_run_status(state, f, start_time, pe, user_mode,
                          0, attempts, disq_attempts,
                          prev_successes, 0, 1, 0, RUN_VIEW_DEFAULT);

    fputs("</tr>\n", f);
  }

  fputs("</table>\n", f);
  if (footer_str) {
    fprintf(f, "%s", footer_str);
  }

  html_armor_free(&ab);
}

void
write_public_log(
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
  do_write_public_log(state, cnts, f, header_str, footer_str, user_mode);
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
