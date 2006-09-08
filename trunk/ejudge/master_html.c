/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2002-2006 Alexander Chernov <cher@ejudge.ru> */

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

#include "filter_tree.h"
#include "filter_eval.h"
#include "prepare.h"
#include "protocol.h"
#include "misctext.h"
#include "mischtml.h"
#include "teamdb.h"
#include "clarlog.h"
#include "runlog.h"
#include "base64.h"
#include "html.h"
#include "fileutl.h"
#include "client_actions.h"
#include "sformat.h"
#include "archive_paths.h"
#include "team_extra.h"
#include "xml_utils.h"
#include "userlist.h"
#include "testing_report_xml.h"
#include "full_archive.h"
#include "filehash.h"
#include "digest_io.h"
#include "errlog.h"
#include "serve_state.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

struct user_filter_info
{
  struct user_filter_info *next;

  ej_cookie_t session_id;
  int prev_first_run;
  int prev_last_run;
  int prev_first_clar;
  int prev_last_clar;
  int prev_mode_clar;           /* 1 - view all, 2 - view unanswered */
  unsigned char *prev_filter_expr;
  struct filter_tree *prev_tree;
  struct filter_tree_mem *tree_mem;
  unsigned char *error_msgs;
};

struct user_state_info
{
  struct user_filter_info *first_filter;
};

static int users_a;
static struct user_state_info **users;
static struct user_filter_info *cur_user;

static void
print_nav_buttons(FILE *f, int run_id,
                  ej_cookie_t sid,
                  unsigned char const *self_url,
                  unsigned char const *hidden_vars,
                  unsigned char const *extra_args,
                  unsigned char const *t1,
                  unsigned char const *t2,
                  unsigned char const *t3,
                  unsigned char const *t4,
                  unsigned char const *t5,
                  unsigned char const *t6,
                  const unsigned char *t7)
{
  unsigned char hbuf[128];
  const unsigned char *t8 = 0;

  if (!t1) t1 = _("Refresh");
  if (!t2) t2 = _("Standings");
  if (!t3) t3 = _("View teams");
  if (!t4) t4 = _("Log out");
  if (!t8) t8 = _("Audit log");

  fprintf(f, "<table><tr><td>");
  fprintf(f, "%s", html_hyperref(hbuf, sizeof(hbuf), sid, self_url, extra_args, 0));
  fprintf(f, "%s</a></td><td>", t1);
  fprintf(f, "%s",
          html_hyperref(hbuf, sizeof(hbuf), sid, self_url, extra_args, "stand=1"));
  fprintf(f, "%s</a></td><td>", t2);
  fprintf(f, "%s",
          html_hyperref(hbuf, sizeof(hbuf), sid, self_url, extra_args, "viewteams=1"));
  fprintf(f, "%s</a></td>", t3);
  if (t5) {
    fprintf(f, "<td>%s%s</a></td>",
            html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                          extra_args, "source_%d=1", run_id),
            t5);
  }
  if (t6) {
    fprintf(f, "<td>%s%s</a></td>",
            html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                          extra_args, "report_%d=1", run_id),
            t6);
  }
  if (serve_state.global->team_enable_rep_view && t7) {
    fprintf(f, "<td>%s%s</a></td>",
            html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                          extra_args, "report_%d=1&t=1", run_id),
            t7);
  }
  fprintf(f, "<td>%s%s</a></td>",
          html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                        extra_args, "action=%d&run_id=%d",
                        ACTION_VIEW_AUDIT_LOG, run_id),
          t8);
  fprintf(f, "<td>%s",
          html_hyperref(hbuf, sizeof(hbuf), sid, self_url, extra_args, "logout=1"));
  fprintf(f, "%s</a></td></tr></table>", t4);
}

static void
parse_error_func(void *data, unsigned char const *format, ...)
{
  va_list args;
  unsigned char buf[1024];
  int l;

  va_start(args, format);
  l = vsnprintf(buf, sizeof(buf) - 24, format, args);
  va_end(args);
  strcpy(buf + l, "\n");
  cur_user->error_msgs = xstrmerge1(cur_user->error_msgs, buf);
  filter_expr_nerrs++;
}

// FIXME: currently no localization for these strings
static const unsigned char * const change_status_strings[RUN_LAST + 1] =
{
  [RUN_OK]               = "OK",
  [RUN_COMPILE_ERR]      = "Compilation error",
  [RUN_RUN_TIME_ERR]     = "Run-time error",
  [RUN_TIME_LIMIT_ERR]   = "Time-limit exceeded",
  [RUN_PRESENTATION_ERR] = "Presentation error",
  [RUN_WRONG_ANSWER_ERR] = "Wrong answer",
  // [RUN_CHECK_FAILED]     = 6, // not allowed
  [RUN_PARTIAL]          = "Partial solution",
  [RUN_ACCEPTED]         = "Accepted",
  [RUN_IGNORED]          = "Ignore",
  [RUN_DISQUALIFIED]     = "Disqualify",
  [RUN_MEM_LIMIT_ERR]    = "Mem. limit exceeded",
  [RUN_SECURITY_ERR]     = "Security violation",
  [RUN_PENDING]          = "Mark as PENDING",
  [RUN_FULL_REJUDGE]     = "FULL Rejudge",
  [RUN_REJUDGE]          = "Rejudge",
};
static const int kirov_no_rejudge_status_list[] =
{
  RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_COMPILE_ERR, RUN_PARTIAL,
  -1,
};
static const int kirov_status_list[] =
{
  RUN_REJUDGE, RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_COMPILE_ERR, RUN_PARTIAL,
  -1,
};
static const int olymp_accepting_no_rejudge_status_list[] =
{
  RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING, RUN_ACCEPTED,
  RUN_OK, RUN_PARTIAL, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR, RUN_TIME_LIMIT_ERR,
  RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR, RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR,
  -1,
};
static const int olymp_accepting_status_list[] =
{
  RUN_REJUDGE, RUN_FULL_REJUDGE, RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_ACCEPTED, RUN_OK, RUN_PARTIAL, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR,
  RUN_TIME_LIMIT_ERR, RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR,
  RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR,
  -1,
};
static const int olymp_judging_no_rejudge_status_list[] =
{
  RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_PARTIAL,  RUN_ACCEPTED, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR,
  RUN_TIME_LIMIT_ERR, RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR,
  RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR,
  -1,
};
static const int olymp_judging_status_list[] =
{
  RUN_REJUDGE, RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK,  RUN_PARTIAL, RUN_ACCEPTED, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR,
  RUN_TIME_LIMIT_ERR, RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR,
  RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR,
  -1,
};
static const int acm_no_rejudge_status_list[] =
{
  RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR, RUN_TIME_LIMIT_ERR,
  RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR, RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR,
  -1,
};
static const int acm_status_list[] =
{
  RUN_REJUDGE, RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR, RUN_TIME_LIMIT_ERR,
  RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR, RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR,
  -1,
};

static void
write_change_status_dialog(FILE *f, unsigned char const *var_name,
                           int disable_rejudge_flag, int accepting_mode)
{
  const int * cur_status_list = 0;
  int i;

  if (!var_name) var_name = "status";

  // various sets of valid run statuses
  if (serve_state.global->score_system_val == SCORE_KIROV) {
    if (disable_rejudge_flag) cur_status_list = kirov_no_rejudge_status_list;
    else cur_status_list = kirov_status_list;
  } else if (serve_state.global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
    // OLYMPIAD in accepting mode
    if (disable_rejudge_flag) cur_status_list = olymp_accepting_no_rejudge_status_list;
    else cur_status_list = olymp_accepting_status_list;
  } else if (serve_state.global->score_system_val == SCORE_OLYMPIAD) {
    // OLYMPIAD in judging mode
    if (disable_rejudge_flag) cur_status_list = olymp_judging_no_rejudge_status_list;
    cur_status_list = olymp_judging_status_list;
  } else {
    if (disable_rejudge_flag) cur_status_list = acm_no_rejudge_status_list;
    else cur_status_list = acm_status_list;
  }

  fprintf(f, "<td><select name=\"%s\"><option value=\"\"></option>", var_name);
  for (i = 0; cur_status_list[i] != -1; i++) {
    fprintf(f, "<option value=\"%d\">%s</option>",
            cur_status_list[i], change_status_strings[cur_status_list[i]]);
  }
  fprintf(f, "</select></td>\n");
}

#define BITS_PER_LONG (8*sizeof(unsigned long)) 

static struct user_filter_info *allocate_user_info(int user_id, ej_cookie_t session_id);

static void
print_raw_record(FILE *f, int run_id, struct run_entry *pe, time_t start_time,
                 int attempts, int disq_attempts, int prev_successes)
{
  // indices
  enum
  {
    RAW_RUN_ID,
    RAW_RUN_IS_IMPORTED,
    RAW_RUN_IS_HIDDEN,
    RAW_RUN_IS_READONLY,
    RAW_RUN_TIMESTAMP,
    RAW_RUN_NSEC,
    RAW_RUN_TIME,
    RAW_RUN_IP,
    RAW_RUN_SIZE,
    RAW_RUN_HASH,
    RAW_RUN_USER_ID,
    RAW_RUN_USER_LOGIN,
    RAW_RUN_USER_NAME,
    RAW_RUN_PROBLEM,
    RAW_RUN_VARIANT,
    RAW_RUN_LANGUAGE,
    RAW_RUN_LANG_SFX,
    RAW_RUN_STATUS,
    RAW_RUN_STATUS_STR,
    RAW_RUN_PASSED,
    RAW_RUN_SCORE,
    RAW_RUN_BASE_SCORE,
    RAW_RUN_SCORE_MULTIPLIER,
    RAW_RUN_ATTEMPT,
    RAW_RUN_PENALTY,
    RAW_RUN_DATE_PENALTY,
    RAW_RUN_SCORE_ADJ,
    RAW_RUN_DISQ_ATTEMPT,
    RAW_RUN_DISQ_PENALTY,
    RAW_RUN_PREV_SUCCESS,

    RAW_RUN_LAST
  };
  enum { BSIZE = 64 };
  unsigned char *fields[RAW_RUN_LAST];
  int i, variant = 0, score, mult = 1, date_penalty = 0;
  time_t run_time;
  unsigned char *sha_in, *sha_out;
  struct section_problem_data *pp = 0;
  struct section_language_data *pl = 0;

  memset(fields, 0, sizeof(fields));

  snprintf((fields[RAW_RUN_ID] = alloca(BSIZE)), BSIZE, "%d", run_id);
  snprintf((fields[RAW_RUN_STATUS] = alloca(BSIZE)), BSIZE, "%d", pe->status);
  fields[RAW_RUN_STATUS_STR] = run_status_str(pe->status, 0, 0);

  if (pe->status != RUN_EMPTY) {
    snprintf((fields[RAW_RUN_TIMESTAMP] = alloca(BSIZE)), BSIZE,
             "%d", pe->timestamp);
    snprintf((fields[RAW_RUN_NSEC] = alloca(BSIZE)), BSIZE, "%d", pe->nsec);
    fields[RAW_RUN_IP] = run_unparse_ip(pe->ip);
    snprintf((fields[RAW_RUN_USER_ID] = alloca(BSIZE)), BSIZE, "%d", pe->team);
    fields[RAW_RUN_USER_LOGIN] = teamdb_get_login(serve_state.teamdb_state, pe->team);
    fields[RAW_RUN_USER_NAME] = teamdb_get_name(serve_state.teamdb_state, pe->team);

    if (pe->status != RUN_VIRTUAL_START && pe->status != RUN_VIRTUAL_STOP) {
      run_time = pe->timestamp;
      if (run_time < start_time) run_time = start_time;
      run_time -= start_time;
      snprintf((fields[RAW_RUN_IS_IMPORTED] = alloca(BSIZE)), BSIZE,
                "%d", pe->is_imported);
      snprintf((fields[RAW_RUN_IS_HIDDEN] = alloca(BSIZE)), BSIZE,
                "%d", pe->is_hidden);
      snprintf((fields[RAW_RUN_IS_READONLY] = alloca(BSIZE)), BSIZE,
                "%d", pe->is_readonly);
      snprintf((fields[RAW_RUN_TIME] = alloca(BSIZE)), BSIZE, "%ld", run_time);
      snprintf((fields[RAW_RUN_SIZE] = alloca(BSIZE)), BSIZE, "%u", pe->size);
      sha_in = (unsigned char*) pe->sha1;
      sha_out = fields[RAW_RUN_HASH] = alloca(BSIZE);
      for (i = 0; i < 20; i++, sha_out += 2, sha_in++)
        sprintf(sha_out, "%02x", *sha_in);

      if (pe->problem > 0 && pe->problem <= serve_state.max_prob) pp = serve_state.probs[pe->problem];
      if (pe->language> 0 && pe->language<= serve_state.max_lang) pl = serve_state.langs[pe->language];

      if (pp) {
        fields[RAW_RUN_PROBLEM] = pp->short_name;
      } else {
        snprintf((fields[RAW_RUN_PROBLEM] = alloca(BSIZE)), BSIZE,
                 "??? - %d", pe->problem);
      }

      variant = pe->variant;
      if (pp && pp->variant_num > 0) {
        if (!variant) variant = find_variant(pe->team, pe->problem);
      }
      if (variant > 0) {
        snprintf((fields[RAW_RUN_VARIANT] = alloca(BSIZE)), BSIZE,
                 "%d", variant);
      }

      if (pl) {
        fields[RAW_RUN_LANGUAGE] = pl->short_name;
      } else {
        snprintf((fields[RAW_RUN_LANGUAGE] = alloca(BSIZE)), BSIZE,
                 "??? - %d", pe->language);
      }
      if (pl) fields[RAW_RUN_LANG_SFX] = pl->src_sfx;

      switch (pe->status) {
      case RUN_OK:
        if (serve_state.global->score_system_val == SCORE_ACM) break;
        // FALLTHROUGH
      case RUN_COMPILE_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_PARTIAL:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        if (serve_state.global->score_system_val == SCORE_ACM) {
          if (pe->test > 0) {
            snprintf((fields[RAW_RUN_PASSED] = alloca(BSIZE)), BSIZE,
                     "%d", pe->test);
          }
          break;
        }
        if (pe->test > 0) {
          snprintf((fields[RAW_RUN_PASSED] = alloca(BSIZE)), BSIZE,
                   "%d", pe->test - 1);
        }

        score = calc_kirov_score(0, 0, pe, pp, attempts, disq_attempts,
                                 prev_successes, &date_penalty, 0);
        if (pp->score_multiplier >= 1) mult = pp->score_multiplier;
        snprintf((fields[RAW_RUN_SCORE] = alloca(BSIZE)), BSIZE, "%d", score);
        snprintf((fields[RAW_RUN_BASE_SCORE] = alloca(BSIZE)), BSIZE,
                 "%d", pe->score);
        snprintf((fields[RAW_RUN_SCORE_MULTIPLIER] = alloca(BSIZE)), BSIZE,
                 "%d", mult);
        snprintf((fields[RAW_RUN_ATTEMPT] = alloca(BSIZE)), BSIZE,
                 "%d", attempts);
        if (pp) {
          snprintf((fields[RAW_RUN_PENALTY] = alloca(BSIZE)), BSIZE,
                   "%d", pp->run_penalty);
        }
        snprintf((fields[RAW_RUN_DATE_PENALTY] = alloca(BSIZE)), BSIZE,
                 "%d", date_penalty);
        snprintf((fields[RAW_RUN_SCORE_ADJ] = alloca(BSIZE)), BSIZE,
                 "%d", pe->score_adj);
        snprintf((fields[RAW_RUN_DISQ_ATTEMPT] = alloca(BSIZE)), BSIZE,
                 "%d", disq_attempts);
        if (pp) {
          snprintf((fields[RAW_RUN_DISQ_PENALTY] = alloca(BSIZE)), BSIZE,
                   "%d", pp->disqualified_penalty);
        }
        snprintf((fields[RAW_RUN_PREV_SUCCESS] = alloca(BSIZE)), BSIZE,
                 "%d", prev_successes);
      }
    }
  }

  for (i = 0; i < RAW_RUN_LAST; i++) {
    if (!fields[i]) fields[i] = "";
    if (i > 0) putc('&', f);
    fputs(fields[i], f);
  }
  putc('\n', f);
}

/* note: if self_url is an empty string, raw format is used */
int
write_priv_all_runs(FILE *f, int user_id, struct user_filter_info *u,
                    int priv_level, ej_cookie_t sid,
                    int first_run, int last_run,
                    int accepting_mode,
                    unsigned char const *self_url,
                    unsigned char const *filter_expr,
                    unsigned char const *hidden_vars,
                    unsigned char const *extra_args)
{
  struct filter_env env;
  int i, r, j;
  int *match_idx = 0;
  int match_tot = 0;
  int transient_tot = 0;
  int *list_idx = 0;
  int list_tot = 0;
  unsigned char *str1 = 0, *str2 = 0;
  unsigned char durstr[64], statstr[64];
  int rid, attempts, disq_attempts, prev_successes;
  time_t run_time, start_time;
  struct run_entry *pe;
  unsigned char *fe_html;
  int fe_html_len;
  unsigned char first_run_str[32] = { 0 }, last_run_str[32] = { 0 };
  unsigned char hbuf[128];
  unsigned char *prob_str;
  const unsigned char *imported_str;
  const unsigned char *rejudge_dis_str;
  unsigned long *displayed_mask = 0;
  int displayed_size = 0, raw_format = 0;
  unsigned char stat_select_name[32];

  if (!u) u = allocate_user_info(user_id, sid);

  if (!self_url || !*self_url) raw_format = 1;

  if (!filter_expr || !*filter_expr ||
      (u->prev_filter_expr && !strcmp(u->prev_filter_expr, filter_expr))){
    /* nothing to do, use the previous values */
  } else {
    if (u->prev_filter_expr) xfree(u->prev_filter_expr);
    if (u->tree_mem) filter_tree_delete(u->tree_mem);
    if (u->error_msgs) xfree(u->error_msgs);
    u->error_msgs = 0;
    u->prev_filter_expr = 0;
    u->prev_tree = 0;
    u->tree_mem = 0;

    u->prev_filter_expr = xstrdup(filter_expr);
    u->tree_mem = filter_tree_new();
    filter_expr_set_string(filter_expr, u->tree_mem, parse_error_func,
                           &serve_state);
    filter_expr_init_parser(u->tree_mem, parse_error_func, &serve_state);
    i = filter_expr_parse();
    if (i + filter_expr_nerrs == 0 && filter_expr_lval &&
        filter_expr_lval->type == FILTER_TYPE_BOOL) {
      // parsing successful
      u->prev_tree = filter_expr_lval;
    } else {
      // parsing failed
      if (i + filter_expr_nerrs == 0 && filter_expr_lval &&
          filter_expr_lval->type != FILTER_TYPE_BOOL) {
        parse_error_func(&serve_state, "bool expression expected");
      } else {
        parse_error_func(&serve_state, "filter expression parsing failed");
      }
      /* In the error case we print the diagnostics, new filter expression
       * form (incl. "Reset filter") button.
       * We'll need u->error_msgs string, but the tree should be freed.
       */
      u->tree_mem = filter_tree_delete(u->tree_mem);
      u->prev_tree = 0;
      u->tree_mem = 0;
    }
  }

  /* in the raw output format we cannot produce reasonable output in case of error */
  if (raw_format && u->error_msgs) {
    return -SRV_ERR_FILTER_EXPR;
  }

  if (!u->error_msgs) {
    memset(&env, 0, sizeof(env));
    env.teamdb_state = serve_state.teamdb_state;
    env.mem = filter_tree_new();
    env.maxlang = serve_state.max_lang;
    env.langs = serve_state.langs;
    env.maxprob = serve_state.max_prob;
    env.probs = serve_state.probs;
    env.rtotal = run_get_total(serve_state.runlog_state);
    run_get_header(serve_state.runlog_state, &env.rhead);
    env.rentries = alloca(env.rtotal * sizeof(env.rentries[0]));
    env.cur_time = time(0);
    run_get_all_entries(serve_state.runlog_state, env.rentries);

    match_idx = alloca((env.rtotal + 1) * sizeof(match_idx[0]));
    memset(match_idx, 0, (env.rtotal + 1) * sizeof(match_idx[0]));
    match_tot = 0;
    transient_tot = 0;

    for (i = 0; i < env.rtotal; i++) {
      if (env.rentries[i].status >= RUN_TRANSIENT_FIRST
          && env.rentries[i].status <= RUN_TRANSIENT_LAST)
        transient_tot++;
      env.rid = i;
      if (u->prev_tree) {
        r = filter_tree_bool_eval(&env, u->prev_tree);
        if (r < 0) {
          parse_error_func(&serve_state, "run %d: %s", i, filter_strerror(-r));
          continue;
        }
        if (!r) continue;
      }
      match_idx[match_tot++] = i;
    }
    env.mem = filter_tree_delete(env.mem);
  }

  if (raw_format && u->error_msgs) {
    return -SRV_ERR_FILTER_EXPR;
  }

  if (!u->error_msgs) {
    /* create the displayed runs mask */
    displayed_size = (env.rtotal + BITS_PER_LONG - 1) / BITS_PER_LONG;
    if (!displayed_size) displayed_size = 1;
    displayed_mask = (unsigned long*) alloca(displayed_size*sizeof(displayed_mask[0]));
    memset(displayed_mask, 0, displayed_size * sizeof(displayed_mask[0]));

    list_idx = alloca((env.rtotal + 1) * sizeof(list_idx[0]));
    memset(list_idx, 0, (env.rtotal + 1) * sizeof(list_idx[0]));
    list_tot = 0;

    if (!first_run) first_run = u->prev_first_run;
    if (!last_run) last_run = u->prev_last_run;
    u->prev_first_run = first_run;
    u->prev_last_run = last_run;

    if (!first_run && !last_run) {
      // last 20 in the reverse order
      first_run = -1;
      last_run = -20;
    } else if (!first_run) {
      // from the last in the reverse order
      first_run = -1;
    } else if (!last_run) {
      // 20 in the reverse order
      last_run = first_run - 20 + 1;
      if (first_run > 0 && last_run <= 0) {
        last_run = 1;
      }
    }
    if (first_run > 0) first_run--;
    if (last_run > 0) last_run--;
    if (first_run >= match_tot) first_run = match_tot;
    if (first_run < 0) {
      first_run = match_tot + first_run;
      if (first_run < 0) first_run = 0;
    }
    if (last_run >= match_tot) last_run = match_tot;
    if (last_run < 0) {
      last_run = match_tot + last_run;
      if (last_run < 0) last_run = 0;
    }
    if (first_run <= last_run) {
      for (i = first_run; i <= last_run && i < match_tot; i++)
        list_idx[list_tot++] = match_idx[i];
    } else {
      for (i = first_run; i >= last_run; i--)
        list_idx[list_tot++] = match_idx[i];
    }
  }

  if (!raw_format) {
    fprintf(f, "<hr><h2>%s</h2>\n", _("Submissions"));
  }

  if (!raw_format && !u->error_msgs) {
    fprintf(f, "<p><big>%s: %d, %s: %d, %s: %d</big></p>\n",
            _("Total submissions"), env.rtotal,
            _("Filtered"), match_tot,
            _("Shown"), list_tot);
    fprintf(f, "<p><big>Compiling and running: %d</big></p>\n", transient_tot);
  }

  if (!raw_format) {
    if (u->prev_filter_expr) {
      fe_html_len = html_armored_strlen(u->prev_filter_expr);
      fe_html = alloca(fe_html_len + 16);
      html_armor_string(u->prev_filter_expr, fe_html);
    } else {
      fe_html = "";
      fe_html_len = 0;
    }
    if (u->prev_first_run) {
      snprintf(first_run_str, sizeof(first_run_str), "%d",
               (u->prev_first_run>0)?u->prev_first_run - 1:u->prev_first_run);
    }
    if (u->prev_last_run) {
      snprintf(last_run_str, sizeof(last_run_str), "%d",
               (u->prev_last_run > 0)?u->prev_last_run - 1:u->prev_last_run);
    }
    html_start_form(f, 0, self_url, hidden_vars);
    fprintf(f, "<p>%s: <input type=\"text\" name=\"filter_expr\" size=\"32\" maxlength=\"128\" value=\"%s\">", _("Filter expression"), fe_html);
    fprintf(f, "%s: <input type=\"text\" name=\"filter_first_run\" size=\"16\" value=\"%s\">", _("First run"), first_run_str);
    fprintf(f, "%s: <input type=\"text\" name=\"filter_last_run\" size=\"16\" value=\"%s\">", _("Last run"), last_run_str);
    fprintf(f, "<input type=\"submit\" name=\"filter_view\" value=\"%s\">", _("View"));
    //fprintf(f, "</form>\n");
    //html_start_form(f, 0, sid, self_url, hidden_vars);
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_RESET_FILTER, _("Reset filter"));
    fprintf(f, "</form></p>\n");
  }

  if (u->error_msgs) {
    fprintf(f, "<h2>Filter expression errors</h2>\n");
    fprintf(f, "<p><pre><font color=\"red\">%s</font></pre></p>\n",
            u->error_msgs);
  }

  if (!u->error_msgs) {
    switch (serve_state.global->score_system_val) {
    case SCORE_ACM:
      str1 = _("Failed test");
      break;
    case SCORE_KIROV:
    case SCORE_OLYMPIAD:
      str1 = _("Tests passed");
      str2 = _("Score");
      break;
    case SCORE_MOSCOW:
      str1 = _("Failed test");
      str2 = _("Score");
      break;
    default:
      abort();
    }

    //fprintf(f, "<font size=\"-1\">\n");
    if (!raw_format) {
      fprintf(f, "<table border=\"1\"><tr><th>%s</th><th>%s</th>"
              "<th>%s</th><th>%s</th>"
              "<th>%s</th><th>%s</th>"
              "<th>%s</th><th>%s</th>"
              "<th>%s</th><th>%s</th>", 
              _("Run ID"), _("Time"), _("Size"), _("IP"),
              _("Team ID"), _("Team name"), _("Problem"),
              _("Language"), _("Result"), str1);
      if (str2) {
        fprintf(f, "<th>%s</th>", str2);
      }
      if (priv_level == PRIV_LEVEL_ADMIN) {
        fprintf(f, "<th>%s</th>", _("New result"));
        fprintf(f, "<th>%s</th>", _("Change result"));
      }
      fprintf(f, "<th>%s</th><th>%s</th></tr>\n",
              _("View source"), _("View report"));
    }

    for (i = 0; i < list_tot; i++) {
      rid = list_idx[i];
      ASSERT(rid >= 0 && rid < env.rtotal);
      pe = &env.rentries[rid];

      displayed_mask[rid / BITS_PER_LONG] |= (1 << (rid % BITS_PER_LONG));

      if (pe->status == RUN_EMPTY) {
        run_status_str(pe->status, statstr, 0);

        if (raw_format) {
          print_raw_record(f, rid, pe, 0, 0, 0, 0);
          continue;
        }

        fprintf(f, "<tr>");
        fprintf(f, "<td>%d</td>", rid);
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td><b>%s</b></td>", statstr);
        fprintf(f, "<td>&nbsp;</td>");
        if (serve_state.global->score_system_val == SCORE_KIROV
            || serve_state.global->score_system_val == SCORE_OLYMPIAD
            || serve_state.global->score_system_val == SCORE_MOSCOW) {
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        if (priv_level == PRIV_LEVEL_ADMIN) {
          fprintf(f, "<td>&nbsp;</td>");
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "</tr>\n");
        continue;
      }
      if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP) {
        run_time = pe->timestamp;
        if (!env.rhead.start_time) run_time = 0;
        if (env.rhead.start_time > run_time) run_time = env.rhead.start_time;
        duration_str(1, run_time, env.rhead.start_time, durstr, 0);
        run_status_str(pe->status, statstr, 0);

        if (raw_format) {
          print_raw_record(f, rid, pe, 0, 0, 0, 0);
          continue;
        }

        fprintf(f, "<tr>");
        fprintf(f, "<td>%d</td>", rid);
        fprintf(f, "<td>%s</td>", durstr);
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>%s</td>", run_unparse_ip(pe->ip));
        fprintf(f, "<td>%d</td>", pe->team);
        fprintf(f, "<td>%s</td>", teamdb_get_name(serve_state.teamdb_state, pe->team));
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td><b>%s</b></td>", statstr);
        fprintf(f, "<td>&nbsp;</td>");
        if (serve_state.global->score_system_val == SCORE_KIROV
            || serve_state.global->score_system_val == SCORE_OLYMPIAD
            || serve_state.global->score_system_val == SCORE_MOSCOW) {
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "<td>&nbsp;</td>");
        if (priv_level == PRIV_LEVEL_ADMIN) {
          fprintf(f, "<td>");
          html_start_form(f, 1, self_url, hidden_vars);
          fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">",
                  rid);
          fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
                  ACTION_CLEAR_RUN, _("clear"));
          fprintf(f, "</form></td>");
        } else {
          fprintf(f, "<td>&nbsp;</td>");
        }
        if (priv_level == PRIV_LEVEL_ADMIN) {
          fprintf(f, "<td>&nbsp;</td>");
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "</tr>\n");
        continue;
      }

      prev_successes = RUN_TOO_MANY;
      if (serve_state.global->score_system_val == SCORE_KIROV && pe->status == RUN_OK
          && pe->problem > 0 && pe->problem <= serve_state.max_prob && !pe->is_hidden
          && serve_state.probs[pe->problem] && serve_state.probs[pe->problem]->score_bonus_total > 0) {
        if ((prev_successes = run_get_prev_successes(serve_state.runlog_state, rid)) < 0)
          prev_successes = RUN_TOO_MANY;
      }

      attempts = 0; disq_attempts = 0;
      if (serve_state.global->score_system_val == SCORE_KIROV && !pe->is_hidden) {
        run_get_attempts(serve_state.runlog_state, rid, &attempts, &disq_attempts,
                         serve_state.global->ignore_compile_errors);
      }
      run_time = pe->timestamp;
      imported_str = "";
      rejudge_dis_str = "";
      if (pe->is_imported) {
        imported_str = "*";
        rejudge_dis_str = " disabled=\"1\"";
      }
      if (pe->is_hidden) {
        imported_str = "#";
      }
      start_time = env.rhead.start_time;
      if (serve_state.global->virtual) {
        start_time = run_get_virtual_start_time(serve_state.runlog_state, pe->team);
      }
      if (!start_time) run_time = 0;
      if (start_time > run_time) run_time = start_time;
      duration_str(serve_state.global->show_astr_time, run_time, start_time,
                   durstr, 0);
      run_status_str(pe->status, statstr, 0);

      if (raw_format) {
        print_raw_record(f, rid, pe, start_time, attempts, disq_attempts,
                         prev_successes);
        continue;
      }

      if (priv_level == PRIV_LEVEL_ADMIN) {
        html_start_form(f, 1, self_url, hidden_vars);
      }
      fprintf(f, "<tr>");
      fprintf(f, "<td>%d%s</td>", rid, imported_str);
      fprintf(f, "<td>%s</td>", durstr);
      fprintf(f, "<td>%u</td>", pe->size);
      fprintf(f, "<td>%s</td>", run_unparse_ip(pe->ip));
      fprintf(f, "<td>%d</td>", pe->team);
      fprintf(f, "<td>%s</td>", teamdb_get_name(serve_state.teamdb_state, pe->team));
      if (pe->problem > 0 && pe->problem <= serve_state.max_prob && serve_state.probs[pe->problem]) {
        struct section_problem_data *cur_prob = serve_state.probs[pe->problem];
        int variant = 0;
        if (cur_prob->variant_num > 0) {
          variant = pe->variant;
          if (!variant) variant = find_variant(pe->team, pe->problem);
          prob_str = alloca(strlen(cur_prob->short_name) + 10);
          if (variant > 0) {
            sprintf(prob_str, "%s-%d", cur_prob->short_name, variant);
          } else {
            sprintf(prob_str, "%s-?", cur_prob->short_name);
          }
        } else {
          prob_str = cur_prob->short_name;
        }
      } else {
        prob_str = alloca(32);
        sprintf(prob_str, "??? - %d", pe->problem);
      }
      fprintf(f, "<td>%s</td>", prob_str);
      if (pe->language > 0 && pe->language <= serve_state.max_lang
          && serve_state.langs[pe->language]) {
        fprintf(f, "<td>%s</td>", serve_state.langs[pe->language]->short_name);
      } else {
        fprintf(f, "<td>??? - %d</td>", pe->language);
      }
      write_html_run_status(f, pe, priv_level, attempts, disq_attempts,
                            prev_successes);
      if (priv_level == PRIV_LEVEL_ADMIN) {
        snprintf(stat_select_name, sizeof(stat_select_name), "stat_%d", rid);
        write_change_status_dialog(f, stat_select_name, pe->is_imported,
                                   accepting_mode);
        fprintf(f,
                "<td><input type=\"submit\" name=\"change_%d\""
                " value=\"%s\"></td>\n", rid, _("change"));
      }

      fprintf(f, "<td>");
      fprintf(f, "%s",
              html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                            extra_args, "source_%d=1", rid));
      fprintf(f, "%s</a></td>", _("View"));
      if (pe->is_imported) {
        fprintf(f, "<td>N/A</td>");
      } else {
        fprintf(f, "<td>");
        fprintf(f, "%s",
                html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                              extra_args, "report_%d=1", rid));
        fprintf(f, "%s</a></td>", _("View"));
      }
      fprintf(f, "</tr>\n");
      if (priv_level == PRIV_LEVEL_ADMIN) {
        fprintf(f, "</form>\n");
      }
    }

    if (raw_format) return 0;

    fprintf(f, "</table>\n");
    //fprintf(f, "</font>\n");
  }

  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args, 0, 0, 0, 0, 0, 0, 0);

  if (priv_level == PRIV_LEVEL_ADMIN &&!u->error_msgs) {
    fprintf(f, "<table border=\"0\"><tr><td>");
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_REJUDGE_ALL_1, _("Rejudge all"));
    fprintf(f, "</form></td><td>\n");

    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_JUDGE_SUSPENDED_1, _("Judge suspended runs"));
    fprintf(f, "</form></td><td>\n");

    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_mask_size\" value=\"%d\">\n",
            displayed_size);
    fprintf(f, "<input type=\"hidden\" name=\"run_mask\" value=\"");
    for (i = 0; i < displayed_size; i++) {
      if (i > 0) fprintf(f, " ");
      fprintf(f, "%lx", displayed_mask[i]);
    }
    fprintf(f, "\">\n");
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_REJUDGE_DISPLAYED_1, _("Rejudge displayed runs"));
    fprintf(f, "</form></td><td>\n");

    if (serve_state.global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f,"<input type=\"hidden\" name=\"run_mask_size\" value=\"%d\">\n",
              displayed_size);
      fprintf(f, "<input type=\"hidden\" name=\"run_mask\" value=\"");
      for (i = 0; i < displayed_size; i++) {
        if (i > 0) fprintf(f, " ");
        fprintf(f, "%lx", displayed_mask[i]);
      }
      fprintf(f, "\">\n");
      fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
              ACTION_FULL_REJUDGE_DISPLAYED_1,
              _("Full rejudge displayed runs"));
      fprintf(f, "</form></td><td>\n");
    }

    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_SQUEEZE_RUNS, _("Squeeze runs"));
    fprintf(f, "</form></td></tr></table>\n");

    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "%s: <select name=\"problem\"><option value=\"\">\n",
            _("Rejudge problem"));
    for (i = 1; i <= serve_state.max_prob; i++)
      if (serve_state.probs[i]) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                serve_state.probs[i]->id, serve_state.probs[i]->short_name, serve_state.probs[i]->long_name);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_REJUDGE_PROBLEM, _("Rejudge!"));
    fprintf(f, "</form></p>\n");
  }

  if (priv_level == PRIV_LEVEL_ADMIN && serve_state.global->enable_runlog_merge) {
    html_start_form(f, 2, self_url, hidden_vars);
    fprintf(f, "<table border=\"0\"><tr><td>%s: </td>\n",
            _("Import and merge XML runs log"));
    fprintf(f, "<td><input type=\"file\" name=\"file\"></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_MERGE_RUNS, _("Send!"));
    fprintf(f, "</tr></table></form>\n");
  }

  // submit solution dialog
  fprintf(f, "<hr><h2>%s</h2>\n", _("Send a submission"));
  html_start_form(f, 2, self_url, hidden_vars);
  fprintf(f, "<table>\n");
  fprintf(f, "<tr><td>%s:</td><td>", _("Problem"));
  fprintf(f, "<select name=\"problem\"><option value=\"\">\n");
  for (i = 1; i <= serve_state.max_prob; i++) {
    if (!serve_state.probs[i]) continue;
    if (serve_state.probs[i]->variant_num > 0) {
      for (j = 1; j <= serve_state.probs[i]->variant_num; j++) {
        fprintf(f, "<option value=\"%d,%d\">%s-%d - %s\n",
                i, j, serve_state.probs[i]->short_name, j, serve_state.probs[i]->long_name);
      }
    } else {
      fprintf(f, "<option value=\"%d\">%s - %s\n",
              i, serve_state.probs[i]->short_name, serve_state.probs[i]->long_name);
    }
  }
  fprintf(f, "</select>\n");
  fprintf(f, "</td></tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>", _("Language"));
  fprintf(f, "<select name=\"language\"><option value=\"\">\n");
  for (i = 1; i <= serve_state.max_lang; i++) {
    if (!serve_state.langs[i]) continue;
    fprintf(f, "<option value=\"%d\">%s - %s\n",
            i, serve_state.langs[i]->short_name, serve_state.langs[i]->long_name);
  }
  fprintf(f, "</select>\n");
  fprintf(f, "</td></tr>\n");
  fprintf(f, "<tr><td>%s:</td>"
          "<td><input type=\"file\" name=\"file\"></td></tr>\n"
          "<tr><td>%s</td>"
          "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr>",
          _("File"), _("Send!"), ACTION_SUBMIT_RUN, _("Send!"));
  fprintf(f, "</table></form>\n");

  fprintf(f, "<table><tr><td>");
  fprintf(f, "%s", html_hyperref(hbuf, sizeof(hbuf), sid, self_url,
                                 extra_args, "action=%d",
                                 ACTION_NEW_RUN_FORM));
  fprintf(f, "%s</a><td></tr></table>", _("Add new run"));

  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args, 0, 0, 0, 0, 0, 0, 0);
  return 0;
}

static void
write_all_clars(FILE *f, struct user_filter_info *u,
                int priv_level, ej_cookie_t sid,
                int mode_clar, int first_clar, int last_clar,
                unsigned char const *self_url,
                unsigned char const *hidden_vars,
                unsigned char const *extra_args)
{
  int total, i, j;

  int *list_idx;
  int list_tot;

  unsigned char first_clar_str[64] = { 0 }, last_clar_str[64] = { 0 };

  size_t size;
  time_t start, time;
  int from, to, flags, j_from, hide_flag;
  unsigned char subj[CLAR_MAX_SUBJ_LEN + 4];
  unsigned char psubj[CLAR_MAX_SUBJ_TXT_LEN + 4];
  unsigned char durstr[64];
  unsigned char ip[CLAR_MAX_IP_LEN + 4];
  unsigned char hbuf[128];
  unsigned char *asubj = 0;
  int asubj_len = 0, new_len;
  int show_astr_time;

  fprintf(f, "<hr><h2>%s</h2>\n", _("Messages"));

  start = run_get_start_time(serve_state.runlog_state);
  total = clar_get_total(serve_state.clarlog_state);
  if (!mode_clar) mode_clar = u->prev_mode_clar;
  if (!first_clar) first_clar = u->prev_first_clar;
  if (!last_clar) last_clar = u->prev_last_clar;
  if (!mode_clar) {
    mode_clar = 1;
    if (priv_level != PRIV_LEVEL_ADMIN) mode_clar = 2;
  }
  u->prev_mode_clar = mode_clar;
  u->prev_first_clar = first_clar;
  u->prev_last_clar = last_clar;
  show_astr_time = serve_state.global->show_astr_time;
  if (serve_state.global->virtual) show_astr_time = 1;

  if (!first_clar && !last_clar) {
    first_clar = -1;
    last_clar = -10;
  } else if (!first_clar) {
    first_clar = -1;
  } else if (!last_clar) {
    last_clar = first_clar - 10 + 1;
    if (first_clar > 0 && last_clar < 0) last_clar = 1;
  }
  if (first_clar > 0) first_clar--;
  if (last_clar > 0) last_clar--;
  if (first_clar < 0) {
    first_clar = total + first_clar;
    if (first_clar < 0) first_clar = 0;
  }
  if (last_clar < 0) {
    last_clar = total + last_clar;
    if (last_clar < 0) last_clar = 0;
  }

  list_idx = alloca((total + 1) * sizeof(list_idx[0]));
  memset(list_idx, 0, (total + 1) * sizeof(list_idx[0]));
  list_tot = 0;
  if (first_clar <= last_clar) {
    for (i = first_clar; i <= last_clar && i < total; i++)
      list_idx[list_tot++] = i;
  } else {
    for (i = first_clar; i >= last_clar; i--)
      list_idx[list_tot++] = i;
  }

  fprintf(f, "<p><big>%s: %d, %s: %d</big></p>\n", _("Total messages"), total,
          _("Shown"), list_tot);

  if (u->prev_first_clar) {
    snprintf(first_clar_str, sizeof(first_clar_str), "%d",
             (u->prev_first_clar > 0)?u->prev_first_clar-1:u->prev_first_clar);
  }
  if (u->prev_last_clar) {
    snprintf(last_clar_str, sizeof(last_clar_str), "%d",
             (u->prev_last_clar > 0)?u->prev_last_clar - 1:u->prev_last_clar);
  }
  html_start_form(f, 0, self_url, hidden_vars);

  fprintf(f,
          "<select name=\"%s\"><option value=\"1\"%s>%s</option>"
          "<option value=\"2\"%s>%s</option></select>\n",
          "filter_mode_clar",
          (mode_clar == 1) ? " selected=\"1\"" : "",
          _("All clars"),
          (mode_clar == 2) ? " selected=\"1\"" : "",
          _("Unanswered clars"));
  fprintf(f, "%s: <input type=\"text\" name=\"filter_first_clar\" size=\"16\" value=\"%s\">", _("First clar"), first_clar_str);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_last_clar\" size=\"16\" value=\"%s\">", _("Last clar"), last_clar_str);
  fprintf(f, "<input type=\"submit\" name=\"filter_view_clars\" value=\"%s\">", _("View"));
  fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
          ACTION_RESET_CLAR_FILTER, _("Reset filter"));
  fprintf(f, "</p></form>\n");

  fprintf(f, "<table border=\"1\"><tr><th>%s</th><th>%s</th><th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th><th>%s</th>"
          "<th>%s</th><th>%s</th></tr>\n",
          _("Clar ID"), _("Flags"), _("Time"), _("IP"), _("Size"),
          _("From"), _("To"), _("Subject"), _("View"));
  for (j = 0; j < list_tot; j++) {
    i = list_idx[j];

    clar_get_record(serve_state.clarlog_state, i, &time, &size, ip, &from, &to, &flags,
                    &j_from, &hide_flag, subj);
    if (mode_clar != 1 && (from <= 0 || flags >= 2)) continue; 

    base64_decode_str(subj, psubj, 0);
    new_len = html_armored_strlen(psubj);
    new_len = (new_len + 7) & ~3;
    if (new_len > asubj_len) asubj = alloca(asubj_len = new_len);
    html_armor_string(psubj, asubj);
    if (!start) time = start;
    if (start > time) time = start;
    duration_str(show_astr_time, time, start, durstr, 0);

    fprintf(f, "<tr>");
    if (hide_flag) fprintf(f, "<td>%d#</td>", i);
    else fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", clar_flags_html(serve_state.clarlog_state, flags, from, to,
                                              0, 0));
    fprintf(f, "<td>%s</td>", durstr);
    fprintf(f, "<td>%s</td>", ip);
    fprintf(f, "<td>%zu</td>", size);
    if (!from) {
      if (!j_from)
        fprintf(f, "<td><b>%s</b></td>", _("judges"));
      else
        fprintf(f, "<td><b>%s</b> (%s)</td>", _("judges"),
                teamdb_get_name(serve_state.teamdb_state, j_from));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_name(serve_state.teamdb_state, from));
    }
    if (!to && !from) {
      fprintf(f, "<td><b>%s</b></td>", _("all"));
    } else if (!to) {
      fprintf(f, "<td><b>%s</b></td>", _("judges"));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_name(serve_state.teamdb_state, to));
    }
    fprintf(f, "<td>%s</td>", asubj);
    fprintf(f, "<td>%s%s</a></td>",
            html_hyperref(hbuf, sizeof(hbuf), sid, self_url, extra_args,
                          "clar_%d=1", i),
            _("View"));

    fprintf(f, "</tr>\n");
  }
  fputs("</table>\n", f);

  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args, 0, 0, 0, 0, 0, 0, 0);
}

static struct user_filter_info *
allocate_user_info(int user_id, ej_cookie_t session_id)
{
  struct user_filter_info *p;

  if (user_id == -1) user_id = 0;
  ASSERT(user_id >= 0 && user_id < 32768);
  ASSERT(session_id);

  if (user_id >= users_a) {
    int new_users_a = users_a;
    struct user_state_info **new_users;

    if (!new_users_a) new_users_a = 64;
    while (new_users_a <= user_id) new_users_a *= 2;
    new_users = xcalloc(new_users_a, sizeof(new_users[0]));
    if (users_a > 0)
      memcpy(new_users, users, users_a * sizeof(users[0]));
    xfree(users);
    users_a = new_users_a;
    users = new_users;
    info("allocate_user_info: new size %d", users_a);
  }
  if (!users[user_id]) {
    users[user_id] = xcalloc(1, sizeof(*users[user_id]));
  }

  for (p = users[user_id]->first_filter; p; p = p->next) {
    if (p->session_id == session_id) break;
  }
  if (!p) {
    XCALLOC(p, 1);
    p->next = users[user_id]->first_filter;
    p->session_id = session_id;
    users[user_id]->first_filter = p;
  }

  cur_user = p;
  return p;
}

void
write_master_page(FILE *f, int user_id, int priv_level,
                  ej_cookie_t sid,
                  int first_run, int last_run,
                  int mode_clar, int first_clar, int last_clar,
                  int accepting_mode,
                  unsigned char const *self_url,
                  unsigned char const *filter_expr,
                  unsigned char const *hidden_vars,
                  unsigned char const *extra_args,
                  const opcap_t *pcaps)
{
  struct user_filter_info *u = allocate_user_info(user_id, sid);

  write_priv_all_runs(f, user_id, u, priv_level, sid, first_run,
                      last_run, accepting_mode, self_url, filter_expr,
                      hidden_vars, extra_args);
  write_all_clars(f, u, priv_level, sid, mode_clar,
                  first_clar, last_clar,
                  self_url, hidden_vars, extra_args);
}

void
write_priv_standings(FILE *f, ej_cookie_t sid,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args, int accepting_mode)
{
  write_standings_header(f, 1, 0, 0, 0);

  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), _("Refresh"), 0, 0, 0, 0, 0);

  if (serve_state.global->score_system_val == SCORE_KIROV
      || serve_state.global->score_system_val == SCORE_OLYMPIAD)
    do_write_kirov_standings(f, 0, 1, 0, 0, 0, 0 /*accepting_mode*/);
  else if (serve_state.global->score_system_val == SCORE_MOSCOW)
    do_write_moscow_standings(f, 0, 1, 0, 0, 0, 0, 0);
  else
    do_write_standings(f, 1, 0, 0, 0, 0, 0);

  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), _("Refresh"), 0, 0, 0, 0, 0);
}

int
write_priv_source(FILE *f, int user_id, int priv_level,
                  ej_cookie_t sid,
                  int accepting_mode,
                  unsigned char const *self_url,
                  unsigned char const *hidden_vars,
                  unsigned char const *extra_args,
                  int run_id,
                  const opcap_t *pcaps)
{
  unsigned char *s;
  int i;
  path_t src_path;
  struct run_entry info;
  char *src_text = 0, *html_text;
  unsigned char *numb_txt;
  size_t src_len, html_len, numb_len;
  time_t start_time;
  int variant, src_flags, run_id2;
  unsigned char const *nbsp = "<td>&nbsp;</td><td>&nbsp;</td>";
  unsigned char numbuf[64];
  unsigned char filtbuf1[128];
  unsigned char filtbuf2[256];
  unsigned char filtbuf3[512];
  unsigned char *ps1, *ps2;

  if (run_id < 0 || run_id >= run_get_total(serve_state.runlog_state))
    return -SRV_ERR_BAD_RUN_ID;
  run_get_entry(serve_state.runlog_state, run_id, &info);

  src_flags = archive_make_read_path(src_path, sizeof(src_path),
                                     serve_state.global->run_archive_dir, run_id, 0, 1);
  start_time = run_get_start_time(serve_state.runlog_state);
  if (info.timestamp < start_time) info.timestamp = start_time;

  fprintf(f, "<h2>%s %d</h2>\n",
          _("Information about run"), run_id);
  if (info.status == RUN_VIRTUAL_START
      || info.status == RUN_VIRTUAL_STOP
      || info.status == RUN_EMPTY) {
    fprintf(f, "<p>Information is not available.</p>\n");
    fprintf(f, "<hr>\n");
    print_nav_buttons(f, run_id, sid, self_url, hidden_vars, extra_args,
                      _("Main page"), 0, 0, 0, 0, 0, 0);
    return 0;
  }
  fprintf(f, "<table>\n");
  fprintf(f, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Run ID"), info.submission, nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s:%d</td>%s</tr>\n",
          _("Submission time"),
          duration_str(1, info.timestamp, start_time, 0, 0), info.nsec, nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("Contest time"),
          duration_str(0, info.timestamp, start_time, 0, 0), nbsp);

  // IP-address
  fprintf(f, "<tr><td>%s:</td>", _("Originator IP"));
  snprintf(filtbuf1, sizeof(filtbuf1), "ip == ip(%d)", run_id);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                extra_args, "filter_expr=%s&filter_view=View",
                filtbuf2);
  fprintf(f, "<td>%s%s</a></td>", filtbuf3, run_unparse_ip(info.ip));
  fprintf(f, "%s</tr>\n", nbsp);

  // size
  ps1 = ""; ps2 = "";
  snprintf(filtbuf1, sizeof(filtbuf1), "size == size(%d)", run_id);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                extra_args, "filter_expr=%s&filter_view=View",
                filtbuf2);
  ps1 = filtbuf3; ps2 = "</a>";
  fprintf(f, "<tr><td>%s:</td><td>%s%u%s</td>%s</tr>\n",
          _("Size"), ps1, info.size, ps2, nbsp);


  ps1 = ""; ps2 = "";
  snprintf(filtbuf1, sizeof(filtbuf1), "hash == hash(%d)", run_id);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                extra_args, "filter_expr=%s&filter_view=View",
                filtbuf2);
  ps1 = filtbuf3; ps2 = "</a>";
  fprintf(f, "<tr><td>%s:</td><td>%s", _("Hash value"), ps1);
  s = (unsigned char*) &info.sha1;
  for (i = 0; i < 20; i++) fprintf(f, "%02x", *s++);
  fprintf(f, "%s</td>%s</tr>\n", ps2, nbsp);

  ps1 = ""; ps2 = "";
  snprintf(filtbuf1, sizeof(filtbuf1), "uid == %d", info.team);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                extra_args, "filter_expr=%s&filter_view=View",
                filtbuf2);
  ps1 = filtbuf3; ps2 = "</a>";
  fprintf(f, "<tr><td>%s:</td><td>%s%d%s</td>",
          _("User ID"), ps1, info.team, ps2);
  if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><input type=\"text\" name=\"run_user_id\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.team, ACTION_RUN_CHANGE_USER_ID, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("User login"), teamdb_get_login(serve_state.teamdb_state, info.team));
  if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><input type=\"text\" name=\"run_user_login\" value=\"%s\" size=\"20\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", teamdb_get_login(serve_state.teamdb_state, info.team), ACTION_RUN_CHANGE_USER_LOGIN, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("User name"), teamdb_get_name(serve_state.teamdb_state, info.team), nbsp);

  ps1 = ""; ps2 = "";
  snprintf(filtbuf1, sizeof(filtbuf1), "prob == \"%s\"", 
           serve_state.probs[info.problem]->short_name);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                extra_args, "filter_expr=%s&filter_view=View",
                filtbuf2);
  ps1 = filtbuf3; ps2 = "</a>";
  fprintf(f, "<tr><td>%s:</td><td>%s%s%s</td>",
          _("Problem"), ps1, serve_state.probs[info.problem]->short_name, ps2);
  if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><select name=\"problem\"><option value=\"\">\n");
    for (i = 1; i <= serve_state.max_prob; i++)
      if (serve_state.probs[i]) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                serve_state.probs[i]->id, serve_state.probs[i]->short_name, serve_state.probs[i]->long_name);
      }
    fprintf(f, "</select></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_PROB, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  if (serve_state.probs[info.problem]->variant_num > 0) {
    variant = info.variant;
    if (!variant) {
      variant = find_variant(info.team, info.problem);
    }
    ps1 = ""; ps2 = "";
    snprintf(filtbuf1, sizeof(filtbuf1), "prob == \"%s\" && variant == %d", 
             serve_state.probs[info.problem]->short_name, variant);
    url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
    html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                  extra_args, "filter_expr=%s&filter_view=View",
                  filtbuf2);
    ps1 = filtbuf3; ps2 = "</a>";
    fprintf(f, "<tr><td>%s:</td>", _("Variant"));
    if (info.variant > 0) {
      fprintf(f, "<td>%s%d%s</td>", ps1, info.variant, ps2);
    } else {
      fprintf(f, "<td>%s%d (implicit)%s</td>", ps1, variant, ps2);
    }
    if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f,"<input type=\"hidden\" name=\"run_id\" value=\"%d\">",run_id);
      fprintf(f, "<td><input type=\"text\" name=\"variant\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.variant, ACTION_RUN_CHANGE_VARIANT, _("Change"));
    } else {
      fprintf(f, "%s", nbsp);
    }
    fprintf(f, "</tr>\n");
  }

  ps1 = ""; ps2 = "";
  if (serve_state.langs[info.language]) {
    snprintf(filtbuf1, sizeof(filtbuf1), "lang == \"%s\"", 
             serve_state.langs[info.language]->short_name);
    url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
    html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                  extra_args, "filter_expr=%s&filter_view=View",
                  filtbuf2);
    ps1 = filtbuf3; ps2 = "</a>";
  }
  fprintf(f, "<tr><td>%s:</td><td>%s%s%s</td>",
          _("Language"), ps1,
          (serve_state.langs[info.language])?((char*)serve_state.langs[info.language]->short_name):"",
          ps2);
  if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><select name=\"language\"><option value=\"\">\n");
    for (i = 1; i <= serve_state.max_lang; i++)
      if (serve_state.langs[i]) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                serve_state.langs[i]->id, serve_state.langs[i]->short_name, serve_state.langs[i]->long_name);
      }
    fprintf(f, "</select></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_LANG, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Imported?"), info.is_imported?_("Yes"):_("No"));
  if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><select name=\"is_imported\">\n");
    fprintf(f, "<option value=\"0\"%s>%s\n",
            info.is_imported?"":" selected=\"1\"", _("No"));
    fprintf(f, "<option value=\"1\"%s>%s\n",
            info.is_imported?" selected=\"1\"":"", _("Yes"));
    fprintf(f, "</select></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_IMPORTED, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Hidden?"), info.is_hidden?_("Yes"):_("No"));
  if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><select name=\"is_hidden\">\n");
    fprintf(f, "<option value=\"0\"%s>%s\n",
            info.is_hidden?"":" selected=\"1\"", _("No"));
    fprintf(f, "<option value=\"1\"%s>%s\n",
            info.is_hidden?" selected=\"1\"":"", _("Yes"));
    fprintf(f, "</select></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_HIDDEN, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Read-only?"), info.is_readonly?_("Yes"):_("No"));
  if (priv_level == PRIV_LEVEL_ADMIN) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><select name=\"is_readonly\">\n");
    fprintf(f, "<option value=\"0\"%s>%s\n",
            info.is_readonly?"":" selected=\"1\"", _("No"));
    fprintf(f, "<option value=\"1\"%s>%s\n",
            info.is_readonly?" selected=\"1\"":"", _("Yes"));
    fprintf(f, "</select></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_READONLY, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Locale ID"), info.locale_id, nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Status"), run_status_str(info.status, 0, 0));
  if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    write_change_status_dialog(f, 0, info.is_imported, accepting_mode);
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_STATUS, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  if (serve_state.global->score_system_val == SCORE_KIROV
      || serve_state.global->score_system_val == SCORE_OLYMPIAD) {
    if (info.test <= 0) {
      snprintf(numbuf, sizeof(numbuf), "N/A");
      info.test = 0;
    } else {
      snprintf(numbuf, sizeof(numbuf), "%d", info.test - 1);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Tests passed"), numbuf);
    if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f,"<input type=\"hidden\" name=\"run_id\" value=\"%d\">",run_id);
      fprintf(f, "<td><input type=\"text\" name=\"tests\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.test - 1, ACTION_RUN_CHANGE_TESTS, _("Change"));
    } else {
      fprintf(f, "%s", nbsp);
    }
    fprintf(f, "</tr>\n");

    if (info.score < 0) {
      snprintf(numbuf, sizeof(numbuf), "N/A");
      info.score = -1;
    } else {
      snprintf(numbuf, sizeof(numbuf), "%d", info.score);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Score gained"), numbuf);
    if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f,"<input type=\"hidden\" name=\"run_id\" value=\"%d\">",run_id);
      fprintf(f, "<td><input type=\"text\" name=\"score\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.score, ACTION_RUN_CHANGE_SCORE, _("Change"));
    } else {
      fprintf(f, "%s", nbsp);
    }
    fprintf(f, "</tr>\n");

    snprintf(numbuf, sizeof(numbuf), "%d", info.score_adj);
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Score adjustment"), numbuf);
    if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f,"<input type=\"hidden\" name=\"run_id\" value=\"%d\">",run_id);
      fprintf(f, "<td><input type=\"text\" name=\"score_adj\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.score_adj, ACTION_RUN_CHANGE_SCORE_ADJ, _("Change"));
    } else {
      fprintf(f, "%s", nbsp);
    }
    fprintf(f, "</tr>\n");
  } else if (serve_state.global->score_system_val == SCORE_MOSCOW) {
    if (info.test <= 0) {
      snprintf(numbuf, sizeof(numbuf), "N/A");
      info.test = 0;
    } else {
      snprintf(numbuf, sizeof(numbuf), "%d", info.test);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Failed test"), numbuf);
    if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f,"<input type=\"hidden\" name=\"run_id\" value=\"%d\">",run_id);
      fprintf(f, "<td><input type=\"text\" name=\"tests\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.test - 1, ACTION_RUN_CHANGE_TESTS, _("Change"));
    } else {
      fprintf(f, "%s", nbsp);
    }
    fprintf(f, "</tr>\n");

    if (info.score < 0) {
      snprintf(numbuf, sizeof(numbuf), "N/A");
      info.score = -1;
    } else {
      snprintf(numbuf, sizeof(numbuf), "%d", info.score);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Score gained"), numbuf);
    if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f,"<input type=\"hidden\" name=\"run_id\" value=\"%d\">",run_id);
      fprintf(f, "<td><input type=\"text\" name=\"score\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.score, ACTION_RUN_CHANGE_SCORE, _("Change"));
    } else {
      fprintf(f, "%s", nbsp);
    }
    fprintf(f, "</tr>\n");

    snprintf(numbuf, sizeof(numbuf), "%d", info.score_adj);
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Score adjustment"), numbuf);
    if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f,"<input type=\"hidden\" name=\"run_id\" value=\"%d\">",run_id);
      fprintf(f, "<td><input type=\"text\" name=\"score_adj\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.score_adj, ACTION_RUN_CHANGE_SCORE_ADJ, _("Change"));
    } else {
      fprintf(f, "%s", nbsp);
    }
    fprintf(f, "</tr>\n");




  } else {
    // ACM scoring system
    if (info.test <= 0) {
      snprintf(numbuf, sizeof(numbuf), "N/A");
      info.test = 0;
    } else {
      snprintf(numbuf, sizeof(numbuf), "%d", info.test);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Failed test"), numbuf);
    if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f,"<input type=\"hidden\" name=\"run_id\" value=\"%d\">",run_id);
      fprintf(f, "<td><input type=\"text\" name=\"tests\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.test, ACTION_RUN_CHANGE_TESTS, _("Change"));
    } else {
      fprintf(f, "%s", nbsp);
    }
    fprintf(f, "</tr>\n");
  }

  fprintf(f, "<tr><td>%s:</td><td>%d</td>",
          _("Pages printed"), info.pages);
  if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><input type=\"text\" name=\"pages\" value=\"%d\" size=\"10\"></td>", info.pages);
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_PAGES, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  fprintf(f, "</table>\n");

  html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                extra_args, "action=%d&run_id=%d",
                ACTION_PRIV_DOWNLOAD_RUN, run_id);
  fprintf(f, "<p>%sDownload run</a>.</p>\n", filtbuf3);

  if (priv_level == PRIV_LEVEL_ADMIN && !info.is_readonly) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<p><input type=\"submit\" name=\"action_%d\" value=\"%s\"></p></form>\n", ACTION_CLEAR_RUN, _("Clear this entry"));
  }

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
  fprintf(f, "<p><input type=\"submit\" name=\"action_%d\" value=\"%s\"></p></form>\n", ACTION_PRINT_PRIV_RUN, _("Print"));

  filtbuf1[0] = 0;
  if (run_id > 0) {
    run_id2 = run_find(serve_state.runlog_state, run_id - 1, 0, info.team, info.problem,
                       info.language);
    if (run_id2 >= 0) {
      snprintf(filtbuf1, sizeof(filtbuf1), "%d", run_id2);
    }
  }
  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
  fprintf(f, "<p>%s: <input type=\"text\" name=\"run_id2\" value=\"%s\" size=\"10\"><input type=\"submit\" name=\"action_%d\" value=\"%s\"></form>\n",
          _("Compare this run with run"), filtbuf1,
          ACTION_COMPARE_RUNS, _("Compare"));

  if (serve_state.global->enable_report_upload) {
    html_start_form(f, 2, self_url, hidden_vars);
    fprintf(f, "<p>%s: ", _("Upload judging protocol"));
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<input type=\"file\" name=\"file\">");
    if (serve_state.global->team_enable_rep_view) {
      fprintf(f, "<input type=\"checkbox\" %s%s>%s",
              "name=\"judge_report\"", "checked=\"yes\"",
              _("Judge's report"));
      fprintf(f, "<input type=\"checkbox\" %s%s>%s",
              "name=\"user_report\"", "checked=\"yes\"",
              _("User's report"));
    }
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_UPLOAD_REPORT, _("Upload!"));
    fprintf(f, "</form>\n");
  }

  print_nav_buttons(f, run_id, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, _("Refresh"), _("View report"),
                    _("View team report"));
  fprintf(f, "<hr>\n");
  if (info.language > 0 && info.language <= serve_state.max_lang
      && serve_state.langs[info.language] && serve_state.langs[info.language]->binary) {
    fprintf(f, "<p>The submission is binary and thus is not shown.</p>\n");
  } else if (!info.is_imported) {
    if (src_flags < 0 || generic_read_file(&src_text, 0, &src_len, src_flags, 0, src_path, "") < 0) {
      fprintf(f, "<big><font color=\"red\">Cannot read source text!</font></big>\n");
    } else {
      numb_txt = "";
      if ((numb_len = text_numbered_memlen(src_text, src_len))) {
        numb_txt = alloca(numb_len + 1);
        text_number_lines(src_text, src_len, numb_txt);
      }

      html_len = html_armored_memlen(numb_txt, numb_len);
      html_text = alloca(html_len + 16);
      html_armor_text(numb_txt, numb_len, html_text);
      html_text[html_len] = 0;
      fprintf(f, "<pre>%s</pre>", html_text);
      xfree(src_text);
    }
    fprintf(f, "<hr>\n");
    print_nav_buttons(f, run_id, sid, self_url, hidden_vars, extra_args,
                      _("Main page"), 0, 0, 0, _("Refresh"), _("View report"),
                      _("View team report"));
  }
  return 0;
}

int
write_new_run_form(FILE *f, int user_id, int priv_level,
                   ej_cookie_t sid,
                   unsigned char const *self_url,
                   unsigned char const *hidden_vars,
                   unsigned char const *extra_args,
                   int run_id,
                   const opcap_t *pcaps)
{
  int i;

  fprintf(f, "<h2>%s</h2>\n", _("Add new run form"));

  print_nav_buttons(f, run_id, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, _("Refresh"), 0, 0);

  html_start_form(f, 1, self_url, hidden_vars);
  fprintf(f, "<table>\n");

  fprintf(f, "<tr><td>%s:</td>", _("User ID"));
  fprintf(f, "<td><input type=\"text\" name=\"run_user_id\" size=\"10\"></td>");
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td>", _("User login"));
  fprintf(f, "<td><input type=\"text\" name=\"run_user_login\" size=\"20\"></td>");
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td>", _("Problem"));
  fprintf(f, "<td><select name=\"problem\"><option value=\"\">\n");
  for (i = 1; i <= serve_state.max_prob; i++)
    if (serve_state.probs[i]) {
      fprintf(f, "<option value=\"%d\">%s - %s\n",
              serve_state.probs[i]->id, serve_state.probs[i]->short_name, serve_state.probs[i]->long_name);
    }
  fprintf(f, "</select></td>\n");
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td>", _("Variant"));
  fprintf(f, "<td><input type=\"text\" name=\"variant\" size=\"10\"></td>");
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td>", _("Language"));
  fprintf(f, "<td><select name=\"language\"><option value=\"\">\n");
  for (i = 1; i <= serve_state.max_lang; i++)
    if (serve_state.langs[i]) {
      fprintf(f, "<option value=\"%d\">%s - %s\n",
              serve_state.langs[i]->id, serve_state.langs[i]->short_name, serve_state.langs[i]->long_name);
    }
  fprintf(f, "</select></td>\n");
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td>", _("Imported?"));
  fprintf(f, "<td><select name=\"is_imported\">\n");
  fprintf(f, "<option value=\"0\">%s\n", _("No"));
  fprintf(f, "<option value=\"1\">%s\n", _("Yes"));
  fprintf(f, "</select></td>\n");
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td>", _("Hidden?"));
  fprintf(f, "<td><select name=\"is_hidden\">\n");
  fprintf(f, "<option value=\"0\">%s\n", _("No"));
  fprintf(f, "<option value=\"1\">%s\n", _("Yes"));
  fprintf(f, "</select></td>\n");
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td>", _("Read-only?"));
  fprintf(f, "<td><select name=\"is_readonly\">\n");
  fprintf(f, "<option value=\"0\">%s\n", _("No"));
  fprintf(f, "<option value=\"1\">%s\n", _("Yes"));
  fprintf(f, "</select></td>\n");
  fprintf(f, "</tr>\n");

  fprintf(f, "<tr><td>%s:</td>", _("Status"));
  write_change_status_dialog(f, 0, 0, 0);
  fprintf(f, "</tr>\n");

  if (serve_state.global->score_system_val == SCORE_KIROV
      || serve_state.global->score_system_val == SCORE_OLYMPIAD) {
    fprintf(f, "<tr><td>%s:</td>", _("Tests passed"));
    fprintf(f, "<td><input type=\"text\" name=\"tests\" size=\"10\"></td>");
    fprintf(f, "</tr>\n");

    fprintf(f, "<tr><td>%s:</td>", _("Score gained"));
    fprintf(f, "<td><input type=\"text\" name=\"score\" size=\"10\"></td>");
    fprintf(f, "</tr>\n");
  } else if (serve_state.global->score_system_val == SCORE_MOSCOW) {
    fprintf(f, "<tr><td>%s:</td>", _("Failed test"));
    fprintf(f, "<td><input type=\"text\" name=\"tests\" size=\"10\"></td>");
    fprintf(f, "</tr>\n");

    fprintf(f, "<tr><td>%s:</td>", _("Score gained"));
    fprintf(f, "<td><input type=\"text\" name=\"score\" size=\"10\"></td>");
    fprintf(f, "</tr>\n");
  } else {
    fprintf(f, "<tr><td>%s:</td>", _("Failed test"));
    fprintf(f, "<td><input type=\"text\" name=\"tests\" size=\"10\"></td>");
    fprintf(f, "</tr>\n");
  }

  fprintf(f, "<tr><td>%s:</td>"
          "<td><input type=\"file\" name=\"file\"></td></tr>\n",
          _("File"));

  fprintf(f, "<tr><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr>\n", ACTION_NEW_RUN, _("Submit"));
  fprintf(f, "</table></form>\n");

  print_nav_buttons(f, run_id, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, _("Refresh"), 0, 0);

  return 0;
}

int
write_xml_testing_report(FILE *f, unsigned char const *txt,
                         ej_cookie_t sid,
                         unsigned char const *self_url,
                         unsigned char const *extra_args)
{
  testing_report_xml_t r = 0;
  unsigned char *s = 0;
  unsigned char *font_color = 0;
  int i, is_kirov = 0, need_comment = 0;
  struct testing_report_test *t;
  unsigned char opening_a[512];
  unsigned char *closing_a = "";

  if (!(r = testing_report_parse_xml(txt))) {
    fprintf(f, "<p><big>Cannot parse XML file!</big></p>\n");
    s = html_armor_string_dup(txt);
    fprintf(f, "<pre>%s</pre>\n", s);
    xfree(s);
    return 0;
  }

  // report the testing status
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
    if (t->comment || t->team_comment) {
      need_comment = 1;
      break;
    }
  }

  fprintf(f,
          "<table border=\"1\">"
          "<tr><th>N</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>",
          _("Result"), _("Time (sec)"), _("Real time (sec)"), _("Extra info"));
  if (is_kirov) {
    fprintf(f, "<th>%s</th>", _("Score"));
  }
  if (need_comment) {
    fprintf(f, "<th>%s</th>", _("Comment"));
  }
  fprintf(f, "<th>%s</th>", _("Link"));
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
    // extra information
    fprintf(f, "<td>");
    switch (t->status) {
    case RUN_OK:
    case RUN_ACCEPTED:
      if (t->checker_comment) {
        s = html_armor_string_dup(t->checker_comment);
        fprintf(f, "%s", s);
        xfree(s);
      } else {
        fprintf(f, "&nbsp;");
      }
      break;

    case RUN_RUN_TIME_ERR:
      if (t->term_signal >= 0) {
        fprintf(f, "%s %d (%s)", _("Signal"), t->term_signal,
                os_GetSignalString(t->term_signal));
      } else {
        fprintf(f, "%s %d", _("Exit code"), t->exit_code);
      }
      break;

    case RUN_TIME_LIMIT_ERR:
      fprintf(f, "&nbsp;");
      break;

    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
      if (t->checker_comment) {
        s = html_armor_string_dup(t->checker_comment);
        fprintf(f, "%s", s);
        xfree(s);
      } else {
        fprintf(f, "&nbsp;");
      }
      break;

    case RUN_CHECK_FAILED: /* what to print here? */
      fprintf(f, "&nbsp;");
      break;

    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
      fprintf(f, "&nbsp;");
      break;

    default:
      fprintf(f, "&nbsp;");
    }
    fprintf(f, "</td>");
    if (is_kirov) {
      fprintf(f, "<td>%d (%d)</td>", t->score, t->nominal_score);
    }
    if (need_comment) {
      if (t->comment) {
        s = html_armor_string_dup(t->comment);
        fprintf(f, "<td>%s</td>", s);
        xfree(s);
      } else if (t->team_comment) {
        s = html_armor_string_dup(t->team_comment);
        fprintf(f, "<td>%s</td>", s);
        xfree(s);
      } else {
        fprintf(f, "<td>&nbsp;</td>");
      }
    }
    // links to extra information
    fprintf(f, "<td>");
    // command line parameters (always inline)
    if (t->args || t->args_too_long) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dL\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "%sL%s", opening_a, closing_a);
    // test input
    if (r->archive_available) {
      html_hyperref(opening_a, sizeof(opening_a), sid, self_url, extra_args,
                    "action=%d&run_id=%d&test_num=%d",
                    ACTION_VIEW_TEST_INPUT, r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->input) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dI\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sI%s", opening_a, closing_a);
    // program output
    if (r->archive_available && t->output_available) {
      html_hyperref(opening_a, sizeof(opening_a), sid, self_url, extra_args,
                    "action=%d&run_id=%d&test_num=%d",
                    ACTION_VIEW_TEST_OUTPUT, r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->output) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dO\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sO%s", opening_a, closing_a);
    // correct output (answer)
    if (r->archive_available && r->correct_available) {
      html_hyperref(opening_a, sizeof(opening_a), sid, self_url, extra_args,
                    "action=%d&run_id=%d&test_num=%d",
                    ACTION_VIEW_TEST_ANSWER, r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->correct) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dA\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sA%s", opening_a, closing_a);
    // program stderr
    if (r->archive_available && t->stderr_available) {
      html_hyperref(opening_a, sizeof(opening_a), sid, self_url, extra_args,
                    "action=%d&run_id=%d&test_num=%d",
                    ACTION_VIEW_TEST_ERROR, r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->error) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dE\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sE%s", opening_a, closing_a);
    // checker output
    if (r->archive_available && t->checker_output_available) {
      html_hyperref(opening_a, sizeof(opening_a), sid, self_url, extra_args,
                    "action=%d&run_id=%d&test_num=%d",
                    ACTION_VIEW_TEST_CHECKER, r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->checker) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dC\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sC%s", opening_a, closing_a);
    // test info file
    if (r->archive_available && r->info_available) {
      html_hyperref(opening_a, sizeof(opening_a), sid, self_url, extra_args,
                    "action=%d&run_id=%d&test_num=%d",
                    ACTION_VIEW_TEST_INFO, r->run_id, t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sF%s", opening_a, closing_a);
    fprintf(f, "</td>");
    fprintf(f, "</tr>\n");
  }
  fprintf(f, "</table>\n");

  fprintf(f,
          "<br><table><font size=\"-2\">\n"
          "<tr><td>L</td><td>%s</td></tr>\n"
          "<tr><td>I</td><td>%s</td></tr>\n"
          "<tr><td>O</td><td>%s</td></tr>\n"
          "<tr><td>A</td><td>%s</td></tr>\n"
          "<tr><td>E</td><td>%s</td></tr>\n"
          "<tr><td>C</td><td>%s</td></tr>\n"
          "<tr><td>F</td><td>%s</td></tr>\n"
          "</font></table>\n",
          _("Command-line parameters"),
          _("Test input"),
          _("Program output"),
          _("Correct output"),
          _("Program output to stderr"),
          _("Checker output"),
          _("Additional test information"));


  // print detailed test information
  fprintf(f, "<pre>");
  for (i = 0; i < r->run_tests; i++) {
    if (!(t = r->tests[i])) continue;
    if (!t->args && !t->args_too_long && !t->input
        && !t->output && !t->error && !t->correct && !t->checker) continue;

    fprintf(f, _("<b>====== Test #%d =======</b>\n"), t->num);
    if (t->args || t->args_too_long) {
      fprintf(f, "<a name=\"%dL\"></a>", t->num);
      fprintf(f, _("<u>--- Command line arguments ---</u>\n"));
      if (t->args_too_long) {
        fprintf(f, _("<i>Command line is too long</i>\n"));
      } else {
        s = html_armor_string_dup(t->args);
        fprintf(f, "%s", s);
        xfree(s);
      }
    }
    if (t->input) {
      fprintf(f, "<a name=\"%dI\"></a>", t->num);
      fprintf(f, _("<u>--- Input ---</u>\n"));
      s = html_armor_string_dup(t->input);
      fprintf(f, "%s", s);
      xfree(s);
    }
    if (t->output) {
      fprintf(f, "<a name=\"%dO\"></a>", t->num);
      fprintf(f, _("<u>--- Output ---</u>\n"));
      s = html_armor_string_dup(t->output);
      fprintf(f, "%s", s);
      xfree(s);
    }
    if (t->correct) {
      fprintf(f, "<a name=\"%dA\"></a>", t->num);
      fprintf(f, _("<u>--- Correct ---</u>\n"));
      s = html_armor_string_dup(t->correct);
      fprintf(f, "%s", s);
      xfree(s);
    }
    if (t->error) {
      fprintf(f, "<a name=\"%dE\"></a>", t->num);
      fprintf(f, _("<u>--- Stderr ---</u>\n"));
      s = html_armor_string_dup(t->error);
      fprintf(f, "%s", s);
      xfree(s);
    }
    if (t->checker) {
      fprintf(f, "<a name=\"%dC\"></a>", t->num);
      fprintf(f, _("<u>--- Checker output ---</u>\n"));
      s = html_armor_string_dup(t->checker);
      fprintf(f, "%s", s);
      xfree(s);
    }
  }
  fprintf(f, "</pre>");

  return 0;
}

int
write_priv_report(FILE *f, int user_id, int priv_level,
                  ej_cookie_t sid,
                  int team_report_flag,
                  unsigned char const *self_url,
                  unsigned char const *hidden_vars,
                  unsigned char const *extra_args,
                  int run_id, const opcap_t *pcaps)
{
  path_t rep_path;
  char *rep_text = 0, *html_text;
  size_t rep_len = 0, html_len;
  int rep_flag, content_type;
  const unsigned char *t6 = _("Refresh");
  const unsigned char *t7 = _("View team report");
  const unsigned char *report_dir = serve_state.global->report_archive_dir;
  const unsigned char *start_ptr = 0;
  struct run_entry re;

  if (team_report_flag && serve_state.global->team_enable_rep_view) {
    t7 = t6;
    t6 = _("View report");
    report_dir = serve_state.global->team_report_archive_dir;
    if (serve_state.global->team_show_judge_report) {
      report_dir = serve_state.global->report_archive_dir;
    }
  }

  if (run_id < 0 || run_id >= run_get_total(serve_state.runlog_state))
    return -SRV_ERR_BAD_RUN_ID;
  if (run_get_entry(serve_state.runlog_state, run_id, &re) < 0) return -SRV_ERR_BAD_RUN_ID;
  if (!run_is_report_available(re.status)) return -SRV_ERR_REPORT_NOT_AVAILABLE;

  print_nav_buttons(f, run_id, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, _("View source"), t6, t7);
  fprintf(f, "<hr>\n");

  rep_flag = archive_make_read_path(rep_path, sizeof(rep_path),
                                    serve_state.global->xml_report_archive_dir, run_id, 0, 1);
  if (rep_flag >= 0) {
    if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0) < 0)
      return -SRV_ERR_SYSTEM_ERROR;
    content_type = get_content_type(rep_text, &start_ptr);
  } else {
    rep_flag = archive_make_read_path(rep_path, sizeof(rep_path),
                                      report_dir, run_id, 0, 1);
    if (rep_flag < 0) return -SRV_ERR_FILE_NOT_EXIST;
    if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0) < 0)
      return -SRV_ERR_SYSTEM_ERROR;
    content_type = get_content_type(rep_text, &start_ptr);
  }

  switch (content_type) {
  case CONTENT_TYPE_TEXT:
    html_len = html_armored_memlen(start_ptr, rep_len);
    html_text = alloca(html_len + 16);
    html_armor_text(rep_text, rep_len, html_text);
    html_text[html_len] = 0;
    fprintf(f, "<pre>%s</pre>", html_text);
    break;
  case CONTENT_TYPE_HTML:
    fprintf(f, "%s", start_ptr);
    break;
  case CONTENT_TYPE_XML:
    if (team_report_flag) {
      write_xml_team_testing_report(f, start_ptr);
    } else {
      write_xml_testing_report(f, start_ptr, sid, self_url, extra_args);
    }
    break;
  default:
    abort();
  }

  xfree(rep_text);
  fprintf(f, "<hr>\n");
  print_nav_buttons(f, run_id, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, _("View source"), t6, t7);
  return 0;
}

int
write_priv_clar(FILE *f, int user_id, int priv_level,
                ej_cookie_t sid,
                unsigned char const *self_url,
                unsigned char const *hidden_vars,
                unsigned char const *extra_args,
                int clar_id, const opcap_t *pcaps)
{
  time_t clar_time, start_time;
  size_t size, txt_subj_len, html_subj_len, txt_msg_len = 0, html_msg_len;
  int from, to, flags, j_from, hide_flag;
  unsigned char ip[CLAR_MAX_IP_LEN + 16];
  unsigned char b64_subj[CLAR_MAX_SUBJ_LEN + 16];
  unsigned char txt_subj[CLAR_MAX_SUBJ_LEN + 16];
  unsigned char *html_subj, *txt_msg = 0, *html_msg;
  unsigned char name_buf[64];
  char *tmp_txt_msg = 0;

  if (clar_id < 0 || clar_id >= clar_get_total(serve_state.clarlog_state))
    return -SRV_ERR_BAD_CLAR_ID;

  start_time = run_get_start_time(serve_state.runlog_state);
  clar_get_record(serve_state.clarlog_state, clar_id, &clar_time, &size, ip, &from, &to,
                  &flags, &j_from, &hide_flag, b64_subj);
  txt_subj_len = base64_decode_str(b64_subj, txt_subj, 0);
  html_subj_len = html_armored_strlen(txt_subj);
  html_subj = alloca(html_subj_len);
  html_armor_string(txt_subj, html_subj);

  fprintf(f, "<h2>%s %d</h2>\n", _("Message"), clar_id);
  fprintf(f, "<table border=\"0\">\n");
  fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>\n", _("Clar ID"), clar_id);
  if (hide_flag)
    fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Available only after contest start"), hide_flag?_("YES"):_("NO"));
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Flags"),
          clar_flags_html(serve_state.clarlog_state, flags, from, to, 0, 0));
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
          _("Time"), duration_str(1, clar_time, 0, 0, 0));
  if (!serve_state.global->virtual) {
    fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Duration"), duration_str(0, clar_time, start_time, 0, 0));
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("IP address"), ip);
  fprintf(f, "<tr><td>%s:</td><td>%zu</td></tr>\n", _("Size"), size);
  fprintf(f, "<tr><td>%s:</td>", _("Sender"));
  if (!from) {
    if (!j_from)
      fprintf(f, "<td><b>%s</b></td>", _("judges"));
    else
      fprintf(f, "<td><b>%s</b> (%s)</td>", _("judges"),
              teamdb_get_name(serve_state.teamdb_state, j_from));
  } else {
    fprintf(f, "<td>%s (%d)</td>", teamdb_get_name(serve_state.teamdb_state, from), from);
  }
  fprintf(f, "</tr>\n<tr><td>%s:</td>", _("To"));
  if (!to && !from) {
    fprintf(f, "<td><b>%s</b></td>", _("all"));
  } else if (!to) {
    fprintf(f, "<td><b>%s</b></td>", _("judges"));
  } else {
    fprintf(f, "<td>%s (%d)</td>", teamdb_get_name(serve_state.teamdb_state, to), to);
  }
  fprintf(f, "</tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>", _("Subject"), html_subj);
  fprintf(f, "</table>\n");
  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, 0, 0, 0);
  fprintf(f, "<hr>\n");

  snprintf(name_buf, sizeof(name_buf), "%06d", clar_id);
  if (generic_read_file(&tmp_txt_msg, 0, &txt_msg_len, 0,
                        serve_state.global->clar_archive_dir, name_buf, "") < 0) {
    fprintf(f, "<big><font color=\"red\">Cannot read message text!</font></big>\n");
  } else {
    txt_msg = tmp_txt_msg;
    txt_msg[txt_msg_len] = 0;
    html_msg_len = html_armored_strlen(txt_msg);
    html_msg = alloca(html_msg_len + 16);
    html_armor_string(txt_msg, html_msg);
    fprintf(f, "<pre>%s</pre><hr>", html_msg);
  }

  if (priv_level >= PRIV_LEVEL_JUDGE && from) {
    html_start_form(f, 2, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"in_reply_to\" value=\"%d\">\n",
            clar_id);
    fprintf(f, "<p><input type=\"submit\" name=\"answ_read\" value=\"%s\">\n",
            _("Answer: Read the problem"));
    fprintf(f, "<input type=\"submit\" name=\"answ_no_comments\" value=\"%s\"><input type=\"submit\" name=\"answ_yes\" value=\"%s\"><input type=\"submit\" name=\"answ_no\" value=\"%s\"></p>\n",
           _("Answer: No comments"), _("Answer: YES"), _("Answer: NO"));
    fprintf(f, "<p><textarea name=\"reply\" rows=\"20\" cols=\"60\"></textarea></p>\n");
    fprintf(f, "<p><input type=\"submit\" name=\"answ_text\" value=\"%s\">"
           "<input type=\"submit\" name=\"answ_all\" value=\"%s\"></p>\n",
           _("Send to sender"), _("Send to all"));
    fprintf(f, "</form>\n");
  }
  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, 0, 0, 0);

  return 0;
}

int
write_priv_users(FILE *f, int user_id, int priv_level,
                 ej_cookie_t sid,
                 unsigned char const *self_url,
                 unsigned char const *hidden_vars,
                 unsigned char const *extra_args,
                 const opcap_t *pcaps)
{
  int tot_teams, i, max_team, flags, runs_num = 0, clars_num = 0;
  unsigned char const *txt_login, *txt_name;
  unsigned char *html_login, *html_name;
  size_t html_login_len, html_name_len, runs_total = 0, clars_total = 0;
  unsigned char href_buf[128];
  struct teamdb_export info;
  unsigned char team_modes[128];
  unsigned char filtbuf1[512], filtbuf2[512], filtbuf3[512], *ps1, *ps2;
  const struct team_extra *t_extra;

  tot_teams = teamdb_get_total_teams(serve_state.teamdb_state);
  max_team = teamdb_get_max_team_id(serve_state.teamdb_state);

  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, _("Refresh"), 0, 0, 0, 0);
  fprintf(f, "<hr/><p><big>Total teams: %d</big></p>\n", tot_teams);
  fprintf(f,
          "<table border=\"1\">"
          "<tr>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>",
          _("User ID"),
          _("User login"),
          _("E-mail"),
          _("User name"),
          _("Flags"),
          _("No. of runs"), _("Size of runs"),
          _("No. of clars"), _("Size of clars"));
  if (serve_state.global->contestant_status_num > 0) {
    fprintf(f, "<th>%s</th>", _("Status"));
  }
  fprintf(f, "<th>%s</th><th>&nbsp;</th></tr>\n", _("No. of warns"));

  for (i = 1; i <= max_team; i++) {
    if (!teamdb_lookup(serve_state.teamdb_state, i)) continue;
    teamdb_export_team(serve_state.teamdb_state, i, &info);
    t_extra = team_extra_get_entry(serve_state.team_extra_state, i);

    run_get_team_usage(serve_state.runlog_state, i, &runs_num, &runs_total);
    clar_get_team_usage(serve_state.clarlog_state, i, &clars_num, &clars_total);
    /*
    if (priv_level == PRIV_LEVEL_ADMIN) {
      html_start_form(f, 1, sid, self_url, hidden_vars, extra_args);
      fprintf(f, "<input type=\"hidden\" name=\"user_id\" value=\"%d\">", i);
    }
    */
    fprintf(f, "<tr>");


    ps1 = ""; ps2 = "";
    snprintf(filtbuf1, sizeof(filtbuf1), "uid == %d", i);
    url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
    html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                  extra_args, "filter_expr=%s&filter_view=View",
                  filtbuf2);
    ps1 = filtbuf3; ps2 = "</a>";
    fprintf(f, "<td>%s%d%s</td>", ps1, i, ps2);

    txt_login = teamdb_get_login(serve_state.teamdb_state, i);
    html_login_len = html_armored_strlen(txt_login);
    html_login = alloca(html_login_len + 16);
    html_armor_string(txt_login, html_login);
    fprintf(f, "<td>");
    if (serve_state.global->team_info_url[0]) {
      sformat_message(href_buf, sizeof(href_buf), serve_state.global->team_info_url,
                      NULL, NULL, NULL, NULL, &info, 0, 0, 0);
      fprintf(f, "<a href=\"%s\">", href_buf);
    }
    fprintf(f, "%s", html_login);
    if (serve_state.global->team_info_url[0]) {
      fprintf(f, "</a>");
    }
    fprintf(f, "</td>");

    txt_name = teamdb_get_name(serve_state.teamdb_state, i);
    html_name_len = html_armored_strlen(txt_name);
    html_name = alloca(html_name_len + 16);
    html_armor_string(txt_name, html_name);

    // e-mail
    if (info.user && info.user->email) {
      fprintf(f, "<td><a href=\"mailto:%s &lt;%s&gt;\">%s<a></td>",
              html_name, info.user->email, info.user->email);
    } else {
      fprintf(f, "<td>&nbsp;</td>");
    }

    fprintf(f, "<td>%s</td>", html_name);

    flags = teamdb_get_flags(serve_state.teamdb_state, i);
    team_modes[0] = 0;
    if ((flags & TEAM_BANNED)) {
      strcpy(team_modes, "banned");
    }
    if ((flags & TEAM_INVISIBLE)) {
      if (team_modes[0]) strcat(team_modes, ",");
      strcat(team_modes, "invisible");
    }
    if ((flags & TEAM_LOCKED)) {
      if (team_modes[0]) strcat(team_modes, ",");
      strcat(team_modes, "locked");
    }
    if (!team_modes[0]) {
      strcpy(team_modes, "&nbsp;");
    }
    fprintf(f, "<td>%s</td>", team_modes);

    fprintf(f,
            "<td>%d</td>"
            "<td>%zu</td>"
            "<td>%d</td>"
            "<td>%zu</td>",
            runs_num, runs_total, clars_num, clars_total);

    if (t_extra) {
      if (serve_state.global->contestant_status_num > 0) {
        if (t_extra->status < 0 || t_extra->status >= serve_state.global->contestant_status_num) {
          fprintf(f, "<td>%d - ??? </td>", t_extra->status);
        } else {
          fprintf(f, "<td>%d - %s</td>", t_extra->status, serve_state.global->contestant_status_legend[t_extra->status]);
        }
      }
      fprintf(f, "<td>%d</td>", t_extra->warn_u);
    } else {
      if (serve_state.global->contestant_status_num > 0) {
        fprintf(f, "<td>&nbsp;</td>");
      }
      fprintf(f, "<td>&nbsp;</td>");
    }

    ps1 = ""; ps2 = "";
    html_hyperref(filtbuf3, sizeof(filtbuf3), sid, self_url,
                  extra_args, "user_id=%d&action=%d",
                  i, ACTION_VIEW_TEAM);
    ps1 = filtbuf3; ps2 = "</a>";
    fprintf(f, "<td>%s%s%s</td>", ps1, _("View"), ps2);

    /*
    if (priv_level == PRIV_LEVEL_ADMIN) {
      fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_USER_TOGGLE_BAN, (flags & TEAM_BANNED)?_("Unban"):_("Ban"));
    } else {
      fprintf(f, "<td>&nbsp;</td>");
    }

    if (priv_level == PRIV_LEVEL_ADMIN) {
      fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_USER_TOGGLE_VISIBILITY, (flags & TEAM_INVISIBLE)?_("Make visible"):_("Make invisible"));
    } else {
      fprintf(f, "<td>&nbsp;</td>");
    }

    if (priv_level == PRIV_LEVEL_ADMIN) {
      fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_USER_TOGGLE_LOCK, (flags & TEAM_LOCKED)?_("Unlock"):_("Lock"));
    } else {
      fprintf(f, "<td>&nbsp;</td>");
    }
    */

    fprintf(f, "</tr>\n");
    /*
    if (priv_level == PRIV_LEVEL_ADMIN) {
      fprintf(f, "</form>");
    }
    */
  }
  fprintf(f, "</table>\n");

  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, _("Refresh"), 0, 0, 0, 0);
  return 0;
}

int
write_priv_user(FILE *f, int user_id, int priv_level,
                ej_cookie_t sid,
                unsigned char const *self_url,
                unsigned char const *hidden_vars,
                unsigned char const *extra_args,
                int view_user_id,
                const opcap_t *pcaps)
{
  struct teamdb_export info;
  const struct team_extra *t_extra;
  size_t runs_total = 0, clars_total = 0, pages_total = 0;
  int runs_num = 0, clars_num = 0;
  int allowed_edit = 0;
  int flags, needed_cap, init_value, i;
  const struct team_warning *cur_warn;

  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, _("View teams"), 0, 0, 0, 0);
  fprintf(f, "<hr/>\n");

  if (!teamdb_lookup(serve_state.teamdb_state, view_user_id)) {
    fprintf(f, "<big>Invalid user id</big>\n");
    return 0;
  }

  teamdb_export_team(serve_state.teamdb_state, view_user_id, &info);
  t_extra = team_extra_get_entry(serve_state.team_extra_state, view_user_id);
  run_get_team_usage(serve_state.runlog_state, view_user_id, &runs_num, &runs_total);
  clar_get_team_usage(serve_state.clarlog_state, view_user_id, &clars_num, &clars_total);
  pages_total = run_get_total_pages(serve_state.runlog_state, view_user_id);
  flags = teamdb_get_flags(serve_state.teamdb_state, view_user_id);

  // table has 4 columns
  fprintf(f, "<table>\n");

  // user id
  fprintf(f, "<tr><td>%s:</td><td>%d</td><td>&nbsp;</td><td>&nbsp</td></tr>\n",
          _("User Id"), view_user_id);

  // user login
  fprintf(f, "<tr><td>%s:</td>", _("User Login"));
  xml_unparse_text(f, "td", teamdb_get_login(serve_state.teamdb_state, view_user_id), "");
  fprintf(f, "<td>&nbsp;</td><td>&nbsp</td></tr>\n");

  // user name
  fprintf(f, "<tr><td>%s:</td>", _("User Name"));
  xml_unparse_text(f, "td", teamdb_get_name(serve_state.teamdb_state, view_user_id), "");
  fprintf(f, "<td>&nbsp;</td><td>&nbsp</td></tr>\n");

  fprintf(f,"<tr><td>%s:</td><td>%s</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
          _("Privileged?"),
          (info.user && info.user->is_privileged)? _("Yes") : _("No"));

  // last login name
  /*
  s = "Never";
  if (info.user && info.user->last_login_time) {
    s = xml_unparse_date(info.user->last_login_time);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td><td>&nbsp</td></tr>\n",
          _("Last login time"), s);
  */

  // invisible, locked, banned status and change buttons
  // to make invisible EDIT_REG is enough for all users
  // to ban or lock DELETE_PRIV_REG required for privileged users
  allowed_edit = 0;
  if (info.user && opcaps_check(*pcaps, OPCAP_EDIT_REG) >= 0) {
    allowed_edit = 1;
  }
  if (allowed_edit) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"user_id\" value=\"%d\">",
            view_user_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td>",
          _("Invisible?"), (flags & TEAM_INVISIBLE)?_("Yes"):_("No"));
  if(allowed_edit) {
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_USER_TOGGLE_VISIBILITY, (flags & TEAM_INVISIBLE)?_("Make visible"):_("Make invisible"));
  } else {
    fprintf(f, "<td>&nbsp;</td>");
  }
  fprintf(f, "</tr>\n");
  if (allowed_edit) {
    fprintf(f, "</form>");
  }

  allowed_edit = 0;
  if (info.user) {
    if (info.user->is_privileged) {
      if ((flags & TEAM_BANNED)) needed_cap = OPCAP_PRIV_CREATE_REG;
      else needed_cap = OPCAP_PRIV_DELETE_REG;
    } else {
      if ((flags & TEAM_BANNED)) needed_cap = OPCAP_CREATE_REG;
      else needed_cap = OPCAP_DELETE_REG;
    }
    if (opcaps_check(*pcaps, needed_cap) >= 0) allowed_edit = 1;
  }
  if (allowed_edit) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"user_id\" value=\"%d\">",
            view_user_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td>",
          _("Banned?"), (flags & TEAM_BANNED)?_("Yes"):_("No"));
  if(allowed_edit) {
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_USER_TOGGLE_BAN, (flags & TEAM_BANNED)?_("Remove ban"):_("Ban"));
  } else {
    fprintf(f, "<td>&nbsp;</td>");
  }
  fprintf(f, "</tr>\n");
  if (allowed_edit) {
    fprintf(f, "</form>");
  }

  allowed_edit = 0;
  if (info.user) {
    if (info.user->is_privileged) {
      if ((flags & TEAM_LOCKED)) needed_cap = OPCAP_PRIV_CREATE_REG;
      else needed_cap = OPCAP_PRIV_DELETE_REG;
    } else {
      if ((flags & TEAM_LOCKED)) needed_cap = OPCAP_CREATE_REG;
      else needed_cap = OPCAP_DELETE_REG;
    }
    if (opcaps_check(*pcaps, needed_cap) >= 0) allowed_edit = 1;
  }
  if (allowed_edit) {
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"user_id\" value=\"%d\">",
            view_user_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td>",
          _("Locked?"), (flags & TEAM_LOCKED)?_("Yes"):_("No"));
  if(allowed_edit) {
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_USER_TOGGLE_LOCK, (flags & TEAM_LOCKED)?_("Unlock"):_("Lock"));
  } else {
    fprintf(f, "<td>&nbsp;</td>");
  }
  fprintf(f, "</tr>\n");
  if (allowed_edit) {
    fprintf(f, "</form>");
  }

  fprintf(f,"<tr><td>%s:</td><td>%d</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
          _("Number of Runs"), runs_num);
  fprintf(f,"<tr><td>%s:</td><td>%zu</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
          _("Total size of Runs"), runs_total);
  fprintf(f,"<tr><td>%s:</td><td>%d</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
          _("Number of Clars"), clars_num);
  fprintf(f,"<tr><td>%s:</td><td>%zu</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
          _("Total size of Clars"), clars_total);
  fprintf(f,"<tr><td>%s:</td><td>%zu</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
          _("Number of printed pages"), pages_total);

  if (serve_state.global->contestant_status_num > 0) {
    // contestant status is editable when OPCAP_EDIT_REG is set
    allowed_edit = 0;
    if (opcaps_check(*pcaps, OPCAP_EDIT_REG) >= 0) allowed_edit = 1;
    if (allowed_edit) {
      html_start_form(f, 1, self_url, hidden_vars);
      fprintf(f, "<input type=\"hidden\" name=\"user_id\" value=\"%d\">",
              view_user_id);
    }
    fprintf(f, "<tr><td>%s:</td><td>", _("Status"));
    init_value = 0;
    if (!t_extra) {
      fprintf(f, "N/A");
    } else if (t_extra->status < 0 || t_extra->status >= serve_state.global->contestant_status_num) {
      fprintf(f, "%d - ???", t_extra->status);
    } else {
      fprintf(f, "%d - %s", t_extra->status, serve_state.global->contestant_status_legend[t_extra->status]);
      init_value = t_extra->status;
    }
    fprintf(f, "</td>");
    if (allowed_edit) {
      fprintf(f, "<td><select name=\"status\">\n");
      for (i = 0; i < serve_state.global->contestant_status_num; i++) {
        fprintf(f, "<option value=\"%d\"", i);
        if (i == init_value) fprintf(f, " selected=\"1\"");
        fprintf(f, ">%d - %s\n", i, serve_state.global->contestant_status_legend[i]);
      }
      fprintf(f, "</select></td>\n");
      fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>\n", ACTION_CHANGE_CONTESTANT_STATUS, _("Set status"));
    } else {
      fprintf(f, "<td>&nbsp;</td><td>&nbsp;</td>");
    }
    fprintf(f, "</tr>\n");
    if (allowed_edit) {
      fprintf(f, "</form>");
    }
  }
  i = 0;
  if (t_extra) i = t_extra->warn_u;
  fprintf(f,"<tr><td>%s:</td><td>%d</td><td>&nbsp;</td><td>&nbsp;</td></tr>\n",
          _("Number of warnings"), i);

  fprintf(f, "</table>\n");

  print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, _("View teams"), 0, 0, 0, 0);
  fprintf(f, "<hr/>\n");

  if (!t_extra || !t_extra->warn_u) {
    fprintf(f, "<h2>No warnings</h2>\n");
  } else {
    fprintf(f, "<h2>Warnings</h2>\n");
    for (i = 0; i < t_extra->warn_u; i++) {
      if (!(cur_warn = t_extra->warns[i])) continue;
      fprintf(f, "<h3>Warning %d: issued: %s, issued by: %s (%d), issued from: %s</h3>", i + 1, xml_unparse_date(cur_warn->date), teamdb_get_login(serve_state.teamdb_state, cur_warn->issuer_id), cur_warn->issuer_id, xml_unparse_ip(cur_warn->issuer_ip));
      fprintf(f, "<p>User explanation:\n");
      xml_unparse_text(f, "pre", cur_warn->text, "");
      fprintf(f, "<p>Judge's comment:\n");
      xml_unparse_text(f, "pre", cur_warn->comment, "");
    }
  }

  if (opcaps_check(*pcaps, OPCAP_EDIT_REG) >= 0) {
    fprintf(f, "<h2>Issue a warning</h3>\n");
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "<input type=\"hidden\" name=\"user_id\" value=\"%d\">",
            view_user_id);
    fprintf(f, "<p>Warning explanation for the user (mandatory):<br>\n");
    fprintf(f, "<p><textarea name=\"warn_text\" rows=\"5\" cols=\"60\"></textarea></p>\n");
    fprintf(f, "<p>Comment for other judges (optional):<br>\n");
    fprintf(f, "<p><textarea name=\"warn_comment\" rows=\"5\" cols=\"60\"></textarea></p>\n");
    fprintf(f, "<p><input type=\"submit\" name=\"action_%d\" value=\"%s\">\n",
            ACTION_ISSUE_WARNING, _("Issue warning"));
    fprintf(f, "</form>\n");
    
    print_nav_buttons(f, 0, sid, self_url, hidden_vars, extra_args,
                      _("Main page"), 0, _("View teams"), 0, 0, 0, 0);
  }

  return 0;
}

void
html_reset_filter(int user_id, ej_cookie_t session_id)
{
  struct user_filter_info *u = allocate_user_info(user_id, session_id);

  u->prev_first_run = 0;
  u->prev_last_run = 0;
  xfree(u->prev_filter_expr); u->prev_filter_expr = 0;
  xfree(u->error_msgs); u->error_msgs = 0;
  if (u->tree_mem) {
    filter_tree_delete(u->tree_mem);
    u->tree_mem = 0;
  }
  u->prev_tree = 0;
}

void
html_reset_clar_filter(int user_id, ej_cookie_t session_id)
{
  struct user_filter_info *u = allocate_user_info(user_id, session_id);

  u->prev_mode_clar = 0;
  u->prev_first_clar = 0;
  u->prev_last_clar = 0;
}

void
write_runs_dump(FILE *f, const unsigned char *url,
                unsigned char const *charset)
{
  int total_runs, i, j;
  struct run_entry re;
  struct tm *pts;
  time_t start_time, dur;
  unsigned char *s;
  unsigned char statstr[64];
  time_t tmp_time;

  if (url && *url) {
    fprintf(f, "Content-type: text/plain; charset=%s\n\n", charset);
  }

  total_runs = run_get_total(serve_state.runlog_state);
  start_time = run_get_start_time(serve_state.runlog_state);
  for (i = 0; i < total_runs; i++) {
    if (run_get_entry(serve_state.runlog_state, i, &re) < 0) {
      fprintf(f, "%d;Cannot read entry!\n", i);
      continue;
    }
    fprintf(f, "%d;", i);
    fprintf(f, "%d;", re.timestamp);
    tmp_time = re.timestamp;
    pts = localtime(&tmp_time);
    fprintf(f, "%04d%02d%02d%02d%02d%02d;",
            pts->tm_year + 1900,
            pts->tm_mon + 1,
            pts->tm_mday,
            pts->tm_hour,
            pts->tm_min,
            pts->tm_sec);
    fprintf(f, "%04d%02d%02d;",
            pts->tm_year + 1900,
            pts->tm_mon + 1,
            pts->tm_mday);
    fprintf(f, "%04d;%02d;%02d;%02d;%02d;%02d;",
            pts->tm_year + 1900,
            pts->tm_mon + 1,
            pts->tm_mday,
            pts->tm_hour,
            pts->tm_min,
            pts->tm_sec);
    if (serve_state.global->virtual) {
      start_time = run_get_virtual_start_time(serve_state.runlog_state, re.team);
    }

    dur = re.timestamp - start_time;
    if (dur < 0) dur = 0;
    fprintf(f, "%ld;", dur);
    pts->tm_sec = dur % 60;
    dur /= 60;
    pts->tm_min = dur % 60;
    dur /= 60;
    pts->tm_hour = dur % 24;
    dur /= 24;
    fprintf(f, "%ld;%02d;%02d;%02d;",
            dur, pts->tm_hour, pts->tm_min, pts->tm_sec);

    fprintf(f, "%u;", re.size);
    fprintf(f, "%s;", run_unparse_ip(re.ip));

    s = (unsigned char*) re.sha1;
    for (j = 0; j < 20; j++) fprintf(f, "%02x", *s++);
    fprintf(f, ";");

    fprintf(f, "%d;", re.team);
    if (!(s = teamdb_get_login(serve_state.teamdb_state, re.team))) {
      fprintf(f, "!INVALID TEAM!;");
    } else {
      fprintf(f, "%s;", s);
    }
    if (!(s = teamdb_get_name(serve_state.teamdb_state, re.team))) {
      fprintf(f, "!INVALID TEAM!;");
    } else {
      fprintf(f, "%s;", s);
    }
    j = teamdb_get_flags(serve_state.teamdb_state, re.team);
    s = "";
    if ((j & TEAM_INVISIBLE)) s = "I";
    fprintf(f, "%s;", s);
    s = "";
    if ((j & TEAM_BANNED)) s = "B";
    fprintf(f, "%s;", s);
    s = "";
    if ((j & TEAM_LOCKED)) s = "L";
    fprintf(f, "%s;", s);

    if (re.problem > 0 && re.problem <= serve_state.max_prob
        && serve_state.probs[re.problem] && serve_state.probs[re.problem]->short_name) {
      fprintf(f, "%s;", serve_state.probs[re.problem]->short_name);
    } else {
      fprintf(f, "!INVALID PROBLEM %d!;", re.problem);
    }

    if (re.language > 0 && re.language <= serve_state.max_lang
        && serve_state.langs[re.language] && serve_state.langs[re.language]->short_name) {
      fprintf(f, "%s;", serve_state.langs[re.language]->short_name);
    } else {
      fprintf(f, "!INVALID LANGUAGE %d!;", re.language);
    }

    run_status_str(re.status, statstr, 0);
    fprintf(f, "%s;", statstr);
    fprintf(f, "%d;", re.score);
    fprintf(f, "%d;", re.test);
    fprintf(f, "%d;", re.is_imported);
    fprintf(f, "%d;", re.variant);
    fprintf(f, "%d;", re.is_hidden);
    fprintf(f, "%d;", re.is_readonly);

    fprintf(f, "\n");
  }
}

void
write_raw_standings(FILE *f, unsigned char const *charset)
{
  if (serve_state.global->score_system_val == SCORE_KIROV
      || serve_state.global->score_system_val == SCORE_OLYMPIAD)
    do_write_kirov_standings(f, 0, 1, 0, 0, 1, 0);
  else if (serve_state.global->score_system_val == SCORE_MOSCOW)
    do_write_moscow_standings(f, 0, 1, 0, 0, 0, 1, 0);
  else
    do_write_standings(f, 1, 0, 0, 0, 1, 0);
}

int
write_raw_source(FILE *f, const unsigned char *self_url, int run_id)
{
  path_t src_path;
  int src_flags;
  char *src_text = 0;
  size_t src_len = 0;
  struct run_entry info;

  if (run_id < 0 || run_id >= run_get_total(serve_state.runlog_state))
    return -SRV_ERR_BAD_RUN_ID;
  run_get_entry(serve_state.runlog_state, run_id, &info);
  if (info.language <= 0 || info.language > serve_state.max_lang
      || !serve_state.langs[info.language]) return -SRV_ERR_BAD_LANG_ID;

  src_flags = archive_make_read_path(src_path, sizeof(src_path),
                                     serve_state.global->run_archive_dir, run_id, 0, 1);
  if (src_flags < 0) return -SRV_ERR_FILE_NOT_EXIST;
  if (generic_read_file(&src_text, 0, &src_len, src_flags, 0, src_path, "")<0)
    return -SRV_ERR_SYSTEM_ERROR;

  if (self_url && *self_url) {
    if (serve_state.langs[info.language]->content_type) {
      fprintf(f, "Content-type: %s\n", serve_state.langs[info.language]->content_type);
      fprintf(f, "Content-Disposition: attachment; filename=\"%06d%s\"\n\n",
              run_id, serve_state.langs[info.language]->src_sfx);
    } else if (serve_state.langs[info.language]->binary) {
      fprintf(f, "Content-type: application/octet-stream\n\n");
      fprintf(f, "Content-Disposition: attachment; filename=\"%06d%s\"\n\n",
              run_id, serve_state.langs[info.language]->src_sfx);
    } else {
      fprintf(f, "Content-type: text/plain\n");
      fprintf(f, "Content-Disposition: attachment; filename=\"%06d%s\"\n\n",
              run_id, serve_state.langs[info.language]->src_sfx);
    }
  }

  if (fwrite(src_text, 1, src_len, f) != src_len) return -SRV_ERR_SYSTEM_ERROR;
  return 0;
}

int
write_raw_report(FILE *f, const unsigned char *self_url, int run_id,
                 int team_report_flag)
{
  path_t src_path;
  int src_flags;
  char *src_text = 0;
  size_t src_len = 0;
  struct run_entry info;
  const unsigned char *report_dir = serve_state.global->report_archive_dir;

  if (team_report_flag && serve_state.global->team_enable_rep_view) {
    report_dir = serve_state.global->team_report_archive_dir;
    if (serve_state.global->team_show_judge_report) {
      report_dir = serve_state.global->report_archive_dir;
    }
  }

  if (run_id < 0 || run_id >= run_get_total(serve_state.runlog_state))
    return -SRV_ERR_BAD_RUN_ID;
  run_get_entry(serve_state.runlog_state, run_id, &info);
  if (info.language <= 0 || info.language > serve_state.max_lang
      || !serve_state.langs[info.language]) return -SRV_ERR_BAD_LANG_ID;

  src_flags = archive_make_read_path(src_path, sizeof(src_path),
                                     report_dir, run_id, 0, 1);
  if (src_flags < 0) return -SRV_ERR_FILE_NOT_EXIST;
  if (generic_read_file(&src_text, 0, &src_len, src_flags, 0, src_path, "")<0)
    return -SRV_ERR_SYSTEM_ERROR;

  if (self_url && *self_url) {
    fprintf(f, "Content-type: text/plain\n");
    fprintf(f, "Content-Disposition: attachment; filename=\"%06d.txt\"\n\n",
            run_id);
  }

  if (fwrite(src_text, 1, src_len, f) != src_len) return -SRV_ERR_SYSTEM_ERROR;
  return 0;
}

int
write_tests(FILE *f, int cmd, int run_id, int test_num)
{
  path_t rep_path;
  path_t arch_path;
  int rep_flag, errcode = 0;
  char *rep_text = 0;
  size_t rep_len = 0;
  testing_report_xml_t r = 0;
  struct testing_report_test *t = 0;
  unsigned char fnbuf[64];
  full_archive_t far = 0;
  long arch_size, arch_raw_size;
  unsigned int arch_flags;
  const unsigned char *arch_data;
  unsigned char *text = 0;
  struct run_entry re;
  struct section_problem_data *prb;
  path_t path1, path2;
  unsigned char *indir;
  char *text2 = 0;
  size_t text2_len = 0;
  const unsigned char *start_ptr = 0;
  const unsigned char *digest_ptr = 0;
  unsigned char cur_digest[32];
  int good_digest_flag = 1;

  if (run_id < 0 || run_id >= run_get_total(serve_state.runlog_state)) {
    errcode = SRV_ERR_BAD_RUN_ID;
    goto failure;
  }
  if (test_num <= 0) {
    errcode = SRV_ERR_BAD_TEST_NUM;
    goto failure;
  }

  if ((rep_flag = archive_make_read_path(rep_path, sizeof(rep_path),
                                         serve_state.global->xml_report_archive_dir, run_id,
                                         0, 1)) < 0
      && (rep_flag = archive_make_read_path(rep_path, sizeof(rep_path),
                                            serve_state.global->report_archive_dir, run_id,
                                            0, 1)) < 0) {
    errcode = SRV_ERR_FILE_NOT_EXIST;
    goto failure;
  }
  if (generic_read_file(&rep_text, 0, &rep_len, rep_flag,0,rep_path, "") < 0) {
    errcode = SRV_ERR_SYSTEM_ERROR;
    goto failure;
  }
  if (get_content_type(rep_text, &start_ptr) != CONTENT_TYPE_XML) {
    // we expect the master log in XML format
    errcode = SRV_ERR_BAD_XML;
    goto failure;
  }
  if (!(r = testing_report_parse_xml(start_ptr))) {
    errcode = SRV_ERR_BAD_XML;
    goto failure;
  }
  if (test_num > r->run_tests) {
    errcode = SRV_ERR_BAD_TEST_NUM;
    goto failure;
  }
  t = r->tests[test_num - 1];

  if (cmd == SRV_CMD_VIEW_TEST_ANSWER || cmd == SRV_CMD_VIEW_TEST_INPUT
      || cmd == SRV_CMD_VIEW_TEST_INFO) {
    if (run_get_entry(serve_state.runlog_state, run_id, &re) < 0) {
      errcode = SRV_ERR_SYSTEM_ERROR;
      goto failure;
    }
    if (re.problem <= 0 || re.problem > serve_state.max_prob || !(prb = serve_state.probs[re.problem])) {
      errcode = SRV_ERR_BAD_PROB_ID;
      goto failure;
    }

    switch (cmd) {
    case SRV_CMD_VIEW_TEST_INPUT:
      indir = prb->test_dir;
      if (prb->test_pat[0]) {
        snprintf(path2, sizeof(path2), prb->test_pat, test_num);
      } else {
        snprintf(path2, sizeof(path2), "%03d%s", test_num, prb->test_sfx);
      }
      if (t->has_input_digest) digest_ptr = t->input_digest;
      break;
    case SRV_CMD_VIEW_TEST_ANSWER:
      if (!prb->use_corr || !r->correct_available) {
        errcode = SRV_ERR_NOT_SUPPORTED;
        goto failure;
      }
      indir = prb->corr_dir;
      if (prb->corr_pat[0]) {
        snprintf(path2, sizeof(path2), prb->corr_pat, test_num);
      } else {
        snprintf(path2, sizeof(path2), "%03d%s", test_num, prb->corr_sfx);
      }
      if (t->has_correct_digest) digest_ptr = t->correct_digest;
      break;
    case SRV_CMD_VIEW_TEST_INFO:
      if (!prb->use_info || !r->info_available) {
        errcode = SRV_ERR_NOT_SUPPORTED;
        goto failure;
      }
      indir = prb->info_dir;
      if (prb->info_pat[0]) {
        snprintf(path2, sizeof(path2), prb->info_pat, test_num);
      } else {
        snprintf(path2, sizeof(path2), "%03d%s", test_num, prb->info_sfx);
      }
      if (t->has_info_digest) digest_ptr = t->info_digest;
      break;
    default:
      abort();
    }

    if ((prb->variant_num > 0 && r->variant <= 0)
        || (prb->variant_num <= 0 && r->variant > 0)) { 
      errcode = SRV_ERR_NOT_SUPPORTED;
      goto failure;
    }

    if (r->variant > 0) {
      snprintf(path1, sizeof(path1), "%s-%d/%s", indir, r->variant, path2);
    } else {
      snprintf(path1, sizeof(path1), "%s/%s", indir, path2);
    }

    if (digest_ptr) {
      if (filehash_get(path1, cur_digest) < 0) {
        errcode = SRV_ERR_SYSTEM_ERROR;
        goto failure;
      }
      good_digest_flag = digest_is_equal(DIGEST_SHA1, digest_ptr, cur_digest);
    }

    if (generic_read_file(&text2, 0, &text2_len, 0, 0, path1, 0) < 0) {
      errcode = SRV_ERR_SYSTEM_ERROR;
      goto failure;
    }

    fprintf(f, "Content-type: text/plain\n\n");
    if (!good_digest_flag) {
      fprintf(f,
              "*********\n"
              "NOTE: The file checksum has been changed!\n"
              "It is possible, that the file was edited!\n"
              "*********\n\n");
    }
    if (text2_len > 0) {
      if (fwrite(text2, 1, text2_len, f) != text2_len) {
        err("write_tests: fwrite failed");
        errcode = SRV_ERR_SYSTEM_ERROR;
        goto failure;
      }
    }
  } else {
    switch (cmd) {
    case SRV_CMD_VIEW_TEST_OUTPUT:
      if (!t->output_available) {
        errcode = SRV_ERR_NOT_SUPPORTED;
        goto failure;
      }
      snprintf(fnbuf, sizeof(fnbuf), "%06d.o", test_num);
      break;
    case SRV_CMD_VIEW_TEST_ERROR:
      if (!t->stderr_available) {
        errcode = SRV_ERR_NOT_SUPPORTED;
        goto failure;
      }
      snprintf(fnbuf, sizeof(fnbuf), "%06d.e", test_num);
      break;
    case SRV_CMD_VIEW_TEST_CHECKER:
      if (!t->checker_output_available) {
        errcode = SRV_ERR_NOT_SUPPORTED;
        goto failure;
      }
      snprintf(fnbuf, sizeof(fnbuf), "%06d.c", test_num);
      break;
    default:
      abort();
    }

    rep_flag = archive_make_read_path(arch_path, sizeof(arch_path),
                                      serve_state.global->full_archive_dir, run_id, 0, 0);
    if (rep_flag < 0) {
      errcode = SRV_ERR_SYSTEM_ERROR;
      goto failure;
    }
    if (!(far = full_archive_open_read(arch_path))) {
      errcode = SRV_ERR_FILE_NOT_EXIST;
      goto failure;
    }
    rep_flag = full_archive_find_file(far, fnbuf,
                                      &arch_size,&arch_raw_size,&arch_flags,&arch_data);
    if (rep_flag < 0) {
      errcode = SRV_ERR_SYSTEM_ERROR;
      goto failure;
    }
    if (!rep_flag) {
      errcode = SRV_ERR_FILE_NOT_EXIST;
      goto failure;
    }

    if (arch_raw_size > 0) {
      text = (unsigned char*) xmalloc(arch_raw_size);
      if (uncompress(text, &arch_raw_size, arch_data, arch_size) != Z_OK) {
        err("write_tests: uncompress failed");
        errcode = SRV_ERR_SYSTEM_ERROR;
        goto failure;
      }
    }

    fprintf(f, "Content-type: text/plain\n\n");
    if (arch_raw_size > 0) {
      if (fwrite(text, 1, arch_raw_size, f) != arch_raw_size) {
        err("write_tests: fwrite failed");
        errcode = SRV_ERR_SYSTEM_ERROR;
        goto failure;
      }
    }
  }

  xfree(text2);
  xfree(text);
  full_archive_close(far);
  xfree(rep_text);
  testing_report_free(r);
  return 0;

 failure:
  xfree(text2);
  xfree(text);
  full_archive_close(far);
  testing_report_free(r);
  xfree(rep_text);
  return -errcode;
}

int
write_audit_log(FILE *f, int run_id)
{
  int errcode = 0, rep_flag;
  path_t audit_log_path;
  struct stat stb;
  char *audit_text = 0;
  size_t audit_text_size = 0;

  if (run_id < 0 || run_id >= run_get_total(serve_state.runlog_state)) {
    errcode = SRV_ERR_BAD_RUN_ID;
    goto failure;
  }

  if ((rep_flag = archive_make_read_path(audit_log_path, sizeof(audit_log_path),
                                         serve_state.global->audit_log_dir, run_id, 0, 0)) < 0) {
    goto empty_log;
  }

  if (lstat(audit_log_path, &stb) < 0) goto empty_log;
  if (!S_ISREG(stb.st_mode)) {
    errcode = SRV_ERR_SYSTEM_ERROR;
    goto failure;
  }

  if (generic_read_file(&audit_text, 0, &audit_text_size, 0, 0, audit_log_path, 0)<0) {
    errcode = SRV_ERR_SYSTEM_ERROR;
    goto failure;
  }

  fprintf(f, "Content-type: text/plain\n\n");
  if (audit_text_size > 0) {
    if (fwrite(audit_text, 1, audit_text_size, f) != audit_text_size) {
      err("write_tests: fwrite failed");
      errcode = SRV_ERR_SYSTEM_ERROR;
      goto failure;
    }
  }
  return 0;

 empty_log:
  fprintf(f, "Content-type: text/plain\n\n");
  return 0;

 failure:
  return -errcode;
}

static int
is_registered_today(struct userlist_user *user, time_t from_time,
                    time_t to_time)
{
  struct userlist_contest *uc = 0;

  if (!user || !user->contests) return 0;
  uc = (struct userlist_contest*) user->contests->first_down;
  while (uc) {
    if (uc->id == serve_state.global->contest_id
        && uc->date >= from_time
        && uc->date < to_time)
      return 1;
    uc = (struct userlist_contest*) uc->b.right;
  }
  return 0;
}

void
generate_daily_statistics(FILE *f, time_t from_time, time_t to_time)
{
  int u_max, u_tot;
  int *u_ind, *u_rev;
  int p_max, p_tot, i, j;
  int *p_ind, *p_rev;
  int row_sz, row_sh;
  unsigned char *solved = 0;
  int r_tot, u, p, idx, max_u_total;
  const struct run_entry *runs, *rcur;
  int *u_total = 0, *u_ok = 0, *u_failed = 0, *u_afterok = 0, *u_errors = 0;
  int *u_trans = 0, *u_cf = 0, *u_ac = 0, *u_ign = 0, *u_disq = 0, *u_pend = 0;
  int *u_ce = 0, *u_sort = 0;
  int *l_total = 0, *l_ok = 0, *l_ce = 0;
  int *p_total = 0, *p_ok = 0;
  unsigned char *u_reg = 0;
  struct teamdb_export uinfo;
  int *sort_num, *sort_idx;

  int total_empty = 0;
  int total_errors = 0;
  int total_status[128];
  int total_pseudo = 0;
  int total_afterok = 0;
  int total_trans = 0;
  int total_ok = 0;
  int total_failed = 0;
  int total_cf = 0;
  int total_ac = 0;
  int total_ign = 0;
  int total_disq = 0;
  int total_pend = 0;
  int total_ce = 0;
  int total_reg = 0;
  int total_runs = 0;

  unsigned char *login, *name, probname[256], langname[256];

  int clar_total = 0, clar_total_today = 0, clar_from_judges = 0;
  int clar_to_judges = 0, clar_flags, clar_from, clar_to;
  time_t clar_time;

  /* u_tot             - total number of teams in index array
   * u_max             - maximal possible number of teams
   * u_ind[0..u_tot-1] - index array:   team_idx -> team_id
   * u_rev[0..u_max-1] - reverse index: team_id -> team_idx
   */
  u_max = teamdb_get_max_team_id(serve_state.teamdb_state) + 1;
  XALLOCAZ(u_ind, u_max);
  XALLOCAZ(u_rev, u_max);
  XALLOCAZ(u_reg, u_max);
  for (i = 1, u_tot = 0; i < u_max; i++) {
    u_rev[i] = -1;
    if (teamdb_lookup(serve_state.teamdb_state, i)
        && teamdb_export_team(serve_state.teamdb_state, i, &uinfo) >= 0) {
      if (is_registered_today(uinfo.user, from_time, to_time)) {
        total_reg++;
        u_reg[u_tot] = 1;
      }
      u_rev[i] = u_tot;
      u_ind[u_tot++] = i;
    }
  }

  /* p_tot             - total number of problems in index array
   * p_max             - maximal possible number of problems
   * p_ind[0..p_tot-1] - index array:   prob_idx -> prob_id
   * p_rev[0..p_max-1] - reverse index: prob_id -> prob_idx
   */
  p_max = serve_state.max_prob + 1;
  XALLOCAZ(p_ind, p_max);
  XALLOCAZ(p_rev, p_max);
  for (i = 1, p_tot = 0; i < p_max; i++) {
    p_rev[i] = -1;
    if (serve_state.probs[i]) {
      p_rev[i] = p_tot;
      p_ind[p_tot++] = i;
    }
  }

  r_tot = run_get_total(serve_state.runlog_state);
  runs = run_get_entries_ptr(serve_state.runlog_state);

  if (!u_tot || !p_tot || !r_tot) return;

  /* calculate the power of 2 not less than p_tot */
  for (row_sz = 1, row_sh = 0; row_sz < p_tot; row_sz <<= 1, row_sh++);
  /* all two-dimensional arrays will have rows of size row_sz */

  XCALLOC(solved, row_sz * u_tot);
  memset(total_status, 0, sizeof(total_status));
  XALLOCAZ(u_total, u_tot);
  XALLOCAZ(u_ok, u_tot);
  XALLOCAZ(u_failed, u_tot);
  XALLOCAZ(u_afterok, u_tot);
  XALLOCAZ(u_errors, u_tot);
  XALLOCAZ(u_trans, u_tot);
  XALLOCAZ(u_cf, u_tot);
  XALLOCAZ(u_ac, u_tot);
  XALLOCAZ(u_ign, u_tot);
  XALLOCAZ(u_disq, u_tot);
  XALLOCAZ(u_pend, u_tot);
  XALLOCAZ(u_ce, u_tot);
  XALLOCA(u_sort, u_tot);

  XALLOCAZ(l_total, serve_state.max_lang + 1);
  XALLOCAZ(l_ok, serve_state.max_lang + 1);
  XALLOCAZ(l_ce, serve_state.max_lang + 1);

  XALLOCAZ(p_total, p_tot);
  XALLOCAZ(p_ok, p_tot);

  for (i = 0, rcur = runs; i < r_tot; i++, rcur++) {
    if (rcur->timestamp >= to_time) break;
    if (rcur->timestamp < from_time) {
      if (rcur->status == RUN_EMPTY) continue;
      if (rcur->status != RUN_OK) continue;
      if (rcur->team <= 0 || rcur->team >= u_max || u_rev[rcur->team] < 0)
        continue;
      if (rcur->problem <= 0 || rcur->problem >= p_max
          || p_rev[rcur->problem] < 0)
        continue;
      solved[(u_rev[rcur->team] << row_sh) + p_rev[rcur->problem]] = 1;
      continue;
    }

    // ok, collect statistics
    if ((rcur->status > RUN_MAX_STATUS && rcur->status < RUN_PSEUDO_FIRST)
        || (rcur->status>RUN_PSEUDO_LAST && rcur->status<RUN_TRANSIENT_FIRST)
        || (rcur->status > RUN_TRANSIENT_LAST)) {
      fprintf(f, "error: run %d has invalid status %d\n", i, rcur->status);
      total_errors++;
      continue;
    }
    if (rcur->status == RUN_EMPTY) {
      total_empty++;
      continue;
    }
    if (rcur->team <= 0 || rcur->team >= u_max || (u = u_rev[rcur->team]) < 0) {
      fprintf(f, "error: run %d has invalid user_id %d\n",
              i, rcur->team);
      total_errors++;
      continue;
    }
    if (rcur->status >= RUN_PSEUDO_FIRST && rcur->status <= RUN_PSEUDO_LAST) {
      total_status[rcur->status]++;
      total_pseudo++;
      u_total[u]++;
      continue;
    }
    if (rcur->problem <= 0 || rcur->problem >= p_max
        || (p = p_rev[rcur->problem]) < 0) {
      fprintf(f, "error: run %d has invalid prob_id %d\n",
              i, rcur->problem);
      total_errors++;
      u_errors[u]++;
      u_total[u]++;
      continue;
    }
    idx = (u << row_sh) + p;
    if (solved[idx]) {
      u_afterok[u]++;
      u_total[u]++;
      total_afterok++;
      continue;
    }
    if (rcur->language <= 0 || rcur->language > serve_state.max_lang
        || !serve_state.langs[rcur->language]) {
      fprintf(f, "error: run %d has invalid lang_id %d\n",
              i, rcur->language);
      total_errors++;
      u_errors[u]++;
      u_total[u]++;
      continue;
    }
    if (rcur->status >= RUN_TRANSIENT_FIRST
        && rcur->status <= RUN_TRANSIENT_LAST) {
      total_trans++;
      u_total[u]++;
      u_trans[u]++;
      continue;
    }

    switch (rcur->status) {
    case RUN_OK:
      total_ok++;
      u_ok[u]++;
      u_total[u]++;
      l_total[rcur->language]++;
      l_ok[rcur->language]++;
      p_total[p]++;
      p_ok[p]++;
      solved[idx] = 1;
      break;

    case RUN_COMPILE_ERR:
      total_ce++;
      u_ce[u]++;
      u_total[u]++;
      l_total[rcur->language]++;
      l_ce[rcur->language]++;
      p_total[p]++;
      break;

    case RUN_RUN_TIME_ERR:
    case RUN_TIME_LIMIT_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
    case RUN_PARTIAL:
      total_failed++;
      u_failed[u]++;
      u_total[u]++;
      l_total[rcur->language]++;
      p_total[p]++;
      total_status[rcur->status]++;
      break;

    case RUN_CHECK_FAILED:
      total_cf++;
      u_cf[u]++;
      u_total[u]++;
      break;

    case RUN_ACCEPTED:
      total_ac++;
      u_ac[u]++;
      u_total[u]++;
      break;

    case RUN_IGNORED:
      total_ign++;
      u_ign[u]++;
      u_total[u]++;
      break;

    case RUN_DISQUALIFIED:
      total_disq++;
      u_disq[u]++;
      u_total[u]++;
      break;

    case RUN_PENDING:
      total_pend++;
      u_pend[u]++;
      u_total[u]++;
      break;

    default:
      abort();
    }
  }

  clar_total = clar_get_total(serve_state.clarlog_state);
  for (i = 0; i < clar_total; i++) {
    if (clar_get_record(serve_state.clarlog_state, i, &clar_time, NULL, NULL,
                        &clar_from, &clar_to, &clar_flags, NULL, NULL,NULL) < 0)
      continue;
    if (clar_time >= to_time) break;
    if (clar_time < from_time) continue;

    clar_total_today++;
    if (!clar_from) clar_from_judges++;
    else clar_to_judges++;
  }

  if (total_reg > 0) {
    fprintf(f, "New users registered: %d\n", total_reg);
    for (i = 0; i < u_tot; i++) {
      if (!u_reg[i]) continue;
      u = u_ind[i];
      if (!(login = teamdb_get_login(serve_state.teamdb_state, u))) login = "";
      if (!(name = teamdb_get_name(serve_state.teamdb_state, u))) name = "";
      fprintf(f, "  %-6d %-15.15s %-30.30s\n", u, login, name);
    }
    fprintf(f, "\n");
  }

  total_runs = total_empty + total_pseudo + total_afterok + total_trans
    + total_ok + total_failed + total_cf
    + total_ac + total_ign + total_disq + total_pend + total_ce;
  if (total_runs > 0)
    fprintf(f, "Total new runs:            %d\n", total_runs);
  if (total_empty > 0)
    fprintf(f, "  Empty (cleared) records: %d\n", total_empty);
  if (total_pseudo > 0)
    fprintf(f, "  Virtual records:         %d\n", total_pseudo);
  if (total_trans > 0)
    fprintf(f, "  Currently being tested:  %d\n", total_trans);
  if (total_afterok > 0)
    fprintf(f, "  Submits after success:   %d\n", total_afterok);
  if (total_ok > 0)
    fprintf(f, "  Successful submits:      %d\n", total_ok);
  if (total_failed > 0)
    fprintf(f, "  Unsuccessful submits:    %d\n", total_failed);
  if (total_status[RUN_RUN_TIME_ERR] > 0)
    fprintf(f, "    Run-time error:        %d\n", total_status[RUN_RUN_TIME_ERR]);
  if (total_status[RUN_TIME_LIMIT_ERR] > 0)
    fprintf(f, "    Time-limit exceeded:   %d\n", total_status[RUN_TIME_LIMIT_ERR]);
  if (total_status[RUN_PRESENTATION_ERR] > 0)
    fprintf(f, "    Presentation error:    %d\n", total_status[RUN_PRESENTATION_ERR]);
  if (total_status[RUN_WRONG_ANSWER_ERR] > 0)
    fprintf(f, "    Wrong answer:          %d\n", total_status[RUN_WRONG_ANSWER_ERR]);
  if (total_status[RUN_MEM_LIMIT_ERR] > 0)
    fprintf(f, "    Memory limit exceeded: %d\n", total_status[RUN_MEM_LIMIT_ERR]);
  if (total_status[RUN_SECURITY_ERR] > 0)
    fprintf(f, "    Security violation:    %d\n", total_status[RUN_SECURITY_ERR]);
  if (total_status[RUN_PARTIAL] > 0)
    fprintf(f, "    Partial solution:      %d\n", total_status[RUN_PARTIAL]);
  if (total_ce > 0)
    fprintf(f, "  Compilation error:       %d\n", total_ce);
  if (total_cf > 0)
    fprintf(f, "  Checking failed:         %d\n", total_cf);
  if (total_ac > 0)
    fprintf(f, "  Accepted for testing:    %d\n", total_ac);
  if (total_ign > 0)
    fprintf(f, "  Ignored:                 %d\n", total_ign);
  if (total_disq > 0)
    fprintf(f, "  Disqualified:            %d\n", total_disq);
  if (total_pend > 0)
    fprintf(f, "  Pending check:           %d\n", total_pend);
  if (total_runs > 0)
    fprintf(f, "\n");

  if (total_runs > 0) {
    fprintf(f, "%-40.40s %-7.7s %-7.7s\n", "Problem", "Total", "Success");
    for (i = 0; i < p_tot; i++) {
      p = p_ind[i];
      snprintf(probname, sizeof(probname), "%s: %s",
               serve_state.probs[p]->short_name, serve_state.probs[p]->long_name);
      fprintf(f, "%-40.40s %-7d %-7d\n", probname, p_total[i], p_ok[i]);
    }
    fprintf(f, "\n");
  }

  if (total_runs > 0) {
    fprintf(f, "%-40.40s %-7.7s %-7.7s %-7.7s\n",
            "Problem", "Total", "CE", "Success");
    for (i = 1; i <= serve_state.max_lang; i++) {
      if (!serve_state.langs[i]) continue;
      snprintf(langname, sizeof(langname), "%s - %s",
               serve_state.langs[i]->short_name,
               serve_state.langs[i]->long_name);
      fprintf(f, "%-40.40s %-7d %-7d %-7d\n",
              langname, l_total[i], l_ce[i], l_ok[i]);
    }
    fprintf(f, "\n");
  }

  // sort users by decreasing order of user's submit
  max_u_total = 0;
  for (i = 0; i < u_tot; i++)
    if (u_total[i] > max_u_total)
      max_u_total = u_total[i];
  XALLOCAZ(sort_num, max_u_total + 1);
  XALLOCAZ(sort_idx, max_u_total + 1);
  for (i = 0; i < u_tot; i++)
    sort_num[u_total[i]]++;
  sort_idx[max_u_total] = 0;
  for (i = max_u_total - 1; i >= 0; i--)
    sort_idx[i] = sort_idx[i + 1] + sort_num[i + 1];
  for (i = 0; i < u_tot; i++)
    u_sort[sort_idx[u_total[i]]++] = i;

  if (total_runs > 0) {
    fprintf(f, "%-7.7s %-24.24s %-7.7s %-7.7s %s\n",
            "Id", "User", "Total", "Success", "Other");
    for (i = 0; i < u_tot; i++) {
      j = u_sort[i];
      if (!u_total[j]) break;

      u = u_ind[j];
      name = teamdb_get_name(serve_state.teamdb_state, u);
      if (!name) name = teamdb_get_login(serve_state.teamdb_state, u);
      if (!name) name = "";

      fprintf(f, "%-7d %-24.24s %-7d %-7d %-7d %d/%d/%d %d/%d/%d/%d/%d/%d\n",
              u, name, u_total[j], u_ok[j], u_failed[j],
              u_cf[j], u_ce[j], u_ign[j],
              u_afterok[j], u_errors[j], u_trans[j],
              u_ac[j], u_disq[j], u_pend[j]);
    }
    fprintf(f, "\n");
  }

  if (clar_total_today > 0) {
    fprintf(f,
            "Clarification requests: %d\n"
            "To judges:              %d\n"
            "From judges:            %d\n\n",
            clar_total_today, clar_to_judges, clar_from_judges);
  }
  
  xfree(solved);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
