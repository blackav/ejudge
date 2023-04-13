/* -*- mode: c -*- */

/* Copyright (C) 2002-2023 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/filter_tree.h"
#include "ejudge/filter_eval.h"
#include "ejudge/prepare.h"
#include "ejudge/protocol.h"
#include "ejudge/misctext.h"
#include "ejudge/mischtml.h"
#include "ejudge/teamdb.h"
#include "ejudge/clarlog.h"
#include "ejudge/runlog.h"
#include "ejudge/base64.h"
#include "ejudge/html.h"
#include "ejudge/fileutl.h"
#include "ejudge/sformat.h"
#include "ejudge/archive_paths.h"
#include "ejudge/team_extra.h"
#include "ejudge/xml_utils.h"
#include "ejudge/userlist.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/full_archive.h"
#include "ejudge/filehash.h"
#include "ejudge/digest_io.h"
#include "ejudge/errlog.h"
#include "ejudge/serve_state.h"
#include "ejudge/mime_type.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

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

#define ARMOR(s)  html_armor_buf(&ab, s)

// FIXME: currently no localization for these strings
static const unsigned char * const change_status_strings[RUN_STATUS_SIZE] =
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
  [RUN_SYNC_ERR]         = "Synchronization error",
  [RUN_STYLE_ERR]        = "Coding style violation",
  [RUN_REJECTED]         = "Rejected",
  [RUN_WALL_TIME_LIMIT_ERR] = "Wall time-limit exceeded",
  [RUN_PENDING_REVIEW]   = "Pending review",
  [RUN_SUMMONED]         = "Summoned for defence",
  [RUN_PENDING]          = "Mark as PENDING",
  [RUN_FULL_REJUDGE]     = "FULL Rejudge",
  [RUN_REJUDGE]          = "Rejudge",
};
static const int kirov_no_rejudge_status_list[] =
{
  RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_COMPILE_ERR, RUN_PARTIAL, RUN_ACCEPTED, RUN_STYLE_ERR,
  RUN_PENDING_REVIEW, RUN_REJECTED, RUN_SUMMONED,
  -1,
};
static const int kirov_status_list[] =
{
  RUN_REJUDGE, RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_COMPILE_ERR, RUN_PARTIAL, RUN_ACCEPTED, RUN_STYLE_ERR,
  RUN_PENDING_REVIEW, RUN_REJECTED, RUN_SUMMONED,
  -1,
};
static const int olymp_accepting_no_rejudge_status_list[] =
{
  RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING, RUN_ACCEPTED,
  RUN_OK, RUN_PARTIAL, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR, RUN_TIME_LIMIT_ERR,
  RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR, RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR, RUN_SYNC_ERR,
  RUN_STYLE_ERR, RUN_WALL_TIME_LIMIT_ERR, RUN_PENDING_REVIEW, RUN_REJECTED, RUN_SUMMONED,
  -1,
};
static const int olymp_accepting_status_list[] =
{
  RUN_REJUDGE, RUN_FULL_REJUDGE, RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_ACCEPTED, RUN_OK, RUN_PARTIAL, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR,
  RUN_TIME_LIMIT_ERR, RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR,
  RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR, RUN_SYNC_ERR, RUN_STYLE_ERR, RUN_WALL_TIME_LIMIT_ERR,
  RUN_PENDING_REVIEW, RUN_REJECTED, RUN_SUMMONED,
  -1,
};
static const int olymp_judging_no_rejudge_status_list[] =
{
  RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_PARTIAL,  RUN_ACCEPTED, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR,
  RUN_TIME_LIMIT_ERR, RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR,
  RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR, RUN_SYNC_ERR, RUN_STYLE_ERR, RUN_WALL_TIME_LIMIT_ERR,
  RUN_PENDING_REVIEW, RUN_REJECTED, RUN_SUMMONED,
  -1,
};
static const int olymp_judging_status_list[] =
{
  RUN_REJUDGE, RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK,  RUN_PARTIAL, RUN_ACCEPTED, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR,
  RUN_TIME_LIMIT_ERR, RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR,
  RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR, RUN_SYNC_ERR, RUN_STYLE_ERR, RUN_WALL_TIME_LIMIT_ERR,
  RUN_PENDING_REVIEW, RUN_REJECTED, RUN_SUMMONED,
  -1,
};
static const int acm_no_rejudge_status_list[] =
{
  RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR, RUN_TIME_LIMIT_ERR,
  RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR, RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR, RUN_SYNC_ERR, RUN_ACCEPTED,
  RUN_STYLE_ERR, RUN_WALL_TIME_LIMIT_ERR, RUN_PENDING_REVIEW, RUN_REJECTED, RUN_SUMMONED,
  -1,
};
static const int acm_status_list[] =
{
  RUN_REJUDGE, RUN_IGNORED, RUN_DISQUALIFIED, RUN_PENDING,
  RUN_OK, RUN_COMPILE_ERR, RUN_RUN_TIME_ERR, RUN_TIME_LIMIT_ERR,
  RUN_PRESENTATION_ERR, RUN_WRONG_ANSWER_ERR, RUN_MEM_LIMIT_ERR, RUN_SECURITY_ERR, RUN_SYNC_ERR, RUN_ACCEPTED,
  RUN_STYLE_ERR, RUN_WALL_TIME_LIMIT_ERR, RUN_PENDING_REVIEW, RUN_REJECTED, RUN_SUMMONED,
  -1,
};

void
write_change_status_dialog(
        const serve_state_t state,
        FILE *f,
        unsigned char const *var_name,
        int disable_rejudge_flag,
        const unsigned char *td_class,
        int cur_value,
        int is_disabled)
{
  const int * cur_status_list = 0;
  int i;
  unsigned char cl[128] = { 0 };
  const unsigned char *dis = "";

  if (is_disabled) dis = " disabled=\"disabled\"";

  if (!var_name) var_name = "status";
  if (td_class && *td_class) {
    snprintf(cl, sizeof(cl), " class=\"%s\"", td_class);
  }

  // various sets of valid run statuses
  if (state->global->score_system == SCORE_KIROV) {
    if (disable_rejudge_flag) cur_status_list = kirov_no_rejudge_status_list;
    else cur_status_list = kirov_status_list;
  } else if (state->global->score_system == SCORE_OLYMPIAD
             && state->accepting_mode) {
    // OLYMPIAD in accepting mode
    if (disable_rejudge_flag) cur_status_list = olymp_accepting_no_rejudge_status_list;
    else cur_status_list = olymp_accepting_status_list;
  } else if (state->global->score_system == SCORE_OLYMPIAD) {
    // OLYMPIAD in judging mode
    if (disable_rejudge_flag) cur_status_list = olymp_judging_no_rejudge_status_list;
    cur_status_list = olymp_judging_status_list;
  } else {
    if (disable_rejudge_flag) cur_status_list = acm_no_rejudge_status_list;
    else cur_status_list = acm_status_list;
  }

  fprintf(f, "<td%s><select name=\"%s\"%s><option value=\"\"></option>",
          cl, var_name, dis);
  for (i = 0; cur_status_list[i] != -1; i++) {
    const unsigned char *s = "";
    if (cur_value == cur_status_list[i]) s = " selected=\"selected\"";
    fprintf(f, "<option value=\"%d\"%s>%s</option>",
            cur_status_list[i], s, change_status_strings[cur_status_list[i]]);
  }
  fprintf(f, "</select></td>\n");
}

#define BITS_PER_LONG (8*sizeof(unsigned long))

#define BGCOLOR_CHECK_FAILED " bgcolor=\"#FF80FF\""
#define BGCOLOR_FAIL         " bgcolor=\"#FF8080\""
#define BGCOLOR_PASS         " bgcolor=\"#80FF80\""

static int
is_duplicated_row(const struct testing_report_xml *r, int row)
{
  if (!r || !r->tests_mode) return 0;

  if (row <= 0 || row >= r->tt_row_count) return 0;
  struct testing_report_row *trr = r->tt_rows[row];
  if (!trr->must_fail) return 0;

  for (int j = 0; j < r->tt_column_count; ++j) {
    if (r->tt_cells[row][j]->status == RUN_CHECK_FAILED) return 0;
  }

  int i;
  for (i = 0; i < row; ++i) {
    struct testing_report_row *trr2 = r->tt_rows[i];
    if (!trr2->must_fail) continue;

    int j;
    for (j = 0; j < r->tt_column_count; ++j) {
      struct testing_report_cell *trc = r->tt_cells[row][j];
      struct testing_report_cell *trc2 = r->tt_cells[i][j];
      if (trc->status != trc2->status)
        break;
    }
    if (j >= r->tt_column_count) break;
  }
  return i < row;
}

static int
is_duplicated_column(const struct testing_report_xml *r, int col)
{
  if (!r || !r->tests_mode) return 0;
  if (col <= 0 || col >= r->tt_column_count) return 0;

  for (int i = 0; i < r->tt_row_count; ++i) {
    if (r->tt_cells[i][col]->status == RUN_CHECK_FAILED) return 0;
  }
  int i;
  for (i = 0; i < r->tt_row_count; ++i) {
    if (r->tt_cells[i][col]->status != RUN_OK) break;
  }
  if (i >= r->tt_row_count) return 1;

  int j;
  for (j = 0; j < col; ++j) {
    for (i = 0; i < r->tt_row_count; ++i) {
      struct testing_report_cell *trc = r->tt_cells[i][col];
      struct testing_report_cell *trc2 = r->tt_cells[i][j];
      if (trc->status != trc2->status)
        break;
    }
    if (i >= r->tt_row_count) break;
  }
  return j < col;
}

int
write_xml_tests_report(
        FILE *f,
        int user_mode,
        const struct testing_report_xml *r,
        ej_cookie_t sid,
        unsigned char const *self_url,
        unsigned char const *extra_args,
        const unsigned char *class1,
        const unsigned char *class2)
{
  unsigned char *cl1 = " border=\"1\"";
  unsigned char *cl2 = "";
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *font_color = "";
  const unsigned char *bgcolor = "";
  const unsigned char *fail_str = "";
  int i, j;
  struct testing_report_row *trr = 0;
  struct testing_report_cell *trc = 0;
  unsigned char buf[64];

  if (class1 && *class1) {
    cl1 = (unsigned char *) alloca(strlen(class1) + 16);
    sprintf(cl1, " class=\"%s\"", class1);
  }
  if (class2 && *class2) {
    cl2 = (unsigned char*) alloca(strlen(class2) + 16);
    sprintf(cl2, " class=\"%s\"", class2);
  }

  if (r->compile_error) {
    fprintf(f, "<h2><font color=\"red\">%s</font></h2>\n", run_status_str(r->status, 0, 0, 0, 0));
    if (r->compiler_output) {
      fprintf(f, "<pre>%s</pre>\n", ARMOR(r->compiler_output));
    }
    goto done;
  }

  if (r->status == RUN_CHECK_FAILED) {
    font_color = " color=\"magenta\"";
  } else if (r->status == RUN_OK || r->status == RUN_ACCEPTED || r->status == RUN_PENDING_REVIEW || r->status == RUN_SUMMONED) {
    font_color = " color=\"green\"";
  } else {
    font_color = " color=\"red\"";
  }
  fprintf(f, "<h2><font%s>%s</font></h2>\n",
          font_color, run_status_str(r->status, 0, 0, 0, 0));

  if (user_mode && r->status == RUN_CHECK_FAILED) {
    goto done;
  }

  if (r->comment) {
    fprintf(f, "<h3>%s</h3>\n", _("Testing comments"));
    fprintf(f, "<pre>%s</pre>\n", ARMOR(r->comment));
  }

  if (r->valuer_comment || r->valuer_judge_comment || r->valuer_errors) {
    fprintf(f, "<h3>%s</h3>\n", _("Valuer information"));
    if (r->valuer_comment) {
      fprintf(f, "<b><u>%s</u></b><br/><pre>%s</pre>\n",
              _("Valuer comments"), ARMOR(r->valuer_comment));
    }
    if (r->valuer_judge_comment) {
      fprintf(f, "<b><u>%s</u></b><br/><pre>%s</pre>\n",
              _("Valuer judge comments"), ARMOR(r->valuer_judge_comment));
    }
    if (r->valuer_errors) {
      fprintf(f, "<b><u>%s</u></b><br/><pre><font color=\"red\">%s</font></pre>\n",
              _("Valuer errors"), ARMOR(r->valuer_errors));
    }
  }

  if (r->host && !user_mode) {
    fprintf(f, "<p><big>Tested on host: %s</big></p>\n", r->host);
  }
  if (r->cpu_model && !user_mode) {
    fprintf(f, "<p>CPU model: %s</p>\n", r->cpu_model);
  }
  if (r->cpu_mhz && !user_mode) {
    fprintf(f, "<p>CPU MHz: %s</p>\n", r->cpu_mhz);
  }

  if (r->tt_row_count <= 0 || r->tt_column_count <= 0) {
    if (r->errors) {
      fprintf(f, "<h3>%s</h3>\n", _("Testing messages"));
      fprintf(f, "<pre>%s</pre>\n", ARMOR(r->errors));
    }
    fprintf(f, "<p>%s</p>\n",
            _("Further testing information is not available"));
    goto done;
  }

  fprintf(f, "<p>%s: %d.</p>\n",
          _("Total number of sample programs in the test suite"),
          r->tt_row_count);
  fprintf(f, "<p>%s: %d.</p>\n",
          _("Total number of submitted tests"),
          r->tt_column_count);

  fprintf(f, "<table%s>\n", cl1);
  fprintf(f, "<tr>");
  fprintf(f, "<th%s width=\"30px\">NN</td>", cl1);
  fprintf(f, "<th%s width=\"120px\">Prog. name</td>", cl1);
  fprintf(f, "<th%s width=\"50px\" align=\"center\">Goodness</td>", cl1);
  for (j = 0; j < r->tt_column_count; ++j) {
    const unsigned char *stb = "";
    const unsigned char *ste = "";
    if (is_duplicated_column(r, j)) {
      stb = "<strike>";
      ste = "</strike>";
    }
    fprintf(f, "<th%s width=\"40px\" align=\"center\">%s%d%s</td>", cl1, stb, j + 1, ste);
  }
  fprintf(f, "</tr>\n");
  for (i = 0; i < r->tt_row_count; ++i) {
    const unsigned char *stb = "";
    const unsigned char *ste = "";
    if (is_duplicated_row(r, i)) {
      stb = "<strike>";
      ste = "</strike>";
    }

    fprintf(f, "<tr>");
    trr = r->tt_rows[i];
    if (trr->status == RUN_CHECK_FAILED) {
      bgcolor = BGCOLOR_CHECK_FAILED;
    } else if (trr->status == RUN_OK) {
      if (trr->must_fail) {
        bgcolor = BGCOLOR_FAIL;
      } else {
        bgcolor = BGCOLOR_PASS;
      }
    } else {
      if (trr->must_fail) {
        bgcolor = BGCOLOR_PASS;
      } else {
        bgcolor = BGCOLOR_FAIL;
      }
    }
    fail_str = "PASS";
    font_color = " color=\"green\"";
    if (trr->must_fail) {
      fail_str = "FAIL";
      font_color = " color=\"red\"";
    }
    fprintf(f, "<td%s%s>%s%d%s</td>", cl1, bgcolor, stb, i + 1, ste);
    fprintf(f, "<td%s%s>%s<tt>%s</tt>%s</td>", cl1, bgcolor, stb, ARMOR(trr->name), ste);
    fprintf(f, "<td%s%s align=\"center\">%s<font%s><b>%s</b></font>%s</td>", cl1, bgcolor, stb, font_color, fail_str, ste);
    for (j = 0; j < r->tt_column_count; ++j) {
      trc = r->tt_cells[i][j];
      if (trc->status == RUN_CHECK_FAILED) {
        font_color = "";
      } else if (trc->status == RUN_OK) {
        font_color = " color=\"green\"";
      } else {
        font_color = " color=\"red\"";
      }
      run_status_to_str_short(buf, sizeof(buf), trc->status);
      fprintf(f, "<td%s%s align=\"center\"><tt><font%s>%s</font></tt></td>", cl1, bgcolor, font_color, buf);
    }
    fprintf(f, "</tr>\n");
  }
  fprintf(f, "</table>\n");

  if (r->errors) {
    fprintf(f, "<h3>%s</h3>\n", _("Testing messages"));
    fprintf(f, "<pre>%s</pre>\n", ARMOR(r->errors));
  }

done:
  html_armor_free(&ab);
  return 0;
}

void
html_lock_filter(serve_state_t cs, int user_id, ej_cookie_t session_id)
{
  struct user_filter_info *u = user_filter_info_allocate(cs, user_id, session_id);

  if (u->error_msgs || !u->prev_filter_expr || !*u->prev_filter_expr || !u->tree_mem || !u->prev_tree) {
    return html_reset_filter(cs, user_id, session_id);
  }

  char *new_filter_s = NULL;
  size_t new_filter_z = 0;
  FILE *new_filter_f = open_memstream(&new_filter_s, &new_filter_z);
  struct filter_env env;
  int count = 0;

  memset(&env, 0, sizeof(env));
  env.teamdb_state = cs->teamdb_state;
  env.serve_state = cs;
  env.mem = filter_tree_new();
  env.maxlang = cs->max_lang;
  env.langs = (const struct section_language_data * const *) cs->langs;
  env.maxprob = cs->max_prob;
  env.probs = (const struct section_problem_data * const *) cs->probs;
  env.rbegin = run_get_first(cs->runlog_state);
  env.rtotal = run_get_total(cs->runlog_state);
  run_get_header(cs->runlog_state, &env.rhead);
  struct timeval tv;
  gettimeofday(&tv, NULL);
  env.cur_time = tv.tv_sec;
  env.cur_time_us = tv.tv_sec * 1000000LL + tv.tv_usec;
  env.rentries = run_get_entries_ptr(cs->runlog_state);

  for (int i = env.rbegin; i < env.rtotal; i++) {
    env.rid = i;
    if (filter_tree_bool_eval(&env, u->prev_tree) > 0) {
      if (count > 0) fprintf(new_filter_f, "||");
      fprintf(new_filter_f, "id==%d", i);
      ++count;
    }
  }
  env.mem = filter_tree_delete(env.mem);
  fclose(new_filter_f); new_filter_f = NULL;

  if (count <= 0) {
    free(new_filter_s);
    return html_reset_filter(cs, user_id, session_id);
  }

  if (u->prev_filter_expr) xfree(u->prev_filter_expr);
  if (u->tree_mem) filter_tree_delete(u->tree_mem);
  if (u->error_msgs) xfree(u->error_msgs);
  u->error_msgs = 0;
  u->prev_filter_expr = 0;
  u->prev_tree = 0;
  u->tree_mem = 0;
  u->prev_filter_expr = new_filter_s; new_filter_s = NULL;
  u->tree_mem = filter_tree_new();
  filter_expr_set_string(u->prev_filter_expr, u->tree_mem, NULL, cs);
  filter_expr_init_parser(u->tree_mem, NULL, cs);
  int res = filter_expr_parse();
  if (res + filter_expr_nerrs == 0 && filter_expr_lval &&
      filter_expr_lval->type == FILTER_TYPE_BOOL) {
    u->prev_tree = filter_expr_lval;
  } else {
    return html_reset_filter(cs, user_id, session_id);
  }
}

void
html_reset_filter(serve_state_t state, int user_id, ej_cookie_t session_id)
{
  struct user_filter_info *u = user_filter_info_allocate(state, user_id, session_id);

  u->prev_first_run_set = 0;
  u->prev_first_run = 0;
  u->prev_last_run_set = 0;
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
html_reset_clar_filter(
        serve_state_t state,
        int user_id,
        ej_cookie_t session_id)
{
  struct user_filter_info *u = user_filter_info_allocate(state, user_id, session_id);

  u->prev_mode_clar = 0;
  u->prev_first_clar = -1;
  u->prev_last_clar = -10;
}


void
write_runs_dump(const serve_state_t state, FILE *f, const unsigned char *url,
                unsigned char const *charset)
{
  int total_runs, i, j;
  struct run_entry re;
  struct tm *pts;
  time_t start_time, dur;
  unsigned char *s;
  unsigned char statstr[128];
  time_t tmp_time;

  if (url && *url) {
    fprintf(f, "Content-type: text/plain; charset=%s\n\n", charset);
  }

  fprintf(f,
          "RunId"
          ";Time;Nsec;Time2;Date;Year;Mon;Day;Hour;Min;Sec"
          ";Dur;Dur_Day;Dur_Hour;Dur_Min;Dur_Sec"
          ";Size"
          ";IPV6_Flag;IP;SSL_Flag"
          ";Sha1"
          ";UserId;Login;Name"
          ";User_Inv;User_Ban;User_Lock"
          ";Problem;Variant"
          ";Language;Content_Type"
          ";Stat_Short;Status;Score;Score_Adj;Tests;Passed_Mode"
          ";Import_Flag;Hidden_Flag;RO_Flag;Locale_Id;Pages;Judge_Id"
          "\n");

  total_runs = run_get_total(state->runlog_state);
  start_time = run_get_start_time(state->runlog_state);
  for (i = 0; i < total_runs; i++) {
    if (run_get_entry(state->runlog_state, i, &re) < 0) {
      fprintf(f, "%d;Cannot read entry!\n", i);
      continue;
    }
    if (!run_is_valid_status(re.status)) {
      fprintf(f, "%d;Invalid status %d!\n", i, re.status);
      continue;
    }
    if (re.status == RUN_EMPTY) continue;

    fprintf(f, "%d;", i);
    fprintf(f, "%lld;%09d;", re.time, re.nsec);
    tmp_time = re.time;
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
    if (state->global->is_virtual) {
      start_time = run_get_virtual_start_time(state->runlog_state, re.user_id);
    }

    dur = re.time - start_time;
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
    fprintf(f, "%d;%s;%d;", re.ipv6_flag, xml_unparse_ip(re.a.ip), re.ssl_flag);

    s = (unsigned char*) re.h.sha1;
    for (j = 0; j < 20; j++) fprintf(f, "%02x", *s++);
    fprintf(f, ";");

    fprintf(f, "%d;", re.user_id);
    if (!(s = teamdb_get_login(state->teamdb_state, re.user_id))) {
      fprintf(f, "!INVALID TEAM!;");
    } else {
      fprintf(f, "%s;", s);
    }
    if (!(s = teamdb_get_name(state->teamdb_state, re.user_id))) {
      fprintf(f, "!INVALID TEAM!;");
    } else {
      fprintf(f, "%s;", s);
    }
    j = teamdb_get_flags(state->teamdb_state, re.user_id);
    s = "";
    if ((j & TEAM_INVISIBLE)) s = "I";
    fprintf(f, "%s;", s);
    s = "";
    if ((j & TEAM_BANNED)) s = "B";
    fprintf(f, "%s;", s);
    s = "";
    if ((j & TEAM_LOCKED)) s = "L";
    fprintf(f, "%s;", s);

    if (re.status == RUN_VIRTUAL_START || re.status == RUN_VIRTUAL_STOP) {
      //fprintf(f, "<problem>;<variant>;<lang_short>;<mime_type>;<short_status>;<status>;<score>;<score_adj>;<test>;<is_imported>;<is_hidden>;<is_readonly>;<locale_id>;<pages>;<judge_id>\n");
      fprintf(f, ";;;;");
      run_status_to_str_short(statstr, sizeof(statstr), re.status);
      fprintf(f, "%s;", statstr);
      run_status_str(re.status, statstr, sizeof(statstr), 0, 0);
      fprintf(f, "%s;", statstr);
      fprintf(f, ";;;;;;;;;\n");
      continue;
    }

    if (re.prob_id > 0 && re.prob_id <= state->max_prob
        /*&& state->probs[re.prob_id] && state->probs[re.prob_id]->short_name*/) {
      fprintf(f, "%s;", state->probs[re.prob_id]->short_name);
    } else {
      fprintf(f, "!INVALID PROBLEM %d!;", re.prob_id);
    }
    fprintf(f, "%d;", re.variant);

    if (!re.lang_id) {
      fprintf(f, ";%s;", mime_type_get_type(re.mime_type));
    } else if (re.lang_id > 0 && re.lang_id <= state->max_lang
               /*&& state->langs[re.lang_id] && state->langs[re.lang_id]->short_name*/) {
      fprintf(f, "%s;;", state->langs[re.lang_id]->short_name);
    } else {
      fprintf(f, "!INVALID LANGUAGE %d!;", re.lang_id);
    }

    run_status_to_str_short(statstr, sizeof(statstr), re.status);
    fprintf(f, "%s;", statstr);
    run_status_str(re.status, statstr, sizeof(statstr), 0, 0);
    fprintf(f, "%s;", statstr);
    fprintf(f, "%d;%d;", re.score, re.score_adj);
    fprintf(f, "%d;", re.test);
    fprintf(f, "%d;", (re.passed_mode > 0));
    fprintf(f, "%d;", re.is_imported);
    fprintf(f, "%d;", re.is_hidden);
    fprintf(f, "%d;", re.is_readonly);
    fprintf(f, "%d;%d;%d", re.locale_id, re.pages, re.j.judge_id);

    fprintf(f, "\n");
  }
}

static int
is_registered_today(
        const struct contest_desc *cnts,
        struct userlist_user *user,
        time_t from_time,
        time_t to_time)
{
  struct userlist_contest *uc = 0;

  if (!user || !user->contests) return 0;
  uc = (struct userlist_contest*) user->contests->first_down;
  while (uc) {
    if (uc->id == cnts->id
        && uc->create_time >= from_time
        && uc->create_time < to_time)
      return 1;
    uc = (struct userlist_contest*) uc->b.right;
  }
  return 0;
}

void
collect_telegram_reminder(
        const struct contest_desc *cnts,
        const serve_state_t cs,
        struct telegram_reminder_data *pdata)
{
  memset(pdata, 0, sizeof(*pdata));

  int r_beg = run_get_first(cs->runlog_state);
  int r_tot = run_get_total(cs->runlog_state);
  const struct run_entry *runs = run_get_entries_ptr(cs->runlog_state);
  time_t old_time = cs->current_time - 2 * 24 * 60 * 60;

  for (int run_id = r_beg; run_id < r_tot; ++run_id) {
    const struct run_entry *run = runs + run_id;
    if (run->status == RUN_PENDING_REVIEW) {
      ++pdata->pr_total;
      if (run->time < old_time)
        ++pdata->pr_too_old;
    }
  }
  pdata->unans_clars = clar_get_unanswered_count(cs->clarlog_state, old_time);
}

void
generate_daily_statistics(
        const struct contest_desc *cnts,
        const serve_state_t state,
        FILE *f,
        time_t from_time,
        time_t to_time,
        int utf8_mode)
{
  int u_max, u_tot;
  int *u_ind, *u_rev;
  int p_max, p_tot, i, j;
  int *p_ind, *p_rev;
  int row_sz, row_sh;
  unsigned char *solved = 0;
  int r_beg, r_tot, u, p, idx, max_u_total;
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
  int w, y;

  unsigned char *login, *name, probname[256], langname[256];

  int clar_total = 0, clar_total_today = 0, clar_from_judges = 0;
  int clar_to_judges = 0;
  time_t clar_time;
  struct clar_entry_v2 clar;

  /* u_tot             - total number of teams in index array
   * u_max             - maximal possible number of teams
   * u_ind[0..u_tot-1] - index array:   team_idx -> team_id
   * u_rev[0..u_max-1] - reverse index: team_id -> team_idx
   */
  if (state->global->disable_user_database > 0) {
    u_max = run_get_max_user_id(state->runlog_state) + 1;
  } else {
    u_max = teamdb_get_max_team_id(state->teamdb_state) + 1;
  }
  XALLOCAZ(u_ind, u_max);
  XALLOCAZ(u_rev, u_max);
  XALLOCAZ(u_reg, u_max);
  for (i = 1, u_tot = 0; i < u_max; i++) {
    u_rev[i] = -1;
    if (teamdb_lookup(state->teamdb_state, i)
        && teamdb_export_team(state->teamdb_state, i, &uinfo) >= 0) {
      if (is_registered_today(cnts, uinfo.user, from_time, to_time)) {
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
  p_max = state->max_prob + 1;
  XALLOCAZ(p_ind, p_max);
  XALLOCAZ(p_rev, p_max);
  for (i = 1, p_tot = 0; i < p_max; i++) {
    p_rev[i] = -1;
    if (state->probs[i]) {
      p_rev[i] = p_tot;
      p_ind[p_tot++] = i;
    }
  }

  r_beg = run_get_first(state->runlog_state);
  r_tot = run_get_total(state->runlog_state);
  runs = run_get_entries_ptr(state->runlog_state);

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

  XALLOCAZ(l_total, state->max_lang + 1);
  XALLOCAZ(l_ok, state->max_lang + 1);
  XALLOCAZ(l_ce, state->max_lang + 1);

  XALLOCAZ(p_total, p_tot);
  XALLOCAZ(p_ok, p_tot);

  for (i = r_beg, rcur = runs; i < r_tot; i++, rcur++) {
    if (rcur->time >= to_time) break;
    if (rcur->time < from_time) {
      if (rcur->status == RUN_EMPTY) continue;
      if (rcur->status != RUN_OK) continue;
      if (rcur->user_id <= 0 || rcur->user_id >= u_max || u_rev[rcur->user_id] < 0)
        continue;
      if (rcur->prob_id <= 0 || rcur->prob_id >= p_max
          || p_rev[rcur->prob_id] < 0)
        continue;
      solved[(u_rev[rcur->user_id] << row_sh) + p_rev[rcur->prob_id]] = 1;
      continue;
    }

    // ok, collect statistics
    if (run_is_invalid_status(rcur->status)) {
      fprintf(f, "error: run %d has invalid status %d\n", i, rcur->status);
      total_errors++;
      continue;
    }
    if (rcur->status == RUN_EMPTY) {
      total_empty++;
      continue;
    }
    if (rcur->user_id <= 0 || rcur->user_id >= u_max || (u = u_rev[rcur->user_id]) < 0) {
      fprintf(f, "error: run %d has invalid user_id %d\n",
              i, rcur->user_id);
      total_errors++;
      continue;
    }
    if (rcur->status >= RUN_PSEUDO_FIRST && rcur->status <= RUN_PSEUDO_LAST) {
      total_status[rcur->status]++;
      total_pseudo++;
      u_total[u]++;
      continue;
    }
    if (rcur->prob_id <= 0 || rcur->prob_id >= p_max
        || (p = p_rev[rcur->prob_id]) < 0) {
      fprintf(f, "error: run %d has invalid prob_id %d\n",
              i, rcur->prob_id);
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
    if (rcur->lang_id) {
      if (rcur->lang_id < 0 || rcur->lang_id > state->max_lang
          || !state->langs[rcur->lang_id]) {
        fprintf(f, "error: run %d has invalid lang_id %d\n",
                i, rcur->lang_id);
        total_errors++;
        u_errors[u]++;
        u_total[u]++;
        continue;
      }
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
      l_total[rcur->lang_id]++;
      l_ok[rcur->lang_id]++;
      p_total[p]++;
      p_ok[p]++;
      solved[idx] = 1;
      break;

    case RUN_COMPILE_ERR:
    case RUN_STYLE_ERR:
    case RUN_REJECTED:
      total_ce++;
      u_ce[u]++;
      u_total[u]++;
      l_total[rcur->lang_id]++;
      l_ce[rcur->lang_id]++;
      p_total[p]++;
      break;

    case RUN_RUN_TIME_ERR:
    case RUN_TIME_LIMIT_ERR:
    case RUN_WALL_TIME_LIMIT_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
    case RUN_SYNC_ERR:
    case RUN_PARTIAL:
      total_failed++;
      u_failed[u]++;
      u_total[u]++;
      l_total[rcur->lang_id]++;
      p_total[p]++;
      total_status[rcur->status]++;
      break;

    case RUN_CHECK_FAILED:
      total_cf++;
      u_cf[u]++;
      u_total[u]++;
      break;

    case RUN_ACCEPTED:
    case RUN_PENDING_REVIEW:
    case RUN_SUMMONED:
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

  clar_total = clar_get_total(state->clarlog_state);
  for (i = 0; i < clar_total; i++) {
    if (clar_get_record(state->clarlog_state, i, &clar) < 0) continue;
    if (clar.id < 0) continue;
    clar_time = clar.time;
    if (clar_time >= to_time) break;
    if (clar_time < from_time) continue;

    clar_total_today++;
    if (!clar.from) clar_from_judges++;
    else clar_to_judges++;
  }

  if (total_reg > 0) {
    fprintf(f, "New users registered: %d\n", total_reg);
    for (i = 0; i < u_tot; i++) {
      if (!u_reg[i]) continue;
      u = u_ind[i];
      if (!(login = teamdb_get_login(state->teamdb_state, u))) login = "";
      if (!(name = teamdb_get_name(state->teamdb_state, u))) name = "";
      w = 30; y = 0;
      if (utf8_mode) w = utf8_cnt(name, w, &y);
      fprintf(f, "  %-6d %-15.15s %-*.*s\n", u, login, w + y, w, name);
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
  if (total_status[RUN_SYNC_ERR] > 0)
    fprintf(f, "    Synchronization error: %d\n", total_status[RUN_SYNC_ERR]);
  if (total_status[RUN_WALL_TIME_LIMIT_ERR] > 0)
    fprintf(f, "    Wall time-limit exceeded:%d\n", total_status[RUN_WALL_TIME_LIMIT_ERR]);
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
      const unsigned char *long_name = state->probs[p]->long_name;
      if (!long_name) long_name = "";
      snprintf(probname, sizeof(probname), "%s: %s",
               state->probs[p]->short_name, long_name);
      w = 40; y = 0;
      if (utf8_mode) w = utf8_cnt(probname, w, &y);
      fprintf(f, "%-*.*s %-7d %-7d\n", w + y, w, probname, p_total[i],
              p_ok[i]);
    }
    fprintf(f, "\n");
  }

  if (total_runs > 0) {
    fprintf(f, "%-40.40s %-7.7s %-7.7s %-7.7s\n",
            "Language", "Total", "CE", "Success");
    if (l_total[0] > 0) {
      fprintf(f, "%-40.40s %-7d %-7d %-7d\n",
              "N/A (0)", l_total[0], l_ce[0], l_ok[0]);
    }
    for (i = 1; i <= state->max_lang; i++) {
      if (!state->langs[i]) continue;
      snprintf(langname, sizeof(langname), "%s - %s",
               state->langs[i]->short_name,
               state->langs[i]->long_name);
      w = 40; y = 0;
      if (utf8_mode) w = utf8_cnt(langname, w, &y);
      fprintf(f, "%-*.*s %-7d %-7d %-7d\n", w + y, w, langname, l_total[i],
              l_ce[i], l_ok[i]);
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
      name = teamdb_get_name(state->teamdb_state, u);
      if (!name || !*name) name = teamdb_get_login(state->teamdb_state, u);
      if (!name) name = "";

      w = 24; y = 0;
      if (utf8_mode) w = utf8_cnt(name, w, &y);
      fprintf(f, "%-7d %-*.*s %-7d %-7d %-7d %d/%d/%d %d/%d/%d/%d/%d/%d\n",
              u, w + y, w, name, u_total[j], u_ok[j], u_failed[j],
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
