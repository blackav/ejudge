/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002 Alexander Chernov <cher@ispras.ru> */

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

#include "filter_tree.h"
#include "filter_eval.h"
#include "prepare.h"
#include "protocol.h"
#include "misctext.h"
#include "teamdb.h"
#include "clarlog.h"
#include "runlog.h"
#include "base64.h"
#include "html.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

struct user_state_info
{
  int prev_first_run;
  int prev_last_run;
  int prev_first_clar;
  int prev_last_clar;
  unsigned char *prev_filter_expr;
  struct filter_tree *prev_tree;
  struct filter_tree_mem *tree_mem;
  unsigned char *error_msgs;
};

static int users_a;
static struct user_state_info **users;
static struct user_state_info *cur_user;

static const unsigned char form_header_simple[] =
"form method=\"POST\" ENCTYPE=\"application/x-www-form-urlencoded\" action=";
static const unsigned char form_header_multipart[] =
"form method=\"POST\" ENCTYPE=\"multipart/form-data\" action=";

static void parse_error_func(unsigned char const *format, ...)
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

static void
write_all_runs(FILE *f, struct user_state_info *u,
               int priv_level, int first_run, int last_run,
               unsigned char const *self_url,
               unsigned char const *filter_expr,
               unsigned char const *hidden_vars)
{
  struct filter_env env;
  int i, r;
  int *match_idx;
  int match_tot;
  int *list_idx;
  int list_tot;
  unsigned char *str1 = 0, *str2 = 0;
  unsigned char durstr[64], statstr[64];
  int rid, attempts, score;
  time_t run_time;
  struct run_entry *pe;
  unsigned char *fe_html;
  int fe_html_len;
  unsigned char first_run_str[32] = { 0 }, last_run_str[32] = { 0 };

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
    filter_expr_set_string(filter_expr, u->tree_mem, parse_error_func);
    filter_expr_init_parser(u->tree_mem, parse_error_func);
    i = filter_expr_parse();
    if (i + filter_expr_nerrs == 0) {
      if (filter_expr_lval && filter_expr_lval->type != FILTER_TYPE_BOOL) {
        parse_error_func("bool expression expected");
      } else {
        u->prev_tree = filter_expr_lval;
      }
    } else {
      parse_error_func("filter expression parsing failed");
    }
  }

  if (u->error_msgs) {
    fprintf(f, "<hr><h2>%s</h2>\n", _("Submissions"));

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
               (u->prev_first_run > 0)?u->prev_first_run-1:u->prev_first_run);
    }
    if (u->prev_last_run) {
      snprintf(last_run_str, sizeof(last_run_str), "%d",
               (u->prev_last_run > 0)?u->prev_last_run - 1:u->prev_last_run);
    }
    fprintf(f, "<%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
    fprintf(f, "<p>%s: <input type=\"text\" name=\"filter_expr\" size=\"32\" maxlength=\"128\" value=\"%s\">", _("Filter expression"), fe_html);
    fprintf(f, "%s: <input type=\"text\" name=\"filter_first_run\" size=\"16\" value=\"%s\">", _("First run"), first_run_str);
    fprintf(f, "%s: <input type=\"text\" name=\"filter_last_run\" size=\"16\" value=\"%s\">", _("Last run"), last_run_str);
    fprintf(f, "<input type=\"submit\" name=\"filter_view\" value=\"%s\">", _("View"));
    fprintf(f, "</p></form>\n");

    fprintf(f, "<h2>Filter expression parse errors</h2>\n");
    fprintf(f, "<p><pre><font color=\"red\">%s</font></pre></p>\n",
            u->error_msgs);
    return;
  }

  memset(&env, 0, sizeof(env));
  env.mem = filter_tree_new();
  env.maxlang = max_lang;
  env.langs = langs;
  env.maxprob = max_prob;
  env.probs = probs;
  env.rtotal = run_get_total();
  run_get_header(&env.rhead);
  env.rentries = alloca(env.rtotal * sizeof(env.rentries[0]));
  env.cur_time = time(0);
  run_get_all_entries(env.rentries);

  match_idx = alloca((env.rtotal + 1) * sizeof(match_idx[0]));
  memset(match_idx, 0, (env.rtotal + 1) * sizeof(match_idx[0]));
  match_tot = 0;

  for (i = 0; i < env.rtotal; i++) {
    env.rid = i;
    if (u->prev_tree) {
      r = filter_tree_bool_eval(&env, u->prev_tree);
      if (r < 0) {
        parse_error_func("run %d: %s", i, filter_strerror(-r));
        continue;
      }
      if (!r) continue;
    }
    match_idx[match_tot++] = i;
  }
  filter_tree_delete(env.mem);
  if (u->error_msgs) {
    fprintf(f, "<hr><h2>%s</h2>\n", _("Submissions"));

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
               (u->prev_first_run > 0)?u->prev_first_run-1:u->prev_first_run);
    }
    if (u->prev_last_run) {
      snprintf(last_run_str, sizeof(last_run_str), "%d",
               (u->prev_last_run > 0)?u->prev_last_run - 1:u->prev_last_run);
    }
    fprintf(f, "<%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
    fprintf(f, "<p>%s: <input type=\"text\" name=\"filter_expr\" size=\"32\" maxlength=\"128\" value=\"%s\">", _("Filter expression"), fe_html);
    fprintf(f, "%s: <input type=\"text\" name=\"filter_first_run\" size=\"16\" value=\"%s\">", _("First run"), first_run_str);
    fprintf(f, "%s: <input type=\"text\" name=\"filter_last_run\" size=\"16\" value=\"%s\">", _("Last run"), last_run_str);
    fprintf(f, "<input type=\"submit\" name=\"filter_view\" value=\"%s\">", _("View"));
    fprintf(f, "</p></form>\n");

    fprintf(f, "<h2>Filter expression execution errors</h2>\n");
    fprintf(f, "<p><pre><font color=\"red\">%s</font></pre></p>\n",
            u->error_msgs);
    xfree(u->error_msgs);
    u->error_msgs = 0;
    return;
  }

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
  ASSERT(first_run >= 0 && first_run < match_tot);
  ASSERT(last_run >= 0 && last_run < match_tot);
  if (first_run <= last_run) {
    for (i = first_run; i <= last_run; i++)
      list_idx[list_tot++] = match_idx[i];
  } else {
    for (i = first_run; i >= last_run; i--)
      list_idx[list_tot++] = match_idx[i];
  }

  fprintf(f, "<hr><h2>%s</h2>\n", _("Submissions"));
  fprintf(f, "<p><big>%s: %d, %s: %d, %s: %d</big></p>\n",
          _("Total submissions"), env.rtotal,
          _("Filtered"), match_tot,
          _("Shown"), list_tot);

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
             (u->prev_first_run > 0)?u->prev_first_run - 1:u->prev_first_run);
  }
  if (u->prev_last_run) {
    snprintf(last_run_str, sizeof(last_run_str), "%d",
             (u->prev_last_run > 0)?u->prev_last_run - 1:u->prev_last_run);
  }
  fprintf(f, "<%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
  fprintf(f, "<p>%s: <input type=\"text\" name=\"filter_expr\" size=\"32\" maxlength=\"128\" value=\"%s\">", _("Filter expression"), fe_html);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_first_run\" size=\"16\" value=\"%s\">", _("First run"), first_run_str);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_last_run\" size=\"16\" value=\"%s\">", _("Last run"), last_run_str);
  fprintf(f, "<input type=\"submit\" name=\"filter_view\" value=\"%s\">", _("View"));
  fprintf(f, "</p></form>\n");

  switch (global->score_system_val) {
  case SCORE_ACM:
    str1 = _("Failed test");
    break;
  case SCORE_KIROV:
  case SCORE_OLYMPIAD:
    str1 = _("Tests passed");
    str2 = _("Score");
    break;
  default:
    abort();
  }

  //fprintf(f, "<font size=\"-1\">\n");
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

  for (i = 0; i < list_tot; i++) {
    rid = list_idx[i];
    ASSERT(rid >= 0 && rid < env.rtotal);
    pe = &env.rentries[rid];
    run_get_attempts(rid, &attempts);
    run_time = pe->timestamp;
    if (!env.rhead.start_time) run_time = 0;
    if (env.rhead.start_time > run_time) run_time = env.rhead.start_time;
    duration_str(global->show_astr_time, run_time, env.rhead.start_time,
                 durstr, 0);
    run_status_str(pe->status, statstr, 0);

    fprintf(f, "<%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
    fprintf(f, "<tr>");
    fprintf(f, "<td>%d</td>", rid);
    fprintf(f, "<td>%s</td>", durstr);
    fprintf(f, "<td>%zu</td>", pe->size);
    fprintf(f, "<td>%s</td>", run_unparse_ip(pe->ip));
    fprintf(f, "<td>%d</td>", pe->team);
    fprintf(f, "<td>%s</td>", teamdb_get_name(pe->team));
    if (pe->problem > 0 && pe->problem <= max_prob && probs[pe->problem]) {
      fprintf(f, "<td>%s</td>", probs[pe->problem]->short_name);
    } else {
      fprintf(f, "<td>??? - %d</td>", pe->problem);
    }
    if (pe->language > 0 && pe->language <= max_lang
        && langs[pe->language]) {
      fprintf(f, "<td>%s</td>", langs[pe->language]->short_name);
    } else {
      fprintf(f, "<td>??? - %d</td>", pe->language);
    }
    fprintf(f, "<td>%s</td>", statstr);

    if (pe->test <= 0) {
      fprintf(f, "<td>%s</td>\n", _("N/A"));
      if (global->score_system_val == SCORE_KIROV
          || global->score_system_val == SCORE_OLYMPIAD) {
        fprintf(f, "<td>%s</td>\n", _("N/A"));
      }
    } else if (global->score_system_val == SCORE_KIROV ||
               global->score_system_val == SCORE_OLYMPIAD) {
      fprintf(f, "<td>%d</td>\n", pe->test - 1);
      if (pe->score == -1) {
        fprintf(f, "<td>%s</td>", _("N/A"));
      } else {
        if (global->score_system_val == SCORE_OLYMPIAD) {
          fprintf(f, "<td>%d</td>", pe->score);
        } else {
          score = pe->score - attempts * probs[pe->problem]->run_penalty;
          if (score < 0) score = 0;
          fprintf(f, "<td>%d(%d)=%d</td>", pe->score, attempts, score);
        }
      }
    } else {
      fprintf(f, "<td>%d</td>\n", pe->test);
    }

    if (priv_level == PRIV_LEVEL_ADMIN) {
      if (global->score_system_val == SCORE_KIROV) {
        fprintf(f,
                "<td><select name=\"stat_%d\">"
                "<option value=\"\"></option>"
                "<option value=\"99\">%s</option>"
                "<option value=\"9\">%s</option>"
                "<optgroup label=\"%s:\">"
                "<option value=\"0\">%s</option>"
                "<option value=\"1\">%s</option>"
                "<option value=\"7\">%s</option>"
                "</optgroup>"
                "</select></td>\n", rid,
                _("Rejudge"), _("Ignore"), _("Judgements"),
                _("OK"), _("Compilation error"),
                _("Partial solution"));
      } else if (global->score_system_val == SCORE_OLYMPIAD) {
        fprintf(f,
                "<td><select name=\"stat_%d\">"
                "<option value=\"\"> "
                "<option value=\"99\">%s"
                "<option value=\"9\">%s</option>"
                "<optgroup label=\"%s:\">"
                "<option value=\"0\">%s</option>"
                "<option value=\"1\">%s</option>"
                "<option value=\"2\">%s</option>"
                "<option value=\"3\">%s</option>"
                "<option value=\"4\">%s</option>"
                "<option value=\"5\">%s</option>"
                "<option value=\"7\">%s</option>"
                "<option value=\"8\">%s</option>"
                "</optgroup>"
                "</select></td>\n", rid,
                _("Rejudge"), _("Ignore"), _("Judgements"),
                _("OK"), _("Compilation error"), _("Run-time error"),
                _("Time-limit exceeded"), _("Presentation error"),
                _("Wrong answer"), _("Partial solution"),
                _("Accepted"));
      } else {
        fprintf(f,
                "<td><select name=\"stat_%d\">"
                "<option value=\"\"> "
                "<option value=\"99\">%s"
                "<option value=\"9\">%s</option>"
                "<optgroup label=\"%s:\">"
                "<option value=\"0\">%s"
                "<option value=\"1\">%s"
                "<option value=\"2\">%s"
                "<option value=\"3\">%s"
                "<option value=\"4\">%s"
                "<option value=\"5\">%s"
                "</optgroup>"
                "</select></td>\n", rid,
                _("Rejudge"), _("Ignore"), _("Judgements"),
                _("OK"), _("Compilation error"), _("Run-time error"),
                _("Time-limit exceeded"), _("Presentation error"),
                _("Wrong answer"));
      }
      fprintf(f,
              "<td><input type=\"submit\" name=\"change_%d\""
              " value=\"%s\"></td>\n", rid, _("change"));
    }

    fprintf(f, "<td><input type=\"submit\" name=\"source_%d\" value=\"%s\"></td>\n", rid, _("view"));
    fprintf(f, "<td><input type=\"submit\" name=\"report_%d\" value=\"%s\"></td>\n", rid, _("view"));

    fprintf(f, "</tr></form>\n");
  }

  fprintf(f, "</table>\n");
  //fprintf(f, "</font>\n");

  fprintf(f, "<%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
  fprintf(f, "<p><input type=\"submit\" name=\"view_all_runs\" value=\"%s\">"
          "<input type=\"submit\" name=\"refresh\" value=\"%s\">"
          "<input type=\"submit\" name=\"stand\" value=\"%s\"></p>",
          _("View all"), _("Refresh"), _("Standings"));
  fprintf(f, "</form>\n");

  fprintf(f, "<p><%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
  fprintf(f, "<input type=\"submit\" name=\"rejudge_all\" value=\"%s\">",
          _("Rejudge all"));
  fprintf(f, "</form></p>\n");

  fprintf(f, "<p><%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
  fprintf(f, "%s: <select name=\"problem\"><option value=\"\">\n",
          _("Rejudge problem"));
  for (i = 1; i <= max_prob; i++)
    if (probs[i]) {
      fprintf(f, "<option value=\"%d\">%s - %s\n",
              probs[i]->id, probs[i]->short_name, probs[i]->long_name);
    }
  fprintf(f, "</select>\n");
  fprintf(f, "<input type=\"submit\" name=\"rejudge_problem\" value=\"%s\">",
          _("Rejudge!"));
  fprintf(f, "</form></p>\n");
}

static void
write_all_clars(FILE *f, struct user_state_info *u,
                int priv_level, int first_clar, int last_clar,
                unsigned char const *self_url,
                unsigned char const *hidden_vars)
{
  int total, i, j;

  int *list_idx;
  int list_tot;

  unsigned char first_clar_str[64] = { 0 }, last_clar_str[64] = { 0 };

  size_t size;
  time_t start, time;
  int from, to, flags;
  unsigned char subj[CLAR_MAX_SUBJ_LEN + 4];
  unsigned char psubj[CLAR_MAX_SUBJ_TXT_LEN + 4];
  unsigned char durstr[64];
  unsigned char ip[CLAR_MAX_IP_LEN + 4];
  unsigned char *asubj;
  int asubj_len = 0, new_len;

  fprintf(f, "<hr><h2>%s</h2>\n", _("Messages"));

  start = run_get_start_time();
  total = clar_get_total();
  if (!first_clar) first_clar = u->prev_first_clar;
  if (!last_clar) last_clar = u->prev_last_clar;
  u->prev_first_clar = first_clar;
  u->prev_last_clar = last_clar;

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
  ASSERT(first_clar >= 0 && first_clar < total);
  ASSERT(last_clar >= 0 && last_clar < total);

  list_idx = alloca((total + 1) * sizeof(list_idx[0]));
  memset(list_idx, 0, (total + 1) * sizeof(list_idx[0]));
  list_tot = 0;
  if (first_clar <= last_clar) {
    for (i = first_clar; i <= last_clar; i++)
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
  fprintf(f, "<%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_first_clar\" size=\"16\" value=\"%s\">", _("First clar"), first_clar_str);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_last_clar\" size=\"16\" value=\"%s\">", _("Last clar"), last_clar_str);
  fprintf(f, "<input type=\"submit\" name=\"filter_view_clars\" value=\"%s\">", _("View"));
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

    clar_get_record(i, &time, (unsigned long*) &size,
                    ip, &from, &to, &flags, subj);
    if (priv_level != PRIV_LEVEL_ADMIN && (from <= 0 || flags >= 2)) continue; 

    base64_decode_str(subj, psubj, 0);
    new_len = html_armored_strlen(psubj);
    new_len = (new_len + 7) & ~3;
    if (new_len > asubj_len) asubj = alloca(asubj_len = new_len);
    html_armor_string(psubj, asubj);
    if (!start) time = start;
    if (start > time) time = start;
    duration_str(global->show_astr_time, time, start, durstr, 0);

    fprintf(f, "<%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
    fprintf(f, "<tr>");
    fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", clar_flags_html(flags, from, to, 0, 0));
    fprintf(f, "<td>%s</td>", durstr);
    fprintf(f, "<td>%s</td>", ip);
    fprintf(f, "<td>%zu</td>", size);
    if (!from) {
      fprintf(f, "<td><b>%s</b></td>", _("judges"));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_name(from));
    }
    if (!to && !from) {
      fprintf(f, "<td><b>%s</b></td>", _("all"));
    } else if (!to) {
      fprintf(f, "<td><b>%s</b></td>", _("judges"));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_name(to));
    }
    fprintf(f, "<td>%s</td>", asubj);
    fprintf(f, "<input type=\"hidden\" name=\"enable_reply\" value=\"%d\">",
            !!from);
    fprintf(f, "<td><input type=\"submit\" name=\"clar_%d\" value=\"%s\"></td>\n", i, _("view"));

    fprintf(f, "</tr></form>\n");
  }
  fputs("</table>\n", f);

  fprintf(f, "<%s\"%s\">%s", form_header_simple, self_url, hidden_vars);
  fprintf(f, "<p><input type=\"submit\" name=\"view_all_clars\" value=\"%s\">"
          "<input type=\"submit\" name=\"refresh\" value=\"%s\">"
          "<input type=\"submit\" name=\"stand\" value=\"%s\"></p>",
          _("View all"), _("Refresh"), _("Standings"));
  fprintf(f, "</form>\n");
}

static struct user_state_info *
allocate_user_info(int user_id)
{
  if (user_id == -1) user_id = 0;
  ASSERT(user_id >= 0 && user_id < 32768);
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
  cur_user = users[user_id];
  return users[user_id];
}

void
write_master_page(FILE *f, int user_id, int priv_level,
                  int first_run, int last_run,
                  int first_clar, int last_clar,
                  unsigned char const *self_url,
                  unsigned char const *filter_expr,
                  unsigned char const *hidden_vars)
{
  struct user_state_info *u = allocate_user_info(user_id);

  write_all_runs(f, u, priv_level, first_run, last_run, self_url, filter_expr,
                 hidden_vars);
  write_all_clars(f, u, priv_level, first_clar, last_clar, self_url,
                  hidden_vars);
}

/**
 * Local variables:
 *  compile-command: "make -C .."
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */
