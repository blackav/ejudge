/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2002,2003 Alexander Chernov <cher@ispras.ru> */

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
#include "fileutl.h"
#include "client_actions.h"
#include "sformat.h"

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

enum
  {
    SID_DISABLED = 0,
    SID_EMBED,
    SID_URL,
    SID_COOKIE
  };

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

static const unsigned char form_header_get[] =
"form method=\"GET\" action=";
static const unsigned char form_header_post[] =
"form method=\"POST\" ENCTYPE=\"application/x-www-form-urlencoded\" action=";
static const unsigned char form_header_multipart[] =
"form method=\"POST\" ENCTYPE=\"multipart/form-data\" action=";

void
html_start_form(FILE *f, int mode, int sid_mode, unsigned long long sid,
                unsigned char const *self_url,
                unsigned char const *hidden_vars,
                unsigned char const *extra_args)
{
  switch (mode) {
  case 0:                       /* simple idempotent form */
    switch (sid_mode) {
    case SID_DISABLED:
    case SID_EMBED:
      fprintf(f, "<%s\"%s\">%s", form_header_post, self_url, hidden_vars);
      break;
    case SID_URL:
      fprintf(f, "<%s\"%s\">%s", form_header_get, self_url, hidden_vars);
      break;
    case SID_COOKIE:
      fprintf(f, "<%s\"%s\">%s", form_header_get, self_url, hidden_vars);
      break;
    default:
      SWERR(("unhandled sid_mode: %d", sid_mode));
    }
    break;
  case 1:                       /* simple side-effect form */
    switch (sid_mode) {
    case SID_DISABLED:
    case SID_EMBED:
      fprintf(f, "<%s\"%s\">%s", form_header_post, self_url, hidden_vars);
      break;
    case SID_URL:
      fprintf(f, "<%s\"%s\">%s", form_header_post, self_url, hidden_vars);
      break;
    case SID_COOKIE:
      fprintf(f, "<%s\"%s\">%s", form_header_post, self_url, hidden_vars);
      break;
    default:
      SWERR(("unhandled sid_mode: %d", sid_mode));
    }
    break;
  case 2:                       /* multipart form */
    switch (sid_mode) {
    case SID_DISABLED:
    case SID_EMBED:
      fprintf(f, "<%s\"%s\">%s", form_header_multipart, self_url, hidden_vars);
      break;
    case SID_URL:
      fprintf(f, "<%s\"%s\">%s", form_header_multipart, self_url, hidden_vars);
      break;
    case SID_COOKIE:
      fprintf(f, "<%s\"%s\">%s", form_header_multipart, self_url, hidden_vars);
      break;
    default:
      SWERR(("unhandled sid_mode: %d", sid_mode));
    }
    break;
  default:
    SWERR(("unhandled form start mode: %d", mode));
  }
}

unsigned char *
html_hyperref(unsigned char *buf, int size,
              int sid_mode, unsigned long long sid,
              unsigned char const *self_url,
              unsigned char const *extra_args,
              unsigned char const *format, ...)
{
  va_list args;
  unsigned char *out = buf;
  int left = size, n;

  ASSERT(sid_mode == SID_URL || sid_mode == SID_COOKIE);
  if (sid_mode == SID_COOKIE) {
    n = snprintf(out, left, "<a href=\"%s?sid_mode=%d%s",
                 self_url, SID_COOKIE, extra_args);
  } else {
    n = snprintf(out, left, "<a href=\"%s?sid_mode=%d&SID=%016llx%s",
                 self_url, SID_URL, sid, extra_args);
  }
  if (n >= left) n = left;
  left -= n; out += n;
  if (format && *format) {
    n = snprintf(out, left, "&");
    if (n >= left) n = left;
    left -= n; out += n;
    va_start(args, format);
    n = vsnprintf(out, left, format, args);
    va_end(args);
    if (n >= left) n = left;
    left -= n; out += n;

  }
  snprintf(out, left, "\">");
  return buf;
}

static void
print_nav_buttons(FILE *f,
                  int sid_mode, unsigned long long sid,
                  unsigned char const *self_url,
                  unsigned char const *hidden_vars,
                  unsigned char const *extra_args,
                  unsigned char const *t1,
                  unsigned char const *t2,
                  unsigned char const *t3,
                  unsigned char const *t4)
{
  unsigned char hbuf[128];

  if (!t1) t1 = _("Refresh");
  if (!t2) t2 = _("Standings");
  if (!t3) t3 = _("View teams");
  if (!t4) t4 = _("Log out");

  if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
    html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<table><tr>"
            "<td><input type=\"submit\" name=\"refresh\" value=\"%s\"></td>"
            "<td><input type=\"submit\" name=\"stand\" value=\"%s\"></td>"
            "<td><input type=\"submit\" name=\"viewteams\" value=\"%s\"></td>"
            "<td><input type=\"submit\" name=\"logout\" value=\"%s\"></td>"
            "</tr></table></form>\n", t1, t2, t3, t4);
  } else {
    fprintf(f, "<table><tr><td>");
    fprintf(f, "%s",
            html_hyperref(hbuf, sizeof(hbuf), sid_mode, sid, self_url,
                          extra_args, 0));
    fprintf(f, "%s</a></td><td>", t1);
    fprintf(f, "%s",
            html_hyperref(hbuf, sizeof(hbuf), sid_mode, sid, self_url,
                          extra_args, "stand=1"));
    fprintf(f, "%s</a></td><td>", t2);
    fprintf(f, "%s",
            html_hyperref(hbuf, sizeof(hbuf),
                          sid_mode, sid, self_url,
                          extra_args, "viewteams=1"));
    fprintf(f, "%s</a></td><td>", t3);
    fprintf(f, "%s",
            html_hyperref(hbuf, sizeof(hbuf), sid_mode, sid, self_url,
                          extra_args, "logout=1"));
    fprintf(f, "%s</a></td></tr></table>", t4);
  }

}

static void
parse_error_func(unsigned char const *format, ...)
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
write_change_status_dialog(FILE *f, unsigned char const *var_name,
                           int disable_rejudge_flag)
{
  const unsigned char *dis_str = "";

  if (!var_name) var_name = "status";
  if (disable_rejudge_flag) dis_str = " disabled=\"1\"";

  if (global->score_system_val == SCORE_KIROV) {
    fprintf(f,
            "<td><select name=\"%s\">"
            "<option value=\"\"></option>"
            "<option%s value=\"99\">%s</option>"
            "<option value=\"9\">%s</option>"
            "<optgroup label=\"%s:\">"
            "<option value=\"0\">%s</option>"
            "<option value=\"1\">%s</option>"
            "<option value=\"7\">%s</option>"
            "</optgroup>"
            "</select></td>\n", var_name, dis_str,
            _("Rejudge"), _("Ignore"), _("Judgements"),
            _("OK"), _("Compilation error"),
            _("Partial solution"));
  } else if (global->score_system_val == SCORE_OLYMPIAD) {
    fprintf(f,
            "<td><select name=\"%s\">"
            "<option value=\"\"> "
            "<option%s value=\"99\">%s"
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
            "</select></td>\n", var_name, dis_str,
            _("Rejudge"), _("Ignore"), _("Judgements"),
            _("OK"), _("Compilation error"), _("Run-time error"),
            _("Time-limit exceeded"), _("Presentation error"),
            _("Wrong answer"), _("Partial solution"),
            _("Accepted"));
  } else {
    fprintf(f,
            "<td><select name=\"%s\">"
            "<option value=\"\"> "
            "<option%s value=\"99\">%s"
            "<option value=\"9\">%s</option>"
            "<optgroup label=\"%s:\">"
            "<option value=\"0\">%s"
            "<option value=\"1\">%s"
            "<option value=\"2\">%s"
            "<option value=\"3\">%s"
            "<option value=\"4\">%s"
            "<option value=\"5\">%s"
            "</optgroup>"
            "</select></td>\n", var_name, dis_str,
            _("Rejudge"), _("Ignore"), _("Judgements"),
            _("OK"), _("Compilation error"), _("Run-time error"),
            _("Time-limit exceeded"), _("Presentation error"),
            _("Wrong answer"));
  }
}

static void
write_all_runs(FILE *f, struct user_state_info *u,
               int priv_level, int sid_mode, unsigned long long sid,
               int first_run, int last_run,
               unsigned char const *self_url,
               unsigned char const *filter_expr,
               unsigned char const *hidden_vars,
               unsigned char const *extra_args)
{
  struct filter_env env;
  int i, r;
  int *match_idx;
  int match_tot = 0;
  int *list_idx = 0;
  int list_tot = 0;
  unsigned char *str1 = 0, *str2 = 0;
  unsigned char durstr[64], statstr[64];
  int rid, attempts, score;
  time_t run_time, start_time;
  struct run_entry *pe;
  unsigned char *fe_html;
  int fe_html_len;
  unsigned char first_run_str[32] = { 0 }, last_run_str[32] = { 0 };
  unsigned char hbuf[128];
  int has_parse_errors = 0;
  int has_filter_errors = 0;
  unsigned char *prob_str;
  const unsigned char *imported_str;
  const unsigned char *rejudge_dis_str;

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
    has_parse_errors = 1;
  }

  if (!has_parse_errors) {
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
      has_filter_errors = 1;
    }
  }

  if (!has_parse_errors && !has_filter_errors) {
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

  fprintf(f, "<hr><h2>%s</h2>\n", _("Submissions"));

  if (!has_parse_errors && !has_filter_errors) {
    fprintf(f, "<p><big>%s: %d, %s: %d, %s: %d</big></p>\n",
            _("Total submissions"), env.rtotal,
            _("Filtered"), match_tot,
            _("Shown"), list_tot);
  }

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
  html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars, extra_args);
  fprintf(f, "<p>%s: <input type=\"text\" name=\"filter_expr\" size=\"32\" maxlength=\"128\" value=\"%s\">", _("Filter expression"), fe_html);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_first_run\" size=\"16\" value=\"%s\">", _("First run"), first_run_str);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_last_run\" size=\"16\" value=\"%s\">", _("Last run"), last_run_str);
  fprintf(f, "<input type=\"submit\" name=\"filter_view\" value=\"%s\">", _("View"));
  //fprintf(f, "</form>\n");
  //html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars);
  fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
          ACTION_RESET_FILTER, _("Reset filter"));
  fprintf(f, "</form></p>\n");

  if (u->error_msgs) {
    fprintf(f, "<h2>Filter expression errors</h2>\n");
    fprintf(f, "<p><pre><font color=\"red\">%s</font></pre></p>\n",
            u->error_msgs);
    if (has_filter_errors) {
      xfree(u->error_msgs);
      u->error_msgs = 0;
    }
  }

  if (!has_parse_errors && !has_filter_errors) {
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

      if (pe->status == RUN_EMPTY) {
        run_status_str(pe->status, statstr, 0);

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
        if (global->score_system_val == SCORE_KIROV ||
            global->score_system_val == SCORE_OLYMPIAD) {
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "</tr>\n");
        continue;
      }
      if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP) {
        run_time = pe->timestamp;
        if (!env.rhead.start_time) run_time = 0;
        if (env.rhead.start_time > run_time) run_time = env.rhead.start_time;
        duration_str(1, run_time, env.rhead.start_time, durstr, 0);
        run_status_str(pe->status, statstr, 0);

        fprintf(f, "<tr>");
        fprintf(f, "<td>%d</td>", rid);
        fprintf(f, "<td>%s</td>", durstr);
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>%s</td>", run_unparse_ip(pe->ip));
        fprintf(f, "<td>%d</td>", pe->team);
        fprintf(f, "<td>%s</td>", teamdb_get_name(pe->team));
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td><b>%s</b></td>", statstr);
        fprintf(f, "<td>&nbsp;</td>");
        if (global->score_system_val == SCORE_KIROV ||
            global->score_system_val == SCORE_OLYMPIAD) {
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "<td>&nbsp;</td>");
        if (priv_level == PRIV_LEVEL_ADMIN) {
          fprintf(f, "<td>");
          html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars,
                          extra_args);
          fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">",
                  rid);
          fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
                  ACTION_CLEAR_RUN, _("clear"));
          fprintf(f, "</form></td>");
        } else {
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "</tr>\n");
        continue;
      }

      run_get_attempts(rid, &attempts, global->ignore_compile_errors);
      run_time = pe->timestamp;
      imported_str = "";
      rejudge_dis_str = "";
      if (pe->is_imported) {
        imported_str = "*";
        rejudge_dis_str = " disabled=\"1\"";
      }
      start_time = env.rhead.start_time;
      if (global->virtual) {
        start_time = run_get_virtual_start_time(pe->team);
      }
      if (!start_time) run_time = 0;
      if (start_time > run_time) run_time = start_time;
      duration_str(global->show_astr_time, run_time, start_time,
                   durstr, 0);
      run_status_str(pe->status, statstr, 0);

      if (priv_level == PRIV_LEVEL_ADMIN
          || sid_mode == SID_DISABLED
          || sid_mode == SID_EMBED) {
        html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars,
                        extra_args);
      }
      fprintf(f, "<tr>");
      fprintf(f, "<td>%d%s</td>", rid, imported_str);
      fprintf(f, "<td>%s</td>", durstr);
      fprintf(f, "<td>%zu</td>", pe->size);
      fprintf(f, "<td>%s</td>", run_unparse_ip(pe->ip));
      fprintf(f, "<td>%d</td>", pe->team);
      fprintf(f, "<td>%s</td>", teamdb_get_name(pe->team));
      if (pe->problem > 0 && pe->problem <= max_prob && probs[pe->problem]) {
        struct section_problem_data *cur_prob = probs[pe->problem];
        int variant = 0;
        if (cur_prob->variant_num > 0) {
          variant = find_variant(pe->team, pe->problem);
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
                  "<option%s value=\"99\">%s</option>"
                  "<option value=\"9\">%s</option>"
                  "<optgroup label=\"%s:\">"
                  "<option value=\"0\">%s</option>"
                  "<option value=\"1\">%s</option>"
                  "<option value=\"7\">%s</option>"
                  "</optgroup>"
                  "</select></td>\n", rid, rejudge_dis_str,
                  _("Rejudge"), _("Ignore"), _("Judgements"),
                  _("OK"), _("Compilation error"),
                  _("Partial solution"));
        } else if (global->score_system_val == SCORE_OLYMPIAD) {
          fprintf(f,
                  "<td><select name=\"stat_%d\">"
                  "<option value=\"\"> "
                  "<option%s value=\"99\">%s"
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
                  "</select></td>\n", rid, rejudge_dis_str,
                  _("Rejudge"), _("Ignore"), _("Judgements"),
                  _("OK"), _("Compilation error"), _("Run-time error"),
                  _("Time-limit exceeded"), _("Presentation error"),
                  _("Wrong answer"), _("Partial solution"),
                  _("Accepted"));
        } else {
          fprintf(f,
                  "<td><select name=\"stat_%d\">"
                  "<option value=\"\"> "
                  "<option%s value=\"99\">%s"
                  "<option value=\"9\">%s</option>"
                  "<optgroup label=\"%s:\">"
                  "<option value=\"0\">%s"
                  "<option value=\"1\">%s"
                  "<option value=\"2\">%s"
                  "<option value=\"3\">%s"
                  "<option value=\"4\">%s"
                  "<option value=\"5\">%s"
                  "</optgroup>"
                  "</select></td>\n", rid, rejudge_dis_str,
                  _("Rejudge"), _("Ignore"), _("Judgements"),
                  _("OK"), _("Compilation error"), _("Run-time error"),
                  _("Time-limit exceeded"), _("Presentation error"),
                  _("Wrong answer"));
        }
        fprintf(f,
                "<td><input type=\"submit\" name=\"change_%d\""
                " value=\"%s\"></td>\n", rid, _("change"));
      }

      switch (sid_mode) {
      case SID_DISABLED: case SID_EMBED:
        fprintf(f, "<td><input type=\"submit\" name=\"source_%d\" value=\"%s\"></td>\n", rid, _("View"));
        if (pe->is_imported) {
          fprintf(f, "<td>N/A</td>");
        } else {
          fprintf(f, "<td><input type=\"submit\" name=\"report_%d\" value=\"%s\"></td>\n", rid, _("View"));
        }
        fprintf(f, "</tr></form>\n");
        break;
      case SID_COOKIE: case SID_URL:
        fprintf(f, "<td>");
        fprintf(f, "%s",
                html_hyperref(hbuf, sizeof(hbuf),
                              sid_mode, sid, self_url,
                              extra_args, "source_%d=1", rid));
        fprintf(f, "%s</a></td>", _("View"));
        if (pe->is_imported) {
          fprintf(f, "<td>N/A</td>");
        } else {
          fprintf(f, "<td>");
          fprintf(f, "%s",
                  html_hyperref(hbuf, sizeof(hbuf),
                                sid_mode, sid, self_url,
                                extra_args, "report_%d=1", rid));
          fprintf(f, "%s</a></td>", _("View"));
        }
        fprintf(f, "</tr>\n");
        if (priv_level == PRIV_LEVEL_ADMIN) {
          fprintf(f, "</form>\n");
        }
        break;
      default:
        abort();
      }
    }

  fprintf(f, "</table>\n");
  //fprintf(f, "</font>\n");
  }

  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    0, 0, 0, 0);

  if (priv_level == PRIV_LEVEL_ADMIN &&!has_parse_errors&&!has_filter_errors) {
    fprintf(f, "<table border=\"0\"><tr><td>");
    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_REJUDGE_ALL_1, _("Rejudge all"));
    fprintf(f, "</form></td><td>\n");

    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_SQUEEZE_RUNS, _("Squeeze runs"));
    fprintf(f, "</form></td></tr></table>\n");

    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "%s: <select name=\"problem\"><option value=\"\">\n",
            _("Rejudge problem"));
    for (i = 1; i <= max_prob; i++)
      if (probs[i]) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                probs[i]->id, probs[i]->short_name, probs[i]->long_name);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_REJUDGE_PROBLEM, _("Rejudge!"));
    fprintf(f, "</form></p>\n");
  }

  if (priv_level == PRIV_LEVEL_ADMIN && global->enable_runlog_merge) {
    html_start_form(f, 2, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<table border=\"0\"><tr><td>%s: </td>\n",
            _("Import and merge XML runs log"));
    fprintf(f, "<td><input type=\"file\" name=\"file\"></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_MERGE_RUNS, _("Send!"));
    fprintf(f, "</tr></table></form>\n");
  }
}

static void
write_all_clars(FILE *f, struct user_state_info *u,
                int priv_level, int sid_mode, unsigned long long sid,
                int first_clar, int last_clar,
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
  int from, to, flags;
  unsigned char subj[CLAR_MAX_SUBJ_LEN + 4];
  unsigned char psubj[CLAR_MAX_SUBJ_TXT_LEN + 4];
  unsigned char durstr[64];
  unsigned char ip[CLAR_MAX_IP_LEN + 4];
  unsigned char hbuf[128];
  unsigned char *asubj = 0;
  int asubj_len = 0, new_len;
  int show_astr_time;

  fprintf(f, "<hr><h2>%s</h2>\n", _("Messages"));

  start = run_get_start_time();
  total = clar_get_total();
  if (!first_clar) first_clar = u->prev_first_clar;
  if (!last_clar) last_clar = u->prev_last_clar;
  u->prev_first_clar = first_clar;
  u->prev_last_clar = last_clar;
  show_astr_time = global->show_astr_time;
  if (global->virtual) show_astr_time = 1;

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
  html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars, extra_args);
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
    duration_str(show_astr_time, time, start, durstr, 0);

    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars, extra_args);
    }
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
    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      fprintf(f, "<td><input type=\"submit\" name=\"clar_%d\" value=\"%s\"></td>\n", i, _("View"));
    } else {
      fprintf(f, "<td>%s%s</a></td>",
              html_hyperref(hbuf, sizeof(hbuf),
                            sid_mode, sid, self_url, extra_args,
                            "clar_%d=1", i),
              _("View"));
    }

    fprintf(f, "</tr>\n");
    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      fprintf(f, "</form>\n");
    }
  }
  fputs("</table>\n", f);

  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    0, 0, 0, 0);
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
                  int sid_mode, unsigned long long sid,
                  int first_run, int last_run,
                  int first_clar, int last_clar,
                  unsigned char const *self_url,
                  unsigned char const *filter_expr,
                  unsigned char const *hidden_vars,
                  unsigned char const *extra_args)
{
  struct user_state_info *u = allocate_user_info(user_id);

  write_all_runs(f, u, priv_level, sid_mode, sid, first_run, last_run,
                 self_url, filter_expr, hidden_vars, extra_args);
  write_all_clars(f, u, priv_level, sid_mode, sid, first_clar, last_clar,
                  self_url, hidden_vars, extra_args);
}

void
write_priv_standings(FILE *f, int sid_mode, unsigned long long sid,
                     unsigned char const *self_url,
                     unsigned char const *hidden_vars,
                     unsigned char const *extra_args)
{
  write_standings_header(f, 1, 0, 0, 0);

  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), _("Refresh"), 0, 0);

  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD)
    do_write_kirov_standings(f, 1, 0, 0);
  else
    do_write_standings(f, 1, 0, 0, 0);

  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), _("Refresh"), 0, 0);
}

int
write_priv_source(FILE *f, int user_id, int priv_level,
                  int sid_mode, unsigned long long sid,
                  unsigned char const *self_url,
                  unsigned char const *hidden_vars,
                  unsigned char const *extra_args,
                  int run_id)
{
  unsigned char src_base[64];
  unsigned char *s;
  int i;
  path_t src_path;
  struct run_entry info;
  char *src_text = 0, *html_text;
  size_t src_len, html_len;
  time_t start_time;
  int variant;
  unsigned char const *nbsp = "<td>&nbsp;</td><td>&nbsp;</td>";

  if (run_id < 0 || run_id >= run_get_total()) return -SRV_ERR_BAD_RUN_ID;
  run_get_entry(run_id, &info);
  snprintf(src_base, sizeof(src_base), "%06d", run_id);
  pathmake(src_path, global->run_archive_dir, "/", src_base, 0);
  start_time = run_get_start_time();
  if (info.timestamp < start_time) info.timestamp = start_time;

  fprintf(f, "<h2>%s %d</h2>\n",
          _("Information about run"), run_id);
  if (info.status == RUN_VIRTUAL_START
      || info.status == RUN_VIRTUAL_STOP
      || info.status == RUN_EMPTY) {
    fprintf(f, "<p>Information is not available.</p>\n");
    fprintf(f, "<hr>\n");
    print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                      _("Main page"), 0, 0, 0);
    return 0;
  }
  fprintf(f, "<table>\n");
  fprintf(f, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Run ID"), info.submission, nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("Submission time"),
          duration_str(1, info.timestamp, start_time, 0, 0), nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("Contest time"),
          duration_str(0, info.timestamp, start_time, 0, 0), nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("Originator IP"), run_unparse_ip(info.ip), nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%zu</td>%s</tr>\n",
          _("Size"), info.size, nbsp);
  fprintf(f, "<tr><td>%s:</td><td>", _("Hash value"));
  s = (unsigned char*) &info.sha1;
  for (i = 0; i < 20; i++) fprintf(f, "%02x", *s++);
  fprintf(f, "</td>%s</tr>\n", nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%d</td>",
          _("User ID"), info.team);
  if (priv_level == PRIV_LEVEL_ADMIN) {
    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><input type=\"text\" name=\"run_user_id\" value=\"%d\" size=\"10\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", info.team, ACTION_RUN_CHANGE_USER_ID, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("User login"), teamdb_get_login(info.team));
  if (priv_level == PRIV_LEVEL_ADMIN) {
    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><input type=\"text\" name=\"run_user_login\" value=\"%s\" size=\"20\"></td><td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>", teamdb_get_login(info.team), ACTION_RUN_CHANGE_USER_LOGIN, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("User name"), teamdb_get_name(info.team), nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Problem"), probs[info.problem]->short_name);
  if (priv_level == PRIV_LEVEL_ADMIN) {
    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><select name=\"problem\"><option value=\"\">\n");
    for (i = 1; i <= max_prob; i++)
      if (probs[i]) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                probs[i]->id, probs[i]->short_name, probs[i]->long_name);
      }
    fprintf(f, "</select></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_PROB, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  if (probs[info.problem]->variant_num > 0) {
    variant = find_variant(info.team, info.problem);
    fprintf(f, "<tr><td>%s:</td><td>%d</td><td>%s</td></tr>\n",
            _("Variant"), variant, nbsp);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Language"),
          (langs[info.language])?(langs[info.language]->short_name):"");
  if (priv_level == PRIV_LEVEL_ADMIN) {
    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<td><select name=\"language\"><option value=\"\">\n");
    for (i = 1; i <= max_lang; i++)
      if (langs[i]) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                langs[i]->id, langs[i]->short_name, langs[i]->long_name);
      }
    fprintf(f, "</select></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_LANG, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Imported?"), info.is_imported?_("Yes"):_("No"));
  if (priv_level == PRIV_LEVEL_ADMIN) {
    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
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

  fprintf(f, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Locale ID"), info.locale_id, nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Status"), run_status_str(info.status, 0, 0));
  if (priv_level == PRIV_LEVEL_ADMIN) {
    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    write_change_status_dialog(f, 0, info.is_imported);
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></form>\n", ACTION_RUN_CHANGE_STATUS, _("Change"));
  } else {
    fprintf(f, "%s", nbsp);
  }
  fprintf(f, "</tr>\n");
  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD) {
    if (info.test <= 0) {
      fprintf(f, "<tr><td>%s:</td><td>N/A</td>%s</tr>\n",
              _("Tests passed"), nbsp);
      fprintf(f, "<tr><td>%s:</td><td>N/A</td>%s</tr>\n",
              _("Score gained"), nbsp);
    } else {
      fprintf(f, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
              _("Tests passed"), info.test - 1, nbsp);
      fprintf(f, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
              _("Score gained"), info.score, nbsp);
    }
  } else {
    if (info.test <= 0) {
      fprintf(f, "<tr><td>%s:</td><td>N/A</td>%s</tr>\n",
              _("Failed test"), nbsp);
    } else {
      fprintf(f, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
              _("Failed test"), info.test, nbsp);
    }
  }
  fprintf(f, "</table>\n");
  if (priv_level == PRIV_LEVEL_ADMIN) {
    html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<input type=\"hidden\" name=\"run_id\" value=\"%d\">", run_id);
    fprintf(f, "<p><input type=\"submit\" name=\"action_%d\" value=\"%s\"></p></form>\n", ACTION_CLEAR_RUN, _("Clear this entry"));
  }
  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0);
  fprintf(f, "<hr>\n");
  if (!info.is_imported) {
    if (generic_read_file(&src_text, 0, &src_len, 0, 0, src_path, "") < 0) {
      fprintf(f, "<big><font color=\"red\">Cannot read source text!</font></big>\n");
    } else {
      html_len = html_armored_memlen(src_text, src_len);
      html_text = alloca(html_len + 16);
      html_armor_text(src_text, src_len, html_text);
      html_text[html_len] = 0;
      fprintf(f, "<pre>%s</pre>", html_text);
      xfree(src_text);
    }
    fprintf(f, "<hr>\n");
    print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                      _("Main page"), 0, 0, 0);
  }
  return 0;
}

int
write_priv_report(FILE *f, int user_id, int priv_level,
                  int sid_mode, unsigned long long sid,
                  unsigned char const *self_url,
                  unsigned char const *hidden_vars,
                  unsigned char const *extra_args,
                  int run_id)
{
  unsigned char rep_base[64];
  path_t rep_path;
  char *rep_text = 0, *html_text;
  size_t rep_len = 0, html_len;

  if (run_id < 0 || run_id >= run_get_total()) return -SRV_ERR_BAD_RUN_ID;
  snprintf(rep_base, sizeof(rep_base), "%06d", run_id);
  pathmake(rep_path, global->report_archive_dir, "/", rep_base, 0);
  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0);
  fprintf(f, "<hr>\n");
  if (generic_read_file(&rep_text, 0, &rep_len, 0, 0, rep_path, "") < 0) {
    fprintf(f, "<big><font color=\"red\">Cannot read report text!</font></big>\n");
  } else {
    html_len = html_armored_memlen(rep_text, rep_len);
    html_text = alloca(html_len + 16);
    html_armor_text(rep_text, rep_len, html_text);
    html_text[html_len] = 0;
    fprintf(f, "<pre>%s</pre>", html_text);
    xfree(rep_text);
  }
  fprintf(f, "<hr>\n");
  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0);
  return 0;
}

int
write_priv_clar(FILE *f, int user_id, int priv_level,
                int sid_mode, unsigned long long sid,
                unsigned char const *self_url,
                unsigned char const *hidden_vars,
                unsigned char const *extra_args,
                int clar_id)
{
  time_t clar_time, start_time;
  size_t size, txt_subj_len, html_subj_len, txt_msg_len = 0, html_msg_len;
  int from, to, flags;
  unsigned char ip[CLAR_MAX_IP_LEN + 16];
  unsigned char b64_subj[CLAR_MAX_SUBJ_LEN + 16];
  unsigned char txt_subj[CLAR_MAX_SUBJ_LEN + 16];
  unsigned char *html_subj, *txt_msg = 0, *html_msg;
  unsigned char name_buf[64];

  if (clar_id < 0 || clar_id >= clar_get_total()) return -SRV_ERR_BAD_CLAR_ID;

  start_time = run_get_start_time();
  clar_get_record(clar_id, &clar_time,
                  (unsigned long*) &size, ip, &from, &to, &flags,b64_subj);
  txt_subj_len = base64_decode_str(b64_subj, txt_subj, 0);
  html_subj_len = html_armored_strlen(txt_subj);
  html_subj = alloca(html_subj_len);
  html_armor_string(txt_subj, html_subj);

  fprintf(f, "<h2>%s %d</h2>\n", _("Message"), clar_id);
  fprintf(f, "<table border=\"0\">\n");
  fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>\n", _("Clar ID"), clar_id);
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Flags"),
          clar_flags_html(flags, from, to, 0, 0));
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
          _("Time"), duration_str(1, clar_time, 0, 0, 0));
  if (!global->virtual) {
    fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Duration"), duration_str(0, clar_time, start_time, 0, 0));
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("IP address"), ip);
  fprintf(f, "<tr><td>%s:</td><td>%zu</td></tr>\n", _("Size"), size);
  fprintf(f, "<tr><td>%s:</td>", _("Sender"));
  if (!from) {
    fprintf(f, "<td><b>%s</b></td>", _("judges"));
  } else {
    fprintf(f, "<td>%s (%d)</td>", teamdb_get_name(from), from);
  }
  fprintf(f, "</tr>\n<tr><td>%s:</td>", _("To"));
  if (!to && !from) {
    fprintf(f, "<td><b>%s</b></td>", _("all"));
  } else if (!to) {
    fprintf(f, "<td><b>%s</b></td>", _("judges"));
  } else {
    fprintf(f, "<td>%s (%d)</td>", teamdb_get_name(to), to);
  }
  fprintf(f, "</tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>", _("Subject"), html_subj);
  fprintf(f, "</table>\n");
  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0);
  fprintf(f, "<hr>\n");

  snprintf(name_buf, sizeof(name_buf), "%06d", clar_id);
  if (generic_read_file((char**) &txt_msg, 0, &txt_msg_len, 0,
                        global->clar_archive_dir, name_buf, "") < 0) {
    fprintf(f, "<big><font color=\"red\">Cannot read message text!</font></big>\n");
  } else {
    txt_msg[txt_msg_len] = 0;
    html_msg_len = html_armored_strlen(txt_msg);
    html_msg = alloca(html_msg_len + 16);
    html_armor_string(txt_msg, html_msg);
    fprintf(f, "<pre>%s</pre><hr>", html_msg);
  }

  if (priv_level > PRIV_LEVEL_OBSERVER && from) {
    html_start_form(f, 2, sid_mode, sid, self_url, hidden_vars, extra_args);
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
  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0);

  return 0;
}

int
write_priv_users(FILE *f, int user_id, int priv_level,
                 int sid_mode, unsigned long long sid,
                 unsigned char const *self_url,
                 unsigned char const *hidden_vars,
                 unsigned char const *extra_args)
{
  int tot_teams, i, max_team, flags, runs_num = 0, clars_num = 0;
  unsigned char const *txt_login, *txt_name;
  unsigned char *html_login, *html_name;
  size_t html_login_len, html_name_len, runs_total = 0, clars_total = 0;
  unsigned char href_buf[128];
  struct teamdb_export info;
  unsigned char team_modes[128];

  tot_teams = teamdb_get_total_teams();
  max_team = teamdb_get_max_team_id();

  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, _("Refresh"), 0);
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
          "<th>&nbsp;</th>"
          "<th>&nbsp;</th>"
          "<th>&nbsp;</th>"
          "</tr>\n",
          _("User ID"),
          _("User login"),
          _("User name"),
          _("Flags"),
          _("Number of runs"), _("Size of runs"),
          _("Number of clars"), _("Size of clars"));
  for (i = 1; i <= max_team; i++) {
    if (!teamdb_lookup(i)) continue;
    run_get_team_usage(i, &runs_num, &runs_total);
    clar_get_team_usage(i, &clars_num, (unsigned long *) &clars_total);
    if (priv_level == PRIV_LEVEL_ADMIN) {
      html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
      fprintf(f, "<input type=\"hidden\" name=\"user_id\" value=\"%d\">", i);
    }
    fprintf(f, "<tr>");

    fprintf(f, "<td>");
    if (global->team_info_url[0]) {
      teamdb_export_team(i, &info);
      sformat_message(href_buf, sizeof(href_buf), global->team_info_url,
                      NULL, NULL, NULL, NULL, &info);
      fprintf(f, "<a href=\"%s\">", href_buf);
    }
    fprintf(f, "%d", i);
    if (global->team_info_url[0]) {
      fprintf(f, "</a>");
    }
    fprintf(f, "</td>");

    txt_login = teamdb_get_login(i);
    html_login_len = html_armored_strlen(txt_login);
    html_login = alloca(html_login_len + 16);
    html_armor_string(txt_login, html_login);
    fprintf(f, "<td>%s</td>", html_login);

    txt_name = teamdb_get_name(i);
    html_name_len = html_armored_strlen(txt_name);
    html_name = alloca(html_name_len + 16);
    html_armor_string(txt_name, html_name);
    fprintf(f, "<td>%s</td>", html_name);

    flags = teamdb_get_flags(i);
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
            "<td>%d</td>"
            "<td>%d</td>"
            "<td>%d</td>",
            runs_num, runs_total, clars_num, clars_total);

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

    fprintf(f, "</tr>\n");
    if (priv_level == PRIV_LEVEL_ADMIN) {
      fprintf(f, "</form>");
    }
  }
  fprintf(f, "</table>\n");

  print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, _("Refresh"), 0);
  return 0;
}

void
html_reset_filter(int user_id)
{
  struct user_state_info *u = allocate_user_info(user_id);

  u->prev_first_run = 0;
  u->prev_last_run = 0;
  u->prev_first_clar = 0;
  u->prev_last_clar = 0;
  xfree(u->prev_filter_expr); u->prev_filter_expr = 0;
  xfree(u->error_msgs); u->error_msgs = 0;
  if (u->tree_mem) {
    filter_tree_delete(u->tree_mem);
    u->tree_mem = 0;
  }
  u->prev_tree = 0;
}

void
write_runs_dump(FILE *f, unsigned char const *charset)
{
  int total_runs, i, j;
  struct run_entry re;
  struct tm *pts;
  time_t start_time, dur;
  unsigned char *s;
  unsigned char statstr[64];

  fprintf(f, "Content-type: text/plain; charset=%s\n\n", charset);

  total_runs = run_get_total();
  start_time = run_get_start_time();
  for (i = 0; i < total_runs; i++) {
    if (run_get_entry(i, &re) < 0) {
      fprintf(f, "%d;Cannot read entry!\n", i);
      continue;
    }
    fprintf(f, "%d;", i);
    fprintf(f, "%ld;", re.timestamp);
    pts = localtime(&re.timestamp);
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
    if (global->virtual) {
      start_time = run_get_virtual_start_time(re.team);
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

    fprintf(f, "%zu;", re.size);
    fprintf(f, "%s;", run_unparse_ip(re.ip));

    s = (unsigned char*) re.sha1;
    for (j = 0; j < 20; j++) fprintf(f, "%02x", *s++);
    fprintf(f, ";");

    fprintf(f, "%d;", re.team);
    if (!(s = teamdb_get_login(re.team))) {
      fprintf(f, "!INVALID TEAM!;");
    } else {
      fprintf(f, "%s;", s);
    }
    if (!(s = teamdb_get_name(re.team))) {
      fprintf(f, "!INVALID TEAM!;");
    } else {
      fprintf(f, "%s;", s);
    }
    j = teamdb_get_flags(re.team);
    s = "";
    if ((j & TEAM_INVISIBLE)) s = "I";
    fprintf(f, "%s;", s);
    s = "";
    if ((j & TEAM_BANNED)) s = "B";
    fprintf(f, "%s;", s);
    s = "";
    if ((j & TEAM_LOCKED)) s = "L";
    fprintf(f, "%s;", s);

    if (re.problem > 0 && re.problem <= max_prob
        && probs[re.problem] && probs[re.problem]->short_name) {
      fprintf(f, "%s;", probs[re.problem]->short_name);
    } else {
      fprintf(f, "!INVALID PROBLEM %d!;", re.problem);
    }

    if (re.language > 0 && re.language <= max_lang
        && langs[re.language] && langs[re.language]->short_name) {
      fprintf(f, "%s;", langs[re.language]->short_name);
    } else {
      fprintf(f, "!INVALID LANGUAGE %d!;", re.language);
    }

    run_status_str(re.status, statstr, 0);
    fprintf(f, "%s;", statstr);
    fprintf(f, "%d;", re.score);
    fprintf(f, "%d;", re.test);

    fprintf(f, "\n");
  }
}

void
write_raw_standings(FILE *f, unsigned char const *charset)
{
  fprintf(f, "Content-type: text/plain; charset=%s\n\n", charset);

  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD)
    do_write_kirov_standings(f, 1, 0, 1);
  else
    do_write_standings(f, 1, 0, 0, 1);
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
