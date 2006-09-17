/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006 Alexander Chernov <cher@ejudge.ru> */

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
#include "ej_types.h"
#include "ej_limits.h"

#include "new-server.h"
#include "filter_eval.h"
#include "misctext.h"
#include "mischtml.h"
#include "html.h"
#include "clarlog.h"
#include "base64.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

#define BITS_PER_LONG (8*sizeof(unsigned long)) 

static void
parse_error_func(void *data, unsigned char const *format, ...)
{
  va_list args;
  unsigned char buf[1024];
  int l;
  struct serve_state *state = (struct serve_state*) data;

  va_start(args, format);
  l = vsnprintf(buf, sizeof(buf) - 24, format, args);
  va_end(args);
  strcpy(buf + l, "\n");
  state->cur_user->error_msgs = xstrmerge1(state->cur_user->error_msgs, buf);
  filter_expr_nerrs++;
}

void
new_serve_write_priv_all_runs(FILE *f,
                              struct http_request_info *phr,
                              const struct contest_desc *cnts,
                              struct contest_extra *extra,
                              int first_run, int last_run,
                              unsigned char const *filter_expr)
{
  struct user_filter_info *u = 0;
  struct filter_env env;
  int i, r;
  int *match_idx = 0;
  int match_tot = 0;
  int transient_tot = 0;
  int *list_idx = 0;
  int list_tot = 0;
  unsigned char *str1 = 0, *str2 = 0;
  unsigned char durstr[64], statstr[64];
  int rid, attempts, disq_attempts, prev_successes;
  time_t run_time, start_time;
  const struct run_entry *pe;
  unsigned char *fe_html;
  int fe_html_len;
  unsigned char first_run_str[32] = { 0 }, last_run_str[32] = { 0 };
  unsigned char hbuf[128];
  unsigned char *prob_str;
  const unsigned char *imported_str;
  const unsigned char *rejudge_dis_str;
  unsigned long *displayed_mask = 0;
  int displayed_size = 0;
  unsigned char stat_select_name[32];
  unsigned char bbuf[1024];
  unsigned char endrow[256];

  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;

  if (!u) u = user_filter_info_allocate(cs, phr->user_id, phr->session_id);

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
    filter_expr_set_string(filter_expr, u->tree_mem, parse_error_func, cs);
    filter_expr_init_parser(u->tree_mem, parse_error_func, cs);
    i = filter_expr_parse();
    if (i + filter_expr_nerrs == 0 && filter_expr_lval &&
        filter_expr_lval->type == FILTER_TYPE_BOOL) {
      // parsing successful
      u->prev_tree = filter_expr_lval;
    } else {
      // parsing failed
      if (i + filter_expr_nerrs == 0 && filter_expr_lval &&
          filter_expr_lval->type != FILTER_TYPE_BOOL) {
        parse_error_func(cs, "bool expression expected");
      } else {
        parse_error_func(cs, "filter expression parsing failed");
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

  if (!u->error_msgs) {
    memset(&env, 0, sizeof(env));
    env.teamdb_state = cs->teamdb_state;
    env.serve_state = cs;
    env.mem = filter_tree_new();
    env.maxlang = cs->max_lang;
    env.langs = (const struct section_language_data * const *) cs->langs;
    env.maxprob = cs->max_prob;
    env.probs = (const struct section_problem_data * const *) cs->probs;
    env.rtotal = run_get_total(cs->runlog_state);
    run_get_header(cs->runlog_state, &env.rhead);
    env.cur_time = time(0);
    env.rentries = run_get_entries_ptr(cs->runlog_state);

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
          parse_error_func(cs, "run %d: %s", i, filter_strerror(-r));
          continue;
        }
        if (!r) continue;
      }
      match_idx[match_tot++] = i;
    }
    env.mem = filter_tree_delete(env.mem);
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

  fprintf(f, "<hr><h2>%s</h2>\n", _("Submissions"));

  if (!u->error_msgs) {
    fprintf(f, "<p><big>%s: %d, %s: %d, %s: %d</big></p>\n",
            _("Total submissions"), env.rtotal,
            _("Filtered"), match_tot,
            _("Shown"), list_tot);
    fprintf(f, "<p><big>Compiling and running: %d</big></p>\n", transient_tot);
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
             (u->prev_first_run>0)?u->prev_first_run - 1:u->prev_first_run);
  }
  if (u->prev_last_run) {
    snprintf(last_run_str, sizeof(last_run_str), "%d",
             (u->prev_last_run > 0)?u->prev_last_run - 1:u->prev_last_run);
  }
  html_start_form(f, 0, phr->self_url, phr->hidden_vars);
  fprintf(f, "<p>%s: <input type=\"text\" name=\"filter_expr\" size=\"32\" maxlength=\"128\" value=\"%s\">", _("Filter expression"), fe_html);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_first_run\" size=\"16\" value=\"%s\">", _("First run"), first_run_str);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_last_run\" size=\"16\" value=\"%s\">", _("Last run"), last_run_str);
  fprintf(f, "%s",
          new_serve_submit_button(bbuf, sizeof(bbuf), "filter_view", 1,
                                  _("View")));
  fprintf(f, "%s",
          new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                  NEW_SRV_ACTION_RESET_FILTER, 0));
  fprintf(f, "</form></p>\n");

  if (u->error_msgs) {
    fprintf(f, "<h2>Filter expression errors</h2>\n");
    fprintf(f, "<p><pre><font color=\"red\">%s</font></pre></p>\n",
            u->error_msgs);
  }

  if (!u->error_msgs) {
    switch (global->score_system_val) {
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
    if (phr->role == USER_ROLE_ADMIN) {
      fprintf(f, "<th>%s</th>", _("New result"));
      fprintf(f, "<th>%s</th>", _("Change result"));
    }
    fprintf(f, "<th>%s</th><th>%s</th></tr>\n",
            _("View source"), _("View report"));
    if (phr->role == USER_ROLE_ADMIN) {
      snprintf(endrow, sizeof(endrow), "</tr></form>\n");
    } else {
      snprintf(endrow, sizeof(endrow), "</tr>\n");
    }

    for (i = 0; i < list_tot; i++) {
      rid = list_idx[i];
      ASSERT(rid >= 0 && rid < env.rtotal);
      pe = &env.rentries[rid];

      displayed_mask[rid / BITS_PER_LONG] |= (1 << (rid % BITS_PER_LONG));

      if (phr->role == USER_ROLE_ADMIN) {
        html_start_form(f, 1, phr->self_url, phr->hidden_vars);
        html_hidden(f, "run_id", "%d", rid);
      }
      fprintf(f, "<tr>");

      if (pe->status == RUN_EMPTY) {
        run_status_str(pe->status, statstr, 0);
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
        if (global->score_system_val == SCORE_KIROV
            || global->score_system_val == SCORE_OLYMPIAD
            || global->score_system_val == SCORE_MOSCOW) {
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        if (phr->role == USER_ROLE_ADMIN) {
          fprintf(f, "<td>&nbsp;</td>");
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "%s", endrow);
        continue;
      }
      if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP) {
        run_time = pe->time;
        if (!env.rhead.start_time) run_time = 0;
        if (env.rhead.start_time > run_time) run_time = env.rhead.start_time;
        duration_str(1, run_time, env.rhead.start_time, durstr, 0);
        run_status_str(pe->status, statstr, 0);

        fprintf(f, "<td>%d</td>", rid);
        fprintf(f, "<td>%s</td>", durstr);
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>%s</td>", run_unparse_ip(pe->a.ip));
        fprintf(f, "<td>%d</td>", pe->user_id);
        fprintf(f, "<td>%s</td>",teamdb_get_name(cs->teamdb_state,pe->user_id));
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td>&nbsp;</td>");
        fprintf(f, "<td><b>%s</b></td>", statstr);
        fprintf(f, "<td>&nbsp;</td>");
        if (global->score_system_val == SCORE_KIROV
            || global->score_system_val == SCORE_OLYMPIAD
            || global->score_system_val == SCORE_MOSCOW) {
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "<td>&nbsp;</td>");
        if (phr->role == USER_ROLE_ADMIN) {
          fprintf(f, "<td>%s</td>",
                  new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                          NEW_SRV_ACTION_CLEAR_RUN, 0));
        } else {
          fprintf(f, "<td>&nbsp;</td>");
        }
        if (phr->role == USER_ROLE_ADMIN) {
          fprintf(f, "<td>&nbsp;</td>");
          fprintf(f, "<td>&nbsp;</td>");
        }
        fprintf(f, "%s", endrow);
        continue;
      }

      prev_successes = RUN_TOO_MANY;
      if (global->score_system_val == SCORE_KIROV && pe->status == RUN_OK
          && pe->prob_id > 0 && pe->prob_id <= cs->max_prob && !pe->is_hidden
          && cs->probs[pe->prob_id]
          && cs->probs[pe->prob_id]->score_bonus_total > 0) {
        if ((prev_successes = run_get_prev_successes(cs->runlog_state, rid))<0)
          prev_successes = RUN_TOO_MANY;
      }

      attempts = 0; disq_attempts = 0;
      if (global->score_system_val == SCORE_KIROV && !pe->is_hidden) {
        run_get_attempts(cs->runlog_state, rid, &attempts, &disq_attempts,
                         global->ignore_compile_errors);
      }
      run_time = pe->time;
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
      if (global->virtual) {
        start_time = run_get_virtual_start_time(cs->runlog_state, pe->user_id);
      }
      if (!start_time) run_time = 0;
      if (start_time > run_time) run_time = start_time;
      duration_str(global->show_astr_time, run_time, start_time,
                   durstr, 0);
      run_status_str(pe->status, statstr, 0);

      if (phr->role == USER_ROLE_ADMIN) {
        html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      }
      fprintf(f, "<td>%d%s</td>", rid, imported_str);
      fprintf(f, "<td>%s</td>", durstr);
      fprintf(f, "<td>%u</td>", pe->size);
      fprintf(f, "<td>%s</td>", run_unparse_ip(pe->a.ip));
      fprintf(f, "<td>%d</td>", pe->user_id);
      fprintf(f, "<td>%s</td>", teamdb_get_name(cs->teamdb_state, pe->user_id));
      if (pe->prob_id > 0 && pe->prob_id <= cs->max_prob
          && cs->probs[pe->prob_id]) {
        struct section_problem_data *cur_prob = cs->probs[pe->prob_id];
        int variant = 0;
        if (cur_prob->variant_num > 0) {
          variant = pe->variant;
          if (!variant) variant = find_variant(cs, pe->user_id, pe->prob_id);
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
        sprintf(prob_str, "??? - %d", pe->prob_id);
      }
      fprintf(f, "<td>%s</td>", prob_str);
      if (pe->lang_id > 0 && pe->lang_id <= cs->max_lang
          && cs->langs[pe->lang_id]) {
        fprintf(f, "<td>%s</td>", cs->langs[pe->lang_id]->short_name);
      } else {
        fprintf(f, "<td>??? - %d</td>", pe->lang_id);
      }
      write_html_run_status(cs, f, pe, 1, attempts, disq_attempts,
                            prev_successes);
      if (phr->role == USER_ROLE_ADMIN) {
        snprintf(stat_select_name, sizeof(stat_select_name), "stat_%d", rid);
        write_change_status_dialog(cs, f, stat_select_name, pe->is_imported);
        fprintf(f, "<td>%s</td>",
                new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                        NEW_SRV_ACTION_CHANGE_STATUS, 0));
      }

      fprintf(f, "<td><a href=\"%s\">%s</a></td>",
              new_serve_url(hbuf, sizeof(hbuf), phr,
                            NEW_SRV_ACTION_VIEW_SOURCE, "run_id=%d", rid),
              _("View"));
      if (pe->is_imported) {
        fprintf(f, "<td>N/A</td>");
      } else {
        fprintf(f, "<td><a href=\"%s\">%s</a></td>",
                new_serve_url(hbuf, sizeof(hbuf), phr,
                              NEW_SRV_ACTION_VIEW_REPORT, "run_id=%d", rid),
                _("View"));
      }
      fprintf(f, "</tr>\n");
      if (phr->role == USER_ROLE_ADMIN) {
        fprintf(f, "</form>\n");
      }
    }

    fprintf(f, "</table>\n");
    //fprintf(f, "</font>\n");
  }

  /*
  print_nav_buttons(state, f, 0, sid, self_url, hidden_vars, extra_args,
                    0, 0, 0, 0, 0, 0, 0);
  */

  if (phr->role == USER_ROLE_ADMIN &&!u->error_msgs) {
    fprintf(f, "<table border=\"0\"><tr><td>");
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    fprintf(f, "%s",
            new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                    NEW_SRV_ACTION_REJUDGE_ALL_1, 0));
    fprintf(f, "</form></td><td>\n");

    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    fprintf(f, "%s",
            new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                    NEW_SRV_ACTION_REJUDGE_SUSPENDED_1, 0));
    fprintf(f, "</form></td><td>\n");

    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_mask_size", "%d", displayed_size);
    fprintf(f, "<input type=\"hidden\" name=\"run_mask\" value=\"");
    for (i = 0; i < displayed_size; i++) {
      if (i > 0) fprintf(f, " ");
      fprintf(f, "%lx", displayed_mask[i]);
    }
    fprintf(f, "\">\n");
    fprintf(f, "%s",
            new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                    NEW_SRV_ACTION_REJUDGE_DISPLAYED_1, 0));
    fprintf(f, "</form></td><td>\n");

    if (global->score_system_val == SCORE_OLYMPIAD && cs->accepting_mode) {
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_mask_size", "%d", displayed_size);
      fprintf(f, "<input type=\"hidden\" name=\"run_mask\" value=\"");
      for (i = 0; i < displayed_size; i++) {
        if (i > 0) fprintf(f, " ");
        fprintf(f, "%lx", displayed_mask[i]);
      }
      fprintf(f, "\">\n");
      fprintf(f, "%s",
              new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                      NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1,
                                      0));
      fprintf(f, "</form></td><td>\n");
    }

    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    fprintf(f, "%s",
            new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                    NEW_SRV_ACTION_SQUEEZE_RUNS, 0));
    fprintf(f, "</form></td></tr></table>\n");

    /*
    html_start_form(f, 1, self_url, hidden_vars);
    fprintf(f, "%s: <select name=\"problem\"><option value=\"\">\n",
            _("Rejudge problem"));
    for (i = 1; i <= state->max_prob; i++)
      if (state->probs[i]) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                state->probs[i]->id, state->probs[i]->short_name, state->probs[i]->long_name);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
            ACTION_REJUDGE_PROBLEM, _("Rejudge!"));
    fprintf(f, "</form></p>\n");
    */
  }

  if (phr->role == USER_ROLE_ADMIN && global->enable_runlog_merge) {
    /*
    html_start_form(f, 2, self_url, hidden_vars);
    fprintf(f, "<table border=\"0\"><tr><td>%s: </td>\n",
            _("Import and merge XML runs log"));
    fprintf(f, "<td><input type=\"file\" name=\"file\"></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_MERGE_RUNS, _("Send!"));
    fprintf(f, "</tr></table></form>\n");
    */
  }

  /*
  fprintf(f, "<hr><h2>%s</h2>\n", _("Send a submission"));
  html_start_form(f, 2, self_url, hidden_vars);
  fprintf(f, "<table>\n");
  fprintf(f, "<tr><td>%s:</td><td>", _("Problem"));
  fprintf(f, "<select name=\"problem\"><option value=\"\">\n");
  for (i = 1; i <= state->max_prob; i++) {
    if (!state->probs[i]) continue;
    if (state->probs[i]->variant_num > 0) {
      for (j = 1; j <= state->probs[i]->variant_num; j++) {
        fprintf(f, "<option value=\"%d,%d\">%s-%d - %s\n",
                i, j, state->probs[i]->short_name, j, state->probs[i]->long_name);
      }
    } else {
      fprintf(f, "<option value=\"%d\">%s - %s\n",
              i, state->probs[i]->short_name, state->probs[i]->long_name);
    }
  }
  fprintf(f, "</select>\n");
  fprintf(f, "</td></tr>\n");
  fprintf(f, "<tr><td>%s:</td><td>", _("Language"));
  fprintf(f, "<select name=\"language\"><option value=\"\">\n");
  for (i = 1; i <= state->max_lang; i++) {
    if (!state->langs[i]) continue;
    fprintf(f, "<option value=\"%d\">%s - %s\n",
            i, state->langs[i]->short_name, state->langs[i]->long_name);
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

  print_nav_buttons(state, f, 0, sid, self_url, hidden_vars, extra_args,
                    0, 0, 0, 0, 0, 0, 0);
  */
}

/*
int
new_serve_write_priv_all_runs(FILE *f,
                              struct http_request_info *phr,
                              const struct contest_desc *cnts,
                              struct contest_extra *extra,
                              int first_run, int last_run,
                              unsigned char const *filter_expr)
*/

void
new_serve_write_all_clars(FILE *f,
                          struct http_request_info *phr,
                          const struct contest_desc *cnts,
                          struct contest_extra *extra,
                          int mode_clar, int first_clar, int last_clar)
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
  unsigned char *asubj = 0;
  int asubj_len = 0, new_len;
  int show_astr_time;
  unsigned char bbuf[1024];

  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  struct user_filter_info *u = 0;

  u = user_filter_info_allocate(cs, phr->user_id, phr->session_id);

  fprintf(f, "<hr><h2>%s</h2>\n", _("Messages"));

  start = run_get_start_time(cs->runlog_state);
  total = clar_get_total(cs->clarlog_state);
  if (!mode_clar) mode_clar = u->prev_mode_clar;
  if (!first_clar) first_clar = u->prev_first_clar;
  if (!last_clar) last_clar = u->prev_last_clar;
  if (!mode_clar) {
    mode_clar = 1;
    if (phr->role != USER_ROLE_ADMIN) mode_clar = 2;
  }
  u->prev_mode_clar = mode_clar;
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
  html_start_form(f, 0, phr->self_url, phr->hidden_vars);

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
  fprintf(f, "%s",
          new_serve_submit_button(bbuf, sizeof(bbuf), "filter_view_clars",
                                  1, _("View")));
  fprintf(f, "%s",
          new_serve_submit_button(bbuf, sizeof(bbuf), 0,
                                  NEW_SRV_ACTION_RESET_CLAR_FILTER, 0));
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

    clar_get_record(cs->clarlog_state, i, &time, &size, ip, &from, &to, &flags,
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
    fprintf(f, "<td>%s</td>", clar_flags_html(cs->clarlog_state, flags, from,
                                              to, 0, 0));
    fprintf(f, "<td>%s</td>", durstr);
    fprintf(f, "<td>%s</td>", ip);
    fprintf(f, "<td>%zu</td>", size);
    if (!from) {
      if (!j_from)
        fprintf(f, "<td><b>%s</b></td>", _("judges"));
      else
        fprintf(f, "<td><b>%s</b> (%s)</td>", _("judges"),
                teamdb_get_name(cs->teamdb_state, j_from));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_name(cs->teamdb_state, from));
    }
    if (!to && !from) {
      fprintf(f, "<td><b>%s</b></td>", _("all"));
    } else if (!to) {
      fprintf(f, "<td><b>%s</b></td>", _("judges"));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_name(cs->teamdb_state, to));
    }
    fprintf(f, "<td>%s</td>", asubj);
    fprintf(f, "<td><a href=\"%s\">%s</a></td>",
            new_serve_url(bbuf, sizeof(bbuf), phr,
                          NEW_SRV_ACTION_VIEW_CLAR,
                          "clar_id=%d", i), _("View"));
    fprintf(f, "</tr>\n");
  }
  fputs("</table>\n", f);

  /*
  print_nav_buttons(state, f, 0, sid, self_url, hidden_vars, extra_args,
                    0, 0, 0, 0, 0, 0, 0);
  */
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
