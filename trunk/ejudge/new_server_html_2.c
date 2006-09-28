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
#include "xml_utils.h"
#include "archive_paths.h"
#include "fileutl.h"
#include "mime_type.h"

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
#define BUTTON(a) new_serve_submit_button(bb, sizeof(bb), 0, a, 0)

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
  unsigned char bb[1024];
  unsigned char endrow[256];
  unsigned char *s;

  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;

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
  fprintf(f, "%s</form>",
          new_serve_submit_button(bb, sizeof(bb), "filter_view", 1, _("View")));
  html_start_form(f, 0, phr->self_url, phr->hidden_vars);
  fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_RESET_FILTER));
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
        fprintf(f, "<td>%s</td>", xml_unparse_ip(pe->a.ip));
        fprintf(f, "<td>%d</td>", pe->user_id);
        fprintf(f, "<td>%s</td>", teamdb_get_name_2(cs->teamdb_state,
                                                    pe->user_id));
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
          fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_CLEAR_RUN));
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
      if (global->is_virtual) {
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
      fprintf(f, "<td>%s</td>", xml_unparse_ip(pe->a.ip));
      fprintf(f, "<td>%d</td>", pe->user_id);
      fprintf(f, "<td>%s</td>", teamdb_get_name_2(cs->teamdb_state,
                                                  pe->user_id));
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
      } else if (!pe->lang_id) {
        fprintf(f, "<td>N/A</td>");
      } else {
        fprintf(f, "<td>??? - %d</td>", pe->lang_id);
      }
      write_html_run_status(cs, f, pe, 1, attempts, disq_attempts,
                            prev_successes);
      if (phr->role == USER_ROLE_ADMIN) {
        snprintf(stat_select_name, sizeof(stat_select_name), "stat_%d", rid);
        write_change_status_dialog(cs, f, stat_select_name, pe->is_imported);
        fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_CHANGE_STATUS));
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
    fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_REJUDGE_ALL_1));
    fprintf(f, "</form></td><td>\n");

    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_REJUDGE_SUSPENDED_1));
    fprintf(f, "</form></td><td>\n");

    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_mask_size", "%d", displayed_size);
    fprintf(f, "<input type=\"hidden\" name=\"run_mask\" value=\"");
    for (i = 0; i < displayed_size; i++) {
      if (i > 0) fprintf(f, " ");
      fprintf(f, "%lx", displayed_mask[i]);
    }
    fprintf(f, "\">\n");
    fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_REJUDGE_DISPLAYED_1));
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
      fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1));
      fprintf(f, "</form></td><td>\n");
    }

    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_SQUEEZE_RUNS));
    fprintf(f, "</form></td></tr></table>\n");

    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    fprintf(f, "%s: <select name=\"prob_id\"><option value=\"\"></option>\n",
            _("Rejudge problem"));
    for (i = 1; i <= cs->max_prob; i++) {
      if (!(prob = cs->probs[i])) continue;
      // check the problems that we ever can rejudge
      if (prob->type_val > 0) {
        if (prob->manual_checking > 0 && prob->check_presentation <= 0)
          continue;
        if (prob->manual_checking <= 0 && prob->disable_testing > 0
            && prob->enable_compilation <= 0)
          continue;
      } else {
        // standard problems
        if (prob->disable_testing > 0 && prob->enable_compilation <= 0)
          continue;
      }
      s = html_armor_string_dup(prob->long_name);
      fprintf(f, "<option value=\"%d\">%s - %s\n", i, prob->short_name, s);
      xfree(s); s = 0;
    }
    fprintf(f, "</select>%s\n", BUTTON(NEW_SRV_ACTION_REJUDGE_PROBLEM));
    fprintf(f, "</form>\n");
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
  if (global->is_virtual) show_astr_time = 1;

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
                teamdb_get_name_2(cs->teamdb_state, j_from));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_name_2(cs->teamdb_state, from));
    }
    if (!to && !from) {
      fprintf(f, "<td><b>%s</b></td>", _("all"));
    } else if (!to) {
      fprintf(f, "<td><b>%s</b></td>", _("judges"));
    } else {
      fprintf(f, "<td>%s</td>", teamdb_get_name_2(cs->teamdb_state, to));
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

static unsigned char *
html_unparse_bool(unsigned char *buf, size_t size, int value)
{
  snprintf(buf, size, "%s", value?_("Yes"):_("No"));
  return buf;
}
static unsigned char *
html_select_yesno(unsigned char *buf, size_t size,
                  const unsigned char *var_name, int value)
{
  unsigned char *s1 = "", *s2 = "";

  if (!var_name) var_name = "param";
  if (value) s2 = " selected=\"yes\"";
  else s1 = " selected=\"yes\"";

  snprintf(buf, size,
           "<select name=\"%s\">"
           "<option value=\"0\"%s>%s</option>"
           "<option value=\"1\"%s>%s</option>"
           "</select>",
           var_name, s1, _("No"), s2, _("Yes"));

  return buf;
}

void
new_serve_write_priv_source(const serve_state_t state,
                            FILE *f,
                            FILE *log_f,
                            struct http_request_info *phr,
                            const struct contest_desc *cnts,
                            struct contest_extra *extra,
                            int run_id)
{
  unsigned char *s;
  int i;
  path_t src_path;
  struct run_entry info;
  char *src_text = 0, *html_text;
  unsigned char *numb_txt;
  size_t src_len, html_len, numb_len;
  time_t start_time;
  int variant, src_flags;
  unsigned char const *nbsp = "<td>&nbsp;</td><td>&nbsp;</td>";
  unsigned char filtbuf1[128];
  unsigned char filtbuf2[256];
  unsigned char filtbuf3[512];
  unsigned char *ps1, *ps2;
  time_t run_time;
  int editable, run_id2;
  unsigned char bt[1024];
  unsigned char bb[1024];
  const struct section_problem_data *prob = 0;
  const struct section_language_data *lang = 0;
  const unsigned char *ss;
  const struct section_global_data *global = state->global;

  if (run_id < 0 || run_id >= run_get_total(state->runlog_state)) {
    fprintf(log_f, _("Invalid run_id."));
    return;
  }
  run_get_entry(state->runlog_state, run_id, &info);
  if (info.status > RUN_LAST
      || (info.status > RUN_MAX_STATUS && info.status < RUN_TRANSIENT_FIRST)) {
    fprintf(log_f, _("Information is not available."));
    return;
  }

  src_flags = archive_make_read_path(state, src_path, sizeof(src_path),
                                     global->run_archive_dir, run_id,
                                     0, 1);
  if (src_flags < 0) {
    fprintf(log_f, _("Invalid run_id."));
    return;
  }

  if (info.prob_id > 0 && info.prob_id <= state->max_prob)
    prob = state->probs[info.prob_id];
  if (info.lang_id > 0 && info.lang_id <= state->max_lang)
    lang = state->langs[info.lang_id];

  new_serve_header(f, extra->header_txt, 0, 0, phr->locale_id,
                   "%s [%s, %s]: %s %d", new_serve_unparse_role(phr->role),
                   phr->name_arm, extra->contest_arm,
                   _("Viewing run"), run_id);

  run_time = info.time;
  if (run_time < 0) run_time = 0;
  start_time = run_get_start_time(state->runlog_state);
  if (start_time < 0) start_time = 0;
  if (run_time < start_time) run_time = start_time;

  fprintf(f, "<h2>%s %d</h2>\n",
          _("Information about run"), run_id);
  fprintf(f, "<table>\n");
  fprintf(f, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Run ID"), info.run_id, nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s:%d</td>%s</tr>\n",
          _("Submission time"),
          duration_str(1, info.time, 0, 0, 0), info.nsec, nbsp);
  fprintf(f, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("Contest time"),
          duration_str(0, run_time, start_time, 0, 0), nbsp);

  // IP-address
  fprintf(f, "<tr><td>%s:</td>", _("Originator IP"));
  snprintf(filtbuf1, sizeof(filtbuf1), "ip == ip(%d)", run_id);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  fprintf(f, "<td>%s%s</a></td>",
          new_serve_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
                         "filter_expr=%s", filtbuf2),
          xml_unparse_ip(info.a.ip));
  fprintf(f, "%s</tr>\n", nbsp);

  // size
  snprintf(filtbuf1, sizeof(filtbuf1), "size == size(%d)", run_id);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  fprintf(f, "<tr><td>%s:</td><td>%s%u</a></td>%s</tr>\n",
          _("Size"),
          new_serve_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
                         "filter_expr=%s", filtbuf2),
          info.size, nbsp);

  // hash code
  snprintf(filtbuf1, sizeof(filtbuf1), "hash == hash(%d)", run_id);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  fprintf(f, "<tr><td>%s:</td><td>%s%s</a></td>%s</tr>\n",
          _("Hash value"),
          new_serve_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
                         "filter_expr=%s", filtbuf2),
          unparse_sha1(info.sha1), nbsp);

  // this is common flag for many editing forms below
  editable = 0;
  if (phr->role == USER_ROLE_ADMIN
      && opcaps_check(phr->caps, OPCAP_EDIT_RUN) >= 0
      && !info.is_readonly)
    editable = 1;

  // user_id
  snprintf(filtbuf1, sizeof(filtbuf1), "uid == %d", info.user_id);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s%d</a></td>",
          _("User ID"),
          new_serve_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
                         "filter_expr=%s", filtbuf2),
          info.user_id);
  if (editable) {
    fprintf(f, "<td>%s</td><td>%s</td></tr></form>",
            html_input_text(bt, sizeof(bt), "param", 10,
                            "%d", info.user_id),
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_USER_ID));
  } else {
    fprintf(f, "%s</tr>", nbsp);
  }

  // user login
  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("User login"),
          teamdb_get_login(state->teamdb_state, info.user_id));
  if (editable) {
    fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
            html_input_text(bt, sizeof(bt), "param", 10,
                            "%s",
                            teamdb_get_login(state->teamdb_state,
                                             info.user_id)),
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_USER_LOGIN));
  } else {
    fprintf(f, "%s</tr>\n", nbsp);
  }

  // user name
  s = html_armor_string_dup(teamdb_get_name(state->teamdb_state, info.user_id));
  fprintf(f, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("User name"), s, nbsp);
  xfree(s); s = 0;

  // problem
  if (prob) {
    snprintf(filtbuf1, sizeof(filtbuf1), "prob == \"%s\"",  prob->short_name);
    url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
    ps1 = new_serve_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
                         "filter_expr=%s", filtbuf2);
    ps2 = "</a>";
    ss = prob->short_name;
  } else {
    ps1 = ""; ps2 = "";
    snprintf(bb, sizeof(bb), "??? - %d", info.prob_id);
    ss = bb;
  }
  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s%s%s</td>", _("Problem"), ps1, ss, ps2);
  if (editable) {
    fprintf(f, "<td><select name=\"param\">\n");
    for (i = 1; i <= state->max_prob; i++) {
      if (!state->probs[i]) continue;
      ss = "";
      if (i == info.prob_id) ss = " selected=\"yes\"";
      s = html_armor_string_dup(state->probs[i]->long_name);
      fprintf(f, "<option value=\"%d\"%s>%s - %s\n",
              i, ss, state->probs[i]->short_name, s);
      xfree(s);
    }
    fprintf(f, "</select></td><td>%s</td></tr></form>\n",
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_PROB_ID));
  } else {
    fprintf(f, "%s</tr>\n", nbsp);
  }

  // variant
  if (prob && prob->variant_num > 0) {
    variant = info.variant;
    if (!variant) variant = find_variant(state, info.user_id, info.prob_id);
    if (variant > 0) {
      snprintf(filtbuf1, sizeof(filtbuf1), "prob == \"%s\" && variant == %d", 
               prob->short_name, variant);
      url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
      ps1 = new_serve_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
                           "filter_expr=%s", filtbuf2);
      ps2 = "</a>";
      if (info.variant > 0) {
        snprintf(bb, sizeof(bb), "%d", info.variant);
      } else {
        snprintf(bb, sizeof(bb), "%d (implicit)", variant);
      }
    } else {
      ps1 = ""; ps2 = "";
      snprintf(bb, sizeof(bb), "<i>unassigned</i>");
    }
    if (editable) {
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_id", "%d", run_id);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s%s%s</td>", _("Variant"), ps1, bb, ps2);
    if (editable) {
      fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
              html_input_text(bt, sizeof(bt), "param", 10, "%d", info.variant),
              BUTTON(NEW_SRV_ACTION_CHANGE_RUN_VARIANT));
    } else {
      fprintf(f, "%s</tr>\n", nbsp);
    }
  }

  // lang_id
  if (lang) {
    snprintf(filtbuf1, sizeof(filtbuf1), "lang == \"%s\"", lang->short_name);
    url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
    ps1 = new_serve_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
                         "filter_expr=%s", filtbuf2);
    ps2 = "</a>";
    ss = lang->short_name;
  } else if (!info.lang_id) {
    ps1 = ps2 = "";
    ss = "N/A";
  } else {
    snprintf(bb, sizeof(bb), "??? - %d", info.lang_id);
    ps1 = ps2 = "";
    ss = bb;
  }
  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s%s%s</td>", _("Language"), ps1, ss, ps2);
  if (editable) {
    fprintf(f, "<td><select name=\"param\">\n");
    for (i = 1; i <= state->max_lang; i++) {
      if (!state->langs[i]) continue;
      ss = "";
      if (i == info.lang_id) ss = " selected=\"yes\"";
      s = html_armor_string_dup(state->langs[i]->long_name);
      fprintf(f, "<option value=\"%d\"%s>%s - %s</option>\n",
              i, ss, state->langs[i]->short_name, s);
      xfree(s);
    }
    fprintf(f, "</select></td><td>%s</td></tr></form>\n",
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_VARIANT));
  } else {
    fprintf(f, "%s</tr>\n", nbsp);
  }

  // mime_type
  if (!info.lang_id) {
    fprintf(f, "<tr><td>%s</td><td>%s</td>%s</tr>\n",
	    _("Content type"), mime_type_get_type(info.mime_type), nbsp);
  }

  // is_imported
  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Imported?"), html_unparse_bool(bb, sizeof(bb), info.is_imported));
  if (editable) {
    fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
            html_select_yesno(bt, sizeof(bt), "param", info.is_imported),
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_IS_IMPORTED));
  } else {
    fprintf(f, "%s</tr>\n", nbsp);
  }

  // is_hidden
  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Hidden?"), html_unparse_bool(bb, sizeof(bb), info.is_hidden));
  if (editable) {
    fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
            html_select_yesno(bt, sizeof(bt), "param", info.is_hidden),
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_IS_HIDDEN));
  } else {
    fprintf(f, "%s</tr>\n", nbsp);
  }

  // is_readonly
  // special editable rules!
  if (phr->role==USER_ROLE_ADMIN && opcaps_check(phr->caps,OPCAP_EDIT_RUN)>=0){
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Read-only?"), html_unparse_bool(bb, sizeof(bb), info.is_readonly));
  if (phr->role==USER_ROLE_ADMIN && opcaps_check(phr->caps,OPCAP_EDIT_RUN)>=0){
    fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
            html_select_yesno(bt, sizeof(bt), "param", info.is_readonly),
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_IS_READONLY));
  } else {
    fprintf(f, "%s</tr>\n", nbsp);
  }

  // locale_id
  fprintf(f, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Locale ID"), info.locale_id, nbsp);

  // status
  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Status"), run_status_str(info.status, 0, 0));
  if (editable) {
    write_change_status_dialog(state, f, 0, info.is_imported);
    fprintf(f, "<td>%s</td></tr></form>\n",
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_STATUS));
  } else {
    fprintf(f, "%s</tr>\n", nbsp);
  }

  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD) {
    // test (number of tests passed)
    if (info.test <= 0) {
      snprintf(bb, sizeof(bb), "N/A");
    } else {
      snprintf(bb, sizeof(bb), "%d", info.test - 1);
    }
    if (editable) {
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_id", "%d", run_id);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Tests passed"), bb);
    if (editable) {
      fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
              html_input_text(bt, sizeof(bt), "param", 10, "%d", info.test - 1),
              BUTTON(NEW_SRV_ACTION_CHANGE_RUN_TEST));
    } else {
      fprintf(f, "%s</tr>\n", nbsp);
    }

    // score
    if (info.score < 0) {
      snprintf(bb, sizeof(bb), "N/A");
    } else {
      snprintf(bb, sizeof(bb), "%d", info.score);
    }
    if (editable) {
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_id", "%d", run_id);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Score gained"), bb);
    if (editable) {
      fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
              html_input_text(bt, sizeof(bt), "param", 10, "%d", info.score),
              BUTTON(NEW_SRV_ACTION_CHANGE_RUN_SCORE));
    } else {
      fprintf(f, "%s</tr>\n", nbsp);
    }

    // score_adj
    if (editable) {
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_id", "%d", run_id);
    }
    fprintf(f, "<tr><td>%s:</td><td>%d</td>", _("Score adjustment"),
            info.score_adj);
    if (editable) {
      fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
              html_input_text(bt, sizeof(bt), "param", 10, "%d",
                              info.score_adj),
              BUTTON(NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ));
    } else {
      fprintf(f, "%s</tr>\n", nbsp);
    }
  } else if (global->score_system_val == SCORE_MOSCOW) {
    // the first failed test
    if (info.test <= 0) {
      snprintf(bb, sizeof(bb), "N/A");
    } else {
      snprintf(bb, sizeof(bb), "%d", info.test);
    }
    if (editable) {
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_id", "%d", run_id);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Failed test"), bb);
    if (editable) {
      fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
              html_input_text(bt, sizeof(bt), "param", 10, "%d",
                              info.score_adj),
              BUTTON(NEW_SRV_ACTION_CHANGE_RUN_TEST));
    } else {
      fprintf(f, "%s</tr>\n", nbsp);
    }

    // score
    if (info.score < 0) {
      snprintf(bb, sizeof(bb), "N/A");
    } else {
      snprintf(bb, sizeof(bb), "%d", info.score);
    }
    if (editable) {
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_id", "%d", run_id);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Score gained"), bb);
    if (editable) {
      fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
              html_input_text(bt, sizeof(bt), "param", 10, "%d",
                              info.score_adj),
              BUTTON(NEW_SRV_ACTION_CHANGE_RUN_SCORE));
    } else {
      fprintf(f, "%s</tr>\n", nbsp);
    }

    // score_adj
    if (editable) {
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_id", "%d", run_id);
    }
    fprintf(f, "<tr><td>%s:</td><td>%d</td>", _("Score adjustment"),
            info.score_adj);
    if (editable) {
      fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
              html_input_text(bt, sizeof(bt), "param", 10, "%d",
                              info.score_adj),
              BUTTON(NEW_SRV_ACTION_CHANGE_RUN_SCORE_ADJ));
    } else {
      fprintf(f, "%s</tr>\n", nbsp);
    }
  } else {
    // ACM scoring system
    // first failed test
    if (info.test <= 0) {
      snprintf(bb, sizeof(bb), "N/A");
    } else {
      snprintf(bb, sizeof(bb), "%d", info.test);
    }
    if (editable) {
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_id", "%d", run_id);
    }
    fprintf(f, "<tr><td>%s:</td><td>%s</td>", _("Failed test"), bb);
    if (editable) {
      fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
              html_input_text(bt, sizeof(bt), "param", 10, "%d",
                              info.score_adj),
              BUTTON(NEW_SRV_ACTION_CHANGE_RUN_TEST));
    } else {
      fprintf(f, "%s</tr>\n", nbsp);
    }
  }

  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%d</td>", _("Pages printed"), info.pages);
  if (editable) {
    fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
            html_input_text(bt, sizeof(bt), "param", 10, "%d",
                            info.score_adj),
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_PAGES));
  } else {
    fprintf(f, "%s</tr>\n", nbsp);
  }
  fprintf(f, "</table>\n");

  fprintf(f, "<p>%s%s</a></p>\n",
          new_serve_aref(filtbuf3, sizeof(filtbuf3), phr,
                         NEW_SRV_ACTION_PRIV_DOWNLOAD_RUN,
                         "run_id=%d", run_id),
          _("Download run"));

  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
    fprintf(f, "<p>%s</p>", BUTTON(NEW_SRV_ACTION_CLEAR_RUN));
    fprintf(f, "</form>");
  }

  if (opcaps_check(phr->caps, OPCAP_PRINT_RUN) >= 0) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
    fprintf(f, "<p>%s</p>", BUTTON(NEW_SRV_ACTION_PRINT_RUN));
    fprintf(f, "</form>");
  }

  filtbuf1[0] = 0;
  if (run_id > 0) {
    run_id2 = run_find(state->runlog_state, run_id - 1, 0, info.user_id,
		       info.prob_id, info.lang_id);
    if (run_id2 >= 0) {
      snprintf(filtbuf1, sizeof(filtbuf1), "%d", run_id2);
    }
  }
  html_start_form(f, 1, phr->self_url, phr->hidden_vars);
  html_hidden(f, "run_id", "%d", run_id);
  fprintf(f, "<p>%s: %s %s</p>\n",
	  _("Compare this run with run"),
          html_input_text(bt, sizeof(bt), "run_id2", 10, "%s", filtbuf1),
	  BUTTON(NEW_SRV_ACTION_COMPARE_RUNS));

  if (global->enable_report_upload) {
    html_start_form(f, 2, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
    fprintf(f, "<p>%s: ", _("Upload judging protocol"));
    fprintf(f, "<input type=\"file\" name=\"file\">");
    if (global->team_enable_rep_view) {
      fprintf(f, "<input type=\"checkbox\" %s%s>%s",
              "name=\"judge_report\"", "checked=\"yes\"",
              _("Judge's report"));
      fprintf(f, "<input type=\"checkbox\" %s%s>%s",
              "name=\"user_report\"", "checked=\"yes\"",
              _("User's report"));
    }
    fprintf(f, "%s</form>\n", BUTTON(NEW_SRV_ACTION_UPLOAD_REPORT));
  }

  /*
  print_nav_buttons(state, f, run_id, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, _("Refresh"), _("View report"),
                    _("View team report"));
  */

  fprintf(f, "<hr>\n");
  if (prob && prob->type_val > 0 && info.mime_type > 0) {
    if(info.mime_type >= MIME_TYPE_IMAGE_FIRST
       && info.mime_type <= MIME_TYPE_IMAGE_LAST) {
      fprintf(f, "<p><img src=\"%s\"></p>",
              new_serve_url(filtbuf3, sizeof(filtbuf3), phr,
                            NEW_SRV_ACTION_PRIV_DOWNLOAD_RUN,
                            "run_id=%d&no_disp=1", run_id));
    } else {
      fprintf(f, "<p>The submission is binary and thus is not shown.</p>\n");
    }
  } else if (lang && lang->binary) {
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
    /*
    print_nav_buttons(state, f, run_id, sid, self_url, hidden_vars, extra_args,
                      _("Main page"), 0, 0, 0, _("Refresh"), _("View report"),
                      _("View team report"));
    */
  }
}

void
new_serve_write_priv_report(const serve_state_t cs,
                            FILE *f,
                            FILE *log_f,
                            struct http_request_info *phr,
                            const struct contest_desc *cnts,
                            struct contest_extra *extra,
                            int team_report_flag,
                            int run_id)
{
  path_t rep_path;
  char *rep_text = 0, *html_text;
  size_t rep_len = 0, html_len;
  int rep_flag, content_type;
  const unsigned char *t6 = _("Refresh");
  const unsigned char *t7 = _("View team report");
  const unsigned char *start_ptr = 0;
  struct run_entry re;
  const struct section_global_data *global = cs->global;
  const unsigned char *report_dir = global->report_archive_dir;

  if (team_report_flag && global->team_enable_rep_view) {
    t7 = t6;
    t6 = _("View report");
    report_dir = global->team_report_archive_dir;
    if (global->team_show_judge_report) {
      report_dir = global->report_archive_dir;
    }
  }

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)
      || run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    fprintf(log_f, _("Invalid run_id."));
    goto done;
  }
  if (re.status > RUN_MAX_STATUS) {
    fprintf(log_f, _("Report is not available."));
    goto done;
  }
  /*
  // FIXME: switch is here for begin more explicit
  if (!run_is_report_available(re.status))
  return -SRV_ERR_REPORT_NOT_AVAILABLE;
  */
  switch (re.status) {
  case RUN_IGNORED:
  case RUN_DISQUALIFIED:
  case RUN_PENDING:
    fprintf(log_f, _("Report is not available."));
    goto done;
  }

  /*
  print_nav_buttons(state, f, run_id, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, _("View source"), t6, t7);
  fprintf(f, "<hr>\n");
  */

  rep_flag = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                    global->xml_report_archive_dir,
                                    run_id, 0, 1);
  if (rep_flag >= 0) {
    if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0)<0){
      fprintf(log_f, _("Read error while reading %s."), rep_path);
      goto done;
    }
    content_type = get_content_type(rep_text, &start_ptr);
  } else {
    rep_flag = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                      report_dir, run_id, 0, 1);
    if (rep_flag < 0) {
      fprintf(log_f, _("Report file does not exist."));
      goto done;
    }
    if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0)<0){
      fprintf(log_f, _("Read error while reading %s."), rep_path);
      goto done;
    }
    content_type = get_content_type(rep_text, &start_ptr);
  }

  new_serve_header(f, extra->header_txt, 0, 0, phr->locale_id,
                   "%s [%s, %s]: %s %d", new_serve_unparse_role(phr->role),
                   phr->name_arm, extra->contest_arm,
                   _("Viewing report"), run_id);

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
      write_xml_team_testing_report(cs, f, start_ptr);
    } else {
      write_xml_testing_report(f, start_ptr, phr->session_id,phr->self_url, "");
    }
    break;
  default:
    abort();
  }

  /*
  xfree(rep_text);
  fprintf(f, "<hr>\n");
  print_nav_buttons(state, f, run_id, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, _("View source"), t6, t7);
  */

 done:;
  xfree(rep_text);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
