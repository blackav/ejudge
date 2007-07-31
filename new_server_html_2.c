/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2006-2007 Alexander Chernov <cher@ejudge.ru> */

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
#include "new_server_proto.h"
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
#include "l10n.h"
#include "filehash.h"
#include "digest_io.h"
#include "testing_report_xml.h"
#include "full_archive.h"
#include "teamdb.h"
#include "userlist.h"
#include "team_extra.h"
#include "errlog.h"
#include "csv.h"
#include "sha.h"
#include "sformat.h"
#include "userlist_clnt.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <zlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/wait.h>
#include <ctype.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif
#define __(x) x

#define BITS_PER_LONG (8*sizeof(unsigned long)) 
#define BUTTON(a) ns_submit_button(bb, sizeof(bb), 0, a, 0)
#define ARMOR(s)  html_armor_buf(&ab, s)

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
ns_write_priv_all_runs(FILE *f,
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
  unsigned char durstr[64], statstr[128];
  int rid, attempts, disq_attempts, prev_successes;
  time_t run_time, start_time;
  const struct run_entry *pe;
  unsigned char *fe_html;
  int fe_html_len;
  unsigned char first_run_str[32] = { 0 }, last_run_str[32] = { 0 };
  unsigned char hbuf[128];
  unsigned char *prob_str;
  const unsigned char *imported_str;
  const unsigned char *examinable_str;
  const unsigned char *rejudge_dis_str;
  unsigned long *displayed_mask = 0;
  int displayed_size = 0;
  unsigned char bb[1024];
  unsigned char endrow[256];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob = 0;
  unsigned char cl[128];
  int prob_type = 0;

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
    fprintf(f, "<p><big>%s: %d</big></p>\n",
            _("Compiling and running"), transient_tot);
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
  fprintf(f, "<p>%s: <input type=\"text\" name=\"filter_expr\" size=\"32\" maxlength=\"128\" value=\"%s\"/>", _("Filter expression"), fe_html);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_first_run\" size=\"16\" value=\"%s\"/>", _("First run"), first_run_str);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_last_run\" size=\"16\" value=\"%s\"/>", _("Last run"), last_run_str);
  fprintf(f, "%s</form>",
          ns_submit_button(bb, sizeof(bb), "filter_view", 1, _("View")));
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

    // FIXME: class should be a parameter
    snprintf(cl, sizeof(cl), " class=\"b1\"");

    fprintf(f, "<table%s><tr><th%s>%s</th><th%s>%s</th>"
            "<th%s>%s</th><th%s>%s</th>"
            "<th%s>%s</th><th%s>%s</th>"
            "<th%s>%s</th><th%s>%s</th>"
            "<th%s>%s</th><th%s>%s</th>", 
            cl, cl, _("Run ID"), cl, _("Time"), cl, _("Size"), cl, _("IP"),
            cl, _("Team ID"), cl, _("Team name"), cl, _("Problem"),
            cl, _("Language"), cl, _("Result"), cl, str1);
    if (str2) {
      fprintf(f, "<th%s>%s</th>", cl, str2);
    }
    if (phr->role == USER_ROLE_ADMIN) {
      fprintf(f, "<th%s>%s</th>", cl, _("New result"));
      fprintf(f, "<th%s>%s</th>", cl, _("Change result"));
    }
    fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>\n",
            cl, _("View source"), cl, _("View report"));
    if (phr->role == USER_ROLE_ADMIN) {
      snprintf(endrow, sizeof(endrow), "</tr></form>\n");
    } else {
      snprintf(endrow, sizeof(endrow), "</tr>\n");
    }

    for (i = 0; i < list_tot; i++) {
      rid = list_idx[i];
      ASSERT(rid >= 0 && rid < env.rtotal);
      pe = &env.rentries[rid];

      displayed_mask[rid / BITS_PER_LONG] |= (1L << (rid % BITS_PER_LONG));

      if (phr->role == USER_ROLE_ADMIN) {
        html_start_form(f, 1, phr->self_url, phr->hidden_vars);
        html_hidden(f, "run_id", "%d", rid);
      }
      fprintf(f, "<tr>");

      if (pe->status == RUN_EMPTY) {
        run_status_str(pe->status, statstr, sizeof(statstr), 0, 0);
        fprintf(f, "<td%s>%d</td>", cl, rid);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s><b>%s</b></td>", cl, statstr);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        if (global->score_system_val == SCORE_KIROV
            || global->score_system_val == SCORE_OLYMPIAD
            || global->score_system_val == SCORE_MOSCOW) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        if (phr->role == USER_ROLE_ADMIN) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        fprintf(f, "%s", endrow);
        continue;
      }
      if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP) {
        run_time = pe->time;
        if (!env.rhead.start_time) run_time = 0;
        if (env.rhead.start_time > run_time) run_time = env.rhead.start_time;
        duration_str(1, run_time, env.rhead.start_time, durstr, 0);
        run_status_str(pe->status, statstr, sizeof(statstr), 0, 0);

        fprintf(f, "<td%s>%d</td>", cl, rid);
        fprintf(f, "<td%s>%s</td>", cl, durstr);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>%s</td>", cl, xml_unparse_ip(pe->a.ip));
        fprintf(f, "<td%s>%d</td>", cl, pe->user_id);
        /*
        fprintf(f, "<td%s>%s</td>", cl, teamdb_get_name_2(cs->teamdb_state,
                                                          pe->user_id));
        */
        fprintf(f, "<td%s><a href=\"%s\">%s</a></td>", cl,
                ns_url(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_USER_INFO,
                       "user_id=%d", pe->user_id),
                teamdb_get_name_2(cs->teamdb_state, pe->user_id));

        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s><b>%s</b></td>", cl, statstr);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        if (global->score_system_val == SCORE_KIROV
            || global->score_system_val == SCORE_OLYMPIAD
            || global->score_system_val == SCORE_MOSCOW) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        if (phr->role == USER_ROLE_ADMIN) {
          fprintf(f, "<td%s>%s</td>", cl, BUTTON(NEW_SRV_ACTION_CLEAR_RUN));
        } else {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (phr->role == USER_ROLE_ADMIN) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
          fprintf(f, "<td%s>&nbsp;</td>", cl);
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
                         cs->probs[pe->prob_id]->ignore_compile_errors);
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
      examinable_str = "";
      if (pe->is_examinable) {
        examinable_str = "!";
      }
      start_time = env.rhead.start_time;
      if (global->is_virtual) {
        start_time = run_get_virtual_start_time(cs->runlog_state, pe->user_id);
      }
      if (!start_time) run_time = 0;
      if (start_time > run_time) run_time = start_time;
      duration_str(global->show_astr_time, run_time, start_time,
                   durstr, 0);

      if (phr->role == USER_ROLE_ADMIN) {
        html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      }
      fprintf(f, "<td%s>%d%s%s</td>", cl, rid, imported_str, examinable_str);
      fprintf(f, "<td%s>%s</td>", cl, durstr);
      fprintf(f, "<td%s>%u</td>", cl, pe->size);
      fprintf(f, "<td%s>%s</td>", cl, xml_unparse_ip(pe->a.ip));
      fprintf(f, "<td%s>%d</td>", cl, pe->user_id);
      fprintf(f, "<td%s>%s</td>", cl, teamdb_get_name_2(cs->teamdb_state,
                                                        pe->user_id));
      prob_type = 0;
      if (pe->prob_id > 0 && pe->prob_id <= cs->max_prob
          && cs->probs[pe->prob_id]) {
        struct section_problem_data *cur_prob = cs->probs[pe->prob_id];
        int variant = 0;
        prob_type = cur_prob->type_val;
        if (cur_prob->variant_num > 0) {
          variant = pe->variant;
          if (!variant) variant = find_variant(cs, pe->user_id, pe->prob_id, 0);
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
      fprintf(f, "<td%s>%s</td>", cl, prob_str);
      if (pe->lang_id > 0 && pe->lang_id <= cs->max_lang
          && cs->langs[pe->lang_id]) {
        fprintf(f, "<td%s>%s</td>", cl, cs->langs[pe->lang_id]->short_name);
      } else if (!pe->lang_id) {
        fprintf(f, "<td%s>N/A</td>", cl);
      } else {
        fprintf(f, "<td%s>??? - %d</td>", cl, pe->lang_id);
      }
      run_status_str(pe->status, statstr, sizeof(statstr), prob_type, 0);
      write_html_run_status(cs, f, pe, 1, attempts, disq_attempts,
                            prev_successes, "b1");
      if (phr->role == USER_ROLE_ADMIN) {
        write_change_status_dialog(cs, f, "status", pe->is_imported, "b1");
        fprintf(f, "<td%s>%s</td>", cl, BUTTON(NEW_SRV_ACTION_CHANGE_STATUS));
      }

      fprintf(f, "<td%s><a href=\"%s\">%s</a></td>", cl, 
              ns_url(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_SOURCE,
                     "run_id=%d", rid),
              _("View"));
      if (pe->is_imported) {
        fprintf(f, "<td%s>N/A</td>", cl);
      } else {
        fprintf(f, "<td%s><a href=\"%s\">%s</a></td>", cl,
                ns_url(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_REPORT,
                       "run_id=%d", rid),
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
    fprintf(f, "\"/>\n");
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
      fprintf(f, "\"/>\n");
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
      fprintf(f, "<option value=\"%d\">%s - %s\n", i, prob->short_name,
              ARMOR(prob->long_name));
    }
    fprintf(f, "</select>%s\n", BUTTON(NEW_SRV_ACTION_REJUDGE_PROBLEM_1));
    fprintf(f, "</form>\n");
  }

  if (phr->role == USER_ROLE_ADMIN && global->enable_runlog_merge) {
    /*
    html_start_form(f, 2, self_url, hidden_vars);
    fprintf(f, "<table border=\"0\"><tr><td>%s: </td>\n",
            _("Import and merge XML runs log"));
    fprintf(f, "<td><input type=\"file\" name=\"file\"/></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"/></td>", ACTION_MERGE_RUNS, _("Send!"));
    fprintf(f, "</tr></table></form>\n");
    */
  }

  if (opcaps_check(phr->caps, OPCAP_DUMP_RUNS) >= 0) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_mask_size", "%d", displayed_size);
    fprintf(f, "<input type=\"hidden\" name=\"run_mask\" value=\"");
    for (i = 0; i < displayed_size; i++) {
      if (i > 0) fprintf(f, " ");
      fprintf(f, "%lx", displayed_mask[i]);
    }
    fprintf(f, "\"/>\n");
    fprintf(f, "<table><tr><td>");
    fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_DOWNLOAD_ARCHIVE_1));
    fprintf(f, "</td></tr></table>");
    fprintf(f, "</form>\n");
  }

  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) >= 0
      && opcaps_check(phr->caps, OPCAP_EDIT_RUN) >= 0) {
    fprintf(f, "<table><tr><td>%s%s</a></td></td></table>\n",
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_NEW_RUN_FORM, 0),
            _("Add new run"));
  }

  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) >= 0) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_mask_size", "%d", displayed_size);
    fprintf(f, "<input type=\"hidden\" name=\"run_mask\" value=\"");
    for (i = 0; i < displayed_size; i++) {
      if (i > 0) fprintf(f, " ");
      fprintf(f, "%lx", displayed_mask[i]);
    }
    fprintf(f, "\"/>\n");
    fprintf(f, "<table><tr>");
    fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_CLEAR_DISPLAYED_1));
    fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_IGNORE_DISPLAYED_1));
    fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1));
    fprintf(f, "</tr></table></form>\n");
  }

  if (opcaps_check(phr->caps, OPCAP_IMPORT_XML_RUNS) >= 0) {
    fprintf(f, "<table><tr><td>%s%s</a></td></td></table>\n",
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_1, 0),
            _("Add new runs in CSV format"));

    fprintf(f, "<table><tr><td>%s%s</a></td></td></table>\n",
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_1, 0),
            _("Merge runs in XML format"));
  }

  if (opcaps_check(phr->caps, OPCAP_PRINT_RUN) >= 0
      && cnts->exam_mode > 0 && phr->role == USER_ROLE_ADMIN) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    fprintf(f, "<table class=\"b0\"><tr><td class=\"b0\">%s:</td><td>",
            _("Print problem protocol"));
    fprintf(f, "<select name=\"prob_id\"><option value=\"\"></option>\n");

    for (i = 1; i <= cs->max_prob; i++) {
      if (!(prob = cs->probs[i])) continue;
      fprintf(f, "<option value=\"%d\">%s - %s\n", i, prob->short_name,
              ARMOR(prob->long_name));
    }

    fprintf(f, "</select></td><td class=\"b0\">%s</td></tr></table></form>\n",
            BUTTON(NEW_SRV_ACTION_PRINT_PROBLEM_PROTOCOL));
  }

  /*
  print_nav_buttons(state, f, 0, sid, self_url, hidden_vars, extra_args,
                    0, 0, 0, 0, 0, 0, 0);
  */
  html_armor_free(&ab);
}

void
ns_write_all_clars(FILE *f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra,
                   int mode_clar, int first_clar, int last_clar)
{
  int total, i, j;

  int *list_idx;
  int list_tot;

  unsigned char first_clar_str[64] = { 0 }, last_clar_str[64] = { 0 };

  time_t start, submit_time;
  unsigned char durstr[64];
  int show_astr_time;
  unsigned char bbuf[1024];
  struct clar_entry_v1 clar;
  unsigned char cl[128];

  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  struct user_filter_info *u = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

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
  fprintf(f, "%s: <input type=\"text\" name=\"filter_first_clar\" size=\"16\" value=\"%s\"/>", _("First clar"), first_clar_str);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_last_clar\" size=\"16\" value=\"%s\"/>", _("Last clar"), last_clar_str);
  fprintf(f, "%s",
          ns_submit_button(bbuf, sizeof(bbuf), "filter_view_clars",
                           1, _("View")));
  fprintf(f, "%s",
          ns_submit_button(bbuf, sizeof(bbuf), 0,
                           NEW_SRV_ACTION_RESET_CLAR_FILTER, 0));
  fprintf(f, "</p></form>\n");

  snprintf(cl, sizeof(cl), " class=\"b1\"");

  fprintf(f, "<table%s><tr><th%s>%s</th><th%s>%s</th><th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th><th%s>%s</th>"
          "<th%s>%s</th><th%s>%s</th></tr>\n",
          cl, cl, _("Clar ID"), cl, _("Flags"), cl, _("Time"),
          cl, _("IP"), cl, _("Size"), cl, _("From"), cl, _("To"),
          cl, _("Subject"), cl, _("View"));
  for (j = 0; j < list_tot; j++) {
    i = list_idx[j];

    if (clar_get_record_new(cs->clarlog_state, i, &clar) < 0) continue;
    if (mode_clar != 1 && (clar.from <= 0 || clar.flags >= 2)) continue; 

    submit_time = clar.time;
    if (submit_time < 0) submit_time = 0;
    if (!start) {
      duration_str(1, submit_time, start, durstr, 0);
    } else {
      if (!show_astr_time && submit_time < start) submit_time = start;
      duration_str(show_astr_time, submit_time, start, durstr, 0);
    }

    fprintf(f, "<tr>");
    if (clar.hide_flag) fprintf(f, "<td%s>%d#</td>", cl, i);
    else fprintf(f, "<td%s>%d</td>", cl, i);
    fprintf(f, "<td%s>%s</td>", cl, 
            clar_flags_html(cs->clarlog_state, clar.flags,
                            clar.from, clar.to, 0, 0));
    fprintf(f, "<td%s>%s</td>", cl, durstr);
    fprintf(f, "<td%s>%s</td>", cl, xml_unparse_ip(clar.a.ip));
    fprintf(f, "<td%s>%u</td>", cl, clar.size);
    if (!clar.from) {
      if (!clar.j_from)
        fprintf(f, "<td%s><b>%s</b></td>", cl, _("judges"));
      else
        fprintf(f, "<td%s><b>%s</b> (%s)</td>", cl, _("judges"),
                teamdb_get_name_2(cs->teamdb_state, clar.j_from));
    } else {
      fprintf(f, "<td%s>%s</td>", cl,
              teamdb_get_name_2(cs->teamdb_state, clar.from));
    }
    if (!clar.to && !clar.from) {
      fprintf(f, "<td%s><b>%s</b></td>", cl, _("all"));
    } else if (!clar.to) {
      fprintf(f, "<td%s><b>%s</b></td>", cl, _("judges"));
    } else {
      fprintf(f, "<td%s>%s</td>", cl,
              teamdb_get_name_2(cs->teamdb_state, clar.to));
    }
    fprintf(f, "<td%s>%s</td>", cl, ARMOR(clar.subj));
    fprintf(f, "<td%s><a href=\"%s\">%s</a></td>", cl,
            ns_url(bbuf, sizeof(bbuf), phr, NEW_SRV_ACTION_VIEW_CLAR,
                   "clar_id=%d", i), _("View"));
    fprintf(f, "</tr>\n");
  }
  fputs("</table>\n", f);

  /*
  print_nav_buttons(state, f, 0, sid, self_url, hidden_vars, extra_args,
                    0, 0, 0, 0, 0, 0, 0);
  */
  html_armor_free(&ab);
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
ns_write_run_view_menu(
	FILE *f, struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int run_id)
{
  unsigned char hbuf[1024];
  int i;
  static int action_list[] =
  {
    NEW_SRV_ACTION_VIEW_SOURCE,
    NEW_SRV_ACTION_VIEW_REPORT,
    NEW_SRV_ACTION_VIEW_USER_REPORT,
    NEW_SRV_ACTION_VIEW_AUDIT_LOG,
    0,
  };
  static const unsigned char * const action_name[] =
  {
    __("Source"),
    __("Report"),
    __("User report"),
    __("Audit log"),
  };

  fprintf(f, "<table class=\"b0\"><tr>");
  fprintf(f, "<td class=\"b0\">%s%s</a></td>",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_MAIN_PAGE, 0),
          _("Main page"));
  for (i = 0; action_list[i] > 0; i++) {
    fprintf(f, "<td class=\"b0\">");
    if (phr->action != action_list[i]) {
      /*
      fprintf(f, "%s",
              ns_aref_2(hbuf, sizeof(hbuf), phr, "menu", action_list[i],
                        "run_id=%d", run_id));
      */
      fprintf(f, "%s",
              ns_aref(hbuf, sizeof(hbuf), phr, action_list[i],
                      "run_id=%d", run_id));
    }
    fprintf(f, "%s", gettext(action_name[i]));
    if (phr->action != action_list[i]) {
      fprintf(f, "</a>");
    }
    fprintf(f, "</td>");
  }
  fprintf(f, "</tr></table>\n");
}

void
ns_write_priv_source(const serve_state_t state,
                     FILE *f,
                     FILE *log_f,
                     struct http_request_info *phr,
                     const struct contest_desc *cnts,
                     struct contest_extra *extra,
                     int run_id)
{
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
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (run_id < 0 || run_id >= run_get_total(state->runlog_state)) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    return;
  }
  run_get_entry(state->runlog_state, run_id, &info);
  if (info.status > RUN_LAST
      || (info.status > RUN_MAX_STATUS && info.status < RUN_TRANSIENT_FIRST)) {
    ns_error(log_f, NEW_SRV_ERR_SOURCE_UNAVAILABLE);
    return;
  }

  src_flags = archive_make_read_path(state, src_path, sizeof(src_path),
                                     global->run_archive_dir, run_id,
                                     0, 1);
  if (src_flags < 0) {
    ns_error(log_f, NEW_SRV_ERR_SOURCE_NONEXISTANT);
    return;
  }

  if (info.prob_id > 0 && info.prob_id <= state->max_prob)
    prob = state->probs[info.prob_id];
  if (info.lang_id > 0 && info.lang_id <= state->max_lang)
    lang = state->langs[info.lang_id];

  ns_header(f, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %s]: %s %d", ns_unparse_role(phr->role),
            phr->name_arm, extra->contest_arm,
            _("Viewing run"), run_id);

  run_time = info.time;
  if (run_time < 0) run_time = 0;
  start_time = run_get_start_time(state->runlog_state);
  if (start_time < 0) start_time = 0;
  if (run_time < start_time) run_time = start_time;

  ns_write_run_view_menu(f, phr, cnts, extra, run_id);

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
          ns_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
                  "filter_expr=%s", filtbuf2),
          xml_unparse_ip(info.a.ip));
  fprintf(f, "%s</tr>\n", nbsp);

  // size
  snprintf(filtbuf1, sizeof(filtbuf1), "size == size(%d)", run_id);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  fprintf(f, "<tr><td>%s:</td><td>%s%u</a></td>%s</tr>\n",
          _("Size"),
          ns_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
                  "filter_expr=%s", filtbuf2),
          info.size, nbsp);

  // hash code
  snprintf(filtbuf1, sizeof(filtbuf1), "hash == hash(%d)", run_id);
  url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
  fprintf(f, "<tr><td>%s:</td><td>%s%s</a></td>%s</tr>\n",
          _("Hash value"),
          ns_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
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
          ns_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
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
  fprintf(f, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("User name"),
          ARMOR(teamdb_get_name(state->teamdb_state, info.user_id)),
          nbsp);

  // problem
  if (prob) {
    snprintf(filtbuf1, sizeof(filtbuf1), "prob == \"%s\"",  prob->short_name);
    url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
    ps1 = ns_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
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
      fprintf(f, "<option value=\"%d\"%s>%s - %s\n",
              i, ss, state->probs[i]->short_name,
              ARMOR(state->probs[i]->long_name));
    }
    fprintf(f, "</select></td><td>%s</td></tr></form>\n",
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_PROB_ID));
  } else {
    fprintf(f, "%s</tr>\n", nbsp);
  }

  // variant
  if (prob && prob->variant_num > 0) {
    variant = info.variant;
    if (!variant) variant = find_variant(state, info.user_id, info.prob_id, 0);
    if (variant > 0) {
      snprintf(filtbuf1, sizeof(filtbuf1), "prob == \"%s\" && variant == %d", 
               prob->short_name, variant);
      url_armor_string(filtbuf2, sizeof(filtbuf2), filtbuf1);
      ps1 = ns_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
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
    ps1 = ns_aref(filtbuf3, sizeof(filtbuf3), phr, 0,
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
      fprintf(f, "<option value=\"%d\"%s>%s - %s</option>\n",
              i, ss, state->langs[i]->short_name,
              ARMOR(state->langs[i]->long_name));
    }
    fprintf(f, "</select></td><td>%s</td></tr></form>\n",
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_LANG_ID));
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

  // is_examinable
  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td>",
          _("Examinable?"),
          html_unparse_bool(bb, sizeof(bb), info.is_examinable));
  if (editable) {
    fprintf(f, "<td>%s</td><td>%s</td></tr></form>\n",
            html_select_yesno(bt, sizeof(bt), "param", info.is_examinable),
            BUTTON(NEW_SRV_ACTION_CHANGE_RUN_IS_EXAMINABLE));
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
          _("Status"), run_status_str(info.status, 0, 0, 0, 0));
  if (editable) {
    write_change_status_dialog(state, f, 0, info.is_imported, 0);
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
          ns_aref(filtbuf3, sizeof(filtbuf3), phr,
                  NEW_SRV_ACTION_PRIV_DOWNLOAD_RUN, "run_id=%d", run_id),
          _("Download run"));

  if (editable) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
    fprintf(f, "<p>%s</p>", BUTTON(NEW_SRV_ACTION_CLEAR_RUN));
    fprintf(f, "</form>\n");
  }

  if (opcaps_check(phr->caps, OPCAP_PRINT_RUN) >= 0) {
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
    fprintf(f, "<p>%s</p>", BUTTON(NEW_SRV_ACTION_PRINT_RUN));
    fprintf(f, "</form>\n");
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
  fprintf(f, "<p>%s: %s %s</p></form>\n",
	  _("Compare this run with run"),
          html_input_text(bt, sizeof(bt), "run_id2", 10, "%s", filtbuf1),
	  BUTTON(NEW_SRV_ACTION_COMPARE_RUNS));

  if (global->enable_report_upload) {
    html_start_form(f, 2, phr->self_url, phr->hidden_vars);
    html_hidden(f, "run_id", "%d", run_id);
    fprintf(f, "<p>%s: ", _("Upload judging protocol"));
    fprintf(f, "<input type=\"file\" name=\"file\"/>");
    if (global->team_enable_rep_view) {
      fprintf(f, "<input type=\"checkbox\" %s%s/>%s",
              "name=\"judge_report\"", "checked=\"yes\"",
              _("Judge's report"));
      fprintf(f, "<input type=\"checkbox\" %s%s/>%s",
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
      fprintf(f, "<p><img src=\"%s\" alt=\"submit image\"/></p>",
              ns_url(filtbuf3, sizeof(filtbuf3), phr,
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
  html_armor_free(&ab);
}

void
ns_write_priv_report(const serve_state_t cs,
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

  static const int new_actions_vector[] =
  {
    NEW_SRV_ACTION_VIEW_TEST_INPUT,
    NEW_SRV_ACTION_VIEW_TEST_OUTPUT,
    NEW_SRV_ACTION_VIEW_TEST_ANSWER,
    NEW_SRV_ACTION_VIEW_TEST_ERROR,
    NEW_SRV_ACTION_VIEW_TEST_CHECKER,
    NEW_SRV_ACTION_VIEW_TEST_INFO,
  };

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
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto done;
  }
  if (re.status > RUN_MAX_STATUS) {
    ns_error(log_f, NEW_SRV_ERR_REPORT_UNAVAILABLE);
    goto done;
  }
  if (!run_is_report_available(re.status)) {
    ns_error(log_f, NEW_SRV_ERR_REPORT_UNAVAILABLE);
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
      ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
      goto done;
    }
    content_type = get_content_type(rep_text, &start_ptr);
  } else {
    rep_flag = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                      report_dir, run_id, 0, 1);
    if (rep_flag < 0) {
      ns_error(log_f, NEW_SRV_ERR_REPORT_NONEXISTANT);
      goto done;
    }
    if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0)<0){
      ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
      goto done;
    }
    content_type = get_content_type(rep_text, &start_ptr);
  }

  ns_header(f, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %s]: %s %d", ns_unparse_role(phr->role),
            phr->name_arm, extra->contest_arm,
            team_report_flag?_("Viewing user report"):_("Viewing report"),
            run_id);

  ns_write_run_view_menu(f, phr, cnts, extra, run_id);

  switch (content_type) {
  case CONTENT_TYPE_TEXT:
    html_len = html_armored_memlen(start_ptr, rep_len);
    if (html_len > 2 * 1024 * 1024) {
      html_text = xmalloc(html_len + 16);
      html_armor_text(rep_text, rep_len, html_text);
      html_text[html_len] = 0;
      fprintf(f, "<pre>%s</pre>", html_text);
      xfree(html_text);
    } else {
      html_text = alloca(html_len + 16);
      html_armor_text(rep_text, rep_len, html_text);
      html_text[html_len] = 0;
      fprintf(f, "<pre>%s</pre>", html_text);
    }
    break;
  case CONTENT_TYPE_HTML:
    fprintf(f, "%s", start_ptr);
    break;
  case CONTENT_TYPE_XML:
    if (team_report_flag) {
      write_xml_team_testing_report(cs, f, 0, start_ptr, "b1");
    } else {
      write_xml_testing_report(f, start_ptr, phr->session_id,phr->self_url, "",
                               new_actions_vector, "b1", 0);
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

void
ns_write_audit_log(const serve_state_t cs,
                   FILE *f,
                   FILE *log_f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra,
                   int run_id)
{
  struct run_entry re;
  int rep_flag;
  path_t audit_log_path;
  struct stat stb;
  char *audit_text = 0;
  size_t audit_text_size = 0;
  char *audit_html = 0;

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)
      || run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto done;
  }

  if ((rep_flag = archive_make_read_path(cs, audit_log_path,
                                         sizeof(audit_log_path),
                                         cs->global->audit_log_dir,
                                         run_id, 0, 0)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_AUDIT_LOG_NONEXISTANT);
    goto done;
  }
  if (lstat(audit_log_path, &stb) < 0
      || !S_ISREG(stb.st_mode)) {
    ns_error(log_f, NEW_SRV_ERR_AUDIT_LOG_NONEXISTANT);
    goto done;
  }

  if (generic_read_file(&audit_text, 0, &audit_text_size, 0, 0, audit_log_path,
                        0) < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
    goto done;
  }
  audit_html = html_armor_string_dup(audit_text);

  ns_header(f, extra->header_txt, 0, 0, 0, 0, phr->locale_id,
            "%s [%s, %s]: %s %d", ns_unparse_role(phr->role),
            phr->name_arm, extra->contest_arm,
            _("Viewing audit log for"), run_id);
  ns_write_run_view_menu(f, phr, cnts, extra, run_id);
  fprintf(f, "<hr/>\n");
  if (!audit_text || !*audit_text) {
    fprintf(f, "<p><i>%s</i></p>", _("Audit log is empty"));
  } else {
    fprintf(f, "<pre>%s</pre>", audit_html);
  }
  ns_footer(f, extra->footer_txt, extra->copyright_txt, phr->locale_id);

 done:;
  xfree(audit_html);
  xfree(audit_text);
}

void
ns_write_priv_clar(const serve_state_t cs,
                   FILE *f,
                   FILE *log_f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra,
                   int clar_id)
{
  const struct section_global_data *global = cs->global;
  struct clar_entry_v1 clar;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  time_t start_time;
  path_t name_buf;
  char *msg_txt = 0;
  size_t msg_len = 0;
  unsigned char bb[1024];
  unsigned char b1[1024], b2[1024];

  if (clar_id < 0 || clar_id >= clar_get_total(cs->clarlog_state)
      || clar_get_record_new(cs->clarlog_state, clar_id, &clar) < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_CLAR_ID);
    goto done;
  }
  start_time = run_get_start_time(cs->runlog_state);

  fprintf(f, "<h2>%s %d</h2>\n", _("Message"), clar_id);
  fprintf(f, "<table border=\"0\">\n");
  fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>\n", _("Clar ID"), clar_id);
  if (clar.hide_flag)
    fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Available only after contest start"),
            clar.hide_flag?_("YES"):_("NO"));
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Flags"),
          clar_flags_html(cs->clarlog_state, clar.flags,
                          clar.from, clar.to, 0, 0));
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
          _("Time"), duration_str(1, clar.time, 0, 0, 0));
  if (!cs->global->is_virtual && start_time > 0) {
    fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n",
            _("Duration"), duration_str(0, clar.time, start_time, 0, 0));
  }
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("IP address"),
          xml_unparse_ip(clar.a.ip));
  fprintf(f, "<tr><td>%s:</td><td>%u</td></tr>\n", _("Size"), clar.size);
  fprintf(f, "<tr><td>%s:</td>", _("Sender"));
  if (!clar.from) {
    if (!clar.j_from)
      fprintf(f, "<td><b>%s</b></td>", _("judges"));
    else
      fprintf(f, "<td><b>%s</b> (%s)</td>", _("judges"),
              ARMOR(teamdb_get_name_2(cs->teamdb_state, clar.j_from)));
  } else {
    snprintf(b1, sizeof(b1), "uid == %d", clar.from);
    url_armor_string(b2, sizeof(b2), b1);
    fprintf(f, "<td>%s%s (%d)</a></td>",
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_MAIN_PAGE,
                    "filter_expr=%s", b2),
            ARMOR(teamdb_get_name_2(cs->teamdb_state, clar.from)),
            clar.from);
  }
  fprintf(f, "</tr>\n<tr><td>%s:</td>", _("To"));
  if (!clar.to && !clar.from) {
    fprintf(f, "<td><b>%s</b></td>", _("all"));
  } else if (!clar.to) {
    fprintf(f, "<td><b>%s</b></td>", _("judges"));
  } else {
    snprintf(b1, sizeof(b1), "uid == %d", clar.to);
    url_armor_string(b2, sizeof(b2), b1);
    fprintf(f, "<td>%s%s (%d)</a></td>",
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_MAIN_PAGE,
                    "filter_expr=%s", b2),
            ARMOR(teamdb_get_name_2(cs->teamdb_state, clar.to)), clar.to);
  }
  fprintf(f, "</tr>\n");
  if (clar.in_reply_to > 0) {
    fprintf(f, "<tr><td>%s:</td><td>%s%d</td></a></tr>", _("In reply to"),
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_VIEW_CLAR,
                    "clar_id=%d", clar.in_reply_to - 1),
            clar.in_reply_to - 1);
  }
  fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>", _("Locale code"),
          clar.locale_id);
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>", _("Subject"),ARMOR(clar.subj));
  fprintf(f, "</table>\n");
  /*
  print_nav_buttons(state, f, 0, sid, self_url, hidden_vars, extra_args,
                    _("Main page"), 0, 0, 0, 0, 0, 0);
  */
  fprintf(f, "<hr>\n");

  snprintf(name_buf, sizeof(name_buf), "%06d", clar_id);
  if (generic_read_file(&msg_txt, 0, &msg_len, 0,
                        global->clar_archive_dir, name_buf, "") < 0) {
    fprintf(f, "<big><font color=\"red\">%s</font></big>\n",
            _("Cannot read message text!"));
  } else {
    fprintf(f, "<pre>%s</pre><hr>", ARMOR(msg_txt));
  }

  if (phr->role >= USER_ROLE_JUDGE && clar.from
      && opcaps_check(phr->caps, OPCAP_REPLY_MESSAGE) >= 0) {
    html_start_form(f, 2, phr->self_url, phr->hidden_vars);
    html_hidden(f, "in_reply_to", "%d", clar_id);
    fprintf(f, "<p>%s\n", BUTTON(NEW_SRV_ACTION_CLAR_REPLY_READ_PROBLEM));
    fprintf(f, "%s\n", BUTTON(NEW_SRV_ACTION_CLAR_REPLY_NO_COMMENTS));
    fprintf(f, "%s\n", BUTTON(NEW_SRV_ACTION_CLAR_REPLY_YES));
    fprintf(f, "%s\n", BUTTON(NEW_SRV_ACTION_CLAR_REPLY_NO));
    fprintf(f, "<p><textarea name=\"reply\" rows=\"20\" cols=\"60\"></textarea></p>\n");
    fprintf(f, "<p>%s\n", BUTTON(NEW_SRV_ACTION_CLAR_REPLY));
    fprintf(f, "%s\n", BUTTON(NEW_SRV_ACTION_CLAR_REPLY_ALL));
    fprintf(f, "</form>\n");
  }

 done:;
  html_armor_free(&ab);
  xfree(msg_txt);
}


static void
write_from_contest_dir(FILE *log_f, FILE *fout,
                       int flag1,
                       int flag2,
                       int test_num,
                       int variant,
                       const unsigned char *dir,
                       const unsigned char *suffix,
                       const unsigned char *pattern,
                       int has_digest,
                       const unsigned char *digest_ptr)
{
  path_t path1;
  path_t path2;
  unsigned char cur_digest[32];
  int good_digest_flag = 0;
  char *file_bytes = 0;
  size_t file_size = 0;

  if (!flag1 || !flag2) {
    ns_error(log_f, NEW_SRV_ERR_TEST_NONEXISTANT);
    goto done;
  }

  if (pattern[0]) {
    snprintf(path2, sizeof(path2), pattern, test_num);
  } else {
    snprintf(path2, sizeof(path2), "%03d%s", test_num, suffix);
  }

  if (variant > 0) {
    snprintf(path1, sizeof(path1), "%s-%d/%s", dir, variant, path2);
  } else {
    snprintf(path1, sizeof(path1), "%s/%s", dir, path2);
  }

  if (has_digest && digest_ptr) {
    if (filehash_get(path1, cur_digest) < 0) {
      ns_error(log_f, NEW_SRV_ERR_CHECKSUMMING_FAILED);
      goto done;
    }
    good_digest_flag = digest_is_equal(DIGEST_SHA1, digest_ptr, cur_digest);
  }

  if (generic_read_file(&file_bytes, 0, &file_size, 0, 0, path1, 0) < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
    goto done;
  }

  fprintf(fout, "Content-type: text/plain\n\n");
  if (!good_digest_flag) {
    fprintf(fout,
            "*********\n"
            "NOTE: The file checksum has been changed!\n"
            "It is possible, that the file was edited!\n"
            "*********\n\n");
  }
  if (file_size > 0) {
    if (fwrite(file_bytes, 1, file_size, fout) != file_size) {
      ns_error(log_f, NEW_SRV_ERR_OUTPUT_ERROR);
      goto done;
    }
  }

 done:
    xfree(file_bytes);
}

static void
write_from_archive(const serve_state_t cs,
                   FILE *log_f, FILE *fout,
                   int flag, int run_id, int test_num,
                   const unsigned char *dir,
                   const unsigned char *suffix)
{
  full_archive_t far = 0;
  unsigned char fnbuf[64];
  int rep_flag = 0, arch_flags = 0;
  path_t arch_path;
  long arch_size = 0, arch_raw_size = 0;
  const unsigned char *arch_data = 0;
  unsigned char *text = 0;

  if (!flag) {
    ns_error(log_f, NEW_SRV_ERR_TEST_UNAVAILABLE);
    goto done;
  }

  snprintf(fnbuf, sizeof(fnbuf), "%06d%s", test_num, suffix);

  rep_flag = archive_make_read_path(cs, arch_path, sizeof(arch_path),
                                    dir, run_id, 0, 0);
  if (rep_flag < 0 || !(far = full_archive_open_read(arch_path))) {
    ns_error(log_f, NEW_SRV_ERR_TEST_NONEXISTANT);
    goto done;
  }

  rep_flag = full_archive_find_file(far, fnbuf, &arch_size, &arch_raw_size,
                                    &arch_flags, &arch_data);
  if (rep_flag <= 0) {
    ns_error(log_f, NEW_SRV_ERR_TEST_NONEXISTANT);
    goto done;
  }

  if (arch_raw_size > 0) {
    text = (unsigned char*) xmalloc(arch_raw_size);
    if (uncompress(text, &arch_raw_size, arch_data, arch_size) != Z_OK) {
      ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
      goto done;
    }
  }

  fprintf(fout, "Content-type: text/plain\n\n");
  if (arch_raw_size > 0) {
    if (fwrite(text, 1, arch_raw_size, fout) != arch_raw_size) {
      ns_error(log_f, NEW_SRV_ERR_OUTPUT_ERROR);
      goto done;
    }
  }

 done:
  full_archive_close(far);
  xfree(text);
}

void
ns_write_tests(const serve_state_t cs, FILE *fout, FILE *log_f,
               int action, int run_id, int test_num)
{
  int rep_flag;
  path_t rep_path;
  char *rep_text = 0;
  size_t rep_len = 0;
  const unsigned char *start_ptr = 0;
  testing_report_xml_t r = 0;
  struct run_entry re;
  const struct section_problem_data *prb = 0;
  const struct testing_report_test *t = 0;

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state)
      || run_get_entry(cs->runlog_state, run_id, &re) < 0) {
    ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
    goto done;
  }

  if ((rep_flag = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                         cs->global->xml_report_archive_dir,
                                         run_id, 0, 1)) < 0
      && (rep_flag = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                            cs->global->report_archive_dir,
                                            run_id, 0, 1)) < 0) {
    ns_error(log_f, NEW_SRV_ERR_REPORT_NONEXISTANT);
    goto done;
  }

  if (generic_read_file(&rep_text, 0, &rep_len, rep_flag,0,rep_path, "") < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
    goto done;
  }
  if (get_content_type(rep_text, &start_ptr) != CONTENT_TYPE_XML) {
    // we expect the master log in XML format
    ns_error(log_f, NEW_SRV_ERR_REPORT_UNAVAILABLE);
    goto done;
  }

  if (!(r = testing_report_parse_xml(start_ptr))) {
    ns_error(log_f, NEW_SRV_ERR_REPORT_UNAVAILABLE);
    goto done;
  }
  xfree(rep_text); rep_text = 0;

  if (test_num <= 0 || test_num > r->run_tests) { 
    ns_error(log_f, NEW_SRV_ERR_INV_TEST);
    goto done;
  }

  t = r->tests[test_num - 1];

  if (re.prob_id <= 0 || re.prob_id > cs->max_prob
      || !(prb = cs->probs[re.prob_id])) {
    ns_error(log_f, NEW_SRV_ERR_INV_PROB_ID);
    goto done;
  }

  if (prb->type_val > 0) {
    ns_error(log_f, NEW_SRV_ERR_TEST_UNAVAILABLE);
    goto done;
  }

  if ((prb->variant_num > 0
       && (r->variant <= 0 || r->variant > prb->variant_num))
      || (prb->variant_num <= 0 && r->variant > 0)) { 
    ns_error(log_f, NEW_SRV_ERR_INV_VARIANT);
    goto done;
  }

  switch (action) {
  case NEW_SRV_ACTION_VIEW_TEST_INPUT:
    write_from_contest_dir(log_f, fout, 1, 1, test_num, r->variant,
                           prb->test_dir, prb->test_sfx, prb->test_pat,
                           t->has_input_digest, t->input_digest);
    goto done;
  case NEW_SRV_ACTION_VIEW_TEST_ANSWER:
    write_from_contest_dir(log_f, fout, prb->use_corr, r->correct_available,
                           test_num, r->variant,
                           prb->corr_dir, prb->corr_sfx, prb->corr_pat,
                           t->has_correct_digest, t->correct_digest);
    goto done;
  case NEW_SRV_ACTION_VIEW_TEST_INFO:
    write_from_contest_dir(log_f, fout, prb->use_info, r->info_available,
                           test_num, r->variant,
                           prb->info_dir, prb->info_sfx, prb->info_pat,
                           t->has_info_digest, t->info_digest);
    goto done;

  case NEW_SRV_ACTION_VIEW_TEST_OUTPUT:
    write_from_archive(cs, log_f, fout, t->output_available, run_id, test_num,
                       cs->global->full_archive_dir, ".o");
    goto done;

  case NEW_SRV_ACTION_VIEW_TEST_ERROR:
    write_from_archive(cs, log_f, fout, t->stderr_available, run_id, test_num,
                       cs->global->full_archive_dir, ".e");
    goto done;

  case NEW_SRV_ACTION_VIEW_TEST_CHECKER:
    write_from_archive(cs, log_f, fout, t->checker_output_available,
                       run_id, test_num,
                       cs->global->full_archive_dir, ".c");
    goto done;
  }

 done:
  xfree(rep_text);
  testing_report_free(r);
}

int
ns_write_passwords(FILE *fout, FILE *log_f,
                   struct http_request_info *phr,
                   const struct contest_desc *cnts,
                   struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const unsigned char *s;
  int i, max_user_id, serial = 1;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct teamdb_export td;
  unsigned char cl[128];

  snprintf(cl, sizeof(cl), " class=\"b1\"");

  fprintf(fout, "<table%s>\n"
          "<tr><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th><th%s>%s</th></tr>",
          cl, cl, "NN", cl, _("User Id"), cl, _("User login"),
          cl, _("User name"), cl, _("Flags"),
          cl, _("Password"), cl, _("Location"));
  max_user_id = teamdb_get_max_team_id(cs->teamdb_state);
  for (i = 1; i <= max_user_id; i++) {
    if (!teamdb_lookup(cs->teamdb_state, i)) continue;
    if (teamdb_export_team(cs->teamdb_state, i, &td) < 0) continue;
    if (td.flags) continue;
    if (!td.user) continue;
    if (phr->action == NEW_SRV_ACTION_VIEW_CNTS_PWDS) {
      if (td.user->i.team_passwd_method != USERLIST_PWD_PLAIN) continue;
      s = td.user->i.team_passwd;
    } else {
      if (td.user->passwd_method != USERLIST_PWD_PLAIN) continue;
      s = td.user->passwd;
    }
    fprintf(fout, "<tr><td%s>%d</td><td%s>%d</td><td%s><tt>%s</tt></td>",
            cl, serial++, cl, i, cl, ARMOR(td.login));
    if (td.name && *td.name) {
      fprintf(fout, "<td%s><tt>%s</tt></td>", cl, ARMOR(td.name));
    } else {
      fprintf(fout, "<td%s><i>%s</i></td>", cl, _("Not set"));
    }
    fprintf(fout, "<td%s>%s</td>", cl, "&nbsp;"); /* FIXME: print flags */
    if (s && *s) {
      fprintf(fout, "<td%s><tt>%s</tt></td>", cl, ARMOR(s));
    } else {
      fprintf(fout, "<td%s><i>%s</i></td>", cl, _("Not set"));
    }
    if (td.user->i.location) {
      fprintf(fout, "<td%s>%s</td>", cl, ARMOR(td.user->i.location));
    } else {
      fprintf(fout, "<td%s><i>%s</i></td>", cl, _("Not set"));
    }
    fprintf(fout, "</tr>");
  }
  fprintf(fout, "</table>\n");

  html_armor_free(&ab);
  return 0;
}

int
ns_write_online_users(
	FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  int i, max_user_id, j, serial = 1;
  struct last_access_info *ai;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  struct teamdb_export td;
  unsigned char cl[128];

  snprintf(cl, sizeof(cl), " class=\"b1\"");

  fprintf(fout, "<table%s>"
          "<tr>"
          "<th%s>NN</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th>"
          "</tr>",
          cl,
          cl,
          cl, _("User Id"),
          cl, _("User login"),
          cl, _("User name"),
          cl, _("IP address"));

  max_user_id = teamdb_get_max_team_id(cs->teamdb_state);
  for (i = 1; i <= max_user_id; i++) {
    if (i >= extra->user_access_idx.a) continue;
    if ((j = extra->user_access_idx.v[i]) < 0) continue;
    ai = &extra->user_access[USER_ROLE_CONTESTANT].v[j];
    if (ai->time + 65 < cs->current_time) continue;
    if (!teamdb_lookup(cs->teamdb_state, i)) continue;
    if (teamdb_export_team(cs->teamdb_state, i, &td) < 0) continue;

    fprintf(fout, "<tr><td%s>%d</td><td%s>%d</td><td%s>%s</td>",
            cl, serial++, cl, i, cl, ARMOR(td.login));
    if (td.name && *td.name) {
      fprintf(fout, "<td%s><tt>%s</tt></td>", cl, ARMOR(td.name));
    } else {
      fprintf(fout, "<td%s><i>%s</i></td>", cl, _("Not set"));
    }
    fprintf(fout, "<td%s><tt>%s%s</tt></td>",
            cl, xml_unparse_ip(ai->ip), ai->ssl?"/ssl":"");
    fprintf(fout, "</tr>\n");
  }
  fprintf(fout, "</table>\n");
  html_armor_free(&ab);
  return 0;
}

int
ns_user_info_page(FILE *fout, FILE *log_f,
                  struct http_request_info *phr,
                  const struct contest_desc *cnts,
                  struct contest_extra *extra,
                  int view_user_id)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  struct teamdb_export u_info;
  const struct team_extra *u_extra = 0;
  const struct team_warning *cur_warn = 0;
  int flags, pages_total;
  int runs_num = 0, clars_num = 0;
  size_t clars_total = 0, runs_total = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *nbsp2 = "<td>&nbsp;</td><td>&nbsp;</td>";
  const unsigned char *s;
  const struct userlist_user *u = 0;
  const struct userlist_contest *uc = 0;
  unsigned char bb[1024], hbuf[1024];
  int allowed_edit = 0, needed_cap = 0, init_value, i;

  teamdb_export_team(cs->teamdb_state, view_user_id, &u_info);
  u_extra = team_extra_get_entry(cs->team_extra_state, view_user_id);
  run_get_team_usage(cs->runlog_state, view_user_id, &runs_num, &runs_total);
  clar_get_team_usage(cs->clarlog_state,view_user_id, &clars_num, &clars_total);
  pages_total = run_get_total_pages(cs->runlog_state, view_user_id);
  flags = teamdb_get_flags(cs->teamdb_state, view_user_id);
  u = u_info.user;
  if (u) uc = userlist_get_user_contest(u, phr->contest_id);

  fprintf(fout, "<ul>\n");
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, 0, 0),
          _("Main page"));
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_USERS, 0),
          _("View regular users"));
  fprintf(fout, "<li>%s%s</a></li>\n",
          ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_REG_PWDS, 0),
          _("View registration passwords"));
  if (!cnts->disable_team_password) {
    fprintf(fout, "<li>%s%s</a></li>\n",
            ns_aref(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_CNTS_PWDS, 0),
            _("View contest passwords"));
  }
  fprintf(fout, "</ul>\n");

  // table has 4 columns
  fprintf(fout, "<table>\n");

  // user id
  fprintf(fout, "<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("User Id"), view_user_id, nbsp2);

  // user login
  fprintf(fout, "<tr><td>%s:</td><td><tt>%s</tt></td>%s</tr>\n",
          _("User Login"), ARMOR(u_info.login), nbsp2);

  // user name
  if (u_info.name && *u_info.name) {
    s = ARMOR(u_info.name);
  } else {
    s = _("<i>Not set</i>");
  }
  fprintf(fout, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("User Name"), s, nbsp2);

  // contest registration time
  if (uc && uc->date > 0) {
    s = xml_unparse_date(uc->date);
  } else {
    s = "&nbsp;";
  }
  fprintf(fout, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("Registration time"), s, nbsp2);
  // last login time
  if (u && u->i.last_login_time > 0) {
    s = xml_unparse_date(u->i.last_login_time);
  } else {
    s = "&nbsp;";
  }
  fprintf(fout, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("Last login time"), s, nbsp2);
  if (opcaps_check(phr->caps, OPCAP_GENERATE_TEAM_PASSWORDS) >= 0) {
  // registration password (if available)
    bb[0] = 0;
    if (u && !u->passwd) {
      snprintf(bb, sizeof(bb), "<i>%s</i>", _("Not set"));
    } else if (u && u->passwd_method != USERLIST_PWD_PLAIN) {
      snprintf(bb, sizeof(bb), "<i>%s</i>", _("Changed by user"));
    } else if (u) {
      snprintf(bb, sizeof(bb), "<tt>%s</tt>", ARMOR(u->passwd));
    }
    if (bb[0]) {
      fprintf(fout, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
              _("Registration password"), bb, nbsp2);
    }
  // contest password (if enabled and available)
    if (!cnts->disable_team_password) {
      bb[0] = 0;
      if (u && !u->i.team_passwd) {
        snprintf(bb, sizeof(bb), "<i>%s</i>", _("Not set"));
      } else if (u && u->i.team_passwd_method != USERLIST_PWD_PLAIN) {
        snprintf(bb, sizeof(bb), "<i>%s</i>", _("Changed by user"));
      } else if (u) {
        snprintf(bb, sizeof(bb), "<tt>%s</tt>", ARMOR(u->i.team_passwd));
      }
      if (bb[0]) {
        fprintf(fout, "<tr><td>%s:</td><td>%s</td>%s</tr>\n",
                _("Contest password"), bb, nbsp2);
      }
    }
  }

  fprintf(fout,"<tr><td>%s:</td><td>%s</td>%s</tr>\n",
          _("Privileged?"),
          (u && u->is_privileged)? _("Yes") : _("No"),
          nbsp2);

  // invisible, locked, banned status and change buttons
  // to make invisible EDIT_REG is enough for all users
  // to ban or lock DELETE_PRIV_REG required for privileged users
  allowed_edit = 0;
  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) >= 0) allowed_edit = 1;
  if (allowed_edit) {
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    html_hidden(fout, "user_id", "%d", view_user_id);
  }
  fprintf(fout, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td>",
          _("Invisible?"), (flags & TEAM_INVISIBLE)?_("Yes"):_("No"));
  if(allowed_edit) {
    fprintf(fout, "<td>%s</td>",
            ns_submit_button(bb, sizeof(bb), 0,
                             NEW_SRV_ACTION_TOGGLE_VISIBILITY,
                             (flags & TEAM_INVISIBLE)?_("Make visible"):_("Make invisible")));
  } else {
    fprintf(fout, "<td>&nbsp;</td>");
  }
  fprintf(fout, "</tr>\n");
  if (allowed_edit) {
    fprintf(fout, "</form>");
  }

  allowed_edit = 0;
  if (u) {
    if (u->is_privileged) {
      if ((flags & TEAM_BANNED)) needed_cap = OPCAP_PRIV_CREATE_REG;
      else needed_cap = OPCAP_PRIV_DELETE_REG;
    } else {
      if ((flags & TEAM_BANNED)) needed_cap = OPCAP_CREATE_REG;
      else needed_cap = OPCAP_DELETE_REG;
    }
    if (opcaps_check(phr->caps, needed_cap) >= 0) allowed_edit = 1;
  }
  if (allowed_edit) {
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    html_hidden(fout, "user_id", "%d", view_user_id);
  }
  fprintf(fout, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td>",
          _("Banned?"), (flags & TEAM_BANNED)?_("Yes"):_("No"));
  if(allowed_edit) {
    fprintf(fout, "<td>%s</td>",
            ns_submit_button(bb, sizeof(bb), 0,
                             NEW_SRV_ACTION_TOGGLE_BAN,
                             (flags & TEAM_BANNED)?_("Remove ban"):_("Ban")));
  } else {
    fprintf(fout, "<td>&nbsp;</td>");
  }
  fprintf(fout, "</tr>\n");
  if (allowed_edit) {
    fprintf(fout, "</form>");
  }

  allowed_edit = 0;
  if (u) {
    if (u->is_privileged) {
      if ((flags & TEAM_LOCKED)) needed_cap = OPCAP_PRIV_CREATE_REG;
      else needed_cap = OPCAP_PRIV_DELETE_REG;
    } else {
      if ((flags & TEAM_LOCKED)) needed_cap = OPCAP_CREATE_REG;
      else needed_cap = OPCAP_DELETE_REG;
    }
    if (opcaps_check(phr->caps, needed_cap) >= 0) allowed_edit = 1;
  }
  if (allowed_edit) {
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    html_hidden(fout, "user_id", "%d", view_user_id);
  }
  fprintf(fout, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td>",
          _("Locked?"), (flags & TEAM_LOCKED)?_("Yes"):_("No"));
  if(allowed_edit) {
    fprintf(fout, "<td>%s</td>",
            ns_submit_button(bb, sizeof(bb), 0, NEW_SRV_ACTION_TOGGLE_LOCK,
                             (flags & TEAM_LOCKED)?_("Unlock"):_("Lock")));
  } else {
    fprintf(fout, "<td>&nbsp;</td>");
  }
  fprintf(fout, "</tr>\n");
  if (allowed_edit) {
    fprintf(fout, "</form>");
  }

  allowed_edit = 0;
  if (u) {
    if (u->is_privileged) {
      if ((flags & TEAM_INCOMPLETE)) needed_cap = OPCAP_PRIV_CREATE_REG;
      else needed_cap = OPCAP_PRIV_DELETE_REG;
    } else {
      if ((flags & TEAM_INCOMPLETE)) needed_cap = OPCAP_CREATE_REG;
      else needed_cap = OPCAP_DELETE_REG;
    }
    if (opcaps_check(phr->caps, needed_cap) >= 0) allowed_edit = 1;
  }
  if (allowed_edit) {
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    html_hidden(fout, "user_id", "%d", view_user_id);
  }
  fprintf(fout, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td>",
          _("Incomplete?"), (flags & TEAM_INCOMPLETE)?_("Yes"):_("No"));
  if(allowed_edit) {
    fprintf(fout, "<td>%s</td>",
            ns_submit_button(bb, sizeof(bb), 0,
                             NEW_SRV_ACTION_TOGGLE_INCOMPLETENESS,
                             (flags & TEAM_INCOMPLETE)?_("Clear"):_("Set")));
  } else {
    fprintf(fout, "<td>&nbsp;</td>");
  }
  fprintf(fout, "</tr>\n");
  if (allowed_edit) {
    fprintf(fout, "</form>");
  }
  fprintf(fout, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td><td>&nbsp;</td></tr>", _("Disqualified?"), (flags & TEAM_DISQUALIFIED)?_("Yes"):_("No"));

  fprintf(fout,"<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Number of Runs"), runs_num, nbsp2);
  fprintf(fout,"<tr><td>%s:</td><td>%zu</td>%s</tr>\n",
          _("Total size of Runs"), runs_total, nbsp2);
  fprintf(fout,"<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Number of Clars"), clars_num, nbsp2);
  fprintf(fout,"<tr><td>%s:</td><td>%zu</td>%s</tr>\n",
          _("Total size of Clars"), clars_total, nbsp2);
  fprintf(fout,"<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Number of printed pages"), pages_total, nbsp2);

  if (global->contestant_status_num > 0) {
    // contestant status is editable when OPCAP_EDIT_REG is set
    allowed_edit = 0;
    if (opcaps_check(phr->caps, OPCAP_EDIT_REG) >= 0) allowed_edit = 1;
    if (allowed_edit) {
      html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
      html_hidden(fout, "user_id", "%d", view_user_id);
    }
    fprintf(fout, "<tr><td>%s:</td><td>", _("Status"));
    init_value = 0;
    if (!u_extra) {
      fprintf(fout, "N/A");
    } else if (u_extra->status < 0
               || u_extra->status >= global->contestant_status_num) {
      fprintf(fout, "%d - ???", u_extra->status);
    } else {
      fprintf(fout, "%d - %s", u_extra->status,
              global->contestant_status_legend[u_extra->status]);
      init_value = u_extra->status;
    }
    fprintf(fout, "</td>");
    if (allowed_edit) {
      fprintf(fout, "<td><select name=\"status\">\n");
      for (i = 0; i < global->contestant_status_num; i++) {
        s = "";
        if (i == init_value) s = " selected=\"1\"";
        fprintf(fout, "<option value=\"%d\"%s>%d - %s</option>\n",
                i, s, i, global->contestant_status_legend[i]);
      }
      fprintf(fout, "</select></td>\n");
      fprintf(fout, "<td>%s</td>\n", BUTTON(NEW_SRV_ACTION_USER_CHANGE_STATUS));
    } else {
      fprintf(fout, "%s", nbsp2);
    }
    fprintf(fout, "</tr>\n");
    if (allowed_edit) {
      fprintf(fout, "</form>");
    }
  }

  i = 0;
  if (u_extra) i = u_extra->warn_u;
  fprintf(fout,"<tr><td>%s:</td><td>%d</td>%s</tr>\n",
          _("Number of warnings"), i, nbsp2);

  fprintf(fout, "</table>\n");

  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  html_hidden(fout, "user_id", "%d", view_user_id);
  fprintf(fout, "<p>%s</p>\n", BUTTON(NEW_SRV_ACTION_PRINT_USER_PROTOCOL));
  fprintf(fout, "</form>\n");
  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  html_hidden(fout, "user_id", "%d", view_user_id);
  fprintf(fout, "<p>%s</p>\n", BUTTON(NEW_SRV_ACTION_PRINT_USER_FULL_PROTOCOL));
  fprintf(fout, "</form>\n");
  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  html_hidden(fout, "user_id", "%d", view_user_id);
  fprintf(fout, "<p>%s</p>\n", BUTTON(NEW_SRV_ACTION_PRINT_UFC_PROTOCOL));
  fprintf(fout, "</form>\n");

  if (!u_extra || !u_extra->warn_u) {
    fprintf(fout, "<h2>%s</h2>\n", _("No warnings"));
  } else {
    fprintf(fout, "<h2>%s</h2>\n", _("Warnings"));
    for (i = 0; i < u_extra->warn_u; i++) {
      if (!(cur_warn = u_extra->warns[i])) continue;
      fprintf(fout, _("<h3>Warning %d: issued: %s, issued by: %s (%d), issued from: %s</h3>"), i + 1, xml_unparse_date(cur_warn->date), teamdb_get_login(cs->teamdb_state, cur_warn->issuer_id), cur_warn->issuer_id, xml_unparse_ip(cur_warn->issuer_ip));
      fprintf(fout, "<p>%s:\n<pre>%s</pre>\n", _("Warning text for the user"),
              ARMOR(cur_warn->text));
      fprintf(fout, "<p>%s:\n<pre>%s</pre>\n", _("Judge's comment"),
              ARMOR(cur_warn->comment));
    }
  }

  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) >= 0) {
    fprintf(fout, "<h2>%s</h3>\n", _("Issue a warning"));
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    html_hidden(fout, "user_id", "%d", view_user_id);
    fprintf(fout, "<p>%s:<br>\n",
            _("Warning explanation for the user (mandatory)"));
    fprintf(fout, "<p><textarea name=\"warn_text\" rows=\"5\" cols=\"60\"></textarea></p>\n");
    fprintf(fout, "<p>%s:<br>\n", _("Comment for other judges (optional)"));
    fprintf(fout, "<p><textarea name=\"warn_comment\" rows=\"5\" cols=\"60\"></textarea></p>\n");
    fprintf(fout, "<p>%s</p>\n", BUTTON(NEW_SRV_ACTION_ISSUE_WARNING));
    fprintf(fout, "</form>\n");
  }

  if (opcaps_check(phr->caps, OPCAP_EDIT_REG) >= 0) {
    fprintf(fout, "<h2>%s</h3>\n", _("Disqualify user"));
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    html_hidden(fout, "user_id", "%d", view_user_id);
    fprintf(fout, "<p>%s:<br>\n",
            _("Disqualification explanation"));
    fprintf(fout, "<p><textarea name=\"disq_comment\" rows=\"5\" cols=\"60\">");
    if (u_extra->disq_comment) {
      fprintf(fout, "%s", ARMOR(u_extra->disq_comment));
    }
    fprintf(fout, "</textarea></p>\n");

    fprintf(fout, "<table class=\"b0\"><tr>");
    fprintf(fout, "<td class=\"b0\">%s</td>",
            ns_submit_button(bb, sizeof(bb), 0,
                             NEW_SRV_ACTION_SET_DISQUALIFICATION,
                             (flags & TEAM_DISQUALIFIED)?_("Edit comment"):_("Disqualify")));
    if ((flags & TEAM_DISQUALIFIED))
      fprintf(fout, "<td class=\"b0\">%s</td>\n",
              BUTTON(NEW_SRV_ACTION_CLEAR_DISQUALIFICATION));
    fprintf(fout, "</tr></table>\n");
    fprintf(fout, "</form>\n");
  }

  html_armor_free(&ab);
  return 0;
}

int
ns_new_run_form(FILE *fout, FILE *log_f,
                struct http_request_info *phr,
                const struct contest_desc *cnts,
                struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int i;
  unsigned char bb[1024];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  fprintf(fout, "<p>%s%s</a></p>",
          ns_aref(bb, sizeof(bb), phr, 0, 0),
          _("To main page"));

  html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
  fprintf(fout, "<table>\n");

  fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
          _("User ID"), html_input_text(bb, sizeof(bb), "run_user_id", 10, 0));

  fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n",
          _("User login"),
          html_input_text(bb, sizeof(bb), "run_user_login", 10, 0));

  fprintf(fout, "<tr><td>%s:</td>", _("Problem"));
  fprintf(fout, "<td><select name=\"prob_id\"><option value=\"\"></option>\n");
  for (i = 1; i <= cs->max_prob; i++)
    if (cs->probs[i]) {
      fprintf(fout, "<option value=\"%d\">%s - %s</option>\n",
              i, cs->probs[i]->short_name, ARMOR(cs->probs[i]->long_name));
    }
  fprintf(fout, "</select></td></tr>\n");

  fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Variant"),
          html_input_text(bb, sizeof(bb), "variant", 10, 0));

  fprintf(fout, "<tr><td>%s:</td>", _("Language"));
  fprintf(fout, "<td><select name=\"language\"><option value=\"\"></option>\n");
  for (i = 1; i <= cs->max_lang; i++)
    if (cs->langs[i]) {
      fprintf(fout, "<option value=\"%d\">%s - %s</option>\n",
              i, cs->langs[i]->short_name, ARMOR(cs->langs[i]->long_name));
    }
  fprintf(fout, "</select></td></tr>\n");

  fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Imported?"),
          html_select_yesno(bb, sizeof(bb), "is_imported", 0));
  fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Hidden?"),
          html_select_yesno(bb, sizeof(bb), "is_hidden", 0));
  fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Read-only?"),
          html_select_yesno(bb, sizeof(bb), "is_readonly", 0));

  fprintf(fout, "<tr><td>%s:</td>", _("Status"));
  write_change_status_dialog(cs, fout, 0, 0, 0);
  fprintf(fout, "</tr>\n");

  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Tests passed"),
            html_input_text(bb, sizeof(bb), "tests", 10, 0));
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Score gained"),
            html_input_text(bb, sizeof(bb), "score", 10, 0));
  } else if (global->score_system_val == SCORE_MOSCOW) {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Failed test"),
            html_input_text(bb, sizeof(bb), "tests", 10, 0));
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Score gained"),
            html_input_text(bb, sizeof(bb), "score", 10, 0));
  } else {
    fprintf(fout, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Failed test"),
            html_input_text(bb, sizeof(bb), "tests", 10, 0));
  }

  fprintf(fout, "<tr><td>%s:</td>"
          "<td><input type=\"file\" name=\"file\"/></td></tr>\n",
          _("File"));

  fprintf(fout, "<tr><td>%s</td><td>&nbsp;</td></tr>\n",
          BUTTON(NEW_SRV_ACTION_NEW_RUN));
  fprintf(fout, "</table></form>\n");

  html_armor_free(&ab);
  return 0;
}

void
ns_write_priv_standings(const serve_state_t state,
                        const struct contest_desc *cnts,
                        FILE *f, int accepting_mode)
{
  write_standings_header(state, cnts, f, 1, 0, 0, 0);

  if (state->global->score_system_val == SCORE_KIROV
      || state->global->score_system_val == SCORE_OLYMPIAD)
    do_write_kirov_standings(state, cnts, f, 0, 1, 0, 0, 0, 0, 0 /*accepting_mode*/, 1, 0);
  else if (state->global->score_system_val == SCORE_MOSCOW)
    do_write_moscow_standings(state, cnts, f, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0);
  else
    do_write_standings(state, cnts, f, 1, 0, 0, 0, 0, 0, 0, 1, 0);
}

void
ns_download_runs(
	const serve_state_t cs, FILE *fout, FILE *log_f,
        int run_selection,
        int dir_struct,
        int file_name_mask,
        size_t run_mask_size,
        unsigned long *run_mask)
{
  path_t tmpdir = { 0 };
  path_t dir1;
  const unsigned char *s = 0;
  time_t cur_time = time(0);
  int serial = 0;
  struct tm *ptm;
  path_t dir2 = { 0 };
  int need_remove = 0;
  path_t name3, dir3;
  int pid, p, status;
  path_t tgzname, tgzpath;
  char *file_bytes = 0;
  size_t file_size = 0;
  int total_runs, run_id;
  struct run_entry info;
  path_t dir4, dir4a, dir5;
  unsigned char prob_buf[1024], *prob_ptr;
  unsigned char login_buf[1024], *login_ptr;
  unsigned char name_buf[1024];
  unsigned char lang_buf[1024], *lang_ptr;
  const unsigned char *name_ptr;
  const unsigned char *suff_ptr;
  unsigned char *file_name_str = 0;
  size_t file_name_size = 0, file_name_exp_len;
  unsigned char *sep, *ptr;
  path_t dstpath, srcpath;
  int srcflags;

  file_name_size = 1024;
  file_name_str = (unsigned char*) xmalloc(file_name_size);

  if ((s = getenv("TMPDIR"))) {
    snprintf(tmpdir, sizeof(tmpdir), "%s", s);
  }
#if defined P_tmpdir
  if (!tmpdir[0]) {
    snprintf(tmpdir, sizeof(tmpdir), "%s", P_tmpdir);
  }
#endif
  if (!tmpdir[0]) {
    snprintf(tmpdir, sizeof(tmpdir), "%s", "/tmp");
  }

  ptm = localtime(&cur_time);
  snprintf(dir1, sizeof(dir1), "ejudge%04d%02d%02d%02d%02d%02d",
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  while (1) {
    snprintf(dir2, sizeof(dir2), "%s/%s%d", tmpdir, dir1, serial);
    errno = 0;
    if (mkdir(dir2, 0700) >= 0) break;
    if (errno != EEXIST) {
      ns_error(log_f, NEW_SRV_ERR_MKDIR_FAILED, dir2, os_ErrorMsg());
      goto cleanup;
    }
    serial++;
  }
  need_remove = 1;

  snprintf(name3, sizeof(name3), "contest_%d_%04d%02d%02d%02d%02d%02d",
           cs->global->contest_id, 
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  snprintf(dir3, sizeof(dir3), "%s/%s", dir2, name3);
  if (mkdir(dir3, 0755) < 0) {
    ns_error(log_f, NEW_SRV_ERR_MKDIR_FAILED, dir2, os_ErrorMsg());
    goto cleanup;
  }
  snprintf(tgzname, sizeof(tgzname), "%s.tgz", name3);
  snprintf(tgzpath, sizeof(tgzpath), "%s/%s", dir2, tgzname);

  total_runs = run_get_total(cs->runlog_state);
  for (run_id = 0; run_id < total_runs; run_id++) {
    if (run_selection == NS_RUNSEL_DISPLAYED) {
      if (run_id >= 8 * sizeof(run_mask[0]) * run_mask_size) continue;
      if (!(run_mask[run_id / (8 * sizeof(run_mask[0]))] & (1UL << (run_id % (8 * sizeof(run_mask[0])))))) continue;
    }
    if (run_get_entry(cs->runlog_state, run_id, &info) < 0) {
      ns_error(log_f, NEW_SRV_ERR_INV_RUN_ID);
      goto cleanup;
    }
    if (run_selection == NS_RUNSEL_OK && info.status != RUN_OK) continue;
    if (info.status > RUN_LAST) continue;
    if (info.status > RUN_MAX_STATUS && info.status < RUN_TRANSIENT_FIRST)
      continue;

    if (!(login_ptr = teamdb_get_login(cs->teamdb_state, info.user_id))) {
      snprintf(login_buf, sizeof(login_buf), "!user_%d", info.user_id);
      login_ptr = login_buf;
    }
    if (!(name_ptr = teamdb_get_name_2(cs->teamdb_state, info.user_id))) {
      snprintf(name_buf, sizeof(name_buf), "!user_%d", info.user_id);
      name_ptr = name_buf;
    } else {
      filename_armor_bytes(name_buf, sizeof(name_buf), name_ptr,
                           strlen(name_ptr));
      name_ptr = name_buf;
    }
    if (info.prob_id > 0 && info.prob_id <= cs->max_prob
        && cs->probs[info.prob_id]) {
      prob_ptr = cs->probs[info.prob_id]->short_name;
    } else {
      snprintf(prob_buf, sizeof(prob_buf), "!prob_%d", info.prob_id);
      prob_ptr = prob_buf;
    }
    if (info.lang_id > 0 && info.lang_id <= cs->max_lang
        && cs->langs[info.lang_id]) {
      lang_ptr = cs->langs[info.lang_id]->short_name;
      suff_ptr = cs->langs[info.lang_id]->src_sfx;
    } else if (info.lang_id) {
      snprintf(lang_buf, sizeof(lang_buf), "!lang_%d", info.lang_id);
      lang_ptr = lang_buf;
      suff_ptr = "";
    } else {
      lang_buf[0] = 0;
      lang_ptr = lang_buf;
      suff_ptr = mime_type_get_suffix(info.mime_type);
    }

    // create necessary directories
    dir4[0] = 0;
    dir4a[0] = 0;
    switch (dir_struct) {
    case 0:// /<File> (no directory structure)
      break;
    case 1:// /<Problem>/<File>
      snprintf(dir4, sizeof(dir4), "%s", prob_ptr);
      break;
    case 2:// /<User_Id>/<File>
      snprintf(dir4, sizeof(dir4), "%d", info.user_id);
      break;
    case 3:// /<User_Login>/<File>
      snprintf(dir4, sizeof(dir4), "%s", login_ptr);
      break;
    case 4:// /<Problem>/<User_Id>/<File>
      snprintf(dir4, sizeof(dir4), "%s", prob_ptr);
      snprintf(dir4a, sizeof(dir4a), "%d", info.user_id);
      break;
    case 5:// /<Problem>/<User_Login>/<File>
      snprintf(dir4, sizeof(dir4), "%s", prob_ptr);
      snprintf(dir4a, sizeof(dir4a), "%s", login_ptr);
      break;
    case 6:// /<User_Id>/<Problem>/<File>
      snprintf(dir4, sizeof(dir4), "%d", info.user_id);
      snprintf(dir4a, sizeof(dir4a), "%s", prob_ptr);
      break;
    case 7:// /<User_Login>/<Problem>/<File>
      snprintf(dir4, sizeof(dir4), "%s", login_ptr);
      snprintf(dir4a, sizeof(dir4a), "%s", prob_ptr);
      break;
    case 8:// /<User_Name>/<File>
      snprintf(dir4, sizeof(dir4), "%s", name_ptr);
      break;
    case 9:// /<Problem>/<User_Name>/<File>
      snprintf(dir4, sizeof(dir4), "%s", prob_ptr);
      snprintf(dir4a, sizeof(dir4a), "%s", name_ptr);
      break;
    case 10:// /<User_Name>/<Problem>/<File>
      snprintf(dir4, sizeof(dir4), "%s", name_ptr);
      snprintf(dir4a, sizeof(dir4a), "%s", prob_ptr);
      break;
    default:
      abort();
    }
    if (dir4[0]) {
      snprintf(dir5, sizeof(dir5), "%s/%s", dir3, dir4);
      errno = 0;
      if (mkdir(dir5, 0755) < 0 && errno != EEXIST) {
        ns_error(log_f, NEW_SRV_ERR_MKDIR_FAILED, dir5, os_ErrorMsg());
        goto cleanup;
      }
      if (dir4a[0]) {
        snprintf(dir5, sizeof(dir5), "%s/%s/%s", dir3, dir4, dir4a);
        errno = 0;
        if (mkdir(dir5, 0755) < 0 && errno != EEXIST) {
          ns_error(log_f, NEW_SRV_ERR_MKDIR_FAILED, dir5, os_ErrorMsg());
          goto cleanup;
        }
      }
    } else {
      snprintf(dir5, sizeof(dir5), "%s", dir3);
    }

    file_name_exp_len = 64 + strlen(login_ptr) + strlen(name_ptr)
      + strlen(prob_ptr) + strlen(lang_ptr) + strlen(suff_ptr);
    if (file_name_exp_len > file_name_size) {
      while (file_name_exp_len > file_name_size) file_name_size *= 2;
      xfree(file_name_str);
      file_name_str = (unsigned char*) xmalloc(file_name_size);
    }

    sep = "";
    ptr = file_name_str;
    if ((file_name_mask & NS_FILE_PATTERN_RUN)) {
      ptr += sprintf(ptr, "%s%06d", sep, run_id);
      sep = "-";
    }
    if ((file_name_mask & NS_FILE_PATTERN_UID)) {
      ptr += sprintf(ptr, "%s%d", sep, info.user_id);
      sep = "-";
    }
    if ((file_name_mask & NS_FILE_PATTERN_LOGIN)) {
      ptr += sprintf(ptr, "%s%s", sep, login_ptr);
      sep = "-";
    }
    if ((file_name_mask & NS_FILE_PATTERN_NAME)) {
      ptr += sprintf(ptr, "%s%s", sep, name_ptr);
      sep = "-";
    }
    if ((file_name_mask & NS_FILE_PATTERN_PROB)) {
      ptr += sprintf(ptr, "%s%s", sep, prob_ptr);
      sep = "-";
    }
    if ((file_name_mask & NS_FILE_PATTERN_LANG)) {
      ptr += sprintf(ptr, "%s%s", sep, lang_ptr);
      sep = "-";
    }
    if ((file_name_mask & NS_FILE_PATTERN_SUFFIX)) {
      ptr += sprintf(ptr, "%s", suff_ptr);
    }
    snprintf(dstpath, sizeof(dstpath), "%s/%s", dir5, file_name_str);

    srcflags = archive_make_read_path(cs, srcpath, sizeof(srcpath),
                                      cs->global->run_archive_dir, run_id,
                                      0, 0);
    if (srcflags < 0) {
      ns_error(log_f, NEW_SRV_ERR_SOURCE_NONEXISTANT);
      goto cleanup;
    }

    if (generic_copy_file(srcflags, 0, srcpath, "", 0, 0, dstpath, "") < 0) {
      ns_error(log_f, NEW_SRV_ERR_DISK_WRITE_ERROR);
      goto cleanup;
    }
  }

  if ((pid = fork()) < 0) {
    err("fork failed: %s", os_ErrorMsg());
    ns_error(log_f, NEW_SRV_ERR_TAR_FAILED);
    goto cleanup;
  } else if (!pid) {
    if (chdir(dir2) < 0) {
      err("chdir to %s failed: %s", dir2, os_ErrorMsg());
      _exit(1);
    }
    execl("/bin/tar", "/bin/tar", "cfz", tgzname, name3, NULL);
    err("execl failed: %s", os_ErrorMsg());
    _exit(1);
  }

  while ((p = waitpid(pid, &status, 0)) != p);
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    ns_error(log_f, NEW_SRV_ERR_TAR_FAILED);
    goto cleanup;
  }

  if (generic_read_file(&file_bytes, 0, &file_size, 0, 0, tgzpath, 0) < 0) {
    ns_error(log_f, NEW_SRV_ERR_DISK_READ_ERROR);
    goto cleanup;
  }
  
  fprintf(fout,
          "Content-type: application/x-tar\n"
          "Content-Disposition: attachment; filename=\"%s\"\n"
          "\n",
          tgzname);
  if (file_size > 0) {
    if (fwrite(file_bytes, 1, file_size, fout) != file_size) {
      ns_error(log_f, NEW_SRV_ERR_OUTPUT_ERROR);
      goto cleanup;
    }
  }

 cleanup:;
  if (need_remove) {
    remove_directory_recursively(dir2);
  }
  xfree(file_bytes);
  xfree(file_name_str);
}

enum
{
  CSV_RUNID,
  CSV_UID,
  CSV_LOGIN,
  CSV_NAME,
  CSV_CYPHER,
  CSV_PROB,
  CSV_LANG,
  CSV_STATUS,
  CSV_TESTS,
  CSV_SCORE,

  CSV_LAST,
};

static const unsigned char * const supported_columns[] =
{
  "RunId",
  "UserId",
  "Login",
  "Name",
  "Cypher",
  "Problem",
  "Language",
  "Status",
  "Tests",
  "Score",

  0,
};

int
ns_upload_csv_runs(
	struct http_request_info *phr,
	const serve_state_t cs, FILE *log_f,
        const unsigned char *csv_text)
{
  int retval = -1;
  struct csv_file *csv = 0;
  int ncol, row, col, i, x, n;
  int col_ind[CSV_LAST];
  struct run_entry *runs = 0;
  struct csv_line *rr;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  const struct section_language_data *lang;
  const unsigned char *run_text = "";
  size_t run_size = 0;
  int mime_type = 0;
  const unsigned char *mime_type_str = 0;
  char **lang_list = 0;
  char *eptr;
  int run_id;
  struct timeval precise_time;
  int arch_flags;
  path_t run_path;
  const unsigned char *s;

  memset(col_ind, -1, sizeof(col_ind));
  if (!(csv = csv_parse(csv_text, log_f, ';'))) goto cleanup;
  if (csv->u <= 1) {
    fprintf(log_f, "%s\n", _("Too few lines in CSV file"));
    goto cleanup;
  }
  ncol = csv->v[0].u;
  for (row = 1; row < csv->u; row++)
    if (csv->v[row].u != ncol) {
      fprintf(log_f,
              _("Header row defines %d columns, but row %d has %zu columns\n"), 
              ncol, row, csv->v[row].u);
      goto cleanup;
    }

  // enumerate header columns
  for (col = 0; col < ncol; col++) {
    if (!csv->v[0].v[col] || !*csv->v[0].v[col]) {
      fprintf(log_f, _("Ignoring empty column %d\n"), col + 1);
      continue;
    }
    for (i = 0; supported_columns[i]; i++)
      if (!strcasecmp(supported_columns[i], csv->v[0].v[col]))
        break;
    if (!supported_columns[i]) {
      fprintf(log_f, _("Ignoring unsupported column %d (%s)\n"), col + 1,
              csv->v[0].v[col]);
      continue;
    }
    if (col_ind[i] >= 0) {
      fprintf(log_f, _("Column name %s is already defined as column %d\n"),
              supported_columns[i], col_ind[i] + 1);
      goto cleanup;
    }
    col_ind[i] = col;
  }
  /*
  // check mandatory columns
  for (i = 0; i < CSV_LAST; i++)
    if (mandatory_columns[i] && col_ind[i] < 0) {
      fprintf(log_f, _("Mandatory column %s is not specified"),
              supported_columns[i]);
      goto cleanup;
    }
  */

  // check every row
  XCALLOC(runs, csv->u);
  for (row = 1; row < csv->u; row++) {
    rr = &csv->v[row];

    // we need either user_id, user_login, or user_name
    if (col_ind[CSV_UID] >= 0) {
      if (!(s = rr->v[col_ind[CSV_UID]]) || !*s) {
        fprintf(log_f, _("UId is empty in row %d\n"), row);
        goto cleanup;
      }
      if (sscanf(s, "%d%n", &x, &n) != 1 || s[n]
          || teamdb_lookup(cs->teamdb_state, x) < 0) {
        fprintf(log_f, _("Invalid UId %s in row %d\n"), s, row);
        goto cleanup;
      }
      runs[row].user_id = x;
    } else if (col_ind[CSV_LOGIN] >= 0) {
      if (!(s = rr->v[col_ind[CSV_LOGIN]]) || !*s) {
        fprintf(log_f, _("Login is empty in row %d\n"), row);
        goto cleanup;
      }
      if ((x = teamdb_lookup_login(cs->teamdb_state, s)) <= 0){
        fprintf(log_f, _("Invalid login `%s' in row %d\n"),
                rr->v[col_ind[CSV_LOGIN]], row);
        goto cleanup;
      }
      runs[row].user_id = x;
    } else if (col_ind[CSV_NAME] >= 0) {
      if (!(s = rr->v[col_ind[CSV_NAME]]) || !*s) {
        fprintf(log_f, _("Name is empty in row %d\n"), row);
        goto cleanup;
      }
      if ((x = teamdb_lookup_name(cs->teamdb_state, s)) <= 0){
        fprintf(log_f, _("Invalid name `%s' in row %d\n"),
                rr->v[col_ind[CSV_NAME]], row);
        goto cleanup;
      }
      runs[row].user_id = x;
    } else {
      fprintf(log_f, _("Neither user_id, login, nor name are specified\n"));
      goto cleanup;
    }

    if (col_ind[CSV_PROB] < 0) {
      fprintf(log_f, _("Problem column is undefined\n"));
      goto cleanup;
    }
    if (!(s = rr->v[col_ind[CSV_PROB]]) || !*s) {
      fprintf(log_f, _("Problem is empty in row %d\n"), row);
      goto cleanup;
    }
    prob = 0;
    for (x = 1; x <= cs->max_prob; x++)
      if (cs->probs[x] && !strcmp(s, cs->probs[x]->short_name)) {
        prob = cs->probs[x];
        break;
      }
    if (!prob) {
      fprintf(log_f, _("Invalid problem `%s' in row %d\n"), s, row);
      goto cleanup;
    }
    runs[row].prob_id = prob->id;

    lang = 0;
    if (prob->type_val == PROB_TYPE_STANDARD) {
      if (col_ind[CSV_LANG] < 0) {
        fprintf(log_f, _("Language column is undefined\n"));
        goto cleanup;
      }
      if (!(s = rr->v[col_ind[CSV_LANG]]) || !*s) {
        fprintf(log_f, _("Language is empty in row %d\n"), row);
        goto cleanup;
      }
      for (x = 1; x <= cs->max_lang; x++)
        if (cs->langs[x] && !strcmp(s, cs->langs[x]->short_name)) {
          lang = cs->langs[x];
          break;
        }
      if (!lang) {
        fprintf(log_f, _("Invalid language `%s' in row %d\n"), s, row);
        goto cleanup;
      }
      runs[row].lang_id = lang->id;

      if (lang->disabled) {
        fprintf(log_f, _("Language %s is disabled in row %d\n"),
                lang->short_name, row);
        goto cleanup;
      }

      if (prob->enable_language) {
        lang_list = prob->enable_language;
        for (i = 0; lang_list[i]; i++)
          if (!strcmp(lang_list[i], lang->short_name))
            break;
        if (!lang_list[i]) {
          fprintf(log_f, _("Language %s is not enabled for problem %s in row %d\n"),
                  lang->short_name, prob->short_name, row);
          goto cleanup;
        }
      } else if (prob->disable_language) {
        lang_list = prob->disable_language;
        for (i = 0; lang_list[i]; i++)
          if (!strcmp(lang_list[i], lang->short_name))
            break;
        if (lang_list[i]) {
          fprintf(log_f, _("Language %s is disabled for problem %s in row %d\n"),
                  lang->short_name, prob->short_name, row);
          goto cleanup;
        }
      }
    } else {
      mime_type = MIME_TYPE_TEXT;
      mime_type_str = mime_type_get_type(mime_type);
      runs[row].mime_type = mime_type;

      if (prob->enable_language) {
        lang_list = prob->enable_language;
        for (i = 0; lang_list[i]; i++)
          if (!strcmp(lang_list[i], mime_type_str))
            break;
        if (!lang_list[i]) {
          fprintf(log_f, _("Content type %s is not enabled for problem %s in row %d\n"),
                  mime_type_str, prob->short_name, row);
          goto cleanup;
        }
      } else if (prob->disable_language) {
        lang_list = prob->disable_language;
        for (i = 0; lang_list[i]; i++)
          if (!strcmp(lang_list[i], mime_type_str))
            break;
        if (lang_list[i]) {
          fprintf(log_f, _("Content type %s is disabled for problem %s in row %d\n"),
                  mime_type_str, prob->short_name, row);
          goto cleanup;
        }
      }
    }
    sha_buffer(run_text, run_size, runs[row].sha1);

    if (col_ind[CSV_TESTS] >= 0) {
      if (!(s = rr->v[col_ind[CSV_TESTS]]) || !*s) {
        fprintf(log_f, _("Tests is empty in row %d\n"), row);
        goto cleanup;
      }
      errno = 0;
      x = strtol(s, &eptr, 10);
      if (errno || *eptr || x < -1 || x > 100000) {
        fprintf(log_f, _("Tests value `%s' is invalid in row %d\n"), s, row);
        goto cleanup;
      }
      runs[row].test = x;
    } else {
      runs[row].test = 1;
    }

    if (col_ind[CSV_SCORE] < 0) {
      fprintf(log_f, _("Score column is undefined\n"));
      goto cleanup;
    }
    if (!(s = rr->v[col_ind[CSV_SCORE]]) || !*s) {
      fprintf(log_f, _("Score is empty in row %d\n"), row);
      goto cleanup;
    }
    errno = 0;
    x = strtol(s, &eptr, 10);
    if (errno || *eptr || x < -1 || x > 100000) {
      fprintf(log_f, _("Score value `%s' is invalid in row %d\n"), s, row);
      goto cleanup;
    }
    runs[row].score = x;

    if (col_ind[CSV_STATUS] >= 0) {
      if (!(s = rr->v[col_ind[CSV_STATUS]]) || !*s) {
        fprintf(log_f, _("Status is empty in row %d\n"), row);
        goto cleanup;
      }
      if (run_str_short_to_status(s, &x) < 0) {
        fprintf(log_f, _("Invalid status `%s' in row %d\n"), s, row);
        goto cleanup;
      }
      if (x < 0 || x > RUN_MAX_STATUS) {
        fprintf(log_f, _("Invalid status `%s' (%d) in row %d\n"),
                rr->v[col_ind[CSV_STATUS]], x, row);
        goto cleanup;
      }
      runs[row].status = x;
    } else {
      if (runs[row].score >= prob->full_score)
        runs[row].status = RUN_OK;
      else
        runs[row].status = RUN_PARTIAL;
    }

    fprintf(log_f,
            "%d: user %d, problem %d, language %d, status %d, tests %d, score %d\n",
            row, runs[row].user_id, runs[row].prob_id, runs[row].lang_id,
            runs[row].status, runs[row].test, runs[row].score);
  }

  for (row = 1; row < csv->u; row++) {
    gettimeofday(&precise_time, 0);
    run_id = run_add_record(cs->runlog_state, 
                            precise_time.tv_sec, precise_time.tv_usec * 1000,
                            run_size, runs[row].sha1,
                            phr->ip, phr->ssl_flag, phr->locale_id,
                            runs[row].user_id,
                            runs[row].prob_id,
                            runs[row].lang_id,
                            runs[row].variant,
                            runs[row].is_hidden,
                            runs[row].mime_type);
    if (run_id < 0) {
      fprintf(log_f, _("Failed to add row %d to runlog\n"), row);
      goto cleanup;
    }
    serve_move_files_to_insert_run(cs, run_id);
    arch_flags = archive_make_write_path(cs, run_path, sizeof(run_path),
                                         global->run_archive_dir, run_id,
                                         run_size, 0);
    if (arch_flags < 0) {
      run_undo_add_record(cs->runlog_state, run_id);
      fprintf(log_f, _("Cannot allocate space to store run row %d\n"), row);
      goto cleanup;
    }
    if (archive_dir_prepare(cs, global->run_archive_dir, run_id, 0, 0) < 0) {
      run_undo_add_record(cs->runlog_state, run_id);
      fprintf(log_f, _("Cannot allocate space to store run row %d\n"), row);
      goto cleanup;
    }
    if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
      run_undo_add_record(cs->runlog_state, run_id);
      fprintf(log_f, _("Cannot write run row %d\n"), row);
      goto cleanup;
    }
    run_set_entry(cs->runlog_state, run_id,
                  RUN_ENTRY_STATUS | RUN_ENTRY_TEST | RUN_ENTRY_SCORE,
                  &runs[row]);

    serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                    "Command: new_run\n"
                    "Status: %s\n"
                    "Run-id: %d\n",
                    run_status_str(runs[row].status, 0, 0, 0, 0),
                    run_id);
  }

  retval = 0;

 cleanup:
  xfree(runs);
  csv_free(csv);
  return retval;
}

int
ns_upload_csv_results(
	struct http_request_info *phr,
	const serve_state_t cs, FILE *log_f,
        const unsigned char *csv_text)
{
  int retval = -1;
  int col_ind[CSV_LAST];
  struct csv_file *csv = 0;
  struct run_entry *runs = 0, *pe, te;
  struct csv_line *rr;
  int ncol, row, col, i, x, n, run_id;
  unsigned char *s;
  const unsigned char *cyph;
  const struct section_problem_data *prob = 0;
  char *eptr;

  memset(col_ind, -1, sizeof(col_ind));
  if (!(csv = csv_parse(csv_text, log_f, ';'))) goto cleanup;
  if (csv->u <= 1) {
    fprintf(log_f, "%s\n", _("Too few lines in CSV file"));
    goto cleanup;
  }
  ncol = csv->v[0].u;
  for (row = 1; row < csv->u; row++)
    if (csv->v[row].u != ncol) {
      fprintf(log_f,
              _("Header row defines %d columns, but row %d has %zu columns\n"), 
              ncol, row, csv->v[row].u);
      goto cleanup;
    }

  // enumerate header columns
  for (col = 0; col < ncol; col++) {
    if (!csv->v[0].v[col] || !*csv->v[0].v[col]) {
      fprintf(log_f, _("Ignoring empty column %d\n"), col + 1);
      continue;
    }
    for (i = 0; supported_columns[i]; i++)
      if (!strcasecmp(supported_columns[i], csv->v[0].v[col]))
        break;
    if (!supported_columns[i]) {
      fprintf(log_f, _("Ignoring unsupported column %d (%s)\n"), col + 1,
              csv->v[0].v[col]);
      continue;
    }
    if (col_ind[i] >= 0) {
      fprintf(log_f, _("Column name %s is already defined as column %d\n"),
              supported_columns[i], col_ind[i] + 1);
      goto cleanup;
    }
    col_ind[i] = col;
  }

  // check every row
  XCALLOC(runs, csv->u);
  for (row = 1; row < csv->u; row++) {
    rr = &csv->v[row];
    pe = &runs[row];

    if (col_ind[CSV_RUNID] >= 0) {
      if (!(s = rr->v[col_ind[CSV_RUNID]]) || !*s) {
        fprintf(log_f, _("UId is empty in row %d\n"), row);
        goto cleanup;
      }
      if (sscanf(s, "%d%n", &x, &n) != 1 || s[n]
          || run_get_entry(cs->runlog_state, x, pe)) {
        fprintf(log_f, _("Invalid RunId %s in row %d\n"), s, row);
        goto cleanup;
      }
      if (pe->prob_id <= 0 || pe->prob_id > cs->max_prob
          || !(prob = cs->probs[pe->prob_id])) {
        fprintf(log_f, _("Invalid problem in run %d in row %d\n"), x, row);
        goto cleanup;
      }
    } else {
      if (col_ind[CSV_PROB] < 0) {
        fprintf(log_f, _("Problem column is undefined\n"));
        goto cleanup;
      }
      if (!(s = rr->v[col_ind[CSV_PROB]]) || !*s) {
        fprintf(log_f, _("Problem is empty in row %d\n"), row);
        goto cleanup;
      }
      prob = 0;
      for (x = 1; x <= cs->max_prob; x++)
        if (cs->probs[x] && !strcmp(s, cs->probs[x]->short_name)) {
          prob = cs->probs[x];
          break;
        }
      if (!prob) {
        fprintf(log_f, _("Invalid problem `%s' in row %d\n"), s, row);
        goto cleanup;
      }
      pe->prob_id = prob->id;

      if (col_ind[CSV_UID] >= 0) {
        if (!(s = rr->v[col_ind[CSV_UID]]) || !*s) {
          fprintf(log_f, _("UId is empty in row %d\n"), row);
          goto cleanup;
        }
        if (sscanf(s, "%d%n", &x, &n) != 1 || s[n]
            || teamdb_lookup(cs->teamdb_state, x) < 0) {
          fprintf(log_f, _("Invalid UId %s in row %d\n"), s, row);
          goto cleanup;
        }
        pe->user_id = x;
        // find the latest ACCEPTED run by uid/prob_id pair
        for (run_id = run_get_total(cs->runlog_state) - 1; run_id >= 0; run_id--) {
          if (run_get_entry(cs->runlog_state, run_id, &te) < 0) continue;
          if (!run_is_source_available(te.status)) continue;
          if (pe->user_id == te.user_id && pe->prob_id == te.prob_id) break;
        }
        if (run_id < 0) {
          fprintf(log_f, _("No entry for %d/%s\n"), pe->user_id, prob->short_name);
	  pe->run_id = -1;
	  continue;
        }
        *pe = te;
      } else if (col_ind[CSV_LOGIN] >= 0) {
        if (!(s = rr->v[col_ind[CSV_LOGIN]]) || !*s) {
          fprintf(log_f, _("Login is empty in row %d\n"), row);
          goto cleanup;
        }
        if ((x = teamdb_lookup_login(cs->teamdb_state, s)) <= 0){
          fprintf(log_f, _("Invalid login `%s' in row %d\n"), s, row);
          goto cleanup;
        }
        pe->user_id = x;

        // find the latest ACCEPTED run by login/prob_id pair
        for (run_id = run_get_total(cs->runlog_state) - 1; run_id >= 0; run_id--) {
          if (run_get_entry(cs->runlog_state, run_id, &te) < 0) continue;
          if (!run_is_source_available(te.status)) continue;
          if (!strcmp(s, teamdb_get_login(cs->teamdb_state, te.user_id)) && pe->prob_id == te.prob_id) break;
        }
        if (run_id < 0) {
          fprintf(log_f, _("No entry for %s/%s\n"), s, prob->short_name);
	  pe->run_id = -1;
	  continue;
        }
        *pe = te;
      } else if (col_ind[CSV_NAME] >= 0) {
        if (!(s = rr->v[col_ind[CSV_NAME]]) || !*s) {
          fprintf(log_f, _("Name is empty in row %d\n"), row);
          goto cleanup;
        }
        if ((x = teamdb_lookup_name(cs->teamdb_state, s)) <= 0){
          fprintf(log_f, _("Invalid name `%s' in row %d\n"), s, row);
          goto cleanup;
        }
        pe->user_id = x;

        // find the latest ACCEPTED run by name/prob_id pair
        for (run_id = run_get_total(cs->runlog_state) - 1; run_id >= 0; run_id--) {
          if (run_get_entry(cs->runlog_state, run_id, &te) < 0) continue;
          if (!run_is_source_available(te.status)) continue;
          if (!strcmp(s, teamdb_get_name_2(cs->teamdb_state, te.user_id)) && pe->prob_id == te.prob_id) break;
        }
        if (run_id < 0) {
          fprintf(log_f, _("No entry for %s/%s\n"), s, prob->short_name);
	  pe->run_id = -1;
	  continue;
        }
        *pe = te;
      } else if (col_ind[CSV_CYPHER] >= 0) {
        if (!(s = rr->v[col_ind[CSV_CYPHER]]) || !*s) {
          fprintf(log_f, _("Cypher is empty in row %d\n"), row);
          goto cleanup;
        }
        if ((x = teamdb_lookup_cypher(cs->teamdb_state, s)) <= 0){
          fprintf(log_f, _("Invalid cypher `%s' in row %d\n"), s, row);
          goto cleanup;
        }
        pe->user_id = x;

        // find the latest ACCEPTED run by cypher/prob_id pair
        for (run_id = run_get_total(cs->runlog_state) - 1; run_id >= 0; run_id--) {
          if (run_get_entry(cs->runlog_state, run_id, &te) < 0) continue;
          if (!run_is_source_available(te.status)) continue;
          if (!(cyph = teamdb_get_cypher(cs->teamdb_state, te.user_id)))
            continue;
          if (!strcmp(s, cyph) && pe->prob_id == te.prob_id) break;
        }
        if (run_id < 0) {
          fprintf(log_f, _("No entry for %s/%s\n"), s, prob->short_name);
	  pe->run_id = -1;
	  continue;
        }
        *pe = te;
      } else {
        fprintf(log_f, _("Neither user_id, login, name, nor cypher are specified\n"));
        goto cleanup;
      }
    }

    if (col_ind[CSV_TESTS] >= 0) {
      if (!(s = rr->v[col_ind[CSV_TESTS]]) || !*s) {
        fprintf(log_f, _("Tests is empty in row %d\n"), row);
        goto cleanup;
      }
      errno = 0;
      x = strtol(s, &eptr, 10);
      if (errno || *eptr || x < -1 || x > 100000) {
        fprintf(log_f, _("Tests value `%s' is invalid in row %d\n"), s, row);
        goto cleanup;
      }
      pe->test = x;
    } else {
      pe->test = 1;
    }

    if (col_ind[CSV_SCORE] < 0) {
      fprintf(log_f, _("Score column is undefined\n"));
      goto cleanup;
    }
    if (!(s = rr->v[col_ind[CSV_SCORE]]) || !*s) {
      fprintf(log_f, _("Score is empty in row %d\n"), row);
      goto cleanup;
    }
    errno = 0;
    x = strtol(s, &eptr, 10);
    if (errno || *eptr || x < -1 || x > 100000) {
      fprintf(log_f, _("Score value `%s' is invalid in row %d\n"), s, row);
      goto cleanup;
    }
    pe->score = x;

    if (col_ind[CSV_STATUS] >= 0) {
      if (!(s = rr->v[col_ind[CSV_STATUS]]) || !*s) {
        fprintf(log_f, _("Status is empty in row %d\n"), row);
        goto cleanup;
      }
      if (run_str_short_to_status(s, &x) < 0) {
        fprintf(log_f, _("Invalid status `%s' in row %d\n"), s, row);
        goto cleanup;
      }
      if (x < 0 || x > RUN_MAX_STATUS) {
        fprintf(log_f, _("Invalid status `%s' (%d) in row %d\n"),
                rr->v[col_ind[CSV_STATUS]], x, row);
        goto cleanup;
      }
      pe->status = x;
    } else {
      if (pe->score >= prob->full_score)
        pe->status = RUN_OK;
      else
        pe->status = RUN_PARTIAL;
    }

    fprintf(log_f,
            "%d: run_id %d, status %d, tests %d, score %d\n",
            row, pe->run_id,  pe->status, pe->test, pe->score);
  }

  for (row = 1; row < csv->u; row++) {
    if (runs[row].run_id == -1) continue;
    run_set_entry(cs->runlog_state, runs[row].run_id,
                  RUN_ENTRY_STATUS | RUN_ENTRY_TEST | RUN_ENTRY_SCORE,
                  &runs[row]);
  }

  /*
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  const struct section_language_data *lang;
  const unsigned char *run_text = "";
  size_t run_size = 0;
  int mime_type = 0;
  const unsigned char *mime_type_str = 0;
  char **lang_list = 0;
  char *eptr;
  int run_id;
  struct timeval precise_time;
  int arch_flags;
  path_t run_path;
  const unsigned char *s;


  // check every row
  XCALLOC(runs, csv->u);
  for (row = 1; row < csv->u; row++) {
    rr = &csv->v[row];

    // we need either user_id, user_login, or user_name
    if (col_ind[CSV_UID] >= 0) {
      if (!(s = rr->v[col_ind[CSV_UID]]) || !*s) {
        fprintf(log_f, _("UId is empty in row %d\n"), row);
        goto cleanup;
      }
      if (sscanf(s, "%d%n", &x, &n) != 1 || s[n]
          || teamdb_lookup(cs->teamdb_state, x) < 0) {
        fprintf(log_f, _("Invalid UId %s in row %d\n"), s, row);
        goto cleanup;
      }
    } else if (col_ind[CSV_LOGIN] >= 0) {
      if (!(s = rr->v[col_ind[CSV_LOGIN]]) || !*s) {
        fprintf(log_f, _("Login is empty in row %d\n"), row);
        goto cleanup;
      }
      if ((x = teamdb_lookup_login(cs->teamdb_state, s)) <= 0){
        fprintf(log_f, _("Invalid login `%s' in row %d\n"),
                rr->v[col_ind[CSV_LOGIN]], row);
        goto cleanup;
      }
      runs[row].user_id = x;
    } else if (col_ind[CSV_NAME] >= 0) {
      if (!(s = rr->v[col_ind[CSV_NAME]]) || !*s) {
        fprintf(log_f, _("Name is empty in row %d\n"), row);
        goto cleanup;
      }
      if ((x = teamdb_lookup_name(cs->teamdb_state, s)) <= 0){
        fprintf(log_f, _("Invalid name `%s' in row %d\n"),
                rr->v[col_ind[CSV_NAME]], row);
        goto cleanup;
      }
      runs[row].user_id = x;
    } else {
      fprintf(log_f, _("Neither user_id, login, nor name are specified\n"));
      goto cleanup;
    }

    if (col_ind[CSV_PROB] < 0) {
      fprintf(log_f, _("Problem column is undefined\n"));
      goto cleanup;
    }
    if (!(s = rr->v[col_ind[CSV_PROB]]) || !*s) {
      fprintf(log_f, _("Problem is empty in row %d\n"), row);
      goto cleanup;
    }
    prob = 0;
    for (x = 1; x <= cs->max_prob; x++)
      if (cs->probs[x] && !strcmp(s, cs->probs[x]->short_name)) {
        prob = cs->probs[x];
        break;
      }
    if (!prob) {
      fprintf(log_f, _("Invalid problem `%s' in row %d\n"), s, row);
      goto cleanup;
    }
    runs[row].prob_id = prob->id;

    lang = 0;
    if (prob->type_val == PROB_TYPE_STANDARD) {
      if (col_ind[CSV_LANG] < 0) {
        fprintf(log_f, _("Language column is undefined\n"));
        goto cleanup;
      }
      if (!(s = rr->v[col_ind[CSV_LANG]]) || !*s) {
        fprintf(log_f, _("Language is empty in row %d\n"), row);
        goto cleanup;
      }
      for (x = 1; x <= cs->max_lang; x++)
        if (cs->langs[x] && !strcmp(s, cs->langs[x]->short_name)) {
          lang = cs->langs[x];
          break;
        }
      if (!lang) {
        fprintf(log_f, _("Invalid language `%s' in row %d\n"), s, row);
        goto cleanup;
      }
      runs[row].lang_id = lang->id;

      if (lang->disabled) {
        fprintf(log_f, _("Language %s is disabled in row %d\n"),
                lang->short_name, row);
        goto cleanup;
      }

      if (prob->enable_language) {
        lang_list = prob->enable_language;
        for (i = 0; lang_list[i]; i++)
          if (!strcmp(lang_list[i], lang->short_name))
            break;
        if (!lang_list[i]) {
          fprintf(log_f, _("Language %s is not enabled for problem %s in row %d\n"),
                  lang->short_name, prob->short_name, row);
          goto cleanup;
        }
      } else if (prob->disable_language) {
        lang_list = prob->disable_language;
        for (i = 0; lang_list[i]; i++)
          if (!strcmp(lang_list[i], lang->short_name))
            break;
        if (lang_list[i]) {
          fprintf(log_f, _("Language %s is disabled for problem %s in row %d\n"),
                  lang->short_name, prob->short_name, row);
          goto cleanup;
        }
      }
    } else {
      mime_type = MIME_TYPE_TEXT;
      mime_type_str = mime_type_get_type(mime_type);
      runs[row].mime_type = mime_type;

      if (prob->enable_language) {
        lang_list = prob->enable_language;
        for (i = 0; lang_list[i]; i++)
          if (!strcmp(lang_list[i], mime_type_str))
            break;
        if (!lang_list[i]) {
          fprintf(log_f, _("Content type %s is not enabled for problem %s in row %d\n"),
                  mime_type_str, prob->short_name, row);
          goto cleanup;
        }
      } else if (prob->disable_language) {
        lang_list = prob->disable_language;
        for (i = 0; lang_list[i]; i++)
          if (!strcmp(lang_list[i], mime_type_str))
            break;
        if (lang_list[i]) {
          fprintf(log_f, _("Content type %s is disabled for problem %s in row %d\n"),
                  mime_type_str, prob->short_name, row);
          goto cleanup;
        }
      }
    }
    sha_buffer(run_text, run_size, runs[row].sha1);

    if (col_ind[CSV_TESTS] >= 0) {
      if (!(s = rr->v[col_ind[CSV_TESTS]]) || !*s) {
        fprintf(log_f, _("Tests is empty in row %d\n"), row);
        goto cleanup;
      }
      errno = 0;
      x = strtol(s, &eptr, 10);
      if (errno || *eptr || x < -1 || x > 100000) {
        fprintf(log_f, _("Tests value `%s' is invalid in row %d\n"), s, row);
        goto cleanup;
      }
      runs[row].test = x;
    } else {
      runs[row].test = 1;
    }

    if (col_ind[CSV_SCORE] < 0) {
      fprintf(log_f, _("Score column is undefined\n"));
      goto cleanup;
    }
    if (!(s = rr->v[col_ind[CSV_SCORE]]) || !*s) {
      fprintf(log_f, _("Score is empty in row %d\n"), row);
      goto cleanup;
    }
    errno = 0;
    x = strtol(s, &eptr, 10);
    if (errno || *eptr || x < -1 || x > 100000) {
      fprintf(log_f, _("Score value `%s' is invalid in row %d\n"), s, row);
      goto cleanup;
    }
    runs[row].score = x;

    if (col_ind[CSV_STATUS] >= 0) {
      if (!(s = rr->v[col_ind[CSV_STATUS]]) || !*s) {
        fprintf(log_f, _("Status is empty in row %d\n"), row);
        goto cleanup;
      }
      if (run_str_short_to_status(s, &x) < 0) {
        fprintf(log_f, _("Invalid status `%s' in row %d\n"), s, row);
        goto cleanup;
      }
      if (x < 0 || x > RUN_MAX_STATUS) {
        fprintf(log_f, _("Invalid status `%s' (%d) in row %d\n"),
                rr->v[col_ind[CSV_STATUS]], x, row);
        goto cleanup;
      }
      runs[row].status = x;
    } else {
      if (runs[row].score >= prob->full_score)
        runs[row].status = RUN_OK;
      else
        runs[row].status = RUN_PARTIAL;
    }

    fprintf(log_f,
            "%d: user %d, problem %d, language %d, status %d, tests %d, score %d\n",
            row, runs[row].user_id, runs[row].prob_id, runs[row].lang_id,
            runs[row].status, runs[row].test, runs[row].score);
  }

  for (row = 1; row < csv->u; row++) {
    gettimeofday(&precise_time, 0);
    run_id = run_add_record(cs->runlog_state, 
                            precise_time.tv_sec, precise_time.tv_usec * 1000,
                            run_size, runs[row].sha1,
                            phr->ip, phr->ssl_flag, phr->locale_id,
                            runs[row].user_id,
                            runs[row].prob_id,
                            runs[row].lang_id,
                            runs[row].variant,
                            runs[row].is_hidden,
                            runs[row].mime_type);
    if (run_id < 0) {
      fprintf(log_f, _("Failed to add row %d to runlog\n"), row);
      goto cleanup;
    }
    serve_move_files_to_insert_run(cs, run_id);
    arch_flags = archive_make_write_path(cs, run_path, sizeof(run_path),
                                         global->run_archive_dir, run_id,
                                         run_size, 0);
    if (arch_flags < 0) {
      run_undo_add_record(cs->runlog_state, run_id);
      fprintf(log_f, _("Cannot allocate space to store run row %d\n"), row);
      goto cleanup;
    }
    if (archive_dir_prepare(cs, global->run_archive_dir, run_id, 0, 0) < 0) {
      run_undo_add_record(cs->runlog_state, run_id);
      fprintf(log_f, _("Cannot allocate space to store run row %d\n"), row);
      goto cleanup;
    }
    if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
      run_undo_add_record(cs->runlog_state, run_id);
      fprintf(log_f, _("Cannot write run row %d\n"), row);
      goto cleanup;
    }
    run_set_entry(cs->runlog_state, run_id,
                  RUN_ENTRY_STATUS | RUN_ENTRY_TEST | RUN_ENTRY_SCORE,
                  &runs[row]);

    serve_audit_log(cs, run_id, phr->user_id, phr->ip, phr->ssl_flag,
                    "Command: new_run\n"
                    "Status: %s\n"
                    "Run-id: %d\n",
                    run_status_str(runs[row].status, 0, 0, 0),
                    run_id);
  }
  */

  retval = 0;

 cleanup:
  xfree(runs);
  csv_free(csv);
  return retval;
}

int
ns_write_user_run_status(
	const serve_state_t cs,
        FILE *fout,
        int run_id)
{
  struct run_entry re;
  int attempts = 0, disq_attempts = 0;
  int prev_successes = RUN_TOO_MANY;
  struct section_problem_data *cur_prob = 0;
  unsigned char *run_kind_str = "", *prob_str = "???", *lang_str = "???";
  time_t run_time, start_time;
  unsigned char dur_str[64];

  if (run_id < 0 || run_id >= run_get_total(cs->runlog_state))
    return -NEW_SRV_ERR_INV_RUN_ID;
  run_get_entry(cs->runlog_state, run_id, &re);

  if (cs->global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, run_id);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
  }

  if (cs->global->score_system_val == SCORE_OLYMPIAD && cs->accepting_mode) {
    if (re.status == RUN_OK || re.status == RUN_PARTIAL)
      re.status = RUN_ACCEPTED;
  }

  if (re.prob_id > 0 && re.prob_id <= cs->max_prob)
    cur_prob = cs->probs[re.prob_id];

  attempts = 0; disq_attempts = 0;
  if (cs->global->score_system_val == SCORE_KIROV && !re.is_hidden)
    run_get_attempts(cs->runlog_state, run_id, &attempts, &disq_attempts,
                     cur_prob->ignore_compile_errors);

  prev_successes = RUN_TOO_MANY;
  if (cs->global->score_system_val == SCORE_KIROV
      && re.status == RUN_OK
      && !re.is_hidden
      && cur_prob && cur_prob->score_bonus_total > 0) {
    if ((prev_successes = run_get_prev_successes(cs->runlog_state, run_id)) < 0)
      prev_successes = RUN_TOO_MANY;
  }

  if (re.is_imported) run_kind_str = "I";
  if (re.is_hidden) run_kind_str = "H";

  run_time = re.time;
  if (!start_time) run_time = start_time;
  if (start_time > run_time) run_time = start_time;
  duration_str(cs->global->show_astr_time, run_time, start_time, dur_str, 0);

  prob_str = "???";
  if (cs->probs[re.prob_id]) {
    if (cs->probs[re.prob_id]->variant_num > 0) {
      int variant = re.variant;
      if (!variant) variant = find_variant(cs, re.user_id, re.prob_id, 0);
      prob_str = alloca(strlen(cs->probs[re.prob_id]->short_name) + 10);
      if (variant > 0) {
        sprintf(prob_str, "%s-%d", cs->probs[re.prob_id]->short_name, variant);
      } else {
        sprintf(prob_str, "%s-?", cs->probs[re.prob_id]->short_name);
      }
    } else {
      prob_str = cs->probs[re.prob_id]->short_name;
    }
  }

  lang_str = "???";
  if (!re.lang_id) {
    lang_str = "N/A";
  } else if (re.lang_id >= 0 && re.lang_id <= cs->max_lang
             && cs->langs[re.lang_id]) {
    lang_str = cs->langs[re.lang_id]->short_name;
  }

  fprintf(fout, "%d;%s;%s;%u;%s;%s;", run_id, run_kind_str, dur_str, re.size,
          prob_str, lang_str);
  write_text_run_status(cs, fout, &re, 0, attempts, disq_attempts,
                        prev_successes);
  fprintf(fout, "\n");

  return 0;
}

static unsigned char *
get_source(
	const serve_state_t cs,
        int run_id,
        const struct section_problem_data *prob,
        int variant)
{
  const struct section_global_data *global = cs->global;
  int src_flag = 0, i, n;
  char *eptr = 0;
  path_t src_path = { 0 };
  char *src_txt = 0;
  size_t src_len = 0;
  unsigned char *s = 0, *val = 0;
  struct watched_file *pw = 0;
  const unsigned char *pw_path;
  const unsigned char *alternatives = 0;
  path_t variant_stmt_file;
  unsigned char buf[512];
  problem_xml_t px = 0;
  char *tmp_txt = 0;
  size_t tmp_len = 0;
  FILE *tmp_f = 0;

  if (!prob) goto cleanup;
  switch (prob->type_val) {
  case PROB_TYPE_STANDARD:
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_CUSTOM:
    goto cleanup;
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
  case PROB_TYPE_SELECT_MANY:
    break;
  }

  if ((src_flag = archive_make_read_path(cs, src_path, sizeof(src_path),
                                         global->run_archive_dir,
                                         run_id, 0, 1)) < 0)
    goto cleanup;
  if (generic_read_file(&src_txt, 0, &src_len, src_flag, 0, src_path, 0) < 0)
    goto cleanup;
  s = src_txt;
  while (src_len > 0 && isspace(s[src_len])) src_len--;
  s[src_len] = 0;
  if (prob->type_val == PROB_TYPE_SELECT_ONE) {
    errno = 0;
    n = strtol(s, &eptr, 10);
    if (*eptr || errno) goto inv_answer_n;
    if (variant > 0 && prob->xml.a) {
      px = prob->xml.a[variant - 1];
    } else {
      px = prob->xml.p;
    }

    if (px && px->answers) {
      if (n <= 0 || n > px->ans_num) goto inv_answer_n;
      i = problem_xml_find_language(0, px->tr_num, px->tr_names);
      tmp_f = open_memstream(&tmp_txt, &tmp_len);
      problem_xml_unparse_node(tmp_f, px->answers[n - 1][i], 0, 0);
      fclose(tmp_f); tmp_f = 0;
      val = tmp_txt; tmp_txt = 0;
    } else if (prob->alternative) {
      for (i = 0; i + 1 != n && prob->alternative[i]; i++);
      if (i + 1 != n || !prob->alternative[i]) goto inv_answer_n;
      val = html_armor_string_dup(prob->alternative[i]);
    } else {
      if (variant > 0 && prob->variant_num > 0) {
        prepare_insert_variant_num(variant_stmt_file, sizeof(variant_stmt_file),
                                   prob->alternatives_file, variant);
        pw = &cs->prob_extras[prob->id].v_alts[variant];
        pw_path = variant_stmt_file;
      } else {
        pw = &cs->prob_extras[prob->id].alt;
        pw_path = prob->alternatives_file;
      }
      watched_file_update(pw, pw_path, cs->current_time);
      alternatives = pw->text;
      if (!(val = get_nth_alternative(alternatives, n))) goto inv_answer_n;
    }
    snprintf(buf, sizeof(buf), "&lt;<i>%d</i>&gt;: %s", n, val);
    xfree(val);
    val = xstrdup(buf);
    goto cleanup;
  }
  val = html_armor_string_dup(s);

 cleanup:
  xfree(src_txt);
  return val;

 inv_answer_n:
  xfree(src_txt);
  snprintf(buf, sizeof(buf), _("<i>Invalid answer: %d</i>"), n);
  return xstrdup(buf);
}

unsigned char *
ns_get_checker_comment(
	const serve_state_t cs,
        int run_id,
        int need_html_armor)
{
  const struct section_global_data *global = cs->global;
  int rep_flag;
  path_t rep_path;
  unsigned char *str = 0;
  char *rep_txt = 0;
  size_t rep_len = 0;
  testing_report_xml_t rep_xml = 0;
  struct testing_report_test *rep_tst;
  const unsigned char *start_ptr = 0;

  if ((rep_flag = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                         global->xml_report_archive_dir,
                                         run_id, 0, 1)) < 0)
    goto cleanup;
  if (generic_read_file(&rep_txt, 0, &rep_len, rep_flag, 0, rep_path, 0) < 0)
    goto cleanup;
  if (get_content_type(rep_txt, &start_ptr) != CONTENT_TYPE_XML)
    goto cleanup;
  if (!(rep_xml = testing_report_parse_xml(start_ptr)))
    goto cleanup;
  /*
  if (rep_xml->status != RUN_PRESENTATION_ERR)
    goto cleanup;
  if (rep_xml->scoring_system != SCORE_OLYMPIAD)
    goto cleanup;
  */
  if (rep_xml->run_tests != 1)
    goto cleanup;
  if (!(rep_tst = rep_xml->tests[0]))
    goto cleanup;
  if (rep_tst->checker_comment && need_html_armor)
    str = html_armor_string_dup(rep_tst->checker_comment);
  else if (rep_tst->checker_comment)
    str = xstrdup(rep_tst->checker_comment);

 cleanup:
  testing_report_free(rep_xml);
  xfree(rep_txt);
  return str;
}

static int get_accepting_passed_tests(
	const serve_state_t cs,
        const struct section_problem_data *prob,
        int run_id,
	const struct run_entry *re)
{
  const struct section_global_data *global = cs->global;
  int rep_flag;
  path_t rep_path;
  char *rep_txt = 0;
  size_t rep_len = 0;
  testing_report_xml_t rep_xml = 0;
  const unsigned char *start_ptr = 0;
  int r, i, t;

  switch (re->status) {
  case RUN_OK:
  case RUN_ACCEPTED:
  case RUN_PARTIAL:
    if (prob->accept_partial <= 0 && prob->min_tests_to_accept < 0)
      return prob->tests_to_accept;
    break;

  case RUN_RUN_TIME_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_PRESENTATION_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_MEM_LIMIT_ERR:
  case RUN_SECURITY_ERR:
    r = re->test;
    if (r > 0) r--;
    // whether this ever possible?
    if (r > prob->tests_to_accept) r = prob->tests_to_accept;
    return r;

  default:
    return 0;
  }

  r = 0;
  if ((rep_flag = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                         global->xml_report_archive_dir,
                                         run_id, 0, 1)) < 0)
    goto cleanup;
  if (generic_read_file(&rep_txt, 0, &rep_len, rep_flag, 0, rep_path, 0) < 0)
    goto cleanup;
  if (get_content_type(rep_txt, &start_ptr) != CONTENT_TYPE_XML)
    goto cleanup;
  if (!(rep_xml = testing_report_parse_xml(start_ptr)))
    goto cleanup;
  /*
  if (rep_xml->status != RUN_PRESENTATION_ERR)
    goto cleanup;
  if (rep_xml->scoring_system != SCORE_OLYMPIAD)
    goto cleanup;
  */
  t = prob->tests_to_accept;
  if (t > rep_xml->run_tests) t = rep_xml->run_tests;
  for (i = 0; i < t; i++)
    if (rep_xml->tests[i]->status == RUN_OK)
      r++;

 cleanup:
  testing_report_free(rep_xml);
  xfree(rep_txt);
  return r;
}

void
ns_write_olympiads_user_runs(
	struct http_request_info *phr,
        FILE *fout,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int all_runs,
        int prob_id,
        const unsigned char *table_class)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob, *filt_prob = 0;
  const struct section_language_data *lang;
  int accepting_mode = 0;
  struct run_entry re;
  time_t start_time, run_time;
  unsigned char *cl = 0;
  int runs_to_show = all_runs?INT_MAX:15;
  int i, shown, variant = 0, run_latest, report_allowed, score;
  unsigned char *latest_flag = 0;
  unsigned char lang_name_buf[64];
  unsigned char prob_name_buf[128];
  const unsigned char *lang_name_ptr, *prob_name_ptr;
  unsigned char run_kind_buf[32], *run_kind_ptr;
  unsigned char dur_str[64];
  unsigned char stat_str[128];
  const unsigned char *row_attr;
  unsigned char tests_buf[64], score_buf[64];
  unsigned char ab[1024];
  unsigned char *report_comment = 0, *src_txt = 0;
  int run_count = 0;

  if (table_class && *table_class) {
    cl = alloca(strlen(table_class) + 16);
    sprintf(cl, " class=\"%s\"", table_class);
  }

  if (prob_id > 0 && prob_id <= cs->max_prob)
    filt_prob = cs->probs[prob_id];

  ASSERT(global->score_system_val == SCORE_OLYMPIAD);
  if (global->is_virtual) {
    if (run_get_virtual_start_entry(cs->runlog_state, phr->user_id, &re) < 0) {
      accepting_mode = 0;
      start_time = run_get_start_time(cs->runlog_state);
    } else {
      if (run_get_virtual_stop_time(cs->runlog_state, phr->user_id, 0) <= 0) {
        accepting_mode = 1;
      } else {
        if (!re.judge_id && global->disable_virtual_auto_judge <= 0)
          accepting_mode = 1;
        if (global->disable_virtual_auto_judge > 0 && cs->testing_finished <= 0)
          accepting_mode = 1;
      }
      start_time = re.time;
    }
  } else {
    accepting_mode = cs->accepting_mode;
    start_time = run_get_start_time(cs->runlog_state);
  }

  if (cnts->exam_mode)
    run_count = run_count_all_attempts(cs->runlog_state, phr->user_id, prob_id);

  XALLOCAZ(latest_flag, cs->max_prob + 1);

  fprintf(fout, "<table border=\"1\"%s><tr>", cl);
  if (!cnts->exam_mode) fprintf(fout, "<th%s>%s</th>", cl, _("Run ID"));
  if (cnts->exam_mode) fprintf(fout,"<th%s>%s</th>", cl, "NN");
  if (!cnts->exam_mode) fprintf(fout,"<th%s>%s</th>", cl, _("Time"));
  if (!cnts->exam_mode) fprintf(fout,"<th%s>%s</th>", cl, _("Size"));
  if (!filt_prob) fprintf(fout, "<th%s>%s</th>", cl, _("Problem"));
  if (global->disable_language <= 0
      && (!filt_prob || filt_prob->type_val == PROB_TYPE_STANDARD))
    fprintf(fout, "<th%s>%s</th>", cl, _("Programming language"));
  fprintf(fout, "<th%s>%s</th>", cl, _("Result"));
  if (global->disable_passed_tests <= 0
      && (!filt_prob || filt_prob->type_val == PROB_TYPE_STANDARD))
    fprintf(fout, "<th%s>%s</th>", cl, _("Tests passed"));
  if (!accepting_mode)
    fprintf(fout, "<th%s>%s</th>", cl, _("Score"));

  if (global->team_enable_src_view)
    fprintf(fout, "<th%s>%s</th>", cl, _("View submitted answer"));
  /*if (global->team_enable_rep_view || global->team_enable_ce_view)*/
  fprintf(fout, "<th%s>%s</th>", cl, _("View check details"));
  if (global->enable_printing && !cs->printing_suspended)
    fprintf(fout, "<th%s>%s</th>", cl, _("Print sources"));
  fprintf(fout, "</tr>\n");

  for (shown = 0, i = run_get_total(cs->runlog_state) - 1;
       i >= 0 && shown < runs_to_show;
       i--) {
    if (run_get_entry(cs->runlog_state, i, &re) < 0) continue;
    if (re.status > RUN_LAST) continue;
    if (re.status > RUN_MAX_STATUS && re.status <= RUN_TRANSIENT_FIRST)
      continue;
    if (re.user_id != phr->user_id) continue;
    if (prob_id > 0 && re.prob_id != prob_id) continue;

    prob = 0;
    if (re.prob_id > 0 && re.prob_id <= cs->max_prob)
      prob = cs->probs[re.prob_id];
    if (prob) {
      if (prob->variant_num <= 0) {
        prob_name_ptr = prob->short_name;
      } else {
        variant = re.variant;
        if (!variant) variant = find_variant(cs, re.user_id, re.prob_id, 0);
        if (variant > 0) {
          snprintf(prob_name_buf, sizeof(prob_name_buf), "%s-%d",
                   prob->short_name, variant);
        } else {
          snprintf(prob_name_buf, sizeof(prob_name_buf), "%s-?",
                   prob->short_name);
        }
        prob_name_ptr = prob_name_buf;
      }
    } else {
      snprintf(prob_name_buf, sizeof(prob_name_buf), "??? (%d)", re.prob_id);
      prob_name_ptr = prob_name_buf;
    }

    lang = 0;
    if (!re.lang_id) {
      lang_name_ptr = "&nbsp;";
    } else if (re.lang_id > 0 && re.lang_id <= cs->max_lang
               && (lang = cs->langs[re.lang_id])) {
      lang_name_ptr = lang->short_name;
    } else {
      snprintf(lang_name_buf, sizeof(lang_name_buf), "??? (%d)", re.lang_id);
      lang_name_ptr = lang_name_buf;
    }

    run_kind_ptr = run_kind_buf;
    if (re.is_imported) *run_kind_ptr++ = '*';
    if (re.is_hidden) *run_kind_ptr++ = '#';
    *run_kind_ptr = 0;

    run_time = re.time;
    if (!start_time) run_time = start_time;
    if (start_time > run_time) run_time = start_time;
    duration_str(global->show_astr_time, run_time, start_time, dur_str, 0);

    if (prob && prob->type_val != PROB_TYPE_STANDARD) {
      // there are check statuses that can never appear in output-only probs
      switch (re.status) {
      case RUN_COMPILE_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        re.status = RUN_CHECK_FAILED;
        break;
      case RUN_WRONG_ANSWER_ERR:
        if (accepting_mode) re.status = RUN_ACCEPTED;
        break;
      }
    }

    run_latest = 0;
    report_allowed = 0;
    if (accepting_mode) {
      switch (re.status) {
      case RUN_OK:
      case RUN_PARTIAL:
      case RUN_ACCEPTED:
        re.status = RUN_ACCEPTED;
        if (prob && prob->type_val != PROB_TYPE_STANDARD) {
          snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        } else {
          //snprintf(tests_buf, sizeof(tests_buf), "%d", prob->tests_to_accept);
          snprintf(tests_buf, sizeof(tests_buf), "%d",
                   get_accepting_passed_tests(cs, prob, i, &re));
          report_allowed = 1;
        }
        if (prob && !latest_flag[prob->id]) run_latest = 1;
        break;

      case RUN_COMPILE_ERR:
        report_allowed = 1;
        snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        break;

      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        if (prob && prob->type_val != PROB_TYPE_STANDARD) {
          // This is presentation error
          report_comment = ns_get_checker_comment(cs, i, 1);
          snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        } else {
          /*
          if (re.test > 0) re.test--;
          if (prob && re.test > prob->tests_to_accept)
            re.test = prob->tests_to_accept;
          snprintf(tests_buf, sizeof(tests_buf), "%d", re.test);
          */
          snprintf(tests_buf, sizeof(tests_buf), "%d",
                   get_accepting_passed_tests(cs, prob, i, &re));
          report_allowed = 1;
        }
        break;

      default:
        snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
      }
      snprintf(score_buf, sizeof(score_buf), "&nbsp;");
    } else {
      switch (re.status) {
      case RUN_OK:
        if (prob && prob->type_val != PROB_TYPE_STANDARD) {
          snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        } else {
          snprintf(tests_buf, sizeof(tests_buf), "%d", re.test);
          report_allowed = 1;
        }
        if (prob && !latest_flag[prob->id]) run_latest = 1;
        score = re.score;
        if (prob && !prob->variable_full_score) score = prob->full_score;
        if (re.score_adj) score += re.score_adj;
        if (score < 0) score = 0;
        snprintf(score_buf, sizeof(score_buf), "%d", score);
        break;
      case RUN_PARTIAL:
        if (prob && prob->type_val != PROB_TYPE_STANDARD) {
          snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        } else {
          snprintf(tests_buf, sizeof(tests_buf), "%d", re.test);
        }
        report_allowed = 1;
        if (prob && !latest_flag[prob->id]) run_latest = 1;
        score = re.score;
        if (re.score_adj) score += re.score_adj;
        if (score < 0) score = 0;
        snprintf(score_buf, sizeof(score_buf), "%d", score);
        break;
      case RUN_COMPILE_ERR:
        snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        snprintf(score_buf, sizeof(score_buf), "&nbsp;");
        report_allowed = 1;
        break;

      case RUN_ACCEPTED:
        if (prob && !latest_flag[prob->id]) run_latest = 1;
        // FALLTHROUGH

      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        if (prob && prob->type_val != PROB_TYPE_STANDARD) {
          snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        } else {
          snprintf(tests_buf, sizeof(tests_buf), "%d", re.test);
        }
        report_allowed = 1;
        snprintf(score_buf, sizeof(score_buf), "&nbsp;");
        break;

      default:
        snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        snprintf(score_buf, sizeof(score_buf), "&nbsp;");
      }
    }

    run_status_str(re.status, stat_str, sizeof(stat_str),
                   prob?prob->type_val:0, prob?prob->scoring_checker:0);

    row_attr = "";
    if (run_latest) {
      if (accepting_mode) {
        row_attr = " bgcolor=\"#ddffdd\""; /* green */
      } else {
        if (re.status == RUN_OK) {
          row_attr = " bgcolor=\"#ddffdd\""; /* green */
        } else {
          row_attr = " bgcolor=\"#ffdddd\""; /* green */
        }
      }
      latest_flag[prob->id] = 1;
    }

    fprintf(fout, "<tr%s>", row_attr);
    if (!cnts->exam_mode)
      fprintf(fout, "<td%s>%d%s</td>", cl, i, run_kind_ptr);
    if (cnts->exam_mode) fprintf(fout, "<td%s>%d</td>", cl, run_count--);
    if (!cnts->exam_mode) fprintf(fout, "<td%s>%s</td>", cl, dur_str);
    if (!cnts->exam_mode)
      fprintf(fout, "<td%s>%u</td>", cl, re.size);
    if (!filt_prob) fprintf(fout, "<td%s>%s</td>", cl, prob_name_ptr);
    if (global->disable_language <= 0
        && (!filt_prob || filt_prob->type_val == PROB_TYPE_STANDARD))
      fprintf(fout, "<td%s>%s</td>", cl, lang_name_ptr);
    fprintf(fout, "<td%s>%s</td>", cl, stat_str);
    if (global->disable_passed_tests <= 0
        && (!filt_prob || filt_prob->type_val == PROB_TYPE_STANDARD))
      fprintf(fout, "<td%s>%s</td>", cl, tests_buf);
    if (!accepting_mode)
      fprintf(fout, "<td%s>%s</td>", cl, score_buf);

    if (global->team_enable_src_view) {
      if (cnts->exam_mode && (src_txt = get_source(cs, i, prob, variant))) {
        fprintf(fout, "<td%s>%s</td>", cl, src_txt);
        xfree(src_txt); src_txt = 0;
      } else {
        fprintf(fout, "<td%s>%s%s</a></td>", cl,
                ns_aref(ab, sizeof(ab), phr, NEW_SRV_ACTION_VIEW_SOURCE,
                        "run_id=%d", i), _("View"));
      }
    }
    if (report_comment && *report_comment) {
      fprintf(fout, "<td%s>%s</td>", cl, report_comment);
    } else if (re.status == RUN_COMPILE_ERR
          && (global->team_enable_rep_view || global->team_enable_ce_view)
          && report_allowed) {
      fprintf(fout, "<td%s>%s%s</a></td>", cl,
              ns_aref(ab, sizeof(ab), phr, NEW_SRV_ACTION_VIEW_REPORT,
                      "run_id=%d", i), _("View"));
    } else if (global->team_enable_rep_view && report_allowed) {
      fprintf(fout, "<td%s>%s%s</a></td>", cl,
              ns_aref(ab, sizeof(ab), phr, NEW_SRV_ACTION_VIEW_REPORT,
                      "run_id=%d", i), _("View"));
    } else if (global->team_enable_rep_view || global->team_enable_ce_view) {
      fprintf(fout, "<td%s>&nbsp;</td>", cl);
    }

    /* FIXME: add "print sources" reference */

    fprintf(fout, "</tr>\n");
    shown++;

    xfree(report_comment); report_comment = 0;
  }
  fprintf(fout, "</table>\n");
}

void
ns_get_user_problems_summary(
	const serve_state_t cs, int user_id, int accepting_mode,
        unsigned char *solved_flag,   /* whether the problem was OK */
        unsigned char *accepted_flag, /* whether the problem was accepted */
        unsigned char *pending_flag,  /* whether there are pending runs */
        unsigned char *trans_flag,    /* whether there are transient runs */
        int *best_run,                /* the number of the best run */
        int *attempts,                /* the number of previous attempts */
        int *disqualified,            /* the number of prev. disq. attempts */
        int *best_score,              /* the best score for the problem */
        int *prev_successes,          /* the number of prev. successes */
        int *all_attempts)            /* all attempts count */
{
  const struct section_global_data *global = cs->global;
  time_t start_time;
  int total_runs, run_id, cur_score, total_teams;
  struct run_entry re;
  struct section_problem_data *cur_prob = 0;
  unsigned char *user_flag = 0;

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, user_id);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
  }
  total_runs = run_get_total(cs->runlog_state);
  total_teams = teamdb_get_max_team_id(cs->teamdb_state) + 1;

  memset(best_run, -1, sizeof(best_run[0]) * (cs->max_prob + 1));
  XCALLOC(user_flag, (cs->max_prob + 1) * total_teams);

  for (run_id = 0; run_id < total_runs; run_id++) {
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0) continue;
    if (!run_is_valid_status(re.status)) continue;
    if (re.status >= RUN_TRANSIENT_FIRST && re.status <= RUN_TRANSIENT_LAST
        && re.user_id == user_id
        && re.prob_id > 0 && re.prob_id <= cs->max_prob
        && cs->probs[re.prob_id]) {
      trans_flag[re.prob_id] = 1;
      all_attempts[re.prob_id]++;
    }
    if (re.status > RUN_MAX_STATUS) continue;

    cur_prob = 0;
    if (re.prob_id > 0 && re.prob_id <= cs->max_prob)
      cur_prob = cs->probs[re.prob_id];
    if (!cur_prob) continue;

    if (re.user_id <= 0 || re.user_id >= total_teams) continue;
    if (re.user_id != user_id) {
      if (re.is_hidden) continue;
      if (teamdb_get_flags(cs->teamdb_state,
                           re.user_id) & (TEAM_INVISIBLE | TEAM_BANNED))
        continue;
      if (re.status == RUN_OK) {
        if (!user_flag[re.user_id * (cs->max_prob + 1) + re.prob_id]) {
          prev_successes[re.prob_id]++;
        }
        user_flag[re.user_id * (cs->max_prob + 1) + re.prob_id] = 1;
      }
      continue;
    }

    all_attempts[re.prob_id]++;
    if (global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
      // OLYMPIAD contest in accepting mode
      if (cur_prob->type_val != PROB_TYPE_STANDARD) {
        switch (re.status) {
        case RUN_OK:
        case RUN_PARTIAL:
        case RUN_ACCEPTED:
        case RUN_WRONG_ANSWER_ERR:
          re.status = RUN_ACCEPTED;
          break;

        case RUN_COMPILE_ERR:
        case RUN_RUN_TIME_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_CHECK_FAILED:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
          re.status = RUN_CHECK_FAILED;
          break;
        }
        switch (re.status) {
        case RUN_ACCEPTED:
          accepted_flag[re.prob_id] = 1;
          best_run[re.prob_id] = run_id;
          break;

        case RUN_PRESENTATION_ERR:
          if (!accepted_flag[re.prob_id]) {
            best_run[re.prob_id] = run_id;
          }
          break;

        case RUN_CHECK_FAILED:
        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
          break;

        case RUN_PENDING:
          pending_flag[re.prob_id] = 1;
          attempts[re.prob_id]++;
          if (best_run[re.prob_id] < 0) best_run[re.prob_id] = run_id;
          break;

        default:
          abort();
        }
      } else {
        // regular problems
        switch (re.status) {
        case RUN_OK:
        case RUN_PARTIAL:
        case RUN_ACCEPTED:
          accepted_flag[re.prob_id] = 1;
          best_run[re.prob_id] = run_id;
          break;

        case RUN_COMPILE_ERR:
        case RUN_RUN_TIME_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_PRESENTATION_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_CHECK_FAILED:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
          if (!accepted_flag[re.prob_id]) {
            best_run[re.prob_id] = run_id;
          }
          break;

        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
          break;

        case RUN_PENDING:
          pending_flag[re.prob_id] = 1;
          attempts[re.prob_id]++;
          if (best_run[re.prob_id] < 0) best_run[re.prob_id] = run_id;
          break;

        default:
          abort();
        }
      }
    } else if (global->score_system_val == SCORE_OLYMPIAD) {
      // OLYMPIAD contest in judging mode
      //if (solved_flag[re.prob_id]) continue;

      switch (re.status) {
      case RUN_OK:
        solved_flag[re.prob_id] = 1;
        best_run[re.prob_id] = run_id;
        cur_score = calc_kirov_score(0, 0, &re, cur_prob, 0, 0, 0, 0, 0);
        //if (cur_score > best_score[re.prob_id])
        best_score[re.prob_id] = cur_score;
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
        solved_flag[re.prob_id] = 0;
        best_run[re.prob_id] = run_id;
        attempts[re.prob_id]++;
        cur_score = calc_kirov_score(0, 0, &re, cur_prob, 0, 0, 0, 0, 0);
        //if (cur_score > best_score[re.prob_id])
        best_score[re.prob_id] = cur_score;
        break;

      case RUN_ACCEPTED:
        break;

      case RUN_IGNORED:
        break;

      case RUN_DISQUALIFIED:
        break;

      case RUN_PENDING:
        pending_flag[re.prob_id] = 1;
        if (best_run[re.prob_id] < 0) best_run[re.prob_id] = run_id;
        break;

      default:
        abort();
      }
    } else if (global->score_system_val == SCORE_KIROV) {
      // KIROV contest
      if (solved_flag[re.prob_id]) continue;

      switch (re.status) {
      case RUN_OK:
        solved_flag[re.prob_id] = 1;
        cur_score = calc_kirov_score(0, 0, &re, cur_prob,
                                     attempts[re.prob_id],
                                     disqualified[re.prob_id],
                                     prev_successes[re.prob_id], 0, 0);

        if (cur_score >= best_score[re.prob_id]) {
          best_score[re.prob_id] = cur_score;
          best_run[re.prob_id] = run_id;
        }
        break;

      case RUN_COMPILE_ERR:
        if (!cur_prob->ignore_compile_errors) {
          attempts[re.prob_id]++;
          cur_score = 0;
          if (cur_score >= best_score[re.prob_id]) {
            best_score[re.prob_id] = cur_score;
            best_run[re.prob_id] = run_id;
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
                                     attempts[re.prob_id],
                                     disqualified[re.prob_id],
                                     prev_successes[re.prob_id], 0, 0);

        attempts[re.prob_id]++;
        if (cur_score >= best_score[re.prob_id]) {
          best_score[re.prob_id] = cur_score;
          best_run[re.prob_id] = run_id;
        }
        break;

      case RUN_ACCEPTED:
        break;

      case RUN_IGNORED:
        break;

      case RUN_DISQUALIFIED:
        disqualified[re.prob_id]++;
        break;

      case RUN_PENDING:
        pending_flag[re.prob_id] = 1;
        attempts[re.prob_id]++;
        if (best_run[re.prob_id] < 0) best_run[re.prob_id] = run_id;
        break;

      default:
        abort();
      }
    } else if (global->score_system_val == SCORE_MOSCOW) {
      if (solved_flag[re.prob_id]) continue;

      switch (re.status) {
      case RUN_OK:
        solved_flag[re.prob_id] = 1;
        best_run[re.prob_id] = run_id;
        cur_score = cur_prob->full_score;
        if (cur_score >= best_score[re.prob_id]) {
          best_score[re.prob_id] = cur_score;
          best_run[re.prob_id] = run_id;
        }
        break;

      case RUN_COMPILE_ERR:
        if (!cur_prob->ignore_compile_errors) {
          attempts[re.prob_id]++;
          cur_score = 0;
          if (cur_score >= best_score[re.prob_id]
              || best_run[re.prob_id] < 0) {
            best_score[re.prob_id] = cur_score;
            best_run[re.prob_id] = run_id;
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
        attempts[re.prob_id]++;
        cur_score = re.score;
        if (cur_score >= best_score[re.prob_id]
            || best_run[re.prob_id] < 0) {
          best_score[re.prob_id] = cur_score;
          best_run[re.prob_id] = run_id;
        }
        break;

      case RUN_PARTIAL:
      case RUN_ACCEPTED:
      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
        break;

      case RUN_PENDING:
        pending_flag[re.prob_id] = 1;
        attempts[re.prob_id]++;
        if (best_run[re.prob_id] < 0) best_run[re.prob_id] = run_id;
        break;

      default:
        abort();
      }
    } else {
      // ACM contest
      if (solved_flag[re.prob_id]) continue;

      switch (re.status) {
      case RUN_OK:
        solved_flag[re.prob_id] = 1;
        best_run[re.prob_id] = run_id;
        break;

      case RUN_COMPILE_ERR:
        if (!cur_prob->ignore_compile_errors) {
          attempts[re.prob_id]++;
          best_run[re.prob_id] = run_id;
        }
        break;
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        attempts[re.prob_id]++;
        best_run[re.prob_id] = run_id;
        break;

      case RUN_PARTIAL:
      case RUN_ACCEPTED:
      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
        break;

      case RUN_PENDING:
        pending_flag[re.prob_id] = 1;
        attempts[re.prob_id]++;
        if (best_run[re.prob_id] < 0) best_run[re.prob_id] = run_id;
        break;

      default:
        abort();
      }
    }
  }

  xfree(user_flag);
}

void
ns_write_user_problems_summary(
	const struct contest_desc *cnts,
	const serve_state_t cs,
        FILE *fout,
        int user_id,
        int accepting_mode,
        const unsigned char *table_class,
        unsigned char *solved_flag,   /* whether the problem was OK */
        unsigned char *accepted_flag, /* whether the problem was accepted */
        unsigned char *pending_flag,  /* whether there are pending runs */
        unsigned char *trans_flag,    /* whether there are transient runs */
        int *best_run,                /* the number of the best run */
        int *attempts,                /* the number of previous attempts */
        int *disqualified,            /* the number of prev. disq. attempts */
        int *best_score,              /* the best score for the problem */
        int *prev_successes)          /* the number of prev. successes */
{
  const struct section_global_data *global = cs->global;
  time_t start_time;
  int total_runs, total_teams, prob_id, total_score = 0;
  struct run_entry re;
  struct section_problem_data *cur_prob = 0;
  unsigned char *s;
  unsigned char url_buf[1024];
  unsigned char status_str[128];
  time_t current_time = time(0);
  int act_status;
  unsigned char *cl = "";
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, user_id);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
  }
  total_runs = run_get_total(cs->runlog_state);
  total_teams = teamdb_get_max_team_id(cs->teamdb_state) + 1;

  if (table_class && *table_class) {
    cl = alloca(strlen(table_class) + 16);
    sprintf(cl, " class=\"%s\"", table_class);
  }

  fprintf(fout, "<table border=\"1\"%s><tr>", cl);
  if (cnts->exam_mode || global->disable_prob_long_name > 0) {
    fprintf(fout, "<th%s>%s</th>", cl, _("Problem"));
  } else {
    fprintf(fout, "<th%s>%s</th><th%s>%s</th>",
            cl, _("Short name"), cl, _("Long name"));
  }
  fprintf(fout, "<th%s>%s</th>", cl, _("Status"));
  if (global->score_system_val == SCORE_OLYMPIAD && accepting_mode
      && global->disable_passed_tests <= 0) {
    fprintf(fout, "<th%s>%s</th>", cl, _("Tests passed"));
  } else if ((global->score_system_val == SCORE_OLYMPIAD && !accepting_mode)
             || global->score_system_val == SCORE_KIROV) {
    if (global->disable_passed_tests <= 0) {
      fprintf(fout, "<th%s>%s</th>", cl, _("Tests passed"));
    }
    fprintf(fout, "<th%s>%s</th>", cl, _("Score"));
  } else if (global->score_system_val == SCORE_MOSCOW) {
    fprintf(fout, "<th%s>%s</th>", cl, _("Failed test"));
    fprintf(fout, "<th%s>%s</th>", cl, _("Score"));
  } else {
    fprintf(fout, "<th%s>%s</th>", cl, _("Failed test"));
  }
  if (!cnts->exam_mode) {
    fprintf(fout, "<th%s>%s</th>", cl, _("Run ID"));
  }
  fprintf(fout, "</tr>\n");

  for (prob_id = 1; prob_id <= cs->max_prob; prob_id++) {
    if (!(cur_prob = cs->probs[prob_id])) continue;
    if (cur_prob->t_start_date && current_time < cur_prob->t_start_date)
      continue;
    if (cur_prob->hidden > 0) continue;
    s = "";
    if (accepted_flag[prob_id] || solved_flag[prob_id])
      s = " bgcolor=\"#ddffdd\"";
    else if (!pending_flag[prob_id] && attempts[prob_id])
      s = " bgcolor=\"#ffdddd\"";
    fprintf(fout, "<tr%s>", s);
    if (cnts->exam_mode) {
      fprintf(fout, "<td%s>%s</td>", cl, ARMOR(cur_prob->long_name));
    } else {
      fprintf(fout, "<td%s>", cl);
      if (global->prob_info_url[0]) {
        sformat_message(url_buf, sizeof(url_buf), global->prob_info_url,
                        NULL, cur_prob, NULL, NULL, NULL, 0, 0, 0);
        fprintf(fout, "<a href=\"%s\" target=\"_blank\">", url_buf);
      }
      fprintf(fout, "%s", ARMOR(cur_prob->short_name));
      if (global->prob_info_url[0]) fprintf(fout, "</a>");
      fprintf(fout, "</td>");
      if (global->disable_prob_long_name <= 0)
        fprintf(fout, "<td%s>%s</td>", cl, ARMOR(cur_prob->long_name));
    }
    if (best_run[prob_id] < 0) {
      if (global->score_system_val == SCORE_KIROV
          || (global->score_system_val == SCORE_OLYMPIAD
              && !accepting_mode)
          || global->score_system_val == SCORE_MOSCOW) {
        fprintf(fout, "<td%s>&nbsp;</td><td%s>&nbsp;</td>", cl, cl);
        if (global->disable_passed_tests <= 0)
          fprintf(fout, "<td%s>&nbsp;</td>", cl);
        if (!cnts->exam_mode) {
          fprintf(fout, "<td%s>&nbsp;</td>", cl);
        }
        fprintf(fout, "</tr>\n");
      } else {
        fprintf(fout, "<td%s>&nbsp;</td><td%s>&nbsp;</td>", cl, cl);
        if (!cnts->exam_mode) {
          fprintf(fout, "<td%s>&nbsp;</td>", cl);
        }
        fprintf(fout, "</tr>\n");
      }
      continue;
    }

    run_get_entry(cs->runlog_state, best_run[prob_id], &re);
    act_status = re.status;
    if (global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
      if (act_status == RUN_OK || act_status == RUN_PARTIAL
          || (act_status == RUN_WRONG_ANSWER_ERR
              && cur_prob->type_val != PROB_TYPE_STANDARD))
        act_status = RUN_ACCEPTED;
    }
    run_status_str(act_status, status_str, sizeof(status_str),
                   cur_prob->type_val, cur_prob->scoring_checker);
    fprintf(fout, "<td%s>%s</td>", cl, status_str);

    if (global->score_system_val == SCORE_OLYMPIAD && accepting_mode) {
      if (global->disable_passed_tests <= 0) {
        switch (act_status) {
        case RUN_RUN_TIME_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_PRESENTATION_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
          fprintf(fout, "<td%s>%d</td>", cl, re.test);
          break;
        default:
          fprintf(fout, "<td%s>&nbsp;</td>", cl);
          break;
        }
      }
    } else if (global->score_system_val == SCORE_OLYMPIAD) {
      total_score += best_score[prob_id];
      switch (re.status) {
      case RUN_OK:
      case RUN_PARTIAL:
        if (cur_prob->type_val != PROB_TYPE_STANDARD) {
          if (global->disable_passed_tests <= 0) {
            fprintf(fout, "<td%s>&nbsp;</td>", cl);
          }
          fprintf(fout, "<td%s>%d</td>", cl, best_score[prob_id]);
        } else {
          fprintf(fout, "<td%s>%d</td><td%s>%d</td>",
                  cl, re.test - 1, cl, best_score[prob_id]);
        }
        break;
      default:
        if (global->disable_passed_tests <= 0) {
          fprintf(fout, "<td%s>&nbsp;</td>", cl);
        }
        fprintf(fout, "<td%s>&nbsp;</td>", cl);
        break;
      }
    } else if (global->score_system_val == SCORE_KIROV) {
      total_score += best_score[prob_id];
      switch (re.status) {
      case RUN_OK:
      case RUN_PARTIAL:
        fprintf(fout, "<td%s>%d</td><td%s>%d</td>",
                cl, re.test - 1, cl, best_score[prob_id]);
        break;
      default:
        fprintf(fout, "<td%s>&nbsp;</td><td%s>&nbsp;</td>", cl, cl);
        break;
      }
    } else if (global->score_system_val == SCORE_MOSCOW) {
      total_score += best_score[prob_id];
      switch (re.status) {
      case RUN_OK:
        fprintf(fout, "<td%s>&nbsp;</td><td%s>%d</td>",
                cl, cl, best_score[prob_id]);
        break;
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
        if (global->disable_failed_test_view > 0) {
          fprintf(fout, "<td%s>&nbsp;</td>", cl);
        } else {
          fprintf(fout, "<td%s>%d</td>", cl, re.test);
        }
        fprintf(fout, "<td%s>%d</td>", cl, best_score[prob_id]);
        break;
      default:
        fprintf(fout, "<td%s>&nbsp;</td><td%s>&nbsp;</td>", cl, cl);
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
        if (global->disable_failed_test_view > 0) {
          fprintf(fout, "<td%s>&nbsp;</td>", cl);
        } else {
          fprintf(fout, "<td%s>%d</td>", cl, re.test);
        }
        break;
      default:
        fprintf(fout, "<td%s>&nbsp;</td>", cl);
        break;
      }
    }
    if (!cnts->exam_mode) {
      fprintf(fout, "<td%s>%d</td>", cl, best_run[prob_id]);
    }
    fprintf(fout, "</tr>\n");
  }

  fprintf(fout, "</table>\n");

  if ((global->score_system_val == SCORE_OLYMPIAD && !accepting_mode)
      || global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_MOSCOW) {
    fprintf(fout, "<p><big>%s: %d</big></p>\n", _("Total score"), total_score);
  }

  html_armor_free(&ab);
}

int
ns_examiners_page(
	FILE *fout,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  const serve_state_t cs = extra->serve_state;
  const struct section_problem_data *prob = 0;
  int prob_id, user_id, max_user_id = -1, i, role_mask, ex_cnt, chief_user_id;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int_iterator_t iter = 0;
  unsigned char **logins = 0, **names = 0, *roles = 0;
  unsigned char *login = 0, *name = 0;
  unsigned char bb[1024];
  const unsigned char *s = 0, *s_beg = 0, *s_end = 0;
  unsigned char nbuf[1024];
  int exam_role_count = 0, chief_role_count = 0, add_count, ex_num;
  int assignable_runs, assigned_runs;
  unsigned char *exam_flag = 0;

  fprintf(fout, "<p>%s%s</a></p>",
          ns_aref(nbuf, sizeof(nbuf), phr, NEW_SRV_ACTION_MAIN_PAGE, 0),
          _("Main page"));

  // find all users that have EXAMINER or CHIEF_EXAMINER role
  for (iter = nsdb_get_contest_user_id_iterator(phr->contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    user_id = iter->get(iter);
    role_mask = 0;
    if (nsdb_get_priv_role_mask_by_iter(iter, &role_mask) < 0) continue;
    if (!(role_mask & ((1 << USER_ROLE_EXAMINER) | (1 << USER_ROLE_CHIEF_EXAMINER))))
      continue;
    if (user_id > max_user_id) max_user_id = user_id;
  }
  iter->destroy(iter); iter = 0;

  if (max_user_id > 0) {
    XCALLOC(logins, max_user_id + 1);
    XCALLOC(names, max_user_id + 1);
    XCALLOC(roles, max_user_id + 1);
    XCALLOC(exam_flag, max_user_id + 1);
  }

  for (iter = nsdb_get_contest_user_id_iterator(phr->contest_id);
       iter->has_next(iter);
       iter->next(iter)) {
    user_id = iter->get(iter);
    if (nsdb_get_priv_role_mask_by_iter(iter, &role_mask) < 0) continue;
    if (!(role_mask & ((1 << USER_ROLE_EXAMINER) | (1 << USER_ROLE_CHIEF_EXAMINER))))
      continue;
    if (userlist_clnt_lookup_user_id(ul_conn, user_id, phr->contest_id,
                                     &login, &name) < 0)
      continue;
    if (!login || !*login) {
      xfree(login); xfree(name);
      continue;
    }
    logins[user_id] = login;
    if (!*name) {
      xfree(name); name = 0;
    }
    if (name && !strcmp(name, login)) {
      xfree(name); name = 0;
    }
    names[user_id] = name;
    roles[user_id] = role_mask;
    login = name = 0;
  }
  iter->destroy(iter); iter = 0;

  for (i = 1; i <= max_user_id; i++) {
    if ((roles[i] & (1 << USER_ROLE_CHIEF_EXAMINER))) chief_role_count++;
    if ((roles[i] & (1 << USER_ROLE_EXAMINER))) exam_role_count++;
  }

  for (prob_id = 1; prob_id <= cs->max_prob; prob_id++) {
    if (!(prob = cs->probs[prob_id]) || prob->manual_checking <= 0) continue;

    fprintf(fout, "<h3>%s %s: %s</h3>\n", _("Problem"),
            prob->short_name, ARMOR(prob->long_name));

    // chief examiner + drop-down box for its changing
    // examiners + drop-down box to add an examiner + button to delete
    html_start_form(fout, 1, phr->self_url, phr->hidden_vars);
    html_hidden(fout, "prob_id", "%d", prob_id);
    fprintf(fout, "<table class=\"b1\">");
    fprintf(fout, "<tr><td class=\"b1\" valign=\"top\">%s</td>",
            _("Chief examiner"));

    user_id = nsdb_find_chief_examiner(phr->contest_id, prob_id);
    chief_user_id = user_id;
    s_beg = ""; s_end = "";
    if (user_id < 0) {
      snprintf(nbuf, sizeof(nbuf), "<i><font color=\"red\">Error!</font></i>");
    } else if (!user_id) {
      snprintf(nbuf, sizeof(nbuf), "<i>Not set</i>");
    } else {
      if (user_id > max_user_id || !logins[user_id]) {
        s_beg = "<s>"; s_end = "</s>";
        snprintf(nbuf, sizeof(nbuf), "User %d", user_id);
      } else {
        if (!(roles[user_id] & (1 << USER_ROLE_CHIEF_EXAMINER))) {
          s_beg = "<s>"; s_end = "</s>";
        }
        if (!names[user_id]) {
          snprintf(nbuf, sizeof(nbuf), "%s", logins[user_id]);
        } else {
          snprintf(nbuf, sizeof(nbuf), "%s (%s)",
                   logins[user_id], ARMOR(names[user_id]));
        }
      }
    }
    fprintf(fout, "<td class=\"b1\" valign=\"top\">%s%s%s</td>", s_beg, nbuf, s_end);

    fprintf(fout, "<td class=\"b1\" valign=\"top\">");
    fprintf(fout, "<select name=\"chief_user_id\"><option value=\"0\"></option>");
    for (i = 1; i <= max_user_id; i++) {
      if (!(roles[i] & (1 << USER_ROLE_CHIEF_EXAMINER)))
        continue;
      s = "";
      if (i == user_id) s = " selected=\"selected\"";
      fprintf(fout, "<option value=\"%d\">", i);
      if (!names[i])
        fprintf(fout, "%s", logins[i]);
      else
        fprintf(fout, "%s (%s)", logins[i], ARMOR(names[i]));
      fprintf(fout, "</option>");
    }
    fprintf(fout, "</select>");
    fprintf(fout, "%s", BUTTON(NEW_SRV_ACTION_ASSIGN_CHIEF_EXAMINER));
    fprintf(fout, "</td>");
    fprintf(fout, "</tr>");

    // examiners
    fprintf(fout, "<tr><td class=\"b1\" valign=\"top\">%s</td>",
            _("Examiners"));

    // list of examiners
    fprintf(fout, "<td class=\"b1\" valign=\"top\">");
    ex_cnt = nsdb_get_examiner_count(phr->contest_id, prob_id);
    if (max_user_id > 0) memset(exam_flag, 0, max_user_id + 1);
    if (ex_cnt < 0) {
      fprintf(fout, "<i><font color=\"red\">Error!</font></i>");
    } else if (!ex_cnt) {
      fprintf(fout, "<i>%s</i>", "Nobody");
    } else {
      fprintf(fout, "<table class=\"b0\">");
      for (iter = nsdb_get_examiner_user_id_iterator(phr->contest_id, prob_id);
           iter->has_next(iter);
           iter->next(iter)) {
        user_id = iter->get(iter);
        if (user_id <= 0 || user_id > max_user_id || !logins[user_id]) {
          s_beg = "<s>"; s_end = "</s>";
          snprintf(nbuf, sizeof(nbuf), "User %d", user_id);
        } else {
          exam_flag[user_id] = 1;
          s_beg = ""; s_end = "";
          if (!(roles[user_id] & (1 << USER_ROLE_EXAMINER))) {
            s_beg = "<s>"; s_end = "</s>";
          }
          if (!names[user_id]) {
            snprintf(nbuf, sizeof(nbuf), "%s", logins[user_id]);
          } else {
            snprintf(nbuf, sizeof(nbuf), "%s (%s)",
                     logins[user_id], ARMOR(names[user_id]));
          }
        }
        fprintf(fout, "<tr><td class=\"b0\">%s%s%s</td></tr>",
                s_beg, nbuf, s_end);
      }
      iter->destroy(iter); iter = 0;
      fprintf(fout, "</table>");
    }
    fprintf(fout, "</td>");

    // control elements
    fprintf(fout, "<td class=\"b1\" valign=\"top\">");
    if (!ex_cnt && !exam_role_count) {
      fprintf(fout, "&nbsp;");
    } else {
      fprintf(fout, "<table class=\"b0\">");
      if (ex_cnt > 0) {
        // remove examiner
        fprintf(fout, "<tr><td class=\"b0\"><select name=\"exam_del_user_id\"><option value=\"0\"></option>");
        for (iter=nsdb_get_examiner_user_id_iterator(phr->contest_id, prob_id);
             iter->has_next(iter);
             iter->next(iter)) {
          user_id = iter->get(iter);
          if (user_id <= 0 || user_id > max_user_id || !logins[user_id]) {
            snprintf(nbuf, sizeof(nbuf), "User %d", user_id);
          } else {
            if (!names[user_id]) {
              snprintf(nbuf, sizeof(nbuf), "%s", logins[user_id]);
            } else {
              snprintf(nbuf, sizeof(nbuf), "%s (%s)",
                       logins[user_id], ARMOR(names[user_id]));
            }
          }
          fprintf(fout, "<option value=\"%d\">%s</option>", user_id, nbuf);
        }
        iter->destroy(iter); iter = 0;
        fprintf(fout, "</select></td><td class=\"b0\">%s</td></tr>",
                BUTTON(NEW_SRV_ACTION_UNASSIGN_EXAMINER));
      }
      // add examiner
      add_count = 0;
      for (i = 1; i <= max_user_id; i++)
        if ((roles[i] & (1 << USER_ROLE_EXAMINER)) && !exam_flag[i])
          add_count++;
      if (add_count > 0) {
        fprintf(fout, "<tr><td class=\"b0\"><select name=\"exam_add_user_id\"><option value=\"0\"></option>");
        for (i = 1; i <= max_user_id; i++) {
          if (!(roles[i] & (1 << USER_ROLE_EXAMINER)) || exam_flag[i])
            continue;
          if (!names[i])
            snprintf(nbuf, sizeof(nbuf), "%s", logins[i]);
          else
            snprintf(nbuf, sizeof(nbuf), "%s (%s)", logins[i], ARMOR(names[i]));
          fprintf(fout, "<option value=\"%d\">%s</option>", i, nbuf);
        }
        fprintf(fout, "</select></td><td class=\"b0\">%s</td></tr>",
                BUTTON(NEW_SRV_ACTION_ASSIGN_EXAMINER));
      }
      fprintf(fout, "</table>");
    }
    fprintf(fout, "</td>");
    fprintf(fout, "</tr>");

    fprintf(fout, "</table></form>\n");

    if (chief_user_id <= 0) {
      fprintf(fout, "<p><font color=\"red\">%s</font></p>",
              _("Chief examiner must be assigned."));
    }
    ex_num = 1;
    if (prob->examinator_num > 1 && prob->examinator_num <= 3)
      ex_num = prob->examinator_num;
    if (ex_cnt < ex_num) {
      fprintf(fout, _("<p><font color=\"red\">At least %d examiners must be assigned.</font></p>"), ex_num);

    }

    assigned_runs = 0;
    assignable_runs = run_count_examinable_runs(cs->runlog_state, prob_id,
                                                ex_num, &assigned_runs);
    if (!assignable_runs) {
      fprintf(fout, "<p>%s</p>\n", _("No assignable runs."));
    }
  }

  if (logins) {
    for (i = 0; i <= max_user_id; i++)
      xfree(logins[i]);
    xfree(logins);
  }
  if (names) {
    for (i = 0; i <= max_user_id; i++)
      xfree(names[i]);
    xfree(names);
  }

  xfree(roles);
  xfree(exam_flag);
  html_armor_free(&ab);
  return 0;
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "va_list")
 * End:
 */
