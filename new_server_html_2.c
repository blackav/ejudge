/* -*- mode: c -*- */

/* Copyright (C) 2006-2016 Alexander Chernov <cher@ejudge.ru> */

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
#include "ejudge/ej_types.h"
#include "ejudge/ej_limits.h"
#include "ejudge/new-server.h"
#include "ejudge/new_server_proto.h"
#include "ejudge/filter_eval.h"
#include "ejudge/misctext.h"
#include "ejudge/mischtml.h"
#include "ejudge/html.h"
#include "ejudge/clarlog.h"
#include "ejudge/base64.h"
#include "ejudge/xml_utils.h"
#include "ejudge/archive_paths.h"
#include "ejudge/fileutl.h"
#include "ejudge/mime_type.h"
#include "ejudge/l10n.h"
#include "ejudge/filehash.h"
#include "ejudge/digest_io.h"
#include "ejudge/testing_report_xml.h"
#include "ejudge/full_archive.h"
#include "ejudge/teamdb.h"
#include "ejudge/userlist.h"
#include "ejudge/team_extra.h"
#include "ejudge/errlog.h"
#include "ejudge/csv.h"
#include "ejudge/sha.h"
#include "ejudge/sformat.h"
#include "ejudge/userlist_clnt.h"
#include "ejudge/charsets.h"
#include "ejudge/compat.h"
#include "ejudge/run_packet.h"
#include "ejudge/prepare_dflt.h"
#include "ejudge/super_run_packet.h"
#include "ejudge/ej_uuid.h"
#include "ejudge/new_server_pi.h"
#include "ejudge/xuser_plugin.h"
#include "ejudge/super_run_status.h"

#include "ejudge/xalloc.h"
#include "ejudge/logger.h"
#include "ejudge/osdeps.h"

#include <zlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>

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
ns_write_priv_all_runs(
        FILE *f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int first_run_set,
        int first_run,
        int last_run_set,
        int last_run,
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
  unsigned char hbuf[512];
  const unsigned char *imported_str;
  const unsigned char *examinable_str;
  const unsigned char *marked_str;
  const unsigned char *saved_str;
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
  int enable_js_status_menu = 0;
  int run_fields;

  if (!u) u = user_filter_info_allocate(cs, phr->user_id, phr->session_id);

  run_fields = u->run_fields;
  if (run_fields <= 0 && cs->xuser_state) {
    run_fields = cs->xuser_state->vt->get_run_fields(cs->xuser_state, phr->user_id);
  }
  if (run_fields <= 0) {
    run_fields = RUN_VIEW_DEFAULT;
  }

  // FIXME: check permissions
  enable_js_status_menu = 1;

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

    if (!first_run_set) {
      first_run_set = u->prev_first_run_set;
      first_run = u->prev_first_run;
    }
    if (!last_run_set) {
      last_run_set = u->prev_last_run_set;
      last_run = u->prev_last_run;
    }
    u->prev_first_run_set = first_run_set;
    u->prev_first_run = first_run;
    u->prev_last_run_set = last_run_set;
    u->prev_last_run = last_run;

    if (!first_run_set && !last_run_set) {
      // last 20 in the reverse order
      first_run = -1;
      last_run = -20;
    } else if (!first_run_set) {
      // from the last in the reverse order
      first_run = -1;
    } else if (!last_run_set) {
      // 20 in the reverse order
      last_run = first_run - 20 + 1;
      if (first_run >= 0 && last_run < 0) last_run = 0;
    }

    if (first_run >= match_tot) {
      first_run = match_tot - 1;
      if (first_run < 0) first_run = 0;
    }
    if (first_run < 0) {
      first_run = match_tot + first_run;
      if (first_run < 0) first_run = 0;
    }
    if (last_run >= match_tot) {
      last_run = match_tot - 1;
      if (last_run < 0) last_run = 0;
    }
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
  if (u->prev_first_run_set) {
    snprintf(first_run_str, sizeof(first_run_str), "%d", u->prev_first_run);
  }
  if (u->prev_last_run_set) {
    snprintf(last_run_str, sizeof(last_run_str), "%d", u->prev_last_run);
  }
  html_start_form(f, 0, phr->self_url, phr->hidden_vars);
  fprintf(f, "<p>%s: <input type=\"text\" name=\"filter_expr\" size=\"32\" maxlength=\"1024\" value=\"%s\"/>", _("Filter expression"), fe_html);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_first_run\" size=\"16\" value=\"%s\"/>", _("First run"), first_run_str);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_last_run\" size=\"16\" value=\"%s\"/>", _("Last run"), last_run_str);
  fprintf(f, "%s",
          ns_submit_button(bb, sizeof(bb), "filter_view", 1, _("View")));
  //html_start_form(f, 0, phr->self_url, phr->hidden_vars);
  fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_RESET_FILTER));
  fprintf(f, "<a href=\"%sfilter_expr.html\" target=\"_blank\">%s</a>",
          CONF_STYLE_PREFIX, _("Help"));
  fprintf(f, "</p></form><br/>\n");

  if (u->error_msgs) {
    fprintf(f, "<h2>Filter expression errors</h2>\n");
    fprintf(f, "<p><pre><font color=\"red\">%s</font></pre></p>\n",
            u->error_msgs);
  }

  if (!u->error_msgs) {
    switch (global->score_system) {
    case SCORE_ACM:
      //str1 = _("Failed test");
      str1 = "Failed";
      break;
    case SCORE_KIROV:
    case SCORE_OLYMPIAD:
      //str1 = _("Tests passed");
      str1 = "Tests";
      str2 = _("Score");
      break;
    case SCORE_MOSCOW:
      //str1 = _("Failed test");
      str1 = "Failed";
      str2 = _("Score");
      break;
    default:
      abort();
    }

    // this is a hidden form to change status
    fprintf(f, "<form id=\"ChangeStatusForm\" method=\"POST\" action=\"%s\">\n"
            "<input type=\"hidden\" name=\"SID\" value=\"%016llx\" />\n"
            "<input type=\"hidden\" name=\"action\" value=\"%d\" />\n"
            "<input type=\"hidden\" name=\"run_id\" value=\"\" />\n"
            "<input type=\"hidden\" name=\"status\" value=\"\" />\n"
            "</form>\n", phr->self_url, phr->session_id, NEW_SRV_ACTION_CHANGE_STATUS);

    // FIXME: class should be a parameter
    snprintf(cl, sizeof(cl), " class=\"b1\"");

    fprintf(f, "<table%s><tr>", cl);
    if (run_fields & (1 << RUN_VIEW_RUN_ID)) {
      fprintf(f, "<th%s>%s</th>", cl, _("Run ID"));
    }
    if (run_fields & (1 << RUN_VIEW_RUN_UUID)) {
      fprintf(f, "<th%s>%s</th>", cl, "UUID");
    }
    if (run_fields & (1 << RUN_VIEW_STORE_FLAGS)) {
      fprintf(f, "<th%s>%s</th>", cl, "Storage Flags");
    }
    if (run_fields & (1 << RUN_VIEW_TIME)) {
      fprintf(f, "<th%s>%s</th>", cl, _("Time"));
    }
    if (run_fields & (1 << RUN_VIEW_ABS_TIME)) {
      fprintf(f, "<th%s>%s</th>", cl, "Abs. Time");
    }
    if (run_fields & (1 << RUN_VIEW_REL_TIME)) {
      fprintf(f, "<th%s>%s</th>", cl, "Rel. Time");
    }
    if (run_fields & (1 << RUN_VIEW_NSEC)) {
      fprintf(f, "<th%s>%s</th>", cl, "ns");
    }
    if (run_fields & (1 << RUN_VIEW_SIZE)) {
      fprintf(f, "<th%s>%s</th>", cl, "Size");
    }
    if (run_fields & (1 << RUN_VIEW_MIME_TYPE)) {
      fprintf(f, "<th%s>%s</th>", cl, "Mime type");
    }
    if (run_fields & (1 << RUN_VIEW_IP)) {
      fprintf(f, "<th%s>%s</th>", cl, "IP");
    }
    if (run_fields & (1 << RUN_VIEW_SHA1)) {
      fprintf(f, "<th%s>%s</th>", cl, "SHA1");
    }
    if (run_fields & (1 << RUN_VIEW_USER_ID)) {
      fprintf(f, "<th%s>%s</th>", cl, "User ID");
    }
    if (run_fields & (1 << RUN_VIEW_USER_LOGIN)) {
      fprintf(f, "<th%s>%s</th>", cl, "Login");
    }
    if (run_fields & (1 << RUN_VIEW_USER_NAME)) {
      fprintf(f, "<th%s>%s</th>", cl, "User name");
    }
    if (run_fields & (1 << RUN_VIEW_PROB_ID)) {
      fprintf(f, "<th%s>%s</th>", cl, "Prob ID");
    }
    if (run_fields & (1 << RUN_VIEW_PROB_NAME)) {
      fprintf(f, "<th%s>%s</th>", cl, "Problem");
    }
    if (run_fields & (1 << RUN_VIEW_VARIANT)) {
      fprintf(f, "<th%s>%s</th>", cl, "Variant");
    }
    if (run_fields & (1 << RUN_VIEW_LANG_ID)) {
      fprintf(f, "<th%s>%s</th>", cl, "Lang ID");
    }
    if (run_fields & (1 << RUN_VIEW_LANG_NAME)) {
      fprintf(f, "<th%s>%s</th>", cl, "Language");
    }
    if (run_fields & (1 << RUN_VIEW_EOLN_TYPE)) {
      fprintf(f, "<th%s>%s</th>", cl, "EOLN Type");
    }
    if (run_fields & (1 << RUN_VIEW_TOKENS)) {
      fprintf(f, "<th%s>%s</th>", cl, "Tokens");
    }
    if (run_fields & (1 << RUN_VIEW_STATUS)) {
      fprintf(f, "<th%s>%s</th>", cl, "Result");
    }
    if (run_fields & (1 << RUN_VIEW_TEST)) {
      fprintf(f, "<th%s>%s</th>", cl, str1);
    }
    if (str2 && (run_fields & (1 << RUN_VIEW_SCORE))) {
      fprintf(f, "<th%s>%s</th>", cl, str2);
    }
    if (run_fields & (1 << RUN_VIEW_SCORE_ADJ)) {
      fprintf(f, "<th%s>%s</th>", cl, "Score Adj.");
    }
    if (run_fields & (1 << RUN_VIEW_SAVED_STATUS)) {
      fprintf(f, "<th%s>%s</th>", cl, "Saved status");
    }
    if (run_fields & (1 << RUN_VIEW_SAVED_TEST)) {
      fprintf(f, "<th%s>%s</th>", cl, "Saved test");
    }
    if (run_fields & (1 << RUN_VIEW_SAVED_SCORE)) {
      fprintf(f, "<th%s>%s</th>", cl, "Saved score");
    }
    /*
    if (phr->role == USER_ROLE_ADMIN) {
      fprintf(f, "<th%s>%s</th>", cl, _("New result"));
      fprintf(f, "<th%s>%s</th>", cl, _("Change result"));
    }
    */

    /*
      fprintf(f, "<td%s><a href=\"javascript:ej_stat(%d)\">%s</a><div class=\"ej_dd\" id=\"ej_dd_%d\"></div></td>", cl, pe->run_id, status_str, pe->run_id);

     */

    fprintf(f, "<th%s>%s</th><th%s>%s&nbsp;<a href=\"javascript:ej_field_popup(%d)\">&gt;&gt;</a><div class=\"ej_dd\" id=\"ej_field_popup\"></div></th></tr>\n",
            cl, "Source", cl, "Report", run_fields);
    if (phr->role == USER_ROLE_ADMIN) {
      //snprintf(endrow, sizeof(endrow), "</tr></form>\n");
      snprintf(endrow, sizeof(endrow), "</tr>\n");
    } else {
      snprintf(endrow, sizeof(endrow), "</tr>\n");
    }

    for (i = 0; i < list_tot; i++) {
      rid = list_idx[i];
      ASSERT(rid >= 0 && rid < env.rtotal);
      pe = &env.rentries[rid];

      displayed_mask[rid / BITS_PER_LONG] |= (1L << (rid % BITS_PER_LONG));

      const struct section_problem_data *prob = NULL;
      if (pe->prob_id > 0 && pe->prob_id <= cs->max_prob) {
        prob = cs->probs[pe->prob_id];
      }
      prob_type = 0;
      if (prob) prob_type = prob->type;

      const struct section_language_data *lang = NULL;
      if (pe->lang_id > 0 && pe->lang_id <= cs->max_lang) {
        lang = cs->langs[pe->lang_id];
      }

      /*
      if (phr->role == USER_ROLE_ADMIN) {
        html_start_form(f, 1, phr->self_url, phr->hidden_vars);
        html_hidden(f, "run_id", "%d", rid);
      }
      */
      fprintf(f, "<tr>");

      if (pe->status == RUN_EMPTY) {
        run_status_str(pe->status, statstr, sizeof(statstr), 0, 0);
        if (run_fields & (1 << RUN_VIEW_RUN_ID)) {
          fprintf(f, "<td%s>%d</td>", cl, rid);
        }
        if (run_fields & (1 << RUN_VIEW_RUN_UUID)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_STORE_FLAGS)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_TIME)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_ABS_TIME)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_REL_TIME)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_NSEC)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SIZE)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_MIME_TYPE)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_IP)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SHA1)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_USER_ID)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_USER_LOGIN)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_USER_NAME)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_PROB_ID)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_PROB_NAME)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_VARIANT)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_LANG_ID)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_LANG_NAME)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_EOLN_TYPE)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_TOKENS)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_STATUS)) {
          fprintf(f, "<td%s><b>%s</b></td>", cl, statstr);
        }
        if (run_fields & (1 << RUN_VIEW_TEST)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (str2 && (run_fields & (1 << RUN_VIEW_SCORE))) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SCORE_ADJ)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SAVED_STATUS)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SAVED_TEST)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SAVED_SCORE)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        fprintf(f, "<td%s>&nbsp;</td>", cl);
        /*
        if (phr->role == USER_ROLE_ADMIN) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        */
        fprintf(f, "%s", endrow);
        continue;
      }
      if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP) {
        examinable_str = "";
        if (pe->judge_id > 0) examinable_str = "!";
        run_time = pe->time;
        if (!env.rhead.start_time) run_time = 0;
        if (env.rhead.start_time > run_time) run_time = env.rhead.start_time;
        duration_str(1, run_time, env.rhead.start_time, durstr, 0);
        run_status_str(pe->status, statstr, sizeof(statstr), 0, 0);

        if (run_fields & (1 << RUN_VIEW_RUN_ID)) {
          fprintf(f, "<td%s>%d%s</td>", cl, rid, examinable_str);
        }
        if (run_fields & (1 << RUN_VIEW_RUN_UUID)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_STORE_FLAGS)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_TIME)) {
          fprintf(f, "<td%s>%s</td>", cl, durstr);
        }
        if (run_fields & (1 << RUN_VIEW_ABS_TIME)) {
          fprintf(f, "<td%s>%s</td>", cl, durstr);
        }
        if (run_fields & (1 << RUN_VIEW_REL_TIME)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_NSEC)) {
          fprintf(f, "<td%s>%d</td>", cl, (int) pe->nsec);
        }
        if (run_fields & (1 << RUN_VIEW_SIZE)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_MIME_TYPE)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_IP)) {
          fprintf(f, "<td%s>%s</td>", cl, xml_unparse_ip(pe->a.ip));
        }
        if (run_fields & (1 << RUN_VIEW_SHA1)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_USER_ID)) {
          fprintf(f, "<td%s>%d</td>", cl, pe->user_id);
        }
        if (run_fields & (1 << RUN_VIEW_USER_LOGIN)) {
          fprintf(f, "<td%s>%s</td>", cl, teamdb_get_login(cs->teamdb_state, pe->user_id));
        }
        if (run_fields & (1 << RUN_VIEW_USER_NAME)) {
          fprintf(f, "<td%s><a href=\"%s\">%s</a></td>", cl,
                  ns_url(hbuf, sizeof(hbuf), phr, NEW_SRV_ACTION_VIEW_USER_INFO,
                         "user_id=%d", pe->user_id),
                  ARMOR(teamdb_get_name_2(cs->teamdb_state, pe->user_id)));
        }
        if (run_fields & (1 << RUN_VIEW_PROB_ID)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_PROB_NAME)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_VARIANT)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_LANG_ID)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_LANG_NAME)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_EOLN_TYPE)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_TOKENS)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_STATUS)) {
          fprintf(f, "<td%s><b>%s</b></td>", cl, statstr);
        }
        if (run_fields & (1 << RUN_VIEW_TEST)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (str2 && (run_fields & (1 << RUN_VIEW_SCORE))) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SCORE_ADJ)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SAVED_STATUS)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SAVED_TEST)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        if (run_fields & (1 << RUN_VIEW_SAVED_SCORE)) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }

        fprintf(f, "<td%s>&nbsp;</td>", cl);
        if (phr->role == USER_ROLE_ADMIN) {
          fprintf(f, "<td%s>", cl);
          html_start_form(f, 1, phr->self_url, phr->hidden_vars);
          html_hidden(f, "run_id", "%d", rid);
          fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_CLEAR_RUN));
          fprintf(f, "</form></td>");
        } else {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        /*
        if (phr->role == USER_ROLE_ADMIN) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
        */
        fprintf(f, "%s", endrow);
        continue;
      }

      prob = 0;
      if (pe->prob_id > 0 && pe->prob_id <= cs->max_prob) {
        prob = cs->probs[pe->prob_id];
      }
      prev_successes = RUN_TOO_MANY;
      if (global->score_system == SCORE_KIROV && pe->status == RUN_OK
          && prob && prob->score_bonus_total > 0) {
        if ((prev_successes = run_get_prev_successes(cs->runlog_state, rid))<0)
          prev_successes = RUN_TOO_MANY;
      }

      attempts = 0; disq_attempts = 0;
      if (global->score_system == SCORE_KIROV && !pe->is_hidden) {
        int ice = 0;
        if (prob) ice = prob->ignore_compile_errors;
        run_get_attempts(cs->runlog_state, rid, &attempts, &disq_attempts, ice);
      }
      run_time = pe->time;
      imported_str = "";
      if (pe->is_imported) {
        imported_str = "*";
      }
      if (pe->is_hidden) {
        imported_str = "#";
      }
      examinable_str = "";
      /*
      if (pe->is_examinable) {
        examinable_str = "!";
      }
      */
      marked_str = "";
      if (pe->is_marked) {
        marked_str = "@";
      }
      saved_str = "";
      if (pe->is_saved) {
        saved_str = "+";
      }
      start_time = env.rhead.start_time;
      if (global->is_virtual) {
        start_time = run_get_virtual_start_time(cs->runlog_state, pe->user_id);
      }
      if (!start_time) run_time = 0;
      if (start_time > run_time) run_time = start_time;
      duration_str(global->show_astr_time, run_time, start_time,
                   durstr, 0);

      if (run_fields & (1 << RUN_VIEW_RUN_ID)) {
        fprintf(f, "<td%s>%d%s%s%s%s</td>", cl, rid, imported_str, examinable_str,
                marked_str, saved_str);
      }
      if (run_fields & (1 << RUN_VIEW_RUN_UUID)) {
        fprintf(f, "<td%s>%s</td>", cl, ej_uuid_unparse(&pe->run_uuid, "&nbsp;"));
      }
      if (run_fields & (1 << RUN_VIEW_STORE_FLAGS)) {
        fprintf(f, "<td%s>%d</td>", cl, pe->store_flags);
      }
      if (run_fields & (1 << RUN_VIEW_TIME)) {
        fprintf(f, "<td%s>%s</td>", cl, durstr);
      }
      if (run_fields & (1 << RUN_VIEW_ABS_TIME)) {
        if (global->show_astr_time <= 0) {
          duration_str(1, run_time, start_time, durstr, 0);
        }
        fprintf(f, "<td%s>%s</td>", cl, durstr);
      }
      if (run_fields & (1 << RUN_VIEW_REL_TIME)) {
        if (global->show_astr_time > 0) {
          duration_str(0, run_time, start_time, durstr, 0);
        }
        fprintf(f, "<td%s>%s</td>", cl, durstr);
      }
      if (run_fields & (1 << RUN_VIEW_NSEC)) {
        fprintf(f, "<td%s>%d</td>", cl, (int) pe->nsec);
      }
      if (run_fields & (1 << RUN_VIEW_SIZE)) {
        fprintf(f, "<td%s>%u</td>", cl, pe->size);
      }
      if (run_fields & (1 << RUN_VIEW_MIME_TYPE)) {
        if (pe->lang_id <= 0) {
          fprintf(f, "<td%s>%s</td>", cl, mime_type_get_type(pe->mime_type));
        } else {
          fprintf(f, "<td%s>%s</td>", cl, "&nbsp;");
        }
      }
      if (run_fields & (1 << RUN_VIEW_IP)) {
        fprintf(f, "<td%s>%s</td>", cl, xml_unparse_ip(pe->a.ip));
      }
      if (run_fields & (1 << RUN_VIEW_SHA1)) {
        fprintf(f, "<td%s>%s</td>", cl, unparse_sha1(pe->sha1));
      }
      if (run_fields & (1 << RUN_VIEW_USER_ID)) {
        fprintf(f, "<td%s>%d</td>", cl, pe->user_id);
      }
      if (run_fields & (1 << RUN_VIEW_USER_LOGIN)) {
        fprintf(f, "<td%s>%s</td>", cl,
                ARMOR(teamdb_get_login(cs->teamdb_state, pe->user_id)));
      }
      if (run_fields & (1 << RUN_VIEW_USER_NAME)) {
        fprintf(f, "<td%s>%s</td>", cl,
                ARMOR(teamdb_get_name_2(cs->teamdb_state, pe->user_id)));
      }
      if (run_fields & (1 << RUN_VIEW_PROB_ID)) {
        fprintf(f, "<td%s>%d</td>", cl, pe->prob_id);
      }
      if (run_fields & (1 << RUN_VIEW_PROB_NAME)) {
        if (prob) {
          if (prob->variant_num > 0) {
            int variant = pe->variant;
            if (!variant) variant = find_variant(cs, pe->user_id, pe->prob_id, 0);
            if (variant > 0) {
              fprintf(f, "<td%s>%s-%d</td>", cl, prob->short_name, variant);
            } else {
              fprintf(f, "<td%s>%s-?</td>", cl, prob->short_name);
            }
          } else {
            fprintf(f, "<td%s>%s</td>", cl, prob->short_name);
          }
        } else {
          fprintf(f, "<td%s>??? - %d</td>", cl, pe->prob_id);
        }
      }
      if (run_fields & (1 << RUN_VIEW_VARIANT)) {
        if (prob && prob->variant_num > 0) {
          fprintf(f, "<td%s>%d</td>", cl, pe->variant);
        } else {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
      }
      if (run_fields & (1 << RUN_VIEW_LANG_ID)) {
        fprintf(f, "<td%s>%d</td>", cl, pe->lang_id);
      }
      if (run_fields & (1 << RUN_VIEW_LANG_NAME)) {
        if (!pe->lang_id) {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        } else if (lang) {
          fprintf(f, "<td%s>%s</td>", cl, lang->short_name);
        } else {
          fprintf(f, "<td%s>??? - %d</td>", cl, pe->lang_id);
        }
      }
      if (run_fields & (1 << RUN_VIEW_EOLN_TYPE)) {
        fprintf(f, "<td%s>%s</td>", cl, eoln_type_unparse_html(pe->eoln_type));
      }
      if (run_fields & (1 << RUN_VIEW_TOKENS)) {
        fprintf(f, "<td%s>%d, %d</td>", cl, pe->token_flags, pe->token_count);
      }

      run_status_str(pe->status, statstr, sizeof(statstr), prob_type, 0);
      write_html_run_status(cs, f, start_time, pe, 0, 1, attempts, disq_attempts,
                            prev_successes, "b1", 0,
                            enable_js_status_menu, run_fields);

      if (run_fields & (1 << RUN_VIEW_SCORE_ADJ)) {
        fprintf(f, "<td%s>%d</td>", cl, pe->score_adj);
      }
      if (run_fields & (1 << RUN_VIEW_SAVED_STATUS)) {
        if (pe->is_saved > 0) {
          run_status_str(pe->saved_status, statstr, sizeof(statstr), prob_type, 0);
          fprintf(f, "<td%s>%s</td>", cl, statstr);
        } else {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
      }
      if (run_fields & (1 << RUN_VIEW_SAVED_TEST)) {
        if (pe->is_saved > 0) {
          fprintf(f, "<td%s>%d</td>", cl, pe->saved_test);
        } else {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
      }
      if (run_fields & (1 << RUN_VIEW_SAVED_SCORE)) {
        if (pe->is_saved > 0) {
          fprintf(f, "<td%s>%d</td>", cl, pe->saved_score);
        } else {
          fprintf(f, "<td%s>&nbsp;</td>", cl);
        }
      }

      /*
      if (phr->role == USER_ROLE_ADMIN) {
        html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      }
      */
      /*
      if (phr->role == USER_ROLE_ADMIN) {
        write_change_status_dialog(cs, f, "status", pe->is_imported, "b1");
        fprintf(f, "<td%s>%s</td>", cl, BUTTON(NEW_SRV_ACTION_CHANGE_STATUS));
      }
      */

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
      /*
      if (phr->role == USER_ROLE_ADMIN) {
        fprintf(f, "</form>\n");
      }
      */
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
    fprintf(f, "</form></td>\n");

    if (global->score_system == SCORE_OLYMPIAD && cs->accepting_mode) {
      fprintf(f, "<td>\n");
      html_start_form(f, 1, phr->self_url, phr->hidden_vars);
      html_hidden(f, "run_mask_size", "%d", displayed_size);
      fprintf(f, "<input type=\"hidden\" name=\"run_mask\" value=\"");
      for (i = 0; i < displayed_size; i++) {
        if (i > 0) fprintf(f, " ");
        fprintf(f, "%lx", displayed_mask[i]);
      }
      fprintf(f, "\"/>\n");
      fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_FULL_REJUDGE_DISPLAYED_1));
      fprintf(f, "</form></td>\n");
    }

    /*
    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    fprintf(f, "%s", BUTTON(NEW_SRV_ACTION_SQUEEZE_RUNS));
    fprintf(f, "</form></td>\n");
    */
    fprintf(f, "</tr></table>\n");

    html_start_form(f, 1, phr->self_url, phr->hidden_vars);
    fprintf(f, "%s: <select name=\"prob_id\"><option value=\"\"></option>\n",
            _("Rejudge problem"));
    for (i = 1; i <= cs->max_prob; i++) {
      if (!(prob = cs->probs[i])) continue;
      // check the problems that we ever can rejudge
      if (prob->type > 0) {
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

  /*
  if (phr->role == USER_ROLE_ADMIN
      && opcaps_check(phr->caps, OPCAP_EDIT_RUN) >= 0) {
    fprintf(f, "<table><tr><td>%s%s</a></td></td></table>\n",
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_PRIO_FORM, 0),
            _("Change judging priorities"));
  }
  */

    /*
  if (phr->role == USER_ROLE_ADMIN && global->enable_runlog_merge) {
    html_start_form(f, 2, self_url, hidden_vars);
    fprintf(f, "<table border=\"0\"><tr><td>%s: </td>\n",
            _("Import and merge XML runs log"));
    fprintf(f, "<td><input type=\"file\" name=\"file\"/></td>\n");
    fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"/></td>", ACTION_MERGE_RUNS, _("Send!"));
    fprintf(f, "</tr></table></form>\n");
  }
    */

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

  /*
  if (opcaps_check(phr->caps, OPCAP_SUBMIT_RUN) >= 0
      && opcaps_check(phr->caps, OPCAP_EDIT_RUN) >= 0) {
    fprintf(f, "<table><tr><td>%s%s</a></td></td></table>\n",
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_NEW_RUN_FORM, 0),
            _("Add new run"));
  }
  */

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
    fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_MARK_DISPLAYED_2));
    fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_UNMARK_DISPLAYED_2));
    fprintf(f, "</tr></table><br/>\n");
    fprintf(f, "<table><tr>");
    fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_CLEAR_DISPLAYED_1));
    fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_IGNORE_DISPLAYED_1));
    fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_DISQUALIFY_DISPLAYED_1));
    fprintf(f, "<td>%s</td>", BUTTON(NEW_SRV_ACTION_TOKENIZE_DISPLAYED_1));
    fprintf(f, "</tr></table></form>\n");
  }

  /*
  if (opcaps_check(phr->caps, OPCAP_IMPORT_XML_RUNS) >= 0) {
    fprintf(f, "<table><tr><td>%s%s</a></td></td></table>\n",
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_UPLOAD_RUNLOG_CSV_1, 0),
            _("Add new runs in CSV format"));

    fprintf(f, "<table><tr><td>%s%s</a></td></td></table>\n",
            ns_aref(bb, sizeof(bb), phr, NEW_SRV_ACTION_UPLOAD_RUNLOG_XML_1, 0),
            _("Merge runs in XML format"));
  }
  */

  /*
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
*/

  /*
  print_nav_buttons(state, f, 0, sid, self_url, hidden_vars, extra_args,
                    0, 0, 0, 0, 0, 0, 0);
  */
  html_armor_free(&ab);
}

static int
parse_clar_num(
        const unsigned char *str,
        int min_val,
        int max_val,
        int dflt_val)
{
  int slen;
  unsigned char *buf;
  int val;
  char *eptr;

  if (!str) return dflt_val;
  slen = strlen(str);
  buf = (unsigned char*) alloca(slen + 1);
  memcpy(buf, str, slen + 1);
  while (slen > 0 && isspace(buf[slen - 1])) --slen;
  buf[slen] = 0;
  if (!slen) return dflt_val;
  errno = 0;
  val = strtol(buf, &eptr, 10);
  if (errno || *eptr) return dflt_val;
  if (val < min_val || val > max_val) return dflt_val;
  return val;
}

// mode_clar
// 1: all clars
// 2: unanswered clars & comments (default)
// 3: all clars & comments
// 4: clars to all
// 5: all including empty entries
static int
match_clar(serve_state_t cs, int clar_id, int mode_clar)
{
  struct clar_entry_v2 clar;

  if (mode_clar == CLAR_FILTER_NONE) return 1;
  if (clar_get_record(cs->clarlog_state, clar_id, &clar) < 0) return 0;
  if (clar.id < 0) return 0;

  switch (mode_clar) {
  case CLAR_FILTER_ALL_CLARS:
    return clar.run_id <= 0;
  case CLAR_FILTER_ALL_CLARS_COMMENTS:
    return 1;
  case CLAR_FILTER_CLARS_TO_ALL:
    return clar.from == 0 && clar.to == 0;
  case CLAR_FILTER_UNANS_CLARS_COMMENTS:
  default:
    return clar.from > 0 && clar.flags < 2;
  }
}

const unsigned char * const clar_filter_options[] =
{
  NULL,
  [CLAR_FILTER_ALL_CLARS] = __("All clars"),
  [CLAR_FILTER_UNANS_CLARS_COMMENTS] = __("Unanswered clars"),
  [CLAR_FILTER_ALL_CLARS_COMMENTS] = __("All clars and comments"),
  [CLAR_FILTER_CLARS_TO_ALL] = __("Clars to all"),
  [CLAR_FILTER_NONE] = __("All entries"),
};

void
ns_write_all_clars(
        FILE *f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra,
        int mode_clar,
        const unsigned char *first_clar_str,
        const unsigned char *last_clar_str)
{
  int total, i, j;

  int *list_idx = NULL;
  int list_tot = 0;

  unsigned char first_clar_buf[64] = { 0 };
  unsigned char last_clar_buf[64] = { 0 };

  time_t start, submit_time;
  unsigned char durstr[64];
  int show_astr_time;
  unsigned char bbuf[1024];
  struct clar_entry_v2 clar;
  unsigned char cl[128];
  int first_clar = -1, last_clar = -10;
  int count, max_mode_clar;

  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  struct user_filter_info *u = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  const unsigned char *clar_subj = 0;
  const unsigned char *judge_name = NULL;
  const unsigned char *s = "";

  u = user_filter_info_allocate(cs, phr->user_id, phr->session_id);

  if (mode_clar < 0) mode_clar = 0;
  if (phr->role == USER_ROLE_ADMIN && mode_clar > CLAR_FILTER_NONE) {
    mode_clar = 0;
  } else if (phr->role != USER_ROLE_ADMIN && mode_clar > CLAR_FILTER_NONE - 1) {
    mode_clar = 0;
  }

  fprintf(f, "<hr><h2>%s</h2>\n", _("Messages"));

  start = run_get_start_time(cs->runlog_state);
  total = clar_get_total(cs->clarlog_state);
  if (!mode_clar) mode_clar = u->prev_mode_clar;
  first_clar = parse_clar_num(first_clar_str,-total,total-1,u->prev_first_clar);
  last_clar = parse_clar_num(last_clar_str, -total, total-1, u->prev_last_clar);
  if (!mode_clar) {
    mode_clar = CLAR_FILTER_ALL_CLARS;
    if (phr->role != USER_ROLE_ADMIN) mode_clar = CLAR_FILTER_UNANS_CLARS_COMMENTS;
  }
  u->prev_mode_clar = mode_clar;
  u->prev_first_clar = first_clar;
  u->prev_last_clar = last_clar;
  show_astr_time = global->show_astr_time;
  if (global->is_virtual) show_astr_time = 1;

  if (first_clar < 0) {
    first_clar = total + first_clar;
    if (first_clar < 0) first_clar = 0;
  }

  XCALLOC(list_idx, total + 1);

  // last_clar is actually count
  // count == 0, show all matching in descending order
  // count < 0, descending order
  // count > 0, ascending order
  if (!(count = last_clar)) {
    count = total;
  } else if (count < 0) {
    count = -count;
  }
  if (total > 0) {
    if (last_clar > 0) {
      for (i = first_clar; i < total && list_tot < count; ++i) {
        if (match_clar(cs, i, mode_clar)) {
          list_idx[list_tot++] = i;
        }
      }
    } else {
      for (i = first_clar; i >= 0 && list_tot < count; --i) {
        if (match_clar(cs, i, mode_clar)) {
          list_idx[list_tot++] = i;
        }
      }
    }
  }

  fprintf(f, "<p><big>%s: %d, %s: %d</big></p>\n", _("Total messages"), total,
          _("Shown"), list_tot);

  if (u->prev_first_clar != -1) {
    snprintf(first_clar_buf, sizeof(first_clar_buf), "%d", u->prev_first_clar);
  }
  if (u->prev_last_clar != -10) {
    snprintf(last_clar_buf, sizeof(last_clar_buf), "%d", u->prev_last_clar);
  }

  fprintf(f, "<p>");
  html_start_form(f, 0, phr->self_url, phr->hidden_vars);
  fprintf(f, "<select name=\"%s\">", "filter_mode_clar");
  max_mode_clar = CLAR_FILTER_NONE;
  if (phr->role != USER_ROLE_ADMIN) max_mode_clar = CLAR_FILTER_NONE - 1;
  for (int j = 1; j <= max_mode_clar; ++j) {
    s = "";
    if (mode_clar == j) s = " selected=\"selected\"";
    fprintf(f, "<option value=\"%d\"%s>%s</option>", j, s, gettext(clar_filter_options[j]));
  }
  fprintf(f, "</select>\n");
  fprintf(f, "%s: <input type=\"text\" name=\"filter_first_clar\" size=\"16\" value=\"%s\"/>", _("First clar"), first_clar_buf);
  fprintf(f, "%s: <input type=\"text\" name=\"filter_last_clar\" size=\"16\" value=\"%s\"/>", _("Last clar"), last_clar_buf);
  fprintf(f, "%s",
          ns_submit_button(bbuf, sizeof(bbuf), "filter_view_clars",
                           1, _("View")));
  fprintf(f, "%s",
          ns_submit_button(bbuf, sizeof(bbuf), 0,
                           NEW_SRV_ACTION_RESET_CLAR_FILTER, 0));
  fprintf(f, "</p></form><br/>\n");

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

    if (clar_get_record(cs->clarlog_state, i, &clar) < 0) continue;

    clar_subj = clar_get_subject(cs->clarlog_state, i);
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
      else {
        judge_name = teamdb_get_name_2(cs->teamdb_state, clar.j_from);
        if (!judge_name) {
          fprintf(f, "<td%s><b>%s</b> (invalid id %d)</td>", cl, _("judges"),
                  clar.j_from);
        } else {
          fprintf(f, "<td%s><b>%s</b> (%s)</td>", cl, _("judges"),
                  ARMOR(judge_name));
        }
      }
    } else {
      fprintf(f, "<td%s>%s</td>", cl,
              ARMOR(teamdb_get_name_2(cs->teamdb_state, clar.from)));
    }
    if (!clar.to && !clar.from) {
      fprintf(f, "<td%s><b>%s</b></td>", cl, _("all"));
    } else if (!clar.to) {
      fprintf(f, "<td%s><b>%s</b></td>", cl, _("judges"));
    } else {
      fprintf(f, "<td%s>%s</td>", cl,
              ARMOR(teamdb_get_name_2(cs->teamdb_state, clar.to)));
    }
    fprintf(f, "<td%s>%s</td>", cl, ARMOR(clar_subj));
    fprintf(f, "<td%s>", cl);
    if (clar.run_id > 0) {
      fprintf(f, "<a href=\"%s\">", ns_url(bbuf, sizeof(bbuf), phr, NEW_SRV_ACTION_VIEW_SOURCE, "run_id=%d", clar.run_id - 1));
    } else {
      fprintf(f, "<a href=\"%s\">", ns_url(bbuf, sizeof(bbuf), phr, NEW_SRV_ACTION_VIEW_CLAR, "clar_id=%d", i));
    }
    fprintf(f, "%s</a></td>", _("View"));
    fprintf(f, "</tr>\n");
  }
  fputs("</table>\n", f);

  html_armor_free(&ab);
  xfree(list_idx);
}

// 0 - undefined or empty, -1 - invalid, 1 - ok
static int
parse_user_field(
        const serve_state_t cs,
        struct http_request_info *phr,
        const unsigned char *name,
        int all_enabled,
        int judges_enabled,
        int *p_user_id)
{
  const unsigned char *s = NULL;
  unsigned char *str = NULL;
  int r = hr_cgi_param(phr, name, &s);
  char *eptr = NULL;
  int user_id = 0;

  if (r <= 0) return r;
  if (is_empty_string(s)) return 0;
  str = text_input_process_string(s, 0, 0);
  if (!str || !*str) {
    xfree(str);
    return 0;
  }
  if (str[0] == '#') {
    if (!str[1]) goto fail;
    str[0] = ' ';
    errno = 0;
    user_id = strtol(str, &eptr, 10);
    if (errno || *eptr) goto fail;
    if (!teamdb_lookup(cs->teamdb_state, user_id)) goto fail;
    goto done;
  }
  if (!strcasecmp(str, "all")) {
    if (!all_enabled) goto fail;
    user_id = 0;
    goto done;
  }
  if (!strcasecmp(str, "judges")) {
    if (!judges_enabled) goto fail;
    user_id = 0;
    goto done;
  }
  if ((user_id = teamdb_lookup_login(cs->teamdb_state, str)) > 0) goto done;
  errno = 0;
  user_id = strtol(str, &eptr, 10);
  if (errno || *eptr) goto fail;
  if (!teamdb_lookup(cs->teamdb_state, user_id)) goto fail;

done:
  *p_user_id = user_id;
  xfree(str);
  return 1;

fail:
  xfree(str);
  return -1;
}

#define FAIL(c) do { retval = -(c); goto cleanup; } while (0)

int
ns_priv_edit_clar_action(
        FILE *out_f,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  int retval = 0, r;
  int clar_id = -1;
  struct clar_entry_v2 clar, new_clar;
  const unsigned char *s = NULL;
  int new_from = 0, new_to = 0, new_j_from = 0, new_flags = 0;
  int new_hide_flag = 0, new_appeal_flag = 0, new_ssl_flag = 0;
  int new_locale_id = 0, new_in_reply_to = -1, new_run_id = -1;
  int new_size = 0;
  ej_ip_t new_ip;
  unsigned char *new_charset = NULL;
  unsigned char *new_subject = NULL;
  unsigned char *new_text = NULL;
  unsigned char *old_text = NULL;
  size_t old_size = 0;
  int mask = 0;

  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0) {
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  }

  if (hr_cgi_param_int(phr, "clar_id", &clar_id) < 0
      || clar_id < 0 || clar_id >= clar_get_total(cs->clarlog_state)
      || clar_get_record(cs->clarlog_state, clar_id, &clar) < 0
      || clar.id < 0) {
    FAIL(NEW_SRV_ERR_INV_CLAR_ID);
  }

  if (hr_cgi_param(phr, "cancel", &s) > 0 && *s) goto cleanup;
  s = NULL;
  if (hr_cgi_param(phr, "save", &s) <= 0 || !*s) goto cleanup;

  if (parse_user_field(cs, phr, "from", 0, 1, &new_from) <= 0) {
    fprintf(log_f, "invalid 'from' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (parse_user_field(cs, phr, "to", (new_from == 0), (new_from > 0), &new_to) <= 0) {
    fprintf(log_f, "invalid 'to' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (!new_from) {
    r = parse_user_field(cs, phr, "j_from", 0, 0, &new_j_from);
    if (r < 0) {
      fprintf(log_f, "invalid 'j_from' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    if (!r || new_j_from <= 0) new_j_from = 0;
  }
  if (hr_cgi_param_int(phr, "flags", &new_flags) < 0 || new_flags < 0 || new_flags > 2) {
    fprintf(log_f, "invalid 'flags' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (hr_cgi_param(phr, "hide_flag", &s) > 0) new_hide_flag = 1;
  if (hr_cgi_param(phr, "appeal_flag", &s) > 0) new_appeal_flag = 1;
  if (hr_cgi_param(phr, "ssl_flag", &s) > 0) new_ssl_flag = 1;
  if ((r = hr_cgi_param(phr, "ip", &s)) < 0) {
    fprintf(log_f, "invalid 'ip' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (!r || !s || !*s) s = "127.0.0.1";
  if (xml_parse_ipv6(NULL, 0, 0, 0, s, &new_ip) < 0) {
    fprintf(log_f, "invalid 'ip' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (hr_cgi_param_int_opt(phr, "locale_id", &new_locale_id, 0) < 0) {
    fprintf(log_f, "invalid 'locale_id' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  // FIXME: check for valid locales better
  if (new_locale_id != 0 && new_locale_id != 1) {
    fprintf(log_f, "invalid 'locale_id' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (hr_cgi_param_int_opt(phr, "in_reply_to", &new_in_reply_to, -1) < 0) {
    fprintf(log_f, "invalid 'in_reply_to' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (new_in_reply_to < -1 || new_in_reply_to >= clar_get_total(cs->clarlog_state)) {
    fprintf(log_f, "invalid 'in_reply_to' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  ++new_in_reply_to;
  if (hr_cgi_param_int_opt(phr, "run_id", &new_run_id, -1) < 0) {
    fprintf(log_f, "invalid 'run_id' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (new_run_id < -1 || new_run_id >= run_get_total(cs->runlog_state)) {
    fprintf(log_f, "invalid 'run_id' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  ++new_run_id;

  s = NULL;
  if ((r = hr_cgi_param(phr, "charset", &s)) < 0) {
    fprintf(log_f, "invalid 'charset' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (!r || !s) s = "";
  new_charset = text_input_process_string(s, 0, 0);
  // FIXME: validate charset
  xfree(new_charset);
  new_charset = xstrdup(EJUDGE_CHARSET);

  s = NULL;
  if ((r = hr_cgi_param(phr, "subject", &s)) < 0) {
    fprintf(log_f, "invalid 'subject' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (!r || !s) s = "";
  new_subject = text_input_process_string(s, 0, 0);

  s = NULL;
  if ((r = hr_cgi_param(phr, "text", &s)) < 0) {
    fprintf(log_f, "invalid 'text' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (!r || !s) s = "";
  new_text = text_area_process_string(s, 0, 0);
  new_size = strlen(new_text);

  if (clar_get_text(cs->clarlog_state, clar_id, &old_text, &old_size) < 0
      || new_size != old_size || strcmp(new_text, old_text) != 0) {
    if (clar_modify_text(cs->clarlog_state, clar_id, new_text, new_size) < 0) {
      FAIL(NEW_SRV_ERR_DATABASE_FAILED);
    }
  }

  // **from, **to, **j_from, **flags, **hide_flag, **appeal_flag, **ip, **ssl_flag
  // **locale_id, **in_reply_to, **run_id, **charset, **subject, *text

  memset(&new_clar, 0, sizeof(new_clar));
  if (clar.from != new_from) {
    new_clar.from = new_from;
    mask |= 1 << CLAR_FIELD_FROM;
  }
  if (clar.to != new_to) {
    new_clar.to = new_to;
    mask |= 1 << CLAR_FIELD_TO;
  }
  if (clar.j_from != new_j_from) {
    new_clar.j_from = new_j_from;
    mask |= 1 << CLAR_FIELD_J_FROM;
  }
  if (clar.flags != new_flags) {
    new_clar.flags = new_flags;
    mask |= 1 << CLAR_FIELD_FLAGS;
  }
  if (clar.hide_flag != new_hide_flag) {
    new_clar.hide_flag = new_hide_flag;
    mask |= 1 << CLAR_FIELD_HIDE_FLAG;
  }
  if (clar.appeal_flag != new_appeal_flag) {
    new_clar.appeal_flag = new_appeal_flag;
    mask |= 1 << CLAR_FIELD_APPEAL_FLAG;
  }
  // FIXME: do better
  ej_ip_t ipv6;
  clar_entry_to_ipv6(&clar, &ipv6);
  if (ipv6cmp(&ipv6, &new_ip) != 0) {
    ipv6_to_clar_entry(&new_ip, &new_clar);
    mask |= 1 << CLAR_FIELD_IP;
  }
  if (clar.ssl_flag != new_ssl_flag) {
    new_clar.ssl_flag = new_ssl_flag;
    mask |= 1 << CLAR_FIELD_SSL_FLAG;
  }
  if (clar.locale_id != new_locale_id) {
    new_clar.locale_id = new_locale_id;
    mask |= 1 << CLAR_FIELD_LOCALE_ID;
  }
  if (clar.in_reply_to != new_in_reply_to) {
    new_clar.in_reply_to = new_in_reply_to;
    mask |= 1 << CLAR_FIELD_IN_REPLY_TO;
  }
  if (clar.run_id != new_run_id) {
    new_clar.run_id = new_run_id;
    mask |= 1 << CLAR_FIELD_RUN_ID;
  }
  if (clar.size != new_size) {
    new_clar.size = new_size;
    mask |= 1 << CLAR_FIELD_SIZE;
  }
  if (strcmp(clar.charset, new_charset) != 0) {
    snprintf(new_clar.charset, sizeof(new_clar.charset), "%s", new_charset);
    mask |= 1 << CLAR_FIELD_CHARSET;
  }
  if (strcmp(clar.subj, new_subject) != 0) {
    snprintf(new_clar.subj, sizeof(new_clar.subj), "%s", new_subject);
    mask |= 1 << CLAR_FIELD_SUBJECT;
  }
  if (mask <= 0) goto cleanup;

  if (clar_modify_record(cs->clarlog_state, clar_id, mask, &new_clar) < 0) {
    FAIL(NEW_SRV_ERR_DATABASE_FAILED);
  }

cleanup:
  xfree(old_text);
  xfree(new_charset);
  xfree(new_subject);
  xfree(new_text);
  return retval;
}

int
ns_priv_edit_run_action(
        FILE *out_f,
        FILE *log_f,
        struct http_request_info *phr,
        const struct contest_desc *cnts,
        struct contest_extra *extra)
{
  serve_state_t cs = extra->serve_state;
  const struct section_global_data *global = cs->global;
  int retval = 0, r;
  int run_id = -1;
  struct run_entry info, new_info;
  const unsigned char *s = NULL;
  int mask = 0;
  int new_is_readonly = 0, value = 0;
  ej_ip_t new_ip;
  ruint32_t new_sha1[5];
  time_t start_time = 0;
  int need_rejudge = 0;

  memset(&new_info, 0, sizeof(new_info));

  if (opcaps_check(phr->caps, OPCAP_EDIT_RUN) < 0) {
    FAIL(NEW_SRV_ERR_PERMISSION_DENIED);
  }

  if (hr_cgi_param_int(phr, "run_id", &run_id) < 0
      || run_id < 0 || run_id >= run_get_total(cs->runlog_state)) {
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  }
  if (run_get_entry(cs->runlog_state, run_id, &info) < 0) {
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  }
  if (info.status < 0 || info.status > RUN_MAX_STATUS) {
    FAIL(NEW_SRV_ERR_INV_RUN_ID);
  }

  if (hr_cgi_param(phr, "cancel", &s) > 0 && *s) goto cleanup;
  s = NULL;
  if (hr_cgi_param(phr, "save", &s) <= 0 || !*s) goto cleanup;
  s = NULL;

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, info.user_id);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
  }
  if (start_time < 0) start_time = 0;

  // FIXME: handle special "recheck file attributes" option

  if (hr_cgi_param(phr, "is_readonly", &s) > 0) new_is_readonly = 1;
  if (info.is_readonly > 0 && new_is_readonly) goto cleanup;
  if (info.is_readonly > 0 && !new_is_readonly) {
    new_info.is_readonly = 0;
    mask |= RE_IS_READONLY;
    if (run_set_entry(cs->runlog_state, run_id, mask, &new_info) < 0)
      FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);
    goto cleanup;
  }
  if (info.is_readonly != new_is_readonly) {
    new_info.is_readonly = new_is_readonly;
    mask |= RE_IS_READONLY;
  }

  if (parse_user_field(cs, phr, "user", 0, 0, &value) <= 0) {
    fprintf(log_f, "invalid 'user' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (info.user_id != value) {
    new_info.user_id = value;
    mask |= RE_USER_ID;
  }

  value = -1;
  if (hr_cgi_param_int(phr, "prob", &value) < 0 || value <= 0) {
    fprintf(log_f, "invalid 'prob' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (info.prob_id != value) {
    if (value > cs->max_prob || !cs->probs[value]) {
      fprintf(log_f, "invalid 'prob' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);    
    }
    new_info.prob_id = value;
    mask |= RE_PROB_ID;
  } else {
    new_info.prob_id = info.prob_id;
  }

  const struct section_problem_data *prob = NULL;
  if (new_info.prob_id > 0 && new_info.prob_id <= cs->max_prob) {
    prob = cs->probs[new_info.prob_id];
  }
  if (prob && prob->variant_num > 0) {
    value = -1;
    if (hr_cgi_param_int(phr, "variant", &value) < 0 || value < 0) {
      /*
      fprintf(log_f, "invalid 'variant' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
      */
      if (info.variant > 0) {
        new_info.variant = 0;
        mask |= RE_VARIANT;
      }
    } else {
      if (info.variant != value) {
        if (value > prob->variant_num) {
          fprintf(log_f, "invalid 'variant' field value\n");
          FAIL(NEW_SRV_ERR_INV_PARAM);
        }
        new_info.variant = value;
        mask |= RE_VARIANT;
      }
    }
  }

  value = -1;
  if (hr_cgi_param_int(phr, "lang", &value) < 0 || value < 0) {
    fprintf(log_f, "invalid 'lang' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (info.lang_id != value) {
    if (prob && prob->type == PROB_TYPE_STANDARD) {
      if (value <= 0 || value > cs->max_lang || !cs->langs[value]) {
        fprintf(log_f, "invalid 'lang' field value\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);    
      }
    } else if (prob) {
      if (value != 0) {
        fprintf(log_f, "invalid 'lang' field value\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);    
      }
    }
    new_info.lang_id = value;
    mask |= RE_LANG_ID;
  } else {
    new_info.lang_id = info.lang_id;
  }

  value = -1;
  if (hr_cgi_param_int(phr, "eoln_type", &value) < 0
      || value < 0 || value > EOLN_CRLF) {
    fprintf(log_f, "invalid 'eoln_type' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (info.eoln_type != value) {
    new_info.eoln_type = value;
    mask |= RE_EOLN_TYPE;
  } else {
    new_info.eoln_type = info.eoln_type;
  }

  const struct section_language_data *lang = NULL;
  if (new_info.lang_id > 0 && new_info.lang_id <= cs->max_lang) {
    lang = cs->langs[new_info.lang_id];
  }
  (void) lang;

  value = -1;
  if (hr_cgi_param_int(phr, "status", &value) < 0 || value < 0) {
    fprintf(log_f, "invalid 'status' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (value == RUN_REJUDGE || value == RUN_FULL_REJUDGE) {
    need_rejudge = value;
    value = info.status;
  }
  if (info.status != value) {
    // FIXME: handle rejudge request
    if (value > RUN_MAX_STATUS) {
      fprintf(log_f, "invalid 'status' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);    
    }
    new_info.status = value;
    mask |= RE_STATUS;
  } else {
    new_info.status = info.status;
  }

  value = -1;
  if (hr_cgi_param_int_opt(phr, "test", &value, -1) < 0) {
    fprintf(log_f, "invalid 'test' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (info.test != value || info.passed_mode <= 0) {
    new_info.test = value;
    new_info.passed_mode = 1;
    mask |= RE_TEST | RE_PASSED_MODE;
  }
  /*
  if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD) {
    ++value;
  }
  if (info._test != value) {
    if (value < 0 || value > 100000) {
      fprintf(log_f, "invalid 'test' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    switch (new_info.status) {
    case RUN_OK:
      if (global->score_system == SCORE_ACM || global->score_system == SCORE_MOSCOW) {
        value = 0;
      }
      break;

    case RUN_COMPILE_ERR:
    case RUN_CHECK_FAILED:
    case RUN_ACCEPTED:
    case RUN_PENDING_REVIEW:
    case RUN_IGNORED:
    case RUN_DISQUALIFIED:
    case RUN_PENDING:
    case RUN_STYLE_ERR:
    case RUN_REJECTED:
      value = 0;
      break;

    case RUN_RUN_TIME_ERR:
    case RUN_TIME_LIMIT_ERR:
    case RUN_WALL_TIME_LIMIT_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_PARTIAL:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
    case RUN_SYNC_ERR:
      if (!value) {
        fprintf(log_f, "invalid 'test' field value\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);
      }
      break;
    }
    new_info._test = value;
    mask |= RE_TEST;
  }
  */

  if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD
      || global->score_system == SCORE_MOSCOW) {
    value = -1;
    if (hr_cgi_param_int_opt(phr, "score", &value, -1) < 0) {
      fprintf(log_f, "invalid 'score' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    if (info.score != value) {
      if (!prob) {
        fprintf(log_f, "invalid 'prob' field value\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);
      }
      if (value < 0 || value > 100000) {
        fprintf(log_f, "invalid 'score' field value\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);
      }
      switch (new_info.status) {
      case RUN_OK:
        if (prob->variable_full_score > 0) {
          if (value < 0 || value > prob->full_score) {
            fprintf(log_f, "invalid 'score' field value\n");
            FAIL(NEW_SRV_ERR_INV_PARAM);
          }
        } else {
          value = prob->full_score;
        }
        break;

      case RUN_COMPILE_ERR:
      case RUN_CHECK_FAILED:
      case RUN_ACCEPTED:
      case RUN_PENDING_REVIEW:
      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
      case RUN_PENDING:
      case RUN_STYLE_ERR:
      case RUN_REJECTED:
        value = 0;
        break;

      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_PARTIAL:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_SYNC_ERR:
        if (value < 0 || value > prob->full_score) {
          fprintf(log_f, "invalid 'score' field value\n");
          FAIL(NEW_SRV_ERR_INV_PARAM);
        }
        break;
      }
      new_info.score = value;
      mask |= RE_SCORE;
    }

    value = -100000;
    if (hr_cgi_param_int_opt(phr, "score_adj", &value, -100000) < 0) {
      fprintf(log_f, "invalid 'score_adj' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    if (value > -100000 && info.score_adj != value) {
      if (value <= -100000 || value >= 100000) {
        fprintf(log_f, "invalid 'score_adj' field value\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);
      }
      new_info.score_adj = value;
      mask |= RE_SCORE_ADJ;
    }
  }

  value = 0;
  if (hr_cgi_param(phr, "is_marked", &s) > 0) value = 1;
  if (info.is_marked != value) {
    new_info.is_marked = value;
    mask |= RE_IS_MARKED;
  }

  if (prob && prob->enable_tokens > 0) {
    value = -1;
    if (hr_cgi_param_int_opt(phr, "token_flags", &value, 0) < 0 || value < 0 || value > 255) {
      fprintf(log_f, "invalid 'token_flags' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    new_info.token_flags = value;
    mask |= RE_TOKEN_FLAGS;

    value = -1;
    if (hr_cgi_param_int_opt(phr, "token_count", &value, 0) < 0 || value < 0 || value > 255) {
      fprintf(log_f, "invalid 'token_count' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    new_info.token_count = value;
    mask |= RE_TOKEN_COUNT;
  }

  if (global->separate_user_score > 0) {
    value = 0;
    if (hr_cgi_param(phr, "is_saved", &s) > 0) value = 1;
    if (info.is_saved != value) {
      new_info.is_saved = value;
      mask |= RE_IS_SAVED;
      if (!value) {
        new_info.saved_status = 0;
        new_info.saved_test = 0;
        new_info.saved_score = 0;
        mask |= RE_SAVED_STATUS | RE_SAVED_TEST | RE_SAVED_SCORE;
      }
    } else {
      new_info.is_saved = info.is_saved;
    }
    if (new_info.is_saved) {
      value = -1;
      if (hr_cgi_param_int(phr, "saved_status", &value) < 0 || value < 0) {
        fprintf(log_f, "invalid 'saved_status' field value\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);    
      }
      if (info.saved_status != value || !info.is_saved) {
        if (value > RUN_MAX_STATUS) {
          fprintf(log_f, "invalid 'saved_status' field value\n");
          FAIL(NEW_SRV_ERR_INV_PARAM);
        }
        new_info.saved_status = value;
        mask |= RE_SAVED_STATUS;
      } else {
        new_info.saved_status = info.saved_status;
      }

      value = -1;
      if (hr_cgi_param_int_opt(phr, "saved_test", &value, -1) < 0) {
        fprintf(log_f, "invalid 'saved_test' field value\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);
      }
      if (info.saved_test != value || !info.is_saved) {
        if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD) {
          ++value;
        }
        if (value < 0 || value > 100000) {
          fprintf(log_f, "invalid 'saved_test' field value\n");
          FAIL(NEW_SRV_ERR_INV_PARAM);
        }
        switch (new_info.saved_status) {
        case RUN_OK:
        case RUN_COMPILE_ERR:
        case RUN_CHECK_FAILED:
        case RUN_ACCEPTED:
        case RUN_PENDING_REVIEW:
        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
        case RUN_PENDING:
        case RUN_STYLE_ERR:
        case RUN_REJECTED:
          value = 0;
          break;

        case RUN_RUN_TIME_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_WALL_TIME_LIMIT_ERR:
        case RUN_PRESENTATION_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_PARTIAL:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
        case RUN_SYNC_ERR:
          if (!value) {
            fprintf(log_f, "invalid 'saved_test' field value\n");
            FAIL(NEW_SRV_ERR_INV_PARAM);
          }
          break;
        }
        new_info.saved_test = value;
        mask |= RE_SAVED_TEST;
      }

      if (global->score_system == SCORE_KIROV || global->score_system == SCORE_OLYMPIAD
          || global->score_system == SCORE_MOSCOW) {
        value = -1;
        if (hr_cgi_param_int_opt(phr, "saved_score", &value, -1) < 0) {
          fprintf(log_f, "invalid 'saved_score' field value\n");
          FAIL(NEW_SRV_ERR_INV_PARAM);
        }
        if (info.saved_score != value || !info.is_saved) {
          if (!prob) {
            fprintf(log_f, "invalid 'prob' field value\n");
            FAIL(NEW_SRV_ERR_INV_PARAM);
          }
          if (value < 0 || value > 100000) {
            fprintf(log_f, "invalid 'saved_score' field value\n");
            FAIL(NEW_SRV_ERR_INV_PARAM);
          }
          switch (new_info.saved_status) {
          case RUN_OK:
            if (prob->variable_full_score > 0) {
              if (value < 0 || value > prob->full_user_score) {
                fprintf(log_f, "invalid 'saved_score' field value\n");
                FAIL(NEW_SRV_ERR_INV_PARAM);
              }
            } else {
              value = prob->full_user_score;
            }
            break;

          case RUN_COMPILE_ERR:
          case RUN_CHECK_FAILED:
          case RUN_ACCEPTED:
          case RUN_PENDING_REVIEW:
          case RUN_IGNORED:
          case RUN_DISQUALIFIED:
          case RUN_PENDING:
          case RUN_STYLE_ERR:
          case RUN_REJECTED:
            value = 0;
            break;

          case RUN_RUN_TIME_ERR:
          case RUN_TIME_LIMIT_ERR:
          case RUN_WALL_TIME_LIMIT_ERR:
          case RUN_PRESENTATION_ERR:
          case RUN_WRONG_ANSWER_ERR:
          case RUN_PARTIAL:
          case RUN_MEM_LIMIT_ERR:
          case RUN_SECURITY_ERR:
          case RUN_SYNC_ERR:
            if (value < 0 || value > prob->full_user_score) {
              fprintf(log_f, "invalid 'saved_score' field value\n");
              FAIL(NEW_SRV_ERR_INV_PARAM);
            }
            break;
          }
          new_info.saved_score = value;
          mask |= RE_SAVED_SCORE;
        }
      }
    }
  }

  s = NULL;
  if ((r = hr_cgi_param(phr, "ip", &s)) < 0) {
    fprintf(log_f, "invalid 'ip' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (!r || !s || !*s) s = "127.0.0.1";
  if (xml_parse_ipv6(NULL, 0, 0, 0, s, &new_ip) < 0) {
    fprintf(log_f, "invalid 'ip' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  ej_ip_t ipv6;
  run_entry_to_ipv6(&info, &ipv6);
  if (ipv6cmp(&new_ip, &ipv6) != 0) {
    ipv6_to_run_entry(&new_ip, &new_info);
    mask |= RE_IP;
  }
  value = 0;
  if (hr_cgi_param(phr, "ssl_flag", &s) > 0) value = 1;
  if (info.ssl_flag != value) {
    new_info.ssl_flag = value;
    mask |= RE_SSL_FLAG;
  }

  value = -1;
  if (hr_cgi_param_int(phr, "size", &value) < 0 || value < 0) {
    fprintf(log_f, "invalid 'size' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (info.size != value) {
    if (value >= (1 * 1024 * 1024 * 1024)) {
      fprintf(log_f, "invalid 'size' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);    
    }
    new_info.size = value;
    mask |= RE_SIZE;
  }

  s = NULL;
  if ((r = hr_cgi_param(phr, "sha1", &s)) < 0) {
    fprintf(log_f, "invalid 'sha1' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (r > 0 && s && *s) {
    memset(new_sha1, 0, sizeof(new_sha1));
    if ((r = parse_sha1(new_sha1, s)) < 0) {
      fprintf(log_f, "invalid 'sha1' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);    
    }
    if (r > 0 && memcmp(info.sha1, new_sha1, sizeof(info.sha1)) != 0) {
      memcpy(new_info.sha1, new_sha1, sizeof(new_info.sha1));
      mask |= RE_SHA1;
    }
  }

#if CONF_HAS_LIBUUID - 0 != 0
  s = NULL;
  if ((r = hr_cgi_param(phr, "uuid", &s)) < 0) {
    fprintf(log_f, "invalid 'uuid' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);    
  }
  if (r > 0 && s && *s) {
    ej_uuid_t new_uuid;
    if (ej_uuid_parse(s, &new_uuid) < 0) {
      fprintf(log_f, "invalid 'uuid' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);    
    }
    if (memcmp(&info.run_uuid, &new_uuid, sizeof(info.run_uuid)) != 0) {
      memcpy(&new_info.run_uuid, &new_uuid, sizeof(new_info.run_uuid));
      mask |= RE_RUN_UUID;
    }
  } else if (r > 0) {
    if (info.run_uuid.v[0] || info.run_uuid.v[1] || info.run_uuid.v[2] || info.run_uuid.v[3]) {
      new_info.run_uuid.v[0] = 0;
      new_info.run_uuid.v[1] = 0;
      new_info.run_uuid.v[2] = 0;
      new_info.run_uuid.v[3] = 0;
      mask |= RE_RUN_UUID;
    }
  }
#endif

  if (new_info.lang_id == 0) {
    s = NULL;
    if ((r = hr_cgi_param(phr, "mime_type", &s)) < 0) {
      fprintf(log_f, "invalid 'mime_type' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);    
    }
    if (r > 0 && s && *s) {
      if ((value = mime_type_parse(s)) < 0) {
        fprintf(log_f, "invalid 'mime_type' field value\n");
        FAIL(NEW_SRV_ERR_INV_PARAM);    
      }
      if (info.mime_type != value) {
        new_info.mime_type = value;
        mask |= RE_MIME_TYPE;
      }
    }
  }

  value = 0;
  if (hr_cgi_param(phr, "is_hidden", &s) > 0) value = 1;
  if (info.is_hidden != value) {
    if (!value && info.time < start_time) {
      fprintf(log_f, "is_hidden flag cannot be cleared because time < start_time");
      FAIL(NEW_SRV_ERR_INV_PARAM);    
    }
    new_info.is_hidden = value;
    mask |= RE_IS_HIDDEN;
  }

  value = 0;
  if (hr_cgi_param(phr, "is_imported", &s) > 0) value = 1;
  if (info.is_imported != value) {
    // check availability of operation
    new_info.is_imported = value;
    mask |= RE_IS_IMPORTED;
  }

  value = -1;
  if (hr_cgi_param_int_opt(phr, "locale_id", &value, -1) < 0) {
    fprintf(log_f, "invalid 'locale_id' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (value >= 0 && info.locale_id != value) {
    if (value != 0 && value != 1) {
      fprintf(log_f, "invalid 'locale_id' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    new_info.locale_id = value;
    mask |= RE_LOCALE_ID;
  }

  value = -1;
  if (hr_cgi_param_int_opt(phr, "pages", &value, -1) < 0) {
    fprintf(log_f, "invalid 'pages' field value\n");
    FAIL(NEW_SRV_ERR_INV_PARAM);
  }
  if (value >= 0 && info.pages != value) {
    if (value > 100000) {
      fprintf(log_f, "invalid 'pages' field value\n");
      FAIL(NEW_SRV_ERR_INV_PARAM);
    }
    new_info.pages = value;
    mask |= RE_PAGES;
  }

  if (!mask) goto cleanup;
  if (run_set_entry(cs->runlog_state, run_id, mask, &new_info) < 0)
    FAIL(NEW_SRV_ERR_RUNLOG_UPDATE_FAILED);

  serve_audit_log(cs, run_id, &info, phr->user_id, &phr->ip, phr->ssl_flag,
                  "edit-run", "ok", -1,
                  "  mask: 0x%08x", mask);

  if (need_rejudge > 0) {
    serve_rejudge_run(ejudge_config, cnts, cs, run_id, phr->user_id, &phr->ip, phr->ssl_flag,
                      (need_rejudge == RUN_FULL_REJUDGE),
                      DFLT_G_REJUDGE_PRIORITY_ADJUSTMENT);
  }

cleanup:;
  return retval;
}

static void
write_from_contest_dir(
        FILE *log_f,
        FILE *fout,
        int flag1,
        int flag2,
        int test_num,
        int variant,
        const struct section_global_data *global,
        const struct section_problem_data *prb,
        const unsigned char *entry,
        const unsigned char *dir,
        const unsigned char *suffix,
        const unsigned char *pattern,
        int has_digest,
        const unsigned char *digest_ptr)
{
  path_t path1;
  path_t path2;
  path_t path3;
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

  if (global->advanced_layout > 0) {
    get_advanced_layout_path(path3, sizeof(path3), global, prb, entry,variant);
    snprintf(path1, sizeof(path1), "%s/%s", path3, path2);
  } else {
    if (variant > 0) {
      snprintf(path1, sizeof(path1), "%s-%d/%s", dir, variant, path2);
    } else {
      snprintf(path1, sizeof(path1), "%s/%s", dir, path2);
    }
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
write_from_archive(
        const serve_state_t cs,
        FILE *log_f,
        FILE *fout,
        int flag,
        int test_num,
        const struct run_entry *re,
        const unsigned char *suffix)
{
  full_archive_t far = 0;
  unsigned char fnbuf[64];
  int rep_flag = 0, arch_flags = 0;
  path_t arch_path;
  long arch_raw_size = 0;
  unsigned char *text = 0;

  if (!flag) {
    ns_error(log_f, NEW_SRV_ERR_TEST_UNAVAILABLE);
    goto done;
  }

  snprintf(fnbuf, sizeof(fnbuf), "%06d%s", test_num, suffix);

  rep_flag = serve_make_full_report_read_path(cs, arch_path, sizeof(arch_path), re);
  if (rep_flag < 0 || !(far = full_archive_open_read(arch_path))) {
    ns_error(log_f, NEW_SRV_ERR_TEST_NONEXISTANT);
    goto done;
  }

  rep_flag = full_archive_find_file(far, fnbuf, &arch_raw_size,
                                    &arch_flags, &text);
  if (rep_flag <= 0) {
    ns_error(log_f, NEW_SRV_ERR_TEST_NONEXISTANT);
    goto done;
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

  if ((rep_flag = serve_make_xml_report_read_path(cs, rep_path, sizeof(rep_path), &re)) < 0
      && (rep_flag = serve_make_report_read_path(cs, rep_path, sizeof(rep_path), &re)) < 0) {
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

  /*
  if (prb->type > 0) {
    ns_error(log_f, NEW_SRV_ERR_TEST_UNAVAILABLE);
    goto done;
  }
  */
  if (prb->type != PROB_TYPE_STANDARD && prb->type != PROB_TYPE_OUTPUT_ONLY) {
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
                           cs->global, prb, DFLT_P_TEST_DIR,
                           prb->test_dir, prb->test_sfx, prb->test_pat,
                           t->has_input_digest, t->input_digest);
    goto done;
  case NEW_SRV_ACTION_VIEW_TEST_ANSWER:
    write_from_contest_dir(log_f, fout, prb->use_corr, r->correct_available,
                           test_num, r->variant,
                           cs->global, prb, DFLT_P_CORR_DIR,
                           prb->corr_dir, prb->corr_sfx, prb->corr_pat,
                           t->has_correct_digest, t->correct_digest);
    goto done;
  case NEW_SRV_ACTION_VIEW_TEST_INFO:
    write_from_contest_dir(log_f, fout, prb->use_info, r->info_available,
                           test_num, r->variant,
                           cs->global, prb, DFLT_P_INFO_DIR,
                           prb->info_dir, prb->info_sfx, prb->info_pat,
                           t->has_info_digest, t->info_digest);
    goto done;

  case NEW_SRV_ACTION_VIEW_TEST_OUTPUT:
    write_from_archive(cs, log_f, fout, t->output_available, test_num, &re, ".o");
    goto done;

  case NEW_SRV_ACTION_VIEW_TEST_ERROR:
    write_from_archive(cs, log_f, fout, t->stderr_available, test_num, &re, ".e");
    goto done;

  case NEW_SRV_ACTION_VIEW_TEST_CHECKER:
    write_from_archive(cs, log_f, fout, t->checker_output_available, test_num, &re, ".c");
    goto done;
  }

 done:
  xfree(rep_text);
  testing_report_free(r);
}

static void
stand_parse_error_func(void *data, unsigned char const *format, ...)
{
  va_list args;
  unsigned char buf[1024];
  int l;
  struct serve_state *state = (struct serve_state*) data;

  va_start(args, format);
  l = vsnprintf(buf, sizeof(buf) - 24, format, args);
  va_end(args);
  strcpy(buf + l, "\n");
  state->cur_user->stand_error_msgs = xstrmerge1(state->cur_user->stand_error_msgs, buf);
  filter_expr_nerrs++;
}

#define READ_PARAM(name) do { \
  if (hr_cgi_param(phr, #name, &s) <= 0 || !s) return; \
  len = strlen(s); \
  if (len > 128 * 1024) return; \
  name = (unsigned char*) alloca(len + 1); \
  strcpy(name, s); \
  while (isspace(*name)) name++; \
  len = strlen(name); \
  while (len > 0 && isspace(name[len - 1])) len--; \
  name[len] = 0; \
  } while (0)

#define IS_EQUAL(name) ((((!u->name || !*u->name) && !*name) || (u->name && !strcmp(u->name, name))))

void
ns_set_stand_filter(
        const serve_state_t state,
        struct http_request_info *phr)
{
  const unsigned char *s = 0;
  int len, r;
  unsigned char *stand_user_expr = 0;
  unsigned char *stand_prob_expr = 0;
  unsigned char *stand_run_expr = 0;
  struct user_filter_info *u = 0;

  u = user_filter_info_allocate(state, phr->user_id, phr->session_id);
  if (!u) return;

  READ_PARAM(stand_user_expr);
  READ_PARAM(stand_prob_expr);
  READ_PARAM(stand_run_expr);

  if (!*stand_user_expr && !*stand_prob_expr && !*stand_run_expr) {
    // all cleared
    serve_state_destroy_stand_expr(u);
    return;
  }

  if (IS_EQUAL(stand_user_expr) && IS_EQUAL(stand_prob_expr)
      && IS_EQUAL(stand_run_expr)) {
    // nothing to do
    return;
  }

  xfree(u->stand_error_msgs); u->stand_error_msgs = NULL;

  if (!IS_EQUAL(stand_user_expr)) {
    if (!*stand_user_expr) {
      u->stand_user_expr = 0;
      u->stand_user_tree = 0;
    } else {
      u->stand_user_expr = xstrdup(stand_user_expr);
      if (!u->stand_mem) {
        u->stand_mem = filter_tree_new();
      }
      u->stand_user_tree = 0;
      filter_expr_set_string(stand_user_expr, u->stand_mem,
                             stand_parse_error_func, state);
      filter_expr_init_parser(u->stand_mem, stand_parse_error_func, state);
      filter_expr_nerrs = 0;
      r = filter_expr_parse();
      if (r + filter_expr_nerrs != 0 || !filter_expr_lval) {
        stand_parse_error_func(state, "user filter expression parsing failed");
      } else if (filter_expr_lval->type != FILTER_TYPE_BOOL) {
        stand_parse_error_func(state, "user boolean expression expected");
      } else {
        u->stand_user_tree = filter_expr_lval;
      }
    }
  }

  if (!IS_EQUAL(stand_prob_expr)) {
    if (!*stand_prob_expr) {
      u->stand_prob_expr = 0;
      u->stand_prob_tree = 0;
    } else {
      u->stand_prob_expr = xstrdup(stand_prob_expr);
      if (!u->stand_mem) {
        u->stand_mem = filter_tree_new();
      }
      u->stand_prob_tree = 0;
      filter_expr_set_string(stand_prob_expr, u->stand_mem,
                             stand_parse_error_func, state);
      filter_expr_init_parser(u->stand_mem, stand_parse_error_func, state);
      filter_expr_nerrs = 0;
      r = filter_expr_parse();
      if (r + filter_expr_nerrs != 0 || !filter_expr_lval) {
        stand_parse_error_func(state, "problem filter expression parsing failed");
      } else if (filter_expr_lval->type != FILTER_TYPE_BOOL) {
        stand_parse_error_func(state, "problem boolean expression expected");
      } else {
        u->stand_prob_tree = filter_expr_lval;
      }
    }
  }

  if (!IS_EQUAL(stand_run_expr)) {
    if (!*stand_run_expr) {
      xfree(u->stand_run_expr);
      u->stand_run_expr = 0;
      u->stand_run_tree = 0;
    } else {
      u->stand_run_expr = xstrdup(stand_run_expr);
      if (!u->stand_mem) {
        u->stand_mem = filter_tree_new();
      }
      u->stand_run_tree = 0;
      filter_expr_set_string(stand_run_expr, u->stand_mem,
                             stand_parse_error_func, state);
      filter_expr_init_parser(u->stand_mem, stand_parse_error_func, state);
      filter_expr_nerrs = 0;
      r = filter_expr_parse();
      if (r + filter_expr_nerrs != 0 || !filter_expr_lval) {
        stand_parse_error_func(state, "run filter expression parsing failed");
      } else if (filter_expr_lval->type != FILTER_TYPE_BOOL) {
        stand_parse_error_func(state, "run boolean expression expected");
      } else {
        u->stand_run_tree = filter_expr_lval;
      }
    }
  }

  if (!u->stand_user_tree && !u->stand_prob_tree && !u->stand_run_tree) {
    u->stand_mem = filter_tree_delete(u->stand_mem);
  }
}

void
ns_reset_stand_filter(
        const serve_state_t state,
        struct http_request_info *phr)
{
  struct user_filter_info *u = 0;

  u = user_filter_info_allocate(state, phr->user_id, phr->session_id);
  if (!u) return;

  serve_state_destroy_stand_expr(u);
}

void
ns_download_runs(
        const struct contest_desc *cnts,
        const serve_state_t cs,
        FILE *fout,
        FILE *log_f,
        int run_selection,
        int dir_struct,
        int file_name_mask,
        int use_problem_extid,
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
    if (mkdir(dir2, 0770) >= 0) break;
    if (errno != EEXIST) {
      ns_error(log_f, NEW_SRV_ERR_MKDIR_FAILED, dir2, os_ErrorMsg());
      goto cleanup;
    }
    serial++;
  }
  need_remove = 1;

  snprintf(name3, sizeof(name3), "contest_%d_%04d%02d%02d%02d%02d%02d",
           cnts->id, 
           ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday,
           ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
  snprintf(dir3, sizeof(dir3), "%s/%s", dir2, name3);
  if (mkdir(dir3, 0775) < 0) {
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
    if (run_selection == NS_RUNSEL_OKPR && info.status != RUN_OK && info.status != RUN_PENDING_REVIEW) continue;
    if (run_selection == NS_RUNSEL_OKPRRJ
        && info.status != RUN_OK && info.status != RUN_PENDING_REVIEW
        && info.status != RUN_IGNORED && info.status != RUN_REJECTED
        && info.status != RUN_PENDING && info.status != RUN_DISQUALIFIED)
      continue;
    if (info.status > RUN_LAST) continue;
    if (info.status > RUN_MAX_STATUS && info.status < RUN_TRANSIENT_FIRST)
      continue;
    if (info.is_hidden) continue;

    if (!(login_ptr = teamdb_get_login(cs->teamdb_state, info.user_id))) {
      snprintf(login_buf, sizeof(login_buf), "!user_%d", info.user_id);
      login_ptr = login_buf;
    }
    if (!(name_ptr = teamdb_get_name_2(cs->teamdb_state, info.user_id))) {
      snprintf(name_buf, sizeof(name_buf), "!user_%d", info.user_id);
      name_ptr = name_buf;
    } else {
      //filename_armor_bytes(name_buf, sizeof(name_buf), name_ptr, strlen(name_ptr));
      //name_ptr = name_buf;
    }
    if (info.prob_id > 0 && info.prob_id <= cs->max_prob
        && cs->probs[info.prob_id]) {
      if (use_problem_extid && cs->probs[info.prob_id]->extid && cs->probs[info.prob_id]->extid[0]) {
        prob_ptr = cs->probs[info.prob_id]->extid;
      } else {
        prob_ptr = cs->probs[info.prob_id]->short_name;
      }
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
      if (mkdir(dir5, 0775) < 0 && errno != EEXIST) {
        ns_error(log_f, NEW_SRV_ERR_MKDIR_FAILED, dir5, os_ErrorMsg());
        goto cleanup;
      }
      if (dir4a[0]) {
        snprintf(dir5, sizeof(dir5), "%s/%s/%s", dir3, dir4, dir4a);
        errno = 0;
        if (mkdir(dir5, 0775) < 0 && errno != EEXIST) {
          ns_error(log_f, NEW_SRV_ERR_MKDIR_FAILED, dir5, os_ErrorMsg());
          goto cleanup;
        }
      }
    } else {
      snprintf(dir5, sizeof(dir5), "%s", dir3);
    }

    file_name_exp_len = 128 + strlen(login_ptr) + strlen(name_ptr)
      + strlen(prob_ptr) + strlen(lang_ptr) + strlen(suff_ptr);
    if (file_name_exp_len > file_name_size) {
      while (file_name_exp_len > file_name_size) file_name_size *= 2;
      xfree(file_name_str);
      file_name_str = (unsigned char*) xmalloc(file_name_size);
    }

    sep = "";
    ptr = file_name_str;
    if ((file_name_mask & NS_FILE_PATTERN_CONTEST)) {
      ptr += sprintf(ptr, "%s%d", sep, cnts->id);
      sep = "-";
    }
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
    if ((file_name_mask & NS_FILE_PATTERN_TIME)) {
      time_t ttm = info.time;
      struct tm *rtm = localtime(&ttm);
      ptr += sprintf(ptr, "%s%04d%02d%02d%02d%02d%02d", sep, rtm->tm_year + 1900, rtm->tm_mon + 1, rtm->tm_mday, rtm->tm_hour, rtm->tm_min, rtm->tm_sec);
      sep = "-";
    }
    if ((file_name_mask & NS_FILE_PATTERN_SUFFIX)) {
      ptr += sprintf(ptr, "%s", suff_ptr);
    }
    for (ptr = file_name_str; *ptr; ++ptr) {
      if (*ptr <= ' ') *ptr = '_';
    }
    snprintf(dstpath, sizeof(dstpath), "%s/%s", dir5, file_name_str);

    srcflags = serve_make_source_read_path(cs, srcpath, sizeof(srcpath), &info);
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

  while ((p = waitpid(pid, &status, 0)) != pid);
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
    remove_directory_recursively(dir2, 0);
  }
  xfree(file_bytes);
  xfree(file_name_str);
}

static int
do_add_row(
        struct http_request_info *phr,
        const serve_state_t cs,
        FILE *log_f,
        int row,
        const struct run_entry *re,
        size_t run_size,
        const unsigned char *run_text)
{
  struct timeval precise_time;
  int run_id;
  int arch_flags = 0;
  path_t run_path;

  ej_uuid_t run_uuid;
  int store_flags = 0;
  gettimeofday(&precise_time, 0);
  ej_uuid_generate(&run_uuid);
  if (cs->global->uuid_run_store > 0 && run_get_uuid_hash_state(cs->runlog_state) >= 0 && ej_uuid_is_nonempty(run_uuid)) {
    store_flags = 1;
  }
  run_id = run_add_record(cs->runlog_state, 
                          precise_time.tv_sec, precise_time.tv_usec * 1000,
                          run_size, re->sha1, &run_uuid,
                          &phr->ip, phr->ssl_flag, phr->locale_id,
                          re->user_id, re->prob_id, re->lang_id, re->eoln_type,
                          re->variant, re->is_hidden, re->mime_type, store_flags);
  if (run_id < 0) {
    fprintf(log_f, _("Failed to add row %d to runlog\n"), row);
    return -1;
  }
  serve_move_files_to_insert_run(cs, run_id);

  if (store_flags == 1) {
    arch_flags = uuid_archive_prepare_write_path(cs, run_path, sizeof(run_path),
                                                 &run_uuid, run_size,
                                                 DFLT_R_UUID_SOURCE, 0, 0);
  } else {
    arch_flags = archive_prepare_write_path(cs, run_path, sizeof(run_path),
                                            cs->global->run_archive_dir, run_id,
                                            run_size, NULL, 0, 0);
  }
  if (arch_flags < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    fprintf(log_f, _("Cannot allocate space to store run row %d\n"), row);
    return -1;
  }

  if (generic_write_file(run_text, run_size, arch_flags, 0, run_path, "") < 0) {
    run_undo_add_record(cs->runlog_state, run_id);
    fprintf(log_f, _("Cannot write run row %d\n"), row);
    return -1;
  }
  run_set_entry(cs->runlog_state, run_id, RE_STATUS | RE_TEST | RE_SCORE, re);

  serve_audit_log(cs, run_id, NULL, phr->user_id, &phr->ip, phr->ssl_flag,
                  "priv-new-run", "ok", re->status, NULL);
  return run_id;
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
  const struct section_problem_data *prob;
  const struct section_language_data *lang;
  const unsigned char *run_text = "";
  size_t run_size = 0;
  int mime_type = 0;
  const unsigned char *mime_type_str = 0;
  char **lang_list = 0;
  char *eptr;
  int run_id;
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
    if (prob->type == PROB_TYPE_STANDARD) {
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
      runs[row].passed_mode = 1;
    } else {
      runs[row].test = 0;
      runs[row].passed_mode = 1;
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
    run_id = do_add_row(phr, cs, log_f, row, &runs[row], run_size, run_text);
    if (run_id < 0) goto cleanup;
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
        const serve_state_t cs,
        FILE *log_f,
        const unsigned char *csv_text,
        int add_flag)
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
  size_t run_size = 0;
  const unsigned char *run_text = "";
  ruint32_t sha1[5];

  sha_buffer(run_text, run_size, sha1);
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
        // FIXME: add new run if add_flag is set
        if (run_id < 0 && add_flag) {
          pe->run_id = -1;
          pe->size = run_size;
          memcpy(pe->sha1, sha1, sizeof(pe->sha1));
          ipv6_to_run_entry(&phr->ip, pe);
          pe->ssl_flag = phr->ssl_flag;
          pe->locale_id = phr->locale_id;
          pe->lang_id = 0;
          pe->variant = 0;
          pe->is_hidden = 0;
          pe->mime_type = 0;
        } else if (run_id < 0) {
          fprintf(log_f, _("No entry for %d/%s\n"), pe->user_id,
                  prob->short_name);
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
        // FIXME: add new run if add_flag is set
        if (run_id < 0 && add_flag) {
          pe->run_id = -1;
          pe->size = run_size;
          memcpy(pe->sha1, sha1, sizeof(pe->sha1));
          ipv6_to_run_entry(&phr->ip, pe);
          pe->ssl_flag = phr->ssl_flag;
          pe->locale_id = phr->locale_id;
          pe->lang_id = 0;
          pe->variant = 0;
          pe->is_hidden = 0;
          pe->mime_type = 0;
        } else if (run_id < 0) {
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
        pe->user_id  = x;

        // find the latest ACCEPTED run by name/prob_id pair
        for (run_id = run_get_total(cs->runlog_state) - 1; run_id >= 0; run_id--) {
          if (run_get_entry(cs->runlog_state, run_id, &te) < 0) continue;
          if (!run_is_source_available(te.status)) continue;
          if (!strcmp(s, teamdb_get_name_2(cs->teamdb_state, te.user_id)) && pe->prob_id == te.prob_id) break;
        }
        // FIXME: add new run if add_flag is set
        if (run_id < 0 && add_flag) {
          pe->run_id = -1;
          pe->size = run_size;
          memcpy(pe->sha1, sha1, sizeof(pe->sha1));
          ipv6_to_run_entry(&phr->ip, pe);
          pe->ssl_flag = phr->ssl_flag;
          pe->locale_id = phr->locale_id;
          pe->lang_id = 0;
          pe->variant = 0;
          pe->is_hidden = 0;
          pe->mime_type = 0;
        } else if (run_id < 0) {
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
        // FIXME: add new run if add_flag is set
        if (run_id < 0 && add_flag) {
          pe->run_id = -1;
          pe->size = run_size;
          memcpy(pe->sha1, sha1, sizeof(pe->sha1));
          ipv6_to_run_entry(&phr->ip, pe);
          pe->ssl_flag = phr->ssl_flag;
          pe->locale_id = phr->locale_id;
          pe->lang_id = 0;
          pe->variant = 0;
          pe->is_hidden = 0;
          pe->mime_type = 0;
        } else if (run_id < 0) {
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
      pe->passed_mode = 1;
    } else {
      pe->test = 0;
      pe->passed_mode = 1;
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
    if (runs[row].run_id == -1) {
      if (!add_flag) continue;
      do_add_row(phr, cs, log_f, row, &runs[row], run_size, run_text);
    }
    run_set_entry(cs->runlog_state, runs[row].run_id,
                  RE_STATUS | RE_TEST | RE_SCORE | RE_PASSED_MODE,
                  &runs[row]);
  }

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
    start_time = run_get_virtual_start_time(cs->runlog_state, re.user_id);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
  }

  if (cs->global->score_system == SCORE_OLYMPIAD && cs->accepting_mode) {
    if (re.status == RUN_OK || re.status == RUN_PARTIAL)
      re.status = RUN_ACCEPTED;
  }

  if (re.prob_id > 0 && re.prob_id <= cs->max_prob)
    cur_prob = cs->probs[re.prob_id];

  attempts = 0; disq_attempts = 0;
  if (cs->global->score_system == SCORE_KIROV && !re.is_hidden)
    run_get_attempts(cs->runlog_state, run_id, &attempts, &disq_attempts,
                     cur_prob->ignore_compile_errors);

  prev_successes = RUN_TOO_MANY;
  if (cs->global->score_system == SCORE_KIROV
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
  write_text_run_status(cs, fout, start_time, &re, 1 /* user_mode */, 0, attempts,
                        disq_attempts, prev_successes);
  fprintf(fout, "\n");

  return 0;
}

static unsigned char *
get_source(
        const serve_state_t cs,
        int run_id,
        const struct run_entry *re,
        const struct section_problem_data *prob,
        int variant)
{
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
  switch (prob->type) {
  case PROB_TYPE_STANDARD:
  case PROB_TYPE_OUTPUT_ONLY:
  case PROB_TYPE_TEXT_ANSWER:
  case PROB_TYPE_CUSTOM:
  case PROB_TYPE_TESTS:
    goto cleanup;
  case PROB_TYPE_SHORT_ANSWER:
  case PROB_TYPE_SELECT_ONE:
  case PROB_TYPE_SELECT_MANY:
    break;
  }

  if ((src_flag = serve_make_source_read_path(cs, src_path, sizeof(src_path), re)) < 0)
    goto cleanup;
  if (generic_read_file(&src_txt, 0, &src_len, src_flag, 0, src_path, 0) < 0)
    goto cleanup;
  s = src_txt;
  while (src_len > 0 && isspace(s[src_len])) src_len--;
  s[src_len] = 0;
  if (prob->type == PROB_TYPE_SELECT_ONE) {
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
      close_memstream(tmp_f); tmp_f = 0;
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
  int rep_flag;
  path_t rep_path;
  unsigned char *str = 0;
  char *rep_txt = 0;
  size_t rep_len = 0;
  testing_report_xml_t rep_xml = 0;
  struct testing_report_test *rep_tst;
  const unsigned char *start_ptr = 0;
  struct run_entry re;

  if (run_get_entry(cs->runlog_state, run_id, &re) < 0)
    goto cleanup;

  if ((rep_flag = serve_make_xml_report_read_path(cs, rep_path, sizeof(rep_path), &re)) < 0)
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
  int rep_flag;
  path_t rep_path;
  char *rep_txt = 0;
  size_t rep_len = 0;
  testing_report_xml_t rep_xml = 0;
  const unsigned char *start_ptr = 0;
  int r, i, t;

  // problem is deleted?
  if (!prob) return 0;

  switch (re->status) {
  case RUN_OK:
  case RUN_ACCEPTED:
  case RUN_PENDING_REVIEW:
  case RUN_PARTIAL:
    if (prob->accept_partial <= 0 && prob->min_tests_to_accept < 0)
      return prob->tests_to_accept;
    break;

  case RUN_RUN_TIME_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_WALL_TIME_LIMIT_ERR:
  case RUN_PRESENTATION_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_MEM_LIMIT_ERR:
  case RUN_SECURITY_ERR:
  case RUN_SYNC_ERR:
    r = re->test;
    if (re->passed_mode > 0) {
    } else {
      if (r > 0) r--;
    }
    // whether this ever possible?
    if (r > prob->tests_to_accept) r = prob->tests_to_accept;
    return r;

  default:
    return 0;
  }

  r = 0;
  if ((rep_flag = serve_make_xml_report_read_path(cs, rep_path, sizeof(rep_path), re)) < 0)
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
        const unsigned char *table_class,
        const struct UserProblemInfo *pinfo,
        int back_action)
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
  int enable_src_view = 0;
  int enable_rep_view = 0;

  if (table_class && *table_class) {
    cl = alloca(strlen(table_class) + 16);
    sprintf(cl, " class=\"%s\"", table_class);
  }

  if (prob_id > 0 && prob_id <= cs->max_prob)
    filt_prob = cs->probs[prob_id];

  ASSERT(global->score_system == SCORE_OLYMPIAD);
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

  fprintf(fout, "<table class=\"table\"><tr>");
  if (!cnts->exam_mode) fprintf(fout, "<th%s>%s</th>", cl, _("Run ID"));
  if (cnts->exam_mode) fprintf(fout,"<th%s>%s</th>", cl, "NN");
  if (!cnts->exam_mode) fprintf(fout,"<th%s>%s</th>", cl, _("Time"));
  if (!cnts->exam_mode) fprintf(fout,"<th%s>%s</th>", cl, _("Size"));
  if (!filt_prob) fprintf(fout, "<th%s>%s</th>", cl, _("Problem"));
  if (global->disable_language <= 0
      && (!filt_prob || filt_prob->type == PROB_TYPE_STANDARD))
    fprintf(fout, "<th%s>%s</th>", cl, _("Programming language"));
  fprintf(fout, "<th%s>%s</th>", cl, _("Result"));
  if (global->disable_passed_tests <= 0
      && (!filt_prob || filt_prob->type == PROB_TYPE_STANDARD))
    fprintf(fout, "<th%s>%s</th>", cl, _("Tests passed"));
  if (!accepting_mode)
    fprintf(fout, "<th%s>%s</th>", cl, _("Score"));

  enable_src_view = (cs->online_view_source > 0 || (!cs->online_view_source && global->team_enable_src_view > 0));
  enable_rep_view = (cs->online_view_report > 0 || (!cs->online_view_report && global->team_enable_rep_view > 0));

  if (enable_src_view)
    fprintf(fout, "<th%s>%s</th>", cl, _("View submitted answer"));
  fprintf(fout, "<th%s>%s</th>", cl, _("View check details"));
  if (global->enable_printing && !cs->printing_suspended)
    fprintf(fout, "<th%s>%s</th>", cl, _("Print sources"));
  fprintf(fout, "</tr>\n");

  for (shown = 0, i = run_get_user_last_run_id(cs->runlog_state, phr->user_id);
       i >= 0 && shown < runs_to_show;
       i = run_get_user_prev_run_id(cs->runlog_state, i)) {
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

    if (prob && prob->type != PROB_TYPE_STANDARD) {
      // there are check statuses that can never appear in output-only probs
      switch (re.status) {
      case RUN_COMPILE_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_SYNC_ERR:
      case RUN_STYLE_ERR:
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
      case RUN_PENDING_REVIEW:
        re.status = RUN_ACCEPTED;
        if (prob && prob->type != PROB_TYPE_STANDARD) {
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
      case RUN_STYLE_ERR:
      case RUN_REJECTED:
        report_allowed = 1;
        snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        break;

      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_SYNC_ERR:
        if (prob && prob->type != PROB_TYPE_STANDARD) {
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
        if (prob && prob->type != PROB_TYPE_STANDARD) {
          snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
          report_allowed = 1;
        } else {
          if (re.passed_mode > 0) {
            snprintf(tests_buf, sizeof(tests_buf), "%d", re.test);
          } else {
            snprintf(tests_buf, sizeof(tests_buf), "%d", re.test - 1);
          }
          report_allowed = 1;
        }
        if (prob && !latest_flag[prob->id]) run_latest = 1;
        score = re.score;
        if (prob && !prob->variable_full_score) score = prob->full_score;
        if (re.score_adj) score += re.score_adj;
        if (score < 0) score = 0;
        score_view_display(score_buf, sizeof(score_buf), prob, score);
        break;
      case RUN_PARTIAL:
        if (prob && prob->type != PROB_TYPE_STANDARD) {
          snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        } else {
          if (re.passed_mode > 0) {
            snprintf(tests_buf, sizeof(tests_buf), "%d", re.test);
          } else {
            snprintf(tests_buf, sizeof(tests_buf), "%d", re.test - 1);
          }
        }
        report_allowed = 1;
        if (prob && !latest_flag[prob->id]) run_latest = 1;
        score = re.score;
        if (re.score_adj) score += re.score_adj;
        if (score < 0) score = 0;
        score_view_display(score_buf, sizeof(score_buf), prob, score);
        break;
      case RUN_COMPILE_ERR:
      case RUN_STYLE_ERR:
      case RUN_REJECTED:
        snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        snprintf(score_buf, sizeof(score_buf), "&nbsp;");
        report_allowed = 1;
        break;

      case RUN_ACCEPTED:
      case RUN_PENDING_REVIEW:
        if (prob && !latest_flag[prob->id]) run_latest = 1;
        if (prob && prob->type != PROB_TYPE_STANDARD) {
          snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        } else {
          if (re.passed_mode > 0) {
            snprintf(tests_buf, sizeof(tests_buf), "%d", re.test);
          } else {
            snprintf(tests_buf, sizeof(tests_buf), "%d", re.test - 1);
          }
        }
        report_allowed = 1;
        snprintf(score_buf, sizeof(score_buf), "&nbsp;");
        break;

      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_SYNC_ERR:
        if (prob && prob->type != PROB_TYPE_STANDARD) {
          snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
          score = re.score;
          if (score < 0) score = 0;
          score_view_display(score_buf, sizeof(score_buf), prob, score);
        } else {
          if (re.passed_mode > 0) {
            snprintf(tests_buf, sizeof(tests_buf), "%d", re.test);
          } else {
            snprintf(tests_buf, sizeof(tests_buf), "%d", re.test);
          }
          snprintf(score_buf, sizeof(score_buf), "&nbsp;");
        }
        report_allowed = 1;
        break;

      default:
        snprintf(tests_buf, sizeof(tests_buf), "&nbsp;");
        snprintf(score_buf, sizeof(score_buf), "&nbsp;");
      }
    }

    run_status_str(re.status, stat_str, sizeof(stat_str),
                   prob?prob->type:0, prob?prob->scoring_checker:0);

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
        && (!filt_prob || filt_prob->type == PROB_TYPE_STANDARD))
      fprintf(fout, "<td%s>%s</td>", cl, lang_name_ptr);
    fprintf(fout, "<td%s>%s</td>", cl, stat_str);
    if (global->disable_passed_tests <= 0
        && (!filt_prob || filt_prob->type == PROB_TYPE_STANDARD))
      fprintf(fout, "<td%s>%s</td>", cl, tests_buf);
    if (!accepting_mode)
      fprintf(fout, "<td%s>%s</td>", cl, score_buf);

    if (enable_src_view) {
      if (cnts->exam_mode && (src_txt = get_source(cs, i, &re, prob, variant))) {
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
    } else if ((re.status == RUN_COMPILE_ERR
                || re.status == RUN_STYLE_ERR
                || re.status == RUN_REJECTED)
          && (enable_rep_view || global->team_enable_ce_view)
          && report_allowed) {
      fprintf(fout, "<td%s>%s%s</a></td>", cl,
              ns_aref(ab, sizeof(ab), phr, NEW_SRV_ACTION_VIEW_REPORT,
                      "run_id=%d", i), _("View"));
    } else if (enable_rep_view && report_allowed) {
      fprintf(fout, "<td%s>%s%s</a></td>", cl,
              ns_aref(ab, sizeof(ab), phr, NEW_SRV_ACTION_VIEW_REPORT,
                      "run_id=%d", i), _("View"));
    } else if (enable_rep_view || global->team_enable_ce_view) {
      fprintf(fout, "<td%s>&nbsp;</td>", cl);
    }

    /* FIXME: add "print sources" reference */

    fprintf(fout, "</tr>\n");
    shown++;

    xfree(report_comment); report_comment = 0;
  }
  fprintf(fout, "</table>\n");
}

static void
kirov_score_latest_or_unmarked(
        const struct section_problem_data *cur_prob,
        struct run_entry *re,
        UserProblemInfo *pinfo,
        time_t start_time,
        int run_id,
        int separate_user_score,
        int status,
        int score)
{
  int cur_score = 0;

  ASSERT(cur_prob->score_latest_or_unmarked > 0);

  /*
   * if there exists a "marked" run, the last "marked" score is taken
   * if there is no "marked" run, the max score is taken
   */
  if (pinfo->marked_flag && !re->is_marked) {
    // already have a "marked" run, so ignore "unmarked" runs
    return;
  }
  pinfo->marked_flag = re->is_marked;

  switch (status) {
  case RUN_OK:
    pinfo->solved_flag = 1;
    cur_score = calc_kirov_score(0, 0, start_time, separate_user_score,
                                 1 /* user_mode */, re->token_flags, re, cur_prob,
                                 pinfo->attempts,
                                 pinfo->disqualified,
                                 pinfo->prev_successes, 0, 0);
    if (re->is_marked || cur_score > pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_PENDING_REVIEW:
    // this is OK solution without manual confirmation
    pinfo->pr_flag = 1;
    cur_score = calc_kirov_score(0, 0, start_time, separate_user_score,
                                 1 /* user_mode */, re->token_flags, re, cur_prob,
                                 pinfo->attempts,
                                 pinfo->disqualified,
                                 pinfo->prev_successes, 0, 0);
    if (re->is_marked || cur_score > pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_COMPILE_ERR:
  case RUN_STYLE_ERR:
    if (cur_prob->ignore_compile_errors > 0) return;
    pinfo->attempts++;
    if (re->is_marked || cur_score > pinfo->best_score) {
      cur_score = 0;
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_RUN_TIME_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_WALL_TIME_LIMIT_ERR:
  case RUN_PRESENTATION_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_CHECK_FAILED:
  case RUN_MEM_LIMIT_ERR:
  case RUN_SECURITY_ERR:
  case RUN_SYNC_ERR:
    break;

  case RUN_PARTIAL:
    cur_score = calc_kirov_score(0, 0, start_time, separate_user_score,
                                 1 /* user_mode */, re->token_flags, re, cur_prob,
                                 pinfo->attempts,
                                 pinfo->disqualified,
                                 pinfo->prev_successes, 0, 0);
    pinfo->attempts++;
    if (re->is_marked || cur_score > pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_REJECTED:
  case RUN_IGNORED:
    break;

  case RUN_DISQUALIFIED:
    pinfo->disqualified++;
    break;

  case RUN_ACCEPTED:
  case RUN_PENDING:
    pinfo->pending_flag = 1;
    pinfo->attempts++;
    if (pinfo->best_run < 0) pinfo->best_run = run_id;
    break;

  default:
    abort();
  }
}

static void
kirov_score_latest(
        const struct section_problem_data *cur_prob,
        struct run_entry *re,
        UserProblemInfo *pinfo,
        time_t start_time,
        int run_id,
        int separate_user_score,
        int status,
        int score)
{
  int cur_score = 0;

  ASSERT(cur_prob->score_latest > 0);

  if (cur_prob->ignore_unmarked > 0 && !re->is_marked) {
    // ignore submits which are not "marked"
    return;
  }

  cur_score = calc_kirov_score(0, 0, start_time, separate_user_score,
                               1 /* user_mode */, re->token_flags, re, cur_prob,
                               pinfo->attempts,
                               pinfo->disqualified,
                               pinfo->prev_successes, 0, 0);
  switch (status) {
  case RUN_OK:
    pinfo->marked_flag = re->is_marked;
    pinfo->solved_flag = 1;
    pinfo->accepted_flag = 0;
    pinfo->pr_flag = 0;
    pinfo->pending_flag = 0;
    pinfo->best_score = cur_score;
    pinfo->best_run = run_id;
    break;

  case RUN_PENDING_REVIEW:
    pinfo->marked_flag = re->is_marked;
    pinfo->solved_flag = 0;
    pinfo->accepted_flag = 0;
    pinfo->pr_flag = 1;
    pinfo->pending_flag = 0;
    pinfo->best_score = cur_score;
    pinfo->best_run = run_id;
    ++pinfo->attempts;
    break;

  case RUN_ACCEPTED:
    pinfo->marked_flag = re->is_marked;
    pinfo->solved_flag = 0;
    pinfo->accepted_flag = 1;
    pinfo->pr_flag = 0;
    pinfo->pending_flag = 0;
    pinfo->best_score = cur_score;
    pinfo->best_run = run_id;
    ++pinfo->attempts;
    break;

  case RUN_COMPILE_ERR:
  case RUN_STYLE_ERR:
    if (cur_prob->ignore_compile_errors > 0) break;
    pinfo->marked_flag = re->is_marked;
    pinfo->solved_flag = 0;
    pinfo->accepted_flag = 0;
    pinfo->pr_flag = 0;
    pinfo->pending_flag = 0;
    pinfo->best_score = 0;
    pinfo->best_run = run_id;
    ++pinfo->attempts;
    break;

  case RUN_CHECK_FAILED:
  case RUN_IGNORED:
    break;

  case RUN_REJECTED:
    pinfo->marked_flag = re->is_marked;
    pinfo->solved_flag = 0;
    pinfo->accepted_flag = 0;
    pinfo->pr_flag = 0;
    pinfo->pending_flag = 0;
    pinfo->best_score = 0;
    pinfo->best_run = run_id;
    break;

  case RUN_DISQUALIFIED:
    pinfo->marked_flag = re->is_marked;
    pinfo->solved_flag = 0;
    pinfo->accepted_flag = 0;
    pinfo->pr_flag = 0;
    pinfo->pending_flag = 0;
    pinfo->best_score = 0;
    pinfo->best_run = run_id;
    ++pinfo->disqualified;
    break;

  case RUN_PENDING:
    pinfo->marked_flag = re->is_marked;
    pinfo->solved_flag = 0;
    pinfo->accepted_flag = 0;
    pinfo->pr_flag = 0;
    pinfo->pending_flag = 1;
    pinfo->best_score = 0;
    pinfo->best_run = run_id;
    break;

  case RUN_RUN_TIME_ERR:
  case RUN_TIME_LIMIT_ERR:
  case RUN_PRESENTATION_ERR:
  case RUN_WRONG_ANSWER_ERR:
  case RUN_PARTIAL:
  case RUN_MEM_LIMIT_ERR:
  case RUN_SECURITY_ERR:
  case RUN_SYNC_ERR:
  case RUN_WALL_TIME_LIMIT_ERR:
    pinfo->marked_flag = re->is_marked;
    pinfo->solved_flag = 0;
    pinfo->accepted_flag = 0;
    pinfo->pr_flag = 0;
    pinfo->pending_flag = 0;
    pinfo->best_score = cur_score;
    pinfo->best_run = run_id;
    ++pinfo->attempts;
    break;

  default:
    abort();
  }
}

static void
kirov_score_tokenized(
        const struct section_problem_data *cur_prob,
        struct run_entry *re,
        UserProblemInfo *pinfo,
        time_t start_time,
        int run_id,
        int separate_user_score,
        int status,
        int score)
{
  ASSERT(cur_prob->score_tokenized > 0);

  int cur_score = 0;

  if (!re->token_flags) {
    if (cur_prob->tokens_for_user_ac > 0 && re->is_saved) {
      if (re->saved_status == RUN_OK || re->saved_status == RUN_ACCEPTED) {
        pinfo->last_untokenized = 1;
      }
    }
    // FIXME: handle other cases?
    return;
  }

  pinfo->last_untokenized = 0;
  cur_score = calc_kirov_score(0, 0, start_time, separate_user_score,
                               1 /* user_mode */, re->token_flags, re, cur_prob,
                               pinfo->attempts,
                               pinfo->disqualified,
                               pinfo->prev_successes, 0, 0);

  switch (status) {
  case RUN_OK:
    pinfo->solved_flag = 1;
    break;

  case RUN_PENDING_REVIEW:
    pinfo->pr_flag = 1;
    break;

  case RUN_COMPILE_ERR:
  case RUN_STYLE_ERR:
    if (cur_prob->ignore_compile_errors > 0) return;
    cur_score = 0;
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
    break;

  case RUN_ACCEPTED:
    pinfo->accepted_flag = 1;
    break;

  case RUN_REJECTED:
    return;

  case RUN_CHECK_FAILED:
  case RUN_IGNORED:
    return;

  case RUN_DISQUALIFIED:
    ++pinfo->disqualified;
    cur_score = 0;
    break;

  case RUN_PENDING:
    pinfo->pending_flag = 1;
    break;

  default:
    abort();
  }

  ++pinfo->attempts;
  if (cur_score >= pinfo->best_score) {
    pinfo->best_score = cur_score;
    pinfo->best_run = run_id;
  }
}

static void
kirov_score_default(
        const struct section_problem_data *cur_prob,
        struct run_entry *re,
        UserProblemInfo *pinfo,
        time_t start_time,
        int run_id,
        int separate_user_score,
        int status,
        int score)
{
  int cur_score = 0;

  if (pinfo->solved_flag) {
    // if the problem is already solved, no need to process this run
    return;
  }
  if (cur_prob->ignore_unmarked > 0 && !re->is_marked) {
    // ignore "unmarked" runs, if the option is set
    return;
  }

  cur_score = calc_kirov_score(0, 0, start_time, separate_user_score,
                               1 /* user_mode */, re->token_flags, re, cur_prob,
                               pinfo->attempts,
                               pinfo->disqualified,
                               pinfo->prev_successes, 0, 0);

  switch (status) {
  case RUN_OK:
    pinfo->solved_flag = 1;
    if (cur_score >= pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_PENDING_REVIEW:
    pinfo->pr_flag = 1;
    if (cur_score >= pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_COMPILE_ERR:
  case RUN_STYLE_ERR:
    if (cur_prob->ignore_compile_errors > 0) break;

    ++pinfo->attempts;
    cur_score = 0;
    if (cur_score >= pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
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
    ++pinfo->attempts;
    if (cur_score >= pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_ACCEPTED:
    pinfo->accepted_flag = 1;
    if (cur_score >= pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_REJECTED:
    cur_score = 0;
    if (cur_score >= pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_CHECK_FAILED:
  case RUN_IGNORED:
    break;

  case RUN_DISQUALIFIED:
    ++pinfo->disqualified;
    cur_score = 0;
    if (cur_score >= pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  case RUN_PENDING:
    pinfo->pending_flag = 1;
    ++pinfo->attempts;
    cur_score = 0;
    if (cur_score >= pinfo->best_score) {
      pinfo->best_score = cur_score;
      pinfo->best_run = run_id;
    }
    break;

  default:
    abort();
  }
}

void
ns_get_user_problems_summary(
        const serve_state_t cs,
        int user_id,
        const unsigned char *user_login,
        int accepting_mode,
        time_t start_time,
        time_t stop_time,
        UserProblemInfo *pinfo)       /* user problem status */
{
  const struct section_global_data *global = cs->global;
  int total_runs, run_id, cur_score = 0, total_teams;
  struct run_entry re;
  struct section_problem_data *cur_prob = 0;
  unsigned char *user_flag = 0;
  int status, score;
  int separate_user_score = 0;
  int need_prev_succ = 0; // 1, if we need to compute 'prev_successes' array

  /* if 'score_bonus' is set for atleast one problem, we have to scan all runs */
  for (int prob_id = 1; prob_id <= cs->max_prob; ++prob_id) {
    struct section_problem_data *prob = cs->probs[prob_id];
    if (prob && prob->score_bonus_total > 0) {
      need_prev_succ = 1;
    }
  }

  total_runs = run_get_total(cs->runlog_state);
  if (global->disable_user_database > 0) {
    total_teams = run_get_max_user_id(cs->runlog_state) + 1;
  } else {
    total_teams = teamdb_get_max_team_id(cs->teamdb_state) + 1;
  }
  separate_user_score = global->separate_user_score > 0 && cs->online_view_judge_score <= 0;

  /*
  time_t start_time;
  if (global->is_virtual) {
    if (run_get_virtual_start_entry(cs->runlog_state, user_id, &re) < 0) {
      start_time = run_get_start_time(cs->runlog_state);
    } else {
      start_time = re.time;
    }
  } else {
    start_time = run_get_start_time(cs->runlog_state);
  }
  */

  if (need_prev_succ) {
    XCALLOC(user_flag, (cs->max_prob + 1) * total_teams);
  }

  for (run_id = need_prev_succ?0:run_get_user_first_run_id(cs->runlog_state, user_id);
       run_id >= 0 && run_id < total_runs;
       run_id = need_prev_succ?(run_id + 1):run_get_user_next_run_id(cs->runlog_state, run_id)) {
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0) continue;
    if (!run_is_valid_status(re.status)) continue;
    if (re.status >= RUN_PSEUDO_FIRST && re.status <= RUN_PSEUDO_LAST) continue;
    if (re.prob_id <= 0 || re.prob_id > cs->max_prob) continue;
    if (!(cur_prob = cs->probs[re.prob_id])) continue;
    if (re.user_id <= 0 || re.user_id >= total_teams) continue;

    if (separate_user_score > 0 && re.is_saved) {
      if (re.token_count > 0 && (re.token_flags & TOKEN_FINALSCORE_BIT)) {
        status = re.status;
        score = re.score;
      } else {
        status = re.saved_status;
        score = re.saved_score;
      }
    } else {
      status = re.status;
      score = re.score;
    }

    if (need_prev_succ && re.user_id != user_id) {
      if (re.is_hidden) continue;
      if (teamdb_get_flags(cs->teamdb_state, re.user_id) & (TEAM_INVISIBLE | TEAM_BANNED))
        continue;
      if (status == RUN_OK) {
        if (!user_flag[re.user_id * (cs->max_prob + 1) + re.prob_id]) {
          pinfo[re.prob_id].prev_successes++;
        }
        user_flag[re.user_id * (cs->max_prob + 1) + re.prob_id] = 1;
      }
      continue;
    }

    ASSERT(re.user_id == user_id);
    pinfo[re.prob_id].token_count += re.token_count;
    if (status != RUN_IGNORED && (status != RUN_COMPILE_ERR || cur_prob->ignore_compile_errors <= 0)) {
      ++pinfo[re.prob_id].eff_attempts;
    }
    if (status >= RUN_TRANSIENT_FIRST && status <= RUN_TRANSIENT_LAST) {
      pinfo[re.prob_id].trans_flag = 1;
      pinfo[re.prob_id].all_attempts++;
    }
    if (status > RUN_MAX_STATUS) continue;

    pinfo[re.prob_id].all_attempts++;
    if (global->score_system == SCORE_OLYMPIAD && accepting_mode) {
      // OLYMPIAD contest in accepting mode
      if (cur_prob->type != PROB_TYPE_STANDARD) {
        switch (status) {
        case RUN_OK:
        case RUN_PARTIAL:
        case RUN_ACCEPTED:
        case RUN_PENDING_REVIEW:
        case RUN_WRONG_ANSWER_ERR:
          status = RUN_ACCEPTED;
          break;

        case RUN_COMPILE_ERR:
        case RUN_RUN_TIME_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_WALL_TIME_LIMIT_ERR:
        case RUN_CHECK_FAILED:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
        case RUN_SYNC_ERR:
        case RUN_STYLE_ERR:
        case RUN_REJECTED:
          status = RUN_CHECK_FAILED;
          break;
        }
        switch (status) {
        case RUN_ACCEPTED:
        case RUN_PENDING_REVIEW:
          pinfo[re.prob_id].accepted_flag = 1;
          pinfo[re.prob_id].best_run = run_id;
          break;

        case RUN_PRESENTATION_ERR:
          if (!pinfo[re.prob_id].accepted_flag) {
            pinfo[re.prob_id].best_run = run_id;
          }
          break;

        case RUN_CHECK_FAILED:
        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
          break;

        case RUN_PENDING:
          pinfo[re.prob_id].pending_flag = 1;
          pinfo[re.prob_id].attempts++;
          if (pinfo[re.prob_id].best_run < 0) pinfo[re.prob_id].best_run = run_id;
          break;

        default:
          abort();
        }
      } else {
        // regular problems
        switch (status) {
        case RUN_OK:
        case RUN_PARTIAL:
        case RUN_ACCEPTED:
        case RUN_PENDING_REVIEW:
          pinfo[re.prob_id].accepted_flag = 1;
          pinfo[re.prob_id].best_run = run_id;
          break;

        case RUN_COMPILE_ERR:
        case RUN_RUN_TIME_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_WALL_TIME_LIMIT_ERR:
        case RUN_PRESENTATION_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_CHECK_FAILED:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
        case RUN_SYNC_ERR:
        case RUN_STYLE_ERR:
          if (!pinfo[re.prob_id].accepted_flag) {
            pinfo[re.prob_id].best_run = run_id;
          }
          break;

        case RUN_REJECTED:
        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
          break;

        case RUN_PENDING:
          pinfo[re.prob_id].pending_flag = 1;
          pinfo[re.prob_id].attempts++;
          if (pinfo[re.prob_id].best_run < 0) pinfo[re.prob_id].best_run = run_id;
          break;

        default:
          abort();
        }
      }
    } else if (global->score_system == SCORE_OLYMPIAD) {
      // OLYMPIAD contest in judging mode
      //if (solved_flag[re.prob_id]) continue;
      if (cur_prob->type != PROB_TYPE_STANDARD) {
        if (status == RUN_PRESENTATION_ERR || status == RUN_WRONG_ANSWER_ERR)
          status = RUN_PARTIAL;
      }

      switch (status) {
      case RUN_OK:
        pinfo[re.prob_id].solved_flag = 1;
        pinfo[re.prob_id].best_run = run_id;
        cur_score = calc_kirov_score(0, 0, start_time,
                                     separate_user_score, 1 /* user_mode */, re.token_flags,
                                     &re, cur_prob, 0, 0, 0, 0, 0);
        //if (cur_score > best_score[re.prob_id])
        pinfo[re.prob_id].best_score = cur_score;
        break;

      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_COMPILE_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_SYNC_ERR:
      case RUN_STYLE_ERR:
      case RUN_REJECTED:
        break;

      case RUN_PARTIAL:
        pinfo[re.prob_id].solved_flag = 0;
        pinfo[re.prob_id].best_run = run_id;
        pinfo[re.prob_id].attempts++;
        cur_score = calc_kirov_score(0, 0, start_time, separate_user_score,
                                     1 /* user_mode */, re.token_flags,
                                     &re, cur_prob, 0, 0, 0, 0, 0);
        //if (cur_score > best_score[re.prob_id])
        pinfo[re.prob_id].best_score = cur_score;
        break;

      case RUN_ACCEPTED:
      case RUN_PENDING_REVIEW:
        break;

      case RUN_IGNORED:
        break;

      case RUN_DISQUALIFIED:
        break;

      case RUN_PENDING:
        pinfo[re.prob_id].pending_flag = 1;
        if (pinfo[re.prob_id].best_run < 0) pinfo[re.prob_id].best_run = run_id;
        break;

      default:
        abort();
      }
    } else if (global->score_system == SCORE_KIROV) {
      // KIROV contest
      if (cur_prob->score_latest_or_unmarked > 0) {
        kirov_score_latest_or_unmarked(cur_prob, &re, &pinfo[re.prob_id],
                                       start_time, run_id, separate_user_score, status, score);
      } else if (cur_prob->score_latest > 0) {
        kirov_score_latest(cur_prob, &re, &pinfo[re.prob_id],
                           start_time, run_id, separate_user_score, status, score);
      } else if (cur_prob->score_tokenized > 0) {
        kirov_score_tokenized(cur_prob, &re, &pinfo[re.prob_id],
                              start_time, run_id, separate_user_score, status, score);
      } else {
        kirov_score_default(cur_prob, &re, &pinfo[re.prob_id],
                            start_time, run_id, separate_user_score, status, score);
      }
    } else if (global->score_system == SCORE_MOSCOW) {
      if (pinfo[re.prob_id].solved_flag) continue;

      switch (status) {
      case RUN_OK:
        pinfo[re.prob_id].solved_flag = 1;
        pinfo[re.prob_id].best_run = run_id;
        cur_score = cur_prob->full_score;
        if (cur_score >= pinfo[re.prob_id].best_score) {
          pinfo[re.prob_id].best_score = cur_score;
          pinfo[re.prob_id].best_run = run_id;
        }
        break;

      case RUN_COMPILE_ERR:
      case RUN_STYLE_ERR:
      case RUN_REJECTED:
        if (!cur_prob->ignore_compile_errors) {
          pinfo[re.prob_id].attempts++;
          cur_score = 0;
          if (cur_score >= pinfo[re.prob_id].best_score
              || pinfo[re.prob_id].best_run < 0) {
            pinfo[re.prob_id].best_score = cur_score;
            pinfo[re.prob_id].best_run = run_id;
          }
        }
        break;
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_SYNC_ERR:
        pinfo[re.prob_id].attempts++;
        cur_score = score;
        if (cur_score >= pinfo[re.prob_id].best_score
            || pinfo[re.prob_id].best_run < 0) {
          pinfo[re.prob_id].best_score = cur_score;
          pinfo[re.prob_id].best_run = run_id;
        }
        break;

      case RUN_PARTIAL:
      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
        break;

      case RUN_ACCEPTED:
      case RUN_PENDING_REVIEW:
      case RUN_PENDING:
        pinfo[re.prob_id].pending_flag = 1;
        pinfo[re.prob_id].attempts++;
        if (pinfo[re.prob_id].best_run < 0) pinfo[re.prob_id].best_run = run_id;
        break;

      default:
        abort();
      }
    } else {
      // ACM contest
      if (pinfo[re.prob_id].solved_flag) continue;

      switch (status) {
      case RUN_OK:
        pinfo[re.prob_id].solved_flag = 1;
        pinfo[re.prob_id].best_run = run_id;
        break;

      case RUN_COMPILE_ERR:
      case RUN_STYLE_ERR:
      case RUN_REJECTED:
        if (!cur_prob->ignore_compile_errors) {
          pinfo[re.prob_id].attempts++;
          pinfo[re.prob_id].best_run = run_id;
        }
        break;
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_CHECK_FAILED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_SYNC_ERR:
        pinfo[re.prob_id].attempts++;
        pinfo[re.prob_id].best_run = run_id;
        break;

      case RUN_PARTIAL:
      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
        break;
 
      case RUN_ACCEPTED:
      case RUN_PENDING_REVIEW:
      case RUN_PENDING:
        pinfo[re.prob_id].pending_flag = 1;
        pinfo[re.prob_id].attempts++;
        if (pinfo[re.prob_id].best_run < 0) pinfo[re.prob_id].best_run = run_id;
        break;

      default:
        abort();
      }
    }
  }

  xfree(user_flag);

  // nothing before contest start
  if (start_time <= 0) return;

  for (int prob_id = 1; prob_id <= cs->max_prob; prob_id++) {
    if (!(cur_prob = cs->probs[prob_id])) continue;

    // the problem is completely disabled before its start_date
    if (!serve_is_problem_started(cs, user_id, cur_prob))
      continue;

    // the problem is completely disabled before requirements are met
    // check requirements
    if (cur_prob->require) {
      int j;
      for (j = 0; cur_prob->require[j]; j++) {
        int k;
        for (k = 1; k <= cs->max_prob; k++) {
          if (cs->probs[k]
              && !strcmp(cs->probs[k]->short_name, cur_prob->require[j]))
            break;
        }
        // no such problem :(
        if (k > cs->max_prob) break;
        // this problem is not yet accepted or solved
        if (!pinfo[k].solved_flag && !pinfo[k].accepted_flag) break;
      }
      // if the requirements are not met, skip this problem
      if (cur_prob->require[j]) continue;
    }

    // check problem deadline
    time_t user_deadline = 0;
    int is_deadlined = serve_is_problem_deadlined(cs, user_id, user_login,
                                                  cur_prob, &user_deadline);

    if (cur_prob->unrestricted_statement > 0 || !is_deadlined)
      pinfo[prob_id].status |= PROB_STATUS_VIEWABLE;

    if (!is_deadlined && cur_prob->disable_user_submit <= 0
        && (cur_prob->disable_submit_after_ok <= 0 || !pinfo[prob_id].solved_flag))
      pinfo[prob_id].status |= PROB_STATUS_SUBMITTABLE;

    if (cur_prob->disable_tab <= 0)
      pinfo[prob_id].status |= PROB_STATUS_TABABLE;
  }
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
  const unsigned char *s_beg = 0, *s_end = 0;
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

TestingQueueArray *
testing_queue_array_free(TestingQueueArray *parr, int free_struct_flag)
{
  if (parr) {
    for (int i = 0; i < parr->u; ++i) {
      xfree(parr->v[i].queue_id);
      xfree(parr->v[i].entry_name);
      super_run_in_packet_free(parr->v[i].packet);
    }
    xfree(parr->v);
    memset(parr, 0, sizeof(*parr));
    if (free_struct_flag) xfree(parr);
  }
  return NULL;
}

static int
scan_run_sort_func(const void *v1, const void *v2)
{
  const TestingQueueEntry *p1 = (const TestingQueueEntry*)v1;
  const TestingQueueEntry *p2 = (const TestingQueueEntry*)v2;

  const unsigned char *qid1 = p1->queue_id;
  const unsigned char *qid2 = p2->queue_id;
  if (!qid1) qid1 = "";
  if (!qid2) qid2 = "";
  int v = strcmp(qid1, qid2);
  if (v) return v;

  return strcmp(p1->entry_name, p2->entry_name);
}

static void
ns_scan_run_queue_one(
        serve_state_t cs,
        const unsigned char *did,
        const unsigned char *dpath,
        struct TestingQueueArray *vec)
{
  path_t qpath;
  path_t path;
  DIR *d = NULL;
  struct dirent *dd;
  struct stat sb;
  char *pkt_buf = 0;
  size_t pkt_size = 0;
  struct super_run_in_packet *srp = NULL;
  int priority = 0;

  snprintf(qpath, sizeof(qpath), "%s/dir", dpath);
  if (!(d = opendir(qpath))) {
    return;
  }

  while ((dd = readdir(d))) {
    if (!strcmp(dd->d_name, ".") || !strcmp(dd->d_name, "..")) continue;
    snprintf(path, sizeof(path), "%s/%s", qpath, dd->d_name);
    if (lstat(path, &sb) < 0) continue;
    if (!S_ISREG(sb.st_mode)) continue;

    if (generic_read_file(&pkt_buf, 0, &pkt_size, 0, 0, path, 0) < 0)
      continue;

    if (!(srp = super_run_in_packet_parse_cfg_str(dd->d_name, pkt_buf, pkt_size))) {
      xfree(pkt_buf); pkt_buf = 0;
      pkt_size = 0;
      continue;
    }

    xfree(pkt_buf); pkt_buf = 0;
    pkt_size = 0;

    if (!srp->global || !srp->problem) {
      srp = super_run_in_packet_free(srp);
      continue;
    }

    /*
    if (srp->global->contest_id != contest_id) {
      srp = super_run_in_packet_free(srp);
      continue;
    }
    */

    priority = 0;
    if (dd->d_name[0] >= '0' && dd->d_name[0] <= '9') {
      priority = -16 + (dd->d_name[0] - '0');
    } else if (dd->d_name[0] >= 'A' && dd->d_name[0] <= 'V') {
      priority = -6 + (dd->d_name[0] - 'A');
    }

    if (vec->u == vec->a) {
      if (!vec->a) {
        vec->a = 32;
        XCALLOC(vec->v, vec->a);
      } else {
        int new_sz = vec->a * 2;
        struct TestingQueueEntry *new_v = 0;
        XCALLOC(new_v, new_sz);
        memcpy(new_v, vec->v, vec->a * sizeof(new_v[0]));
        xfree(vec->v);
        vec->v = new_v;
        vec->a = new_sz;
      }
    }

    TestingQueueEntry *cur = &vec->v[vec->u];
    memset(cur, 0, sizeof(*cur));

    cur->queue_id = xstrdup(did);
    cur->entry_name = xstrdup(dd->d_name);
    cur->priority = priority;
    cur->mtime = sb.st_mtime;
    cur->packet = srp; srp = 0;
    vec->u++;
  }

  if (d) closedir(d);
}

void
ns_scan_run_queue(
        serve_state_t cs,
        struct TestingQueueArray *vec)
{
  memset(vec, 0, sizeof(*vec));

  for (int i = 0; i < cs->run_queues_u; ++i) {
    ns_scan_run_queue_one(cs, cs->run_queues[i].id, cs->run_queues[i].queue_dir, vec);
  }

  qsort(vec->v, vec->u, sizeof(vec->v[0]), scan_run_sort_func);
}

static int
heartbeat_status_sort_func(const void *v1, const void *v2)
{
  const struct super_run_status_vector_item *i1 = *(const struct super_run_status_vector_item**) v1;
  const struct super_run_status_vector_item *i2 = *(const struct super_run_status_vector_item**) v2;
  const struct super_run_status *p1 = &i1->status;
  const struct super_run_status *p2 = &i2->status;
  const unsigned char *s1 = super_run_status_get_str(p1, super_run_idx);
  const unsigned char *s2 = super_run_status_get_str(p2, super_run_idx);
  return strcmp(s1, s2);
}

void
ns_scan_heartbeat_dirs(
        serve_state_t cs,
        struct super_run_status_vector *vec)
{
  memset(vec, 0, sizeof(*vec));
  for (int i = 0; i < cs->run_queues_u; ++i) {
    if (cs->run_queues[i].heartbeat_dir) {
      super_run_status_scan(cs->run_queues[i].id, cs->run_queues[i].heartbeat_dir, vec);
    }
  }
  qsort(vec->v, vec->u, sizeof(vec->v[0]), heartbeat_status_sort_func);
}

void
new_write_user_runs(
        const serve_state_t state,
        FILE *f,
        struct http_request_info *phr,
        unsigned int show_flags,
        int prob_id,
        const unsigned char *table_class,
        const UserProblemInfo *pinfo,
        int back_action,
        time_t start_time,
        time_t stop_time)
{
  const struct section_global_data *global = state->global;
  int i, showed, runs_to_show = 0;
  int attempts, disq_attempts, prev_successes;
  time_t time;
  unsigned char dur_str[64];
  unsigned char stat_str[128];
  unsigned char *prob_str;
  unsigned char *lang_str;
  unsigned char href[512];
  struct run_entry re;
  const unsigned char *run_kind_str = 0;
  struct section_problem_data *cur_prob;
  struct section_language_data *lang = 0;
  unsigned char *cl = "";
  int status;
  int enable_src_view = 0;
  int enable_rep_view = 0;
  int separate_user_score = 0;

  if (table_class && *table_class) {
    cl = alloca(strlen(table_class) + 16);
    sprintf(cl, " class=\"%s\"", table_class);
  }

  if (prob_id < 0 || prob_id > state->max_prob 
      || !state->probs || !state->probs[prob_id])
    prob_id = 0;

  if (prob_id > 0) runs_to_show = state->probs[prob_id]->prev_runs_to_show;
  if (runs_to_show <= 0) runs_to_show = 15;
  if (show_flags) runs_to_show = 100000;

  /* write run statistics: show last 15 in the reverse order */
  fprintf(f,"<table class=\"table\"><tr><th%s>%s</th><th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th><th%s>%s</th>",
          cl, _("Run ID"), cl, _("Time"), cl, _("Size"), cl, _("Problem"),
          cl, _("Language"));
  if (global->show_sha1 > 0) {
    fprintf(f, "<th%s>%s</th>", cl, "SHA1");
  }
  fprintf(f, "<th%s>%s</th>", cl, _("Result"));

  if (global->score_system == SCORE_KIROV
      || global->score_system == SCORE_OLYMPIAD) {
    fprintf(f, "<th%s>%s</th>", cl, _("Tests passed"));
    fprintf(f, "<th%s>%s</th>", cl, _("Score"));
  } else if (global->score_system == SCORE_MOSCOW) {
    fprintf(f, "<th%s>%s</th><th%s>%s</th>", cl, _("Failed test"),
            cl, _("Score"));
  } else {
    fprintf(f, "<th%s>%s</th>", cl, _("Failed test"));
  }

  enable_src_view = (state->online_view_source > 0 || (!state->online_view_source && global->team_enable_src_view > 0));
  enable_rep_view = (state->online_view_report > 0 || (!state->online_view_report && global->team_enable_rep_view > 0));
  separate_user_score = global->separate_user_score > 0 && state->online_view_judge_score <= 0;

  if (enable_src_view)
    fprintf(f, "<th%s>%s</th>", cl, _("View source"));
  if (enable_rep_view || global->team_enable_ce_view || global->enable_tokens > 0)
    fprintf(f, "<th%s>%s</th>", cl, _("View report"));
  if (global->enable_printing && !state->printing_suspended)
    fprintf(f, "<th%s>%s</th>", cl, _("Print sources"));

  fprintf(f, "</tr>\n");

  for (showed = 0, i = run_get_user_last_run_id(state->runlog_state, phr->user_id);
       i >= 0 && showed < runs_to_show;
       i = run_get_user_prev_run_id(state->runlog_state, i)) {
    if (run_get_entry(state->runlog_state, i, &re) < 0) continue;
    if (re.status == RUN_VIRTUAL_START || re.status == RUN_VIRTUAL_STOP
        || re.status == RUN_EMPTY)
      continue;
    if (re.user_id != phr->user_id) continue;
    if (prob_id > 0 && re.prob_id != prob_id) continue;

    cur_prob = 0;
    if (re.prob_id > 0 && re.prob_id <= state->max_prob && state->probs)
      cur_prob = state->probs[re.prob_id];
    if (!cur_prob) continue;

    showed++;

    lang = 0;
    if (re.lang_id > 0 && re.lang_id <= state->max_lang)
      lang = state->langs[re.lang_id];

    if (separate_user_score > 0 && re.is_saved) {
      if (re.token_count > 0 && (re.token_flags & TOKEN_FINALSCORE_BIT)) {
        status = re.status;
      } else {
        status = re.saved_status;
      }
    } else {
      status = re.status;
    }

    if (global->score_system == SCORE_OLYMPIAD && state->accepting_mode) {
      if (status == RUN_OK || status == RUN_PARTIAL)
        status = RUN_ACCEPTED;
    }

    attempts = 0; disq_attempts = 0;
    if (global->score_system == SCORE_KIROV && !re.is_hidden)
      run_get_attempts(state->runlog_state, i, &attempts, &disq_attempts,
                       cur_prob->ignore_compile_errors);

    prev_successes = RUN_TOO_MANY;
    if (global->score_system == SCORE_KIROV
        && status == RUN_OK
        && !re.is_hidden
        && cur_prob && cur_prob->score_bonus_total > 0) {
      if ((prev_successes = run_get_prev_successes(state->runlog_state, i)) < 0)
        prev_successes = RUN_TOO_MANY;
    }

    run_kind_str = "";
    if (re.is_imported) run_kind_str = "*";
    if (re.is_hidden) run_kind_str = "#";

    time = re.time;
    if (!start_time) time = start_time;
    if (start_time > time) time = start_time;
    duration_str(global->show_astr_time, time, start_time, dur_str, 0);
    run_status_str(status, stat_str, sizeof(stat_str), 0, 0);
    prob_str = "???";
    if (cur_prob) {
      if (cur_prob->variant_num > 0) {
        int variant = re.variant;
        if (!variant) variant = find_variant(state, re.user_id, re.prob_id, 0);
        prob_str = alloca(strlen(cur_prob->short_name) + 10);
        if (variant > 0) {
          sprintf(prob_str, "%s-%d", cur_prob->short_name, variant);
        } else {
          sprintf(prob_str, "%s-?", cur_prob->short_name);
        }
      } else {
        prob_str = cur_prob->short_name;
      }
    }
    lang_str = "???";
    if (!re.lang_id) lang_str = "N/A";
    if (lang) lang_str = lang->short_name;

    fprintf(f, "<tr>\n");
    fprintf(f, "<td%s>%d%s</td>", cl, i, run_kind_str);
    fprintf(f, "<td%s>%s</td>", cl, dur_str);
    fprintf(f, "<td%s>%u</td>", cl, re.size);
    fprintf(f, "<td%s>%s</td>", cl, prob_str);
    fprintf(f, "<td%s>%s</td>", cl, lang_str);
    if (global->show_sha1 > 0) {
      fprintf(f, "<td%s><tt>%s</tt></td>", cl, unparse_abbrev_sha1(re.sha1));
    }

    write_html_run_status(state, f, start_time, &re, 1 /* user_mode */,
                          0, attempts, disq_attempts,
                          prev_successes, table_class, 0, 0, RUN_VIEW_DEFAULT);

    if (enable_src_view) {
      fprintf(f, "<td%s>", cl);
      fprintf(f, "%s", ns_aref(href, sizeof(href), phr, NEW_SRV_ACTION_VIEW_SOURCE, "run_id=%d", i));
      fprintf(f, "%s</a>", _("View"));
      fprintf(f, "</td>");
    }
      /* FIXME: RUN_PRESENTATION_ERR and != standard problem type */
    if (cur_prob->enable_tokens > 0) {
      int enable_report_link = 0;
      int enable_use_link = 0;

      int available_tokens = compute_available_tokens(state, cur_prob, start_time);
      available_tokens -= pinfo[re.prob_id].token_count;
      if (available_tokens < 0) available_tokens = 0;

      switch (status) {
      case RUN_OK:
      case RUN_RUN_TIME_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_PRESENTATION_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_PARTIAL:
      case RUN_ACCEPTED:
      case RUN_DISQUALIFIED:
      case RUN_MEM_LIMIT_ERR:
      case RUN_SECURITY_ERR:
      case RUN_SYNC_ERR:
      case RUN_WALL_TIME_LIMIT_ERR:
      case RUN_PENDING_REVIEW:
      case RUN_REJECTED:
        if (cur_prob->team_enable_rep_view > 0) {
          enable_report_link = 1;
        } else if ((re.token_flags & TOKEN_TESTS_MASK)) {
          // report is paid by tokens
          enable_report_link = 1;
        }
        if (start_time > 0 && stop_time <= 0) {
          if (cur_prob->token_info
              && (re.token_flags & cur_prob->token_info->open_flags) != cur_prob->token_info->open_flags
              && available_tokens >= cur_prob->token_info->open_cost) {
            if (cur_prob->tokens_for_user_ac <= 0) {
              enable_use_link = 1;
            } else if (re.is_saved && re.saved_status == RUN_ACCEPTED) {
              enable_use_link = 1;
            }
          }
        }
        break;

      case RUN_COMPILE_ERR:
      case RUN_STYLE_ERR:
        if (cur_prob->team_enable_ce_view > 0 || cur_prob->team_enable_rep_view > 0) {
          // reports enabled by contest settings
          enable_report_link = 1;
        } else if ((re.token_flags & TOKEN_TESTS_MASK)) {
          // report is paid by tokens
          enable_report_link = 1;
        } else if (cur_prob->token_info && (cur_prob->token_info->open_flags & TOKEN_TESTS_MASK) != 0
                   && available_tokens >= cur_prob->token_info->open_cost) {
          enable_use_link = 1;
        }
        break;

        /*
      case RUN_CHECK_FAILED:
      case RUN_IGNORED:
      case RUN_PENDING:
      case RUN_SKIPPED:
        */
      default:
        // nothing
        ;
      }
      fprintf(f, "<td%s>", cl);
      if (!enable_report_link && !enable_use_link) {
        fprintf(f, "N/A");
      } else {
        if (enable_report_link) {
          fprintf(f, "[%s%s</a>]", ns_aref(href, sizeof(href), phr, NEW_SRV_ACTION_VIEW_REPORT, "run_id=%d", i), _("View"));
        }
        if (enable_use_link) {
          fprintf(f, "[%s%s", ns_aref(href, sizeof(href), phr, NEW_SRV_ACTION_USE_TOKEN, "run_id=%d&back_action=%d", i, back_action),
                  _("Use token"));
          fprintf(f, _(" (%d of %d)"), cur_prob->token_info->open_cost, available_tokens);
          fprintf(f, "</a>]");
        }
      }
      if (re.token_count > 0) {
        fprintf(f, _(" (%d token(s) used)"), re.token_count);
      }
      fprintf(f, "</td>");
    } else if (enable_rep_view) {
      fprintf(f, "<td%s>", cl);
      if (status == RUN_CHECK_FAILED || status == RUN_IGNORED
          || status == RUN_PENDING || status > RUN_MAX_STATUS
          || (cur_prob && !cur_prob->team_enable_rep_view)) {
        fprintf(f, "N/A");
      } else {
        fprintf(f, "%s%s</a>", ns_aref(href, sizeof(href), phr, NEW_SRV_ACTION_VIEW_REPORT, "run_id=%d", i),
                _("View"));
      }
      fprintf(f, "</td>");
    } else if (global->team_enable_ce_view) {
      fprintf(f, "<td%s>", cl);
      if (status != RUN_COMPILE_ERR && status != RUN_STYLE_ERR) {
        fprintf(f, "N/A");
      } else {
        fprintf(f, "%s%s</a>",
                ns_aref(href, sizeof(href), phr, NEW_SRV_ACTION_VIEW_REPORT, "run_id=%d", i),
                _("View"));
      }
      fprintf(f, "</td>");
    }

    if (global->enable_printing && !state->printing_suspended) {
      fprintf(f, "<td%s>", cl);
      if (re.pages > 0) {
        fprintf(f, "N/A");
      } else {
        fprintf(f, "%s%s</a>",
                ns_aref(href, sizeof(href), phr, NEW_SRV_ACTION_PRINT_RUN, "run_id=%d", i),
                _("Print"));
      }
      fprintf(f, "</td>\n");
    }

    fprintf(f, "\n</tr>\n");
  }
  fputs("</table>\n", f);
}

static unsigned char *
team_clar_flags(
        const serve_state_t state,
        int user_id,
        int clar_id,
        const ej_uuid_t *p_clar_uuid,
        int flags,
        int from,
        int to)
{
  if (from != user_id) {
    if (state->xuser_state && !state->xuser_state->vt->get_clar_status(state->xuser_state, user_id, clar_id, p_clar_uuid)) {
      return "N";
    }
    else return "&nbsp;";
  }
  if (!flags) return "U";
  return clar_flags_html(state->clarlog_state, flags, from, to, 0, 0);
}

void
new_write_user_clars(
        const serve_state_t state,
        FILE *f,
        struct http_request_info *phr,
        unsigned int show_flags,
        const unsigned char *table_class)
{
  const struct section_global_data *global = state->global;
  int showed, i, clars_to_show, n;
  time_t start_time, time;
  int show_astr_time = 0;

  char  dur_str[64];
  const unsigned char *psubj = 0;
  char *asubj = 0; /* html armored subj */
  int   asubj_len = 0; /* html armored subj len */
  unsigned char href[512];
  unsigned char *cl = "";
  struct clar_entry_v2 clar;
  const unsigned char *clar_flags = 0;

  if (table_class && *table_class) {
    cl = alloca(strlen(table_class) + 16);
    sprintf(cl, " class=\"%s\"", table_class);
  }

  start_time = run_get_start_time(state->runlog_state);
  if (global->is_virtual)
    start_time = run_get_virtual_start_time(state->runlog_state, phr->user_id);
  clars_to_show = 15;
  if (show_flags) clars_to_show = 100000;
  show_astr_time = global->show_astr_time;
  if (global->is_virtual) show_astr_time = 1;

  /* write clars statistics for the last 15 in the reverse order */
  fprintf(f,"<table class=\"table\"><tr><th%s>%s</th><th%s>%s</th><th%s>%s</th>"
          "<th%s>%s</th>"
          "<th%s>%s</th><th%s>%s</th>"
          "<th%s>%s</th><th%s>%s</th></tr>\n", cl,
          _("Clar ID"), cl, _("Flags"), cl, _("Time"), cl, _("Size"),
          cl, _("From"), cl, _("To"), cl, _("Subject"), cl, _("View"));
  for (showed = 0, i = clar_get_total(state->clarlog_state) - 1;
       showed < clars_to_show && i >= 0;
       i--) {
    if (clar_get_record(state->clarlog_state, i, &clar) < 0)
      continue;
    if (clar.id < 0) continue;
    if (clar.from > 0 && clar.from != phr->user_id) continue;
    if (clar.to > 0 && clar.to != phr->user_id) continue;
    if (start_time <= 0 && clar.hide_flag) continue;
    showed++;

    psubj = clar_get_subject(state->clarlog_state, i);
    n = html_armored_strlen(psubj);
    if (n + 4 > asubj_len) {
      asubj_len = (n + 7) & ~3;
      asubj = alloca(asubj_len);
    }
    html_armor_string(psubj, asubj);
    time = clar.time;
    if (!start_time) time = start_time;
    if (start_time > time) time = start_time;
    duration_str(show_astr_time, time, start_time, dur_str, 0);

    clar_flags = team_clar_flags(state, phr->user_id, i, &clar.uuid, clar.flags, clar.from, clar.to);
    fputs("<tr>", f);
    fprintf(f, "<td%s>%d</td>", cl, i);
    fprintf(f, "<td%s>%s</td>", cl, clar_flags);
    fprintf(f, "<td%s>%s</td>", cl, dur_str);
    fprintf(f, "<td%s>%zu</td>", cl, (size_t) clar.size);
    if (!clar.from) {
      fprintf(f, "<td%s><b>%s</b></td>", cl, _("judges"));
    } else {
      fprintf(f, "<td%s>%s</td>", cl,
              teamdb_get_login(state->teamdb_state, clar.from));
    }
    if (!clar.to && !clar.from) {
      fprintf(f, "<td%s><b>%s</b></td>", cl, _("all"));
    } else if (!clar.to) {
      fprintf(f, "<td%s><b>%s</b></td>", cl, _("judges"));
    } else {
      fprintf(f, "<td%s>%s</td>",
              cl, teamdb_get_login(state->teamdb_state, clar.to));
    }
    fprintf(f, "<td%s>%s</td>", cl, asubj);
    fprintf(f, "<td%s>", cl);
    if (clar.run_id > 0 && clar_flags && clar_flags[0] == 'N') {
      fprintf(f, "%s", ns_aref(href, sizeof(href), phr, NEW_SRV_ACTION_VIEW_SOURCE, "run_id=%d&clar_id=%d", clar.run_id - 1, i));
    } else if (clar.run_id > 0) {
      fprintf(f, "%s", ns_aref(href, sizeof(href), phr, NEW_SRV_ACTION_VIEW_SOURCE, "run_id=%d", clar.run_id - 1));
    } else {
      fprintf(f, "%s", ns_aref(href, sizeof(href), phr, NEW_SRV_ACTION_VIEW_CLAR, "clar_id=%d", i));
    }
    fprintf(f, "%s</a>", _("View"));
    fprintf(f, "</td>");
    fprintf(f, "</tr>\n");
  }
  fputs("</table>\n", f);
}

static const unsigned char *
html_make_title(unsigned char *buf, size_t size, const unsigned char *title)
{
  snprintf(buf, size, " title=\"%s\"", title);
  return buf;
}

int
write_xml_team_testing_report(
        const serve_state_t state,
        const struct section_problem_data *prob,
        FILE *f,
        struct http_request_info *phr,
        int output_only,
        int is_marked,
        int token_flags,
        const unsigned char *txt,
        const unsigned char *table_class)
{
  const struct section_global_data *global = state->global;
  testing_report_xml_t r = 0;
  struct testing_report_test *t;
  unsigned char *style = 0, *s, *font_color = 0;
  int need_comment = 0, need_info = 0, is_kirov = 0, i;
  unsigned char cl[128] = { 0 };
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int visibility = 0, serial = 0, has_full = 0, need_links = 0;
  int status, score, max_score;
  int run_tests, tests_passed;
  unsigned char hbuf[1024];
  unsigned char tbuf[1024];
  int hide_score = 0;

  if (table_class && *table_class) {
    snprintf(cl, sizeof(cl), " class=\"%s\"", table_class);
  }

  if (!(r = testing_report_parse_xml(txt))) {
    fprintf(f, "<p><big>Cannot parse XML file!</big></p>\n");
    return 0;
  }

  if (r->compile_error) {
    fprintf(f, "<h2 style=\"color: #A32C2C; margin-bottom: 7px;\">%s</h2>\n", run_status_str(r->status, 0, 0, 0, 0));
    if (r->compiler_output) {
      fprintf(f, "<pre>%s</pre>\n", ARMOR(r->compiler_output));
    }
    testing_report_free(r);
    html_armor_free(&ab);
    return 0;
  }

  status = r->status;
  score = r->score;
  max_score = r->max_score;
  run_tests = r->run_tests;
  tests_passed = r->tests_passed;
  if (global->separate_user_score > 0 && state->online_view_judge_score <= 0 && !(token_flags & TOKEN_FINALSCORE_BIT)) {
    if (r->user_status >= 0) status = r->user_status;
    if (r->user_score >= 0) score = r->user_score;
    if (r->user_max_score >= 0) max_score = r->user_max_score;
    if (r->user_run_tests >= 0) run_tests = r->user_run_tests;
    if (r->user_tests_passed >= 0) tests_passed = r->user_tests_passed;
  }

  if (status == RUN_OK || status == RUN_ACCEPTED || status == RUN_PENDING_REVIEW) {
    style = "color: green; margin-bottom: 7px;";
  } else {
    style = "color: #A32C2C; margin-bottom: 7px;";
  }
  fprintf(f, "<h2 style=\"%s\">%s</h2>\n",
          style, run_status_str(status, 0, 0, output_only, 0));

  if (output_only) {
    if (r->run_tests != 1 || !(t = r->tests[0])) {
      testing_report_free(r);
      return 0;
    }
    fprintf(f,
      "<table class=\"table\">"
      "<tr><th%s>N</th><th%s>%s</th>",
      cl, cl, _("Result"));
    if (t->score >= 0 && t->nominal_score >= 0)
      fprintf(f, "<th%s>%s</th>", cl, _("Score"));
    if (t->status == RUN_PRESENTATION_ERR || prob->show_checker_comment > 0) {
      fprintf(f, "<th%s>%s</th>", cl, _("Extra info"));
    }
    fprintf(f, "</tr>\n");

    fprintf(f, "<tr>");
    fprintf(f, "<td%s>%d</td>", cl, t->num);
    if (t->status == RUN_OK || t->status == RUN_ACCEPTED || t->status == RUN_PENDING_REVIEW) {
      font_color = "green";
    } else {
      font_color = "red";
    }
    fprintf(f, "<td%s><font color=\"%s\">%s</font></td>\n",
            cl, font_color, run_status_str(t->status, 0, 0, output_only, 0));
    if (t->score >= 0 && t->nominal_score >= 0)
      fprintf(f, "<td%s>%d (%d)</td>", cl, t->score, t->nominal_score);
    if (t->status == RUN_PRESENTATION_ERR || prob->show_checker_comment > 0) {
      s = html_armor_string_dup(t->checker_comment);
      fprintf(f, "<td%s>%s</td>", cl, s);
      xfree(s); s = 0;
    }
    fprintf(f, "</table>\n");
    testing_report_free(r);
    return 0;
  }

  if (r->scoring_system == SCORE_KIROV ||
      (r->scoring_system == SCORE_OLYMPIAD && !r->accepting_mode)) {
    is_kirov = 1;
  }

  if (is_kirov) {
    fprintf(f, _("<big>%d total tests runs, %d passed, %d failed.<br/>\n"),
            run_tests, tests_passed, run_tests - tests_passed);
    fprintf(f, _("Score gained: %d (out of %d).<br/><br/></big>\n"),
            score, max_score);
  } else {
    if (status != RUN_OK && status != RUN_ACCEPTED && status != RUN_PENDING_REVIEW) {
      fprintf(f, _("<big>Failed test: %d.<br/><br/></big>\n"), r->failed_test);
    }
  }

  /*
  if (r->comment) {
    s = html_armor_string_dup(r->comment);
    fprintf(f, "<big>Note: %s.<br/><br/></big>\n", s);
    xfree(s);
  }
  */

  if (r->valuer_comment) {
    fprintf(f, "<p><b>%s</b>:<br/></p><pre>%s</pre>\n", _("Valuer comments"),
            ARMOR(r->valuer_comment));
    hide_score = 1;
  }
  if ((token_flags & TOKEN_VALUER_JUDGE_COMMENT_BIT) && r->valuer_judge_comment) {
    fprintf(f, "<p><b>%s</b>:<br/></p><pre>%s</pre>\n", _("Valuer comments"),
            ARMOR(r->valuer_judge_comment));
    hide_score = 1;
  }

  for (i = 0; i < r->run_tests; ++i) {
    if (!(t = r->tests[i])) continue;
    // TV_NORMAL, TV_FULL, TV_FULLIFMARKED, TV_BRIEF, TV_EXISTS, TV_HIDDEN
    visibility = cntsprob_get_test_visibility(prob, i + 1, state->online_final_visibility, token_flags);
    if (visibility == TV_FULLIFMARKED) {
      visibility = TV_HIDDEN;
      if (is_marked) visibility = TV_FULL;
    }
    if (visibility == TV_EXISTS || visibility == TV_HIDDEN) continue;
    if (t->team_comment) {
      need_comment = 1;
    }
    // for any visibility of TV_NORMAL, TV_FULL, TV_BRIEF
    if (global->report_error_code && t->status == RUN_RUN_TIME_ERR) {
      need_info = 1;
    }
    if (visibility == TV_FULL) {
      if (t->status == RUN_RUN_TIME_ERR) need_info = 1;
      has_full = 1;
      if (r->archive_available) need_links = 1;
    }
  }

  fprintf(f,
          "<table class=\"table\">"
          "<tr><th%s>N</th><th%s>%s</th><th%s>%s</th>",
          cl, cl, _("Result"), cl, _("Time (sec)")/*,
          cl, _("Real time (sec)")*/);
  if (need_info) {
    fprintf(f, "<th%s>%s</th>", cl, _("Extra info"));
  }
  if (is_kirov && !hide_score) {
    fprintf(f, "<th%s>%s</th>", cl, _("Score"));
  }
  if (need_comment) {
    fprintf(f, "<th%s>%s</th>", cl, _("Comment"));
  }
  if (need_links) {
    fprintf(f, "<th%s>%s</th>", cl, _("Links"));
  }

  fprintf(f, "</tr>\n");

  for (i = 0; i < r->run_tests; i++) {
    if (!(t = r->tests[i])) continue;
    // TV_NORMAL, TV_FULL, TV_FULLIFMARKED, TV_BRIEF, TV_EXISTS, TV_HIDDEN
    visibility = cntsprob_get_test_visibility(prob, i + 1, state->online_final_visibility, token_flags);
    if (visibility == TV_FULLIFMARKED) {
      visibility = TV_HIDDEN;
      if (is_marked) visibility = TV_FULL;
    }
    if (visibility == TV_HIDDEN) continue;
    ++serial;
    if (visibility == TV_EXISTS) {
      fprintf(f, "<tr>");
      fprintf(f, "<td%s>%d</td>", cl, serial);
      fprintf(f, "<td%s>&nbsp;</td>", cl); // status
      fprintf(f, "<td%s>&nbsp;</td>", cl); // time
      if (need_info) {
        fprintf(f, "<td%s>&nbsp;</td>", cl); // info
      }
      if (is_kirov && !hide_score) {
        fprintf(f, "<td%s>&nbsp;</td>", cl); // score
      }
      if (need_comment) {
        fprintf(f, "<td%s>&nbsp;</td>", cl); // info
      }
      fprintf(f, "</tr>\n");
      continue;
    }

    fprintf(f, "<tr>");
    fprintf(f, "<td%s>%d</td>", cl, serial);
    if (t->status == RUN_OK || t->status == RUN_ACCEPTED || t->status == RUN_PENDING_REVIEW) {
      font_color = "green";
    } else {
      font_color = "red";
    }
    fprintf(f, "<td%s><font color=\"%s\">%s</font></td>\n",
            cl, font_color, run_status_str(t->status, 0, 0, output_only, 0));
    if ((t->status == RUN_TIME_LIMIT_ERR || t->status == RUN_WALL_TIME_LIMIT_ERR) && r->time_limit_ms > 0) {
      fprintf(f, "<td%s>&gt;%d.%03d</td>", cl,
              r->time_limit_ms / 1000, r->time_limit_ms % 1000);
    } else {
      fprintf(f, "<td%s>%d.%03d</td>", cl, t->time / 1000, t->time % 1000);
    }
    /*
    if (t->real_time > 0) {
      disp_time = t->real_time;
      if (disp_time < t->time) disp_time = t->time;
      fprintf(f, "<td%s>%d.%03d</td>", cl, disp_time / 1000, disp_time % 1000);
    } else {
      fprintf(f, "<td%s>N/A</td>", cl);
    }
    */
    if (need_info) {
      fprintf(f, "<td%s>", cl);
      if (t->status == RUN_RUN_TIME_ERR
          && (global->report_error_code || visibility == TV_FULL)) {
        if (t->exit_comment) {
          fprintf(f, "%s", t->exit_comment);
        } else if (t->term_signal >= 0) {
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
    if (is_kirov && !hide_score) {
      fprintf(f, "<td%s>%d (%d)</td>", cl, t->score, t->nominal_score);
    }
    if (need_comment) {
      if (!t->team_comment) {
        fprintf(f, "<td%s>&nbsp;</td>", cl);
      } else {
        s = html_armor_string_dup(t->team_comment);
        fprintf(f, "<td%s>%s</td>", cl, s);
        xfree(s);
      }
    }
    if (need_links) {
      fprintf(f, "<td%s>", cl);
      if (visibility == TV_FULL) {
        fprintf(f, "&nbsp;%s[I]</a>",
                ns_aref_2(hbuf, sizeof(hbuf), phr,
                          html_make_title(tbuf, sizeof(tbuf), _("Test input data")),
                          NEW_SRV_ACTION_VIEW_TEST_INPUT,
                          "run_id=%d&test_num=%d",
                          r->run_id, t->num));
        if (t->output_available) {
          fprintf(f, "&nbsp;%s[O]</a>",
                  ns_aref_2(hbuf, sizeof(hbuf), phr,
                            html_make_title(tbuf, sizeof(tbuf), _("Program output")),
                            NEW_SRV_ACTION_VIEW_TEST_OUTPUT,
                            "run_id=%d&test_num=%d",
                            r->run_id, t->num));
        }
        if (r->correct_available) {
          fprintf(f, "&nbsp;%s[A]</a>",
                  ns_aref_2(hbuf, sizeof(hbuf), phr,
                            html_make_title(tbuf, sizeof(tbuf), _("Correct answer")),
                            NEW_SRV_ACTION_VIEW_TEST_ANSWER,
                            "run_id=%d&test_num=%d",
                            r->run_id, t->num));
        }
        if (t->stderr_available) {
          fprintf(f, "&nbsp;%s[E]</a>",
                  ns_aref_2(hbuf, sizeof(hbuf), phr,
                            html_make_title(tbuf, sizeof(tbuf), _("Program stderr output")),
                            NEW_SRV_ACTION_VIEW_TEST_ERROR,
                            "run_id=%d&test_num=%d",
                            r->run_id, t->num));
        }
        if (t->checker_output_available) {
          fprintf(f, "&nbsp;%s[C]</a>",
                  ns_aref_2(hbuf, sizeof(hbuf), phr,
                            html_make_title(tbuf, sizeof(tbuf), _("Checker output")),
                            NEW_SRV_ACTION_VIEW_TEST_CHECKER,
                            "run_id=%d&test_num=%d",
                            r->run_id, t->num));
        }
        if (r->info_available) {
          fprintf(f, "&nbsp;%s[F]</a>",
                  ns_aref_2(hbuf, sizeof(hbuf), phr,
                            html_make_title(tbuf, sizeof(tbuf), _("Test information")),
                            NEW_SRV_ACTION_VIEW_TEST_INFO,
                            "run_id=%d&test_num=%d",
                            r->run_id, t->num));
        }
      }
      fprintf(f, "</td>");
    }
    fprintf(f, "</tr>\n");
  }
  fprintf(f, "</table>\n");

  if (has_full) {
    fprintf(f, "<pre>");
    for (i = 0; i < r->run_tests; i++) {
      if (!(t = r->tests[i])) continue;
      if (t->status == RUN_SKIPPED) continue;
      visibility = cntsprob_get_test_visibility(prob, i + 1, state->online_final_visibility, token_flags);
      if (visibility == TV_FULLIFMARKED) {
        visibility = TV_HIDDEN;
        if (is_marked) visibility = TV_FULL;
      }
      if (visibility != TV_FULL) continue;
      if (!t->args && !t->args_too_long && t->input.size < 0
          && t->output.size < 0 && t->error.size < 0 && t->correct.size < 0 && t->checker.size < 0)
        continue;
      fprintf(f, _("<b>====== Test #%d =======</b>\n"), t->num);
      if (t->args || t->args_too_long) {
        fprintf(f, "<a name=\"%dL\"></a>", t->num);
        fprintf(f, _("<u>--- Command line arguments ---</u>\n"));
        if (t->args_too_long) {
          fprintf(f, _("<i>Command line is too long</i>\n"));
        } else {
          fprintf(f, "%s", ARMOR(t->args));
        }
      }
      if (t->input.size >= 0) {
        fprintf(f, "<a name=\"%dI\"></a>", t->num);
        html_print_testing_report_file_content(f, &ab, &t->input, TESTING_REPORT_INPUT);
      }
      if (t->output.size >= 0) {
        fprintf(f, "<a name=\"%dO\"></a>", t->num);
        html_print_testing_report_file_content(f, &ab, &t->output, TESTING_REPORT_OUTPUT);
      }
      if (t->correct.size >= 0) {
        fprintf(f, "<a name=\"%dA\"></a>", t->num);
        html_print_testing_report_file_content(f, &ab, &t->correct, TESTING_REPORT_CORRECT);
      }
      if (t->error.size >= 0) {
        fprintf(f, "<a name=\"%dE\"></a>", t->num);
        html_print_testing_report_file_content(f, &ab, &t->error, TESTING_REPORT_ERROR);
      }
      if (t->checker.size >= 0) {
        fprintf(f, "<a name=\"%dC\"></a>", t->num);
        html_print_testing_report_file_content(f, &ab, &t->checker, TESTING_REPORT_CHECKER);
      }
    }
    fprintf(f, "</pre>");
  }

  html_armor_free(&ab);
  testing_report_free(r);
  return 0;
}

int
write_xml_team_output_only_acc_report(
        FILE *f,
        const unsigned char *txt,
        int rid,
        const struct run_entry *re,
        const struct section_problem_data *prob,
        const unsigned char *table_class)
{
  testing_report_xml_t r = 0;
  struct testing_report_test *t;
  unsigned char *font_color = 0, *s;
  int i, act_status, tests_to_show;
  unsigned char *cl = "";
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (!(r = testing_report_parse_xml(txt))) {
    fprintf(f, "<p><big>Cannot parse XML file!</big></p>\n");
    return 0;
  }

  if (r->compile_error) {
    fprintf(f, "<h2><font color=\"red\">%s</font></h2>\n", run_status_str(r->status, 0, 0, 0, 0));
    if (r->compiler_output) {
      fprintf(f, "<pre>%s</pre>\n", ARMOR(r->compiler_output));
    }
    testing_report_free(r);
    html_armor_free(&ab);
    return 0;
  }

  if (table_class && *table_class) {
    cl = (unsigned char *) alloca(strlen(table_class) + 16);
    sprintf(cl, " class=\"%s\"", table_class);
  }

  act_status = r->status;
  if (act_status == RUN_OK || act_status == RUN_PARTIAL
      || act_status == RUN_WRONG_ANSWER_ERR)
    act_status = RUN_ACCEPTED;

  if (act_status == RUN_ACCEPTED) {
    font_color = "green";
  } else {
    font_color = "red";
  }
  fprintf(f, "<h2><font color=\"%s\">%s</font></h2>\n",
          font_color, run_status_str(act_status, 0, 0, 1, 0));

  /*
  if (act_status != RUN_ACCEPTED) {
    fprintf(f, _("<big>Failed test: %d.<br/><br/></big>\n"), r->failed_test);
  }
  */

  tests_to_show = r->run_tests;
  if (tests_to_show > 1) tests_to_show = 1;

  fprintf(f,
          "<table%s>"
          "<tr><th%s>N</th><th%s>%s</th><th%s>%s</th>",
          cl, cl, cl, _("Result"), cl, _("Extra info"));
  fprintf(f, "<th%s>%s</th>", cl, _("Link"));
  fprintf(f, "</tr>\n");
  for (i = 0; i < tests_to_show; i++) {
    if (!(t = r->tests[i])) continue;
    fprintf(f, "<tr>");
    fprintf(f, "<td%s>%d</td>", cl, t->num);
    act_status = t->status;
    if (act_status == RUN_OK || act_status == RUN_ACCEPTED || act_status == RUN_PENDING_REVIEW
        || act_status == RUN_WRONG_ANSWER_ERR) {
      act_status = RUN_OK;
      font_color = "green";
    } else {
      font_color = "red";
    }
    fprintf(f, "<td%s><font color=\"%s\">%s</font></td>\n",
            cl, font_color, run_status_str(act_status, 0, 0, 1, 0));
    // extra information
    fprintf(f, "<td%s>", cl);
    switch (t->status) {
    case RUN_OK:
    case RUN_ACCEPTED:
    case RUN_PENDING_REVIEW:
    case RUN_WRONG_ANSWER_ERR:
      fprintf(f, "&nbsp;");
      break;

    case RUN_RUN_TIME_ERR:
      if (t->exit_comment) {
        fprintf(f, "%s", t->exit_comment);
      } else if (t->term_signal >= 0) {
        fprintf(f, "%s %d (%s)", _("Signal"), t->term_signal,
                os_GetSignalString(t->term_signal));
      } else {
        fprintf(f, "%s %d", _("Exit code"), t->exit_code);
      }
      break;

    case RUN_TIME_LIMIT_ERR:
    case RUN_WALL_TIME_LIMIT_ERR:
      fprintf(f, "&nbsp;");
      break;

    case RUN_PRESENTATION_ERR:
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
    case RUN_SYNC_ERR:
      fprintf(f, "&nbsp;");
      break;

    default:
      fprintf(f, "&nbsp;");
    }
    fprintf(f, "</td>");
    fprintf(f, "</tr>\n");
  }
  fprintf(f, "</table>\n");

  testing_report_free(r);
  return 0;
}

int
write_xml_team_accepting_report(
        FILE *f,
        struct http_request_info *phr,        
        const unsigned char *txt,
        int rid,
        const struct run_entry *re,
        const struct section_problem_data *prob,
        int exam_mode,
        const unsigned char *table_class)
{
  testing_report_xml_t r = 0;
  struct testing_report_test *t;
  unsigned char *font_color = 0, *s;
  int need_comment = 0, i, act_status, tests_to_show;
  unsigned char opening_a[512];
  unsigned char *closing_a = "";
  unsigned char cl[128] = { 0 };
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (table_class && *table_class) {
    snprintf(cl, sizeof(cl), " class=\"%s\"", table_class);
  }

  if (prob->type > 0)
    return write_xml_team_output_only_acc_report(f, txt, rid, re, prob, table_class);

  if (!(r = testing_report_parse_xml(txt))) {
    fprintf(f, "<p><big>Cannot parse XML file!</big></p>\n");
    return 0;
  }

  if (r->compile_error) {
    fprintf(f, "<h2><font color=\"red\">%s</font></h2>\n", run_status_str(r->status, 0, 0, 0, 0));
    if (r->compiler_output) {
      fprintf(f, "<pre>%s</pre>\n", ARMOR(r->compiler_output));
    }
    testing_report_free(r);
    html_armor_free(&ab);
    return 0;
  }

  act_status = r->status;
  if (act_status == RUN_OK || act_status == RUN_PARTIAL)
    act_status = RUN_ACCEPTED;

  if (act_status == RUN_ACCEPTED) {
    font_color = "green";
  } else {
    font_color = "red";
  }
  fprintf(f, "<h2><font color=\"%s\">%s</font></h2>\n",
          font_color, run_status_str(act_status, 0, 0, 0, 0));

  if (act_status != RUN_ACCEPTED && act_status != RUN_PENDING_REVIEW) {
    fprintf(f, _("<big>Failed test: %d.<br/><br/></big>\n"), r->failed_test);
  }

  tests_to_show = r->run_tests;
  if (tests_to_show > prob->tests_to_accept)
    tests_to_show = prob->tests_to_accept;

  for (i = 0; i < tests_to_show; i++) {
    if (!(t = r->tests[i])) continue;
    if (t->comment || t->team_comment) {
      need_comment = 1;
      break;
    }
  }

  fprintf(f, "<table%s><tr><th%s>N</th>", cl, cl);
  fprintf(f, "<th%s>%s</th>", cl, _("Result"));
  if (!exam_mode)
    fprintf(f, "<th%s>%s</th>", cl, _("Time (sec)")/*,
            cl, _("Real time (sec)")*/);
  fprintf(f, "<th%s>%s</th>", cl, _("Extra info"));
  if (need_comment) {
    fprintf(f, "<th%s>%s</th>", cl, _("Comment"));
  }
  if (!exam_mode) fprintf(f, "<th%s>%s</th>", cl, _("Link"));
  fprintf(f, "</tr>\n");
  for (i = 0; i < tests_to_show; i++) {
    if (!(t = r->tests[i])) continue;
    fprintf(f, "<tr>");
    fprintf(f, "<td%s>%d</td>", cl, t->num);
    if (t->status == RUN_OK || t->status == RUN_ACCEPTED || t->status == RUN_PENDING_REVIEW) {
      font_color = "green";
    } else {
      font_color = "red";
    }
    fprintf(f, "<td%s><font color=\"%s\">%s</font></td>\n",
            cl, font_color, run_status_str(t->status, 0, 0, 0, 0));
    if (!exam_mode) {
      if ((t->status == RUN_TIME_LIMIT_ERR || t->status == RUN_WALL_TIME_LIMIT_ERR) && r->time_limit_ms > 0) {
        fprintf(f, "<td%s>&gt;%d.%03d</td>", cl,
                r->time_limit_ms / 1000, r->time_limit_ms % 1000);
      } else {
        fprintf(f, "<td%s>%d.%03d</td>", cl, t->time / 1000, t->time % 1000);
      }
      /*
      if (t->real_time > 0) {
        fprintf(f, "<td%s>%d.%03d</td>",
                cl, t->real_time / 1000, t->real_time % 1000);
      } else {
        fprintf(f, "<td%s>N/A</td>", cl);
      }
      */
    }
    // extra information
    fprintf(f, "<td%s>", cl);
    switch (t->status) {
    case RUN_OK:
    case RUN_ACCEPTED:
    case RUN_PENDING_REVIEW:
      if (t->checker_comment) {
        s = html_armor_string_dup(t->checker_comment);
        fprintf(f, "%s", s);
        xfree(s);
      } else {
        fprintf(f, "&nbsp;");
      }
      break;

    case RUN_RUN_TIME_ERR:
      if (t->exit_comment) {
        fprintf(f, "%s", t->exit_comment);
      } else if (t->term_signal >= 0) {
        fprintf(f, "%s %d (%s)", _("Signal"), t->term_signal,
                os_GetSignalString(t->term_signal));
      } else {
        fprintf(f, "%s %d", _("Exit code"), t->exit_code);
      }
      break;

    case RUN_TIME_LIMIT_ERR:
    case RUN_WALL_TIME_LIMIT_ERR:
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
    case RUN_SYNC_ERR:
      fprintf(f, "&nbsp;");
      break;

    default:
      fprintf(f, "&nbsp;");
    }
    fprintf(f, "</td>");
    if (need_comment) {
      if (t->comment) {
        s = html_armor_string_dup(t->comment);
        fprintf(f, "<td%s>%s</td>", cl, s);
        xfree(s);
      } else if (t->team_comment) {
        s = html_armor_string_dup(t->team_comment);
        fprintf(f, "<td%s>%s</td>", cl, s);
        xfree(s);
      } else {
        fprintf(f, "<td%s>&nbsp;</td>", cl);
      }
    }
    // links to extra information
    if (exam_mode) {
      fprintf(f, "</tr>\n");
      continue;
    }
    fprintf(f, "<td%s>", cl);
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
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_INPUT,
                    "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->input.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dI\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sI%s", opening_a, closing_a);
    // program output
    if (r->archive_available && t->output_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_OUTPUT,
                    "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->output.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dO\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sO%s", opening_a, closing_a);
    // correct output (answer)
    if (r->archive_available && r->correct_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_ANSWER,
                    "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->correct.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dA\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sA%s", opening_a, closing_a);
    // program stderr
    if (r->archive_available && t->stderr_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_ERROR,
                    "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->error.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dE\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sE%s", opening_a, closing_a);
    // checker output
    if (r->archive_available && t->checker_output_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_CHECKER,
                    "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->checker.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dC\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sC%s", opening_a, closing_a);
    // test info file
    if (r->archive_available && r->info_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_INFO,
                    "run_id=%d&test_num=%d", r->run_id, t->num);
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

  if (!exam_mode) {
    fprintf(f,
            "<br/><table%s><font size=\"-2\">\n"
            "<tr><td%s>L</td><td%s>%s</td></tr>\n"
            "<tr><td%s>I</td><td%s>%s</td></tr>\n"
            "<tr><td%s>O</td><td%s>%s</td></tr>\n"
            "<tr><td%s>A</td><td%s>%s</td></tr>\n"
            "<tr><td%s>E</td><td%s>%s</td></tr>\n"
            "<tr><td%s>C</td><td%s>%s</td></tr>\n"
            "<tr><td%s>F</td><td%s>%s</td></tr>\n"
            "</font></table>\n", cl,
            cl, cl, _("Command-line parameters"),
            cl, cl, _("Test input"),
            cl, cl, _("Program output"),
            cl, cl, _("Correct output"),
            cl, cl, _("Program output to stderr"),
            cl, cl, _("Checker output"),
            cl, cl, _("Additional test information"));
  }

  // print detailed test information
  fprintf(f, "<pre>");
  for (i = 0; i < tests_to_show; i++) {
    if (!(t = r->tests[i])) continue;
    if (!t->args && !t->args_too_long && t->input.size < 0
        && t->output.size < 0 && t->error.size < 0 && t->correct.size < 0 && t->checker.size < 0) continue;

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
    if (t->input.size >= 0) {
      fprintf(f, "<a name=\"%dI\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->input, TESTING_REPORT_INPUT);
    }
    if (t->output.size >= 0) {
      fprintf(f, "<a name=\"%dO\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->output, TESTING_REPORT_OUTPUT);
    }
    if (t->correct.size >= 0) {
      fprintf(f, "<a name=\"%dA\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->correct, TESTING_REPORT_CORRECT);
    }
    if (t->error.size >= 0) {
      fprintf(f, "<a name=\"%dE\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->error, TESTING_REPORT_ERROR);
    }
    if (t->checker.size >= 0) {
      fprintf(f, "<a name=\"%dC\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->checker, TESTING_REPORT_CHECKER);
    }
  }
  fprintf(f, "</pre>");

  testing_report_free(r);
  return 0;
}

#define BGCOLOR_CHECK_FAILED " bgcolor=\"#FF80FF\""
#define BGCOLOR_FAIL         " bgcolor=\"#FF8080\""
#define BGCOLOR_PASS         " bgcolor=\"#80FF80\""

int
write_xml_team_tests_report(
        const serve_state_t state,
        const struct section_problem_data *prob,
        FILE *f,
        const unsigned char *txt,
        const unsigned char *table_class)
{
  testing_report_xml_t r = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  unsigned char *cl = 0;
  const unsigned char *font_color = 0;
  const unsigned char *comment = 0;
  const unsigned char *bgcolor = 0;
  const unsigned char *fail_str = 0;
  int i;
  struct testing_report_row *trr = 0;

  if (!(r = testing_report_parse_xml(txt))) {
    fprintf(f, "<p><big>Cannot parse XML file!</big></p>\n");
    fprintf(f, "<pre>%s</pre>\n", ARMOR(txt));
    goto done;
  }

  if (r->compile_error) {
    fprintf(f, "<h2><font color=\"red\">%s</font></h2>\n", run_status_str(r->status, 0, 0, 0, 0));
    if (r->compiler_output) {
      fprintf(f, "<pre>%s</pre>\n", ARMOR(r->compiler_output));
    }
    goto done;
  }

  if (!r->tests_mode) {
    fprintf(f, "<p><big>Invalid XML file!</big></p>\n");
    fprintf(f, "<pre>%s</pre>\n", ARMOR(txt));
    goto done;
  }

  if (table_class && *table_class) {
    cl = (unsigned char *) alloca(strlen(table_class) + 16);
    sprintf(cl, " class=\"%s\"", table_class);
  }

  if (r->status == RUN_CHECK_FAILED) {
    font_color = " color=\"magenta\"";
  } else if (r->status == RUN_OK || r->status == RUN_ACCEPTED || r->status == RUN_PENDING_REVIEW) {
    font_color = " color=\"green\"";
  } else {
    font_color = " color=\"red\"";
  }
  fprintf(f, "<h2><font%s>%s</font></h2>\n",
          font_color, run_status_str(r->status, 0, 0, 0, 0));

  if (r->status == RUN_CHECK_FAILED) {
    goto done;
  }

  if (r->errors && (r->tt_row_count <= 0 || r->tt_column_count <= 0)) {
    fprintf(f, "<h3>%s</h3>\n", _("Testing messages"));
    fprintf(f, "<pre>%s</pre>\n", ARMOR(r->errors));
  }

  if (r->tt_row_count <= 0 || r->tt_column_count <= 0) {
    goto done;
  }

  fprintf(f, "<p>%s: %d.</p>\n",
          _("Total number of sample programs in the test suite"),
          r->tt_row_count);
  fprintf(f, "<p>%s: %d.</p>\n",
          _("Total number of submitted tests"),
          r->tt_column_count);

  fprintf(f, "<table%s>\n", cl);
  fprintf(f, "<tr>");
  fprintf(f, "<td%s>NN</td>", cl);
  fprintf(f, "<td%s>Pass/fail</td>", cl);
  fprintf(f, "<td%s>%s</td>", cl, _("Comment"));
  fprintf(f, "</tr>\n");

  for (i = 0; i < r->tt_row_count; ++i) {
    fprintf(f, "<tr>");
    trr = r->tt_rows[i];
    comment = "&nbsp;";
    if (trr->status == RUN_CHECK_FAILED) {
      bgcolor = BGCOLOR_CHECK_FAILED;
    } else if (trr->status == RUN_OK) {
      if (trr->must_fail) {
        bgcolor = BGCOLOR_FAIL;
        comment = _("This test program is incorrect, but passed all tests");
      } else {
        bgcolor = BGCOLOR_PASS;
      }
    } else {
      if (trr->must_fail) {
        bgcolor = BGCOLOR_PASS;
      } else {
        bgcolor = BGCOLOR_FAIL;
        comment = _("This test program is correct, but failed on some tests");
      }
    }
    fail_str = "pass";
    if (trr->must_fail) fail_str = "fail";
    fprintf(f, "<td%s%s>%d</td>", cl, bgcolor, i + 1);
    fprintf(f, "<td%s%s>%s</td>", cl, bgcolor, fail_str);
    fprintf(f, "<td%s%s>%s</td>", cl, bgcolor, comment);
    fprintf(f, "</tr>\n");
  }

  fprintf(f, "</table>\n");


done:
  testing_report_free(r);
  html_armor_free(&ab);
  return 0;
}

int
write_xml_testing_report(
        FILE *f,
        struct http_request_info *phr,        
        int user_mode,
        unsigned char const *txt,
        const unsigned char *class1,
        const unsigned char *class2)
{
  testing_report_xml_t r = 0;
  unsigned char *s = 0;
  unsigned char *font_color = 0;
  int i, is_kirov = 0, need_comment = 0;
  struct testing_report_test *t;
  unsigned char opening_a[512];
  unsigned char *closing_a = "";
  unsigned char *cl1 = " border=\"1\"";
  unsigned char *cl2 = "";
  int max_cpu_time = -1, max_cpu_time_tl = -1;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;

  if (class1 && *class1) {
    cl1 = (unsigned char *) alloca(strlen(class1) + 16);
    sprintf(cl1, " class=\"%s\"", class1);
  }
  if (class2 && *class2) {
    cl2 = (unsigned char*) alloca(strlen(class2) + 16);
    sprintf(cl2, " class=\"%s\"", class2);
  }

  if (!(r = testing_report_parse_xml(txt))) {
    fprintf(f, "<p><big>Cannot parse XML file!</big></p>\n");
    s = html_armor_string_dup(txt);
    fprintf(f, "<pre>%s</pre>\n", s);
    xfree(s);
    return 0;
  }

  if (r->compile_error) {
    fprintf(f, "<h2><font color=\"red\">%s</font></h2>\n", run_status_str(r->status, 0, 0, 0, 0));
    if (r->compiler_output) {
      fprintf(f, "<pre>%s</pre>\n", ARMOR(r->compiler_output));
    }
    testing_report_free(r);
    html_armor_free(&ab);
    return 0;
  }

  // report the testing status
  if (r->status == RUN_OK || r->status == RUN_ACCEPTED || r->status == RUN_PENDING_REVIEW) {
    font_color = "green";
  } else {
    font_color = "red";
  }
  fprintf(f, "<h2><font color=\"%s\">%s</font></h2>\n",
          font_color, run_status_str(r->status, 0, 0, 0, 0));

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
    if (r->status != RUN_OK && r->status != RUN_ACCEPTED && r->status != RUN_PENDING_REVIEW) {
      fprintf(f, _("<big>Failed test: %d.<br><br></big>\n"), r->failed_test);
    }
  }

  if (r->errors && r->errors[0]) {
    fprintf(f, "<font color=\"red\"><b><u>%s</u></b><br/><pre>%s</pre></font>\n",
            "Errors", ARMOR(r->errors));
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

  // calculate max CPU time
  for (i = 0; i < r->run_tests; i++) {
    if (!(t = r->tests[i])) continue;
    switch (t->status) {
    case RUN_OK:
    case RUN_RUN_TIME_ERR:
    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
    case RUN_SYNC_ERR:
      if (max_cpu_time_tl > 0) break;
      max_cpu_time_tl = 0;
      if (max_cpu_time < 0 || max_cpu_time < r->tests[i]->time) {
        max_cpu_time = r->tests[i]->time;
      }
      break;
    case RUN_TIME_LIMIT_ERR:
    case RUN_WALL_TIME_LIMIT_ERR:
      if (max_cpu_time_tl <= 0 || max_cpu_time < 0
          || max_cpu_time < r->tests[i]->time) {
        max_cpu_time = r->tests[i]->time;
      }
      max_cpu_time_tl = 1;
      break;
    }
  }

  if (r->time_limit_ms > 0 && max_cpu_time_tl > 0) {
    fprintf(f, "<big>Max. CPU time: &gt;%d.%03d (time-limit exceeded)<br><br></big>\n", r->time_limit_ms / 1000, r->time_limit_ms % 1000);
  } else if (max_cpu_time_tl > 0) {
    fprintf(f, "<big>Max. CPU time: %d.%03d (time-limit exceeded)<br><br></big>\n", max_cpu_time / 1000, max_cpu_time % 1000);
  } else if (!max_cpu_time_tl && max_cpu_time >= 0) {
    fprintf(f, "<big>Max. CPU time: %d.%03d<br><br></big>\n",
            max_cpu_time / 1000, max_cpu_time % 1000);
  }

  if (r->host && !user_mode) {
    fprintf(f, "<big>Tested on host: %s</big><br/><br/>\n", r->host);
  }
  if (r->cpu_model && !user_mode) {
    fprintf(f, "<p>CPU model: %s</p>\n", r->cpu_model);
  }
  if (r->cpu_mhz && !user_mode) {
    fprintf(f, "<p>CPU MHz: %s</p>\n", r->cpu_mhz);
  }

  if (r->comment) {
    s = html_armor_string_dup(r->comment);
    fprintf(f, "<big><u>Testing messages</u>:</big><br/><br/>\n");
    fprintf(f, "<pre>%s</pre>\n", s);
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
          "<table%s>"
          "<tr><th%s>N</th><th%s>%s</th><th%s>%s</th>",
          cl1, cl1, cl1,
          _("Result"), cl1, _("Time (sec)"));
  if (r->real_time_available) {
    fprintf(f, "<th%s>%s</th>", cl1, _("Real time (sec)"));
  }
  if (r->max_memory_used_available) {
    fprintf(f, "<th%s>%s</th>", cl1, _("Max memory used"));
  }
  fprintf(f, "<th%s>%s</th>", cl1, _("Extra info"));
  if (is_kirov) {
    fprintf(f, "<th%s>%s</th>", cl1, _("Score"));
  }
  if (need_comment) {
    fprintf(f, "<th%s>%s</th>", cl1, _("Comment"));
  }
  fprintf(f, "<th%s>%s</th>", cl1, _("Link"));
  fprintf(f, "</tr>\n");
  for (i = 0; i < r->run_tests; i++) {
    if (!(t = r->tests[i])) continue;
    fprintf(f, "<tr>");
    fprintf(f, "<td%s>%d</td>", cl1, t->num);
    if (t->status == RUN_OK || t->status == RUN_ACCEPTED || t->status == RUN_PENDING_REVIEW) {
      font_color = "green";
    } else {
      font_color = "red";
    }
    fprintf(f, "<td%s><font color=\"%s\">%s</font></td>\n", cl1,
            font_color, run_status_str(t->status, 0, 0, 0, 0));
    if (user_mode && (t->status == RUN_TIME_LIMIT_ERR || t->status == RUN_WALL_TIME_LIMIT_ERR)) {
      // tell lies about the running time in case of time limit :)
      if (r->time_limit_ms > 0) {
        fprintf(f, "<td%s>&gt;%d.%03d</td>", cl1,
                r->time_limit_ms / 1000, r->time_limit_ms % 1000);
      } else {
        fprintf(f, "<td%s>N/A</td>", cl1);
      }
      if (r->real_time_available) {
        fprintf(f, "<td%s>N/A</td>", cl1);
      }
    } else {
      fprintf(f, "<td%s>%d.%03d</td>", cl1, t->time / 1000, t->time % 1000);
      if (r->real_time_available) {
        fprintf(f, "<td%s>%d.%03d</td>", cl1,
                t->real_time / 1000, t->real_time % 1000);
      }
    }
    if (r->max_memory_used_available) {
      fprintf(f, "<td%s>%lu</td>", cl1, t->max_memory_used);
    }

    // extra information
    fprintf(f, "<td%s>", cl1);
    switch (t->status) {
    case RUN_OK:
    case RUN_ACCEPTED:
    case RUN_PENDING_REVIEW:
      if (t->checker_comment) {
        s = html_armor_string_dup(t->checker_comment);
        fprintf(f, "%s", s);
        xfree(s);
      } else {
        fprintf(f, "&nbsp;");
      }
      break;

    case RUN_RUN_TIME_ERR:
      if (t->exit_comment) {
        fprintf(f, "%s", t->exit_comment);
      } else if (t->term_signal >= 0) {
        fprintf(f, "%s %d (%s)", _("Signal"), t->term_signal,
                os_GetSignalString(t->term_signal));
      } else {
        fprintf(f, "%s %d", _("Exit code"), t->exit_code);
      }
      break;

    case RUN_TIME_LIMIT_ERR:
    case RUN_WALL_TIME_LIMIT_ERR:
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
    case RUN_SYNC_ERR:
      fprintf(f, "&nbsp;");
      break;

    default:
      fprintf(f, "&nbsp;");
    }
    fprintf(f, "</td>");
    if (is_kirov) {
      fprintf(f, "<td%s>%d (%d)</td>", cl1, t->score, t->nominal_score);
    }
    if (need_comment) {
      if (t->comment) {
        s = html_armor_string_dup(t->comment);
        fprintf(f, "<td%s>%s</td>", cl1, s);
        xfree(s);
      } else if (t->team_comment) {
        s = html_armor_string_dup(t->team_comment);
        fprintf(f, "<td%s>%s</td>", cl1, s);
        xfree(s);
      } else {
        fprintf(f, "<td%s>&nbsp;</td>", cl1);
      }
    }
    // links to extra information
    fprintf(f, "<td%s>", cl1);
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
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_INPUT,
              "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->input.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dI\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sI%s", opening_a, closing_a);
    // program output
    if (r->archive_available && t->output_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_OUTPUT,
              "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->output.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dO\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sO%s", opening_a, closing_a);
    // correct output (answer)
    if (r->archive_available && r->correct_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_ANSWER,
              "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->correct.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dA\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sA%s", opening_a, closing_a);
    // program stderr
    if (r->archive_available && t->stderr_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_ERROR,
              "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->error.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dE\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sE%s", opening_a, closing_a);
    // checker output
    if (r->archive_available && t->checker_output_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_CHECKER,
              "run_id=%d&test_num=%d", r->run_id, t->num);
      closing_a = "</a>";
    } else if (t->checker.size >= 0) {
      snprintf(opening_a, sizeof(opening_a), "<a href=\"#%dC\">", t->num);
      closing_a = "</a>";
    } else {
      opening_a[0] = 0;
      closing_a = "";
    }
    fprintf(f, "&nbsp;%sC%s", opening_a, closing_a);
    // test info file
    if (r->archive_available && r->info_available) {
      ns_aref(opening_a, sizeof(opening_a), phr, NEW_SRV_ACTION_VIEW_TEST_INFO,
              "run_id=%d&test_num=%d", r->run_id, t->num);
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
          "<br><table%s><font size=\"-2\">\n"
          "<tr><td%s>L</td><td%s>%s</td></tr>\n"
          "<tr><td%s>I</td><td%s>%s</td></tr>\n"
          "<tr><td%s>O</td><td%s>%s</td></tr>\n"
          "<tr><td%s>A</td><td%s>%s</td></tr>\n"
          "<tr><td%s>E</td><td%s>%s</td></tr>\n"
          "<tr><td%s>C</td><td%s>%s</td></tr>\n"
          "<tr><td%s>F</td><td%s>%s</td></tr>\n"
          "</font></table>\n", cl2,
          cl2, cl2, _("Command-line parameters"),
          cl2, cl2, _("Test input"),
          cl2, cl2, _("Program output"),
          cl2, cl2, _("Correct output"),
          cl2, cl2, _("Program output to stderr"),
          cl2, cl2, _("Checker output"),
          cl2, cl2, _("Additional test information"));


  // print detailed test information
  fprintf(f, "<pre>");
  for (i = 0; i < r->run_tests; i++) {
    if (!(t = r->tests[i])) continue;
    if (t->status == RUN_SKIPPED) continue;
    if (!t->args && !t->args_too_long && t->input.size < 0
        && t->output.size < 0 && t->error.size < 0 && t->correct.size < 0 && t->checker.size < 0) continue;

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
    if (t->input.size >= 0) {
      fprintf(f, "<a name=\"%dI\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->input, TESTING_REPORT_INPUT);
    }
    if (t->output.size >= 0) {
      fprintf(f, "<a name=\"%dO\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->output, TESTING_REPORT_OUTPUT);
    }
    if (t->correct.size >= 0) {
      fprintf(f, "<a name=\"%dA\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->correct, TESTING_REPORT_CORRECT);
    }
    if (t->error.size >= 0) {
      fprintf(f, "<a name=\"%dE\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->error, TESTING_REPORT_ERROR);
    }
    if (t->checker.size >= 0) {
      fprintf(f, "<a name=\"%dC\"></a>", t->num);
      html_print_testing_report_file_content(f, &ab, &t->checker, TESTING_REPORT_CHECKER);
    }
  }
  fprintf(f, "</pre>");

  testing_report_free(r);
  html_armor_free(&ab);
  return 0;
}
