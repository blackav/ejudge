/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2000-2004 Alexander Chernov <cher@ispras.ru> */

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

#include "html.h"
#include "misctext.h"
#include "pathutl.h"
#include "fileutl.h"
#include "runlog.h"
#include "clarlog.h"
#include "teamdb.h"
#include "prepare.h"
#include "base64.h"
#include "sformat.h"
#include "protocol.h"
#include "client_actions.h"
#include "copyright.h"
#include "archive_paths.h"
#include "team_extra.h"

#include <reuse/logger.h>
#include <reuse/xalloc.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <time.h>
#include <unistd.h>

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

FILE *
sf_fopen(char const *path, char const *flags)
{
  FILE *f = fopen(path, flags);
  if (f) return f;
  err("fopen(\"%s\",\"%s\") failed: %s", path, flags, os_ErrorMsg());
  return NULL;
}

void
new_write_user_runs(FILE *f, int uid, unsigned int show_flags,
                    int sid_mode, unsigned long long sid,
                    unsigned char const *self_url,
                    unsigned char const *hidden_vars,
                    unsigned char const *extra_args)
{
  int i, showed, runs_to_show;
  int attempts, score1;
  time_t start_time, time;
  unsigned char dur_str[64];
  unsigned char stat_str[64];
  unsigned char *prob_str;
  unsigned char *lang_str;
  unsigned char href[128];
  struct run_entry re;
  const unsigned char *run_kind_str = 0;

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
  } else {
    fprintf(f, "<th>%s</th>", _("Failed test"));
  }

  if (global->team_enable_src_view)
    fprintf(f, "<th>%s</th>", _("View source"));
  if (global->team_enable_rep_view || global->team_enable_ce_view)
    fprintf(f, "<th>%s</th>", _("View report"));

  fprintf(f, "</tr>\n");

  for (showed = 0, i = run_get_total() - 1;
       i >= 0 && showed < runs_to_show;
       i--) {
    if (run_get_entry(i, &re) < 0) continue;
    if (re.status == RUN_VIRTUAL_START || re.status == RUN_VIRTUAL_STOP
        || re.status == RUN_EMPTY)
      continue;
    attempts = 0;
    if (global->score_system_val == SCORE_KIROV && !re.is_hidden)
      run_get_attempts(i, &attempts, global->ignore_compile_errors);
    if (re.team != uid) continue;
    showed++;

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

    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars, extra_args);
    }
    fprintf(f, "<tr>\n");
    fprintf(f, "<td>%d%s</td>", i, run_kind_str);
    fprintf(f, "<td>%s</td>", dur_str);
    fprintf(f, "<td>%zu</td>", re.size);
    fprintf(f, "<td>%s</td>", prob_str);
    fprintf(f, "<td>%s</td>", lang_str);
    fprintf(f, "<td>%s</td>", stat_str);
    if (re.test <= 0) {
      fprintf(f, "<td>%s</td>", _("N/A"));
      if (global->score_system_val == SCORE_KIROV
          || global->score_system_val == SCORE_OLYMPIAD)
        fprintf(f, "<td>%s</td>", _("N/A"));
    } else if (global->score_system_val == SCORE_KIROV
               || global->score_system_val == SCORE_OLYMPIAD) {
      fprintf(f, "<td>%d</td>", re.test - 1);
      if (re.score == -1) {
        fprintf(f, "<td>%s</td>", _("N/A"));
      } else {
        if (global->score_system_val == SCORE_OLYMPIAD || re.is_hidden) {
          fprintf(f, "<td>%d</td>", re.score);
        } else {
          score1 = re.score - attempts * probs[re.problem]->run_penalty;
          if (score1 < 0) score1 = 0;
          fprintf(f, "<td>%d(%d)=%d</td>", re.score, attempts, score1);
        }
      }
    } else {
      fprintf(f, "<td>%d</td>", re.test);
    }
    if (global->team_enable_src_view) {
      fprintf(f, "<td>");
      if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
        fprintf(f, "<input type=\"submit\" name=\"source_%d\" value=\"%s\">\n",
                i, _("View"));
      } else {
        fprintf(f, "%s%s</a>", html_hyperref(href, sizeof(href), sid_mode, sid,
                                             self_url, extra_args,
                                             "source_%d=1", i), _("View"));
      }
      fprintf(f, "</td>");
    }
    if (global->team_enable_rep_view) {
      fprintf(f, "<td>");
      if (re.status == RUN_CHECK_FAILED || re.status == RUN_IGNORED
          || re.status > RUN_MAX_STATUS) {
        fprintf(f, "N/A");
      } else {
        if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
          fprintf(f, "<input type=\"submit\" name=\"report_%d\" value=\"%s\">\n", i, _("View"));
        } else {
          fprintf(f, "%s%s</a>", html_hyperref(href, sizeof(href), sid_mode, sid, self_url, extra_args, "report_%d=1", i), _("View"));
        }
      }
      fprintf(f, "</td>");
    } else if (global->team_enable_ce_view) {
      fprintf(f, "<td>");
      if (re.status != RUN_COMPILE_ERR) {
        fprintf(f, "N/A");
      } else {
        if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
          fprintf(f, "<input type=\"submit\" name=\"report_%d\" value=\"%s\">\n", i, _("View"));
        } else {
          fprintf(f, "%s%s</a>", html_hyperref(href, sizeof(href), sid_mode, sid, self_url, extra_args, "report_%d=1", i), _("View"));
        }
      }
      fprintf(f, "</td>");
    }

    fprintf(f, "\n</tr>\n");
    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      fputs("</form>\n", f);
    }
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
    if (from != user_id && !team_extra_get_clar_status(user_id, i))
      total++;
  }
  return total;
}

void
new_write_user_clars(FILE *f, int uid, unsigned int show_flags,
                     int sid_mode, unsigned long long sid,
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
    if (clar_get_record(i, &time, (unsigned long*) &size,
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

    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars, extra_args);
    }
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
    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      fprintf(f, "<input type=\"submit\" name=\"clar_%d\" value=\"%s\">\n",
              i, _("View"));
    } else {
      fprintf(f, "%s%s</a>", html_hyperref(href, sizeof(href), sid_mode, sid,
                                           self_url, extra_args,
                                           "clar_%d=1", i), _("View"));
    }
    fprintf(f, "</td>");
    fprintf(f, "</tr>\n");
    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      fputs("</form>\n", f);
    }
  }
  fputs("</table>\n", f);
}

int
new_write_user_clar(FILE *f, int uid, int cid)
{
  unsigned long start_time, size, time;
  int from, to;
  int  asubj_len, atxt_len;
  char subj[CLAR_MAX_SUBJ_LEN + 4];
  char psubj[CLAR_MAX_SUBJ_TXT_LEN + 4];
  char *asubj, *atxt;
  char dur_str[64];
  char cname[64];
  char *csrc = 0;
  int  csize = 0;
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
  fprintf(f, "<tr><td>%s:</td><td>%lu</td></tr>\n", _("Size"), size);
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
                global->standings_charset,
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
              global->standings_charset,
              header, header);
    }
  } else {
    fprintf(f, "<%s>%s</%s>\n", cur_contest->team_head_style,
            header, cur_contest->team_head_style);
  }
}


#define ALLOCAZERO(a,b) do { if (!XALLOCA(a,b)) goto alloca_failed; XMEMZERO(a,b); } while(0)

void
do_write_kirov_standings(FILE *f, int client_flag,
                         unsigned char const *footer_str,
                         int raw_flag)
{
  unsigned long start_time;
  unsigned long stop_time;
  unsigned long cur_time;

  int  t_max, t_tot, p_max, p_tot, r_tot;
  int *t_ind, *t_rev, *p_ind, *p_rev;
  unsigned char *t_runs;

  int i, k, j;

  int **prob_score;
  int **att_num;
  int **full_sol;
  int  *tot_score, *tot_full;
  int  *t_sort, *t_n1, *t_n2;
  char dur_str[1024];
  unsigned char *head_style;
  struct teamdb_export ttt;
  struct run_entry *runs;

  if (client_flag) head_style = cur_contest->team_head_style;
  else head_style = "h2";

  /* Check that the contest is started */
  start_time = run_get_start_time();
  stop_time = run_get_stop_time();
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
  ALLOCAZERO(t_ind, t_max);
  ALLOCAZERO(t_rev, t_max);
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
  ALLOCAZERO(p_ind, p_max);
  ALLOCAZERO(p_rev, p_max);
  for (i = 1, p_tot = 0; i < p_max; i++) {
    p_rev[i] = -1;
    if (!probs[i]) continue;
    p_rev[i] = p_tot;
    p_ind[p_tot++] = i;
  }

  /* calculation tables */
  /* prob_score[0..t_tot-1][0..p_tot-1] - maximum score for the problem
   * att_num[0..t_tot-1][0..p_tot-1]    - number of attempts made
   * tot_score[0..t_tot-1]              - total scores for teams
   * full_sol[0..t_tot-1][0..p_tot-1]   - 1, if full solution
   * tot_full[0..t_tot-1]               - total number of fully solved
   */
  ALLOCAZERO(prob_score, t_tot);
  ALLOCAZERO(att_num, t_tot);
  ALLOCAZERO(full_sol, t_tot);
  ALLOCAZERO(tot_score, t_tot);
  ALLOCAZERO(tot_full, t_tot);
  for (i = 0; i < t_tot; i++) {
    ALLOCAZERO(prob_score[i], p_tot);
    ALLOCAZERO(att_num[i], p_tot);
    ALLOCAZERO(full_sol[i], p_tot);
  }

  /* auxiluary sorting stuff */
  /* t_sort[0..t_tot-1] - indices of teams (sorted)
   * t_n1[0..t_tot-1]   - first place in interval in case of ties
   * t_n2[0..t_tot-1]   - last place in interval in case of ties
   */
  ALLOCAZERO(t_sort, t_tot);
  ALLOCAZERO(t_n1, t_tot);
  ALLOCAZERO(t_n2, t_tot);
  for (i = 0; i < t_tot; i++) t_sort[i] = i;

  for (k = 0; k < r_tot; k++) {
    int tind;
    int pind;
    int score, run_score;
    struct section_problem_data *p;
    struct run_entry *pe = &runs[k];

    if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP
        || pe->status == RUN_EMPTY) continue;
    if (pe->team <= 0 || pe->team >= t_max) continue;
    if (pe->problem <= 0 || pe->problem > max_prob) continue;
    if (pe->is_hidden) continue;
    tind = t_rev[pe->team];
    pind = p_rev[pe->problem];
    p = probs[pe->problem];
    if (!p || tind < 0 || pind < 0) continue;

    run_score = pe->score;
    if (global->score_system_val == SCORE_OLYMPIAD) {
      if (run_score == -1) run_score = 0;
      switch (pe->status) {
      case RUN_OK:
        full_sol[tind][pind] = 1;
      case RUN_PARTIAL:
        prob_score[tind][pind] = run_score;
        att_num[tind][pind]++;
        break;
      case RUN_ACCEPTED:
      case RUN_COMPILE_ERR:
      case RUN_TIME_LIMIT_ERR:
      case RUN_RUN_TIME_ERR:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_PRESENTATION_ERR:
        att_num[tind][pind]++;
        break;
      default:
        break;
      }
    } else {
      if (run_score == -1) run_score = 0;
      if (pe->status == RUN_OK) {
        if (!p->variable_full_score) run_score = p->full_score;
        score = run_score - p->run_penalty * att_num[tind][pind];
        if (score < 0) score = 0;
        if (score > prob_score[tind][pind]) prob_score[tind][pind] = score;
        att_num[tind][pind]++;
        full_sol[tind][pind] = 1;
      } else if (pe->status == RUN_PARTIAL) {
        score = run_score - p->run_penalty*att_num[tind][pind];
        if (score < 0) score = 0;
        if (score > prob_score[tind][pind]) prob_score[tind][pind] = score;
        att_num[tind][pind]++;
      } else if (pe->status==RUN_COMPILE_ERR&&!global->ignore_compile_errors) {
        att_num[tind][pind]++;
      } else {
        /* something like "compiling..." or "running..." */
      }
    }
  }

  /* compute the total for each team */
  for (i = 0; i < t_tot; i++) {
    for (j = 0; j < p_tot; j++) {
      tot_score[i] += prob_score[i][j];
      tot_full[i] += full_sol[i][j];
    }
  }

  /* sort the teams */
  for (i = 0; i < t_tot - 1; i++) {
    int maxind = i, temp;
    for (j = i + 1; j < t_tot; j++) {
      if (tot_score[t_sort[j]] > tot_score[t_sort[maxind]])
        maxind = j;
    }
    temp = t_sort[i];
    t_sort[i] = t_sort[maxind];
    t_sort[maxind] = temp;
  }

  /* now resolve ties */
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

  /* now print HTML table */
  cur_time = time(0);
  if (start_time > cur_time) cur_time = start_time;
  if (stop_time && cur_time > stop_time) cur_time = stop_time;

  if (raw_flag) {
    /* print table contents */
    for (i = 0; i < t_tot; i++) {
      int t = t_sort[i];

      fprintf(f, "%d;%d;", t_n1[i] + 1, t_n2[i] + 1);
      fprintf(f, "%d;", t_ind[t]);
      for (j = 0; j < p_tot; j++) {
        if (!att_num[t][j]) {
          fprintf(f, "0;0;;");
        } else if (full_sol[t][j]) {
          fprintf(f, "%d;1;%d;", att_num[t][j], prob_score[t][j]);
        } else {
          fprintf(f, "%d;0;%d;", att_num[t][j], prob_score[t][j]);
        }
      }
      fprintf(f, "%d;%d;", tot_full[t], tot_score[t]);
      fprintf(f, "\n");
    }
  } else {
    /* print table header */
    fprintf(f, "<table border=\"1\"%s><tr><th%s>%s</th><th%s>%s</th>",
            global->stand_table_attr,
            global->stand_place_attr, _("Place"),
            global->stand_team_attr, _("Team"));
    if (global->stand_extra_format[0]) {
      if (global->stand_extra_legend[0])
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                global->stand_extra_legend);
      else
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                _("Extra info"));
    }
    for (j = 0; j < p_tot; j++) {
      fprintf(f, "<th%s>", global->stand_prob_attr);
      if (global->prob_info_url[0]) {
        sformat_message(dur_str, sizeof(dur_str), global->prob_info_url,
                        NULL, probs[p_ind[j]], NULL, NULL, NULL);
        fprintf(f, "<a href=\"%s\">", dur_str);
      }
      fprintf(f, "%s", probs[p_ind[j]]->short_name);
      if (global->prob_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</th>");
    }
    fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>",
            global->stand_solved_attr, _("Solved<br>problems"),
            global->stand_score_attr, _("Score"));
    
    /* print table contents */
    for (i = 0; i < t_tot; i++) {
      int t = t_sort[i];

      if (global->team_info_url[0] || global->stand_extra_format[0]) {
        teamdb_export_team(t_ind[t], &ttt);
      } else {
        memset(&ttt, 0, sizeof(ttt));
      }
      fprintf(f, "<tr><td%s>", global->stand_place_attr);
      if (t_n1[i] == t_n2[i]) fprintf(f, "%d", t_n1[i] + 1);
      else fprintf(f, "%d-%d", t_n1[i] + 1, t_n2[i] + 1);
      fputs("</td>", f);
      fprintf(f, "<td%s>", global->stand_team_attr);
      if (global->team_info_url[0]) {
        sformat_message(dur_str, sizeof(dur_str), global->team_info_url,
                        NULL, NULL, NULL, NULL, &ttt);
        fprintf(f, "<a href=\"%s\">", dur_str);
      }
      fprintf(f, "%s", teamdb_get_name(t_ind[t]));
      if (global->team_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</td>");
      if (global->stand_extra_format[0]) {
        sformat_message(dur_str, sizeof(dur_str), global->stand_extra_format,
                        NULL, NULL, NULL, NULL, &ttt);
        fprintf(f, "<td%s>%s</td>", global->stand_extra_attr, dur_str);
      }
      for (j = 0; j < p_tot; j++) {
        if (!att_num[t][j]) {
          fprintf(f, "<td%s>&nbsp;</td>", global->stand_prob_attr);
        } else if (full_sol[t][j]) {
          fprintf(f, "<td%s><b>%d</b></td>", global->stand_prob_attr, 
                  prob_score[t][j]);
        } else {
          fprintf(f, "<td%s>%d</td>", global->stand_prob_attr, 
                  prob_score[t][j]);
        }
      }
      fprintf(f, "<td%s>%d</td><td%s>%d</td></tr>",
              global->stand_solved_attr, tot_full[t],
              global->stand_score_attr, tot_score[t]);
    }

    fputs("</table>\n", f);
    if (!client_flag) {
      if (footer_str) {
        process_template(f, footer_str, 0, 0, 0, get_copyright());
      } else {
        fputs("</body></html>", f);
      }
    }
  }

  return;
 alloca_failed: 
  err("alloca failed");
  return;
}

void
do_write_standings(FILE *f, int client_flag, int user_id,
                   unsigned char const *footer_str, int raw_flag)
{
  int      i, j;

  int     *t_ind;
  int      t_max;
  int      t_tot;
  int     *t_prob;
  int     *t_pen;
  int     *t_rev;
  int     *t_sort;
  int     *t_n1;
  int     *t_n2;
  int     *p_ind;
  int     *p_rev;
  int      p_max;
  int      p_tot;
  int    **calc;
  int      r_tot, k;
  int      tt, pp;

  unsigned long **ok_time;

  unsigned long start_time;
  unsigned long stop_time;
  unsigned long cur_time;
  time_t        contest_dur;
  time_t        current_dur, run_time;
  time_t        tdur = 0, tstart;

  char          url_str[1024];
  unsigned char *bgcolor_ptr;
  unsigned char *head_style;
  struct teamdb_export ttt;      
  struct run_entry *runs, *pe;
  unsigned char *t_runs;

  if (client_flag) head_style = cur_contest->team_head_style;
  else head_style = "h2";

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
  if (!XALLOCA(t_ind, t_max)) goto alloca_failed;
  XMEMZERO(t_ind, t_max);
  if (!XALLOCA(t_rev, t_max)) goto alloca_failed;
  XMEMZERO(t_rev, t_max);
  for (i = 1, t_tot = 0; i < t_max; i++) {
    t_rev[i] = -1;
    if (!teamdb_lookup(i)) continue;
    if ((teamdb_get_flags(i) & (TEAM_INVISIBLE | TEAM_BANNED))) continue;
    if (!t_runs[i]) continue;
    t_rev[i] = t_tot;
    t_ind[t_tot++] = i;
  }
  if (!XALLOCA(t_prob, t_tot)) goto alloca_failed;
  XMEMZERO(t_prob, t_tot);
  if (!XALLOCA(t_pen,t_tot)) goto alloca_failed;
  XMEMZERO(t_pen, t_tot);
  if (!XALLOCA(t_sort, t_tot)) goto alloca_failed;
  for (i = 0; i < t_tot; i++)
    t_sort[i] = i;
  if (!XALLOCA(t_n1, t_tot)) goto alloca_failed;
  if (!XALLOCA(t_n2, t_tot)) goto alloca_failed;

  /* make problem index */
  p_max = max_prob + 1;
  if (!XALLOCA(p_ind, p_max)) goto alloca_failed;
  XMEMZERO(p_ind, p_max);
  if (!XALLOCA(p_rev, p_max)) goto alloca_failed;
  XMEMZERO(p_rev, p_max);
  for (i = 1, p_tot = 0; i < p_max; i++) {
    p_rev[i] = -1;
    if (!probs[i]) continue;
    p_rev[i] = p_tot;
    p_ind[p_tot++] = i;
  }

  /* make calculation table */
  if (!XALLOCA(calc, t_tot)) goto alloca_failed;
  XMEMZERO(calc, t_tot);
  if (!XALLOCA(ok_time, t_tot)) goto alloca_failed;
  for (i = 0; i < t_tot; i++) {
    if (!XALLOCA(calc[i], p_tot)) goto alloca_failed;
    XMEMZERO(calc[i], p_tot);
    if (!XALLOCA(ok_time[i], p_tot)) goto alloca_failed;
    XMEMZERO(ok_time[i], p_tot);
  }

  /* now scan runs log */
  for (k = 0; k < r_tot; k++) {
    pe = &runs[k];
    run_time = pe->timestamp;
    if (pe->status == RUN_VIRTUAL_START || pe->status == RUN_VIRTUAL_STOP
        || pe->status == RUN_EMPTY) continue;
    if (pe->team <= 0 || pe->team >= t_max || t_rev[pe->team] < 0) continue;
    if (pe->problem <= 0 || pe->problem > max_prob || p_rev[pe->problem] < 0)
      continue;
    if (pe->is_hidden) continue;
    if (global->virtual) {
      // filter "future" virtual runs
      tstart = run_get_virtual_start_time(pe->team);
      ASSERT(run_time >= tstart);
      tdur = run_time - tstart;
      ASSERT(tdur <= contest_dur);
      if (user_id > 0 && tdur > current_dur) continue;
    }
    tt = t_rev[pe->team];
    pp = p_rev[pe->problem];

    if (pe->status == RUN_OK) {
      /* program accepted */
      if (calc[tt][pp] > 0) continue;

      t_pen[tt] += 20 * -calc[tt][pp];
      calc[tt][pp] = 1 - calc[tt][pp];
      t_prob[tt]++;
      if (global->virtual) {
        ok_time[tt][pp] = (tdur + 59) / 60;
        t_pen[tt] += ok_time[tt][pp];
      } else {
        if (run_time < start_time) run_time = start_time;
        ok_time[tt][pp] = (run_time - start_time + 59) / 60;
        t_pen[tt] += ok_time[tt][pp];
      }
    } else if (pe->status==RUN_COMPILE_ERR && !global->ignore_compile_errors) {
      if (calc[tt][pp] <= 0) calc[tt][pp]--;
    } else if (pe->status > RUN_OK && pe->status < RUN_CHECK_FAILED) {
      /* some error */
      if (calc[tt][pp] <= 0) calc[tt][pp]--;
    }
  }

  /* now sort the teams in the descending order */
  /* t_sort: sorted->unsorted index map */
  /* ties are resolved in the order of the team's ids */
  for (i = 0; i < t_tot - 1; i++) {
    int maxind = i, temp;
    for (j = i + 1; j < t_tot; j++) {
      if (t_prob[t_sort[j]] < t_prob[t_sort[maxind]]) continue;
      if (t_prob[t_sort[j]] > t_prob[t_sort[maxind]]) {
        maxind = j;
        continue;
      }
      /* t_prob[t_sort[j]] == t_prob[t_sort[maxind]] */
      if (t_pen[t_sort[j]] > t_pen[t_sort[maxind]]) continue;
      if (t_pen[t_sort[j]] < t_pen[t_sort[maxind]]) {
        maxind = j;
        continue;
      }
      /* t_pen[t_sort[j]] == t_pen[t_sort[maxind]] */
      if (t_sort[j] < t_sort[maxind]) {
        maxind = j;
      }
    }
    temp = t_sort[i];
    t_sort[i] = t_sort[maxind];
    t_sort[maxind] = temp;
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
      int t = t_sort[i];
      fprintf(f, "%d;%d;", t_n1[i] + 1, t_n2[i] + 1);
      fprintf(f, "%d;", t_ind[t]);
      for (j = 0; j < p_tot; j++) {
        if (calc[t][j] < 0) {
          fprintf(f, "%d;0;;", -calc[t][j]);
        } else if (calc[t][j] > 0) {
          fprintf(f, "%d;1;%ld;", calc[t][j] - 1, ok_time[t][j]);
        } else {
          fprintf(f, "0;0;;");
        }
      }
      fprintf(f, "%d;%d;", t_prob[t], t_pen[t]);
      fprintf(f, "\n");
    }
  } else {
    /* print table header */
    fprintf(f, "<table border=\"1\"%s><tr><th%s>%s</th><th%s>%s</th>",
            global->stand_table_attr,
            global->stand_place_attr, _("Place"),
            global->stand_team_attr, _("Team"));
    if (global->stand_extra_format[0]) {
      if (global->stand_extra_legend[0])
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                global->stand_extra_legend);
      else
        fprintf(f, "<th%s>%s</th>", global->stand_extra_attr,
                _("Extra info"));
    }
    for (j = 0; j < p_tot; j++) {
      fprintf(f, "<th%s>", global->stand_prob_attr);
      if (global->prob_info_url[0]) {
        sformat_message(url_str, sizeof(url_str), global->prob_info_url,
                        NULL, probs[p_ind[j]], NULL, NULL, NULL);
        fprintf(f, "<a href=\"%s\">", url_str);
      }
      fprintf(f, "%s", probs[p_ind[j]]->short_name);
      if (global->prob_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</th>");
    }
    fprintf(f, "<th%s>%s</th><th%s>%s</th></tr>",
            global->stand_solved_attr, _("Total"),
            global->stand_penalty_attr, _("Penalty"));

    for (i = 0; i < t_tot; i++) {
      int t = t_sort[i];
      bgcolor_ptr = 0;
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
      if (bgcolor_ptr) {
        fprintf(f, "<tr%s>", bgcolor_ptr);
      } else {
        fputs("<tr>", f);
      }
      fprintf(f, "<td%s>", global->stand_place_attr);
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
                        NULL, NULL, NULL, NULL, &ttt);
        fprintf(f, "<a href=\"%s\">", url_str);      
      }
      fprintf(f, "%s", teamdb_get_name(t_ind[t]));
      if (global->team_info_url[0]) {
        fprintf(f, "</a>");
      }
      fprintf(f, "</td>");
      if (global->stand_extra_format[0]) {
        sformat_message(url_str, sizeof(url_str), global->stand_extra_format,
                        NULL, NULL, NULL, NULL, &ttt);
        fprintf(f, "<td%s>%s</td>", global->stand_extra_attr, url_str);
      }
      for (j = 0; j < p_tot; j++) {
        fprintf(f, "<td%s>", global->stand_prob_attr);
        if (calc[t][j] < 0) {
          fprintf(f, "%d", calc[t][j]);
        } else if (calc[t][j] == 1) {
          fprintf(f, "+ <div%s>(%ld:%02ld)</div>",
                  global->stand_time_attr,
                  ok_time[t][j] / 60, ok_time[t][j] % 60);
        } else if (calc[t][j] > 0) {
          fprintf(f, "+%d <div%s>(%ld:%02ld)</div>", calc[t][j] - 1,
                  global->stand_time_attr,
                  ok_time[t][j] / 60, ok_time[t][j] % 60);
        } else {
          fprintf(f, "&nbsp;");
        }
        fputs("</td>", f);
      }
      fprintf(f, "<td%s>%d</td><td%s>%d</td></tr>",
              global->stand_solved_attr, t_prob[t],
              global->stand_penalty_attr, t_pen[t]);
    }
    
    fputs("</table>\n", f);
    if (!client_flag) {
      if (footer_str) {
        process_template(f, footer_str, 0, 0, 0, get_copyright());
      } else {
        fputs("</body></html>", f);
      } 
    }
  }
    
  return;

 alloca_failed: 
  err("alloca failed");
  return;
}

void
write_standings(char const *stat_dir, char const *name,
                char const *header_str, char const *footer_str)
{
  char    tbuf[64];
  path_t  tpath;
  FILE   *f;

  if (global->charset_ptr && global->standings_charset_ptr
      && global->charset_ptr != global->standings_charset_ptr) {
    unsigned char *html_ptr = 0;
    size_t html_len = 0;

    f = open_memstream((char**) &html_ptr, &html_len);
    write_standings_header(f, 0, 0, header_str, 0);
    if (global->score_system_val == SCORE_KIROV
        || global->score_system_val == SCORE_OLYMPIAD)
      do_write_kirov_standings(f, 0, footer_str, 0);
    else
      do_write_standings(f, 0, 0, footer_str, 0);
    fclose(f);
    if (!html_ptr) {
      html_ptr = xstrdup("");
      html_len = 0;
    }
    // FIXME: local encoding might be any
    str_koi8_to_enc_unchecked(global->standings_charset_ptr,
                              html_ptr, html_ptr);
    generic_write_file(html_ptr, html_len, SAFE, stat_dir, name, "");
    return;
  }

  sprintf(tbuf, "XXX_%lu%d", time(0), getpid());
  pathmake(tpath, stat_dir, "/", tbuf, 0);
  if (!(f = sf_fopen(tpath, "w"))) return;
  write_standings_header(f, 0, 0, header_str, 0);
  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD)
    do_write_kirov_standings(f, 0, footer_str, 0);
  else
    do_write_standings(f, 0, 0, footer_str, 0);
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
  int attempts, score1;

  char durstr[64], statstr[64];
  char *str1 = 0, *str2 = 0;

  struct run_entry *runs, *pe;

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
    break;
  default:
    abort();
  }

  if (header_str) {
    fprintf(f, "%s", header_str);
  } else {
    fprintf(f, "Content-type: text/plain; charset=koi8-r\n\n");
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

    time = pe->timestamp;
    run_get_attempts(i, &attempts, global->ignore_compile_errors);

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
          score1 = pe->score - attempts * probs[pe->problem]->run_penalty;
          if (score1 < 0) score1 = 0;
          fprintf(f, "<td>%d(%d)=%d</td>", pe->score, attempts, score1);
        }
      }
    } else {
      fprintf(f, "<td>%d</td>\n", pe->test);
    }
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
  int src_len = 0, html_len, src_flags;
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
                                        global->run_archive_dir,rid,0,0))<0){
    return -SRV_ERR_SYSTEM_ERROR;
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
new_write_user_report_view(FILE *f, int uid, int rid)
{
  int report_len = 0, html_len = 0, report_flags;
  path_t report_path;
  char *report = 0, *html_report;
  const unsigned char *archive_dir = 0;
  struct run_entry re;

  if (rid < 0 || rid >= run_get_total()) {
    err("invalid run_id: %d", rid);
    return -SRV_ERR_BAD_RUN_ID;
  }
  if (run_get_entry(rid, &re) < 0) {
    return -SRV_ERR_BAD_RUN_ID;
  }
  if (re.problem <= 0 || re.problem > max_prob || !probs[re.problem]) {
    err("get_record returned bad prob_id %d", re.problem);
    return -SRV_ERR_BAD_PROB_ID;
  }
  if (uid != re.team) {
    err("user ids does not match");
    return -SRV_ERR_ACCESS_DENIED;
  }
  if (!probs[re.problem]->team_enable_rep_view) {
    if (probs[re.problem]->team_enable_ce_view && re.status == RUN_COMPILE_ERR)
      archive_dir = global->report_archive_dir;
    else {
      err("viewing report is disabled for this problem");
      return -SRV_ERR_REPORT_DISABLED;
    }
  } else {
    if (probs[re.problem]->team_show_judge_report)
      archive_dir = global->report_archive_dir;
    else
      archive_dir = global->team_report_archive_dir;
  }

  report_flags = archive_make_read_path(report_path, sizeof(report_path),
                                        archive_dir, rid, 0, 0);
  if (report_flags < 0) return -SRV_ERR_SYSTEM_ERROR;
  if (generic_read_file(&report, 0, &report_len, report_flags,
                        0, report_path, "") < 0) {
    return -SRV_ERR_SYSTEM_ERROR;
  }
  
  html_len = html_armored_memlen(report, report_len);
  html_report = alloca(html_len + 16);
  html_armor_text(report, report_len, html_report);
  html_report[html_len] = 0;
  xfree(report);

  fprintf(f, "<pre>%s</pre>", html_report);
  return 0;
}

static void
print_nav_buttons(FILE *f,
                  int sid_mode, unsigned long long sid,
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

  if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
    html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<table><tr>"
            "<td><input type=\"submit\" name=\"refresh\" value=\"%s\"></td>",
            t1);
    if (global->virtual) {
      fprintf(f, "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>", ACTION_STANDINGS, t2);
    }
    fprintf(f, 
            "<td><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td>"
            "</tr></table></form>\n",
            ACTION_LOGOUT, t3);
  } else {
    fprintf(f, "<table><tr><td>");
    fprintf(f, "%s",
            html_hyperref(hbuf, sizeof(hbuf), sid_mode, sid, self_url,
                          extra_args, 0));
    fprintf(f, "%s</a></td><td>", t1);
    if (global->virtual) {
      fprintf(f, "%s",
              html_hyperref(hbuf, sizeof(hbuf), sid_mode, sid, self_url,
                            extra_args, "action=%d", ACTION_STANDINGS));
      fprintf(f, "%s</a></td><td>", t2);
    }
    fprintf(f, "%s",
            html_hyperref(hbuf, sizeof(hbuf), sid_mode, sid, self_url,
                          extra_args, "action=%d", ACTION_LOGOUT));
    fprintf(f, "%s</a></td></tr></table>", t3);
  }
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
                int sid_mode, unsigned long long sid,
                int all_runs, int all_clars,
                unsigned char const *self_url,
                unsigned char const *hidden_vars,
                unsigned char const *extra_args,
                time_t server_start, time_t server_end)
{
  int i;
  unsigned char hbuf[128];
  struct tm *dl_time;
  unsigned char dl_time_str[128];
  time_t current_time = time(0);
  unsigned char *prob_str;
  int unread_clars = 0;

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
      html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
      fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
              ACTION_START_VIRTUAL, _("Start virtual contest"));
      fprintf(f, "</form>\n");
    } else if (server_start && !server_end) {
      html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
      fprintf(f, "<input type=\"submit\" name=\"action_%d\" value=\"%s\">",
              ACTION_STOP_VIRTUAL, _("Stop virtual contest"));
      fprintf(f, "</form>\n");
    }
    print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                      0, 0, 0);
  }

  if (server_start && (!global->disable_clars || !global->disable_team_clars)){
    unread_clars = count_unread_clars(user_id);
    if (unread_clars > 0) {
      fprintf(f, _("<hr><big><b>You have %d unread message(s)!</b></big>\n"),
              unread_clars);
    }
  }

  if (server_start && !server_end) {
    fprintf(f, "<hr><a name=\"submit\"></a><%s>%s</%s>\n",
            cur_contest->team_head_style, _("Send a submission"),
            cur_contest->team_head_style);
    html_start_form(f, 2, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<table>\n");
    fprintf(f, "<tr><td>%s:</td><td>", _("Problem"));
    fprintf(f, "<select name=\"problem\"><option value=\"\">\n");
    for (i = 1; i <= max_prob; i++)
      if (probs[i]) {
        if (probs[i]->t_deadline && current_time >= probs[i]->t_deadline)
          continue;

        dl_time_str[0] = 0;
        if (probs[i]->t_deadline && global->show_deadline) {
          dl_time = localtime(&probs[i]->t_deadline);
          snprintf(dl_time_str, sizeof(dl_time_str),
                   " (%04d/%02d/%02d %02d:%02d:%02d)",
                   dl_time->tm_year + 1900, dl_time->tm_mon + 1,
                   dl_time->tm_mday, dl_time->tm_hour,
                   dl_time->tm_min, dl_time->tm_sec);
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
        fprintf(f, "<option value=\"%d\">%s - %s%s\n",
                probs[i]->id, prob_str, probs[i]->long_name, dl_time_str);
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
    print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                      0, 0, 0);
  }

  if (server_start) {
    fprintf(f, "<hr><a name=\"runstat\"></a><%s>%s (%s)</%s>\n",
            cur_contest->team_head_style,
            _("Sent submissions"),
            all_runs?_("all"):_("last 15"),
            cur_contest->team_head_style);
    new_write_user_runs(f, user_id, all_runs,
                        sid_mode, sid, self_url, hidden_vars, extra_args);

    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars, extra_args);
      fprintf(f, "<p%s>"
              "<input type=\"submit\" name=\"all_runs\" value=\"%s\">"
              "</p>",
              cur_contest->team_par_style, _("View all"));
    } else {
      fprintf(f, "<p%s>%s%s</a></p>",
              cur_contest->team_par_style,
              html_hyperref(hbuf, sizeof(hbuf), sid_mode, sid, self_url,
                            extra_args, "all_runs=1"),
              _("View all"));
    }

    print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                      0, 0, 0);
    if (global->team_download_time > 0) {
      fprintf(f, "<p%s>", cur_contest->team_par_style);
      html_start_form(f, 1, sid_mode, sid, self_url, hidden_vars, extra_args);
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
    html_start_form(f, 2, sid_mode, sid, self_url, hidden_vars, extra_args);
    fprintf(f, "<table><tr><td>%s:</td><td>", _("Problem"));
    fprintf(f, "<select name=\"problem\"><option value=\"\">\n");
    for (i = 1; i <= max_prob; i++)
      if (probs[i]) {
        if (probs[i]->t_deadline && current_time >= probs[i]->t_deadline)
          continue;

        dl_time_str[0] = 0;
        if (probs[i]->t_deadline && global->show_deadline) {
          dl_time = localtime(&probs[i]->t_deadline);
          snprintf(dl_time_str, sizeof(dl_time_str),
                   " (%04d/%02d/%02d %02d:%02d:%02d)",
                   dl_time->tm_year + 1900, dl_time->tm_mon + 1,
                   dl_time->tm_mday, dl_time->tm_hour,
                   dl_time->tm_min, dl_time->tm_sec);
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
        fprintf(f, "<option value=\"%s\">%s - %s%s\n",
                probs[i]->short_name,
                prob_str, probs[i]->long_name, dl_time_str);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "<tr><td>%s:</td>"
            "<td><input type=\"text\" name=\"subject\"></td></tr>\n"
            "<tr><td colspan=\"2\"><textarea name=\"text\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n"
            "<tr><td colspan=\"2\"><input type=\"submit\" name=\"action_%d\" value=\"%s\"></td></tr>\n"
            "</table></form>\n",
            _("Subject"), ACTION_SUBMIT_CLAR, _("Send!"));
    print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
                      0, 0, 0);
  }

  if (!global->disable_clars) {
    fprintf(f, "<hr><a name=\"clarstat\"></a><%s>%s (%s)</%s>\n",
            cur_contest->team_head_style, _("Messages"),
            all_clars?_("all"):_("last 15"), cur_contest->team_head_style);

    new_write_user_clars(f, user_id, all_clars, sid_mode, sid,
                         self_url, hidden_vars, extra_args);

    if (sid_mode == SID_DISABLED || sid_mode == SID_EMBED) {
      html_start_form(f, 0, sid_mode, sid, self_url, hidden_vars, extra_args);
      fprintf(f, "<p%s>"
              "<input type=\"submit\" name=\"all_clars\" value=\"%s\">"
              "</p>",
              cur_contest->team_par_style, _("View all"));
    } else {
      fprintf(f, "<p%s>%s%s</a></p>",
              cur_contest->team_par_style,
              html_hyperref(hbuf, sizeof(hbuf), sid_mode, sid, self_url,
                            extra_args, "all_clars=1"),
              _("View all"));
    }

    print_nav_buttons(f, sid_mode, sid, self_url, hidden_vars, extra_args,
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
  write_standings_header(f, 1, user_id, 0, astr);
  do_write_standings(f, 1, user_id, 0, 0);
  return 0;
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 * End:
 */

