/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2000-2002 Alexander Chernov <cher@ispras.ru> */

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
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

FILE *
sf_fopen(char const *path, char const *flags)
{
  FILE *f = fopen(path, flags);
  if (f) return f;
  err("fopen(\"%s\",\"%s\") failed: %s", path, flags, os_ErrorMsg());
  return NULL;
}

void
write_clar_view(int id, char const *clar_dir,
                const char *dir, const char *name, int mode)
{
  FILE   *f = 0;
  path_t  path;

  unsigned long  time;
  unsigned long  size;
  unsigned long  start;
  char           ip[CLAR_MAX_IP_LEN + 16];
  char           subj[CLAR_MAX_SUBJ_LEN + 16];
  char           rsubj[CLAR_MAX_SUBJ_LEN + 16];
  char          *hsubj = 0;
  int            hsubj_len = 0;
  int            from;
  int            to;
  int            flags;
  char           durstr[64];

  char *full_txt = 0;
  char *full_txt_armored;
  int   ft_len = 0, fta_len = 0;
  char  full_name_buf[64];

  pathmake(path, dir, "/", name, NULL);
  info("writing clar view %d to %s", id, path);
  if (!(f = sf_fopen(path, "w"))) return;

  start = run_get_start_time();
  clar_get_record(id, &time, &size, ip, &from, &to, &flags, subj);
  hsubj_len = base64_decode(subj, strlen(subj), rsubj, 0);
  rsubj[hsubj_len] = 0;
  hsubj_len = html_armored_strlen(rsubj);
  hsubj_len = (hsubj_len + 7) & ~3;
  hsubj = alloca(hsubj_len);
  html_armor_string(rsubj, hsubj);
  duration_str(global->show_astr_time, time, start, durstr, 0);

  fprintf(f, "<h2>%s #%d</h2>\n", _("Message"), id);
  fprintf(f, "<table border=\"0\">\n");
  fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>\n", _("Number"), id);
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Flags"),
          clar_flags_html(flags, from, to, 0, 0));
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("Time"),durstr);
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>\n", _("IP address"), ip);
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
  fprintf(f, "<tr><td>%s:</td><td>%s</td></tr>", _("Subject"), hsubj);
  fprintf(f, "</table>\n");

  sprintf(full_name_buf, "%06d", id);
  if (generic_read_file(&full_txt, 0, &ft_len, 0,
                        clar_dir, full_name_buf, "") < 0) {
    fprintf(f, "<hr><big>%s</big><hr>\n", _("Cannot read message body"));
  } else {
    fta_len = html_armored_memlen(full_txt, ft_len);
    full_txt_armored = alloca(fta_len + 16);
    fta_len = html_armor_text(full_txt, ft_len, full_txt_armored);
    full_txt_armored[fta_len] = 0;
    fprintf(f, "<hr><pre>");
    fprintf(f, "%s", full_txt_armored);
    fprintf(f, "</pre><hr>");
  }
  fclose(f);
}

void
new_write_user_runs(FILE *f, int uid, unsigned int show_flags,
                    unsigned char const *form)
{
  int i, showed, runs_to_show, team_id, lang_id, prob_id;
  int status, test, score, attempts, score1;
  size_t size;
  time_t start_time, time;
  unsigned char dur_str[64];
  unsigned char stat_str[64];
  unsigned char *prob_str;
  unsigned char *lang_str;

  start_time = run_get_start_time();
  if (form && !*form) form = 0;
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

  if (global->team_enable_src_view && form)
    fprintf(f, "<th>%s</th>", _("View source"));
  if (global->team_enable_rep_view && form)
    fprintf(f, "<th>%s</th>", _("View report"));

  fprintf(f, "</tr>\n");

  for (showed = 0, i = run_get_total() - 1;
       i >= 0 && showed < runs_to_show;
       i--) {
    run_get_record(i, &time, &size, 0, 0, 0,
                   &team_id, &lang_id, &prob_id, &status, &test, &score);
    if (global->score_system_val == SCORE_KIROV)
      run_get_attempts(i, &attempts);
    if (team_id != uid) continue;
    showed++;

    if (!start_time) time = start_time;
    if (start_time > time) time = start_time;
    duration_str(global->show_astr_time, time, start_time, dur_str, 0);
    run_status_str(status, stat_str, 0);
    prob_str = "???";
    if (probs[prob_id]) prob_str = probs[prob_id]->short_name;
    lang_str = "???";
    if (langs[lang_id]) lang_str = langs[lang_id]->short_name;

    if (form) fprintf(f, "%s", form);
    fprintf(f, "<tr>\n");
    fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", dur_str);
    fprintf(f, "<td>%zu</td>", size);
    fprintf(f, "<td>%s</td>", prob_str);
    fprintf(f, "<td>%s</td>", lang_str);
    fprintf(f, "<td>%s</td>", stat_str);
    if (test <= 0) {
      fprintf(f, "<td>%s</td>", _("N/A"));
      if (global->score_system_val == SCORE_KIROV
          || global->score_system_val == SCORE_OLYMPIAD)
        fprintf(f, "<td>%s</td>", _("N/A"));
    } else if (global->score_system_val == SCORE_KIROV
               || global->score_system_val == SCORE_OLYMPIAD) {
      fprintf(f, "<td>%d</td>", test - 1);
      if (score == -1) {
        fprintf(f, "<td>%s</td>", _("N/A"));
      } else {
        if (global->score_system_val == SCORE_OLYMPIAD) {
          fprintf(f, "<td>%d</td>", score);
        } else {
          score1 = score - attempts * probs[prob_id]->run_penalty;
          if (score1 < 0) score1 = 0;
          fprintf(f, "<td>%d(%d)=%d</td>", score, attempts, score1);
        }
      }
    } else {
      fprintf(f, "<td>%d</td>", test);
    }
    if (global->team_enable_src_view) {
      fprintf(f, "<td><input type=\"submit\" name=\"source_%d\" value=\"%s\"></td>", i, _("view"));
    }
    if (global->team_enable_rep_view) {
      fprintf(f, "<td><input type=\"submit\" name=\"report_%d\" value=\"%s\"</td>", i, _("view"));
    }
    fprintf(f, "\n</tr>\n");
    if (form) fputs("</form>\n", f);
  }
  fputs("</table>\n", f);
}

void
new_write_user_clars(FILE *f, int uid, unsigned int show_flags,
                     unsigned char const *form)
{
  int showed, i, clars_to_show;
  int from, to, flags, n;
  size_t size;
  time_t start_time, time;

  char  dur_str[64];
  char  subj[CLAR_MAX_SUBJ_LEN + 4];      /* base64 subj */
  char  psubj[CLAR_MAX_SUBJ_TXT_LEN + 4]; /* plain text subj */
  char *asubj = 0; /* html armored subj */
  int   asubj_len = 0; /* html armored subj len */

  start_time = run_get_start_time();
  if (form && !*form) form = 0;
  clars_to_show = 15;
  if (show_flags) clars_to_show = 100000;

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
    duration_str(global->show_astr_time, time, start_time, dur_str, 0);

    if (form) fprintf(f, "%s", form);
    fputs("<tr>", f);
    fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", clar_flags_html(flags, from, to, 0, 0));
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
    fprintf(f, "<td><input type=\"submit\" name=\"clar_%d\" value=\"%s\"></td>\n", i, _("view"));

    fprintf(f, "</tr>\n");
    fputs("</form>\n", f);
  }
  fputs("</table>\n", f);
}

void
write_team_statistics(int team, int all_runs_flag, int all_clars_flag,
                      char const *dir, char const *name)
{
  path_t  path;
  FILE   *f = 0;

  pathmake(path, dir, "/", name, 0);
  info("team %d statistics to %s", team, path);
  if (!(f = sf_fopen(path, "w"))) return;
  new_write_user_runs(f, team, all_runs_flag, "$1");
  putc(1, f);
  new_write_user_clars(f, team, all_clars_flag, "$1");
  fclose(f);
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

  if (global->disable_clars) {
    err("clarifications are disabled");
    return -SRV_ERR_CLARS_DISABLED;
  }
  if (cid < 0 || cid >= clar_get_total()) {
    err("invalid clar_id %d", cid);
    return -SRV_ERR_BAD_CLAR_ID;
  }

  start_time = run_get_start_time();
  if (clar_get_record(cid, &time, &size, NULL,
                      &from, &to, NULL, subj) < 0) {
    return -SRV_ERR_BAD_CLAR_ID;
  }
  if (from > 0 && from != uid) return -SRV_ERR_ACCESS_DENIED;
  if (to > 0 && to != uid) return -SRV_ERR_ACCESS_DENIED;

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
  duration_str(global->show_astr_time, time, start_time, dur_str, 0);

  fprintf(f, "<h2>%s #%d</h2>\n", _("Message"), cid);
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

#define ALLOCAZERO(a,b) do { if (!XALLOCA(a,b)) goto alloca_failed; XMEMZERO(a,b); } while(0)

static void
do_write_kirov_standings(FILE *f, int client_flag,
                         char const *header_str, char const *footer_str)
{
  unsigned long start_time;
  unsigned long stop_time;
  unsigned long cur_time;

  int  t_max, t_tot, p_max, p_tot, r_tot;
  int *t_ind, *t_rev, *p_ind, *p_rev;

  int i, k, j;

  int **prob_score;
  int **att_num;
  int **full_sol;
  int  *tot_score, *tot_full;
  int  *t_sort, *t_n1, *t_n2;

  /* http header */
  char header[1024];
  char dur_str[1024];

  /* Check that the contest is started */
  start_time = run_get_start_time();
  stop_time = run_get_stop_time();
  if (!start_time) {
    if (global->name[0]) {
      sprintf(header, "%s &quot;%s&quot; - %s",
              _("Contest"), global->name, _("team standings"));
    } else {
      sprintf(header, "%s", _("Team standings"));
    }

    if (!client_flag) {
      if (header_str) {
        fprintf(f, header_str, global->charset, header, header);
      } else {
        fprintf(f, "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>%s</title></head><body><h1>%s</h1>\n",
                global->standings_charset,
                header, header);
      }
    } else {
      fprintf(f, "%s%c", header, 1);
    }
    fprintf(f, "<h2>%s</h2>", _("The contest is not started"));
    if (!client_flag) {
      if (footer_str) {
        fprintf(f, "%s", footer_str);
      } else {
        fprintf(f, "</body></html>");
      }
    }
    return;
  }

  /* The contest is started, so we can collect scores */

  /* make team index */
  /* t_tot             - total number of teams in index array
   * t_max             - maximal possible number of teams
   * t_ind[0..t_tot-1] - index array:   team_idx -> team_id
   * t_rev[0..t_max-1] - reverse index: team_id -> team_idx
   */
  t_max = teamdb_get_max_team_id() + 1;
  ALLOCAZERO(t_ind, t_max);
  ALLOCAZERO(t_rev, t_max);
  for (i = 1, t_tot = 0; i < t_max; i++) {
    t_rev[i] = -1;
    if (!teamdb_lookup(i)) continue;
    if ((teamdb_get_flags(i) & (TEAM_INVISIBLE | TEAM_BANNED))) continue;
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

  r_tot = run_get_total();
  for (k = 0; k < r_tot; k++) {
    int team_id;
    int prob_id;
    int status;
    int tests;
    int tind;
    int pind;
    int score;
    int run_score;

    struct section_problem_data *p;

    run_get_record(k, 0, 0, 0, 0, 0, &team_id, 0, &prob_id, &status, &tests,
                   &run_score);
    if (team_id <= 0 || team_id >= t_max) continue;
    if (prob_id <= 0 || prob_id > max_prob) continue;
    tind = t_rev[team_id];
    pind = p_rev[prob_id];
    p = probs[prob_id];
    if (!p || tind < 0 || pind < 0) continue;

    if (global->score_system_val == SCORE_OLYMPIAD) {
      if (run_score == -1) run_score = 0;
      switch (status) {
      case RUN_OK:
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
      if (status == RUN_OK) {
        score = p->full_score - p->run_penalty * att_num[tind][pind];
        if (score < 0) score = 0;
        if (score > prob_score[tind][pind]) prob_score[tind][pind] = score;
        att_num[tind][pind]++;
        full_sol[tind][pind] = 1;
      } else if (status == RUN_PARTIAL) {
        score = run_score - p->run_penalty*att_num[tind][pind];
        if (score < 0) score = 0;
        if (score > prob_score[tind][pind]) prob_score[tind][pind] = score;
        att_num[tind][pind]++;
      } else if (status == RUN_COMPILE_ERR) {
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
  duration_str(global->show_astr_time, cur_time, start_time, dur_str, 0);

  if (global->name[0]) {
    sprintf(header, "%s &quot;%s&quot; - %s [%s]",
            _("Contest"), global->name, _("team standings"), dur_str);
  } else {
    sprintf(header, "%s [%s]", _("Team standings"), dur_str);
  }

  if (!client_flag) {
    if (header_str) {
      fprintf(f, header_str, global->standings_charset, header, header);
    } else {
      fprintf(f, "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>%s</title></head><body><h1>%s</h1>",
              global->standings_charset,
              header, header);
    }
  } else {
    fprintf(f, "%s%c", header, 1);
  }

  /* print table header */
  fprintf(f, "<table border=\"1\"><tr><th>%s</th><th>%s</th>",
          _("Place"), _("Team"));
  for (j = 0; j < p_tot; j++) {
    fprintf(f, "<th>");
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
  fprintf(f, "<th>%s</th><th>%s</th></tr>",
          _("Solved<br>problems"), _("Score"));

  /* print table contents */
  for (i = 0; i < t_tot; i++) {
    int t = t_sort[i];
    fputs("<tr><td>", f);
    if (t_n1[i] == t_n2[i]) fprintf(f, "%d", t_n1[i] + 1);
    else fprintf(f, "%d-%d", t_n1[i] + 1, t_n2[i] + 1);
    fputs("</td>", f);
    fprintf(f, "<td>");
    if (global->team_info_url[0]) {
      struct teamdb_export ttt;

      teamdb_export_team(t_ind[t], &ttt);
      sformat_message(dur_str, sizeof(dur_str), global->team_info_url,
                      NULL, NULL, NULL, NULL, &ttt);
      fprintf(f, "<a href=\"%s\">", dur_str);
    }
    fprintf(f, "%s", teamdb_get_name(t_ind[t]));
    if (global->team_info_url[0]) {
      fprintf(f, "</a>");
    }
    fprintf(f, "</td>");
    for (j = 0; j < p_tot; j++) {
      if (!att_num[t][j]) {
        fprintf(f, "<td>&nbsp;</td>");
      } else if (full_sol[t][j]) {
        fprintf(f, "<td><b>%d</b></td>", prob_score[t][j]);
      } else {
        fprintf(f, "<td>%d</td>", prob_score[t][j]);
      }
    }
    fprintf(f, "<td>%d</td><td>%d</td></tr>",
            tot_full[t], tot_score[t]);
  }

  fputs("</table>\n", f);
  if (!client_flag) {
    if (footer_str) {
      fprintf(f, "%s", footer_str);
    } else {
      fputs("</body></html>", f);
    }
  }

  return;
 alloca_failed: 
  err("alloca failed");
  return;
}

static void
do_write_standings(FILE *f, int client_flag,
                   char const *header_str, char const *footer_str)
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

  char     dur_str[64];

  unsigned long start_time;
  unsigned long stop_time;
  unsigned long cur_time;
  unsigned long run_time;
  int           team_id;
  int           prob_id;
  int           score;
  int           status;

  char          header[1024];
  char          url_str[1024];

  start_time = run_get_start_time();
  stop_time = run_get_stop_time();
  if (!start_time) {
    if (global->name[0]) {
      sprintf(header, "%s &quot;%s&quot; - %s",
              _("Contest"), global->name, _("team standings"));
    } else {
      sprintf(header, "%s", _("Team standings"));
    }

    if (!client_flag) {
      if (header_str) {
        fprintf(f, header_str, global->standings_charset, header, header);
      } else {
        fprintf(f, "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>%s</title></head><body><h1>%s</h1>\n",
                global->standings_charset,
                header, header);
      }
    } else {
      fprintf(f, "%s%c", header, 1);
    }
    fprintf(f, "<h2>%s</h2>", _("The contest is not started"));
    if (!client_flag) {
      if (footer_str) {
        fprintf(f, "%s", footer_str);
      } else {
        fprintf(f, "</body></html>");
      }
    }
    return;
  }

  /* make team index */
  t_max = teamdb_get_max_team_id() + 1;
  if (!XALLOCA(t_ind, t_max)) goto alloca_failed;
  XMEMZERO(t_ind, t_max);
  if (!XALLOCA(t_rev, t_max)) goto alloca_failed;
  XMEMZERO(t_rev, t_max);
  for (i = 1, t_tot = 0; i < t_max; i++) {
    t_rev[i] = -1;
    if (!teamdb_lookup(i)) continue;
    if ((teamdb_get_flags(i) & (TEAM_INVISIBLE | TEAM_BANNED))) continue;
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
  r_tot = run_get_total();
  for (k = 0; k < r_tot; k++) {
    run_get_record(k, &run_time, 0, 0, 0, 0, &team_id, 0, &prob_id, &status, 0,
                   &score);
    if (team_id <= 0 || team_id >= t_max) continue;
    if (t_rev[team_id] < 0) continue;
    if (prob_id <= 0 || prob_id > max_prob) continue;
    if (p_rev[prob_id] < 0) continue;
    tt = t_rev[team_id];
    pp = p_rev[prob_id];

    if (status == 0) {
      /* program accepted */
      if (calc[tt][pp] > 0) continue;

      t_pen[tt] += 20 * -calc[tt][pp];
      calc[tt][pp] = 1 - calc[tt][pp];
      t_prob[tt]++;
      if (run_time < start_time) run_time = start_time;
      ok_time[tt][pp] = (run_time - start_time + 59) / 60;
      t_pen[tt] += ok_time[tt][pp];
    } else if (status > 0 && status < 6) {
      /* some error */
      if (calc[tt][pp] <= 0) calc[tt][pp]--;
    }
  }

  /* now sort the teams in the descending order */
  for (i = 0; i < t_tot - 1; i++) {
    int maxind = i, temp;
    for (j = i + 1; j < t_tot; j++) {
      if (t_prob[t_sort[j]] > t_prob[t_sort[maxind]]
          || (t_prob[t_sort[j]] == t_prob[t_sort[maxind]] && t_pen[t_sort[j]] < t_pen[t_sort[maxind]]))
        maxind = j;
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

  /* now print this stuff */
  cur_time = time(0);
  if (start_time > cur_time) cur_time = start_time;
  if (stop_time && cur_time > stop_time) cur_time = stop_time;
  duration_str(global->show_astr_time, cur_time, start_time, dur_str, 0);

  if (global->name[0]) {
    sprintf(header, "%s &quot;%s&quot; - %s [%s]",
            _("Contest"), global->name, _("team standings"), dur_str);
  } else {
    sprintf(header, "%s [%s]", _("Team standings"), dur_str);
  }

  if (!client_flag) {
    if (header_str) {
      fprintf(f, header_str, global->standings_charset, header, header);
    } else {
      fprintf(f, "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=%s\"><title>%s</title></head><body><h1>%s</h1>",
              global->standings_charset,
              header, header);
    }
  } else {
    fprintf(f, "%s%c", header, 1);
  }

  /* print table header */
  fprintf(f, "<table border=\"1\"><tr><th>%s</th><th>%s</th>",
          _("Place"), _("Team"));
  for (j = 0; j < p_tot; j++) {
    fprintf(f, "<th>");
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
  fprintf(f, "<th>%s</th><th>%s</th></tr>",
          _("Total"), _("Penalty"));

  for (i = 0; i < t_tot; i++) {
    int t = t_sort[i];
    fputs("<tr><td>", f);
    if (t_n1[i] == t_n2[i]) fprintf(f, "%d", t_n1[i] + 1);
    else fprintf(f, "%d-%d", t_n1[i] + 1, t_n2[i] + 1);
    fputs("</td>", f);
    fprintf(f, "<td>");
    if (global->team_info_url[0]) {
      struct teamdb_export ttt;

      teamdb_export_team(t_ind[t], &ttt);
      sformat_message(url_str, sizeof(url_str), global->team_info_url,
                      NULL, NULL, NULL, NULL, &ttt);
      fprintf(f, "<a href=\"%s\">", url_str);      
    }
    fprintf(f, "%s", teamdb_get_name(t_ind[t]));
    if (global->team_info_url[0]) {
      fprintf(f, "</a>");
    }
    fprintf(f, "</td>");
    for (j = 0; j < p_tot; j++) {
      if (calc[t][j] < 0) {
        fprintf(f, "<td>%d</td>", calc[t][j]);
      } else if (calc[t][j] == 1) {
        fprintf(f, "<td>+ (%ld:%02ld)</td>",
                ok_time[t][j] / 60, ok_time[t][j] % 60);
      } else if (calc[t][j] > 0) {
        fprintf(f, "<td>+%d (%ld:%02ld)</td>",
                calc[t][j] - 1, ok_time[t][j] / 60, ok_time[t][j] % 60);
      } else {
        fprintf(f, "<td>&nbsp;</td>");
      }
    }
    fprintf(f, "<td>%d</td><td>%d</td></tr>",
            t_prob[t], t_pen[t]);
  }

  fputs("</table>\n", f);
  if (!client_flag) {
    if (footer_str) {
      fprintf(f, "%s", footer_str);
    } else {
      fputs("</body></html>", f);
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
    if (global->score_system_val == SCORE_KIROV
        || global->score_system_val == SCORE_OLYMPIAD)
      do_write_kirov_standings(f, 0, header_str, footer_str);
    else
      do_write_standings(f, 0, header_str, footer_str);
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
  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD)
    do_write_kirov_standings(f, 0, header_str, footer_str);
  else
    do_write_standings(f, 0, header_str, footer_str);
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
  size_t size;
  unsigned long ip;
  int teamid, langid, probid, status, test, score;
  int attempts, score1;

  char durstr[64], statstr[64];
  char *str1 = 0, *str2 = 0;

  start = run_get_start_time();
  total = run_get_total();

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
  fprintf(f, "<p><big>%s: %d</big></p>\n",
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
    run_get_record(i, &time, &size, 0, &ip, 0,
                   &teamid, &langid, &probid, &status, &test, &score);
    run_get_attempts(i, &attempts);

    if (!start) time = start;
    if (start > time) time = start;
    duration_str(global->show_astr_time, time, start, durstr, 0);
    run_status_str(status, statstr, 0);

    fputs("<tr>", f);
    fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", durstr);
    fprintf(f, "<td>%s</td>", teamdb_get_name(teamid));
    if (probs[probid]) fprintf(f, "<td>%s</td>", probs[probid]->short_name);
    else fprintf(f, "<td>??? - %d</td>", probid);
    if (langs[langid]) fprintf(f, "<td>%s</td>", langs[langid]->short_name);
    else fprintf(f, "<td>??? - %d</td>", langid);
    fprintf(f, "<td>%s</td>", statstr);
    if (test <= 0) {
      fprintf(f, "<td>%s</td>\n", _("N/A"));
      if (global->score_system_val == SCORE_KIROV
          || global->score_system_val == SCORE_OLYMPIAD) {
        fprintf(f, "<td>%s</td>\n", _("N/A"));
      }
    } else if (global->score_system_val == SCORE_KIROV ||
               global->score_system_val == SCORE_OLYMPIAD) {
      fprintf(f, "<td>%d</td>\n", test - 1);
      if (score == -1) {
        fprintf(f, "<td>%s</td>", _("N/A"));
      } else {
        if (global->score_system_val == SCORE_OLYMPIAD) {
          fprintf(f, "<td>%d</td>", score);
        } else {
          score1 = score - attempts * probs[probid]->run_penalty;
          if (score1 < 0) score1 = 0;
          fprintf(f, "<td>%d(%d)=%d</td>", score, attempts, score1);
        }
      }
    } else {
      fprintf(f, "<td>%d</td>\n", test);
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

static void
write_judge_allruns(int master_mode, int show_all, FILE *f)
{
  int total;
  int show_num;
  int i;

  time_t time, start;
  size_t size;
  unsigned long ip;
  int teamid, langid, probid, status, test, score;
  int attempts, score1;

  char durstr[64], statstr[64];
  char *str1 = 0, *str2 = 0;

  start = run_get_start_time();
  total = run_get_total();
  show_num = 10;
  if (show_all) show_num = total;

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

  /* header */
  fprintf(f, "<p><big>%s: %d</big></p>\n",
          _("Total submissions"), total);
  fprintf(f, "<table border=\"1\"><tr><th>%s</th><th>%s</th>"
          "<th>%s</th><th>%s</th>"
          "<th>%s</th><th>%s</th>"
          "<th>%s</th><th>%s</th>"
          "<th>%s</th><th>%s</th>", 
          _("Run ID"), _("Time"), _("Size"), _("IP"),
          _("Team login"), _("Team name"), _("Problem"),
          _("Language"), _("Result"), str1);
  if (str2) {
    fprintf(f, "<th>%s</th>", str2);
  }
  if (master_mode) {
    fprintf(f, "<th>%s</th><th>%s</th>",
            _("New result"),
            (global->score_system_val == SCORE_KIROV
             || global->score_system_val == SCORE_OLYMPIAD)
            ?_("New passed"):_("New test"));
    if (global->score_system_val == SCORE_KIROV
        || global->score_system_val == SCORE_OLYMPIAD) {
      fprintf(f, "<th>%s</th>", _("New score"));
    }
    fprintf(f, "<th>%s</th>", _("Change result"));
  }
  fprintf(f, "<th>%s</th><th>%s</th></tr>\n",
          _("View source"), _("View report"));

  for (i = total - 1; i >= 0 && show_num; i--, show_num--) {
    run_get_record(i, &time, &size, 0, &ip, 0,
                   &teamid, &langid, &probid, &status, &test, &score);
    run_get_attempts(i, &attempts);

    if (!start) time = start;
    if (start > time) time = start;
    duration_str(global->show_astr_time, time, start, durstr, 0);
    run_status_str(status, statstr, 0);

    fputs("$1", f);

    fputs("<tr>", f);
    fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", durstr);
    fprintf(f, "<td>%zu</td>", size);
    fprintf(f, "<td>%s</td>", run_unparse_ip(ip));
    fprintf(f, "<td>%s</td>", teamdb_get_login(teamid));
    fprintf(f, "<td>%s</td>", teamdb_get_name(teamid));
    if (probs[probid]) fprintf(f, "<td>%s</td>", probs[probid]->short_name);
    else fprintf(f, "<td>??? - %d</td>", probid);
    if (langs[langid]) fprintf(f, "<td>%s</td>", langs[langid]->short_name);
    else fprintf(f, "<td>??? - %d</td>", langid);
    fprintf(f, "<td>%s</td>", statstr);
    if (test <= 0) {
      fprintf(f, "<td>%s</td>\n", _("N/A"));
      if (global->score_system_val == SCORE_KIROV
          || global->score_system_val == SCORE_OLYMPIAD) {
        fprintf(f, "<td>%s</td>\n", _("N/A"));
      }
    } else if (global->score_system_val == SCORE_KIROV ||
               global->score_system_val == SCORE_OLYMPIAD) {
      fprintf(f, "<td>%d</td>\n", test - 1);
      if (score == -1) {
        fprintf(f, "<td>%s</td>", _("N/A"));
      } else {
        if (global->score_system_val == SCORE_OLYMPIAD) {
          fprintf(f, "<td>%d</td>", score);
        } else {
          score1 = score - attempts * probs[probid]->run_penalty;
          if (score1 < 0) score1 = 0;
          fprintf(f, "<td>%d(%d)=%d</td>", score, attempts, score1);
        }
      }
    } else {
      fprintf(f, "<td>%d</td>\n", test);
    }

    if (master_mode) {
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
                "</select></td>\n", i,
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
                "</select></td>\n", i,
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
                "</select></td>\n", i,
                _("Rejudge"), _("Ignore"), _("Judgements"),
                _("OK"), _("Compilation error"), _("Run-time error"),
                _("Time-limit exceeded"), _("Presentation error"),
                _("Wrong answer"));
      }

      fprintf(f,
              "<td><input type=\"text\" name=\"failed_%d\" size=\"2\"></td>",
              i);

      if (global->score_system_val == SCORE_KIROV
          || global->score_system_val == SCORE_OLYMPIAD) {
        fprintf(f,
                "<td><input type=\"text\" name=\"score_%d\" size=\"2\"></td>",
                i);
      }

      fprintf(f,
              "<td><input type=\"submit\" name=\"change_%d\""
              " value=\"%s\"></td>\n", i, _("change"));
    }

    fprintf(f, "<td><input type=\"submit\" name=\"source_%d\" value=\"%s\"></td>\n", i, _("view"));
    fprintf(f, "<td><input type=\"submit\" name=\"report_%d\" value=\"%s\"></td>\n", i, _("view"));

    fputs("</tr></form>\n", f);
  }

  fputs("</table>\n", f);
}

static void
write_judge_allclars(int master_mode, int show_all, FILE *f)
{
  int total;
  int show_num = 15;

  unsigned long start, time, size;
  int from, to, flags;
  int i;

  char subj[CLAR_MAX_SUBJ_LEN + 4];
  char psubj[CLAR_MAX_SUBJ_TXT_LEN + 4];
  char ip[CLAR_MAX_IP_LEN + 4];
  char *asubj = 0;
  int   asubj_len = 0, new_len;

  char durstr[64];

  start = run_get_start_time();
  total = clar_get_total();
  if (show_all) show_num = total;

  fprintf(f, "<p><big>%s: %d</big></p>\n", _("Total messages"), total);
  fprintf(f, "<table border=\"1\"><tr><th>%s</th><th>%s</th><th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th>"
          "<th>%s</th><th>%s</th>"
          "<th>%s</th><th>%s</th></tr>\n",
          _("Clar ID"), _("Flags"), _("Time"), _("IP"), _("Size"),
          _("From"), _("To"), _("Subject"), _("View"));

  for (i = total - 1; i >= 0 && show_num; i--, show_num--) {
    clar_get_record(i, &time, &size, ip, &from, &to, &flags, subj);
    if (!master_mode && (from <= 0 || flags >= 2)) continue; 

    base64_decode_str(subj, psubj, 0);
    new_len = html_armored_strlen(psubj);
    new_len = (new_len + 7) & ~3;
    if (new_len > asubj_len) asubj = alloca(asubj_len = new_len);
    html_armor_string(psubj, asubj);
    if (!start) time = start;
    if (start > time) time = start;
    duration_str(global->show_astr_time, time, start, durstr, 0);

    fputs("$1<tr>", f);
    fprintf(f, "<td>%d</td>", i);
    fprintf(f, "<td>%s</td>", clar_flags_html(flags, from, to, 0, 0));
    fprintf(f, "<td>%s</td>", durstr);
    fprintf(f, "<td>%s</td>", ip);
    fprintf(f, "<td>%lu</td>", size);
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

    fputs("</tr></form>\n", f);
  }

  fputs("</table>\n", f);
}

void
write_judge_allstat(int master_mode, int all_runs, int all_clars,
                    char const *dir, char const *name)
{
  path_t  path;
  FILE   *f;

  pathmake(path, dir, "/", name, 0);
  info("judge statistics to %s", path);
  if (!(f = sf_fopen(path, "w"))) return;

  write_judge_allruns(master_mode, all_runs, f);
  putc(1, f);
  write_judge_allclars(master_mode, all_clars, f);

  fclose(f);
}

void
write_judge_source_view(char const *pk_name, int rid)
{
  path_t  path;
  FILE   *f = 0;
  path_t  src_base;
  path_t  src_path;
  char   *src = 0;
  char   *html = 0;
  int     src_len = 0;
  int     html_len;

  ASSERT(rid >= 0 && rid < run_get_total());
  pathmake(path, global->pipe_dir, "/", pk_name, 0);
  if (!(f = sf_fopen(path, "w"))) return;

  sprintf(src_base, "%06d", rid);
  pathmake(src_path, global->run_archive_dir, "/", src_base, 0);
  if (generic_read_file(&src, 0, &src_len, 0, 0, src_path, "") < 0) {
    fprintf(f, "<h2>%s</h2><p>%s</p>",
            _("Server is unable to perform your request"),
            _("Source file is not found"));
    goto _cleanup;
  }

  html_len = html_armored_memlen(src, src_len);
  html = alloca(html_len + 16);
  html_armor_text(src, src_len, html);
  html[html_len] = 0;

  fprintf(f, "<pre>%s</pre>", html);

 _cleanup:
  if (f) fclose(f);
  if (src) xfree(src);  
}

int
new_write_user_source_view(FILE *f, int uid, int rid)
{
  path_t  src_base, src_path;
  int run_uid, src_len = 0, html_len;
  char   *src = 0, *html = 0;

  if (!global->team_enable_src_view) {
    err("viewing user source is disabled");
    return -SRV_ERR_SOURCE_DISABLED;
  }
  if (rid < 0 || rid >= run_get_total()) {
    err("invalid run_id: %d", rid);
    return -SRV_ERR_BAD_RUN_ID;
  }
  run_get_record(rid, 0, 0, 0, 0, 0, &run_uid, 0, 0, 0, 0, 0);
  if (uid != run_uid) {
    err("user ids does not match");
    return -SRV_ERR_ACCESS_DENIED;
  }
  sprintf(src_base, "%06d", rid);
  pathmake(src_path, global->run_archive_dir, "/", src_base, 0);
  if (generic_read_file(&src, 0, &src_len, 0, 0, src_path, "") < 0) {
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
  int run_uid, report_len = 0, html_len = 0, prob_id;
  path_t report_base, report_path;
  char *report = 0, *html_report;

  if (rid < 0 || rid >= run_get_total()) {
    err("invalid run_id: %d", rid);
    return -SRV_ERR_BAD_RUN_ID;
  }
  if (run_get_record(rid, 0, 0, 0, 0, 0, &run_uid, 0, &prob_id, 0, 0, 0) < 0) {
    return -SRV_ERR_BAD_RUN_ID;
  }
  if (prob_id <= 0 || prob_id > max_prob || !probs[prob_id]) {
    err("get_record returned bad prob_id %d", prob_id);
    return -SRV_ERR_BAD_PROB_ID;
  }
  if (!probs[prob_id]->team_enable_rep_view) {
    err("viewing report is disabled for this problem");
    return -SRV_ERR_REPORT_DISABLED;
  }

  sprintf(report_base, "%06d", rid);
  pathmake(report_path,
           global->team_report_archive_dir, "/", report_base, 0);
  if (generic_read_file(&report, 0, &report_len, 0, 0, report_path, "") < 0) {
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

void
write_judge_report_view(char const *pk_name, int rid)
{
  path_t  path;
  FILE   *f = 0;
  path_t  report_base;
  path_t  report_path;
  char   *report = 0;
  char   *html_report = 0;
  int     report_len;
  int     html_len;

  ASSERT(rid >= 0 && rid < run_get_total());
  pathmake(path, global->pipe_dir, "/", pk_name, 0);
  if (!(f = sf_fopen(path, "w"))) return;

  sprintf(report_base, "%06d", rid);
  pathmake(report_path, global->report_archive_dir, "/", report_base, 0);
  if (generic_read_file(&report, 0, &report_len, 0, 0, report_path, "") < 0) {
    fprintf(f, "<h2>%s</h2><p>%s</p>",
            _("Server is unable to perform your request"),
            _("Report file is not found"));
    goto _cleanup;
  }

  html_len = html_armored_memlen(report, report_len);
  html_report = alloca(html_len + 16);
  html_armor_text(report, report_len, html_report);
  html_report[html_len] = 0;

  fprintf(f, "<pre>%s</pre>", html_report);

 _cleanup:
  if (f) fclose(f);
  if (report) xfree(report);
}

void
write_judge_standings(char const *pk_name)
{
  path_t  path;
  FILE   *f;

  pathmake(path, global->pipe_dir, "/", pk_name, 0);
  if (!(f = sf_fopen(path, "w"))) return;
  if (global->score_system_val == SCORE_KIROV
      || global->score_system_val == SCORE_OLYMPIAD)
    do_write_kirov_standings(f, 1, 0, 0);
  else
    do_write_standings(f, 1, 0, 0);
  fclose(f);
}

void
write_judge_teams_view(char const *pk_name, int master_mode)
{
  path_t  path;
  FILE   *f;
  int     tot_teams, i, teamid, flags;
  char    buf[1024], *s, *t, arms[1024];

  pathmake(path, global->pipe_dir, "/", pk_name, 0);
  if (!(f = sf_fopen(path, "w"))) return;
  tot_teams = teamdb_get_total_teams();
  fprintf(f, "%d\n", tot_teams);
  for (i = 0, teamid = 1; i < tot_teams; teamid++) {
    if (!teamdb_lookup(teamid)) continue;
    i++;
    s = buf;
    s += sprintf(s, "<tr><td>");

    t = teamdb_get_login(teamid);
    if (html_armored_strlen(t) > 256) {
      html_armor_string("<login is too long>", arms);
    } else {
      html_armor_string(t, arms);
    }
    s += sprintf(s, "%s", arms);
    s += sprintf(s, "</td><td>");
    s += sprintf(s, "%d", teamid);
    s += sprintf(s, "</td><td>");

    t = teamdb_get_name(teamid);
    if (html_armored_strlen(t) > 256) {
      html_armor_string("<team name is too long>", arms);
    } else {
      html_armor_string(t, arms);
    }
    s += sprintf(s, "%s", arms);
    s += sprintf(s, "</td><td>");
    flags = teamdb_get_flags(teamid);
    if ((flags & TEAM_INVISIBLE) && (flags & TEAM_BANNED)) {
      t = "<b>banned</b>,<i>invisible</i>";
    } else if ((flags & TEAM_INVISIBLE)) {
      t = "<i>invisible</i>";
    } else if ((flags & TEAM_BANNED)) {
      t = "<b>banned</b>";
    } else {
      t = "&nbsp;";
    }
    s += sprintf(s, "%s", t);
    if (master_mode) {
      s += sprintf(s, "</td><td>");
      s += sprintf(s, "<input type=\"submit\" name=\"team_%d\" value=\"change\">", teamid);
    }
    s += sprintf(s, "</td></tr>\n");
    fprintf(f, "%d %s", s - buf, buf);
  }
  fprintf(f, "%d\n", tot_teams);
  fclose(f);
}

void
write_judge_one_team_view(char const *pk_name, int teamid)
{
  path_t  path;
  FILE   *f;
  char   *a_login = 0;
  char   *a_name = 0;
  char const *s_login, *s_name;
  int     l_login, l_name;
  int     flags;

  pathmake(path, global->pipe_dir, "/", pk_name, 0);
  if (!(f = sf_fopen(path, "w"))) return;
  if (!teamdb_lookup(teamid)) {
    fprintf(f, "<p><b>Invalid team id %d</b>\n", teamid);
    fclose(f);
    return;
  }
  flags = teamdb_get_flags(teamid);
  s_login = teamdb_get_login(teamid);
  l_login = html_armored_strlen(s_login);
  s_name = teamdb_get_name(teamid);
  l_name = html_armored_strlen(s_name);
  XALLOCA(a_login, l_login + 10);
  XALLOCA(a_name, l_name + 10);
  html_armor_string(s_login, a_login);
  html_armor_string(s_name, a_name);

  // delete is a very hard operation, so not supported
  /*
  fprintf(f, "<table><tr><td><input type=\"submit\" name=\"tdel_%d\" value=\"%s\"></td></tr></table>\n", teamid, _("delete!"));
  */

  fprintf(f, "<input type=\"hidden\" name=\"teamid\" value=\"%d\">\n",
          teamid);
  fprintf(f, "<table>\n");
  fprintf(f, "<tr><td>%s:</td><td>%d</td></tr>\n",
          _("Team id"), teamid);
  fprintf(f, "<tr><td>%s:</td><td>%s</td><td><input type=\"text\" name=\"tlogin\" size=\"32\"></td><td><input type=\"submit\" name=\"tchglogin\" value=\"%s\"></td></tr>\n", _("Team login"), a_login, _("change"));
  fprintf(f, "<tr><td>%s:</td><td>%s</td><td><input type=\"text\" name=\"tname\" size=\"32\"></td><td><input type=\"submit\" name=\"tchgname\" value=\"%s\"></td></tr>\n", _("Team name"), a_name, _("change"));
  fprintf(f, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td><td><input type=\"submit\" name=\"tbanchg\" value=\"%s\"></td></tr>\n",
          _("Availability"),
          ((flags & TEAM_BANNED))?_("banned"):_("not banned"),
          ((flags & TEAM_BANNED))?_("clear flag"):_("ban"));
  fprintf(f, "<tr><td>%s:</td><td>%s</td><td>&nbsp;</td><td><input type=\"submit\" name=\"tinvchg\" value=\"%s\"></td></tr>\n",
          _("Visibility"),
          ((flags & TEAM_INVISIBLE))?_("invisible"):_("visible"),
          ((flags & TEAM_INVISIBLE))?_("make visible"):_("make invisible"));
  fprintf(f, "<tr><td>%s:</td><td>&nbsp;</td><td><input type=\"password\" name=\"tpasswd1\" size=\"16\"></td></tr>\n",
          _("New password"));
  fprintf(f, "<tr><td>%s:</td><td>&nbsp;</td><td><input type=\"password\" name=\"tpasswd2\" size=\"16\"></td><td><input type=\"submit\" name=\"tchgpwd\" value=\"%s\"></td></tr>\n",
          _("Retype password"), _("change"));
  fprintf(f, "</table>\n");
  fclose(f);
}

void
write_team_page(FILE *f, int user_id, int all_runs, int all_clars,
                unsigned char const *simple_form,
                unsigned char const *multi_form,
                time_t server_start, time_t server_end)
{
  int i;

  if (server_start && !server_end) {
    fprintf(f, "<hr><a name=\"submit\"><h2>%s</h2>\n", _("Send a submission"));
    fprintf(f, "<table>%s\n", multi_form);
    fprintf(f, "<tr><td>%s:</td><td>", _("Problem"));
    fprintf(f, "<select name=\"problem\"><option value=\"\">\n");
    for (i = 1; i <= max_prob; i++)
      if (probs[i]) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                probs[i]->id, probs[i]->short_name, probs[i]->long_name);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "</td></tr>\n");
    fprintf(f, "<tr><td>%s:</td><td>", _("Language"));
    fprintf(f, "<select name=\"language\"><option value=\"\">\n");
    for (i = 1; i <= max_lang; i++)
      if (langs[i]) {
        fprintf(f, "<option value=\"%d\">%s - %s\n",
                langs[i]->id, langs[i]->short_name, langs[i]->long_name);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "</td></tr>\n");
    fprintf(f, "<tr><td>%s:</td>"
            "<td><input type=\"file\" name=\"file\"></td></tr>\n"
            "<tr><td>%s</td>"
            "<td><input type=\"submit\" name=\"send\" value=\"%s\"></td></tr>",
            _("File"), _("Send!"), _("Send!"));
    fprintf(f, "</form></table>\n");
    fprintf(f,
            "%s<input type=\"submit\" name=\"refresh\" value=\"%s\"></form>\n",
           simple_form, _("Refresh"));
    fprintf(f, "</form>");
  }

  if (server_start) {
    fprintf(f, "<hr><a name=\"runstat\"><h2>%s (%s)</h2>\n",
            _("Sent submissions"),
            all_runs?_("all"):_("last 15"));
    new_write_user_runs(f, user_id, all_runs, simple_form);
    fprintf(f, "<p>%s"
            "<input type=\"submit\" name=\"view_all_runs\" value=\"%s\">"
            "</form>\n", simple_form, _("View all"));
    fprintf(f,
            "%s<input type=\"submit\" name=\"refresh\" value=\"%s\"></form>\n",
            simple_form, _("Refresh"));
    fprintf(f, "</form>");
    if (global->team_download_time > 0) {
      fprintf(f, "<p>%s"
              "<input type=\"submit\" name=\"archive\" value=\"%s\"></form>\n",
              simple_form, _("Download your submits"));
      fprintf(f, _("<p><b>Note,</b> if downloads are allowed, you may download your runs once per %d minutes. The archive is in <tt>.tar.gz</tt> (<tt>.tgz</tt>) format.</p>\n"), global->team_download_time / 60);
    }
  }

  if (!global->disable_clars && !global->disable_team_clars
      && server_start && !server_end) {
    fprintf(f, "<hr><a name=\"clar\"><h2>%s</h2>\n",
            _("Send a message to judges"));
    fprintf(f, "<table>%s\n<tr><td>%s:</td><td>", multi_form, _("Problem"));
    fprintf(f, "<select name=\"problem\"><option value=\"\">\n");
    for (i = 1; i <= max_prob; i++)
      if (probs[i]) {
        fprintf(f, "<option value=\"%s\">%s - %s\n",
                probs[i]->short_name,
                probs[i]->short_name, probs[i]->long_name);
      }
    fprintf(f, "</select>\n");
    fprintf(f, "<tr><td>%s:</td>"
            "<td><input type=\"text\" name=\"subject\"></td></tr>\n"
            "<tr><td colspan=\"2\"><textarea name=\"text\" rows=\"20\" cols=\"60\"></textarea></td></tr>\n"
            "<tr><td colspan=\"2\"><input type=\"submit\" name=\"msg\" value=\"%s\"></td></tr>\n"
            "</form></table>\n",
            _("Subject"), _("Send!"));
    fprintf(f,
            "%s<input type=\"submit\" name=\"refresh\" value=\"%s\"></form>\n",
            simple_form, _("Refresh"));
    fprintf(f, "</form>");
  }

  if (!global->disable_clars) {
    fprintf(f, "<hr><a name=\"clarstat\"><h2>%s (%s)</h2>\n",
            _("Messages"), all_clars?_("all"):_("last 15"));
    new_write_user_clars(f, user_id, all_clars, simple_form);
    fprintf(f,"<p>%s"
            "<input type=\"submit\" name=\"view_all_clars\" value=\"%s\">"
            "</form>\n", simple_form, _("View all"));
    fprintf(f,
            "%s<input type=\"submit\" name=\"refresh\" value=\"%s\"></form>\n",
           simple_form, _("Refresh"));
    fprintf(f, "</form>");
  }
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE")
 *  eval: (set-language-environment "Cyrillic-KOI8")
 * End:
 */

