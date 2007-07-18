/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "serve_state.h"
#include "prepare.h"
#include "runlog.h"
#include "misctext.h"
#include "archive_paths.h"
#include "fileutl.h"
#include "teamdb.h"
#include "sformat.h"

#include <reuse/xalloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#if CONF_HAS_LIBINTL - 0 == 1
#include <libintl.h>
#define _(x) gettext(x)
#else
#define _(x) x
#endif

static const signed char armored_tex_len_table[256] =
{
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,2,2,2,2,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,11,1,11,2,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,12,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
};

static unsigned char const * const armored_tex_translate_table[256] =
{
  " "," "," "," "," "," "," "," "," "," ",  0," "," ",  0," "," ",
  " "," "," "," "," "," "," "," "," "," "," "," "," "," "," "," ",
  0,0,0,"\\#","\\$","\\%","\\&",0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,"\\symbol{92}",0,"\\symbol{94}","\\_",
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,"\\symbol{126}"," ",
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

int
tex_armor_needed(const unsigned char *str, size_t *psz)
{
  const unsigned char *p = str;
  size_t s_sz = 0, d_sz = 0;

  if (!str) return 0;
  while (*p) {
    s_sz++;
    d_sz += armored_tex_len_table[*p];
    p++;
  }
  if (s_sz == d_sz) return 0;
  *psz = d_sz;
  return 1;
}

const unsigned char *
tex_armor_buf(struct html_armor_buffer *pb, const unsigned char *s)
{
  const unsigned char *p = s, *q;
  int needed = 0;
  size_t s_sz = 0, d_sz = 0;
  unsigned char *t;

  if (!s) return "";
  while (*p) {
    s_sz++;
    d_sz += armored_tex_len_table[*p];
    if (armored_tex_translate_table[*p]) needed = 1;
    p++;
  }
  if (!needed) return s;

  if (d_sz >= pb->size) {
    xfree(pb->buf);
    if (!pb->size) pb->size = 64;
    while (d_sz >= pb->size) pb->size *= 2;
    pb->buf = (unsigned char*) xmalloc(pb->size);
  }

  for (p = s, t = pb->buf; *p; p++) {
    if (!(q = armored_tex_translate_table[*p])) {
      *t++ = *p;
    } else {
      while ((*t++ = *q++));
      t--;
    }
  }
  *t = 0;
  return pb->buf;
}

int
user_report_generate(unsigned char *out_path, size_t out_size,
                     const struct contest_desc *cnts,
                     FILE *log_f, const serve_state_t cs, int user_id)
{
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  int *run_ids;
  int total_runs, run_id, retval = -1, f_id, l_id, i, j;
  struct run_entry re;
  FILE *fout = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  path_t src_path;
  int src_flags, answer, variant;
  char *src_txt = 0, *eptr;
  size_t src_len = 0;
  unsigned char *usrc;
  problem_xml_t px;
  const unsigned char *ans_txt;
  struct xml_attr *a;
  struct watched_file *pw = 0;
  const unsigned char *pw_path;
  path_t variant_stmt_file;
  unsigned char bigbuf[16384];
  struct teamdb_export tdb;

  if (global->score_system_val != SCORE_OLYMPIAD) return -1;

  if (teamdb_export_team(cs->teamdb_state, user_id, &tdb) < 0) {
    fprintf(log_f, "Invalid user %d\n", user_id);
    goto cleanup;
  }


  XALLOCA(run_ids, cs->max_prob + 1);
  memset(run_ids, -1, sizeof(run_ids[0]) * (cs->max_prob + 1));
  out_path[0] = 0;

  // find the latest run in acceptable state
  total_runs = run_get_total(cs->runlog_state);
  if (total_runs > 0) {
    for (run_id = total_runs - 1; run_id >= 0; run_id--) {
      if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
        fprintf(log_f, "Invalid run %d\n", run_id);
        goto cleanup;
      }
      if (!run_is_source_available(re.status)) continue;
      if (re.user_id != user_id) continue;
      if (re.prob_id <= 0 || re.prob_id > cs->max_prob
          || !(prob = cs->probs[re.prob_id])) {
        fprintf(log_f, "Invalid problem %d in run %d\n", re.prob_id, run_id);
        goto cleanup;
      }
      if (prob->type_val == PROB_TYPE_OUTPUT_ONLY
          || prob->type_val == PROB_TYPE_SELECT_MANY
          || prob->type_val == PROB_TYPE_CUSTOM) {
        fprintf(log_f,"Problem type `%s' for problem %s is not yet supported\n",
                problem_unparse_type(prob->type_val), prob->short_name);
        goto cleanup;
      }
      if (run_ids[re.prob_id] >= 0) continue;
      if (prob->type_val != PROB_TYPE_STANDARD) {
        switch (re.status) {
        case RUN_OK:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_PARTIAL:
        case RUN_ACCEPTED:
          run_ids[re.prob_id] = run_id;
          break;

        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
        case RUN_PRESENTATION_ERR:
          break;

        default:
          fprintf(log_f, "Invalid run status %d (%s) in run %d\n",
                  re.status, run_status_str(re.status, 0, 0, 0, 0),
                  run_id);
          goto cleanup;
        }
      } else {
        switch (re.status) {
        case RUN_OK:
        case RUN_PARTIAL:
        case RUN_ACCEPTED:
          run_ids[re.prob_id] = run_id;
          break;

        case RUN_COMPILE_ERR:
        case RUN_RUN_TIME_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_PRESENTATION_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
          break;

        default:
          fprintf(log_f, "Invalid run status %d (%s) in run %d\n",
                  re.status, run_status_str(re.status, 0, 0, 0, 0),
                  run_id);
          goto cleanup;
        }
      }
    }
  }

  if (total_runs > 0) {
    for (run_id = total_runs - 1; run_id >= 0; run_id--) {
      if (run_get_entry(cs->runlog_state, run_id, &re) < 0) abort();
      if (!run_is_source_available(re.status)) continue;
      if (re.user_id != user_id) continue;
      prob = cs->probs[re.prob_id];
      if (run_ids[re.prob_id] >= 0) continue;
      if (prob->type_val != PROB_TYPE_STANDARD) {
        switch (re.status) {
        case RUN_PRESENTATION_ERR:
          run_ids[re.prob_id] = run_id;
          break;

        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
          break;

        default:
          abort();
        }
      } else {
        switch (re.status) {
        case RUN_COMPILE_ERR:
        case RUN_RUN_TIME_ERR:
        case RUN_TIME_LIMIT_ERR:
        case RUN_PRESENTATION_ERR:
        case RUN_WRONG_ANSWER_ERR:
        case RUN_MEM_LIMIT_ERR:
        case RUN_SECURITY_ERR:
          run_ids[re.prob_id] = run_id;
          break;

        case RUN_IGNORED:
        case RUN_DISQUALIFIED:
          break;

        default:
          abort();
        }
      }
    }
  }

  snprintf(out_path, out_size, "%s/%06d.tex", global->print_work_dir, run_id);
  if (!(fout = fopen(out_path, "w"))) {
    fprintf(log_f, "Cannot open `%s' for writing\n", out_path);
    goto cleanup;
  }

  if (global->user_exam_protocol_header_file[0]) {
    sformat_message(bigbuf, sizeof(bigbuf),
                    global->user_exam_protocol_header_file,
                    global, 0, 0, 0, &tdb, 0, cnts, 0);
    fprintf(fout, "%s", bigbuf);
  }

  f_id = 0;
  while (1) {
    for (; f_id <= cs->max_prob && !cs->probs[f_id]; f_id++);
    if (f_id > cs->max_prob) break;
    l_id = f_id + 1;
    prob = cs->probs[f_id];
    if (prob->type_val == PROB_TYPE_SHORT_ANSWER
        || prob->type_val == PROB_TYPE_SELECT_ONE) {
      for (; l_id <= cs->max_prob && (!cs->probs[l_id] || cs->probs[l_id]->type_val == prob->type_val); l_id++);
    }
    switch (prob->type_val) {
    case PROB_TYPE_STANDARD:
    case PROB_TYPE_SHORT_ANSWER:
    case PROB_TYPE_TEXT_ANSWER:
      break;

    case PROB_TYPE_SELECT_ONE:
      fprintf(fout, "\n\n\\begin{tabular}{|p{2cm}|p{2cm}|p{4cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s & %s & %s\\\\",
              _("Problem"), _("Answer code"), _("Answer"));
      for (i = f_id; i < l_id; i++) {
        if (!(prob = cs->probs[i])) continue;
        if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
          fprintf(fout, "%s & ", tex_armor_buf(&ab, prob->short_name));
        } else {
          fprintf(fout, "%s-", tex_armor_buf(&ab, prob->short_name));
          fprintf(fout, "%s &", tex_armor_buf(&ab, prob->long_name));
        }
        if (run_ids[i] < 0) {
          fprintf(fout, " & \textit{%s}\\\\", _("No answer is given"));
          continue;
        }
        if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
        if (re.status != RUN_OK && re.status != RUN_PARTIAL
            && re.status != RUN_WRONG_ANSWER_ERR) {
          fprintf(log_f, "Invalid run status %d (%s) in run %d\n",
                  re.status, run_status_str(re.status, 0, 0, 0, 0),
                  run_id);
          goto cleanup;
        }

        if ((src_flags = archive_make_read_path(cs, src_path, sizeof(src_path),
                                                global->run_archive_dir, run_id,
                                                0, 0)) < 0) {
          fprintf(log_f, "Source for run %d is not available\n", run_id);
          goto cleanup;
        }
        if (generic_read_file(&src_txt, 0, &src_len, src_flags, 0, src_path, "") < 0) {
          fprintf(log_f, "Error reading from %s\n", src_path);
          goto cleanup;
        }
        if (strlen(src_txt) != src_len) {
          fprintf(log_f, "Source file %s is binary\n", src_path);
          goto cleanup;
        }
        usrc = (unsigned char*) src_txt + src_len - 1;
        while (src_len > 0 && isspace(*usrc)) {
          usrc--;
          src_len--;
        }
        *usrc = 0;
        errno = 0;
        answer = strtol(src_txt, &eptr, 10);
        if (errno || *eptr) {
          fprintf(log_f, "Source file %s is invalid\n", src_path);
          goto cleanup;
        }
        xfree(src_txt); src_txt = 0; src_len = 0;
        variant = 0;
        if (prob->variant_num > 0) {
          if (find_variant(cs, user_id, i, 0) <= 0) {
            fprintf(log_f, "Variant for run %d is invalid\n", run_ids[i]);
            goto cleanup;
          }
        }
        if (variant > 0 && prob->xml.a) {
          px = prob->xml.a[variant - 1];
        } else {
          px = prob->xml.p;
        }
        ans_txt = 0;
        if (px && px->answers) {
          if (answer <= 0 || answer > px->ans_num) {
            fprintf(log_f, "Answer code %d is invalid in run %d\n", answer,
                    re.run_id);
            goto cleanup;
          }
          j = problem_xml_find_language(0, px->tr_num, px->tr_names);
          for (a = px->answers[answer - 1][j]->first;
               a && a->tag != PROB_A_TEX;
               a = a->next);
          if (a) ans_txt = a->text;
          if (!ans_txt)
            ans_txt = tex_armor_buf(&ab, px->answers[answer - 1][j]->text);
        } else if (prob->alternative) {
          for (j = 0; j + 1 != answer && prob->alternative[j]; j++);
          if (j + 1 != answer || !prob->alternative[j]) {
            fprintf(log_f, "Answer code %d is invalid in run %d\n", answer,
                    re.run_id);
            goto cleanup;
          }
        } else {
          if (variant > 0) {
            prepare_insert_variant_num(variant_stmt_file, sizeof(variant_stmt_file), prob->alternatives_file, variant);
            pw = &cs->prob_extras[prob->id].v_alts[variant];
            pw_path = variant_stmt_file;
          } else {
            pw = &cs->prob_extras[prob->id].alt;
            pw_path = prob->alternatives_file;
          }
          watched_file_update(pw, pw_path, cs->current_time);
          if (!(ans_txt = get_nth_alternative(pw->text, answer))) {
            fprintf(log_f, "Answer code %d is invalid in run %d\n", answer,
                    re.run_id);
            goto cleanup;
          }
          ans_txt = tex_armor_buf(&ab, ans_txt);
        }
        fprintf(fout, "%d & %s\\\\\n", answer, ans_txt);
      }
      fprintf(fout, "\\hline\n");
      fprintf(fout, "\\end{tabular}\n");
      break;

    default:
      //case PROB_TYPE_OUTPUT_ONLY:
      //case PROB_TYPE_SELECT_MANY:
      //case PROB_TYPE_CUSTOM:
      abort();
      break;
    }
    f_id = l_id;
  }

  if (global->user_exam_protocol_footer_file[0]) {
    sformat_message(bigbuf, sizeof(bigbuf),
                    global->user_exam_protocol_footer_file,
                    global, 0, 0, 0, &tdb, 0, cnts, 0);
    fprintf(fout, "%s", bigbuf);
  }

  if (ferror(fout)) {
    fprintf(log_f, "Write error to `%s'\n", out_path);
    goto cleanup;
  }
  if (fclose(fout) < 0) {
    fout = 0;
    fprintf(log_f, "Write error to `%s'\n", out_path);
    goto cleanup;
  }
  fout = 0;

  retval = 0;

 cleanup:
  xfree(src_txt);
  html_armor_free(&ab);
  if (fout) fclose(fout);
  if (out_path[0]) unlink(out_path);
  return retval;
}
