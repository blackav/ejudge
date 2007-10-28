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
#include "xml_utils.h"
#include "new-server.h"
#include "userlist.h"
#include "random.h"
#include "testing_report_xml.h"
#include "mime_type.h"

#include <reuse/xalloc.h>
#include <reuse/exec.h>
#include <reuse/osdeps.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>

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

static void
write_xml_tex_testing_report(
        FILE *fout,
        const serve_state_t cs,
        int run_id);

/*
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
*/

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

static void
fix_tex_utf8(unsigned char *str)
{
  unsigned char *p = str;
  while (*p) {
    if (*p == 0342 && p[1] == 0200 && p[2] == 0224) {
      p[0] = ' '; p[1] = '-'; p[2] = ' ';
    }
    if (*p == 0342 && p[1] == 0210 && p[2] == 0222) {
      p[0] = ' '; p[1] = '-'; p[2] = ' ';
    }
    if (*p == 0342 && p[1] == 0211 && p[2] == 0245) {
      p[0] = '>'; p[1] = '='; p[2] = ' ';
    }
    p++;
  }
}

static unsigned char *
tex_armor_verbatim(unsigned char *str)
{
  unsigned char *s;

  for (s = str; *s; s++)
    if (*s < ' ' && *s != '\n') *s = ' ';
  if (utf8_mode) {
    utf8_fix_string(str, 0);
    fix_tex_utf8(str);
  } else {
    for (s = str; *s; s++)
      if (*s >= 0x7f) *s = '?';
  }
  return str;
}

enum { VERBATIM_WIDTH = 70 };

static unsigned char *
tex_armor_verbatim_2(unsigned char *str, int width)
{
  unsigned char *s, *p;
  int pos;
  int slen, swidth, *sind, i, j;

  for (s = str; *s; s++)
    if (*s < ' ' && *s != '\n') *s = ' ';
  if (utf8_mode) {
    fix_tex_utf8(str);
    slen = strlen(str);
    sind = (int*) xmalloc((slen + 1) * sizeof(sind[0]));
    swidth = utf8_fix_string(str, sind);
    for (i = 0, pos = 0; i < swidth; ) {
      if (str[sind[i]] == '\n') {
        i++;
        pos = 0;
      } else if (pos == width && str[sind[i]] == ' ') {
        str[sind[i]] = '\n';
        i++;
        pos = 0;
      } else if (pos == width) {
        j = i - 1;
        while (j >= 0 && str[sind[j]] != '\n' && str[sind[j]] != ' ') j--;
        if (j < 0 || str[sind[j]] == '\n') {
          while (str[sind[i]] && str[sind[i]] != ' ' && str[sind[i]] != '\n')
            i++;
          if (str[sind[i]] == ' ') {
            str[sind[i]] = '\n';
            pos = 0;
            i++;
          } else if (str[sind[i]] == '\n') {
            pos = 0;
            i++;
          }
        } else {
          str[sind[j]] = '\n';
          pos = 0;
          i = j + 1;
        }
      } else {
        i++;
        pos++;
      }
    }
    xfree(sind); sind = 0;
  } else {
    // split the lines longer than `width'
    for (s = str, pos = 0; *s; ) {
      if (*s == '\n') {
        s++;
        pos = 0;
      } else if (pos == width && *s == ' ') {
        *s = '\n';
        s++;
        pos = 0;
      } else if (pos == width) {
        p = s - 1;
        while (p >= str && *p != '\n' && *p != ' ') p--;
        if (p < str || *p == '\n') {
          while (*s && *s != ' ' && *s != '\n') s++;
          if (*s == ' ') {
            *s = '\n';
            pos = 0;
            s++;
          } else if (*s == '\n') {
            pos = 0;
            s++;
          }
        } else {
          *p = '\n';
          pos = 0;
          s = p + 1;
        }
      } else {
        s++;
        pos++;
      }
    }
  }
  return str;
}

static unsigned char *
chop2(unsigned char *str)
{
  size_t len;

  if (!str) return 0;
  len = strlen(str);
  if (len > 0 && isspace(str[len - 1])) len--;
  str[len] = 0;
  return str;
}

#define TARMOR(s) tex_armor_buf(&ab, s)
#define ARMOR(s) html_armor_buf(&ab, s)

static int
user_report_generate(
        unsigned char *out_path,
        size_t out_size,
        const struct contest_desc *cnts,
        FILE *log_f,
        const serve_state_t cs,
        int user_id,
        int locale_id)
{
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  const struct section_language_data *lang;
  int *run_ids;
  int total_runs, run_id, retval = -1, f_id, l_id, i, j, k;
  struct run_entry re;
  FILE *fout = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  path_t src_path;
  int src_flags, answer, variant, passed_tests;
  char *src_txt = 0, *eptr, *num_txt = 0;
  size_t src_len = 0, num_len = 0;
  problem_xml_t px;
  const unsigned char *ans_txt;
  struct xml_attr *a;
  struct watched_file *pw = 0;
  const unsigned char *pw_path;
  path_t variant_stmt_file;
  unsigned char bigbuf[16384];
  struct teamdb_export tdb;
  time_t start_time, stop_time;
  unsigned char *psrc;
  const struct userlist_user *u = 0;
  const struct userlist_member *m = 0;
  const unsigned char *s;

  if (global->score_system_val != SCORE_OLYMPIAD) return -1;

  if (teamdb_export_team(cs->teamdb_state, user_id, &tdb) < 0) {
    fprintf(log_f, "Invalid user %d\n", user_id);
    goto cleanup;
  }
  u = tdb.user;
  if (u && u->i.members[CONTEST_M_CONTESTANT]
      && u->i.members[CONTEST_M_CONTESTANT]->total > 0)
    m = u->i.members[CONTEST_M_CONTESTANT]->members[0];

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

  snprintf(out_path, out_size, "%s/%06d.tex", global->print_work_dir, user_id);
  if (!(fout = fopen(out_path, "w"))) {
    fprintf(log_f, "Cannot open `%s' for writing\n", out_path);
    goto cleanup;
  }

  if (global->user_exam_protocol_header_file[0]
      && global->user_exam_protocol_header_txt) {
    sformat_message(bigbuf, sizeof(bigbuf),
                    global->user_exam_protocol_header_txt,
                    global, 0, 0, 0, &tdb, tdb.user, cnts, 0);
    fprintf(fout, "%s", bigbuf);
  }

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }

  fprintf(fout, "\\noindent\\begin{tabular}{ll}\n");
  fprintf(fout, "%s: & %s\\\\\n", _("Login"), TARMOR(tdb.login));
  s = 0;
  if (m) {
    if (locale_id > 0) {
      s = m->surname;
      if (!s) s = m->surname_en;
    } else {
      s = m->surname_en;
      if (!s) s = m->surname;
    }
    if (s) fprintf(fout, "%s: & %s\\\\\n", _("Family name"), TARMOR(s));
    s = 0;
    if (locale_id > 0) {
      s = m->firstname;
      if (!s) s = m->firstname_en;
    } else {
      s = m->firstname_en;
      if (!s) s = m->firstname;
    }
    if (s) fprintf(fout, "%s: & %s\\\\\n", _("First name"), TARMOR(s));
    s = 0;
    if (locale_id > 0) {
      s = m->middlename;
      if (!s) s = m->middlename_en;
    } else {
      s = m->middlename_en;
      if (!s) s = m->middlename;
    }
    if (s) fprintf(fout, "%s: & %s\\\\\n", _("Middle name"), TARMOR(s));
  } else {
    fprintf(fout, "%s: & %s\\\\\n", _("Name"), TARMOR(tdb.name));
  }
  if (u && u->i.exam_id)
    fprintf(fout, "%s: & %s\\\\\n", _("Exam Id"), TARMOR(u->i.exam_id));
  if (u && u->i.location)
    fprintf(fout, "%s: & %s\\\\\n", _("Location"), TARMOR(u->i.location));

  if (start_time > 0) {
    fprintf(fout, "%s: & %s\\\\\n", _("Exam start time"),
            xml_unparse_date(start_time));
  }
  if (stop_time > 0) {
    fprintf(fout, "%s: & %s\\\\\n", _("Exam finish time"),
            xml_unparse_date(stop_time));
  }
  fprintf(fout, "\\end{tabular}\n\n");

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
      fprintf(fout, "\n\n\\vspace{0.5cm}\n\\noindent\\begin{tabular}{|p{2cm}|p{4cm}|p{3.5cm}|p{4.5cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s & %s & %s & %s \\\\\n", _("Problem"), _("Language"), _("Passed tests"), _("Comment"));
      fprintf(fout, "\\hline\n");

      prob = cs->probs[i = f_id];
      if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
        fprintf(fout, "%s & ", TARMOR(prob->short_name));
      } else {
        fprintf(fout, "%s-", TARMOR(prob->short_name));
        fprintf(fout, "%s &", TARMOR(prob->long_name));
      }
      if ((run_id = run_ids[i]) < 0) {
        fprintf(fout, " & & \\textit{%s}\\\\\n", _("No answer is given"));
        fprintf(fout, "\\hline\n");
        fprintf(fout, "\\end{tabular}\n\n");
        break;
      }
      if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
      if (re.status == RUN_OK || re.status == RUN_PARTIAL)
        re.status = RUN_ACCEPTED;
      passed_tests = re.test - 1;
      if (passed_tests > prob->tests_to_accept)
        passed_tests = prob->tests_to_accept;
      if (re.lang_id <= 0 || re.lang_id > cs->max_lang
          || !(lang = cs->langs[re.lang_id])) {
        fprintf(log_f, "Invalid language %d in run %d\n", re.lang_id, run_id);
        goto cleanup;
      }
      if (!lang->long_name[0] || !strcmp(lang->long_name, lang->short_name)) {
        fprintf(fout, " %s & ", TARMOR(lang->short_name));
      } else {
        fprintf(fout, " %s-", TARMOR(lang->short_name));
        fprintf(fout, "%s &", TARMOR(lang->long_name));
      }
      fprintf(fout, " %d &", passed_tests);
      fprintf(fout, " \\textit{%s} \\\\\n",
              run_status_str(re.status, 0, 0, 0, 0));
      fprintf(fout, "\\hline\n\\end{tabular}\n\n");

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
      while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
      src_txt[src_len] = 0;

      num_len = text_numbered_memlen(src_txt, src_len);
      num_txt = xmalloc(num_len + 16);
      text_number_lines(src_txt, src_len, num_txt);
      fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n%s\n\n",
              tex_armor_verbatim(num_txt),
              _("Note, lines are numbered just for your convinience."));
      xfree(num_txt); num_txt = 0; num_len = 0;
      xfree(src_txt); src_txt = 0; src_len = 0;
      break;

    case PROB_TYPE_TEXT_ANSWER:
      fprintf(fout, "\n\n\\vspace{0.5cm}\n\\noindent\\begin{tabular}{|p{2cm}|p{12cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s & %s\\\\\n", _("Problem"), _("Comment"));
      fprintf(fout, "\\hline\n");
      i = f_id;
      prob = cs->probs[f_id];
      if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
        fprintf(fout, "%s & ", TARMOR(prob->short_name));
      } else {
        fprintf(fout, "%s-", TARMOR(prob->short_name));
        fprintf(fout, "%s &", TARMOR(prob->long_name));
      }
      if ((run_id = run_ids[i]) < 0) {
        fprintf(fout, "\\textit{%s}\\\\\n", _("No answer is given"));
        fprintf(fout, "\\hline\n");
        fprintf(fout, "\\end{tabular}\n\n");
        break;
      }
      if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
      if (re.status == RUN_OK || re.status == RUN_PARTIAL
          || re.status == RUN_WRONG_ANSWER_ERR)
        re.status = RUN_ACCEPTED;
      if (re.status != RUN_ACCEPTED) {
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
      while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
      src_txt[src_len] = 0;

      if (!src_len) {
        fprintf(fout, " \\textit{%s}\\\\\n", _("Answer is empty"));
        fprintf(fout, "\\hline\n\\end{tabular}\n\n");
        break;
      }
      fprintf(fout, " \\textit{%s}\\\\\n", _("Accepted for testing"));
      fprintf(fout, "\\hline\n\\end{tabular}\n\n");

      num_len = text_numbered_memlen(src_txt, src_len);
      num_txt = xmalloc(num_len + 16);
      text_number_lines(src_txt, src_len, num_txt);
      fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n%s\n\n",
              tex_armor_verbatim_2(num_txt, VERBATIM_WIDTH),
              _("Note, lines are numbered just for your convinience."));
      xfree(num_txt); num_txt = 0; num_len = 0;
      xfree(src_txt); src_txt = 0; src_len = 0;
      break;

    case PROB_TYPE_SHORT_ANSWER:
      fprintf(fout, "\n\n\\vspace{0.5cm}\n\\noindent\\begin{tabular}{|p{2cm}|p{5cm}|p{2cm}|p{5cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s & %s & %s & %s \\\\\n",
              _("Problem"), _("Answer"), _("Problem"), _("Answer"));
      for (i = f_id, k = 0; i < l_id; i++, k++) {
        if (!(prob = cs->probs[i])) continue;
        if (!(k % 2)) fprintf(fout, "\\hline\n");
        if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
          fprintf(fout, "%s & ", TARMOR(prob->short_name));
        } else {
          fprintf(fout, "%s-", TARMOR(prob->short_name));
          fprintf(fout, "%s &", TARMOR(prob->long_name));
        }
        if ((run_id = run_ids[i]) < 0) {
          fprintf(fout, "\\textit{%s}", _("No answer"));
          if ((k % 2) == 1) fprintf(fout, " \\\\\n");
          else fprintf(fout, " & ");
          continue;
        }
        if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
        if (re.status == RUN_OK || re.status == RUN_PARTIAL
            || re.status == RUN_WRONG_ANSWER_ERR)
          re.status = RUN_ACCEPTED;
        if (re.status != RUN_ACCEPTED && re.status != RUN_PRESENTATION_ERR) {
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
        while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
        src_txt[src_len] = 0;
        for (psrc = src_txt; *psrc; psrc++)
          if (*psrc < ' ') *psrc = ' ';
        //for (psrc = src_txt; *psrc && *psrc != ' '; psrc++);
        fprintf(fout, " %s ", TARMOR(src_txt));

        /*
        if (re.status == RUN_ACCEPTED) {
          fprintf(fout, " \\textit{%s}\\\\\n", _("Accepted for testing"));
        } else {
        // presentation error
          psrc = ns_get_checker_comment(cs, run_id, 0);
          if (!psrc) psrc = xstrdup("");
          fprintf(fout, "\\textit{%s} \\\\\n", TARMOR(psrc));
          xfree(psrc);
        }
        */
        xfree(src_txt); src_txt = 0;
        src_len = 0;
        if ((k % 2) == 1) fprintf(fout, " \\\\\n");
        else fprintf(fout, " & ");
      }
      if (k % 2 == 1) fprintf(fout, " & & \\\\\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "\\end{tabular}\n\n");
      /*
      fprintf(fout, "\\noindent{}%s\n\n",
              _("Note, that only solutions marked ``Accepted for testing'' are subject to further testing. Other solutions \\textbf{will not} be tested."));
      */
      break;

    case PROB_TYPE_SELECT_ONE:
      fprintf(fout, "\n\n\\vspace{0.5cm}\n\\noindent\\begin{tabular}{|p{1.5cm}|p{3.0cm}|p{1.5cm}|p{3.0cm}|p{1.5cm}|p{3.0cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s & %s & %s & %s & %s & %s \\\\\n",
              _("Problem"), _("Answer code"), _("Problem"), _("Answer code"),
              _("Problem"), _("Answer code"));
      for (i = f_id, k = 0; i < l_id; i++, k++) {
        if (!(prob = cs->probs[i])) continue;
        if (!(k % 3)) fprintf(fout, "\\hline\n");
        if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
          fprintf(fout, "%s & ", TARMOR(prob->short_name));
        } else {
          fprintf(fout, "%s-", TARMOR(prob->short_name));
          fprintf(fout, "%s &", TARMOR(prob->long_name));
        }
        if ((run_id = run_ids[i]) < 0) {
          fprintf(fout, " \\textit{%s}", _("No answer"));
          if ((k % 3) == 2) fprintf(fout, " \\\\\n");
          else fprintf(fout, " & ");
          continue;
        }
        if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
        if (re.status != RUN_OK && re.status != RUN_PARTIAL
            && re.status != RUN_ACCEPTED && re.status != RUN_WRONG_ANSWER_ERR) {
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
        while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
        src_txt[src_len] = 0;
        errno = 0;
        answer = strtol(src_txt, &eptr, 10);
        if (errno || *eptr) {
          fprintf(log_f, "Source file %s is invalid\n", src_path);
          goto cleanup;
        }
        xfree(src_txt); src_txt = 0; src_len = 0;
        variant = 0;
        if (prob->variant_num > 0) {
          if ((variant = find_variant(cs, user_id, i, 0)) <= 0) {
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
            ans_txt = TARMOR(px->answers[answer - 1][j]->text);
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
          ans_txt = TARMOR(ans_txt);
        }
        //fprintf(fout, "%d & %s\\\\\n", answer, ans_txt);
        fprintf(fout, "%d", answer);
        if ((k % 3) == 2) fprintf(fout, " \\\\\n");
        else fprintf(fout, " & ");
      }
      if ((k % 3) == 1) fprintf(fout, " & & & \\\\\n");
      if ((k % 3) == 2) fprintf(fout, " & \\\\\n");
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

  if (global->user_exam_protocol_footer_file[0]
      && global->user_exam_protocol_footer_txt) {
    sformat_message(bigbuf, sizeof(bigbuf),
                    global->user_exam_protocol_footer_txt,
                    global, 0, 0, 0, &tdb, tdb.user, cnts, 0);
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
  //if (out_path[0]) unlink(out_path);
  return retval;
}

static int
full_user_report_generate(
        unsigned char *out_path,
        size_t out_size,
        const struct contest_desc *cnts,
        FILE *log_f,
        const serve_state_t cs,
        int user_id,
        int locale_id,
        int use_cypher)
{
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  const struct section_language_data *lang;
  int *run_ids;
  int total_runs, run_id, retval = -1, f_id, l_id, i, j, k;
  struct run_entry re;
  FILE *fout = 0;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  path_t src_path;
  int src_flags, answer, variant;
  char *src_txt = 0, *eptr, *num_txt = 0;
  size_t src_len = 0, num_len = 0;
  problem_xml_t px;
  const unsigned char *ans_txt;
  struct xml_attr *a;
  struct watched_file *pw = 0;
  const unsigned char *pw_path;
  path_t variant_stmt_file;
  unsigned char bigbuf[16384];
  struct teamdb_export tdb;
  time_t start_time, stop_time;
  unsigned char *psrc;
  const struct userlist_user *u = 0;
  const struct userlist_member *m = 0;
  const unsigned char *s;
  int need_variant = 0;
  int total_score = 0, cur_score;
  struct sformat_extra_data sf_extra;
  unsigned char sf_extra_buf[1024];

  memset(&sf_extra, 0, sizeof(sf_extra));
  sf_extra.str1 = sf_extra_buf;
  sf_extra_buf[0] = 0;

  if (global->score_system_val != SCORE_OLYMPIAD) return -1;

  if (teamdb_export_team(cs->teamdb_state, user_id, &tdb) < 0) {
    fprintf(log_f, "Invalid user %d\n", user_id);
    goto cleanup;
  }
  u = tdb.user;
  if (u && u->i.members[CONTEST_M_CONTESTANT]
      && u->i.members[CONTEST_M_CONTESTANT]->total > 0)
    m = u->i.members[CONTEST_M_CONTESTANT]->members[0];

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

  for (i = 1; i <= cs->max_prob; i++) {
    if (!(prob = cs->probs[i])) continue;
    if ((run_id = run_ids[i]) < 0) continue;
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0) continue;
    cur_score = re.score;
    if (cur_score < 0) cur_score = 0;
    cur_score += re.score_adj;
    if (cur_score < 0) cur_score = 0;
    if (re.status == RUN_OK && prob->variable_full_score <= 0)
      cur_score = prob->full_score;
    if (prob->score_multiplier > 0) cur_score *= prob->score_multiplier;
    total_score += cur_score;
  }

  snprintf(out_path, out_size, "%s/%06d.tex", global->print_work_dir, user_id);
  if (!(fout = fopen(out_path, "w"))) {
    fprintf(log_f, "Cannot open `%s' for writing\n", out_path);
    goto cleanup;
  }

  if (use_cypher) {
    if (u && u->i.exam_cypher)
      snprintf(sf_extra_buf, sizeof(sf_extra_buf), "%s", u->i.exam_cypher);
  } else {
    if (u && u->i.exam_id) {
      snprintf(sf_extra_buf, sizeof(sf_extra_buf), "%s, %s",
               teamdb_get_name_2(cs->teamdb_state, user_id),
               u->i.exam_id);
    } else {
      snprintf(sf_extra_buf, sizeof(sf_extra_buf), "%s",
               teamdb_get_name_2(cs->teamdb_state, user_id));
    }
  }

  if (global->full_exam_protocol_header_file[0]
      && global->full_exam_protocol_header_txt) {
    sformat_message(bigbuf, sizeof(bigbuf),
                    global->full_exam_protocol_header_txt,
                    global, 0, 0, 0, &tdb, tdb.user, cnts, &sf_extra);
    fprintf(fout, "%s", bigbuf);
  }

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }

  fprintf(fout, "\\noindent\\begin{tabular}{ll}\n");
  if (use_cypher && u && u->i.exam_cypher) {
    fprintf(fout, "%s: & %s\\\\\n", _("Cypher"), TARMOR(u->i.exam_cypher));
  } else {
    fprintf(fout, "%s: & %s\\\\\n", _("Login"), TARMOR(tdb.login));
    s = 0;
    if (m) {
      if (locale_id > 0) {
        s = m->surname;
        if (!s) s = m->surname_en;
      } else {
        s = m->surname_en;
        if (!s) s = m->surname;
      }
      if (s) fprintf(fout, "%s: & %s\\\\\n", _("Family name"), TARMOR(s));
      s = 0;
      if (locale_id > 0) {
        s = m->firstname;
        if (!s) s = m->firstname_en;
      } else {
        s = m->firstname_en;
        if (!s) s = m->firstname;
      }
      if (s) fprintf(fout, "%s: & %s\\\\\n", _("First name"), TARMOR(s));
      s = 0;
      if (locale_id > 0) {
        s = m->middlename;
        if (!s) s = m->middlename_en;
      } else {
        s = m->middlename_en;
        if (!s) s = m->middlename;
      }
      if (s) fprintf(fout, "%s: & %s\\\\\n", _("Middle name"), TARMOR(s));
    } else {
      fprintf(fout, "%s: & %s\\\\\n", _("Name"), TARMOR(tdb.name));
    }
    if (u && u->i.exam_id)
      fprintf(fout, "%s: & %s\\\\\n", _("Exam Id"), TARMOR(u->i.exam_id));
    if (u && u->i.location)
      fprintf(fout, "%s: & %s\\\\\n", _("Location"), TARMOR(u->i.location));

    if (start_time > 0) {
      fprintf(fout, "%s: & %s\\\\\n", _("Exam start time"),
              xml_unparse_date(start_time));
    }
    if (stop_time > 0) {
      fprintf(fout, "%s: & %s\\\\\n", _("Exam finish time"),
              xml_unparse_date(stop_time));
    }
  }
  fprintf(fout, "%s: & %d\\\\\n", _("Score"), total_score);
  fprintf(fout, "\\end{tabular}\n\n");

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
      prob = cs->probs[i = f_id];
      variant = 0;
      if (prob->variant_num > 0) {
        if ((variant = find_variant(cs, user_id, prob->id, 0)) <= 0) {
          fprintf(log_f, "No variant for user %d\n", user_id);
          goto cleanup;
        }
      }

      fprintf(fout, "\n\n\\vspace{0.5cm}\n\\noindent\\begin{tabular}{|p{1.5cm}");
      if (prob->variant_num > 0) fprintf(fout, "|l");
      fprintf(fout, "|p{3cm}|p{3cm}|p{1.5cm}|p{5cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s ", _("Problem"));
      if (prob->variant_num > 0) fprintf(fout, " & V");
      fprintf(fout, "& %s & %s & %s & %s\\\\\n\\hline\n",
              _("Language"), _("Tests passed"), _("Score"), _("Status"));

      if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
        fprintf(fout, "%s", TARMOR(prob->short_name));
      } else {
        fprintf(fout, "%s ---", TARMOR(prob->short_name));
        fprintf(fout, "%s", TARMOR(prob->long_name));
      }
      if (variant > 0) fprintf(fout, " & %d", variant);
      if ((run_id = run_ids[i]) < 0) {
        fprintf(fout, " & & & & \\textit{%s}\\\\\n", _("No answer is given"));
        fprintf(fout, "\\hline\n");
        fprintf(fout, "\\end{tabular}\n\n");
        break;
      }

      if (run_get_entry(cs->runlog_state, run_id, &re) < 0) abort();
      lang = 0;
      if (re.lang_id > 0 && re.lang_id <= cs->max_lang)
        lang = cs->langs[re.lang_id];
      if (!lang->long_name[0] || !strcmp(lang->long_name, lang->short_name)) {
        fprintf(fout, "& %s", TARMOR(lang->short_name));
      } else {
        fprintf(fout, "& %s ---", TARMOR(lang->short_name));
        fprintf(fout, "%s", TARMOR(lang->long_name));
      }

      // here calculate the score
      cur_score = re.score;
      if (re.status == RUN_OK && !prob->variable_full_score)
        cur_score = prob->full_score;

      // print the table
      if (re.test > 0) {
        fprintf(fout, " & %d", re.test - 1);
      } else {
        fprintf(fout, " &");
      }
      if (re.score >= 0) {
        fprintf(fout, " & %d", cur_score);
      } else {
        fprintf(fout, " &");
      }
      fprintf(fout, " & %s\\\\\n", run_status_str(re.status, 0, 0, 0, 0));
      fprintf(fout, "\\hline\n");
      fprintf(fout, "\\end{tabular}\n\n");

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
      while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
      src_txt[src_len] = 0;

      num_len = text_numbered_memlen(src_txt, src_len);
      num_txt = xmalloc(num_len + 16);
      text_number_lines(src_txt, src_len, num_txt);
      fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n",
              tex_armor_verbatim(num_txt));
      xfree(num_txt); num_txt = 0; num_len = 0;
      xfree(src_txt); src_txt = 0; src_len = 0;

      if (run_is_report_available(re.status)) {
        write_xml_tex_testing_report(fout, cs, run_id);
      }
      break;

    case PROB_TYPE_TEXT_ANSWER:
      prob = cs->probs[i = f_id];
      variant = 0;
      if (prob->variant_num > 0) {
        if ((variant = find_variant(cs, user_id, prob->id, 0)) <= 0) {
          fprintf(log_f, "No variant for user %d\n", user_id);
          goto cleanup;
        }
      }

      fprintf(fout, "\n\n\\vspace{0.5cm}\n\\noindent\\begin{tabular}{|p{1.5cm}");
      if (prob->variant_num > 0) fprintf(fout, "|l");
      fprintf(fout, "|p{3cm}|p{5cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s ", _("Problem"));
      if (prob->variant_num > 0) fprintf(fout, " & V");
      fprintf(fout, "& %s & %s\\\\\n\\hline\n", _("Score"), _("Status"));

      if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
        fprintf(fout, "%s", TARMOR(prob->short_name));
      } else {
        fprintf(fout, "%s ---", TARMOR(prob->short_name));
        fprintf(fout, "%s", TARMOR(prob->long_name));
      }
      if (variant > 0) fprintf(fout, " & %d", variant);
      if ((run_id = run_ids[i]) < 0) {
        fprintf(fout, " & & \\textit{%s}\\\\\n", _("No answer is given"));
        fprintf(fout, "\\hline\n");
        fprintf(fout, "\\end{tabular}\n\n");
        break;
      }

      if (run_get_entry(cs->runlog_state, run_id, &re) < 0) abort();
      cur_score = re.score;
      if (re.status == RUN_OK && !prob->variable_full_score)
        cur_score = prob->full_score;
      bigbuf[0] = 0;
      if (cur_score >= 0) snprintf(bigbuf, sizeof(bigbuf), "%d", cur_score);
      fprintf(fout, "& %s & %s \\\\\n", bigbuf,
              run_status_str(re.status, 0, 0, 0, 0));
      fprintf(fout, "\\hline\n");
      fprintf(fout, "\\end{tabular}\n\n");

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
      while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
      src_txt[src_len] = 0;

      num_len = text_numbered_memlen(src_txt, src_len);
      num_txt = xmalloc(num_len + 16);
      text_number_lines(src_txt, src_len, num_txt);
      fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n",
              tex_armor_verbatim_2(num_txt, VERBATIM_WIDTH));
      xfree(num_txt); num_txt = 0; num_len = 0;
      xfree(src_txt); src_txt = 0; src_len = 0;
      break;

    case PROB_TYPE_SHORT_ANSWER:
      need_variant = 0;
      for (i = f_id, k = 0; i < l_id; i++, k++)
        if ((prob = cs->probs[i]) && prob->variant_num > 0)
          need_variant = 1;

      fprintf(fout, "\n\n\\vspace{0.5cm}\n\\noindent\\begin{tabular}{|p{1.5cm}");
      if (need_variant) fprintf(fout, "|l");
      fprintf(fout, "|p{4cm}|p{1.5cm}|p{3cm}|p{4cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s", _("Problem"));
      if (need_variant) fprintf(fout, " & V");
      fprintf(fout, " & %s & %s & %s & %s \\\\\n", 
              _("Answer"), _("Score"), _("Status"), _("Comment"));
      for (i = f_id, k = 0; i < l_id; i++, k++) {
        if (!(prob = cs->probs[i])) continue;
        fprintf(fout, "\\hline\n");

        if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
          fprintf(fout, "%s", TARMOR(prob->short_name));
        } else {
          fprintf(fout, "%s-", TARMOR(prob->short_name));
          fprintf(fout, "%s", TARMOR(prob->long_name));
        }

        variant = 0;
        if (prob->variant_num > 0) {
          variant = find_variant(cs, user_id, prob->id, 0);
        }
        if (variant > 0) fprintf(fout, " & %d", variant);
        else if (need_variant) fprintf(fout, " &");

        if ((run_id = run_ids[i]) < 0) {
          fprintf(fout, " & & & & \\textit{%s} \\\\\n", _("No answer"));
          continue;
        }

        if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
        if (re.status == RUN_PARTIAL) re.status = RUN_WRONG_ANSWER_ERR;

        if ((src_flags = archive_make_read_path(cs, src_path, sizeof(src_path),
                                                global->run_archive_dir, run_id,
                                                0, 0)) < 0) {
          fprintf(log_f, "Source for run %d is not available\n", run_id);
          goto cleanup;
        }
        if (generic_read_file(&src_txt, 0, &src_len, src_flags, 0, src_path,
                              "") < 0) {
          fprintf(log_f, "Error reading from %s\n", src_path);
          goto cleanup;
        }
        if (strlen(src_txt) != src_len) {
          fprintf(log_f, "Source file %s is binary\n", src_path);
          goto cleanup;
        }
        while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
        src_txt[src_len] = 0;
        for (psrc = src_txt; *psrc; psrc++)
          if (*psrc < ' ') *psrc = ' ';

        fprintf(fout, " & %s", TARMOR(src_txt));
        cur_score = re.score;
        if (re.status == RUN_OK && !prob->variable_full_score)
          cur_score = prob->full_score;
        if (cur_score >= 0)
          fprintf(fout, " & %d", cur_score);
        else 
          fprintf(fout, " &");
        fprintf(fout, " & %s", run_status_str(re.status, 0, 0, 0, 0));
        psrc = ns_get_checker_comment(cs, run_id, 0);
        if (!psrc) psrc = xstrdup("");
        fprintf(fout, " & %s \\\\\n", TARMOR(psrc));
        xfree(psrc);
        xfree(src_txt); src_txt = 0; src_len = 0;
      }
      fprintf(fout, "\\hline\n");
      fprintf(fout, "\\end{tabular}\n\n");
      break;

    case PROB_TYPE_SELECT_ONE:
      need_variant = 0;
      for (i = f_id, k = 0; i < l_id; i++, k++)
        if ((prob = cs->probs[i]) && prob->variant_num > 0)
          need_variant = 1;

      fprintf(fout, "\n\n\\vspace{0.5cm}\n\\noindent\\begin{tabular}{|p{1.5cm}");
      if (need_variant) fprintf(fout, "|l");
      fprintf(fout, "|p{1.5cm}|p{5.5cm}|p{1.5cm}|p{4cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s", _("Problem"));
      if (need_variant) fprintf(fout, " & V");
      fprintf(fout, " & %s & %s & %s & %s \\\\\n", 
              _("Answer code"), _("Answer"), _("Score"), _("Status"));
      for (i = f_id, k = 0; i < l_id; i++, k++) {
        if (!(prob = cs->probs[i])) continue;
        fprintf(fout, "\\hline\n");

        if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
          fprintf(fout, "%s", TARMOR(prob->short_name));
        } else {
          fprintf(fout, "%s-", TARMOR(prob->short_name));
          fprintf(fout, "%s", TARMOR(prob->long_name));
        }
      
        variant = 0;
        if (prob->variant_num > 0) {
          variant = find_variant(cs, user_id, prob->id, 0);
        }
        if (variant > 0) fprintf(fout, " & %d", variant);
        else if (need_variant) fprintf(fout, " &");

        if ((run_id = run_ids[i]) < 0) {
          fprintf(fout, " & & & & \\textit{%s}", _("No answer"));
          fprintf(fout, " \\\\\n");
          continue;
        }

        if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
        if (re.status == RUN_PARTIAL) re.status = RUN_WRONG_ANSWER_ERR;
        cur_score = re.score;
        if (re.status == RUN_OK && !prob->variable_full_score)
          cur_score = prob->full_score;

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
        while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
        src_txt[src_len] = 0;
        errno = 0;
        answer = strtol(src_txt, &eptr, 10);
        if (errno || *eptr) {
          fprintf(log_f, "Source file %s is invalid\n", src_path);
          goto cleanup;
        }
        xfree(src_txt); src_txt = 0; src_len = 0;

        fprintf(fout, " & %d", answer);

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
            ans_txt = TARMOR(px->answers[answer - 1][j]->text);
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
          ans_txt = TARMOR(ans_txt);
        }

        fprintf(fout, " & %s", ans_txt);
        //fprintf(fout, " & %s", TARMOR(src_txt));
        if (cur_score >= 0)
          fprintf(fout, " & %d", cur_score);
        else 
          fprintf(fout, " &");
        fprintf(fout, " & %s\\\\\n",
                run_status_str(re.status, 0, 0, 0, 0));
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

  if (global->full_exam_protocol_footer_file[0]
      && global->full_exam_protocol_footer_txt) {
    sformat_message(bigbuf, sizeof(bigbuf),
                    global->full_exam_protocol_footer_txt,
                    global, 0, 0, 0, &tdb, tdb.user, cnts, 0);
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
  //if (out_path[0]) unlink(out_path);
  return retval;
}

static char * latex_args[] =
{
  "/usr/bin/latex",
  "-file-line-error-style",
  "-interaction=nonstopmode",
  "-src-specials",
  "-translate-file=cp8bit.tcx",
  0,
};

static int
invoke_latex(
        FILE *log_f,
        const unsigned char *tex_path,
        const unsigned char *err_path,
        const unsigned char *work_dir,
        int save_log_flag)
{
  tpTask tsk = 0;
  int retval = -1, i;
  char *err_txt = 0;
  size_t err_len = 0;

  if (!(tsk = task_New())) goto cleanup;
  task_SetWorkingDir(tsk, work_dir);
  task_pzAddArgs(tsk, latex_args);
  task_AddArg(tsk, tex_path);
  task_SetPathAsArg0(tsk);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", O_RDONLY);
  if (save_log_flag) {
    task_SetRedir(tsk, 2, TSR_FILE, err_path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    task_SetRedir(tsk, 1, TSR_DUP, 2);
  } else {
    task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", O_WRONLY, 0);
    task_SetRedir(tsk, 2, TSR_FILE, "/dev/null", O_WRONLY, 0);
  }

  fprintf(log_f, "%s", latex_args[0]);
  for (i = 1; latex_args[i]; i++)
    fprintf(log_f, " %s", latex_args[i]);
  fprintf(log_f, " %s", tex_path);
  if (save_log_flag) {
    fprintf(log_f, " </dev/null 2>%s 1>&2\n", err_path);
  } else {
    fprintf(log_f, " </dev/null 2>/dev/null 1>/dev/null\n");
  }
  if (task_Start(tsk) < 0) {
    fprintf(log_f, "failed to start process\n");
    goto cleanup;
  }
  task_Wait(tsk);
  if (save_log_flag) {
    if (generic_read_file(&err_txt, 0, &err_len, 0, 0, err_path, 0) < 0) {
      fprintf(log_f, "failed to read log file from %s\n", err_path);
    } else {
      fwrite(err_txt, 1, err_len, log_f);
      fprintf(log_f, "\n");
      xfree(err_txt); err_txt = 0;
      err_len = 0;
    }
  }

  if (task_IsTimeout(tsk)) {
    fprintf(log_f, "latex process time-out\n");
    goto cleanup;
  } else if (task_IsAbnormal(tsk)) {
    if (task_Status(tsk) == TSK_SIGNALED) {
      i = task_TermSignal(tsk);
      fprintf(log_f, "latex process terminated by signal %d (%s)\n",
              i, os_GetSignalString(i));
    } else {
      fprintf(log_f, "latex process exited with code %d\n",
              task_ExitCode(tsk));
    }
    goto cleanup;
  }

  fprintf(log_f, "latex process exited normally\n");
  task_Delete(tsk); tsk = 0;
  retval = 0;

 cleanup:
  xfree(err_txt);
  if (tsk) task_Delete(tsk);
  return retval;
}

static char * dvips_args[] =
{
  "/usr/bin/dvips",
  0,
};

static int
invoke_dvips(
        FILE *log_f,
        const unsigned char *dvi_path,
        const unsigned char *err_path,
        const unsigned char *work_dir,
        int save_log_flag)
{
  tpTask tsk = 0;
  int retval = -1, i;
  char *err_txt = 0;
  size_t err_len = 0;

  if (!(tsk = task_New())) goto cleanup;
  task_SetWorkingDir(tsk, work_dir);
  task_pzAddArgs(tsk, dvips_args);
  task_AddArg(tsk, dvi_path);
  task_AddArg(tsk, "-o");
  task_SetPathAsArg0(tsk);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", O_RDONLY);
  if (save_log_flag) {
    task_SetRedir(tsk, 2, TSR_FILE, err_path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    task_SetRedir(tsk, 1, TSR_DUP, 2);
  } else {
    task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", O_WRONLY, 0);
    task_SetRedir(tsk, 2, TSR_FILE, "/dev/null", O_WRONLY, 0);
  }

  fprintf(log_f, "%s", dvips_args[0]);
  for (i = 1; dvips_args[i]; i++)
    fprintf(log_f, " %s", dvips_args[i]);
  fprintf(log_f, " %s -o", dvi_path);
  if (save_log_flag) {
    fprintf(log_f, " </dev/null 2>%s 1>&2\n", err_path);
  } else {
    fprintf(log_f, " </dev/null 2>/dev/null 1>/dev/null\n");
  }
  if (task_Start(tsk) < 0) {
    fprintf(log_f, "failed to start process\n");
    goto cleanup;
  }
  task_Wait(tsk);
  if (save_log_flag) {
    if (generic_read_file(&err_txt, 0, &err_len, 0, 0, err_path, 0) < 0) {
      fprintf(log_f, "failed to read log file from %s\n", err_path);
    } else {
      fwrite(err_txt, 1, err_len, log_f);
      fprintf(log_f, "\n");
      xfree(err_txt); err_txt = 0;
      err_len = 0;
    }
  }

  if (task_IsTimeout(tsk)) {
    fprintf(log_f, "dvips process time-out\n");
    goto cleanup;
  } else if (task_IsAbnormal(tsk)) {
    if (task_Status(tsk) == TSK_SIGNALED) {
      i = task_TermSignal(tsk);
      fprintf(log_f, "dvips process terminated by signal %d (%s)\n",
              i, os_GetSignalString(i));
    } else {
      fprintf(log_f, "dvips process exited with code %d\n",
              task_ExitCode(tsk));
    }
    goto cleanup;
  }

  fprintf(log_f, "dvips process exited normally\n");
  task_Delete(tsk); tsk = 0;
  retval = 0;

 cleanup:
  xfree(err_txt);
  if (tsk) task_Delete(tsk);
  return retval;
}

int
invoke_lpr(
        FILE *log_f,
        const struct section_global_data *global,
        const unsigned char *printer_name,
        const unsigned char *ps_path,
        const unsigned char *err_path,
        int save_log_flag)
{
  tpTask tsk = 0;
  int retval = -1, i;
  char *err_txt = 0;
  size_t err_len = 0;

  if (!(tsk = task_New())) goto cleanup;
  task_SetWorkingDir(tsk, global->print_work_dir);
  task_AddArg(tsk, global->lpr_path);
  if (global->lpr_args) {
    for (i = 0; global->lpr_args[i]; i++)
      task_AddArg(tsk, global->lpr_args[i]);
  }
  if (printer_name) {
    task_AddArg(tsk, "-P");
    task_AddArg(tsk, printer_name);
  }
  task_AddArg(tsk, ps_path);
  task_SetPathAsArg0(tsk);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", O_RDONLY);
  if (save_log_flag) {
    task_SetRedir(tsk, 2, TSR_FILE, err_path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    task_SetRedir(tsk, 1, TSR_DUP, 2);
  } else {
    task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", O_WRONLY, 0);
    task_SetRedir(tsk, 2, TSR_FILE, "/dev/null", O_WRONLY, 0);
  }

  fprintf(log_f, "%s", global->lpr_path);
  if (global->lpr_args) {
    for (i = 1; global->lpr_args[i]; i++)
      fprintf(log_f, " %s", global->lpr_args[i]);
  }
  if (printer_name) {
    fprintf(log_f, " -P %s", printer_name);
  }
  fprintf(log_f, " %s", ps_path);
  if (save_log_flag) {
    fprintf(log_f, " </dev/null 2>%s 1>&2\n", err_path);
  } else {
    fprintf(log_f, " </dev/null 2>/dev/null 1>/dev/null\n");
  }
  if (task_Start(tsk) < 0) {
    fprintf(log_f, "failed to start process\n");
    goto cleanup;
  }
  task_Wait(tsk);
  if (save_log_flag) {
    if (generic_read_file(&err_txt, 0, &err_len, 0, 0, err_path, 0) < 0) {
      fprintf(log_f, "failed to read log file from %s\n", err_path);
    } else {
      fwrite(err_txt, 1, err_len, log_f);
      fprintf(log_f, "\n");
      xfree(err_txt); err_txt = 0;
      err_len = 0;
    }
  }

  if (task_IsTimeout(tsk)) {
    fprintf(log_f, "lpr process time-out\n");
    goto cleanup;
  } else if (task_IsAbnormal(tsk)) {
    if (task_Status(tsk) == TSK_SIGNALED) {
      i = task_TermSignal(tsk);
      fprintf(log_f, "lpr process terminated by signal %d (%s)\n",
              i, os_GetSignalString(i));
    } else {
      fprintf(log_f, "lpr process exited with code %d\n",
              task_ExitCode(tsk));
    }
    goto cleanup;
  }

  fprintf(log_f, "lpr process exited normally\n");
  task_Delete(tsk); tsk = 0;
  retval = 0;

 cleanup:
  xfree(err_txt);
  if (tsk) task_Delete(tsk);
  return retval;
}

int
invoke_convert(
        FILE *log_f,
        const struct section_global_data *global,
        const unsigned char *in_path,
        const unsigned char *ps_path,
        const unsigned char *err_path,
        int save_log_flag)
{
  tpTask tsk = 0;
  int retval = -1, i;
  char *err_txt = 0;
  size_t err_len = 0;

  if (!(tsk = task_New())) goto cleanup;
  task_SetWorkingDir(tsk, global->print_work_dir);
  task_AddArg(tsk, "/usr/bin/convert");
  task_AddArg(tsk, in_path);
  task_AddArg(tsk, ps_path);
  task_SetPathAsArg0(tsk);
  task_SetRedir(tsk, 0, TSR_FILE, "/dev/null", O_RDONLY);
  if (save_log_flag) {
    task_SetRedir(tsk, 2, TSR_FILE, err_path, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    task_SetRedir(tsk, 1, TSR_DUP, 2);
  } else {
    task_SetRedir(tsk, 1, TSR_FILE, "/dev/null", O_WRONLY, 0);
    task_SetRedir(tsk, 2, TSR_FILE, "/dev/null", O_WRONLY, 0);
  }

  fprintf(log_f, "%s", "/usr/bin/convert");
  fprintf(log_f, " %s", in_path);
  fprintf(log_f, " %s", ps_path);
  if (save_log_flag) {
    fprintf(log_f, " </dev/null 2>%s 1>&2\n", err_path);
  } else {
    fprintf(log_f, " </dev/null 2>/dev/null 1>/dev/null\n");
  }
  if (task_Start(tsk) < 0) {
    fprintf(log_f, "failed to start process\n");
    goto cleanup;
  }
  task_Wait(tsk);
  if (save_log_flag) {
    if (generic_read_file(&err_txt, 0, &err_len, 0, 0, err_path, 0) < 0) {
      fprintf(log_f, "failed to read log file from %s\n", err_path);
    } else {
      fwrite(err_txt, 1, err_len, log_f);
      fprintf(log_f, "\n");
      xfree(err_txt); err_txt = 0;
      err_len = 0;
    }
  }

  if (task_IsTimeout(tsk)) {
    fprintf(log_f, "convert process time-out\n");
    goto cleanup;
  } else if (task_IsAbnormal(tsk)) {
    if (task_Status(tsk) == TSK_SIGNALED) {
      i = task_TermSignal(tsk);
      fprintf(log_f, "convert process terminated by signal %d (%s)\n",
              i, os_GetSignalString(i));
    } else {
      fprintf(log_f, "convert process exited with code %d\n",
              task_ExitCode(tsk));
    }
    goto cleanup;
  }

  fprintf(log_f, "convert process exited normally\n");
  task_Delete(tsk); tsk = 0;
  retval = 0;

 cleanup:
  xfree(err_txt);
  if (tsk) task_Delete(tsk);
  return retval;
}

int
ns_print_user_exam_protocol(
        const struct contest_desc *cnts,
        const serve_state_t cs,
        FILE *log_f,
        int user_id,
        int locale_id,
        int use_user_printer,
        int full_report,
        int use_cypher)
{
  const struct section_global_data *global = cs->global;
  path_t tex_path;
  path_t err_path;
  path_t dvi_path;
  path_t ps_path;
  path_t tst_path;
  int retval = -1;
  const unsigned char *printer_name = 0;
  struct teamdb_export tdb;

  if (use_user_printer) {
    memset(&tdb, 0, sizeof(tdb));
    teamdb_export_team(cs->teamdb_state, user_id, &tdb);
    if (tdb.user) printer_name = tdb.user->i.printer_name;
  }

  tex_path[0] = 0;
  if (full_report) {
    if (full_user_report_generate(tex_path, sizeof(tex_path), cnts, log_f, cs,
                                  user_id, locale_id, use_cypher) < 0)
      goto cleanup;
  } else {
    if (user_report_generate(tex_path, sizeof(tex_path), cnts, log_f, cs,
                             user_id, locale_id) < 0)
      goto cleanup;
  }

  snprintf(err_path, sizeof(err_path), "%s/%06d.err",
           global->print_work_dir, user_id);
  snprintf(dvi_path, sizeof(dvi_path), "%s/%06d.dvi",
           global->print_work_dir, user_id);
  snprintf(ps_path, sizeof(ps_path), "%s/%06d.ps",
           global->print_work_dir, user_id);
  if (invoke_latex(log_f, tex_path, err_path, global->print_work_dir, 1) < 0)
    goto cleanup;
  if (invoke_latex(log_f, tex_path, err_path, global->print_work_dir, 0) < 0)
    goto cleanup;
  if (invoke_dvips(log_f, dvi_path, err_path, global->print_work_dir, 1) < 0)
    goto cleanup;

  snprintf(tst_path, sizeof(tst_path), "%s/.noprint", global->print_work_dir);
  if (os_CheckAccess(tst_path, REUSE_F_OK) < 0) {
    if (invoke_lpr(log_f, global, printer_name, ps_path, err_path, 1) < 0)
      goto cleanup;
  }

  retval = 0;

 cleanup:
  snprintf(tst_path, sizeof(tst_path), "%s/.noclean", global->print_work_dir);
  if (os_CheckAccess(tst_path, REUSE_F_OK) < 0) {
    clear_directory(global->print_work_dir);
  }
  return retval;
}

int
ns_print_user_exam_protocols(
        const struct contest_desc *cnts,
        const serve_state_t cs,
        FILE *log_f,
        int nuser,
        int *user_ids,
        int locale_id,
        int use_user_printer,
        int full_report,
        int use_cypher)
{
  const struct section_global_data *global = cs->global;
  path_t tex_path;
  path_t err_path;
  path_t dvi_path;
  path_t ps_path;
  path_t tst_path;
  int retval = -1, i, user_id;
  const unsigned char *printer_name = 0;
  struct teamdb_export tdb;

  for (i = 0; i < nuser; i++) {
    user_id = user_ids[i];
    tex_path[0] = 0;
    if (full_report) {
      if (full_user_report_generate(tex_path, sizeof(tex_path), cnts, log_f, cs,
                                    user_id, locale_id, use_cypher) < 0)
        goto cleanup;
    } else {
      if (user_report_generate(tex_path, sizeof(tex_path), cnts, log_f, cs,
                               user_id, locale_id) < 0)
        goto cleanup;
    }

    snprintf(err_path, sizeof(err_path), "%s/%06d.err",
             global->print_work_dir, user_id);
    snprintf(dvi_path, sizeof(dvi_path), "%s/%06d.dvi",
             global->print_work_dir, user_id);
    if (invoke_latex(log_f, tex_path, err_path, global->print_work_dir, 1) < 0)
      goto cleanup;
    if (invoke_latex(log_f, tex_path, err_path, global->print_work_dir, 0) < 0)
      goto cleanup;
    if (invoke_dvips(log_f, dvi_path, err_path, global->print_work_dir, 1) < 0)
      goto cleanup;
  }

  // all PS files are ready, so print them all
  for (i = 0; i < nuser; i++) {
    user_id = user_ids[i];

    printer_name = 0;
    if (use_user_printer) {
      memset(&tdb, 0, sizeof(tdb));
      teamdb_export_team(cs->teamdb_state, user_id, &tdb);
      if (tdb.user) printer_name = tdb.user->i.printer_name;
    }

    snprintf(ps_path, sizeof(ps_path), "%s/%06d.ps",
             global->print_work_dir, user_id);

    snprintf(tst_path, sizeof(tst_path), "%s/.noprint", global->print_work_dir);
    if (os_CheckAccess(tst_path, REUSE_F_OK) < 0) {
      if (invoke_lpr(log_f, global, printer_name, ps_path, err_path, 1) < 0)
        goto cleanup;
    }
  }

  retval = 0;

 cleanup:
  snprintf(tst_path, sizeof(tst_path), "%s/.noclean", global->print_work_dir);
  if (os_CheckAccess(tst_path, REUSE_F_OK) < 0) {
    clear_directory(global->print_work_dir);
  }
  return retval;
}

int
ns_olympiad_final_user_report(
        FILE *fout,
        FILE *log_f,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int user_id,
        int locale_id)
{
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  const struct section_language_data *lang;
  int *run_ids;
  int total_runs, run_id, retval = -1, f_id, l_id, i, j, k;
  struct run_entry re;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  path_t src_path;
  int src_flags, answer, variant, passed_tests;
  char *src_txt = 0, *eptr, *num_txt = 0;
  size_t src_len = 0, num_len = 0;
  problem_xml_t px;
  const unsigned char *ans_txt;
  struct xml_attr *a;
  struct watched_file *pw = 0;
  const unsigned char *pw_path;
  path_t variant_stmt_file;
  struct teamdb_export tdb;
  time_t start_time, stop_time;
  unsigned char *psrc;
  const struct userlist_user *u = 0;
  const struct userlist_member *m = 0;
  const unsigned char *s;
  const unsigned char *td0 = "<td class=\"b0\">";
  const unsigned char *td1 = "<td class=\"b1\">";
  const unsigned char *th1 = "<th class=\"b1\">";

  if (global->score_system_val != SCORE_OLYMPIAD) return -1;

  if (teamdb_export_team(cs->teamdb_state, user_id, &tdb) < 0) {
    fprintf(log_f, "Invalid user %d\n", user_id);
    goto cleanup;
  }
  u = tdb.user;
  if (u && u->i.members[CONTEST_M_CONTESTANT]
      && u->i.members[CONTEST_M_CONTESTANT]->total > 0)
    m = u->i.members[CONTEST_M_CONTESTANT]->members[0];

  XALLOCA(run_ids, cs->max_prob + 1);
  memset(run_ids, -1, sizeof(run_ids[0]) * (cs->max_prob + 1));

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

  // from this point on we cannot report fatal error

  if (global->is_virtual) {
    start_time = run_get_virtual_start_time(cs->runlog_state, user_id);
    stop_time = run_get_virtual_stop_time(cs->runlog_state, user_id,
                                          cs->current_time);
  } else {
    start_time = run_get_start_time(cs->runlog_state);
    stop_time = run_get_stop_time(cs->runlog_state);
  }

  fprintf(fout, "<table class=\"b0\">\n");
  fprintf(fout, "<tr>%s%s:</td>%s%s</td></tr>\n",
          td0, _("Login"), td0, ARMOR(tdb.login));
  s = 0;
  if (m) {
    if (locale_id > 0) {
      s = m->surname;
      if (!s) s = m->surname_en;
    } else {
      s = m->surname_en;
      if (!s) s = m->surname;
    }
    if (s) fprintf(fout, "<tr>%s%s:</td>%s%s</td></tr>\n",
                   td0, _("Family name"), td0, ARMOR(s));
    s = 0;
    if (locale_id > 0) {
      s = m->firstname;
      if (!s) s = m->firstname_en;
    } else {
      s = m->firstname_en;
      if (!s) s = m->firstname;
    }
    if (s) fprintf(fout, "<tr>%s%s:</td>%s%s</td></tr>\n",
                   td0, _("First name"), td0, ARMOR(s));
    s = 0;
    if (locale_id > 0) {
      s = m->middlename;
      if (!s) s = m->middlename_en;
    } else {
      s = m->middlename_en;
      if (!s) s = m->middlename;
    }
    if (s) fprintf(fout, "<tr>%s%s:</td>%s%s</td></tr>\n",
                   td0, _("Middle name"), td0, ARMOR(s));
  } else {
    fprintf(fout, "<tr>%s%s:</td>%s%s</td></tr>\n",
            td0, _("Name"), td0, ARMOR(tdb.name));
  }
  if (u && u->i.exam_id)
    fprintf(fout, "<tr>%s%s:</td>%s%s</td></tr>\n",
            td0, _("Exam Id"), td0, ARMOR(u->i.exam_id));
  if (u && u->i.location)
    fprintf(fout, "<tr>%s%s:</td>%s%s</td></tr>\n",
            td0, _("Location"), td0, ARMOR(u->i.location));

  if (start_time > 0) {
    fprintf(fout, "<tr>%s%s:</td>%s%s</td></tr>\n",
            td0, _("Exam start time"), td0, xml_unparse_date(start_time));
  }
  if (stop_time > 0) {
    fprintf(fout, "<tr>%s%s:</td>%s%s</td></tr>\n",
            td0, _("Exam finish time"), td0, xml_unparse_date(stop_time));
  }
  fprintf(fout, "</table>\n");

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
      fprintf(fout, "<br/><table class=\"b1\"><tr>%s%s</th>%s%s</th>%s%s</th>%s%s</th></tr>\n",
              th1, _("Problem"), th1, _("Language"), th1, _("Passed tests"),
              th1, _("Comment"));

      fprintf(fout, "<tr>%s", td1);
      prob = cs->probs[i = f_id];
      if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
        fprintf(fout, "%s", ARMOR(prob->short_name));
      } else {
        fprintf(fout, "%s-", ARMOR(prob->short_name));
        fprintf(fout, "%s", ARMOR(prob->long_name));
      }
      fprintf(fout, "</td>");
      if ((run_id = run_ids[i]) < 0) {
        fprintf(fout, "%s&nbsp;</td>%s&nbsp;</td>%s<i>%s</i></td></tr></table>\n",
                td1, td1, td1, _("No answer is given"));
        break;
      }
      if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
      if (re.status == RUN_OK || re.status == RUN_PARTIAL)
        re.status = RUN_ACCEPTED;
      passed_tests = re.test - 1;
      if (passed_tests > prob->tests_to_accept)
        passed_tests = prob->tests_to_accept;
      if (re.lang_id <= 0 || re.lang_id > cs->max_lang
          || !(lang = cs->langs[re.lang_id])) {
        fprintf(log_f, "Invalid language %d in run %d\n", re.lang_id, run_id);
        goto cleanup;
      }
      if (!lang->long_name[0] || !strcmp(lang->long_name, lang->short_name)) {
        fprintf(fout, "%s%s</td>", td1, ARMOR(lang->short_name));
      } else {
        fprintf(fout, "%s%s-", td1, ARMOR(lang->short_name));
        fprintf(fout, "%s</td>", ARMOR(lang->long_name));
      }
      fprintf(fout, "%s%d</td>", td1, passed_tests);
      fprintf(fout, "%s<i>%s</i></td></tr></table>\n", td1,
              run_status_str(re.status, 0, 0, 0, 0));

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
      while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
      src_txt[src_len] = 0;

      num_len = text_numbered_memlen(src_txt, src_len);
      num_txt = xmalloc(num_len + 16);
      text_number_lines(src_txt, src_len, num_txt);
      fprintf(fout, "<br/><table class=\"b1\"><tr>%s%s</th></tr>\n<tr>%s<pre>%s</pre></td></tr></table>\n",
              th1, _("Source code"),
              td1, ARMOR(num_txt));
      fprintf(fout, "<p>%s</p>\n",
              _("Note, lines are numbered just for your convinience."));
      xfree(num_txt); num_txt = 0; num_len = 0;
      xfree(src_txt); src_txt = 0; src_len = 0;
      break;

    case PROB_TYPE_TEXT_ANSWER:
      fprintf(fout, "<br/><table class=\"b1\"><tr>%s%s</th>%s%s</th></tr>\n",
              th1, _("Problem"), th1, _("Comment"));
      i = f_id;
      prob = cs->probs[f_id];
      fprintf(fout, "<tr>");
      if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
        fprintf(fout, "%s%s</td>", td1, ARMOR(prob->short_name));
      } else {
        fprintf(fout, "%s%s-", td1, ARMOR(prob->short_name));
        fprintf(fout, "%s</td>", ARMOR(prob->long_name));
      }
      if ((run_id = run_ids[i]) < 0) {
        fprintf(fout, "%s<i>%s</i></td></tr></table>\n", td1,
                _("No answer is given"));
        break;
      }
      if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
      if (re.status == RUN_OK || re.status == RUN_PARTIAL
          || re.status == RUN_WRONG_ANSWER_ERR)
        re.status = RUN_ACCEPTED;
      if (re.status != RUN_ACCEPTED) {
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
      while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
      src_txt[src_len] = 0;

      if (!src_len) {
        fprintf(fout, "%s<i>%s</i></td></tr></table>\n", td1,
                _("Answer is empty"));
        break;
      }
      fprintf(fout, "%s<i>%s</i></td></tr></table>\n", td1,
              _("Accepted for testing"));

      num_len = text_numbered_memlen(src_txt, src_len);
      num_txt = xmalloc(num_len + 16);
      text_number_lines(src_txt, src_len, num_txt);
      fprintf(fout,
              "<br/><table class=\"b1\"><tr>%s%s</th></tr>\n<tr>%s<pre>%s</pre></td></tr></table>\n",
              th1, _("Answer text"),
              td1, ARMOR(num_txt));
      fprintf(fout, "<p>%s</p>\n", 
              _("Note, lines are numbered just for your convinience."));
      xfree(num_txt); num_txt = 0; num_len = 0;
      xfree(src_txt); src_txt = 0; src_len = 0;
      break;

    case PROB_TYPE_SHORT_ANSWER:
      fprintf(fout, "<br/><table class=\"b1\">\n"
              "<tr>%s%s</th>%s%s</th>%s%s</th>%s%s</th></tr>\n",
              th1, _("Problem"), th1, _("Answer"),
              th1, _("Problem"), th1, _("Answer"));
      for (i = f_id, k = 0; i < l_id; i++, k++) {
        if (!(prob = cs->probs[i])) continue;
        if (!(k % 2)) fprintf(fout, "<tr>");
        if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
          fprintf(fout, "%s%s</td>", td1, ARMOR(prob->short_name));
        } else {
          fprintf(fout, "%s%s-", td1, ARMOR(prob->short_name));
          fprintf(fout, "%s</td>", ARMOR(prob->long_name));
        }
        if ((run_id = run_ids[i]) < 0) {
          fprintf(fout, "%s<i>%s</i></td>", td1, _("No answer"));
          if ((k % 2) == 1) fprintf(fout, "</tr>\n");
          continue;
        }
        if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
        if (re.status == RUN_OK || re.status == RUN_PARTIAL
            || re.status == RUN_WRONG_ANSWER_ERR)
          re.status = RUN_ACCEPTED;
        if (re.status != RUN_ACCEPTED && re.status != RUN_PRESENTATION_ERR) {
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
        while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
        src_txt[src_len] = 0;
        for (psrc = src_txt; *psrc; psrc++)
          if (*psrc < ' ') *psrc = ' ';
        //for (psrc = src_txt; *psrc && *psrc != ' '; psrc++);
        fprintf(fout, "%s%s</td>", td1, ARMOR(src_txt));

        /*
        if (re.status == RUN_ACCEPTED) {
          fprintf(fout, " \\textit{%s}\\\\\n", _("Accepted for testing"));
        } else {
        // presentation error
          psrc = ns_get_checker_comment(cs, run_id, 0);
          if (!psrc) psrc = xstrdup("");
          fprintf(fout, "\\textit{%s} \\\\\n", TARMOR(psrc));
          xfree(psrc);
        }
        */
        xfree(src_txt); src_txt = 0;
        src_len = 0;
        if ((k % 2) == 1) fprintf(fout, "</tr>\n");
      }
      if (k % 2 == 1) fprintf(fout, "%s&nbsp;</td>%s&nbsp;</td></tr>",
                              td1, td1);
      fprintf(fout, "</table>\n");
      /*
      fprintf(fout, "\\noindent{}%s\n\n",
              _("Note, that only solutions marked ``Accepted for testing'' are subject to further testing. Other solutions \\textbf{will not} be tested."));
      */
      break;

    case PROB_TYPE_SELECT_ONE:
      fprintf(fout, "<br/><table class=\"b1\">\n"
              "<tr>%s%s</th>%s%s</th>%s%s</th>%s%s</th>%s%s</th>%s%s</th></tr>\n",
              th1, _("Problem"), th1, _("Answer code"),
              th1, _("Problem"), th1, _("Answer code"),
              th1, _("Problem"), th1, _("Answer code"));
      for (i = f_id, k = 0; i < l_id; i++, k++) {
        if (!(prob = cs->probs[i])) continue;
        if (!(k % 3)) fprintf(fout, "<tr>");
        if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
          fprintf(fout, "%s%s</td>", td1, ARMOR(prob->short_name));
        } else {
          fprintf(fout, "%s%s-", td1, ARMOR(prob->short_name));
          fprintf(fout, "%s</td>", ARMOR(prob->long_name));
        }
        if ((run_id = run_ids[i]) < 0) {
          fprintf(fout, "%s<i>%s</i></td>", td1, _("No answer"));
          if ((k % 3) == 2) fprintf(fout, "</tr>\n");
          continue;
        }
        if (run_get_entry(cs->runlog_state, run_ids[i], &re) < 0) abort();
        if (re.status != RUN_OK && re.status != RUN_PARTIAL
            && re.status != RUN_ACCEPTED && re.status != RUN_WRONG_ANSWER_ERR) {
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
        while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
        src_txt[src_len] = 0;
        errno = 0;
        answer = strtol(src_txt, &eptr, 10);
        if (errno || *eptr) {
          fprintf(log_f, "Source file %s is invalid\n", src_path);
          goto cleanup;
        }
        xfree(src_txt); src_txt = 0; src_len = 0;
        variant = 0;
        if (prob->variant_num > 0) {
          if ((variant = find_variant(cs, user_id, i, 0)) <= 0) {
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
            ans_txt = TARMOR(px->answers[answer - 1][j]->text);
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
          ans_txt = TARMOR(ans_txt);
        }
        //fprintf(fout, "%d & %s\\\\\n", answer, ans_txt);
        fprintf(fout, "%s%d</td>", td1, answer);
        if ((k % 3) == 2) fprintf(fout, "</tr>\n");
      }
      if ((k % 3) == 1)
        fprintf(fout, "%s&nbsp;</td>%s&nbsp;</td>%s&nbsp;</td>%s&nbsp;</td></tr>\n", td1, td1, td1, td1);
      if ((k % 3) == 2)
        fprintf(fout, "%s&nbsp;</td>%s&nbsp;</td></tr>\n", td1, td1);
      fprintf(fout, "</table>\n");
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

  retval = 0;

 cleanup:
  xfree(src_txt);
  html_armor_free(&ab);
  //if (out_path[0]) unlink(out_path);
  return retval;
}

static void
write_xml_tex_testing_report(
        FILE *fout,
        const serve_state_t cs,
        int run_id)
{
  const struct section_global_data *global = cs->global;
  path_t rep_path;
  int rep_flag, i;
  char *rep_text = 0;
  size_t rep_len = 0;
  const unsigned char *start_ptr = 0;
  testing_report_xml_t r = 0;
  struct testing_report_test *t;
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int max_cpu_time = -1, max_cpu_time_tl = -1, need_comment = 0;

  rep_flag = archive_make_read_path(cs, rep_path, sizeof(rep_path),
                                    global->xml_report_archive_dir,
                                    run_id, 0, 1);
  if (rep_flag < 0) {
    fprintf(fout, "\n\nReport for run %d is not available.\n\n", run_id);
    goto cleanup;
  }

  if (generic_read_file(&rep_text, 0, &rep_len, rep_flag, 0, rep_path, 0) < 0) {
    fprintf(fout, "\n\nRead error for report %d.\n\n", run_id);
    goto cleanup;
  }

  if (get_content_type(rep_text, &start_ptr) != CONTENT_TYPE_XML) {
    fprintf(fout, "\n\nReport is not in XML format.\n\n");
    goto cleanup;
  }

  if (!(r = testing_report_parse_xml(start_ptr))) {
    fprintf(fout, "\n\nXML report parse error.\n\n");
    goto cleanup;
  }

  fprintf(fout, _("\n\n%d total tests runs, %d passed, %d failed.\n\n"),
            r->run_tests, r->tests_passed, r->run_tests - r->tests_passed);
  fprintf(fout, _("Score gained: %d (out of %d).\n\n"), r->score, r->max_score);

  if (r->valuer_comment) {
    fprintf(fout, "%s:\n", _("Valuer comments"));
    fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n",
            tex_armor_verbatim_2(chop2(r->valuer_comment), VERBATIM_WIDTH));
  }
  if (r->valuer_judge_comment) {
    fprintf(fout, "%s:\n", _("Valuer judge comments"));
    fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n",
            tex_armor_verbatim_2(chop2(r->valuer_judge_comment),
                                 VERBATIM_WIDTH));
  }
  if (r->valuer_errors) {
    fprintf(fout, "%s:\n", _("Valuer errors"));
    fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n",
            tex_armor_verbatim_2(chop2(r->valuer_errors), VERBATIM_WIDTH));
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
      if (max_cpu_time_tl > 0) break;
      max_cpu_time_tl = 0;
      if (max_cpu_time < 0 || max_cpu_time < r->tests[i]->time) {
        max_cpu_time = r->tests[i]->time;
      }
      break;
    case RUN_TIME_LIMIT_ERR:
      if (max_cpu_time_tl <= 0 || max_cpu_time < 0
          || max_cpu_time < r->tests[i]->time) {
        max_cpu_time = r->tests[i]->time;
      }
      max_cpu_time_tl = 1;
      break;
    }
  }

  if (max_cpu_time_tl > 0) {
    fprintf(fout, _("Max. CPU time: %d.%03d (time-limit exceeded)\n\n"),
            max_cpu_time / 1000, max_cpu_time % 1000);
  } else if (!max_cpu_time_tl) {
    fprintf(fout, _("Max. CPU time: %d.%03d\n\n"),
            max_cpu_time / 1000, max_cpu_time % 1000);
  }

  if (r->comment) {
    fprintf(fout, "Note:\n\\begin{verbatim}\n%s\\end{verbatim}\n\n",
            tex_armor_verbatim_2(chop2(r->comment), VERBATIM_WIDTH));
  }

  for (i = 0; i < r->run_tests; i++) {
    if (!(t = r->tests[i])) continue;
    if (t->comment || t->team_comment) {
      need_comment = 1;
      break;
    }
  }

  fprintf(fout, "\n\n\\noindent\\begin{tabular}{|l|p{4cm}|p{1.5cm}|p{1.5cm}|p{5cm}|p{1.5cm}");
  if (need_comment) fprintf(fout, "|p{4cm}");
  fprintf(fout, "|}\n\\hline\n"
          "N & %s & %s & %s & %s & %s",
          _("Result"), _("Time (sec)"), _("Real time (sec)"),
          _("Extra info"), _("Score"));
  if (need_comment) fprintf(fout, " & %s", _("Comment"));
  fprintf(fout, "\\\\\n\\hline\n");

  for (i = 0; i < r->run_tests; i++) {
    if (!(t = r->tests[i])) continue;
    fprintf(fout, "%d", t->num);
    fprintf(fout, " & %s", run_status_str(t->status, 0, 0, 0, 0));
    fprintf(fout, " & %d.%03d", t->time / 1000, t->time % 1000);
    if (t->real_time > 0) {
      fprintf(fout, " & %d.%03d", t->real_time / 1000, t->real_time % 1000);
    } else {
      fprintf(fout, " &");
    }

    // extra information
    switch (t->status) {
    case RUN_OK:
    case RUN_ACCEPTED:
      if (t->checker_comment) {
        fprintf(fout, " & %s", TARMOR(t->checker_comment));
      } else {
        fprintf(fout, " &");
      }
      break;

    case RUN_RUN_TIME_ERR:
      if (t->term_signal >= 0) {
        fprintf(fout, " & %s %d (%s)", _("Signal"), t->term_signal,
                os_GetSignalString(t->term_signal));
      } else {
        fprintf(fout, " & %s %d", _("Exit code"), t->exit_code);
      }
      break;

    case RUN_TIME_LIMIT_ERR:
      fprintf(fout, " &");
      break;

    case RUN_PRESENTATION_ERR:
    case RUN_WRONG_ANSWER_ERR:
      if (t->checker_comment) {
        fprintf(fout, " & %s", TARMOR(t->checker_comment));
      } else {
        fprintf(fout, " &");
      }
      break;

    case RUN_CHECK_FAILED:
      fprintf(fout, " &");
      break;

    case RUN_MEM_LIMIT_ERR:
    case RUN_SECURITY_ERR:
      fprintf(fout, " &");
      break;

    default:
      fprintf(fout, "&nbsp;");
    }

    fprintf(fout, " & %d (%d)", t->score, t->nominal_score);
    if (need_comment) {
      if (t->comment) {
        fprintf(fout, " & %s", TARMOR (t->comment));
      } else if (t->team_comment) {
        fprintf(fout, " & %s", TARMOR(t->team_comment));
      } else {
        fprintf(fout, " &");
      }
    }
    fprintf(fout, "\\\\\n");
  }
  fprintf(fout, "\\hline\n\\end{tabular}\n\n");

 cleanup:
  xfree(rep_text);
  testing_report_free(r);
  html_armor_free(&ab);
}

enum { SHORT_ANSWER_GROUP = 10 };

int
problem_report_generate(
        FILE *fout,
        FILE *log_f,
        const struct contest_desc *cnts,
        const serve_state_t cs,
        int prob_id,
        int locale_id,
        int use_exam_cypher)
{
  const struct section_global_data *global = cs->global;
  int retval = -1;
  const struct section_problem_data *prob;
  int user_num = 0, i, j, total_runs, run_id, user_id, run_cnt, variant;
  int *run_ids = 0, *user_ind = 0;
  unsigned char **user_str = 0;
  int *u_flags = 0;
  struct teamdb_export tdb;
  struct run_entry re;
  unsigned char bigbuf[16384];
  struct html_armor_buffer ab = HTML_ARMOR_INITIALIZER;
  int src_flags;
  path_t src_path;
  char *src_txt = 0, *num_txt = 0;
  size_t src_len = 0, num_len = 0;
  unsigned char probname[1024];
  unsigned char *psrc;
  path_t img_path;
  path_t eps_path;
  path_t ierr_path;
  const unsigned char *img_suffix = 0;

  if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id])) {
    fprintf(log_f, "Invalind prob_id %d\n", prob_id);
    goto cleanup;
  }
  if (!prob->long_name[0] || !strcmp(prob->long_name, prob->short_name)) {
    snprintf(probname, sizeof(probname), "%s", prob->short_name);
  } else {
    snprintf(probname, sizeof(probname), "%s-%s", prob->short_name,
             TARMOR(prob->long_name));
  }
  if ((user_num = teamdb_get_max_team_id(cs->teamdb_state)) <= 0) {
    fprintf(log_f, "No users registered for the contest\n");
    goto cleanup;
  }
  user_num++;
  run_ids = (int*) malloc(user_num * sizeof(run_ids[0]));
  memset(run_ids, -1, user_num * sizeof(run_ids[0]));
  XCALLOC(user_str, user_num);
  u_flags = (int*) malloc(user_num * sizeof(u_flags[0]));
  memset(u_flags, -1, user_num * sizeof(u_flags[0]));
  XCALLOC(user_ind, user_num);

  if (use_exam_cypher) {
    for (i = 1; i < user_num; i++) {
      if (teamdb_lookup(cs->teamdb_state, i) <= 0) continue;
      if (teamdb_export_team(cs->teamdb_state, i, &tdb) < 0) continue;
      u_flags[i] = tdb.flags;
      if (tdb.user && tdb.user->i.exam_cypher)
        user_str[i] = xstrdup(tdb.user->i.exam_cypher);
    }
  } else {
    for (i = 1; i < user_num; i++) {
      if (teamdb_lookup(cs->teamdb_state, i) <= 0) continue;
      if (teamdb_export_team(cs->teamdb_state, i, &tdb) < 0) continue;
      u_flags[i] = tdb.flags;
      if (tdb.user) {
        bigbuf[0] = 0;
        if (tdb.user->i.name[0] && tdb.user->i.exam_id) {
          snprintf(bigbuf, sizeof(bigbuf), "%s (%s)", tdb.user->i.name,
                   tdb.user->i.exam_id);
        } else if (tdb.user->i.exam_id) {
          snprintf(bigbuf, sizeof(bigbuf), "%s", tdb.user->i.exam_id);
        } else if (tdb.user->i.name) {
          snprintf(bigbuf, sizeof(bigbuf), "%s", tdb.user->i.name);
        }
        if (bigbuf[0]) user_str[i] = xstrdup(bigbuf);
      }
    }
  }

  // check for duplicated identification
  for (i = 1; i < user_num; i++) {
    if (!user_str[i]) continue;
    for (j = 1; j < i; j++)
      if (user_str[j] && !strcmp(user_str[i], user_str[j]))
        break;
    if (j < i) {
      fprintf(log_f, "duplicated user identification for users %d and %d\n",
              i, j);
      goto cleanup;
    }
  }

  // find the latest run in acceptable state
  if ((total_runs = run_get_total(cs->runlog_state)) <= 0) {
    fprintf(log_f, "No runs\n");
    goto cleanup;
  }

  for (run_id = total_runs - 1; run_id >= 0; run_id--) {
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0) {
      fprintf(log_f, "Invalid run %d\n", run_id);
      goto cleanup;
    }
    if (!run_is_source_available(re.status)) continue;
    if (re.prob_id != prob_id) continue;
    if (re.user_id <= 0 || re.user_id >= user_num) {
      fprintf(log_f, "Invalid user_id %d in run %d\n", re.user_id, run_id);
      goto cleanup;
    }
    user_id = re.user_id;
    if (u_flags[user_id] < 0) {
      fprintf(log_f, "User %d in run %d is not registered\n", user_id, run_id);
      continue;
    }
    if (u_flags[user_id] & (TEAM_BANNED | TEAM_INVISIBLE | TEAM_LOCKED | TEAM_DISQUALIFIED)) {
      fprintf(log_f, "User %d in run %d is banned, invisible, locked, or disqualified\n", user_id, run_id);
      continue;
    }
    if (prob->type_val == PROB_TYPE_SELECT_MANY
        || prob->type_val == PROB_TYPE_CUSTOM) {
      fprintf(log_f,"Problem type `%s' for problem %s is not yet supported\n",
              problem_unparse_type(prob->type_val), prob->short_name);
      goto cleanup;
    }
    if (run_ids[user_id] >= 0) continue;
    if (prob->type_val != PROB_TYPE_STANDARD) {
      switch (re.status) {
      case RUN_OK:
      case RUN_WRONG_ANSWER_ERR:
      case RUN_PARTIAL:
      case RUN_ACCEPTED:
        run_ids[user_id] = run_id;
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
        run_ids[user_id] = run_id;
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

  for (run_id = total_runs - 1; run_id >= 0; run_id--) {
    if (run_get_entry(cs->runlog_state, run_id, &re) < 0) abort();
    if (!run_is_source_available(re.status)) continue;
    if (re.prob_id != prob_id) continue;
    user_id = re.user_id;
    if (re.user_id <= 0 || re.user_id >= user_num) abort();
    if (u_flags[user_id] < 0) {
      fprintf(log_f, "User %d in run %d is not registered\n", user_id, run_id);
      continue;
    }
    if (u_flags[user_id] & (TEAM_BANNED | TEAM_INVISIBLE | TEAM_LOCKED | TEAM_DISQUALIFIED)) {
      fprintf(log_f, "User %d in run %d is banned, invisible, locked, or disqualified\n", user_id, run_id);
      continue;
    }

    if (run_ids[user_id] >= 0) continue;
    if (prob->type_val != PROB_TYPE_STANDARD) {
      switch (re.status) {
      case RUN_PRESENTATION_ERR:
        run_ids[user_id] = run_id;
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
        run_ids[user_id] = run_id;
        break;

      case RUN_IGNORED:
      case RUN_DISQUALIFIED:
        break;

      default:
        abort();
      }
    }
  }

  // check, that identification exists for all users
  for (i = 1; i < user_num; i++) {
    if (run_ids[i] >= 0 && !user_str[i]) {
      fprintf(log_f, "User %d has no identification\n", i);
      goto cleanup;
    }
  }

  if (use_exam_cypher) {
    // do a random shuffle
    srand(random_u16());
    for (i = 1, run_cnt = 0; i < user_num; i++)
      if (run_ids[i] >= 0)
        run_cnt++;
    for (i = 1; i < user_num; i++) {
      if (run_ids[i] < 0) continue;
      do {
        j = (int) ((rand() / (RAND_MAX + 1.0)) * run_cnt);
      } while (user_ind[j] > 0);
      user_ind[j] = i;
    }
  } else {
    for (i = 1, run_cnt = 0; i < user_num; i++)
      if (run_ids[i] >= 0)
        user_ind[run_cnt++] = i;
  }

  if (global->prob_exam_protocol_header_file[0]
      && global->prob_exam_protocol_header_txt) {
    sformat_message(bigbuf, sizeof(bigbuf),
                    global->prob_exam_protocol_header_txt,
                    global, 0, 0, 0, 0, 0, cnts, 0);
    fprintf(fout, "%s", bigbuf);
  }

  switch (prob->type_val) {
  case PROB_TYPE_TEXT_ANSWER:
    for (i = 0; i < run_cnt; i++) {
      user_id = user_ind[i];
      run_id = run_ids[user_id];

      variant = 0;
      if (prob->variant_num > 0) {
        if ((variant = find_variant(cs, user_id, prob_id, 0)) <= 0) {
          fprintf(log_f, "No variant for user %d\n", user_id);
          goto cleanup;
        }
      }

      fprintf(fout, "\\subsection*{%s %s", _("Problem"), probname);
      if (variant > 0) {
        fprintf(fout, ", %s %d", _("variant"), variant);
      }
      fprintf(fout, ", %s %s}\n\n", _("user"), TARMOR(user_str[user_id]));
      if (run_get_entry(cs->runlog_state, run_id, &re) < 0) abort();
      if (re.status != RUN_OK && re.status != RUN_PARTIAL
          && re.status != RUN_WRONG_ANSWER_ERR && re.status != RUN_ACCEPTED) {
        fprintf(log_f, "Invalid run status %d (%s) in run %d\n",
                re.status, run_status_str(re.status, 0, 0, 0, 0),
                run_id);
        goto cleanup;
      }

      // print the table
      fprintf(fout, "\\noindent\\begin{tabular}{|p{3cm}|p{4cm}|p{1cm}|p{5cm}|}\n");
      fprintf(fout, "\\hline\n");
      bigbuf[0] = 0;
      if (re.score >= 0) snprintf(bigbuf, sizeof(bigbuf), "%d", re.score);
      fprintf(fout, "%s & %s & %s & %s \\\\\n",  probname,
              TARMOR(user_str[user_id]), bigbuf,
              run_status_str(re.status, 0, 0, 0, 0));
      fprintf(fout, "\\hline\n");
      fprintf(fout, "\\end{tabular}\n\n");

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
      while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
      src_txt[src_len] = 0;

      num_len = text_numbered_memlen(src_txt, src_len);
      num_txt = xmalloc(num_len + 16);
      text_number_lines(src_txt, src_len, num_txt);
      fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n",
              tex_armor_verbatim_2(num_txt, VERBATIM_WIDTH));
      xfree(num_txt); num_txt = 0; num_len = 0;
      xfree(src_txt); src_txt = 0; src_len = 0;
    }
    break;

  case PROB_TYPE_STANDARD:
    for (i = 0; i < run_cnt; i++) {
      user_id = user_ind[i];
      run_id = run_ids[user_id];

      variant = 0;
      if (prob->variant_num > 0) {
        if ((variant = find_variant(cs, user_id, prob_id, 0)) <= 0) {
          fprintf(log_f, "No variant for user %d\n", user_id);
          goto cleanup;
        }
      }

      fprintf(fout, "\\subsection*{%s %s", _("Problem"), probname);
      if (variant > 0) {
        fprintf(fout, ", %s %d", _("variant"), variant);
      }
      fprintf(fout, ", %s %s}\n\n", _("user"), TARMOR(user_str[user_id]));
      if (run_get_entry(cs->runlog_state, run_id, &re) < 0) abort();

      // print the table
      fprintf(fout, "\\noindent\\begin{tabular}{|p{1.5cm}|p{3cm}|p{3.5cm}|p{1.5cm}|p{5cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s & %s & %s & %s & %s\\\\\n\\hline\n",
              _("Problem"), use_exam_cypher?_("Cypher"):_("Name"), _("Tests passed"), _("Score"), _("Status"));
      fprintf(fout, "%s & %s", probname, TARMOR(user_str[user_id]));
      if (re.test > 0) {
        fprintf(fout, " & %d", re.test - 1);
      } else {
        fprintf(fout, " &");
      }
      if (re.score >= 0) {
        fprintf(fout, " & %d", re.score);
      } else {
        fprintf(fout, " &");
      }
      fprintf(fout, " & %s\\\\\n", run_status_str(re.status, 0, 0, 0, 0));
      fprintf(fout, "\\hline\n");
      fprintf(fout, "\\end{tabular}\n\n");

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
      while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
      src_txt[src_len] = 0;

      num_len = text_numbered_memlen(src_txt, src_len);
      num_txt = xmalloc(num_len + 16);
      text_number_lines(src_txt, src_len, num_txt);
      fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n",
              tex_armor_verbatim(num_txt));
      xfree(num_txt); num_txt = 0; num_len = 0;
      xfree(src_txt); src_txt = 0; src_len = 0;

      if (run_is_report_available(re.status)) {
        write_xml_tex_testing_report(fout, cs, run_id);
      }
    }
    break;

  case PROB_TYPE_OUTPUT_ONLY:
    for (i = 0; i < run_cnt; i++) {
      user_id = user_ind[i];
      run_id = run_ids[user_id];

      variant = 0;
      if (prob->variant_num > 0) {
        if ((variant = find_variant(cs, user_id, prob_id, 0)) <= 0) {
          fprintf(log_f, "No variant for user %d\n", user_id);
          goto cleanup;
        }
      }

      fprintf(fout, "\\subsection*{%s %s", _("Problem"), probname);
      if (variant > 0) {
        fprintf(fout, ", %s %d", _("variant"), variant);
      }
      fprintf(fout, ", %s %s}\n\n", _("user"), TARMOR(user_str[user_id]));
      if (run_get_entry(cs->runlog_state, run_id, &re) < 0) abort();

      // print the table
      fprintf(fout, "\\noindent\\begin{tabular}{|p{1.5cm}|p{3cm}|p{1.5cm}|p{5cm}|}\n");
      fprintf(fout, "\\hline\n");
      fprintf(fout, "%s & %s & %s & %s\\\\\n\\hline\n",
              _("Problem"), use_exam_cypher?_("Cypher"):_("Name"), _("Score"), _("Status"));
      fprintf(fout, "%s & %s", probname, TARMOR(user_str[user_id]));
      /*
      if (re.test > 0) {
        fprintf(fout, " & %d", re.test - 1);
      } else {
        fprintf(fout, " &");
      }
      */
      if (re.score >= 0) {
        fprintf(fout, " & %d", re.score);
      } else {
        fprintf(fout, " &");
      }
      fprintf(fout, " & %s\\\\\n", run_status_str(re.status, 0, 0, 0, 0));
      fprintf(fout, "\\hline\n");
      fprintf(fout, "\\end{tabular}\n\n");

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
      if (re.mime_type == 0) {
        // plain text
        if (strlen(src_txt) != src_len) {
          fprintf(log_f, "Source file %s is binary\n", src_path);
          goto cleanup;
        }
        while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
        src_txt[src_len] = 0;

        num_len = text_numbered_memlen(src_txt, src_len);
        num_txt = xmalloc(num_len + 16);
        text_number_lines(src_txt, src_len, num_txt);
        fprintf(fout, "\\begin{verbatim}\n%s\n\\end{verbatim}\n\n",
                tex_armor_verbatim_2(num_txt, VERBATIM_WIDTH));
        xfree(num_txt); num_txt = 0; num_len = 0;
      } else {
        img_suffix = mime_type_get_suffix(re.mime_type);
        if (!img_suffix) img_suffix = "";
        snprintf(img_path, sizeof(img_path), "%s/i%06d%s",
                 global->print_work_dir, run_id, img_suffix);
        snprintf(eps_path, sizeof(eps_path), "%s/i%06d.eps",
                 global->print_work_dir, run_id);
        snprintf(ierr_path, sizeof(ierr_path), "%s/i%06d.err",
                 global->print_work_dir, run_id);
        generic_write_file(src_txt, src_len, 0, 0, img_path, "");
        invoke_convert(log_f, global, img_path, eps_path, ierr_path, 1);
        fprintf(fout, "\\includegraphics{i%06d.eps}\n", run_id);
      }
      xfree(src_txt); src_txt = 0; src_len = 0;
    }
    break;

  case PROB_TYPE_SHORT_ANSWER:
    fprintf(fout, "\\subsection*{%s %s}\n\n", _("Problem"), probname);

    // group tables by SHORT_ANSWER_GROUP entries
    for (i = 0; i < run_cnt; i++) {
      user_id = user_ind[i];
      run_id = run_ids[user_id];

      if (run_get_entry(cs->runlog_state, run_id, &re) < 0) abort();

      variant = 0;
      if (prob->variant_num > 0) {
        if ((variant = find_variant(cs, user_id, prob_id, 0)) <= 0) {
          fprintf(log_f, "No variant for user %d\n", user_id);
          goto cleanup;
        }
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
      while (src_len > 0 && isspace(src_txt[src_len - 1])) src_len--;
      src_txt[src_len] = 0;
      for (psrc = src_txt; *psrc; psrc++)
        if (*psrc < ' ') *psrc = ' ';

      // [variant] user answer status score comment
      if (i % SHORT_ANSWER_GROUP == 0) {
        fprintf(fout, "\\noindent\\begin{tabular}{");
        if (prob->variant_num > 0) fprintf(fout, "|l");
        fprintf(fout, "|p{2cm}|p{4cm}|p{3cm}|p{1.5cm}|p{3cm}|}\n");
        fprintf(fout, "\\hline\n");
        if (prob->variant_num > 0) fprintf(fout, "%s &", "V");
        fprintf(fout, "%s & %s & %s & %s & %s \\\\\n",
                use_exam_cypher?_("Cypher"):_("Name"),
                _("Answer"), _("Status"), _("Score"), _("Comment"));
      }
      fprintf(fout, "\\hline\n");
      if (prob->variant_num) fprintf(fout, "%d &", variant);
      fprintf(fout, " %s", TARMOR(user_str[user_id]));
      fprintf(fout, " & %s", TARMOR(src_txt));
      fprintf(fout, " & %s", run_status_str(re.status, 0, 0, 0, 0));
      if (re.score >= 0)
        fprintf(fout, " & %d", re.score);
      else 
        fprintf(fout, " &");
      psrc = ns_get_checker_comment(cs, run_id, 0);
      if (!psrc) psrc = xstrdup("");
      fprintf(fout, " & %s \\\\\n", TARMOR(psrc));
      xfree(psrc);
      xfree(src_txt); src_txt = 0; src_len = 0;
      if (i % SHORT_ANSWER_GROUP == (SHORT_ANSWER_GROUP - 1)) {
        fprintf(fout, "\\hline\n\\end{tabular}\n\n");
      }
    }
    if (i % SHORT_ANSWER_GROUP != 0) {
      fprintf(fout, "\\hline\n\\end{tabular}\n\n");
    }
    break;

  default:
    abort();
  }

  if (global->prob_exam_protocol_footer_file[0]
      && global->prob_exam_protocol_footer_txt) {
    sformat_message(bigbuf, sizeof(bigbuf),
                    global->prob_exam_protocol_footer_txt,
                    global, 0, 0, 0, 0, 0, cnts, 0);
    fprintf(fout, "%s", bigbuf);
  }

  retval = 0;

 cleanup:
  xfree(src_txt);
  xfree(num_txt);
  if (user_str) {
    for (i = 0; i < user_num; i++)
      xfree(user_str[i]);
  }
  xfree(user_ind);
  xfree(run_ids);
  xfree(user_str);
  xfree(u_flags);
  html_armor_free(&ab);
  return retval;
}

int
ns_print_prob_exam_protocol(
        const struct contest_desc *cnts,
        const serve_state_t cs,
        FILE *log_f,
        int prob_id,
        int locale_id,
        int use_exam_cypher)
{
  const struct section_global_data *global = cs->global;
  const struct section_problem_data *prob;
  path_t tex_path;
  path_t err_path;
  path_t dvi_path;
  path_t ps_path;
  path_t tst_path;
  int retval = -1;
  FILE *fout = 0;
  unsigned char prob_base[1024];

  if (prob_id <= 0 || prob_id > cs->max_prob || !(prob = cs->probs[prob_id]))
    goto cleanup;

  snprintf(prob_base, sizeof(prob_base), "prob_%s", prob->short_name);
  snprintf(tex_path, sizeof(tex_path), "%s/%s.tex", global->print_work_dir,
           prob_base);
  if (!(fout = fopen(tex_path, "w"))) {
    fprintf(log_f, "cannot open `%s' for writing\n", tex_path);
    goto cleanup;
  }
  if (problem_report_generate(fout, log_f, cnts, cs, prob_id, locale_id,
                              use_exam_cypher) < 0)
    goto cleanup;
  if (ferror(fout)) {
    fprintf(log_f, "write error to `%s'\n", tex_path);
    goto cleanup;
  }
  if (fclose(fout) < 0) {
    fout = 0;
    fprintf(log_f, "write error to `%s'\n", tex_path);
    goto cleanup;
  }
  fout = 0;

  snprintf(err_path, sizeof(err_path), "%s/%s.err", global->print_work_dir,
           prob_base);
  snprintf(dvi_path, sizeof(dvi_path), "%s/%s.dvi", global->print_work_dir,
           prob_base);
  snprintf(ps_path, sizeof(ps_path), "%s/%s.ps", global->print_work_dir,
           prob_base);
  if (invoke_latex(log_f, tex_path, err_path, global->print_work_dir, 1) < 0)
    goto cleanup;
  if (invoke_latex(log_f, tex_path, err_path, global->print_work_dir, 0) < 0)
    goto cleanup;
  if (invoke_dvips(log_f, dvi_path, err_path, global->print_work_dir, 1) < 0)
    goto cleanup;

  snprintf(tst_path, sizeof(tst_path), "%s/.noprint", global->print_work_dir);
  if (os_CheckAccess(tst_path, REUSE_F_OK) < 0) {
    if (invoke_lpr(log_f, global, 0, ps_path, err_path, 1) < 0)
      goto cleanup;
  }

  retval = 0;

 cleanup:
  if (fout) fclose(fout);
  snprintf(tst_path, sizeof(tst_path), "%s/.noclean", global->print_work_dir);
  if (os_CheckAccess(tst_path, REUSE_F_OK) < 0) {
    clear_directory(global->print_work_dir);
  }
  return retval;
}
