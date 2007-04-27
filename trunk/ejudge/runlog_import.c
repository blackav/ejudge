/* -*- mode: c -*- */
/* $Id$ */

/* Copyright (C) 2003-2007 Alexander Chernov <cher@ejudge.ru> */

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

#include "runlog.h"
#include "misctext.h"
#include "prepare.h"
#include "teamdb.h"
#include "archive_paths.h"
#include "serve_state.h"
#include "fileutl.h"

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <stdlib.h>

static void
rename_archive_files(const serve_state_t state, FILE *flog, int num, int *map)
{
  int i;

  for (i = 0; i < num; i++) {
    if (map[i] < 0) continue;
    if (map[i] == i) continue;
    archive_rename(state, state->global->run_archive_dir,
                   flog, i, "", i, "_", 0);
    archive_rename(state, state->global->xml_report_archive_dir,
                   flog, i, "", i, "_", 1);
    archive_rename(state, state->global->report_archive_dir,
                   flog, i, "", i, "_", 1);
    if (state->global->team_enable_rep_view) {
      archive_rename(state, state->global->team_report_archive_dir,
                     flog, i, "", i, "_", 0);
    }
    if (state->global->enable_full_archive) {
      archive_rename(state, state->global->full_archive_dir,
                     flog, i, "", i, "_", 0);
    }
    archive_rename(state, state->global->audit_log_dir,
                   flog, i, "", i, "_", 0);
  }

  for (i = 0; i < num; i++) {
    if (map[i] < 0) continue;
    if (map[i] == i) continue;
    archive_rename(state, state->global->run_archive_dir, flog,
                   i, "_", map[i], "", 0);
    archive_rename(state, state->global->xml_report_archive_dir, flog,
                   i, "_", map[i], "", 1);
    archive_rename(state, state->global->report_archive_dir, flog,
                   i, "_", map[i], "", 1);
    if (state->global->team_enable_rep_view) {
      archive_rename(state, state->global->team_report_archive_dir, flog,
                     i, "_", map[i], "", 0);
    }
    if (state->global->enable_full_archive) {
      archive_rename(state, state->global->full_archive_dir,
                     flog, i, "_", map[i], "", 0);
    }
    archive_rename(state, state->global->audit_log_dir, flog,
                   i, "_", map[i], "", 0);
  }
}

void
runlog_import_xml(serve_state_t state, runlog_state_t runlog_state,
                  FILE *hlog, int flags, const unsigned char *in_xml)
{
  const struct section_global_data *global = state->global;

  size_t armor_len, flog_len = 0;
  unsigned char *armor_str;
  char *flog_text = 0;
  FILE *flog;

  struct run_header in_header;
  struct run_header cur_header;
  struct run_entry *in_entries = 0;
  struct run_entry *cur_entries = 0;
  struct run_entry *out_entries = 0;
  struct run_data *in_data = 0;
  struct run_entry *pa, *pb;
  size_t in_entries_num = 0;
  size_t cur_entries_num = 0;
  size_t out_entries_num = 0;
  int r, i, st, j, k, corr_total, i2, j2, i3, j3, cur_out, prev_i;
  int min_i, min_j;
  time_t prev_time, cur_time = 0;
  int prev_nsec;
  int *cur_new_map, *cur_merged_map, *new_cur_map, *new_merged_map;
  int update_flag = 0;
  int min_team_id;
  unsigned char *cur_used_flag, *in_used_flag;
  int both_auth_warn_printed = 0;
  int arch_flags = 0;
  path_t run_path;

  flog = open_memstream(&flog_text, &flog_len);
  memset(&in_header, 0, sizeof(in_header));
  memset(&cur_header, 0, sizeof(cur_header));

  cur_entries_num = run_get_total(runlog_state);
  if (cur_entries_num > 0) {
    XCALLOC(cur_entries, cur_entries_num);
  }
  run_get_header(runlog_state, &cur_header);
  run_get_all_entries(runlog_state, cur_entries);

  if (!cur_header.start_time) {
    fprintf(flog, "Contest is not yet started\n");
    goto done;
  }

  fprintf(flog, "Current run log has %zu entries\n", cur_entries_num);
  fprintf(flog, "Doing sanity check on the current log\n");
  if (runlog_check(flog, &cur_header, cur_entries_num, cur_entries) < 0) {
    fprintf(flog, "Sanity check failed!\n");
    goto done;
  }
  fprintf(flog, "Sanity check is ok\n");

  fprintf(flog, "Scanning the existing entries\n");
  for (i = 0; i < cur_entries_num; i++) {
    st = cur_entries[i].status;
    ASSERT(st >= RUN_OK && st <= RUN_TRANSIENT_LAST);
    if (st <= RUN_MAX_STATUS) continue;
    ASSERT(st >= RUN_PSEUDO_FIRST);
    if (st == RUN_VIRTUAL_START || st == RUN_VIRTUAL_STOP) {
      fprintf(flog, "Run %d is a virtual contest control record\n", i);
      continue;
    }
    if (st == RUN_EMPTY) {
      fprintf(flog, "Run %d is empty\n", i);
      continue;
    }
    ASSERT(st >= RUN_TRANSIENT_FIRST);
    fprintf(flog, "Run %d is a transient run %d ('%s')\n",
            i, st, run_status_str(st, 0, 0, 0, 0));
    fprintf(flog, "Cannot merge logs with transient runs\n");
    goto done;
  }
  prev_time = 0;
  prev_nsec = 0;
  prev_i = -1;
  for (i = 0; i < cur_entries_num; i++) {
    if (cur_entries[i].status == RUN_EMPTY) continue;
    if (cur_entries[i].time < 0) {
      fprintf(flog, "Run %d time is negative\n", i);
      goto done;
    }
    if (cur_entries[i].time < prev_time ||
        (cur_entries[i].time == prev_time
         && cur_entries[i].nsec < prev_nsec)) {
      fprintf(flog, "Run %d time is less than previous run time\n", i);
      goto done;
    }
    if (prev_i >= 0
        && cur_entries[prev_i].time == cur_entries[i].time
        && cur_entries[prev_i].nsec == cur_entries[i].nsec
        && cur_entries[prev_i].user_id == cur_entries[i].user_id
        && cur_entries[prev_i].lang_id == cur_entries[i].lang_id
        && cur_entries[prev_i].prob_id == cur_entries[i].prob_id) {
      fprintf(flog, "Run %d seems like a duplicate of the previuos run\n", i);
      goto done;
    }
    prev_time = cur_entries[i].time;
    prev_nsec = cur_entries[i].nsec;
    prev_i = i;
  }
  fprintf(flog, "Scanning the existing entries done successfully\n");

  r = parse_runlog_xml(in_xml, &in_header, &in_entries_num, &in_entries,
                       &in_data);
  if (r < 0) {
    fprintf(flog, "XML parsing failed\n");
    goto done;
  }
  fprintf(flog, "XML parsing successful: %zu entries\n", in_entries_num);

  fprintf(flog, "Scanning new entries\n");
  for (i = 0; i < in_entries_num; i++) {
    if (in_entries[i].run_id != i) {
      fprintf(flog, "Run %d has run_id %d\n", i, in_entries[i].run_id);
      goto done;
    }
    if (in_entries[i].is_hidden) {
      fprintf(flog, "Run %d is hidden\n", i);
      goto done;
    }
    st = in_entries[i].status;
    if (st < RUN_OK || st > RUN_TRANSIENT_LAST) {
      fprintf(flog, "Run %d status %d is invalid\n", i, st);
      goto done;
    }
    if (st <= RUN_MAX_STATUS) continue;
    if (st < RUN_PSEUDO_FIRST) {
      fprintf(flog, "Run %d status %d is invalid\n", i, st);
      goto done;
    }
    if (st == RUN_VIRTUAL_START || st == RUN_VIRTUAL_STOP) {
      fprintf(flog, "Run %d is a virtual contest control record\n", i);
      continue;
    }
    if (st == RUN_EMPTY) {
      fprintf(flog, "Run %d is empty\n", i);
      continue;
    }
    if (st < RUN_TRANSIENT_FIRST) {
      fprintf(flog, "Run %d status %d is invalid\n", i, st);
      goto done;
    }
    fprintf(flog, "Run %d is a transient run %d ('%s')\n",
            i, st, run_status_str(st, 0, 0, 0, 0));
    goto done;
  }
  prev_time = 0;
  prev_nsec = 0;
  prev_i = -1;
  for (i = 0; i < in_entries_num; i++) {
    if (in_entries[i].status == RUN_EMPTY) continue;
    ASSERT(in_entries[i].status <= RUN_MAX_STATUS);
    if (in_entries[i].time < 0) {
      fprintf(flog, "Run %d time is negative\n", i);
      goto done;
    }
    if (in_entries[i].time < prev_time ||
        (in_entries[i].time == prev_time
         && in_entries[i].nsec < prev_nsec)) {
      fprintf(flog, "Run %d time is less than previous run time\n", i);
      goto done;
    }
    if (prev_i >= 0
        && in_entries[prev_i].time == in_entries[i].time
        && in_entries[prev_i].nsec == in_entries[i].nsec
        && in_entries[prev_i].user_id == in_entries[i].user_id
        && in_entries[prev_i].lang_id == in_entries[i].lang_id
        && in_entries[prev_i].prob_id == in_entries[i].prob_id) {
      fprintf(flog, "Run %d seems like a duplicate of the previuos run\n", i);
      goto done;
    }
    prev_time = in_entries[i].time;
    prev_nsec = in_entries[i].nsec;
    prev_i = i;
    if (!teamdb_lookup(state->teamdb_state, in_entries[i].user_id)) {
      fprintf(flog, "Run %d team %d is not known\n", i, in_entries[i].user_id);
      goto done;
    }
    r = in_entries[i].prob_id;
    if (r <= 0 || r > state->max_prob || !state->probs[r]) {
      fprintf(flog, "Run %d problem %d is not known\n", i, r);
      goto done;
    }
    r = in_entries[i].lang_id;
    if (r <= 0 || r > state->max_lang || !state->langs[r]) {
      fprintf(flog, "Run %d problem %d is not known\n", i, r);
      goto done;
    }
    if (in_entries[i].nsec < 0 || in_entries[i].nsec >= 1000000000) {
      fprintf(flog, "Run %d nsec %d is invalid\n", i, in_entries[i].nsec);
      goto done;
    }
  }
  fprintf(flog, "Scanning new entries done successfully\n");

  /* all maps are initialized with -1 */
  /* maps original run entries to the new entries */
  cur_new_map = (int*) alloca(cur_entries_num * sizeof(cur_new_map[0]));
  memset(cur_new_map, 0xff, cur_entries_num * sizeof(cur_new_map[0]));
  /* maps original run entries to the merged entries */
  cur_merged_map = (int*) alloca(cur_entries_num * sizeof(cur_merged_map[0]));
  memset(cur_merged_map, 0xff, cur_entries_num * sizeof(cur_merged_map[0]));
  /* maps the new entries to the original entries */
  new_cur_map = (int*) alloca(in_entries_num * sizeof(new_cur_map[0]));
  memset(new_cur_map, 0xff, in_entries_num * sizeof(new_cur_map[0]));
  /* maps the new entries to the merged entries */
  new_merged_map = (int*) alloca(in_entries_num * sizeof(new_merged_map[0]));
  memset(new_merged_map, 0xff, in_entries_num * sizeof(new_merged_map[0]));

  /* find the correspondence */
  fprintf(flog, "Establishing correspondence between runs\n");
  corr_total = 0;
  i = 0, j = 0;
  while (1) {
    if (i >= cur_entries_num) break;
    while (i < cur_entries_num && j < in_entries_num) {
      if (cur_entries[i].status == RUN_EMPTY) {
        i++;
        continue;
      }
      if (cur_entries[i].is_hidden) {
        i++;
        continue;
      }
      cur_time = cur_entries[i].time - cur_header.start_time;
      if (cur_time < 0) cur_time = 0;
      if (in_entries[j].status == RUN_EMPTY) {
        j++;
        continue;
      }
      if (cur_time == in_entries[j].time
          && cur_entries[i].nsec == in_entries[j].nsec) break;
      if (cur_time < in_entries[j].time
          || (cur_time == in_entries[j].time
              && cur_entries[i].nsec < in_entries[j].nsec))
        i++;
      else
        j++;
    }
    if (i >= cur_entries_num || j >= in_entries_num) break;

    /* find a correspondence among the incoming runs starting from j'th */
    k = j;
    for (; k < in_entries_num; k++) {
      if (in_entries[k].status == RUN_EMPTY) continue;
      if (in_entries[k].time != cur_time) break;
      if (in_entries[k].nsec != cur_entries[i].nsec) break;
      if (new_cur_map[k] >= 0) continue;
      if (cur_entries[i].user_id != in_entries[k].user_id) continue;
      if (cur_entries[i].prob_id != in_entries[k].prob_id) continue;
      if (cur_entries[i].lang_id != in_entries[k].lang_id) continue;
      break;
    }
    if (k < in_entries_num && in_entries[k].time == cur_time
        && in_entries[k].nsec == cur_entries[i].nsec) {
      /* establish correspondence */
      ASSERT(cur_new_map[i] == -1);
      ASSERT(new_cur_map[k] == -1);
      cur_new_map[i] = k;
      new_cur_map[k] = i;
      corr_total++;
    }
    i++;
  }
  fprintf(flog, "%d correspondences established\n", corr_total);

  /* check correspondences */
  for (i = 0; i < cur_entries_num; i++) {
    if ((j = cur_new_map[i]) == -1) continue;
    ASSERT(j >= 0 && j < in_entries_num);
    pa = &cur_entries[i];
    pb = &in_entries[j];
    if (!pa->is_imported && !pb->is_imported) {
      if (!both_auth_warn_printed) {
        fprintf(flog, "Both runs are authoritative!\n");
        fprintf(flog, "Local run %d and imported run %d\n", i, j);
        fprintf(flog, "Assuming that we are merging our own log\n");
        fprintf(flog, "This message is printed only once for all runs\n");
        both_auth_warn_printed = 1;
      }
      if (!in_data[j].source.data) pb->is_imported = 1;
    }
    if (pa->is_imported && pb->is_imported) {
      /* just warn, if values differ */
      if (pa->size != pb->size) {
        fprintf(flog, "Local run %d, imported %d: `size' does not match\n",
                i, j);
      }
      if (pa->a.ip != pb->a.ip) {
        fprintf(flog, "Local run %d, imported %d: `ip' does not match\n",
                i, j);
      }
      if (memcmp(pa->sha1, pb->sha1, sizeof(pa->sha1)) != 0) {
        fprintf(flog, "Local run %d, imported %d: `sha1' does not match\n",
                i, j);
      }
      if (pa->score != pb->score) {
        fprintf(flog, "Local run %d, imported %d: `score' does not match\n",
                i, j);
      }
      if (pa->locale_id != pb->locale_id) {
        fprintf(flog,"Local run %d, imported %d: `locale_id' does not match\n",
                i, j);
      }
      if (pa->status != pb->status) {
        fprintf(flog,"Local run %d, imported %d: `status' does not match\n",
                i, j);
      }
      if (pa->test != pb->test) {
        fprintf(flog,"Local run %d, imported %d: `test' does not match\n",
                i, j);
      }
      if (pa->variant != pb->variant) {
        fprintf(flog,"Local run %d, imported %d: `variant' does not match\n",
                i, j);
      }
      if (pa->is_readonly != pb->is_readonly) {
        fprintf(flog,
                "Local run %d, imported %d: `is_readonly' does not match\n",
                i, j);
      }
    }
  }

  /* calculate the size of the resulting log */
  out_entries_num = 0;
  for (i = 0; i < cur_entries_num; i++) {
    if (cur_entries[i].status == RUN_EMPTY) continue;
    out_entries_num++;
  }
  r = 0;
  for (j = 0; j < in_entries_num; j++) {
    if (in_entries[j].status == RUN_EMPTY) continue;
    if (new_cur_map[j] != -1) continue;
    out_entries_num++;
    r++;
  }
  if (!r) {
    fprintf(flog, "The imported runlog contain no new entries\n");
    fprintf(flog, "Updating the local non-authoritative entries\n");
    r = 0;
    for (i = 0; i < cur_entries_num; i++) {
      pa = &cur_entries[i];
      if (pa->status == RUN_EMPTY) continue;
      if (!pa->is_imported) continue;
      if ((j = cur_new_map[i]) == -1) continue;
      pb = &in_entries[j];
      if (pb->is_imported) continue;
      /* size, ip, sha1, score, locale_id, status, test */
      r = 0;
      if (pa->size != pb->size) {
        pa->size = pb->size;
        r = 1;
      }
      if (pa->a.ip != pb->a.ip) {
        pa->a.ip = pb->a.ip;
        r = 1;
      }
      if (memcmp(pa->sha1, pb->sha1, sizeof(pa->sha1)) != 0) {
        memcpy(pa->sha1, pb->sha1, sizeof(pa->sha1));
        r = 1;
      }
      if (pa->score != pb->score) {
        pa->score = pb->score;
        r = 1;
      }
      if (pa->locale_id != pb->locale_id) {
        pa->locale_id = pb->locale_id;
        r = 1;
      }
      if (pa->status != pb->status) {
        pa->status = pb->status;
        r = 1;
      }
      if (pa->test != pb->test) {
        pa->test = pb->test;
        r = 1;
      }
      if (pa->variant != pb->variant) {
        pa->variant = pb->variant;
        r = 1;
      }
      if (pa->is_readonly != pb->is_readonly) {
        pa->is_readonly = pb->is_readonly;
        r = 1;
      }
      if (r) {
        update_flag++;
      }
      run_set_entry(runlog_state, i, RUN_ENTRY_ALL, pa);
    }
    fprintf(flog, "%d entries updated\n", update_flag);
    goto done;
  }
  fprintf(flog, "The merged runlog contains %zu records\n", out_entries_num);

  if (!out_entries_num) {
    fprintf(flog, "Refuse to create runlog of size 0\n");
    goto done;
  }

  out_entries = alloca((out_entries_num + 1) * sizeof(out_entries[0]));
  memset(out_entries, 0, out_entries_num * sizeof(out_entries[0]));
  cur_used_flag = alloca(cur_entries_num);
  memset(cur_used_flag, 0, cur_entries_num);
  in_used_flag = alloca(in_entries_num);
  memset(in_used_flag, 0, in_entries_num);

  /* fix time in the imported runs */
  for (j = 0; j < in_entries_num; j++) {
    if (in_entries[j].status == RUN_EMPTY) continue;
    in_entries[j].time += cur_header.start_time;
  }

  fprintf(flog, "Doing sanity check of the new runlog\n");
  if (runlog_check(flog, &cur_header, in_entries_num, in_entries) < 0) {
    fprintf(flog, "Sanity check failed\n");
  }
  fprintf(flog, "Sanity check is ok\n");

  /* the runs with the same submit time are sorted by team_id,
   * then by current run_id */
  cur_out = 0;
  for (i = 0, j = 0; i < cur_entries_num && j < in_entries_num;) {
    if (cur_entries[i].status == RUN_EMPTY) {
      i++;
      continue;
    }
    if (in_entries[j].status == RUN_EMPTY) {
      j++;
      continue;
    }
    if (cur_entries[i].time < in_entries[j].time
        || (cur_entries[i].time == in_entries[j].time
            && cur_entries[i].nsec < in_entries[j].nsec)) {
      ASSERT(cur_new_map[i] == -1);
      memcpy(&out_entries[cur_out], &cur_entries[i], sizeof(out_entries[0]));
      out_entries[cur_out].run_id = cur_out;
      cur_merged_map[i] = cur_out;
      i++;
      cur_out++;
      continue;
    }
    if (cur_entries[i].time > in_entries[j].time
        || (cur_entries[i].time == in_entries[j].time
            && cur_entries[i].nsec > in_entries[j].nsec)) {
      ASSERT(new_cur_map[j] == -1);
      memcpy(&out_entries[cur_out], &in_entries[j], sizeof(out_entries[0]));
      out_entries[cur_out].run_id = cur_out;
      if (!in_data[j].source.data) out_entries[cur_out].is_imported = 1;
      else out_entries[cur_out].status = RUN_PENDING;
      new_merged_map[j] = cur_out;
      j++;
      cur_out++;
      continue;
    }

    /* order the entries with the same timestamp */
    /* detect entries with the same timestamp */
    for (i2 = i; i2 < cur_entries_num; i2++) {
      if (cur_entries[i2].status == RUN_EMPTY) continue;
      if (cur_entries[i2].time != cur_entries[i].time
          || cur_entries[i2].nsec != cur_entries[i].nsec) break;
    }
    for (j2 = j; j2 < in_entries_num; j2++) {
      if (in_entries[j2].status == RUN_EMPTY) continue;
      if (in_entries[j2].time != in_entries[j].time
          || in_entries[j2].nsec != in_entries[j].nsec) break;
    }
    while (1) {
      min_team_id = INT_MAX, min_i = -1, min_j = -1;
      for (i3 = i; i3 < i2; i3++) {
        if (cur_entries[i3].status == RUN_EMPTY) continue;
        if (cur_used_flag[i3]) continue;
        if (cur_entries[i3].user_id < min_team_id) {
          min_team_id = cur_entries[i3].user_id;
          min_i = i3;
          min_j = -1;
        }
      }
      for (j3 = j; j3 < j2; j3++) {
        if (in_entries[j3].status == RUN_EMPTY) continue;
        if (in_used_flag[j3]) continue;
        if (in_entries[j3].user_id < min_team_id) {
          min_team_id = in_entries[j3].user_id;
          min_i = -1;
          min_j = j3;
        }
      }
      if (min_team_id == INT_MAX) break;
      ASSERT(min_i >= 0 || min_j >= 0);
      ASSERT(min_i < 0 || min_j < 0);
      if (min_i >= 0) {
        min_j = cur_new_map[min_i];
        if (min_j != -1 && !in_entries[min_j].is_imported) {
	  fprintf(flog, "Overriding local run %d with imported %d\n",
		  min_i, min_j);
          memcpy(&out_entries[cur_out], &in_entries[min_j],
                 sizeof(out_entries[0]));
          out_entries[cur_out].run_id = cur_out;
          out_entries[cur_out].is_imported = 1;
          new_merged_map[min_j] = cur_out;
          in_used_flag[min_j] = 1;
          cur_merged_map[min_i] = cur_out;
          cur_used_flag[min_i] = 1;
	  cur_out++;
        } else {
          /* copying from the current log */
          memcpy(&out_entries[cur_out], &cur_entries[min_i],
                 sizeof(out_entries[0]));
          out_entries[cur_out].run_id = cur_out;
          cur_merged_map[min_i] = cur_out;
          cur_used_flag[min_i] = 1;
          if (min_j != -1) {
            new_merged_map[min_j] = cur_out;
            in_used_flag[min_j] = 1;
          }
          cur_out++;
        }
      } else {
        /* copying from the import log */
        ASSERT(new_cur_map[min_j] == -1);
        memcpy(&out_entries[cur_out], &in_entries[min_j],
               sizeof(out_entries[0]));
        out_entries[cur_out].run_id = cur_out;
        if (!in_data[min_j].source.data) out_entries[cur_out].is_imported = 1;
        else out_entries[cur_out].status = RUN_PENDING;
        new_merged_map[min_j] = cur_out;
        in_used_flag[min_j] = 1;
        cur_out++;
      }
    }
    i = i2;
    j = j2;
  }

  for (;i < cur_entries_num;i++) {
    if (cur_entries[i].status == RUN_EMPTY) continue;
    ASSERT(cur_new_map[i] == -1);
    memcpy(&out_entries[cur_out], &cur_entries[i], sizeof(out_entries[0]));
    out_entries[cur_out].run_id = cur_out;
    cur_merged_map[i] = cur_out;
    cur_out++;
  }
  for (;j < in_entries_num; j++) {
    if (in_entries[j].status == RUN_EMPTY) continue;
    ASSERT(new_cur_map[j] == -1);
    memcpy(&out_entries[cur_out], &in_entries[j], sizeof(out_entries[0]));
    out_entries[cur_out].run_id = cur_out;
    if (!in_data[j].source.data) out_entries[cur_out].is_imported = 1;
    else out_entries[cur_out].status = RUN_PENDING;
    new_merged_map[j] = cur_out;
    cur_out++;
  }
  ASSERT(cur_out == out_entries_num);
  fprintf(flog, "Runlog successfully merged\n");

  fprintf(flog, "Performing sanity check on the resulting log\n");
  if (runlog_check(flog, &cur_header, out_entries_num, out_entries) < 0)
    goto done;
  fprintf(flog, "Sanity check done\n");

  fprintf(flog, "Saving the new runlog\n");
  run_backup(runlog_state, state->global->run_log_file);
  run_set_runlog(runlog_state, out_entries_num, out_entries);
  fprintf(flog, "Renaming archive files\n");
  for (i = 0; i < cur_entries_num; i++)
    if (cur_entries[i].is_imported)
      cur_merged_map[i] = -1;
  rename_archive_files(state, flog, cur_entries_num, cur_merged_map);
  fprintf(flog, "Saving imported source and audit files\n");
  for (i = 0; i < in_entries_num; i++) {
    if (!in_data[i].source.data) continue;
    if ((j = new_merged_map[i]) < 0) continue;

    arch_flags = archive_make_write_path(state, run_path, sizeof(run_path),
                                         global->run_archive_dir, j,
                                         in_data[i].source.size, 0);
    if (arch_flags < 0) {
      fprintf(flog, "ERROR: failed to create source write path for run %d", j);
      continue;
    }
    if (archive_dir_prepare(state, global->run_archive_dir, j, 0, 0) < 0) {
      fprintf(flog, "ERROR: failed to create directories for run %d", j);
      continue;
    }
    if (generic_write_file(in_data[i].source.data, in_data[i].source.size,
                           arch_flags, 0, run_path, "") < 0) {
      fprintf(flog, "ERROR: failed to write source for run %d", j);
      continue;
    }

    if (in_data[i].audit.data) {
      arch_flags = archive_make_write_path(state, run_path, sizeof(run_path),
                                           global->audit_log_dir, j, 0, 0);
      if (arch_flags < 0) {
        fprintf(flog, "ERROR: failed to create audit write path for run %d", j);
        continue;
      }
      if (archive_dir_prepare(state, global->audit_log_dir, j, 0, 0) < 0) {
        fprintf(flog, "ERROR: failed to create directories for audit %d", j);
        continue;
      }
      if (generic_write_file(in_data[i].audit.data, in_data[i].audit.size,
                             arch_flags, 0, run_path, "") < 0) {
        fprintf(flog, "ERROR: failed to write audit for run %d", j);
        continue;
      }
    }

    serve_audit_log(state, j, 0, 0, 0,
                    "Command: import\n"
                    "Status: success\n"
                    "Run-id: %d\n",
                    j);
  }
  fprintf(flog, "Merge complete\n");

 done:
  fclose(flog);
  if (!flog_text) flog_text = xstrdup("");
  if (flags) {
    // no html formatting... dumb however, may avoid flog buf at all...
    fprintf(hlog, "%s", flog_text);
  } else {
    armor_len = html_armored_strlen(flog_text);
    armor_str = alloca(armor_len + 1);
    html_armor_string(flog_text, armor_str);
    fprintf(hlog, "<pre>%s</pre>\n", armor_str);
  }
  xfree(flog_text);
  xfree(in_entries);
  xfree(cur_entries);
  if (in_data) {
    for (i = 0; i < in_entries_num; i++) {
      xfree(in_data[i].source.data);
      xfree(in_data[i].audit.data);
    }
  }
  xfree(in_data);
}

/*
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
