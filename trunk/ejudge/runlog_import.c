/* -*- mode: c; coding: koi8-r -*- */
/* $Id$ */

/* Copyright (C) 2003 Alexander Chernov <cher@ispras.ru> */

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

#include <reuse/xalloc.h>
#include <reuse/logger.h>
#include <reuse/osdeps.h>

#include <stdlib.h>

static void
do_rename(const unsigned char *dir, FILE *flog,
          int n1, const unsigned char *pfx1,
          int n2, const unsigned char *pfx2)
{
  path_t name1, name2;

  if (!pfx1) pfx1 = "";
  if (!pfx2) pfx2 = "";
  snprintf(name1, sizeof(name1), "%s/%s%06d", dir, pfx1, n1);
  snprintf(name2, sizeof(name2), "%s/%s%06d", dir, pfx2, n2);
  if (rename(name1, name2) < 0) {
    fprintf(flog, "rename %s - %s failed: %s", name1, name2, os_ErrorMsg());
    err("rename(%s,%s) failed: %s", name1, name2, os_ErrorMsg());
  }
}

static void
rename_archive_files(FILE *flog, int num, int *map)
{
  int i;

  for (i = 0; i < num; i++) {
    if (map[i] < 0) continue;
    do_rename(global->run_archive_dir, flog, i, "", i, "_");
    do_rename(global->report_archive_dir, flog, i, "", i, "_");
    if (global->team_enable_rep_view) {
      do_rename(global->team_report_archive_dir, flog, i, "", i, "_");
    }
  }

  for (i = 0; i < num; i++) {
    if (map[i] < 0) continue;
    do_rename(global->run_archive_dir, flog, i, "_", map[i], "");
    do_rename(global->report_archive_dir, flog, i, "_", map[i], "");
    if (global->team_enable_rep_view) {
      do_rename(global->team_report_archive_dir, flog, i, "_", map[i], "");
    }
  }
}

void
runlog_import_xml(FILE *hlog, const unsigned char *in_xml)
{
  size_t armor_len, flog_len = 0;
  unsigned char *armor_str, *flog_text = 0;
  FILE *flog;

  struct run_header in_header;
  struct run_header cur_header;
  struct run_entry *in_entries = 0;
  struct run_entry *cur_entries = 0;
  struct run_entry *out_entries = 0;
  struct run_entry *pa, *pb;
  size_t in_entries_num = 0;
  size_t cur_entries_num = 0;
  size_t out_entries_num = 0;
  int r, i, st, j, k, corr_total, i2, j2, i3, j3, cur_out;
  int min_i, min_j;
  time_t prev_time, cur_time = 0;
  int *cur_new_map, *cur_merged_map, *new_cur_map, *new_merged_map;
  int update_flag = 0;
  int min_team_id;
  unsigned char *cur_used_flag, *in_used_flag;
  int both_auth_warn_printed = 0;

  flog = open_memstream((char**) &flog_text, &flog_len);
  memset(&in_header, 0, sizeof(in_header));
  memset(&cur_header, 0, sizeof(cur_header));

  if (global->virtual) {
    fprintf(flog, "XML import is not yet implemented for virtual contests\n");
    goto done;
  }

  cur_entries_num = run_get_total();
  if (cur_entries_num > 0) {
    XCALLOC(cur_entries, cur_entries_num);
  }
  run_get_header(&cur_header);
  run_get_all_entries(cur_entries);

  if (!cur_header.start_time) {
    fprintf(flog, "Contest is not yet started\n");
    goto done;
  }

  fprintf(flog, "Current run log has %d entries\n", cur_entries_num);
  fprintf(flog, "Scanning the existing entries\n");

  for (i = 0; i < cur_entries_num; i++) {
    st = cur_entries[i].status;
    ASSERT(st >= RUN_OK && st <= RUN_TRANSIENT_LAST);
    if (st <= RUN_MAX_STATUS) continue;
    ASSERT(st >= RUN_PSEUDO_FIRST);
    if (st == RUN_VIRTUAL_START || st == RUN_VIRTUAL_STOP) {
      fprintf(flog, "Run %d is a virtual contest control record!\n", i);
      goto done;
    }
    if (st == RUN_EMPTY) {
      fprintf(flog, "Run %d is empty\n", i);
      continue;
    }
    ASSERT(st >= RUN_TRANSIENT_FIRST);
    fprintf(flog, "Run %d is a transient run %d ('%s')\n",
            i, st, run_status_str(st, 0, 0));
    fprintf(flog, "Cannot merge logs with transient runs\n");
    goto done;
  }
  prev_time = 0;
  for (i = 0; i < cur_entries_num; i++) {
    if (cur_entries[i].timestamp < 0) {
      fprintf(flog, "Run %d time is negative\n", i);
      goto done;
    }
    if (cur_entries[i].timestamp < prev_time) {
      fprintf(flog, "Run %d time is less than previous run time\n", i);
      goto done;
    }
    prev_time = cur_entries[i].timestamp;
  }
  fprintf(flog, "Scanning the existing entries done successfully\n");

  r = parse_runlog_xml(in_xml, &in_header, &in_entries_num, &in_entries);
  if (r < 0) {
    fprintf(flog, "XML parsing failed\n");
    goto done;
  }
  fprintf(flog, "XML parsing successful: %zu entries\n", in_entries_num);

  fprintf(flog, "Scanning new entries\n");
  for (i = 0; i < in_entries_num; i++) {
    if (in_entries[i].submission != i) {
      fprintf(flog, "Run %d has run_id %d\n", i, in_entries[i].submission);
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
      goto done;
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
            i, st, run_status_str(st, 0, 0));
    goto done;
  }
  prev_time = 0;
  for (i = 0; i < in_entries_num; i++) {
    if (in_entries[i].status == RUN_EMPTY) continue;
    ASSERT(in_entries[i].status <= RUN_MAX_STATUS);
    if (in_entries[i].timestamp < 0) {
      fprintf(flog, "Run %d time is negative\n", i);
      goto done;
    }
    if (in_entries[i].timestamp < prev_time) {
      fprintf(flog, "Run %d time is less than previous run time\n", i);
      goto done;
    }
    prev_time = in_entries[i].timestamp;
    if (!teamdb_lookup(in_entries[i].team)) {
      fprintf(flog, "Run %d team %d is not known\n", i, in_entries[i].team);
      goto done;
    }
    r = in_entries[i].problem;
    if (r <= 0 || r > max_prob || !probs[r]) {
      fprintf(flog, "Run %d problem %d is not known\n", i, r);
      goto done;
    }
    r = in_entries[i].language;
    if (r <= 0 || r > max_lang || !langs[r]) {
      fprintf(flog, "Run %d problem %d is not known\n", i, r);
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
    if (cur_entries[i].status == RUN_EMPTY) {
      i++;
      continue;
    }
    while (i < cur_entries_num && j < in_entries_num) {
      cur_time = cur_entries[i].timestamp - cur_header.start_time;
      if (cur_time < 0) cur_time = 0;
      if (in_entries[j].status == RUN_EMPTY) {
        j++;
        continue;
      }
      if (cur_time == in_entries[j].timestamp) break;
      if (cur_time < in_entries[j].timestamp)
        i++;
      else
        j++;
    }
    if (i >= cur_entries_num || j >= in_entries_num) break;
    k = j;
    for (; k < in_entries_num; k++) {
      if (in_entries[k].status == RUN_EMPTY) continue;
      if (in_entries[k].timestamp != cur_time) break;
      if (new_cur_map[k] >= 0) continue;
      if (cur_entries[i].team != in_entries[k].team) continue;
      if (cur_entries[i].problem != in_entries[k].problem) continue;
      if (cur_entries[i].language != in_entries[k].language) continue;
      break;
    }
    if (k < in_entries_num && in_entries[k].timestamp == cur_time) {
      /* establish correspondence */
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
      pb->is_imported = 1;
    }
    if (pa->is_imported && pb->is_imported) {
      /* just warn, if values differ */
      if (pa->size != pb->size) {
        fprintf(flog, "Local run %d, imported %d: `size' does not match\n",
                i, j);
      }
      if (pa->ip != pb->ip) {
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
      if (pa->ip != pb->ip) {
        pa->ip = pb->ip;
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
      if (r) {
        update_flag++;
      }
      run_set_entry(i, RUN_ENTRY_ALL, pa);
    }
    fprintf(flog, "%d entries updated\n", update_flag);
    goto done;
  }
  fprintf(flog, "The merged runlog contains %d records\n", out_entries_num);
  if (!out_entries_num) {
    fprintf(flog, "Refuse to create runlog of size 0\n");
    goto done;
  }
  out_entries = alloca(out_entries_num * sizeof(out_entries[0]));
  memset(out_entries, 0, out_entries_num * sizeof(out_entries[0]));
  cur_used_flag = alloca(cur_entries_num);
  memset(cur_used_flag, 0, cur_entries_num);
  in_used_flag = alloca(in_entries_num);
  memset(in_used_flag, 0, in_entries_num);

  /* fix time in the imported runs */
  for (j = 0; j < in_entries_num; j++) {
    if (in_entries[j].status == RUN_EMPTY) continue;
    in_entries[j].timestamp += cur_header.start_time;
  }

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
    if (cur_entries[i].timestamp < in_entries[j].timestamp) {
      ASSERT(cur_new_map[i] == -1);
      memcpy(&out_entries[cur_out], &cur_entries[i], sizeof(out_entries[0]));
      out_entries[cur_out].submission = cur_out;
      cur_merged_map[i] = cur_out;
      i++;
      cur_out++;
      continue;
    }
    if (cur_entries[i].timestamp > in_entries[j].timestamp) {
      ASSERT(new_cur_map[j] == -1);
      memcpy(&out_entries[cur_out], &in_entries[j], sizeof(out_entries[0]));
      out_entries[cur_out].submission = cur_out;
      out_entries[cur_out].is_imported = 1;
      new_merged_map[j] = cur_out;
      j++;
      cur_out++;
      continue;
    }
    /* detect entries with the same timestamp */
    for (i2 = i; i2 < cur_entries_num; i2++) {
      if (cur_entries[i2].status == RUN_EMPTY) continue;
      if (cur_entries[i2].timestamp != cur_entries[i].timestamp) break;
    }
    for (j2 = j; j2 < in_entries_num; j2++) {
      if (in_entries[j2].status == RUN_EMPTY) continue;
      if (in_entries[j2].timestamp != in_entries[j].timestamp) break;
    }
    while (1) {
      min_team_id = INT_MAX, min_i = -1, min_j = -1;
      for (i3 = i; i3 < i2; i3++) {
        if (cur_entries[i3].status == RUN_EMPTY) continue;
        if (cur_used_flag[i3]) continue;
        if (cur_entries[i3].team < min_team_id) {
          min_team_id = cur_entries[i3].team;
          min_i = i3;
          min_j = -1;
        }
      }
      for (j3 = j; j3 < j2; j3++) {
        if (in_entries[j3].status == RUN_EMPTY) continue;
        if (in_used_flag[j3]) continue;
        if (in_entries[j3].team < min_team_id) {
          min_team_id = in_entries[j3].team;
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
          out_entries[cur_out].submission = cur_out;
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
          out_entries[cur_out].submission = cur_out;
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
        out_entries[cur_out].submission = cur_out;
        out_entries[cur_out].is_imported = 1;
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
    out_entries[cur_out].submission = cur_out;
    cur_merged_map[i] = cur_out;
    cur_out++;
  }
  for (;j < in_entries_num; j++) {
    if (in_entries[j].status == RUN_EMPTY) continue;
    ASSERT(new_cur_map[j] == -1);
    memcpy(&out_entries[cur_out], &in_entries[j], sizeof(out_entries[0]));
    out_entries[cur_out].submission = cur_out;
    out_entries[cur_out].is_imported = 1;
    new_merged_map[j] = cur_out;
    cur_out++;
  }
  ASSERT(cur_out == out_entries_num);
  fprintf(flog, "Runlog successfully merged\n");

  fprintf(flog, "Saving the new runlog\n");
  run_backup(global->run_log_file);
  run_set_runlog(out_entries_num, out_entries);
  fprintf(flog, "Renaming archive files\n");
  for (i = 0; i < cur_entries_num; i++)
    if (cur_entries[i].is_imported)
      cur_merged_map[i] = -1;
  rename_archive_files(flog, cur_entries_num, cur_merged_map);
  fprintf(flog, "Merge complete\n");

 done:
  fclose(flog);
  if (!flog_text) flog_text = xstrdup("");
  armor_len = html_armored_strlen(flog_text);
  armor_str = alloca(armor_len + 1);
  html_armor_string(flog_text, armor_str);
  fprintf(hlog, "<pre>%s</pre>\n", armor_str);
  xfree(flog_text);
  xfree(in_entries);
  xfree(cur_entries);
}

/**
 * Local variables:
 *  compile-command: "make"
 *  c-font-lock-extra-types: ("\\sw+_t" "FILE" "DIR")
 * End:
 */
